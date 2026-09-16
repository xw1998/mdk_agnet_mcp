# -*- coding: utf-8 -*-
"""
Mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务（MCP Server）。

通过 UVSOCK/TCP 连接 Keil uVision 调试器，向 MCP 客户端（Claude、灵犀等）
暴露如下调试工具：
  - get_version    查询 UVSOCK 插件版本
  - get_status     查询调试 / 目标运行状态
  - calc_expression 读取表达式 / 变量值
  - read_mem       读取目标内存
  - write_mem      写入目标内存
  - run / stop / reset / step  运行控制

运行形态：常驻服务 + 空闲自动断开连接缓存。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import sys
import xml.etree.ElementTree as ET

from mcp.server.mcpserver import MCPServer

from .client import UVClient, UVSOCKConnectError
from .locator import Locator
from . import builder, mapfile, __version__
from .periph import (list_peripherals as _periph_list, get_peripheral as _periph_get,
                     query_memory_map as _query_memory_map)

logger = logging.getLogger("mdkdebug.server")

# 全局共享一个带连接缓存的客户端（线程安全）
_client: UVClient | None = None
# 编译/烧录配置（UV4.exe 路径与默认工程）
_builder_cfg = {"uv4": None, "default_project": None}
# 符号定位配置（.axf 路径与 Locator 实例）
_symbol_cfg = {"locator": None, "axf": None}
_breakpoints: list = []  # 内部断点记录（expr/address/file/line），因 BL 输出不经 socket 回传
_watchpoints: list = []  # 内部数据断点（watchpoint）记录
_snapshot_baseline: dict | None = None  # snapshot_diff 对比基线

def _resolve_axf(uvprojx_path: str | None) -> str | None:
    """从 .uvprojx 推断 .axf 路径（解析 OutputDirectory/OutputName）。"""
    if not uvprojx_path or not os.path.isfile(uvprojx_path):
        return None
    try:
        root = ET.parse(uvprojx_path).getroot()
        out_dir = out_name = None
        for tgt in root.iter("Target"):
            for o in tgt.iter("OutputName"):
                if o.text:
                    out_name = o.text.strip()
            for o in tgt.iter("OutputDirectory"):
                if o.text:
                    out_dir = o.text.strip()
        if out_name:
            base = os.path.dirname(os.path.abspath(uvprojx_path))
            axf = os.path.normpath(os.path.join(base, out_dir or "", out_name + ".axf"))
            if os.path.isfile(axf):
                return axf
    except Exception as e:  # noqa: BLE001
        logger.warning("解析 uvprojx 输出配置失败: %s", e)
    return None

# AC5(ARMCC) Cads/Optim 数值 → 优化选项文本（Keil 下拉：-O0/-O1/-O2/-O3/-Otime）
_OPTIM_TEXT = {"0": "-O0", "1": "-O1", "2": "-O2", "3": "-O3", "4": "-Otime"}


def _parse_uvprojx_config(uvprojx_path: str | None, target_name: str | None = None) -> dict:
    """解析 .uvprojx 各 target 的编译器类型 / 优化级别 / 编译宏 / 包含路径。

    定位 target 用 <TargetName>；uAC6=0→ARMCC(AC5)、1→ARMCLANG(AC6)；
    优化级别：AC5 在 <Cads><Optim>（0-4 映射 _OPTIM_TEXT），AC6 尝试同一节点文本；
    编译宏：<Cads><VariousControls><Define>（逗号分隔）；包含路径同节点 <IncludePath>（分号分隔）。
    用于排查“不同 target 行为不同”——宏/优化差异一目了然。
    """
    import xml.etree.ElementTree as ET
    if not uvprojx_path or not os.path.isfile(uvprojx_path):
        return {"ok": False, "error": f"工程文件不存在: {uvprojx_path}"}
    try:
        root = ET.parse(uvprojx_path).getroot()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"解析 uvprojx 失败: {e}"}
    targets: list[dict] = []
    chosen = None
    for t in root.iter("Target"):
        name_el = t.find("TargetName")
        name = (name_el.text or "").strip() if name_el is not None else ""
        if not name:
            continue
        uac6 = (t.findtext("uAC6") or "0").strip()
        # Cads/Optim、Cads/VariousControls/* 在 TargetOption/TargetCommonOption 之下，用任意深度路径
        optim = (t.findtext(".//Cads/Optim") or "").strip()
        cdef_el = t.find(".//Cads/VariousControls/Define")
        cdefs = []
        if cdef_el is not None and cdef_el.text and cdef_el.text.strip():
            cdefs = [x.strip() for x in cdef_el.text.split(",") if x.strip()]
        inc_el = t.find(".//Cads/VariousControls/IncludePath")
        inc = [x.strip() for x in (inc_el.text or "").split(";") if x.strip()] if inc_el is not None else []
        info = {
            "name": name,
            "compiler": "ARMCLANG(AC6)" if uac6 == "1" else "ARMCC(AC5)",
            "uAC6": uac6,
            "optimization": optim,
            "optimization_level": _OPTIM_TEXT.get(optim, f"-O{optim}" if optim.isdigit() else ""),
            "defines": cdefs,
            "include_paths": inc,
        }
        targets.append(info)
        if chosen is None and (target_name is None or name == target_name):
            chosen = info
    if chosen is None:
        chosen = targets[0] if targets else None
    out: dict = {"ok": bool(targets), "targets": targets, "count": len(targets)}
    if chosen is not None:
        out["current"] = chosen
    else:
        out["error"] = "工程中未找到 Target 配置"
    return out


def _get_locator() -> Locator | None:
    return _symbol_cfg.get("locator")


def _resolve_map() -> str:
    """从已配置的 .axf 推断同目录同名 .map 路径；不存在返回空串。"""
    axf = _symbol_cfg.get("axf")
    if axf:
        base = os.path.splitext(axf)[0] + ".map"
        if os.path.isfile(base):
            return base
    return ""

def _parse_target(locator, target: str):
    """把目标字符串解析为地址。支持 0x地址 或 文件:行号（如 main.c:77）。"""
    t = (target or "").strip()
    if t.lower().startswith("0x"):
        try:
            return int(t, 16)
        except ValueError:
            return None
    if ":" in t:
        file, line = t.rsplit(":", 1)
        try:
            ln = int(line.strip())
        except ValueError:
            return None
        return locator.line_to_addr(file.strip(), ln)
    return None

def _get_client() -> UVClient:
    global _client
    if _client is None:
        raise RuntimeError("客户端未初始化，请先调用 create_server()")
    return _client


def _parse_addr(s: str | int) -> int:
    """把地址参数解析为整数，支持 0x/0b/0o 前缀或纯十进制。"""
    if isinstance(s, int):
        return s
    s = (s or "").strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.lower().startswith("0b"):
        return int(s, 2)
    if s.lower().startswith("0o"):
        return int(s, 8)
    return int(s, 10)


def _fmt_field(raw: bytes, tname: str):
    """把结构体成员原始字节格式化为友好值。返回 {hex, int(可选), float(可选), ascii(可选)}。"""
    import struct as _struct
    n = len(raw)
    t = (tname or "").lower()
    out = {"hex": raw.hex()}
    if n in (4, 8) and ("float" in t or "double" in t):
        try:
            out["float"] = _struct.unpack("<f" if n == 4 else "<d", raw[:n])[0]
            return out
        except Exception:  # noqa: BLE001
            pass
    if n in (1, 2, 4, 8):
        v = int.from_bytes(raw[:n], "little", signed=False)
        out["int"] = v
        out["hex_int"] = f"0x{v:x}"
    elif n >= 4:
        v = int.from_bytes(raw[:4], "little", signed=False)
        out["int"] = v
        out["hex_int"] = f"0x{v:x}"
    if n and all(0x20 <= b < 0x7f for b in raw):
        out["ascii"] = raw.decode("ascii", errors="replace")
    return out


def _backtrace(client, loc, pc, lr, sp, max_frames: int = 16, stack_bytes: int = 1024) -> list:
    """基于 PC/LR + 栈启发式读取做完整调用栈回溯。

    第一帧为 PC，第二帧为 LR，之后从 SP 向上扫描栈内存（AAPCS 下返回地址在栈中
    成链），凡落在 FLASH 代码段的值视为返回地址并反查 文件:行。启发式方案，不保证
    与真实帧完全一致，但对多数 ARM 调用链足够给出完整路径。返回 [{level,pc,file,line}]。
    """
    frames: list = []
    seen: set = set()

    def add(addr: int) -> None:
        if addr in seen or not loc.is_code_address(addr):
            return
        seen.add(addr)
        l = loc.addr_to_location(addr)
        frames.append({"pc": hex(addr),
                       "file": l["file"] if l else "?",
                       "line": l["line"] if l else None})

    add(pc)
    if isinstance(lr, int):
        add(lr)
    if isinstance(sp, int):
        raw = b""
        try:
            r = client.read_mem(sp, stack_bytes)
            data_hex = r.get("data_hex") or ""
            raw = bytes.fromhex(data_hex) if data_hex else b""
        except Exception as e:  # noqa: BLE001
            logger.debug("栈回溯读取失败: %s", e)
        for off in range(0, len(raw) - 3, 4):
            w = int.from_bytes(raw[off:off + 4], "little")
            if len(frames) >= max_frames:
                break
            if loc.is_code_address(w):
                add(w)
    for i, fr in enumerate(frames):
        fr["level"] = i
    return frames


def _build_location(client):
    """读取当前 PC 并构建停靠位置信息：文件行、源码上下文、完整调用栈。

    供 get_current_location 与 step/run 系列复用，让 AI 查询后立即看到停靠代码。
    返回 dict：{ok, pc, registers, file, line, address, source, display_path, callstack,
    warning(可选), hit_breakpoint(可选)}；.axf 未就绪返回 None；无法读寄存器返回 {ok:False}。
    """
    loc = _get_locator()
    if not loc or not loc.is_ready():
        return None
    regs = client.read_cpu_registers_stable()
    if not regs.get("ok"):
        return {"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试）", "detail": regs}
    pc = regs.get("pc")
    lr = regs.get("lr")
    sp = regs.get("sp")
    result = {"ok": True, "pc": hex(pc) if isinstance(pc, int) else pc, "registers": regs}
    cur = loc.addr_to_location(pc) if isinstance(pc, int) else None
    if cur:
        result["file"] = cur["file"]
        result["line"] = cur["line"]
        result["address"] = hex(cur["address"])
        src = loc.read_source(cur["file"], cur["line"], context=4)
        if src:
            result["source"] = src["source"]
            result["display_path"] = src["display_path"]
        # 漂移检测：当前文件比 .axf 新则提示重编译，避免行号/符号错位
        stale, path = loc.source_stale(cur["file"])
        if stale:
            result["warning"] = (f"源码 {path} 比 .axf 新（未重编译），行号/符号可能偏移，"
                                  "建议先 build_and_flash 再调试")
    # 完整调用栈回溯（PC/LR/SP + 栈启发式）
    result["callstack"] = _backtrace(client, loc, pc, lr, sp)
    # 断点命中反馈：停靠地址是否落在已设断点
    if cur and _breakpoints and isinstance(pc, int):
        for bp in _breakpoints:
            try:
                if bp.get("address") and int(bp["address"], 16) == pc:
                    bp["hit_count"] = bp.get("hit_count", 0) + 1
                    result["hit_breakpoint"] = {
                        "expr": bp.get("expr"), "address": bp.get("address"),
                        "file": bp.get("file"), "line": bp.get("line"),
                        "hit_count": bp.get("hit_count"),
                    }
                    break
            except (TypeError, ValueError):
                continue
    return result


def _js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def create_server(host: str = "127.0.0.1", port: int = 4823,
                  idle_timeout: float = 30.0,
                  uv4_path: str | None = None,
                  default_project: str | None = None,
                  axf_path: str | None = None) -> MCPServer:
    global _client, _builder_cfg, _symbol_cfg
    _client = UVClient(host=host, port=port, idle_timeout=idle_timeout)
    uv4 = builder.find_uv4(uv4_path)
    if uv4 is None:
        logger.warning("未定位到 UV4.exe，编译/烧录工具不可用。可用 --uv4-path 指定。")
    _builder_cfg = {"uv4": uv4, "default_project": default_project}
    # 符号定位：优先显式 axf_path，其次从默认工程推断
    axf = axf_path or _resolve_axf(default_project)
    locator = None
    if axf and os.path.isfile(axf):
        proj_dir = os.path.dirname(default_project) if default_project else None
        locator = Locator(axf, project_dir=proj_dir)
        logger.info("符号定位：axf=%s 条目=%d", axf, locator.total_entries())
    elif not axf:
        logger.warning("未定位到 .axf，位置定位工具(get_current_location/run_to_line)不可用")
    _symbol_cfg = {"locator": locator, "axf": axf}
    logger.info("Mdkdebug 已就绪：UVSOCK@%s:%d  idle_timeout=%ss", host, port, idle_timeout)
    logger.info("构建配置：UV4=%s  默认工程=%s", uv4, default_project)

    server = MCPServer(
        name="mdkdebug",
        title="Keil uVision Debug (Mdkdebug)",
        version=__version__,
        description=(
            "通过 UVSOCK/TCP 连接 Keil uVision 调试器，提供读变量/表达式、"
            "读写目标内存、运行控制（运行/暂停/复位/单步）和状态查询能力。"
            "适用于 Cortex-M 等 ARM 目标板的在线调试。"
        ),
        log_level="INFO",
    )

    # ---------------- 状态 / 版本 ----------------
    @server.tool(
        name="get_version",
        title="查询调试插件版本",
        description="查询 Keil UVSOCK 插件的版本信息，返回十六进制版本串。",
    )
    async def get_version() -> str:
        try:
            return _js(_get_client().get_version())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="get_status",
        title="查询调试/目标状态",
        description=(
            "查询当前调试状态：是否处于调试会话、目标是否在运行、"
            "以及 UVSOCK 状态码。可用于判断可否安全读写内存。"
        ),
    )
    async def get_status() -> str:
        try:
            return _js(_get_client().get_status())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 表达式 / 变量 ----------------
    @server.tool(
        name="calc_expression",
        title="读取表达式 / 变量值",
        description=(
            "计算并读取调试器中的一个表达式（变量名、寄存器、指针解引用等）。"
            "例如传入全局变量名 'SData_UA'、'timer.sec'，或 '*(uint32_t*)0x20000000'。"
            "返回表达式在当前断点处的值及其类型。"
        ),
    )
    async def calc_expression(expr: str) -> str:
        try:
            return _js(_get_client().calc_expression(expr))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expression": expr, "error": str(e)})

    @server.tool(
        name="read_variable",
        title="按变量名查询变量地址与内容",
        description=(
            "按变量名查询变量的内存地址与当前内容（值），支持数组等类型。"
            "内部用 '&变量名' 取地址、'变量名' 取值、'sizeof(变量名)' 取大小，"
            "AI 无需手写取地址表达式即可定位变量。"
            "name 为变量名（如 'SData_UA'、'timer.sec'、'arr'）；"
            "count 可选：>0 时按数组逐元素读 name[0..count-1] 返回 elements；"
            "返回 {address, value, value_type, size_bytes, elements, memory_hex}。"
            "适合先查地址/数组内容，再配合 read_mem/write_mem 进一步读写。"
        ),
    )
    async def read_variable(name: str, count: int = 0, read_memory: bool = True) -> str:
        try:
            return _js(_get_client().read_variable(name, count=int(count or 0),
                                                  read_memory=bool(read_memory)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "name": str(name), "error": str(e)})

    # ---------------- 内存读写 ----------------
    @server.tool(
        name="read_mem",
        title="读取目标内存",
        description=(
            "从指定内存地址读取 n_bytes 个字节。"
            "addr 支持十六进制（如 '0x20000000'）或十进制；返回十六进制字节串及 ASCII 视图。"
        ),
    )
    async def read_mem(addr: str, n_bytes: int) -> str:
        try:
            a = _parse_addr(addr)
            return _js(_get_client().read_mem(a, int(n_bytes)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    @server.tool(
        name="write_mem",
        title="写入目标内存",
        description=(
            "向指定内存地址写入字节。data_hex 为十六进制字节串（偶数长度），"
            "如 'de ad be ef' 或 'deadbeef'（自动去空格）。返回实际写入长度。"
        ),
    )
    async def write_mem(addr: str, data_hex: str) -> str:
        try:
            a = _parse_addr(addr)
            hex_str = "".join((data_hex or "").split())
            payload = bytes.fromhex(hex_str)
            return _js(_get_client().write_mem(a, payload))
        except ValueError as e:
            return _js({"ok": False, "addr": str(addr), "error": f"data_hex 非法: {e}"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    # ---------------- 调试会话控制 ----------------
    @server.tool(
        name="enter_debug",
        title="进入调试模式",
        description=(
            "自动进入 Keil 调试模式（UV_DBG_ENTER）。"
            "受工程 Load/Flash Download/Run-to-main 设置影响，属于有副作用的操作；"
            "进入后即可设断点、读变量、运行控制。"
        ),
    )
    async def enter_debug() -> str:
        try:
            return _js(_get_client().enter_debug())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="exit_debug",
        title="退出调试模式",
        description="自动退出 Keil 调试模式（UV_DBG_EXIT）。",
    )
    async def exit_debug() -> str:
        try:
            return _js(_get_client().exit_debug())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 断点管理 ----------------
    @server.tool(
        name="set_breakpoint",
        title="设置断点",
        description=(
            "在指定符号或地址处设置软件断点。expr 可为函数名/变量名"
            "（如 'main'）或地址（如 '0x08001034'）。返回是否成功。"
        ),
    )
    async def set_breakpoint(expr: str) -> str:
        try:
            client = _get_client()
            e = (expr or "").strip()
            # 先解析地址再设断点：BS 命令后连接会被断点响应污染（异步消息堆积），
            # 此时再 calc_expression(&expr) 会收到 BS 的 status 22 而非表达式结果。
            addr = None
            if e.lower().startswith("0x"):
                try:
                    addr = int(e, 16)
                except ValueError:
                    addr = None
            else:
                ar = client.calc_expression(f"&{e}")
                if ar.get("ok") and isinstance(ar.get("value"), int):
                    addr = ar["value"]
            # 用解析出的地址设断点，更精确且能拿到位置信息
            r = client.set_breakpoint(hex(addr) if addr is not None else expr)
            out = {"expr": expr}
            out.update(r)
            loc = _get_locator()
            if addr is not None:
                out["address"] = hex(addr)
                l = loc.addr_to_location(addr) if loc else None
                if l:
                    out["file"] = l["file"]
                    out["line"] = l["line"]
                _breakpoints.append({"expr": expr, "address": hex(addr),
                                     "file": out.get("file"), "line": out.get("line")})
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="set_conditional_breakpoint",
        title="设置条件断点",
        description=(
            "在符号/地址处设带条件的软件断点：仅当 condition（C 表达式，如 'R0==5'、"
            "'test_array[0]==0x11111111'）成立时才暂停；count 为命中计数（默认1，第 count 次满足才停）。"
            "用于只在特定条件/次数下停住，减少无关中断。需已进入调试且配置 .axf。"
        ),
    )
    async def set_conditional_breakpoint(expr: str, condition: str, count: int = 1) -> str:
        try:
            client = _get_client()
            e = (expr or "").strip()
            cond = (condition or "").strip()
            if not cond:
                return _js({"ok": False, "expr": expr, "error": "condition 不能为空"})
            # 先解析地址（避开 BS 命令后连接被污染的坑）
            addr = None
            if e.lower().startswith("0x"):
                try:
                    addr = int(e, 16)
                except ValueError:
                    addr = None
            else:
                ar = client.calc_expression(f"&{e}")
                if ar.get("ok") and isinstance(ar.get("value"), int):
                    addr = ar["value"]
            loc = _get_locator()
            target = hex(addr) if addr is not None else expr
            cmd = f"BS {target}, {cond}"
            if count and count > 1:
                cmd = f"{cmd}, {count}"
            r = client.exec_command(cmd)
            out = {"ok": r.get("ok"), "expr": expr, "condition": cond, "count": count,
                   "command": cmd, "status_text": r.get("status_text")}
            if addr is not None:
                out["address"] = hex(addr)
                l = loc.addr_to_location(addr) if loc else None
                if l:
                    out["file"] = l["file"]
                    out["line"] = l["line"]
                _breakpoints.append({"expr": expr, "address": hex(addr), "condition": cond,
                                     "count": count, "file": out.get("file"), "line": out.get("line")})
            if not r.get("ok"):
                out["error"] = f"设置条件断点失败: {r}"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "condition": condition, "error": str(e)})

    @server.tool(
        name="set_watchpoint",
        title="设置数据断点（访问断点）",
        description=(
            "设置数据/访问断点：当指定地址被 读取/写入/读写 时目标运行自动暂停。"
            "用于定位'谁在何时改坏了某变量/内存'。expr 为变量名（如 'test_array'）或地址（如 '0x20000000'）；"
            "access 取 read/write/readwrite，默认 write；count 为触发次数（默认1）。"
            "返回设断地址与 文件:行。命中后可用 get_current_location/snapshot 看是谁改的。需已进入调试。"
        ),
    )
    async def set_watchpoint(expr: str, access: str = "write", count: int = 1) -> str:
        try:
            client = _get_client()
            e = (expr or "").strip()
            acc = (access or "write").lower()
            acc_map = {"read": "READ", "write": "WRITE", "rw": "READWRITE",
                       "wr": "READWRITE", "readwrite": "READWRITE"}
            if acc not in acc_map:
                return _js({"ok": False, "expr": expr, "access": access,
                            "error": "access 须为 read / write / readwrite"})
            acc_up = acc_map[acc]
            # 解析目标地址：0x 直接取，变量名先 & 取址（避开 BS 命令后连接被污染的坑）
            addr = None
            if e.lower().startswith("0x"):
                try:
                    addr = int(e, 16)
                except ValueError:
                    addr = None
            else:
                ar = client.calc_expression(f"&{e}")
                if ar.get("ok") and isinstance(ar.get("value"), int):
                    addr = ar["value"]
            if addr is None:
                return _js({"ok": False, "expr": expr,
                            "error": "无法解析目标地址（变量不存在或未处于调试状态）"})
            cmd = f"BS {acc_up} 0x{addr:x}"
            r = client.exec_command(cmd)
            out = {"ok": r.get("ok"), "expr": expr, "address": hex(addr),
                   "access": acc, "count": count, "command": cmd}
            if not r.get("ok"):
                out["error"] = f"设置数据断点失败: {r}"
                return _js(out)
            loc = _get_locator()
            l = loc.addr_to_location(addr) if loc else None
            if l:
                out["file"] = l["file"]
                out["line"] = l["line"]
            _watchpoints.append({"expr": expr, "address": hex(addr), "access": acc,
                                 "count": count, "file": out.get("file"),
                                 "line": out.get("line")})
            out["message"] = f"已设置{acc}数据断点，命中即暂停"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="clear_watchpoint",
        title="清除数据断点",
        description="清除指定地址/变量的数据断点（命令窗口 BK）。expr 为变量名或 0x 地址。",
    )
    async def clear_watchpoint(expr: str) -> str:
        try:
            client = _get_client()
            e = (expr or "").strip()
            r = client.exec_command(f"BK {e}")
            _watchpoints[:] = [w for w in _watchpoints
                               if w.get("expr") != e and w.get("address") != e]
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="list_watchpoints",
        title="列出数据断点",
        description="列出本服务设置的内部数据断点记录（命令窗口 BL 对数据断点输出不经 socket 回传）。",
    )
    async def list_watchpoints() -> str:
        try:
            return _js({"ok": True, "watchpoints": list(_watchpoints)})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_breakpoint",
        title="清除断点",
        description="清除指定符号或断点编号处的断点（命令窗口 BK）。",
    )
    async def clear_breakpoint(expr: str) -> str:
        try:
            r = _get_client().clear_breakpoint(expr)
            _breakpoints[:] = [b for b in _breakpoints if b.get("expr") != expr]
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="list_breakpoints",
        title="列出断点",
        description="列出当前调试会话中的所有断点（命令窗口 BL）。",
    )
    async def list_breakpoints() -> str:
        try:
            if _breakpoints:
                return _js({"ok": True, "breakpoints": list(_breakpoints)})
            return _js(_get_client().list_breakpoints())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 符号检索 ----------------
    @server.tool(
        name="find_symbol",
        title="检索符号",
        description=(
            "从 .axf ELF 符号表模糊检索 函数/全局变量 符号（query 为子串，大小写不敏感，空则列出全部）。"
            "AI 想读取某个全局变量或跳到某函数而不知道确切名字时，先用它搜到符号名与地址，"
            "再配合 calc_expression / read_variable / set_breakpoint / disassemble 使用。"
            "kind 可取 all/func/object/global/local 过滤。需配置 .axf 调试符号。"
        ),
    )
    async def find_symbol(query: str = "", limit: int = 50, kind: str = "all") -> str:
        try:
            loc = _get_locator()
            if loc is None:
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号，或未从工程推断到）"})
            symbols = loc.search_symbols(query=query, limit=max(1, min(limit, 200)), kind=kind)
            return _js({"ok": True, "query": query, "kind": kind, "count": len(symbols), "symbols": symbols})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "query": query, "error": str(e)})

    # ---------------- 位置定位 / run to cursor ----------------
    @server.tool(
        name="get_current_location",
        title="读取当前执行位置",
        description=(
            "读取当前 PC，定位到 源文件:行号 并返回该行附近的源码上下文，"
            "同时给出调用栈（PC + LR 反查）。让 AI 像人一样知道程序停在哪、看的是什么代码。"
            "需已进入调试状态且配置了 .axf 调试符号。"
        ),
    )
    async def get_current_location() -> str:
        try:
            client = _get_client()
            info = _build_location(client)
            if info is None:
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号，或未从工程推断到）"})
            return _js(info)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_locals",
        title="读取当前函数局部变量",
        description=(
            "读取当前 PC 所在函数的 参数+局部变量 及其当前值。基于 .axf(DWARF) 定位"
            "包含当前 PC 的函数作用域，得到变量名列表后用 calc_expression 在当前上下文求值，"
            "让 AI 看到当前函数（而非仅全局变量）的局部状态。需已进入调试且配置 .axf。"
        ),
    )
    async def read_locals() -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            regs = client.read_cpu_registers_stable()
            if not regs.get("ok"):
                return _js({"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试）", "detail": regs})
            pc = regs.get("pc")
            if not isinstance(pc, int):
                return _js({"ok": False, "error": "无法获取当前 PC"})
            names = loc.local_variables(pc)
            if names is None:
                return _js({"ok": False, "pc": hex(pc), "error": "未从 .axf 定位到当前函数或变量信息"})
            cur = loc.addr_to_location(pc)
            out = {"ok": True, "pc": hex(pc)}
            if cur:
                out["file"] = cur["file"]
                out["line"] = cur["line"]
            vars_list = []
            for name in names:
                try:
                    r = client.calc_expression(name)
                    vars_list.append({"name": name, "ok": r.get("ok"),
                                      "value_type": r.get("value_type"),
                                      "value": r.get("value")})
                except Exception as ex:  # noqa: BLE001
                    vars_list.append({"name": name, "ok": False, "error": str(ex)})
            out["locals"] = vars_list
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="snapshot",
        title="获取调试状态快照",
        description=(
            "一次返回当前调试位置的全貌：PC、文件:行、源码上下文、完整调用栈、当前函数局部变量，"
            "以及指定的全局变量（globals 参数传入变量名列表）。AI 排查问题时一次调用即可获得完整画面，"
            "避免多次 get_current_location/read_locals/read_variable 往返。globals 可选，"
            "如 ['SystemCoreClock','test_array']。需已进入调试且配置 .axf。"
        ),
    )
    async def snapshot(globals: list = None, source_context: int = 4) -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            info = _build_location(client)
            if info is None:
                return _js({"ok": False, "error": "无法构建位置信息"})
            out = {"ok": True, "pc": info.get("pc"),
                   "file": info.get("file"), "line": info.get("line"),
                   "address": info.get("address"),
                   "source": info.get("source"), "display_path": info.get("display_path"),
                   "callstack": info.get("callstack")}
            if info.get("warning"):
                out["warning"] = info["warning"]
            if info.get("hit_breakpoint"):
                out["hit_breakpoint"] = info["hit_breakpoint"]
            regs = info.get("registers") or {}
            pc = regs.get("pc")
            # 当前函数局部变量
            if isinstance(pc, int):
                names = loc.local_variables(pc)
                if names:
                    out["locals"] = []
                    for name in names:
                        try:
                            r = client.calc_expression(name)
                            out["locals"].append({"name": name, "ok": r.get("ok"),
                                                  "value_type": r.get("value_type"),
                                                  "value": r.get("value")})
                        except Exception as ex:  # noqa: BLE001
                            out["locals"].append({"name": name, "ok": False, "error": str(ex)})
            # 指定全局变量
            if globals:
                out["globals"] = []
                for g in globals:
                    try:
                        r = client.read_variable(str(g), read_memory=False)
                        out["globals"].append({"name": str(g), "ok": r.get("ok"),
                                               "value_type": r.get("value_type"),
                                               "value": r.get("value"),
                                               "address": r.get("address")})
                    except Exception as ex:  # noqa: BLE001
                        out["globals"].append({"name": str(g), "ok": False, "error": str(ex)})
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="watch",
        title="批量读取表达式",
        description=(
            "一次求值多个表达式（变量/寄存器/指针解引用等）并返回结果，减少往返调用。"
            "expressions 为表达式列表，如 ['SystemCoreClock','timer.sec','*(uint32_t*)0x20000000']。"
            "需已进入调试状态。"
        ),
    )
    async def watch(expressions: list) -> str:
        try:
            client = _get_client()
            if not expressions:
                return _js({"ok": False, "error": "expressions 不能为空"})
            results = []
            for expr in expressions:
                try:
                    r = client.calc_expression(str(expr))
                    results.append({"expression": str(expr), "ok": r.get("ok"),
                                    "value_type": r.get("value_type"),
                                    "value": r.get("value")})
                except Exception as ex:  # noqa: BLE001
                    results.append({"expression": str(expr), "ok": False, "error": str(ex)})
            return _js({"ok": True, "results": results})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_struct",
        title="读取结构体/联合体字段概览",
        description=(
            "按变量名读取一个结构体（或联合体）变量，解析其 DWARF 成员布局（成员名/偏移/类型/大小），"
            "并逐个读出每个成员当前值，供 AI 查看外设配置、数据包等复杂结构体的字段级内容。"
            "name 为全局结构体变量名（如 'hUart1'、'timHandle'）。需已进入调试且配置 .axf。"
        ),
    )
    async def read_struct(name: str, max_fields: int = 64) -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            ar = client.calc_expression(f"&{name}")
            vr = client.calc_expression(name)
            base = ar.get("value") if (ar.get("ok") and isinstance(ar.get("value"), int)) else None
            info = loc.struct_members(name)
            out = {"ok": True, "name": name}
            if base is not None:
                out["address"] = hex(base)
            if vr.get("ok"):
                out["value_type"] = vr.get("value_type")
            if not info:
                out["error"] = ("未从 .axf(DWARF) 解析到结构体字段（变量可能非结构体、已优化或无调试信息）。"
                                "可用 read_variable 读原始内存。")
                if vr.get("ok"):
                    out["value"] = vr.get("value")
                return _js(out)
            out["struct_type"] = info["type"]
            out["size_bytes"] = info["size_bytes"]
            fields = []
            for fd in info.get("fields", [])[:max_fields]:
                off = fd.get("offset", 0)
                sz = fd.get("size") or 4
                field_val = None
                if base is not None:
                    try:
                        r = client.read_mem(base + off, sz)
                        dh = r.get("data_hex") or ""
                        raw = bytes.fromhex("".join(dh.split())) if dh else b""
                        if raw:
                            field_val = _fmt_field(raw, fd.get("type", ""))
                    except Exception as ex:  # noqa: BLE001
                        field_val = {"error": str(ex)}
                fields.append({"name": fd.get("name"), "offset": off,
                               "type": fd.get("type"), "size": sz, "value": field_val})
            out["fields"] = fields
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_registers",
        title="读取 CPU 寄存器组",
        description=(
            "批量读取 CPU 核心寄存器 R0-R12/SP/LR/PC/xPSR 及当前值，并按 AAPCS 调用约定解读："
            "R0-R3 为函数前 4 个入参（若当前停在函数入口/调用点），R0 为返回值，SP 栈指针、LR 返回地址。"
            "排查函数参数传错、返回值不对、寄存器被踩等问题时使用。需已进入调试状态。"
        ),
    )
    async def read_registers() -> str:
        try:
            client = _get_client()
            # 寄存器名候选（大小写兼容不同 Keil 版本）
            order = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                     "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC", "xPSR"]
            aliases = {"SP": ("__currentSP()", "SP", "R13"),
                       "LR": ("__currentLR()", "LR", "R14"),
                       "PC": ("__currentPC()", "PC", "R15")}
            core: dict = {}
            failed: list = []
            for name in order:
                cands = aliases.get(name, (name,))
                val = None
                for c in cands:
                    try:
                        r = client.calc_expression(c)
                    except Exception:  # noqa: BLE001
                        continue
                    if r.get("ok") and isinstance(r.get("value"), int):
                        val = r["value"]
                        break
                if val is None:
                    failed.append(name)
                else:
                    core[name.lower()] = val
            if not core:
                return _js({"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试）", "failed": failed})
            out = {"ok": True, "registers": core, "count": len(core)}
            if failed:
                out["unavailable"] = failed
            # AAPCS 解读：R0-R3 前4入参（当帧为函数入口时才有意义），R0 返回值，LR 返回地址
            aapcs = {}
            for i in range(4):
                key = f"r{i}"
                if key in core:
                    aapcs[f"arg{i+1}"] = core[key]
            if "r0" in core:
                aapcs["return_value"] = core["r0"]
            if "lr" in core:
                aapcs["return_address"] = core["lr"]
            if "sp" in core:
                aapcs["stack_pointer"] = core["sp"]
            if "pc" in core:
                aapcs["program_counter"] = core["pc"]
            out["aapcs"] = aapcs
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="set_register",
        title="写寄存器 / 改 PC",
        description=(
            "向指定 CPU 寄存器写入值（支持 R0-R12/SP/LR/PC/xPSR，R13/R14/R15 自动映射为 SP/LR/PC）。"
            "value 可为 0x 十六进制或十进制。写后自动读回验证。用于修正现场、强制改返回值、"
            "或改 PC 跳到某函数/地址执行（改 PC 后需配合 run 继续执行）。需已进入调试状态。"
        ),
    )
    async def set_register(register: str, value: str) -> str:
        try:
            client = _get_client()
            reg = (register or "").strip().upper()
            aliases = {"R13": "SP", "R14": "LR", "R15": "PC", "XPSR": "xPSR"}
            if reg in aliases:
                reg = aliases[reg]
            if reg not in ("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                           "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC", "xPSR"):
                return _js({"ok": False, "register": register, "error": f"不支持的寄存器名: {register}"})
            vs = (value or "").strip()
            try:
                num = int(vs, 0) if vs.lower().startswith(("0x", "-0x")) else int(vs, 10)
            except ValueError:
                return _js({"ok": False, "register": reg, "error": f"无法解析数值: {value}"})
            # Keil Watch 表达式赋值（R0 = 0x...），走 CALC_EXPRESSION 求值器
            r = client.calc_expression(f"{reg} = {num}")
            if not r.get("ok"):
                r2 = client.exec_command(f"{reg} = {num}")
                if not r2.get("ok"):
                    return _js({"ok": False, "register": reg, "value": value,
                                "error": "寄存器写入失败", "detail": r2})
            check = client.calc_expression(reg)
            return _js({"ok": True, "register": reg, "set_value": "0x%x" % num,
                        "readback": check.get("value") if check.get("ok") else None,
                        "readback_ok": check.get("ok", False)})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "register": register, "error": str(e)})

    # ---------------- DWT 周期计数器（性能分析） ----------------
    # DEMCR @0xE000EDFC bit24 TRCENA、DWT_CTRL @0xE0001000 bit0 CYCCNTENA、CYCCNT @0xE0001004
    _DWT_DEMCR = 0xE000EDFC
    _DWT_CTRL = 0xE0001000
    _DWT_CYCCNT = 0xE0001004

    @staticmethod
    def _dwt_read_u32(client, addr: int):
        r = client.read_mem(addr, 4)
        if not r.get("ok"):
            return None
        # read_mem 返回小端字节序 hex，需按小端解析成 u32
        return int.from_bytes(bytes.fromhex(r["data_hex"]), "little")

    @staticmethod
    def _dwt_write_u32(client, addr: int, val: int) -> bool:
        r = client.write_mem(addr, struct.pack("<I", val & 0xFFFFFFFF))
        return bool(r.get("ok"))

    @staticmethod
    def _dwt_enable(client) -> bool:
        demcr = _dwt_read_u32(client, _DWT_DEMCR) or 0
        if not _dwt_write_u32(client, _DWT_DEMCR, demcr | 0x01000000):
            return False
        ctrl = _dwt_read_u32(client, _DWT_CTRL) or 0
        return _dwt_write_u32(client, _DWT_CTRL, ctrl | 1)

    # ---------------- HardFault / 异常现场定位 ----------------
    _FAULT_NAME = {0: "Thread(正常线程)", 1: "Reset", 2: "NMI", 3: "HardFault", 4: "MemManage",
                   5: "BusFault", 6: "UsageFault", 11: "SVCall", 12: "DebugMonitor",
                   14: "PendSV", 15: "SysTick"}

    @staticmethod
    def _reg_val(client, *cands):
        """按候选表达式顺序读寄存器/表达式的整数值，返回第一个成功的。"""
        for c in cands:
            try:
                r = client.calc_expression(c)
                if r.get("ok") and isinstance(r.get("value"), int):
                    return r["value"]
            except Exception:  # noqa: BLE001
                continue
        return None

    @staticmethod
    def _decode_cfsr(cfsr: int) -> list:
        """把 CFSR(0xE000ED28) 拆解为可读的故障原因列表。"""
        flags = []
        if cfsr & 0x01: flags.append("MMFSR:IACCVIOL 指令访问冲突")
        if cfsr & 0x02: flags.append("MMFSR:DACCVIOL 数据访问冲突")
        if cfsr & 0x08: flags.append("MMFSR:MSTKERR 异常入栈错误")
        if cfsr & 0x10: flags.append("MMFSR:MUNSTKERR 异常出栈错误")
        if cfsr & 0x100: flags.append("BFSR:IBUSERR 指令总线错误")
        if cfsr & 0x200: flags.append("BFSR:PRECISERR 精确数据总线错误")
        if cfsr & 0x400: flags.append("BFSR:IMPRECISERR 不精确数据总线错误")
        if cfsr & 0x800: flags.append("BFSR:UNSTKERR 异常出栈错误")
        if cfsr & 0x1000: flags.append("BFSR:STKERR 异常入栈错误")
        if cfsr & 0x10000: flags.append("UFSR:UNDEFINSTR 未定义指令")
        if cfsr & 0x20000: flags.append("UFSR:INVSTATE 无效执行状态")
        if cfsr & 0x40000: flags.append("UFSR:INVPC 无效PC")
        if cfsr & 0x80000: flags.append("UFSR:NOCP 无协处理器")
        if cfsr & 0x1000000: flags.append("UFSR:UNALIGNED 非对齐访问")
        if cfsr & 0x2000000: flags.append("UFSR:DIVBYZERO 除零")
        return flags

    @server.tool(
        name="dwt",
        title="DWT 周期计数器（性能分析）",
        description=(
            "读取 Cortex-M DWT->CYCCNT 周期计数器（自动使能 DWT+TRCENA）。返回当前周期计数 cycles、"
            "CPU 频率 frequency_hz 与估算的运行秒数。用法：在同一代码段 前后各调一次 dwt，"
            "执行周期数 = (cycles2 - cycles1) & 0xFFFFFFFF，耗时 = 周期数 / frequency_hz。"
            "用于测某段代码/某个函数的执行时间（如 SysTick 中断耗时、循环耗时）。需已进入调试且目标暂停。"
        ),
    )
    async def dwt() -> str:
        try:
            client = _get_client()
            _dwt_enable(client)
            cycles = _dwt_read_u32(client, _DWT_CYCCNT)
            freq = None
            try:
                f = client.calc_expression("SystemCoreClock")
                if f.get("ok") and isinstance(f.get("value"), int):
                    freq = f["value"]
            except Exception:  # noqa: BLE001
                pass
            out = {"ok": True, "cycles": cycles,
                   "frequency_hz": freq,
                   "usage": "执行周期数 = (cycles2 - cycles1) & 0xFFFFFFFF；耗时 = 周期数 / frequency_hz"}
            if freq and cycles:
                out["seconds_since_enable"] = round(cycles / freq, 6)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- ITM / Debug(printf) Viewer trace ----------------
    # ITM 寄存器（Cortex-M4）
    _ITM_DEMCR = 0xE000EDFC   # bit24 TRCENA
    _ITM_TCR = 0xE0000E80     # bit0 ITMENA, bit22 SWOENA, bit23 SYNCENA, bit1 TSENA, bits16-20 TraceBusID
    _ITM_TER = 0xE0000E00     # 每 bit 一个 stimulus port（bit0 = Port0）
    _ITM_TPR = 0xE0000E40     # 特权访问控制
    _DWT_CTRL = 0xE0001000    # bit1 CYCCNTENA 等

    @staticmethod
    def _read_u32(client, addr: int):
        r = client.read_mem(addr, 4)
        if not r.get("ok"):
            return None
        return int.from_bytes(bytes.fromhex(r["data_hex"]), "little")

    @server.tool(
        name="itm_trace",
        title="ITM / Debug(printf) Viewer trace",
        description=(
            "读取 Cortex-M ITM（Instrumentation Trace Macrocell）经 SWO 输出的调试打印数据，"
            "即 Keil 的 Debug(printf) Viewer 缓冲内容，并检查 Trace 配置是否就绪。"
            "参数 port=串口窗口编号（Debug(printf) Viewer 对应其中一个，默认 0）、"
            "size=最多读取字节数(默认4096)。返回 {config, trace}：config 给出 DEMCR.TRCENA / "
            "ITM->TCR / ITM->TER 的 Trace 使能诊断（判断为何收不到 ITM 打印）；trace 为拉取到的"
            "缓冲文本。需已进入调试；真实 ITM 输出还要求 Keil 已配置 Trace(Core Clock + "
            "Stimulus Port0) 且调试器(ST-Link/J-Link) SWO 引脚已连接。"
        ),
    )
    async def itm_trace(port: int = 0, size: int = 4096) -> str:
        try:
            client = _get_client()
            demcr = _read_u32(client, _ITM_DEMCR)
            tcr = _read_u32(client, _ITM_TCR)
            ter = _read_u32(client, _ITM_TER)
            cfg = {"demcr": demcr, "tcr": tcr, "ter": ter}
            cfg["trcena"] = bool(demcr is not None and (demcr & 0x01000000))
            cfg["itmena"] = bool(tcr is not None and (tcr & 0x01))
            cfg["swoena"] = bool(tcr is not None and (tcr & 0x00400000))
            port0_en = bool(ter is not None and (ter & 0x01))
            cfg["port0_en"] = port0_en
            # Trace 就绪诊断
            ready = cfg["trcena"] and cfg["itmena"] and cfg["swoena"] and port0_en
            cfg["ready"] = ready
            cfg["note"] = (
                "Trace 已就绪，可接收 ITM 打印。" if ready else
                "Trace 未完全就绪：请确认 Keil 已勾选 Trace 使能(Core Clock 正确、Stimulus Port0 已勾选)，"
                "并确认调试器 SWO 引脚已连接，且程序已初始化 ITM(TCR.ITMENA=1)。"
            )
            # 拉取串口窗口缓冲
            trace = client.serial_get(port=int(port), size=int(size))
            out = {"ok": trace.get("ok"), "config": cfg, "trace": trace}
            if trace.get("ok"):
                out["text"] = trace.get("ascii", "")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="fault_report",
        title="HardFault / 异常现场定位",
        description=(
            "读取 SCB 异常寄存器（ICSR/HFSR/CFSR/MMFAR/BFAR）判断当前异常类型与原因，"
            "并从异常栈帧恢复现场（异常发生时 R0-R3/R12/LR/PC/xPSR）。排查死机/跑飞/复位循环时使用："
            "先看 exception 是什么异常、cfsr.reasons 给出原因，再看 fault_frame.pc 定位出错指令。"
            "需已进入调试且停在异常处理程序（best-effort，handler 已运行时栈帧可能偏移）。"
        ),
    )
    async def fault_report() -> str:
        try:
            client = _get_client()
            icsr = _dwt_read_u32(client, 0xE000ED04) or 0
            cfsr = _dwt_read_u32(client, 0xE000ED28) or 0
            hfsr = _dwt_read_u32(client, 0xE000ED2C) or 0
            mmfar = _dwt_read_u32(client, 0xE000ED34)
            bfar = _dwt_read_u32(client, 0xE000ED38)
            vect = icsr & 0x1FF
            exc = _FAULT_NAME.get(vect, f"外部中断 IRQ{vect - 16}") if vect >= 16 \
                else _FAULT_NAME.get(vect, f"异常{vect}")
            out = {"ok": True, "exception": {"vector": vect, "name": exc}}
            reasons = _decode_cfsr(cfsr)
            out["cfsr"] = {"value": "0x%08x" % (cfsr or 0), "reasons": reasons}
            if hfsr:
                hf = []
                if hfsr & 0x40000000: hf.append("HFSR:FORCED 强制异常(由子级 fault 升级)")
                if hfsr & 0x02: hf.append("HFSR:VECTTBL 向量表错误")
                if hf: out["hardfault"] = hf
            if mmfar: out["mmfar"] = "0x%08x" % mmfar
            if bfar: out["bfar"] = "0x%08x" % bfar
            # 当前现场
            info = _build_location(client)
            if info:
                out["current"] = info
            # 异常栈帧恢复：EXC_RETURN bit2=0 用 MSP，bit2=1 用 PSP
            lr = _reg_val(client, "LR", "R14")
            out["exception_return"] = "0x%08x" % lr if lr is not None else None
            if lr is not None:
                sp_reg = "PSP" if (lr & 0x4) else "MSP"
                sp_ptr = _reg_val(client, sp_reg, "__currentSP()")
                if sp_ptr is not None:
                    # Cortex-M 异常帧：R0,R1,R2,R3,R12,LR,PC,xPSR（自低地址到高）
                    r0 = _dwt_read_u32(client, sp_ptr + 0x00) or 0
                    r1 = _dwt_read_u32(client, sp_ptr + 0x04) or 0
                    r2 = _dwt_read_u32(client, sp_ptr + 0x08) or 0
                    r3 = _dwt_read_u32(client, sp_ptr + 0x0C) or 0
                    r12 = _dwt_read_u32(client, sp_ptr + 0x10) or 0
                    flr = _dwt_read_u32(client, sp_ptr + 0x14) or 0
                    fpc = _dwt_read_u32(client, sp_ptr + 0x18) or 0
                    fxpsr = _dwt_read_u32(client, sp_ptr + 0x1C) or 0
                    out["fault_frame"] = {"stack": "0x%08x" % sp_ptr,
                                          "r0": "0x%08x" % r0, "r1": "0x%08x" % r1,
                                          "r2": "0x%08x" % r2, "r3": "0x%08x" % r3,
                                          "r12": "0x%08x" % r12, "lr": "0x%08x" % flr,
                                          "pc": "0x%08x" % fpc, "xpsr": "0x%08x" % fxpsr}
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="disassemble",
        title="反汇编指定地址",
        description=(
            "反汇编目标代码。addr 可为 十六进制地址(0x...) 或 符号名(如 'main'、'SystemClock_Config')；"
            "省略时用当前 PC。count 为反汇编的指令条数（默认 8）。返回每条指令的地址、机器码、汇编文本。"
            "排查死循环 / 跑飞 / 启动流程 / 优化后行为时，查看 PC 处指令在做什么。需已进入调试且配置 .axf。"
        ),
    )
    async def disassemble(addr: str = "", count: int = 8) -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            # 解析目标地址：显式地址 / 符号名（calc_expression &name 取址）/ 文件:行 / 当前 PC
            if (addr or "").strip():
                a = (addr or "").strip()
                base = None
                if a.lower().startswith("0x"):
                    base = int(a, 16)
                else:
                    ar = client.calc_expression(f"&{a}")
                    if ar.get("ok") and isinstance(ar.get("value"), int):
                        base = ar["value"]
                    else:
                        base = _parse_target(loc, a)  # 尝试 文件:行号
                if base is None:
                    return _js({"ok": False, "addr": a, "error": "无法解析地址（需 0x地址 或符号名）"})
            else:
                regs = client.read_cpu_registers_stable()
                if not regs.get("ok") or not isinstance(regs.get("pc"), int):
                    return _js({"ok": False, "error": "未指定地址且无法读取当前 PC"})
                base = regs["pc"]
            # 读取指令字节（每条 Thumb 指令最多 4 字节，预取足够缓冲）
            n = max(1, int(count))
            n_bytes = min(n * 4 + 16, 4096)
            r = client.read_mem(base, n_bytes)
            data_hex = r.get("data_hex") or ""
            raw = bytes.fromhex(data_hex) if data_hex else b""
            if not raw:
                return _js({"ok": False, "addr": hex(base), "error": "读取指令内存失败"})
            # capstone 反汇编（Thumb，支持 Thumb-2 混合）
            try:
                import capstone
            except ImportError as ie:  # noqa: BLE001
                return _js({"ok": False, "error": f"缺少 capstone 依赖: {ie}，请 pip install capstone"})
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            md.detail = False
            insns = []
            for ins in md.disasm(raw, base):
                insns.append({"address": f"0x{ins.address:x}",
                              "bytes": ins.bytes.hex(),
                              "mnemonic": ins.mnemonic,
                              "op_str": ins.op_str,
                              "text": f"{ins.mnemonic} {ins.op_str}".strip()})
                if len(insns) >= n:
                    break
            out = {"ok": True, "addr": hex(base), "count": len(insns)}
            # 定位起始地址对应的 文件:行
            sl = loc.addr_to_location(base) if loc else None
            if sl:
                out["file"] = sl["file"]
                out["line"] = sl["line"]
            out["instructions"] = insns
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="diagnose",
        title="一键诊断当前现场",
        description=(
            "聚合一次排查所需的所有现场信息：CPU 寄存器组(含 AAPCS 解读) + PC 处指令反汇编 + "
            "源码上下文 + 完整调用栈 + 当前函数局部变量 + 指定关键全局变量，生成结构化现场报告。"
            "AI 接到 bug 报告后一次调用即可看清程序卡在哪、寄存器状态、正在执行什么指令、谁调进来的，"
            "避免多次 get_current_location/read_registers/disassemble/read_locals 往返。"
            "globals 可选，传关键全局变量名列表。需已进入调试且配置 .axf。"
        ),
    )
    async def diagnose(globals: list = None, source_context: int = 4, disasm_count: int = 6) -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            out: dict = {"ok": True}
            # 1) 寄存器组 + AAPCS
            regs = client.read_cpu_registers()
            if regs.get("ok"):
                core = regs.get("registers") or {}
                out["registers"] = core
                aapcs = {}
                for i in range(4):
                    if f"r{i}" in core:
                        aapcs[f"arg{i+1}"] = core[f"r{i}"]
                for k, v in (("return_value", "r0"), ("return_address", "lr"),
                             ("stack_pointer", "sp"), ("program_counter", "pc")):
                    if v in core:
                        aapcs[k] = core[v]
                out["aapcs"] = aapcs
            # 2) 位置 + 源码上下文 + 完整调用栈
            info = _build_location(client)
            if info:
                out["pc"] = info.get("pc")
                out["file"] = info.get("file")
                out["line"] = info.get("line")
                out["address"] = info.get("address")
                out["source"] = info.get("source")
                out["display_path"] = info.get("display_path")
                out["callstack"] = info.get("callstack")
                if info.get("warning"):
                    out["warning"] = info["warning"]
                if info.get("hit_breakpoint"):
                    out["hit_breakpoint"] = info["hit_breakpoint"]
                pc = regs.get("pc") if regs.get("ok") else None
                # 3) PC 处反汇编（正在执行的指令）
                if isinstance(pc, int):
                    try:
                        import capstone
                        n = max(1, int(disasm_count))
                        r = client.read_mem(pc, n * 4 + 16)
                        raw = bytes.fromhex(r.get("data_hex") or "") if r.get("data_hex") else b""
                        if raw:
                            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
                            md.detail = False
                            insns = []
                            for ins in md.disasm(raw, pc):
                                insns.append({"address": f"0x{ins.address:x}",
                                              "text": f"{ins.mnemonic} {ins.op_str}".strip()})
                                if len(insns) >= n:
                                    break
                            out["disassembly"] = {"pc": hex(pc), "instructions": insns}
                    except ImportError:
                        out["disassembly"] = {"error": "缺少 capstone 依赖，跳过反汇编"}
                # 4) 当前函数局部变量
                if isinstance(pc, int):
                    names = loc.local_variables(pc)
                    if names:
                        out["locals"] = []
                        for name in names:
                            try:
                                r = client.calc_expression(name)
                                out["locals"].append({"name": name, "ok": r.get("ok"),
                                                      "value_type": r.get("value_type"),
                                                      "value": r.get("value")})
                            except Exception as ex:  # noqa: BLE001
                                out["locals"].append({"name": name, "ok": False, "error": str(ex)})
            # 5) 指定关键全局变量
            if globals:
                out["globals"] = []
                for g in globals:
                    try:
                        r = client.read_variable(str(g), read_memory=False)
                        out["globals"].append({"name": str(g), "ok": r.get("ok"),
                                               "value_type": r.get("value_type"),
                                               "value": r.get("value"),
                                               "address": r.get("address")})
                    except Exception as ex:  # noqa: BLE001
                        out["globals"].append({"name": str(g), "ok": False, "error": str(ex)})
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="run_to_line",
        title="运行到指定行",
        description=(
            "让目标运行到指定位置后停止（run to cursor）。target 可为 十六进制地址(0x...) 或"
            "文件:行号（如 main.c:77）。实现为：临时断点->运行->清除断点。"
            "需已进入调试状态且配置了 .axf 调试符号。"
        ),
    )
    async def run_to_line(target: str) -> str:
        try:
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            addr = _parse_target(loc, target)
            if addr is None:
                return _js({"ok": False, "target": target,
                            "error": "无法解析目标：需为 0x地址 或 文件:行号（如 main.c:77）"})
            client = _get_client()
            bp = client.set_breakpoint(hex(addr))
            if not bp.get("ok"):
                return _js({"ok": False, "target": target, "addr": hex(addr),
                            "error": f"设置临时断点失败: {bp}"})
            r = client.run()
            # UVSOCK 的 run(START_EXECUTION) 在运行到断点停止时会返回 BP_CREATED(22) 而非 0，
            # 视为"已运行并停在断点"，据此判定运行成功
            run_ok = r.get("ok") or r.get("status") == 22
            client.clear_breakpoint(hex(addr))
            _breakpoints[:] = [b for b in _breakpoints if b.get("expr") != hex(addr)]
            if not run_ok:
                return _js({"ok": False, "target": target, "addr": hex(addr),
                            "error": f"运行失败: {r}"})
            # run 刚停止时 PC 可能是脏值(实测=1)，用稳定读取跳过脏值得到真实停靠位置
            regs = client.read_cpu_registers_stable()
            out = {"ok": True, "target": target, "addr": hex(addr)}
            if regs.get("ok") and isinstance(regs.get("pc"), int):
                stop = loc.addr_to_location(regs["pc"])
                if stop:
                    out["stopped_file"] = stop["file"]
                    out["stopped_line"] = stop["line"]
                    src = loc.read_source(stop["file"], stop["line"], context=3)
                    if src:
                        out["stopped_source"] = src["source"]
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "target": target, "error": str(e)})

    # ---------------- 运行控制 ----------------
    @server.tool(
        name="run",
        title="全速运行",
        description="让目标 MCU 全速运行（启动执行）。",
    )
    async def run() -> str:
        try:
            return _js(_get_client().run())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="run_timeout",
        title="运行一段时间后自动暂停",
        description=(
            "让目标 MCU 全速运行 timeout_ms 毫秒后自动暂停，并返回停靠位置（文件行+源码+完整调用栈）。"
            "用于验证时序 / 观察运行 N 毫秒后的状态。timeout_ms 默认 1000。"
        ),
    )
    async def run_timeout(timeout_ms: int = 1000) -> str:
        try:
            client = _get_client()
            t = max(1, int(timeout_ms))
            r = client.run()
            if not (r.get("ok") or r.get("status") == 22):
                return _js({"ok": False, "error": f"运行失败: {r}"})
            await asyncio.sleep(t / 1000.0)
            client.stop()
            info = _build_location(client)
            out = {"ok": True, "action": "run_with_timeout", "timeout_ms": t}
            out.update(r)
            if info:
                out.update(info)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="stop",
        title="暂停执行",
        description="暂停目标 MCU 的执行（进入断点/挂起状态）。",
    )
    async def stop() -> str:
        try:
            return _js(_get_client().stop())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="reset",
        title="复位目标",
        description="复位目标 MCU。",
    )
    async def reset() -> str:
        try:
            return _js(_get_client().reset())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="step",
        title="单步执行",
        description=(
            "单步执行。mode 可选：'into'（单步进入）、'over'（单步跳过）、"
            "'out'（跳出）、'instruction'（指令级）。默认 'into'。"
        ),
    )
    async def step(mode: str = "into") -> str:
        try:
            client = _get_client()
            r = client.step(mode)
            out = dict(r)
            # 单步成功后附带当前停靠位置+源码上下文+调用栈，让 AI 立即看到进/出函数的效果
            try:
                loc = _get_locator()
                if loc and loc.is_ready():
                    info = _build_location(client)
                    if info and info.get("ok"):
                        out["pc"] = info.get("pc")
                        out["stopped_file"] = info.get("file")
                        out["stopped_line"] = info.get("line")
                        out["stopped_address"] = info.get("address")
                        if info.get("source"):
                            out["stopped_source"] = info["source"]
                            out["display_path"] = info.get("display_path")
                        if info.get("callstack"):
                            out["callstack"] = info["callstack"]
            except Exception as e:  # noqa: BLE001
                out["location_error"] = str(e)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 编译 / 烧录（UV4 命令行） ----------------
    def _resolve_project(project: str) -> str:
        """解析待操作工程：参数优先，其次服务配置的默认工程。"""
        if _builder_cfg["uv4"] is None:
            raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定编译工具路径")
        if project.strip():
            return project.strip()
        if _builder_cfg["default_project"]:
            return _builder_cfg["default_project"]
        raise RuntimeError("未指定工程路径，请传入 project 参数或配置默认工程")

    @server.tool(
        name="launch_uvision",
        description=(
            "可见方式启动 Keil uVision 并打开工程，供人工查看界面 / 调试准备。"
            "project 为 .uvprojx 路径，可省略以用默认工程；若已运行同工程则复用已有实例。"
            "用户无需手动打开 Keil，AI 可通过本工具拉起。"
        ),
    )
    async def launch_uvision(project: str = "") -> str:
        try:
            if _builder_cfg["uv4"] is None:
                raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定")
            p = _resolve_project(project)
            return _js(builder.launch_uvision(_builder_cfg["uv4"], p))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="close_uvision",
        description=(
            "关闭所有 Keil uVision 实例，配合 launch_uvision 实现 Keil 开关闭环。"
            "force 默认 False：先优雅关闭（发送关闭消息），残留则自动强制终止；"
            "force=True 直接强制结束所有 UV4.exe。注意：会关闭所有 Keil 实例。"
        ),
    )
    async def close_uvision(force: bool = False) -> str:
        try:
            return _js(builder.close_uvision(force=force))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="build_project",
        description=(
            "编译 Keil 工程（UV4 -b，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，可省略以用默认工程；"
            "target 为可选目标名。返回退出码与编译日志。"
        ),
    )
    async def build_project(project: str = "", target: str = "") -> str:
        try:
            p = _resolve_project(project)
            return _js(builder.build_project(_builder_cfg["uv4"], p, target.strip() or None))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="rebuild_project",
        description=(
            "重新编译 Keil 工程（UV4 -r，全量重编，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，"
            "可省略以用默认工程；target 为可选目标名。"
        ),
    )
    async def rebuild_project(project: str = "", target: str = "") -> str:
        try:
            p = _resolve_project(project)
            return _js(builder.rebuild_project(_builder_cfg["uv4"], p, target.strip() or None))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="flash_download",
        description=(
            "烧录 Keil 工程到目标 Flash（UV4 -f，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，"
            "可省略以用默认工程；target 为可选目标名。"
        ),
    )
    async def flash_download(project: str = "", target: str = "") -> str:
        try:
            p = _resolve_project(project)
            return _js(builder.flash_download(_builder_cfg["uv4"], p, target.strip() or None))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="build_and_flash",
        description=(
            "编译并烧录闭环（后台隐藏窗口，不闪现界面）：先编译，成功后才烧录（UV4 -b 成功后 -f）。"
            "project 为 .uvprojx 路径，可省略以用默认工程；target 为可选目标名。"
        ),
    )
    async def build_and_flash(project: str = "", target: str = "") -> str:
        try:
            p = _resolve_project(project)
            return _js(builder.build_and_flash(_builder_cfg["uv4"], p, target.strip() or None))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="flash_debug",
        description=(
            "「关旧 Keil→编烧→开新→进调试」一体闭环：先关闭所有 Keil 实例（避免残留旧工程窗口导致调试到旧代码），"
            "再编译并烧录新固件，成功后重新以可见方式打开本工程并自动进入调试模式。"
            "适用于 AI 修改代码后需上板验证新代码的完整流程，规避「旧窗口调试旧代码」问题。"
            "project 为 .uvprojx 路径，可省略用默认工程；target 为可选目标名。"
        ),
    )
    async def flash_debug(project: str = "", target: str = "") -> str:
        try:
            p = _resolve_project(project)
            uv4 = _builder_cfg["uv4"]
            if uv4 is None:
                raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定")
            # 1) 关闭所有 Keil 实例，确保后续用干净实例加载新固件
            close = builder.close_uvision(force=False)
            # 2) 编译 + 烧录新固件
            bf = builder.build_and_flash(uv4, p, target.strip() or None)
            if not bf.get("ok"):
                return _js({
                    "ok": False, "action": "flash_debug", "stage": "编译烧录",
                    "close_uvision": close, "build_flash": bf,
                    "status_text": "编译/烧录未通过，未重开工程进入调试",
                })
            # 3) 重新打开本工程（干净实例，加载新固件符号）
            launch = builder.launch_uvision(uv4, p)
            # 4) 进入调试：Keil 启动需时间，对连接类错误做短暂重试
            client = _get_client()
            enter = None
            last_error = None
            for _ in range(8):
                try:
                    enter = client.enter_debug()
                    break
                except UVSOCKConnectError as e:  # Keil 尚未就绪 / UVSOCK 未开启
                    last_error = str(e)
                    await asyncio.sleep(1)
                except Exception as e:  # noqa: BLE001 其他错误立即返回
                    last_error = str(e)
                    break
            if enter is None:
                enter = {"ok": False, "error": last_error or "进入调试失败"}
            return _js({
                "ok": enter.get("ok", False),
                "action": "flash_debug", "stage": "调试",
                "close_uvision": close,
                "build": bf.get("build"), "flash": bf.get("flash"),
                "launch_uvision": launch, "enter_debug": enter,
                "status_text": ("已重新打开工程并进入调试" if enter.get("ok")
                                else "已重新打开工程，但进入调试失败，请检查 UVSOCK 是否开启"),
            })
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @staticmethod
    def _periph_read_u32(client, addr: int):
        """按小端解析读取外设寄存器 32 位值，失败返回 None。"""
        r = client.read_mem(addr, 4)
        if not r.get("ok"):
            return None
        return int.from_bytes(bytes.fromhex(r["data_hex"]), "little")

    @server.tool(
        name="list_peripherals",
        title="列出可用外设寄存器表",
        description=(
            "列出 mdkdebug 内置的 STM32F4 常用外设（RCC/GPIOA-H/USART/SPI/I2C/TIM/ADC/"
            "PWR/FLASH/SysTick/SCB/NVIC/DWT/EXTI/SYSCFG 等）及基址，供 read_peripheral 使用。"
        ),
    )
    async def list_peripherals() -> str:
        return _js({"ok": True, "count": len(_periph_list()), "peripherals": _periph_list()})

    @server.tool(
        name="read_peripheral",
        title="读取外设寄存器组（SFR）",
        description=(
            "一键读取指定外设（如 RCC/GPIOA/USART1/SPI1/I2C1/TIM2/ADC1/SCB/SysTick）的全部寄存器当前值，"
            "并解析关键位域（时钟使能/波特率/GPIO 模式/定时器计数等）。"
            "排查时钟没使能、GPIO 模式配置错误、串口波特率不对、定时器计数是否跑起来等场景。"
            "需已进入调试状态。periph 为外设名（大小写不敏感）。"
        ),
    )
    async def read_peripheral(periph: str) -> str:
        try:
            client = _get_client()
            p = _periph_get(periph)
            if not p:
                avail = ", ".join(x["name"] for x in _periph_list())
                return _js({"ok": False, "error": f"未知外设 {periph}，可用: {avail}"})
            regs: list = []
            for name, rdef in p["regs"].items():
                addr = p["base"] + rdef["off"]
                val = _periph_read_u32(client, addr)
                if val is None:
                    regs.append({"reg": name, "addr": f"0x{addr:X}", "value": None})
                    continue
                entry = {"reg": name, "addr": f"0x{addr:X}", "value": f"0x{val:08X}", "raw": val}
                # 关键位域解读
                bits = []
                for fname, lsb, width, enum in rdef.get("fields", []):
                    fval = (val >> lsb) & ((1 << width) - 1)
                    item = {"name": fname, "bits": f"{lsb}+{width}", "value": fval}
                    if enum is not None:
                        desc = enum.get(fval)
                        if desc is not None:
                            item["desc"] = desc
                    bits.append(item)
                if bits:
                    entry["fields"] = bits
                regs.append(entry)
            return _js({"ok": True, "peripheral": p["name"], "base": f"0x{p['base']:08X}",
                        "desc": p["desc"], "reg_count": len(regs), "regs": regs})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "periph": periph, "error": str(e)})

    async def _wait_stopped(client, timeout: float = 8.0) -> bool:
        """轮询等待目标停止（running 变为 False），超时返回 False。

        先确认目标进入过运行态（见过 running=True），再等其停止；避免 run/step 命令
        刚发出时首次 get_status 读到旧的停止态而误判，导致随后读内存撞上目标正在运行
        的竞态（AMEM 响应异常）。若一直未见过运行态（run 未生效或目标立即停在很近的
        断点），连续若干次未运行也视为已停止。
        """
        import time as _t
        deadline = _t.monotonic() + timeout
        seen_running = False
        stable_stopped = 0
        while _t.monotonic() < deadline:
            st = client.get_status()
            if st.get("running") is True:
                seen_running = True
                stable_stopped = 0
            else:  # running False
                if seen_running:
                    return True
                stable_stopped += 1
                if stable_stopped >= 3:
                    # run 未生效或目标立即停在很近断点：目标确为停止态，读内存安全
                    return True
            await asyncio.sleep(0.1)
        return False

    # ---------------- 批次4-1：内存地图 / 搜索 / 填充 ----------------
    @server.tool(
        name="query_memory_map",
        title="查询内存区域地图",
        description=(
            "返回目标 STM32 的内存布局（FLASH/SRAM1/2/APB1/APB2/AHB1/AHB2/ITM/DWT/SCS 地址范围），"
            "可用 addr 参数标注某地址落在哪个区域。在 read_mem/write_mem/fill_mem 前调用，"
            "避免把外设区当 RAM 读或把越界地址当合法地址。addr 为空返回全部区域。"
        ),
    )
    async def query_memory_map(addr: str = "") -> str:
        try:
            a = _parse_addr(addr) if addr else None
            return _js(_query_memory_map(a))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="search_mem",
        title="在内存范围内搜索字节序列",
        description=(
            "在 [start,end) 地址范围内扫描十六进制字节序列（pattern_hex，如 'DEADBEEF'），"
            "返回所有命中地址（分块读、块间重叠防跨块漏匹配）。用于找魔数、定位被越界写坏的缓冲、"
            "搜索特定数据结构。需已进入调试。start/end 用 0x 十六进制。"
        ),
    )
    async def search_mem(start: str, end: str, pattern_hex: str, max_results: int = 20) -> str:
        try:
            client = _get_client()
            try:
                pattern = bytes.fromhex((pattern_hex or "").replace(" ", "").replace("0x", ""))
            except ValueError:
                return _js({"ok": False, "error": "pattern_hex 非法，须为偶数个十六进制字符"})
            if not pattern:
                return _js({"ok": False, "error": "pattern_hex 不能为空"})
            return _js(client.search_mem(_parse_addr(start), _parse_addr(end), pattern, max_results))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="fill_mem",
        title="批量填充/清零内存",
        description=(
            "从 addr 起连续写入 count 个相同字节（byte 为 0~255 单字节值）。用于清零大块缓冲、"
            "SRAM 初始化、批量回填等。需已进入调试。addr 用 0x 十六进制。"
        ),
    )
    async def fill_mem(addr: str, byte: int, count: int) -> str:
        try:
            client = _get_client()
            return _js(client.fill_mem(_parse_addr(addr), int(byte), int(count)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次4-2：状态对比 / 函数耗时 ----------------
    @server.tool(
        name="snapshot_diff",
        title="对比调试状态快照（diff）",
        description=(
            "记录/对比调试状态的基线：首次调用创建基线（保存指定 globals 与 PC/LR/SP 寄存器），"
            "之后调用对比当前状态，输出 changed/unchanged/unreadable。用于观察程序运行后哪些变量/"
            "寄存器发生变化，定位被意外改写的状态。globals 传变量名列表（如 ['SystemCoreClock']）。"
            "需已进入调试且配置 .axf。"
        ),
    )
    async def snapshot_diff(globals: list = None) -> str:
        global _snapshot_baseline
        try:
            client = _get_client()
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            regs = client.read_cpu_registers_stable()
            if not regs.get("ok"):
                return _js({"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试）", "detail": regs})
            g = {}
            for name in (globals or []):
                try:
                    r = client.read_variable(str(name), read_memory=False)
                    g[str(name)] = {"ok": r.get("ok"), "value": r.get("value"),
                                    "value_type": r.get("value_type")}
                except Exception as ex:  # noqa: BLE001
                    g[str(name)] = {"ok": False, "error": str(ex)}
            current = {"globals": g, "registers": dict(regs.get("registers") or {})}
            if _snapshot_baseline is None:
                _snapshot_baseline = current
                return _js({"ok": True, "created": True,
                            "message": "已创建基线快照（再次调用对比变化）",
                            "globals_count": len(g)})
            base = _snapshot_baseline
            changed, unchanged, unreadable = [], [], []
            allg = set(base["globals"]) | set(g)
            for name in sorted(allg):
                b = base["globals"].get(name, {})
                c = g.get(name, {})
                if not b.get("ok") or not c.get("ok"):
                    unreadable.append(name)
                elif b.get("value") != c.get("value"):
                    changed.append({"name": name, "before": b.get("value"),
                                    "after": c.get("value")})
                else:
                    unchanged.append(name)
            reg_changed = []
            for k in sorted(set(base["registers"]) | set(current["registers"])):
                bv = base["registers"].get(k)
                cv = current["registers"].get(k)
                if bv != cv:
                    reg_changed.append({"reg": k, "before": bv, "after": cv})
            return _js({"ok": True, "created": False,
                        "changed_globals": changed, "unchanged_globals": unchanged,
                        "unreadable": unreadable,
                        "changed_registers": reg_changed})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="profile_function",
        title="函数执行耗时（周期数）分析",
        description=(
            "测量指定函数（func 传函数名或 0x 入口地址）一次调用的执行周期数：自动设入口断点、"
            "运行到入口记录 DWT CYCCNT、step out 返回调用者后再记录，求差值。用于函数级性能分析、"
            "对比优化前后耗时。依赖 DWT 周期计数器（Cortex-M3/M4 内置）。"
            "需已进入调试且函数当前未被占用。"
        ),
    )
    async def profile_function(func: str, max_ms: int = 10000) -> str:
        try:
            client = _get_client()
            addr = None
            f = (func or "").strip()
            if not f:
                return _js({"ok": False, "error": "func 不能为空"})
            if f.lower().startswith("0x"):
                try:
                    addr = int(f, 16)
                except ValueError:
                    addr = None
            else:
                ar = client.calc_expression(f)
                if ar.get("ok") and isinstance(ar.get("value"), int):
                    addr = ar["value"]
            if addr is None:
                return _js({"ok": False, "error": f"无法解析函数入口地址: {f}"})
            if not _dwt_enable(client):
                return _js({"ok": False, "error": "无法使能 DWT CYCCNT"})
            bp_expr = hex(addr)
            client.set_breakpoint(bp_expr)
            # Keil 会异步推送“断点已设”消息，若立即 run，该消息与 run 响应错位导致 status 乱码
            await asyncio.sleep(0.2)
            r = client.run()
            if not (r.get("ok") or r.get("status") == 22):
                client.clear_breakpoint(bp_expr)
                return _js({"ok": False, "error": f"运行失败: {r}"})
            if not await _wait_stopped(client, max_ms / 1000.0):
                client.stop()
                client.clear_breakpoint(bp_expr)
                return _js({"ok": False, "error": f"运行 {max_ms}ms 未到达函数入口（函数可能未被调用）"})
            t0 = _dwt_read_u32(client, _DWT_CYCCNT) or 0
            client.clear_breakpoint(bp_expr)
            # 清断点同样触发“断点删除”异步消息，立即 step 会与响应错位
            await asyncio.sleep(0.2)
            so = client.step("out")
            if not so.get("ok"):
                return _js({"ok": False, "error": f"step out 失败: {so}"})
            if not await _wait_stopped(client, max_ms / 1000.0):
                client.stop()
                return _js({"ok": False, "error": "step out 超时"})
            t1 = _dwt_read_u32(client, _DWT_CYCCNT) or 0
            cycles = (t1 - t0) & 0xFFFFFFFF
            info = _build_location(client)
            out = {"ok": True, "function": f, "entry": hex(addr),
                   "cycles": cycles, "cycles_hex": hex(cycles)}
            if info:
                out.update(info)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次4-3：编译错误 / map 解析 ----------------
    @server.tool(
        name="parse_build_errors",
        title="解析编译错误输出",
        description=(
            "把 build/rebuild 输出的错误/警告文本解析为结构化列表（文件:行:列 + 消息），"
            "兼容 ARMCC5(AC5) 'path(line): error:' 与 ARMCLANG(AC6) 'path:line:col: error:' 两种格式，"
            "并用 .axf 符号表尝试把文件定位到源码路径。errors_text 传入 build 工具返回的错误信息。"
        ),
    )
    async def parse_build_errors(errors_text: str) -> str:
        import re
        try:
            loc = _get_locator()
            text = errors_text or ""
            # ARMCLANG (AC6): path\file.c:12:5: error: message
            ac6 = re.findall(r'^(.+?\.(?:c|h|cpp|s|S)):(\d+):(\d+):\s*(error|warning):\s*(.+)$',
                             text, re.M)
            # ARMCC5 (AC5): path\file.c(12): error:  message
            ac5 = re.findall(r'^(.+?\.(?:c|h|cpp|s|S))\((\d+)\):\s*(error|warning):\s*(.+)$',
                             text, re.M)
            items = []
            for m in ac6:
                file, line, col, lvl, msg = m
                resolved = loc.resolve_source_path(file) if loc else file
                items.append({"file": resolved, "line": int(line), "column": int(col),
                              "level": lvl, "message": msg.strip()})
            for m in ac5:
                file, line, lvl, msg = m
                resolved = loc.resolve_source_path(file) if loc else file
                items.append({"file": resolved, "line": int(line), "column": None,
                              "level": lvl, "message": msg.strip()})
            errors = [x for x in items if x["level"] == "error"]
            warnings = [x for x in items if x["level"] == "warning"]
            return _js({"ok": True, "count": len(items),
                        "error_count": len(errors), "warning_count": len(warnings),
                        "items": items})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="parse_map",
        title="解析 .map 链接映射文件",
        description=(
            "解析当前工程的 .map 文件（由 .axf 同目录推断），返回 program_size、各 section 占用、"
            "符号地址表、栈使用、未使用 section。用于检查 FLASH/RAM 占用、确认符号地址、分析栈溢出风险。"
            "需已 build 生成 .map 文件且已配置 .axf。"
        ),
    )
    async def parse_map() -> str:
        try:
            path = _resolve_map()
            if not path:
                return _js({"ok": False, "error": "未找到 .map 文件（请先 build_project 生成，"
                            "并确保已配置 .axf）"})
            data = mapfile.parse_map_file(path)
            return _js({**data, "path": path})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次4-4：写外设 / 异常等待 ----------------
    @server.tool(
        name="write_peripheral",
        title="写入外设寄存器",
        description=(
            "向指定外设（如 GPIOA/USART1/RCC/TIM2）的单个寄存器写值（value 可为 0x 十六进制或十进制），"
            "写后立即读回确认。用于置位时钟使能、改 GPIO 模式、配置波特率、修改定时器寄存器等。"
            "需已进入调试。periph 为外设名，reg 为寄存器名（大小写不敏感）。"
        ),
    )
    async def write_peripheral(periph: str, reg: str, value: str) -> str:
        try:
            client = _get_client()
            p = _periph_get(periph)
            if not p:
                avail = ", ".join(x["name"] for x in _periph_list())
                return _js({"ok": False, "error": f"未知外设 {periph}，可用: {avail}"})
            rkey = None
            for k in p["regs"]:
                if k.lower() == (reg or "").lower():
                    rkey = k
                    break
            if not rkey:
                avail = ", ".join(p["regs"].keys())
                return _js({"ok": False, "error": f"外设 {p['name']} 无寄存器 {reg}，可用: {avail}"})
            rdef = p["regs"][rkey]
            addr = p["base"] + rdef["off"]
            val = _parse_addr(value)
            wr = client.write_mem(addr, struct.pack("<I", val & 0xFFFFFFFF))
            if not wr.get("ok"):
                return _js({"ok": False, "peripheral": p["name"], "reg": rkey,
                            "addr": f"0x{addr:X}", "error": wr.get("status_text")})
            rv = _periph_read_u32(client, addr)
            return _js({"ok": True, "peripheral": p["name"], "reg": rkey,
                        "addr": f"0x{addr:X}", "written": f"0x{val:08X}",
                        "readback": f"0x{rv:08X}" if rv is not None else None,
                        "match": rv == val})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="wait_fault",
        title="运行至异常/断点并自动诊断",
        description=(
            "运行目标并轮询等待其停止（timeout_ms 内），若停在异常（HardFault/BusFault/UsageFault/"
            "MemManage 等）则自动读取 ICSR/CFSR 判断异常类型并收集现场（寄存器+调用栈）；"
            "若停在断点则返回停靠位置。用于复现崩溃：启动后等待崩溃发生并自动抓取现场。"
            "需已进入调试且配置 .axf。"
        ),
    )
    async def wait_fault(timeout_ms: int = 10000) -> str:
        try:
            client = _get_client()
            r = client.run()
            if not (r.get("ok") or r.get("status") == 22):
                return _js({"ok": False, "error": f"运行失败: {r}"})
            t = max(1, int(timeout_ms))
            if not await _wait_stopped(client, t / 1000.0):
                client.stop()
                return _js({"ok": False, "error": f"运行 {timeout_ms}ms 未停止（未复现异常/未命中断点）"})
            icsr = _dwt_read_u32(client, 0xE000ED04) or 0
            vect = icsr & 0x1FF
            exc = _FAULT_NAME.get(vect, f"异常{vect}")
            cfsr = _dwt_read_u32(client, 0xE000ED28) or 0
            out = {"ok": True, "action": "wait_fault",
                   "exception": {"vector": vect, "name": exc},
                   "is_fault": vect in (3, 4, 5, 6)}
            if cfsr:
                out["cfsr"] = {"value": "0x%08x" % cfsr, "reasons": _decode_cfsr(cfsr)}
            info = _build_location(client)
            if info:
                out.update(info)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次5：批量命令 / 多 target / 工程配置 ----------------
    @server.tool(
        name="read_mem_multi",
        title="一次读取多个地址的内存",
        description=(
            "批量读内存：addresses 传地址列表，每项为 {addr, n_bytes}（n_bytes 缺省 32）。"
            "一次 MCP 往返读多个地址，减少 AI 连续调用 read_mem 的往返。返回每处 ok/data_hex/ascii。"
        ),
    )
    async def read_mem_multi(addresses: list) -> str:
        try:
            client = _get_client()
            results = []
            for item in addresses or []:
                if isinstance(item, dict):
                    addr = item.get("addr", item.get("address", ""))
                    size = int(item.get("n_bytes", item.get("size", 32)) or 32)
                else:
                    addr, size = item, 32
                a = _parse_addr(addr)
                m = client.read_mem(a, size)
                results.append({"addr": hex(a), "size": size, "ok": m.get("ok", False),
                                "data_hex": m.get("data_hex", ""), "ascii": m.get("ascii", "")})
            return _js({"ok": True, "count": len(results), "results": results})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="batch",
        title="批量执行多条读类命令",
        description=(
            "一次提交多条只读命令，聚合返回，减少 AI 往返。commands 为列表，每项 "
            "{tool, args}。支持 read_mem(addr/n_bytes)/read_variable(name)/"
            "calc_expression(expr)/get_status/read_registers。返回每条 ok 与结果。"
        ),
    )
    async def batch(commands: list) -> str:
        try:
            client = _get_client()
            results = []
            for c in commands or []:
                tool = (c or {}).get("tool", "")
                args = (c or {}).get("args", {}) or {}
                one = {"tool": tool, "ok": False}
                try:
                    if tool == "read_mem":
                        a = _parse_addr(args.get("addr", args.get("address", "")))
                        n = int(args.get("n_bytes", args.get("size", 32)) or 32)
                        m = client.read_mem(a, n)
                        one.update({"addr": hex(a), "n_bytes": n,
                                    "data_hex": m.get("data_hex", ""), "ascii": m.get("ascii", ""),
                                    "ok": m.get("ok", False)})
                    elif tool == "read_variable":
                        one.update(client.read_variable(args.get("name", "")))
                    elif tool == "calc_expression":
                        one.update(client.calc_expression(args.get("expr", "")))
                    elif tool == "get_status":
                        one.update(client.get_status())
                    elif tool == "read_registers":
                        one.update(client.read_cpu_registers_stable())
                    else:
                        one["error"] = f"batch 不支持工具: {tool}"
                except Exception as e:  # noqa: BLE001
                    one["error"] = str(e)
                results.append(one)
            return _js({"ok": True, "count": len(results), "results": results})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="project_targets",
        title="枚举工程 target 与当前/调试目标",
        description=(
            "查询当前工程全部 target（UV_PRJ_ENUM_TARGETS）、当前 target（GET_CUR_TARGET）"
            "与当前调试 target（GET_DEBUG_TARGET）。多 target 工程排查/切换前先调它确认目标清单。"
        ),
    )
    async def project_targets(project: str = "") -> str:
        try:
            client = _get_client()
            cur = client.get_cur_target()
            en = client.enum_targets()
            dbg = client.get_debug_target()
            targets = en.get("targets", [])
            src = "uvsock"
            if not targets:
                # 真实 Keil UV_PRJ_ENUM_TARGETS 常返回空 data，回退从 .uvprojx 解析 target 列表
                p = (project or "").strip() or _builder_cfg.get("default_project", "")
                if p:
                    cfg = _parse_uvprojx_config(p)
                    if cfg.get("ok"):
                        targets = [t["name"] for t in cfg.get("targets", [])]
                        src = "uvprojx"
            out = {"ok": cur.get("ok") or en.get("ok"),
                   "current_target": cur.get("target", ""),
                   "debug_target": dbg.get("target", ""),
                   "targets": targets, "targets_source": src,
                   "detail": {"cur": cur, "enum": en, "debug": dbg}}
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="set_debug_target",
        title="切换调试 target",
        description=(
            "设置当前调试 target（UV_PRJ_SET_DEBUG_TARGET），target 传 target 名或索引。"
            "多 target 工程切换调试目标后再 enter_debug。"
        ),
    )
    async def set_debug_target(target: str) -> str:
        try:
            client = _get_client()
            return _js(client.set_debug_target(target))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_project_config",
        title="读取工程配置（编译宏/优化级别）",
        description=(
            "解析 .uvprojx 各 target 的编译器（AC5/AC6）、优化级别（-O0..-Otime）、编译宏 Define、"
            "包含路径。project 传 .uvprojx 路径（省略用默认工程），target 指定某 target（省略用第一个）。"
            "排查“不同 target 行为不同”时对比宏/优化差异。"
        ),
    )
    async def read_project_config(project: str = "", target: str = "") -> str:
        try:
            p = (project or "").strip() or _builder_cfg.get("default_project", "")
            if not p:
                return _js({"ok": False, "error": "未提供工程路径，且未配置默认工程"})
            cfg = _parse_uvprojx_config(p, target.strip() or None)
            cfg["project"] = p
            return _js(cfg)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    return server


async def run_stdio(host: str = "127.0.0.1", port: int = 4823,
                    idle_timeout: float = 30.0,
                    uv4_path: str | None = None,
                    default_project: str | None = None,
                    axf_path: str | None = None) -> None:
    """以标准输入/输出方式运行（MCP 客户端常用方式）。"""
    server = create_server(host=host, port=port, idle_timeout=idle_timeout,
                           uv4_path=uv4_path, default_project=default_project,
                           axf_path=axf_path)
    await server.run_stdio_async()


async def run_http(host: str = "127.0.0.1", port: int = 4823,
                   idle_timeout: float = 30.0,
                   http_host: str = "127.0.0.1", http_port: int = 8300,
                   uv4_path: str | None = None,
                   default_project: str | None = None,
                   axf_path: str | None = None) -> None:
    """以 Streamable HTTP 方式运行（可被远程/浏览器 MCP 客户端连接）。"""
    import uvicorn
    server = create_server(host=host, port=port, idle_timeout=idle_timeout,
                           uv4_path=uv4_path, default_project=default_project,
                           axf_path=axf_path)
    app = server.streamable_http_app()
    config = uvicorn.Config(app, host=http_host, port=http_port, log_level="info")
    uvicorn.Server(config).run()
