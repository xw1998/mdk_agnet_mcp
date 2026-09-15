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
import sys
import xml.etree.ElementTree as ET

from mcp.server.mcpserver import MCPServer

from .client import UVClient, UVSOCKConnectError
from .locator import Locator
from . import builder, __version__

logger = logging.getLogger("mdkdebug.server")

# 全局共享一个带连接缓存的客户端（线程安全）
_client: UVClient | None = None
# 编译/烧录配置（UV4.exe 路径与默认工程）
_builder_cfg = {"uv4": None, "default_project": None}
# 符号定位配置（.axf 路径与 Locator 实例）
_symbol_cfg = {"locator": None, "axf": None}
_breakpoints: list = []  # 内部断点记录（expr/address/file/line），因 BL 输出不经 socket 回传

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

def _get_locator() -> Locator | None:
    return _symbol_cfg.get("locator")

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
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号，或未从工程推断到）"})
            client = _get_client()
            # 用稳定读取跳过 run 刚停止时的脏 PC 值
            regs = client.read_cpu_registers_stable()
            if not regs.get("ok"):
                return _js({"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试）", "detail": regs})
            pc = regs.get("pc"); lr = regs.get("lr")
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
            callstack = []
            if cur:
                callstack.append({"level": 0, "pc": hex(pc), "file": cur["file"], "line": cur["line"]})
            if isinstance(lr, int):
                lrc = loc.addr_to_location(lr)
                if lrc:
                    callstack.append({"level": 1, "pc": hex(lr), "file": lrc["file"], "line": lrc["line"]})
            result["callstack"] = callstack
            return _js(result)
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
            return _js(_get_client().step(mode))
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
