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
import time
import xml.etree.ElementTree as ET

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .client import UVClient, UVSOCKConnectError
from .locator import Locator
from . import builder, mapfile, winutil, uvoptx as _uvoptx, __version__
from . import serialmon
from . import aliases as _aliases
from .periph import (list_peripherals as _periph_list, get_peripheral as _periph_get,
                     query_memory_map as _query_memory_map)

logger = logging.getLogger("mdkdebug.server")


def _csv_tokens(value, sep_extra=";|"):
    """把「逗号分隔字符串」参数归一化为 token 列表，兼容调用方直接传数组。

    用户反馈（第 8 轮）：read_peripheral 的 regs 传 ["MODER","ODR"] 会崩——内部直接对
    参数调 .replace，报 'list' object has no attribute 'replace'。AI 的直觉写法就是给
    列表，故这里统一兼容 str / list / tuple / set（数组元素再按分隔符拆一遍），
    其余类型转字符串；同时兼容分号/竖线/空格分隔。返回保持原样大小写，由调用方决定大小写策略。
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        items = []
        for x in value:
            items.extend(str(x).split(","))
        raw = ",".join(items)
    elif isinstance(value, str):
        raw = value
    else:
        raw = str(value)
    for ch in sep_extra:
        raw = raw.replace(ch, ",")
    # 兼容「用空格分隔」的写法（regs="MODER ODR"）
    raw = raw.replace(" ", ",")
    return [x.strip() for x in raw.split(",") if x.strip()]

def _items_arg(value):
    """「结构化列表」参数的类型兼容：数组 / JSON 数组字符串 / 分隔符字符串。

    第 9 轮通则：所有接受「列表」的参数都同时接受数组与分隔符字符串，不要让 AI 靠报错
    学习签名。用于 read_mem_multi.addresses、batch.commands 这类元素为对象的列表参数：
    - 数组 / 元组 / 集合：原样返回
    - JSON 字符串（以 [ 或 { 开头）：json.loads 解析
    - 其余字符串：按逗号/分号/竖线/空格拆成 token，元素再按各自类型处理
    解析失败时抛 ValueError，由调用方转成带说明的 error 返回。
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        if s[:1] in "[{":
            try:
                loaded = json.loads(s)
            except Exception as e:  # noqa: BLE001
                raise ValueError(
                    "参数是字符串且看起来像 JSON，但解析失败：%s"
                    "（请改为规范的 JSON 数组，或直接用数组写法）" % e)
            if isinstance(loaded, (list, tuple)):
                return list(loaded)
            return [loaded]
        return _csv_tokens(s)
    return [value]

def _addr_arg(value):
    """地址/表达式类参数的类型兼容：整数地址也能直接用。

    真机实测（批次25）：AI 的直觉写法是 read_mem(addr=0x20000000)，而工具签名声明为
    字符串，会被框架直接判为类型错误（Input should be a valid string）。内部
    _parse_addr / _resolve_addr_arg 本来就接受 int，这里把入口也放开：
    - int / float：转为 "0xXXXX" 字符串（下游按十六进制解析，语义等价）
    - 字符串：原样 strip（"0x.."、十进制串、符号名、表达式都照旧）
    - None：空串
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, int):
        return "0x%X" % value
    if isinstance(value, float):
        return "0x%X" % int(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "ignore")
    return str(value).strip()

# 全局共享一个带连接缓存的客户端（线程安全）
_client: UVClient | None = None
# 编译/烧录配置（UV4.exe 路径与默认工程）
_builder_cfg = {"uv4": None, "default_project": None}
# 符号定位配置（.axf 路径与 Locator 实例）
_symbol_cfg = {"locator": None, "axf": None, "source_type": None}
# 预登记候选符号工程注册表：AI 可据此切换/自动匹配当前调试固件的符号文件。
# flash 区段用于 PC 自动匹配（辅助定位，固件 flash 可能重叠，手动 set_symbol_file 为主）。
#
# 为开源跨机可用，本表【不写死任何本机绝对路径】：
#   - 仓库内置工程（mdk_test）用相对仓库根推导，clone 后编译出 .axf 即自动可用；
#   - 本机/外部工程（如 SVCRTOS_TEST 内核）通过启动参数 --symbol-project 或环境变量
#     MDKDEBUG_SYMBOL_PROJECTS（JSON 数组）注入追加，不硬编码进代码。
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _builtin_symbol_projects() -> list:
    """仓库内置符号工程：mdk_test（相对仓库根推导，跨机 clone 编译后即用）。"""
    base = os.path.join(_REPO_ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test")
    return [{
        "name": "mdk_test",
        "axf": os.path.join(base, "mdk_test.axf"),
        "map": os.path.join(base, "mdk_test.map"),
        "flash_start": 0x08000000, "flash_size": 0x80000,
    }]


def _symbol_projects_from_env() -> list:
    """从环境变量 MDKDEBUG_SYMBOL_PROJECTS 读取追加的符号工程（JSON 数组，每项含
    name/axf/map/flash_start/flash_size）。用于注入本机/外部工程而不改代码。"""
    raw = os.environ.get("MDKDEBUG_SYMBOL_PROJECTS")
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            logger.warning("MDKDEBUG_SYMBOL_PROJECTS 应为 JSON 数组，已忽略")
            return []
        return [p for p in data if isinstance(p, dict) and p.get("name")]
    except Exception as e:  # noqa: BLE001
        logger.warning("MDKDEBUG_SYMBOL_PROJECTS 解析失败: %s", e)
        return []


_SYMBOL_PROJECTS: list = _builtin_symbol_projects()
_breakpoints: list = []  # 内部断点记录（id/expr/address/file/line），因 BL 输出不经 socket 回传
_bp_counter: int = 0  # 断点/数据断点 id 自增
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
    另解析 <Utilities><Flash1><UpdateFlashBeforeDebugging>：=1 表示 Keil 在进入调试前会自动把
    最新 .axf 下载进 Flash（等价一次烧录），据此可省掉显式的 UV4 -f 烧录。
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
        # 「调试前更新目标」：Keil 的 Utilities 页选项，勾选时进入调试会自动下载程序到 Flash
        ufbd = (t.findtext(".//Utilities/Flash1/UpdateFlashBeforeDebugging") or "").strip()
        info = {
            "name": name,
            "compiler": "ARMCLANG(AC6)" if uac6 == "1" else "ARMCC(AC5)",
            "uAC6": uac6,
            "optimization": optim,
            "optimization_level": _OPTIM_TEXT.get(optim, f"-O{optim}" if optim.isdigit() else ""),
            "defines": cdefs,
            "include_paths": inc,
            "update_flash_before_debugging": (ufbd == "1") if ufbd in ("0", "1") else None,
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


# ---------------- 批次6：器件信息 / 采样剖析 / 环境自检 辅助 ----------------

# STM32F4 常见 DEV_ID（DBGMCU->IDCODE 低 16 位）→ 型号与标称 Flash/RAM（KB）
_DEV_ID_MAP = {
    0x413: {"name": "STM32F405/407/415/417", "flash_kb": 1024, "ram_kb": 192},
    0x419: {"name": "STM32F427/437/429/439", "flash_kb": 2048, "ram_kb": 256},
    0x423: {"name": "STM32F401xB/C",         "flash_kb": 512,  "ram_kb": 96},
    0x431: {"name": "STM32F411xE",            "flash_kb": 512,  "ram_kb": 128},
    0x441: {"name": "STM32F412",              "flash_kb": 1024, "ram_kb": 256},
    0x421: {"name": "STM32F446",              "flash_kb": 512,  "ram_kb": 128},
    0x434: {"name": "STM32F469/479",          "flash_kb": 2048, "ram_kb": 384},
    0x458: {"name": "STM32F410",              "flash_kb": 128,  "ram_kb": 32},
    0x433: {"name": "STM32F4(DE变体)",        "flash_kb": None, "ram_kb": None},
    0x463: {"name": "STM32F413/423",          "flash_kb": 1536, "ram_kb": 320},
}
_DEV_ID_CODE_BASE = 0x08000000
_DEV_ID_DBGMCU_BASE = 0xE0042000  # DBGMCU 外设基址（Cortex-M4）
_RTOS_MARKERS = {
    "FreeRTOS": ["pxCurrentTCB", "pxReadyTasksLists", "uxCurrentNumberOfTasks"],
    "RT-Thread": ["rt_current_thread", "rt_thread_priority_table", "rt_object_attach_hook"],
    "Keil RTX": ["osActiveThread"],
}
_func_cache = {"mtime": None, "funcs": []}  # 采样剖析函数符号表缓存


def _probe_tcp(host: str, port: int, timeout: float = 0.5) -> bool:
    """探测目标主机端口是否可达（判断 Keil UVSOCK 是否开启监听）。"""
    import socket as _socket
    try:
        with _socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _load_func_table(limit: int = 10 ** 6) -> list:
    """读取 .axf 全部函数符号 → [(start, end, name)]，按 start 排序；带 mtime 缓存。"""
    loc = _get_locator()
    if not loc or not loc.is_ready():
        return []
    try:
        mtime = loc.axf_mtime
    except Exception:  # noqa: BLE001
        mtime = None
    if _func_cache["mtime"] == mtime and _func_cache["funcs"]:
        return _func_cache["funcs"]
    syms = loc.search_symbols("", limit=limit, kind="func")
    funcs = []
    for s in syms:
        try:
            start = int(s["addr"], 16)
        except (TypeError, ValueError):
            continue
        size = int(s.get("size") or 0)
        end = start + size if size > 0 else start
        funcs.append((start, end, s["name"]))
    funcs.sort(key=lambda x: x[0])
    # 无 size 的符号用下一个符号 start 作结束界
    for i in range(len(funcs) - 1):
        if funcs[i][1] <= funcs[i][0]:
            funcs[i] = (funcs[i][0], funcs[i + 1][0], funcs[i][2])
    _func_cache["mtime"] = mtime
    _func_cache["funcs"] = funcs
    return funcs


def _func_for_pc(funcs: list, pc: int):
    """把 PC 归到函数名（最近 start<=pc 且 pc<end 的符号）；无则返回 None。"""
    lo, hi, hit = 0, len(funcs) - 1, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= pc:
            hit = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if hit < 0:
        return None
    start, end, name = funcs[hit]
    if pc < end:
        return name
    return None


_CPU_PARTNO = {0xC20: "Cortex-M0", 0xC21: "Cortex-M3", 0xC24: "Cortex-M4", 0xC23: "Cortex-M7"}


def _read_cpu_arch(client):
    """读 SCB->CPUID (0xE000ED00) 解析 ARM 内核类型。返回 {arch, cpu_arch}。"""
    try:
        r = client.read_mem(0xE000ED00, 4)
        h = r.get("data_hex") or ""
        if not (r.get("ok") and len(h) >= 8):
            return {"arch": "未知", "cpu_arch": None}
        cpuid = int.from_bytes(bytes.fromhex(h[:8]), "little")
        partno = (cpuid >> 4) & 0xFFF
        arch_bits = (cpuid >> 16) & 0xF
        # Cortex-M3/M4/M7 的 CPUID Architecture 字段为 0xF(ARMv7E-M)；M0 为 0xA(ARMv6-M)
        arch_name = {0xF: "ARMv7E-M", 0xC: "ARMv7E-M", 0xA: "ARMv6-M"}.get(arch_bits, f"arch_{arch_bits}")
        core = _CPU_PARTNO.get(partno, f"未知(partno 0x{partno:X})")
        return {"arch": arch_name, "cpu_arch": core, "cpuid": f"0x{cpuid:08X}"}
    except Exception as e:  # noqa: BLE001
        return {"arch": "未知", "cpu_arch": None, "error": str(e)}


def _probe_rtos():
    """探测当前固件是否编译进常见 RTOS（基于 .axf 符号存在性）。返回 [{rtos, present}]。"""
    loc = _get_locator()
    if not loc or not loc.is_ready():
        return []
    try:
        all_syms = loc.search_symbols("", limit=10 ** 6, kind="all")
        names = {s["name"] for s in all_syms}
    except Exception:  # noqa: BLE001
        return []
    out = []
    for rtos, marks in _RTOS_MARKERS.items():
        found = [m for m in marks if m in names]
        if found:
            out.append({"rtos": rtos, "present": True, "markers": found})
    if not out:
        out.append({"rtos": "none", "present": False, "note": "未检测到常见 RTOS 符号，疑为裸机工程"})
    return out


def _get_locator() -> Locator | None:
    return _symbol_cfg.get("locator")




class MapLocator:
    """用 .map 的 Image Symbol Table 作为符号源（无 DWARF，仅函数/全局符号地址）。

    提供与 Locator 对齐的接口（search_symbols / addr_to_location / is_ready），
    addr_to_location 只能返回函数名级（无 file/line），source_type 标记为 map。
    """

    def __init__(self, map_path: str):
        self.map_path = os.path.abspath(map_path)
        self._syms: list = []  # [(addr, name)] 按 addr 升序
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            r = mapfile.parse_map_file(self.map_path)
            if r.get("ok") is False:
                logger.warning("解析 map 失败: %s", r.get("error"))
                return
            syms = sorted((s["addr"], s["name"])
                          for s in r.get("symbols", []) if s.get("addr"))
            self._syms = syms
            logger.info("MapLocator 加载 %d 个符号（%s）", len(syms), self.map_path)
        except Exception as e:  # noqa: BLE001
            logger.warning("加载 map 失败: %s", e)

    def is_ready(self) -> bool:
        self._ensure_loaded()
        return bool(self._syms)

    def total_entries(self) -> int:
        self._ensure_loaded()
        return len(self._syms)

    def search_symbols(self, query: str = "", limit: int = 50, kind: str = "all"):
        self._ensure_loaded()
        q = (query or "").lower()
        out = []
        for addr, name in self._syms:
            if q and q not in name.lower():
                continue
            out.append({"name": name, "type": "func", "bind": "global",
                        "addr": "0x%08x" % addr, "size": 0})
            if len(out) >= max(1, min(limit, 200)):
                break
        return out

    def addr_to_location(self, addr: int):
        """二分找 <= addr 的最近符号（函数名级），无 file/line。"""
        self._ensure_loaded()
        lo, hi, best = 0, len(self._syms) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if self._syms[mid][0] <= addr:
                best = self._syms[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        if best is None:
            return None
        return {"file": None, "line": None, "address": best[0], "function": best[1],
                "source_type": "map"}


    def is_covered(self, addr: int) -> bool:
        """.map 符号无 size 信息，不做覆盖断言（保守返回 True，避免误伤）。"""
        return True

    def locate(self, addr: int):
        """与 Locator.locate 对齐：map 无行号，仅返回函数名级信息。"""
        l = self.addr_to_location(addr)
        if l is None:
            return {"address": addr, "file": None, "line": None, "covered": True}
        d = dict(l)
        d["covered"] = True
        return d

def _load_symbol_file(path: str):
    """加载符号文件（.axf 或 .map），更新 _symbol_cfg。返回 (ok, message, count)。"""
    global _symbol_cfg
    p = (path or "").strip().strip('"')
    if not p:
        return False, "未指定符号文件路径", 0
    if not os.path.isfile(p):
        return False, f"符号文件不存在: {p}", 0
    ext = os.path.splitext(p)[1].lower()
    if ext == ".map":
        loc = MapLocator(p)
        loc._ensure_loaded()
        if not loc.is_ready():
            return False, f".map 未解析到任何符号: {p}", 0
        _symbol_cfg = {"locator": loc, "axf": None, "source_type": "map"}
        return True, f"已加载 .map 符号（{loc.total_entries()} 条，无 DWARF 行号）", loc.total_entries()
    try:
        loc = Locator(p)
        n = loc.total_entries()
    except Exception as e:  # noqa: BLE001
        return False, f"加载 .axf 失败: {e}", 0
    _symbol_cfg = {"locator": loc, "axf": os.path.abspath(p), "source_type": "axf"}
    return True, f"已加载 .axf 符号（{n} 条）", n

# ----------------------------------------------------------------------
# 批次29：符号文件状态、调试会话快照、串行化遥测
# ----------------------------------------------------------------------
# 「运行镜像 vs 符号文件」不一致是极隐蔽的一类坑：flash_download/编译之后旧调试会话的
# 符号就已经过期，此时表达式求值集体报 status 13「解析错误」，调用方容易去怀疑目标代码
# 而不是「符号旧了」。故记录进入调试时的符号文件签名，之后任何读取都据此报陈旧。
_debug_session = {"axf": None, "mtime": None, "mtime_text": None,
                  "since": None, "reason": None}
_firmware_events: list = []          # 最近几次编译/烧录（时间 + 原因）
_tool_concurrency = {"in_flight": 0, "max_in_flight": 0, "tool_calls": 0, "last_tool": ""}
_debugging_cache = {"ts": 0.0, "value": None}


def _file_mtime_text(mtime) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(mtime)))
    except Exception:  # noqa: BLE001
        return ""


def _mark_debug_session(reason: str = "") -> dict:
    """记录「本次调试会话加载的是哪个 .axf（及其时间戳）」。"""
    axf = (_symbol_cfg or {}).get("axf") or ""
    mtime = None
    try:
        if axf:
            mtime = os.stat(axf).st_mtime
    except OSError:
        mtime = None
    _debug_session.update({"axf": axf or None, "mtime": mtime,
                           "mtime_text": _file_mtime_text(mtime) if mtime else None,
                           "since": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "reason": reason or ""})
    _debugging_cache["ts"] = 0.0
    _debugging_cache["value"] = True
    return dict(_debug_session)


def _clear_debug_session(reason: str = "") -> None:
    """调试会话结束：清空快照（下次进入调试会重新记录）。"""
    _debug_session.update({"axf": None, "mtime": None, "mtime_text": None,
                           "since": None, "reason": reason or ""})
    _debugging_cache["ts"] = 0.0
    _debugging_cache["value"] = False


def _note_firmware_event(reason: str) -> None:
    """记录一次编译/烧录（供 get_status 说明「固件是什么时候换的」）。"""
    _firmware_events.append({"reason": reason, "ts": time.time(),
                             "time_text": _file_mtime_text(time.time())})
    del _firmware_events[:-5]


def _is_debugging(client=None, ttl: float = 1.0):
    """带短缓存的「是否处于调试态」（错误路径补提示用，避免额外往返）。"""
    now = time.monotonic()
    if _debugging_cache["value"] is not None and now - _debugging_cache["ts"] < ttl:
        return _debugging_cache["value"]
    val = None
    try:
        st = (client or _get_client()).get_status()
        val = bool(st.get("debugging"))
    except Exception:  # noqa: BLE001
        val = None
    _debugging_cache.update({"ts": now, "value": val})
    return val


def _symbol_state(debugging=None) -> dict:
    """符号文件（.axf/.map）路径 + 时间戳 + 是否已与当前调试会话不一致。"""
    cfg = _symbol_cfg or {}
    axf = cfg.get("axf") or ""
    out = {"symbol_file": axf or None,
           "symbol_source_type": cfg.get("source_type"),
           "symbol_entries": None,
           "symbol_stale": False}
    try:
        loc = cfg.get("locator")
        out["symbol_entries"] = loc.total_entries() if loc is not None else None
    except Exception:  # noqa: BLE001
        pass
    mtime = None
    if axf:
        try:
            st = os.stat(axf)
            mtime = st.st_mtime
            out["symbol_mtime"] = round(mtime, 3)
            out["symbol_mtime_text"] = _file_mtime_text(mtime)
            out["symbol_size"] = st.st_size
        except OSError as e:
            out["symbol_file_error"] = str(e)
    snap = _debug_session
    if debugging:
        if snap.get("mtime") is None:
            # 首次观察到调试态：以此为基线（此前发生了什么已无从判断，如实说明）
            _mark_debug_session("首次观察到调试态，自动记录基线")
            out["debug_session_since"] = _debug_session.get("since")
            out["debug_session_note"] = "本进程首次观察到调试态，已以此为符号基线"
        elif snap.get("axf") and axf and \
                os.path.normcase(os.path.abspath(snap["axf"])) != os.path.normcase(os.path.abspath(axf)):
            out["symbol_stale"] = True
            out["symbol_stale_note"] = (
                "当前调试会话加载的是 %s 的符号，但符号文件已切到 %s：表达式/断点会解析到"
                "错误符号（报解析错误或给出无意义地址）。请 exit_debug + enter_debug 重新加载，"
                "或用 set_symbol_file 切回本次调试的固件符号。" % (snap.get("axf"), axf or "(无)"))
        elif snap.get("mtime") is not None and mtime is not None and \
                abs(float(snap["mtime"]) - mtime) > 1e-6:
            out["symbol_stale"] = True
            out["symbol_stale_note"] = (
                "符号文件在进入本次调试之后被重新生成（%s → %s）：**当前调试会话用的仍是旧符号**，"
                "表达式求值/断点解析会报 status 13 之类的解析错误——这不代表目标代码有问题。"
                "请 exit_debug + enter_debug 重新加载符号，或直接用 flash_debug（关旧Keil→编烧→重开→进调试）"
                "一步闭环。" % (snap.get("mtime_text") or "?", out.get("symbol_mtime_text") or "?"))
    out["debug_session_since"] = snap.get("since")
    out["debug_session_symbol"] = snap.get("axf")
    if _firmware_events:
        out["last_firmware_event"] = _firmware_events[-1]
    return out


def _symbol_stale_hint(client=None) -> str:
    """符号与当前会话不一致时的提示文本（空串＝无异常）。用于错误路径附言。"""
    try:
        st = _symbol_state(debugging=_is_debugging(client))
    except Exception:  # noqa: BLE001
        return ""
    return st.get("symbol_stale_note") or ""


def _serialization_fields() -> dict:
    """串行化方式 + 并发竞争遥测 + 其他 mdkdebug 实例（get_status / keil_health 共用）。"""
    try:
        out = dict(_get_client().serialization_snapshot())
    except Exception as e:  # noqa: BLE001
        out = {"mode": "serialized", "error": str(e)}
    out["in_process"] = dict(_tool_concurrency)
    stats = out.get("stats") or {}
    if not out.get("warning") and int(stats.get("lock_timeouts") or 0) > 0:
        out["warning"] = (
            "跨进程互斥锁曾超时 %d 次（对手 PID=%s）：确有另一个进程在用同一 UVSOCK，"
            "并发调用时命令会互相穿插。" % (int(stats["lock_timeouts"]), stats.get("foreign_pid")))
    elif not out.get("warning") and int(stats.get("waits") or 0) > 0:
        out["contention_note"] = (
            "出现过 %d 次命令闸门等待（最长 %.1fms）：说明有并发调用进入了串行队列，"
            "已被互斥挡住，未丢失命令。" % (int(stats["waits"]), float(stats.get("max_wait_ms") or 0)))
    return out


def _verify_write(client, addr: int, payload: bytes) -> dict:
    """写后回读校验：写入是否真的落地。

    批次29（真机反馈）：并发、目标运行中、或写只读/未擦写区域时，write_mem 可能返回成功
    而值并未改变（被另一条命令覆盖，或被调试器静默忽略），调用方却以为写成功了——
    「看门狗又复位了」这类误判往往由此而来。故写后立刻回读比对，不一致就显式报出来。
    """
    n = len(payload)
    try:
        rb = client.read_mem(addr, n)
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "verify_note": "写入已发出，但回读校验失败：%s" % e}
    if not rb.get("ok"):
        return {"verified": False, "verify_note":
                "写入已发出，但回读校验失败（%s）：无法确认是否落地（目标可能在运行中，"
                "或该地址不可读）" % rb.get("status_text"),
                "verify_status": rb.get("status")}
    got = bytes.fromhex(rb.get("data_hex") or "")
    if got[:n] == payload:
        return {"verified": True, "readback_hex": got[:n].hex()}
    return {"verified": False, "readback_hex": got[:n].hex(),
            "verify_note": (
                "回读与写入不一致——**写入没有真正落地**（已读回 %s）。常见原因："
                "① 目标在运行中，内存写入被调试器忽略（先 stop 再写）；"
                "② 地址是只读/需解锁的寄存器，或 Flash 未擦写；"
                "③ 有另一个 mdkdebug 实例并发写同一处（get_status 看 serialization）。"
                % got[:n].hex())}


def _post_flash_debug_state(client, do_exit: bool = True) -> dict:
    """编译/烧录之后处理旧调试会话——批次29 反馈②。

    flash_download 之后旧调试会话的符号就是陈旧的（新固件已在板上、.axf 已重生成），
    继续用它做表达式求值会集体报 status 13，工具却一声不响。这里要么自动退出调试
    （默认，退出前必要时先 stop），要么保留会话但**显式提示**符号已过期。
    """
    out = {"checked": True, "exit_debug_after": bool(do_exit)}
    try:
        st = client.get_status()
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        out["note"] = "无法读取调试状态（%s）：若原来在调试，请手动 exit_debug 后重进以刷新符号。" % e
        return out
    out["debugging_before"] = bool(st.get("debugging"))
    out["target_running_before"] = bool(st.get("running"))
    if not out["debugging_before"]:
        out["note"] = "编译/烧录前未处于调试态，无旧符号残留"
        _clear_debug_session("编译/烧录前未处于调试态")
        return out
    if out["target_running_before"]:
        try:
            out["stop"] = client.stop()
            try:
                client.wait_until_stopped(timeout=1.0)
            except Exception:  # noqa: BLE001
                pass
        except Exception as e:  # noqa: BLE001
            out["stop"] = {"ok": False, "error": str(e)}
    if not do_exit:
        out["exited_debug"] = False
        out["note"] = (
            "已按 exit_debug_after=false 保留旧调试会话：**该会话的符号已过期**（.axf 刚被"
            "重新编译/烧录），此后表达式与断点解析可能报 status 13 解析错误。"
            "要继续调试请 exit_debug + enter_debug（或 flash_debug）重新加载符号。")
        return out
    try:
        ex = client.exit_debug()
    except Exception as e:  # noqa: BLE001
        ex = {"ok": False, "error": str(e)}
    out["exit_debug"] = ex
    out["exited_debug"] = bool(ex.get("ok"))
    if out["exited_debug"]:
        out["note"] = ("旧调试会话的符号已过期，已自动退出调试（%s）；要重新调试请 "
                       "enter_debug 或 flash_debug 以加载新符号。"
                       % ("目标运行中，先 stop 再退出" if out["target_running_before"] else "直接退出"))
        _clear_debug_session("编译/烧录后自动退出调试")
    else:
        out["note"] = ("旧调试会话的符号已过期，自动退出调试未成功（%s）；请手动 stop 后 "
                       "exit_debug 再重进，否则表达式求值会报解析错误。"
                       % (ex.get("error") or ex.get("status_text") or ex.get("status")))
    return out




def _release_serial(reason: str, out: dict | None = None,
                    key: str = "serial_release") -> dict:
    """串口「用完就还」：释放 COM 口占用，但**保留已收日志**。

    释放只放掉端口（不释放的话 Keil 串口窗口/其他串口工具会打不开，WinError=5），
    ring buffer 里的行照旧保留、serial_read 仍可增量读；需要接着采集时重新
    serial_monitor_start() 即可——同端口同波特率会复用同一实例，不丢已收日志。
    没有在监听时返回 {}，不打扰主流程。
    """
    try:
        if not serialmon.has_monitor():
            return {}
        r = serialmon.release_monitor(reason)
        if out is not None and isinstance(r, dict) and r.get("ok"):
            out[key] = {k: r.get(k) for k in
                        ("released", "port", "lines", "release_reason", "release_note")}
            out[key] = {k: v for k, v in out[key].items() if v is not None}
        return r
    except Exception as e:  # noqa: BLE001
        logger.debug("释放串口失败（不影响主流程）: %s", e)
        return {"ok": False, "error": str(e)}


def _pc_in_flash(pc) -> bool:
    """判断 PC 是否落在任意预登记固件的 flash 区段。"""
    if not isinstance(pc, int):
        return False
    for pr in _SYMBOL_PROJECTS:
        fs, sz = pr.get("flash_start"), pr.get("flash_size")
        if fs and fs <= pc < fs + sz:
            return True
    return False


def _auto_match_symbol(client):
    """按当前 PC 自动匹配预登记固件并切换符号。返回切换说明 dict 或 None。"""
    try:
        regs = client.read_cpu_registers_stable()
        pc = regs.get("pc")
        if not isinstance(pc, int):
            return None
        for pr in _SYMBOL_PROJECTS:
            fs, sz = pr.get("flash_start"), pr.get("flash_size")
            if fs and fs <= pc < fs + sz:
                axf = pr.get("axf")
                if axf and os.path.isfile(axf):
                    cur = _symbol_cfg.get("axf")
                    if cur and os.path.normcase(os.path.abspath(cur)) == os.path.normcase(os.path.abspath(axf)):
                        return None  # 已是当前符号文件
                    ok, msg, _n = _load_symbol_file(axf)
                    if ok:
                        return {"auto_switched": True, "project": pr["name"],
                                "axf": axf, "message": msg, "pc": hex(pc)}
        return None
    except Exception as e:  # noqa: BLE001
        logger.warning("PC 自动匹配符号失败: %s", e)
        return None
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

# 编译/烧录后的调试通道自愈需要丢弃旧 UVSOCK 连接；builder 不反向依赖 server，
# 在此注入钩子（工具内部先 keil_health 快照，编译后按需自动恢复，省掉一轮 restart_keil 往返）。
builder.set_reset_connection_hook(
    lambda reason: _get_client().reset_connection(reason=reason))


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


def _resolve_addr_arg(s, client=None):
    """把地址参数解析为整数地址：支持 0x/十进制，也支持符号名（函数/全局变量）。

    AI 常把符号名（如 'svcrt_task_table'）直接当 addr 传入，旧实现会抛
    "invalid literal for int()" 逼其先 find_symbol 绕一圈。这里先按数字解析，
    失败再当符号名处理：先查当前 .axf 符号表精确匹配，再退化到调试器表达式 '&名'。
    返回 (addr:int, note:str|None)；无法解析时抛带操作指引的 ValueError。
    """
    try:
        return _parse_addr(s), None
    except (ValueError, TypeError):
        pass
    name = str(s or "").strip()
    if not name:
        raise ValueError("addr 为空：应为地址（如 '0x20000000'）或符号名（如 'svcrt_task_table'）")
    loc = _get_locator()
    if loc is not None:
        hit = loc.symbol_addr(name)
        if hit:
            return hit["addr"], ("addr 由符号 '%s' 解析（%s/%s）"
                                 % (hit["name"], hit["type"], hit["bind"]))
    if client is not None:
        try:
            ar = client.calc_expression("&" + name)
        except Exception:  # noqa: BLE001
            ar = {}
        v = ar.get("value") if isinstance(ar, dict) else None
        if isinstance(v, int) and v != 0:
            return (v & ~1), "addr 由调试器表达式 '&%s' 解析（符号表未命中）" % name
    raise ValueError(
        "无法把 '%s' 解析为地址：既不是合法数字地址，也不在当前 .axf 符号表中；"
        "可用 find_symbol 检索符号名，或先 set_symbol_file 切到该符号所属的 .axf" % name)


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

    第一帧为 PC、第二帧为 LR（均取自寄存器，置信 high）；之后从 SP 向上扫描栈内存，
    凡落在 FLASH 代码段的值视为返回地址并反查 文件:行。栈扫描为启发式：栈中可能残留
    陈旧字被误判为帧（如出现在调用链中间、或落在当前 .axf 符号范围外的野地址）。
    为此每帧带 origin(pc/lr/stack) 与 confidence(high/low)：
    - 栈扫描帧若地址不在当前符号覆盖范围内、或解析不到 文件:行，标记 confidence=low
      并附 note，且**停止继续扫描**（其后栈内容更不可信，避免堆叠更多错误帧）。
    返回 [{level,pc,file,line,origin,confidence[,note]}]。
    """
    frames: list = []
    seen: set = set()
    _is_code = getattr(loc, "is_code_address", None) or (
        lambda a: 0x08000000 <= a <= 0x081FFFFF)

    def _locate(addr: int):
        f = getattr(loc, "locate", None)
        return f(addr) if f else loc.addr_to_location(addr)

    def add(addr: int, origin: str) -> bool:
        """添加一帧，返回是否为低置信度帧。"""
        if addr in seen or not _is_code(addr):
            return False
        seen.add(addr)
        l = _locate(addr)
        covered = bool(l and l.get("covered"))
        ffile = l.get("file") if l else None
        fline = l.get("line") if l else None
        frame = {"pc": hex(addr), "file": ffile or "?", "line": fline,
                 "origin": origin}
        if origin == "stack" and (not covered or not ffile):
            frame["confidence"] = "low"
            frame["note"] = ("该返回地址不在当前 .axf 符号覆盖范围内或无法解析，"
                             "疑似栈中陈旧值，可信度低")
        else:
            frame["confidence"] = "high"
        frames.append(frame)
        return frame["confidence"] == "low"

    add(pc, "pc")
    if isinstance(lr, int):
        add(lr, "lr")
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
            if _is_code(w) and w not in seen:
                if add(w, "stack"):
                    break  # 出现低置信度帧，停止继续扫描
    for i, fr in enumerate(frames):
        fr["level"] = i
    return frames


def _build_location(client):
    """读取当前 PC 并构建停靠位置信息：文件行、源码上下文、完整调用栈。

    供 get_current_location 与 step/run 系列复用，让 AI 查询后立即看到停靠代码。
    返回 dict：{ok, pc, registers, file, line, address, source, display_path, callstack,
    warning(可选), hit_breakpoint(可选)}；.axf 未就绪返回 None；无法读寄存器返回 {ok:False}。
    """
    # 目标运行中读到的是陈旧寄存器（实测 PC 稳定停在复位附近地址，看着像"停在
    # Reset_Handler"，而 LR/SP 指向空闲循环）。据此给停靠位置/调用栈会把排查带偏，
    # 故先确认目标已停止；未停止就不给位置，直接说明原因。
    try:
        st = client.get_status()
    except Exception:  # noqa: BLE001
        st = {}
    if st.get("ok") and st.get("running"):
        return {"ok": False, "target_running": True,
                "error": "目标正在运行，PC/寄存器为陈旧值不可信（实测会稳定返回复位附近地址，"
                         "易误判成停在复位），不给出停靠位置；请先 stop 并确认停止后再读",
                "status": st}
    loc = _get_locator()
    regs = client.read_cpu_registers_stable(require_stopped=True)
    if not regs.get("ok"):
        return {"ok": False, "error": "无法读取 CPU 寄存器（请先进入调试，或确认目标已停止）",
                "detail": regs}
    pc = regs.get("pc")
    lr = regs.get("lr")
    sp = regs.get("sp")
    result = {"ok": True, "pc": hex(pc) if isinstance(pc, int) else pc, "registers": regs,
              "pc_confidence": "low" if regs.get("stable") is False else "high"}
    if regs.get("stable") is False:
        result["pc_warning"] = regs.get("warning")
    # 汇编级降级：符号未就绪或 PC 无法解析时，仍返回地址级信息并显式告警，不硬套源码
    if not loc or not loc.is_ready() or not isinstance(pc, int):
        result["warning"] = ("符号定位未就绪，仅返回汇编/地址级信息；"
                             "请用 set_symbol_file 指定当前固件的 .axf/.map")
        result["callstack"] = []
        if isinstance(pc, int):
            result["address"] = hex(pc)
        return result
    cur = loc.addr_to_location(pc)
    if cur is None:
        # PC 自动匹配：尝试按当前 PC 切到预登记固件符号，避免符号漂移误判
        switched = _auto_match_symbol(client)
        if switched:
            result["auto_symbol"] = switched
            loc2 = _get_locator()
            cur = loc2.addr_to_location(pc) if loc2 else None
            if cur is not None:
                loc = loc2
        if cur is None:
            result["warning"] = (f"当前 PC({hex(pc)}) 未能在当前符号文件解析，符号可能与固件不匹配；"
                                 "请 set_symbol_file 切换符号文件，或以地址级信息为准")
            result["address"] = hex(pc)
            result["callstack"] = _backtrace(client, loc, pc, lr, sp)
            return result
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


def _near_function_entry(pc, meta: dict | None, window: int = 16) -> bool:
    """当前 PC 是否位于函数入口 window 字节内（prologue 阶段，DWARF 位置常未就绪）。"""
    if not meta or meta.get("low_pc") is None or not isinstance(pc, int):
        return False
    low = meta["low_pc"] & ~1
    return 0 <= (pc & ~1) - low <= window


def _aapcs_param_fallback(client, idx, regs: dict | None = None):
    """函数入口处按 AAPCS 回退读取参数：前 4 个在 R0-R3，第 5 个起在栈上。

    仅由 read_locals 在"表达式求值取不到有效值(失败或 0) + PC 位于函数入口"时调用。
    返回 {value, value_type, source, fallback}；无法回退时返回 None。
    注意：栈传参按"SP 尚未因 prologue push 调整"假定取值，SP 已下移时可能偏移。
    """
    if not isinstance(idx, int) or idx < 0:
        return None
    regs = regs or {}
    if idx < 4:
        rname = "R%d" % idx
        val = regs.get(rname.lower())
        if not isinstance(val, int):
            try:
                r = client.calc_expression(rname)
                if r.get("ok") and isinstance(r.get("value"), int):
                    val = r["value"]
            except Exception:  # noqa: BLE001
                val = None
        if isinstance(val, int) and val != 0:
            return {"value": val, "value_type": "int",
                    "source": "register:%s" % rname, "fallback": True}
        return None
    sp = regs.get("sp")
    if not isinstance(sp, int):
        return None
    addr = sp + (idx - 4) * 4
    try:
        mr = client.read_mem(addr, 4)
        if mr.get("ok"):
            raw = bytes.fromhex(mr.get("data_hex") or "")
            if len(raw) >= 4:
                val = int.from_bytes(raw[:4], "little")
                if val != 0:
                    return {"value": val, "value_type": "int",
                            "source": "stack:0x%08x" % addr, "fallback": True}
    except Exception:  # noqa: BLE001
        pass
    return None


_FPB_SLOTS = 6  # Cortex-M3/M4 FPB 代码断点槽位典型值（M0/M0+ 为 4）


def _bp_clear_note(n_cleared: int) -> str:
    """断点清除后的提示语：按断点类型给建议，避免"每次都让人重烧"的误导。

    Keil 经 SWD/JTAG 调试 Cortex-M 目标时，代码断点默认使用硬件断点（FPB），
    只写调试单元、不改 Flash 指令，清除后无需重新烧录；只有断点数超出硬件槽位
    而落到 Flash 软件断点、或使用模拟器时，才需要重新烧录恢复原指令。
    """
    note = ("已清除。Cortex-M 目标经 SWD/JTAG 调试时，未超出硬件断点槽位(FPB，典型 %d 个)"
            "的代码断点走硬件断点，清除不涉及改写 Flash，无需重新烧录。" % _FPB_SLOTS)
    if n_cleared > _FPB_SLOTS:
        note += ("本次共清除 %d 个断点，已超过硬件槽位上限，可能包含写改 Flash 的软件断点；"
                 "仅在目标行为异常时才需要 build_and_flash 重刷。" % n_cleared)
    else:
        note += "仅当断点超出硬件槽位落到 Flash 软件断点、或使用模拟器时才需重新烧录。"
    return note


# 常见参数名 -> 示例值（生成"调用示例"用；未收录的按 JSON 类型给占位值）
_PARAM_EXAMPLES = {
    "addr": "0x20000000", "address": "0x20000000",
    "addresses": [{"addr": "0x20000000", "n_bytes": 16}],
    "n_bytes": 16, "size": 64, "data_hex": "deadbeef", "byte": 0, "count": 1,
    "expr": "main", "expressions": ["SData_UA", "timer.sec"], "name": "SData_UA",
    "query": "main", "kind": "func", "limit": 50,
    "target": "0x08000db4", "timeout_ms": 1000, "mode": "into", "access": "write",
    "condition": "i == 10", "bp_id": 1, "project": "", "path": "path/to/firmware.axf",
    "start": "0x20000000", "end": "0x20000040", "pattern_hex": "deadbeef",
    "max_results": 20, "commands": [{"tool": "read_mem",
                                     "args": {"addr": "0x20000000", "n_bytes": 16}}],
    "stop_on_error": False, "duration_ms": 1000, "interval_ms": 20,
    "periph": "GPIOA", "reg": "ODR", "value": "0x0001", "register": "r0",
    "globals": ["g_flag"], "source_context": 4, "max_fields": 64, "func": "main",
    "max_ms": 5000, "port": 0, "clear": False, "backup": True,
    "include_uvoptx": False, "read_memory": True, "max_frames": 16,
    "errors_text": "main.c(12): error: #20: identifier x is undefined",
}


def _example_value(name: str, spec: dict):
    """按参数名/JSON 类型给出示例值。"""
    if name in _PARAM_EXAMPLES:
        return _PARAM_EXAMPLES[name]
    t = spec.get("type")
    if isinstance(t, list):
        t = t[0] if t else None
    if t == "integer":
        return 0
    if t == "number":
        return 0
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    return "<%s>" % name


# 参数别名表：主参数 -> 别名。为了让别名在直接调用时也能用，主参数在 schema 里
# 变成了可选（框架只认 schema 的 required）；但对调用方而言它仍是必填，故这里把
# 必填口径补回，使描述/list_tools 与实际校验一致，避免"看似可选、一传才报错"。
_ALIAS_HINT = {
    "read_mem": {"n_bytes": "length"},
    "find_symbol": {"query": "name"},
}


def _req_params(tool_name: str, params: dict) -> list:
    """必填参数口径 = schema required + 别名的宿主参数（如 read_mem 的 n_bytes）。"""
    req = list(params.get("required") or [])
    for main in (_ALIAS_HINT.get(tool_name) or {}):
        if main not in req:
            req.append(main)
    return req


def _alias_note(tool_name: str) -> str:
    """别名提示文本，如"（别名：n_bytes 也可写作 length）"。"""
    amap = _ALIAS_HINT.get(tool_name) or {}
    if not amap:
        return ""
    return "（别名：" + "；".join("%s 也可写作 %s" % (k, v) for k, v in amap.items()) + "）"


def _param_signature(tool) -> str:
    """由工具 inputSchema 生成"必填参数 + 调用示例"文本块。"""
    params = getattr(tool, "parameters", None) or {}
    props = params.get("properties") or {}
    if not props:
        return "无（直接调用，args 传 {}）"
    required = _req_params(getattr(tool, "name", ""), params)
    optional = [n for n in props if n not in required]
    req_txt = ", ".join(required) if required else "无"
    opt_txt = ", ".join(optional) if optional else "无"
    return "必填: %s；可选: %s%s" % (req_txt, opt_txt, _alias_note(getattr(tool, "name", "")))


def _param_hint_block(tool) -> str:
    """生成可直接照抄的【参数】/【调用示例】说明块，附到工具描述末尾。

    AI 冷启动常猜错参数名（addr 写成 address、expr 写成 name），而框架只在报错里
    给一句 "Field required"，要试错 2~3 次。这里把必填/可选参数与调用示例写进描述，
    一次调用即可对齐。
    """
    params = getattr(tool, "parameters", None) or {}
    props = params.get("properties") or {}
    if not props:
        return "\n【参数】无（直接调用）\n【调用示例】{}"
    required = _req_params(getattr(tool, "name", ""), params)
    example = {}
    for nm, spec in props.items():
        if nm in required:
            example[nm] = _example_value(nm, spec if isinstance(spec, dict) else {})
    if not required:
        example = {}
    return ("\n【参数】%s\n【调用示例】%s"
            % (_param_signature(tool), json.dumps(example, ensure_ascii=False)))


# ---------------- 符号重定位偏移（App 侧变量按符号名直读） ----------------
# 背景：App 运行期重定位后，运行地址 = .axf 里的链接地址 + delta（SVCrtOS 里是 0xF000）。
# 此前读 App 变量必须手工算偏移，这里做成全局设置 + 按调用覆盖。
_reloc_cfg = {"delta": 0}


def _parse_reloc_delta(v):
    """解析重定位偏移（0x 十六进制 / 十进制 / 可带负号）；空值返回 None。"""
    t = str(v or "").strip()
    if not t:
        return None
    neg = t.startswith("-")
    body = t[1:].strip() if neg else t
    try:
        val = int(body, 16) if body.lower().startswith("0x") else int(body, 10)
    except ValueError:
        raise ValueError("reloc_delta 需为 0x 十六进制或十进制整数（可带负号），收到 %r" % v)
    return -val if neg else val


def _eff_reloc_delta(arg=None):
    """确定本次生效的重定位偏移：显式参数优先，其次全局设置。返回 (delta, 说明)。"""
    d = _parse_reloc_delta(arg)
    if d is not None:
        return d, "本次调用显式指定"
    d = int(_reloc_cfg.get("delta") or 0)
    return d, ("全局 set_reloc_delta(0x%X)" % d if d else "未设置重定位偏移（默认 0）")


def _resolve_addr_with_reloc(addr_arg, client, delta):
    """解析地址参数，并对**符号名**应用重定位偏移。

    只偏移符号名：显式数字地址（如 '0x20000100'）通常是调用方给的确切运行地址，
    再偏移会读到别处；而符号地址（.axf 链接地址）在 App 重定位场景下必须 +delta。
    """
    try:
        return _parse_addr(addr_arg), None
    except (ValueError, TypeError):
        pass
    a, note = _resolve_addr_arg(addr_arg, client)
    if not delta:
        return a, note
    run = (int(a) + int(delta)) & 0xFFFFFFFF
    tip = "已按 reloc_delta=0x%X 偏到运行地址 0x%X（符号地址是链接地址）" % (delta, run)
    return run, ((note + "；" + tip) if note else tip)


def _read_variable_reloc(client, name, count, read_memory, delta, dnote):
    """重定位偏移下的变量读取。

    Keil 表达式 '&name' 返回的是链接地址，直接求值会读到错误位置；因此这里取链接地址
    +delta 得运行地址，再从运行地址读内存并解析（小端整数 / 浮点）。
    """
    out = {"ok": False, "name": name,
           "reloc_delta": "0x%X" % delta, "reloc_note": dnote}
    link = None
    ar = client.calc_expression("&" + name)
    if isinstance(ar, dict) and ar.get("ok") and isinstance(ar.get("value"), int):
        link = int(ar["value"]) & ~1
        out["link_address_source"] = "调试器表达式 &%s" % name
    if link is None:
        loc = _get_locator()
        hit = loc.symbol_addr(name) if loc is not None else None
        if hit:
            link = int(hit["addr"])
            out["link_address_source"] = ".axf 符号表"
    if link is None:
        out["error"] = "无法解析符号 '%s' 的链接地址（符号不存在或未进入调试态）" % name
        return out
    run = (link + int(delta)) & 0xFFFFFFFF
    out["link_address"] = hex(link)
    out["run_address"] = hex(run)
    out["address"] = hex(run)
    size = None
    sz = client.calc_expression("sizeof(%s)" % name)
    if isinstance(sz, dict) and sz.get("ok") and isinstance(sz.get("value"), int):
        size = int(sz["value"])
    n = size if (size and 0 < size <= 1024) else 4
    out["size_bytes"] = n
    try:
        mem = client.read_mem(run, n)
    except Exception as e:  # noqa: BLE001
        out["error"] = "读取运行地址失败: %s" % e
        return out
    if not mem.get("ok"):
        out["error"] = "读取运行地址 0x%X 失败: %s" % (run, mem)
        return out
    data = bytes.fromhex(mem.get("data_hex") or "")
    out["ok"] = True
    if read_memory:
        out["memory_hex"] = mem.get("data_hex")
        out["ascii"] = mem.get("ascii")
    out["value"] = int.from_bytes(data[:min(n, 8)], "little") if data else None
    if n == 4 and len(data) >= 4:
        out["value_as_float"] = struct.unpack("<f", data[:4])[0]
    if count and int(count) > 0:
        cnt = int(count)
        elem = (size // cnt) if (size and size % cnt == 0) else 4
        elems = []
        for i in range(cnt):
            try:
                m = client.read_mem(run + i * elem, elem)
            except Exception as e:  # noqa: BLE001
                elems.append({"index": i, "error": str(e)})
                break
            if not m.get("ok"):
                elems.append({"index": i, "error": "读取失败"})
                break
            d = bytes.fromhex(m.get("data_hex") or "")
            elems.append({"index": i,
                          "value": int.from_bytes(d[:elem], "little") if d else None})
        out["elements"] = elems
        out["elem_size"] = elem
    out["value_note"] = ("value 按小端整数解析运行地址处的内存；浮点看 value_as_float，"
                         "结构体/字符串看 memory_hex")
    return out


def _batch_alias_args(tool: str, args: dict) -> dict:
    """batch 历史别名兼容：addr/address、n_bytes/size 等旧写法仍可用。"""
    a = dict(args or {})
    if tool in ("read_mem", "read_mem_multi", "write_mem", "fill_mem", "search_mem"):
        if "addr" not in a and "address" in a:
            a["addr"] = a["address"]
        if tool == "read_mem" and "n_bytes" not in a and "size" in a:
            a["n_bytes"] = a["size"]
    a.pop("address", None)
    return a


def _usage_summary(desc: str, limit: int = 90) -> str:
    """从工具描述里取一句用途摘要（去掉追加的【参数】块，截到第一个句号）。"""
    t = (desc or "").split("【参数】")[0].replace("\n", " ").strip()
    for sep in ("。", "；", ". "):
        i = t.find(sep)
        if 0 <= i <= limit:
            return t[:i]
    return t[:limit]


def _apply_param_hints(server) -> int:
    """给所有已注册工具的描述追加【参数】/【调用示例】（幂等）。"""
    tm = getattr(server, "_tool_manager", None)
    tools = getattr(tm, "_tools", None) or {}
    n = 0
    for tool in tools.values():
        desc = getattr(tool, "description", "") or ""
        block = _param_hint_block(tool)
        if block and "\n【参数】" not in desc:
            tool.description = desc + block
            n += 1
    return n


def _js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


class AliasMCPServer(MCPServer):
    """在工具调用入口做参数名归一（第 9 轮建议②「参数名收敛」）。

    主名保持不变（不改名＝不破坏已有调用与文档），但每个工具额外接受一组统一别名：
    AI 按直觉写 query / name / expression / address / timeout_ms 都能落地。
    list_tools 会把「主名 ← 别名」写进描述，AI 不必靠报错反推签名。

    两条安全约束：
    - **别名不得遮蔽真实参数**：与某工具真实参数同名的别名会被剔除（如 read_mem 真有
      length 参数，就不再拿 length 当 n_bytes 的别名）；
    - **主名优先**：主名与别名同时出现时只认主名，不静默改写用户给的参数。
    """

    def _real_params(self, tool: str) -> set:
        """该工具的真实参数名集合（用于剔除会遮蔽真实参数的别名）。"""
        cache = getattr(self, "_alias_real_params", None)
        if cache is None:
            cache = {}
            try:
                for info in self._tool_manager.list_tools():
                    params = getattr(info, "parameters", None) or {}
                    props = params.get("properties") if isinstance(params, dict) else None
                    cache[info.name] = set((props or {}).keys())
            except Exception:  # noqa: BLE001
                logger.debug("构建别名白名单失败，按无别名处理", exc_info=True)
            self._alias_real_params = cache
        return cache.get(tool, set())

    def _real_params_or_none(self, tool: str) -> set | None:
        """该工具的真实参数集合；**工具不在注册表里**返回 None（与"无参数工具"区分开）。"""
        self._real_params(tool)                      # 预热缓存
        cache = getattr(self, "_alias_real_params", None) or {}
        return cache.get(tool)

    def _alias_map(self, tool: str) -> dict:
        amap = _aliases.aliases_of(tool)
        if not amap:
            return {}
        real = self._real_params(tool)
        return {k: v for k, v in amap.items() if k not in real}

    def normalize_arguments(self, tool: str, arguments) -> tuple:
        """把别名键换成主名；返回 (参数, 生效的别名说明列表)。"""
        if not isinstance(arguments, dict) or not arguments:
            return arguments, []
        amap = self._alias_map(tool)
        if not amap:
            return arguments, []
        out, applied = dict(arguments), []
        for key in list(arguments.keys()):
            primary = amap.get(key)
            if not primary:
                continue                      # 真正不认识的名字 → 交给 unknown_params 拒绝
            if primary in arguments:
                # 主名优先：不覆盖已给的主名，但**别名键必须删掉**——留着它会以
                # "未知参数"的身份被拒（batch 里 _batch_alias_args 补的 n_bytes 与遗留的
                # size 撞在一起时就会这样：报错说 size 不被接受，而它分明是 n_bytes 的别名）。
                out.pop(key, None)
                applied.append("%s 已忽略（主名 %s 同时给出，取主名）" % (key, primary))
                continue
            out[primary] = _aliases.convert_time(primary, key, arguments[key])
            out.pop(key, None)
            applied.append("%s→%s" % (key, primary))
        return out, applied

    def unknown_params(self, tool: str, arguments) -> list:
        """框架默认会**静默忽略**未知参数——AI 打错键名（如 timeouts_s）会悄悄拿到默认值，
        排查代价很高。这里显式拒绝，并在报错里列出可用参数与别名。"""
        if not isinstance(arguments, dict):
            return []
        real = self._real_params_or_none(tool)
        if real is None:
            return []                     # 工具未注册 / 读不到 schema → 不拦，交给框架
        # real 为空集＝该工具确实不需要任何参数：给了参数就是打错了，同样要拒绝
        return [k for k in arguments if k not in real and not k.startswith("_")]

    def prepare_arguments(self, tool: str, arguments) -> tuple:
        """别名归一 + 拒绝未知参数——**单工具直调与 batch 共用的唯一入口**。

        第 11 轮反馈（批次28）：batch 原先直接调用注册表里的裸函数
        `await entry.fn(**args)`，绕过了本层，于是 `run_timeout(timeout_s=0.5)` 直调可用、
        放进 batch 却报 `got an unexpected keyword argument` —— 整套别名（族展开 + 单位换算）
        在多步调试最常用的入口上完全不可见。故把归一/拒绝抽成本方法，两条路径都过它。
        """
        arguments, applied = self.normalize_arguments(tool, arguments)
        bad = self.unknown_params(tool, arguments)
        if bad:
            real = sorted(self._real_params(tool))
            note = _aliases.alias_note(tool, set(real))
            msg = ("参数名不被接受：%s。%s %s"
                   % ("、".join(bad), tool,
                      ("接受的参数：" + "、".join(real)) if real else "不接受任何参数"))
            if note:
                msg += "（参数别名：%s）" % note
            raise ToolError(msg)
        return arguments, applied

    async def call_tool(self, name, arguments, context=None):
        arguments, applied = self.prepare_arguments(name, arguments)
        if applied:
            logger.info("参数别名归一 %s: %s", name, "、".join(applied))
        # 批次29：记录工具级并发度——出现 in_flight>1 说明框架确实并发派发了调用，
        # 这既解释了「命令互相穿插」，也是 get_status.serialization 里的证据。
        _tool_concurrency["in_flight"] += 1
        _tool_concurrency["tool_calls"] += 1
        _tool_concurrency["last_tool"] = str(name)
        if _tool_concurrency["in_flight"] > _tool_concurrency["max_in_flight"]:
            _tool_concurrency["max_in_flight"] = _tool_concurrency["in_flight"]
        try:
            return await super().call_tool(name, arguments, context)
        finally:
            _tool_concurrency["in_flight"] -= 1

    async def list_tools(self):
        # 描述里补「主名 ← 别名」，只补一次（重复调用不会叠加）
        for info in self._tool_manager.list_tools():
            note = _aliases.alias_note(info.name, self._real_params(info.name))
            if not note:
                continue
            desc = info.description or ""
            if "\n【参数别名】" in desc:
                continue
            try:
                # 第 9 轮反馈：「别名层只做了一半」，会让 AI 以为「随便写也行」。故这里
                # 把口径写死——规范名以【参数】行为准，别名只是兼容写法，未列出的名字会被拒绝。
                info.description = (desc + "\n【参数别名】" + note
                                    + "。规范名以上方【参数】行为准；"
                                      "未列出的参数名会被拒绝，不会静默忽略")
            except Exception:  # noqa: BLE001
                logger.debug("未能写入别名说明：%s", info.name, exc_info=True)
        return await super().list_tools()


def create_server(host: str = "127.0.0.1", port: int = 4823,
                  idle_timeout: float = 30.0,
                  uv4_path: str | None = None,
                  default_project: str | None = None,
                  axf_path: str | None = None,
                  symbol_projects: list | None = None) -> MCPServer:
    global _client, _builder_cfg, _symbol_cfg, _SYMBOL_PROJECTS
    # 合并符号工程注册表：内置(仓库内相对) + 环境变量注入 + 启动参数注入
    _SYMBOL_PROJECTS = (_builtin_symbol_projects()
                        + _symbol_projects_from_env()
                        + list(symbol_projects or []))
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
    _symbol_cfg = {"locator": locator, "axf": axf,
                   "source_type": ("axf" if locator is not None else None)}
    logger.info("Mdkdebug 已就绪：UVSOCK@%s:%d  idle_timeout=%ss", host, port, idle_timeout)
    logger.info("构建配置：UV4=%s  默认工程=%s", uv4, default_project)

    server = AliasMCPServer(
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
        description="查询 Keil UVSOCK 插件的版本信息，返回十六进制版本串。注意：需 Keil 已启动且已开启 UVSOCK（Edit→Configuration→Other→UVSOCK Enabled→端口4823→重启Keil），否则连接失败并返回开启指引。",
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
            "查询当前调试状态：是否处于调试会话、目标是否在运行、以及 UVSOCK 状态码，"
            "并额外返回 **symbol_file / symbol_mtime / symbol_stale**（当前符号文件路径、"
            "时间戳，以及「符号是否已与本次调试会话不一致」——编译或烧录之后旧会话的符号即过期，"
            "继续求值会报 status 13 解析错误）与 **serialization**（串行化方式、并发竞争遥测、"
            "是否还有别的 mdkdebug 进程在抢同一 UVSOCK）。可用于判断可否安全读写内存。注意：UVSOCK 响应的 r_status 恒为 0，真实运行状态在 data 低字节（0=停止,1=执行中），本工具已正确解析。目标运行中可查状态，但此时不可安全读内存。"
        ),
    )
    async def get_status() -> str:
        try:
            client = _get_client()
            out = dict(client.get_status())
            # 批次29：符号文件路径/时间戳 + 陈旧判定；串行化与并发竞争视图
            out.update(_symbol_state(debugging=out.get('debugging')))
            out['serialization'] = _serialization_fields()
            if out.get('symbol_stale'):
                out['symbol_stale_warning'] = out.get('symbol_stale_note')
            if (out.get('serialization') or {}).get('warning'):
                out['concurrency_warning'] = out['serialization']['warning']
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_console_output",
        title="读取命令窗口输出",
        description=(
            "读取 Keil 命令窗口(Command)的调试输出，来自 UVSOCK 推送的 UV_DBG_CMD_OUTPUT(0x5020) "
            "异步消息。执行 EXEC_CMD / BL / EVAL / 断点 等命令后，其输出（如断点列表、EVAL 结果、"
            "printf 调试打印、错误行）通过本工具读取，实现调试信息闭环。clear 可选清空缓存。"
            "注意：输出为异步推送，需先执行命令再读；每次发送请求前会自动收集堆积的异步帧。"
        ),
    )
    async def read_console_output(clear: bool = False) -> str:
        try:
            msgs = _get_client().read_console_output(clear=clear)
            return _js({"ok": True, "count": len(msgs),
                        "lines": [m.get("text") for m in msgs],
                        "clear": clear,
                        "note": "读自 Keil UVSOCK 命令窗口输出(0x5020)"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="read_async_messages",
        title="读取异步消息/报错",
        description=(
            "读取 Keil 异步消息与报错信息，来自 UVSOCK 推送的 UV_ASYNC_MSG(0x4000)。"
            "包含命令执行状态(status)与报错文本（如 '*** error 34: undefined identifier'、"
            "编译/烧录/调试失败的弹窗报错内容），用于闭环捕获 Keil 侧错误。clear 可选清空缓存。"
            "注意：报错为异步推送，先执行可能出错的操作再读；status 为 Keil 返回的错误码。"
        ),
    )
    async def read_async_messages(clear: bool = False) -> str:
        try:
            msgs = _get_client().read_async_messages(clear=clear)
            return _js({"ok": True, "count": len(msgs), "messages": msgs,
                        "clear": clear,
                        "note": "读自 Keil UVSOCK 异步消息(0x4000)，含执行状态与报错"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 表达式 / 变量 ----------------
    @server.tool(
        name="calc_expression",
        title="读取表达式 / 变量值",
        description=(
            "计算并读取调试器中的一个表达式（变量名、寄存器、指针解引用等）。"
            "例如传入全局变量名 'SData_UA'、'timer.sec'，或 '*(uint32_t*)0x20000000'。"
            "返回表达式在当前断点处的值及其类型。注意：需已进入调试且目标暂停，目标运行中无法求值。刚 run 到断点停止的瞬间读取表达式可能返回脏值（如 PC=1），必要时重试。"
        ),
    )
    async def calc_expression(expr: str) -> str:
        client = None
        try:
            client = _get_client()
            out = dict(client.calc_expression(expr))
            # 批次29：编译/烧录后旧调试会话的符号是陈旧的，此时求值会集体报 status 13
            # 「解析错误」——在原位点明原因，省掉一轮错误方向的排查。
            if not out.get("ok"):
                hint = _symbol_stale_hint(client)
                if hint:
                    out["symbol_stale_warning"] = hint
            return _js(out)
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "expression": expr, "error": str(e)}
            hint = _symbol_stale_hint(client)
            if hint:
                out["symbol_stale_warning"] = hint
            return _js(out)

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
            "**读 App 侧变量**（运行期重定位过）时传 reloc_delta=\"0xF000\"，或先调 "
            "set_reloc_delta 设一次全局偏移：工具会把符号的链接地址 + 偏移当作运行地址去读，"
            "返回 link_address / run_address，不必再手工换算（此时 value 按小端整数解析内存，"
            "浮点看 value_as_float）。"
            "适合先查地址/数组内容，再配合 read_mem/write_mem 进一步读写。注意：需目标暂停（运行中读取会失败/错位）；依赖 .axf 调试符号。刚停止瞬间取值可能读到脏值。"
        ),
    )
    async def read_variable(name: str, count: int = 0, read_memory: bool = True,
                            reloc_delta: str = "") -> str:
        client = None
        try:
            client = _get_client()
            delta, dnote = _eff_reloc_delta(reloc_delta)
            if not delta:
                out = dict(client.read_variable(name, count=int(count or 0),
                                                read_memory=bool(read_memory)))
            else:
                out = dict(_read_variable_reloc(client, name, count, read_memory,
                                                delta, dnote))
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "name": str(name), "error": str(e)}
        if not out.get("ok"):
            hint = _symbol_stale_hint(client)
            if hint:
                out["symbol_stale_warning"] = hint
        return _js(out)

    # ---------------- 内存读写 ----------------
    @server.tool(
        name="read_mem",
        title="读取目标内存",
        description=(
            "从指定内存地址读取 n_bytes（别名 length，二者传其一）个字节。"
            "addr 支持十六进制（如 '0x20000000'）、十进制，或符号名（如 'SystemCoreClock'、"
            "'svcrt_task_table'——自动查当前 .axf 符号表解析，命中时返回 addr_note 说明来源）；"
            "读 App 侧符号可传 reloc_delta=\"0xF000\"（或先用 set_reloc_delta 设全局），"
            "工具会把符号的链接地址偏到运行地址；**显式数字地址不会被偏移**；"
            "返回十六进制字节串及 ASCII 视图。注意：需目标暂停——目标运行期间 UVSOCK 推送异步消息会堆积，导致读取响应错位（典型报错 AMEM 响应数据过短），务必先 stop 再读。勿越界读外设保留区，可先 query_memory_map 确认范围。"
        ),
    )
    async def read_mem(addr: str | int, n_bytes: int = 0, length: int = 0,
                       reloc_delta: str = "") -> str:
        addr = _addr_arg(addr)
        try:
            client = _get_client()
            n = int(n_bytes or 0) or int(length or 0)
            if n <= 0:
                return _js({"ok": False, "addr": addr,
                            "error": "参数不足：必须指定读取字节数 n_bytes（别名 length），应为正整数"})
            delta, _dnote = _eff_reloc_delta(reloc_delta)
            a, note = _resolve_addr_with_reloc(addr, client, delta)
            out = client.read_mem(a, n)
            if note and isinstance(out, dict):
                out = dict(out)
                out["addr"] = hex(a)
                out["addr_note"] = note
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    @server.tool(
        name="write_mem",
        title="写入目标内存",
        description=(
            "向指定内存地址写入字节。data_hex 为十六进制字节串（偶数长度），"
            "如 'de ad be ef' 或 'deadbeef'（自动去空格）。返回实际写入长度，"
            "并默认做**写后回读校验**（verify=true，返回 verified/readback_hex）："
            "并发写入、目标运行中、或写只读/未擦写区域时，写入可能被静默忽略——"
            "verified=false 即明确告诉你「写下去了但没生效」，不要据此推断目标行为"
            "（如误判为看门狗复位）。addr 支持十六进制/十进制/符号名。注意：需目标暂停，运行中写入会失败/错位（回读校验会报 verified=false）。写外设寄存器/关键内存有副作用，写入前确认地址与值正确（可先 read_mem 备份）。"
        ),
    )
    async def write_mem(addr: str | int, data_hex: str, verify: bool = True) -> str:
        addr = _addr_arg(addr)
        try:
            client = _get_client()
            a, note = _resolve_addr_arg(addr, client)
            hex_str = "".join((data_hex or "").split())
            try:
                payload = bytes.fromhex(hex_str)
            except ValueError as e:
                return _js({"ok": False, "addr": str(addr), "error": f"data_hex 非法: {e}"})
            out = dict(client.write_mem(a, payload))
            if note:
                out["addr_note"] = note
            # 批次29：写后回读校验——把「写入被静默吞掉」变成显式 verified=false
            if verify and out.get("ok"):
                out.update(_verify_write(client, a, payload))
                if out.get("verified") is False:
                    out["warning"] = out.get("verify_note")
            elif not verify:
                out["verified"] = None
                out["verify_note"] = "已按 verify=false 跳过回读校验（无法确认写入是否落地）"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    # ---------------- 调试会话控制 ----------------
    @server.tool(
        name="enter_debug",
        title="进入调试模式",
        description=(
            "自动进入 Keil 调试模式（UV_DBG_ENTER）。"
            "若目标本来就在调试态（status=10 正在调试），不会报失败，而是返回 "
            "ok=true + already_in_debug=true + note，可省掉一轮 exit/enter；"
            "返回 ready/ready_waited_ms 表示已确认就绪。"
            "受工程 Load/Flash Download/Run-to-main 设置影响，属于有副作用的操作：若工程 Utilities 勾选了 "
            "Update Target before Debugging（.uvprojx 的 Utilities/Flash1/UpdateFlashBeforeDebugging=1），"
            "Keil 会在进入调试前**自动把最新 .axf 下载进 Flash**（等价一次烧录）——此时编译完直接 "
            "enter_debug 即可，不必先 flash_download；该选项为 0 时 Keil 不下载，板上可能仍是旧固件"
            "（可用 read_project_config 查该字段）。"
            "进入后即可设断点、读变量、运行控制。注意：若当前 Keil 是旧窗口、加载旧固件，进入后调试的是旧代码符号；建议改用 flash_debug 闭环（关旧Keil→编烧→重开→进调试）。受工程 Load/Flash Download/Run-to-main 设置影响，属有副作用操作。需 UVSOCK 已开启。"
            "真机实测：进入调试是异步的——命令返回成功时目标尚未挂载完成，约 0.6~0.7s 后才真正就绪，"
            "期间紧接的读内存/表达式/断点命令会返回 status=6（Target is not in debug mode）。"
            "本工具已自动轮询等待就绪（默认最多 6s），返回 ready 与 ready_waited_ms；"
            "若超时未就绪会给出 warning，此时先读内存会失败，请检查目标板连接或 Keil 是否弹窗待确认。"
        ),
    )
    async def enter_debug() -> str:
        try:
            r = _get_client().enter_debug()
            out = dict(r)
            # 遗留断点预警：.uvoptx 里的持久化断点会在进调试时被 Keil 自动恢复
            # （BK 清不掉），是「目标行为诡异」的隐蔽干扰源，这里主动报出来。
            try:
                info = _read_uvoptx_persistent("")
                items = info.get("breakpoints") or info.get("bps") or []
                out["uvoptx_breakpoints"] = {
                    "count": int(info.get("count", len(items)) or 0),
                    "items": items[:5]}
                if out["uvoptx_breakpoints"]["count"]:
                    out["uvoptx_warning"] = (
                        "工程 .uvoptx 里有 %d 个持久化断点，会随本次进调试被 Keil 自动恢复"
                        "（软件断点命令清不掉）。若目标行为不符合预期，先用 "
                        "list_uvoptx_breakpoints 确认、必要时 clear_uvoptx_breakpoints 清理。"
                        % out["uvoptx_breakpoints"]["count"])
            except Exception:  # noqa: BLE001
                pass
            if not r.get("ok"):
                # status=10「正在调试」不是失败：目标本来就在调试态（上一次 exit_debug 尚未生效、
                # 或人工/其他工具已进入）。确认一下就绪并返回成功，避免 AI 误判后反复重试或重启 Keil。
                already = False
                try:
                    from .uvsock import UV_STATUS_DEBUGGING as _DEBUGGING
                except Exception:  # noqa: BLE001
                    _DEBUGGING = 10
                if r.get("status") == _DEBUGGING:
                    try:
                        already = bool(_get_client().get_status().get("debugging"))
                    except Exception:  # noqa: BLE001
                        already = False
                if already:
                    out["ok"] = True
                    out["ready"] = True
                    out["already_in_debug"] = True
                    out["status_text"] = "已在调试态"
                    out["note"] = (
                        "目标已处于调试态（status=10 正在调试），本次无需重新进入；"
                        "如需重新开始，可先 exit_debug 再 enter_debug。"
                    )
                else:
                    out["diagnosis"] = (
                        "进入调试失败，请依次排查：① 目标板是否已连接且调试器驱动正常；"
                        "② 工程是否已编译出 .axf（缺失/过旧时 Keil 无法加载符号，可先 build_project 或 flash_debug）；"
                        "③ 是否已在调试态（重复 enter 会被拒）。若 Keil 弹出需人工确认的窗口，请在界面处理。"
                    )
            if out.get("ok"):
                # 批次29：记录本次调试会话加载的符号基线（.axf 路径 + 时间戳），
                # 之后 .axf 被重编/重烧即可判定「会话符号已过期」。
                out["symbol_session"] = _mark_debug_session("enter_debug")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="exit_debug",
        title="退出调试模式",
        description=("自动退出 Keil 调试模式（UV_DBG_EXIT）。注意：目标处于运行状态时退出会被拒（status=11），需先 stop 再 exit_debug。"
                     "退出成功后会顺带释放宿主机串口监听占用的 COM 口（否则调试完了串口还占着，Keil 串口窗口/其他工具打不开，WinError=5）；"
                     "释放只放端口，已收日志仍保留、serial_read 继续可读，需要接着采集重新 serial_monitor_start() 即可。"),
    )
    async def exit_debug() -> str:
        try:
            r = _get_client().exit_debug()
            if r.get("ok"):
                _clear_debug_session("exit_debug 成功")
                # 调试结束＝串口用完就还（端口释放，已收日志保留）
                _release_serial("退出调试（exit_debug 成功）", r)
                return _js(r)
            out = dict(r)
            try:
                # with_dialogs：原先 health 里根本没有 modal_dialogs 键，下面那条模态框
                # 分支永远不会命中（死代码），退出调试被模态框挡住时给不出可用诊断。
                health = winutil.keil_health(with_dialogs=True)
            except Exception:  # noqa: BLE001
                health = {}
            out["keil"] = health
            code = health.get("code")
            if code in ("keil_not_running", "port_not_listening"):
                out["diagnosis"] = (
                    "Keil 已经不在（%s）——本次调试会话实际已丢失，退出调试自然失败。"
                    "可用 restart_keil 一步恢复（关闭残留 Keil → 脱离父进程重启 → 等 UVSOCK "
                    "就绪 → 重建连接）；注意重启会丢失当前会话（断点/观察变量需重新设置），"
                    "但 .uvoptx 里的持久化断点会被 Keil 自动恢复。" % code)
            elif health.get("modal_dialogs"):
                shown = []
                for d in health["modal_dialogs"][:2]:
                    txt = (d.get("message") or "").strip()
                    btns = "、".join(d.get("button_texts") or [])
                    shown.append("%s%s%s" % (d.get("title") or "(无标题)",
                                             ("：" + txt) if txt else "",
                                             ("[按钮: %s]" % btns) if btns else ""))
                out["diagnosis"] = (
                    "退出调试被拒，且检测到 Keil 有模态对话框（%s）——命令会被阻塞。"
                    "可用 dismiss_dialog 读取正文并按按钮关闭（如 dismiss_dialog(button=\"确定\")），"
                    "或直接在 Keil 界面处理，然后重试。"
                    % "；".join(shown))
            else:
                out["diagnosis"] = (
                    "退出调试失败：目标在运行态时会被拒（status=11），请先 stop 再 exit_debug；"
                    "若反复失败，可用 keil_health 看进程/端口/模态框状态，"
                    "或用 reset_connection / restart_keil 恢复会话。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            try:
                health = winutil.keil_health()
            except Exception:  # noqa: BLE001
                health = {}
            return _js({"ok": False, "error": str(e), "keil": health,
                        "diagnosis": "退出调试过程出错；若 Keil 已退出，用 restart_keil 一步恢复。"})

    # ---------------- 断点管理 ----------------
    @server.tool(
        name="set_breakpoint",
        title="设置断点",
        description=(
            "在指定符号或地址处设置软件断点。expr 可为函数名/变量名"
            "（如 'main'）或地址（如 '0x08001034'）。返回是否成功。注意：设断点走命令窗口 BS，会触发 Keil 异步推送断点消息，紧随其后的命令响应可能被污染（本工具已改为先 calc_expression 取地址再 BS 0xaddr）；设断点后立即 run/step 前需稍等异步消息落地。需已进入调试且配置 .axf。"
        ),
    )
    async def set_breakpoint(expr: str | int) -> str:
        global _bp_counter
        expr = _addr_arg(expr)
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
                l = loc.locate(addr) if loc else None
                if l and l.get("file"):
                    out["file"] = l["file"]
                    out["line"] = l["line"]
                elif l and not l.get("covered"):
                    out["location_note"] = (
                        "该地址不在当前 .axf 符号覆盖范围内（未匹配到包含它的函数/对象），未给出 file/line，仅按地址下断；若目标是其他固件，请先 set_symbol_file 切到对应 .axf")
                _bp_counter += 1
                _breakpoints.append({"id": _bp_counter, "expr": expr, "address": hex(addr),
                                     "file": out.get("file"), "line": out.get("line")})
                out["breakpoint_id"] = _bp_counter
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="set_conditional_breakpoint",
        title="设置条件断点",
        description=(
            "在符号/地址处设带条件的软件断点：仅当 condition（C 表达式，如 'R0==5'、"
            "'test_array[0]==0x11111111'）成立时才暂停；count 为命中计数（默认1，第 count 次满足才停）。"
            "用于只在特定条件/次数下停住，减少无关中断。需已进入调试且配置 .axf。注意：同 set_breakpoint——设断点后异步消息可能污染下一条命令，设断点与运行控制之间建议留落地时间。需已进入调试且配置 .axf。"
        ),
    )
    async def set_conditional_breakpoint(expr: str, condition: str, count: int = 1) -> str:
        global _bp_counter
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
                l = loc.locate(addr) if loc else None
                if l and l.get("file"):
                    out["file"] = l["file"]
                    out["line"] = l["line"]
                elif l and not l.get("covered"):
                    out["location_note"] = (
                        "该地址不在当前 .axf 符号覆盖范围内（未匹配到包含它的函数/对象），未给出 file/line，仅按地址下断；若目标是其他固件，请先 set_symbol_file 切到对应 .axf")
                _bp_counter += 1
                _breakpoints.append({"id": _bp_counter, "expr": expr, "address": hex(addr), "condition": cond,
                                     "count": count, "file": out.get("file"), "line": out.get("line")})
                out["breakpoint_id"] = _bp_counter
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
            "返回设断地址与 文件:行。命中后可用 get_current_location/snapshot 看是谁改的。需已进入调试。注意：数据/访问断点依赖硬件 DWT 支持，可同时生效个数有限（通常2-4个），设多了会失败；命中后目标暂停，用 get_current_location/snapshot 看现场。需已进入调试。"
        ),
    )
    async def set_watchpoint(expr: str | int, access: str = "write", count: int = 1) -> str:
        global _bp_counter
        expr = _addr_arg(expr)
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
            # 批次24：记录观察地址当前值，作为「命中时该地址是否真被改写」的基线。
            # 真机上观察点往往在 run 后几微秒内就命中、目标随即停住，等待开始时的
            # 现场读取拿到的已是变动后的值，故基线必须在设点时就留下。
            try:
                # 仅在目标停止时记录：运行中读到的值可能是陈旧值，用它当基线会高估
                # 「本次等待期间被改写」的证据强度，宁可退化为「无基线」。
                if client.get_status().get("running") is False:
                    client.watch_remember_values([addr])
                    out["baseline_ready"] = True
                else:
                    out["baseline_ready"] = False
                    out["baseline_note"] = ("目标当时处于运行态，未记录值变化基线；"
                                            "命中判定会退化为「无基线」而不冒充证据")
            except Exception:  # noqa: BLE001
                pass
            loc = _get_locator()
            l = loc.locate(addr) if loc else None
            if l and l.get("file"):
                out["file"] = l["file"]
                out["line"] = l["line"]
            elif l and not l.get("covered"):
                out["location_note"] = (
                    "该地址不在当前符号覆盖范围内，未给出 file/line（数据断点按地址生效即可）")
            _bp_counter += 1
            _watchpoints.append({"id": _bp_counter, "expr": expr, "address": hex(addr), "access": acc,
                                 "count": count, "file": out.get("file"),
                                 "line": out.get("line")})
            out["watchpoint_id"] = _bp_counter
            out["message"] = f"已设置{acc}数据断点，命中即暂停"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="clear_watchpoint",
        title="清除数据断点",
        description=("清除指定数据断点。expr 传变量名/0x 地址，或直接用 bp_id。实现上先解析 Keil 真实断点编号再"
                     "`BK <number>`（真机实测：数据观察点按地址清除会报 error 72 invalid item number，看似成功其实没清掉）。"
                     "返回 cleared_by 表示实际用的方式；若真实断点表里找不到会明确报 ok=false 并给出原因。"),
    )
    async def clear_watchpoint(expr: str | int = "", bp_id: int | None = None) -> str:
        expr = _addr_arg(expr)
        try:
            client = _get_client()
            e = (expr or "").strip()
            removed = []
            target = e
            swap_from = None
            if bp_id is not None:
                match = [w for w in _watchpoints if w.get("id") == bp_id]
                if not match:
                    return _js({"ok": False, "bp_id": bp_id,
                                "error": f"内部数据断点表中无 id={bp_id}（可用 list_watchpoints 查看）"})
                removed = match
                target = removed[0].get("address") or removed[0].get("expr")
            elif e:
                removed = [w for w in _watchpoints
                           if w.get("expr") == e or w.get("address") == e]
                if removed and removed[0].get("address") and removed[0]["address"] != target:
                    # 真机实测（批次23 全量回归）：数据断点在命令窗口 BL 里的 expr 就是地址
                    # （形如 '0x20000000'），传符号名发 `BK test_array` 解析不出编号、清不掉。
                    # 故命中内部记录时优先用记录里的确切地址——BK 由地址能映射到 Keil 编号。
                    swap_from, target = target, removed[0]["address"]
            if not target:
                return _js({"ok": False, "error": "需提供 expr 或 bp_id 指定要清除的数据断点"})
            r = client.clear_breakpoint(target)
            ids = {w.get("id") for w in removed}
            success = bool(r.get("ok"))
            if success:
                _watchpoints[:] = [w for w in _watchpoints if w.get("id") not in ids]
            out = {"ok": success, "cleared_target": target,
                   "status_text": r.get("status_text"), "removed": removed,
                   "cleared_by": r.get("cleared_by"),
                   "remaining": len(_watchpoints)}
            if swap_from:
                out["resolve_note"] = ("数据断点按符号名清不掉（BL 里记的是地址），"
                                       "已改用记录地址 %s 清除（原 expr：%s）"
                                       % (target, swap_from))
            if not success:
                out["error"] = ("Keil 清除未确认成功：%s" % (r.get("error") or r))
                out["diagnosis"] = (
                    "数据观察点清不掉时的排查：① 用 list_breakpoints 看 real 字段确认真实断点编号，"
                    "再 BK <编号>（按地址会报 error 72）；② 目标需处于停止状态；"
                    "③ 顽固残留可用 clear_all_watchpoints(hard=true) 以 BK * 一次性清空 Keil 侧断点。")
                if r.get("console"):
                    out["console"] = r["console"]
            else:
                out["note"] = ("数据断点依赖硬件 DWT（可同时生效 2-4 个），清除后相关触发槽位应已释放；"
                               "本次%s。" % (r.get("note") or "已清除"))
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "bp_id": bp_id, "error": str(e)})

    @server.tool(
        name="list_watchpoints",
        title="列出数据断点",
        description="列出本服务设置的内部数据断点记录（命令窗口 BL 对数据断点输出不经 socket 回传）。注意：返回的是本服务内部记录（命令窗口 BL 对数据断点的输出不经 socket 回传），非 Keil 界面实时列表。",
    )
    async def list_watchpoints() -> str:
        try:
            return _js({"ok": True, "watchpoints": list(_watchpoints),
                        "total": len(_watchpoints),
                        "note": "数据断点依赖硬件 DWT，支持个数有限；本列表为本服务内部 id 记录，用于按 bp_id 清除。"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_breakpoint",
        title="清除断点",
        description=(
            "清除断点。三种指定方式（任选其一）：expr 传符号/地址；bp_id 传本服务内部 id；"
            "keil_number 传 Keil 界面/命令窗口 BL 里的真实断点编号。"
            "清除走命令窗口 BK：**数据观察点按地址清不掉**（BK <地址> 时 UVSOCK 回成功、"
            "窗口却报 error 72 invalid item number），必须按编号清除，故内部会自动把地址/"
            "符号解析成 Keil 编号再 BK <编号>，解析不出才回退按地址。"
            "bp_id 在本服务内无此 id 时会自动改按 Keil 真实编号处理并给出 note，"
            "不必再用 clear_all_*(hard=true) 一刀切。"
            "注意：清除断点同样走命令窗口并触发异步消息，清除后立即 run/step 前建议稍等。需已进入调试。"
        ),
    )
    async def clear_breakpoint(expr: str | int = "", bp_id: int | None = None,
                               keil_number: int | None = None) -> str:
        expr = _addr_arg(expr)
        try:
            # 定位清除目标：优先内部断点 id，其次按地址/符号名；用确切地址发 BK 更可靠
            target = (expr or "").strip()
            removed = []
            cb_note = None
            # keil_number：直接按 Keil 真实编号清除（数据观察点只能这样清）
            if keil_number is None and bp_id is not None:
                match = [b for b in _breakpoints if b.get("id") == bp_id]
                if match:
                    removed = match
                    target = removed[0].get("address") or removed[0].get("expr")
                else:
                    # 内部表里没有：很可能是用户看到 Keil 界面/BL 输出的编号后直接传进来，
                    # 这里改按 Keil 真实编号处理，避免「只有 BK * 一条路」。
                    keil_number = bp_id
                    cb_note = (f"内部断点表无 id={bp_id}，已改按 Keil 真实断点编号清除"
                               f"（可用 list_breakpoints 的 real 字段核对编号）")
            if keil_number is not None:
                r = _get_client().clear_breakpoint(str(int(keil_number)))
                if not r.get("ok"):
                    return _js({"ok": False, "keil_number": keil_number,
                                "error": f"按 Keil 编号 {keil_number} 清除失败: {r}"})
                out = {"ok": True, "cleared_by": "keil_number",
                       "keil_number": int(keil_number),
                       "resolved": {"bp_number": r.get("bp_number"),
                                    "target": r.get("cleared_target")},
                       "status_text": r.get("status_text"),
                       "note": r.get("note") or f"已按 Keil 编号 {int(keil_number)} 清除"}
                if cb_note:
                    out["resolve_note"] = cb_note
                sync = _sync_internal_after_bk(_get_client())
                if sync:
                    out["internal_sync"] = sync
                return _js(out)
            cb_swap = None
            if target:
                removed = [b for b in _breakpoints
                           if b.get("address") == target or b.get("expr") == target]
                if removed and removed[0].get("address") and removed[0]["address"] != target:
                    # 同上：符号名换成内部记录里的确切地址，BK 才能解析到真实编号
                    # （数据观察点在 BL 里的 expr 就是地址，按符号名发 BK 会报 error 72）
                    cb_swap, target = target, removed[0]["address"]
            if not target:
                return _js({"ok": False, "error": "需提供 expr（符号/地址）或 bp_id 指定要清除的断点"})
            r = _get_client().clear_breakpoint(target)  # BK target：用确切地址更可靠
            ids = {b.get("id") for b in removed}
            _breakpoints[:] = [b for b in _breakpoints if b.get("id") not in ids]
            out = {"ok": r.get("ok"), "cleared_target": target,
                   "status_text": r.get("status_text"),
                   "removed": removed, "remaining": len(_breakpoints),
                   "command": r.get("command")}
            if cb_swap:
                out["resolve_note"] = ("已改用内部记录的确切地址 %s 清除（原 expr：%s），"
                                       "避免按符号名发 BK 解析不到编号" % (target, cb_swap))
            if not r.get("ok"):
                out["error"] = f"Keil 清除命令未确认成功: {r}"
            out["note"] = ("Cortex-M 目标经 SWD/JTAG 调试时代码断点默认用硬件断点(FPB)，"
                           "清除不涉及改写 Flash，无需重新烧录；仅当断点超出硬件槽位而落到 "
                           "Flash 软件断点、或使用模拟器(Simulator)时，才需重新烧录恢复原指令")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "bp_id": bp_id, "error": str(e)})

    # ---- .uvoptx 持久化断点（Keil 在下次进调试时自动恢复，BK 清不掉）----
    def _uvoptx_project_path(project: str) -> str:
        p = (project or "").strip() or (_builder_cfg.get("default_project") or "")
        return _uvoptx.uvoptx_path_for(p) if p else ""

    def _sync_internal_after_bk(client) -> dict | None:
        """BK 之后按 Keil 真实断点表回收内部记录，避免内部 id 表与板上实际脱节。"""
        try:
            real = client.list_breakpoints_real()
        except Exception:  # noqa: BLE001
            return None
        if not real.get("ok"):
            return None
        alive = set()
        for b in real.get("breakpoints") or []:
            try:
                a = int(str(b.get("address")), 16)
            except Exception:  # noqa: BLE001
                continue
            alive.add(a)
            alive.add(a | 1)
        before_bp, before_wp = len(_breakpoints), len(_watchpoints)
        def _alive(b):
            try:
                a = int(str(b.get("address")), 16)
            except Exception:  # noqa: BLE001
                return True
            return a in alive or (a | 1) in alive
        _breakpoints[:] = [b for b in _breakpoints if _alive(b)]
        _watchpoints[:] = [w for w in _watchpoints if _alive(w)]
        return {"internal_breakpoints": [before_bp, len(_breakpoints)],
                "internal_watchpoints": [before_wp, len(_watchpoints)],
                "real_total": real.get("count")}

    def _read_uvoptx_persistent(project: str = "") -> dict:
        path = _uvoptx_project_path(project)
        if not path:
            return {"ok": False, "error": "未指定工程（传 project 或配置 --default-project），无法定位 .uvoptx"}
        if not os.path.isfile(path):
            return {"ok": True, "path": path, "count": 0, "breakpoints": [],
                    "note": "工程无 .uvoptx 文件（尚未生成或已删除）"}
        try:
            bps = _uvoptx.parse_uvoptx_breakpoints(path)
            return {"ok": True, "path": path, "count": len(bps), "breakpoints": bps,
                    "note": "Keil 持久化断点：BK 清不掉，Keil 下次进入调试会自动恢复"
                            "（清除用 clear_uvoptx_breakpoints）"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "path": path, "error": str(e)}

    @server.tool(
        name="list_uvoptx_breakpoints",
        title="读取持久化断点(.uvoptx)",
        description=(
            "读取 Keil 工程 .uvoptx 中持久化的断点列表（不依赖 UVSOCK，直接解析 XML）。"
            "这些断点由 Keil 在调试期间写入工程文件，会在下次进入调试时自动恢复，"
            "命令窗口 BK 无法清除（即 clear_breakpoint 返回成功、断点却依然生效的根因）。"
            "project 传 .uvprojx/.uvoptx 路径（省略用 --default-project）。"
            "配合 clear_uvoptx_breakpoints 使用：先确认残留，再清理。注意：Keil 运行时会用内存断点回写，清理前建议先 close_uvision。"
        ),
    )
    async def list_uvoptx_breakpoints(project: str = "") -> str:
        try:
            return _js(_read_uvoptx_persistent(project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_uvoptx_breakpoints",
        title="清除持久化断点(.uvoptx)",
        description=(
            "清除 Keil 工程 .uvoptx 中持久化的断点（直接改写 XML，不依赖 UVSOCK），"
            "解决 BK 清不掉、下次进调试自动恢复的顽固残留。project 传 .uvprojx/.uvoptx 路径"
            "（省略用 --default-project）；backup=True（默认）先备份为 .uvoptx.mdkdebug.bak。"
            "注意：Keil 打开该工程时会用内存中的断点覆盖 uvoptx，务必在 Keil 关闭后（或先调 close_uvision）执行。"
        ),
    )
    async def clear_uvoptx_breakpoints(project: str = "", backup: bool = True) -> str:
        try:
            path = _uvoptx_project_path(project)
            if not path:
                return _js({"ok": False, "error": "未指定工程（传 project 或配置 --default-project）"})
            r = _uvoptx.clear_uvoptx_breakpoints(path, backup=backup)
            r["note"] = ("已清除 .uvoptx 持久断点。若 Keil 正打开该工程，请先关闭 Keil 再清理，"
                         "否则会被其内存断点回写覆盖。")
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="list_breakpoints",
        title="列出断点",
        description=("列出断点。返回两部分：① 本服务内部记录（breakpoints/内部 id，用于按 bp_id 清除）；"
                     "② real 字段——本会话 Keil 的**真实断点表**（解析命令窗口 BL 输出获得，含 Keil 断点编号、"
                     "类型 exec/access、地址、CNT、enabled）。注意：真机实测本版 Keil 的 CNT 是断点的计数条件"
                     "设置值（.uvoptx 的 break_if_rcount），**不随命中递增**，不能当命中次数用。"
                     "real 才是板上实际生效的断点：.uvoptx 持久化断点、"
                     "数据观察点都会出现在这里。注意清除数据观察点必须按 Keil 编号（按地址会报 error 72）。"
                     "另附 uvoptx 字段暴露工程里 BK 清不掉、下次进调试会自动恢复的持久化断点。"),
    )
    async def list_breakpoints() -> str:
        try:
            out = {"ok": True, "breakpoints": list(_breakpoints),
                   "total": len(_breakpoints),
                   "note": "breakpoints 是本服务内部 id 记录（用于按 bp_id 清除）；"
                           "真实生效的断点见 real 字段（解析 Keil 命令窗口 BL 输出，含 Keil 断点编号）。"}
            # 真实断点表：解析 BL 输出（真机实测 BL 会经 0x5020 命令输出通道回传）
            try:
                real = _get_client().list_breakpoints_real()
                out["real"] = real
                out["real_total"] = real.get("count", 0)
                acc = [b for b in (real.get("breakpoints") or [])
                       if b.get("kind") == "access"]
                if acc:
                    out["note"] += (" 其中 %d 个是数据观察点，清除请用 clear_watchpoint / "
                                    "clear_all_watchpoints（内部按 Keil 编号 BK，按地址会报 error 72）。"
                                    % len(acc))
            except Exception as e:  # noqa: BLE001
                out["real"] = {"ok": False, "error": str(e)}
            # 附加：工程 .uvoptx 中 Keil 持久化的断点（BK 清不掉，下次进调试自动恢复）
            uv = _read_uvoptx_persistent()
            out["uvoptx"] = uv
            if uv.get("ok") and uv.get("count"):
                out["note"] += (f" 另：工程 .uvoptx 有 {uv['count']} 个持久化断点"
                                "（BK 清不掉、下次进调试自动恢复），见 uvoptx 字段，"
                                "可用 clear_uvoptx_breakpoints 清除。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_all_breakpoints",
        title="清除全部软件断点",
        description=(
            "清除软件断点：清空本服务内部记录并逐个按确切地址发 BK。include_uvoptx=True 时"
            "一并清除工程 .uvoptx 中 Keil 持久化的断点（BK 清不掉、下次进调试会自动恢复的残留）。"
            "注意：Cortex-M 目标经 SWD/JTAG 调试时，未超出硬件断点槽位(FPB)的代码断点走硬件断点，"
            "清除不涉及改写 Flash，无需重新烧录；仅当断点数量超出硬件槽位而落到 Flash 软件断点、"
            "或使用模拟器(Simulator)时才需重新烧录恢复原指令。"
            "清理 .uvoptx 需 Keil 已关闭（否则被内存断点回写覆盖）。"
        ),
    )
    async def clear_all_breakpoints(include_uvoptx: bool = False,
                                    hard: bool = False) -> str:
        try:
            client = _get_client()
            cleared = []
            hard_result = None
            if hard:
                # BK * 一次性清空 Keil 侧全部断点（含 .uvoptx 恢复出来的持久断点与数据观察点），
                # 比逐个按地址清除可靠；代价是会连带清掉非本服务设置的断点。
                hard_result = client.exec_command_checked("BK *", settle=0.2)
                _breakpoints[:] = []
            for b in list(_breakpoints):
                target = b.get("address") or b.get("expr")
                try:
                    r = client.clear_breakpoint(target)
                    cleared.append({"id": b.get("id"), "expr": b.get("expr"),
                                    "address": b.get("address"), "ok": r.get("ok")})
                except Exception as e:  # noqa: BLE001
                    cleared.append({"id": b.get("id"), "expr": b.get("expr"),
                                    "address": b.get("address"), "ok": False, "error": str(e)})
            _breakpoints[:] = []
            out = {"ok": True, "cleared": len(cleared), "items": cleared,
                   "note": _bp_clear_note(len(cleared))}
            if hard:
                out["hard"] = True
                out["hard_result"] = hard_result
                real = {}
                try:
                    real = _get_client().list_breakpoints_real()
                    out["real_after"] = {"count": real.get("count", 0)}
                except Exception as e:  # noqa: BLE001
                    out["real_after"] = {"error": str(e)}
                if not hard_result or not hard_result.get("ok"):
                    out["ok"] = False
                    out["error"] = ("BK * 未确认成功：%s" % (hard_result or {}))
                else:
                    out["note"] += (" 已用 BK * 清空 Keil 侧全部断点（含 .uvoptx 持久断点与数据观察点）；"
                                    "当前真实断点数 %s。" % out["real_after"].get("count"))
            # 可选：一并清除 .uvoptx 持久化断点（BK 清不掉的残留）
            if include_uvoptx:
                path = _uvoptx_project_path("")
                if not path:
                    out["uvoptx"] = {"ok": False, "error": "未配置默认工程，无法定位 .uvoptx（请改用 clear_uvoptx_breakpoints 并传 project）"}
                else:
                    out["uvoptx"] = _uvoptx.clear_uvoptx_breakpoints(path)
                    out["note"] += " 已一并清理 .uvoptx 持久断点（需 Keil 已关闭才不会被回写）。"
            else:
                uv = _read_uvoptx_persistent()
                if uv.get("ok") and uv.get("count"):
                    out["uvoptx_persistent"] = {"count": uv["count"], "path": uv.get("path")}
                    out["note"] += (f" 注意：工程 .uvoptx 仍有 {uv['count']} 个持久化断点未清"
                                    "（BK 清不掉、下次进调试自动恢复），可设 include_uvoptx=True 或调 clear_uvoptx_breakpoints 清除。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_all_watchpoints",
        title="清除全部数据断点",
        description=(
            "清除全部数据断点（逐个发 BK），并清空内部数据断点表，用于一次释放所有 DWT 数据断点槽位。"
            "实现上按 Keil 真实断点编号清除（真机实测：数据观察点按地址 BK 会报 error 72，看似成功实则没清掉）。"
            "hard=true 时用 `BK *` 一次性清空 Keil 侧全部断点（含 .uvoptx 持久断点），"
            "代价是也会清掉非本服务设置的代码断点；用于顽固残留。"
            "返回 real_after 给出清理后 Keil 真实断点数，便于确认是否真的清干净。"
        ),
    )
    async def clear_all_watchpoints(hard: bool = False) -> str:
        try:
            client = _get_client()
            cleared = []
            hard_result = None
            if hard:
                hard_result = client.exec_command_checked("BK *", settle=0.2)
                _watchpoints[:] = []
            else:
                for w in list(_watchpoints):
                    target = w.get("address") or w.get("expr")
                    try:
                        r = client.clear_breakpoint(target)
                        item = {"id": w.get("id"), "expr": w.get("expr"),
                                "address": w.get("address"), "ok": r.get("ok"),
                                "cleared_by": r.get("cleared_by")}
                        if not r.get("ok"):
                            item["error"] = r.get("error")
                        cleared.append(item)
                    except Exception as e:  # noqa: BLE001
                        cleared.append({"id": w.get("id"), "expr": w.get("expr"),
                                        "address": w.get("address"), "ok": False,
                                        "error": str(e)})
                if all(i.get("ok") for i in cleared):
                    _watchpoints[:] = []
            out = {"ok": True, "cleared": len(cleared), "items": cleared,
                   "hard": bool(hard), "hard_result": hard_result}
            failed = [i for i in cleared if not i.get("ok")]
            if failed:
                out["ok"] = False
                out["error"] = "有 %d 个数据断点未确认清除" % len(failed)
                out["diagnosis"] = ("可按 Keil 真实编号清除：先用 list_breakpoints 看 real 字段拿到编号，"
                                    "再 BK <编号>；顽固残留用 hard=true（BK * 一次性清空 Keil 侧断点）。")
            # 复查 Keil 真实断点数，避免「说清了其实没清」
            try:
                real = client.list_breakpoints_real()
                out["real_after"] = {"count": real.get("count", 0),
                                     "breakpoints": real.get("breakpoints") or []}
                if not hard and real.get("count"):
                    out["note"] = ("清除后 Keil 仍有 %d 个断点（含代码断点/持久化断点，见 real_after）；"
                                   "数据断点消失即表示槽位已释放。" % real["count"])
            except Exception as e:  # noqa: BLE001
                out["real_after"] = {"error": str(e)}
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 符号检索 ----------------
    @server.tool(
        name="set_symbol_file",
        title="设置/切换当前调试符号文件",
        description=(
            "运行时切换调试符号文件，解决符号绑定错误（find_symbol/get_current_location/"
            "断点行号解析到错误的 .axf）问题。path 支持 .axf（完整 DWARF 行号/局部变量）"
            "或 .map（函数/全局符号地址，无行号）。加载成功返回符号条目数；失败给出明确错误"
            "（文件不存在/无DWARF/格式不支持）。注意：建议 AI 落地后先 list_symbol_projects "
            "查看候选，再 set_symbol_file 切到当前正在调试的固件符号，避免符号漂移误判。"
        ),
    )
    async def set_symbol_file(path: str) -> str:
        try:
            ok, msg, n = _load_symbol_file(path)
            if not ok:
                return _js({"ok": False, "error": msg})
            return _js({"ok": True, "message": msg, "entries": n,
                        "source_type": _symbol_cfg.get("source_type")})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="list_symbol_projects",
        title="列出预登记候选符号工程",
        description=(
            "返回预登记的可切换符号工程（如 SVCRTOS_TEST 内核、mdk_test），含 .axf/.map "
            "路径与 flash 地址段。AI 据此了解可切换的符号目标，并可与 set_symbol_file 配合"
            "把符号切到当前调试固件。flash 段用于 PC 自动匹配（辅助）。注意：仅列出本机存在的候选。"
        ),
    )
    async def list_symbol_projects() -> str:
        try:
            proj = []
            for p in _SYMBOL_PROJECTS:
                proj.append({
                    "name": p["name"],
                    "axf": p.get("axf"),
                    "map": p.get("map"),
                    "flash_start": "0x%08x" % p["flash_start"],
                    "flash_size": "0x%x" % p["flash_size"],
                    "axf_exists": bool(p.get("axf") and os.path.isfile(p["axf"])),
                    "map_exists": bool(p.get("map") and os.path.isfile(p["map"])),
                })
            return _js({"ok": True, "count": len(proj), "projects": proj,
                        "current_axf": _symbol_cfg.get("axf"),
                        "current_source_type": _symbol_cfg.get("source_type")})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    @server.tool(
        name="set_reloc_delta",
        title="设置 App 符号重定位偏移",
        description=(
            "设置全局符号重定位偏移（默认 0），解决「读 App 侧变量还要手工做 "
            "- SVCRT_RELOC_DELTA(0xF000) 换算」的麻烦。"
            "App 运行期重定位后：运行地址 = 链接地址(.axf 符号地址) + delta。设置一次后，"
            "read_variable / read_mem / find_symbol / wait_breakpoint 都会自动把符号地址偏到"
            "运行地址（显式传数字地址的不偏移），返回里同时给 link_address 与 run_address 便于核对。"
            "delta 支持 0x 十六进制 / 十进制 / 负数；传 0 即关闭。"
            "注意：只影响符号名解析，且是全局的——切回内核符号调试时记得清 0。"
        ),
    )
    async def set_reloc_delta(delta: str = "0x0") -> str:
        try:
            d = _parse_reloc_delta(delta)
            if d is None:
                d = 0
            old = int(_reloc_cfg.get("delta") or 0)
            _reloc_cfg["delta"] = d
            return _js({"ok": True, "previous_delta": "0x%X" % old,
                        "reloc_delta": "0x%X" % d, "delta_dec": d,
                        "note": ("已关闭符号重定位偏移（按符号名取地址不再偏移）" if d == 0 else
                                 "此后按符号名取地址将自动 +0x%X，读 App 变量直接传符号名即可" % d)})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "delta": delta, "error": str(e)})

    @server.tool(
        name="find_symbol",
        title="检索符号",
        description=(
            "从 .axf ELF 符号表模糊检索 函数/全局变量 符号（query 为子串，大小写不敏感，空则列出全部；"
            "参数名 query 与 name 等价，传哪个都行）。"
            "传了 reloc_delta（或已 set_reloc_delta）时，每条结果会附带 run_addr ——"
            "App 重定位后的实际运行地址，供 set_breakpoint / read_mem 直接使用。"
            "AI 想读取某个全局变量或跳到某函数而不知道确切名字时，先用它搜到符号名与地址，"
            "再配合 calc_expression / read_variable / set_breakpoint / disassemble 使用。"
            "kind 可取 all/func/object/global/local 过滤。需配置 .axf 调试符号。注意：依赖 .axf ELF 符号表（需已编译且配置 .axf），未编译或符号被 strip 时查不到；匹配为子串模糊，注意区分同名符号。"
        ),
    )
    async def find_symbol(query: str = "", limit: int = 50, kind: str = "all",
                          name: str = "", reloc_delta: str = "") -> str:
        try:
            q = (query or "").strip() or (name or "").strip()
            loc = _get_locator()
            if loc is None:
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号，或未从工程推断到）"})
            symbols = loc.search_symbols(query=q, limit=max(1, min(limit, 200)), kind=kind)
            out = {"ok": True, "query": q, "kind": kind,
                   "count": len(symbols), "symbols": symbols}
            delta, dnote = _eff_reloc_delta(reloc_delta)
            if delta:
                for sym in symbols:
                    try:
                        v = sym.get("addr")
                        iv = int(str(v), 16) if str(v).lower().startswith("0x") else int(v)
                        sym["run_addr"] = hex((iv + delta) & 0xFFFFFFFF)
                    except Exception:  # noqa: BLE001
                        continue
                out["reloc_delta"] = "0x%X" % delta
                out["reloc_note"] = dnote + "；run_addr = addr + reloc_delta"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "query": query, "error": str(e)})

    # ---------------- 位置定位 / run to cursor ----------------
    @server.tool(
        name="get_current_location",
        title="读取当前执行位置",
        description=(
            "读取当前 PC，定位到 源文件:行号 并返回该行附近的源码上下文，"
            "同时给出调用栈（PC + LR 反查）。让 AI 像人一样知道程序停在哪、看的是什么代码。"
            "需已进入调试状态且配置了 .axf 调试符号。注意：读 PC 已做脏值过滤与重试（run 到断点刚停止瞬间 PC 可能读到脏值1，单步可能读到 SRAM 脏值）。调用栈为 SP+LR 栈启发式回溯（每帧带 origin 与 confidence；confidence=low 表示该帧疑似栈中陈旧值、且其后帧已截断），在全速运行后手动 stop 或 SysTick 中断频繁场景层数受限/可能错位。"
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
            "让 AI 看到当前函数（而非仅全局变量）的局部状态。需已进入调试且配置 .axf。注意：依赖 .axf(DWARF) 且需 CPU 暂停在正常 C 函数内；若停在 SysTick 中断/异常 handler 或全速运行后手动 stop 处，局部变量解析可能不准或为空（硬件限制）。"
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
            meta = loc.local_var_meta(pc) if hasattr(loc, "local_var_meta") else None
            names = [v["name"] for v in meta["vars"]] if meta and meta.get("vars") else None
            if not names:
                names = loc.local_variables(pc)
                meta = None
            if names is None:
                return _js({"ok": False, "pc": hex(pc), "error": "未从 .axf 定位到当前函数或变量信息"})
            cur = loc.addr_to_location(pc)
            out = {"ok": True, "pc": hex(pc)}
            if cur:
                out["file"] = cur["file"]
                out["line"] = cur["line"]
            pinfo = {v["name"]: v for v in (meta or {}).get("vars", [])}
            at_entry = _near_function_entry(pc, meta)
            fallbacks = []
            vars_list = []
            for name in names:
                try:
                    r = client.calc_expression(name)
                    item = {"name": name, "ok": r.get("ok"),
                            "value_type": r.get("value_type"),
                            "value": r.get("value")}
                except Exception as ex:  # noqa: BLE001
                    item = {"name": name, "ok": False, "error": str(ex)}
                p = pinfo.get(name)
                if (at_entry and p and p.get("is_param")
                        and (not item.get("ok") or item.get("value") in (0, None))):
                    fb = _aapcs_param_fallback(client, p.get("param_index"), regs)
                    if fb:
                        item.update(fb)
                        item["note"] = ("当前 PC 位于函数入口(prologue 阶段)，表达式求值未取到有效值，"
                                        "已按 AAPCS 回退读取；该值为按调用约定推断，单步过 prologue 后更准确。")
                        fallbacks.append(name)
                vars_list.append(item)
            out["locals"] = vars_list
            if fallbacks:
                out["param_fallback"] = {
                    "names": fallbacks,
                    "note": ("函数入口处 DWARF 位置描述可能未就绪：前 4 个参数取 R0-R3，"
                             "第 5 个起取栈；已回退读取的参数仅供参考。"),
                }
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="snapshot",
        title="获取调试状态快照",
        description=(
            "一次返回当前调试位置的全貌：PC、文件:行、源码上下文、完整调用栈、当前函数局部变量，"
            "以及指定的全局变量（globals 传变量名列表，数组或逗号/分号分隔字符串均可）。"
            "AI 排查问题时一次调用即可获得完整画面，"
            "避免多次 get_current_location/read_locals/read_variable 往返。globals 可选，"
            "如 ['SystemCoreClock','test_array']。需已进入调试且配置 .axf。注意：聚合 read_locals/get_current_location，同样受中断上下文限制——全速运行后手动 stop 或停在 SysTick 中断时，局部变量与完整调用栈可能层数受限/为空。"
        ),
    )
    async def snapshot(globals: list | str = None, source_context: int = 4) -> str:
        try:
            globals = _csv_tokens(globals)
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
            "expressions 为表达式列表，如 ['SystemCoreClock','timer.sec','*(uint32_t*)0x20000000']；"
            "也接受分隔符字符串（数组写法优先；字符串写法建议用分号分隔，避免表达式内部的逗号被拆开）。"
            "需已进入调试状态。注意：需目标暂停，运行中表达式无法求值；刚停止瞬间个别表达式可能读到脏值。"
        ),
    )
    async def watch(expressions: list | str) -> str:
        try:
            expressions = _csv_tokens(expressions)
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
            "name 为全局结构体变量名（如 'hUart1'、'timHandle'）。需已进入调试且配置 .axf。注意：依赖 DWARF 类型信息解析成员布局，局部/内联结构体或停在中断上下文时可能解析不到；需目标暂停在正常函数内。仅支持结构体/联合体，数组/指针另用 read_variable。"
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
            "排查函数参数传错、返回值不对、寄存器被踩等问题时使用。需已进入调试状态。注意：需目标暂停。真机实测 halt 后首次读到的 PC 可能是上一次 halt 的残留值（LR/SP 已更新），"
            "本工具因此按'连续采样收敛'判定（连续两次 PC/LR/SP 一致才采纳），返回 stable 标记；"
            "stable=false 表示未收敛、PC 不可信，请重试。SP/LR 在中断上下文为现场脏值，AAPCS 解读仅对普通函数调用点成立。"
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
            # 标注 PC 可信度：真机反馈「读到的 PC 可能是上一次 halt 的残留值」，
            # 仅凭 ok=True 就采信会把排查带偏（报出 HAL_Init / 反复同一地址）。
            # 这里复用寄存器稳定性收敛 + 复查是否真的停住的判定。
            try:
                anchor = {"pc": core.get("pc"), "lr": core.get("lr"), "sp": core.get("sp"),
                          "ok": True, "stable": True}
                anchor = client._annotate_stop(anchor, verify_halt=True)
                for k in ("pc_confidence", "halt_verified", "warning", "repeat_count",
                          "repeat_warning", "target_running", "halt_check", "stable"):
                    if k in anchor:
                        out[k] = anchor[k]
            except Exception:  # noqa: BLE001
                pass
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="set_register",
        title="写寄存器 / 改 PC",
        description=(
            "向指定 CPU 寄存器写入值（支持 R0-R12/SP/LR/PC/xPSR，R13/R14/R15 自动映射为 SP/LR/PC）。"
            "value 可为 0x 十六进制或十进制。写后自动读回验证。用于修正现场、强制改返回值、"
            "或改 PC 跳到某函数/地址执行（改 PC 后需配合 run 继续执行）。需已进入调试状态。注意：写 PC/SP/xPSR 等关键寄存器有较大副作用（改 PC 需再 run 才生效；改 SP 可能破坏栈现场）；写后已自动读回验证。需目标暂停。"
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
            "用于测某段代码/某个函数的执行时间（如 SysTick 中断耗时、循环耗时）。需已进入调试且目标暂停。注意：依赖 Cortex-M DWT 周期计数器（M3/M4 内置），需目标暂停；CYCCNT 为 32 位会回绕，测长时间需用 (cycles2-cycles1)&0xFFFFFFFF 差分。计时区间内勿手动 stop 干扰。"
        ),
    )
    async def dwt() -> str:
        try:
            client = _get_client()
            if not _dwt_enable(client):
                return _js({"ok": False,
                            "error": ("使能 DWT 失败（无法写 DEMCR.TRCENA 或 DWT_CTRL.CYCCNTENA）："
                                      "请先 enter_debug 并确认目标已停止")})
            cycles = _dwt_read_u32(client, _DWT_CYCCNT)
            if cycles is None:
                return _js({"ok": False,
                            "error": ("读不到 DWT->CYCCNT（0xE0001004）：常见原因是尚未进入调试态"
                                      "或目标正在运行（本工具需目标暂停），也可能是目标器件无 DWT。"
                                      "请先 enter_debug 并 stop 后重试。")})
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
            "Stimulus Port0) 且调试器(ST-Link/J-Link) SWO 引脚已连接。注意：真实 ITM 输出需 Keil 已配置 Trace(Core Clock + Stimulus Port0) 且调试器 SWO 引脚已连接，缺任一都收不到数据（config 会给出诊断）；仅依赖 ITM 缓冲，非全量 trace。"
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
            "需已进入调试且停在异常处理程序（best-effort，handler 已运行时栈帧可能偏移）。注意：需已进入调试且目标停在异常处理程序（HardFault_Handler 等）；若异常已导致复位/死循环重入，寄存器现场可能已被破坏或读不准（best-effort）。"
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
            "排查死循环 / 跑飞 / 启动流程 / 优化后行为时，查看 PC 处指令在做什么。需已进入调试且配置 .axf。注意：依赖 .axf 符号表与配置；Thumb/ARM 指令模式按符号/地址推断，个别地址可能模式误判。需目标暂停。"
        ),
    )
    async def disassemble(addr: str | int = "", count: int = 8) -> str:
        addr = _addr_arg(addr)
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
            "globals 可选，传关键全局变量名列表（数组或逗号/分号分隔字符串均可）。需已进入调试且配置 .axf。注意：聚合多个只读诊断，同样受中断上下文限制——停在 SysTick 中断/全速运行后手动 stop 时，局部变量与完整调用栈可能受限/为空。需已进入调试且配置 .axf。"
        ),
    )
    async def diagnose(globals: list | str = None, source_context: int = 4,
                       disasm_count: int = 6) -> str:
        try:
            globals = _csv_tokens(globals)
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
            "需已进入调试状态且配置了 .axf 调试符号。注意：实现为临时断点→run→清除。run 到断点停止时返回的 status 是 22(断点已创建) 而非 0；刚停止瞬间读 PC 可能为脏值（本工具已用稳定读取修复）。需已进入调试且配置 .axf。"
        ),
    )
    async def run_to_line(target: str | int) -> str:
        target = _addr_arg(target)
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
            _breakpoints[:] = [b for b in _breakpoints
                               if b.get("address") != hex(addr)]
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
        description="让目标 MCU 全速运行（启动执行）。注意：run 后目标全速运行，此时读内存/寄存器/表达式会失败或错位（异步消息堆积），需先 stop 再读。目标运行期间 UVSOCK 会推送异步消息。若期望'运行到某断点停住'，请以 get_current_location 实测 PC 停靠位置为准，run 本身返回的停靠信息不可信（PC 可能为脏值）。"
            "关于'看不到现象'：调试是 halt 式的——只要 MCP/Keil 保持调试连接，目标要么被挂起、"
            "要么在被断点拦停，外设现象（LED、串口输出、周期动作）会随之停滞，这是调试的本质而非工具缺陷。"
            "要看真实运行现象，请在 run 之后**不要**再 stop/读内存/读寄存器，让目标自由运行；"
            "需要恢复观察时先 exit_debug（退出调试后目标按复位/运行设置自由执行）。",
    )
    async def run() -> str:
        try:
            return _js(_get_client().run())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="wait_breakpoint",
        title="等待断点命中（带超时）",
        description=(
            "带超时地等待目标停在断点上：轮询目标状态，一旦停止就读取 PC（含收敛判定与"
            "「是否真的停住」复查），回落到源码位置，返回 hit / hit_address / hit_count / "
            "waited_ms。用来确证「App 是否真的调用到内核某函数」，不必再靠读 PC 猜、"
            "也不必手工循环 get_status。"
            "symbol 传符号名（如 svcrt_ptable_lookup，自动解析为地址）；address 传 0x 地址；"
            "两者都不传时用工程 .uvoptx 里的持久化断点作候选（use_project_breakpoints 控制）。"
            "命中后返回里直接带 file/line/callstack，并累计该地址命中次数（breakpoint_stats 可查全部）。"
            "**只认「本次等待期间新发生的停止」**：若调用时目标已停着（典型——刚被 run_timeout "
            "停在某行再调本工具），那次停止不计为命中，会返回 hit=false、stop_is_new=false、"
            "ran_during_wait=false 且 note 说明「目标在等待期间未曾运行」，避免把「进来时已停」"
            "误报成「等到了断点命中」。故正确用法是先 run（或 reset 后 run）再调本工具；"
            "调用时先给一个很短的宽限窗口确认目标是真想跑（run 是异步命令，响应会滞后），"
            "若窗口内没见运行且 PC 相对调用时没有移动，才判为旧停止。"
            "注意：命中判定为「目标已停止 且 PC 等于候选地址」（自动兼容 Thumb 位），"
            "并额外支持数据观察点命中——数据断点触发时 PC 不等于观察地址，判定链路按证据强度递减："
            "① 等待前后各读一次 Keil 断点表的 CNT，某条 CNT 增加即为命中项；"
            "② 读 DFSR(0xE000ED30)：等待开始前先清零（DFSR 为 W1C），命中后若 DWTTRAP(bit2) "
            "置位即判为观察点命中，并用 DWT_COMPn 定位命中的是哪个观察点——这是硬件证据；"
            "**真机实测（UVSOCK@4823 + STM32F401）本版 Keil 的 BL CNT 是断点计数条件设置值、"
            "不随命中递增**，此时由 ② 接手；③ ①② 都取不到时才退化为「目标已停止 + PC 不在"
            "任何代码候选 + 存在观察点」推断为观察点命中。"
            "返回 hit_kind（code/watch）、hit_confidence（verified=有 PC/CNT/DFSR 实际证据，"
            "inferred=纯推断）、hit_entry（source 字段：pc/cnt/dfsr/inferred）、"
            "dfsr / dfsr_note（DFSR 原始值与解读）与 cnt_note（说明判定依据强度）；"
            "候选来源除 symbol/address/.uvoptx 外，还包含本服务 set_watchpoint 设的数据观察点，"
            "以及在无其他候选时取 Keil 真实断点表（list_breakpoints.real）中的执行断点；"
            "若本该命中却一直不停，先用 list_breakpoints / list_uvoptx_breakpoints 确认断点存在且启用"
            "（App 侧重定位后运行时地址与符号地址不同，应传实际运行地址）。需已进入调试。"
        ),
    )
    async def wait_breakpoint(symbol: str = "", address: str | int = "",
                              timeout_s: float = 10.0, poll_ms: int = 100,
                              use_project_breakpoints: bool = True,
                              project: str = "", reloc_delta: str = "") -> str:
        try:
            client = _get_client()
            candidates: list = []
            notes: list = []
            delta, _dnote = _eff_reloc_delta(reloc_delta)
            if symbol:
                loc = _get_locator()
                hit = loc.symbol_addr(symbol) if loc is not None else None
                if not hit:
                    return _js({"ok": False, "symbol": symbol,
                                "error": "找不到符号（检查拼写，或先用 find_symbol 检索）"})
                a0 = int(hit["addr"])
                if delta:
                    notes.append("symbol %s 链接地址 %s → 运行地址 %s（reloc_delta=0x%X）"
                                 % (symbol, hex(a0), hex((a0 + delta) & 0xFFFFFFFF), delta))
                    a0 = (a0 + delta) & 0xFFFFFFFF
                candidates.append(a0)
                notes.append("symbol %s -> %s" % (symbol, hex(a0)))
            if address:
                a, an = _resolve_addr_arg(address, client)
                candidates.append(int(a))
                if an:
                    notes.append(an)
            # 数据观察点：命中时 PC 不等于观察地址，必须单独作为一类候选交给 client 判定
            watch_addrs = []
            for w in list(_watchpoints):
                try:
                    watch_addrs.append(int(str(w.get("address")), 16))
                except Exception:  # noqa: BLE001
                    continue
            if watch_addrs:
                notes.append("并入本服务数据观察点 %d 个（命中按 CNT 判定）" % len(watch_addrs))
            if not candidates and use_project_breakpoints:
                info = _read_uvoptx_persistent(project)
                items = info.get("breakpoints") or info.get("bps") or []
                for bp in items:
                    try:
                        candidates.append(int(bp.get("address") or bp.get("addr") or 0))
                    except Exception:  # noqa: BLE001
                        continue
                candidates = [c for c in candidates if c]
                if candidates:
                    notes.append("候选来自 .uvoptx 持久化断点 %d 个" % len(candidates))
            if not candidates:
                # 无显式候选时退回 Keil 真实断点表（板上实际生效的断点），比只认 .uvoptx 更准
                try:
                    real = client.list_breakpoints_real()
                    for b in (real.get("breakpoints") or []):
                        if b.get("kind") != "exec":
                            continue
                        try:
                            candidates.append(int(str(b.get("address")), 16))
                        except Exception:  # noqa: BLE001
                            continue
                    if candidates:
                        notes.append("候选来自 Keil 真实断点表 %d 个" % len(candidates))
                except Exception:  # noqa: BLE001
                    pass
            r = client.wait_breakpoint(candidates, timeout_s=float(timeout_s),
                                      poll=max(0.01, int(poll_ms) / 1000.0),
                                      watch_addresses=watch_addrs)
            out = dict(r)
            if notes:
                out["candidates_note"] = "；".join(notes)
            if r.get("hit") and r.get("stopped"):
                info = _build_location(client)
                if info and info.get("ok"):
                    for k in ("file", "line", "source", "address", "display_path", "callstack"):
                        if k in info:
                            out[k] = info[k]
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="breakpoint_stats",
        title="断点命中统计",
        description=(
            "查看本进程内各断点的命中次数（由 wait_breakpoint 累计），用来回答"
            "「这个断点到底命中过几次」「App 有没有走到过某函数」。"
            "注意：只统计经 wait_breakpoint 观察到的命中，服务重启即清零；"
            "在此之前发生的历史命中无法回溯——需要历史请用数据断点(watch)或自行埋点。"
        ),
    )
    async def breakpoint_stats() -> str:
        try:
            hits = _get_client().breakpoint_hits()
            return _js({"ok": True, "count": len(hits), "hits": hits,
                        "note": "计数自本进程启动起累计，仅含 wait_breakpoint 观察到的命中"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="run_timeout",
        title="运行一段时间后自动暂停",
        description=(
            "让目标 MCU 全速运行 timeout_ms 毫秒后自动暂停，并返回停靠位置（文件行+源码+完整调用栈）。"
            "用于验证时序 / 观察运行 N 毫秒后的状态。timeout_ms 默认 1000。"
            "时长以分段字段给出，别混用：requested_run_ms 是你请求的运行时长；"
            "actual_run_ms 是实测「run 返回 → 发 stop」的间隔（Windows 定时器粒度约 15.6ms，"
            "请求 137ms 时实测常在 140~155ms，属 sleep 精度而非工具延迟）；"
            "stop_wait_ms 是 stop 之后等目标确认停止的耗时（**这才是 wait_stopped.waited_ms 的含义**，"
            "它与 timeout_ms 无关，不要当运行时长用）；total_ms 是整次调用总耗时。"
            "halt 落点还受 UVSOCK 往返影响，毫秒级精度要求请改用 DWT 周期计数或 GPIO 打点。"
            "注意：到点 stop 后会轮询确认目标真正停止（stop 是异步生效的）才读 PC；"
            "若未能确认停止，返回 stopped=false + warning 且不返回停靠位置，"
            "避免把陈旧 PC（常量落复位附近 0x0800024c 之类）误当成停靠点。"
            "另外真机实测：halt 后**首次**读到的 PC 常是上一次 halt 的残留值（LR/SP 已是新值），"
            "故读取按'连续采样收敛'判定（连续两次 PC/LR/SP 一致才采纳），"
            "返回 pc_confidence=high/low；low 表示采样未收敛或复查发现目标其实仍在运行，"
            "PC 不可信，请重试。返回里始终带 pc_confidence 与 stop_verified："
            "stop_verified=false 表示「没能确证目标已停」，此时绝不要把任何地址当停靠点"
            "（真机踩过：报出 HAL_Init / 连续同一个地址，而目标其实在跑）。"
            "若你怀疑目标没停或反复复位，请改用 wait_breakpoint（等断点命中）"
            "或 read_variable / 串口输出交叉确认。"
            "到点常停在 SysTick 等中断上下文，此时局部变量与调用栈层数可能受限/为空，"
            "AAPCS 寄存器解读不适用。需已进入调试且配置 .axf。"
        ),
    )
    async def run_timeout(timeout_ms: int = 1000) -> str:
        try:
            client = _get_client()
            t = max(1, int(timeout_ms))
            t_begin = time.monotonic()
            r = client.run()
            if not (r.get("ok") or r.get("status") in (11, 12, 22)):
                return _js({"ok": False, "error": f"运行失败: {r}"})
            t_ran = time.monotonic()
            await asyncio.sleep(t / 1000.0)
            t_slept = time.monotonic()
            sp = client.stop()
            # stop 异步生效：必须轮询确认目标真正停下，否则读到的 PC 是陈旧值
            # （实测稳定返回复位附近地址，误判成"停在 Reset_Handler"）。
            ws = client.wait_until_stopped(timeout=1.0)
            t_done = time.monotonic()
            out = {"ok": True, "action": "run_with_timeout", "timeout_ms": t,
                   "stopped": bool(ws.get("stopped")), "stop": sp, "wait_stopped": ws}
            out.update(r)
            # 分段计时：此前只透出 wait_stopped.waited_ms，容易被误读成「实际运行时长」
            # （它是 stop 后的确认耗时，与 timeout_ms 无关）。这里把三段分开写清。
            out["requested_run_ms"] = t
            out["actual_run_ms"] = int((t_slept - t_ran) * 1000)
            out["stop_wait_ms"] = int((t_done - t_slept) * 1000)
            out["total_ms"] = int((t_done - t_begin) * 1000)
            out["timing_note"] = (
                "actual_run_ms 为 run 返回到发 stop 的实测间隔（Windows sleep 粒度约 15.6ms，"
                "与请求值有 ±16ms 级差异属正常）；stop_wait_ms = wait_stopped.waited_ms，"
                "是 stop 后确认停住的耗时，不是运行时长。")
            if not ws.get("stopped"):
                out["ok"] = False
                out["warning"] = ("到点已发送 stop，但目标仍在运行（未能确认停止）；"
                                  "此时 PC/寄存器为陈旧值不可信，已不返回停靠位置。"
                                  "可重试 stop，或先用 get_status 确认停止后再读。")
                return _js(out)
            info = _build_location(client)
            if info:
                out.update(info)
            # 无论定位成败都显式给出 PC 可信度（真机反馈：把陈旧 PC 当停靠点会把排查
            # 带偏，报出 HAL_Init / 连续同一地址，而目标其实在跑）。
            if "pc_confidence" not in out:
                out["pc_confidence"] = "low"
                out["pc_warning"] = (
                    "本次未取得可信的 PC（未能确认目标已停止，或符号未就绪）："
                    "不要把任何地址当作停靠点。需要定位时先 stop 再用 get_current_location，"
                    "或改用 wait_breakpoint 等断点命中。")
            regs = out.get("registers") or {}
            out["stop_verified"] = bool(ws.get("stopped")) and bool(regs.get("halt_verified"))
            if regs.get("target_running"):
                out["ok"] = False
                out["pc_warning"] = regs.get("warning")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="stop",
        title="暂停执行",
        description="暂停目标 MCU 的执行（进入断点/挂起状态）。注意：stop 后目标进入挂起态，此时才可安全读内存/寄存器/表达式。停止瞬间个别读取可能读到脏值，必要时重试。",
    )
    async def stop() -> str:
        try:
            return _js(_get_client().stop())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="reset",
        title="复位目标",
        description="复位目标 MCU。注意：复位后程序从复位向量重新运行，变量回到初值、断点保留；若复位后立即读内存，目标可能已重新运行，需先 stop。",
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
            "'out'（跳出）、'instruction'（指令级）。默认 'into'。注意：单步瞬间读 PC 可能读到 SRAM 脏值（已用 FLASH 区段过滤修复）。在中断/异常 handler 内单步或 SP/LR 回溯可能层数受限；'out' 在函数入口处不可靠（Keil 可能无法正确跳出），若卡住可改用 run_to_line 跳到函数返回行。需已进入调试且配置 .axf（source 级单步）。"
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
        name="keil_health",
        description=(
            "检查 Keil 调试通道的健康状态：UV4 进程是否存在、UVSOCK 端口是否监听、"
            "是否有模态对话框阻塞。返回 keil_alive / uv4_pids / port / port_listening / "
            "uvsock_ready / code / diagnosis / suggestion；**mdkdebug_instances** 给出"
            "串行化方式、并发竞争遥测（等待次数/最长等待/锁超时）与**其他仍在驱动同一 UVSOCK "
            "的 mdkdebug 进程**（多个实例并存会互相穿插、静默吃掉写入，这是最隐蔽的一类故障）；"
            "检测到 Keil 模态框时一并给出"
            "modal_dialogs[{title, message, button_texts}]——**正文与可点按钮都有**，"
            "知道框里写了什么、该点哪个（配套 dismiss_dialog 直接关框，不必再去界面手点）。"
            "用途：命令超时或「操作了没反应」时先调它，直接看清断在哪一环（keil_not_running / "
            "port_not_listening / port_occupied），而不是干等到超时；也可作为操作前后的廉价自检"
            "（纯 ctypes + socket 探测，Keil 未运行时也能正常返回）。"
        ),
    )
    async def keil_health() -> str:
        try:
            port = _get_client().port
            # with_dialogs：一并取回模态框的**正文与按钮**——第 11 轮反馈指出"只给标题"
            # 帮助有限（知道有个 μVision 框，却不知道框里写什么、该点哪个）。
            h = winutil.keil_health(port, with_dialogs=True)
            # 批次29：实例清点——多个 mdkdebug 进程抢同一 UVSOCK 是「写入被静默吞掉」
            # 最可能的成因，这里直接报出来（含 PID、心跳年龄与并发遥测）。
            try:
                conc = _serialization_fields()
                h["mdkdebug_instances"] = conc
                if conc.get("warning"):
                    h["concurrency_warning"] = conc["warning"]
                    h["suggestion"] = ((h.get("suggestion") or "") + " " + conc["warning"])
            except Exception as e:  # noqa: BLE001
                h["mdkdebug_instances"] = {"error": str(e)}
            if h.get("modal_blocked_suspected"):
                h["suggestion"] = ((h.get("suggestion") or "")
                                   + " 接下来用 dismiss_dialog 查看正文并按按钮关闭"
                                     "（button 省略则按确定/OK/是/关闭自动挑）。")
            h["dialog_note"] = ("modal_dialogs[].message 是框内正文、button_texts 是可点按钮；"
                                "两者为空说明该框不是标准控件（少见），可退回 Keil 界面手动处理。")
            return _js(h)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="dismiss_dialog",
        title="读取并关闭阻塞 Keil 的模态对话框",
        description=(
            "把 Keil「有个模态框在挡路」补成「框里写什么、点哪个按钮」：枚举 UV4 的模态对话框"
            "（类名 #32770），**读出正文（Static 控件）与全部按钮文字（Button 控件）**并按按钮点击关闭。"
            "button 传按钮文字（如「确定」「重试」，支持部分匹配）；不传则按 确定/OK/是/关闭/重试 "
            "的语义顺序自动挑，没有可点按钮时退化为 WM_CLOSE。title 可按标题筛（多个框时），"
            "index 取第几个（默认 0）。返回 {ok, dismissed, clicked, method, dialog{title,message,buttons}, "
            "remaining}。"
            "用法：命令不返回且 keil_health 报 modal_blocked_suspected=true 时调它——"
            "先看 dialog.message 知道 Keil 报了什么，再决定点哪个按钮，解除阻塞后重试原命令。"
            "注意：① 关框只解除阻塞，不等于问题已修（如正文说输出文件写不进去，要先解决占用/权限）；"
            "② 指定 button 却匹配不到时**不会**擅自改点别的按钮，而是返回 button_not_found 并列出可用按钮。"
        ),
    )
    async def dismiss_dialog(button: str = "", title: str = "", index: int = 0) -> str:
        try:
            return _js(winutil.dismiss_modal_dialog(button=button, title=title, index=index))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="reset_connection",
        description=(
            "只重置 UVSOCK 连接（不重启 Keil）：丢弃当前 socket 与全部残留接收缓冲，"
            "下次调用自动重新建连。用于长连接会话被弄脏（调试会话残留、异步消息堆积、"
            "模态框阻塞后）导致后续命令连续超时的场景——以前只能「关掉 Keil 再开」，"
            "现在可以先用本工具原地复位；复位无效再上 restart_keil。"
        ),
    )
    async def reset_connection(reason: str = "") -> str:
        try:
            return _js(_get_client().reset_connection(reason=reason))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="restart_keil",
        description=(
            "一键重启 Keil 并重建调试通道：关闭所有 Keil 实例 → 以脱离父进程的方式重新拉起并打开工程 → "
            "等待 UVSOCK 端口监听 → 重置连接。把「Keil 死了 / 会话脏了只能人工关掉再开」整条恢复流程变成一次调用。"
            "project 为 .uvprojx 路径（省略用默认工程）；force=True 直接强制结束残留实例；"
            "wait_ready 为等待 UVSOCK 监听的秒数（默认 20）。返回各阶段结果与最终健康快照。"
            "注意：会关闭所有 Keil 实例（含人工查看中的窗口），未保存的调试会话/源码改动可能丢失，调用前请确认。"
        ),
    )
    async def restart_keil(project: str = "", force: bool = True,
                           wait_ready: float = 20.0) -> str:
        try:
            if _builder_cfg["uv4"] is None:
                raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定")
            p = _resolve_project(project)
            client = _get_client()
            out = {"action": "重启 Keil", "project": p}
            out["pids_before"] = winutil.uv4_pids()
            out["close"] = builder.close_uvision(force=force)
            _release_serial("重启 Keil（restart_keil）", out)
            out["exit_wait"] = winutil.wait_uv4_exit(timeout=6.0 if force else 12.0)
            out["launch"] = builder.launch_uvision(_builder_cfg["uv4"], p)
            try:
                out["port_wait"] = winutil.wait_port_listening(
                    port=client.port, timeout=float(wait_ready or 20.0))
            except Exception as e:  # noqa: BLE001
                out["port_wait"] = {"ok": False, "error": str(e)}
            out["reset"] = client.reset_connection(reason="restart_keil")
            health = winutil.keil_health(client.port)
            out["health"] = health
            out["keil_alive"] = health["keil_alive"]
            out["port_listening"] = health["port_listening"]
            out["ok"] = bool(health["uvsock_ready"])
            out["status_text"] = ("Keil 已重启且 UVSOCK 就绪" if out["ok"]
                                  else "Keil 已重启但 UVSOCK 未就绪：" + health["diagnosis"])
            if not out["ok"]:
                out["suggestion"] = health["suggestion"]
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="launch_uvision",
        description=(
            "可见方式启动 Keil uVision 并打开工程，供人工查看界面 / 调试准备。"
            "project 为 .uvprojx 路径，可省略以用默认工程。"
            "reuse（默认 true）：已有打开同一工程的 Keil 窗口时**复用**该窗口并前置，不新开——"
            "真机实测 UV4.exe 并非单实例程序，反复调用本工具会累积出多个同工程窗口（曾达 6 个），"
            "因此默认复用；确需第二个窗口时才传 reuse=false。"
            "返回值含 reused / pid / instances（当前同工程窗口数）。"
            "用户无需手动打开 Keil，AI 可通过本工具拉起；想看当前开了几个窗口用 list_uvision_instances，"
            '想把多余的收掉用 close_uvision(keep="latest")。'
        ),
    )
    async def launch_uvision(project: str = "", reuse: bool = True) -> str:
        try:
            if _builder_cfg["uv4"] is None:
                raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定")
            p = _resolve_project(project)
            return _js(builder.launch_uvision(_builder_cfg["uv4"], p, reuse=bool(reuse)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="list_uvision_instances",
        description=(
            "列出当前所有 Keil uVision 实例：PID、启动时间、打开的工程、是否有窗口。"
            "用于确认是否残留了多个同工程窗口——UV4.exe 并非单实例程序，反复 launch_uvision / "
            "flash_debug 会累积实例而互不回收（真机上曾同时开着 6 个同工程窗口）。"
            "project 可选：只统计打开该工程的实例。count>1 时返回 note 提示收敛方式。"
            '收敛为一个窗口：close_uvision(keep="latest")。'
        ),
    )
    async def list_uvision_instances(project: str = "") -> str:
        try:
            p = _resolve_project(project) if project else ""
            return _js(builder.list_uvision_instances(p))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="close_uvision",
        description=(
            "关闭 Keil uVision 实例，配合 launch_uvision 实现 Keil 开关闭环。"
            'keep="all"（默认）关闭全部实例；keep="latest" / "oldest" 只保留一个实例'
            "（最新 / 最早启动的那个），其余关闭——用于把累积的多个同工程窗口收敛成一个，"
            "只开一个窗口调试。project 非空时只处理打开该工程的实例。"
            "force 默认 False：先优雅关闭（发送关闭消息），残留则自动强制终止；"
            "force=True 直接强制结束。返回 closed / kept / total_before / remaining。"
            "注意：会关闭 Keil 窗口（含人工查看中的），调用前确认无需保留。强制终止后立即重取进程列表可能短暂误报残留（本工具已轮询等待）。沙箱环境受权限/跨会话限制可能无法关闭，需在真实运行环境使用。"
        ),
    )
    async def close_uvision(force: bool = False, keep: str = "all",
                            project: str = "") -> str:
        try:
            p = _resolve_project(project) if project else ""
            out = dict(builder.close_uvision(force=force, keep=keep, project=p))
            _release_serial("关闭 Keil（close_uvision）", out)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="build_project",
        description=(
            "编译 Keil 工程（UV4 -b，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，可省略以用默认工程；"
            "target 为可选目标名。timeout_s 为可选超时秒数（0=默认 1800s）；大型工程/首次全量编译可显式调大，超时会返回 exit_code=-1 并说明。"
            "返回退出码与编译日志。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。注意：UV4 -b 会新起独立隐藏进程，构建输出经 -o 捕获返回（不会显示在你已打开的 Keil 窗口）；退出码 0/1=成功,2=有错误,>=3=不完整。Keil 处于调试态时编译可能失败，建议先退出调试。"
        ),
    )
    async def build_project(project: str = "", target: str = "",
                            timeout_s: int = 0,
                            ensure_debug_channel: bool = True) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_BUILD_TIMEOUT
            return _js(builder.build_project(_builder_cfg["uv4"], p, target.strip() or None, t,
                                             ensure_debug_channel=ensure_debug_channel))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="rebuild_project",
        description=(
            "重新编译 Keil 工程（UV4 -r，全量重编，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，"
            "可省略以用默认工程；target 为可选目标名。timeout_s 为可选超时秒数（0=默认 1800s），全量重编耗时更久，建议按需调大。"
            "注意：UV4 -r 全量重编，同上——新起隐藏进程、输出经 -o 捕获；退出码语义同 build。Keil 处于调试态时编译可能失败。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。"
        ),
    )
    async def rebuild_project(project: str = "", target: str = "",
                              timeout_s: int = 0,
                              ensure_debug_channel: bool = True) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_BUILD_TIMEOUT
            return _js(builder.rebuild_project(_builder_cfg["uv4"], p, target.strip() or None, t,
                                               ensure_debug_channel=ensure_debug_channel))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="flash_download",
        description=(
            "烧录 Keil 工程到目标 Flash（UV4 -f，后台隐藏窗口，不闪现界面）。project 为 .uvprojx 路径，"
            "可省略以用默认工程；target 为可选目标名。timeout_s 为可选超时秒数（0=默认 600s）。"
            "注意：UV4 -f 烧录，需目标板与烧录器已连接且工程烧录算法配置正确；Keil 处于调试态时烧录可能失败，建议先退出调试。烧录会覆盖目标 Flash，属有副作用操作。"
            "exit_debug_after（默认 true）：烧录后若目标仍处于调试态，自动退出调试——因为旧会话的符号已过期"
            "（新固件已在板上、.axf 已重生成），继续用它求值会报 status 13 解析错误；退出前若目标在运行会先 stop。"
            "返回 debug_session 字段说明本次如何处理（debugging_before / stop / exited_debug / note）；设为 false 则保留会话但显式提示符号已过期。release_serial（默认 true）：烧录后释放串口监听占用的 COM 口（日志保留，仍可 serial_read），设为 false 可保留占用；没有串口监听时该参数无副作用。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。"
        ),
    )
    async def flash_download(project: str = "", target: str = "",
                             timeout_s: int = 0,
                             ensure_debug_channel: bool = True,
                             exit_debug_after: bool = True,
                             release_serial: bool = True) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_FLASH_TIMEOUT
            out = dict(builder.flash_download(_builder_cfg["uv4"], p, target.strip() or None, t,
                                              ensure_debug_channel=ensure_debug_channel))
            _note_firmware_event("flash_download")
            # 批次29：烧录后旧调试会话的符号已过期——处理它（默认自动退出），
            # 避免调用方拿着旧符号求值却得到一堆 status 13 解析错误。
            try:
                out["debug_session"] = _post_flash_debug_state(_get_client(),
                                                               do_exit=bool(exit_debug_after))
            except Exception as e:  # noqa: BLE001
                out["debug_session"] = {"error": str(e)}
            # 烧录＝上次调试这一段结束，串口用完就还（日志保留）
            if release_serial:
                _release_serial("烧录新固件（flash_download）", out)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="build_and_flash",
        description=(
            "编译并烧录闭环（后台隐藏窗口，不闪现界面）：先编译，成功后才烧录（UV4 -b 成功后 -f）。"
            "project 为 .uvprojx 路径，可省略以用默认工程；target 为可选目标名。"
            "timeout_s 为可选超时秒数（0=用默认：编译 1800s、烧录 600s）；大型工程或首次全量编译建议显式调大。"
            "注意：先编译成功才烧录（编译失败不烧录）；编译/烧录均新起隐藏 UV4 进程、输出经 -o 捕获。Keil 处于调试态时建议先退出再执行。"
            "exit_debug_after（默认 true）：烧录后若仍处于调试态则自动退出调试（旧会话符号已过期，否则求值报 status 13），"
            "返回值含 debug_session 说明处理过程；设为 false 则保留会话但显式提示符号已过期。release_serial（默认 true）：烧录后释放串口监听占用的 COM 口（日志保留）。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。"
        ),
    )
    async def build_and_flash(project: str = "", target: str = "",
                              timeout_s: int = 0,
                              ensure_debug_channel: bool = True,
                              exit_debug_after: bool = True,
                              release_serial: bool = True) -> str:
        try:
            p = _resolve_project(project)
            bt = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_BUILD_TIMEOUT
            ft = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_FLASH_TIMEOUT
            out = dict(builder.build_and_flash(_builder_cfg["uv4"], p,
                                               target.strip() or None, bt, ft,
                                               ensure_debug_channel=ensure_debug_channel))
            _note_firmware_event("build_and_flash")
            try:
                out["debug_session"] = _post_flash_debug_state(_get_client(),
                                                               do_exit=bool(exit_debug_after))
            except Exception as e:  # noqa: BLE001
                out["debug_session"] = {"error": str(e)}
            if release_serial:
                _release_serial("烧录新固件（build_and_flash）", out)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="flash_debug",
        description=(
            "「关旧 Keil→编烧→开新→进调试」一体闭环：先关闭所有 Keil 实例（避免残留旧工程窗口导致调试到旧代码），"
            "再让新固件上板，成功后重新以可见方式打开本工程并自动进入调试模式。"
            "上板方式自动选择：若工程勾选了 Update Target before Debugging（.uvprojx 的 "
            "UpdateFlashBeforeDebugging=1，Keil 默认），进调试时 Keil 会自己把最新程序下载进 Flash，"
            "此时只需编译、不必再显式烧录（省掉一次全片擦写与往返），返回 flash_plan=\"debug_download\"；"
            "未勾选时才走显式 UV4 -f 烧录（flash_plan=\"explicit_flash\"）。"
            "适用于 AI 修改代码后需上板验证新代码的完整流程，规避「旧窗口调试旧代码」问题。"
            "project 为 .uvprojx 路径，可省略用默认工程；target 为可选目标名。注意：会关闭所有 Keil 实例→编烧→重开→进调试，全程约数秒到数十秒；请先确认 project 路径正确。若板子未连接/烧录失败，不会重开工程也不进调试。输出经 -o 捕获。"
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
            # 关掉所有 Keil 实例后，串口也没理由继续占着（新实例/串口窗口可能要开这个口）
            serial_release = _release_serial("flash_debug 关闭 Keil 实例")
            # 2) 让新固件上板：
            #    UpdateFlashBeforeDebugging=1 时 Keil 进入调试会自动下载（用户实测 + .uvprojx 可查），
            #    故这里只编译，省掉一次显式烧录（全片擦写 + 一次 UV4 -f 往返）；
            #    未勾选时才退回「编译 + 显式烧录」，保证板上固件一定是新的。
            auto_dl = ((_parse_uvprojx_config(p, target.strip() or None).get("current") or {})
                       .get("update_flash_before_debugging"))
            if auto_dl:
                bf = builder.build_project(uv4, p, target.strip() or None)
                flash_plan = "debug_download"
            else:
                bf = builder.build_and_flash(uv4, p, target.strip() or None)
                flash_plan = "explicit_flash"
            if not bf.get("ok"):
                return _js({
                    "ok": False, "action": "flash_debug",
                    "stage": "编译" if auto_dl else "编译烧录",
                    "flash_plan": flash_plan,
                    "close_uvision": close, "build_flash": bf,
                    "serial_release": serial_release,
                    "status_text": ("编译未通过，未重开工程进入调试" if auto_dl
                                    else "编译/烧录未通过，未重开工程进入调试"),
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
            if enter.get("ok"):
                _note_firmware_event("flash_debug")
                _mark_debug_session("flash_debug")   # 新会话＝新固件符号，重新记基线
            return _js({
                "ok": enter.get("ok", False),
                "action": "flash_debug", "stage": "调试",
                "close_uvision": close,
                "flash_plan": flash_plan,
                "serial_release": serial_release,
                "flash_note": ("工程已勾选 Update Target before Debugging，进调试时由 Keil 自动下载"
                               "最新程序，本次未显式烧录（省掉一次全片擦写）"
                               if auto_dl else
                               "工程未勾选 Update Target before Debugging，已显式 UV4 -f 烧录新固件"),
                "build": bf if auto_dl else bf.get("build"),
                "flash": None if auto_dl else bf.get("flash"),
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
            "PWR/FLASH/SysTick/SCB/NVIC/DWT/EXTI/SYSCFG 等）及基址，供 read_peripheral 使用。注意：仅内置 STM32F4 系列外设表（RCC/GPIO/USART/SPI/I2C/TIM/ADC/PWR/FLASH/SysTick/SCB/NVIC/DWT/EXTI/SYSCFG）；其他系列/型号无对应表。"
        ),
    )
    async def list_peripherals() -> str:
        return _js({"ok": True, "count": len(_periph_list()), "peripherals": _periph_list()})

    @server.tool(
        name="read_peripheral",
        title="读取外设寄存器组（SFR）",
        description=(
            "一键读取指定外设（如 RCC/GPIOA/USART1/SPI1/I2C1/TIM2/ADC1/SCB/SysTick）的寄存器当前值，"
            "并解析关键位域（时钟使能/波特率/GPIO 模式/定时器计数等）。"
            "**强烈建议用 regs 只取需要的寄存器**（逗号分隔，可用全名或去掉外设前缀的裸名，"
            "如 regs=\"MODER,OTYPER,IDR\" 或 \"GPIOC_MODER\"；也接受字符串数组写法 "
            "regs=[\"MODER\",\"ODR\"]）：默认输出全部寄存器 + 逐位域，"
            "一个 GPIO 就有十几个寄存器、几十个位域，很容易撑爆上下文；"
            "只看值不看位域时再传 fields=\"off\"。返回里 reg_filter 回显本次筛选，"
            "not_found_regs 列出传了但没匹配上的名字（拼错时能立刻发现）。"
            "排查时钟没使能、GPIO 模式配置错误、串口波特率不对、定时器计数是否跑起来等场景。"
            "需已进入调试状态。periph 为外设名（大小写不敏感）。注意：仅适配 STM32F4 寄存器布局；目标型号非 F4 时寄存器偏移/位域可能不准。需已进入调试且目标暂停。"
        ),
    )
    async def read_peripheral(periph: str, regs: str | list = "",
                              fields: str | list = "auto") -> str:
        try:
            client = _get_client()
            p = _periph_get(periph)
            if not p:
                avail = ", ".join(x["name"] for x in _periph_list())
                return _js({"ok": False, "error": f"未知外设 {periph}，可用: {avail}"})
            # regs：按名筛选（全名或裸名，大小写不敏感），留空 = 全部。
            # 兼容数组写法（regs=["MODER","ODR"]）——用户反馈直接传列表会崩。
            want = [x.upper() for x in _csv_tokens(regs)]
            # 允许两种写法：裸名（MODER）或带外设前缀（GPIOC_MODER）——寄存器表里存的是
            # 裸名，用户按 Keil 手册习惯写全名时也要能匹配上。
            pfx = ((p.get("name") or "").strip().upper() + "_")
            want_norm = set()
            for w in want:
                want_norm.add(w)
                if pfx != "_" and w.startswith(pfx):
                    want_norm.add(w[len(pfx):])
            # fields 同样兼容数组（fields=["off"] 之类），取第一个元素判定
            fields_v = fields
            if isinstance(fields_v, (list, tuple, set, frozenset)):
                fields_v = list(fields_v)[0] if fields_v else "auto"
            with_fields = str(fields_v or "auto").strip().lower() not in (
                "off", "none", "no", "false", "0")
            out_regs: list = []
            hit_names: set = set()
            for name, rdef in p["regs"].items():
                # 同时给「裸名」（去掉外设前缀，如 GPIOC_MODER -> MODER），
                # 便于脚本直接 regs["MODER"]，不用再手工 strip 前缀
                _bare = name.split("_", 1)[1] if "_" in name else name
                if want and (name.upper() not in want_norm and _bare.upper() not in want_norm):
                    continue
                hit_names.add(name.upper())
                hit_names.add(_bare.upper())
                if pfx != "_" and name.upper().startswith(pfx):
                    hit_names.add(name.upper()[len(pfx):])
                addr = p["base"] + rdef["off"]
                val = _periph_read_u32(client, addr)
                if val is None:
                    out_regs.append({"reg": name, "addr": f"0x{addr:X}", "value": None})
                    continue
                entry = {"reg": name, "name": _bare,
                         "addr": f"0x{addr:X}", "value": f"0x{val:08X}", "raw": val}
                if with_fields:
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
                    if bits and with_fields:
                        entry["fields"] = bits
                out_regs.append(entry)
            out = {"ok": True, "peripheral": p["name"], "base": f"0x{p['base']:08X}",
                   "desc": p["desc"], "reg_count": len(out_regs), "regs": out_regs}
            if want:
                out["reg_filter"] = want
                miss = [w for w in want
                        if w not in hit_names
                        and not (pfx != "_" and w.startswith(pfx) and w[len(pfx):] in hit_names)]
                if miss:
                    out["not_found_regs"] = miss
                    out["note"] = ("以下寄存器名未匹配到（拼写或该外设无此寄存器）：%s；"
                                   "可用 list_peripherals 查看该外设的寄存器清单" % "、".join(miss))
                if not out_regs:
                    out["ok"] = False
                    out["error"] = "筛选后无任何寄存器可读，请核对 regs 里的名字"
            if not with_fields and out_regs:
                out["fields_mode"] = "off"
            return _js(out)
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
            "避免把外设区当 RAM 读或把越界地址当合法地址。addr 为空返回全部区域。注意：返回的是 STM32F4 的典型内存布局；其他内核/系列（如 M0/M7、G/L 系列）地址范围可能不同，请勿对非 F4 目标直接套用。"
        ),
    )
    async def query_memory_map(addr: str | int = "") -> str:
        addr = _addr_arg(addr)
        try:
            a = _parse_addr(addr) if addr else None
            return _js(_query_memory_map(a))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="search_mem",
        title="在内存范围内搜索字节序列",
        description=(
            "在 [start,end) 地址范围内扫描字节序列。两种给法：pattern_hex 为十六进制"
            "（如 'DEADBEEF'），pattern_text 为文本（如 'appstat'，默认 ascii 编码，"
            "不用自己转十六进制）——两者只用一个，同时给时以 pattern_text 为准。"
            "返回所有命中地址（分块读、块间重叠防跨块漏匹配）。用于找魔数、定位被越界写坏的缓冲、"
            "搜索特定数据结构。需已进入调试。start/end 用 0x 十六进制。注意：需目标暂停；大范围扫描较慢（分块读）；请勿搜索外设保留区或未映射地址（可能读取失败）。块间重叠处理了跨块匹配。"
        ),
    )
    async def search_mem(start: str | int, end: str | int, pattern_hex: str = "",
                         max_results: int = 20, pattern_text: str = "",
                         encoding: str = "ascii") -> str:
        try:
            client = _get_client()
            if pattern_text:
                try:
                    pattern = pattern_text.encode(encoding or "ascii")
                except Exception as e:  # noqa: BLE001
                    return _js({"ok": False, "error": "pattern_text 编码失败: %s" % e})
            else:
                try:
                    pattern = bytes.fromhex((pattern_hex or "").replace(" ", "").replace("0x", ""))
                except ValueError:
                    return _js({"ok": False, "error": "pattern_hex 非法，须为偶数个十六进制字符；"
                                                      "搜字符串请用 pattern_text"})
            if not pattern:
                return _js({"ok": False, "error": "pattern_hex 不能为空"})
            s, sn = _resolve_addr_arg(start, client)
            e, en = _resolve_addr_arg(end, client)
            out = client.search_mem(s, e, pattern, max_results)
            notes = [n for n in (sn, en) if n]
            if notes and isinstance(out, dict):
                out = dict(out)
                out["addr_note"] = "；".join(notes)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="fill_mem",
        title="批量填充/清零内存",
        description=(
            "从 addr 起连续写入 count 个相同字节（byte 为 0~255 单字节值）。用于清零大块缓冲、"
            "SRAM 初始化、批量回填等。需已进入调试。addr 用 0x 十六进制。注意：需目标暂停；批量写内存/清零有副作用，误写关键区（栈、外设、Flash）可能导致程序异常，写入前确认范围。"
        ),
    )
    async def fill_mem(addr: str | int, byte: int, count: int) -> str:
        addr = _addr_arg(addr)
        try:
            client = _get_client()
            a, _note = _resolve_addr_arg(addr, client)
            return _js(client.fill_mem(a, int(byte), int(count)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次4-2：状态对比 / 函数耗时 ----------------
    @server.tool(
        name="snapshot_diff",
        title="对比调试状态快照（diff）",
        description=(
            "记录/对比调试状态的基线：首次调用创建基线（保存指定 globals 与 PC/LR/SP 寄存器），"
            "之后调用对比当前状态，输出 changed/unchanged/unreadable。用于观察程序运行后哪些变量/"
            "寄存器发生变化，定位被意外改写的状态。globals 传变量名列表（如 ['SystemCoreClock']，"
            "数组或逗号/分号分隔字符串均可）。"
            "需已进入调试且配置 .axf。注意：首次调用创建基线、之后调用做对比；需目标暂停。若两次调用间目标已重启，寄存器基线（PC/SP/LR）对比意义有限。"
        ),
    )
    async def snapshot_diff(globals: list | str = None) -> str:
        global _snapshot_baseline
        try:
            globals = _csv_tokens(globals)
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
            "需已进入调试且函数当前未被占用。注意：依赖 DWT 周期计数器（Cortex-M3/M4 内置）。函数若被中断频繁打断、或当前被占用，step out 可能错位导致测量不准；仅适合稳定可重复的函数级测量。"
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
            "并用 .axf 符号表尝试把文件定位到源码路径。errors_text 传入 build 工具返回的错误信息。注意：输入应为 build/rebuild 工具返回的错误文本格式；依赖 .axf 符号表尝试定位源码路径，未配置 .axf 时仅返回原始解析结果。"
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
            "需已 build 生成 .map 文件且已配置 .axf。注意：需已 build 生成 .map 文件且已配置 .axf（.map 与 .axf 同目录）；.map 是链接静态产物，改动源码需重新编译后才反映新布局。"
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
            "需已进入调试。periph 为外设名，reg 为寄存器名（大小写不敏感）。注意：仅适配 STM32F4 寄存器布局；需目标暂停。写关键寄存器（如 RCC 时钟使能、GPIO 模式）有副作用，写错可能改变外设/系统行为，写入前确认。"
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
            "需已进入调试且配置 .axf。注意：需目标会触发异常或断点；timeout_ms 内未停则超时返回。若目标死循环不触发异常且无断点，会一直运行到超时。需已进入调试且配置 .axf。"
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
            "批量读内存：addresses 传地址列表，每项为 {addr, n_bytes}（n_bytes 缺省 32）；也可直接传地址字符串"
            "（如 \"0x20000000,0x20001000\"）或地址数组，此时每处按 n_bytes=32 读。"
            "一次 MCP 往返读多个地址，减少 AI 连续调用 read_mem 的往返。返回每处 ok/data_hex/ascii。注意：批量读内存，需目标暂停（运行中读取会失败/错位）；仍受异步消息堆积影响，建议先 stop。"
        ),
    )
    async def read_mem_multi(addresses: list | str) -> str:
        try:
            client = _get_client()
            results = []
            for item in _items_arg(addresses):
                if isinstance(item, dict):
                    addr = item.get("addr", item.get("address", ""))
                    size = int(item.get("n_bytes", item.get("size", 32)) or 32)
                else:
                    addr, size = item, 32
                a, note = _resolve_addr_arg(addr, client)
                m = client.read_mem(a, size)
                item_out = {"addr": hex(a), "size": size, "ok": m.get("ok", False),
                            "data_hex": m.get("data_hex", ""), "ascii": m.get("ascii", "")}
                if note:
                    item_out["addr_note"] = note
                results.append(item_out)
            return _js({"ok": True, "count": len(results), "results": results})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="batch",
        title="批量执行多条命令（读类 + 断点 + 运行控制）",
        description=(
            "一次提交多条命令、聚合返回，减少 AI 往返。commands 为列表（也接受 JSON 数组字符串），"
            "每项 {\"tool\": \"工具名\", \"args\": {\"参数名\": 值}}；"
            "tool 必须是本服务已注册的工具名（**本服务全部工具都支持**，含 disassemble、编译烧录、"
            "断点管理、运行控制等；仅不支持 batch 自身，避免递归），"
            "args 就是该工具自己的参数名（可先看该工具描述末尾的【参数】/【调用示例】）；"
            "batch 内与单工具直调**完全等价**：别名写法（如 timeout_s / duration_ms）"
            "同样生效、未知参数同样被拒绝（命中别名时该条结果会带 param_alias）。"
            "例：一次往返下 2 个断点再运行——"
            "commands=[{\"tool\": \"set_breakpoint\", \"args\": {\"expr\": \"main\"}},"
            " {\"tool\": \"set_breakpoint\", \"args\": {\"expr\": \"svcrt_sched_activate\"}},"
            " {\"tool\": \"run\", \"args\": {}}]。"
            "返回 {ok, count, results:[{tool, ok, ...该工具原始返回字段}]}，逐条独立执行，"
            "单条失败不影响其余（error 字段给出原因，参数不匹配时提示该工具的参数名）。"
            "注意：不支持嵌套调用 batch 自身；有副作用的命令（write_mem/run/reset/flash_debug 等）"
            "会按顺序真实执行，请自行确认顺序与后果。"
        ),
    )
    async def batch(commands: list | str, stop_on_error: bool = False) -> str:
        try:
            _get_client()
            tm = getattr(server, "_tool_manager", None)
            results = []
            for c in _items_arg(commands):
                tool = str((c or {}).get("tool", "") or "")
                args = dict((c or {}).get("args", {}) or {})
                one = {"tool": tool, "ok": False}
                entry = tm.get_tool(tool) if tm is not None else None
                if not tool or tool == "batch":
                    one["error"] = f"batch 不支持工具: {tool or '(空)'}（不支持嵌套调用 batch 自身）"
                elif entry is None:
                    one["error"] = f"batch 不支持工具: {tool}（不是本服务已注册的工具名）"
                else:
                    args = _batch_alias_args(tool, args)
                    # 批次28：batch 内的参数与单工具直调**必须走同一层**——别名归一
                    # （族展开 + 单位换算）与未知参数拒绝都在 prepare_arguments 里，
                    # 不再直接拿注册表里的裸函数调用。
                    prep = getattr(server, "prepare_arguments", None)
                    if prep is None:
                        pass                                  # 非别名版 server（极简嵌入）→ 原样
                    else:
                        try:
                            args, applied = prep(tool, args)
                            if applied:
                                one["param_alias"] = applied
                        except Exception as e:  # noqa: BLE001
                            args = None
                            one["error"] = str(e)
                    if args is not None:
                        try:
                            raw = await entry.fn(**args)
                        except TypeError as e:
                            raw = None
                            one["error"] = (f"参数不匹配: {e}；该工具参数{_param_signature(entry)}"
                                            "（见该工具描述里的【调用示例】）")
                        except Exception as e:  # noqa: BLE001
                            raw = None
                            one["error"] = str(e)
                    else:
                        raw = None
                    if raw is not None:
                        try:
                            data = json.loads(raw) if isinstance(raw, str) else raw
                        except Exception:  # noqa: BLE001
                            data = {"result": raw}
                        if isinstance(data, dict):
                            one.update(data)
                        else:
                            one["result"] = data
                        one["ok"] = bool(one.get("ok"))
                results.append(one)
                if stop_on_error and not one.get("ok"):
                    break
            return _js({"ok": True, "count": len(results), "results": results,
                        "note": "逐条独立执行；tool 可为本服务任意已注册工具（不含 batch 自身）"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="project_targets",
        title="枚举工程 target 与当前/调试目标",
        description=(
            "查询当前工程全部 target（UV_PRJ_ENUM_TARGETS）、当前 target（GET_CUR_TARGET）"
            "与当前调试 target（GET_DEBUG_TARGET）。多 target 工程排查/切换前先调它确认目标清单。注意：UV_PRJ_ENUM_TARGETS 真机可能返回空 data（回退从 .uvprojx 解析 target 名）；GET_DEBUG_TARGET 真机常返回空（无值可取）；调试态下枚举/切换 target 会被拒（status=10），需先 exit_debug。"
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
            "多 target 工程切换调试目标后再 enter_debug。注意：调试态下设置调试 target 会被拒（status=10 Target is in debug mode），需先 exit_debug 再切换、再 enter_debug 恢复。target 传名称或索引。"
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
            "包含路径，以及 update_flash_before_debugging（Keil 的 Update Target before Debugging："
            "为 true 时进入调试会自动把最新程序下载进 Flash，可省掉显式烧录）。"
            "project 传 .uvprojx 路径（省略用默认工程），target 指定某 target（省略用第一个）。"
            "排查“不同 target 行为不同”时对比宏/优化差异。注意：基于 .uvprojx 静态解析各 target 配置，需工程文件在且格式为 Keil 标准 uvprojx；不含运行时状态（优化级别/宏为工程设置值）。"
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

    # ---------------- 批次6：目标器件信息 / 采样剖析 / 环境自检引导 ----------------
    @server.tool(
        name="target_info",
        title="查询目标器件信息（芯片型号/Flash/RAM）",
        description=(
            "查询目标芯片信息：实时读 DBGMCU->IDCODE 寄存器得到 DEV_ID/REV_ID 并映射到型号，"
            "返回标称 Flash/RAM 容量与内存布局。排查“资源吃紧/选错型号/容量不符”时先调它。"
            "idcode 实时读取需已进入调试（内存读依赖调试会话）；非调试态仅返回静态布局信息。注意：DEV_ID = IDCODE 低12位(&0x0FFF)、REV_ID = 高16位、IDCODE 为小端字节序（本工具已正确解析）；实时读 IDCODE 需已进入调试，非调试态仅返回静态布局信息。未收录型号返回标称容量 None + 提示按丝印确认。"
        ),
    )
    async def target_info() -> str:
        try:
            client = _get_client()
            out: dict = {"ok": False}
            idcode = None
            try:
                r = client.read_mem(_DEV_ID_DBGMCU_BASE, 4)
                h = r.get("data_hex") or ""
                if r.get("ok") and len(h) >= 8:
                    idcode = int.from_bytes(bytes.fromhex(h[:8]), "little")  # 小端字节序
            except Exception as e:  # noqa: BLE001
                out["idcode_error"] = str(e)
            if idcode is not None:
                dev = idcode & 0x0FFF   # DEV_ID 取低 12 位（STM32 DBGMCU_IDCODE 位[0:11]）
                rev = (idcode >> 16) & 0xFFFF   # REV_ID 取高 16 位（位[16:31]）
                info = _DEV_ID_MAP.get(dev)
                out.update({
                    "ok": True, "source": "IDCODE实时读取",
                    "idcode": f"0x{idcode:08X}", "dev_id": f"0x{dev:04X}",
                    "rev_id": f"0x{rev:04X}",
                    "device_name": info["name"] if info else "未知(DEV_ID不在内置表)",
                    "flash_kb": info["flash_kb"] if info else None,
                    "ram_kb": info["ram_kb"] if info else None,
                })
                out["cpu"] = _read_cpu_arch(client)
                if out.get("flash_kb") is None:
                    out["capacity_note"] = (
                        "该 DEV_ID 未内置标称容量，具体 Flash/RAM 请按芯片丝印或工程器件配置确认"
                    )
            else:
                out.update({
                    "source": "静态(未进入调试，无法读IDCODE)",
                    "device_name": "未知", "flash_kb": None, "ram_kb": None,
                    "note": "实时读取需已进入调试模式",
                })
            out["memory_layout"] = {
                "code_base": f"0x{_DEV_ID_CODE_BASE:08X}",
                "ram_base": "0x20000000", "periph_base": "0x40000000",
                "dbgmcu": f"0x{_DEV_ID_DBGMCU_BASE:08X}",
            }
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="profile_sampling",
        title="采样剖析：定位热点函数",
        description=(
            "基于 PC 统计采样剖析：让目标运行，周期性暂停采样当前 PC，按 .axf 符号表归到函数，"
            "统计各函数命中次数/占比，找出热点。用于定位“哪个函数占用最多 CPU 时间”的性能瓶颈。"
            "duration_ms 采样总时长，interval_ms 两次采样间目标运行时间，max_samples 采样数上限。"
            "注意：通过周期性 run/stop 采样，非硬件 ETM 实时采样，会轻微扰动运行时序；"
            "某函数未命中可能因其未被执行或区间未覆盖到。注意：采样间隔越小对运行时序扰动越大，建议按需取适中值；PC 落在函数符号间隙时会显示裸地址（属正常，不影响热点定位）。"
        ),
    )
    async def profile_sampling(duration_ms: int = 1000, interval_ms: int = 20,
                               max_samples: int = 200) -> str:
        try:
            client = _get_client()
            loc = _get_locator()
            funcs = _load_func_table()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf）"})
            st = client.get_status()
            if not st.get("debugging"):
                return _js({"ok": False, "error": "未进入调试，无法运行/采样", "status": st})
            dur = max(10, int(duration_ms))
            iv = max(1, int(interval_ms))
            ms = max(1, int(max_samples))
            counts: dict = {}
            samples: list = []
            deadline = time.monotonic() + dur / 1000.0
            client.run()
            n = 0
            try:
                while n < ms and time.monotonic() < deadline:
                    await asyncio.sleep(iv / 1000.0)
                    client.stop()
                    regs = client.read_cpu_registers_stable()
                    pc = regs.get("pc")
                    if isinstance(pc, int) and loc.is_code_address(pc):
                        fname = _func_for_pc(funcs, pc)
                        if fname is None:
                            fname = f"0x{pc:08X}(未解析)"
                        counts[fname] = counts.get(fname, 0) + 1
                        samples.append(pc)
                    client.run()
                    n += 1
            finally:
                client.stop()
            total = sum(counts.values())
            top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:20]
            hot = [{"function": k, "hits": v,
                    "percent": round(v * 100.0 / total, 1) if total else 0} for k, v in top]
            return _js({
                "ok": True, "total_samples": total, "sampled_pcs": n,
                "duration_ms": dur, "interval_ms": iv,
                "hot_functions": hot,
                "note": "周期性 run/stop 统计采样，会轻微扰动时序；非硬件 ETM 实时采样",
            })
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 串口日志监听（宿主机侧，ring buffer） ----------------
    # 用户反馈（第 13 轮）：COM9 的日志此前是用 MCP 之外的 Python 脚本抓的，
    # 调试链路上多了一个手工步骤。这里做成「后台线程收 + ring buffer + 增量 read」，
    # 与 RT-Thread 的 rt_kprintf/ULOG 配合时能直接在同一次会话里看日志。
    @server.tool(
        name="serial_monitor_start",
        title="启动串口日志监听（宿主机）",
        description=(
            "在**宿主机**打开串口并后台收日志，按行切分后进 ring buffer，供 serial_read 增量读取——"
            "不必再在 MCP 之外另开 Python 脚本抓口。典型场景：RT-Thread 的 rt_kprintf / ULOG 输出、"
            "验证 App 是否真的跑起来、看复位原因。"
            "port 传 \"COM9\" 或 \"9\"（留空则自动取本机第一个可用串口，并在 available_ports 里列出全部）；"
            "baud 默认 115200；databits/parity/stopbits 默认 8/none/1。"
            "capacity 为保留行数（默认 2000，超出丢最旧行并计入 dropped）。"
            "同一进程只监听一个串口：重复 start 且端口或波特率不同时，restart=true（默认）切换旧监听，"
            "restart=false 则返回 conflict 且不抢占。"
            "返回 {ok, port, state, capacity, available_ports}；端口不存在或被别的程序占用时 ok=false、"
            "并给出 last_error 与可用端口（不会静默失败）；监听线程会按固定间隔自动重连（reopen_count 计数）。"
            "**用完就还**：idle_release_s（默认 900 秒，0=不自动）为无人访问多久后自动释放端口——"
            "释放只放掉 COM 口占用，已收日志仍保留、serial_read 继续可读，"
            "需要接着采集重新调本工具即可（同端口同波特率复用同一实例，不丢已收日志）。"
            "另外 exit_debug / flash_download / build_and_flash / flash_debug / close_uvision / restart_keil "
            "都会顺带释放端口，进程退出也会自动释放——正常调用下不必担心调试完了串口还被占着。"
            "注意：监听期间不要在别处（Keil 串口窗口、其他工具）再打开同一个口，会互相抢占（WinError=5）。"
        ),
    )
    async def serial_monitor_start(port: str = "", baud: int = 115200,
                                   databits: int = 8, parity: str = "none",
                                   stopbits: int = 1, capacity: int = 2000,
                                   encoding: str = "utf-8", label: str = "",
                                   restart: bool = True,
                                   idle_release_s: float = 900.0) -> str:
        try:
            ports = serialmon.list_ports()
            p = str(port or "").strip()
            if not p:
                if not ports:
                    return _js({"ok": False, "error": "本机未发现任何串口",
                                "available_ports": []})
                p = ports[0]
            st = dict(serialmon.start_monitor(
                p, baud=baud, databits=databits, parity=parity, stopbits=stopbits,
                capacity=capacity, encoding=encoding, label=label, restart=restart,
                idle_release_s=idle_release_s))
            st["available_ports"] = ports
            if st.get("state") == "stopped":
                st["ok"] = "conflict" not in st
            else:
                # 打开动作在后台线程里做，失败要过一小会儿才反映到 state 上。
                # 这里多等一眼，把「启动就失败」当场告诉调用方，而不是让它去 read 一个空 buffer。
                await asyncio.sleep(0.4)
                fresh = serialmon.status()
                st["state"] = fresh.get("state")
                st["last_error"] = fresh.get("last_error")
                st["reopen_count"] = fresh.get("reopen_count")
                if fresh.get("state") == "error":
                    st["ok"] = False
                    st["hint"] = ("串口打开失败，监听线程正在自动重试；"
                                  "请确认端口号/波特率正确，且该口没被别的程序占用")
                else:
                    st["ok"] = True
            return _js(st)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e),
                        "available_ports": serialmon.list_ports()})

    @server.tool(
        name="serial_read",
        title="读取串口日志（支持增量）",
        description=(
            "读取 serial_monitor_start 收上来的日志行。"
            "**增量读法**：把上一次返回里的 next_seq 记下来，下次当 since 传入，就只拿新行、不重复——"
            "适合「跑一段 → 读新日志 → 再跑一段」的迭代调试。"
            "max_items 取最近 N 行（默认 200，被截断时 truncated=true）；clear=true 表示读后清空 buffer。"
            "返回 {ok, items:[{seq,text,t}], lines:[文本...], count, next_seq, first_seq, dropped, "
            "truncated, partial, bytes_total, last_error}。"
            "partial 是「还没等到换行的半行」（例如 rt_kprintf 没带 \\n），末尾日志不完整时可看它。"
            "若当前没有监听：ok=false，提示先 serial_monitor_start，并附 available_ports。"
        ),
    )
    async def serial_read(max_items: int = 200, clear: bool = False,
                          since: int | None = None) -> str:
        try:
            return _js(serialmon.read_lines(max_items=max_items, clear=clear, since=since))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e),
                        "available_ports": serialmon.list_ports()})

    @server.tool(
        name="serial_monitor_status",
        title="串口监听状态",
        description=(
            "查询宿主机串口监听的当前状态：port/baud/state(running/error/stopped)/running/"
            "bytes_total/lines/capacity/dropped/next_seq/reopen_count/last_error/partial_len，"
            "并附本机全部可用串口 available_ports（用来确认 COM 号写没写错）。"
            "**没在监听时不会报错**，而是 ok=true、running=false + available_ports，适合先探一下再决定要不要 start。"
            "last_error 非空说明曾经打开失败或被拔线（线程仍在自动重连）。"
        ),
    )
    async def serial_monitor_status() -> str:
        try:
            return _js(serialmon.status())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e),
                        "available_ports": serialmon.list_ports()})

    @server.tool(
        name="serial_monitor_stop",
        title="停止串口监听",
        description=(
            "停止宿主机串口监听并释放串口（返回停之前的最后一帧状态，含未满一行的 partial）。"
            "**默认保留已收日志**（clear_buffer=true 才清空）：释放只放掉 COM 口，ring buffer 里的行仍在，"
            "serial_read 继续可读，需要接着采集重新 serial_monitor_start() 会复用同一实例、不丢日志。"
            "正常情况下不必手工调它——exit_debug / 烧录 / 关 Keil 等都会自动释放，另有空闲超时与进程退出兜底；"
            "本工具用于「明确要现在就把口让出去」的场合。没在监听时也返回 ok=true，不会报错。"
        ),
    )
    async def serial_monitor_stop(clear_buffer: bool = False) -> str:
        try:
            return _js(serialmon.stop_monitor(clear_buffer=clear_buffer))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="mdk_guide",
        title="环境自检与调试工作流引导",
        description=(
            "AI 落地的第一个工具：一键自检 Keil/UVSOCK/UV4/.axf/源码漂移/调试态/RTOS 类型，"
            "并返回推荐的调试工作流与各场景应调用的工具，避免 AI 盲目试错。"
            "返回 {environment:{...}, recommended_workflow:[...], scene_tools:{...}}。注意：建议 AI 落地第一件事先调本工具获取环境自检与工作流，再按场景选择工具；自检为无副作用只读操作，可在任意时刻调用。"
        ),
    )
    async def mdk_guide() -> str:
        try:
            host = getattr(_client, "host", "127.0.0.1")
            port = getattr(_client, "port", 4823)
            env = {
                "keil_uvsocket_reachable": _probe_tcp(host, port),
                "uv4_path": _builder_cfg.get("uv4"),
                "default_project": _builder_cfg.get("default_project"),
                "axf_configured": bool(_symbol_cfg.get("axf")),
                "symbol_ready": bool(_get_locator() and _get_locator().is_ready()),
            }
            try:
                status = _get_client().get_status()
            except Exception as e:  # noqa: BLE001
                env["status_error"] = str(e)
                status = None
            if status:
                env["debugging"] = status.get("debugging")
                env["target_running"] = status.get("running")
            if env.get("symbol_ready"):
                try:
                    info = _build_location(_get_client())
                    if info and info.get("ok"):
                        env["current_file"] = info.get("file")
                        env["current_line"] = info.get("line")
                        env["source_stale"] = "warning" in info
                        if info.get("warning"):
                            env["source_stale_detail"] = info["warning"]
                except Exception as e:  # noqa: BLE001
                    env["location_error"] = str(e)
            env["rtos"] = _probe_rtos()
            workflow = [
                "1. 先调 mdk_guide 自检环境（Keil/UVSOCK/axf/是否调试态/RTOS类型）",
                "2. 若未进入调试，enter_debug 进入；进入后 set_breakpoint / run_to_line 设断点",
                "3. 运行到断点后：get_current_location 看停靠位置，read_locals/read_variable 看变量",
                "4. 排查现场：diagnose 一次聚合 寄存器+反汇编+调用栈+局部变量",
                "5. 排查崩溃：fault_report 看异常类型+现场；wait_fault 复现异常",
                "6. 性能：profile_sampling 找热点函数，profile_function 测单函数耗时",
                "7. 行为不同：project_targets/set_debug_target/read_project_config 对比 target 宏/优化",
                "8. 改代码上板：build_and_flash / flash_debug；收尾 exit_debug 退出调试",
                "9. 看串口日志：serial_monitor_start(port=\"COM9\") → run → serial_read(since=上次next_seq) → serial_monitor_stop"
                "（串口用完就还：exit_debug/烧录/关 Keil 都会自动释放端口，释放后已收日志仍可 serial_read）",
            ]
            scene_tools = {
                "看程序停在哪": "get_current_location / snapshot",
                "看局部变量": "read_locals / read_struct / watch",
                "崩溃死机复位循环": "fault_report / wait_fault / diagnose",
                "性能热点": "profile_sampling / profile_function / dwt",
                "内存被改坏": "set_watchpoint / search_mem / snapshot_diff",
                "不同target行为不同": "project_targets / set_debug_target / read_project_config",
                "串口不打印/时钟问题": "list_peripherals / read_peripheral / itm_trace",
                "抓宿主机串口日志(rt_kprintf/ULOG)": "serial_monitor_start / serial_read / serial_monitor_stop",
                "串口被占用/打不开(WinError=5)": "serial_monitor_stop（释放端口，日志保留）→ 或等空闲自动释放（idle_release_s）",
                "改代码重新上板": "build_and_flash / flash_debug",
            }
            return _js({"ok": True, "environment": env,
                        "recommended_workflow": workflow, "scene_tools": scene_tools})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="list_tools",
        title="列出全部工具与必填参数",
        description=(
            "一次列出本服务的全部工具：名称、用途、必填/可选参数与最小调用示例（example_args "
            "可直接照抄成 args）。AI 冷启动、或不确定某工具准确参数名时先调它——"
            "本服务的参数命名不统一（有 query/expr/addr/n_bytes 等），只靠 'Field required' "
            "报错试错代价高；这里一次就能对齐。keyword 按工具名或用途子串过滤"
            "（如 keyword=\"breakpoint\"、\"mem\"、\"断点\"），留空返回全部。"
        ),
    )
    async def list_all_tools(keyword: str = "") -> str:
        try:
            tm = getattr(server, "_tool_manager", None)
            tools = getattr(tm, "_tools", None) or {}
            kw = (keyword or "").strip().lower()
            items = []
            for nm in sorted(tools.keys()):
                t = tools[nm]
                title = getattr(t, "title", "") or ""
                desc = getattr(t, "description", "") or ""
                if kw and kw not in nm.lower() and kw not in title.lower() \
                        and kw not in desc.lower():
                    continue
                params = getattr(t, "parameters", None) or {}
                props = params.get("properties") or {}
                required = _req_params(nm, params)
                example = {}
                for n in required:
                    spec = props.get(n) if isinstance(props.get(n), dict) else {}
                    example[n] = _example_value(n, spec or {})
                items.append({"tool": nm, "title": title,
                              "required": required,
                              "optional": [n for n in props if n not in required],
                              "aliases": dict(_ALIAS_HINT.get(nm) or {}),
                              "example_args": example,
                              "usage": _usage_summary(desc)})
            return _js({"ok": True, "count": len(items), "total": len(tools),
                        "keyword": keyword, "tools": items,
                        "note": "example_args 只含必填参数，可直接作为 args 传入；"
                                "aliases 给出该工具接受的参数别名（如 n_bytes/length 等价）；"
                                "required 中的参数哪怕 schema 标了默认值也必须给（如 read_mem 的 n_bytes）。"
                                "每个工具的完整说明见其 description 末尾的【参数】/【调用示例】"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "keyword": keyword, "error": str(e)})

    # 为每个工具描述追加【参数】/【调用示例】：AI 冷启动可直接照抄参数名，
    # 不必靠 "Field required" 反复试错。
    hinted = _apply_param_hints(server)
    logger.info("已为 %d 个工具补充参数调用示例", hinted)

    return server


async def run_stdio(host: str = "127.0.0.1", port: int = 4823,
                    idle_timeout: float = 30.0,
                    uv4_path: str | None = None,
                    default_project: str | None = None,
                    axf_path: str | None = None,
                    symbol_projects: list | None = None) -> None:
    """以标准输入/输出方式运行（MCP 客户端常用方式）。"""
    server = create_server(host=host, port=port, idle_timeout=idle_timeout,
                           uv4_path=uv4_path, default_project=default_project,
                           axf_path=axf_path, symbol_projects=symbol_projects)
    await server.run_stdio_async()


async def run_http(host: str = "127.0.0.1", port: int = 4823,
                   idle_timeout: float = 30.0,
                   http_host: str = "127.0.0.1", http_port: int = 8300,
                   uv4_path: str | None = None,
                   default_project: str | None = None,
                   axf_path: str | None = None,
                   symbol_projects: list | None = None) -> None:
    """以 Streamable HTTP 方式运行（可被远程/浏览器 MCP 客户端连接）。"""
    import uvicorn
    server = create_server(host=host, port=port, idle_timeout=idle_timeout,
                           uv4_path=uv4_path, default_project=default_project,
                           axf_path=axf_path, symbol_projects=symbol_projects)
    app = server.streamable_http_app()
    config = uvicorn.Config(app, host=http_host, port=http_port, log_level="info")
    uvicorn.Server(config).run()
