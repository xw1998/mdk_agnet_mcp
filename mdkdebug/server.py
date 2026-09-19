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
from . import annotate as _annotate
from . import errors as _errors
from . import keilkb as _keilkb
from . import cmdscript as _cmdscript
from . import svd as _svd
from . import uvprojx as _uvprojx
from . import session as _session
from . import outctl as _outctl
from . import toolchain as _toolchain
from . import targets as _targets
from . import ocd as _ocd
from . import trace as _trace
from . import workspace as _workspace
from . import rtos as _rtos
from . import toolbox as _toolbox
from . import thin as _thin
from . import traceproto as _traceproto
from . import modbus as _modbus
from . import resetwatch as _resetwatch
from . import coverage as _coverage
from . import scatter as _scatter
from . import cores as _cores
from . import etm as _etm
from . import reloc as _reloc
from . import chipid as _chipid
from . import rtrecord as _rtr
from . import rtrace as _rtrace
from . import viz as _viz
from . import eventrec as _eventrec
from .periph import (list_peripherals as _periph_list, get_peripheral as _periph_get,
                     query_memory_map as _query_memory_map)

logger = logging.getLogger("mdkdebug.server")

# itm_trace 的增量解码状态（Keil 的 Debug(printf) Viewer 缓冲是「拉一次给一坨」，
# 分片拉取时半包必须留到下次，否则 ITM 解码会整段错位）。
_ITM_VIEW = {"state": {}, "prev_hex": "", "prev_len": 0, "pulls": 0,
             "fed_bytes": 0, "overflow": 0, "buffer_resets": 0}


def _itm_looks_text(raw: bytes) -> bool:
    """启发式：像纯文本就按文本解，否则按 ITM 报文解。

    依据：可打印 ASCII（含 \\r\\n\\t）占比 >= 90%。Keil 的 Debug(printf) Viewer 缓冲
    通常是**已经解好的显示文本**；若目标把原始 SWO 流灌进来，则走 ITM 解码。
    判不出来时把判据一起返回（decided_by=heuristic），不假装是权威结论。
    """
    if not raw:
        return True
    printable = 0
    for b in raw:
        if b in (9, 10, 13) or 32 <= b <= 126:
            printable += 1
    return printable >= len(raw) * 0.9


def _itm_packet_json(p: dict) -> dict:
    """报文里的 data 是 bytes，JSON 化前转成 text/hex（避免 json.dumps 直接炸）。"""
    q = dict(p)
    d = q.get("data")
    if isinstance(d, (bytes, bytearray)):
        q["data_hex"] = bytes(d).hex()
        q["data_text"] = bytes(d).decode("utf-8", "replace")
        q.pop("data", None)
    return q


def _decode_itm_view(raw: bytes, mode: str = "auto", reset: bool = False,
                     port_filter: int = -1) -> dict:
    """把 itm_trace 拉到的缓冲结构化（增量喂给 traceproto.decode_itm_stream）。

    增量判据：上次缓冲是本次的前缀 → 只喂新增字节；否则整段重喂并如实标
    buffer_reset（Keil 缓冲每拉一次清空的话，这属于正常，计数会持续增长）。
    """
    st = _ITM_VIEW
    if reset:
        st["state"] = {}
        st["prev_hex"] = ""
        st["prev_len"] = 0
        st["pulls"] = 0
        st["fed_bytes"] = 0
        st["overflow"] = 0
        st["buffer_resets"] = 0
    m = (mode or "auto").strip().lower()
    if m not in ("auto", "itm", "text"):
        return {"ok": False, "error": "decode 只能是 auto / itm / text",
                "error_code": "bad-decode-mode"}
    st["pulls"] += 1
    if m == "auto":
        use = "text" if _itm_looks_text(raw) else "itm"
        decided = "heuristic"
    else:
        use = m
        decided = "explicit"
    if use == "text":
        st["prev_hex"] = raw.hex()
        st["prev_len"] = len(raw)
        return {"ok": True, "mode": "text", "decided_by": decided,
                "bytes": len(raw),
                "text": raw.decode("utf-8", "replace"),
                "note": "按文本解（Keil Debug(printf) Viewer 缓冲通常是已解好的显示文本）；"
                        "要看 ITM 报文结构请显式传 decode=\"itm\""}
    prev = bytes.fromhex(st["prev_hex"]) if st["prev_hex"] else b""
    probe = min(len(prev), 64)
    appended = bool(prev) and len(raw) > len(prev) and raw[:probe] == prev[:probe]
    delta = raw[len(prev):] if appended else raw
    if not appended and st["pulls"] > 1:
        st["buffer_resets"] += 1
    st["prev_hex"] = raw.hex()
    st["prev_len"] = len(raw)
    pk = _traceproto.decode_itm_stream(st["state"], delta)
    st["fed_bytes"] += len(delta)
    st["overflow"] = int(st["state"].get("overflow") or 0)
    packets = [_itm_packet_json(p) for p in (pk.get("packets") or [])]
    if int(port_filter) >= 0:
        packets = [p for p in packets if p.get("port") == int(port_filter)]
    txt = "".join(p.get("data_text") or "" for p in packets
                 if p.get("kind") == "instrumentation")
    warns = []
    if int(pk.get("overflow") or 0) > 0:
        warns.append("本次有 %d 个 ITM Overflow 报文（ITM FIFO 溢出）：此处之后有报文丢失，"
                     "事件时间线不完整" % int(pk["overflow"]))
    if not appended and st["pulls"] > 1:
        warns.append("本次不是增量（上次缓冲不是本次的前缀）：按整段重喂。Keil 缓冲每拉一次"
                     "就清空的话这属于正常；若它保留历史内容，说明是滚动窗口（老字节被挤掉），"
                     "累计计数会偏高——所以要看计数增减，不要只看绝对值")
    if st["state"].get("leftover"):
        warns.append("有 %d 字节未凑齐整包，已留到下次拉取接着解"
                     % len(st["state"]["leftover"]))
    return {"ok": True, "mode": "itm", "decided_by": decided,
            "raw_bytes": len(raw), "fed_bytes": len(delta), "delta": appended,
            "overflow": int(pk.get("overflow") or 0),
            "overflow_total": st["overflow"],
            "leftover_bytes": len(st["state"].get("leftover") or b""),
            "packets": packets[:80], "packets_total": len(packets),
            "truncated": len(packets) > 80,
            "text": txt,
            "summary": _traceproto.summarize(packets),
            "state": {"pulls": st["pulls"], "fed_bytes": st["fed_bytes"],
                      "overflow_total": st["overflow"],
                      "buffer_resets": st["buffer_resets"]},
            "warnings": warns}


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

#: Keil 命令窗口错误码中「地址类」的已知含义（真机实证）
_BP_ERR_MEANING = {
    57: "illegal address（地址非法）",
    65: "cannot access memory / 无效的地址表达式",
    72: "invalid item number（该项不存在：常见于按地址清数据观察点）",
    145: "Redefinition: item already exists（断点已存在，对「设置」语义视为成功）",
}


def _thumb_even(addr):
    """把带 Thumb 位（bit0=1）的**代码地址**归一为偶地址。

    真机实测（批次32）：Keil 的 ``BS`` 命令对奇数地址一律报
    ``*** error 57: illegal address (0x08000DB5)``——同一个函数换成偶地址
    ``0x08000DB4`` 就成功。而 ``calc_expression("&main")`` 返回的是**偶地址**，
    函数指针的值却常带 bit0（Thumb 位），于是「用裸地址设断点」会莫名其妙失败，
    用符号名却成功——这正是用户报的「裸地址路径绕过了解析」的根因。

    只在代码区（< 0x20000000）且确实为奇数时才清 bit0：
    0x20000000 以上的 RAM 数据地址（数据观察点、重定位区）不动，
    避免把合法的奇数数据地址改坏。

    返回 ``(归一后的地址或 None, 是否清过位)``。
    """
    if not isinstance(addr, int):
        return None, False
    if addr and (addr & 1) and addr < 0x20000000:
        return addr & ~1, True
    return addr, False


def _bp_failure_hint(client, addr, r, loc=None):
    """断点设置失败时给出可操作的诊断（而不是只回一句 error 57）。"""
    # 同一个错误可能同时经命令窗口(0x5020)与异步消息(0x4000)抵达，去重后更好读
    codes = []
    for e in (r.get("errors") or []):
        if isinstance(e, dict) and e.get("code") is not None \
                and e.get("code") not in codes:
            codes.append(e.get("code"))
    out = {"status": r.get("status"), "status_text": r.get("status_text"),
           "errors": r.get("errors")}
    if codes:
        out["codes"] = codes
        out["meaning"] = [_BP_ERR_MEANING.get(c, "未知错误码") for c in codes]
    hints = []
    if addr is None:
        # 地址没解析出来时**也要**保留错误码专属建议（原先直接 return，
        # 于是「error 145 断点已存在」这类结论被吞掉，只剩一句符号提示）
        checks = {"addr": None,
                  "addr_note": "未能从符号名解析出地址（不在当前 .axf 符号表内）"}
        hints.append("未解析出地址：符号名可能不在当前 .axf 里——用 find_symbol 搜索，"
                     "或 set_symbol_file 切到与目标固件匹配的 .axf。"
                     + ("（" + _symbol_switch_hint() + "）"
                        if _toolbox.tool_hidden("set_symbol_file") else ""))
    else:
        checks = {"addr": "0x%08X" % addr,
                  "addr_odd": bool(addr & 1),
                  "addr_hex_input": "0x%08X" % addr}
        try:
            mm = _query_memory_map(addr)
            if mm.get("matched"):
                checks["region"] = mm["region"]["name"]
                checks["region_desc"] = mm["region"]["desc"]
            else:
                checks["region"] = None
                checks["region_note"] = "该地址不在内置内存区表内（可能是外设/保留区）"
        except Exception:  # noqa: BLE001
            pass
        if loc is not None:
            try:
                l = loc.locate(addr)
                checks["in_symbol_coverage"] = bool(l and l.get("covered"))
                if l and l.get("file"):
                    checks["symbol_location"] = "%s:%s" % (l.get("file"), l.get("line"))
            except Exception:  # noqa: BLE001
                pass
    out["checks"] = checks
    if 57 in codes:
        hints.append("error 57 = illegal address：Keil 认为这个地址不能下断点。"
                     "已自动处理 Thumb 位（bit0）问题，若仍报此错，常见原因是——")
        hints.append("① 地址不落在**当前调试镜像的代码区**：确认目标固件与 .axf 是否匹配"
                     "（get_status 的 symbol_stale/symbol_file、find_symbol 交叉核对），"
                     "不匹配时先 set_symbol_file 或重新 flash_debug。")
        hints.append("② 地址在 Flash 但不在 .axf 覆盖范围内（例如板上跑的是别的固件）："
                     "find_symbol 搜符号名，或用 list_symbol_projects / set_symbol_file 切符号。")
        hints.append("③ App 重定位场景：下断点要用**运行地址**，可先 set_reloc_delta 设一次"
                     "偏移量，再按符号名设断点（符号名会自动换算）。")
        hints.append("④ 该地址若属于当前正在运行的固件且确实在代码区，改用符号名设断点"
                     "（符号名路径会先 calc_expression 取地址，Keil 自己算出的地址一定合法）。")
    if 145 in codes:
        hints.append("error 145 表示断点已存在——对「设置」语义本就成功，"
                     "可用 list_breakpoints 的 real 字段核对。")
    if not hints:
        hints.append("未识别的失败原因：%s（errors=%s）"
                     % (r.get("status_text"), r.get("errors")))
    out["hints"] = hints
    return out

#: D-Cache 状态探测结果缓存（避免每次读/写内存都多打一轮 UVSOCK）
_CACHE_PROBE = {"ts": 0.0, "state": None}

def _ram_region(addr) -> bool:
    """地址是否落在 SRAM（0x2000_0000~0x3FFF_FFFF）：只有这里才和 D-Cache 打交道。"""
    return isinstance(addr, int) and (0x20000000 <= addr < 0x40000000)

def _halt_guard(client):
    """需要「目标停下来给我一个确定的窗口」时用：暂停→等真停→返回恢复闭包。

    返回 {was_running, pause(), resume(), stopped}。调用方负责在 finally 里 resume（），
    否则目标会一直停在那里——这是有副作用的操作，不能默默吞掉。
    """
    try:
        st = client.get_status()
    except Exception as e:  # noqa: BLE001
        st = {"ok": False, "error": str(e)}
    was_running = bool(st.get("debugging") and st.get("running"))
    info = {"was_running": was_running, "stop_ok": None, "stop_error": None,
            "resumed": None, "resume_error": None}
    if not was_running:
        return info
    s = client.stop()
    info["stop_ok"] = bool(s.get("ok"))
    if not info["stop_ok"]:
        info["stop_error"] = s.get("status_text") or s.get("error") or "暂停目标失败"
        return info
    client.wait_until_stopped(timeout=1.0)
    return info


def _resume_after_halt(client, info: dict) -> dict:
    """把 _halt_guard 暂停过的目标恢复运行，并把结果如实写回 info。"""
    if not info.get("was_running") or info.get("stop_ok") is not True:
        return info
    r = client.run()
    info["resumed"] = bool(r.get("ok"))
    if not info["resumed"]:
        info["resume_error"] = r.get("status_text") or r.get("error") or "恢复运行失败"
    return info


def _halt_note(info: dict, paused_ms) -> list:
    """把停-读-走这件事的副作用写成给用户看的句子（有副作用就必须说出来）。"""
    notes = []
    if not info.get("was_running"):
        return notes
    if info.get("stop_ok") is not True:
        notes.append("暂停目标失败（%s），本次未能拿到停机快照" % info.get("stop_error"))
        return notes
    notes.append("本次操作把目标暂停了 %s ms 再恢复运行（running=\"halt\" 的正常代价）"
                 % paused_ms)
    if info.get("resumed") is False:
        notes.append("**恢复运行失败，目标仍停在停止态**：%s" % info.get("resume_error"))
    return notes


def _cache_advisory(client, addr, op: str, ttl: float = 5.0):
    """D-Cache 已使能且目标地址在 SRAM 时，给出「DAP 直读/直写不可全信」的提示。

    真机反馈（第17轮③）：H7 开着 D-Cache 时，DAP 直读 RAM 可能是陈旧值、直写可能被
    脏行回写覆盖，而工具全程没有任何提示。这里把这件事显式报出来。
    只在 SRAM 地址 + 确实检测到 D-Cache 使能时才给，M3/M4（无 D-Cache）不会多出噪声字段。
    探测结果带 TTL 缓存，避免每次读写都多一轮寄存器访问。
    """
    if not _ram_region(addr):
        return None
    now = time.time()
    st = _CACHE_PROBE["state"]
    if st is None or (now - _CACHE_PROBE["ts"]) > ttl:
        try:
            st = client.get_cache_state()
        except Exception:  # noqa: BLE001
            return None
        _CACHE_PROBE["ts"] = now
        _CACHE_PROBE["state"] = st
    if not isinstance(st, dict) or not st.get("ok") or not st.get("dcache"):
        return None
    ccr = st.get("ccr")
    out = {"dcache": True, "ccr": ccr,
           "probed_ago_s": round(max(0.0, time.time() - _CACHE_PROBE["ts"]), 1)}
    if op == "read":
        out["note"] = (
            "目标 D-Cache 已使能（SCB->CCR=%s）：本值由调试器经 DAP **直接读内存**取得，"
            "若 CPU 刚写过该地址且脏行尚未回写，这里读到的会是**内存中的旧值**——"
            "调试器无法保证它等于 CPU 视角的值。要据此下结论（如判定变量被清零/被改）时，"
            "请先让目标做缓存维护（SCB_CleanDCache）或复位后复读核对，不要只看一次直读。" % ccr)
    else:
        out["note"] = (
            "目标 D-Cache 已使能（SCB->CCR=%s）：本写入由调试器经 DAP **直接写内存**，"
            "若 CPU 侧同一地址存在**脏缓存行**，该行稍后被回写时会**覆盖掉你刚写下的值**"
            "（且写入本身仍报成功）。改内存变量/标志位时请留意，"
            "必要时先让目标 clean/invalidate 再写，或写后隔一会儿重读复核。" % ccr)
    return out

# ---------------- DWT 数据观察点槽位（批次48） ----------------
# DWT_COMP0 @0xE0001020 / DWT_MASK0 @0xE0001024 / DWT_FUNCTION0 @0xE0001028，
# 每个比较器占 0x10 字节，Cortex-M3/M4 上共 4 个槽。
# 用户真实踩到：clear_all_watchpoints 只清了 Keil 断点表，**硬件比较器还武装着**，
# 于是「run 即停」的鬼魂断点，最后只能手写 DWT_FUNCTION3=0 才解开。
_DWT_COMP0 = 0xE0001020
_DWT_SLOT_STRIDE = 0x10
_DWT_SLOT_COUNT = 4
# FUNCTIONn 的 bit[3:0] 是功能字段：0 = 该比较器未启用。真机实测 F429 上
# FUNCTION1 读回 0x200（落在字段之外、写 0 也改不掉），只看整字非 0 会误报武装。
_DWT_FN_FIELD_MASK = 0x0F

def _dwt_slot_addrs(slot: int) -> dict:
    base = _DWT_COMP0 + _DWT_SLOT_STRIDE * int(slot)
    return {"comp": base, "mask": base + 4, "function": base + 8}

def _mem_read_u32(client, addr: int):
    """读 32 位（小端）；读不到返回 None（区别于 0）。"""
    try:
        r = client.read_mem(int(addr), 4)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(r, dict) or not r.get("ok"):
        return None
    try:
        b = bytes.fromhex(r.get("data_hex") or "")
    except ValueError:
        return None
    return int.from_bytes(b[:4], "little") if len(b) >= 4 else None

def _mem_write_u32(client, addr: int, val) -> bool:
    try:
        r = client.write_mem(int(addr), struct.pack("<I", int(val) & 0xFFFFFFFF))
        return bool(isinstance(r, dict) and r.get("ok"))
    except Exception:  # noqa: BLE001
        return False

def _dwt_watch_slots(client, slots: int = _DWT_SLOT_COUNT):
    """回读 DWT 比较器槽位。function != 0 即「已武装」（正在比较，会触发暂停）。"""
    out = []
    for n in range(int(slots)):
        a = _dwt_slot_addrs(n)
        fn = _mem_read_u32(client, a["function"])
        comp = _mem_read_u32(client, a["comp"])
        mask = _mem_read_u32(client, a["mask"])
        out.append({"slot": n,
                    "function": None if fn is None else "0x%08X" % fn,
                    "comp": None if comp is None else "0x%08X" % comp,
                    "mask": None if mask is None else "0x%08X" % mask,
                    "function_raw": fn, "comp_raw": comp,
                    "function_field": (None if fn is None
                                       else fn & _DWT_FN_FIELD_MASK),
                    "function_extra": (None if fn is None
                                       else fn & ~_DWT_FN_FIELD_MASK),
                    "function_addr": "0x%08X" % a["function"],
                    "comp_addr": "0x%08X" % a["comp"],
                    "readable": fn is not None,
                    "armed": (fn is not None
                              and (fn & _DWT_FN_FIELD_MASK) != 0)})
    return out

def _dwt_clear_watch_slots(client, slots: int = _DWT_SLOT_COUNT) -> dict:
    """清 DWT 数据观察点槽位：先关比较（FUNCTIONn=0）再清 COMPn/MASKn，**回读复核**。

    只关不核等于自欺——这整条链路的教训就是「说清了其实没清」。
    """
    before = _dwt_watch_slots(client, slots)
    written = []
    for n in range(int(slots)):
        a = _dwt_slot_addrs(n)
        written.append({"slot": n,
                        "function_cleared": _mem_write_u32(client, a["function"], 0),
                        "comp_cleared": _mem_write_u32(client, a["comp"], 0),
                        "mask_cleared": _mem_write_u32(client, a["mask"], 0)})
    after = _dwt_watch_slots(client, slots)
    armed_after = [x["slot"] for x in after if x.get("armed")]
    readable = all(x.get("readable") for x in after)
    return {"before": before, "written": written, "after": after,
            "armed_before": [x["slot"] for x in before if x.get("armed")],
            "armed_after": armed_after,
            "readable": readable,
            "cleared": (not armed_after) if readable else None,
            "note": ("DWT 比较器 0..%d 已回读确认全部关闭（FUNCTION 字段=0）" % (int(slots) - 1)
                     if readable and not armed_after else
                     ("回读仍有槽位武装：%s" % armed_after) if readable else
                     "DWT 寄存器读不到（未进入调试 / 目标在运行），无法确认是否真的清干净")}

def _auto_freeze_watchdogs(client):
    """halt/进调试后自动置位 DBGMCU 的 IWDG/WWDG 冻结位（失败只报信息，不影响主流程）。

    真机反馈（第17轮②）：新会话/复位后 DBGMCU 冻结位会被清零，目标停机超过看门狗
    溢出时间就被 IWDG 复位、RAM 现场全丢。故 stop / enter_debug 默认自动补上这一步。
    """
    try:
        r = client.set_watchdog_freeze(True)
    except Exception as e:  # noqa: BLE001
        return {"attempted": True, "ok": False, "error": str(e),
                "warning": "自动冻结 IWDG/WWDG 时异常：%s。停机过久可能被看门狗复位，"
                           "可手动调 watchdog_freeze(action=\"enable\") 重试。" % e}
    if not isinstance(r, dict):
        return {"attempted": True, "ok": False, "error": "返回体非字典",
                "warning": "自动冻结 IWDG/WWDG 未取得可解析结果，请手动用 watchdog_freeze 复核。"}
    r = dict(r)
    r["attempted"] = True
    if not r.get("ok"):
        r["warning"] = ("自动冻结 IWDG/WWDG 失败（%s）：目标停机超过看门狗溢出时间仍会被复位、"
                        "RAM 现场丢失。可先确认目标已进入调试并暂停，再调 "
                        "watchdog_freeze(action=\"enable\") 重试。"
                        % (r.get("error") or "未知原因"))
    elif not r.get("all_frozen"):
        r["warning"] = ("自动冻结后回读仍未全部置起（IWDG/WWDG），看门狗可能仍在计数，"
                        "请用 watchdog_freeze(action=\"status\") 复核。")
    return r

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
# axf_source 记录「这份符号是怎么来的」：显式 set_symbol_file / 启动参数 / 默认工程推断 /
# 自动匹配 / 会话恢复 / 随烧录重钉——烧录时要不要重钉符号要靠它判断（显式选择优先）。
_symbol_cfg = {"locator": None, "axf": None, "source_type": None, "axf_source": None}
# 「当前符号是否已核对过与板上固件同源」的最近结论：只有 _symbol_source_check 得出
# same / content-confirmed 才记入，烧录换固件时作废。_build_location 据此透出
# symbol_verified——解析出函数名 ≠ 这个名字可信，假符号最隐蔽的形态是「解析得很成功」。
_symbol_verify = {"axf": None, "verdict": None, "ts": 0.0, "reason": None}
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
_last_project: str = ""  # 本次会话最近一次通过工具参数指定的 .uvprojx（惰性符号定位优先用它）
_breakpoints: list = []  # 内部断点记录（id/expr/address/file/line），因 BL 输出不经 socket 回传
_bp_counter: int = 0  # 断点/数据断点 id 自增
# 内置寄存器表（periph.py）覆盖的器件系列：它是硬编码的 STM32F4 布局。
# 批次49 起，外设级工具要拿它和**实测芯片**比对，不一致就拒绝执行。
_BUILTIN_REG_SERIES = "STM32F4"

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
    """取符号定位器；没装过就按需惰性解析一次（见 _ensure_locator）。"""
    return _ensure_locator()


def _attach_locator(axf: str, source: str, project_dir: str | None = None):
    """装载 .axf 并记下来源（axf_source），供 get_status 等如实披露。"""
    try:
        loc = Locator(axf, project_dir=project_dir)
    except Exception as e:  # noqa: BLE001
        logger.warning("装载符号失败 axf=%s: %s", axf, e)
        return None
    _symbol_cfg.update({"locator": loc, "axf": axf, "source_type": "axf",
                        "axf_source": source})
    logger.info("符号定位（惰性装载）：axf=%s 来源=%s 条目=%d", axf, source, loc.total_entries())
    return loc


def _find_project_candidates(max_depth: int = 4, cap: int = 200) -> list:
    """有界搜索 .uvprojx，供「没给工程 / 工程不存在」时把候选列出来。

    吸收 embeddedskills / Serial-Agent 的硬规则：多候选时**不许替调用方挑一个**。

    **必须是模块级**（批次60）：模块级的 `_ensure_locator()` 也要用它做「附近自动发现」
    兜底；此前它缩在 `create_server()` 里，`_ensure_locator` 调到它只会抛
    `NameError: name '_find_project_candidates' is not defined`——于是「启动时没配工程」
    这个**正是它要解决的场景**里，第 4 条兜底直接崩，既拿不到自动挂载也拿不到
    设计好的提示。真机按空注册表复现过。
    此前只有一句「未指定工程路径」，调用方还得自己去找工程在哪——这里直接把
    候选摊开。深度与目录数都设了上限，避免在大盘上走成一次全盘扫描。

    深度默认 4：Keil 工程的常规布局是 `<仓库>/<工程>/MDK-ARM/x.uvprojx`（3 层），
    旧默认 2 层**连本仓库自带的 example_mdk_project 都找不到**，却会回一句
    「未在附近找到任何 .uvprojx」——又是一条看似权威的错答案。目录数仍由 cap 兜住。
    """
    roots = []
    dp = _builder_cfg.get("default_project")
    if dp:
        roots.append(os.path.dirname(str(dp)))
    try:
        roots.append(os.getcwd())
    except OSError:
        pass
    out, seen, scanned = [], set(), 0
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        base_depth = root.rstrip("\\/").count(os.sep)
        for cur, dirs, files in os.walk(root):
            scanned += 1
            if scanned > cap:
                break
            if cur.count(os.sep) - base_depth >= max_depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs
                       if d.lower() not in (".git", "__pycache__", "node_modules",
                                            ".pytest_cache", "obj", "bin")]
            for fn in files:
                if fn.lower().endswith(".uvprojx"):
                    full = os.path.join(cur, fn)
                    if full not in seen:
                        seen.add(full)
                        out.append(full)
        if out:
            break
    return out[:20]


def _ensure_locator() -> Locator | None:
    """按需惰性解析符号定位器——真机踩坑：启动时没配工程，一整族工具全废。

    MCP 服务启动时若既没给 --axf 也没给 --default-project，locator 就是 None；
    之后就算 AI 已经用 launch_uvision / build_project 明确指定过工程，
    find_symbol / snapshot / read_locals / get_current_location 这一族依然全报
    「符号定位未就绪」，只能重启服务才能用——信息明明拿得到却不用。

    这里在每次真正需要符号时按可信度依次尝试，并记录实际来源（axf_source）：
      1. 本次会话用过的工程（工具参数里出现过的 .uvprojx，最可信）
      2. 服务配置的默认工程
      3. 符号工程注册表（内置/环境/启动参数注入）里**唯一**存在 .axf 的那项
      4. 附近自动发现的 .uvprojx，且能**唯一**推断出 .axf
    多候选时**不替调用方决定**：保持 None 并记日志，由调用方报错（宁可报错也不给
    可能张冠李戴的符号）。
    """
    if _symbol_cfg.get("locator") is not None:
        return _symbol_cfg["locator"]
    cands = []
    if _last_project:
        cands.append(("本次会话使用的工程", _last_project))
    if (_builder_cfg or {}).get("default_project"):
        cands.append(("服务默认工程", _builder_cfg["default_project"]))
    for src, proj in cands:
        axf = _resolve_axf(proj)
        if axf:
            return _attach_locator(axf, "%s：%s" % (src, proj),
                                   os.path.dirname(os.path.abspath(proj)))
    regs = [r for r in (_SYMBOL_PROJECTS or [])
            if r.get("axf") and os.path.isfile(r["axf"])]
    if len(regs) == 1:
        return _attach_locator(regs[0]["axf"],
                               "符号工程注册表：%s" % (regs[0].get("name") or regs[0]["axf"]))
    if not regs:
        found = []
        for proj in _find_project_candidates():
            axf = _resolve_axf(proj)
            if axf:
                found.append((axf, proj))
        if len(found) == 1:
            return _attach_locator(found[0][0], "附近唯一可推断的工程：%s" % found[0][1],
                                   os.path.dirname(os.path.abspath(found[0][1])))
        if len(found) > 1:
            logger.warning("符号自动定位：附近有多个候选 .axf，不替调用方决定：%s",
                           [f[0] for f in found])
    else:
        logger.warning("符号自动定位：注册表里有多个可用 .axf，不替调用方决定：%s",
                       [r.get("name") for r in regs])
    return None




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

def _load_symbol_file(path: str, source: str = "set_symbol_file"):
    """加载符号文件（.axf 或 .map），更新 _symbol_cfg。返回 (ok, message, count)。

    source 记录「这次是谁装的符号」：调用方显式切换（set_symbol_file）还是服务端自己
    的动作（按 PC 自动匹配 / 随烧录重钉 / 会话恢复）。烧录后是否自动重钉要看它——
    显式选择优先，服务端不替调用方改回去（见 _rebind_symbol_to_flashed）。
    """
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
        _symbol_cfg = {"locator": loc, "axf": None, "source_type": "map",
                       "axf_source": source}
        return True, f"已加载 .map 符号（{loc.total_entries()} 条，无 DWARF 行号）", loc.total_entries()
    try:
        loc = Locator(p)
        n = loc.total_entries()
    except Exception as e:  # noqa: BLE001
        return False, f"加载 .axf 失败: {e}", 0
    _symbol_cfg = {"locator": loc, "axf": os.path.abspath(p), "source_type": "axf",
                   "axf_source": source}
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


# 最近一次「烧上去的固件」：工程 + .axf + 时间。跨工程调试的防呆基础——
# 真机踩过：flash_download 烧的是 special 工程，enter_debug 加载的却是当前打开的
# 主固件工程的 .axf，两套固件函数地址错位，PC 全被解析成**假符号**（停在 special 的
# map 里早被链接器裁掉的函数上），纯误导。工具必须先记住「刚烧的是什么」，
# 才有资格核对符号与板上固件是否同源。
_fw_cfg = {"project": None, "target": None, "axf": None, "reason": None,
           "ts": None, "time_text": None}

def _record_flashed_firmware(project: str, target: str = "", reason: str = "") -> dict:
    """记下刚烧上去的固件（工程 + 由该工程推出来的 .axf）。"""
    axf = ""
    try:
        axf = _resolve_axf(project) or ""
    except Exception:  # noqa: BLE001
        axf = ""
    _fw_cfg.update({"project": os.path.abspath(project) if project else None,
                    "target": target or None, "axf": axf or None,
                    "reason": reason or "", "ts": time.time(),
                    "time_text": _file_mtime_text(time.time())})
    _chip_probe["ts"] = 0.0        # 换固件了：芯片探测缓存作废
    # 换固件了：上一次「符号已核对」的结论随之失效（先清、再按新固件重钉；重钉成功会重记）。
    _symbol_verify.update({"axf": None, "verdict": None, "ts": 0.0, "reason": None})
    out = dict(_fw_cfg)
    try:
        out["symbol_rebind"] = _rebind_symbol_to_flashed(out.get("axf") or "", reason)
    except Exception as e:  # noqa: BLE001
        out["symbol_rebind"] = {"action": "failed", "error": str(e),
                                "note": "烧录后自动重钉符号时出错，符号保持不变。"}
    return out

def _same_file(a: str, b: str) -> bool:
    if not a or not b:
        return False
    try:
        return os.path.samefile(os.path.abspath(a), os.path.abspath(b))
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))

def _rebind_symbol_to_flashed(axf: str, reason: str = "") -> dict:
    """烧录后把符号重新钉到刚烧的那份 .axf 上（调用方显式切换过则不覆盖）。

    为什么放在烧录里：符号与板上固件不同源这件事，**源头就是烧录**——服务端在这一步
    顺手对齐，比事后在 env_check / get_current_location 里反复提醒省事得多（那两处已经
    能报，但报完还要调用方自己动手）。

    优先级规则（不许悄悄替调用方做决定）：
      - 当前符号是调用方**显式 set_symbol_file** 装的 -> 不覆盖，只回 kept-explicit 与
        可执行的切换动作：显式切换往往意味着调用方知道自己在干什么（App 重定位、双工程
        对比调试），服务端擅自改回去属于替调用方做决定；
      - 其余（启动参数 / 默认工程推断 / 按 PC 自动匹配 / 上一次自动重钉 / 本来没符号）
        -> 重钉到刚烧的 .axf；
      - 推不出 .axf、或文件不存在 -> skipped，如实说明，不猜替代品。

    返回 {action, ...}，action ∈ rebound / kept-explicit / already-current / skipped / failed。
    """
    cur = (_symbol_cfg or {}).get("axf") or ""
    src = str((_symbol_cfg or {}).get("axf_source") or "")
    out = {"target_axf": axf or None, "flashed_reason": reason or "",
           "current_axf": cur or None, "symbol_source": src or None}
    if not axf:
        out["action"] = "skipped"
        out["note"] = ("刚烧工程的 .axf 推不出来（未编译出可执行文件 / 工程配置里没有可执行"
                       "文件输出路径），符号未自动重钉；要切换请 list_symbol_projects "
                       "看候选后 set_symbol_file 指定。")
        return out
    if not os.path.isfile(axf):
        out["action"] = "skipped"
        out["note"] = "刚烧工程推导出的 .axf 不存在（%s），未自动重钉符号。" % axf
        return out
    if cur and _same_file(cur, axf):
        out["action"] = "already-current"
        out["note"] = "当前符号已经是刚烧录的那份 .axf，无需切换。"
        return out
    if "set_symbol_file" in src:
        out["action"] = "kept-explicit"
        out["note"] = ("当前符号是显式 set_symbol_file 选定的（%s，来源：%s），本次烧录未自动"
                       "覆盖——显式选择优先。若这次烧的固件才是要调的对象，按下面的动作切过去；"
                       "若你在做 App 重定位 / 双工程对比调试，保持现状即可，符号是否与板上同源"
                       "由停靠位置里的 symbol_verified 与 env_check 透出。"
                       % (os.path.basename(cur or "?") or cur, src or "未记录"))
        out["next_actions"] = _symbol_switch_actions() + [
            "env_check 核对当前符号与板上固件是否同源（切完立即复核）"]
        return out
    ok, msg, n = _load_symbol_file(axf, source="随烧录自动重钉（%s）" % (reason or "flash"))
    out["action"] = "rebound" if ok else "failed"
    out["message"] = msg
    out["previous_axf"] = cur or None
    if ok:
        out["entries"] = n
        # 刚烧的固件与这次加载的 .axf 是同一次编译产物：记「已核对」，让停靠位置不再
        # 每次都对一次刚烧完的符号唱「未核对」。
        _symbol_verify.update({"axf": os.path.abspath(axf), "verdict": "same",
                               "ts": time.time(),
                               "reason": "烧录后自动重钉到刚烧的 .axf（同一次编译产物）"})
    else:
        out["error"] = msg
    return out


def _symbol_switch_actions(server=None) -> list:
    """「把符号切到与板上固件同源的那份」的可执行动作清单（含必要的工具面装卸步骤）。

    为什么动作里必须显式带上「装 symbol 组」：报符号不一致的 env_check 在**默认可见的
    core 组**，而唯一的修复手段 set_symbol_file 在**默认不暴露的 symbol 组**
    （toolbox.DEFAULT_GROUPS=("core",)）。旧文案只说「set_symbol_file 切到…」，调用方
    照做只会撞「未知工具」——而「要先装 symbol 组」这条线索当时只写在 toolset 工具的
    描述里，不在报错里、也不在体检结论里。检测器与修复手段不在同一个工具面上时，
    「怎么把手段拿到手」必须和手段写在同一条动作里，否则等于递了把打不开的钥匙。

    set_symbol_file 是否真的不在面上，按当前工具面**账面**判断（不猜）：账本查得到才
    断言「已被收起」；查不到（None）时按「可能不在」措辞，并如实说明这是未知而非已知。
    """
    hid = _toolbox.tool_hidden("set_symbol_file", server)
    acts = []
    if hid is True:
        acts.append(
            '先 toolset(action="load", toolsets="symbol") 把符号组装进工具面'
            "（本服务默认只暴露 core 组，set_symbol_file / list_symbol_projects 都不在"
            "默认面上，不装的话下一步会报「未知工具」；装完若客户端仍报未知工具，"
            "先重拉一次 tools/list）")
    elif hid is None:
        acts.append(
            'set_symbol_file 若不在当前工具面上（本服务默认只暴露 core 组），先调 '
            'toolset(action="load", toolsets="symbol") 把它装上再调')
    acts.append("set_symbol_file 切到与刚烧录固件同源的 .axf")
    return acts

def _symbol_switch_hint(server=None) -> str:
    """把 _symbol_switch_actions 压成一句话，供 warning / 提示文案内嵌。"""
    return "；".join(_symbol_switch_actions(server))

def _symbol_source_check(client=None, axf: str = "", deep: str = "auto",
                         server=None) -> dict:
    """核对「当前符号 .axf」与「最近一次烧录的固件」是否同源，并把结论记进 _symbol_verify。

    这里只是薄包装：判据全在 _symbol_source_check_impl，外面这层负责把结论写进状态，
    供 _build_location 透出「本会话这份符号被核对过没有」。
    """
    out = _symbol_source_check_impl(client=client, axf=axf, deep=deep, server=server)
    _note_symbol_check(out)
    return out


def _note_symbol_check(out: dict) -> None:
    """把一次核对结论记进 _symbol_verify（供 _build_location 透出可信度）。

    只有「已证明同源」的两种结论才算数：same（文件就是刚烧的那份）与
    content-confirmed（Flash 指纹逐块比对一致）。其余一律**清空**——different /
    content-mismatch / no-symbols / no-flash-record / unknown 都不是「通过」，宁可说
    「未核对」，也不留下上一次留下的绿色标记。没测 ≠ 通过。
    """
    v = (out or {}).get("verdict")
    if v in ("same", "content-confirmed"):
        _symbol_verify.update({
            "axf": (out.get("symbol_axf") or (out.get("flashed") or {}).get("axf")
                    or (_symbol_cfg or {}).get("axf")),
            "verdict": v, "ts": time.time(),
            "reason": ("符号就是刚烧录的那份 .axf" if v == "same"
                       else "板上内存与含符号的 .axf 内容指纹一致（同源）")})
    else:
        _symbol_verify.update({"axf": None, "verdict": None, "ts": 0.0, "reason": None})


def _symbol_source_check_impl(client=None, axf: str = "", deep: str = "auto",
                              server=None) -> dict:
    """核对「当前符号 .axf」与「最近一次烧录的固件」是否同源。

    判据分两层，**先证据后推断**：
      1. 文件同一性：符号就是刚烧的那份 .axf -> 直接可信，不做额外读取；
      2. 内容指纹（deep）：用 reloc.verify 拿 .axf 的 Flash 指纹与板上内存逐块比对——
         这条能识破「文件名不同但其实是同一份代码」，也能识破「Keil 加载的符号
         不是板上固件」，是唯一不依赖文件名的硬证据。

    无法判断时如实给 unknown / no-flash-record，**不拿推断当结论**。
    """
    cur = axf or (_symbol_cfg or {}).get("axf") or ""
    fw = dict(_fw_cfg or {})
    flashed = fw.get("axf") or ""
    out = {"flashed": {"project": fw.get("project"), "axf": flashed or None,
                       "reason": fw.get("reason"), "time": fw.get("time_text")},
           "symbol_axf": cur or None,
           "symbol_source": (_symbol_cfg or {}).get("source_type")}
    if not cur and not flashed:
        out["verdict"] = "unknown"
        out["note"] = "本进程既没加载符号、也没有烧录记录，无法核对符号与固件是否同源。"
        return out
    if cur and flashed and _same_file(cur, flashed):
        out["verdict"] = "same"
        out["note"] = "当前符号就是刚烧录的那份 .axf：符号可信。"
        return out
    if cur and flashed:
        out["verdict"] = "different"
    elif flashed:
        out["verdict"] = "no-symbols"
    else:
        out["verdict"] = "no-flash-record"

    ref = cur or flashed
    want_deep = str(deep).lower() not in ("false", "0", "no", "off")
    cv = None
    if want_deep and client is not None and ref:
        try:
            delta, dnote = _eff_reloc_delta()
            m = _chipid.firmware_match(client, ref, delta)
            cc = {"axf": ref, "delta": "0x%X" % delta, "delta_note": dnote,
                  "verdict": m.get("verdict"), "note": m.get("note")}
            if m.get("suggested_delta"):
                cc["suggested_delta"] = m["suggested_delta"]
            out["content_check"] = cc
            cv = m.get("verdict")
        except Exception as e:  # noqa: BLE001
            out["content_check"] = {"error": str(e)}

    if cv == "firmware-confirmed":
        out["verdict"] = "content-confirmed"
        out["note"] = ("文件名/记录与符号源不同，但板上内存与 %s 的 Flash 指纹一致："
                       "内容同源，符号可用（多为同一份代码重新编译过）。"
                       % os.path.basename(ref or "?"))
        return out
    if cv == "firmware-mismatch":
        out["verdict"] = "content-mismatch"
        out["warning"] = (
            "**当前 .axf 很可能不是板上跑的那份固件**（Flash 指纹一条都没中，连按当前 PC "
            "反推的偏移也对不上）。这种情况下断点停下后解析出的函数名/行号都可能是不存在的"
            "「假符号」——真机踩过：PC 显示停在 rt_mq_send_wait，而该函数在板上固件的 map 里"
            "早被链接器裁掉了，会把人带偏。请先确认刚烧的是哪个工程，再 set_symbol_file 切到"
            "与它对应的 .axf。")
        out["next_actions"] = _symbol_switch_actions(server) + [
            "flash_debug 走「关旧Keil→编烧→开新→进调试」闭环，避免符号与固件不同源",
            "env_check 一键体检环境一致性（芯片 / SVD / 固件 / 符号 / D-Cache）",
        ]
        return out
    if not cur:
        out["verdict"] = "no-symbols"
        out["next_actions"] = _symbol_switch_actions(server)
        if cv == "firmware-confirmed":
            out["note"] = ("板上固件与刚烧录的 %s 指纹一致；但本会话尚未加载符号文件，"
                           "解析位置前请先 set_symbol_file 指到这份 .axf。"
                           % os.path.basename(flashed or "?"))
            out["warning"] = ("本会话未加载符号：断点/PC 的函数名解析将依赖 Keil 自己加载的"
                              "符号，可能与板上固件不同源（跨工程调试时必踩）。建议先 "
                              "set_symbol_file 指到刚烧的那份 .axf。")
        else:
            out["note"] = ("本会话尚未加载符号文件（%s）；请 set_symbol_file 指到刚烧录的 "
                           ".axf，否则函数名/行号解析可能来自别的工程。"
                           % (out.get("content_check", {}).get("note") or "未能核对板上固件"))
        return out
    if out["verdict"] == "different":
        out["warning"] = (
            "当前符号 %s **不是**刚烧录的那份 %s（也不能证明内容同源）：跨工程调试时"
            "PC/断点会被解析成别套固件的符号——「符号表里早被裁剪掉的函数」就是这么冒出来的。"
            "请用 set_symbol_file 切到与板上固件对应的 .axf。"
            % (os.path.basename(cur or "?"), os.path.basename(flashed or "?")))
        out["next_actions"] = _symbol_switch_actions(server) + [
            "env_check 做一次完整体检",
        ]
        return out
    out["note"] = ("本进程没有见过烧录记录（未用 flash_download / build_and_flash / "
                   "flash_debug）：无法核对符号 %s 是否对应板上固件；若刚用 Keil 手工烧过，"
                   "建议跑一次 env_check 做内容级核对。"
                   % (os.path.basename(cur or "?") if cur else "（未加载）"))
    return out

# 芯片探测缓存：外设级工具每次都要核对器件，但 IDCODE 不会变——缓存 5s 免得
# 每读一个寄存器就打一串内存读取。（烧录/换工程时由 _record_flashed_firmware 作废。）
_chip_probe = {"ts": 0.0, "client": None, "value": None}

def _probe_chip_cached(client, ttl: float = 5.0) -> dict:
    now = time.time()
    if (_chip_probe.get("client") is client and _chip_probe.get("value") is not None
            and now - float(_chip_probe.get("ts") or 0.0) <= ttl):
        return dict(_chip_probe["value"])
    v = _chipid.probe_chip(client)
    _chip_probe.update({"ts": now, "client": client, "value": v})
    return dict(v)

def _periph_device_guard(client, configured_name: str, allow_mismatch: bool = False,
                         what: str = "读外设寄存器") -> dict:
    """外设级操作前的环境校验（配置型号 vs 实测芯片）。

    真机踩过：SVD/内置表是 STM32F4 的，芯片是 H743——read_peripheral 返回 F4 的
    RCC base 0x40023800、读出 0xAAAAAAAA，还查不到 H7 才有的 APB1LENR。这跟「没有数据」
    完全不是一回事：是**看着像样却完全错的答案**。所以不匹配时默认拒绝执行。
    """
    try:
        chip = _probe_chip_cached(client)
    except Exception as e:  # noqa: BLE001
        return {"allowed": True, "verdict": "unknown",
                "reason": "芯片探测失败：%s" % e, "configured": configured_name}
    try:
        return _chipid.guard_configured_device(client, configured_name,
                                               allow_mismatch=allow_mismatch,
                                               what=what, chip=chip)
    except Exception as e:  # noqa: BLE001
        return {"allowed": True, "verdict": "unknown",
                "reason": "环境校验失败：%s" % e, "configured": configured_name}


# CFSR/HFSR 是**粘滞位**（sticky）：写 1 清除或复位才归零，不会因为异常处理完自动清。
# 因此「读到 UsageFault」并不等于「此刻正在 UsageFault」——很可能只是上一次异常留下的残位。
# 这里跟踪「本进程内首次/最近观察到置位」与「最近一次显式清除」，让 fault_report 能给出
# 时效与来源判断（批次30 反馈③：AI 曾把历史残留位当成当前故障，差点查错方向）。
_FAULT_TRACK = {"cfsr_first_seen": None, "cfsr_last_seen": None,
                "cfsr_last_value": 0, "hfsr_last_value": 0,
                "last_cleared": None}

_FAULT_MASK = {3: 0xFFFFFFFF,        # HardFault：可能是子级 fault 升级而来，任何位都算
               4: 0x000000FF,        # MemManage：MMFSR
               5: 0x0000FF00,        # BusFault：BFSR
               6: 0xFFFF0000}        # UsageFault：UFSR

# eol 取值 → (规范名, 追加字节)
_EOL_TABLE = {
    "crlf": ("crlf", b"\r\n"), "cr+lf": ("crlf", b"\r\n"), "crlfcrlf": ("crlf", b"\r\n"),
    "windows": ("crlf", b"\r\n"), "dos": ("crlf", b"\r\n"),
    "\\r\\n": ("crlf", b"\r\n"),
    "lf": ("lf", b"\n"), "unix": ("lf", b"\n"), "\\n": ("lf", b"\n"),
    "cr": ("cr", b"\r"), "mac": ("cr", b"\r"), "\\r": ("cr", b"\r"),
    "none": ("none", b""), "off": ("none", b""), "no": ("none", b""),
    "raw": ("none", b""), "": ("none", b""),
}
_EOL_HELP = ("可用取值：'crlf'（默认，=\\r\\n）/ 'lf'（=\\n）/ 'cr'（=\\r）/ 'none'（不追加）/ "
             "'auto'（先 crlf，无任何回显再补发单个 \\r）；也可直接传转义写法 \"\\r\" / \"\\n\" / \"\\r\\n\"。")

def _norm_eol(eol):
    """把 eol 参数归一成 (规范名, 追加字节, warning)。

    真机反馈（批次30 复验）：传真实转义字符（JSON 里的 "\\r"）会被旧实现的
    ``str(eol).strip()`` 吃掉 —— ``\\r`` 本身就是空白字符，strip 后成空串，落到
    所有分支之外，于是**换行根本没发出去，工具却仍然返回 ok:true**，只能靠
    read_after 的「没有新行」间接暴露（真机表现为命令逐字符回显但不执行、
    行缓冲累积到下次才一起执行并报 Command not found）。

    现在先取原始串（不做 strip 前置），把真实控制字符映射成转义写法后再归一；
    无法识别时明确返回 warning + 可用取值，不再静默。
    """
    raw = "" if eol is None else str(eol)
    key = (raw.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
           .replace(" ", "").strip().lower())
    if key in _EOL_TABLE:
        name, b = _EOL_TABLE[key]
        return name, b, None
    return None, b"", ("eol 取值无法识别（收到 %r）：本次**未追加任何行尾**，"
                       "命令可能因此不被目标执行。" % raw)


def _norm_tristate(v, default: str = "auto") -> str:
    """把「真/假/自动」三态参数归一成 "true"/"false"/"auto"。

    真机反馈：verify 这类三态参数，调用方常按 JSON 习惯传布尔 false，
    旧签名只接受 str，会被参数校验直接拒绝（validation error），
    调用方拿到的只是一句类型错误、而不是它想要的「关掉复读」。
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    s = str(v if v is not None else default).strip().lower()
    if s in ("0", "no", "off", "never", "false"):
        return "false"
    if s in ("1", "yes", "on", "always", "force", "true"):
        return "true"
    return "auto"


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


def _hex_bytes(text: str):
    """把用户写的十六进制字节串转成 bytes，容忍常见写法（真机踩坑）。

    真机实测：`write_mem(addr="0x20001000", data="0x11223344")` 直接报
    `non-hexadecimal number found ... at position 1`——地址能写 0x 前缀、值不能，
    属于用户/模型都会踩的不一致。这里统一容忍 `0x/0X` 前缀、空格、逗号、下划线、
    分号、冒号（`0x11,0x22` 也能拼对）。返回 (bytes | None, 错误说明)。
    """
    s = "".join((text or "").split())
    for sep in (",", "_", ";", "|", ":"):
        s = s.replace(sep, "")
    if "0x" in s.lower():
        s = "".join(p for p in s.lower().split("0x") if p)
    try:
        return bytes.fromhex(s), ""
    except ValueError as e:
        return None, ("非法十六进制字节串：%s；期望形如 deadbeef、de ad be ef 或 "
                      "0x11223344（长度需为偶数）" % e)


def _symbol_state(debugging=None) -> dict:
    """符号文件（.axf/.map）路径 + 时间戳 + 是否已与当前调试会话不一致。"""
    cfg = _symbol_cfg or {}
    axf = cfg.get("axf") or ""
    out = {"symbol_file": axf or None,
           "symbol_source_type": cfg.get("source_type"),
           "symbol_source": cfg.get("axf_source"),
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
                    ok, msg, _n = _load_symbol_file(
                        axf, source="按 PC 自动匹配（%s）" % pr.get("name"))
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
    return _parse_target_ex(locator, target)["addr"]

# 源文件后缀：用来把「看起来是源文件」与「写法根本不认识」分开，好在报错里说清该补什么
_SOURCE_EXTS = (".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".s", ".asm", ".inc")


def _looks_like_file(s: str) -> bool:
    """判断字符串「看起来是源文件」（带路径分隔符，或后缀是源文件后缀）。

    存在的意义是把错误原因**指对方向**：`D:\\proj\\Core\\Src\\main.c` 漏写行号时，
    rsplit(':', 1) 会切成 file='D' / line='\\proj\\Core\\Src\\main.c'，旧实现于是报
    「行号不是整数：'\\proj\\...'」——把 AI 引去「修行号」，而真正缺的是行号本身。
    """
    q = (s or "").strip().strip('"').strip("'")
    if not q:
        return False
    if "\\" in q or "/" in q:
        return True
    return os.path.splitext(q)[1].lower() in _SOURCE_EXTS


def _parse_target_ex(locator, target: str):
    """目标解析的**带证据版**（批次48/60）。

    旧实现只回一个地址，行号解析撞了同名文件也看不出来。这里把匹配证据一并返回，
    供 run_to_line 在触发前拦截可疑目标（详见 locator.line_to_addr_ex）。

    批次60 补四类判别（此前都会静默给出**误导性**原因）：
      * 漏写行号的绝对路径（``D:\\a\\main.c``）被报成「行号不是整数」→ 改报缺行号
      * 冒号后为空（``main.c:``）→ 明确说「行号缺失」
      * 行号 0 / 负数 → 直接拒绝（行号从 1 起算，0 没有对应指令）
      * 文件名缺失（``:77``）→ 明确说「文件名缺失」，不丢给 locator 去猜
    无冒号但看起来是文件路径的（``main.c``、``Core/Src/main.c``）同样提示缺行号。
    """
    t = (target or "").strip()
    if t.lower().startswith("0x"):
        try:
            return {"addr": int(t, 16), "kind": "address", "explicit": True}
        except ValueError:
            return {"addr": None, "kind": "address", "explicit": True,
                    "reason": "0x 地址解析失败：%r" % t}
    if ":" in t:
        file, line = t.rsplit(":", 1)
        fname = file.strip()
        lstr = line.strip()
        if not fname:
            return {"addr": None, "kind": "line", "explicit": False,
                    "file": fname, "line": None,
                    "reason": "文件名缺失：%r" % t,
                    "hint": "写成 文件:行号（如 Core/Src/main.c:77）"}
        if not lstr:
            return {"addr": None, "kind": "line", "explicit": False,
                    "file": fname, "line": None,
                    "reason": "行号缺失：%r（冒号后面是空的）" % t,
                    "hint": "写成 文件:行号（如 %s:77）" % fname}
        try:
            ln = int(lstr)
        except ValueError:
            if _looks_like_file(t):
                return {"addr": None, "kind": "line", "explicit": False,
                        "file": fname, "line": None,
                        "reason": "看起来是源文件路径，但缺少行号：%r" % t,
                        "hint": ("写法应为 文件:行号（如 Core/Src/main.c:77）；"
                                 "若这本来不是文件，请改用 0x 地址或符号名")}
            return {"addr": None, "kind": "line", "explicit": False,
                    "file": fname, "line": None,
                    "reason": "行号不是整数：%r" % line}
        if ln <= 0:
            return {"addr": None, "kind": "line", "explicit": False,
                    "file": fname, "line": ln,
                    "reason": "行号必须 >= 1（收到 %d）：行号从 1 起算，0 没有对应指令" % ln,
                    "hint": "不确定停在哪一行时先 get_current_location 看一眼"}
        ex = locator.line_to_addr_ex(fname, ln)
        ex["kind"] = "line"
        ex["explicit"] = False
        return ex
    if _looks_like_file(t):
        return {"addr": None, "kind": "line", "explicit": False,
                "file": t, "line": None,
                "reason": "看起来是源文件路径，但缺少行号：%r" % t,
                "hint": "写法应为 文件:行号（如 main.c:77）"}
    return {"addr": None, "kind": "unknown", "explicit": False,
            "reason": "无法识别的目标写法：需为 0x地址 或 文件:行号（如 main.c:77）"}

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


def _note_symbol_verified(result: dict) -> None:
    """在停靠位置结果里透出「这份符号被核对过没有」。

    只透出可信度、不改任何行为：**解析出函数名/行号 ≠ 这个名字可信**。假符号最隐蔽的
    形态就是「解析得很成功」——PC 落在另一套固件的函数里，名字看着像样，其实是板上早被
    链接器裁掉的函数（真机踩过：PC 显示停在 rt_mq_send_wait，map 里根本没它）。

    判据：_symbol_verify 里记的 axf 必须就是当前在用的这份（文件同一性），否则一律
    symbol_verified=False——换了符号文件、烧了新固件之后，旧结论不算数。
    """
    axf = (_symbol_cfg or {}).get("axf") or ""
    v = _symbol_verify or {}
    ok = bool(v.get("verdict")) and _same_file(v.get("axf") or "", axf)
    result["symbol_verified"] = bool(ok)
    if ok:
        result["symbol_verified_note"] = ("符号已核对与板上固件同源（%s：%s）"
                                         % (v.get("verdict"), v.get("reason") or ""))
    else:
        result["symbol_verified_note"] = (
            "本会话尚未核对这份符号与板上固件是否同源：下面解析出的函数名/行号可能来自另一套"
            "固件（即「假符号」，板上根本没有这个函数）。要确认请跑 env_check 做内容级核对，"
            "或 set_symbol_file 切到与刚烧固件同源的 .axf。"
            + ("（" + _symbol_switch_hint() + "）"
               if _toolbox.tool_hidden("set_symbol_file") else ""))


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
                             "请用 set_symbol_file 指定当前固件的 .axf/.map"
                             + ("（" + _symbol_switch_hint() + "）"
                                if _toolbox.tool_hidden("set_symbol_file") else ""))
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
                                 "请 set_symbol_file 切换符号文件，或以地址级信息为准"
                                 + ("（" + _symbol_switch_hint() + "）"
                                    if _toolbox.tool_hidden("set_symbol_file") else ""))
            result["address"] = hex(pc)
            result["callstack"] = _backtrace(client, loc, pc, lr, sp)
            return result
    if cur:
        _note_symbol_verified(result)
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


def _apply_annotations(info) -> None:
    """给工具挂 MCP 官方注解（readOnlyHint / destructiveHint / idempotentHint /
    openWorldHint）。吸收自 MCP 规范的 tool annotations：注解不是安全边界，
    而是给客户端与 AI 的**风险词汇表**——决定要不要弹确认、能不能自动放行。

    做在 list_tools 这一层而不是逐个改注册代码：契约要"所有工具都有"，
    逐个补一定会漏，新增工具又会退回原样（与批次33 统一信封同一理由）。
    """
    try:
        from mcp.types import ToolAnnotations
        a = _annotate.annotations_for(info.name)
        info.annotations = ToolAnnotations(**a)
    except Exception as e:  # noqa: BLE001
        logger.debug("未能写入工具注解：%s（%s）", getattr(info, "name", "?"), e)


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
    # 批次48：偏移错了不会报错，只会读到「全 0」——用户真实踩到，差点被引向
    # 「变量被清零」的错误结论。退化读数必须响亮告警，并指明下一步是校验偏移。
    if data and (data.count(0) == len(data) or data.count(0xFF) == len(data)):
        deg = "全 0x00（可能是 .bss/未初始化，也可能是偏移错了）" if data.count(0) == len(data) \
            else "全 0xFF（擦除态/未编程，通常是偏移错了）"
        out["value_suspect"] = True
        out["value_warning"] = (
            "运行地址 0x%X 读回整帧 %s：**不要**据此判定「变量被清零」。"
            "reloc_delta=0x%X 是跨编译会变的——请先 reloc_check（或 reloc_check 的 "
            "derive 结果）确认偏移与实际布局相符，再解读本值。" % (run, deg, delta))
        out["next_action"] = "调 reloc_check(elf=当前 .axf) 校验/反推正确偏移"
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


def _guard_reject_payload(problems, ev, allow_suspect):
    # 没有问题时必须放行：此前 problems 为空仍去取 problems[0]，把「一切正常」的
    # 目标写成了 IndexError: list index out of range（拿不到 PC 的那条路径必踩）。
    if allow_suspect or not problems:
        return None
    first = problems[0]
    return {"ok": False, "error_code": first["error_code"], "error": first["error"],
            "problems": problems, "evidence": ev, "rejected": True,
            "note": ("已在触发前拦下：下列证据表明解析结果不可信，直接下断点只会白费一次触发。"
                     "确有把握时传 allow_suspect=true 强行执行。"),
            "hints": [p.get("hint") for p in problems if p.get("hint")]}

def _run_to_line_guard(client, loc, ex, addr, allow_suspect=False, max_fuzz=200):
    """run_to_line 触发前的目标一致性校验（批次48）。返回 (拒绝载荷 或 None, 证据)。

    真机踩到：``task_algo.c:719`` 被解析到 ``0x80c952c``（比当前 PC 还小，物理上不可能），
    断点永不命中，白白浪费一次触发。这里动手前把四类可疑目标拦下来——**默认拒绝并给证据**，
    因为「多问一句」远比「白跑一次 + 被引向错误结论」便宜：

    * ``ambiguous-line``    同名文件撞行号（basename 相同、路径不同的多个文件都匹配）
    * ``line-fuzzy``        命中的行比目标行早太多（> max_fuzz，说明该行编译不出独立地址）
    * ``not-in-symbols``    地址不落在任何符号区间（伪地址）
    * ``suspicious-target`` 与当前 PC 不在同一函数、且比当前函数入口还早
                            （run_to_line 只能往前走，这种目标到不了，几乎必是解析错了）

    allow_suspect=true 放行（返回 (None, 证据)）。目标运行态拿不到 PC 时跳过 PC 校验，
    并在证据里注明 skipped——不冒充「校验过」。
    """
    ev = {"target_kind": ex.get("kind"), "addr": hex(addr),
          "matched_file": ex.get("matched_file"), "matched_line": ex.get("matched_line"),
          "fuzz": ex.get("fuzz"), "ambiguous": ex.get("ambiguous"),
          "files": ex.get("files"), "candidates": ex.get("candidates")}
    problems = []
    if ex.get("kind") == "line":
        if ex.get("ambiguous"):
            files = ex.get("files") or []
            problems.append({
                "error_code": "ambiguous-line",
                "error": ("行号解析撞到同名文件：%s:%s 在行号表里匹配到 %d 个文件（%s）"
                          % (ex.get("file"), ex.get("line"), len(files),
                             "、".join(files[:4]))),
                "hint": ("用更完整的路径写法重试（如 Core/Src/%s:%s）；"
                         "或先 address_for_line 看候选再传 0x 地址"
                         % (os.path.basename(str(ex.get("file") or "")), ex.get("line")))})
        fz = ex.get("fuzz")
        if isinstance(fz, int) and fz > int(max_fuzz):
            problems.append({
                "error_code": "line-fuzzy",
                "error": ("该文件里 <= %s 行最近的地址条目是第 %s 行（早了 %d 行，超过上限 %d）："
                          "目标行很可能编译不出独立地址，解析结果不可信"
                          % (ex.get("line"), ex.get("matched_line"), fz, int(max_fuzz))),
                "hint": ("换一个确实有代码的行；或先 address_for_line 核对。"
                         "max_fuzz=0 可放宽该限制")})
    if not loc.is_covered(addr):
        problems.append({
            "error_code": "not-in-symbols",
            "error": "解析出的地址 0x%X 不落在当前 .axf 的任何符号区间内" % addr,
            "hint": "该行很可能没有可执行代码（宏/注释/声明）；换成有代码的行"})
    # PC 一致性校验
    pc = None
    try:
        st = client.get_status()
        if isinstance(st, dict) and st.get("running") is False:
            regs = client.read_cpu_registers_stable()
            if isinstance(regs, dict) and isinstance(regs.get("pc"), int):
                pc = int(regs["pc"]) & ~1
    except Exception:  # noqa: BLE001
        pc = None
    if pc is None:
        ev["pc_check"] = "skipped"
        ev["pc_check_note"] = ("拿不到当前 PC（目标在运行 / 未进入调试），"
                               "本次未做函数边界一致性校验")
        return _guard_reject_payload(problems, ev, allow_suspect), ev
    ev["pc"] = hex(pc)
    pf = loc.func_at(pc)
    tf = loc.func_at(addr)
    ev["pc_check"] = "done"
    ev["pc_function"] = (pf or {}).get("name")
    ev["target_function"] = (tf or {}).get("name")
    if pf and addr < pf["start"] and not (tf and tf["start"] == pf["start"]):
        problems.append({
            "error_code": "suspicious-target",
            "error": ("目标 0x%X 比当前 PC 所在函数 %s（入口 0x%X）还早，且不在同一函数："
                      "run_to_line 只能往**前**跑，这种目标物理上到不了，"
                      "几乎必是行号/符号解析错了" % (addr, pf["name"], pf["start"])),
            "hint": ("先用 get_current_location 看当前停在哪，再 address_for_line 核对目标地址；"
                     "确要强行执行可传 allow_suspect=true")})
    return _guard_reject_payload(problems, ev, allow_suspect), ev

def _read_variable_via_elf(client, name, count=0, read_memory=True, delta=0, dnote=""):
    """符号解析双轨打通（批次48）：Keil 表达式读不到时，改走 .axf 符号表 + read_mem。

    背景：`read_variable` 走 Keil 表达式（`&name`），而 static/被优化掉/停在别处时
    表达式会失败；同一时刻 `find_symbol` 走 ELF 却能查到地址（用户实测的双轨不通）。
    这里把第二条轨道直接接上，失败原因保留在 ``fallback_reason`` 里。

    只处理**纯符号名**（含 '.'/'['/'->' 的成员/下标表达式交给 Keil 表达式那一侧）。
    拿不到定位器、符号不存在、读不到内存时返回 None——不猜值。
    """
    nm = str(name or "").strip()
    if not nm or any(t in nm for t in (".", "[", "->", " ")):
        return None
    loc = _get_locator()
    if loc is None or not loc.is_ready():
        return None
    try:
        hit = loc.symbol_addr(nm)
    except Exception:  # noqa: BLE001
        hit = None
    if not hit:
        return None
    link = int(hit["addr"])
    run = (link + int(delta)) & 0xFFFFFFFF if delta else link
    size = int(hit.get("size") or 0)
    nb = size if 0 < size <= 1024 else 4
    out = {"ok": False, "name": nm, "address": hex(run),
           "link_address": hex(link), "run_address": hex(run),
           "size_bytes": nb, "symbol_kind": hit.get("type"),
           "address_source": ".axf 符号表（ELF .symtab）",
           "fallback": ".axf 符号表 + read_mem"}
    if delta:
        out["reloc_delta"] = "0x%X" % int(delta)
        out["reloc_note"] = dnote
    try:
        mem = client.read_mem(run, nb)
    except Exception as e:  # noqa: BLE001
        out["error"] = "读取运行地址失败: %s" % e
        return out
    if not mem.get("ok"):
        out["error"] = "读取地址 0x%X 失败: %s" % (run, mem)
        return out
    data = bytes.fromhex(mem.get("data_hex") or "")
    if not data:
        out["error"] = "地址 0x%X 读回空数据" % run
        return out
    out["ok"] = True
    if read_memory:
        out["memory_hex"] = mem.get("data_hex")
        out["ascii"] = mem.get("ascii")
    out["value"] = int.from_bytes(data[:min(nb, 8)], "little")
    if nb == 4 and len(data) >= 4:
        out["value_as_float"] = struct.unpack("<f", data[:4])[0]
    if data.count(0) == len(data) or data.count(0xFF) == len(data):
        out["value_suspect"] = True
        out["value_warning"] = ("该地址读回整帧退化值（全 0x00/全 0xFF），"
                                "可能确实是空/擦除态，也可能是偏移或符号已漂移；"
                                "不要仅凭此判定「变量被清零」")
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
    out["value_note"] = ("value 按小端整数解析；浮点看 value_as_float，"
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


# 这些工具的关键可选参数直接决定调用成败，示例里一并给出（照抄即可用）
# ----------------------------------------------------------------------
# 工具面（分组 / 默认精简 / 运行期装卸）——实现都在 toolbox.py
# ----------------------------------------------------------------------
# 起因：工具数到 154 个，每个工具的 description 都要进上下文，把窗口稀释掉，
# 对小模型的注意力尤其不友好。批次42 起**默认只暴露 core 组 + 引导工具**，
# 其余组用 toolset(action=load, toolsets=mem,trace) 按需装回来。
#
# 分组表、默认策略、plan() 与运行期装卸都在 toolbox.py；这里只留别名，
# 免得历史调用点（capabilities / 测试）找不到名字。
_TOOLSETS = _toolbox.TOOLSETS
_TOOLSET_ALWAYS = _toolbox.ALWAYS


def _toolset_env() -> str:
    return _toolbox.env_raw()


def _toolset_plan(tool_names=None) -> dict:
    return _toolbox.plan(tool_names)


_KEY_OPTIONALS = {
    "wait_state": {"state": "stopped", "timeout_s": 10},
    "svd_list": {"device": "STM32F401RCTx"},
    "svd_decode": {"peripheral": "USART2", "register": "CR1", "value": "0x200C"},
    "uvprojx_edit": {"action": "add_include_path", "paths": "../Core/Src"},
    "address_for_line": {"file": "main.c", "line": 100},
    "serial_write": {"text": "help", "eol": "crlf"},
    "watchdog_freeze": {"action": "status"},
    "serial_expect": {"pattern": "msh />", "timeout_s": 5, "send": "help", "eol": "auto"},
    "clean_project": {},
    "toolset": {"action": "load", "toolsets": "mem,trace"},
    "serial_list_ports": {},
}


def _usage_summary(desc: str, limit: int = 170) -> str:
    """从工具描述里取一句用途摘要（去掉追加的【参数】块）。

    真机反馈：原实现按 90 字符硬切，会把句子切在词中间（serial_write 被截成
    「…给 bo」），冷启动照抄摘要反而漏掉关键信息。现在放宽到 170，优先取完整
    一句；确实过长时在标点处断开并加省略号，不再切在词中间。
    """
    t = (desc or "").split("【参数】")[0].replace("\n", " ").strip()
    for sep in ("。", "；", ". "):
        i = t.find(sep)
        if 0 <= i <= limit:
            return t[:i]
    if len(t) <= limit:
        return t
    cut = t[:limit]
    for sep in ("。", "；", "，", "、", "：", ", "):
        i = cut.rfind(sep)
        if i >= limit // 2:
            return cut[:i + 1].rstrip("，、, ")
    return cut.rstrip() + "…"



def _guide_tool(topic: str, name: str, server) -> dict:
    """取回工具说明：单个工具的**完整原文**，或全部归档索引 + 描述档位。

    背景：为省上下文，长描述在工具列表里只留一句话摘要，正文挪进 thin.py 的归档。
    这里就是取回入口——AI 需要边界条件/失败模式/踩坑细节时调它。
    """
    st = _thin.stats()
    tm = getattr(server, "_tool_manager", None)
    tools = getattr(tm, "_tools", None) or {}
    nm = (name or "").strip()
    if nm:
        full = _thin.full_of(nm)
        if full is None:
            if nm not in tools:
                return {"ok": False, "name": nm, "reason": "guide-unknown-tool",
                        "error_code": "guide-unknown-tool",
                        "error": "没有这个工具：%s" % nm,
                        "hint": "工具名要完全一致（如 trace_swd_read）；"
                                "用 list_tools 或 tools_groups 查准确名字"}
            return {"ok": True, "name": nm, "thinned": False,
                    "description": (getattr(tools[nm], "description", "") or ""),
                    "note": "这个工具的说明本来就不长，没有被挪出上下文"}
        ent = _thin.archived().get(nm) or {}
        return {"ok": True, "name": nm, "thinned": True, "mode": ent.get("mode"),
                "moved_chars": ent.get("moved"), "description": full,
                "note": "这是被挪出上下文的完整说明原文（与瘦身前逐字一致）"}
    idx = {k: {"mode": v.get("mode"), "moved_chars": v.get("moved")}
           for k, v in sorted(_thin.archived().items())}
    return {"ok": True, "topic": topic or "tool", "desc_mode": st["mode"],
            "thinned_tools": len(idx), "saved_chars": st["saved"],
            "before_chars": st["before"], "after_chars": st["after"],
            "modes": st["modes"], "env": st["env"], "tools": idx,
            "note": "给 name= 取回某个工具的完整说明；"
                    "描述档位用环境变量 MDKDEBUG_DESC=full/lean/min 调（默认 full，"
                    "只有 nano 档自动用 min）"}


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
        # 批次34：输出控制三件套（compact/max_lines/full）先摘出来——它们是
        # 「返回体整形」参数，工具函数本身并不认识，留着会被未知参数检查拒掉。
        arguments, _out_params = _outctl.split_args(arguments or {})
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
            result = await super().call_tool(name, arguments, context)
        finally:
            _tool_concurrency["in_flight"] -= 1
        # 批次33：统一结果信封（status / next_actions / error_code / risk）。
        # 做在调用出口这一层而不是逐个改 88 个工具——契约要「所有工具都有」，
        # 靠逐个补一定会漏，且后续新增工具又会退回原样。
        try:
            result = _errors.apply_to_result(str(name), result)
        except Exception as e:  # noqa: BLE001
            logger.debug("结果信封处理失败：%s", name, exc_info=True)
        # 批次34：输出控制（compact / max_lines / full）。放在信封之后——先保证
        # status / next_actions 这类结构性字段齐全，再谈瘦身；没有任何控制生效时
        # apply_to_result 原样返回，默认行为与以前完全一致。
        if _out_params:
            try:
                result = _outctl.apply_to_result(result, str(name), _out_params)
            except Exception as e:  # noqa: BLE001
                logger.debug("输出控制失败：%s（已按原样返回）", name, exc_info=True)
        return result

    async def list_tools(self):
        # 描述里补「主名 ← 别名」与「风险级别」，只补一次（重复调用不会叠加）
        for info in self._tool_manager.list_tools():
            desc = info.description or ""
            # 风险标注：高风险＝会改目标 Flash/内存或会动用户的 Keil，属不可逆操作。
            # 吸收 embeddedskills 的 operation_mode 分级——调用方在长链路里最容易忘掉
            # 「我刚做了一次不可逆操作」，所以在描述里显式标出来。
            if "\n【风险】" not in desc:
                if info.name in _errors.RISK_HIGH:
                    _risk_note = ("\n【风险】高——**不可逆**：会改写目标 Flash/内存，"
                                  "或关闭/重启用户的 Keil 实例。执行前确认目标与工程正确。")
                elif info.name in _errors.RISK_MEDIUM:
                    _risk_note = ("\n【风险】中——会改变目标状态或占用共享资源"
                                  "（调试态/串口/Keil 实例），必要时可回退。")
                else:
                    _risk_note = ""
                if _risk_note:
                    try:
                        info.description = desc + _risk_note
                        desc = info.description
                    except Exception:  # noqa: BLE001
                        logger.debug("未能写入风险说明：%s", info.name, exc_info=True)
            _apply_annotations(info)
            note = _aliases.alias_note(info.name, self._real_params(info.name))
            if not note:
                continue
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
                  symbol_projects: list | None = None,
                  toolsets: str | None = None) -> MCPServer:
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
                   "source_type": ("axf" if locator is not None else None),
                   "axf_source": (("--axf 启动参数：%s" % axf) if (axf_path and axf)
                                  else ("从默认工程推断：%s" % default_project) if axf
                                  else None)}
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
    # ---------------- 批次35-1：任意 Keil 命令直通 ----------------
    @server.tool(
        name="keil_command",
        title="执行任意 Keil 命令窗口命令",
        description=(
            "把一条命令**原样**送进 Keil 命令窗口执行（走 UVSOCK 的 EXEC_CMD），"
            "并把命令窗口输出/报错一并带回来。本工具是「万能兜底」：当某个专用工具不覆盖你要的"
            "操作时，用官方命令直接做，不必等封装。\n"
            "**常用命令**：`BS <符号|地址>` 下断点、`BK <编号>` 删断点、`BL` 列断点、"
            "`BK *` 全清、`G` 运行、`G, main` 运行到 main、`T` 单步(进)、`P` 单步(过)、"
            "`O` 单步(出)、`EVAL <表达式>` 求值、`WS <变量>` 加观察、`RESET` 复位、"
            "`_RDWORD(0x地址)` 读 32 位内存、`printf(\"fmt\", x)` 打印到命令窗口、"
            "`LOG >>文件` / `LOG OFF` 把命令窗口输出落盘。\n"
            "**三条真机实测的坑（务必看）**：\n"
            "1. 单步的官方缩写是 **`T`/`P`/`O`**；写 `Step`/`Tstep`/`Pstep` 会回 "
            "`*** error 34: undefined identifier`（无窗口焦点时单步会退化成**指令级**，不进源码级）。\n"
            "2. 命令报错**不会**反映在 UVSOCK 的 status 上（Keil 恒回 status=0）——"
            "本工具已解析命令窗口的 `*** error N: message` 并自动给出错误码含义，"
            "判断成败请看返回里的 ok / errors，不要只看 status。\n"
            "3. 一次只能一条命令（含换行/回车会被拒），多步请用 batch 或 batch_debug_script。\n"
            "返回：ok / status / console（命令窗口新增行）/ errors（含 code+meaning+fix）/ reply。"
            "**高风险**：`BK *`、`RESET`、`G` 等会改变目标运行状态。"
        ),
    )
    async def keil_command(command: str, settle_ms: int = 120,
                           explain_errors: bool = True) -> str:
        try:
            client = _get_client()
            settle = max(0, min(int(settle_ms or 0), 5000)) / 1000.0
            r = client.exec_command_checked(command, settle=settle)
            out = {"ok": bool(r.get("ok")), "status": r.get("status"),
                   "command": r.get("command") or command,
                   "console": r.get("console") or []}
            if r.get("output") is not None:
                out["reply"] = r["output"]
            elif r.get("output_hex"):
                out["reply_hex"] = r["output_hex"]
            errs = r.get("errors") or []
            if errs:
                out["errors"] = errs
                out["error"] = r.get("error")
                if explain_errors:
                    out["error_meanings"] = [
                        {k: v for k, v in _keilkb.explain_command_error(
                            e.get("text") or "", e.get("code")).items()
                         if k in ("code", "meaning", "cause", "fix", "confidence",
                                  "matched", "note", "generic_fix")}
                        for e in errs]
            if not out["console"] and not out.get("reply") and not out.get("reply_hex"):
                out["console_note"] = ("命令窗口没有新增输出。部分命令（如 BS 成功）默认静默，"
                                       "其成功与否看 ok/status；要确认效果请用专用读取工具"
                                       "（list_breakpoints / calc_expression / read_registers）。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e), "command": command})


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
            "**符号解析双轨（批次48）**：Keil 表达式这条路读不到时（static 变量、符号漂移、"
            "停在不相关位置），会自动改走 .axf 符号表地址 + read_mem 兜底，返回 "
            "fallback=\".axf 符号表 + read_mem\" 与 fallback_reason 说明为什么换了轨道；"
            "两条都不通就如实报错，不会给一个像样的假值。"
            "若返回 value_suspect/value_warning（读回整帧全 0x00/全 0xFF），"
            "**不要**据此判定「变量被清零」——先用 reloc_check 校验 reloc_delta 是否与实际布局相符。"
            "适合先查地址/数组内容，再配合 read_mem/write_mem 进一步读写。注意：需目标暂停（运行中读取会失败/错位）；依赖 .axf 调试符号。刚停止瞬间取值可能读到脏值。"
        ),
    )
    async def read_variable(name: str, count: int = 0, read_memory: bool = True,
                            reloc_delta: str = "") -> str:
        client = None
        delta, dnote = 0, ""
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
        # 批次48：把两条符号解析轨道接起来——Keil 表达式读不到时改走 .axf 符号表，
        # 换轨原因保留在 fallback_reason，原轨道的失败信息留在 keil_path（可追溯）。
        if client is not None and ((not out.get("ok"))
                                   or (out.get("address") and out.get("value") is None)):
            try:
                fb = _read_variable_via_elf(client, name, count=count,
                                            read_memory=read_memory, delta=delta,
                                            dnote=dnote)
            except Exception as e:  # noqa: BLE001
                fb = {"ok": False, "error": "ELF 兜底读取异常: %s" % e}
            if fb and fb.get("ok"):
                reason = out.get("error") or (
                    "Keil 表达式路径取到了地址但没取到值" if out.get("ok")
                    else "Keil 表达式路径失败")
                fb["fallback_reason"] = (
                    "Keil 表达式读 '%s' 未成功（%s），已自动改用 .axf 符号表地址 + read_mem"
                    % (name, reason))
                fb["keil_path"] = {k: out.get(k) for k in
                                   ("ok", "error", "value", "address") if k in out}
                out = fb
            elif fb and not fb.get("ok"):
                out.setdefault("elf_fallback", {
                    "ok": False, "error": fb.get("error"),
                    "note": "两条符号轨道（Keil 表达式 / .axf 符号表）都没读到"})
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
            "返回十六进制字节串及 ASCII 视图。"
            "**脏读防护（verify，默认 \"auto\"）**：stop 之后紧跟的第一次读可能整帧返回全 0"
            "（真机实测 0x08022000 读出 16 个 00，重读即正确）——auto 会在「首帧整帧退化（全 0x00/全 0xFF）"
            "或距最近一次 stop 不足 1 秒」时自动复读，连续两次一致才采纳，并返回 read_confidence"
            "（high/low）、reread_count、reread_consistent、degenerate、since_stop_s；"
            "首帧是脏值时用 first_read_hex 留证、data_hex 换成可靠值并给 warning。"
            "verify=true 总是复读（强制确认），verify=false 关闭（大块搬运省时间）；"
            "verify 可传字符串也可传 JSON 布尔（true/false 等价于 \"true\"/\"false\"）。"
            "**运行态读取（running，默认 \"live\"）：目标全速运行时也能读**（真机实测 SRAM 与外设"
            "寄存器都读得到，不必先 stop）；运行态一律多复读一轮，两次不一致时给"
            "read_confidence=medium + read_unstable=true + while_running，并把「该地址本来就在被 CPU"
            "改写」与「这次读被运行中的目标打断了」两种可能都写明（不替你选一个）。"
            "要取某一瞬间的一致快照，用 running=\"halt\"（停-读-走）：会暂停目标再恢复，返回"
            "paused_ms / was_running / resumed / halt_note 如实交代代价，恢复失败会告警。"
            "**看到 read_confidence=\"low\"/\"medium\" 或 degenerate 时不要据此下结论（例如「读到 0 就判定变量被清零」）。**"
            "勿越界读外设保留区，可先 query_memory_map 确认范围。"
        ),
    )
    async def read_mem(addr: str | int, n_bytes: int = 0, length: int = 0,
                       reloc_delta: str = "", verify: str | bool = "auto",
                       running: str = "live") -> str:
        addr = _addr_arg(addr)
        # verify 同时接受 "auto"/"true"/"false" 与 JSON 布尔 true/false
        verify = _norm_tristate(verify)
        run_mode = str(running or "live").strip().lower()
        if run_mode not in ("live", "halt"):
            return _js({"ok": False, "error_code": "invalid-argument",
                        "error": "running 只支持 live（不打断目标）/ halt（停-读-走），收到: %s"
                                 % running})
        try:
            client = _get_client()
            n = int(n_bytes or 0) or int(length or 0)
            if n <= 0:
                return _js({"ok": False, "addr": addr,
                            "error": "参数不足：必须指定读取字节数 n_bytes（别名 length），应为正整数"})
            delta, _dnote = _eff_reloc_delta(reloc_delta)
            a, note = _resolve_addr_with_reloc(addr, client, delta)
            halt_info = None
            paused_ms = 0
            if run_mode == "halt":
                t0 = time.time()
                halt_info = _halt_guard(client)
                try:
                    out = client.read_mem_verified(a, n, verify=verify)
                finally:
                    # 无论读成不成，都要把目标恢复回去（有副作用就得收尾）
                    paused_ms = int((time.time() - t0) * 1000)
                    _resume_after_halt(client, halt_info)
            else:
                out = client.read_mem_verified(a, n, verify=verify)
            ca = _cache_advisory(client, a, "read")
            if ca and isinstance(out, dict):
                out = dict(out)
                out["cache"] = ca
            if note and isinstance(out, dict):
                out = dict(out)
                out["addr"] = hex(a)
                out["addr_note"] = note
            if halt_info is not None:
                out = dict(out)
                out["sampling"] = "halt" if halt_info.get("stop_ok") else "halt_failed"
                out["was_running"] = halt_info.get("was_running")
                out["paused_ms"] = paused_ms
                if halt_info.get("was_running"):
                    out["resumed"] = halt_info.get("resumed")
                hn = _halt_note(halt_info, paused_ms)
                if hn:
                    out["halt_note"] = "；".join(hn)
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
            "（如误判为看门狗复位）。addr 支持十六进制/十进制/符号名。"
            "**运行态写入（running，默认 \"live\"）**：目标全速运行时也能写（回读校验会告诉你有没有落地），"
            "但写入可能被 CPU 后续改写或缓存回行覆盖；要确保写进去就生效，用 running=\"halt\""
            "（停-写-回读-走，返回 paused_ms / was_running / resumed / halt_note）。"
            "写外设寄存器/关键内存有副作用，写入前确认地址与值正确（可先 read_mem 备份）。"
        ),
    )
    async def write_mem(addr: str | int, data_hex: str, verify: bool = True,
                        running: str = "live") -> str:
        addr = _addr_arg(addr)
        run_mode = str(running or "live").strip().lower()
        if run_mode not in ("live", "halt"):
            return _js({"ok": False, "error_code": "invalid-argument",
                        "error": "running 只支持 live（不打断目标）/ halt（停-写-回读-走），收到: %s"
                                 % running})
        try:
            client = _get_client()
            a, note = _resolve_addr_arg(addr, client)
            payload, herr = _hex_bytes(data_hex)
            if payload is None:
                return _js({"ok": False, "addr": str(addr),
                            "error": "data_hex 非法: %s" % herr,
                            "hint": "传十六进制字节串：deadbeef / de ad be ef / 0x11223344"})
            halt_info = None
            paused_ms = 0
            t0 = time.time()
            if run_mode == "halt":
                halt_info = _halt_guard(client)
            try:
                out = dict(client.write_mem(a, payload))
                # 批次29：写后回读校验——把「写入被静默吞掉」变成显式 verified=false
                if verify and out.get("ok"):
                    out.update(_verify_write(client, a, payload))
                    if out.get("verified") is False:
                        out["warning"] = out.get("verify_note")
                elif not verify:
                    out["verified"] = None
                    out["verify_note"] = "已按 verify=false 跳过回读校验（无法确认写入是否落地）"
            finally:
                if halt_info is not None:
                    paused_ms = int((time.time() - t0) * 1000)
                    _resume_after_halt(client, halt_info)
            ca = _cache_advisory(client, a, "write")
            if ca:
                out["cache"] = ca
            if note:
                out["addr_note"] = note
            if halt_info is not None:
                out["sampling"] = "halt" if halt_info.get("stop_ok") else "halt_failed"
                out["was_running"] = halt_info.get("was_running")
                out["paused_ms"] = paused_ms
                if halt_info.get("was_running"):
                    out["resumed"] = halt_info.get("resumed")
                hn = _halt_note(halt_info, paused_ms)
                if hn:
                    out["halt_note"] = "；".join(hn)
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
            "**看门狗防御（真机踩过）**：新会话/复位后 DBGMCU 的 IWDG/WWDG 冻结位会被清零，"
            "目标 halt 超过看门狗溢出时间（典型 ~1.6~26s）就会**被看门狗复位、RAM 现场全丢**。"
            "本工具默认在就绪后自动置位冻结位（freeze_watchdogs=true），返回 watchdog_freeze "
            "供核对；万一失败会带 warning，此时请尽快手动调 watchdog_freeze(action=\"enable\")。"
        ),
    )
    async def enter_debug(freeze_watchdogs: bool = True) -> str:
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
            # ready=False 时不许再报成功：真机踩到过「enter_debug 报成功、随后每条命令
            # 都返回 status=6」的假就绪（Keil 实例里残留命令脚本，进完调试又自己
            # Exited debug mode）。工具要么确认已进入调试态，要么如实报失败——
            # 不能给一个让调用方以为可以继续下命令的错答案。
            if out.get("ok") and out.get("ready") is False:
                out["ok"] = False
                out["error"] = (out.get("warning")
                                or "已发出进入调试命令，但未确认进入调试态")
                out["error_code"] = "enter-debug-not-ready"
                out["diagnosis"] = (
                    "已发出进入调试命令但未确认进入调试态。请依次排查："
                    "① 目标板/调试器连接是否正常（target_info 可看 IDCODE/DEV_ID）；"
                    "② Keil 是否弹了需人工确认的窗口（keil_health 的 modal_dialogs）；"
                    "③ 该实例是否残留命令脚本（进完调试又自己退出）："
                    "close_uvision(force=true) 后 launch_uvision + enter_debug 重开一个干净实例。"
                )
            if out.get("ok"):
                # 批次29：记录本次调试会话加载的符号基线（.axf 路径 + 时间戳），
                # 之后 .axf 被重编/重烧即可判定「会话符号已过期」。
                out["symbol_session"] = _mark_debug_session("enter_debug")
                # 批次49：跨工程符号绑定防呆——「刚烧的固件」与「当前符号」是不是同一份。
                # 真机踩过：烧的是 special 工程，加载的却是主固件工程的 .axf，
                # PC 全解析成假符号；工具不校验就等于默认它们一致，跨仓库调试必踩。
                try:
                    sc = _symbol_source_check(client=_get_client(), server=server)
                    if sc:
                        out["symbol_source"] = sc
                        if sc.get("warning"):
                            out["symbol_source_warning"] = sc["warning"]
                except Exception:  # noqa: BLE001
                    pass
            if freeze_watchdogs and out.get("ok"):
                out["watchdog_freeze"] = _auto_freeze_watchdogs(_get_client())
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
            "（如 'main'）或地址（如 '0x08001034'）。返回是否成功。"
            "**地址路径与符号路径做同一套归一**：入参地址若带 Thumb 位（bit0=1，常见于函数指针）"
            "会自动按偶地址下断并返回 thumb_bit_stripped/address_normalized——真机实测 "
            "Keil 的 BS 对奇数地址一律报 `error 57: illegal address`，而符号名路径经 "
            "calc_expression 拿到的是偶地址，所以只有裸地址会踩这个坑。"
            "设断点失败时返回 diagnosis（错误码含义 + 地址落在哪个区 + 是否在 .axf 覆盖范围 + 下一步建议）。"
            "另外：设断点走命令窗口 BS，会触发 Keil 异步推送断点消息，紧随其后的命令响应可能被污染"
            "（本工具已改为先 calc_expression 取地址再 BS 0xaddr）；设断点后立即 run/step 前需稍等异步消息落地。"
            "需已进入调试且配置 .axf。"
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
            # 裸地址同样过一遍 Thumb 位归一：真机实测 BS 对奇数地址报 error 57
            # illegal address，而函数指针常带 bit0（符号名路径经 calc_expression
            # 拿到的是偶地址，所以只有裸地址会踩这个坑）。
            addr_even, thumb_stripped = _thumb_even(addr)
            if addr_even is not None:
                addr = addr_even
            # 用解析出的地址设断点，更精确且能拿到位置信息
            r = client.set_breakpoint(hex(addr) if addr is not None else expr)
            out = {"expr": expr}
            out.update(r)
            if thumb_stripped:
                out["thumb_bit_stripped"] = True
                out["address_normalized"] = (
                    "入参地址带 Thumb 位（bit0=1），已按偶地址 0x%08X 下断"
                    "（Keil 的 BS 对奇数地址报 error 57 illegal address）。" % addr)
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
            if not r.get("ok"):
                out["diagnosis"] = _bp_failure_hint(client, addr, r, loc)
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
            addr_even, thumb_stripped = _thumb_even(addr)
            if addr_even is not None:
                addr = addr_even
            loc = _get_locator()
            target = hex(addr) if addr is not None else expr
            cmd = f"BS {target}, {cond}"
            if count and count > 1:
                cmd = f"{cmd}, {count}"
            r = client.exec_command(cmd)
            out = {"ok": r.get("ok"), "expr": expr, "condition": cond, "count": count,
                   "command": cmd, "status_text": r.get("status_text")}
            if thumb_stripped:
                out["thumb_bit_stripped"] = True
                out["address_normalized"] = (
                    "入参地址带 Thumb 位（bit0=1），已按偶地址 0x%08X 下条件断点。"
                    % (addr or 0))
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
                     "返回 cleared_by 表示实际用的方式；若真实断点表里找不到会明确报 ok=false 并给出原因。"
                     "**dwt（默认 true）**：清完回读 DWT 硬件比较器（FUNCTION0..3）；"
                     "若内部记录已空但比较器仍武装，说明留下了「run 即停」的鬼魂断点，"
                     "会一并清掉并报 ghost_slots_cleared；dwt=false 则只做 Keil 侧清除。"),
    )
    async def clear_watchpoint(expr: str | int = "", bp_id: int | None = None,
                               dwt: bool = True) -> str:
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
            # 批次48：Keil 断点表与 DWT 硬件比较器是两处状态，清完必须回读复核，
            # 否则「说清了其实没清」——真机上就表现为 run 之后立刻又停下。
            if dwt:
                try:
                    slots = _dwt_watch_slots(client)
                    armed = [x["slot"] for x in slots if x.get("armed")]
                    out["dwt_slots_after"] = slots
                    out["dwt_armed_after"] = armed
                    if not _watchpoints and armed:
                        res = _dwt_clear_watch_slots(client)
                        out["ghost_slots_cleared"] = res
                        out["ghost_note"] = (
                            "内部数据断点记录已空、但 DWT 比较器 %s 仍武装——这就是"
                            "「run 之后立刻又停下」的鬼魂断点来源，已一并清除并回读确认。"
                            % armed)
                    elif not success and armed:
                        out["dwt_warning"] = (
                            "Keil 侧未确认清除，且 DWT 比较器 %s 仍武装：若有「run 即停」"
                            "现象，用 clear_all_watchpoints(hard=true) 或直接写 "
                            "DWT_FUNCTIONn=0 彻底释放。" % armed)
                except Exception as e:  # noqa: BLE001
                    out["dwt_warning"] = "回读 DWT 比较器失败：%s" % e
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
            cb_thumb = None
            if target.lower().startswith("0x"):
                try:
                    _t = int(target, 16)
                    _t2, _stripped = _thumb_even(_t)
                    if _stripped:
                        cb_thumb = target
                        target = hex(_t2)
                except ValueError:
                    pass
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
            if cb_thumb:
                out["thumb_bit_stripped"] = True
                out["address_normalized"] = {"from": cb_thumb, "to": target,
                                             "reason": "原地址带 Thumb 位（bit0=1），"
                                                       "已清位后交给 Keil（真机实测奇数地址报 error 57）"}
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
            "**dwt（默认 true）：同时清 DWT 硬件比较器槽位（FUNCTION0..3，回读复核）。**"
            "只清 Keil 断点表是不够的——真机踩到「清完 run 又立刻停下」的鬼魂断点，"
            "根因就是断点表清了、硬件比较器还武装着（当时只能手写 DWT_FUNCTION3=0 才解开）。"
            "若清理前内部记录已空但比较器仍武装，会额外报 ghost_slots 指出这就是鬼魂来源；"
            "dwt=false 则完全不碰 DWT（有外部工具在用比较器时用）。"
        ),
    )
    async def clear_all_watchpoints(hard: bool = False, dwt: bool = True) -> str:
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
            # 批次48：DWT 比较器必须一起清。Keil 断点表与硬件比较器是两处状态，
            # 只清前者就会留下「run 即停」的鬼魂断点（用户真机踩到并手工解过）。
            if dwt:
                try:
                    slots_before = _dwt_watch_slots(client)
                    armed_before = [x["slot"] for x in slots_before if x.get("armed")]
                    res = _dwt_clear_watch_slots(client)
                    out["dwt"] = res
                    out["dwt_armed_before"] = armed_before
                    if armed_before:
                        out["ghost_slots"] = armed_before
                        out["ghost_note"] = (
                            "清理前 DWT 比较器 %s 仍处于武装状态（内部数据断点记录已空）——"
                            "这正是「run 之后立刻又停下」的鬼魂断点来源，本次已一并清除。"
                            % armed_before)
                    cleared_ok = res.get("cleared")
                    if cleared_ok is False:
                        out["ok"] = False
                        out["error_code"] = "dwt-not-cleared"
                        out["error"] = ("DWT 比较器回读仍在武装（槽位 %s）：硬件断点未真正释放，"
                                        "run 可能立刻又被拦停"
                                        % res.get("armed_after"))
                        out["diagnosis"] = ("可用 set_register 直接写 DWT_FUNCTIONn=0"
                                            "（n=0..3，地址 0xE0001028+0x10n）后重试；"
                                            "若写不进，确认目标处于停止且 DEMCR.TRCENA 未被清。")
                    elif cleared_ok is None:
                        out["dwt_warning"] = res.get("note")
                except Exception as e:  # noqa: BLE001
                    out["dwt"] = {"error": str(e)}
                    out["dwt_warning"] = "清理 DWT 比较器时出错：%s（Keil 侧断点已按上面结果处理）" % e
            else:
                out["dwt"] = {"skipped": True,
                              "note": "dwt=false：本次未动 DWT 硬件比较器（可能仍有鬼魂断点）"}
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
            "names 可选：只要指定寄存器（如 'pc' 或 'pc,sp,lr'，也接受 r13/r14/r15 写法），"
            "不传则整组读；不认识的名单会放进 unknown_names 并列出 supported_names（不静默忽略）。"
        ),
    )
    async def read_registers(names: str = "") -> str:
        try:
            client = _get_client()
            # 寄存器名候选（大小写兼容不同 Keil 版本）
            order = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                     "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC", "xPSR"]
            aliases = {"SP": ("__currentSP()", "SP", "R13"),
                       "LR": ("__currentLR()", "LR", "R14"),
                       "PC": ("__currentPC()", "PC", "R15")}
            # names：只读指定寄存器（真机反馈：想单看 pc 却只能整组读，返回里再自己翻）
            want: list = []
            unknown: list = []
            toks = ((names or "").replace(",", " ").replace(";", " ")
                    .replace("|", " ").split())
            for tok in toks:
                up = tok.strip().upper()
                up = {"R13": "SP", "R14": "LR", "R15": "PC"}.get(up, up)
                if up in order:
                    if up not in want:
                        want.append(up)
                elif tok.strip():
                    unknown.append(tok.strip())
            use = want or order
            core: dict = {}
            failed: list = []
            for name in use:
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
                msg = "无法读取 CPU 寄存器（请先进入调试）"
                if unknown and not want:
                    msg = "指定的寄存器名都不被支持：%s" % ", ".join(unknown)
                return _js({"ok": False, "error": msg, "failed": failed,
                            "unknown_names": unknown or None,
                            "supported_names": [n.lower() for n in order]})
            out = {"ok": True, "registers": core, "count": len(core)}
            if want:
                out["filter"] = [n.lower() for n in want]
            if unknown:
                out["unknown_names"] = unknown
                out["supported_names"] = [n.lower() for n in order]
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
                return _js({"ok": False, "register": register, "error_code": "invalid-argument",
                            "error": f"不支持的寄存器名: {register}",
                            "available": ["R0-R12", "SP", "LR", "PC", "xPSR"]})
            vs = (value or "").strip()
            try:
                num = int(vs, 0) if vs.lower().startswith(("0x", "-0x")) else int(vs, 10)
            except ValueError:
                return _js({"ok": False, "register": reg, "error_code": "invalid-argument",
                            "error": f"无法解析数值: {value}",
                            "hint": "value 支持 0x 十六进制或十进制整数"})
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
            "参数：port=**Keil 串口窗口编号**（Debug(printf) Viewer 对应其中一个，默认 0；"
            "注意它不是 ITM stimulus port）、size=最多读取字节数(默认4096)、"
            "decode=解码方式 auto/itm/text（默认 auto：像文本就按文本，否则按 ITM 报文）、"
            "port_filter=只看某个 ITM stimulus port（-1 表示不过滤）、"
            "reset=true 清掉增量解码状态重来。\n"
            "返回 {config, trace, decode}：config 给出 DEMCR.TRCENA / ITM->TCR / ITM->TER 的 "
            "Trace 使能诊断（判断为何收不到 ITM 打印）；trace 是拉取到的原始缓冲（含 data_hex）；"
            "decode 是结构化结果——packets（instrumentation 打印 / hardware 源包 / overflow / "
            "sync 等，含 header、port、data_text/data_hex）、summary（各类报文计数、涉及 port、"
            "PC 采样数）、overflow 计数、leftover_bytes（未凑齐半包的尾字节，留到下次）、"
            "warnings（丢包/非增量/半包）与增量记账 state。\n"
            "**增量语义**：连续拉取时只喂新增字节（上次缓冲是本次前缀时判为追加）；"
            "否则整段重喂并标 delta=false，不会假装没重复。\n"
            "需已进入调试；真实 ITM 输出还要求 Keil 已配置 Trace(Core Clock + "
            "Stimulus Port0) 且调试器(ST-Link/J-Link) SWO 引脚已连接，缺任一都收不到数据"
            "（config 会给出诊断）；仅依赖 ITM 缓冲，非全量 trace。"
        ),
    )
    async def itm_trace(port: int = 0, size: int = 4096,
                        decode: str = "auto", port_filter: int = -1,
                        reset: bool = False) -> str:
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
            # ---- 结构化解码（增量；半包留到下次）----
            raw = b""
            if trace.get("ok"):
                try:
                    raw = bytes.fromhex(trace.get("data_hex") or "")
                except ValueError:
                    out["decode"] = {"ok": False,
                                     "error": "serial_get 返回的 data_hex 不是合法十六进制",
                                     "error_code": "bad-hex"}
                    raw = None
            if raw is not None:
                out["decode"] = _decode_itm_view(raw, mode=decode,
                                                 reset=bool(reset),
                                                 port_filter=int(port_filter))
            if not cfg["ready"]:
                out["hint"] = ("Trace 未就绪时拉不到真实 ITM 输出；先按 config.note 把 "
                               "Core Clock / Stimulus Port0 / SWO 接线补齐")
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
            "**CFSR/HFSR 是粘滞位（sticky）**：写 1 清除或复位才归零——读到 UsageFault 并不代表此刻正在 "
            "UsageFault，也可能只是此前异常的残留。本工具因此返回 fault_timing："
            "timeliness=current（ICSR 显示当前正处在 fault handler 里，是当下故障）/ "
            "sticky（粘滞位，可能来自更早的异常，含上次调试或上次上电以来）/ none（未置位），"
            "并给出 first_seen（本进程内首次观察到置位的时间）、last_seen、last_cleared（最近一次 clear_faults）。"
            "**看到 timeliness=sticky 就不要按当前故障处理**；想确证是否还有新异常，先调 clear_faults 清位、"
            "再让程序跑一段，然后重新 fault_report：位又置起来才是新发生的。"
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
            out["cfsr"] = {"value": "0x%08x" % (cfsr or 0), "reasons": reasons,
                           "sticky": True,
                           "sticky_note": ("CFSR 为粘滞位：写 1 清除或复位才归零，"
                                           "置位不代表此刻仍有该故障")}
            # 时效/来源判定（批次30 反馈③）
            now_text = _file_mtime_text(time.time())
            in_fault_handler = vect in (3, 4, 5, 6)
            if cfsr or hfsr:
                if _FAULT_TRACK["cfsr_first_seen"] is None:
                    _FAULT_TRACK["cfsr_first_seen"] = now_text
                _FAULT_TRACK["cfsr_last_seen"] = now_text
            _FAULT_TRACK["cfsr_last_value"] = int(cfsr or 0)
            _FAULT_TRACK["hfsr_last_value"] = int(hfsr or 0)
            if not (cfsr or hfsr):
                timeliness = "none"
                timing_note = "CFSR/HFSR 均未置位：当前没有记录到任何故障状态位。"
            elif in_fault_handler and (cfsr or hfsr):
                timeliness = "current"
                timing_note = ("ICSR 显示目标此刻正处在 %s 处理程序中，因此这些置位属于**当前故障**，"
                               "reasons 可直接当作本次异常的原因。" % exc)
            else:
                timeliness = "sticky"
                timing_note = (
                    "这些故障位置着，但 ICSR 显示目标当前**不在**任何 fault handler 里"
                    "（当前向量为 %s）——CFSR/HFSR 是粘滞位，不会自动清，所以更可能是**更早发生的异常残位**"
                    "（上一次调试、或上次上电以来未被清除），不能当作当前故障。"
                    "确证方法：clear_faults 清位 → 让程序继续跑一段 → 重新 fault_report，"
                    "位再置起来才是新发生的。" % exc)
            out["fault_timing"] = {
                "timeliness": timeliness,
                "first_seen": _FAULT_TRACK["cfsr_first_seen"],
                "last_seen": _FAULT_TRACK["cfsr_last_seen"],
                "last_cleared": _FAULT_TRACK["last_cleared"],
                "sticky_bits": True,
                "note": timing_note}
            if timeliness == "sticky":
                out["hint"] = ("fault_timing.timeliness=sticky：请勿直接按当前故障处理；"
                               "先 clear_faults 清位再跑一段复现，重新 fault_report 才能确认新异常。")
            # 无论是否置位都给出 hfsr，避免调用方把「没有该字段」误读成「读不到 HFSR」
            out["hfsr"] = {"value": "0x%08x" % (hfsr or 0), "sticky": True,
                           "sticky_note": ("HFSR 同为粘滞位：写 1 清除或复位才归零；"
                                           "0x00000000 表示自上次清位以来未记录到硬故障")}
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
            if hfsr:
                out["hfsr_sticky"] = True
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clear_faults",
        title="清除故障状态位（区分新旧异常）",
        description=(
            "清除 CFSR(0xE000ED28) 与 HFSR(0xE000ED2C) 的粘滞故障位——这两个寄存器是 W1C"
            "（写 1 清除），本工具按 ARM 规定向它们写 0xFFFFFFFF 完成清除，并顺便清掉 "
            "MMFAR/BFAR 的 VALID 位，返回 before/after 值供对照。"
            "**用途**：区分「当前故障」与「历史残留位」——fault_report 报 timeliness=sticky 时，"
            "先 clear_faults 清位，再让程序继续跑一段（run / run_timeout），然后重新 fault_report："
            "位若又置起来，说明确实新发生了异常；位保持为 0，则原先那些是历史残留。"
            "注意：需已进入调试且目标已停止；清除只影响状态位，不改变程序行为，也不清除寄存器现场。"
            "若某些位置清不掉（读回仍非 0），说明是新异常在持续发生。"
        ),
    )
    async def clear_faults() -> str:
        try:
            client = _get_client()
            b_cfsr = _dwt_read_u32(client, 0xE000ED28)
            b_hfsr = _dwt_read_u32(client, 0xE000ED2C)
            ok_c = _dwt_write_u32(client, 0xE000ED28, 0xFFFFFFFF)
            ok_h = _dwt_write_u32(client, 0xE000ED2C, 0xFFFFFFFF)
            a_cfsr = _dwt_read_u32(client, 0xE000ED28)
            a_hfsr = _dwt_read_u32(client, 0xE000ED2C)
            out = {"ok": bool(ok_c and ok_h),
                   "before": {"cfsr": None if b_cfsr is None else "0x%08x" % b_cfsr,
                              "hfsr": None if b_hfsr is None else "0x%08x" % b_hfsr},
                   "after": {"cfsr": None if a_cfsr is None else "0x%08x" % a_cfsr,
                             "hfsr": None if a_hfsr is None else "0x%08x" % a_hfsr},
                   "cleared": {"cfsr": bool(a_cfsr == 0), "hfsr": bool(a_hfsr == 0)}}
            if out["ok"]:
                _FAULT_TRACK.update({"cfsr_first_seen": None, "cfsr_last_seen": None,
                                     "cfsr_last_value": 0, "hfsr_last_value": 0,
                                     "last_cleared": _file_mtime_text(time.time())})
                out["last_cleared"] = _FAULT_TRACK["last_cleared"]
            if a_cfsr or a_hfsr:
                out["warning"] = ("清除后仍有位保持置位：说明新异常正在持续发生"
                                  "（或目标仍在运行、写入未生效）——请先确认目标已停止，"
                                  "稍后再 clear_faults 并重新 fault_report。")
                out["ok"] = False
            else:
                out["hint"] = ("已清位。现在让程序继续跑一段（run / run_timeout）再重新 fault_report："
                               "位又置起来即为新发生的异常；保持 0 则此前那些是历史残留位。")
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
            "文件:行号（如 main.c:77）。实现为：临时断点->运行->**校验真命中**->清除断点。"
            "已执行过的地址断点不会命中：此时如实返回 ok=false(error_code=run-to-target-timeout) "
            "并把目标停下（旧实现会把「还在跑」报成「停在第 N 行」）。"
            "timeout_s 控制等待命中的超时，默认 10s。"
            "**触发前一致性校验（批次48）**：文件:行号会拿匹配证据先验一遍——"
            "同名文件撞行号（ambiguous-line）、命中行比目标行早太多（line-fuzzy）、"
            "地址不在任何符号区间（not-in-symbols）、目标比当前 PC 所在函数入口还早且不同函数"
            "（suspicious-target）这四类**默认直接拒绝并给出证据**，不浪费一次触发；"
            "返回 target_check 记录本次校验（拿不到 PC 时会注明 skipped，不冒充已校验）。"
            "确有把握时可传 allow_suspect=true 强行执行；max_fuzz 调整行号容差（默认 200）。"
            "需已进入调试状态且配置了 .axf 调试符号。注意：实现为临时断点→run→清除。run 到断点停止时返回的 status 是 22(断点已创建) 而非 0；刚停止瞬间读 PC 可能为脏值（本工具已用稳定读取修复）。需已进入调试且配置 .axf。"
        ),
    )
    async def run_to_line(target: str | int, timeout_s: float = 10.0,
                          allow_suspect: bool = False, max_fuzz: int = 200) -> str:
        target = _addr_arg(target)
        try:
            loc = _get_locator()
            if not loc or not loc.is_ready():
                return _js({"ok": False, "error": "符号定位未就绪（缺少 .axf 调试符号）"})
            ex = _parse_target_ex(loc, target)
            addr = ex.get("addr")
            if addr is None:
                return _js({"ok": False, "target": target,
                            "error": ex.get("reason")
                                     or "无法解析目标：需为 0x地址 或 文件:行号（如 main.c:77）",
                            "target_parse": ex,
                            "hint": (ex.get("hint")
                                     or "行号写法尽量带上目录"
                                        "（如 Core/Src/main.c:77），避免同名文件撞行号")})
            addr = int(addr) & ~1
            client = _get_client()
            guard, gev = _run_to_line_guard(client, loc, ex, addr,
                                            allow_suspect=allow_suspect, max_fuzz=max_fuzz)
            if guard:
                return _js(guard)
            bp = client.set_breakpoint(hex(addr))
            if not bp.get("ok"):
                return _js({"ok": False, "target": target, "addr": hex(addr),
                            "error": f"设置临时断点失败: {bp}", "target_check": gev})
            try:
                tm = float(timeout_s)
            except Exception:  # noqa: BLE001
                tm = 10.0
            tm = max(0.5, min(600.0, tm))
            try:
                r = client.run()
                # UVSOCK 的 run(START_EXECUTION) 在运行到断点停止时会返回 BP_CREATED(22) 而非 0，
                # 据此判「命令已生效」；是否真停在目标地址由下面的 wait_breakpoint 校验
                run_ok = r.get("ok") or r.get("status") == 22
                if not run_ok:
                    return _js({"ok": False, "target": target, "addr": hex(addr),
                                "error_code": "run-failed",
                                "error": f"运行失败: {r}"})
                # 批次38 真机实测（假成功）：目标早已跑过该地址时断点永不命中，旧实现
                # 仍拿陈旧 PC 报「ok=true + 停在第 N 行」，而 get_status 显示目标在跑。
                # 改为等一个真正的命中事件（wait_breakpoint 内含「新停止」三条证据判定）。
                hit = client.wait_breakpoint([addr], timeout_s=tm)
            finally:
                client.clear_breakpoint(hex(addr))
                _breakpoints[:] = [b for b in _breakpoints
                                   if b.get("address") != hex(addr)]
            if not (hit.get("ok") and hit.get("hit")):
                observed = "stopped-elsewhere" if isinstance(
                    (hit.get("registers") or {}).get("pc"), int) else "running"
                stop_verified = False
                try:
                    client.stop()
                    # stop 是异步生效的（真机实测：发完立刻 get_status 仍是执行中），
                    # 所以「已停止」必须轮询确认后才敢写进返回值。
                    stop_verified = await _wait_stopped(client, timeout=1.5)
                except Exception:  # noqa: BLE001
                    pass
                if stop_verified:
                    stop_note = "已发送 stop 并确认目标已停止，临时断点已清除"
                else:
                    stop_note = ("已发送 stop，但未能确认目标已停止（stop 异步生效）；"
                                 "请用 get_status 核实后再操作目标")
                return _js({"ok": False, "target": target, "addr": hex(addr),
                            "target_check": gev,
                            "error_code": "run-to-target-timeout",
                            "error": f"运行 {tm:g}s 未停在 {hex(addr)}：断点未命中"
                                     "（目标没走到该处，或该地址已经执行过了）",
                            "observed": observed,
                            "waited_ms": hit.get("waited_ms"),
                            "polls": hit.get("polls"),
                            "ran_during_wait": hit.get("ran_during_wait"),
                            "candidates": hit.get("candidates"),
                            "stop_verified": stop_verified,
                            "note": stop_note + "；需要它继续跑请调 run",
                            "hint": "run_to_line 只能停在「尚未执行到」的位置："
                                    "想让程序回到起点先 reset(run_after=false)；"
                                    "想确认某函数是否被调用请用 set_breakpoint + run"})
            # run 刚停止时 PC 可能是脏值(实测=1)，用稳定读取跳过脏值得到真实停靠位置
            regs = hit.get("registers") if isinstance(hit.get("registers"), dict) else None
            if not regs or not isinstance(regs.get("pc"), int):
                regs = client.read_cpu_registers_stable()
            out = {"ok": True, "target": target, "addr": hex(addr),
                   "hit_address": hit.get("hit_address"),
                   "waited_ms": hit.get("waited_ms"),
                   "new_stop_basis": hit.get("new_stop_basis"),
                   "hit_confidence": hit.get("hit_confidence"),
                   "pc_confidence": hit.get("pc_confidence")}
            if regs.get("ok") and isinstance(regs.get("pc"), int):
                stop = loc.addr_to_location(regs["pc"])
                if stop:
                    out["stopped_file"] = stop["file"]
                    out["stopped_line"] = stop["line"]
                    src = loc.read_source(stop["file"], stop["line"], context=3)
                    if src:
                        out["stopped_source"] = src["source"]
            out["target_check"] = gev
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "target": target, "error": str(e)})

    # ---------------- 批次49：函数时间线录制 / 环境体检 / D-Cache ----------------
    _trace_rec = {"report": None, "at": None}

    @server.tool(
        name="trace_record",
        title="函数运行时线录制（MDK/OpenOCD 双链路）",
        description=(
            "录制「函数运行状态」这一类细粒度事件：在选定函数的**入口**下断点，每次命中就"
            "记一条事件（时间、PC、所属函数、调用者、LR/SP、DWT 周期数），并给出按函数的统计、"
            "调用者分布与时间线。**MDK 与 OpenOCD 两条链路的抓取方式完全不同**（Keil 走 "
            "UVSOCK 的 BS/BK + wait_breakpoint，OpenOCD 走 telnet 的 bp/rbp + wait_halt），"
            "所以是分开实现、由 link=auto|keil|ocd 选路；返回值写明这次实际用的链路。\n"
            "funcs=\"task_a,task_b\" 精确选函数；pattern=\"rt_*,os*\" 用通配符选（二者可同用）。"
            "**必须至少给一个**——把整份符号表全下断点既不可能也没意义。"
            "max_breakpoints 是愿意占用的断点槽位（默认 4，硬件断点一般 6 个、M0 只有 4 个）；"
            "要监控的函数多于槽位时只布前 N 个，armed/skipped 如实说明。"
            "watch_exit=true 时会在命中入口后用 LR 动态补返回地址断点，从而拿到 exit 事件"
            "（槽位不够就没有 exit，返回里会说明，不编）。\n"
            "**录制的是事件流，不是精确耗时**：gap_cyc 是相邻两次命中的 CYCCNT 差值，"
            "精确耗时请用 profile_function；depth_est 由 SP 推断，是估计值。"
            "命中不落在任何已知函数区间时标 unknown 并保留原 PC，**不硬塞函数名**"
            "（符号与板上固件不同源时正是这种「假符号」场景）。\n"
            "action：run（默认，录一次并返回报告）/ status（上次报告摘要）/ "
            "read（带 kind/func/limit 过滤的时间线）/ stop（停目标并清掉残留断点）。"
            "reloc_delta 用于 App 重定位场景（运行地址 = 链接地址 + delta）。"
        ),
    )
    async def trace_record(action: str = "run", link: str = "auto", funcs: str = "",
                           pattern: str = "", max_events: int = 2000,
                           max_ms: int = 3000, max_breakpoints: int = 4,
                           watch_exit: bool = True, kind: str = "", func: str = "",
                           limit: int = 200, reloc_delta: str = "",
                           leave_halted: bool = True,
                           check_symbols: bool = True) -> str:
        try:
            a = (action or "run").strip().lower()
            if a in ("read", "status", "report"):
                rep = (_trace_rec or {}).get("report")
                if not rep:
                    return _js({"ok": False, "action": a,
                                "error_code": "no-recording",
                                "error": "本进程还没有录制过（先 trace_record(action=\"run\")）"})
                if a == "status":
                    out = {k: v for k, v in rep.items() if k != "timeline"}
                    out["action"] = "status"
                    out["timeline_hint"] = "用 trace_record(action=\"read\") 取时间线"
                    return _js(out)
                out = dict(rep)
                out["action"] = "read"
                # 过滤是在**已保留窗口**上做的（环形缓冲本身有上限），如实说明
                tl = list(rep.get("timeline") or [])
                if kind:
                    tl = [e for e in tl if e.get("kind") == kind]
                if func:
                    tl = [e for e in tl if e.get("func") == func]
                tl = tl[-max(1, int(limit or 200)):]
                out["timeline"] = tl
                out["timeline_note"] = ("过滤作用于已保留的 %d 条窗口（events_kept），"
                                        "不是全量；events_total/events_dropped 见报告"
                                        % int(rep.get("events_kept") or 0))
                return _js(out)
            if a in ("stop", "halt"):
                be, err = _rtrace.pick(link, who="停止录制目标")
                if be is None:
                    return _js(err)
                h = be.halt()
                out = {"ok": bool(h.get("ok")), "action": "stop", "link": be.name,
                       "halt": {"ok": bool(h.get("ok")),
                                "error": h.get("error") or h.get("status_text")}}
                rep = (_trace_rec or {}).get("report") or {}
                cleared, still = [], []
                for x in list(rep.get("breakpoints_left") or []):
                    try:
                        ok, _info = be.clear_bp(int(x, 16))
                    except Exception:  # noqa: BLE001
                        ok = False
                    (cleared if ok else still).append(x)
                out["breakpoints_cleared"] = cleared
                out["breakpoints_left"] = still
                return _js(out)
            if a not in ("run", "start", "record"):
                return _js({"ok": False, "action": action,
                            "error": "未知 action",
                            "available": ["run", "status", "read", "stop"]})
            loc = _ensure_locator()
            if loc is None:
                return _js({"ok": False, "action": a,
                            "error": "符号定位未就绪，无法把函数名解析成入口地址",
                            "hint": ("先 set_symbol_file 指到与板上固件同源的 .axf；"
                                     "若不确定是哪份，先跑 env_check 核对符号与固件是否同源")})
            try:
                ranges = loc._load_func_ranges()
            except Exception as e:  # noqa: BLE001
                ranges = []
                out_err = str(e)
            else:
                out_err = ""
            if not ranges:
                return _js({"ok": False, "action": a,
                            "error": ("当前符号源里没有函数区间（%s）：trace_record 需要 .axf"
                                      "（.map 只有名字、没有区间）"
                                      % (out_err or "空符号表")),
                            "symbol_axf": (_symbol_cfg or {}).get("axf"),
                            "symbol_source": (_symbol_cfg or {}).get("source_type")})
            delta, dnote = _eff_reloc_delta(reloc_delta)
            want = [x.strip() for x in str(funcs or "").split(",") if x.strip()]
            pats = [x.strip() for x in str(pattern or "").split(",") if x.strip()]
            if not want and not pats:
                return _js({"ok": False, "action": a,
                            "error": "没有指定要监控的函数（funcs 与 pattern 都为空）",
                            "func_count": len(ranges),
                            "examples": [nm for (_s, _e, nm) in ranges[:6]],
                            "hint": "funcs=\"task_a,task_b\" 精确选；pattern=\"rt_*,os*\" 通配选"})
            from fnmatch import fnmatch as _fnm
            sel, unknown = [], []
            if want:
                low = {nm.lower(): (nm, st, en) for (st, en, nm) in ranges}
                for w in want:
                    hit = low.get(w.lower())
                    if hit:
                        sel.append(hit)
                    else:
                        unknown.append(w)
            if pats:
                for (st, en, nm) in ranges:
                    if any(_fnm(nm, p) for p in pats):
                        sel.append((nm, st, en))
            seen, sel2 = set(), []
            for nm, st, en in sel:
                if nm in seen:
                    continue
                seen.add(nm)
                sel2.append((nm, st, en))
            sel = sel2
            if not sel:
                return _js({"ok": False, "action": a,
                            "error": "按 funcs/pattern 没匹配到任何函数",
                            "unknown_names": unknown[:20],
                            "hint": "用 find_symbol 搜一下确切函数名（注意编译器可能内联/改名）"})
            if unknown:
                out_unknown = unknown[:20]
            else:
                out_unknown = []
            be, err = _rtrace.pick(link, who="录制函数时间线")
            if be is None:
                return _js(err)
            client = None
            if be.name == "keil":
                try:
                    client = _get_client()
                except Exception:  # noqa: BLE001
                    client = None
            index = _rtr.make_func_index([(st + delta, en + delta, nm)
                                          for (st, en, nm) in ranges])
            rep = _rtrace.record(index,
                                 [st + delta for (nm, st, en) in sel],
                                 exits=(), backend=be,
                                 max_events=int(max_events or 2000),
                                 max_ms=float(max_ms or 3000),
                                 max_breakpoints=int(max_breakpoints or 4),
                                 watch_exit=bool(watch_exit),
                                 leave_halted=bool(leave_halted),
                                 limit=int(limit or 200),
                                 label="trace_record")
            rep["action"] = "run"
            rep["symbol_axf"] = (_symbol_cfg or {}).get("axf")
            rep["symbol_source"] = (_symbol_cfg or {}).get("source_type")
            rep["reloc_delta"] = "0x%X" % delta
            rep["reloc_note"] = dnote
            rep["selected"] = ["%s@0x%X" % (nm, st + delta) for (nm, st, en) in sel]
            if out_unknown:
                rep["unknown_names"] = out_unknown
            rep["symbol_note"] = ("事件里的函数名来自当前符号源；若它与板上固件不同源，"
                                  "名字会是「假符号」——先 env_check 核对")
            if check_symbols:
                try:
                    sc = _symbol_source_check(client=client, server=server)
                    if sc:
                        rep["symbol_check"] = sc
                        if sc.get("warning"):
                            rep["symbol_check_warning"] = sc["warning"]
                except Exception:  # noqa: BLE001
                    pass
            _trace_rec.update({"report": rep, "at": time.time()})
            return _js(rep)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})

    @server.tool(
        name="trace_eventrec",
        title="读 CMSIS Event Recorder（MDK 原生、纯 SWD 可用的事件缓冲）",
        description=(
            "读并解码目标 RAM 里的 CMSIS Event Recorder 缓冲——这是 MDK 原生、"
            "**不需要 SWO 引脚**的事件记录通路（uVision 的 Event Recorder / Event "
            "Statistics 窗口读的就是这份数据，数据通路是调试器读目标内存）。\n"
            "action：\n"
            "  status —— 录制器状态：协议版本、记录条数、缓冲地址、是否在记录、"
            "写指针、时间戳源与频率、EventStatus 签名校验；\n"
            "  read   —— 最近 N 条事件（旧→新）：目标侧时间戳、组件号、消息号、"
            "val1/val2、中断上下文、序号、首/末标记；\n"
            "  stats  —— EventStartX(slot)/EventStopX(slot) 成对事件的次数与耗时聚合"
            "（即 uVision 的 Event Statistics 口径：次数/总时间/最短/最长/平均）。\n"
            "**两个前提必须知道**：① 目标工程要链了 Event Recorder 组件并真的调了 "
            "EventRecordXxx —— 它不是自动捕获，没插桩就一条数据都没有（这种情况会明确报"
            "「没找到符号 EventRecorderInfo」）；② 事件名要靠工程里的 SCVD 文件，本工具只能"
            "给 component/message 编号与槽位号，给不了你那套名字。\n"
            "三条如实披露的口径：level 不随记录存储（写入前 id 被 &0xFFFF），只有 "
            "component=0xEF 那组（EventStartX/EventStopX）能按 message 反推组别 A/B/C/D "
            "与槽位；ts 是目标侧时间戳（DWT CYCCNT / SysTick），不是主机时间；读到写一半的"
            "记录会跳过并计数，不当数据。\n"
            "定位：默认用当前符号文件里的 EventRecorderInfo 符号，也可用 info_addr 直接指地址。"
            "link 选内存通路：auto（默认）/ keil / ocd。"
        ),
    )
    async def trace_eventrec(action: str = "status", link: str = "auto",
                             elf: str = "", info_addr: str = "",
                             limit: int = 100) -> str:
        try:
            a = (action or "status").strip().lower()
            xa = 0
            sv = str(info_addr or "").strip()
            if sv:
                try:
                    xa = int(sv, 16) if sv.lower().startswith("0x") else int(sv, 10)
                except ValueError:
                    return _js({"ok": False, "action": a,
                                "error": "info_addr 解析失败：%r（支持 0x 前缀十六进制或十进制）"
                                         % info_addr,
                                "next_actions": ["地址类参数支持 0x 前缀；"
                                                 "也可用当前符号文件里的 EventRecorderInfo 符号"]})
            ef = str(elf or "").strip() or ((_symbol_cfg or {}).get("axf") or "")
            if a == "status":
                out = _eventrec.status(elf=ef, info_addr=xa, link=link)
            elif a in ("read", "events", "timeline"):
                out = _eventrec.read(elf=ef, info_addr=xa, limit=int(limit or 100),
                                     link=link)
                if isinstance(out, dict) and out.get("ok"):
                    out["action"] = "read"
            elif a in ("stats", "statistics"):
                out = _eventrec.stats(elf=ef, info_addr=xa,
                                      limit=int(limit or 0), link=link)
                if isinstance(out, dict):
                    out["action"] = "stats"
            else:
                return _js({"ok": False, "action": a,
                            "error": "未知 action：%r" % action,
                            "available": ["status", "read", "stats"]})
            if isinstance(out, dict) and ef:
                out.setdefault("symbol_axf", ef)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})

    @server.tool(
        name="env_check",
        title="环境一致性体检（芯片 / SVD / 固件 / 符号 / D-Cache）",
        description=(
            "一键核对「工程与工具以为的目标」和「板上真实的目标」是否一致——跨仓库/跨板调试"
            "最毒的两类问题都在这里设防：①符号与板上固件不同源（PC 被解析成假符号）；"
            "②SVD/内置寄存器表选错芯片（读出别的芯片布局下「看着像样」的值）。\n"
            "输出包含：chip（实测 DBGMCU_IDCODE + CPUID 推出的型号/系列/置信度）、"
            "configured（工程 <Device> / 内置寄存器表 / 已加载 SVD 各自的系列，以及逐项 "
            "matched/mismatched/unknown 判定）、firmware_symbol（符号与板上固件的内容指纹"
            "比对）、dcache（D-Cache 是否使能）、last_flashed（本进程最近一次烧录的工程与 "
            ".axf）、problems / next_actions。\n"
            "**判据一律拿目标说话**：读不到 IDCODE 就说 unknown，不拿工程配置冒充实测结果；"
            "allow_mismatch 只影响「后续外设工具要不要放行」，不改变这里的判定。\n"
            "**guard 字段告诉你器件守卫这次到底有没有生效**：active=false 表示没能实测出芯片"
            "型号（多数是目标没在调试态），此时外设级读数**没有**型号核对保护，请自行核对型号——"
            "别把「体检没报错」当成「一定没问题」。\n"
            "链路是懒连接的：只连 UVSOCK **不会**进调试/停机/下载，可以放心先跑本工具看环境。"
        ),
    )
    async def env_check(project: str = "", link: str = "auto",
                        content_check: bool = True) -> str:
        try:
            out = {"ok": True, "action": "env_check"}
            be, berr = _rtrace.pick(link, who="环境体检")
            client = None
            if be is not None and be.name == "keil":
                try:
                    client = _get_client()
                except Exception:  # noqa: BLE001
                    client = None
            out["link"] = be.name if be is not None else None
            if be is None:
                out["link_error"] = (berr or {}).get("error")
                out["link_state"] = "unavailable"
            else:
                out["link_state"] = "connected"
            # 1) 实测芯片
            if client is not None:
                try:
                    chip = _probe_chip_cached(client)
                except Exception as e:  # noqa: BLE001
                    chip = {"confidence": "none", "reason": "探测失败：%s" % e}
            else:
                chip = {"confidence": "none",
                        "reason": ("本工具当前只在 Keil/UVSOCK 链路上读 DBGMCU_IDCODE；"
                                   "OpenOCD 链路可用 ocd_reg(name=\"r0\")+ocd_read_mem 读 "
                                   "0xE0042000 / 0x5C001000，或 ocd_probe 看目标信息")}
            out["chip"] = chip
            # 2) 各处「配置里写的型号」
            cfg = {}
            proj = ""
            try:
                proj = (project or "").strip() or (_last_project or "")
            except Exception:  # noqa: BLE001
                proj = ""
            if not proj:
                try:
                    proj = (_builder_cfg or {}).get("default_project") or ""
                except Exception:  # noqa: BLE001
                    proj = ""
            if proj and os.path.isfile(proj):
                cfg["project"] = proj
                try:
                    cfg["project_device"] = str(
                        (_uvprojx.read_config(proj) or {}).get("device") or "")
                except Exception as e:  # noqa: BLE001
                    cfg["project_device_error"] = str(e)
            else:
                cfg["project"] = proj or None
                cfg["project_note"] = "没有可用的工程路径（传 project= 或配置 --default-project）"
            cfg["builtin_regmap"] = _BUILTIN_REG_SERIES
            if _svd.loaded():
                cfg["svd_device"] = _svd.device()
                cfg["svd_file"] = _svd._CACHE.get("path")
            else:
                auto = _svd_autodevice()
                cfg["svd_device"] = auto or None
                if not auto:
                    cfg["svd_note"] = ("尚未加载 .svd：svd_list(device=\"STM32H743xx\") 或设 "
                                       "MDKDEBUG_SVD 指定一份")
            out["configured"] = cfg
            # 3) 逐项比对
            checks = []
            for what, name in (("project_device", cfg.get("project_device")),
                               ("builtin_regmap", cfg.get("builtin_regmap")),
                               ("svd_device", cfg.get("svd_device"))):
                if not name:
                    continue
                m = _chipid.series_match(name, chip)
                m["what"] = what
                checks.append(m)
            out["checks"] = checks
            # 4) 符号 vs 板上固件
            try:
                out["firmware_symbol"] = _symbol_source_check(
                    client=client, deep=("auto" if content_check else "false"),
                    server=server)
            except Exception as e:  # noqa: BLE001
                out["firmware_symbol"] = {"verdict": "unknown", "error": str(e)}
            # 5) D-Cache
            if client is not None:
                try:
                    out["dcache"] = client.dcache_status()
                except Exception as e:  # noqa: BLE001
                    out["dcache"] = {"ok": False, "error": str(e)}
            # 6) 最近一次烧录
            out["last_flashed"] = dict(_fw_cfg or {})
            # 7) 汇总
            problems, actions = [], []
            for m in checks:
                if m.get("verdict") == "mismatched":
                    problems.append({"what": m.get("what"), "detail": m.get("reason"),
                                     "error_code": "svd-device-mismatch"})
                    actions.append("按实测系列换寄存器表/SVD：%s" % (m.get("reason") or ""))
            fs = out.get("firmware_symbol") or {}
            if fs.get("warning"):
                problems.append({"what": "symbol-as-firmware",
                                 "detail": fs.get("warning")})
                actions.extend(fs.get("next_actions") or [])
            if not chip.get("series"):
                problems.append({"what": "chip-identity", "detail": chip.get("reason"),
                                 "error_code": "chip-unknown"})
                actions.append("确认目标已进入调试（Keil: enter_debug / OCD: ocd_start→halt）"
                               "后重跑 env_check")
            # 器件守卫有没有真的生效：只有实测出系列（confidence=high）才谈得上核对
            guard_active = bool(chip.get("series")) and chip.get("confidence") == "high"
            out["guard"] = {
                "active": guard_active,
                "what": "外设级读写（list_peripherals/read_peripheral/write_peripheral/"
                        "svd_decode/query_memory_map）在型号不符时默认拒绝执行",
                "note": ("实测芯片系列已拿到，守卫生效；下面的 checks 是按实测结果逐项核对"
                         if guard_active else
                         "**器件守卫本次没有生效**：没能实测出芯片型号（%s），"
                         "外设级读数没有型号核对保护，请自行核对型号后再采信"
                         % (chip.get("reason") or "原因未知")),
                "next_actions": [] if guard_active else [
                    "确认目标处于调试态（Keil: enter_debug / OpenOCD: ocd_start→halt）后重跑 env_check",
                    "不带调试器时可用 ocd_probe / ocd_reg 读 DEV_ID 间接核对",
                ],
            }
            if not guard_active:
                actions.extend(out["guard"]["next_actions"])
            out["problems"] = problems
            out["next_actions"] = list(dict.fromkeys(actions))
            if problems:
                out["verdict"] = "mismatch"
            elif not chip.get("series"):
                out["verdict"] = "unverified"
            else:
                out["verdict"] = "consistent"
            out["note"] = ("verdict=consistent 只代表**本次能核对的项**都一致；"
                           "unverified 表示关键证据（芯片 IDCODE）没读到，"
                           "别把「没发现问题」当成「一定没问题」。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": "env_check", "error": str(e)})

    @server.tool(
        name="dcache_maintain",
        title="D-Cache 一致性维护（状态 / 按地址 clean+invalidate）",
        description=(
            "Cortex-M7 一类带 D-Cache 的核上，调试器直读 RAM 走的是 AHB 旁路：命中的可能是"
            "**尚未回写的 cache 行**或**陈旧的 DRAM 副本**，于是读到「连续全 0」——"
            "真机反馈里读线程栈（0x2400FB00 一类 AXI SRAM）就是这么被误导的。\n"
            "action=status：读 SCB->CCR（0xE000ED14）的 DC/IC 位，说明 D-Cache 到底有没有开"
            "（读不到就说读不到，不猜）。action=clean_invalidate：对 addr 所在的 cache 行先 "
            "DCCMVAC（clean，脏行写回）再 DCIMVAC（invalidate）——**顺序不能反**，直接 "
            "invalidate 会把还没回写的脏数据丢掉。维护前后各读一遍并对比，值变了就说明"
            "之前那次读确实取到了陈旧副本。\n"
            "read_mem 在 RAM 区遇到「整帧退化」且 D-Cache 使能时已会自动做同样的维护，"
            "本工具用于手动确认/指定地址处理。写 SCB 寄存器需目标处于停止态。"
        ),
    )
    async def dcache_maintain(action: str = "status", addr: str = "",
                              n_bytes: int = 32) -> str:
        try:
            client = _get_client()
            a = (action or "status").strip().lower()
            if a in ("status", "info"):
                st = client.dcache_status()
                if st.get("ok"):
                    st["action"] = "status"
                    st["hint"] = ("dcache=true 时，调试器直读 RAM 可能取到陈旧/未回写的内容；"
                                  "读到可疑的整帧退化解，用 "
                                  "dcache_maintain(action=\"clean_invalidate\", addr=…) 维护后重读")
                    if client.running_cached():
                        st["target_running"] = True
                        st["running_note"] = ("目标当前在全速运行，维护 SCB 寄存器需要先 stop；"
                                              "读数本身可读，但一致性不保证")
                return _js(st)
            if a in ("clean_invalidate", "clean", "invalidate", "maintain"):
                if not str(addr or "").strip():
                    return _js({"ok": False, "action": a,
                                "error": "addr 必填：要维护哪一条 cache 行（按地址定位）"})
                try:
                    ad = _parse_addr(str(addr).strip())
                except Exception:  # noqa: BLE001
                    return _js({"ok": False, "action": a, "addr": addr,
                                "error": "addr 解析失败，支持 0x 前缀或十进制"})
                n = max(4, min(int(n_bytes or 32), 256))
                run = client.running_cached()
                before = client.read_mem(ad, n)
                ci = client.cache_clean_invalidate(ad)
                after = client.read_mem(ad, n)
                bhex = (before.get("data_hex") or "").lower() if before.get("ok") else None
                ahex = (after.get("data_hex") or "").lower() if after.get("ok") else None
                out = {"ok": bool(ci.get("ok")), "action": "clean_invalidate",
                       "addr": "0x%X" % ad, "n_bytes": n,
                       "ops": ci.get("ops"), "ops_ok": bool(ci.get("ok")),
                       "before_hex": bhex, "after_hex": ahex,
                       "changed": (bhex != ahex) if (bhex is not None and ahex is not None) else None,
                       "source": ci}
                if run:
                    out["target_running"] = True
                    out["warning"] = ("目标当时在全速运行：写 SCB 寄存器可能未生效，"
                                      "先 stop 再重试才能保证维护动作真的做了")
                if out["changed"] is True:
                    out["note"] = ("维护后读到的内容变了：此前那次读确实取到了未回写的"
                                   "陈旧副本（D-Cache 直读的典型表现）")
                elif out["changed"] is False:
                    out["note"] = ("维护前后内容一致：倾向于该地址在 RAM 里就是这些值，"
                                   "不是缓存陈旧造成的")
                elif not ci.get("ok"):
                    out["note"] = "维护动作未全部成功，上面的 before/after 仅供参照，别当成结论"
                return _js(out)
            return _js({"ok": False, "action": action, "error": "未知 action",
                        "available": ["status", "clean_invalidate"]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})

    @server.tool(
        name="reloc_check",
        title="校验/推导符号重定位偏移",
        description=(
            "校验 reloc_delta（App 运行期重定位偏移：**运行地址 = .axf 链接地址 + delta**）"
            "是否与实际布局相符，并可从当前 PC 反推正确偏移。"
            "**为什么必须有**：delta 跨编译会变，偏移错了不会报错，只会读到「全 0」——"
            "极易被误判成「变量被清零」，是真机上被静默带沟里的一种失败。"
            "做法一（verify）：从 .axf 可加载段挑若干**非退化**的字节块当内容指纹"
            "（全 0x00/全 0xFF 的块在哪儿都长得一样，不能当指纹），按「链接地址 + delta」"
            "到目标读回来逐字节比对，给出 verdict："
            "delta-confirmed（全中）/ delta-likely-wrong（一条都没中）/ "
            "delta-uncertain（部分中）/ unreadable（读不到）/ no-sample（没有可用指纹）。"
            "做法二（derive）：读当前 PC 处的代码字节，回到 .axf 里反查这段代码的链接地址，"
            "直接算出 delta；匹配到多处或一处都匹配不上时**如实说定不了，不猜**。"
            "delta 省略时用全局 set_reloc_delta 的值；elf 省略时用当前调试的 .axf。"
            "返回 confirmed 明确表示偏移是否**被证实**（注意 ok 只表示检查跑完了，"
            "这两件事分开，免得把「跑完了」读成「没问题」）。"
            "需目标暂停（运行中读内存会失败/错位）。"
        ),
    )
    async def reloc_check(delta: str = "", elf: str = "", samples: int = 8) -> str:
        try:
            client = _get_client()
            path = (elf or "").strip() or (_symbol_cfg.get("axf") or "")
            if not path or not os.path.isfile(path):
                return _js({"ok": False, "error_code": "elf-missing",
                            "error": "未找到可用于比对的 .axf：请传 elf= 指定，"
                                     "或先用 set_symbol_file 设置当前调试符号",
                            "elf": path or None})
            d, dnote = _eff_reloc_delta(delta)
            try:
                want = max(1, min(64, int(samples or 8)))
            except (TypeError, ValueError):
                want = 8
            ver = _reloc.verify(client, path, d, samples=want)
            out = {"ok": bool(ver.get("ok")), "elf": os.path.abspath(path),
                   "delta": "0x%X" % d, "delta_note": dnote,
                   "verify": ver, "confirmed": bool(ver.get("confirmed"))}
            der = _reloc.derive_from_pc(client, path)
            out["derive"] = der
            if ver.get("verdict") == "delta-confirmed":
                out["conclusion"] = ("reloc_delta=0x%X 与实际布局相符（%d 个内容指纹全部命中），"
                                     "可以放心按该偏移解读变量值" % (d, ver.get("samples")))
            elif ver.get("verdict") == "delta-likely-wrong":
                out["conclusion"] = ("reloc_delta=0x%X **与实际布局不符**（内容指纹一条都没对上）："
                                     "**不要**把读到的全 0 当成「变量被清零」"
                                     % d)
            elif ver.get("verdict") in ("unreadable", "no-sample"):
                out["conclusion"] = ("本次无法验证该偏移（%s）——请如实当作「未验证」，"
                                     "不要据此下任何结论" % ver.get("reason"))
            else:
                out["conclusion"] = ("偏移 %s 部分命中（%d/%d），既不能确认也不能否定"
                                     % (out["delta"], ver.get("matched"), ver.get("samples")))
            sd = der.get("delta_int") if isinstance(der, dict) else None
            if sd is not None and int(sd) != int(d):
                out["suggested_delta"] = der.get("delta")
                out["suggested_delta_int"] = int(sd)
                out["action"] = ("从当前 PC 反推出的偏移是 %s（与传入的 %s 不同）："
                                 "可 set_reloc_delta(%s) 设为全局，或本次调用传 "
                                 "reloc_delta=\"%s\""
                                 % (der.get("delta"), out["delta"], der.get("delta"),
                                    der.get("delta")))
            elif isinstance(der, dict) and der.get("reason"):
                out["derive_note"] = der.get("reason")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

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
        title="暂停执行（含停止确证）",
        description=(
            "暂停目标 MCU 的执行（进入断点/挂起状态），此时才可安全读内存/寄存器/表达式。"
            "**停止是异步生效的**：命令返回不代表目标已停（真机实测 stop 回 ok 后紧跟的 get_status 仍报\"执行中\"），"
            "这期间读到的内存/寄存器可能是脏值或陈旧值。本工具默认在 stop 之后轮询确认"
            "（verify=true），返回 stopped / stop_verified / waited_ms / state_after_stop："
            "**stop_verified=false 表示没能确证目标已停，此时不要读内存/寄存器、也不要据其下结论**，"
            "可重试 stop 或稍后再读（与 run_timeout 的 stop_verified 同一口径）。"
            "verify=false 则只发命令不做确认（快，但需自行承担读到脏值的风险）。"
            "**看门狗防御（真机踩过）**：暂停期间目标虽不跑代码，**看门狗（IWDG）仍在计数**——"
            "新会话/复位后 DBGMCU 冻结位会被清零，halt 超过溢出时间就被复位、RAM 现场全丢。"
            "本工具默认在 stop 后自动置位 DBGMCU 的 IWDG/WWDG 冻结位（freeze_watchdogs=true），"
            "返回 watchdog_freeze 字段供核对（含 all_frozen）；不需要可传 freeze_watchdogs=false。"
        ),
    )
    async def stop(verify: bool = True, timeout: float = 1.0,
                   freeze_watchdogs: bool = True) -> str:
        try:
            client = _get_client()
            out = dict(client.stop())
            if verify and out.get("ok"):
                ws = client.wait_until_stopped(timeout=timeout)
                stopped = bool(ws.get("stopped"))
                out["stopped"] = stopped
                out["stop_verified"] = stopped
                out["waited_ms"] = ws.get("waited_ms")
                out["state_after_stop"] = "stopped" if stopped else "running"
                if not stopped:
                    out["warning"] = (
                        "stop 命令已受理，但 %dms 内未确证目标已停止（%s）：此时读内存/寄存器会拿到脏值"
                        "或陈旧值，请重试 stop 或稍后再读。"
                        % (ws.get("waited_ms") or 0, ws.get("error") or "未知原因"))
            elif not out.get("ok"):
                out.setdefault("stop_verified", False)
            if freeze_watchdogs and out.get("ok"):
                out["watchdog_freeze"] = _auto_freeze_watchdogs(client)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="watchdog_freeze",
        title="看门狗调试冻结（IWDG/WWDG）",
        description=(
            "查询/置位 DBGMCU 的独立看门狗（IWDG）与窗口看门狗（WWDG）**调试冻结位**。"
            "**为什么需要它（真机踩过）**：目标 halt 期间 CPU 不执行喂狗代码，但看门狗仍在计数——"
            "新会话/目标复位后 DBGMCU 冻结位会被清零，此时停机超过溢出时间（典型 1.6~26s）"
            "就**被 IWDG 复位、RAM 现场全丢**，表现为「停下来看一会儿，变量就全变初值、断点也没了」。"
            "置位冻结位后 halt 期间看门狗停止计数，可长时间停留分析现场。"
            "action：status（查当前冻结状态）/ enable（置位，默认）/ disable（清除，恢复真实行为）。"
            "stop 与 enter_debug 默认会自动 enable，本工具用于手动复核或重试。"
            "返回值：dbgmcu_base/dev_id（运行时探测，不按内核硬编码）、apb1fz、"
            "iwdg_stopped/wwdg_stopped/all_frozen；未全部置起时带 warning 说明风险。"
            "适用 STM32（F1/F4/F7/H7 等）；非 STM32 或读取被挡会返回 error 与已尝试的基址。"
        ),
    )
    async def watchdog_freeze(action: str = "status") -> str:
        try:
            a = (action or "status").strip().lower()
            enable_set = ("enable", "on", "set", "true", "1", "freeze", "yes")
            disable_set = ("disable", "off", "clear", "false", "0", "unfreeze", "no")
            status_set = ("status", "get", "query", "read", "show", "")
            client = _get_client()
            if a not in enable_set and a not in disable_set and a not in status_set:
                return _js({"ok": False, "action": action,
                            "error": "action 取值非法：%s" % action,
                            "valid_actions": ["status", "enable", "disable"],
                            "hint": "status=查当前冻结状态；enable=置位（halt 期间冻结看门狗）；"
                                    "disable=清除（恢复看门狗真实行为）。"})
            if a in status_set:
                out = client.get_watchdog_freeze()
            else:
                out = client.set_watchdog_freeze(a in enable_set)
            if isinstance(out, dict) and not out.get("ok"):
                out = dict(out)
                out.setdefault("hint", (
                    "读取失败通常是「目标未进入调试 / 未暂停」或不是 STM32。"
                    "先 enter_debug 并 stop，再重试；非 STM32 目标请忽略本工具。"))
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": str(action), "error": str(e)})

    @server.tool(
        name="cache_info",
        title="目标 Cache 状态（D-Cache / I-Cache）",
        description=(
            "读 SCB->CCR 判定目标是否使能了 D-Cache / I-Cache（M7 有 D-Cache，M3/M4 没有，"
            "M7 默认也不开、需软件显式使能），并给出 D-Cache 容量的粗略信息。"
            "**为什么重要（真机反馈第17轮③）**：D-Cache 开着时，调试器（DAP）**直读 RAM 可能是陈旧值**"
            "（CPU 刚写的新值还在脏行里未回写），**直写 RAM 也可能被脏行回写覆盖**，两者都**不会报错**——"
            "于是「读到的 0」可能只是缓存没刷、「我写下去了」也可能稍后被覆盖。"
            "本工具把这些风险显式报出来；read_mem/write_mem 命中 SRAM 地址且 D-Cache 使能时，"
            "返回体里也会带 cache 字段提示同一件事（探测结果有 5 秒 TTL 缓存，不额外拖慢读写）。"
            "dcache=true 时请对内存结论留有余量：必要时先让目标做 SCB 缓存维护或复位后复读核对。"
        ),
    )
    async def cache_info() -> str:
        try:
            out = _get_client().get_cache_state()
            if isinstance(out, dict) and out.get("ok"):
                out = dict(out)
                out["impact"] = {
                    "read_mem": "SRAM 直读可能落后于 CPU 视角（脏行未回写）" if out.get("dcache")
                                else "SRAM 直读按内存真实状态生效",
                    "write_mem": "SRAM 直写可能被脏行回写覆盖（写入仍报成功）" if out.get("dcache")
                                 else "SRAM 直写按内存真实状态生效",
                }
            elif isinstance(out, dict):
                out = dict(out)
                out.setdefault("hint", "读取 SCB->CCR 失败：请先 enter_debug 并 stop 后重试。")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="reset",
        title="复位目标",
        description=(
            "复位目标 MCU（变量回到初值、断点保留）。"
            "**行为说明（真机实测，与旧描述不同）**：复位后目标**停在复位向量、处于停止态**，"
            "程序不会自行往下跑——必须再调 run（或 run_timeout / run_to_line）才会开始执行；"
            "实测复位后 get_status 返回\"已停止\"，正因为不 run 就没有任何串口输出。"
            "返回带 state_after_reset（stopped/running）与 stopped_after_reset 说明这一点；"
            "run_after=true 可在复位成功后自动 run（等价于复位后自己再调一次 run），"
            "适合「重新跑一遍看串口输出」的场景。"
        ),
    )
    async def reset(run_after: bool = False) -> str:
        try:
            client = _get_client()
            out = dict(client.reset())
            if out.get("ok"):
                ws = client.wait_until_stopped(timeout=0.6)
                stopped = bool(ws.get("stopped"))
                out["stopped_after_reset"] = stopped
                out["state_after_reset"] = "stopped" if stopped else "running"
                if run_after:
                    rr = dict(client.run())
                    out["ran"] = bool(rr.get("ok"))
                    if not rr.get("ok"):
                        out["run_error"] = rr.get("status_text") or rr.get("error")
                    out["hint"] = ("复位后已按 run_after=true 继续运行程序；"
                                   "需要停下来读内存/寄存器时调用 stop（会确证停止）。")
                elif stopped:
                    out["hint"] = ("复位后目标停在复位向量、处于停止态，程序不会自行运行；"
                                   "需要它跑起来请调用 run（或 run_timeout / run_to_line）。")
                else:
                    out["hint"] = ("复位后目标已在运行；若要读内存/寄存器，先 stop 并确认已停止"
                                   "（stop 会返回 stop_verified）。")
            return _js(out)
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
        """解析待操作工程：参数优先，其次服务配置的默认工程。

        没给工程或工程不存在时，把找到的候选一并写进报错——多候选不替调用方决定。
        """
        if _builder_cfg["uv4"] is None:
            raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定编译工具路径")
        p = project.strip()
        if p:
            if not os.path.isfile(p):
                cands = _find_project_candidates()
                raise RuntimeError(
                    "工程文件不存在：%s%s" % (
                        p,
                        ("；本机找到的候选工程：%s" % "、".join(cands)) if cands else
                        "（未在附近找到任何 .uvprojx）"))
            global _last_project
            _last_project = p      # 记下来，供惰性符号定位复用
            return p
        if _builder_cfg["default_project"]:
            dp = _builder_cfg["default_project"]
            if not os.path.isfile(dp):
                raise RuntimeError("默认工程已失效（文件不存在）：%s；请传入 project 参数" % dp)
            return dp
        cands = _find_project_candidates()
        raise RuntimeError(
            "未指定工程路径，请传入 project 参数或配置默认工程（--default-project）"
            + ("；本机找到的候选工程：%s" % "、".join(cands) if cands else ""))

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
            "**single（默认 true）＝「只保留一个 Keil 窗口」的执行者**：已经开着**别的工程**的"
            "窗口时直接拒绝（error_code=keil-multiple-instances，返回 open_instances 与下一步），"
            "不做「偷偷关掉再开」；已经开着**同工程**窗口时强制复用（reuse=false 也被否决，"
            "返回 reuse_forced=true）；本次没给 project 且已有实例同样拒绝（无从比对就不猜）。"
            "确实要同时开多个窗口才传 single=false。"
            "返回值含 reused / pid / instances（当前同工程窗口数）。"
            "用户无需手动打开 Keil，AI 可通过本工具拉起；想看当前开了几个窗口用 list_uvision_instances，"
            '想把多余的收掉用 close_uvision(keep="latest")。'
            "uvsock_port：传端口号则给这次启动加官方开关 `-s <端口>`，让**新实例**在该端口上开 UVSOCK——"
            "当用户的 Keil 里 UVSOCK 没打开/端口被改过时，光拉起 Keil 仍连不上，这个参数能一步到位"
            "（注意 MCP 服务自身的 UVSOCK 端口也要一致）。no_layout=true 加 `-sg` 禁用 uvguix 布局文件："
            "用户改过窗口布局、布局文件损坏导致 UV4 起得极慢或报错时用它绕开。"
        ),
    )
    async def launch_uvision(project: str = "", reuse: bool = True,
                             uvsock_port: int = 0, no_layout: bool = False,
                             single: bool = True) -> str:
        try:
            if _builder_cfg["uv4"] is None:
                raise RuntimeError("未定位到 UV4.exe，请用 --uv4-path 指定")
            p = _resolve_project(project)
            return _js(builder.launch_uvision(_builder_cfg["uv4"], p, reuse=bool(reuse),
                                              uvsock_port=(int(uvsock_port) or None),
                                              no_layout=bool(no_layout),
                                              single=bool(single)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="batch_debug_script",
        title="UV4 命令行批处理调试（-d + 初始化文件）",
        description=(
            "用 Keil 官方**命令行批处理**通道跑一段固定的调试脚本："
            "`UV4 -d <工程> -j0` 进调试并执行**初始化文件**里的命令序列。"
            "不依赖 UVSOCK（不需要 Keil 里开着 UVSOCK、也不怕连接被占/空闲断连），"
            "适合**可重复的冒烟/回归**（复位后采现场、跑几步看寄存器、抓一段打印），"
            "以及 UVSOCK 不可用时的降级通道。交互式排查请仍用 UVSOCK（enter_debug + keil_command）"
            "——那条通道可以中途改主意，本通道是「一条道跑到黑」。\n"
            "commands：命令清单（数组，或换行分隔的字符串），一行一条。常用的有 "
            "`g, main`（运行到 main）、`BS <符号>`（下断点）、`BL`、`G`（跑到断点）、`T`/`P`/`O`（单步）、"
            "`EVAL <表达式>`、`printf(\"%08X\", _RDWORD(0x20000000))`（无头读内存）。\n"
            "**四条真机实测的坑（工具已尽力兜住）**：\n"
            "1. **命令报错不改退出码**（UV4 恒回 0）：成败只认日志里的 `*** error N, line M`。"
            "本工具把退出码、逐条命令的 error、以及每条命令是否走到完成标记分开返回，"
            "ok 字段是综合判定结果。\n"
            "2. `Go main` / `Go` 会**挂死**（官方语法是 `g, main`，逗号不可省）；"
            "`DISPLAY`/`SAVE` 在 `-j0` 无头模式下也**挂死**。这两类写法会被静态检查提前告警，"
            "但仍请避开。\n"
            "3. 无窗口焦点时单步退化为**指令级**（`T` 会进函数逐条指令走）。\n"
            "4. 每轮 15~25s（含进调试 + Erase/Program/Verify），显著慢于 UVSOCK；timeout_s 默认 240。\n"
            "实现细节：初始化文件与 trace 日志写在系统临时目录（ASCII 路径，真机实测中文路径会 "
            "UnicodeEncodeError），并把路径写入 .uvoptx 的 `<tIfile>`；**前置备份、无论成败都还原**，"
            "不会把你的工程改脏。返回 artifacts 里给出 init_file / trace_log / workdir 现场路径，"
            "log_tail 是日志尾部。**高风险**：会真正进调试并下载程序（Erase/Program/Verify）。"
        ),
    )
    async def batch_debug_script(commands, project: str = "", timeout_s: int = 240,
                                 visible: bool = False) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) or 240
            r = await asyncio.to_thread(
                _cmdscript.run_debug_script, _builder_cfg["uv4"], p, commands,
                max(20, min(t, 1800)), bool(visible))
            _release_serial("UV4 -d 批处理调试（batch_debug_script）", r)
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e), "channel": "uv4-cmdline"})


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
            "返回退出码与编译日志。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。注意：UV4 -b 会新起独立隐藏进程，构建输出经 -o 捕获返回（不会显示在你已打开的 Keil 窗口）；退出码完整表见返回值 exit_code_text / exit_code_meaning：0/1=成功,2=有错误,3=致命错误,11=工程打不开,12=器件库缺失,13=写入错误,15=UV4 被占用,20=未知；失败时 next_actions 按码给出下一步，failure_bucket 给出归类桶。Keil 处于调试态时编译可能失败，建议先退出调试。"
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
            "clean_first（默认 false）：true 时改用 **UV4 -cr 先清理再重建**，比 -r 更彻底——-r 只是不做增量，仍可能复用未被判定为过期的产物；-cr 先删掉全部产物再重建，适合改了构建配置/预处理脚本（如 gen_scatter.py）后结果不对的场合。注意：UV4 -r/-cr 全量重编，同上——新起隐藏进程、输出经 -o 捕获；退出码语义同 build，完整码表见返回值 exit_code_text / exit_code_meaning（11=工程打不开、12=器件库缺失、13=写入错误、15=UV4 被占用），失败时 next_actions 直接给下一步。Keil 处于调试态时编译可能失败。ensure_debug_channel（默认 true）：执行前先取调试通道健康快照，若编译后 4823 由可用变不可用（UV4 命令行把 GUI 实例一起带走），会自动拉起 Keil 并重建 UVSOCK 连接，返回值含 keil_before / keil_after / keil_recovered / keil_note，无需再手工 restart_keil；设为 false 可关闭。"
        ),
    )
    async def rebuild_project(project: str = "", target: str = "",
                              timeout_s: int = 0,
                              ensure_debug_channel: bool = True,
                              clean_first: bool = False) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_BUILD_TIMEOUT
            return _js(builder.rebuild_project(_builder_cfg["uv4"], p, target.strip() or None, t,
                                               ensure_debug_channel=ensure_debug_channel,
                                               clean_first=bool(clean_first)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="clean_project",
        title="清理构建产物（UV4 -c）",
        description=(
            "清理 Keil 工程的构建产物（UV4 -c，等价于 Keil 菜单的 Clean Targets）：删掉该 target 的中间文件"
            "与产物（.o/.axf/.hex 等）。project 可省略用默认工程；target 可选。"
            "**有副作用**：清理后**必须重新编译**才有可下载的镜像，否则烧录/调试会拿不到产物（返回值里的 note 会提醒）。"
            "什么时候需要它：怀疑增量构建残留导致行为诡异（改了预处理脚本如 gen_scatter.py、改了构建配置、"
            "产物时间戳比源码新）——此时 rebuild_project 的 -r 可能仍复用未被判定过期的产物，"
            "用本工具（或 rebuild_project(clean_first=true) 的 -cr）先清干净再编。"
            "配套 read_project_config 可先确认 target 名；返回值含 exit_code_text / exit_code_meaning / "
            "next_actions（失败时按 UV4 退出码给下一步，如 15=UV4 被占用、11=工程打不开、13=写入错误）。"
        ),
    )
    async def clean_project(project: str = "", target: str = "",
                            timeout_s: int = 0,
                            ensure_debug_channel: bool = True) -> str:
        try:
            p = _resolve_project(project)
            t = int(timeout_s or 0) if int(timeout_s or 0) > 0 else builder.DEFAULT_CLEAN_TIMEOUT
            return _js(builder.clean_project(_builder_cfg["uv4"], p, target.strip() or None, t,
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
            if out.get("ok", True):
                # 烧录＝符号漂移的源头：顺手把符号钉到刚烧的 .axf（显式选择优先，见
                # _rebind_symbol_to_flashed），比事后反复提醒「符号可能不同源」省事。
                fw = _record_flashed_firmware(p, target.strip() or "", "flash_download")
                if fw.get("symbol_rebind"):
                    out["symbol_rebind"] = fw["symbol_rebind"]
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
            if out.get("ok", True):
                fw = _record_flashed_firmware(p, target.strip() or "", "build_and_flash")
                if fw.get("symbol_rebind"):
                    out["symbol_rebind"] = fw["symbol_rebind"]
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
                stg = "编译" if auto_dl else "编译烧录"
                err = (bf.get("error") or (bf.get("build") or {}).get("error")
                       or (bf.get("flash") or {}).get("error")
                       or bf.get("status_text") or ("%s未通过" % stg))
                return _js({
                    "ok": False, "action": "flash_debug",
                    "stage": stg,
                    "flash_plan": flash_plan,
                    "close_uvision": close, "build_flash": bf,
                    "serial_release": serial_release,
                    # 与成功/进调试失败两条路径一致：顶层直接给原因与错误码，
                    # 不让调用方去 build_flash 子字段里翻（真机实测踩到）
                    "error": err,
                    "error_code": _errors.classify_error(err),
                    "status_text": "%s未通过，未重开工程进入调试" % stg,
                })
            # 3) 重新打开本工程（干净实例，加载新固件符号）
            launch = builder.launch_uvision(uv4, p)
            if not launch.get("ok"):
                # single 守卫/启动失败时别再硬着头皮 enter_debug：那只会得到一条含混的
                # 连接错误。把「重开被拒」这一真实原因与既有窗口清单直接提到顶层。
                return _js({
                    "ok": False, "action": "flash_debug", "stage": "重开工程",
                    "close_uvision": close, "flash_plan": flash_plan,
                    "serial_release": serial_release, "build_flash": bf,
                    "launch_uvision": launch,
                    "error": launch.get("error") or "重新打开工程失败",
                    "error_code": launch.get("error_code") or "keil-launch-failed",
                    "next_actions": launch.get("next_actions"),
                    "status_text": "新固件已上板，但重新打开工程未成功（未进调试）",
                })
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
            symbol_rebind = None
            if enter.get("ok"):
                _note_firmware_event("flash_debug")
                _mark_debug_session("flash_debug")   # 新会话＝新固件符号，重新记基线
                symbol_rebind = _record_flashed_firmware(p, "", "flash_debug").get("symbol_rebind")
            payload = {
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
                # 烧录/自动下载后符号有没有重钉到新固件（kept-explicit＝你显式选过，没覆盖）
                "symbol_rebind": symbol_rebind,
                "launch_uvision": launch, "enter_debug": enter,
                # 披露窗口处置：复用还是新开、新实例 pid 是多少——调用方据此判断要不要收敛窗口
                "launch_reused": bool(launch.get("reused")) if isinstance(launch, dict) else None,
                "launch_pid": launch.get("pid") if isinstance(launch, dict) else None,
                "uvision_instances": launch.get("instances") if isinstance(launch, dict) else None,
                "status_text": ("已重新打开工程并进入调试" if enter.get("ok")
                                else "已重新打开工程，但进入调试失败，请检查 UVSOCK 是否开启"),
            }
            if not enter.get("ok"):
                # 失败原因原本只写在 enter_debug 子字段里，顶层只有一个 ok=false → 调用方
                # 无法直接知道为什么失败、下一步做什么（真机实测踩到）。这里把原因提到顶层，
                # 并按统一错误码字典给可执行的下一步。
                err = (enter.get("error") or enter.get("last_error")
                       or "已重新打开工程，但进入调试失败（UVSOCK 未就绪或目标无响应）")
                payload["error"] = err
                payload["error_code"] = _errors.classify_error(err)
                acts = [a for a in _errors.code_actions("flash_debug", payload["error_code"])]
                acts.append("新固件已编译完成，修好调试通道后直接 enter_debug 即可，不必重复编译烧录")
                payload["next_actions"] = acts
            return _js(payload)
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
        out = {"ok": True, "count": len(_periph_list()), "peripherals": _periph_list(),
               "builtin_regmap_series": _BUILTIN_REG_SERIES}
        # 能读到芯片就说实话：内置表只对 STM32F4 的布局负责。读不到就静默带过
        # （本工具常用于没进调试时先看清单，不该因此变成失败）。
        try:
            g = _periph_device_guard(_get_client(), _BUILTIN_REG_SERIES)
            if g.get("verdict") not in (None, "matched"):
                out["device_guard"] = g
                out["warning"] = ("内置寄存器表是 %s 的布局；本次实测/比对结果见 device_guard，"
                                  "对不上时请改用 svd_list/svd_decode（按真实器件加载 .svd）。"
                                  % _BUILTIN_REG_SERIES)
        except Exception:  # noqa: BLE001
            pass
        return _js(out)

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
                              fields: str | list = "auto",
                              allow_mismatch: bool = False) -> str:
        try:
            client = _get_client()
            p = _periph_get(periph)
            if not p:
                avail = ", ".join(x["name"] for x in _periph_list())
                return _js({"ok": False, "error": f"未知外设 {periph}，可用: {avail}"})
            # 批次49：内置表是 STM32F4 的硬编码布局；实测芯片不是 F4 时必须拒绝——
            # 否则会给出「看着像样却完全是别的芯片布局」的读数（真机：H743 上返回
            # F4 的 RCC base 0x40023800、读出 0xAAAAAAAA）。
            guard = _periph_device_guard(client, _BUILTIN_REG_SERIES,
                                         allow_mismatch=allow_mismatch,
                                         what="读外设寄存器")
            if not guard.get("allowed", True):
                out = dict(guard)
                out["peripheral"] = p["name"]
                out["builtin_regmap_series"] = _BUILTIN_REG_SERIES
                return _js(out)
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
            if guard.get("verdict") != "matched":
                out["device_guard"] = guard
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
            "避免把外设区当 RAM 读或把越界地址当合法地址。addr 为空返回全部区域。"
            "**这张表是内置的 STM32F4 布局**：能读到目标时会先核对实际芯片系列，"
            "不是 F4 就拒绝返回（否则会拿 F4 的地址范围去解释 H7 的地址，看着像样却完全错）；"
            "读不到目标（未进调试）时按纯查表返回，并在返回值里注明这是未核对的布局。"
            "确需在别的系列上强查，传 allow_mismatch=true。"
        ),
    )
    async def query_memory_map(addr: str | int = "", allow_mismatch: bool = False) -> str:
        addr = _addr_arg(addr)
        try:
            a = _parse_addr(addr) if addr else None
            out = _query_memory_map(a)
            # 批次49：内置内存地图与内置外设表一样是**写死的 STM32F4 布局**，
            # 只在 description 里写「请勿套用」等于把核对责任推给调用者，必须自己核对。
            guard = None
            try:
                guard = _periph_device_guard(_get_client(), _BUILTIN_REG_SERIES,
                                             allow_mismatch=allow_mismatch,
                                             what="按内置 STM32F4 布局解读内存地图")
            except Exception:  # noqa: BLE001
                guard = None
            if guard and not guard.get("allowed", True):
                return _js(guard)
            out["builtin_regmap_series"] = _BUILTIN_REG_SERIES
            if guard and guard.get("verdict") != "matched":
                out["device_guard"] = guard
            return _js(out)
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
                return _js({"ok": False, "error_code": "invalid-argument",
                            "error": f"无法解析函数入口地址: {f}"})
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
                return _js({"ok": False, "error_code": "function-not-reached",
                            "function": f, "entry": hex(addr),
                            "error": f"运行 {max_ms}ms 未到达函数入口（函数可能未被调用）"})
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
            # 诊断号：AC5 形如 `#20: identifier ...`；AC6 多数无号，但带号时同义。
            # 之前只保留消息文本，把 `#20` 丢掉，AI 无法据此查手册/复用诊断经验。
            ac6 = re.findall(r'^(.+?\.(?:c|h|cpp|s|S)):(\d+):(\d+):\s*(error|warning|note):\s*(.+)$',
                             text, re.M)
            # ARMCC5 (AC5): path\file.c(12): error:  message
            ac5 = re.findall(r'^(.+?\.(?:c|h|cpp|s|S))\((\d+)\):\s*(error|warning):\s*(.+)$',
                             text, re.M)
            code_re = re.compile(r'#(\d+)\s*:')
            items = []
            for m in ac6:
                file, line, col, lvl, msg = m
                resolved = loc.resolve_source_path(file) if loc else file
                msg = msg.strip()
                cm = code_re.search(msg)
                items.append({"file": resolved, "line": int(line), "column": int(col),
                              "level": lvl, "message": msg,
                              "error_code": (int(cm.group(1)) if cm else None),
                              "compiler": "AC6", "format": "file:line:col"})
            for m in ac5:
                file, line, lvl, msg = m
                resolved = loc.resolve_source_path(file) if loc else file
                msg = msg.strip()
                cm = code_re.search(msg)
                items.append({"file": resolved, "line": int(line), "column": None,
                              "level": lvl, "message": msg,
                              "error_code": (int(cm.group(1)) if cm else None),
                              "compiler": "AC5", "format": "file(line)"})
            errors = [x for x in items if x["level"] == "error"]
            warnings = [x for x in items if x["level"] == "warning"]
            # 去重后的诊断号列表：AI 可直接拿去 explain_build_error 批量解读
            codes = sorted({x["error_code"] for x in items if x["error_code"] is not None})
            return _js({"ok": True, "count": len(items),
                        "error_count": len(errors), "warning_count": len(warnings),
                        "error_codes": codes,
                        "items": items,
                        "hint": ("把任意一条 item 的 message（或 error_code）交给 "
                                 "explain_build_error 可拿到含义/常见原因/处置清单") if items else None})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="explain_build_error",
        title="解读编译错误 / Keil 命令报错",
        description=(
            "把一条编译诊断或 Keil 命令报错翻译成 人话：含义 + 常见原因 + **可执行的处置清单**。\n"
            "两种输入：\n"
            "- **编译诊断**：传行文本如 `main.c(120): error:  #20: identifier \"x\" is undefined`，"
            "给 build_project/rebuild_project/parse_build_errors 返回里的任意一条 message 即可；"
            "也可只传 `code=20`。匹配策略是**文本特征优先**（AC5/AC6 措辞都认），码号兜底。\n"
            "- **命令报错**：传 `*** error 57: illegal address (0x08000DB5)` 这类文本，"
            "或 `code=57`。码表条目**全部来自真机实测**（57 非法地址/Thumb 位、65 断点超限、"
            "72 需按编号清断点、145 断点已存在可忽略、34 未定义标识符）。\n"
            "**未收录的码不做猜测**：会明确回 confidence=unknown 并给通用排查路径，"
            "避免编造一个看起来合理的错因把排查带偏。kind 可显式指定 build/command，"
            "留空则自动判别（含 `*** error` 视为命令报错）。"
        ),
    )
    async def explain_build_error(text: str = "", code: str = "",
                                  kind: str = "") -> str:
        try:
            k = (kind or "").strip().lower()
            text = text or ""
            num = None
            if str(code or "").strip():
                try:
                    num = int(str(code).strip(), 0)
                except ValueError:
                    return _js({"ok": False, "error": "code 必须是数字（如 20 或 0x14）",
                                "code": code})
            if not k:
                if "*** error" in text.lower() or "error " in text.lower()[:12]:
                    k = "command"
                else:
                    k = "build"
            r = (_keilkb.explain_command_error(text, num) if k == "command"
                 else _keilkb.explain_build_error(text, num))
            r["kind"] = k
            if k == "command":
                r["known_codes"] = _keilkb.known_debug_codes()
            return _js(r)
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
    async def write_peripheral(periph: str, reg: str, value: str,
                               allow_mismatch: bool = False) -> str:
        try:
            client = _get_client()
            p = _periph_get(periph)
            if not p:
                avail = ", ".join(x["name"] for x in _periph_list())
                return _js({"ok": False, "error": f"未知外设 {periph}，可用: {avail}"})
            # 批次49：写错布局的外设寄存器比读更危险（可能改变系统行为）。
            guard = _periph_device_guard(client, _BUILTIN_REG_SERIES,
                                         allow_mismatch=allow_mismatch,
                                         what="写外设寄存器")
            if not guard.get("allowed", True):
                out = dict(guard)
                out["peripheral"] = p["name"]
                out["builtin_regmap_series"] = _BUILTIN_REG_SERIES
                return _js(out)
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
                    # 批次34：batch 的既有承诺是「与单工具直调完全等价」，故这里也把
                    # 三个输出控制参数摘出来，作用到该条子结果上（否则它们会以「未知参数」被拒）。
                    args, _sub_out = _outctl.split_args(args)
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
                        if _sub_out:
                            data, _m = _outctl.apply(tool, data, **_sub_out)
                            if isinstance(_m, dict):
                                one["output"] = _m
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
        name="serial_list_ports",
        title="列出本机串口（含芯片推断）",
        description=(
            "列出本机当前可用的串口，**不只是 COM 号**：每个口附设备描述、硬件 ID(VID/PID) "
            "与 likely_chip 芯片推断（CH340 / CP2102 / FT232R / STM32 VCP / DAPLink VCP / 蓝牙虚拟口…），"
            "让选口有依据，而不是靠试。"
            "选口规则（吸收 embeddedskills / Serial-Agent 的 playbook 第一条）：**只有一个候选才自动采用**"
            "（auto_select 字段给出），多个候选一律不替调用方决定——返回 candidates 让你按 likely_chip 显式指定。"
            "返回 {ok, count, ports:[{port, description, hwid, vid, pid, likely_chip, source}], "
            "candidates, auto_select, need_choice, selection_rule, monitoring, current_port}。"
            "典型用法：serial_monitor_start 之前先调它确认 COM 号；日志收不到时也先调它确认口没写错。"
            "detail=false 只返回端口名（更快）。本工具是只读的，不会占用端口。"
        ),
    )
    async def serial_list_ports(detail: bool = True) -> str:
        try:
            if detail:
                ports = serialmon.list_ports_detailed()
            else:
                ports = [{"port": p} for p in serialmon.list_ports()]
            pick = serialmon.pick_port(ports=ports)
            out = {"ok": True, "count": len(ports), "ports": ports,
                   "candidates": [p.get("port") for p in ports],
                   "auto_select": pick.get("port") or None,
                   "need_choice": bool(pick.get("need_choice")),
                   "selection_rule": pick.get("reason")}
            m = serialmon.current()
            out["monitoring"] = m is not None
            if m is not None:
                out["current_port"] = m.port
            if not ports:
                out["hint"] = ("本机未发现任何串口：确认 USB-TTL 已插好、驱动已装"
                               "（设备管理器能看到端口）后再试")
            elif pick.get("need_choice"):
                out["hint"] = ("有 %d 个候选串口，未自动选择——请按 likely_chip 判断哪个是目标板的日志口，"
                               "再把 port 显式传给 serial_monitor_start" % len(ports))
            elif pick.get("port"):
                out["hint"] = ("唯一候选 %s，可直接 serial_monitor_start(port=\"%s\")"
                               % (pick["port"], pick["port"]))
            if m is not None and pick.get("port") and pick["port"] != m.port:
                out["port_conflict_note"] = ("当前监听的是 %s，与本次枚举的首选候选 %s 不同——"
                                             "同一进程只监听一个口，切换需重新 start。"
                                             % (m.port, pick["port"]))
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

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
            "**本监听同时支持下发**（serial_write）：端口打开时优先按「可读可写」取得，"
            "因此可以一边收日志一边发 shell 命令/镜像片段；拿不到写权限时会退回只读，"
            "状态里的 can_write=false 表示当前这个口发不出去。"
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
            _auto_port = None
            if not p:
                if not ports:
                    return _js({"ok": False, "error": "本机未发现任何串口",
                                "available_ports": []})
                p = ports[0]
                # 保持既有的「省略 port 就用第一个」行为（不打断已有调用），
                # 但多候选时**明示这是自动选的**并列出其余候选——否则「选错口」
                # 会变成一个只能靠猜的问题（吸收 embeddedskills 的多候选规则）。
                if len(ports) > 1:
                    _auto_port = {
                        "port_auto_selected": True,
                        "port_candidates": ports,
                        "port_choice_hint": (
                            "本机有 %d 个串口，未指定 port 时自动采用了 %s；"
                            "若目标板日志口不是它，请带 port=... 重调本工具"
                            "（serial_list_ports 可看各口的芯片推断）。" % (len(ports), p)),
                    }
            st = dict(serialmon.start_monitor(
                p, baud=baud, databits=databits, parity=parity, stopbits=stopbits,
                capacity=capacity, encoding=encoding, label=label, restart=restart,
                idle_release_s=idle_release_s))
            if _auto_port:
                st.update(_auto_port)
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
        name="serial_write",
        title="向串口下发数据（一边收一边发）",
        description=(
            "向 serial_monitor_start 已打开的串口**下发数据**，收与发共用同一个句柄——"
            "这是「一边收一边发」的用法：下发 shell/msh 命令并立刻看回显、给 bootloader 发命令、"
            "分段下发镜像/升级数据。"
            "参数：text（文本，按 encoding 编码，默认 utf-8）与 hex（十六进制串，如 '7e 01 00 ff'，"
            "自动去空格/逗号/横线）**二选一**；eol 控制文本末尾追加的行尾，"
            "**可用取值：'crlf'（默认=\\r\\n）/ 'lf'（=\\n）/ 'cr'（=\\r）/ 'none'（不追加）/ "
            "'auto'（先 crlf，若目标毫无回显则补发单个 \\r，兼容 SVCrtOS shell、RT-Thread msh 这类只需 \\r 的口）**，"
            "也可直接传转义写法 \"\\r\" / \"\\n\"（两种写法等价）；"
            "无法识别的取值会**明确返回 warning + eol_hint**，不会静默不发行尾；wait_ms（默认 300）为写完等待多久再取新行；"
            "read_after=true（默认）时**把这次下发之后新增的日志行一起返回**（按写前 next_seq 增量取，"
            "不会重复老日志），省掉再调一次 serial_read。"
            "返回 {ok, written, bytes_sent, sent_hex, sent_bytes, eol_input, eol_applied, eol_bytes_hex, "
            "port, next_seq_before, read_after:{count, lines, bytes_new, next_seq, note}}；"
            "**sent_hex 是本次真正发出去的完整字节（含行尾）**，eol_applied 是归一后的行尾名——"
            "若行尾没发出去，eol_applied 会是 null 并附 warning，不再出现「看着 ok 其实换行没发」；"
            "文本下发后目标**毫无回显**时会附 no_echo_hint（提示改 'cr'/'auto' 或走 hex）；"
            "next_seq 可直接作为下次 serial_read 的 since。"
            "**依赖监听持有端口**：没有监听时 ok=false 并提示先 serial_monitor_start；"
            "端口只读到（can_write=false）、已被拔出/关闭、或正在重连时，ok=false 并给出 last_error，"
            "不会静默丢数据。注意：本工具只回报「写了多少字节」，命令是否被目标接受要看回显"
            "（read_after.lines）——wait_ms 内没等到新行不代表下发失败。"
        ),
    )
    async def serial_write(text: str = "", hex: str = "", eol: str = "crlf",
                           encoding: str = "utf-8", wait_ms: int = 300,
                           read_after: bool = True, max_items: int = 200) -> str:
        try:
            raw = b""
            hex_s = _csv_tokens(hex)
            if hex_s:
                try:
                    raw = bytes.fromhex("".join(hex_s).replace("0x", "").replace("0X", ""))
                except ValueError as e:
                    return _js({"ok": False,
                                "error": "hex 解析失败（应为偶数长度的十六进制字节串）：%s" % e})
            eol_raw = "" if eol is None else str(eol)
            auto = (eol_raw.replace("\r", "\\r").replace("\n", "\\n")
                    .strip().lower() == "auto")
            eol_name, eol_bytes, eol_warn = _norm_eol("crlf" if auto else eol)
            if text:
                try:
                    raw += text.encode(encoding or "utf-8")
                except Exception as e:  # noqa: BLE001
                    return _js({"ok": False,
                                "error": "text 编码失败（encoding=%s）：%s" % (encoding, e)})
                raw += eol_bytes
            if not raw:
                return _js({"ok": False,
                            "error": "参数不足：text（文本）与 hex（十六进制串）至少给一个（都不为空）"})
            out = dict(serialmon.write_bytes(raw, wait_ms=wait_ms,
                                             max_items=max_items, read_after=True))
            # 口径与 write_mem 的 verified/readback_hex 对齐：把「到底发出去了什么字节」摊开
            out["eol_input"] = eol_raw
            out["eol_applied"] = eol_name
            out["eol_bytes_hex"] = eol_bytes.hex()
            out["sent_hex"] = raw.hex()
            out["sent_bytes"] = len(raw)
            if eol_warn:
                out["eol_unrecognized"] = True
                out["warning"] = eol_warn
                out["eol_hint"] = _EOL_HELP
            elif not text and eol_bytes and hex_s:
                out["note"] = ("eol 只对 text 生效：本次只给了 hex，未追加行尾；"
                               "需要行尾请把它写进 hex（如 '...0d0a'）。")
            if auto and out.get("ok"):
                ra = out.get("read_after") or {}
                no_echo = (not int(ra.get("count") or 0)
                           and not int(ra.get("bytes_new") or 0))
                if no_echo:
                    r2 = serialmon.write_bytes(b"\r", wait_ms=wait_ms,
                                               max_items=max_items, read_after=True)
                    ra2 = r2.get("read_after") or {}
                    merged = dict(ra)
                    merged["count"] = int(ra.get("count") or 0) + int(ra2.get("count") or 0)
                    merged["items"] = (ra.get("items") or []) + (ra2.get("items") or [])
                    merged["lines"] = (ra.get("lines") or []) + (ra2.get("lines") or [])
                    merged["bytes_new"] = int(ra.get("bytes_new") or 0) + int(ra2.get("bytes_new") or 0)
                    if ra2.get("next_seq") is not None:
                        merged["next_seq"] = ra2.get("next_seq")
                    merged.pop("note", None)
                    out["read_after"] = merged
                    out["eol_fallback"] = "cr"
                    out["eol_bytes_hex"] = (eol_bytes + b"\r").hex()
                    out["sent_hex"] = (raw + b"\r").hex()
                    out["sent_bytes"] = len(raw) + 1
                    out["note"] = ("eol=auto：crlf 下发后 %dms 内目标没有任何回显，"
                                   "已补发单个 CR（多数只需 \\r 的 shell，如 SVCrtOS shell / "
                                   "RT-Thread msh，据此即可执行）——两次下发见 sent_hex。"
                                   % int(wait_ms))
            if text and not auto and out.get("ok"):
                ra = out.get("read_after") or {}
                if not int(ra.get("count") or 0) and not int(ra.get("bytes_new") or 0):
                    out["no_echo_hint"] = (
                        "目标在 %dms 内没有任何回显：若该 shell 只认单 \\r"
                        "（SVCrtOS shell / RT-Thread msh），把 eol 改成 'cr' 或 'auto' 再试；"
                        "需要精确控字节时用 eol='none' 配合 hex。%s" % (int(wait_ms), _EOL_HELP))
            if read_after is False:
                out.pop("read_after", None)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e),
                        "available_ports": serialmon.list_ports()})

    @server.tool(
        name="serial_expect",
        title="下发并等待串口出现指定内容（原子 send+wait）",
        description=(
            "**请求-响应式串口交互的首选工具**（吸收 Serial-Agent 的 send_and_wait）：可以先下发一段数据，"
            "再等到目标回显中出现匹配 pattern 的内容为止，一次调用拿全「发了什么 + 等到了什么」；"
            "也可以只等不发（配合之前 serial_write 下发的命令）。"
            "**只认本次等待期间新出现的内容**（与 wait_breakpoint 同一口径）：省略 since 时以调用瞬间为基线，"
            "缓冲区里的老日志不会被当成命中——避免「目标早就在刷这句话」被误判成这次请求的响应；"
            "确实要看老内容时传 since=0（或上一条日志的 next_seq）。"
            "include_partial（默认 true）把「还没等到换行的半行」也纳入匹配：**rt_kprintf 这类输出常常不带 \\n**，"
            "只匹配整行会永远等不到，命中时 matched_source=\"partial\" 说明命中的是半行。"
            "参数：pattern 要等待的内容（默认按正则；regex=false 则按字面文本匹配，不用转义 [ ] ( ) 等）；"
            "timeout_s 默认 5；case_sensitive 默认 true；poll_ms 轮询间隔默认 50。"
            "可选下发：send（文本，按 encoding 编码）或 hex（十六进制串）二选一，eol 语义与 serial_write 完全一致"
            "（crlf 默认 / lf / cr / none / auto）；不下发就只等。"
            "返回 {ok, matched, matched_text, matched_group, matched_source, matched_line, waited_ms, "
            "new_lines, lines, bytes_new, next_seq, partial, sent_hex, sent_bytes}。"
            "**未命中不会静默**：note 会区分「一个字节都没新增」（多半是请求没被目标接受/波特率不对）与"
            "「有新增但不匹配」（放宽 pattern 或加大超时），并原样给出已收到的行作为线索。"
            "依赖监听持有端口（收与发同一个句柄）：没有监听时 ok=false 并提示先 serial_monitor_start。"
        ),
    )
    async def serial_expect(pattern: str = "", timeout_s: float = 5.0, since: int = -1,
                            regex: bool = True, case_sensitive: bool = True,
                            poll_ms: int = 50, max_lines: int = 200,
                            include_partial: bool = True,
                            send: str = "", hex: str = "", eol: str = "crlf",
                            encoding: str = "utf-8") -> str:
        try:
            raw = b""
            hex_s = _csv_tokens(hex)
            if hex_s:
                try:
                    raw = bytes.fromhex("".join(hex_s).replace("0x", "").replace("0X", ""))
                except ValueError as e:
                    return _js({"ok": False, "matched": False,
                                "error": "hex 解析失败（应为偶数长度的十六进制字节串）：%s" % e})
            eol_name = eol_bytes = None
            eol_warn = ""
            if send:
                eol_name, eol_bytes, eol_warn = _norm_eol(eol)
                try:
                    raw += str(send).encode(encoding or "utf-8")
                except Exception as e:  # noqa: BLE001
                    return _js({"ok": False, "matched": False,
                                "error": "send 编码失败（encoding=%s）：%s" % (encoding, e)})
                raw += eol_bytes
            base = int(since) if since is not None and int(since) >= 0 else None
            sent = None
            if raw:
                w = dict(serialmon.write_bytes(raw, wait_ms=0, max_items=1, read_after=False))
                if not w.get("ok"):
                    w.setdefault("matched", False)
                    return _js(w)
                if base is None:
                    base = w.get("next_seq_before")
                # 只发 hex 不带 send 时没有行尾可归一（eol_bytes 为 None）：
                # 显式写 null/空串，别让 hex-only 下发在 .hex() 上崩掉。
                sent = {"sent_hex": raw.hex(), "sent_bytes": len(raw),
                        "eol_input": ("" if eol is None else str(eol)),
                        "eol_applied": eol_name,
                        "eol_bytes_hex": (eol_bytes.hex() if eol_bytes else "")}
                if not send:
                    sent["eol_note"] = ("本次按 hex 原样下发，未追加行尾"
                                       "（eol 仅在 send 文本时生效）")
                if eol_warn:
                    sent["eol_unrecognized"] = True
                    sent["warning"] = eol_warn
                    sent["eol_hint"] = _EOL_HELP
            out = dict(serialmon.expect(
                pattern, timeout_s=float(timeout_s or 0), since=base,
                regex=bool(regex), case_sensitive=bool(case_sensitive),
                poll_ms=int(poll_ms or 50), max_lines=int(max_lines or 200),
                include_partial=bool(include_partial), encoding=encoding))
            if sent:
                out.update(sent)
                out["sent"] = True
            else:
                out["sent"] = False
            if out.get("ok") and not raw:
                out.setdefault("note", "")
                out["note"] = ("命中的是等待期间新出现的内容（未下发数据，纯等待）。"
                               + str(out.get("note") or ""))
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "matched": False, "error": str(e),
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

    # ---------------- Modbus 串口支持（规范 RTU/ASCII + 非规范裸帧，批次44） ----------------
    # 用户反馈：「在添加串口规范modbus支持与不规范modbus支持」。
    # 串口上跑的除了日志还有 Modbus：serialmon 按行切分日志，二进制帧接不了
    # （\x00 被当字符、无换行、多从站应答混在一起）。这里补协议层，
    # 端口复用 serialmon 的 HostSerial，保证两个功能不会各自定义一套 Windows 串口代码。
    def _modbus_merge(req, res, keep_frames=False):
        """把请求摘要与 transact 结果合成工具返回值（统一字段顺序，便于人读）。"""
        out = {"ok": bool(res.get("ok")), "request": req.get("summary"),
               "request_hex": res.get("request_hex"),
               "slave": req.get("slave"), "func": req.get("func"),
               "func_name": req.get("func_name"), "mode": req.get("mode"),
               "port": res.get("port"), "elapsed_ms": res.get("elapsed_ms"),
               "response_hex": res.get("response_hex"),
               "sent_bytes": res.get("sent_bytes")}
        for k in ("error", "error_code", "hint", "no_response", "response",
                  "response_parsed", "parsed_ok", "parse_error", "frame_count",
                  "discarded_before_tx", "multi_frame_note", "silence_terminated",
                  "inter_frame_gap_ms"):
            if k in res:
                out[k] = res[k]
        if keep_frames or (res.get("frame_count") or 0) > 1:
            out["frames"] = res.get("frames")
        if req.get("is_write"):
            out["is_write"] = True
        return {k: v for k, v in out.items() if v is not None}

    async def _modbus_ready(port, baud, databits, parity, stopbits, mode, timeout_ms,
                            serial_format=""):
        """公共前置：按参数打开/复用 Modbus 会话。返回 (session, err)。"""
        try:
            r = _modbus.ensure(port=port, baud=baud, databits=databits, parity=parity,
                               stopbits=stopbits, mode=mode,
                               timeout_s=max(0.02, float(timeout_ms or 1000) / 1000.0),
                               serial_format=serial_format)
        except ValueError as e:
            return None, {"ok": False, "error": str(e), "error_code": "invalid-argument"}
        except Exception as e:  # noqa: BLE001
            return None, {"ok": False, "error": str(e)}
        if not r.get("ok"):
            return None, r
        return r["session"], None

    async def _modbus_readback(sess, slave, addr, count, kind, timeout_s):
        """写后回读：按功能码取「读」的对应物（线圈→01，寄存器→03）。"""
        f = 0x01 if kind == "coil" else 0x03
        try:
            req = _modbus.make_request(sess.mode, slave, f, addr=addr, count=count)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        res = sess.transact(req["request"], timeout_s=timeout_s,
                            expected_len=req["expected_len"])
        out = {"request": req["summary"], "response_hex": res.get("response_hex")}
        if not res.get("ok"):
            out.update(ok=False, error=res.get("error"), error_code=res.get("error_code"))
            return out
        dec = (res.get("response") or {})
        if kind == "coil":
            out["read_back"] = dec.get("bits", [])[:count]
        else:
            out["read_back"] = dec.get("registers", [])[:count]
        out["ok"] = True
        return out

    @server.tool(
        name="modbus_read",
        title="Modbus 读（规范功能码 01/02/03/04）",
        description=(
            "按 Modbus 规范读从站：**01 读线圈 / 02 读离散输入 / 03 读保持寄存器 / 04 读输入寄存器**，"
            "RTU(CRC16) 与 ASCII(LRC) 两种模式都支持。返回解码后的值（bits / registers + 有符号视图）"
            "与**原始收发帧**（request_hex / response_hex），便于核对时序与波形。"
            "从站返回异常帧时不会假装成功：is_exception + 异常码会译成中文原因（如 0x02 地址越界）。"
            "串口参数：port（如 \"COM9\"）+ baud（Modbus 常见 9600/19200）+ serial_format 简写"
            "（\"8N1\"/\"8E1\"/\"8O1\"/\"8N2\"，给了它就不用单独填 databits/parity/stopbits）。"
            "**重要：首次调用必须给 port** 才会开端口；之后同一会话可省略 port/baud 直接复用。"
            "端口是独占资源：若 serial_monitor_start 正监听同一个口，本工具会明确报错并让你先 serial_monitor_stop"
            "（不抢口——抢来的「成功」会收到错数据）。"
            "超时且一个字节都没收到 → error_code=modbus-timeout-no-response（查接线/波特率/从站号）；"
            "收到了但 CRC 不过 → modbus-bad-crc（查串口参数/串扰）——这两类是不同的问题，不要混着猜。"
            "典型用法：modbus_read(slave=1, func=3, addr=0, count=10, port=\"COM9\", baud=9600, serial_format=\"8E1\")。"
        ),
    )
    async def modbus_read(slave: int = 1, func: int = 3, addr: int = 0, count: int = 1,
                          port: str = "", baud: int = 9600, serial_format: str = "",
                          databits: int = 8, parity: str = "none", stopbits: float = 1,
                          mode: str = "rtu", timeout_ms: int = 1000,
                          include_frames: bool = False) -> str:
        try:
            sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                            mode, timeout_ms, serial_format)
            if err:
                return _js(err)
            req = _modbus.make_request(sess.mode, slave, func, addr=addr, count=count)
            res = sess.transact(req["request"],
                                timeout_s=max(0.02, float(timeout_ms) / 1000.0),
                                expected_len=req["expected_len"])
            if res.get("ok") and res.get("parsed_ok") is False:
                # 收到了字节但帧不合法（半帧/CRC 错/不是 Modbus）——不当成功
                res["ok"] = False
                res["error"] = res.get("parse_error")
                res["error_code"] = res.get("parse_error_code") or "modbus-bad-frame"
            out = _modbus_merge(req, res, keep_frames=include_frames)
            dec = res.get("response") or {}
            if isinstance(dec, dict) and dec.get("kind") == "registers":
                out["values"] = dec.get("registers")
                out["values_hex"] = dec.get("registers_hex")
                out["signed_values"] = dec.get("signed")
            elif isinstance(dec, dict) and dec.get("kind") == "bits":
                out["bits"] = dec.get("bits")
                out["true_count"] = dec.get("true_count")
            _parsed = res.get("response_parsed") or {}
            if _parsed.get("is_exception"):
                out["ok"] = False
                out["is_exception"] = True
                out["exception_code"] = _parsed.get("exception_code")
                out["exception_text"] = _parsed.get("exception_text")
                out["error"] = _parsed.get("error")
                out["error_code"] = "modbus-exception"
            if out.get("ok"):
                out["hint"] = ("值可能是 32 位量：Modbus 只有 16 位寄存器，双字常见「高字在前」"
                               "或「低字在前」两种拼法，需要时把两个寄存器按设备手册拼一下")
            return _js(out)
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_write",
        title="Modbus 写（规范功能码 05/06/0F/10）",
        description=(
            "按 Modbus 规范写从站：**05 写单个线圈 / 06 写单个保持寄存器 / 0F 写多个线圈 / 10 写多个保持寄存器**。"
            "单点用 value（线圈可写 true/false/1/0/on/off；寄存器写 0~65535），多点用 values"
            "（逗号分隔字符串或数组，如 \"1,2,3\" / [0x1234, 0x5678]）。"
            "verify=true 时**写后自动回读校验**（线圈回读用 01、寄存器回读用 03），把「写进去了没有」"
            "一次做完——很多从站会静默丢弃越界写入，只看回显（05/06 的应答只是原样回显）会误判成功。"
            "这是**会改目标设备状态**的操作：写寄存器/线圈可能改变输出、参数甚至保护阈值，"
            "调用前请确认对象与取值。串口参数与 modbus_read 相同（首次必须给 port）。"
            "返回含 request_hex / response_hex 与 verify 子结果；从站异常帧会译成中文原因。"
        ),
    )
    async def modbus_write(slave: int = 1, func: int = 6, addr: int = 0,
                           value: str = "", values: str = "", port: str = "",
                           baud: int = 9600, serial_format: str = "",
                           databits: int = 8, parity: str = "none", stopbits: float = 1,
                           mode: str = "rtu", timeout_ms: int = 1000,
                           verify: bool = False) -> str:
        try:
            sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                            mode, timeout_ms, serial_format)
            if err:
                return _js(err)
            f = int(func)
            kw = {"addr": addr}
            if f in (0x05, 0x06):
                if str(value or "").strip() == "":
                    return _js({"ok": False, "error_code": "invalid-argument",
                                "error": "func 0x%02X 需要 value（单点写）；多点写请用 func 0F/10 + values" % f})
                kw["value"] = value
            elif f in (0x0F, 0x10):
                if str(values or "").strip() == "":
                    return _js({"ok": False, "error_code": "invalid-argument",
                                "error": "func 0x%02X 需要 values（多点写）；单点写请用 func 05/06 + value" % f})
                kw["values"] = values
            else:
                return _js({"ok": False, "error_code": "invalid-argument",
                            "error": "modbus_write 只支持功能码 05/06/0F/10，收到 0x%02X" % f,
                            "hint": "掩码写(16)/读写合一(17) 等不常用功能码可走 modbus_raw 下发裸帧"})
            req = _modbus.make_request(sess.mode, slave, f, **kw)
            res = sess.transact(req["request"],
                                timeout_s=max(0.02, float(timeout_ms) / 1000.0),
                                expected_len=req["expected_len"])
            if res.get("ok") and res.get("parsed_ok") is False:
                res["ok"] = False
                res["error"] = res.get("parse_error")
                res["error_code"] = res.get("parse_error_code") or "modbus-bad-frame"
            out = _modbus_merge(req, res)
            if isinstance(res.get("response"), dict):
                out["write_echo"] = res["response"]
            _parsed = res.get("response_parsed") or {}
            if _parsed.get("is_exception"):
                out["ok"] = False
                out["is_exception"] = True
                out["exception_code"] = _parsed.get("exception_code")
                out["exception_text"] = _parsed.get("exception_text")
                out["error"] = _parsed.get("error")
                out["error_code"] = "modbus-exception"
            if verify and out.get("ok"):
                if f in (0x05, 0x0F):
                    out["verify"] = await _modbus_readback(
                        sess, slave, addr, 1 if f == 0x05 else len(_modbus.parse_values(values)),
                        "coil", max(0.02, float(timeout_ms) / 1000.0))
                else:
                    out["verify"] = await _modbus_readback(
                        sess, slave, addr, 1 if f == 0x06 else len(_modbus.parse_values(values)),
                        "reg", max(0.02, float(timeout_ms) / 1000.0))
                if out["verify"].get("ok"):
                    out["verify_note"] = ("回读成功：写后读一致由设备决定（有些从站写入是异步生效的，"
                                          "不一致时先看设备手册的写入时序）")
            elif verify:
                out["verify_note"] = "写请求本身没成功（见 error），跳过回读"
            return _js(out)
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_raw",
        title="Modbus 裸帧收发（非规范/私有协议）",
        description=(
            "**不按规范**发送任意字节并回收响应，用于厂商私有协议、不规范实现、以及排查「到底谁在说话」。"
            "req 默认按 hex 解析（\"01 03 00 00 00 01 84 0A\"，也接受连写/0x 前缀）；as_text=true 时按文本下发"
            "（ASCII 帧、私有 ASCII 协议）。auto_crc=true 时把 req 当**不含校验的帧体**，自动补 CRC16(RTU)"
            "或 LRC(ASCII)——手算校验最容易错，这个开关就是为它准备的。"
            "响应不硬凑成一串 hex：按**帧间静默**自动切帧，每段给出 hex/ascii 以及「能不能按 Modbus 解」"
            "（parsed.crc_ok / func / exception_code），解不了的部分标 decoded=false 并保留原文——"
            "**判断不了就说不判断**，不猜一个像样的结论。"
            "max_frames 控制最多收几段（总线多从站应答时会收多段）；expect_len>0 表示「收够这么多字节就返回」"
            "（知道应答长度时用它，比等满超时快得多）。"
            "会写总线的操作，请确认帧内容再发。串口参数与 modbus_read 相同（首次必须给 port）。"
        ),
    )
    async def modbus_raw(req: str = "", as_text: bool = False, auto_crc: bool = False,
                         expect_len: int = 0, max_frames: int = 4,
                         port: str = "", baud: int = 9600, serial_format: str = "",
                         databits: int = 8, parity: str = "none", stopbits: float = 1,
                         mode: str = "rtu", timeout_ms: int = 500) -> str:
        try:
            if not str(req or "").strip():
                return _js({"ok": False, "error_code": "invalid-argument",
                            "error": "req 为空：要发什么？给 hex（\"01 03 00 00 00 01 84 0A\"）"
                                     "或用 as_text=true 给文本"})
            sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                            mode, timeout_ms, serial_format)
            if err:
                return _js(err)
            try:
                data = str(req).encode("utf-8") if as_text else _modbus.parse_hex(req)
            except ValueError as e:
                return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
            crc_note = None
            if auto_crc:
                if sess.mode == "ascii":
                    body = data if data[:1] == b":" else data
                    core = _modbus.strip_ascii_frame(body)
                    raw = bytes.fromhex(core.decode("ascii"))
                    data = b":" + (raw + bytes([_modbus.lrc(raw)])).hex().upper().encode() + b"\r\n"
                    crc_note = "已按 ASCII 追加 LRC"
                else:
                    c = _modbus.crc16(data)
                    data = data + bytes([c & 0xFF, (c >> 8) & 0xFF])
                    crc_note = "已按 RTU 追加 CRC16=0x%04X（低字节在前）" % c
            res = sess.transact(data, timeout_s=max(0.02, float(timeout_ms) / 1000.0),
                                expected_len=int(expect_len) or None,
                                max_frames=max(1, int(max_frames or 1)))
            out = {"ok": bool(res.get("ok")), "port": res.get("port"), "mode": sess.mode,
                   "request_hex": res.get("request_hex"), "sent_bytes": res.get("sent_bytes"),
                   "elapsed_ms": res.get("elapsed_ms"), "frame_count": res.get("frame_count"),
                   "parsed_ok": res.get("parsed_ok"),
                   "frames": res.get("frames"),
                   "silence_terminated": res.get("silence_terminated"),
                   "inter_frame_gap_ms": res.get("inter_frame_gap_ms"),
                   "discarded_before_tx": res.get("discarded_before_tx")}
            for k in ("error", "error_code", "hint"):
                if k in res:
                    out[k] = res[k]
            if crc_note:
                out["crc_note"] = crc_note
            frames = res.get("frames") or []
            if frames:
                first = frames[0].get("parsed") or {}
                out["first_frame_modbus_like"] = bool(first.get("ok"))
                if first.get("ok"):
                    out["first_frame"] = {k: first.get(k) for k in
                                          ("slave", "func", "func_name", "is_exception",
                                           "exception_code", "exception_text", "direction",
                                           "direction_note", "decode")
                                          if first.get(k) is not None}
                else:
                    out["first_frame_note"] = ("首段帧不符合 Modbus 结构（%s）："
                                               "原始内容见 frames[0].hex，本工具不替它编解释"
                                               % (first.get("error") or "校验/长度不符"))
            elif not out.get("ok"):
                out["note"] = ("没有收到任何字节：确认波特率/接线，或用 modbus_sniff 旁听总线看"
                               "设备到底有没有在说话")
            return _js(out)
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_decode",
        title="离线解析 Modbus 报文（不占端口）",
        description=(
            "把一段报文**离线**解析成结构：从站号、功能码（含中文含义）、载荷（线圈位/寄存器值/写回显/"
            "异常码原因）、CRC16 或 LRC 校验是否通过。"
            "frame 接受 hex 串（\"01 03 02 12 34 B5 33\"）或 ASCII 帧（\":0103021234B4\\r\\n\"，自动识别）；"
            "支持一次给多行（用换行分隔）批量解析，适合把示波器/串口助手抓下来的报文粘进来。"
            "mode=auto 自动判别，也可强制 rtu/ascii。"
            "**自动判方向**：先按应答解，不符再按请求解（旁听/抓包得到的帧多半是主站请求），"
            "结果里给 direction=response/request；05/06/08/16 这类请求与应答同形的功能码"
            "如实标 direction=ambiguous，不硬指一个方向。"
            "**不打开任何串口、不发任何字节**，是排查时最安全的工具：先离线看清帧结构，再去动总线。"
            "解析失败会明确说是哪一类（长度不足 / CRC 不过 / LRC 不过 / hex 非法），"
            "不会给出一个「看着像」的结论。"
        ),
    )
    async def modbus_decode(frame: str = "", mode: str = "auto") -> str:
        import re
        try:
            txt = str(frame or "").strip()
            if not txt:
                return _js({"ok": False, "error_code": "invalid-argument",
                            "error": "frame 为空：给 hex 或 ASCII 帧内容",
                            "example_args": {"frame": "01 03 02 12 34 B5 33"}})
            lines = [ln for ln in re.split(r"[\r\n]+", txt) if ln.strip()] if "\n" in txt or "\r" in txt else [txt]
            outs = []
            for ln in lines:
                s = ln.strip()
                try:
                    if s.startswith(":"):
                        data = s.encode("ascii", "replace")
                    else:
                        data = _modbus.parse_hex(s)
                except ValueError as e:
                    outs.append({"input": s, "ok": False, "error": str(e),
                                 "error_code": "modbus-bad-frame"})
                    continue
                p = _modbus.parse_frame(data, mode)
                outs.append({"input": s, **p})
            n_ok = sum(1 for o in outs if o.get("ok"))
            n_bad = sum(1 for o in outs if not o.get("ok") and not o.get("is_exception"))
            n_exc = sum(1 for o in outs if o.get("is_exception"))
            out = {"ok": bool(outs) and n_bad == 0, "count": len(outs), "decoded": n_ok,
                   "exception_frames": n_exc, "bad_frames": n_bad, "frames": outs}
            if len(outs) == 1:
                out.update({k: v for k, v in outs[0].items() if k != "frames"})
            if n_exc:
                out["hint"] = ("异常帧是**从站的正常应答**（它收到了、但拒绝了请求）："
                               "按 exception_code 对号入座改地址/数量/取值，别当通信故障查")
            elif n_bad:
                out["hint"] = ("解析不了的帧：先核对串口参数（波特率/校验位/停止位）与帧是否被截断，"
                               "再考虑它根本不是 Modbus——非规范协议请用 modbus_sniff 看原始帧")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_scan",
        title="扫描总线上在线的 Modbus 从站",
        description=(
            "对一段从站号范围逐个探测（默认发 03 读 1 个保持寄存器），把**有应答的从站**列出来："
            "从站号、应答帧、是正常数据还是异常码。调试新设备最缺的就是「从站号到底是几、波特率对不对」——"
            "它一次把这件事做完。"
            "slaves 支持 \"1-16\" / \"1,3,5\" / \"1-8,20\"；默认只扫 1~16（Modbus 合法范围是 1~247）。"
            "**范围超过 max_slaves（默认 64）会直接报错让你收窄**，而不是静默截断——"
            "少扫了一批却报「扫描完成」比报错难查得多。"
            "timeout_ms 是**每个从站**的等待时间（默认 120ms）：全范围扫描很慢，范围越大越要调小。"
            "波特率/校验位不对时通常一个从站都扫不到，属正常结果：先确认 8E1/8N1 与速率。"
            "本工具会往总线上发请求（会影响总线占用），但不改任何设备状态。"
        ),
    )
    async def modbus_scan(slaves: str = "1-16", func: int = 3, addr: int = 0,
                          count: int = 1, port: str = "", baud: int = 9600,
                          serial_format: str = "", databits: int = 8,
                          parity: str = "none", stopbits: float = 1, mode: str = "rtu",
                          timeout_ms: int = 120, max_slaves: int = 64) -> str:
        try:
            try:
                ids = _modbus.parse_slave_range(slaves)
            except ValueError as e:
                return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
            if len(ids) > int(max_slaves or 64):
                return _js({"ok": False, "error_code": "invalid-argument",
                            "error": "本次要扫 %d 个从站，超过上限 max_slaves=%d"
                                     % (len(ids), int(max_slaves or 64)),
                            "hint": "收窄 slaves（如 \"1-16\"）或把 max_slaves 调大；"
                                    "每个从站要等 timeout_ms=%d ms，全范围 1-247 约需 %.1f 秒"
                                    % (timeout_ms, 247 * float(timeout_ms) / 1000.0)})
            sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                            mode, timeout_ms * 2, serial_format)
            if err:
                return _js(err)
            to = max(0.02, float(timeout_ms) / 1000.0)
            found, silent, bad = [], 0, []
            for sid in ids:
                try:
                    req = _modbus.make_request(sess.mode, sid, func, addr=addr, count=count)
                except ValueError as e:
                    return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
                res = sess.transact(req["request"], timeout_s=to,
                                    expected_len=req["expected_len"])
                if not res.get("ok"):
                    silent += 1
                    continue
                p = res.get("response_parsed") or {}
                if not p.get("ok"):
                    bad.append({"slave": sid, "response_hex": res.get("response_hex"),
                                "note": "有应答但不符合 Modbus 结构：%s"
                                        % (p.get("error") or "校验/长度不符")})
                    continue
                ent = {"slave": sid, "response_hex": res.get("response_hex"),
                       "func": p.get("func"), "func_name": p.get("func_name"),
                       "elapsed_ms": res.get("elapsed_ms")}
                if p.get("is_exception"):
                    ent["is_exception"] = True
                    ent["exception_code"] = p.get("exception_code")
                    ent["exception_text"] = p.get("exception_text")
                    ent["note"] = "从站在线，但拒绝了这个请求（换 addr/count 或功能码再试）"
                else:
                    ent["decode"] = p.get("decode")
                found.append(ent)
            out = {"ok": True, "port": sess.port, "mode": sess.mode,
                   "scanned": len(ids), "slave_range": [ids[0], ids[-1]],
                   "func": func, "addr": addr, "count": count,
                   "timeout_ms_per_slave": timeout_ms,
                   "found_count": len(found), "found": found,
                   "no_response_count": silent, "malformed_count": len(bad)}
            if bad:
                out["malformed"] = bad
            if found:
                out["hint"] = ("在线从站数 %d；**异常码不等于不在线**——它说明从站收到了请求但拒绝了参数。"
                               "接下来用 modbus_read 按 addr/count 细读" % len(found))
            else:
                out["hint"] = ("一个从站都没应答：依次核对 ①波特率/校验位（Modbus 常用 9600 8E1 或 19200 8N1）"
                               "②A/B 线是否交叉、GND 是否共地、终端电阻 ③从站号是否真的在这个范围里"
                               "（不确定就放大 slaves，但注意耗时）④总线是否有别的程序占着")
            return _js(out)
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_sniff",
        title="旁听 Modbus/串口总线（被动收帧，不发一个字节）",
        description=(
            "在指定时长内**只收不发**，把总线上的字节按帧间静默切成帧后列出（hex / ascii / 能否按 Modbus 解）。"
            "适用场景：①别人的主站在问什么、从站回了什么（协议逆向）②私有/非规范协议长什么样"
            "③「到底有没有数据在总线跑」这种接线确认。"
            "duration_ms 是收多久（默认 3000ms）；max_frames 上限（默认 200，满了提前返回并标 max_frames_reached）。"
            "gap_ms 可手工指定切帧间隔（默认按波特率算 t3.5，>19200 波特固定 1.75ms）。"
            "总线上没有主站请求时**一帧都收不到是正常结果**，不是故障——这时该做的是催主站发，"
            "或用 modbus_scan 主动探测。本工具不发送任何字节，因此不会打扰总线。"
        ),
    )
    async def modbus_sniff(duration_ms: int = 3000, max_frames: int = 200,
                           gap_ms: float = 0, port: str = "", baud: int = 9600,
                           serial_format: str = "", databits: int = 8,
                           parity: str = "none", stopbits: float = 1,
                           mode: str = "rtu") -> str:
        try:
            dur = max(0.05, min(float(duration_ms or 3000) / 1000.0, 120.0))
            sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                            mode, duration_ms, serial_format)
            if err:
                return _js(err)
            res = sess.sniff(duration_s=dur, max_frames=max(1, int(max_frames or 200)),
                             gap_s=(float(gap_ms) / 1000.0) if gap_ms else None)
            if not res.get("ok"):
                return _js(res)
            res["ok"] = True
            res["max_frames_reached"] = bool(res.get("frame_count") >= int(max_frames or 200))
            if res["frame_count"] == 0:
                res["hint"] = ("这段时间总线上一帧都没有：确认波特率/接线，并确认确实有人在发请求"
                               "（从站不会自己开口，要等主站问）")
            else:
                modbus_like = sum(1 for f in res["frames"]
                                  if (f.get("parsed") or {}).get("ok"))
                res["modbus_like_frames"] = modbus_like
                if modbus_like < res["frame_count"]:
                    res["hint"] = ("%d/%d 段能按 Modbus 解——其余段是私有/非规范帧，"
                                   "原始内容在 frames[].hex，本工具只给事实不给解释"
                                   % (modbus_like, res["frame_count"]))
            return _js(res)
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="modbus_session",
        title="Modbus 会话状态 / 打开 / 关闭端口",
        description=(
            "查看或管理 Modbus 会话占用的串口：action=status（当前口、波特率、串口格式、RTU/ASCII、"
            "已持有多久、收发了多少帧/字节、帧间间隔）；action=close（**释放端口**，让 Keil 串口窗口、"
            "其他串口工具或 serial_monitor_start 能用）；action=open（按 port/baud 参数预先开好口，"
            "便于确认接线是否通）。"
            "为什么要显式提供：串口是独占资源，Modbus 会话会一直持有直到显式关闭或空闲超时"
            "（idle_release_s，默认 900 秒；进程退出也会自动释放）。"
            "调完 Modbus 想接着看日志/用串口助手，先 action=close，不要让它一直占着。"
            "会话未打开时 status 也返回 ok=true，不报错。"
        ),
    )
    async def modbus_session(action: str = "status", port: str = "", baud: int = 9600,
                             serial_format: str = "", databits: int = 8,
                             parity: str = "none", stopbits: float = 1,
                             mode: str = "rtu", timeout_ms: int = 1000) -> str:
        try:
            act = str(action or "status").strip().lower()
            if act in ("status", "state", "show"):
                st = _modbus.session_status()
                st["action"] = "status"
                return _js(st)
            if act in ("close", "release", "stop"):
                return _js(_modbus.close_session())
            if act in ("open", "start"):
                sess, err = await _modbus_ready(port, baud, databits, parity, stopbits,
                                                mode, timeout_ms, serial_format)
                if err:
                    return _js(err)
                # 直接展开会话状态：塞进 status 键会被外层信封的同名键盖掉（只剩「开了」）
                out = {"ok": True, "action": "open", "note": "会话已就绪，后续同口同参数可省略 port"}
                out.update(sess.status())
                return _js(out)
            return _js({"ok": False, "error_code": "invalid-argument",
                        "error": "action 只支持 status / open / close，收到: %s" % action})
        except ValueError as e:
            return _js({"ok": False, "error": str(e), "error_code": "invalid-argument"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="mdk_guide",
        title="环境自检与调试工作流引导",
        description=(
            "AI 落地的第一个工具：一键自检 Keil/UVSOCK/UV4/.axf/源码漂移/调试态/RTOS 类型，"
            "并返回推荐的调试工作流与各场景应调用的工具，避免 AI 盲目试错。"
            "返回 {environment:{...}, recommended_workflow:[...], scene_tools:{...}}。注意：建议 AI 落地第一件事先调本工具获取环境自检与工作流，再按场景选择工具；自检为无副作用只读操作，可在任意时刻调用。"
            "topic=tool, name=<工具名> 取回该工具被挪出上下文的**完整说明**（为省上下文，长描述在工具列表里只留一句话摘要，正文全文存在这里）；"
            "topic=tool 不带 name 则列出全部已归档工具与描述档位。"
        ),
    )
    async def mdk_guide(topic: str = "", name: str = "") -> str:
        try:
            _t = (topic or "").strip().lower()
            if _t in ("tool", "tools", "desc", "description") or (name or "").strip():
                return _js(_guide_tool(_t, name, server))
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
                "10. 要下发命令/数据（shell、bootloader、镜像片段）：serial_write(text=\"help\")"
                "（收与发共用同一句柄，写后自动把新增回显带回来）",
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
                "串口下发命令/数据(一边收一边发)": "serial_monitor_start（持有端口）→ serial_write → serial_read",
                "串口被占用/打不开(WinError=5)": "serial_monitor_stop（释放端口，日志保留）→ 或等空闲自动释放（idle_release_s）",
                "改代码重新上板": "build_and_flash / flash_debug",
            }
            return _js({"ok": True, "environment": env,
                        "recommended_workflow": workflow, "scene_tools": scene_tools})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="wait_state",
        title="等待目标进入指定状态（通用等待）",
        description=(
            "轮询等待目标进入某个状态，**把「等待 + 超时 + 现场」三件事一次做完**，"
            "省掉 AI 自己 sleep + get_status 的轮询循环（那种循环既慢又容易在超时后不知道现场是什么）。"
            "state 取值：`stopped`（已停下，含 halt 后）、`running`（执行中）、"
            "`not_debugging`（未进入调试）、`expr`（表达式成立，需配 expr 参数，"
            "如 expr=\"uwTick > 1000\" 或 expr=\"state == 3\"，非 0 即视为成立）。"
            "timeout_s 默认 10；poll_ms 默认 200。返回 matched（是否等到）、"
            "elapsed_s、polls、observed（最终观测到的状态）、以及超时时的 timeout_kind"
            "（timeout=等到了时间还没到目标状态 / unreachable=调试通道本身连不上 / "
            "never_debugging=目标停在 not_debugging 但你等的是调试态）。"
            "**不要用它替代 wait_breakpoint**：断点命中要用 wait_breakpoint（它认断点 id 与命中计数，"
            "比轮询 PC 更可靠）；本工具适合「等标志位/等变量变化/等目标自己停下来」这类含糊等待。"
        ),
    )
    async def wait_state(state: str = "stopped", timeout_s: int = 10,
                         poll_ms: int = 200, expr: str = "") -> str:
        try:
            client = _get_client()
            want_raw = str(state or "stopped").strip().lower()
            syn = {"stopped": "stopped", "stop": "stopped", "halt": "stopped",
                   "halted": "stopped", "stop_ped": "stopped",
                   "running": "running", "run": "running", "executing": "running",
                   "not_debugging": "not_debugging", "idle": "not_debugging",
                   "no_debug": "not_debugging", "nodebug": "not_debugging",
                   "expr": "expr", "expression": "expr"}
            want = syn.get(want_raw)
            if want is None:
                return _js({"ok": False, "state": state,
                            "error": "未知状态 %s" % state,
                            "available": sorted(set(syn.values())),
                            "usage": "stopped / running / not_debugging / expr"})
            if want == "expr" and not (expr or "").strip():
                return _js({"ok": False, "state": state, "expr": expr,
                            "error": "state=expr 时必须给 expr（如 expr=\"uwTick > 1000\"）"})
            deadline = time.time() + max(0.2, float(timeout_s or 10))
            interval = max(0.05, float(poll_ms or 200) / 1000.0)
            t0 = time.time()
            polls = 0
            observed = "?"
            last_status = {}
            last_value = None
            while True:
                polls += 1
                st = client.get_status() or {}
                last_status = st
                if not st.get("ok"):
                    observed = "unreachable"
                    matched = False
                elif not st.get("debugging"):
                    observed = "not_debugging"
                    matched = (want == "not_debugging")
                elif st.get("running"):
                    observed = "running"
                    matched = (want == "running")
                else:
                    observed = "stopped"
                    matched = (want == "stopped")
                if want == "expr" and st.get("ok") and st.get("debugging"):
                    ev = client.calc_expression(expr) or {}
                    last_value = ev
                    matched = bool(ev.get("ok")) and bool(ev.get("value"))
                if matched:
                    return _js({"ok": True, "state": want, "matched": True,
                                "elapsed_s": round(time.time() - t0, 3), "polls": polls,
                                "observed": observed, "expr": expr or None,
                                "expr_value": (last_value or {}).get("value")
                                if isinstance(last_value, dict) else None,
                                "note": "已等到目标状态，可以直接做下一步（读内存/看寄存器/继续运行）。"})
                if time.time() >= deadline:
                    tk = "unreachable" if observed == "unreachable" else "timeout"
                    if observed == "not_debugging" and want in ("stopped", "running"):
                        tk = "never_debugging"
                    hints = {
                        "timeout": "超时未达目标状态，现场见 observed/status；"
                                   "先判断是该调大 timeout_s，还是目标根本没走到那一步。",
                        "unreachable": "调试通道本身不可用（Keil 未运行/UVSOCK 未开/连接被占），"
                                       "先调 keil_health 定位，再调 restart_keil 或 reset_connection。",
                        "never_debugging": "目标一直不在调试态，先 enter_debug。",
                    }
                    return _js({"ok": False, "state": want, "matched": False,
                                "timeout_kind": tk, "elapsed_s": round(time.time() - t0, 3),
                                "polls": polls, "observed": observed,
                                "status": last_status, "expr": expr or None,
                                "hint": hints.get(tk), "timeout_s": timeout_s})
                await asyncio.sleep(interval)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "state": state, "error": str(e)})

    def _svd_autodevice() -> str:
        """不给 device 时，从当前工程的 uvprojx <Device> 推断型号。

        真机踩过的坑：盘上有几十份不同厂商的 .svd，不指定器件就会挑到别的芯片，
        把 0x40020000(GPIOA) 判成 TIMER2——**看似权威的错答案比报错更危险**。
        """
        # 真机踩坑：只看「服务默认工程」时，用工具参数指定过工程的会话依然推不出型号
        # （_resolve_project("") 无默认工程就抛异常），于是一整盘 20+ 份 .svd 只好拒绝。
        # 与符号懒加载同理：再退一步用「本次会话用过的工程」，仍无则如实返回空。
        cands = []
        try:
            cands.append(_resolve_project(""))
        except Exception:  # noqa: BLE001
            pass
        if _last_project:
            cands.append(_last_project)
        for p in cands:
            try:
                if p and os.path.isfile(p):
                    dev = str((_uvprojx.read_config(p) or {}).get("device") or "").strip()
                    if dev:
                        return dev
            except Exception:  # noqa: BLE001
                continue
        return ""

    @server.tool(
        name="svd_list",
        title="列出 CMSIS-SVD 外设（按器件找 .svd）",
        description=(
            "用芯片厂商的 **CMSIS-SVD** 文件回答「这个地址/外设叫什么、有哪些寄存器」——"
            "它比本服务内置的 STM32F4 硬编码寄存器表更权威，且**换型号也能用**。"
            "三种用法：① 只给 device（如 `STM32F401RCTx`）→ 在已安装的 Pack 里找匹配的 .svd "
            "并列出其中的外设；② 给 svd_file 直接指定某份 .svd；③ 都不给 → 只列出盘上候选的 .svd 文件"
            "（便于先看清有哪些可用）。keyword 按外设名子串过滤（如 `USART`、`GPIO`）。"
            "**定位逻辑（真机踩过坑）**：包根不是 `Keil_v5/ARM/PACK`（本机该目录是空的！），"
            "而是 `TOOLS.INI` 里 `RTEPATH=` 指向的目录，本服务会先读 TOOLS.INI 再回退猜。"
            "另：SVD 文件名按容量档写（`STM32F401xE`），与订货型号（`STM32F401RCTx`）互不包含，"
            "因此按**公共前缀**匹配，返回 found / device 供你核对是否选错档位。"
            "疑点：SVD 只用于「解释读到的值」，**不会**用它去写寄存器。"
            "解析出的值用 svd_decode 解位域；地址→外设的反查也走 svd_decode(address=...)。"
        ),
    )
    async def svd_list(device: str = "", svd_file: str = "", keyword: str = "") -> str:
        try:
            eff_dev, auto_dev = (device or "").strip(), False
            if not svd_file and not eff_dev and not _svd.loaded():
                eff_dev = _svd_autodevice()
                auto_dev = bool(eff_dev)
            if not svd_file and not eff_dev and not _svd.loaded():
                cands = _svd.find_svd_files("", limit=40)
                return _js({"ok": True, "mode": "candidates",
                            "count": len(cands), "files": cands,
                            "note": "给 device= 或 svd_file= 进一步加载并列出外设；"
                                    "也可设 MDKDEBUG_SVD 环境变量固定一份 .svd。"
                                    "若当前工程已打开，本服务会先按工程 <Device> 自动推断。"})
            r = _svd.load(path=svd_file or "", device=eff_dev or (device or ""))
            if not r.get("ok"):
                return _js(r)
            kw = (keyword or "").strip().lower()
            names = [n for n in _svd.peripheral_names()
                     if not kw or kw in n.lower()]
            out = {"ok": True, "mode": "peripherals", "device": _svd.device(),
                   "path": r.get("path"), "matched_from": r.get("device_hint"),
                   "device_auto": auto_dev,
                   "peripheral_count": len(names), "peripherals": names}
            if kw and not names:
                out["note"] = "keyword 没匹配到任何外设，去掉过滤看看全部 %d 个" % \
                              len(_svd.peripheral_names())
            out["next"] = "用 svd_decode(peripheral=\"USART2\") 看寄存器清单；" \
                          "svd_decode(address=\"0x4000440C\", value=\"0x200C\") 按地址解位域。"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="svd_decode",
        title="按 CMSIS-SVD 解码寄存器值（含地址反查）",
        description=(
            "把读到的寄存器值按 **CMSIS-SVD** 的 bitOffset/bitWidth 拆成位域，"
            "并给出枚举值含义（如 `UE=1` / `MODER3=2 (Alternate function mode)`）——"
            "比内置硬编码表更权威，且支持任意有 SVD 的型号。"
            "两种定位方式：① `peripheral`+`register`（register 支持前缀匹配，写 `CR1` 即可）；"
            "② 只给 `address`（自动反查外设与寄存器）——**这是最省事的方式**："
            "先用 read_mem/read_peripheral 拿到地址和值，直接丢进来。\n"
            "**真机踩过的坑（已修）**：地址反查曾用固定 0x4000 窗口判范围，"
            "在 `0x40003800`(SPI2) 与 `0x40004400`(USART2) 这种只隔 3KB 的密集排布下会串台"
            "（实测把 USART2 的 CR1 判成 SPI2）。现在优先用 SVD 的 `<addressBlock>` 界定真实范围、"
            "并让 addressBlock 随 `derivedFrom` 继承（真机上 USART2 只是 `derivedFrom=\"USART6\"` 的空壳）；"
            "实在没有 addressBlock 才退化为「最近前缀」。返回的 `matched_by` 会告诉你这次是"
            "`addressBlock` 还是 `nearest_base` 判定的——看到 `nearest_base` 说明把握低一档，请核对。\n"
            "value 支持 `0x`/十进制/纯数字字符串；只给 peripheral 不给 register 时返回该外设的寄存器清单。"
            "**本工具只解释，不写寄存器**（写外设请用 write_peripheral / write_mem）。"
        ),
    )
    async def svd_decode(peripheral: str = "", register: str = "", value=0,
                         address: str = "", svd_file: str = "", device: str = "",
                         allow_mismatch: bool = False) -> str:
        try:
            eff_dev, auto_dev = (device or "").strip(), False
            if (svd_file or device) or not _svd.loaded():
                if not eff_dev and not svd_file:
                    eff_dev = _svd_autodevice()
                    auto_dev = bool(eff_dev)
                r = _svd.load(path=svd_file or "", device=eff_dev)
                if not r.get("ok"):
                    return _js(r)
            try:
                val = _parse_addr(value) if isinstance(value, str) else int(value or 0)
            except Exception:  # noqa: BLE001
                return _js({"ok": False, "value": value,
                            "error": "value 解析失败，支持 0x 前缀或十进制（如 0x200C / 8204）"})
            addr = None
            if str(address or "").strip():
                try:
                    addr = _parse_addr(str(address).strip())
                except Exception:  # noqa: BLE001
                    return _js({"ok": False, "address": address,
                                "error": "address 解析失败，支持 0x 前缀或十进制"})
            # 批次49：SVD 选错芯片同样会给「看着权威的错答案」——先拿目标核对型号。
            if not allow_mismatch:
                try:
                    g = _periph_device_guard(_get_client(), _svd.device() or "",
                                             what="按 SVD 解寄存器")
                    if not g.get("allowed", True):
                        g["svd_device"] = _svd.device()
                        g["svd_file"] = _svd._CACHE.get("path")
                        return _js(g)
                except Exception:  # noqa: BLE001
                    pass
            out = _svd.decode_value(peripheral=peripheral or "",
                                    register=register or "", value=val, address=addr)
            if isinstance(out, dict):
                # 透出「这次用的是哪份 .svd」——选错文件会给出看似权威的错答案，
                # 必须让调用方能一眼看出判定依据来自哪个芯片的手册。
                out["svd_device"] = _svd.device()
                out["svd_file"] = _svd._CACHE.get("path")
                out["device_auto"] = auto_dev
                if auto_dev:
                    out["device_hint"] = ("未指定 device，已按当前工程的 <Device> 自动加载 %s；"
                                          "若目标芯片不是它，请显式传 device= 或 svd_file="
                                          % _svd.device())
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="uvprojx_read",
        title="只读查看 uVision 工程配置（target/包含路径/分组文件）",
        description=(
            "读 .uvprojx（Keil 工程文件）里的关键配置，**不做任何写入**。what 取值："
            "`targets`（有哪些 target）、`config`（某 target 的器件/包含路径/宏/输出名/优化等级）、"
            "`groups`（工程分组与各组源文件）、`all`（默认，三者都给）。target 为空时用第一个。"
            "用途：AI 在改工程前先看清现状——本服务多个工具（build/flash/set_debug_target）"
            "都吃 target 名，名字打错很费时间，先跑本工具拿到准确名字。"
            "改工程用 uvprojx_edit。解析用 ElementTree 只读打开，**不会**回写文件。"
        ),
    )
    async def uvprojx_read(project: str = "", target: str = "", what: str = "all") -> str:
        try:
            p = _resolve_project(project)
            if not os.path.isfile(p):
                return _js({"ok": False, "project": p, "error": "工程文件不存在"})
            w = (what or "all").strip().lower()
            out = {"ok": True, "project": p, "what": w}
            if w in ("all", "targets"):
                out["targets"] = _uvprojx.list_targets(p)
            if w in ("all", "config"):
                out["config"] = _uvprojx.read_config(p, target or "")
            if w in ("all", "groups"):
                out["groups"] = _uvprojx.list_groups(p)
            out["next"] = "改工程用 uvprojx_edit（会先自动备份 .uvprojx）；" \
                          "切调试目标用 set_debug_target。"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="uvprojx_edit",
        title="受控编辑 uVision 工程（加包含路径/加文件/按正则删除）",
        description=(
            "改 .uvprojx 的**受控编辑**通道，专治「手工往工程里加一个 .c 文件」这种体力活。"
            "action 取值：`add_include_path`（paths=目录列表）、`del_include_path`（pattern=正则）、"
            "`add_files`（group + files，分组不存在会自动新建）、`remove_files`（pattern=正则，"
            "匹配 FilePath）。project 为空用默认工程；target 为空用第一个 target。"
            "paths/files 接受数组或逗号/分号分隔字符串。\n"
            "**三条真机约定，请照做**：\n"
            "1. **先读后写**：动手前先 uvprojx_read 看清现有分组名与包含路径，避免加出重复项；"
            "2. **一定留着备份**：默认 backup=true，写前把原文件复制成 `<工程名>.uvprojx.mdkdebug.bak`，"
            "返回值里有 backup（备份文件的绝对路径）——改完编译通过再考虑删；\n"
            "3. **改完要重编译**：工程文件变了但 .axf 没变，调试看到的是旧固件的符号。\n"
            "实现上是**文本级替换**（不是 ElementTree 序列化），保留原缩进与属性顺序，"
            "所以 diff 干净、不会把文件洗一遍；每处替换都断言锚点唯一，命中数不为 1 就放弃写入并报错。"
            "4. **Keil 开着同一工程时会被拦下**：返回 project-open-in-keil，"
            "先 close_uvision 收窗口再改——先开 Keil 再改工程会让它弹「文件已被外部修改」模态框，"
            "模态框会把调试通道一起堵死（真机踩过）。确实要写传 force=true。\n"
            "**中风险**：会真实修改用户的工程文件（已自动备份）。"
        ),
    )
    async def uvprojx_edit(action: str, project: str = "", target: str = "",
                           paths="", pattern: str = "", group: str = "",
                           files="", backup: bool = True,
                           force: bool = False) -> str:
        try:
            p = _resolve_project(project)
            if not os.path.isfile(p):
                return _js({"ok": False, "project": p, "error": "工程文件不存在"})
            a = (action or "").strip().lower()
            bk = bool(backup)
            # 写工程文件前先问一句「Keil 是不是正开着这个工程」——这是真机上撞出来的：
            # 先 launch_uvision 打开工程、再改 .uvprojx，Keil 会弹「文件已被外部修改」
            # 的**模态**对话框，而模态框会把 UVSOCK 通道一起堵死（后续命令全超时，
            # 表现成"调试通道假死"）。把这一句做成契约，调用方就不可能踩到。
            if not force:
                _opened = []
                try:
                    _inst = builder.list_uvision_instances(project=p)
                    _opened = [i.get("pid") for i in (_inst.get("instances") or [])]
                except Exception:  # noqa: BLE001
                    _opened = []          # 探测失败不阻断写入（不能让探测把功能锁死）
                if _opened:
                    return _js({
                        "ok": False, "project": p, "action": a,
                        "error_code": "project-open-in-keil",
                        "error": "工程正被 Keil 打开（PID %s）；此时写入会让 Keil 弹"
                                 "「文件已被外部修改」模态框，并把调试通道一起堵住。"
                                 % ", ".join(str(_x) for _x in _opened),
                        "open_instances": _opened,
                        "next_actions": [
                            '先 close_uvision(keep="none") 收起 Keil，改完工程再 launch_uvision；',
                            "确实要在 Keil 开着时写就传 force=true（不推荐：Keil 里那份仍是旧内容）。",
                        ],
                    })
            if a == "add_include_path":
                items = _csv_tokens(paths)
                if not items:
                    return _js({"ok": False, "action": a, "error": "paths 不能为空"})
                return _js(_uvprojx.add_include_path(p, items, target or "", backup=bk))
            if a == "del_include_path":
                if not (pattern or "").strip():
                    return _js({"ok": False, "action": a, "error": "pattern（正则）不能为空"})
                return _js(_uvprojx.del_include_path(p, pattern, target or "", backup=bk))
            if a == "add_files":
                items = _csv_tokens(files)
                if not (group or "").strip() or not items:
                    return _js({"ok": False, "action": a,
                                "error": "add_files 需要 group 与 files"})
                return _js(_uvprojx.add_files(p, group, items, backup=bk))
            if a == "remove_files":
                if not (pattern or "").strip():
                    return _js({"ok": False, "action": a, "error": "pattern（正则）不能为空"})
                res = _uvprojx.remove_files(p, pattern, backup=bk)
                # 真机阶段7 实测：pattern 是正则且作用于 FilePath，写 "stm32f4xx_hal"
                # 会一次命中二十多个文件——不提示就很容易在真工程上「一删一片」。
                _rm = res.get("removed") or []
                if len(_rm) >= 5:
                    res["warning"] = (
                        "pattern 命中了 %d 个文件：它是正则且作用于 FilePath，没锚定时很容易"
                        "吃一大片，请逐条核对 removed 清单；改动前的工程已备份到 backup，"
                        "确认无误前不要删备份。建议把正则收紧，例如 /Src/mdk_.* 这类带目录前缀的写法。"
                        % len(_rm))
                return _js(res)
            return _js({"ok": False, "action": action,
                        "error": "未知 action %s" % action,
                        "available": ["add_include_path", "del_include_path",
                                      "add_files", "remove_files"]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="address_for_line",
        title="源码 文件:行号 → 地址（反查）",
        description=(
            "给「源文件+行号」返回对应机器码地址，补齐反查方向——"
            "get_current_location 是「地址→文件:行」，本工具是「文件:行→地址」。"
            "典型用途：想让目标停在某一行，但那里没有符号；用本工具拿到地址，"
            "再用 set_breakpoint(addr=...) 下**行级断点**。file 可用文件名（`main.c`）"
            "或相对/绝对路径；line 为源码行号。返回 address（偶数，可直接喂 set_breakpoint）"
            "与 thumb_address（带 Thumb 位 +1）。\n"
            "**为什么特意给出偶数地址**：Keil 官方命令通道对奇数地址一律回 `error 57 illegal address`"
            "（真机实测，符号 `&func|1` 这种写法必被拒），所以下裸地址断点前先确认地址是偶数。\n"
            "按「小于等于该行的最近一条行记录」匹配（编译器不会给每行都生成地址），"
            "返回 matched_line 告诉你实际落在哪一行；找不到时 ok=false 并给 nearby "
            "（同文件已收录的行号，便于判断是文件没被收录还是行号超了）。"
            "需已加载符号（.axf / .map），符号来源用 set_symbol_file 切换。"
        ),
    )
    async def address_for_line(file: str, line: int) -> str:
        try:
            loc = _get_locator()
            if loc is None:
                return _js({"ok": False, "file": file, "line": line,
                            "error": "未加载符号文件（.axf/.map），先调 set_symbol_file 或确认工程已编译"})
            ln = int(line)
            addr = loc.line_to_addr(file, ln)
            # 0 不是有效代码地址（locator 已跳过 DWARF 的文件起始占位行，这里再兜一层）
            if not addr:
                nearby = []
                try:
                    want_base = os.path.basename(str(file).replace("\\", "/")).lower()
                    for a, f, l in getattr(loc, "_rows", []) or []:
                        if os.path.basename(str(f).lower()) == want_base:
                            nearby.append(int(l))
                except Exception:  # noqa: BLE001
                    nearby = []
                nearby = sorted(set(nearby))
                return _js({"ok": False, "file": file, "line": ln,
                            "error": "该文件/行号没有对应地址（文件未被符号收录，或行号超出编译出的范围）",
                            "nearby_lines": (nearby[:20] + ["..."] + nearby[-10:])
                            if len(nearby) > 30 else nearby,
                            "symbol_source": _symbol_cfg.get("source_type")})
            return _js({"ok": True, "file": file, "line": ln,
                        "address": int(addr) & ~1,
                        "address_hex": "0x%08X" % (int(addr) & ~1),
                        "thumb_address_hex": "0x%08X" % ((int(addr) & ~1) | 1),
                        "symbol_source": _symbol_cfg.get("source_type"),
                        "note": "下裸地址断点请用 address（偶数）；奇数地址会被 Keil 拒为 error 57。"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "file": file, "line": line, "error": str(e)})

    @server.tool(
        name="capabilities",
        title="能力自检（本服务能做什么、哪条通道现在通）",
        description=(
            "冷启动第一步的**能力自检**：一次看清这台上有什么可用、以及每条通道当前通不通，"
            "避免 AI 拿不存在的功能去试错。返回四块：\n"
            "1. `channels`：两条调试通道的可用性——`uvsock`（交互式，需 Keil 运行且 UVSOCK 已开）"
            "与 `uv4_cmdline`（UV4 -d 批处理，不依赖 UVSOCK）；附各自实测结论与何时该用哪条。\n"
            "2. `modules`：本服务内置模块是否就绪——uvprojx 编辑、CMSIS-SVD 解码、"
            "Keil 报错知识库（含已实测的命令错误码条数）、串口监视、构建器等。\n"
            "3. `env`：UV4 路径、默认工程、符号文件来源、端口、工具裁剪设置。\n"
            "4. `tool_surface`：当前暴露的工具数（受 MDKDEBUG_TOOLSETS 影响），以及推荐工作流。\n"
            "与 keil_health 的分工：keil_health 做**诊断**（坏了帮你定位坏在哪一环），"
            "capabilities 做**枚举**（有什么、哪条路现在能走）。"
        ),
    )
    async def capabilities() -> str:
        try:
            ch = {}
            ver = None
            try:
                ver = _get_client().get_version() or {}
            except Exception as e:  # noqa: BLE001
                ver = {"ok": False, "error": str(e)}
            if isinstance(ver, dict) and ver.get("ok"):
                ch["uvsock"] = {"available": True, "keil_version": ver.get("version"),
                                "detail": "UVSOCK 连接可用，可交互式调试（enter_debug / keil_command / 断点 / 内存）"}
            else:
                ch["uvsock"] = {"available": False,
                                "detail": "UVSOCK 不可用（Keil 未运行 / UVSOCK 未开 / 端口不符 / 模态框阻塞）",
                                "next": ["keil_health 定位断点", "restart_keil 拉起并存活性检查"],
                                "raw": ver}
            uv4 = _builder_cfg.get("uv4")
            ch["uv4_cmdline"] = {
                "available": bool(uv4 and os.path.isfile(uv4)),
                "uv4": uv4,
                "detail": "UV4 -d + 初始化文件批处理通道（batch_debug_script），"
                          "不依赖 UVSOCK；但每轮 15~25s、命令报错不改退出码、"
                          "DISPLAY/SAVE 与 Go main 会挂死（工具已做静态告警）。",
                "when_to_use": "可重复的冒烟/回归；UVSOCK 不可用时的降级通道。",
            }
            if not uv4:
                ch["uv4_cmdline"]["next"] = "启动服务时用 --uv4-path 指定 UV4.exe"
            try:
                svd_ok = bool(_svd.loaded())
                svd_info = {"loaded": svd_ok, "device": _svd.device() if svd_ok else None,
                            "path": (_svd._CACHE.get("path") if svd_ok else None)}
            except Exception as e:  # noqa: BLE001
                svd_info = {"loaded": False, "error": str(e)}
            mods = {
                "uvprojx_edit": {"available": hasattr(_uvprojx, "add_files"),
                                 "detail": "工程受控编辑（包含路径/分组文件增删，自动备份）"},
                "svd": dict({"available": True,
                             "detail": "CMSIS-SVD 解析（derivedFrom/cluster/addressBlock，RTEPATH 探测）"},
                            **svd_info),
                "keilkb": {"available": True,
                           "detail": "Keil 报错知识库：编译诊断规则 + 命令错误码",
                           "known_command_codes": len(_keilkb.known_debug_codes())},
                "serial": {"available": True, "detail": "串口监视/读写（端口占用与释放语义见 serial_monitor_start）"},
                "builder": {"available": bool(uv4), "detail": "UV4 命令行编译/烧录（-b/-f，隐藏窗口，日志捕获）"},
                "session": dict(
                    {"available": True,
                     "detail": "跨会话状态 state.json：把工程/符号/断点等上下文落盘，"
                               "下个会话可读回（session_state）",
                     "state_file": _session.state_path()},
                    **{k: v for k, v in _session.load().items()
                       if k in ("ok", "exists", "saved_at", "size", "error")}),
                "output_control": dict({"available": True}, **_outctl.summary()),
            }
            # 非 MDK 链路（批次36）：不用 Keil 的芯片走这一套。
            # 这里刻意只做**廉价探测**（listdir 级），不跑 --version 也不启动
            # OpenOCD：capabilities 是冷启动就会调的工具，慢一秒都是浪费。
            non_mdk = {}
            try:
                tc = _toolchain.discover(with_version=False)
                fams_have = sorted(f for f, e in (tc.get("families") or {}).items()
                                   if e.get("tools"))
                non_mdk["toolchain"] = {
                    "available": bool(fams_have),
                    "families_found": fams_have,
                    "families_missing": sorted(tc.get("missing") or []),
                    "roots": tc.get("roots"),
                    "detail": "交叉编译器 / make / cmake / ninja / openocd / gdb "
                              "的探测结果（详细版本用 toolchain_list）",
                }
            except Exception as e:  # noqa: BLE001
                non_mdk["toolchain"] = {"available": False, "error": str(e)}
            try:
                non_mdk["targets"] = {
                    "available": True,
                    "profiles": len(_targets.PROFILES),
                    "detail": "内置目标档案（连接方式 + 工具链 + trace 参数），"
                              "详见 target_list",
                }
            except Exception as e:  # noqa: BLE001
                non_mdk["targets"] = {"available": False, "error": str(e)}
            try:
                non_mdk["openocd"] = _ocd.session_info()
            except Exception as e:  # noqa: BLE001
                non_mdk["openocd"] = {"available": False, "error": str(e)}
            try:
                non_mdk["trace"] = _trace.summary()
            except Exception as e:  # noqa: BLE001
                non_mdk["trace"] = {"available": False, "error": str(e)}
            non_mdk["when_to_use"] = (
                "目标不用 Keil 时（RISC-V / ESP32 / 裸 GCC 工程）："
                "target_list 挑档案 → toolchain_env 铺 PATH → toolchain_build 构建 → "
                "ocd_start 起 OpenOCD → ocd_control/ocd_read_mem 调试 → "
                "trace_instrument + trace_swo_start / trace_rtt_attach 做 trace。"
                "MDKDEBUG_TOOLSETS=toolchain,target,ocd,trace 可只暴露这一条链路。"
            )
            env = {"uv4_path": uv4,
                   "default_project": _builder_cfg.get("default_project"),
                   "symbol_source": _symbol_cfg.get("source_type"),
                   "symbol_file": _symbol_cfg.get("axf"),
                   "uvsock_port": (getattr(_client, "port", None) if _client is not None else None),
                   "toolsets_env": os.environ.get("MDKDEBUG_TOOLSETS", ""),
                   "svd_env": os.environ.get("MDKDEBUG_SVD", "")}
            surface = {"tool_count": None, "note": "受工具面策略影响"}
            try:
                tm = getattr(server, "_tool_manager", None)
                st = _toolbox.status(server)
                surface["tool_count"] = len(getattr(tm, "_tools", None) or {})
                surface["registered_total"] = st["total_registered"]
                surface["hidden"] = st["hidden"]
                surface["loaded_groups"] = st["loaded_groups"]
                surface["not_loaded_groups"] = sorted(
                    g for g in st["available_groups"] if g not in st["loaded_groups"])
                surface["groups"] = {g: v["size"] for g, v in st["groups"].items()}
                surface["how_to_load"] = st["hint"]
                surface["note"] = ("默认精简：只暴露 %s，其余组按需 toolset(action=load) 装回来。"
                                   % "、".join(st["default_groups"]))
            except Exception:  # noqa: BLE001
                pass
            return _js({"ok": True, "channels": ch, "modules": mods, "env": env,
                        "non_mdk": non_mdk, "tool_surface": surface,
                        "recommended": ["capabilities 看能做什么", "keil_health 看现在通不通",
                                        "list_tools 查准确参数名",
                                        "mdk_guide 看典型工作流",
                                        "target_list / toolchain_list 看非 MDK 链路"]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 批次34：跨会话状态（state.json） ----------------
    # MCP 工具本身无状态，而一次真实调试要配一堆上下文（工程/符号/断点/串口/器件）。
    # 会话一断就全丢，AI 只能重问一遍或从零摸索——最痛的是**符号文件漂移**：接着上次
    # 的会话调试却加载了别的 .axf，表达式集体解析失败，还去怀疑目标代码。
    # 这里把「这次是怎么配起来的」落盘，三点约束：只存观察到的（采不到就明说）、
    # 读回来默认不自动应用（apply=true 才动手，且只做主机侧可逆动作）、写盘要原子。
    def _session_context() -> dict:
        """采集当前会话上下文：只放观察得到的，采不到就标 available=False + 原因。"""
        ctx = {"host": getattr(_client, "host", None),
               "uvsock_port": getattr(_client, "port", None)}
        dp = _builder_cfg.get("default_project")
        if dp:
            ctx["project"] = {"path": dp, "exists": os.path.isfile(dp)}
        else:
            ctx["project"] = {"available": False,
                              "note": "本服务未配置默认工程（启动参数 --default-project 可指定）"}
        ctx["uv4"] = _builder_cfg.get("uv4")
        loc = (_symbol_cfg or {}).get("locator")
        axf = (_symbol_cfg or {}).get("axf")
        if axf or (_symbol_cfg or {}).get("source_type"):
            ctx["symbol"] = {"path": axf,
                             "source_type": (_symbol_cfg or {}).get("source_type"),
                             "exists": bool(axf and os.path.isfile(axf)),
                             "entries": (loc.total_entries() if loc is not None else None)}
        else:
            ctx["symbol"] = {"available": False, "note": "尚未设置符号文件"}
        ctx["debug_session"] = dict(_debug_session)
        ctx["breakpoints"] = [dict(b) for b in _breakpoints]
        ctx["watchpoints"] = [dict(w) for w in _watchpoints]
        try:
            if serialmon.has_monitor():
                st = serialmon.status()
                ctx["serial"] = {"port": st.get("port"), "baud": st.get("baud"),
                                 "state": st.get("state"), "running": st.get("running"),
                                 "port_held": st.get("port_held"), "lines": st.get("lines")}
            else:
                ctx["serial"] = {"available": False, "note": "当前没有串口监听"}
        except Exception as e:  # noqa: BLE001
            ctx["serial"] = {"available": False, "error": str(e)}
        try:
            if _svd.loaded():
                ctx["svd_device"] = _svd.device()
            else:
                ctx["svd_device"] = {"available": False,
                                     "note": "尚未加载 SVD（svd_list/svd_decode 会按工程器件自动推断）"}
        except Exception as e:  # noqa: BLE001
            ctx["svd_device"] = {"available": False, "error": str(e)}
        if isinstance(_snapshot_baseline, dict):
            ctx["snapshot_baseline"] = {"entries": len(_snapshot_baseline),
                                        "keys_sample": sorted(_snapshot_baseline.keys())[:20]}
        else:
            ctx["snapshot_baseline"] = {"available": False, "note": "没有 snapshot_diff 基线"}
        ctx["toolsets_env"] = os.environ.get("MDKDEBUG_TOOLSETS", "")
        return ctx

    def _session_apply_plan(saved_ctx, do_apply: bool) -> list:
        """列出（do_apply 时执行）从状态文件可恢复的动作。

        只做**主机侧可逆动作**（当前仅符号文件切换）；目标侧状态（断点/内存/运行态）
        任何情况下都不自动重放——那属于改目标，必须由调用方显式下命令。
        """
        acts = []
        saved_ctx = saved_ctx or {}
        proj = (saved_ctx.get("project") or {})
        cur_proj = _builder_cfg.get("default_project")
        if proj.get("path") and cur_proj and os.path.abspath(proj["path"]) != os.path.abspath(cur_proj):
            acts.append({"item": "project", "action": "not_auto_applied",
                         "saved": proj.get("path"), "current": cur_proj,
                         "reason": "默认工程由服务启动参数决定，不自动切换；要按状态里的工程操作，"
                                   "请在对应工具上用 project 参数显式传入"})
        sym = saved_ctx.get("symbol") or {}
        axf = sym.get("path")
        cur_axf = (_symbol_cfg or {}).get("axf")
        if not axf:
            acts.append({"item": "symbol_file", "action": "skipped",
                         "reason": "状态文件里没有记录符号文件（保存时尚未设置）"})
        elif cur_axf and os.path.abspath(cur_axf) == os.path.abspath(axf):
            acts.append({"item": "symbol_file", "action": "already_current", "path": axf,
                         "reason": "当前符号文件与状态一致，无需切换"})
        elif not os.path.isfile(axf):
            acts.append({"item": "symbol_file", "action": "skipped", "path": axf,
                         "reason": "状态里记录的符号文件已不存在——不猜替代品；"
                                   "先 list_symbol_projects 看候选，再 set_symbol_file 指定"})
        elif not do_apply:
            acts.append({"item": "symbol_file", "action": "pending", "path": axf,
                         "current": cur_axf,
                         "reason": "可恢复（需 apply=true）：把符号文件切回状态里记录的那份"})
        else:
            ok, msg, cnt = _load_symbol_file(axf, source="会话恢复（状态快照里记录的符号）")
            one = {"item": "symbol_file", "action": ("applied" if ok else "failed"),
                   "path": axf, "current_before": cur_axf, "message": msg}
            if ok:
                one["entries"] = cnt
            else:
                one["error"] = msg
            acts.append(one)
        lost = []
        if saved_ctx.get("breakpoints"):
            lost.append("breakpoints:%d" % len(saved_ctx["breakpoints"]))
        if saved_ctx.get("watchpoints"):
            lost.append("watchpoints:%d" % len(saved_ctx["watchpoints"]))
        if lost:
            acts.append({"item": "target_side_state", "action": "never_auto_applied",
                         "what": lost,
                         "reason": "断点/数据断点在目标侧，属改目标操作，不自动重放；"
                                   "需要时按状态里的 expr 重新 set_breakpoint / set_watchpoint"})
        return acts

    @server.tool(
        name="session_state",
        title="跨会话状态：保存/读取上次调试上下文",
        description=(
            "把「这次调试是怎么配起来的」落盘成 state.json，供下个会话接续，解决 MCP 工具"
            "无状态、会话一断上下文全丢的问题（最典型的是符号文件漂移：接着上次调试却加载了"
            "别的 .axf，表达式集体解析失败）。记录内容：默认工程、符号文件、调试会话标记、"
            "内部断点/数据断点清单、串口端口与波特率、SVD 器件、snapshot_diff 基线等。"
            "action：show（默认，看当前上下文与磁盘态差异）/ save（落盘，旧文件自动备份为 .bak）"
            "/ load（读回；apply=true 才执行可恢复动作）/ clear（删除，需 confirm=true）。"
            "两条约定：① 只存观察到的，采不到的字段标 available=false 与原因，不填默认值假装成功；"
            "② load 默认只对比不应用，apply=true 也只恢复**主机侧可逆项**（目前仅符号文件切换），"
            "断点/内存/运行态等目标侧状态永不自动重放。路径可用 path 指定，"
            "或用环境变量 MDKDEBUG_STATE_FILE，默认 ~/.mdkdebug/state.json。"
        ),
    )
    async def session_state(action: str = "show", path: str = "",
                            apply: bool = False, confirm: bool = False) -> str:
        try:
            a = (action or "show").strip().lower()
            if a in ("status", "read", "current"):
                a = "show"
            if a not in ("show", "save", "load", "clear"):
                return _js({"ok": False,
                            "error": "未知 action：%s（可用：show / save / load / clear）" % action,
                            "hint": "show=看当前上下文与磁盘态对比；save=落盘；"
                                    "load=读回（apply=true 才恢复）；clear=删除（需 confirm=true）"})
            p = _session.state_path(path)
            current = _session_context()
            if a == "save":
                r = _session.save(current, path)
                if not r.get("ok"):
                    return _js({"ok": False, "action": "save", "path": r.get("path"),
                                "error": r.get("error")})
                return _js({"ok": True, "action": "save", "path": r["path"],
                            "backup": r.get("backup"), "bytes": r.get("bytes"),
                            "saved_at": r.get("saved_at"), "schema": r.get("schema"),
                            "saved_keys": sorted(current.keys()),
                            "note": "已落盘。下个会话用 session_state(action=load, apply=true) 接续"
                                    "（apply 只恢复主机侧可逆项，断点/目标内存不自动重放）"})
            if a == "clear":
                if not confirm:
                    st0 = _session.load(path)
                    return _js({"ok": False, "action": "clear", "path": p,
                                "error": "clear 会删除状态文件，需 confirm=true 确认",
                                "exists": st0.get("exists"),
                                "hint": "确认无误后重调 session_state(action=clear, confirm=true)"})
                r = _session.clear(path)
                return _js(dict({"action": "clear"}, **r))
            st = _session.load(path)
            if a == "show":
                out = {"ok": True, "action": "show", "path": p,
                       "state_file": {"exists": st.get("exists"), "ok": st.get("ok"),
                                      "saved_at": st.get("saved_at"), "size": st.get("size"),
                                      "error": st.get("error")},
                       "current": current}
                if st.get("ok"):
                    out["diff"] = _session.diff(st.get("context"), current)
                    out["apply_plan"] = _session_apply_plan(st.get("context"), False)
                return _js(out)
            if not st.get("ok"):
                return _js({"ok": False, "action": "load", "path": p,
                            "exists": st.get("exists"), "error": st.get("error"),
                            "hint": "文件缺失或损坏时不猜内容；可用 session_state(action=save) 重建"})
            out = {"ok": True, "action": "load", "path": p, "saved_at": st.get("saved_at"),
                   "schema": st.get("schema"), "warning": st.get("warning"),
                   "context": st.get("context"),
                   "diff": _session.diff(st.get("context"), current),
                   "apply_plan": _session_apply_plan(st.get("context"), bool(apply))}
            if not apply:
                out["note"] = ("默认只读不应用（apply=false）：apply_plan 是「会做什么」的预告。"
                               "断点/内存/运行态等目标侧状态任何情况下都不会自动重放，"
                               "需要时请按 context 里的 expr 自己下命令")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})

    @server.tool(
        name="toolset",
        title="工具面装卸（按组按需加载工具）",
        description=(
            "本服务的工具按 11 个组划分，另有一个 **nano 极简档**（只暴露十几个最短入口），"
            "**默认只暴露 core 组**（调试核心 + 环境引导），其余组用到时现装——"
            "这样上下文里只放当前真正用得上的工具描述，工具多的时候这是省上下文的主要手段。"
            "action=status 看当前暴露了哪些组、各组多少个、还差什么；"
            "action=load 把 toolsets 指定的组装回来（例：toolsets=mem,trace，"
            "toolsets=all 一次全装，toolsets=nano 极简）；"
            "action=unload 把某组收起来（例：toolsets=trace）。"
            "可用组与含义：core 调试核心/引导、mem 内存进阶、symbol 符号反汇编、"
            "build 编译烧录、serial 串口、advanced 异常/watch/SVD、"
            "toolchain 非MDK构建、target 目标档案、ocd OpenOCD、"
            "trace SWO/RTT/变量时间线、rtos 任务感知。"
            "**装卸后工具面立即变化，但很多 MCP 客户端缓存了工具列表**："
            "若装完仍报未知工具，先重新拉一次 tools/list 再调。"
            "list_tools / get_version / capabilities / toolset 这四个永远保留。"
            "**小上下文模型**：先 tools_groups() 看有哪些组，再 tools_load(group=...) "
            "现装；或直接以 MDKDEBUG_TOOLSETS=nano 启动，只暴露十几个最短入口。"
        ),
    )
    async def toolset_tool(action: str = "status", toolsets: str = "") -> str:
        try:
            act = (action or "status").strip().lower()
            if act == "status":
                return _js(_toolbox.status(server))
            if act == "load":
                return _js(_toolbox.load(toolsets, server))
            if act == "unload":
                return _js(_toolbox.unload(toolsets, server))
            return _js({"ok": False, "action": action,
                        "error": "action 只能是 status / load / unload",
                        "reason": "toolset-bad-action",
                        "hint": "例：action=load, toolsets=mem,trace",
                        "example_args": {"action": "load", "toolsets": "mem,trace"}})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="tools_groups",
        title="列工具分组与当前装载（精简）",
        description=(
            "列出工具分组（含 nano 极简档）与当前是否已装进上下文。"
            "group 留空给总览；给了组名则列出该组工具名。"
            "小上下文模型从这里挑组，再 tools_load(group=...) 装上。"
        ),
    )
    async def tools_groups(group: str = "") -> str:
        try:
            st = _toolbox.status(server)
            if not st.get("ok"):
                return _js(st)
            g = (group or "").strip().lower()
            if g:
                names = _toolbox.tools_of(g)
                if names is None:
                    return _js({"ok": False, "group": g,
                                "reason": "toolset-unknown-group",
                                "error_code": "toolset-unknown-group",
                                "error": "没有这个组/档：%s" % g,
                                "available_groups": st.get("available_groups"),
                                "hint": "组名见 tools_groups() 总览；也可直接用 all / nano"})
                hidden = set(st.get("hidden_tools") or [])
                return _js({"ok": True, "group": g, "size": len(names), "tools": names,
                            "exposed": [n for n in names if n not in hidden],
                            "hidden": [n for n in names if n in hidden],
                            "note": "看某组里有什么；把这一组装上用 tools_load，"
                                    "group 参数就填这个组名"})
            groups = {k: {"size": v["size"], "loaded": v["loaded"], "note": v["note"]}
                      for k, v in (st.get("groups") or {}).items()}
            return _js({"ok": True, "desc_mode": _thin.stats()["mode"],
                        "exposed": st.get("exposed"), "hidden": st.get("hidden"),
                        "total_registered": st.get("total_registered"),
                        "loaded_groups": st.get("loaded_groups"),
                        "groups": groups, "profiles": st.get("profiles"),
                        "hint": "装某组：tools_load(group=组名)；全装 group=all；"
                                "极简档 group=nano；看某个组里有什么："
                                "tools_groups(group=组名)"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="tools_load",
        title="按组装载工具（含 nano 极简档）",
        description=(
            "把 group 指定的组装进工具面（unload=true 则收起）。"
            "group 可写单个组名、逗号分隔多个、或 all / nano。"
            "装完若客户端仍报未知工具，重新拉一次 tools/list（客户端会缓存工具列表）。"
        ),
    )
    async def tools_load(group: str = "", unload: bool = False) -> str:
        try:
            g = (group or "").strip()
            if not g:
                return _js({"ok": False, "error": "group 不能为空",
                            "reason": "toolset-bad-action",
                            "error_code": "toolset-bad-action",
                            "hint": "例：group=mem、group=mem,trace、group=all、group=nano",
                            "example_args": {"group": "mem,trace"}})
            r = _toolbox.unload(g, server) if unload else _toolbox.load(g, server)
            if not r.get("ok"):
                r.setdefault("reason", "toolset-unknown-group")
                r.setdefault("error_code", r.get("reason"))
                return _js(r)
            return _js({"ok": True,
                        "action": r.get("action") or ("unload" if unload else "load"),
                        "groups": r.get("groups"),
                        "loaded": r.get("loaded"), "unloaded": r.get("unloaded"),
                        "exposed": r.get("exposed"), "hidden": r.get("hidden"),
                        "loaded_groups": r.get("loaded_groups"),
                        "note": r.get("note"), "client_note": r.get("client_note")})
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
                # 关键可选参数也进示例：真机反馈「照抄 example_args 恰好漏掉 eol 这类参数」，
                # 这里的工具其可选参数直接决定成败，示例里带上才能照抄即用。
                example.update(_KEY_OPTIONALS.get(nm) or {})
                items.append({"tool": nm, "title": title,
                              "required": required,
                              "optional": [n for n in props if n not in required],
                              "aliases": dict(_ALIAS_HINT.get(nm) or {}),
                              "example_args": example,
                              "usage": _usage_summary(desc)})
            return _js({"ok": True, "count": len(items), "total": len(tools),
                        "keyword": keyword, "tools": items,
                        "note": "example_args 含必填参数（少数工具另含关键可选参数，"
                                "如 serial_write 的 text/eol），可直接作为 args 传入；"
                                "aliases 给出该工具接受的参数别名（如 n_bytes/length 等价）；"
                                "required 中的参数哪怕 schema 标了默认值也必须给（如 read_mem 的 n_bytes）。"
                                "每个工具的完整说明见其 description 末尾的【参数】/【调用示例】"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "keyword": keyword, "error": str(e)})

    # 非 MDK 能力族（工具链 / 目标档案 / OpenOCD / trace / RTOS）。
    # 这些模块各自把工具注册进来，且都排在工具面策略（toolbox.install）之前，
    # 这样 toolbox 里新加的组才有东西可裁。任一族注册失败都只记日志，
    # 不让整个 server 起不来。
    _extra_counts = {}
    for _mod_name, _mod in (("toolchain", _toolchain), ("targets", _targets),
                            ("ocd", _ocd), ("trace", _trace),
                            ("workspace", _workspace), ("rtos", _rtos),
                            ("resetwatch", _resetwatch),
                            ("coverage", _coverage),
                            ("scatter", _scatter),
                            ("cores", _cores),
                            ("etm", _etm), ("viz", _viz)):
        try:
            _extra_counts[_mod_name] = _mod.register(server, _js)
        except Exception as _e:  # noqa: BLE001
            logger.warning("注册 %s 工具族失败（该族不可用，其余功能不受影响）：%s",
                           _mod_name, _e)
    logger.info("非 MDK 工具族注册：%s", _extra_counts)

    # 批次34：给高输出工具的 schema 补 compact/max_lines/full（必须在 _apply_param_hints
    # 之前——提示块是按 schema 算出来的，先注入才能出现在【参数】说明里）。
    try:
        _outctl.inject_params(server)
    except Exception as _e:  # noqa: BLE001
        logger.warning("输出控制参数注入失败（不影响其余功能）：%s", _e)

    # 为每个工具描述追加【参数】/【调用示例】：AI 冷启动可直接照抄参数名，
    # 不必靠 "Field required" 反复试错。
    hinted = _apply_param_hints(server)
    logger.info("已为 %d 个工具补充参数调用示例", hinted)

    # 工具描述分层（批次56）：把「参考手册」式的长正文挪出上下文，需要时用
    # mdk_guide(topic=tool, name=...) 取回。**必须在 _apply_param_hints 之后**
    # （要连【参数】/【输出控制】块一起保留）、在 toolbox.install 快照之前
    # （快照的就是瘦身后的）。默认档位看工具面：nano 极简档用 min，其余 full
    # （不改写）——默认描述不该缺内容，要省得显式选 lean/min；
    # MDKDEBUG_DESC 显式设了的话以它为准。
    try:
        _thin.install(server,
                      mode=_thin.mode_from_env(
                          _toolbox.desc_default_for(toolsets)),
                      summarizer=_usage_summary)
    except Exception as _e:  # noqa: BLE001
        logger.warning("工具描述分层失败（按原样继续，不影响功能）：%s", _e)

    # 工具面：默认精简 + 运行期按需装卸（实现在 toolbox.py）。
    # **必须在输出控制与参数示例注入之后**——Tool 对象是在这里被快照的，
    # 快照之后再改装，后面 load 回来的就丢了那两批注入的说明。
    # spec 传 None 时交给 toolbox 先看 MDKDEBUG_TOOLSETS，没设才用默认 profile。
    try:
        _toolbox.install(server, spec=toolsets)
    except Exception as _e:  # noqa: BLE001
        logger.warning("工具面策略应用失败（按全开继续）：%s", _e)

    # 批次34：启动时只**提示**上次会话状态的存在，不自动应用——上下文接续由调用方
    # 显式调 session_state(action="load", apply=true) 决定（工具不替 AI 猜该用哪份上下文）。
    try:
        _st = _session.load()
        if _st.get("ok"):
            logger.info("跨会话状态：%s（保存于 %s）——需要接续上次上下文时调 "
                        "session_state(action=load, apply=true)",
                        _st.get("path"), _st.get("saved_at"))
        elif _st.get("exists"):
            logger.warning("跨会话状态文件有问题（不影响本次启动）：%s", _st.get("error"))
    except Exception as _e:  # noqa: BLE001
        logger.debug("读取跨会话状态失败：%s", _e)

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
