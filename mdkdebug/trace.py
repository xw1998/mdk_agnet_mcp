# -*- coding: utf-8 -*-
"""Trace 会话层：把「目标里的插桩数据」变成主机上可读的时间线。

三条通路，按硬件条件自动选择（trace_guide 里对用户讲清楚怎么选）：

**1. SWO（要 SWO 引脚，带宽最高）**
   OpenOCD 侧的 `tpiu config internal <file> uart off <coreclk> <baud>` 把 TPIU
   的原始字节流落到一个文件，主机这边增量读文件 → ITM 解码（traceproto）→
   MTF 帧解析 → 结构化事件。丢包表现为 ITM Overflow 包 + MTF CRC 错，
   **必须如实报给用户**，不能静默补数据。

**2. RTT（只要 SWD/JTAG，不要 SWO 引脚）**
   SEGGER RTT 的控制块就躺在目标 RAM 里，主机完全可以在上层实现读写：
   定位控制块 → 读 WrOff/RdOff → 取数据 → 回写 RdOff。这条**不依赖 OpenOCD
   的 rtt 支持**（RISC-V 目标上 OpenOCD 的 rtt 命令受限，正好绕开），
   只要有 ocd_read_mem/ocd_write_mem 就能跑。

**3. SWD 采样（什么额外引脚都不要，代价是侵入式）**
   没有 SWO 引脚、也不想加 RTT 缓冲时，只能「停下来看看」：halt → 读 PC →
   resume。**这会扰动实时性**，所以返回里一定带上 intrusive 标记与采样丢失统计，
   不假装它是无损剖析。

共同点：三条通路产出的事件都进同一个环形缓冲（_T["events"]），
用 trace_events / trace_timeline 统一查看，这样换通路不影响使用方式。
"""

from __future__ import annotations

import json
import os
import re
import struct
import time

from . import traceproto as _tp
from . import linkio as _link
from . import swd as _swd

__all__ = ["state", "reset_state", "register"]

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPONENT_DIR = os.path.join(_REPO_ROOT, "components", "trace")

_MAX_EVENTS = 20000
_T = {
    "mode": None,            # swo / rtt / profile
    "started_at": 0.0,
    "events": [],
    "decoder": None,         # MTFDecoder（SWO/ITM 通路）
    "rtt_decoder": None,     # MTFDecoder（RTT 通路，与 SWO 分开避免半帧状态互串）
    "itm_state": {},
    "swo": None,
    "rtt": None,
    "swd": None,             # 无缝流会话（解码器 + 本地游标 + 已解事件）
    "counters": {"chunks": 0, "bytes": 0, "itm_packets": 0, "mtf_frames": 0},
    "error": None,
}


def state() -> dict:
    return _T


def summary() -> dict:
    """紧凑状态：**不带事件列表**。

    state() 返回的是内部字典，events 可能有上万条——任何「看一眼现在什么情况」
    的场景都不该把事件全带上（capabilities 这种冷启动工具尤其不能）。
    """
    dec = _T.get("decoder")
    swo = _T.get("swo") or {}
    rtt = _T.get("rtt") or {}
    return {
        "ok": True,
        "mode": _T.get("mode"),
        "running": bool(_T.get("mode")),
        "events": len(_T.get("events") or []),
        "counters": dict(_T.get("counters") or {}),
        "overflow": int((_T.get("itm_state") or {}).get("overflow") or 0),
        "mtf": ({"frames": dec.frames, "crc_errors": dec.crc_errors,
                 "dropped_bytes": dec.dropped_bytes, "bad_magic": dec.bad_magic,
                 "last_error": dec.last_error} if dec is not None else None),
        "swo": ({"file": swo.get("file"), "coreclk": swo.get("coreclk"),
                 "baud": swo.get("baud"), "ports": swo.get("ports"),
                 "bytes_read": swo.get("bytes_read")} if swo else None),
        "rtt": ({"addr": rtt.get("addr_hex"), "elf": rtt.get("elf"),
                 "channels": len(rtt.get("up") or [])} if rtt else None),
        "error": _T.get("error"),
        "note": "完整事件列表用 trace_events；这里只给计数与健康度",
    }


def reset_state(keep_events: bool = False) -> dict:
    ev = list(_T["events"]) if keep_events else []
    _T.update({"mode": None, "started_at": 0.0, "events": ev, "decoder": None,
               "rtt_decoder": None,
               "itm_state": {}, "swo": None, "rtt": None, "swd": None,
               "counters": {"chunks": 0, "bytes": 0, "itm_packets": 0,
                            "mtf_frames": 0}, "error": None})
    return {"ok": True, "cleared_events": not keep_events,
            "kept_events": len(ev)}


# ================================================================ ELF 符号

def elf_funcs(elf: str) -> list:
    """读 ELF 的 FUNC 符号（地址, 名字），按地址排序，用于 PC→函数。"""
    if not elf or not os.path.isfile(elf):
        return []
    try:
        from elftools.elf.elffile import ELFFile
        out = []
        with open(elf, "rb") as f:
            e = ELFFile(f)
            for sec in e.iter_sections():
                if sec.name not in (".symtab", ".dynsym"):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    if not sym["st_value"]:
                        continue
                    out.append((int(sym["st_value"]) & ~1, sym.name))
        out.sort()
        return out
    except Exception:  # noqa: BLE001
        return []


def elf_symbol_addr(elf: str, names) -> int | None:
    """在 ELF 里找符号地址（RTT 控制块定位用）。"""
    if not elf or not os.path.isfile(elf):
        return None
    if isinstance(names, str):
        names = [names]
    want = [n.lower() for n in names]
    try:
        from elftools.elf.elffile import ELFFile
        with open(elf, "rb") as f:
            e = ELFFile(f)
            for sec in e.iter_sections():
                if sec.name not in (".symtab", ".dynsym"):
                    continue
                for sym in sec.iter_symbols():
                    if sym.name.lower() in want and sym["st_value"]:
                        return int(sym["st_value"]) & ~1
    except Exception:  # noqa: BLE001
        return None
    return None


def func_of(pc: int, funcs: list) -> str:
    """二分找 PC 落在哪个函数（符号表按地址升序）。"""
    if not funcs or pc is None:
        return "?"
    lo, hi, best = 0, len(funcs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= pc:
            best = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return best[1] if best else "?"


_ELF_FUNCS_CACHE = {}          # (路径, mtime) -> [(addr, name)]，按 mtime 失效

def _elf_funcs_cached(elf: str) -> list:
    try:
        key = (os.path.abspath(elf), os.path.getmtime(elf))
    except OSError:
        return elf_funcs(elf)
    hit = _ELF_FUNCS_CACHE.get(key)
    if hit is None:
        hit = elf_funcs(elf)
        if len(_ELF_FUNCS_CACHE) > 4:
            _ELF_FUNCS_CACHE.clear()
        _ELF_FUNCS_CACHE[key] = hit
    return hit

# ================================================================ SVCrtOS 任务名
#
# 流里的调度事件只带**任务序号**（0..14，0xF 是 idle），看上去就是一堆数字。
# 序号本身在板子上没有名字，但内核的 svcrt_task_table 里每一项都有 entry
# （void (*)(void)）——「这个槽位从哪个函数开始跑」就是一个稳定的取名字段，
# 再把入口地址翻回 ELF 里的函数名，任务名就出来了。
#
# 序号宽度是 4 bit：svcrt_trace.h 里 0..14 是任务表下标、0xF 是 idle。
# 表本身可能比 15 大（实测 SVCRT_TASK_MAX_NUM=48），但编号 15 被 idle 占用，
# **下标 15 永远不会出现在流里**，所以只给前 15 项取名字，不拿它冒充任务。

_SVCRT_TABLE_SYM = "svcrt_task_table"
_SVCRT_TCB_TYPE = "svcrt_task_t"
_SVCRT_TRACE_TASKS = 15        # 编号 0..14
_SVCRT_IDLE_ID = 0xF

def _svcrt_task_names(elf: str = "", link: str = "auto", halt: bool = False,
                      refresh: bool = False) -> dict:
    """把 svcrt_task_table 里每个槽位的 entry 解成函数名。

    取名字要三样东西，少一样就**明说给不出来**，不编：
      ① ELF 里 svcrt_task_table 的地址；
      ② svcrt_task_t 的 sizeof 与 entry 的成员偏移（从 DWARF 取，不靠猜）；
      ③ 一个能读目标的链路。

    快照可信度是**校验过才声明**的：整段若是伪值（全 0 / 全 FF / 同一个字重复）
    直接拒绝给名字；**入口地址必须是这个 .axf 里某个函数的首地址**（精确匹配，
    不拿「最近的下方符号」顶——那会把别的镜像里的代码硬安上一个像样的名字）。

    但**跨镜像的入口是合法的**：SVCrtOS 的应用/驱动是另外下发的镜像，它们的任务
    入口地址根本不在这份内核 .axf 的符号表里。那种槽位一律**留空**（不是编个
    `sub_XXXXXXXX`），并在 `unmapped` / `hint` 里说清楚「想给它们取名就把 elf
    指到那个镜像的 .axf，或用 names= 手给」。只有当**所有**非空槽都落不到符号
    表里（一份名字都给不出来，说明这次读大概不可信）才整批拒绝。

    halt=True 会停下来读（TCB 每切换一次就被调度器改写，停机读是一份自洽快照），
    读完放回运行态；默认全速读，代价是「快照可能跨在两次切换之间」，所以两项
    校验一个都不省。每个会话只做一次（refresh=True 才重做）。
    """
    elf = str(elf or "").strip() or _session_axf()
    if not elf:
        return {"ok": False, "error_code": "tasks-need-elf",
                "error": "没给 elf，也不知道会话的符号文件，无法定位任务表",
                "hint": "给 elf=你的.axf（首选），或先 set_symbol_file。"}
    if not os.path.isfile(elf):
        return {"ok": False, "error_code": "tasks-elf-missing",
                "error": "ELF 不存在：%s" % elf,
                "hint": "烧录后 .axf 被挪过？给当前工程实际编译出的那个。"}
    try:
        from .rtos import get_index
    except Exception as e:                                        # noqa: BLE001
        return {"ok": False, "error_code": "tasks-no-dwarfinfo",
                "error": "取不到 DWARF 索引：%s" % e}
    ix = get_index(elf)
    if ix.error:
        return {"ok": False, "error_code": "tasks-no-dwarfinfo", "error": ix.error,
                "hint": "任务表布局从 DWARF 取（不靠猜），所以 .axf 必须带调试信息"
                        "（-g / Debug 配置）。"}
    base = ix.addr_of(_SVCRT_TABLE_SYM)
    if base is None:
        return {"ok": False, "error_code": "tasks-table-missing",
                "error": "ELF 里没有符号 %s" % _SVCRT_TABLE_SYM,
                "hint": "这个内核没有可命名的任务表（或符号被裁剪）；"
                        "用 names= 手工给名字，或关掉任务名解析。"}
    st = ix.struct(_SVCRT_TCB_TYPE)
    if not st or st.get("size") is None or ix.field(_SVCRT_TCB_TYPE, "entry") is None:
        return {"ok": False, "error_code": "tasks-layout-missing",
                "error": "取不到 %s 的布局（sizeof / entry 偏移）" % _SVCRT_TCB_TYPE,
                "hint": "该 .axf 的 DWARF 里没有这个类型（内核没参与本次构建？）。"}
    tcb_size = int(st["size"])
    entry_off = int(ix.field(_SVCRT_TCB_TYPE, "entry"))
    vk = ix.var_kind(_SVCRT_TABLE_SYM) or {}
    count = int(vk.get("count") or 0) or _SVCRT_TRACE_TASKS
    n_slots = max(1, min(count, _SVCRT_TRACE_TASKS))

    lk, lerr = _link.pick(link, who="读任务表取名")
    if lk is None:
        return {"ok": False, "error_code": "tasks-link-failed",
                "error": (lerr or {}).get("error") or "取不到链路，无法读任务表",
                "hint": (lerr or {}).get("hint")}
    did_halt = False
    if halt:
        r = lk.halt() or {}
        if not r.get("ok"):
            return {"ok": False, "error_code": "tasks-halt-failed",
                    "error": "读任务表前停机失败：%s"
                             % (r.get("error") or r.get("status_text") or "未知"),
                    "hint": "停机读是为了拿一份自洽的 TCB 快照；停不了就按全速读来，"
                            "或本次不给任务名。"}
        did_halt = True
    nbytes = n_slots * tcb_size

    def _one_read(stop_first=False):
        """读一次任务表；返回 (raw, meta)。停机读要记得放回运行态。"""
        try:
            if stop_first:
                lk.halt()
            return _read_mem_words(base, nbytes, link=link, raw=True)
        finally:
            if stop_first:
                _swd_resume(lk)

    raw, meta = _one_read()
    attempts = 1
    fake = _swd_fake_kind(raw) if raw else None
    if raw is None or fake or len(raw) < nbytes:
        # 已知坑两枚：① 停机后紧跟的第一次读可能读到脏帧；② 目标全速运行时读 SRAM
        # 可能整段读回同一个字。两者都会让「快照」看着像样却是错的——**重读一次**
        # 是划算的（一次链路往返换一个可能的好结果），第二次还不行才如实报失败。
        raw2, meta2 = _one_read(stop_first=not did_halt)
        attempts = 2
        if raw2 is not None:
            fake2 = _swd_fake_kind(raw2)
            if not fake2 and len(raw2) >= nbytes:
                raw, meta, fake = raw2, meta2, None
            else:
                fake = fake2 or fake
                raw, meta = raw2, meta2
    if raw is None:
        return {"ok": False, "error_code": "tasks-read-failed",
                "error": (meta or {}).get("error") or "读任务表失败",
                "at": "0x%X" % base, "attempts": attempts}
    if len(raw) < nbytes:
        return {"ok": False, "error_code": "tasks-read-short",
                "error": "任务表只读到 %d 字节（需要 %d）" % (len(raw), nbytes),
                "at": "0x%X" % base, "attempts": attempts}
    if fake:
        # 宁可给不出名字，也不把一份错快照取名成「像样」的结果
        return {"ok": False, "error_code": "tasks-read-untrusted",
                "error": "任务表读回的是伪值（%s，%d 字节）：读了两遍都不可信"
                         % (fake, len(raw)), "at": "0x%X" % base,
                "attempts": attempts,
                "hint": "这属于「全速运行时读 SRAM 不可靠」；" 
                        "可重试，或让调用方带 halt=True 停机读。"}

    funcs = _elf_funcs_cached(elf)
    if not funcs:
        return {"ok": False, "error_code": "tasks-no-funcs",
                "error": "ELF 里读不到任何函数符号，无法把入口地址翻成名字",
                "hint": "用 strip 过的 .axf 就只能看到地址；换带符号的那个。"}
    # 入口指针 = 函数首地址，做**精确**匹配；不拿"最近的下方符号"顶替，
    # 否则跨镜像的地址会被安上一个随便的（看着像样的）名字。
    exact = {}
    for a, n in funcs:
        exact.setdefault(int(a), n)
    names, slots, unnamed = {}, {}, []
    for i in range(n_slots):
        off = i * tcb_size + entry_off
        e = struct.unpack_from("<I", raw, off)[0]
        slots[i] = {"entry": "0x%08X" % e}
        if e in (0, 0xFFFFFFFF):
            slots[i]["name"] = None
            slots[i]["note"] = "空槽（entry=%s）" % slots[i]["entry"]
            continue
        # entry 是**函数指针**，Thumb 状态的那个低比特（bit0=1）是正常的，
        # 不是错误值——ARMCC 把函数地址存进表里时就是带这个位的，先清掉。
        addr = e & ~1
        slots[i]["entry_addr"] = "0x%08X" % addr
        nm = exact.get(addr)
        if nm is None:
            # 不给名字，也**不编**占位名：这个地址不属于本次给的那个 .axf。
            slots[i]["name"] = None
            slots[i]["note"] = ("入口 %s 不在本次的符号表里——多半是已安装的 app/驱动"
                                "镜像里的函数（也可能被裁剪的静态函数）"
                                % slots[i]["entry"])
            unnamed.append(i)
            continue
        slots[i]["name"] = nm
        names[i] = nm
    nonempty = [i for i in slots
                if slots[i]["entry"] not in ("0x00000000", "0xFFFFFFFF")]
    if nonempty and not names:
        # 一个名字都给不出来：这份快照要么是伪值、要么全是别的镜像的入口。
        # 整批拒绝——部分给名字会让人以为剩下的也是好的。
        return {"ok": False, "error_code": "tasks-snapshot-inconsistent",
                "error": "任务表快照给不出任何名字：%d 个非空槽（%s）的入口都落不到"
                         "这份 .axf 的函数符号上" % (len(nonempty), nonempty),
                "at": "0x%X" % base,
                "unmapped_slots": nonempty,
                "hint": "要么这次读的是伪值（重试一次，或用 halt=True 停机读），"
                        "要么这些任务全来自别的镜像（那就把 elf 指到那个镜像的 .axf）。"}
    out = {"ok": True, "elf": os.path.abspath(elf),
           "table_addr": "0x%X" % base, "table_count": count,
           "named_slots": n_slots, "tcb_size": tcb_size, "entry_off": entry_off,
           "read_mode": "halt" if did_halt else "run",
           "tasks": slots, "names": names, "idle_name": "idle",
           "slots_read": n_slots, "named": len(names),
           "nonempty": len(nonempty),
           "idle_id": _SVCRT_IDLE_ID,
           "read_meta": {k: (meta or {}).get(k) for k in
                         ("read_confidence", "while_running", "degenerate")
                         if k in (meta or {})} or None}
    if count > _SVCRT_TRACE_TASKS:
        out["note"] = ("任务表有 %d 项，但流里的任务号只有 4 bit（0..14 是表下标、"
                       "0xF 是 idle），所以只给前 %d 项取名字——表里下标 15 及以后的"
                       "项**不会出现在流里**，不要拿它当任务。" % (count, _SVCRT_TRACE_TASKS))
    if unnamed:
        out["unmapped_slots"] = unnamed
        out["partial"] = True
        out["unmapped"] = [{"slot": i, "entry": slots[i]["entry"]}
                           for i in unnamed]
        out["hint"] = ("槽位 %s 的入口不在这个 .axf 的符号表里（任务可能来自已安装的"
                       "app/驱动镜像），它们**保持无名、不编**。想给它们取名：把 elf "
                       "指到对应镜像的 .axf，或用 names= 按任务号手工指定。"
                       % unnamed)
    return out

def _apply_task_names(evs: list, names: dict, idle_name: str = "idle") -> int:
    """给事件补上 from_name / to_name / task_name。返回命中条数。

    names 是 {任务序号: 名字}。序号 0xF 是 idle，名字由 idle_name 给。
    只补**能确定**的：查不到的序号不动，也不编一个占位名。
    """
    if not names:
        return 0
    def nm(v):
        if v is None or not isinstance(v, int):
            return None
        if v == _SVCRT_IDLE_ID:
            return idle_name or None
        return names.get(v)
    n = 0
    for ev in evs:
        typ = ev.get("type")
        if typ == "sched":
            f, t = nm(ev.get("from")), nm(ev.get("to"))
            if f:
                ev["from_name"] = f
            else:
                ev.pop("from_name", None)
            if t:
                ev["to_name"] = t
            else:
                ev.pop("to_name", None)
            if f or t:
                n += 1
        elif ev.get("id") in _TASK_ARG_EV:
            v = ev.get("arg")
            v = v & 0xF if isinstance(v, int) else None
            got = nm(v)
            if got:
                ev["task_name"] = got
                n += 1
            else:
                ev.pop("task_name", None)
    return n

# svcrt_trace.h 里 arg 是任务号的系统事件
_TASK_ARG_EV = {0x11: "wait", 0x12: "ready", 0x13: "create", 0x14: "exit"}

def _swd_tasks_for_session(s: dict, elf: str, link: str, tasks: str) -> dict:
    """会话内只解析一次任务表；tasks=off 就一次都不解析。

    失败也**记下来**（连原因一起），不是每次调用都重试一遍：一次读不到的表，
    连读十次还是读不到，而每次重试都要花掉一次链路往返。
    """
    spec = str(tasks or "").strip().lower()
    if spec in ("off", "none", "0", "false", "no"):
        return {"ok": False, "skipped": True, "why": "调用方关掉了任务名解析（tasks=off）"}
    cached = s.get("tasks")
    if cached is not None and spec not in ("refresh", "reload") and not s.get("tasks_stale"):
        return cached
    r = _svcrt_task_names(elf=elf, link=link)
    if not r.get("ok"):
        r = dict(r)
        r["why"] = r.get("error")
    s["tasks"] = r
    return r


def _swd_tasks_brief(tn) -> dict:
    """给返回体的任务名摘要（不把整张表塞进每次 read 的返回里）。"""
    tn = tn or {}
    if tn.get("ok"):
        out = {"ok": True, "source": tn.get("table_addr"),
               "slots_read": tn.get("slots_read"),
               "named": tn.get("named"), "nonempty": tn.get("nonempty"),
               "names": {str(k): v for k, v in (tn.get("names") or {}).items()},
               "idle": tn.get("idle_name")}
        if tn.get("partial"):
            out["partial"] = True
            out["unmapped_slots"] = tn.get("unmapped_slots")
            out["hint"] = tn.get("hint")
        return out
    if tn.get("skipped"):
        return {"ok": False, "skipped": True, "why": tn.get("why")}
    return {"ok": False, "error_code": tn.get("error_code"),
            "error": tn.get("error") or tn.get("why"),
            "hint": tn.get("hint")}


def _swd_sched_count(evs: list) -> dict:
    """这一批里调度事件的命名情况：有多少条、多少条真带上了名字。"""
    tot = named = 0
    for e in evs:
        if e.get("type") != "sched":
            continue
        tot += 1
        if e.get("from_name") or e.get("to_name"):
            named += 1
    return {"sched_events": tot, "with_names": named}

# ================================================================ 事件缓冲

def _push(ev: dict) -> None:
    ev.setdefault("t", round(time.time() - (_T["started_at"] or time.time()), 4))
    _T["events"].append(ev)
    if len(_T["events"]) > _MAX_EVENTS:
        del _T["events"][:len(_T["events"]) - _MAX_EVENTS]


def _ingest(packets: list) -> dict:
    """把 ITM 报文 + MTF 帧变成结构化事件塞进缓冲。"""
    dec = _T["decoder"]
    n_mtf, n_itm_bits, dropped = 0, 0, 0
    for p in packets:
        k = p.get("kind")
        if k == "overflow":
            _push({"kind": "overflow", "source": "itm",
                   "note": "ITM 溢出：此处之后有数据丢失"})
            continue
        if k == "hardware":
            src = p.get("source")
            if src == "exception":
                ex = p.get("exception") or {}
                _push({"kind": "exception", "source": "itm",
                       "number": ex.get("number"), "func": ex.get("function"),
                       "pc": p.get("pc")})
            elif src == "pc_sample":
                _push({"kind": "pc_sample", "source": "itm", "pc": p.get("pc")})
            elif src == "event_counter":
                _push({"kind": "event_counter", "source": "itm",
                       "flags": p.get("event_counter")})
            elif src == "data_trace":
                _push({"kind": "data_trace", "source": "itm",
                       "packet_type": p.get("packet_type"),
                       "comparator": p.get("comparator"),
                       "value": p.get("value")})
            continue
        if k in ("lts1", "lts2", "gts1", "gts2"):
            _push({"kind": "timestamp_itm", "source": "itm", "sub": k,
                   "value": p.get("payload")})
            continue
        if k == "instrumentation":
            n_itm_bits += 1
            if dec is not None:
                frames = dec.feed(p.get("data") or b"")
                for fr in frames:
                    n_mtf += 1
                    e = dict(fr)
                    e["source"] = "mtf"
                    e["port"] = p.get("port")
                    _push(e)
            else:
                _push({"kind": "instrumentation", "source": "itm",
                       "port": p.get("port"), "data_hex": (p.get("data") or b"").hex()})
            continue
        if k == "sync":
            continue
    if dec is not None:
        dropped = dec.dropped_bytes
    _T["counters"]["itm_packets"] += len(packets)
    _T["counters"]["mtf_frames"] += n_mtf
    return {"itm_packets": len(packets), "instrumentation": n_itm_bits,
            "mtf_frames": n_mtf, "dropped_bytes": dropped}


def _ingest_mtf(raw: bytes, source: str = "mtf-rtt", channel=None) -> dict:
    """把 RTT 上收到的**裸 MTF 字节流**解成事件。

    为什么要单独一条路：RTT 传的是 MTF 帧本体，不像 SWO 那样还包着一层 ITM
    报文。早期实现让 RTT 字节也去找 ITM 报文头，结果包里明明有 'boot: ...'
    这种可读文本，`trace_decode` 却解出 0 个事件——典型的静默错答案。
    """
    if _T["rtt_decoder"] is None:
        _T["rtt_decoder"] = _tp.MTFDecoder("rtt")
    dec = _T["rtt_decoder"]
    frames = dec.feed(raw or b"")
    for fr in frames:
        e = dict(fr)
        e["source"] = source
        if channel is not None:
            e["channel"] = channel
        _push(e)
    _T["counters"]["bytes"] += len(raw or b"")
    _T["counters"]["mtf_frames"] += len(frames)
    return {"frames": len(frames), "decoder": dec.stats()}

# ================================================================ SWO

def swo_start(file: str = "", coreclk: int = 0, baud: int = 0, ports="0,1",
              profile: str = "", wait: float = 0.5) -> dict:
    from . import ocd as _ocd
    from . import targets as _targets
    s = _ocd.get_session()
    if not s.running():
        return {"ok": False, "error": "OpenOCD 没在运行",
                "reason": "swo-needs-openocd",
                "hint": "SWO 的 TPIU 配置与原始流落盘由 OpenOCD 做：先 "
                        "ocd_start(profile=\"stm32f401\")。**Keil 链路不走这条**——"
                        "Keil 用户用 itm_trace（读 Keil 的 Trace 窗口缓冲，"
                        "同样解成 ITM 事件），或 trace_scope/trace_rtt（两条链路通用）"}
    spec = {}
    if profile:
        g = _targets.get_profile(profile)
        if not g.get("ok"):
            return g
        spec = g
    swo = spec.get("swo") or {}
    ck = int(coreclk or swo.get("coreclk") or 0)
    bd = int(baud or swo.get("baud") or 0)
    if ck <= 0 or bd <= 0:
        return {"ok": False, "error": "coreclk / baud 必须给出（正数）",
                "hint": "给 profile 让档案带出默认值，或显式指定；"
                        "coreclk 是 CPU 主频（Hz），baud 是 SWO 速率（bit/s，"
                        "必须与目标侧 TPIU 配置一致）",
                "profile_swo": swo or None}
    if not file:
        d = os.path.join(os.path.expanduser("~"), ".mdkdebug", "trace")
        os.makedirs(d, exist_ok=True)
        file = os.path.join(d, "swo_%d.bin" % int(time.time()))
    file = os.path.abspath(file)
    ports_list = [int(x) for x in re.split(r"[,\s]+", str(ports or "0")) if x.strip()]
    cmds = ["tpiu config internal %s uart off %d %d" % (_q(file), ck, bd),
            "itm ports on"]
    for p in ports_list:
        cmds.append("itm port %d on" % p)
    r = s.cmd_many(cmds, timeout=8)
    out = {"ok": r.get("ok"), "file": file, "coreclk": ck, "baud": bd,
           "ports": ports_list, "commands": cmds, "results": r.get("results"),
           "output": r.get("output")}
    if not r.get("ok"):
        out["hint"] = ("tpiu/itm 命令失败常见原因：adapter 不支持 SWO（如 ST-Link "
                       "clone）、SWO 引脚没接、coreclk/baud 不匹配；"
                       "用 ocd_log 看 OpenOCD 日志")
        return out
    if _T["mode"] not in (None, "swo"):
        reset_state(keep_events=True)
    _T.update({"mode": "swo", "started_at": time.time(),
               "decoder": _tp.MTFDecoder("swo"),
               "itm_state": {"leftover": b"", "total_bytes": 0, "overflow": 0},
               "events": [], "swo": {"file": file, "coreclk": ck, "baud": bd,
                                     "ports": ports_list, "offset": 0,
                                     "started_at": time.time()},
               "counters": {"chunks": 0, "bytes": 0, "itm_packets": 0,
                            "mtf_frames": 0}})
    out["note"] = ("SWO 采集已开；目标侧的插桩组件（components/trace）"
                   "必须用同样的 ITM port 和 SWO 波特率，且 DWT/ITM 已使能。"
                   "目标跑起来以后用 trace_swo_read 增量取事件")
    out["state"] = _swo_state()
    return out


def _q(p: str) -> str:
    return "{%s}" % str(p).replace("\\", "/") if " " in str(p) else str(p).replace("\\", "/")


def _swo_state() -> dict:
    sw = _T.get("swo") or {}
    st = {"mode": _T.get("mode"), "file": sw.get("file"),
          "offset": sw.get("offset"), "coreclk": sw.get("coreclk"),
          "baud": sw.get("baud"), "ports": sw.get("ports"),
          "file_size": os.path.getsize(sw["file"]) if sw.get("file")
          and os.path.isfile(sw["file"]) else 0,
          "elapsed_s": round(time.time() - sw["started_at"], 2)
          if sw.get("started_at") else 0}
    return st


def _rd32(s, addr: int, timeout: float = 5.0):
    """DAP 直读一个 32 位寄存器；读不到就返回 (None, 原因)，不猜值。"""
    from . import ocd as _ocd
    r = s.cmd("mdw 0x%X 1" % int(addr), timeout=timeout)
    if not r.get("ok"):
        return None, (r.get("error") or "读寄存器失败")
    p = _ocd._parse_mem(r.get("output") or "", int(addr), 1, 32)
    if not p.get("complete"):
        return None, "没有解析到数据（目标没响应？）"
    return p["words"][0] & 0xFFFFFFFF, None


# SWO 零字节时要去目标上看的那几个寄存器（Cortex-M4 固定地址）
_DEMCR = 0xE000EDFC        # bit24 TRCENA：trace 全局使能
_ITM_TCR = 0xE0000E80      # bit0 ITMENA：ITM 使能
_ITM_TER = 0xE0000E00      # 端口使能位图（目标侧）
_TPIU_SPPR = 0xE00400F0    # 输出协议选择
_TPIU_ACPR = 0xE0040010    # 异步时钟预分频：SWO 速率 = coreclk/(ACPR+1)
_DIAG_REFRESH = 5.0        # 诊断结果缓存秒数（避免反复轮询时反复读寄存器）


def _swo_diag(sw: dict) -> dict:
    """SWO 收不到数据时上目标取证，而不是在主机侧猜原因。

    真机当初的处境：`trace_swo_start` 回 ok、`trace_swo_read` 永远 0 字节，没有任何
    提示——用户无法区分「引脚没接」「目标没使能 ITM」「波特率不对」。这里直接用
    DAP 读 ITM/DEMCR/TPIU 寄存器，把能用事实回答的三件事回答掉：
      1. 目标侧到底有没有使能 trace（DEMCR.TRCENA / ITM_TCR.ITMENA / ITM_TER）；
      2. 目标使能的 ITM 端口位图，和主机侧 `itm port N on` 是否一致；
      3. TPIU 分频算出的实际 SWO 速率（coreclk/(ACPR+1)），和本次配置差多少。
    读不到的寄存器如实列进 `unreadable`，绝不用猜测补齐。
    """
    from . import ocd as _ocd
    now = time.time()
    cached = sw.get("_diag")
    if cached and now - float(cached.get("at") or 0) < _DIAG_REFRESH:
        return dict(cached)
    out = {"at": now, "registers": {}, "unreadable": {}, "verdict": [],
           "checks": []}
    s = _ocd.get_session()
    if not s.running():
        out["verdict"].append("OpenOCD 会话已不在：先 ocd_status 确认，再看 SWO")
        sw["_diag"] = out
        return dict(out)
    vals = {}
    for name, addr in (("DEMCR", _DEMCR), ("ITM_TCR", _ITM_TCR),
                       ("ITM_TER", _ITM_TER), ("TPIU_SPPR", _TPIU_SPPR),
                       ("TPIU_ACPR", _TPIU_ACPR)):
        v, err = _rd32(s, addr)
        if v is None:
            out["unreadable"][name] = err
        else:
            vals[name] = v
    out["registers"] = {k: "0x%08X" % v for k, v in vals.items()}
    ck = int(sw.get("coreclk") or 0)
    bd = int(sw.get("baud") or 0)
    if "TPIU_ACPR" in vals and ck:
        actual = ck // (vals["TPIU_ACPR"] + 1)
        out["tpiu_baud_actual"] = actual
        if bd and abs(actual - bd) > max(1000, bd // 20):
            out["verdict"].append(
                "TPIU 实际速率 %d != 本次配置 %d（coreclk/(ACPR+1)，ACPR=0x%X）："
                "目标侧没按这个速率输出，收到的字节会被当噪声丢掉"
                % (actual, bd, vals["TPIU_ACPR"]))
    if "DEMCR" in vals and not (vals["DEMCR"] >> 24) & 1:
        out["verdict"].append("DEMCR.TRCENA=0：目标根本没使能 trace 单元，"
                              "ITM 写出去的字节一个都到不了引脚")
    if "ITM_TCR" in vals and not vals["ITM_TCR"] & 1:
        out["verdict"].append("ITM_TCR.ITMENA=0：ITM 没使能（组件初始化没跑？）")
    if "ITM_TER" in vals:
        ter = vals["ITM_TER"]
        ports = [int(p) for p in (sw.get("ports") or [])]
        if ter == 0:
            out["verdict"].append(
                "ITM_TER=0：没有任何 ITM 端口被使能——端口使能位在**目标侧**，"
                "OpenOCD 的 `itm port N on` 只是主机侧开关，不能代替它")
        elif ports and not any((ter >> p) & 1 for p in ports):
            out["verdict"].append(
                "ITM_TER=0x%X 不含本次监听的端口 %s：目标写的端口和主机听的端口不一致"
                % (ter, ports))
    out["checks"] = [
        "SWO 引脚有没有真接到探针的 SWO 脚（Cortex-M4 常是 PB3）——"
        "SWCLK/SWDIO 通了不等于 SWO 也接了，这条只能眼查排线",
        "目标侧桁桩组件是否已部署并真的被调用：trace_instrument(target_dir=...) "
        "生成 components/trace，固件要调它的初始化（backend=itm）",
        "主机侧监听的 ITM 端口要和目标写入的端口一致（trace_swo_start 的 ports）",
    ]
    sw["_diag"] = out
    return dict(out)


def swo_read(max_events: int = 300, ports=None) -> dict:
    sw = _T.get("swo")
    if not sw:
        return {"ok": False, "error": "没有正在进行的 SWO 采集",
                "hint": "先 trace_swo_start（需要 OpenOCD 会话在跑）"}
    path = sw["file"]
    if not os.path.isfile(path):
        d = _swo_diag(sw)
        return {"ok": True, "new_bytes": 0, "events": [],
                "note": "采集文件还没生成（OpenOCD 只在收到数据时才写）",
                "diagnostics": d, "verdict": d.get("verdict") or [],
                "hint": _swo_hint(d), "state": _swo_state()}
    size = os.path.getsize(path)
    off = int(sw.get("offset") or 0)
    if size <= off:
        d = _swo_diag(sw)
        elapsed = round(time.time() - float(sw.get("started_at") or time.time()), 1)
        return {"ok": True, "new_bytes": 0, "events": [], "state": _swo_state(),
                "note": "已采集 %.1fs 仍是 0 字节（不是「暂时没数据」）" % elapsed,
                "diagnostics": d, "verdict": d.get("verdict") or [],
                "hint": _swo_hint(d)}


    try:
        with open(path, "rb") as f:
            f.seek(off)
            chunk = f.read(min(size - off, 1 << 20))
    except OSError as e:
        return {"ok": False, "error": "读采集文件失败：%s" % e}
    sw["offset"] = off + len(chunk)
    before = len(_T["events"])
    pk = _tp.decode_itm_stream(_T["itm_state"], chunk, ports=ports)
    ing = _ingest(pk["packets"])
    _T["counters"]["chunks"] += 1
    _T["counters"]["bytes"] += len(chunk)
    new = _T["events"][before:]
    return {"ok": True, "new_bytes": len(chunk), "ingest": ing,
            "events": new[:max_events], "events_total": len(_T["events"]),
            "truncated": len(new) > max_events,
            "state": _swo_state(), "decoder": _T["decoder"].stats()
            if _T["decoder"] else None}


def _swo_hint(d: dict) -> str:
    """把诊断结论整理成一句可执行的提示；没结论时明确说「没查出来」。"""
    v = d.get("verdict") or []
    if v:
        return "零字节原因（来自目标寄存器实读）：" + "；".join(v)
    return ("目标和 TPIU 使能位都正常，但主机侧一个字节也没收到：优先排查 SWO 物理接线"
            "（SWD 通了不代表 SWO 接了），其次用 ocd_log 看探针是否报告 SWO 溢出")


def swo_stop(itm_off: bool = True) -> dict:
    from . import ocd as _ocd
    sw = _T.get("swo")
    if not sw:
        return {"ok": True, "note": "没有正在进行的 SWO 采集"}
    s = _ocd.get_session()
    results = []
    if s.running() and itm_off:
        r = s.cmd("itm ports off", timeout=5)
        results.append({"command": "itm ports off", "ok": r.get("ok"),
                        "output": r.get("output"),
                        "note": "OpenOCD 没有专门的「停止 tpiu 输出」命令，"
                                "关掉 ITM 端口即可停止产生数据；"
                                "采集文件保留，可用 trace_decode 离线解析"})
    _T["mode"] = None
    _T["swo"] = None
    return {"ok": True, "stopped": True, "openocd": results,
            "state": _swo_state()}


# ================================================================ 离线解码

def decode(data_hex: str = "", file: str = "", ports="", limit: int = 500,
           meta: bool = False, fmt: str = "auto") -> dict:
    """解析一段字节流。fmt：auto / itm（SWO 原始流）/ mtf（裸 MTF，如 RTT）。

    auto 先去当 ITM 报文找 instrumentation 包；一个都没找到且字节流里确实
    立着 MTF 魔数 0xA5，就按**裸 MTF** 再解一次。这样 RTT 读回来的数据不会
    因为「不是 ITM 封装」而被静默解成 0 个事件。
    """
    raw = b""
    if data_hex:
        h = re.sub(r"[^0-9a-fA-F]", "", data_hex)
        if len(h) % 2:
            return {"ok": False, "error": "data_hex 长度必须是偶数个十六进制字符"}
        try:
            raw = bytes.fromhex(h)
        except ValueError as e:
            return {"ok": False, "error": "data_hex 解析失败：%s" % e}
    elif file:
        if not os.path.isfile(file):
            return {"ok": False, "file": file, "error": "文件不存在"}
        try:
            with open(file, "rb") as f:
                raw = f.read()
        except OSError as e:
            return {"ok": False, "file": file, "error": str(e)}
    else:
        return {"ok": False, "error": "data_hex 与 file 至少要给一个"}
    if isinstance(ports, str):
        ports = [int(x) for x in re.split(r"[,\s]+", ports) if x.strip()] or None
    mode = (fmt or "auto").strip().lower()
    if mode not in ("auto", "itm", "mtf"):
        return {"ok": False, "fmt": fmt,
                "error": "fmt 只能是 auto/itm/mtf",
                "hint": "RTT 读回的数据用 fmt=\"mtf\"；SWO/ITM 采集文件用 fmt=\"itm\""}
    pk = _tp.decode_itm(raw, ports=ports or None)
    dec = _tp.MTFDecoder("offline")
    frames = []
    if mode in ("auto", "itm"):
        for p in pk["packets"]:
            if p.get("kind") == "instrumentation":
                frames.extend(dec.feed(p.get("data") or b""))
    used = "itm"
    if mode == "mtf" or (mode == "auto" and not frames
                         and raw[:1] == bytes([_tp.MTF_MAGIC])):
        dec = _tp.MTFDecoder("offline")
        frames = dec.feed(raw)
        used = "mtf"
    out = {"ok": True, "bytes": len(raw), "packets": len(pk["packets"]),
           "leftover_bytes": len(pk["leftover"]),
           "summary": _tp.summarize(pk["packets"]),
           "mode_used": used,
           "frames": frames[:limit], "frames_total": len(frames),
           "decoder": dec.stats()}
    if used == "mtf":
        out["note"] = ("按裸 MTF 流解析（fmt=%s）：RTT 通道里就是 MTF 帧本体，"
                       "外面没有 ITM 封装" % mode)
        out["events"] = frames[:limit]
    if meta:
        out["packets_detail"] = pk["packets"][:limit]
    if pk["leftover"] and used == "itm":
        out["note"] = ("尾部 %d 字节不构成完整报文（正常：SWO 文件末尾可能被截断）；"
                       "若这个数很大，说明 coreclk/baud 配错导致比特错位"
                       % len(pk["leftover"]))
    return out


# ================================================================ RTT（主机侧实现）

_RTT_CB_FMT = "<16sii"
_RTT_CH_SIZE = 24


def rtt_parse_cb(raw: bytes) -> dict:
    """解析 SEGGER RTT 控制块（16s + 2×int32 + N×{name,buf,size,wr,rd,flags}）。"""
    if len(raw) < 24:
        return {"ok": False, "error": "控制块太短（%d 字节）" % len(raw)}
    magic, nup, ndown = struct.unpack(_RTT_CB_FMT, raw[:24])
    id_str = magic.split(b"\x00")[0].decode("ascii", "replace")
    # 魔数校验不能省：地址给错时那片 RAM 往往全是 0，会解析出 "0 个通道" 的
    # "合法"控制块——调用方拿到的就是个看似权威的错答案。
    if not id_str.startswith("SEGGER RTT"):
        return {"ok": False, "id": id_str,
                "error": "这里不是 RTT 控制块（读到魔数 %r，应为 'SEGGER RTT'）"
                         % id_str,
                "hint": "地址错了？用 trace_rtt_find 按 ELF 符号或 RAM 扫描定位"}
    if nup < 0 or ndown < 0 or nup > 32 or ndown > 32:
        return {"ok": False, "error": "控制块字段不合理（nup=%d ndown=%d）：地址错了？"
                % (nup, ndown), "id": id_str}
    need = 24 + (nup + ndown) * _RTT_CH_SIZE
    if len(raw) < need:
        return {"ok": False, "error": "控制块数据不足", "id": id_str}
    up, down = [], []
    for i in range(nup + ndown):
        off = 24 + i * _RTT_CH_SIZE
        name_p, buf_p, size, wr, rd, flags = struct.unpack(
            "<IIIIII", raw[off:off + _RTT_CH_SIZE])
        ch = {"index": i if i < nup else i - nup, "dir": "up" if i < nup else "down",
              "name_ptr": "0x%X" % name_p, "buf_ptr": "0x%X" % buf_p,
              "size": size, "wr": wr, "rd": rd, "flags": flags}
        (up if i < nup else down).append(ch)
    return {"ok": True, "id": id_str, "nup": nup, "ndown": ndown,
            "up": up, "down": down}


def _read_mem_words(addr: int, n_bytes: int, timeout: float = 10.0, link="auto",
                    raw: bool = False):
    """读目标内存：走链路原语层，Keil(UVSOCK) / OpenOCD 谁活着用谁。

    返回 (bytes|None, meta)。meta 里带读置信度与「目标当时在不在跑」——
    上层要如实披露，**读到的 0 不等于数据是 0**。

    raw=True 走 **单次读**（Keil 链路的 read_once），不复读、不比对：
    给的是**正在被目标改写**的内存（无缝流环形缓冲就是典型）时，
    read_mem_verified 的复读比对永远不会一致，于是它每块都多读一遍
    + 中间 sleep 50ms，还把**后一帧**当结果返回——搬一段就会被拖成两倍
    时间，且拼出来的字节来自两个不同时刻（流必失步）。
    这类「本来就在变」的内存，要的是一次成形的一致快照，不是复读确认。
    """
    lk, err = _link.pick(link, who="读目标内存")
    if lk is None:
        return None, err
    if raw:
        one = getattr(lk, "read_once", None)
        if one is not None:
            data, meta = one(int(addr), int(n_bytes))
            if data is None:
                return None, meta
            m = dict(meta or {})
            m.setdefault("read_mode", "single")
            m.setdefault("read_raw", True)
            return data, m
    return lk.read(int(addr), int(n_bytes))


def _write_mem(addr: int, data: bytes, timeout: float = 10.0, link="auto"):
    """写目标内存（RTT 推进 RdOff 要用）：同样是链路无关的。"""
    lk, err = _link.pick(link, who="写目标内存")
    if lk is None:
        return dict(err, ok=False)
    ok, meta = lk.write(int(addr), bytes(data))
    out = dict(meta)
    out["ok"] = bool(ok)
    out["count"] = meta.get("written")
    if not ok:
        out.setdefault("error", "写目标内存失败")
    return out


def rtt_find(elf: str = "", ranges=None, id_str: str = "SEGGER RTT",
             chunk: int = 0x1000, max_scan: int = 0x40000,
             link: str = "auto") -> dict:
    """定位 RTT 控制块：先查 ELF 符号，再在 RAM 里扫魔数。两条链路通用。"""
    if elf:
        a = elf_symbol_addr(elf, ["_SEGGER_RTT", "SEGGER_RTT", "_SEGGER_RTT_CB",
                                  "segger_rtt_cb"])
        if a:
            return {"ok": True, "addr": a, "addr_hex": "0x%X" % a,
                    "method": "elf_symbol", "elf": os.path.abspath(elf)}
    if not ranges:
        return {"ok": False, "error_code": "invalid-argument",
                "error": "没给 elf 也没给 ranges，无法定位控制块",
                "hint": "给 elf（里面有 _SEGGER_RTT 符号最省事），或用 "
                        "ranges=\"0x20000000-0x20010000\" 让主机扫 RAM；"
                        "扫 RAM 需要目标已 halt"}
    if isinstance(ranges, str):
        ranges = [x for x in re.split(r"[;,|]", ranges) if x.strip()]
    magic = id_str.encode("ascii")
    scanned = 0
    for rg in ranges:
        m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s*[-~]\s*(0x[0-9a-fA-F]+)\s*$", str(rg))
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        addr = lo
        while addr < hi and scanned < max_scan:
            n = min(chunk, hi - addr)
            data, err = _read_mem_words(addr, n, link=link)
            if data is None:
                return {"ok": False, "error": err.get("error"),
                        "addr": "0x%X" % addr, "scanned": scanned,
                        "link": err.get("link")}
            idx = data.find(magic)
            if idx >= 0:
                return {"ok": True, "addr": addr + idx,
                        "addr_hex": "0x%X" % (addr + idx), "method": "scan",
                        "scanned": scanned + n}
            scanned += n
            addr += n
    return {"ok": False, "error": "没找到 RTT 控制块（魔数 %r）" % id_str,
            "scanned": scanned,
            "hint": "确认固件里真的链接了 RTT（_SEGGER_RTT 段没被 --gc-sections 丢掉）、"
                    "扫描范围覆盖了 RAM；用 exec 找符号表更可靠"}


def rtt_attach(addr: int = 0, size: int = 0, elf: str = "", id_str: str = "SEGGER RTT",
               channel_names: bool = True, link: str = "auto") -> dict:
    """读控制块 → 记住通道信息（含用哪条链路）。之后 rtt_read/rtt_write 直接用。"""
    if not addr:
        f = rtt_find(elf=elf, id_str=id_str, link=link)
        if not f.get("ok"):
            return f
        addr = f["addr"]
    lk, lerr = _link.pick(link, who="读 RTT 控制块")
    if lk is None:
        return dict(lerr)
    cb_size = int(size or 0) or 512
    raw, err = _read_mem_words(addr, cb_size, link=lk.name)
    if raw is None:
        return {"ok": False, "addr": "0x%X" % addr, "error": err.get("error"),
                "hint": "目标可能没在跑 / 地址不对；也可加大 size 再试"}
    cb = rtt_parse_cb(raw)
    if not cb.get("ok"):
        cb["addr"] = "0x%X" % addr
        cb["hint"] = ("控制块魔数应为 'SEGGER RTT'；读到 %r 说明地址不对，"
                      "或组件编进去的缓冲被优化掉了" % (cb.get("id") or ""))
        return cb
    if channel_names:
        for ch in cb["up"] + cb["down"]:
            np = int(ch["name_ptr"], 16)
            if not np:
                ch["name"] = ""
                continue
            nm, e2 = _read_mem_words(np, 32, link=lk.name)
            if nm is not None:
                ch["name"] = nm.split(b"\x00")[0].decode("utf-8", "replace")
    _T["rtt"] = {"addr": addr, "cb": cb, "attached_at": time.time(),
                 "link": lk.name,
                 "reads": 0, "bytes_read": 0, "bytes_written": 0}
    if _T["mode"] is None:
        _T["mode"] = "rtt"
        _T["started_at"] = time.time()
    return {"ok": True, "addr": "0x%X" % addr, "id": cb["id"],
            "link": lk.name, "link_label": lk.label,
            "up_channels": len(cb["up"]), "down_channels": len(cb["down"]),
            "channels": [{"dir": c["dir"], "index": c["index"],
                          "name": c.get("name", ""), "size": c["size"],
                          "wr": c["wr"], "rd": c["rd"], "flags": c["flags"]}
                         for c in cb["up"] + cb["down"]],
            "note": "up=目标→主机（日志/事件），down=主机→目标（命令）"}


def rtt_read(channel: int = 0, max_bytes: int = 1024, timeout: float = 10.0) -> dict:
    st = _T.get("rtt")
    if not st:
        return {"ok": False, "error": "还没 attach RTT",
                "hint": "先 trace_rtt_attach(elf=...) 或 trace_rtt_find"}
    chs = [c for c in st["cb"]["up"] if c["index"] == int(channel)]
    if not chs:
        return {"ok": False, "error": "该 up 通道不存在", "channel": channel,
                "available": [c["index"] for c in st["cb"]["up"]]}
    ch = chs[0]
    # 重新读一次控制块头部，拿最新的 wr/rd（目标在跑，wr 一直变）
    lk, lerr = _link.pick(st.get("link") or "auto", who="读 RTT 控制块")
    if lk is None:
        out = dict(lerr)
        out["hint"] = ("RTT 是在 %s 链路上挂的，那条链路现在不可用了；"
                       "重新 trace_rtt_attach 一次" % (st.get("link") or "auto"))
        return out
    hdr, err = _read_mem_words(st["addr"], 24, link=lk.name)
    if hdr is None:
        return {"ok": False, "error": err.get("error")}
    _, nup, ndown = struct.unpack(_RTT_CB_FMT, hdr[:24])
    off = 24 + int(channel) * _RTT_CH_SIZE
    raw_ch, err = _read_mem_words(st["addr"] + off, _RTT_CH_SIZE, link=lk.name)
    if raw_ch is None:
        return {"ok": False, "error": err.get("error")}
    name_p, buf_p, size, wr, rd, flags = struct.unpack("<IIIIII", raw_ch)
    if size <= 0:
        return {"ok": False, "error": "通道 size=0（控制块没初始化好）"}
    avail = (wr - rd) % size
    if rd == wr:
        return {"ok": True, "channel": channel, "bytes": 0, "data_hex": "",
                "text": "", "wr": wr, "rd": rd, "size": size,
                "note": "通道暂时没有新数据"}
    n = min(avail, int(max_bytes))
    first = min(n, size - rd)
    data = b""
    for piece_off, piece_len in ((rd, first), (0, n - first)):
        if piece_len <= 0:
            continue
        d, err = _read_mem_words(buf_p + piece_off, piece_len, timeout=timeout,
                                 link=lk.name)
        if d is None:
            return {"ok": False, "error": err.get("error"),
                    "hint": "读缓冲失败：目标可能在跑并改写了控制块，重试一次通常就好"}
        data += d[:piece_len]
    new_rd = (rd + n) % size
    w = _write_mem(st["addr"] + off + 16, struct.pack("<I", new_rd),
                   timeout=timeout, link=lk.name)
    st["reads"] += 1
    st["bytes_read"] += len(data)
    # 顺手把 MTF 帧解进事件缓冲：trace_events / trace_profile 才能看到内容。
    # 只解析不报错：RTT 通道里也可能跑用户自己的非 MTF 文本。
    ing = _ingest_mtf(data, source="mtf-rtt", channel=channel)
    return {"ok": True, "channel": channel, "bytes": len(data),
            "available": avail, "dropped": max(0, avail - n),
            "data_hex": data.hex(), "text": data.decode("utf-8", "replace"),
            "frames": ing["frames"], "mtf_decoder": ing["decoder"],
            "wr": wr, "rd": rd, "new_rd": new_rd, "size": size,
            "rd_writeback": w.get("ok"),
            "note": "已把 RdOff 推进到 WrOff（标准 RTT 主机行为，"
                    "不推的话目标会以为缓冲满而丢数据）；"
                    "帧已进事件缓冲，用 trace_events 看内容"}


def rtt_write(channel: int = 0, data: str = "", hex_data: str = "",
              timeout: float = 10.0) -> dict:
    st = _T.get("rtt")
    if not st:
        return {"ok": False, "error": "还没 attach RTT", "hint": "先 trace_rtt_attach"}
    chs = [c for c in st["cb"]["down"] if c["index"] == int(channel)]
    if not chs:
        return {"ok": False, "error": "该 down 通道不存在", "channel": channel,
                "available": [c["index"] for c in st["cb"]["down"]]}
    payload = b""
    if hex_data:
        h = re.sub(r"[^0-9a-fA-F]", "", hex_data)
        payload = bytes.fromhex(h if len(h) % 2 == 0 else "0" + h)
    elif data:
        payload = str(data).encode("utf-8")
    else:
        return {"ok": False, "error": "data 与 hex_data 至少要给一个"}
    lk, lerr = _link.pick(st.get("link") or "auto", who="读 RTT 控制块")
    if lk is None:
        out = dict(lerr)
        out["hint"] = ("RTT 是在 %s 链路上挂的，那条链路现在不可用了；"
                       "重新 trace_rtt_attach 一次" % (st.get("link") or "auto"))
        return out
    off = 24 + (len(st["cb"]["up"]) + int(channel)) * _RTT_CH_SIZE
    raw_ch, err = _read_mem_words(st["addr"] + off, _RTT_CH_SIZE, link=lk.name)
    if raw_ch is None:
        return {"ok": False, "error": err.get("error")}
    name_p, buf_p, size, wr, rd, flags = struct.unpack("<IIIIII", raw_ch)
    free = (rd - wr - 1) % size if size else 0
    if size <= 0 or free <= 0:
        return {"ok": False, "error": "下行缓冲没有空间（size=%d free=%d）" % (size, free),
                "note": "目标侧要及时读走；BLOCK_IF_FIFO_FULL 模式下这里就该等"}
    n = min(len(payload), free)
    first = min(n, size - wr)
    if first > 0:
        _write_mem(buf_p + wr, payload[:first], timeout=timeout, link=lk.name)
    if n - first > 0:
        _write_mem(buf_p, payload[first:n], timeout=timeout, link=lk.name)
    new_wr = (wr + n) % size
    _write_mem(st["addr"] + off + 12, struct.pack("<I", new_wr),
               timeout=timeout, link=lk.name)
    st["bytes_written"] += n
    return {"ok": n == len(payload), "channel": channel, "written": n,
            "requested": len(payload), "dropped": len(payload) - n,
            "new_wr": new_wr, "size": size,
            "note": "只写了 %d 字节（缓冲只剩这么多）" % n if n < len(payload) else None}


def rtt_detach() -> dict:
    st = _T.get("rtt")
    _T["rtt"] = None
    if _T.get("mode") == "rtt":
        _T["mode"] = None
    return {"ok": True, "detached": bool(st),
            "stats": {"reads": st["reads"], "bytes_read": st["bytes_read"],
                      "bytes_written": st["bytes_written"]} if st else None}


# ================================================================ SWD 采样

def profile_samples(samples: int = 200, elf: str = "", interval_ms: float = 0,
                    top: int = 15, timeout: float = 20.0,
                    link: str = "auto") -> dict:
    """halt → 读 PC → resume 的采样剖析（侵入式，明确标注）。两条链路通用。"""
    elf = str(elf or "").strip() or _session_axf()
    lk, lerr = _link.pick(link, who="halt 采样")
    if lk is None:
        return dict(lerr)
    n = max(1, int(samples))
    pcs, fails = [], 0
    t0 = time.time()
    was_running = True
    for _ in range(n):
        r = lk.halt()
        if not r.get("ok"):
            was_running = False
        rr = lk.regs(("pc",))
        pc = rr.get("pc") if rr.get("ok") else None
        if isinstance(pc, int):
            pc &= ~1
            pcs.append(pc)
            _push({"kind": "pc_sample", "source": "swd", "pc": pc})
        else:
            fails += 1
        lk.resume()
        if interval_ms and interval_ms > 0:
            time.sleep(min(float(interval_ms) / 1000.0, 0.2))
        if time.time() - t0 > float(timeout):
            break
    hist = {}
    for pc in pcs:
        hist[pc] = hist.get(pc, 0) + 1
    funcs = elf_funcs(elf) if elf else []
    by_func = {}
    for pc, c in hist.items():
        fn = func_of(pc, funcs) if funcs else ("0x%X" % pc)
        by_func[fn] = by_func.get(fn, 0) + c
    top_list = sorted(by_func.items(), key=lambda kv: -kv[1])[:max(1, int(top))]
    return {"ok": bool(pcs), "link": lk.name,
            "samples": len(pcs), "failed": fails,
            "requested": n, "duration_s": round(time.time() - t0, 2),
            "intrusive": True,
            "warning": "每条样本都做了 halt+resume，会显著扰动实时性；"
                       "结论只能用于「热点大概在哪」，不能当精确耗时",
            "by_function": [{"function": k, "samples": v,
                             "percent": round(100.0 * v / max(1, len(pcs)), 2)}
                            for k, v in top_list],
            "top_pcs": [{"pc": "0x%X" % k, "samples": v}
                        for k, v in sorted(hist.items(), key=lambda kv: -kv[1])[:top]],
            "elf": os.path.abspath(elf) if elf else None,
            "resumed": was_running}


def dwt_counters(link: str = "auto") -> dict:
    """读 DWT 计数器（CYCCNT/CPICNT/EXCCNT/SLEEPCNT/LSUCNT/FOLDCNT）。

    DWT 是内存映射寄存器，两条链路都能读；读不到时如实报「哪条链路、为什么」，
    不返回一份看着像样的 0。
    """
    lk, lerr = _link.pick(link, who="读 DWT 计数器")
    if lk is None:
        return dict(lerr)
    base = 0xE0001000
    names = ["CTRL", "CYCCNT", "CPICNT", "EXCCNT", "SLEEPCNT", "LSUCNT", "FOLDCNT"]
    data, meta = lk.read(base, 4 * len(names))
    if data is None or len(data) < 4 * len(names):
        out = {"ok": False, "link": lk.name,
               "error": (meta.get("error") if data is None
                         else "DWT 区读回 %d 字节（要 %d）" % (len(data), 4 * len(names))),
               "dwt_base": "0xE0001000",
               "hint": "DWT 只在 Cortex-M3 以上存在；RISC-V/Xtensa 用 mcycle CSR。"
                       "另确认目标已连上（Keil：enter_debug；OpenOCD：ocd_start）"}
        for k in ("read_confidence", "while_running", "degenerate"):
            if k in meta:
                out[k] = meta[k]
        return out
    words = [int.from_bytes(data[i:i + 4], "little")
             for i in range(0, 4 * len(names), 4)]
    vals = {names[i]: words[i] for i in range(min(len(names), len(words)))}
    ctrl = vals.get("CTRL", 0)
    return {"ok": True, "link": lk.name, "dwt": vals,
            "dwt_hex": {k: "0x%X" % v for k, v in vals.items()},
            "cyccnt_ena": bool(ctrl & (1 << 0)),
            "note": "DWT 只在 Cortex-M3 以上存在；CYCCNT 使能位是 CTRL[0]。"
                    "ESP32/RISC-V 上没有 DWT（会读到 0 或读失败），"
                    "它们用 mcycle CSR 计时——见 trace_guide"}


# ============================== 非侵入式观测（只用 SWD 两线）
#
# 先把“做不到什么”说清楚（trace_guide 里也写了）——
#   * **指令级 CPU 录制（ETM/PTM 那种“每一跳都记下来”）需要并行 trace 口**，
#     不是 SWD 两线能干的；只接 SWD/SWO 时不要再指望它。
#   * 下面两条是 SWD 两线**真能做到**的非 halt 观测：
#     1) 变量 scope：DAP 读 RAM 不需要停核，主机侧轮询成时间线；
#     2) PC 采样：DWT 硬件采样器 (PCSAMPLENA + DWT_PCSR) 自带采样，主机只读寄存器。
# 两者都**不 halt 目标**，但都有代价（采样率受 SWD 带宽 / 采样器速率限制，会丢窗口），
# 所以返回里一定带真实速率、丢点次数与“样本不代表全时域”的披露。

_SCOPE_LOCK_HINT = ("Keil 侧先 enter_debug、非 MDK 侧先 ocd_start；"
                     "变量 scope 靠调试口读目标 RAM，两条链路都行")


def _elf_symbol(elf: str, name: str):
    """在 ELF 里找**任意**符号的 (地址, 字节大小)——数据变量也能找。

    已有的 elf_symbol_addr 只服务 RTT 控制块定位（返回单个 int），
    变量 scope 还需要符号大小。找不到返回 (None, None)，不猜地址。
    """
    if not elf or not os.path.isfile(elf) or not name:
        return None, None
    want = name.strip().lower()
    try:
        from elftools.elf.elffile import ELFFile
        with open(elf, "rb") as f:
            e = ELFFile(f)
            for sec in e.iter_sections():
                if sec.name not in (".symtab", ".dynsym"):
                    continue
                for sym in sec.iter_symbols():
                    if sym.name.lower() != want or not sym["st_value"]:
                        continue
                    sz = int(sym["st_size"] or 0)
                    return int(sym["st_value"]) & ~1, (sz or None)
    except Exception:  # noqa: BLE001
        return None, None
    return None, None


def _session_axf() -> str:
    """会话里已经定位好的符号文件（set_symbol_file / --axf / --symbol-project）。

    采样类工具（scope / pcsample / profile）原先只在调用方显式传 elf= 时才把地址翻成
    函数名，哪怕会话里已经定位好了 .axf——「先 set_symbol_file 再采样」这条最自然的
    用法反而拿不到名字。这里补回落，显式参数仍然优先。
    """
    try:
        from . import server as _server
        a = ((getattr(_server, "_symbol_cfg", None) or {}).get("axf") or "")
        if a and os.path.isfile(a):
            return os.path.abspath(a)
    except Exception:                                          # noqa: BLE001
        pass
    return ""

def _parse_vars(spec: str, elf: str = "") -> dict:
    """解析变量清单："g_cnt@0x20000000:4, g_flag, 0x20000010:1"。

    每条支持四种写法：`name@addr:size` / `addr:size` / `name@addr` / `name`
    （只给名字就去 ELF 查地址与大小）。size 缺省 4 字节。
    **解析不了的条目一律列在 invalid 里报出来**，不静默跳过——
    少测一个变量比测错一个变量容易被发现。
    """
    items, invalid = [], []
    seen = {}
    for raw in re.split(r"[,;\n]+", str(spec or "")):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        body, _, szs = s.partition(":")
        size = 0
        if szs.strip():
            try:
                size = int(szs.strip(), 0)
            except ValueError:
                invalid.append({"item": s, "why": "size 不是整数：%r" % szs.strip()})
                continue
        name, addr = "", None
        if "@" in body:
            name, _, ab = body.partition("@")
            name, ab = name.strip(), ab.strip()
        else:
            ab = body.strip()
        if ab:
            try:
                addr = int(ab, 0)
            except ValueError:
                # 没有 @ 时整串被当成地址；但写法也可能就是裸变量名（"g_cnt"）。
                # 文档承诺「只给名字就用 elf 查地址与大小」，这里必须真去 ELF 查，
                # 不能拿「地址不是数字」把用户挡在门外。
                if not name:
                    name = ab
                a, esz = _elf_symbol(elf, name)
                if a is None:
                    why = ("ELF 里没找到符号 %r" % name) if elf else \
                          ("没给地址也没给 elf，无法把 %r 当变量名解析" % name)
                    invalid.append({"item": s, "why": why})
                    continue
                addr = a
                if not size and esz:
                    size = int(esz)
        else:
            if not name:
                invalid.append({"item": s, "why": "既没地址也没名字"})
                continue
            a, esz = _elf_symbol(elf, name)
            if a is None:
                invalid.append({"item": s, "why": "ELF 里没找到符号 %r" % name})
                continue
            addr = a
            if not size and esz:
                size = int(esz)
        size = int(size or 4)
        if size <= 0 or size > 64:
            invalid.append({"item": s, "why": "size=%d 超范围（1..64）" % size})
            continue
        nm = name or "var_%X" % addr
        if nm in seen:
            nm = "%s_%X" % (nm, addr)
        seen[nm] = addr
        items.append({"name": nm, "addr": int(addr), "size": size})
    return {"items": items, "invalid": invalid}


def _halt_like(err: str) -> bool:
    """判断 OpenOCD 的报错是不是「目标在跑、不能读内存」。"""
    t = (err or "").lower()
    return ("not halted" in t) or ("target not halted" in t) \
        or ("cannot read memory" in t and "halt" in t)


def _read_var(lk, addr: int, size: int, timeout: float = 5.0) -> dict:
    """读一个变量（不 halt 目标）。返回 {ok, value, meta} 或 {ok:False, error}。"""
    data, meta = lk.read(int(addr), max(1, int(size)))
    if data is None:
        return {"ok": False, "error": (meta.get("error") or "读失败"), "meta": meta}
    if len(data) < int(size):
        return {"ok": False,
                "error": "读取不完整（%d/%d 字节）" % (len(data), int(size)),
                "meta": meta}
    return {"ok": True, "value": int.from_bytes(data[:int(size)], "little"),
            "meta": meta}


def scope_start(vars: str, elf: str = "", period_ms: float = 100.0,
                max_samples: int = 2000, duration_s: float = 0.0,
                timeout: float = 5.0, link: str = "auto") -> dict:
    """启动非 halt 的变量 scope（后台线程轮询调试口读 RAM）。

    两条链路通用：Keil 侧走 UVSOCK 的带脏读判定的内存读（read_mem_verified），
    非 MDK 侧走 OpenOCD 的 mdw。目标在全速跑时读内存，Keil 侧可能错位——
    返回里会如实给出 link 与丢点统计，不假装是干净样本。
    """
    import threading
    elf = str(elf or "").strip() or _session_axf()
    lk, lerr = _link.pick(link, who="轮询目标内存")
    if lk is None:
        out = dict(lerr)
        out["hint"] = (out.get("hint") or "") + "；" + _SCOPE_LOCK_HINT
        return out
    cur = _T.get("scope")
    if cur and cur.get("thread") and cur["thread"].is_alive():
        return {"ok": False, "error": "已有一个变量 scope 在跑",
                "hint": "先 trace_scope_stop 停下再开新的；同一条 SWD 上不要并发采样"}
    p = _parse_vars(vars, elf)
    if not p["items"]:
        return {"ok": False, "error": "没有可用的变量",
                "invalid": p["invalid"],
                "hint": "写法：name@0x20000000:4 / 0x20000000:4 / name（名字靠 elf 查）；"
                        "按逗号分隔"}
    st = {"vars": p["items"], "invalid": p["invalid"], "elf": elf or None,
          "link": lk.name, "link_label": lk.label,
          "period_ms": float(period_ms), "max_samples": int(max_samples),
          "duration_s": float(duration_s), "samples": [],
          "reads": 0, "misses": 0, "last_error": None, "require_halt": False,
          "halted": False, "started_at": time.time(), "stopped_at": None,
          "by_var": {it["name"]: {"last": None, "min": None, "max": None,
                                  "changes": 0, "reads": 0}
                     for it in p["items"]}}
    stop_ev = threading.Event()

    def _run():
        t0 = time.time()
        while not stop_ev.is_set():
            if duration_s and time.time() - t0 >= float(duration_s):
                break
            if len(st["samples"]) >= int(max_samples):
                break
            row = {"t": round(time.time() - t0, 4)}
            for it in p["items"]:
                rv = _read_var(lk, it["addr"], it["size"], timeout=timeout)
                if not rv.get("ok"):
                    st["misses"] += 1
                    st["last_error"] = rv.get("error")
                    if not st["require_halt"] and _halt_like(rv.get("error")):
                        st["require_halt"] = True
                    continue
                v = rv["value"]
                row[it["name"]] = v
                st["reads"] += 1
                bv = st["by_var"][it["name"]]
                bv["reads"] += 1
                if bv["last"] is None:
                    bv["min"] = bv["max"] = v
                else:
                    bv["min"] = min(bv["min"], v)
                    bv["max"] = max(bv["max"], v)
                    if v != bv["last"]:
                        bv["changes"] += 1
                bv["last"] = v
            if len(row) > 1:
                st["samples"].append(row)
            if period_ms and float(period_ms) > 0:
                time.sleep(min(float(period_ms) / 1000.0, 2.0))
        st["stopped_at"] = time.time()

    st["stop_ev"] = stop_ev
    th = threading.Thread(target=_run, name="mdkdebug-scope", daemon=True)
    st["thread"] = th
    _T["scope"] = st
    _T["mode"] = _T.get("mode") or "scope"
    th.start()
    time.sleep(min(float(period_ms) / 1000.0 * 3, 0.5))  # 先跑两三轮再回，便于看首值
    out = scope_read(limit=5)
    out["invalid"] = p["invalid"]
    out["hint"] = ("用 trace_scope_read 取样本、trace_scope_stop 收尾；"
                    "采样率是主机侧轮询率，**不代表目标真实执行周期**。"
                    "需要精确耗时用目标侧计时宏 + trace_dwt_counters")
    return out


def scope_read(limit: int = 200) -> dict:
    """看变量 scope 当前采样：只返回最近 limit 条 + 每变量统计。"""
    st = _T.get("scope")
    if not st:
        return {"ok": False, "error": "还没启动变量 scope",
                "hint": "trace_scope_start(vars=\"g_cnt@0x20000000:4\")"}
    lm = max(1, int(limit))
    sam = st["samples"]
    running = bool(st.get("thread") and st["thread"].is_alive())
    dur = ((st.get("stopped_at") or time.time()) - st["started_at"]) or 1e-9
    return {"ok": True, "running": running, "link": st.get("link"),
            "vars": st["vars"],
            "samples": len(sam), "shown": min(lm, len(sam)),
            "elapsed_s": round(dur, 3),
            "effective_hz": round(len(sam) / dur, 2),
            "reads": st["reads"], "misses": st["misses"],
            "require_halt": bool(st["require_halt"]),
            "last_error": st["last_error"], "intrusive": False,
            "by_var": st["by_var"],
            "recent": sam[-lm:],
            "warning": ("采样率是主机侧轮询率（%dms 一轮，每变量一次 mdw），"
                        "受 SWD 带宽/OS 调度影响，**不等于目标执行周期**；"
                        "轮询窗口之间的取值变化看不到。" % int(st["period_ms"] or 0))
            if not st["require_halt"] else
                       ("目标在跑时 OpenOCD 拒绝读内存（需 halt）——这条链路上"
                        "读到的全是丢点，请改用 RTT/ITM 让目标自己往外推数据")}


def scope_stop() -> dict:
    """停掉变量 scope，返回汇总（每变量 min/max/变化次数 + 真实采样率）。"""
    st = _T.get("scope")
    if not st:
        return {"ok": True, "stopped": False, "note": "没有在跑的变量 scope"}
    ev = st.get("stop_ev")
    if ev is not None:
        ev.set()
    th = st.get("thread")
    joined = False
    if th and th.is_alive():
        # 线程每轮最多阻塞 2s，join 给足两轮的时间；没退就如实说没退
        th.join(timeout=min(5.0, max(1.0, float(st["period_ms"]) / 1000.0 * 2 + 2.0)))
        joined = not th.is_alive()
    _T["scope"] = None
    _T["mode"] = None
    sam = st["samples"]
    dur = ((st.get("stopped_at") or time.time()) - st["started_at"]) or 1e-9
    return {"ok": True, "stopped": True, "link": st.get("link"),
            "vars": st["vars"],
            "samples": len(sam), "elapsed_s": round(dur, 3),
            "effective_hz": round(len(sam) / dur, 2),
            "reads": st["reads"], "misses": st["misses"],
            "require_halt": bool(st["require_halt"]),
            "last_error": st["last_error"], "by_var": st["by_var"],
            "intrusive": False, "thread_joined": joined,
            "warning": "轮询式观测：两次采样之间的变化看不到，"
                       "丢了几个点看 misses；要无丢点请用 RTT（目标侧缓冲）"}


def pc_sample(samples: int = 500, interval_ms: float = 10.0, elf: str = "",
              top: int = 15, enable_dwt: bool = True, restore: bool = True,
              timeout: float = 20.0, link: str = "auto") -> dict:
    """非 halt 的 PC 采样：开 DWT 硬件 PC 采样器，主机只轮询 DWT_PCSR。

    与 trace_profile（halt→读 PC→resume）的区别：**全程不停核**，
    因此不扰动实时性；代价是样本来自硬件采样器（速率受 POSTPRESET/POSTCNT 控制），
    而且部分芯片修订版上 PC 采样器根本不工作——那种情况会明确报
    `sampler_inactive` 而不是给一份看着像样的分布。
    """
    elf = str(elf or "").strip() or _session_axf()
    lk, lerr = _link.pick(link, who="读 DWT 寄存器")
    if lk is None:
        return dict(lerr)
    DEMCR, DWT_CTRL, DWT_PCSR = 0xE000EDFC, 0xE0001000, 0xE000101C

    def rd(addr):
        data, _meta = lk.read(int(addr), 4)
        if data is None or len(data) < 4:
            return None
        return int.from_bytes(data[:4], "little")

    def wr(addr, val):
        ok, _meta = lk.write(int(addr), int(val).to_bytes(4, "little"))
        return bool(ok)

    demcr0 = rd(DEMCR)
    ctrl0 = rd(DWT_CTRL)
    if demcr0 is None or ctrl0 is None:
        return {"ok": False, "error": "读 DWT/DEMCR 失败（目标没连上或不是 Cortex-M）",
                "hint": "RISC-V/Xtensa 没有 DWT，它们要用 mcycle CSR；见 trace_guide"}
    enabled = []
    if enable_dwt:
        # TRCENA(bit24) 不置位时 DWT 整个不工作
        if not (demcr0 & (1 << 24)):
            if not wr(DEMCR, demcr0 | (1 << 24)):
                return {"ok": False, "error": "写 DEMCR.TRCENA 失败",
                        "demcr": "0x%X" % demcr0}
            enabled.append("DEMCR.TRCENA")
        # PCSAMPLENA=bit12；POSTPRESET=bits[4:1]（置 0xF 让采样尽量慢下来，
        # 避免采样器疯狂覆盖而主机读不到变化）
        want = (ctrl0 | (1 << 12) | (0xF << 1)) & ~(0xF << 5)
        if wr(DWT_CTRL, want):
            enabled.append("DWT_CTRL.PCSAMPLENA")
        else:
            return {"ok": False, "error": "写 DWT_CTRL.PCSAMPLENA 失败",
                    "dwt_ctrl": "0x%X" % ctrl0,
                    "hint": "部分 Cortex-M 修订版不支持 PC 采样（PCSAMPLEENA 恒 0）"}
    pcs, distinct, fails = [], {}, 0
    t0 = time.time()
    n = max(1, int(samples))
    for _ in range(n):
        v = rd(DWT_PCSR)
        if v is None:
            fails += 1
        else:
            v &= ~1
            pcs.append(v)
            distinct[v] = distinct.get(v, 0) + 1
        if interval_ms and float(interval_ms) > 0:
            time.sleep(min(float(interval_ms) / 1000.0, 1.0))
        if time.time() - t0 > float(timeout):
            break
    ctrl1 = rd(DWT_CTRL)
    sampler_ok = bool(ctrl1 is not None and (ctrl1 & (1 << 12)))
    if restore:
        if ctrl0 is not None:
            wr(DWT_CTRL, ctrl0)
        if demcr0 is not None:
            wr(DEMCR, demcr0)
    dur = time.time() - t0
    out = {"ok": bool(pcs) and sampler_ok, "link": lk.name,
           "samples": len(pcs), "fails": fails,
           "requested": n, "duration_s": round(dur, 3),
           "effective_hz": round(len(pcs) / (dur or 1e-9), 2),
           "distinct_pcs": len(distinct), "intrusive": False,
           "sampler_enabled": sampler_ok, "enabled": enabled,
           "restored": bool(restore),
           "dwt_pcsr": "0xE000101C", "dwt_ctrl_after": ("0x%X" % ctrl1) if ctrl1 is not None else None}
    if not pcs:
        out["error"] = "一次 PC 采样都没读到"
        return out
    if not sampler_ok:
        out["error"] = "PC 采样器没使能上（DWT_CTRL.PCSAMPLENA 读回为 0）"
        out["hint"] = ("这条芯片/修订版上 DWT PC 采样不可用，**不给分布**；"
                       "要用非侵入式函数分布只能靠 SWO/ITM 插桩，"
                       "或在目标侧自己做 PCSAMPLE 计数")
        out["distinct_raw"] = len(distinct)
        return out
    funcs = elf_funcs(elf) if elf else []
    if len(pcs) >= 8 and len(distinct) <= 2:
        # 值不变时把“停在哪”说清楚，而不是只报一句“可能 errata”。
        # 真机上就是这么抓到固件 bug 的：PC 恒定 → 一查符号是 Default_Handler
        # → 向量表把 SysTick 接到了死循环（拦截不到的错误全是猜的，这里不猜）。
        out["ok"] = False
        where = []
        for pc in sorted(distinct)[:3]:
            nm = func_of(pc, funcs) if funcs else None
            where.append({"pc": "0x%X" % pc, "function": nm or "(ELF 里没有对应函数)"})
        out["stuck_at"] = where
        known = where[0].get("function") if where else None
        out["error"] = ("PC 采样值几乎不变（%d 个不同值 / %d 次读）"
                        "——采样器在跑但没反映执行流") % (len(distinct), len(pcs))
        if known and "Default_Handler" in str(known):
            out["diagnosis"] = ("目标停在 Default_Handler：有中断/异常被使能但没写处理函数"
                                "（最常见是向量表里某个入口填了默认死循环）")
            out["hint"] = ("对着 ELF 查一下是哪个向量：如果固件自己的中断处理函数存在，"
                            "就是向量表没指过去；找不到就确认是触发了一类异常"
                            "（读 0xE000ED28 CFSR / 0xE000ED2C HFSR）")
        else:
            out["hint"] = ("两种可能：目标真的全程停在同一循环（比如等标志、空转），"
                            "或 PC 采样器在该芯片修订版上不可用；"
                            "用 trace_profile（halt 采样，侵入式）交叉验证再下结论")
        return out
    by_func = {}
    for pc, c in distinct.items():
        fn = func_of(pc, funcs) if funcs else ("0x%X" % pc)
        by_func[fn] = by_func.get(fn, 0) + c
    tl = sorted(by_func.items(), key=lambda kv: -kv[1])[:max(1, int(top))]
    out["by_function"] = [{"function": k, "samples": v,
                           "percent": round(100.0 * v / max(1, len(pcs)), 2)}
                          for k, v in tl]
    out["top_pcs"] = [{"pc": "0x%X" % k, "samples": v}
                      for k, v in sorted(distinct.items(), key=lambda kv: -kv[1])[:int(top)]]
    out["elf"] = os.path.abspath(elf) if elf else None
    out["warning"] = ("DWT 硬件 PC 采样：不 halt 目标，但样本是「采样器最近一次采到的 PC」，"
                      "同一值会被重复读到，占比只能当参考；"
                      "POSTPRESET/POSTCNT 定了采样周期，采样率 ≠ 指令数")
    return out


# ================================================================ 插桩组件部署

def list_components() -> dict:
    if not os.path.isdir(COMPONENT_DIR):
        return {"ok": False, "error": "组件目录不存在：%s" % COMPONENT_DIR}
    files = []
    for root, _dirs, fs in os.walk(COMPONENT_DIR):
        for f in fs:
            p = os.path.join(root, f)
            files.append({"path": os.path.relpath(p, COMPONENT_DIR).replace("\\", "/"),
                          "bytes": os.path.getsize(p)})
    files.sort(key=lambda x: x["path"])
    return {"ok": True, "dir": COMPONENT_DIR, "count": len(files), "files": files}


# ============================ 组件部署后的链接自检
#
# 「拷进去了」不等于「编得过、链得上」。批次55 加 buff 后端时，头文件写了
# `extern mdk_trace_buff_blob_t mdk_trace_buff_blob;`，却没有任何 .c 定义它；
# 同族的 SWD 后端在 mdk_trace_swd.c 里有定义，是 buff 漏了。主机的 mock 用例
# 只造替身符号，照样全绿——少一个定义也能"通过"，直到用户第一次真编译才炸出
# `L6218E: Undefined symbol mdk_trace_buff_blob`。
#
# 所以部署完就地把组件真编一遍再链接：空壳提供 CMSIS 内在函数与入口，缺任何符号
# 都会在链接期以 undefined reference 现形——正是用户会撞到的那个报错的等价物，
# 而且发生在部署当场，不是他第一次 build 的时候。

_COMPONENT_BACKEND_MACRO = {
    "itm": "MDK_TRACE_BACKEND_ITM",
    "rtt": "MDK_TRACE_BACKEND_RTT",
    "uart": "MDK_TRACE_BACKEND_UART",
    "buff": "MDK_TRACE_BACKEND_BUFF",
    "swd": "MDK_TRACE_BACKEND_SWD",
    "none": "MDK_TRACE_BACKEND_NONE",
}

_COMPONENT_STUB_C = """/* mdkdebug link self-check stub: CMSIS intrinsics + entry point, nothing else.
 * It exists so the component can be linked on its own; any symbol it does NOT
 * provide must come from the component, or the check fails right here. */
#include <stdint.h>
uint32_t __get_PSP(void) { return 0u; }
uint32_t __get_MSP(void) { return 0u; }
uint32_t __get_PRIMASK(void) { return 0u; }
void __set_PRIMASK(uint32_t x) { (void)x; }
void __disable_irq(void) { }
void __enable_irq(void) { }
int main(void) { return 0; }
"""

def component_sources(backend: str) -> list:
    """该后端真正需要加入编译的组件源文件（next 清单与自检共用同一份）。"""
    b = (backend or "itm").strip().lower()
    srcs = ["mdk_trace.c"]
    if b in ("rtt", "uart"):
        srcs.append("mdk_trace_rtt.c")
    if b == "buff":
        srcs.append("mdk_trace_buff.c")
    if b == "swd":
        srcs.append("mdk_trace_swd.c")
    return srcs

def component_link_check(backend: str = "itm", src_dir: str = "",
                         family: str = "arm-none-eabi", cpu: str = "cortex-m4",
                         timeout: float = 240.0, keep_temp: bool = False) -> dict:
    """把该后端的组件源文件真编一遍并链接：缺符号（如没人定义的 blob）当场报出来。

    `checked` 与 `ok` 分开：找不到 C 编译器时 checked=False 且 ok=None（**没查**，
    不等于通过），调用方必须如实转述，不能把「没检查」说成「没问题」。
    """
    import shutil
    import tempfile

    from . import toolchain as _tc

    b = (backend or "itm").strip().lower()
    d = os.path.abspath(src_dir or COMPONENT_DIR)
    files = component_sources(b)
    missing_files = [f for f in files if not os.path.isfile(os.path.join(d, f))]
    if missing_files:
        return {"ok": False, "checked": True, "backend": b, "sources": files,
                "missing_symbols": [], "errors": [],
                "reason": "组件源文件缺失：%s" % ", ".join(missing_files)}
    gcc = _tc.find_tool(family, "gcc")
    if not gcc:
        return {"ok": None, "checked": False, "backend": b, "sources": files,
                "missing_symbols": [], "errors": [],
                "reason": "找不到 %s 的 C 编译器，未做链接自检" % family}
    tmp = tempfile.mkdtemp(prefix="mdk_trace_link_")
    try:
        stub = os.path.join(tmp, "_mdk_link_stub.c")
        with open(stub, "w", encoding="utf-8", newline="\n") as f:
            f.write(_COMPONENT_STUB_C)
        out = os.path.join(tmp, "out.elf")
        argv = ["-mcpu=%s" % cpu, "-mthumb", "-std=c99", "-O1",
                "-nostartfiles", "--specs=nosys.specs",
                "-I", d, "-DMDK_TRACE_ENABLE=1"]
        macro = _COMPONENT_BACKEND_MACRO.get(b)
        if macro:
            argv.append("-D%s=1" % macro)
        argv += [os.path.join(d, f) for f in files] + [stub, "-o", out]
        r = _tc.run_tool(gcc, argv, timeout=timeout)
        text = (r.get("stdout") or "") + "\n" + (r.get("stderr") or "")
        missing = sorted(set(re.findall(r"undefined reference to [`'\"]([^`'\"]+)", text)))
        ok = bool(r.get("ok")) and not missing
        res = {"ok": ok, "checked": True, "backend": b, "sources": files,
               "compiler": gcc, "missing_symbols": missing,
               "errors": [ln.strip() for ln in text.splitlines()
                          if "error" in ln.lower()][:6],
               "command": r.get("cmd") or (" ".join([gcc] + argv))}
        if ok:
            res["elf"] = out
        else:
            res["reason"] = ("组件缺符号：%s" % ", ".join(missing) if missing
                             else (r.get("error") or "编译/链接失败"))
            res["hint"] = ("缺的符号应该由组件自己的 .c 定义（buff 的 mdk_trace_buff_blob、"
                           "swd 的 mdk_trace_swd_blob 都在各自 .c 里）；确认 component_sources "
                           "列出的文件都进了编译，再重跑 trace_instrument。")
        if keep_temp:
            res["temp_dir"] = tmp
        return res
    finally:
        if not keep_temp:
            shutil.rmtree(tmp, ignore_errors=True)

def build_sources_check(src_dir: str = "", backend: str = "itm") -> dict:
    """构建清单自检：各处列出的 .c 与**实际存在的后端源文件**是否一致。

    比对三份「清单」：

    - `mdk_trace.mk(生成模板)`：工具自己生成的 Make 片段（改组件后最容易忘记同步的就是它）；
    - `mdk_trace.mk`：部署目录里的实际文件（可能被用户改过、或是旧版遗留）；
    - `CMakeLists.txt`：部署目录里的 CMake 清单。

    两个方向都查，缺一个都不算通过：

    - **漏**：目录里有 `mdk_trace_*.c` 却没被列出 —— 那条通路的代码根本没编进工程，
      要到链接期甚至运行时才暴露（`mdk_trace.mk` 与 `CMakeLists.txt` 历史上都漏过 `mdk_trace_swd.c`）；
    - **多**：清单列了目录里不存在的文件 —— 构建必然失败，而报错点在用户工程里。

    清单是「承诺」，目录里的 .c 是「事实」，两者不一致就是缺陷，不该等用户第一次 build 才发现。
    部署目录里没有某个清单文件时按「不适用」跳过（ok=None），既不冒充通过也不误报失败。
    """
    d = os.path.abspath(src_dir or COMPONENT_DIR)
    actual = sorted(f for f in os.listdir(d)
                    if f.startswith("mdk_trace") and f.endswith(".c"))
    texts = [("mdk_trace.mk(生成模板)", _gen_make_fragment())]
    for name in ("mdk_trace.mk", "CMakeLists.txt"):
        fp = os.path.join(d, name)
        if os.path.isfile(fp):
            try:
                texts.append((name, open(fp, encoding="utf-8", errors="replace").read()))
            except OSError as e:
                texts.append((name, "\n<读不了：%s>" % e))
        else:
            texts.append((name, ""))
    checks = {}
    for label, text in texts:
        if not text:
            checks[label] = {"ok": None, "reason": "该目录没有这个清单文件（不适用）"}
            continue
        listed = sorted(set(re.findall(r"mdk_trace[a-z_]*\.c", text)))
        missing = [f for f in actual if f not in listed]
        ghost = [f for f in listed if f not in actual]
        checks[label] = {"ok": (not missing and not ghost), "listed": listed,
                         "missing": missing, "ghost": ghost}
    bad = {k: v for k, v in checks.items() if v.get("ok") is False}
    out = {"ok": not bad, "dir": d, "actual": actual, "backend": backend,
           "checks": checks}
    if bad:
        bits = []
        for k, v in bad.items():
            if v.get("missing"):
                bits.append("%s 漏列 %s" % (k, ", ".join(v["missing"])))
            if v.get("ghost"):
                bits.append("%s 列了不存在的 %s" % (k, ", ".join(v["ghost"])))
        out["reason"] = "；".join(bits) or "构建清单与源文件不一致"
        out["hint"] = ("清单是承诺、目录里的 .c 是事实，两者必须一致：漏列该后端的 .c 会让"
                       "那条通路根本没编进去；改组件后同步更新 mdk_trace.mk 模板与 "
                       "CMakeLists.txt。")
    return out

def deploy_component(target_dir: str, backend: str = "itm", itm_port: int = 1,
                     rtt_up: int = 2, rtt_down: int = 1, rtt_buf: int = 1024,
                     coreclk: int = 0, overwrite: bool = False,
                     swo_baud: int = 2000000, dbgmcu_cr: int = 0xE0042004,
                     buff_records: int = 2048, buff_ts_shift: int = 0,
                     buff_clear_on_init: bool = False,
                     swd_bytes: int = 8192, swd_ts_shift: int = 0,
                     swd_clear_on_init: bool = True,
                     fault_frame: bool = True, link_check: bool = True) -> dict:
    """把插桩组件拷进工程，并生成 mdk_trace_config.h + 构建片段。

    复制完会就地做一次**编译 + 链接**自检（link_check，默认开）：组件缺符号
    （如某个后端忘了定义自己的 blob）当场报出来，而不是等用户第一次 build
    撞 L6218E。"""
    if not target_dir:
        return {"ok": False, "error": "target_dir 不能为空"}
    src = COMPONENT_DIR
    if not os.path.isdir(src):
        return {"ok": False, "error": "组件目录不存在：%s" % src}
    dst = os.path.abspath(target_dir)
    os.makedirs(dst, exist_ok=True)
    copied, skipped = [], []
    for root, _d, fs in os.walk(src):
        for f in fs:
            sp = os.path.join(root, f)
            rel = os.path.relpath(sp, src)
            dp = os.path.join(dst, rel)
            os.makedirs(os.path.dirname(dp), exist_ok=True)
            if os.path.exists(dp) and not overwrite:
                skipped.append(rel.replace("\\", "/"))
                continue
            try:
                with open(sp, "rb") as a, open(dp, "wb") as b:
                    b.write(a.read())
                copied.append(rel.replace("\\", "/"))
            except OSError as e:
                return {"ok": False, "error": "复制 %s 失败：%s" % (rel, e)}
    cfg = _gen_config_h(backend, itm_port, rtt_up, rtt_down, rtt_buf, coreclk,
                        swo_baud, dbgmcu_cr, buff_records=buff_records,
                        buff_ts_shift=buff_ts_shift,
                        buff_clear_on_init=buff_clear_on_init,
                        swd_bytes=swd_bytes, swd_ts_shift=swd_ts_shift,
                        swd_clear_on_init=swd_clear_on_init,
                        fault_frame=fault_frame)
    cfg_path = os.path.join(dst, "mdk_trace_config.h")
    if os.path.exists(cfg_path) and not overwrite:
        skipped.append("mdk_trace_config.h")
    else:
        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(cfg)
        copied.append("mdk_trace_config.h")
    mk = _gen_make_fragment()
    mk_path = os.path.join(dst, "mdk_trace.mk")
    if not (os.path.exists(mk_path) and not overwrite):
        with open(mk_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(mk)
        copied.append("mdk_trace.mk")
    b = (backend or "itm").strip().lower()
    sources = component_sources(b)
    nxt = ["把 %s 加入工程编译" % " / ".join(sources),
           "include mdk_trace.mk（Make）或 add_subdirectory（CMake）",
           "在初始化处调 mdk_trace_init()；用 MDK_TRACE_SCOPE() 打点",
           "在 HardFault / MemManage / BusFault / UsageFault handler 的**第一条**语句调 "
           "MDK_TRACE_FAULT_CAPTURE()（越早越好，栈还可能没被破坏），再进你的死循环；"
           "看门狗喂狗点、关键状态迁移用 MDK_TRACE_MARK()",
           "任务 / 线程切换处调 MDK_TRACE_SCHED(from, to)"]
    if b == "buff":
        nxt += ["buff 模式：目标跑完或出事后 trace_buff_dump(elf=你的.axf) 一次性读回",
                "buff 模式不需要 SWO 引脚、不需要主机实时跟读，但缓冲写满会覆盖最旧的",
                "buff 的存储由 mdk_trace_buff.c 定义（符号 mdk_trace_buff_blob，主机就靠这"
                "一个符号定位控制块与记录区）——这个 .c 必须进编译，漏了会报 "
                "L6218E: Undefined symbol mdk_trace_buff_blob"]
    elif b == "swd":
        nxt += ["swd 的存储由 mdk_trace_swd.c 定义（符号 mdk_trace_swd_blob），"
                "这个 .c 必须进编译；buff/swd 是各自独立的 blob，不要只加其中一个",
                "swd 模式：反复 trace_swd_read(elf=你的.axf) 把已录的那段搬走；"
                "主机平均搬运速度跟得上事件产生速度，就能一直录下去且零丢失",
                "swd 模式只要 SWD 两线：不要 SWO 引脚、不抢目标时间、不停机；"
                "背压而不是覆盖 —— 跟不上时目标丢新事件并计入 lost_events",
                "swd 模式可以把上下文切换、异常 handler 都插上（开销约几十个周期/条）"]
    else:
        nxt += ["SWO 通路：trace_swo_start + 目标侧 MDK_TRACE_BACKEND_ITM",
                "RTT 通路：trace_rtt_attach(elf=你的.elf)"]
    out = {"ok": True, "target_dir": dst, "copied": copied, "skipped": skipped,
           "backend": b, "itm_port": itm_port, "next": nxt, "sources": sources,
           "skip_note": "已存在的文件默认不覆盖（overwrite=true 才覆盖）"}
    if link_check:
        chk = component_link_check(backend=b, src_dir=dst)
        out["self_check"] = chk
        if chk.get("checked") and not chk.get("ok"):
            out["ok"] = False
            out["error_code"] = "component-link-failed"
            out["error"] = ("组件链接自检失败：%s —— 工程按现状接进构建会在链接期报 "
                            "undefined reference，先补全组件源码再继续。"
                            % (chk.get("reason") or "未知原因"))
            out["missing_symbols"] = chk.get("missing_symbols") or []
        elif not chk.get("checked"):
            out["self_check_note"] = ("未做链接自检（%s）——这不等于组件没问题"
                                      % (chk.get("reason") or "未提供原因"))
    else:
        out["self_check"] = {"checked": False, "reason": "link_check=false（调用方关闭）"}

    # 构建清单自检：与链接自检独立（不依赖 C 编译器），漏列一个后端源文件同样致命
    blc = build_sources_check(src_dir=dst, backend=b)
    out["build_list_check"] = blc
    if not blc.get("ok"):
        out["ok"] = False
        if not out.get("error_code"):
            out["error_code"] = "component-sources-mismatch"
        out["error"] = ("构建清单自检失败：%s —— 工程按现状接进构建会少编/误编源文件。"
                        % (blc.get("reason") or "清单与源文件不一致"))
    return out


def _gen_config_h(backend: str, itm_port: int, rtt_up: int, rtt_down: int,
                  rtt_buf: int, coreclk: int, swo_baud: int = 2000000,
                  dbgmcu_cr: int = 0xE0042004, buff_records: int = 2048,
                  buff_ts_shift: int = 0, buff_clear_on_init: bool = False,
                  swd_bytes: int = 8192, swd_ts_shift: int = 0,
                  swd_clear_on_init: bool = True,
                  fault_frame: bool = True) -> str:
    b = (backend or "itm").strip().lower()
    if b not in ("itm", "rtt", "uart", "none", "buff", "swd"):
        b = "itm"
    lines = [
        "#ifndef MDK_TRACE_CONFIG_H",
        "#define MDK_TRACE_CONFIG_H",
        "/* 由 mdkdebug 的 trace_instrument 生成；改这里不用改组件源码。 */",
        "",
        "#define MDK_TRACE_ENABLE          1",
        "#define MDK_TRACE_BACKEND_%s 1" % b.upper(),
        "#define MDK_TRACE_ITM_PORT        %d" % int(itm_port),
        "#define MDK_TRACE_RTT_UP_CHANNELS   %d" % int(rtt_up),
        "#define MDK_TRACE_RTT_DOWN_CHANNELS %d" % int(rtt_down),
        "#define MDK_TRACE_RTT_BUF_SIZE      %d" % int(rtt_buf),
        "#define MDK_TRACE_TEXT_BUF_SIZE     128",
        "#define MDK_TRACE_CPU_HZ            %d" % int(coreclk or 0),
        "#define MDK_TRACE_SWO_BAUD          %d" % int(swo_baud or 2000000),
        "#define MDK_TRACE_DBGMCU_CR         0x%08Xu" % (int(dbgmcu_cr or 0) & 0xFFFFFFFF),
        "/* buff 模式（MDK_TRACE_BACKEND_BUFF）：全速录、事后一次性读回 */",
        "/* 记录数 × 12 字节就是静态 RAM 占用，按芯片余量调 */",
        "#define MDK_TRACE_BUFF_RECORDS      %d" % int(buff_records),
        "/* dt 的时间粒度：0 = 每 CPU 周期（最细），>0 = 右移这么多位 */",
        "#define MDK_TRACE_BUFF_TS_SHIFT     %d" % int(buff_ts_shift),
        "/* 0 = 复位后保留上一次运行的记录（看门狗/fault 复位时那才是唯一证据） */",
        "#define MDK_TRACE_BUFF_CLEAR_ON_INIT %d" % (1 if buff_clear_on_init else 0),
        "/* fault handler 里多存一份寄存器现场（PC/LR/SP/xPSR/HFSR/MMFAR/BFAR） */",
        "#define MDK_TRACE_FAULT_FRAME       %d" % (1 if fault_frame else 0),
        "/* swd 模式（MDK_TRACE_BACKEND_SWD）：SWD 两线无缝流，压缩 + 背压 */",
        "/* 环容量（字节）：必须是 2 的幂；8192 字节约存 3400 条事件 */",
        "#define MDK_TRACE_SWD_BYTES         %d" % int(swd_bytes),
        "/* dt = DWT 周期 >> TS_SHIFT；0 = 最细。单个间隔超 2^32 周期（84MHz 下 51s）才需要抬 */",
        "#define MDK_TRACE_SWD_TS_SHIFT      %d" % int(swd_ts_shift),
        "/* 0 = 复位后保留上一次运行的环内容（两段会被无缝拼在一起，很危险） */",
        "#define MDK_TRACE_SWD_CLEAR_ON_INIT %d" % (1 if swd_clear_on_init else 0),
        "/* 把控制块的 cycles 换算成秒用；必填，否则时间轴只有周期数 */",
        "#define MDK_TRACE_SWD_CPU_HZ        %d" % int(coreclk or 0),
        "",
        "/* 事件 ID 区间（主机侧按区间分派语义） */",
        "#define MDK_TRACE_ID_APP_BASE      0x1000",
        "#define MDK_TRACE_ID_ISR_BASE      0x2000",
        "",
        "#endif /* MDK_TRACE_CONFIG_H */",
        "",
    ]
    return "\n".join(lines)


def _gen_make_fragment() -> str:
    return "\n".join([
        "# 由 mdkdebug 的 trace_instrument 生成：把插桩组件接进 Makefile",
        "# 用法：在你的 Makefile 里 `include path/to/mdk_trace.mk`",
        "MDK_TRACE_DIR ?= $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))",
        "# 四个源文件都可无脑编：未选中的后端会编成空目标文件（内容裹在 #if 里）",
        "# 每个后端自己的 blob（主机定位用的那个符号）就定义在它自己的 .c 里：",
        "#   buff -> mdk_trace_buff_blob（mdk_trace_buff.c）",
        "#   swd  -> mdk_trace_swd_blob（mdk_trace_swd.c）",
        "# 漏掉对应 .c 会在链接期报 undefined reference，不是运行时才出问题",
        "MDK_TRACE_SRCS := $(MDK_TRACE_DIR)/mdk_trace.c \\",
        "                  $(MDK_TRACE_DIR)/mdk_trace_buff.c \\",
        "                  $(MDK_TRACE_DIR)/mdk_trace_swd.c \\",
        "                  $(MDK_TRACE_DIR)/mdk_trace_rtt.c",
        "C_SOURCES  += $(MDK_TRACE_SRCS)",
        "C_INCLUDES += -I$(MDK_TRACE_DIR)",
        "",
    ])


# ============================ buff 模式（全速录制，事后一次性读回）
#
# 与 stream（ITM / RTT / UART）相对：目标侧把事件写进 RAM 里的环形缓冲，
# **一个字节都不出芯片**，内核不阻塞、不碰外设，所以能全速录；代价是容量有限
# （写满后新记录覆盖最旧的）、文本帧放不进 12 字节记录（单独计数）、
# 时间戳只存「与上一条的周期差」——绝对时刻由控制块里的 last_cycles 反推。
#
# 主机只做三件事：按符号定位 blob → 一次把记录区读回来 → 把 dt 累成时间轴。
# 记录格式（小端 12 字节）：[0]type [1]kind [2..3]id [4..7]arg [8..11]dt

_BUFF_MAGIC = b"MDKTBUF1"
_BUFF_VERSION = 1
_BUFF_REC_SIZE = 12
_BUFF_CTRL_BYTES = 80
_BUFF_SYMBOL = "mdk_trace_buff_blob"
_BUFF_FLAG_ENABLED = 1 << 0
_BUFF_FLAG_WRAPPED = 1 << 1
_BUFF_FLAG_RESTARTED = 1 << 2
_BUFF_RESET_REQ_OFF = 56

_BUFF_TYPES = {0: "raw", 1: "text", 2: "event", 3: "counter", 4: "isr",
               5: "mark", 6: "ts", 7: "kv", 8: "reset", 9: "fault",
               10: "sched"}
_BUFF_KINDS = {0: "enter", 1: "exit", 2: "point", 3: "abort"}
_BUFF_FAULT_CLASS = {0: "hardfault", 1: "memmanage", 2: "busfault",
                     3: "usagefault"}
_BUFF_FAULT_REGS = {0xFF01: "pc", 0xFF02: "lr", 0xFF03: "sp",
                    0xFF04: "hfsr", 0xFF05: "mmfar", 0xFF06: "bfar",
                    0xFF07: "xpsr"}

# CFSR 各状态位的名字。HardFault 现场只给一个 0x... 数字，读的人还得翻手册；
# 拆成「哪一类、哪一位」是这份 dump 最有用的地方之一——不拆的话，
# 一个 cfsr=0x00020000 到底是被谁打的，等于没说。
_CFSR_BITS = [
    (0x00000001, "IACCVIOL", "取指访问违规（MPU / XN）"),
    (0x00000002, "DACCVIOL", "数据访问违规（MPU）"),
    (0x00000008, "MUNSTKERR", "出栈时 MemManage"),
    (0x00000010, "MSTKERR", "入栈时 MemManage"),
    (0x00000080, "MMARVALID", "MMFAR 有效"),
    (0x00000100, "IBUSERR", "取指总线错误"),
    (0x00000200, "PRECISERR", "精确总线错误（BFAR 有效）"),
    (0x00000400, "IMPRECISERR", "非精确总线错误（回写缓冲）"),
    (0x00000800, "UNSTKERR", "出栈时 BusFault"),
    (0x00001000, "STKERR", "入栈时 BusFault"),
    (0x00008000, "BFARVALID", "BFAR 有效"),
    (0x00010000, "UNDEFINSTR", "未定义指令"),
    (0x00020000, "INVSTATE", "非法 EPSR / T 位（跳进了数据）"),
    (0x00040000, "INVPC", "非法 PC 加载（EXC_RETURN 用错）"),
    (0x00080000, "NOCP", "協处理器不可用（FPU 没使能）"),
    (0x00100000, "UNALIGNED", "非对齐访问"),
    (0x00200000, "DIVBYZERO", "除零"),
]

def _buff_cfsr_bits(cfsr: int) -> list:
    return [{"bit": "0x%08X" % b, "name": nm, "desc": ds}
            for b, nm, ds in _CFSR_BITS if cfsr & b]

def _buff_parse_names(spec: str) -> dict:
    """把 "0x10=switch,0x11=wait" 解成 {16: 'switch', 17: 'wait'}。

    buff 记录里只有数字 id，语义在应用里。让调用方把 id 表直接写进参数，
    比事后对着手册查要省事，也避免工具替应用“猜”名字。
    """
    out = {}
    for part in re.split(r"[,;]", spec or ""):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k or not v:
            continue
        try:
            out[int(k, 0)] = v
        except ValueError:
            continue
    return out

def _buff_locate(elf: str = "", addr=""):
    """定位控制块地址。只管地址，不读内容——校验魔数是读的人的责任。"""
    if addr:
        try:
            a = int(str(addr), 16) if str(addr).lower().startswith("0x") else int(addr)
            if a > 0:
                return a, {"method": "explicit"}
        except (TypeError, ValueError):
            pass
        return None, {"ok": False, "error_code": "invalid-argument",
                      "error": "addr 不是合法地址：%r" % (addr,)}
    e = elf or _session_axf()
    if e:
        a, sz = _elf_symbol(e, _BUFF_SYMBOL)
        if a:
            return a, {"method": "elf_symbol", "symbol": _BUFF_SYMBOL,
                       "blob_bytes": sz, "elf": os.path.abspath(e)}
        return None, {
            "ok": False, "error_code": "buff-symbol-missing",
            "error": "ELF 里找不到符号 %s" % _BUFF_SYMBOL,
            "elf": os.path.abspath(e),
            "hint": "① 固件是不是用 MDK_TRACE_BACKEND_BUFF 编的（stream 构建里根本没有这个符号）；"
                    "② 符号被 --gc-sections 回收了？给它 KEEP 或让代码真的引用到它；"
                    "③ 也可以直接用 addr=0x... 把 blob 地址喂进来"}
    return None, {"ok": False, "error_code": "buff-locate-failed",
                  "error": "既没给 addr 也没给 elf，无法定位 %s" % _BUFF_SYMBOL,
                  "hint": "给 elf=你的.axf（首选），或 addr=0x... 的 blob 绝对地址；"
                          "会话里已 set_symbol_file 过的话可以都不给"}

def _buff_parse_ctrl(raw: bytes, meta: dict, addr: int):
    """解析 80 字节控制块。魔数 / 版本 / 字段自洽性任一不过就报错，绝不硬解。"""
    view = {"addr": "0x%X" % addr,
            "read_confidence": (meta or {}).get("read_confidence"),
            "while_running": (meta or {}).get("while_running")}
    magic = raw[:8].split(b"\x00")[0].decode("ascii", "replace")
    if raw[:8] != _BUFF_MAGIC:
        deg = (meta or {}).get("degenerate")
        allz = raw.count(0) == len(raw)
        err = dict(view)
        err["ok"] = False
        err["magic"] = magic
        if allz or deg:
            err.update({
                "error_code": "buff-read-degenerate",
                "degenerate": deg or "all_zero",
                "error": "控制块位置整片读回 0x00，不是 'MDKTBUF1'"
                         "——**这不等于缓冲是空的**，是这次读不可信",
                "hint": "目标全速运行时经 SWD 读 SRAM 可能整片读回 0（Keil 链路实测如此）："
                        "① 先 stop（halt）目标再读——buff 模式的记录不会因停机丢失，缓存在 RAM 里；"
                        "② 或换链路重试；"
                        "③ 不要把这个 0 当成「没有事件」下结论。"})
        else:
            err.update({
                "error_code": "buff-magic-mismatch",
                "error": "这里不是 buff 控制块（读到魔数 %r，应为 'MDKTBUF1'）" % magic,
                "hint": "地址错了？用 elf= 让工具按符号 %s 定位" % _BUFF_SYMBOL})
        return None, err
    try:
        (version, rec_size, cap, recs_addr, head, total, lost, text_dropped,
         ts_shift, cpu_hz, last_cycles, flags, _reset_req, seq) = \
            struct.unpack_from("<14I", raw, 8)
    except struct.error as e:
        return None, dict(view, ok=False, error_code="buff-ctrl-truncated",
                          error="控制块解不开：%s" % e)
    if version != _BUFF_VERSION or rec_size != _BUFF_REC_SIZE:
        return None, dict(view, ok=False, error_code="buff-version-mismatch",
                          version=version, rec_size=rec_size,
                          error="控制块版本/记录尺寸与主机不一致（目标 version=%d "
                                "rec_size=%d，主机 support version=%d rec_size=%d）"
                                % (version, rec_size, _BUFF_VERSION, _BUFF_REC_SIZE),
                          hint="组件与主机不同版本：把 components/trace/ 和 mdkdebug/ "
                               "一起更新，不要只换一边")
    if cap == 0 or not recs_addr or cap * _BUFF_REC_SIZE > (1 << 22):
        return None, dict(view, ok=False, error_code="buff-ctrl-inconsistent",
                          error="控制块字段不合理（cap=%d recs_addr=0x%X）：地址大概不对"
                                % (cap, recs_addr),
                          hint="别按这个结果继续解析——先确认符号地址")
    info = dict(view)
    info.update({
        "symbol": _BUFF_SYMBOL, "version": version, "rec_size": rec_size,
        "cap": cap, "recs_addr": "0x%X" % recs_addr, "head": head,
        "total": total, "lost": lost, "text_dropped": text_dropped,
        "ts_shift": ts_shift, "cpu_hz": cpu_hz, "last_cycles": last_cycles,
        "flags": flags, "enabled": bool(flags & _BUFF_FLAG_ENABLED),
        "wrapped": bool(flags & _BUFF_FLAG_WRAPPED),
        "restarted": bool(flags & _BUFF_FLAG_RESTARTED), "seq": seq,
        "kept": cap if (flags & _BUFF_FLAG_WRAPPED) else head,
        "fits_in_buffer": total <= cap,
    })
    return info, None

def _buff_read_ctrl(addr: int, link: str = "auto"):
    raw, meta = _read_mem_words(addr, _BUFF_CTRL_BYTES, link=link)
    if raw is None:
        return None, {"ok": False, "addr": "0x%X" % addr,
                      "error_code": "buff-read-failed",
                      "error": (meta or {}).get("error") or "读控制块失败",
                      "link": (meta or {}).get("link")}
    if len(raw) < _BUFF_CTRL_BYTES:
        return None, {"ok": False, "addr": "0x%X" % addr,
                      "error_code": "buff-read-failed",
                      "error": "只读到 %d 字节（要 %d）：目标没响应或地址跨了不可读区"
                               % (len(raw), _BUFF_CTRL_BYTES)}
    return _buff_parse_ctrl(raw, meta or {}, addr)

def _buff_read_recs(recs_addr: int, n_recs: int, link: str = "auto",
                    chunk_recs: int = 256):
    """把记录区一次性读回来（分块以防单次读太大）。读短了就报错，不补 0 充数。"""
    out = bytearray()
    meta = {}
    done = 0
    while done < n_recs:
        take = min(chunk_recs, n_recs - done)
        addr = recs_addr + done * _BUFF_REC_SIZE
        want = take * _BUFF_REC_SIZE
        d, m = _read_mem_words(addr, want, link=link)
        if d is None:
            return None, {"ok": False, "error_code": "buff-read-failed",
                          "error": (m or {}).get("error") or "读记录区失败",
                          "at": "0x%X" % addr,
                          "records_read": done,
                          "link": (m or {}).get("link")}
        if len(d) < want:
            return None, {"ok": False, "error_code": "buff-read-short",
                          "error": "记录区读短了：0x%X 处读到 %d 字节，期望 %d"
                                   % (addr, len(d), want),
                          "records_read": done}
        out += d
        meta = m or meta
        done += take
    return bytes(out), meta

def buff_status(elf: str = "", addr="", link: str = "auto") -> dict:
    """只读控制块（80 字节）的健康快照：值得信、但便宜。"""
    a, loc = _buff_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    info, err = _buff_read_ctrl(a, link=link)
    if info is None:
        return err
    out = dict(info)
    out["ok"] = True
    out["locate"] = loc
    out["next"] = ["trace_buff_dump 把记录解成时间线",
                   "trace_buff_reset 让目标开一段新录制"]
    if not out["cpu_hz"]:
        out.setdefault("warnings", []).append(
            "控制块里 cpu_hz=0：dt 只能给周期数，给不了微秒。"
            "把 MDK_TRACE_CPU_HZ（或 trace_instrument 的 coreclk=）设成真实主频。")
    if out["lost"] or out["text_dropped"]:
        out.setdefault("warnings", []).append(
            "lost=%d text_dropped=%d：这次录制不是完整的，时间线上有没记下来的东西"
            % (out["lost"], out["text_dropped"]))
    if out["wrapped"]:
        out.setdefault("warnings", []).append(
            "环形缓冲已回卷（total=%d > cap=%d）：现在看到的是一个窗口，不是全程"
            % (out["total"], out["cap"]))
    if out["restarted"]:
        out.setdefault("warnings", []).append(
            "目标在保留旧记录的情况下重启过（seq=%d）：时间轴在 RESET 记录处分段"
            % out["seq"])
    return out

def _buff_decode(info: dict, recs: bytes, names: dict = None) -> dict:
    """把定长记录解成带绝对时间的事件序列 + 统计 + 异常现场。"""
    names = names or {}
    cap = info["cap"]
    # 只解码**真正读回来**的那几条（head 条或回卷后的 cap 条）。
    # 不能按 cap 去翻 recs：没回卷时记录区后半截是上一次运行的残渣或 0，
    # 把它们当记录解出来就是凭空多出一段假时间线。
    n_have = len(recs) // _BUFF_REC_SIZE
    raw_recs = []
    for i in range(n_have):
        b = recs[i * _BUFF_REC_SIZE:(i + 1) * _BUFF_REC_SIZE]
        raw_recs.append({
            "type": b[0], "kind": b[1],
            "id": b[2] | (b[3] << 8),
            "arg": struct.unpack_from("<I", b, 4)[0],
            "dt": struct.unpack_from("<I", b, 8)[0],
        })
    # 回卷时最旧的一条在 head 处；没回卷时 0..head-1 就是全部。
    order = (list(range(info["head"], cap)) + list(range(0, info["head"]))
             if info["wrapped"] else list(range(0, info["head"])))
    ts_shift = info["ts_shift"]
    total_dt = 0
    for idx in order:
        total_dt += raw_recs[idx]["dt"] << ts_shift
    cpu_hz = info["cpu_hz"]
    # last_cycles 是**最新**记录的时刻；往前扣掉所有 dt 就是起点。
    t0 = (info["last_cycles"] - total_dt) & 0xFFFFFFFF
    events = []
    t = t0
    by_type, by_id, by_kind = {}, {}, {}
    faults = []
    cur_fault = None
    for n, idx in enumerate(order):
        r = raw_recs[idx]
        t = (t + (r["dt"] << ts_shift)) & 0xFFFFFFFF
        typ = _BUFF_TYPES.get(r["type"], "type%d" % r["type"])
        ev = {"n": n, "type": typ, "id": r["id"], "arg": r["arg"],
              "dt": r["dt"] << ts_shift, "t_cycles": t}
        if typ in ("event", "isr"):
            ev["kind"] = _BUFF_KINDS.get(r["kind"], "kind%d" % r["kind"])
        if cpu_hz:
            ev["t_us"] = round((t - t0) / float(cpu_hz) * 1e6, 3)
        nm = names.get(r["id"])
        if nm and typ in ("event", "isr", "counter", "sched"):
            ev["id_name"] = nm
        if typ == "fault":
            ev["fault_class"] = _BUFF_FAULT_CLASS.get(r["id"], "class%d" % r["id"])
            ev["cfsr"] = "0x%08X" % r["arg"]
            ev["cfsr_bits"] = _buff_cfsr_bits(r["arg"])
            cur_fault = {"n": len(faults), "t_us": ev.get("t_us"),
                         "class": ev["fault_class"], "cfsr": ev["cfsr"],
                         "cfsr_bits": ev["cfsr_bits"], "registers": {}}
            faults.append(cur_fault)
        elif typ == "sched":
            ev["from"] = r["id"]
            ev["to"] = r["arg"]
        elif typ == "counter" and r["id"] in _BUFF_FAULT_REGS:
            reg = _BUFF_FAULT_REGS[r["id"]]
            ev["reg"] = reg
            ev["value_hex"] = "0x%08X" % r["arg"]
            if cur_fault is not None and reg not in cur_fault["registers"]:
                cur_fault["registers"][reg] = "0x%08X" % r["arg"]
        by_type[typ] = by_type.get(typ, 0) + 1
        by_id[r["id"]] = by_id.get(r["id"], 0) + 1
        if "kind" in ev:
            by_kind[ev["kind"]] = by_kind.get(ev["kind"], 0) + 1
        events.append(ev)
    return {"events": events, "raw": raw_recs, "t0": t0,
            "by_type": by_type, "by_id": by_id, "by_kind": by_kind,
            "faults": faults}

def buff_dump(elf: str = "", addr="", limit: int = 200, out_file: str = "",
              names: str = "", link: str = "auto") -> dict:
    """读回整个环形缓冲并解成时间线。返回最新 limit 条；全量可落 out_file。"""
    a, loc = _buff_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    info, err = _buff_read_ctrl(a, link=link)
    if info is None:
        return err
    n_recs = info["kept"]
    if n_recs <= 0:
        out = dict(info, ok=True, locate=loc, record_count=0, events=[],
                   note="环形缓冲里还没有记录：固件调过 mdk_trace_init() 了吗？"
                        "有没有真的触发过带插桩的代码路径？")
        return out
    recs, rmeta = _buff_read_recs(int(info["recs_addr"], 16), n_recs, link=link)
    if recs is None:
        return rmeta
    dec = _buff_decode(info, recs, _buff_parse_names(names))
    evs = dec["events"]
    lim = max(1, int(limit or 200))
    tail = evs[-lim:] if len(evs) > lim else evs
    dts = [e["dt"] for e in evs if e["dt"]]
    span_cycles = (evs[-1]["t_cycles"] - evs[0]["t_cycles"]) & 0xFFFFFFFF
    out = dict(info)
    out.update({
        "ok": True, "locate": loc, "record_count": len(evs),
        "buffer_window_truncated": bool(info["wrapped"]),
        "counts_by_type": dec["by_type"], "counts_by_kind": dec["by_kind"],
        "top_ids": sorted(({"id": k, "count": v} for k, v in dec["by_id"].items()),
                          key=lambda x: -x["count"])[:20],
        "span_cycles": span_cycles,
        "span_us": round(span_cycles / float(info["cpu_hz"]) * 1e6, 3)
                   if info["cpu_hz"] else None,
        "dt_cycles": {"min": min(dts), "max": max(dts),
                      "mean": round(sum(dts) / float(len(dts)), 1)} if dts else None,
        "faults": dec["faults"],
        "read_meta": {k: rmeta.get(k) for k in
                      ("read_confidence", "while_running", "degenerate",
                       "read_unstable", "reread_count")
                      if k in rmeta},
        "events": tail,
        "truncated": len(evs) > lim,
        "next": ["trace_buff_reset 让目标开一段新录制",
                 "要看某个 id 的语义就把 id 表用 names=\"0x10=switch,0x11=wait\" 传进来"],
    })
    if out["lost"] or out["text_dropped"]:
        out.setdefault("warnings", []).append(
            "lost=%d text_dropped=%d：有记录没被记下来，这条时间线不完整"
            % (info["lost"], info["text_dropped"]))
    if info["restarted"]:
        out.setdefault("warnings", []).append(
            "目标重启过且保留了旧记录（seq=%d）：看到 reset 类型的事件处就是接缝，"
            "那之前的时间轴属于上一次运行" % info["seq"])
    if dec["faults"]:
        out.setdefault("warnings", []).append(
            "录到 %d 次异常（fault 类型），faults 字段里是异常的类别、CFSR 拆位与寄存器现场"
            % len(dec["faults"]))
    if info["wrapped"]:
        out.setdefault("warnings", []).append(
            "环形缓冲已回卷（total=%d > cap=%d）：现在看到的是一个窗口，不是全程——"
            "想圈定一段完整过程就先把目标 halt 再 trace_buff_reset，然后重新跑一遍"
            % (info["total"], info["cap"]))
    if out_file:
        try:
            p = os.path.abspath(out_file)
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(p, "w") as f:
                json.dump({"meta": {k: v for k, v in out.items()
                                    if k not in ("events", "next", "locate")},
                           "events": evs, "counts_by_type": dec["by_type"],
                           "top_ids": out["top_ids"], "faults": dec["faults"]},
                          f, ensure_ascii=False, default=str)
            out["out_file"] = p
            out["out_records"] = len(evs)
        except OSError as e:
            out.setdefault("warnings", []).append("写 out_file 失败：%s" % e)
    return out

def buff_reset(elf: str = "", addr="", wait: bool = True, link: str = "auto") -> dict:
    """请目标开一段新录制：置控制块的 reset_req，目标在下一条记录写入时执行。"""
    a, loc = _buff_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    info, err = _buff_read_ctrl(a, link=link)
    if info is None:
        return err
    seq0 = info["seq"]
    w = _write_mem(a + _BUFF_RESET_REQ_OFF, struct.pack("<I", 1))
    out = {"ok": bool(w.get("ok")), "addr": "0x%X" % a, "locate": loc,
           "wrote": "0x%X" % (a + _BUFF_RESET_REQ_OFF), "write_meta": w,
           "seq_before": seq0}
    if not w.get("ok"):
        out["error_code"] = "buff-reset-write-failed"
        out["error"] = w.get("error") or "写 reset_req 失败"
        out["hint"] = ("目标全速运行时写 SRAM 可能不生效（Keil 链路尤其如此）："
                       "先 halt（stop）目标再试；实在不行让固件自己调 "
                       "mdk_trace_buff_reset()。")
        return out
    if not wait:
        out["applied"] = False
        out["note"] = "已请求，但 reset_req 只在下一条记录写入时被处理"
        return out
    info2, err2 = _buff_read_ctrl(a, link=link)
    if info2 is None:
        out["applied"] = False
        out["pending"] = True
        out["note"] = "写入成功，但控制块重读失败，无法确认是否已生效"
        out["reread_error"] = err2.get("error") if err2 else None
        return out
    applied = info2["seq"] != seq0
    out["seq_after"] = info2["seq"]
    out["applied"] = applied
    out["request_latched"] = None if applied else True
    if applied:
        out["note"] = "新录制已开始（seq %d -> %d）：现在缓存里是这一段的新记录" \
                      % (seq0, info2["seq"])
    else:
        out["note"] = ("reset_req 已写进去但还没被执行（seq 仍是 %d）：它在下一条记录写入时"
                       "才处理。目标若长期没有插桩事件，它会一直挂着——这不是失败，"
                       "但也不能当成『已清空』。" % seq0)
        out.setdefault("warnings", []).append(
            "别把 pending 当成 applied：要看有没有生效就再读一次 trace_buff_status 看 seq。")
    return out

# ============================ swd 无缝流模式（压缩 + 背压；SWD 两线连续录）
#
# 和 buff 的分工一句话说清：
#   buff = 写满覆盖最旧的，事后一次性读回 —— 用来圈一段**短过程**；
#   swd  = 未读区永不被覆盖，主机增量搬走 —— 用来录**全程**。
#
# 目标把事件压进 RAM 环（典型 2.3 字节/事件），主机每次只搬走 [drained, head)
# 并把 drained 推上去，环于是循环使用。只要主机平均搬运速度 ≥ 事件产生速度，
# 这个录制就永远不结束、也不丢东西——这就是「无缝」。
#
# 三条必须如实告诉用户的边界（不藏着）：
#   ① 主机跟不上时目标**丢弃新事件**（绝不覆盖未读区），权威计数在 lost_events；
#   ② 字典只有 64 槽：事件四元组 (type,kind,id,arg) 的工作集超过 64 种时命中率
#      崩塌，压缩比从 ~5x 掉到 1x 上下（这时该归并 id，或改用 buff 模式）；
#   ③ 主机「半路接管」时流里没有起点信息——会话第一条事件之前的绝对时刻拿不到，
#      只能给相对时刻（返回里 time_origin 字段说明用的是哪种）。

_SWD_MAX_SESSION_EVENTS = 500000


def _swd_locate(elf: str = "", addr=""):
    """定位 blob 地址。只管地址，不读内容——校验魔数是读的人的责任。"""
    if addr:
        try:
            a = int(str(addr), 16) if str(addr).lower().startswith("0x") else int(addr)
            if a > 0:
                return a, {"method": "explicit"}
        except (TypeError, ValueError):
            pass
        return None, {"ok": False, "error_code": "invalid-argument",
                      "error": "addr 不是合法地址：%r" % (addr,)}
    e = elf or _session_axf()
    if e:
        a, sz = _elf_symbol(e, _swd.SYMBOL)
        if a:
            return a, {"method": "elf_symbol", "symbol": _swd.SYMBOL,
                       "blob_bytes": sz, "elf": os.path.abspath(e)}
        return None, {
            "ok": False, "error_code": "swd-symbol-missing",
            "error": "ELF 里找不到符号 %s" % _swd.SYMBOL,
            "elf": os.path.abspath(e),
            "hint": "① 固件是不是用 MDK_TRACE_BACKEND_SWD 编的（别的后端里根本没有这个符号）；"
                    "② 符号被 --gc-sections 回收了？让它被真正引用到；"
                    "③ 也可以 addr=0x... 直接给 blob 地址"}
    return None, {"ok": False, "error_code": "swd-locate-failed",
                  "error": "既没给 addr 也没给 elf，无法定位 %s" % _swd.SYMBOL,
                  "hint": "给 elf=你的.axf（首选），或 addr=0x...；"
                          "会话里已 set_symbol_file 过的话可以都不给"}


def _swd_read_ctrl(addr: int, link: str = "auto"):
    raw, meta = _read_mem_words(addr, _swd.CTRL_BYTES, link=link)
    if raw is None:
        return None, {"ok": False, "addr": "0x%X" % addr,
                      "error_code": "swd-read-failed",
                      "error": (meta or {}).get("error") or "读控制块失败",
                      "link": (meta or {}).get("link")}
    info = _swd.parse_ctrl(raw, addr)
    if not info.get("ok"):
        if raw.count(0) == len(raw):
            info = dict(info)
            info["degenerate"] = "all_zero"
            info["error_code"] = "swd-read-degenerate"
            info["error"] = ("控制块位置整片读回 0x00 —— **这不等于没有事件**，"
                             "是这次读不可信")
            info["hint"] = ("目标全速运行时经 SWD 读 SRAM 可能整片读回 0（Keil 链路实测如此）："
                            "① 先 halt 再读——无缝流的未读数据不会因停机丢失；"
                            "② 或换链路重试；③ 别把这个 0 当成「没有事件」下结论。")
        return None, info
    info["addr"] = "0x%X" % addr
    info["ctrl_addr"] = addr
    info["read_meta"] = {k: (meta or {}).get(k) for k in
                         ("read_confidence", "while_running", "degenerate",
                          "read_unstable", "reread_count") if k in (meta or {})}
    return info, None


# 一次 UVSOCK 请求最多能搬多少字节（client.MAX_CHUNK 就是 16384）。
# 环的默认容量 8192 因此**一请求就能搬完**：零碎的 1KB 分块会把缓冲区
# 对应的 UVSOCK 往返次数抬 8 倍，而往返开销才是这条通路的瓶颈（真机实测
# 1KB 分块只有 ~3B/ms，搬不过目标 6B/ms 的产出速度）。
_SWD_READ_CHUNK = 16384

# 伪值签名判定门槛：至少 16 字节（4 个相同的、字节不全同的字）才算伪值。
# 环的增量搬运常常一次只有几十字节，门槛太低会把正常小段误判成脏读。
_SWD_FAKE_MIN = 16


def _swd_fake_kind(data: bytes) -> str:
    """对**搬回来的整段字节**做伪值签名检查（不看 meta）。返回原因或 ""。

    真机实测（STM32F427 + Keil UVSOCK）：目标全速运行时经 SWD 读 SRAM 的某些区段
    （实测 ≥ 0x20004000，以及外设区）会整段重复同一个 4 字节字。它既不是全 0
    也不是全 FF，旧检测认不出来，于是伪值被当正常字节流解码——结果是失步 + 丢事件，
    而且看起来像「目标丢了数据」。
    """
    if not data or len(data) < _SWD_FAKE_MIN:
        return ""
    if all(b == 0x00 for b in data):
        return "all_zero"
    if all(b == 0xFF for b in data):
        return "all_ff"
    # 「重复字」必须**扫描着找**，不能只看整段：真机上往往只有一段（实测是
    # 环尾跨过 0x20004000 的那截）是伪值，前半段完全正常——整段判定会漏掉。
    # 逐字节滑动（不假设 4 字节对齐：起点取决于 drained，不必对齐），
    # 连续 12 个相等的相邻四字节窗 = 有 ≥ 16 字节的重复区；再看这个字是不是
    # 字节全同（HITN 密集段就是 0x40 连发，那是**正常**流，不能判伪）。
    run = 0
    for i in range(max(0, len(data) - 8)):
        if data[i:i + 4] == data[i + 4:i + 8]:
            run += 1
            if run >= 12 and len(set(data[i:i + 4])) > 1:
                return "repeated_word"
        else:
            run = 0
    return ""


def _swd_resume(lk) -> None:
    """停机搬运收尾：把目标放回运行态（失败不报，调用方自己会看到状态）。"""
    if lk is None:
        return
    try:
        lk.resume()
    except Exception:                                               # noqa: BLE001
        pass


def _swd_read_stream(ring_addr: int, cap: int, start: int, n: int,
                     link: str = "auto", chunk: int = _SWD_READ_CHUNK):
    """按**逻辑**偏移 [start, start+n) 读环内容，跨环尾时自动分两段。

    只读用得着的那一段，不整片搬：增量搬运是这条通路的核心动作，
    每次多读一倍就是白花一倍的调试链路时间。

    字节一律**单次读**（raw）：环正被目标持续覆写，复读比对永远不一致，
    只会把每一块拖成两倍时间、还把后一帧当结果拼进来（失步的直接成因）。
    """
    out = bytearray()
    meta = {}
    done = 0
    while done < n:
        take = min(chunk, n - done)
        phys = (start + done) & (cap - 1)
        first = min(take, cap - phys)
        d, m = _read_mem_words(ring_addr + phys, first, link=link, raw=True)
        if d is None:
            return None, {"ok": False, "error_code": "swd-read-failed",
                          "error": (m or {}).get("error") or "读环形缓冲失败",
                          "at": "0x%X" % (ring_addr + phys),
                          "bytes_read": done, "link": (m or {}).get("link")}
        if len(d) < first:
            return None, {"ok": False, "error_code": "swd-read-short",
                          "error": "环形缓冲读短了：0x%X 处读到 %d 字节，期望 %d"
                                   % (ring_addr + phys, len(d), first),
                          "bytes_read": done,
                          "hint": "目标可能刚被 halt 或正在复位；重试一次通常就好"}
        out += d
        meta = m or meta
        rest = take - first
        if rest:
            d2, m2 = _read_mem_words(ring_addr, rest, link=link, raw=True)
            if d2 is None or len(d2) < rest:
                return None, {"ok": False, "error_code": "swd-read-short",
                              "error": "环形缓冲回绕段读失败/读短（0x%X，期望 %d 字节）"
                                       % (ring_addr, rest),
                              "bytes_read": done + first}
            out += d2
            meta = m2 or meta
        done += take
    return bytes(out), meta


def _swd_session(addr: int) -> dict:
    s = _T.get("swd")
    if s is None or s.get("addr") != addr:
        s = {"addr": addr, "dec": _swd.Decoder(), "events": [], "faults": [],
             "drained": None, "seq": None, "rel_cycles": 0, "restarts": 0,
             "syncs": 0, "bytes_read": 0, "events_seen": 0,
             "anchor_cycle": None, "cursor_write_failed": False,
             "gran": None}
        _T["swd"] = s
    return s


def _swd_fold(s: dict, items: list, ts_shift: int, cpu_hz: int,
              names: dict, dt_unit: int = 0, ts_off: bool = False,
              task_names: dict = None, idle_name: str = "idle") -> list:
    """把解码出的 token 序列折成带时间的事件列表，并推进会话的时间累计。

    gap / sync 要按**流里的先后**插进事件序列（因此用 Decoder.items 而不是把
    events 与 ctl 分开看）——时间轴上一条断口画在哪一格，取决于它前面是哪条事件。

    dt 的量化单位由目标侧控制块决定，三分支（顺序固定、与固件一致）：
      ts_off  → 整条流没有时间戳：dt_cycles / t_us 一律给 None，绝不按到达顺序
                编一个假的相对时间（那会让下游以为这是一条有时间轴的数据）；
      dt_unit → dt * dt_unit（整数除法得来的，粒度可以不是 2 的幂，
                内核 tick 500us = 42000 周期正是这种情况）；
      ts_shift→ dt << ts_shift；两者都为 0 就是 1 周期 / 单位，最细。
    """
    out = []
    cur_fault = None
    for it in items:
        if it[0] == "ctl":
            sub, val = it[1], it[2]
            tm = {"ts": "none"} if ts_off else {"rel_cycles": s["rel_cycles"]}
            if sub == _swd.CTL_LOST:
                ev = {"type": "gap", "kind": "lost", "events_dropped": val,
                      "note": "目标在这里丢了 %d 条事件（宿主没跟上）" % val}
                ev.update(tm)
                out.append(ev)
            elif sub == _swd.CTL_SYNC:
                s["syncs"] += 1
                ev = {"type": "sync", "kind": "point", "seq": val,
                      "note": "目标在这里重开了录制段（seq=%d），字典已清" % val}
                ev.update(tm)
                out.append(ev)
            continue
        key, dt = it[1], it[2]
        t, k, i, a = key
        dcyc = None
        if not ts_off:
            dcyc = (dt * dt_unit) if dt_unit else (dt << ts_shift)
            s["rel_cycles"] = (s["rel_cycles"] + dcyc) & _swd.U32
        s["events_seen"] += 1
        typ = _swd.TYPES.get(t, "type%d" % t)
        ev = {"type": typ, "kind": _swd.KINDS.get(k, "kind%d" % k),
              "id": i, "arg": a}
        if ts_off:
            ev["dt_cycles"] = None
            ev["ts"] = "none"
        else:
            ev["dt_cycles"] = dcyc
            ev["rel_cycles"] = s["rel_cycles"]
            if cpu_hz:
                ev["t_us"] = round(s["rel_cycles"] * 1e6 / cpu_hz, 3)
        nm = names.get(i)
        if nm:
            ev["id_name"] = nm
        if typ == "sched":
            # 真实 token：id = from，arg = to（目标侧 mdk_trace_sched(from, to) ->
            # mdk_trace_swd_event(SCHED, K_POINT, from, to)）。目标是应用任务号：
            # 0..14 是任务表下标，0xF 是 idle。
            # 旧代码按「arg = from << 4 | to」解、且只在 id == 0 时解——那是
            # SVCRT_TR_SW_PACK 那套从没用上的编码，结果就是**几乎每条上下文切换都
            # 没有 from/to**，时间轴上整个任务维度等于不存在。buff 路径一直解的是
            # id/arg，两条路现在一致。
            ev["from"] = i
            ev["to"] = a
            if i > 0xF or a > 0xF:
                ev["warn"] = ("调度事件的 from/to 超出 0..15（id=%d arg=%d）："
                              "这条 token 可能不是上下文切换" % (i, a))
        elif typ == "fault" and _swd.FAULT_BASE <= i < _swd.FAULT_BASE + 0x100:
            ev["fault_class"] = _swd.FAULT_CLASS.get(i - _swd.FAULT_BASE, "unknown")
            ev["cfsr"] = "0x%08X" % a
            ev["cfsr_bits"] = _buff_cfsr_bits(a)
            cur_fault = {"class": ev["fault_class"], "cfsr": ev["cfsr"],
                         "cfsr_bits": ev["cfsr_bits"], "registers": {},
                         "_ev": ev}
            s["faults"].append(cur_fault)
        elif typ == "kv" and i in _swd.FAULT_REGS:
            ev["reg"] = _swd.FAULT_REGS[i]
            ev["value_hex"] = "0x%08X" % a
            if cur_fault is not None and ev["reg"] not in cur_fault["registers"]:
                cur_fault["registers"][ev["reg"]] = ev["value_hex"]
        out.append(ev)
    if task_names is not None:
        # 名字在这里一次性补上：事件里存的是**原始** id/arg/from/to，所以即使
        # 名字是后到的（会话中途才解析出任务表），也能回头重补（见 _swd_rename）。
        _apply_task_names(out, task_names, idle_name)
    return out


def _swd_anchor(s: dict, anchor: int, cpu_hz: int, out: list) -> None:
    """把本批事件从「会话起点为 0」换算成绝对 DWT 周期。

    anchor 是**会话最后一条事件**的绝对周期数（取自控制块 cycles）。
    往前按 dt 倒推即可，不需要另存每条的绝对时刻。
    """
    rel_total = s["rel_cycles"]
    for ev in out:
        if "rel_cycles" not in ev:
            continue
        cyc = (anchor - rel_total + ev["rel_cycles"]) & _swd.U32
        ev["cycles"] = cyc
        if cpu_hz:
            ev["t_us"] = round(cyc * 1e6 / cpu_hz, 3)
    for f in s["faults"]:
        ev = f.get("_ev")
        if ev is not None and "cycles" in ev:
            f["cycles"] = ev["cycles"]
            f["t_us"] = ev.get("t_us")
            f.pop("_ev", None)


def _swd_session_view(s: dict, limit: int = 0) -> dict:
    evs = s["events"]
    faults = [{k: v for k, v in f.items() if k != "_ev"} for f in s["faults"]]
    by_type, by_id = {}, {}
    for e in evs:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        if "id" in e:
            by_id[e["id"]] = by_id.get(e["id"], 0) + 1
    lim = int(limit or 0)
    tail = evs[-lim:] if (lim and len(evs) > lim) else evs
    return {
        "event_count": len(evs),
        "counts_by_type": by_type,
        "top_ids": sorted(({"id": k, "count": v} for k, v in by_id.items()),
                          key=lambda x: -x["count"])[:20],
        "faults": faults,
        "events": tail,
        "truncated": bool(lim and len(evs) > lim),
    }


def _swd_gran_desc(info: dict) -> dict:
    """把控制块里的量化参数翻成人话——别让调用方自己拼 ts_shift / dt_unit / ts_off。

    `unit_cycles` 是「一个 dt 单位 = 多少个 CPU 周期」，是**唯一**该拿去做换算的数；
    cpu_hz 已知时再补一个 unit_us。ts_off 时 unit_cycles 给 None：这段流压根没有
    时间维度，给个数就等于在编。
    """
    ts_off = bool(info.get("ts_off"))
    du = info.get("dt_unit") or 0
    sh = info.get("ts_shift") or 0
    if ts_off:
        d = {"mode": "none", "unit_cycles": None, "unit_us": None,
             "ts_off": True, "dt_unit": 0, "ts_shift": 0,
             "note": "只记事件顺序：整条流没有时间戳，cycles / t_us 一律为 null"}
    elif du:
        d = {"mode": "dt_unit", "unit_cycles": du, "ts_off": False,
             "dt_unit": du, "ts_shift": 0,
             "note": "dt 的单位是 %d 个 CPU 周期（整数除法，粒度精确；"
                     "不是 2 的幂也支持——内核 tick 正是这种）" % du}
    else:
        d = {"mode": "ts_shift", "unit_cycles": 1 << sh, "ts_off": False,
             "dt_unit": 0, "ts_shift": sh,
             "note": ("dt 的单位是 2^%d = %d 个 CPU 周期" % (sh, 1 << sh)) if sh
                     else "最小粒度：一个 dt 单位就是一个 CPU 周期"}
    if d["unit_cycles"] and info.get("cpu_hz"):
        d["unit_us"] = round(d["unit_cycles"] * 1e6 / float(info["cpu_hz"]), 4)
    return d


def _swd_gran_of_info(info: dict) -> tuple:
    """从控制块抽出「当前生效的三元组」，用来跟调用方请求的粒度比。

    dt_unit 与 ts_shift 全为 0 且 ts_off 为假，就是最细粒度；不能只看 ts_shift
    ——内核 tick 那种非 2 的幂粒度走的是 dt_unit，ts_shift 恰好是 0。
    """
    return (info.get("ts_shift") or 0, info.get("dt_unit") or 0,
            bool(info.get("ts_off")))


def _swd_apply_granularity(addr: int, info: dict, spec) -> dict:
    """把时间粒度写进控制块：TS_SHIFT / DT_UNIT / FLAGS 里的 TS_OFF 位。

    只写这三个字，不动 cpu_hz / cycles（那是目标自己维护的，宿主写进去就把
    对锚的基准毁了）。写完**紧接着必须写 reset_req**——一段流里混两种单位就
    没法正确换算时间，所以真正的入口是 trace_swd_reset(granularity=...)，
    别单独调这个函数改粒度。
    """
    try:
        ts_shift, dt_unit, ts_off, note = _swd.resolve_granularity(
            spec, info.get("cpu_hz") or 0)
    except ValueError as e:
        return {"ok": False, "error_code": "swd-granularity-invalid",
                "error": str(e),
                "hint": "粒度写法可用 cycle（最小）/ none（不记时间戳）/ 500us / 1ms "
                        "/ 2.5us 这类字符串，或直接给微秒数。"}
    if ts_shift is None:
        return {"ok": True, "changed": False, "requested": spec,
                "granularity": _swd_gran_desc(info), "note": note}
    flags = (1 if info.get("enabled") else 0) | (
        _swd.FLAG_TS_OFF if ts_off else 0)
    wrote = []
    for off, val in ((_swd.OFF_TS_SHIFT, ts_shift), (_swd.OFF_DT_UNIT, dt_unit),
                     (_swd.OFF_FLAGS, flags)):
        w = _write_mem(addr + int(off), struct.pack("<I", int(val) & _swd.U32))
        if not w.get("ok"):
            w = _write_mem(addr + int(off), struct.pack("<I", int(val) & _swd.U32))
        if not w.get("ok"):
            return {"ok": False, "error_code": "swd-granularity-write-failed",
                    "error": "写 0x%X（控制块偏移 %d，值 %d）失败：%s"
                             % (addr + int(off), off, val,
                                w.get("error") or "未知"),
                    "wrote": wrote,
                    "hint": "目标全速跑时经 Keil 链路写 SRAM 可能不生效：先 halt"
                            "（stop）再试，然后重开一段录制。"}
        wrote.append({"off": int(off), "addr": "0x%X" % (addr + int(off)),
                      "value": int(val)})
    cur = dict(info)
    cur.update({"ts_shift": ts_shift, "dt_unit": dt_unit, "ts_off": ts_off})
    return {"ok": True, "changed": True, "requested": spec,
            "granularity": _swd_gran_desc(cur), "wrote": wrote,
            "note": note + "。改粒度必须配一次重开录制才生效得干净"
                            "（trace_swd_reset(granularity=...)）——"
                            "一段流里混两种单位就换算不出时间轴。"}


def swd_status(elf: str = "", addr="", link: str = "auto") -> dict:
    """只读 80 字节控制块：够便宜，能一眼看出「宿主跟不跟得上」。

    顺带把当前的**时间粒度**翻成人话（granularity 字段：一个 dt 单位 = 多少
    CPU 周期 / 多少微秒，TS_OFF 时明说没有时间轴）。只读不改——改粒度必须配
    一次重开录制，走 trace_swd_reset(granularity=...)。
    """
    a, loc = _swd_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    info, err = _swd_read_ctrl(a, link=link)
    if info is None:
        if isinstance(err, dict) and err.get("seq") is not None:
            err["note"] = ("控制块读到了字段但不自洽——先看 seq 是不是变了"
                           "（目标重开会把游标归零）")
        return err
    out = dict(info)
    out["ok"] = True
    out["locate"] = loc
    out["granularity"] = _swd_gran_desc(info)
    s = _T.get("swd")
    if s and s.get("addr") == a:
        out["session"] = {
            "events_decoded": len(s["events"]),
            "local_drained": s["drained"],
            "unread_bytes": (info["head"] - s["drained"]) & _swd.U32
                            if s["drained"] is not None else None,
            "want_resync": bool(s.get("seq") is not None
                                and s["seq"] != info["seq"]),
        }
    if info["events"]:
        out["overall_bytes_per_event"] = round(info["head"] / float(info["events"]), 2)
        out["compression_vs_12B"] = round(12.0 / max(0.01, info["head"] / float(info["events"])), 2)
    if info["ts_off"]:
        out.setdefault("warnings", []).append(
            "控制块的 TS_OFF 置位：这段流**只有事件顺序、没有任何时间戳**"
            "（事件里的 cycles/t_us 一律为 null，工具也不会替你编一个相对时间）。"
            "要时间轴就把粒度调回 cycle/500us 并重开一段录制。")
    out["next"] = ["trace_swd_read 把未读的那段搬走并解成事件",
                   "trace_swd_reset 让目标开一段新录制"]
    if not out["cpu_hz"]:
        out.setdefault("warnings", []).append(
            "控制块里 cpu_hz=0：dt 只能给周期数，给不了微秒。"
            "把 MDK_TRACE_SWD_CPU_HZ（或 trace_instrument 的 coreclk=）设成真实主频。")
    if out["pending"] >= out["cap"]:
        out.setdefault("warnings", []).append(
            "环已经满了（pending=cap=%d）：宿主一点没搬，目标现在**每条事件都在丢**"
            % out["cap"])
    elif out["pending"] > out["cap"] * 3 // 4:
        out.setdefault("warnings", []).append(
            "环已用 %d/%d：宿主搬运速度跟不上事件产生速度时会开始丢事件"
            % (out["pending"], out["cap"]))
    if info["lost_events"]:
        out.setdefault("warnings", []).append(
            "lost_events=%d（lost_bytes=%d）：这次录制**不是完整的**，"
            "时间轴上有没记下来的东西" % (info["lost_events"], info["lost_bytes"]))
    if info["reset_req"]:
        out.setdefault("warnings", []).append(
            "控制块里的 reset_req 还是 1：目标还没执行它（下一条事件写入时才处理）")
    return out


def swd_read(elf: str = "", addr="", limit: int = 200, out_file: str = "",
             names: str = "", link: str = "auto", reset_session: bool = False,
             granularity: str = "", consistent: str = "halt",
             tasks: str = "auto",
             max_session_events: int = _SWD_MAX_SESSION_EVENTS) -> dict:
    """无缝流的**核心动作**：把 [drained, head) 搬走 → 解码 → 把 drained 推上去。

    consistent= 决定「怎么搬这一块」：
      * halt（默认）：先 halt → 就地重读控制块（一致快照）→ 搬 → 写游标 → resume。
        真机实测这是唯一能保证「搬到的就是目标写进去的那一份」的做法
        （停机读与目标 tokens 计数逐字节吻合），代价是每搬一次停几毫秒；
        停机期间未读数据不会丢（背压不覆写），所以「跑一段 → 停一下搬走」是无损的。
      * run：全速搬（快）。但实测有的目标/地址段会整片读回伪值（全 0、全 FF、
        或整段重复同一个 4 字节字），遇到伪值**直接报 swd-read-untrusted**，不拿去解码。
      * auto：先全速读，发现伪值自动停机重读一次（读得快又不会静默错）。

    多次调用会累加成一个连续的时间线（会话状态留在进程内）。
    返回 events 只给最新 limit 条；全量用 out_file 落盘。

    granularity= 是**校验**不是设置：给了就要求控制块当前的粒度与它一致，不一致
    直接报 swd-granularity-mismatch（一段流里混两种单位，时间轴换算出来就是错的）。
    改粒度请用 trace_swd_reset(granularity=...)——它会写完粒度后重开一段录制。
    会话里记下的粒度若与控制块不符（谁在背后改过），也报错而不是照算。

    tasks= 决定要不要给调度事件补**任务名**（默认 auto）：
      * auto（默认）：会话内解析一次 svcrt_task_table，把每个槽位的入口函数
        （TCB 的 entry 字段，偏移从 DWARF 取）翻成 ELF 里的函数名，于是流里
        的数字 0..15 变成真实任务名；解析成功后**历史上已解过的事件也会回头
        重补名字**。解析不出来就在 task_names 里如实说明原因（不给假名字）。
      * refresh：手工重解析一次（换了固件/换了 .axf 后用）。
      * off：完全不解析。
    """
    mode = (consistent or "halt").strip().lower()
    if mode not in ("halt", "run", "auto"):
        # 参数错就报错，**一句都不碰目标**：校验放在任何读/停机之前。
        return {"ok": False, "error_code": "swd-consistent-invalid",
                "error": "consistent 只能是 halt / run / auto，收到 %r" % (consistent,),
                "hint": "halt=停机搬（可信，代价是几毫秒停机）；run=全速搬（快，"
                        "但实测有的目标/地址段会读回伪值，遇到伪值直接报错）；"
                        "auto=先全速读，发现伪值自动停机重读。"}
    a, loc = _swd_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    if reset_session:
        _T["swd"] = None
    info, err = _swd_read_ctrl(a, link=link)
    if info is None:
        return err
    s = _swd_session(a)
    notes = []

    # ---- 目标重新初始化过？它的游标可能已经归零，旧游标不能再拿来做减法
    if s["seq"] is not None and info["seq"] != s["seq"]:
        unread = 0 if s["drained"] is None else (info["head"] - s["drained"]) & _swd.U32
        if s["drained"] is not None and unread <= info["cap"]:
            notes.append("目标重开录制时丢弃了宿主还没读走的 %d 字节" % unread)
        s["dec"] = _swd.Decoder()
        s["drained"] = info["drained"]
        s["rel_cycles"] = 0
        s["anchor_cycle"] = None
        s["gran"] = None
        s["restarts"] += 1
        notes.append("目标重开过录制（seq -> %d）：宿主解码器已重来，"
                     "此前解出的事件仍保留在会话里，它们与之后的事件不在同一条时间基上"
                     % info["seq"])
    s["seq"] = info["seq"]

    # ---- 时间粒度：一段流里只能有一种单位，混着换算出来就是错的
    cur_gran = _swd_gran_of_info(info)
    if granularity:
        try:
            want = _swd.resolve_granularity(granularity, info.get("cpu_hz") or 0)
        except ValueError as e:
            return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                    "error_code": "swd-granularity-invalid", "error": str(e),
                    "hint": "粒度写法可用 cycle / none / 500us / 1ms / 2.5us，"
                            "或直接给微秒数。"}
        if want[:3] != cur_gran:
            return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                    "error_code": "swd-granularity-mismatch",
                    "error": "控制块当前粒度 ts_shift=%r dt_unit=%r ts_off=%r，"
                             "与请求的 %r 不符" % (cur_gran + (granularity,)),
                    "current": _swd_gran_desc(info), "requested": granularity,
                    "hint": "改粒度不能在一段流中间做：前半段用旧单位、后半段用新"
                            "单位，换算出来的时间轴是错的。用 trace_swd_reset"
                            "(granularity=%r) 让目标开一段新录制。" % (granularity,)}
    if s["gran"] is not None and s["gran"] != cur_gran:
        return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                "error_code": "swd-granularity-changed",
                "error": "会话记下的是 ts_shift=%r dt_unit=%r ts_off=%r，控制块现在"
                         "是 %r——粒度在会话中途被改过" % (s["gran"] + (cur_gran,)),
                "current": _swd_gran_desc(info),
                "hint": "已解出的事件是按旧单位换算的，两者不能混在同一条时间轴上。"
                        "重开一段：trace_swd_reset(granularity=...)，然后"
                        " trace_swd_read(reset_session=true)。"}
    s["gran"] = cur_gran

    drained = s["drained"]
    if drained is None:
        drained = info["drained"]
    s["drained"] = drained
    pending = (info["head"] - drained) & _swd.U32
    if pending > info["cap"]:
        return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                "error_code": "swd-cursor-mismatch",
                "error": "宿主游标 %d 与控制块的 head=%d 对不上（差 %d > cap=%d）"
                         % (drained, info["head"], pending, info["cap"]),
                "hint": "多半是宿主会话与目标不同步（MCP 重启过、换了固件、目标复位过）。"
                        "① reset_session=true 重新建立会话；"
                        "② 或先 trace_swd_reset 让目标侧重开一段录制。",
                "seq": info["seq"], "ctrl": {k: info[k] for k in
                                              ("head", "drained", "cap", "events", "tokens")}}

    def _drain_now():
        d, m = _swd_read_stream(info["ring_addr"], info["cap"], drained,
                                pending, link=link)
        return d, (m or {})

    def _halt_and_reread_ctrl():
        """停机 + 就地重读控制块（停机后 head 不再动，这一段是个一致快照）。

        返回 (lk, 错误 dict 或 None)。成功时把外层的 info / pending 就地更新。
        """
        nonlocal info, pending
        lk, lerr = _link.pick(link, who="停机搬环")
        if lk is None:
            return None, dict(lerr or {}, ok=False, error_code="swd-halt-failed")
        r = lk.halt() or {}
        if not r.get("ok"):
            return None, {"ok": False, "addr": "0x%X" % a, "locate": loc,
                          "error_code": "swd-halt-failed",
                          "error": "停机失败：%s"
                                   % (r.get("error") or r.get("status_text") or "未知"),
                          "hint": "consistent=halt 要求能把目标停下来；停不了就改 "
                                  "consistent=\"run\"，但要自己担运行态读的伪值风险。"}
        info2, e2 = _swd_read_ctrl(a, link=link)
        if info2 is None:
            _swd_resume(lk)
            return None, e2
        info = info2
        pending = (info["head"] - drained) & _swd.U32
        if pending > info["cap"]:
            _swd_resume(lk)
            return None, {
                "ok": False, "addr": "0x%X" % a, "locate": loc,
                "error_code": "swd-cursor-mismatch",
                "error": "停机后控制块 head=%d 与宿主游标 %d 差 %d > cap=%d"
                         % (info["head"], drained, pending, info["cap"]),
                "hint": "宿主会话与目标不同步（MCP 重启过 / 换了固件 / 目标复位过）："
                        "reset_session=true 重建会话，或 trace_swd_reset 重开一段录制。"}
        return lk, None

    data = b""
    rmeta = {}
    lk_h = None
    halted = False
    halt_ms = None
    halt_started = None
    did_halt = False
    drain_notes = []
    if pending:
        if mode == "halt":
            halt_started = time.perf_counter()
            lk_h, herr = _halt_and_reread_ctrl()
            if lk_h is None:
                return herr
            halted = True
            did_halt = True
        data, rmeta = _drain_now()
        if data is None:
            if halted:
                _swd_resume(lk_h)
            return rmeta
        fake = _swd_fake_kind(data) or (rmeta.get("degenerate") or "")
        if fake and not halted:
            if mode == "run":
                return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                        "error_code": "swd-read-untrusted",
                        "error": "全速运行时搬回的这段字节是伪值（%s，共 %d 字节）"
                                 % (fake, len(data)),
                        "at_drained": drained, "unread_bytes": pending,
                        "hint": "这段字节不是目标写进去的内容，拿去解码只会解出垃圾并失步。"
                                "consistent=\"halt\"（或 auto）会停机搬——停机读实测与目标"
                                " tokens 计数逐字节吻合；停机期间未读数据不会丢（靠背压）。"}
            halt_started = time.perf_counter()
            lk_h, herr = _halt_and_reread_ctrl()
            if lk_h is None:
                drain_notes.append("全速搬回的是伪值（%s），且停机失败：这批字节不可信"
                                   % fake)
                data, rmeta = b"", {}
            else:
                halted = True
                d2, m2 = _drain_now()
                if d2 is None:
                    _swd_resume(lk_h)
                    return m2
                k2 = _swd_fake_kind(d2) or ((m2 or {}).get("degenerate") or "")
                if k2:
                    _swd_resume(lk_h)
                    return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                            "error_code": "swd-read-untrusted",
                            "error": "停机后搬回的字节仍是伪值（%s）" % k2,
                            "hint": "这不再是「运行态读」的问题，而是链路/固件本身："
                                    "核对 cap/ring_addr 与固件是否一致，或换链路重试。"}
                data, rmeta = d2, m2
                did_halt = True
                drain_notes.append("全速搬回的是伪值（%s，%d 字节），已改用停机搬运"
                                   % (fake, len(data)))
    notes.extend(drain_notes)

    dec = s["dec"]
    base_ev, base_ct, base_it = len(dec.events), len(dec.ctl), len(dec.items)
    if data:
        try:
            dec.feed(data)
        except _swd.StreamDesync as e:
            # 回滚这一批：不推进游标，让同一段字节下次重新解——否则会解出
            # 半截事件、而剩下的字节再也对不上。
            del dec.events[base_ev:]
            del dec.ctl[base_ct:]
            del dec.items[base_it:]
            return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                    "error_code": "swd-stream-desync", "error": str(e),
                    "at_drained": drained, "unread_bytes": pending,
                    "hint": "宿主字典与目标字典不同步（语义上等价于流从中间开始）。"
                            "无缝流没有「从半路接上」的办法——跑 trace_swd_reset "
                            "让目标重开一段录制，两边字典一起清掉。\n"
                            "常见成因：MCP 进程重启后接了上一次录制的游标；"
                            "或目标在宿主离线期间复位过。"}

    if data and dec.leftover:
        # head 一定落在 token 边界上，读到半截说明这一读不可信。
        del dec.events[base_ev:]
        del dec.ctl[base_ct:]
        del dec.items[base_it:]
        return {"ok": False, "addr": "0x%X" % a, "locate": loc,
                "error_code": "swd-partial-token",
                "error": "读完 %d 字节后还剩 %d 字节凑不成一个完整 token"
                         % (len(data), dec.leftover),
                "hint": "head 一定是 token 边界，出现半截多半是链路读短了。重试一次；"
                        "仍这样就用 trace_swd_reset 重开一段。"}

    # ---- 推进目标侧游标。必须**先读后推**：推早了目标就会覆写没搬走的字节。
    write_err = None
    if pending:
        w = _write_mem(a + _swd.OFF_DRAINED, struct.pack("<I", info["head"]))
        if not w.get("ok"):
            w = _write_mem(a + _swd.OFF_DRAINED, struct.pack("<I", info["head"]))
        if not w.get("ok"):
            write_err = w.get("error") or "写 drained 失败"
            s["cursor_write_failed"] = True
        else:
            s["cursor_write_failed"] = False
        s["drained"] = info["head"]

    # ---- 停机搬运：游标已推完才放目标跑（运行态写 SRAM 也可能不生效，停机时写最稳）
    if halted:
        _swd_resume(lk_h)
        halted = False
        if halt_started is not None:
            halt_ms = (time.perf_counter() - halt_started) * 1000.0

    # ---- 对上锚：本批读完后控制块没再动过，cycles 就是**本会话最后一条事件**的时刻
    stable = False
    if pending:
        info2, _e2 = _swd_read_ctrl(a, link=link)
        stable = bool(info2 and info2.get("ok")
                      and info2["head"] == info["head"]
                      and info2["seq"] == info["seq"]
                      and info2["lost_events"] == info["lost_events"])
        if stable:
            s["anchor_cycle"] = info2["cycles"]
            s["cpu_hz"] = info2["cpu_hz"]
            s["ts_shift"], s["dt_unit"], s["ts_off"] = _swd_gran_of_info(info2)

    if "cpu_hz" not in s:
        s["cpu_hz"] = info["cpu_hz"]
    s["ts_shift"], s["dt_unit"], s["ts_off"] = cur_gran

    # ---- 任务名（序号 -> 名字）：会话内解析一次，解析出来之后连**历史上已经解过的**
    # 事件一起重补名字——否则名字只能从「解析成功之后」的那一段开始有，时间轴前半段
    # 还是数字，看起来就像“任务只出现在后半段”。
    tn = _swd_tasks_for_session(s, elf, link, tasks)
    tnames = (tn or {}).get("names") if (tn or {}).get("ok") else None

    new_items = dec.items[base_it:]
    evs = _swd_fold(s, new_items, s["ts_shift"], s["cpu_hz"],
                    _buff_parse_names(names), dt_unit=s["dt_unit"] or 0,
                    ts_off=bool(s["ts_off"]),
                    task_names=(tnames if tnames is not None else None),
                    idle_name=(tn or {}).get("idle_name") or "idle")
    if s["anchor_cycle"] is not None and not s["ts_off"]:
        _swd_anchor(s, s["anchor_cycle"], s["cpu_hz"], evs)
    if tnames is not None:
        # 已存事件回头重补（幂等：只写它算得准的字段）
        _apply_task_names(s["events"], tnames, (tn or {}).get("idle_name") or "idle")
    s["events"].extend(evs)
    if len(s["events"]) > int(max_session_events or 0) > 0:
        drop = len(s["events"]) - int(max_session_events)
        del s["events"][:drop]
        s["session_events_dropped"] = s.get("session_events_dropped", 0) + drop
    s["bytes_read"] += len(data)

    view = _swd_session_view(s, limit=limit)
    out = {
        "ok": True, "addr": "0x%X" % a, "locate": loc,
        "ctrl": {k: info[k] for k in ("version", "cap", "ring_off", "head",
                                       "drained", "pending", "lost_events",
                                       "lost_bytes", "events", "tokens", "seq",
                                       "ts_shift", "dt_unit", "ts_off", "cpu_hz",
                                       "cycles", "enabled")},
        "granularity": _swd_gran_desc(info),
        "cursor_before": drained,
        "cursor_after": s["drained"],
        "bytes_drained": len(data),
        "new_events": len(evs),
        "session": {"events": view["event_count"], "bytes_read": s["bytes_read"],
                    "restarts": s["restarts"], "syncs": s["syncs"],
                    "anchored": s["anchor_cycle"] is not None,
                    "dropped_from_session": s.get("session_events_dropped", 0)},
        "time_origin": ("无（TS_OFF：这段流只有事件顺序，没有时间戳）"
                        if s["ts_off"] else
                        "绝对（DWT 周期数，锚在控制块 cycles 上）"
                        if s["anchor_cycle"] is not None else
                        "相对（会话第一条事件为 0；本批没对上锚）"),
        "measured_bytes_per_event": (round(s["bytes_read"] / float(view["event_count"]), 2)
                                     if view["event_count"] else None),
        "overall_bytes_per_event": (round(info["head"] / float(info["events"]), 2)
                                    if info["events"] else None),
        "counts_by_type": view["counts_by_type"],
        "top_ids": view["top_ids"],
        "faults": view["faults"],
        "events": view["events"],
        "truncated": view["truncated"],
        "consistent": "halt" if did_halt else "run",
        "halt_ms": round(halt_ms, 2) if halt_ms is not None else None,
        "task_names": _swd_tasks_brief(tn),
        "sched_decoded": _swd_sched_count(evs),
        "read_meta": {k: rmeta.get(k) for k in ("read_confidence", "while_running")
                      if k in rmeta} or None,
        "next": ["连续录：反复调 trace_swd_read，每次它只搬走新增的那一段",
                 "想看整体健康度用 trace_swd_status（更便宜）"],
    }
    if notes:
        out["notes"] = notes
    if not pending:
        out["note"] = "没有新数据：从上次读到现在的这一段是空的"
    if write_err:
        out["warnings"] = out.get("warnings", []) + [
            "写回 drained 失败（%s）：字节已经解出来了，但目标仍以为它们没被读走；"
            "环满之后目标会开始丢事件。建议 trace_swd_reset 重开一段。" % write_err]
    if rmeta.get("degenerate") or rmeta.get("read_unstable"):
        out["warnings"] = out.get("warnings", []) + [
            "这次读的置信度不高（%s）：结果可能不完整，建议重读一次复核"
            % (rmeta.get("degenerate") or "read_unstable")]
    if s["ts_off"]:
        out["warnings"] = out.get("warnings", []) + [
            "这段流是 TS_OFF（不记时间戳）：事件里的 dt_cycles/cycles/t_us 都是 null，"
            "只有先后顺序——别把等距排列当成等距时间。"]
    if info["lost_events"]:
        out["warnings"] = out.get("warnings", []) + [
            "lost_events=%d：目标因为宿主跟不上丢了事件，这条时间线不是完整的"
            % info["lost_events"]]
    if view["faults"]:
        out["warnings"] = out.get("warnings", []) + [
            "录到 %d 次异常，faults 字段里是类别、CFSR 拆位与寄存器现场"
            % len(view["faults"])]
    if out_file:
        try:
            p = os.path.abspath(out_file)
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"meta": {k: v for k, v in out.items()
                                    if k not in ("events", "next", "locate", "faults")},
                           "events": s["events"], "faults": view["faults"],
                           "counts_by_type": view["counts_by_type"],
                           "top_ids": view["top_ids"]},
                          f, ensure_ascii=False, default=str)
            out["out_file"] = p
            out["out_records"] = len(s["events"])
        except OSError as e:
            out["warnings"] = out.get("warnings", []) + ["写 out_file 失败：%s" % e]
    return out


def swd_reset(elf: str = "", addr="", wait: bool = True, link: str = "auto",
              granularity: str = "") -> dict:
    """请目标**开一段新录制**：清环、清计数、字典两边一起清、seq 加一。

    这是无缝流唯一的「重新对齐」手段：宿主字典与目标字典不同步时，只能靠目标
    重开一段来把两边一起归零——宿主单方面清字典只会让后续每个 HIT 都解错。
    与 buff 一样是**延迟生效**的：目标在下一條事件写入时才处理，长期没有插桩
    事件时会一直挂着（返回 request_latched 说明这一点）。

    granularity= 是**切换时间粒度的唯一入口**：先把 TS_SHIFT / DT_UNIT / FLAGS 的
    TS_OFF 位写进控制块，紧接着请求重开录制，于是新录的那段整段都是新粒度，不会
    出现「半段旧单位、半段新单位」这种换算不出来的流。取值 cycle / none / 500us /
    1ms / 2.5us，或直接给微秒数；留空表示不动粒度。
    """
    a, loc = _swd_locate(elf=elf, addr=addr)
    if a is None:
        return loc
    info, err = _swd_read_ctrl(a, link=link)
    if info is None:
        return err
    seq0 = info["seq"]
    gran = None
    if granularity:
        g = _swd_apply_granularity(a, info, granularity)
        if not g.get("ok"):
            g.update({"addr": "0x%X" % a, "locate": loc, "seq_before": seq0})
            return g
        gran = g
    w = _write_mem(a + _swd.OFF_RESET_REQ, struct.pack("<I", 1))
    out = {"ok": bool(w.get("ok")), "addr": "0x%X" % a, "locate": loc,
           "wrote": "0x%X" % (a + _swd.OFF_RESET_REQ), "write_meta": w,
           "seq_before": seq0}
    if gran is not None:
        out["granularity"] = gran["granularity"]
        out["granularity_write"] = gran
        out["granularity_note"] = (
            gran["note"] + "。它与 reset_req 一起生效：新录的那段整段都是这个粒度。")
    if not w.get("ok"):
        out["error_code"] = "swd-reset-write-failed"
        out["error"] = w.get("error") or "写 reset_req 失败"
        out["hint"] = ("目标全速运行时写 SRAM 可能不生效（Keil 链路尤其如此）："
                       "先 halt（stop）再试；实在不行让固件自己调 "
                       "mdk_trace_swd_init()。")
        return out
    if not wait:
        out["applied"] = False
        out["note"] = "已请求；reset_req 只在下一条事件写入时被处理"
        return out
    info2, _e2 = _swd_read_ctrl(a, link=link)
    if info2 is None:
        out["applied"] = False
        out["pending"] = True
        out["note"] = "写入成功，但控制块重读失败，无法确认是否已生效"
        return out
    applied = info2["seq"] != seq0
    out["seq_after"] = info2["seq"]
    out["applied"] = applied
    out["request_latched"] = None if applied else True
    if applied:
        out["note"] = ("新录制已开始（seq %d -> %d）：环已清空，"
                       "宿主下次 trace_swd_read 会自己认出 seq 变了并重置解码器"
                       % (seq0, info2["seq"]))
        s = _T.get("swd")
        if s and s.get("addr") == a:
            s["seq"] = info2["seq"]
            s["drained"] = info2["drained"]
            s["dec"] = _swd.Decoder()
            s["rel_cycles"] = 0
            s["anchor_cycle"] = None
            s["gran"] = None
            s["restarts"] += 1
    else:
        out["note"] = ("reset_req 已写进去但还没被执行（seq 仍是 %d）：它在下一条事件"
                       "写入时才处理。目标若长期没有插桩事件，它会一直挂着——这不是"
                       "失败，但也不能当成「已清空」" % seq0)
        out.setdefault("warnings", []).append(
            "别把 pending 当成 applied：要看有没有生效就再读一次 trace_swd_status 看 seq。")
    return out


# ================================================================ MCP 注册

def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


GUIDE = {
    "howto": (
        "三条通路的取舍：\n"
        "  SWO（要 SWO 引脚）：带宽最高、时间戳最准，能拿 ITM 打印 + 硬件事件（异常/PC 采样/数据 trace）。"
        "走 trace_swo_start → 目标跑起来 → trace_swo_read。\n"
        "  RTT（只要 SWD/JTAG）：不要额外引脚，双向通道，主机直读目标 RAM。"
        "走 trace_rtt_attach → trace_rtt_read/write。ESP32 这类没 ITM 的目标首选。\n"
        "  SWD 采样（什么都不要）：halt+读PC+resume，侵入式，只能看热点分布。走 trace_profile。\n"
        "  SWD 仅两线也能做的非侵入观测：变量 scope（trace_scope_start，DAP 轮询 RAM，"
        "不 halt）与 DWT 硬件 PC 采样（trace_pcsample，不 halt）。\n"
        "  SWD 仅两线也能录「函数进入/退出时间线」（trace_record）：不是硬件 trace，"
        "而是 FPB 断点命中 + DWT_CYCCNT 计时，能拿到进入/退出/调用者/深度估计。"
        "代价是**侵入式**（每次命中停下读寄存器再 resume）且同时布的断点数受 FPB 比较器"
        "数量限制（M0 4 / M3-M4 一般 6 / M7 一般 8），适合盯关键路径上的少数函数，"
        "不是全量录制；keil 链路需目标处于调试态（先 enter_debug）。"
        "**指令级录制 SWD 两线做不到**，详见 topic=swd_limits。\n"
        "  目标侧插桩本身又分两种工作模式（events 什么时候离开芯片）："
        "stream（ITM/RTT/UART，持续录持续读）与 buff（全速录、事后一次性读回）。"
        "要最细的时间粒度 + 一段完整过程，选 buff——见 topic=instrument_modes。\n"
        "  该往哪儿插桩、哪些点最值钱（HardFault 等异常 handler 排第一）见 topic=instrument_points；"
        "这几次在真板上撞到的坑见 topic=lessons。"
    ),
    "links": (
        "trace 的内存通路有两条，观测类工具都带 link 参数（默认 auto，也可显式 keil / ocd）：\n"
        "  keil —— Keil 调试会话（UVSOCK）；先 enter_debug 再调 trace 工具。读内存走带脏读判定的"
        "read_mem_verified，慢一点但不会把脏帧当真值。\n"
        "  ocd  —— OpenOCD；先 ocd_start。读内存走 mdw。\n"
        "  auto —— 哪条在跑用哪条；两条都可用时优先 keil。**显式指定而那条不可用时报错，"
        "不会悄悄换成另一条顶上**（避免读到另一个目标的现场）。\n"
        "通用性：变量 scope、RTT、halt 采样、DWT 计数、PC 采样两条链路通用；"
        "**SWO（trace_swo_start）只走 OpenOCD**，Keil 用户请用 trace_rtt_* 或 trace_scope/trace_pcsample。\n"
        "  MDK 原生的 Event Recorder / Event Statistics 是 **uVision 自己的窗口能力**"
        "（走调试器读目标 RAM 缓冲，不需要 SWO 引脚）——**本工具集能直接解码**：用 trace_eventrec 读这份缓冲（批次53 起）。\n"
        "ITM 结构化解码（trace_decode）与 itm 报文读取两条链路通用。"
    ),
    "swd_wiring": (
        "SWD 最少四根：SWCLK / SWDIO / GND / 3V3(参考电平)。"
        "目标独立供电时别把调试器的 3V3 当电源用（供电不足是「连不上」的头号原因）。"
        "SWO 是第五根（Cortex-M 上通常是 PB3 / TDO 复用），接到调试器的 SWO/RX 脚；"
        "DAPLink、J-Link、ST-Link V2-1 才有，很多廉价 ST-Link 克隆没有 SWO。"
    ),
    "rtt_notes": (
        "RTT 原理：目标里放一个控制块（ID 字符串 'SEGGER RTT' + 若干上下行环缓冲），"
        "主机直接读写目标 RAM。要点：\n"
        "  - 控制块别被 --gc-sections 回收（KEEP 或让它有引用）；\n"
        "  - 主机读完必须把 RdOff 推进到 WrOff，否则目标认为缓冲满会丢数据；\n"
        "  - 我们的 trace_rtt_read 就是这么做的（纯内存读写实现，"
        "不依赖 OpenOCD 的 rtt 命令）——RISC-V 目标上 OpenOCD 的 rtt 支持有限，这条正好绕开。"
    ),
    "itm_notes": (
        "ITM 侧要点：目标必须先使能 DWT/ITM（组件里做了），SWO 引脚必须配好；"
        "核心时钟 coreclk 和波特率 baud 必须与目标一致，配错的表现是"
        "「解出来一堆 garbage/dropped_bytes 暴涨」。丢包（Overflow 包）是常态，"
        "主机侧不会假装数据完整：trace_swo_read 会返回 overflow 计数与 CRC 错计数。"
    ),
    "when_unavailable": (
        "连不上/SWO 没数据时的排查顺序：ocd_log 看日志 → ocd_probe 确认目标已识别 → "
        "确认探针是否支持 SWO → 用 RTT 或采样剖析兜底（这两条只要求能读写内存）。"
    ),
    "swd_limits": (
        "只接 SWD 两线时，到底能做到什么、做不到什么：\n"
        "  ✅ **MDK 原生：Event Recorder / Event Statistics（插桩，不停机）**：MDK 5.22 起的"
        "CMSIS 组件（EventRecorder.c）。它的数据通路**不是 SWO 引脚**，而是调试器的内存访问——"
        "目标侧把事件写进 RAM 里的 Event Buffer，uVision 在调试会话里经 DAP 把缓冲读出来渲染。"
        "SWD 两线接上就能用（J-Link / ST-Link / CMSIS-DAP 都行），带 ITM 的 M3/M4/M7/M33 "
        "记录期间无需开关中断。EventStart/EventStop 夹住一段代码就是一次耗时测量，"
        "Event Statistics 窗口直接给每个事件的次数 / 总时间 / 最长单次；RTX5 与中间件自带插桩。"
        "两个前提：① **必须插桩**——工程要链组件并调 API，没调的地方不会有记录，"
        "它**不是**自动捕获所有函数；② 要挂着调试会话才看得到（数据在目标 RAM，靠调试器搬，"
        "不像 RTT 有独立 Viewer 能离线看）。\n"
        "  ✅ **本工具集能解码** Event Recorder 的目标侧缓冲：trace_eventrec"
        "（action=read 给事件流、action=stats 给次数/总时间/最短/最长/平均，"
        "与 uVision 的 Event Statistics 同口径）。边界仍要如实知道：① 事件名靠工程里的 "
        "SCVD 文件，本工具只给 component/message 编号与槽位号，给不了你那套名字；"
        "② level 不随记录存储（写入前 id 与 0xFFFF），只有 component=0xEF 那组"
        "（EventStartX/EventStopX）能按 message 反推组别 A/B/C/D 与槽位；"
        "③ 目标没插桩就一条数据都没有，这种情况会明确报 eventrec-symbol-missing。\n"
        "  ✅ **变量 scope（非侵入）**：DAP 读 RAM 不需要停核，主机侧按周期轮询就能把"
        "变量连成时间线 → trace_scope_start/read/stop。代价：轮询有间隔，"
        "两次采样之间的跳变看不到；采样率是主机轮询率而非目标周期。\n"
        "  ✅ **函数分布（非侵入）**：DWT 自带的硬件 PC 采样器（DEMCR.TRCENA + "
        "DWT_CTRL.PCSAMPLENA，读 DWT_PCSR），主机只读寄存器 → trace_pcsample。"
        "代价：样本是「采样器最近一次采到的 PC」，同一值会被重复读到，占比仅供参考；"
        "部分芯片修订版上采样器根本不动（这种会直接报错，不会给假分布）。\n"
        "  ✅ **函数进入/退出录制（侵入式，槽位受限）**：trace_record 靠 FPB 断点命中 + "
        "DWT_CYCCNT 计时，能录「谁在什么时候进了哪个函数、被谁调用、栈深大概多少、"
        "两次命中隔了多少周期」，**不需要 SWO 引脚、也不需要目标里链 RTT 代码**。"
        "两个代价：① 每次命中都要 halt 读寄存器再 resume，**破坏实时性**，高频短函数上会"
        "明显拖慢甚至丢事件；② 同时能布的断点数受 FPB 比较器数量限制（M0/M0+ 4 个、"
        "M3/M4 一般 6 个、M7 一般 8 个），只能盯少数函数，槽位不够时如实报 armed/skipped。\n"
        "  ⚠️ **侵入式 PC 采样**：halt→读PC→resume 的 trace_profile，能拿到更确定的"
        "热点分布，但每条样本都中断目标，会破坏实时性。\n"
        "  ↔ **两者怎么选**：要「函数入口/出口成对的事件与调用关系」用 trace_record；"
        "只要「整体热点占比」用 trace_pcsample（不 halt）或 trace_profile。\n"
        "  【「侵入式」必须拆成两个维度】别把 RTT 与断点式录制归成一类（「反正都是侵入」）——"
        "它们在下面两个维度上正好相反：\n"
        "    · **插桩**（要不要改目标代码）：RTT / Event Recorder **要**（链组件 + 调 API）；"
        "trace_record **不要**（FPB 硬件断点，免插桩）。\n"
        "    · **停机**（会不会打断执行、破坏实时性）：RTT / Event Recorder **不会**"
        "（目标侧只是往 RAM 环形缓冲 memcpy，微秒级、不 halt、不改执行流向）；"
        "trace_record **会**（每次命中 halt→读寄存器→resume，毫秒级）。\n"
        "    所以 RTT / Event Recorder 是「插桩但不停机」（低侵扰，SEGGER 把这条叫非侵入式调试），"
        "trace_record 是「免插桩但停机」——两者互补，不是同一类。\n"
        "  【选型：SWD 两线做函数级观测】按上面两个维度分四类——\n"
        "    · 改得动代码、要求不停机 → MDK Event Recorder + Event Statistics（原生窗口，本工具集用 trace_eventrec 也能读），"
        "或 SEGGER RTT / SystemView（可离线看）。\n"
        "    · 改不动代码、能接受停机 → trace_record（盯少数关键函数）。\n"
        "    · 只看整体热点占比 → trace_pcsample（不 halt）/ trace_profile（停机、更确定）。\n"
        "    · 全自动、无损、每跳都记 → 只能 SWO + ITM 或 ETM，SWD 两线做不到。\n"
        "  ❌ **指令级 CPU 录制（每一跳都记下来、事后回放）**：需要 ETM/PTM 并行 trace 口"
        "（额外 4~5 根线 + 大容量 trace 缓冲）或 SWO 引脚上的指令 trace 流，"
        "**SWD 两线本身做不到**——不要在这条链路上承诺它。\n"
        "  ❌ **带时间戳的逐事件时间线**：要么目标侧插桩（RTT/ITM，见 components/trace/），"
        "要么上硬件 trace 口；纯轮询给不了无丢包的时间线。\n"
        "结论：SWD 两线能覆盖「观测」与「函数级事件」两类——非侵入的变量/函数分布"
        "（trace_scope / trace_pcsample）、免插桩但停机的函数进入/退出（trace_record）、"
        "以及插桩但不停机的事件流（MDK Event Recorder / RTT / SystemView）。"
        "做不到的是「全自动、无损、每跳都记」：那要么 SWO 引脚 + ITM，要么 ETM 的 4~5 根线，"
        "要么目标侧自建插桩。"
    ),
    "instrument_modes": (
        "插桩的两种工作模式——区别只在「事件什么时候离开芯片」：\n"
        "  **stream**（持续录、持续读）：ITM / RTT / UART 三个后端\n"
        "    · 事件一发生就立刻推出去，主机必须跟得上；\n"
        "    · 带宽有限（SWO 常见 1~2 Mbit/s，RTT 受 SWD 与目标 RAM 带宽限制），"
        "每秒上千次的事件很容易丢——返回里的 dropped/overflow 非零就是真丢了；\n"
        "    · 每次读取都要占调试口 / 抢目标时间（RTT 读要把 RdOff 写回）；\n"
        "    · 好处：能实时看、能长时间跑、不占目标 RAM。\n"
        "    · 适合：跑着的系统上追一段时间线、printf 式日志、低频事件。\n"
        "  **buff**（全速录、事后一次性读回）：MDK_TRACE_BACKEND_BUFF\n"
        "    · 事件只写进 RAM 里的环形缓冲，**一个字节都不出芯片**：目标侧就几次 store，"
        "不阻塞、不碰外设、不看主机脸色 → 可以全速跑；\n"
        "    · 时间粒度可以开到**最小**（MDK_TRACE_BUFF_TS_SHIFT=0 = 每 CPU 周期，"
        "84MHz 上 11.9ns），因为它不占用任何传输带宽；\n"
        "    · 三条代价，都会如实报出、绝不静默：\n"
        "        ① 容量有限（MDK_TRACE_BUFF_RECORDS × 12 字节），写满后新记录覆盖最旧的 → "
        "wrapped=true 且 total/cap 都给你，「看到的是窗口不是全程」；\n"
        "        ② 文本帧（printf）放不进 12 字节记录 → 单独计 text_dropped；\n"
        "        ③ 时间戳只存「与上一条的周期差」→ 绝对时刻由控制块 last_cycles 反推；"
        "单次间隔超过 2^32 周期（84MHz 上 51 秒）要把 TS_SHIFT 调大。\n"
        "    · 读回三步：trace_buff_status（容量/丢没丢/回卷没）→ "
        "trace_buff_dump（解成时间线）→ trace_buff_reset（开一段新录制）。\n"
        "    · 适合：录一段「全速运行」的精确过程、还原切换/中断/异常现场、"
        "以及**已经出事了**（HardFault / 看门狗复位）以后取现场。\n"
        "  怎么选：\n"
        "    · 要实时看 → stream；要最细粒度 + 一次完整过程 → buff。\n"
        "    · 高频事件（>1000 次/秒）× 长时间 → 两者都不行（stream 会丢、buff 会回卷）："
        "把插桩点收窄到真正关心的那几个，或把 TS_SHIFT 与记录数按需求配平。\n"
        "  **swd**（无缝流：目标压缩入环、主机增量搬走）：MDK_TRACE_BACKEND_SWD\n"
        "    · 第三种模式，也是「只有 SWD 两线、又要不丢」时的正解：事件先被**压缩**"
        "写进 RAM 里的环形缓冲，主机定期经 SWD 把「还没搬走的那一段」搬出来，"
        "再把游标回报给目标；环循环使用。\n"
        "    · 与 buff 的关键差别是**满了怎么办**：buff 写满**覆盖最旧**（事后 dump 只看得到窗口），"
        "swd 是**未读区永不覆盖**——写不下就整条丢弃并计数（背压）。"
        "所以只要主机平均搬运速度 ≥ 事件产生速度，就是**零丢失**；跟不上时丢了多少也如实报。\n"
        "    · 与 stream 的关键差别是**什么时候离开芯片**：stream 事件一发生就推出去（要主机"
        "实时接住）；swd 事件留在芯片里等主机来搬，因此不占 SWO 引脚、也不抢目标执行时间。\n"
        "    · 压缩：把 (type, kind, id, arg) 当字典键，重复出现的事件只发一个 6bit 槽号。"
        "典型负载 **2.35 字节/事件**（定长记录要 12 字节，约 5.1×）。\n"
        "    · **必须知道的边界**：字典只有 64 槽且是直接映射哈希。"
        "**不同四元组超过 64 个（工作集大于字典）时命中率归零**，退化到约 11.3 字节/事件。"
        "所以插桩点要收窄、ID 要复用（同一「任务切换」语义别用一堆不同 arg 去编码）。\n"
        "    · 三个工具：trace_swd_status（环容量/游标/丢了多少/压缩比）→ "
        "trace_swd_read（增量搬一批并解成时间线）→ trace_swd_reset（开一段新录制）。\n"
        "    · 两条硬规矩：① **一丢就双方清字典**——命中只发槽号，两边字典不同步会解出"
        "**错误的 key**，比丢数据严重得多，所以对齐标记必须是「整条流重来」；"
        "② **搬走的字节在游标推进之前不能被覆盖**，读数顺序固定为"
        "「读控制块 → 读字节 → 解码 → 校验没有半截 token → 推进游标 → 重读控制块对锚」，"
        "`trace_swd_read` 已按这个顺序做；读到半截会回滚这一批、不推进游标，宁可报错也不给错答案。\n"
        "    · 适合：长时间连续录、要保证「一条都没丢」，而手上只有 SWD 两线。\n"
        "  怎么选：\n"
        "    · 要实时看 → stream；要最细粒度 + 一次完整过程 → buff。\n"
        "    · 要**长时间连续、不丢**、且只有 SWD 两线 → swd（见 topic=swd_seamless）。\n"
        "    · 高频事件（>1000 次/秒）× 长时间 → stream 会丢、buff 会回卷，"
        "swd 能扛但需要主机持续搬运：把插桩点收窄到真正关心的那几个，"
        "或把 TS_SHIFT 与记录数按需求配平。\n"
        "    · 三种模式的插桩点宏是同一份代码，只改 MDK_TRACE_BACKEND_* 重编切后端。"
    ),
    "swd_seamless": (
        "只有 SWD 两线，怎么做到**无缝（不丢）**地连续录制——这是 swd 后端要解决的问题，"
        "先记住一句话：\n"
        "  **事件先压缩进目标内存的环，主机定期来搬走已录部分，环循环用；"
        "只要平均搬运速度 ≥ 产生速度，就一条都不丢。**\n"
        "为什么别的路都走不通：\n"
        "  · ITM/SWO 要占 SWO 引脚——只有两线时没有这根线；\n"
        "  · RTT 要主机主动读，读的时候抢目标时间，长期高频会掉；\n"
        "  · 直接轮询内存（trace_scope 那类）粒度粗，中间发生的事看不见；\n"
        "  · buff 全速录但**写满覆盖最旧**，只能看一个窗口，看不到全程。\n"
        "所以唯一能连续的路径就是上面那句：**在环上做「背压」，而不是「覆盖」。**\n"
        "三个必须配对的设计（缺一个就不是无缝了）：\n"
        "  ① **背压**：写 token 前先算「这条要 n 字节，未读空间还够不够」，不够就整条丢弃"
        "并计数（lost_events / lost_bytes），**绝不覆盖还没被搬走的区域**。"
        "另外留一小块保留区（16 字节）只给控制帧用，保证「我丢过数据所以要重对齐」"
        "这条标记在最坏情况下仍然写得进去。\n"
        "  ② **压缩**：把 (type, kind, id, arg) 四元组当字典键，重复出现的事件只发一个 6bit "
        "槽号（命中），没见过的才发完整字面量并写进字典。典型负载 12 字节 → **2.35 字节/事件**。\n"
        "     **边界要说在前面**：字典 64 槽、直接映射哈希（O(1)，中断里开销可预测）。"
        "工作集超过 64 个不同四元组时命中率会归零，退化到约 11.3 字节/事件——"
        "这时要么把插桩点收窄、ID 复用，要么加大缓冲。\n"
        "  ③ **单边游标**：主机每搬走一批就把「读到哪儿了」写回目标（drained），"
        "目标只在这之后才允许复写那段空间。游标只有一个主人，不会两边各记一套。\n"
        "丢了怎么办——**必须双方一起清字典**：\n"
        "  · 命中只发槽号，字典不同步会把槽号解成**另一个 key**——这比丢数据严重得多，"
        "是典型的「看似权威的错答案」；\n"
        "  · 所以对齐手段只有一个：目标重开一段录制（清环、清字典、seq+1，并写一个 SYNC 标记），"
        "主机看到 seq 变了就跟着重置解码器。\n"
        "  · 这个动作由 `trace_swd_reset` 触发：宿主往控制块偏移 64 写 reset_req=1，"
        "目标在**下一条事件**开头清零并重开。\n"
        "  · 注意它是**延迟生效**的：目标长期没有事件时请求会一直挂着。"
        "返回里的 `applied` / `request_latched` 就是告诉你「生效了没有」，"
        "**别把 pending 当成 applied**，要确认就再读一次 status 看 seq。\n"
        "主机侧一次搬运的固定顺序（trace_swd_read 内部就是这么做的）：\n"
        "  读控制块 → 读字节 → 喂解码器 → 校验没有半截 token（leftover 必须为 0）→ "
        "推进 drained → 重读控制块对锚。\n"
        "  · 先读后推是硬要求：推早了目标就会覆写你还没搬走的字节；\n"
        "  · leftover 非 0 说明读到了半截 token → **回滚这一批、不推进游标**，"
        "报 swd-partial-token，宁可这次不推进也不给错解码；\n"
        "  · 只有「读完本批后 head / seq / lost_events 都没变」时，"
        "控制块里的周期计数才被当成最后一条事件的绝对时刻（anchor），否则时间原点标为「相对」。\n"
        "上手三步：\n"
        "  trace_swd_status → trace_swd_read（可反复调，一直看新的）→ trace_swd_reset（开新的）\n"
        "  记录量不够（环几分钟就绕一圈）时先别急着放弃：**时间粒度可以调粗**，"
        "见 topic=time_granularity。\n"
        "  插桩点怎么选见 topic=instrument_points；两种老模式见 topic=instrument_modes。"
    ),
    "time_granularity": (
        "无缝流的时间粒度是**可调的**：从「1 个 CPU 周期」到「一个系统调度 tick」"
        "再到「完全不记时间戳」——录得多长、看得多细，由你定。\n"
        "为什么需要它：事件率是硬的（SysTick 500us 一拍就要写 2 条、每次上下文切换写 "
        "2~3 条，真板上实测约 **10.5k 事件/秒**），而 dt 是变长编码——粒度高的时候"
        "几乎每条事件都要拖一个 varint 时间差。粒度调粗后相邻事件的时间差常常量化成 "
        "0，这时编码器自动改用 **HITN token（1 字节、干脆不带 dt）**，所以调粗粒度"
        "不只是「省几个字节」，是把绝大多数 token 压到 1 字节。\n"
        "  · 实测：cycle 档 3.67 字节/事件（8 KB 环装 0.21 s）；tick/none 档约 "
        "1.00 字节/事件（8 KB 环装 0.78 s，**约 3.7 倍**）。\n"
        "怎么切——**只有 trace_swd_reset(granularity=...) 这一个入口**，它先把粒度写进"
        "控制块（TS_SHIFT / DT_UNIT / FLAGS 的 TS_OFF 位），紧接着请求重开一段录制；"
        "于是新录的那一段整段都是新粒度，不会出现「半段旧单位、半段新单位」——"
        "那种流的时间轴是换算不出来的，工具会直接报 swd-granularity-mismatch，"
        "而不是给你一条看起来对、其实每格都错的时间轴。\n"
        "取值与语义：\n"
        "  · cycle —— 最细，1 个 dt 单位 = 1 个 CPU 周期；要看函数级/中断级的精确间隔时用。\n"
        "  · 500us —— **对齐内核 tick**（相当于「每 tick 一个单位」，粗到看不见 tick 内部）。"
        "注意 500us @84MHz = 42000 个周期，**不是 2 的幂**，所以走的是整数除法（DT_UNIT）"
        "而不是移位：把 42000 凑成 2 的幂就是给你一个错答案，我们不这么干。\n"
        "  · 1ms / 2.5us / 42 —— 直接给时间，工具按 cpu_hz 换算成周期数；"
        "恰好是 2 的幂时自动改走移位并在 note 里如实说明（移位最便宜）。\n"
        "  · none —— 完全不记时间戳，只留事件顺序，最省。**这时工具会明确告诉你"
        "「这段流没有时间轴」**：事件里的 dt_cycles / cycles / t_us 一律给 null，"
        "绝不按到达顺序编一个等距的假时间；画回放时也不能把等距排列画成等距时间。\n"
        "两条边界：\n"
        "  ① 按时间换算粒度前必须知道 cpu_hz——控制块里 cpu_hz=0（固件没填 "
        "MDK_TRACE_SWD_CPU_HZ）时会**直接报错**，让你改用 cycle / none，"
        "而不是拿一个编出来的主频去算；\n"
        "  ② 粗粒度只丢**分辨率**，不丢**事件**：每条事件都在，只是同单位内的先后"
        "被量化掉了（所以同刻的几条会被画在同一格）。时间原点仍锚在控制块的绝对周期"
        "计数上，量化误差只在段内、不累积。\n"
        "一次录制能不能装下，就是道算术题：\n"
        "  **环容量 ÷（事件率 × 字节/事件）** = 能录多久，再乘上主机的搬运频率就是上限。"
        "真板 10.5k 事件/秒时，cycle 档 8 KB 只装 0.21 s、tick 档 0.78 s——"
        "要长时间录就把粒度调粗、把插桩点收窄，或把环开大。\n"
        "与 ts_shift 的关系：ts_shift 是「单位 = 2^shift 个周期」，dt_unit 是"
        "「单位 = dt_unit 个周期」，两者只生效一个；都为 0 就是最细。"
        "用 time_granularity 这层抽象就不用自己算 shift 了。"
    ),
    "instrument_points": (
        "「桩插在哪儿」比「怎么读」更决定这次 trace 有没有用。按对排查的价值排序：\n"
        "  1. **异常 handler：第一优先级，而且必须插在第一条语句**\n"
        "     · HardFault / MemManage / BusFault / UsageFault / NMI：在 handler 开头调 "
        "MDK_TRACE_FAULT_CAPTURE()（读 LR/MSP/PSP，再从异常栈帧取 PC/LR/xPSR，按 CFSR 分类）。\n"
        "     · **越早越好**：栈（尤其 PSP）再被压一层、或你在 handler 里又调了函数，"
        "现场就变了；有些芯片还可能在 fault 里二次异常。\n"
        "     · 附带的寄存器转储（pc/lr/sp/xpsr/hfsr/mmfar/bfar）是 buff 模式最值钱的输出："
        "一块「刚砌掉」的板子，第一个问题就是 PC 在哪。\n"
        "     · 分类不要猜：CFSR 有具体字段就报具体类别，没有就如实报 HardFault。\n"
        "  2. **看门狗喂狗点 + 复位原因：第二优先级**\n"
        "     · 喂狗点用 MDK_TRACE_MARK()：喂狗停了，录到的最后一次喂狗与它前后的时间差"
        "就是「卡了多久」的直接证据。\n"
        "     · 复位后第一件事（main 里、外设初始化之前）打一个 MARK：配合 "
        "MDK_TRACE_BUFF_CLEAR_ON_INIT=0（默认），上一次运行（含异常复位前）的记录会保留，"
        "时间轴上以 reset 事件为接缝——这正是「复位循环」类问题唯一能用的证据。\n"
        "  3. **任务 / 线程切换点：看调度是否按预期**\n"
        "     · 每个切换点调 MDK_TRACE_SCHED(from, to)；同时给任务主体循环打一对 "
        "SCOPE_BEGIN/END，任务级耗时与切换频率都能算出来。\n"
        "     · 只在真正的阻塞原语里打 WAIT：漏了一两条阻塞路径，时间线上那段时间就是盲区。\n"
        "  4. **关键状态迁移 / 协议节点**：状态机迁移、通信帧头尾、中断进出，用成对的 "
        "SCOPE_BEGIN/SCOPE_END 夹住；ID 按自己的编号表定义，"
        "主机侧用 names=\"0x10=switch,0x11=wait\" 把它译成名字。\n"
        "  5. **不要插在的地方**\n"
        "     · 高频内循环（每毫秒上千次）→ buff 会回卷、stream 会丢，插桩本身还会影响时序；\n"
        "     · fault 之后还会继续执行、可能再次异常的代码路径；\n"
        "     · 优先级高于你要观测的中断的地方（插桩是普通函数调用，不是原子操作）。\n"
        "  一条硬规矩：插桩点只做「记一笔」，不要在里面调 printf 级别的重逻辑。"
        "buff 模式一次记录就是十来个 store——这才是它敢全速录的前提。"
    ),
    "lessons": (
        "这几次在真板上用 trace 撞出来的坑（完整版在 components/trace/README.md "
        "与 docs/PITFALLS.md）：\n"
        "  ① **目标全速运行时经 SWD 读 RAM，可能整片读回 0**（Keil 链路实测如此）。"
        "这**不等于那片内存是 0**，更不等于「缓冲是空的」。工具会在这种时候报 "
        "degenerate / read_confidence=low，buff 工具会直接报 buff-read-degenerate "
        "并让你先 halt——不要把 0 当结论。要读 RAM 就先停目标；buff 的记录在 RAM 里，"
        "停机不会丢。\n"
        "  ② **halt→读→resume 的代价**：单次约 320~510ms，停机期间目标时间被冻结。"
        "工具上报的 paused_ms 偏高（实测报 0.33~0.43s，按目标自身计数反算真实有效冻结"
        "约 0.27~0.30s）——**要用目标侧的时间戳算，不要用主机时钟**。\n"
        "  ③ **stop 之后第一次 read_mem 会读到全 0 脏帧**，重读才对。"
        "别拿第一次的结果下结论（read_mem_verified 会复读，自己手搓内存读时尤其要注意）。\n"
        "  ④ **不要用内核 tick 当时间戳**：500µs 的节拍会让大量相邻事件的 dt=0，"
        "10µs 级的切片全退化成 0，时间线看着像坏了。用 DWT_CYCCNT（84MHz 上 11.9ns），"
        "而且要先使能 DEMCR.TRCENA(1<<24)，否则计数不动。\n"
        "  ⑤ **环形缓冲一定会溢出**：必须把 lost / wrapped 透出来。分块 dump + reset "
        "拼时间线一定会留空洞（实测 8 块之间 7 段空洞、合计 4.1s），空洞要在图上画出来，"
        "不要连成一条直线骗人。\n"
        "  ⑥ **用 4bit 打包任务号，上限就是 14 个任务**（0x0F 要留给空闲）。"
        "任务多了要么换字段宽度，要么先裁掉不关心的任务。\n"
        "  ⑦ **只插了部分阻塞路径时，「任务 A 消失了 200ms」可能只是没插桩**，"
        "不是它真的在跑——这是「没测不等于没有」的原型。"
    ),
}


def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="trace_guide",
        title="Trace 方案选型与接线指南（SWO / RTT / SWD 采样）",
        description=(
            "讲清楚各条 trace 通路的硬件要求与代价，以及接线、ITM、RTT 的注意点。"
            "topic 可取：howto（总览与取舍）/ instrument_modes（**插桩的三种工作模式："
            "stream 持续录持续读 / buff 全速录事后一次性读回 / swd 无缝流（目标压缩入环、"
            "主机增量搬走），各自代价与选型**）/ swd_seamless（**只有 SWD 两线时怎么做"
            "无缝不丢的连续录制：背压而非覆盖、四元组字典压缩、丢失即双方清字典、"
            "reset_req 握手与延迟生效、搬字节的固定顺序**）/ "
            "time_granularity（**无缝流的时间粒度从「1 个 CPU 周期」到「系统 tick」"
            "再到「完全不记时间戳」怎么切：HITN 自动省字节、dt_unit 精确对齐 tick、"
            "改粒度必须重开一段录制**）/ "
            "instrument_points（**该往哪儿插桩：HardFault 等异常 handler 排第一，"
            "其次是看门狗喂狗点与任务切换点，以及哪些地方不该插**）/ "
            "lessons（**这几次在真板上撞出来的 7 个坑：运行态读 RAM 读回 0、"
            "halt 冻结与 paused_ms 偏高、stop 后首读脏帧、tick 当时间戳导致 dt=0、"
            "环形缓冲溢出与空洞、4bit 任务号只有 14 个、没插桩不等于没发生**）/ "
            "swd_limits（只用 SWD 两线能做到什么、做不到什么：变量 scope 与 DWT PC "
            "采样能做，指令级录制做不到）/ swd_wiring（接线）/ links（Keil 链路 vs "
            "OpenOCD 链路：观测类工具都带 link 参数）/ rtt_notes / itm_notes / "
            "when_unavailable（没数据时怎么排查）；留空返回全部。\n"
            "**没有 SWO 引脚并不等于不能 trace**：RTT 只要 SWD，无缝流（swd）也只要 SWD，"
            "采样剖析连缓冲都不要，MDK 原生 Event Recorder / Event Statistics 也只要 SWD（trace_eventrec 直接读它的缓冲），"
            "只是能拿到的东西不同——这份指南就是帮你按手头硬件选对路子。"
        ),
    )
    async def trace_guide(topic: str = "") -> str:
        try:
            t = (topic or "").strip().lower()
            if t and t in GUIDE:
                return _js({"ok": True, "topic": t, "text": GUIDE[t]})
            return _js({"ok": True, "topics": sorted(GUIDE), "guide": GUIDE,
                        "component_dir": COMPONENT_DIR,
                        "note": "组件源码在仓库 components/trace/，"
                                "用 trace_instrument 直接拷进工程"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_status",
        title="Trace 会话状态（模式 / 采集量 / 丢包统计）",
        description=(
            "一眼看清当前 trace 在干什么：mode（swo/rtt/profile）、已采集字节与报文数、"
            "MTF 帧数、**CRC 错与丢弃字节数**（这两个数 >0 就说明事件不全，"
            "不能把时间线当完整证据）、剩余未解析字节。"
            "RTT 模式下还会给 attach 的地址与通道统计。"
        ),
    )
    async def trace_status() -> str:
        try:
            out = {"ok": True, "mode": _T["mode"],
                   "link": ((_T.get("rtt") or {}).get("link")
                            or (_T.get("scope") or {}).get("link")),
                   "started_at": _T["started_at"] or None,
                   "uptime_s": round(time.time() - _T["started_at"], 2)
                   if _T["started_at"] else 0,
                   "events": len(_T["events"]),
                   "counters": dict(_T["counters"]),
                   "error": _T["error"]}
            if _T.get("decoder"):
                out["decoder"] = _T["decoder"].stats()
            if _T.get("itm_state"):
                out["itm_state"] = dict(_T["itm_state"])
            if _T.get("swo"):
                out["swo"] = _swo_state()
            if _T.get("rtt"):
                r = _T["rtt"]
                out["rtt"] = {"addr": "0x%X" % r["addr"],
                              "up_channels": len(r["cb"]["up"]),
                              "down_channels": len(r["cb"]["down"]),
                              "reads": r["reads"], "bytes_read": r["bytes_read"],
                              "bytes_written": r["bytes_written"]}
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swo_start",
        title="开始 SWO/ITM 采集（OpenOCD tpiu → 文件，主机侧增量解析）",
        description=(
            "在运行中的 OpenOCD 会话上配置 TPIU 并把原始 SWO 字节流落到文件："
            "`tpiu config internal <file> uart off <coreclk> <baud>` + `itm ports on` + "
            "`itm port N on`。\n"
            "coreclk（CPU 主频 Hz）与 baud（SWO 速率 bit/s）**必须与目标侧一致**，"
            "配错的表现是解析出来全是垃圾、dropped_bytes 暴涨；给 profile 可由目标档案"
            "带出默认值。ports 默认 \"0,1\"（0 一般是 printf 的 ITM 通道，"
            "1 留给结构化事件）。\n"
            "**前提**：探针支持 SWO 且 SWO 引脚已接；目标侧跑我们的插桩组件"
            "（components/trace）才有人往 ITM 里写。开始后用 trace_swo_read 增量取。"
        ),
    )
    async def trace_swo_start(file: str = "", coreclk: int = 0, baud: int = 0,
                              ports: str = "0,1", profile: str = "") -> str:
        try:
            return _js(swo_start(file=file, coreclk=coreclk, baud=baud,
                                 ports=ports, profile=profile))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swo_read",
        title="增量读取 SWO 采集并解成事件（不阻塞）",
        description=(
            "从上次读到的位置继续读采集文件，做 ITM 解码 + MTF 帧解析，返回**新增事件**。"
            "可以反复调（像轮询日志一样），不会读重复数据。\n"
            "返回里务必看三个数字：overflow（ITM 溢出次数）、decoder.crc_errors"
            "（被截断的帧）、decoder.dropped_bytes（非 MTF 残渣）——"
            "**任一非零都说明事件流不完整**，分析时序时不能当全量证据。\n"
            "ports 可只关心部分 ITM 端口，减少噪声。"
        ),
    )
    async def trace_swo_read(max_events: int = 300, ports: str = "") -> str:
        try:
            pl = None
            if ports:
                pl = [int(x) for x in re.split(r"[,\s]+", ports) if x.strip()]
            return _js(swo_read(max_events=int(max_events), ports=pl))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swo_stop",
        title="停止 SWO 采集",
        description=(
            "关掉 ITM 端口停止数据产生（OpenOCD 没有专门的「停 tpiu 输出」命令，"
            "关端口是等价且安全的做法），采集文件保留，可随时用 trace_decode 离线复解。"
        ),
    )
    async def trace_swo_stop() -> str:
        try:
            return _js(swo_stop())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_decode",
        title="离线解码 SWO 字节流（hex 或文件）",
        description=(
            "不依赖会话，直接把一段 SWO 原始字节（data_hex 或 file）解成 "
            "ITM 报文 + MTF 事件帧，并给报文类型统计（各端口多少包、硬件源包分布、"
            "溢出次数）。用途：\n"
            "  - 复解之前 trace_swo_start 落下的文件（不带会话也能分析）；\n"
            "fmt：auto/itm/mtf——**RTT 读回的数据要 fmt=\"mtf\"**（RTT 通道里就是 MTF 帧本体，外面没有 ITM 封装；auto 也会自动识别）；\n"
            "  - 单独验证一段抓包（比如同事发来的 bin）；\n"
            "  - meta=true 时附 ITM 报文明细，用来核对波特率/时钟配错没配错。"
        ),
    )
    async def trace_decode(data_hex: str = "", file: str = "", ports: str = "",
                           limit: int = 500, meta: bool = False,
                           fmt: str = "auto") -> str:
        try:
            return _js(decode(data_hex=data_hex, file=file, ports=ports,
                              limit=int(limit), meta=bool(meta), fmt=fmt))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_events",
        title="查看已解析的结构化事件（时间线）",
        description=(
            "返回缓冲里的事件（SWO 的 ITM/MTF、RTT 不算在内、SWD 采样的 PC 样本在内），"
            "可按 kind 或通道/端口过滤，并给按类型/按函数/按事件 ID 的计数。\n"
            "事件类型：text（打印）、event（进入/退出）、counter、isr、mark、ts、kv、"
            "exception（硬件异常）、pc_sample、overflow（丢包）、timestamp_itm。\n"
            "limit 控制返回条数（默认从最新往回取），counts 给全量统计。"
        ),
    )
    async def trace_events(limit: int = 100, kind: str = "", channel: str = "",
                           since: float = 0) -> str:
        try:
            evs = _T["events"]
            if kind:
                ks = {k.strip() for k in re.split(r"[,\s]+", kind) if k.strip()}
                evs = [e for e in evs if e.get("kind") in ks]
            if channel:
                ch = channel.strip()
                evs = [e for e in evs if str(e.get("port") or e.get("channel") or "") == ch]
            if since:
                evs = [e for e in evs if (e.get("t") or 0) >= float(since)]
            counts = {}
            for e in evs:
                counts[e.get("kind")] = counts.get(e.get("kind"), 0) + 1
            n_max = max(1, int(limit))
            tail = evs[-n_max:]
            return _js({"ok": True, "total_matched": len(evs),
                        "buffer_total": len(_T["events"]),
                        "counts": counts, "events": tail,
                        "truncated": len(evs) > n_max,
                        "note": "t 是相对 trace 开始的时间（秒，主机侧时间）；"
                                "要目标侧精确时间看 ts 字段（DWT 周期数）"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_clear",
        title="清空 trace 事件缓冲 / 重置会话状态",
        description=(
            "清事件缓冲，或（reset=true）连模式、解码器状态、SWO 偏移一起复位。"
            "**reset=true 不会去动 OpenOCD 会话**（采集还在继续，只是主机侧重新计数），"
            "要停采集用 trace_swo_stop。"
        ),
    )
    async def trace_clear(reset: bool = False) -> str:
        try:
            if reset:
                return _js(reset_state(keep_events=False))
            n0 = len(_T["events"])
            _T["events"] = []
            return _js({"ok": True, "cleared": n0})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_rtt_find",
        title="定位 RTT 控制块（ELF 符号优先，其次扫 RAM）",
        description=(
            "找 SEGGER RTT 控制块地址。两条路：\n"
            "  1. 给 elf —— 直接读符号 `_SEGGER_RTT`（最可靠，符号被 --gc-sections "
            "回收时会找不到）；\n"
            "  2. 给 ranges（如 \"0x20000000-0x20010000\"）—— 主机分块读 RAM 扫 "
            "'SEGGER RTT' 魔数（需要目标已 halt，扫 256KB 也就几十次内存读）。\n"
            "找到后喂给 trace_rtt_attach。\n"
            "link 选内存通路：auto（默认，哪条在跑用哪条）/ keil / ocd。"
        ),
    )
    async def trace_rtt_find(elf: str = "", ranges: str = "",
                             id_str: str = "SEGGER RTT",
                             link: str = "auto") -> str:
        try:
            return _js(rtt_find(elf=elf, ranges=ranges, id_str=id_str,
                                link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_rtt_attach",
        title="挂接 RTT（读控制块，列出上下行通道）",
        description=(
            "读 RTT 控制块并记住通道信息，之后 trace_rtt_read / trace_rtt_write "
            "直接用。addr 省略时自动按 elf 符号或 RAM 扫描定位。\n"
            "返回 up（目标→主机，日志/事件）与 down（主机→目标，命令）通道列表，"
            "含缓冲大小与当前读写指针。**只依赖内存读写**，不依赖 OpenOCD 的 rtt 命令"
            "——RISC-V/Xtensa 目标上这条路照样通。\n"
            "link 选内存通路：auto（默认）/ keil / ocd；挂上后 rtt_read/rtt_write 沿用这条链路。"
        ),
    )
    async def trace_rtt_attach(addr: str = "", size: int = 0, elf: str = "",
                               id_str: str = "SEGGER RTT",
                               link: str = "auto") -> str:
        try:
            a = int(addr, 16) if str(addr).lower().startswith("0x") else (
                int(addr) if str(addr).strip().isdigit() else 0)
            return _js(rtt_attach(addr=a, size=int(size or 0), elf=elf,
                                  id_str=id_str, link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": addr, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_rtt_read",
        title="读 RTT 上行通道（并按标准协议推进 RdOff）",
        description=(
            "从 up 通道取数据。内部做了三件正确的事：重读控制块拿最新 WrOff（目标在跑，"
            "指针一直在变）、按环形缓冲绕回分段读、读完把 RdOff 写回目标。\n"
            "**不写回 RdOff 是自制 RTT 主机最常见的错误**：目标会认为缓冲一直满，"
            "后续数据全丢。返回里给 dropped（这次没读完的部分）与 rd_writeback。\n"
            "max_bytes 控制单次最多取多少（避免一次拉满）。"
        ),
    )
    async def trace_rtt_read(channel: int = 0, max_bytes: int = 1024) -> str:
        try:
            return _js(rtt_read(channel=int(channel), max_bytes=int(max_bytes)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "channel": channel, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_rtt_write",
        title="写 RTT 下行通道（主机→目标命令）",
        description=(
            "往 down 通道写数据（目标侧轮询读取）。空间不足时按标准 RTT 语义"
            "**只写能写下的部分并如实返回 dropped**（不阻塞、不覆盖未读数据）。"
            "data 按 UTF-8 编码，hex_data 可发二进制（如带 CRC 的命令帧）。"
        ),
    )
    async def trace_rtt_write(channel: int = 0, data: str = "",
                              hex_data: str = "") -> str:
        try:
            return _js(rtt_write(channel=int(channel), data=data, hex_data=hex_data))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "channel": channel, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_rtt_detach",
        title="断开 RTT 挂接（保留事件缓冲）",
        description="清掉 RTT 会话状态并返回本次读/写统计；不动事件缓冲，也不停采集。",
    )
    async def trace_rtt_detach() -> str:
        try:
            return _js(rtt_detach())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_scope_start",
        title="变量 scope（只用 SWD 两线，不 halt 目标）",
        description=(
            "不用改目标代码、也不用 SWO 引脚，直接观测 RAM 里的变量：主机侧按周期"
            "用 DAP 读内存（**不 halt 目标、不扰动执行**），把变量值连成时间线。\n"
            "vars 写法（逗号分隔）：`g_cnt@0x20000000:4` / `0x20000010:4` / "
            "`name@addr` / `name`（只给名字就用 elf 查地址与大小）。\n"
            "**它做不到什么必须说清楚**：轮询是有间隔的，两次采样之间的跳变看不到；"
            "采样率是主机轮询率而非目标周期；目标在跑时若 OpenOCD 拒绝读内存"
            "（require_halt=true），就必须改用 RTT/ITM 让目标自己推数据。\n"
            "指令级 CPU 录制（每一跳都记下来）需要 ETM 并行 trace 口，**SWD 两线做不到**。\n"
            "**这条两条链路通用**：Keil 侧先在调试会话里 enter_debug，OpenOCD 侧先 ocd_start；"
            "link 可显式指定 auto/keil/ocd。"
        ),
    )
    async def trace_scope_start(vars: str = "", elf: str = "",
                                period_ms: float = 100.0,
                                max_samples: int = 2000,
                                duration_s: float = 0.0,
                                timeout: float = 5.0,
                                link: str = "auto") -> str:
        try:
            return _js(scope_start(vars=vars, elf=elf, period_ms=float(period_ms),
                                   max_samples=int(max_samples),
                                   duration_s=float(duration_s),
                                   timeout=float(timeout), link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_scope_read",
        title="看变量 scope 的最近采样与统计",
        description=(
            "取变量 scope 的最新情况：每变量 min/max/最后值/变化次数、真实生效采样率、"
            "丢点次数（misses）。recent 只给最近 limit 条，不会把上万条样本塞回上下文。"
        ),
    )
    async def trace_scope_read(limit: int = 200) -> str:
        try:
            return _js(scope_read(limit=int(limit)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_scope_stop",
        title="停止变量 scope 并汇总",
        description=("停掉后台轮询线程，返回本次观测汇总（每变量 min/max/变化次数、"
                     "实际采样率、丢点）。**忘了停会一直占着 SWD 带宽**，"
                     "影响后面的 halt/断点操作，用完就停。"),
    )
    async def trace_scope_stop() -> str:
        try:
            return _js(scope_stop())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_pcsample",
        title="DWT 硬件 PC 采样（不 halt 目标的函数分布）",
        description=(
            "靠 DWT 自带的硬件 PC 采样器（DEMCR.TRCENA + DWT_CTRL.PCSAMPLENA，"
            "读 DWT_PCSR）看函数分布：**全程不 halt 目标**，实时性不受扰动。\n"
            "与 trace_profile 的区别：那个是 halt→读 PC→resume（侵入式），"
            "这个是硬件采样器自己采、主机只读寄存器（非侵入）。\n"
            "**如果采样器不工作会明确报错**（sampler_inactive / 值不变），"
            "不会给一份看着像样的分布——部分 Cortex-M 修订版上 PC 采样器确实不可用。\n"
            "样本是「采样器最近一次采到的 PC」，同一值会被重复读到，占比仅供参考；"
            "默认采样结束会恢复 DEMCR/DWT_CTRL 原值。"
        ),
    )
    async def trace_pcsample(samples: int = 500, interval_ms: float = 10.0,
                             elf: str = "", top: int = 15,
                             enable_dwt: bool = True, restore: bool = True,
                             timeout: float = 20.0,
                             link: str = "auto") -> str:
        try:
            return _js(pc_sample(samples=int(samples),
                                 interval_ms=float(interval_ms), elf=elf,
                                 top=int(top), enable_dwt=bool(enable_dwt),
                                 restore=bool(restore), timeout=float(timeout),
                                 link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_profile",
        title="采样剖析（SWD 无 SWO 时的兜底：halt→读 PC→resume）",
        description=(
            "没有 SWO 引脚、也不想加 RTT 缓冲时，用「停下来取样」的办法看热点："
            "反复 halt → 读 pc → resume，统计函数命中分布。给 elf 就能把地址翻译成函数名"
            "（否则按地址聚合）。\n"
            "**明确标注为侵入式**：每条样本都中断了目标，实时性被破坏，"
            "返回里的 warning 和 intrusive=true 别忽略——结论只能用于"
            "「热点大概在哪」，不能当精确耗时。要做真实耗时请用 DWT CYCCNT"
            "（trace_dwt_counters 看计数，目标侧用组件里的计时宏）。"
        ),
    )
    async def trace_profile(samples: int = 200, elf: str = "",
                            interval_ms: float = 0, top: int = 15,
                            timeout: float = 20.0,
                            link: str = "auto") -> str:
        try:
            return _js(profile_samples(samples=int(samples), elf=elf,
                                       interval_ms=float(interval_ms),
                                       top=int(top), timeout=float(timeout),
                                       link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_dwt_counters",
        title="读 DWT 计数器（CYCCNT / 异常 / 睡眠 / 折叠周期）",
        description=(
            "读 DWT 的 CTRL/CYCCNT/CPICNT/EXCCNT/SLEEPCNT/LSUCNT/FOLDCNT 并解出 "
            "CYCCNT 使能位。配合目标侧插桩组件里的计时宏，可以测「这段代码花了多少周期」"
            "——**这是不丢精度的计时手段，比采样剖析靠谱得多**。\n"
            "FOLDCNT 非零说明邮箱都被占用了，SWO 那边必然丢包；SLEEPCNT 反映空闲程度。"
            "仅 Cortex-M3 及以上有 DWT；RISC-V/Xtensa 上读不到，用它们的 mcycle CSR。"
        ),
    )
    async def trace_dwt_counters(link: str = "auto") -> str:
        try:
            return _js(dwt_counters(link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_instrument",
        title="把插桩组件部署进工程（生成配置头 + 构建片段）",
        description=(
            "把 components/trace/ 的目标侧插桩组件拷进你的工程，并按参数生成 "
            "mdk_trace_config.h（后端选择 ITM/RTT/UART/BUFF/SWD、ITM 端口、RTT 通道数与"
            "缓冲大小、CPU 主频、SWO 波特率、DBGMCU_CR 地址）与 mdk_trace.mk（Make 集成片段）。\n"
            "**为什么必须有目标侧组件**：SWO/RTT 只是通道，芯片不会自己往外说话——"
            "得有代码在关键点把事件写进 ITM/RTT 缓冲，主机才 trace 得到东西。"
            "安装完按返回的 next 步骤接进构建（CMake 用 add_subdirectory 或直接加源文件）。"
            "target_dir 指定部署目录（如工程里的 components/trace）。\n"
            "**backend 五选一**：itm / rtt / uart（stream：事件立刻出芯片，主机实时跟读）/ "
            "**buff（全速录：事件只写进 RAM 环形缓冲，事后用 trace_buff_dump 一次性读回，"
            "时间粒度可以开到每 CPU 周期）** / **swd（无缝流：事件压缩后写进环形缓冲，"
            "主机用 trace_swd_read 增量搬走、未读区永不覆盖，只要平均搬运速度跟得上就零丢失；"
            "只有 SWD 两线、又要长时间不丢时选它）**。\n"
            "buff 的旋钮：buff_records（记录数 × 12B = 静态 RAM）、buff_ts_shift（0 = 每周期，"
            "间隔可能超 51s 才需调大）、buff_clear_on_init（默认 false = 复位后保留上一次运行的"
            "记录，看门狗/fault 复位时那是唯一证据）、fault_frame（异常 handler 里多存一份寄存器现场）。\n"
            "swd 的旋钮：swd_bytes（环字节数 = 静态 RAM，默认 8192）、swd_ts_shift（0 = 每周期）、"
            "swd_clear_on_init（**默认 true**，与 buff 相反——无缝流主机是从游标往 head 读，"
            "环里留着上一次运行的字节会把两段无关运行无缝拼在一起，没有可见接缝，最危险）。\n"
            "**构建清单自检**：返回里还带 build_list_check —— 核对 mdk_trace.mk 与 "
            "CMakeLists.txt 列出的 .c 是否与目录里实际的后端源文件一致（漏列 = 那条通路"
            "根本没编进去，多列 = 构建必然失败）；不一致时 ok=false、"
            "error_code=component-sources-mismatch。这一项不依赖 C 编译器。\n"
            "**部署后自检**：返回里带 self_check —— 就地用 arm-none-eabi-gcc 把该后端的"
            "组件源文件真编一遍并链接（空壳提供 CMSIS 内在函数与入口），缺符号当场报 "
            "undefined reference，就是 build 时那个 L6218E 的等价物。缺符号时整体 ok=false、"
            "error_code=component-link-failed，并给出 missing_symbols 与 sources（该进编译的"
            "文件清单）。本机没有 C 编译器时 self_check.checked=false —— 那是**没查**，"
            "不等于组件没问题，别把它当成通过。\n"
            "该往哪儿插桩见 trace_guide(topic=\"instrument_points\")。"
        ),
    )
    async def trace_instrument(target_dir: str, backend: str = "itm",
                               itm_port: int = 1, rtt_up: int = 2,
                               rtt_down: int = 1, rtt_buf: int = 1024,
                               coreclk: int = 0, overwrite: bool = False,
                               swo_baud: int = 2000000,
                               dbgmcu_cr: int = 0xE0042004,
                               buff_records: int = 2048,
                               buff_ts_shift: int = 0,
                               buff_clear_on_init: bool = False,
                               fault_frame: bool = True,
                               swd_bytes: int = 8192,
                               swd_ts_shift: int = 0,
                               swd_clear_on_init: bool = True,
                               link_check: bool = True) -> str:
        try:
            return _js(deploy_component(target_dir, backend=backend,
                                        itm_port=int(itm_port), rtt_up=int(rtt_up),
                                        rtt_down=int(rtt_down), rtt_buf=int(rtt_buf),
                                        coreclk=int(coreclk), overwrite=bool(overwrite),
                                        swo_baud=int(swo_baud),
                                        dbgmcu_cr=int(dbgmcu_cr),
                                        buff_records=int(buff_records),
                                        buff_ts_shift=int(buff_ts_shift),
                                        buff_clear_on_init=bool(buff_clear_on_init),
                                        fault_frame=bool(fault_frame),
                                        swd_bytes=int(swd_bytes),
                                        swd_ts_shift=int(swd_ts_shift),
                                        swd_clear_on_init=bool(swd_clear_on_init),
                                        link_check=bool(link_check)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "target_dir": target_dir, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_buff_status",
        title="buff 模式：读控制块（容量 / 已录 / 丢了多少 / 是否回卷）",
        description=(
            "buff 模式（目标侧把事件写进 RAM 环形缓冲、一个字节不出芯片）的健康快照。"
            "只需一次 80 字节内存读，很便宜。返回：cap/total/lost/text_dropped、"
            "是否回卷（wrapped）、目标是否在保留旧记录的前提下重启过（restarted）、"
            "ts_shift（时间粒度）、cpu_hz、记录的起始地址。\n"
            "**定位**：默认按 ELF 符号 mdk_trace_buff_blob 找（elf= 或会话已 set_symbol_file 的可省），"
            "也可以 addr=0x... 直接给。找不到符号会明确报 buff-symbol-missing，不会猜。\n"
            "**读回整片 0 不等于缓冲是空的**：目标全速运行时经 SWD 读 RAM 可能整片读回 0，"
            "这种情况会报 buff-read-degenerate 并让你先停下目标再读。"
        ),
    )
    async def trace_buff_status(elf: str = "", addr: str = "",
                                link: str = "auto") -> str:
        try:
            return _js(buff_status(elf=elf, addr=addr, link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_buff_dump",
        title="buff 模式：一次性读回整个环形缓冲并解成时间线",
        description=(
            "把目标 RAM 里的定长记录（12 字节：type/kind/id/arg/dt）全部读回来，"
            "按 dt 累出绝对时间轴，并给出分类型/分 id 计数、周期统计、异常现场。\n"
            "**这是「全速录制」的读取端**：目标侧不阻塞、不停机、不需要 SWO 引脚，"
            "所以可以把时间粒度开到最小（MDK_TRACE_BUFF_TS_SHIFT=0，即每 CPU 周期）。"
            "代价是缓冲写满后新记录覆盖最旧的（返回 wrapped=true 并给 total/cap）。\n"
            "**异常（fault）会被展开**：类别 + CFSR 逐位拆解 + 寄存器现场"
            "（pc/lr/sp/xpsr/hfsr/mmfar/bfar），这是插桩录制最有价值的输出之一。\n"
            "limit 只控制**返回**给你的条数（默认 200，取最新的）；要看全量就传 out_file，"
            "工具会把整个时间线写成 JSON 落盘并只回统计——几万条记录不要往对话里塞。\n"
            "names 可把 id 译成名字（如 \"0x10=switch,0x11=wait\"），避免对着手册查。"
        ),
    )
    async def trace_buff_dump(elf: str = "", addr: str = "", limit: int = 200,
                              out_file: str = "", names: str = "",
                              link: str = "auto") -> str:
        try:
            return _js(buff_dump(elf=elf, addr=addr, limit=int(limit),
                                 out_file=out_file, names=names, link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_buff_reset",
        title="buff 模式：让目标开一段新录制",
        description=(
            "往控制块的 reset_req 写 1，目标在**下一条记录写入时**清空缓冲、seq 加一。\n"
            "**必须知道的两件事**：① 它是延迟生效的——目标若长期没有插桩事件，"
            "这个请求会一直挂着，返回里 request_latched/pending 就是这个意思，"
            "不要把它当成「已清空」；② 目标全速运行时写 SRAM 可能不生效，"
            "这种情况会如实报 buff-reset-write-failed 并建议先 halt。\n"
            "生效与否以 seq 是否变化为准（wait=true 会重读控制块确认），而不是以「写成功」为准。"
        ),
    )
    async def trace_buff_reset(elf: str = "", addr: str = "",
                               wait: bool = True, link: str = "auto") -> str:
        try:
            return _js(buff_reset(elf=elf, addr=addr, wait=bool(wait), link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swd_status",
        title="swd 无缝流：读控制块（容量 / 未读字节 / 丢了多少 / 压缩比）",
        description=(
            "swd 无缝流后端（压缩 + 背压，只要 SWD 两线的**连续**录制）的健康快照。"
            "只读 80 字节控制块，很便宜。返回：head/drained/pending、重复次数 seq、"
            "lost_events/lost_bytes、环容量、cpu_hz，以及整体的 "
            "overall_bytes_per_event 与 compression_vs_12B。\n"
            "**时间粒度**在 granularity 字段里翻成人话：mode=ts_shift/dt_unit/none、"
            "unit_cycles（一个 dt 单位 = 多少 CPU 周期）、unit_us。"
            "mode=none 表示这段流压根没有时间戳（只有事件顺序）。"
            "改粒度请用 trace_swd_reset(granularity=...)——它必须配一次重开录制。\n"
            "**定位**：默认按 ELF 符号 mdk_trace_swd_blob 找（elf= 或会话已 set_symbol_file 的可省），"
            "也可以 addr=0x... 直接给；找不到会明确报 swd-symbol-missing，不会猜。\n"
            "**读回整片 0 不等于没事件**：目标全速运行时经 SWD 读 RAM 可能整片读回 0，"
            "这种情况会报 swd-read-degenerate 并让你先 halt；停一下不会丢数据。\n"
            "pending 接近 cap 时会在 warnings 里提醒：宿主再跟不上，目标就要开始丢事件了。"
        ),
    )
    async def trace_swd_status(elf: str = "", addr: str = "",
                               link: str = "auto") -> str:
        try:
            return _js(swd_status(elf=elf, addr=addr, link=link))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swd_read",
        title="swd 无缝流：把未读的那段搬走并解成事件（连续录制的主操作）",
        description=(
            "**无缝流的核心动作**：读控制块 → 读 [drained, head) → 解码 → 把 drained 推上去。"
            "目标因此可以循环使用那块环，主机反复调这个工具就能一直录下去。\n"
            "与 buff 的关键区别：**未读区永不被覆盖**。宿主跟不上时目标丢**新**事件并计入 "
            "lost_events（权威计数），已经录下的那部分始终是完整可读的。\n"
            "多次调用会累加成一个连续时间线（会话状态在进程内）；返回的 events 只给最新 limit 条，"
            "全量用 out_file 落盘——几万条不要往对话里塞。\n"
            "事件里 auto 带出 gap（丢了一段）、sync（目标重开了录制段）、fault（异常，含 CFSR 拆位"
            "与寄存器现场）。\n"
            "**宿主一侧没有「从半路接上」的办法**：HIT token 只带槽号，字典一旦漂移就会解出错误的 id，"
            "那时会报 swd-stream-desync，正确做法是 trace_swd_reset 让目标重开一段。\n"
            "**时间粒度**：返回里的 granularity 说明这段流一个 dt 单位是多少 CPU 周期"
            "（mode=none 就是没有时间戳、只有顺序）。granularity= 传值时只做**校验**："
            "与控制块不符会报 swd-granularity-mismatch（一段流里混两种单位换算出来就是"
            "错的），改粒度要用 trace_swd_reset(granularity=...)。\n"
            "**consistent= 决定怎么搬这一块**（默认 halt）：halt=先停机、就地重读控制块做个"
            "一致快照、搬完写游标再放行——真机实测这是唯一能保证「搬到的就是目标写进去的"
            "那一份」的做法（停机读与目标 tokens 计数逐字节吻合），停机期间未读数据不会丢"
            "（背压不覆写），代价是每搬一次停几毫秒；run=全速搬，但实测有的目标/地址段会"
            "整片读回伪值（全 0 / 全 FF / 整段重复同一个 4 字节字），碰到伪值直接报 "
            "swd-read-untrusted 而不是拿去解码；auto=先全速读，发现伪值自动停机重读一次。"
            "返回里的 consistent / halt_ms 说明这一块实际是怎么搬的。\n"
            "**任务名（tasks=，默认 auto）**：调度事件在流里只带任务序号（0..14，0xF=idle），"
            "默认会读一次内核的 svcrt_task_table，用每个槽位的 entry 函数地址反查 ELF 符号，"
            "把序号变成真实任务名（事件里多出 from_name / to_name / task_name）；"
            "同一会话只解析一次，解析出来后历史上已解过的事件也会回头重补名字。"
            "取不到就只在 task_names 里如实说明原因，**不编名字**（宁可没名字，也不要错名字）。"
            "tasks=refresh 强制重解析，tasks=off 完全关掉。"
        ),
    )
    async def trace_swd_read(elf: str = "", addr: str = "", limit: int = 200,
                             out_file: str = "", names: str = "",
                             link: str = "auto",
                             reset_session: bool = False,
                             granularity: str = "",
                             consistent: str = "halt",
                             tasks: str = "auto") -> str:
        try:
            return _js(swd_read(elf=elf, addr=addr, limit=int(limit),
                                out_file=out_file, names=names, link=link,
                                reset_session=bool(reset_session),
                                granularity=granularity,
                                consistent=consistent, tasks=tasks))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swd_tasks",
        title="swd 无缝流：把任务序号解成任务名（调度事件可读的前提）",
        description=(
            "流里的调度事件只带**任务序号**（4 bit：0..14 是任务表下标、0xF 是 idle），"
            "看上去就是一堆数字。本工具把序号翻成名字，办法是读内核的 svcrt_task_table："
            "每一项的 entry（void (*)(void)）就是这个槽位从哪个函数开始跑，"
            "再拿入口地址反查 ELF 的函数符号。（TCB 里没有名字字段，这是能稳定取到"
            "「任务叫什么」的字段；TCB 的 sizeof 与 entry 偏移从 DWARF 取，不靠猜。）\n"
            "**只认精确符号**：入口地址必须是这份 .axf 里某个函数的首地址。**不拿"
            "「最近的下方符号」顶**——跨镜像的地址会被硬安上一个像样的错名字。\n"
            "**跨镜像的入口是合法的**：SVCrtOS 的 app/驱动是另外下发的镜像，它们的任务"
            "入口根本不在这份内核 .axf 的符号表里，这种槽位一律**留空**（不编 sub_XXXX），"
            "并在 unmapped_slots / hint 里说清楚怎么给它们取名。整段读回伪值（全 0/全 FF/"
            "同一个字重复）→ 拒绝；**所有**非空槽都落不到符号表里（一个名字都给不出）→ "
            "整批拒绝（报 tasks-snapshot-inconsistent），不拿半张表冒充好结果。\n"
            "**下标 15 不给名**：编号 15 被 idle 占用，表里下标 15 及以后的项永远"
            "不出现在流里（内核 TCB 表实测 48 项，但流只能看见前 15 项）。\n"
            "halt=True 会停机读（TCB 每次切换都被改写，停机读是一份自洽快照），"
            "读完放回运行态；默认全速读。trace_swd_read 默认会自动调它一次。"
        ),
    )
    async def trace_swd_tasks(elf: str = "", link: str = "auto",
                              halt: bool = False, refresh: bool = False) -> str:
        try:
            return _js(_svcrt_task_names(elf=elf, link=link, halt=bool(halt),
                                         refresh=bool(refresh)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_swd_reset",
        title="swd 无缝流：让目标开一段新录制（清环 + 两边一起清字典）",
        description=(
            "往控制块的 reset_req 写 1，目标在下一条事件写入时清环、清计数、字典两边一起清、seq 加一，"
            "并往新流里写一个 SYNC 标记。\n"
            "**这是无缝流唯一的重新对齐手段**：宿主字典与目标字典不同步时，宿主单方面清字典只会让"
            "后续每个 HIT 都解错——只能由目标重开一段把两边一起归零。\n"
            "与 buff 一样是**延迟生效**的：目标长期没有插桩事件时会一直挂着（返回 request_latched），"
            "那不是失败，但也不能当成「已清空」。生效与否以 seq 是否变化为准（wait=true 会重读确认）。\n"
            "**granularity= 是切换时间粒度的唯一入口**：先把 TS_SHIFT / DT_UNIT / "
            "FLAGS 的 TS_OFF 位写进控制块，再请求重开录制，于是新录的那一段整段都是"
            "新粒度。取值 cycle（最小，1 个 CPU 周期）/ none（完全不记时间戳，只留"
            "顺序，最省字节）/ 500us（对齐内核 tick）/ 1ms / 2.5us，或直接给微秒数；"
            "留空不动粒度。想多录事件就把粒度调粗：tick 档实测约 1.00 字节/事件。"
        ),
    )
    async def trace_swd_reset(elf: str = "", addr: str = "",
                              wait: bool = True, link: str = "auto",
                              granularity: str = "") -> str:
        try:
            return _js(swd_reset(elf=elf, addr=addr, wait=bool(wait), link=link,
                                 granularity=granularity))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
