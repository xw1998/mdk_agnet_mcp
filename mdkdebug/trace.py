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
               "itm_state": {}, "swo": None, "rtt": None,
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


def _read_mem_words(addr: int, n_bytes: int, timeout: float = 10.0, link="auto"):
    """读目标内存：走链路原语层，Keil(UVSOCK) / OpenOCD 谁活着用谁。

    返回 (bytes|None, meta)。meta 里带读置信度与「目标当时在不在跑」——
    上层要如实披露，**读到的 0 不等于数据是 0**。
    """
    lk, err = _link.pick(link, who="读目标内存")
    if lk is None:
        return None, err
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


def deploy_component(target_dir: str, backend: str = "itm", itm_port: int = 1,
                     rtt_up: int = 2, rtt_down: int = 1, rtt_buf: int = 1024,
                     coreclk: int = 0, overwrite: bool = False,
                     swo_baud: int = 2000000, dbgmcu_cr: int = 0xE0042004,
                     buff_records: int = 2048, buff_ts_shift: int = 0,
                     buff_clear_on_init: bool = False,
                     fault_frame: bool = True) -> dict:
    """把插桩组件拷进工程，并生成 mdk_trace_config.h + 构建片段。"""
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
    sources = ["mdk_trace.c"]
    if b == "rtt":
        sources.append("mdk_trace_rtt.c")
    if b == "buff":
        sources.append("mdk_trace_buff.c")
    nxt = ["把 %s 加入工程编译" % " / ".join(sources),
           "include mdk_trace.mk（Make）或 add_subdirectory（CMake）",
           "在初始化处调 mdk_trace_init()；用 MDK_TRACE_SCOPE() 打点",
           "在 HardFault / MemManage / BusFault / UsageFault handler 的**第一条**语句调 "
           "MDK_TRACE_FAULT_CAPTURE()（越早越好，栈还可能没被破坏），再进你的死循环；"
           "看门狗喂狗点、关键状态迁移用 MDK_TRACE_MARK()",
           "任务 / 线程切换处调 MDK_TRACE_SCHED(from, to)"]
    if b == "buff":
        nxt += ["buff 模式：目标跑完或出事后 trace_buff_dump(elf=你的.axf) 一次性读回",
                "buff 模式不需要 SWO 引脚、不需要主机实时跟读，但缓冲写满会覆盖最旧的"]
    else:
        nxt += ["SWO 通路：trace_swo_start + 目标侧 MDK_TRACE_BACKEND_ITM",
                "RTT 通路：trace_rtt_attach(elf=你的.elf)"]
    return {"ok": True, "target_dir": dst, "copied": copied, "skipped": skipped,
            "backend": b, "itm_port": itm_port, "next": nxt,
            "skip_note": "已存在的文件默认不覆盖（overwrite=true 才覆盖）"}


def _gen_config_h(backend: str, itm_port: int, rtt_up: int, rtt_down: int,
                  rtt_buf: int, coreclk: int, swo_baud: int = 2000000,
                  dbgmcu_cr: int = 0xE0042004, buff_records: int = 2048,
                  buff_ts_shift: int = 0, buff_clear_on_init: bool = False,
                  fault_frame: bool = True) -> str:
    b = (backend or "itm").strip().lower()
    if b not in ("itm", "rtt", "uart", "none", "buff"):
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
        "# 三个源文件都可无脑编：未选中的后端会编成空目标文件（内容裹在 #if 里）",
        "# 只有 buff 模式会用 mdk_trace_buff.c，只有 rtt 模式会用 mdk_trace_rtt.c",
        "MDK_TRACE_SRCS := $(MDK_TRACE_DIR)/mdk_trace.c \\",
        "                  $(MDK_TRACE_DIR)/mdk_trace_buff.c \\",
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
        "    · 两套插桩点宏是同一份代码，只改 MDK_TRACE_BACKEND_* 重编切后端。"
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
            "topic 可取：howto（总览与取舍）/ instrument_modes（**插桩的两种工作模式："
            "stream 持续录持续读 vs buff 全速录事后一次性读回，各自代价与选型**）/ "
            "instrument_points（**该往哪儿插桩：HardFault 等异常 handler 排第一，"
            "其次是看门狗喂狗点与任务切换点，以及哪些地方不该插**）/ "
            "lessons（**这几次在真板上撞出来的 7 个坑：运行态读 RAM 读回 0、"
            "halt 冻结与 paused_ms 偏高、stop 后首读脏帧、tick 当时间戳导致 dt=0、"
            "环形缓冲溢出与空洞、4bit 任务号只有 14 个、没插桩不等于没发生**）/ "
            "swd_limits（只用 SWD 两线能做到什么、做不到什么：变量 scope 与 DWT PC "
            "采样能做，指令级录制做不到）/ swd_wiring（接线）/ links（Keil 链路 vs "
            "OpenOCD 链路：观测类工具都带 link 参数）/ rtt_notes / itm_notes / "
            "when_unavailable（没数据时怎么排查）；留空返回全部。\n"
            "**没有 SWO 引脚并不等于不能 trace**：RTT 只要 SWD，采样剖析连缓冲都不要，MDK 原生 Event Recorder / Event Statistics 也只要 SWD（trace_eventrec 直接读它的缓冲），"
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
            "mdk_trace_config.h（后端选择 ITM/RTT/UART、ITM 端口、RTT 通道数与缓冲大小、"
            "CPU 主频、SWO 波特率、DBGMCU_CR 地址）与 mdk_trace.mk（Make 集成片段）。\n"
            "**为什么必须有目标侧组件**：SWO/RTT 只是通道，芯片不会自己往外说话——"
            "得有代码在关键点把事件写进 ITM/RTT 缓冲，主机才 trace 得到东西。"
            "安装完按返回的 next 步骤接进构建（CMake 用 add_subdirectory 或直接加源文件）。"
            "target_dir 指定部署目录（如工程里的 components/trace）。\n"
            "**backend 四选一**：itm / rtt / uart（stream：事件立刻出芯片，主机实时跟读）/ "
            "**buff（全速录：事件只写进 RAM 环形缓冲，事后用 trace_buff_dump 一次性读回，"
            "时间粒度可以开到每 CPU 周期）**。buff 的旋钮：buff_records（记录数 × 12B = "
            "静态 RAM）、buff_ts_shift（0 = 每周期，间隔可能超 51s 才需调大）、"
            "buff_clear_on_init（默认 false = 复位后保留上一次运行的记录，看门狗/fault "
            "复位时那是唯一证据）、fault_frame（异常 handler 里多存一份寄存器现场）。\n"
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
                               fault_frame: bool = True) -> str:
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
                                        fault_frame=bool(fault_frame)))
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

    return n
