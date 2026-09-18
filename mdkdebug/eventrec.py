# -*- coding: utf-8 -*-
"""CMSIS Event Recorder（MDK 原生通路）的目标侧缓冲读取与解码 —— 批次53。

为什么值得单独一个模块
----------------------
Event Recorder 是 MDK 原生、**纯 SWD 两线就能用**的事件记录通路：数据通路是
「调试器读目标 RAM」（不是 SWO 引脚），uVision 的 Event Recorder / Event
Statistics 窗口就是靠它工作的。但它的二进制格式不在任何公开手册里 —— 只写在
Keil ARM_Compiler pack 的 EventRecorder.c 源码里。

本模块的所有位域常量直接对齐那份源码（V1.5.1，核对于本地 pack
`Keil/ARM_Compiler/1.7.2/Source/EventRecorder.c`），不做任何推测：**猜错一位，
解出来的就是「看着像样但完全是别的东西」的事件流**。

目标侧结构（定长、定布局）
--------------------------
EventRecorderInfo（`const`，符号名 `EventRecorderInfo`，24 字节）::

    0  u8   protocol_type     1 = DAP
    1  u8   reserved
    2  u16  protocol_version  [15:8]=major [7:0]=minor
    4  u32  record_count      记录条数（2 的幂）
    8  u32  event_buffer      环形缓冲首地址
    12 u32  event_filter      事件过滤位图
    16 u32  event_status      状态块首地址
    20 u8   ts_source
    21 u8[3] reserved

EventStatus（36 字节，`event_status` 指向）::

    0  u8   state             0=停 / 1=记录中
    1  u8   context
    2  u16  info_crc          EventRecorderInfo 的 CRC16-CCITT
    4  u32  record_index      **单调递增**，槽位 = index & (count-1)
    8  u32  records_written
    12 u32  records_dumped
    16 u32  ts_overflow
    20 u32  ts_freq           Hz
    24 u32  ts_last
    28 u32  init_count
    32 u32  signature         = 0xE1A5276B

EventRecord（16 字节 × record_count，环形）::

    0 u32 ts | 4 u32 val1 | 8 u32 val2 | 12 u32 info

info 位域（EventRecorder.c 的定义）::

    [ 7.. 0] message number      [15.. 8] component number
    [18..16] data length / context        [19] IRQ flag
    [23..20] sequence number     [24] first record   [25] last record
    [26] locked                  [27] valid record
    [28] timestamp MSB           [29] val1 MSB       [30] val2 MSB
    [31] toggle bit

键名约定
--------
`slot` 一律指**记录在环形缓冲里的槽位号**（decode_buffer 填）；
component=0xEF 反推出的 EventStartX(slot) 统计槽位另给 **`stat_slot`**。
两者含义不同，不共用键名（曾共用过一次，后果是聚合把同一次 Start/Stop
认成两个槽位、items 恒为空）。状态块结构放在 **`event_status`** 下 ——
统一信封一定会写 `out["status"]`（"ok"/"error"），撞名会被覆盖成字符串。

三条必须尊重的口径（不糊弄用户）
--------------------------------
1. **ts / val1 / val2 的 bit31 在记录里不是数据**：写入时它被换成 toggle bit
   （`record->ts = (ts & ~TBIT) | tbit`），真值的高位挪到 info 的 MSB 位上。
   解码必须重建，否则凡是超过 2^31 的值全错。
2. **level 没有随记录存下来**：`EventRecord2/4/Data` 在写入前做了
   `id &= EVENT_RECORD_ID_MASK`（0xFFFF），而 level 编码在 id 的 bit[17:16]
   （见 EventID(level, comp_no, msg_no)）。所以从缓冲里**读不到 level**；
   只有 component=0xEF（EvtStatistics_No）那组 Start/Stop 事件能按 message 的
   bit[7:6] 反推组别（A/B/C/D ↔ Error/API/Op/Detail）。返回值里如实标注这一点。
3. **一致性判据是 toggle 对齐**：写记录的顺序是 ts→val1→val2→info（解锁时同时
   翻 toggle），只有「三条的 bit31 与 info 的 bit31 全一致」才说明这是一条完整
   记录。不一致、仍处于 locked 状态的按「写一半」处理：跳过并计数，**绝不把半条
   记录当数据**。
"""

from __future__ import annotations

import os
import struct

from . import linkio as _link
from . import trace as _trace

# ----------------------------------------------------------------------
# 常量：全部对齐 EventRecorder.c（V1.5.1）
# ----------------------------------------------------------------------
SIGNATURE = 0xE1A5276B

INFO_ID_MASK = 0x0000FFFF
INFO_DLEN_MASK = 0x00070000     # 同一字段：[18..16] 数据长度 / 事件上下文
INFO_IRQ = 0x00080000
INFO_SEQ_MASK = 0x00F00000
INFO_SEQ_POS = 20
INFO_FIRST = 0x01000000
INFO_LAST = 0x02000000
INFO_LOCKED = 0x04000000
INFO_VALID = 0x08000000
INFO_MSB_TS = 0x10000000
INFO_MSB_VAL1 = 0x20000000
INFO_MSB_VAL2 = 0x40000000
INFO_TBIT = 0x80000000

INFO_SIZE = 24
STATUS_SIZE = 36
RECORD_SIZE = 16

STAT_COMPONENT = 0xEF            # EvtStatistics_No
LEVEL_NAMES = {0: "error", 1: "api", 2: "op", 3: "detail"}
GROUP_LETTERS = {0: "A", 1: "B", 2: "C", 3: "D"}
SLOT_KINDS = {0: "start", 1: "start_v", 2: "stop", 3: "stop_v"}

TS_SOURCE_NAMES = {
    0: "DWT CYCCNT", 1: "SysTick", 2: "CMSIS-RTOS2 System Timer",
    3: "User Timer (Normal Reset)", 4: "User Timer (Power-On Reset)",
}

MAX_READ_RECORDS = 8192         # 单次最多读多少条记录（16B/条 → 128KB 上限）


# ----------------------------------------------------------------------
# 纯解码（不碰目标，可离线测）
# ----------------------------------------------------------------------
def parse_info(info: int) -> dict:
    """拆 info 字。"""
    eid = info & INFO_ID_MASK
    return {
        "id": eid,
        "id_hex": "0x%04X" % eid,
        "component": (eid >> 8) & 0xFF,
        "message": eid & 0xFF,
        "seq": (info & INFO_SEQ_MASK) >> INFO_SEQ_POS,
        "dlen_ctx": (info & INFO_DLEN_MASK) >> 16,
        "irq": bool(info & INFO_IRQ),
        "first": bool(info & INFO_FIRST),
        "last": bool(info & INFO_LAST),
        "locked": bool(info & INFO_LOCKED),
        "valid": bool(info & INFO_VALID),
        "toggle": 1 if (info & INFO_TBIT) else 0,
    }


def decode_slot_meta(component: int, message: int) -> dict:
    """component=0xEF 那组（EventStartX/EventStopX 用的槽位事件）能反推组别/类型/槽位。

    其他 component 一律**不给 level**（记录里根本没存，见模块 docstring 第 2 条），
    宁可少给也不猜。
    """
    if component != STAT_COMPONENT:
        return {}
    grp = (message >> 6) & 0x3
    kind = (message >> 4) & 0x3
    return {
        "group": GROUP_LETTERS[grp],
        "level": LEVEL_NAMES[grp],
        "kind": SLOT_KINDS[kind],
        # 注意：这是 EventStartX(slot) 的统计槽位，与「记录在环形缓冲里的
        # 槽位号」（decode_buffer 填的 slot）是两回事，绝不共用键名 ——
        # 一旦共用，聚合会把同一次 Start/Stop 认成两个槽位、聚不出区间。
        "stat_slot": message & 0xF,
    }


def decode_record(raw: bytes) -> dict:
    """16 字节记录 → 结构化。失败时 ok=False 并给 reason。"""
    if len(raw) < RECORD_SIZE:
        return {"ok": False, "reason": "记录长度不足 16 字节"}
    ts_r, v1_r, v2_r, info = struct.unpack("<IIII", raw[:RECORD_SIZE])
    if not (info & INFO_VALID):
        return {"ok": False, "reason": "空槽（VALID=0）", "info_hex": "0x%08X" % info}
    tbit = 1 if (info & INFO_TBIT) else 0
    consistent = ((ts_r >> 31) == tbit and (v1_r >> 31) == tbit
                  and (v2_r >> 31) == tbit)
    rec = parse_info(info)
    rec.update({
        "ok": True,
        "ts_raw": ts_r,
        # bit31 是 toggle，真值高位在 info 的 MSB 位上 —— 必须重建
        "ts": (ts_r & 0x7FFFFFFF) | ((info & INFO_MSB_TS) << 3),
        "val1": (v1_r & 0x7FFFFFFF) | ((info & INFO_MSB_VAL1) << 2),
        "val2": (v2_r & 0x7FFFFFFF) | ((info & INFO_MSB_VAL2) << 1),
        "consistent": consistent,
        "info_hex": "0x%08X" % info,
    })
    rec.update(decode_slot_meta(rec["component"], rec["message"]))
    return rec


def parse_info_struct(raw: bytes) -> dict:
    """24 字节 EventRecorderInfo → 结构化。"""
    if not raw or len(raw) < INFO_SIZE:
        return {"ok": False, "error": "EventRecorderInfo 只读到 %d 字节（要 %d）"
                                      % (len(raw or b""), INFO_SIZE)}
    (ptype, _rsvd, pver, count, buf, filt, st, tss,
     _rsvd3) = struct.unpack("<BBHIIIIB3s", raw[:INFO_SIZE])
    major, minor = (pver >> 8) & 0xFF, pver & 0xFF
    return {
        "ok": True,
        "protocol_type": ptype,
        "protocol_type_name": {1: "DAP"}.get(ptype, "unknown(%d)" % ptype),
        "protocol_version": "%d.%d" % (major, minor),
        "protocol_version_raw": "0x%04X" % pver,
        "record_count": int(count),
        "event_buffer": int(buf),
        "event_filter": int(filt),
        "event_status": int(st),
        "ts_source": int(tss),
        "ts_source_name": TS_SOURCE_NAMES.get(int(tss), "unknown(%d)" % int(tss)),
    }


def parse_status(raw: bytes) -> dict:
    """36 字节 EventStatus → 结构化。"""
    if not raw or len(raw) < STATUS_SIZE:
        return {"ok": False, "error": "EventStatus 只读到 %d 字节（要 %d）"
                                      % (len(raw or b""), STATUS_SIZE)}
    (state, ctx, crc, idx, written, dumped, ts_ovf, ts_freq,
     ts_last, init_cnt, sig) = struct.unpack("<BBH8I", raw[:STATUS_SIZE])
    return {
        "ok": True,
        "state": int(state),
        "state_name": {0: "stopped", 1: "recording"}.get(int(state), "unknown(%d)" % int(state)),
        "context": int(ctx),
        "info_crc": "0x%04X" % int(crc),
        "record_index": int(idx),
        "records_written": int(written),
        "records_dumped": int(dumped),
        "ts_overflow": int(ts_ovf),
        "ts_freq": int(ts_freq),
        "ts_last": int(ts_last),
        "init_count": int(init_cnt),
        "signature": "0x%08X" % int(sig),
        "signature_ok": int(sig) == SIGNATURE,
    }


def window_slots(record_index: int, count: int, limit: int = 0,
                 written=None) -> list:
    """最近 N 条记录的槽位号（旧 → 新）。record_index 是「下一个待写」的单调索引。

    written 的语义要分清：**明确的整数**表示已经写过多少条（0 = 确实还没写过 →
    空）；None 表示读不到 EventStatus、不知道写了多少 —— 这时按整圈扫（宁可多扫
    一遍空槽，也不因为读不到状态就谎报「没有记录」）。
    """
    count = int(count or 0)
    if count <= 0:
        return []
    n = count
    if written is not None:
        n = min(n, max(0, int(written)))
    if limit and int(limit) > 0:
        n = min(n, int(limit))
    n = min(n, MAX_READ_RECORDS)
    if n <= 0:
        return []
    latest = int(record_index or 0) - 1
    return [i & (count - 1) for i in range(latest - n + 1, latest + 1)]


def decode_buffer(buf: bytes, count: int, record_index: int,
                  written=None, limit: int = 0, slots=None) -> dict:
    """按环形顺序解码最近 N 条。

    buf 的排布有两种来源，必须分清（这里错过一次，事件会整体错位）：
      · slots=None：buf 是**从槽位 0 开始**的连续缓冲（count*16 字节），
        自己按 window_slots 算窗口、用槽位号索引；
      · slots=[...]：buf 是**按这个槽位序列逐槽拼起来**的（每槽 16 字节）。
        read() 分段读回环缓冲时走这条 —— 跨回绕的段不从槽位 0 开始，
        拿槽位号直接当索引必然错位。
    """
    if slots is None:
        slots = window_slots(record_index, count, limit, written)
    events, skipped = [], {"empty": 0, "partial": 0}
    for i, s in enumerate(slots):
        r = decode_record(buf[i * RECORD_SIZE:(i + 1) * RECORD_SIZE])
        if not r.get("ok"):
            skipped["empty"] += 1
            continue
        if r.get("locked") or not r.get("consistent"):
            # 写一半 / 正在写：跳过，不当数据
            skipped["partial"] += 1
            continue
        r["slot"] = s        # 环形缓冲槽位号（统计槽位另见 stat_slot）
        events.append(r)
    return {"ok": True, "events": events, "slots_scanned": len(slots),
            "skipped": skipped}


def aggregate(events: list, ts_freq: int = 0) -> dict:
    """Event Statistics 口径的聚合：component 0xEF 的 Start/Stop 成对事件。

    只统计**成对**的（Start 后遇到同组同槽位的 Stop）；落单的 Start 与没有
    Start 的 Stop 分别计数报出来，不硬凑成一次耗时。
    """
    opened, items, unpaired = {}, {}, 0
    for e in events or []:
        if e.get("component") != STAT_COMPONENT or "kind" not in e:
            continue
        key = (e.get("group"), e.get("stat_slot"))
        it = items.setdefault(key, {"group": e.get("group"), "level": e.get("level"),
                                    "stat_slot": e.get("stat_slot"), "count": 0,
                                    "total_ticks": 0, "min_ticks": None,
                                    "max_ticks": None})
        if str(e.get("kind")).startswith("start"):
            opened[key] = e.get("ts")
            continue
        t0 = opened.pop(key, None)
        if t0 is None:
            unpaired += 1
            continue
        dt = int(e.get("ts") or 0) - int(t0)
        if dt < 0:                      # 32 位时间戳回绕
            dt += 1 << 32
        it["count"] += 1
        it["total_ticks"] += dt
        it["min_ticks"] = dt if it["min_ticks"] is None else min(it["min_ticks"], dt)
        it["max_ticks"] = dt if it["max_ticks"] is None else max(it["max_ticks"], dt)

    out = []
    for it in items.values():
        if not it["count"]:
            continue
        rec = dict(it)
        if ts_freq:
            f = float(ts_freq)
            rec["total_ms"] = round(it["total_ticks"] * 1000.0 / f, 3)
            rec["min_ms"] = round(it["min_ticks"] * 1000.0 / f, 4)
            rec["max_ms"] = round(it["max_ticks"] * 1000.0 / f, 4)
            rec["avg_ms"] = round(it["total_ticks"] * 1000.0 / f / it["count"], 4)
        out.append(rec)
    out.sort(key=lambda r: -(r.get("total_ticks") or 0))
    return {"ok": True, "items": out, "unpaired_stops": unpaired,
            "open_starts": len(opened), "ts_freq": int(ts_freq or 0)}


# ----------------------------------------------------------------------
# 读目标（链路无关：Keil / OpenOCD 谁活着用谁）
# ----------------------------------------------------------------------
def _read(addr: int, n: int, link: str = "auto"):
    lk, err = _link.pick(link, who="读 Event Recorder 缓冲")
    if lk is None:
        return None, err
    return lk.read(int(addr), int(n))


def locate(elf: str = "", info_addr: int = 0) -> dict:
    """定位 EventRecorderInfo：显式地址优先，其次 ELF 符号。"""
    if info_addr:
        return {"ok": True, "addr": int(info_addr), "method": "explicit"}
    if not elf:
        return {"ok": False, "error_code": "invalid-argument",
                "error": "既没给 info_addr 也没给 elf，无法定位 EventRecorderInfo",
                "next_actions": [
                    "用 set_symbol_file 指向正在调试的 .axf（里面有 EventRecorderInfo 符号），"
                    "或直接给 info_addr",
                    "不确定目标链没链 Event Recorder：先 list_tools(keyword=\"symbol\") / "
                    "find_symbol 找符号 EventRecorderInfo",
                ]}
    if not os.path.isfile(elf):
        return {"ok": False, "error_code": "project-not-found",
                "error": "elf 路径不存在：%s" % elf}
    a = _trace.elf_symbol_addr(elf, ["EventRecorderInfo", "_EventRecorderInfo"])
    if a:
        return {"ok": True, "addr": a, "method": "elf_symbol",
                "elf": os.path.abspath(elf)}
    return {"ok": False, "error_code": "eventrec-symbol-missing",
            "elf": os.path.abspath(elf),
            "error": "在 %s 里没找到符号 EventRecorderInfo" % os.path.basename(elf),
            "note": "两种可能：① 目标固件没链 Event Recorder 组件（那就没有数据可读）；"
                    "② 符号被 --gc-sections 回收了（工程里给它加 __USED / 在 SCVD 或 "
                    "EventRecorder 配置里保留）",
            "next_actions": [
                "确认目标工程真的用了 Event Recorder（EventRecorderInitialize + EventRecordXxx）",
                "符号被回收的话：给 info_addr 直接指地址，或在工程里保留该符号",
                "只想看热点/函数进入退出（不需要插桩）：用 trace_pcsample / trace_record",
            ]}


def status(elf: str = "", info_addr: int = 0, link: str = "auto") -> dict:
    """读 EventRecorderInfo + EventStatus，给人一份「录制器现在什么状态」。"""
    loc = locate(elf=elf, info_addr=info_addr)
    if not loc.get("ok"):
        return loc
    a = loc["addr"]
    raw, meta = _read(a, INFO_SIZE, link)
    if raw is None:
        return {"ok": False, "addr": "0x%X" % a, "method": loc["method"],
                "error": meta.get("error"), "link": (meta or {}).get("link"),
                "hint": "读不到 EventRecorderInfo：地址对不对？目标在不在？"}
    info = parse_info_struct(raw)
    if not info.get("ok"):
        info["addr"] = "0x%X" % a
        return info
    out = {"ok": True, "addr": "0x%X" % a, "method": loc["method"],
           "info": info, "link": (meta or {}).get("link"),
           "info_raw_hex": raw[:INFO_SIZE].hex()}
    if loc["method"] == "elf_symbol":
        out["elf"] = loc["elf"]

    warnings = []
    if info["protocol_type"] != 1:
        warnings.append("protocol_type=%d 不是 1(DAP) —— 这个地址上的内容不像 "
                        "EventRecorderInfo" % info["protocol_type"])
    if not (info["record_count"] and (info["record_count"] & (info["record_count"] - 1)) == 0):
        warnings.append("record_count=%d 不是 2 的幂 —— 结构布局可能对不上"
                        % info["record_count"])

    if info.get("event_status"):
        raw2, meta2 = _read(info["event_status"], STATUS_SIZE, link)
        if raw2 is None:
            warnings.append("EventStatus 读不到（%s）" % (meta2 or {}).get("error"))
        else:
            st = parse_status(raw2)
            # 键名用 event_status 而不是 status：统一信封一定会写 out["status"]
            # （"ok"/"error"），撞名会把这份状态结构覆盖成字符串。
            out["event_status"] = st
            out["status_raw_hex"] = raw2[:STATUS_SIZE].hex()
            if st.get("ok") and not st.get("signature_ok"):
                warnings.append("EventStatus.signature=%s 与 0xE1A5276B 不符 —— "
                                "Event Recorder 可能还没被 EventRecorderInitialize 初始化过，"
                                "下面的统计不可信" % st.get("signature"))
    if warnings:
        out["warning"] = "；".join(warnings)
    return out


def read(elf: str = "", info_addr: int = 0, limit: int = 100,
         link: str = "auto") -> dict:
    """读最近 limit 条记录并解码（旧 → 新）。"""
    st = status(elf=elf, info_addr=info_addr, link=link)
    if not st.get("ok"):
        return st
    info, stat = st.get("info") or {}, st.get("event_status") or {}
    count = int(info.get("record_count") or 0)
    buf = int(info.get("event_buffer") or 0)
    limit = int(limit or 0)
    if count <= 0 or buf == 0:
        return {"ok": False, "error": "EventRecorderInfo 里 record_count/event_buffer 不合理",
                "info": info}
    if limit > MAX_READ_RECORDS:
        limit = MAX_READ_RECORDS

    slots = window_slots(stat.get("record_index") or 0, count, limit,
                         stat.get("records_written"))
    if not slots:
        return {"ok": True, "events": [], "count": 0,
                "note": "环形缓冲里还没有记录（records_written=%s）"
                        % stat.get("records_written"), "info": info,
                "event_status": stat}

    # 环形窗口最多分成两段（跨回绕），分段读，避免整块拉 1MB
    segs, s0, prev = [], slots[0], slots[0]
    for s in slots[1:]:
        if s == prev + 1:
            prev = s
            continue
        segs.append((s0, prev))
        s0 = prev = s
    segs.append((s0, prev))

    blob = b""
    for (lo, hi) in segs:
        n = (hi - lo + 1) * RECORD_SIZE
        raw, meta = _read(buf + lo * RECORD_SIZE, n, link)
        if raw is None:
            return {"ok": False, "error": meta.get("error"), "at": "0x%X" % (buf + lo * RECORD_SIZE),
                    "link": (meta or {}).get("link")}
        if len(raw) < n:
            return {"ok": False,
                    "error": "只读到 %d/%d 字节（0x%X 起）" % (len(raw), n, buf + lo * RECORD_SIZE)}
        blob += raw

    # blob 是**按 slots 顺序拼的**，所以把 slots 显式传进去，别让它拿槽位号当索引
    dec = decode_buffer(blob, count, stat.get("record_index") or 0,
                        stat.get("records_written"), limit, slots=slots)
    out = {
        "ok": True,
        "info": info,
        "event_status": stat,
        "record_buffer": "0x%X" % buf,
        "segments": [{"from": "0x%X" % (buf + lo * RECORD_SIZE),
                      "records": hi - lo + 1} for (lo, hi) in segs],
        "events": dec["events"],
        "count": len(dec["events"]),
        "slots_scanned": dec["slots_scanned"],
        "skipped": dec["skipped"],
        "note": ("ts 是目标侧时间戳（%s，%s Hz），不是主机时间；"
                 "gap 要自己按相邻 ts 差值算。level 不随记录存储（写入前 id 被 "
                 "&0xFFFF），只有 component=0xEF 那组能按 message 反推组别/槽位。"
                 % (info.get("ts_source_name"), stat.get("ts_freq")))
    }
    return out


def stats(elf: str = "", info_addr: int = 0, limit: int = 0,
          link: str = "auto") -> dict:
    """读缓冲并做 Event Statistics 口径的聚合（Start/Stop 成对耗时）。"""
    limit = int(limit or 0) or MAX_READ_RECORDS
    r = read(elf=elf, info_addr=info_addr, limit=limit, link=link)
    if not r.get("ok"):
        return r
    freq = int((r.get("event_status") or {}).get("ts_freq") or 0)
    agg = aggregate(r.get("events") or [], ts_freq=freq)
    if not agg.get("items"):
        agg["note"] = ("缓冲里没有 component=0xEF 的 Start/Stop 成对事件 —— "
                       "Event Statistics 只统计用 EventStartX(slot)/EventStopX(slot) "
                       "夹出来的区间")
    return {"ok": True, "stats": agg, "count": r.get("count"),
            "skipped": r.get("skipped"), "event_status": r.get("event_status"),
            "info": r.get("info"),
            "note": "耗时由相邻的 Start/Stop 时间戳差值算出（%d Hz），"
                    "只统计成对的；落单的在 unpaired_stops/open_starts 里如实报出" % freq}


def encode_record(ts: int, val1: int, val2: int, component: int, message: int,
                  seq: int = 0, irq: bool = False, first: bool = True,
                  last: bool = True, valid: bool = True, locked: bool = False,
                  dlen: int = 0, tbit: int = 0) -> bytes:
    """构造一条 Event Record（16 字节）。

    给 mock 测试、以及「手工在 RAM 里造一段缓冲来验证解码链路」用；真实数据由
    目标侧的 EventRecorder.c 产生。位域拼法与 EventRecordItem 一一对应 —— 包括
    把 ts/val1/val2 的 bit31 换成 toggle bit、把真值高位放进 info。
    """
    eid = ((int(component) & 0xFF) << 8) | (int(message) & 0xFF)
    info = eid | ((int(seq) & 0xF) << INFO_SEQ_POS) | ((int(dlen) & 0x7) << 16)
    if irq:
        info |= INFO_IRQ
    if first:
        info |= INFO_FIRST
    if last:
        info |= INFO_LAST
    if valid:
        info |= INFO_VALID
    if locked:
        info |= INFO_LOCKED
    ts, val1, val2 = int(ts), int(val1), int(val2)
    if ts & 0x80000000:
        info |= INFO_MSB_TS
    if val1 & 0x80000000:
        info |= INFO_MSB_VAL1
    if val2 & 0x80000000:
        info |= INFO_MSB_VAL2
    tb = 0x80000000 if tbit else 0
    info |= tb
    return struct.pack("<IIII", (ts & 0x7FFFFFFF) | tb,
                       (val1 & 0x7FFFFFFF) | tb,
                       (val2 & 0x7FFFFFFF) | tb, info)


def encode_info(record_count: int, event_buffer: int, event_filter: int = 0,
                event_status: int = 0, ts_source: int = 0,
                protocol_type: int = 1, protocol_version: int = 0x0101) -> bytes:
    """构造 24 字节 EventRecorderInfo（真机造缓冲 / mock 用）。"""
    return struct.pack("<BBHIIIIB3s", int(protocol_type), 0, int(protocol_version),
                       int(record_count), int(event_buffer), int(event_filter),
                       int(event_status), int(ts_source), b"\x00\x00\x00")


def encode_status(record_index: int, records_written: int, ts_freq: int,
                  records_dumped: int = 0, ts_overflow: int = 0, ts_last: int = 0,
                  state: int = 1, init_count: int = 1,
                  signature: int = SIGNATURE, info_crc: int = 0) -> bytes:
    """构造 36 字节 EventStatus（真机造缓冲 / mock 用）。"""
    return struct.pack("<BBH8I", int(state), 0, int(info_crc), int(record_index),
                       int(records_written), int(records_dumped), int(ts_overflow),
                       int(ts_freq), int(ts_last), int(init_count), int(signature))
