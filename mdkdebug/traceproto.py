# -*- coding: utf-8 -*-
"""Trace 协议层：ITM/SWO 报文解码 + 自定义事件帧（MTF）。

两块内容：

**一、ITM 报文解码**（SWO 引脚那条线）
  SWO 上跑的是 ITM 的字节流。ITM 是**面向字节、自解析**的协议：每个报文的
  第一个字节就是它的头部，头部的低位决定后面跟几个数据字节。映射关系
  （按 ARMv7-M 架构手册 D1.2.1 与 itm_decode 0.6.1 的实现核对过）：

    0000_0000            Sync（同步包，主机用它对齐字节流）
    0111_0000            Overflow（ITM FIFO 溢出，**数据丢了**，必须报给用户）
    11rr_0000            LTS1 本地时间戳（rr = 与上一个时间戳的关系）
    0ttt_0000            LTS2 本地时间戳（ttt = 5 或 12 位扩展）
    1001_0100            GTS1 全局时间戳（低 26 位）
    1011_0100            GTS2 全局时间戳（高 22 位）
    0ppp_1000            Extension（扩展页号 ppp）
    aaaa_a0ss            Instrumentation 源包（port=a；ss→载荷 1/2/4 字节）
    aaaa_a1ss            Hardware source 包（disc=a；ss→载荷 1/2/4 字节）
    其它                 InvalidHeader（说明我们错位了，要重新找同步包）

  ss 编码：01→1 字节、10→2 字节、11→4 字节、00 保留（视为错位）。
  硬件源包按 disc 解释：0=事件计数器回绕、1=异常（进/出）、2=PC 采样、
  8..23=数据 trace。

**二、MTF 事件帧**（我们自己给插桩组件定的协议）
  光有 ITM 只能拿到「port N 上有一串字节」，主机根本不知道那是什么。
  所以目标侧的插桩组件按 MTF 打包，主机侧在这里解包成结构化事件：
    A5  (ver<<4|type)  len  payload[len]  crc8
  crc8 覆盖 magic 到 payload 末尾。**丢了 CRC 就没法区分「数据被 SWO 丢包截断」**
  和「本来就这样」，SWO 丢包是常态，所以这个字节不能省。
  帧长度字段是 1 字节，故单帧载荷上限 255 字节；超长文本由组件侧切帧。
"""

from __future__ import annotations

import struct

__all__ = [
    "MTF_MAGIC", "MTF_VERSION", "MTF_TYPES", "MTF_KINDS",
    "crc8", "mtf_frame", "MTFDecoder", "MTFError",
    "decode_itm", "decode_itm_stream", "summarize", "header_kind",
]

# ================================================================ ITM

SYNC = 0x00
OVERFLOW = 0x70
GTS1 = 0x94
GTS2 = 0xB4

_SS_SIZE = {0: 0, 1: 1, 2: 2, 3: 4}

HW_DISC = {
    0: "event_counter",
    1: "exception",
    2: "pc_sample",
}
# 8..23 是数据 trace
HW_DATA_RANGE = (8, 23)
# 数据 trace 的低 2 位含义
HW_DATA_PKT = {0: "pc_value", 1: "addr_offset", 2: "data_value", 3: "reserved"}


def header_kind(h: int) -> str:
    """判定一个字节在 ITM 里是什么（不消费后续数据）。"""
    h = int(h) & 0xFF
    if h == SYNC:
        return "sync"
    if h == OVERFLOW:
        return "overflow"
    if h == GTS1:
        return "gts1"
    if h == GTS2:
        return "gts2"
    if (h & 0x0F) == 0:
        return "lts1" if (h & 0xC0) == 0xC0 else "lts2"
    if (h & 0x8F) == 0x08:
        return "extension"
    ss = h & 0x03
    if ss == 0:
        return "invalid"
    return "hw" if (h & 0x04) else "instrumentation"


def decode_itm(data: bytes, ports=None) -> dict:
    """解码一段（连续的）ITM 字节流。

    返回 packets / consumed / leftover（尾部不完整的字节）。
    ports 给定时只保留这些 port 的 instrumentation 包（其它仍计数但不返回明细）。
    """
    buf = bytes(data or b"")
    packets = []
    i, n = 0, len(buf)
    overflow_count = 0
    while i < n:
        h = buf[i]
        kind = header_kind(h)
        if kind == "sync":
            packets.append({"kind": "sync", "offset": i, "header": "0x%02X" % h})
            i += 1
            continue
        if kind == "overflow":
            overflow_count += 1
            packets.append({"kind": "overflow", "offset": i, "header": "0x%02X" % h,
                            "note": "ITM FIFO 溢出：此处之后有报文丢失（SWO 带宽不足）"})
            i += 1
            continue
        if kind in ("lts1", "lts2", "gts1", "gts2", "extension", "invalid"):
            packets.append({"kind": kind, "offset": i, "header": "0x%02X" % h,
                            "payload": (h >> 4) & 0x7 if kind == "lts2" else None})
            i += 1
            continue
        # 需要载荷的包
        ss = h & 0x03
        size = _SS_SIZE.get(ss, 0)
        if size == 0 or i + 1 + size > n:
            # 数据不够：整个报文（含头部）留到下一批
            break
        payload = buf[i + 1:i + 1 + size]
        if kind == "instrumentation":
            port = h >> 3
            rec = {"kind": "instrumentation", "offset": i, "header": "0x%02X" % h,
                   "port": port, "size": size, "data": payload,
                   "value": int.from_bytes(payload, "little")}
            if ports is None or port in ports:
                packets.append(rec)
            else:
                packets.append({"kind": "instrumentation_filtered", "offset": i,
                                "port": port, "size": size})
        else:
            disc = h >> 3
            rec = {"kind": "hardware", "offset": i, "header": "0x%02X" % h,
                   "disc": disc, "size": size, "data": payload,
                   "value": int.from_bytes(payload, "little")}
            _explain_hw(rec)
            packets.append(rec)
        i += 1 + size
    return {"packets": packets, "consumed": i, "leftover": buf[i:],
            "overflow": overflow_count}


def _explain_hw(rec: dict) -> None:
    d = rec["disc"]
    if d in HW_DISC:
        rec["source"] = HW_DISC[d]
        if d == 0 and len(rec["data"]) >= 1:
            p = rec["data"][0]
            rec["event_counter"] = {
                "cyc": bool(p & 0x01), "fold": bool(p & 0x02), "lsu": bool(p & 0x04),
                "sleep": bool(p & 0x08), "exc": bool(p & 0x10), "cpi": (p >> 5) & 0x03,
            }
        elif d == 1 and len(rec["data"]) >= 2:
            p = rec["data"]
            rec["exception"] = {"function": (p[1] >> 4) & 0x03,
                                "number": ((p[1] & 0x01) << 8) | p[0],
                                "note": "function: 0=进入 1=返回 2=预留"}
        elif d == 2:
            if len(rec["data"]) == 1 and rec["data"][0] == 0:
                rec["pc"] = None
                rec["note"] = "PC 采样值为 0（睡眠中或 DWT 未开）"
            elif len(rec["data"]) == 4:
                rec["pc"] = int.from_bytes(rec["data"], "little")
    elif HW_DATA_RANGE[0] <= d <= HW_DATA_RANGE[1]:
        rec["source"] = "data_trace"
        rec["packet_type"] = HW_DATA_PKT.get(d & 0x03)
        rec["comparator"] = (d >> 2) & 0x0F
    else:
        rec["source"] = "unknown"


def decode_itm_stream(state: dict, chunk: bytes, ports=None) -> dict:
    """增量解码：state 里存 leftover，多次喂数据（SWO 是流式的，不能等全部到齐）。"""
    if state is None:
        state = {}
    buf = bytes(state.get("leftover") or b"") + bytes(chunk or b"")
    r = decode_itm(buf, ports=ports)
    state["leftover"] = r["leftover"]
    state["total_bytes"] = int(state.get("total_bytes") or 0) + len(chunk or b"")
    state["overflow"] = int(state.get("overflow") or 0) + r["overflow"]
    r["state"] = state
    return r


def summarize(packets) -> dict:
    """统计各类报文数量、涉及的 port/disc。"""
    by_kind, ports, discs = {}, {}, {}
    pcs = []
    for p in packets or []:
        k = p.get("kind")
        by_kind[k] = by_kind.get(k, 0) + 1
        if k == "instrumentation" or k == "instrumentation_filtered":
            pt = p.get("port")
            ports[pt] = ports.get(pt, 0) + 1
        elif k == "hardware":
            d = p.get("disc")
            discs[d] = discs.get(d, 0) + 1
            if p.get("pc"):
                pcs.append(p["pc"])
    return {"total": len(packets or []), "by_kind": by_kind,
            "ports": {str(k): v for k, v in sorted(ports.items())},
            "discs": {str(k): v for k, v in sorted(discs.items())},
            "pc_samples": len(pcs),
            "note": "by_kind 里 instrumentation=ITM 普通打印；hardware=硬件源包；"
                    "overflow>0 说明中间丢过数据，时间线不可全信"}


# ================================================================ MTF 事件帧

MTF_MAGIC = 0xA5
MTF_VERSION = 1

# type 编号 → 名字（与 components/trace 的 C 定义必须一致）
MTF_TYPES = {
    0: "raw",
    1: "text",
    2: "event",
    3: "counter",
    4: "isr",
    5: "mark",
    6: "ts",
    7: "kv",
    8: "reset",
}

# event/isr 的 kind
MTF_KINDS = {0: "enter", 1: "exit", 2: "point", 3: "abort"}

_PAYLOAD_FMT = {
    2: ("<HBII", ("id", "kind", "ts", "arg")),      # event
    3: ("<HI", ("id", "value")),                    # counter
    4: ("<HBI", ("id", "kind", "ts")),              # isr
    5: ("<I", ("tag",)),                            # mark
    6: ("<I", ("ts",)),                             # ts
    7: ("<Hi", ("key", "value")),                   # kv
}


class MTFError(Exception):
    pass


def crc8(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    """CRC-8/ATM 风格（poly=0x07，无反射，无 xorout）——与 C 侧实现一致。"""
    crc = init & 0xFF
    for b in bytes(data or b""):
        crc ^= b & 0xFF
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


def mtf_frame(ftype: int, payload: bytes) -> bytes:
    """按协议打一帧（主机侧测试与主机→目标下行共用）。"""
    if len(payload) > 255:
        raise MTFError("MTF 单帧载荷上限 255 字节，超长请分帧")
    body = bytes([MTF_MAGIC, ((MTF_VERSION & 0x0F) << 4) | (int(ftype) & 0x0F),
                  len(payload)]) + bytes(payload)
    return body + bytes([crc8(body)])


def _decode_payload(ftype: int, payload: bytes) -> dict:
    spec = _PAYLOAD_FMT.get(ftype)
    if not spec:
        if ftype == 1:
            return {"text": payload.decode("utf-8", "replace")}
        if ftype == 0:
            return {"data_hex": payload.hex()}
        if ftype == 8:
            return {"reason": payload.decode("utf-8", "replace")}
        return {"raw_hex": payload.hex()}
    fmt, names = spec
    need = struct.calcsize(fmt)
    if len(payload) < need:
        return {"malformed": "载荷长度不足（%d < %d）" % (len(payload), need)}
    vals = struct.unpack(fmt, payload[:need])
    out = dict(zip(names, vals))
    if "kind" in out:
        out["kind_name"] = MTF_KINDS.get(out["kind"])
    if "id" in out:
        out["id_hex"] = "0x%04X" % out["id"]
    return out


class MTFDecoder:
    """MTF 流式解码：喂任意切片，吐出完整帧，残帧留在缓冲区。"""

    def __init__(self, name: str = ""):
        self.buf = bytearray()
        self.name = name
        self.frames = 0
        self.crc_errors = 0
        self.dropped_bytes = 0
        self.bad_magic = 0
        self.last_error = None

    def feed(self, chunk: bytes) -> list:
        self.buf += bytes(chunk or b"")
        out = []
        while True:
            # 找 magic；magic 之前的字节都是丢包残渣，丢掉并计数
            try:
                idx = self.buf.index(MTF_MAGIC)
            except ValueError:
                self.dropped_bytes += len(self.buf)
                self.buf.clear()
                break
            if idx:
                self.dropped_bytes += idx
                del self.buf[:idx]
            if len(self.buf) < 4:
                break
            ver = (self.buf[1] >> 4) & 0x0F
            ftype = self.buf[1] & 0x0F
            ln = self.buf[2]
            total = 4 + ln
            if len(self.buf) < total:
                break
            body = bytes(self.buf[:total - 1])
            got = self.buf[total - 1]
            want = crc8(body)
            if ver != MTF_VERSION:
                self.bad_magic += 1
                self.last_error = "版本不匹配：帧声明 v%d，主机支持 v%d" % (ver, MTF_VERSION)
                del self.buf[:1]
                continue
            if got != want:
                self.crc_errors += 1
                self.last_error = ("CRC 不符（帧内 0x%02X vs 计算 0x%02X）："
                                   "多半是 SWO 丢包把帧切了" % (got, want))
                del self.buf[:1]
                continue
            payload = bytes(self.buf[3:3 + ln])
            rec = {"type": ftype, "type_name": MTF_TYPES.get(ftype, "unknown"),
                   "len": ln}
            rec.update(_decode_payload(ftype, payload))
            out.append(rec)
            self.frames += 1
            del self.buf[:total]
        return out

    def stats(self) -> dict:
        return {"frames": self.frames, "crc_errors": self.crc_errors,
                "bad_magic": self.bad_magic, "dropped_bytes": self.dropped_bytes,
                "pending_bytes": len(self.buf), "last_error": self.last_error,
                "name": self.name,
                "note": "dropped_bytes>0 说明流里有非 MTF 字节（通常是丢包残留）；"
                        "crc_errors>0 说明有帧被截断——两者都意味着事件可能不全"}
