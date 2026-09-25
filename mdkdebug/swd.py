# -*- coding: utf-8 -*-
"""SWD 无缝流 trace 的编解码（主机侧）。

与目标侧 components/trace/mdk_trace_swd.c 逐字节一致；改任何一边都要跑
tools/swd_compare.py 做跨实现比对。

协议速查
--------
token 首字节高 2 位是 tag：

    00 HIT  [00|slot(6b)]                            varint(dt)   字典命中
    01 LIT  [01|000000] type kind id(2B,LE) varint(arg) varint(dt)  字面量，写字典
    10 CTL  [10|subcmd(6b)]                          <参数>
    11 保留

字典键是 (type, kind, id, arg) 四元组，64 槽直接映射哈希。HIT 只发槽号，
所以主机必须靠自己的字典还原 —— 一旦某个 LIT 被背压丢掉，主机的字典就
不再可信，目标会写一条 CTL_LOST 让双方清空重来。这是刻意的：解出一个
**错误的 key** 比少解一条事件糟糕得多。

丢失的权威计数在控制块的 lost_events；流内的 CTL_LOST 只是尽力而为的断点
标记（环满时连它自己也写不进去）。
"""

NSLOT = 64
SLOT_MASK = NSLOT - 1

TAG_HIT = 0
TAG_LIT = 1
TAG_CTL = 2
# 3 号 tag 一直空着，现在用来做「不带 dt」的命中：1 字节一条。
# 目标侧在量化后的 dt == 0 时自动用它，所以**粒度调粗本身就省字节**，
# 不需要额外开关；解码端必须读成 dt = 0（= 与上一条同一时刻），
# 而不是「时间未知」。
TAG_HITN = 3

CTL_SYNC = 0
CTL_LOST = 1

MAGIC = b"MDKSWD1\x00"
VERSION = 2
# v1 没有 HITN / dt_unit / TS_OFF，但 v2 主机解 v1 流是安全的
# （v1 目标永远不会发出 v2 才有的东西）。反过来才危险，所以这里只在
# 目标版本高于本工具时才拒绝。
SUPPORTED_VERSIONS = (1, 2)
CTRL_BYTES = 80
SYMBOL = "mdk_trace_swd_blob"

U32 = 0xFFFFFFFF

# 控制块字段偏移（见 mdk_trace_swd.h 的 mdk_trace_swd_ctrl_t）
OFF_VERSION = 8
OFF_CTRL_BYTES = 10
OFF_CAP = 12
OFF_RING_OFF = 16
OFF_HEAD = 20
OFF_DRAINED = 24
OFF_LOST_EVENTS = 28
OFF_LOST_BYTES = 32
OFF_EVENTS = 36
OFF_TOKENS = 40
OFF_SEQ = 44
OFF_TS_SHIFT = 48
OFF_CPU_HZ = 52
OFF_CYCLES = 56
OFF_FLAGS = 60
OFF_RESET_REQ = 64      # 宿主请求目标「开一段新录制」的握手字
OFF_DT_UNIT = 68        # 宿主写：dt = cycles / dt_unit；0 表示 1（最小粒度）

FLAG_ENABLED = 1 << 0
FLAG_TS_OFF = 1 << 2    # 宿主写：完全不记时间戳，只记事件顺序

# 事件类型 / kind，与 mdk_trace.h 保持同一套编号
TYPES = {0: "raw", 1: "text", 2: "event", 3: "counter", 4: "isr", 5: "mark",
         6: "ts", 7: "kv", 8: "reset", 9: "fault", 10: "sched",
         # 11/12 是批次72 加的语义事件：sync 把原语等待/唤醒/所有权做成一等事件、
         # heap 让分配/释放可统计。压缩流只有 2 bit 的 kind，所以这两个类型
         # **不复用 kind**，语义打包在 id 里（sync: id=(obj<<3)|op、heap: id=op），
         # val/size 走 arg 全 32 位。类型号必须 < 16 —— make_key 里是 type & 0xF，
         # 超过 15 会被静默取模成另一个类型（那就是看似权威的错答案）。
         11: "sync", 12: "heap"}
KINDS = {0: "enter", 1: "exit", 2: "point", 3: "abort"}
FAULT_CLASS = {0: "hardfault", 1: "memmanage", 2: "busfault", 3: "usagefault"}
FAULT_BASE = 0xFE00
FAULT_REGS = {0xFF01: "pc", 0xFF02: "lr", 0xFF03: "sp", 0xFF04: "hfsr",
              0xFF05: "mmfar", 0xFF06: "bfar", 0xFF07: "xpsr", 0xFF08: "cfsr"}

_M1 = 0x9E3779B1
_M2 = 0x85EBCA6B
_M3 = 0xC2B2AE35


def make_key(type_, kind, id_, arg):
    return (type_ & 0xF, kind & 0x3, id_ & 0xFFFF, arg & U32)


def slot_of(key):
    t, k, i, a = key
    x = (t * _M1 + k * _M2 + i * _M3 + a) & U32
    x ^= x >> 13
    x ^= x >> 23
    return x & SLOT_MASK


def put_varint(out, v):
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def get_varint(buf, pos):
    v = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise IndexError("varint 截断")
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, pos
        shift += 7


# ------------------------------------------------------------- 时间粒度

def _is_pow2(n):
    return n > 0 and (n & (n - 1)) == 0

def resolve_granularity(spec, cpu_hz):
    """把「时间粒度」翻译成控制块里要写的三个值。

    返回 (ts_shift, dt_unit, ts_off, note)。ts_shift 与 dt_unit 里总有一个
    为 0；两者都为 0 就是最细粒度（1 个 dt 单位 = 1 个 CPU 周期）。
    ts_off=True 表示完全不记时间戳。note 里头如实写明实际走了哪条路径，
    让工具能原样回报，不让人猜。

    spec 接受：
      None                 不改动（三项都返回 None）
      "cycle"              最小粒度
      "none"               不记时间戳
      "500us" / "1ms" / "84ns"   每个 dt 单位对应这么多时间
      数字                 按微秒算（<=0 视为 cycle）
    """
    if spec is None:
        return (None, None, None, "不改动目标的粒度设置")
    if isinstance(spec, str):
        s = spec.strip().lower()
        if s in ("cycle", "cycles", "min", "raw"):
            return (0, 0, False, "最小粒度：1 个 dt 单位 = 1 个 CPU 周期")
        if s in ("none", "off", "notime", "none_ts"):
            return (0, 0, True, "不记时间戳：只保留事件顺序，"
                                "主机端必须按“无时间轴”呈现（不能画成等距就等于有时间）")
        seconds = None
        for suf, mul in (("ns", 1e-9), ("us", 1e-6), ("\u00b5s", 1e-6), ("ms", 1e-3), ("s", 1.0)):
            if s.endswith(suf):
                try:
                    seconds = float(s[:-len(suf)]) * mul
                except ValueError:
                    seconds = None
                break
        if seconds is None:
            raise ValueError("粒度写法不认识：%r（可用 cycle / none / 500us / 1ms / 2.5us）"
                             % (spec,))
    elif isinstance(spec, (int, float)):
        seconds = float(spec) * 1e-6
    else:
        raise ValueError("粒度参数类型不认识：%r" % (spec,))

    if not cpu_hz:
        raise ValueError("要按时间换算粒度就必须知道 cpu_hz，但控制块里 cpu_hz=0"
                         "（固件没填 MDK_TRACE_SWD_CPU_HZ）。改用 cycle / none，"
                         "或让固件把主频写上。")
    unit = int(round(seconds * cpu_hz))
    if unit <= 1:
        return (0, 0, False, "请求的粒度比一个 CPU 周期还细，按最小粒度处理")
    if _is_pow2(unit):
        return (unit.bit_length() - 1, 0, False,
                "每 %d 个周期一个单位（2 的幂，走移位，最便宜）" % unit)
    return (0, unit, False,
            "每 %d 个周期一个单位（不是 2 的幂，走整数除法；"
            "内核 tick 正是这种情况，凑成 2 的幂就是错答案）" % unit)


class Encoder:
    """目标侧编码器的模型。主机不编码，这里是为了自测与跨实现比对。"""

    def __init__(self):
        self.slot = [None] * NSLOT
        self.stats = {"events": 0, "bytes": 0, "hit": 0, "hitn": 0,
                      "lit": 0}

    def reset_dict(self):
        self.slot = [None] * NSLOT

    def encode(self, events):
        out = bytearray()
        for key, dt in events:
            h = slot_of(key)
            # hit 必须在写字典**之前**算好：写完之后那句条件会重新求值，
            # 于是新见的 key 恰好 dt==0 时会少写 dt，而 LIT 的 dt 是必带的。
            hit = self.slot[h] == key
            if hit and dt == 0:
                out.append((TAG_HITN << 6) | h)
                self.stats["hitn"] += 1
            elif hit:
                out.append((TAG_HIT << 6) | h)
                self.stats["hit"] += 1
            else:
                self.slot[h] = key
                t, k, i, a = key
                out.append(TAG_LIT << 6)
                out.append(t)
                out.append(k)
                out.append(i & 0xFF)
                out.append((i >> 8) & 0xFF)
                put_varint(out, a)
                self.stats["lit"] += 1
            if not (hit and dt == 0):
                put_varint(out, dt)
        self.stats["events"] += len(events)
        self.stats["bytes"] += len(out)
        return bytes(out)

    def sync(self, seq):
        out = bytearray([(TAG_CTL << 6) | CTL_SYNC])
        put_varint(out, seq)
        return bytes(out)

    def lost(self, n):
        out = bytearray([(TAG_CTL << 6) | CTL_LOST])
        put_varint(out, n)
        return bytes(out)


class StreamDesync(Exception):
    """流从中间开始（或字典不同步）：解出来的 key 不可信。"""


class Decoder:
    """有状态解码器：可任意分片喂入，跨分片保持字典与半截 token。"""

    def __init__(self):
        self.slot = [None] * NSLOT
        self.buf = bytearray()
        self.pos = 0
        self.events = []
        self.ctl = []
        # 与 events/ctl 并行的**有序**序列。时间轴要按流里的先后把 gap / sync
        # 插到正确位置，而 events 与 ctl 分开存会丢掉「谁在前」这个信息。
        self.items = []
        self.lost = 0
        self.hit = 0
        self.hitn = 0
        self.lit = 0

    @property
    def leftover(self):
        """已喂进来但还没被解成完整 token 的字节数。

        head 永远落在 token 边界上，所以正常读完一段之后这里必须是 0；
        非 0 说明流对不齐（或宿主只读了一半），此时**不能**推进 drained，
        否则剩下的半截 token 会被目标的环覆写掉。
        """
        return len(self.buf) - self.pos

    def feed(self, data):
        self.buf += data
        self._drain()
        if self.pos > 8192:
            del self.buf[:self.pos]
            self.pos = 0
        return self.events

    def _drain(self):
        buf = self.buf
        while self.pos < len(buf):
            start = self.pos
            try:
                tag = buf[start] >> 6
                low = buf[start] & 0x3F
                p = start + 1
                if tag == TAG_HITN:
                    key = self.slot[low]
                    if key is None:
                        raise StreamDesync(
                            "HITN 指向空槽：流不是从边界开始的，或字典已不同步")
                    dt = 0
                    self.events.append((key, dt))
                    self.items.append(("ev", key, dt))
                    self.hitn += 1
                elif tag == TAG_HIT:
                    key = self.slot[low]
                    if key is None:
                        raise StreamDesync(
                            "HIT 指向空槽：流不是从边界开始的，或字典已不同步")
                    dt, p = get_varint(buf, p)
                    self.events.append((key, dt))
                    self.items.append(("ev", key, dt))
                    self.hit += 1
                elif tag == TAG_LIT:
                    if p + 4 > len(buf):
                        raise IndexError("LIT 字段截断")
                    t = buf[p] & 0xF
                    k = buf[p + 1] & 0x3
                    i = buf[p + 2] | (buf[p + 3] << 8)
                    p += 4
                    a, p = get_varint(buf, p)
                    dt, p = get_varint(buf, p)
                    if a > U32:
                        raise StreamDesync("arg 越界（流未对齐）")
                    key = (t, k, i, a)
                    self.slot[slot_of(key)] = key
                    self.events.append((key, dt))
                    self.items.append(("ev", key, dt))
                    self.lit += 1
                elif tag == TAG_CTL:
                    val, p = get_varint(buf, p)
                    self.ctl.append((low, val))
                    self.items.append(("ctl", low, val))
                    if low == CTL_LOST:
                        self.lost += val
                        self.slot = [None] * NSLOT
                    elif low == CTL_SYNC:
                        self.slot = [None] * NSLOT
                else:
                    raise StreamDesync("保留 tag 0b11（流未对齐）")
                self.pos = p
            except IndexError:
                self.pos = start   # 半截 token，等下一次喂
                return


def parse_ctrl(raw, addr=0):
    """把 80 字节控制块解成 dict。字段不对就明说哪里不对，不猜。"""
    if raw is None or len(raw) < CTRL_BYTES:
        return {"ok": False, "error_code": "swd-read-short",
                "error": "控制块只读到 %d 字节（需要 %d）"
                         % (0 if raw is None else len(raw), CTRL_BYTES),
                "hint": "目标在跑时经 SWD 读 RAM 可能短读/读回全 0，先 halt 再读。"}
    if raw[:8] != MAGIC:
        return {"ok": False, "error_code": "swd-magic-mismatch",
                "error": "地址 0x%08X 处不是 SWD 无缝流控制块（magic=%s）"
                         % (addr, raw[:8].hex()),
                "hint": "固件是不是用 MDK_TRACE_BACKEND_SWD 编的？符号 "
                        "mdk_trace_swd_blob 定位更可靠（给 elf=）。"}

    def u16(o):
        return int.from_bytes(raw[o:o + 2], "little")

    def u32(o):
        return int.from_bytes(raw[o:o + 4], "little")

    version = u16(OFF_VERSION)
    if version not in SUPPORTED_VERSIONS:
        return {"ok": False, "error_code": "swd-version-mismatch",
                "error": "控制块版本 %d，本工具支持 %s"
                         % (version, "/".join(str(v) for v in SUPPORTED_VERSIONS)),
                "hint": "主机与目标侧的组件版本不一致，换用配套的一组。"}
    cap = u32(OFF_CAP)
    ring_off = u32(OFF_RING_OFF)
    ctrl_bytes = u16(OFF_CTRL_BYTES)
    if ctrl_bytes != CTRL_BYTES or ring_off != CTRL_BYTES:
        return {"ok": False, "error_code": "swd-ctrl-inconsistent",
                "error": "控制块自述 ctrl_bytes=%d ring_off=%d，与协议的 %d 不符"
                         % (ctrl_bytes, ring_off, CTRL_BYTES)}
    if cap == 0 or (cap & (cap - 1)) != 0:
        return {"ok": False, "error_code": "swd-ctrl-inconsistent",
                "error": "cap=%d 不是 2 的幂（环形索引靠掩码，必须成幂）" % cap}

    head, drained = u32(OFF_HEAD), u32(OFF_DRAINED)
    pending = (head - drained) & U32
    info = {
        "ok": True, "addr": addr, "version": version, "cap": cap,
        "ring_off": ring_off, "ring_addr": addr + ring_off,
        "head": head, "drained": drained, "pending": pending,
        "lost_events": u32(OFF_LOST_EVENTS), "lost_bytes": u32(OFF_LOST_BYTES),
        "events": u32(OFF_EVENTS), "tokens": u32(OFF_TOKENS),
        "seq": u32(OFF_SEQ), "ts_shift": u32(OFF_TS_SHIFT),
        "cpu_hz": u32(OFF_CPU_HZ), "cycles": u32(OFF_CYCLES),
        "reset_req": u32(OFF_RESET_REQ),
        "dt_unit": u32(OFF_DT_UNIT),
        "ts_off": bool(u32(OFF_FLAGS) & FLAG_TS_OFF),
        "enabled": bool(u32(OFF_FLAGS) & FLAG_ENABLED),
        "wrapped": pending == cap,
    }
    if pending > cap:
        # 字段一并带出去：调用方要靠 seq 判断这是「地址错了」还是「目标重启过、
        # 游标被归零」——只报一句“不一致”的话，外面只能猜。
        info.update({
            "ok": False, "error_code": "swd-ctrl-inconsistent",
            "error": "head-drained=%d 超过容量 %d（head=%d drained=%d，地址大概不对，"
                     "或控制块是上一次运行的残值）" % (pending, cap, head, drained),
            "hint": "先看 seq 是不是变了（目标重启会重置游标）；地址错时用 elf= 按符号定位。"})
    return info


def read_logical(ring, cap, start, n):
    """从物理环里按逻辑偏移取 n 字节。ring 是整片 cap 字节的镜像。"""
    out = bytearray()
    for i in range(n):
        out.append(ring[(start + i) % cap])
    return bytes(out)


def event_dict(key, dt, prev_cycle, cpu_hz, ts_shift, dt_unit=0, ts_off=False):
    """把一条 (key, dt) 摊平成可读结构，并算出绝对时刻（秒）。

    dt_unit != 0 时 dt 的单位是 dt_unit 个周期（整数除法得来的），否则是
    2**ts_shift 个周期。ts_off=True 时整条流没有时间戳：cycles / t_us 一律
    给 None 并附 ts="none"，**不能**填成 0 或按到达顺序编时间——那会让下游
    以为这是一条有时间轴的数据。
    """
    t, k, i, a = key
    if ts_off:
        ev = {
            "type": TYPES.get(t, "type%d" % t), "kind": KINDS.get(k, "kind%d" % k),
            "id": i, "arg": a, "dt_cycles": None, "cycles": None, "ts": "none",
        }
        if t == 10 and i == 0:
            ev["from"] = (a >> 4) & 0xF
            ev["to"] = a & 0xF
        if t == 9 and FAULT_BASE <= i < FAULT_BASE + 0x100:
            ev["fault_class"] = FAULT_CLASS.get(i - FAULT_BASE, "unknown")
        if t == 7 and i in FAULT_REGS:
            ev["reg"] = FAULT_REGS[i]
        return ev, prev_cycle
    cycles = ((dt * dt_unit) if dt_unit else (dt << ts_shift)) & U32
    total = (prev_cycle + cycles) & 0xFFFFFFFFFFFFFFFF
    ev = {
        "type": TYPES.get(t, "type%d" % t),
        "kind": KINDS.get(k, "kind%d" % k),
        "id": i,
        "arg": a,
        "dt_cycles": cycles,
        "cycles": total,
    }
    if cpu_hz:
        ev["t_us"] = round(total * 1e6 / cpu_hz, 3)
    if t == 10 and i == 0:
        ev["from"] = (a >> 4) & 0xF
        ev["to"] = a & 0xF
    if t == 9 and FAULT_BASE <= i < FAULT_BASE + 0x100:
        ev["fault_class"] = FAULT_CLASS.get(i - FAULT_BASE, "unknown")
    if t == 7 and i in FAULT_REGS:
        ev["reg"] = FAULT_REGS[i]
    return ev, total
