# -*- coding: utf-8 -*-
"""批次55 mock 测试：buff 模式（全速录制、事后一次性读回）。

背景（用户在 F401 上跑 SVCrtOS trace 时定下的需求）：
「插桩的方式可以分两种工作模式，一个 stream 持续录持续读，另一个 buff 就是
全速录、时间粒度可以调整到最低。」

stream（ITM/RTT/UART）是「每条事件立刻出芯片，主机必须跟得上」；buff 是
「事件只写进 RAM 环形缓冲，一个字节不出芯片，跑完再读」。后者能全速录，
代价是缓冲有限、文本帧放不下、时间戳只存与上一条的周期差。

这一批测试盯的不是「能不能解出一条时间线」，而是**解错时会不会装作解对了**：
  - 控制块魔数不对 → 明确报地址/构建不对，不硬解；
  - 整片读回 0x00 → 报「这次读不可信」，**绝不等于「缓冲是空的」**；
  - 版本/记录尺寸不匹配 → 报不匹配，不按旧布局解析；
  - 读短了 → 报短读，不补 0 充数；
  - reset_req 写进去但目标还没处理 → 报 pending，不当成「已清空」；
  - 环形回卷 → 明确说「看到的是窗口不是全程」。

运行：python -m tests.test_batch55
"""
import os
import sys
import json
import struct
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import server as SV           # noqa: E402
from mdkdebug import trace as TR            # noqa: E402

PORT = 15881
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def call(srv, name, args):
    r = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}

def use(obj, name, val):
    old = getattr(obj, name)
    setattr(obj, name, val)
    return lambda: setattr(obj, name, old)

# ======================================================================
# 假目标内存：一个字节数组 + 链路原语替身。
# 替身必须忠实于真链路的语义——尤其是「可疑读数」这条：真 read_mem_verified
# 在整片 0x00/0xFF 时会带 read_confidence=low + degenerate。替身不能省这个，
# 否则「把脏读当空缓冲」这个错在 mock 里根本复现不出来。
BASE = 0x20000000
BLOB = 0x20001000
RECS = BLOB + TR._BUFF_CTRL_BYTES

class FakeMem:
    def __init__(self, size=0x8000, fill=0x00):
        self.mem = bytearray(bytes([fill]) * size)
        self.size = size
        self.writes = []
        self.write_fail = False
        self.degenerate = None
        self.read_confidence = "high"

    def _slice(self, addr, n):
        off = addr - BASE
        if off < 0 or off + n > self.size:
            return None
        return bytes(self.mem[off:off + n])

    def read(self, addr, n_bytes, timeout=10.0, link="auto"):
        if addr == 0xDEAD0000:                      # 专用：模拟链路读失败
            return None, {"ok": False, "error": "链路读失败(mock)", "link": "keil"}
        d = self._slice(addr, n_bytes)
        if d is None:
            return None, {"ok": False, "error": "地址越界(mock)", "link": "keil"}
        meta = {"link": "keil", "read_confidence": self.read_confidence,
                "while_running": False}
        if self.degenerate:
            meta["degenerate"] = self.degenerate
        if addr == 0xDEAD0004:                      # 专用：模拟读短
            return d[:-4], meta
        return d, meta

    def write(self, addr, data, timeout=10.0, link="auto"):
        if self.write_fail or addr == 0xDEAD0000:
            return {"ok": False, "error": "目标全速运行中，写不进去(mock)",
                    "link": "keil"}
        off = addr - BASE
        if off < 0 or off + len(data) > self.size:
            return {"ok": False, "error": "地址越界(mock)", "link": "keil"}
        self.mem[off:off + len(data)] = data
        self.writes.append((addr, bytes(data)))
        return {"ok": True, "written": len(data), "link": "keil"}

def rec(t, k, i, a, dt):
    return bytes([t & 0xFF, k & 0xFF, i & 0xFF, (i >> 8) & 0xFF]) + struct.pack("<II", a, dt)

def put_ctrl(mem, *, magic=b"MDKTBUF1", version=1, rec_size=12, cap=8,
             head=0, total=0, lost=0, text_dropped=0, ts_shift=0,
             cpu_hz=84000000, last_cycles=0, flags=1, reset_req=0, seq=1):
    ctrl = bytearray(TR._BUFF_CTRL_BYTES)
    ctrl[0:8] = magic
    struct.pack_into("<14I", ctrl, 8, version, rec_size, cap, RECS, head, total,
                     lost, text_dropped, ts_shift, cpu_hz, last_cycles, flags,
                     reset_req, seq)
    mem.mem[BLOB - BASE:BLOB - BASE + TR._BUFF_CTRL_BYTES] = ctrl

def put_recs(mem, recs):
    buf = b"".join(recs)
    mem.mem[RECS - BASE:RECS - BASE + len(buf)] = buf

def patch(mem, blob=BLOB):
    """把 _read_mem_words / _write_mem / _elf_symbol 换成替身。返回 undo。"""
    u1 = use(TR, "_read_mem_words", mem.read)
    u2 = use(TR, "_write_mem", mem.write)
    u3 = use(TR, "_elf_symbol",
             lambda elf, nm: ((blob, 0x80) if nm == TR._BUFF_SYMBOL else (None, None)))
    u4 = use(TR, "_session_axf", lambda: "")
    return lambda: (u1(), u2(), u3(), u4())

ELF = os.path.abspath(__file__)      # 只当「存在的路径」用，符号表由替身提供

# ======================================================================
def section_a():
    print("A. 定位：找不到符号就说找不到，不猜地址")
    mem = FakeMem()
    undo = patch(mem)
    undo_elf = use(TR, "_elf_symbol", lambda elf, nm: (None, None))
    try:
        r = TR.buff_status(elf=ELF)
        check("A1 elf 里没有 mdk_trace_buff_blob → buff-symbol-missing",
              r.get("ok") is False and r.get("error_code") == "buff-symbol-missing", r)
        h = r.get("hint") or ""
        check("A2 提示说清三条真路（是不是 buff 构建 / gc-sections / 直接给 addr）",
              "BACKEND_BUFF" in h and "gc-sections" in h and "addr" in h, h)

        r2 = TR.buff_status(addr="0xZZ")
        check("A3 addr 解析失败 → invalid-argument（不静默当 0）",
              r2.get("ok") is False and r2.get("error_code") == "invalid-argument", r2)

        r3 = TR.buff_status()
        check("A4 既没 elf 也没 addr → buff-locate-failed",
              r3.get("ok") is False and r3.get("error_code") == "buff-locate-failed", r3)
    finally:
        undo()
        undo_elf()

def section_b():
    print("B. 控制块校验：宁可报错，也不按错地址硬解")
    # B1 魔数不对（且不是全 0）→ magic-mismatch
    mem = FakeMem()
    put_ctrl(mem, magic=b"XXXXXXXX")
    undo = patch(mem)
    try:
        r = TR.buff_status(elf=ELF)
        check("B1 魔数不对 → buff-magic-mismatch，且报出读到的魔数",
              r.get("ok") is False and r.get("error_code") == "buff-magic-mismatch"
              and r.get("magic") == "XXXXXXXX", r)
    finally:
        undo()

    # B2 整片 0x00 → 明确「这次读不可信」，不是「缓冲空」
    mem = FakeMem(fill=0x00)
    undo = patch(mem)
    try:
        r = TR.buff_status(elf=ELF)
        check("B2 整片 0x00 → buff-read-degenerate（不是「缓冲是空的」）",
              r.get("ok") is False and r.get("error_code") == "buff-read-degenerate", r)
        txt = (r.get("error") or "") + (r.get("hint") or "")
        check("B3 文案明确否认「空缓冲」这个错误读法，并给出 halt/换链路两条路",
              "不等于缓冲是空的" in txt and "halt" in txt and "链路" in txt, txt)
    finally:
        undo()

    # B4 版本/记录尺寸不匹配
    mem = FakeMem()
    put_ctrl(mem, version=7)
    undo = patch(mem)
    try:
        r = TR.buff_status(elf=ELF)
        check("B4 版本不匹配 → buff-version-mismatch（不按旧布局硬解）",
              r.get("ok") is False and r.get("error_code") == "buff-version-mismatch"
              and r.get("version") == 7, r)
    finally:
        undo()

    # B5 字段不合理
    mem = FakeMem()
    put_ctrl(mem, cap=0)
    undo = patch(mem)
    try:
        r = TR.buff_status(elf=ELF)
        check("B5 cap=0 → buff-ctrl-inconsistent",
              r.get("ok") is False and r.get("error_code") == "buff-ctrl-inconsistent", r)
    finally:
        undo()

    # B6 链路读失败如实传
    mem = FakeMem()
    undo = patch(mem, blob=0xDEAD0000)
    try:
        r = TR.buff_status(elf=ELF)
        check("B6 链路读失败 → buff-read-failed 并带上原链路的错",
              r.get("ok") is False and r.get("error_code") == "buff-read-failed"
              and "mock" in (r.get("error") or ""), r)
    finally:
        undo()

def section_c():
    print("C. 时间轴：dt 累加 + last_cycles 反推绝对时刻")
    CPU = 84000000
    recs = [
        rec(10, 0, 0, 1, 84000),          # sched 0->1，1ms 后
        rec(2, 0, 0x10, 0, 8400),         # event id=0x10 enter，100us 后
        rec(9, 0, 1, 0x00000082, 42),     # fault memmanage，CFSR=DACCVIOL|MMARVALID
        rec(3, 0, 0xFF01, 0x08001234, 10),  # pc
        rec(3, 0, 0xFF03, 0x20001FF0, 10),  # sp
        rec(3, 0, 0xFF04, 0x40000000, 10),  # hfsr
        rec(5, 0, 0, 0xAABBCCDD, 100),    # mark
    ]
    total_dt = sum(r[8:12] and struct.unpack_from("<I", r, 8)[0] for r in recs)
    last = (0x12345678 + total_dt) & 0xFFFFFFFF
    mem = FakeMem()
    put_ctrl(mem, cap=16, head=len(recs), total=len(recs), last_cycles=last)
    put_recs(mem, recs)
    undo = patch(mem)
    try:
        r = TR.buff_dump(elf=ELF, names="0x10=switch")
        check("C1 dump 成功且记录数 = head",
              r.get("ok") is True and r.get("record_count") == len(recs), r)
        ev = r.get("events") or []
        check("C2 七条记录的类型都解对",
              [e["type"] for e in ev] == ["sched", "event", "fault", "counter",
                                          "counter", "counter", "mark"],
              [e.get("type") for e in ev])
        check("C3 第一条事件的相对时刻 = 它自己的 dt（84e3 cycles @84MHz = 1000us）",
              abs(ev[0].get("t_us", 0) - 1000.0) < 1e-6, ev[0])
        check("C4 时间单调不减（dt 是差值，累加不该回头）",
              all(ev[i]["t_cycles"] <= ev[i + 1]["t_cycles"] for i in range(len(ev) - 1)),
              [e.get("t_cycles") for e in ev])
        check("C5 末条记录的时刻 == 控制块里的 last_cycles（反推对得上）",
              ev[-1]["t_cycles"] == last, (ev[-1].get("t_cycles"), last))
        check("C6 span 与 dt 总和一致",
              r.get("span_cycles") == total_dt - 84000, (r.get("span_cycles"), total_dt))
        check("C7 sched 事件译出 from/to",
              ev[0].get("from") == 0 and ev[0].get("to") == 1, ev[0])
        check("C8 names 把 id 译成名字", ev[1].get("id_name") == "switch", ev[1])
        check("C9 event 的 kind 解出 enter", ev[1].get("kind") == "enter", ev[1])
    finally:
        undo()

def section_d():
    print("D. 异常现场：CFSR 逐位拆解 + 寄存器归到那一次 fault")
    recs = [
        rec(9, 0, 1, 0x00000082, 100),      # memmanage: DACCVIOL|MMARVALID
        rec(3, 0, 0xFF01, 0x08001234, 10),  # pc
        rec(3, 0, 0xFF02, 0x08005678, 10),  # lr
        rec(3, 0, 0xFF03, 0x20001FF0, 10),  # sp
        rec(3, 0, 0xFF04, 0x40000000, 10),  # hfsr
        rec(3, 0, 0xFF05, 0x00000000, 10),  # mmfar
        rec(3, 0, 0xFF06, 0x00000000, 10),  # bfar
        rec(3, 0, 0xFF07, 0x61000000, 10),  # xpsr
    ]
    last = 0x2000 + sum(struct.unpack_from("<I", r, 8)[0] for r in recs)
    mem = FakeMem()
    put_ctrl(mem, cap=16, head=len(recs), total=len(recs), last_cycles=last)
    put_recs(mem, recs)
    undo = patch(mem)
    try:
        r = TR.buff_dump(elf=ELF)
        f = (r.get("faults") or [])
        check("D1 录到 1 次异常", len(f) == 1, f)
        check("D2 异常类别解成 memmanage", f and f[0]["class"] == "memmanage", f)
        check("D3 CFSR 原值透出", f and f[0]["cfsr"] == "0x00000082", f)
        names = [b["name"] for b in (f[0]["cfsr_bits"] if f else [])]
        check("D4 CFSR 被拆成可读位名（DACCVIOL + MMARVALID）",
              names == ["DACCVIOL", "MMARVALID"], names)
        regs = (f[0]["registers"] if f else {})
        check("D5 七个寄存器现场都归到这次 fault 上",
              set(regs) == {"pc", "lr", "sp", "hfsr", "mmfar", "bfar", "xpsr"}, regs)
        check("D6 pc 值正确（这是排查 brick 现场第一个要看的数）",
              regs.get("pc") == "0x08001234", regs)
        check("D7 计数器事件本身带 reg/value_hex 标注",
              any(e.get("reg") == "pc" and e.get("value_hex") == "0x08001234"
                  for e in (r.get("events") or [])), r.get("events"))
        check("D8 有异常时给出 warnings（不让它埋在 events 里）",
              any("异常" in w for w in (r.get("warnings") or [])), r.get("warnings"))
    finally:
        undo()

def section_e():
    print("E. 环形回卷：看到的是窗口，不是全程")
    cap = 4
    recs = [rec(5, 0, 0, n, 100) for n in range(7)]   # 写 7 条进 cap=4
    # 7 次写入后 head = 7 % 4 = 3；槽位 3,0,1,2 依次是「次旧→最新」
    slot = {3: 3, 0: 4, 1: 5, 2: 6}
    buf = [b""] * cap
    for s, n in slot.items():
        buf[s] = recs[n]
    last = 1000 + sum(struct.unpack_from("<I", r, 8)[0] for r in buf)
    mem = FakeMem()
    put_ctrl(mem, cap=cap, head=3, total=7, last_cycles=last, flags=1 | 2)
    put_recs(mem, buf)
    undo = patch(mem)
    try:
        r = TR.buff_dump(elf=ELF)
        ev = r.get("events") or []
        check("E1 回卷时只给 cap 条，且顺序是次旧→最新（从 head 绕回去）",
              r.get("record_count") == cap and [e["n"] for e in ev] == [0, 1, 2, 3], ev)
        check("E2 arg 顺序 = 第 4,5,6,7 条（最旧的 3 条已被覆盖）",
              [e["arg"] for e in ev] == [3, 4, 5, 6], [e.get("arg") for e in ev])
        check("E3 wrapped 透出，且 total/cap 都给（能区分「上限 N」与「只有 N 次」）",
              r.get("wrapped") is True and r.get("total") == 7 and r.get("cap") == cap, r)
        check("E4 warnings 说清「看到的是一个窗口，不是全程」",
              any("窗口" in w for w in (r.get("warnings") or [])), r.get("warnings"))
    finally:
        undo()

def section_f():
    print("F. 丢记录 / 重启接缝：如实计数，不当成完整时间线")
    recs = [rec(5, 0, 0, 1, 100), rec(8, 0, 0, 0, 100), rec(5, 0, 0, 2, 100)]
    last = 500 + 300
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=3, total=3, last_cycles=last, lost=17,
             text_dropped=3, flags=1 | 4)
    put_recs(mem, recs)
    undo = patch(mem)
    try:
        r = TR.buff_dump(elf=ELF)
        check("F1 lost / text_dropped 原样透出",
              r.get("lost") == 17 and r.get("text_dropped") == 3, r)
        w = " ".join(r.get("warnings") or [])
        check("F2 warnings 点明时间线不完整", "不完整" in w, w)
        check("F3 warnings 点明重启接缝（旧记录属于上一次运行）",
              "重启" in w and "接缝" in w, w)
        (r.get("events") or [])
        check("F4 reset 类型事件解得出（作为接缝标记）",
              any(e.get("type") == "reset" for e in r.get("events") or []), r.get("events"))
    finally:
        undo()

    # 空缓冲：这是唯一可以合法说「什么也没有」的场景
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=0, total=0, last_cycles=0)
    undo = patch(mem)
    try:
        r = TR.buff_dump(elf=ELF)
        check("F5 head=0 且魔数正确 → 才允许说「还没有记录」，并问「init 调了吗 / 触发过插桩吗」",
              r.get("ok") is True and r.get("record_count") == 0
              and "mdk_trace_init" in (r.get("note") or ""), r)
    finally:
        undo()

def section_g():
    print("G. 短读 / 导出：读不全就报，不补 0 充数")
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=4, total=4, last_cycles=1000)
    put_recs(mem, [rec(5, 0, 0, n, 10) for n in range(4)])
    mem.mem[RECS - BASE + 8:RECS - BASE + 12] = b"\x00\x00\x00\x00"
    # 让记录区首块读成短包
    real_read = mem.read

    def short_read(addr, n_bytes, timeout=10.0, link="auto"):
        d, m = real_read(addr, n_bytes, timeout=timeout, link=link)
        if addr == RECS and d is not None:
            return d[:-12], m
        return d, m

    undo = patch(mem)
    old = TR._read_mem_words
    TR._read_mem_words = short_read
    try:
        r = TR.buff_dump(elf=ELF)
        check("G1 记录区读短 → buff-read-short，不补 0 当成完整记录",
              r.get("ok") is False and r.get("error_code") == "buff-read-short", r)
    finally:
        TR._read_mem_words = old
        undo()

    # 正常导出
    mem = FakeMem()
    recs = [rec(10, 0, 0, 1, 8400), rec(14, 0, 3, 0, 4200), rec(5, 0, 0, 9, 42)]
    last = 999 + 8400 + 4200 + 42
    put_ctrl(mem, cap=8, head=3, total=3, last_cycles=last)
    put_recs(mem, recs)
    undo = patch(mem)
    tmp = tempfile.mkdtemp(prefix="mdk_buff_")
    out = os.path.join(tmp, "sub", "timeline.json")
    try:
        r = TR.buff_dump(elf=ELF, limit=1, out_file=out)
        check("G2 limit 只截返回条数，record_count 仍是全量",
              r.get("ok") and len(r.get("events") or []) == 1
              and r.get("record_count") == 3 and r.get("truncated") is True, r)
        check("G3 out_file 自动建父目录并写全量", os.path.isfile(out), out)
        with open(out, encoding="utf-8") as f:
            j = json.load(f)
        check("G4 落盘 JSON 里是全量事件 + meta + faults",
              len(j.get("events") or []) == 3 and "meta" in j and "faults" in j,
              list(j))
        check("G5 返回里给 out_file 与条数，便于上层直接引用",
              r.get("out_file") == os.path.abspath(out) and r.get("out_records") == 3, r)
    finally:
        undo()

def section_h():
    print("H. reset_req：延迟生效要说清，别把 pending 当成 applied")
    # H1 写入失败（读得到控制块，只有写不进去）
    mem = FakeMem()
    mem.write_fail = True
    put_ctrl(mem, cap=8, head=0, total=0, seq=5)
    undo = patch(mem)
    try:
        r = TR.buff_reset(elf=ELF)
        check("H1 写不进去 → buff-reset-write-failed（带原链路错与先 halt 的建议）",
              r.get("ok") is False and r.get("error_code") == "buff-reset-write-failed"
              and "halt" in (r.get("hint") or "") and "mock" in (r.get("error") or ""), r)
    finally:
        undo()

    # H2 写成功但 seq 没变 → pending，不是 applied
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=0, total=0, seq=5)
    undo = patch(mem)
    try:
        r = TR.buff_reset(elf=ELF)
        check("H2 写成功但目标没处理 → applied=False / request_latched=True",
              r.get("ok") and r.get("applied") is False
              and r.get("request_latched") is True, r)
        check("H3 文案明确「这不是失败，但也不能当成已清空」",
              "已清空" in (r.get("note") or ""), r.get("note"))
        check("H4 写到了控制块 +56（reset_req 偏移）",
              mem.writes and mem.writes[0][0] == BLOB + TR._BUFF_RESET_REQ_OFF
              and mem.writes[0][1] == struct.pack("<I", 1), mem.writes)
    finally:
        undo()

    # H3 真生效（模拟目标处理了：seq 变了）
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=0, total=0, seq=5)

    def write_and_bump(addr, data, timeout=10.0, link="auto"):
        r = mem.__class__.write(mem, addr, data, timeout=timeout, link=link)
        if addr == BLOB + TR._BUFF_RESET_REQ_OFF:
            put_ctrl(mem, cap=8, head=0, total=0, seq=6)
        return r

    undo = patch(mem)
    old_w = TR._write_mem
    TR._write_mem = write_and_bump
    try:
        r = TR.buff_reset(elf=ELF)
        check("H5 seq 变了才报 applied=True（判据是可观测结果，不是「写成功」）",
              r.get("ok") and r.get("applied") is True
              and r.get("seq_before") == 5 and r.get("seq_after") == 6, r)
    finally:
        TR._write_mem = old_w
        undo()

    # H4 no-wait 情形
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=0, total=0, seq=2)
    undo = patch(mem)
    try:
        r = TR.buff_reset(elf=ELF, wait=False)
        check("H6 wait=False → 不回读、applied=False，并说明尚未确认",
              r.get("ok") and r.get("applied") is False
              and "下一条记录" in (r.get("note") or ""), r)
    finally:
        undo()

def section_i():
    print("I. 没有时间基：宁可交空，也不编一个时间戳")
    mem = FakeMem()
    put_ctrl(mem, cap=8, head=3, total=3, cpu_hz=0, last_cycles=100)
    put_recs(mem, [rec(5, 0, 0, 1, 10)] * 3)
    undo = patch(mem)
    try:
        r = TR.buff_status(elf=ELF)
        check("I1 cpu_hz=0 → 状态里明确警告 dt 只有周期数、给不了微秒",
              any("cpu_hz=0" in w or "微秒" in w for w in (r.get("warnings") or [])), r)
        r2 = TR.buff_dump(elf=ELF)
        check("I2 cpu_hz=0 时 t_us 不给（返回 None），span_us 也是 None",
              (r2.get("events") or [{}])[0].get("t_us") is None
              and r2.get("span_us") is None, r2.get("events"))
        check("I3 周期数仍然给（t_cycles 不为空），不是把数据一起丢了",
              (r2.get("events") or [{}])[0].get("t_cycles") is not None, r2.get("events"))
    finally:
        undo()

def section_j():
    print("J. 主机侧工具层（server）")
    mem = FakeMem()
    recs = [rec(10, 0, 0, 1, 8400), rec(2, 0, 0x10, 0, 42)]
    last = 777 + 8400 + 42
    put_ctrl(mem, cap=8, head=2, total=2, last_cycles=last)
    put_recs(mem, recs)
    undo = patch(mem)
    try:
        srv = SV.create_server(port=PORT)
        r = call(srv, "trace_buff_status", {"elf": ELF, "link": "keil"})
        check("J1 trace_buff_status 经 server 可用，status=ok",
              r.get("ok") is True and r.get("status") == "ok"
              and r.get("total") == 2, r)
        r2 = call(srv, "trace_buff_dump",
                  {"elf": ELF, "link": "keil", "names": "0x10=switch"})
        check("J2 trace_buff_dump 经 server 可用，事件被解出",
              r2.get("ok") is True and r2.get("record_count") == 2
              and (r2.get("events") or [{}])[1].get("id_name") == "switch", r2)
        r3 = call(srv, "trace_buff_reset", {"elf": ELF, "link": "keil"})
        check("J3 trace_buff_reset 经 server 可用", r3.get("ok") is True, r3)
    finally:
        undo()

    # trace_instrument 的 buff 后端与配置头生成
    tmp = tempfile.mkdtemp(prefix="mdk_buff_dep_")
    r = TR.deploy_component(tmp, backend="buff", coreclk=84000000,
                            buff_records=4096, buff_ts_shift=0)
    check("K1 trace_instrument backend=buff 被接受（不再回落 itm）",
          r.get("ok") is True and r.get("backend") == "buff", r)
    cfg = ""
    p = os.path.join(tmp, "mdk_trace_config.h")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            cfg = f.read()
    check("K2 配置头里选的是 BUFF 后端",
          "MDK_TRACE_BACKEND_BUFF 1" in cfg, cfg[:400])
    check("K3 配置头带 buff 三个旋钮（记录数 / 时间粒度 / 复位是否保留）",
          "MDK_TRACE_BUFF_RECORDS      4096" in cfg
          and "MDK_TRACE_BUFF_TS_SHIFT     0" in cfg
          and "MDK_TRACE_BUFF_CLEAR_ON_INIT 0" in cfg, cfg)
    check("K4 配置头带 FAULT_FRAME（异常现场是 buff 模式最有价值的输出）",
          "MDK_TRACE_FAULT_FRAME       1" in cfg, cfg)
    check("K5 cpu_hz 写进去了（不然 dt 只能给周期数）",
          "MDK_TRACE_CPU_HZ            84000000" in cfg, cfg)
    nxt = " ".join(r.get("next") or [])
    check("K6 next 指向 trace_buff_dump（buff 模式的读取端）",
          "trace_buff_dump" in nxt, nxt)
    mk = os.path.join(tmp, "mdk_trace.mk")
    mk_txt = open(mk, encoding="utf-8").read() if os.path.isfile(mk) else ""
    check("K7 make 片段包含 mdk_trace_buff.c", "mdk_trace_buff.c" in mk_txt, mk_txt)

    r2 = TR.deploy_component(tempfile.mkdtemp(prefix="mdk_dep2_"), backend="buff")
    nxt2 = " ".join(r2.get("next") or [])
    check("K8 next 提醒在 fault handler 第一条语句调 MDK_TRACE_FAULT_CAPTURE()",
          "MDK_TRACE_FAULT_CAPTURE" in nxt2 and "第一条" in nxt2, nxt2)
    check("K9 next 提醒 MDK_TRACE_SCHED 打任务切换点",
          "MDK_TRACE_SCHED" in nxt2, nxt2)

def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    section_h()
    section_i()
    section_j()
    print("\n批次55 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
