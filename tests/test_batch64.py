# -*- coding: utf-8 -*-
"""批次64 mock 测试：SWD 无缝流的「任务维度」——调度事件解出 from/to，并给它们名字。

两件事，都是「看起来对、其实不对」的历史欠账：

1. **调度事件解错了**。目标侧 `mdk_trace_sched(from, to)` 发出的 token 是
   `id=from, arg=to`；主机 `_swd_fold` 却按「arg = from<<4 | to」解，而且只在
   `id == 0` 时才解——那是 SVCRT_TR_SW_PACK 那套**从没用上**的编码。结果是绝大多数
   上下文切换在时间轴上没有 from/to，任务维度等于不存在（buff 路径一直解的是
   id/arg，两条路互相矛盾，说明错的是 SWD 这条）。

2. **任务只有序号没有名字**。流里的任务号是 4 bit（0..14 是任务表下标、0xF 是
   idle）。TCB 里没有名字字段，能稳定取名字的字段是 `svcrt_task_table[i].entry`
   （void (*)(void)）——把它反查 ELF 函数符号就得到任务名。取不到就如实说明原因，
   **绝不编一个像样的名字**（名字错了比没名字更难发现）。

  A 调度事件解码：from=id / to=arg，与 buff 路径一致，超范围显式告警
  B 任务名：序号→名字、idle 单独处理、arg 是任务号的事件也认
  C 回头重补：名字后到时，历史事件也补上（否则前半段还是数字）
  D 解析失败的错误码：无 elf / 无表符号 / 无布局 / 伪值 / 快照不自洽
  D4 跨镜像入口：留空不编名（app 的任务入口不在内核 .axf 里是合法的）
  E 会话内只解析一次；tasks=off 完全不碰
  F 真实 .axf 的 DWARF 路径（无目标，纯本地解析；文件不在则跳过）
  H 多份镜像（内核;app）联合取名：任何一份的入口都能配上名字，但**跨镜像**的名字
    必须过内容核对（板上机器码 == .axf 同地址字节）——地址对上不等于板上跑的是
    这份构建；核不过/核不了就丢名并记 unconfirmed_slots
  I 时间轴冻结：粒度比事件间隔粗时，目标算 dt 丢掉余数 → 每条都是 0 → 宿主累加
    出来的时间轴冻在原点，必须当场报 time_axis_frozen 而不是画一条平平的轴
  J events 口径：默认给会话尾部（含前几次调用的事件、互相重叠），only_new=true
    才只给本批新增——自己拼线性轨迹时搞错就会把同一段时间数很多遍

运行：python -m tests.test_batch64
"""
import os
import sys
import struct
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import linkio as L            # noqa: E402
from mdkdebug import rtos as RTOS           # noqa: E402
from mdkdebug import swd as SWD             # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402
from mdkdebug.client import UVClient        # noqa: E402

PASS, FAIL, SKIP = [], [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def skip(name, why):
    SKIP.append(name)
    print("  [SKIP] %s %s" % (name, why), flush=True)

# ======================================================================
# 假目标：控制块 + 环 + 一张任务表
# ======================================================================
TBL = 0x20001000          # 任务表地址（与环无关，随便挑一个）
TCB_SIZE = 76             # svcrt_task_t（F427 Debug 实测）
ENTRY_OFF = 64

def build_ctrl(addr, cap=8192, head=0, drained=0, seq=7, flags=None,
               tokens=0, events=0):
    if flags is None:
        flags = SWD.FLAG_ENABLED | SWD.FLAG_TS_OFF
    b = bytearray(SWD.CTRL_BYTES)
    b[0:8] = SWD.MAGIC
    b[SWD.OFF_VERSION:SWD.OFF_VERSION + 2] = struct.pack(
        "<H", SWD.SUPPORTED_VERSIONS[0])
    b[SWD.OFF_CTRL_BYTES:SWD.OFF_CTRL_BYTES + 2] = struct.pack("<H", SWD.CTRL_BYTES)
    b[SWD.OFF_CAP:SWD.OFF_CAP + 4] = struct.pack("<I", cap)
    b[SWD.OFF_RING_OFF:SWD.OFF_RING_OFF + 4] = struct.pack("<I", SWD.CTRL_BYTES)
    b[SWD.OFF_HEAD:SWD.OFF_HEAD + 4] = struct.pack("<I", head)
    b[SWD.OFF_DRAINED:SWD.OFF_DRAINED + 4] = struct.pack("<I", drained)
    b[SWD.OFF_EVENTS:SWD.OFF_EVENTS + 4] = struct.pack("<I", events)
    b[SWD.OFF_TOKENS:SWD.OFF_TOKENS + 4] = struct.pack("<I", tokens)
    b[SWD.OFF_SEQ:SWD.OFF_SEQ + 4] = struct.pack("<I", seq)
    b[SWD.OFF_CPU_HZ:SWD.OFF_CPU_HZ + 4] = struct.pack("<I", 168000000)
    b[SWD.OFF_FLAGS:SWD.OFF_FLAGS + 4] = struct.pack("<I", flags)
    return bytes(b)

def task_table_bytes(entries, n_slots=15, size=TCB_SIZE, off=ENTRY_OFF):
    """按 TCB 布局造一张表：只有 entry 字段有值，其余填 0xA5。"""
    b = bytearray(0xA5 for _ in range(n_slots * size))
    for i in range(n_slots):
        e = entries.get(i, 0)
        struct.pack_into("<I", b, i * size + off, e & 0xFFFFFFFF)
    return bytes(b)

class FakeSwdLink:
    name = "keil"
    label = "Keil(mock)"

    def __init__(self, addr, ctrl, ring, extra=None, running=True):
        self.addr = int(addr)
        self.ring_base = self.addr + SWD.CTRL_BYTES
        self.ctrl = bytearray(ctrl)
        self.ring = bytearray(ring)
        self.extra = dict(extra or {})          # 地址 -> bytes
        self.running = bool(running)
        self.halt_calls = 0
        self.resume_calls = 0
        self.reads = []

    def _mem(self, addr, n):
        addr, n = int(addr), int(n)
        out = bytearray()
        for i in range(n):
            a = addr + i
            off = a - self.addr
            if 0 <= off < SWD.CTRL_BYTES:
                out.append(self.ctrl[off])
            elif 0 <= a - self.ring_base < len(self.ring):
                out.append(self.ring[a - self.ring_base])
            else:
                got = None
                for base, blob in self.extra.items():
                    if base <= a < base + len(blob):
                        got = blob[a - base]
                        break
                out.append(0x00 if got is None else got)
        return bytes(out)

    def read(self, addr, n):
        self.reads.append((int(addr), int(n)))
        data = self._mem(addr, n)
        meta = {"link": self.name}
        deg = UVClient._degenerate_kind(data)
        if deg:
            meta["degenerate"] = deg
        return data, meta

    def read_once(self, addr, n):
        data = self._mem(addr, n)
        meta = {"link": self.name, "read_mode": "single"}
        deg = UVClient._degenerate_kind(data)
        if deg:
            meta["degenerate"] = deg
        return data, meta

    def write(self, addr, data):
        for i, b in enumerate(data):
            off = int(addr) + i - self.addr
            if 0 <= off < SWD.CTRL_BYTES:
                self.ctrl[off] = b
        return True, {"link": self.name}

    def halt(self):
        self.halt_calls += 1
        self.running = False
        return {"ok": True}

    def resume(self):
        self.resume_calls += 1
        self.running = True
        return {"ok": True}

    def describe(self):
        return {"debugging": True, "running": self.running,
                "status_text": "running(mock)"}

    need_halt_for_read = staticmethod(lambda: False)

def patch_pick(fake):
    real = L.pick
    L.pick = lambda link="auto", who="": (fake, None)
    return lambda: setattr(L, "pick", real)

# ======================================================================
# 假的 ELF 索引 + 假的函数符号表
# ======================================================================
class FakeIndex:
    def __init__(self, base=TBL, count=48, tcb=None, entry_off=ENTRY_OFF,
                 struct_size=TCB_SIZE, no_table=False, no_layout=False,
                 code=None):
        self._base = None if no_table else base
        self._count = count
        self._tcb = tcb
        self._entry_off = entry_off
        self._size = struct_size
        self._no_layout = no_layout
        self._code = dict(code or {})      # vaddr -> 该 .axf 里那个地址的字节
        self.error = None

    def bytes_at(self, vaddr, n):
        """模拟 ElfIndex.bytes_at：取不到就 None（跨镜像名字的内容核对靠它）。"""
        blob = self._code.get(int(vaddr))
        if blob is None:
            return None
        return bytes(blob)[:int(n)]

    def addr_of(self, name):
        return self._base if name == TRC._SVCRT_TABLE_SYM else None

    def struct(self, name):
        if self._no_layout or name != TRC._SVCRT_TCB_TYPE:
            return None
        return {"size": self._size, "fields": {"entry": self._entry_off},
                "_arrlen": {}}

    def field(self, name, member):
        if self._no_layout:
            return None
        return self._entry_off if member == "entry" else None

    def var_kind(self, name):
        return {"kind": "array", "type": TRC._SVCRT_TCB_TYPE,
                "count": self._count, "size": self._count * self._size}

FUNCS = [(0x08000100, "app_main"), (0x08000200, "bled_task"),
         (0x08000300, "drv_poll"), (0x08000400, "shell_task"),
         (0x08010000, "dummy_tail")]

def patch_elf(index, funcs=FUNCS):
    old_i, old_f = RTOS.get_index, TRC._elf_funcs_cached
    RTOS.get_index = lambda p: index
    TRC._elf_funcs_cached = lambda p: list(funcs)
    def undo():
        RTOS.get_index = old_i
        TRC._elf_funcs_cached = old_f
    return undo

def patch_read_mem(table_bytes, code=None):
    """把 _read_mem_words 拦在任务表地址上（其他地址照常走假链路）。

    code 给 {vaddr: bytes}：那些地址按字节返回，用来喂跨镜像名字的**内容核对**——
    核对要求「板上机器码 == .axf 同地址字节」，这里就是那个「板上机器码」。
    """
    real = TRC._read_mem_words
    hits = []
    code = dict(code or {})
    def fake(addr, n, link="auto", raw=False, **kw):
        if int(addr) in code:
            hits.append((int(addr), int(n)))
            blob = code[int(addr)]
            return bytes(blob[:int(n)]), {"link": "keil", "read_mode": "single"}
        if TBL <= int(addr) < TBL + len(table_bytes):
            hits.append((int(addr), int(n)))
            off = int(addr) - TBL
            return table_bytes[off:off + int(n)], {"link": "keil", "read_mode": "single"}
        return real(addr, n, link=link, raw=raw, **kw)
    TRC._read_mem_words = fake
    def undo():
        TRC._read_mem_words = real
    return hits, undo

def scenario(events, tbl_entries=None, no_table=False, no_layout=False,
             table_bytes=None, count=48, extra=None, flags=None):
    """一段含 sync + 事件的合法流，外加一张任务表。

    flags 默认带 TS_OFF（老夹具都是「没有时间轴」那种流）；要看**有时间戳**
    的行为（例如 dt 全 0 的冻结轴）就传 SWD.FLAG_ENABLED。
    """
    enc = SWD.Encoder()
    stream = enc.sync(1) + enc.encode(events)
    ring = bytearray(8192)
    ring[0:len(stream)] = stream
    addr = 0x200020C8
    ctrl = build_ctrl(addr, head=len(stream), tokens=len(events),
                      events=len(events), flags=flags)
    lk = FakeSwdLink(addr, ctrl, ring, extra=extra)
    idx = FakeIndex(no_table=no_table, no_layout=no_layout, count=count)
    tb = table_bytes if table_bytes is not None else task_table_bytes(
        tbl_entries if tbl_entries is not None else
        # 0=app_main 1=bled_task 2=drv_poll 3=shell_task 5=app_main（夹具的默认快照）
        {0: 0x08000101, 1: 0x08000201, 2: 0x08000301, 3: 0x08000401,
         5: 0x08000101},
        n_slots=min(count, 15))
    hits, undo_r = patch_read_mem(tb)
    undo_p = patch_pick(lk)
    undo_e = patch_elf(idx)
    TRC._T["swd"] = None
    def undo():
        undo_r(); undo_p(); undo_e(); TRC._T["swd"] = None
    return lk, hits, undo

SCHED_EV = [(SWD.make_key(10, 2, 2, 5), 0),    # sched from=2 to=5
            (SWD.make_key(10, 2, 0, 1), 0)]    # sched from=0 to=1

BLOB_ADDR = "0x200020C8"   # 与 scenario() 里假链路绑定的 blob 地址一致；
                            # 真机上也可以留给 ELF 符号，但这里的 elf 是空壳，必须显式给
ARGF = "/tmp/_t64.axf"                          # 假的 elf 路径（文件不存在时用例自己造）

def with_fake_axf(fn):
    """_svcrt_task_names 要求 elf 是真实存在的文件，这里造一个空壳。"""
    fd, p = tempfile.mkstemp(suffix=".axf")
    os.close(fd)
    try:
        return fn(p)
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass

# ======================================================================
def main():
    print("== A 调度事件解码（from=id / to=arg） ==", flush=True)
    s = {"rel_cycles": 0, "events_seen": 0, "faults": []}
    items = [("ev", SWD.make_key(10, 2, 2, 5), 0)]
    ev = TRC._swd_fold(s, items, 0, 168000000, {})[0]
    check("A1 id=2/arg=5 解出 from=2 to=5（旧代码这条根本没有 from/to）",
          ev.get("type") == "sched" and ev.get("from") == 2 and ev.get("to") == 5, ev)
    s = {"rel_cycles": 0, "events_seen": 0, "faults": []}
    items = [("ev", SWD.make_key(10, 2, 0, 1), 0)]
    ev = TRC._swd_fold(s, items, 0, 168000000, {})[0]
    check("A2 id=0/arg=1 仍解出 0->1（老行为不回归）",
          ev.get("from") == 0 and ev.get("to") == 1, ev)
    s = {"rel_cycles": 0, "events_seen": 0, "faults": []}
    items = [("ev", SWD.make_key(10, 2, 0x1F, 0x40), 0)]
    ev = TRC._swd_fold(s, items, 0, 168000000, {})[0]
    check("A3 from/to 超出 0..15 时显式告警（不静默乱解）",
          bool(ev.get("warn")) and ev.get("from") == 0x1F, ev)

    print("== B 任务名 ==", flush=True)
    lk, hits, undo = scenario(SCHED_EV)
    try:
        out = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=50)
        evs = [e for e in out["events"] if e.get("type") == "sched"]
        check("B1 调度事件带上真实任务名",
              evs and evs[0].get("from_name") == "drv_poll"
              and evs[0].get("to_name") == "app_main",
              [(e.get("from"), e.get("from_name"), e.get("to"), e.get("to_name"))
               for e in evs])
        tn = out.get("task_names") or {}
        check("B2 task_names 摘要给出名字表",
              tn.get("ok") is True and tn.get("names", {}).get("1") == "bled_task", tn)
        check("B3 sched_decoded 报出本批命名情况",
              (out.get("sched_decoded") or {}).get("sched_events") == 2
              and (out.get("sched_decoded") or {}).get("with_names") == 2,
              out.get("sched_decoded"))
    finally:
        undo()

    # idle（0xF）要叫 idle，而且不因为表里没这一项就丢掉
    lk, hits, undo = scenario(SCHED_EV + [(SWD.make_key(10, 2, 15, 0), 0)])
    try:
        out = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=50)
        last = [e for e in out["events"] if e.get("type") == "sched"][-1]
        check("B4 from=0xF 说到 idle 上（idle 不是任务表里的任务）",
              last.get("from_name") == "idle" and last.get("to_name") == "app_main",
              last)
    finally:
        undo()

    # arg 是任务号的事件（WAIT/READY）
    lk, hits, undo = scenario([(SWD.make_key(2, 2, 0x11, 1), 0),
                              (SWD.make_key(2, 2, 0x12, 3), 0)])
    try:
        out = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=50)
        evs = [e for e in out["events"] if e.get("type") == "event"]
        check("B5 WAIT(0x11)/READY(0x12) 的 arg 也解出任务名",
              [e.get("task_name") for e in evs] == ["bled_task", "shell_task"], evs)
    finally:
        undo()

    print("== C 名字后到：历史事件回头重补 ==", flush=True)
    lk, hits, undo = scenario(SCHED_EV)
    try:
        o1 = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, tasks="off", limit=50)
        e1 = [e for e in o1["events"] if e.get("type") == "sched"][0]
        check("C1 tasks=off 时不给名字，也不读任务表",
              "from_name" not in e1 and not hits, (e1, hits))
        check("C2 tasks=off 时不碰任务表（不发读请求）", hits == [], hits)
        o2 = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, tasks="auto", limit=50)
        e2 = [e for e in o2["events"] if e.get("type") == "sched"]
        check("C3 事后解析出名字时，**历史事件也补上**（否则前半段还是数字）",
              all(e.get("from_name") for e in e2), e2)
    finally:
        undo()

    print("== C4 首读是脏帧：停机重读一次 ==", flush=True)
    # 真机踩到的坑：停机后紧跟的第一次读可能整段读回 0（伪值）。只读一次就把
    # 「没有名字」缓存一整个会话是白丢信息——重读一次（并停机），第二次好就用。
    lk, hits, undo = scenario(SCHED_EV)
    real_read = TRC._read_mem_words
    state = {"n": 0}
    def flaky(addr, n, link="auto", raw=False, **kw):
        if TBL <= int(addr) < TBL + 15 * TCB_SIZE:
            state["n"] += 1
            if state["n"] == 1:
                return b"\x00" * int(n), {"link": "keil", "read_mode": "single",
                                          "degenerate": "all_zero"}
        return real_read(addr, n, link=link, raw=raw, **kw)
    TRC._read_mem_words = flaky
    try:
        r = TRC._svcrt_task_names(elf=WITH_ELF, link="keil")
        check("C4 首读伪值 -> 自动重读一次，第二次好就照样给名字",
              r.get("ok") is True and r.get("names", {}).get(0) == "app_main"
              and state["n"] == 2, (r.get("error_code"), state["n"]))
        check("C4b 重读时停了机、读完放回运行态",
              lk.halt_calls >= 1 and lk.resume_calls >= 1 and lk.running is True,
              (lk.halt_calls, lk.resume_calls, lk.running))
    finally:
        TRC._read_mem_words = real_read
        undo()

    print("== D 解析失败：明确错误码，不编名字 ==", flush=True)
    lk, hits, undo = scenario(SCHED_EV)
    try:
        r = TRC._svcrt_task_names(elf="")
        check("D1 没有 elf → tasks-need-elf",
              r.get("ok") is False and r.get("error_code") == "tasks-need-elf", r)
        keep = L.pick
        L.pick = lambda link="auto", who="": (
                None, {"ok": False, "reason": "bad-link-name",
                       "error": "link 只能是 auto / keil / ocd（收到 %r）"
                                % (link,)})
        try:
            r = TRC._svcrt_task_names(elf=WITH_ELF, link="nope-not-a-link")
        finally:
            L.pick = keep
        check("D2 取不到链路 → tasks-link-failed/明确报错",
              r.get("ok") is False
              and str(r.get("error_code", "")).startswith("tasks-"), r)
    finally:
        undo()

    def _one(idx_kw, expect, tbl=None):
        lk, hits, undo = scenario(SCHED_EV, table_bytes=tbl, **idx_kw)
        try:
            out = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=50)
            tn = out.get("task_names") or {}
            ok = out.get("ok") is True and tn.get("ok") is False \
                and tn.get("error_code") == expect
            check("D3 %s → %s（read 仍可用，只是没有名字）" % (expect, expect), ok, tn)
            evs = [e for e in out["events"] if e.get("type") == "sched"]
            check("D3' %s 时事件里**不出现**任何名字" % expect,
                  all("from_name" not in e for e in evs), evs[0] if evs else None)
        finally:
            undo()

    _one({"no_table": True}, "tasks-table-missing")
    _one({"no_layout": True}, "tasks-layout-missing")
    # 伪值：整张表读回重复的同一个字
    _one({}, "tasks-read-untrusted",
         tbl=bytes([0x32, 0xC6, 0xB2, 0x07]) * (15 * TCB_SIZE // 4))
    # 一个名字都给不出来：所有非空入口都落不到符号表上 → 整批拒绝
    bad = task_table_bytes({0: 0xDEADBEEF, 1: 0x20001234})
    _one({}, "tasks-snapshot-inconsistent", tbl=bad)

    print("== D4 跨镜像入口：留空不编名 ==", flush=True)
    # 真机上 SVCrtOS 的 app 是另外下发的镜像，它的任务入口不在这份内核 .axf 的符号表里
    # （F427 实测：0=led_blink_task / 1=led2_blink_task / 2=svcrt_timer_daemon
    #  / 5=svcrt_shell_task 能命名；3、4、6 落在 0x08040xxx~0x08043xxx 一带 → 无名且不编）。
    mixed = task_table_bytes({0: 0x08000101, 1: 0x08000201, 2: 0x08000301,
                              3: 0x08040301, 4: 0x08000401})
    lk, hits, undo = scenario(SCHED_EV, table_bytes=mixed)
    try:
        out = TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=50)
        tn = out.get("task_names") or {}
        check("D4 有名字的给名字、跨镜像的留空（不编 sub_XXXX）",
              out.get("ok") is True and tn.get("ok") is True
              and tn.get("names", {}).get("0") == "app_main"
              and tn.get("names", {}).get("3") is None
              and tn.get("partial") is True
              and tn.get("unmapped_slots") == [3], tn)
    finally:
        undo()

    # 入口落在函数中间（不是首地址）时也不硬安名字：拿
    # 「最近的下方符号」会给出一个看着合理却错的名字。
    mid = task_table_bytes({0: 0x08000101, 1: 0x08000191})
    lk, hits, undo = scenario(SCHED_EV, table_bytes=mid)
    try:
        r = TRC._svcrt_task_names(elf=WITH_ELF, link="keil")
        check("D4b 入口不在函数首地址 -> 不拿最近的下方符号顶",
              r.get("ok") is True and r.get("names", {}).get(0) == "app_main"
              and r.get("names", {}).get(1) is None
              and r.get("unmapped_slots") == [1], r)
    finally:
        undo()

    print("== E 会话内只解析一次 ==", flush=True)
    lk, hits, undo = scenario(SCHED_EV)
    try:
        TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=10)
        n1 = len(hits)
        TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=10)
        check("E1 第二次 read 不再读任务表（一次会话取一次）",
              n1 == 1 and len(hits) == 1, (n1, len(hits)))
        TRC.swd_read(elf=WITH_ELF, addr=BLOB_ADDR, limit=10, reset_session=True)
        check("E2 reset_session 后重新解析（换了固件/axf 就该重取）",
              len(hits) == 2, hits)
    finally:
        undo()

    print("== F 真实 .axf 的 DWARF 路径（无目标） ==", flush=True)
    AXF = (r"D:\工作\git_project\svcrtos_new\example\stm32f427\kernel"
           r"\SVCRTOS_TEST\MDK-ARM\SVCRTOS_TEST\SVCRTOS_TEST.axf")
    if not os.path.isfile(AXF):
        skip("F1/F2 真实 axf", "本机没有 SVCrtOS 的 .axf（跳过，不算失败）")
    else:
        ix = RTOS.ElfIndex(AXF)
        check("F1 匿名 typedef 结构体的布局能取到（svcrt_task_t）",
              (ix.struct("svcrt_task_t") or {}).get("size") == TCB_SIZE
              and ix.field("svcrt_task_t", "entry") == ENTRY_OFF,
              (ix.struct("svcrt_task_t") or {}).get("size"),
              )
        vk = ix.var_kind(TRC._SVCRT_TABLE_SYM) or {}
        check("F2 任务表符号与元素个数都能取到",
              ix.addr_of(TRC._SVCRT_TABLE_SYM) and (vk.get("count") or 0) >= 15, vk)

    print("== H 多份镜像（内核;app）联合取名 ==", flush=True)
    h = tempfile.mkstemp(suffix="_k.axf")
    os.close(h[0])
    h2 = tempfile.mkstemp(suffix="_a.axf")
    os.close(h2[0])
    K, AP = h[1], h2[1]
    KFUNCS = [(0x08000200, "bled_task")]
    AFUNCS = [(0x08000400, "app_task_entry")]
    # 跨镜像名字要过内容核对（板上机器码 == .axf 同地址字节），两边都给一份可比的
    KCODE = {0x08000200: bytes(range(0x10, 0x20))}
    ACODE = {0x08000400: bytes(range(0x20, 0x30))}
    ENTRY2 = {0: 0x08000201, 1: 0x08000401}          # 0=内核任务 1=app 任务
    old_i, old_f = RTOS.get_index, TRC._elf_funcs_cached
    _, hh, undo = scenario(SCHED_EV)          # 先跑夹具，再把镜像映射换成两份
    _ = hh
    try:
        tb = task_table_bytes(ENTRY2, n_slots=15)
        both_code = dict(KCODE)
        both_code.update(ACODE)
        hits2, undo_r = patch_read_mem(tb, code=both_code)
        RTOS.get_index = lambda p: (FakeIndex(code=KCODE) if p == K
                                    else FakeIndex(code=ACODE, no_table=True))
        TRC._elf_funcs_cached = lambda p: list(KFUNCS if p == K else AFUNCS)
        try:
                r1 = TRC._svcrt_task_names(elf=K)
                check("H1 只给内核 .axf：app 任务的槽位保持无名（不编）",
                      r1.get("ok") and r1["names"] == {0: "bled_task"}
                      and r1.get("unmapped_slots") == [1],
                      {k: r1.get(k) for k in ("names", "unmapped_slots", "error")})
                r2 = TRC._svcrt_task_names(elf="%s;%s" % (K, AP))
                check("H2 给了两份：app 任务也带上了名字（入口落在 app 符号上）",
                      r2.get("ok") and r2["names"] == {0: "bled_task", 1: "app_task_entry"},
                      {k: r2.get(k) for k in ("names", "error")}) 
                check("H3 名字标明来自哪份镜像（sym_from 只在自己不是第一份时给）",
                      (r2["tasks"][1] or {}).get("sym_from") == os.path.basename(AP)
                      and "sym_from" not in r2["tasks"][0],
                      (r2["tasks"][0], r2["tasks"][1]))
                check("H4 elfs 字段列出全部符号来源，elf 仍是第一份",
                      len(r2.get("elfs") or []) == 2 and r2["elf"] == os.path.abspath(K),
                      (r2.get("elf"), r2.get("elfs")))
                check("H5 单份时不多出 sym_from（老行为不变）",
                      "sym_from" not in r1["tasks"][0], r1["tasks"][0])
                check("H5b 核过的跨镜像名字标出 content-confirmed",
                      r2["tasks"][1].get("sym_verified") == "content-confirmed",
                      r2["tasks"][1])
                # 核对不过就丢名：地址精确匹配只证明「那个地址在这份 .axf 里是
                # 函数首地址」，不证明板上跑的就是这份构建。
                bad = dict(KCODE)
                bad[0x08000400] = bytes(range(0x30, 0x40))
                _, undo_b = patch_read_mem(tb, code=bad)
                try:
                    r5 = TRC._svcrt_task_names(elf="%s;%s" % (K, AP))
                    check("H8 跨镜像名字对不上机器码 -> 丢名记 unconfirmed（不硬安）",
                          r5.get("ok") and r5["names"] == {0: "bled_task"}
                          and (r5.get("unconfirmed_slots") or [{}])[0].get("name")
                          == "app_task_entry"
                          and r5.get("partial") is True,
                          {k: r5.get(k) for k in ("names", "unconfirmed_slots", "partial")})
                finally:
                    undo_b()
                # 核不了（.axf 里取不到该地址字节）也不等于核过——一样不给名字。
                RTOS.get_index = lambda p: (FakeIndex(code=KCODE) if p == K
                                            else FakeIndex(code={}, no_table=True))
                r6 = TRC._svcrt_task_names(elf="%s;%s" % (K, AP))
                check("H9 核不了（.axf 取不到字节）也不给名字",
                      r6.get("ok") and r6["names"] == {0: "bled_task"}
                      and r6.get("unconfirmed_slots"),
                      {k: r6.get(k) for k in ("names", "unconfirmed_slots")})
                RTOS.get_index = lambda p: (FakeIndex(code=KCODE) if p == K
                                            else FakeIndex(code=ACODE, no_table=True))
        finally:
            RTOS.get_index, TRC._elf_funcs_cached = old_i, old_f
            undo_r()
            undo()
        r3 = TRC._svcrt_task_names(elf="%s;%s" % (K, "/tmp/does-not-exist-64.axf"))
        check("H6 点了不存在的镜像就报 tasks-elf-missing（不默默少给名字）",
              r3.get("error_code") == "tasks-elf-missing" and "does-not-exist-64" in str(r3.get("error")),
              r3)
        RTOS.get_index = lambda p: FakeIndex(no_table=True)
        r4 = TRC._svcrt_task_names(elf="%s;%s" % (K, AP))
        check("H7 两份都没有任务表 -> 报第一份的原因（tasks-table-missing）",
              r4.get("error_code") == "tasks-table-missing", r4)
    finally:
        RTOS.get_index, TRC._elf_funcs_cached = old_i, old_f
        for p in (K, AP):
            try:
                os.unlink(p)
            except OSError:
                pass
        TRC._T["swd"] = None

    print("== I 粒度比事件密：时间轴冻结要报出来 ==", flush=True)
    # 真机上就是这么撞的：500 µs 粒度 + 约 6700 事件/s，目标按「与上一条的差 ÷ 粒度」
    # 算 dt 并丢掉余数，于是每条都算 0，宿主累加出来的时间轴**冻在原点**。
    # 页面当时照样画出了一条平平的「时间轴」，看着像模像样——这类必须有话说。
    evs_flat = [(SWD.make_key(10, 2, i % 8, (i + 1) % 8), 0) for i in range(300)]
    lk, hits, undo = scenario(evs_flat, flags=SWD.FLAG_ENABLED)
    try:
        out = TRC.swd_read(elf="", addr=BLOB_ADDR, limit=10)
        check("I1 dt 全是 0（粒度比事件密）-> 报 time_axis_frozen，不装看不见",
              out.get("ok") and (out.get("time_axis_frozen") or {}).get("events"),
              {k: out.get(k) for k in ("ok", "error", "time_axis_frozen")})
        check("I2 警告里说清是「冻」的、并指向换细粒度重录",
              any("冻" in str(w) for w in out.get("warnings") or [])
              and any("granularity" in str(w) for w in out.get("warnings") or []),
              out.get("warnings"))
        check("I3 事件顺序仍然照常给（冻结的是时间，不是解码）",
              len(out.get("events") or []) == 10, len(out.get("events") or []))
    finally:
        undo()

    print("== J events 口径：会话尾部 vs 本批新增 ==", flush=True)
    # 真机上就是这么录错的：events.extend(out["events"]) 看上去条数很壮观，
    # 其实是 N 个互相重叠的窗口——同一段时间被数了很多遍。
    evs_j = [(SWD.make_key(10, 2, 0, 1), 0) for _ in range(300)]
    # 复用同一个编码器对象：scenario 里是同一串事件、同一个确定性编码器，
    # 所以下面 append() 接上去的那一段与环里已有的那段字典是连续的（HIT 才解得对）。
    enc_j = SWD.Encoder()
    enc_j.sync(1) + enc_j.encode(evs_j)
    lk, hits, undo = scenario(evs_j, flags=SWD.FLAG_ENABLED)
    try:
        o1 = TRC.swd_read(elf="", addr=BLOB_ADDR, limit=10)
        check("J1 默认口径：events 是会话尾部（被 limit 截到 10），new_events 报本批新增",
              o1.get("new_events") >= 300 and len(o1.get("events") or []) == 10
              and o1.get("events_scope") == "session",
              {k: o1.get(k) for k in ("new_events", "events_scope", "truncated")})

        def append(evs_n):
            """在同一个编码器状态上再接一段流（字典连续），并把环指针推过去。"""
            chunk = enc_j.encode([(SWD.make_key(10, 2, 2, 5), 0)] * evs_n)
            head = struct.unpack_from("<I", lk.ctrl, SWD.OFF_HEAD)[0]
            lk.ring[head:head + len(chunk)] = chunk
            n_ev = struct.unpack_from("<I", lk.ctrl, SWD.OFF_EVENTS)[0] + evs_n
            n_tk = struct.unpack_from("<I", lk.ctrl, SWD.OFF_TOKENS)[0] + evs_n
            struct.pack_into("<I", lk.ctrl, SWD.OFF_HEAD, head + len(chunk))
            struct.pack_into("<I", lk.ctrl, SWD.OFF_EVENTS, n_ev)
            struct.pack_into("<I", lk.ctrl, SWD.OFF_TOKENS, n_tk)

        append(7)
        o2 = TRC.swd_read(elf="", addr=BLOB_ADDR, limit=100)
        check("J2 默认口径下第二次仍给会话尾部：100 条里只有 7 条是新的（重叠陷阱）",
              o2.get("new_events") == 7 and len(o2.get("events") or []) == 100,
              {k: o2.get(k) for k in ("new_events", "events_scope")}
              | {"len(events)": len(o2.get("events") or [])})
        append(5)
        o3 = TRC.swd_read(elf="", addr=BLOB_ADDR, limit=100, only_new=True)
        check("J3 only_new=true：只给本批新增的那 5 条，拼线性轨迹才是对的",
              o3.get("new_events") == 5 and len(o3.get("events") or []) == 5
              and o3.get("events_scope") == "new",
              {k: o3.get(k) for k in ("new_events", "events_scope")}
              | {"len(events)": len(o3.get("events") or [])})
    finally:
        undo()

    print("== G 工具面 ==", flush=True)
    import asyncio
    from mdkdebug import server as SV
    srv = SV.create_server(port=4899, toolsets="all")
    tools = asyncio.run(srv.list_tools())
    names = [t.name for t in tools]
    check("G1 trace_swd_tasks 已注册", "trace_swd_tasks" in names, len(names))
    t_read = [t for t in tools if t.name == "trace_swd_read"][0]
    _props = t_read.input_schema.get("properties") or {}
    check("G2 trace_swd_read 多了 tasks 参数", "tasks" in _props, list(_props))
    check("G3 trace_swd_read 多了 only_new 参数", "only_new" in _props, list(_props))

    print()
    print("通过 %d，失败 %d，跳过 %d" % (len(PASS), len(FAIL), len(SKIP)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0

WITH_ELF = None

if __name__ == "__main__":
    # _svcrt_task_names 要求 elf 是个真实文件；造一个空壳当「符号文件已指定」。
    fd, WITH_ELF = tempfile.mkstemp(suffix=".axf")
    os.close(fd)
    try:
        sys.exit(main())
    finally:
        try:
            os.unlink(WITH_ELF)
        except OSError:
            pass
