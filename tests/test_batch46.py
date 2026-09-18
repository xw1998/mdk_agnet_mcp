# -*- coding: utf-8 -*-
"""批次46 mock 测试：复位循环 / 启动失败自动识别（watch_reset）。

来源：用户缺口表「复位循环/启动失败自动检测——wait_fault 抓单次异常，
没有『每 N ms 复位一次』这类复位循环模式的自动识别」。

判据是 Cortex-M 的 DHCSR.S_RESET_ST：**读即清**的标准位，自上次读之后复位过
则置位。于是「按固定间隔读 DHCSR」= 「按固定间隔问『这段时间复位过吗』」——
不需要目标已停，也不需要地址或符号，跨芯片通用。

  A 纯逻辑：DHCSR 解码 / 模式判定（none·single·repeat·periodic·irregular·too_fast）
     / advice / 分组与注解
  B 工具层：读不到就报错、无复位、周期复位、快过采样、max_resets 提前收工、
     sample_pc 的落点与副作用披露、读失败提前收工、链路名非法、参数越界
  C 真实时钟：真 sleep 路径可用

运行：python -m tests.test_batch46
"""
import os
import sys
import struct
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A      # noqa: E402
from mdkdebug import linkio as L        # noqa: E402
from mdkdebug import resetwatch as R    # noqa: E402
from mdkdebug import server as S        # noqa: E402
from mdkdebug import toolbox as TB      # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def _dhcsr(reset=False, lockup=False, halt=False, sleep=False):
    v = 0
    if reset:
        v |= R.S_RESET_ST
    if lockup:
        v |= R.S_LOCKUP
    if halt:
        v |= R.S_HALT
    if sleep:
        v |= R.S_SLEEP
    return struct.pack("<I", v)


# ======================================================================
# 夹具
# ======================================================================
class Clock:
    """假时钟：让「间隔」可精确断言，不靠真实调度抖动。"""

    def __init__(self, t=1000.0):
        self.t = float(t)

    def monotonic(self):
        return self.t


class FakeLink(L.Link):
    """seq 按「第几次读」依次取用，用完后一直取最后一帧；None 表示这次读失败。"""

    name = "fake"
    label = "假链路"

    def __init__(self, seq, pc=0x08001234, flags=None):
        self.seq = list(seq)
        self.i = 0
        self.pc = pc
        # flags 给了就按地址分流：DHCSR 走 seq，其余地址（复位标志寄存器）走 flags
        self.flags = list(flags) if flags is not None else None
        self.fi = 0
        self.halt_calls = 0
        self.resume_calls = 0
        self.reads = 0

    def _next(self):
        if not self.seq:
            return b"\x00\x00\x00\x00"
        v = self.seq[self.i] if self.i < len(self.seq) else self.seq[-1]
        self.i += 1
        return v

    def read_once(self, addr, n):
        self.reads += 1
        if self.flags is not None and int(addr) != R.DHCSR:
            v = (self.flags[self.fi] if self.fi < len(self.flags)
                 else self.flags[-1])
            self.fi += 1
            if v is None:
                return None, {"link": self.name, "error": "复位标志寄存器读失败(mock)"}
            return v, {"link": self.name, "read_mode": "single"}
        v = self._next()
        if v is None:
            return None, {"link": self.name, "error": "DHCSR 读失败(mock)"}
        return v, {"link": self.name, "read_mode": "single"}

    def read(self, addr, n):
        return self.read_once(addr, n)

    def halt(self):
        self.halt_calls += 1
        return {"ok": True, "link": self.name}

    def resume(self):
        self.resume_calls += 1
        return {"ok": True, "link": self.name}

    def regs(self, names=("pc",)):
        return {"ok": True, "link": self.name, "pc": self.pc}


_SRV = None


def call(name, **args):
    import asyncio
    import json
    global _SRV
    if _SRV is None:
        _SRV = S.create_server()
    res = asyncio.run(_SRV.call_tool(name, args))
    return json.loads("".join(getattr(c, "text", "") or "" for c in res.content))


def patch(link, clock=None):
    """把链路与（可选的）时钟/sleep 换掉，返回还原函数。"""
    saved = (L.pick, R.time, R.asyncio)
    _lk = link
    L.pick = lambda link="auto", who="": (_lk, None)
    if clock is not None:
        async def _sleep(sec):
            clock.t += float(sec)
        R.time = types.SimpleNamespace(monotonic=clock.monotonic)
        R.asyncio = types.SimpleNamespace(sleep=_sleep)

    def restore():
        L.pick, R.time, R.asyncio = saved
    return restore


# ======================================================================
# A 纯逻辑
# ======================================================================
def section_a():
    print("\n-- A 纯逻辑：DHCSR 解码 / 模式判定 / 建议 --")

    d = R.decode_dhcsr(R.S_RESET_ST | R.S_LOCKUP | 0x1)
    check("A1 decode_dhcsr 拆出命名位（读即清位与锁死位都要认得）",
          d["s_reset_st"] and d["s_lockup"] and not d["s_halt"]
          and d["raw"] == "0x02080001", d)

    check("A2 没有间隔样本时不编数（count=0，不给中位数）",
          R.interval_stats([]) == {"count": 0}, R.interval_stats([]))

    st = R.interval_stats([500.0, 498.0, 502.0])
    check("A3 间隔统计给出中位数与抖动比值",
          st["count"] == 3 and st["median_ms"] == 500.0 and st["min_ms"] == 498.0
          and st["max_ms"] == 502.0 and st["max_min_ratio"] == round(502.0 / 498.0, 3),
          st)

    c = R.classify(0, [], 0)
    check("A4 一次都没读成功 → no-data（不是 none）", c["pattern"] == "no-data", c)

    c = R.classify(0, [], 20)
    check("A5 窗口内无复位 → none",
          c["pattern"] == "none" and "没有检测到复位" in c["verdict"], c)

    c = R.classify(4, [], 20, too_fast=True)
    check("A6 复位快过采样间隔 → too_fast，且明说测不出间隔",
          c["pattern"] == "too_fast" and "测不出间隔" in c["verdict"], c)

    c = R.classify(1, [], 20)
    check("A7 单次复位 → single，不硬说成循环",
          c["pattern"] == "single" and "不足以判定" in c["verdict"], c)

    c = R.classify(2, [300.0], 20)
    check("A8 两次复位 → repeat（间隔样本只有 1 个，不断言稳定周期）",
          c["pattern"] == "repeat" and "repeat" == c["pattern"], c)

    c = R.classify(4, [500.0, 498.0, 502.0], 40)
    check("A9 间隔稳定 → periodic 并给出中位数",
          c["pattern"] == "periodic" and c["interval_stats"]["median_ms"] == 500.0
          and "复位循环" in c["verdict"], c)

    c = R.classify(4, [100.0, 900.0, 200.0], 40)
    check("A10 间隔乱 → irregular（不硬套看门狗周期）",
          c["pattern"] == "irregular" and "忽长忽短" in c["verdict"], c)

    ad = R.advice("periodic", {"lockup": 0})
    check("A11 有复位时给可执行的下一步（冻看门狗 / fault_report / wait_fault）",
          any("watchdog_freeze" in x for x in ad)
          and any("fault_report" in x for x in ad)
          and any("wait_fault" in x for x in ad), ad)

    ad = R.advice("periodic", {"lockup": 2})
    check("A12 LOCKUP 置位时单独点名（比普通复位更硬的证据）",
          any("S_LOCKUP" in x and "2" in x for x in ad), ad)

    ad = R.advice("none", {})
    check("A13 没复位时不推看门狗那套，改为提示窗口/目标在不在跑",
          not any("watchdog_freeze" in x for x in ad)
          and any("窗口" in x for x in ad), ad)

    rep = R.build_report(link_name="fake", duration_ms=100, interval_ms=10,
                         samples=5, read_fail=0, reset_count=2,
                         resets=[{"at_ms": 10.0}], flags={"lockup": 0},
                         intervals_ms=[20.0], too_fast=False)
    check("A14 build_report 字段齐全且交代时间戳来源",
          rep["pattern"] == "repeat" and rep["reset_count"] == 2
          and rep["action"] == "watch_reset" and "主机侧时间戳" in rep["note"], rep)

    check("A15 watch_reset 归入 advanced 组（不是 core——默认不外露）",
          "watch_reset" in TB.TOOLSETS.get("advanced", set())
          and "watch_reset" not in TB.TOOLSETS.get("core", set()), None)

    c = R.classify(0, [], 20, flags_signal=True)
    check("A17 标志寄存器有置起而 DHCSR 没抓到 → flags-only，并明说是前者漏报",
          c["pattern"] == "flags-only" and "漏报" in c["verdict"], c)

    c = R.classify(0, [], 20)
    check("A18 none 的结论里带上「读即清可能漏报」与交叉验证的提示",
          "漏报" in c["verdict"] and "flags_addr" in c["verdict"], c)

    ad = R.advice("none", {})
    check("A19 advice 指向 flags_addr 做交叉验证",
          any("flags_addr" in x for x in ad), ad)

    ad = R.advice("flags-only", {})
    check("A20 flags-only 时指向 set_bits 与芯片手册，并解释漏报成因",
          any("set_bits" in x for x in ad) and any("重同步" in x for x in ad), ad)

    rep2 = R.build_report(link_name="fake", duration_ms=100, interval_ms=10,
                          samples=5, read_fail=0, reset_count=0, resets=[],
                          flags={}, intervals_ms=[], too_fast=False,
                          reset_flags={"addr": "0x40023874",
                                       "changed_bits": [28], "set_bits": [28]})
    check("A21 build_report 收到标志置起就把 pattern 改成 flags-only 并透出 reset_flags",
          rep2["pattern"] == "flags-only" and rep2["reset_flags"]["set_bits"] == [28],
          rep2)

    an = A.annotations_for("watch_reset")
    check("A16 标只读（默认只读 DHCSR；sample_pc 的短暂停与 wait_breakpoint 同口径）",
          an["readOnlyHint"] is True and an["destructiveHint"] is False, an)
    check("A16b 不许标成可并发/幂等之外的错值（非破坏性）",
          an["openWorldHint"] is False, an)


# ======================================================================
# B 工具层
# ======================================================================
def section_b():
    print("\n-- B 工具层：读不到 / 无复位 / 周期 / 过快 / 提前收工 / sample_pc --")

    fake = FakeLink([None])
    restore = patch(fake)
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50)
    finally:
        restore()
    check("B1 DHCSR 读不到 → 直接报错，并明说别据此认为「目标没复位」",
          r.get("ok") is False and r.get("reason") == "dhcsr-unreadable"
          and "不要据此认为" in (r.get("hint") or ""), r)

    fake = FakeLink([_dhcsr()] * 30)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50)
    finally:
        restore()
    check("B2 窗口内无复位 → none，且给出采样数（不凭一次读下结论）",
          r.get("ok") and r.get("pattern") == "none" and r.get("reset_count") == 0
          and r.get("samples") >= 3, r)
    check("B3 没开 sample_pc 就不返回 pc_samples/halt_info（不虚报副作用）",
          "pc_samples" not in r and "halt_info" not in r, r)

    # 尾部补几个「不复位」帧：窗口末次采样可能落在边界上多采一次，
    # 那里若恰好是复位帧会多出一个被窗口截断的短间隔，干扰周期性判定。
    seq = ([_dhcsr()]
           + ([_dhcsr(), _dhcsr(), _dhcsr(), _dhcsr(), _dhcsr(reset=True)] * 4)
           + [_dhcsr()] * 3)
    fake = FakeLink(seq, pc=0x08001234)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=1000, interval_ms=50)
    finally:
        restore()
    check("B4 间隔稳定的复位 → periodic，4 次复位间隔都是 250ms",
          r.get("pattern") == "periodic" and r.get("reset_count") == 4
          and (r.get("interval_stats") or {}).get("median_ms") == 250.0, r)
    check("B5 第一次复位不给 since_prev_ms（不编间隔），后续给真间隔",
          "since_prev_ms" not in r["resets"][0]
          and r["resets"][1].get("since_prev_ms") == 250.0, r.get("resets"))

    fake = FakeLink([_dhcsr()] + [_dhcsr(reset=True)] * 12)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=300, interval_ms=50)
    finally:
        restore()
    check("B6 每次采样都见复位 → too_fast，结论里明说测不出间隔",
          r.get("pattern") == "too_fast" and "测不出间隔" in (r.get("verdict") or ""), r)

    fake = FakeLink([_dhcsr()] + [_dhcsr(reset=True)] * 30)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=1000, interval_ms=50, max_resets=2)
    finally:
        restore()
    check("B7 达到 max_resets 提前收工，并如实说明「实际可能更多」",
          r.get("reset_count") == 2 and "stopped_early" in r
          and "可能更多" in (r.get("stopped_early") or ""), r)

    seq = [_dhcsr()] + ([_dhcsr(), _dhcsr(reset=True)] * 6)
    fake = FakeLink(seq, pc=0x08001234)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=300, interval_ms=50,
                 sample_pc=True, settle_ms=20)
    finally:
        restore()
    ok_pc = (r.get("pc_samples") and len(r["pc_samples"]) >= 2
             and all(p.get("pc") == "0x08001234" for p in r["pc_samples"]))
    check("B8 sample_pc=true → 每次复位后停一下读落点",
          bool(ok_pc), r.get("pc_samples"))
    check("B9 sample_pc 的停/走都如实计数，且每次都恢复了运行",
          (r.get("halt_info") or {}).get("rounds") == len(r.get("pc_samples") or [])
          and (r.get("halt_info") or {}).get("resumed") == len(r.get("pc_samples") or [])
          and fake.halt_calls == len(r.get("pc_samples") or [])
          and fake.resume_calls == len(r.get("pc_samples") or []), r.get("halt_info"))

    fake = FakeLink([_dhcsr()] + [_dhcsr(), None, None, None])
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=500, interval_ms=50)
    finally:
        restore()
    check("B10 连续读失败 → 提前收工，且明说漏掉多少次「说不准」",
          r.get("read_fail") >= 3 and "说不准" in (r.get("warning") or ""), r)

    fake = FakeLink([_dhcsr()] * 300)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=1, interval_ms=1, max_resets=0)
    finally:
        restore()
    check("B11 duration/interval 越界被夹到合法下界（不静默接受非法值）",
          r.get("duration_ms") >= 200 and r.get("interval_ms") >= 20, r)

    fake = FakeLink([_dhcsr()] * 40,
                    flags=[b"\x00\x00\x00\x00", b"\x00\x00\x00\x00"])
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50,
                 flags_addr="0x40023874")
    finally:
        restore()
    check("B13 给了 flags_addr：窗口前后各读一次，无变化时 set_bits 为空",
          (r.get("reset_flags") or {}).get("addr") == "0x40023874"
          and (r.get("reset_flags") or {}).get("set_bits") == []
          and r.get("pattern") == "none", r.get("reset_flags"))

    fake = FakeLink([_dhcsr()] * 40,
                    flags=[b"\x00\x00\x00\x00",
                           struct.pack("<I", 1 << 28)])
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50,
                 flags_addr="0x40023874")
    finally:
        restore()
    check("B14 标志位在窗口内被置起而 DHCSR 没抓到 → flags-only",
          r.get("pattern") == "flags-only"
          and (r.get("reset_flags") or {}).get("set_bits") == [28]
          and "漏报" in (r.get("verdict") or ""), r)

    fake = FakeLink([_dhcsr()] * 40)
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50, flags_addr="abc")
    finally:
        restore()
    check("B15 flags_addr 不是地址 → invalid-argument（不猜一个地址去读）",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)

    fake = FakeLink([_dhcsr()] * 40, flags=[None])
    restore = patch(fake, Clock())
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50,
                 flags_addr="0x40023874")
    finally:
        restore()
    check("B16 标志寄存器读不回 → 明确报错，并说明留空可跳过（不假装没证据）",
          r.get("ok") is False and r.get("reason") == "flags-unreadable"
          and "留空" in (r.get("hint") or ""), r)

    r = call("watch_reset", link="bogus")
    check("B12 链路名拼错 → 报错（不静默退化成 auto 去读另一个目标）",
          r.get("ok") is False and r.get("reason") == "bad-link-name", r)


# ======================================================================
# C 真实时钟
# ======================================================================
def section_c():
    print("\n-- C 真实时钟：真 asyncio.sleep 路径 --")
    fake = FakeLink([_dhcsr()] * 100)
    restore = patch(fake)
    try:
        r = call("watch_reset", duration_ms=200, interval_ms=50)
    finally:
        restore()
    check("C1 真 sleep 路径可用（约 200ms 窗口，采样 >=3 次）",
          r.get("ok") and r.get("pattern") == "none" and r.get("samples") >= 3, r)

    fake = FakeLink([_dhcsr()] * 100, flags=[b"\x00\x00\x00\x00"])
    restore = patch(fake)
    try:
        r2 = call("watch_reset", duration_ms=200, interval_ms=50)
    finally:
        restore()
    check("C2 没给 flags_addr 就不返回 reset_flags（不虚报交叉证据）",
          r2.get("ok") and "reset_flags" not in r2, r2)


def main():
    section_a()
    section_b()
    section_c()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for n in FAIL:
            print("  - %s" % n)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
