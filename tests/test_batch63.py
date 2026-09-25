# -*- coding: utf-8 -*-
"""批次63 mock 测试：SWD 无缝流「搬得可信」——停机一致性搬运 + 伪值当场报错。

背景（真机实测，STM32F427 + DAPLink + Keil UVSOCK@4823）：
目标**全速运行时**经 SWD 读 SRAM 的某些区段（实测 ≥ 0x20004000，以及外设区）会
整段重复同一个 4 字节字——既不是全 0 也不是全 FF，旧退化检测认不出来，伪值于是被
当正常字节流解码，结果是 swd-stream-desync + 游标不再推进 + 环填满 → 丢失
几十万事件，而现场看起来像「目标自己丢了数据」。停机读同一段则与目标 tokens
计数逐字节吻合。

  A 伪值签名：repeated_word 认得出；短读 / 同值字节流不误判（两层实现一致）
  B consistent=halt（默认）：停机 → 就地重读控制块 → 搬 → 写游标 → resume
  C consistent=run：伪值直接报 swd-read-untrusted，不解码、不推进游标
  D consistent=auto：全速发现伪值 → 自动停机重读 → 成功，并把这次「改道」说出来
  E 停机失败 / 参数非法：错误码明确，不静默降级
  F run 模式正常数据：目标不受打扰（halt 次数 0），consistent 如实报 run

运行：python -m tests.test_batch63
"""
import os
import sys
import json
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import linkio as L            # noqa: E402
from mdkdebug import swd as SWD             # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402
from mdkdebug.client import UVClient        # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


# ======================================================================
def build_ctrl(addr, cap=8192, head=0, drained=0, seq=7, flags=None,
               tokens=0, events=0, lost=0):
    """造一个合法的 80 字节无缝流控制块。"""
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
    b[SWD.OFF_LOST_EVENTS:SWD.OFF_LOST_EVENTS + 4] = struct.pack("<I", lost)
    b[SWD.OFF_EVENTS:SWD.OFF_EVENTS + 4] = struct.pack("<I", events)
    b[SWD.OFF_TOKENS:SWD.OFF_TOKENS + 4] = struct.pack("<I", tokens)
    b[SWD.OFF_SEQ:SWD.OFF_SEQ + 4] = struct.pack("<I", seq)
    b[SWD.OFF_CPU_HZ:SWD.OFF_CPU_HZ + 4] = struct.pack("<I", 168000000)
    b[SWD.OFF_FLAGS:SWD.OFF_FLAGS + 4] = struct.pack("<I", flags)
    return bytes(b)


class FakeSwdLink:
    """假链路：环内容按「运行态/停机」返回两份（模拟真机的运行态伪值）。

    run_fake=None 表示运行态读也忠实。
    """

    name = "keil"
    label = "Keil(mock)"

    def __init__(self, addr, ctrl, ring, running=True, run_fake=None,
                 halt_ok=True):
        self.addr = int(addr)
        self.ring_base = self.addr + SWD.CTRL_BYTES
        self.ctrl = bytearray(ctrl)
        self.ring = bytearray(ring)
        self.running = bool(running)
        self.run_fake = run_fake
        self.halt_ok = bool(halt_ok)
        self.halt_calls = 0
        self.resume_calls = 0
        self.writes = []
        self.reads = []

    # -- 内存 --------------------------------------------------------
    def _mem(self, addr, n):
        addr = int(addr)
        n = int(n)
        out = bytearray()
        for i in range(n):
            a = addr + i
            off = a - self.addr
            if 0 <= off < SWD.CTRL_BYTES:
                out.append(self.ctrl[off])
            elif 0 <= a - self.ring_base < len(self.ring):
                if self.running and self.run_fake is not None:
                    out.append(self.run_fake[(a - self.ring_base) % len(self.run_fake)])
                else:
                    out.append(self.ring[a - self.ring_base])
            else:
                out.append(0x00)
        return bytes(out)

    def read(self, addr, n):
        self.reads.append((int(addr), int(n)))
        data = self._mem(addr, n)
        deg = UVClient._degenerate_kind(data)
        meta = {"link": self.name}
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
        self.writes.append((int(addr), bytes(data)))
        for i, b in enumerate(data):
            off = int(addr) + i - self.addr
            if 0 <= off < SWD.CTRL_BYTES:
                self.ctrl[off] = b
        return True, {"link": self.name}

    # -- 运行控制 ----------------------------------------------------
    def halt(self):
        self.halt_calls += 1
        if not self.halt_ok:
            return {"ok": False, "error": "模拟：halt 失败"}
        self.running = False
        return {"ok": True}

    def resume(self):
        self.resume_calls += 1
        self.running = True
        return {"ok": True}

    def describe(self):
        return {"debugging": True, "running": self.running,
                "status_text": "running(mock)" if self.running else "stopped(mock)"}

    need_halt_for_read = staticmethod(lambda: False)


def patch_pick(fake):
    real = L.pick
    L.pick = lambda link="auto", who="": ((fake, None) if fake is not None else real(link, who))
    return lambda: setattr(L, "pick", real)


def scenario(addr=0x200020C8, events=None, running=True, run_fake=None,
             halt_ok=True, drained=0):
    """造一段含 sync + 若干事件的合法流。"""
    enc = SWD.Encoder()
    stream = enc.sync(1)
    evs = events if events is not None else [
        ((0x1, 0, 3, 0), 0), ((0x1, 0, 3, 0), 5), ((0x2, 0, 0, 0), 0)]
    stream += enc.encode(evs)
    ring = bytearray(8192)
    ring[0:len(stream)] = stream
    ctrl = build_ctrl(addr, head=len(stream), drained=drained,
                      tokens=len(evs), events=len(evs))
    lk = FakeSwdLink(addr, ctrl, ring, running=running, run_fake=run_fake,
                     halt_ok=halt_ok)
    return lk, stream, len(evs)


def fresh_session():
    TRC._T["swd"] = None


FAKE = bytes([0x32, 0xC6, 0xB2, 0x07]) * 16        # 真机抓到的那种「重复字」


def ev_count(out):
    """折出来的事件数：去掉 sync/lost 这类 CTL 标记（它们也是 item，但不是事件）。"""
    return len([e for e in (out.get("events") or [])
                if e.get("type") not in ("segment", "lost", "gap")])


def main():
    print("== A 伪值签名 ==", flush=True)
    check("A1 client 层认出 repeated_word",
          UVClient._degenerate_kind(FAKE) == "repeated_word",
          UVClient._degenerate_kind(FAKE))
    check("A2 trace 层认出 repeated_word",
          TRC._swd_fake_kind(FAKE) == "repeated_word",
          TRC._swd_fake_kind(FAKE))
    check("A3 全 0x00 仍按 all_zero",
          UVClient._degenerate_kind(bytes(32)) == "all_zero")
    check("A4 短读（<16B）不判伪值",
          UVClient._degenerate_kind(FAKE[:12]) == ""
          and TRC._swd_fake_kind(FAKE[:12]) == "")
    check("A5 同值字节流（HITN 密集段长这样）不判伪值",
          TRC._swd_fake_kind(bytes([0x40]) * 64) == ""
          and UVClient._degenerate_kind(bytes([0x40]) * 64) == "")
    check("A6 正常字节流不判伪值",
          TRC._swd_fake_kind(bytes(range(32))) == "")
    check("A7 只有尾部坏（真机就是这个形状）也要认出来",
          TRC._swd_fake_kind(bytes(range(200)) + FAKE[:64]) == "repeated_word",
          TRC._swd_fake_kind(bytes(range(200)) + FAKE[:64]))
    check("A8 不假设 4 字节对齐（起点取决于 drained）",
          TRC._swd_fake_kind(b"\x01" + FAKE[:64] + b"\x02") == "repeated_word",
          TRC._swd_fake_kind(b"\x01" + FAKE[:64] + b"\x02"))
    check("A9 长段 HITN 连发（0x40 连发）不判伪值",
          TRC._swd_fake_kind(bytes([0x40]) * 4096) == "")

    print("\n== B consistent=halt（默认） ==", flush=True)
    fresh_session()
    lk, stream, nev = scenario()
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr)
    finally:
        rp()
    check("B1 搬成功且事件数对得上", out.get("ok") and ev_count(out) == nev,
          out)
    check("B2 consistent=halt / halt_ms 有值",
          out.get("consistent") == "halt" and (out.get("halt_ms") or 0) > 0, out)
    check("B3 停机与放行各一次",
          lk.halt_calls == 1 and lk.resume_calls == 1,
          (lk.halt_calls, lk.resume_calls))
    check("B4 停机期间就把游标推上去了（写 drained = head）",
          any(a == lk.addr + SWD.OFF_DRAINED for a, _ in lk.writes), lk.writes)
    check("B5 目标最终回到运行态", lk.running is True)

    print("\n== C consistent=run：伪值必须当场报错 ==", flush=True)
    fresh_session()
    lk, stream, nev = scenario(running=True, run_fake=FAKE)
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr, consistent="run")
    finally:
        rp()
    check("C1 报 swd-read-untrusted", out.get("error_code") == "swd-read-untrusted", out)
    check("C2 不推进游标（没写 drained）", lk.writes == [], lk.writes)
    check("C3 不打扰目标（没停机）", lk.halt_calls == 0, lk.halt_calls)
    check("C4 提示指向 halt", "halt" in (out.get("hint") or ""), out.get("hint"))

    print("\n== D consistent=auto：自动改道停机 ==", flush=True)
    fresh_session()
    lk, stream, nev = scenario(running=True, run_fake=FAKE)
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr, consistent="auto")
    finally:
        rp()
    check("D1 最终搬成功", out.get("ok") and ev_count(out) == nev, out)
    check("D2 consistent 报 halt（如实说这次是怎么搬的）",
          out.get("consistent") == "halt", out)
    check("D3 停机/放行各一次",
          lk.halt_calls == 1 and lk.resume_calls == 1,
          (lk.halt_calls, lk.resume_calls))
    check("D4 notes 里说明「已改用停机搬运」",
          any("停机搬运" in n for n in (out.get("notes") or [])), out.get("notes"))

    print("\n== E 失败与非法参数 ==", flush=True)
    fresh_session()
    lk, stream, nev = scenario(halt_ok=False)
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr)
    finally:
        rp()
    check("E1 halt 失败报 swd-halt-failed", out.get("error_code") == "swd-halt-failed", out)
    check("E2 失败时不假装搬成功", out.get("ok") is not True and lk.writes == [])

    fresh_session()
    lk, stream, nev = scenario()
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr, consistent="zoo")
    finally:
        rp()
    check("E3 非法 consistent 报 swd-consistent-invalid",
          out.get("error_code") == "swd-consistent-invalid", out)
    check("E4 非法参数时一次链路都没碰", lk.halt_calls == 0 and lk.reads == [])

    print("\n== F consistent=run：干净链路不打扰目标 ==", flush=True)
    fresh_session()
    lk, stream, nev = scenario(running=True, run_fake=None)
    rp = patch_pick(lk)
    try:
        out = TRC.swd_read(addr="0x%X" % lk.addr, consistent="run")
    finally:
        rp()
    check("F1 搬成功", out.get("ok") and ev_count(out) == nev, out)
    check("F2 consistent=run / halt_ms 为 None",
          out.get("consistent") == "run" and out.get("halt_ms") is None, out)
    check("F3 全程没停机", lk.halt_calls == 0 and lk.resume_calls == 0,
          (lk.halt_calls, lk.resume_calls))

    print("\n----")
    print("通过 %d，失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
