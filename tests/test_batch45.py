# -*- coding: utf-8 -*-
"""批次45 mock 测试：Keil 链路的运行态读写内存（非停机观测）。

来源：用户缺口表「非停机读写内存（Keil 链路）——目标运行时读内存会错位/脏读，
目前靠防护缓解；DAP 后台直读（OpenOCD 链路已能做）可让 Keil 链路也能运行态观测」。

真机复核推翻了旧前提：Keil 链路在目标全速运行时**读得到**（SRAM 与外设寄存器都读得到、
256B 大块也稳），旧文档里「务必先 stop 再读」不再成立。于是本批把「运行态读」从
「不许」改成「可以，但必须把可信度说清楚」：

  A client 层：while_running 披露、运行态强制复读、两次不一致时给 medium + unstable，
    并把「该地址本来就在被 CPU 改写」与「这次读被打断」两种解释都写明——不替你选一个
  B 停-读-走：_halt_guard / _resume_after_halt / _halt_note（有副作用就必须交代）
  C 链路层：need_halt_for_read 更正为 False（运行态可读，不再一刀切要求先停）
  D 工具层：read_mem / write_mem 的 running=live|halt 与非法值报错

运行：python -m tests.test_batch45
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import client as CL         # noqa: E402
from mdkdebug import linkio as L          # noqa: E402
from mdkdebug import server as S          # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


# ======================================================================
# 夹具：假 UVClient（只装本批用得到的那几个属性，不碰真 UVSOCK）
# ======================================================================
class FakeClient(CL.UVClient):
    """frames 按「第几次读」依次取用，用完后一直取最后一帧。"""

    def __init__(self, frames=None, running=True, status_ok=True,
                 stop_ok=True, run_ok=True):
        self._lock = threading.RLock()
        self._exec_ts = 0.0
        self._last_stop_obs_ts = 0.0
        self._run_cache = None
        self._run_cache_at = 0.0
        self._frames = list(frames or [b"\x11" * 8])
        self._ri = 0
        self._running = running
        self._status_ok = status_ok
        self._stop_ok = stop_ok
        self._run_ok = run_ok
        self.status_calls = 0
        self.stop_calls = 0
        self.run_calls = 0
        self.write_calls = []

    # -- 替掉真实链路 --
    def get_status(self):
        self.status_calls += 1
        return {"ok": self._status_ok, "debugging": True, "running": self._running}

    def read_mem(self, addr, n_bytes):
        i = min(self._ri, len(self._frames) - 1)
        self._ri += 1
        return {"ok": True, "addr": addr, "data_hex": self._frames[i].hex(),
                "ascii": "", "length": len(self._frames[i])}

    def write_mem(self, addr, data):
        self.write_calls.append((addr, bytes(data)))
        return {"ok": True, "addr": addr, "written": len(data)}

    def stop(self):
        self.stop_calls += 1
        if not self._stop_ok:
            return {"ok": False, "status_text": "暂停被拒绝"}
        self._running = False
        return {"ok": True, "status_text": "已停止"}

    def run(self):
        self.run_calls += 1
        if not self._run_ok:
            return {"ok": False, "status_text": "恢复被拒绝"}
        self._running = True
        return {"ok": True, "status_text": "执行中"}

    def wait_until_stopped(self, timeout=1.0):
        return {"ok": True, "stopped": True, "waited_ms": 1}


# ======================================================================
def section_a():
    print("\n-- A client 层：运行态读数怎么交代可信度 --")
    A = b"\x11" * 8

    c = FakeClient(frames=[A], running=True)
    check("A1 running_cached 目标在跑 → True",
          c.running_cached() is True, None)

    c = FakeClient(frames=[A], running=False)
    check("A2 running_cached 目标已停 → False",
          c.running_cached() is False, None)

    c = FakeClient(frames=[A], status_ok=False)
    check("A3 状态查不出来 → None（不猜一个方向）",
          c.running_cached() is None, None)

    c = FakeClient(frames=[A], running=True)
    c.running_cached()
    n0 = c.status_calls
    c.running_cached()
    c.running_cached()
    check("A4 「目标在不在跑」1 秒内复用（轮询采样不再每点打一次状态查询）",
          c.status_calls == n0, (n0, c.status_calls))

    # 停止态：不额外复读（既有行为不能回归）
    c = FakeClient(frames=[A], running=False)
    r = c.read_mem_verified(0x20000000, 8)
    check("A5 停止态读：while_running=False 且不额外复读",
          r.get("while_running") is False and r.get("reread_count") == 0, r)

    # 运行态 + 两次一致
    c = FakeClient(frames=[A, A], running=True)
    r = c.read_mem_verified(0x20000000, 8)
    check("A6 运行态读两次一致 → while_running=True 且置信度 high",
          r.get("while_running") is True and r.get("read_confidence") == "high"
          and r.get("reread_count", 0) >= 1 and not r.get("read_unstable"), r)

    # 运行态 + 两次不一致
    c = FakeClient(frames=[A, b"\x22" * 8], running=True)
    r = c.read_mem_verified(0x20000000, 8)
    w = r.get("warning") or ""
    check("A7 运行态读两次不一致 → medium + read_unstable（不当成坏帧，也不当成真值）",
          r.get("read_confidence") == "medium" and r.get("read_unstable") is True
          and r.get("reread_consistent") is False, r)
    check("A8 两种解释都要写明（变量本来在变 / 读被打断），不替调用者选一个",
          "CPU" in w and "改写" in w and "打断" in w and "halt" in w, w)

    # 停止态读数一直变 → 仍按原有「不可信」处理（别被运行态分支带偏）
    c = FakeClient(frames=[A, b"\x22" * 8, b"\x33" * 8], running=False)
    r = c.read_mem_verified(0x20000000, 8, verify="true")
    check("A9 停止态强制复读且一直不一致 → 仍判 low（不因新增运行态分支而放宽）",
          r.get("read_confidence") == "low"
          and not r.get("read_unstable"), r)


# ======================================================================
def section_b():
    print("\n-- B 停-读-走：副作用如实交代 --")
    A = b"\x11" * 8

    c = FakeClient(frames=[A], running=True)
    info = S._halt_guard(c)
    check("B1 目标在跑 → 真的暂停了，并记下 was_running/stop_ok",
          info.get("was_running") is True and info.get("stop_ok") is True
          and c.stop_calls == 1, info)

    c = FakeClient(frames=[A], running=False)
    info = S._halt_guard(c)
    check("B2 目标本来就停着 → 不动它（不多此一举暂停）",
          info.get("was_running") is False and c.stop_calls == 0, info)

    c = FakeClient(frames=[A], running=True, stop_ok=False)
    info = S._halt_guard(c)
    check("B3 暂停失败 → stop_ok=False 且带上原因（不含糊成「成功」）",
          info.get("stop_ok") is False and info.get("stop_error"), info)

    c = FakeClient(frames=[A], running=True)
    info = S._halt_guard(c)
    S._resume_after_halt(c, info)
    check("B4 停过就一定要恢复运行",
          info.get("resumed") is True and c.run_calls == 1
          and c._running is True, info)

    c = FakeClient(frames=[A], running=True, run_ok=False)
    info = S._halt_guard(c)
    S._resume_after_halt(c, info)
    check("B5 恢复失败 → resumed=False + resume_error（不静默）",
          info.get("resumed") is False and info.get("resume_error"), info)

    c = FakeClient(frames=[A], running=False)
    info = S._halt_guard(c)
    S._resume_after_halt(c, info)
    check("B6 本来没停过 → 不去「恢复」它（避免凭空把目标跑起来）",
          c.run_calls == 0 and info.get("resumed") is None, info)

    notes = S._halt_note({"was_running": True, "stop_ok": True, "resumed": True}, 12)
    check("B7 halt_note 写明暂停代价（paused_ms）",
          any("暂停" in n and "12" in n for n in notes), notes)

    notes = S._halt_note({"was_running": True, "stop_ok": True, "resumed": False,
                          "resume_error": "恢复被拒绝"}, 12)
    check("B8 恢复失败必须在 note 里告警（目标还停着，别当没发生）",
          any("恢复运行失败" in n for n in notes), notes)

    notes = S._halt_note({"was_running": False, "stop_ok": None}, 0)
    check("B9 没停过就没有副作用可说（不硬凑一句）", notes == [], notes)

    notes = S._halt_note({"was_running": True, "stop_ok": False,
                          "stop_error": "暂停被拒绝"}, 0)
    check("B10 暂停失败要明说「没拿到停机快照」", notes and "暂停" in notes[0], notes)


# ======================================================================
def section_c():
    print("\n-- C 链路层：不再一刀切要求先停 --")
    kl = L.KeilLink(None)
    check("C1 KeilLink.need_halt_for_read() 更正为 False（真机实测运行态读得到）",
          kl.need_halt_for_read() is False, None)
    check("C2 OcdLink 同样不要求先停",
          L.OcdLink(None).need_halt_for_read() is False, None)

    c = FakeClient(frames=[b"\x11" * 8], running=True)
    kl2 = L.KeilLink(c)
    _, meta = kl2.read(0x20000000, 8)
    check("C3 KeilLink.read 的 meta 如实带 while_running",
          meta.get("while_running") is True, meta)


# ======================================================================
def section_d():
    print("\n-- D 工具层：running 参数 --")
    srv = S.create_server()

    import asyncio
    import json

    def call(name, **args):
        res = asyncio.run(srv.call_tool(name, args))
        return json.loads("".join(getattr(c, "text", "") or "" for c in res.content))

    r = call("read_mem", addr="0x20000000", n_bytes=4, running="xx")
    check("D1 read_mem 的 running 非法值 → invalid-argument（不猜一个默认行为）",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)

    r = call("write_mem", addr="0x20000000", data_hex="aabb", running="xx")
    check("D2 write_mem 的 running 非法值 → invalid-argument",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)

    # 用假 client 走完整工具路径：halt 模式的返回值必须交代副作用
    fake = FakeClient(frames=[b"\xaa" * 8], running=True)
    orig = S._get_client
    S._get_client = lambda: fake
    try:
        r = call("read_mem", addr="0x20000000", n_bytes=8, running="halt")
    finally:
        S._get_client = orig
    check("D3 read_mem(running=halt) 返回停机快照 + 暂停代价 + 已恢复",
          r.get("ok") and r.get("sampling") == "halt"
          and r.get("was_running") is True and r.get("resumed") is True
          and isinstance(r.get("paused_ms"), int)
          and "暂停" in (r.get("halt_note") or ""), r)

    fake = FakeClient(frames=[b"\xaa" * 8], running=False)
    orig = S._get_client
    S._get_client = lambda: fake
    try:
        r = call("read_mem", addr="0x20000000", n_bytes=8, running="halt")
    finally:
        S._get_client = orig
    check("D4 目标本来停着 → sampling=halt 但不谎报「我停了它」",
          r.get("ok") and r.get("was_running") is False
          and not r.get("halt_note") and r.get("paused_ms") == 0, r)

    fake = FakeClient(frames=[b"\xaa" * 8], running=True)
    orig = S._get_client
    S._get_client = lambda: fake
    try:
        r = call("write_mem", addr="0x20000000", data_hex="aabbccdd", running="halt")
    finally:
        S._get_client = orig
    check("D5 write_mem(running=halt) 停-写-回读-走，回读校验落地",
          r.get("ok") and r.get("sampling") == "halt" and r.get("resumed") is True
          and fake.write_calls and fake.write_calls[0][1] == b"\xaa\xbb\xcc\xdd", r)


# ======================================================================
def main():
    print("批次45 mock 测试：Keil 链路的运行态读写内存（非停机观测）")
    section_a()
    section_b()
    section_c()
    section_d()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for n in FAIL:
            print("  - %s" % n)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
