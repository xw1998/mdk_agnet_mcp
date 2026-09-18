# -*- coding: utf-8 -*-
"""批次54 mock 测试：F401 trace 矩阵在板上暴露的 4 项「看似权威的错答案」。

在 F401 上把 trace 工具族跑了一遍（CMSIS-DAP、无 SWO），撞出四个同族问题——
共同点都是「工具给了一个像模像样的结果/结论，但和板上真实情况不符」：

  ① trace_scope_start(vars="g_cnt") 报「地址不是数字：'g_cnt'」。
     文档明写「只给名字就用 elf 查地址与大小」，实现却没查——把最自然的用法挡在门外。
  ② 采样类工具（scope / pcsample / profile）只在调用方显式传 elf= 时才把地址翻成
     函数名，哪怕会话里已经 set_symbol_file 定位好了 .axf——PC 全退化成裸地址。
  ③ 目标已停机时 trace_record 安静地录到 0 事件、却仍回 ok——「没测到」被当成「没有」。
  ④ 零事件时断言「读不到 DWT_CYCCNT（未使能或该内核没有）」——可当时 CYCCNT
     明明读得动（0x5A36DC87）；把「没测过」说成了「没有」。

   A _parse_vars 裸名回落 ELF（显式 @addr 不受影响）
   B _session_axf 回落（会话符号；文件不在就不认）
   C 采样/轮询工具在未传 elf 时会话符号被查询（显式参数仍优先）
   D record：停机复核（不再静默空结果）
   E cyccnt_note 分情形（保留 H11(r2)「不要编造」措辞）+ 零事件 no_hit

运行：python -m tests.test_batch54
"""
import os
import sys
import json
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import rtrace as RT           # noqa: E402
from mdkdebug import rtrecord as RR         # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import trace as TR            # noqa: E402

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


# ======================================================================
class FakeBackend(RT.Backend):
    """rtrace 驱动用的假链路（比 batch49 那份多一个可注入的 running 状态）。"""

    name = "keil"
    label = "Keil/UVSOCK(mock)"

    def __init__(self, hits=None, slots_n=4, bp_ok=True, halt_ok=True,
                 resume_ok=True, clear_ok=True, cyc=None, name=None,
                 running=None):
        self.hits = list(hits or [])
        self._slots = int(slots_n)
        self.bp_ok = bp_ok
        self.halt_ok = halt_ok
        self.resume_ok = resume_ok
        self.clear_ok = clear_ok
        self.cyc = cyc
        self.running = running
        if name:
            self.name = name
        self.planted = []
        self.cleared = []
        self.halt_calls = 0
        self.resume_calls = 0

    def available(self):
        return True

    def describe(self):
        d = {"name": self.name, "label": self.label, "mock": True}
        if self.running is not None:
            d["running"] = self.running
            d["status_text"] = "run" if self.running else "stop(复核)"
        return d

    def slots(self):
        return self._slots

    def halt(self):
        self.halt_calls += 1
        return {"ok": self.halt_ok, "was_running": False,
                "error": None if self.halt_ok else "halt 失败(mock)"}

    def resume(self):
        self.resume_calls += 1
        return {"ok": self.resume_ok,
                "error": None if self.resume_ok else "resume 失败(mock)"}

    def regs(self, names=("pc", "lr", "sp")):
        return {"ok": True, "pc": 0x100, "lr": 0x200, "sp": 0x20001000}

    def read_u32(self, addr):
        if self.cyc is None:
            return None, {"error": "读不到 CYCCNT(mock)"}
        return self.cyc, {}

    def set_bp(self, addr):
        if not self.bp_ok:
            return False, {"error": "槽位不足(mock)", "addr": "0x%X" % int(addr)}
        self.planted.append(int(addr))
        return True, {"addr": "0x%X" % int(addr)}

    def clear_bp(self, addr):
        self.cleared.append(int(addr))
        return self.clear_ok, {"addr": "0x%X" % int(addr)}

    def wait_hit(self, addrs, timeout_s=10.0):
        if not self.hits:
            return {"ok": True, "hit": False, "link": self.name}
        h = self.hits.pop(0)
        return {"ok": True, "hit": True, "link": self.name,
                "hit_address": h.get("pc"), "registers": h}


def use(obj, name, val):
    old = getattr(obj, name)
    setattr(obj, name, val)
    return lambda: setattr(obj, name, old)


# ======================================================================
def section_a():
    print("A. trace._parse_vars：裸变量名回落 ELF")
    SYMS = {"g_cnt": (0x20000010, 4), "g_flag": (0x20000020, 1)}
    ELF = os.path.abspath(__file__)   # 只当"存在的路径"用，符号表由替身提供

    def fake(elf, nm):
        # 忠实替身：真 _elf_symbol 在 elf 为空/不存在时直接 (None, None)（不看符号表）
        if not elf or not os.path.isfile(elf):
            return None, None
        return SYMS.get((nm or "").strip().lower(), (None, None))
    undo = use(TR, "_elf_symbol", fake)
    try:
        p = TR._parse_vars("g_cnt", elf=ELF)
        check("A1 裸变量名 + 有 elf → 真去 ELF 查到地址与大小（不再报「地址不是数字」）",
              p["invalid"] == [] and p["items"]
              and p["items"][0]["addr"] == 0x20000010
              and p["items"][0]["size"] == 4, p)

        p = TR._parse_vars("g_flag", elf=ELF)
        check("A2 符号自带大小（1 字节）时以 ELF 的 st_size 为准，不是默认 4",
              p["items"] and p["items"][0]["size"] == 1, p)

        p = TR._parse_vars("g_cnt", elf="")      # 没给 elf，且这条也不是纯数字地址
        check("A3 裸名但没给 elf → 如实进 invalid，说清「没给地址也没给 elf」",
              p["items"] == [] and len(p["invalid"]) == 1
              and "没给地址" in p["invalid"][0]["why"], p)

        p = TR._parse_vars("g_nope", elf=ELF)
        check("A4 给了 elf 但符号不在 → 报「ELF 里没找到符号」，不猜地址",
              p["items"] == [] and "没找到符号" in p["invalid"][0]["why"], p)

        p = TR._parse_vars("g_cnt@0x20000030:2", elf=ELF)
        check("A5 显式 name@addr:size 仍原样生效（回归，不因回落改动而变）",
              p["items"][0]["addr"] == 0x20000030 and p["items"][0]["size"] == 2, p)

        p = TR._parse_vars("g_cnt, 0x20000040:4, g_nope, 0x20000050", elf=ELF)
        check("A6 合法/非法混排时如实分列：3 条解析成功（含纯地址）、1 条进 invalid",
              len(p["items"]) == 3 and len(p["invalid"]) == 1
              and p["invalid"][0]["item"] == "g_nope", p)
    finally:
        undo()


def section_b():
    print("B. trace._session_axf：会话符号回落")
    cfg = SV._symbol_cfg
    old = dict(cfg)
    try:
        here = os.path.abspath(__file__)
        cfg["axf"] = here
        got = TR._session_axf()
        check("B1 会话里已定位 .axf → 返回它的绝对路径",
              got == here, got)

        cfg["axf"] = os.path.join(os.path.dirname(here), "不存在的文件.axf")
        check("B2 会话里的路径已失效 → 返回空串（不把死路径当符号文件用）",
              TR._session_axf() == "", TR._session_axf())

        cfg["axf"] = ""
        check("B3 会话没有符号文件 → 空串", TR._session_axf() == "")

        cfg.pop("axf", None)
        check("B4 会话配置里连键都没有 → 空串，且不抛异常",
              TR._session_axf() == "")
    finally:
        cfg.clear()
        cfg.update(old)


def section_c():
    print("C. 采样/轮询工具：未传 elf 时会话符号被查询（显式参数优先）")
    calls = []
    undo_sess = use(TR, "_session_axf", lambda: calls.append(1) or "/tmp/sess.axf")

    def pick_fail(link="auto", who=""):
        return None, {"ok": False, "error": "%s 没有可用链路(mock)" % who}

    undo2 = use(TR._link, "pick", pick_fail)
    try:
        for fn, kw in ((TR.scope_start, {"vars": "0x20000010:4"}),
                       (TR.pc_sample, {}),
                       (TR.profile_samples, {})):
            calls.clear()
            r = fn(**kw)
            check("C-%s 未传 elf 也会查会话符号（查询发生 %d 次）"
                  % (fn.__name__, len(calls)),
                  len(calls) == 1 and r.get("ok") is False, (len(calls), r))

        calls.clear()
        TR.pc_sample(elf="/tmp/explicit.axf")
        check("C-explicit 显式 elf 时不回落会话符号（0 次查询）",
              calls == [], calls)
    finally:
        undo2()
        undo_sess()


def section_d():
    print("D. rtrace.record：resume 之后复核运行态")
    idx = RR.make_func_index([(0x100, 0x200, "task_a")])
    hits = [{"pc": 0x100, "lr": 0, "sp": 0x20001000}]

    be = FakeBackend(hits=hits, running=False)
    r = RT.record(idx, [0x100], backend=be, max_ms=200)
    check("D1 resume 回显成功但复核发现仍在停机 → ok=false 并报「仍处于停止态」",
          r["ok"] is False and "仍处于停止态" in (r.get("error") or ""), r.get("error"))
    check("D2 停机时不装作录完了：没有 timeline 事件、也不再往下轮询",
          not r.get("timeline") and not r.get("events"), r)
    check("D3 已布下的断点被撤掉并留痕（不留半个现场）",
          0x100 in be.cleared and r["breakpoints_left"] == [],
          (be.cleared, r["breakpoints_left"]))
    check("D4 复核结论如实透出 target_running_after_resume=False",
          r.get("target_running_after_resume") is False, r.get("target_running_after_resume"))

    be2 = FakeBackend(hits=list(hits), running=True)
    r2 = RT.record(idx, [0x100], backend=be2, max_ms=200)
    check("D5 复核确认在跑 → 照常录制，并透出 target_running_after_resume=True",
          r2["ok"] is True and r2.get("target_running_after_resume") is True
          and r2.get("timeline"), (r2.get("ok"), r2.get("target_running_after_resume")))

    be3 = FakeBackend(hits=list(hits))          # describe 不带 running（老后端）
    r3 = RT.record(idx, [0x100], backend=be3, max_ms=200)
    check("D6 链路根本不报 running → 不替目标下判断，照常录制且不出现该字段",
          r3["ok"] is True and "target_running_after_resume" not in r3, r3)


def section_e():
    print("E. cyccnt_note 分情形 + 零事件 no_hit")
    idx = RR.make_func_index([(0x100, 0x200, "task_a")])

    # 零事件：既没说「读不到 CYCCNT」，也要说明「没命中 ≠ 没被调用」
    be = FakeBackend(hits=[], running=True)
    r = RT.record(idx, [0x100], backend=be, max_ms=120)
    note = r.get("cyccnt_note") or ""
    check("E1 零事件 → cyccnt_note 说「无法判定」，不再断言内核没有 DWT_CYCCNT",
          "无法判定" in note and "不要据此说" in note
          and "trace_dwt_counters" in note, note)
    check("E2 零事件 → 给出 no_hit，说清「不等于函数没被调用」",
          "no_hit" in r and "不等于" in r["no_hit"], r.get("no_hit"))

    # 有事件但读不到 CYCCNT：必须保留 batch49 H11(r2) 的「不要编造」措辞
    be2 = FakeBackend(hits=[{"pc": 0x100, "lr": 0, "sp": 0x20001000}], cyc=None,
                      running=True)
    r2 = RT.record(idx, [0x100], backend=be2, max_ms=120)
    check("E3 有命中但 CYCCNT 读不到 → 仍保留「不要编造」的措辞（不破坏 batch49）",
          r2["cyccnt_available"] is False and "不要编造" in (r2.get("cyccnt_note") or ""),
          r2.get("cyccnt_note"))
    check("E4 有命中 → 不出现 no_hit（命中过就不该提示零事件）",
          "no_hit" not in r2, r2.get("no_hit"))

    be3 = FakeBackend(hits=[{"pc": 0x100, "lr": 0, "sp": 0x20001000}], cyc=1000,
                      running=True)
    r3 = RT.record(idx, [0x100], backend=be3, max_ms=120)
    check("E5 CYCCNT 读得到 → 无 cyccnt_note、无 no_hit（没什么可提醒的）",
          r3["cyccnt_available"] is True and "cyccnt_note" not in r3
          and "no_hit" not in r3, r3)


def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    print("\n通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
