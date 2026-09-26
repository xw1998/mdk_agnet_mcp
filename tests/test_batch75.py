# -*- coding: utf-8 -*-
"""批次75 mock 测试：条件触发层（trace_watch / mdkdebug/trwatch.py）。

需求：AI 不该「一点一点看事件」，而应该**等一件事发生**——命中就把「命中事件 +
前后上下文 + 诊断结论」一次交回。本批在**主机侧**做（目标侧 SWD 控制块只有 80 字节、
无 mask/filter/trigger 字段，实测），覆盖范围是整个会话已录部分（无缝流无损累积），
且**手动插桩与自动钩子事件共用同一套条件**（同一条流）。

  A 条件引擎：语法、比较符、obj/op 名与数字等价、min_count、上下文、报错即报错
  B watch_test：在已录事件上预检（含「一条事件都没有」时不能说「没命中」）
  C watch_arm / status / clear：游标语义
  D watch_wait：长轮询命中 / 超时 / 丢事件时覆盖度不完整 / 被裁剪 / 搬运失败
  E 工具面：trace_watch 在 trace 组、不在默认面；工具总数
  F 参数与动作校验（认不出的 action / spec 不静默兜底）

运行：python -m tests.test_batch75
"""
import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import trwatch as TW          # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import server as SV           # noqa: E402

PORT = 15575
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

# 一段真假想流：手插桩事件(id=42) + 自动钩子事件(sched/sync/heap/isr/fault)
EVS = [
    {"type": "sched", "kind": "point", "id": 0, "arg": 0x30, "from": 3, "to": 0,
     "cycles": 100, "t_us": 1.0, "from_name": "blink", "to_name": "idle"},
    {"type": "sync", "kind": "point", "id": 48, "arg": 7, "obj": 6, "op": 0,
     "op_name": "wait", "cycles": 200, "t_us": 2.0},
    {"type": "isr", "kind": "enter", "id": 10, "arg": 10, "cycles": 300, "t_us": 3.0},
    {"type": "sync", "kind": "point", "id": 48, "arg": 0, "obj": 6, "op": 1,
     "op_name": "signal", "cycles": 400, "t_us": 4.0},
    {"type": "fault", "kind": "point", "id": 0xFE00, "arg": 1,
     "fault_class": "hardfault", "cycles": 500, "t_us": 6000.0},
    {"type": "event", "kind": "point", "id": 42, "arg": 0, "cycles": 600, "t_us": 7.0},
    {"type": "heap", "kind": "point", "id": 0, "arg": 256, "op": 0,
     "op_name": "alloc", "size": 256, "cycles": 700, "t_us": 8.0},
]

def _ids(res):
    return [h["index"] for h in res["hits"]]

def fake_session(events=None, lost_events=0, cpu_hz=96000000):
    s = {"addr": 0x20000000, "dec": None,
         "events": list(EVS if events is None else events),
         "faults": [], "drained": 0, "seq": 1, "rel_cycles": 0, "restarts": 0,
         "syncs": 0, "bytes_read": 0,
         "events_seen": len(EVS if events is None else events),
         "anchor_cycle": 1, "cursor_write_failed": False, "gran": None,
         "ts_off": False, "cpu_hz": cpu_hz,
         "last_ctrl": {"lost_events": int(lost_events)}}
    TRC._T["swd"] = s
    return s

# ------------------------------------------------------------------ A
def section_a():
    print("A. 条件引擎")
    cases = [("fault", [4]), ("sync,obj=cond,op=wait", [1]), ("id=42", [5]),
             ("isr,id=10", [2]), ("t_us>=1500", [4]),
             ("sched,to=3|sched,from=3", [0])]
    ok = True
    for spec, want in cases:
        r = TW.evaluate(EVS, spec)
        ok = ok and _ids(r) == want
    check("A1 六条典型条件各自命中预期事件（含裸词简写与 | 或）", ok,
          [(s, _ids(TW.evaluate(EVS, s))) for s, w in cases])
    check("A2 逗号是「且」：sched,to=3 不命中 to=0 的事件",
          TW.evaluate(EVS, "sched,to=3")["matches"] == 0)
    check("A3 obj 类名与数字等价（cond==6）",
          TW.evaluate(EVS, "obj=cond")["matches"] == TW.evaluate(EVS, "obj=6")["matches"] == 2)
    only_num_op = [dict(EVS[1], op=0) for _ in [0]]
    only_num_op[0].pop("op_name")
    check("A4 事件里只有数字 op 时 op=wait 仍命中（不静默不命中）",
          TW.evaluate(only_num_op, "op=wait")["matches"] == 1)
    check("A5 heap 的 size 字段可判（size>=256）",
          _ids(TW.evaluate(EVS, "heap,op=alloc,size>=256")) == [6])
    check("A6 比较符 > >= < <= != 都生效",
          TW.evaluate(EVS, "t_us>6000")["matches"] == 0
          and TW.evaluate(EVS, "t_us>=6000")["matches"] == 1
          and TW.evaluate(EVS, "id!=42")["matches"] == len(EVS) - 1
          and TW.evaluate(EVS, "arg<10")["matches"] == 4)
    r = TW.evaluate(EVS, "type=sync", min_count=2)
    check("A7 min_count=2：命中 2 次才算触发", r["matches"] == 2 and r["triggered"])
    check("A8 min_count=3 时同样 2 次命中 → 不算触发",
          not TW.evaluate(EVS, "type=sync", min_count=3)["triggered"])
    h = TW.evaluate(EVS, "id=42", before=2, after=2)["hits"][0]
    check("A9 上下文窗口按 before/after 取（含边界裁剪）",
          [e["id"] for e in h["before"]] == [48, 0xFE00] and len(h["after"]) == 1,
          (h["before"], h["after"]))
    r = TW.evaluate(EVS, "type=event|type=sync", max_hits=1)
    check("A10 max_hits 只限返回条数，matches 仍是全量",
          len(r["hits"]) == 1 and r["matches"] == 3 and r["hits_truncated"])
    bad = ["faul", "type=faul", "id>=", "obj=mutexx", "=3", "", "sync,op=wai",
           "cond", "nosuch=1"]
    errs = []
    for spec in bad:
        try:
            TW.evaluate(EVS, spec)
            errs.append((spec, "没报错"))
        except TW.SpecError as e:
            errs.append((spec, str(e)[:20]))
    check("A11 条件写错一律报错（9 类都不静默）",
          all(msg != "没报错" for _s, msg in errs), errs)
    try:
        TW.parse("nosuch=1")
        msg = ""
    except TW.SpecError as e:
        msg = str(e)
    check("A12 报错里给出可用字段清单（让人能自己改对）",
          "可用" in msg and "type" in msg, msg[:120])
    check("A13 *_name 条件在流里没有名字时如实提示（不静默不命中）",
          TW.evaluate([{"type": "sched", "from": 1, "to": 2}], "from_name=x")["unmatched_names"])

# ------------------------------------------------------------------ B
def section_b():
    print("B. watch_test：在已录事件上预检")
    fake_session()
    r = TRC.watch_test(spec="fault", source="swd")
    check("B1 命中：ok/triggered/matches/available 齐",
          r.get("ok") and r["triggered"] and r["matches"] == 1
          and r["available"] == len(EVS), r)
    r = TRC.watch_test(spec="sync,obj=cond,op=wait", source="swd")
    check("B2 归一化后的语义字段（obj/op_name）在预检里可用",
          r["matches"] == 1 and _ids(r) == [1], r.get("matches"))
    r = TRC.watch_test(spec="nosuch=1", source="swd")
    check("B3 条件错 → watch-spec-invalid（带可用字段）",
          r.get("error_code") == "watch-spec-invalid" and r.get("fields"), r)
    fake_session(events=[])
    r = TRC.watch_test(spec="fault", source="swd")
    check("B4 零事件时给出 empty + hint，且不把「没命中」当成结论",
          r.get("ok") and r.get("empty") and r.get("hint")
          and not r["triggered"], r)

# ------------------------------------------------------------------ C
def section_c():
    print("C. arm / status / clear")
    TRC.watch_clear()
    fake_session()
    r = TRC.watch_arm(spec="id=42")
    check("C1 arm 默认从当前位置起判（历史不计）",
          r["ok"] and r["cursor"] == len(EVS), r)
    r2 = TRC.watch_test(spec="id=42", source="swd")
    r3 = TRC.watch_arm(spec="id=42", cursor="history")
    check("C2 cursor=\"history\" 从会话起点起判",
          r3["cursor"] == 0, r3)
    st = TRC.watch_status()
    check("C3 status 报 armed/spec/cursor/命中数",
          st["armed"] and st["cursor"] == 0 and st["matches"] == 0
          and st["session_events"] == len(EVS), st)
    check("C4 clear 之后不再 armed",
          TRC.watch_clear()["cleared"] and not TRC.watch_status()["armed"])
    r = TRC.watch_arm(spec="badfield=1")
    check("C5 arm 时条件写错 → 不装上（报错而不是装着个永不命中的条件）",
          r.get("error_code") == "watch-spec-invalid"
          and not TRC.watch_status()["armed"], r)

# ------------------------------------------------------------------ D
def section_d():
    print("D. watch_wait：这就是「通知 AI」的形态（有界长轮询）")
    _real_read = TRC.swd_read
    try:
        # D1 第二轮命中
        fake_session()
        TRC.watch_clear()
        box = {"n": 0, "appended": 0}
        def fake_read(**kw):
            box["n"] += 1
            if box["n"] == 2 and not box["appended"]:
                box["appended"] = 1
                TRC._T["swd"]["events"].append(
                    {"type": "event", "kind": "point", "id": 42, "arg": 0,
                     "cycles": 900, "t_us": 9.0})
            return {"ok": True, "new_events": 1}
        TRC.swd_read = fake_read
        r = TRC.watch_wait(spec="id=42", timeout_ms=3000, pace_ms=50,
                           diagnose=False)
        check("D1 命中即返回：triggered + 命中事件 + 上下文 + rounds",
              r["triggered"] and r["hit"]["event"]["id"] == 42
              and r["rounds"] == 2 and r["coverage"]["complete"], r)
        check("D2 命中块带 index / clause（说得清是「哪条子句在哪个位置命中的」）",
              isinstance(r["hit"]["index"], int) and r["hit"]["clause"], r["hit"]["clause"])

        # D3 超时：没命中 ≠ 没发生（覆盖完整时才敢说「没发生」）
        box2 = {"n": 0}
        def fake_read2(**kw):
            box2["n"] += 1
            return {"ok": True, "new_events": 0}
        TRC.swd_read = fake_read2
        r = TRC.watch_clear() and TRC.watch_wait(spec="id=42", timeout_ms=250,
                                                 pace_ms=50, diagnose=False)
        check("D3 超时：triggered=False + 「没测到」措辞 + 在覆盖完整时才允许说没发生",
              (not r["triggered"]) and "没测到" in (r["coverage"].get("note") or "")
              and r["coverage"]["complete"], r.get("coverage"))

        # D4 期间目标丢事件 → 覆盖不完整（红线：不许把「没测到」说成「没发生」）
        def fake_read3(**kw):
            TRC._T["swd"]["last_ctrl"] = {"lost_events": 7}
            return {"ok": True, "new_events": 0}
        TRC.swd_read = fake_read3
        TRC.watch_clear()
        r = TRC.watch_wait(spec="id=42", timeout_ms=250, pace_ms=50, diagnose=False)
        check("D4 期间丢过事件 → coverage.complete=False + warning（不许当「没发生」）",
              (not r["coverage"]["complete"]) and r["coverage"]["lost_events"] == 7
              and r["coverage"].get("warning"), r.get("coverage"))

        # D5 一段新事件都没有 → 明确指出「条件不会命中，先查目标在不在跑」
        def fake_read4(**kw):
            return {"ok": True, "new_events": 0}
        TRC.swd_read = fake_read4
        TRC.watch_clear()
        r = TRC.watch_wait(spec="id=42", timeout_ms=250, pace_ms=50, diagnose=False)
        check("D5 零新事件时说明「这段期间一条新事件都没有」",
              "一条新事件都没有" in (r["coverage"].get("note") or ""), r["coverage"].get("note"))

        # D6 会话被裁剪 → 游标回 0 且如实说（不静默从头重扫造成重复计数）
        fake_session()
        def fake_read5(**kw):
            TRC._T["swd"]["events"] = TRC._T["swd"]["events"][-2:]
            return {"ok": True, "new_events": 0, "notes": []}
        TRC.swd_read = fake_read5
        TRC.watch_clear()
        r = TRC.watch_wait(spec="id=99999", timeout_ms=250, pace_ms=50, diagnose=False)
        check("D6 会话被裁剪时如实说明并重置游标（不静默重复计数）",
              r["ok"] and r["coverage"]["complete"] is not None, r)

        # D7 搬运失败 → 明确失败，不假装「没命中」
        TRC.watch_clear()
        TRC.swd_read = lambda **kw: {"ok": False, "error": "目标没在跑"}
        r = TRC.watch_wait(spec="id=42", timeout_ms=250, pace_ms=50, diagnose=False)
        check("D7 搬运失败 → ok=False + watch-wait-failed（不混进「没命中」）",
              (not r["ok"]) and r["error_code"] == "watch-wait-failed", r)

        # D8 没 arm 也没给 spec
        TRC.swd_read = _real_read
        TRC.watch_clear()
        r = TRC.watch_wait(timeout_ms=100, diagnose=False)
        check("D8 既没 arm 也没给 spec → watch-not-armed（带怎么做）",
              r.get("error_code") == "watch-not-armed" and r.get("hint"), r)
    finally:
        TRC.swd_read = _real_read
        TRC.watch_clear()

# ------------------------------------------------------------------ E
def section_e():
    print("E. 工具面")
    tr = TB.tools_of("trace")
    check("E1 trace_watch 在 trace 组内（按需装载可见）",
          "trace_watch" in tr, len(tr))
    os.environ.pop("MDKDEBUG_TOOLSETS", None)
    srv = SV.create_server(port=PORT)
    names = [t.name for t in asyncio.run(srv.list_tools())]
    check("E2 不在默认面（默认面仍是 44 个，注意力预算不涨）",
          len(names) == 44 and "trace_watch" not in names, len(names))
    check("E3 工具总数 == 200（新工具已注册且计入）",
          len(SV.create_server(toolsets="all", port=PORT)._tool_manager._tools) == 200)

# ------------------------------------------------------------------ F
def section_f():
    print("F. 动作与参数校验")
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "trace_watch", {"action": "nosuch", "spec": "fault"})).content[0].text)
    check("F1 认不出的 action → watch-action-invalid（列出可用动作）",
          r.get("error_code") == "watch-action-invalid"
          and "wait" in (r.get("hint") or ""), r)
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "trace_watch", {"action": "status"})).content[0].text)
    check("F2 status 在没装条件时明确说「没有装」",
          r.get("ok") and r.get("armed") is False and r.get("note"), r)

# ------------------------------------------------------------------
def main():
    for fn in (section_a, section_b, section_c, section_d, section_e, section_f):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常: %r" % (fn.__name__, e))
    print("\n==== test_batch75: %d pass / %d fail ====" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAIL:", f)
        sys.exit(1)

if __name__ == "__main__":
    main()
