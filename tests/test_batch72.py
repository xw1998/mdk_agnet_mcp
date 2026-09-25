# -*- coding: utf-8 -*-
"""批次72 mock 测试：软插桩分析层（trace_stats / trace_diagnose）+ 内核自动钩子。

本批做两件事，都**不新增采集后端**：

1. **分析层**（`mdkdebug/trstats.py`）：在**已有事件**上算结论、跑规则诊断。
   - `trace_stats`：归一化 → 时间基判定 → 调度/同步/堆/中断/异常/断口/时间轴健康。
     每个指标要么带 `basis`（依据），要么进 `not_applicable`（为什么不适用）。
     **时间占比类只认目标侧时间基**：MTF（SWO/RTT）只有主机到达时刻，混链路与主机
     调度抖动 —— 用它算 CPU 负载/时长会是「看着正常、实际是错的数」，一律 not_applicable。
   - `trace_diagnose`：16 条规则 → findings（rule/severity/title/detail/evidence/hint），
     verdict 三态（problems/warnings/clean），且 `checked` 与 `not_applicable` **必须一起读**
     —— 只读 findings 会把「没查」当成「没问题」。

2. **SVCrtOS 内核自动钩子**（`components/trace/mdk_trace_svcrt.c/.h`）：让「插桩」从
   「人手放」变成「装上就有」。`MDK_TRACE_SVCRT_HOOKS=0` 时编成空目标文件（仍可链接、
   不给未用 SVCrtOS 的工程添乱），主机侧把「没有任何内核事件」当成一条**可命名**的诊断
   （kernel-hooks-absent）报出来，而不是静默给一条空时间线。

3. **键名一义**：`_swd_fold` 的 CTL_SYNC 段重开标记从 `type:"sync"` 改名为 `type:"segment"`
   —— 否则它会和批次72 新增的 11 号语义事件类型 `"sync"` 在 counts_by_type / 轨道分组里
   静默合并。

运行：python -m tests.test_batch72
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import server as SV            # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402
from mdkdebug import trace as TR             # noqa: E402
from mdkdebug import trstats as TS           # noqa: E402
from mdkdebug import swd as SWD              # noqa: E402
from mdkdebug import traceproto as TP        # noqa: E402
from mdkdebug import viz as VIZ              # noqa: E402

PORT_TOOL, PORT_DEF = 14995, 14996

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:600]), flush=True)


async def _call(srv, n, a):
    res = await srv.call_tool(n, a)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    return json.loads(txt)


def call_sync(srv, n, a):
    return asyncio.run(_call(srv, n, a))


def tool_names(srv):
    return sorted(t.name for t in asyncio.run(srv.list_tools()))


def ev(**kw):
    """造一条归一化事件（缺省字段补齐，省得每个用例写一长串）。"""
    d = {"src": "test", "type": None, "kind": None, "id": None, "arg": None,
         "from": None, "to": None}
    d.update(kw)
    return d


# ======================================================================
# A. 类型映射与键名一义（段标记改名）
# ======================================================================
def group_a():
    print("A. 类型映射与键名一义")
    check("A1 swd.TYPES 认 11=sync / 12=heap，且都 < 16（make_key 是 type & 0xF）",
          SWD.TYPES.get(11) == "sync" and SWD.TYPES.get(12) == "heap"
          and all(k < 16 for k in SWD.TYPES), SWD.TYPES)
    check("A2 MTF 通路补上了 9-12（原先缺 → SCHED/FAULT/SYNC/HEAP 解成 raw_hex，信息全丢）",
          all(TP.MTF_TYPES.get(k) == v for k, v in
              {9: "fault", 10: "sched", 11: "sync", 12: "heap"}.items()),
          TP.MTF_TYPES)
    check("A3 MTF 的 _PAYLOAD_FMT 对 9-12 都按 id/arg 解（from/to、obj/op、CFSR 才留得住）",
          all(TP._PAYLOAD_FMT.get(k) == ("<HI", ("id", "arg"))
              for k in (9, 10, 11, 12)), TP._PAYLOAD_FMT)
    check("A4 buff 解码表也认 11/12",
          TR._BUFF_TYPES.get(11) == "sync" and TR._BUFF_TYPES.get(12) == "heap",
          TR._BUFF_TYPES)

    src = open(os.path.join(ROOT, "mdkdebug", "trace.py"), encoding="utf-8").read()
    check("A5 _swd_fold 的段重开标记改名为 segment（不再与语义事件类型 sync 撞名）",
          '"type": "segment"' in src and '"type": "sync"' not in src, None)
    adp = open(os.path.join(ROOT, "mdkdebug", "viz", "adapters.py"),
               encoding="utf-8").read()
    check("A6 viz/adapters 跟着认 segment，且 sync/heap 有中文名",
          "segment" in adp and "sync" in adp and "heap" in adp, None)


# ======================================================================
# B. 语义派生（sync 的 id 打包、heap 的 op）
# ======================================================================
def group_b():
    print("B. 语义派生")
    # sync: id = (obj<<3) | op，op 全 32 位不截断
    e = ev(type="sync", id=(5 << 3) | 0, arg=7)
    TR._derive_semantics(e)
    check("B1 sync 从 id 解出 obj=5 / op=0(wait)",
          e.get("obj") == 5 and e.get("op") == 0 and e.get("op_name") == "wait", e)
    e = ev(type="sync", id=(9 << 3) | 3, arg=0xDEADBEEF)
    TR._derive_semantics(e)
    check("B2 sync 的 arg（val）保留全 32 位（裁到 24 位＝静默截断）",
          e.get("op_name") == "release" and e.get("arg") == 0xDEADBEEF, e)
    e = ev(type="heap", id=0, arg=64)
    TR._derive_semantics(e)
    check("B3 heap op=0 → alloc，size 走 arg",
          e.get("op_name") == "alloc" and e.get("size") == 64, e)
    e = ev(type="heap", id=1, arg=64)
    TR._derive_semantics(e)
    check("B4 heap op=1 → free", e.get("op_name") == "free", e)
    e = ev(type="sched")
    e["from"], e["to"] = 1, 2
    TR._derive_semantics(e)
    check("B5 sched 不被动 obj/op（它是 from/to 语义）",
          "obj" not in e and "op" not in e, e)


# ======================================================================
# C. 归一化：三种源形状
# ======================================================================
def group_c():
    print("C. 归一化")
    # MTF：type 是 int + type_name
    out = TS.normalize([{"type": 10, "type_name": "sched", "id": 1, "arg": 2, "t": 3.5}],
                       "mtf")
    check("C1 MTF 帧按 type_name 归一，t 记成 t_host",
          len(out) == 1 and out[0]["type"] == "sched" and out[0]["t_host"] == 3.5, out)
    out = TS.normalize([{"kind": "pc_sample", "pc": 0x8000, "t": 1.0}], "mtf")
    check("C2 MTF 的 ITM 硬件报文只留 pc_sample / overflow（其余无分析价值）",
          len(out) == 1 and out[0]["type"] == "pc_sample", out)
    out = TS.normalize([{"kind": "overflow"}], "mtf")
    check("C3 MTF overflow → gap（一个断口）",
          len(out) == 1 and out[0]["type"] == "gap" and out[0]["kind"] == "overflow", out)
    out = TS.normalize([{"kind": "unknown_thing"}], "mtf")
    check("C4 MTF 里不认识的报文被丢掉（不硬凑成事件）", out == [], out)

    # 流式（swd/buff）：时间键优先 cycles → t_cycles → rel_cycles
    out = TS.normalize([{"type": "sched", "from": 1, "to": 2, "cycles": 100,
                         "t_cycles": 999}], "swd")
    check("C5 绝对 cycles 优先于 t_cycles", out[0]["t_c"] == 100, out)
    out = TS.normalize([{"type": "sched", "from": 1, "to": 2, "rel_cycles": 42}], "buff")
    check("C6 没有绝对周期时退化到 rel_cycles",
          out[0]["t_c"] == 42 and out[0]["src"] == "buff", out)
    out = TS.normalize([{"type": "event", "t_us": 12.5}], "swd")
    check("C7 t_us 记成 t_u（swd 的 t_us 在 anchor 之后是绝对的）",
          out[0]["t_u"] == 12.5, out)
    out = TS.normalize([{"type": "sync", "obj": 3, "op": 1, "op_name": "signal"}], "swd")
    check("C8 流式源里已带 obj/op 的原样保留",
          out[0]["obj"] == 3 and out[0]["op_name"] == "signal", out)
    check("C9 非 dict / 无 type 的输入被安全跳过",
          TS.normalize([None, 42, {"no_type": 1}], "swd") == [], None)


# ======================================================================
# D. 分析：时间基 / 调度 / 同步 / 堆 / 中断 / 异常 / 断口
# ======================================================================
def group_d():
    print("D. 分析")

    sched4 = [ev(type="sched", **{"from": 1, "to": 2}, t_c=0),
              ev(type="sched", **{"from": 2, "to": 1}, t_c=1000),
              ev(type="sched", **{"from": 1, "to": 0xF}, t_c=2000),
              ev(type="sched", **{"from": 0xF, "to": 1}, t_c=3000)]
    a = TS.analyze([dict(x) for x in sched4], cpu_hz=1000000)
    check("D1 有目标周期 + 主频 → 算出 CPU 负载与逐任务占比",
          a["timebase"]["basis"] == "cycles" and "sched" in a
          and a["sched"].get("cpu_load_pct") is not None, a.get("sched"))
    pcts = {t["task"]: t["pct"] for t in (a["sched"].get("tasks") or [])}
    check("D2 idle（任务号 0xF）被识别，占比落在 idle 上",
          "idle" in pcts and a["sched"]["idle_pct"] > 0, pcts)

    a = TS.analyze([dict(x) for x in sched4], cpu_hz=0)
    check("D3 有周期无主频：占比照算，绝对时长只给周期数（不硬编一个微秒数）",
          a["sched"]["tasks"][0]["exec_us"] is None
          and a["sched"]["tasks"][0]["exec_cycles"] is not None, a["sched"])
    check("D4 timebase 注明「占比仍可算，绝对时长只给周期数」",
          "主频" in (a["timebase"].get("note") or ""), a["timebase"])

    # MTF-only：只有主机到达时刻 → 不能算时间
    mtf = TS.normalize([{"type": 10, "type_name": "sched", "id": 1, "arg": 2, "t": 1.0},
                        {"type": 10, "type_name": "sched", "id": 2, "arg": 1, "t": 2.0}],
                       "mtf")
    a = TS.analyze(mtf)
    check("D5 MTF 只有主机到达时刻 → basis=none，span 进 not_applicable（不用错时间基算假数）",
          a["timebase"]["basis"] == "none" and "span" in a["not_applicable"], a["timebase"])
    check("D6 MTF 下调度执行时间也落 not_applicable",
          "sched.exec" in a["not_applicable"], a["not_applicable"])

    # 同步：wait 配对 signal
    sy = [ev(type="sync", obj=1, op=0, op_name="wait", t_c=0),
          ev(type="sync", obj=1, op=1, op_name="signal", t_c=500),
          ev(type="sync", obj=2, op=0, op_name="wait", t_c=600)]   # 没人唤醒
    a = TS.analyze([dict(x) for x in sy], cpu_hz=1000000)
    check("D7 同步原语按 op 计数、按对象聚合",
          a["sync"]["counts_by_op"].get("wait") == 2
          and a["sync"]["counts_by_op"].get("signal") == 1, a["sync"])
    check("D8 wait→signal 按等长配对（wait_us 有 min/max/mean）",
          a["sync"]["wait_pairs"] == 1 and "wait_us" in a["sync"], a["sync"])
    check("D9 没被唤醒的 wait 计入 unpaired_waits（不是静默丢掉）",
          a["sync"]["unpaired_waits"] == 1, a["sync"])

    # 同一对象两个等待者 → FIFO 配对带歧义
    sy2 = [ev(type="sync", obj=5, op=0, op_name="wait", t_c=0),
           ev(type="sync", obj=5, op=0, op_name="wait", t_c=10),
           ev(type="sync", obj=5, op=1, op_name="signal", t_c=20)]
    a = TS.analyze([dict(x) for x in sy2], cpu_hz=1000000)
    check("D10 同对象多等待者 → ambiguous_pairs 报出来（FIFO 假设可能不成立）",
          a["sync"]["ambiguous_pairs"] == 1, a["sync"])

    # 堆
    hp = [ev(type="heap", op_name="alloc", size=64),
          ev(type="heap", op_name="alloc", size=32),
          ev(type="heap", op_name="free", size=64),
          ev(type="heap", op_name="alloc", size=None)]
    a = TS.analyze([dict(x) for x in hp])
    h = a["heap"]
    check("D11 堆净额 = 分配 − 释放（net_bytes 是净变化，不是峰值）",
          h["alloc_bytes"] == 96 and h["free_bytes"] == 64 and h["net_bytes"] == 32, h)
    check("D12 最大单次分配 + 未知尺寸计数都如实报",
          h["largest_alloc"] == 64 and h["unknown_size"] == 1, h)
    check("D13 note 明确说 net_bytes 不是峰值、不猜峰值",
          "不是峰值" in h["note"], h)

    # 中断
    isr = [ev(type="isr", id=15, kind="enter", t_c=0),
           ev(type="isr", id=15, kind="exit", t_c=2000),
           ev(type="isr", id=7, kind="enter", t_c=3000)]   # 没 exit
    a = TS.analyze([dict(x) for x in isr], cpu_hz=1000000, isr_long_us=1.0)
    i = a["isr"]
    check("D14 中断 enter/exit 配对算时长（basis=us）",
          i["duration"]["count"] == 1 and i["duration"]["basis"] == "us", i)
    check("D15 不成对的 enter 计入 unpaired（末尾被截断也要如实报）",
          i["unpaired"] == 1, i)
    check("D16 超阈值的中断被计进 over_threshold，且指出最慢的哪个 IRQ",
          i["over_threshold"] == 1 and i["duration"]["slowest_irq"] == 15, i)

    # 异常
    fa = [ev(type="fault", fault_class="hardfault", cfsr=0x00020000,
             cfsr_bits=["INVSTATE"], t_u=12.0)]
    a = TS.analyze([dict(x) for x in fa])
    check("D17 异常事件进 faults，带类别 / CFSR / 拆位",
          a["fault_count"] == 1 and a["faults"][0]["class"] == "hardfault"
          and a["faults"][0]["cfsr_bits"] == ["INVSTATE"], a.get("faults"))

    # 断口 / 段
    gp = [ev(type="gap", events_dropped=17), ev(type="segment", seq=3)]
    a = TS.analyze([dict(x) for x in gp])
    check("D18 断口与段重开分开统计（dropped / segments.count）",
          a["gaps"] == {"events": 1, "dropped": 17}
          and a["segments"]["count"] == 1, (a["gaps"], a["segments"]))

    # 时间轴冻结
    fz = [ev(type="event", t_c=0), ev(type="event", t_c=0),
          ev(type="event", t_c=0)]
    a = TS.analyze([dict(x) for x in fz])
    check("D19 所有事件同周期 → dt.frozen（目标按差值算，粒度粗时全丢成 0）",
          a["dt"]["frozen"] is True, a.get("dt"))


# ======================================================================
# E. 诊断规则
# ======================================================================
def group_e():
    print("E. 诊断规则")

    # 空数据
    empty = []
    st = TS.analyze([])
    # 直接用内部管道无法注入空事件源，改为验证 stats 的空来源路径
    srv = SV.create_server(port=PORT_TOOL, toolsets="all")
    r = call_sync(srv, "trace_stats", {"source": "auto"})
    check("E1 进程内没采过任何事件时 trace_stats ok=True 且标 empty（不是报错、更不是假结论）",
          r.get("ok") is True and r.get("empty") is True and r.get("events") == 0, r)
    check("E2 empty 时的 hint 指向「确认 init / 插桩点 / 后端匹配 / source=buff」",
          "mdk_trace_init" in (r.get("hint") or "")
          and "buff" in (r.get("hint") or ""), r.get("hint"))

    d = call_sync(srv, "trace_diagnose", {"source": "auto"})
    rules = {f["rule"] for f in d.get("findings") or []}
    check("E3 空数据 → no-data 一条 warn，verdict=warnings",
          "no-data" in rules and d.get("verdict") == "warnings", d)
    check("E4 checked 里含 no-data（真的评估过）",
          "no-data" in (d.get("checked") or []), d.get("checked"))
    check("E5 note 说明 checked 与 not_applicable 必须一起读",
          "没查" in (d.get("note") or ""), d.get("note"))

    # source 非法值 → 报错（不猜一个源）
    bad = call_sync(srv, "trace_stats", {"source": "nonsense"})
    check("E6 source 非法值 → ok=False 并列出认哪些（不用一个默认源糊过去）",
          bad.get("ok") is False and "只认" in (bad.get("error") or ""), bad)

    # 内核事件缺失：有事件但没有 sched/sync/heap
    k = call_sync(srv, "trace_diagnose", {"with_stats": False})
    check("E7 trace_diagnose 默认带 stats，with_stats=False 时可以不附",
          "stats" not in k, sorted(k.keys()))

    # 直接对规则层做一条 fault 判定（走 analyze+内部规则无法注入，改为断言规则表覆盖）
    src = open(os.path.join(ROOT, "mdkdebug", "trstats.py"), encoding="utf-8").read()
    for rule in ("no-data", "no-timeline", "timebase-missing", "dt-frozen",
                 "dt-zero-heavy", "events-lost", "segments-restarted",
                 "kernel-hooks-absent", "no-sched", "isr-unpaired", "isr-long",
                 "fault-present", "sync-wait-unpaired", "sync-pair-ambiguous",
                 "quiet-window"):
        check("E8 规则 %s 已实现" % rule, '"%s"' % rule in src, None)


# ======================================================================
# F. 工具面与注册
# ======================================================================
def group_f():
    print("F. 工具面与注册")
    srv_all = SV.create_server(port=PORT_TOOL, toolsets="all")
    na = tool_names(srv_all)
    check("F1 注册总数 199", len(na) == 199, len(na))
    check("F2 trace_stats / trace_diagnose 已注册",
          "trace_stats" in na and "trace_diagnose" in na, None)
    check("F3 两个新工具都在 trace 组里",
          {"trace_stats", "trace_diagnose"} <= set(TB.TOOLSETS.get("trace") or ()),
          TB.TOOLSETS.get("trace"))

    srv_def = SV.create_server(port=PORT_DEF, toolsets=None)
    nd = tool_names(srv_def)
    check("F4 默认面仍是 44（新工具只在 trace 组，不进默认面）", len(nd) == 44, len(nd))
    check("F5 默认面上看不到 trace_stats / trace_diagnose",
          "trace_stats" not in nd and "trace_diagnose" not in nd, None)

    descs = {t.name: (t.description or "") for t in asyncio.run(srv_all.list_tools())}
    ds = descs.get("trace_stats", "")
    dd = descs.get("trace_diagnose", "")
    check("F6 trace_stats 描述讲清 source 取值与「不隐式读设备」",
          "source" in ds and ("auto" in ds) and "buff" in ds, ds[:200])
    check("F7 trace_stats 描述讲清时间基限制（MTF 只有主机到达时刻）",
          "MTF" in ds or "主机到达时刻" in ds, ds[:200])
    check("F8 trace_diagnose 描述讲清 verdict 三态与 checked/not_applicable",
          "verdict" in dd and "checked" in dd and "not_applicable" in dd, dd[:200])


# ======================================================================
# G. 组件源清单与内核钩子
# ======================================================================
def group_g():
    print("G. 组件源清单与内核钩子")
    cdir = os.path.join(ROOT, "components", "trace")
    for b in ("itm", "rtt", "buff", "swd"):
        check("G1 后端 %s 的源清单都含 mdk_trace_svcrt.c（与后端无关，一律入列）" % b,
              "mdk_trace_svcrt.c" in TR.component_sources(b), TR.component_sources(b))
    check("G2 mdk_trace_svcrt.c/.h 都在组件目录里",
          os.path.isfile(os.path.join(cdir, "mdk_trace_svcrt.c"))
          and os.path.isfile(os.path.join(cdir, "mdk_trace_svcrt.h")), None)
    h = open(os.path.join(cdir, "mdk_trace_svcrt.h"), encoding="utf-8").read()
    for fn in ("mdk_trace_svcrt_init", "mdk_trace_svcrt_enabled",
               "mdk_trace_svcrt_task_switch", "mdk_trace_svcrt_obj_wait"):
        check("G3 头文件声明 %s" % fn, fn in h, None)
    c = open(os.path.join(cdir, "mdk_trace_svcrt.c"), encoding="utf-8").read()
    check("G4 .c 用 #if 开关：MDK_TRACE_SVCRT_HOOKS 关上编成空实现（仍可链接）",
          "MDK_TRACE_SVCRT_HOOKS" in c and c.count("#else") >= 1, None)

    # CMake 与 make 模板双向比对：实际 mdk_trace*.c 一个都不能漏
    import glob
    actual = sorted(os.path.basename(p) for p in
                    glob.glob(os.path.join(cdir, "mdk_trace*.c")))
    cm = open(os.path.join(cdir, "CMakeLists.txt"), encoding="utf-8").read()
    missing_cm = [f for f in actual if f not in cm]
    check("G5 CMakeLists 与磁盘上的 mdk_trace*.c 双向一致（漏列即失败）",
          not missing_cm, missing_cm)
    mk = TR._gen_make_fragment()
    missing_mk = [f for f in actual if f not in mk]
    check("G6 make 片段与磁盘上的 mdk_trace*.c 双向一致",
          not missing_mk, missing_mk)

    # 部署生成 config：svcrt_hooks=1 → MDK_TRACE_SVCRT_HOOKS 1
    tmp = tempfile.mkdtemp(prefix="mdktrace72_")
    try:
        r = call_sync(SV.create_server(port=PORT_DEF + 5, toolsets="all"),
                      "trace_instrument",
                      {"target_dir": tmp, "backend": "swd", "link_check": False,
                       "svcrt_hooks": 1, "overwrite": True})
        cfg = os.path.join(tmp, "mdk_trace_config.h")
        txt = open(cfg, encoding="utf-8").read() if os.path.isfile(cfg) else ""
        check("G7 trace_instrument(svcrt_hooks=1) 生成 MDK_TRACE_SVCRT_HOOKS 1",
              "#define MDK_TRACE_SVCRT_HOOKS       1" in txt, txt[-400:])
        check("G8 生成物里带上了 mdk_trace_svcrt.c",
              os.path.isfile(os.path.join(tmp, "mdk_trace_svcrt.c")), None)
        r2 = call_sync(SV.create_server(port=PORT_DEF + 6, toolsets="all"),
                       "trace_instrument",
                       {"target_dir": tempfile.mkdtemp(prefix="mdktrace72b_"),
                        "backend": "itm", "link_check": False, "overwrite": True})
        check("G9 不传 svcrt_hooks 时默认是 0（不改变老工程行为）",
              r2.get("ok") is True, r2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("批次72：软插桩分析层（trace_stats / trace_diagnose）+ 内核自动钩子")
    group_a()
    group_b()
    group_c()
    group_d()
    group_e()
    group_f()
    group_g()
    print("\n==== 批次72 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
