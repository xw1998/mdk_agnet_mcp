# -*- coding: utf-8 -*-
"""批次59 mock 测试：可视化（view_render / view_guide）——把采集结果套路化成网页。

为什么要测这一层：它的价值全在「AI 不必再手写 HTML」——所以真正要守住的是
**三件事**，任何一件坏了，工具就退回成「又一种会骗人的输出」：

  1. **认数据不认人**：采集工具的返回原样丢进来就要能认出来；认不出**必须报错**，
     不能给一张空图（空图会被读成「这段时间什么都没发生」，比报错更坏）。
  2. **页面是单文件、离线、无外部依赖**：gitee 上只能预览源码，用户拿到的是一个
     html，如果里面引了 CDN/字体/图片，离线打开就是白板。
  3. **边界写在页面上**：图上没有的 = 没被记录，不等于没发生；scope 横轴是主机
     轮询时刻不是目标执行时刻。这些「说明不了什么」必须进 limits，不能只留在工具描述里。

  A 数据识别：events/recent/by_function/hot/items/timeline 的签名判断与优先级
  B 适配器：时间线（泳道/切换/中断/异常/丢失断口）、波形（通道类型推断）、排行、函数时间线
  C 直填 spec：timeline/scope/bars/report 的最小可用形态与体检
  D 渲染产物：单文件无外链、`</script>` 转义、写盘、data_file 三条错误路径
  E 工具层：注册与归组、注解、调用、错误码与统一信封、ERROR_CODES 登记
  F 文档同步：README / SKILL 提到 view_render 与工具数

运行：python -m tests.test_viz
"""
import os
import sys
import json
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import errors as ERR          # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import viz as VZ              # noqa: E402
from mdkdebug.viz import adapters as AD     # noqa: E402
from mdkdebug.viz import page as PG         # noqa: E402

PORT = 15499

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def js(o):
    return json.dumps(o, ensure_ascii=False, default=str)

def call(srv, name, args):
    r = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}

# ======================================================================
# 样本数据（形状照抄真机返回，值缩小到能一眼看懂）
# ======================================================================
SWD = {
    "ctrl": {"cpu_hz": 16000000, "lost_events": 0, "ts_shift": 0},
    "events": [
        {"type": "sched", "kind": "sw", "from": 0, "to": 1, "t_us": 0, "id_name": None},
        {"type": "sched", "kind": "sw", "from": 1, "to": 2, "t_us": 1000},
        {"type": "isr", "kind": "enter", "id": 15, "t_us": 1250, "id_name": "SysTick"},
        {"type": "isr", "kind": "exit", "id": 15, "t_us": 1350},
        {"type": "fault", "kind": "point", "id": 3, "t_us": 2000,
         "fault_class": "HardFault", "cfsr": 0x400},
        {"type": "sync", "kind": "point", "seq": 1, "t_us": 2500},
        {"type": "gap", "kind": "lost", "t_us": 2600, "events_dropped": 40},
        {"type": "sched", "kind": "sw", "from": 2, "to": 0, "t_us": 3000},
    ],
    "counts_by_type": {"sched": 3, "isr": 2, "fault": 1, "sync": 1},
    "read_meta": {"unstable": True},
    "warnings": ["TS_OFF：本次没读到时间戳，横轴按事件序号"],
}

# 无时间戳的 SWD（TS_OFF）：横轴必须退回事件序号，且写进 limits
SWD_NOTIME = {"ctrl": {"cpu_hz": 16000000}, "events": [
    {"type": "sched", "from": 0, "to": 1},
    {"type": "sched", "from": 1, "to": 0},
    {"type": "isr", "kind": "enter", "id": 14},
]}

SCOPE = {
    "recent": [
        {"t": 0.00, "task": 0, "state": 1, "adc": 100},
        {"t": 0.01, "task": 1, "state": 2, "adc": 120},
        {"t": 0.02, "task": 1, "state": 3, "adc": 90},
        {"t": 0.03, "task": 0, "state": 1, "adc": 110},
        {"t": 0.04, "task": 1, "state": 2, "adc": 130},
        {"t": 0.05, "task": 0, "state": 3, "adc": 105},
        {"t": 0.06, "task": 1, "state": 1, "adc": 115},
        {"t": 0.07, "task": 0, "state": 2, "adc": 125},
        {"t": 0.08, "task": 1, "state": 3, "adc": 95},
    ],
    "by_var": {"adc": {"min": 90, "max": 130, "changes": 3}},
    "misses": 2, "require_halt": True, "effective_hz": 100.0,
    "vars": ["task", "state", "adc"],
}

BARS_FN = {"by_function": [{"function": "main", "samples": 50, "percent": 50.0},
                           {"function": "led_task", "samples": 30, "percent": 30.0}],
           "samples": 100, "sampler_active": True}
BARS_HOT = {"hot": [{"name": "HardFault_Handler", "hits": 3},
                    {"name": "SysTick_Handler", "hits": 12}]}
BARS_ITEMS = {"items": [{"group": "A", "stat_slot": 1, "count": 2,
                         "total_ms": 1.5, "min_ms": 0.5, "max_ms": 1.0, "avg_ms": 0.75}],
              "link": "keil"}

REC = {"timeline": [{"kind": "enter", "func": "main", "cyc": 0},
                    {"kind": "enter", "func": "led_task", "cyc": 1600},
                    {"kind": "exit", "func": "led_task", "cyc": 3200},
                    {"kind": "exit", "func": "main", "cyc": 4800}],
       "cpu_hz": 16000000, "events_dropped": 0}

# ======================================================================
def section_a():
    """A. 认数据不认人：签名判断与优先级。"""
    print("A. 数据识别（detected_view）")
    dv = VZ.detected_view
    check("A1 events 列表 -> timeline",
          dv(SWD) == "timeline", dv(SWD))
    check("A2 裸事件数组 -> timeline",
          dv(SWD["events"]) == "timeline", dv(SWD["events"]))
    check("A3 trace_scope_read 的返回（recent）-> scope",
          dv(SCOPE) == "scope", dv(SCOPE))
    check("A4 {series:{...}} -> scope",
          dv({"series": {"t": [0, 1], "v": {"a": [1, 2]}}}) == "scope")
    # pcsample 的结果里 samples 是个**整数**（采样条数），不是序列——
    # 若先判 scope，它会被抢走并画出一条空波形。
    check("A5 by_function 优先于 scope（pcsample 的 samples 是 int）",
          dv({"by_function": [], "samples": 123, "hot": [{"name": "x", "hits": 1}]}) == "bars")
    check("A6 hot -> bars", dv(BARS_HOT) == "bars")
    check("A7 items -> bars", dv(BARS_ITEMS) == "bars")
    check("A8 trace_record 的 timeline -> timeline",
          dv(REC) == "timeline", dv(REC))
    check("A9 认不出返回空串（不硬猜）",
          dv({"foo": "bar"}) == "" and dv("hello") == "" and dv(None) == "")
    check("A10 显式 kind 优先", dv({"kind": "report", "events": SWD["events"]}) == "report")


def section_b():
    """B. 适配器：把采集结果折成渲染模型。"""
    print("B. 适配器")
    # --- 时间线 ---
    r = VZ.adapt(SWD, view="auto", title="任务切换")
    check("B1 swd 返回 -> timeline 模型", r.get("ok") and r["model"]["kind"] == "timeline", r)
    m = r["model"] if r.get("ok") else {}
    tr = {t["id"]: t for t in (m.get("tracks") or [])}
    # 泳道按「切成谁」分组。注意 0 号任务的最后一段（最后一条 sched 到 tmax）宽度为 0，
    # 会被丢掉——这是**故意的**：凭空延长一段区间等于宣称「它一直跑到底」。
    check("B2 有切换去向的上下文各自成一条泳道（本例 1、2 两条）",
          sum(1 for k in tr if k.startswith("lane-")) == 2, sorted(tr))
    check("B3 泳道是 spans 类型且区间非空",
          any(t["type"] == "spans" and t.get("spans") for t in tr.values()), tr)
    sw = tr.get("switch")
    check("B4 切换带是 marks，且每条都带「切向谁」",
          bool(sw) and sw["type"] == "marks" and len(sw["targets"]) == len(sw["marks"]),
          sw)
    check("B5 中断进出成对 -> intervals",
          any(t["type"] == "intervals" and t.get("pairs") for t in tr.values()),
          [(k, v["type"]) for k, v in tr.items()])
    check("B6 异常进 markers（level=bad）",
          any(mk.get("level") == "bad" for mk in (m.get("markers") or [])),
          m.get("markers"))
    check("B7 丢失断口进 gaps",
          bool(m.get("gaps")) and "丢失" in str(m.get("badges")), m.get("gaps"))
    check("B8 badges 里报出上下文切换次数与异常次数",
          any(b["k"] == "上下文切换" for b in m.get("badges") or []) and
          any(b["k"] == "异常" for b in m.get("badges") or []), m.get("badges"))
    check("B9 read_meta.unstable / warnings 原样进 limits（不加工成结论）",
          any("TS_OFF" in str(x) for x in m.get("limits") or []), m.get("limits"))
    check("B10 时间轴口径写进 subtitle（这次有时间戳）",
          "µs" in str(m.get("subtitle") or ""), m.get("subtitle"))
    check("B11 limits 必带「图上没有的=没被记录」",
          any("没被记录" in str(x) for x in m.get("limits") or []), m.get("limits"))

    r2 = VZ.adapt(SWD_NOTIME, view="timeline")
    m2 = r2.get("model") or {}
    check("B12 没有时间戳时横轴退回事件序号，并如实写进 limits",
          r2.get("ok") and any("序号" in str(x) for x in (m2.get("limits") or [])),
          m2.get("limits"))

    # --- 波形 ---
    rs = VZ.adapt(SCOPE, view="scope")
    check("B13 scope 返回 -> scope 模型", rs.get("ok") and rs["model"]["kind"] == "scope", rs)
    ms = rs.get("model") or {}
    ch = {c["name"]: c for c in (ms.get("channels") or [])}
    check("B14 通道识别：全 0/1 -> bool、少量整数 -> enum、其余 -> analog",
          ch.get("task", {}).get("type") == "bool" and
          ch.get("state", {}).get("type") == "enum" and
          ch.get("adc", {}).get("type") == "analog",
          {k: v.get("type") for k, v in ch.items()})
    check("B15 秒 -> µs（横轴单位统一）",
          (ms.get("series", {}).get("t") or [])[:3] == [0.0, 10000.0, 20000.0],
          (ms.get("series", {}).get("t") or [])[:3])
    check("B16 by_var 的 min/max/changes 被用上",
          ch.get("adc", {}).get("min") == 90 and ch.get("adc", {}).get("max") == 130 and
          ch.get("adc", {}).get("changes") == 3, ch.get("adc"))
    check("B17 缺值和 misses 写进 limits（不装作没丢）",
          any("misses" in str(x) for x in ms.get("limits") or []) and
          any("主机轮询时刻" in str(x) for x in ms.get("limits") or []), ms.get("limits"))

    # --- 排行 ---
    rb = VZ.adapt(BARS_FN, view="bars")
    mb = rb.get("model") or {}
    check("B18 by_function -> bars（单位=样本）",
          rb.get("ok") and mb.get("bars", {}).get("unit") == "样本" and
          len(mb.get("bars", {}).get("items") or []) == 2, rb)
    check("B19 条目按值降序且带占比",
          [i["name"] for i in mb["bars"]["items"]] == ["main", "led_task"] and
          mb["bars"]["items"][0].get("share") is not None, mb["bars"]["items"])
    check("B20 hot -> bars（单位=命中）",
          (VZ.adapt(BARS_HOT, view="bars").get("model") or {}).get("bars", {}).get("unit") == "命中")
    rbi = VZ.adapt(BARS_ITEMS, view="bars")
    mbi = rbi.get("model") or {}
    check("B21 items -> bars（单位=ms，副标题带 n/均/峰）",
          mbi.get("bars", {}).get("unit") == "ms" and
          "均" in str(mbi["bars"]["items"][0].get("sub") or "") and
          "峰" in str(mbi["bars"]["items"][0].get("sub") or ""),
          mbi.get("bars"))
    check("B22 采样法必须自述「占比是采样命中占比，不是精确耗时」",
          any("采样" in str(x) for x in mb.get("limits") or []), mb.get("limits"))

    # --- 函数时间线 ---
    rr = VZ.adapt(REC, view="timeline")
    mr = rr.get("model") or {}
    check("B23 trace_record -> 函数时间线（cyc 换成 µs）",
          rr.get("ok") and "µs" in str(mr.get("subtitle") or ""), mr.get("subtitle"))
    check("B24 每个函数一条轨道",
          sorted(t["name"] for t in (mr.get("tracks") or [])) == ["led_task", "main"],
          mr.get("tracks"))
    check("B25 侵入式断点的时间线要自述「间隔不能当精确耗时」",
          any("侵入式" in str(x) for x in mr.get("limits") or []), mr.get("limits"))

    # --- 空数据：报错而不是空图 ---
    check("B26 events 为空 -> 报错（不画空图）",
          VZ.adapt({"events": []}, view="timeline").get("ok") is False)
    check("B27 认不出 -> view-unknown-data",
          VZ.adapt({"foo": 1}, view="auto").get("error_code") == "view-unknown-data")
    check("B28 names 写错 -> view-bad-names（不静默丢弃）",
          VZ.adapt(SWD, view="timeline", names="abc").get("error_code") == "view-bad-names")
    check("B29 names 正常解析成 id->名字",
          AD.parse_names("0x10=switch,1=led_task")["names"] == {16: "switch", 1: "led_task"})
    check("B30 names 里的坏项单独报出来",
          AD.parse_names("0x10=switch,abc")["bad"] == ["abc"],
          AD.parse_names("0x10=switch,abc"))


def section_c():
    """C. 自己写 spec（展示算法 / 自定义信号）。"""
    print("C. 直填 spec")
    spec_tl = {"kind": "timeline", "title": "算法阶段", "span": [0, 1000],
               "tracks": [{"name": "stage", "type": "spans", "spans": [[0, 300], [300, 900]]}],
               "markers": [{"t": 900, "label": "收敛", "level": "ok"}],
               "limits": ["这是算法内部计时，不是目标执行时间。"]}
    r = VZ.adapt(spec_tl, view="auto")
    check("C1 自写 timeline 可用（缺 span 也能推）",
          r.get("ok") and r["model"]["tracks"][0]["name"] == "stage", r)
    r2 = VZ.adapt({"kind": "timeline", "tracks": [{"name": "a", "type": "spans",
                                                   "spans": [[500, 800]]}]}, view="auto")
    check("C2 没给 span 时按数据最大时刻推，并写进 limits",
          r2.get("ok") and any("span" in str(x).lower() or "时刻" in str(x)
                               for x in (r2["model"].get("limits") or [])),
          (r2.get("model") or {}).get("limits"))
    r3 = VZ.adapt({"kind": "scope", "channels": [{"name": "x", "type": "analog"}],
                   "series": {"t": [0, 1000], "v": {"x": [1, 2]}}}, view="auto")
    check("C3 自写 scope 可用", r3.get("ok") and r3["model"]["kind"] == "scope", r3)
    r4 = VZ.adapt({"kind": "bars", "bars": {"unit": "ms",
                                           "items": [{"name": "a", "value": 20},
                                                     {"name": "b", "value": 10}]}}, view="auto")
    check("C4 自写 bars 可用（自动算 share）",
          r4.get("ok") and len(r4["model"]["bars"]["items"]) == 2, r4)
    r5 = VZ.adapt({"kind": "report", "verdict": {"level": "bad", "text": "丢事件"},
                   "sections": [{"h": "现象", "p": ["第 2 秒起丢事件"]},
                                {"h": "证据", "view": SWD}]}, view="auto")
    m5 = r5.get("model") or {}
    check("C5 report 的 sections 里可以直接嵌采集结果（自动认出来）",
          r5.get("ok") and m5.get("sections")[1].get("view", {}).get("kind") == "timeline",
          [s.get("view", {}).get("kind") if isinstance(s.get("view"), dict) else None
           for s in (m5.get("sections") or [])])
    r6 = VZ.adapt({"kind": "report", "sections": []}, view="auto")
    check("C6 空 sections 的 report 会写明「报告里只有标题和结论」",
          r6.get("ok") and any("sections" in str(x) for x in r6["model"]["limits"]),
          r6["model"]["limits"])
    r7 = VZ.adapt({"kind": "timeline", "tracks": "oops"}, view="auto")
    check("C7 结构不对 -> view-bad-spec / 报错",
          r7.get("ok") is False, r7)
    # 真机跑出来的三类「静默错答案」，这里钉死：
    # ① 轨道键名写成 items -> 会安静地画一张空白图（空白图=「什么都没发生」）
    r8 = VZ.adapt({"kind": "timeline",
                   "tracks": [{"name": "stage", "type": "spans", "items": [[500, 800]]}]},
                  view="auto")
    check("C8 轨道里放错键（items）-> view-bad-spec，不画空白图",
          r8.get("ok") is False and r8.get("error_code") == "view-bad-spec" and
          "spans" in str(r8.get("hint") or ""), r8)
    r9 = VZ.adapt({"kind": "timeline",
                   "tracks": [{"name": "stage", "type": "spans", "spans": ["a", "b"]}]},
                  view="auto")
    check("C9 区间不是两个数字 -> view-bad-spec",
          r9.get("ok") is False and r9.get("error_code") == "view-bad-spec", r9)
    r10 = VZ.adapt({"kind": "timeline",
                    "tracks": [{"name": "stage", "type": "spans", "spans": [[500, 800]]},
                               {"name": "mark", "type": "marks", "marks": [[100, "go"]]}]},
                   view="auto")
    bs = {b["k"] for b in (r10.get("model") or {}).get("badges") or []}
    check("C10 自写 timeline 的页眉也有数字（轨道/元素/时长）",
          r10.get("ok") and {"轨道", "元素", "时长"} <= bs, (r10.get("model") or {}).get("badges"))
    # ② items 是两个世界共用的键：显式 kind 必须优先，不能当成 Event Statistics 而给值安上 ms
    r11 = VZ.adapt({"kind": "bars", "unit": "次",
                    "items": [{"name": "led_blink", "value": 40}, {"name": "idle", "value": 10}]},
                   view="auto")
    m11 = r11.get("model") or {}
    check("C11 显式 kind=bars + items 走 spec（单位用给定的，不擅自补 ms）",
          r11.get("ok") and (m11.get("bars") or {}).get("unit") == "次", r11)
    r12 = VZ.adapt({"kind": "bars", "items": [{"name": "a", "value": 1}]}, view="auto")
    check("C12 没给单位就写明「别替它读成 ms」",
          r12.get("ok") and any("单位" in str(x) for x in (r12["model"].get("limits") or [])),
          (r12.get("model") or {}).get("limits"))
    # ③ 波形视图用不上 names，过去静默忽略
    # 真机页面上撞到的：report 一节把 p 写成字符串 -> 整页后续（含嵌图）全被吞掉
    r15 = VZ.adapt({"kind": "report", "verdict": "warn",
                    "sections": [{"h2": "结论", "p": "一切正常",
                                  "ul": "要点一", "pre": "regs = 0x0",
                                  "view": {"kind": "timeline",
                                           "tracks": [{"name": "t", "type": "marks",
                                                       "marks": [[0, "x"]]}]}},
                                 {"h": "证据", "p": ["见图"]}]}, view="auto")
    m15 = r15.get("model") or {}
    sec0 = (m15.get("sections") or [{}])[0]
    check("C15 report 段落的别名/字符串写法被归一（h2→h、p 字符串、ul→bullets、pre→code）",
          r15.get("ok") and sec0.get("h") == "结论" and sec0.get("p") == ["一切正常"] and
          sec0.get("bullets") == ["要点一"] and sec0.get("code") == "regs = 0x0" and
          isinstance(sec0.get("view"), dict), sec0)
    check("C16 verdict 给字符串按 level 收下（不会静默丢结论）",
          m15.get("verdict") == {"level": "warn", "text": ""}, m15.get("verdict"))
    r17 = VZ.adapt({"kind": "report", "sections": "oops"}, view="auto")
    check("C17 sections 不是数组 -> view-bad-spec",
          r17.get("ok") is False and r17.get("error_code") == "view-bad-spec", r17)
    r14 = VZ.adapt({"kind": "timeline",
                    "tracks": [{"name": "s", "type": "spans", "spans": [[0, 1000]]}]}, view="auto")
    check("C14 自写时间线写明时刻按微秒解释（防 ms/s 差 1000 倍）",
          r14.get("ok") and any("微秒" in str(x) for x in (r14["model"].get("limits") or [])),
          (r14.get("model") or {}).get("limits"))
    r13 = VZ.adapt({"kind": "scope", "channels": [{"name": "adc", "type": "analog"}],
                    "series": {"t": [0, 1000], "v": {"adc": [1, 2]}}},
                   view="auto", names="1=led_task")
    check("C13 波形视图下 names 用不上 -> 写进边界栏，不静默吞掉",
          r13.get("ok") and any("names" in str(x) for x in (r13["model"].get("limits") or [])),
          (r13.get("model") or {}).get("limits"))


def section_d():
    """D. 渲染产物：单文件、离线、无外链。"""
    print("D. 渲染产物")
    d = tempfile.mkdtemp(prefix="mdkviz_")
    out = os.path.join(d, "t.html")
    r = VZ.render(data=SWD, title="任务切换", out=out)
    check("D1 render 返回 ok/path/html_bytes", r.get("ok") is True and os.path.exists(r["path"]), r)
    html = open(r["path"], "r", encoding="utf-8").read()
    check("D2 页面是单文件（挂载点 + 内联样式 + 内联运行时，共 2 个 script）",
          '<div id="mdk-root">' in html and "window.__MDK_VIEW__ =" in html and
          "--bg:#0f1115" in html and len(html) > 20000 and html.count("<script") == 2,
          (len(html), html.count("<script")))
    # 外部依赖检查：CDN / 外链脚本 / 外链样式 / 图片
    ext = [tok for tok in ('src="http', "src='http", 'href="http', "href='http",
                           "<script src", "<link ", "url(http", "@import")
           if tok in html]
    check("D3 无任何外部依赖（CDN/外链 js/css/字体/图片）", not ext, ext)
    check("D4 没有网络请求（fetch/XHR/WebSocket）",
          "fetch(" not in html and "XMLHttpRequest" not in html and "WebSocket" not in html)
    check("D5 页面底部有「这说明不了什么」边界栏",
          "这说明不了什么" in html, "")
    check("D6 外部资源一个都没有（无 link/@import/url(http)）",
          "<link" not in html and "@import" not in html and "url(http" not in html,
          "")
    # 真把危险串塞进数据里试一次
    # report 的图嵌在 sections 里：顶层 counts 全 0，容易读成「报告里没图」
    rep = VZ.render(data={"kind": "report", "sections": [
        {"h2": "a", "view": {"kind": "timeline", "tracks": [{"name": "t", "type": "marks",
                                                             "marks": [[0, "x"]]}]}},
        {"h2": "b", "view": {"kind": "bars", "unit": "次", "items": [{"name": "x", "value": 1}]}}]},
        out=os.path.join(d, "rep.html"))
    cn = rep.get("counts") or {}
    check("D9 report 单独报 nested（内嵌轨道/条形），不与顶层键名混用",
          rep.get("ok") and (cn.get("nested") or {}).get("tracks") == 1 and
          (cn.get("nested") or {}).get("bars") == 1 and cn.get("tracks") == 0, cn)
    r2 = VZ.render(data={"kind": "report", "verdict": {"level": "ok", "text": "</script><b>x"},
                         "sections": [{"h": "x", "p": ["</script>"]}]},
                   out=os.path.join(d, "esc.html"))
    h2 = open(r2["path"], "r", encoding="utf-8").read()
    body = h2.split("window.__MDK_VIEW__ = ", 1)[1].split("</script>", 1)[0]
    check("D7 数据里的 `</script>` 不会截断脚本（已转义）",
          "</script>" not in body and "\\u003c/script" in body, body[:120])
    check("D8 默认输出目录是 ./mdkdebug_views/",
          VZ.default_out_dir().endswith("mdkdebug_views"), VZ.default_out_dir())
    # data_file 三条错误路径 + 正常读取
    jf = os.path.join(d, "data.json")
    with open(jf, "w", encoding="utf-8") as f:
        json.dump(SWD, f, ensure_ascii=False)
    r3 = VZ.render(data_file=jf, out=os.path.join(d, "from_file.html"))
    check("D9 data_file 可读（采集工具 out_file 的产物）", r3.get("ok") is True, r3)
    r4 = VZ.render(data_file=os.path.join(d, "nope.json"))
    check("D10 data_file 不存在 -> view-file-missing",
          r4.get("error_code") == "view-file-missing", r4)
    bad = os.path.join(d, "bad.json")
    open(bad, "w", encoding="utf-8").write("{not json")
    r5 = VZ.render(data_file=bad)
    check("D11 data_file 不是 JSON -> view-file-bad", r5.get("error_code") == "view-file-bad", r5)
    r6 = VZ.render(data=None)
    check("D12 既没 data 也没 data_file -> view-no-data",
          r6.get("error_code") == "view-no-data", r6)
    r7 = VZ.render(data=SWD, out=d)   # out 给的是目录
    check("D13 out 给目录时自动落一个文件名进去",
          r7.get("ok") and os.path.isfile(r7["path"]), r7)
    check("D14 返回值里有 counts/badges/next（AI 不必解析 html）",
          isinstance(r.get("counts"), dict) and isinstance(r.get("badges"), list)
          and isinstance(r.get("next"), list), list(r))
    # 四种视图都能出图
    okk = []
    for nm, dta in (("timeline", SWD), ("scope", SCOPE), ("bars", BARS_FN), ("report",
                    {"kind": "report", "verdict": {"level": "ok", "text": "ok"},
                     "sections": [{"h": "a", "p": ["b"]}]})):
        rr = VZ.render(data=dta, view=nm, out=os.path.join(d, nm + ".html"))
        okk.append((nm, bool(rr.get("ok")), rr.get("html_kb")))
    check("D15 四种视图都能落盘且 html 有一定体积",
          all(o for _n, o, _k in okk) and all((k or 0) > 1 for _n, _o, k in okk), okk)
    check("D16 build_html 直接可用（不落盘也能进 IDE 预览）",
          PG.build_html({"kind": "bars", "title": "t", "bars": {"unit": "ms", "items": []}})
          .startswith("<!DOCTYPE html>"))


def section_e():
    """E. MCP 工具层。"""
    print("E. 工具层")
    check("E1 view_render / view_guide 归 core 组（默认面可见）",
          "view_render" in (TB.TOOLSETS.get("core") or []) and
          "view_guide" in (TB.TOOLSETS.get("core") or []),
          sorted(TB.TOOLSETS.get("core") or []))
    check("E2 annotate：render 会写本地文件（非只读、非幂等）；guide 只读",
          A.annotations_for("view_render")["readOnlyHint"] is False and
          A.annotations_for("view_render")["idempotentHint"] is False and
          A.annotations_for("view_guide")["readOnlyHint"] is True,
          (A.annotations_for("view_render"), A.annotations_for("view_guide")))
    for c in ("view-unknown-data", "view-no-data", "view-file-missing", "view-file-bad",
              "view-bad-names", "view-bad-view", "view-bad-data", "view-bad-spec",
              "view-bad-topic", "view-write-failed"):
        check("E3 错误码登记：%s" % c, c in ERR.ERROR_CODES, c)

    srv = SV.create_server()
    tm = getattr(srv, "_tool_manager", None)
    names = sorted((getattr(tm, "_tools", None) or {}).keys())
    check("E4 注册进服务（总数 189）", "view_render" in names and len(names) == 189, len(names))
    check("E5 check_surface 全过（无未归类/幽灵工具）", not A.check_surface(names),
          A.check_surface(names))

    d = tempfile.mkdtemp(prefix="mdkviz_e_")
    r = call(srv, "view_render", {"data": SWD, "title": "任务切换",
                                  "out": os.path.join(d, "a.html")})
    check("E6 端到端：swd 返回 -> 页面", r.get("ok") is True and os.path.exists(r.get("path") or ""), r)
    check("E7 信封：成功时 status=ok", r.get("status") == "ok", r.get("status"))
    r2 = call(srv, "view_render", {"data": js(SWD), "view": "timeline",
                                   "out": os.path.join(d, "b.html")})
    check("E8 data 传 JSON 文本也能用（模型常这么传）", r2.get("ok") is True, r2)
    r3 = call(srv, "view_render", {"data": "not json{"})
    check("E9 data 不是合法 JSON -> view-bad-data",
          r3.get("error_code") == "view-bad-data" and r3.get("status") == "error", r3)
    r4 = call(srv, "view_render", {"data": {"foo": 1}})
    check("E10 认不出 -> view-unknown-data 且给 next_actions",
          r4.get("error_code") == "view-unknown-data" and r4.get("next_actions"), r4)
    r5 = call(srv, "view_render", {"data": SWD, "view": "nope"})
    check("E11 view 写错 -> view-bad-view", r5.get("error_code") == "view-bad-view", r5)
    r6 = call(srv, "view_guide", {})
    check("E12 view_guide 默认给 howto", r6.get("ok") and r6.get("topic") == "howto", r6)
    r7 = call(srv, "view_guide", {"topic": "all"})
    check("E13 topic=all 给全部四段",
          r7.get("ok") and sorted((r7.get("guide") or {}).keys()) ==
          ["howto", "limits", "spec", "views"], r7)
    r8 = call(srv, "view_guide", {"topic": "zzz"})
    check("E14 topic 写错 -> view-bad-topic", r8.get("error_code") == "view-bad-topic", r8)
    r9 = call(srv, "view_render", {"data_file": os.path.join(d, "nope.json")})
    check("E15 端到端：data_file 缺失报 view-file-missing",
          r9.get("error_code") == "view-file-missing", r9)


def section_f():
    """F. 文档同步。"""
    print("F. 文档同步")
    def rd(p):
        with open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
            return f.read()
    readme = rd("README.md")
    skill = rd("skills/mdkdebug/SKILL.md")
    check("F1 README 有 view_render（工具面/可读性入口）", "view_render" in readme, "")
    check("F2 SKILL 有 view_render 与 view_guide",
          "view_render" in skill and "view_guide" in skill, "")
    check("F3 文档工具数同步为 189 / 收起 147",
          "189 个" in readme and "147 个" in readme and
          "189 个工具" in skill and "147 个" in skill, "")


def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    print("\n批次59 可视化结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
