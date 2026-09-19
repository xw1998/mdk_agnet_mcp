# -*- coding: utf-8 -*-
"""mdkdebug 可视化：把采集结果套路化成**人能看懂的页面**。

为什么要有这一层
----------------
在此之前，每要给人看一次数据，就得现场手写一个几百行的 HTML（深色主题、
canvas 缩放平移、泳道、气泡……）。同样的活儿重复做，token 花在重写 CSS 和
坐标变换上，不同批次画出来的东西还不一样——**看图的人每次都要重新适应**。

现在分成三块，各司其职：
  · **采集**（已有工具）：trace_swd_read / trace_scope_read / trace_pcsample …
  · **适配**（adapters.py）：把采集结果折成渲染模型，认不出就报错，不猜
  · **渲染**（runtime.js + page.py）：一套固定的交互与画法，一个 html 文件

于是 AI 侧的动作退化成一句话：「把这个采集结果渲染出来」，**不需要写 HTML**。

用法（Python 侧）
-----------------
>>> from mdkdebug import viz
>>> viz.render(data=swd_read_result, title="任务切换")
{'ok': True, 'path': '.../mdkdebug_views/timeline-20260919-101530.html', ...}

工具侧对应 `view_render` / `view_guide`。
"""
from __future__ import annotations

import datetime
import os
import time

from . import adapters, page

__all__ = ["render", "adapt", "VIEWS", "GUIDE", "default_out_dir"]

VIEWS = ("auto", "timeline", "scope", "bars", "report")

DEFAULT_SUBDIR = "mdkdebug_views"


def default_out_dir() -> str:
    return os.path.abspath(DEFAULT_SUBDIR)


def _looks_like_events(v) -> bool:
    return isinstance(v, list) and bool(v) and isinstance(v[0], dict)


def _is_scopeish(p: dict) -> bool:
    if isinstance(p.get("recent"), list) and p.get("recent"):
        return True
    if isinstance(p.get("samples"), list) and p.get("samples"):
        return True
    if isinstance(p.get("series"), dict):
        return True
    return False


def _is_barsish(p: dict) -> bool:
    return bool(p.get("by_function")) or bool(p.get("hot")) or bool(p.get("items"))


def detected_view(data) -> str:
    """认数据不认人说：按字段签名判断这是什么。认不出返回 ""。"""
    if isinstance(data, list):
        return "timeline" if _looks_like_events(data) else ""
    if not isinstance(data, dict):
        return ""
    if str(data.get("kind") or "") in ("timeline", "scope", "bars", "report"):
        return str(data["kind"])
    if str(data.get("view") or "") in ("timeline", "scope", "bars", "report"):
        return str(data["view"])
    # 先判统计类：pcsample/profile 的结果里也有 samples（int），别被 scope 抢走
    if _is_barsish(data):
        return "bars"
    if isinstance(data.get("timeline"), list) and data["timeline"]:
        return "timeline"
    if _looks_like_events(data.get("events")):
        return "timeline"
    if _is_scopeish(data):
        return "scope"
    return ""


def adapt(data, view: str = "auto", title: str = "", names: str = "",
          top: int = 40, max_events: int = 200000) -> dict:
    """数据 → 渲染模型。返回 {ok, model} 或 {ok:False, error_code, error, hint}。"""
    v = (view or "auto").strip().lower()
    if v in ("", "auto"):
        v = detected_view(data)
        if not v:
            return {"ok": False, "error_code": "view-unknown-data",
                    "error": "认不出这是什么数据，也没有显式指定 view",
                    "hint": ("支持：① trace_swd_read / trace_buff_dump / trace_eventrec 的返回"
                             "（events）→ timeline；② trace_scope_read 的返回（recent/samples）"
                             "→ scope；③ trace_pcsample / trace_profile / coverage_read / "
                             "trace_eventrec 统计（by_function/hot/items）→ bars；"
                             "④ trace_record(action=read)（timeline）→ timeline；"
                             "⑤ 自己写 spec：{kind: timeline|scope|bars|report, ...}。"
                             "也可以显式传 view=… 指定")}
    nm = adapters.parse_names(names)
    if nm["bad"]:
        return {"ok": False, "error_code": "view-bad-names",
                "error": "names 里有解析不了的条目：%s" % ", ".join(nm["bad"]),
                "hint": "写法：names=\"0x10=switch,1=led_task\"（十进制或 0x 都行）"}
    # 显式 kind 且**没有任何采集字段** ⇒ 这是调用方自己写的 spec（展示算法/自定义信号）。
    # 没有这一步时，自写的 {kind:"timeline", tracks:[…]} 会被送去 timeline_from_events
    # 找 events，报「这份数据里没有 events」——与 view_guide(topic="spec") 的承诺矛盾。
    _spec_kind = ""
    if isinstance(data, dict) and str(data.get("kind") or "") in ("timeline", "scope", "bars"):
        # 只认真·采集容器。`series`（scope spec 也用）与 `items`（bars spec 也用）
        # 是两个世界共用的键，放进这张表会让自写的 spec 被当成采集结果——真机上撞到的
        # 例子：{kind:"bars", items:[…]} 被当成 Event Statistics，数值上被安了单位「ms」。
        if not any(data.get(k) for k in ("events", "timeline", "recent", "samples", "rows")):
            _spec_kind = str(data["kind"])
    if _spec_kind:
        r = adapters.from_spec(data, nm["names"])
    elif v == "timeline":
        if isinstance(data, list):
            r = adapters.timeline_from_events({"events": data}, nm["names"], title, max_events)
        elif isinstance(data, dict) and isinstance(data.get("timeline"), list) and \
                not _looks_like_events(data.get("events")):
            r = adapters.timeline_from_record(data, title)
        elif isinstance(data, dict):
            r = adapters.timeline_from_events(data, nm["names"], title, max_events)
        else:
            r = {"ok": False, "error_code": "view-bad-data", "error": "timeline 需要事件列表或采集结果"}
    elif v == "scope":
        r = adapters.scope_from_samples(data if isinstance(data, dict) else {}, nm["names"], title)
    elif v == "bars":
        r = adapters.bars_from_payload(data if isinstance(data, dict) else {}, title, top)
    elif v == "report":
        r = _resolve_report(data, nm["names"], title)
    else:
        return {"ok": False, "error_code": "view-bad-view",
                "error": "未知 view：%r" % view,
                "hint": "可选：%s" % ", ".join(VIEWS)}
    if r.get("ok") and isinstance(r.get("model"), dict):
        m = r["model"]
        m.setdefault("kind", v)
        if not m.get("notes"):
            m["notes"] = []
        if not m.get("limits"):
            m["limits"] = []
        return r
    return r


def _count_nested(model) -> dict:
    """report 页的图嵌在 sections 里，顶层 counts 会全是 0——单独报一层 `nested`，
    **不与顶层键名共用**，免得下游把「报告里没有图」当成结论。"""
    n = {"tracks": 0, "channels": 0, "bars": 0, "sections": 0}
    for sec in (model.get("sections") or []):
        v = sec.get("view") if isinstance(sec, dict) else None
        if not isinstance(v, dict):
            continue
        n["tracks"] += len(v.get("tracks") or [])
        n["channels"] += len(v.get("channels") or [])
        n["bars"] += len(((v.get("bars") or {}).get("items")) or [])
        n["sections"] += len(v.get("sections") or [])
        sub = _count_nested(v)
        for k in n:
            n[k] += sub[k]
    return n


def _resolve_report(spec, names: dict, title: str) -> dict:
    """report 的 sections 里可以直接嵌**采集结果**，这里递归解析成 model。"""
    if not isinstance(spec, dict):
        return {"ok": False, "error_code": "view-bad-spec",
                "error": "report 需要对象：{kind:\"report\", verdict:…, sections:[…]}"}
    out = dict(spec)
    out["kind"] = "report"
    out.setdefault("title", title or "分析报告")
    out.setdefault("badges", [])
    out.setdefault("notes", [])
    out.setdefault("limits", [])
    if spec.get("sections") is not None and not isinstance(spec["sections"], list):
        return {"ok": False, "error_code": "view-bad-spec",
                "error": "report 的 sections 必须是数组，收到 %s" % type(spec["sections"]).__name__,
                "hint": "sections:[{h, p:[…], bullets:[…], code, view:{kind:…}}]"}
    vd, verr = adapters.norm_verdict(out.get("verdict"))
    if verr:
        out["limits"] = list(out["limits"]) + [verr]
    else:
        out["verdict"] = vd
    secs = []
    for s in (spec.get("sections") or []):
        s2, serr = adapters.norm_report_section(s)
        if serr:
            out["limits"] = list(out["limits"]) + [serr]
            continue
        sub = s2.get("view")
        if isinstance(sub, dict):
            inner = detected_view(sub)
            if inner:
                r = adapt(sub, inner, names=",".join("%s=%s" % (k, v) for k, v in (names or {}).items()))
                if r.get("ok"):
                    s2["view"] = r["model"]
                else:
                    s2.setdefault("p", []).append("（这一节的图没画出来：%s）" % r.get("error"))
                    s2.pop("view", None)
            elif str(sub.get("kind")) in VIEWS:
                r = _resolve_report(sub, names, "") if str(sub.get("kind")) == "report" else adapters.from_spec(sub)
                if r.get("ok"):
                    s2["view"] = r["model"]
                else:
                    s2.pop("view", None)
            else:
                s2.pop("view", None)
                s2.setdefault("p", []).append("（这一节的 view 认不出，已跳过）")
        secs.append(s2)
    out["sections"] = secs
    if not secs:
        out["limits"] = list(out["limits"]) + ["报告里没有 sections：只有标题和结论。"]
    return {"ok": True, "model": out}


def render(view: str = "auto", data=None, data_file: str = "", out: str = "",
           title: str = "", subtitle: str = "", names: str = "", top: int = 40,
           max_events: int = 200000, open_hint: bool = True) -> dict:
    """采集结果（或自写 spec）→ 单文件 HTML。

    data_file 给了就从文件读（采集工具的 `out_file` 产物），data 优先。
    返回 {ok, path, view, html_bytes, bytes, badges, limits, next}。
    """
    payload = data
    src = ""
    if payload is None and data_file:
        import json
        p = os.path.abspath(data_file)
        if not os.path.exists(p):
            return {"ok": False, "error_code": "view-file-missing",
                    "error": "data_file 不存在：%s" % p,
                    "hint": "先用采集工具写 out_file（如 trace_swd_read(out_file=…)），再渲染"}
        try:
            with open(p, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError) as e:
            return {"ok": False, "error_code": "view-file-bad",
                    "error": "读 data_file 失败：%s" % e}
        src = p
    if payload is None:
        return {"ok": False, "error_code": "view-no-data",
                "error": "既没给 data 也没给 data_file",
                "hint": "把采集工具的返回原样传进 data；或先写 out_file 再传 data_file"}
    r = adapt(payload, view=view, title=title, names=names, top=top, max_events=max_events)
    if not r.get("ok"):
        return r
    model = r["model"]
    if subtitle:
        model["subtitle"] = subtitle
    if src:
        model.setdefault("notes", []).append("数据源文件：%s" % src)
    if not out:
        stamp = datetime.datetime.fromtimestamp(time.time()).strftime("%Y%m%d-%H%M%S")
        out = os.path.join(default_out_dir(), "%s-%s.html" % (model["kind"], stamp))
    if os.path.isdir(out):
        stamp = datetime.datetime.fromtimestamp(time.time()).strftime("%Y%m%d-%H%M%S")
        out = os.path.join(out, "%s-%s.html" % (model["kind"], stamp))
    try:
        w = page.write_html(model, out)
    except OSError as e:
        return {"ok": False, "error_code": "view-write-failed",
                "error": "写 HTML 失败：%s" % e}
    badges = model.get("badges") or []
    nxt = ["双击页面空白处可回到全览；滚轮以鼠标为锚缩放；单击定位游标"]
    if open_hint:
        nxt.insert(0, "把这个 html 路径给用户，浏览器直接打开（单文件、无需联网）")
    if model.get("limits"):
        nxt.append("页面底部「这说明不了什么」列了 %d 条边界，讲结论前先看它" % len(model["limits"]))
    return {"ok": True, "view": model["kind"], "path": w["path"],
            "html_bytes": w["bytes"], "html_kb": round(w["bytes"] / 1024.0, 1),
            "badges": badges,
            "counts": {"tracks": len(model.get("tracks") or []),
                       "channels": len(model.get("channels") or []),
                       "bars": len(((model.get("bars") or {}).get("items")) or []),
                       "sections": len(model.get("sections") or []),
                       "nested": _count_nested(model)},
            "data_file": src or None,
            "next": nxt}


GUIDE = {
    "howto": (
        "一条命令出图：把采集工具的**返回原样**丢进 view_render 的 data。\n"
        "  trace_swd_read / trace_buff_dump / trace_eventrec  → 事件时间线（泳道/切换/中断/异常）\n"
        "  trace_scope_read（或自己拼的 samples）             → 变量波形（多通道、阶梯/折线）\n"
        "  trace_pcsample / trace_profile / coverage_read     → 函数热点排行（横向条形）\n"
        "  trace_record(action=\"read\")                       → 函数进入/退出时间线\n"
        "  trace_eventrec 的 items（Event Statistics）        → 每个事件的耗时排行\n"
        "采集结果大时先落盘：trace_swd_read(out_file=\"trace.json\")，再 view_render(data_file=\"trace.json\")，"
        "避免把几万条事件塞进对话。\n"
        "想讲一个问题（结论 + 证据 + 图）就用 report：view_render(data={kind:\"report\", …})，"
        "sections 里的 view 可以直接塞采集结果，工具会自己认出来。"
    ),
    "views": (
        "auto —— 认数据不认人：按字段签名推断（events→timeline、recent/samples→scope、"
        "by_function/hot/items→bars、timeline→函数时间线）。认不出会**报错**，不会给你一张空图。\n"
        "timeline —— 时间轴：上下文泳道（spans）、切换竖线（marks，放大后显示切向谁）、"
        "中断进出（intervals，视野内过多自动切密度条）、事件/异常标记、丢失断口（斜纹带）。\n"
        "scope —— 变量波形：每通道一条曲线（bool/enum 自动画阶梯），左侧给 min/max/变化次数，"
        "游标处给当前值。\n"
        "bars —— 统计排行：函数热点 / 覆盖率命中 / Event Statistics 耗时。\n"
        "report —— 结论 + 场景 + 证据：verdict（ok/warn/bad）+ sections（标题/段落/要点/代码/嵌图）。"
    ),
    "spec": (
        "自己写 spec（采集结果不合适、想展示算法或自定义信号时）：\n"
        "通用字段：kind / title / subtitle / badges:[{k,v,level}] / notes:[…] / limits:[…]；"
        "level 取 ok|warn|bad|dim。\n"
        "timeline：{kind:\"timeline\", span:[0,t], tracks:[{id?,name,sub?,color?,type:"
        "\"spans\"|\"marks\"|\"intervals\"|\"density\", spans:[[t0,t1]], marks:[[t]], "
        "pairs:[[t0,t1]], targets?:[{t,i,color}], count?}], markers:[{t,label,level}], "
        "gaps:[{t0,t1,label}]}（时间单位一律 **µs**）。\n"
        "scope：{kind:\"scope\", channels:[{name,unit?,type:\"analog\"|\"bool\"|\"enum\","
        "min?,max?,changes?}], series:{t:[…], v:{通道名:[…]}}}（t 为 µs，缺值用 null）。\n"
        "bars：{kind:\"bars\", bars:{unit:\"ms\", items:[{name,value,share?,sub?,color?}]}}。\n"
        "report：{kind:\"report\", verdict:{level,text}, sections:[{h, p:[…], bullets:[…], "
        "code?, view:{…上面任意一种…}}]}。\n"
        "注意：limits 是给**人**看的边界（「这说明不了什么」），不要写成结论；"
        "自称「实测」前先确认横轴真的是时间（TS_OFF 的数据横轴是事件序号）。"
    ),
    "limits": (
        "页面是**单文件、无外部依赖、无网络请求**的 html，file:// 双击就能开，"
        "也可以直接发给别人（数据内联在页面里，注意别把敏感数据发出去）。\n"
        "一个页面就是一次快照：它是给你/用户看的，不会自己刷新——数据变了要重新渲染。\n"
        "大数据的代价：几万条事件内联进 html 会有几百 KB～几 MB，浏览器缩放平移仍然流畅；"
        "轨道超过 24 条会被合并，事件超过上限会抽稀，这两件事都会写在页面底部。\n"
        "图上没有的 = **没被记录 / 没插桩**，不等于没发生——这句话每个页面都会写。"
    ),
}

# ----------------------------------------------------------------------
# MCP 工具注册（供 server.py 的工具族循环调用）
# ----------------------------------------------------------------------
def register(server, js=None) -> int:
    """把 `view_render` / `view_guide` 注册进 MCP server，返回注册数。

    与其它工具族（trace/coverage/ocd…）同一写法：server.py 的循环里调用
    `register(server, _js)`，失败只记日志，不影响其余工具。
    """
    import json as _json

    def _d(o):
        return _json.dumps(o, ensure_ascii=False, default=str)

    _js = js or _d
    n = 0

    @server.tool(
        name="view_render",
        title="把采集结果渲染成人能看懂的单文件网页",
        description=(
            "把**已有的采集结果**渲染成一个可交互的单文件 HTML（深色主题、可缩放/平移/回放），"
            "给人看「问题出在哪、场景长什么样」——不必再手写网页。渲染层是固定的："
            "同一类数据画出来长得一样，看图的人不用每次重新适应。\n"
            "最常用的一步调用：把采集工具的**返回原样**丢进 `data`（不用先转格式，工具自己认）：\n"
            "  · trace_swd_read / trace_buff_dump / trace_eventrec → 事件时间线：上下文泳道、"
            "切换竖线（放大显示切向谁）、中断进出、异常标记、丢失断口；\n"
            "  · trace_scope_read（或自己拼 {t:[…], 变量:[…]}）→ 变量波形（bool/enum 自动阶梯）；\n"
            "  · trace_pcsample / trace_profile / coverage_read → 函数热点排行；\n"
            "  · trace_eventrec 的 items（Event Statistics）→ 每个事件的耗时排行；\n"
            "  · trace_record(action=\"read\") → 函数进入/退出时间线；\n"
            "  · 自己写 {kind:\"timeline|scope|bars|report\", …} → 展示算法/自定义信号。\n"
            "**数据大时先落盘**：trace_swd_read(out_file=\"trace.json\") 拿到几万条事件时，"
            "别再把它塞回对话，改传 `data_file=\"trace.json\"`（省 token，也避免截断）。\n"
            "params：view=auto|timeline|scope|bars|report（默认 auto 认数据不认人）；"
            "names=\"0x10=switch,1=led_task\" 给 id 起人名；top=热点头条数；"
            "out=输出路径（默认 ./mdkdebug_views/<kind>-<时间戳>.html）；"
            "title/subtitle 写进页面抬头。\n"
            "**认不出就报错、不画空图**（error_code=view-unknown-data/view-bad-*）。"
            "返回 counts 是画了什么，badges 是页面顶部的关键数，next 是给人看的操作提示；"
            "返回 path 直接交给用户，浏览器（file://）打开即可，页面**无外部依赖、无需联网**。\n"
            "一次快照，不会自动刷新：数据变了要重新渲染。页面上「这说明不了什么」那栏是"
            "**边界声明**（图上没有的=没被记录/没插桩，不等于没发生），讲结论前先看它。\n"
            "只想讲清一个问题（结论+证据+图）用 report：sections 里的 view 可以直接嵌采集结果。"
        ),
    )
    async def view_render(data=None, data_file: str = "", view: str = "auto",
                          title: str = "", subtitle: str = "", names: str = "",
                          top: int = 40, max_events: int = 200000,
                          out: str = "") -> str:
        try:
            payload = data
            if isinstance(payload, str):
                s = payload.strip()
                if not s:
                    payload = None
                else:
                    try:
                        payload = _json.loads(s)
                    except ValueError as e:
                        return _js({"ok": False, "error_code": "view-bad-data",
                                    "error": "data 传的是字符串但不是合法 JSON：%s" % e,
                                    "hint": ("要么把采集工具的返回原样（对象/数组）传给 data，"
                                             "要么先写 out_file 再传 data_file")})
            r = render(view=view, data=payload, data_file=data_file, out=out,
                       title=title, subtitle=subtitle, names=names, top=top,
                       max_events=max_events)
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error_code": "view-failed", "error": str(e)})

    n += 1

    @server.tool(
        name="view_guide",
        title="可视化用法与 spec 说明（怎么把数据变成页面）",
        description=(
            "`view_render` 的说明书：怎么把采集结果变成页面、五种视图各画什么、"
            "以及**自己写 spec** 的完整字段（想把算法输出、自定义信号画出来时用）。\n"
            "topic：howto（默认，一步出图与数据来源）/ views（五种视图各适合回答什么）/ "
            "spec（自写 spec 的字段与单位约定）/ limits（页面边界与大数据代价）/ all（全部）。\n"
            "**先看 howto**：多数场景不需要读 spec——采集工具的返回原样传进 data 就够了。"
            "自写 spec 时时间单位一律 **µs**，且 limits 要写「这说明不了什么」，不要写成结论。"
        ),
    )
    async def view_guide(topic: str = "") -> str:
        try:
            t = (topic or "howto").strip().lower()
            if t in ("", "all", "*"):
                return _js({"ok": True, "topic": "all", "topics": sorted(GUIDE),
                            "guide": dict(GUIDE)})
            if t not in GUIDE:
                return _js({"ok": False, "error_code": "view-bad-topic",
                            "error": "未知 topic：%r" % topic,
                            "hint": "可选：%s（或 all）" % ", ".join(sorted(GUIDE))})
            return _js({"ok": True, "topic": t, "topics": sorted(GUIDE),
                        "text": GUIDE[t]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error_code": "view-failed", "error": str(e)})

    n += 1
    return n
