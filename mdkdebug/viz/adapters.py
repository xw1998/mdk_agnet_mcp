# -*- coding: utf-8 -*-
"""采集结果 → 渲染模型（adapter 层）。

**这一层是整个可视化工具的省 token 关键**：AI 不需要手写 HTML，也不需要把
采集结果转成某种中间格式——把 `trace_swd_read` / `trace_buff_dump` /
`trace_scope_read` / `trace_pcsample` / `coverage_read` / `trace_eventrec` /
`trace_record` 的**返回原样**丢进来，这里负责认出来并折成页面模型。

设计原则
--------
· **只画有的东西**：时间戳缺了就用事件序号当横轴，并在 limits 里写明
  「横轴是顺序不是时间」——绝不按到达顺序编一条假时间轴。
· **规模摊开讲**：事件数、丢失数、是否抽稀、是否截断，都进 badges/limits。
· **认不出就不猜**：既不是已知采集结果、又没给显式 view/kind，直接报错
  （`view-unknown-data`），不生成一个「看起来像样的空图」。
"""
from __future__ import annotations

import re

# Cortex-M 异常号 → 名字（isr 轨道没给名字时用这个兜底）
_CM_EXC = {
    2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault", 6: "UsageFault",
    7: "SecureFault", 8: "reserved", 9: "reserved", 10: "reserved", 11: "SVC",
    12: "DebugMon", 13: "reserved", 14: "PendSV", 15: "SysTick",
}

# svcrt_trace.h 里 arg 是任务号的系统事件（只在 event 类事件没给名字时用来起名）
_SVC_ARG_EV = {0x11: "wait", 0x12: "ready", 0x13: "create", 0x14: "exit"}

# 事件类型的中文写法（只影响标题，不改判定）
_TYP_CN = {"event": "事件", "sched": "调度", "isr": "中断", "fault": "异常"}

_MAX_TRACKS = 24          # 轨道数上限（超出合并）
_MAX_SPLIT = 10           # 同一类事件按 id 最多拆几条轨道


def parse_names(spec) -> dict:
    """`"0x10=switch,1=led_task"` → {16: "switch", 1: "led_task"}。

    只认「数字（可带 0x/十进制）= 名字」，解析不了的条目原样报出来（由调用方
    决定是报错还是只提示），不静默丢弃。
    """
    out, bad = {}, []
    if isinstance(spec, dict):
        for k, v in spec.items():
            try:
                out[int(str(k), 0)] = str(v)
            except (TypeError, ValueError):
                bad.append("%s=%s" % (k, v))
        return {"names": out, "bad": bad}
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            bad.append(part)
            continue
        k, v = part.split("=", 1)
        try:
            out[int(k.strip(), 0)] = v.strip()
        except ValueError:
            bad.append(part)
    return {"names": out, "bad": bad}


# svcrt_trace.h：流里的任务号只有 4 bit，0xF 是 idle（不是一个表项下标）
_IDLE_ID_DEFAULT = 0xF


def _name_of(names: dict, ident, fallback=None):
    try:
        key = int(str(ident), 0)
    except (TypeError, ValueError):
        key = None
    if key is not None and key in (names or {}):
        return names[key]
    return fallback


def _task_names_from(payload, names: dict = None):
    """把「返回体里已经带的任务名」凑成 {任务号(int): 名字}。

    来源优先级：显式 names 参数 > 返回体的 task_names/names（采集时按符号表定的
    名）> 事件自带的 from_name / to_name / task_name。显式参数与采集来的名合并，
    不互相覆盖（同一个号谁先有值用谁）。

    返回 (名字表, idle 名字, idle 号, why)：一个名字都拿不到就返回空表和 why
    （说明为什么没有），**不编占位名**——图上显示 ctx5 好过显示一个编出来的名。
    """
    m, why = {}, []

    def put(k, v):
        k = _as_int(k)
        if k is None or not isinstance(v, str) or not v.strip():
            return
        m.setdefault(k, v.strip())

    for k, v in (names or {}).items():
        put(k, v)

    idle_name, idle_id = None, None
    if isinstance(payload, dict):
        for cand in (payload.get("task_names"), payload.get("tasks_meta")):
            if not isinstance(cand, dict):
                continue
            rown = 0
            for k, v in (cand.get("names") or {}).items():
                put(k, v)
                rown += 1
            for row in (cand.get("tasks") or []):
                if isinstance(row, dict) and row.get("name"):
                    put(row.get("slot", row.get("id", row.get("index"))), row["name"])
                    rown += 1
            if cand.get("idle"):
                idle_name = str(cand["idle"])
            if cand.get("idle_id") is not None:
                idle_id = _as_int(cand.get("idle_id"))
            if cand.get("ok") is False and not rown:
                why.append(str(cand.get("error") or cand.get("why") or "任务名没取到"))
        if isinstance(payload.get("names"), dict):
            for k, v in payload["names"].items():
                put(k, v)
        for row in (payload.get("tasks") or []):
            if isinstance(row, dict) and row.get("name"):
                put(row.get("slot", row.get("id", row.get("index"))), row["name"])
        if payload.get("idle_id") is not None:
            idle_id = _as_int(payload.get("idle_id"))
        if payload.get("idle_name"):
            idle_name = str(payload["idle_name"])
        # 事件自带的名字（trace_swd_read 已经按序号补过）
        for e in (payload.get("events") or []):
            if not isinstance(e, dict):
                continue
            put(e.get("from"), e.get("from_name"))
            put(e.get("to"), e.get("to_name"))
            if e.get("task_name") is not None and e.get("arg") is not None:
                a = _as_int(e.get("arg"))
                put(None if a is None else (a & 0xF), e.get("task_name"))
    elif isinstance(payload, list):
        for e in payload:
            if isinstance(e, dict):
                put(e.get("from"), e.get("from_name"))
                put(e.get("to"), e.get("to_name"))

    if idle_id is None and (m or idle_name):
        idle_id = _IDLE_ID_DEFAULT
    if idle_name and idle_id is not None:
        m.setdefault(idle_id, idle_name)
    return m, idle_name, idle_id, why


def _as_int(v):
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None


def _num(x, default=None):
    try:
        if x is None:
            return default
        return float(x)
    except (TypeError, ValueError):
        return default


def _dig(payload, *path, default=None):
    cur = payload
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _cpu_hz(payload) -> float:
    for v in (_dig(payload, "ctrl", "cpu_hz"), payload.get("cpu_hz") if isinstance(payload, dict) else None,
              _dig(payload, "meta", "cpu_hz"), _dig(payload, "info", "cpu_hz")):
        f = _num(v)
        if f and f > 0:
            return f
    return 0.0


def _ts_freq(payload) -> float:
    for v in (payload.get("ts_freq") if isinstance(payload, dict) else None,
              _dig(payload, "meta", "ts_freq")):
        f = _num(v)
        if f and f > 0:
            return f
    return 0.0


def collect_notes_limits(payload: dict) -> tuple:
    """从采集结果里提炼「说明」与「边界」，原样转述，不加工成结论。"""
    notes, limits = [], []
    if not isinstance(payload, dict):
        return notes, limits
    for w in (payload.get("warnings") or []):
        limits.append(str(w))
    w1 = payload.get("warning")
    if w1:
        limits.append(str(w1))
    rm = payload.get("read_meta") or {}
    if isinstance(rm, dict):
        if rm.get("read_unstable") or rm.get("degenerate"):
            limits.append("这次读内存的置信度不高（%s）：数据可能不完整，建议重读复核。"
                          % (rm.get("degenerate") or "read_unstable"))
        if rm.get("while_running"):
            limits.append("读的时候目标在跑：Keil 链路上运行时读 RAM 可能错位（while_running=true）。")
    for k, label in (("lost", "记录缓冲丢了 %s 条"), ("lost_events", "目标丢了 %s 条事件"),
                     ("text_dropped", "丢弃文本 %s 条"), ("session_events_dropped",
                                                          "会话窗口滑掉了 %s 条老事件")):
        v = _num(payload.get(k))
        if v:
            limits.append((label % int(v)) + "：这条线不是完整的。")
    if payload.get("truncated"):
        limits.append("返回里只带了最近一部分事件（truncated=true）：页面画的就是这一部分。")
    if payload.get("buffer_window_truncated") or payload.get("wrapped"):
        limits.append("环形缓冲已回卷：现在看到的是一个时间窗口，不是全程。")
    if payload.get("ts_off"):
        limits.append("这段流是 TS_OFF（不记时间戳）：横轴是事件顺序，不是时间。")
    return notes, limits


def _rel_times(evs, payload, names_note) -> tuple:
    """事件 → 相对微秒时间数组。返回 (times, ok_time, unit_note)。

    优先级：t_us → cycles(+cpu_hz) → t_cycles(+cpu_hz) → rel_cycles(+cpu_hz)
            → dt_cycles 累加(+cpu_hz) → ts(+ts_freq) → 无（用序号）。
    """
    def pick(key):
        for i, e in enumerate(evs):
            if isinstance(e, dict) and _num(e.get(key)) is not None:
                return i
        return -1

    hz = _cpu_hz(payload)
    idx = pick("t_us")
    if idx >= 0:
        t0 = _num(evs[idx]["t_us"])
        times = [(_num(e.get("t_us"), None) if isinstance(e, dict) else None) for e in evs]
        base = next((t for t in times if t is not None), 0.0)
        return [None if t is None else (t - base) for t in times], True, "µs（源：t_us）"
    if hz:
        for key, mode in (("cycles", "abs"), ("t_cycles", "abs"), ("rel_cycles", "abs")):
            if pick(key) >= 0:
                raw = [_num(e.get(key), None) for e in evs]
                base = next((t for t in raw if t is not None), 0.0)
                return [None if t is None else (t - base) * 1e6 / hz for t in raw], True, \
                       "µs（源：%s / cpu_hz=%.0f）" % (key, hz)
        if pick("dt_cycles") >= 0:
            acc, out = 0.0, []
            for e in evs:
                d = _num(e.get("dt_cycles"), None)
                if d is not None:
                    acc += d
                out.append(acc * 1e6 / hz)
            return out, True, "µs（源：dt_cycles 累加 / cpu_hz=%.0f）" % hz
    freq = _ts_freq(payload)
    if freq and pick("ts") >= 0:
        raw = [_num(e.get("ts"), None) for e in evs]
        base = next((t for t in raw if t is not None), 0.0)
        return [None if t is None else (t - base) / freq * 1e6 for t in raw], True, \
               "µs（源：ts / ts_freq=%.0f）" % freq
    return [float(i) for i in range(len(evs))], False, "事件序号（源数据没有时间戳）"


# ---------------------------------------------------------------- timeline

def _count_by_type(evs) -> dict:
    """全量事件的类型计数（sched / isr / fault）——badge 上的口径就用这个。"""
    c = {}
    for e in evs or []:
        if not isinstance(e, dict):
            continue
        t = str(e.get("type") or "")
        if t in ("sched", "isr", "fault"):
            c[t] = c.get(t, 0) + 1
    return c


def timeline_from_events(payload: dict, names: dict = None, title: str = "",
                         max_events: int = 200000) -> dict:
    """事件流 → timeline 模型（swd / buff / eventrec / 通用事件列表）。"""
    evs = payload.get("events") if isinstance(payload, dict) else payload
    if not isinstance(evs, list) or not evs:
        return {"ok": False, "error_code": "view-empty-data",
                "error": "这份数据里没有 events，画不了时间线",
                "hint": "把 trace_swd_read / trace_buff_dump / trace_eventrec 的返回整个传进来"}
    # 统计口径与绘图口径要分开：evs 后面会被抽稀（画不下那么多点），但 badge 上
    # 报的条数必须是**真实总条数**。旧写法用 len(evs) * thinned 反推，没抽稀时
    # thinned=0 直接报 0（满屏轨道配一个「事件 0」）；抽稀时又是估算值（8 条报成
    # 10 条）。两处都是错数，这里先把真值留下来。
    evs_all = evs
    total_events = len(evs)
    thinned = 0
    if len(evs) > max_events:
        step = len(evs) // max_events + 1
        evs = evs[::step]
        thinned = step
    # 返回体里已经带的任务名（trace_swd_read/ tasks 的返回）直接拿来用：
    # 采集时是按符号表精确匹到的名，比事后让调用方再拼一遍靠谱。
    names_in = names or {}          # 调用方显式给的（给中断号起名用的就是这份）
    names, idle_name, idle_id, name_why = _task_names_from(payload, names)
    times, has_time, unit_note = _rel_times(evs, payload, names)
    # 有 t_us 字段 ≠ 时间轴能用：粒度比事件间隔粗时（目标把每次除法的**余数**丢掉了），
    # 每条事件的量化增量都是 0，横轴会**冻成一条竖线**。这种轴必须报出来，
    # 不能画成一条平平的、看着像模像样的时间轴。
    timed = [t for t in times if t is not None]
    t_frozen = bool(has_time and len(timed) >= 50 and not any(timed))
    tmax = max(timed or [1.0]) or 1.0
    tracks, markers, gaps, extras = [], [], [], []
    counts = {}

    def add(track):
        tracks.append(track)

    # --- 上下文切换：泳道 + 切换带 ---
    sched = [(i, e, times[i]) for i, e in enumerate(evs)
             if isinstance(e, dict) and str(e.get("type")) == "sched" and times[i] is not None]
    for i, e, t in sched:
        counts["sched"] = counts.get("sched", 0) + 1
    lanes = {}
    if sched:
        order = sorted(set([_int_or_none(e.get("from")) for _, e, _t in sched] +
                           [_int_or_none(e.get("to")) for _, e, _t in sched]) - {None})
        for k, tid in enumerate(order):
            lanes[tid] = {"id": tid,
                          "name": _name_of(names, tid,
                                           idle_name if (idle_id is not None and tid == idle_id)
                                           else "ctx%s" % tid),
                          "color": None, "spans": []}
        for n, (i, e, t) in enumerate(sched):
            tid = _int_or_none(e.get("to"))
            if tid is None:
                continue
            t1 = sched[n + 1][2] if n + 1 < len(sched) else tmax
            if t1 > t:
                lanes[tid]["spans"].append([t, t1])
        for tid in order:
            ln = lanes[tid]
            if not ln["spans"]:
                continue
            add({"id": "lane-%s" % tid, "name": ln["name"], "sub": "上下文泳道",
                 "type": "spans", "spans": ln["spans"],
                 "count": len(ln["spans"]), "toggle": True})
        # 切换带（按切出者着色）+ 放大后显示切向谁
        sw_marks, sw_targets = [], []
        for k, (i, e, t) in enumerate(sched):
            frm, to = _int_or_none(e.get("from")), _int_or_none(e.get("to"))
            sw_marks.append([t, None])
            sw_targets.append({"t": t, "i": order.index(to) if to in order else 0})
        add({"id": "switch", "name": "上下文切换", "sub": "每次切换一根竖线（放大后右侧显示切向谁）",
             "type": "marks", "marks": sw_marks, "targets": sw_targets,
             "count": len(sw_marks), "toggle": True})
        unnamed_tids = [tid for tid in order
                        if _name_of(names, tid) is None
                        and not (idle_id is not None and tid == idle_id)]
        if unnamed_tids:
            if names:
                extras.append("任务号 %s 取不到名字（图上按 ctxN 显示）：它们的入口符号不在"
                              "这次解析的镜像里，不等于它们没在跑。"
                              % ", ".join(str(x) for x in unnamed_tids))
            else:
                extras.append("这段流里的任务号**没有名字**（%s）：横轴上只有编号，"
                              "不要把 ctxN 当成任务名。"
                              % ("; ".join(name_why) if name_why else
                                 "这份数据里没带任务名，采集时可能用了 tasks=off"))
        # from 的颜色信息附在 marks 上（JS 里 fallback 到轨道色）
        for mk, (i, e, t) in zip(sw_marks, sched):
            frm = _int_or_none(e.get("from"))
            if frm in lanes:
                mk.append(_lane_color(order.index(frm)))

    # --- 中断 / 异常：enter/exit 配对成区间 ---
    isr_ev = [(i, e, times[i]) for i, e in enumerate(evs)
              if isinstance(e, dict) and str(e.get("type")) == "isr" and times[i] is not None]
    grouped, isr_evname = {}, {}
    for i, e, t in isr_ev:
        ident = _int_or_none(e.get("id"))
        grouped.setdefault(ident, []).append((str(e.get("kind") or ""), t))
        if e.get("id_name") and not isr_evname.get(ident):
            isr_evname[ident] = str(e["id_name"])
    for ident, seq in grouped.items():
        pairs, opened, unpaired = [], None, 0
        for kind, t in seq:
            if kind.startswith("enter"):
                if opened is not None:
                    unpaired += 1
                opened = t
            elif kind.startswith("exit"):
                if opened is None:
                    unpaired += 1
                else:
                    pairs.append([opened, t])
                    opened = None
        if opened is not None:
            unpaired += 1
        # 中断号与任务号不是一个命名空间：这里只认事件自带的名字/显式 names/
        # Cortex-M 异常表，**不用**从任务表凑出来的名字（否则 0xF=idle 会把 SysTick 改名）
        nm = (isr_evname.get(ident) or _name_of(names_in, ident, None)
              or _CM_EXC.get(ident) or ("IRQ%s" % ident))
        sub = "%d 段进出" % len(pairs) + ("，%d 个落单（没配成对，未画）" % unpaired if unpaired else "")
        add({"id": "isr-%s" % ident, "name": str(nm), "sub": sub,
             "type": "intervals", "pairs": pairs, "count": len(pairs), "toggle": True})
        if unpaired:
            extras.append("%s 有 %d 个落单的进/出事件（没配成对，图上没画）" % (nm, unpaired))

    # --- 异常发生点 ---
    for i, e in enumerate(evs):
        if not isinstance(e, dict) or str(e.get("type")) != "fault":
            continue
        t = times[i]
        if t is None:
            continue
        cls = e.get("fault_class") or "fault"
        markers.append({"t": t, "label": str(cls), "level": "bad"})
        counts["fault"] = counts.get("fault", 0) + 1

    # --- 断口 / 重启点 ---
    for i, e in enumerate(evs):
        if not isinstance(e, dict):
            continue
        typ = str(e.get("type"))
        t = times[i]
        if t is None:
            continue
        if typ == "gap":
            nxt = next((times[j] for j in range(i + 1, len(evs)) if times[j] is not None), None)
            w = max(((nxt - t) if nxt and nxt > t else tmax * 0.002), tmax * 0.0005)
            gaps.append({"t0": t, "t1": t + w,
                         "label": "丢 %s 条事件" % (e.get("events_dropped") or "?")})
        elif typ == "sync":
            markers.append({"t": t, "label": "重开录制段 seq=%s" % (e.get("seq") or "?"),
                            "level": "warn"})

    # --- 其它事件：按 (type, id) 分组 ---
    buckets = {}
    for i, e in enumerate(evs):
        if not isinstance(e, dict):
            continue
        typ = str(e.get("type") or "event")
        if typ in ("sched", "isr", "fault", "gap", "sync"):
            continue
        if times[i] is None:
            continue
        ident = e.get("id") if "id" in e else None
        # 同一类系统事件可能来自不同任务（WAIT/READY 的 arg 就是任务号）：
        # 按任务名再分一层轨道，否则一整个「wait」看不出是谁在等。
        tname = e.get("task_name") or None
        buckets.setdefault((typ, ident, tname), []).append((times[i], e))
    ranked = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
    shown = ranked[:_MAX_SPLIT]
    rest = ranked[_MAX_SPLIT:]
    for (typ, ident, tname), items in shown:
        nm = None
        for _t, e in items:
            nm = e.get("id_name") or nm
            break
        nm = nm or _name_of(names, ident, None)
        if nm:
            label = str(nm)
        elif tname:
            label = "%s · %s" % (_SVC_ARG_EV.get(ident) or typ, tname)
        else:
            label = "%s%s" % (typ, "" if ident is None else " id=%s" % ident)
        idnote = "" if ident is None else "（id=%s）" % (
            "0x%X" % ident if isinstance(ident, int) else ident)
        marks = [[t, None] for t, _e in items]
        dense = len(marks) > 3000
        add({"id": "%s-%s-%s" % (typ, ident, tname), "name": label,
             "sub": "%d 个%s%s" % (len(items), _TYP_CN.get(typ, typ), idnote),
             "type": "density" if dense else "marks",
             "marks": marks, "count": len(marks), "toggle": True})
    if rest:
        allrest = []
        for _k, items in rest:
            allrest.extend([[t, None] for t, _e in items])
        allrest.sort(key=lambda x: x[0])
        add({"id": "rest", "name": "其它事件（%d 类）" % len(rest),
             "sub": "%d 个，合并成密度条" % len(allrest),
             "type": "density", "marks": allrest, "count": len(allrest), "toggle": True})

    if len(tracks) > _MAX_TRACKS:
        extras.append("轨道超过 %d 条，只保留前 %d 条（其余在数据里，未画）" % (_MAX_TRACKS, _MAX_TRACKS))
        tracks = tracks[:_MAX_TRACKS]

    notes, limits = collect_notes_limits(payload if isinstance(payload, dict) else {})
    if not has_time:
        limits.append("源数据没有可用时间戳：横轴是**事件序号**，间距不代表时间间隔。")
    if t_frozen:
        limits.append("**时间轴是冻结的**：%d 条事件的时间增量全是 0（目标按「与上一条的差 ÷ "
                      "粒度」算 dt 并丢掉余数，事件比粒度密时每条都算 0）。横轴上「时长 / 间隔」"
                      "都不成立，**事件顺序仍是对的**。要真时间轴就用更细的粒度重录"
                      "（trace_swd_reset(granularity=\"cycle\")），代价是每事件字节数变大。"
                      % len(timed))
    if thinned:
        limits.append("事件 %d 条超过上限，每 %d 条抽 1 条**绘制**（总数与下面的计数"
                      "仍是全量）。" % (total_events, thinned))
    limits.extend(extras)
    limits.append("图上没有的 = 没被记录/没插桩，不等于没发生。")

    # 计数一律按**全量**算：抽稀只影响画几个点，不影响「发生过几次」。
    counts_full = _count_by_type(evs_all)
    badges = [{"k": "事件", "v": "%d" % total_events},
              {"k": "轨道", "v": str(len(tracks))},
              {"k": "时长", "v": _fmt_us(tmax) if has_time else "—"},
              {"k": "时间轴", "v": "冻结" if t_frozen else ("时间" if has_time else "序号"),
               "level": "bad" if t_frozen else ("ok" if has_time else "warn")}]
    for typ in ("sched", "isr", "fault"):
        if counts_full.get(typ):
            badges.append({"k": {"sched": "上下文切换", "isr": "中断进出", "fault": "异常"}[typ],
                           "v": str(counts_full[typ]),
                           "level": "bad" if typ == "fault" else None})
    if sched:
        n_lane = [tid for tid in lanes if _name_of(names, tid) is not None]
        badges.append({"k": "任务名", "v": "%d/%d" % (len(n_lane), len(lanes)),
                       "level": "ok" if len(n_lane) == len(lanes)
                                else ("warn" if n_lane else "bad")})
    if gaps:
        badges.append({"k": "丢失断口", "v": str(len(gaps)), "level": "bad"})
    lost = _num(payload.get("lost_events")) if isinstance(payload, dict) else None
    if lost is None and isinstance(payload, dict):
        lost = _num(payload.get("lost"))
    if lost:
        badges.append({"k": "丢失", "v": str(int(lost)), "level": "bad"})

    return {"ok": True, "model": {
        "kind": "timeline",
        "title": title or "事件时间线",
        "subtitle": unit_note,
        "span": [0.0, float(tmax)],
        "tracks": tracks, "markers": markers, "gaps": gaps,
        "badges": badges, "notes": notes, "limits": limits,
    }}


def _int_or_none(v):
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None


def _lane_color(idx: int):
    pal = ["#4a9eff", "#2ed573", "#ff9f43", "#a55eea", "#37d3d3", "#ff5c69",
           "#e8b339", "#7bd389", "#f78fb3", "#6c7bff"]
    return pal[idx % len(pal)]


def _fmt_us(us) -> str:
    us = float(us or 0)
    if us >= 1e6:
        return "%.3f s" % (us / 1e6)
    if us >= 1e3:
        return "%.3f ms" % (us / 1e3)
    return "%.1f µs" % us


# ------------------------------------------------------------------- scope

def _infer_chan_type(values):
    vals = [v for v in values if v is not None]
    if vals and all((v in (0, 1, True, False)) for v in vals):
        return "bool"
    if vals and all(float(v).is_integer() for v in vals) and len(set(vals)) <= 8:
        return "enum"
    return "analog"


def scope_from_samples(payload, names: dict = None, title: str = "") -> dict:
    """变量 scope 数据 → scope 模型。

    接受 `trace_scope_read` 的返回（样本在 `recent`）或 `trace_scope_stop` 的
    汇总，也接受调用方自己给的 `samples`/`series`。
    """
    rows = None
    for key in ("series", "samples", "recent", "rows"):
        v = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(v, list) and v:
            rows = v
            break
    if rows is None:
        return {"ok": False, "error_code": "view-empty-data",
                "error": "这份数据里没有样本序列（samples/recent），画不了波形",
                "hint": "trace_scope_start 之后用 trace_scope_read 取样本，"
                        "把它的返回整个传进来；跨多次采样请自己拼成 samples 列表"}
    # 变量名集合：按出现顺序
    chans = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        for k in r:
            if k == "t" or k in [c["name"] for c in chans]:
                continue
            chans.append({"name": k})
    if not chans:
        return {"ok": False, "error_code": "view-empty-data",
                "error": "样本里除了 t 没有任何通道字段"}
    by_var = payload.get("by_var") or {}
    unit_s = _num(payload.get("t_unit_s"), 1.0)      # scope 的 t 是**秒**
    t = [_num(r.get("t"), 0.0) * 1e6 * unit_s for r in rows]
    t0 = t[0] if t else 0.0
    t = [x - t0 for x in t]
    series_v = {}
    for c in chans:
        vals = [(_num(r.get(c["name"]), None) if isinstance(r, dict) else None) for r in rows]
        clean = [(None if v is None else (int(v) if float(v).is_integer() else v)) for v in vals]
        series_v[c["name"]] = clean
        meta = by_var.get(c["name"]) or {}
        c["min"] = meta.get("min") if meta.get("min") is not None else _m(clean, min)
        c["max"] = meta.get("max") if meta.get("max") is not None else _m(clean, max)
        c["changes"] = meta.get("changes")
        c["samples"] = len([v for v in clean if v is not None])
        c["type"] = _infer_chan_type(clean)
        if payload.get("t_unit_name"):
            c["unit"] = payload["t_unit_name"]
    notes, limits = collect_notes_limits(payload if isinstance(payload, dict) else {})
    miss = _num(payload.get("misses")) if isinstance(payload, dict) else None
    if miss:
        limits.append("轮询丢了 %d 个点（misses）：两次采样之间的变化看不到。" % int(miss))
    if payload.get("require_halt"):
        limits.append("该链路上读内存需要目标 halt——这份数据里的空洞可能就是这个原因。")
    limits.append("横轴是**主机轮询时刻**，不是目标执行时刻；轮询间隔之间的变化看不到。")
    if names:
        limits.append(_NAMES_DEAD_IN_SCOPE)
    eff = _num(payload.get("effective_hz")) if isinstance(payload, dict) else None
    badges = [{"k": "变量", "v": str(len(chans))},
              {"k": "样本", "v": str(len(rows))}]
    if eff:
        badges.append({"k": "有效采样率", "v": "%.1f Hz" % eff, "level": "warn" if eff < 20 else None})
    if miss:
        badges.append({"k": "丢点", "v": str(int(miss)), "level": "warn"})
    span_t = t[-1] if t else 0.0
    badges.append({"k": "时长", "v": _fmt_us(span_t)})
    return {"ok": True, "model": {
        "kind": "scope",
        "title": title or "变量 scope",
        "subtitle": payload.get("link") and ("链路 %s" % payload["link"]) or "",
        "span": [0.0, float(span_t) or 1.0],
        "channels": chans,
        "series": {"t": t, "v": series_v},
        "badges": badges, "notes": notes, "limits": limits,
    }}


def _m(vals, fn):
    v = [x for x in vals if x is not None]
    return fn(v) if v else None


# -------------------------------------------------------------------- bars

def bars_from_payload(payload: dict, title: str = "", top: int = 40) -> dict:
    """函数/耗时统计 → bars 模型。

    认识三种口径（都来自本工具链自己的采集结果）：
      · `by_function`: [{function, samples, percent}]（trace_pcsample / trace_profile）
      · `hot`: [{name, hits}]（coverage_read）
      · `items`: [{group, stat_slot, count, total_ms, min_ms, max_ms}]（trace_eventrec 统计）
    """
    items, unit, note = [], "", ""
    if isinstance(payload.get("by_function"), list) and payload["by_function"]:
        total = sum((_num(r.get("samples"), 0) or 0) for r in payload["by_function"])
        for r in payload["by_function"][:top]:
            v = _num(r.get("samples"), 0) or 0
            items.append({"name": str(r.get("function") or "?"), "value": v,
                          "share": r.get("percent") if r.get("percent") is not None
                                   else (round(100.0 * v / total, 2) if total else None)})
        unit = "样本"
        note = "占比是**采样命中占比**，只能说明热点大概在哪，不是精确耗时。"
    elif isinstance(payload.get("hot"), list) and payload["hot"]:
        total = sum((_num(r.get("hits"), 0) or 0) for r in payload["hot"])
        for r in payload["hot"][:top]:
            v = _num(r.get("hits"), 0) or 0
            items.append({"name": str(r.get("name") or "?"), "value": v,
                          "share": round(100.0 * v / total, 2) if total else None})
        unit = "命中"
        note = "按 PC 采样命中次数排序：命中多 = 在那里待得久，不代表它慢。"
    elif isinstance(payload.get("items"), list) and payload["items"]:
        rs = payload["items"][:top]
        for r in rs:
            sub = "n=%s" % r.get("count")
            if r.get("avg_ms") is not None:
                sub += " · 均 %s ms" % r.get("avg_ms")
            if r.get("max_ms") is not None:
                sub += " · 峰 %s ms" % r.get("max_ms")
            items.append({"name": "%s #%s" % (r.get("group"), r.get("stat_slot")),
                          "value": _num(r.get("total_ms"), 0) or 0, "sub": sub})
        unit = "ms"
        note = "Event Statistics 口径：total 是成对 Start/Stop 的累计时间，落单的没算进来。"
    if not items:
        return {"ok": False, "error_code": "view-empty-data",
                "error": "这份数据里没有可排序的统计（by_function / hot / items 都没有）",
                "hint": "trace_pcsample、trace_profile、coverage_read、trace_eventrec 的结果都支持"}
    items.sort(key=lambda r: -(r["value"] or 0))
    mx = max([it["value"] or 0 for it in items] or [1])
    for it in items:
        it["value"] = round(it["value"], 4) if it["value"] < 1 else round(it["value"], 2)
        it.setdefault("share", None)
    notes, limits = collect_notes_limits(payload)
    if note:
        limits.append(note)
    if len(payload.get("by_function") or payload.get("hot") or payload.get("items") or []) > top:
        limits.append("只显示前 %d 条（总共 %d 条）。" % (
            top, len(payload.get("by_function") or payload.get("hot") or payload.get("items"))))
    if payload.get("intrusive"):
        limits.append("这次采集是**侵入式**的（每样本 halt+resume），会扰动实时性。")
    if payload.get("unseen"):
        limits.append("有 %d 个函数一次都没命中（unseen），需要的话用 coverage_read 的 unseen 列表看。" %
                      len(payload["unseen"]))
    badges = [{"k": "条目", "v": str(len(items))},
              {"k": "最大", "v": "%.2f %s" % (mx, unit)}]
    for k, lab in (("samples", "样本"), ("distinct_pcs", "不同 PC"), ("duration_s", "耗时")):
        if payload.get(k) is not None:
            badges.append({"k": lab, "v": str(payload[k])})
    if payload.get("sampler_active") is False:
        badges.append({"k": "采样器", "v": "没在工作", "level": "bad"})
    return {"ok": True, "model": {
        "kind": "bars", "title": title or "统计排行",
        "subtitle": payload.get("link") and ("链路 %s" % payload["link"]) or "",
        "bars": {"unit": unit, "items": items},
        "badges": badges, "notes": notes, "limits": limits,
    }}


# ------------------------------------------------------------ trace_record

def timeline_from_record(payload: dict, title: str = "") -> dict:
    """trace_record 的函数进入/退出时间线 → timeline 模型。"""
    tl = payload.get("timeline") if isinstance(payload, dict) else None
    if not isinstance(tl, list) or not tl:
        return {"ok": False, "error_code": "view-empty-data",
                "error": "这份数据里没有 timeline（trace_record 的进入/退出事件）",
                "hint": "先 trace_record(action=\"run\")，再用 trace_record(action=\"read\")"}
    hz = _cpu_hz(payload) or 0.0
    cyc = [(i, _num(e.get("cyc"))) for i, e in enumerate(tl) if isinstance(e, dict)]
    have_cyc = any(c is not None for _i, c in cyc)
    t_us, unit_note = [], ""
    if have_cyc:
        base = next((c for _i, c in cyc if c is not None), 0.0)
        t_us = [None if c is None else (c - base) * 1e6 / hz if hz else (c - base) for _i, c in cyc]
        unit_note = ("µs（DWT 周期换算，cpu_hz=%.0f）" % hz) if hz else "周期数（没给 cpu_hz，未换算）"
    else:
        t_us = [float(i) for i in range(len(tl))]
        unit_note = "事件序号（这次命中读不到 DWT_CYCCNT）"
    tmax = max([t for t in t_us if t is not None] or [1.0]) or 1.0
    funcs, tracks = {}, {}
    for idx, e in enumerate(tl):
        fn = str(e.get("func") or "?")
        kind = str(e.get("kind") or "")
        t = t_us[idx]
        if t is None:
            continue
        funcs.setdefault(fn, {"marks": [], "open": None, "pairs": []})
        funcs[fn]["marks"].append([t, None])
        if kind.startswith("enter"):
            funcs[fn]["open"] = t
        elif kind.startswith("exit") and funcs[fn]["open"] is not None:
            funcs[fn]["pairs"].append([funcs[fn]["open"], t])
            funcs[fn]["open"] = None
    for n, (fn, d) in enumerate(sorted(funcs.items(), key=lambda kv: -len(kv[1]["marks"]))):
        tracks["f-" + fn] = {"id": "f-" + fn, "name": fn,
                             "sub": "%d 次进入 / %d 段区间" % (len(d["marks"]), len(d["pairs"])),
                             "type": "spans" if len(d["pairs"]) >= len(d["marks"]) * 0.5 else "marks",
                             "spans": d["pairs"], "marks": d["marks"],
                             "count": len(d["marks"]), "toggle": True}
    notes, limits = collect_notes_limits(payload)
    limits.append("函数进入/退出是 **FPB 断点命中**换来的（侵入式，每次命中要停机读寄存器）："
                  "事件间隔不能当精确耗时。")
    if payload.get("events_dropped"):
        limits.append("长录制丢了 %s 条事件。" % payload["events_dropped"])
    if payload.get("cyccnt_note"):
        limits.append(str(payload["cyccnt_note"]))
    badges = [{"k": "函数", "v": str(len(tracks))},
              {"k": "事件", "v": str(len(tl))},
              {"k": "时长", "v": _fmt_us(tmax) if have_cyc else "—",
               "level": None if have_cyc else "warn"}]
    return {"ok": True, "model": {
        "kind": "timeline", "title": title or "函数进入/退出时间线",
        "subtitle": unit_note, "span": [0.0, float(tmax)],
        "tracks": list(tracks.values()), "markers": [], "gaps": [],
        "badges": badges, "notes": notes, "limits": limits,
    }}


# ---------------------------------------------------------------- 直填 spec

_ALLOWED_KIND = ("timeline", "scope", "bars", "report")

# 波形视图的通道名来自数据字段名，names（"0x10=led_task"）在这里没有作用对象。
# 过去静默忽略，用的人会以为改名生效了——改成写进页面的边界栏。
_NAMES_DEAD_IN_SCOPE = ("波形视图用不上 names（它认的是**事件 id 数字**）：通道名直接取数据里的字段名，"
                        "要改名请改采样时的变量名。")

# 轨道里**真会被画出来**的键（runtime.js 认的就是这三个）。名字写错
# （items / data / values）不会报错，但会渲染出一张**空白图**——空白图会被读成
# 「这段时间什么都没发生」，比报错危险，所以这里必须硬校验。
_TRACK_KEYS = ("spans", "pairs", "marks")


def _bad_spec(error, hint=""):
    r = {"ok": False, "error_code": "view-bad-spec", "error": error}
    if hint:
        r["hint"] = hint
    return r


def _entries_ok(tname, key, seq):
    """轨道条目体检：spans/pairs 要 [起, 止]，marks 要 [时刻(, 标签)]。"""
    for e in seq:
        if not isinstance(e, (list, tuple)) or not e or _num(e[0]) is None:
            return _bad_spec(
                "轨道 %r 的 %s 里有不合规的条目：%r（要 [时刻] 或 [时刻, 标签]，时刻必须是数字）"
                % (tname, key, e),
                "spans / pairs 是 [起, 止]；marks 是 [时刻, 标签?]。符号名、字符串时间都要先自己换算成数字。")
        if key in ("spans", "pairs") and (len(e) < 2 or _num(e[1]) is None):
            return _bad_spec(
                "轨道 %r 的 %s 里有不合规的区间：%r（要 [起, 止]，两个都是数字）" % (tname, key, e))
    return None


def norm_report_section(sec):
    """report 的一节：h2→h、p 字符串→[p]、ul→bullets、pre→code。

    返回 (节, None) 或 (None, 错误文本)。两条入口共用，免得同一份 spec 换个内容
    就有两种命运。
    """
    if not isinstance(sec, dict):
        return None, "sections 的每一项都必须是对象：{h, p:[…], bullets:[…], code, view}"
    s2 = dict(sec)
    if s2.get("h") is None and s2.get("h2") is not None:
        s2["h"] = s2.pop("h2")
    if isinstance(s2.get("p"), str):
        s2["p"] = [s2["p"]]
    if s2.get("bullets") is None and s2.get("ul") is not None:
        b = s2.pop("ul")
        s2["bullets"] = [b] if isinstance(b, str) else b
    if s2.get("code") is None and s2.get("pre") is not None:
        s2["code"] = s2.pop("pre")
    if s2.get("p") is not None and not isinstance(s2["p"], list):
        return None, "sections[].p 要是数组或字符串，收到 %s" % type(s2["p"]).__name__
    return s2, None


def norm_verdict(vd):
    """verdict 允许简写成字符串（当 level 用），别把结论静默丢掉。"""
    if isinstance(vd, str):
        return {"level": vd, "text": ""}, None
    if vd is not None and not isinstance(vd, dict):
        return None, "verdict 要么是字符串（ok/warn/bad/dim），要么是 {level, text}"
    return vd, None


def from_spec(spec: dict, names: dict = None) -> dict:
    """调用方（AI）自己给的渲染模型：只做字段规整与体检，不改语义。

    **结构不对一律报 `view-bad-spec`，不静默画半张/空白图**：空白图会被读成
    「这段时间什么都没发生」，那是最坏的一种「看似权威的错答案」。
    """
    if not isinstance(spec, dict):
        return _bad_spec("spec 必须是对象")
    kind = str(spec.get("kind") or spec.get("view") or "").strip()
    if kind not in _ALLOWED_KIND:
        return _bad_spec("kind 必须是 %s 之一，收到 %r" % ("/".join(_ALLOWED_KIND), kind))
    m = dict(spec)
    m["kind"] = kind
    m.setdefault("title", "mdkdebug 视图")
    m.setdefault("badges", [])
    m.setdefault("notes", [])
    m.setdefault("limits", [])

    if kind == "timeline":
        if m.get("tracks") is not None and not isinstance(m["tracks"], list):
            return _bad_spec("timeline 的 tracks 必须是数组，收到 %s" % type(m["tracks"]).__name__,
                             '写法：tracks=[{name, type:"spans"|"intervals"|"marks", spans/pairs/marks:[…]}]')
        tracks = m.get("tracks") or []
        ts, n_items = [], 0
        for t in tracks:
            if not isinstance(t, dict):
                return _bad_spec("tracks 的每一项都必须是对象（{name,type,spans/marks}）")
            keys = [k for k in _TRACK_KEYS if isinstance(t.get(k), list)]
            if not keys:
                return _bad_spec(
                    "轨道 %r 里没有画图用的数据：需要 %s 之一，收到的键是 %s"
                    % (t.get("name") or t.get("id") or "?", " / ".join(_TRACK_KEYS),
                       ", ".join(sorted(t.keys())) or "（除了 name 什么都没有）"),
                    "键名就是 spans（区间）/ pairs（区间）/ marks（点）；写成 items / data 会画出空白图。"
                    "区间 [起, 止]，点 [时刻, 标签?]，时刻单位统一用微秒。")
            t.setdefault("type", "spans" if "spans" in keys else ("intervals" if "pairs" in keys else "marks"))
            for k in keys:
                bad = _entries_ok(t.get("name") or t.get("id") or "?", k, t[k])
                if bad:
                    return bad
                for e in t[k]:
                    ts.append(_num(e[0]))
                    if k != "marks":
                        ts.append(_num(e[1]))
                n_items += len(t[k])
        if not isinstance(m.get("span"), list) or len(m["span"]) != 2:
            m["span"] = [0.0, float(max(ts) if ts else 1.0)]
            m["limits"].append("没给 span，按数据里的最大时刻推的。")
        m["limits"].append("时刻统一按**微秒**解释（页面内部单位）：给的是毫秒/秒的数据要先自己换算，"
                           "否则时长会差 1000 倍。")
        m["tracks"] = tracks
        m.setdefault("markers", [])
        m.setdefault("gaps", [])
        m["badges"] = list(m.get("badges") or []) + [{"k": "轨道", "v": str(len(tracks))},
                                                     {"k": "元素", "v": str(n_items)},
                                                     {"k": "时长", "v": _fmt_us(m["span"][1])}]
    elif kind == "scope":
        s = m.get("series") or {}
        if not isinstance(m.get("channels"), list) or not m["channels"] or not s.get("t"):
            return _bad_spec("scope 需要 channels:[{name}] 和 series:{t:[…], v:{名字:[…]}}",
                             "自己造的波形（算法中间量、仿真信号）走这条路；"
                             "trace_scope_read 的返回直接丢给 view=auto 就行。")
        m["channels"] = [dict(c, type=c.get("type") or "analog") for c in m["channels"]]
        if names:
            m["limits"].append(_NAMES_DEAD_IN_SCOPE)
        t = s["t"]
        m.setdefault("span", [0.0, float(t[-1] if t else 1.0)])
        m["badges"] = list(m.get("badges") or []) + [{"k": "通道", "v": str(len(m["channels"]))},
                                                     {"k": "样本", "v": str(len(t))}]
    elif kind == "bars":
        b = m.get("bars")
        if not isinstance(b, dict) and isinstance(m.get("items"), list):
            # items 是简写；单位没给就不给——不能替调用方安一个单位
            b = {"items": m["items"], "unit": m.get("unit") or ""}
        if not isinstance(b, dict) or not isinstance(b.get("items"), list) or not b["items"]:
            return _bad_spec("bars 需要 bars:{unit, items:[{name,value,share?}]}",
                             '也可以写成 {kind:"bars", items:[{name,value}], unit:"次"}。')
        for it in b["items"]:
            if not isinstance(it, dict) or it.get("name") is None:
                return _bad_spec("bars 的每一项都必须是 {name, value, share?}，收到 %r" % (it,))
            it.setdefault("value", 0)
        b.setdefault("unit", "")
        m["bars"] = b
        if not b["unit"]:
            m["limits"].append("这份 spec 没写单位（bars.unit），所以数值只是数字——"
                               "**别替它读成 ms 或次数**。")
        m["badges"] = list(m.get("badges") or []) + [{"k": "条目", "v": str(len(b["items"]))}]
    elif kind == "report":
        m.setdefault("sections", [])
        if not isinstance(m["sections"], list):
            return _bad_spec("report 的 sections 必须是数组：sections:[{h, p:[…], view:{…}}]")
        vd, verr = norm_verdict(m.get("verdict"))
        if verr:
            return _bad_spec(verr)
        m["verdict"] = vd
        norm = []
        for sec in m["sections"]:
            s2, err = norm_report_section(sec)
            if err:
                return _bad_spec(err)
            norm.append(s2)
        m["sections"] = norm
        m["badges"] = list(m.get("badges") or []) + [{"k": "段落", "v": str(len(m["sections"]))}]
    return {"ok": True, "model": m}
