"""软插桩的**分析层**：把「采到的一堆事件」算成结论（trace_stats）与
可命名的问题（trace_diagnose）。

为什么需要它
------------
采集类工具（trace_swo_read / trace_swd_read / trace_buff_dump …）给的是
**事件列表**：一台设备连着几条、id 几号、什么时候、谁切到谁。列表本身不是结论，
每次都要人肉去数。Percepio Tracealyzer / SEGGER SystemView 值钱的地方有一半
就在这里：CPU 负载、任务执行时间、ISR 时长、堆占用——一条命令给出来。

本模块补上这一层，并且守住本项目的一条底线：**算不出来就说算不出来**。
每个指标都带 `basis`（依据什么算的）或落在 `not_applicable`（为什么不适用），
绝不给一个「看起来很权威」的数字。特别地：

* 时间占比类指标（CPU 负载 / 各任务执行时间 / ISR 时长 / 等待时长）**只认目标侧
  时间基**（buff 的 `t_cycles`、swd 的 `cycles`/`rel_cycles`）。SWO/RTT（MTF）通路
  只有主机的到达时刻 `t`：那里面混着链路缓冲与主机调度抖动，用它算占比会得到
  一个看着很正常、实际是错的数——所以这些指标在 MTF 源上一律 `not_applicable`。
* 计数类指标（事件数 / 类型分布 / 同步原语次数 / 堆净额）不需要时间基，任何源都能算。
* 配对（wait→signal、isr enter→exit）按流过顺序做，**不用时间**；只有时长需要时间。

三种数据源的事件形状不一样（MTF 帧 / SWD 会话 / buff 记录），所以先归一化：
    {src, type, kind, id, arg, obj, op, op_name, from, to, size,
     id_name, from_name, to_name, task_name,
     t_c, t_u, t_host, fault_class, cfsr, cfsr_bits, events_dropped}

`trace_diagnose` 是规则层：把上面的事实过一遍规则，产出一组 findings，每条带
severity + evidence（最小证据）+ hint（下一步怎么做）。同时输出 `checked` 与
`not_applicable`——**没查 ≠ 通过**，一条规则没被评估时必须说清为什么。
"""

from __future__ import annotations

import json

from . import trace as _tr
from . import traceproto as _tp

# 诊断阈值（调用方可在工具参数里覆盖）
DEFAULT_ISR_LONG_US = 1000.0     # 单个 ISR 超过这个时长值得看一眼
DEFAULT_QUIET_RATIO = 100.0      # 最大 dt 超过平均 dt 这么多倍算「长静默」

_SOURCES = ("auto", "session", "mtf", "swd", "buff")
_SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}

# 判定「这段时间是 idle 在跑」的两种依据：任务号（0xF）或解出来的名字。
_IDLE_NAMES = ("idle", "IDLE", "Idle")


# ================================================================ 基础工具

def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _top(d: dict, n: int = 20) -> list:
    return [{"key": k, "count": v} for k, v in
            sorted(d.items(), key=lambda kv: -kv[1])[:n]]


def _mean(xs: list):
    return round(sum(xs) / float(len(xs)), 3) if xs else None


# ================================================================ 归一化

def _fix_mtf_semantics(ev: dict) -> None:
    """MTF 帧里语义是打包在 id/arg 里的，拆出来（就地修改）。

    sched: id=from, arg=to        fault: id=类别, arg=CFSR
    sync : id=(obj<<3)|op         heap : id=op, arg=size
    """
    typ = ev.get("type")
    i = ev.get("id")
    if typ == "sched" and _is_int(i):
        ev["from"] = i
        ev["to"] = ev.get("arg")
    elif typ == "fault" and _is_int(i):
        ev["fault_class"] = _tr._BUFF_FAULT_CLASS.get(i, "class%d" % i)
        a = ev.get("arg")
        if _is_int(a):
            ev["cfsr"] = "0x%08X" % (a & 0xFFFFFFFF)
            ev["cfsr_bits"] = _tr._buff_cfsr_bits(a)
    elif typ in ("sync", "heap"):
        _tr._derive_semantics(ev)


def _norm_mtf(e: dict):
    """MTF（SWO/RTT）事件 → 归一化事件；不是事件的返回 None。

    解码后的 MTF 帧带 `type`（int）与 `type_name`；ITM 硬件报文只带字符串 `kind`。
    后者里只有 pc_sample（可用于热点）与 overflow（一个断口）对分析有意义。
    """
    t = e.get("type")
    if not _is_int(t):
        k = e.get("kind")
        if k == "pc_sample":
            return {"src": "mtf", "type": "pc_sample", "pc": e.get("pc"),
                    "t_host": e.get("t") if _is_num(e.get("t")) else None}
        if k == "overflow":
            return {"src": "mtf", "type": "gap", "kind": "overflow",
                    "events_dropped": None,
                    "t_host": e.get("t") if _is_num(e.get("t")) else None}
        return None
    name = e.get("type_name") or _tp.MTF_TYPES.get(t, "type%d" % t)
    ev = {"src": "mtf", "type": name,
          "id": e.get("id"), "arg": e.get("arg"),
          "t_host": e.get("t") if _is_num(e.get("t")) else None}
    k = e.get("kind")
    if _is_int(k):
        ev["kind"] = _tp.MTF_KINDS.get(k, "kind%d" % k)
    elif isinstance(k, str):
        ev["kind"] = k
    if isinstance(e.get("id_name"), str):
        ev["id_name"] = e["id_name"]
    _fix_mtf_semantics(ev)
    return ev


def _norm_stream(e: dict, src: str):
    """SWD 会话事件 / buff 记录 → 归一化事件（两者字段几乎一致，只有时间键不同）。"""
    if not isinstance(e, dict):
        return None
    typ = e.get("type")
    if not isinstance(typ, str):
        return None
    ev = {"src": src, "type": typ, "kind": e.get("kind"),
          "id": e.get("id"), "arg": e.get("arg"),
          "from": e.get("from"), "to": e.get("to")}
    if _is_int(e.get("obj")):
        ev["obj"] = e["obj"]
    if _is_int(e.get("op")):
        ev["op"] = e["op"]
        ev["op_name"] = e.get("op_name") or "op%d" % e["op"]
    if _is_int(e.get("size")):
        ev["size"] = e["size"]
    for k in ("id_name", "from_name", "to_name", "task_name",
              "fault_class", "cfsr"):
        if isinstance(e.get(k), str):
            ev[k] = e[k]
    if isinstance(e.get("cfsr_bits"), list):
        ev["cfsr_bits"] = e["cfsr_bits"]
    if _is_int(e.get("events_dropped")) or e.get("events_dropped") is not None:
        ev["events_dropped"] = e.get("events_dropped")
    # 目标侧时间基：优先绝对周期（cycles），退化到会话内相对周期（rel_cycles），
    # 再到 buff 的 t_cycles。swd 的 t_us 在 _swd_anchor 之后是绝对的，用它。
    tc = None
    for k in ("cycles", "t_cycles", "rel_cycles"):
        if _is_int(e.get(k)):
            tc = e[k]
            break
    if tc is not None:
        ev["t_c"] = tc
    if _is_num(e.get("t_us")):
        ev["t_u"] = float(e["t_us"])
    return ev


def normalize(evs, src: str) -> list:
    out = []
    for e in (evs or []):
        if not isinstance(e, dict):
            continue
        n = _norm_mtf(e) if src == "mtf" else _norm_stream(e, src)
        if n is not None:
            out.append(n)
    return out


# ================================================================ 采集

def collect(source: str = "auto", elf: str = "", addr: str = "",
            limit: int = 0, names: str = "", link: str = "auto",
            cpu_hz: int = 0) -> dict:
    """把选定数据源的事件读进内存并归一化。

    source：
      auto / session —— 当前进程内已采到的事件（MTF 通路 + SWD 会话），**不碰设备**；
      mtf / swd      —— 只取其中一条通路；
      buff           —— 现场读一次目标 RAM 里的 buff 环形缓冲（需要 link 可用）。

    `auto` 刻意**不**去自动读设备：一个「看一眼现在什么情况」的分析工具不该有
    隐式的一次调试器读。要看 buff 就显式给 source="buff"。
    """
    src = str(source or "auto").strip().lower()
    if src not in _SOURCES:
        return {"ok": False, "source": src,
                "error": "source 只认 %s" % " / ".join(_SOURCES)}
    evs, meta, seen = [], {}, {}

    def take(which):
        got = []
        if which in ("mtf", "session"):
            st = _tr.state()
            raw = list(st.get("events") or [])
            seen["mtf"] = len(raw)
            got += normalize(raw, "mtf")
        if which in ("swd", "session"):
            st = _tr.state()
            s = st.get("swd") or {}
            raw = list(s.get("events") or [])
            seen["swd"] = len(raw)
            got += normalize(raw, "swd")
        return got

    if src in ("auto", "session"):
        evs = take("session")
    elif src in ("mtf", "swd"):
        evs = take(src)
    else:  # buff：现场读一次
        dump = _tr.buff_dump(elf=elf, addr=addr, limit=int(limit or 100000),
                             names=names, link=link)
        if not dump.get("ok"):
            return {"ok": False, "source": "buff", "error": dump.get("error")
                    or dump.get("reason") or "读 buff 失败", "buff": dump}
        raw = list(dump.get("events") or [])
        seen["buff"] = raw
        evs = normalize(raw, "buff")
        meta = {"buff": {k: dump.get(k) for k in
                         ("record_count", "wrapped", "total", "cap", "lost",
                          "text_dropped", "cpu_hz", "span_cycles", "span_us",
                          "truncated", "segment_seq")
                         if k in dump}}
        if not cpu_hz and _is_int(dump.get("cpu_hz")):
            cpu_hz = dump["cpu_hz"]

    out = {"ok": True, "source": src, "events": evs, "seen": seen,
           "cpu_hz": int(cpu_hz or 0)}
    out.update(meta)
    return out


# ================================================================ 分析

def analyze(events: list, cpu_hz: int = 0,
            isr_long_us: float = DEFAULT_ISR_LONG_US,
            quiet_ratio: float = DEFAULT_QUIET_RATIO) -> dict:
    """把归一化事件算成结论。算不出来的进 not_applicable，不给假数字。"""
    n = len(events)
    checked, na = [], {}

    by_type, by_kind = {}, {}
    for e in events:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        if e.get("kind"):
            by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1

    out = {
        "events": n,
        "counts_by_type": by_type,
        "counts_by_kind": by_kind,
        "top_ids": _top(_id_counts(events)),
        "checked": checked,
        "not_applicable": na,
    }

    # ---------------- 时间基 ----------------
    has_c = any(_is_int(e.get("t_c")) for e in events)
    has_u = any(_is_num(e.get("t_u")) for e in events)
    if has_c:
        basis = "cycles"
    elif has_u:
        basis = "us"
    else:
        basis = "none"
    tb = {"basis": basis, "cpu_hz": int(cpu_hz or 0)}
    if basis == "cycles" and not cpu_hz:
        tb["note"] = ("有绝对周期数但没有 CPU 主频，无法换算成微秒；"
                      "占比（负载）仍可算，绝对时长只给周期数")
    out["timebase"] = tb

    def tv(e):
        if basis == "cycles":
            return e.get("t_c")
        if basis == "us":
            return e.get("t_u")
        return None

    timed = sorted((e for e in events if tv(e) is not None), key=tv)
    if basis == "none":
        na["span"] = ("所有来源都没有目标侧时间戳：MTF（SWO/RTT）只有主机到达时刻，"
                      "混着链路与主机调度抖动，不能当时间基用")
    elif len(timed) < 2:
        na["span"] = "带时间戳的事件不足 2 条，构不成区间"
    else:
        t0, t1 = tv(timed[0]), tv(timed[-1])
        span = t1 - t0
        to_us = (lambda x: round(x * 1e6 / cpu_hz, 3)) if (
            basis == "cycles" and cpu_hz) else (lambda x: round(x, 3))
        out["span"] = {"basis": ("target-cycles" if basis == "cycles" else "target-us"),
                       "t0": t0, "t1": t1,
                       "span_cycles": int(span) if basis == "cycles" else None,
                       "span_us": to_us(span) if (basis == "us" or cpu_hz) else None,
                       "timed_events": len(timed),
                       "untimed_events": n - len(timed)}
        checked.append("span")
        if n and out["span"]["span_us"]:
            out["events_per_s"] = round(n / (out["span"]["span_us"] / 1e6), 3)

    # ---------------- 调度 / CPU 负载 ----------------
    sched = [e for e in events if e["type"] == "sched"
             and _is_int(e.get("from")) and _is_int(e.get("to"))]
    if not sched:
        na["sched"] = ("没有调度事件（type=sched）：要么目标不是 RTOS、要么内核钩子"
                       "没插在切换点上")
    else:
        info = {"events": len(sched),
                "switches": sum(1 for e in sched
                                if _is_int(e.get("from")) and _is_int(e.get("to")))}
        ts = [e for e in sched if tv(e) is not None]
        if basis == "none" or len(ts) < 2:
            na["sched.exec"] = ("调度事件没有目标侧时间戳，算不出各任务执行时间与 "
                                "CPU 负载（用 MTF 的主机到达时刻算会是错的）")
            info["timed_events"] = len(ts)
        else:
            exec_c = {}
            into_c, out_c = {}, {}
            for e in sched:
                f, t = e.get("from"), e.get("to")
                out_c[f] = out_c.get(f, 0) + 1
                into_c[t] = into_c.get(t, 0) + 1
            busy = total = 0
            for i in range(len(ts) - 1):
                cur, nxt = ts[i], ts[i + 1]
                run = cur.get("to")
                dt = tv(nxt) - tv(cur)
                if dt <= 0 or not _is_int(run):
                    continue
                total += dt
                exec_c[run] = exec_c.get(run, 0) + dt
                if not _is_idle(run, cur):
                    busy += dt
            if total <= 0:
                na["sched.exec"] = "调度事件的时间戳全部相同（时间轴冻结），区间为 0"
            else:
                to_us = (lambda x: round(x * 1e6 / cpu_hz, 3)) if cpu_hz else (
                    lambda x: round(x, 3))
                tasks = []
                for k, v in sorted(exec_c.items(), key=lambda kv: -kv[1]):
                    tasks.append({
                        "task": _task_label(k),
                        "exec_us": to_us(v) if (basis == "us" or cpu_hz) else None,
                        "exec_cycles": int(v) if basis == "cycles" else None,
                        "pct": round(100.0 * v / total, 2),
                        "into": into_c.get(k, 0), "out": out_c.get(k, 0)})
                info["covered_us"] = to_us(total) if (basis == "us" or cpu_hz) else None
                info["covered_cycles"] = int(total) if basis == "cycles" else None
                info["cpu_load_pct"] = round(100.0 * busy / total, 2)
                info["idle_pct"] = round(100.0 * (total - busy) / total, 2)
                info["tasks"] = tasks
                info["basis"] = "target-cycles" if basis == "cycles" else "target-us"
                checked.append("sched.exec")
        out["sched"] = info

    # ---------------- 同步原语（wait/signal/acquire/release） ----------------
    syncs = [e for e in events if e["type"] == "sync"]
    if not syncs:
        na["sync"] = ("没有同步原语事件（type=sync）：内核没在等待/唤醒点插桩，"
                      "或这段录制里真的没有阻塞")
    else:
        ops = {}
        for e in syncs:
            ops[e.get("op_name") or "op"] = ops.get(e.get("op_name") or "op", 0) + 1
        by_obj = {}
        for e in syncs:
            if _is_int(e.get("obj")):
                d = by_obj.setdefault(e["obj"], {})
                k = e.get("op_name") or "op"
                d[k] = d.get(k, 0) + 1
        info = {"events": len(syncs), "counts_by_op": ops,
                "objects": [{"obj": k, "ops": v} for k, v in
                            sorted(by_obj.items(), key=lambda kv: -sum(kv[1].values()))[:20]]}
        # wait → signal/timeout 配对：只按流过顺序做 FIFO，**不用时间**。
        outstanding, dur, unpaired, ambiguous = {}, [], 0, 0
        for e in syncs:
            obj, op = e.get("obj"), e.get("op_name")
            if op == "wait":
                outstanding.setdefault(obj, []).append(tv(e))
            elif op in ("signal", "timeout"):
                lst = outstanding.get(obj) or []
                if lst:
                    t0 = lst.pop(0)
                    if len(lst) >= 1:
                        ambiguous += 1   # 同一对象上还有别的等待者，FIFO 假设可能不成立
                    t1 = tv(e)
                    if t0 is not None and t1 is not None and t1 >= t0:
                        dur.append(t1 - t0)
        unpaired = sum(len(v) for v in outstanding.values())
        info["wait_pairs"] = len(dur)
        info["unpaired_waits"] = unpaired
        info["ambiguous_pairs"] = ambiguous
        if dur:
            to_us = (lambda x: round(x * 1e6 / cpu_hz, 3)) if (
                basis == "cycles" and cpu_hz) else (lambda x: round(x, 3))
            info["wait_us"] = {"min": to_us(min(dur)), "max": to_us(max(dur)),
                               "mean": to_us(sum(dur) / float(len(dur))),
                               "count": len(dur)}
            if basis == "cycles" and not cpu_hz:
                info["wait_us"]["note"] = "单位为 CPU 周期（没有主频，未换算）"
            checked.append("sync.wait")
        else:
            na["sync.wait"] = ("wait 与 signal/timeout 没有成对，或没有可用时间戳："
                              "算不出等待时长（次数与对象分布仍有效）")
        out["sync"] = info

    # ---------------- 堆 ----------------
    heaps = [e for e in events if e["type"] == "heap"]
    if not heaps:
        na["heap"] = ("没有堆事件（type=heap）：内核没有堆、或没在分配/释放点插桩。"
                      "注意「没插桩」不等于「没分配」")
    else:
        allocs = [e for e in heaps if e.get("op_name") == "alloc"]
        frees = [e for e in heaps if e.get("op_name") == "free"]
        a_bytes = sum(e["size"] for e in allocs if _is_int(e.get("size")))
        f_bytes = sum(e["size"] for e in frees if _is_int(e.get("size")))
        out["heap"] = {
            "events": len(heaps), "allocs": len(allocs), "frees": len(frees),
            "alloc_bytes": a_bytes, "free_bytes": f_bytes,
            "net_bytes": a_bytes - f_bytes,
            "largest_alloc": max([e["size"] for e in allocs
                                  if _is_int(e.get("size"))] or [None]),
            "unknown_size": sum(1 for e in heaps if not _is_int(e.get("size"))),
            "note": ("net_bytes 是「本文中分配的字节 − 释放的字节」；它是**净变化**，"
                     "不是峰值占用——峰值需要每次分配时知道堆的实时用量，本协议没带，"
                     "不猜。空出 ≥64 B 余量给分配器元数据也会占，别按 net_bytes 卡死"),
        }
        checked.append("heap")

    # ---------------- 中断 ----------------
    isrs = [e for e in events if e["type"] == "isr"]
    if not isrs:
        na["isr"] = "没有中断事件（type=isr）"
    else:
        stack, dur, unpaired = {}, [], 0
        by_id = {}
        for e in isrs:
            i, k = e.get("id"), e.get("kind")
            by_id[i] = by_id.get(i, 0) + 1
            if k == "enter":
                stack.setdefault(i, []).append(tv(e))
            elif k == "exit":
                lst = stack.get(i) or []
                if lst:
                    t0 = lst.pop()
                    t1 = tv(e)
                    if t0 is not None and t1 is not None and t1 >= t0:
                        dur.append((t1 - t0, i))
        unpaired = sum(len(v) for v in stack.values())
        info = {"events": len(isrs), "enters": sum(
            1 for e in isrs if e.get("kind") == "enter"),
            "exits": sum(1 for e in isrs if e.get("kind") == "exit"),
            "unpaired": unpaired,
            "top_irqs": _top(by_id, 10)}
        if dur:
            to_us = (lambda x: round(x * 1e6 / cpu_hz, 3)) if (
                basis == "cycles" and cpu_hz) else (lambda x: round(x, 3))
            vals = sorted(x[0] for x in dur)
            slowest = max(dur, key=lambda x: x[0])
            info["duration"] = {
                "basis": ("cycles" if (basis == "cycles" and not cpu_hz) else "us"),
                "count": len(dur),
                "min": to_us(vals[0]),
                "max": to_us(vals[-1]),
                "mean": to_us(sum(vals) / float(len(vals))),
                "slowest_irq": slowest[1]}
            if basis == "cycles" and not cpu_hz:
                info["duration"]["note"] = "单位为 CPU 周期（没有主频，未换算）"
            thr = to_us(isr_long_us * cpu_hz / 1e6) if (
                basis == "cycles" and cpu_hz) else isr_long_us
            info["over_threshold"] = sum(1 for v in vals if v > thr)
            info["threshold"] = {"value": isr_long_us, "unit": "us"}
            checked.append("isr.duration")
        else:
            na["isr.duration"] = ("enter/exit 没成对，或没有可用时间戳：算不出中断时长"
                                  "（次数与最忙的中断号仍有效）")
        out["isr"] = info

    # ---------------- 异常 ----------------
    faults = [e for e in events if e["type"] == "fault" or e.get("fault_class")]
    if not faults:
        na["fault"] = "没有异常事件（type=fault）：这段录制里没触发 fault 捕获"
    else:
        out["faults"] = [{"class": e.get("fault_class"), "cfsr": e.get("cfsr"),
                          "cfsr_bits": e.get("cfsr_bits"),
                          "t_us": e.get("t_u")} for e in faults[:20]]
        out["fault_count"] = len(faults)
        checked.append("fault")

    # ---------------- 断口 / 段 ----------------
    gaps = [e for e in events if e["type"] == "gap"]
    segments = [e for e in events if e["type"] == "segment"]
    dropped = sum(e["events_dropped"] for e in gaps
                  if _is_int(e.get("events_dropped")))
    out["gaps"] = {"events": len(gaps), "dropped": dropped}
    out["segments"] = {"count": len(segments),
                       "seq": [e.get("seq") for e in segments][:10]}
    if gaps or segments:
        checked.append("gaps")

    # ---------------- 时间轴健康状况 ----------------
    if basis != "none" and len(timed) >= 2:
        t0, t1 = tv(timed[0]), tv(timed[-1])
        dts = [tv(timed[i + 1]) - tv(timed[i]) for i in range(len(timed) - 1)]
        pos = [d for d in dts if d > 0]
        out["dt"] = {"count": len(dts),
                     "zero": sum(1 for d in dts if d == 0),
                     "min": min(dts), "max": max(dts) if dts else None,
                     "mean": round(sum(dts) / float(len(dts)), 3) if dts else None}
        out["dt"]["frozen"] = (t1 == t0)
        if pos and out["dt"]["mean"]:
            out["dt"]["quiet_ratio"] = round(max(pos) / (sum(pos) / float(len(pos))), 2)
        checked.append("dt")
        if segments:
            out["dt"]["caveat"] = ("这段录制里有 %d 个段重开标记（segment）："
                                   "段与段之间的时间轴不连续，跨段算出来的时长会偏"
                                   % len(segments))

    if n and not events[0].get("type"):
        na["normalize"] = "输入事件没有可识别的 type（不是本工具认识的形状）"
    return out


def _id_counts(events: list) -> dict:
    d = {}
    for e in events:
        i = e.get("id")
        if _is_int(i):
            d[i] = d.get(i, 0) + 1
    return d


def _is_idle(task, ev) -> bool:
    if task == _tr._SVCRT_IDLE_ID:
        return True
    nm = ev.get("to_name")
    return bool(nm and nm in _IDLE_NAMES)


def _task_label(v) -> str:
    if v is None:
        return "?"
    if v == _tr._SVCRT_IDLE_ID:
        return "idle"
    return "task%d" % v


# ================================================================ 对外：stats

def stats(source: str = "auto", elf: str = "", addr: str = "", limit: int = 0,
          names: str = "", link: str = "auto", cpu_hz: int = 0,
          isr_long_us: float = DEFAULT_ISR_LONG_US) -> dict:
    """trace_stats 的实现：采集 + 分析。"""
    got = collect(source=source, elf=elf, addr=addr, limit=limit, names=names,
                  link=link, cpu_hz=cpu_hz)
    if not got.get("ok"):
        return got
    res = analyze(got["events"], cpu_hz=got.get("cpu_hz") or 0,
                  isr_long_us=isr_long_us)
    res["ok"] = True
    res["source"] = got["source"]
    res["seen"] = got["seen"]
    if got.get("buff"):
        res["buff"] = got["buff"]
    if not res["events"]:
        res["empty"] = True
        res["hint"] = ("这个来源里一条事件都没有。先确认：目标固件调过 mdk_trace_init()、"
                       "插桩点真的被执行到、后端与主机读法匹配"
                       "（trace_status / trace_guide(topic=\"when_unavailable\")）。"
                       "要看目标 RAM 里的 buff 得显式给 source=\"buff\"。")
    return res


# ================================================================ 对外：diagnose

def _f(rule, severity, title, detail, evidence=None, hint=None) -> dict:
    d = {"rule": rule, "severity": severity, "title": title, "detail": detail}
    if evidence:
        d["evidence"] = evidence
    if hint:
        d["hint"] = hint
    return d


def diagnose(source: str = "auto", elf: str = "", addr: str = "", limit: int = 0,
             names: str = "", link: str = "auto", cpu_hz: int = 0,
             isr_long_us: float = DEFAULT_ISR_LONG_US,
             quiet_ratio: float = DEFAULT_QUIET_RATIO,
             with_stats: bool = True) -> dict:
    """trace_diagnose 的实现：把事实过一遍规则，产出可命名的问题 + 证据 + 下一步。

    `checked` 是**真的评估过**的规则名，`not_applicable` 是没法评估的（带原因）。
    两者都要看：只读 findings 会把「没查」当成「没问题」。
    """
    got = collect(source=source, elf=elf, addr=addr, limit=limit, names=names,
                  link=link, cpu_hz=cpu_hz)
    if not got.get("ok"):
        return got
    evs = got["events"]
    cpu = got.get("cpu_hz") or 0
    st = analyze(evs, cpu_hz=cpu, isr_long_us=isr_long_us, quiet_ratio=quiet_ratio)

    findings, checked, na = [], [], {}

    def mark(rule):
        checked.append(rule)

    # 1. 有没有数据
    mark("no-data")
    if not evs:
        findings.append(_f(
            "no-data", "warn", "没有采到任何事件",
            "选定的数据源里一条事件都没有——任何结论都无从谈起。",
            {"source": got["source"], "seen": got.get("seen")},
            "确认固件调过 mdk_trace_init()、插桩点被执行到、后端与主机读法匹配；"
            "要看目标 RAM 里的 buff 环形缓冲要显式 source=\"buff\""))
        return _diagnose_out(got, st, findings, checked, na, with_stats)

    # 2. 时间轴
    mark("no-timeline")
    basis = st["timebase"]["basis"]
    if basis == "none":
        findings.append(_f(
            "no-timeline", "warn", "事件没有目标侧时间戳",
            "所有事件都没有绝对周期/微秒时间；跑在 MTF（SWO/RTT）上时只有主机到达"
            "时刻，那里面混着链路缓冲与主机调度抖动。",
            {"timed_events": 0, "events": len(evs)},
            "事件顺序仍然可用（计数/类型/堆净额照算）。要时间轴：改 buff 或 swd 后端"
            "（目标侧记 DWT 周期），并用 trace_instrument(coreclk=真实主频) 让主机能换算"))
    else:
        mark("timebase-missing")
        if basis == "cycles" and not cpu:
            findings.append(_f(
                "timebase-missing", "info", "有绝对周期数但没有 CPU 主频",
                "能算占比（CPU 负载按周期比例），但所有绝对时长只能给周期数。",
                {"basis": basis, "cpu_hz": 0},
                "用 trace_instrument(coreclk=真实主频) 重新部署（写进 "
                "MDK_TRACE_SWD_CPU_HZ / MDK_TRACE_CPU_HZ），或给本工具传 cpu_hz="))

    # 3. 时间轴冻结（swd 粗粒度最经典的坑）
    mark("dt-frozen")
    if st.get("dt", {}).get("frozen"):
        findings.append(_f(
            "dt-frozen", "warn", "时间轴冻结：所有事件时间戳相同",
            "目标按「与上一条的差 ÷ 粒度」算 dt 并丢掉余数；粒度比事件平均间隔粗时"
            "每条都算 0，累加出来的时间轴停在原点——舞台看着正常、时长全错。",
            {"dt_zero": st["dt"]["zero"], "dt_count": st["dt"]["count"]},
            "用更细的粒度重录：trace_swd_reset(granularity=\"cycle\")（代价是每事件"
            "字节数变大）；或保留现状，只看事件顺序、不看时长"))
    elif st.get("dt") and st["dt"].get("zero"):
        if st["dt"]["zero"] > max(1, st["dt"]["count"] // 4):
            findings.append(_f(
                "dt-zero-heavy", "warn", "超过四分之一的事件时间增量为 0",
                "这不是错误（同一周期内可以有多个事件），但比例这么高通常意味着"
                "时间粒度比事件间隔粗——绝对时长会系统性偏小。",
                {"dt_zero": st["dt"]["zero"], "dt_count": st["dt"]["count"]},
                "把粒度调细一档（trace_swd_reset(granularity=...)）再录一段对比"))

    # 4. 丢事件 / 段重开
    mark("events-lost")
    gp = st.get("gaps") or {}
    lost = int(gp.get("dropped") or 0) + int(gp.get("events") or 0)
    buf = st.get("buff") or {}
    if buf.get("lost") or buf.get("text_dropped"):
        lost += int(buf.get("lost") or 0) + int(buf.get("text_dropped") or 0)
    if lost:
        findings.append(_f(
            "events-lost", "warn", "有事件没被记录下来",
            "时间线上存在断口或目标侧丢计数：这条时间线**不完整**。",
            {"gap_events": gp.get("events"), "dropped": gp.get("dropped"),
             "buff_lost": buf.get("lost"), "text_dropped": buf.get("text_dropped")},
            "buff：缓冲太小 → 调大 MDK_TRACE_BUFF_RECORDS；swd：主机搬运跟不上 → "
            "提高 trace_swd_read 的频率或调相颗粒度；记录区旁的 lost 计数就是答案"))
    mark("segments-restarted")
    seg = st.get("segments") or {}
    if (seg.get("count") or 0) > 1 or buf.get("wrapped"):
        findings.append(_f(
            "segments-restarted", "info", "时间线跨了多个录制段",
            "存在段重开标记（或环形缓冲已回卷）：段与段之间的时间轴不连续，"
            "跨段算出来的时长会偏，别把整条时间线当成一次连续运行。",
            {"segments": seg.get("count"), "seq": seg.get("seq"),
             "wrapped": buf.get("wrapped")},
            "先 halt 目标再 trace_buff_reset / trace_swd_reset，然后重跑一遍，"
            "得到的就是一段干净连续的录制"))

    # 5. 内核事件在不在
    mark("no-sched")
    if not st.get("sched") and not st.get("sync") and not st.get("heap"):
        findings.append(_f(
            "kernel-hooks-absent", "warn", "没有任何内核事件（调度/同步/堆都没有）",
            "数据里有事件，但看不出任务切换、阻塞唤醒或堆分配——最可能是内核钩子"
            "没打开或没接上，而不是「目标什么都没做」。",
            {"counts_by_type": st.get("counts_by_type"), "seen": got.get("seen")},
            "trace_instrument(svcrt_hooks=1) 打开 MDK_TRACE_SVCRT_HOOKS，并按 "
            "mdk_trace_svcrt.h 里的 5 个钩点在核心里调一次对应函数"))
    elif not st.get("sched"):
        findings.append(_f(
            "no-sched", "info", "没有调度事件，算不出 CPU 负载与任务执行时间",
            "有别的内核事件但没有上下文切换记录——任务级占比无从算起。",
            {"counts_by_type": st.get("counts_by_type")},
            "在 PendSV / 调度器的切换点调 mdk_trace_svcrt_task_switch(from, to)"))
    elif st.get("sched", {}).get("tasks") is None:
        findings.append(_f(
            "sched-no-time", "warn", "有调度事件但没有时间戳",
            "任务切换的次数能数出来，但占比算不出来（缺目标侧时间基）。",
            {"sched_events": st["sched"].get("events")},
            "见 no-timeline 的处置：换 buff/swd 后端并给真实主频"))

    # 6. 中断
    mark("isr")
    isr = st.get("isr")
    if isr:
        if isr.get("unpaired"):
            findings.append(_f(
                "isr-unpaired", "warn", "中断 enter/exit 没有成对",
                "有 enter 没有 exit（或反过来）：时间线上这些中断的时长是无意义的，"
                "也可能是记录被截断在中断中间。",
                {"enters": isr.get("enters"), "exits": isr.get("exits"),
                 "unpaired": isr.get("unpaired")},
                "核对该 IRQ 的 enter/exit 是否都插了；靠近录制末尾的那一条可能是"
                "还没退出就被切断了（无害），中间段的才是问题"))
        d = isr.get("duration") or {}
        if (isr.get("over_threshold") or 0) > 0:
            findings.append(_f(
                "isr-long", "warn", "有中断执行时间超过阈值",
                "长中断会把别的实时任务推迟——尤其当它的优先级高于这些任务时。",
                {"threshold_us": isr_long_us, "over": isr.get("over_threshold"),
                 "max_us": d.get("max"), "slowest_irq": d.get("slowest_irq")},
                "看 slowest_irq 是哪一个，把它的临界区缩短；阈值可用 isr_long_us= 调"))
    else:
        na["isr"] = st.get("not_applicable", {}).get("isr", "没有中断事件")

    # 7. 异常
    mark("fault")
    if st.get("fault_count"):
        cls = {f.get("class") for f in (st.get("faults") or [])}
        sev = "error" if ("hardfault" in cls or "memmanage" in cls
                          or "busfault" in cls) else "warn"
        findings.append(_f(
            "fault-present", sev, "录制里有异常发生（%d 次）" % st["fault_count"],
            "目标进过 fault handler；faults 字段里有类别、CFSR 拆位与发生的时刻。",
            {"count": st["fault_count"], "classes": sorted(x for x in cls if x),
             "first": (st.get("faults") or [{}])[0]},
            "先看 CFSR 拆出来的位（如 INVSTATE = 跳进了数据、UNALIGNED = 非对齐访问），"
            "再对照 fault 时刻前后的事件定位"))
    else:
        na["fault"] = st.get("not_applicable", {}).get("fault", "没有异常事件")

    # 8. 同步原语的等待配对
    mark("sync-wait")
    sy = st.get("sync")
    if sy:
        if sy.get("unpaired_waits"):
            findings.append(_f(
                "sync-wait-unpaired", "info", "有等待没有对应的唤醒/超时",
                "可能真的还在阻塞，也可能是唤醒路径没插桩——两者的表象一样。",
                {"unpaired_waits": sy.get("unpaired_waits"),
                 "wait_pairs": sy.get("wait_pairs")},
                "确认 obj_signal / obj_timeout 在所有唤醒路径上都被调到；"
                "若确实还在阻塞，这条就是「谁卡住了」的直接证据"))
        if sy.get("ambiguous_pairs"):
            findings.append(_f(
                "sync-pair-ambiguous", "info", "等待时长的配对带歧义",
                "同一个对象上同时有多个等待者时，本工具按 FIFO 配对 wait→signal；"
                "真正的唤醒顺序由内核调度决定，可能与 FIFO 不同。",
                {"ambiguous_pairs": sy.get("ambiguous_pairs"),
                 "wait_pairs": sy.get("wait_pairs")},
                "要精确的逐任务等待时长，需要内核在 wait 事件里带上任务号"
                "（当前协议只带对象）"))
    else:
        na["sync"] = st.get("not_applicable", {}).get("sync", "没有同步原语事件")

    # 9. 长静默
    mark("quiet-window")
    dt = st.get("dt") or {}
    if dt.get("quiet_ratio") and dt["quiet_ratio"] > quiet_ratio:
        findings.append(_f(
            "quiet-window", "info", "有一段时间远长于平均事件间隔",
            "最大事件间隔是平均间隔的 %s 倍。可能只是任务真的没事干，"
            "也可能是这段时间的事件没被记下来。" % dt["quiet_ratio"],
            {"max_dt": dt.get("max"), "mean_dt": dt.get("mean"),
             "ratio": dt["quiet_ratio"]},
            "对照同期的业务日志判断是「真的闲」还是「没插桩」——"
            "图上的空白不等于没发生"))
    elif not dt:
        na["quiet-window"] = "没有可用时间轴，算不出事件间隔"

    return _diagnose_out(got, st, findings, checked, na, with_stats)


def _diagnose_out(got, st, findings, checked, na, with_stats) -> dict:
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    counts = {"error": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if counts.get("error"):
        verdict = "problems"
    elif counts.get("warn"):
        verdict = "warnings"
    elif findings:
        verdict = "clean"
    else:
        verdict = "clean"
    out = {
        "ok": True,
        "source": got["source"],
        "verdict": verdict,
        "summary": {"findings": len(findings), "by_severity": counts,
                    "events": st.get("events"),
                    "lines": [f["title"] for f in findings]},
        "findings": findings,
        "checked": sorted(set(checked)),
        "not_applicable": na,
        "note": ("checked 是真的评估过的规则，not_applicable 是没法评估的（带原因）："
                 "两者都要读，只读 findings 会把「没查」当成「没问题」"),
    }
    if got.get("buff"):
        out["buff"] = got["buff"]
    if not st.get("events"):
        out["empty"] = True
    if with_stats:
        out["stats"] = st
    return out


# ================================================================ 工具注册

def register(server, js=None) -> int:
    _js = js or (lambda o: json.dumps(o, ensure_ascii=False, default=str))
    n = 0

    @server.tool(
        name="trace_stats",
        title="把已采到的 trace 事件算成结论（CPU 负载/任务执行/ISR/堆/等待）",
        description=(
            "采集类工具给的是**事件列表**，这个工具给**结论**：CPU 负载、各任务执行时间与"
            "占比、中断时长（min/max/mean 与最长的那个）、同步原语等待时长、堆净增与最大"
            "单次分配、事件率。\n"
            "**source 决定从哪儿取数据**（默认 auto）：\n"
            "  · auto / session —— 本进程内**已经采到**的事件（MTF 通路 + SWD 会话），"
            "不碰设备；\n"
            "  · mtf / swd —— 只取其中一条通路；\n"
            "  · buff —— **现场读一次**目标 RAM 里的 buff 环形缓冲（要 link 可用；"
            "auto 不会隐式读设备，要看 buff 必须显式指定）。\n"
            "**哪些指标要目标侧时间基（重要）**：时间占比类（CPU 负载 / 任务执行时间 / "
            "ISR 时长 / 等待时长）只认 buff 的周期数或 swd 的绝对周期。SWO/RTT（MTF）"
            "只有主机到达时刻，混着链路与主机调度抖动——这些指标在那类源上会明确落到 "
            "not_applicable 并说明原因，**不会**用一个错时间基算出一个看着正常的数。\n"
            "**计数类不需要时间基**：事件数、类型分布、同步原语次数、堆净额在任何源上都算。\n"
            "每个指标带 basis（依据）或 not_applicable（为什么不适用）；`checked` 列出真的"
            "评估过的项。cpu_hz= 可在主机不知道主频时手工给（否则绝对时长只给周期数）。\n"
            "找问题用 trace_diagnose（它在本工具的结果上跑规则并给下一步）。"
        ),
    )
    async def trace_stats(source: str = "auto", elf: str = "", addr: str = "",
                          limit: int = 0, names: str = "", link: str = "auto",
                          cpu_hz: int = 0,
                          isr_long_us: float = DEFAULT_ISR_LONG_US) -> str:
        try:
            return _js(stats(source=source, elf=elf, addr=addr,
                             limit=int(limit or 0), names=names, link=link,
                             cpu_hz=int(cpu_hz or 0),
                             isr_long_us=float(isr_long_us or DEFAULT_ISR_LONG_US)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "source": source, "error": str(e)})
    n += 1

    @server.tool(
        name="trace_diagnose",
        title="对 trace 做规则化诊断（可命名的问题 + 证据 + 下一步）",
        description=(
            "把 trace_stats 算出来的事实过一遍规则，产出一组 findings，每条带 "
            "severity（error/warn/info）+ evidence（最小证据）+ hint（下一步怎么做）。\n"
            "**覆盖的规则**：no-data（一条事件都没有）/ no-timeline（没有目标侧时间戳）/ "
            "timebase-missing（有周期无主频）/ dt-frozen（时间轴冻结：粒度比事件间隔粗）/ "
            "dt-zero-heavy / events-lost（时间线不完整）/ segments-restarted（跨了多段录制）/ "
            "kernel-hooks-absent（没有任何内核事件，多半是 MDK_TRACE_SVCRT_HOOKS 没开）/ "
            "no-sched / sched-no-time / isr-unpaired / isr-long / fault-present / "
            "sync-wait-unpaired / sync-pair-ambiguous / quiet-window（长静默）。\n"
            "**checked 与 not_applicable 必须一起读**：checked 是**真的评估过**的规则，"
            "not_applicable 是没法评估的（带原因）——只读 findings 会把「没查」当成"
            "「没问题」。verdict 只有 problems / warnings / clean 三态，不编一个「健康分」。\n"
            "参数与 trace_stats 相同（source / elf / addr / names / link / cpu_hz），"
            "另有 isr_long_us=（中断时长阈值，默认 1000us）、quiet_ratio=（长静默判定倍数，"
            "默认 100）、with_stats=（是否附带完整统计，默认 true）。\n"
            "想直接看事件本身用 trace_events / trace_swd_read / trace_buff_dump；"
            "要画出来用 view_render。"
        ),
    )
    async def trace_diagnose(source: str = "auto", elf: str = "", addr: str = "",
                             limit: int = 0, names: str = "", link: str = "auto",
                             cpu_hz: int = 0,
                             isr_long_us: float = DEFAULT_ISR_LONG_US,
                             quiet_ratio: float = DEFAULT_QUIET_RATIO,
                             with_stats: bool = True) -> str:
        try:
            return _js(diagnose(source=source, elf=elf, addr=addr,
                                limit=int(limit or 0), names=names, link=link,
                                cpu_hz=int(cpu_hz or 0),
                                isr_long_us=float(isr_long_us or DEFAULT_ISR_LONG_US),
                                quiet_ratio=float(quiet_ratio or DEFAULT_QUIET_RATIO),
                                with_stats=bool(with_stats)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "source": source, "error": str(e)})
    n += 1

    return n
