# -*- coding: utf-8 -*-
"""函数运行时线录制引擎（批次49）——裸机也能用的细粒度事件录制。

为什么单独一个模块
------------------
用户要的是「录制函数运行状态等细粒度事件」，MDK 与 OpenOCD 两条链路的抓取机制
并不一样（Keil 走 UVSOCK 断点 + DWT CYCCNT；OpenOCD 走 telnet 的 bp/resume/halt），
**没法合并成同一段 I/O 代码**。所以这里只放「与链路无关」的那一半：

* 事件环形缓冲（长时间录制不涨内存，丢了就如实报 dropped）
* 事件分类（enter / exit / watch / unknown）与 caller 归属
* 栈深估计（命中时的 SP 相对基线）
* 统计与时间线输出

各链路的 I/O 由调用方以回调注入（set_bp / clear_bps / wait_hit / read_regs / read_cyc），
本模块不 import 任何链路。

设计红线（与全项目一致）：拿不准就标注，不猜
------------------------------------------
* ``gap_cyc`` 是「相邻两次命中的 CYCCNT 差」，**不是**函数精确耗时——字段名与 note
  都写明，免得被当作 profile_function 那样的精确测量。
* ``depth_est`` 是估计值（由 SP 推断），字段名带 _est，并在 note 里说明推断依据。
* 命中地址不落在任何已知函数区间时：``func=None`` + ``kind="unknown"``，**不硬塞名字**。
  真机踩过：符号与板上固件不同源时，PC 会被解析成"看着很像"的假符号——那是纯误导。
"""
from __future__ import annotations

import time
from collections import deque


def make_func_index(funcs) -> list:
    """把函数表规整成按起点排序的区间表 [(start, end, name)]。

    funcs 接受多种写法：{name: (start, end)} / [(start, end, name)] / [(start, end)]。
    """
    out = []
    if isinstance(funcs, dict):
        for name, v in funcs.items():
            if isinstance(v, dict):
                s, e = v.get("start"), v.get("end")
            elif isinstance(v, (list, tuple)) and len(v) >= 2:
                s, e = v[0], v[1]
            else:
                continue
            if isinstance(s, int) and isinstance(e, int) and e > s:
                out.append((int(s), int(e), str(name)))
    elif isinstance(funcs, (list, tuple)):
        for item in funcs:
            if isinstance(item, dict):
                s, e, nm = item.get("start"), item.get("end"), item.get("name")
            elif isinstance(item, (list, tuple)) and len(item) >= 3:
                s, e, nm = item[0], item[1], item[2]
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                s, e, nm = item[0], item[1], None
            else:
                continue
            if isinstance(s, int) and isinstance(e, int) and e > s:
                out.append((int(s), int(e), str(nm) if nm else "0x%X" % s))
    out.sort(key=lambda x: (x[0], -x[1]))
    return out


def func_at(index, addr):
    """取 addr 所属的**最内层**函数区间；不在任何区间返回 None。"""
    if not isinstance(addr, int):
        return None
    best = None
    for s, e, nm in index:
        if s <= addr < e:
            if best is None or s >= best[0]:
                best = (s, e, nm)
        elif s > addr and best is not None:
            break
    if best is None:
        return None
    return {"start": best[0], "end": best[1], "name": best[2],
            "offset": addr - best[0]}


class Recorder:
    """函数运行时线录制器（纯逻辑，无 I/O）。

    funcs      : 参与录制的函数区间表（make_func_index 的输入）
    exits      : 可选，出口地址集合（已知返回点时才给；不给就没有 exit 事件）
    max_events : 事件环形缓冲上限（丢弃最旧的，dropped 计数如实上报）
    """

    def __init__(self, funcs=None, exits=None, max_events: int = 2000,
                 max_ms: float = 5000.0, label: str = ""):
        self.index = make_func_index(funcs or [])
        self.exits = set(int(x) for x in (exits or []))
        self.max_events = max(1, int(max_events))
        self.max_ms = float(max_ms)
        self.label = str(label or "")
        self.events = deque(maxlen=self.max_events)
        self.dropped = 0
        self.total = 0
        self.stats = {}          # func -> dict
        self.t0 = None
        self.last = None         # (cyc, t_ms)
        self.sp_base = None
        self.stopped = False
        self.note = ""

    # -- 记录 ---------------------------------------------------------
    def on_hit(self, addr, cyc=None, lr=None, sp=None, ts=None,
               kind_hint: str = "") -> dict:
        """记录一次「目标停下来了」：按地址分类并追加事件。返回该事件。"""
        now = time.time() if ts is None else float(ts)
        if self.t0 is None:
            self.t0 = now
        t_ms = round((now - self.t0) * 1000.0, 2)
        addr = int(addr) if isinstance(addr, int) else None
        hit = func_at(self.index, addr) if addr is not None else None
        name = hit["name"] if hit else None
        if kind_hint:
            kind = kind_hint
        elif addr is not None and addr in self.exits:
            kind = "exit"
        elif name is not None:
            kind = "enter"
        else:
            # 不落在任何已知函数区间：如实标 unknown，不硬塞一个名字
            kind = "unknown"
        caller = None
        if isinstance(lr, int):
            cf = func_at(self.index, lr & ~1)
            caller = cf["name"] if cf else None
        depth = None
        if isinstance(sp, int):
            if self.sp_base is None:
                self.sp_base = sp
            # 栈向低地址生长：SP 比基线大 = 比进入录制时浅 = 已经返回过若干层
            depth = int((sp - self.sp_base) // 8)
        gap = None
        if isinstance(cyc, int) and self.last and isinstance(self.last[0], int):
            gap = cyc - self.last[0]
            if gap < 0:      # 计数器回绕/复位，不猜，如实置 None
                gap = None
        ev = {"i": self.total, "t_ms": t_ms, "pc": None if addr is None else hex(addr),
              "func": name, "kind": kind, "caller": caller,
              "lr": None if not isinstance(lr, int) else hex(lr),
              "sp": None if not isinstance(sp, int) else hex(sp),
              "cyc": cyc, "gap_cyc": gap, "depth_est": depth}
        self.total += 1
        if len(self.events) == self.max_events:
            self.dropped += 1
        self.events.append(ev)
        if isinstance(cyc, int):
            self.last = (cyc, t_ms)
        self._accumulate(ev)
        return ev

    def _accumulate(self, ev):
        """统计是**全量**的（不受环形缓冲丢弃影响）。"""
        if ev["kind"] == "unknown":
            key = "_unknown_"
        else:
            key = ev["func"] or "_unknown_"
        st = self.stats.get(key)
        if st is None:
            st = self.stats[key] = {
                "func": None if key == "_unknown_" else key,
                "count": 0, "enter": 0, "exit": 0, "watch": 0, "unknown": 0,
                "first_t_ms": ev["t_ms"], "last_t_ms": ev["t_ms"],
                "gap_cyc_avg": None, "gap_cyc_max": None, "gap_n": 0,
                "depth_min": None, "depth_max": None, "callers": {}}
        st["count"] += 1
        st[ev["kind"] if ev["kind"] in ("enter", "exit", "watch") else "unknown"] += 1
        st["last_t_ms"] = ev["t_ms"]
        g = ev.get("gap_cyc")
        if isinstance(g, int):
            st["gap_n"] += 1
            st["gap_cyc_avg"] = int(((st["gap_cyc_avg"] or 0) * (st["gap_n"] - 1) + g)
                                    / st["gap_n"])
            st["gap_cyc_max"] = g if st["gap_cyc_max"] is None else max(st["gap_cyc_max"], g)
        d = ev.get("depth_est")
        if isinstance(d, int):
            st["depth_min"] = d if st["depth_min"] is None else min(st["depth_min"], d)
            st["depth_max"] = d if st["depth_max"] is None else max(st["depth_max"], d)
        if ev.get("caller"):
            st["callers"][ev["caller"]] = st["callers"].get(ev["caller"], 0) + 1

    # -- 输出 ---------------------------------------------------------
    def timeline(self, limit: int = 200, kind: str = "", func: str = "") -> list:
        evs = list(self.events)
        if kind:
            evs = [e for e in evs if e["kind"] == kind]
        if func:
            evs = [e for e in evs if e["func"] == func]
        lim = max(1, int(limit or 200))
        if len(evs) > lim:
            evs = evs[-lim:]
        return evs

    def report(self, limit: int = 200, elapsed_ms=None) -> dict:
        by_func = sorted(self.stats.values(),
                         key=lambda s: (-s["count"], str(s["func"])))
        top_calls = [s for s in by_func if s["func"]][:20]
        unknown = self.stats.get("_unknown_")
        out = {
            "events_total": self.total,
            "events_kept": len(self.events),
            "events_dropped": self.dropped,
            "elapsed_ms": None if elapsed_ms is None else round(float(elapsed_ms), 1),
            "funcs_seen": len([s for s in by_func if s["func"]]),
            "by_func": by_func,
            "top_calls": top_calls,
            "timeline": self.timeline(limit=limit),
            "note": ("gap_cyc 是相邻两次命中的 CYCCNT 差值（不是函数精确耗时）；"
                     "depth_est 由命中时 SP 相对录制起点推断，是估计值；"
                     "caller 由命中时的 LR 落在哪个函数推得。"),
        }
        if unknown:
            out["unknown_hits"] = {"count": unknown["count"],
                                   "note": ("有命中不落在任何已知函数区间：可能是符号与板上"
                                            "固件不同源（PC 被解析成假符号），或命中的是"
                                            "数据/异常向量。别把它当成函数名。")}
        return out

    def stop(self, note: str = ""):
        self.stopped = True
        if note:
            self.note = note


# ----------------------------------------------------------------------
# 链路无关的「命中收集」小工具（供 server 侧两条链路共用）
# ----------------------------------------------------------------------
def hit_payload(regs, addr, cyc=None, ts=None) -> dict:
    """把一次「读到寄存器」的结果整成 on_hit 的入参（两条链路都复用）。"""
    regs = regs if isinstance(regs, dict) else {}
    lr = regs.get("lr") if isinstance(regs.get("lr"), int) else None
    sp = regs.get("sp") if isinstance(regs.get("sp"), int) else None
    pc = regs.get("pc") if isinstance(regs.get("pc"), int) else None
    return {"addr": int(addr) if isinstance(addr, int) else pc,
            "cyc": cyc, "lr": lr, "sp": sp, "ts": ts}
