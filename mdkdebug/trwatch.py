# -*- coding: utf-8 -*-
"""软插桩的**条件触发层**（watch）：让「等一件事发生」变成一次调用，而不是
肉眼看几千条事件。

为什么需要它
------------
采集/分析层（trace_swd_read / trace_stats / trace_diagnose）给的是**一段流**与
**一份统计**。真正常见的调试动作却是「等某个东西出现」：等某个同步对象被等待、
等某个 ISR 进来、等某条插桩 id 被走到、等 fault。没有触发层时，唯一办法是反复
搬一小段、人来扫——既费上下文，又容易看漏（尤其事件率上万时）。

本模块把「条件」做成**主机侧**的一等对象：在已经搬回来的事件流上求值，命中就
给出**命中事件 + 前后上下文 + 一份诊断结论**，AI 不必自己翻。三条设计口径：

1. **只在主机侧判**。目标侧的 SWD 控制块只有 80 字节、没有 mask/filter/trigger
   字段（实测），固件也不做条件判定。主机侧的办法是：无缝流本来就是**无损累积**
   的（未读区不被覆盖），所以「你在两次调用之间错过的那段」照样能判——覆盖范围
   等于整个会话已录部分，而不是「我调用那一刻」。
2. **插桩事件与自动钩子事件同一条流、同一套条件**。手动 `MDK_TRACE_*` 插桩事件
   带的是你自己指定的 id，内核自动钩子给的是 sched / sync / heap / isr / fault
   这类语义事件——条件语言同时认 id 与这些语义字段，不需要两套。
3. **算不出来就说算不出来**。命不中时**不能**等于「没发生」：目标因宿主跟不上
   丢过事件（lost_events）时，覆盖是**不完整**的，本模块一律在结论里写明
   `coverage=incomplete` 并说明丢了多少——宁可说「没测到」，也不给「没发生」。

条件语法（`spec`，一行写完）
---------------------------
    spec := clause ("|" clause)*           # | 是「或」
    clause := pred ("," pred)*             # , 是「且」
    pred := field [op] value               # op ∈ = != > >= < <=（缺省 =）

字段（`mdkdebug/trwatch.py:FIELDS` 是权威列表，工具描述里同步）：

| 字段 | 取值 | 说明 |
|---|---|---|
| `type` | `fault` `sched` `sync` `heap` `isr` `event` `text` `counter` `mark` `ts` `kv` `reset` `raw` `segment` `gap` | 事件类型 |
| `kind` | `enter` `exit` `point` `abort` | |
| `id` | 数字 | **原始事件 id**。手插桩就是你插桩时用的那个 id；自动钩子的 id 是内核事件号 |
| `arg` | 数字 | 事件数值负载（fault 事件里 arg = CFSR） |
| `obj` | `sem` `mutex` `queue` `event` `fs` `dev` `cond` 或数字 | sync 事件的对象类别（`6=cond`） |
| `op` | `wait` `signal` `acquire` `release` `timeout` `create` `delete`（sync）／`alloc` `free`（heap） | 语义操作 |
| `from` `to` `task` | 0..15 或数字 | 调度事件的任务号；`task` = from 或 to |
| `from_name` `to_name` `task_name` | 字符串 | 任务名（会话里解析出名字时才有；解析不出就在 `unmatched_names` 里说明） |
| `class` | `hardfault` `memmanage` `busfault` `usagefault` | 异常类别 |
| `reg` | `pc` `lr` `sp` `hfsr` `mmfar` `bfar` `xpsr` `cfsr` | 故障寄存器帧字段 |
| `dt_cycles` `cycles` `t_us` | 数字 | 时间（只在目标侧有时间基时存在） |

例：`sync,obj=cond,op=wait`（有人等条件变量）、`fault`（任何异常）、
`isr,id=10`（10 号中断进来）、`id=42`（你插桩 id=42 的点被走到）、
`t_us>=1500`（距流起点超过 1.5 ms 的事件）、`sched,to=3|sched,from=3`。

**写错一个字段名或枚举值一律报错**（SpecError），绝不静默当成「永不命中」——
那会把「条件写错了」伪装成「事情没发生」，属本项目的「看似权威的错答案」红线。
"""

from __future__ import annotations

# ----------------------------------------------------------------- 字段表
# obj 类别的名字与 components/trace/mdk_trace_svcrt.h 的 CLS 一一对应
OBJ_CLASSES = {0: "sem", 1: "mutex", 2: "queue", 3: "event", 4: "fs",
               5: "dev", 6: "cond"}
FAULT_CLASSES = ("hardfault", "memmanage", "busfault", "usagefault")
REG_NAMES = ("pc", "lr", "sp", "hfsr", "mmfar", "bfar", "xpsr", "cfsr")
SYNC_OPS = {0: "wait", 1: "signal", 2: "acquire", 3: "release",
            4: "timeout", 5: "create", 6: "delete"}
HEAP_OPS = {0: "alloc", 1: "free"}
EVENT_TYPES = ("fault", "sched", "sync", "heap", "isr", "event", "text",
               "counter", "mark", "ts", "kv", "reset", "raw", "segment", "gap")
KINDS = ("enter", "exit", "point", "abort")

NUMERIC_FIELDS = ("id", "arg", "from", "to", "task", "obj", "size",
                  "dt_cycles", "cycles", "t_us", "events_dropped")
ENUM_FIELDS = {"type": EVENT_TYPES, "kind": KINDS,
               "class": FAULT_CLASSES, "reg": REG_NAMES}
STR_FIELDS = ("from_name", "to_name", "task_name", "id_name")
FIELDS = tuple(NUMERIC_FIELDS) + tuple(ENUM_FIELDS) + STR_FIELDS + ("op",)

_OPS = ("!=", ">=", "<=", "=", ">", "<")


class SpecError(ValueError):
    """条件写错了。**必须抛**：写成「永不命中」会把错误伪装成「没发生」。"""


# ----------------------------------------------------------------- 解析
class Spec:
    __slots__ = ("raw", "clauses")

    def __init__(self, raw: str, clauses: list):
        self.raw = raw
        self.clauses = clauses          # [[(field, op, value), ...], ...]

    def __repr__(self):
        return "Spec(%r)" % self.raw

    def describe(self):
        """人话描述，回显给调用方（让 AI/人确认「我判的到底是什么」）。"""
        out = []
        for cl in self.clauses:
            out.append(" 且 ".join(
                "%s%s%s" % (f, "" if op == "=" else op, _fmt(v))
                for f, op, v in cl))
        return " 或 ".join("（%s）" % c for c in out)


def _fmt(v):
    return v if isinstance(v, str) else str(v)


def _parse_value(field, op, val):
    if field == "obj":
        # obj 允许类名（sem/mutex/.../cond）或数字；统一成数字比，比较才不会是
        # 「名字 vs 数字」的静默不命中。
        if isinstance(val, str) and val in OBJ_CLASSES.values():
            return list(OBJ_CLASSES.values()).index(val)
        if isinstance(val, str) and val.lstrip("-").isdigit():
            return int(val)
        raise SpecError("obj 只能是 %s（或对应数字 0..%d），收到 %r"
                        % (" / ".join(OBJ_CLASSES.values()),
                           max(OBJ_CLASSES), val))
    if field in NUMERIC_FIELDS:
        try:
            return int(val, 0) if isinstance(val, str) else int(val)
        except (TypeError, ValueError):
            raise SpecError("%s 需要数字，收到 %r" % (field, val))
    if field in ENUM_FIELDS:
        allowed = ENUM_FIELDS[field]
        if isinstance(val, str) and val in allowed:
            return val
        raise SpecError("%s 只能是 %s，收到 %r"
                        % (field, " / ".join(allowed), val))
    if field == "op":
        names = tuple(SYNC_OPS.values()) + tuple(HEAP_OPS.values())
        if isinstance(val, str) and val in names:
            return val
        raise SpecError("op 只能是 %s，收到 %r" % (" / ".join(sorted(set(names))), val))
    if field == "obj":
        if isinstance(val, str) and val in OBJ_CLASSES.values():
            return val
        raise SpecError("obj 只能是 %s，收到 %r"
                        % (" / ".join(OBJ_CLASSES.values()), val))
    return val


def parse(spec) -> Spec:
    """字符串 → Spec。写错就抛 SpecError（附可用字段/取值）。"""
    if isinstance(spec, Spec):
        return spec
    if not isinstance(spec, str) or not spec.strip():
        raise SpecError("条件为空。写法见 trace_watch 的工具描述"
                        "（例：sync,obj=cond,op=wait / fault / id=42）")
    clauses = []
    for raw_clause in spec.split("|"):
        cl = []
        for raw_pred in raw_clause.split(","):
            p = raw_pred.strip()
            if not p:
                continue
            field, op, val = _split_pred(p)
            if field not in FIELDS:
                raise SpecError(
                    "认不出字段 %r（可用：%s）" % (field, " / ".join(FIELDS)))
            cl.append((field, op, _parse_value(field, op, val)))
        if not cl:
            raise SpecError("条件里有一个空子句：%r" % spec)
        clauses.append(cl)
    return Spec(spec, clauses)


def _split_pred(p):
    """把 `field op value` 拆开。裸词（无比较符）当 type= 的简写。"""
    for op in _OPS:
        i = p.find(op)
        if i > 0:
            field = p[:i].strip()
            val = p[i + len(op):].strip()
            if not val:
                raise SpecError("比较符 %s 后面没有值：%r" % (op, p))
            return field, ("=" if op == "=" else op), val
    # 裸词：type 简写（fault / sched / sync / heap / isr …）
    if p in EVENT_TYPES:
        return "type", "=", p
    if p in FIELDS:
        raise SpecError("%r 后面缺比较符与值（例：%s=1）" % (p, p))
    raise SpecError("认不出条件 %r：要么写成 field=value，要么是事件类型之一（%s）"
                    % (p, " / ".join(EVENT_TYPES)))


# ----------------------------------------------------------------- 求值
def _ev_field(ev: dict, field: str):
    """按字段取事件里的值。取不到返回 None（**不是** 0/""）。"""
    if field == "task":
        f, t = ev.get("from"), ev.get("to")
        if f is None and t is None:
            return None
        return [f, t]                    # 任一匹配即可
    if field == "obj":
        return ev.get("obj")
    if field == "size":
        return ev.get("size", ev.get("arg") if ev.get("type") == "heap" else None)
    if field == "class":
        return ev.get("fault_class")
    if field in ("from", "to", "id", "arg", "dt_cycles", "cycles", "t_us",
                 "events_dropped"):
        return ev.get(field)
    if field == "op":
        if ev.get("op_name"):
            return ev["op_name"]
        op = ev.get("op")
        if isinstance(op, int):
            # 事件里只有数字 op（老的记录形态）：按同一张表翻成名字再比，
            # 否则 op=wait 会静默不命中——那是「看似权威」的错误。
            tbl = SYNC_OPS if ev.get("type") == "sync" else HEAP_OPS
            return tbl.get(op, "op%d" % op)
        return None
    return ev.get(field)


def _cmp(got, op, want):
    if got is None:
        return False                       # 字段不存在 → 不算命中（但不报错）
    if isinstance(got, list):
        return any(_cmp(g, op, want) for g in got)
    if op == "=":
        return got == want
    if op == "!=":
        return got != want
    try:
        if op == ">":
            return got > want
        if op == ">=":
            return got >= want
        if op == "<":
            return got < want
        if op == "<=":
            return got <= want
    except TypeError:
        return False
    return False


def clause_match(clause, ev) -> bool:
    for field, op, want in clause:
        if not _cmp(_ev_field(ev, field), op, want):
            return False
    return True


def match(spec, ev):
    """(是否命中, 命中的子句序号)。"""
    sp = parse(spec)
    for i, cl in enumerate(sp.clauses):
        if clause_match(cl, ev):
            return True, i
    return False, -1


def evaluate(events, spec, start: int = 0, min_count: int = 1,
             max_hits: int = 20, before: int = 3, after: int = 3,
             names: dict = None) -> dict:
    """在 events[start:] 上求值。返回命中清单 + 每条命中的上下文窗口。

    min_count=N 表示「第 N 次命中才算触发」（默认 1）。max_hits 只限**返回**多少条，
    不影响 matches 计数（计数始终是全量）。
    """
    sp = parse(spec)
    n = len(events)
    start = max(0, int(start))
    hits = []
    matches = 0
    for i in range(start, n):
        ev = events[i]
        for ci, cl in enumerate(sp.clauses):
            if clause_match(cl, ev):
                matches += 1
                if len(hits) < max(0, int(max_hits)):
                    hits.append(_hit(events, i, cl, ci, before, after))
                break
    return {
        "spec": sp.raw,
        "spec_desc": sp.describe(),
        "scanned": {"from": start, "to": n, "count": max(0, n - start)},
        "matches": matches,
        "triggered": matches >= max(1, int(min_count)),
        "min_count": max(1, int(min_count)),
        "hits": hits,
        "hits_truncated": matches > len(hits),
        "unmatched_names": _name_hints(sp, events, names),
    }


def _hit(events, idx, clause, ci, before, after):
    lo = max(0, idx - max(0, int(before)))
    hi = min(len(events), idx + 1 + max(0, int(after)))
    ev = events[idx]
    return {
        "index": idx,
        "clause": " 且 ".join("%s%s%s" % (f, "" if op == "=" else op, _fmt(v))
                              for f, op, v in clause),
        "clause_index": ci,
        "event": ev,
        "before": events[lo:idx],
        "after": events[idx + 1:hi],
    }


def _name_hints(sp, events, names):
    """条件里用了 *_name 但流里没有名字时**如实说明**，别让人以为「没发生」。"""
    want_name = [f for cl in sp.clauses for f, _op, _v in cl
                 if f in ("from_name", "to_name", "task_name")]
    if not want_name:
        return []
    have = any((e.get("from_name") or e.get("to_name") or e.get("task_name"))
               for e in events)
    if have:
        return []
    return ["条件里用到了 %s，但这段流里没有任何任务名（会话没解析出 "
            "svcrt_task_table，或事件不是调度事件）——按名字判会永远不命中，"
            "请改用任务号（from= / to= / task=）或先 trace_swd_read(tasks=refresh)"
            % " / ".join(sorted(set(want_name)))]


def coverage(lost_events: int = 0, gaps: int = 0, dropped: int = 0,
             note: str = "") -> dict:
    """覆盖度如实上报。**没触发 ≠ 没发生**，这条是硬规矩。"""
    lost = int(lost_events or 0) + int(gaps or 0) + int(dropped or 0)
    out = {"complete": lost == 0,
           "lost_events": int(lost_events or 0),
           "gap_events": int(gaps or 0),
           "dropped": int(dropped or 0)}
    if lost:
        out["warning"] = ("这段录制**不完整**：目标因宿主跟不上丢了 %d 个事件。"
                          "「没命中」只能说明「已录下的部分里没有」，不能说"
                          "「没发生过」——要下「没发生」的结论请先 trace_swd_reset "
                          "重开一段（或调大环 / 调粗粒度 / 少插桩）再判。" % lost)
    if note:
        out["note"] = note
    return out
