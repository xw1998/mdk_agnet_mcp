# -*- coding: utf-8 -*-
"""调用图与栈深度（批次102）：静态最坏链。

AC5 的 ``armlink --callgraph`` 出的是 HTML 调用图，但它要一份能链接的工程；
这里做的是**只看镜像**的静态分析，剥离符号的 bin 也能算：

  * 每个函数的栈帧 = prologue 的 ``push {}`` 字节 + ``sub sp, #imm``（取峰值，
    中途 add/pop 会退回；出现 ``mov sp, rX`` 判 dynamic，不给数）；
  * 最坏链 = 从根（向量表 / 入口 / 命名根）出发 DFS，累加各层帧；
  * **遇到环就不给上界**：递归/互调的最坏链是无穷，报告里单列 cycle，不硬凑一个数；
  * 间接调用（``blx r3`` 且寄存器值静态未知）→ 边上标 ``unknown``，
    该根的总量降级为下界，并逐条列出未解析点。

口径一句话：这是**上界估算**，不是实测。它假设所有直接调用都走到底、
没有尾调用优化、没有编译器把帧合并。真正上板要用栈水位（paint test）对一遍。
"""
import os

from . import recover as _recover
from . import rtypes as _rtypes

MAX_CHAIN = 64


def _frame(insns: dict, start: int, end: int) -> dict:
    """函数栈帧（字节）。返回峰值、是否动态、依据。"""
    cur, peak, dynamic, basis = 0, 0, False, []
    for a in sorted(k for k in insns if start <= k < end):
        ins = insns[a]
        m = (ins.get("mnemonic") or "").lower()
        op = ins.get("op_str") or ""
        nop = op.replace(" ", "")
        if m in ("push", "push.w"):
            cur += _rtypes._push_bytes(op)
            peak = max(peak, cur)
            basis.append("%s %s (+%d)" % (m, op, _rtypes._push_bytes(op)))
            continue
        if m in ("pop", "pop.w"):
            cur -= _rtypes._push_bytes(op)
            continue
        # capstone 对 `sub sp, #imm` 的 op_str 是 "sp, #0x40"（两操作数），
        # 对 `sub.w sp, sp, #imm` 才是 "sp, sp, #imm"：两种都要认
        if m in ("sub", "subs", "sub.w") and (nop.startswith("sp,")
                                              or nop.startswith("sp,sp,")):
            v = _rtypes._imm(op.split(",")[-1].strip())
            if v:
                cur += v
                peak = max(peak, cur)
                basis.append("%s %s (+%d)" % (m, op, v))
            else:
                dynamic = True
            continue
        if m in ("add", "adds", "add.w") and (nop.startswith("sp,")
                                              or nop.startswith("sp,sp,")):
            v = _rtypes._imm(op.split(",")[-1].strip())
            if v:
                cur -= v
            else:
                dynamic = True
            continue
        # 只有「写 sp」才算动态：`mov r0, sp` 是读 sp，不改帧
        if m in ("mov", "mov.w") and (nop.startswith("sp,")
                                      or nop.startswith("sp,sp")):
            dynamic = True
    return {"frame": peak, "aligned": (peak + 7) // 8 * 8,
            "dynamic": dynamic, "basis": basis[:6]}


def _root_list(unit, funcs, want) -> list:
    roots, why = [], {}
    # skip_empty=True：Cortex-M 的保留槽位（7..10）常为 0，一旦当终止就会把
    # SysTick/外设中断入口整片丢掉，那些根的最坏链就永远不进报告
    vt = _recover.vector_table(unit, max_entries=256, skip_empty=True)
    for e in vt.get("entries") or []:
        if e.get("in_code"):
            a = int(e["handler_hex"], 16) & ~1
            roots.append(a)
            why.setdefault(a, "vector_table:%s" % (e.get("name") or e["index"]))
    hint = int(getattr(unit, "entry_hint", 0) or 0)
    if hint:
        a = hint & ~1 if unit.arch.get("family") == "arm" else hint
        roots.append(a)
        why.setdefault(a, "entry_hint")
    for f in funcs:
        if (f.get("name") or "") in want:
            roots.append(f["addr"])
            why.setdefault(f["addr"], "named_root:%s" % f.get("name"))
    return [a for a in dict.fromkeys(roots)], why


def analyze_stack(path: str, *, base: int = 0, stack_size: int = 0,
                  roots: str = "", max_insns: int = 600000,
                  max_roots: int = 200) -> dict:
    """调用图 + 每个根的最坏调用链与累计栈帧。"""
    an = _recover.analyze(path, base=base, deep=True, max_insns=max_insns)
    if not an.get("ok"):
        return an
    unit = an.pop("_unit")
    rec = an.pop("_recover")
    insns = rec.get("_insns") or {}
    funcs = rec.get("functions") or []
    rel = rec.get("_relations") or {}
    graph = rel.get("call_graph") or {}
    xr = rel.get("xrefs") or {}
    gaps = list(an.get("gaps") or [])

    by_addr = {f["addr"]: f for f in funcs}
    frames = {}
    for f in funcs:
        fr = _frame(insns, f["addr"], int(f.get("end_addr") or f["addr"]))
        frames[f["addr"]] = fr

    callees, indirect = {}, {}
    for e in graph.get("edges") or []:
        callees.setdefault(e["caller"], []).append(
            {"to": e["callee"], "callsite_hex": e["callsite_hex"],
             "confidence": e.get("confidence")})
    for u in xr.get("unresolved") or []:
        if u.get("kind") == "call_indirect":
            indirect.setdefault(u.get("func"), []).append(
                {"callsite_hex": u.get("from_hex"), "reg": u.get("reg"),
                 "insn": u.get("insn")})

    # 尾调用（b/b.w 到另一个函数入口）：被调函数的帧会被算漏（调用者的帧已经弹掉），
    # 所以链上出现它时给的数量偏小——计数出来，不静默
    tail = 0
    for x in (xr.get("xrefs") or []):
        if x.get("kind") != "branch":
            continue
        a, b = int(x.get("func") or 0), int(x.get("to") or 0)
        if a and b and a != b and a in by_addr and b in by_addr:
            tail += 1

    want = {s.strip() for s in (roots or "").split(",") if s.strip()}
    want |= {"main", "Reset_Handler", "reset_handler"}
    root_addrs, root_why = _root_list(unit, funcs, want)
    root_addrs = [a for a in root_addrs if a in by_addr]

    cycles = [(c["addrs_hex"], c["size"]) for c in graph.get("cycles") or []]
    on_cycle = set()
    for addrs, _n in cycles:
        for h in addrs:
            on_cycle.add(int(h, 16))

    memo, visiting = {}, set()

    def depth(a: int):
        """返回 ``(总字节, 链, 是否有环, 是否含未知)``；环上返回常量 0 并标 has_cycle。"""
        if a in memo:
            return memo[a]
        if a in visiting:
            return 0, [], True, False
        visiting.add(a)
        fr = frames.get(a) or {"frame": 0, "aligned": 0, "dynamic": False}
        best = (0, [], False, False)
        for c in callees.get(a, []):
            sub, chain, cyc, unk = depth(c["to"])
            if sub > best[0]:
                best = (sub, chain, cyc, unk)
        visiting.discard(a)
        unk = bool(indirect.get(a))
        total = fr["frame"] + best[0]
        chain = [{"addr_hex": "0x%08X" % a, "name": (by_addr.get(a) or {}).get("name")
                  or "sub_%08X" % a, "frame": fr["frame"],
                  "dynamic_frame": fr["dynamic"]}] + best[1]
        out = (total, chain, best[2] or (a in on_cycle), best[3] or unk)
        memo[a] = out
        return out

    out_roots = []
    for a in root_addrs[:max_roots]:
        total, chain, cyc, unk = depth(a)
        fr = frames.get(a) or {}
        rec_root = {
            "root_hex": "0x%08X" % a,
            "name": (by_addr.get(a) or {}).get("name") or "sub_%08X" % a,
            "why": root_why.get(a, ""),
            "worst_depth_bytes": total,
            "worst_depth_bytes_aligned": (total + 7) // 8 * 8,
            "chain": chain[:MAX_CHAIN],
            "has_cycle": cyc,
            "has_indirect": unk,
            "indirect_sites": indirect.get(a, [])[:8],
            "basis": "各层 prologue push/sub sp 的峰值相加；未计异常入栈的硬件 8 字",
        }
        if cyc:
            rec_root["verdict"] = "unbounded"
            rec_root["why_unbounded"] = ("调用链上有环（递归/互调）：最坏深度没有静态上界，"
                                         "不给数字")
        elif unk:
            rec_root["verdict"] = "lower_bound"
            rec_root["why_lower_bound"] = ("这条链上有 %d 处间接调用解析不了：算出来的"
                                           "值是**下界**" % len(indirect.get(a, [])))
        else:
            rec_root["verdict"] = "static_bound"
        if stack_size:
            if rec_root["verdict"] == "static_bound":
                rec_root["fits"] = total <= int(stack_size) - 32
                rec_root["stack_size"] = int(stack_size)
                rec_root["margin_bytes"] = int(stack_size) - 32 - total
        out_roots.append(rec_root)
    out_roots.sort(key=lambda r: -int(r["worst_depth_bytes"] or 0))

    n_dyn = sum(1 for f in frames.values() if f["dynamic"])
    deep_level = graph.get("max_depth") or 0
    return {
        "ok": True,
        "image": {"name": os.path.basename(path), "container": unit.container,
                  "base_hex": "0x%08X" % unit.base_used,
                  "functions": len(funcs)},
        "call_graph": {
            "n_nodes": graph.get("n_nodes"), "n_edges": graph.get("n_edges"),
            "max_depth_levels": deep_level,
            "n_leaves": graph.get("n_leaves"),
            "cycles": [{"size": n, "addrs_hex": a[:8]} for a, n in cycles][:20],
            "n_cycles": len(cycles),
        },
        "frames": {"counted": len(frames), "dynamic": n_dyn,
                   "largest": sorted(
                       [{"addr_hex": "0x%08X" % a,
                         "name": (by_addr.get(a) or {}).get("name") or "",
                         "frame": fr["frame"], "basis": fr["basis"]}
                        for a, fr in frames.items()],
                       key=lambda r: -r["frame"])[:20]},
        "roots": out_roots,
        "worst": ({"root_hex": out_roots[0]["root_hex"],
                   "worst_depth_bytes": out_roots[0]["worst_depth_bytes"],
                   "verdict": out_roots[0]["verdict"]} if out_roots else None),
        "tail_calls": {"total": tail,
                       "note": "b/b.w 到函数入口的尾调用：这类跳转会释放调用者的帧，"
                               "本模型不累加被调函数帧，所以含尾调用的链偏小"},
        "indirect_calls": {"total": sum(len(v) for v in indirect.values()),
                           "functions": len(indirect),
                           "note": "间接调用的目标静态未知：这些位置让「最坏链」只能算下界"},
        "stack_size": int(stack_size or 0),
        "rule": [
            "帧 = prologue 里 push {} 的寄存器数×4 与 sub sp,#imm 的**峰值**（中途 pop/add 会退回）",
            "最坏链 = 从每个根出发 DFS，累加各层帧，取最大的那条；同一函数在链上出现两次即判环",
            "环（递归/互调）不给数字：判 unbounded——静态上界是无穷",
            "间接调用未知 → 该根的数是下界（verdict=lower_bound），逐条列出未解析点",
            "Cortex-M 异常入栈的硬件 8 个字（32 字节）不在函数帧里：给 stack_size 时"
            "已按 32 字节预留后再比",
        ],
        "limitations": [
            "**静态上界 ≠ 实测**：尾调用优化、编译器合并帧、内联都会让实际更小；"
            "要上板用栈水位（paint test）或调试器读 MSP/PSP 极值对一遍",
            "函数清单完整度未知：间接调用的目标可能整个函数都不在清单里（那就更算不到）",
            "只覆盖主栈（MSP）：RTOS 任务栈（PSP）每条任务的深度要用各自的根单独算",
            "浮点上下文（FPU lazy stacking）与异常嵌套的额外占用不在这个模型里",
            "尾调用（b 到函数入口）不累加被调函数的帧：链上有尾调用时数字偏小，"
            "不要拿它当上界用",
        ],
        "gaps": gaps,
    }
