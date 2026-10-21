"""reveng —— 从指令流里恢复「关系」，零新增依赖（capstone + 自己的操作数解析）。

批次82 吸收 Ghidra 的三块**静态分析产物**（思路，不是代码）：

1. **交叉引用库**：code→code（调用/跳转）、code→data（读/写/取址）、data→code（字面量池里的函数指针）、
   code→string。Ghidra 的 xref 之所以有用，是因为它能回答「谁碰过这个地址」；这里把同一条关系
   存成可反查的表，并保留「从哪条指令、怎么算出来的」。
2. **调用图**：入度/出度、根、叶、强连通分量（环）、可达深度。Ghidra 的 function call graph 做的
   就是这件事；区别是这里直接给 CSV/JSON，方便脚本查。
3. **跳转表 / switch 恢复**：Thumb-2 的 `tbb/tbh [pc, rN]`、ARM 的 `ldr pc, [pc, rN, lsl #2]`、
   `add pc, pc, rN, lsl #2`，以及「cmp + bhi 比较链」。这是「反汇编少了 case 分支」的根因——
   跳转表里的目标不经过 bl，不恢复就永远看不到。

三条铁律（与批次81 一致）：
- 只报证据：每条 xref 带 ``how``（哪条指令、怎么算的），不猜；
- 置信度分级：``observed``（符号/数据直接给出）/ ``inferred``（控制流推出）/ ``weak``（单条间接证据）；
- 不改既有字段语义：全部并列新增，老的 ``size_basis`` / ``size`` 一个不动。
"""

import bisect
import re

# ---- 指令族 ---------------------------------------------------------------
_CALL_MN = ("bl", "blx", "call", "jal", "jalr", "bl.w")
_BRANCH_MN = ("b", "b.w", "j", "bal", "beq", "bne", "bcs", "bhs", "bcc", "blo",
              "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt",
              "ble", "cbz", "cbnz", "jal")
_LOAD_MN = ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "lw", "lb", "lh",
            "lbu", "lhu", "ldr.w", "ldrb.w", "ldrh.w")
_STORE_MN = ("str", "strb", "strh", "strd", "sw", "sb", "sh", "str.w",
             "strb.w", "strh.w")
_UNCOND_MN = ("b", "b.w", "j", "bal")

_WIDTH_OF = {"ldrb": 1, "strb": 1, "ldrsb": 1, "ldrh": 2, "strh": 2, "ldrsh": 2,
             "ldrd": 8, "strd": 8, "ldr": 4, "str": 4}

_MEM_RE = re.compile(r"^\s*([^,\[]+?)\s*,\s*(?:\[([^\]]*)\]|\[([^\]]*)\]!)")
_IMM_RE = re.compile(r"^#?(-?0x[0-9a-fA-F]+|-?\d+)$")


def _imm(tok: str):
    """``#0x10`` / ``10`` / ``#-4`` → int；不是立即数返回 None。"""
    tok = (tok or "").strip()
    if not tok:
        return None
    m = _IMM_RE.match(tok)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def _norm_reg(name: str) -> str:
    """统一寄存器写法：``R0``→``r0``，``w3``→``r3``（AArch64 的 32 位视图），``x3``→``r3``。"""
    n = (name or "").strip().lower()
    if not n:
        return ""
    if n in ("x29", "x30"):
        return {"x29": "fp", "x30": "lr"}[n]
    if n.startswith("w") and n[1:].isdigit():
        return "r" + n[1:]
    if n.startswith("x") and n[1:].isdigit():
        return "r" + n[1:]
    return n


def parse_mem(op_str: str):
    """解析 load/store 的「目的寄存器 + 内存操作数」。

    返回 ``{"dest", "base", "offset", "index", "shift", "writeback"}`` 或 None。
    只认 ``ldr/str`` 这一族最常见的形态：
        ``r3, [r0, #0x10]`` / ``r3, [r0, r1, lsl #2]`` / ``r3, [r0]`` /
        ``r3, [pc, #0x40]`` / ``r3, [sp, #4]!``
    """
    m = _MEM_RE.match(op_str or "")
    if not m:
        return None
    dest = _norm_reg(m.group(1))
    body = m.group(2) if m.group(2) is not None else m.group(3)
    tail = (op_str or "")[m.end():]
    writeback = tail.lstrip().startswith("!")
    parts = [p.strip() for p in body.split(",") if p.strip()]
    if not parts:
        return None
    base = _norm_reg(parts[0])
    out = {"dest": dest, "base": base, "offset": 0, "index": None,
           "shift": 0, "writeback": writeback}
    rest = parts[1:]
    if rest:
        imm = _imm(rest[0])
        if imm is not None:
            out["offset"] = imm
        else:
            out["index"] = _norm_reg(rest[0])
            if len(rest) > 1:
                for tok in rest[1:]:
                    t = tok.strip().lower()
                    if t.startswith("lsl"):
                        sh = _imm(t.replace("lsl", "").strip())
                        if sh is None and len(rest) > 2:
                            sh = _imm(t)
                        out["shift"] = sh or 0
                    elif t.startswith("uxt"):
                        out["shift"] = 0
    return out


def read_u32(unit, addr: int):
    b = unit.read(addr, 4)
    if len(b) < 4:
        return None
    return int.from_bytes(b, unit.arch.get("endian", "little"))


def _pc_value(unit, ins: dict) -> int:
    """PC 相对寻址的基准：Thumb 是 ``addr+4`` 再按 4 对齐，ARM 是 ``addr+8``。"""
    if unit.arch.get("thumb"):
        return (ins["addr"] + 4) & ~3
    return ins["addr"] + 8


class FuncSpan:
    """按地址查「这条指令属于哪个函数」。"""

    def __init__(self, funcs):
        self.items = sorted((f["addr"], f.get("end_addr") or f["addr"], f)
                            for f in funcs)

    def at(self, addr: int):
        lo, hi = 0, len(self.items) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, f = self.items[mid]
            if addr < start:
                hi = mid - 1
            elif addr >= end:
                lo = mid + 1
            else:
                return f
        return None


def _clobber_written(env: dict, movt_lo: dict, ins: dict, keep: str = ""):
    """把这条指令**写到的**寄存器从常量表里删掉（``keep`` 除外）。

    只删被写的：删多了会把同块里前面算出来的常量白白丢掉，删少了会拿过期
    常量算出一个看着像真的错地址——后者更坏，所以宁可这里保守。
    """
    for r in (_norm_reg(x) for x in (ins.get("writes") or [])):
        if r and r != keep:
            env.pop(r, None)
            movt_lo.pop(r, None)


def _const_env_step(unit, env: dict, movt_lo: dict, ins: dict):
    """基本块内最小的常量传播：只为回答「这条访问落在哪个地址」。

    认得五条就够嵌入式固件用：``mov/movw/movt`` 立即数、``add/sub rd, rN, #imm``、
    ``adr``、``ldr rd, [pc, #imm]`` 字面量。写别的寄存器就把它从表里删掉
    （宁可说「不知道」，也不拿过期常量算地址）。
    """
    m = (ins.get("mnemonic") or "").lower()
    op = ins.get("op_str") or ""
    regs = [x.strip() for x in op.split(",")]
    dest = _norm_reg(regs[0]) if regs else ""
    handled = False

    if m in ("mov", "movs", "mov.w") and len(regs) >= 2:
        v = _imm(regs[1])
        if v is not None:
            env[dest] = v & 0xFFFFFFFF
            handled = True
        elif _norm_reg(regs[1]) in env:
            env[dest] = env[_norm_reg(regs[1])]
            handled = True
    elif m == "movw" and len(regs) >= 2:
        v = _imm(regs[1])
        if v is not None:
            movt_lo[dest] = v & 0xFFFF
            env[dest] = v & 0xFFFF
            handled = True
    elif m == "movt" and len(regs) >= 2:
        v = _imm(regs[1])
        if v is not None:
            lo = movt_lo.get(dest, env.get(dest, 0) & 0xFFFF)
            env[dest] = ((v & 0xFFFF) << 16) | lo
            handled = True
    elif m in ("add", "adds", "add.w", "sub", "subs", "sub.w") and len(regs) >= 3:
        src = _norm_reg(regs[1])
        v = _imm(regs[2])
        if v is not None:
            if src == "pc":
                base = _pc_value(unit, ins)
            else:
                base = env.get(src)
            if base is not None:
                env[dest] = (base + (v if m.startswith("add") else -v)) & 0xFFFFFFFF
                handled = True
    elif m in ("adr", "adr.w", "adrl") and len(regs) >= 2:
        v = _imm(regs[1])
        if v is not None:
            env[dest] = (_pc_value(unit, ins) + v) & 0xFFFFFFFF
            handled = True
    elif m in _LOAD_MN:
        mem = parse_mem(op)
        if mem and mem["base"] == "pc":
            lit = _pc_value(unit, ins) + mem["offset"]
            val = read_u32(unit, lit)
            if val is not None:
                env[mem["dest"]] = val
                handled = True
    _clobber_written(env, movt_lo, ins, keep=dest if handled else "")


def build_xrefs(unit, insns: dict, funcs: list, *, max_xrefs: int = 60000) -> dict:
    """扫一遍指令流，产出交叉引用表与「可疑但未解析」的清单。

    ``insns`` 是 ``{addr: 反汇编记录}``（``_sweep`` 的产物，需带 ``reads``/``writes``）。
    """
    xrefs = []
    unresolved = []
    truncated = False
    all_addrs = sorted(insns)
    # 按函数切块：常量传播不能跨函数（跨过去就会把上一个函数的常量当成本函数的）
    for f in funcs:
        start, end = f["addr"], f.get("end_addr") or f["addr"]
        lo = bisect.bisect_left(all_addrs, start)
        hi = bisect.bisect_left(all_addrs, end)
        addrs = all_addrs[lo:hi]
        if not addrs:
            continue
        env, movt_lo = {}, {}
        for a in addrs:
            if len(xrefs) >= max_xrefs:
                truncated = True
                break
            ins = insns[a]
            m = (ins.get("mnemonic") or "").lower()
            op = ins.get("op_str") or ""
            base = {"from": a, "from_hex": "0x%08X" % a,
                    "func": f["addr"], "func_name": f.get("name") or "",
                    "insn": ("%s %s" % (ins.get("mnemonic"), op)).strip()}
            tgt = ins.get("target")
            if m in _CALL_MN:
                if tgt is not None:
                    xrefs.append(dict(base, kind="call", to=tgt & ~1,
                                      to_hex="0x%08X" % (tgt & ~1),
                                      how="direct", confidence="observed"))
                else:
                    # blx r3：靠常量传播解析目标
                    reg = _norm_reg(op.split(",")[-1].strip()) if op else ""
                    if reg in env and unit.is_exec_address(env[reg]):
                        xrefs.append(dict(base, kind="call", to=env[reg] & ~1,
                                          to_hex="0x%08X" % (env[reg] & ~1),
                                          how="indirect_const:%s" % reg,
                                          confidence="inferred"))
                    else:
                        unresolved.append(dict(base, kind="call_indirect",
                                               reg=reg, why="寄存器值未知"))
                env.clear()
                movt_lo.clear()
                continue
            if m in _BRANCH_MN and tgt is not None:
                xrefs.append(dict(base, kind="branch", to=tgt & ~1,
                                  to_hex="0x%08X" % (tgt & ~1),
                                  how="direct", confidence="observed"))
            mem = parse_mem(op) if (m in _LOAD_MN or m in _STORE_MN) else None
            if mem:
                addr = None
                how = ""
                if mem["base"] == "pc":
                    addr = _pc_value(unit, ins) + mem["offset"]
                    how = "pc_relative"
                    # 字面量池里的代码指针：data→code 的证据
                    if m in _LOAD_MN and addr is not None:
                        val = read_u32(unit, addr)
                        if val is not None and unit.is_exec_address(val):
                            xrefs.append(dict(base, kind="data_code_pointer",
                                              to=val & ~1,
                                              to_hex="0x%08X" % (val & ~1),
                                              how="literal_pool@0x%08X" % addr,
                                              confidence="weak"))
                elif mem["base"] in env:
                    addr = (env[mem["base"]] + mem["offset"]) & 0xFFFFFFFF
                    how = "const_base:%s" % mem["base"]
                    if mem["index"] is not None and mem["index"] in env:
                        addr = (addr + (env[mem["index"]] << mem["shift"])) & 0xFFFFFFFF
                        how += "+index"
                else:
                    unresolved.append(dict(base, kind="mem",
                                           base_reg=mem["base"],
                                           offset=mem["offset"],
                                           index=mem["index"], shift=mem["shift"],
                                           access="read" if m in _LOAD_MN else "write",
                                           width=_WIDTH_OF.get(
                                               m, 1 if m in ("ldrb", "strb") else
                                               2 if m in ("ldrh", "strh") else 4),
                                           why="基址寄存器值未知"))
                if addr is not None:
                    xrefs.append(dict(base,
                                      kind="data_read" if m in _LOAD_MN else "data_write",
                                      to=addr, to_hex="0x%08X" % addr, how=how,
                                      confidence="observed" if how == "pc_relative"
                                      else "inferred",
                                      access="read" if m in _LOAD_MN else "write",
                                      width={"ldrb": 1, "strb": 1, "ldrh": 2,
                                             "strh": 2}.get(m, 4),
                                      member=mem["offset"],
                                      base_reg=mem["base"],
                                      index=mem["index"], shift=mem["shift"]))
            _const_env_step(unit, env, movt_lo, ins)
    counts = {}
    for x in xrefs:
        counts[x["kind"]] = counts.get(x["kind"], 0) + 1
    return {"xrefs": xrefs, "counts": counts, "unresolved": unresolved[:2000],
            "n_unresolved": len(unresolved), "truncated": truncated}


# ----------------------------------------------------------------------
# 调用图
# ----------------------------------------------------------------------
def call_graph(funcs: list, xrefs: list, *, max_edges: int = 20000) -> dict:
    """由 call xref 建调用图：入度/出度、根、叶、环（强连通分量）、深度。

    环用 Tarjan 求强连通分量（不用 DFS 记栈——递归调用的图一定有环，
    用栈标记会漏报）。深度用「从根出发 BFS」，遇环即停，得到的是**下界**。
    """
    by_addr = {f["addr"]: f for f in funcs}
    edges = []
    seen = set()
    for x in xrefs:
        if x["kind"] != "call":
            continue
        a, b = x["func"], x["to"]
        if a == 0 or (a, b) in seen:
            continue
        seen.add((a, b))
        edges.append({"caller": a, "caller_hex": "0x%08X" % a,
                      "caller_name": by_addr.get(a, {}).get("name") or "sub_%08X" % a,
                      "callee": b, "callee_hex": "0x%08X" % b,
                      "callee_name": by_addr.get(b, {}).get("name") or "sub_%08X" % b,
                      "callsite": x["from"], "callsite_hex": x["from_hex"],
                      "confidence": x.get("confidence", "inferred"),
                      "in_graph": b in by_addr})
    truncated = len(edges) > max_edges
    edges = edges[:max_edges]
    out_deg, in_deg = {}, {}
    adj, radj = {}, {}
    for e in edges:
        out_deg[e["caller"]] = out_deg.get(e["caller"], 0) + 1
        in_deg[e["callee"]] = in_deg.get(e["callee"], 0) + 1
        adj.setdefault(e["caller"], []).append(e["callee"])
        radj.setdefault(e["callee"], []).append(e["caller"])
    nodes = {f["addr"] for f in funcs} | set(in_deg) | set(out_deg)
    # 根 = 「有出边、没有入边」的函数（孤立函数不是根，是没人调也没调人的死代码）
    roots = sorted(n for n in nodes if n in by_addr and in_deg.get(n, 0) == 0
                   and out_deg.get(n, 0) > 0)
    leaves = sorted(n for n in nodes if out_deg.get(n, 0) == 0)
    # Tarjan（迭代版，避免深递归）
    index, low, on_stack, stack, comps = {}, {}, set(), [], []
    counter = [0]
    for v in sorted(nodes):
        if v in index:
            continue
        work = [(v, 0)]
        while work:
            node, pi = work.pop()
            if pi == 0:
                index[node] = low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on_stack.add(node)
            succ = adj.get(node, [])
            recurse = False
            for i in range(pi, len(succ)):
                w = succ[i]
                if w not in index:
                    work.append((node, i + 1))
                    work.append((w, 0))
                    recurse = True
                    break
                if w in on_stack:
                    low[node] = min(low[node], index[w])
            if recurse:
                continue
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                comps.append(sorted(comp))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    cycles = [c for c in comps if len(c) > 1]
    # 深度：从根 BFS，遇已访问即停
    depth = {}
    queue = [(r, 0) for r in roots]
    while queue:
        node, d = queue.pop(0)
        if node in depth and depth[node] <= d:
            continue
        depth[node] = d
        for w in adj.get(node, []):
            if w not in depth:
                queue.append((w, d + 1))
    return {"edges": edges, "n_edges": len(edges), "truncated": truncated,
            "n_nodes": len(nodes),
            "roots": [{"addr_hex": "0x%08X" % r,
                       "name": by_addr.get(r, {}).get("name") or ""} for r in roots],
            "n_leaves": len(leaves),
            "cycles": [{"size": len(c),
                        "addrs_hex": ["0x%08X" % a for a in c]} for c in cycles],
            "max_depth": max(depth.values()) if depth else 0,
            "by_name": {by_addr[a]["name"]: {"out": out_deg.get(a, 0),
                                             "in": in_deg.get(a, 0)}
                        for a in by_addr if a in out_deg or a in in_deg}}


# ----------------------------------------------------------------------
# 跳转表 / switch
# ----------------------------------------------------------------------
_MAX_TABLE = 256


def _bound_from_cmp(insns: dict, addr: int, *, back: int = 12):
    """向**回**找 ``cmp rN, #K`` + 紧随的守卫分支，返回 ``(K, 表项数或 None)``。

    Ghidra 的 switch 分析也从守卫条件取上界：表长在指令里没有编码，靠「扫到越界」
    去猜，就会把表后面的填充/其它数据当成 case。守卫条件才是可靠边界。

    项数取决于守卫条件本身，不能一律 ``K+1``：

    - ``cmp rN, #K`` + ``bhs/bcs default``：rN >= K 走 default ⇒ 合法下标 0..K-1 ⇒ **K 项**
    - ``cmp rN, #K`` + ``bhi default``：rN > K 走 default ⇒ 合法下标 0..K ⇒ **K+1 项**
    - 其它条件（lt/gt/eq/ne…）不是「上界守卫」，项数只能扫，返回 None
      （这时表长仍是推断值，调用方必须把它当 weak 置信度）。
    """
    keys = sorted(insns)
    prev = [a for a in keys if a < addr][-back:]
    bound = None
    cmp_at = None
    for a in reversed(prev):
        ins = insns[a]
        m = (ins.get("mnemonic") or "").lower()
        if m in ("tbb", "tbh") or "[pc" in (ins.get("op_str") or ""):
            break
        if m in ("cmp", "cmp.w"):
            for tok in (ins.get("op_str") or "").split(",")[1:]:
                v = _imm(tok.strip())
                if v is not None:
                    bound = v
                    cmp_at = a
                    break
            break
    if bound is None:
        return None, None
    cond = None
    nxt = [a for a in keys if a > cmp_at][:3]
    for a in nxt:
        m = (insns[a].get("mnemonic") or "").lower()
        if m.startswith("b") and m not in ("b", "bl", "blx", "bx", "bic", "bics"):
            cond = m[1:]
            break
        if m in ("it",) or m.startswith("it"):
            continue
        break
    if cond in ("hs", "cs"):
        return bound, bound
    if cond == "hi":
        return bound, bound + 1
    return bound, None


def _table_from_tbb(unit, ins, count: int, bound=None):
    """Thumb-2 ``tbb [pc, rN]`` / ``tbh [pc, rN, lsl #1]``：表紧跟在指令后面。

    ``bound`` 是**门数**（不是 ``cmp`` 里的 K——两者的差值由守卫条件决定）。

    ARM ARM：基址 = Align(PC,4)，PC 是**指令地址 + 4**；tbb 每项 1 字节、
    目标 = 基址 + 2*项；tbh 每项 2 字节半字、目标 = 基址 + 2*项。
    表长在指令里没有编码，只能「扫到目标离开代码区」或上限为止——这一点
    必须如实标注（置信度 inferred，长度是推断的）。
    """
    m = (ins.get("mnemonic") or "").lower()
    half = m.startswith("tbh")
    base = (ins["addr"] + 4) & ~3
    width = 2 if half else 1
    targets, raw = [], []
    limit = bound if bound is not None else count
    for i in range(min(limit, _MAX_TABLE)):
        b = unit.read(base + i * width, width)
        if len(b) < width:
            break
        v = int.from_bytes(b, "little")
        t = (base + 2 * v) & 0xFFFFFFFF
        if not unit.in_code(t):
            break
        raw.append(v)
        targets.append(t)
    return base, targets, raw


def _table_from_ldr_pc(unit, ins, count: int, bound=None):
    """ARM ``ldr pc, [pc, rN, lsl #2]``：表里是**绝对地址**，基址 = 指令地址 + 8。"""
    base = ins["addr"] + 8
    targets, raw = [], []
    limit = bound if bound is not None else count
    for i in range(min(limit, _MAX_TABLE)):
        v = read_u32(unit, base + i * 4)
        if v is None or not unit.in_code(v & ~1):
            break
        raw.append(v)
        targets.append(v & ~1)
    return base, targets, raw


def _table_from_add_pc(unit, ins, count: int, bound=None):
    """``add pc, pc, rN, lsl #2``：表里是**相对偏移**，基址 = 指令地址 + 8。"""
    base = ins["addr"] + 8
    targets, raw = [], []
    limit = bound if bound is not None else count
    for i in range(min(limit, _MAX_TABLE)):
        v = read_u32(unit, base + i * 4)
        if v is None:
            break
        t = (base + v) & 0xFFFFFFFF
        if not unit.in_code(t):
            break
        raw.append(v)
        targets.append(t)
    return base, targets, raw


def switch_tables(unit, insns: dict, funcs: list) -> dict:
    """恢复 switch 分支：跳转表三种形态 + 比较链。

    Ghidra 在反编译阶段做同样的事（``switch`` 的 case 目标来自
    ``JumpTable`` 分析）；不恢复它，反汇编里这些 case 分支根本不存在。
    """
    span = FuncSpan(funcs)
    out, unresolved = [], 0
    for addr in sorted(insns):
        ins = insns[addr]
        m = (ins.get("mnemonic") or "").lower()
        op = ins.get("op_str") or ""
        f = span.at(addr)
        if f is None:
            continue
        common = {"addr": addr, "addr_hex": "0x%08X" % addr,
                  "func": f["addr"], "func_name": f.get("name") or "",
                  "insn": ("%s %s" % (ins.get("mnemonic"), op)).strip()}
        if m in ("tbb", "tbh"):
            bound, nwant = _bound_from_cmp(insns, addr)
            base, targets, raw = _table_from_tbb(unit, ins, _MAX_TABLE, nwant)
            if targets:
                out.append(dict(common, kind=m, table_addr=base,
                                table_addr_hex="0x%08X" % base,
                                n_cases=len(targets),
                                targets_hex=["0x%08X" % t for t in targets],
                                confidence="inferred" if bound is not None else "weak",
                                length_basis=(("守卫条件 cmp #%d ⇒ %d 项" % (bound, nwant))
                                              if nwant is not None else
                                              ("表长无编码：扫到目标离开代码区/上限 %d 为止"
                                               % _MAX_TABLE))))
            else:
                unresolved += 1
        elif m == "ldr" and op.strip().startswith("pc,") and "[pc" in op:
            bound, nwant = _bound_from_cmp(insns, addr)
            base, targets, raw = _table_from_ldr_pc(unit, ins, _MAX_TABLE, nwant)
            if targets:
                out.append(dict(common, kind="ldr_pc_table", table_addr=base,
                                table_addr_hex="0x%08X" % base,
                                n_cases=len(targets),
                                targets_hex=["0x%08X" % t for t in targets],
                                confidence="inferred" if bound is not None else "weak",
                                length_basis=(("守卫条件 cmp #%d ⇒ %d 项" % (bound, nwant))
                                              if nwant is not None else
                                              "扫到目标离开代码区/上限 %d 为止" % _MAX_TABLE)))
            else:
                unresolved += 1
        elif m in ("add", "adds") and op.strip().startswith("pc,") and "lsl" in op:
            bound, nwant = _bound_from_cmp(insns, addr)
            base, targets, raw = _table_from_add_pc(unit, ins, _MAX_TABLE, nwant)
            if targets:
                out.append(dict(common, kind="add_pc_table", table_addr=base,
                                table_addr_hex="0x%08X" % base,
                                n_cases=len(targets),
                                targets_hex=["0x%08X" % t for t in targets],
                                confidence="weak",
                                length_basis=("相对偏移表，守卫 cmp #%d ⇒ %d 项" %
                                              (bound, nwant)) if nwant is not None
                                             else "相对偏移表，扫到越界为止"))
            else:
                unresolved += 1
    # 比较链：cmp rN,#K + bhi default，紧跟一串条件跳转
    out.extend(_compare_chain(unit, insns, funcs))
    counts = {}
    for s in out:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    return {"switches": out, "counts": counts, "n_unresolved": unresolved}


def _compare_chain(unit, insns: dict, funcs: list, *, max_cases: int = 64) -> list:
    """``cmp rN, #K`` + ``bhi default``，随后连续条件跳转 → 比较链 switch。

    这是编译器在没有跳转表时的写法（case 很少或值很稀疏）。判断依据是
    「上界 K 与随后条件跳转个数一致」，不一致就不报——猜一个 case 数没有意义。
    """
    span = FuncSpan(funcs)
    found = []
    addrs = sorted(insns)
    for i, addr in enumerate(addrs):
        ins = insns[addr]
        m = (ins.get("mnemonic") or "").lower()
        if m not in ("cmp", "cmp.w"):
            continue
        bound = None
        for tok in (ins.get("op_str") or "").split(",")[1:]:
            bound = _imm(tok.strip())
            if bound is not None:
                break
        if bound is None or bound > max_cases:
            continue
        f = span.at(addr)
        if f is None:
            continue
        # 下一条必须是比较链的出口（bhi/bgt 跳到 default）
        if i + 1 >= len(addrs):
            continue
        nxt = insns[addrs[i + 1]]
        nm = (nxt.get("mnemonic") or "").lower()
        if nm not in ("bhi", "bgt", "bls", "bge", "blt", "bgt.w", "bhi.w"):
            continue
        cases, j = [], i + 2
        while j < len(addrs) and len(cases) < bound + 1:
            c = insns[addrs[j]]
            cm = (c.get("mnemonic") or "").lower()
            if not (cm.startswith("b") and cm not in ("b", "b.w", "bl", "blx")) \
                    or c.get("target") is None:
                break
            cases.append(c["target"] & ~1)
            j += 1
        if len(cases) < 2:
            continue
        found.append({"addr": addr, "addr_hex": "0x%08X" % addr,
                      "func": f["addr"], "func_name": f.get("name") or "",
                      "insn": ("%s %s" % (ins.get("mnemonic"),
                                          ins.get("op_str"))).strip(),
                      "kind": "compare_chain", "n_cases": len(cases),
                      "bound": bound,
                      "targets_hex": ["0x%08X" % t for t in cases],
                      "default_hex": nxt.get("target_hex") or "",
                      "confidence": "inferred" if len(cases) == bound + 1 else "weak",
                      "length_basis": "cmp 上界与随后条件跳转个数对照"})
    return found
