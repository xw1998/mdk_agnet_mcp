"""rtypes —— 从访问模式里恢复「数据长什么样」，零新增依赖。

批次83 吸收 Ghidra 的**类型/栈帧恢复**口径（思路，不是代码）：

1. **栈帧局部变量**：``[sp, #off]`` / ``[fp, #off]`` 的每一次访问都是一个槽位的证据，
   宽度由助记符给出（``ldrb``=1 / ``ldrh``=2 / 其它=4）。Ghidra 的栈分析做的同一件事；
   区别是这里不做类型传播，只报「这个槽位被读了几次、写了几次、宽度是多少」。
2. **结构体候选**：以「基址寄存器相同、偏移不同」聚类。一个寄存器被 ``[rX, #0]``、
   ``[rX, #4]``、``[rX, #0x10]`` 碰过，就说明它指向一个至少 0x14 长的聚合体。
3. **数组指纹**：``[rX, rY, lsl #k]`` 的 ``k`` 直接给出元素大小 ``1<<k``。
4. **全局/静态对象**：PC 相对或常量基址访问到的地址，按地址归组，跨度 = 最大偏移 + 宽度。

三条铁律不变：
- 只报证据：每个槽位/字段都带「哪几条指令碰过它」；
- 置信度分级：``inferred``（多指令一致）/ ``weak``（单指令单次）；
- **不猜类型**：不把 4 字节就说成 ``int``，不把偏移 0 就说成「成员名」。
  类型是编译器优化后不可逆的信息，这里只给形状（offset / width / 读写次数）。
"""

from collections import defaultdict

from .reveng import _imm, parse_mem

_WIDTH_OF = {"ldrb": 1, "strb": 1, "ldrsb": 1, "ldrh": 2, "strh": 2,
             "ldrsh": 2, "ldrd": 8, "strd": 8, "ldr": 4, "str": 4}
_LOAD = ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "lw", "lb", "lh",
         "lbu", "lhu", "ldr.w", "ldrb.w", "ldrh.w")
_STORE = ("str", "strb", "strh", "strd", "sw", "sb", "sh", "str.w",
          "strb.w", "strh.w")
_ARG_REGS = ("r0", "r1", "r2", "r3")
_CALLEE_SAVED = ("r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11")


def _width(mnemonic: str) -> int:
    m = (mnemonic or "").lower()
    for k in ("ldrsb", "ldrsh", "ldrb", "strb", "ldrh", "strh", "ldrd", "strd"):
        if m.startswith(k):
            return _WIDTH_OF[k]
    return _WIDTH_OF.get(m, 4)


def _push_bytes(op_str: str) -> int:
    """``push {r4-r7, lr}`` → 20 字节（按寄存器个数 * 4）。"""
    regs = 0
    body = (op_str or "").strip().strip("{}")
    for tok in body.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            try:
                ra = int(a.strip().lstrip("rR"))
                rb = int(b.strip().lstrip("rR"))
                regs += abs(rb - ra) + 1
            except ValueError:
                regs += 1
        else:
            regs += 1
    return regs * 4


def stack_frame(insns: dict, start: int, end: int, *, max_slots: int = 128) -> dict:
    """一个函数的栈槽位表。

    ``sp_adj`` 是**累计**的 sp 变化（push 后为负，sub sp 后更负）。槽位号用
    ``sp_adj + offset`` 做不变量：这样 prologue 之后再访问同一个局部，算出来还是同一个槽。
    """
    slots = defaultdict(lambda: {"offset": 0, "width": 0, "reads": 0, "writes": 0,
                                 "addrs": [], "basis": ""})
    sp_adj = 0
    dynamic = False
    for a in sorted(k for k in insns if start <= k < end):
        ins = insns[a]
        m = (ins.get("mnemonic") or "").lower()
        op = ins.get("op_str") or ""
        if m in ("push", "push.w"):
            sp_adj -= _push_bytes(op)
            continue
        if m in ("pop", "pop.w"):
            continue
        if m in ("sub", "subs", "sub.w") and op.replace(" ", "").startswith("sp,sp,"):
            v = _imm(op.split(",")[-1].strip())
            if v:
                sp_adj -= v
            else:
                dynamic = True
            continue
        if m in ("add", "adds", "add.w") and op.replace(" ", "").startswith("sp,sp,"):
            v = _imm(op.split(",")[-1].strip())
            if v:
                sp_adj += v
            else:
                dynamic = True
            continue
        if m not in _LOAD and m not in _STORE:
            continue
        mem = parse_mem(op)
        if not mem or mem["base"] not in ("sp", "fp", "r7", "r11"):
            continue
        idx = ("sp" if mem["base"] == "sp" else "fp")
        key = sp_adj + mem["offset"] if idx == "sp" else mem["offset"]
        s = slots[key]
        s["offset"] = key
        s["width"] = max(s["width"], _width(m))   # 同槽位多种宽度取最大
        s["basis"] = "sp:%+d" % sp_adj if idx == "sp" else "fp"
        if m in _LOAD:
            s["reads"] += 1
        else:
            s["writes"] += 1
        if len(s["addrs"]) < 6:
            s["addrs"].append("0x%08X" % a)
    out = []
    for key in sorted(slots)[:max_slots]:
        s = slots[key]
        out.append({"offset": s["offset"], "offset_hex": "%+d (0x%X)" %
                    (s["offset"], abs(s["offset"])),
                    "width": s["width"] or 4, "reads": s["reads"],
                    "writes": s["writes"], "basis": s["basis"],
                    "accessed_at": s["addrs"],
                    "confidence": "inferred" if (s["reads"] + s["writes"]) > 1
                    else "weak"})
    span = (max((s["offset"] + s["width"] for s in out), default=0)
            - min((s["offset"] for s in out), default=0))
    return {"slots": out, "n_slots": len(out), "frame_span": span,
            "dynamic_sp": dynamic,
            "note": ("sp 在函数体中间有非固定调整：槽位偏移按当时的 sp 记账，"
                     "可能不再是同一个局部" if dynamic else "")}


def struct_candidates(unresolved: list, insns: dict, funcs: list,
                      *, max_per_func: int = 16) -> dict:
    """把「基址寄存器值未知」的访存聚成结构体候选。

    ``unresolved`` 是 ``reveng.build_xrefs`` 给出的那些记录：它们**不是噪声**，
    而是「这个寄存器指向的东西至少被访问到 offset 0xNN、宽度 4」这类证据。
    """
    by_func = defaultdict(lambda: defaultdict(list))
    for u in unresolved:
        if u.get("kind") != "mem":
            continue
        if (u.get("base_reg") or "") in ("sp", "fp", "pc"):
            continue          # 栈槽位归 stack_frame，不是结构体
        by_func[u["func"]][u.get("base_reg") or "?"].append(u)
    out = []
    for faddr, regs in by_func.items():
        fname = next((f.get("name") for f in funcs if f["addr"] == faddr), "")
        items = []
        for reg, us in sorted(regs.items()):
            offs = defaultdict(lambda: {"reads": 0, "writes": 0, "width": 4,
                                        "indexed": False, "shift": 0})
            for u in us:
                o = u.get("offset") or 0
                e = offs[o]
                e["width"] = max(e["width"], u.get("width") or 4)
                if u.get("access") == "read":
                    e["reads"] += 1
                else:
                    e["writes"] += 1
                if u.get("index") is not None:
                    e["indexed"] = True
                    e["shift"] = u.get("shift") or 0
            span = max((o + e["width"] for o, e in offs.items()), default=0)
            if len(offs) < 2:
                continue          # 只碰过一个偏移，说明不了「聚合体」
            # 跨度离谱（>1KB）：多半是同一个寄存器在不同分支里指向不同对象。
            # 这类结果留着，但必须降级——否则「结构体 3352 字节」会被当成事实。
            fishy = span > 1024
            items.append({
                "base_reg": reg,
                "kind": ("arg_pointer" if reg in _ARG_REGS else
                         "local_pointer" if reg in _CALLEE_SAVED else "unknown_base"),
                "n_fields": len(offs),
                "span": span,
                "fields": [{"offset": o, "offset_hex": "0x%X" % o,
                            "width": e["width"], "reads": e["reads"],
                            "writes": e["writes"],
                            "array_elem_size": (1 << e["shift"]) if e["indexed"] else 0}
                           for o, e in sorted(offs.items())],
                "confidence": ("weak" if fishy else
                               "inferred" if len(offs) >= 3 else "weak"),
                "suspicious_span": fishy,
                "note": ("跨度异常大（>1KB）：很可能是同一个寄存器在不同分支里"
                         "指向不同对象，别当成一个结构体" if fishy else
                         "偏移与宽度是**证据**；字段类型不可逆，不猜"),
            })
        if items:
            out.append({"func": faddr, "func_hex": "0x%08X" % faddr,
                        "func_name": fname,
                        "candidates": sorted(items, key=lambda x: -x["span"])
                        [:max_per_func]})
    return {"functions": out, "n_functions": len(out),
            "n_candidates": sum(len(f["candidates"]) for f in out)}


def array_accesses(insns: dict, funcs: list, *, max_items: int = 2000) -> dict:
    """``[rX, rY, lsl #k]`` 的 k 就是元素大小 ``1<<k``——数组指纹。"""
    items = []
    for a in sorted(insns):
        ins = insns[a]
        m = (ins.get("mnemonic") or "").lower()
        if m not in _LOAD and m not in _STORE:
            continue
        mem = parse_mem(ins.get("op_str") or "")
        if not mem or mem["index"] is None:
            continue
        f = next((x for x in funcs
                  if x["addr"] <= a < (x.get("end_addr") or x["addr"])), None)
        items.append({"addr_hex": "0x%08X" % a,
                      "func": f["addr"] if f else 0,
                      "func_name": f.get("name") if f else "",
                      "base_reg": mem["base"], "index_reg": mem["index"],
                      "offset": mem["offset"],
                      "elem_size": 1 << mem["shift"],
                      "width": _width(m),
                      "access": "read" if m in _LOAD else "write"})
        if len(items) >= max_items:
            break
    return {"items": items, "n_items": len(items),
            "by_elem_size": dict(sorted({s: sum(1 for i in items
                                                if i["elem_size"] == s)
                                         for s in {i["elem_size"] for i in items}}.items()))}


def global_objects(xrefs: list, *, min_field: int = 1, max_items: int = 4000) -> dict:
    """按地址归组「被访问到的数据对象」：跨度 = 最大偏移 + 宽度。"""
    acc = defaultdict(lambda: {"reads": 0, "writes": 0, "max_end": 0,
                               "addrs": [], "funcs": set(), "how": set()})
    for x in xrefs:
        if x["kind"] not in ("data_read", "data_write"):
            continue
        e = acc[x["to"]]
        w = x.get("width") or 4
        e["max_end"] = max(e["max_end"], w)
        if x["kind"] == "data_read":
            e["reads"] += 1
        else:
            e["writes"] += 1
        if len(e["addrs"]) < 8:
            e["addrs"].append(x["from_hex"])
        e["funcs"].add(x.get("func_name") or "")
        e["how"].add(x.get("how") or "")
    items = []
    for addr in sorted(acc):
        e = acc[addr]
        items.append({"addr": addr, "addr_hex": "0x%08X" % addr,
                      "size_at_least": e["max_end"],
                      "reads": e["reads"], "writes": e["writes"],
                      "accessed_from": e["addrs"],
                      "funcs": sorted(x for x in e["funcs"] if x)[:6],
                      "how": sorted(e["how"]),
                      "confidence": "observed" if "pc_relative" in e["how"]
                      else "inferred"})
        if len(items) >= max_items:
            break
    return {"items": items, "n_items": len(items),
            "n_written": sum(1 for i in items if i["writes"])}


def analyze_types(insns: dict, funcs: list, xrefs: dict) -> dict:
    """一次把四件事做完：栈帧 / 结构体候选 / 数组指纹 / 全局对象。"""
    frames, structs = [], []
    for f in funcs:
        st, en = f["addr"], f.get("end_addr") or f["addr"]
        if en - st < 4:
            continue
        fr = stack_frame(insns, st, en)
        if fr["n_slots"]:
            frames.append({"func": f["addr"], "func_hex": "0x%08X" % f["addr"],
                           "func_name": f.get("name") or "", **fr})
    sc = struct_candidates(xrefs.get("unresolved") or [], insns, funcs)
    arr = array_accesses(insns, funcs)
    gl = global_objects(xrefs.get("xrefs") or [])
    return {
        "stack_frames": frames,
        "n_frames": len(frames),
        "n_slots": sum(f["n_slots"] for f in frames),
        "structs": sc["functions"],
        "n_struct_candidates": sc["n_candidates"],
        "arrays": arr["items"],
        "array_elem_sizes": arr["by_elem_size"],
        "globals": gl["items"],
        "n_globals": gl["n_items"],
        "basis": "栈槽位=sp/fp 相对偏移按宽度记账；结构体=同基址寄存器多偏移聚类；"
                 "数组=索引寻址的 lsl 移位；全局=PC 相对/常量基址访问的地址归组",
        "limitations": [
            "只给**形状**（偏移 / 宽度 / 读写次数），不给类型名：编译器优化之后"
            "类型信息不可逆，把 4 字节说成 int 就是编的",
            "结构体候选来自「基址寄存器 + 偏移」，寄存器里存的到底是结构体指针、"
            "数组还是字符串，本工具不判断",
        ],
    }
