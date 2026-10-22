"""decomp —— 寄存器级伪 C（lifting）。批次84。

把 ARM/Thumb 指令提升成 **寄存器级 C**：每条指令变成一条赋值/存储/调用，
控制流用 ``if`` / ``goto`` / ``switch`` 表示。它**不是原始源码**：类型名、
结构体、宏、注释、变量名都不会自己长出来（Ghidra 的反编译器同样是从 p-code
重建表达式，只是它的类型推断与结构化要强得多；这里只做到「表达式 + 控制流」）。

三条口径（与批次81~83 一致）：

- **保语义不保好看**：结构化失败的地方保留 ``goto``，不为了「像 C」编造结构；
- **推断必须标注**：跳转表长度来自守卫 ``cmp``（inferred）还是扫到越界（weak）
  写进注释；条件依赖的 flags 找不到生产者时输出 ``flag_<cond>`` 并计数；
- **不支持的指令不静默丢**：输出 ``/* 未支持: <mnemonic> */`` 并计入 ``unsupported``。

零新增依赖：只用 capstone（已在使用）+ 批次82 的 ``reveng``（跳转表 / 名字）。
"""

import os
import re

from . import reveng

# ----------------------------------------------------------------------
# 常量表
# ----------------------------------------------------------------------
# capstone ARM 的移位类型：0=invalid 1=ASR 2=LSL 3=LSR 4=ROR 5=RRX
_SHIFT_OP = {1: " >> ", 2: " << ", 3: " >> "}

_TY = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
_STY = {1: "int8_t", 2: "int16_t", 4: "int32_t"}

# 二元运算：``rd = a <op> b``
_ARITH = {"add": "+", "addw": "+", "sub": "-", "subw": "-",
          "and": "&", "orr": "|", "eor": "^", "lsl": "<<", "lsr": ">>",
          "asr": ">>"}

_BRANCH_CONDS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
                 "hi", "ls", "ge", "lt", "gt", "le")

# 条件码取反（结构化 if 用：``b<cond> Lskip`` ⇒ ``if (!cond)``）
_OPPOSITE = {"eq": "ne", "ne": "eq", "cs": "cc", "hs": "lo", "cc": "cs",
             "lo": "hs", "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs",
             "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge", "gt": "le",
             "le": "gt"}

# 比较/测试类（只写 flags，不产出赋值）
_FLAG_MN = ("cmp", "cmn", "tst", "teq")

# 只有这些基名后面才允许跟 ``s`` 表示「写 flags」（``bls`` 是分支不是 ``bl+s``）
# 这些指令写 flags 时 C 位不可预测（不是进位/借位），adc/sbc/rrx 遇到它们必须降级
_C_UNKNOWN = {"and", "orr", "eor", "bic", "orn", "mov", "mvn", "mul"}

_FLAGSET_MN = {"add", "sub", "and", "orr", "eor", "lsl", "lsr", "asr", "mul",
               "mov", "mvn", "bic", "orn", "rsb", "adc", "sbc", "addw",
               "subw", "movw", "rrx"}

_UNSUPPORTED_HINT = {
    "cpsid": "关中断", "cpsie": "开中断", "msr": "写特殊寄存器",
    "mrs": "读特殊寄存器", "svc": "系统调用", "bkpt": "断点",
    "clz": "前导零", "rev": "字节反转", "rev16": "字节反转",
    "revsh": "字节反转", "mla": "乘加", "mls": "乘减", "sbc": "带借位减",
    "vldr": "浮点装", "vstr": "浮点存", "vmov": "浮点搬",
}

_KNOWN_MN = tuple(sorted({
    "adc", "add", "addw", "adr", "and", "asr", "b", "bic", "bkpt", "bl", "blx",
    "bx", "cbz", "cbnz", "clz", "cmn", "cmp", "cpsid", "cpsie", "dmb", "dsb",
    "eor", "isb", "it", "ldm", "ldmdb", "ldmia", "ldr", "ldrb", "ldrd", "ldrh",
    "ldrex", "ldrexb", "ldrexh", "ldrsb", "ldrsh", "lsl", "lsr", "mla", "mls",
    "mov", "movt", "movw", "mrs", "msr", "mul", "mvn", "nop", "orn", "orr",
    "pop", "push", "rev", "rev16", "revsh", "ror", "rrx", "rsb", "sbc",
    "sbfx", "sdiv", "sev", "smull", "smlal", "stm", "stmdb", "stmia", "str",
    "strb", "strd", "strex", "strexb", "strexh", "strh", "sub", "subw", "svc",
    "sxtb", "sxth", "tbb", "tbh", "teq", "tst", "ubfx", "udiv", "umlal",
    "umull", "uxtb", "uxth", "wfe", "wfi",
}, key=len, reverse=True))

_GOTO_RE = re.compile(r"^L_([0-9A-F]{8}):")

# 跳转表每项的字节数（tbb 是字节表，tbh 是半字表，pc 表是 32 位地址/偏移表）
_TABLE_ENTRY_SIZE = {"tbb": 1, "tbh": 2,
                    "ldr_pc_table": 4, "add_pc_table": 4}

# 剥表数据的安全上限：超过这个字节数说明表长很可能是扫过头的推断值，不剥
_MAX_TABLE_DROP = 1024

def _table_ranges(switches) -> list:
    """跳转表 → ``[(起, 止, 描述)]``，只收能确定表基址与项宽度的。"""
    out = []
    for s in switches or []:
        base = s.get("table_addr")
        n = int(s.get("n_cases") or 0)
        w = _TABLE_ENTRY_SIZE.get(str(s.get("kind") or ""))
        if base is None or n <= 0 or not w:
            continue
        start = int(base)
        end = start + n * w
        if end - start > _MAX_TABLE_DROP:
            continue
        out.append((start, end, "%s 跳转表 %d 项" % (s.get("kind"), n)))
    return out


def _hex(v) -> str:
    v = int(v or 0)
    if v < 0:
        return "-0x%X" % (-v)
    return "0x%X" % (v & 0xFFFFFFFF)


def _base_mn(mn: str) -> str:
    """去掉 capstone 的 ``.w`` / ``.n`` 后缀。"""
    m = (mn or "").strip().lower()
    for suf in (".w", ".n"):
        if m.endswith(suf):
            m = m[: -len(suf)]
    return m


def _branch_cond(mn: str):
    """``beq``→``eq``；``b``→``""``；不是条件分支 → None。"""
    m = _base_mn(mn)
    if m == "b":
        return ""
    if m.startswith("b") and m[1:] in _BRANCH_CONDS:
        return m[1:]
    return None


def _split_cond(mn: str):
    """把 ``addeq`` 拆成 ``("add", "eq")``；``adds`` → ``("add", "")``。

    只对**已知基名**成立（避免把 ``bls`` 当成 ``bl``+``s``）。
    """
    m = _base_mn(mn)
    if m.startswith("it") and set(m[2:]) <= {"t", "e"}:
        return "it", ""
    for base in _KNOWN_MN:
        if not m.startswith(base):
            continue
        rest = m[len(base):]
        if rest == "":
            return base, ""
        if rest in _BRANCH_CONDS:
            return base, rest
        if base in _FLAGSET_MN:
            if rest == "s":
                return base, ""
            if rest.startswith("s") and rest[1:] in _BRANCH_CONDS:
                return base, rest[1:]
    return m, ""


def _shift_carry(base: str, a: str, b: str):
    """移位指令写 flags 时的 C 位（= 最后移出位）；拿不到立即数就返回 None。

    ``rrx`` 就靠这个 C 位（``lsrs r1,#1`` 后接 ``rrx r2,r2`` 是编译器常见写法）。
    """
    try:
        n = int(str(b), 16) if str(b).startswith("0x") else int(b)
    except (TypeError, ValueError):
        return None
    if base == "lsl":
        if n == 0:
            return "keep"               # #0 不改 C（沿用上一条）
        if n >= 32:
            return "0"
        return "((uint32_t)(%s) >> %d) & 1" % (a, 32 - n)
    if n == 0:
        return "keep"
    if n >= 32:
        return ("((uint32_t)(%s) >> 31) & 1" % a) if base == "asr" else "0"
    return "((uint32_t)(%s) >> %d) & 1" % (a, n - 1)

def _sets_flags(mn: str) -> bool:
    """这条指令是否写 flags（``subs`` / ``subs.w`` / ``subshs`` 都算）。

    ``_base_mn`` 只去掉 ``.w``/``.n``，所以 ``subs.w`` 的文本以 ``.w`` 结尾，
    直接 ``endswith("s")`` 会漏判——这是个会且已经导致进位链断掉的坑。
    """
    m = _base_mn(mn)
    for base in _FLAGSET_MN:
        if not m.startswith(base):
            continue
        rest = m[len(base):]
        if rest == "s":
            return True
        if rest.startswith("s") and rest[1:] in _BRANCH_CONDS:
            return True
    return False

def _c_name(name: str, fallback: str) -> str:
    n = "".join(c if (c.isalnum() or c == "_") else "_" for c in (name or ""))
    if not n:
        return fallback
    if n[0].isdigit():
        n = "_" + n
    return n


def _it_conds(mn: str, op: str) -> list:
    """``it ne`` → ``["ne"]``；``ite eq`` → ``["eq","ne"]``（第二条取反）。

    模式（t/e 序列）在**助记符**里（``itt``/``ite``/``itte``），不在 op_str 里。
    """
    m = _base_mn(mn)
    toks = (op or "").replace(",", " ").split()
    if not m.startswith("it") or not toks:
        return []
    cond = toks[-1].lower()
    if cond not in _BRANCH_CONDS:
        return []
    pat = "t" + m[2:]          # 第一条指令的条件码不写在助记符里
    out = []
    for ch in pat:
        if ch == "t":
            out.append(cond)
        elif ch == "e":
            out.append(_OPPOSITE.get(cond, cond))
    return out


# ----------------------------------------------------------------------
# 取指
# ----------------------------------------------------------------------
def meta_src(rd: dict) -> dict:
    """``read_ex`` 的出处（批次94）：伪 C 也要能说清「这些字节是从文件哪儿读的」。"""
    off = rd.get("file_offset")
    return {"file_offset_hex": ("0x%X" % off) if off is not None else None,
            "requested": rd.get("requested"), "got": rd.get("got"),
            "clipped": bool(rd.get("clipped")), "reason": rd.get("reason") or ""}


def _decode(unit, start: int, end: int, *, max_insns: int = 4000):
    """反汇编 ``[start, end)``，返回 **capstone 指令对象**（要 operands 细节）。

    坏字节按指令对齐跳过并计数（与 ``recover.disassemble`` 同一策略），
    不把「一个坏字节」当成「后面没有指令」。
    """
    from .recover import _make_cs           # 避免模块级循环导入
    md, why = _make_cs(unit.arch)
    if md is None:
        return None, 0, why, {}
    from .recover import readback_mismatches     # 批次94：字节回填校验
    rd = unit.read_ex(start, end - start)
    blob = rd["data"]
    if not blob:
        return None, 0, (rd.get("reason") or
                         "地址 0x%08X 不在镜像的映射范围内" % start), {}
    md.detail = True
    insns, skipped = [], 0
    step = 2 if (unit.arch.get("thumb") or unit.arch.get("family") == "riscv") else 4
    pos = 0
    while pos < len(blob):
        got = False
        for ins in md.disasm(blob[pos:], start + pos):
            insns.append(ins)
            pos = ins.address + ins.size - start
            got = True
            if len(insns) >= max_insns:
                return insns, skipped, "", {}
        if not got or pos < len(blob):
            pos = min(pos + step, len(blob))
            skipped += 1
    # 批次94：解码用的字节必须能按同一地址从文件重读（读错偏移/跨段拼接的兜底）。
    # 放在翻译之前：这里还是 capstone 对象，bytes 是原样的机器码。
    bad = readback_mismatches(unit, [(i.address, i.size, i.bytes.hex())
                                     for i in insns])
    if bad:
        return None, 0, ("字节回填校验失败：解码用的字节与按地址从文件重读的字节不一致"
                         "（读错偏移或跨段拼接都会这样），指令流/字面量池都不可信"), \
            {"mismatches": bad, "source": meta_src(rd)}
    # 批次93：非 ARM 家族先把指令翻成「ARM 形状的 IR」，再进同一套提升器；
    # MIPS 的分支延迟槽在这里整组提到分支之前（否则伪 C 的顺序是错的）。
    meta = {"family": (unit.arch or {}).get("family") or "arm",
            "delay_slots_hoisted": 0, "source": meta_src(rd)}
    if meta["family"] in ("riscv", "mips"):
        from . import lift_isa             # noqa: PLC0415
        groups = [lift_isa.normalise(unit, i) for i in insns]
        if meta["family"] == "mips":       # 只有 MIPS 有分支延迟槽
            insns, moved = lift_isa.hoist_delay_slots(groups)
            meta["delay_slots_hoisted"] = moved
        else:
            insns = [x for g in groups for x in g]
    return insns, skipped, "", meta


# ----------------------------------------------------------------------
# 操作数 → C 表达式
# ----------------------------------------------------------------------
_REG_ALIAS = {"sl": "r10", "fp": "r11", "ip": "r12", "sb": "r9"}


def _reg(ins, reg_id: int) -> str:
    try:
        name = reveng._norm_reg(ins.reg_name(reg_id))
    except Exception:                      # noqa: BLE001
        return "r?"
    return _REG_ALIAS.get(name, name)


def _addr_text(unit, ins, op) -> str:
    """内存操作数 → 地址表达式（pc 相对会算成绝对地址）。"""
    base = _reg(ins, op.mem.base) if op.mem.base else ""
    idx = _reg(ins, op.mem.index) if op.mem.index else ""
    disp = int(op.mem.disp or 0)
    lshift = int(getattr(op.mem, "lshift", 0) or 0)
    if base == "pc":
        pc = reveng._pc_value(unit, {"addr": ins.address})
        return _hex(pc + disp)
    parts = []
    if base:
        parts.append(base)
    if idx:
        parts.append("(%s << %d)" % (idx, lshift) if lshift else idx)
    if disp or not parts:
        parts.append(_hex(disp))
    out = parts[0]
    for p in parts[1:]:
        if p.startswith("-"):
            out += " - " + p[1:]
        else:
            out += " + " + p
    return out


def _mem_expr(unit, ins, op, width: int, signed: bool = False) -> str:
    ty = (_STY if signed else _TY).get(width, "uint32_t")
    addr = _addr_text(unit, ins, op)
    if addr.startswith("0x"):
        return "*(%s *)%s" % (ty, addr)
    return "*(%s *)(%s)" % (ty, addr)


def _op_expr(unit, ins, op) -> str:
    t = int(getattr(op, "type", 0))
    if t == 1:                                     # REG
        name = _reg(ins, op.reg)
        sh = getattr(op, "shift", None)
        if sh is not None and getattr(sh, "type", 0):
            opstr = _SHIFT_OP.get(int(sh.type))
            if opstr:
                return "(%s%s%d)" % (name, opstr, int(sh.value or 0))
            return "%s /* ror %d */" % (name, int(sh.value or 0))
        return name
    if t == 2:                                     # IMM
        return _hex(op.imm)
    if t == 3:                                     # MEM（取地址）
        return _addr_text(unit, ins, op)
    return "/*op%d?*/" % t


def _reglist(ins) -> list:
    return [_reg(ins, op.reg) for op in ins.operands
            if int(getattr(op, "type", 0)) == 1]


def _target(ins):
    """直接跳转目标（立即数），没有就 None。"""
    for op in ins.operands:
        if int(getattr(op, "type", 0)) == 2:
            return int(op.imm)
    return None


def _abs_pc(unit, ins) -> str:
    """``add/sub <rd>, pc, #imm`` 的绝对地址。"""
    return _hex(reveng._pc_value(unit, {"addr": ins.address}))


# ----------------------------------------------------------------------
# 条件表达式（靠「上一条写 flags 的指令」解释条件码）
# ----------------------------------------------------------------------
def _carry_of_add(a: str, b: str) -> str:
    """``adds`` 后的 C 位：32 位加法的进位。"""
    return "((uint32_t)(((uint64_t)(%s) + (uint64_t)(%s)) >> 32))" % (a, b)

def _carry_of_sub(a: str, b: str) -> str:
    """``subs`` 后的 C 位：无借位（a >= b）。"""
    return "((uint32_t)(%s) >= (uint32_t)(%s))" % (a, b)

def _cond_text(cond: str, flags) -> str:
    """把条件码变成 C 表达式。

    ``flags`` 是 ``{"kind": "cmp"/"tst", "a": ..., "b": ...}``；
    为 None（找不到生产者）时返回 ``flag_<cond>``——**不猜**，由调用方计数。
    """
    if not cond or cond == "al":
        return ""
    if flags is None:
        return "flag_%s" % cond
    a, b, kind = flags.get("a", "?"), flags.get("b", "?"), flags.get("kind")
    if kind == "logic" and cond not in ("eq", "ne", "mi", "pl"):
        return "flag_%s" % cond          # 逻辑/移位只定义 Z/N，C/V 不解释
    if kind == "add" and cond in ("cs", "hs", "cc", "lo"):
        return "flag_%s" % cond          # adds 的进位是溢出位，不是无符号大小关系
    if kind == "tst":
        t = "(%s & %s)" % (a, b)
        return {"eq": "%s == 0" % t, "ne": "%s != 0" % t,
                "mi": "((%s) >> 31) & 1" % t,
                "pl": "!(((%s) >> 31) & 1)" % t}.get(cond, "flag_%s" % cond)
    if cond in ("eq", "ne"):
        return "%s %s %s" % (a, "==" if cond == "eq" else "!=", b)
    if cond in ("cs", "hs"):
        return "%s >= %s /* 无符号 */" % (a, b)
    if cond in ("cc", "lo"):
        return "%s < %s /* 无符号 */" % (a, b)
    if cond == "hi":
        return "%s > %s /* 无符号 */" % (a, b)
    if cond == "ls":
        return "%s <= %s /* 无符号 */" % (a, b)
    if cond == "ge":
        return "(int32_t)%s >= (int32_t)%s" % (a, b)
    if cond == "lt":
        return "(int32_t)%s < (int32_t)%s" % (a, b)
    if cond == "gt":
        return "(int32_t)%s > (int32_t)%s" % (a, b)
    if cond == "le":
        return "(int32_t)%s <= (int32_t)%s" % (a, b)
    if cond in ("mi", "pl"):
        if b in ("0", "0x0"):
            return ("(int32_t)%s < 0" % a) if cond == "mi" else (
                "(int32_t)%s >= 0" % a)
        d = "((int32_t)%s - (int32_t)%s)" % (a, b)
        return "%s < 0" % d if cond == "mi" else "%s >= 0" % d
    return "flag_%s" % cond


# ----------------------------------------------------------------------
# 单条指令 → 语句
# ----------------------------------------------------------------------
def _lift(unit, ins, ctx) -> list:
    """返回若干行 C；带条件的指令（含 IT 块）在这里统一包成 ``if``。"""
    # 非 ARM 家族的 IR 可以自带「已经渲染好的 C 行」（翻译层有把握的形态），
    # 或「未支持」的注释。这两类都不过 ARM 的条件/flags 逻辑。
    fixed = getattr(ins, "fixed", None)
    if fixed is not None:
        note = getattr(ins, "note", "") or ""
        if note == "unsupported":
            ctx["unsupported"].append(getattr(ins, "src_mnemonic", ins.mnemonic))
        elif note == "ctrl":
            ctx["ctrl_note"] = ctx.get("ctrl_note", 0) + 1
        elif note == "discard":
            ctx["discard"] = ctx.get("discard", 0) + 1
        return list(fixed)
    base, cond = _split_cond(ins.mnemonic)
    if base == "it":
        ctx["it"] = _it_conds(ins.mnemonic, ins.op_str)
        return ["/* %s %s —— 后续 %d 条指令的 IT 条件已展开为 if */"
                % (ins.mnemonic, ins.op_str, len(ctx["it"]))]
    queue = ctx.get("it") or []
    if queue:
        cond = queue.pop(0)
    flags_before = ctx.get("flags")
    stmts = _lift_one(unit, ins, ctx, base)
    # 逻辑/乘法类指令的 C 位不可预测（不是进位）——进位链到此断掉，adc/sbc 降级
    # （移位单独在 _shift_carry 里算了，不能在这里一并清掉）
    if (ctx.get("flags") is not flags_before
            and _split_cond(ins.mnemonic)[0] in _C_UNKNOWN
            and (ctx.get("flags") or {}).get("kind") == "logic"):
        ctx["carry"] = None
    if not cond:
        return stmts
    expr = _cond_text(cond, flags_before)
    if expr.startswith("flag_"):
        ctx["flag_unresolved"] = ctx.get("flag_unresolved", 0) + 1
    out = []
    for s in stmts:
        if s.lstrip().startswith("/*") or s.split()[0].startswith("/*"):
            out.append(s)
        else:
            out.append("if (%s) { %s }" % (expr or "1", s))
    return out


def _abi_of(ctx) -> dict:
    return ctx.get("abi") or {}


def _ret_name(ctx) -> str:
    """返回寄存器在人读代码里的名字（ARM 是 r0，RISC-V 是 a0，MIPS 是 v0）。"""
    return _abi_of(ctx).get("ret_name") or "r0"


def _call_args(ctx) -> str:
    names = (_abi_of(ctx).get("arg_names") or ["r0", "r1", "r2", "r3"])[:4]
    return ", ".join(names)


def _unsupported(ins, ctx, base) -> list:
    ctx["unsupported"].append(ins.mnemonic)
    hint = _UNSUPPORTED_HINT.get(base, "")
    return ["/* 未支持: %s %s%s */" % (ins.mnemonic, ins.op_str,
                                      ("（%s）" % hint) if hint else "")]


def _lift_one(unit, ins, ctx, base) -> list:
    ops = list(ins.operands)
    sets_flags = _sets_flags(ins.mnemonic)

    # ---- flags 类：只记不写 ----
    if base in _FLAG_MN:
        a = _op_expr(unit, ins, ops[0]) if ops else "?"
        b = _op_expr(unit, ins, ops[1]) if len(ops) > 1 else "0"
        ctx["flags"] = {"kind": "tst" if base in ("tst", "teq") else "cmp",
                        "a": a, "b": b}
        if base == "cmp":
            ctx["carry"] = _carry_of_sub(a, b)
        elif base == "cmn":
            ctx["carry"] = _carry_of_add(a, b)
        else:                              # tst/teq：进位来自移位器，未建模
            ctx["carry"] = None
        return ["/* %s %s, %s */" % (base, a, b)]

    # ---- mov / mvn / 常量 ----
    if base in ("mov", "movs"):
        if len(ops) >= 2:
            dest = _op_expr(unit, ins, ops[0])
            if sets_flags:
                ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
            return ["%s = %s;" % (dest, _op_expr(unit, ins, ops[1]))]
        return _unsupported(ins, ctx, base)
    if base in ("movw", "movt"):
        if len(ops) >= 2 and int(getattr(ops[1], "type", 0)) == 2:
            dest = _op_expr(unit, ins, ops[0])
            v = int(ops[1].imm or 0)
            if base == "movw":
                return ["%s = %s; /* movw */" % (dest, _hex(v & 0xFFFF))]
            return ["%s = (%s << 16) | (%s & 0xFFFF); /* movt */"
                    % (dest, _hex(v & 0xFFFF), dest)]
        return _unsupported(ins, ctx, base)
    if base in ("mvn", "mvns"):
        if len(ops) >= 2:
            dest = _op_expr(unit, ins, ops[0])
            if sets_flags:
                ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
            return ["%s = ~%s;" % (dest, _op_expr(unit, ins, ops[1]))]
        return _unsupported(ins, ctx, base)
    if base == "adr":
        if len(ops) >= 2 and int(getattr(ops[1], "type", 0)) == 2:
            dest = _op_expr(unit, ins, ops[0])
            v = int(ops[1].imm or 0)
            # capstone 对 Thumb 的 ADR 给的是**偏移**，对 ARM 可能已给绝对地址
            lo = min(a for a, _ in unit.code_ranges) if unit.code_ranges else 0
            hi = max(b for _, b in unit.code_ranges) if unit.code_ranges else 0
            abs_addr = v if (lo and lo <= v < hi) else (
                reveng._pc_value(unit, {"addr": ins.address}) + v)
            return ["%s = %s; /* adr */" % (dest, _hex(abs_addr))]
        return _unsupported(ins, ctx, base)

    # ---- 带进位加减（64 位算术的半部分）----
    if base in ("adc", "sbc") and len(ops) >= 2:
        carry = ctx.get("carry")
        dest = _op_expr(unit, ins, ops[0])
        if len(ops) >= 3:
            a, b = _op_expr(unit, ins, ops[1]), _op_expr(unit, ins, ops[2])
        else:
            a, b = dest, _op_expr(unit, ins, ops[1])
        if carry is None:
            # 进位链断了（上一条不带 flags / 逻辑运算 / 调用）——不猜，降级
            return _unsupported(ins, ctx, base)
        if base == "adc":
            ctx["carry"] = ("((uint32_t)(((uint64_t)(%s) + (uint64_t)(%s)"
                            " + (uint64_t)(%s)) >> 32))" % (a, b, carry))
            return ["%s = %s + %s + (%s); /* adc（进位来自上一条 add/sub） */"
                    % (dest, a, b, carry)]
        ctx["carry"] = ("((uint32_t)(%s) >= (uint32_t)(%s) + (uint32_t)(1 - (%s)))"
                        % (a, b, carry))
        return ["%s = %s - %s - (1 - (%s)); /* sbc（借位来自上一条 add/sub） */"
                % (dest, a, b, carry)]

    # ---- 二元算术 / 逻辑 / 移位 ----
    if base in _ARITH:
        # ``addw/subw rd, pc, #imm`` ⇒ 绝对地址
        if len(ops) >= 3 and _op_expr(unit, ins, ops[1]) == "pc":
            return ["%s = %s; /* %s pc 相对 */"
                    % (_op_expr(unit, ins, ops[0]), _abs_pc(unit, ins), base)]
        if len(ops) >= 3:
            dest = _op_expr(unit, ins, ops[0])
            a = _op_expr(unit, ins, ops[1])
            b = _op_expr(unit, ins, ops[2])
            if sets_flags:
                # add/sub 的 C/Z/N/V 等价于「a 与 b 比较」；移位/逻辑只对结果判零
                if base in ("add", "addw", "sub", "subw"):
                    ctx["flags"] = {"kind": ("sub" if base.startswith("sub")
                                             else "add"), "a": a, "b": b}
                    ctx["carry"] = (_carry_of_sub(a, b) if base.startswith("sub")
                                     else _carry_of_add(a, b))
                elif base in ("lsl", "lsr", "asr"):
                    ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
                    sc = _shift_carry(base, a, b)
                    if sc != "keep":
                        ctx["carry"] = sc
                else:
                    ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
                    ctx["carry"] = None
            return ["%s = %s %s %s;" % (dest, a, _ARITH[base], b)]
        if len(ops) == 2 and int(getattr(ops[0], "type", 0)) == 1:
            dest = _op_expr(unit, ins, ops[0])
            b = _op_expr(unit, ins, ops[1])
            if sets_flags:
                if base in ("add", "addw", "sub", "subw"):
                    ctx["flags"] = {"kind": ("sub" if base.startswith("sub")
                                             else "add"), "a": dest, "b": b}
                    ctx["carry"] = (_carry_of_sub(dest, b) if base.startswith("sub")
                                     else _carry_of_add(dest, b))
                elif base in ("lsl", "lsr", "asr"):
                    ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
                    sc = _shift_carry(base, dest, b)
                    if sc != "keep":
                        ctx["carry"] = sc
                else:
                    ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
                    ctx["carry"] = None
            return ["%s = %s %s %s;" % (dest, dest, _ARITH[base], b)]
        return _unsupported(ins, ctx, base)
    if base in ("rsb", "rsbs") and len(ops) >= 3:
        dest = _op_expr(unit, ins, ops[0])
        ctx["flags"] = ({"kind": "cmp", "a": dest, "b": "0"} if sets_flags else None)
        return ["%s = %s - %s;" % (dest, _op_expr(unit, ins, ops[2]),
                                   _op_expr(unit, ins, ops[1]))]
    if base in ("bic", "bics") and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        a = dest if len(ops) == 2 else _op_expr(unit, ins, ops[1])
        b = _op_expr(unit, ins, ops[-1])
        if sets_flags:
            ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
        return ["%s = %s & ~%s;" % (dest, a, b)]
    if base in ("orn", "orns") and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        a = dest if len(ops) == 2 else _op_expr(unit, ins, ops[1])
        b = _op_expr(unit, ins, ops[-1])
        if sets_flags:
            ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
        return ["%s = %s | ~%s;" % (dest, a, b)]
    if base in ("mul", "muls"):
        if len(ops) >= 3:
            dest = _op_expr(unit, ins, ops[0])
            if sets_flags:
                ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
            return ["%s = %s * %s;" % (dest, _op_expr(unit, ins, ops[1]),
                                       _op_expr(unit, ins, ops[2]))]
        if len(ops) == 2:
            dest = _op_expr(unit, ins, ops[0])
            if sets_flags:
                ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
            return ["%s = %s * %s;" % (dest, dest, _op_expr(unit, ins, ops[1]))]
    if base in ("udiv", "sdiv") and len(ops) >= 3:
        dest = _op_expr(unit, ins, ops[0])
        a = _op_expr(unit, ins, ops[1])
        b = _op_expr(unit, ins, ops[2])
        return ["%s = %s / %s; /* %s */"
                % (dest, a, ("(int32_t)" + b) if base == "sdiv" else b, base)]
    if base in ("uxtb", "uxth", "sxtb", "sxth") and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        ty = {"uxtb": "uint8_t", "uxth": "uint16_t",
              "sxtb": "int8_t", "sxth": "int16_t"}[base]
        return ["%s = (%s)%s;" % (dest, ty, _op_expr(unit, ins, ops[1]))]

    # ---- load ----
    if base in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd"):
        width = {"ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2,
                 "ldrd": 8}.get(base, 4)
        signed = base in ("ldrsb", "ldrsh")
        mem = [o for o in ops if int(getattr(o, "type", 0)) == 3]
        if mem and int(getattr(ops[0], "type", 0)) == 1:
            dest = _op_expr(unit, ins, ops[0])
            if dest == "pc":
                return _unsupported(ins, ctx, base)
            out = ["%s = %s;" % (dest, _mem_expr(unit, ins, mem[0],
                                                 width, signed))]
            post = _post_index(ins, ops, mem[0])
            if post:
                out.append("%s; /* 后索引 */" % post)
            return out
        return _unsupported(ins, ctx, base)

    # ---- store ----
    if base in ("str", "strb", "strh", "strd"):
        width = {"strb": 1, "strh": 2, "strd": 8}.get(base, 4)
        mem = [o for o in ops if int(getattr(o, "type", 0)) == 3]
        if mem and int(getattr(ops[0], "type", 0)) == 1:
            out = ["%s = %s;" % (_mem_expr(unit, ins, mem[0], width),
                                 _op_expr(unit, ins, ops[0]))]
            post = _post_index(ins, ops, mem[0])
            if post:
                out.append("%s; /* 后索引 */" % post)
            return out
        return _unsupported(ins, ctx, base)

    # ---- 位域提取 ----
    if base in ("ubfx", "sbfx") and len(ops) >= 4:
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        lsb = int(ops[2].imm or 0)
        width = int(ops[3].imm or 0)
        mask = (1 << width) - 1 if width else 0
        if base == "ubfx":
            return ["%s = (%s >> %d) & %s; /* ubfx */"
                    % (dest, src, lsb, _hex(mask))]
        return ["%s = (int32_t)((%s << %d) & %s) >> (32 - %d); /* sbfx */"
                % (dest, src, 32 - lsb - width, _hex(mask << (32 - lsb - width)),
                   32 - lsb - width)]
    # ---- 乘加 / 长乘 ----
    if base in ("mla", "mls") and len(ops) >= 4:
        dest = _op_expr(unit, ins, ops[0])
        a = _op_expr(unit, ins, ops[1])
        b = _op_expr(unit, ins, ops[2])
        acc = _op_expr(unit, ins, ops[3])
        return ["%s = %s %s %s * %s; /* %s */"
                % (dest, acc, "+" if base == "mla" else "-", a, b, base)]
    if base in ("umull", "smull", "umlal", "smlal") and len(ops) >= 4:
        lo = _op_expr(unit, ins, ops[0])
        hi = _op_expr(unit, ins, ops[1])
        a = _op_expr(unit, ins, ops[2])
        b = _op_expr(unit, ins, ops[3])
        unsigned = base.startswith("um")
        cast = "uint64_t" if unsigned else "int64_t"
        acc = "%s | ((uint64_t)%s << 32)" % (lo, hi) if base.endswith("lal") else "0"
        return ["{ uint64_t _t = (%s)(%s) * (%s)(%s) + (%s);"
                " %s = (uint32_t)_t; %s = (uint32_t)(_t >> 32); } /* %s */"
                % (cast, a, cast, b, acc, lo, hi, base)]
    # ---- 前导零 ----
    if base == "clz" and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        return ["%s = (%s) ? (31 - __builtin_clz(%s)) : 32; /* clz */"
                % (dest, src, src)]
    # ---- 带进位循环右移（rrx 的进位就是上一条 add/sub 的 C）----
    if base == "rrx" and len(ops) >= 2:
        carry = ctx.get("carry")
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        if carry is None:
            return _unsupported(ins, ctx, base)
        if sets_flags:
            ctx["flags"] = {"kind": "logic", "a": dest, "b": "0"}
            ctx["carry"] = "((uint32_t)(%s) >> 31) & 1" % src
        return ["%s = (%s >> 1) | ((uint32_t)(%s) << 31); /* rrx */"
                % (dest, src, carry)]
    # ---- 字节反转 ----
    if base == "rev" and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        return ["%s = (%s >> 24) | ((%s >> 8) & 0xFF00) | "
                "((%s << 8) & 0xFF0000) | (%s << 24); /* rev */"
                % (dest, src, src, src, src)]
    if base == "rev16" and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        return ["%s = ((%s >> 8) & 0x00FF00FF) | ((%s << 8) & 0xFF00FF00);"
                " /* rev16 */" % (dest, src, src)]
    if base == "revsh" and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        return ["%s = (int32_t)(int16_t)(((%s & 0xFF) << 8) | "
                "((%s >> 8) & 0xFF)); /* revsh */" % (dest, src, src)]
    # ---- 独占访问（监视器未建模：按普通访存处理并标注）----
    if base in ("ldrex", "ldrexb", "ldrexh") and len(ops) >= 2:
        dest = _op_expr(unit, ins, ops[0])
        mem = [o for o in ops if int(getattr(o, "type", 0)) == 3]
        if mem:
            ctx["assumed"] = ctx.get("assumed", 0) + 1
            return ["%s = %s; /* ldrex：独占监视器未建模，按普通读 */"
                    % (dest, _mem_expr(unit, ins, mem[0], 4))]
    if base in ("strex", "strexb", "strexh") and len(ops) >= 3:
        status = _op_expr(unit, ins, ops[0])
        src = _op_expr(unit, ins, ops[1])
        mem = [o for o in ops if int(getattr(o, "type", 0)) == 3]
        if mem:
            ctx["assumed"] = ctx.get("assumed", 0) + 1
            return ["%s = %s; %s = 0; "
                    "/* strex：假设独占成功（监视器未建模） */"
                    % (_mem_expr(unit, ins, mem[0], 4), src, status)]

    # ---- push / pop / ldm / stm ----
    if base == "push":
        regs = _reglist(ins)
        body = ["sp -= 4; *(uint32_t *)sp = %s; /* push */" % r
                for r in reversed(regs)]
        return body
    if base == "pop":
        regs = _reglist(ins)
        return ["%s = *(uint32_t *)sp; sp += 4; /* pop */" % r for r in regs]
    if base in ("ldm", "ldmia", "ldmdb", "stm", "stmia", "stmdb"):
        regs = _reglist(ins)
        mem = [o for o in ops if int(getattr(o, "type", 0)) == 3]
        if mem:                            # 少数形态带显式内存操作数
            addr = _addr_text(unit, ins, mem[0])
            base_reg = _reg(ins, mem[0].mem.base) if mem[0].mem.base else ""
            if not regs:
                return _unsupported(ins, ctx, base)
        else:
            # capstone 把 ``ldm.w r0, {r1, r2}`` 表示成 [r0, r1, r2]：首个寄存器是基址
            if len(regs) < 2 or int(getattr(ops[0], "type", 0)) != 1:
                return _unsupported(ins, ctx, base)
            base_reg = _reg(ins, ops[0].reg)
            addr = base_reg
            regs = regs[1:]
        load = base.startswith("ldm")
        dec = base.endswith("db")
        writeback = "!" in (ins.op_str or "")
        order = list(reversed(regs)) if dec else list(regs)
        body = []
        if load:
            lo = 4 * (len(order) - 1)
            for i, r in enumerate(order):
                off = 0 if dec else 4 * i
                if dec:
                    off = lo - 4 * i
                body.append("%s = *(uint32_t *)(%s%s);"
                            % (r, addr, (" + %d" % off) if off else ""))
        else:
            for i, r in enumerate(order):
                off = 0 if dec else 4 * i
                if dec:
                    off = 4 * (len(order) - 1) - 4 * i
                body.append("*(uint32_t *)(%s%s) = %s;"
                            % (addr, (" + %d" % off) if off else "", r))
        if writeback and base_reg:
            body.append("%s %s= %d;" % (base_reg, "+" if load else "+",
                                        4 * len(order)))
        return ["{ %s } /* %s */" % (" ".join(body), ins.mnemonic)]

    # ---- 调用 / 返回（分支由控制流层接管）----
    if base == "bl":
        ctx["carry"] = None
        tgt = _target(ins)
        name = ctx["names"].get(tgt) if tgt is not None else None
        fn = _c_name(name, "sub_%08X" % (tgt or 0)) if name else (
            "sub_%08X" % tgt if tgt is not None else "sub_unknown")
        ctx["flags"] = None
        return ["%s = %s(%s); /* bl %s */"
                % (_ret_name(ctx), fn, _call_args(ctx),
                   _hex(tgt) if tgt is not None else "?")]
    if base == "blx":
        reg = _op_expr(unit, ins, ops[0]) if ops else "?"
        ctx["flags"] = None
        ctx["carry"] = None
        return ["%s = ((uint32_t (*)(uint32_t, uint32_t, uint32_t, uint32_t))%s)"
                "(%s); /* blx */" % (_ret_name(ctx), reg, _call_args(ctx))]
    if base == "bx":
        reg = _op_expr(unit, ins, ops[0]) if ops else _abi_of(ctx).get(
            "link_name", "lr")
        ctx["flags"] = None
        if reg == _abi_of(ctx).get("link_name", "lr"):
            return ["return %s; /* bx lr（链接寄存器） */" % _ret_name(ctx)]
        return ["return %s; /* bx %s —— 尾调用/间接跳转，目标未解析 */"
                % (_ret_name(ctx), reg)]
    if base in ("cbz", "cbnz"):
        r = _op_expr(unit, ins, ops[0]) if ops else "?"
        tgt = _target(ins)
        return ["if (%s %s 0) goto L_%08X; /* %s */"
                % (r, "==" if base == "cbz" else "!=", tgt or 0, ins.mnemonic)]
    if base in ("nop", "dsb", "dmb", "isb", "sev", "wfe", "wfi"):
        return ["/* %s */" % ins.mnemonic]
    # 控制类：保留成注释（不影响数据流，所以不计数、但也不静默丢）
    if base in ("cpsid", "cpsie", "bkpt", "vmsr", "vmrs"):
        ctx["ctrl_note"] = ctx.get("ctrl_note", 0) + 1
        return ["/* %s %s —— %s（未建模，不影响数据流） */"
                % (ins.mnemonic, ins.op_str,
                   _UNSUPPORTED_HINT.get(base, "控制"))]

    return _unsupported(ins, ctx, base)


def _post_index(ins, ops, mem_op) -> str:
    """后索引 ``[rN], #imm`` → 基址更新语句（空串表示没有）。"""
    try:
        if len(ops) == 2 and int(getattr(ops[1], "type", 0)) == 2:
            base = _reg(ins, mem_op.mem.base) if mem_op.mem.base else ""
            if base and base not in ("pc", "sp"):
                v = int(ops[1].imm or 0)
                return "%s %s= %s" % (base, "+" if v >= 0 else "-", _hex(abs(v)))
    except Exception:                      # noqa: BLE001
        return ""
    return ""


# ----------------------------------------------------------------------
# 函数级：基本块 + 结构化
# ----------------------------------------------------------------------
def _is_ret(ins) -> bool:
    m = _base_mn(ins.mnemonic)
    op = (ins.op_str or "").replace(" ", "").lower()
    if m == "bx" and op.startswith("lr"):
        return True
    if m == "pop" and "pc" in op:
        return True
    if m == "ldr" and op.startswith("pc,[sp"):
        return True
    if m == "mov" and op == "pc,lr":
        return True
    return False


def _is_table_term(ins) -> bool:
    m = _base_mn(ins.mnemonic)
    if m in ("tbb", "tbh"):
        return True
    return m in ("ldr", "add", "adds") and \
        (ins.op_str or "").strip().lower().startswith("pc,")


def _is_term(ins) -> bool:
    if _is_ret(ins) or _is_table_term(ins):
        return True
    if _base_mn(ins.mnemonic) == "bx":     # bx rN = 尾调用/间接跳转，同样是块终止
        return True
    if _branch_cond(ins.mnemonic) is not None:
        return True
    return _base_mn(ins.mnemonic) in ("cbz", "cbnz")


def _blocks(insns, start: int, case_targets: dict) -> list:
    """按「跳转目标 + 跳转指令的下一条 + 跳转表 case 目标」切基本块。"""
    addr_set = {ins.address for ins in insns}
    leaders = {start}
    for i, ins in enumerate(insns):
        if not _is_term(ins):
            continue
        t = _target(ins)
        if t is not None and t in addr_set:
            leaders.add(t)
        if _branch_cond(ins.mnemonic) is not None or \
                _base_mn(ins.mnemonic) in ("cbz", "cbnz") or _is_table_term(ins):
            if i + 1 < len(insns):
                leaders.add(insns[i + 1].address)
        for t2 in (case_targets.get(ins.address) or []):
            if t2 in addr_set:
                leaders.add(t2)
    out, cur = [], None
    for ins in insns:
        if ins.address in leaders and (cur is None or ins.address != cur["start"]):
            if cur is not None:
                out.append(cur)
            cur = {"start": ins.address, "insns": []}
        if cur is None:
            cur = {"start": ins.address, "insns": []}
        cur["insns"].append(ins)
    if cur is not None:
        out.append(cur)
    for b in out:
        b["end"] = b["insns"][-1].address + b["insns"][-1].size
    return out


def _predecessors(blocks) -> dict:
    pred = {b["start"]: set() for b in blocks}
    for i, b in enumerate(blocks):
        last = b["insns"][-1]
        t = _target(last)
        if t is not None and t in pred:
            pred[t].add(b["start"])
        cond = _branch_cond(last.mnemonic)
        m = _base_mn(last.mnemonic)
        if (cond not in (None, "")) or m in ("cbz", "cbnz") or _is_table_term(last):
            if i + 1 < len(blocks):
                pred[blocks[i + 1]["start"]].add(b["start"])
    return pred


def _structure(blocks, idx, pred) -> dict:
    """两种**可证明安全**的结构化；其余一律保留 goto。

    形态1（if）：``b<cond> L_skip``，``L_skip`` 是 B 之后第 2 块，中间块与
    ``L_skip`` 都只有 B 一个前驱 ⇒ ``if (!cond) { 中间块 }``。

    形态2（if/else）：``b<cond> L_else``（B 之后第 2 块），中间块以 ``b L_end``
    结束且 ``L_end`` 是 ``L_else`` 之后第 1 块，三块前驱各自唯一
    ⇒ ``if (!cond) { 中间块 } else { L_else }``。

    条件不满足就什么都不做——宁可留 goto，也不生成连错的「漂亮」结构。
    """
    if_at = {}
    consumed = set()
    i, n = 0, len(blocks)
    while i < n:
        b = blocks[i]
        last = b["insns"][-1]
        cond = _branch_cond(last.mnemonic)
        tgt = _target(last)
        if cond not in (None, "") and tgt is not None and tgt in idx:
            body = blocks[i + 1] if i + 1 < n else None
            if body is not None and i + 2 < n and idx[tgt] == i + 2:
                skip = blocks[i + 2]
                if (pred.get(body["start"]) == {b["start"]}
                        and pred.get(skip["start"]) == {b["start"]}):
                    if_at[i] = {"mode": "if", "cond": cond,
                                "body": i + 1, "skip": i + 2}
                    consumed.add(i + 1)
                    i += 2
                    continue
            if body is not None and i + 3 < n and idx[tgt] == i + 2:
                alt = blocks[i + 2]
                end = blocks[i + 3]
                blast = body["insns"][-1]
                if (_branch_cond(blast.mnemonic) == ""
                        and _target(blast) == end["start"]
                        and pred.get(body["start"]) == {b["start"]}
                        and pred.get(alt["start"]) == {b["start"]}
                        and pred.get(end["start"]) == {body["start"],
                                                       alt["start"]}):
                    if_at[i] = {"mode": "ifelse", "cond": cond,
                                "body": i + 1, "alt": i + 2, "end": i + 3}
                    consumed.add(i + 1)
                    consumed.add(i + 2)
                    i += 3
                    continue
        i += 1
    return {"if_at": if_at, "consumed": consumed}


def _span(func, funcs, code_end) -> tuple:
    start = int(func["addr"])
    end = int(func.get("end_addr") or 0)
    if not end:
        size = int(func.get("size") or 0)
        end = start + size if size else 0
    if not end:
        nxt = [f["addr"] for f in funcs if f["addr"] > start]
        end = min(nxt) if nxt else code_end
    return start, min(max(end, start + 2), code_end)


# ----------------------------------------------------------------------
# 批次92：变量命名 / 符号性 / 结构体候选 / 内联边界 / 跨函数数据流
#   每一项都是**推断**：所以每项都带 basis；证据冲突时给 unknown，不猜。
# ----------------------------------------------------------------------
_REG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])r(\d+)(?![A-Za-z0-9_])")

_LOAD_MN = {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "ldrex",
            "ldrexb", "ldrexh", "ldrexd", "ldm", "ldmia", "ldmib", "ldmdb",
            "pop", "ldrt", "ldrbt", "ldrht"}
_STORE_MN = {"str", "strb", "strh", "strd", "strex", "strexb", "strexh",
             "strexd", "stm", "stmia", "stmib", "stmdb", "push",
             "strt", "strbt", "strht"}
_ACCESS_WIDTH = {"ldrb": 1, "ldrsb": 1, "strb": 1, "ldrbt": 1, "strbt": 1,
                 "ldrh": 2, "ldrsh": 2, "strh": 2, "ldrht": 2, "strht": 2,
                 "ldrd": 8, "strd": 8, "ldrexd": 8, "strexd": 8,
                 "ldrexb": 1, "strexb": 1, "ldrexh": 2, "strexh": 2}

# 符号性证据：**只收「消费该值的指令」，不收「猜」**。
_SIGNED_MN = {"ldrsb", "ldrsh", "sxtb", "sxth", "sxtb16", "asr", "asrs",
              "sdiv", "sdivs", "smull", "smlal", "smmul", "smulbb", "smulwb",
              "smmla", "ssat"}
_UNSIGNED_MN = {"ldrb", "ldrh", "ldrbt", "ldrht", "uxtb", "uxth",
                "uxtb16", "lsr", "lsrs", "udiv", "udivs", "umull", "umlal",
                "usat"}
_SIGNED_BR = {"bgt", "bge", "blt", "ble"}
_UNSIGNED_BR = {"bhi", "bhs", "blo", "bls"}


def _regnum(ins, reg_id) -> int:
    """capstone 寄存器 id → 寄存器号（r0..r12 / sp=13 / lr=14 / pc=15 / -1 未知）。

    非 ARM 家族的指令是 ``lift_isa`` 造的 IR，槽位由它自己给（``reg_slot``）：
    这里先问 IR，问不到再按 ARM 的名字规则解析。
    """
    hook = getattr(ins, "reg_slot", None)
    if hook is not None:
        try:
            return int(hook(reg_id))
        except Exception:                  # noqa: BLE001
            return -1
    try:
        name = reveng._norm_reg(ins.reg_name(reg_id))
    except Exception:                      # noqa: BLE001
        return -1
    name = _REG_ALIAS.get(name, name)
    if len(name) > 1 and name[0] == "r" and name[1:].isdigit():
        return int(name[1:])
    return {"sp": 13, "lr": 14, "pc": 15}.get(name, -1)


def _used_regs(insns, abi=None) -> list:
    """函数里出现过的寄存器号（按操作数扫，比 regs_access 完整——ldm/ldm.w 的
    基址寄存器在寄存器表里未必列全，早先的 locals 声明因此漏掉过 r10）。

    ``bl`` 在 capstone 里只有立即数操作数，但它隐式读 r0..r3、写 r0，
    所以调用指令要单独补上这四个（否则「只做转发」的函数一个寄存器都用不到）。
    """
    used = set()
    for ins in insns:
        if _base_mn(ins.mnemonic) in ("bl", "blx"):
            used.update(((abi or {}).get("arg_slots") or (0, 1, 2, 3))[:4])
        for op in ins.operands:
            t = int(getattr(op, "type", 0))
            if t == 1:
                used.add(_regnum(ins, op.reg))
            elif t == 3:
                if getattr(op.mem, "base", 0):
                    used.add(_regnum(ins, op.mem.base))
                if getattr(op.mem, "index", 0):
                    used.add(_regnum(ins, op.mem.index))
    return sorted(n for n in used if n >= 0)


def _accesses(insns, abi=None) -> list:
    """所有栈外访存：基址寄存器 / 偏移 / 宽度 / 读还是写。"""
    out = []
    for ins in insns:
        base = _base_mn(ins.mnemonic)
        store = base in _STORE_MN
        if base not in _LOAD_MN and not store:
            continue
        width = _ACCESS_WIDTH.get(base, 4)
        for op in ins.operands:
            if int(getattr(op, "type", 0)) != 3:
                continue
            rn = _regnum(ins, op.mem.base) if getattr(op.mem, "base", 0) else -1
            if rn < 0 or rn in ((abi or {}).get("skip_slots") or (13, 15)):
                continue
            out.append({"addr": ins.address, "reg": rn,
                        "disp": int(op.mem.disp or 0), "width": width,
                        "store": store, "mnemonic": ins.mnemonic})
    return out


def _signedness(insns) -> dict:
    """寄存器号 → {"kind": signed/unsigned/unknown, "basis": [...]}。

    证据只有两类真凭据：① 谁在读这个值（`asr`/`lsr`/`ldrsb`/`uxtb`…）；
    ② 比较之后用哪种条件下的跳（`bgt` vs `bhi`）。两向证据都在 ⇒ unknown。
    """
    votes = {}

    def say(rn, kind, why):
        if rn is None or rn < 0:
            return
        votes.setdefault(int(rn), {"signed": [], "unsigned": []})[kind].append(why)

    last_cmp = []
    for ins in insns:
        base = _base_mn(ins.mnemonic)
        ops = list(ins.operands)
        regs = [_regnum(ins, o.reg) for o in ops if int(getattr(o, "type", 0)) == 1]
        dest = regs[0] if regs else -1
        if base in _SIGNED_MN:
            say(dest, "signed", base)
        elif base in _UNSIGNED_MN:
            say(dest, "unsigned", base)
        elif base == "cmp":
            last_cmp = [n for n in regs if 0 <= n < 13]
        elif base in _SIGNED_BR or base in _UNSIGNED_BR:
            kind = "signed" if base in _SIGNED_BR else "unsigned"
            for n in last_cmp:
                say(n, kind, "由 %s 判定" % base)
    out = {}
    for rn, v in votes.items():
        s, u = v["signed"], v["unsigned"]
        if s and not u:
            out["r%d" % rn] = {"kind": "signed", "basis": s}
        elif u and not s:
            out["r%d" % rn] = {"kind": "unsigned", "basis": u}
        else:
            out["r%d" % rn] = {
                "kind": "unknown",
                "basis": ["证据冲突，不猜：有符号(%s) / 无符号(%s)"
                          % (", ".join(s), ", ".join(u))]}
    return out


def _struct_candidates(acc) -> list:
    """同一个基址寄存器上多个非零偏移 ⇒ 疑似结构体；等步长且步长==访问宽度 ⇒ 疑似数组。

    只给「候选」与字段表（偏移/宽度/读写次数），不发明成员名。
    """
    by = {}
    for a in acc:
        by.setdefault(a["reg"], []).append(a)
    out = []
    for rn, items in sorted(by.items()):
        disps = sorted({it["disp"] for it in items})
        nonzero = [d for d in disps if d != 0]
        if len(nonzero) < 2:
            continue
        fields = {}
        for it in items:
            f = fields.setdefault(it["disp"], {"offset": it["disp"], "reads": 0,
                                               "writes": 0, "widths": set()})
            f["writes" if it["store"] else "reads"] += 1
            f["widths"].add(it["width"])
        for f in fields.values():
            f["width"] = max(f["widths"])
            f.pop("widths", None)
        steps = [b - a for a, b in zip(nonzero, nonzero[1:])]
        widths = {fields[d]["width"] for d in nonzero}
        kind, stride = "struct_candidate", None
        if len(set(steps)) == 1 and steps[0] in widths:
            kind, stride = "array_candidate", steps[0]
        out.append({"base_reg": "r%d" % rn, "kind": kind, "stride": stride,
                    "n_fields": len(fields),
                    "fields": [fields[d] for d in sorted(fields)],
                    "basis": "同一基址寄存器上 %d 个不同偏移（%s）"
                             % (len(disps),
                                ", ".join(_hex(d) for d in disps[:8]))})
    return out


def _loop_counters(insns) -> dict:
    """回边范围内「自增自己 + 被 cmp 比较」的寄存器 → 计数器的证据文本。"""
    at = {ins.address: k for k, ins in enumerate(insns)}
    out = {}
    for k, ins in enumerate(insns):
        base = _base_mn(ins.mnemonic)
        if _branch_cond(ins.mnemonic) is None and base not in ("cbz", "cbnz"):
            continue
        tgt = _target(ins)
        if tgt is None or tgt > ins.address:
            continue
        j = at.get(tgt)
        if j is None:
            continue
        for m in range(j, k):
            x = insns[m]
            b2 = _base_mn(x.mnemonic)
            ops = list(x.operands)
            if b2 in ("add", "adds", "sub", "subs") and len(ops) >= 2:
                if int(getattr(ops[0], "type", 0)) != 1:
                    continue
                d = _regnum(x, ops[0].reg)
                src = d
                if len(ops) >= 3 and int(getattr(ops[1], "type", 0)) == 1:
                    src = _regnum(x, ops[1].reg)
                elif len(ops) == 2 and int(getattr(ops[1], "type", 0)) == 1:
                    src = _regnum(x, ops[1].reg)
                if d >= 0 and d == src:
                    out.setdefault(d, "回边 0x%08X..0x%08X 里自增/自减自己"
                                      % (tgt, ins.address))
            elif b2 == "cmp" and ops and int(getattr(ops[0], "type", 0)) == 1:
                d = _regnum(x, ops[0].reg)
                if d in out:
                    out[d] += "，并在循环内被 cmp 判定"
    return out


def _call_sites(unit, insns) -> list:
    """每个 bl 点：目标 + 四个实参的来源（局部 copy-propagation，32 条指令窗口）。"""
    out = []
    for k, ins in enumerate(insns):
        base = _base_mn(ins.mnemonic)
        if base not in ("bl", "blx"):
            continue
        tgt = _target(ins) if base == "bl" else None
        out.append({"addr": ins.address, "callee_addr": tgt,
                    "callee": ("sub_%08X" % tgt) if tgt is not None else None,
                    "args": [_arg_source(unit, insns, k, n) for n in range(4)]})
    return out


def _arg_source(unit, insns, k, rn) -> dict:
    """从 bl 往前找最近一次写 rN 的指令 → 来源描述。找不到就是入口值。"""
    for j in range(k - 1, max(-1, k - 32), -1):
        ins = insns[j]
        base = _base_mn(ins.mnemonic)
        if base in ("bl", "blx"):
            if rn == 0:                    # 只有 r0 被调用改写，r1..r3 按 AAPCS 保留
                tgt = _target(ins) if base == "bl" else None
                return {"kind": "return",
                        "of": ("sub_%08X" % tgt) if tgt is not None else "blx",
                        "addr_hex": "0x%08X" % ins.address}
            continue
        try:
            _rd, wr = ins.regs_access()    # capstone 返回 (读到的, 写到的)
        except Exception:                  # noqa: BLE001
            return {"kind": "unknown"}
        if rn not in {_regnum(ins, r) for r in wr}:
            continue
        ops = list(ins.operands)
        if base in ("mov", "movs", "movw", "movt") and len(ops) >= 2:
            t1 = int(getattr(ops[1], "type", 0))
            if base in ("mov", "movs") and t1 == 1:
                return {"kind": "copy", "of": "r%d" % _regnum(ins, ops[1].reg)}
            if t1 == 2:
                return {"kind": "const", "value": _hex(ops[1].imm)}
        if base in _LOAD_MN:
            mem = next((o for o in ops if int(getattr(o, "type", 0)) == 3), None)
            if mem is not None:
                return {"kind": "mem", "expr": _addr_text(unit, ins, mem)}
        if base in ("add", "adds", "sub", "subs") and len(ops) >= 3:
            return {"kind": "calc",
                    "expr": "%s %s %s" % (_op_expr(unit, ins, ops[1]),
                                          "+" if base.startswith("add") else "-",
                                          _op_expr(unit, ins, ops[2]))}
        return {"kind": "computed", "by": ins.mnemonic}
    return {"kind": "entry"}


def _arg_text(a) -> str:
    k = a.get("kind")
    if k == "const":
        return "常量 %s" % a.get("value")
    if k == "copy":
        return "复制 %s" % a.get("of")
    if k == "mem":
        return "内存 %s" % a.get("expr")
    if k == "calc":
        return "算式 %s" % a.get("expr")
    if k == "return":
        return "%s 的返回值" % a.get("of")
    if k == "computed":
        return "%s 的结果" % a.get("by")
    if k == "entry":
        return "入口值"
    return "未追踪"


def _insn_fp(ins) -> tuple:
    """位置无关的指令指纹：分支按相对位移比，寄存器按编号比。"""
    base = _base_mn(ins.mnemonic)
    ops = []
    for o in ins.operands:
        t = int(getattr(o, "type", 0))
        if t == 1:
            sh = getattr(o, "shift", None)
            ops.append(("r", _regnum(ins, o.reg),
                        int(getattr(sh, "type", 0) or 0),
                        int(getattr(sh, "value", 0) or 0)))
        elif t == 2:
            v = int(o.imm or 0)
            if (_branch_cond(ins.mnemonic) is not None
                    or _base_mn(ins.mnemonic) in ("bl", "blx")):
                v = v - ins.address        # 分支/调用按相对位移比，位置无关
            ops.append(("i", v))
        elif t == 3:
            ops.append(("m",
                        _regnum(ins, o.mem.base) if o.mem.base else -1,
                        _regnum(ins, o.mem.index) if o.mem.index else -1,
                        int(o.mem.disp or 0)))
        else:
            ops.append(("?",))
    return (base,) + tuple(ops)


def _inline_candidates(insns, funcs, start, end) -> list:
    """内联**只能标边界与来源**：内联进来就是一串普通指令，没有调用点可还原。

    两种证据：① 同函数内 4 条指令的窗口逐条等价（含分支/调用，排除纯模板重排）；
    ② 另一个函数的整段区间落在本函数范围内。
    """
    out = []
    win = 6                              # 4 条指令的窗口太容易巧合（重复的模板代码）
    if len(insns) >= 2 * win:
        seen = {}
        for i in range(len(insns) - win + 1):
            frag = insns[i:i + win]
            # 内联函数体通常**含调用**；纯算术/纯访存的重复片段更可能是同一模板代码
            if not any(_base_mn(x.mnemonic) in ("bl", "blx") for x in frag):
                continue
            seen.setdefault(tuple(_insn_fp(x) for x in frag), []).append(insns[i].address)
        for fp, addrs in seen.items():
            if len(addrs) < 2:
                continue
            gaps = [b - a for a, b in zip(addrs, addrs[1:])]
            if min(gaps) < win * 2:        # 窗口互相重叠，是同一段代码不是两份
                continue
            out.append({"kind": "dup_window", "n_insns": win,
                        "addrs_hex": ["0x%08X" % a for a in addrs[:4]],
                        "basis": "同函数内 %d 段指令逐条等价（寄存器/立即数/位移一致）"
                                 "⇒ 疑似内联或宏展开" % len(addrs)})
    for f in funcs or []:
        try:
            fs = int(f.get("addr") or 0)
            fe = int(f.get("end_addr") or 0)
        except (TypeError, ValueError):
            continue
        if not fs or not fe or (fs, fe) == (start, end):
            continue
        if start <= fs and fe <= end and (fe - fs) >= 8:
            out.append({"kind": "contains_function",
                        "name": f.get("name") or ("sub_%08X" % fs),
                        "start_hex": "0x%08X" % fs, "end_hex": "0x%08X" % fe,
                        "basis": "%s 的整段区间被本函数覆盖（内联或共享尾段；"
                                 "两种情况都没有调用点可还原）"
                                 % (f.get("name") or "").strip()})
    return out[:8]


def _name_registers(used, acc, signs, counters, abi=None) -> tuple:
    """寄存器 → 名字（带 basis）。命名阶梯：参数 a0..a3 / 计数器 i,j / 基址 p0,p1 / v<N>。

    ``abi["naming"] == "abi"`` 的家族（RISC-V / MIPS）**不做阶梯**：它们的寄存器
    本来就有约定俗成的 ABI 名（a0..a7、s0..s11、ra、sp），改成 i/j/p0 反而是
    把有信息量的名字换成猜的。basis 里写明来源是 ABI。
    """
    if (abi or {}).get("naming") == "abi":
        names = abi.get("slot_names") or {}
        renames, vars_ = {}, []
        # 前四个参数寄存器**一律**有 ABI 名（哪怕没用），否则签名会出现
        # a0, a1, r12, r13 这种混排（与 ARM 那条「无条件映射」同源）
        for n in list((abi.get("arg_slots") or [])[:4]) + [abi.get("stack_slot"),
                                                           abi.get("link_slot")]:
            if names.get(n):
                renames["r%d" % n] = names[n]
        for n in used:
            nm = names.get(n) or ("r%d" % n)
            renames["r%d" % n] = nm
            sg = signs.get("r%d" % n) or {"kind": "unknown", "basis": []}
            vars_.append({
                "reg": "r%d" % n, "name": nm,
                "type": "int32_t" if sg["kind"] == "signed" else "uint32_t",
                "signedness": sg["kind"],
                "signed_basis": sg.get("basis") or [],
                "basis": "%s 的 ABI 寄存器名（%d 号）；非 ARM 家族不做命名阶梯"
                         % (abi.get("abi") or abi.get("family"), n)})
        return renames, vars_
    ptr = {}
    for a in acc:
        if a["disp"]:
            ptr.setdefault(a["reg"], set()).add(a["disp"])
    renames, picked, pi, ci = {}, [], 0, 0
    for n in range(4):                     # 四个参数寄存器一律有 ABI 名字
        renames["r%d" % n] = "a%d" % n     # （即使函数体没用到，签名里也要一致）
        if n in used:
            picked.append((n, "a%d" % n,
                           "AAPCS：入口第 %d 个参数（调用方填，本函数没写它就是入口值）"
                           % (n + 1)))
    for n in used:
        if n < 4 or n >= 13:
            continue
        if n in counters:
            nm = "i" if ci == 0 else ("j" if ci == 1 else "i%d" % ci)
            ci += 1
            basis = counters[n]
        elif len(ptr.get(n) or ()) >= 2:
            nm = "p%d" % pi
            pi += 1
            basis = "疑似结构体/数组基址：%d 个不同偏移的访存（%s）" % (
                len(ptr[n]), ", ".join(_hex(d) for d in sorted(ptr[n])[:6]))
        else:
            nm = "v%d" % n
            basis = "命名证据不足，保留寄存器号（v=本函数内的临时量）"
        renames["r%d" % n] = nm
        picked.append((n, nm, basis))
    vars_ = []
    for n, nm, basis in sorted(picked):
        sg = signs.get("r%d" % n) or {"kind": "unknown", "basis": []}
        vars_.append({"reg": "r%d" % n, "name": nm,
                      "type": "int32_t" if sg["kind"] == "signed" else "uint32_t",
                      "signedness": sg["kind"],
                      "signed_basis": sg.get("basis") or [],
                      "basis": basis})
    return renames, vars_


def _apply_renames(code: str, renames: dict) -> str:
    """把文本里的 rN 换成新名字。

    两条边界：① 词边界替换（``L_0800…`` / ``sub_0800…`` 不会被误伤）；
    ② **注释里不改**——注释是汇编注记，保持 rN 才能和反汇编对照。
    """
    if not renames:
        return code
    table = {int(k[1:]): v for k, v in renames.items()
             if k.startswith("r") and k[1:].isdigit()}

    def one(text):
        return _REG_TOKEN_RE.sub(lambda m: table.get(int(m.group(1)), m.group(0)), text)

    out, pos = [], 0
    for m in re.finditer(r"/\*.*?\*/", code, re.S):
        out.append(one(code[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(one(code[pos:]))
    return "".join(out)


def _analyse(unit, insns, *, funcs=None, start: int = 0, end: int = 0,
             abi=None) -> dict:
    """一次性算齐命名/类型/结构体/内联/调用点数据流（都带 basis）。"""
    used = _used_regs(insns, abi)
    acc = _accesses(insns, abi)
    signs = _signedness(insns)
    counters = _loop_counters(insns)
    renames, vars_ = _name_registers(used, acc, signs, counters, abi)
    calls = _call_sites(unit, insns)
    for cs in calls:                       # 实参来源里的寄存器名跟着改名
        for a in cs["args"]:
            of = a.get("of") or ""
            if of.startswith("r") and of[1:].isdigit():
                a["of_reg"] = of
                a["of"] = renames.get(of, of)
    structs = _struct_candidates(acc)
    for st in structs:
        st["base"] = renames.get(st["base_reg"], st["base_reg"])
    return {"used": used, "renames": renames, "vars": vars_, "signs": signs,
            "structs": structs, "calls": calls,
            "inline": _inline_candidates(insns, funcs, start, end)}


def decompile_function(unit, func, *, funcs=None, names=None, switches=None,
                       max_insns: int = 4000, rename: bool = True) -> dict:
    """单个函数 → 伪 C 文本 + 统计。失败时返回 ``{"ok": False, "error": ...}``。

    ``rename=False`` 时不改名、不按推断类型声明（输出与批次91 逐字节一致，
    用于对照与回归）。
    """
    from . import lift_isa                 # noqa: PLC0415
    fam = (unit.arch or {}).get("family") or "unknown"
    if fam == "unknown":
        return {"ok": False,
                "error": "架构未判定（裸 bin / S-record 里没有指令集信息）："
                         "伪 C 必须知道指令集才能翻译，工具不猜",
                "hint": "显式给 arch=（arm / riscv / mips）+ 必要的 bits/endian/thumb/entry，"
                        "再请求 fmt=\"c\"；也可以先用 recover_probe 看能不能判出来"}
    if not lift_isa.liftable(fam):
        return {"ok": False, "error": lift_isa.refusal(fam),
                "hint": "用 recover_disasm（不加 fmt=\"c\"）看该架构的汇编；"
                        "反汇编后端支持 arm / arm64 / riscv / x86 / x86_64 / mips / "
                        "ppc / m68k / sparc / mos65xx"}
    abi = lift_isa.descriptor(fam)
    funcs = funcs or [func]
    code_end = max((b for _, b in unit.code_ranges), default=None)
    if code_end is None:
        return {"ok": False, "error": "没有可执行区间"}
    start, end = _span(func, funcs, code_end)
    sw_err = ""
    insns, skipped, why, meta = _decode(unit, start, end, max_insns=max_insns)
    if insns is None:
        out = {"ok": False, "error": why}
        if (meta or {}).get("mismatches"):
            out["mismatches"] = meta["mismatches"]
            out["source"] = meta.get("source")
        return out
    if not insns:
        return {"ok": False, "error": "0x%08X 处没有指令" % start}
    names = names or {}
    if switches is None:
        recs = {i.address: {"addr": i.address, "size": i.size,
                            "mnemonic": i.mnemonic, "op_str": i.op_str}
                for i in insns}
        try:
            switches = reveng.switch_tables(
                unit, recs, [{"addr": start, "end_addr": end,
                              "name": func.get("name") or ""}])["switches"]
        except Exception as e:             # noqa: BLE001
            switches = []
            sw_err = "%s: %s" % (type(e).__name__, e)
    # 跳转表的字节和代码挨在一起（tbb/tbh 表紧跟指令），按指令解码会变成一段
    # 看似合法的垃圾指令；Ghidra 也把这块标成数据。这里按表范围剥掉。
    sw_by_addr = {int(s["addr"]): s for s in switches if s.get("addr") is not None}
    case_targets = {}
    for a, s in sw_by_addr.items():
        case_targets[a] = []
        for h in (s.get("targets_hex") or []):
            try:
                case_targets[a].append(int(h, 16))
            except ValueError:
                continue
    all_cases = {t for v in case_targets.values() for t in v}

    # 剥表时不能误删 case 目标（表范围若被推断得偏大，目标会是真代码）
    tbl_ranges = _table_ranges(switches)
    dropped_tbl = []
    if tbl_ranges:
        keep = []
        for i in insns:
            inside = any(a <= i.address and i.address + i.size <= b
                         for a, b, _d in tbl_ranges)
            if inside and i.address not in all_cases:
                dropped_tbl.append(i.address)
                continue
            keep.append(i)
        insns = keep
        if not insns:
            return {"ok": False, "error": "剥掉跳转表数据后函数范围内没有指令"}

    ctx = {"unit": unit, "names": names, "unsupported": [], "flags": None,
           "carry": None, "switches": sw_by_addr, "it": [],
           "flag_unresolved": 0, "switch_unresolved": 0, "ctrl_note": 0,
           "discard": 0,
           "abi": abi, "fam": fam,
           "delay_hoisted": (meta or {}).get("delay_slots_hoisted", 0)}

    blocks = _blocks(insns, start, case_targets)
    idx = {b["start"]: i for i, b in enumerate(blocks)}
    pred = _predecessors(blocks)
    struct = _structure(blocks, idx, pred)
    if_at = struct["if_at"]
    loop_targets = set()
    for b in blocks:
        last = b["insns"][-1]
        if _is_term(last):
            t = _target(last)
            if t is not None:
                loop_targets.add(t)

    # 批次92：命名/符号性/结构体候选/内联边界/调用点数据流（全部带 basis）
    ana = _analyse(unit, insns, funcs=funcs, start=start, end=end, abi=abi)
    renames = ana["renames"] if rename else {}
    used = set(ana["used"])                # 按操作数扫：ldm/ldm.w 的基址寄存器也算
    if abi.get("naming") == "arm":
        locals_ = ["r%d" % n for n in range(4, 13) if n in used]
        if 14 in used:
            locals_.append("lr")
    else:
        # 非 ARM：用到的都声明（槽位自己带 ABI 名），参数/栈/链接寄存器单独处理
        # 只有前 4 个参数槽能进签名；RISC-V 的 a4..a7 之类的槽位仍要当局部变量声明
        _skip = set((abi.get("arg_slots") or ())[:4]) | {abi.get("stack_slot"),
                                                        abi.get("link_slot")}
        locals_ = ["r%d" % n for n in used if n not in _skip]
        if abi.get("link_slot") in used:
            locals_.append("r%d" % abi["link_slot"])
    locals_.append("r%d" % (abi.get("stack_slot") if abi.get("naming") != "arm"
                            else 13))

    name0 = func.get("name") or ""
    fn_name = _c_name(name0, "") if name0 else ""
    if not fn_name:
        fn_name = "sub_%08X" % start

    var_by_reg = {v["reg"]: v for v in ana["vars"]}

    def _vname(reg):
        return renames.get(reg, reg)

    params = []
    for _n in (abi.get("arg_slots") or [0, 1, 2, 3])[:4]:
        _v = var_by_reg.get("r%d" % _n) or {}
        params.append("%s %s" % (_v.get("type") or "uint32_t", _vname("r%d" % _n)))
    decls = {}
    for _reg in locals_:
        _v = var_by_reg.get(_reg) or {}
        decls.setdefault(_v.get("type") or "uint32_t", []).append(_vname(_reg))
    ana_lines = []
    for st in ana["structs"][:3]:
        ana_lines.append(" * %s 上 %d 个字段（%s）：%s" % (
            st["base"], st["n_fields"], st["kind"],
            ", ".join("[%s w%d 读%d 写%d]" % (_hex(f["offset"]), f["width"],
                                              f["reads"], f["writes"])
                      for f in st["fields"][:8])))
    for c in ana["inline"][:2]:
        ana_lines.append(" * 内联候选：%s" % c.get("basis"))

    lines = [
        "/* %s —— 0x%08X..0x%08X，%d 条指令 / %d 个基本块%s" % (
            fn_name, start, end, len(insns), len(blocks),
            "" if not skipped else " / %d 处坏字节已跳过" % skipped),
        " * 寄存器级伪 C（lifting）：表达式与控制流保真；类型/结构体/变量名是**推断**的，"
        "不是原始源码。",
        " * bl 按 %s 传前四个参数寄存器（%s，返回值落 %s）；栈访问用 %s 偏移表达式。 */"
        % (abi.get("abi") or "AAPCS", _call_args(ctx), _ret_name(ctx),
           abi.get("stack_name") or "sp"),
    ] + ana_lines + [
        "uint32_t %s(%s)" % (fn_name, ", ".join(params)),
        "{",
    ]
    for _ty, _names in decls.items():
        lines.append("    %s %s;" % (_ty, ", ".join(_names)))
    for cs in ana["calls"][:8]:
        _parts = ["a%d=%s" % (i, _arg_text(a))
                  for i, a in enumerate(cs["args"][:4]) if a.get("kind") != "entry"]
        lines.append("    /* 调用 0x%08X → %s(%s) */" % (
            cs["addr"], cs["callee"] or "间接",
            ", ".join(_parts) if _parts else "四个实参都是入口值"))
    lines.append("")
    state = {"ret": False}

    def emit_body_lines(b, ind):
        for ins in b["insns"]:
            if ins is b["insns"][-1] and _is_term(ins):
                continue
            for stmt in _lift(unit, ins, ctx):
                lines.append(ind + stmt)

    def emit_block(i, ind, cond_open=None):
        b = blocks[i]
        if b["start"] != start or b["start"] in loop_targets:
            lines.append("L_%08X:" % b["start"])
        emit_body_lines(b, ind)
        last = b["insns"][-1]
        if not _is_term(last):
            return
        if cond_open is not None:
            expr = _cond_text(_OPPOSITE.get(cond_open, cond_open), ctx.get("flags"))
            if expr.startswith("flag_"):
                ctx["flag_unresolved"] = ctx.get("flag_unresolved", 0) + 1
            lines.append(ind + "if (%s) {" % (expr or "1"))
            return
        tl, _had = _terminator_lines(unit, last, ctx, blocks)
        for stmt in tl:
            lines.append(ind + stmt)
        if any(s.startswith("return ") for s in tl):
            state["ret"] = True

    def emit_inner(i, ind, drop_jump_to=None):
        b = blocks[i]
        emit_body_lines(b, ind)
        last = b["insns"][-1]
        if not _is_term(last):
            return
        if _is_ret(last):
            lines.append(ind + "return %s; /* %s %s */"
                         % (_ret_name(ctx), last.mnemonic, last.op_str))
            state["ret"] = True
            return
        if (drop_jump_to is not None and _branch_cond(last.mnemonic) == ""
                and _target(last) == drop_jump_to):
            return
        tl, _had = _terminator_lines(unit, last, ctx, blocks)
        for stmt in tl:
            lines.append(ind + stmt)

    i, n = 0, len(blocks)
    while i < n:
        st = if_at.get(i)
        if st and st["mode"] == "if":
            emit_block(i, "    ", cond_open=st["cond"])
            emit_inner(st["body"], "        ", drop_jump_to=st["skip"])
            lines.append("    }")
            i += 2
            continue
        if st and st["mode"] == "ifelse":
            emit_block(i, "    ", cond_open=st["cond"])
            emit_inner(st["body"], "        ", drop_jump_to=st["end"])
            lines.append("    } else {")
            emit_inner(st["alt"], "        ")
            lines.append("    }")
            i += 3
            continue
        emit_block(i, "    ")
        i += 1

    if not state["ret"]:
        lines.append("    return %s; /* 末尾无显式返回：沿用返回寄存器 */"
                     % _ret_name(ctx))

    # 紧接在其目标标签之前的 goto / if-goto 是空跳转，删掉（语义不变、可读性大幅提升）
    cleaned = []
    for k, ln in enumerate(lines):
        st = ln.strip()
        nxt = ""
        for ln2 in lines[k + 1:]:
            if ln2.strip():
                nxt = ln2.strip()
                break
        m = re.match(r"^goto L_([0-9A-F]{8});", st)
        if m and nxt.startswith("L_%s:" % m.group(1)):
            continue
        m = re.match(r"^if \(.*\) goto L_([0-9A-F]{8});", st)
        if m and nxt.startswith("L_%s:" % m.group(1)):
            continue
        cleaned.append(ln)
    lines = cleaned

    # 没被展开的目标（函数范围外/共享尾段）补空标签，保证 goto 有落点
    labels, gotos = set(), set()
    for ln in lines:
        s = ln.strip()
        m = _GOTO_RE.match(s)
        if m:
            labels.add(m.group(1))
        for g in re.findall(r"goto L_([0-9A-F]{8})", s):
            gotos.add(g)
    missing = sorted(gotos - labels)
    if missing:
        lines.append("")
        lines.append("    /* 以下目标不在本函数范围内（共享尾段/内联/表项），未展开 */")
        for a in missing:
            lines.append("L_%s: ;" % a)
    lines.append("}")
    code = "\n".join(lines) + "\n"
    if renames:
        code = _apply_renames(code, renames)

    uns = sorted(set(ctx["unsupported"]))
    notes = []
    if uns:
        notes.append("有 %d 类指令未提升，源码里以 /* 未支持 */ 标注：%s"
                     % (len(uns), ", ".join(uns)))
    if ctx["flag_unresolved"]:
        notes.append("%d 处条件依赖的 flags 找不到生产者，输出为 flag_<cond>（未猜）"
                     % ctx["flag_unresolved"])
    if ctx["switch_unresolved"]:
        notes.append("%d 处跳转表未能恢复（表长无编码/目标越界），分支未展开"
                     % ctx["switch_unresolved"])
    if sw_err:
        notes.append("跳转表恢复抛异常（已按未恢复处理）：%s" % sw_err)
    if dropped_tbl:
        notes.append("跳转表数据按数据剔除：%s（%d 条伪指令不再出现在源码里）"
                     % (", ".join("0x%08X" % a for a, _b, _d in tbl_ranges),
                        len(dropped_tbl)))
    if tbl_ranges and not insns:
        notes.append("剥掉跳转表后范围内没有指令，疑似函数体只有一次间接跳转")
    if ctx.get("ctrl_note"):
        if fam == "arm":
            notes.append("%d 处控制/状态指令（bkpt/cpsid/cpsie/vmsr/vmrs）只保留为注释：未建模"
                         % ctx["ctrl_note"])
        else:
            notes.append("%d 处控制/状态指令（csr/syscall/eret/fence 之类）只保留为注释：未建模"
                         % ctx["ctrl_note"])
    if ctx.get("discard"):
        notes.append("%d 处写零寄存器（x0 / $zero 恒为 0）的结果丢弃：只保留为注释"
                     % ctx["discard"])
    if ctx.get("assumed"):
        notes.append("%d 处独占访问（ldrex/strex）按普通访存 + 假设成功输出"
                     "（独占监视器未建模）" % ctx["assumed"])
    if fam != "arm":
        notes.append("%s 家族：指令已按等价语义翻译成统一 IR；寄存器用 ABI 名（%s），"
                     "调用约定按 %s，不做命名阶梯"
                     % (fam, ", ".join((abi.get("arg_names") or [])[:4]),
                        abi.get("abi")))
    if ctx.get("delay_hoisted"):
        notes.append("%d 处分支延迟槽已提到分支之前（MIPS 延迟槽语义）"
                     % ctx["delay_hoisted"])
    if skipped:
        notes.append("%d 处坏字节已跳过，对应指令不在源码里" % skipped)
    if missing:
        notes.append("%d 个跳转目标落在函数范围外，只补了空标签（未展开代码）"
                     % len(missing))
    return {"ok": True, "name": fn_name, "start": start, "end": end,
            "addr_hex": "0x%08X" % start, "code": code,
            "n_insns": len(insns), "n_blocks": len(blocks),
            "n_structured": len(if_at),
            "n_unsupported": len(ctx["unsupported"]),
            "unsupported": uns, "n_skipped": skipped,
            "n_discard": ctx.get("discard", 0),
            "n_flag_unresolved": ctx["flag_unresolved"],
            "n_switch_unresolved": ctx["switch_unresolved"],
            "n_outside_targets": len(missing),
            "vars": ana["vars"],
            "types": {"by_reg": {v["reg"]: v["type"] for v in ana["vars"]},
                      "n_signed": sum(1 for v in ana["vars"]
                                      if v["signedness"] == "signed"),
                      "n_unknown": sum(1 for v in ana["vars"]
                                       if v["signedness"] == "unknown"),
                      "note": "类型由访问宽度与消费指令推断；镜像里没有调试信息，"
                              "int vs unsigned 只在有消费指令作证时才区分，冲突时 unknown"},
            "structs": ana["structs"],
            "inline": ana["inline"],
            "flow": {"n_calls": len(ana["calls"]), "calls": ana["calls"],
                     "note": "实参来源按「最近一次写该寄存器」推断（32 条指令窗口）；"
                             "不做跨函数的全局传播"},
            "renamed": bool(renames),
            "notes": notes}


def _terminator_lines(unit, ins, ctx, blocks) -> tuple:
    """块末尾指令 → (行列表, 是否有显式控制转移)。"""
    m = _base_mn(ins.mnemonic)
    if _is_ret(ins):
        return (["return %s; /* %s %s */" % (_ret_name(ctx), ins.mnemonic,
                                             ins.op_str)], True)
    if _is_table_term(ins):
        return (_switch_lines(unit, ins, ctx), True)
    if m == "bx":
        reg = _op_expr(unit, ins, list(ins.operands)[0]) if ins.operands \
            else _abi_of(ctx).get("link_name", "lr")
        return (["return %s; /* bx %s */" % (_ret_name(ctx), reg)], True)
    if m in ("cbz", "cbnz"):
        r = _op_expr(unit, ins, list(ins.operands)[0]) if ins.operands else "?"
        return (["if (%s %s 0) goto L_%08X;" % (r, "==" if m == "cbz" else "!=",
                                                _target(ins) or 0)], True)
    cond = _branch_cond(ins.mnemonic)
    if cond is not None:
        tgt = _target(ins)
        if cond == "":
            if tgt is None:
                return (["goto /* 目标未知 */;"], True)
            tail = ""
            for b in blocks:
                if b["start"] == tgt and tgt < ins.address:
                    tail = " /* 回边（循环） */"
                    break
            return (["goto L_%08X;%s" % (tgt, tail)], True)
        tgt = tgt or 0
        c = _cond_text(cond, ctx.get("flags"))
        if c.startswith("flag_"):
            ctx["flag_unresolved"] = ctx.get("flag_unresolved", 0) + 1
        ctx["flags"] = None
        back = " /* 回边（循环） */" if tgt < ins.address else ""
        return (["if (%s) goto L_%08X;%s" % (c, tgt, back)], True)
    return ([], False)


def _switch_lines(unit, ins, ctx) -> list:
    sw = (ctx.get("switches") or {}).get(ins.address)
    if not sw:
        ctx["switch_unresolved"] = ctx.get("switch_unresolved", 0) + 1
        return ["/* 跳转表未恢复: %s %s ⇒ 后续分支不明 */"
                % (ins.mnemonic, ins.op_str)]
    targets = []
    for h in sw.get("targets_hex") or []:
        try:
            targets.append(int(h, 16))
        except ValueError:
            continue
    if not targets:
        ctx["switch_unresolved"] = ctx.get("switch_unresolved", 0) + 1
        return ["/* 跳转表未恢复: %s */" % ins.mnemonic]
    out = ["switch (%s) { /* %s，%d 项，依据：%s */"
           % (_switch_index(ins), sw.get("kind"), len(targets),
              sw.get("length_basis") or "未知")]
    for i, t in enumerate(targets):
        out.append("case %d: goto L_%08X; /* = 0x%08X */" % (i, t, t))
    out.append("default: break;")
    out.append("}")
    ctx["flags"] = None
    return out


def _switch_index(ins) -> str:
    """``tbb [pc, r0]`` → 索引寄存器；``ldr pc, [pc, r0, lsl #2]`` 同理。"""
    for op in ins.operands:
        if int(getattr(op, "type", 0)) == 3 and op.mem.index:
            return _reg(ins, op.mem.index)
    return "?"


# ----------------------------------------------------------------------
# 批量 / 文件
# ----------------------------------------------------------------------
def _ipa(items) -> dict:
    """跨函数数据流的一层合成：调用边 + 「A 的返回值 → B 的实参」链。

    只做一层（不再往下传播），因为实参来源本身已经是局部推断。
    """
    edges = {}
    for it in items:
        for cs in (it.get("flow") or {}).get("calls") or []:
            key = (it["name"], cs.get("callee") or "间接")
            e = edges.setdefault(key, {"caller": key[0], "callee": key[1],
                                       "n_calls": 0, "addrs_hex": []})
            e["n_calls"] += 1
            if len(e["addrs_hex"]) < 8:
                e["addrs_hex"].append("0x%08X" % cs["addr"])
    by = {it["name"]: it for it in items}
    chains = []
    for it in items:
        for cs in (it.get("flow") or {}).get("calls") or []:
            for i, a in enumerate(cs.get("args") or []):
                if a.get("kind") != "return":
                    continue
                src = by.get(a.get("of") or "")
                dst = by.get(cs.get("callee") or "")
                if src is None or dst is None:
                    continue
                chains.append({"from": src["name"], "via": it["name"],
                               "to": dst["name"], "param": "a%d" % i,
                               "text": "%s 的返回值经 %s 传给 %s 的 a%d"
                                       % (src["name"], it["name"], dst["name"], i)})
                if len(chains) >= 12:
                    break
            if len(chains) >= 12:
                break
    return {"n_edges": len(edges), "edges": list(edges.values()),
            "chains": chains,
            "note": "只做一层组合（被调函数返回值 → 另一被调函数的实参）；"
                    "不做更深传播，也不跟踪全局变量"}


def decompile(unit, funcs, *, max_funcs: int = 60, max_insns: int = 4000,
              names=None, switches=None, rename: bool = True) -> dict:
    """按函数清单批量出伪 C（默认最多 60 个，避免一次吐几 MB）。"""
    names = names or {}
    code_end = max((b for _, b in unit.code_ranges), default=None)
    if code_end is None:
        return {"ok": False, "error": "没有可执行区间"}
    funcs = sorted(funcs, key=lambda f: int(f["addr"]))
    items, failed = [], []
    for f in funcs[:max_funcs]:
        r = decompile_function(unit, f, funcs=funcs, names=names,
                               switches=switches, max_insns=max_insns,
                               rename=rename)
        if not r.get("ok"):
            failed.append({"addr_hex": "0x%08X" % int(f.get("addr") or 0),
                           "name": f.get("name") or "", "error": r.get("error")})
            continue
        items.append(r)
    uns_all = sorted({u for it in items for u in it.get("unsupported") or []})
    return {"ok": True,
            "n_functions": len(items), "n_failed": len(failed),
            "n_total": len(funcs), "truncated": len(funcs) > len(items),
            "n_insns": sum(int(it.get("n_insns") or 0) for it in items),
            "n_unsupported": sum(int(it.get("n_unsupported") or 0) for it in items),
            "unsupported": uns_all,
            "n_with_unsupported": sum(1 for it in items if it.get("unsupported")),
            "n_renamed": sum(1 for it in items if it.get("renamed")),
            "n_signed_vars": sum(int((it.get("types") or {}).get("n_signed") or 0)
                                 for it in items),
            "n_unknown_signed": sum(int((it.get("types") or {}).get("n_unknown") or 0)
                                    for it in items),
            "n_structs": sum(len(it.get("structs") or []) for it in items),
            "n_inline": sum(len(it.get("inline") or []) for it in items),
            "ipa": _ipa(items),
            "functions": items, "failed": failed,
            "limitations": [
                "寄存器级伪 C：表达式与控制流保真，**类型/结构体/变量名是推断的**",
                "bl 按 AAPCS 传当前前四个参数寄存器；返回值在第一个（多返回值/浮点未建模）",
                "间接跳转（函数指针、未恢复的跳转表）保留为注释，不编造分支",
                "只做「单块 if」与「单块 if/else」结构化；循环保留 goto 并标回边",
                "函数范围外的跳转目标只补空标签（共享尾段/内联体不展开）",
                "变量名按「参数 a0..a3 / 计数器 i,j / 基址 p0,p1 / 临时量 v<N>」推断，"
                "注释里保留原始寄存器号便于对照汇编",
                "类型是推断：访问宽度定 uintN_t，int vs unsigned 只看消费指令"
                "（asr/ldrsb/bgt vs lsr/ldrb/bhi…），两向证据冲突时给 unknown，不猜",
                "结构体只给字段候选表（偏移/宽度/读写次数），不发明成员名与嵌套结构",
                "内联只标边界与来源——内联体就是一串普通指令，没有调用点可还原成 call",
                "跨函数数据流只到「实参来源 + 一层返回值传递」，不做全局变量传播",
            ]}


def pseudo_c_file(results: dict, *, title: str = "recovered") -> str:
    """把批量结果拼成一个 .c 文件（带文件头与限制声明）。"""
    head = [
        "/* %s —— 由 mdkdebug 从固件镜像提升出的**寄存器级伪 C**" % title,
        " *",
        " * 这不是原始源码。证据链：指令 -> 表达式/控制流（保真）；",
        " * 类型名、结构体划分、变量名、注释（推断/缺失）。",
        " * 变量名按参数/计数器/基址/临时量推断，注释里保留原始寄存器号；",
        " * int vs unsigned 只在有消费指令作证时才区分，冲突处写 unknown。",
        " * 未提升的指令在源码里逐条留下「未支持」注释。",
        " */",
        "#include <stdint.h>",
        "",
    ]
    body = [it["code"] for it in (results.get("functions") or [])]
    return "\n".join(head + body)


def write_pseudo_c(results: dict, dest: str, *, title: str = "recovered") -> str:
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    text = pseudo_c_file(results, title=title)
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return text
