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
def _decode(unit, start: int, end: int, *, max_insns: int = 4000):
    """反汇编 ``[start, end)``，返回 **capstone 指令对象**（要 operands 细节）。

    坏字节按指令对齐跳过并计数（与 ``recover.disassemble`` 同一策略），
    不把「一个坏字节」当成「后面没有指令」。
    """
    from .recover import _make_cs           # 避免模块级循环导入
    md, why = _make_cs(unit.arch)
    if md is None:
        return None, 0, why
    blob = unit.read(start, end - start)
    if not blob:
        return None, 0, "地址 0x%08X 不在镜像的映射范围内" % start
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
                return insns, skipped, ""
        if not got or pos < len(blob):
            pos = min(pos + step, len(blob))
            skipped += 1
    return insns, skipped, ""


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
        return ["r0 = %s(r0, r1, r2, r3); /* bl %s */"
                % (fn, _hex(tgt) if tgt is not None else "?")]
    if base == "blx":
        reg = _op_expr(unit, ins, ops[0]) if ops else "?"
        ctx["flags"] = None
        ctx["carry"] = None
        return ["r0 = ((uint32_t (*)(uint32_t, uint32_t, uint32_t, uint32_t))%s)"
                "(r0, r1, r2, r3); /* blx */" % reg]
    if base == "bx":
        reg = _op_expr(unit, ins, ops[0]) if ops else "lr"
        ctx["flags"] = None
        if reg == "lr":
            return ["return r0; /* bx lr */"]
        return ["return r0; /* bx %s —— 尾调用/间接跳转，目标未解析 */" % reg]
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


def decompile_function(unit, func, *, funcs=None, names=None, switches=None,
                       max_insns: int = 4000) -> dict:
    """单个函数 → 伪 C 文本 + 统计。失败时返回 ``{"ok": False, "error": ...}``。"""
    fam = (unit.arch or {}).get("family")
    if fam != "arm":
        return {"ok": False,
                "error": "伪 C 提升只做了 ARM/Thumb（32 位寄存器模型：r0..r12/sp/lr/pc）；"
                         "当前架构是 %s，不做提升——把 x86/MIPS/PPC 的指令塞进这个模型"
                         "只会得到「看着像」的错答案" % (fam or "未知"),
                "hint": "用 recover_disasm（不加 fmt=\"c\"）看该架构的汇编"}
    funcs = funcs or [func]
    code_end = max((b for _, b in unit.code_ranges), default=None)
    if code_end is None:
        return {"ok": False, "error": "没有可执行区间"}
    start, end = _span(func, funcs, code_end)
    sw_err = ""
    insns, skipped, why = _decode(unit, start, end, max_insns=max_insns)
    if insns is None:
        return {"ok": False, "error": why}
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
           "flag_unresolved": 0, "switch_unresolved": 0, "ctrl_note": 0}

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

    used = set()
    for ins in insns:
        try:
            rd, wr = ins.regs_access()
            used.update(reveng._norm_reg(ins.reg_name(r))
                        for r in list(rd) + list(wr))
        except Exception:                  # noqa: BLE001
            pass
    locals_ = ["r%d" % n for n in range(4, 13) if "r%d" % n in used]
    if "lr" in used:
        locals_.append("lr")
    locals_.append("sp")

    name0 = func.get("name") or ""
    fn_name = _c_name(name0, "") if name0 else ""
    if not fn_name:
        fn_name = "sub_%08X" % start

    lines = [
        "/* %s —— 0x%08X..0x%08X，%d 条指令 / %d 个基本块%s" % (
            fn_name, start, end, len(insns), len(blocks),
            "" if not skipped else " / %d 处坏字节已跳过" % skipped),
        " * 寄存器级伪 C（lifting）：表达式与控制流保真；类型/结构体/变量名是**推断**的，"
        "不是原始源码。",
        " * bl 按 AAPCS 传当前 r0..r3（返回值落 r0）；栈访问用 sp 偏移表达式。 */",
        "uint32_t %s(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3)" % fn_name,
        "{",
        "    uint32_t %s;" % ", ".join(locals_),
        "",
    ]
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
            lines.append(ind + "return r0; /* %s %s */"
                         % (last.mnemonic, last.op_str))
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
        lines.append("    return r0; /* 末尾无显式返回：沿用 r0 */")

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
        notes.append("%d 处控制/状态指令（bkpt/cpsid/cpsie/vmsr/vmrs）只保留为注释：未建模"
                     % ctx["ctrl_note"])
    if ctx.get("assumed"):
        notes.append("%d 处独占访问（ldrex/strex）按普通访存 + 假设成功输出"
                     "（独占监视器未建模）" % ctx["assumed"])
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
            "n_flag_unresolved": ctx["flag_unresolved"],
            "n_switch_unresolved": ctx["switch_unresolved"],
            "n_outside_targets": len(missing),
            "notes": notes}


def _terminator_lines(unit, ins, ctx, blocks) -> tuple:
    """块末尾指令 → (行列表, 是否有显式控制转移)。"""
    m = _base_mn(ins.mnemonic)
    if _is_ret(ins):
        return (["return r0; /* %s %s */" % (ins.mnemonic, ins.op_str)], True)
    if _is_table_term(ins):
        return (_switch_lines(unit, ins, ctx), True)
    if m == "bx":
        reg = _op_expr(unit, ins, list(ins.operands)[0]) if ins.operands else "lr"
        return (["return r0; /* bx %s */" % reg], True)
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
def decompile(unit, funcs, *, max_funcs: int = 60, max_insns: int = 4000,
              names=None, switches=None) -> dict:
    """按函数清单批量出伪 C（默认最多 60 个，避免一次吐几 MB）。"""
    names = names or {}
    code_end = max((b for _, b in unit.code_ranges), default=None)
    if code_end is None:
        return {"ok": False, "error": "没有可执行区间"}
    funcs = sorted(funcs, key=lambda f: int(f["addr"]))
    items, failed = [], []
    for f in funcs[:max_funcs]:
        r = decompile_function(unit, f, funcs=funcs, names=names,
                               switches=switches, max_insns=max_insns)
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
            "functions": items, "failed": failed,
            "limitations": [
                "寄存器级伪 C：表达式与控制流保真，**类型/结构体/变量名是推断的**",
                "bl 按 AAPCS 传当前 r0..r3；返回值在 r0（多返回值/浮点未建模）",
                "间接跳转（函数指针、未恢复的跳转表）保留为注释，不编造分支",
                "只做「单块 if」与「单块 if/else」结构化；循环保留 goto 并标回边",
                "函数范围外的跳转目标只补空标签（共享尾段/内联体不展开）",
            ]}


def pseudo_c_file(results: dict, *, title: str = "recovered") -> str:
    """把批量结果拼成一个 .c 文件（带文件头与限制声明）。"""
    head = [
        "/* %s —— 由 mdkdebug 从固件镜像提升出的**寄存器级伪 C**" % title,
        " *",
        " * 这不是原始源码。证据链：指令 -> 表达式/控制流（保真）；",
        " * 类型名、结构体划分、变量名、注释（推断/缺失）。",
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
