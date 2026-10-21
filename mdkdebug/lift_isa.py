"""批次93：把非 ARM 家族的指令**规范化成 ARM 形状的中间表示（IR）**。

为什么是「翻译」而不是「另写一套提升器」：``decomp`` 里那套提升器真正依赖的
不是 ARM 的编码，而是**少量语法约定**——``mov/add/sub/and/orr/eor/lsl/lsr/asr``
的二元赋值、``ldr/str`` 的 ``[基址, #位移]``、``cmp`` + ``b<cond>`` 的条件对、
``bl`` 的调用、``bx lr`` 的返回。把这些约定当接口，别的家族只要把指令翻成
同样的形状，就能**逐字复用**命名/类型/结构体/内联/跨函数那一整套分析
（那套分析也是按这同一组约定写的）。

翻译必须**保语义**，所以三条边界：

1. **只翻有把握的形态**。翻不动的（浮点、SIMD、DSP 扩展、协处理器）整条不翻，
   由上层写成 ``/* 未支持 */``——不假装做过。
2. **看不见的副作用必须补出来**。MIPS 的**分支延迟槽**不是「下一条指令」而是
   「本条指令效果的一部分」，不把它移到分支之前，出来的伪 C 就是错的；这类
   顺序修正只做有证明的那一种（把延迟槽整组提到分支前）。
3. **家族差异写进 IR 的注释**，别让读者以为 ``a0`` 是 ARM 的 AAPCS 参数。

家族描述符（``FAMILIES``）只放「调用约定 + 寄存器名」这两件上层必须知道的事：
参数寄存器、返回寄存器、链接寄存器、栈寄存器。其余（指令翻译）在各家族自己的
``_rv_*`` / ``_mips_*`` 函数里。
"""

# ----------------------------------------------------------------------
# IR 数据结构：故意长得像 capstone 的 insn（decomp 直接吃）
# ----------------------------------------------------------------------
class IRMem:
    __slots__ = ("base", "index", "disp", "lshift")

    def __init__(self, base: int = 0, index: int = 0, disp: int = 0,
                 lshift: int = 0):
        self.base, self.index = int(base or 0), int(index or 0)
        self.disp, self.lshift = int(disp or 0), int(lshift or 0)


class IROp:
    """``type`` 沿用 capstone 的编号：1=REG、2=IMM、3=MEM。"""
    __slots__ = ("type", "reg", "imm", "mem", "shift")

    def __init__(self, kind: int, reg: int = 0, imm: int = 0, mem=None):
        self.type = int(kind)
        self.reg, self.imm, self.mem, self.shift = int(reg), int(imm), mem, None


class IRInsn:
    """一条（或一对）IR 指令。``fixed`` 非空时直接产出这些 C 行。

    ``reg_slot`` / ``reg_name`` 是给 ``decomp`` 的两个钩子：前者给分析层用的
    数值槽位，后者给出**人读的寄存器名**（RISC-V 是 ABI 名 ``a0``，MIPS 是
    ``$`` 去掉后的 ``a0``）。
    """
    __slots__ = ("address", "size", "mnemonic", "op_str", "operands",
                 "names", "fixed", "family", "src_mnemonic", "note")

    def __init__(self, address: int, size: int, mnemonic: str, op_str: str,
                 operands: list, names: dict, family: str,
                 src_mnemonic: str = "", fixed=None, note: str = ""):
        self.address, self.size = int(address), int(size)
        self.mnemonic, self.op_str = mnemonic, op_str
        self.operands, self.names = operands, names
        self.family, self.fixed, self.note = family, fixed, note
        self.src_mnemonic = src_mnemonic or mnemonic

    # capstone 形状的接口 -------------------------------------------------
    def reg_name(self, reg_id) -> str:
        return self.names.get(int(reg_id), "r?")

    def reg_slot(self, reg_id) -> int:
        return int(reg_id)

    def regs_access(self):
        """(读到的槽位, 写到的槽位)。比 capstone 粗，但同一套口径下自洽。

        用处只有一个：``_arg_source`` 找「最近一次写这个寄存器」。
        """
        wr, rd = set(), set()
        m = self.mnemonic
        no_write = (m in ("cmp", "cmn", "tst", "teq", "b", "bx", "bl", "blx",
                          "str", "strb", "strh", "strd", "push", "nop")
                    or _branch_cond(m) is not None)
        for k, op in enumerate(self.operands):
            if op.type == 1:
                rd.add(op.reg)
                if k == 0 and not no_write:
                    wr.add(op.reg)
            elif op.type == 3 and op.mem is not None:
                if op.mem.base:
                    rd.add(op.mem.base)
                if op.mem.index:
                    rd.add(op.mem.index)
        return rd, wr


def _branch_cond(mn: str):
    """与 ``decomp._branch_cond`` 同义（这里复制一份避免循环导入）。"""
    m = (mn or "").strip().lower()
    for suf in (".w", ".n"):
        if m.endswith(suf):
            m = m[: -len(suf)]
    if m == "b":
        return ""
    conds = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
             "hi", "ls", "ge", "lt", "gt", "le")
    if m.startswith("b") and m[1:] in conds:
        return m[1:]
    return None


def _hex(v) -> str:
    v = int(v or 0)
    if v < 0:
        return "-0x%X" % (-v)
    return "0x%X" % (v & 0xFFFFFFFF)


# ----------------------------------------------------------------------
# 家族描述符：上层（decomp）只需要这几项
# ----------------------------------------------------------------------
_RV_NAMES = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
             "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
             "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
             "t3", "t4", "t5", "t6"]

# MIPS 的通用寄存器名，按编号 0..31
_MIPS_NAMES = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
               "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
               "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
               "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]

FAMILIES = {
    "arm": {
        "naming": "arm",                 # 沿用 rN + AAPCS 命名阶梯
        "arg_slots": [0, 1, 2, 3],
        "arg_names": ["a0", "a1", "a2", "a3"],
        "ret_name": "r0", "ret_slot": 0,
        "link_name": "lr", "link_slot": 14,
        "stack_name": "sp", "stack_slot": 13,
        "skip_slots": (13, 15),
        "abi": "AAPCS",
        "slot_names": {"%d" % i: "r%d" % i for i in range(16)},
    },
    "riscv": {
        "naming": "abi",                 # 用 ABI 名，不做命名阶梯
        "arg_slots": [10, 11, 12, 13, 14, 15, 16, 17],
        "arg_names": ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        "ret_name": "a0", "ret_slot": 10,
        "link_name": "ra", "link_slot": 1,
        "stack_name": "sp", "stack_slot": 2,
        "skip_slots": (1, 2),
        "abi": "RISC-V psABI",
        "slot_names": {i: n for i, n in enumerate(_RV_NAMES)},
    },
    "mips": {
        "naming": "abi",
        "arg_slots": [4, 5, 6, 7],
        "arg_names": ["a0", "a1", "a2", "a3"],
        "ret_name": "v0", "ret_slot": 2,
        "link_name": "ra", "link_slot": 31,
        "stack_name": "sp", "stack_slot": 29,
        "skip_slots": (29, 31),
        "abi": "o32",
        "slot_names": {i: n for i, n in enumerate(_MIPS_NAMES)},
    },
}

# 能翻译的家族；其余家族给理由（**拒绝也要说清楚缺什么**）
NOT_LIFTABLE = {
    "arm64": "AArch64 是 64 位寄存器模型（x0..x30），本提升器的类型层是 32 位"
             "（uint32_t/int32_t）；硬套会得到「宽度错、看着对」的错答案",
    "x86": "x86 的寄存器是分段/子寄存器/栈机语义（eax/ax/al 同一寄存器），"
           "且指令隐式读写栈，与 RISC 型提升模型不同构",
    "x86_64": "同 x86：子寄存器与隐式栈语义，且 64 位",
    "ppc": "PowerPC 的条件寄存器字段（cr0..cr7）与 update 后缀（addi./lwz）"
           "还没建模；翻译出来会把「顺带写 CR0」丢掉",
    "m68k": "68k 是「地址寄存器 + 数据寄存器」两套寄存器组，且大量指令带"
            "后自增/前自减寻址，与 [基址,#位移] 模型不同构",
    "sparc": "SPARC 的寄存器窗口（register window / save-restore）未建模",
    "mos65xx": "6502 是 8 位累加器机，没有通用寄存器堆",
    "s390": "无后端",
}


def descriptor(fam: str) -> dict:
    return FAMILIES.get(fam) or {}


def liftable(fam: str) -> bool:
    return fam in FAMILIES


def refusal(fam: str) -> str:
    why = NOT_LIFTABLE.get(fam)
    if why:
        return ("伪 C 提升没有接入 %s：%s。可用家族：%s"
                % (fam, why, " / ".join(sorted(FAMILIES))))
    return ("伪 C 提升没有接入 %s（未知家族）。可用家族：%s"
            % (fam, " / ".join(sorted(FAMILIES))))


# ----------------------------------------------------------------------
# 家族内部：寄存器名 → 槽位
# ----------------------------------------------------------------------
_SLOT_CACHE = {}


def _slots(fam: str, names) -> dict:
    """名字 → 槽位。槽位是**本模块自定**的连续编号，与 capstone 的 reg id 无关
    （capstone 的 id 是枚举值，跨版本会变；我们只要稳定 + 唯一）。"""
    key = (fam, tuple(names))
    if key not in _SLOT_CACHE:
        _SLOT_CACHE[key] = {n: i for i, n in enumerate(names)}
    return _SLOT_CACHE[key]


_EXTRA = {}


def _slot(fam: str, names, name: str) -> int:
    """名字 → 槽位；表里没有的（DSP/浮点/协处理器寄存器）给 100 起的稳定槽位。"""
    mp = _slots(fam, names)
    if name in mp:
        return mp[name]
    key = (fam, name)
    if key not in _EXTRA:
        _EXTRA[key] = 100 + len(_EXTRA)
    return _EXTRA[key]


def _raw_name(ins, reg_id) -> str:
    try:
        return (ins.reg_name(int(reg_id)) or "").strip().lower().lstrip("$")
    except Exception:                      # noqa: BLE001
        return ""


def _ops(ins):
    return list(ins.operands)


def _imm(op) -> int:
    return int(getattr(op, "imm", 0) or 0)


# ----------------------------------------------------------------------
# IR 构造
# ----------------------------------------------------------------------
def _R(slot: int) -> IROp:
    return IROp(1, reg=slot)


def _I(v: int) -> IROp:
    return IROp(2, imm=int(v))


def _M(base: int, disp: int = 0, index: int = 0) -> IROp:
    return IROp(3, mem=IRMem(base, index, disp))


class _B:
    """一条源指令的翻译器：管住「家族 + 名字表 + 源指令」三件事。"""

    def __init__(self, fam: str, ins, names: list):
        self.fam, self.ins, self.names = fam, ins, names

    # 名字/槽位 ---------------------------------------------------------
    def name(self, reg_id) -> str:
        raw = _raw_name(self.ins, reg_id)
        if not raw:
            return "r?"
        return raw

    def slot(self, reg_id) -> int:
        return _slot(self.fam, self.names, self.name(reg_id))

    def r(self, op) -> IROp:
        """源操作数 → IR 操作数：零寄存器不是变量，直接给立即数 0。"""
        if int(getattr(op, "type", 0)) != 1:
            return _I(_imm(op))
        if self.name(op.reg) == "zero":
            return _I(0)
        return _R(self.slot(op.reg))

    def dst(self, op) -> IROp:
        """目的操作数：写零寄存器等于丢弃（x0/$zero 恒为 0）。"""
        return _R(self.slot(op.reg))

    def reg(self, op) -> str:
        return self.name(op.reg)

    def slot_of(self, op) -> int:
        return self.slot(op.reg)

    def sx(self, op) -> str:
        """操作数 → C 表达式（只有寄存器/立即数两种，内存单独处理）。"""
        if int(getattr(op, "type", 0)) == 1:
            return self.reg(op)
        return _hex(_imm(op))

    # 构造 ---------------------------------------------------------------
    def mk(self, mn: str, ops: list, op_str=None, fixed=None, note="") -> IRInsn:
        text = op_str if op_str is not None else ", ".join(
            (self.reg(o) if o.type == 1 else _hex(o.imm)) if o.type != 3
            else (self.name(o.mem.base) if o.mem else "?") for o in ops)
        return IRInsn(self.ins.address, self.ins.size, mn, text, ops,
                      {s: n for n, s in _slots(self.fam, self.names).items()},
                      self.fam, self.ins.mnemonic, fixed=fixed, note=note)

    def mem(self, op) -> IROp:
        b = self.slot(op.mem.base) if getattr(op.mem, "base", 0) else 0
        i = self.slot(op.mem.index) if getattr(op.mem, "index", 0) else 0
        return _M(b, int(getattr(op.mem, "disp", 0) or 0), i)


# ----------------------------------------------------------------------
# RISC-V
# ----------------------------------------------------------------------
_RV_ARITH = {"add": "add", "sub": "sub", "and": "and", "or": "orr",
             "xor": "eor", "sll": "lsl", "srl": "lsr", "sra": "asr",
             "addw": "add", "subw": "sub", "sllw": "lsl", "srlw": "lsr",
             "sraw": "asr", "mul": "mul", "mulw": "mul"}
_RV_LOAD = {"lb": "ldrsb", "lh": "ldrsh", "lw": "ldr", "ld": "ldrd",
            "lbu": "ldrb", "lhu": "ldrh", "lwu": "ldr"}
_RV_STORE = {"sb": "strb", "sh": "strh", "sw": "str", "sd": "strd"}
_RV_BRANCH = {"beq": ("cmp", "beq"), "bne": ("cmp", "bne"),
              "blt": ("cmp", "blt"), "bge": ("cmp", "bge"),
              "bltu": ("cmp", "blo"), "bgeu": ("cmp", "bhs"),
              "bgt": ("cmp", "bgt"), "ble": ("cmp", "ble")}
_RV_BRANCH_Z = {"beqz": "beq", "bnez": "bne", "bltz": "blt", "bgez": "bge",
                "blez": "ble", "bgtz": "bgt"}
_RV_CTRL = ("csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci",
            "ecall", "ebreak", "fence", "fence.i", "wfi", "sfence.vma",
            "mret", "sret", "uret")


def _rv(b: _B, mn: str, ops: list):
    ins = b.ins
    if mn in ("c.nop", "nop"):
        return [b.mk("nop", [])]
    if mn == "ret":
        return [b.mk("bx", [_R(_slot(b.fam, _RV_NAMES, "ra"))], op_str="lr")]
    if mn == "jr":                       # RISC-V 没有 jr，留作兼容写法
        return [b.mk("bx", [b.r(ops[0])], op_str=b.reg(ops[0]))]
    if mn == "j":
        return [b.mk("b", [_I(ins.address + _imm(ops[-1]))])]
    if mn == "jal":
        if len(ops) == 1:
            return [b.mk("bl", [_I(ins.address + _imm(ops[0]))])]
        rd = b.reg(ops[0])
        if len(ops) >= 3:                # jal rd, rs, off —— 间接，不建模
            return [b.mk("blx", [b.r(ops[1])])]
        if rd not in ("ra", "zero"):
            return [b.mk("mov", [b.r(ops[0])],
                         fixed=["%s = %s; /* jal：返回地址（rd≠ra 的用法未建模） */"
                                % (rd, _hex(ins.address + ins.size))])]
        return [b.mk("bl", [_I(ins.address + _imm(ops[1]))])]
    if mn == "jalr":
        if len(ops) == 1:
            return [b.mk("bx", [b.r(ops[0])],
                         op_str=b.reg(ops[0]))]
        rd = b.reg(ops[0])
        rs = b.reg(ops[1])
        if rd in ("ra", "zero"):
            if rs in ("ra", "zero"):
                return [b.mk("bx", [_R(_slot(b.fam, _RV_NAMES, "ra"))],
                             op_str="lr")]
            return [b.mk("bx", [b.r(ops[1])], op_str=rs)]
        return [b.mk("blx", [b.r(ops[1])])]
    if mn in _RV_BRANCH and len(ops) >= 3:
        _, br = _RV_BRANCH[mn]
        return [b.mk("cmp", [b.r(ops[0]), b.r(ops[1])]),
                b.mk(br, [_I(ins.address + _imm(ops[2]))])]
    if mn in _RV_BRANCH_Z and len(ops) >= 2:
        br = _RV_BRANCH_Z[mn]
        return [b.mk("cmp", [b.r(ops[0]), _I(0)]),
                b.mk(br, [_I(ins.address + _imm(ops[1]))])]
    if mn in ("li", "mv") and len(ops) >= 2:
        src = (b.r(ops[1]) if ops[1].type == 1 else _I(_imm(ops[1])))
        return [b.mk("mov", [b.r(ops[0]), src])]
    if mn == "lui" and len(ops) >= 2:
        v = _imm(ops[1]) & 0xFFFFF
        return [b.mk("mov", [b.r(ops[0]), _I(v << 12)],
                     fixed=None)]
    if mn == "auipc" and len(ops) >= 2:
        base = ins.address + ((_imm(ops[1]) & 0xFFFFF) << 12) & 0xFFFFFFFF
        return [b.mk("mov", [b.r(ops[0]), _I(base)],
                     fixed=["%s = %s; /* auipc：pc + 高 20 位 */"
                            % (b.reg(ops[0]), _hex(base))])]
    if mn in ("addi", "addiw"):
        rd = ops[0]
        if len(ops) == 2:                # c.addi：rd 既是源也是目的
            return [b.mk("add", [_R(b.slot_of(rd)), _R(b.slot_of(rd)),
                                 _I(_imm(ops[1]))])]
        rs, im = ops[1], _imm(ops[2])
        if b.reg(rs) == "zero":
            return [b.mk("mov", [_R(b.slot_of(rd)), _I(im)])]
        return [b.mk("add", [_R(b.slot_of(rd)), _R(b.slot_of(rs)), _I(im)])]
    if mn in ("addi4spn", "addi16sp"):    # 压缩序言里的 sp 调整
        if len(ops) >= 3:
            return [b.mk("add", [_R(b.slot_of(ops[0])), _R(b.slot_of(ops[1])),
                                 _I(_imm(ops[2]))])]
        return [b.mk("add", [_R(b.slot_of(ops[0])), _R(b.slot_of(ops[0])),
                             _I(_imm(ops[1]))])]
    if mn in ("andi", "ori", "xori"):
        tgt = {"andi": "and", "ori": "orr", "xori": "eor"}[mn]
        src = b.slot_of(ops[0]) if len(ops) == 2 else b.slot_of(ops[1])
        im = _imm(ops[-1])
        return [b.mk(tgt, [_R(b.slot_of(ops[0])), _R(src), _I(im)])]
    if mn in ("slli", "srli", "srai", "slliw", "srliw", "sraiw"):
        tgt = {"slli": "lsl", "srli": "lsr", "srai": "asr",
               "slliw": "lsl", "srliw": "lsr", "sraiw": "asr"}[mn]
        src = b.slot_of(ops[0]) if len(ops) == 2 else b.slot_of(ops[1])
        return [b.mk(tgt, [_R(b.slot_of(ops[0])), _R(src), _I(_imm(ops[-1]))])]
    if mn in ("slt", "sltu", "slti", "sltiu"):
        signed = mn in ("slt", "slti")
        rt = "int32_t" if signed else "uint32_t"
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = (%s)%s < (%s)%s ? 1 : 0; /* %s */"
            % (b.reg(ops[0]), rt, b.sx(ops[1]), rt, b.sx(ops[2]), mn)])]
    if mn in _RV_ARITH and len(ops) >= 3:
        return [b.mk(_RV_ARITH[mn], [b.r(ops[0]), b.r(ops[1]),
                                    b.r(ops[2])])]
    if mn in _RV_ARITH and len(ops) == 2:      # c.add/c.sub/c.and…：rd 也是源 1
        dst = b.slot_of(ops[0])
        return [b.mk(_RV_ARITH[mn], [_R(dst), _R(dst), b.r(ops[1])])]
    if mn in ("div", "divu", "rem", "remu"):
        rt = "int32_t" if mn in ("div", "rem") else "uint32_t"
        op = "/" if "div" in mn else "%"
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = (%s)%s %s (%s)%s; /* %s（除零未建模） */"
            % (b.reg(ops[0]), rt, b.reg(ops[1]), op, rt, b.reg(ops[2]), mn)])]
    if mn in _RV_LOAD and len(ops) >= 2:
        return [b.mk(_RV_LOAD[mn], [b.r(ops[0]), b.mem(ops[1])])]
    if mn in _RV_STORE and len(ops) >= 2:
        return [b.mk(_RV_STORE[mn], [b.r(ops[0]), b.mem(ops[1])])]
    if mn == "neg":
        return [b.mk("mov", [b.r(ops[0]), _I(0)],
                     fixed=["%s = 0 - %s;" % (b.reg(ops[0]), b.reg(ops[1]))])]
    if mn == "not":
        return [b.mk("mov", [b.r(ops[0]), _I(0)],
                     fixed=["%s = ~%s;" % (b.reg(ops[0]), b.reg(ops[1]))])]
    if mn in ("seqz", "snez", "sltz", "sgtz"):
        expr = {"seqz": "%s == 0", "snez": "%s != 0",
                "sltz": "(int32_t)%s < 0", "sgtz": "(int32_t)%s > 0"}[mn]
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = %s ? 1 : 0; /* %s */"
            % (b.reg(ops[0]), expr % b.reg(ops[1]), mn)])]
    if mn in ("sext.b", "sext.h", "sext.w", "zext.b", "zext.h", "zext.w"):
        ty = {"sext.b": "int8_t", "sext.h": "int16_t", "sext.w": "int32_t",
              "zext.b": "uint8_t", "zext.h": "uint16_t",
              "zext.w": "uint32_t"}[mn]
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = (%s)%s;" % (b.reg(ops[0]), ty, b.reg(ops[1]))])]
    if mn in _RV_CTRL:
        return [b.mk("nop", [], fixed=["/* 控制/状态：%s %s（未建模，不影响数据流） */"
                                       % (ins.mnemonic, ins.op_str)], note="ctrl")]
    return None


# ----------------------------------------------------------------------
# MIPS（含分支延迟槽）
# ----------------------------------------------------------------------
_MIPS_ARITH = {"addu": "add", "add": "add", "subu": "sub", "sub": "sub",
               "and": "and", "or": "orr", "xor": "eor",
               "sll": "lsl", "srl": "lsr", "sra": "asr",
               "sllv": "lsl", "srlv": "lsr", "srav": "asr",
               "mul": "mul"}
_MIPS_LOAD = {"lb": "ldrsb", "lh": "ldrsh", "lw": "ldr", "ld": "ldrd",
              "lbu": "ldrb", "lhu": "ldrh", "lwl": "ldr", "lwr": "ldr"}
_MIPS_STORE = {"sb": "strb", "sh": "strh", "sw": "str", "sd": "strd"}
_MIPS_BRANCH = {"beq": ("cmp", "beq"), "bne": ("cmp", "bne")}
_MIPS_BRANCH_Z = {"blez": "ble", "bgtz": "bgt", "bltz": "blt",
                  "bgez": "bge", "beql": "beq", "bnel": "bne"}
_MIPS_CTRL = ("syscall", "break", "eret", "mtc0", "mfc0", "mtc1", "mfc1",
              "teq", "tne", "cache", "pref", "sync", "wait")


def _mips(b: _B, mn: str, ops: list):
    ins = b.ins
    if mn in ("nop", "ssnop"):
        return [b.mk("nop", [])]
    if mn == "jr":
        if len(ops) >= 1 and b.reg(ops[0]) == "ra":
            return [b.mk("bx", [_R(_slot(b.fam, _MIPS_NAMES, "ra"))], op_str="lr")]
        return [b.mk("bx", [b.r(ops[0])], op_str=b.reg(ops[0]))]
    if mn == "jalr":
        if len(ops) >= 2:
            return [b.mk("blx", [b.r(ops[1])])]
        return [b.mk("blx", [b.r(ops[0])])]
    if mn in ("j", "b"):
        return [b.mk("b", [_I(_imm(ops[0]))])]
    if mn == "jal":
        return [b.mk("bl", [_I(_imm(ops[0]))])]
    if mn in _MIPS_BRANCH and len(ops) >= 3:
        return [b.mk("cmp", [b.r(ops[0]), b.r(ops[1])]),
                b.mk(_MIPS_BRANCH[mn][1], [_I(_imm(ops[2]))])]
    if mn in _MIPS_BRANCH_Z and len(ops) >= 2:
        return [b.mk("cmp", [b.r(ops[0]), _I(0)]),
                b.mk(_MIPS_BRANCH_Z[mn], [_I(_imm(ops[1]))])]
    if mn in ("addiu", "addi"):
        rd, rs = ops[0], ops[1]
        if b.reg(rs) == "zero":
            return [b.mk("mov", [_R(b.slot_of(rd)), _I(_imm(ops[2]))])]
        return [b.mk("add", [_R(b.slot_of(rd)), _R(b.slot_of(rs)),
                             _I(_imm(ops[2]))])]
    if mn in ("andi", "ori", "xori"):
        tgt = {"andi": "and", "ori": "orr", "xori": "eor"}[mn]
        return [b.mk(tgt, [b.r(ops[0]), b.r(ops[1]),
                           _I(_imm(ops[2]) & (0xFFFF if mn != "andi" else 0xFFFF))])]
    if mn == "lui":
        return [b.mk("mov", [b.r(ops[0]), _I((_imm(ops[1]) & 0xFFFF) << 16)])]
    if mn in ("slt", "sltu", "slti", "sltiu"):
        signed = mn in ("slt", "slti")
        rt = "int32_t" if signed else "uint32_t"
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = (%s)%s < (%s)%s ? 1 : 0; /* %s */"
            % (b.reg(ops[0]), rt, b.sx(ops[1]), rt, b.sx(ops[2]), mn)])]
    if mn in _MIPS_ARITH and len(ops) >= 3:
        return [b.mk(_MIPS_ARITH[mn], [b.r(ops[0]),
                                       b.r(ops[1]),
                                       b.r(ops[2])])]
    if mn in ("div", "divu", "rem", "remu"):
        rt = "int32_t" if mn in ("div", "rem") else "uint32_t"
        op = "/" if "div" in mn else "%"
        return [b.mk("mov", [b.r(ops[0]), _I(0)], fixed=[
            "%s = (%s)%s %s (%s)%s; /* %s（MIPS 的 div 写 hi/lo，这里按常见用法折叠） */"
            % (b.reg(ops[0]), rt, b.reg(ops[1]), op, rt, b.reg(ops[2]), mn)])]
    if mn in _MIPS_LOAD and len(ops) >= 2:
        return [b.mk(_MIPS_LOAD[mn], [b.r(ops[0]), b.mem(ops[1])])]
    if mn in _MIPS_STORE and len(ops) >= 2:
        return [b.mk(_MIPS_STORE[mn], [b.r(ops[0]), b.mem(ops[1])])]
    if mn in ("mult", "multu", "madd", "maddu"):
        rt = "int32_t" if mn in ("mult", "madd") else "uint32_t"
        return [b.mk("nop", [], fixed=[
            "/* hi:lo = (%s)%s * (%s)%s（乘积寄存器未建模）；下面按 mflo 取低 32 位 */"
            % (rt, b.reg(ops[0]), rt, b.reg(ops[1]))], note="ctrl")]
    if mn in ("mflo", "mfhi"):
        hi = mn == "mfhi"
        return [b.mk("nop", [], fixed=[
            "%s = %s; /* %s：乘积/除法寄存器未建模，这里只是占位 */"
            % (b.reg(ops[0]), "0 /* hi */" if hi else "0 /* lo */", mn)], note="ctrl")]
    if mn in ("mtlo", "mthi", "clz", "clo", "wsbh", "rotr", "rotrv"):
        return None
    if mn in _MIPS_CTRL:
        return [b.mk("nop", [], fixed=["/* 控制/状态：%s %s（未建模，不影响数据流） */"
                                       % (ins.mnemonic, ins.op_str)], note="ctrl")]
    return None


_TABLE = {"riscv": (_rv, _RV_NAMES), "mips": (_mips, _MIPS_NAMES)}

# 分支/跳转（延迟槽在这些指令之后执行，MIPS 才有）
_DELAY_MN = ("j", "jal", "jr", "jalr", "beq", "bne", "blez", "bgtz", "bltz",
             "bgez", "beql", "bnel")


def normalise(unit, ins) -> list:
    """一条源指令 → IR 列表（可能 0/1/2 条；无法翻译时返回 ``[]``）。"""
    fam = (unit.arch or {}).get("family")
    ent = _TABLE.get(fam)
    if ent is None:
        return []
    fn, names = ent
    b = _B(fam, ins, names)
    mn = (ins.mnemonic or "").strip().lower()
    if mn.startswith("c."):
        mn = mn[2:]
    out = fn(b, mn, _ops(ins))
    if out is None:
        # 翻不动就**留一条注释**并计数：静默丢掉会让「未支持」的统计说谎
        return [b.mk("nop", [], fixed=[
            "/* 未支持: %s %s（%s 家族里这种形态没有翻译） */"
            % (ins.mnemonic, ins.op_str, fam)], note="unsupported")]
    # 写零寄存器（x0 / $zero）等于丢弃：两个家族的零寄存器都固定占槽位 0。
    # 直接渲染会得到 `zero = ...`，看起来像个变量，会把人带偏。
    if _writes_zero(b, mn, _ops(ins)):
        return [b.mk("nop", [], fixed=[
            "/* 结果丢弃: %s %s（写零寄存器，值恒为 0） */"
            % (ins.mnemonic, ins.op_str)], note="discard")]
    return out


# 这些形态的第一个操作数是**目的寄存器**（不是源值）。其余（str/branch/ctrl）
# 的第一个操作数就算写成零寄存器也不是「丢弃」语义。
_WRITES_RD = set("""
add sub and or xor sll srl sra addw subw sllw srlw sraw mul mulw
addu subu sllv srlv srav
addi addiu addiw andi ori xori slli srli srai slliw srliw sraiw
slt sltu slti sltiu
lb lh lw ld lbu lhu lwu lwl lwr
lui auipc li mv jal jalr
div divu rem remu neg not seqz snez sltz sgtz
sext.b sext.h sext.w zext.b zext.h zext.w
mult multu madd maddu mflo mfhi
""".split())

def _writes_zero(b: _B, mn: str, ops: list) -> bool:
    """这条指令的目的是不是零寄存器（x0 / $zero 恒为 0 ⇒ 结果丢弃）。"""
    if mn not in _WRITES_RD or not ops:
        return False
    op = ops[0]
    if int(getattr(op, "type", 0)) != 1:
        return False
    return b.name(op.reg) == "zero"


def is_delay_branch(irs) -> bool:
    """这组 IR 是不是「带延迟槽的分支/跳转」（按源助记符判）。"""
    return bool(irs) and (irs[0].src_mnemonic or "").lower() in _DELAY_MN


def hoist_delay_slots(groups: list) -> tuple:
    """MIPS 的分支延迟槽：下一条指令**先于**分支生效。

    做法是把「分支那组」与「延迟槽那组」交换顺序（延迟槽整组提到分支前）。
    只在两种情况下动：① 前一组确实是带延迟槽的分支；② 后一组不是分支
    （分支接分支是未定义写法，原样保留并计数）。

    返回 ``(新组列表, 被移动的次数)``。
    """
    out, moved = [], 0
    i, n = 0, len(groups)
    while i < n:
        g = groups[i]
        if g and i + 1 < n and is_delay_branch(g) and not is_delay_branch(groups[i + 1]):
            nxt = groups[i + 1]
            # nop 延迟槽没有必要留在源码里（它什么都不做）
            keep = [x for x in nxt if x.mnemonic != "nop"]
            if keep:                 # 只有真搬了东西才算「提到前面」
                out.append(keep)
                moved += 1
            out.append(g)
            i += 2
            continue
        out.append(g)
        i += 1
    flat = []
    for g in out:
        flat.extend(g)
    return flat, moved
