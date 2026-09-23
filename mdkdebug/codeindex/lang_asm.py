# -*- coding: utf-8 -*-
"""代码索引：汇编解析层（`.s` / `.S` / `.asm`）。

为什么不是 tree-sitter：C/C++ 用 tree-sitter 轮子，但汇编**没有可用的预编译语法轮子**，
而汇编又恰恰是 MCU 工程里最容易变成「读不到的黑洞」的部分——启动文件、上下文切换、
SVC/PendSV 入口、向量表都在这里。这一层因此走**行式解析**（纯标准库、零依赖），
只挑那些**词法上就能证实的**东西：

  标签 / 函数（`PROC…ENDP`、`.type x,%function`、`.thumb_func`、被 `bl` 指向的标签）
  调用（`BL`/`BLX` 符号式；`BLX Rn` 只在**同段内数得出 `LDR Rn, =sym` / `ADR Rn, sym`** 时才命名；
       `B sym` **仅当 sym 来自本文件的 `IMPORT`/`EXTERN`** 才算尾调用——见下）
  外部声明（`IMPORT` / `EXTERN` / `.extern`）—— **它是一条真实存在的「声明」**，让
      「汇编调 C 函数」这种跨语言调用点上能给出比 name-only 更硬的依据（见下）
  include（`GET` / `INCLUDE` / `#include` / `.include`）
  宏（`name MACRO`…`MEND`、`.macro`…`.endm`）
  取地址（`LDR Rn, =sym`、`ADR Rn, sym`）与数据指针（`DCD sym` / `.word sym`）→ 进 fptr 表当**盲区证据**
  条件汇编（armasm `IF/ELSE/ELIF/ENDIF`、GNU `.if*/.else/.endif`）→ `in_conditional`

**这份清单就是全部**——行式解析不理解的语句一律不看。所以：

1. `parse_error` 对汇编**恒为 0**，它**不代表**这份汇编被完全理解了（残指令、语法错误都不会被发现）；
2. **没有名字的间接调用**（`BLX Rn` 且寄存器来源静态看不到）**不产生调用点**：没有名字就没有可查的
   东西，宁可少一条，也不自造一个像 `R2` 这样的假名字去污染 `unresolved_names`；
3. **宏不展开**：宏体内的 `bl` 不记为调用点（展开点不在宏定义处，记下来等于给一个假的调用者）。
   `LDR Rn, =sym` + `BLX Rn` 这种「取地址再跳」是 armasm 里常见的间接调用写法，按 `via_pointer=1`
   记成调用点——名字是文本里给的，但**它只是线索**，置信度照样压到 `blind`（见 resolve.py）；
4. 符号种类三个，**不复用 C 的 `function`**（不假装汇编标签就是 C 函数）：
   `asm_func`（PROC/ENDP、`.type %function`、`.thumb_func`、被 `bl` 指向的标签）、
   `asm_label`（其它标签、EQU/数据/常量——含 `storage="constant"`）、
   `asm_import`（`IMPORT`/`EXTERN` 声明的外部符号，`is_definition=0`）。
   `asm_import` 进 `resolve.CALLABLE_KINDS`：汇编里 `IMPORT` 既可能是函数也可能是数据，
   **函数还是数据在汇编层面看不出来**——所以不复用 `function` 去冒充一个我知道不了的种类，
   但把它当「声明」用（kind 字样如实透出给调用方自己判断）。
5. `B sym`（无条件跳转）与 `BL` 不同：本文件内的 `B label` 是循环/条件分支，把它画成
   调用边就是一张看着完整的假图。所以只认「目标是 **IMPORT/EXTERN 进来的外部符号**」的
   `B`——外部的 `B` 不可能是本文件内的循环，只能是把控制权交出去（尾调用；SVC/PendSV
   入口正是这么写的：`B SVC_Server`）。**故意保守**：宁可少一条，也不把普通分支当调用。
6. 以 `.` 开头的名字（GNU 的 `.L…` 局部标签、伪指令）**不进符号表**，也不算「没看懂的行」。
   返回体里除了 `unparsed_lines` 计数，还给 `unparsed_samples`（前 10 条原文）——
   报「有多少行没看懂」时必须能让人去核对，否则这个数字本身就不可信。
7. armasm 与 GNU 两种方言都是「名字在前、指令在后」（`Name PROC` / `Name EQU 5`）与
   「指令在前」（`.globl name` / `.type name,%function`）并存的，两种写法都认；
   认不出方言时按 **armasm** 处理（MDK 的 `.s` 绝大多数是 armasm），判定结果记进返回体。
"""
import re

LANG = "asm"

#: 符号种类
KIND_FUNC = "asm_func"
KIND_LABEL = "asm_label"
KIND_IMPORT = "asm_import"

#: ARM/Thumb 助记符（用于「整行只有一个词」时区分「裸标签」与「指令」；也用于把
#: 不关心的指令行与「真的没看懂的行」分开计）
_MNEMONICS = frozenset("""
adc add addw adr and asr b bfc bfi bic bkpt bl blx bx cbnz cbz cdp clrex clz cmn cmp cps
cpsid cpsie dbg dmb dsb eor eref eret hlt isb it ite itet ittt itttt ldc ldm ldmia ldmdb
ldmia ldr ldrb ldrbt ldrh ldrsb ldrsh ldrt lea lsl lsr mcr mcrr mla mls mov movs movt movw
mrc mrrc mrs msr mul mvn neg nop orn orr pkhbt pkhtb pld pli pop push qadd qadd16 qadd8
qasx qdadd qdsub qsax qsub qsub16 qsub8 rbit rev rev16 revsh ror rrx rsb rsc sadd16 sadd8
sasx sbc sbfx sdiv sel setend sev shadd16 shadd8 shasx shsax shsub16 shsub8 smc smlad
smladx smlal smlald smlaldx smlalxy smlaltb smlaltbb smlaltt smlalbt smlawb smlawt smlsd
smlsld smlsldx smmla smmlar smmls smmlsr smmul smmulr smuad smuadx smulbb smulbt smull
smultb smultt smulwb smulwt smusd smusdx srs ssat ssat16 ssax ssub16 ssub8 stc stm stmia
stmdb str strb strbt strh strt sub subw svc swp swpb sxtab sxtab16 sxtah sxtb sxtb16 sxth
tbb tbh teq tst uadd16 uadd8 uasx ubfx udf udiv uhadd16 uhadd8 uhasx uhsax uhsub16 uhsub8
umaal umlal uls umull uqadd16 uqadd8 uqasx uqsax uqsub16 uqsub8 usad8 usada8 usat usat16
usax usub16 usub8 uxtab uxtab16 uxtah uxtb uxtb16 uxth vabs vadc vadd vaddhn vand vbic
vcls vclz vcmp vcvt vcvtr vdiv vext vfma vfms vfnma vfnms vhadd vhsub vldm vldr vmax vmin
vmla vmlal vmls vmlsl vmov vmovl vmovn vmrs vmsr vmul vneg vnmla vnmls vnmul vorn vorr
vpack vpadd vpaddl vpmax vpmin vpop vpush vqabs vqadd vqdmlal vqdmlsl vqdmulh vqdmull vqmovn
vqmovun vqneg vqrdmulh vqrshl vqrshrn vqrshrun vqshl vqshlu vqshrn vqshrun vqsub vraddhn
vrecpe vrecps vrev16 vrev32 vrev64 vrhadd vrinta vrintm vrintn vrintp vrintr vrintx vrintz
vrshl vrshrn vrshr vrsqrte vrsqrts vrsra vrsubhn vsadd vsbdt vsel vshl vshll vshr vshrn
vsli vsqrt vsra vssub vstm vstr vsub vsubhn vsubl vsubw vswp vtbx vtbl vtrn vtst vuzp vzip
vldmia vldmdb vldmib vldmda vstmia vstmdb vstmib vstmda vpst vplt adr.w movw movt ldr.w str.w
""".split())

#: armasm 里能跟在**名字后面**的指令（`Name PROC` / `Name EQU 5` / `Name DCD ...`）——
#: armasm 的语法是「名字在列 1、指令缩进」，去掉缩进后只能靠这张表把两截分开。
_ARM_OPS = frozenset("""
proc endp endfunc macro mend equ seta setl sets setg set rn space fill align dcd dci dcq
dcw dcb dcfs dcfd dcfdu dcpu dcu map field ltorg assert info keep nobt nofp require
preserve8 export import extern include get area entry end code code16 code32 data gbla
gbll gbls in frame fpu arch cpu option
""".split())

#: 汇编器指令全集（armasm + GNU as 常见集）；用于「整行只有一个词」时区分裸标签
_DIRECTIVES = frozenset(set(_ARM_OPS) | set("""
text section global weak type size thumb_func thumb_set func begin endm rept endr irp
endrp while endw else elif endif if ifdef ifndef ifb ifnb ifeq ifne ifc ifnc ifge ifgt
ifle iflt word long quad short byte ascii asciz string octa single double float zero skip
org abort err error warning print title subtitle psize eject list nolist llist
thumb require8 endfunction endregion armattr attribute
public pubweak section module rout alignrom arm dc32 dc8 dc16 dc64
""".split()))

#: 条件后缀（`MRSEQ` / `VLDMIAEQ` / `BEQ` …）——判断「这是不是一条指令」时要能剥掉
_COND_SUFFIX = re.compile(r"^(.*?)(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$")

def _is_mnemonic(op):
    """这条 token 是不是一条指令（含条件后缀 / `S` 后缀 / `EQ` 这类变体）。

    为什么要这层：`unparsed_lines` 是**诚实指标**（「有多少行没看懂」），如果连
    `MRSEQ R0, MSP`、`VLDMIAEQ R0!, {S16-S31}` 这种正常指令都算「没看懂」，
    这个数字就会虚高到毫无意义——那就成了一条自欺的统计。
    """
    if op in _MNEMONICS:
        return True
    base = op[:-1] if op.endswith("s") else op          # MOVS / ADDS / SUBS …
    if base != op and base in _MNEMONICS:
        return True
    m = _COND_SUFFIX.match(base or op)
    return bool(m and m.group(1) and m.group(1) in _MNEMONICS)

#: 条件汇编的开/闭记号（armasm 用 IF/ELSE/ELIF/ENDIF，GNU 用 .if/.ifdef/... /.endif）
_COND_OPEN = frozenset(("if", "ifdef", "ifndef", ".if", ".ifdef", ".ifndef", ".ifb",
                        ".ifnb", ".ifeq", ".ifne", ".ifc", ".ifnc", ".ifge", ".ifgt",
                        ".ifle", ".iflt"))
_COND_MID = frozenset(("else", "elif", ".else", ".elseif", ".elseifc"))
_COND_CLOSE = frozenset(("endif", ".endif"))
_MACRO_CLOSE = frozenset(("mend", ".endm"))

#: 一个合法的（可查的）符号名：不要 GNU 的 `.L…` 局部标签与数字局部标签
_RE_NAME_OK = re.compile(r"^[A-Za-z_|$][\w.$|]*$")
_RE_REG = re.compile(r"^(R\d{1,2}|R1[0-5]|LR|PC|SP|FP|IP|SL|SB)$", re.I)
_RE_INCLUDE = re.compile(r"^\s*#?\s*include\s+[\"<]([^\">]+)[\">]", re.I)
#: `LDR Rn, =sym`——**必须带 `=`**：不带等号的 `LDR R0, R1` 是寄存器传送，
#: 不写死这个条件就会把每条寄存器装载都记成「取了 R1 的地址」（假 fptr）。
_RE_LDR_LIT = re.compile(r"^\s*LDR\s+(R\d{1,2}|R1[0-5]|LR|PC|SP|FP|IP|SL|SB)\s*,\s*=\s*"
                         r"([A-Za-z_|$][\w.$|]*)\s*$", re.I)
#: `ADR Rn, sym`——取地址没有「寄存器传送」这个歧义，但源必须是名字不是寄存器
_RE_ADR = re.compile(r"^\s*ADR(?:\.W)?\s+(R\d{1,2}|R1[0-5]|LR|PC|SP|FP|IP|SL|SB)\s*,\s*"
                     r"([A-Za-z_|$][\w.$|]*)\s*$", re.I)
_RE_CALL_REG = re.compile(r"^\s*(BL|BLX)(?:\.W)?\s+(R\d{1,2}|R1[0-5]|LR|PC|SP)\s*$", re.I)
_RE_CALL_SYM = re.compile(r"^\s*(BL|BLX)(?:\.W)?\s+([A-Za-z_|$][\w.$|]*)\s*$", re.I)
_RE_BRANCH = re.compile(r"^\s*B(?:\.W)?\s+([A-Za-z_|$][\w.$|]*)\s*$", re.I)
_RE_DATA = re.compile(r"^\s*(DCD|DCI|DCQ|DC32|DC64|DC16|DC8|\.word|\.long|\.quad)\s+(.+)$",
                       re.I)
_RE_TYPEDECL = re.compile(r"^\s*([A-Za-z_|$][\w.$|]*)\s*,\s*([^,]+)\s*$")

def _decode(src):
    """汇编注释常是 GBK（Keil 老工程）。先 UTF-8，失败再 GBK，最后容错解码——名字都是
    ASCII，容错只影响注释文本，不会造出错名字。"""
    for enc in ("utf-8", "gbk"):
        try:
            return src.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return src.decode("utf-8", "replace"), "utf-8/replace"

def _dialect(text):
    """按出现的指令认方言。认不出时按 **armasm** 处理（MDK 的 `.s` 绝大多数是 armasm），
    并把判定结果记进返回体，让上层能如实显示。"""
    low = text.lower()
    gnu = sum(low.count(k) for k in (".text", ".section", ".globl", ".global",
                                     ".macro", ".endm", ".type", ".thumb_func",
                                     ".extern", ".align", ".word", ".long"))
    ar = sum(low.count(k) for k in ("area ", " proc", " endp", "mend", "export ",
                                    "import ", "endfunc", "preserve8", "\tdcd"))
    if gnu > ar:
        return "gnu"
    return "armasm"

def _strip_comment(line, dialect, block=False):
    """去掉注释，返回 (代码串, 是否仍在块注释里)。`;`/`//`/`/* */` 两种方言都认；`@` 只在
    GNU 方言下当注释 —— armasm 里 `#` 是立即数前缀（`#0x10`）不是注释，所以 `#` 一律不当注释。

    块注释状态要**跨行**传递：`/*` 开在上一行、`*/` 关在下一行时，只按单行判断就会把
    注释中间那几行当成真实代码（也正是「看似权威的错答案」的一种）。"""
    out, i, n = [], 0, len(line)
    while i < n:
        if block:
            j = line.find("*/", i)
            if j < 0:
                return "".join(out), True
            block = False
            i = j + 2
            continue
        two = line[i:i + 2]
        if two == "/*":
            block = True
            i += 2
            continue
        ch = line[i]
        if ch == ";" or two == "//":
            break
        if ch == "@" and dialect == "gnu":
            break
        out.append(ch)
        i += 1
    return "".join(out), block

def _clean(name):
    return name.strip().strip("|").strip()

def parse(src, rel):
    """解析一份汇编 → 与 tree-sitter 路径**同形状**的记录字典（额外多几个 asm 专属字段）。

    src 为 bytes；返回 dict 与 parser.extract 的 C/C++ 分支同键名，另加
    dialect / enc / unnamed_indirect_calls / unparsed_lines。
    """
    text, enc = _decode(src)
    dialect = _dialect(text)
    raw_lines = text.split("\n")

    # 先把**续行**合成逻辑行：armasm/CMSIS 的启动文件里满是
    #     HardFault_Handler\
    #                     PROC
    # 这种写法，不合并的话标签会变成 `HardFault_Handler\`（一个带反斜杠的假名字），
    # 而 `PROC` 单独一行又什么都不产生 —— 整张中断处理函数表会静默丢掉。
    logical = []                     # [(起始行号, 代码串)]
    _carry, _start, _block = None, None, False
    for idx, raw in enumerate(raw_lines):
        code, _block = _strip_comment(raw, dialect, _block)
        if _carry is None:
            _carry, _start = code, idx + 1
        else:
            _carry = _carry + " " + code
        if _carry.rstrip().endswith("\\"):
            _carry = _carry.rstrip()[:-1]
            continue
        logical.append((_start, _carry))
        _carry = None
    if _carry is not None:
        logical.append((_start, _carry))

    symbols, includes, calls, fptrs = [], [], [], []
    seen = set()
    cond_depth = 0
    func = None
    macro = None
    exported, imported, func_names = set(), set(), set()
    pending_thumb_func = False
    regmap = {}                      # 本段内 `LDR Rn, =sym` / `ADR Rn, sym` 的结果
    unnamed_indirect = 0
    skipped = 0
    skipped_samples = []
    branches = []                   # `B sym` 候选：收尾时只有目标是 IMPORT 才算尾调用

    def add_sym(name, kind, line, is_def=1, storage=None):
        nm = _clean(name)
        if not nm:
            return None
        key = (nm, line)
        if key in seen:
            return None
        seen.add(key)
        s = {"name": nm, "kind": kind, "start_line": line, "end_line": line,
             "start_col": 0, "end_col": 0, "signature": None,
             "is_definition": is_def, "storage": storage,
             "parent": None, "in_conditional": cond_depth > 0,
             "body_start": line if is_def else None, "body_end": None, "path": rel}
        symbols.append(s)
        return s

    def add_call(line, callee, via_pointer, col=0):
        calls.append({"line": line, "col": col, "callee": _clean(callee),
                      "in_conditional": cond_depth > 0,
                      "via_pointer": bool(via_pointer)})

    def add_fptr(name, line, decl):
        fptrs.append({"name": _clean(name), "line": line, "decl": decl})

    for ln, code in logical:
        raw = code
        stripped = code.strip()
        if not stripped:
            continue
        toks = stripped.split()
        t0 = toks[0]
        low0 = t0.lower()

        # ---- 宏体：整段跳过（含体里的 IF/ENDIF，否则会把外层 cond_depth 带歪；
        #      也含体里的 bl，展开点不在宏定义处，记下来就是个假调用者）
        if low0 in _MACRO_CLOSE:
            if macro is not None:
                macro["body_end"] = ln
                macro = None
            continue
        if macro is not None:
            continue

        # ---- 条件汇编（先算，后面记录的 in_conditional 才准）
        if low0 in _COND_OPEN:
            cond_depth += 1
            continue
        if low0 in _COND_MID:
            continue
        if low0 in _COND_CLOSE:
            cond_depth = max(0, cond_depth - 1)
            continue

        # ---- 拆出 名字 / 指令：三种形态
        #   (a) `Name:` / `Name: op ...`      —— 冒号标签
        #   (b) `Name OP ...`（armasm）        —— 名字在前，op 在 _ARM_OPS 里
        #   (c) `OP ...` / 裸标签              —— 指令在前
        label, body = None, stripped
        if t0.endswith(":"):
            label = t0[:-1]
            body = stripped[len(t0):].lstrip()
        elif len(toks) >= 2 and toks[1].lower() in _ARM_OPS:
            label = t0
            body = stripped[len(t0):].lstrip()
        elif (len(toks) == 1 and not _is_mnemonic(low0) and low0 not in _DIRECTIVES
              and _RE_NAME_OK.match(_clean(t0))):
            label = t0
            body = ""
        rt = body.split()
        op = rt[0].lower() if rt else None
        args = rt[1:]

        # ---- 宏开始：`name MACRO` / `.macro name`
        if op in ("macro", ".macro"):
            nm = label or (args[0].split(",")[0] if args else None)
            macro = add_sym(nm, "macro_fn", ln)
            continue

        # ---- `Name ENDP` / 光杆 `ENDP`：闭合当前函数（**必须在处理 label 之前**，
        #      否则 `Name ENDP` 会被当成又一次「定义 Name」）
        if op in ("endp", "endfunc"):
            if func is not None:
                func["body_end"] = ln
                func = None
            regmap = {}
            continue

        # ---- `Name RN 0`：寄存器别名，不是符号
        if op == "rn":
            continue

        # ---- include
        if op in ("get", "include") and args:
            includes.append({"target": _clean(args[0].strip("\"<>")), "is_system": False,
                             "line": ln, "in_conditional": cond_depth > 0})
            continue
        if op == ".include" and args:
            includes.append({"target": _clean(body.split(None, 1)[1].strip("\"<>")),
                             "is_system": False, "line": ln,
                             "in_conditional": cond_depth > 0})
            continue
        m = _RE_INCLUDE.match(stripped)
        if m:
            includes.append({"target": _clean(m.group(1)), "is_system": False, "line": ln,
                             "in_conditional": cond_depth > 0})
            continue

        # ---- EXPORT / IMPORT / .globl / .type / .thumb_func
        if op in ("export", "global", ".globl", ".global"):
            for t in args:
                exported.add(_clean(t.rstrip(",")))
            continue
        # IAR 的 `PUBLIC` / `PUBWEAK` 只是「这个名字是全局的」（weak 定义也在这里）；
        # 注意它**不能**当函数定义——PUBWEAK 后面跟的可能是函数也可能是数据，汇编层面看不出。
        if op in ("public", "pubweak"):
            for t in args:
                exported.add(_clean(t.rstrip(",")))
            continue
        if op in ("import", "extern", ".extern", ".global"):
            for t in args:
                nm = _clean(t.rstrip(","))
                imported.add(nm)
                add_sym(nm, KIND_IMPORT, ln, is_def=0, storage="import")
            continue
        if op == ".type" and args:
            m = _RE_TYPEDECL.match(" ".join(args))
            if m and "function" in m.group(2).lower():
                func_names.add(_clean(m.group(1)))
            continue
        if op == ".thumb_func":
            pending_thumb_func = True
            continue
        if op == ".thumb_set" and args:
            func_names.add(_clean(args[0].split(",")[0]))
            continue
        if op in (".equ", ".set", ".equiv") and args and label is None:
            add_sym(args[0].split(",")[0], KIND_LABEL, ln, storage="constant")
            continue

        # ---- 标签（含函数判定）与 armasm 的 `Name EQU …`
        if label is not None:
            nm = _clean(label)
            if nm and _RE_NAME_OK.match(nm):
                if op in ("equ", "seta", "setl", "sets", "setg", "set"):
                    add_sym(nm, KIND_LABEL, ln, storage="constant")
                    continue
                is_func = (pending_thumb_func or nm in func_names
                           or op in ("proc", "function", "func"))
                pending_thumb_func = False
                regmap = {}
                s = add_sym(nm, KIND_FUNC if is_func else KIND_LABEL, ln,
                            storage="global" if nm in exported else None)
                if is_func and s is not None:
                    func = s
                if op is None:
                    continue
            else:
                regmap = {}
                if op is None:
                    continue

        if op in ("proc", "function", "func"):
            regmap = {}
            continue

        # ---- 取地址 → 进 fptr 表（间接调用的**证据**，不是结论）
        m = _RE_LDR_LIT.match(body)
        if m and not _RE_REG.match(m.group(2)):
            regmap[m.group(1).upper()] = m.group(2)
            add_fptr(m.group(2), ln, " ".join(body.split())[:160])
            continue
        m = _RE_ADR.match(body)
        if m and not _RE_REG.match(m.group(2)):
            regmap[m.group(1).upper()] = m.group(2)
            add_fptr(m.group(2), ln, " ".join(body.split())[:160])
            continue

        # ---- 调用（**先认寄存器**：`BL R2` 里的 `R2` 也长得像标识符，
        #      先走符号式正则就会把它记成「调用了一个叫 R2 的函数」这种假名字）
        m = _RE_CALL_REG.match(body)
        if m:
            tgt = regmap.get(m.group(2).upper())
            if tgt:
                add_call(ln, tgt, True, col=len(raw) - len(raw.lstrip()))
            else:
                unnamed_indirect += 1
            continue
        m = _RE_CALL_SYM.match(body)
        if m:
            add_call(ln, m.group(2), False, col=len(raw) - len(raw.lstrip()))
            continue
        m = _RE_BRANCH.match(body)
        if m:
            branches.append({"line": ln, "callee": _clean(m.group(1)),
                             "col": len(raw) - len(raw.lstrip()),
                             "in_conditional": cond_depth > 0})
            continue

        # ---- 数据指针（DCD sym / .word sym）→ fptr 表
        m = _RE_DATA.match(body)
        if m:
            for item in m.group(2).split(","):
                item = item.strip()
                if _RE_NAME_OK.match(item) and item.lower() not in _DIRECTIVES:
                    add_fptr(item, ln, " ".join(body.split())[:160])
            continue

        # ---- 不关心的指令/指令符：看懂但不需要记（**不算「没看懂的行」**）。
        #      `op.startswith(".")` = GNU 的伪指令（.syntax/.cpu/.size/.ident/…），
        #      一行行去列它们没有意义，而把 `.syntax unified` 算成「没看懂」是错的。
        if op is None or _is_mnemonic(op) or op in _DIRECTIVES or op.startswith("."):
            continue
        skipped += 1
        if len(skipped_samples) < 10:
            skipped_samples.append({"line": ln, "text": stripped[:120]})

    # `B sym`（无条件跳转）只在目标是 **IMPORT/EXTERN 进来的外部符号** 时才记成调用点：
    # 外部的 `B` 不可能是本文件里的循环/条件分支，只能是把控制权交出去（尾调用，
    # SVC/PendSV 入口很爱这么写）。本文件内的 `B label` 一律不记——那是循环和分支，
    # 把它画成调用图就是一份看着完整的假图。这条判据是**故意保守**的。
    for b in branches:
        if b["callee"] in imported:
            calls.append({"line": b["line"], "col": b["col"], "callee": b["callee"],
                          "in_conditional": b["in_conditional"], "via_pointer": False})

    # 收尾：没 ENDP 的函数体到文件末
    for s in symbols:
        if s["kind"] == KIND_FUNC and s["body_end"] is None:
            s["body_end"] = len(raw_lines)

    # 「被 bl 指向的标签」升格为函数：这是**本文件内的词法事实**（bl 的目标是代码入口），
    # 比「所有标签都是函数」保守得多，也让 callees 的「调用者归属」有落点。
    called = {c["callee"] for c in calls if not c["via_pointer"]}
    for s in symbols:
        if s["kind"] == KIND_LABEL and s["name"] in called:
            s["kind"] = KIND_FUNC
            s["body_start"] = s["body_start"] or s["start_line"]
            if s["body_end"] is None:
                s["body_end"] = len(raw_lines)

    # 调用者归属：最内层**函数**（PROC/bl 目标/标注函数）优先；否则最内层标签 region
    # （标签到下一个标签之间）；找不到就不给 caller（不许编一个）。
    funcs = [s for s in symbols if s["kind"] == KIND_FUNC and s["is_definition"]]
    labels = [s for s in symbols if s["kind"] == KIND_LABEL]
    regions = sorted(((s["start_line"], s) for s in labels))
    for i, (st, s) in enumerate(regions):
        s["_region_end"] = regions[i + 1][0] - 1 if i + 1 < len(regions) else len(raw_lines)

    for c in calls:
        best = None
        for s in funcs:
            if s["start_line"] <= c["line"] <= (s["body_end"] or s["end_line"]):
                if best is None or s["start_line"] > best["start_line"]:
                    best = s
        if best is None:
            for s in labels:
                if s["start_line"] <= c["line"] <= s.get("_region_end", s["start_line"]):
                    if best is None or s["start_line"] > best["start_line"]:
                        best = s
        c["caller"] = best["name"] if best else None
    for s in symbols:
        s.pop("_region_end", None)

    # 行数口径与 C/C++ 分支一致（末尾换行不额外算一行，空文件 0 行）
    lines = src.count(b"\n") + (0 if (src.endswith(b"\n") or not src) else 1)
    return {"symbols": symbols, "includes": includes, "calls": calls,
            "refs": [], "fptrs": fptrs,
            "lines": lines,
            # 行式解析没有「解析失败」这个概念：恒 0，且**不代表**这份汇编被完全理解（见模块说明）
            "parse_error": False,
            "normalized": False,
            "dialect": dialect, "enc": enc,
            "unnamed_indirect_calls": unnamed_indirect, "unparsed_lines": skipped,
            "unparsed_samples": skipped_samples}
