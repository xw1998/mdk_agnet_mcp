# -*- coding: utf-8 -*-
"""批次93 测试：伪 C 的指令集不再只有 Cortex-M（ARM）——加 RISC-V / MIPS / ARM 模式。

做法是**翻译层**而不是另写提升器：`mdkdebug/lift_isa.py` 把 RISC-V/MIPS 指令翻成
「ARM 形状的统一 IR」（mov/add/ldr/str/cmp+bcond/bl/bx lr），再喂给同一个提升器。
所以类型恢复、变量命名、结构体候选、内联边界、跨函数数据流对三个家族全部生效。

  A RISC-V：算术/访存/条件分支/ret → 结构化伪 C + 调用约定（a0..a3 / 返回值 a0）
  B RISC-V：零寄存器不是变量（写 x0 = 丢弃）、lui、div、压缩指令未支持、控制指令
  C RISC-V：结构体候选 / 符号性 / 跨函数调用实参
  D MIPS：分支延迟槽提到分支之前（语义）、jr $ra、lui、slt（绝对值目标）
  E ARM 模式（ARMv5/ARM9）：push/pop、ldm、bx lr、movw/movt、bl
  F 闸门：不可翻译的家族要明确拒绝并给理由；工具面仍 214；零新增依赖

夹具全是手写字节，**不依赖工具链**；编码在写之前用 capstone 逐条核对过。
运行：python -m tests.test_batch93
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import decomp as DC          # noqa: E402
from mdkdebug import lift_isa as LI        # noqa: E402
from mdkdebug import recover as RC         # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else "-> %r" % (detail,)))

def rv(*ws):
    """RISC-V 32 位小端指令。"""
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in ws)

def rv16(*hs):
    """RISC-V 压缩（16 位）指令。"""
    return b"".join(struct.pack("<H", h & 0xFFFF) for h in hs)

def mips(*ws):
    """MIPS32 大端指令。"""
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)

def arm(*ws):
    """ARM 模式小端 32 位指令。"""
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in ws)

def unit(blob, fam, base=0x08000000, endian="little", thumb=False):
    u = RC.Unit(blob, "t", base=base)
    u.arch = {"family": fam, "bits": 32, "endian": endian, "thumb": thumb,
              "supported": True, "why": "test fixture"}
    return u

def dec(blob, fam, base=0x08000000, endian="little", **kw):
    u = unit(blob, fam, base=base, endian=endian)
    f = {"addr": u.base, "end_addr": u.base + len(u.data), "name": "f"}
    return DC.decompile_function(u, f, funcs=[f], **kw)

# ==================================================================
# RISC-V 编码（capstone 5.0.7 核对：addi a0,zero,1 / lw a1,4(a0) / ...）
RV_ADDI_A0_ZERO_1 = 0x00100513
RV_LW_A1_4_A0 = 0x00452583
RV_SW_A1_8_A0 = 0x00B52423
RV_BEQ_A0_A1_8 = 0x00B50463
RV_ADDI_A0_A0_1 = 0x00150513
RV_RET = 0x00008067
RV_LUI_A0_1 = 0x00001537
RV_DIV_A0_A0_A1 = 0x02B54533
RV_MRET = 0x30200073
RV_LB_A0_0_A1 = 0x00058503          # 有符号字节装载
RV_LBU_A0_0_A1 = 0x0005C503         # 无符号字节装载
RV_SB_A1_0_A0 = 0x00B50023
RV_JAL_RA_8 = 0x008000EF
RV_C_SUB_A0_A1 = 0x8D0D             # 压缩指令 c.sub（RVC 常态）
RV_AMOADD_A0_A1_A2 = 0x0B6252F      # 原子指令（翻译层没覆盖：读改写没建模）
RV_ADDI_ZERO_ZERO_1 = 0x00100013

# MIPS 编码（大端）
MP_ADDIU_V0_ZERO_1 = 0x24020001
MP_LW_A1_4_A0 = 0x8C850004
MP_BEQ_A0_A1_2 = 0x10850002         # 目标 = pc+4+8
MP_ADDIU_A0_A0_1 = 0x24840001
MP_ADDIU_A0_A0_2 = 0x24840002
MP_JR_RA = 0x03E00008
MP_NOP = 0x00000000
MP_LUI_A0_1234 = 0x3C041234
MP_SLT_V0_A0_A1 = 0x0085102A

# ARM 模式编码（小端）
A_MOV_R0_1 = 0xE3A00001
A_ADD_R1_R2_R3 = 0xE0821003
A_LDR_R0_R1_4 = 0xE5910004
A_STR_R0_R1_8 = 0xE5810008
A_CMP_R0_0 = 0xE3500000
A_BEQ_8 = 0x0A000002
A_MOVW_R0_1234 = 0xE3010234
A_MOVT_R0_5678 = 0xE3410234
A_BL_16 = 0xEB000004
A_PUSH_R4_LR = 0xE92D4010
A_POP_R4_PC = 0xE8BD8010
A_LDM_R0_R1_R2 = 0xE8B00006
A_BX_LR = 0xE12FFF1E

# ==================================================================
def section_a():
    print("\nA RISC-V：算术 / 访存 / 条件分支 / ret")
    blob = rv(RV_ADDI_A0_ZERO_1, RV_LW_A1_4_A0, RV_SW_A1_8_A0,
              RV_BEQ_A0_A1_8, RV_ADDI_A0_A0_1, RV_RET)
    r = dec(blob, "riscv", base=0x1000)
    code = r.get("code") or ""
    check("A1 能出码且没有未支持指令", r.get("ok") and r.get("n_unsupported") == 0,
          r.get("error") or r.get("unsupported"))
    check("A2 签名按 RISC-V psABI（a0..a3）",
          "uint32_t f(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)" in code,
          code.splitlines()[-8:])
    check("A3 addi a0,zero,1 → a0 = 0x1", "a0 = 0x1;" in code, code)
    check("A4 lw → 指针解引用（基址 + 位移）",
          "*(uint32_t *)(a0 + 0x4)" in code, code)
    check("A5 sw → 内存写", ("*(uint32_t *)(a0 + 0x8) = a1;" in code), code)
    check("A6 beq → if (a0 != a1) 结构化", "if (a0 != a1) {" in code, code)
    check("A7 ret → return a0; /* bx lr */",
          "return a0;" in code and "bx lr" in code, code)
    check("A8 notes 写明家族与翻译（不是逐字节照抄 ARM）",
          any("riscv 家族" in s for s in r.get("notes") or []), r.get("notes"))
    check("A9 头部注释的调用约定按 psABI",
          any("bl 按 RISC-V psABI" in s for s in r.get("notes") or [])
          or "bl 按 RISC-V psABI" in code, (r.get("notes"), code[:400]))

def section_b():
    print("\nB RISC-V：零寄存器 / lui / div / 压缩指令 / 控制指令")
    r = dec(rv(RV_ADDI_ZERO_ZERO_1, RV_RET), "riscv", base=0x1000)
    code = r.get("code") or ""
    check("B1 写 x0 的结果丢弃（不给 zero 分配变量）",
          "结果丢弃" in code and "uint32_t zero" not in code, code)
    check("B2 丢弃处计数（n_discard / notes）",
          r.get("n_discard") == 1
          and any("写零寄存器" in s for s in r.get("notes") or []),
          (r.get("n_discard"), r.get("notes")))

    r = dec(rv(RV_LUI_A0_1, RV_RET), "riscv", base=0x1000)
    check("B3 lui a0,0x1 → a0 = 0x1000（高 20 位左移 12）",
          "a0 = 0x1000;" in (r.get("code") or ""), r.get("code"))

    r = dec(rv(RV_DIV_A0_A0_A1, RV_RET), "riscv", base=0x1000)
    check("B4 div → 带符号除法表达式（并有「除零未建模」）",
          "a0 = (int32_t)a0 / (int32_t)a1;" in (r.get("code") or "")
          and "除零未建模" in (r.get("code") or ""), r.get("code"))

    r = dec(rv16(RV_C_SUB_A0_A1) + rv(RV_RET), "riscv", base=0x1000)
    code = r.get("code") or ""
    check("B5 压缩指令 c.sub（2 字节）能解出来并译成减法",
          "a0 = a0 - a1;" in code and r.get("n_skipped") == 0, code)

    r = dec(rv(RV_AMOADD_A0_A1_A2, RV_RET), "riscv", base=0x1000)
    code = r.get("code") or ""
    check("B5b 翻不动的形态留痕并计数（不静默丢）",
          r.get("ok") and r.get("n_unsupported") == 1
          and "未支持: amoadd.w" in code, (r.get("n_unsupported"), code))

    r = dec(rv(RV_MRET, RV_RET), "riscv", base=0x1000)
    check("B6 控制/状态指令只留注释并计数",
          any("控制/状态指令" in s for s in r.get("notes") or [])
          and "mret" in (r.get("code") or ""), (r.get("notes"), r.get("code")))

def section_c():
    print("\nC RISC-V：结构体候选 / 符号性 / 跨函数调用")
    blob = rv(RV_LW_A1_4_A0, RV_SW_A1_8_A0, RV_LB_A0_0_A1,
              RV_LBU_A0_0_A1, RV_JAL_RA_8, RV_RET)
    r = dec(blob, "riscv", base=0x1000)
    code = r.get("code") or ""
    st = r.get("structs") or []
    check("C1 a0 上有字段候选（偏移/宽度/读写次数）",
          bool(st) and st[0].get("base") == "a0"
          and len(st[0].get("fields") or []) >= 2,
          st)
    check("C2 lb（有符号字节）→ int8_t 宽度",
          "int8_t" in code, code)
    check("C3 bl 行用 a0..a3 传参、返回值落 a0",
          "a0 = sub_00001018(a0, a1, a2, a3);" in code, code)
    check("C4 调用点数据流仍然工作（flow.calls 有实参来源）",
          bool((r.get("flow") or {}).get("calls")), r.get("flow"))

    # 第 5 个及以后的参数槽（a4..a7）不在签名里，但**必须**当局部变量声明，
    # 否则源码里会出现一个没声明的名字（C 编译器直接报错，读者也追不到来源）
    r = dec(rv(0x00178793, 0x00148493, RV_RET), "riscv", base=0x1000)  # a5+=1; s1+=1
    c = r.get("code") or ""
    check("C5 签名外的 ABI 寄存器照样声明（a5/s1）",
          "uint32_t" in c and " a5" in c and "s1" in c
          and "uint32_t f(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)" in c, c)

def section_d():
    print("\nD MIPS：分支延迟槽 / jr $ra / lui / slt")
    # beq 在 0x1008，目标 0x1014（跳过 0x1010 的 a0+2）；延迟槽在 0x100C
    blob = mips(MP_ADDIU_V0_ZERO_1, MP_LW_A1_4_A0, MP_BEQ_A0_A1_2,
                MP_ADDIU_A0_A0_1, MP_ADDIU_A0_A0_2, MP_JR_RA, MP_NOP)
    r = dec(blob, "mips", base=0x1000, endian="big")
    code = r.get("code") or ""
    check("D1 能出码且没有未支持指令", r.get("ok") and r.get("n_unsupported") == 0,
          r.get("error") or r.get("unsupported"))
    check("D2 延迟槽被提到分支之前（语义正确：a0+1 先执行）",
          "a0 = a0 + 0x1;" in code and "分支延迟槽" in " ".join(r.get("notes") or []),
          (code, r.get("notes")))
    i_delay = code.find("a0 = a0 + 0x1;")
    i_cmp = code.find("/* cmp a0, a1 */")
    i_br = code.find("if (a0 != a1)")
    check("D3 顺序是 延迟槽 → cmp → 分支", 0 <= i_delay < i_cmp < i_br,
          (i_delay, i_cmp, i_br, code))
    check("D4 jr $ra → return v0（返回值在 v0）",
          "return v0;" in code and "bx lr" in code, code)
    check("D5 延迟槽里的 nop 被丢掉、且不虚报搬动次数",
          (r.get("notes") or []) and
          any("1 处分支延迟槽" in s for s in r.get("notes") or []),
          r.get("notes"))
    check("D6 签名按 o32（a0..a3）",
          "uint32_t f(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)" in code,
          code[:400])

    r2 = dec(mips(MP_LUI_A0_1234, MP_SLT_V0_A0_A1, MP_JR_RA, MP_NOP),
             "mips", base=0x1000, endian="big")
    c2 = r2.get("code") or ""
    check("D7 lui → 高 16 位左移", "a0 = 0x12340000;" in c2, c2)
    check("D8 slt → 带符号比较表达式",
          "v0 = (int32_t)a0 < (int32_t)a1 ? 1 : 0;" in c2, c2)

def section_e():
    print("\nE ARM 模式（ARMv5/ARM9）")
    blob = arm(A_PUSH_R4_LR, A_MOV_R0_1, A_ADD_R1_R2_R3, A_LDR_R0_R1_4,
               A_STR_R0_R1_8, A_CMP_R0_0, A_BEQ_8, A_MOVW_R0_1234,
               A_MOVT_R0_5678, A_BL_16, A_POP_R4_PC)
    r = dec(blob, "arm", base=0x1000)
    code = r.get("code") or ""
    check("E1 ARM 模式能出码且没有未支持指令",
          r.get("ok") and r.get("n_unsupported") == 0,
          r.get("error") or r.get("unsupported"))
    check("E2 mov/add 正常", "a0 = 0x1;" in code and "a1 = a2 + a3;" in code, code)
    check("E3 push/pop 译成 sp 偏移访存 + 返回",
          "sp -= 4;" in code and "return a0;" in code, code)
    check("E4 movw/movt 拼成常量",
          "a0 = 0x1234;" in code and "<< 16" in code, code)
    check("E5 bl → 调用（返回值落 r0）",
          "a0 = sub_0000103C(a0, a1, a2, a3);" in code, code)
    check("E6 ARM 模式判定要求 4 字节对齐（11 条指令爬完 0x2C）",
          r.get("n_insns") == 11, r.get("n_insns"))

    u = unit(arm(A_LDM_R0_R1_R2, A_BX_LR), "arm", base=0x1000)
    f = {"addr": u.base, "end_addr": u.base + len(u.data), "name": "g"}
    r2 = DC.decompile_function(u, f, funcs=[f])
    check("E7 ldm/bx lr（ARM 模式的多寄存器装载与返回）",
          r2.get("ok") and "0x6" not in (r2.get("code") or "").split("ldm")[0]
          and "return" in (r2.get("code") or ""), r2.get("code"))

def section_f():
    print("\nF 闸门：家族拒绝 / 工具面 / 零新增依赖")
    r = dec(rv(RV_RET), "arm64")
    check("F1 arm64 明确拒绝并说明理由（64 位模型）",
          r.get("ok") is False and "arm64" in (r.get("error") or "")
          and "64 位" in (r.get("error") or ""), r.get("error"))
    r = dec(rv(RV_RET), "x86_64")
    check("F2 x86_64 明确拒绝，且列出可用家族（含 riscv / mips）",
          r.get("ok") is False and "x86_64" in (r.get("error") or "")
          and "riscv" in (r.get("error") or "") and "mips" in (r.get("error") or ""),
          r.get("error"))
    r = dec(rv(RV_RET), "unknown")
    check("F3 架构未判定 → 拒绝并说「不猜」",
          r.get("ok") is False and "不猜" in (r.get("error") or ""), r.get("error"))
    check("F4 家族描述符字段齐全（命名/参数/返回/链接/栈/ABI）",
          all(k in LI.descriptor(f) for f in ("arm", "riscv", "mips")
              for k in ("naming", "arg_slots", "arg_names", "ret_name",
                        "link_name", "stack_name", "abi")),
          [f for f in ("arm", "riscv", "mips") if not LI.descriptor(f)])
    check("F5 liftable 只放行三个家族（其余都走 refusal）",
          all(LI.liftable(f) for f in ("arm", "riscv", "mips"))
          and not any(LI.liftable(f) for f in ("arm64", "x86", "ppc", "m68k")),
          [f for f in ("arm64", "x86", "ppc", "m68k") if LI.liftable(f)])

    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15994, toolsets="all").list_tools())}
    check("F6 工具总数仍是 214（本批只改既有工具的行为）",
          len(names) == 214, len(names))
    check("F7 没有引入新依赖（反汇编/翻译只用 capstone + struct）",
          not any(m in sys.modules for m in
                  ("unicorn", "keystone", "angr", "r2pipe", "lief")),
          [m for m in ("unicorn", "keystone", "angr", "r2pipe", "lief")
           if m in sys.modules])
    _src = open(LI.__file__, encoding="utf-8").read()
    check("F8 lift_isa 不 import capstone（翻译层只吃 IR，解码是别人干）",
          "import capstone" not in _src, [l for l in _src.splitlines()
                                          if "import capstone" in l])

    import tempfile
    _blob = rv(RV_ADDI_A0_ZERO_1, RV_RET)
    _p = os.path.join(tempfile.gettempdir(), "b93_rv_fixture.bin")
    open(_p, "wb").write(_blob)
    d = RC.disasm_at(_p, base=0x1000, start=0x1000, end=0x1008,
                     arch="riscv", fmt="c")
    check("F9 recover_disasm(fmt='c') 端到端通，限制文案按家族写",
          d.get("ok") and any("RISC-V psABI" in s
                              for s in d.get("limitations") or []),
          (d.get("error"), d.get("limitations")))
    os.remove(_p)

def main():
    print("== 批次93：伪 C 支持 RISC-V / MIPS / ARM 模式 ==")
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
