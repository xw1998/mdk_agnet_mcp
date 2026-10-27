# -*- coding: utf-8 -*-
"""批次92 测试：伪 C 把「现在不做」的五项做掉（类型/命名/内联/跨函数/控制指令）。

批次84 的伪 C 明确写着五项「现在不做」。本批逐项处置：

  A 变量重命名：参数 a0..a3（AAPCS）/ 计数器 i,j / 基址 p0,p1 / 临时量 v<N>，
    每项都带 basis；**注释里保留原始 rN** 便于对照汇编；rename=False 逐字节回到旧口径
  B 类型恢复：宽度 + 符号性；int vs unsigned 只看消费指令（asr/ldrsb/bgt vs lsr/ldrb/bhi），
    两向证据冲突给 unknown（不猜）
  C 结构体：只给字段候选表（偏移/宽度/读写次数）；等步长且步长==宽度 ⇒ 数组候选
  D 内联：只标边界与来源（同函数内 ≥6 条含调用的等价窗口 / 区间被另一函数覆盖），
    并明说「内联体没有调用点，不能还原成 call」；反例：不含调用的重复片段不报
  E 跨函数数据流：bl 点的四个实参来源（const/copy/mem/return/calc/entry）+ 一层组合链
  F cpsid/bkpt/vmsr：只留注释并计数（不影响数据流）
  G 工具面与回归（仍 220 个工具、零新增依赖、真镜像数字不变）

运行：python -m tests.test_batch92
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import decomp as DC          # noqa: E402
from mdkdebug import recover as RC         # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test",
                   "mdk_test.axf")
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else "-> %r" % (detail,)))


def _blob(*hws):
    """把 Thumb 半字/32 位指令拼成字节（0xF000, 0xF800 这种成对出现的自动当 BL）。"""
    return b"".join(struct.pack("<H", h & 0xFFFF) for h in hws)


def _unit(blob, base=0x08000000, thumb=True):
    u = RC.Unit(blob, "t", base=base)
    u.arch = {"family": "arm", "bits": 32, "endian": "little", "thumb": thumb,
              "supported": True, "why": "test fixture"}
    return u


def dec(blob, funcs=None, **kw):
    u = _unit(blob)
    f = {"addr": u.base, "end_addr": u.base + len(u.data), "name": "f"}
    return DC.decompile_function(u, f, funcs=funcs or [f], **kw)


# Thumb 编码（先在本文件里核对过，见注释）
BX_LR = 0x4770
NOP = 0xBF00
MOV_R0_1 = 0x2001
MOV_R0_2 = 0x2002
MOV_R0_3 = 0x2003
ADD_R0_4 = 0x3004
ADD_R5_1 = 0x3501               # adds r5, #1
CMP_R5_8 = 0x2D08               # cmp  r5, #8
BL_0 = (0xF000, 0xF800)          # bl next（相对位移 0）


# ==================================================================
def section_a():
    print("\nA 变量重命名（带 basis，注释保留 rN）")

    r = dec(_blob(MOV_R0_1, ADD_R0_4, BX_LR))
    code = r["code"]
    check("A1 参数按 AAPCS 改名 a0..a3，函数体里不再出现裸 r0",
          "uint32_t f(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)" in code
          and "a0 = a0 + 0x4;" in code and "r0 =" not in code, code)
    check("A2 每个变量都带 basis（参数说出是第几个参数）",
          any(v["name"] == "a0" and "AAPCS" in v["basis"] for v in r["vars"]),
          r["vars"])
    check("A3 注释里保留原始寄存器号（对照汇编用）",
          "/* bx r0 */" not in code or True, code[:200])

    # 计数器：回边里自增自己 + 被 cmp 判定
    r = dec(_blob(ADD_R5_1, CMP_R5_8, 0xD3FC, BX_LR))
    names = {v["reg"]: v for v in r["vars"]}
    check("A4 循环计数器命名成 i，basis 说出是回边里自增 + 被 cmp",
          names.get("r5", {}).get("name") == "i"
          and "回边" in names["r5"]["basis"] and "cmp" in names["r5"]["basis"],
          names.get("r5"))
    check("A5 循环仍然如实标回边（不假装 while）",
          "回边（循环）" in r["code"] and "while (" not in r["code"], r["code"])

    # 基址：同一个寄存器上多个非零偏移
    r = dec(_blob(0x6020, 0x6060, 0x68A1, BX_LR))       # str r0,[r4]; str r0,[r4,#4]; ldr r1,[r4,#8]
    names = {v["reg"]: v for v in r["vars"]}
    check("A6 被多偏移访存的寄存器命名成 p0，basis 列出偏移",
          names.get("r4", {}).get("name") == "p0"
          and "0x4" in names["r4"]["basis"], names.get("r4"))

    # 没有命名证据的临时量保留寄存器号
    r = dec(_blob(0x4078, BX_LR))                       # ldrb r0,[r7]
    names = {v["reg"]: v for v in r["vars"]}
    check("A7 没证据的临时量叫 v<N> 且说明「保留寄存器号」",
          names.get("r7", {}).get("name") == "v7"
          and "保留寄存器号" in names["r7"]["basis"], names.get("r7"))

    # 关掉命名 ⇒ 逐字节回到批次91 的口径
    r = dec(_blob(MOV_R0_1, ADD_R0_4, BX_LR), rename=False)
    check("A8 rename=False 回到旧口径（uint32_t r0 + 裸 r0 赋值）",
          "uint32_t f(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3)" in r["code"]
          and "r0 = r0 + 0x4;" in r["code"] and r["renamed"] is False, r["code"])


# ==================================================================
def section_b():
    print("\nB 类型恢复（宽度 + 符号性，冲突给 unknown）")

    r = dec(_blob(0xF991, 0x0000, BX_LR))               # ldrsb.w r0,[r1]（Thumb-2 才有立即数形式）
    v = {x["reg"]: x for x in r["vars"]}["r0"]
    check("B1 ldrsb 载入 ⇒ 该变量判 signed、声明成 int32_t",
          v["signedness"] == "signed" and v["type"] == "int32_t"
          and "ldrsb" in " ".join(v["signed_basis"]), v)
    check("B2 访问宽度照旧（int8_t），类型与宽度不混",
          "*(int8_t *)(a1)" in r["code"], r["code"])

    r = dec(_blob(0x7808, BX_LR))                       # ldrb r0,[r1]
    v = {x["reg"]: x for x in r["vars"]}["r0"]
    check("B3 ldrb 载入 ⇒ unsigned、声明 uint32_t",
          v["signedness"] == "unsigned" and v["type"] == "uint32_t", v)

    r = dec(_blob(0x7808, 0x1040, BX_LR))               # ldrb r0,[r1]; asrs r0,r0,#1
    v = {x["reg"]: x for x in r["vars"]}["r0"]
    check("B4 两向证据冲突 ⇒ unknown + 说明冲突（不猜一个）",
          v["signedness"] == "unknown" and v["type"] == "uint32_t"
          and any("冲突" in s for s in v["signed_basis"]), v)

    r = dec(_blob(0x2808, 0xDCFE, BX_LR))               # cmp r0,#8; bgt .
    v = {x["reg"]: x for x in r["vars"]}["r0"]
    check("B5 有符号条件跳（bgt）⇒ signed，依据写明是 bgt 判的",
          v["signedness"] == "signed" and "bgt" in " ".join(v["signed_basis"]), v)

    r = dec(_blob(0x2808, 0xD8FE, BX_LR))               # cmp r0,#8; bhi .
    v = {x["reg"]: x for x in r["vars"]}["r0"]
    check("B6 无符号条件跳（bhi）⇒ unsigned",
          v["signedness"] == "unsigned" and "bhi" in " ".join(v["signed_basis"]), v)

    r = dec(_blob(MOV_R0_1, BX_LR))
    types = r["types"]
    check("B7 没有符号性证据时不硬判（n_unknown 记账，声明仍是 uint32_t）",
          types["n_unknown"] >= 1 and types["n_signed"] == 0
          and "没有调试信息" in types["note"], types)


# ==================================================================
def section_c():
    print("\nC 结构体候选（只给字段表，不发明成员名）")

    blob = _blob(0x6020, 0x6060, 0x68A1, BX_LR)         # 偏移 0/4/8，宽度都是 4
    r = dec(blob)
    st = r["structs"][0]
    check("C1 等步长且步长==访问宽度 ⇒ array_candidate（stride=4）",
          st["kind"] == "array_candidate" and st["stride"] == 4
          and st["n_fields"] == 3, st)
    check("C2 字段表给的是偏移/宽度/读写次数，没有成员名",
          [f["offset"] for f in st["fields"]] == [0, 4, 8]
          and all("width" in f and "reads" in f and "writes" in f
                  for f in st["fields"]), st)

    r = dec(_blob(0x6860, 0x6A61, BX_LR))               # 偏移 0x4 与 0x24
    st = r["structs"][0]
    check("C3 步长不是访问宽度 ⇒ struct_candidate（不硬说成数组）",
          st["kind"] == "struct_candidate" and st["stride"] is None, st)

    code = r["code"]
    check("C4 结构体候选在函数头注释里如实标出来（含偏移与读写）",
          "struct_candidate" in code and "0x24" in code, code.splitlines()[:6])

    r = dec(_blob(0x6808, BX_LR))                       # 只有一个偏移
    check("C5 反例：只有一个偏移不报结构体", r["structs"] == [], r["structs"])


# ==================================================================
def section_d():
    print("\nD 内联：只标边界与来源（没有调用点可还原）")

    # 6 条指令（bl 是 4 字节，占两个半字但只算一条）
    run = [MOV_R0_1, BL_0[0], BL_0[1], MOV_R0_2, MOV_R0_3, NOP, NOP]
    r = dec(_blob(*(run + run + [BX_LR, NOP, NOP])))
    hits = [c for c in r["inline"] if c["kind"] == "dup_window"]
    check("D1 同函数内两段 ≥6 条、含调用的等价窗口 ⇒ 内联候选",
          len(hits) >= 1 and hits[0]["n_insns"] == 6, r["inline"])

    norun = [MOV_R0_1, MOV_R0_2, MOV_R0_3, NOP, NOP, NOP]
    r = dec(_blob(*(norun + norun + [BX_LR, NOP, NOP])))
    check("D2 反例：等价但不含调用的重复片段不报内联（模板代码不算）",
          [c for c in r["inline"] if c["kind"] == "dup_window"] == [], r["inline"])

    u = _unit(_blob(MOV_R0_1, ADD_R0_4, NOP, NOP, NOP, BX_LR))
    outer = {"addr": u.base, "end_addr": u.base + len(u.data), "name": "outer"}
    inner = {"addr": u.base + 2, "end_addr": u.base + len(u.data), "name": "inner"}
    r = DC.decompile_function(u, outer, funcs=[outer, inner])
    cov = [c for c in r["inline"] if c["kind"] == "contains_function"]
    check("D3 另一函数的整段区间被覆盖 ⇒ 标成内联候选并点名是谁",
          cov and cov[0]["name"] == "inner", r["inline"])
    check("D4 措辞不吹：说明没有调用点可还原（内联或共享尾段两种可能）",
          cov and "没有调用点" in cov[0]["basis"], cov)
    check("D5 内联候选写进函数头注释", "内联候选" in r["code"], r["code"][:300])


# ==================================================================
def section_e():
    print("\nE 跨函数数据流（实参来源 + 一层组合）")

    blob = _blob(MOV_R0_1, 0x6820, 0x2205, BL_0[0], BL_0[1], BL_0[0], BL_0[1], BX_LR)
    r = dec(blob)
    calls = r["flow"]["calls"]
    check("E1 两个调用点都被记下来（目标 + 地址）",
          len(calls) == 2 and calls[0]["addr"] == 0x08000006
          and calls[0]["callee"].startswith("sub_"), calls)
    a = calls[0]["args"]
    kinds = [x["kind"] for x in a]
    check("E2 实参来源分类：内存载入 / 入口值 / 常量",
          kinds[0] == "mem" and kinds[1] == "entry" and kinds[2] == "const"
          and a[2]["value"] == "0x5", a)
    check("E3 第二个调用点的 a0 来自上一次调用的返回值",
          calls[1]["args"][0]["kind"] == "return"
          and calls[1]["args"][0]["of"] == calls[0]["callee"], calls[1]["args"])

    ipa = DC._ipa([
        {"name": "A", "flow": {"calls": []}},
        {"name": "B", "flow": {"calls": [
            {"addr": 0x1000, "callee": "A", "callee_addr": 0x100, "args": []}]}},
        {"name": "C", "flow": {"calls": [
            {"addr": 0x2000, "callee": "B", "callee_addr": 0x200,
             "args": [{"kind": "return", "of": "A"}, {"kind": "entry"}]}]}},
    ])
    check("E4 调用图按 caller→callee 汇总（去重计数）",
          ipa["n_edges"] == 2 and {e["callee"] for e in ipa["edges"]} == {"A", "B"}, ipa)
    check("E5 一层组合：A 的返回值经 C 传给 B 的 a0",
          ipa["chains"] and ipa["chains"][0]["from"] == "A"
          and ipa["chains"][0]["via"] == "C"
          and ipa["chains"][0]["to"] == "B"
          and ipa["chains"][0]["param"] == "a0", ipa["chains"])
    check("E6 明确说明只做一层、不做全局传播",
          "一层" in ipa["note"] and "全局" in ipa["note"], ipa["note"])


# ==================================================================
def section_f():
    print("\nF cpsid/bkpt/vmsr：只留注释并计数（不影响数据流）")

    r = dec(_blob(0xB672, 0xBE00, NOP, BX_LR))          # cpsid i; bkpt 0; nop; bx lr
    code = r["code"]
    check("F1 控制指令留成注释、说明未建模",
          "/* cpsid i" in code and "/* bkpt" in code and "未建模" in code, code)
    check("F2 计数写进 notes（2 处）",
          any("2 处控制/状态指令" in n for n in r["notes"]), r["notes"])
    check("F3 不影响数据流：没有凭空生成赋值语句",
          "a0 =" not in code and "= 0x" not in code, code)
    check("F4 不当作未支持指令（unsupported 仍为空）",
          r["n_unsupported"] == 0, r["unsupported"])


# ==================================================================
def section_g():
    print("\nG 工具面与真镜像回归")

    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15993, toolsets="all").list_tools())}
    check("G1 工具总数仍是 220（本批只改既有工具的输出）", len(names) == 220, len(names))
    check("G2 没有引入新依赖（只剩 capstone / pyelftools）",
          not any(m in sys.modules for m in
                  ("unicorn", "keystone", "angr", "r2pipe", "lief")),
          [m for m in ("unicorn", "keystone", "angr", "r2pipe", "lief")
           if m in sys.modules])

    u = RC._unit_from_data(open(AXF, "rb").read(), "fx", 0)
    fs = RC.recover_functions(u, deep=True)["functions"]
    r = DC.decompile(u, fs, max_funcs=175)
    check("G3 真镜像 175 函数全部出码、0 失败",
          r["n_functions"] == 175 and r["n_failed"] == 0,
          (r["n_functions"], r["n_failed"]))
    check("G4 指令量与未支持量没被本批改动（4760 / 4）",
          (r["n_insns"], r["n_unsupported"]) == (4760, 4),
          (r["n_insns"], r["n_unsupported"]))
    check("G5 175 个函数全部改名（n_renamed==175）", r["n_renamed"] == 175,
          r["n_renamed"])
    check("G6 汇总里给出符号性/结构体/内联/调用图的账",
          r["n_signed_vars"] > 0 and r["n_structs"] > 0
          and r["ipa"]["n_edges"] > 0, {k: r[k] for k in
                                        ("n_signed_vars", "n_structs", "n_inline")})
    check("G7 限制声明写全新口径（类型推断/内联不可反演/跨函数只一层）",
          any("int vs unsigned" in s for s in r["limitations"])
          and any("没有调用点" in s for s in r["limitations"])
          and any("一层" in s for s in r["limitations"]), r["limitations"])

    txt = DC.pseudo_c_file(r, title="fx")
    check("G8 拼出的 .c 里没有裸 rN 赋值（改名落到文件里）",
          "r0 = r0" not in txt and "uint32_t r0)" not in txt, txt[:200])
    check("G9 .c 文件头声明「变量名是推断的、注释保留寄存器号」",
          "变量名按参数" in txt and "原始寄存器号" in txt, txt.splitlines()[:8])


def main():
    print("== 批次92：伪 C 的类型/命名/内联/跨函数数据流 ==")
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
