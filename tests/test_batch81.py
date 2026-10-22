# -*- coding: utf-8 -*-
"""批次81 测试：吸收 Ghidra 的分析口径（函数体形状 / AAPCS 调用约定 / thunk），零新依赖。

来由：用户提到「NSA 开源的逆向工具」，即 Ghidra。它的反编译器要 400 MB 安装 + JDK 21，
把一个「有 Keil 就能跑」的工具变成有前提的工具，用户明确要求**不要增加依赖**。
于是只吸收它**怎么看代码**的两条口径，用现有 capstone 自己实现：

  · 函数体到**终止指令**为止（返回 / 跳出本区间的无条件跳转 / 间接跳转），
    不是「切到下一个已知入口」；
  · 按 AAPCS 看 r0..r3 的**首次访问是读还是写**估参数个数（并估有无返回值）；
  · 整条函数只有一条跳到别处的无条件跳转 ⇒ thunk。

  A 形状：返回终止 / 尾调用 / 循环内的 b 不终止 / 间接跳转 / thunk / 空区间
  B 参数：读前写 / 先写 / 中间断档 / 返回值证据
  C 真镜像端到端：形状分布、参数分布、thunk 落在函数集合、边界不变式、CSV/头文件/report
  D 默认输出不变性：without with_regs 时不出现 reads/writes（老调用方逐字节不变）
  E 工具面：没有新增工具（用户要求不增依赖，工具数不变）

运行：python -m tests.test_batch81
"""
import asyncio
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC           # noqa: E402

EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []
_TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def _tmpdir(prefix="mdk81_"):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


def ins(addr, mnemonic, op_str="", size=2, **kw):
    """造一条反汇编记录（和 disassemble() 产出的结构一致）。"""
    rec = {"addr": addr, "addr_hex": "0x%08X" % addr, "mnemonic": mnemonic,
           "op_str": op_str, "bytes": "00" * size, "size": size}
    rec.update(kw)
    return rec


# ==================================================================
def section_a():
    print("\nA 函数体形状（口径：到终止指令为止）")

    # A1 以返回结束：函数体应当结束在 pop {pc} 之后，而不是切到 0x08000100
    code = {0x08000000: ins(0x08000000, "push", "{r4, lr}"),
            0x08000002: ins(0x08000002, "movs", "r0, #1"),
            0x08000004: ins(0x08000004, "pop", "{r4, pc}", ends_function=True),
            0x08000006: ins(0x08000006, "movs", "r0, #2")}
    sh = RC._shape_function(code, 0x08000000, 0x08000100)
    check("A1 以返回结束的函数，body_basis=return 且 end 在返回指令之后",
          sh["body_basis"] == "return" and sh["end_addr"] == 0x08000006, sh)

    # A2 跳出本区间的无条件跳转 = 尾调用（不是「函数没结束」）
    code = {0x08000000: ins(0x08000000, "b.w", "0x08000900", size=4,
                            target=0x08000900, target_hex="0x08000900")}
    sh = RC._shape_function(code, 0x08000000, 0x08000100)
    check("A2 跳到区间外的 b 判为尾调用，body 结束在该跳转之后",
          sh["body_basis"] == "tail_call" and sh["end_addr"] == 0x08000004
          and sh["terminals"][0]["target_hex"] == "0x08000900", sh)

    # A3 区间内的向后跳（循环）不算终止
    code = {0x08000000: ins(0x08000000, "movs", "r0, #0"),
            0x08000002: ins(0x08000002, "adds", "r0, #1"),
            0x08000004: ins(0x08000004, "b", "0x08000002", target=0x08000002),
            0x08000006: ins(0x08000006, "bx", "lr", ends_function=True)}
    sh = RC._shape_function(code, 0x08000000, 0x08000010)
    check("A3 循环内的 b 不终止函数体（最后仍以 return 结束）",
          sh["body_basis"] == "return" and sh["end_addr"] == 0x08000008, sh)

    # A4 间接跳转（bx r4，不是 bx lr）= 函数体在此结束
    code = {0x08000000: ins(0x08000000, "bx", "r4")}
    sh = RC._shape_function(code, 0x08000000, 0x08000010)
    check("A4 bx 到非 lr 寄存器判为间接跳转（body 到此结束）",
          sh["body_basis"] == "indirect_branch" and sh["end_addr"] == 0x08000002, sh)

    # A5 thunk：整条函数只有一条跳转
    code = {0x08000000: ins(0x08000000, "b.w", "0x08000301", size=4,
                            target=0x08000301)}
    sh = RC._shape_function(code, 0x08000000, 0x08000010)
    check("A5 单条 b 到别的函数 ⇒ is_thunk 意义上的 thunk_to（且去掉 Thumb 位）",
          sh["thunk_to"] == 0x08000300, sh)

    # A6 没有任何指令：如实说「没有指令」，不给假边界
    sh = RC._shape_function({}, 0x08000000, 0x08000010)
    check("A6 区间里没有指令时 body_basis=no_instructions（不假装分析过）",
          sh["body_basis"] == "no_instructions", sh)


# ==================================================================
def section_b():
    print("\nB 调用约定（AAPCS：r0..r3 首次访问是读还是写）")

    # B1 读 r0、读 r1 ⇒ 2 参
    code = {0x0: ins(0x0, "cmp", "r0, #0", reads=["r0"]),
            0x2: ins(0x2, "mov", "r2, r1", reads=["r1"], writes=["r2"])}
    h = RC._arg_hint(code, 0, 0x10)
    check("B1 先读 r0/r1 ⇒ 2 参", h["params"] == 2, h)

    # B2 先写 r0 ⇒ 0 参（r0 是局部变量）
    code = {0x0: ins(0x0, "movs", "r0, #0", writes=["r0"])}
    h = RC._arg_hint(code, 0, 0x10)
    check("B2 r0 先被写 ⇒ 0 参", h["params"] == 0, h)
    check("B2b r0 先被写 ⇒ 返回值证据为 likely_value",
          h["returns"] == "likely_value", h)

    # B3 读 r0/r1、但 r2 先写 ⇒ 断在 r2，仍是 2 参
    code = {0x0: ins(0x0, "push", "{r0, r1}", reads=["r0", "r1"]),
            0x2: ins(0x2, "movs", "r2, #0", writes=["r2"]),
            0x4: ins(0x4, "ldr", "r3, [r2]", reads=["r2"], writes=["r3"])}
    h = RC._arg_hint(code, 0, 0x10)
    check("B3 中间寄存器先写时断档，参数个数不越过它", h["params"] == 2, h)

    # B4 从头到尾没碰 r0 ⇒ 返回值 unknown（不猜 void）
    code = {0x0: ins(0x0, "push", "{r4, lr}", reads=["r4", "lr"])}
    h = RC._arg_hint(code, 0, 0x10)
    check("B4 完全没碰 r0 ⇒ returns=unknown（不武断判 void）",
          h["returns"] == "unknown" and h["params"] == 0, h)


# ==================================================================
def section_c():
    print("\nC 真镜像端到端（example_mdk_project 的 axf）")
    if not os.path.isfile(EXAMPLE_AXF):
        check("C0 示例 axf 存在（缺失则整段跳过）", False, EXAMPLE_AXF)
        return
    an = RC.analyze(EXAMPLE_AXF, deep=True)
    check("C1 analyze 成功", an.get("ok") is True, an.get("error"))
    if not an.get("ok"):
        return
    rec = an["_recover"]
    funcs = rec["functions"]
    shape = rec.get("shape") or {}
    cnt = shape.get("counts") or {}
    check("C2 形状统计里既有 return 终止也有尾调用（不是全切到下一个入口）",
          cnt.get("return", 0) > 0 and cnt.get("tail_call", 0) > 0, cnt)
    check("C3 每个函数的参数估计落在 0..4（AAPCS 只有 r0..r3）",
          all(0 <= (f.get("params_estimate") or 0) <= 4 for f in funcs),
          [f.get("params_estimate") for f in funcs][:12])
    thunks = [f for f in funcs if f.get("is_thunk")]
    known = {f["addr"] for f in funcs}
    check("C4 识别出的 thunk 都指向另一个已知函数入口",
          bool(thunks) and all((f.get("thunk_to") or 0) in known for f in thunks),
          [(f["name"], f.get("thunk_to_hex")) for f in thunks])
    # 边界不变式：**控制流推出来的**边界不许越过下一个入口。
    # 符号表给的 size 不在此列：ARM 的链接器符号本来就会大过相邻的局部符号
    # （__scatterload_null 就落在 __scatterload_rt2_thumb_only 的 size 范围内），
    # 那是符号表的原话，不是我们算错。
    addrs = sorted(f["addr"] for f in funcs)
    pos = {a: i for i, a in enumerate(addrs)}
    bad = []
    for f in funcs:
        i = pos[f["addr"]]
        nxt = addrs[i + 1] if i + 1 < len(addrs) else None
        if f["end_addr"] <= f["addr"]:
            bad.append((f["name"], "end<=start"))
        elif f.get("size_basis") != "symtab" and nxt is not None \
                and f["end_addr"] > nxt:
            bad.append((f["name"], hex(f["end_addr"]), hex(nxt)))
    check("C5 控制流推出的函数体边界不越过下一个入口（符号表给的 size 不受此约束）",
          not bad, bad[:5])
    gaps = " ".join(str(g.get("reason") or "") for g in (rec.get("gaps") or []))
    check("C6 gaps 里明说参数/返回值是推断（不冒充类型信息）",
          "推断" in gaps and "AAPCS" in gaps, gaps[:200])

    d = os.path.join(_tmpdir(), "proj")
    out = RC.build_project(EXAMPLE_AXF, d, include_asm=True)
    check("C7 recover_project 成功且文件回读校验通过",
          out.get("ok") and out.get("sha256_verified") is True, out.get("error"))
    if not out.get("ok"):
        return
    fcsv = open(os.path.join(d, "map", "functions.csv"), encoding="utf-8").read()
    head = fcsv.splitlines()[0]
    check("C8 functions.csv 表头保留原有列序，新列追加在末尾",
          head.startswith("addr,end_addr,name")
          and head.endswith("body_basis,params,returns,thunk_to"), head)
    hdr = open(os.path.join(d, "include", "recovered_symbols.h"),
               encoding="utf-8").read()
    check("C9 符号头注释带「推断 n 参」（但不改原型声明）",
          "推断" in hdr and "参/" in hdr and "void " in hdr and "(void);" in hdr,
          hdr[:300])
    check("C10 函数记录带 body_basis/params_estimate/returns_estimate",
          bool(funcs) and all("body_basis" in f and "params_estimate" in f
                              and "returns_estimate" in f for f in funcs[:20]),
          list(funcs[0])[:12] if funcs else "empty")
    rep = json.loads(open(os.path.join(d, "report.json"), encoding="utf-8").read())
    check("C11 report.json 的 shape.basis 写明口径（含 thunk 计数）",
          "终止指令" in (rep.get("shape") or {}).get("basis", "")
          and isinstance((rep.get("shape") or {}).get("thunks"), int),
          rep.get("shape"))


# ==================================================================
def section_d():
    print("\nD 默认输出不变性（with_regs 默认关）")
    if not os.path.isfile(EXAMPLE_AXF):
        check("D0 示例 axf 存在", False, EXAMPLE_AXF)
        return
    r1 = RC.disasm_at(EXAMPLE_AXF, start=0x08000000, end=0x08000010)
    insns = (r1.get("insns") or [])
    check("D1 默认反汇编记录里没有 reads/writes（老输出逐字节不变）",
          bool(insns) and all("reads" not in i and "writes" not in i for i in insns),
          insns[:1])
    unit = RC._unit_from_data(open(EXAMPLE_AXF, "rb").read(), EXAMPLE_AXF, 0)
    r2 = RC.disassemble(unit, 0x08000000, 0x08000020, with_regs=True)
    has = [i for i in (r2.get("insns") or []) if "reads" in i and "writes" in i]
    check("D2 with_regs=True 时带寄存器读写集合（且非空集合真的出现）",
          bool(has) and any(i["reads"] or i["writes"] for i in has), r2.get("error"))


# ==================================================================
def section_e():
    print("\nE 工具面（不新增依赖也就不新增工具）")

    from mdkdebug import server as SV
    tools = asyncio.run(SV.create_server(port=15881, toolsets="all").list_tools())
    names = {t.name for t in tools}
    check("E1 工具总数 214（本批次不加工具；+1 来自批次86 recover_diff）",
          len(names) == 214, len(names))
    check("E2 没有引入 Ghidra 相关工具",
          not any("ghidra" in n.lower() for n in names),
          [n for n in names if "ghidra" in n.lower()])


# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d, section_e):
        fn()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
