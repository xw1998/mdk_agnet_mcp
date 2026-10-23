# -*- coding: utf-8 -*-
"""批次84 测试：寄存器级伪 C 反编译器（吸收 Ghidra 的反编译面，零新依赖）。

Ghidra 最贵的一层是反编译器：把指令提升成带表达式、结构化控制流、并能标明
「哪些是保真的、哪些是推断的」的伪 C。没有这一层，逆向出来的只有反汇编文本，
读代码的人得自己在脑子里做数据流。本批次把这一层做进 mdkdebug：

  A 口径（条件码/进位/表项数/名字清洗）
  B 指令提升（访存宽度、位域、乘加、长乘、字节反转、IT 块）
  C 控制流（switch、if/else、循环回边、比较链）
  D 跳转表：按守卫条件定项数 + 表数据剔除（不把表字节当指令）
  E 真镜像端到端（175 函数，未支持如实标注）
  F 批量/写文件/错误路径
  G 工具面：215 个工具、不增依赖（+1 来自批次86）
  H 接入面：recover_disasm(fmt="c") / recover_project 的 src/pseudo_c.c

运行：python -m tests.test_batch84
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import decomp as DC           # noqa: E402
from mdkdebug import reveng as RV           # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "decomp", "decomp_fx.axf")
EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


_CACHE = {}


def load(path):
    """读镜像 → (unit, funcs, decompile 结果, {name: 结果})。"""
    if path in _CACHE:
        return _CACHE[path]
    data, err = RC._read_file(path)
    unit = RC._unit_from_data(data, path, 0)
    funcs = RC.recover_functions(unit, deep=True)["functions"]
    res = DC.decompile(unit, funcs, max_funcs=len(funcs))
    by = {it["name"]: it for it in res["functions"]}
    _CACHE[path] = (unit, funcs, res, by)
    return _CACHE[path]


# ==================================================================
def section_a():
    print("\nA 口径（条件码 / 进位 / 表项数 / 名字）")

    check("A1 _hex 三种形态", (DC._hex(0), DC._hex(0x1F), DC._hex(-1))
          == ("0x0", "0x1F", "-0x1"), DC._hex(-1))
    check("A2 _base_mn 只去 .w/.n 后缀", DC._base_mn("adds.w") == "adds"
          and DC._base_mn("mov.n") == "mov", DC._base_mn("adds.w"))
    check("A3 _branch_cond：b 无条件 / bls 是 ls / bl 与 bx 不是分支条件",
          DC._branch_cond("b") == "" and DC._branch_cond("bls") == "ls"
          and DC._branch_cond("bl") is None and DC._branch_cond("bx") is None)
    check("A4 _split_cond 四种形态（base / base+cond / base+s / base+s+cond）",
          DC._split_cond("bics") == ("bic", "")
          and DC._split_cond("subshs") == ("sub", "hs")
          and DC._split_cond("addeq") == ("add", "eq")
          and DC._split_cond("add") == ("add", ""))
    check("A5 bls 不被拆成 bl+s（是 b+ls，不是带 flags 的 bl）",
          DC._split_cond("bls") == ("b", "ls"), DC._split_cond("bls"))
    check("A6 _sets_flags 认 .w 后缀 / 条件+s 组合，且不误判 bls",
          DC._sets_flags("subs.w") and DC._sets_flags("subshs")
          and DC._sets_flags("rrxs") and not DC._sets_flags("sub.w")
          and not DC._sets_flags("bls"))
    check("A7 _c_name 清洗非法字符与数字开头",
          DC._c_name("HAL_Init", "") == "HAL_Init"
          and DC._c_name("1bad", "") == "_1bad"
          and DC._c_name("", "fb") == "fb")
    check("A8 进位表达式：加法的进位 / 减法的无借位",
          "uint64_t" in DC._carry_of_add("a", "b")
          and ">> 32" in DC._carry_of_add("a", "b")
          and ">=" in DC._carry_of_sub("a", "b"))
    check("A9 移位对 C 位：#1 取 bit0 / #0 保持 / 寄存器量未知 / #32 为 0",
          DC._shift_carry("lsr", "v", "0x1") == "((uint32_t)(v) >> 0) & 1"
          and DC._shift_carry("lsl", "v", "0x0") == "keep"
          and DC._shift_carry("lsl", "v", "r2") is None
          and DC._shift_carry("lsl", "v", "0x20") == "0",
          DC._shift_carry("lsr", "v", "0x1"))
    check("A10 _it_conds 的模式来自助记符（ite eq ⇒ [eq, ne]）",
          DC._it_conds("ite", "eq") == ["eq", "ne"], DC._it_conds("ite", "eq"))
    check("A11 找不到 flags 生产者时不猜，返回 flag_<cond>",
          DC._cond_text("hs", None) == "flag_hs"
          and DC._cond_text("eq", {"kind": "cmp", "a": "r0", "b": "0x0"})
          == "r0 == 0x0")
    r = DC._table_ranges([{"kind": "tbb", "table_addr": 0x08001000,
                           "n_cases": 4}])
    check("A12 表范围按项宽算（tbb 1 字节/项）",
          r == [(0x08001000, 0x08001004, "tbb 跳转表 4 项")], r)
    check("A13 表长超过安全上限时不剥（推断值不可信）",
          DC._table_ranges([{"kind": "ldr_pc_table", "table_addr": 0x08001000,
                             "n_cases": 4000}]) == [])


# ==================================================================
def section_b():
    print("\nB 指令提升（真 armcc 编译的夹具）")
    _unit, _fs, res, by = load(FX)

    check("B0 夹具 13 个函数全部出码、0 未支持",
          res["n_functions"] == 13 and res["n_failed"] == 0
          and res["n_unsupported"] == 0,
          (res["n_functions"], res["n_failed"], res["n_unsupported"]))

    f = by["field_stuff"]["code"]
    check("B1 ubfx 提升成「右移+掩码」", "(a0 >> 5) & 0x1FF" in f, f)
    check("B2 sbfx 提升成「左移+掩码+算术右移」",
          ">> (32 - 12)" in f and "(int32_t)" in f, f)

    f = by["mac"]["code"]
    check("B3 mla 提升成「加+乘」且不丢累加项",
          "a0 = a0 + a1 * a2;" in f and "/* mla */" in f, f)

    f = by["wide_mul"]["code"]
    check("B4 umull 提升成 64 位中间变量（无空括号 (uint64_t)()）",
          "uint64_t _t" in f and "(uint64_t)()" not in f
          and "_t >> 32" in f, f)

    f = by["revbytes"]["code"]
    check("B5 rev 提升成四段字节拼接",
          ">> 24" in f and "<< 24" in f and "/* rev */" in f, f)

    f = by["use_struct"]["code"]
    check("B6 访存宽度按指令给（uint32_t / uint16_t / uint8_t）",
          "*(uint32_t *)(a0)" in f and "*(uint16_t *)(a0 + 0x4)" in f
          and "*(uint8_t *)(a0 + 0x9)" in f, f)

    f = by["carry_flags"]["code"]
    check("B7 无符号比较标注出来、有符号才加 int32_t",
          "a0 >= 0x10000 /* 无符号 */" in f, f)

    f = by["it_block"]["code"]
    check("B8 IT 块展开成 if，且不出现裸条件码 if (eq)",
          "if (eq)" not in f and f.count("if (") >= 2, f)

    f = by["swap32"]["code"]
    check("B9 3 操作数移位（移位量走操作数）不丢移位",
          "(a0 >> 8) & 0xFF" in f and "(a2 << 16)" in f, f)


# ==================================================================
def section_c():
    print("\nC 控制流（switch / if-else / 循环 / 比较链）")
    _unit, _fs, res, by = load(FX)

    f = by["dispatch"]["code"]
    cases = [ln for ln in f.splitlines() if ln.strip().startswith("case ")]
    check("C1 tbb 跳转表恢复成 switch，8 个 case",
          "switch (a0)" in f and len(cases) == 8, (len(cases), f[:400]))
    labels = {ln.strip().rstrip(":") for ln in f.splitlines()
              if ln.strip().startswith("L_")}
    tgt = {ln.split("goto ")[1].split(";")[0] for ln in cases}
    check("C2 每个 case 的目标都有标签（goto 有落点）", tgt <= labels,
          sorted(tgt - labels))
    check("C3 表长取守卫上界（bhs ⇒ cmp #8 是 8 项，不越界多出 case 8）",
          "case 8" not in f and "⇒ 8 项" in f, f[:400])

    f = by["sparse_switch"]["code"]
    check("C4 稀疏 switch 保留比较链（不硬造 switch）",
          "switch (" not in f and "if (a0 == 0x1) goto" in f
          and "if (a0 == 0x28) goto" in f, f)

    f = by["while_loop"]["code"]
    check("C5 循环保留 goto 并标回边（不假装成 while）",
          "/* 回边（循环） */" in f and "while (" not in f, f)

    f = by["sum_arr"]["code"]
    check("C6 先跳后体的循环布局不丢入口标签",
          "goto L_" in f and "L_0800005E:" in f, f)

    f = by["divmod"]["code"]
    check("C7 单块 if 结构化（条件用相反条件包裹）",
          by["divmod"]["n_structured"] >= 1 and "if (a1 != 0x0) {" in f, f)

    check("C8 夹具内没有「条件找不到 flags」的降级（结构自由但语义确定）",
          sum(it["n_flag_unresolved"] for it in res["functions"]) == 0)


# ==================================================================
def section_d():
    print("\nD 跳转表：项数与表数据")
    _unit, _fs, res, by = load(FX)
    f = by["dispatch"]
    check("D1 表数据被剔除并如实记账",
          any("跳转表数据按数据剔除" in n for n in f["notes"]), f["notes"])
    check("D2 表字节不再被反汇编成伪指令",
          "r4 = r0 << 0x18" not in f["code"]
          and "r6 = r1 >> 0x4" not in f["code"], f["code"][:400])
    check("D3 指令数按剔除后统计（21 条，不是 25 条）", f["n_insns"] == 21,
          f["n_insns"])
    check("D4 表内所有 case 目标都在函数里展开（没有越界目标）",
          f["n_outside_targets"] == 0, f["n_outside_targets"])

    unit, funcs, _res, _by = load(FX)
    recs = {i.address: {"addr": i.address, "size": i.size,
                        "mnemonic": i.mnemonic, "op_str": i.op_str}
            for i in DC._decode(unit, 0x08000000, 0x08000040)[0]}
    sw = RV.switch_tables(unit, recs, funcs)["switches"]
    hit = [s for s in sw if s["kind"] == "tbb"]
    check("D5 switch_tables 的项数与守卫条件一致（cmp #8 + bhs ⇒ 8 项）",
          hit and hit[0]["n_cases"] == 8
          and "⇒ 8 项" in hit[0]["length_basis"],
          hit[:1])
    check("D6 表基址与 tbb 的 Align(PC,4) 一致",
          hit and hit[0]["table_addr"] == 0x08000008, hit[:1])


# ==================================================================
def section_e():
    print("\nE 真镜像端到端（175 函数）")
    _unit, _fs, res, by = load(EXAMPLE_AXF)

    check("E1 全镜像 175 个函数全部出码、0 失败",
          res["n_functions"] == 175 and res["n_failed"] == 0,
          (res["n_functions"], res["n_failed"]))
    check("E2 指令总量与未支持量（4760 条 / 4 处）",
          res["n_insns"] == 4760 and res["n_unsupported"] == 4,
          (res["n_insns"], res["n_unsupported"]))
    check("E3 未支持的类别如实列出（只剩真做不了的）",
          set(res["unsupported"]) == {"adcs", "rrx", "sbc.w"},
          res["unsupported"])

    f = by["HAL_RCC_OscConfig"]
    check("E4 HAL_RCC_OscConfig 341 条指令 / 104 块 / 0 未支持",
          (f["n_insns"], f["n_blocks"], f["n_unsupported"]) == (341, 104, 0),
          (f["n_insns"], f["n_blocks"], f["n_unsupported"]))

    outside = [it for it in res["functions"] if it["n_outside_targets"]]
    check("E5 函数范围外的跳转目标只补空标签（不静默丢 goto）",
          len(outside) >= 1
          and "以下目标不在本函数范围内" in outside[0]["code"], len(outside))

    flags = [it for it in res["functions"] if it["n_flag_unresolved"]]
    check("E6 flags 生产者缺失时输出 flag_<cond> 并计数",
          flags and "flag_" in flags[0]["code"], len(flags))

    f = by["_printf_longlong_dec"]
    check("E7 未支持指令在源码里逐条留痕 + notes 汇总",
          "sbc.w" in f["unsupported"]
          and any("未支持" in n for n in f["notes"])
          and any("未支持: sbc.w" in ln for ln in f["code"].splitlines()),
          f["notes"])

    bad = []
    for it in res["functions"]:
        for m in it["unsupported"]:
            if not any(("未支持: " + m) in ln for ln in it["code"].splitlines()):
                bad.append((it["name"], m))
    check("E8 没有「计了数却没在源码里标注」的未支持指令", bad == [], bad[:5])

    check("E9 有进位链断掉时的降级标注（adc/sbc 只在有 C 位来源时才提升）",
          all("carry" not in it["code"].split() for it in res["functions"]))


# ==================================================================
def section_f():
    print("\nF 批量 / 写文件 / 错误路径")
    unit, funcs, res, _by = load(FX)

    r = DC.decompile(unit, funcs, max_funcs=3)
    check("F1 max_funcs 截断时 n_total/truncated 如实",
          r["n_functions"] == 3 and r["truncated"] is True
          and r["n_total"] == len(funcs), (r["n_functions"], r["n_total"]))

    text = DC.pseudo_c_file({"functions": [it for it in res["functions"][:2]]},
                            title="fx")
    check("F2 拼出的 .c 带「不是原始源码」声明与 stdint",
          "不是原始源码" in text and "#include <stdint.h>" in text, text[:200])

    import tempfile
    d = tempfile.mkdtemp(prefix="mdk84_")
    dest = os.path.join(d, "src", "pseudo_c.c")
    DC.write_pseudo_c(res, dest, title="fx")
    raw = open(dest, "rb").read()
    check("F3 write_pseudo_c 落盘、UTF-8 无 BOM、LF 行尾",
          raw.startswith(b"/*") and b"\r\n" not in raw and raw.count(b"\n") > 10,
          raw[:40])

    r = DC.decompile(unit, [{"addr": 0x09000000, "addr_hex": "0x09000000",
                             "name": "nope", "size": 16,
                             "end_addr": 0x09000010}], max_funcs=4)
    check("F4 映射范围外的地址进 failed（不编造代码）",
          r["n_functions"] == 0 and r["n_failed"] == 1
          and "不在镜像" in (r["failed"][0].get("error") or ""), r["failed"])

    one = DC.decompile_function(unit, funcs[0], funcs=funcs)
    check("F5 单函数接口返回 ok + 统计字段齐全",
          one["ok"] and one["addr_hex"].startswith("0x") and one["n_blocks"] >= 1
          and isinstance(one["notes"], list), list(one.keys()))

    check("F6 limitations 明确写出伪 C 的边界（类型是推断的 / 间接跳转不编造）",
          any("推断" in s for s in r.get("limitations") or [])
          and any("间接跳转" in s for s in r["limitations"]),
          r.get("limitations"))


# ==================================================================
def section_g():
    print("\nG 工具面（不新增依赖 ⇒ 不新增工具）")
    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15884, toolsets="all").list_tools())}
    check("G1 工具总数 215（本批不新增）", len(names) == 215, len(names))
    check("G2 反编译没有新造工具（能力做进既有 recover_*）",
          not any(k in n for n in names
                  for k in ("decomp", "pseudo", "lift")),
          [n for n in names if "decomp" in n or "pseudo" in n])
    check("G3 没有引入反编译第三方库（只需 capstone + pyelftools）",
          "unicorn" not in sys.modules and "keystone" not in sys.modules
          and "angr" not in sys.modules)


# ==================================================================
def section_h():
    print("\nH 接入面（既有工具加参数，不新增工具）")

    r = RC.disasm_at(FX, symbol="dispatch", fmt="c")
    check("H1 recover_disasm(fmt=c) 出伪 C 且带 format 标记",
          r.get("ok") and r.get("format") == "pseudo_c"
          and "switch (a0)" in (r.get("code") or ""), list(r)[:6])
    check("H2 fmt=c 保留老字段（arch/span/input/notes/limitations）",
          r.get("arch") and (r.get("span") or {}).get("start_hex")
          and (r.get("input") or {}).get("sha256") and r.get("limits") is None,
          r.get("span"))

    r = RC.disasm_at(FX, symbol="dispatch")
    check("H3 不给 fmt 时行为不变（仍返回指令表）",
          r.get("ok") and r.get("insns") and not r.get("code"),
          list(r)[:8])

    import tempfile
    out = os.path.join(tempfile.mkdtemp(prefix="mdk84proj_"), "proj")
    b = RC.build_project(FX, out, max_pseudo_c_functions=5)
    rels = {f["rel"]: f for f in b.get("files") or []}
    check("H4 工程里带 src/pseudo_c.c 且回读校验通过",
          "src/pseudo_c.c" in rels
          and rels["src/pseudo_c.c"]["sha256_verified"]
          and b.get("pseudo_c_generated") is True, sorted(rels))
    txt = open(os.path.join(out, "src", "pseudo_c.c"), encoding="utf-8").read()
    check("H5 伪 C 文件声明自己不是原始源码",
          "不是原始源码" in txt and "dispatch" in txt, txt[:120])

    out2 = os.path.join(tempfile.mkdtemp(prefix="mdk84proj_"), "proj")
    b2 = RC.build_project(FX, out2, include_pseudo_c=False)
    rels2 = {f["rel"] for f in b2.get("files") or []}
    check("H6 include_pseudo_c=False 时不产出该文件（开关有效）",
          "src/pseudo_c.c" not in rels2 and b2.get("pseudo_c_generated") is False,
          sorted(rels2))

    import asyncio
    from mdkdebug import server as SV
    tools = asyncio.run(SV.create_server(port=15886, toolsets="all").list_tools())
    rd = [t for t in tools if t.name == "recover_disasm"]
    props = (rd[0].input_schema or {}).get("properties") or {}
    rp = [t for t in tools if t.name == "recover_project"]
    props2 = (rp[0].input_schema or {}).get("properties") or {}
    check("H7 参数挂在既有工具上（recover_disasm.fmt / recover_project.include_pseudo_c）",
          "fmt" in props and "include_pseudo_c" in props2, (list(props), list(props2)))


# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d,
               section_e, section_f, section_g, section_h):
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
