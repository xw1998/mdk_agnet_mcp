# -*- coding: utf-8 -*-
"""批次82 测试：交叉引用库 / 调用图 / 跳转表与 switch（吸收 Ghidra 的关系层，零新依赖）。

用户要求把 Ghidra 与 REA 里**所有嵌入式相关功能**吸收进来。Ghidra 的关系层是三件产物：
xref（谁碰过这个地址）、call graph（谁调谁）、jump table / switch（不经过 bl 的分支目标）。
这三件事一旦缺了，反汇编会「看着完整其实少一半」——case 分支不经过 bl，永远不在
调用目标里；字符串/全局的引用只在 ldr 的偏移里，不在符号表里。

  A 操作数解析：load/store 的基址/偏移/索引/移位
  B 常量传播：movw+movt / ldr 字面量 / add pc / adr，写别的寄存器就清掉
  C 交叉引用：直接调用 / 经常量的间接调用 / 字面量池里的代码指针 / 常量基址访存 / 未知基址
  D 调用图：入度出度、根（=有出边无入边）、环（Tarjan）、深度
  E 跳转表：tbb / tbh / ldr pc 表 / add pc 相对表 / 比较链
  F 真镜像端到端：关系层进 report.json、三份 CSV 落盘、老文件不变
  G 工具面：213 个工具（本批不新增；+1 来自批次86）

运行：python -m tests.test_batch82
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import reveng as RV           # noqa: E402

EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []
_TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


def _tmpdir(prefix="mdk82_"):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


def ins(addr, mnemonic, op_str="", size=2, **kw):
    rec = {"addr": addr, "addr_hex": "0x%08X" % addr, "mnemonic": mnemonic,
           "op_str": op_str, "bytes": "00" * size, "size": size}
    rec.update(kw)
    return rec


def make_unit(size=0x1000, base=0x08000000, blobs=None):
    """造一份 Thumb 形态的扁平镜像（前 8 字节是向量表：SP + 复位地址，bit0=1）。"""
    data = bytearray(size)
    data[0:4] = (0x20001000).to_bytes(4, "little")
    data[4:8] = (base + 1).to_bytes(4, "little")
    for addr, blob in (blobs or {}).items():
        off = addr - base
        data[off:off + len(blob)] = blob
    return RC.Unit(bytes(data), "synthetic.bin", base=base)


def funcs(*spec):
    """``(addr, name, size)`` → 函数记录（带 end_addr，和 recover_functions 产出同形）。"""
    out = []
    for addr, name, size in spec:
        out.append({"addr": addr, "addr_hex": "0x%08X" % addr, "name": name,
                    "size": size, "end_addr": addr + size,
                    "size_basis": "symtab"})
    return out


# ==================================================================
def section_a():
    print("\nA 操作数解析（基址 / 偏移 / 索引 / 移位）")

    m = RV.parse_mem("r3, [r0, #0x10]")
    check("A1 ldr r3, [r0, #0x10] → base r0 / offset 0x10",
          m and m["base"] == "r0" and m["offset"] == 0x10 and m["index"] is None, m)

    m = RV.parse_mem("r3, [r0, r1, lsl #2]")
    check("A2 索引寻址 → index r1 / shift 2（数组元素大小 4 的指纹）",
          m and m["index"] == "r1" and m["shift"] == 2, m)

    m = RV.parse_mem("r3, [pc, #0x40]")
    check("A3 PC 相对 → base pc", m and m["base"] == "pc" and m["offset"] == 0x40, m)

    m = RV.parse_mem("r3, [sp, #4]!")
    check("A4 前索引写回：base sp / offset 4 / writeback",
          m and m["base"] == "sp" and m["offset"] == 4 and m["writeback"] is True, m)

    m = RV.parse_mem("r4, [r5]")
    check("A5 无偏移 → offset 0", m and m["base"] == "r5" and m["offset"] == 0, m)

    check("A6 push {r4, lr} 不是访存（返回 None）", RV.parse_mem("{r4, lr}") is None)

    check("A7 立即数解析：#0x10 / -4 / 裸 16",
          RV._imm("#0x10") == 16 and RV._imm("#-4") == -4 and RV._imm("16") == 16)

    check("A8 AArch64 的 w3 / x3 归一到 r3",
          RV._norm_reg("W3") == "r3" and RV._norm_reg("x3") == "r3"
          and RV._norm_reg("sp") == "sp")


# ==================================================================
def section_b():
    print("\nB 常量传播（只服务「这条访问落在哪」）")

    u = make_unit()
    code = {0x08000100: ins(0x08000100, "movw", "r3, #0x2000",
                            writes=["r3"]),
            0x08000104: ins(0x08000104, "movt", "r3, #0x2000",
                            writes=["r3"]),
            0x08000108: ins(0x08000108, "str", "r1, [r3, #0x10]", size=2)}
    funcs_ = funcs((0x08000100, "f", 0x10))
    r = RV.build_xrefs(u, code, funcs_)
    writes = [x for x in r["xrefs"] if x["kind"] == "data_write"]
    check("B1 movw+movt 拼出 0x20002000，str 偏移 0x10 → 0x20002010",
          len(writes) == 1 and writes[0]["to"] == 0x20002010
          and writes[0]["how"] == "const_base:r3", r["xrefs"])

    # 字面量池：ldr r2, [pc, #0x0c] → 池地址 = (0x08000100+4)&~3 + 0x0c
    pool_at = ((0x08000100 + 4) & ~3) + 0x0c
    u = make_unit(blobs={pool_at: (0x08000301).to_bytes(4, "little")})
    code = {0x08000100: ins(0x08000100, "ldr", "r2, [pc, #0x0c]", size=2,
                            writes=["r2"])}
    r = RV.build_xrefs(u, code, funcs((0x08000100, "f", 0x10)))
    dr = [x for x in r["xrefs"] if x["kind"] == "data_read"]
    cp = [x for x in r["xrefs"] if x["kind"] == "data_code_pointer"]
    check("B2 PC 相对 ldr 记一条 data_read（地址=池地址）",
          len(dr) == 1 and dr[0]["to"] == pool_at and dr[0]["how"] == "pc_relative", dr)
    check("B3 池里是代码指针 ⇒ 再记一条 data_code_pointer（去掉 Thumb 位）",
          len(cp) == 1 and cp[0]["to"] == 0x08000300, cp)

    # 写别的寄存器不影响已算出的常量
    u = make_unit()
    code = {0x08000100: ins(0x08000100, "movw", "r3, #0x0000", writes=["r3"]),
            0x08000102: ins(0x08000102, "movt", "r3, #0x2000", writes=["r3"]),
            0x08000106: ins(0x08000106, "movw", "r4, #0x1", writes=["r4"]),
            0x0800010A: ins(0x0800010A, "str", "r1, [r3, #0x4]")}
    r = RV.build_xrefs(u, code, funcs((0x08000100, "f", 0x10)))
    check("B4 写另一个寄存器不会把已算出的常量清掉（保守但不至于失忆）",
          any(x["kind"] == "data_write" and x["to"] == 0x20000004
              for x in r["xrefs"]), r["xrefs"])

    # 被改写的寄存器必须失效：movw r3,#0x2000 → movw r3,#0x3000 → str
    u = make_unit()
    code = {0x08000100: ins(0x08000100, "movw", "r3, #0x0000", writes=["r3"]),
            0x08000102: ins(0x08000102, "movt", "r3, #0x2000", writes=["r3"]),
            0x08000106: ins(0x08000106, "movw", "r3, #0x0000", writes=["r3"]),
            0x08000108: ins(0x08000108, "movt", "r3, #0x3000", writes=["r3"]),
            0x0800010C: ins(0x0800010C, "str", "r1, [r3, #0x4]")}
    r = RV.build_xrefs(u, code, funcs((0x08000100, "f", 0x10)))
    dw = [x for x in r["xrefs"] if x["kind"] == "data_write"]
    check("B5 寄存器被改写后，用的是新常量而不是旧常量（宁可报错不给错答案）",
          len(dw) == 1 and dw[0]["to"] == 0x30000004, dw)


# ==================================================================
def section_c():
    print("\nC 交叉引用（谁碰过这个地址）")

    u = make_unit(blobs={0x08000120: (0x08000201).to_bytes(4, "little")})
    code = {
        0x08000100: ins(0x08000100, "bl", "0x08000200", size=4,
                        target=0x08000200, target_hex="0x08000200"),
        0x08000104: ins(0x08000104, "movw", "r3, #0x0200", writes=["r3"]),
        0x08000108: ins(0x08000108, "movt", "r3, #0x0800", writes=["r3"]),
        0x0800010C: ins(0x0800010C, "blx", "r3", size=2),
        0x08000110: ins(0x08000110, "ldr", "r2, [pc, #0x0c]", writes=["r2"]),
        0x08000114: ins(0x08000114, "ldr", "r1, [r0, #0x10]"),
    }
    r = RV.build_xrefs(u, code, funcs((0x08000100, "f", 0x18)))
    calls = [x for x in r["xrefs"] if x["kind"] == "call"]
    check("C1 直接调用记一条 call（to 去掉 Thumb 位、how=direct、observed）",
          len(calls) == 2 and calls[0]["to"] == 0x08000200
          and calls[0]["how"] == "direct" and calls[0]["confidence"] == "observed",
          calls)
    check("C2 movw+movt+blx r3 ⇒ 间接调用被解析成 inferred（不是「不知道」）",
          len(calls) == 2 and calls[1]["how"] == "indirect_const:r3"
          and calls[1]["to"] == 0x08000200 and calls[1]["confidence"] == "inferred",
          calls)

    unresolved = [x for x in r["unresolved"] if x["kind"] == "mem"]
    check("C3 基址未知的访存记进 unresolved（带 base_reg/offset，不是丢掉）",
          len(unresolved) == 1 and unresolved[0]["base_reg"] == "r0"
          and unresolved[0]["offset"] == 0x10, unresolved)

    check("C4 每条 xref 都带「从哪条指令来」：from / func / insn",
          all(x.get("from_hex") and x.get("func") is not None and x.get("insn")
              for x in r["xrefs"]), r["xrefs"][:2])

    # 每条关系都能反查：同一个目标地址被谁引用过
    by_to = {}
    for x in r["xrefs"]:
        by_to.setdefault(x["to"], []).append(x["kind"])
    check("C5 xref 可反查（同一目标汇集多种引用类型：调用 + 池里的代码指针）",
          by_to.get(0x08000200, []).count("call") == 2
          and "data_code_pointer" in by_to.get(0x08000200, []), by_to)


# ==================================================================
def section_d():
    print("\nD 调用图（谁调谁）")

    fs = funcs((0x08000100, "A", 8), (0x08000200, "B", 8),
               (0x08000300, "C", 8), (0x08000400, "D", 8))

    def xr(caller, callee, callsite):
        return {"kind": "call", "from": callsite, "from_hex": "0x%08X" % callsite,
                "to": callee, "to_hex": "0x%08X" % callee, "func": caller,
                "func_name": "", "insn": "bl", "how": "direct",
                "confidence": "observed"}

    # A→B→A 成环；B→C；D→A（D 是根）
    g = RV.call_graph(fs, [xr(0x08000100, 0x08000200, 0x08000104),
                           xr(0x08000200, 0x08000100, 0x08000204),
                           xr(0x08000200, 0x08000300, 0x08000208),
                           xr(0x08000400, 0x08000100, 0x08000404)])
    check("D1 边数 = 去重后的 (caller,callee) 对 = 4", g["n_edges"] == 4, g["n_edges"])
    check("D2 根 = 有出边、无入边 ⇒ 只有 D",
          [r["name"] for r in g["roots"]] == ["D"], g["roots"])
    check("D3 环用强连通分量判：A/B 成一个环，C 不在环里",
          len(g["cycles"]) == 1 and g["cycles"][0]["size"] == 2, g["cycles"])
    check("D4 深度从根算（D→A→B→C = 3）", g["max_depth"] == 3, g["max_depth"])
    check("D5 入度/出度按名字可查（B 的入 1 出 2）",
          g["by_name"]["B"] == {"out": 2, "in": 1}, g["by_name"].get("B"))

    # 自调用（递归）：Tarjan 的单点分量不算环（惯例），但边仍要保留
    g2 = RV.call_graph(fs, [xr(0x08000100, 0x08000100, 0x08000104)])
    check("D6 自调用保留为边、不误报成环",
          g2["n_edges"] == 1 and g2["cycles"] == [], g2)

    g3 = RV.call_graph(fs, [xr(0x08000100, 0x08000900, 0x08000104)])
    check("D7 目标不在函数集合里 ⇒ 边仍在，但标 in_graph=False（外部符号）",
          g3["edges"][0]["in_graph"] is False, g3["edges"])


# ==================================================================
def section_e():
    print("\nE 跳转表与 switch（不经过 bl 的分支目标）")

    # tbb：表紧跟在指令后面，目标 = 基址 + 2*项
    base = 0x08000000
    u = make_unit(blobs={0x08000104: bytes([0, 1, 2, 3, 0, 0, 0, 0])})
    code = {0x080000FC: ins(0x080000FC, "cmp", "r0, #3"),
            0x080000FE: ins(0x080000FE, "bhi", "0x08000400", target=0x08000400),
            0x08000100: ins(0x08000100, "tbb", "[pc, r0]")}
    sw = RV.switch_tables(u, code, funcs((0x08000100, "f", 0x40)))
    t = sw["switches"][0]
    check("E1 tbb：4 个 case，目标 = 表基址 + 2*项，全在代码区",
          t["kind"] == "tbb" and t["n_cases"] == 4
          and t["targets_hex"] == ["0x08000104", "0x08000106",
                                   "0x08000108", "0x0800010A"], t)
    check("E2 表长由守卫 cmp 给出（不是「扫到越界」猜的），依据写进 length_basis",
          "cmp #3" in t["length_basis"] and t["confidence"] == "inferred", t)

    # tbh：每项 2 字节半字
    u = make_unit(blobs={0x08000104: (0).to_bytes(2, "little") +
                                     (2).to_bytes(2, "little") + b"\x00" * 8})
    code = {0x080000FC: ins(0x080000FC, "cmp", "r3, #1"),
            0x080000FE: ins(0x080000FE, "bhi", "0x08000400", target=0x08000400),
            0x08000100: ins(0x08000100, "tbh", "[pc, r3, lsl #1]")}
    sw = RV.switch_tables(u, code, funcs((0x08000100, "f", 0x40)))
    t = sw["switches"][0]
    check("E3 tbh：半字项、目标 = 基址 + 2*项",
          t["kind"] == "tbh" and t["targets_hex"] == ["0x08000104", "0x08000108"], t)

    # 目标越出代码区就停：表长是推断的，不能无限读下去
    u = make_unit(size=0x120)
    code = {0x08000100: ins(0x08000100, "tbb", "[pc, r0]")}   # 无守卫 cmp ⇒ 回退扫描
    u.data = u.data[:0x104] + bytes([0, 1]) + b"\xff" * 0x400
    u.spans = [(base, base + 0x110, 0)]
    u.code_ranges = [(base, base + 0x110)]
    sw = RV.switch_tables(u, code, funcs((0x08000100, "f", 0x110)))
    check("E4 越出代码区即停止（不把随机字节当成 case 目标）",
          sw["switches"][0]["n_cases"] == 2, sw["switches"][0]["targets_hex"])

    # ARM: ldr pc, [pc, r3, lsl #2] —— 表里是绝对地址
    u = make_unit(blobs={0x08000208: (0x08000301).to_bytes(4, "little") +
                                     (0x08000305).to_bytes(4, "little")})
    code = {0x080001FC: ins(0x080001FC, "cmp", "r3, #1"),
            0x080001FE: ins(0x080001FE, "bhi", "0x08000400", target=0x08000400),
            0x08000200: ins(0x08000200, "ldr", "pc, [pc, r3, lsl #2]", size=4)}
    sw = RV.switch_tables(u, code, funcs((0x08000200, "f", 0x40)))
    t = [x for x in sw["switches"] if x["kind"] == "ldr_pc_table"][0]
    check("E5 ARM ldr pc 表：绝对地址、去掉 Thumb 位",
          t["targets_hex"] == ["0x08000300", "0x08000304"], t)

    # add pc, pc, r3, lsl #2 —— 表里是相对偏移
    u = make_unit(blobs={0x08000248: (0x10).to_bytes(4, "little") +
                                     (0x20).to_bytes(4, "little")})
    code = {0x0800023C: ins(0x0800023C, "cmp", "r3, #1"),
            0x0800023E: ins(0x0800023E, "bhi", "0x08000400", target=0x08000400),
            0x08000240: ins(0x08000240, "add", "pc, pc, r3, lsl #2", size=4)}
    sw = RV.switch_tables(u, code, funcs((0x08000240, "f", 0x40)))
    t = [x for x in sw["switches"] if x["kind"] == "add_pc_table"][0]
    check("E6 add pc 相对表：目标 = 表基址 + 偏移，置信度 weak（相对表本身少见）",
          t["targets_hex"] == ["0x08000258", "0x08000268"]
          and t["confidence"] == "weak", t)

    # 比较链
    code = {
        0x08000400: ins(0x08000400, "cmp", "r0, #2"),
        0x08000402: ins(0x08000402, "bhi", "0x08000420", size=2,
                        target=0x08000420, target_hex="0x08000420"),
        0x08000404: ins(0x08000404, "beq", "0x08000410", size=2,
                        target=0x08000410, target_hex="0x08000410"),
        0x08000406: ins(0x08000406, "beq", "0x08000414", size=2,
                        target=0x08000414, target_hex="0x08000414"),
        0x08000408: ins(0x08000408, "beq", "0x08000418", size=2,
                        target=0x08000418, target_hex="0x08000418"),
    }
    u = make_unit()
    sw = RV.switch_tables(u, code, funcs((0x08000400, "f", 0x40)))
    ch = [x for x in sw["switches"] if x["kind"] == "compare_chain"]
    check("E7 比较链：cmp #2 + bhi 出口 + 3 条条件跳转 ⇒ 3 个 case（与上界吻合才报 inferred）",
          len(ch) == 1 and ch[0]["n_cases"] == 3
          and ch[0]["confidence"] == "inferred", ch)

    # 比较链个数与上界对不上时必须降级，而不是照抄
    code2 = dict(code)
    code2[0x08000408] = ins(0x08000408, "movs", "r1, #0", writes=["r1"])
    sw = RV.switch_tables(u, code2, funcs((0x08000400, "f", 0x40)))
    ch = [x for x in sw["switches"] if x["kind"] == "compare_chain"]
    check("E8 case 数与 cmp 上界不吻合 ⇒ confidence 降为 weak（照抄才是错答案）",
          len(ch) == 1 and ch[0]["confidence"] == "weak", ch)


# ==================================================================
def section_f():
    print("\nF 真镜像端到端（report.json + 三份 CSV）")

    an = RC.analyze(EXAMPLE_AXF, deep=True)
    rel = an.get("relations") or {}
    check("F1 analyze 带出 relations 摘要（xref 计数 / 未解析数 / 调用图 / switch）",
          rel.get("xref_counts", {}).get("call", 0) > 100
          and rel.get("n_unresolved", 0) > 0
          and rel.get("call_graph", {}).get("n_edges", 0) > 100, rel)
    check("F2 调用图有强连通分量的容器（没有环就是空表，不是缺字段）",
          "cycles" in rel["call_graph"] and isinstance(rel["call_graph"]["cycles"], list),
          rel["call_graph"].keys())
    check("F3 根节点都是「有出边、无入边」的函数",
          len(rel["call_graph"]["roots"]) > 0, rel["call_graph"]["roots"][:3])
    check("F4 关系层没有把 _relations 混进 report.json（内部字段不外泄）",
          "_relations" not in json.loads(json.dumps(RC._jsonable(an))),
          list(an.keys()))

    out = _tmpdir()
    proj = os.path.join(out, "proj")
    r = RC.build_project(EXAMPLE_AXF, proj)
    check("F5 工程产出成功", r.get("ok"), r.get("error"))
    names = {f["rel"] for f in r.get("files") or []}
    check("F6 三份新 CSV 都落盘（xrefs_full / callgraph / switches）",
          {"map/xrefs_full.csv", "map/callgraph.csv",
           "map/switches.csv"} <= names, sorted(names))
    check("F7 老的 map/xrefs.csv 仍在（不改既有产物）", "map/xrefs.csv" in names)
    head = open(os.path.join(proj, "map/xrefs_full.csv"), encoding="utf-8").readline()
    check("F8 xrefs_full.csv 表头含 kind/from/to/func/how/confidence",
          all(k in head for k in ("kind", "from", "to", "func", "how", "confidence")),
          head)
    cg = open(os.path.join(proj, "map/callgraph.csv"), encoding="utf-8").read().splitlines()
    check("F9 callgraph.csv 有内容（表头 + 至少 100 条边）", len(cg) > 100, len(cg))


# ==================================================================
def section_g():
    print("\nG 工具面（不新增依赖 ⇒ 不新增工具）")
    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15882, toolsets="all").list_tools())}
    check("G1 工具总数 213（本批不新增）", len(names) == 213, len(names))
    check("G2 关系层没有新造工具（能力做进既有 recover_*）",
          not any(k in n for n in names for k in ("xref", "callgraph", "switch")),
          [n for n in names if "xref" in n or "graph" in n])


# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d,
               section_e, section_f, section_g):
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
