# -*- coding: utf-8 -*-
"""批次83 测试：栈帧 / 结构体候选 / 数组指纹 / 全局对象（吸收 Ghidra 的类型恢复口径）。

Ghidra 的类型恢复是「从访问模式反推数据形状」：栈槽位、结构体字段偏移、数组元素大小、
全局对象跨度。它不发明类型名——**类型在编译器优化之后不可逆**，这里同样只给形状
（offset / width / reads / writes），并且每个结论都带证据。

  A 栈帧：sp 绝对槽位（push/sub 累计）、宽度、fp 基址、动态 sp 标注
  B 结构体：同基址多偏移聚类、单偏移不报、栈基址排除、离谱跨度降级
  C 数组：lsl 移位 = 元素大小
  D 全局对象：地址归组、跨度、读/写
  E 真镜像交叉验证：HAL_UART_* 推出的 72 字节 == DWARF 里 __UART_HandleTypeDef 的 72；
                    HAL_DMA_Abort 推出的 96 == __DMA_HandleTypeDef 的 96
  F 工程产出：三份类型 CSV 落盘
  G 工具面：214 个工具（+1 来自批次86）

运行：python -m tests.test_batch83
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import rtypes as RT           # noqa: E402

EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []
_TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


def _tmpdir(prefix="mdk83_"):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


def ins(addr, mnemonic, op_str="", size=2, **kw):
    rec = {"addr": addr, "addr_hex": "0x%08X" % addr, "mnemonic": mnemonic,
           "op_str": op_str, "bytes": "00" * size, "size": size}
    rec.update(kw)
    return rec


def funcs(*spec):
    return [{"addr": a, "addr_hex": "0x%08X" % a, "name": n, "size": s,
             "end_addr": a + s, "size_basis": "symtab"} for a, n, s in spec]


# ==================================================================
def section_a():
    print("\nA 栈帧（槽位 + 宽度 + 基址）")

    code = {
        0x08000100: ins(0x08000100, "push", "{r4, lr}"),          # -8
        0x08000102: ins(0x08000102, "sub", "sp, sp, #8"),         # -16
        0x08000104: ins(0x08000104, "str", "r0, [sp, #0]"),       # 槽 -16
        0x08000106: ins(0x08000106, "ldr", "r1, [sp, #4]"),       # 槽 -12
        0x08000108: ins(0x08000108, "strb", "r2, [sp, #7]"),      # 槽 -9，宽 1
        0x0800010A: ins(0x0800010A, "ldrh", "r3, [sp, #4]"),      # 槽 -12，宽 2
        0x0800010C: ins(0x0800010C, "pop", "{r4, pc}", ends_function=True),
    }
    fr = RT.stack_frame(code, 0x08000100, 0x08000110)
    slots = {s["offset"]: s for s in fr["slots"]}
    check("A1 push(-8)+sub(-8) 后 [sp,#0] 的绝对槽位是 -16（累计 sp，不是裸偏移）",
          -16 in slots, sorted(slots))
    check("A2 [sp,#4] 的槽位是 -12，宽度按助记符取最大值（ldr 4 / ldrh 2 ⇒ 4）",
          slots[-12]["width"] == 4, slots.get(-12))
    check("A3 strb 的宽度是 1（字节访问不会被当成 4 字节）",
          slots[-9]["width"] == 1, slots.get(-9))
    check("A4 同一槽位被读两次 ⇒ reads=2、confidence=inferred",
          slots[-12]["reads"] == 2 and slots[-12]["confidence"] == "inferred",
          slots.get(-12))
    check("A5 每个槽位记住「哪几条指令碰过它」（可复核）",
          len(slots[-16]["accessed_at"]) == 1
          and slots[-16]["accessed_at"][0] == "0x08000104", slots.get(-16))

    code2 = {0x08000200: ins(0x08000200, "mov", "r7, sp"),
             0x08000202: ins(0x08000202, "str", "r0, [r7, #4]"),
             0x08000204: ins(0x08000204, "add", "sp, sp, r1")}   # 动态 sp
    fr2 = RT.stack_frame(code2, 0x08000200, 0x08000210)
    check("A6 fp/r7 基址的槽位按原偏移记，basis=fp",
          fr2["slots"][0]["basis"] == "fp" and fr2["slots"][0]["offset"] == 4, fr2)
    check("A7 sp 有非固定调整（add sp, sp, r1）⇒ 明确标 dynamic_sp",
          fr2["dynamic_sp"] is True and "非固定" in fr2["note"], fr2)


# ==================================================================
def section_b():
    print("\nB 结构体候选（同基址 + 多偏移）")

    base = {"from": 0x1000, "from_hex": "0x00001000", "func": 0x1000,
            "func_name": "f", "insn": "x", "why": "w"}

    def mem(reg, off, access="read", width=4, index=None, shift=0):
        return dict(base, kind="mem", base_reg=reg, offset=off, access=access,
                    width=width, index=index, shift=shift)

    un = [mem("r0", 0), mem("r0", 4), mem("r0", 0x10, "write"),
          mem("r1", 0),                       # 只有一个偏移 ⇒ 不报
          mem("sp", 0), mem("sp", 4)]         # 栈基址 ⇒ 排除
    sc = RT.struct_candidates(un, {}, funcs((0x1000, "f", 0x100)))
    cands = sc["functions"][0]["candidates"]
    check("B1 同基址 3 个偏移 ⇒ 一个候选，跨度 = 最大偏移 + 宽度 = 0x14",
          len(cands) == 1 and cands[0]["span"] == 0x14, cands)
    check("B2 只有一个偏移的基址不报（说明不了聚合体）",
          all(c["base_reg"] != "r1" for c in cands), cands)
    check("B3 栈基址不进结构体候选（归栈帧）",
          all(c["base_reg"] != "sp" for c in cands), cands)
    check("B4 参数寄存器（r0-r3）标记为 arg_pointer，便于分辨「谁传进来的」",
          cands[0]["kind"] == "arg_pointer", cands[0])
    check("B5 字段级证据保留 reads/writes/width",
          any(f["offset"] == 0x10 and f["writes"] == 1 for f in cands[0]["fields"]),
          cands[0]["fields"])

    un2 = [mem("r4", o) for o in range(0, 0x1000, 4)]
    sc2 = RT.struct_candidates(un2, {}, funcs((0x1000, "f", 0x100)))
    c2 = sc2["functions"][0]["candidates"][0]
    check("B6 跨度 >1KB ⇒ 标 suspicious_span 且降为 weak（不装成事实）",
          c2["suspicious_span"] is True and c2["confidence"] == "weak", c2)


# ==================================================================
def section_c():
    print("\nC 数组指纹（lsl 移位 = 元素大小）")

    code = {
        0x08000100: ins(0x08000100, "ldr", "r2, [r0, r1, lsl #2]"),
        0x08000102: ins(0x08000102, "ldrb", "r3, [r0, r4, lsl #0]"),
        0x08000104: ins(0x08000104, "ldrh", "r5, [r0, r6, lsl #1]"),
        0x08000106: ins(0x08000106, "str", "r2, [r0, #4]"),     # 无索引，不算
    }
    arr = RT.array_accesses(code, funcs((0x08000100, "f", 0x10)))
    sizes = sorted(i["elem_size"] for i in arr["items"])
    check("C1 三条索引寻址 ⇒ 元素大小 1/2/4（lsl #0/#1/#2）",
          sizes == [1, 2, 4], sizes)
    check("C2 无索引的偏移访问不算数组", all(i["index_reg"] for i in arr["items"]))
    check("C3 按元素大小可汇总（嵌入式最常见的 1 字节 = 字符串/字节缓冲）",
          arr["by_elem_size"] == {1: 1, 2: 1, 4: 1}, arr["by_elem_size"])


# ==================================================================
def section_d():
    print("\nD 全局对象（地址归组）")

    def x(to, kind="data_read", width=4, how="pc_relative"):
        return {"kind": kind, "from": 0x100, "from_hex": "0x00000100",
                "to": to, "to_hex": "0x%08X" % to, "func": 0x100,
                "func_name": "f", "insn": "x", "how": how,
                "confidence": "observed", "width": width}

    gl = RT.global_objects([x(0x20000000), x(0x20000000),
                            x(0x20000004, "data_write", how="const_base:r3")])
    items = {i["addr"]: i for i in gl["items"]}
    check("D1 同一地址两次读 ⇒ reads=2", items[0x20000000]["reads"] == 2, items)
    check("D2 写访问单独计数（谁被改写看得出来）",
          items[0x20000004]["writes"] == 1, items)
    check("D3 PC 相对访问的置信度是 observed，常量基址是 inferred",
          items[0x20000000]["confidence"] == "observed"
          and items[0x20000004]["confidence"] == "inferred", items)
    check("D4 「至少多大」按访问宽度给：size_at_least=4",
          items[0x20000000]["size_at_least"] == 4, items[0x20000000])


# ==================================================================
def section_e():
    print("\nE 真镜像交叉验证（推断的跨度和 DWARF 里的真实尺寸对照）")

    from elftools.elf.elffile import ELFFile
    dwarf_sizes = {}
    with open(EXAMPLE_AXF, "rb") as f:
        e = ELFFile(f)
        if e.has_dwarf_info():
            dw = e.get_dwarf_info()
            for cu in dw.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_structure_type":
                        continue
                    n = die.attributes.get("DW_AT_name")
                    s = die.attributes.get("DW_AT_byte_size")
                    if n and s:
                        nm = n.value.decode() if isinstance(n.value, bytes) else n.value
                        dwarf_sizes[nm] = s.value
    check("E1 DWARF 里有可对照的结构体（__UART_HandleTypeDef / __DMA_HandleTypeDef）",
          dwarf_sizes.get("__UART_HandleTypeDef") == 72
          and dwarf_sizes.get("__DMA_HandleTypeDef") == 96, dwarf_sizes)

    an = RC.analyze(EXAMPLE_AXF, deep=True)
    ty = an["_recover"]["_relations"]["types"]
    got = {}
    for fn in ty["structs"]:
        for c in fn["candidates"]:
            got.setdefault(fn["func_name"], []).append((c["base_reg"], c["span"]))

    uart = [s for n, cs in got.items() if n.startswith("HAL_UART")
            for (r, s) in cs if s == 72]
    dma = [s for n, cs in got.items() if n.startswith("HAL_DMA")
           for (r, s) in cs if s == 96]
    check("E2 HAL_UART_* 推出的结构体跨度 72 == DWARF 的 __UART_HandleTypeDef(72)",
          len(uart) >= 1, {k: v for k, v in got.items() if k.startswith("HAL_UART")})
    check("E3 HAL_DMA_Abort 推出的跨度 96 == DWARF 的 __DMA_HandleTypeDef(96)",
          len(dma) >= 1, {k: v for k, v in got.items() if k.startswith("HAL_DMA")})
    check("E4 栈帧、结构体、数组、全局四块都有真实数据",
          ty["n_frames"] > 10 and ty["n_struct_candidates"] > 10
          and len(ty["arrays"]) > 10 and ty["n_globals"] > 10,
          (ty["n_frames"], ty["n_struct_candidates"], len(ty["arrays"]),
           ty["n_globals"]))
    check("E5 离谱跨度的候选被降级（__NVIC_SetPriority 的 3352 不能算事实）",
          any(c.get("suspicious_span") for fn in ty["structs"]
              for c in fn["candidates"]), "无人被标 suspicious")


# ==================================================================
def section_f():
    print("\nF 工程产出（三份类型 CSV）")

    out = _tmpdir()
    proj = os.path.join(out, "proj")
    r = RC.build_project(EXAMPLE_AXF, proj)
    names = {f["rel"] for f in r.get("files") or []}
    check("F1 产出成功", r.get("ok"), r.get("error"))
    check("F2 stack_frames / struct_candidates / globals 三份 CSV 都落盘",
          {"map/stack_frames.csv", "map/struct_candidates.csv",
           "map/globals.csv"} <= names, sorted(names))
    head = open(os.path.join(proj, "map/struct_candidates.csv"),
                encoding="utf-8").readline()
    check("F3 结构体 CSV 表头带 offset/width/array_elem_size/confidence",
          all(k in head for k in ("offset", "width", "array_elem_size",
                                  "confidence")), head)
    rows = open(os.path.join(proj, "map/stack_frames.csv"),
                encoding="utf-8").read().splitlines()
    check("F4 栈帧 CSV 有内容", len(rows) > 10, len(rows))


# ==================================================================
def section_g():
    print("\nG 工具面")
    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15883, toolsets="all").list_tools())}
    check("G1 工具总数 214（不增依赖、本批不增工具）", len(names) == 214, len(names))


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
