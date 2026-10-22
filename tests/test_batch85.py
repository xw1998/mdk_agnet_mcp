# -*- coding: utf-8 -*-
"""批次85 测试：多容器 + 多架构（吸收 Ghidra 加载器的口径，零新依赖）。

Ghidra 支持一堆容器（ELF / PE / COFF / Mach-O / raw）和一堆架构，这是它能「打开任意
固件」的前提。这里吸收的是**加载器口径**，不是它的代码：

  A 识别：按字节判，不看扩展名，每条判据都要说清
  B PE32/PE32+：ImageBase+RVA、节属性、导出表（observed 函数名的唯一来源）、COFF 符号
  C COFF 目标文件：可重定位 ⇒ 符号值是节内偏移，出工程要拒
  D Mach-O：thin/fat、LC_SEGMENT_64、LC_SYMTAB、LC_MAIN 入口
  E S-record：真 fromelf --m32 产物，逐字节对上 bin
  F 显式架构/入口：文件里没有的东西不猜，调用方给了就用并留痕
  G 诚实性：非 ARM 一律拒绝提升，不做「看着像」的答案
  H 回归：ARM/ELF 老路径一字不改

运行：python -m tests.test_batch85
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "decomp"))

from mdkdebug import containers as CT      # noqa: E402
from mdkdebug import recover as RC         # noqa: E402
from mdkdebug import decomp as DC          # noqa: E402
import synth_bins as SB                    # noqa: E402

FXD = os.path.join(ROOT, "tests", "fixtures", "decomp")
FX = os.path.join(FXD, "decomp_fx.axf")
FX_SREC = os.path.join(FXD, "decomp_fx.srec")
EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b85")
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


def _tmp(name: str, blob: bytes) -> str:
    os.makedirs(TMP, exist_ok=True)
    p = os.path.join(TMP, name)
    with open(p, "wb") as f:
        f.write(blob)
    return p


# ==================================================================
def section_a():
    print("\nA 识别（按字节 + 给判据）")
    pe, coff, macho, fat = SB.make_pe(), SB.make_coff(), SB.make_macho(), SB.make_macho(True)
    cases = [("elf", open(FX, "rb").read(), "elf"),
             ("srec", open(FX_SREC, "rb").read(), "srec"),
             ("pe", pe, "pe"),
             ("coff", coff, "coff"),
             ("macho", macho, "macho"),
             ("fat", fat, "macho")]
    for name, blob, want in cases:
        kind, why = CT.detect(blob[:4096])
        check("A1 %s 识别为 %s，判据非空" % (name, want),
              kind == want and bool(why), (kind, why))
    kind, why = CT.detect(b"\x00" * 64)
    check("A2 无特征头 → bin（不猜）", kind == "bin" and "没有" in why, (kind, why))
    # 扩展名不能用来肯定结论：把一个 PE 命名成 .bin，判定仍要是 pe
    kind, _ = CT.detect(pe[:4096], name="firmware.bin")
    check("A3 扩展名不影响判定（PE 内容即使叫 .bin 也是 pe）", kind == "pe", kind)
    check("A4 识别不依赖 file 命令/外部工具（纯字节）",
          CT.detect(b"!<arch>\n")[0] == "ar")


# ==================================================================
def section_b():
    print("\nB PE32+（ImageBase + RVA）")
    pe = CT.parse_pe(SB.make_pe())
    check("B1 解析成功且是 PE32+", pe.get("ok") and pe["class"] == 64, pe.get("error"))
    check("B2 机器码 → x86_64 / 64 位", pe["family"] == "x86_64"
          and pe["machine"] == "amd64", (pe["family"], pe["machine"]))
    check("B3 入口 = ImageBase + AddressOfEntryPoint",
          pe["entry"] == 0x140001000, hex(pe["entry"]))
    names = {s["name"]: s for s in pe["sections"]}
    check("B4 .text 地址 = ImageBase+RVA 且可执行",
          names[".text"]["addr"] == 0x140001000 and names[".text"]["exec"],
          names.get(".text"))
    check("B5 .rdata 不可执行", names[".rdata"]["exec"] is False,
          names.get(".rdata"))
    syms = {s["name"]: s for s in pe["symbols"]}
    check("B6 导出表给出 observed 函数名（func_a → ImageBase+0x1000）",
          "func_a" in syms and syms["func_a"]["value"] == 0x140001000,
          list(syms))
    check("B7 COFF 符号表按节 VA 换算（coffsym）",
          "coffsym" in syms and syms["coffsym"]["value"] == 0x140001010,
          list(syms))
    check("B8 PE 不是可重定位目标", pe["relocatable"] is False)
    bad = CT.parse_pe(b"MZ" + b"\x00" * 0x3A + b"\x00\x00\x00\x00")
    check("B9 MZ 但没有 PE 签名 → 明确报错（不返回空节表）",
          not bad.get("ok") and "PE" in (bad.get("error") or ""), bad.get("error"))


# ==================================================================
def section_c():
    print("\nC COFF 目标文件")
    c = CT.parse_coff(SB.make_coff())
    check("C1 解析成功且标为可重定位", c.get("ok") and c["relocatable"] is True,
          c.get("error"))
    check("C2 机器码 0x14C → x86 / 32 位", c["family"] == "x86"
          and c["class"] == 32, (c["family"], c["class"]))
    check("C3 .text 可执行", [s["name"] for s in c["sections"] if s["exec"]] == [".text"],
          c["sections"])
    names = [s["name"] for s in c["symbols"]]
    check("C4 符号名走字符串表（symptr + nsym*18 才是 strtab 起点）",
          names == ["coff_obj_func"], names)
    check("C5 符号值是节内偏移（0，不是 VA）",
          c["symbols"][0]["value"] == 0, c["symbols"][0])
    check("C6 限制里写明「节内偏移、先链接」",
          any("节内偏移" in n for n in c.get("notes") or []), c.get("notes"))
    p = _tmp("t.obj", SB.make_coff())
    # 出工程会建目录，重跑时必须先清掉，否则撞到「输出目录已存在」而测不到本意
    import shutil
    _out = os.path.join(TMP, "out_coff")
    if os.path.isdir(_out):
        shutil.rmtree(_out, ignore_errors=True)
    proj = RC.build_project(p, _out, name="x")
    check("C7 可重定位目标 → 出工程被拒（不给地址全错的工程）",
          proj.get("ok") is False and "可重定位" in (proj.get("error") or ""),
          proj.get("error"))


# ==================================================================
def section_d():
    print("\nD Mach-O")
    m = CT.parse_macho(SB.make_macho())
    check("D1 解析成功、arm64、64 位、小端",
          m.get("ok") and m["family"] == "arm64" and m["class"] == 64
          and m["endian"] == "little", (m.get("error"), m.get("family")))
    check("D2 入口来自 LC_MAIN（__TEXT + 0x200）",
          m["entry"] == 0x100000200, hex(m["entry"]))
    secs = {s["name"]: s for s in m["sections"]}
    check("D3 __text 可执行、地址与大小对", "__text" in secs
          and secs["__text"]["exec"] and secs["__text"]["addr"] == 0x100000200
          and secs["__text"]["size"] == 8, secs.get("__text"))
    check("D4 nlist_64 符号（_main）", [s["name"] for s in m["symbols"]] == ["_main"],
          [s["name"] for s in m["symbols"]])
    check("D5 入口依据写进 notes", any("LC_MAIN" in n for n in m.get("notes") or []),
          m.get("notes"))

    f = CT.parse_macho(SB.make_macho(fat=True))
    check("D6 fat 包取第一个切片并如实说明", f.get("ok")
          and any("fat" in n for n in f.get("notes") or []), f.get("notes"))
    check("D7 fat 切片在文件里的偏移被加到节偏移上（512+4096）",
          f["sections"][0]["offset"] == 4608, f["sections"][0]["offset"])
    bad = CT.parse_macho(b"\xcf\xfa\xed\xfe" + b"\x00" * 10)
    check("D8 头被截断 → 明确报错", not bad.get("ok") and bad.get("error"),
          bad.get("error"))


# ==================================================================
def section_e():
    print("\nE S-record（真 fromelf --m32 产物）")
    text = open(FX_SREC, encoding="latin-1").read()
    info = CT.parse_srec(text)
    check("E1 解析出数据记录且无校验错",
          info["data_records"] > 0 and not info["checksum_errors"],
          (info["data_records"], info["checksum_errors"]))
    check("E2 起始地址 = 0x08000000（S3 24/32 位地址）",
          info["min_addr"] == 0x08000000, hex(info["min_addr"] or 0))
    flat = CT.srec_flat(text)
    elf = RC.parse_elf(open(FX, "rb").read())
    # armcc 的可执行区叫 ER_RO（不是 .text）：按**可执行**挑，不按名字挑
    text_sec = next(s for s in elf["sections"] if s["exec"] and s["size"])
    raw = open(FX, "rb").read()
    want = raw[text_sec["offset"]:text_sec["offset"] + text_sec["size"]]
    got = flat["data"][text_sec["addr"] - flat["base"]:][:len(want)]
    check("E3 S-record 反解出的字节与 axf 的可执行段逐字节相同（%s）"
          % text_sec["name"], flat.get("ok") and got == want, (len(got), len(want)))
    bad = text.replace(text.splitlines()[0], text.splitlines()[0][:-2] + "00")
    info2 = CT.parse_srec(bad)
    check("E4 校验和错的行被记下来（不静默吞）",
          bool(info2["checksum_errors"]), info2["checksum_errors"])

    p = _tmp("t.srec", open(FX_SREC, "rb").read())
    u = RC._unit_from_data(open(p, "rb").read(), "t.srec", 0)
    check("E5 单元容器标为 srec、基址取自记录",
          u.container == "srec" and u.base == 0x08000000, (u.container, hex(u.base)))
    r = RC.analyze(p, arch="arm", thumb=True, entry=0x08000000)
    check("E6 S-record + 显式架构 → 能出函数（入口按 entry_hint）",
          r.get("ok") and r["_recover"]["total"] >= 1
          and any(f["sources"] == ["entry_hint"] for f in r["_recover"]["functions"]),
          [f["name"] for f in (r.get("_recover") or {}).get("functions", [])][:4])


# ==================================================================
def section_f():
    print("\nF 显式架构与入口（文件里没有的东西不猜）")
    ok = CT.arch_from_name("x86_64")
    check("F1 架构名 → 位宽/端序默认值", ok.get("ok")
          and ok["arch"]["bits"] == 64 and ok["arch"]["family"] == "x86_64", ok)
    bad = CT.arch_from_name("pdp11")
    check("F2 不认识的架构名 → 报错并列出可用值",
          not bad.get("ok") and "x86" in (bad.get("error") or ""), bad.get("error"))
    m68k = CT.arch_from_name("m68k")
    check("F3 68k 默认大端（按小端喂会得到看着像指令的垃圾）",
          m68k["arch"]["endian"] == "big", m68k)

    p = _tmp("t.exe", SB.make_pe())
    r = RC.analyze(p, arch="x86_64")
    check("F4 analyze 接受显式架构并标 basis=explicit",
          r.get("ok") and r["arch"].get("basis") == "explicit", r.get("arch"))
    check("F5 显式值与原推断并列保留（冲突看得见）",
          "arch_declared" in r, list(r)[:8])
    r2 = RC.analyze(p)
    check("F6 从 PE 头自己判出 x86_64（不需要显式指定）",
          r2["arch"]["family"] == "x86_64" and r2["arch"].get("basis") is None,
          r2.get("arch"))

    d = RC.disasm_at(p, start=0x140001000, end=0x140001004, arch="x86_64")
    check("F7 disasm_at 支持显式架构（PE/x86_64 出 ret/nop）",
          d.get("ok") and [i["mnemonic"] for i in d["insns"]][:2] == ["ret", "nop"],
          d.get("error") or [i["mnemonic"] for i in d.get("insns") or []])


# ==================================================================
def section_g():
    print("\nG 诚实性（非 ARM 不做提升）")
    p = _tmp("t.exe", SB.make_pe())
    r = RC.disasm_at(p, symbol="func_a", fmt="c")
    # 批次93 起伪 C 也支持 riscv/mips，所以拒绝文案里列的是「可用家族」而不是 ARM
    _e = r.get("error") or ""
    check("G1 不支持的家族请求伪 C → 明确拒绝并给替代动作",
          r.get("ok") is False and "x86_64" in _e and "riscv" in _e
          and r.get("hint"), _e)
    an = RC.analyze(p)
    check("G2 非 ARM 的报告里写明「参数/返回值不要按 AAPCS 读」",
          any("AAPCS" in s for s in an.get("limitations") or []),
          an.get("limitations"))
    sh = RC._make_cs({"family": "sh", "bits": 32, "endian": "little"})
    check("G3 没有后端支持的家族 → 报不支持并列可用家族（不给空结果）",
          sh[0] is None and "不支持" in sh[1], sh[1])
    m68k = RC._make_cs({"family": "m68k", "bits": 32, "endian": "big"})
    check("G4 m68k 后端可用且按大端建", m68k[0] is not None, m68k[1])


# ==================================================================
def section_h():
    print("\nH 回归与工具面")
    u = RC._unit_from_data(open(FX, "rb").read(), "fx", 0)
    rec = RC.recover_functions(u, deep=True)
    check("H1 ARM/ELF 老路径不变（夹具 13 函数全 observed）",
          rec["total"] == 13 and rec["counts"]["observed"] == 13, rec["counts"])
    check("H2 detect_container 老接口仍返回 kind 字符串",
          RC.detect_container(open(FX, "rb").read()[:64]) == "elf"
          and RC.detect_container(open(FX_SREC, "rb").read()[:64]) == "srec")
    r = DC.decompile(u, rec["functions"], max_funcs=2)
    check("H3 ARM 伪 C 仍然出码", r["functions"] and r["functions"][0]["code"])

    import asyncio
    from mdkdebug import server as SV
    tools = {t.name: t for t in asyncio.run(
        SV.create_server(port=15885, toolsets="all").list_tools())}
    check("H4 工具总数 214（本批次不新增工具；+1 来自批次86 recover_diff）", len(tools) == 214, len(tools))
    probe = tools["recover_probe"].input_schema.get("properties") or {}
    check("H5 recover_probe 暴露 arch/endian/bits/thumb/entry",
          all(k in probe for k in ("arch", "endian", "bits", "thumb", "entry")),
          sorted(probe))
    dis = tools["recover_disasm"].input_schema.get("properties") or {}
    check("H6 recover_disasm 暴露 arch/endian/bits/thumb",
          all(k in dis for k in ("arch", "endian", "bits", "thumb")), sorted(dis))
    check("H7 没有引入新依赖（只用 struct + capstone）",
          "unicorn" not in sys.modules and "pefile" not in sys.modules
          and "macholib" not in sys.modules)


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
