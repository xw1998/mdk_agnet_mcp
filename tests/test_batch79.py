# -*- coding: utf-8 -*-
"""批次79 mock 测试：工程级逆向（hex / bin / elf / lib / so → 可用工程骨架）。

来由：用户要求「像 rea 一样工程级逆向，从 hex/bin/elf/lib/so 逆向出可用工程」。
本批次只做**能纯标准库做到**的那部分，且坚持三条口径：
  · 观察 / 推导 / 未知三分（符号表=observed，向量表与调用目标=inferred，代码指针=weak）
  · 不假装恢复语义（函数原型按无参 void 写，文件头写明是推断）
  · 出件不覆盖（输出目录必须不存在 + 独占写 + 回读 SHA-256）

  A 容器解析：ELF32/64、ar（长名）、Intel HEX、bin
  B 架构/向量表：Thumb 依据、bin 从向量表推断、读到 0 停止、base 错要报 gaps
  C 符号恢复：三档置信、调用目标、代码指针、边界依据、DWARF
  D 反汇编：按符号/按区间、截断、跳过坏字节、缺 capstone 要报错
  E 工程生成：目录必须不存在、文件齐、回读校验、README/报告内容
  F lib/so：取件 + 成员剖析 + .so 的「地址是相对基址」口径
  G 工具面：注册数、分组、默认面、注解归类

运行：python -m tests.test_batch79
"""
import asyncio
import json
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402
from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import server as SV            # noqa: E402

EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []
_TMP = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def _tmpdir(prefix="mdk79_"):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


def _w(name, data, d=None):
    d = d or _tmpdir()
    p = os.path.join(d, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(p, mode, **({} if isinstance(data, bytes) else {"newline": "\n"})) as f:
        f.write(data)
    return p


# ------------------------------------------------------------------
# 合成夹具：一份最小但完整的 ELF32/ARM
#  0x08000000 向量表：SP=0x20001000，Reset=0x08000011（Thumb），其余 0
#  0x08000010 Reset_Handler：bl 0x08000020
#  0x08000020 sub：bx lr
#  0x08000022 代码区里的字 0x08000023 —— 只有「代码指针」一条证据（weak）
# ------------------------------------------------------------------
VT_CODE = (struct.pack("<II", 0x20001000, 0x08000011)
           + b"\x00" * 8                                   # NMI..保留 都 0
           + bytes.fromhex("00F006F8")                     # bl 0x08000020
           + b"\x00\x00" * 6
           + bytes.fromhex("7047")                         # bx lr
           + b"\x00\x00"
           + struct.pack("<I", 0x08000023)                 # 代码指针（weak 证据）
           + b"\x00" * 16
           + struct.pack("<I", 0x11223344))                # 一个数据字


def _mk_elf32(members, symbols, *, e_type=2, entry=0x08000011, machine=40,
              flags=0x05000000):
    """members: [(name, sh_type, flags, addr, data)]；symbols: [(name, value, size, bind, type, shndx)]"""
    ehsize = 52
    body = b""
    off = ehsize
    laid = []
    for name, sh_type, sh_flags, addr, data in members:
        laid.append({"name": name, "type": sh_type, "flags": sh_flags,
                     "addr": addr, "offset": off, "data": data})
        body += data
        off += len(data)
        if len(data) % 4:
            pad = 4 - len(data) % 4
            body += b"\x00" * pad
            off += pad
    # strtab + symtab
    strtab = b"\x00"
    ents = [struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)]
    for name, value, size, bind, typ, shndx in symbols:
        ents.append(struct.pack("<IIIBBH", len(strtab), value, size,
                                (bind << 4) | typ, 0, shndx))
        strtab += name.encode() + b"\x00"
    symdata = b"".join(ents)
    # 节名表
    shstr = b"\x00"
    nameoff = {}

    def _add(n):
        nonlocal shstr
        nameoff[n] = len(shstr)
        shstr += n.encode() + b"\x00"

    _add(".symtab")
    _add(".strtab")
    _add(".shstrtab")
    for m in laid:
        _add(m["name"])

    sym_off = off
    off += len(symdata)
    str_off = off
    off += len(strtab)
    shs_off = off
    off += len(shstr)
    shoff = off

    idx_sym = len(laid) + 1
    idx_str = len(laid) + 2
    idx_shs = len(laid) + 3
    shdrs = b"\x00" * 40
    for m in laid:
        shdrs += struct.pack("<IIIIIIIIII", nameoff[m["name"]], m["type"],
                             m["flags"], m["addr"], m["offset"],
                             len(m["data"]), 0, 0, 4, 0)
    shdrs += struct.pack("<IIIIIIIIII", nameoff[".symtab"], 2, 0, 0, sym_off,
                         len(symdata), idx_str, 1, 4, 16)
    shdrs += struct.pack("<IIIIIIIIII", nameoff[".strtab"], 3, 0, 0, str_off,
                         len(strtab), 0, 0, 1, 0)
    shdrs += struct.pack("<IIIIIIIIII", nameoff[".shstrtab"], 3, 0, 0, shs_off,
                         len(shstr), 0, 0, 1, 0)

    ehdr = (b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
            + struct.pack("<HHIIIIIHHHHHH", e_type, machine, 1, entry, 0, shoff,
                          flags, ehsize, 0, 0, 40, len(laid) + 4, idx_shs))
    return ehdr + body + symdata + strtab + shstr + shdrs


def _synthetic_elf(e_type=2):
    members = [(".text", 1, 0x6, 0x08000000, VT_CODE)]
    symbols = [("Reset_Handler", 0x08000011, 6, 1, 2, 1),
               ("g_buf", 0x08000030, 4, 1, 1, 1)]
    return _mk_elf32(members, symbols, e_type=e_type)


def _mk_ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        hdr = (name.ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
               + "100644".ljust(8) + str(len(data)).ljust(10) + "`\n")
        out += hdr.encode() + data
        if len(data) % 2:
            out += b"\n"
    return out


def _to_hex(base, data, width=16):
    lines = [":" + (bytes([2, 0, 0, 4]) + struct.pack(">H", base >> 16)
                    + bytes([(-sum(bytes([2, 0, 0, 4]) + struct.pack(">H", base >> 16))) & 0xFF])).hex().upper()]
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        body = bytes([len(chunk), ((i >> 8) & 0xFF), (i & 0xFF), 0]) + chunk
        lines.append(":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper())
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"


ELF = None
BIN = None
HEX = None


def _fixtures():
    global ELF, BIN, HEX
    ELF = _w("synth.axf", _synthetic_elf())
    BIN = _w("synth.bin", VT_CODE)
    HEX = _w("synth.hex", _to_hex(0x08000000, VT_CODE))


# ==================================================================
def section_a():
    print("A. 容器与解析")
    _fixtures()
    check("A1 ELF 魔数被认成 elf",
          RC.detect_container(open(ELF, "rb").read()[:64]) == "elf")
    check("A2 ar 魔数被认成 ar",
          RC.detect_container(b"!<arch>\n" + b"x" * 60) == "ar")
    check("A3 HEX 文本被认成 ihex",
          RC.detect_container(open(HEX, "rb").read()[:512]) == "ihex")
    check("A4 随机字节被认成 bin", RC.detect_container(b"\x00\x01\x02\x03") == "bin")

    e = RC.parse_elf(open(ELF, "rb").read())
    check("A5 ELF 头字段（class/type/machine/entry）",
          e["ok"] and e["class"] == 32 and e["type"] == "EXEC"
          and e["machine"] == "ARM" and e["entry"] == 0x08000011, e.get("error"))
    names = [s["name"] for s in e["sections"]]
    check("A6 节名表解析出来（含 .symtab/.strtab）",
          ".text" in names and ".symtab" in names and ".strtab" in names, names)
    syms = {s["name"]: s for s in e["symbols"]}
    check("A7 符号表：Reset_Handler 是 FUNC 且 observe 到位",
          syms.get("Reset_Handler", {}).get("type") == "FUNC"
          and syms["Reset_Handler"]["value"] == 0x08000011, syms.get("Reset_Handler"))
    check("A8 符号表：g_buf 是 OBJECT 且 size=4",
          syms.get("g_buf", {}).get("type") == "OBJECT"
          and syms["g_buf"]["size"] == 4, syms.get("g_buf"))

    ar = RC.parse_ar(_mk_ar([("a.o/", b"AAAA"), ("b.o/", b"BBBBB")]))
    check("A9 ar 成员被逐个切出（奇数长度补位也对）",
          ar["ok"] and [m["name"] for m in ar["members"]] == ["a.o", "b.o"]
          and ar["members"][1]["size"] == 5, ar)
    check("A10 ar 被截断时进 gaps，不静默丢成员",
          RC.parse_ar(b"!<arch>\n" + b"x" * 30)["gaps"] != [])


def section_b():
    print("B. 架构与向量表")
    arch = RC.arch_of(RC.parse_elf(open(ELF, "rb").read()))
    check("B1 Thumb 判定给依据（入口末位/奇数符号/$t）",
          arch["thumb"] is True and "Thumb" in arch["why"], arch)
    check("B2 架构族与位宽（arm/32）",
          arch["family"] == "arm" and arch["bits"] == 32, arch)

    u = RC._unit_from_data(open(BIN, "rb").read(), "b", 0x08000000)
    check("B3 bin 无 ELF 头时从向量表推断 Thumb，并标注 basis",
          u.arch["thumb"] and u.arch.get("basis") == "inferred_from_vector_table",
          u.arch)
    check("B4 bin 的架构推断会留限制说明（base 错会整体错位）",
          any("推断" in x for x in u.limitations), u.limitations)

    vt = RC.vector_table(u, base=0x08000000)
    check("B5 向量表 SP 与复位地址读数正确",
          vt["sp_hex"] == "0x20001000" and vt["reset_hex"] == "0x08000011", vt)
    check("B6 读到 0 就停（不把空洞后面的字节当入口）", vt["count"] == 1, vt)
    check("B7 向量条目带 thumb 位与 in_code 判定",
          vt["entries"][0]["thumb"] is True and vt["entries"][0]["in_code"] is True,
          vt["entries"])

    vt2 = RC.vector_table(u, base=0x09000000)
    check("B8 base 给错时进 gaps 而不是硬判",
          bool(vt2["gaps"]) or vt2["count"] == 0, vt2)


def section_c():
    print("C. 符号恢复（三档置信）")
    an = RC.analyze(ELF, deep=True)
    rec = an["_recover"]
    counts = rec["counts"]
    check("C1 符号表函数记为 observed", counts.get("observed", 0) >= 1, counts)
    names = {f["addr"]: f for f in rec["functions"]}
    check("C2 Reset_Handler 落在 0x08000010（去 Thumb 位）",
          0x08000010 in names and names[0x08000010]["name"] == "Reset_Handler",
          list(names))
    check("C3 调用目标 0x08000020 被恢复成函数（inferred）",
          0x08000020 in names and names[0x08000020]["confidence"] == "inferred",
          names.get(0x08000020))
    check("C4 只有代码指针证据的入口记 weak",
          any(f["confidence"] == "weak" and "code_pointer" in f["sources"]
              for f in rec["functions"]),
          [(f["addr_hex"], f["confidence"]) for f in rec["functions"]])
    check("C5 证据来源逐条留痕（sources 列表）",
          all(f["sources"] for f in rec["functions"]), rec["functions"][:2])
    check("C6 有 size 时用 symtab 定边界",
          any(f.get("size_basis") == "symtab" for f in rec["functions"]),
          [f.get("size_basis") for f in rec["functions"]])
    check("C7 没有 size 时用「下一个入口」定边界",
          any(f.get("size_basis") == "next_entry" for f in rec["functions"]),
          [f.get("size_basis") for f in rec["functions"]])
    check("C8 对象（g_buf）不被当成函数",
          all(f["name"] != "g_buf" for f in rec["functions"]),
          [f["name"] for f in rec["functions"]])
    check("C9 证据规则随结果一起返回（下游能读懂三档含义）",
          len(rec.get("evidence_rule") or []) == 3, rec.get("evidence_rule"))

    an_bin = RC.analyze(BIN, base=0x08000000, deep=True)
    r2 = an_bin["_recover"]
    check("C10 无符号 bin 也能恢复函数（向量表 Reset_Handler）",
          any(f["name"] == "Reset_Handler" for f in r2["functions"]),
          [(f["name"], f["confidence"]) for f in r2["functions"]])

    an_shallow = RC.analyze(BIN, base=0x08000000, deep=False)
    check("C11 deep=False 不报错、也不假装做了深度扫描",
          an_shallow["ok"] and an_shallow["_recover"]["total"] >= 1
          and any("深度扫描" in g.get("reason", "")
                  for g in (an_shallow["gaps"] or [])),
          an_shallow.get("gaps"))

    an_axf = RC.analyze(EXAMPLE_AXF)
    check("C12 真实 axf：符号函数数 > 100 且 observed 占多数",
          an_axf["_recover"]["counts"].get("observed", 0) > 100,
          an_axf["_recover"]["counts"])
    check("C13 真实 axf：DWARF 给出原始源文件数（>=10）",
          an_axf["dwarf"].get("available")
          and an_axf["dwarf"].get("files", 0) >= 10, an_axf["dwarf"])
    check("C14 字符串交叉引用能落到真实文案上",
          any("help" in (r.get("text") or "")
              for r in an_axf["_recover"]["string_refs"]),
          [r.get("text") for r in an_axf["_recover"]["string_refs"][:3]])


def section_d():
    print("D. 反汇编")
    r = RC.disasm_at(ELF, symbol="Reset_Handler", max_insns=20)
    check("D1 按符号定位到函数起点",
          r["ok"] and r["span"]["start_hex"] == "0x08000010", r.get("error"))
    check("D2 直接调用目标带 target_hex",
          any(i.get("target") == 0x08000020 for i in r["insns"]),
          [i.get("target_hex") for i in r["insns"]])
    r_end = RC.disasm_at(ELF, start=0x08000010, end=0x08000024, max_insns=50)
    check("D3 bx lr 被标成函数结束",
          any(i.get("ends_function") for i in r_end["insns"]), r_end["insns"])

    r2 = RC.disasm_at(ELF, start=0x08000000, end=0x08000030, max_insns=10)
    check("D4 按区间反汇编 + 触到上限时如实报 truncated",
          r2["ok"] and r2["truncated"] is True and r2["count"] == 10, r2.get("count"))

    r3 = RC.disasm_at(ELF, symbol="不存在的符号")
    check("D5 符号找不到时报错并给提示（不返回空结果冒充成功）",
          r3["ok"] is False and "hint" in r3, r3)

    r4 = RC.disasm_at(ELF, max_insns=8)
    check("D6 不给 start/symbol 时从复位入口开始（并说明）",
          r4["span"]["start_hex"] == "0x08000010"
          and any("复位入口" in n for n in r4["notes"]), r4.get("notes"))

    # 批次85 起 mips/ppc/x86 等都有 capstone 后端了，改用确实没有后端的家族（sh）
    # 来测「不支持的架构明确报错」这条语义
    md, why = RC._make_cs({"family": "sh", "bits": 32, "endian": "little",
                           "thumb": False})
    check("D7 不支持的架构明确报错（不给假汇编）",
          md is None and "不支持" in why and "capstone" in why, why)

    real = RC.disasm_at(EXAMPLE_AXF, symbol="uart_handle_line", max_insns=60)
    check("D8 真实 axf 按符号反汇编可读（含 push/bl）",
          real["ok"] and real["count"] == 60
          and any("push" in i["mnemonic"] for i in real["insns"]), real.get("count"))

    ar_path = _w("x.lib", _mk_ar([("a.o/", _synthetic_elf(1))]))
    r5 = RC.disasm_at(ar_path)
    check("D9 对库归档直接反汇编要拒绝并指路（成员是可重定位目标）",
          r5["ok"] is False and "recover_project" in r5["error"], r5)

    unit = RC._unit_from_data(VT_CODE + b"\xff\xff\xff\xff" + bytes.fromhex("7047"),
                              "junk", 0x08000000)
    r6 = RC.disassemble(unit, 0x08000000, 0x08000000 + len(unit.data), max_insns=500)
    check("D10 无法解码的字节被跳过而不是「后面没有指令」",
          r6["ok"] and r6["undefined_skips"] >= 1 and r6["count"] >= 3, r6.get("undefined_skips"))


def section_e():
    print("E. 工程骨架生成")
    d = os.path.join(_tmpdir(), "proj")
    out = RC.build_project(ELF, d)
    check("E1 生成成功", out["ok"] and os.path.isdir(d), out.get("error"))
    rels = {f["rel"] for f in out.get("files") or []}
    want = {"README.md", "report.json", "linker/recovered.sct", "linker/recovered.ld",
            "include/recovered_symbols.h", "include/recovered_memory.h",
            "src/startup_recovered.c", "src/recovered_stubs.c",
            "Makefile", "CMakeLists.txt", "asm/disassembly.asm",
            "map/functions.csv", "map/objects.csv", "map/vector_table.csv",
            "map/strings.csv", "map/xrefs.csv"}
    check("E2 关键文件全都在", want <= rels, sorted(want - rels))
    check("E3 每个文件落盘后都被回读校验（sha256_verified）",
          out["sha256_verified"] is True, [f for f in out["files"] if not f["sha256_verified"]])

    sct = open(os.path.join(d, "linker", "recovered.sct"), encoding="utf-8").read()
    check("E4 scatter 用原镜像的 FLASH 基址与长度",
          "0x08000000" in sct and "LR_IROM1" in sct, sct[:120])
    ld = open(os.path.join(d, "linker", "recovered.ld"), encoding="utf-8").read()
    check("E5 ld 脚本有 ENTRY 与 MEMORY 两段（能直接链接）",
          "ENTRY(Reset_Handler)" in ld and "MEMORY" in ld, ld[:120])

    hdr = open(os.path.join(d, "include", "recovered_symbols.h"), encoding="utf-8").read()
    check("E6 符号头声明了函数并写明原型是推断的",
          "void Reset_Handler(void);" in hdr and "推断" in hdr, hdr[:200])
    check("E7 符号头带地址宏与 SP/复位地址",
          "REC_INITIAL_SP" in hdr and "REC_RESET_HANDLER" in hdr, hdr[:400])

    stubs = open(os.path.join(d, "src", "recovered_stubs.c"), encoding="utf-8").read()
    check("E8 占位实现是 weak 且注明「原函数体没有恢复」",
          "__attribute__((weak))" in stubs and "占位实现" in stubs, stubs[:200])
    su = open(os.path.join(d, "src", "startup_recovered.c"), encoding="utf-8").read()
    check("E9 启动文件照抄原向量表（SP + Reset）",
          "REC_INITIAL_SP" in su and "Reset_Handler" in su
          and "g_recovered_vectors" in su, su[:200])

    fcsv = open(os.path.join(d, "map", "functions.csv"), encoding="utf-8").read()
    check("E10 functions.csv 每行带地址/置信度/证据来源",
          fcsv.splitlines()[0].startswith("addr,end_addr,name")
          and len(fcsv.splitlines()) >= 3, fcsv.splitlines()[:2])
    rep = json.loads(open(os.path.join(d, "report.json"), encoding="utf-8").read())
    check("E11 report.json 可解析且带 identity（path/size/sha256）",
          rep.get("sha256") and rep.get("size") > 0, list(rep)[:6])

    rd = open(os.path.join(d, "README.md"), encoding="utf-8").read()
    check("E12 README 写明「没有恢复什么」而不是只报喜",
          "没有恢复什么" in rd and "SHA-256" in rd, rd[:200])
    check("E13 汇编文件里有真实指令（不是空壳）",
          "0x08000010" in open(os.path.join(d, "asm", "disassembly.asm"),
                               encoding="utf-8").read()
          or "08000010" in open(os.path.join(d, "asm", "disassembly.asm"),
                                encoding="utf-8").read())

    d2 = os.path.join(_tmpdir(), "exists")
    os.makedirs(d2)
    out2 = RC.build_project(ELF, d2)
    check("E14 输出目录已存在时拒绝（不覆盖既有证据）",
          out2["ok"] is False and "已存在" in out2["error"], out2)

    d3 = os.path.join(_tmpdir(), "projbin")
    out3 = RC.build_project(BIN, d3, base=0x08000000)
    check("E15 bin 也能生成工程（架构来自向量表推断）",
          out3["ok"] and out3["arch"]["basis"] == "inferred_from_vector_table",
          out3.get("error"))


def section_f():
    print("F. lib / so")
    ar = _w("mix.lib", _mk_ar([("a.o/", _synthetic_elf(1)),
                               ("blob.bin/", b"\x00\x01\x02")]))
    an = RC.analyze(ar)
    check("F1 库归档逐成员剖析出函数数", an["ok"] and an["member_count"] == 2
          and an["members"][0].get("functions", 0) >= 1, an.get("members"))
    check("F2 非 ELF 成员被标成 data 而不是硬解析",
          an["members"][1]["kind"] == "data", an["members"][1])

    d = os.path.join(_tmpdir(), "libout")
    out = RC.build_project(ar, d)
    check("F3 库输出：成员原样取件 + manifest",
          out["ok"] and os.path.isfile(os.path.join(d, "members", "manifest.json")),
          out.get("error"))
    man = json.loads(open(os.path.join(d, "members", "manifest.json"),
                          encoding="utf-8").read())
    check("F4 manifest 里每个成员都有 sha256 与回读校验",
          all(m.get("sha256") and m.get("sha256_verified") for m in man["members"]),
          man["members"])
    check("F5 取出的成员字节与原成员一致",
          open(os.path.join(d, "members", "00_a.o"), "rb").read() == _synthetic_elf(1))
    check("F6 库生成的 README 说明「地址是节内偏移」",
          "节内偏移" in open(os.path.join(d, "README.md"), encoding="utf-8").read())

    so = _w("libsynth.so", _synthetic_elf(3))
    an_so = RC.analyze(so)
    check("F7 .so 被识别为 DYN 并给「地址相对加载基址」的口径",
          an_so["ok"] and an_so["elf"]["type"] == "DYN"
          and any("相对加载基址" in x for x in an_so["limitations"]),
          an_so.get("elf"))
    check("F8 .so 仍能恢复符号（按相对地址）",
          an_so["_recover"]["counts"].get("observed", 0) >= 1, an_so["_recover"]["counts"])


def section_g():
    print("G. 工具面与注解")
    all_names = [t.name for t in asyncio.run(
        SV.create_server(port=15879, toolsets="all").list_tools())]
    core_names = [t.name for t in asyncio.run(
        SV.create_server(port=15879, toolsets="core").list_tools())]
    check("G1 注册总数 211", len(all_names) == 211, len(all_names))
    check("G2 build 组 27（含 7 个逆向工具）", len(TB.TOOLSETS["build"]) == 27,
          len(TB.TOOLSETS["build"]))
    check("G3 四个工具都在 build 组",
          {"recover_probe", "recover_symbols", "recover_disasm",
           "recover_project"} <= set(TB.TOOLSETS["build"]))
    check("G4 默认面仍是 44（逆向工具不进默认面，省上下文）",
          len(core_names) == 44, len(core_names))
    check("G5 收起后是 167", len(all_names) - len(core_names) == 167,
          len(all_names) - len(core_names))
    check("G6 三个读操作在 READONLY，recover_project 在 MUTATING 且不在 DESTRUCTIVE",
          {"recover_probe", "recover_symbols", "recover_disasm"} <= AN.READONLY
          and "recover_project" in AN.MUTATING
          and "recover_project" not in AN.DESTRUCTIVE
          and not ({"recover_probe", "recover_symbols",
                    "recover_disasm"} & AN.MUTATING))
    bad = AN.check_surface(all_names)
    check("G7 注解表全覆盖（check_surface 无问题）", not bad, bad)

    a1 = AN.annotations_for("recover_probe")
    check("G8 recover_probe 标为只读", a1["readOnlyHint"] is True, a1)
    a2 = AN.annotations_for("recover_project")
    check("G9 recover_project 标为会改/非幂等（不可逆为 False）",
          a2["readOnlyHint"] is False and a2["idempotentHint"] is False
          and a2["destructiveHint"] is False, a2)

    srv = SV.create_server(port=15879, toolsets="all")
    r = json.loads(asyncio.run(srv.call_tool(
        "recover_probe", {"path": ELF, "deep": True})).content[0].text)
    check("G10 recover_probe 端到端：架构/函数/向量表齐全",
          r.get("ok") and r["arch"]["thumb"] and r["functions"]["total"] >= 2
          and r["vector_table"]["reset_hex"] == "0x08000011", r.get("error"))

    r2 = json.loads(asyncio.run(srv.call_tool(
        "recover_symbols", {"path": ELF})).content[0].text)
    check("G11 recover_symbols 端到端：带三档计数与证据规则",
          r2.get("ok") and r2["counts"].get("observed", 0) >= 1
          and len(r2.get("evidence_rule") or []) == 3, r2.get("counts"))

    r3 = json.loads(asyncio.run(srv.call_tool(
        "recover_disasm", {"path": ELF, "symbol": "Reset_Handler"})).content[0].text)
    check("G12 recover_disasm 端到端：返回指令与跳转目标",
          r3.get("ok") and r3["count"] >= 1
          and any(i.get("target") == 0x08000020 for i in r3["insns"]), r3.get("count"))

    d = os.path.join(_tmpdir(), "eproj")
    r4 = json.loads(asyncio.run(srv.call_tool(
        "recover_project", {"path": ELF, "out_dir": d})).content[0].text)
    check("G13 recover_project 端到端：目录生成且文件校验通过",
          r4.get("ok") and r4["sha256_verified"] is True
          and os.path.isfile(os.path.join(d, "README.md")), r4.get("error"))
    r5 = json.loads(asyncio.run(srv.call_tool(
        "recover_project", {"path": ELF, "out_dir": d})).content[0].text)
    check("G14 重复调用同一目录被拒（不覆盖）",
          r5.get("ok") is False and "已存在" in r5.get("error", ""), r5)


# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d, section_e,
               section_f, section_g):
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
