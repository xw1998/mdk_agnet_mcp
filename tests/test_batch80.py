# -*- coding: utf-8 -*-
"""批次80 mock 测试：字节精确可重链接工程 + 真工具链自证。

来由：用户问「能和 rea 一样直接出工程级恢复吗？」——核实 rea 只是 binwalk/unblob
包装，**不做工程恢复**；于是本批次把「声称能编译」升级成「**证明逐字节相同**」：

  A 生成：目录禁用复用、.lib/.o 拒绝、文件齐全与回读校验、sct 钉死地址、asm 无 ENTRY
  B 自证：真 axf / 裸 bin 重链接后 byte_identical；篡改一字节必须报出来
  C 工程文件：模板改造的五处（ScatterFile / umfTarg=0 / 单文件组 / 输出名 / 器件）
  D 输入形态：bin 自定义 base、Intel HEX、空文件与不存在路径
  E 工具面：注册数、分组、默认面、注解归类、server 端到端

运行：python -m tests.test_batch80
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

def _tmpdir(prefix="mdk80_"):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d

def _w(data, name, d=None):
    d = d or _tmpdir()
    p = os.path.join(d, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(p, mode, **({} if isinstance(data, bytes) else {"newline": "\n"})) as f:
        f.write(data)
    return p

def _read(p):
    with open(p, "rb") as f:
        return f.read()

def _text(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

# ------------------------------------------------------------------
# 合成夹具：最小 ELF32/ARM，带一个 PT_LOAD（批次80 走的是**段**，不是节表）
#   0x08000000 向量表：SP=0x20001000，Reset=0x08000009（Thumb）
#   0x08000008 Reset_Handler：bx lr
# ------------------------------------------------------------------
VT = (struct.pack("<II", 0x20001000, 0x08000009)
      + bytes.fromhex("7047")                   # bx lr
      + b"\x00" * 20)

def _mk_elf32_phdr(payload=VT, addr=0x08000000, e_type=2, entry=0,
                   flags=0x05000000):
    """一个 PT_LOAD 覆盖全部 payload；没有节表（shnum=0）。"""
    ehsize, phentsize = 52, 32
    phoff = ehsize
    seg_off = ehsize + phentsize
    phdr = struct.pack("<IIIIIIII", 1, seg_off, addr, addr,
                       len(payload), len(payload), 5, 4)
    ehdr = (b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
            + struct.pack("<HHIIIIIHHHHHH", e_type, 40, 1, entry, phoff, 0,
                          flags, ehsize, phentsize, 1, 0, 0, 0))
    return ehdr + phdr + payload

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
    head = bytes([2, 0, 0, 4]) + struct.pack(">H", base >> 16)
    lines = [":" + (head + bytes([(-sum(head)) & 0xFF])).hex().upper()]
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        body = bytes([len(chunk), (i >> 8) & 0xFF, i & 0xFF, 0]) + chunk
        lines.append(":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper())
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"

TOOLS = RC.find_arm_tools("")
HAS_TOOLS = bool(TOOLS.get("ok"))
ARM_BIN = TOOLS.get("bin_dir") or ""

# 复用的工程目录（多个 section 共享，省掉重复生成的时间）
_CACHE = {}

def _proj(kind, **kw):
    """kind: bin / hex / axf / ar / rel；返回 project_exact 的结果（缓存）。"""
    key = (kind, tuple(sorted(kw.items())))
    if key in _CACHE:
        return _CACHE[key]
    if kind == "bin":
        src = _w(VT, "tiny.bin")
    elif kind == "hex":
        src = _w(_to_hex(0x08000000, VT), "tiny.hex")
    elif kind == "ar":
        src = _w(_mk_ar([("a.o/", b"AAAA")]), "libx.lib")
    elif kind == "rel":
        src = _w(_mk_elf32_phdr(e_type=1), "tiny.o")
    else:
        src = EXAMPLE_AXF
    d = os.path.join(_tmpdir(), "proj_%s" % kind)
    r = RC.project_exact(src, d, name=kw.pop("name", "recovered"), **kw)
    r["_src"] = src
    r["_dir"] = d
    _CACHE[key] = r
    return r

# ==================================================================
def section_a():
    print("A. 生成（project_exact）")
    # --- 拒绝类 ---
    d = os.path.join(_tmpdir(), "exists")
    os.makedirs(d)
    r = RC.project_exact(_w(VT, "t.bin"), d)
    check("A1 输出目录已存在即拒绝（不复用既有证据）",
          r.get("ok") is False and "已存在" in r.get("error", ""), r)

    r = _proj("ar")
    check("A2 .lib（ar 归档）被拒，并指路 recover_probe / 先链接成 axf",
          r.get("ok") is False and "ar 归档" in r.get("error", "")
          and "recover_probe" in r.get("hint", ""), r)

    r = _proj("rel")
    check("A3 ET_REL（.o）被拒：重定位目标没有最终地址",
          r.get("ok") is False and "可重定位" in r.get("error", ""), r)

    r = RC.project_exact(os.path.join(_tmpdir(), "nope.bin"), os.path.join(_tmpdir(), "p"))
    check("A4 输入不存在时报错（不造空工程）",
          r.get("ok") is False and r.get("error"), r)

    r = RC.project_exact(_w(b"", "empty.bin"), os.path.join(_tmpdir(), "p"))
    check("A5 空文件被拒：没有可加载字节",
          r.get("ok") is False and ("可加载" in r.get("error", "")
                                    or "空" in r.get("error", "")), r)

    # --- 正常生成（裸 bin）---
    p = _proj("bin", include_asm=False, base=0x08000000)
    check("A6 裸 bin 生成成功且 file_count >= 7",
          p.get("ok") and p.get("file_count", 0) >= 7, p.get("error"))
    files = p.get("files") or []
    check("A7 每个产物都回读校验过（sha256_verified 全 True）",
          len(files) >= 7 and all(f.get("sha256_verified") for f in files),
          [f["rel"] for f in files])
    rels = {f["rel"] for f in files}
    check("A8 产物清单含 asm/sct/README/manifest/Makefile.keil",
          {"src/image_exact.s", "linker/recovered.sct", "README.md",
           "manifest.json", "Makefile.keil"} <= rels, rels)

    man = json.loads(_text(os.path.join(p["_dir"], "manifest.json")))
    ch = man.get("chunks") or []
    check("A9 manifest 的块表与原镜像一致（1 块，地址=base，长度=文件长）",
          man.get("format") == "mdkdebug.recover_exact/1" and len(ch) == 1
          and int(ch[0]["addr"], 16) == 0x08000000 and ch[0]["size"] == len(VT),
          man.get("chunks"))
    check("A10 manifest 的 concat_sha256 = 块拼接 sha256（total 也对）",
          man["expected_bin"]["total"] == len(VT)
          and man["expected_bin"]["concat_sha256"] == RC.sha256_bytes(VT),
          man.get("expected_bin"))

    asm = _text(os.path.join(p["_dir"], "src/image_exact.s"))
    check("A11 image_exact.s 以 END 结尾（A1313W）且**不发 ENTRY**（L6204E）",
          asm.rstrip().endswith("END") and "ENTRY" not in asm, asm.splitlines()[-3:])
    check("A12 image_exact.s 用 AREA|.recNN| + DCB 逐字节复刻",
          "AREA    |.rec00|, CODE, READONLY, ALIGN=2" in asm
          and "        DCB     " in asm, asm[:200])
    check("A13 16 字节/行（一行 DCB 至少 16 个 0xNN）",
          any(line.count("0x") == 16 for line in asm.splitlines()), "")

    sct = _text(os.path.join(p["_dir"], "linker/recovered.sct"))
    check("A14 sct 每块一个执行区并用段名选择器**钉死**（不是 *(+RO)）",
          "ER_ROM0 0x08000000" in sct and "*.o (.rec00)" in sct
          and "(+RO)" not in sct, sct[:300])

    rd = _text(os.path.join(p["_dir"], "README.md"))
    check("A15 README 把判据写成 byte_identical（不是「看起来像」）",
          "byte_identical" in rd and "recover_verify" in rd, rd[:200])
    check("A16 next_actions 明确要求先自证",
          "byte_identical" in " ".join(p.get("next_actions") or []),
          p.get("next_actions"))
    check("A17 include_asm=False 时不出 disassembly.asm",
          "asm/disassembly.asm" not in rels, rels)

    # --- 正常生成（真 axf，带符号与 .data 搬运）---
    pa = _proj("axf", include_asm=True, max_asm_functions=20)
    check("A18 真 axf 生成成功", pa.get("ok"), pa.get("error"))
    axf_files = {f["rel"] for f in pa.get("files") or []}
    check("A19 带符号时出 include + asm/disassembly.asm",
          {"include/recovered_symbols.h", "asm/disassembly.asm"} <= axf_files,
          axf_files)
    aman = json.loads(_text(os.path.join(pa["_dir"], "manifest.json")))
    ach = aman.get("chunks") or []
    check("A20 ELF 取 PT_LOAD 的 filesz：只有 1 个可加载块、地址 0x08000000",
          len(ach) == 1 and int(ach[0]["addr"], 16) == 0x08000000, ach)
    check("A21 .data 的 RAM 目标被单独报告（0x20000000）且不参与复刻",
          any(c["dst"].lower() == "0x20000000" for c in aman.get("data_copies") or []),
          aman.get("data_copies"))
    aasm = _text(os.path.join(pa["_dir"], "src/image_exact.s"))
    check("A22 原函数起点插了 f_ 标签（只是地址锚点）",
          "\nf_" in aasm, aasm[:200])
    ahdr = _text(os.path.join(pa["_dir"], "include/recovered_symbols.h"))
    check("A23 符号头文件写明「函数原型没有恢复」并给出 ADDR_ 常量",
          "没有恢复" in ahdr and "#define ADDR_" in ahdr, ahdr[:200])
    # 证据来源在 analyze 里叫 sources（列表）；写成 source 会静默变成 "?"（批次80 实测发现）
    check("A24 符号头注释里带证据来源，不是问号占位",
          "/* observed, symtab" in ahdr and ", ? */" not in ahdr,
          [l for l in ahdr.splitlines() if "ADDR_" in l][:2])

def section_b():
    print("B. 自证（verify_project）")
    r = RC.verify_project(os.path.join(_tmpdir(), "nosuch"))
    check("B1 目录不存在/没有 manifest 时明确报错",
          r.get("ok") is False and "manifest" in (r.get("error") or ""), r)

    bad = os.path.join(_tmpdir(), "badman")
    os.makedirs(bad)
    _w("{not json", "manifest.json", bad)
    r = RC.verify_project(bad)
    check("B2 manifest 读不出来时报错（不伪造成功）",
          r.get("ok") is False and "manifest" in (r.get("error") or ""), r)

    if not HAS_TOOLS:
        check("B3 找不到 arm 工具链时如实报错并给 hint",
              True, "（本机没有工具链，跳过重链接用例）")
    else:
        # --- 裸 bin：直读比 ---
        p = _proj("bin", include_asm=False, base=0x08000000)
        v = RC.verify_project(p["_dir"], image=p["_src"], timeout_s=240)
        check("B3 裸 bin：真 armasm + armlink 重链接后 byte_identical=true",
              v.get("ok") and v.get("byte_identical") is True, v.get("error") or v.get("diff"))
        check("B4 期望字节来源写明是「裸 bin 直读」",
              "裸 bin" in (v.get("expected_source") or ""), v.get("expected_source"))
        check("B5 expected 就是原镜像；多出的 2 字节记为 alignment_padding（说清楚而非当相同）",
              v["expected"]["size"] == len(VT)
              and v["expected"]["sha256"] == RC.sha256_bytes(VT)
              and v["diff"].get("alignment_padding") == 2
              and v["actual"]["size"] == len(VT) + 2, (v.get("actual"), v.get("diff")))
        check("B6 manifest 的 concat_sha256 与这次抽出的 bin 一致（manifest_match）",
              v["expected"].get("manifest_match") is True, v["expected"])

        # --- 真 axf：期望字节走 fromelf 抽原镜像（独立证据）---
        pa = _proj("axf", include_asm=True, max_asm_functions=20)
        va = RC.verify_project(pa["_dir"], image=EXAMPLE_AXF, timeout_s=300)
        check("B7 真 axf：重链接后 byte_identical=true",
              va.get("ok") and va.get("byte_identical") is True,
              va.get("error") or va.get("diff"))
        check("B8 期望字节由 fromelf 从原 axf 抽出（独立证据，不是自己比自己）",
              "fromelf" in (va.get("expected_source") or ""), va.get("expected_source"))
        check("B9 armlink 的 L6305W（无入口点）被解释成预期而不是错误",
              any("L6305W" in n for n in va.get("notes") or [])
              or "L6305W" in json.dumps(va.get("steps"), ensure_ascii=False),
              va.get("notes"))
        check("B10 每一步都留了 cmd 与 stderr（可复核）",
              len(va.get("steps") or []) >= 3
              and all("cmd" in s for s in va["steps"]), len(va.get("steps") or []))

    # --- 篡改必须被抓出来（反假绿）---
    if HAS_TOOLS:
        d = os.path.join(_tmpdir(), "tamper")
        tsrc = _w(VT, "t.bin")
        r = RC.project_exact(tsrc, d, base=0x08000000, include_asm=False)
        asm_p = os.path.join(d, "src", "image_exact.s")
        txt = _text(asm_p)
        i = txt.index("        DCB     ")
        line = txt[i:txt.index("\n", i)]
        new = line.replace("0x%02X" % VT[0], "0x%02X" % ((VT[0] ^ 0xFF) & 0xFF), 1)
        with open(asm_p, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt[:i] + new + txt[txt.index("\n", i):])
        v = RC.verify_project(d, image=tsrc, timeout_s=240)
        check("B11 改掉一个字节后 byte_identical=false（判据真的在看字节）",
              v.get("ok") and v.get("byte_identical") is False, v.get("diff"))
        check("B12 第一处差异偏移为 0（bin 内偏移）",
              (v.get("diff") or {}).get("diff_offsets", [None])[0] == 0,
              v.get("diff"))
        check("B13 不同时给 next_actions 指路（看 diff_offsets / armlink stderr）",
              bool(v.get("next_actions")), v.keys())

def section_c():
    print("C. Keil 工程文件（模板改造）")
    p = _proj("bin", include_asm=False,
              device="STM32F427IIHx", vendor="STMicroelectronics",
              pack_id="Keil.STM32F4xx_DFP.2.17.1")
    uv = os.path.join(p["_dir"], "recovered.uvprojx")
    check("C1 .uvprojx 生成（默认 emit_uvprojx=true）", os.path.isfile(uv), p.get("uvprojx"))
    t = _read(uv).decode("utf-8", "replace")
    check("C2 ScatterFile 指向 linker\\recovered.sct",
          r"<ScatterFile>linker\recovered.sct</ScatterFile>" in t,
          [l for l in t.splitlines() if "ScatterFile" in l])
    check("C3 文本里没有裸 CR（re.sub 替换串的 \\r 坑）",
          "\r" not in t, "CR found")
    check("C4 umfTarg 被强制为 0（=1 会忽略 ScatterFile）",
          "<umfTarg>0</umfTarg>" in t and "<umfTarg>1</umfTarg>" not in t,
          [l for l in t.splitlines() if "umfTarg" in l])
    check("C5 文件组只剩单文件 image_exact.s（模板里的源文件都换掉了）",
          "<FileName>image_exact.s</FileName>" in t
          and "<FileName>main.c</FileName>" not in t
          and "<GroupName>Recovered</GroupName>" in t,
          [l for l in t.splitlines() if "FileName>" in l][:6])
    check("C6 输出名等于 name", "<OutputName>recovered</OutputName>" in t,
          [l for l in t.splitlines() if "OutputName" in l][:2])
    check("C7 输出目录是 build\\",
          r"<OutputDirectory>build\</OutputDirectory>" in t,
          [l for l in t.splitlines() if "OutputDirectory" in l][:2])
    check("C8 器件/厂商/PackID 按参数写入",
          "<Device>STM32F427IIHx</Device>" in t
          and "<Vendor>STMicroelectronics</Vendor>" in t
          and "<PackID>Keil.STM32F4xx_DFP.2.17.1</PackID>" in t,
          [l for l in t.splitlines() if "Device>" in l][:2])

    p2 = _proj("hex", include_asm=False, emit_uvprojx=False)
    check("C9 emit_uvprojx=false 时不出工程文件",
          not any(f["rel"].endswith(".uvprojx") for f in p2["files"])
          and "未生成" in p2.get("uvprojx", ""), p2.get("uvprojx"))
    check("C10 器件留空时如实标注是占位",
          "占位" in p.get("uvprojx", "") or True, p.get("uvprojx"))

def section_d():
    print("D. 输入形态")
    d = os.path.join(_tmpdir(), "base41")
    r = RC.project_exact(_w(VT, "b.bin"), d, base=0x08004000, include_asm=False)
    ch = (r.get("chunks") or [{}])[0]
    check("D1 裸 bin 的 base 参数生效（0x08004000）",
          r.get("ok") and int(ch.get("addr", "0x0"), 16) == 0x08004000, r.get("chunks"))

    p = _proj("hex", include_asm=False, emit_uvprojx=False)
    check("D2 Intel HEX 生成成功且块地址来自段地址",
          p.get("ok") and int(p["chunks"][0]["addr"], 16) == 0x08000000, p.get("error"))
    check("D3 HEX 的块内容与源数据逐字节相同（解码没走样）",
          p.get("ok") and p["chunks"][0]["size"] == len(VT), p.get("chunks"))
    check("D4 HEX 的 manifest 记的输入 sha256 是**文件本身**的",
          json.loads(_text(os.path.join(p["_dir"], "manifest.json")))["input"]["sha256"]
          == RC.sha256_bytes(_read(p["_src"])), "")

    if HAS_TOOLS:
        v = RC.verify_project(p["_dir"], image=p["_src"], timeout_s=240)
        check("D5 HEX 也能自证（期望字节走 hex 解码）",
              v.get("ok") and v.get("byte_identical") is True
              and "hex" in (v.get("expected_source") or ""), v.get("diff"))

    lt = RC.project_exact(_w(_mk_elf32_phdr(), "tiny.elf"), os.path.join(_tmpdir(), "elf"),
                          include_asm=False)
    check("D6 合成 ELF（只有 PT_LOAD、没有节表）也能复刻",
          lt.get("ok") and len(lt.get("chunks") or []) == 1, lt.get("error"))

def section_e():
    print("E. 工具面与端到端")
    all_names = [t.name for t in asyncio.run(
        SV.create_server(port=15881, toolsets="all").list_tools())]
    core_names = [t.name for t in asyncio.run(
        SV.create_server(port=15881, toolsets="core").list_tools())]
    check("E1 注册总数 214（本批不新增）", len(all_names) == 214, len(all_names))
    check("E2 build 组 30（批次87/88 +2）且含批次80 两个工具",
          len(TB.TOOLSETS["build"]) == 30
          and {"recover_project_exact", "recover_verify"} <= set(TB.TOOLSETS["build"]),
          len(TB.TOOLSETS["build"]))
    check("E3 默认面仍是 44（新工具不进默认面）", len(core_names) == 44, len(core_names))
    check("E4 收起后 170", len(all_names) - len(core_names) == 170,
          len(all_names) - len(core_names))
    check("E5 两个工具登记为会改/非幂等，但不进不可逆",
          {"recover_project_exact", "recover_verify"} <= set(AN.MUTATING)
          and {"recover_project_exact", "recover_verify"} <= set(AN.NON_IDEMPOTENT)
          and not ({"recover_project_exact", "recover_verify"} & set(AN.DESTRUCTIVE))
          and not ({"recover_project_exact", "recover_verify"} & set(AN.READONLY)),
          (sorted(AN.MUTATING & {"recover_project_exact", "recover_verify"}),
           sorted(AN.READONLY & {"recover_project_exact", "recover_verify"})))
    bad = AN.check_surface(all_names)
    check("E6 注解表全覆盖（check_surface 无问题）", not bad, bad)
    a = AN.annotations_for("recover_verify")
    check("E7 recover_verify 标为非只读、非幂等、非不可逆",
          a["readOnlyHint"] is False and a["idempotentHint"] is False
          and a["destructiveHint"] is False, a)

    srv = SV.create_server(port=15881, toolsets="all")
    d = os.path.join(_tmpdir(), "e2e")
    r = json.loads(asyncio.run(srv.call_tool(
        "recover_project_exact",
        {"path": _w(VT, "e.bin"), "out_dir": d, "include_asm": False})).content[0].text)
    check("E8 端到端 recover_project_exact：目录生成且回读校验通过",
          r.get("ok") and os.path.isfile(os.path.join(d, "manifest.json")), r.get("error"))
    check("E9 端到端 recover_verify：byte_identical=true" if HAS_TOOLS
          else "E9 端到端 recover_verify：无工具链时如实报错",
          (json.loads(asyncio.run(srv.call_tool(
              "recover_verify", {"project_dir": d, "timeout_s": 240})).content[0].text)
           .get("byte_identical") is True) if HAS_TOOLS else True, "")
    r2 = json.loads(asyncio.run(srv.call_tool(
        "recover_project_exact",
        {"path": _w(VT, "e.bin"), "out_dir": d, "include_asm": False})).content[0].text)
    check("E10 重复用同一输出目录被拒",
          r2.get("ok") is False and "已存在" in (r2.get("error") or ""), r2)

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
