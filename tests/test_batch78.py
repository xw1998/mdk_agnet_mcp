# -*- coding: utf-8 -*-
"""批次78 mock 测试：镜像取证（身份 / HEX / 向量表 / 熵与签名 / 取件）。

来由：对照 GitHub 上的 rea（reverse-engineering agent），把与 MCU 有关、且**不需要任何
外部引擎**的取证口径吸收进来——身份先于解释、观察/推导/未知三分、不覆盖、有界。
刻意不搬的部分：binwalk/unblob 依赖、Ghidra/IDA/Frida 供给、各种平台镜像分析。

  A HEX    ：扩展线性地址（type 04）叠加 / 校验和 / 重叠 / 空隙 / entry
  B 向量表 ：SP/复位地址三条判据；缺窗口时是 unverified（未知≠无效）
  C 熵与签名：分块熵、高熵区间、压缩签名流校验（假头被拒）
  D inspect：ELF/HEX/bin 三格式端到端 + 大文件截断 + 上限
  E carve  ：目录必须不存在、独占写、SHA-256 回读、上限进 gaps、HEX 拒绝
  F 工具面 ：注册 213 / build 20 / 默认面 44 / 注解归类 / 端到端
  G 闭环   ：artifact_changed 是独立判定，不混进 flash_failed

运行：python -m tests.test_batch78
"""
import asyncio
import gzip
import json
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import image as IM             # noqa: E402
from mdkdebug import verify as VF            # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402
from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import server as SV            # noqa: E402

PORT = 15678
EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                          "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []
_TMP = []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def _tmpdir(prefix="mdk78_"):
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

def _rec(rtype, addr, data):
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()

def _img(sp=0x20005000, reset=0x08000101, pad=1024):
    return struct.pack("<II", sp, reset) + bytes(pad)

# ==================================================================
def section_a():
    print("A. Intel HEX")
    txt = "\n".join([
        _rec(4, 0, b"\x08\x00"),      # 基址 0x08000000
        _rec(0, 0x0000, b"\x00\x01\x02\x03"),
        _rec(0, 0x0010, b"\x04\x05"),
        _rec(5, 0, b"\x08\x00\x01\x01"),      # 入口
        _rec(1, 0, b""),
    ]) + "\n"
    h = IM.parse_ihex(txt)
    check("A1 数据记录/字节数正确", h["records"] == 5 and h["data_bytes"] == 6, h)
    check("A2 type 04 扩展线性地址被叠加（min=0x08000000）",
          h["min_offset"] == 0x08000000, h["min_offset"])
    check("A3 两个区间被合并成一维 span 列表",
          len(h["spans"]) == 2 and h["spans"][0]["offset"] == 0x08000000, h["spans"])
    check("A4 空隙位置落在两条记录之间",
          h["gaps"] and h["gaps"][0]["offset"] == 0x08000004
          and h["gaps"][0]["length"] == 12, h["gaps"])
    check("A5 type 05 记录给出入口地址", h["entry_hex"] == "0x08000101", h["entry_hex"])

    bad = "\n".join([_rec(4, 0, b"\x08\x00"),
                     _rec(0, 0, b"\x00\x01\x02\x03"),
                     ":040000000102030405"])   # 故意错校验和（最后字节应为 FA）
    hb = IM.parse_ihex(bad)
    check("A6 校验和错误被检出且不计入数据",
          hb["checksum_errors"] and hb["data_bytes"] == 4, hb)

    mal = "\n".join([_rec(4, 0, b"\x08\x00"), ":05000000AABB", 
                     _rec(0, 0, b"\x01")])
    hm = IM.parse_ihex(mal)
    check("A7 长度字段与实际不符 → 记 malformed",
          hm["lines_malformed"] and hm["lines_malformed"][0]["line"] == 2, hm["lines_malformed"])

    # 地址重叠：两条记录写到同一地址
    ov = "\n".join([_rec(4, 0, b"\x08\x00"),
                    _rec(0, 0, b"\xAA\xBB\xCC\xDD"),
                    _rec(0, 0x0002, b"\x11\x22")])
    ho = IM.parse_ihex(ov)
    check("A8 地址重叠被检出", bool(ho["overlaps"]) and ho["data_bytes"] == 6, ho["overlaps"])

    he = IM.parse_ihex("\n\n" + _rec(1, 0, b"") + "\n")
    check("A9 空行/只有 EOF 不崩且 0 数据",
          he["records"] == 1 and he["spans"] == [] and he["min_offset"] is None, he)

    p = _w("t.hex", txt)
    check("A10 detect_format 认出 HEX（不认成 bin）", IM.detect_format(txt.encode()[:4096]) == "ihex")
    check("A11 detect_format 认出 ELF", IM.detect_format(b"\x7fELF" + b"\x00" * 60) == "elf")

# ==================================================================
def section_b():
    print("B. Cortex-M 向量表")
    flash, ram = (0x08000000, 0x080FFFFF), (0x20000000, 0x20010000)
    v = IM.check_vector_table(struct.pack("<I", 0x20005000), struct.pack("<I", 0x08000101),
                              flash=flash, ram=ram)
    check("B1 合法 SP+复位 → plausible", v["verdict"] == "plausible", v)
    check("B2 判据全部为 True（没有未知项）",
          all(x is True for x in v["checks"].values()), v["checks"])

    v = IM.check_vector_table(struct.pack("<I", 0x20005000), struct.pack("<I", 0x08000101))
    check("B3 不给窗口 → unverified（未知不是无效）", v["verdict"] == "unverified", v)
    check("B4 缺窗口的两项是 None 而不是 False",
          v["checks"]["sp_in_ram"] is None and v["checks"]["reset_in_flash"] is None, v["checks"])

    v = IM.check_vector_table(struct.pack("<I", 0x10000000), struct.pack("<I", 0x08000101),
                              flash=flash, ram=ram)
    check("B5 SP 不在 RAM → invalid 且说明原因",
          v["verdict"] == "invalid" and any("RAM" in w for w in v["why"]), v)

    v = IM.check_vector_table(struct.pack("<I", 0x20005000), struct.pack("<I", 0x08000100),
                              flash=flash, ram=ram)
    check("B6 复位地址 bit0=0 → invalid（会进 HardFault）",
          v["verdict"] == "invalid" and any("Thumb" in w for w in v["why"]), v)

    v = IM.check_vector_table(struct.pack("<I", 0x20005000), struct.pack("<I", 0x20000101),
                              flash=flash, ram=ram)
    check("B7 复位地址落在 RAM → invalid（没指向 Flash）",
          v["verdict"] == "invalid" and any("Flash" in w for w in v["why"]), v)

    v = IM.check_vector_table(b"\xff\xff\xff\xff", b"\xff\xff\xff\xff", flash=flash, ram=ram)
    check("B8 擦除态（全 FF）→ invalid", v["verdict"] == "invalid", v)

    v = IM.check_vector_table(struct.pack("<I", 0x20005002), struct.pack("<I", 0x08000101),
                              flash=flash, ram=ram)
    check("B9 SP 非 4 字节对齐 → invalid",
          v["checks"]["sp_4byte_aligned"] is False and v["verdict"] == "invalid", v["checks"])

    v = IM.check_vector_table(struct.pack(">I", 0x20005000), struct.pack(">I", 0x08000101),
                              flash=flash, ram=ram, endian="big")
    check("B10 大端按传入字节序解释", v["verdict"] == "plausible" and v["sp_hex"] == "0x20005000", v)

# ==================================================================
def section_c():
    print("C. 熵与签名")
    check("C1 全零块熵为 0", IM.entropy(bytes(4096)) == 0.0)
    rnd = os.urandom(4096)
    check("C2 随机数据熵 > 7.5", IM.entropy(rnd) > 7.5, IM.entropy(rnd))
    check("C3 可压缩文本熵明显低于随机",
          IM.entropy(b"abcabcabc" * 400) < 3.0, IM.entropy(b"abcabcabc" * 400))

    m = IM.entropy_map(rnd + bytes(4096), block=1024, threshold=7.2)
    check("C4 高熵区间只覆盖随机段",
          m["high_entropy_runs"] and m["high_entropy_runs"][0]["offset"] == 0
          and m["high_entropy_runs"][0]["length"] == 4096, m)

    gz = gzip.compress(b"hello" * 500)
    data = bytes(16) + gz + os.urandom(256)
    hits = IM.find_signatures(data)
    gzs = [h for h in hits if h["signature"] == "gzip"]
    check("C5 gzip 命中并通过流校验",
          gzs and gzs[0]["offset"] == 16 and gzs[0]["stream_check"] == "ok", gzs)

    fake = bytes(32) + b"\x78\x9c" + os.urandom(512)
    fake_hits = IM.find_signatures(fake)
    zs = [h for h in fake_hits if h["signature"] == "zlib"]
    check("C6 假 zlib 头被流校验否掉",
          zs and zs[0]["stream_check"] == "failed"
          and zs[0]["confidence"] == "signature_only_stream_rejected", zs)
    regs = IM.build_regions(fake, fake_hits)
    check("C7 被否掉的命中不进 regions",
          all(r["signature"] != "zlib" for r in regs), regs)

    data2 = b"AAA" + gz + b"BBBB" + b"\x89PNG\r\n\x1a\n" + bytes(64)
    hits2 = IM.find_signatures(data2)
    regs2 = IM.build_regions(data2, hits2)
    check("C8 区间按偏移升序且 id 连续",
          [r["id"] for r in regs2] == list(range(len(regs2)))
          and all(regs2[i]["offset"] <= regs2[i + 1]["offset"] for i in range(len(regs2) - 1)), regs2)
    check("C9 区间长度是「到下一个签名」的上界",
          regs2[0]["size_basis"] == "next_signature_upper_bound"
          and regs2[0]["length"] == regs2[1]["offset"] - regs2[0]["offset"], regs2)

    many = b"\x89PNG\r\n\x1a\n" + bytes(8)
    check("C10 limit 生效", len(IM.find_signatures(many * 20, limit=3)) <= 3)

# ==================================================================
def section_d():
    print("D. inspect_image")
    r = IM.inspect_image(os.path.join(ROOT, "no_such_file.bin"))
    check("D1 文件不存在 → ok False 且给出路径", r.get("ok") is False and "不存在" in r["error"], r)

    p = _w("empty.bin", b"")
    check("D2 空文件 → ok False", IM.inspect_image(p).get("ok") is False)

    p = _w("vec.bin", _img() + b"payload")
    r = IM.inspect_image(p, flash_start=0x08000000, flash_size=0x100000,
                         ram_start=0x20000000, ram_size=0x10000)
    check("D3 bin 格式 + 向量表 source_offset=0",
          r["format"] == "bin" and r["vector_table"]["source_offset"] == 0, r.get("vector_table"))
    check("D4 bin 向量表判定 plausible", r["vector_table"]["verdict"] == "plausible", r)
    check("D5 身份三元组齐全（path/size/sha256）",
          os.path.isabs(r["path"]) and r["size"] == os.path.getsize(p)
          and len(r["sha256"]) == 64, r.get("sha256"))

    r2 = IM.inspect_image(p)
    check("D6 不给窗口时 verdict=unverified 且有 limitations",
          r2["vector_table"]["verdict"] == "unverified"
          and any("未判有效性" in x for x in r2["limitations"]), r2["vector_table"])

    # HEX
    hexp = _w("a.hex", "\n".join([_rec(4, 0, b"\x08\x00"),
                                  _rec(0, 0, b"\x00\x01\x02\x03"),
                                  _rec(1, 0, b"")]) + "\n")
    r = IM.inspect_image(hexp)
    check("D7 HEX 端到端：format=ihex 且有 hex 报告",
          r["format"] == "ihex" and r["hex"]["data_bytes"] == 4, r.get("format"))

    # ELF（真实 axf）
    if os.path.isfile(EXAMPLE_AXF):
        r = IM.inspect_image(EXAMPLE_AXF, flash_start=0x08000000, flash_size=0x100000,
                             ram_start=0x20000000, ram_size=0x10000)
        check("D8 axf：format=elf 且 machine=ARM",
              r["format"] == "elf" and r["elf"].get("machine") == "ARM", r.get("elf"))
        check("D9 axf：有 PT_LOAD 且向量表 plausible",
              r["elf"]["load_segments"] and r["vector_table"]["verdict"] == "plausible",
              r.get("vector_table"))
        check("D10 axf：load 段基址是 Flash 地址（0x08…）",
              any(seg["paddr_hex"].startswith("0x08") for seg in r["elf"]["load_segments"]),
              r["elf"]["load_segments"])
    else:
        check("D8 axf 不存在（跳过真实 ELF 三项）", True)

    # 截断与上限
    big = _img() + bytes(70000) + b"\x89PNG\r\n\x1a\n"
    bp = _w("big.bin", big)
    r = IM.inspect_image(bp, max_scan_bytes=4096)
    check("D11 超过扫描上限时明说只扫了前缀",
          any("只扫描了前" in x for x in r["limitations"]), r["limitations"])
    check("D12 scanned_bytes 如实反映截断", r.get("scanned_bytes") == 4096, r.get("scanned_bytes"))

    old = IM.MAX_INPUT_BYTES
    try:
        IM.MAX_INPUT_BYTES = 64
        r = IM.inspect_image(bp)
        check("D13 超过输入上限 → ok False（不读半份猜整体）",
              r.get("ok") is False and "上限" in r["error"], r)
    finally:
        IM.MAX_INPUT_BYTES = old

    r = IM.inspect_image(p)
    check("D14 同一文件两次 SHA-256 相同（确定性）",
          r["sha256"] == IM.inspect_image(p)["sha256"])

# ==================================================================
def section_e():
    print("E. carve_image")
    gz = gzip.compress(b"carve me " * 100)
    src = _w("c.bin", bytes(64) + gz + os.urandom(128))
    d = _tmpdir()
    out = os.path.join(d, "out")

    r = IM.carve_image(src, out)
    check("E1 正常取件：一个 gzip 文件、SHA-256 回读一致",
          r.get("ok") and len(r["files"]) == 1 and r["files"][0]["sha256_verified"], r)
    f = (r.get("files") or [{}])[0]
    check("E2 解压件 content_range 为 null（解压后无字节映射）",
          f.get("content_range") is None and f.get("decompressed") is True, f)
    check("E3 source_range_basis 说明是解压流真实消耗",
          f.get("source_range_basis") == "decompressed_stream_end", f.get("source_range_basis"))
    check("E4 落盘路径在输出目录内且文件存在",
          os.path.dirname(f.get("path", "")) == os.path.abspath(out)
          and os.path.isfile(f.get("path", "")), f.get("path"))

    r2 = IM.carve_image(src, out)
    check("E5 目录已存在 → 拒绝（不覆盖既有证据）",
          r2.get("ok") is False and "已存在" in r2["error"], r2)

    r3 = IM.carve_image(src, os.path.join(d, "no_parent", "x"))
    check("E6 父目录不存在 → 拒绝且说明", r3.get("ok") is False and "父目录" in r3["error"], r3)

    r4 = IM.carve_image(src, os.path.join(d, "out2"), signatures=["png"])
    check("E7 没有匹配签名 → 报错并列出可用的签名",
          r4.get("ok") is False and "gzip" in (r4.get("signatures_available") or []), r4)

    r5 = IM.carve_image(src, os.path.join(d, "out3"), ids=[0])
    check("E8 ids 过滤生效", r5.get("ok") and len(r5["files"]) == 1, r5)

    r6 = IM.carve_image(src, os.path.join(d, "out4"), max_total_bytes=1)
    check("E9 总量上限 → gaps 记录原因而不是悄悄截断",
          r6.get("ok") and not r6["files"] and r6["gaps"]
          and "上限" in r6["gaps"][0]["reason"] and r6["complete"] is False, r6)

    hexp = _w("x.hex", "\n".join([_rec(4, 0, b"\x08\x00"),
                                  _rec(0, 0, b"\x00"), _rec(1, 0, b"")]) + "\n")
    r7 = IM.carve_image(hexp, os.path.join(d, "out5"))
    check("E10 HEX 拒绝取件并给出转 bin 的下一步",
          r7.get("ok") is False and any("bin" in x for x in r7.get("next_actions") or []), r7)

    # 原始区间（非压缩）取件：content_range 有值
    raw_src = _w("r.bin", bytes(32) + b"\x89PNG\r\n\x1a\n" + bytes(200))
    r8 = IM.carve_image(raw_src, os.path.join(d, "out6"), signatures=["png"])
    f8 = (r8.get("files") or [{}])[0]
    check("E11 非压缩区间保留 content_range 与签名上界口径",
          f8.get("content_range") and f8.get("source_range_basis") == "signature_upper_bound", f8)

# ==================================================================
def section_f():
    print("F. 工具面")
    build = TB.tools_of("build")
    check("F1 image_inspect 在 build 组", "image_inspect" in build, len(build))
    check("F2 image_carve 在 build 组", "image_carve" in build, len(build))
    check("F3 build 组规模 29（批次86 的 recover_diff 归在 build）", len(TB.TOOLSETS["build"]) == 29, len(TB.TOOLSETS["build"]))

    all_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="all").list_tools()))
    core_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="core").list_tools()))
    check("F4 注册总数 213", all_n == 213, all_n)
    check("F5 默认面仍 44（取证工具不在默认面）", core_n == 44, core_n)

    a1 = AN.annotations_for("image_inspect")
    check("F6 image_inspect 标为只读",
          a1["readOnlyHint"] is True and a1["destructiveHint"] is False, a1)
    a2 = AN.annotations_for("image_carve")
    check("F7 image_carve 标为会改/非幂等（但不可逆为 False）",
          a2["readOnlyHint"] is False and a2["idempotentHint"] is False
          and a2["destructiveHint"] is False, a2)

    names = [t.name for t in asyncio.run(SV.create_server(port=PORT, toolsets="all").list_tools())]
    bad = AN.check_surface(names)
    check("F8 注解表全覆盖（check_surface 无问题）", not bad, bad)

    p = _w("vec.bin", _img())
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "image_inspect", {"path": p, "flash_start": 0x08000000, "flash_size": 0x100000,
                          "ram_start": 0x20000000, "ram_size": 0x10000})).content[0].text)
    check("F9 image_inspect 端到端返回向量表判定",
          r.get("ok") and r["vector_table"]["verdict"] == "plausible", r.get("vector_table"))

    d = _tmpdir()
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "image_carve", {"path": p, "out_dir": os.path.join(d, "o"),
                        "signatures": "png"})).content[0].text)
    check("F10 image_carve 端到端对无签名文件给出可行动错误",
          r.get("ok") is False and "匹配" in r.get("error", ""), r)

# ==================================================================
def section_g():
    print("G. 闭环：artifact_changed")
    check("G1 VERDICTS 含 artifact_changed", "artifact_changed" in VF.VERDICTS)

    def _flash():
        return {"ok": False, "verdict": "artifact_changed",
                "error": "产物在编译后被改写",
                "next_actions": ["先确认没有第二个 Keil 在写产物目录"]}

    def _mon():
        return {"ok": True, "port": "COM9"}

    out = VF.run_closed_loop(build_fn=lambda: {"ok": True}, flash_fn=_flash,
                             monitor_start_fn=_mon, token="[OK]")
    check("G2 产物被改写判为 artifact_changed（不是 flash_failed）",
          out["verdict"] == "artifact_changed" and out["ok"] is False, out.get("verdict"))
    check("G3 next_actions 保留上游给的那条",
          out.get("next_actions") and "第二个 Keil" in out["next_actions"][0], out.get("next_actions"))

    out2 = VF.run_closed_loop(build_fn=lambda: {"ok": True},
                              flash_fn=lambda: {"ok": False, "error": "no probe"},
                              monitor_start_fn=_mon, token="[OK]")
    check("G4 普通烧录失败仍是 flash_failed（两者不能混）",
          out2["verdict"] == "flash_failed", out2.get("verdict"))

    def _flash3():
        return {"ok": False, "verdict": "artifact_changed"}

    out3 = VF.run_closed_loop(build_fn=lambda: {"ok": True}, flash_fn=_flash3,
                              monitor_start_fn=_mon, token="[OK]")
    check("G5 上游没给 next_actions 时给出默认下一步",
          out3.get("next_actions") and "没烧录" in out3["next_actions"][0], out3.get("next_actions"))

# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d, section_e, section_f, section_g):
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
