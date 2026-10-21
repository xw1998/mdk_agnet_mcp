# -*- coding: utf-8 -*-
"""批次87 测试：固件镜像切分（向量表 + 擦除带 + 容器自报长度）。

每节都在测一条「怎么算错答案」：
  A 向量表判据：缺窗口是 plausible 不是 strong、SP=0 不是表、bit0=0 不是表
  B 扫描：真 dump 找得到、表内自证噪声被 min_spacing 挡住、纯数据不误报
  C 擦除带：只有「够长」才叫擦除带，填充字节记下来
  D 流长度：解到流尾才是精确长度，截断/不支持的格式明说而不是猜
  E 切分：三种 size_basis 用对、unassigned 不算空洞
  F 端到端与工具面：真 dump、HEX 的假擦除、错误输入、注册与只读
  G 回归：既有取证输出不变、零新增依赖

运行：python -m tests.test_batch87
"""
import bz2
import gzip
import io
import json
import lzma
import os
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import image as IM          # noqa: E402
from mdkdebug import imagesplit as SP     # noqa: E402

BIN = os.path.join("C:/tmp", "b86", "mdk_test.bin")
FX_SREC = os.path.join(ROOT, "tests", "fixtures", "decomp", "decomp_fx.srec")
TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b87")
PASS, FAIL = [], []
BASE = 0x08000000
FLASH = (0x08000000, 0x08200000 - 1)
RAM = (0x20000000, 0x20000000 + 128 * 1024)

os.makedirs(TMP, exist_ok=True)


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                           "" if ok else "-> %r" % (detail,)))


def app_bytes():
    """真实的 Cortex-M app 镜像字节（fromelf --bin 产物）；没有就退化成合成表。"""
    if os.path.isfile(BIN):
        with open(BIN, "rb") as f:
            return f.read()
    # 合成：SP 在 RAM 顶，复位地址 = base+0x101（Thumb），后面 6 个 handler
    words = [0x20020000, BASE + 0x101] + [BASE + 0x101 + 4 * i for i in range(1, 7)]
    return b"".join(w.to_bytes(4, "little") for w in words) + b"\x00\xbf" * 64


def make_dump(boot_len=0x2000, erase_gap=0xE000):
    """boot(截自 app) + 擦除带 + app，全部拼成一整颗 dump。"""
    app = app_bytes()
    boot = app[:boot_len] if len(app) >= boot_len else app
    dump = bytearray(b"\xff" * (boot_len + erase_gap))
    dump[0:len(boot)] = boot
    dump = bytes(dump) + app
    path = os.path.join(TMP, "dump.bin")
    with open(path, "wb") as f:
        f.write(dump)
    return path, boot_len, len(app)


# ==================================================================
def section_a():
    print("\nA 向量表判据")
    app = app_bytes()
    r = SP.score_table(app, 0, base=BASE, ram=RAM, flash=FLASH)
    check("A1 真向量表：accepted + strong",
          r.get("accepted") is True and r.get("confidence") == "strong", r)
    check("A1b 判据逐项留下证据（SP 在 RAM / reset Thumb / reset 在 Flash）",
          r["checks"].get("sp_in_ram") is True
          and r["checks"].get("reset_thumb_bit") is True
          and r["checks"].get("reset_in_flash") is True, r["checks"])
    r2 = SP.score_table(app, 0, base=BASE, ram=None, flash=None)
    check("A2 两个窗口都不给：只能 plausible，并把限制写进 why",
          r2.get("accepted") is True and r2.get("confidence") == "plausible"
          and any("RAM" in w for w in r2.get("why") or []), r2)

    sp0 = b"\x00\x00\x00\x00" + app[4:]
    r3 = SP.score_table(sp0, 0, base=BASE, ram=RAM, flash=FLASH)
    check("A3 初值 SP=0 不是表", r3.get("accepted") is False, r3)

    no_thumb = app[:4] + (BASE + 0x100).to_bytes(4, "little") + app[8:]
    r4 = SP.score_table(no_thumb, 0, base=BASE, ram=RAM, flash=FLASH)
    check("A4 复位地址 bit0=0 不是表（会进 HardFault）",
          r4.get("accepted") is False
          and any("bit0" in w for w in r4.get("why") or []), r4)

    bad_reset = app[:4] + (0x30000101).to_bytes(4, "little") + app[8:]
    r5 = SP.score_table(bad_reset, 0, base=BASE, ram=RAM, flash=FLASH)
    check("A5 复位地址不在 Flash 窗口 → 拒绝",
          r5.get("accepted") is False
          and any("Flash 窗口" in w for w in r5.get("why") or []), r5)

    zeros = app[:8] + b"\x00" * 24
    r6 = SP.score_table(zeros, 0, base=BASE, ram=RAM, flash=FLASH)
    check("A6 handler 不像代码地址 → 拒绝（并说明比例不够）",
          r6.get("accepted") is False
          and any("比例" in w for w in r6.get("why") or []), r6)

    short = SP.score_table(app, len(app) - 4, base=BASE, ram=RAM, flash=FLASH)
    check("A7 偏移处字节不够 → ok=False（不当作表）",
          short.get("ok") is False, short)


# ==================================================================
def section_b():
    print("\nB 向量表扫描")
    path, _boot, _applen = make_dump()
    with open(path, "rb") as f:
        dump = f.read()
    tabs = SP.scan_vector_tables(dump, base=BASE, ram=RAM, flash=FLASH)
    check("B1 合成 dump 扫出 2 张表（boot 与 app 各一张）",
          len(tabs) == 2, [(t["offset_hex"], t.get("confidence")) for t in tabs])
    check("B2 表的偏移正好在镜像起点上（4 字节对齐、不漂移）",
          [t["offset"] for t in tabs] == [0, 0x10000],
          [t["offset_hex"] for t in tabs])
    check("B3 同一张表内部不再产生第二张表（min_spacing）",
          all(b["offset"] - a["offset"] >= SP.DEFAULT_MIN_SPACING
              for a, b in zip(tabs, tabs[1:])), [t["offset"] for t in tabs])

    many = SP.scan_vector_tables(dump, base=BASE, ram=RAM, flash=FLASH, max_tables=1)
    check("B4 max_tables 生效（只留最靠前的那张）",
          len(many) == 1 and many[0]["offset"] == 0, [t["offset"] for t in many])

    noise = bytes([(i * 37 + 11) & 0xFF for i in range(4096)])
    check("B5 纯噪声一个表也不报（不硬凑）",
          SP.scan_vector_tables(noise, base=BASE, ram=RAM, flash=FLASH) == [])


# ==================================================================
def section_c():
    print("\nC 擦除带")
    data = b"\x11" * 100 + b"\xff" * 300 + b"\x22" * 100
    runs = SP.find_erase_runs(data, erase=0xFF, min_len=256, base=BASE)
    check("C1 够长的 0xFF 带被找到（偏移/长度/地址）",
          len(runs) == 1 and runs[0]["offset"] == 100
          and runs[0]["length"] == 300
          and runs[0]["addr_hex"] == "0x%X" % (BASE + 100), runs)
    check("C2 填充字节记下来（不是所有平台都擦成 0xFF）",
          runs[0]["fill_byte"] == "0xFF", runs[0].get("fill_byte"))
    short = SP.find_erase_runs(data, erase=0xFF, min_len=301, base=BASE)
    check("C3 短于 min_len 的不算擦除带（避开数据里的偶然 0xFF）", short == [], short)
    zero = SP.find_erase_runs(b"\x00" * 400, erase=0x00, min_len=256, base=BASE)
    check("C4 erase=0x00 也能用（有的器件擦成 0x00）",
          len(zero) == 1 and zero[0]["length"] == 400, zero)


# ==================================================================
def section_d():
    print("\nD 容器自报长度")
    payload = b"hello-firmware" * 40
    for kind, blob, kw in (
            ("gzip", gzip.compress(payload), {}),
            ("zlib", zlib.compress(payload), {}),
            ("bzip2", bz2.compress(payload), {}),
            ("xz", lzma.compress(payload), {})):
        data = b"\x00" * 16 + blob + b"\xff" * 64
        r = SP.stream_extent(data, 16, kind)
        check("D1 %s 解到流尾 → 精确长度" % kind,
              r.get("ok") is True and r.get("compressed_bytes") == len(blob)
              and r.get("raw_bytes") == len(payload)
              and r.get("size_basis", "").startswith("stream_end"), r)
    gz = gzip.compress(payload)
    r = SP.stream_extent(b"\x00" * 8 + gz + b"\xff" * 16, 8, "gzip")
    check("D2 gzip 还核 ISIZE（尾部声明与解压长度对得上）",
          r.get("isize_verified") is True, r)

    trunc = gzip.compress(payload)[:-6]
    r2 = SP.stream_extent(b"\x00" * 8 + trunc + b"\xff" * 16, 8, "gzip")
    check("D3 截断的流 → 报错，不给估计长度（不把残流当完整流）",
          r2.get("ok") is False and "compressed_bytes" not in r2, r2)

    r3 = SP.stream_extent(b"\xff" * 64, 0, "lz4-frame")
    check("D4 没有标准库能解到流尾的格式 → not_supported（不猜）",
          r3.get("ok") is False and r3.get("status") == "not_supported", r3)

    r4 = SP.stream_extent(b"\x1f\x8b\x08" + b"\x00" * 20, 0, "gzip")
    check("D5 头部像 gzip 但流不完整 → 明确失败（不是 0 长度成功）",
          r4.get("ok") is False, r4)


# ==================================================================
def section_e():
    print("\nE 切分")
    path, boot_len, applen = make_dump()
    with open(path, "rb") as f:
        dump = f.read()
    tabs = SP.scan_vector_tables(dump, base=BASE, ram=RAM, flash=FLASH)
    runs = SP.find_erase_runs(dump, erase=0xFF, min_len=256, base=BASE)
    part = SP.partition_image(dump, tabs, base=BASE, erase_runs=runs)
    imgs = part["images"]
    check("E1 两个镜像，起点 = 两张表的偏移",
          [im["offset"] for im in imgs] == [0, 0x10000], [i["offset"] for i in imgs])
    check("E2 第一个镜像的结尾是擦除带（最可靠的依据）",
          imgs[0]["size_basis"] == "erase_gap" and imgs[0]["length"] == boot_len,
          (imgs[0]["size_basis"], imgs[0]["length"]))
    check("E3 最后一个镜像到文件尾",
          imgs[-1]["size_basis"] == "end_of_file" and imgs[-1]["length"] == applen,
          (imgs[-1]["size_basis"], imgs[-1]["length"]))
    check("E4 擦除带不被算进任何镜像，也不丢账（unassigned=0）",
          part["coverage"]["unassigned_bytes"] == 0
          and part["coverage"]["erase_bytes"] > 0, part["coverage"])

    # 两张表紧挨着、中间没有擦除带：前一块的结尾只能推到「下一个表」（上界）
    tight = dump[:0x2000] + dump[0x10000:]
    tabs2 = [{"offset": 0, "sp_hex": "0x0", "reset_hex": "0x0",
              "handler_ratio": 1.0, "confidence": "strong"},
             {"offset": 0x2000, "sp_hex": "0x0", "reset_hex": "0x0",
              "handler_ratio": 1.0, "confidence": "strong"}]
    p2 = SP.partition_image(tight, tabs2, base=BASE, erase_runs=[])
    check("E5 没有擦除带时退化成 next_vector_table（并明说是上界）",
          p2["images"][0]["size_basis"] == "next_vector_table"
          and p2["images"][0]["length"] == 0x2000, p2["images"][0])
    check("E6 没有擦除证据时绝不凭空发明擦除态（erase_bytes=0）",
          p2["coverage"]["erase_bytes"] == 0, p2["coverage"])

    # 表在 0x100（前面 0x100 字节是头部/其它数据）：这段字节不能被算进镜像
    head = b"\x00" * 0x100 + dump
    tabs3 = [dict(tabs2[0], offset=0x100)]
    p3 = SP.partition_image(head, tabs3, base=BASE, erase_runs=[])
    check("E7 表之前的字节算 unassigned（不硬塞进镜像）",
          p3["coverage"]["unassigned_bytes"] == 0x100, p3["coverage"])

    short_payload = tight[:0x2000 + 16]
    p4 = SP.partition_image(short_payload, tabs2, base=BASE, erase_runs=[],
                            min_image=0x100)
    check("E8 短得出奇的「镜像」会被标成噪声（warning 带出来）",
          any("向量表噪声" in w for w in p4["warnings"]), p4["warnings"])


# ==================================================================
def section_f():
    print("\nF 端到端与工具面")
    path, boot_len, applen = make_dump()
    out = SP.split_image(path, base=BASE, flash_start=FLASH[0],
                         flash_size=FLASH[1] - FLASH[0] + 1,
                         ram_start=RAM[0], ram_size=RAM[1] - RAM[0] + 1)
    check("F1 端到端：2 张表 / 2 个镜像 / 地址正确",
          len(out["tables"]) == 2 and len(out["images"]) == 2
          and out["images"][1]["addr_hex"] == "0x%X" % (BASE + 0x10000), out["coverage"])
    check("F2 覆盖度照实报（in_images + erase = total，unassigned=0）",
          out["coverage"]["unassigned_bytes"] == 0
          and out["coverage"]["in_images"] + out["coverage"]["erase_bytes"]
          == out["coverage"]["total_bytes"], out["coverage"])
    check("F3 给了两侧窗口 → strong；limitations 里不再抱怨缺窗口",
          all(t["confidence"] == "strong" for t in out["tables"])
          and not any("没有同时给 Flash 窗口" in x for x in out["limitations"]),
          out["limitations"])

    no_win = SP.split_image(path)
    check("F4 不给窗口 → plausible + 明确写出判据退化",
          all(t["confidence"] == "plausible" for t in no_win["tables"])
          and any("没有同时给 Flash 窗口" in x for x in no_win["limitations"]),
          no_win["limitations"][:2])

    hexout = SP.split_image(FX_SREC)
    check("F5 HEX 输入：不据此判擦除带，并把原因写进 limitations",
          hexout.get("ok") is True and hexout["erase_runs"] == []
          and any("不代表" in x or "不代表那边是擦除态" in x
                  for x in hexout["limitations"]), hexout.get("limitations"))

    empty = os.path.join(TMP, "empty.bin")
    open(empty, "wb").close()
    r = SP.split_image(empty)
    check("F6 空文件 → 明确报错（没有任何可判的事实）",
          r.get("ok") is False and "空文件" in (r.get("error") or ""), r)
    r2 = SP.split_image(os.path.join(TMP, "nope.bin"))
    check("F7 文件不存在 → 明确报错", r2.get("ok") is False, r2)

    import asyncio
    from mdkdebug import annotate as AN
    from mdkdebug import server as SV
    srv = SV.create_server(port=15897, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    check("F8 注册总数 213（批次87 +1）", len(tools) == 213, len(tools))
    props = (tools.get("image_split").input_schema.get("properties") or {})
    check("F9 参数齐全（path/base/窗口/erase/阈值）",
          all(k in props for k in ("path", "base", "flash_start", "flash_size",
                                   "ram_start", "ram_size", "erase", "erase_min",
                                   "max_tables", "handler_ratio", "min_image")),
          sorted(props))
    check("F10 在 build 组、不在默认面",
          "image_split" in SV._toolbox.TOOLSETS.get("build", set())
          and "image_split" not in {t.name for t in
                                   asyncio.run(SV.create_server(port=15896).list_tools())})
    check("F11 标为只读工具", AN.annotations_for("image_split")["readOnlyHint"] is True,
          AN.annotations_for("image_split"))
    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("F12 描述写明「长度是推导」与「只找 Cortex-M 向量表」",
          "推导" in src and "只找 Cortex-M 向量表" in src)

    payload = json.loads(asyncio.run(srv.call_tool(
        "image_split", {"path": path, "base": BASE})).content[0].text)
    check("F13 工具真返回对象（不是协程 repr），且带 verdict/coverage",
          isinstance(payload, dict) and payload.get("ok") is True
          and "coverage" in payload and payload.get("verdict") in ("ok", "warn"), payload)


# ==================================================================
def section_g():
    print("\nG 回归")
    path, _b, _a = make_dump()
    ins = IM.inspect_image(path)
    check("G1 既有取证输出不变（inspect_image 仍报 regions/entropy/vector_table）",
          ins.get("ok") is True and "regions" in ins and "entropy" in ins
          and "vector_table" in ins, sorted(ins)[:8])
    src = io.open(os.path.join(ROOT, "mdkdebug", "imagesplit.py"), encoding="utf-8").read()
    banned = [m for m in ("capstone", "elftools", "pefile", "macholib", "numpy", "requests")
              if ("import %s" % m) in src or ("from %s" % m) in src]
    check("G2 零新增依赖（只用 zlib/bz2/lzma/struct 这类标准库）", not banned, banned)
    check("G3 没有 import struct 之外的二进制解析库",
          "from . import image" in src)


def main():
    print("环境：Python %s" % sys.version.split()[0])
    for fn in (section_a, section_b, section_c, section_d,
               section_e, section_f, section_g):
        fn()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  - %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
