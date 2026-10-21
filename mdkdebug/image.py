# -*- coding: utf-8 -*-
"""镜像取证（批次78）——把「这个文件里到底是什么」变成**可复核的事实**。

为什么值得单独做
--------------
烧录与判定的前后，最伤人的错答案不是"读不到"，而是**读到了却解释错**：

- 「HEX 里 0 条数据记录」被读成"镜像正常、只是小"——其实是解析器不认 Keil 的
  扩展线性地址记录（type 04），地址全被当成 0，后写覆盖前写；
- 「向量表第一个字是 0x20005000，所以固件是对的」——没有 RAM 窗口就没法判它是不是
  SP，更没有判第二个字（复位地址）在不在 Flash 里、Thumb 位有没有置；
- 「文件里有 0x1F8B 就是一段 gzip」——签名只说明"这四个字节像"，不说明后面是一段
  合法数据流，更不说明它是一份能用的文件系统。

本模块的口径（借自 rea 的 firmware/artifact 取证，只留与 MCU 有关的部分）：

1. **身份先于解释**：任何结论都挂在 `path + size + sha256` 上。同一路径内容变了，
   结论就作废（`build_flash_verify` 用它做 `artifact_changed` 判定）。
2. **区分「观察 / 推导 / 未知」**：签名命中是观察；由下一个签名推出的长度是推导
   （`size_basis=next_signature_upper_bound`）；没有窗口信息时向量表"是否有效"是
   **未知**，不是"无效"。
3. **不覆盖、不假设**：取件目录必须不存在（与 rea 的 publication 同口径）——
   已有目录一律拒绝，避免把上一次的证据冲掉。
4. **有界**：输入、单文件解压、文件数、总字节数都有上限，超了如实报截断，
   不悄悄截断后当完整结果返回。

纯标准库 + 已有的 pyelftools，不需要 binwalk / unblob / readelf 任何外部引擎。
"""
from __future__ import annotations

import bz2
import hashlib
import lzma
import math
import os
import zlib

# 单个输入上限（与 rea 的固件输入口径一致：128 MiB）
MAX_INPUT_BYTES = 128 * 1024 * 1024
# 取件时单文件解压上限与总量上限（防解压炸弹）
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FILES = 32

# 签名表：**只做观察**，不代表"后面就是合法内容"。
# 名字 → (magic, kind, 可解压实现)
SIGNATURES = [
    ("elf", b"\x7fELF", "container"),
    ("gzip", b"\x1f\x8b\x08", "compressed"),
    ("zlib", b"\x78\x01", "compressed"),
    ("zlib", b"\x78\x9c", "compressed"),
    ("zlib", b"\x78\xda", "compressed"),
    ("xz", b"\xfd7zXZ\x00", "compressed"),
    ("lzma-alone", b"\x5d\x00\x00", "compressed"),
    ("bzip2", b"BZh", "compressed"),
    ("lz4-frame", b"\x04\x22\x4d\x18", "compressed"),
    ("zstd", b"\x28\xb5\x2f\xfd", "compressed"),
    ("littlefs", b"littlefs", "filesystem"),
    ("fat-label", b"FAT12", "filesystem"),
    ("fat-label", b"FAT16", "filesystem"),
    ("fat-label", b"FAT32", "filesystem"),
    ("png", b"\x89PNG\r\n\x1a\n", "image"),
    ("jpeg", b"\xff\xd8\xff", "image"),
    ("gif", b"GIF89a", "image"),
    ("zip", b"PK\x03\x04", "archive"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "archive"),
    ("rar", b"Rar!\x1a\x07", "archive"),
    ("sqlite", b"SQLite format 3\x00", "database"),
]

_COMPRESSED = {
    "gzip": "gzip", "zlib": "zlib", "xz": "xz", "lzma-alone": "lzma",
    "bzip2": "bzip2",
}


# ----------------------------------------------------------------------
# 身份
# ----------------------------------------------------------------------
def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    """流式算 SHA-256（大镜像不整读进内存）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _identity(path: str) -> dict:
    return {
        "path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "sha256": sha256_file(path),
    }


# ----------------------------------------------------------------------
# Intel HEX
# ----------------------------------------------------------------------
def parse_ihex(text: str) -> dict:
    """解析 Intel HEX，返回**数据覆盖范围**而不是"一条条记录"。

    为什么不能只数记录：Keil 生成的 HEX 用 ``04``（扩展线性地址）分段，
    高地址段的记录必须叠加 ``base`` 才是真实地址。忽略它会把所有记录压到 0 附近，
    于是「后写覆盖前写」——镜像看起来存在，实际已经毁了。
    """
    out = {
        "records": 0,
        "data_records": 0,
        "data_bytes": 0,
        "lines_malformed": [],
        "checksum_errors": [],
        "spans": [],          # [{offset, length}] 合并后
        "gaps": [],
        "overlaps": [],
        "entry_hex": None,
        "max_offset": 0,
        "min_offset": None,
    }
    base = 0
    ranges = []  # (start, end)
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        if not s.startswith(":"):
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "缺起始冒号"})
            continue
        out["records"] += 1
        body = s[1:]
        try:
            raw = bytes.fromhex(body)
        except ValueError:
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "非十六进制字符"})
            continue
        if len(raw) < 5:
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "记录长度不足"})
            continue
        n, addr, rtype, data, cks = raw[0], (raw[1] << 8) | raw[2], raw[3], raw[4:-1], raw[-1]
        if n != len(data):
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "长度字段与实际数据不符"})
            continue
        calc = (-sum(raw[:-1])) & 0xFF
        if calc != cks:
            if len(out["checksum_errors"]) < 5:
                out["checksum_errors"].append({"line": lineno, "declared": cks, "calculated": calc})
            continue
        if rtype == 0x00:
            out["data_records"] += 1
            out["data_bytes"] += len(data)
            start = base + addr
            ranges.append((start, start + len(data)))
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            if len(data) == 2:
                base = ((data[0] << 8) | data[1]) << 4
        elif rtype == 0x04:
            if len(data) == 2:
                base = ((data[0] << 8) | data[1]) << 16
        elif rtype == 0x03:
            if len(data) == 4:
                out["entry_hex"] = "0x%08X" % (((data[0] << 8) | data[1]) << 4)
        elif rtype == 0x05:
            if len(data) == 4:
                out["entry_hex"] = "0x%08X" % int.from_bytes(data, "big")
    if not ranges:
        return out
    ranges.sort()
    out["min_offset"] = ranges[0][0]
    out["max_offset"] = max(r[1] for r in ranges)
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            if start < merged[-1][1] and len(out["overlaps"]) < 5:
                out["overlaps"].append({"offset": start, "span": merged[-1][1] - start})
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out["spans"] = [{"offset": a, "length": b - a} for a, b in merged]
    for i in range(1, len(merged)):
        gap = merged[i][0] - merged[i - 1][1]
        if gap > 0 and len(out["gaps"]) < 20:
            out["gaps"].append({"offset": merged[i - 1][1], "length": gap})
    span_total = (out["max_offset"] - out["min_offset"]) or 1
    out["coverage"] = round(out["data_bytes"] / span_total, 4)
    return out


# ----------------------------------------------------------------------
# 熵
# ----------------------------------------------------------------------
def entropy(data: bytes) -> float:
    """Shannon 熵（bit/byte，0~8）。压缩/加密数据接近 8。"""
    if not data:
        return 0.0
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def entropy_map(data: bytes, block: int = 1024, threshold: float = 7.2,
                max_runs: int = 32) -> dict:
    """分块熵 + 高熵连续区间（压缩/加密/资源区的粗略定位）。"""
    block = max(64, int(block))
    blocks = []
    for off in range(0, len(data), block):
        blocks.append({"offset": off, "entropy": entropy(data[off:off + block])})
    runs = []
    cur = None
    for b in blocks:
        if b["entropy"] >= threshold:
            if cur is None:
                cur = {"offset": b["offset"], "length": block}
            else:
                cur["length"] += block
        else:
            if cur:
                runs.append(cur)
                cur = None
    if cur:
        runs.append(cur)
    vals = [b["entropy"] for b in blocks] or [0.0]
    return {
        "block_size": block,
        "blocks": len(blocks),
        "min": min(vals),
        "max": max(vals),
        "mean": round(sum(vals) / len(vals), 3),
        "threshold": threshold,
        "high_entropy_runs": runs[:max_runs],
        "high_entropy_runs_total": len(runs),
    }


# ----------------------------------------------------------------------
# 内嵌签名
# ----------------------------------------------------------------------
def find_signatures(data: bytes, limit: int = 64) -> list:
    """扫描内嵌签名。**同名多次命中各自保留**（不可合并成"一段"）。

    压缩类签名会**顺手试解压**（最多看前 256 KiB）：``0x78 0x9C`` 在二进制里出现得
    太随意，只报"命中了"等于给调用方一堆噪声。``stream_check`` 只回答
    「这段字节开头像不像一条真数据流」，不回答"里面是什么"。
    """
    hits = []
    for name, magic, kind in SIGNATURES:
        start = 0
        while len(hits) < limit:
            i = data.find(magic, start)
            if i < 0:
                break
            hit = {"offset": i, "signature": name, "kind": kind,
                   "confidence": "signature_only"}
            if name in _COMPRESSED:
                probe, _consumed, _trunc = _decompress_limited(
                    data[i:i + 256 * 1024], _COMPRESSED[name], 1 << 20)
                if probe is None:
                    hit["stream_check"] = "failed"
                    hit["confidence"] = "signature_only_stream_rejected"
                elif not probe:
                    hit["stream_check"] = "empty"
                else:
                    hit["stream_check"] = "ok"
                    hit["decompressed_probe_bytes"] = len(probe)
            hits.append(hit)
            start = i + 1
    hits.sort(key=lambda h: h["offset"])
    return hits[:limit]


def build_regions(data: bytes, hits: list, max_regions: int = 64) -> list:
    """把签名命中整理成区间：长度取「到下一个签名」的上界。

    这个长度是**推导**，不是观察：``size_basis=next_signature_upper_bound``。
    一个签名后面可能紧跟垃圾字节、也可能是一段真正的数据流；本字段不区分。
    """
    usable = [h for h in hits if h.get("stream_check") != "failed"]
    regions = []
    for i, h in enumerate(usable[:max_regions]):
        nxt = usable[i + 1]["offset"] if i + 1 < len(usable) else len(data)
        length = max(0, nxt - h["offset"])
        regions.append({
            "id": i,
            "offset": h["offset"],
            "offset_hex": "0x%X" % h["offset"],
            "length": length,
            "signature": h["signature"],
            "kind": h["kind"],
            "confidence": h["confidence"],
            "size_basis": "next_signature_upper_bound",
        })
    return regions


# ----------------------------------------------------------------------
# Cortex-M 向量表
# ----------------------------------------------------------------------
def check_vector_table(word0: bytes, word1: bytes, *,
                       ram=None, flash=None, endian: str = "little") -> dict:
    """判前两个字是不是一个**说得通**的 Cortex-M 向量表。

    三条判据各自独立，缺窗口时判据是 ``None``（未知），**不是 False**：
      - 初值 SP 4 字节对齐，落在 RAM 窗口内（允许等于窗口末端——栈顶通常就是 RAM 末尾）；
      - 复位地址（bit0 是 Thumb 位）去掉 bit0 后落在 Flash 窗口内；
      - 复位地址 bit0 必须为 1（跳到 Thumb 代码），否则进 HardFault。
    """
    sp = int.from_bytes(word0, endian, signed=False)
    reset_raw = int.from_bytes(word1, endian, signed=False)
    reset = reset_raw & ~1
    out = {
        "sp_hex": "0x%08X" % sp,
        "reset_hex": "0x%08X" % reset_raw,
        "reset_aligned_hex": "0x%08X" % reset,
        "checks": {},
        "verdict": None,
        "why": [],
    }
    checks = {}
    if sp == 0 or sp == 0xFFFFFFFF:
        checks["sp_nonzero"] = False
        out["why"].append("初值 SP 是 0 或全 1：这不像一张向量表（空白/擦除态/取错偏移）")
    else:
        checks["sp_nonzero"] = True
    checks["sp_4byte_aligned"] = (sp % 4) == 0
    if ram:
        lo, hi = ram
        checks["sp_in_ram"] = lo <= sp <= hi
        if not checks["sp_in_ram"]:
            out["why"].append("初值 SP 0x%08X 不在给定 RAM 窗口 0x%08X~0x%08X 内" % (sp, lo, hi))
    else:
        checks["sp_in_ram"] = None
    checks["reset_thumb_bit"] = bool(reset_raw & 1)
    if not checks["reset_thumb_bit"]:
        out["why"].append("复位地址 bit0 为 0：Cortex-M 必须跳 Thumb 代码，否则进 HardFault")
    if flash:
        lo, hi = flash
        checks["reset_in_flash"] = lo <= reset <= hi
        if not checks["reset_in_flash"]:
            out["why"].append("复位地址 0x%08X 不在给定 Flash 窗口 0x%08X~0x%08X 内" % (reset, lo, hi))
    else:
        checks["reset_in_flash"] = None
    out["checks"] = checks
    known = [v for v in checks.values() if v is not None]
    if any(v is False for v in known):
        out["verdict"] = "invalid"
    elif any(v is None for v in checks.values()):
        out["verdict"] = "unverified"
    else:
        out["verdict"] = "plausible"
    return out


# ----------------------------------------------------------------------
# ELF（纯标准库：只读文件头 + 程序头，够定位 PT_LOAD 与向量表）
# ----------------------------------------------------------------------
_PT_LOAD = 1


def elf_layout(path: str) -> dict:
    """用文件头/程序头回答「PT_LOAD 在哪、装到哪个地址」。

    刻意不用 pyelftools：本项目对它的依赖是可选的，而这里需要的字段
    （e_type/e_machine/e_entry/phoff/phentsize/phnum + PT_LOAD 五项）
    在 ELF32/ELF64 里位置固定，``struct`` 足够，**不为一个字段引入一个包**。
    """
    import struct
    with open(path, "rb") as f:
        head = f.read(64)
        if len(head) < 52 or not head.startswith(b"\x7fELF"):
            return {"available": False, "why": "不是 ELF"}
        cls = head[4]          # 1=32 位, 2=64 位
        data_enc = head[5]     # 1=小端, 2=大端
        if cls not in (1, 2) or data_enc not in (1, 2):
            return {"available": False, "why": "ELF class/字节序字段不认识"}
        en = "<" if data_enc == 1 else ">"
        e_type, e_machine = struct.unpack(en + "HH", head[16:20])
        if cls == 1:
            e_entry = struct.unpack(en + "I", head[24:28])[0]
            e_phoff = struct.unpack(en + "I", head[28:32])[0]
            e_phentsize, e_phnum = struct.unpack(en + "HH", head[42:46])
        else:
            e_entry = struct.unpack(en + "Q", head[24:32])[0]
            e_phoff = struct.unpack(en + "Q", head[32:40])[0]
            e_phentsize, e_phnum = struct.unpack(en + "HH", head[54:58])
        segs = []
        ph = head[:0]
        f.seek(e_phoff)
        ph = f.read(max(0, e_phentsize * e_phnum))
        for i in range(e_phnum):
            b = ph[i * e_phentsize:(i + 1) * e_phentsize]
            if len(b) < e_phentsize:
                break
            if cls == 1:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack(
                    en + "IIIIII", b[:24])
            else:
                p_type = struct.unpack(en + "I", b[:4])[0]
                p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack(
                    en + "QQQQQ", b[8:48])
            if p_type != _PT_LOAD or p_filesz == 0:
                continue
            segs.append({
                "offset": int(p_offset),
                "vaddr_hex": "0x%08X" % int(p_vaddr),
                "paddr_hex": "0x%08X" % int(p_paddr),
                "filesz": int(p_filesz),
                "memsz": int(p_memsz),
            })
        return {
            "available": True,
            "class": 32 if cls == 1 else 64,
            "little_endian": data_enc == 1,
            "type": {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, e_type),
            "machine": {0x28: "ARM", 0x3E: "x86-64", 0x03: "x86",
                        0xF3: "RISC-V", 0x2A: "SuperH"}.get(e_machine, e_machine),
            "entry_hex": "0x%08X" % e_entry,
            "load_segments": segs,
        }


# ----------------------------------------------------------------------
# 格式判定与总览
# ----------------------------------------------------------------------
def detect_format(head: bytes, path: str = "") -> str:
    if head.startswith(b"\x7fELF"):
        return "elf"
    # Intel HEX 是纯文本，且以 ':' 开头的行占绝大多数
    sample = head[:4096].decode("latin-1", "replace")
    lines = [ln for ln in sample.splitlines() if ln.strip()]
    if lines and sum(1 for ln in lines if ln.lstrip().startswith(":")) >= max(1, len(lines) // 2):
        return "ihex"
    return "bin"


def _hex_bytes_to_sparse(text: str) -> bytes:
    """把 HEX 铺成字节图（最小偏移对齐到 0），仅用于熵/签名这类"看内容"的检查。"""
    parsed = parse_ihex(text)
    if not parsed["spans"]:
        return b""
    lo = parsed["min_offset"] or 0
    hi = parsed["max_offset"] or 0
    if hi - lo > MAX_INPUT_BYTES:
        return b""
    buf = bytearray(hi - lo)
    base = 0
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith(":"):
            continue
        try:
            raw = bytes.fromhex(s[1:])
        except ValueError:
            continue
        if len(raw) < 5 or raw[0] != len(raw) - 5:
            continue
        if (-sum(raw[:-1])) & 0xFF != raw[-1]:
            continue
        rtype = raw[3]
        if rtype == 0x02 and len(raw) == 7:
            base = ((raw[4] << 8) | raw[5]) << 4
        elif rtype == 0x04 and len(raw) == 7:
            base = ((raw[4] << 8) | raw[5]) << 16
        elif rtype == 0x00:
            addr = base + ((raw[1] << 8) | raw[2]) - lo
            if 0 <= addr < len(buf):
                buf[addr:addr + len(raw) - 5] = raw[4:-1]
    return bytes(buf)


def inspect_image(path: str, *, base: int = 0, flash_start: int | None = None,
                  flash_size: int | None = None, ram_start: int | None = None,
                  ram_size: int | None = None, block: int = 1024,
                  max_regions: int = 64, max_signatures: int = 64,
                  max_scan_bytes: int = 32 * 1024 * 1024) -> dict:
    """回答「这个文件里到底是什么」：格式、身份、布局、向量表、熵、内嵌签名。"""
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：%s" % path}
    size = os.path.getsize(path)
    if size == 0:
        return {"ok": False, "path": os.path.abspath(path), "size": 0,
                "error": "空文件：没有任何可判的事实"}
    if size > MAX_INPUT_BYTES:
        return {"ok": False, "path": os.path.abspath(path), "size": size,
                "error": "输入超过 %d MiB 上限（本工具不读部分文件来「猜」整体）"
                         % (MAX_INPUT_BYTES // (1024 * 1024))}
    with open(path, "rb") as f:
        data = f.read()

    fmt = detect_format(data[:4096], path)
    out = {"ok": True}
    out.update(_identity(path))
    out["format"] = fmt
    out["base_hex"] = "0x%X" % int(base)
    warnings, limitations = [], []

    if fmt == "ihex":
        text = data.decode("latin-1")
        hexinfo = parse_ihex(text)
        out["hex"] = hexinfo
        if hexinfo["checksum_errors"]:
            warnings.append("HEX 有 %d 条校验和错误（只列前 5 条）：文件在传输/保存中损坏"
                            % len(hexinfo["checksum_errors"]))
        if hexinfo["lines_malformed"]:
            warnings.append("HEX 有无法解析的行（只列前 5 条）")
        if hexinfo["overlaps"]:
            warnings.append("HEX 有数据记录地址重叠：后写覆盖前写，镜像内容取决于记录顺序")
        if hexinfo["min_offset"]:
            out["base_hex"] = "0x%X" % hexinfo["min_offset"]
        payload = _hex_bytes_to_sparse(text)
        limitations.append("HEX 检出的是**记录覆盖范围**；空隙（gaps）表示该区间没有数据，"
                           "不等于该地址上的 Flash 是擦除态")
    else:
        payload = data
        if fmt == "elf":
            out["elf"] = elf_layout(path)

    # 向量表：ELF 取第一个 PT_LOAD 的 paddr/offset；HEX/BIN 取 base
    vt_off = None
    if fmt == "elf" and out.get("elf", {}).get("available"):
        for seg in out["elf"]["load_segments"]:
            if seg["filesz"] >= 8 and vt_off is None:
                vt_off = seg["offset"]
                break
    elif fmt == "bin":
        vt_off = 0
    if vt_off is not None and len(data) >= vt_off + 8:
        words = data[vt_off:vt_off + 8]
        flash = None
        if flash_start is not None and flash_size:
            flash = (int(flash_start), int(flash_start) + int(flash_size) - 1)
        ram = None
        if ram_start is not None and ram_size:
            ram = (int(ram_start), int(ram_start) + int(ram_size))
        vt = check_vector_table(words[:4], words[4:], ram=ram, flash=flash)
        vt["source_offset"] = vt_off
        out["vector_table"] = vt
        if vt["verdict"] == "invalid":
            warnings.append("向量表判为 invalid：" + "；".join(vt["why"][:3]))
        if vt["verdict"] == "unverified":
            limitations.append("向量表只给出数值、**未判有效性**：没有同时给 flash_start/flash_size "
                               "与 ram_start/ram_size，就不知道 SP/复位地址该落在哪")
    elif fmt == "elf":
        limitations.append("ELF 没有可读的 PT_LOAD，向量表位置未知")
    else:
        limitations.append("未能定位向量表（文件短于 8 字节或布局不认识）")

    # 内容类事实只看 payload（HEX 的稀疏图）。扫描有上限：大 dump 只扫前缀并**明说**。
    scan = payload[:max_scan_bytes] if payload else b""
    if payload and len(payload) > len(scan):
        limitations.append("只扫描了前 %d 字节（输入 %d 字节）；后段的签名/熵未观察"
                           % (len(scan), len(payload)))
    if scan:
        out["entropy"] = entropy_map(scan, block=block)
        out["scanned_bytes"] = len(scan)
        hits = find_signatures(scan, limit=max_signatures)
        out["signatures"] = hits
        out["regions"] = build_regions(scan, hits, max_regions=max_regions)
        if hits:
            limitations.append("签名只是**字节模式命中**：不证明后面是合法数据流、"
                               "分区表或可运行代码；区间长度是「到下一个签名」的上界")
    else:
        out["signatures"] = []
        out["regions"] = []
        limitations.append("没有可扫描的数据（HEX 无数据记录或超出体积上限）")

    out["warnings"] = warnings
    out["limitations"] = limitations
    out["ok"] = True
    out["verdict"] = "warn" if warnings else "ok"
    return out


# ----------------------------------------------------------------------
# 取件
# ----------------------------------------------------------------------
def _decompress_limited(raw: bytes, kind: str, limit: int):
    """有界解压，返回 (data, consumed, truncated)。consumed 是**输入**里被吃掉的字节数。"""
    try:
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw, limit)
            truncated = bool(d.unconsumed_tail)
            consumed = len(raw) - len(d.unused_data) if not truncated else len(raw)
            return out, consumed, truncated
        if kind == "zlib":
            d = zlib.decompressobj()
            out = d.decompress(raw, limit)
            truncated = bool(d.unconsumed_tail)
            consumed = len(raw) - len(d.unused_data)
            return out, consumed, truncated
        if kind == "xz":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            out = d.decompress(raw, max_length=limit)
            consumed = len(raw) - len(d.unused_data)
            return out, consumed, not d.eof
        if kind == "lzma-alone":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            out = d.decompress(raw, max_length=limit)
            consumed = len(raw) - len(d.unused_data)
            return out, consumed, not d.eof
        if kind == "bzip2":
            d = bz2.BZ2Decompressor()
            out = d.decompress(raw, max_length=limit)
            consumed = len(raw) - len(d.unused_data)
            return out, consumed, not d.eof
    except Exception as e:  # noqa: BLE001
        return None, 0, False
    return None, 0, False


def _safe_name(offset: int, sig: str, decompressed: bool) -> str:
    ext = {"gzip": ".gz", "zlib": ".zlib", "xz": ".xz", "lzma-alone": ".lzma",
           "bzip2": ".bz2"}.get(sig, "")
    return "0x%08X_%s%s%s" % (offset, sig.replace("-", "_"), ext,
                              ".decomp" if decompressed else ".raw")


def carve_image(path: str, out_dir: str, *, ids=None, signatures=None,
                max_files: int = DEFAULT_MAX_FILES,
                max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> dict:
    """把签名区间取成文件。**目录必须不存在**：不覆盖任何既有证据。"""
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：%s" % path}
    dest = os.path.abspath(out_dir)
    if os.path.exists(dest):
        return {"ok": False, "error": "输出目录已存在：%s" % dest,
                "next_actions": ["换一个新的目录名（本工具不覆盖既有目录，"
                                 "避免把上一次取件的证据冲掉）"]}
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent):
        return {"ok": False, "error": "输出目录的父目录不存在：%s" % parent}
    ins = inspect_image(path, max_regions=max(64, int(max_files) * 2))
    if not ins.get("ok"):
        return ins
    regions = list(ins.get("regions") or [])
    if ins["format"] == "ihex":
        return {"ok": False, "error": "HEX 是稀疏文本，取件需先转成 bin",
                "next_actions": ["用 toolchain_objcopy 或 Keil fromelf 转 bin 后再取件"]}
    regions = list(ins.get("regions") or [])
    if ids:
        keep = {int(i) for i in ids}
        regions = [r for r in regions if r["id"] in keep]
    if signatures:
        want = {str(s) for s in signatures}
        regions = [r for r in regions if r["signature"] in want]
    if not regions:
        return {"ok": False, "error": "没有匹配的区间可取",
                "signatures_available": sorted({r["signature"] for r in ins.get("regions") or []}),
                "next_actions": ["先 image_inspect 看 regions，再按 id 或签名名指定"]}

    with open(path, "rb") as f:
        data = f.read()

    os.makedirs(dest, exist_ok=False)
    files, gaps = [], []
    total = 0
    for r in regions:
        if len(files) >= max_files:
            gaps.append({"region_id": r["id"], "offset": r["offset"],
                         "reason": "达到 max_files 上限"})
            continue
        raw = data[r["offset"]:r["offset"] + r["length"]]
        kind = _COMPRESSED.get(r["signature"])
        if kind:
            dec, consumed, truncated = _decompress_limited(raw, kind, max_file_bytes)
            if dec is None:
                gaps.append({"region_id": r["id"], "offset": r["offset"],
                             "reason": "签名像 %s，但解压失败：不是一段合法数据流" % r["signature"]})
                continue
            name = _safe_name(r["offset"], r["signature"], True)
            hash_input = dec
            src_len = consumed or r["length"]
            content_range = None  # 解压后的内容与原文件字节没有一一映射
        else:
            if len(raw) > max_file_bytes:
                gaps.append({"region_id": r["id"], "offset": r["offset"],
                             "reason": "区间超过单文件上限 %d 字节" % max_file_bytes})
                continue
            dec, truncated = raw, False
            name = _safe_name(r["offset"], r["signature"], False)
            hash_input = dec
            src_len = r["length"]
            content_range = {"offset": r["offset"], "length": r["length"]}
        if total + len(dec) > max_total_bytes:
            gaps.append({"region_id": r["id"], "offset": r["offset"],
                         "reason": "达到总字节上限 %d" % max_total_bytes})
            continue
        dst = os.path.join(dest, name)
        try:
            with open(dst, "xb") as w:  # 独占写：同名即失败，绝不覆盖
                w.write(dec)
        except FileExistsError:
            gaps.append({"region_id": r["id"], "offset": r["offset"],
                         "reason": "目标文件已存在（不覆盖）"})
            continue
        got = sha256_file(dst)
        want = hashlib.sha256(hash_input).hexdigest()
        total += len(dec)
        files.append({
            "region_id": r["id"],
            "file": name,
            "path": dst,
            "size": len(dec),
            "sha256": got,
            "sha256_verified": got == want,
            "source": {"offset": r["offset"], "length": src_len},
            "source_range_basis": ("decompressed_stream_end" if kind else "signature_upper_bound"),
            "content_range": content_range,
            "decompressed": bool(kind),
            "truncated": bool(truncated),
        })
    out = {
        "ok": True,
        "input": {"path": ins["path"], "size": ins["size"], "sha256": ins["sha256"]},
        "output_directory": dest,
        "files": files,
        "gaps": gaps,
        "total_bytes": total,
        "complete": not gaps,
        "limitations": [
            "解压出来的内容与原文件字节**没有一一映射**（content_range 为 null）",
            "未取件的区间不代表镜像损坏；它只是没被本次选择覆盖",
        ],
    }
    if gaps:
        out["next_actions"] = ["按 gaps 的 reason 放宽 max_files / max_file_bytes / max_total_bytes，"
                               "或换一个新目录重取（既有目录不会被覆盖）"]
    return out
