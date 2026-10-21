# -*- coding: utf-8 -*-
"""固件镜像切分（批次87）：一颗 Flash dump 里到底装了几个镜像。

批次78 的 ``image.py`` 回答「这个文件里有什么」（格式、熵、内嵌签名），并只检查
**一个**向量表（bin 的 0 偏移 / ELF 的第一个 ``PT_LOAD``）。但现场更常见的是
「一整颗 Flash 的 dump」——bootloader + app + 备份槽 + 若干压缩过的升级包。

要切分它，能零依赖依靠的证据只有三类：

1. **向量表**（Cortex-M）：``word0`` 是初值 SP、``word1`` 是复位地址（bit0=1）。
   一张真表后面还跟着一串 handler 地址。这条证据能把「镜像起点」钉到 4 字节对齐的
   具体偏移上，且不依赖任何文件头。
2. **擦除态**（``0xFF`` 连续区）：Flash 擦掉之后就是一片 0xFF。一条足够长的 0xFF
   带意味着「这一段没有内容」，它自然把前后两块隔开。
3. **容器自报长度**：gzip/zlib/bzip2/xz/lzma 都能解到流尾，从而得到**精确**的
   压缩流长度——比「到下一个签名」的上界可靠得多。

本模块只做这三件事，并且**每条结论都带证据与推导依据**：镜像长度是「到下一个
向量表 / 到擦除带 / 到文件尾」的上界，不是实测值（``size_basis`` 会说清是哪一种）。

零第三方依赖：只用 ``struct``（无）、``zlib``、``bz2``、``lzma`` 三个标准库。
"""
import bz2
import hashlib
import lzma
import os
import zlib

from . import containers as CT
from . import image as IM

# 一张向量表至少要有 SP+复位地址（8 字节）+ 几个 handler 才能拿来做证据
MIN_TABLE_BYTES = 8
# 扫描时的默认参数（都是「宁可少报，也不要把数据当镜像」的取值）
DEFAULT_N_HANDLERS = 6
DEFAULT_HANDLER_RATIO = 0.75
DEFAULT_MIN_SPACING = 0x80
DEFAULT_ERASE_MIN = 256
DEFAULT_MIN_IMAGE = 0x100
MAX_TABLES = 32
# 解压求长度时的输出上限（防解压炸弹；超过就报「超过上限」，不给猜的长度）
MAX_STREAM_OUT = 64 * 1024 * 1024


# ----------------------------------------------------------------------
# 一、向量表扫描
# ----------------------------------------------------------------------
def _word(data, off, endian="little"):
    return int.from_bytes(data[off:off + 4], endian, signed=False)


def score_table(payload, offset, *, base=0, ram=None, flash=None,
                n_handlers=DEFAULT_N_HANDLERS,
                handler_ratio=DEFAULT_HANDLER_RATIO, endian="little") -> dict:
    """给「偏移 offset 处是不是一张 Cortex-M 向量表」打分（不猜：缺窗口就是 None）。

    接受的必要条件（任何一条不满足就不算表）：
      - 初值 SP 非 0/全 1、4 字节对齐；
      - 复位地址 bit0 为 1（Cortex-M 必须跳 Thumb 代码）；
      - 复位地址落在可判定的范围内（给了 Flash 窗口就看窗口，否则看镜像自身范围）；
      - 后续 ``n_handlers`` 个字里，「bit0=1 且落在代码范围」的比例 ≥ 阈值。
    """
    need = 4 * (2 + int(n_handlers))
    if offset < 0 or offset + need > len(payload):
        return {"ok": False, "why": "偏移不足以容纳 SP + 复位地址 + %d 个 handler" % n_handlers}
    img_lo, img_hi = int(base), int(base) + len(payload) - 1
    sp = _word(payload, offset, endian)
    reset_raw = _word(payload, offset + 4, endian)
    reset = reset_raw & ~1
    checks = {}
    checks["sp_nonzero"] = sp not in (0, 0xFFFFFFFF)
    checks["sp_4byte_aligned"] = (sp % 4) == 0
    checks["sp_in_ram"] = (None if ram is None else (int(ram[0]) <= sp <= int(ram[1])))
    checks["reset_thumb_bit"] = bool(reset_raw & 1)
    if flash is not None:
        checks["reset_in_flash"] = int(flash[0]) <= reset <= int(flash[1])
        # 判据退化：SP 不在 RAM 窗口里时，仅凭「复位地址落在 Flash」不能算证据充分
        checks["sp_window_known"] = ram is not None
    else:
        checks["reset_in_image"] = img_lo <= reset < img_hi
        checks["sp_window_known"] = False
    why = []
    if not checks["sp_nonzero"]:
        why.append("初值 SP 是 0 或全 1（空白区/取错偏移）")
    if not checks["sp_4byte_aligned"]:
        why.append("初值 SP 未 4 字节对齐：不是 AAPCS 的栈顶")
    if not checks["reset_thumb_bit"]:
        why.append("复位地址 bit0 为 0：Cortex-M 跳 Thumb，bit0 必须为 1")
    if checks.get("reset_in_flash") is False:
        why.append("复位地址 0x%08X 不在给定 Flash 窗口内" % reset)
    if checks.get("reset_in_image") is False:
        why.append("复位地址 0x%08X 不在本镜像地址范围内" % reset)
    if checks.get("sp_in_ram") is False:
        why.append("初值 SP 0x%08X 不在给定 RAM 窗口内" % sp)

    hits = 0
    for i in range(int(n_handlers)):
        w = _word(payload, offset + 8 + 4 * i, endian)
        tgt = w & ~1
        if w & 1 and (img_lo <= tgt < img_hi if flash is None
                      else int(flash[0]) <= tgt <= int(flash[1])):
            hits += 1
    ratio = hits / float(n_handlers) if n_handlers else 0.0

    hard_ok = (checks["sp_nonzero"] and checks["sp_4byte_aligned"]
               and checks["reset_thumb_bit"]
               and checks.get("reset_in_flash", True) is not False
               and checks.get("reset_in_image", True) is not False
               and checks.get("sp_in_ram", True) is not False)
    accepted = bool(hard_ok and ratio >= float(handler_ratio))
    if hard_ok and ratio < float(handler_ratio):
        why.append("后续 %d 个字里只有 %d 个像代码地址（比例 %.2f < %.2f）："
                   "判断依据不足" % (n_handlers, hits, ratio, float(handler_ratio)))
    if not checks["sp_window_known"]:
        confidence = "plausible" if accepted else "rejected"
        if accepted and ram is None:
            why.append("没有给 RAM 窗口：SP 只在「非 0 且对齐」这一层被判过")
    else:
        confidence = "strong" if accepted else "rejected"
    return {"ok": True, "accepted": accepted, "confidence": confidence,
            "sp_hex": "0x%08X" % sp, "reset_hex": "0x%08X" % reset_raw,
            "reset_aligned_hex": "0x%08X" % reset,
            "handler_hits": hits, "handler_ratio": round(ratio, 3),
            "checks": checks, "why": why}


def scan_vector_tables(payload, *, base=0, ram=None, flash=None,
                       limit=None, max_tables=MAX_TABLES,
                       n_handlers=DEFAULT_N_HANDLERS,
                       handler_ratio=DEFAULT_HANDLER_RATIO,
                       min_spacing=DEFAULT_MIN_SPACING) -> list:
    """在整份 payload 里扫 Cortex-M 向量表（4 字节步进）。

    为什么需要 `min_spacing`：一张表的 handler 区里，某些 handler 地址**本身**也可能
    凑出一个「SP 像栈顶、下一个字像 Thumb 地址」的假表。同一张表的表项间距远小于
    0x80，所以「已接受的表之后 0x80 字节内不再接受新表」能把这类自证噪声挡掉。
    """
    n = len(payload) if limit is None else min(len(payload), int(limit))
    accepted, rejected_noise = [], 0
    off = 0
    while off + 4 * (2 + int(n_handlers)) <= n:
        if off % 4:
            off += 4 - (off % 4)
            continue
        if accepted and off - accepted[-1]["offset"] < min_spacing:
            off += 4
            continue
        r = score_table(payload, off, base=base, ram=ram, flash=flash,
                        n_handlers=n_handlers, handler_ratio=handler_ratio)
        if r.get("accepted"):
            r.update({"offset": off, "offset_hex": "0x%X" % off,
                      "addr_hex": "0x%X" % (int(base) + off)})
            r["size_basis"] = "vector_table"
            accepted.append(r)
            if len(accepted) >= int(max_tables):
                break
        elif r.get("ok") and r.get("handler_hits", 0) >= max(2, int(n_handlers) - 1):
            rejected_noise += 1
        off += 4
    if len(accepted) > int(max_tables):
        del accepted[int(max_tables):]
    return accepted


# ----------------------------------------------------------------------
# 二、擦除态
# ----------------------------------------------------------------------
def find_erase_runs(payload, *, erase=0xFF, min_len=DEFAULT_ERASE_MIN,
                    base=0, limit=None, max_runs=64) -> list:
    """找足够长的擦除带（默认 0xFF）。这是「这一段没有内容」的**正向证据**。"""
    data = payload if limit is None else payload[:int(limit)]
    runs, start, n = [], None, len(data)
    for i in range(n):
        if data[i] == erase:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= int(min_len):
                runs.append(_run(start, i, base, erase))
                if len(runs) >= int(max_runs):
                    start = None
                    break
            start = None
    if start is not None and n - start >= int(min_len) and len(runs) < int(max_runs):
        runs.append(_run(start, n, base, erase))
    return runs


def _run(start, end, base, fill):
    return {"offset": start, "offset_hex": "0x%X" % start,
            "addr_hex": "0x%X" % (int(base) + start),
            "length": end - start,
            "fill_byte": "0x%02X" % int(fill)}


# ----------------------------------------------------------------------
# 三、容器自报长度（精确的流尾）
# ----------------------------------------------------------------------
def stream_extent(data, offset, kind, *, max_out=MAX_STREAM_OUT) -> dict:
    """用容器自己声明的结构求出「这条流到哪结束」（精确长度，不是上界）。

    支持 gzip / zlib / bzip2 / xz / lzma-alone——都是标准库能解到流尾的格式。
    lz4 / zstd 没有标准库实现，明确报 ``not_supported``，不返回估计值。
    """
    raw = data[int(offset):]
    if not raw:
        return {"ok": False, "why": "偏移处没有字节"}
    try:
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw, max_out)
            eof, unused = d.eof, d.unused_data
        elif kind == "zlib":
            d = zlib.decompressobj()
            out = d.decompress(raw, max_out)
            eof, unused = d.eof, d.unused_data
        elif kind == "bzip2":
            d = bz2.BZ2Decompressor()
            out = d.decompress(raw, max_out)
            eof, unused = d.eof, d.unused_data
        elif kind == "xz":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            out = d.decompress(raw, max_out)
            eof, unused = d.eof, d.unused_data
        elif kind == "lzma-alone":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            out = d.decompress(raw, max_out)
            eof, unused = d.eof, d.unused_data
        else:
            return {"ok": False, "why": "没有标准库能解到流尾：%s" % kind,
                    "status": "not_supported"}
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError) as e:
        return {"ok": False, "why": "解压失败（不是一条完整数据流）：%s" % e}
    if not eof:
        return {"ok": False,
                "why": "流没有正常结束（被截断，或解压输出超过 %d 字节上限）" % max_out}
    consumed = len(raw) - len(unused)
    n_raw = len(out)          # ⚠ 先把解压长度记下来：下面 out 会被换成结果字典
    out = {"ok": True, "status": "ok",
           "raw_bytes": n_raw, "compressed_bytes": consumed,
           "size_basis": "stream_end"}
    if kind == "gzip" and consumed >= 8:
        isize = int.from_bytes(data[int(offset) + consumed - 4:
                                    int(offset) + consumed], "little")
        out["isize_verified"] = (isize == (n_raw & 0xFFFFFFFF))
        if not out["isize_verified"]:
            out["why"] = ("gzip 尾部 ISIZE 与解压长度不符：这条流可能被拼接/截断，"
                          "长度不可信")
            out["size_basis"] = "stream_end_isize_mismatch"
    return out


# ----------------------------------------------------------------------
# 四、切分
# ----------------------------------------------------------------------
def partition_image(payload, tables, *, base=0, signatures=None,
                    erase_runs=None, erase=0xFF,
                    min_image=DEFAULT_MIN_IMAGE, endian="little") -> dict:
    """按向量表 + 擦除带把 payload 切成若干镜像块。

    每块的结尾是**推导**出来的，三种依据按可信度从高到低：
      - ``erase_gap``：到紧邻的擦除带开头（擦除带把两块内容隔开，最可靠的边界）；
      - ``next_vector_table``：到下一个向量表（中间可能夹着本块自己的尾部数据）；
      - ``end_of_file``：到文件尾（最后一个镜像）。
    """
    tables = sorted(tables, key=lambda t: t["offset"]) if tables else []
    runs = find_erase_runs(payload, erase=erase) if erase_runs is None else erase_runs
    sigs = signatures or []
    images, warnings = [], []
    for i, t in enumerate(tables):
        start = t["offset"]
        nxt_tbl = tables[i + 1]["offset"] if i + 1 < len(tables) else len(payload)
        sep = [r for r in runs if r["offset"] > start and r["offset"] < nxt_tbl]
        if sep:
            end, basis = sep[0]["offset"], "erase_gap"
        elif nxt_tbl < len(payload):
            end, basis = nxt_tbl, "next_vector_table"
        else:
            end, basis = len(payload), "end_of_file"
        length = max(0, end - start)
        if length < int(min_image):
            warnings.append("偏移 0x%X 处的镜像只有 %d 字节（< %d）："
                            "很可能是向量表噪声，不是独立镜像"
                            % (start, length, min_image))
        inner = [s for s in sigs
                 if s.get("stream_check") != "failed"
                 and start <= s.get("offset", -1) < end]
        images.append({
            "id": len(images),
            "offset": start,
            "offset_hex": "0x%X" % start,
            "addr_hex": "0x%X" % (int(base) + start),
            "length": length,
            "size_basis": basis,
            "vector_table": {"offset": t["offset"],
                             "sp_hex": t.get("sp_hex"),
                             "reset_hex": t.get("reset_hex"),
                             "handler_ratio": t.get("handler_ratio"),
                             "confidence": t.get("confidence")},
            "signatures": [{"offset_hex": "0x%X" % s["offset"],
                            "signature": s.get("signature"),
                            "kind": s.get("kind")} for s in inner[:16]],
            "confidence": t.get("confidence"),
        })
    # 未归属的字节：镜像块之外、也不是擦除态。它们是「这里还有东西，但没有证据说是镜像」
    covered = sum(img["length"] for img in images)
    erase_bytes = sum(r["length"] for r in runs)
    unknown = max(0, len(payload) - covered - erase_bytes)
    return {"images": images, "erase_runs": runs, "warnings": warnings,
            "coverage": {"total_bytes": len(payload),
                         "in_images": covered,
                         "erase_bytes": erase_bytes,
                         "unassigned_bytes": unknown,
                         "images_found": len(images),
                         "tables_found": len(tables)}}


# ----------------------------------------------------------------------
# 五、一次做完（工具入口用）
# ----------------------------------------------------------------------
def split_image(path: str, *, base=0,
                flash_start=None, flash_size=None,
                ram_start=None, ram_size=None,
                erase=0xFF, erase_min=DEFAULT_ERASE_MIN,
                max_tables=MAX_TABLES, handler_ratio=DEFAULT_HANDLER_RATIO,
                n_handlers=DEFAULT_N_HANDLERS, min_spacing=DEFAULT_MIN_SPACING,
                min_image=DEFAULT_MIN_IMAGE,
                max_signatures=64, max_scan_bytes=32 * 1024 * 1024,
                endian="little", out_dir: str = "") -> dict:
    """读一个镜像文件，报「这里面有几个镜像、各自的地址与边界依据」。

    ``out_dir``（批次90）：给了就把每个镜像按 ``offset..offset+length`` **原样切成
    单独文件**（``image_00.bin`` …）并回读 SHA-256。切出来的字节可以直接喂
    ``recover_project_exact`` / ``recover_probe``——一颗 dump 里切出几份镜像之后，
    下一步不该还要调用方自己读偏移量写文件。目录必须不存在（不覆盖既有证据）。
    """
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：%s" % path}
    size = os.path.getsize(path)
    if size == 0:
        return {"ok": False, "path": os.path.abspath(path), "size": 0,
                "error": "空文件：没有任何可判的事实"}
    if size > IM.MAX_INPUT_BYTES:
        return {"ok": False, "path": os.path.abspath(path), "size": size,
                "error": "输入超过 %d MiB 上限（本工具不读部分文件来「猜」整体）"
                         % (IM.MAX_INPUT_BYTES // (1024 * 1024))}
    with open(path, "rb") as f:
        data = f.read()
    kind, evidence = CT.detect(data[:4096], path)
    fmt = "ihex" if kind == "ihex" else ("srec" if kind == "srec" else
                                        IM.detect_format(data[:4096], path))
    warnings, limitations = [], []
    text_kind = kind in ("ihex", "srec")
    if text_kind:
        # 稀疏文本：先铺成字节图，再用**记录给出的**基址（不是调用方猜的）
        if kind == "ihex":
            payload = IM._hex_bytes_to_sparse(data.decode("latin-1"))
            flat_base = base
            parsed = IM.parse_ihex(data.decode("latin-1"))
            if parsed.get("min_offset"):
                flat_base = int(base or 0) + int(parsed["min_offset"])
        else:
            flat = CT.srec_flat(data.decode("latin-1"))
            if not flat.get("ok"):
                return {"ok": False, "error": "S-record 解析失败：%s"
                                              % (flat.get("error") or "无数据记录")}
            payload, flat_base = flat["data"], int(flat["base"])
        base = flat_base
        limitations.append("%s 是稀疏文本：本工具按「最小偏移铺成字节图」看待它，"
                           "空隙被填 0x00，**不代表那边是擦除态**；因此不据此判擦除带"
                           "（%s）" % (fmt.upper(), evidence))
        erase_runs = []
    else:
        payload = data
        erase_runs = find_erase_runs(payload, erase=erase, min_len=erase_min,
                                     base=base)
    if fmt == "elf":
        limitations.append("ELF 内部可能本来就只有一个镜像；多向量表扫描仍照做，"
                           "但 ELF 的段/节布局才是它的权威边界")

    flash = None
    if flash_start is not None and flash_size:
        flash = (int(flash_start), int(flash_start) + int(flash_size) - 1)
    ram = None
    if ram_start is not None and ram_size:
        ram = (int(ram_start), int(ram_start) + int(ram_size))
    if flash is None or ram is None:
        limitations.append("没有同时给 Flash 窗口（flash_start/flash_size）与 RAM 窗口"
                           "（ram_start/ram_size）：向量表判据退化成「非 0 + 对齐 + "
                           "地址落在镜像内」，置信度只能是 plausible，不是 strong")

    scan = payload[:int(max_scan_bytes)]
    if len(payload) > len(scan):
        limitations.append("只扫描了前 %d 字节（输入 %d 字节）：后段没有判据"
                           % (len(scan), len(payload)))
    tables = scan_vector_tables(scan, base=base, ram=ram, flash=flash,
                               max_tables=max_tables, n_handlers=n_handlers,
                               handler_ratio=handler_ratio, min_spacing=min_spacing)
    sigs = IM.find_signatures(scan, limit=max_signatures) if scan else []
    # 压缩流用「流尾」替掉「到下一个签名」的上界（只对标准库能解到流尾的格式）
    for s in sigs:
        if s.get("stream_check") != "ok":
            continue
        kind = IM._COMPRESSED.get(s.get("signature"))
        if not kind:
            continue
        ext = stream_extent(scan, s["offset"], kind)
        if ext.get("ok"):
            s["stream_extent"] = ext
            s["confidence"] = "stream_verified"
    part = partition_image(scan, tables, base=base, signatures=sigs,
                           erase_runs=erase_runs, erase=erase,
                           min_image=min_image, endian=endian)
    warnings.extend(part["warnings"])
    if not tables:
        warnings.append("整份输入里**没有**任何偏移能凑出一张说得通的 Cortex-M 向量表："
                        "可能是非 Cortex-M 架构、被加密/压缩的镜像，或偏移没对齐"
                        "（base 给错时会显示成对不上）")
    limitations.append("镜像长度是**推导**值（到擦除带/下一个向量表/文件尾），"
                       "不是镜像自己声明的长度；同一颗 Flash 上的两个镜像之间如果"
                       "没有擦除带，前一块的尾部数据会被算进前一块")
    limitations.append("本工具只找 Cortex-M 向量表；RISC-V/ARM9 等其他架构的镜像起点"
                       "不在判据里（可在 recover_probe / image_inspect 里另找证据）")
    files = []
    if out_dir:
        dest = os.path.abspath(out_dir)
        if os.path.exists(dest):
            return {"ok": False,
                    "error": "输出目录已存在：%s" % dest,
                    "hint": "切片不复用目录（不覆盖既有证据）；换一个不存在的路径"}
        os.makedirs(dest)
        for i, im in enumerate(part["images"]):
            off = int(im.get("offset") or 0)
            ln = int(im.get("length") or 0)
            blob = data[off:off + ln]
            name = "image_%02d.bin" % i
            fp = os.path.join(dest, name)
            with open(fp, "wb") as f:
                f.write(blob)
            back = open(fp, "rb").read()
            im["path"] = fp
            im["sha256"] = hashlib.sha256(blob).hexdigest()
            files.append({"path": fp, "bytes": len(blob),
                          "sha256": im["sha256"],
                          "readback_ok": back == blob,
                          "offset": off, "offset_hex": im.get("offset_hex"),
                          "addr_hex": im.get("addr_hex")})
        bad = [f for f in files if not f["readback_ok"]]
        if bad:
            return {"ok": False,
                    "error": "切片回读校验失败：%s" % ", ".join(f["path"] for f in bad),
                    "files": files}

    out = {"ok": True, "input": {"path": os.path.abspath(path), "size": size,
                                 "sha256": IM.sha256_file(path)},
           "format": fmt, "base_hex": "0x%X" % int(base),
           "out_dir": os.path.abspath(out_dir) if out_dir else "",
           "files": files,
           "windows": {"flash": _win(flash), "ram": _win(ram)},
           "tables": tables,
           "images": part["images"],
           "erase_runs": part["erase_runs"],
           "signatures": sigs,
           "coverage": part["coverage"],
           "warnings": warnings,
           "limitations": limitations}
    out["verdict"] = "warn" if warnings else "ok"
    return out


def _win(w):
    if not w:
        return None
    return {"start_hex": "0x%X" % int(w[0]), "end_hex": "0x%X" % int(w[1]),
            "size": int(w[1]) - int(w[0]) + 1}
