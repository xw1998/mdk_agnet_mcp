# -*- coding: utf-8 -*-
"""Keil 工程管理文件（``.uvprojx`` / ``.uvoptx`` / ``.uvmpw``）的**编码体检与安全写入**。

为什么单独一个模块（批次97）
----------------------------
真实事故不止一起：AI（或人）用「读文本 → 改一行 → 写回文本」的方式改工程文件，
写回时把 **BOM 丢了、行尾从 CRLF 变成 LF、非 ASCII 字节被替换成 ``?``**，
结果 uVision 打开工程报错/分组丢失。这类损坏的共同点是：

1. 用 ``open(path, "w", encoding=...)`` 直接写——**没有往返校验**，一旦解码时
   走过 ``errors="replace"`` 或 ``latin-1`` 兜底，原来的字节就已经不是原来的字节了；
2. 用 text 模式写而没带 ``newline=""``——Python 会把 ``\\n`` 翻成 ``\\r\\n``（Windows），
   混着原文件里的 ``\\r\\n`` 就变成 ``\\r\\r\\n``；
3. 新增的几行用 ``\\n`` 拼进去，而原文件是 CRLF——**同一文件里两种行尾**，
   Keil 的解析器对此容错很差；
4. 写完不看结果，于是「写入成功」被当成「文件正确」。

本模块把上面四条变成硬约束：

* ``read_text`` —— 严格解码，**不用 ``replace``**；记录编码/BOM/行尾/非 ASCII 数。
* ``write_text`` —— 写前四条校验、写时原子替换、写后回读核对：
  ① 调用方视角的 ``old_text`` 必须能**逐字节**还原出磁盘上的原始字节（往返校验）；
  ② 新文本必须能用**原编码**编回去（编不回去就报错，绝不替换成 ``?``）；
  ③ 新文本必须仍是**可解析的 XML**；
  ④ 写后回读字节与预期**完全一致**，再解析一次。
  任一不满足就**不落盘**并返回错误码——宁可失败，也不给「看起来改好了」的错答案。
* 新增行的行尾按原文件风格补齐（只改「这次改动的区间」，不动文件其余部分）。

用法（供 uvprojx / uvoptx / cmdscript 复用）::

    from . import projectfile
    text, meta = projectfile.read_text(path)
    res = projectfile.write_text(path, new_text, old_text=text, backup=True)
    if not res["ok"]:
        return res           # 已经带 ok/error/error_code，直接回给调用方
"""
from __future__ import annotations

import codecs
import hashlib
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET

# 解码尝试顺序：先 UTF-8（含 BOM），再 GBK（中文 Windows 上 Keil 的常见输出），
# 最后 latin-1（**任何**字节都能解，只用来兜底读出文本做展示，标记 confident=False）。
_CODEC_TRY = ("utf-8", "gbk")

# 这些后缀是 Keil 的 XML 工程文件，写入后必须能解析。
XML_SUFFIXES = (".uvprojx", ".uvoptx", ".uvmpw", ".uvguix", ".scvd")


# ----------------------------------------------------------------------
# 体检
# ----------------------------------------------------------------------
def _decode(raw: bytes) -> tuple:
    """返回 (text, encoding, confident)。**不使用 errors="replace"**。"""
    if raw.startswith(codecs.BOM_UTF8):
        try:
            return raw.decode("utf-8-sig"), "utf-8-sig", True
        except UnicodeDecodeError:
            pass
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        try:
            return raw.decode("utf-16"), "utf-16", True
        except UnicodeDecodeError:
            pass
    for enc in _CODEC_TRY:
        try:
            return raw.decode(enc), enc, True
        except UnicodeDecodeError:
            continue
    # 兜底：能解码（latin-1 恒成立），但**不声称自己知道编码**
    return raw.decode("latin-1"), "latin-1", False


def detect(raw: bytes) -> dict:
    """从原始字节算出编码/BOM/行尾/非 ASCII 等事实（纯函数，不读磁盘）。"""
    text, enc, confident = _decode(raw)
    bom = ""
    if raw.startswith(codecs.BOM_UTF8):
        bom = "utf-8"
    elif raw.startswith(codecs.BOM_UTF16_LE):
        bom = "utf-16-le"
    elif raw.startswith(codecs.BOM_UTF16_BE):
        bom = "utf-16-be"

    crlf = raw.count(b"\r\n")
    lf_total = raw.count(b"\n")
    cr_total = raw.count(b"\r")
    bare_lf = lf_total - crlf
    bare_cr = cr_total - crlf
    if crlf and not (bare_lf or bare_cr):
        newline = "\r\n"
    elif (bare_lf or bare_cr) and not crlf:
        newline = "\n"
    elif crlf or bare_lf:
        # 混合：取多的那个，同时置 mixed 让调用方知道「这文件本来就不统一」
        newline = "\r\n" if crlf >= bare_lf else "\n"
    else:
        newline = "\n"             # 单行/空文件：无行尾可循，按 LF
    mixed = bool((crlf and bare_lf) or bare_cr)

    # 往返校验：用检测到的编码把文本编回去，必须与原始字节**逐字节相同**。
    # 这一条是「这次改动不会静默毁字符」的基础；不成立就说明编码判断不可靠。
    try:
        roundtrip = text.encode(enc) == raw
    except UnicodeEncodeError:
        roundtrip = False

    return {
        "encoding": enc,
        "encoding_confident": confident,
        "bom": bom,
        "newline": "CRLF" if newline == "\r\n" else "LF",
        "crlf": crlf,
        "lf_only": bare_lf,
        "cr_only": bare_cr,
        "mixed_newline": mixed,
        "non_ascii_bytes": sum(1 for b in raw if b >= 0x80),
        "replacement_chars": text.count("\ufffd"),
        "text": text,
        "roundtrip_ok": roundtrip,
    }


_EXPAT_ENC = {"utf-8-sig": "utf-8", "utf-16": "utf-16", "latin-1": "iso-8859-1"}


def _xml_probe(data: bytes, encoding: str = "") -> tuple:
    """尝试解析 XML，返回 (ok, error, root_tag)。

    **必须显式告诉 expat 编码**：中文工程里很常见的真实情况是「XML 声明写着
    ``encoding="UTF-8"``，但路径里的中文其实是 GBK 字节」——严格按声明解会解不开，
    可 uVision 自己毫不在意、照常打开。若拿严格解析当写入闸门，就会把这类正常工程判死。
    故这里按**检测到的实际编码**解析（声明被显式编码覆盖）。
    """
    try:
        enc = _EXPAT_ENC.get(encoding, encoding or "")
        if enc:
            try:
                root = ET.fromstring(data, parser=ET.XMLParser(encoding=enc))
            except ValueError:
                # expat 不支持 GBK/GB18030/Big5 这类多字节编码（"multi-byte encodings
                # are not supported"）。退一步：先按实际编码解成 str，再去掉 XML 声明
                # （str 形式不能带 encoding 声明），然后解析——语义等价。
                txt = data.decode(enc) if enc else data.decode("utf-8")
                txt = re.sub(r"^\s*<\?xml[^>]*\?>", "", txt, count=1)
                root = ET.fromstring(txt)
        else:
            root = ET.fromstring(data)
        return True, "", (root.tag if isinstance(root.tag, str) else "")
    except Exception as e:  # noqa: BLE001
        return False, "%s: %s" % (type(e).__name__, e), ""


def inspect(path: str) -> dict:
    """只读体检一个工程文件：编码/BOM/行尾/混合行尾/XML 是否可解析/可疑点。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return {"ok": False, "path": path, "error": "读取失败：%s" % e}
    meta = detect(raw)
    text = meta.pop("text")
    out = {"ok": True, "path": path, "size": len(raw),
           "sha256": hashlib.sha256(raw).hexdigest()}
    out.update(meta)

    suffix = os.path.splitext(path)[1].lower()
    if suffix in XML_SUFFIXES:
        xml_ok, xml_err, root_tag = _xml_probe(raw, meta["encoding"])
        out["xml_ok"] = xml_ok
        out["xml_error"] = xml_err
        out["root_tag"] = root_tag

    notes, level = [], "ok"
    if not meta["encoding_confident"]:
        notes.append("编码无法判定（UTF-8/GBK 都解不开），写入时不会做任何替换，"
                     "只会拒绝。这份文件多半已经被别的工具写坏过。")
        level = "error"
    if meta["replacement_chars"]:
        notes.append("文本里有 %d 个 U+FFFD 替换字符——这是「用 errors='replace' 写回过」"
                     "的典型痕迹，原文的字符已经不可恢复，建议从版本库/备份找回。"
                     % meta["replacement_chars"])
        level = "error"
    if out.get("xml_ok") is False:
        notes.append("XML 解析失败（%s）——uVision 打开这个工程就会报错。"
                     % out.get("xml_error"))
        level = "error"
    if meta["mixed_newline"] and level == "ok":
        notes.append("行尾是混合的（CRLF %d / 裸 LF %d）——本服务写入时只改本次改动的区间，"
                     "不会顺手统一全文件；但 uVision 对此容错差，建议用 git 还原成统一行尾。"
                     % (meta["crlf"], meta["lf_only"]))
        level = "warn"
    if not meta["roundtrip_ok"] and level == "ok":
        notes.append("用检测到的编码「解→编」不能还原原始字节，说明这份文件的编码判断不可靠。")
        level = "warn"
    out["notes"] = notes
    out["level"] = level
    return out


def describe(path: str) -> dict:
    """``inspect`` 的紧凑版（给工具返回值用，不带长文本）。"""
    r = inspect(path)
    if not r.get("ok"):
        return r
    keys = ("path", "size", "sha256", "encoding", "encoding_confident", "bom", "newline",
            "crlf", "lf_only", "cr_only", "mixed_newline", "non_ascii_bytes",
            "replacement_chars", "roundtrip_ok", "xml_ok", "xml_error", "root_tag",
            "level", "notes")
    return {k: r[k] for k in keys if k in r}


def read_text(path: str) -> tuple:
    """严格读取，返回 ``(text, meta)``；``meta`` 里含 encoding/bom/newline 等。

    与旧 ``_read_text`` 的区别：**语义不变地**保留原始文本（换行不做翻译），
    但把「实际编码是什么」与「是否可信」一并带出去，供写入时使用。
    """
    with open(path, "rb") as f:
        raw = f.read()
    meta = detect(raw)
    text = meta.pop("text")
    meta["sha256"] = hashlib.sha256(raw).hexdigest()
    return text, meta


# ----------------------------------------------------------------------
# 写入
# ----------------------------------------------------------------------
def _common_prefix_len(a: str, b: str) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    # 不要切在 \r\n 中间（那样后面的行尾归一化会把原行尾误判成新增行尾）
    if 0 < i < len(a) and a[i - 1] == "\r" and a[i:i + 1] == "\n":
        i -= 1
    if 0 < i < len(b) and b[i - 1] == "\r" and b[i:i + 1] == "\n":
        i -= 1
    return i


def _common_suffix_len(a: str, b: str, i: int) -> int:
    n = min(len(a), len(b)) - i
    j = 0
    while j < n and a[len(a) - 1 - j] == b[len(b) - 1 - j]:
        j += 1
    if j and b[len(b) - j - 1:len(b) - j + 1] == "\r\n":
        j -= 1
    return j


def normalize_inserted_newlines(old_text: str, new_text: str, newline: str) -> tuple:
    """只把**本次改动区间**的行尾归一化到原文件风格，其余字节一律不动。

    为什么不做全文件替换：工程文件里混行尾是既成事实（甚至同一工程里 .uvprojx 是 LF、
    .uvoptx 是 CRLF），全文件统一会制造一处与本次改动无关的 diff，且可能改坏
    uVision 的原文比对。返回 (新文本, 被改写的行数)。
    """
    want = newline or "\n"
    i = _common_prefix_len(old_text, new_text)
    j = _common_suffix_len(old_text, new_text, i)
    mid = new_text[i:len(new_text) - j if j else len(new_text)]
    if "\n" not in mid and "\r" not in mid:
        return new_text, 0
    uni = mid.replace("\r\n", "\n").replace("\r", "\n")
    n = uni.count("\n")
    fixed = uni.replace("\n", want)
    if fixed == mid:
        return new_text, 0
    return new_text[:i] + fixed + (new_text[len(new_text) - j:] if j else ""), n


def _atomic_write(path: str, data: bytes) -> None:
    """同目录临时文件 + ``os.replace``：写到一半断电也不会留下半截工程文件。"""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".mdkdebug_", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise


def write_text(path: str, new_text: str, old_text: str = None,
               backup: bool = True, expected_sha: str = None,
               validate_xml: bool = True, allow_mixed: bool = True) -> dict:
    """把 ``new_text`` 安全写回工程文件。**任何一条校验不过都不落盘。**

    参数
    ----
    old_text      调用方读到的原文。给了就做往返校验（``old_text`` 用原编码编回去
                  必须与磁盘字节逐字节相同）——这是防「读到的是被 replace 过的文本，
                  再写回去就等于把文件洗坏」的关键一步。
    expected_sha  期望的写入前 sha256；不符说明文件被别的进程改过，拒绝写（并发保护）。
    validate_xml  XML 后缀的文件写完必须是可解析的 XML（默认开）。

    返回 ``{ok, changed, encoding, bom, newline, ...}``；失败时带 ``error_code``：
    ``stale-content`` / ``stale-sha`` / ``encode-failed`` / ``xml-invalid`` /
    ``verify-failed`` / ``mixed-newline`` / ``write-failed``。
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return {"ok": False, "path": path, "error": "文件不存在",
                "error_code": "not-found"}
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return {"ok": False, "path": path, "error": "读取失败：%s" % e,
                "error_code": "read-failed"}

    meta = detect(raw)
    cur_text = meta.pop("text")
    sha_before = hashlib.sha256(raw).hexdigest()
    base = {"path": path, "encoding": meta["encoding"], "bom": meta["bom"],
            "newline": meta["newline"], "sha256_before": sha_before,
            "size_before": len(raw)}

    if expected_sha and expected_sha.strip().lower() != sha_before:
        return dict(base, ok=False, error_code="stale-sha",
                    error="写入前 sha256 与 expected_sha 不符（文件已被别的进程改过）："
                          "期望 %s，实际 %s。请重新读一遍再改。"
                          % (expected_sha.strip(), sha_before))

    if old_text is not None:
        try:
            back = old_text.encode(meta["encoding"])
        except UnicodeEncodeError as e:
            return dict(base, ok=False, error_code="stale-content",
                        error="调用方给的 old_text 用 %s 编不回去（%s）——说明它不是从这份"
                              "文件按该编码读出来的，拒绝写以免把文件洗坏。"
                              % (meta["encoding"], e))
        if back != raw:
            return dict(base, ok=False, error_code="stale-content",
                        error="调用方给的 old_text 与磁盘字节不一致（往返校验失败，"
                              "磁盘 %d 字节 / 回编 %d 字节）。文件可能已被改过，或读的时候"
                              "走了有损解码。请重新读一遍再改。" % (len(raw), len(back)))

    if meta["mixed_newline"] and not allow_mixed:
        return dict(base, ok=False, error_code="mixed-newline",
                    error="原文件行尾是混合的（CRLF %d / 裸 LF %d），已按 allow_mixed=false "
                          "拒绝写入。先用 git 还原成统一行尾。" % (meta["crlf"], meta["lf_only"]))

    if new_text == cur_text:
        return dict(base, ok=True, changed=False, message="内容无变化，未写文件")

    fixed_text, nl_fixed = normalize_inserted_newlines(cur_text, new_text, meta["newline"])
    try:
        data = fixed_text.encode(meta["encoding"])
    except UnicodeEncodeError as e:
        bad = ""
        try:
            bad = fixed_text[e.start:e.start + 20]
        except Exception:  # noqa: BLE001
            pass
        return dict(base, ok=False, error_code="encode-failed",
                    error="新内容里有字符无法用原编码 %s 表示（%s，附近文本：%r）。"
                          "旧实现会用 errors='replace' 把它写成 '?'，静默毁掉原文；现在直接拒绝。"
                          "若确实要写这些字符，请先把整份文件转成 UTF-8（会改变文件编码，需用户同意）。"
                          % (meta["encoding"], e, bad),
                    offending_text=bad)

    old_xml_ok = None
    if validate_xml and os.path.splitext(path)[1].lower() in XML_SUFFIXES:
        old_xml_ok, _old_err, _t = _xml_probe(raw, meta["encoding"])
        xml_ok, xml_err, _tag = _xml_probe(data, meta["encoding"])
        if old_xml_ok and not xml_ok:
            return dict(base, ok=False, error_code="xml-invalid",
                        error="改后的内容不是可解析的 XML（%s）——不写，否则 uVision 打开"
                              "工程就报错。" % xml_err)

    bak = None
    if backup:
        bak = path + ".mdkdebug.bak"
        try:
            shutil.copy2(path, bak)
        except OSError as e:
            return dict(base, ok=False, error_code="write-failed",
                        error="备份失败，未写入：%s" % e)
        base["backup"] = bak

    try:
        _atomic_write(path, data)
    except OSError as e:
        return dict(base, ok=False, error_code="write-failed",
                    error="写入失败：%s" % e)

    # 写后回读核对：这一条把「写入没报错」升级成「磁盘上确实是我们要的字节」。
    try:
        with open(path, "rb") as f:
            after = f.read()
    except OSError as e:
        return dict(base, ok=False, error_code="verify-failed",
                    error="写后回读失败：%s（备份在 %s）" % (e, bak))
    if after != data:
        return dict(base, ok=False, error_code="verify-failed",
                    error="写后回读的字节与预期不一致（%d vs %d 字节，备份在 %s）。"
                          "可能有别的进程同时改这个文件。"
                          % (len(after), len(data), bak))

    out = dict(base, ok=True, changed=True, backup=bak,
               sha256_after=hashlib.sha256(after).hexdigest(),
               size_after=len(after), newline_fixed=nl_fixed,
               encoding_preserved=True, roundtrip_ok=meta["roundtrip_ok"],
               verify="byte-identical")
    if old_xml_ok is not None:
        out["xml_ok"] = bool(old_xml_ok)
    if old_xml_ok is False:
        out["xml_note"] = ("原文件本身就不是可解析的 XML（可能是「声明 UTF-8 但实际是 GBK "
                           "字节」这类既有问题），本次写入未做 XML 校验，请自行核对。")
    if nl_fixed:
        out["newline_note"] = ("新增的 %d 个换行已按原文件风格（%s）补齐——"
                               "旧实现会把 LF 混进 CRLF 文件里。" % (nl_fixed, meta["newline"]))
    return out


def check_project(project: str, extra=()) -> dict:
    """体检一个工程：``.uvprojx`` 与同名 ``.uvoptx``（以及 ``extra`` 里的路径）。"""
    paths = []
    p = os.path.abspath(project) if project else ""
    low = p.lower()
    if low.endswith(".uvprojx"):
        paths.append(p)
        sib = p[:-len(".uvprojx")] + ".uvoptx"
        if os.path.isfile(sib):
            paths.append(sib)
    elif low.endswith(".uvoptx"):
        paths.append(p)
        sib = p[:-len(".uvoptx")] + ".uvprojx"
        if os.path.isfile(sib):
            paths.append(sib)
    elif p and os.path.isdir(p):
        for name in sorted(os.listdir(p)):
            if name.lower().endswith((".uvprojx", ".uvoptx", ".uvmpw")):
                paths.append(os.path.join(p, name))
    for e in (extra or ()):
        if e and os.path.isfile(e) and e not in paths:
            paths.append(os.path.abspath(e))
    if not paths:
        return {"ok": False, "error": "没找到工程文件（给 .uvprojx/.uvoptx 或含它们的目录）",
                "project": project}
    files = [describe(x) for x in paths]
    bad = [f for f in files if f.get("level") == "error"]
    warn = [f for f in files if f.get("level") == "warn"]
    out = {"ok": True, "project": p or project, "count": len(files), "files": files,
           "level": "error" if bad else ("warn" if warn else "ok")}
    if not bad and not warn:
        out["message"] = ("工程文件编码/行尾/BOM/XML 全部正常；改动请走 uvprojx_edit，"
                          "不要用文本工具整体重写。")
    return out
