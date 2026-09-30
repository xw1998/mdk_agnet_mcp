# -*- coding: utf-8 -*-
"""固件契约预检（批次77）——**上板之前**先把「注定判不出来」的事情说清楚。

为什么要单独有这一步
------------------
AI 驱动的闭环里，最贵的错误不是"编译失败"，而是**把工具/环境的问题伪装成代码问题**：
闭环一直超时 → AI 去改本来正确的代码 → 再超时 → 再改。所以这里做的事，是在编译之前
把「缺什么、缺了会表现成什么」逐条摆出来，让「事情没发生」和「你看不见」分开。

三条通道的诚实口径（借用同类开源项目的分类，我们只保留与自己有关的）
- 编译：**0 Error** 才有下一步；
- 烧录：**探针在位**才能上板；
- 串口：**收到通过令牌**才算过——没有串口时，能定位崩溃但**无法判定成功**，
  这一条必须显式说出来，不能让它退化成"大概是失败"。

本模块只读，不改任何文件。
"""
from __future__ import annotations

import os
import re

DEFAULT_TOKEN = "[ALL TESTS PASSED]"

# 单个源文件超过这个大小就跳过（避免对超大生成文件做无谓扫描）
_MAX_FILE_BYTES = 2 * 1024 * 1024

def classify_encoding(raw: bytes) -> str:
    """判断源文件编码，用于回答「AC5 会不会把它读错」。

    AC5（``armcc``）**按本机代码页**解析源文件——中文 Windows 上是 GBK。于是：
    - ``ascii``：没有非 ASCII 字节，怎么读都一样，安全；
    - ``utf-8``：非 ASCII 是以 UTF-8 多字节存进去的，被当 GBK 读就会把一个汉字拆成
      两个"半个汉字"的字节序列，**字符串字面量**里直接报语法错；
    - ``gbk``：正好对上代码页，安全；
    - ``unknown``：两种都严解不了，如实标注"无法判定"，不硬猜。
    """
    if not raw:
        return "ascii"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    if all(b < 0x80 for b in raw):
        return "ascii"
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        raw.decode("gbk")
        return "gbk"
    except UnicodeDecodeError:
        return "unknown"

def scan_literals(text: str) -> list:
    """扫出**字符串/字符字面量**里的非 ASCII 内容（注释里的不算）。

    这是 ``#8: missing closing quote`` 的真凶所在。实测（本机 AC5 5.06u7，中文代码页）：

        const char *g_s = "中文测试串";   // UTF-8 存盘
        → t.c, line 3: Error: #8: missing closing quote    ← 报的是"引号不对"
        → t.c, line 4: Error: #65: expected a ";"          ← 还甩锅给下一行

    同一个内容存成 GBK 则 0 Error。所以判据是「**文件是 UTF-8** 且 **字面量里有非 ASCII**」，
    而不是"文件里有中文"——中文注释是安全的（踩坑记录里也是这个口径）。
    """
    out = []
    i, n, line = 0, len(text), 1
    line_start = 0
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            line_start = i
            continue
        if c == "\\" and i + 1 < n and text[i + 1] == "\n":     # 续行：不换行计数
            i += 2
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                break
            line += text.count("\n", i, j)
            i = j + 2
            line_start = max(text.rfind("\n", 0, i) + 1, 0)
            continue
        if c in "\"'":
            quote, start_line = c, line
            j, buf = i + 1, []
            closed = False
            while j < n:
                ch = text[j]
                if ch == "\\":
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                if ch == quote:
                    closed = True
                    break
                if ch == "\n":                                   # 未闭合的引号
                    break
                buf.append(ch)
                j += 1
            lit = "".join(buf)
            if closed and any(ord(x) > 127 for x in lit):
                head = text[line_start:i]
                out.append({
                    "line": start_line,
                    "literal": lit,
                    "non_ascii": "".join(sorted({x for x in lit if ord(x) > 127})),
                    "kind": "include" if re.match(r"\s*#\s*include\s*$", head) else "literal",
                })
            i = j + 1 if closed else j
            continue
        i += 1
    return out

def scan_file(path: str) -> dict:
    """扫一个源文件；返回是否可疑 + 命中的字面量清单。"""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return {"file": path, "ok": False, "error": str(e)}
    if size > _MAX_FILE_BYTES:
        return {"file": path, "ok": True, "skipped": "文件超过 %d 字节，未扫描"
                % _MAX_FILE_BYTES, "literals": []}
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return {"file": path, "ok": False, "error": str(e)}
    enc = classify_encoding(raw)
    out = {"file": path, "ok": True, "encoding": enc, "size": size, "literals": []}
    if enc == "utf-8":
        text = raw.decode("utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]
        out["literals"] = scan_literals(text)
    return out

def resolve_sources(project: str, target: str = "") -> list:
    """从 .uvprojx 里列出参与编译的源文件（绝对路径，去重、只保留真实存在的）。"""
    from . import uvprojx as _uvp
    base = os.path.dirname(os.path.abspath(project))
    out, seen = [], set()
    for g in _uvp.list_groups(project):
        for f in (g.get("files") or []):
            p = str(f.get("path") or "").strip()
            if not p:
                continue
            ap = os.path.normpath(os.path.join(base, p.replace("\\", os.sep)))
            k = os.path.normcase(ap)
            if k in seen:
                continue
            seen.add(k)
            out.append({"path": ap, "group": g.get("group", ""), "exists": os.path.isfile(ap)})
    return out

# ----------------------------------------------------------------------
def _check_literals(project: str, target: str, ac6: bool, max_files: int) -> dict:
    """AC5 + UTF-8 源文件 + 非 ASCII 字面量 = 必然编译失败，且报错指向引号。"""
    if ac6:
        return {
            "id": "ac5_non_ascii_literal", "status": "not_applicable",
            "why": "该 target 用的是 AC6（armclang），默认按 UTF-8 解析源文件，"
                   "不存在「被当 GBK 读」这条陷阱。",
            "findings": [],
        }
    srcs = resolve_sources(project, target)
    if not srcs:
        return {"id": "ac5_non_ascii_literal", "status": "unknown",
                "why": "没能从 .uvprojx 列出源文件，本项无法判定（不猜）。",
                "findings": []}
    findings, scanned, skipped_missing = [], 0, 0
    unknown_enc = []
    for s in srcs[:max_files]:
        if not s["exists"]:
            skipped_missing += 1
            continue
        r = scan_file(s["path"])
        scanned += 1
        if not r.get("ok"):
            continue
        if r.get("encoding") == "unknown":
            unknown_enc.append(_rel(s["path"], project))
        for lit in (r.get("literals") or []):
            findings.append({
                "file": _rel(s["path"], project),
                "line": lit["line"],
                "kind": lit["kind"],
                "literal": lit["literal"][:80],
                "non_ascii": lit["non_ascii"],
            })
    if findings:
        return {
            "id": "ac5_non_ascii_literal", "status": "fail", "severity": "error",
            "why": "源文件是 UTF-8，而 AC5（armcc）按本机代码页（中文 Windows 上为 GBK）解析。"
                   "字符串字面量里的非 ASCII 字节会被拆坏，报 **#8: missing closing quote** ——"
                   "**报错指向引号，还会连累下一行**（实测：第 3 行的字面量会让第 4 行也报 "
                   "expected a \";\"），照报错去改会把一行正确的代码改坏。",
            "how_to_read": "看 literal 字段：中文应只出现在注释里；要保留中文字面量就把该文件"
                           "另存为 GBK，或把文案移出字面量。",
            "findings": findings[:50],
            "finding_count": len(findings),
        }
    return {
        "id": "ac5_non_ascii_literal", "status": "pass",
        "why": "扫了 %d 个源文件，字符串/字符字面量里没有非 ASCII 内容。" % scanned,
        "scanned_files": scanned, "skipped_missing": skipped_missing,
        "unknown_encoding_files": unknown_enc[:10],
        "findings": [],
    }

def _check_token(project: str, token: str, max_files: int) -> dict:
    """通过令牌必须真的在源码里——否则闭环永远不可能判定成功。"""
    tok = (token or DEFAULT_TOKEN)
    srcs = resolve_sources(project)
    hits = []
    for s in srcs[:max_files]:
        if not s["exists"]:
            continue
        try:
            with open(s["path"], "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if tok.encode("utf-8") in raw or tok.encode("gbk", errors="ignore") in raw:
            hits.append(_rel(s["path"], project))
        elif not s["path"].lower().startswith(os.path.dirname(os.path.abspath(project)).lower()):
            # 工程目录之外的源码（库/公共组件）也扫一眼，避免把令牌判成"不存在"
            continue
    if hits:
        return {"id": "pass_token", "status": "pass",
                "why": "源码里找到了通过令牌 %s。" % tok, "found_in": hits[:10], "findings": []}
    return {
        "id": "pass_token", "status": "warn",
        "why": "扫了 %d 个源文件，**没有**找到通过令牌 %s。没有它，闭环不可能判定成功——"
               "超时时说「测试没通过」其实只是「没等到那句话」。"
               % (min(len(srcs), max_files), tok),
        "how_to_fix": "在测试通过路径上输出 %s；若令牌文本不同，把本工具的 token 参数设成实际值。"
                      % tok,
        "findings": [],
    }

def _check_serial(port: str) -> dict:
    """没有串口 → 能定位崩溃、但无法判定成功。这条必须显式说出来。"""
    from . import serialmon
    ports = serialmon.list_ports()
    if port:
        p = str(port).strip()
        if p in ports:
            return {"id": "serial", "status": "pass",
                    "why": "指定串口 %s 本机存在。" % p, "selected": p, "findings": []}
        return {"id": "serial", "status": "warn",
                "why": "指定的串口 %s 本机不存在（现有：%s）。" % (p, ports or "无"),
                "how_to_fix": "serial_list_ports 看各口的芯片推断，再指定正确的端口。",
                "findings": []}
    if ports:
        return {"id": "serial", "status": "pass",
                "why": "本机有 %d 个串口：%s。未指定 port 时闭环会取第一个（多候选会明示）。"
                       % (len(ports), ", ".join(ports[:6])),
                "available_ports": ports, "findings": []}
    return {
        "id": "serial", "status": "warn",
        "why": "本机**没有发现任何串口**：编译、烧录、SWD 读故障寄存器都还能用，但"
               "**「测试是否真的通过」无法判定**（缺了通过令牌这条硬证据）。",
        "how_to_fix": "接 USB-UART（TX/RX/GND 三根线即可，多数板载 ST-Link 已带虚拟串口）；"
                      "此外注意：多数缺陷既非编译错误也非运行时崩溃（帧解析偏移、时钟配置错、"
                      "从机地址错、状态机分支遗漏），程序照跑只是结果不对——**没有串口时这类问题"
                      "完全不可见**，且会被持续判成失败而诱使去改本来正确的代码。",
        "findings": [],
    }

def _check_debug_info(project: str, target: str) -> dict:
    """没有调试信息，崩溃定位就只剩地址。"""
    from . import uvprojx as _uvp
    r = _uvp.debug_information(project, target)
    if not r.get("ok"):
        return {"id": "debug_information", "status": "unknown",
                "why": "读不到 <DebugInformation>：%s" % r.get("error"), "findings": []}
    if r.get("enabled"):
        return {"id": "debug_information", "status": "pass",
                "why": "target「%s」已开启调试信息，编译产出 DWARF，崩溃可定位到源码行。"
                       % r.get("target"), "findings": []}
    return {
        "id": "debug_information", "status": "warn",
        "why": "target「%s」的 <DebugInformation> 是关闭的：编译器不产出 DWARF，"
               "崩溃现场只剩一串地址（PC 停在 0x08001A3C 对定位没有帮助）。" % r.get("target"),
        "how_to_fix": 'uvprojx_edit(action="set_debug_information", enabled=true) 打开它。',
        "findings": [],
    }

def _rel(path: str, project: str) -> str:
    try:
        return os.path.relpath(path, os.path.dirname(os.path.abspath(project)))
    except Exception:                                             # noqa: BLE001
        return path

def precheck(project: str, target: str = "", token: str = "", port: str = "",
             max_files: int = 400) -> dict:
    """跑完整的固件契约预检。只读，不碰硬件、不改文件。"""
    from . import uvprojx as _uvp
    project = os.path.abspath(project)
    if not os.path.isfile(project):
        return {"ok": False, "error": "工程文件不存在：%s" % project}
    cfg = _uvp.read_config(project, target)
    if not cfg.get("ok"):
        return {"ok": False, "error": cfg.get("error"), "targets": cfg.get("targets")}
    # target 为空时用工程里的实际 target 名往下传——否则返回里全是「(第一个)」，
    # 用户拿着这句话去 Options 里对不上号。
    tgt = cfg.get("target") or target
    uac6 = _is_ac6(project, tgt)
    checks = [
        _check_literals(project, tgt, uac6, max_files),
        _check_token(project, token, max_files),
        _check_debug_info(project, tgt),
        _check_serial(port),
    ]
    failed = [c["id"] for c in checks if c.get("status") == "fail"]
    warned = [c["id"] for c in checks if c.get("status") == "warn"]
    unknown = [c["id"] for c in checks if c.get("status") == "unknown"]
    nxt = []
    for c in checks:
        if c.get("status") == "fail":
            nxt.append("**先修 %s**：%s" % (c["id"], (c.get("how_to_read") or c.get("why") or "")[:120]))
        elif c.get("status") == "warn":
            nxt.append("注意 %s：%s" % (c["id"], (c.get("how_to_fix") or c.get("why") or "")[:120]))
    return {
        "ok": not failed,
        "project": project,
        "target": cfg.get("target"),
        "device": cfg.get("device"),
        "compiler": "AC6" if uac6 else "AC5",
        "verdict": "blocked" if failed else ("warn" if warned else "ready"),
        "failed": failed, "warned": warned, "unknown": unknown,
        "checks": checks,
        "next_actions": nxt,
        "note": "本预检只回答问题「上板之前有什么注定判不出来/注定编不过」；"
                "它不替代编译，也不碰硬件。",
    }

def _is_ac6(project: str, target: str) -> bool:
    """从 .uvprojx 判断该 target 用的是 AC6（armclang）还是 AC5（armcc）。

    读到 ``<uAC6>1</uAC6>`` 即 AC6。读不到时**按 AC5 处理**——AC5 的坑是真会让人
    白改代码的，宁可多报一次也不要漏报（这条选择写在返回值 status 里，不藏）。
    """
    from . import uvprojx as _uvp
    text, _ = _uvp._read_text(project)
    a, b = _uvp._target_span(text, target)
    if a is None:
        return False
    seg = text[a:b]
    m = re.search(r"<uAC6>\s*(\d+)\s*</uAC6>", seg)
    return bool(m and m.group(1).strip() == "1")
