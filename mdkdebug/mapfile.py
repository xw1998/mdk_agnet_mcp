# -*- coding: utf-8 -*-
"""
mapfile —— 解析 Keil/ARMCC 生成的 .map 链接映射文件。

从 .map 文本中提取：内存布局段（section placement）、全局/局部符号表、
程序大小（Code/RO/RW/ZI）、栈使用（若开启）、未用段（Unused section）。
供 AI 排查 ROM/RAM 占用、函数大小、栈溢出、Flash 超限等问题——这些信息
原本要人工翻 map 文件，现在可结构化为机器可读结果。

兼容 ARMCC5(armcc) 与 ARMCLANG(ac6) 生成的常见 map 格式；解析不到的字段
给出原始相关片段，不因个别差异而整体失败。
"""
from __future__ import annotations

import re

# ---- 分段锚点 ----
_SECTION_ANCHOR = "section placement"      # 段放置表（ARMCC5/AC6 旧格式）
_EXECREGION_ANCHOR = "Execution Region"     # 段放置表（标准 Keil 格式）
_MEMORYMAP_ANCHOR = "Memory Map of the image"  # 内存图（符号表结束）
_SYMBOL_ANCHOR = "Image Symbol Table"      # 符号表
_COMPONENT_ANCHOR = "Image component sizes"  # 组件大小（符号表结束）
_STACK_ANCHOR = "Stack Usage"              # 栈使用（可选）
_UNUSED_ANCHOR = "Unused section"          # 未用段（可选）
_TOTAL_ANCHOR = "Grand Totals"             # 汇总（可选）

# 段放置行：Base Size Type Attr Idx Section Object
_RE_SECTION = re.compile(
    r"^\s*(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+"
    r"(\w+)\s+(\w+)\s+\d+\s+\S+\s*(.+?)\s*$"
)
# 段放置行（Execution Region）：Exec Addr Load Addr Size Type Attr Idx E Section Object
_RE_EXECREGION = re.compile(
    r"^\s*(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+|-)\s+(0x[0-9A-Fa-f]+)\s+"
    r"(\w+)\s+(\w+)\s+(\d+)\s+(.{0,2})\s+(.+?)\s*$"
)
# 符号行：Name  Value  Ov  Size  Object(Section)   （Ov 为 Section/Number 文本）
_RE_SYMBOL = re.compile(
    r"^\s*(\S+(?:\s+\S+)*?)\s{2,}(0x[0-9A-Fa-f]+)\s+"
    r"(\S+)\s+(\d+)\s+(.+?)\s*$"
)
# 程序大小行：Program Size: Code=.. RO-data=.. RW-data=.. ZI-data=..
_RE_PROGSIZE = re.compile(
    r"(?:Code|RO|RW|ZI)[- ]?\w*\s*=\s*(\d+)", re.IGNORECASE
)
# 栈使用行： FuncName  bytes
_RE_STACK = re.compile(r"^\s*(\S+)\s+(\d+)\s*$")


def _lines_until(text: str, stop_anchor: str):
    """返回从 text 起，到 stop_anchor 出现前的行列表（含 stop 之前）。"""
    lines = text.splitlines()
    out = []
    for ln in lines:
        if stop_anchor and stop_anchor in ln:
            break
        out.append(ln)
    return out


def _parse_program_size(text: str) -> dict:
    """在文本中查找 'Program Size: Code=.. RO-data=.. RW-data=.. ZI-data=..'。"""
    m = re.search(r"Program Size:\s*(.*)", text)
    if not m:
        return {}
    seg = m.group(1)
    labels = {"Code": "code", "RO-data": "ro", "RO Data": "ro", "RO": "ro",
              "RW-data": "rw", "RW Data": "rw", "RW": "rw",
              "ZI-data": "zi", "ZI Data": "zi", "ZI": "zi"}
    out: dict = {}
    for label, key in labels.items():
        mm = re.search(rf"{label}\s*=\s*(\d+)", seg)
        if mm:
            out[key] = int(mm.group(1))
    return out


def parse_map_text(text: str) -> dict:
    """解析 .map 文本，返回结构化字典。"""
    if not text:
        return {"ok": False, "error": "map 内容为空"}
    result: dict = {"ok": True}

    # ---- 程序大小 ----
    ps = _parse_program_size(text)
    if ps:
        result["program_size"] = ps
        total = sum(ps.values())
        result["program_size_total"] = total

    # ---- 段放置：优先标准 Keil Execution Region，回退 ARMCC 旧 section placement ----
    sections = []
    eri = text.find(_EXECREGION_ANCHOR)
    if eri >= 0:
        for ln in _lines_until(text[eri:], _COMPONENT_ANCHOR):
            m = _RE_EXECREGION.match(ln)
            if not m:
                continue
            rest = m.group(8).strip()
            parts = rest.rsplit(None, 1)
            if len(parts) == 2 and any(k in parts[1] for k in (".o", ".a", ".lib")):
                sec_name, obj = parts[0], parts[1]
            else:
                sec_name, obj = rest, ""
            sections.append({
                "exec": m.group(1),
                "base": int(m.group(1), 16),
                "base_hex": m.group(1),
                "load": m.group(2),
                "size": int(m.group(3), 16),
                "size_hex": m.group(3),
                "type": m.group(4),
                "attr": m.group(5),
                "section": sec_name,
                "object": obj,
            })
    if not sections:
        si = text.find(_SECTION_ANCHOR)
        if si >= 0:
            for ln in _lines_until(text[si:], _COMPONENT_ANCHOR):
                m = _RE_SECTION.match(ln)
                if m:
                    sections.append({
                        "base": int(m.group(1), 16),
                        "base_hex": m.group(1),
                        "size": int(m.group(2), 16),
                        "size_hex": m.group(2),
                        "type": m.group(3),
                        "attr": m.group(4),
                        "object": m.group(5).strip(),
                    })
    result["sections"] = sections
    result["section_count"] = len(sections)

    # ---- 符号表（Image Symbol Table 段，止于 Memory Map 表） ----
    symbols = []
    sy = text.find(_SYMBOL_ANCHOR)
    if sy >= 0:
        body = _lines_until(text[sy:], _MEMORYMAP_ANCHOR)
        for ln in body:
            m = _RE_SYMBOL.match(ln)
            if m and m.group(1) and m.group(2):
                symbols.append({
                    "name": m.group(1).strip(),
                    "addr": int(m.group(2), 16),
                    "addr_hex": m.group(2),
                    "ov": m.group(3),
                    "size": m.group(4),
                    "object": m.group(5).strip(),
                })
    result["symbols"] = symbols
    result["symbol_count"] = len(symbols)

    # ---- 栈使用（可选） ----
    stack = []
    st = text.find(_STACK_ANCHOR)
    if st >= 0:
        for ln in _lines_until(text[st:], _UNUSED_ANCHOR)[1:]:
            m = _RE_STACK.match(ln)
            if m:
                stack.append({"function": m.group(1), "bytes": int(m.group(2))})
    if stack:
        result["stack_usage"] = stack

    # ---- 未用段（可选） ----
    unused = []
    un = text.find(_UNUSED_ANCHOR)
    if un >= 0:
        for ln in _lines_until(text[un:], _TOTAL_ANCHOR)[1:]:
            s = ln.strip()
            if s:
                unused.append(s)
    if unused:
        result["unused_sections"] = unused

    return result


def parse_map_file(path: str) -> dict:
    """读取并解析 .map 文件。路径不存在/读取失败返回错误。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return {"ok": False, "error": f"读取 map 文件失败: {e}", "path": path}
    return parse_map_text(text)
