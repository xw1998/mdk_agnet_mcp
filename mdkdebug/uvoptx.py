# -*- coding: utf-8 -*-
"""Keil .uvoptx 工程选项文件：读取 / 清理持久化断点。

背景
----
Keil uVision 在调试会话中会把断点**持久化**写入工程同目录的 ``<工程名>.uvoptx``
（纯 XML）。结构为::

    <Breakpoint>
      <Bp>
        <Number>0</Number>
        <Type>0</Type>
        <LineNumber>161</LineNumber>
        <EnabledFlag>1</EnabledFlag>
        <Address>134219356</Address>       <!-- 十进制 -->
        <BreakByAccess>0</BreakByAccess>
        <BreakIfRCount>1</BreakIfRCount>
        <Filename>...\\stm32f4xx_hal.c</Filename>
        <ExecCommand></ExecCommand>
        <Expression>\\\\proj\\../Src/stm32f4xx_hal.c\\161</Expression>
      </Bp>
      ...
    </Breakpoint>

这类断点会在**下次进入调试时被 Keil 自动恢复**，而命令窗口 ``BK`` 只影响当前会话，
因此会出现"``clear_breakpoint``/``clear_all_breakpoints`` 返回成功、断点却依然生效"的
顽固残留（本工具"清不掉断点"的根因）。本模块提供不依赖 UVSOCK 的解析与清理能力。

设计要点
--------
- **编码容错**：uvoptx 正常为 UTF-8（XML 声明亦为 UTF-8）；个别环境可能为 GBK/ANSI，
  读取时依次尝试 utf-8 → gbk → latin-1，写回沿用探测到的编码，绝不擅自转码。
- **文本级清理**：不用 XML 序列化器重写整个文件（会丢失缩进/节点顺序/注释），
  只在 ``<Breakpoint>…</Breakpoint>`` 区间内删除 ``<Bp>…</Bp>`` 块，其余原样保留。
- **留备份**：清理前默认备份为 ``<name>.uvoptx.mdkdebug.bak``。
- **Keil 运行时回写**：Keil 打开工程时会用内存中的断点覆盖 uvoptx，故清理应在
  Keil 关闭（或先 ``close_uvision``）后执行；调用方需提示用户。
"""
from __future__ import annotations

import os
import re
import shutil
import xml.etree.ElementTree as ET

# ``<Breakpoint>…</Breakpoint>`` 块与其中的 ``<Bp>…</Bp>`` 断点条目
_BP_BLOCK_RE = re.compile(r"(<Breakpoint>)(.*?)(</Breakpoint>)", re.DOTALL)
_BP_ITEM_RE = re.compile(r"[ \t]*<Bp>.*?</Bp>[ \t]*\r?\n?", re.DOTALL)


def uvoptx_path_for(project: str) -> str:
    """由 .uvprojx / .uvoptx 路径推导出 .uvoptx 路径（同目录同名）。"""
    p = (project or "").strip()
    if not p:
        return ""
    low = p.lower()
    if low.endswith(".uvoptx"):
        return p
    if low.endswith(".uvprojx"):
        return p[:-len(".uvprojx")] + ".uvoptx"
    # 非工程文件：按同名前缀尝试
    return p + ".uvoptx"


def _read_text(path: str) -> tuple[str, str]:
    """编码容错读取，返回 (文本, 实际编码)。"""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"


def _text_of(bp: ET.Element, tag: str) -> str:
    el = bp.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def parse_uvoptx_breakpoints(path: str) -> list:
    """解析 uvoptx 中的持久化断点，返回结构化列表（文件不存在/无断点返回 []）。

    每项：{number, type, address(int), address_hex, line, filename, expression,
           enabled(bool), break_by_access, break_if_rcount}
    """
    if not path or not os.path.isfile(path):
        return []
    text, _ = _read_text(path)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for block in root.iter("Breakpoint"):
        for bp in block.findall("Bp"):
            addr_s = _text_of(bp, "Address")
            try:
                addr = int(addr_s)
            except (TypeError, ValueError):
                addr = None
            line_s = _text_of(bp, "LineNumber")
            try:
                line = int(line_s)
            except (TypeError, ValueError):
                line = None
            out.append({
                "number": _text_of(bp, "Number"),
                "type": _text_of(bp, "Type"),
                "address": addr,
                "address_hex": (hex(addr) if isinstance(addr, int) else None),
                "line": line,
                "filename": _text_of(bp, "Filename"),
                "expression": _text_of(bp, "Expression"),
                "enabled": _text_of(bp, "EnabledFlag") == "1",
                "break_by_access": _text_of(bp, "BreakByAccess"),
                "break_if_rcount": _text_of(bp, "BreakIfRCount"),
            })
    return out


def clear_uvoptx_breakpoints(path: str, backup: bool = True) -> dict:
    """删除 uvoptx 中 ``<Breakpoint>`` 下的全部 ``<Bp>`` 条目（保留空节点与其余内容）。

    返回 {ok, removed, removed_items, backup, encoding, changed, error}。
    """
    res = {"ok": False, "removed": 0, "removed_items": [], "backup": None,
           "encoding": None, "changed": False, "error": None}
    if not path or not os.path.isfile(path):
        res["error"] = f"uvoptx 文件不存在: {path}"
        return res
    try:
        text, enc = _read_text(path)
        res["encoding"] = enc
        res["removed_items"] = parse_uvoptx_breakpoints(path)

        def _strip_block(m: re.Match) -> str:
            head, body, tail = m.group(1), m.group(2), m.group(3)
            new_body, n = _BP_ITEM_RE.subn("", body)
            # 记录清除数量（挂到闭包）
            _strip_block.removed += n  # type: ignore[attr-defined]
            return head + new_body + tail

        _strip_block.removed = 0  # type: ignore[attr-defined]
        new_text = _BP_BLOCK_RE.sub(_strip_block, text)

        # 兜底：若文件无 <Breakpoint> 块（异常格式），不做修改
        n_removed = int(getattr(_strip_block, "removed", 0))
        res["removed"] = n_removed
        if n_removed == 0:
            res["ok"] = True
            return res

        if backup:
            bak = path + ".mdkdebug.bak"
            shutil.copy2(path, bak)
            res["backup"] = bak
        with open(path, "w", encoding=enc, newline="") as f:
            f.write(new_text)
        res["ok"] = True
        res["changed"] = True
        return res
    except Exception as e:  # noqa: BLE001
        res["error"] = str(e)
        return res
