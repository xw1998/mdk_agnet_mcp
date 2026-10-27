# -*- coding: utf-8 -*-
"""导出文件的统一写入口径：**无 BOM 的 UTF-8**。

真机反馈：`l2_ledger.csv` 的首列表头是 `'\ufeffaddr'`，下游按 `addr` 取列取不到，
必须先按 `utf-8-sig` 读。带 BOM 的 CSV 对 Excel 友好、对其它程序全是噪声，而本服务的
产物是给**程序**（和 AI）读的证据，所以统一无 BOM：

- `write_text()`：`encoding="utf-8"`、`newline="\n"`、不写 BOM；
- `csv_text()` / `write_csv()`：同一个 `csv.writer` 口径（`lineterminator="\\n"`），
  表头与行都不带 BOM；
- `has_bom()`：读回校验用（自证真的没写 BOM）。
"""

from __future__ import annotations

import csv
import io
import os

BOM = b"\xef\xbb\xbf"


def csv_text(header, rows) -> str:
    """拼 CSV 文本（`\\n` 行尾、无 BOM、不做平台相关换行）。"""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(list(header))
    w.writerows(rows or [])
    return buf.getvalue()


def write_text(path: str, text: str, *, exclusive: bool = False) -> int:
    """按「无 BOM UTF-8」写文本，返回字节数。"""
    data = text.encode("utf-8")
    full = os.path.abspath(path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(full, "xb" if exclusive else "wb") as fh:
        fh.write(data)
    return len(data)


def write_csv(path: str, header, rows, *, exclusive: bool = False) -> int:
    return write_text(path, csv_text(header, rows), exclusive=exclusive)


def has_bom(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(3) == BOM
    except OSError:
        return False
