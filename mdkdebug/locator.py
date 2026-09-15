"""符号定位模块：基于 .axf(DWARF) 将程序地址映射到 源文件:行号，并可读取源码上下文。

mdkdebug 用 UVSOCK 读到 CPU 的 PC/LR 后，经本模块可定位到"停在哪、看的是什么代码"，
让 AI 像人一样了解当前调试位置。同时支持 源文件:行号 -> 地址 反向映射，供 run_to_line 使用。
"""
from __future__ import annotations

import os
import bisect
import logging
from typing import Optional

from elftools.elf.elffile import ELFFile  # pyelftools

logger = logging.getLogger(__name__)


def _decode_name(b) -> str:
    """DWARF 文件名可能是 bytes，统一解码为 str。"""
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace")
    return str(b)


class Locator:
    """封装 .axf 的 DWARF 行号表，提供 地址<->文件:行 双向定位与源码读取。

    project_dir 为 uvprojx 所在目录；DWARF 中的源路径（如 ../Core/Src/main.c）
    是相对该目录的，据此定位实际源文件。
    """

    def __init__(self, axf_path: str, project_dir: Optional[str] = None):
        self.axf_path = os.path.abspath(axf_path)
        self.project_dir = os.path.abspath(project_dir) if project_dir else self._infer_project_dir()
        self._rows: list = []  # 有序 [(addr, file, line)]
        self._loaded = False

    def _infer_project_dir(self) -> str:
        # axf 通常在 <uvprojx目录>/<OutputDirectory>/<OutputName>.axf
        d1 = os.path.dirname(self.axf_path)      # <OutputDirectory>
        d2 = os.path.dirname(d1)                 # <uvprojx目录>
        return d2 or d1

    def _load(self) -> None:
        if self._loaded:
            return
        rows: list = []
        try:
            with open(self.axf_path, "rb") as f:
                elf = ELFFile(f)
                if not elf.has_dwarf_info():
                    logger.warning("%s 无 DWARF 调试信息", self.axf_path)
                    self._loaded = True
                    return
                di = elf.get_dwarf_info()
                for cu in di.iter_CUs():
                    try:
                        lp = di.line_program_for_CU(cu)
                    except Exception as e:  # noqa: BLE001
                        logger.debug("跳过 CU 行号程序: %s", e)
                        continue
                    if lp is None:
                        continue
                    fe = lp.header["file_entry"]
                    for entry in lp.get_entries():
                        st = entry.state
                        if st is None or st.address is None:
                            continue
                        fname = "?"
                        if st.file and st.file <= len(fe) and fe[st.file - 1]:
                            fname = _decode_name(fe[st.file - 1].name)
                        rows.append((st.address, fname, st.line))
        except Exception as e:  # noqa: BLE001
            logger.warning("解析 .axf 失败: %s", e)
        rows.sort(key=lambda r: (r[0], r[2]))
        self._rows = rows
        self._loaded = True
        logger.info("Locator 加载 %d 条行号条目（%s）", len(rows), self.axf_path)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load()

    def is_ready(self) -> bool:
        self._ensure_loaded()
        return bool(self._rows)

    def total_entries(self) -> int:
        self._ensure_loaded()
        return len(self._rows)

    def addr_to_location(self, addr: int):
        """地址 -> {file, line}（取 <=addr 的最近行条目）。"""
        self._ensure_loaded()
        if not self._rows:
            return None
        idx = bisect.bisect_right(self._rows, (addr, "\uffff", 10**9)) - 1
        if idx < 0:
            return None
        a, f, l = self._rows[idx]
        return {"address": a, "file": f, "line": l}

    def line_to_addr(self, file: str, line: int):
        """源文件:行号 -> 地址（反向最近匹配）。file 可按 basename 或路径匹配。"""
        self._ensure_loaded()
        if not self._rows:
            return None
        want_base = os.path.basename(file.replace("\\", "/")).lower()
        want_norm = os.path.normpath(file.replace("\\", "/")).lower()
        best = None  # (距离, 地址)
        for a, f, l in self._rows:
            if l > line:
                continue
            f_low = f.lower()
            if not (os.path.basename(f_low) == want_base
                    or os.path.normpath(f_low.replace("\\", "/")).lower() == want_norm
                    or f_low.endswith(want_norm)):
                continue
            if best is None or (line - l) < best[0]:
                best = ((line - l), a)
        return best[1] if best else None

    def resolve_source_path(self, file: str):
        """把 DWARF 相对路径（如 ../Core/Src/main.c）定位到实际源文件。"""
        if not file or file == "?":
            return None
        norm = file.replace("\\", "/")
        cand = os.path.normpath(os.path.join(self.project_dir, norm))
        if os.path.isfile(cand):
            return cand
        base = os.path.basename(norm)
        for root, _dirs, files in os.walk(self.project_dir):
            if base in files:
                return os.path.join(root, base)
        return None

    def read_source(self, file: str, line: int, context: int = 4):
        """读取指定文件某行及上下文源码。返回 {file, display_path, line, source:[{lineno,code}]}。"""
        path = self.resolve_source_path(file)
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except Exception as e:  # noqa: BLE001
            logger.warning("读取源码失败 %s: %s", path, e)
            return None
        if line < 1 or line > len(lines):
            return None
        start = max(1, line - context)
        end = min(len(lines), line + context)
        source = [
            {"lineno": i, "code": lines[i - 1].rstrip()}
            for i in range(start, end + 1)
        ]
        rel = os.path.relpath(path, self.project_dir).replace("\\", "/")
        return {
            "file": rel,
            "display_path": path,
            "line": line,
            "source": source,
        }
