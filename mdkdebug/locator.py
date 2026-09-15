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

    def search_symbols(self, query: str = "", limit: int = 50, kind: str = "all"):
        """从 .axf ELF 符号表模糊检索符号（函数 / 对象），供 find_symbol 使用。

        query 为空则列出全部；kind 取 all/func/object/global/local。
        仅返回地址非零、类型为 func/object 的符号，过滤 .debug 伪符号；按地址排序。
        """
        self._ensure_loaded()
        try:
            with open(self.axf_path, "rb") as f:
                elf = ELFFile(f)
                sec = elf.get_section_by_name(".symtab")
                if sec is None:
                    sec = elf.get_section_by_name(".dynsym")
                if sec is None:
                    return []
                q = (query or "").lower()
                out = []
                for sym in sec.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    if q and q not in name.lower():
                        continue
                    addr = sym.entry["st_value"]
                    if addr == 0:
                        continue
                    st = sym.entry["st_info"]
                    # pyelftools 的 bind/type 是名字字符串（如 STT_FUNC / STB_GLOBAL），st_info 为 Container
                    stype = str(st["type"])
                    bind = str(st["bind"])
                    tname = stype.replace("STT_", "").lower()  # func / object / notype ...
                    bname = bind.replace("STB_", "").lower()   # global / local / weak
                    if tname not in ("func", "object"):
                        continue
                    if kind == "func" and tname != "func":
                        continue
                    if kind == "object" and tname != "object":
                        continue
                    if kind in ("global", "local") and bname != kind:
                        continue
                    out.append({
                        "name": name,
                        "type": tname,
                        "bind": bname,
                        "addr": "0x%08x" % addr,
                        "size": sym.entry.get("st_size", 0),
                    })
                out.sort(key=lambda s: int(s["addr"], 16))
                return out[:limit]
        except Exception as e:  # noqa: BLE001
            logger.warning("读取 .axf 符号表失败: %s", e)
            return []

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


    # ------------------------------------------------------------------
    # 完整调用栈辅助 / 局部变量 / 漂移检测 / 代码地址判断
    # ------------------------------------------------------------------
    @staticmethod
    def is_code_address(addr: int) -> bool:
        """判断地址是否落在 FLASH 代码段（真实 PC / 返回地址所在区段）。"""
        return 0x08000000 <= addr <= 0x081FFFFF

    @property
    def axf_mtime(self):
        """.axf 文件最后修改时间（用于检测源码漂移）。"""
        try:
            return os.path.getmtime(self.axf_path)
        except OSError:
            return None

    def source_stale(self, file: str):
        """定位文件是否比 .axf 新（源码已改但未重编译）。返回 (bool, 绝对路径)。"""
        if not file or file == "?":
            return False, None
        mt = self.axf_mtime
        if mt is None:
            return False, None
        path = self.resolve_source_path(file)
        if not path:
            return False, None
        try:
            return os.path.getmtime(path) > mt, path
        except OSError:
            return False, None

    def local_variables(self, pc: int):
        """返回包含 pc 的函数内的 参数+局部变量名 列表（含嵌套块/内联函数）。

        供调试时在当前上下文用 calc_expression 逐个求值。未定位到函数或无 .axf 返回 None。
        """
        self._ensure_loaded()
        try:
            with open(self.axf_path, "rb") as f:
                elf = ELFFile(f)
                if not elf.has_dwarf_info():
                    return None
                di = elf.get_dwarf_info()
                all_names: list = []
                for cu in di.iter_CUs():
                    top = cu.get_top_DIE()
                    for die in top.iter_children():
                        if die.tag != "DW_TAG_subprogram":
                            continue
                        lo = die.attributes.get("DW_AT_low_pc")
                        if lo is None:
                            continue
                        low = lo.value
                        hi = die.attributes.get("DW_AT_high_pc")
                        if hi is None:
                            continue
                        high = hi.value if hi.form == "DW_FORM_addr" else low + hi.value
                        # 寄存器 PC 为去 Thumb bit 的值(如 0x8000d00)，而 DIE low_pc 常带 bit0(1)，
                        # 故同时用 pc 与 pc|1 匹配范围，避免误判不在函数内
                        if not (low <= pc <= high or low <= (pc | 1) <= high):
                            continue
                        self._collect_die_vars(die, all_names)
                # 多个匹配 DIE(声明/内联/范围重叠)可能各自收集部分变量，合并去重保序
                seen: set = set()
                uniq = [n for n in all_names if not (n in seen or seen.add(n))]
                return uniq or None
        except Exception as e:  # noqa: BLE001
            logger.warning("解析局部变量失败: %s", e)
            return None

    def _collect_die_vars(self, die, names: list) -> None:
        """递归收集 DIE 及其子块（lexical_block/内联）的参数与局部变量名。"""
        for c in die.iter_children():
            if c.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
                nm = c.attributes.get("DW_AT_name")
                if nm is not None:
                    name = _decode_name(nm.value)
                    if name and name not in names:
                        names.append(name)
            if c.tag in ("DW_TAG_lexical_block", "DW_TAG_subprogram",
                         "DW_TAG_inlined_subroutine", "DW_TAG_catch_block"):
                self._collect_die_vars(c, names)

    # --------------------------------------------------------------
    # 结构体字段概览：按变量名解析 DWARF 结构体/联合体成员布局
    # --------------------------------------------------------------
    def _ref_die(self, die, attr_name: str):
        """返回 die 的引用类属性 attr_name（如 'DW_AT_type'）指向的 DIE。

        用 pyelftools 的 get_DIE_from_attribute(name)，其按 form 正确区分
        DW_FORM_ref4（CU 内偏移，需加 cu_offset）与 DW_FORM_ref_addr（绝对偏移），
        避免直接 get_DIE_from_refaddr 漏加偏移导致 typedef 被错解成 unsigned int。
        """
        if die is None or not attr_name:
            return None
        try:
            return die.get_DIE_from_attribute(attr_name)
        except Exception as e:  # noqa: BLE001
            logger.debug("解析类型引用失败 %s: %s", attr_name, e)
            return None

    def _type_info(self, dwarfinfo, die, depth: int = 0):
        """从类型 DIE 提取 {type_name, kind, size}，处理 typedef/const/volatile 解引用。"""
        if die is None or depth > 8:
            return {"type_name": "?", "kind": None, "size": None}
        tag = die.tag
        nm = die.attributes.get("DW_AT_name")
        name = _decode_name(nm.value) if nm is not None else None
        size = die.attributes.get("DW_AT_byte_size")
        sz = size.value if size is not None else None
        # 解引用类型修饰（typedef/const/volatile/restrict/pointer 指向的引用）
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type",
                   "DW_TAG_volatile_type", "DW_TAG_restrict_type",
                   "DW_TAG_reference_type"):
            t = die.attributes.get("DW_AT_type")
            inner = self._type_info(dwarfinfo, self._ref_die(die, "DW_AT_type") if t else None,
                                    depth + 1)
            return {"type_name": name or inner.get("type_name"),
                    "kind": inner.get("kind"), "size": sz or inner.get("size")}
        # 指针固定 4 字节（Cortex-M 32 位）
        if tag == "DW_TAG_pointer_type":
            return {"type_name": (name or "*") + "*", "kind": "pointer", "size": 4}
        # 数组/结构体/联合体若无显式 byte_size，尝试从数组维度/成员推断
        if sz is None:
            if tag == "DW_TAG_array_type":
                et = die.attributes.get("DW_AT_type")
                elem = self._type_info(dwarfinfo, self._ref_die(die, "DW_AT_type") if et else None,
                                       depth + 1)
                count = 1
                for sub in die.iter_children():
                    if sub.tag == "DW_TAG_subrange_type":
                        ub = sub.attributes.get("DW_AT_upper_bound")
                        lo = sub.attributes.get("DW_AT_lower_bound")
                        lo_v = lo.value if lo is not None else 0
                        if ub is not None:
                            try:
                                count *= (int(ub.value) - int(lo_v) + 1)
                            except (TypeError, ValueError):
                                pass
                if elem.get("size"):
                    sz = elem["size"] * max(1, count)
        return {"type_name": name or tag.replace("DW_TAG_", ""),
                "kind": tag.replace("DW_TAG_", ""), "size": sz}

    def struct_members(self, var_name: str):
        """按变量名解析其 DWARF 结构体/联合体类型与成员布局。

        返回 {type, size_bytes, fields:[{name, offset, type, size}]}；
        变量不存在 / 非结构体 / 无 DWARF 返回 None。供 server.read_struct 按偏移读各成员。
        变量可为全局变量、局部变量或形式参数。DWARF 中同名符号可能有多个（如局部结构体变量与同名指针参数），
        故对每个同名变量逐个尝试，取第一个能解到结构体的。
        """
        self._ensure_loaded()
        try:
            with open(self.axf_path, "rb") as f:
                elf = ELFFile(f)
                if not elf.has_dwarf_info():
                    return None
                dwarfinfo = elf.get_dwarf_info()
                for cu in dwarfinfo.iter_CUs():
                    for type_die in self._iter_var_type_dies(dwarfinfo, cu.get_top_DIE(), var_name):
                        desc = self._describe_struct(dwarfinfo, type_die)
                        if desc is not None:
                            return desc
        except Exception as e:  # noqa: BLE001
            logger.warning("解析结构体成员失败 %s: %s", var_name, e)
        return None

    def _iter_var_type_dies(self, dwarfinfo, die, var_name: str, depth: int = 0):
        """生成器：递归产出名为 var_name 的变量/参数的类型 DIE（同名可能有多个）。"""
        if depth > 300:
            return
        nm = die.attributes.get("DW_AT_name")
        if die.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter") and nm is not None \
                and _decode_name(nm.value) == var_name:
            t = die.attributes.get("DW_AT_type")
            if t is not None:
                yield self._ref_die(die, "DW_AT_type")
        for c in die.iter_children():
            yield from self._iter_var_type_dies(dwarfinfo, c, var_name, depth + 1)

    def _describe_struct(self, dwarfinfo, type_die):
        """解析结构体/联合体 DIE 的成员布局。"""
        if type_die is None:
            return None
        # typedef 指向的实际结构体
        while type_die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            t = type_die.attributes.get("DW_AT_type")
            if t is None:
                break
            nxt = self._ref_die(type_die, "DW_AT_type")
            if nxt is None:
                break
            type_die = nxt
        if type_die is None or type_die.tag not in ("DW_TAG_structure_type", "DW_TAG_union_type",
                                                    "DW_TAG_class_type"):
            return None
        nm = type_die.attributes.get("DW_AT_name")
        sz = type_die.attributes.get("DW_AT_byte_size")
        fields = []
        for m in type_die.iter_children():
            if m.tag != "DW_TAG_member":
                continue
            mname = m.attributes.get("DW_AT_name")
            mt = m.attributes.get("DW_AT_type")
            loc = m.attributes.get("DW_AT_data_member_location")
            # data_member_location 可能是常量(字节偏移)或表达式(简化为取常量)
            off = 0
            if loc is not None:
                lv = loc.value
                off = int(lv) if isinstance(lv, (int, float)) else 0
            mtype_die = self._ref_die(m, "DW_AT_type") if mt else None
            tinfo = self._type_info(dwarfinfo, mtype_die) if mtype_die else {}
            fields.append({
                "name": _decode_name(mname.value) if mname is not None else "?",
                "offset": off,
                "type": tinfo.get("type_name", "?"),
                "size": tinfo.get("size"),
            })
        return {
            "type": _decode_name(nm.value) if nm is not None else "struct",
            "size_bytes": sz.value if sz is not None else None,
            "fields": fields,
        }
