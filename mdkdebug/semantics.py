# -*- coding: utf-8 -*-
"""语义层（批次102）：字符串/数据池、死代码、数据表。

这三个能力都靠**同一件事**成立：能把「这个地址有没有被人用过」说清楚。

  * :func:`strings` —— 不只是「这串字节可打印」，而是「它被字面量池/指令引用了吗」，
    并给出字符集（ASCII / GBK）、边界（NUL 终止 / 落在段首尾）、分类（格式串 / 路径 /
    AT 指令 / 诊断文案）。三重过滤的每一重都**记下判据**，被丢掉的也报数——这样
    「2820 条假阳性收敛到 218 条」就是一个可以复核的过程，而不是一句保证。
  * :func:`deadcode` —— 从根（向量表 / 入口 / 全局符号）做可达性，再给「无任何引用」
    的区间。判词是 ``unreferenced``（静态无引用）而不是「死代码」：间接调用解析不了、
    自修改代码、外部中断向量都可能让它在运行期被用到。
  * :func:`datatable` —— 把定长结构导成带字段名的 C 数组，并且**回读自证**：
    生成的 C 文本再解析回来，与字节逐个比对，对不上就报错而不是给一份看着对的表。

设计口径（与批次101 一致）：产物是**证据**；写盘走 :mod:`mdkdebug.textio`（无 BOM），
写盘前过 :mod:`mdkdebug.evidence` 的护栏；所有结论带 ``confidence`` / ``basis``。
"""
import os
import re

from . import evidence as _evidence
from . import recover as _recover
from . import reveng as _reveng
from . import rtypes as _rtypes
from . import textio as _textio

MAX_STRINGS = 4000
MAX_RANGES = 400

# ----------------------------------------------------------------------
# 公用：打开镜像 + 做一次深度扫描
# ----------------------------------------------------------------------
def _open(path: str, base: int = 0, *, deep: bool = True,
          max_functions: int = 20000, max_insns: int = 600000):
    """返回 ``(unit, insns, funcs, xrefs, gaps)``。失败时第二个元素是错误 dict。"""
    an = _recover.analyze(path, base=base, deep=deep,
                          max_functions=max_functions, max_insns=max_insns)
    if not an.get("ok"):
        return None, None, None, None, an
    unit = an.pop("_unit")
    rec = an.pop("_recover")
    insns = rec.get("_insns") or {}
    funcs = rec.get("functions") or []
    rel = rec.get("_relations") or {}
    gaps = list(an.get("gaps") or [])
    return unit, insns, funcs, rel, gaps


def _data_spans(unit):
    """非可执行区间（只读数据/参数区）。IROM 混装时这里会是空表——不猜。"""
    out = []
    for start, end, _off in unit.spans:
        cur = start
        for a, b in unit.code_ranges:
            if b <= cur or a >= end:
                continue
            if a > cur:
                out.append((cur, min(a, end)))
            cur = max(cur, b)
        if cur < end:
            out.append((cur, end))
    return out


# ======================================================================
# 一、字符串 / 数据池语义
# ======================================================================
_CLASS_RULES = [
    ("format", re.compile(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diuoxXfFeEgGaAcspn%]")),
    ("at_command", re.compile(r"^AT(?:[+#$%&]|[+\-]?\w*$)")),
    ("url", re.compile(r"^(?:https?|ftp)://", re.I)),
    ("path", re.compile(r"^(?:[A-Za-z]:[\\/]|\.{0,2}[\\/])|\.(?:bin|txt|csv|log|ini|cfg|json|axf|hex|dat|db)$", re.I)),
    ("version", re.compile(r"\bv?\d+\.\d+\.\d+(?:[-+]\w+)?\b")),
    ("mac_addr", re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")),
]
_DIAG_WORDS = ("error", "err", "fail", "invalid", "timeout", "denied", "abort",
               "not found", "unsupported", "overflow", "ok", "done", "busy",
               "失败", "错误", "无效", "超时", "成功", "忙", "异常", "越界")
_CJK = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")


def classify(text: str) -> dict:
    """给一条字符串分类。**多条命中就多条**——一个带中文的格式串既是 format 也是 cjk。"""
    kinds, why = [], []
    for name, rx in _CLASS_RULES:
        if rx.search(text):
            kinds.append(name)
            why.append("%s: 匹配 %s" % (name, rx.pattern[:40]))
    low = text.lower()
    for w in _DIAG_WORDS:
        if w in low:
            kinds.append("diagnostic")
            why.append("diagnostic: 含「%s」" % w)
            break
    if _CJK.search(text):
        kinds.append("cjk")
        why.append("cjk: 含中日韩字符")
    if not kinds:
        kinds.append("plain")
        why.append("plain: 没有可识别的语义特征")
    return {"kinds": sorted(set(kinds)), "why": why}


def _is_printable_ascii(c: int) -> bool:
    return 0x20 <= c <= 0x7E or c == 0x09


def _gbk_pair(b: bytes, i: int):
    """``(i, i+2)`` 是否是一个合法的 GBK 双字节字符。"""
    if i + 1 >= len(b):
        return False
    lead, trail = b[i], b[i + 1]
    return (0x81 <= lead <= 0xFE) and (0x40 <= trail <= 0xFE) and trail != 0x7F


def _plausible_cjk_char(c: str) -> bool:
    """这个字像不像**真文案**里的字。

    GBK 的 trail 范围宽到 0x40..0xFE，随便两字节指令也能拼出一个合法码位（西里尔、
    希腊、制表符占位）——不加这层判据，字符串扫描就会淹没在“合法但没人会写的字符”里。
    只放行：ASCII 可打印、汉字、中文标点、全角符号与少量常用符号。
    """
    o = ord(c)
    if 0x20 <= o <= 0x7E or o == 0x09:
        return True
    for lo, hi in ((0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x3000, 0x303F),
                   (0xFF00, 0xFF65), (0x2010, 0x203B), (0x2460, 0x24FF)):
        if lo <= o <= hi:
            return True
    return o in (0xB0, 0xB1, 0xB7, 0xD7, 0xF7, 0x2103, 0x2116, 0x00B5, 0x00B1)


def _high_text(raw: bytes):
    """高字节串分级判定 → ``(text, enc, lenient)``；不是文本就返回 None。

    分两级，**默认口径只信第一级**：
      * ``gb2312``（lenient=False）：每个双字节都落在 GB2312 区（符号 0xA1A1-0xA9FE、
        汉字 0xB0A1-0xF7FE）。随机指令字节要连中两对才有 20% 概率，四五个字的串
        几乎不可能凑出来——这是「2820 → 218」那种收敛真正靠的一层。
      * ``gbk``（lenient=True）：只在 GBK 扩展区成立（0x81-0xA0 引头或 trail<0xA1）。
        合法但极不可信：默认要「有引用」才留（见 :func:`strings` 的第三重过滤）。
    """
    pairs, i = [], 0
    while i < len(raw):
        if raw[i] < 0x80:
            pairs.append(None)
            i += 1
            continue
        if i + 1 >= len(raw):
            return None
        lead, trail = raw[i], raw[i + 1]
        gb2312 = (0xA1 <= lead <= 0xF7) and (0xA1 <= trail <= 0xFE)
        pairs.append(gb2312)
        i += 2
    try:
        text = raw.decode("gb2312" if all(p is not False for p in pairs) else "gbk",
                          "strict")
    except (UnicodeDecodeError, LookupError):
        return None
    if not all(_plausible_cjk_char(c) for c in text):
        return None
    if all(p is not False for p in pairs):
        return text, "gb2312", False
    return text, "gbk", True


def _scan_strings(unit, *, min_len: int = 4, max_strings: int = MAX_STRINGS,
                  allow_gbk: bool = True) -> dict:
    """扫描可打印串（含 GBK 双字节）。返回候选 + 丢弃计数。

    与 :func:`mdkdebug.recover.find_strings` 的差别：这里同时采集**边界信息**
    （前一个字节、是否 NUL 终止、是否落在段首尾），后面三重过滤要用。
    """
    items, dropped = [], {"too_short": 0, "not_printable": 0}
    truncated = False
    # 数据区先扫：代码区里“可打印”的候选绝大多数是指令字节，先扫它们会把上限吃光
    for start, end, off in sorted(unit.spans, key=lambda sp: unit.in_code(sp[0])):
        blob = unit.data[off:off + (end - start)]
        in_code = unit.in_code(start)
        n, i = len(blob), 0
        while i < n:
            b = blob[i]
            if not (_is_printable_ascii(b) or (allow_gbk and 0x81 <= b <= 0xFE)):
                i += 1
                continue
            j = i
            while j < n:
                c = blob[j]
                if _is_printable_ascii(c):
                    j += 1
                elif allow_gbk and _gbk_pair(blob, j):
                    j += 2
                else:
                    break
            raw = blob[i:j]
            # 去掉尾部 \r\n 与空格（AT 指令常见），但保留「是否曾有换行」这个事实
            had_eol = raw.endswith(b"\r\n") or raw.endswith(b"\n")
            text_raw = raw.rstrip(b"\r\n\t ")
            if len(text_raw) < min_len:
                dropped["too_short"] += 1
                j = max(j, i + 1)
                i = j
                continue
            lenient = False
            if any(x > 0x7E for x in text_raw):
                hi = _high_text(text_raw)
                if hi is None:
                    # 解不成“像真文案的高字节串”：这段字节不是文本，整段跳过
                    dropped["not_printable"] += 1
                    i = max(j, i + 1)
                    continue
                text, enc, lenient = hi
                enc_ok = True
            else:
                text, enc = text_raw.decode("ascii"), "ascii"
                enc_ok = True
            addr = start + i
            items.append({
                "addr": addr, "addr_hex": "0x%08X" % addr,
                "len": len(text_raw), "byte_len": len(raw),
                "text": text[:512], "encoding": enc, "encoding_ok": enc_ok,
                "lenient_encoding": lenient,
                "in_code": in_code,
                "nul_terminated": (i + len(raw) < n and blob[i + len(raw)] == 0),
                "prev_byte": (blob[i - 1] if i else None),
                "at_span_edge": (i == 0 or i + len(raw) >= n),
                "had_eol": had_eol,
                "bytes_hex": text_raw[:64].hex(),
            })
            if len(items) >= max_strings:
                truncated = True
                break
            i = j
        if truncated:
            break
    return {"items": items, "truncated": truncated, "dropped_scan": dropped}


def _data_refs(unit, insns, xrefs) -> dict:
    """建「谁引用过这个地址」的索引。

    强度分档（写进每条的结果，不合并）：
      ``strong``  = 指令直接算出/取到的地址（adr / add pc / ldr 字面量池的值）
      ``table``   = 某个**被指令引用的**指针字，值指向它（指针数组的成员）
      ``pointer`` = 数据区里一个孤立的 4 字节字指向它，但那个字本身没人引用
    """
    endl = unit.arch.get("endian", "little")
    refs = {}

    def add(addr, rec):
        refs.setdefault(int(addr), []).append(rec)

    # ① 指令里的 pc 相对引用（含 ldr 字面量 → 值）
    for a, ins in insns.items():
        ref = _recover._pc_ref(ins)
        if not ref:
            continue
        if ref["kind"] == "address":
            add(ref["addr"], {"from": a, "from_hex": "0x%08X" % a,
                              "how": "adr/pc-add", "insn": _ins_text(ins),
                              "strength": "strong", "loads_pointer": False})
        else:
            slot = ref["addr"]
            add(slot, {"from": a, "from_hex": "0x%08X" % a,
                       "how": "literal_pool_slot", "insn": _ins_text(ins),
                       "strength": "strong", "loads_pointer": True})
            w = unit.read(slot, 4)
            if len(w) == 4:
                v = int.from_bytes(w, endl)
                if _in_span(unit, v):
                    add(v, {"from": a, "from_hex": "0x%08X" % a,
                            "how": "literal_pool_value@0x%08X" % slot,
                            "insn": _ins_text(ins),
                            "strength": "strong", "loads_pointer": True,
                            "pool_slot_hex": "0x%08X" % slot})

    # ② 交叉引用表里的数据读写（movw/movt 常量基址走这条）
    for x in (xrefs or {}).get("xrefs") or []:
        if x.get("kind") not in ("data_read", "data_write"):
            continue
        add(int(x.get("to") or 0), {"from": x.get("from"), "from_hex": x.get("from_hex"),
                                    "how": "xref:%s" % (x.get("how") or ""),
                                    "insn": x.get("insn") or "",
                                    "width": x.get("width"),
                                    "strength": "strong", "loads_pointer": False})

    # ③ 指针表：4 字节字里有值落进镜像 → table / pointer
    strong_slots = {a for a, lst in refs.items()
                    if any(r.get("loads_pointer") or r["strength"] == "strong" for r in lst)}
    pool = []
    for start, end, off in unit.spans:
        n = (end - start) // 4
        blob = unit.data[off:off + n * 4]
        for k in range(n):
            a = start + k * 4
            v = int.from_bytes(blob[k * 4:k * 4 + 4], endl)
            if not _in_span(unit, v) or v == a:
                continue
            strength = "table" if a in strong_slots else "pointer"
            add(v, {"from": a, "from_hex": "0x%08X" % a, "how": "pointer_word",
                    "strength": strength, "loads_pointer": True})
            pool.append({"slot": a, "slot_hex": "0x%08X" % a,
                         "value_hex": "0x%08X" % v, "slot_referenced": a in strong_slots})
    return {"refs": refs, "pool": pool}


def _ins_text(ins) -> str:
    return ("%s %s" % (ins.get("mnemonic") or "", ins.get("op_str") or "")).strip()


def _in_span(unit, addr: int) -> bool:
    return bool(addr) and unit._locate(addr)[0] is not None


def strings(path: str, *, base: int = 0, min_len: int = 4,
            max_strings: int = MAX_STRINGS, allow_gbk: bool = True,
            referenced_only: bool = False, kinds: str = "",
            include_dropped: bool = False, code_strings: bool = False) -> dict:
    """字符串 + 数据池语义：**带引用证据**的可打印串清单。

    ``referenced_only=True`` 只留「被指令或指针表引用」的（假阳性最少的那个口径）；
    ``kinds`` 用逗号过滤分类（如 ``"diagnostic,format"``）。
    ``code_strings=True`` 才把「落在可执行区、又没有引用」的候选也列出来：多数镜像
    的 rodata 与 .text 同在一个可执行段，那里的“可打印”候选 99% 是指令字节凑出来的。
    """
    unit, insns, funcs, rel, gaps = _open(path, base=base, deep=True)
    if unit is None:
        return gaps
    xrefs = rel.get("xrefs") or {}
    scan = _scan_strings(unit, min_len=min_len, max_strings=max_strings,
                         allow_gbk=allow_gbk)
    idx = _data_refs(unit, insns, xrefs)
    refs = idx["refs"]
    want = {k.strip() for k in (kinds or "").split(",") if k.strip()}

    kept, dropped = [], {"no_reference": 0, "in_code_no_boundary": 0,
                         "in_code_unreferenced": 0,
                         "undecodable": 0, "loose_gbk": 0,
                         "kind_filtered": 0}
    for s in scan["items"]:
        rs = refs.get(s["addr"], [])
        strength = ""
        for tag in ("strong", "table", "pointer"):
            if any(r["strength"] == tag for r in rs):
                strength = tag
                break
        hard = bool(s["nul_terminated"] or s["at_span_edge"]
                    or s["prev_byte"] == 0)
        s["refs"] = rs[:8]
        s["ref_strength"] = strength or "none"
        s["hard_boundary"] = hard
        s["pool_slot"] = (s["addr"] - 4) if any(
            r.get("how", "").startswith("literal_pool_slot") for r in rs) else None
        cls = classify(s["text"])
        s["kinds"], s["kind_why"] = cls["kinds"], cls["why"]

        # 三重过滤：① 字符集/可解码 ② 边界 ③ 引用
        if not s["encoding_ok"]:
            s["verdict"] = "dropped"
            s["drop_reason"] = "undecodable: 高字节串按 GBK 也解不通（多半是指令/压缩数据）"
            dropped["undecodable"] += 1
        elif s.get("lenient_encoding") and strength not in ("strong", "table"):
            s["verdict"] = "dropped"
            s["drop_reason"] = ("loose_gbk: 只在 GBK 扩展区成立（不在 GB2312 区）、"
                                "又没有强引用——随机指令字节也常凑得出这种组合")
            dropped["loose_gbk"] += 1
        elif not hard and s["in_code"]:
            s["verdict"] = "dropped"
            s["drop_reason"] = ("in_code_no_boundary: 落在代码区、前后都不是 NUL/段界，"
                                "又没有引用——最像指令字节凑巧可打印")
            dropped["in_code_no_boundary"] += 1
        elif s["in_code"] and not strength and not code_strings:
            s["verdict"] = "dropped"
            s["drop_reason"] = ("in_code_unreferenced: 落在可执行区、有硬边界但没有任何引用"
                                "——rodata 与 .text 混装时这里的候选基本是指令字节；"
                                "要看得开 code_strings=true")
            dropped["in_code_unreferenced"] += 1
        elif not strength:
            s["verdict"] = "unreferenced"
            s["drop_reason"] = "no_reference: 没有任何指令或指针字指向它"
            dropped["no_reference"] += 1
        else:
            s["verdict"] = "confirmed" if strength in ("strong", "table") else "weak"
        if want and not (set(s["kinds"]) & want):
            s["verdict"] = "dropped"
            s["drop_reason"] = "kind_filtered: 分类不在 kinds=%s 里" % sorted(want)
            dropped["kind_filtered"] += 1
        if referenced_only and s["verdict"] in ("unreferenced", "dropped"):
            continue
        kept.append(s)
    # 输出顺序：confirmed → weak → unreferenced → dropped；被丢的有样例外留而不占列表
    order = {"confirmed": 0, "weak": 1, "unreferenced": 2, "dropped": 3}
    kept.sort(key=lambda s: (order.get(s["verdict"], 9), -int(s.get("len") or 0)))
    dropped_sample = [s for s in kept if s["verdict"] == "dropped"][:12]

    n_conf = sum(1 for s in kept if s["verdict"] == "confirmed")
    by_kind = {}
    for s in kept:
        for k in s["kinds"]:
            by_kind[k] = by_kind.get(k, 0) + 1
    pool = [p for p in idx["pool"] if p["slot_referenced"]]
    return {
        "ok": True,
        "image": {"name": os.path.basename(path), "container": unit.container,
                  "base_hex": "0x%08X" % unit.base_used,
                  "code_ranges": [{"start_hex": "0x%08X" % a, "end_hex": "0x%08X" % b}
                                  for a, b in unit.code_ranges]},
        "counts": {
            "candidates": len(scan["items"]),
            "kept": len(kept),
            "confirmed": n_conf,
            "weak": sum(1 for s in kept if s["verdict"] == "weak"),
            "unreferenced": sum(1 for s in kept if s["verdict"] == "unreferenced"),
            "dropped": dropped,
            "scan_dropped": scan["dropped_scan"],
            "by_kind": by_kind,
            "pool_slots_referenced": len(pool),
            "code_pointers_in_pool": sum(
                1 for p in pool if unit.is_exec_address(int(p["value_hex"], 16))),
        },
        "filter_rule": [
            "① 字符集：ASCII 可打印（含 \\t）或中文双字节。高字节串分两级：落在 GB2312 区"
            "（符号 0xA1A1-0xA9FE / 汉字 0xB0A1-0xF7FE）算硬；只在 GBK 扩展区成立的标 "
            "loose_gbk，必须有强引用才留；两头都不成立判 undecodable"," 边界与引用见下",
            "② 边界：NUL 终止 / 落在段首尾 / 前一个字节是 0x00 三选一才算硬边界；"
            "代码区里没有硬边界的串默认丢弃",
            "③ 引用：指令直接算出地址（adr / add pc）、字面量池里被 ldr 取出的值、"
            "被指令引用的指针字（table）——任一命中才算被引用；"
            "孤立的指针字（pointer）只算弱证据",
            "④ 落在可执行区且①②都不成立候选、又没有任何引用（in_code_unreferenced）"
            "默认不进列表只计数——rodata 与 .text 混装时这类候选取自指令字节；"
            "要看它传 code_strings=true",
            "被丢弃的每一条都计数并给出原因，不静默减少",
        ],
        "strings": ([s for s in kept if s["verdict"] != "dropped"]
                    if not include_dropped else kept)[:max_strings],
        "dropped_sample": dropped_sample,
        "truncated": scan["truncated"] or len(kept) > max_strings,
        "scan_truncated": bool(scan["truncated"]),
        "complete": (not scan["truncated"]) and len(kept) <= max_strings,
        "pool": {"referenced_slots": pool[:200],
                 "all_slots": len(idx["pool"]),
                 "note": "referenced_slots 只列「本身被指令取过」的字面量池槽位；"
                         "all_slots 是镜像里全部指向镜像内的 4 字节字（含结构体字段，"
                         "不都是池）"},
        "gaps": gaps + (
            ([{"reason": "候选上限 max_strings=%d 在扫描阶段就被吃满：本报告**不完整**，"
                          "请调小 min_len 或放宽 kinds 后重扫" % max_strings}]
             if scan["truncated"] else [])
            + ([{"reason": "反向引用只覆盖「静态可解析」的指令：间接寻址的"
                           "字符串（如 base 由另一函数传入）会落成 "
                           "no_reference，不证明它没用"}]
               if idx["pool"] else [])),
        "limitations": [
            "「被引用」= 静态证据，不证明运行期一定用到；反过来「无引用」也不证明没用",
            "字符串长度取到首个非打印字节为止：嵌入 \\0 的格式化拼接会切成多条",
            "GBK 与 Latin-1 在单字节 0xA1..0xFE 上会撞车：encoding_ok=False 的条目"
            "已给出原始字节 hex，请自行核对",
        ],
    }


# ======================================================================
# 二、死代码 / 未引用判定
# ======================================================================
def _merge_ranges(items) -> list:
    items = sorted(items)
    out = []
    for a, b in items:
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _looks_like(blob: bytes) -> str:
    if not blob:
        return "empty"
    if all(b == 0 for b in blob):
        return "zeros"
    printable = sum(1 for b in blob if 0x20 <= b <= 0x7E)
    if printable >= len(blob) * 0.9:
        return "text"
    if len(blob) % 4 == 0:
        return "words"
    return "bytes"


def deadcode(path: str, *, base: int = 0, min_gap: int = 64,
             max_ranges: int = MAX_RANGES, symbols: str = "") -> dict:
    """未引用函数与未引用区间（**静态**可达性，判词是 unreferenced 不是「死」）。

    ``symbols`` 可按需补根（逗号分隔的函数名，比如 ``"main,app_entry"``）。
    """
    unit, insns, funcs, rel, gaps = _open(path, base=base, deep=True)
    if unit is None:
        return gaps
    xrefs = rel.get("xrefs") or {}
    graph = rel.get("call_graph") or {}
    edges = graph.get("edges") or []
    roots, root_why = [], {}

    # skip_empty=True：保留槽位常是 0，一旦当终止就会把 SysTick/外设中断入口整片丢掉
    vt = _recover.vector_table(unit, max_entries=256, skip_empty=True)
    vt_base = int(vt["base_hex"], 16) if vt.get("base_hex") else 0
    vt_end = vt_base + 4 * (vt.get("count", 0) + 1)
    for e in vt.get("entries") or []:
        if e.get("in_code"):
            a = int(e["handler_hex"], 16) & ~1
            roots.append(a)
            root_why.setdefault(a, "vector_table:%s" % (e.get("name") or e["index"]))
    hint = int(getattr(unit, "entry_hint", 0) or 0)
    if hint:
        a = hint & ~1 if unit.arch.get("family") == "arm" else hint
        roots.append(a)
        root_why.setdefault(a, "entry_hint")
    want = {s.strip() for s in (symbols or "").split(",") if s.strip()}
    want |= {"main", "Reset_Handler", "reset_handler"}
    for f in funcs:
        nm = (f.get("name") or "").strip()
        if nm in want:
            roots.append(f["addr"])
            root_why.setdefault(f["addr"], "named_root:%s" % nm)

    by_addr = {f["addr"]: f for f in funcs}
    roots = [a for a in dict.fromkeys(roots) if a in by_addr]
    callees = {}
    callers = {}
    for e in edges:
        callees.setdefault(e["caller"], set()).add(e["callee"])
        callers.setdefault(e["callee"], set()).add(e["caller"])
    # 跨函数之外还有一种「入口」：函数指针被存进数据（中断表之外的回调表）
    idx = _data_refs(unit, insns, xrefs)
    ptr_targets = {}
    for x in (xrefs or {}).get("xrefs") or []:
        if x.get("kind") == "data_code_pointer":
            ptr_targets.setdefault(int(x["to"]), []).append(x.get("from_hex"))
    # 字面量池/指针表里被指令取过的「代码指针」：printf 的格式化函数表、
    # 回调注册表都走这条路，只看 xrefs 会把它们全判成无引用
    for p in idx["pool"]:
        v = int(p["value_hex"], 16)
        if p["slot_referenced"] and unit.is_exec_address(v):
            ptr_targets.setdefault(v, []).append("pool@%s" % p["slot_hex"])
    for f in funcs:
        for cp in f.get("call_targets") or []:
            callees.setdefault(f["addr"], set()).add(cp)
    # 尾调用（b/b.w 到函数入口）在 call_graph 里是 branch 而不是 call：
    # 中断处理函数基本都是这么跳到 HAL_xxx_IRQHandler 的，不补就会把它判成不可达。
    tail = 0
    for x in (xrefs or {}).get("xrefs") or []:
        if x.get("kind") != "branch":
            continue
        a, b = int(x.get("func") or 0), int(x.get("to") or 0)
        if not a or b not in by_addr or a not in by_addr or b == a:
            continue
        callees.setdefault(a, set()).add(b)
        tail += 1

    seen, queue = set(), list(roots)
    while queue:
        a = queue.pop()
        if a in seen or a not in by_addr:
            continue
        seen.add(a)
        for b in callees.get(a, ()):
            if b not in seen:
                queue.append(b)

    unreach = []
    for f in funcs:
        if f["addr"] in seen:
            continue
        ptr = ptr_targets.get(f["addr"]) or []
        n_callers = len(callers.get(f["addr"], ()))
        rec = {
            "addr_hex": f["addr_hex"], "name": f.get("name") or "",
            "size": int(f.get("end_addr") or 0) - int(f["addr"] or 0),
            "confidence": f.get("confidence") or "",
            "n_callers": n_callers, "pointer_sites": ptr[:6],
            "verdict": "unreferenced",
            "basis": ["不在向量表/入口/命名根的可达集里", "没有 bl/b 调用指向它"],
        }
        if n_callers:
            rec["verdict"] = "unreachable_but_called"
            rec["basis"].append("有 %d 个调用方，但它们自己也不可达" % n_callers)
        if ptr:
            rec["verdict"] = "unreachable_but_pointed"
            rec["basis"].append("有 %d 处字面量池/数据字指向它（回调表的可能）" % len(ptr))
        unreach.append(rec)
    unreach.sort(key=lambda r: -int(r["size"] or 0))

    # ---- 数据区间：把「被引用过的字节」涂掉，剩下的空洞就是候选 ----
    covered = []
    covered.append((vt_base, vt_end))
    width_map = {}
    for x in (xrefs or {}).get("xrefs") or []:
        if x.get("kind") not in ("data_read", "data_write"):
            continue
        a = int(x.get("to") or 0)
        w = int(x.get("width") or 4)
        width_map[a] = max(width_map.get(a, 0), w)
        covered.append((a, a + w))
    for p in idx["pool"]:
        if p["slot_referenced"]:
            covered.append((p["slot"], p["slot"] + 4))
    cov = _merge_ranges(covered)

    # 符号表里有的对象：即使没被指令碰到也不许判「无引用」（可能是别人 export 的）
    sym_objs = []
    st = _recover.symbol_table(unit)
    for o in st.get("objects") or []:
        if o.get("size"):
            sym_objs.append((int(o["addr"]), int(o["addr"]) + int(o["size"]),
                             o.get("name") or ""))

    spans = _data_spans(unit)
    data_span_bytes = sum(b - a for a, b in spans)
    ranges = []
    for start, end in spans:
        cur = start
        for a, b in cov:
            if b <= cur or a >= end:
                continue
            if a > cur:
                ranges.append((cur, min(a, end)))
            cur = max(cur, b)
        if cur < end:
            ranges.append((cur, end))
    out_ranges = []
    for a, b in ranges:
        if b - a < min_gap:
            continue
        blob = unit.read(a, b - a)
        hit = [nm for (sa, sb, nm) in sym_objs if sa < b and sb > a]
        rec = {"start_hex": "0x%08X" % a, "end_hex": "0x%08X" % b,
               "size": b - a, "looks_like": _looks_like(blob),
               "head_hex": blob[:16].hex(),
               "in_symbols": hit[:4],
               "verdict": "unreferenced" if not hit else "symboled",
               "basis": (["没有任何指令/指针字覆盖这段"] if not hit else
                         ["被符号表里的 %s 覆盖：有名字就不能判无引用" % ", ".join(hit[:4])])}
        if rec["looks_like"] == "zeros":
            rec["basis"].append("内容全 0（更像预留/擦除态，不像数据）")
        out_ranges.append(rec)
    out_ranges.sort(key=lambda r: -r["size"])
    total_dead = sum(r["size"] for r in out_ranges if r["verdict"] == "unreferenced")
    # 区间判定的诚实声明：数据段为空 / 全被引用覆盖 / 全部小于 min_gap 时，
    # unreferenced_ranges=0 **不是**「没有死代码」，只是这条判据在本镜像上不适用。
    ranges_note = ""
    if not spans:
        ranges_note = ("本镜像没有可与代码分离的数据区间（可执行段覆盖全部存储）："
                       "「无引用数据区间」这条判据不可用，不是没有死代码。"
                       "函数级 unreachable 统计不受影响。")
    elif total_dead == 0:
        ranges_note = ("可分离的数据区间共 %d 字节，全部被引用覆盖或被符号表覆盖"
                       "（或小于 min_gap=%d 被滤掉）：本镜像里没有可判定的"
                       "「无引用数据区间」" % (data_span_bytes, min_gap))
    total_fn = sum(int(r["size"] or 0) for r in unreach)

    n_unres = int((xrefs or {}).get("n_unresolved") or 0)
    lim = [
        "判词是 unreferenced（静态无引用），**不是**「死代码」：间接调用、函数指针表、"
        "外部中断向量、自修改代码都能让它在运行期被用到",
        "要把它变成确定结论，走「删掉重建、bin 逐字节相同」那条路："
        "recover_project_exact 出件 → 删掉这些区间 → recover_verify 比对",
    ]
    if n_unres:
        lim.append("有 %d 条访存/间接调用的基址寄存器无法静态确定："
                   "这些位置既可能引用被判无引用的对象，也可能指向别处" % n_unres)
    return {
        "ok": True,
        "inventory": {"functions": len(funcs), "roots": len(roots),
                      "reachable": len(seen), "unreachable": len(unreach),
                      "code_bytes": sum(int(f.get("end_addr") or 0) - int(f["addr"])
                                        for f in funcs)},
        "roots": [{"addr_hex": "0x%08X" % a, "why": root_why.get(a, ""),
                   "name": by_addr[a].get("name") or ""} for a in roots][:200],
        "unreachable_functions": unreach[:400],
        "unreachable_function_bytes": total_fn,
        "unreferenced_ranges": out_ranges[:max_ranges],
        "unreferenced_bytes": total_dead,
        "data_span_bytes": data_span_bytes,
        "ranges_note": ranges_note,
        "truncated": len(out_ranges) > max_ranges,
        "how_to_confirm": [
            "1) recover_project_exact 把原镜像复刻成可重链接工程，recover_verify 确认"
            "重建 bin 与原镜像逐字节相同（这一步先证明工具链口径没跑偏）",
            "2) 从工程里删掉本报告列出的函数/区间，再重建；bin 仍逐字节相同 ⇒ "
            "链接器也认为它们没人要",
            "3) 只要有一个字节变了，就说明删多了：把差异区间的地址回填进来重新判断",
        ],
        "gaps": gaps + ([{"reason": ranges_note}] if ranges_note else []),
        "limitations": lim,
    }


# ======================================================================
# 三、数据表结构化导出为 C
# ======================================================================
_TYPES = {
    "u8": ("uint8_t", 1, False), "s8": ("int8_t", 1, True),
    "u16": ("uint16_t", 2, False), "s16": ("int16_t", 2, True),
    "u32": ("uint32_t", 4, False), "s32": ("int32_t", 4, True),
}


def _crc_tables() -> dict:
    """现算三种常见 CRC 表（用来**证明**这块数据是哪种表，不靠猜）。"""
    out = {}
    t32 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        t32.append(c & 0xFFFFFFFF)
    out["crc32"] = {"poly_hex": "0xEDB88320", "width": 4, "values": t32}
    for name, poly in (("crc16_arc", 0xA001), ("crc16_ccitt", 0x8408)):
        t16 = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ (poly if c & 1 else 0)
            t16.append(c & 0xFFFF)
        out[name] = {"poly_hex": "0x%04X" % poly, "width": 2, "values": t16}
    return out


def _c_bytes(b: bytes) -> str:
    """字节 → C 字符串字面量（八进制转义，任何字节都能原样往返）。"""
    out = []
    for ch in b:
        if ch in (0x22, 0x5C):
            out.append("\\" + chr(ch))
        elif 0x20 <= ch <= 0x7E:
            out.append(chr(ch))
        else:
            out.append("\\%03o" % ch)
    return '"' + "".join(out) + '"'


def _parse_fields(spec: str) -> list:
    """``"id:u16,flags:u16,value:s32"`` → ``[{name, off, type, size}]``。"""
    out, off = [], 0
    for tok in (spec or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if ":" not in tok:
            raise ValueError("字段写法是 name:type（收到 %r）" % tok)
        name, typ = tok.split(":", 1)
        name, typ = name.strip(), typ.strip().lower()
        m = re.match(r"^(u8|s8|u16|s16|u32|s32|char)(?:\[(\d+)\])?$", typ)
        if not m:
            raise ValueError("不认识的字段类型 %r（支持 u8/s8/u16/s16/u32/s32/char[N]）" % typ)
        base, arr = m.group(1), m.group(2)
        size = 1 if base == "char" else _TYPES[base][1]
        n = int(arr) if arr else 1
        out.append({"name": name, "offset": off, "type": base,
                    "elem_size": size, "count": n, "size": size * n})
        off += size * n
    return out


def _signed_view(value: int, typ: str) -> int:
    """按类型的有符号视图取值——**与 `_fmt_value` 打印出来的字面量同义**。"""
    bits = {"s8": 8, "s16": 16, "s32": 32}.get(typ)
    if not bits:
        return value
    half = 1 << (bits - 1)
    return value - (1 << bits) if value >= half else value

def _fmt_value(value: int, typ: str) -> str:
    if typ == "s8":
        v = value - 0x100 if value >= 0x80 else value
        return str(v)
    if typ == "s16":
        v = value - 0x10000 if value >= 0x8000 else value
        return str(v)
    if typ == "s32":
        v = value - 0x100000000 if value >= 0x80000000 else value
        return str(v)
    if typ == "u8":
        return "0x%02X" % value
    if typ == "u16":
        return "0x%04X" % value
    return "0x%08X" % value


def _init_cells(lines) -> list:
    """把**生成的 C 初始化列表**再解析回数值清单（回读自证用）。

    口径：从 ``= {`` 那一行开始、``};`` 之前结束，**只解析数组体**，并把 C 字符串
    字面量整段抹掉（``char[N]`` 字段与 ``\101`` 这种八进制转义里的数字不能当值）。

    以前这里是 ``re.findall(r"0x...", text)`` 扫**整段**文本——文件头注释里的
    ``0x08000000``、``0xEDB88320`` 会被当成第 0、1 个元素，于是「回读校验」永远
    对不上：真的写错了反倒被淹没在一屏假 mismatch 里。回读必须只读被回读的那一段。
    """
    header = any("= {" in ln for ln in lines)
    body, started = [], False
    for ln in lines:
        if header:
            # 传进来的是整段声明：只取 `= {` 之后、`};` 之前的数组体
            if not started:
                if "= {" in ln:
                    started = True
                continue
            if ln.strip().startswith("}"):
                break
        body.append(ln)
    text = re.sub(r'"(?:[^"\\]|\\.)*"', " ", " ".join(body))
    out = []
    # 注意顺序：`0x…` 必须排在十进制前面。反过来写的话 `0x00000000` 会先被
    # `-?\d+` 吃掉一个 `0`、再剩下 `x00000000` 又吃一个 `0`——两格假值。
    for tok in re.findall(r"0x[0-9A-Fa-f]+|-?\d+", text):
        out.append(int(tok, 16) if tok.lower().startswith("0x") else int(tok))
    return out

def _read_cells(unit, addr: int, count: int, elem: int, signed: bool) -> list:
    got = unit.read_ex(addr, count * elem)
    if got["clipped"]:
        raise ValueError("读不了这么多：%s" % got["reason"])
    blob = got["data"]
    endl = unit.arch.get("endian", "little")
    vals = []
    for i in range(count):
        chunk = blob[i * elem:(i + 1) * elem]
        v = int.from_bytes(chunk, endl, signed=signed)
        vals.append(v & ((1 << (8 * elem)) - 1))
    return vals


def datatable(path: str, *, base: int = 0, addr: int = 0, count: int = 0,
              elem: int = 4, signed: bool = False, fmt: str = "auto",
              record_size: int = 0, fields: str = "", name: str = "",
              out: str = "", evidence_only: bool = True) -> dict:
    """把 `[addr, addr+…)` 的定长结构导成带字段名的 C 数组，并**回读自证**。

    ``fmt``：``auto | array | records | crc32 | crc16_arc | crc16_ccitt | at_table``
    """
    unit, insns, funcs, rel, gaps = _open(path, base=base, deep=False)
    if unit is None:
        return gaps
    xrefs = rel.get("xrefs") or {}
    unit.entry_hint = 0
    addr = int(addr or 0)
    if not addr:
        return {"ok": False, "error": "缺少 addr：要导哪一段数据表？",
                "hint": "先 recover_strings / recover_probe 定位，或用 recover_disasm 看引用"}
    endl = unit.arch.get("endian", "little")
    fl = [f for f in (_parse_fields(fields) or [])] if fields else []
    if fl:
        record_size = record_size or sum(f["size"] for f in fl)
    explicit = (fmt or "auto").lower()
    detected = None
    if explicit == "auto":
        # ① CRC 表：先按 256 项试着认，认出来就用它的宽度
        for nm, t in _crc_tables().items():
            w = t["width"]
            try:
                vals = _read_cells(unit, addr, 256, w, False)
            except ValueError:
                continue
            if vals == t["values"]:
                explicit, detected, elem = nm, {"kind": nm, "poly_hex": t["poly_hex"]}, w
                count = 256
                break
        # ② 指针数组 → AT/命令表
        if explicit == "auto" and not fl:
            try:
                words = _read_cells(unit, addr, 64 if not count else min(count, 1024), 4, False)
            except ValueError:
                words = []
            strs, ok = [], bool(words)
            for w in words:
                if not _in_span(unit, w):
                    ok = False
                    break
                got = unit.read_ex(w, 256)
                raw = got["data"].split(b"\x00", 1)[0]
                if len(raw) < 2 or not all(0x20 <= b <= 0x7E for b in raw):
                    ok = False
                    break
                strs.append((w, raw))
            if ok and strs:
                explicit, detected, elem = "at_table", {"kind": "at_table",
                                                       "n_strings": len(strs)}, 4
                count = len(strs)
        if explicit == "auto":
            explicit = "records" if fl else "array"

    if explicit in ("crc32", "crc16_arc", "crc16_ccitt"):
        t = _crc_tables()[explicit]
        elem, count = t["width"], 256
        name = name or explicit
        typ = "u16" if elem == 2 else "u32"
        vals = _read_cells(unit, addr, count, elem, False)
        if vals != t["values"]:
            bad = [i for i, (a, b) in enumerate(zip(vals, t["values"])) if a != b][:8]
            detected = {"kind": explicit, "match": False, "mismatch_index": bad}
            return {"ok": False,
                    "error": "这段数据与 %s 表不一致（不猜）：不一致的项 %s"
                             % (explicit, bad),
                    "hint": "确认 addr/长度/端序；若确实不是 CRC 表就用 fmt=array 显式导",
                    "detected": detected}
        detected = {"kind": explicit, "match": True, "poly_hex": t["poly_hex"]}
        lines = _array_text(name, typ, vals, elem)
        text = _wrap(name, lines, evidence_only, {},
                     "0x%08X，%d × %s（%s，poly=%s）"
                     % (addr, count, typ, explicit, t["poly_hex"]))
        parsed = _init_cells(lines)
        result = _finish(text, name, typ, vals, parsed, addr, out, evidence_only)
        result["detected"] = detected
        return result

    if explicit == "at_table":
        n = count or 64
        words = _read_cells(unit, addr, n, 4, False)
        entries = []
        for w in words:
            if not _in_span(unit, w):
                break
            raw = unit.read_ex(w, 4096)["data"].split(b"\x00", 1)[0]
            if len(raw) < 2 or not all(0x20 <= b <= 0x7E for b in raw):
                break
            entries.append((w, raw))
        if not entries:
            return {"ok": False, "error": "addr 处的字都不指向可打印字符串：这不是字符串指针表",
                    "hint": "用 fmt=array 看原始字，或确认 addr 是否正确"}
        name = name or "str_table"
        body = ["static const char *const %s[%d] = {" % (name, len(entries))]
        for w, raw in entries:
            body.append("    %s,  /* 0x%08X */" % (_c_bytes(raw), w))
        body.append("};")
        text = _wrap(name, body, evidence_only, {},
                     "0x%08X，%d 个指向字符串的指针（fmt=at_table）" % (addr, len(entries)))
        # 回读：把八进制转义解回字节，与内存逐字节比
        parsed = [_un_c(ln.split(",")[0].strip())
                  for ln in body[1:-1]]
        mism = [i for i, (p, (_w, raw)) in enumerate(zip(parsed, entries)) if p != raw]
        result = _finish(text, name, "char*", [w for w, _ in entries], parsed,
                         addr, out, evidence_only, expect_mismatch=mism)
        result["detected"] = {"kind": "at_table", "n_strings": len(entries)}
        result["strings"] = [{"addr_hex": "0x%08X" % w,
                              "text": raw.decode("latin-1")} for w, raw in entries[:200]]
        return result

    if explicit == "records":
        if not fl:
            return {"ok": False, "error": "fmt=records 需要 fields（如 id:u16,value:s32）"}
        rs = int(record_size or sum(f["size"] for f in fl))
        if rs < sum(f["size"] for f in fl):
            return {"ok": False, "error": "record_size=%d 小于字段总长 %d"
                    % (rs, sum(f["size"] for f in fl))}
        n = int(count or 1)
        got = unit.read_ex(addr, rs * n)
        if got["clipped"]:
            return {"ok": False, "error": "读不了 %d 条记录：%s" % (n, got["reason"])}
        blob = got["data"]
        name = name or "table"
        sname = name + "_t"
        body = ["typedef struct {"] if True else []
        for f in fl:
            if f["type"] == "char":
                body.append("    char %s[%d];" % (f["name"], f["count"]))
            else:
                body.append("    %s %s;" % (_TYPES[f["type"]][0], f["name"]))
        body.append("} %s;" % sname)
        body.append("")
        body.append("static const %s %s[%d] = {" % (sname, name, n))
        expect, char_checks, init = [], [], []
        for k in range(n):
            rec_bytes = blob[k * rs:(k + 1) * rs]
            cells = []
            for f in fl:
                chunk = rec_bytes[f["offset"]:f["offset"] + f["size"]]
                if f["type"] == "char":
                    lit = _c_bytes(chunk)
                    cells.append(lit)
                    char_checks.append((k, f["name"], lit, chunk))
                else:
                    v = int.from_bytes(chunk, endl)
                    cells.append(_fmt_value(v, f["type"]))
                    # 写出去的是「有符号视图」，回读也按有符号比——否则 s16 的 -1
                    # 会被拿无符号 65535 去比，回读永远失败（口径必须与打印一致）
                    expect.append(_signed_view(v, f["type"]))
            init.append("    { %s }," % ", ".join(cells))
        body.extend(init)
        body.append("};")
        text = _wrap(name, body, evidence_only, {}, "0x%08X，%d 条 × %d 字节记录"
                     % (addr, n, rs))
        # 回读：只解析**写出去的那段初始化列表**，再逐格比对（char[] 单独比字节）
        got_nums = _init_cells(init)
        mism = [i for i, (a, b) in enumerate(zip(expect, got_nums)) if a != b]
        if len(got_nums) != len(expect):
            mism.append(-1)     # 解析出的数值格数与预期不符，同样算回读失败
        for k, fname, lit, chunk in char_checks:
            if _un_c(lit) != chunk:
                mism.append("char@%d.%s" % (k, fname))
        result = _finish(text, name, sname, expect, got_nums, addr, out,
                         evidence_only, expect_mismatch=mism)
        result["detected"] = {"kind": "records", "record_size": rs,
                             "fields": fl}
        result["records"] = n
        return result

    # array
    if not count:
        return {"ok": False, "error": "fmt=array 需要 count（或先让 fmt=auto 认出 CRC/指针表）"}
    if elem not in (1, 2, 4):
        return {"ok": False, "error": "elem 只支持 1/2/4（收到 %r）" % elem}
    typ = ("s" if signed else "u") + str(elem * 8)
    vals = _read_cells(unit, addr, count, elem, signed)
    name = name or "table"
    lines = _array_text(name, typ, vals, elem)
    text = _wrap(name, lines, evidence_only, {}, "0x%08X，%d × %s（fmt=array）"
                 % (addr, count, typ))
    parsed = _init_cells(lines)
    # 打印的是「有符号视图」（s32 的 0xFFFFFFFF 写成 -1），回读也必须按同一口径比
    expect = [_signed_view(v, typ) for v in vals] if signed else vals
    result = _finish(text, name, typ, expect, parsed, addr, out, evidence_only)
    result["detected"] = detected
    return result


def _array_text(name: str, typ: str, vals: list, elem: int) -> list:
    ctype = _TYPES[typ][0]
    per = {1: 12, 2: 8, 4: 4}[elem]
    lines = ["static const %s %s[%d] = {" % (ctype, name, len(vals))]
    for i in range(0, len(vals), per):
        chunk = ", ".join(_fmt_value(v, typ) for v in vals[i:i + per])
        lines.append("    %s," % chunk)
    lines.append("};")
    return lines


def _un_c(lit: str) -> bytes:
    """把 ``_c_bytes`` 生成的 C 字面量解回字节（回读自证用）。"""
    if lit.startswith('"') and lit.endswith('"'):
        lit = lit[1:-1]
    out, i = bytearray(), 0
    while i < len(lit):
        ch = lit[i]
        if ch == "\\":
            nxt = lit[i + 1]
            if nxt in "01234567":
                out.append(int(lit[i + 1:i + 4], 8))
                i += 4
                continue
            if nxt == "x":
                j = i + 2
                while j < len(lit) and lit[j] in "0123456789abcdefABCDEF":
                    j += 1
                out.append(int(lit[i + 2:j], 16))
                i = j
                continue
            out.append({"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "0": 0}[nxt])
            i += 2
            continue
        out.append(ord(ch))
        i += 1
    return bytes(out)


def _wrap(name: str, body: list, evidence_only: bool, _meta: dict, note: str) -> str:
    head = [
        "/* %s — 由 mdkdebug 从镜像字节反推出来的数据表" % name,
        " * %s" % note,
        " * 值一律从文件里读出来，生成后**逐元素回读校验**过（见 verified 字段）",
    ]
    if evidence_only:
        head += [
            " *",
            " * EVIDENCE ONLY —— 这是**证据**，不是整理好的源码：",
            " *   1) 作用域/链接属性(static)与类型是推断的；",
            " *   2) 表名是工具起的，不代表原工程里叫这个；",
            " *   3) 直接挂进工程会变成「Ported/」式的混合体。",
            " */",
            "#if !defined(MDKDEBUG_ALLOW_EVIDENCE_ONLY)",
            "#error 这是 mdkdebug 导出的证据表（EVIDENCE ONLY），不是源码：要编译请先定义 "
            "MDKDEBUG_ALLOW_EVIDENCE_ONLY",
            "#endif",
            "#include <stdint.h>",
            "",
        ]
    else:
        head += [" */", "#include <stdint.h>", ""]
    return "\n".join(head + body) + "\n"


def _finish(text: str, name: str, typ: str, expect: list, parsed: list,
            addr: int, out: str, evidence_only: bool,
            expect_mismatch=None) -> dict:
    mism = list(expect_mismatch or [])
    if typ not in ("char*",) and not expect_mismatch:
        for i, (a, b) in enumerate(zip(expect, parsed)):
            if a != b:
                mism.append(i)
    res = {
        "ok": True,
        "table": {"name": name, "type": typ, "addr_hex": "0x%08X" % addr,
                  "elements": len(expect)},
        "verified": not mism,
        "verify_rule": "把生成的 C 文本重新解析成数值/字节，与从镜像里读的原始值逐个"
                       "比对；只要有一项不同就 verified=false 并列出下标",
        "mismatches": mism[:20],
        "evidence_only": bool(evidence_only),
        "code": text,
    }
    if mism:
        res["ok"] = False
        res["error"] = "回读校验失败：生成的值与镜像字节不一致（下标 %s）" % mism[:8]
    if out:
        bad = _evidence.violation(os.path.dirname(os.path.abspath(out))) \
            if evidence_only else None
        if bad:
            return {**_evidence.refusal(os.path.dirname(os.path.abspath(out)), bad),
                    "hint": "证据表不要写进构建目录；真要当源码用请显式 "
                            "evidence_only=false"}
        _textio.write_text(out, text)
        res["out"] = os.path.abspath(out)
        res["out_bytes"] = len(text.encode("utf-8"))
        res["columns_note"] = ("mdkdebug 写的文本一律 utf-8 且**不带 BOM**"
                               "（BOM 会让下游拿不到首列）")
    return res
