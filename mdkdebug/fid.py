# -*- coding: utf-8 -*-
"""库指纹与函数匹配（批次86）。

吸收的是 Ghidra 的 FID（Function ID）与 REA 的 ``match_native_functions`` 的**判据**，
不是它们的实现。七条口径，每条都对应一个会被误解的坑：

1. **名字相同不等于代码相同。** 唯一精确名只建立「这两条是同一个符号」这个对应，
   不推断函数体未变、更不推断源码同一。报告里名字配对与字节配对是两种 basis。
2. **字节相同才叫 identical**，而且要求：函数体区间**有证据**（符号长度，或沿控制流
   走到终止指令）、字节全部取到、两侧长度相等、指纹在两侧都唯一、架构相同。
3. **不给「下一个入口」猜出来的边界做字节判定。** 那种区间是猜的，字节相等只能说明
   「猜出来的那一段碰巧一样」——所以 ``size_trust="guessed"`` 的函数不进字节配对。
4. **两条指令的函数满街都是。** 结构候选要过最小指令数门槛（默认 6）且指纹唯一，
   否则一律进 ``unresolved`` 组。
5. **only_left / only_right 只说明「在本次两份清单里没有精确对应」。** 重命名、内联、
   strip、字节变动、发现不全都能解释它们，**不证明源码有增删**。
6. **清单完整度未知**（``inventory_complete=False``），这条永远明说。
7. **重复候选不展开笛卡尔积**，保持 ``unresolved`` 组（组内成员数照实报）。

零依赖：只用 ``hashlib`` 与 ``re``。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone

FP_VERSION = 1
SIG_FORMAT = "mdkdebug-sig"

# 自动推导出来的名字（``sub_08000A1C`` / ``ptr_...`` / ``handler_17``）：它们由地址生成，
# 两侧地址一变就对不上，而且**不是**「符号表说这里叫什么」那种证据。名字配对一律跳过。
_AUTO_NAME = re.compile(
    r"^(sub|ptr|entry|handler|loc|func|thunk|unk|zero|dat)_[0-9A-Fa-f]+$")

_HEX = re.compile(r"0x[0-9a-fA-F]+")

# 有证据的边界：符号长度（symtab）或沿控制流走到终止指令。``next_entry`` 是猜的。
_TRUSTED_BASIS = ("return", "tail_call", "indirect_branch")


def _sha256(blob) -> str:
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _in_ranges(value: int, ranges) -> bool:
    for a, b in ranges:
        if a <= value < b:
            return True
    return False


def is_auto_name(name: str) -> bool:
    return bool(_AUTO_NAME.match(str(name or "")))


def size_trust(func: dict) -> str:
    """这条函数的区间有多少证据：``symtab`` / ``control_flow`` / ``guessed``。"""
    if str(func.get("size_basis") or "") == "symtab":
        return "symtab"
    if str(func.get("body_basis") or "") in _TRUSTED_BASIS:
        return "control_flow"
    return "guessed"


def body_bytes(unit, start: int, end: int):
    """取函数体字节。跨越未映射区间时返回 ``None``（不做部分拼接冒充完整）。"""
    if end <= start:
        return None
    blob = unit.read(start, end - start)
    if not blob or len(blob) != end - start:
        return None
    return blob


def normalize_operands(op_str: str, ranges) -> str:
    """把**落在可执行区间里的地址**归一成 ``<CODE>``，其余原样保留。

    为什么只归一代码地址：整份镜像换基址时，函数间跳转的目标会跟着变；而访问外设
    （0x40000000 一带）、字符串、常量池偏移**不该**跟着变，把它们一起抹掉会把两个
    不同的函数洗成同一个指纹。
    """
    def repl(m):
        try:
            v = int(m.group(0), 16)
        except ValueError:      # pragma: no cover - 正则已保证格式
            return m.group(0)
        return "<CODE>" if _in_ranges(v & ~1, ranges) else m.group(0).lower()
    return _HEX.sub(repl, str(op_str or ""))


def _body_insns(insns: dict, start: int, end: int):
    if not insns:
        return []
    return [insns[a] for a in sorted(insns) if start <= a < end]


def fingerprint(unit, func: dict, insns: dict, ranges, strings=()) -> dict:
    """一条函数的指纹。字段含义写进 ``fingerprint_rule``（报告里跟着一起出）。"""
    start = int(func.get("addr") or 0)
    end = int(func.get("end_addr") or start)
    body = body_bytes(unit, start, end) if end > start else None
    trust = size_trust(func)
    recs = _body_insns(insns, start, end)
    tokens, cfg = [], []
    for ins in recs:
        tokens.append("%s %s" % ((ins.get("mnemonic") or "").lower(),
                                 normalize_operands(ins.get("op_str") or "", ranges)))
        cfg.append("B" if ins.get("target") is not None else
                   ("R" if ins.get("ends_function") else "i"))
    srefs = sorted(t for f, t in (strings or ()) if start <= int(f or 0) < end)
    out = {
        "name": func.get("name") or "",
        "addr_hex": func.get("addr_hex") or ("0x%08X" % start),
        "size": max(0, end - start),
        "size_basis": func.get("size_basis") or "",
        "size_trust": trust,
        "body_basis": func.get("body_basis") or "not_analyzed",
        "confidence": func.get("confidence") or "",
        "is_thunk": bool(func.get("is_thunk")),
        "n_callees": int(func.get("callee_count") or len(func.get("callees") or [])),
        "insn_count": len(recs),
        # 只有「区间有证据」且「字节全取到」才给严格指纹；否则留空，让下游无法误用
        "bytes_sha256": (_sha256(body) if (body is not None and trust != "guessed")
                         else ""),
        "insn_sha256": _sha256("\n".join(tokens)) if tokens else "",
        "cfg_sha256": _sha256("".join(cfg)) if cfg else "",
        # 字符串引用是**佐证**：函数引了哪些文案。空 ≠ 没引用（可能没采集到）
        "strings_sha256": _sha256("\n".join(srefs)) if srefs else "",
        "n_strings": len(srefs),
    }
    return out


FINGERPRINT_RULE = [
    "bytes_sha256 = 函数体原始字节的 SHA-256（不做重定位归一）；只在「区间有证据"
    "（符号长度或控制流终点）且字节全取到」时给出，否则留空",
    "insn_sha256 = 规范化指令序列（助记符 + 操作数；落在可执行区间里的地址归一成 "
    "<CODE>，其余立即数保留）",
    "cfg_sha256 = 逐条指令的控制流类别序列（B=带目标跳转 / R=返回 / i=普通）",
    "strings_sha256 = 该函数引用的字符串文案（佐证，不是判据）",
]


def index_functions(unit, funcs, insns, string_refs=(), *, notes=()) -> dict:
    """把一条条函数变成指纹库（可写盘做 FID 库）。"""
    ranges = list(unit.code_ranges)
    strings = [(r.get("from"), r.get("text") or "") for r in (string_refs or ())]
    rows = [fingerprint(unit, f, insns or {}, ranges, strings) for f in funcs]
    return {
        "format": SIG_FORMAT,
        "version": FP_VERSION,
        "arch": dict(unit.arch or {}),
        "container": getattr(unit, "container", ""),
        "functions": rows,
        "fingerprint_rule": list(FINGERPRINT_RULE),
        "notes": list(notes or ()),
    }


# ----------------------------------------------------------------------
# 匹配
# ----------------------------------------------------------------------
def _identity_names(side) -> dict:
    """可做名字配对的条目：observed 且不是自动名，且该名字在**本侧唯一**。"""
    by = {}
    for i, f in enumerate(side):
        if str(f.get("confidence") or "") != "observed":
            continue
        nm = str(f.get("name") or "")
        if not nm or is_auto_name(nm):
            continue
        by.setdefault(nm, []).append(i)
    return by


def _group(side, idxs, key):
    by = {}
    for i in idxs:
        k = side[i].get(key) or ""
        if k:
            by.setdefault(k, []).append(i)
    return by


def _brief(f: dict) -> dict:
    return {"name": f.get("name"), "addr_hex": f.get("addr_hex"),
            "size": f.get("size"), "size_trust": f.get("size_trust"),
            "insn_count": f.get("insn_count"),
            "bytes_sha256": f.get("bytes_sha256"),
            "insn_sha256": f.get("insn_sha256")}


def match(left: dict, right: dict, *, min_insns: int = 6,
          max_groups: int = 200) -> dict:
    """把两份指纹库配对。返回分组结果，**不断言行为等价**。"""
    L = list(left.get("functions") or [])
    R = list(right.get("functions") or [])
    fam_l = (left.get("arch") or {}).get("family") or ""
    fam_r = (right.get("arch") or {}).get("family") or ""
    limits = [
        "清单完整度未知（inventory_complete=False）：函数集合来自符号表 / 向量表 / "
        "调用目标 / 字面量代码指针，可能漏函数（尤其中间被间接调用、或整段被优化掉的）",
        "only_left / only_right 只说明「在本次两份清单里没有精确对应」——重命名、内联、"
        "strip、字节变动、发现不全都能解释它们，**不证明源码有增删**",
        "名字配对只证明「两侧符号表写了同一个名字」，不证明函数体没改；"
        "bytes 配对只证明函数体字节相同，**不推断行为等价**（调用上下文、自修改代码、"
        "未归一化重定位都不在这个判据里）",
        "size_trust=guessed 的函数（边界是「下一个入口」猜的）不参与字节配对",
        "重复的候选保持 unresolved 组，不展开笛卡尔积",
    ]
    if fam_l and fam_r and fam_l != fam_r:
        return {"ok": False,
                "error": "两侧架构不同（%s vs %s）：字节与指令指纹都不可比，"
                         "不做匹配" % (fam_l, fam_r),
                "hint": "确认两条路径是不是同一颗芯片的两个版本；"
                        "裸 bin 可用 arch/endian/bits/thumb 显式指定"}
    if not fam_l or not fam_r:
        limits.append("有一侧架构未判定：字节配对已禁用（不知道是不是同一个指令集），"
                      "只做名字配对")

    used_l, used_r = set(), set()
    matches, groups = [], []

    def add(basis, li, ri, state="matched", extra=None):
        nonlocal matches
        rec = {"state": state, "basis": basis,
               # 地址只是**事实**：相同不代表同一份代码（不同版本可能刚好放在同一处），
               # 不同也不代表代码改了（整体搬移过）。判断一律看 basis。
               "addr_equal": L[li].get("addr_hex") == R[ri].get("addr_hex"),
               "left": _brief(L[li]), "right": _brief(R[ri])}
        if extra:
            rec.update(extra)
        matches.append(rec)
        used_l.add(li)
        used_r.add(ri)

    # ① 唯一精确名（observed、非自动名）
    bl, br = _identity_names(L), _identity_names(R)
    n_by_name = 0
    for name, li in bl.items():
        ri = br.get(name)
        if len(li) != 1 or not ri or len(ri) != 1:
            continue
        a, b = li[0], ri[0]
        sl, sr = L[a].get("bytes_sha256") or "", R[b].get("bytes_sha256") or ""
        same = (sl == sr) if (sl and sr) else None
        add("name", a, b, extra={
            "bytes_equal": same,
            "note": ("名字相同且函数体字节相同" if same is True else
                     "名字相同但函数体字节**不同**（代码改过，或边界/采集不同）"
                     if same is False else
                     "名字相同；函数体字节无法判定（区间或架构证据不足）")})
        n_by_name += 1

    # 名字重复的组：不是「配不上」，而是「名字对上了但一侧有多条同名」——留给 unresolved
    for name, li in bl.items():
        ri = br.get(name) or []
        if len(li) == 1 and len(ri) == 1:
            continue
        if not ri:
            continue
        groups.append({"reason": "duplicate_name", "name": name,
                       "left": [_brief(L[i]) for i in li[:8]],
                       "right": [_brief(R[j]) for j in ri[:8]],
                       "n_left": len(li), "n_right": len(ri)})
        used_l.update(li)
        used_r.update(ri)

    # ② 字节指纹（区间有证据 + 两侧唯一 + 架构已知且相同）
    n_by_bytes = 0
    if fam_l and fam_r:
        # 字节配对再守一次：只收「区间有证据（size_trust != guessed）」的条目。
        # 指纹层已保证 guessed 不出 bytes_sha256，这里是防御——手写的 index 或
        # 外部 .sig.json 都不能凭一个字节指纹把猜出来的边界认可成 identical。
        rest_l = [i for i in range(len(L)) if i not in used_l
                  and L[i].get("size_trust") != "guessed"]
        rest_r = [j for j in range(len(R)) if j not in used_r
                  and R[j].get("size_trust") != "guessed"]
        gl = _group(L, rest_l, "bytes_sha256")
        gr = _group(R, rest_r, "bytes_sha256")
        for fp, li in gl.items():
            ri = gr.get(fp)
            if not ri:
                continue
            if len(li) == 1 and len(ri) == 1:
                add("bytes", li[0], ri[0])
                n_by_bytes += 1
            else:
                groups.append({"reason": "duplicate_bytes",
                               "bytes_sha256": fp,
                               "left": [_brief(L[i]) for i in li[:8]],
                               "right": [_brief(R[j]) for j in ri[:8]],
                               "n_left": len(li), "n_right": len(ri)})
                used_l.update(li)
                used_r.update(ri)

    # ③ 结构候选（指令指纹唯一；长度门槛挡掉「两条指令满街都是」）
    n_cand = 0
    rest_l = [i for i in range(len(L))
              if i not in used_l and int(L[i].get("insn_count") or 0) >= int(min_insns)]
    rest_r = [j for j in range(len(R))
              if j not in used_r and int(R[j].get("insn_count") or 0) >= int(min_insns)]
    gl = _group(L, rest_l, "insn_sha256")
    gr = _group(R, rest_r, "insn_sha256")
    for fp, li in gl.items():
        ri = gr.get(fp)
        if not ri:
            continue
        if len(li) == 1 and len(ri) == 1:
            a, b = li[0], ri[0]
            same_cfg = (L[a].get("cfg_sha256") or "") == (R[b].get("cfg_sha256") or "")
            add("insn_fingerprint", a, b, state="candidate", extra={
                "cfg_equal": same_cfg,
                "note": "指令序列相同（地址已归一），但**不是**字节相同："
                        "可能是同一份代码被重定位过，也可能是不同源码编出同样的指令。"
                        "这条只作候选，不作等价断言"})
            n_cand += 1
        else:
            groups.append({"reason": "duplicate_insn",
                           "insn_sha256": fp,
                           "left": [_brief(L[i]) for i in li[:8]],
                           "right": [_brief(R[j]) for j in ri[:8]],
                           "n_left": len(li), "n_right": len(ri)})
            used_l.update(li)
            used_r.update(ri)

    only_l = [i for i in range(len(L)) if i not in used_l]
    only_r = [j for j in range(len(R)) if j not in used_r]

    matched = [m for m in matches if m["state"] == "matched"]
    return {
        "ok": True,
        "arch": {"left": fam_l or "unknown", "right": fam_r or "unknown"},
        "counts": {
            "matched": len(matched),
            "by_name": n_by_name,
            "by_bytes": n_by_bytes,
            "candidates": n_cand,
            "unresolved_groups": len(groups),
            "only_left": len(only_l),
            "only_right": len(only_r),
        },
        "matches": matches,
        "unresolved": groups[:max_groups],
        "unresolved_truncated": len(groups) > max_groups,
        "only_left": [_brief(L[i]) for i in only_l],
        "only_right": [_brief(R[j]) for j in only_r],
        "coverage": {
            "inventory_complete": False,
            "left": side_coverage(L),
            "right": side_coverage(R),
            "note": "matched + candidates + unresolved 成员 + only_* 覆盖两侧全部条目；"
                    "inventory_complete 恒为 False——本工具不知道「本该有多少个函数」",
        },
        "fingerprint_rule": list(FINGERPRINT_RULE),
        "limitations": limits,
    }


def side_coverage(side) -> dict:
    n = len(side)
    named = sum(1 for f in side
                if str(f.get("confidence") or "") == "observed"
                and not is_auto_name(f.get("name")))
    trusted = sum(1 for f in side if f.get("size_trust") in ("symtab", "control_flow"))
    with_bytes = sum(1 for f in side if f.get("bytes_sha256"))
    with_insn = sum(1 for f in side if f.get("insn_sha256"))
    return {"functions": n, "named_observed": named, "size_trusted": trusted,
            "with_bytes_sha256": with_bytes, "with_insn_sha256": with_insn}


# ----------------------------------------------------------------------
# 指纹库文件（FID 库）
# ----------------------------------------------------------------------
def save_sig(path: str, sig: dict, *, source=None, overwrite: bool = False) -> dict:
    """写指纹库。**默认不覆盖**——已有的库是证据，不该被静默替换。"""
    p = os.path.abspath(str(path or ""))
    if not p:
        return {"ok": False, "error": "没给路径"}
    if os.path.exists(p) and not overwrite:
        return {"ok": False,
                "error": "指纹库已存在：%s" % p,
                "hint": "换一个路径；确要替换请显式 overwrite=true（旧库会被覆盖）"}
    parent = os.path.dirname(p)
    if parent and not os.path.isdir(parent):
        return {"ok": False, "error": "父目录不存在：%s" % parent}
    doc = dict(sig)
    doc["source"] = source or {}
    doc["created"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    blob = json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")
    with open(p, "wb") as f:
        f.write(blob)
    back = open(p, "rb").read()
    if back != blob:                      # 写完回读：产物必须能自证
        return {"ok": False, "error": "回读不一致（磁盘上的内容与写入的不同）"}
    return {"ok": True, "path": p, "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "functions": len(doc.get("functions") or [])}


def load_sig(path: str) -> dict:
    p = os.path.abspath(str(path or ""))
    if not os.path.isfile(p):
        return {"ok": False, "error": "指纹库不存在：%s" % p}
    try:
        with open(p, "rb") as f:
            doc = json.loads(f.read().decode("utf-8"))
    except Exception as e:                # noqa: BLE001
        return {"ok": False, "error": "指纹库读不出来（不是合法 JSON）：%s" % e}
    if not isinstance(doc, dict) or doc.get("format") != SIG_FORMAT:
        return {"ok": False,
                "error": "这不是本工具的指纹库（format 应为 %s，实际 %r）"
                         % (SIG_FORMAT, (doc or {}).get("format")
                            if isinstance(doc, dict) else None)}
    if int(doc.get("version") or 0) != FP_VERSION:
        return {"ok": False,
                "error": "指纹库版本 %s 与当前 %d 不兼容：指纹规则改过之后旧库不可比"
                         % (doc.get("version"), FP_VERSION),
                "hint": "用同一版本重新生成指纹库（不混用两代指纹）"}
    if not isinstance(doc.get("functions"), list):
        return {"ok": False, "error": "指纹库里没有 functions 列表"}
    return {"ok": True, **doc}
