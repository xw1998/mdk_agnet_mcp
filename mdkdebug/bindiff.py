# -*- coding: utf-8 -*-
"""两镜像逐函数差分（批次102）。

为什么不是「字节 diff」：两张镜像整体搬移、链接顺序变化、地址常量重定位，
逐字节比会满屏红。这里做的是**函数级**三态判定，每个判词都有明确判据：

  * ``PASS``    —— 函数体规范化指令序列相同（地址类操作数已归一）。字节可以不同，
                   因为重定位会改地址常量；**不同 **不代表代码改了。
  * ``RESIDUE`` —— 结构对得上（把所有立即数都抹平后序列相同，或相似度超阈值），
                   差异只落在常量上。**必须人工看**：可能是参数改了，也可能是
                   数据地址挪了。报告逐条列出残余差异在哪一条指令上。
  * ``FAIL``    —— 配上了但指令序列实质不同（真的改了），或者一侧里根本没有对应函数。

外加「外设窗口逐窗对比」：``GPIOA@0x40020000+0x400`` 这样的窗口里，
两侧各访问了哪些偏移、读还是写、几次。窗口判词同三态。

写盘产物是**证据**（批次101 的口径）：``report.json`` / ``report.md`` /
``windows.csv``，全部 utf-8 无 BOM，带 ``evidence_only: true``，并过落盘护栏。
"""
import difflib
import os
import re

from . import evidence as _evidence
from . import recover as _recover
from . import textio as _textio

MAX_LIST = 400
_IMM_RE = re.compile(r"(?:#?-?0x[0-9A-Fa-f]+|#-?\d+|(?<![\w.])-?\d+(?![\w.]))")


def _norm_text(ins: dict) -> str:
    return ("%s %s" % ((ins.get("mnemonic") or "").lower(),
                       (ins.get("op_str") or "").lower())).strip()


def _mask(text: str) -> str:
    """把**所有**立即数抹平（含数据地址、外设地址）：用来判「结构是否还在」。"""
    return _IMM_RE.sub("#<I>", text)


def _norm_code(text: str, ranges) -> str:
    """只抹平落在**可执行区间**里的地址（跳转/调用目标）——重定位会改它，语义没改。"""
    def rep(m):
        tok = m.group(0)
        raw = tok.lstrip("#")
        try:
            v = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            return tok
        inside = any(a <= (v & ~1) < b for a, b in ranges)
        return "#<CODE>" if inside else tok
    return _IMM_RE.sub(rep, text)


def _side(path: str, base: int, *, deep: bool, max_functions: int,
          max_insns: int) -> dict:
    an = _recover.analyze(path, base=base, deep=deep,
                          max_functions=max_functions, max_insns=max_insns)
    if not an.get("ok"):
        return {"ok": False, "error": an.get("error"), "path": path}
    unit = an.pop("_unit")
    rec = an.pop("_recover")
    insns = rec.get("_insns") or {}
    funcs = rec.get("functions") or []
    rel = rec.get("_relations") or {}
    ranges = list(unit.code_ranges)
    rows = []
    for f in funcs:
        start = int(f.get("addr") or 0)
        end = int(f.get("end_addr") or start)
        body = unit.read(start, max(0, end - start)) if end > start else b""
        toks, code_toks = [], []
        for a in sorted(k for k in insns if start <= k < end):
            t = _norm_text(insns[a])
            toks.append(_mask(t))
            code_toks.append(_norm_code(t, ranges))
        rows.append({
            "addr": start, "addr_hex": "0x%08X" % start,
            "end_hex": "0x%08X" % end,
            "name": f.get("name") or "sub_%08X" % start,
            "auto_name": (f.get("name") or "").startswith(("sub_", "ptr_", "handler_")),
            "confidence": f.get("confidence") or "",
            "size": max(0, end - start),
            "sha_bytes": _sha(body),
            "code": "\n".join(code_toks),
            "masked": "\n".join(toks),
            "n_insns": len(toks),
            "bytes": body,
        })
    return {"ok": True, "path": path, "unit": unit, "rows": rows,
            "rel": rel, "insns": insns, "gaps": an.get("gaps") or [],
            "arch": (unit.arch or {}).get("family") or "",
            "image": {"name": os.path.basename(path),
                      "container": unit.container,
                      "base_hex": "0x%08X" % unit.base_used,
                      "functions": len(rows)}}


def _sha(blob: bytes) -> str:
    import hashlib
    return hashlib.sha256(blob or b"").hexdigest()


def _unique(rows, key):
    by = {}
    for i, r in enumerate(rows):
        k = r.get(key) or ""
        if k:
            by.setdefault(k, []).append(i)
    return by


def _pair(L, R, *, min_insns: int, threshold: float) -> dict:
    used_l, used_r, pairs = set(), set(), []

    def take(li, ri, basis, extra=None):
        p = {"basis": basis, "left": li, "right": ri}
        if extra:
            p.update(extra)
        pairs.append(p)
        used_l.add(li)
        used_r.add(ri)

    # ① 唯一非自动名
    bl = {r["name"]: i for i, r in enumerate(L)
          if not r["auto_name"] and r["confidence"] == "observed"
          and sum(1 for x in L if x["name"] == r["name"]) == 1}
    br = {r["name"]: i for i, r in enumerate(R)
          if not r["auto_name"] and r["confidence"] == "observed"
          and sum(1 for x in R if x["name"] == r["name"]) == 1}
    for nm, li in bl.items():
        if nm in br:
            take(li, br[nm], "name")

    # ② 函数体字节相同（唯一）
    for key, basis in (("sha_bytes", "bytes"),):
        gl = {k: v for k, v in _unique(L, key).items()
              if len(v) == 1 and v[0] not in used_l}
        gr = {k: v for k, v in _unique(R, key).items()
              if len(v) == 1 and v[0] not in used_r}
        for k, v in gl.items():
            if k in gr:
                take(v[0], gr[k][0], basis)

    # ③ 指令序列相同（代码地址已归一 → 重定位过）
    for key, basis in (("code", "insn_code_norm"), ("masked", "insn_raw_norm")):
        gl = {k: v for k, v in _unique(L, key).items()
              if len(v) == 1 and v[0] not in used_l
              and L[v[0]]["n_insns"] >= min_insns}
        gr = {k: v for k, v in _unique(R, key).items()
              if len(v) == 1 and v[0] not in used_r
              and R[v[0]]["n_insns"] >= min_insns}
        for k, v in gl.items():
            if k in gr:
                take(v[0], gr[k][0], basis)

    # ④ 相似度兜底：只在「剩余」里做一对一贪心，且必须两边都对得上
    rest_l = [i for i in range(len(L)) if i not in used_l]
    rest_r = [j for j in range(len(R)) if j not in used_r]
    cand = []
    for i in rest_l:
        if L[i]["n_insns"] < min_insns:
            continue
        for j in rest_r:
            if R[j]["n_insns"] < min_insns:
                continue
            sm = difflib.SequenceMatcher(None, L[i]["masked"], R[j]["masked"])
            if sm.quick_ratio() < threshold:
                continue
            r = sm.ratio()
            if r >= threshold:
                cand.append((r, i, j))
    cand.sort(reverse=True)
    for r, i, j in cand:
        if i in used_l or j in used_r:
            continue
        take(i, j, "similarity", {"similarity": round(r, 4)})
    return {"pairs": pairs,
            "only_left": [i for i in range(len(L)) if i not in used_l],
            "only_right": [j for j in range(len(R)) if j not in used_r]}


def _diff_detail(a: dict, b: dict, limit: int = 12) -> list:
    """逐条列出残余差异：位置、左侧指令、右侧指令。"""
    la, lb = a["masked"].split("\n"), b["masked"].split("\n")
    out = []
    for n, (x, y) in enumerate(zip(la, lb)):
        if x != y:
            out.append({"insn_index": n, "left": x, "right": y})
            if len(out) >= limit:
                break
    if len(la) != len(lb):
        out.append({"insn_index": min(len(la), len(lb)),
                    "left": "%d 条指令" % len(la),
                    "right": "%d 条指令" % len(lb),
                    "note": "两侧指令条数不同：差异后面还有"})
    return out


def _parse_windows(spec: str) -> list:
    out = []
    for tok in (spec or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        name = ""
        body = tok
        if "@" in tok:
            name, body = tok.split("@", 1)
            name, body = name.strip(), body.strip()
        if "+" in body:
            start, size = body.split("+", 1)
            start, size = _num(start), _num(size)
            if start is None or size is None:
                raise ValueError("窗口写法是 name@起始+长度（收到 %r）" % tok)
            out.append({"name": name or "0x%08X" % start, "start": start,
                        "end": start + size})
        elif "-" in body and not body.startswith("-"):
            a, b = body.split("-", 1)
            a, b = _num(a), _num(b)
            if a is None or b is None or b <= a:
                raise ValueError("窗口写法是 name@起始-结束（收到 %r）" % tok)
            out.append({"name": name or "0x%08X" % a, "start": a, "end": b})
        else:
            raise ValueError("窗口写法是 name@0x40020000+0x400 或 name@0x40020000-0x40020400"
                             "（收到 %r）" % tok)
    return out


def _num(s: str):
    s = (s or "").strip()
    try:
        return int(s, 0)
    except ValueError:
        return None


def _window_access(rel: dict, win: dict) -> dict:
    hits = {}
    for x in (rel.get("xrefs") or {}).get("xrefs") or []:
        if x.get("kind") not in ("data_read", "data_write"):
            continue
        a = int(x.get("to") or 0)
        if not (win["start"] <= a < win["end"]):
            continue
        key = (a - win["start"], x.get("kind"), int(x.get("width") or 4))
        h = hits.setdefault(key, {"offset": key[0], "kind": key[1], "width": key[2],
                                  "count": 0, "sites": []})
        h["count"] += 1
        if len(h["sites"]) < 4:
            h["sites"].append({"from_hex": x.get("from_hex"),
                               "insn": x.get("insn") or ""})
    return {"items": sorted(hits.values(), key=lambda d: (d["offset"], d["kind"])),
            "total": sum(v["count"] for v in hits.values()),
            "n_offsets": len({k[0] for k in hits})}


def _window_verdict(a: dict, b: dict) -> dict:
    la = {(i["offset"], i["kind"]): i for i in a["items"]}
    lb = {(i["offset"], i["kind"]): i for i in b["items"]}
    only_l = [la[k] for k in la if k not in lb]
    only_r = [lb[k] for k in lb if k not in la]
    count_diff = []
    for k in la:
        if k in lb and la[k]["count"] != lb[k]["count"]:
            count_diff.append({"offset": k[0], "kind": k[1],
                               "reference": la[k]["count"], "target": lb[k]["count"]})
    width_diff = []
    for k in la:
        if k in lb and la[k]["width"] != lb[k]["width"]:
            width_diff.append({"offset": k[0], "kind": k[1],
                               "reference": la[k]["width"], "target": lb[k]["width"]})
    if only_l or only_r:
        verdict, reasons = "FAIL", ["访问的偏移集合不同：一侧有、另一侧没有"]
    elif count_diff:
        verdict, reasons = "RESIDUE", ["访问的偏移相同，但次数不同（初始化/轮询次数变了？）"]
    elif width_diff:
        verdict, reasons = "PASS", ["宽度不同但偏移与读写方向一致（不影响地址判据）"]
    else:
        verdict, reasons = "PASS", ["访问的偏移、读写方向、次数完全一致"]
    return {"verdict": verdict, "reasons": reasons,
            "only_reference": only_l[:40], "only_target": only_r[:40],
            "count_diff": count_diff[:40], "width_diff": width_diff[:40],
            "reference_total": a["total"], "target_total": b["total"],
            "reference_offsets": a["n_offsets"], "target_offsets": b["n_offsets"]}


def compare(reference: str, target: str, *, base: int = 0, base_target: int = 0,
            windows: str = "", out_dir: str = "", name: str = "bindiff",
            max_functions: int = 4000, max_insns: int = 400000,
            min_insns: int = 4, threshold: float = 0.9,
            deep: bool = True) -> dict:
    """逐函数比两张镜像。返回 PASS/RESIDUE/FAIL 三态与逐窗口对比。"""
    if not reference or not target:
        return {"ok": False, "error": "需要 reference 与 target 两张镜像"}
    L = _side(reference, base, deep=deep, max_functions=max_functions,
              max_insns=max_insns)
    if not L.get("ok"):
        return {"ok": False, "error": "参考镜像读取失败：%s" % L.get("error"),
                "side": "reference"}
    R = _side(target, base_target, deep=deep, max_functions=max_functions,
              max_insns=max_insns)
    if not R.get("ok"):
        return {"ok": False, "error": "目标镜像读取失败：%s" % R.get("error"),
                "side": "target"}
    if L["arch"] and R["arch"] and L["arch"] != R["arch"]:
        return {"ok": False,
                "error": "两侧架构不同（%s vs %s）：指令不可比，不做差分"
                         % (L["arch"], R["arch"])}

    pr = _pair(L["rows"], R["rows"], min_insns=min_insns, threshold=threshold)
    items = []
    counts = {"PASS": 0, "RESIDUE": 0, "FAIL": 0}
    for p in pr["pairs"]:
        a, b = L["rows"][p["left"]], R["rows"][p["right"]]
        if a["code"] == b["code"]:
            status, why = "PASS", "规范化指令序列相同（可执行地址已归一）"
        elif a["sha_bytes"] == b["sha_bytes"]:
            status, why = "PASS", "函数体字节逐字节相同"
        elif a["masked"] == b["masked"]:
            status, why = "RESIDUE", "结构完全相同，差异只在立即数（地址/常量）上"
        else:
            ratio = p.get("similarity")
            if ratio is None:
                sm = difflib.SequenceMatcher(None, a["masked"], b["masked"])
                ratio = round(sm.ratio(), 4)
            if p["basis"] in ("name", "bytes") or ratio >= 0.98:
                status, why = "FAIL", "配上了但指令序列有实质差异"
            elif ratio >= threshold:
                status, why = "RESIDUE", "相似度 %.3f：结构大体还在，需人工看差异" % ratio
            else:
                status, why = "FAIL", "相似度 %.3f 低于阈值：不是同一个函数" % ratio
        rec = {"status": status, "basis": p["basis"], "why": why,
               "left": {"addr_hex": a["addr_hex"], "name": a["name"],
                        "size": a["size"], "n_insns": a["n_insns"],
                        "sha_bytes": a["sha_bytes"][:16]},
               "right": {"addr_hex": b["addr_hex"], "name": b["name"],
                         "size": b["size"], "n_insns": b["n_insns"],
                         "sha_bytes": b["sha_bytes"][:16]},
               "byte_identical": a["sha_bytes"] == b["sha_bytes"],
               "insn_identical": a["code"] == b["code"]}
        if status != "PASS":
            rec["differences"] = _diff_detail(a, b)
            if status == "RESIDUE":
                rec["residue_kind"] = ("immediates_only" if a["masked"] == b["masked"]
                                       else "structural_shift")
        counts[status] += 1
        items.append(rec)
    for i in pr["only_left"]:
        a = L["rows"][i]
        counts["FAIL"] += 1
        items.append({"status": "FAIL", "basis": "missing_in_target",
                      "why": "参考镜像里有、目标镜像里找不到对应（删了/被内联/规则外重构）",
                      "left": {"addr_hex": a["addr_hex"], "name": a["name"],
                               "size": a["size"], "n_insns": a["n_insns"]},
                      "right": None})
    for j in pr["only_right"]:
        b = R["rows"][j]
        counts["FAIL"] += 1
        items.append({"status": "FAIL", "basis": "missing_in_reference",
                      "why": "目标镜像里有、参考镜像里找不到对应（新增/被内联）",
                      "left": None,
                      "right": {"addr_hex": b["addr_hex"], "name": b["name"],
                                "size": b["size"], "n_insns": b["n_insns"]}})
    items.sort(key=lambda r: {"FAIL": 0, "RESIDUE": 1, "PASS": 2}[r["status"]])

    win_out = []
    try:
        wins = _parse_windows(windows)
    except ValueError as e:
        return {"ok": False, "error": str(e),
                "hint": "窗口写法：GPIOA@0x40020000+0x400 或 0x40020000-0x40020400，"
                        "多个用逗号分隔"}
    for w in wins:
        A = _window_access(L.get("rel") or {}, w)
        B = _window_access(R.get("rel") or {}, w)
        v = _window_verdict(A, B)
        rec = {"name": w["name"],
               "start_hex": "0x%08X" % w["start"], "end_hex": "0x%08X" % w["end"],
               "size": w["end"] - w["start"],
               "reference_accesses": A["items"][:60],
               "target_accesses": B["items"][:60]}
        rec.update(v)
        win_out.append(rec)

    res = {
        "ok": True,
        "reference": L["image"],
        "target": R["image"],
        "counts": dict(counts, pairs=len(pr["pairs"]),
                       only_reference=len(pr["only_left"]),
                       only_target=len(pr["only_right"])),
        "functions": items[:MAX_LIST],
        "truncated": len(items) > MAX_LIST,
        "windows": win_out,
        "verdict_rule": [
            "PASS：规范化指令序列相同（可执行区间里的地址已归一成 <CODE>），"
            "或函数体字节逐字节相同。字节不同**不**扣分——重定位会改地址常量",
            "RESIDUE：指令序列在「把所有立即数都抹平」后相同，或相似度 ≥ 阈值。"
            "差异集中在常量上，必须人工看是哪一类（数据地址/外设地址/参数）",
            "FAIL：配上了但序列有实质差异，或一侧根本没有对应函数（missing_in_*）",
            "配对顺序：唯一非自动名 → 字节相同 → 指令序列相同 → 相似度贪心。"
            "相似度只在剩余集合里做一对一，不展开笛卡尔积",
        ],
        "limitations": [
            "函数集合来自符号表/向量表/调用目标/代码指针：**清单完整度未知**，"
            "missing_in_* 不能单独证明源码有增删（内联、strip、发现不全都能解释）",
            "PASS 只说明「这段机器码没变」，不证明运行行为相同（调用上下文、"
            "全局状态、中断时序都不在这个判据里）",
            "相似度用的是指令文本序列（difflib），不是语义等价判定",
            "窗口对比只看静态可解析的访存：寄存器间接寻址落在外设窗口里的访问"
            "会漏（那是 unresolved，不在这里猜）",
        ],
        "gaps": (L.get("gaps") or []) + (R.get("gaps") or []),
    }
    if out_dir:
        res.update(_write_reports(res, out_dir, name, L, R, win_out, pr))
    return res


# ----------------------------------------------------------------------
# 报告落盘（证据，批次101 口径：utf-8 无 BOM + evidence_only + 护栏）
# ----------------------------------------------------------------------
def _md_report(res: dict) -> str:
    c = res["counts"]
    lines = [
        "# 两镜像逐函数差分报告",
        "",
        "- 参考：%s（%s，base %s，%d 个函数）"
        % (res["reference"]["name"], res["reference"]["container"],
           res["reference"]["base_hex"], res["reference"]["functions"]),
        "- 目标：%s（%s，base %s，%d 个函数）"
        % (res["target"]["name"], res["target"]["container"],
           res["target"]["base_hex"], res["target"]["functions"]),
        "",
        "| 判词 | 数量 |",
        "| --- | --- |",
        "| PASS | %d |" % c["PASS"],
        "| RESIDUE | %d |" % c["RESIDUE"],
        "| FAIL | %d |" % c["FAIL"],
        "| 只在一侧（reference） | %d |" % c.get("only_reference", 0),
        "| 只在一侧（target） | %d |" % c.get("only_target", 0),
        "",
        "## 判据",
        "",
    ]
    lines += ["- " + x for x in res.get("verdict_rule") or []]
    lines += ["", "## 非 PASS 明细", "",
              "| 判词 | 依据 | 参考侧 | 目标侧 | 说明 |",
              "| --- | --- | --- | --- | --- |"]
    for it in res.get("functions") or []:
        if it["status"] == "PASS":
            continue
        l = it.get("left") or {}
        r = it.get("right") or {}
        lines.append("| %s | %s | %s %s | %s %s | %s |"
                     % (it["status"], it["basis"],
                        l.get("addr_hex") or "-", l.get("name") or "",
                        r.get("addr_hex") or "-", r.get("name") or "",
                        it["why"]))
    if res.get("windows"):
        lines += ["", "## 外设窗口", "",
                  "| 窗口 | 范围 | 判词 | 参考访问 | 目标访问 | 说明 |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for w in res["windows"]:
            lines.append("| %s | %s..%s | %s | %d | %d | %s |"
                         % (w["name"], w["start_hex"], w["end_hex"], w["verdict"],
                            w["reference_total"], w["target_total"],
                            "；".join(w["reasons"])))
    lines += ["", "## 限制", ""]
    lines += ["- " + x for x in res.get("limitations") or []]
    return "\n".join(lines) + "\n"


def _write_reports(res: dict, out_dir: str, name: str, L: dict, R: dict,
                   windows: list, pr: dict) -> dict:
    """把报告写成证据：report.json / report.md / windows.csv（无 BOM）。"""
    import json
    dest = os.path.abspath(out_dir)
    bad = _evidence.violation(dest)
    if bad:
        return {**_evidence.refusal(dest, bad), "out_dir": dest}
    if os.path.exists(dest) and os.listdir(dest):
        return {"ok": False, "out_dir": dest,
                "error": "输出目录非空：%s —— 报告不复用目录（不覆盖既有证据）" % dest,
                "hint": "换一个不存在或空的目录"}
    os.makedirs(dest, exist_ok=True)
    files = []
    payload = {k: v for k, v in res.items() if k not in ("code",)}
    payload["evidence_only"] = True
    payload["artifact_kind"] = "evidence"
    payload["image_pair"] = {"reference": res["reference"]["name"],
                             "target": res["target"]["name"]}
    payload["evidence_only_files"] = ["report.json", "report.md", "windows.csv"]
    _textio.write_text(os.path.join(dest, "report.json"),
                       json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    files.append("report.json")
    _textio.write_text(os.path.join(dest, "report.md"),
                       "# EVIDENCE ONLY（mdkdebug bindiff）\n\n" + _md_report(res))
    files.append("report.md")
    rows = []
    for w in windows:
        rows.append([w["name"], w["start_hex"], w["end_hex"], w["verdict"],
                     w["reference_total"], w["target_total"],
                     w["reference_offsets"], w["target_offsets"],
                     "；".join(w["reasons"])])
    _textio.write_csv(os.path.join(dest, "windows.csv"),
                      ["window", "start", "end", "verdict", "reference_accesses",
                       "target_accesses", "reference_offsets", "target_offsets",
                       "reasons"], rows)
    files.append("windows.csv")
    return {"out_dir": dest, "files": files,
            "evidence_only": True,
            "wrote_bom": _textio.has_bom(os.path.join(dest, "windows.csv"))}
