# -*- coding: utf-8 -*-
"""Keil 分散加载文件（``.sct``）的**受控编辑**（批次47）。

为什么不能整文件重写
--------------------
``.sct`` 里除了区域与段选择器，还常常有注释、对齐用的空格、Keil 自己写进去的
说明行。用「解析成对象再序列化」的办法写回去，会把这些**全部抹掉**，产生一个
「语义等价但面目全非」的 diff——用户下次打开 Keil 或跑生成脚本，两边又打架。

故本模块与 uvprojx.py / uvoptx.py 同一套思路：**按行**解析、**按行**改，
未涉及的行一字不动（包括行尾、缩进、注释）。写之前强制备份、锚点必须唯一，
写之后**重新解析校验**，不合格直接回滚。

支持的结构（Keil 的 .sct 实际写法）
-----------------------------------
```
LR_IROM1 0x08000000 0x00100000  {    ; load region
  ER_IROM1 0x08000000 0x00100000  {
   *.o (RESET, +First)
   .ANY (+RO)
  }
  RW_IRAM1 0x20000000 0x00030000  {
   .ANY (+RW +ZI)
  }
}
```
- 区域头：`名字 [基址] [长度] {`，基址/长度可省；基址允许 `+N`（相对上一区域末尾）。
- 段选择器：`*.o (RESET, +First)`、`.ANY (+RW +ZI)`、各类 `+First`/`+Last` 修饰。
- 注释：`;` 起到行尾。

诚实边界
--------
- 解析是**面向行**的：把整块写在一行（`ER_IROM1 0x08000000 { ... }`）这类极端写法
  会被判为 `unparsable`，工具**拒绝改**而不是猜着改。
- 越界/重叠校验需要芯片内存布局；不提供 `memmap` 时只做「同层自重叠」这一层，
  绝不假设某个器件的地图。
"""
from __future__ import annotations

import os
import re
import shutil

# 区域头：名字 + 可选基址（0x... 或 +N） + 可选长度（0x... 或十进制）
_HEAD_RE = re.compile(
    r"^(?P<name>[^\s{,]+)"
    r"(?:\s+(?P<base>(?:0[xX][0-9A-Fa-f]+|\+\s*0[xX][0-9A-Fa-f]+|\+\s*\d+|\d+)))?"
    r"(?:\s+(?P<size>(?:0[xX][0-9A-Fa-f]+|\d+)))?\s*\{$")

def _read_text(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"

def _backup(path: str) -> str:
    bak = path + ".mdkdebug.bak"
    shutil.copy2(path, bak)
    return bak

def _strip_comment(line: str) -> str:
    i = line.find(";")
    return line if i < 0 else line[:i]

def _to_int(s):
    if s is None:
        return None
    t = str(s).strip()
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if re.fullmatch(r"\d+", t):
            return int(t, 10)
    except (TypeError, ValueError):
        return None
    return None

def resolve_path(path: str) -> str:
    """收下用户给的路径：目录（或工程目录）就找里面唯一的 .sct。

    不在目录里瞎猜：找到 0 个或多个 .sct 都如实报错并把候选列出来。
    """
    p = str(path or "").strip().strip('"')
    if not p:
        return ""
    if not os.path.isabs(p):
        p = os.path.abspath(p)
    if os.path.isdir(p):
        cands = sorted(f for f in os.listdir(p) if f.lower().endswith(".sct"))
        if len(cands) == 1:
            return os.path.join(p, cands[0])
        return p if not cands else p     # 交给调用方报错（保留目录信息）
    return p

def parse(text: str) -> dict:
    """把 .sct 文本解析成「区域树 + 行索引」。返回的 line 是 0 基行号。

    面向行解析：任何一行不能被归类为「区域头 / 区域尾 / 段选择器」时，
    在 `errors` 里记一笔并把该行标 `kind="unknown"`——不猜、也不丢。
    """
    lines = text.splitlines()
    root = {"name": None, "base": None, "size": None, "base_raw": None,
            "size_raw": None, "line": None, "end_line": None, "selectors": [],
            "children": [], "kind": "root"}
    stack = [root]
    errors = []
    for i, raw in enumerate(lines):
        body = _strip_comment(raw).strip()
        if not body:
            continue
        if body == "}":
            if len(stack) == 1:
                errors.append({"line": i + 1, "reason": "多余的 '}'",
                               "text": raw.strip()})
                continue
            stack[-1]["end_line"] = i
            stack.pop()
            continue
        if body.startswith("}"):
            # `} /* 后面还跟着东西 */` 这种：先收尾，再看剩下的是不是选择器
            if len(stack) == 1:
                errors.append({"line": i + 1, "reason": "多余的 '}'",
                               "text": raw.strip()})
                continue
            stack[-1]["end_line"] = i
            stack.pop()
            rest = body[1:].strip()
            if rest:
                stack[-1]["selectors"].append({"line": i, "text": rest})
            continue
        if "{" in body:
            if not body.endswith("{"):
                errors.append({"line": i + 1,
                               "reason": "区域头与内容写在同一行，本解析器不支持（拒绝改，不猜）",
                               "text": raw.strip()})
                continue
            m = _HEAD_RE.match(body)
            if not m:
                errors.append({"line": i + 1, "reason": "区域头无法解析",
                               "text": raw.strip()})
                continue
            base_raw = m.group("base")
            size_raw = m.group("size")
            node = {"kind": "region", "name": m.group("name"),
                    "base_raw": base_raw, "size_raw": size_raw,
                    "base": _to_int(base_raw),
                    "size": _to_int(size_raw),
                    "base_relative": bool(base_raw and base_raw.strip().startswith("+")),
                    "line": i, "end_line": None, "selectors": [],
                    "children": [],
                    "header_style": {
                        "comma": ", " if ", " in body else " ",
                        "suffix": raw[raw.rfind("{"):] if "{" in raw else "{"}}
            stack[-1]["children"].append(node)
            stack.append(node)
            continue
        stack[-1]["selectors"].append({"line": i, "text": body})
    if len(stack) != 1:
        errors.append({"line": len(lines), "reason": "有 %d 个区域没闭合"
                       % (len(stack) - 1), "text": ""})
    return {"ok": not errors, "errors": errors, "root": root,
            "lines": lines, "regions": _walk(root)}

def _walk(node, out=None, depth=0, parent=None):
    if out is None:
        out = []
    for ch in node.get("children", []):
        item = {"name": ch["name"], "base": ch["base"], "size": ch["size"],
                "base_raw": ch["base_raw"], "size_raw": ch["size_raw"],
                "base_relative": ch["base_relative"],
                "depth": depth, "line": ch["line"], "end_line": ch["end_line"],
                "parent": parent,
                "selectors": [s["text"] for s in ch["selectors"]],
                "is_load_region": depth == 0,
                "children": [c["name"] for c in ch["children"]]}
        out.append(item)
        _walk(ch, out, depth + 1, ch["name"])
    return out

def _find_region(root, name):
    for ch in root.get("children", []):
        if ch["name"] == name:
            return ch, root
        hit = _find_region(ch, name)
        if hit[0] is not None:
            return hit
    return None, None

def _fmt_header(name, base_raw, size_raw, style=None):
    style = style or {}
    parts = [name]
    if base_raw is not None:
        parts.append(str(base_raw))
    if size_raw is not None:
        parts.append(str(size_raw))
    return " ".join(parts) + " {"

def check(path: str, memmap: str = "") -> dict:
    """静态检查：结构、同名、重叠、长度缺失，以及（给了 memmap 时）是否越界。

    `memmap` 写法：`0x08000000:0x00100000,0x20000000:0x00030000`（基址:长度，逗号分隔）。
    不给就不做越界判断——本工具**不内置任何器件的内存地图**。
    """
    real = resolve_path(path)
    if not os.path.isfile(real):
        return {"ok": False, "action": "scatter_check", "error": "文件不存在：%s" % path}
    text, enc = _read_text(real)
    p = parse(text)
    problems = []
    for e in p["errors"]:
        problems.append(dict(e, kind="parse"))
    seen = {}
    for r in p["regions"]:
        if r["name"] in seen:
            problems.append({"kind": "duplicate", "region": r["name"],
                             "line": r["line"] + 1,
                             "reason": "同名区域重复（先出现在第 %d 行）"
                                       % (seen[r["name"]] + 1)})
        else:
            seen[r["name"]] = r["line"]
        if r["size"] is None:
            problems.append({"kind": "no-size", "region": r["name"],
                             "line": r["line"] + 1,
                             "reason": "没有长度；Keil 会按剩余空间自动分配，"
                                       "但受控编辑时无法做重叠/越界校验"})
        elif r["size"] == 0:
            problems.append({"kind": "zero-size", "region": r["name"],
                             "line": r["line"] + 1, "reason": "长度为 0"})
    # 同层重叠
    def _same_level(node):
        abs_items = []
        for ch in node.get("children", []):
            if ch["base"] is not None and not ch["base_relative"] and ch["size"]:
                abs_items.append((ch["base"], ch["base"] + ch["size"], ch["name"],
                                  ch["line"]))
        abs_items.sort()
        for i in range(1, len(abs_items)):
            a0, a1, an, al = abs_items[i - 1]
            b0, b1, bn, bl = abs_items[i]
            if b0 < a1:
                problems.append({"kind": "overlap", "region": bn, "line": bl + 1,
                                 "reason": "与 %s 重叠（0x%08X~0x%08X vs 0x%08X~0x%08X）"
                                           % (an, a0, a1, b0, b1)})
        for ch in node.get("children", []):
            _same_level(ch)
    _same_level(p["root"])
    # 越界（只在给了 memmap 时）
    ranges = []
    for chunk in str(memmap or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            return {"ok": False, "action": "scatter_check",
                    "error": "memmap 每段要写成 基址:长度（收到 %r）" % chunk}
        b, s = chunk.split(":", 1)
        bi, si = _to_int(b), _to_int(s)
        if bi is None or si is None:
            return {"ok": False, "action": "scatter_check",
                    "error": "memmap 里 %r 的基址/长度不是数值" % chunk}
        ranges.append((bi, bi + si))
    if ranges:
        for r in p["regions"]:
            if r["base"] is None or r["base_relative"] or not r["size"]:
                continue
            lo, hi = r["base"], r["base"] + r["size"]
            if not any(a <= lo and hi <= b for a, b in ranges):
                problems.append({"kind": "out-of-map", "region": r["name"],
                                 "line": r["line"] + 1,
                                 "reason": "0x%08X~0x%08X 不完全落在给出的内存范围内"
                                           % (lo, hi)})
    return {"ok": True, "action": "scatter_check", "path": real, "encoding": enc,
            # ok 只表示「检查跑完了」；文件干不干净看 clean / problems。
            # 两者必须分开：把 ok 当结论会让「检查成功」被误读成「文件没问题」。
            "clean": not problems,
            "problems": problems, "problem_count": len(problems),
            "regions": p["regions"], "memmap": memmap or None,
            "note": ("结构问题（parse/duplicate/no-size）来自文本本身；overlap 与 "
                     "out-of-map 是**静态判断**，不替代 Keil 链接器的最终结论。"
                     "没给 memmap 就不做越界判断——本工具不内置器件内存地图。")}

def read(path: str, text_out: bool = False) -> dict:
    real = resolve_path(path)
    if not os.path.isfile(real):
        return {"ok": False, "action": "scatter_read",
                "error": "文件不存在：%s" % path,
                "hint": "路径可以是 .sct 文件，也可以是指向它的目录（目录里正好一个 .sct 才行）"}
    text, enc = _read_text(real)
    p = parse(text)
    out = {"ok": True, "action": "scatter_read", "path": real, "encoding": enc,
           "line_count": len(p["lines"]),
           "regions": p["regions"],
           "region_count": len(p["regions"]),
           "parse_errors": p["errors"]}
    if p["errors"]:
        out["warning"] = ("文本里有 %d 处解析不了的地方，scatter_edit 会拒绝改动它"
                          "（不猜着改）" % len(p["errors"]))
    if text_out:
        out["text"] = text
    else:
        out["hint"] = "需要原文用 scatter_read(text_out=true)"
    return out

def _region_name(op, kind):
    """取 op 里的区域名：`name` / `region` 两种写法都认。

    少写字段时给一句明确的话——不要退化成「找不到区域 None」这种看不出原因的报错。"""
    v = op.get("name")
    if v is None:
        v = op.get("region")
    if v is None or not str(v).strip():
        raise ValueError("%s 需要 name（或 region）：要操作哪个区域。"
                         "当前 op 里没有区域名，先用 scatter_read 看有哪些区域" % kind)
    return str(v).strip()

def _apply_ops(lines, root, ops):
    """按 ops 改 lines（原地），返回 changes。所有锚点都必须唯一，否则抛错。"""
    changes = []
    for idx, op in enumerate(ops or []):
        if not isinstance(op, dict):
            raise ValueError("第 %d 个 op 不是对象" % (idx + 1))
        kind = str(op.get("op") or "").strip().lower()
        if kind == "set_region":
            name = _region_name(op, kind)
            node, _parent = _find_region(root, name)
            if node is None:
                raise ValueError("找不到区域 %r（先用 scatter_read 看有哪些）" % (name,))
            style = node.get("header_style") or {}
            sep = style.get("comma") or " "
            base_raw = (op["base"] if "base" in op and op["base"] is not None
                        else node["base_raw"])
            size_raw = (op["size"] if "size" in op and op["size"] is not None
                        else node["size_raw"])
            new_line = " ".join(x for x in (node["name"], str(base_raw), str(size_raw))
                                if x is not None) + sep + "{"
            if new_line == lines[node["line"]]:
                changes.append({"op": kind, "region": name, "skipped": "no-change"})
                continue
            changes.append({"op": kind, "region": name,
                            "before": lines[node["line"]].strip(), "after": new_line})
            lines[node["line"]] = new_line
        elif kind == "add_selector":
            name = _region_name(op, kind)
            text = str(op.get("text") or "").strip()
            if not text:
                raise ValueError("add_selector 需要 text")
            node, _p = _find_region(root, name)
            if node is None:
                raise ValueError("找不到区域 %r" % (name,))
            indent = _indent_of(lines, node)
            pos = len(lines) if node["end_line"] is not None else len(lines)
            if node["end_line"] is not None:
                pos = node["end_line"]
            elif node["selectors"]:
                pos = node["selectors"][-1]["line"] + 1
            lines.insert(pos, indent + "  " + text)
            changes.append({"op": kind, "region": name, "inserted_at": pos + 1,
                            "text": text})
        elif kind == "remove_selector":
            name = _region_name(op, kind)
            text = str(op.get("text") or "").strip()
            node, _p = _find_region(root, name)
            if node is None:
                raise ValueError("找不到区域 %r" % (name,))
            hit = [s for s in node["selectors"] if s["text"] == text]
            if len(hit) != 1:
                raise ValueError("在区域 %r 里匹配到 %d 个 %r，要求恰好 1 个"
                                 % (name, len(hit), text))
            lines.pop(hit[0]["line"])
            changes.append({"op": kind, "region": name, "removed": text,
                            "line": hit[0]["line"] + 1})
        elif kind == "add_region":
            name = str(op.get("name") or op.get("region") or "").strip()
            if not name:
                raise ValueError("add_region 需要 name（或 region）：新区域叫什么名字")
            if _find_region(root, name)[0] is not None:
                raise ValueError("区域 %r 已存在" % (name,))
            parent = op.get("parent")
            host = root
            if parent:
                host, _p = _find_region(root, parent)
                if host is None:
                    raise ValueError("找不到父区域 %r" % (parent,))
            sels = [str(s).strip() for s in (op.get("selectors") or []) if str(s).strip()]
            head = _fmt_header(name, op.get("base"), op.get("size"))
            indent = _indent_of(lines, host)
            block = [indent + "  " + head]
            block += [indent + "   " + s for s in sels]
            block.append(indent + "  }")
            pos = len(lines)
            if host is not root and host.get("end_line") is not None:
                pos = host["end_line"]
            lines[pos:pos] = block
            changes.append({"op": kind, "region": name, "parent": parent or None,
                            "inserted_at": pos + 1, "block": block})
        elif kind == "remove_region":
            name = _region_name(op, kind)
            node, _p = _find_region(root, name)
            if node is None:
                raise ValueError("找不到区域 %r" % (name,))
            if node["end_line"] is None:
                raise ValueError("区域 %r 没有闭合，拒绝删（文件本身有问题）" % (name,))
            lo, hi = node["line"], node["end_line"]
            removed = lines[lo:hi + 1]
            del lines[lo:hi + 1]
            changes.append({"op": kind, "region": name, "removed_lines": len(removed)})
        else:
            raise ValueError("不认识的 op：%r（支持 set_region / add_region / "
                             "remove_region / add_selector / remove_selector）" % (kind,))
    return changes

def _indent_of(lines, node):
    if node.get("line") is not None and node["line"] < len(lines):
        raw = lines[node["line"]]
        return raw[:len(raw) - len(raw.lstrip())]
    return ""

def edit(path: str, ops, dry_run: bool = False, backup: bool = True,
         create: bool = False, memmap: str = "") -> dict:
    """受控编辑：改完重新解析 + 校验，不合格就回滚（dry_run 时压根不落盘）。"""
    real = resolve_path(path)
    exists = os.path.isfile(real)
    if not exists and not create:
        return {"ok": False, "action": "scatter_edit",
                "error": "文件不存在：%s" % path,
                "hint": "新建请显式给 create=true（配合 add_region 使用）"}
    if exists:
        text, enc = _read_text(real)
    else:
        text, enc = "", "utf-8"
    p0 = parse(text)
    if exists and p0["errors"]:
        return {"ok": False, "action": "scatter_edit",
                "error": "文本里有 %d 处解析不了的地方，拒绝改动（不猜着改）"
                         % len(p0["errors"]),
                "parse_errors": p0["errors"]}
    if not isinstance(ops, list):
        return {"ok": False, "action": "scatter_edit",
                "error": "ops 必须是数组，每项形如 "
                         '{"op":"set_region","name":"RW_IRAM1","size":0x40000}'}
    lines = list(p0["lines"])
    trailing_nl = text.endswith("\n") or text.endswith("\r\n")
    newline = "\r\n" if "\r\n" in text else "\n"
    try:
        changes = _apply_ops(lines, p0["root"], ops)
    except ValueError as e:
        return {"ok": False, "action": "scatter_edit", "error": str(e)}
    new_text = newline.join(lines) + (newline if trailing_nl else "")
    p1 = parse(new_text)
    problems = []
    if p1["errors"]:
        problems = [dict(e, kind="parse") for e in p1["errors"]]
    names = [r["name"] for r in p1["regions"]]
    dup = sorted({n for n in names if names.count(n) > 1})
    for n in dup:
        problems.append({"kind": "duplicate", "region": n,
                         "reason": "改动后出现同名区域"})
    if problems:
        return {"ok": False, "action": "scatter_edit",
                "error": "改动后的文本没通过校验，**没有落盘**",
                "problems": problems, "changes": changes,
                "hint": "把 ops 拆小一点逐个来，或先用 scatter_read 看结构"}
    out = {"ok": True, "action": "scatter_edit", "path": real,
           "encoding": enc, "dry_run": bool(dry_run),
           "changes": changes, "regions": p1["regions"],
           "created": bool(not exists)}
    if dry_run:
        out["new_text"] = new_text
        out["hint"] = "dry_run 没有写文件；确认无误后去掉 dry_run 再调一次。"
        return out
    if exists and backup:
        out["backup"] = _backup(real)
    with open(real, "w", encoding=enc, newline="") as f:
        f.write(new_text)
    out["written"] = True
    if memmap:
        c = check(real, memmap=memmap)
        out["post_check"] = {"problem_count": c.get("problem_count"),
                             "problems": c.get("problems")}
    out["hint"] = ("改完请让 Keil 重新链接（build/rebuild）确认链接器也认；"
                   "本工具的校验只覆盖结构、同名、同层重叠，不等于链接器结论。")
    return out

# ----------------------------------------------------------------------
# MCP 工具注册
# ----------------------------------------------------------------------
def _default_js(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)

def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="scatter_read",
        title="读分散加载文件（.sct）的结构",
        description=(
            "把 Keil 的 `.sct` 解析成**区域树**：每个区域的 名字/基址/长度/相对基址标志/"
            "所在行/父区域/子区域/段选择器清单。用于「这个工程的内存怎么分的」以及"
            "改之前先看清结构。\n"
            "路径可以是 .sct 文件，也可以是**目录**（目录里正好一个 .sct 才认）。\n"
            "解析是**面向行**的：把整块写在一行（`ER_IROM1 0x08000000 { ... }`）这类写法"
            "会在 `parse_errors` 里报出来，并且 scatter_edit 会拒绝改它——不猜着改。"
        ),
    )
    async def scatter_read(path: str, text_out: bool = False) -> str:
        try:
            return _js(read(path, text_out=bool(text_out)))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "scatter_read", "error": str(e)})
    n += 1

    @server.tool(
        name="scatter_edit",
        title="受控编辑分散加载文件（.sct）",
        description=(
            "**按行**改 `.sct`，没碰到的行一字不动（保住缩进、注释、Keil 自己的说明行）——"
            "不做「解析成对象再整体序列化」，那会把 diff 弄成面目全非。\n"
            "ops 是数组，支持五种：\n"
            "① `{\"op\":\"set_region\",\"name\":\"RW_IRAM1\",\"base\":\"0x20000000\","
            "\"size\":\"0x40000\"}` —— 改区域基址/长度（基址可用 `+0x1000` 的相对写法）；\n"
            "② `{\"op\":\"add_region\",\"parent\":\"LR_IROM1\",\"name\":\"ER_APP\","
            "\"base\":\"0x08040000\",\"size\":\"0x40000\",\"selectors\":[\".ANY (+RO)\"]}`；\n"
            "③ `{\"op\":\"remove_region\",\"name\":\"ER_OLD\"}` —— 整块删（含子行）；\n"
            "④ `{\"op\":\"add_selector\",\"region\":\"ER_IROM1\",\"text\":\".ANY (+XO)\"}`；\n"
            "⑤ `{\"op\":\"remove_selector\",\"region\":\"ER_IROM1\",\"text\":\".ANY (+XO)\"}`。\n"
            "安全：改前**强制备份** `<文件>.mdkdebug.bak`（backup=false 可关）、"
            "改后**重新解析 + 校验**（结构/同名），不合格一律**不落盘**并要求你把 ops 拆小。"
            "`dry_run=true` 只算不写，并返回 new_text 给你看。`create=true` 允许新建文件。\n"
            "校验边界：本工具只做结构、同名、同层重叠、以及（给了 memmap 时）越界判断，"
            "**不内置任何器件内存地图**，也**不能替代链接器结论**——改完请重新 build 让链接器说话。"
        ),
    )
    async def scatter_edit(path: str, ops, dry_run: bool = False,
                           backup: bool = True, create: bool = False,
                           memmap: str = "") -> str:
        try:
            return _js(edit(path, ops, dry_run=bool(dry_run),
                            backup=bool(backup), create=bool(create),
                            memmap=memmap))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "scatter_edit", "error": str(e)})
    n += 1

    @server.tool(
        name="scatter_check",
        title="校验分散加载文件（.sct）",
        description=(
            "静态检查 `.sct`：解析问题、同名区域、长度缺失/为 0、**同层区域重叠**，"
            "以及给了 `memmap` 时的**越界**判断。\n"
            "读结论请看 **`clean`（布尔）与 `problems`（逐条带行号）**——"
            "`ok` 只表示「检查跑完了」，**不代表文件没问题**：大 `.sct` 里几个坑一起中，"
            "是常态，别只看 ok。\n"
            "`memmap` 写法 `0x08000000:0x00100000,0x20000000:0x00030000`（基址:长度，逗号分隔）。"
            "**不给就不做越界判断**——本工具不内置任何器件的内存地图。\n"
            "结论只覆盖静态结构，不替代链接器的最终判断。"
        ),
    )
    async def scatter_check(path: str, memmap: str = "") -> str:
        try:
            return _js(check(path, memmap=memmap))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "scatter_check", "error": str(e)})
    n += 1
    return n
