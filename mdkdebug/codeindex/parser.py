# -*- coding: utf-8 -*-
"""代码索引：tree-sitter 解析层。

把一份源码变成「记录」：符号、include、调用点、引用、函数指针声明，外加一份
**解析错误**标记（有语法错误的文件照样索引已解析出来的部分，但如实标出来）。

诚实边界（写在这里也写给调用方看）：
- 宏**不展开**，条件编译的**所有分支**都会被索引，只标 `in_conditional`；
- 函数指针的**声明**能认出来（进 fptr 表当盲区证据，不区分作用域；文件作用域的那几个
  同时也进符号表、`kind=fptr`），但「谁通过它调用」静态看不出来；
- 局部变量不进符号表（只索引文件作用域变量），函数体内的 `identifier` 不做引用收集。
"""
import importlib
import os

try:
    from tree_sitter import Language, Parser, Query, QueryCursor
    _TS_OK, _TS_ERR = True, None
except Exception as exc:                     # 依赖缺失：如实报缺，不静默降级成 grep
    _TS_OK, _TS_ERR = False, "%s: %s" % (type(exc).__name__, exc)

LANG_MODULES = {"c": "mdkdebug.codeindex.lang_c", "cpp": "mdkdebug.codeindex.lang_cpp"}

# 概念 → 符号种类（引用类概念不产符号）
KIND_OF = {
    "function.def": ("function", 1),
    "function.decl": ("function", 0),
    "macro.def": ("macro", 1),
    "macro.fn": ("macro_fn", 1),
    "struct.def": ("struct", 1),
    "class.def": ("class", 1),
    "union.def": ("union", 1),
    "enum.def": ("enum", 1),
    "enum.member": ("enumerator", 1),
    "typedef.def": ("typedef", 1),
    "field.def": ("field", 1),
    "variable.def": ("variable", 1),
    "namespace.def": ("namespace", 1),
    "fptr.def": ("fptr", 1),
}
_IDENT_TYPES = ("identifier", "field_identifier", "type_identifier",
                "namespace_identifier", "statement_identifier")
_CONTAINER_TYPES = ("struct_specifier", "class_specifier", "union_specifier",
                    "enum_specifier", "namespace_definition")
_COND_TYPES = ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif",
               "preproc_elifdef", "preproc_else_if")


def available():
    """tree-sitter 是否可用。缺依赖时给出装法（不猜、不降级）。"""
    if not _TS_OK:
        return False, {"error": _TS_ERR,
                       "hint": "缺 tree-sitter 解析器：pip install "
                               "\"tree-sitter>=0.26\" \"tree-sitter-c>=0.24\" "
                               "\"tree-sitter-cpp>=0.23\"（都是预编译轮子，不需要编译器）"}
    versions = {}
    for lang, mod in LANG_MODULES.items():
        try:
            m = importlib.import_module(mod)
            versions[lang] = getattr(m, "LANG", lang)
        except Exception as exc:
            return False, {"error": "语法轮子缺失（%s）：%s" % (lang, exc),
                           "hint": "pip install tree-sitter-c tree-sitter-cpp"}
    try:
        import tree_sitter
        versions["tree_sitter"] = getattr(tree_sitter, "__version__", "?")
    except Exception:
        pass
    return True, {"versions": versions, "languages": sorted(LANG_MODULES)}


_cache = {}


def _load(lang):
    if lang in _cache:
        return _cache[lang]
    mod_name = LANG_MODULES.get(lang)
    if not mod_name:
        raise ValueError("未注册的语言：%s（已注册：%s）" % (lang, ", ".join(sorted(LANG_MODULES))))
    mod = importlib.import_module(mod_name)
    grammar = importlib.import_module(mod.GRAMMAR)
    language = Language(grammar.language())
    queries = [(c, Query(language, q)) for c, q in mod.QUERIES]
    _cache[lang] = (mod, language, Parser(language), queries)
    return _cache[lang]


def _text(node):
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:
        return ""


def _name_of(node):
    """从捕获到的名字节点取标识符。

    多数情况 @name 直接就是 identifier；typedef/函数指针这类会捕获到声明符节点，
    此时取其中**最后一个**标识符——这是词法事实，不是语义推断。
    """
    if node is None:
        return None
    if node.type in _IDENT_TYPES:
        return _text(node)
    stack = [node]
    last = None
    while stack:
        cur = stack.pop()
        if cur.type in _IDENT_TYPES and last is None:
            pass
        for ch in cur.children:
            if ch.type in _IDENT_TYPES:
                last = ch
            stack.append(ch)
    return _text(last) if last is not None else _text(node).strip().split("(")[0].strip()


def _walk(node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _in_conditional(node, guards=frozenset()):
    cur = node
    while cur is not None:
        if cur.type in _COND_TYPES and cur.id not in guards:
            return True
        cur = cur.parent
    return False

def _include_guard_ids(root):
    """认出头文件的 include guard（顶层 `#ifndef X` / `#if !defined(X)` 且内部立刻
    `#define X`），返回这些条件节点的 id 集合。

    为什么必须排掉：几乎每个 .h 都用 include guard 把整个文件包住，若不排除，
    `in_conditional` 会变成「这个头里的一切都是条件编译」——这句话看着像事实，
    实际上只是**防重复包含**，对判断「这段代码在不在编译里」毫无信息量，
    属于典型的「看似权威的错答案」。真正的 `#if LIMIT>4` 仍然照标。
    """
    guards = set()
    for ch in root.children:
        if ch.type not in ("preproc_ifdef", "preproc_if"):
            continue
        name = None
        for c in ch.children:
            if c.type == "identifier" and name is None:
                name = _text(c)
            elif c.type == "preproc_def":
                ident = None
                for cc in c.children:
                    if cc.type == "identifier":
                        ident = _text(cc)
                        break
                if name and ident == name:
                    guards.add(ch.id)
                break
    return guards


def _enclosing_name(node):
    cur = node.parent
    while cur is not None:
        if cur.type in _CONTAINER_TYPES:
            for ch in cur.children:
                if ch.type in _IDENT_TYPES:
                    return _text(ch)
        cur = cur.parent
    return None


def _file_scope(node):
    """文件作用域判定：祖先里没有 compound_statement（函数体）就算——只索引全局变量。"""
    cur = node.parent
    while cur is not None:
        if cur.type in ("compound_statement", "function_definition"):
            return False
        cur = cur.parent
    return True


def _body_range(node):
    for ch in node.children:
        if ch.type == "compound_statement":
            return ch.start_point[0] + 1, ch.end_point[0] + 1
    return None, None


def _storage(node):
    for ch in node.children:
        if ch.type == "storage_class_specifier":
            return _text(ch).strip()
    return None


def _signature(node, body_start):
    end_line = (body_start - 1) if body_start else node.end_point[0] + 1
    lines = []
    for line in _text(node).splitlines():
        lines.append(" ".join(line.split()))
        if len(lines) >= (end_line - node.start_point[0]):
            break
    sig = " ".join(lines)
    if len(sig) > 240:
        sig = sig[:237] + "..."
    return sig


def _blank_extern_c(src):
    """把「`#ifdef __cplusplus` 包着的 `extern "C" {` / `}`」换成**等长空格**。

    为什么：这是 C/C++ 头文件里最普遍的写法——

        #ifdef __cplusplus
        extern "C" {
        #endif
        ... 声明 ...
        #ifdef __cplusplus
        }
        #endif

    一对花括号被拆到了两个条件分支里，tree-sitter 的预处理结点处理不了跨分支的括号配对，
    整个文件因此走恢复态（实测 svcrtos_new：605 个 parse_error 里有 166 个只因为这个）。
    这两个记号对 C 的符号事实没有任何贡献，抹成空格后**字节长度不变**：行号、列偏移、
    后续所有位置全不受影响，代价只是索引里查不到 `extern "C"` 这个词本身。

    只认「整行就是这些东西」的形式，不碰别的内容；返回 (bytes, 是否改动过)。
    """
    lines = src.split(b"\n")
    if b'extern "C" {' not in src and b'extern "C"{' not in src:
        return src, False
    out, changed = list(lines), False
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s in (b'extern "C" {', b'extern "C"{', b'extern "C"'):
            out[i] = b" " * len(ln)
            changed = True
        elif s == b"}":
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            if j >= 0 and lines[j].strip().startswith(b"#ifdef __cplusplus"):
                out[i] = b" " * len(ln)
                changed = True
    if not changed:
        return src, False
    return b"\n".join(out), True


def extract(src, rel, lang):
    """解析一份源码 → 记录字典。src 为 bytes。"""
    src, normalized = _blank_extern_c(src)
    mod, language, parser, queries = _load(lang)
    tree = parser.parse(src)
    root = tree.root_node
    guards = _include_guard_ids(root)

    symbols, includes, calls, refs, fptrs = [], [], [], [], []
    seen = set()

    for concept, query in queries:
        cur = QueryCursor(query)
        try:
            matches = cur.matches(root)
        except Exception:
            continue
        for _pidx, caps in matches:
            nodes = caps.get("node") or caps.get("name") or caps.get("callee") or []
            primary = nodes[0] if nodes else None
            if primary is None:
                continue
            line = primary.start_point[0] + 1

            if concept == "include":
                tgt_nodes = caps.get("target") or []
                if not tgt_nodes:
                    continue
                raw = _text(tgt_nodes[0])
                is_sys = raw.startswith("<")
                target = raw.strip("<>\"")
                includes.append({"target": target, "is_system": is_sys,
                                 "line": line,
                                 "in_conditional": _in_conditional(primary, guards)})
                continue

            if concept in ("call", "call.ptr"):
                names = caps.get("callee") or []
                if not names:
                    continue
                callee = _text(names[0])
                if concept == "call.ptr":
                    callee = callee.strip("()").split(")")[0].strip() or callee
                calls.append({"line": line, "col": primary.start_point[1],
                              "callee": callee,
                              "in_conditional": _in_conditional(primary, guards),
                              "via_pointer": concept == "call.ptr"})
                continue

            if concept in ("type.use", "macro.use"):
                nm = caps.get("name") or []
                if nm:
                    refs.append({"line": line, "col": nm[0].start_point[1],
                                 "name": _text(nm[0]),
                                 "kind": "type_use" if concept == "type.use" else "macro_use"})
                continue

            name_nodes = caps.get("name") or []
            name = _name_of(name_nodes[0]) if name_nodes else None
            if not name:
                continue

            if concept == "variable.def" and not _file_scope(primary):
                continue                    # 局部变量不进符号表（见模块说明）
            if concept == "fptr.def":
                # fptr 表收**所有**函数指针声明（含函数体内的局部）——它是「这个调用点
                # 可能是间接调用」的盲区证据，作用域不影响这个用途。
                fptrs.append({"name": name, "line": line,
                              "decl": " ".join(_text(primary).split())[:160]})
                # 但**符号表**仍旧只收文件作用域名字（与 variable 同一条边界）：
                # 局部函数指针不进符号表，否则 `handler` 这类常见局部名会污染按名检索。
                # 进符号表是必须的：`code_query`/`code_node` 的描述把 `fptr` 列为可查的
                # kind——描述承诺了却查不到，就是「看似权威的错答案」。
                if _file_scope(primary):
                    key = (name, "fptr", primary.start_point[0], primary.start_point[1])
                    if key not in seen:
                        seen.add(key)
                        symbols.append({
                            "name": name, "kind": "fptr",
                            "start_line": line,
                            "end_line": primary.end_point[0] + 1,
                            "start_col": primary.start_point[1],
                            "end_col": primary.end_point[1],
                            "signature": _signature(primary, None),
                            "is_definition": 1, "storage": _storage(primary),
                            "parent": _enclosing_name(primary),
                            "in_conditional": _in_conditional(primary, guards),
                            "body_start": None, "body_end": None,
                            "path": rel,
                        })
                continue

            kind, is_def = KIND_OF.get(concept, ("unknown", 1))
            bs, be = (None, None)
            if kind == "function":
                bs, be = _body_range(primary)
            key = (name, kind, primary.start_point[0], primary.start_point[1])
            if key in seen:
                continue
            seen.add(key)
            symbols.append({
                "name": name, "kind": kind,
                "start_line": line, "end_line": primary.end_point[0] + 1,
                "start_col": primary.start_point[1], "end_col": primary.end_point[1],
                "signature": _signature(primary, bs),
                "is_definition": is_def,
                "storage": _storage(primary),
                "parent": _enclosing_name(primary),
                "in_conditional": _in_conditional(primary, guards),
                "body_start": bs, "body_end": be,
                "path": rel,
            })

    # 调用归因：找到包含该调用点的最内层函数定义（同一文件内）
    funcs = [s for s in symbols if s["kind"] == "function" and s["is_definition"]]
    for c in calls:
        best = None
        for s in funcs:
            if s["start_line"] <= c["line"] <= (s["body_end"] or s["end_line"]):
                if best is None or s["start_line"] > best["start_line"]:
                    best = s
        c["caller"] = best["name"] if best else None

    # 行数口径与 code_node(file=) 的 `line_count` 对齐：文件末尾的换行不额外算一行，
    # 空文件算 0 行。同一件事实不能有两个数字（差值 1 最容易被当成「差不多」吞掉）。
    lines = src.count(b"\n") + (0 if (src.endswith(b"\n") or not src) else 1)
    return {"symbols": symbols, "includes": includes, "calls": calls,
            "refs": refs, "fptrs": fptrs,
            "lines": lines,
            "normalized": normalized,
            "parse_error": bool(root.has_error)}
