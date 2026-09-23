# -*- coding: utf-8 -*-
"""代码索引：项目遍历与过滤。

取向（与仓库其它模块一致）：**只报可证的事实**。哪些文件进了索引、哪些被跳过，
每个跳过项都带理由（`reason`），调用方原样透出给工具层——不静默吞掉。

过滤优先级（先命中先算）：
1. 硬编码目录名排除（build/Objects/Listings/.git/node_modules/…）——构建产物与三方件
2. 项目根的 `.gitignore`（简单实现：逐行 glob，支持 `dir/`、`/前缀`、`*`、`**`、`!` 取反）
3. `codeindex.json` 的 `exclude` / `include`（exclude 优先；include 能把被 .gitignore
   排除的源码拉回来，用于「源码被 .gitignore 掉」的工程，例如 SVN/Perforce 项目）
4. 单文件 > MAX_FILE_BYTES → 跳过（生成文件、打包产物）
5. 扩展名不认识 → 不进候选（只计数，不逐条列出，避免噪音）
"""
import fnmatch
import json
import os
import re

# 语言注册表：扩展名 → 语言 id。加语言 = 在这里加一条 + 加一个语法轮子 + 一个 lang_*.py
EXT_LANG = {
    ".c": "c",
    ".h": "c",          # 默认按 C 解析；C++ 工程用 codeindex.json 的 extensions 覆盖成 cpp
    ".inc": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".h++": "cpp",
    # 汇编：`.S`/`.s` 经 splitext().lower() 都归到这里。方言（armasm / GNU / IAR）
    # 不靠扩展名判定——同一工程里 `svcrt_context.S` 是 armasm、CMSIS 的 `.s` 是 GNU，
    # 由 lang_asm 按文件内实际出现的指令认，认不出来按 armasm。
    ".s": "asm",
    ".asm": "asm",
}

# 永远不看的目录名（构建产物 / 三方件 / 工具目录）
DEFAULT_EXCLUDE_DIRS = frozenset((
    ".git", ".hg", ".svn", ".mdkdebug", ".codegraph", ".lingxi", ".vs", ".vscode",
    "node_modules", "vendor", "dist", "build", "Build", "out", "target",
    "Objects", "Listings", "DebugConfig", "RTE", "Debug", "Release",
    "__pycache__", ".venv", "venv", "site-packages",
))

MAX_FILE_BYTES = 1024 * 1024     # 与 CodeGraph 同口径：>1 MB 的文件当生成物跳过


def load_config(project):
    """读项目根的 codeindex.json（可选）。坏文件不静默吞：返回 error 让上层如实报。"""
    path = os.path.join(project, "codeindex.json")
    cfg = {"exclude": [], "include": [], "extensions": {}}
    if not os.path.isfile(path):
        return cfg, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:                     # 坏 JSON 不猜内容
        return cfg, "codeindex.json 解析失败（%s）：%s" % (type(exc).__name__, exc)
    if not isinstance(raw, dict):
        return cfg, "codeindex.json 顶层必须是对象"
    for key in ("exclude", "include"):
        v = raw.get(key)
        if v is None:
            continue
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            return cfg, "codeindex.json 的 %s 必须是字符串数组" % key
        cfg[key] = list(v)
    ext = raw.get("extensions")
    if ext is not None:
        if not isinstance(ext, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in ext.items()):
            return cfg, "codeindex.json 的 extensions 必须是 {扩展名: 语言} 字符串映射"
        cfg["extensions"] = dict(ext)
    return cfg, None


def lang_for(path, cfg=None):
    """按扩展名判语言；配置可覆盖（例如把 .h 当 cpp）。"""
    ext = os.path.splitext(path)[1].lower()
    if cfg and ext in (cfg.get("extensions") or {}):
        return cfg["extensions"][ext]
    return EXT_LANG.get(ext)


def supported_extensions(cfg=None):
    exts = dict(EXT_LANG)
    if cfg:
        for k, v in (cfg.get("extensions") or {}).items():
            exts[k.lower()] = v
    return exts


# ---------------------------------------------------------------- gitignore

def _gitignore_rules(base, text):
    """把一份 .gitignore 转成 [(regex, negated)]；规则按出现顺序后匹配者胜。"""
    rules = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        line = line.strip()
        if not line:
            continue
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        anchored = line.startswith("/") or "/" in line.strip("/")
        line = line.lstrip("/")
        # glob → regex
        out, i = [], 0
        while i < len(line):
            ch = line[i]
            if ch == "*" and i + 1 < len(line) and line[i + 1] == "*":
                out.append(".*")
                i += 2
                if i < len(line) and line[i] == "/":
                    i += 1
                continue
            if ch == "*":
                out.append("[^/]*")
            elif ch == "?":
                out.append("[^/]")
            else:
                out.append(re.escape(ch))
            i += 1
        body = "".join(out)
        if anchored:
            rx = r"^%s$" % body
        else:
            rx = r"(^|/)%s$" % body
        if dir_only:
            rx = rx[:-1] + r"(/.*)?$" if not anchored else rx[:-1] + r"(/.*)?$"
        try:
            rules.append((re.compile(rx), negated))
        except re.error:
            continue
    return rules


def load_gitignore(project):
    """收集项目内所有 .gitignore（含嵌套），返回 [(base_rel, regex, negated)]。"""
    collected = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]
        if ".gitignore" not in files:
            continue
        base = os.path.relpath(root, project).replace("\\", "/")
        base = "" if base == "." else base
        try:
            with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8",
                      errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for rx, neg in _gitignore_rules(base, text):
            collected.append((base, rx, neg, 0))
    return collected


def _gitignored(rel, is_dir, rules):
    """rel 用正斜杠、相对项目根。返回 True 表示被忽略。"""
    hit = False
    for base, rx, neg, _ in rules:
        if base:
            if not rel.startswith(base + "/"):
                continue
            sub = rel[len(base) + 1:]
        else:
            sub = rel
        if rx.match(sub) or (is_dir and rx.match(sub + "/")):
            hit = not neg
    return hit


def _cfg_match(rel, patterns):
    for pat in patterns:
        p = pat.rstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*") or rel.startswith(p + "/"):
            return True
        if fnmatch.fnmatch(os.path.basename(rel), p):
            return True
    return False


def iter_source_files(project, cfg=None):
    """遍历项目，返回 (files, skipped, unknown_ext_count)。

    files:   [{"rel", "abs", "lang", "size", "mtime"}]
    skipped: [{"rel", "reason", "detail"}]，reason ∈ excluded-dir/excluded/gitignored/big/unreadable
    """
    project = os.path.abspath(project)
    if cfg is None:
        cfg, _err = load_config(project)
    rules = load_gitignore(project)
    files, skipped, unknown = [], [], 0

    for root, dirs, names in os.walk(project):
        rel_root = os.path.relpath(root, project).replace("\\", "/")
        rel_root = "" if rel_root == "." else rel_root
        # 按目录名排除（构建产物 / 三方件 / 工具目录）：**照样进 skipped**，逐条给理由——
        # 模块的取向是「不静默吞」；调用方问「我那个文件为什么不在索引里」时要能查到。
        keep = []
        for d in dirs:
            if d in DEFAULT_EXCLUDE_DIRS:
                rel = ("%s/%s" % (rel_root, d)) if rel_root else d
                skipped.append({"rel": rel + "/", "reason": "excluded-dir",
                                "detail": "按目录名排除（构建产物/三方件/工具目录）：%s" % d})
                continue
            keep.append(d)
        dirs[:] = sorted(keep)
        keep = []
        for d in dirs:
            rel = ("%s/%s" % (rel_root, d)) if rel_root else d
            if _gitignored(rel, True, rules) and not _cfg_match(rel, cfg["include"]):
                # include 也能救回**被 .gitignore 整目录排除**的源码（SVN/Perforce 工程常见：
                # 源码目录被 .gitignore 掉）。目录级与文件级用同一条优先级，否则
                # 「include 能把被 .gitignore 排除的源码拉回来」这句在有目录规则时不成立。
                skipped.append({"rel": rel + "/", "reason": "gitignored",
                                "detail": "被 .gitignore 忽略的目录"})
                continue
            if _cfg_match(rel, cfg["exclude"]) and not _cfg_match(rel, cfg["include"]):
                skipped.append({"rel": rel + "/", "reason": "excluded",
                                "detail": "codeindex.json exclude 命中目录"})
                continue
            keep.append(d)
        dirs[:] = keep

        for nm in sorted(names):
            abs_p = os.path.join(root, nm)
            rel = ("%s/%s" % (rel_root, nm)) if rel_root else nm
            lang = lang_for(nm, cfg)
            if lang is None:
                unknown += 1
                continue
            if _gitignored(rel, False, rules) and not _cfg_match(rel, cfg["include"]):
                skipped.append({"rel": rel, "reason": "gitignored",
                                "detail": "被 .gitignore 忽略"})
                continue
            if _cfg_match(rel, cfg["exclude"]) and not _cfg_match(rel, cfg["include"]):
                skipped.append({"rel": rel, "reason": "excluded",
                                "detail": "codeindex.json exclude 命中"})
                continue
            try:
                st = os.stat(abs_p)
            except OSError as exc:
                skipped.append({"rel": rel, "reason": "unreadable",
                                "detail": str(exc)})
                continue
            if st.st_size > MAX_FILE_BYTES:
                skipped.append({"rel": rel, "reason": "big",
                                "detail": "%d 字节 > %d 上限（当生成物/打包产物跳过）"
                                          % (st.st_size, MAX_FILE_BYTES)})
                continue
            files.append({"rel": rel, "abs": abs_p, "lang": lang,
                          "size": st.st_size, "mtime": st.st_mtime})
    return files, skipped, unknown
