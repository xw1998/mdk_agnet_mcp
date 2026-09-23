# -*- coding: utf-8 -*-
"""代码索引：门面层（批次68/69）。

一层薄门面，把 `walk`（遍历）/ `store`（SQLite）/ `parser`（tree-sitter）/ `resolve`（
关系与置信度）拼成调用方要的动作：`build` / `sync` / `status` / `drop` / `files` /
`query` / `node`（批次68，解析级事实）+ `relations` / `impact`（批次69，带 basis 的
近似关系）。

三条贯穿全模块的取向（与仓库其它模块一致）：

1. **解析级事实与近似关系分开**。批次68 产出**解析级事实**：符号表、include 图、
   单符号源码体、调用点。批次69 才给 **调用点 → 定义** 的归属推断（`relations`/`impact`），
   且每条边都带 `basis`/`confidence`：`resolved` 只在 `exact` 时非空，猜测只进 `candidates`；
   看不见的部分（函数指针/条件编译/无定义）只报规模与位置（`blind_spots`），不画一个像样的调用图。
2. **索引不往用户项目里写**。默认落在 `~/.mdkdebug/codeindex/<路径哈希>/index.db`
   （可用 `MDKDEBUG_CODEINDEX_DIR` 覆盖根目录，测试用）；只有调用方显式要
   `in_project=true` 才写进 `<project>/.mdkdebug/index.db`。
3. **缺依赖/缺索引/索引过期都如实报**（`parser-missing` / `no-index` / `index-stale`），
   不静默降级成 grep、不假装有结果。`index-stale` 只报不自动重建。
"""
from __future__ import annotations

import hashlib
import os
import time

from . import walk as _walk
from . import parser as _parser
from . import resolve as _resolve
from .store import SCHEMA_VERSION, Store

#: 索引根目录的环境变量覆盖（测试用；也方便把索引放到别的盘）
ENV_ROOT = "MDKDEBUG_CODEINDEX_DIR"

#: 单文件解析进符号表后，`code_node` 默认最多回多少行源码
DEFAULT_NODE_LINES = 400


# ------------------------------------------------------------------ 位置

def index_root():
    """索引根目录。默认 `~/.mdkdebug/codeindex`，可用 MDKDEBUG_CODEINDEX_DIR 覆盖。"""
    env = (os.environ.get(ENV_ROOT) or "").strip()
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(os.path.expanduser("~"), ".mdkdebug", "codeindex")


def project_key(project):
    """项目路径 → 目录名。用规范化绝对路径的 sha1 前 16 位（大小写不敏感平台归一）。"""
    p = os.path.abspath(os.path.expanduser(project)).replace("\\", "/")
    if os.name == "nt":
        p = p.lower()
    return hashlib.sha1(p.encode("utf-8", "replace")).hexdigest()[:16]


def db_path(project, in_project=False):
    """索引库路径。`in_project=True` 时写进项目内 `.mdkdebug/`。"""
    project = os.path.abspath(os.path.expanduser(project))
    if in_project:
        return os.path.join(project, ".mdkdebug", "index.db")
    return os.path.join(index_root(), project_key(project), "index.db")


def ensure_project(project):
    """把 project 归一成存在的目录。返回 (abs_path, error)。"""
    if not project or not str(project).strip():
        return None, "没有指定工程目录（传 project=<源码根目录>）"
    p = os.path.abspath(os.path.expanduser(str(project).strip()))
    if not os.path.isdir(p):
        return None, "目录不存在：%s" % p
    return p, None


# ------------------------------------------------------------------ 工具函数

def _sha1(data):
    return hashlib.sha1(data).hexdigest()


def _db_size(path):
    """索引库体积（含 WAL/SHM，因为它们也是这次索引实际占的盘）。"""
    total, parts = 0, {}
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.isfile(p):
            try:
                n = os.path.getsize(p)
            except OSError:
                continue
            parts[suffix or "db"] = n
            total += n
    return total, parts


def _open(project, in_project=False, create=False):
    """打开索引库。create=False 时不存在就返回 (None, error)。

    返回 (store, error)；store 由调用方 close()。
    """
    path = db_path(project, in_project=in_project)
    if not create and not os.path.isfile(path):
        return None, ("该项目还没有索引：%s。用 code_index(action=\"build\") 建一次"
                      "（会写 %s，不动你的工程目录）" % (path, os.path.dirname(path)))
    store = Store(path).open()
    err = store.ensure_schema()
    if err:
        store.close()
        return None, err
    return store, None


def _resolve_includes(store):
    """include 后置处理：把工程内头文件按**唯一 basename** 匹配成 resolved_rel。

    只做「唯一匹配」——同名头文件出现多次时**不猜**（留 None，批次69 的 `include-visible`
    会把它当候选之一并如实报歧义）。系统头（`<...>`）不匹配。
    """
    rows = store.conn.execute(
        "SELECT DISTINCT rel FROM files WHERE rel LIKE '%.h' OR rel LIKE '%.hpp' "
        "OR rel LIKE '%.hh' OR rel LIKE '%.hxx' OR rel LIKE '%.inc'").fetchall()
    by_base = {}
    for r in rows:
        by_base.setdefault(os.path.basename(r["rel"]).lower(), []).append(r["rel"])
    for r in store.conn.execute(
            "SELECT id, target FROM includes WHERE is_system=0").fetchall():
        cands = by_base.get(os.path.basename(r["target"]).lower()) or []
        if len(cands) == 1:
            store.conn.execute("UPDATE includes SET resolved_rel=? WHERE id=?",
                               (cands[0], r["id"]))


def _parse_into(store, project, ent):
    """解析一个文件并写库。返回 (ok, note)。"""
    abs_p = os.path.join(project, ent["rel"].replace("/", os.sep))
    try:
        with open(abs_p, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return False, "读取失败：%s" % exc
    try:
        rec = _parser.extract(data, ent["rel"], ent["lang"])
    except Exception as exc:  # noqa: BLE001
        return False, "解析失败（%s）：%s" % (type(exc).__name__, exc)
    fid = store.upsert_file(ent["rel"], ent["lang"], len(data), ent["mtime"],
                            _sha1(data), rec["lines"], rec["parse_error"],
                            rec.get("normalized"))
    store.clear_children(fid)
    store.add_symbols(fid, rec["symbols"])
    store.add_includes(fid, rec["includes"])
    store.add_calls(fid, rec["calls"])
    store.add_refs(fid, rec["refs"])
    store.add_fptrs(fid, rec["fptrs"])
    # note 可能是 "parse-error+normalized"：两件事各自独立计数（都发生过就是都算），
    # 不互相吞——「归一化过的文件也还可能走恢复态」这个事实不能丢。
    tags = []
    if rec["parse_error"]:
        tags.append("parse-error")
    if rec.get("normalized"):
        tags.append("normalized")
    return True, ("+".join(tags) or None)


# ------------------------------------------------------------------ 建索引

def _run_parse(project, entries, store):
    """entries: [(ent, sha1_or_None)]；返回统计 dict。"""
    parsed, failed, parse_errors, normalized = 0, [], [], 0
    t0 = time.time()
    for ent, sha in entries:
        ok, note = _parse_into(store, project, ent)
        if not ok:
            failed.append({"rel": ent["rel"], "error": note})
            continue
        parsed += 1
        if note and "parse-error" in note:
            parse_errors.append(ent["rel"])
        if note and "normalized" in note:
            normalized += 1
    return {"parsed": parsed, "failed": failed, "parse_errors": parse_errors,
            "normalized": normalized, "parse_seconds": round(time.time() - t0, 2)}


def build(project, in_project=False):
    """全量重建：解析项目内全部候选文件（不删库，逐文件替换，保留其它元信息）。"""
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    ok, info = _parser.available()
    if not ok:
        return {"ok": False, "error": info.get("error"),
                "hint": info.get("hint"), "error_code": "parser-missing"}

    cfg, cfg_err = _walk.load_config(project)
    files, skipped, unknown = _walk.iter_source_files(project, cfg)
    store, err = _open(project, in_project=in_project, create=True)
    if err:
        return {"ok": False, "error": err, "error_code": "index-schema-mismatch"}

    t0 = time.time()
    try:
        store.begin()
        st = _run_parse(project, [(f, None) for f in files], store)
        _resolve_includes(store)
        store.meta_set("project", project)
        store.meta_set("built_at", time.time())
        store.meta_set("build_kind", "build")
        store.meta_set("schema_version", str(SCHEMA_VERSION))
        store.commit()
        counts = store.counts()
    except Exception as exc:  # noqa: BLE001
        store.rollback()
        store.close()
        return {"ok": False, "error": "写索引失败（已回滚）：%s" % exc,
                "error_code": "index-write-failed"}

    size, parts = _db_size(db_path(project, in_project=in_project))
    out = {
        "ok": True, "action": "build", "project": project,
        "in_project": bool(in_project), "index": db_path(project, in_project=in_project),
        "index_bytes": size, "index_parts": parts,
        "files": {"candidates": len(files), "parsed": st["parsed"],
                  "skipped": len(skipped), "unknown_ext": unknown},
        "counts": counts,
        "parse_errors": st["parse_errors"][:20],
        "parse_error_count": len(st["parse_errors"]),
        "normalized_count": st["normalized"],
        "skipped_list": skipped[:40],
        "seconds": round(time.time() - t0, 2),
        "config_error": cfg_err,
        "note": ("索引写在 %s（**不往你的工程目录里写**）。默认只建一次；"
                 "源码改动后用 code_index(action=\"sync\") 增量刷。"
                 % ("<project>/.mdkdebug/index.db" if in_project else index_root())),
    }
    if st["failed"]:
        out["failed"] = st["failed"][:20]
    if cfg_err:
        out["ok"] = False
        out["error_code"] = "config-bad"
        out["error"] = cfg_err
    store.close()
    return out


def sync(project, in_project=False):
    """增量同步：mtime/size 未变的不重解析；变了的重算 sha1（内容真变才重解析）。"""
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    ok, info = _parser.available()
    if not ok:
        return {"ok": False, "error": info.get("error"),
                "hint": info.get("hint"), "error_code": "parser-missing"}

    cfg, cfg_err = _walk.load_config(project)
    files, skipped, unknown = _walk.iter_source_files(project, cfg)
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}

    t0 = time.time()
    have = store.file_map()
    changed, added, metadata_only, removed = [], [], [], []
    seen = set()
    for f in files:
        seen.add(f["rel"])
        old = have.get(f["rel"])
        if old is None:
            added.append((f, None))
            continue
        same_meta = (old["size"] == f["size"]
                     and abs((old["mtime"] or 0) - f["mtime"]) < 1.0)
        if same_meta:
            continue
        changed.append(f)                     # 先记候选，sha1 比对见下
    for rel in have:
        if rel not in seen:
            removed.append(rel)

    sha_changed = []
    for f in changed:
        try:
            with open(f["abs"], "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        sha = _sha1(data)
        if sha == have[f["rel"]]["sha1"]:
            metadata_only.append(f)           # 只是 mtime 动了（git checkout/复制），内容没变
        else:
            sha_changed.append(f)

    try:
        store.begin()
        for rel in removed:
            store.delete_file(rel)
        # 内容没变但 mtime 变了：只更新文件行，不动子表（省一次解析）
        for f in metadata_only:
            cur = store.file_row(f["rel"])
            store.upsert_file(f["rel"], f["lang"], f["size"], f["mtime"],
                              have[f["rel"]]["sha1"], cur["lines"] if cur else None,
                              cur["parse_error"] if cur else 0,
                              cur["normalized"] if cur else 0)
        st = _run_parse(project, [(f, None) for f in added] +
                        [(f, None) for f in sha_changed], store)
        _resolve_includes(store)
        store.meta_set("project", project)
        store.meta_set("synced_at", time.time())
        store.meta_set("build_kind", "sync")
        store.commit()
        counts = store.counts()
    except Exception as exc:  # noqa: BLE001
        store.rollback()
        store.close()
        return {"ok": False, "error": "写索引失败（已回滚）：%s" % exc,
                "error_code": "index-write-failed"}

    size, parts = _db_size(db_path(project, in_project=in_project))
    out = {
        "ok": True, "action": "sync", "project": project,
        "in_project": bool(in_project), "index": db_path(project, in_project=in_project),
        "index_bytes": size,
        "files": {"candidates": len(files), "added": len(added),
                  "reparsed": len(sha_changed), "metadata_only": len(metadata_only),
                  "removed": len(removed), "unchanged": len(files) - len(added) - len(changed),
                  "skipped": len(skipped), "unknown_ext": unknown},
        "counts": counts,
        "parse_errors": st["parse_errors"][:20],
        "parse_error_count": len(st["parse_errors"]),
        "normalized_count": st["normalized"],
        "removed_list": removed[:20],
        "seconds": round(time.time() - t0, 2),
        "note": ("增量只省**解析**：符号/调用点是按文件重算的，跨文件的引用聚合"
                 "（批次69 的关系层）每次都会重算——所以 sync 的耗时由改动文件数决定，"
                 "不是零成本。"),
    }
    if st["failed"]:
        out["failed"] = st["failed"][:20]
    if cfg_err:
        out["ok"] = False
        out["error_code"] = "config-bad"
        out["error"] = cfg_err
    store.close()
    return out


def drop(project, in_project=False):
    """删除索引库（连同 -wal/-shm）。**这是不可逆操作**，工具层会先说明影响。"""
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    path = db_path(project, in_project=in_project)
    removed = []
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.isfile(p):
            try:
                os.remove(p)
                removed.append(p)
            except OSError as exc:
                return {"ok": False, "error": "删除失败：%s（%s）" % (exc, p),
                        "error_code": "index-drop-failed", "removed": removed}
    return {"ok": True, "action": "drop", "project": project,
            "index": path, "removed": removed,
            "note": "索引已删除；源码未动。下次查询前需重新 code_index(action=\"build\")。"}


# ------------------------------------------------------------------ 状态

def stale_info(store, project):
    """索引是否落后于源码：逐条 stat 已索引文件，并扫盘找新文件。"""
    changed, missing = [], []
    for r in store.conn.execute("SELECT rel, size, mtime FROM files").fetchall():
        rel = r["rel"]
        p = os.path.join(project, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            missing.append(rel)
            continue
        try:
            stt = os.stat(p)
        except OSError:
            missing.append(rel)
            continue
        if stt.st_size != r["size"] or abs(stt.st_mtime - (r["mtime"] or 0)) >= 1.0:
            changed.append(rel)
    added = []
    try:
        cfg, _err = _walk.load_config(project)
        files, _sk, _un = _walk.iter_source_files(project, cfg)
        have = set(r["rel"] for r in store.conn.execute("SELECT rel FROM files"))
        added = [f["rel"] for f in files if f["rel"] not in have]
    except Exception:  # noqa: BLE001 — 扫盘失败不伪造成「没落后」
        added = None
    return {"changed": changed, "missing": missing, "added": added,
            "stale": bool(changed or missing or added)}


def status(project, in_project=False):
    """项目/索引状态：有没有、多大、多少文件与符号、上次构建时间、是否落后。"""
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    ok, info = _parser.available()
    path = db_path(project, in_project=in_project)
    cfg, cfg_err = _walk.load_config(project)
    out = {
        "ok": True, "project": project, "in_project": bool(in_project),
        "index": path, "index_exists": os.path.isfile(path),
        "index_root": index_root(),
        "parser": {"available": ok, "languages": (info.get("languages") if ok else []),
                   "versions": (info.get("versions") if ok else {}),
                   "hint": (None if ok else info.get("hint")),
                   "error": (None if ok else info.get("error"))},
        "languages": sorted(set(_walk.supported_extensions(cfg).values())),
        "extensions": _walk.supported_extensions(cfg),
        "config_error": cfg_err,
    }
    if cfg_err:
        out["ok"] = False
        out["error_code"] = "config-bad"
        out["error"] = cfg_err
    if not os.path.isfile(path):
        # 「没有索引」不是一个可用的状态：**如实报失败**（ok=false），否则调用方会
        # 拿着一个 status=ok 但 error_code=no-index 的结果继续往下走——两种口径写在
        # 同一个返回体里，下游必然挑错那个当依据。payload 仍然带全（解析器可用性、
        # 索引路径），失败信息与下一步动作由统一信封补上。
        out["ok"] = False
        out["error"] = "该项目还没有建代码索引：%s" % path
        out["error_code"] = "no-index"
        out["note"] = ("上面的索引路径就是建完会落在哪儿；建一次用 "
                       "code_index(action=\"build\", project=...)。"
                       "建索引只读源码，索引写在用户目录，不往你工程目录里写。")
        return out

    store, err = _open(project, in_project=in_project, create=False)
    if err:
        out["ok"] = False
        out["error_code"] = "index-schema-mismatch"
        out["error"] = err
        return out
    try:
        meta = store.meta_all()
        size, parts = _db_size(path)
        st = stale_info(store, project)
        pes = store.parse_errors()
        nrm = store.normalized_files()
        out.update({
            "schema_version": meta.get("schema_version"),
            "index_bytes": size, "index_parts": parts,
            "built_at": float(meta["built_at"]) if meta.get("built_at") else None,
            "synced_at": float(meta["synced_at"]) if meta.get("synced_at") else None,
            "built_at_text": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(float(meta["built_at"]))) if meta.get("built_at") else None,
            "build_kind": meta.get("build_kind"),
            "counts": store.counts(),
            # 索引完整度：解析器走过恢复态的文件。不报的话，调用方会把一个
            # 部分解析的索引当成全量事实（「没测」被读成「没有」那类错答案）。
            "parse_error_count": len(pes),
            "parse_errors": pes[:20],
            "parse_errors_note": ("tree-sitter 走过恢复态的文件（索引里这部分不可全信）；"
                                  "常见于内联汇编与预处理嵌套写法，不等于文件内容错。"),
            "normalized_count": len(nrm),
            "normalized_note": ("为绕开 `#ifdef __cplusplus extern \"C\" {` 跨条件括号的"
                                "恢复态，这些文件解析前把该记号换成了**等长空格**"
                                "（行号/列偏移不变，因此索引里查不到 `extern \"C\"` 本身）。"),
            "stale": {"is_stale": st["stale"],
                      "changed": len(st["changed"]), "missing": len(st["missing"]),
                      "added": (None if st["added"] is None else len(st["added"])),
                      "samples": (st["changed"] + st["missing"])[:10],
                      "added_samples": (st["added"] or [])[:10],
                      "added_known": st["added"] is not None},
        })
        if st["stale"]:
            out["warning"] = ("索引可能已落后于源码（changed=%d missing=%d added=%s）。"
                              "**不会自动重建**：要刷就显式 code_index(action=\"sync\")。"
                              % (len(st["changed"]), len(st["missing"]),
                                 "unknown" if st["added"] is None else len(st["added"])))
            out["warning_code"] = "index-stale"
    finally:
        store.close()
    return out


# ------------------------------------------------------------------ 查询

def files(project, pattern=None, max_depth=None, in_project=False):
    """索引内的文件/目录结构（比扫盘快），可 pattern 过滤、max_depth 限制路径层数。

    max_depth：**路径层数上限**——`a.c` 为 1 层、`inc/util.h` 为 2 层；
    None 或 <=0 表示不限制（默认）。
    """
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}
    try:
        rows = store.files_like(pattern)
    finally:
        store.close()
    if max_depth is not None and int(max_depth) > 0:
        md = int(max_depth)
        rows = [r for r in rows if len(r["rel"].split("/")) <= md]
    # 目录集合单独收集：**不能**用「n_sym==0 的条目」来反推目录——
    # 一是顶层目录名不带 `/` 会被漏掉，二是空文件（0 个符号）会被误当目录。
    dirs = set()
    for r in rows:
        parts = r["rel"].split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    return {"ok": True, "project": project, "count": len(rows),
            "pattern": pattern, "max_depth": max_depth,
            "dirs": sorted(dirs),
            "files": [{"rel": r["rel"], "lang": r["lang"], "lines": r["lines"],
                       "symbols": r["n_sym"]} for r in rows]}


def query(project, name, kind=None, limit=50, mode="auto",
          only_definitions=False, in_project=False):
    """符号检索（替代 `grep -rn` 的第一步）：只回位置与签名，不回源码体。"""
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "name 不能为空", "error_code": "invalid-argument"}
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}
    try:
        rows = store.search_symbols(name, mode=mode, kind=kind, limit=limit,
                                    only_definitions=only_definitions)
    finally:
        store.close()
    return {"ok": True, "project": project, "name": name, "mode": mode,
            "kind": kind, "count": len(rows),
            "symbols": [{"name": r["name"], "kind": r["kind"], "path": r["path"],
                         "line": r["start_line"], "end_line": r["end_line"],
                         "is_definition": bool(r["is_definition"]),
                         "storage": r["storage"], "parent": r["parent"],
                         "signature": r["signature"],
                         "in_conditional": bool(r["in_conditional"])}
                        for r in rows],
            "note": ("只回位置与签名；要看源码体用 code_node(name=...)。"
                     "检索默认走可预测的精确/前缀/子串（mode=auto），"
                     "mode=\"fts\" 是实验性的全文相关度排序——代码标识符用 FTS 反而容易意外。"
                     "**不含局部变量**（只索引文件作用域符号），宏定义在 kind=macro。")}


def _read_lines(project, rel, start, end):
    """读 rel 的第 [start, end] 行（1 基，含端点）。返回 (lines, error)。"""
    p = os.path.join(project, rel.replace("/", os.sep))
    if not os.path.isfile(p):
        return None, "文件不在磁盘上：%s" % rel
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.read().splitlines()
    except OSError as exc:
        return None, "读取失败：%s" % exc
    n = len(all_lines)
    s = max(1, int(start or 1))
    e = min(n, int(end or n))
    return [(i, all_lines[i - 1]) for i in range(s, e + 1)], None


def node(project, name=None, file=None, max_lines=DEFAULT_NODE_LINES,
         start_line=None, end_line=None, in_project=False, kind=None):
    """单符号（签名 + 源码体 + 位置 + 被引用位置）或整文件（带行号，Read-parity）。

    同名符号**给全部候选**（不猜哪一个），调用方按 path/line 自己挑。
    """
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    if not name and not file:
        return {"ok": False, "error": "要么给 name（符号）要么给 file（整文件）",
                "error_code": "invalid-argument", "hint": "Read 整文件用 file=..."}
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}
    try:
        if file:
            fr = store.file_row(file)
            fr2 = None
            if fr is None:
                out = store.files_like(file)
                if len(out) == 1:
                    fr2 = out[0]
                    file = fr2["rel"]
            if fr is None and fr2 is None:
                return {"ok": False, "error": "索引里没有这个文件：%s" % file,
                        "error_code": "file-not-found",
                        "hint": "用 code_files(pattern=...) 找真实路径"}
            lines, lerr = _read_lines(project, file, start_line or 1,
                                      end_line or (fr2["lines"] if fr2 else None))
            if lerr:
                return {"ok": False, "error": lerr, "error_code": "file-not-found"}
            syms = store.symbols_in_file(file)
            return {"ok": True, "mode": "file", "project": project, "path": file,
                    "start_line": lines[0][0], "end_line": lines[-1][0],
                    "line_count": len(lines),
                    "code": [{"line": i, "text": t} for i, t in lines],
                    "symbols": [{"name": s["name"], "kind": s["kind"],
                                 "line": s["start_line"], "end_line": s["end_line"],
                                 "signature": s["signature"]} for s in syms],
                    "note": "整文件带行号（Read-parity）。要看某个符号的体用 code_node(name=...)。"}

        rows = store.symbols_by_name(name, kind=kind)
        if not rows:
            return {"ok": False, "error": "索引里没有这个符号：%s" % name,
                    "error_code": "symbol-not-found",
                    "hint": "先 code_query(name=...) 确认名字；宏/字段也各有 kind"}
        cands = []
        budget = max(1, int(max_lines or DEFAULT_NODE_LINES))
        truncated = False
        for s in rows:
            bs = s["body_start"] or s["start_line"]
            be = s["body_end"] or s["end_line"]
            nlines = (be or bs) - bs + 1
            if nlines > budget:
                be = bs + budget - 1
                truncated = True
            lines, lerr = _read_lines(project, s["path"], bs, be)
            refs = store.refs_of(s["name"])[:40]
            calls_out = store.calls_from(s["name"])[:80]
            cands.append({
                "name": s["name"], "kind": s["kind"], "path": s["path"],
                "start_line": s["start_line"], "end_line": s["end_line"],
                "body_start": s["body_start"], "body_end": s["body_end"],
                "signature": s["signature"],
                "is_definition": bool(s["is_definition"]),
                "storage": s["storage"], "parent": s["parent"],
                "in_conditional": bool(s["in_conditional"]),
                "code": ([{"line": i, "text": t} for i, t in lines]
                         if lines else []),
                "code_error": lerr,
                # refs：**只收可证的两类**——类型名（type_identifier）与条件编译里
                # 出现的宏名。它不是「谁引用了这个符号」，不要把条数当引用数。
                "refs": [{"path": r["path"], "line": r["line"], "kind": r["kind"]}
                         for r in refs],
                "ref_count": len(store.refs_of(s["name"])),
                # calls_out：该符号体内的**调用点**（谁被它调）——解析级事实，不是推断。
                # 反向的「谁调了它」属推断，见批次69 的 code_relations。
                "calls_out": [{"callee": c["callee"], "line": c["line"],
                               "via_pointer": bool(c["via_pointer"]),
                               "in_conditional": bool(c["in_conditional"])}
                              for c in calls_out],
                "calls_out_count": len(store.calls_from(s["name"])),
            })
    finally:
        store.close()
    return {"ok": True, "mode": "symbol", "project": project, "name": name,
            "count": len(cands), "candidates": cands,
            "truncated": truncated, "max_lines": budget,
            "note": ("同名给全部候选（不猜）。两个字段别混：`calls_out` 是**该符号体内的"
                     "调用点**（谁被它调，解析级事实）；`refs` 只含**类型名与条件编译里的宏名**"
                     "的出现位置，不等于「谁引用了它」。反向的「谁调了它」是推断，"
                     "带 basis/confidence 后由 code_relations(direction=\"callers\") 给；"
                     "改动影响面用 code_impact。")}


# ------------------------------------------------------------------ 关系（批次69）

def _sym_brief(s):
    """符号行 → 精简条目（关系结果里列定义/声明用）。"""
    return {"name": s["name"], "kind": s["kind"], "path": s["path"],
            "line": s["start_line"], "end_line": s["end_line"],
            "signature": s["signature"], "storage": s["storage"],
            "is_definition": bool(s["is_definition"]),
            "in_conditional": bool(s["in_conditional"])}


def _pick_symbols(store, name, path=None, line=None):
    """按 name（可加 path/line 限定）挑符号。返回 (syms, defs, error)。

    没有符号名但有调用点时**不当错**：那正是「有人调了它、工程里没有定义」这个盲区结论，
    用 symbol-not-found 把「谁在调它」一起吞掉就是把一个事实说没了。此时返回空符号集。
    """
    allsyms = store.symbols_by_name(name)
    if not allsyms:
        if not (path or line) and store.calls_to(name):
            return [], [], None
        return None, None, "索引里没有这个符号：%s" % name
    syms = allsyms
    if path:
        syms = [s for s in syms if s["path"] == path]
    if line:
        try:
            want = int(line)
        except (TypeError, ValueError):
            return None, None, "line 要是整数（符号的起始行）"
        syms = [s for s in syms if int(s["start_line"] or 0) == want]
    if not syms:
        return None, None, "按 path/line 限定后没有匹配的符号（去掉限定拿全部候选）"
    return syms, [s for s in syms if s["is_definition"]], None


def relations(project, name=None, direction="callers", depth=1, path=None,
              line=None, limit=200, in_project=False):
    """调用关系：`callers`（谁调用了它）/ `callees`（它调用了谁）/ `both`。

    每条边 = 一个**调用点**（解析级事实）＋ 该调用点对目标名的**解析结论**
    （`basis`/`confidence`/`candidates`）。`basis=exact&confidence=high` 才是
    「证明得到」；其余按 `include-visible`（medium）/ `name-only`（low）/ `blind`
    如实降级。**`resolved` 只在 exact 时非空**，猜测一律只进 `candidates`。
    """
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "name 不能为空", "error_code": "invalid-argument",
                "hint": "先 code_query(name=...) 确认符号名"}
    direction = (direction or "callers").strip().lower()
    if direction not in ("callers", "callees", "both"):
        return {"ok": False, "error": "direction 取 callers / callees / both",
                "error_code": "invalid-argument",
                "hint": "callers=谁调用了它；callees=它调用了谁；both=都要"}
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}
    try:
        rv = _resolve.Resolver(store)
        syms, defs, serr = _pick_symbols(store, name, path=path, line=line)
        if serr:
            return {"ok": False, "error": serr, "error_code": "symbol-not-found",
                    "hint": "先 code_query(name=...) 看有哪些候选（含 path/line）"}
        out = {"ok": True, "project": project, "name": name,
               "direction": direction, "depth": max(1, int(depth or 1)),
               "symbols": [_sym_brief(s) for s in syms],
               "definitions": [_sym_brief(s) for s in defs],
               "callers": None, "callees": None}
        if direction in ("callers", "both"):
            edges, trunc = rv.callers(name, depth=depth, limit=limit)
            out["callers"] = edges
            out["callers_truncated"] = trunc
        if direction in ("callees", "both"):
            edges, trunc = [], False
            for s in (defs or syms):
                e, t = rv.callees(s, depth=depth, limit=limit)
                edges.extend(e)
                trunc = trunc or t
            out["callees"] = edges
            out["callees_truncated"] = trunc
        out["blind_spots"] = rv.blind_spots(name)
        out["summary"] = {
            "callers": _resolve.summarize(out["callers"]) if out["callers"] is not None else None,
            "callees": _resolve.summarize(out["callees"]) if out["callees"] is not None else None,
        }
        out["note"] = ("每条边的 basis 说明这条边凭什么：exact/high=证明得到（同文件唯一定义，"
                       "或 TU 内可见声明且全工程唯一定义）；include-visible/medium=include 可达"
                       "但有同名候选；name-only/low=只见同名、未证实可见性；blind=看不到"
                       "（函数指针/查不到定义）。**resolved 只在 exact 时非空**，其余只给候选。"
                       "「谁调用了它」这一侧的 caller 是解析级事实（同文件最内层函数），"
                       "推断只发生在「这个名字对应哪个定义」。")
        if not out["definitions"]:
            out["note"] += (" 注意：这个符号名在索引里**没有定义**，下面列出的调用点"
                            "（若有）都解析不到目标——这本身就是盲区结论，不是空结果。")
        return out
    finally:
        store.close()


def impact(project, name=None, path=None, line=None, depth=2, limit=300,
           in_project=False):
    """改动影响面：分 `direct`（exact/high）/ `possible`（medium+low）/ `unresolved`
    （见到调用但解析不到定义）/ `indirect`（深度 >1 的间接调用者）四段，外加 `blind_spots`。
    """
    project, err = ensure_project(project)
    if err:
        return {"ok": False, "error": err, "error_code": "project-required"}
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "name 不能为空", "error_code": "invalid-argument",
                "hint": "先 code_query(name=...) 确认符号名"}
    store, err = _open(project, in_project=in_project, create=False)
    if err:
        return {"ok": False, "error": err, "error_code": "no-index",
                "hint": "先 code_index(action=\"build\") 建一次索引"}
    try:
        rv = _resolve.Resolver(store)
        syms, defs, serr = _pick_symbols(store, name, path=path, line=line)
        if serr:
            return {"ok": False, "error": serr, "error_code": "symbol-not-found",
                    "hint": "先 code_query(name=...) 看有哪些候选（含 path/line）"}
        edges, trunc = rv.callers(name, depth=max(1, int(depth or 1)), limit=limit)
        direct = [e for e in edges if e["depth"] == 1 and e["basis"] == "exact"]
        possible = [e for e in edges if e["depth"] == 1
                    and e["basis"] in ("include-visible", "name-only")]
        unresolved = [e for e in edges if e["depth"] == 1 and e["basis"] == "blind"]
        indirect = [e for e in edges if e["depth"] > 1]
        return {
            "ok": True, "project": project, "name": name,
            "depth": max(1, int(depth or 1)),
            "symbols": [_sym_brief(s) for s in syms],
            "definitions": [_sym_brief(s) for s in defs],
            "direct": direct, "possible": possible,
            "unresolved": unresolved, "indirect": indirect,
            "blind_spots": rv.blind_spots(name),
            "project_blind_spots": _resolve.project_blind_spots(store),
            "truncated": trunc,
            "summary": {
                "direct": len(direct), "possible": len(possible),
                "unresolved": len(unresolved), "indirect": len(indirect),
                "direct_confidence": "high",
                "possible_confidence": "medium+low",
            },
            "note": ("改这个符号要连带看的地方：`direct`（已证实，exact/high）最该先看，"
                     "`possible`（include-visible/medium 或 name-only/low）要人工扫一眼，"
                     "`unresolved` 是「有人调了这个名字但解析不到定义」（盲区），"
                     "`indirect` 是深度 >1 的间接影响。**别把 possible/unresolved 当确定影响面**："
                     "`blind_spots` 里的函数指针/条件编译调用是静态看不到的部分，它只报规模与位置。"),
        }
    finally:
        store.close()
