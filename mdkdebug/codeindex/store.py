# -*- coding: utf-8 -*-
"""代码索引：SQLite 存储层。

设计要点
- **只用标准库 sqlite3**（FTS5 已确认可用），不引入额外的数据库依赖。
- 索引落在用户目录（`~/.mdkdebug/codeindex/<项目哈希>/index.db`），**不往用户项目里写**。
- 所有写操作在一个事务里完成；`schema_version` 不匹配时**不猜、不原地改**，直接告诉调用方
  需要重建（否则会出现「结构对不上但查询不报错」的静默错答案）。
- `sym_fts`（FTS5）作为可选检索模式；默认检索走 LIKE 精确/前缀/子串——代码标识符检索要的是
  可预测，而不是相关性魔法（`foo_bar` 在 unicode61 下会被切成两个 token，FTS 反而更意外）。
"""
import hashlib
import os
import sqlite3
import time

#: 3 = 批次70：加了汇编（`.s`/`.S`/`.asm`）行式解析。
#: **为什么必须 bump**：表结构没变，但老索引里没有汇编文件——那是一个“结构对得上、
#: 内容静默不全”的库（启动文件、上下文切换、向量表全不在里面）。不 bump 的话它就
#: 一直静静地少一半低层真相，而任何查询都不会报错。
SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY,
  rel TEXT UNIQUE NOT NULL,
  lang TEXT,
  size INTEGER,
  mtime REAL,
  sha1 TEXT,
  lines INTEGER,
  parsed_at REAL,
  parse_error INTEGER DEFAULT 0,
  normalized INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS symbols(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  file_id INTEGER NOT NULL,
  start_line INTEGER, end_line INTEGER,
  start_col INTEGER, end_col INTEGER,
  signature TEXT,
  is_definition INTEGER,
  storage TEXT,
  parent TEXT,
  in_conditional INTEGER,
  body_start INTEGER, body_end INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sym_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_sym_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_sym_kind ON symbols(kind);

CREATE TABLE IF NOT EXISTS includes(
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL,
  target TEXT NOT NULL,
  is_system INTEGER,
  resolved_rel TEXT,
  line INTEGER,
  in_conditional INTEGER
);
CREATE INDEX IF NOT EXISTS idx_inc_file ON includes(file_id);
CREATE INDEX IF NOT EXISTS idx_inc_target ON includes(target);
CREATE INDEX IF NOT EXISTS idx_inc_resolved ON includes(resolved_rel);

CREATE TABLE IF NOT EXISTS calls(
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL,
  line INTEGER, col INTEGER,
  caller TEXT,
  callee TEXT NOT NULL,
  in_conditional INTEGER,
  via_pointer INTEGER
);
CREATE INDEX IF NOT EXISTS idx_call_file ON calls(file_id);
CREATE INDEX IF NOT EXISTS idx_call_callee ON calls(callee);
CREATE INDEX IF NOT EXISTS idx_call_caller ON calls(caller);

CREATE TABLE IF NOT EXISTS refs(
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL,
  line INTEGER, col INTEGER,
  name TEXT NOT NULL,
  kind TEXT
);
CREATE INDEX IF NOT EXISTS idx_ref_name ON refs(name);
CREATE INDEX IF NOT EXISTS idx_ref_file ON refs(file_id);

CREATE TABLE IF NOT EXISTS fptr(
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL,
  name TEXT,
  line INTEGER,
  decl TEXT
);
CREATE INDEX IF NOT EXISTS idx_fptr_file ON fptr(file_id);
CREATE INDEX IF NOT EXISTS idx_fptr_name ON fptr(name);

CREATE VIRTUAL TABLE IF NOT EXISTS sym_fts USING fts5(name, path, kind);
"""


def sha1_file(path, limit=None):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class Store(object):
    """一个索引库的读写门面。调用方负责 close()。"""

    def __init__(self, path):
        self.path = path
        self.conn = None

    # ------------------------------------------------------------ 连接/模式
    def open(self):
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0)
        # 关掉 sqlite3 的隐式事务（默认会在 DML 前自动 BEGIN）：事务边界完全由我们自己的
        # begin()/commit()/rollback() 决定。否则 ensure_schema() 里的一次 INSERT 就会留下
        # 未提交事务，后面显式 begin() 会撞上「cannot start a transaction within a transaction」。
        self.conn.isolation_level = None
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        return self

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            finally:
                self.conn = None

    def exists(self):
        return os.path.isfile(self.path)

    def ensure_schema(self):
        """建表；已有库则校验 schema_version，不匹配就报错（不静默迁就）。"""
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'")
        fresh = cur.fetchone() is None
        self.conn.executescript(SCHEMA)
        if fresh:
            self.meta_set("schema_version", str(SCHEMA_VERSION))
            return None
        have = self.meta_get("schema_version")
        if have != str(SCHEMA_VERSION):
            return ("索引库版本不匹配（库内 %s / 本程序 %d）。请用 "
                    "code_index(action=\"drop\") 后重建，或换一个 --in-project 位置。"
                    % (have, SCHEMA_VERSION))
        return None

    # ------------------------------------------------------------ meta
    def meta_set(self, key, value):
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def meta_get(self, key, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def meta_all(self):
        return {r["key"]: r["value"] for r in self.conn.execute("SELECT key, value FROM meta")}

    # ------------------------------------------------------------ 事务
    def begin(self):
        self.conn.execute("BEGIN")

    def commit(self):
        self.conn.commit()

    def rollback(self):
        try:
            self.conn.rollback()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------ files
    def file_map(self):
        """{rel: {"id","size","mtime","sha1"}}——增量比对用。"""
        out = {}
        for r in self.conn.execute("SELECT id, rel, size, mtime, sha1 FROM files"):
            out[r["rel"]] = {"id": r["id"], "size": r["size"],
                             "mtime": r["mtime"], "sha1": r["sha1"]}
        return out

    def upsert_file(self, rel, lang, size, mtime, sha1, lines, parse_error=0,
                    normalized=0):
        """写/更新文件行。parse_error 要**存下来**：只在 build 的返回体里报一次的话，
        之后就再也查不到「这个索引里有文件解析走过恢复态」——等于把索引的不完整
        藏起来了（status 必须能如实说）。"""
        self.conn.execute(
            "INSERT INTO files(rel, lang, size, mtime, sha1, lines, parsed_at, parse_error, "
            "normalized) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(rel) DO UPDATE SET lang=excluded.lang, size=excluded.size, "
            "mtime=excluded.mtime, sha1=excluded.sha1, lines=excluded.lines, "
            "parsed_at=excluded.parsed_at, parse_error=excluded.parse_error, "
            "normalized=excluded.normalized",
            (rel, lang, size, mtime, sha1, lines, time.time(),
             1 if parse_error else 0, 1 if normalized else 0))
        row = self.conn.execute("SELECT id FROM files WHERE rel=?", (rel,)).fetchone()
        return row["id"]

    def delete_file(self, rel):
        row = self.conn.execute("SELECT id FROM files WHERE rel=?", (rel,)).fetchone()
        if not row:
            return
        fid = row["id"]
        for tbl in ("symbols", "includes", "calls", "refs", "fptr"):
            self.conn.execute("DELETE FROM %s WHERE file_id=?" % tbl, (fid,))
        self.conn.execute("DELETE FROM files WHERE id=?", (fid,))

    def clear_children(self, file_id):
        self.conn.execute("DELETE FROM sym_fts WHERE rowid IN "
                          "(SELECT id FROM symbols WHERE file_id=?)", (file_id,))
        for tbl in ("symbols", "includes", "calls", "refs", "fptr"):
            self.conn.execute("DELETE FROM %s WHERE file_id=?" % tbl, (file_id,))

    def add_symbols(self, file_id, rows):
        """rows: [{name, kind, start_line, end_line, start_col, end_col, signature,
                   is_definition, storage, parent, in_conditional, body_start, body_end, path}]"""
        for r in rows:
            cur = self.conn.execute(
                "INSERT INTO symbols(name, kind, file_id, start_line, end_line, start_col, "
                "end_col, signature, is_definition, storage, parent, in_conditional, "
                "body_start, body_end) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["name"], r["kind"], file_id, r.get("start_line"), r.get("end_line"),
                 r.get("start_col"), r.get("end_col"), r.get("signature"),
                 1 if r.get("is_definition") else 0, r.get("storage"), r.get("parent"),
                 1 if r.get("in_conditional") else 0,
                 r.get("body_start"), r.get("body_end")))
            self.conn.execute(
                "INSERT INTO sym_fts(rowid, name, path, kind) VALUES(?,?,?,?)",
                (cur.lastrowid, r["name"], r.get("path") or "", r["kind"]))

    def add_includes(self, file_id, rows):
        for r in rows:
            self.conn.execute(
                "INSERT INTO includes(file_id, target, is_system, resolved_rel, line, "
                "in_conditional) VALUES(?,?,?,?,?,?)",
                (file_id, r["target"], 1 if r.get("is_system") else 0,
                 r.get("resolved_rel"), r.get("line"),
                 1 if r.get("in_conditional") else 0))

    def add_calls(self, file_id, rows):
        for r in rows:
            self.conn.execute(
                "INSERT INTO calls(file_id, line, col, caller, callee, in_conditional, "
                "via_pointer) VALUES(?,?,?,?,?,?,?)",
                (file_id, r.get("line"), r.get("col"), r.get("caller"), r["callee"],
                 1 if r.get("in_conditional") else 0,
                 1 if r.get("via_pointer") else 0))

    def add_refs(self, file_id, rows):
        for r in rows:
            self.conn.execute(
                "INSERT INTO refs(file_id, line, col, name, kind) VALUES(?,?,?,?,?)",
                (file_id, r.get("line"), r.get("col"), r["name"], r.get("kind")))

    def add_fptrs(self, file_id, rows):
        for r in rows:
            self.conn.execute(
                "INSERT INTO fptr(file_id, name, line, decl) VALUES(?,?,?,?)",
                (file_id, r.get("name"), r.get("line"), r.get("decl")))

    # ------------------------------------------------------------ 查询
    def counts(self):
        c = {}
        for tbl in ("files", "symbols", "includes", "calls", "refs", "fptr"):
            c[tbl] = self.conn.execute("SELECT COUNT(*) AS n FROM %s" % tbl).fetchone()["n"]
        return c

    def parse_errors(self):
        """解析器走过恢复态（tree-sitter root.has_error）的文件 rel 列表。

        含义要如实理解：它说明**该文件的解析树里出现过 ERROR/missing 节点**
        （嵌入式 C 里常见于内联汇编、`#ifdef __cplusplus` 这类预处理嵌套写法），
        不代表文件内容一定是错的；但**索引里这部分不可全信**。"""
        return [r["rel"] for r in self.conn.execute(
            "SELECT rel FROM files WHERE parse_error=1 ORDER BY rel")]

    def normalized_files(self):
        """做过 `extern "C"` 等长抹白（_blank_extern_c）的文件 rel 列表。"""
        return [r["rel"] for r in self.conn.execute(
            "SELECT rel FROM files WHERE normalized=1 ORDER BY rel")]

    def file_row(self, rel):
        return self.conn.execute("SELECT * FROM files WHERE rel=?", (rel,)).fetchone()

    def files_like(self, pattern=None):
        sql = "SELECT f.rel, f.lang, f.lines, (SELECT COUNT(*) FROM symbols s " \
              "WHERE s.file_id=f.id) AS n_sym FROM files f"
        args = ()
        if pattern:
            sql += " WHERE f.rel LIKE ?"
            args = ("%" + pattern.replace("*", "%") + "%",)
        sql += " ORDER BY f.rel"
        return [dict(r) for r in self.conn.execute(sql, args)]

    def search_symbols(self, name, mode="auto", kind=None, limit=50,
                       only_definitions=False):
        """按名字检索。mode: auto/exact/prefix/substring/fts。

        排序（可预测、不做相关性魔法）：精确 > 前缀 > 子串；定义优先于声明；
        名字短的优先；再按文件路径与行号。
        """
        limit = max(1, min(int(limit or 50), 500))
        kind_clause, kind_args = "", ()
        if kind:
            kinds = [k.strip() for k in str(kind).split(",") if k.strip()]
            kind_clause = " AND s.kind IN (%s)" % ",".join("?" * len(kinds))
            kind_args = tuple(kinds)
        def_clause = " AND s.is_definition=1" if only_definitions else ""

        if mode == "fts":
            sql = ("SELECT s.*, f.rel AS path FROM sym_fts x JOIN symbols s ON s.id=x.rowid "
                   "JOIN files f ON f.id=s.file_id WHERE sym_fts MATCH ?" + kind_clause +
                   def_clause + " ORDER BY rank LIMIT ?")
            try:
                return [dict(r) for r in self.conn.execute(
                    sql, (name,) + kind_args + (limit,))]
            except sqlite3.Error:
                mode = "substring"      # FTS 语法不合法 → 退回可预测的子串检索

        pats = []
        if mode in ("auto", "exact"):
            pats.append(("eq", name))
        if mode in ("auto", "prefix"):
            pats.append(("pf", name + "%"))
        if mode in ("auto", "substring"):
            pats.append(("pf", "%" + name + "%"))
        conds, args = [], []
        seen = set()
        for tag, pat in pats:
            if not pat or pat in seen:
                continue
            seen.add(pat)
            if tag == "eq":
                conds.append("s.name = ?")
            else:
                conds.append("s.name LIKE ?")
            args.append(pat)
        if not conds:
            conds.append("s.name LIKE ?")
            args.append("%" + name + "%")
        if mode == "exact":
            order = "s.name = ? DESC, s.is_definition DESC, length(s.name), f.rel, s.start_line"
            extra_args = (name,)
        else:
            order = ("CASE WHEN s.name = ? THEN 0 WHEN s.name LIKE ? THEN 1 ELSE 2 END, "
                     "s.is_definition DESC, length(s.name), f.rel, s.start_line")
            extra_args = (name, name + "%")
        sql = ("SELECT s.*, f.rel AS path FROM symbols s JOIN files f ON f.id=s.file_id "
               "WHERE (" + " OR ".join(conds) + ")" + kind_clause + def_clause +
               " ORDER BY " + order + " LIMIT ?")
        rows = self.conn.execute(sql, tuple(args) + kind_args + tuple(extra_args) + (limit,))
        return [dict(r) for r in rows]

    def symbols_by_name(self, name, kind=None):
        sql = ("SELECT s.*, f.rel AS path FROM symbols s JOIN files f ON f.id=s.file_id "
               "WHERE s.name=?")
        args = [name]
        if kind:
            sql += " AND s.kind=?"
            args.append(kind)
        sql += " ORDER BY s.is_definition DESC, f.rel, s.start_line"
        return [dict(r) for r in self.conn.execute(sql, tuple(args))]

    def symbols_in_file(self, rel):
        return [dict(r) for r in self.conn.execute(
            "SELECT s.*, f.rel AS path FROM symbols s JOIN files f ON f.id=s.file_id "
            "WHERE f.rel=? ORDER BY s.start_line", (rel,))]

    def calls_from(self, caller):
        return [dict(r) for r in self.conn.execute(
            "SELECT c.*, f.rel AS path FROM calls c JOIN files f ON f.id=c.file_id "
            "WHERE c.caller=? ORDER BY f.rel, c.line", (caller,))]

    def calls_to(self, callee):
        return [dict(r) for r in self.conn.execute(
            "SELECT c.*, f.rel AS path FROM calls c JOIN files f ON f.id=c.file_id "
            "WHERE c.callee=? ORDER BY f.rel, c.line", (callee,))]

    def callers_any(self, names):
        if not names:
            return []
        sql = ("SELECT DISTINCT c.caller FROM calls c WHERE c.callee IN (%s) "
               "AND c.caller IS NOT NULL" % ",".join("?" * len(names)))
        return [r["caller"] for r in self.conn.execute(sql, tuple(names))]

    def callees_of(self, names):
        if not names:
            return []
        sql = ("SELECT DISTINCT c.callee FROM calls c WHERE c.caller IN (%s)"
               % ",".join("?" * len(names)))
        return [r["callee"] for r in self.conn.execute(sql, tuple(names))]

    def includes_of(self, rel):
        return [dict(r) for r in self.conn.execute(
            "SELECT i.*, f.rel AS path FROM includes i JOIN files f ON f.id=i.file_id "
            "WHERE f.rel=?", (rel,))]

    def includers_of(self, rel):
        return [dict(r) for r in self.conn.execute(
            "SELECT i.*, f.rel AS path FROM includes i JOIN files f ON f.id=i.file_id "
            "WHERE i.resolved_rel=?", (rel,))]

    def refs_of(self, name):
        return [dict(r) for r in self.conn.execute(
            "SELECT r.*, f.rel AS path FROM refs r JOIN files f ON f.id=r.file_id "
            "WHERE r.name=? ORDER BY f.rel, r.line", (name,))]

    def fptrs_named(self, name):
        return [dict(r) for r in self.conn.execute(
            "SELECT p.*, f.rel AS path FROM fptr p JOIN files f ON f.id=p.file_id "
            "WHERE p.name=?", (name,))]

    # ---------------------------------------------------------- 关系层（批次69）

    def include_edges(self):
        """include 图原始边 [(src_rel, resolved_rel)]。

        **只含唯一匹配上的**（系统头、项目内同名歧义头都是 NULL，不进图）——
        歧义头不能当「可见」的证据，宁可当作没连上（批次69 的 include-visible 另说）。
        """
        rows = self.conn.execute(
            "SELECT f.rel AS src, i.resolved_rel AS dst FROM includes i "
            "JOIN files f ON f.id=i.file_id WHERE i.resolved_rel IS NOT NULL")
        return [(r["src"], r["dst"]) for r in rows]

    def calls_in_file(self, rel):
        """某文件里的所有调用点（按行号）。"""
        return [dict(r) for r in self.conn.execute(
            "SELECT c.*, f.rel AS path FROM calls c JOIN files f ON f.id=c.file_id "
            "WHERE f.rel=? ORDER BY c.line", (rel,))]

    def symbol_at(self, path, line):
        """取某文件某起始行上的符号（定义优先）。用于把「解析出的候选」还原成符号行。"""
        return self.conn.execute(
            "SELECT s.*, f.rel AS path FROM symbols s JOIN files f ON f.id=s.file_id "
            "WHERE f.rel=? AND s.start_line=? ORDER BY s.is_definition DESC LIMIT 1",
            (path, int(line))).fetchone()
