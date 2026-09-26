# -*- coding: utf-8 -*-
"""批次68 mock 测试：自研 Python 代码索引层（tree-sitter + SQLite）。

背景：用户要求「吸收 CodeGraph 的省 token 能力、增强应对大型工程」。经比对，
内嵌 CodeGraph（Node/TS，261 MB 单二进制、平台相关）不可取，最终选**全 Python 自研**：
tree-sitter 解析（预编译轮子）+ SQLite 索引，落成 `mdkdebug/codeindex/`。

本批只交付**解析级事实**与 5 个工具（`code_index` / `code_status` / `code_files` /
`code_query` / `code_node`）。近似关系（调用链、影响面）与 `code_explore` /
`code_context` 留给批次69、70——本批**不猜调用图**。测试的重点因此有两块：

1. **工具真的交付了它承诺的事实**（符号/位置/源码体/调用点/include）；
2. **它没承诺的事一条都不给**——描述里不许出现拿不到的东西（`kind=fptr` 必须真能查到、
   描述里不许提未注册的工具名），且缺依赖/缺索引/坏配置一律**如实报错**，不静默降级。

> 批次71 更新（仅断言口径，产品语义见 test_batch71）：`project` 可省后，B22 改为在
> **空**索引根下验证「列候选报错、不猜当前目录」；E20 不再允许 code_node 描述声称
> 「反向调用关系本批不给」（那是批次68 的事实、批次69 起就已过时）。

分组：
  A 遍历与过滤（walk）：目录名排除 / .gitignore / codeindex.json exclude·include / 大文件
  B 生命周期：build → status（含落后判定）→ sync（增量·metadata_only·removed）→ drop
  C 解析语义（C fixture）：include guard、条件编译、局部变量、fptr、calls_out、解析错误
  D 解析语义（C++ fixture）：class/namespace/field、调用、include 解析
  E 工具层：5 个工具端到端、错误码、注解、outctl、描述诚实边界、parser-missing
  F 工具面：注册 200 / 默认面 44 / code 组 7 且默认收起 / 组数 12

运行：python -m tests.test_batch68
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

# 索引一律写临时目录（不碰 ~/.mdkdebug，也不往 fixture 工程里写）
IDX_ROOT = tempfile.mkdtemp(prefix="mdkidx_root_")
os.environ["MDKDEBUG_CODEINDEX_DIR"] = IDX_ROOT
TMP_ROOT = tempfile.mkdtemp(prefix="mdkidx_proj_")

from mdkdebug import annotate as AN                      # noqa: E402
from mdkdebug import errors as ER                        # noqa: E402
from mdkdebug import outctl as OC                        # noqa: E402
from mdkdebug import server as SV                        # noqa: E402
from mdkdebug import toolbox as TB                       # noqa: E402
from mdkdebug.codeindex import ENV_ROOT                  # noqa: E402
from mdkdebug.codeindex import build as ci_build         # noqa: E402
from mdkdebug.codeindex import db_path, drop as ci_drop  # noqa: E402
from mdkdebug.codeindex import files as ci_files         # noqa: E402
from mdkdebug.codeindex import index_root                # noqa: E402
from mdkdebug.codeindex import node as ci_node           # noqa: E402
from mdkdebug.codeindex import parser as CP              # noqa: E402
from mdkdebug.codeindex import query as ci_query         # noqa: E402
from mdkdebug.codeindex import status as ci_status       # noqa: E402
from mdkdebug.codeindex import sync as ci_sync           # noqa: E402
from mdkdebug.codeindex.store import Store as _Store     # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "codeindex")
PROJ_C = os.path.join(FIX, "proj_c")
PROJ_CPP = os.path.join(FIX, "proj_cpp")

PORT_TOOL, PORT_DEF = 14980, 14981

CODE_TOOLS = ("code_index", "code_status", "code_files", "code_query", "code_node",
              "code_relations", "code_impact")

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:600]), flush=True)


def jd(o):
    return json.dumps(o, ensure_ascii=False, default=str)


# ------------------------------------------------------------ 小工具

def mkproj(name, files, binary=None):
    """在临时目录里造一个工程。files: {相对路径: 文本}；binary: {相对路径: bytes}。"""
    d = os.path.join(TMP_ROOT, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    for rel, text in (files or {}).items():
        p = os.path.join(d, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    for rel, data in (binary or {}).items():
        p = os.path.join(d, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
    os.makedirs(d, exist_ok=True)
    return d


def copy_proj(src, name):
    d = os.path.join(TMP_ROOT, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    shutil.copytree(src, d)
    return d


def skipped_reasons(build_out):
    return {s.get("reason") for s in (build_out.get("skipped_list") or [])}


def rels_of(build_out):
    return sorted(f["rel"] for f in (build_out.get("file_list") or []))


# ------------------------------------------------------------ 服务器调用

async def _call(srv, n, a):
    res = await srv.call_tool(n, a)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    return json.loads(txt)


def call_sync(srv, n, a):
    return asyncio.run(_call(srv, n, a))


def tool_names(srv):
    return sorted(t.name for t in asyncio.run(srv.list_tools()))


def tool_descs(srv):
    return {t.name: (t.description or "") for t in asyncio.run(srv.list_tools())}


# ======================================================================
# A. 遍历与过滤
# ======================================================================
def group_a():
    print("A. 遍历与过滤（walk）")
    big_pad = "/* " + ("x" * 1000) + " */\n"
    files = {
        "src/a.c": "int a_fn(void) { return 0; }\n",
        "src/legacy.c": "int legacy_fn(void) { return 1; }\n",
        "sub/keep.c": "int keep_fn(void) { return 2; }\n",
        "keep2/k.c": "int k_fn(void) { return 3; }\n",
        "cfg/skip.c": "int skip_fn(void) { return 4; }\n",
        "ign/ign.c": "int ign_fn(void) { return 5; }\n",
        "build/gen.c": "int gen_fn(void) { return 6; }\n",
        "Objects/obj.c": "int obj_fn(void) { return 7; }\n",
        "notes.txt": "not source\n",
        ".gitignore": "ign/\nkeep2/\nsrc/legacy.c\n",
        "codeindex.json": json.dumps({"exclude": ["cfg"],
                                      "include": ["keep2", "src/legacy.c"]}),
        "big.c": "int big_fn(void) { return 8; }\n" + big_pad * 1100,
    }
    proj = mkproj("a_walk", files)
    b = ci_build(proj)
    check("A1 build 成功", b.get("ok") is True, b)
    got = sorted(f["rel"] for f in ci_files(proj).get("files") or [])
    want = {"src/a.c", "src/legacy.c", "sub/keep.c", "keep2/k.c"}
    check("A2 候选文件正是「该进的都进了、不该进的一个没有」",
          set(got) == want, "实际：%s / 期望：%s" % (got, sorted(want)))
    check("A4 include 救回了被 .gitignore 整目录排除的 keep2/、以及被忽略的 src/legacy.c",
          "keep2/k.c" in got and "src/legacy.c" in got, got)

    sk = b.get("skipped_list") or []
    by_rel = {s["rel"]: s for s in sk}
    check("A5 构建产物/工具目录按目录名排除且**照样上报**（reason=excluded-dir）",
          by_rel.get("build/", {}).get("reason") == "excluded-dir"
          and by_rel.get("Objects/", {}).get("reason") == "excluded-dir", sk)
    check("A6 被 .gitignore 忽略的目录上报 reason=gitignored",
          by_rel.get("ign/", {}).get("reason") == "gitignored", sk)
    check("A7 codeindex.json 的 exclude 命中目录上报 reason=excluded",
          by_rel.get("cfg/", {}).get("reason") == "excluded", sk)
    check("A8 >1 MB 的文件上报 reason=big 且写明上限",
          by_rel.get("big.c", {}).get("reason") == "big"
          and "上限" in (by_rel.get("big.c", {}).get("detail") or ""), sk)
    check("A9 每条跳过项都带 rel/reason/detail（不静默吞）",
          all(s.get("rel") and s.get("reason") and s.get("detail") for s in sk), sk)
    check("A10 不认识的扩展名只计数、不逐条列",
          b["files"]["unknown_ext"] >= 3 and not [s for s in sk if s["rel"].endswith(".txt")],
          b["files"])
    check("A11 files.parsed == 候选数（4 个）", b["files"]["parsed"] == 4, b["files"])

    # 坏 codeindex.json：不猜内容，如实报 config-bad
    bad = mkproj("a_badcfg", {"a.c": "int a(void){return 0;}\n",
                              "codeindex.json": "{ this is not json"})
    rb = ci_build(bad)
    check("A12 坏 codeindex.json → ok=false + config-bad（不静默吞、不猜）",
          rb.get("ok") is False and rb.get("error_code") == "config-bad"
          and rb.get("config_error"), rb)

    # exclude 必须是字符串数组
    bad2 = mkproj("a_badcfg2", {"a.c": "int a(void){return 0;}\n",
                                "codeindex.json": json.dumps({"exclude": [1, 2]})})
    rb2 = ci_build(bad2)
    check("A13 exclude 类型不对 → config-bad（并说明要求）",
          rb2.get("ok") is False and rb2.get("error_code") == "config-bad"
          and "字符串数组" in (rb2.get("error") or ""), rb2)


# ======================================================================
# B. 生命周期：build / status / sync / drop
# ======================================================================
def group_b():
    print("B. 生命周期（build / status / sync / drop）")
    proj = copy_proj(PROJ_C, "b_life")

    st0 = ci_status(proj)
    check("B1 还没建索引时 status 是**失败**（ok=false + no-index），不是「ok 但没东西」",
          st0.get("ok") is False and st0.get("error_code") == "no-index"
          and st0.get("index_exists") is False, st0)
    check("B2 没索引时 status 也给索引路径与解析器可用性（下一步动作有着落）",
          bool(st0.get("index")) and st0.get("parser", {}).get("available") is True,
          {k: st0.get(k) for k in ("index", "parser")})
    q0 = ci_query(proj, "add")
    check("B3 没索引时 query/files/node 都报 no-index（不静默返空）",
          q0.get("error_code") == "no-index"
          and ci_files(proj).get("error_code") == "no-index"
          and ci_node(proj, name="add").get("error_code") == "no-index", q0)

    b = ci_build(proj)
    check("B4 build：ok、计数正确、解析错误如实计数并列名",
          b.get("ok") is True and b["action"] == "build"
          and b["files"]["candidates"] == 4 and b["files"]["parsed"] == 4
          and b["counts"]["files"] == 4 and b["counts"]["symbols"] >= 13
          and b["counts"]["fptr"] == 1
          and b["parse_error_count"] == 1 and "broken.c" in b["parse_errors"], b)
    check("B5 build 的索引落在用户目录（不在工程目录里写）",
          b.get("in_project") is False and os.path.dirname(b["index"]) != proj
          and not os.path.isdir(os.path.join(proj, ".mdkdebug")), b.get("index"))
    check("B6 索引体积上报（含 -wal/-shm 明细）",
          b.get("index_bytes", 0) > 0 and isinstance(b.get("index_parts"), dict), b)

    st = ci_status(proj)
    check("B7 build 后 status：ok、exists、构建时间可读、build 类型、不落后",
          st.get("ok") is True and st.get("index_exists") is True
          and st.get("built_at_text") and st.get("build_kind") == "build"
          and st["stale"]["is_stale"] is False, st)
    check("B8 status 的 counts 与 build 报的一致",
          st.get("counts") == b.get("counts"), {"status": st.get("counts"),
                                                "build": b.get("counts")})

    # 改一个文件 → 落后，但**不自动重建**
    p = os.path.join(proj, "util.c")
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("/* touched */\n")
    st2 = ci_status(proj)
    check("B9 源码改动后 status 报落后（changed>=1）并给 warning_code",
          st2["stale"]["is_stale"] is True and st2["stale"]["changed"] >= 1
          and st2.get("warning_code") == "index-stale", st2.get("stale"))
    check("B10 落后只报不重建：counts 一点没变（读到的仍是旧索引）",
          st2.get("counts") == b.get("counts"), st2.get("counts"))
    check("B11 warning 明说「不会自动重建」并给出 sync 动作",
          "自动重建" in (st2.get("warning") or "")
          and "sync" in (st2.get("warning") or ""), st2.get("warning"))

    s = ci_sync(proj)
    check("B12 sync：ok、重解析改动的那个文件、没有增删",
          s.get("ok") is True and s["action"] == "sync"
          and s["files"]["reparsed"] == 1 and s["files"]["added"] == 0
          and s["files"]["removed"] == 0, s.get("files"))
    st3 = ci_status(proj)
    check("B13 sync 后不再落后，且 synced_at 有值",
          st3["stale"]["is_stale"] is False and st3.get("synced_at")
          and st3.get("build_kind") == "sync", st3.get("stale"))

    # 只动 mtime、内容没变 → metadata_only（不重解析）
    os.utime(p, (__import__("time").time() - 30, __import__("time").time() - 30))
    s2 = ci_sync(proj)
    check("B14 只改 mtime（内容没变）走 metadata_only、reparsed=0（省一次解析）",
          s2.get("ok") is True and s2["files"]["metadata_only"] == 1
          and s2["files"]["reparsed"] == 0, s2.get("files"))

    # 删一个文件
    os.remove(os.path.join(proj, "main.c"))
    s3 = ci_sync(proj)
    check("B15 源码被删后 sync 报 removed 并从索引里摘掉",
          s3.get("ok") is True and s3["files"]["removed"] == 1
          and s3.get("removed_list") == ["main.c"], s3)
    check("B16 摘掉后 query 查不到它的符号了",
          ci_query(proj, "main", mode="exact").get("count") == 0, None)

    # in_project
    p2 = copy_proj(PROJ_C, "b_inproj")
    bi = ci_build(p2, in_project=True)
    ip = os.path.join(p2, ".mdkdebug", "index.db")
    check("B17 in_project=true 才写进 <工程>/.mdkdebug/index.db",
          bi.get("ok") is True and bi["index"] == db_path(p2, in_project=True)
          and os.path.isfile(ip), bi.get("index"))
    check("B18 status(in_project) 能找到它",
          ci_status(p2, in_project=True).get("index_exists") is True, None)
    check("B19 drop(in_project) 删掉工程内索引",
          ci_drop(p2, in_project=True).get("ok") is True and not os.path.isfile(ip), None)

    # drop
    d = ci_drop(proj)
    check("B20 drop：ok、列出删掉的文件、明说源码未动",
          d.get("ok") is True and d.get("removed") and "源码未动" in (d.get("note") or ""), d)
    check("B21 drop 后 status 立刻回到 no-index",
          ci_status(proj).get("error_code") == "no-index", None)

    # 批次71 起：project 省略只在「本机**唯一**一个已建索引的工程」时自动用（并在返回体里
    # 写 project_source/project_inferred）；多个或一个都没有时列候选报错。这里把索引根换到
    # 一个空目录，验证「一个都没有」这条路：build 列候选报 project-required，status 报 no-index。
    _old_root = os.environ.get(ENV_ROOT)
    os.environ[ENV_ROOT] = tempfile.mkdtemp(prefix="mdkidx_empty_")
    try:
        _b0, _s0 = ci_build(""), ci_status("")
        check("B22 没给 project 且本机无可用索引 → 列候选报错（不猜当前目录）",
              _b0.get("error_code") == "project-required" and _b0.get("candidates") == []
              and "源码根目录" in (_b0.get("hint") or "")
              and _s0.get("error_code") == "no-index", {"build": _b0, "status": _s0})
    finally:
        os.environ[ENV_ROOT] = _old_root
    check("B23 目录不存在 → project-required（带绝对路径）",
          ci_build(os.path.join(TMP_ROOT, "no_such_dir")).get("error_code")
          == "project-required", None)
    check("B24 sync 没有索引时给 no-index + 建索引的做法（不是崩）",
          ci_sync(mkproj("b_nosync", {"a.c": "int a(void){return 0;}\n"})).get("error_code")
          == "no-index", None)


# ======================================================================
# C. 解析语义（C fixture）
# ======================================================================
def group_c():
    print("C. 解析语义（C）")
    b = ci_build(PROJ_C)
    check("C0 proj_c 建索引成功", b.get("ok") is True, b)

    q = ci_query(PROJ_C, "add")
    kinds = [(s["kind"], s["path"], s["line"], s["is_definition"]) for s in q["symbols"]]
    check("C1 同名多处（.c 定义 + .h 声明）全给，不猜要哪一个",
          ("function", "util.c", 5, True) in kinds
          and ("function", "inc/util.h", 11, False) in kinds, kinds)
    check("C2 include guard 里的东西**不**被标成条件编译（整头文件不是「条件编译」）",
          all(s["in_conditional"] is False for s in q["symbols"]), kinds)

    big = ci_query(PROJ_C, "big_only", mode="exact")["symbols"]
    check("C3 真条件编译（#if LIMIT > 4）里的符号标 in_conditional=true",
          len(big) == 1 and big[0]["in_conditional"] is True, big)
    lim = ci_node(PROJ_C, name="LIMIT")
    refs = (lim.get("candidates") or [{}])[0].get("refs") or []
    check("C4 refs 里给出条件编译里宏名出现的行（macro_use）",
          any(r["kind"] == "macro_use" and r["path"] == "inc/util.h" for r in refs), refs)

    check("C5 局部变量不进符号表（mode=exact 查不到函数体内的 r）",
          ci_query(PROJ_C, "r", mode="exact").get("count") == 0, None)
    check("C6 文件作用域变量进符号表、static 如实标出",
          [(s["kind"], s["storage"]) for s in
           ci_query(PROJ_C, "hidden", mode="exact")["symbols"]] == [("variable", "static")],
          ci_query(PROJ_C, "hidden", mode="exact")["symbols"])

    fp = ci_query(PROJ_C, "on_tick", mode="exact")["symbols"]
    check("C7 kind=fptr 真能查到函数指针声明（描述承诺了就必须拿得到）",
          len(fp) == 1 and fp[0]["kind"] == "fptr" and fp[0]["path"] == "main.c", fp)
    check("C8 fptr 表也记了它（盲区证据；build 计数里有 fptr）",
          b["counts"]["fptr"] == 1, b.get("counts"))

    n = ci_node(PROJ_C, name="add")
    cands = n.get("candidates") or []
    defs = [c for c in cands if c["is_definition"]]
    decls = [c for c in cands if not c["is_definition"]]
    check("C9 node(add) 给候选，定义的体范围是真范围（含大括号所在行）",
          len(defs) == 1 and defs[0]["body_start"] == 6 and defs[0]["body_end"] == 9
          and defs[0]["code"] and defs[0]["code"][0]["text"].strip() == "{", cands)
    check("C10 声明没有体：body_start/body_end 为 None（不编一个范围出来）",
          len(decls) == 1 and decls[0]["body_start"] is None
          and decls[0]["body_end"] is None, decls)
    check("C11 源码体带行号、与磁盘内容一致（可当 Read 用）",
          [c["line"] for c in defs[0]["code"]] == [6, 7, 8, 9]
          and defs[0]["code"][1]["text"].strip() == "hidden++;", defs[0]["code"])

    nm = ci_node(PROJ_C, name="main")["candidates"][0]
    callees = sorted(c["callee"] for c in nm["calls_out"])
    check("C12 calls_out 给「该符号体内的调用点」（解析级事实）",
          callees == ["add", "on_tick", "printf"] and nm["calls_out_count"] == 3,
          nm.get("calls_out"))
    check("C13 calls_out 每条带行号，且不冒充「谁调了它」",
          all(isinstance(c["line"], int) and c["line"] > 0 for c in nm["calls_out"])
          and not nm.get("callers") and not nm.get("calls_in"), nm.get("calls_out"))
    # 批次69 起反向关系由 code_relations 交付：node 自己**仍然不给**图，只在 note 里
    # 明确「反向是推断」并指到那两个工具（不越权、也不留一个「谁调了它」的空承诺）
    _n14 = ci_node(PROJ_C, name="main").get("note") or ""
    check("C14 node 的 note 明说反向「谁调了它」是推断、不在这里给，并指到 code_relations",
          "是推断" in _n14 and "code_relations" in _n14 and "code_impact" in _n14
          and not ci_node(PROJ_C, name="main").get("callers"), _n14)

    fr = ci_node(PROJ_C, file="main.c")
    check("C15 file 模式给整文件带行号（Read-parity），并附该文件符号",
          fr.get("ok") is True and fr["mode"] == "file" and fr["line_count"] == 14
          and fr["start_line"] == 1 and fr["end_line"] == 14
          and {"main", "g_counter", "on_tick"} <= {s["name"] for s in fr["symbols"]},
          {k: fr.get(k) for k in ("line_count", "symbols")})
    seg = ci_node(PROJ_C, file="main.c", start_line=8, end_line=10)
    check("C16 file 模式支持 start_line/end_line 只取一段",
          seg.get("line_count") == 3 and seg["code"][0]["line"] == 8
          and "main" in seg["code"][0]["text"], seg.get("code"))
    check("C17 node(file=不存在的文件) → file-not-found（不返空体）",
          ci_node(PROJ_C, file="nope.c").get("error_code") == "file-not-found", None)
    check("C18 node(name=不存在的符号) → symbol-not-found",
          ci_node(PROJ_C, name="no_such_symbol").get("error_code") == "symbol-not-found", None)
    check("C19 node 既不给 name 也不给 file → invalid-argument（并说明两种用法）",
          ci_node(PROJ_C).get("error_code") == "invalid-argument"
          and ci_node(PROJ_C).get("hint"), None)

    check("C20 语法有错的文件照样索引已解析部分，但如实列进 parse_errors",
          b["parse_error_count"] == 1 and b["parse_errors"] == ["broken.c"]
          and ci_query(PROJ_C, "broken_fn", mode="exact").get("count") == 1, b.get("parse_errors"))
    sc = ci_status(PROJ_C)
    check("C20b parse_error 落库：status 也能如实报索引不完整（不只在 build 时报一次）",
          sc.get("parse_error_count") == 1 and sc.get("parse_errors") == ["broken.c"]
          and "不可全信" in (sc.get("parse_errors_note") or ""),
          {k: sc.get(k) for k in ("parse_error_count", "parse_errors")})

    fl = ci_files(PROJ_C)
    check("C21 files：rel/lang/行数/符号数齐全，dirs 含顶层目录 inc",
          {f["rel"] for f in fl["files"]} == {"broken.c", "inc/util.h", "main.c", "util.c"}
          and fl["dirs"] == ["inc"]
          and all(f["lang"] == "c" and f["lines"] > 0 for f in fl["files"]), fl)
    check("C22 files(pattern=) 支持 * 过滤",
          sorted(f["rel"] for f in ci_files(PROJ_C, pattern="*util*")["files"])
          == ["inc/util.h", "util.c"], ci_files(PROJ_C, pattern="*util*")["files"])
    # max_depth = **路径层数上限**（a.c=1 层，inc/util.h=2 层）；0/省略 = 不限制
    check("C23 files(max_depth=1) 只留顶层文件；max_depth=2 才含 inc/ 下的",
          {f["rel"] for f in ci_files(PROJ_C, max_depth=1)["files"]}
          == {"broken.c", "main.c", "util.c"}
          and {f["rel"] for f in ci_files(PROJ_C, max_depth=2)["files"]}
          == {"broken.c", "inc/util.h", "main.c", "util.c"}
          and {f["rel"] for f in ci_files(PROJ_C, max_depth=0)["files"]}
          == {"broken.c", "inc/util.h", "main.c", "util.c"}, None)

    check("C24 kind 过滤可用（function / struct）",
          all(s["kind"] == "function" for s in ci_query(PROJ_C, "add", kind="function")["symbols"])
          and [s["kind"] for s in ci_query(PROJ_C, "point", kind="struct")["symbols"]]
          == ["struct"], None)
    check("C25 only_definitions=true 跳过声明",
          all(s["is_definition"] for s in
              ci_query(PROJ_C, "add", only_definitions=True)["symbols"])
          and ci_query(PROJ_C, "add", only_definitions=True)["count"] == 1, None)
    check("C26 mode=exact 不匹配前缀/子串；prefix 才匹配",
          ci_query(PROJ_C, "poin", mode="exact")["count"] == 0
          and ci_query(PROJ_C, "poin", mode="prefix")["count"] >= 1, None)
    check("C27 query 只回位置与签名、不回源码体（省 token 的关键）",
          all("code" not in s and "signature" in s
              for s in ci_query(PROJ_C, "add")["symbols"]), None)
    st = _Store(db_path(PROJ_C)).open()
    inc_rows = [dict(x) for x in st.conn.execute(
        "SELECT i.target, i.is_system, i.resolved_rel, f.rel AS src "
        "FROM includes i JOIN files f ON f.id=i.file_id").fetchall()]
    st.close()
    # 归一化：`#ifdef __cplusplus / extern "C" {` 成对的写法（嵌入式头文件几乎每个都有）
    # 会让 tree-sitter 走恢复态；抹成等长空格后不再误报，而**后面的声明照样进索引**。
    idiom = ('#ifndef CPP_GUARD_H\n#define CPP_GUARD_H\n\n'
             '#ifdef __cplusplus\nextern "C" {\n#endif\n\n'
             'int after_guard(int x);\nvoid second_decl(void);\n\n'
             '#ifdef __cplusplus\n}\n#endif\n\n#endif /* CPP_GUARD_H */\n')
    ng = mkproj("c_guard", {"inc/cpp_guard.h": idiom,
                            "use.c": '#include "inc/cpp_guard.h"\n'
                                     'int after_guard(int x){return x;}\n'})
    nb = ci_build(ng)
    check("C29 extern \"C\" 跨条件括号的头文件不再误报 parse_error（归一化生效）",
          nb.get("ok") is True and nb["parse_error_count"] == 0
          and nb["normalized_count"] == 1, (nb.get("parse_error_count"),
                                            nb.get("normalized_count")))
    ag = ci_node(ng, name="after_guard")
    check("C30 归一化不影响文件后半部分的符号（行列偏移不变，声明照样进索引）",
          ag.get("count") == 2
          and sorted((c["path"], c["start_line"]) for c in ag["candidates"])
          == [("inc/cpp_guard.h", 8), ("use.c", 2)]
          and ci_query(ng, "second_decl", mode="exact").get("count") == 1,
          ag.get("candidates"))
    nsc = ci_status(ng)
    check("C30b status 也报归一化计数（不是只在 build 里说一次）",
          nsc.get("normalized_count") == 1 and nsc.get("parse_error_count") == 0
          and "等长空格" in (nsc.get("normalized_note") or ""),
          {k: nsc.get(k) for k in ("normalized_count", "parse_error_count")})

    check("C28 include 后置解析：工程内唯一 basename 才解析，系统头（stdio.h）不解析",
          all(r["resolved_rel"] == "inc/util.h" for r in inc_rows
              if r["target"] == "inc/util.h")
          and all(r["resolved_rel"] is None for r in inc_rows if r["is_system"])
          and len(inc_rows) == 3, inc_rows)


# ======================================================================
# D. 解析语义（C++）
# ======================================================================
def group_d():
    print("D. 解析语义（C++）")
    b = ci_build(PROJ_CPP)
    check("D0 proj_cpp 建索引成功、无解析错误", b.get("ok") is True
          and b["parse_error_count"] == 0, b)
    w = ci_query(PROJ_CPP, "Widget", mode="exact")["symbols"]
    check("D1 C++ class 进符号表（kind=class）",
          any(s["kind"] == "class" and s["path"] == "widget.hpp" for s in w), w)
    ns = ci_query(PROJ_CPP, "demo", mode="exact")["symbols"]
    check("D2 namespace 进符号表，两个文件各一份都给",
          {s["path"] for s in ns if s["kind"] == "namespace"}
          == {"widget.hpp", "widget.cpp"}, ns)
    check("D3 C++ 成员字段 kind=field",
          [s["kind"] for s in ci_query(PROJ_CPP, "v_", mode="exact")["symbols"]] == ["field"],
          ci_query(PROJ_CPP, "v_", mode="exact")["symbols"])
    sc = ci_query(PROJ_CPP, "scale", mode="exact")["symbols"]
    check("D4 C++ 函数与 static 存储类如实标出",
          len(sc) == 1 and sc[0]["kind"] == "function" and sc[0]["storage"] == "static", sc)
    tw = ci_node(PROJ_CPP, name="twice")["candidates"][0]
    check("D5 C++ 调用点收集（两次调用同一函数各记一条，带行号）",
          [c["callee"] for c in tw["calls_out"]] == ["scale", "scale"]
          and tw["calls_out_count"] == 2, tw.get("calls_out"))
    check("D6 C++ include 也走唯一 basename 解析",
          ci_build(PROJ_CPP).get("ok") is True, None)
    fl = ci_files(PROJ_CPP)
    check("D7 .hpp 按 C++ 语言建索引（不是按 C）",
          {f["rel"]: f["lang"] for f in fl["files"]}
          == {"widget.cpp": "cpp", "widget.hpp": "cpp"}, fl["files"])

    # refs 只含可证的两类
    allrefs = set()
    store = _Store(db_path(PROJ_CPP)).open()
    for r in store.conn.execute("SELECT DISTINCT kind FROM refs").fetchall():
        allrefs.add(r["kind"])
    store.close()
    check("D8 refs 只有 type_use / macro_use 两类（不冒充「所有引用」）",
          allrefs <= {"type_use", "macro_use"}, allrefs)


# ======================================================================
# E. 工具层
# ======================================================================
def group_e():
    print("E. 工具层（5 个工具 + 错误码 + 注解 + 描述边界）")
    proj = copy_proj(PROJ_C, "e_tools")
    srv = SV.create_server(port=PORT_TOOL, toolsets="all")
    ns = tool_names(srv)

    r = call_sync(srv, "code_index", {"action": "status", "project": proj})
    check("E1 code_index(action=status) 端到端可用（未建索引时如实报 no-index）",
          r.get("ok") is False and r.get("error_code") == "no-index", r)
    r1 = call_sync(srv, "code_index", {"action": "build", "project": proj})
    check("E2 code_index(action=build) 建起来，计数回给调用方",
          r1.get("ok") is True and r1["counts"]["files"] == 4, r1)
    r2 = call_sync(srv, "code_query", {"project": proj, "name": "add"})
    check("E3 code_query 回位置+签名、不回源码体",
          r2.get("ok") is True and r2["count"] == 2
          and all("code" not in s for s in r2["symbols"]), r2)
    r3 = call_sync(srv, "code_node", {"project": proj, "name": "add"})
    check("E4 code_node 回源码体与 calls_out",
          r3.get("ok") is True and r3["count"] == 2
          and any(c["body_start"] for c in r3["candidates"]), r3)
    r4 = call_sync(srv, "code_files", {"project": proj, "pattern": "*util*"})
    check("E5 code_files 支持 pattern",
          r4.get("ok") is True and r4["count"] == 2, r4)
    r5 = call_sync(srv, "code_status", {"project": proj})
    check("E6 code_status 报 exist/不落后/解析器可用",
          r5.get("ok") is True and r5["index_exists"] is True
          and r5["stale"]["is_stale"] is False
          and r5["parser"]["available"] is True, r5)

    r6 = call_sync(srv, "code_index", {"action": "bogus", "project": proj})
    check("E7 不认识的 action → invalid-argument + 列出可取值",
          r6.get("ok") is False and r6.get("error_code") == "invalid-argument"
          and "status" in (r6.get("hint") or ""), r6)
    r7 = call_sync(srv, "code_query", {"project": proj, "name": ""})
    check("E8 空 name → invalid-argument", r7.get("error_code") == "invalid-argument", r7)
    empty = mkproj("e_empty", {"x.c": "int x(void){return 0;}\n"})
    check("E9 五个工具在没索引的项目上一致地报 no-index",
          call_sync(srv, "code_status", {"project": empty}).get("error_code") == "no-index"
          and call_sync(srv, "code_files", {"project": empty}).get("error_code") == "no-index"
          and call_sync(srv, "code_query", {"project": empty, "name": "x"}).get("error_code")
          == "no-index"
          and call_sync(srv, "code_node", {"project": empty, "file": "x.c"}).get("error_code")
          == "no-index", None)
    r8 = call_sync(srv, "code_node", {"project": proj, "name": "no_such"})
    check("E10 symbol-not-found 走统一信封（带 error_code）",
          r8.get("ok") is False and r8.get("error_code") == "symbol-not-found", r8)
    r9 = call_sync(srv, "code_index", {"action": "drop", "project": proj})
    # `risk` 是统一信封的**等级**（high/medium，一个键名一义），风险文案走 note
    check("E11 drop：信封给结构化 risk/reversible，note 说清「只删索引、源码未动」",
          r9.get("ok") is True and r9.get("risk") == "medium"
          and r9.get("reversible") is True and "源码未动" in (r9.get("note") or ""), r9)

    # parser-missing：依赖缺失时如实报，不退化成 grep
    saved, saved_err = CP._TS_OK, CP._TS_ERR
    try:
        CP._TS_OK, CP._TS_ERR = False, "ImportError: no module named 'tree_sitter'"
        pm = call_sync(srv, "code_index", {"action": "build", "project": proj})
        check("E12 缺 tree-sitter → parser-missing + 装法（不假装成功）",
              pm.get("ok") is False and pm.get("error_code") == "parser-missing"
              and "pip install" in (pm.get("hint") or ""), pm)
        check("E13 依赖缺失时 status 也如实说不可用（不报「能用」）",
              call_sync(srv, "code_status", {"project": proj})
              ["parser"]["available"] is False, None)
    finally:
        CP._TS_OK, CP._TS_ERR = saved, saved_err

    # 注解 / outctl / 错误码
    check("E14 annotate：4 个只读、code_index 归「会改」但**不**归「破坏性」",
          all(t in AN.READONLY for t in CODE_TOOLS if t != "code_index")
          and "code_index" in AN.MUTATING
          and "code_index" not in AN.DESTRUCTIVE, None)
    check("E15 annotate.check_surface 在全部工具上无问题",
          not AN.check_surface(ns), AN.check_surface(ns))
    check("E16 outctl：4 个查询类工具进了高输出名单（compact/max_lines 就位）",
          all(t in OC.HIGH_OUTPUT for t in
              ("code_index", "code_files", "code_query", "code_node")), None)
    miss = []
    for code in ("parser-missing", "no-index", "index-stale", "index-schema-mismatch",
                 "index-write-failed", "index-drop-failed", "config-bad",
                 "symbol-not-found"):
        e = ER.ERROR_CODES.get(code) or {}
        if not e.get("next_actions"):
            miss.append(code)
    check("E17 8 个新错误码都在册且都带 next_actions（含 file-not-found 复用既有码）",
          not miss and ER.ERROR_CODES.get("file-not-found"), miss)

    # 描述诚实边界：不指向未注册的工具、不承诺拿不到的东西
    ds = tool_descs(srv)
    check("E18 5 个工具都已注册且有描述",
          all(t in ds and len(ds[t]) > 80 for t in CODE_TOOLS),
          [t for t in CODE_TOOLS if t not in ds])
    import re as _re
    mentioned = set()
    for t in CODE_TOOLS:
        mentioned |= set(_re.findall(r"code_[a-z_]+", ds[t]))
    # `code_error` 是响应体字段名（取源码时的 OS 错误），不是工具名——白名单豁免
    FIELDS = {"code_error"}
    ghost = sorted(m for m in mentioned if m not in ns and m not in FIELDS)
    check("E19 描述里提到的 code_* 工具**全都真实注册**（不指向不存在的工具）",
          not ghost, ghost)
    check("E19b 描述里的 code_* 字段名只用已声明的（code_error 是响应字段，不是工具）",
          "code_error" in mentioned and "code_error" not in CODE_TOOLS, sorted(mentioned))
    # 批次71：code_node 描述里那句「反向调用关系本批**不给**」是批次68 的事实、批次69 就
    # 已经过时了（两种口径写在同一份描述里，读者只能挑一个信）。改成要求它**指向**
    # code_relations / code_impact。
    check("E20 code_node 描述把「谁调了它」交给 code_relations（不再声称不给）",
          "code_relations" in ds["code_node"] and "code_impact" in ds["code_node"]
          and "本批**不给**" not in ds["code_node"], None)
    check("E21 code_query 描述交代「不含局部变量」",
          "局部变量" in ds["code_query"], None)
    check("E22 code_status 描述交代「落后不会自动重建」",
          "自动重建" in ds["code_status"], None)
    check("E23 code_index 描述交代「不会在后台偷偷建」与 skipped_list 的诚实口径",
          "偷偷" in ds["code_index"] and "skipped_list" in ds["code_index"], None)
    check("E24 code_node 描述把 calls_out 与 refs 的区别写清楚",
          "calls_out" in ds["code_node"] and "refs" in ds["code_node"]
          and "推断" in ds["code_node"], None)

    check("E25 索引根目录确实被环境变量改道（测试不碰 ~/.mdkdebug）",
          index_root() == os.path.abspath(IDX_ROOT)
          and os.environ.get(ENV_ROOT) == IDX_ROOT, index_root())


# ======================================================================
# F. 工具面
# ======================================================================
def group_f():
    print("F. 工具面")
    os.environ.pop("MDKDEBUG_TOOLSETS", None)
    srv_def = SV.create_server(port=PORT_DEF, toolsets=None)
    nd = tool_names(srv_def)
    srv_all = SV.create_server(port=PORT_TOOL, toolsets="all")
    na = tool_names(srv_all)

    check("F1 注册总数 200", len(na) == 200, len(na))
    check("F2 默认只暴露 44 个", len(nd) == 44, len(nd))
    check("F3 code 组默认收起（4 个 code_* 都不在默认面）",
          not any(t.startswith("code_") for t in nd), [t for t in nd if t.startswith("code_")])
    check("F4 code 组正好是那 7 个工具",
          TB.TOOLSETS.get("code") == set(CODE_TOOLS), TB.TOOLSETS.get("code"))
    check("F5 组数 12，且每个组都有用途说明",
          len(TB.TOOLSETS) == 12 and len(TB.GROUP_NOTES) == 12
          and "code" in TB.GROUP_NOTES, (len(TB.TOOLSETS), len(TB.GROUP_NOTES)))
    check("F6 高输出工具 48 个（批次68 +4、批次69 +2）", len(OC.HIGH_OUTPUT) == 48,
          len(OC.HIGH_OUTPUT))
    st = call_sync(srv_def, "toolset", {"action": "status"})
    grp = (st.get("groups") or {}).get("code") or {}
    check("F7 toolset(status) 列得出 code 组与规模",
          grp.get("size") == 7, (st.get("groups") or {}).get("code"))
    r = call_sync(srv_def, "toolset", {"action": "load", "toolsets": "code"})
    check("F8 toolset(load, code) 能把 7 个装回来，暴露数 44→51",
          r.get("ok") is True and len(r.get("loaded") or []) == 7
          and r.get("exposed") == 51, r)
    check("F9 装回后 code_query 立刻可调",
          "code_query" in tool_names(srv_def), None)
    # 用**新的**默认面服务器：srv_def 上刚 load 过 code，不再是「未装载」
    srv_fresh = SV.create_server(port=PORT_DEF + 2, toolsets=None)
    cap = call_sync(srv_fresh, "capabilities", {})
    surf = cap.get("tool_surface") or {}
    check("F10 capabilities 的 tool_surface 里 code 组 7 个且列为「未装载」",
          (surf.get("groups") or {}).get("code") == 7
          and "code" in (surf.get("not_loaded_groups") or [])
          and surf.get("registered_total") == 200, surf)


def main():
    print("批次68：自研 Python 代码索引层（tree-sitter + SQLite，7 个工具）")
    print("索引根：%s" % IDX_ROOT)
    group_a()
    group_b()
    group_c()
    group_d()
    group_e()
    group_f()
    print("\n==== 批次68 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
