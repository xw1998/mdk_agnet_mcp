# -*- coding: utf-8 -*-
"""批次69 mock 测试：关系与置信度（basis / 盲区 / code_relations / code_impact）。

批次68 只交付**解析级事实**（符号在哪、调用点在哪、include 指向谁），并明说「不猜调用图」。
批次69 把那些事实拼成**关系结论**，每条结论都带「凭什么」：

  basis            confidence   含义
  exact            high         证明得到（同文件唯一定义 / TU 可见声明且全工程唯一定义）
  include-visible  medium       include 链可达但有多个同名定义（候选全列给你自己挑）
  name-only        low          只见同名、未证实可见性
  blind            None         静态看不到（函数指针调用 / 工程内查不到定义）

本批测试的重点因此不在「有没有结果」，而在**结果有没有越界**：

1. **`resolved` 只在 exact 时非空**——把猜测填进 `resolved` 就是「看似权威的错答案」；
2. **盲区要报数、报位置**（函数指针调用、条件编译内的调用、查不到定义的调用点），
   不许画一张看起来完整的调用图；
3. **下钻只沿 exact 的边**（callees 的 depth>1）——拿猜出来的边继续下钻，第二层起全是假的；
4. 可见性只走**唯一匹配上**的 include 边（系统头/歧义头不进图），猜来的可见性会把
   include-visible 抬成假 exact。

fixture `proj_rel/` 专门为这些边界造：`dup_fn`（两处同名 static → name-only/ambiguous）、
`printf`（无定义 → blind）、`cb_hook`（函数指针变量 → blind）、`cond_use`（条件编译内调用）、
`CALL_IT`（宏 → exact 但 note 说明宏展开看不见）、`alt_ping`（经 include 传递闭包可见）。

分组：
  A 可见性：include 边只收唯一匹配 / 传递闭包 / 含自身 / 不存在的文件
  B 三档 basis 归属（含四类盲区与「resolved 只在 exact」红线）
  C 盲区统计：blind_spots 逐名 / project_blind_spots 全量
  D relations：边、summary、depth 下钻、path/line 限定、错误码
  E impact：direct/possible/unresolved/indirect 分段
  F 工具层：2 个工具端到端、错误码、注解、outctl、描述诚实边界
  G 工具面：注册 199 / 默认面 44 / code 组 7 且默认收起 / 组数 12 / 高输出 48

运行：python -m tests.test_batch69
"""
import asyncio
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

# 索引一律写临时目录（不碰 ~/.mdkdebug，也不往 fixture 工程里写）
IDX_ROOT = tempfile.mkdtemp(prefix="mdkidx69_root_")
os.environ["MDKDEBUG_CODEINDEX_DIR"] = IDX_ROOT
TMP_ROOT = tempfile.mkdtemp(prefix="mdkidx69_proj_")

from mdkdebug import annotate as AN                      # noqa: E402
from mdkdebug import errors as ER                        # noqa: E402
from mdkdebug import outctl as OC                        # noqa: E402
from mdkdebug import server as SV                        # noqa: E402
from mdkdebug import toolbox as TB                       # noqa: E402
from mdkdebug.codeindex import ENV_ROOT                  # noqa: E402
from mdkdebug.codeindex import build as ci_build         # noqa: E402
from mdkdebug.codeindex import db_path, impact           # noqa: E402
from mdkdebug.codeindex import index_root                # noqa: E402
from mdkdebug.codeindex import relations                 # noqa: E402
from mdkdebug.codeindex import resolve as RS             # noqa: E402
from mdkdebug.codeindex.store import Store as _Store     # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "codeindex")
PROJ_REL = os.path.join(FIX, "proj_rel")

PORT_TOOL, PORT_DEF = 14990, 14991

CODE_TOOLS = ("code_index", "code_status", "code_files", "code_query", "code_node",
              "code_relations", "code_impact")
REL_TOOLS = ("code_relations", "code_impact")

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:600]), flush=True)

def jd(o):
    return json.dumps(o, ensure_ascii=False, default=str)

# ------------------------------------------------------------ 小工具

_built = {"done": False}

def ensure_built():
    if not _built["done"]:
        b = ci_build(PROJ_REL)
        assert b.get("ok") is True, b
        _built["fixture"] = b
        _built["done"] = True
    return _built["fixture"]

def store_open():
    return _Store(db_path(PROJ_REL)).open()

def all_call_sites(st):
    """全索引的调用点（逐文件取，走 store 已有接口，不直接摸 conn）。"""
    out = []
    for f in (glob_files() or []):
        out.extend(st.calls_in_file(f["rel"]))
    return out

def glob_files():
    from mdkdebug.codeindex import files as ci_files
    return ci_files(PROJ_REL).get("files")

def mkproj(name, files):
    d = os.path.join(TMP_ROOT, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    for rel, text in (files or {}).items():
        p = os.path.join(d, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    os.makedirs(d, exist_ok=True)
    return d

def copy_proj(src, name):
    d = os.path.join(TMP_ROOT, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    shutil.copytree(src, d)
    return d

def callers_of(name, direction="callers", **kw):
    o = relations(PROJ_REL, name=name, direction=direction, **kw)
    assert o.get("ok") is True, o
    return o

def edge_at(edges, path, line):
    hit = [e for e in (edges or [])
           if e.get("caller_path", e.get("path")) == path and e.get("line") == line]
    return hit[0] if hit else None

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
# A. 可见性（include 边 + 传递闭包）
# ======================================================================
def group_a():
    print("A. 可见性：include 边与传递闭包")
    b = ensure_built()
    check("A1 fixture 建索引成功（files 14 / includes 9 / calls 12）",
          b["counts"]["files"] == 14 and b["counts"]["includes"] == 9
          and b["counts"]["calls"] == 12, b["counts"])

    st = store_open()
    try:
        rv = RS.Resolver(st)
        edges = rv.include_edges()
        check("A2 include 边只收**唯一匹配上**的（系统头 <stdio.h> 不进图）",
              set(edges.get("main.c") or ()) == {"inc/util.h", "inc/alt.h"}
              and not any("stdio" in d for ds in edges.values() for d in ds),
              sorted(edges.items()))
        check("A3 每条边都是「src 文件 → 解析到的项目内相对路径」",
              all(isinstance(k, str) and all(isinstance(d, str) and "/" in d or d
                                            for d in v)
                  for k, v in edges.items()), sorted(edges.items()))
        vis_main = rv.visible_files("main.c")
        check("A4 可见集含自身 + 直接 include",
              vis_main == {"main.c", "inc/util.h", "inc/alt.h"}, sorted(vis_main))
        vis_alt = rv.visible_files("alt.c")
        check("A5 可见性是 include **传递闭包**（alt.c 经 inc/alt.h 与 inc/util.h）",
              "inc/util.h" in vis_alt and "inc/alt.h" in vis_alt, sorted(vis_alt))
        check("A6 没有 include 的文件只见自己（dup_probe.c 看不到 dup_a.c 的 static）",
              rv.visible_files("dup_probe.c") == {"dup_probe.c"},
              sorted(rv.visible_files("dup_probe.c")))
        check("A7 不存在的文件不报错，如实回「只有它自己」",
              rv.visible_files("zzz.c") == {"zzz.c"}, sorted(rv.visible_files("zzz.c")))
        check("A8 可见性带缓存（同一对象，不重复遍历）",
              rv.visible_files("main.c") is rv.visible_files("main.c"), None)
        check("A9 边界常量：BASIS_CONFIDENCE 三档 + blind 不给置信度",
              RS.BASIS_CONFIDENCE == {"exact": "high", "include-visible": "medium",
                                      "name-only": "low", "blind": None},
              RS.BASIS_CONFIDENCE)
        check("A10 CALLABLE_KINDS 含 macro_fn（调用点可能被宏展开）",
              "macro_fn" in RS.CALLABLE_KINDS, RS.CALLABLE_KINDS)
    finally:
        st.close()

# ======================================================================
# B. 三档 basis 归属
# ======================================================================
def group_b():
    print("B. 三档 basis 归属（含四类盲区）")
    ensure_built()
    st = store_open()
    try:
        rv = RS.Resolver(st)
        all_sites = all_call_sites(st)

        r = rv.resolve_callee("main.c", "util_add")
        check("B1 跨文件 + include 可见声明 + 全工程唯一定义 → exact/high",
              r["basis"] == "exact" and r["confidence"] == "high"
              and [c["path"] for c in r["resolved"]] == ["util.c"]
              and "可见该声明" in (r["note"] or ""), r)

        r = rv.resolve_callee("main.c", "helper_local")
        check("B2 同文件唯一同名定义（static）→ exact/high",
              r["basis"] == "exact" and r["confidence"] == "high"
              and r["resolved"][0]["path"] == "main.c"
              and "同文件内唯一同名定义" in (r["note"] or ""), r)

        r = rv.resolve_callee("alt.c", "util_add")
        check("B3 alt.c 的调用点可见 util_add（同 B1 结论，位置不同）",
              r["basis"] == "exact" and r["confidence"] == "high"
              and r["resolved"][0]["line"] == 3, r)

        r = rv.resolve_callee("dup_probe.c", "dup_fn")
        check("B4 只见同名 + 工程内两个同名 static → name-only/low + ambiguous",
              r["basis"] == "name-only" and r["confidence"] == "low"
              and r["ambiguous"] is True and len(r["candidates"]) == 2
              and "未证实可见性" in (r["note"] or ""), r)
        check("B5 **红线**：name-only 的 resolved 必须为空（猜测只进 candidates）",
              r["resolved"] == [] and len(r["candidates"]) == 2, r)

        r = rv.resolve_callee("dup_a.c", "dup_fn")
        check("B6 同名 static 在**本文件内**唯一 → 仍算 exact（可证）",
              r["basis"] == "exact" and r["resolved"][0]["path"] == "dup_a.c", r)

        r = rv.resolve_callee("cb.c", "cb_hook")
        check("B7 目标是**函数指针变量** → blind（不猜指向谁）",
              r["basis"] == "blind" and r["confidence"] is None
              and r["resolved"] == [] and "函数指针变量" in (r["note"] or ""), r)

        r = rv.resolve_callee("main.c", "printf")
        check("B8 工程内查不到定义 → blind（宏展开/系统函数/汇编/未索引）",
              r["basis"] == "blind" and r["confidence"] is None
              and r["resolved"] == [] and "查不到该名字的定义" in (r["note"] or ""), r)

        r = rv.resolve_callee("macro.c", "CALL_IT")
        check("B9 可见的宏定义 → exact，但 note **明说宏展开后看不见**",
              r["basis"] == "exact" and r["confidence"] == "high"
              and "目标是宏" in (r["note"] or ""), r)

        r = rv.resolve_callee("macro.c", "macro_target")
        check("B10 宏文件里的普通函数调用照样 exact（不因同文件有宏就降级）",
              r["basis"] == "exact" and r["resolved"][0]["path"] == "macro.c", r)

        # 红线全量复核：遍历所有调用点，非 exact 的一律 resolved==[]
        bad = []
        for s in all_sites:
            rr = rv.resolve_callee(s["path"], s["callee"], bool(s["via_pointer"]))
            if rr["basis"] != "exact" and rr["resolved"]:
                bad.append((s["path"], s["line"], s["callee"], rr["basis"]))
        check("B11 **红线全量复核**：非 exact 的边一条都不许填 resolved",
              not bad, bad)

        # basis → confidence 映射一致
        mismatch = []
        for s in all_sites:
            rr = rv.resolve_callee(s["path"], s["callee"], bool(s["via_pointer"]))
            if rr["confidence"] != RS.BASIS_CONFIDENCE.get(rr["basis"]):
                mismatch.append((s["callee"], rr["basis"], rr["confidence"]))
        check("B12 confidence 严格由 basis 推出（没有「blind 却给 high」这种）",
              not mismatch, mismatch)
    finally:
        st.close()

# ======================================================================
# C. 盲区统计
# ======================================================================
def group_c():
    print("C. 盲区统计")
    ensure_built()
    st = store_open()
    try:
        rv = RS.Resolver(st)
        c = rv.blind_spots("dup_fn")["counts"]
        check("C1 dup_fn：3 个调用点、2 个定义（同名 static 是「消歧盲区」的规模）",
              c["call_sites"] == 3 and c["definitions"] == 2, c)

        c = rv.blind_spots("cond_use")["counts"]
        check("C2 cond_use：1 个调用点落在**条件编译分支**里（conditional_calls=1）",
              c["call_sites"] == 1 and c["conditional_calls"] == 1, c)

        bs = rv.blind_spots("cb_hook")
        check("C3 cb_hook：fptr_declarations=1 且列出声明位置（不猜指向谁）",
              bs["counts"]["fptr_declarations"] == 1
              and [d["path"] for d in bs["fptr_declarations"]] == ["cb.c"], bs)

        bs = rv.blind_spots("printf")
        check("C4 printf：no_definition=True（「没人定义」本身就是结论）",
              bs["no_definition"] is True and bs["counts"]["definitions"] == 0, bs)

        bs = rv.blind_spots("CALL_IT")
        check("C5 CALL_IT：macro_shadow 列出同名宏（提示宏展开看不见）",
              [m["kind"] for m in bs["macro_shadow"]] == ["macro_fn"], bs)
        check("C6 blind_spots 的 note 说清「只报规模和位置，不给猜出来的目标」",
              "不给一个猜出来的目标" in (bs["note"] or ""), bs["note"])

        c = rv.blind_spots("util_add")["counts"]
        check("C7 util_add：无盲区（call_sites=2、definitions=1、fptr 0、cond 0）",
              c == {"call_sites": 2, "fptr_calls": 0, "conditional_calls": 0,
                    "fptr_declarations": 0, "definitions": 1, "declarations": 1}, c)

        pb = RS.project_blind_spots(st)
        check("C8 project_blind_spots：12 调用点 / 1 条件编译 / 1 fptr 声明 / 1 查不到定义",
              pb["call_sites"] == 12 and pb["in_conditional"] == 1
              and pb["fptr_declarations"] == 1 and pb["unresolved_call_sites"] == 1
              and pb["unresolved_names"] == 1 and pb["via_pointer"] == 0, pb)
        check("C9 project_blind_spots 的 note 交代口径（是「看不全」的规模，不等于错误）",
              "不等于错误" in (pb["note"] or ""), pb["note"])

        s = RS.summarize([])
        check("C10 summarize([]) 不炸：total 0、各分桶为空",
              s["total"] == 0 and s["by_basis"] == {} and s["by_confidence"] == {},
              s)
    finally:
        st.close()

# ======================================================================
# D. relations
# ======================================================================
def group_d():
    print("D. relations（边 / summary / 下钻 / 限定 / 错误码）")
    ensure_built()

    o = callers_of("main", direction="callees")
    cl = o["callees"]
    check("D1 main 体内 4 个调用点全部列出（3 exact + 1 blind printf）",
          len(cl) == 4 and [e["callee"] for e in cl] ==
          ["util_add", "helper_local", "alt_ping", "printf"], [(e["callee"], e["basis"]) for e in cl])
    check("D2 每条 exact 边带 resolved（就是那个定义），blind 边 resolved 为空",
          all(e["resolved"] for e in cl if e["basis"] == "exact")
          and not edge_at(cl, "main.c", 13)["resolved"], cl)
    check("D3 每条边都带 caller 侧的解析级事实（path/line/from）",
          all(e.get("path") and e.get("line") and e.get("from") for e in cl), cl)

    o = callers_of("util_add", direction="callers")
    ct = o["callers"]
    check("D4 util_add 的两个调用者都 exact/high，且 caller 是调用点所在函数",
          len(ct) == 2 and all(e["basis"] == "exact" and e["confidence"] == "high"
                               for e in ct)
          and sorted((e["caller_path"], e["caller"]) for e in ct) ==
          [("alt.c", "alt_ping"), ("main.c", "main")], ct)
    check("D5 summary 结构齐（total/by_basis/by_confidence/ambiguous/in_conditional/"
          "via_pointer/by_depth）",
          o["summary"]["callers"] == {"total": 2, "by_basis": {"exact": 2},
                                      "by_confidence": {"high": 2}, "ambiguous": 0,
                                      "in_conditional": 0, "via_pointer": 0,
                                      "by_depth": {"1": 2}}, o["summary"])

    o = callers_of("dup_fn", direction="callers")
    check("D6 dup_fn：2 exact + 1 name-only(ambiguous)，summary 如实分桶",
          o["summary"]["callers"]["by_basis"] == {"exact": 2, "name-only": 1}
          and o["summary"]["callers"]["by_confidence"] == {"high": 2, "low": 1}
          and o["summary"]["callers"]["ambiguous"] == 1, o["summary"])

    o = callers_of("main", direction="callees", depth=2)
    d2 = [e for e in o["callees"] if e["depth"] == 2]
    check("D7 depth=2 **只沿 exact 已证实的边**下钻：第 2 层只有 alt.c:6 → util_add",
          len(o["callees"]) == 5 and len(d2) == 1
          and d2[0]["path"] == "alt.c" and d2[0]["callee"] == "util_add", d2)
    check("D8 下钻不会因为 printf(blind) 而中断，也不需要猜它的目标",
          all(e["basis"] != "exact" or e["depth"] == 1
              for e in o["callees"] if e["callee"] == "printf"), o["callees"])
    check("D9 depth 有下限保护（传 0 当 1 用）",
          callers_of("main", direction="callees", depth=0)["depth"] == 1, None)

    o = callers_of("util_add", direction="both")
    check("D10 direction=both 同时给 callers 与 callees（alt_ping 调用 util_add）",
          len(o["callers"]) == 2 and not o["callees"], o)

    o = callers_of("dup_fn", direction="both", path="dup_a.c")
    check("D11 path 限定后 definitions 只剩 1 个（pick 到具体那一个定义）",
          [(d["path"], d["line"]) for d in o["definitions"]] == [("dup_a.c", 1)], o)

    o = callers_of("printf")
    check("D12 无定义的符号照样 ok=True：definitions 为空 + note 明说「这本身就是盲区结论」",
          o["ok"] is True and o["definitions"] == [] and len(o["callers"]) == 1
          and o["callers"][0]["basis"] == "blind"
          and "这本身就是盲区结论" in (o["note"] or ""), o)

    r = relations(PROJ_REL, name="no_such_x_at_all")
    check("D13 既无符号也无调用点 → symbol-not-found（不空手装成功）",
          r.get("ok") is False and r.get("error_code") == "symbol-not-found", r)
    r = relations(PROJ_REL, name="")
    check("D14 空 name → invalid-argument",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)
    r = relations(PROJ_REL, name="main", direction="sideways")
    check("D15 不认识的 direction → invalid-argument + 列出可取值",
          r.get("ok") is False and r.get("error_code") == "invalid-argument"
          and "callers" in (r.get("hint") or ""), r)
    r = relations(PROJ_REL, name="dup_fn", line="abc")
    check("D16 line 不是整数 → symbol-not-found（带说明，不抛异常）",
          r.get("ok") is False and "整数" in (r.get("error") or ""), r)
    # 批次71：project 省略时**只**从已有索引里挑，且只在唯一时挑。这里把索引根换到空目录，
    # 验证「无可用索引」这条路：列候选（空表）+ 指向源码根目录，而不是猜当前目录。
    _old_root = os.environ.get(ENV_ROOT)
    os.environ[ENV_ROOT] = tempfile.mkdtemp(prefix="mdkidx69_empty_")
    try:
        r = relations("", name="main")
        check("D17 没给 project 且无可用索引 → project-required（列候选）",
              r.get("ok") is False and r.get("error_code") == "project-required"
              and r.get("candidates") == [], r)
    finally:
        os.environ[ENV_ROOT] = _old_root

    empty = mkproj("d_empty", {"x.c": "int x(void){return 0;}\n"})
    r = relations(empty, name="x")
    check("D18 没建索引 → no-index + 指向 code_index(build)",
          r.get("ok") is False and r.get("error_code") == "no-index"
          and "build" in (r.get("hint") or ""), r)

# ======================================================================
# E. impact
# ======================================================================
def group_e():
    print("E. impact（direct / possible / unresolved / indirect）")
    ensure_built()

    im = impact(PROJ_REL, name="dup_fn")
    check("E1 dup_fn：direct=2（exact）、possible=1（name-only）、unresolved=0、indirect=0",
          im["summary"]["direct"] == 2 and im["summary"]["possible"] == 1
          and im["summary"]["unresolved"] == 0 and im["summary"]["indirect"] == 0,
          im["summary"])
    check("E2 direct 段全是 confidence=high（「已证实」这一段的定义就是这个）",
          all(e["confidence"] == "high" and e["basis"] == "exact" for e in im["direct"]), im["direct"])
    check("E3 possible 段是 include-visible/medium 或 name-only/low",
          all(e["basis"] in ("include-visible", "name-only") for e in im["possible"]), im["possible"])
    check("E4 三段合起来正好等于 depth=1 的全部调用点（不丢也不重）",
          im["summary"]["direct"] + im["summary"]["possible"]
          + im["summary"]["unresolved"] == len(callers_of("dup_fn")["callers"]), None)

    im = impact(PROJ_REL, name="util_add")
    check("E5 util_add：direct=2，indirect=1（main 经 alt_ping 间接调用）",
          im["summary"]["direct"] == 2 and im["summary"]["indirect"] == 1
          and all(e["depth"] > 1 for e in im["indirect"]), im["summary"])
    check("E6 indirect 段带 depth 且 >1",
          im["indirect"][0]["depth"] == 2 and im["indirect"][0]["caller"] == "main",
          im["indirect"])

    im = impact(PROJ_REL, name="printf")
    check("E7 printf：unresolved=1（有调用点但解析不到定义），direct=0",
          im["summary"]["unresolved"] == 1 and im["summary"]["direct"] == 0
          and im["unresolved"][0]["basis"] == "blind", im["summary"])

    im = impact(PROJ_REL, name="cb_hook")
    check("E8 cb_hook：unresolved=1（函数指针调用算 blind，不算 direct）",
          im["summary"]["unresolved"] == 1 and im["summary"]["direct"] == 0, im["summary"])

    im = impact(PROJ_REL, name="cond_use")
    check("E9 cond_use：direct=1 且该边 in_conditional=True（条件编译里的影响照样列出）",
          im["summary"]["direct"] == 1 and im["direct"][0]["in_conditional"] is True,
          im["direct"])

    im = impact(PROJ_REL, name="main")
    check("E10 没人调用 main（可执行入口）→ 四段全 0，不编一个调用者",
          im["summary"]["direct"] == 0 and im["summary"]["possible"] == 0
          and im["summary"]["unresolved"] == 0, im["summary"])
    check("E11 impact 带 project_blind_spots（全量盲区规模），口径与 C8 一致",
          im["project_blind_spots"]["unresolved_call_sites"] == 1
          and im["project_blind_spots"]["call_sites"] == 12, im["project_blind_spots"])
    check("E12 impact 的 note 明说「别把 possible/unresolved 当确定影响面」",
          "别把 possible/unresolved 当确定影响面" in (im["note"] or ""), im["note"])
    check("E13 summary 里标出各段的置信度口径",
          im["summary"]["direct_confidence"] == "high"
          and im["summary"]["possible_confidence"] == "medium+low", im["summary"])

    _old_root = os.environ.get(ENV_ROOT)
    os.environ[ENV_ROOT] = tempfile.mkdtemp(prefix="mdkidx69_empty_")
    try:
        r = impact("", name="main")
        check("E14 impact 缺 project 且无可用索引 → project-required（列候选）",
              r.get("ok") is False and r.get("error_code") == "project-required"
              and r.get("candidates") == [], r)
    finally:
        os.environ[ENV_ROOT] = _old_root
    empty = mkproj("e_empty", {"x.c": "int x(void){return 0;}\n"})
    r = impact(empty, name="x")
    check("E15 impact 没建索引 → no-index",
          r.get("ok") is False and r.get("error_code") == "no-index", r)

# ======================================================================
# F. 工具层
# ======================================================================
def group_f():
    print("F. 工具层（2 个工具 + 错误码 + 注解 + 描述边界）")
    proj = copy_proj(PROJ_REL, "f_tools")
    srv = SV.create_server(port=PORT_TOOL, toolsets="all")
    ns = tool_names(srv)
    b = call_sync(srv, "code_index", {"action": "build", "project": proj})
    check("F0 code_index(build) 先把索引建起来（工具层走真实入口）",
          b.get("ok") is True and b["counts"]["calls"] == 12, b)

    r = call_sync(srv, "code_relations", {"project": proj, "name": "main",
                                          "direction": "callees"})
    check("F1 code_relations 端到端可用（4 条边，含 basis/confidence）",
          r.get("ok") is True and len(r["callees"]) == 4
          and all("basis" in e and "confidence" in e for e in r["callees"]), r)

    r = call_sync(srv, "code_impact", {"project": proj, "name": "dup_fn"})
    check("F2 code_impact 端到端可用（direct/possible 分段 + blind_spots）",
          r.get("ok") is True and r["summary"]["direct"] == 2
          and r["summary"]["possible"] == 1 and "blind_spots" in r, r)

    r = call_sync(srv, "code_relations", {"project": proj, "name": "main",
                                          "direction": "callees"})
    check("F3 工具结果与门面一致（同一份事实，不另起炉灶）",
          r["summary"]["callees"]["total"] == 4, r["summary"])

    r = call_sync(srv, "code_relations", {"project": proj, "name": "no_such"})
    check("F4 symbol-not-found 走统一信封",
          r.get("ok") is False and r.get("error_code") == "symbol-not-found", r)
    r = call_sync(srv, "code_impact", {"project": proj, "name": ""})
    check("F5 code_impact 空 name → invalid-argument",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)
    empty = mkproj("f_empty", {"x.c": "int x(void){return 0;}\n"})
    check("F6 两个工具在没索引的项目上一致地报 no-index",
          call_sync(srv, "code_relations", {"project": empty, "name": "x"})
          .get("error_code") == "no-index"
          and call_sync(srv, "code_impact", {"project": empty, "name": "x"})
          .get("error_code") == "no-index", None)

    check("F7 annotate：两个工具都是只读",
          all(t in AN.READONLY for t in REL_TOOLS)
          and not any(t in AN.MUTATING for t in REL_TOOLS), None)
    check("F8 annotate.check_surface 在全部工具上无问题",
          not AN.check_surface(ns), AN.check_surface(ns))
    check("F9 outctl：两个工具都进了高输出名单（compact/max_lines 就位）",
          all(t in OC.HIGH_OUTPUT for t in REL_TOOLS), None)
    e = ER.ERROR_CODES.get("symbol-not-found") or {}
    check("F10 symbol-not-found 在错误码册里且带 next_actions",
          bool(e.get("next_actions")), e)

    ds = tool_descs(srv)
    check("F11 两个工具都已注册且有描述",
          all(t in ds and len(ds[t]) > 200 for t in REL_TOOLS),
          [t for t in REL_TOOLS if t not in ds])
    mentioned = set()
    for t in REL_TOOLS:
        mentioned |= set(re.findall(r"code_[a-z_]+", ds[t]))
    ghost = sorted(m for m in mentioned if m not in ns)
    check("F12 描述里提到的 code_* 工具**全都真实注册**（不指向不存在的工具）",
          not ghost, ghost)
    check("F13 code_relations 描述钉死红线「resolved 只在 exact 时非空」",
          "resolved" in ds["code_relations"] and "只在 exact" in ds["code_relations"], None)
    check("F14 code_relations 描述列出四档 basis 的含义",
          all(k in ds["code_relations"] for k in ("exact", "include-visible",
                                                 "name-only", "blind")), None)
    check("F15 code_impact 描述交代「别把 possible/unresolved 当确定影响面」与下钻规则",
          "别把 possible/unresolved 当确定影响面" in ds["code_impact"]
          and "只沿" in ds["code_impact"], None)
    check("F16 索引根目录确实被环境变量改道（测试不碰 ~/.mdkdebug）",
          index_root() == os.path.abspath(IDX_ROOT)
          and os.environ.get(ENV_ROOT) == IDX_ROOT, index_root())

# ======================================================================
# G. 工具面
# ======================================================================
def group_g():
    print("G. 工具面")
    os.environ.pop("MDKDEBUG_TOOLSETS", None)
    srv_def = SV.create_server(port=PORT_DEF, toolsets=None)
    nd = tool_names(srv_def)
    srv_all = SV.create_server(port=PORT_TOOL, toolsets="all")
    na = tool_names(srv_all)

    check("G1 注册总数 199", len(na) == 199, len(na))
    check("G2 默认只暴露 44 个", len(nd) == 44, len(nd))
    check("G3 code 组默认收起（7 个 code_* 都不在默认面）",
          not any(t.startswith("code_") for t in nd),
          [t for t in nd if t.startswith("code_")])
    check("G4 code 组正好是那 7 个工具",
          TB.TOOLSETS.get("code") == set(CODE_TOOLS), TB.TOOLSETS.get("code"))
    check("G5 组数 12，且每组都有用途说明",
          len(TB.TOOLSETS) == 12 and len(TB.GROUP_NOTES) == 12
          and "code" in TB.GROUP_NOTES, (len(TB.TOOLSETS), len(TB.GROUP_NOTES)))
    check("G6 高输出工具 48 个（批次68 +4、批次69 +2）",
          len(OC.HIGH_OUTPUT) == 48, len(OC.HIGH_OUTPUT))
    st = call_sync(srv_def, "toolset", {"action": "status"})
    grp = (st.get("groups") or {}).get("code") or {}
    check("G7 toolset(status) 列得出 code 组与规模 7", grp.get("size") == 7,
          (st.get("groups") or {}).get("code"))
    r = call_sync(srv_def, "toolset", {"action": "load", "toolsets": "code"})
    check("G8 toolset(load, code) 装回 7 个，暴露数 44→51",
          r.get("ok") is True and len(r.get("loaded") or []) == 7
          and r.get("exposed") == 51, r)
    srv_fresh = SV.create_server(port=PORT_DEF + 2, toolsets=None)
    cap = call_sync(srv_fresh, "capabilities", {})
    surf = cap.get("tool_surface") or {}
    check("G9 capabilities 的 tool_surface 里 code=7 且列为「未装载」、总数 199",
          (surf.get("groups") or {}).get("code") == 7
          and "code" in (surf.get("not_loaded_groups") or [])
          and surf.get("registered_total") == 199, surf)

def main():
    print("批次69：关系与置信度（basis 三档 + 盲区统计 + code_relations / code_impact）")
    print("索引根：%s" % IDX_ROOT)
    group_a()
    group_b()
    group_c()
    group_d()
    group_e()
    group_f()
    group_g()
    print("\n==== 批次69 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
