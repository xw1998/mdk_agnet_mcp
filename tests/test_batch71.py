# -*- coding: utf-8 -*-
"""批次71 mock 测试：代码索引层的可用性打磨（project 可省 / rebuild / 描述与下一步）。

本批**不加工具、不加解析能力**，只修批次68–70 自用下来暴露的三处「不人性化」：

1. **`project` 每次都得填**——同一个工程要反复贴同一个长路径。现在可省，但只省到
   「本机已经建过索引的工程」为止：只从已有索引里挑、只在**唯一**时挑，并在返回体里
   写 `project_source` / `project_inferred` / `project_hint`。多候选/零候选一律报错并把
   候选摊开——**不凭空挑一个目录去索引，也不替调用方在多个工程之间决定**。
   首次 `build` 不给源码根时，报错里附 Keil 工程线索（标 `verified=False`，只供确认）。

2. **重建索引要拼两步**（`drop` → `build`）——中间那个「库已经没了」的状态会把人绕进
   `no-index` 的循环。新增 `action="rebuild"` 把它收成一个动作，且**删不掉就不建**。

3. **错误码的下一步指错了方向**——通用 `project-required` 说的是「传 .uvprojx」，而代码
   索引要的是「源码根目录」。`code_*` 族改用 `_CODE_ACTIONS` 覆盖。

分组：
  A project 可省 / known_projects / resolve_project 语义（含老库、目录消失、in_project）
  B rebuild 三态（正常 / 无库 / 删不掉不建）与 schema 恢复
  C 工具描述与错误码动作（描述诚实、invalid-action、code_ 族下一步）
  D README 致谢与依赖表同步（参考过的开源项目一个不落）

运行：python -m tests.test_batch71
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# 索引一律写临时目录（不碰 ~/.mdkdebug，也不往 fixture 工程里写）
IDX_ROOT = tempfile.mkdtemp(prefix="mdkidx71_root_")
os.environ["MDKDEBUG_CODEINDEX_DIR"] = IDX_ROOT
TMP_ROOT = tempfile.mkdtemp(prefix="mdkidx71_proj_")

from mdkdebug import errors as ER                            # noqa: E402
from mdkdebug import server as SV                            # noqa: E402
from mdkdebug import toolbox as TB                           # noqa: E402
from mdkdebug.codeindex import ENV_ROOT                      # noqa: E402
from mdkdebug.codeindex import SOURCE_EXPLICIT               # noqa: E402
from mdkdebug.codeindex import SOURCE_UNIQUE_INDEX           # noqa: E402
from mdkdebug.codeindex import _apply_source                 # noqa: E402
from mdkdebug.codeindex import build as ci_build             # noqa: E402
from mdkdebug.codeindex import db_path                       # noqa: E402
from mdkdebug.codeindex import drop as ci_drop               # noqa: E402
from mdkdebug.codeindex import host_project_hints            # noqa: E402
from mdkdebug.codeindex import index_root                    # noqa: E402
from mdkdebug.codeindex import known_projects                # noqa: E402
from mdkdebug.codeindex import rebuild as ci_rebuild         # noqa: E402
from mdkdebug.codeindex import resolve_project               # noqa: E402
from mdkdebug.codeindex import status as ci_status           # noqa: E402
from mdkdebug.codeindex.store import SCHEMA_VERSION          # noqa: E402
from mdkdebug.codeindex.store import Store as _Store         # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "codeindex")
PROJ_C = os.path.join(FIX, "proj_c")

PORT_TOOL, PORT_DEF = 14990, 14991

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:600]), flush=True)

def jd(o):
    return json.dumps(o, ensure_ascii=False, default=str)

# ------------------------------------------------------------ 索引根切换

_ROOTS = []

def fresh_root(tag):
    """换到一个干净的索引根（本机「已建索引的工程」这件事必须可控）。"""
    d = os.path.join(TMP_ROOT, "idx_" + tag)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    _ROOTS.append(os.environ.get(ENV_ROOT))
    os.environ[ENV_ROOT] = d
    return d

def restore_root():
    prev = _ROOTS.pop()
    if prev is None:
        os.environ.pop(ENV_ROOT, None)
    else:
        os.environ[ENV_ROOT] = prev

def copy_proj(src, name):
    d = os.path.join(TMP_ROOT, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    shutil.copytree(src, d)
    return d

def mk_old_index(project, schema="2", with_project=True, built_at=None):
    """手工造一个「老库」：直接写 meta，不经 build（模拟历史遗留/手工放进去的库）。"""
    key_dir = os.path.dirname(db_path(project))
    os.makedirs(key_dir, exist_ok=True)
    st = _Store(os.path.join(key_dir, "index.db")).open()
    st.ensure_schema()
    try:
        if with_project:
            st.meta_set("project", project)
        st.meta_set("schema_version", schema)
        st.meta_set("built_at", built_at or time.time())
        st.meta_set("build_kind", "build")
        st.commit()
    finally:
        st.close()
    return os.path.join(key_dir, "index.db")

# ------------------------------------------------------------ 服务器调用

async def _call(srv, n, a):
    res = await srv.call_tool(n, a)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    return json.loads(txt)

def call_sync(srv, n, a):
    return asyncio.run(_call(srv, n, a))

def tool_descs(srv):
    return {t.name: (t.description or "") for t in asyncio.run(srv.list_tools())}

# ======================================================================
# A. project 可省 / known_projects / resolve_project
# ======================================================================
def group_a():
    print("A. project 可省与 known_projects")

    # --- 唯一索引：known_projects 认得出来，resolve 能省 ---
    root = fresh_root("a1")
    p1 = copy_proj(PROJ_C, "a1_proj")
    b = ci_build(p1)
    check("A1 建索引成功（前置）", b.get("ok") is True, b)

    k = known_projects()
    check("A2 known_projects 结构齐（root/projects/count/truncated/errors）",
          all(x in k for x in ("root", "projects", "count", "truncated", "errors"))
          and k["count"] == 1, {kk: k.get(kk) for kk in ("count", "truncated", "errors")})
    e = (k["projects"] or [{}])[0]
    check("A3 条目字段齐且都认得出来（project_known/exists/schema_ok/files）",
          e.get("project_known") is True and e.get("exists") is True
          and e.get("schema_ok") is True and (e.get("files") or 0) > 0,
          {kk: e.get(kk) for kk in ("project", "project_known", "exists",
                                    "schema_ok", "files")})
    check("A4 条目 project 就是那个工程目录（大小写归一后一致）",
          os.path.normcase(e.get("project") or "") == os.path.normcase(p1), e.get("project"))
    check("A5 索引根就是刚换的那个", os.path.normcase(k["root"]) == os.path.normcase(root),
          (k["root"], root))

    path, src, err = resolve_project("")
    check("A6 唯一可用索引时 project 可省，来源标注 unique-index",
          err is None and os.path.normcase(path) == os.path.normcase(p1)
          and src == SOURCE_UNIQUE_INDEX, (path, src, err))

    path, src, err = resolve_project(p1)
    check("A7 显式给 project 时来源标注 explicit",
          err is None and src == SOURCE_EXPLICIT, (path, src, err))

    # --- _apply_source：只在 ok 时写，且推断时透出 ---
    check("A8 _apply_source 对失败结果不加字段",
          "project_source" not in _apply_source({"ok": False}, SOURCE_UNIQUE_INDEX), None)
    o = _apply_source({"ok": True, "project": p1}, SOURCE_UNIQUE_INDEX)
    check("A9 推断出来的 project 透出 project_inferred + project_hint（不静悄悄）",
          o.get("project_inferred") is True and isinstance(o.get("project_hint"), str)
          and "唯一" in o["project_hint"], o)
    o2 = _apply_source({"ok": True, "project": p1}, SOURCE_EXPLICIT)
    check("A10 显式给的 project 不写 project_inferred",
          o2.get("project_source") == SOURCE_EXPLICIT and "project_inferred" not in o2, o2)
    restore_root()

    # --- 空索引根：报 project-required，且候选是**空表**而不是缺字段 ---
    fresh_root("a2")
    path, src, err = resolve_project("")
    check("A11 零索引时省 project 报 project-required（不猜当前目录）",
          path is None and err and err.get("error_code") == "project-required", err)
    check("A12 候选为空时也发 candidates 字段（可区分「候选为空」与「字段不支持」）",
          err is not None and "candidates" in err and err["candidates"] == [], err)
    check("A13 报错里带索引根，指得出「我扫的是哪儿」",
          err is not None and os.path.normcase(err.get("index_root") or "") ==
          os.path.normcase(index_root()), err)
    check("A14 报错带 keil_project_hints 字段（本机没有 Keil 工程时为空表）",
          err is not None and isinstance(err.get("keil_project_hints"), list), err)
    check("A15 零索引时 hint 指向「源码根目录」，且强调不是 .uvprojx",
          err is not None and "源码根目录" in (err.get("hint") or ""), err)
    restore_root()

    # --- 多个可用索引：列候选报错，不替人挑 ---
    fresh_root("a3")
    q1 = copy_proj(PROJ_C, "a3_proj1")
    q2 = copy_proj(PROJ_C, "a3_proj2")
    ci_build(q1)
    ci_build(q2)
    path, src, err = resolve_project("")
    check("A16 多候选时不替调用方挑，报错并摊开 2 条候选",
          path is None and err and err.get("error_code") == "project-required"
          and len(err.get("candidates") or []) == 2, err)
    check("A17 多候选 reason 里写明「有 N 个」",
          err is not None and "2 个" in (err.get("error") or ""), err.get("error"))
    kb = ci_status("")
    check("A18 status 省 project + 多索引 = 列清单（ok=true, mode=all-projects）",
          kb.get("ok") is True and kb.get("mode") == "all-projects"
          and kb.get("count") == 2 and len(kb.get("known_projects") or []) == 2, kb)
    check("A19 清单里的条目是精简版（不塞 index 路径，省 token）",
          all("index" not in x for x in (kb.get("known_projects") or []))
          and all("built_at" in x for x in (kb.get("known_projects") or [])), kb)
    # status 唯一索引时自动认出来
    restore_root()
    fresh_root("a3b")
    q3 = copy_proj(PROJ_C, "a3b_proj")
    ci_build(q3)
    su = ci_status("")
    check("A20 status 省 project + 唯一索引 = 直接用它的状态并标注来源",
          su.get("ok") is True and su.get("project_source") == SOURCE_UNIQUE_INDEX
          and su.get("project_inferred") is True
          and os.path.normcase(su.get("project") or "") == os.path.normcase(q3), su)
    restore_root()

    # --- 零索引时 status 报 no-index ---
    fresh_root("a4")
    s0 = ci_status("")
    check("A21 status 省 project + 零索引 = ok=false / no-index（如实报失败）",
          s0.get("ok") is False and s0.get("error_code") == "no-index"
          and s0.get("known_projects") == [], s0)
    check("A22 零索引的 status 也带 known_projects_count=0 与 index_root",
          s0.get("known_projects_count") == 0 and bool(s0.get("index_root")), s0)
    restore_root()

    # --- 索引在、但工程目录已被移走：不算可用（不拿一个不存在的目录去索引） ---
    fresh_root("a5")
    g1 = copy_proj(PROJ_C, "a5_proj")
    ci_build(g1)
    gone = g1 + "_moved"
    if os.path.isdir(gone):
        shutil.rmtree(gone)
    os.rename(g1, gone)
    kg = known_projects()
    eg = (kg["projects"] or [{}])[0]
    check("A23 工程目录消失后 exists=False（条目还在，但不谎报可用）",
          eg.get("project_known") is True and eg.get("exists") is False, eg)
    path, src, err = resolve_project("")
    check("A24 「索引在但目录没了」不算可用，仍报 project-required",
          path is None and err and err.get("error_code") == "project-required"
          and len(err.get("candidates") or []) == 1, err)
    os.rename(gone, g1)
    restore_root()

    # --- 老库/手工库：库里没记 project，不反推目录名 ---
    fresh_root("a6")
    h1 = copy_proj(PROJ_C, "a6_proj")
    mk_old_index(h1, schema=str(SCHEMA_VERSION), with_project=False)
    kh = known_projects()
    eh = (kh["projects"] or [{}])[0]
    check("A25 库里没记 project 时 project_known=False、project=None（不反推目录名）",
          eh.get("project_known") is False and eh.get("project") is None, eh)
    check("A26 老库 schema_ok=true（结构对得上就不误报）",
          eh.get("schema_ok") is True, eh)
    path, src, err = resolve_project("")
    check("A27 project_known=False 的库不进「可自动选」的集合",
          path is None and err and err.get("error_code") == "project-required", err)
    restore_root()

    # --- schema 不匹配的库：认得出来，但标 schema_ok=False ---
    fresh_root("a7")
    i1 = copy_proj(PROJ_C, "a7_proj")
    mk_old_index(i1, schema="2")
    ki = known_projects()
    ei = (ki["projects"] or [{}])[0]
    check("A28 旧 schema（2）的库 schema_ok=False（用之前得 rebuild）",
          ei.get("schema_ok") is False and ei.get("schema_version") == "2", ei)
    b7 = ci_build(i1)
    check("A29 旧 schema 上直接 build 报 index-schema-mismatch（不原地改结构）",
          b7.get("ok") is False and b7.get("error_code") == "index-schema-mismatch", b7)
    restore_root()

    # --- in_project=true 时省不了（索引分散在各工程里，无法枚举） ---
    fresh_root("a8")
    j1 = copy_proj(PROJ_C, "a8_proj")
    path, src, err = resolve_project("", in_project=True)
    check("A30 in_project=true 时省 project 直接报错（枚举不了就该说出来）",
          path is None and err and err.get("error_code") == "project-required"
          and "in_project" in (err.get("hint") or ""), err)
    path, src, err = resolve_project(j1, in_project=True)
    check("A31 in_project=true 时显式 project 照旧可用",
          err is None and src == SOURCE_EXPLICIT, (path, src, err))
    restore_root()

    # --- host_project_hints：只当线索，一律 verified=False ---
    hints = host_project_hints()
    check("A32 host_project_hints 返回列表（惰性 import，拿不到就空表不报错）",
          isinstance(hints, list), type(hints).__name__)
    check("A33 线索一律 verified=False（绝不自动采用）",
          all(h.get("verified") is False for h in hints), hints)
    check("A34 每条线索自带 candidate/what/exists 三件套（人才能判断）",
          all(all(x in h for x in ("candidate", "what", "exists", "source"))
              for h in hints), hints)


# ======================================================================
# B. rebuild 三态
# ======================================================================
def group_b():
    print("B. rebuild：删旧索引 + 重建（一步）")

    fresh_root("b1")
    p1 = copy_proj(PROJ_C, "b1_proj")
    b = ci_build(p1)
    check("B1 前置：建索引成功", b.get("ok") is True, b)
    idx = db_path(p1)
    r = ci_rebuild(p1)
    check("B2 rebuild 成功：action=rebuild、ok=true",
          r.get("ok") is True and r.get("action") == "rebuild", r)
    check("B3 rebuild 如实分两段报（stages.drop / stages.build）",
          (r.get("stages") or {}).get("drop", {}).get("ok") is True
          and (r.get("stages") or {}).get("build", {}).get("ok") is True, r.get("stages"))
    check("B4 rebuild 列出真删掉的文件（dropped）",
          len(r.get("dropped") or []) >= 1, r.get("dropped"))
    check("B5 rebuild 的 note 说明「不是增量」（免得被当成 sync）",
          "不是增量" in (r.get("note") or ""), r.get("note"))
    check("B6 rebuild 后索引仍在（重建不是只删）", os.path.isfile(idx), idx)
    st = ci_status(p1)
    check("B7 rebuild 后 status 认得出索引（index_exists=true）",
          st.get("index_exists") is True, st.get("index"))

    # 无库时 rebuild = 直接建
    p2 = copy_proj(PROJ_C, "b1_proj2")
    r2 = ci_rebuild(p2)
    check("B8 没有旧索引时 rebuild 也成功（dropped 为空）",
          r2.get("ok") is True and (r2.get("dropped") or []) == []
          and (r2.get("stages") or {}).get("drop", {}).get("removed") == 0, r2)
    check("B9 无库 rebuild 后索引真的建出来了", os.path.isfile(db_path(p2)), None)

    # 删不掉就不建
    p3 = copy_proj(PROJ_C, "b1_proj3")
    ci_build(p3)
    idx3 = db_path(p3)
    old_size = os.path.getsize(idx3)
    os.chmod(idx3, 0o444)          # Windows 上只读文件 os.remove 会 PermissionError
    try:
        r3 = ci_rebuild(p3)
    finally:
        os.chmod(idx3, 0o666)
    check("B10 索引删不掉时 rebuild 失败，并标明卡在 drop 段",
          r3.get("ok") is False and r3.get("action") == "rebuild"
          and r3.get("stage") == "drop", r3)
    check("B11 删不掉就不建：旧索引原样还在（没被新库覆盖，也没被悄悄留下半成品）",
          os.path.isfile(idx3) and os.path.getsize(idx3) == old_size, None)

    # schema 恢复
    p4 = copy_proj(PROJ_C, "b1_proj4")
    mk_old_index(p4, schema="2")
    kb = [e for e in known_projects()["projects"]
          if os.path.normcase(e.get("project") or "") == os.path.normcase(p4)]
    check("B12 前置：手工老库被认出来且 schema_ok=False",
          kb and kb[0].get("schema_ok") is False, kb)
    r4 = ci_rebuild(p4)
    check("B13 rebuild 把旧 schema 库恢复成当前 schema（一步，不必手拼 drop→build）",
          r4.get("ok") is True and r4.get("action") == "rebuild", r4)
    ka = [e for e in known_projects()["projects"]
          if os.path.normcase(e.get("project") or "") == os.path.normcase(p4)]
    check("B14 rebuild 后 schema_ok=True（真恢复了，不是嘴上说恢复）",
          ka and ka[0].get("schema_ok") is True, ka)

    # in_project 传递
    p5 = copy_proj(PROJ_C, "b1_proj5")
    r5 = ci_rebuild(p5, in_project=True)
    check("B15 rebuild 的 in_project 透传到 drop 与 build（写进工程内 .mdkdebug）",
          r5.get("ok") is True and r5.get("in_project") is True
          and os.path.normcase(r5.get("index") or "").startswith(
              os.path.normcase(os.path.join(p5, ".mdkdebug"))), r5.get("index"))

    # 省 project + 多索引时 rebuild 不猜
    fresh_root("b2")
    m1 = copy_proj(PROJ_C, "b2_proj1")
    m2 = copy_proj(PROJ_C, "b2_proj2")
    ci_build(m1)
    ci_build(m2)
    r6 = ci_rebuild("")
    check("B16 rebuild 省 project + 多索引时报 project-required（不挑一个重建）",
          r6.get("ok") is False and r6.get("error_code") == "project-required"
          and len(r6.get("candidates") or []) == 2, r6)
    restore_root()

    # drop 的 note 指向 rebuild
    fresh_root("b3")
    n1 = copy_proj(PROJ_C, "b3_proj")
    ci_build(n1)
    d = ci_drop(n1)
    check("B17 drop 的 note 指得出 rebuild（重建不必自己拼两步）",
          d.get("ok") is True and "rebuild" in (d.get("note") or ""), d.get("note"))
    check("B18 drop 后索引真的没了", not os.path.isfile(db_path(n1)), None)
    restore_root()


# ======================================================================
# C. 描述与错误码动作
# ======================================================================
def group_c():
    print("C. 工具描述与错误码下一步")
    os.environ.pop("MDKDEBUG_TOOLSETS", None)
    srv = SV.create_server(port=PORT_TOOL, toolsets="all")
    ds = tool_descs(srv)

    check("C1 code_index 描述里有 rebuild 这个动作",
          "rebuild" in ds.get("code_index", ""), None)
    check("C2 code_index 描述说清 rebuild = 删旧索引 + 重建（且删不掉不建）",
          "删掉旧索引" in ds.get("code_index", "")
          and "删不掉就不建" in ds.get("code_index", ""), None)
    check("C3 code_index 描述里 project 标为「可省」",
          "可省" in ds.get("code_index", ""), None)
    check("C4 schema 段指向 rebuild 而不是让人自己拼 drop→build",
          "rebuild" in ds.get("code_index", "")
          and "不必自己拼 drop" in ds.get("code_index", ""), None)

    _OPT = [(n, d) for n, d in ds.items() if n.startswith("code_") and n != "code_index"]
    check("C5 除 code_index 外的 6 个 code_* 工具都说明了 project 可省",
          len(_OPT) == 6 and all("可省" in d and "unique-index" in d for _n, d in _OPT),
          [n for n, d in _OPT if "可省" not in d])
    check("C6 描述里点的工具名都真的注册了（不指路到不存在的东西）",
          all(n in ds for n in ("code_index", "code_status", "code_files", "code_query",
                                "code_node", "code_relations", "code_impact")),
          [n for n in ds if n.startswith("code_")])
    check("C7 code_node 描述不再声称「反向调用关系本批不给」（批次68 口径已过时）",
          "本批**不给**" not in ds.get("code_node", ""), None)
    check("C8 code_node 描述把调用链/影响面指给 code_relations / code_impact",
          "code_relations" in ds.get("code_node", "")
          and "code_impact" in ds.get("code_node", ""), None)

    # invalid-action
    iv = call_sync(srv, "code_index", {"action": "nonsense"})
    check("C9 不认识的 action 报 invalid-argument 并列出可选值（含 rebuild）",
          iv.get("ok") is False and iv.get("error_code") == "invalid-argument"
          and "rebuild" in (iv.get("hint") or ""), iv)

    # 错误码动作：code_* 族要覆盖通用 project-required 的方向
    generic = ER.ERROR_CODES["project-required"]["next_actions"]
    ca = ER.code_actions("code_index", "project-required")
    check("C10 code_index 的 project-required 下一步不是通用的「传 .uvprojx」那套",
          ca and ca != list(generic)
          and any(".uvprojx" in a for a in generic), ca)
    check("C11 code_* 的 project-required 明确指向「源码根目录」",
          any("源码根目录" in a for a in ca)
          and any("不是 .uvprojx" in a for a in ca), ca)
    ni = ER.code_actions("code_status", "no-index")
    check("C12 code_* 的 no-index 下一步给出 build 与先看清单两条",
          any("build" in a for a in ni) and any("code_status" in a for a in ni), ni)
    sm = ER.code_actions("code_index", "index-schema-mismatch")
    check("C13 code_* 的 index-schema-mismatch 第一条就是 rebuild",
          sm and "rebuild" in sm[0], sm)
    check("C14 非 code 工具不套用 code 族动作（各链路互不串味）",
          list(ER.code_actions("get_status", "project-required")) == list(generic),
          ER.code_actions("get_status", "project-required"))
    check("C15 code_ 前缀派发只认 code_（codeindex 这种名字不算）",
          list(ER.code_actions("codeindex_thing", "project-required")) == list(generic),
          ER.code_actions("codeindex_thing", "project-required"))

    # 端到端：零索引 + 省 project 的错误里，next_actions 来自 code 族
    fresh_root("c1")
    e0 = call_sync(srv, "code_status", {})
    check("C16 端到端：零索引省 project → status=error / no-index",
          e0.get("status") == "error" and e0.get("error_code") == "no-index", e0)
    check("C17 端到端：下一步动作是 code 族的（指向源码根目录，不是 .uvprojx）",
          any("源码根目录" in a for a in (e0.get("next_actions") or []))
          and not any(".uvprojx" in a for a in (e0.get("next_actions") or [])),
          e0.get("next_actions"))
    check("C18 端到端：keil_project_hints 从返回体透出（空表也算透出）",
          isinstance(e0.get("keil_project_hints"), list), e0.get("keil_project_hints"))
    restore_root()

    # 端到端：唯一索引 + 省 project → project_hint 被信封收成 next_actions
    fresh_root("c2")
    p1 = copy_proj(PROJ_C, "c2_proj")
    ci_build(p1)
    e1 = call_sync(srv, "code_status", {})
    check("C19 端到端：唯一索引省 project → 结果里标了 unique-index",
          e1.get("project_source") == "unique-index" and e1.get("project_inferred") is True,
          {k: e1.get(k) for k in ("project_source", "project_inferred", "project")})
    check("C20 端到端：project 是推断的这件事被收成 next_actions（不静悄悄）",
          any("唯一一个已建索引" in a for a in (e1.get("next_actions") or [])),
          e1.get("next_actions"))
    restore_root()

    # 端到端：rebuild 可经 MCP 调到
    fresh_root("c3")
    p2 = copy_proj(PROJ_C, "c3_proj")
    ci_build(p2)
    e2 = call_sync(srv, "code_index", {"action": "rebuild", "project": p2})
    check("C21 端到端：code_index(action=rebuild) 走通 MCP 且 status=ok",
          e2.get("status") == "ok" and e2.get("action") == "rebuild", e2)
    restore_root()

    # 工具面没被本批改坏
    check("C22 注册总数 199、code 组仍是 7（批次72 只在 trace 组加分析层）",
          len(ds) == 199 and TB.TOOLSETS.get("code") == {
              "code_index", "code_status", "code_files", "code_query", "code_node",
              "code_relations", "code_impact"}, (len(ds), TB.TOOLSETS.get("code")))


# ======================================================================
# D. README 致谢与依赖表
# ======================================================================
README = os.path.join(ROOT, "README.md")

#: 真的读过、并用上了的参考项目（一一对应 docs/oss-absorption.md 的清单）。
#: 漏一个 → 致谢不诚实；多一个 → 谎报功劳。两个方向都查。
REFERENCED = [
    "KeilAssistant", "debug-keil-uvsc",
    "embeddedskills", "keil-project-tools", "Serial-Agent", "Keil_mcp",
    "dsh-keil-mcp", "McuBuddy", "keil-uvsc-mcp", "Keil-Tool",
    "embedded-debugger-mcp", "jlink-mcp",
    "royforlinux/openocd-mcu-mcp", "luiox/openocd-mcp", "microhenrio/openocd-mcp",
    "agentic-hil",
    "colbymchenry/codegraph",
    "tree-sitter", "tree-sitter-c", "tree-sitter-cpp",
    "pyelftools", "capstone",
]

def group_d():
    print("D. README：致谢与依赖表")
    with open(README, "r", encoding="utf-8") as fh:
        txt = fh.read()

    check("D1 README 有「参考与致谢」一节", "## 参考与致谢" in txt, None)
    check("D2 致谢按「参考了什么」分组（不是一坨清单）",
          all(("### " + h) in txt for h in ("协议与实现参考", "同类开源项目",
                                            "代码索引层", "底层库")), None)
    missing = [r for r in REFERENCED if r not in txt]
    check("D3 参考过的开源项目一个不落（%d 个）" % len(REFERENCED), not missing, missing)
    check("D4 致谢里的引用都给了可点的链接（不是光写名字）",
          "https://github.com/" in txt or "https://gitee.com/" in txt, None)
    check("D5 没参考的也注明「没有参考」（免得后来者重复调查）",
          "没有参考" in txt and "SAP/mdk-mcp-server" in txt, None)
    check("D6 codegraph 这条写清「最终没内嵌、改全 Python 自研」并补了汇编",
          "codegraph" in txt and "没有内嵌" in txt and "汇编" in txt, None)
    check("D7 依赖表补了 tree-sitter 三行（缺依赖时工具才有得说）",
          "| `tree-sitter` " in txt and "| `tree-sitter-c` " in txt
          and "| `tree-sitter-cpp` " in txt, None)
    check("D8 依赖表里的 tree-sitter 标注了「缺失时如实报 parser-missing，不降级 grep」",
          "parser-missing" in txt and "不降级" in txt, None)


def main():
    print("批次71：代码索引层的可用性打磨（project 可省 / rebuild / 描述与下一步）")
    print("索引根：%s" % IDX_ROOT)
    group_a()
    group_b()
    group_c()
    group_d()
    print("\n==== 批次71 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
