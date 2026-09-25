# -*- coding: utf-8 -*-
"""批次70 mock 测试：汇编（`.s` / `.S` / `.asm`）进代码索引。

批次68/69 的索引层只认 C/C++。但 MCU 工程里最容易变成「读不到的黑洞」的恰恰是汇编：
启动文件、向量表、上下文切换、SVC/PendSV 入口全在这里。本批把汇编接进同一套
「解析级事实 → 带置信度的关系」流水线，且**不牺牲诚实性**：

1. **零依赖行式解析**（`lang_asm.py`）：汇编没有可用的 tree-sitter 轮子，所以只挑
   词法上就能证实的东西；看不懂的行不记，但要记数并给样本。
2. **`parse_error` 对汇编恒为 0**，且**不代表**这份汇编被理解了——这条必须写在
   返回体、docstring、工具描述三处（本批专门测它，防止有人拿它当质量背书）。
3. **凑不出的名字不编**：无名间接调用（`BLX Rn`）**不产生调用点**（不造 `R2` 这种假名字）；
   宏体内的 `bl` 不记（展开点不在宏定义处）；本文件内 `B label`（循环/分支）不记成调用。
4. **`LDR Rn,=sym` + `BLX Rn`** 记 `via_pointer=1`，但名字只是线索 → 一律压到 `blind`。
5. **`IMPORT`/`EXTERN` 是一条真实声明**（`asm_import`），所以「汇编调 C 函数」能拿到
   比 name-only 更硬的 `exact`；没有它就只有 name-only。

fixture `proj_asm/`（5 文件）专门为这些边界造：armasm 的 `ctx.S`（PROC/ENDP、GET、
IMPORT、条件汇编、宏、`LDR =sym`+`BLX Rn`、无名 `BLX R3`、`B <imported>` 尾调用）、
被 GET 进来的 `asm_defs.s`、GNU 写法的 `gnu.s`（`.type %function`、`.macro`、`.word`）、
以及 C 侧的 `main.c` + `inc/api.h`。

分组：
  A 解析器接线与方言（available / LINE_LANGS / EXT_LANG / schema / 续行 / GBK）
  B 标签与函数（asm_func / asm_label / asm_import / 被 bl 指向升格 / 宏）
  C 调用与尾调用（BL·BLX·via_pointer·无名间接不记·宏内不记·B 尾调用规则）
  D 跨语言可见性（C 调汇编 exact vs name-only、汇编 IMPORT 调 C exact、GET 传递）
  E 诚实口径（parse_error 恒 0、unparsed 计数与样本、无名间接计数、盲区拆分）
  F 工具层（code_* 端到端 + 描述边界）
  G 工具面：注册 199 / 默认面 44 / code 组 7 / 组数 12 / 高输出 48

运行：python -m tests.test_batch70
"""
import asyncio
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

# 索引一律写临时目录（不碰 ~/.mdkdebug，也不往 fixture 工程里写）
IDX_ROOT = tempfile.mkdtemp(prefix="mdkidx70_root_")
os.environ["MDKDEBUG_CODEINDEX_DIR"] = IDX_ROOT

from mdkdebug import annotate as AN                      # noqa: E402
from mdkdebug import errors as ER                        # noqa: E402
from mdkdebug import outctl as OC                        # noqa: E402
from mdkdebug import server as SV                        # noqa: E402
from mdkdebug import toolbox as TB                       # noqa: E402
from mdkdebug.codeindex import ENV_ROOT                  # noqa: E402
from mdkdebug.codeindex import build as ci_build         # noqa: E402
from mdkdebug.codeindex import db_path, impact           # noqa: E402
from mdkdebug.codeindex import index_root, query, status # noqa: E402
from mdkdebug.codeindex import lang_asm as LA            # noqa: E402
from mdkdebug.codeindex import parser as PA              # noqa: E402
from mdkdebug.codeindex import relations                 # noqa: E402
from mdkdebug.codeindex import resolve as RS             # noqa: E402
from mdkdebug.codeindex import walk as WK                # noqa: E402
from mdkdebug.codeindex.store import Store as _Store     # noqa: E402
from mdkdebug.codeindex.store import SCHEMA_VERSION      # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "codeindex")
PROJ_ASM = os.path.join(FIX, "proj_asm")

PORT_TOOL, PORT_DEF = 14992, 14993

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

_built = {"done": False}

def ensure_built():
    if not _built["done"]:
        b = ci_build(PROJ_ASM)
        assert b.get("ok") is True, b
        _built["fixture"] = b
        _built["done"] = True
    return _built["fixture"]

def store_open():
    return _Store(db_path(PROJ_ASM)).open()

def all_symbols(st):
    out = []
    for f in (st.files_like() or []):
        out.extend(st.symbols_in_file(f["rel"]))
    return out

def all_call_sites(st):
    out = []
    for f in (st.files_like() or []):
        out.extend(st.calls_in_file(f["rel"]))
    return out

def sym_at(st, name, path):
    return [s for s in st.symbols_in_file(path) if s["name"] == name]

def calls_at(st, path, line):
    return [c for c in st.calls_in_file(path) if c["line"] == line]

def callers_of(name, direction="callers", **kw):
    o = relations(PROJ_ASM, name=name, direction=direction, **kw)
    assert o.get("ok") is True, o
    return o

def parse_asm(src, rel="x.s"):
    """直接走记录层解析（bytes），不落库。"""
    assert isinstance(src, bytes)
    return LA.parse(src, rel)

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
# A. 解析器接线与方言
# ======================================================================
def group_a():
    print("A. 解析器接线与方言")
    ok, info = PA.available()
    check("A1 available() 把 asm 列进 languages（和 c/cpp 并列）",
          ok is True and info["languages"] == ["asm", "c", "cpp"], info.get("languages"))
    check("A2 versions 里 asm 标注「行式解析（无依赖）」——谁需要依赖一眼可见",
          "行式解析" in str(info["versions"].get("asm", "")), info.get("versions"))
    check("A3 LINE_LANGS 只有 asm，且指向 lang_asm（零依赖那一路）",
          PA.LINE_LANGS == {"asm": "mdkdebug.codeindex.lang_asm"}, PA.LINE_LANGS)
    check("A4 汇编**不在** tree-sitter 的 LANG_MODULES 里（两条路分开）",
          "asm" not in PA.LANG_MODULES, PA.LANG_MODULES)

    check("A5 EXT_LANG 认 .s/.asm（.S 经 lower 归到 .s）",
          WK.lang_for("a.s") == "asm" and WK.lang_for("a.asm") == "asm"
          and WK.lang_for("a.S") == "asm" and WK.lang_for("a.STM32F4.s") == "asm", None)
    check("A6 supported_extensions 里 .s/.asm 都指向 asm",
          all(WK.supported_extensions().get(e) == "asm" for e in (".s", ".asm")),
          WK.supported_extensions())

    check("A7 索引库结构号 SCHEMA_VERSION==3（批次70 加汇编必须 bump，让老库重建）",
          SCHEMA_VERSION == 3, SCHEMA_VERSION)

    raw = open(os.path.join(PROJ_ASM, "ctx.S"), "rb").read()
    r = PA.extract(raw, "ctx.S", "asm")
    check("A8 extract(lang=asm) 走行式解析并带回 dialect/enc（不与 C 路径混淆）",
          r["dialect"] == "armasm" and r["enc"] == "utf-8"
          and "unnamed_indirect_calls" in r and "unparsed_lines" in r, r.get("dialect"))
    r2 = PA.extract(open(os.path.join(PROJ_ASM, "gnu.s"), "rb").read(), "gnu.s", "asm")
    check("A9 GNU 方言识别（.type/.macro/.text → gnu）", r2["dialect"] == "gnu", r2["dialect"])

    # 续行：armasm/CMSIS 的 `Xxx\\` + `PROC` 必须合并，否则整张中断表丢符号
    r3 = parse_asm(b"HardFault_Handler\\\n                PROC\n        BX      LR\n"
                   b"        ENDP\n", "h.s")
    names = [(s["name"], s["kind"], s["start_line"]) for s in r3["symbols"]]
    check("A10 续行合并：`HardFault_Handler\\` + `PROC` → 一个 asm_func（行号取首行）",
          names == [("HardFault_Handler", "asm_func", 1)], names)

    # GBK：旧源文件实测就是 GBK，行式解析必须自己认编码
    gbk = ("        AREA |.text|, CODE, READONLY  ; 中文注释\n"
           "foo     PROC\n        BX      LR\n        ENDP\n").encode("gbk")
    r4 = parse_asm(gbk, "g.s")
    check("A11 GBK 源文件照样解析（enc=gbk，符号名与注释都不乱）",
          r4["enc"] == "gbk" and r4["dialect"] == "armasm"
          and [s["name"] for s in r4["symbols"]] == ["foo"], (r4["enc"], r4["symbols"]))

# ======================================================================
# B. 标签与函数
# ======================================================================
def group_b():
    print("B. 标签与函数")
    b = ensure_built()
    check("B1 fixture 建索引成功（files5 / symbols15 / includes3 / calls11 / refs1 / fptr2）",
          b["counts"] == {"files": 5, "symbols": 15, "includes": 3, "calls": 11,
                          "refs": 1, "fptr": 2}, b["counts"])

    st = store_open()
    try:
        syms = all_symbols(st)
        funcs = sorted((s["path"], s["name"]) for s in syms if s["kind"] == "asm_func")
        check("B2 asm_func：PROC/ENDP 与 `.type %function` 都算（4 个）",
              funcs == [("asm_defs.s", "defs_func"), ("ctx.S", "asm_entry"),
                        ("ctx.S", "asm_local"), ("gnu.s", "gnu_entry")], funcs)
        labels = sorted((s["path"], s["name"]) for s in syms if s["kind"] == "asm_label")
        check("B3 asm_label：裸标签/数据标签（endpend、gnu_data），不当函数",
              labels == [("ctx.S", "endpend"), ("gnu.s", "gnu_data")], labels)
        imports = sorted((s["path"], s["name"], s["storage"], s["is_definition"])
                         for s in syms if s["kind"] == "asm_import")
        check("B4 asm_import：IMPORT 进来的外部符号 is_definition=0 / storage=import",
              imports == [("ctx.S", "c_helper", "import", 0),
                          ("ctx.S", "d_helper", "import", 0)], imports)

        ae = sym_at(st, "asm_entry", "ctx.S")[0]
        al = sym_at(st, "asm_local", "ctx.S")[0]
        df = sym_at(st, "defs_func", "asm_defs.s")[0]
        check("B5 函数体范围按 PROC…ENDP（asm_entry 8..20、asm_local 22..24、defs_func 3..5）",
              (ae["body_start"], ae["body_end"]) == (8, 20)
              and (al["body_start"], al["body_end"]) == (22, 24)
              and (df["body_start"], df["body_end"]) == (3, 5),
              [(s["name"], s["body_start"], s["body_end"]) for s in (ae, al, df)])
        check("B6 asm_entry 是 EXPORT 过的一层 → storage=global",
              ae["storage"] == "global", ae["storage"])

        macs = sorted((s["path"], s["name"], s["kind"]) for s in syms
                      if s["kind"] == "macro_fn")
        check("B7 宏认两种写法：armasm `X MACRO…MEND` / GNU `.macro…endm`",
              macs == [("ctx.S", "CALL_TWICE", "macro_fn"),
                       ("gnu.s", "gnu_mac", "macro_fn")], macs)
        ct = sym_at(st, "CALL_TWICE", "ctx.S")[0]
        check("B8 宏体范围按 MACRO…MEND（CALL_TWICE 26..28）",
              (ct["body_start"], ct["body_end"]) == (26, 28),
              (ct["body_start"], ct["body_end"]))

        dotted = [s["name"] for s in syms if s["name"].startswith(".")]
        check("B9 `.` 开头的名字（GNU 伪指令/局部标签）不进符号表", not dotted, dotted)

        # 被 bl 指向的裸标签升格为 asm_func（没有 PROC/ENDP 也要能认出是函数）
        r = parse_asm(b"start:\n        BL      target\n        BX      LR\n"
                      b"target:\n        BX      LR\n", "up.s")
        got = sorted((s["name"], s["kind"]) for s in r["symbols"])
        check("B10 被 bl 指向的裸标签**升格**为 asm_func（start 仍是 asm_label）",
              got == [("start", "asm_label"), ("target", "asm_func")], got)

        check("B11 asm_label **不在** CALLABLE_KINDS（数据/分支目标不是调用目标）",
              "asm_label" not in RS.CALLABLE_KINDS
              and "asm_func" in RS.CALLABLE_KINDS
              and "asm_import" in RS.CALLABLE_KINDS, RS.CALLABLE_KINDS)
    finally:
        st.close()

# ======================================================================
# C. 调用与尾调用
# ======================================================================
def group_c():
    print("C. 调用与尾调用")
    ensure_built()
    st = store_open()
    try:
        sites = sorted(((c["path"], c["line"], c["callee"], int(c["via_pointer"]),
                         int(c["in_conditional"])) for c in all_call_sites(st)),
                       key=lambda t: (t[0], t[1]))
        expect = [("ctx.S", 11, "asm_local", 0, 1),
                  ("ctx.S", 14, "c_helper", 1, 0),
                  ("ctx.S", 15, "c_helper", 0, 0),
                  ("ctx.S", 16, "defs_func", 0, 0),
                  ("ctx.S", 18, "d_helper", 0, 0),
                  ("gnu.s", 8, "c_helper", 0, 0),
                  ("gnu.s", 9, "gnu_entry", 0, 0),
                  ("main.c", 12, "asm_entry", 0, 0),
                  ("main.c", 13, "gnu_entry", 0, 0),
                  ("main.c", 14, "c_helper", 0, 0),
                  ("main.c", 15, "printf", 0, 0)]
        check("C1 11 个调用点逐条对得上（行号/名字/via_pointer/条件汇编标记）",
              sites == expect, [s for s in sites if s not in expect])

        c14 = calls_at(st, "ctx.S", 14)[0]
        check("C2 `LDR R2,=c_helper`+`BLX R2` → 记 via_pointer=1（取地址再跳）",
              c14["via_pointer"] == 1 and c14["callee"] == "c_helper", c14)
        fp = st.fptrs_named("c_helper")
        check("C3 取地址那一行进 fptr 表当盲区证据（ctx.S:13 `LDR R2, =c_helper`）",
              [(f["path"], f["line"]) for f in fp] == [("ctx.S", 13)],
              [(f["path"], f["line"]) for f in fp])

        r = parse_asm(open(os.path.join(PROJ_ASM, "ctx.S"), "rb").read(), "ctx.S")
        check("C4 无名间接调用（`BLX R3`）**不产生调用点**：unnamed_indirect=1 且无 R3 假名字",
              r["unnamed_indirect_calls"] == 1
              and not any(c["callee"].upper().startswith("R") for c in r["calls"]),
              (r["unnamed_indirect_calls"], [c["callee"] for c in r["calls"]]))

        check("C5 宏体内的 bl **不记**（CALL_TWICE 体 L27 的 bl c_helper 没有对应调用点）",
              not calls_at(st, "ctx.S", 27) and not calls_at(st, "gnu.s", 13),
              (calls_at(st, "ctx.S", 27), calls_at(st, "gnu.s", 13)))

        b18 = calls_at(st, "ctx.S", 18)[0]
        check("C6 `B d_helper`（目标是 IMPORT 进来的外部符号）→ 记成尾调用、via_pointer=0",
              b18["callee"] == "d_helper" and b18["via_pointer"] == 0
              and b18["caller"] == "asm_entry", b18)

        r = parse_asm(b"loop:\n        B       loop\n        B       ext_fn\n", "y.s")
        check("C7 本文件内 `B label`（循环/分支）**不记**；非 IMPORT 的 `B` 也不记",
              r["calls"] == [], [c["callee"] for c in r["calls"]])

        c11 = calls_at(st, "ctx.S", 11)[0]
        check("C8 条件汇编里的调用点 in_conditional=1，且 caller 归属到 asm_entry",
              c11["in_conditional"] == 1 and c11["caller"] == "asm_entry", c11)
        cl = callers_of("asm_entry", direction="callees")
        check("C9 asm_entry 的 5 个出边里，条件汇编 1 条、via_pointer 1 条如实标出",
              cl["summary"]["callees"]["in_conditional"] == 1
              and cl["summary"]["callees"]["via_pointer"] == 1, cl["summary"])
    finally:
        st.close()

# ======================================================================
# D. 跨语言可见性
# ======================================================================
def group_d():
    print("D. 跨语言可见性")
    ensure_built()
    st = store_open()
    try:
        rv = RS.Resolver(st)

        r = rv.resolve_callee("main.c", "asm_entry")
        check("D1 C 调汇编：api.h 里有声明 + 全工程唯一定义 → exact/high",
              r["basis"] == "exact" and r["confidence"] == "high"
              and [c["path"] for c in r["resolved"]] == ["ctx.S"], r)
        r = rv.resolve_callee("main.c", "gnu_entry")
        check("D2 同工程但有汇编定义、**没有声明** → name-only/low（未证实可见性）",
              r["basis"] == "name-only" and r["confidence"] == "low"
              and r["resolved"] == [] and len(r["candidates"]) == 1, r)

        r = rv.resolve_callee("ctx.S", "c_helper")
        check("D3 汇编调 C：`IMPORT c_helper` 是一条真实声明 → exact/high",
              r["basis"] == "exact" and r["confidence"] == "high"
              and [c["path"] for c in r["resolved"]] == ["main.c"]
              and "可见该声明" in (r["note"] or ""), r)
        r = rv.resolve_callee("gnu.s", "c_helper")
        check("D4 同样是汇编调 C，但没有 IMPORT → 只回到 name-only/low",
              r["basis"] == "name-only" and r["confidence"] == "low"
              and r["resolved"] == [], r)

        r = rv.resolve_callee("ctx.S", "d_helper")
        check("D5 IMPORT 了但全工程查不到定义 → blind，note 点名是「IMPORT/EXTERN」",
              r["basis"] == "blind" and r["confidence"] is None
              and r["resolved"] == [] and "IMPORT/EXTERN" in (r["note"] or ""), r)

        r = rv.resolve_callee("ctx.S", "defs_func")
        check("D6 GET 进来的可见性：asm_defs.s 可见 → exact「定义就在可见文件里」",
              r["basis"] == "exact" and r["resolved"][0]["path"] == "asm_defs.s"
              and "可见文件里" in (r["note"] or ""), r)
        check("D7 visible_files 反映 GET 这条 include 边（ctx.S → asm_defs.s）",
              rv.visible_files("ctx.S") == {"ctx.S", "asm_defs.s"},
              sorted(rv.visible_files("ctx.S")))

        r = rv.resolve_callee("ctx.S", "asm_local")
        check("D8 同文件内唯一同名定义 → exact（汇编也一样）",
              r["basis"] == "exact" and r["resolved"][0]["path"] == "ctx.S", r)

        r = rv.resolve_callee("ctx.S", "CALL_TWICE")
        check("D9 可见的宏 → exact，但 note 明说宏展开后看不见",
              r["basis"] == "exact" and "目标是宏" in (r["note"] or ""), r)

        # 红线全量复核
        bad = []
        for s in all_call_sites(st):
            rr = rv.resolve_callee(s["path"], s["callee"], bool(s["via_pointer"]))
            if rr["basis"] != "exact" and rr["resolved"]:
                bad.append((s["path"], s["line"], s["callee"], rr["basis"]))
        check("D10 **红线**：非 exact 的边一条都不许填 resolved（含汇编调用点）",
              not bad, bad)

        misc = []
        for s in all_call_sites(st):
            rr = rv.resolve_callee(s["path"], s["callee"], bool(s["via_pointer"]))
            if rr["confidence"] != RS.BASIS_CONFIDENCE.get(rr["basis"]):
                misc.append((s["callee"], rr["basis"], rr["confidence"]))
        check("D11 confidence 严格由 basis 推出（没有 blind 却给 high 这种）",
              not misc, misc)

        c = RS.project_blind_spots(st)
        check("D12 全工程盲区规模口径：11 调用点 / 1 via_pointer / 1 条件汇编 / 2 查不到定义",
              c["call_sites"] == 11 and c["via_pointer"] == 1
              and c["in_conditional"] == 1 and c["unresolved_call_sites"] == 2
              and c["unresolved_names"] == 2, c)
    finally:
        st.close()

# ======================================================================
# E. 诚实口径
# ======================================================================
def group_e():
    print("E. 诚实口径（看不清就说看不清）")
    r = parse_asm(b"        AREA |.text|, CODE\n        QWE R0, R1\n        BLX R9\n", "z.s")
    check("E1 看不懂的指令计入 unparsed_lines 并给原文样本（能核对，不是黑箱）",
          r["unparsed_lines"] == 1
          and r["unparsed_samples"] == [{"line": 2, "text": "QWE R0, R1"}],
          (r["unparsed_lines"], r["unparsed_samples"]))
    check("E2 无名间接调用单独计数 unnamed_indirect_calls（不塞进 unparsed 混口径）",
          r["unnamed_indirect_calls"] == 1, r["unnamed_indirect_calls"])
    check("E3 `parse_error` 对汇编**恒 False**（行式解析没有「解析失败」这个概念）",
          r["parse_error"] is False and r["normalized"] is False, r["parse_error"])

    raw = open(os.path.join(PROJ_ASM, "ctx.S"), "rb").read()
    rc = parse_asm(raw, "ctx.S")
    check("E4 fixture 的 ctx.S：unparsed_lines=0（armasm 那些写法全认下来了）",
          rc["unparsed_lines"] == 0 and rc["unnamed_indirect_calls"] == 1,
          (rc["unparsed_lines"], rc["unnamed_indirect_calls"]))

    doc = LA.__doc__ or ""
    check("E5 模块 docstring 明说「parse_error 恒 0，不代表这份汇编被完全理解」",
          "parse_error" in doc and "不代表" in doc, doc[:0])
    check("E6 模块 docstring 记录七条诚实边界（宏不展开 / 无名间接不记 / B 只认外部目标…）",
          all(k in doc for k in ("宏不展开", "没有名字的间接调用", "IMPORT/EXTERN",
                                "unparsed_samples")), None)

    st = store_open()
    try:
        c = RS.project_blind_spots(st)
        check("E7 盲区里「取过地址」拆成 asm/c 两侧（汇编向量表会把它抬到几千条）",
              c["fptr_declarations"] == 2 and c["fptr_declarations_asm"] == 2
              and c["fptr_declarations_c"] == 0, c)
        check("E8 拆分后的 note 交代口径「不要把这个总数当成 C 侧的函数指针数」",
              "不要把这个总数当成 C 侧的函数指针数" in (c["note"] or ""), c["note"])
    finally:
        st.close()

    r = RS.summarize([])
    check("E9 summarize([]) 不炸（空输入仍是结构化空结果）",
          r["total"] == 0 and r["by_basis"] == {}, r)

# ======================================================================
# F. 工具层
# ======================================================================
def group_f():
    print("F. 工具层（code_* 端到端 + 描述边界）")
    srv = SV.create_server(port=PORT_TOOL, toolsets="all")
    ns = tool_names(srv)
    b = call_sync(srv, "code_index", {"action": "build", "project": PROJ_ASM})
    check("F0 code_index(build) 工具层走真实入口，汇编文件一并入库",
          b.get("ok") is True and b["counts"]["calls"] == 11, b)

    st = call_sync(srv, "code_status", {"project": PROJ_ASM})
    check("F1 code_status：languages 含 asm，parser.versions.asm 有值（不装作只有 C/C++）",
          "asm" in (st.get("languages") or [])
          and "asm" in (st.get("parser", {}).get("versions") or {}), st.get("languages"))

    q = call_sync(srv, "code_query", {"project": PROJ_ASM, "name": "asm_entry",
                                      "kind": "asm_func"})
    check("F2 code_query(kind=asm_func) 查得到汇编函数",
          q.get("ok") is True and any(s["path"] == "ctx.S" for s in q.get("symbols") or []), q)

    nd = call_sync(srv, "code_node", {"project": PROJ_ASM, "name": "asm_entry"})
    cands = nd.get("candidates") or []
    asm_c = [c for c in cands if c.get("kind") == "asm_func"]
    check("F3 code_node 取得到汇编函数源码体（body 8..20，含 PROC/ENDP）",
          bool(asm_c) and asm_c[0]["body_start"] == 8 and asm_c[0]["body_end"] == 20
          and any("PROC" in (x.get("text") or "") for x in asm_c[0]["code"]), nd)

    r = call_sync(srv, "code_relations", {"project": PROJ_ASM, "name": "c_helper",
                                          "direction": "callers"})
    check("F4 code_relations 跨语言可用：c_helper 有 4 个调用者（含汇编侧 3 个）",
          r.get("ok") is True and r["summary"]["callers"]["total"] == 4, r.get("summary"))

    im = call_sync(srv, "code_impact", {"project": PROJ_ASM, "name": "asm_entry"})
    check("F5 code_impact：改汇编入口 → direct=1（C 侧 main 的那条 exact 边）",
          im.get("ok") is True and im["summary"]["direct"] == 1
          and "project_blind_spots" in im, im.get("summary"))

    check("F6 annotate：6 个 code_* 只读、code_index 归为可写",
          all(t in AN.READONLY for t in CODE_TOOLS if t != "code_index")
          and "code_index" in AN.MUTATING and "code_index" not in AN.READONLY, None)
    check("F7 annotate.check_surface 在全部工具上无问题",
          not AN.check_surface(ns), AN.check_surface(ns))
    # code_status 的输出是**单个状态对象**（不像 code_node/query 那样成片搬内容），
    # 所以**有意**不入高输出名单；其余 6 个都要有 compact/max_lines/full 三件套。
    HO = [t for t in CODE_TOOLS if t != "code_status"]
    check("F8 outctl：6 个成片输出的 code_* 全在高输出名单（code_status 输出小，有意不入）",
          all(t in OC.HIGH_OUTPUT for t in HO)
          and "code_status" not in OC.HIGH_OUTPUT,
          [t for t in HO if t not in OC.HIGH_OUTPUT])

    # 只扫 code 组自己的描述：描述里引用别的工具要真存在，否则等于递了一把打不开的钥匙。
    # `code_error` 不是工具，是 code_node 取源码失败时返回的**字段名**（用源文件自证）。
    src_init = open(os.path.join(ROOT, "mdkdebug", "codeindex", "__init__.py"),
                    encoding="utf-8").read()
    field_names = {"code_error"} if '"code_error":' in src_init else set()
    ds = tool_descs(srv)
    mentioned = set()
    for t in CODE_TOOLS:
        mentioned |= set(re.findall(r"code_[a-z_]+", ds.get(t) or ""))
    ghost = sorted(m for m in mentioned - field_names if m not in ns)
    check("F9 描述里提到的 code_* 工具**全都真实注册**（字段名 code_error 已用源文件自证排除）",
          not ghost, ghost)

    d = ds.get("code_index") or ""
    check("F10 code_index 描述交代汇编能力（写法/符号种类/行式解析零依赖）",
          all(k in d for k in ("汇编", "asm_func", "asm_label", "asm_import", "行式解析")), None)
    check("F11 code_index 描述钉死诚实口径「汇编 parse_error 恒为 0 且不等于没问题」",
          "恒为 0" in d and "不等于这份汇编没问题" in d, None)
    check("F12 code_index 描述给出 schema=3 与老索引要走 index-schema-mismatch",
          "结构号（schema）为 3" in d and "index-schema-mismatch" in d, None)
    check("F13 code_index 描述**不再**说「调用链与影响面本批不给」（那已随批次69 交付）",
          "本批不给" not in d and "code_relations" in d and "code_impact" in d, None)
    ns_d = ds.get("code_status") or ""
    check("F14 code_status 描述交代汇编 parse_error 恒 0 的口径",
          "asm" in ns_d and "恒为 0" in ns_d, None)
    rq = ds.get("code_query") or ""
    check("F15 code_query 描述列出汇编三种 kind",
          all(k in rq for k in ("asm_func", "asm_label", "asm_import")), None)
    rr = ds.get("code_relations") or ""
    check("F16 code_relations 描述交代汇编侧两条边界（无名间接不产生调用点 / B label 不记）",
          "不产生调用点" in rr and "B label" in rr, None)

    e = ER.ERROR_CODES.get("index-schema-mismatch") or {}
    check("F17 index-schema-mismatch 在错误码册里且带 next_actions",
          bool(e.get("next_actions")), e)

    check("F18 索引根目录确实被环境变量改道（测试不碰 ~/.mdkdebug）",
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
    check("G6 高输出工具 48 个", len(OC.HIGH_OUTPUT) == 48, len(OC.HIGH_OUTPUT))
    st = call_sync(srv_def, "toolset", {"action": "status"})
    grp = (st.get("groups") or {}).get("code") or {}
    check("G7 toolset(status) 列得出 code 组与规模 7", grp.get("size") == 7, grp)
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
    print("批次70：汇编（.s/.S/.asm）进代码索引")
    print("索引根：%s" % IDX_ROOT)
    group_a()
    group_b()
    group_c()
    group_d()
    group_e()
    group_f()
    group_g()
    print("\n==== 批次70 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
