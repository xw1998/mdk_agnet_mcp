# -*- coding: utf-8 -*-
"""代码索引：关系解析与置信度（批次69）。

本模块只做一件事：把**解析级事实**（调用点、include 边、符号定义/声明）拼成
**可复核的关系结论**，并且每条结论都带上「这个结论凭什么」——

  basis          confidence   含义
  exact          high         **证明得到**：同文件内唯一同名定义；或该定义落在调用点所在 TU
                              （经 include 传递闭包）里，且全工程唯一；或声明可见且全工程唯一定义
  include-visible medium      include 链可达，但工程内存在**多个**同名定义（附候选清单）——
                              读者要自己按候选挑，工具不替它挑
  name-only      low          只能靠名字匹配：调用点所在 TU 见不到声明/定义（未见 include 链），
                              或只有一个定义但可见性未证实。**明确标「未证实可见性」**
  blind          None        静态看不到：通过函数指针调用、或工程内压根没有该名字的定义
                              （宏展开 / 系统函数 / 汇编 / 没索引到）

两条**不可越过的红线**（与批次35、68 一脉相承）：

1. **`resolved` 只装「证明得到」的定义**（即 basis=exact 的那一个）。include-visible /
   name-only / blind 的候选一律只进 `candidates`，`resolved` 留空——把「一个像样的猜测」
   填进 `resolved` 就是「看似权威的错答案」。
2. **盲区要报数、报位置**，不能只说「可能有盲区」。函数指针调用、条件编译内的调用、
   同名 static、工程内无定义的调用点，逐条给位置与计数。宁可说「这里我看不到」，
   也不画一张看似完整的调用图。

「谁是调用者」这一侧同样是**解析级事实**：`calls.caller` 是解析时按「包含该调用点的
最内层函数定义（同文件）」记下来的，不是推断；推断只发生在「这个调用名对应哪个定义」。

**汇编（`asm_func` / `asm_import`）也在这套规则里**，但三处边界要记住：
- 汇编文件不 `#include` C 头，所以「汇编调 C 函数」往往靠 `IMPORT`/`EXTERN` 这条**声明**
  拿到 `exact`；没有 `IMPORT` 只有名字对得上，就是 `name-only`（未证实可见性）。
- `LDR Rn, =sym` + `BLX Rn` 记成 `via_pointer=1`：名字是文本里给的，但**那只是线索**，
  一律压成 `blind`（不因为“看起来像”就抬成 exact）。
- 无名间接调用（`BLX Rn` 且寄存器来源不可证）**根本不产生调用点**，所以也不会出现在
  `unresolved_names` 里——“少一条”远好于“编一个像 R2 这样的假名字”。
"""
from __future__ import annotations

#: 能作为调用目标的符号种类（宏函数也算——调用点可能被宏展开）。
#: `asm_func` 是汇编里的函数（PROC/ENDP、`.type %function`、`.thumb_func`、被 bl 指向的标签）；
#: `asm_import` 是汇编里 `IMPORT`/`EXTERN` 进来的外部符号——它是**一条真实的声明**，
#: 有了它「汇编调 C 函数」这个调用点才能给出比 name-only 更硬的依据（而不是靠猜）。
#: 汇编的普通标签 `asm_label` **不在此列**：那是数据/常量/分支目标，不是调用目标。
CALLABLE_KINDS = ("function", "macro_fn", "fptr", "asm_func", "asm_import")

#: basis → confidence（blind 不给置信度：它不是一个结论，是「看不到」）
BASIS_CONFIDENCE = {"exact": "high", "include-visible": "medium",
                    "name-only": "low", "blind": None}

#: 置信度排序（summary 用）
_CONF_ORDER = ("high", "medium", "low")


def _cand(s):
    """符号行 → 候选条目（位置 + 存储类 + 是否在条件编译里）。"""
    return {"name": s["name"], "kind": s["kind"], "path": s["path"],
            "line": s["start_line"], "end_line": s["end_line"],
            "storage": s["storage"], "is_definition": bool(s["is_definition"]),
            "in_conditional": bool(s["in_conditional"])}


class Resolver:
    """一个索引库上的可见性与消歧器。用一次会话就 new 一个（带缓存）。"""

    def __init__(self, store):
        self.store = store
        self._edges = None
        self._vis = {}
        self._syms = {}

    # ------------------------------------------------------------ include 可见性

    def include_edges(self):
        if self._edges is None:
            m = {}
            for src, dst in self.store.include_edges():
                m.setdefault(src, set()).add(dst)
            self._edges = m
        return self._edges

    def visible_files(self, rel):
        """rel 自己 + 经 include **传递**可达的文件集合。

        只走唯一匹配上的 include 边（歧义头/系统头不进图）——「可见」必须是可证的，
        猜来的可见性会把 include-visible 抬成假 exact。
        """
        hit = self._vis.get(rel)
        if hit is not None:
            return hit
        edges = self.include_edges()
        seen = {rel}
        stack = [rel]
        while stack:
            cur = stack.pop()
            for nxt in edges.get(cur, ()):  # noqa: SIM118
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        self._vis[rel] = seen
        return seen

    def symbols_named(self, name):
        if name not in self._syms:
            self._syms[name] = self.store.symbols_by_name(name)
        return self._syms[name]

    # ------------------------------------------------------------ 调用点 → 定义

    def resolve_callee(self, file, callee, via_pointer=False):
        """把一个调用点（file 里调用 callee）解析到定义，附 basis/confidence/候选。

        返回 dict：basis / confidence / resolved / candidates / decls / macro_shadow /
        ambiguous / note。**resolved 只在 exact 时非空**（见模块说明第 1 条红线）。

        两条容易踩的边界，这里都算「看不到」而不是硬给一个名字：
        - 目标是**函数指针变量**（`on_tick(r)`；没有函数定义、只有 fptr 声明）= 间接调用；
        - 目标只有**同名宏**（`#define X ...`）= 宏展开后的真实调用看不见（但仍按宏定义
          是否可见给 exact，因为「这个宏名对应哪条宏定义」是可证的）。
        """
        name = callee
        allsyms = self.symbols_named(name)
        syms = [s for s in allsyms if s["kind"] in CALLABLE_KINDS]
        fn_defs = [s for s in syms
                   if s["is_definition"] and s["kind"] in ("function", "macro_fn", "asm_func")]
        fptr_defs = [s for s in syms
                     if s["is_definition"] and s["kind"] == "fptr"]
        decls = [s for s in syms if not s["is_definition"]]
        macroish = [s for s in allsyms if s["kind"] in ("macro", "macro_fn")]
        defs = fn_defs

        info = {"candidates": [_cand(s) for s in (fn_defs + fptr_defs)],
                "decls": [_cand(s) for s in decls],
                "macro_shadow": [_cand(s) for s in macroish],
                "resolved": [], "ambiguous": False, "basis": "blind",
                "confidence": None, "note": None}

        if via_pointer:
            info["note"] = "通过函数指针调用：静态看不到指向哪个定义（盲区，不猜）"
            return info
        if not defs and fptr_defs:
            info["note"] = ("目标是函数指针变量（间接调用）：真实被调者静态看不到——盲区，"
                            "不猜（候选里给的是这个指针变量的声明位置）")
            return info
        if not defs and any(s["kind"] == "asm_import" for s in syms):
            # 汇编 IMPORT 了它，但全工程找不到定义：典型是汇编里手动跳过去的入口，
            # 或目前只索引了部分目录。这时“能看到声明”不能当成“能看到目标”。
            info["note"] = ("汇编里 IMPORT/EXTERN 了这个名字，但全工程查不到它的定义"
                            "（只索引了一部分目录 / 真的在别的镜像里）——盲区，不猜")
            return info

        vis = self.visible_files(file)
        same_defs = [s for s in defs if s["path"] == file]
        vis_defs = [s for s in defs if s["path"] in vis]
        vis_decls = [s for s in decls if s["path"] in vis]

        def _exact(one, why):
            if one["kind"] == "macro_fn":
                why += "（目标是宏：宏展开后的真实调用静态看不到）"
            info.update(basis="exact", confidence="high",
                        resolved=[_cand(one)], note=why)

        if len(same_defs) == 1:
            _exact(same_defs[0], "同文件内唯一同名定义")
            return info
        if len(same_defs) > 1:
            info.update(basis="include-visible", confidence="medium", ambiguous=True,
                        note="同一文件内有多处同名定义（同名 static？），无法消歧")
            return info
        if len(defs) == 1:
            if vis_defs:
                _exact(defs[0], "定义就在可见文件里，且全工程唯一")
            elif vis_decls:
                _exact(defs[0], "调用点所在 TU 可见该声明，且全工程唯一定义")
            else:
                info.update(basis="name-only", confidence="low",
                            note="只有一个定义，但调用点所在 TU 见不到它的声明/定义"
                                 "（未见 include 链）——未证实可见性")
            return info
        if len(defs) > 1:
            if vis_defs:
                info.update(basis="include-visible", confidence="medium",
                            ambiguous=True,
                            note="可见的同名定义有多个（或可见一个、别处还有）——候选见 candidates")
            elif vis_decls:
                info.update(basis="include-visible", confidence="medium",
                            ambiguous=True,
                            note="声明可见，但工程内有多个同名定义（候选见 candidates）")
            else:
                info.update(basis="name-only", confidence="low", ambiguous=True,
                            note="只见名字匹配且有多个同名定义（未证实可见性）")
            return info
        if vis_decls:
            info.update(basis="name-only", confidence="low",
                        note="声明可见但工程内查不到定义（外部库/汇编/未索引到）")
            return info
        info["note"] = "工程内查不到该名字的定义（宏展开/系统函数/汇编/未索引）——盲区"
        return info

    # ------------------------------------------------------------ 反向：谁调用了它

    def callers(self, name, depth=1, limit=200):
        """name 的调用者（BFS，深度 depth）。返回 (edges, truncated)。

        每条边 = 一个**调用点**（caller/path/line 是解析级事实）＋ 该调用点对 name 的
        解析结论（basis/confidence/resolved/candidates）＋ 深度。
        """
        depth = max(1, int(depth or 1))
        limit = max(1, int(limit or 200))
        edges, truncated = [], False
        visited = {name}
        frontier = [(name, 1)]
        while frontier and not truncated:
            nxt = []
            for nm, d in frontier:
                for s in self.store.calls_to(nm):
                    r = self.resolve_callee(s["path"], nm, bool(s["via_pointer"]))
                    edges.append({
                        "depth": d,
                        "caller": s["caller"], "caller_path": s["path"],
                        "line": s["line"], "callee": nm,
                        "basis": r["basis"], "confidence": r["confidence"],
                        "resolved": r["resolved"], "candidates": r["candidates"],
                        "ambiguous": r["ambiguous"],
                        "in_conditional": bool(s["in_conditional"]),
                        "via_pointer": bool(s["via_pointer"]),
                        "note": r["note"],
                    })
                    if s["caller"] and d < depth and s["caller"] not in visited:
                        visited.add(s["caller"])
                        nxt.append((s["caller"], d + 1))
                    if len(edges) >= limit:
                        truncated = True
                        break
                if truncated:
                    break
            frontier = nxt
        return edges, truncated

    # ------------------------------------------------------------ 正向：它调用了谁

    def _body_sites(self, sym):
        """某函数定义体内（body 范围内）的调用点。"""
        bs = sym["body_start"] or sym["start_line"]
        be = sym["body_end"] or sym["end_line"]
        return [c for c in self.store.calls_in_file(sym["path"])
                if bs <= (c["line"] or 0) <= be]

    def callees(self, sym, depth=1, limit=200):
        """某个函数定义体内的调用（BFS，只沿 **exact 解析到的定义** 继续下钻）。

        沿 exact 才下钻，是因为下钻靠的是「这个调用确实调到了那个定义」这个前提；
        include-visible/low 的边照样列出（带 basis），但不当作继续下钻的依据——
        否则第二层开始就是一串猜出来的边。
        """
        depth = max(1, int(depth or 1))
        limit = max(1, int(limit or 200))
        edges, truncated = [], False
        seen_ids = set()
        frontier = [(sym, 1)]
        while frontier and not truncated:
            nxt = []
            for s, d in frontier:
                for c in self._body_sites(s):
                    r = self.resolve_callee(c["path"], c["callee"],
                                            bool(c["via_pointer"]))
                    edges.append({
                        "depth": d, "from": "%s:%s" % (c["path"], c["line"]),
                        "callee": c["callee"], "path": c["path"], "line": c["line"],
                        "basis": r["basis"], "confidence": r["confidence"],
                        "resolved": r["resolved"], "candidates": r["candidates"],
                        "ambiguous": r["ambiguous"],
                        "in_conditional": bool(c["in_conditional"]),
                        "via_pointer": bool(c["via_pointer"]),
                        "note": r["note"],
                    })
                    if d < depth:
                        for rd in r["resolved"]:            # 只有 exact 才有 resolved
                            nxt_sym = self.store.symbol_at(rd["path"], rd["line"])
                            if nxt_sym is None or nxt_sym["id"] in seen_ids:
                                continue
                            seen_ids.add(nxt_sym["id"])
                            nxt.append((nxt_sym, d + 1))
                    if len(edges) >= limit:
                        truncated = True
                        break
                if truncated:
                    break
            frontier = nxt
        return edges, truncated

    # ------------------------------------------------------------ 盲区

    def blind_spots(self, name):
        """与 name 相关的**看不见的部分**：函数指针、条件编译、无定义、宏同名。"""
        sites = self.store.calls_to(name)
        syms = self.symbols_named(name)
        fptr_decls = self.store.fptrs_named(name)
        callable_defs = [s for s in syms
                         if s["is_definition"] and s["kind"] in CALLABLE_KINDS]
        return {
            "fptr_calls": [{"path": s["path"], "line": s["line"],
                            "caller": s["caller"]}
                           for s in sites if s["via_pointer"]],
            "conditional_calls": [{"path": s["path"], "line": s["line"],
                                   "caller": s["caller"]}
                                  for s in sites if s["in_conditional"]],
            "fptr_declarations": [{"path": d["path"], "line": d["line"],
                                   "name": d["name"], "decl": d["decl"]}
                                  for d in fptr_decls],
            "macro_shadow": [{"path": s["path"], "line": s["start_line"],
                              "kind": s["kind"]} for s in syms
                             if s["kind"] in ("macro", "macro_fn")],
            "no_definition": not callable_defs,
            "counts": {
                "call_sites": len(sites),
                "fptr_calls": sum(1 for s in sites if s["via_pointer"]),
                "conditional_calls": sum(1 for s in sites if s["in_conditional"]),
                "fptr_declarations": len(fptr_decls),
                "definitions": len(callable_defs),
                "declarations": len([s for s in syms
                                     if not s["is_definition"]
                                     and s["kind"] in CALLABLE_KINDS]),
            },
            "note": ("函数指针调用、条件编译内的调用、工程内无定义的调用点都是静态分析的盲区；"
                     "这里只报「有多少、在哪」，不给一个猜出来的目标。"),
        }


def project_blind_spots(store):
    """整个索引的盲区总量（一条 SQL 能算的，不算「逐调用解析」那层）。

    `unresolved_call_sites` 用一条 NOT EXISTS 算出「callee 在符号表里没有任何定义」的
    调用点条数（宏展开 / 系统函数 / 汇编 / 没索引到），是这批里最有说服力的诚实数字。
    """
    q = store.conn.execute
    n_calls = q("SELECT COUNT(*) AS n FROM calls").fetchone()["n"]
    n_viaptr = q("SELECT COUNT(*) AS n FROM calls WHERE via_pointer=1").fetchone()["n"]
    n_cond = q("SELECT COUNT(*) AS n FROM calls WHERE in_conditional=1").fetchone()["n"]
    n_fptr = q("SELECT COUNT(*) AS n FROM fptr").fetchone()["n"]
    # 把「取过地址」拆成汇编 / C 两侧：汇编里的 `LDR Rn, =sym` 与向量表/DCD 数据表
    # 都会进 fptr 表，一个 CMSIS 启动文件的向量表就能带来 ~80 条——不拆开的话，
    # 「fptr_declarations」这个数字会被向量表淹没，读者会以为 C 侧突然多了几百个函数指针。
    n_fptr_asm = q("SELECT COUNT(*) AS n FROM fptr f JOIN files fl ON fl.id=f.file_id "
                   "WHERE fl.lang='asm'").fetchone()["n"]
    kinds = ",".join("?" * len(CALLABLE_KINDS))
    n_unres = q("SELECT COUNT(*) AS n FROM calls c WHERE NOT EXISTS ("
                "SELECT 1 FROM symbols s WHERE s.name=c.callee AND s.is_definition=1 "
                "AND s.kind IN (%s))" % kinds, CALLABLE_KINDS).fetchone()["n"]
    n_unres_names = q("SELECT COUNT(DISTINCT c.callee) AS n FROM calls c WHERE NOT EXISTS ("
                      "SELECT 1 FROM symbols s WHERE s.name=c.callee AND s.is_definition=1 "
                      "AND s.kind IN (%s))" % kinds, CALLABLE_KINDS).fetchone()["n"]
    return {
        "call_sites": n_calls,
        "via_pointer": n_viaptr,
        "in_conditional": n_cond,
        "fptr_declarations": n_fptr,
        "fptr_declarations_asm": n_fptr_asm,
        "fptr_declarations_c": n_fptr - n_fptr_asm,
        "unresolved_call_sites": n_unres,
        "unresolved_names": n_unres_names,
        "note": ("via_pointer 是「通过函数指针调用」的调用点规模；fptr_declarations 是"
                 "「取过地址」的记录数，**已拆成 asm/c 两侧**（汇编侧的 `LDR Rn, =sym`、"
                 "`DCD`/`.word` 向量表都算，十几份 CMSIS 启动文件就能把它抬到几千条，"
                 "所以不要把这个总数当成 C 侧的函数指针数）；in_conditional 是落在条件编译"
                 "分支里的调用点；unresolved 是 callee 在符号表里查不到定义的调用点"
                 "（宏展开/系统函数/没索引到的汇编/未索引）。这些是**看不全**的规模，"
                 "不等于错误。"),
    }


def summarize(edges):
    """按 basis/confidence/depth 汇总一组边。"""
    by_basis, by_conf = {}, {}
    for e in edges:
        by_basis[e["basis"]] = by_basis.get(e["basis"], 0) + 1
        conf = e["confidence"] or "blind"
        by_conf[conf] = by_conf.get(conf, 0) + 1
    return {
        "total": len(edges),
        "by_basis": by_basis,
        "by_confidence": by_conf,
        "ambiguous": sum(1 for e in edges if e.get("ambiguous")),
        "in_conditional": sum(1 for e in edges if e.get("in_conditional")),
        "via_pointer": sum(1 for e in edges if e.get("via_pointer")),
        "by_depth": {str(d): sum(1 for e in edges if e["depth"] == d)
                     for d in sorted({e["depth"] for e in edges})},
    }
