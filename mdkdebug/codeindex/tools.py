# -*- coding: utf-8 -*-
"""代码索引工具族（批次68/69）：把 `codeindex` 门面暴露成 MCP 工具。

与其它工具族（trace / coverage / ocd…）同一写法：server.py 的循环里调用
`register(server, _js)`，失败只记日志，不影响其余工具。

已暴露 7 个工具：
- 批次68（**解析级事实**）：`code_index`（建/同步/删/查状态）、`code_status`、
  `code_files`、`code_query`、`code_node`；
- 批次69（**带 basis 的近似关系**）：`code_relations`（谁调用/被调用）、
  `code_impact`（改动影响面，分 direct/possible/unresolved/indirect + blind_spots）。

两者分开的理由：调用点、include 边、符号定义是语法树里读出来的事实；
「这个名字对应哪个定义」是**推断**。推断必须带 `basis`/`confidence`，
`resolved` 只在 `exact` 时非空，看不见的部分（函数指针/条件编译/无定义）
只报规模与位置。`code_explore` / `code_context` 留给批次70。
"""
from __future__ import annotations

import json

from . import (
    DEFAULT_NODE_LINES,
    build,
    db_path,
    drop,
    files as _files,
    impact as _impact,
    index_root,
    node as _node,
    query as _query,
    relations as _relations,
    status as _status,
    sync,
)
from . import parser as _parser

#: 索引“新鲜度”分级 → 给调用方的下一步（宁可少做，也不猜）
_NEXT_BY_ACTION = {
    "build": "code_index(action=\"sync\", project=...) 增量刷新源码改动",
    "query": "code_query(name=...)\ncode_node(name=...)\ncode_query(name=..., mode=\"prefix\")",
    "query_empty": ("先 code_index(action=\"build\") 建索引；名字不确定时用 "
                    "code_query(name=\"前缀\", mode=\"prefix\") 或 code_files(pattern=...)"),
    "node": "code_node(file=\"相对路径\") 看整个文件",
}


def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    """把 7 个代码索引工具注册进 MCP server，返回注册数。"""
    _js = js or _default_js
    n = 0

    @server.tool(
        name="code_index",
        title="代码索引：建 / 增量同步 / 删除 / 看状态（C/C++/汇编 结构索引）",
        description=(
            "**大型工程的省 token 入口**：把「grep 一遍 + Read 整个文件」换成「一次问结构」。"
            "做法是用 tree-sitter（预编译轮子，不需要你装编译器）把 C/C++ 解析成"
            "**符号表 + include 图 + 单符号源码体**，落在 SQLite（`~/.mdkdebug/codeindex/`，"
            "**不往你的工程目录里写**）。建好之后 `code_query` / `code_node` / `code_files` "
            "都是查库，比扫盘 + 读文件快，也省 token。\n"
            "**汇编（`.s`/`.S`/`.asm`）也进索引**：启动文件、上下文切换、SVC/PendSV 入口、"
            "向量表都在这里。汇编走**行式解析**（零依赖），armasm / GNU / IAR 三种写法都认："
            "标签与函数（PROC…ENDP、`.type %function`、`.thumb_func`）、`BL`/`BLX`、"
            "`IMPORT`/`PUBWEAK`、宏、`LDR Rn,=sym` 与 `DCD` 数据表、条件汇编。符号种类是"
            "`asm_func` / `asm_label` / `asm_import`（**不复用 C 的 `function`**——不假装汇编"
            "标签就是 C 函数）。**它看不懂的行一律不记**，并在文件里给出 `unparsed_lines`："
            "汇编的 `parse_error` **恒为 0，且不等于这份汇编没问题**，不要拿它当质量背书。\n"
            "action：\n"
            "  · `status`（默认）—— 有没有索引、多大、多少文件/符号、上次构建时间、"
            "**是否落后于源码**；\n"
            "  · `build` —— 建索引（全量解析项目内候选文件）。**只有你显式调用才会跑**，"
            "不会在后台偷偷建；\n"
            "  · `sync` —— 增量刷新：mtime/size 没动的文件不重解析，动了的重算 sha1，"
            "**内容真变才重解析**（`git checkout` 只改 mtime 时会走 metadata_only 快路）；\n"
            "  · `drop` —— 删索引文件（**不可逆**，但只删索引，源码一个字不动）。\n"
            "project：源码根目录（必填，别指到 `Objects/` 那种构建产物目录）。\n"
            "in_project=true 才写进 `<项目>/.mdkdebug/index.db`，默认写用户目录。\n"
            "**如实报的几件事**：① 语法有错的文件照样索引已解析的部分，但计入 "
            "`parse_error_count` 并列出文件名（别把不完整的索引当全量）；"
            "② `skipped_list` 逐条给「哪些文件/目录被跳过、为什么」（构建产物、.gitignore、"
            ">1 MB 当生成物），不静默吞；③ 缺 tree-sitter 依赖时报 `parser-missing` 并给装法，"
            "**不会退化成 grep 假装成功**。\n"
            "本批只产**解析级事实**：宏不展开、条件编译所有分支都进索引只标 `in_conditional`、"
            "局部变量不入符号表、C++ 模板/重载/继承不覆盖。**调用链与影响面用 `code_relations` / "
            "`code_impact`** —— 那两条是**推断**，所以每条结论都带 basis/confidence，并单独报出"
            "看不见的部分（盲区）：不先编一个像样的调用图。\n"
            "**索引库结构号（schema）为 3**：批次70 加了汇编，老索引（schema 2）里**没有汇编文件**，"
            "那是「结构对得上、内容静默不全」的库，所以会报 `index-schema-mismatch` 让你 drop 重建。"
        ),
    )
    async def code_index(action: str = "status", project: str = "",
                         in_project: bool = False) -> str:
        try:
            act = (action or "status").strip().lower()
            if act in ("status", "info"):
                return _js(_status(project, in_project=in_project))
            if act == "build":
                return _js(build(project, in_project=in_project))
            if act in ("sync", "update", "refresh"):
                return _js(sync(project, in_project=in_project))
            if act in ("drop", "remove", "delete"):
                # 不在这里写 `risk`：统一信封的 `risk` 是**等级**（medium/high），
                # 业务文案写进去会被静默覆盖（一个键名一义）。风险说明走 `note`。
                return _js(drop(project, in_project=in_project))
            return _js({"ok": False, "error": "不认识的 action：%s" % action,
                        "error_code": "invalid-argument",
                        "hint": "action 取 status / build / sync / drop"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_status",
        title="代码索引：有没有 / 多大 / 落后了没有（+ 解析器可用性）",
        description=(
            "一眼看清索引现状：库路径与体积、文件/符号/include/调用点计数、上次 build/sync 时间、"
            "**是否落后于源码**（changed/missing/added 三类计数 + 样本路径）、"
            "**索引完整度**（`parse_errors` / `parse_error_count`：解析器走过恢复态的文件，"
            "索引里这部分不可全信——别把部分解析的索引当全量），"
            "支持的语言（含 **asm**：汇编是行式解析、零依赖，它的 `parse_error` **恒为 0 且"
            "不代表没问题**），以及 tree-sitter 解析器能不能用（缺依赖时给装法，不装作能用）。\n"
            "**落后不会自动重建**：`stale.is_stale=true` 只说明该刷了，要刷显式 "
            "`code_index(action=\"sync\")`——自动重建会让「读到的到底是什么版本」变得不可知。\n"
            "还没建索引时返回 `error_code=no-index`（不是 ok）并告诉你怎么建。"
        ),
    )
    async def code_status(project: str = "", in_project: bool = False) -> str:
        try:
            return _js(_status(project, in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_files",
        title="代码索引：工程里有哪些源码文件 / 目录结构（索引内的，比扫盘快）",
        description=(
            "列**已索引**的源码文件（rel 路径 / 语言 / 行数 / 该文件符号数），"
            "可选 `pattern` 过滤（支持 `*`，如 `src/*usart*`）与 `max_depth` 限制路径层数"
            "（`a.c` 是 1 层、`inc/util.h` 是 2 层；省略或 0 = 不限制）。\n"
            "用途：找文件真实路径（`code_node(file=...)` 要的是索引里的 rel 路径）、"
            "看一个大工程长什么样，**不必先扫盘**。\n"
            "`dirs` 给目录集合。只看被索引的：被 .gitignore/构建产物排除的这里没有——"
            "想看「为什么某个文件不在」用 `code_index(action=\"build\")` 的 `skipped_list`。"
        ),
    )
    async def code_files(project: str = "", pattern: str = "",
                         max_depth: int = 0, in_project: bool = False) -> str:
        try:
            return _js(_files(project, pattern=(pattern or None),
                              max_depth=(max_depth or None),
                              in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_query",
        title="代码索引：按名字查符号（替代 grep -rn 的第一步，只回位置+签名）",
        description=(
            "按符号名查**位置与签名**（不回源码体，这是省 token 的关键）："
            "每条给 name / kind / path / line / end_line / is_definition / signature / parent。\n"
            "  · 一个名字多处定义（不同文件各有一份 static、或头里只有声明）→ **全给你**，"
            "不猜你要哪一个；\n"
            "  · `kind` 过滤：C/C++ —— function / macro / macro_fn / struct / class / union / "
            "enum / enumerator / typedef / field / variable / namespace / fptr；"
            "汇编 —— asm_func（PROC/`.type %function`/被 bl 指向的标签）/ asm_label（其它标签、"
            "EQU 常量，storage=constant）/ asm_import（`IMPORT`/`EXTERN` 声明的外部符号）；\n"
            "  · `mode`：auto（默认，精确 > 前缀 > 子串，可预测）/ exact / prefix / substring / "
            "fts（**实验性**：按相关度排序，代码标识符用 FTS 反而容易出意外，比如 `foo_bar` "
            "会被切成两个词——要用请知道自己在赌什么）；\n"
            "  · `only_definitions=true` 只看定义，跳过声明。\n"
            "**符号表不含局部变量**（只索引文件作用域符号）。要看某个符号的源码体用 `code_node`。"
        ),
    )
    async def code_query(project: str = "", name: str = "", kind: str = "",
                         limit: int = 50, mode: str = "auto",
                         only_definitions: bool = False,
                         in_project: bool = False) -> str:
        try:
            return _js(_query(project, name, kind=(kind or None), limit=limit,
                              mode=mode, only_definitions=only_definitions,
                              in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_node",
        title="代码索引：取单个符号的源码体 / 整个文件（带行号，可当 Read 用）",
        description=(
            "两种用法：\n"
            "  · `name=<符号名>` —— 给该符号的**签名 + 源码体（带行号）+ 位置 + 它体内的调用点**。"
            "同名多处**给全部候选**（含头里的声明与 .c 里的定义），调用方按 path/line 自己挑；"
            "`body_start`/`body_end` 是函数体的真实范围（声明没有体，只有一行）；\n"
            "  · `file=<相对路径>` —— 给**整个文件带行号**（Read-parity），可配 "
            "`start_line`/`end_line` 只取一段。\n"
            "`max_lines` 限制单个符号回多少行（默认 %d），截断时 `truncated=true`。\n"
            "两个关系字段别混：`calls_out` 是**该符号体内的调用点**（谁被它调，解析级事实）；"
            "`refs` **只含类型名与条件编译里的宏名**的出现位置——它既不是「所有引用」"
            "也不是「谁调用了它」。反向的「谁调了它」是**推断**，本批**不给**："
            "要把它做成带 `basis`/`confidence` 的结论之后才会对外，先编一个像样的"
            "调用图就是假的。\n"
            "取源码时若文件已不在磁盘上，如实报 `code_error`/`file-not-found`，不返空体。"
            % DEFAULT_NODE_LINES
        ),
    )
    async def code_node(project: str = "", name: str = "", file: str = "",
                        kind: str = "", max_lines: int = DEFAULT_NODE_LINES,
                        start_line: int = 0, end_line: int = 0,
                        in_project: bool = False) -> str:
        try:
            return _js(_node(project, name=(name or None), file=(file or None),
                             kind=(kind or None), max_lines=max_lines,
                             start_line=(start_line or None),
                             end_line=(end_line or None),
                             in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_relations",
        title="代码索引：调用关系（谁调用了它 / 它调用了谁，每条边带置信度）",
        description=(
            "从**调用点**（语法事实）推出**关系**（推断），每条边都带「凭什么」：\n"
            "  · `basis=exact` + `confidence=high` —— **证明得到**：同文件内唯一同名定义；"
            "或调用点所在 TU（经 include 传递闭包）里看得见该符号的声明，且全工程唯一定义；\n"
            "  · `include-visible` / `medium` —— include 链可达，但工程内有**多个**同名定义，"
            "候选全列在 `candidates` 里让你自己挑；\n"
            "  · `name-only` / `low` —— 只能靠名字匹配（未见 include 链），**未证实可见性**；\n"
            "  · `blind` —— 静态看不到（函数指针调用 / 工程内查不到定义）。\n"
            "**汇编侧**：`asm_func` 是可作调用目标的一类定义；`asm_import`（`IMPORT`/`EXTERN`）"
            "是一条真实存在的声明，所以「汇编调 C 函数」能拿到比 name-only 更硬的依据。"
            "但汇编里两件事看不到：`BLX Rn` 而寄存器来源不明（**不产生调用点**，不编名字）、"
            "本文件内的 `B label`（那是循环/分支，不是调用）——所以调用图在汇编处会断，"
            "这是如实呈现的边界，不是解析失败。\n"
            "参数：`name`（符号名，必填）、`direction`（callers / callees / both）、`depth`"
            "（BFS 深度，1=只看直接一层）、`path`/`line`（同名多处时指定哪一个定义）。\n"
            "两条别踩的线：① **`resolved` 只在 exact 时非空**——它是「证明得到」的那一个定义，"
            "其余一律只进 `candidates`，不把一个像样的猜测填成结论；"
            "② 「谁调用了它」里的 caller 是**解析级事实**（解析时按同文件最内层函数记下的），"
            "推断只发生在「这个名字对应哪个定义」。\n"
            "响应带 `blind_spots`：与该名相关的**看不见的部分**（函数指针调用、条件编译内的调用、"
            "同名宏、工程内无定义）各有位置与计数——宁可说「这里我看不到」，不画一张像样的调用图。\n"
            "先 `code_index(action=\"build\")` 建索引；没建会报 `no-index`。"
        ),
    )
    async def code_relations(project: str = "", name: str = "",
                             direction: str = "callers", depth: int = 1,
                             path: str = "", line: int = 0, limit: int = 200,
                             in_project: bool = False) -> str:
        try:
            return _js(_relations(project, name=(name or None), direction=direction,
                                  depth=depth, path=(path or None),
                                  line=(line or None), limit=limit,
                                  in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="code_impact",
        title="代码索引：改动影响面（direct 确定 / possible 存疑 / blind 看不见）",
        description=(
            "「改这个函数，要连带看哪些地方」——把**调用者**按置信度分段，而不是笼统给一张图：\n"
            "  · `direct` —— 已证实（`exact`/high）的直接调用者，**最该先看**；\n"
            "  · `possible` —— `include-visible`/medium 或 `name-only`/low 的直接调用者，"
            "要人工扫一眼；\n"
            "  · `unresolved` —— 有调用点叫这个名字、但**解析不到定义**（宏展开/系统函数/汇编），"
            "属盲区；\n"
            "  · `indirect` —— 深度 >1 的间接调用者（`depth` 默认 2）；\n"
            "  · `blind_spots` / `project_blind_spots` —— 静态**看不到**的部分（函数指针调用、"
            "条件编译内的调用、无定义的调用点）的规模与位置。\n"
            "`depth` 只沿 `exact` 已证实的边往下钻（拿猜出来的边继续下钻，第二层起就全是假的）。\n"
            "**别把 possible/unresolved 当确定影响面**：它们是「可能有影响」，不是「一定有」。\n"
            "先 `code_index(action=\"build\")` 建索引；没建会报 `no-index`。"
        ),
    )
    async def code_impact(project: str = "", name: str = "", depth: int = 2,
                          path: str = "", line: int = 0, limit: int = 300,
                          in_project: bool = False) -> str:
        try:
            return _js(_impact(project, name=(name or None), depth=depth,
                               path=(path or None), line=(line or None),
                               limit=limit, in_project=in_project))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
