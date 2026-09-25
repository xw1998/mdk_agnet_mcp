# -*- coding: utf-8 -*-
"""工具面瘦身（批次74）：去掉 tools/list 载荷里「对调用决策没有信息量」的字节。

背景
----
另一路 AI 反馈「本工具规模太大，不利于上下文与注意力机制」。实测（默认面 core
44 个工具）tools/list 的 JSON 是 **89,079 字节**，其中真正影响调用决策的是：
工具名、一句话用途、参数 schema、风险标注。剩下三类是**框架样板或纯注释**，
去掉后语义一个字都不变：

1. `outputSchema`（5,602 字节 / 6.3%）：本服务的工具一律返回一条 JSON 文本，
   框架据此生成的 schema 是恒定样板
   `{"properties":{"result":{"type":"string"}},"required":["result"],
   "title":"xxxOutput","type":"object"}`——不含任何工具特有的信息，而「返回什么」
   描述里已经写清。去掉它只改**声明**，不改返回内容。
2. `inputSchema` 里递归的 `title`（3,327 字节 / 3.7%）：JSON Schema 的 `title` 是
   **纯注释**（校验器不读），而框架生成的 title 与参数名逐字同源
   （`n_bytes` → `N Bytes`），是纯冗余。
3. `annotations` 里等于**规范默认值**、以及在只读工具上**无语义**的字段。

为什么不去改活的注册对象
------------------------
`tool.output_schema` 不是普通字段，而是只读 property，读的是
`fn_metadata.output_schema`；而那个字段在**调用路径**上还决定「要不要把返回值
包成 structuredContent」（`func_metadata.py`:
`output_model = self.output_model if self.output_schema is not None else None`）。
直接把它置 None 会**真的改掉工具的返回形态**——那是「看似权威的错答案」。
所以这里只改 `MCPServer.list_tools()` 每次新造的 **wire 副本**，活的注册对象与
校验/调用路径一个字都不动。
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("mdkdebug")

# 逃生口：MDKDEBUG_SURFACE=off 关掉结构瘦身（A/B 对照与排查用；关掉即回到
# 逐字节的历史行为）。默认开。
ENV_SWITCH = "MDKDEBUG_SURFACE"
_OFF = ("off", "0", "false", "no")

# MCP 规范里 ToolAnnotations 的默认值（逐条抄自 mcp_types.ToolAnnotations 的字段文档）：
#   readOnlyHint    Default: false
#   destructiveHint Default: true
#   idempotentHint  Default: false
#   openWorldHint   Default: true
# 与默认值相同的字段写出去，等于把规范默认值复述一遍——客户端读到的语义一模一样。
ANN_DEFAULTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
# 规范原话：destructiveHint / idempotentHint「只在 read_only_hint == false 时有意义」。
# 只读工具上它们不承载任何信息，留着只会让人误以为「读过一遍才发现是默认值」。
ANN_UNMEANINGFUL_WHEN_READONLY = ("destructiveHint", "idempotentHint")

_state = {"ok": None, "calls": 0, "tools": 0, "output_schema_removed": 0,
          "schema_titles_removed": 0, "saved_bytes": 0}

def enabled() -> bool:
    """结构瘦身是否生效（默认生效；MDKDEBUG_SURFACE=off/0/false/no 关闭）。"""
    return (os.environ.get(ENV_SWITCH) or "").strip().lower() not in _OFF

def slim_annotations(a: dict) -> dict:
    """只留下**承载信息**的注解字段。

    入参是 `annotate.annotations_for()` 的原始字典（字段齐全），返回裁剪后的字典。
    裁剪前后**语义完全一致**：缺省字段由规范默认值补齐，客户端读到的判定结果不变。
    认不出的字段（以后规范新增的）原样保留——不越权丢信息。
    """
    a = dict(a or {})
    out = {}
    for k, v in a.items():
        if k not in ANN_DEFAULTS:
            out[k] = v
            continue
        if v == ANN_DEFAULTS[k]:
            continue                                  # 等于规范默认值：不写
        if a.get("readOnlyHint") is True and k in ANN_UNMEANINGFUL_WHEN_READONLY:
            continue                                  # 只读工具上这两个字段无语义
        out[k] = v
    return out

def _strip_titles(node) -> int:
    """递归删掉 JSON Schema 里的 `title` 键，返回删掉的个数。"""
    n = 0
    if isinstance(node, dict):
        for k in [k for k in node if k == "title"]:
            node.pop(k)
            n += 1
        for v in node.values():
            n += _strip_titles(v)
    elif isinstance(node, list):
        for x in node:
            n += _strip_titles(x)
    return n

def count_titles(node) -> int:
    """递归数 JSON Schema 里的 `title` 键个数（自检/测试用）。"""
    n = 0
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "title":
                n += 1
            else:
                n += count_titles(v)
    elif isinstance(node, list):
        for x in node:
            n += count_titles(x)
    return n

def slim_wire(tools) -> dict:
    """对 **wire 上的** MCPTool 列表做结构瘦身（只改声明，不改任何工具的行为）。

    `tools` 必须是 `MCPServer.list_tools()` 刚造出来的一批 `mcp_types.Tool`
    （每次 list_tools 都会新造），所以在这里改是安全的。
    """
    st = {"ok": True, "tools": 0, "output_schema_removed": 0,
          "schema_titles_removed": 0}
    if not enabled():
        st["ok"] = False
        st["note"] = "%s=off：结构瘦身未生效（与历史行为逐字节一致）" % ENV_SWITCH
        _state.update(st)
        return st
    for t in tools:
        st["tools"] += 1
        if getattr(t, "output_schema", None):
            t.output_schema = None
            st["output_schema_removed"] += 1
        sch = getattr(t, "input_schema", None)
        if isinstance(sch, dict):
            st["schema_titles_removed"] += _strip_titles(sch)
    _state.update(st)
    _state["calls"] = _state.get("calls", 0) + 1
    if _state["calls"] == 1:
        logger.info("工具面结构瘦身：%d 个工具，去掉 outputSchema %d 个 / "
                    "inputSchema 内的 title %d 个（只改声明，调用路径未动）",
                    st["tools"], st["output_schema_removed"],
                    st["schema_titles_removed"])
    return st

def stats() -> dict:
    s = dict(_state)
    s.update({"enabled": enabled(), "env": os.environ.get(ENV_SWITCH, ""),
              "ann_defaults": dict(ANN_DEFAULTS)})
    return s
