# -*- coding: utf-8 -*-
"""工具描述分层：把长说明挪出上下文，需要时再取回。

背景
----
批次42 起工具面已经能按组装卸（默认只暴露 core 组），但**单个工具的描述本身仍然
很长**：全部 180+ 个工具的 description 合计约 9.4 万字符，其中约 87% 是背景叙述、
失败模式、真机踩坑这类「参考手册」内容。工具装全时这堆描述要整份进上下文——这正是
用户反馈里「上下文小的大模型装不全 mcp 工具」的另一半原因（前一半「工具太多」由
批次42 的按组装卸解决）。

做法
----
把描述拆成两层：
  * **常驻层**（进上下文）：一句话用途 + 追加的【参数】/【调用示例】块。
  * **归档层**（按需取回）：被挪走的正文原文，一个字不改地存在进程内，
    用 `mdk_guide(topic="tool", name="xxx")` 取回。

正文截断遵循两条硬规则（违反任何一条都会造出「看似权威的错答案」）：
  1. **结构化尾块整段保留**：从最早出现的 `【输出控制】/【参数】/【风险】/
     【参数别名】` 标记处整段留下。schema 里有的参数，描述里就必须讲清；
     绝不能出现「参数在、说明没了」。
  2. **尾部关键句保留**：正文最后一句往往是最要紧的告警（真机上正是靠
     「置信度低时不要据此下结论」这类话避免误判），所以截断保留
     「段首 + 段末」，只丢中间。

档位（`MDKDEBUG_DESC` 环境变量，或由调用方显式传入；nano 工具面用 min）：
  * `full`（**默认**）—— 不做任何改写，与历史行为逐字节一致。
    为什么默认是 full：186 个工具里有七十多个的描述长到会被截断，而默认对外
    暴露的描述**不该缺内容**——模型看不到边界条件与失败模式，反而更容易用错
    工具（属于「看似权威的错答案」的同族问题）。真「装不下」的场景由
    nano 工具面（自动 min 档）+ `tools_load` 按需装载解决，而不是靠砍默认档。
  * `lean` —— 正文保留到 ~360 字符（优先在段落边界断开），其余归档。
  * `min` —— 正文只留一句话摘要，其余归档。

不变量（防翻车）
----------------
1. **无损**：归档存的就是原文，取回后与未瘦身时完全一致。
2. **本来就不长的描述一个字不动**，也不追加「已挪出」指针——否则满屏指针反而更费
   上下文（指针本身也是字符）。
3. **只动正文**：`_apply_param_hints` 追加的【参数】块原样留在原位，参数口径不受
   影响；`list_tools` 后续追加的【风险】/【参数别名】也照旧能挂上去。
4. **档位认不出来时按默认档处理并告警**，不静默变成 full（那会让人以为配置生效了）。
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("mdkdebug")

MODES = ("full", "lean", "min")
DEFAULT_MODE = "full"
LEAN_LIMIT = 360
# 截断时尾部保底保留的字符数——正文最末往往是最要紧的告警，只截头会把这类
# 告警连根拔掉（read_mem 结尾的「置信度低时不要据此下结论」就吃过这个亏）。
TAIL_MIN = 96
# 结构化尾块的起始标记：取最早出现的一个，从该处起整段保留。
# 【输出控制】由 outctl.inject_params 追加、【参数】由 server._param_hint_block
# 追加、【风险】/【参数别名】由 list_tools 在运行期追加。
_KEEP_MARKERS = ("\n【输出控制】", "\n【参数】", "\n【风险】", "\n【参数别名】")

# 参数提示块的分隔标记，与 server._param_hint_block 一致（现由 _KEEP_MARKERS 覆盖）。
_PARAM_SEP = "\n【参数】"

_ALIAS = {"long": "full", "orig": "full", "original": "full",
          "short": "lean", "brief": "lean",
          "tiny": "min", "none": "min", "minimal": "min"}

_state = {"mode": DEFAULT_MODE, "thinned": 0, "before": 0, "after": 0, "saved": 0}
_ARCHIVE = {}


def mode_from_env(default: str = DEFAULT_MODE) -> str:
    """从 MDKDEBUG_DESC 读档位；没设/认不出来时返回 default（认不出来会告警）。"""
    v = (os.environ.get("MDKDEBUG_DESC") or "").strip().lower()
    if not v:
        return default
    if v in MODES:
        return v
    if v in _ALIAS:
        return _ALIAS[v]
    logger.warning("MDKDEBUG_DESC=%r 认不出来，按 %s 处理（可用：%s）",
                   v, default, " / ".join(MODES))
    return default


_HEAD_SEPS = ("\n", "。", "；")


def _split_at(desc: str) -> int:
    """结构化尾块的起始下标（最早出现的标记）；没有标记返回 -1。"""
    idx = -1
    for mk in _KEEP_MARKERS:
        j = desc.find(mk)
        if j >= 0 and (idx < 0 or j < idx):
            idx = j
    return idx


def _clip(body: str, limit: int = LEAN_LIMIT) -> str:
    """把正文截到 limit 以内，保留「段首 + 段末」，只丢中间。

    只截头会丢掉正文最末的关键告警（真机上正是靠这些告警避免误判），
    所以尾部留一段；两端都优先落在段落/句子边界上。
    """
    b = (body or "").strip()
    if len(b) <= limit:
        return b
    head_budget = max(120, limit - TAIL_MIN - 24)
    cut = b[:head_budget]
    head = ""
    for sep in _HEAD_SEPS:
        i = cut.rfind(sep)
        if i >= head_budget // 2:
            head = cut[:i + len(sep)].rstrip()
            break
    if not head:
        head = cut.rstrip()
    tail_budget = max(TAIL_MIN, limit - len(head) - 8)
    tail = b[-tail_budget:]
    for sep in ("。", "\n", "；"):
        j = tail.find(sep)
        if 0 <= j <= tail_budget // 3:
            tail = tail[j + len(sep):]
            break
    tail = tail.strip()
    if not tail or tail in head:
        return head
    return head + "\n…\n" + tail


def _fallback_summary(body: str, limit: int = 170) -> str:
    """兜底的一句话摘要（调用方没给 summarizer 时用）。"""
    t = (body or "").replace("\n", " ").strip()
    for sep in ("。", "；", ". "):
        i = t.find(sep)
        if 0 <= i <= limit:
            return t[:i]
    return t if len(t) <= limit else t[:limit].rstrip() + "…"


def _pointer(name: str) -> str:
    return ('\n【完整说明】为省上下文，本工具的完整说明（边界条件、失败模式、'
            '真机上踩过的坑）已挪出：mdk_guide(topic="tool", name="%s")' % name)


def install(server, mode: str | None = None, summarizer=None) -> dict:
    """按档位改写全部工具描述，并把被挪走的正文归档。

    必须在 `_apply_param_hints`（【参数】块）之后、`toolbox.install`（快照）之前调用。
    """
    global _state
    m = mode or mode_from_env()
    tm = getattr(server, "_tool_manager", None)
    tools = getattr(tm, "_tools", None)
    if tools is None:
        _state = {"mode": m, "thinned": 0, "before": 0, "after": 0, "saved": 0}
        return {"ok": False, "mode": m,
                "error": "该 MCP SDK 版本没有 _tool_manager._tools，描述分层不可用"}

    before = sum(len(getattr(t, "description", "") or "") for t in tools.values())
    if m == "full":
        _state = {"mode": m, "thinned": 0, "before": before, "after": before, "saved": 0}
        return {"ok": True, "mode": m, "thinned": 0, "before": before,
                "after": before, "saved": 0,
                "note": "档位 full：描述不做任何改写（与历史行为一致）"}

    summ = summarizer or _fallback_summary
    thinned = 0
    for name, tool in list(tools.items()):
        desc = getattr(tool, "description", "") or ""
        i = _split_at(desc)
        body = desc[:i] if i >= 0 else desc
        tail = desc[i:] if i >= 0 else ""
        short = (summ(body) if m == "min" else _clip(body)).strip()
        if not short or len(short) >= len(body.strip()):
            continue                      # 本来就不长：不动，也不留指针
        _ARCHIVE[name] = {"full": desc, "mode": m,
                          "moved": len(body) - len(short)}
        tool.description = short + _pointer(name) + tail
        thinned += 1

    after = sum(len(getattr(t, "description", "") or "") for t in tools.values())
    _state = {"mode": m, "thinned": thinned, "before": before,
              "after": after, "saved": before - after}
    logger.info("工具描述分层：档位=%s，改写 %d 个工具，描述总体积 %d → %d 字符（省 %d，%.0f%%）",
                m, thinned, before, after, before - after,
                100.0 * (before - after) / max(1, before))
    return {"ok": True, "mode": m, "thinned": thinned, "before": before,
            "after": after, "saved": before - after}


def full_of(name: str):
    """取回某个工具被挪走的完整描述；没瘦身过返回 None。"""
    ent = _ARCHIVE.get(str(name or ""))
    return ent["full"] if ent else None


def archived() -> dict:
    """全部归档（只读快照，给 mdk_guide 列索引用）。"""
    return dict(_ARCHIVE)


def stats() -> dict:
    s = dict(_state)
    s.update({"archived": len(_ARCHIVE), "modes": list(MODES),
              "limit_lean": LEAN_LIMIT, "env": os.environ.get("MDKDEBUG_DESC", ""),
              "default_mode": DEFAULT_MODE})
    return s
