# -*- coding: utf-8 -*-
"""高输出工具的输出控制：compact / max_lines / full 三件套（批次34）。

为什么需要
----------
本服务有 99 个工具，其中一批工具的返回体天然是「列表 + 长文本说明」：
`list_tools`（99 条，每条带 usage/aliases/example_args）、`capabilities`、
`read_mem`/`read_mem_multi`/`search_mem`（按字节/条目）、`snapshot`、`batch`、
`list_peripherals`/`read_peripheral`、`parse_map`、`list_breakpoints`、
`profile_sampling`、`serial_read`……在长链路调试里，这些返回会迅速吃掉上下文预算，
而调用方往往只需要其中几条。

显式约定
--------
每个受控工具都额外接受三个**可选**参数（默认不传＝行为与以前完全一致）：

- ``max_lines=N``  只作用于「元素为对象的列表」：最多返回 N 条，其余丢弃并**如实上报**；
- ``compact=true`` 去掉空值字段、把列表元素里**取值完全相同**的字段提到 ``output.shared``
  一次、把「说明类」长字符串（usage/note/detail/hints 之流）截断到 200 字符；
- ``full=true``    强制不裁剪（覆盖环境变量默认与 max_lines），用于「我就是要全量」。

也可以用环境变量给全局默认：``MDKDEBUG_COMPACT=1``、``MDKDEBUG_MAX_LINES=200``——
客户端不方便逐次传参时用。

两条底线（宁可报错，不给「看似权威的错答案」）
----------------------------------------------
1. **裁了就报**：只要扔掉过任何东西，信封里必有 ``output.truncated=true``、
   ``output.dropped``、以及 ``output.hint`` 说明怎么取回全量。绝不静默丢数据后
   让调用方以为「这就是全部」。
2. **不碰真值**：只删「空值字段」「重复字段」「说明性长文本」，绝不修改任何数值、
   绝不截断 line/text/value/bytes/data 这类**内容字段**；列表元素本身也不会被改写。

第三件事：编译/烧录日志的摘录（批次48）
--------------------------------------
``flash_debug`` / ``build_*`` 这类工具的返回体里塞着 UV4 的**全量日志**（几万字），
而调用方要的结论只有几行（用户原话：「全量 build 输出几万字，关键结论 5 行」）。
故这组工具**默认**就把日志字段摘成「头 N 行 + 尾 M 行」，并把 error/warning/体积/耗时
这类关键行抽到 ``output.log_key_lines``；要全量传 ``full=true``。

这是本文件里**唯一**一处「默认行为与以前不同」的地方——默认不精简就等于没修这个硬伤，
故如实在此声明，并且摘录幅度与 ``log_truncated`` / ``log_total_chars`` /
``log_kept_chars`` / ``log_key_lines`` / ``log_full_hint`` 一并写进返回体，绝不静默丢数据。
"""
from __future__ import annotations

import json
import logging
import os
import re

logger = logging.getLogger("mdkdebug.outctl")

#: 受控工具（返回体容易过大、且都是「列表 + 说明」结构）
HIGH_OUTPUT = {
    "list_tools", "capabilities", "mdk_guide",
    "snapshot", "snapshot_diff", "read_mem", "read_mem_multi", "search_mem",
    "read_registers", "read_struct", "read_locals", "read_peripheral",
    "list_peripherals", "query_memory_map", "parse_map", "parse_build_errors",
    "list_breakpoints", "list_watchpoints", "list_uvoptx_breakpoints",
    "breakpoint_stats", "batch", "watch", "diagnose", "fault_report",
    "profile_function", "profile_sampling", "disassemble", "itm_trace", "dwt",
    "serial_read", "serial_monitor_status", "uvprojx_read", "project_targets",
    "svd_list", "list_symbol_projects",
    "session_state",
    # 编译/烧录系列（批次48）：返回体里塞着 UV4 全量日志，属典型高输出工具
    "flash_debug", "build_project", "rebuild_project", "clean_project",
    "flash_download", "build_and_flash",
    # 代码结构索引（批次68）：code_node 直接搬源码体、code_query/code_files 给
    # 长清单、code_index 带 skipped_list——都给 compact/max_lines/full 三件套。
    "code_index", "code_files", "code_query", "code_node",
    # 批次69：关系/影响面会列出大量边（每条带候选清单），同属高输出。
    "code_relations", "code_impact",
}

#: 日志类工具（批次48）：**默认**摘录日志字段（唯一改变默认行为的地方，理由见模块 docstring）
LOG_TOOLS = {
    "flash_debug", "build_project", "rebuild_project", "clean_project",
    "flash_download", "build_and_flash",
}

#: 会被摘录的日志字段名（按字段名小写匹配，任意层级）
LOG_KEYS = {"output", "log", "stdout", "stderr", "build_log", "raw_output"}

#: 摘录参数：超过 LOG_TRIGGER_CHARS 才动手；保留头 LOG_HEAD_LINES / 尾 LOG_TAIL_LINES 行；
#: 最终不超 LOG_KEEP_CHARS 字符
LOG_HEAD_LINES = 40
LOG_TAIL_LINES = 25
LOG_TRIGGER_CHARS = 3000
LOG_KEEP_CHARS = 6000

#: 从日志里抽「关键行」：编译错误/警告 + 体积/耗时汇总
_LOG_KEY_RE = re.compile(
    r"(build target|program size|error\(s\)|warning\(s\)|build time|"
    r"error\s*[#:]|warning\s*[#:]|\berror\b|\bwarning\b)", re.I)

#: 三个控制参数的名字（顺序即文档顺序）
OUT_PARAMS = ("compact", "max_lines", "full")

#: 「说明类」字段：compact 下允许截断的长文本（内容字段一律不动）
_META_TEXT_KEYS = {
    "usage", "description", "desc", "note", "notes", "detail", "hints", "hint",
    "recommended", "help", "title", "why", "advice", "tip", "tips", "warning",
    "warnings", "summary", "doc", "comment", "remarks",
}

#: 这些键下的列表**永远不裁剪**（它们是调用说明/诊断结论，不是数据）
_KEEP_FULL_KEYS = {
    "required", "optional", "aliases", "example_args", "next_actions",
    "error", "errors", "hints", "recommended", "tools_available", "groups",
}

#: compact 下长「说明类」文本的截断长度（按字符）
TEXT_LIMIT = 200

_PARAM_SCHEMAS = {
    "compact": {
        "type": "boolean",
        "description": (
            "精简返回体：去掉空值字段，把列表元素中取值完全相同的字段提到 output.shared，"
            "并把 usage/note/hints 之类**说明性**长文本截断到 200 字符（数值与内容字段不动）。"
            "被裁掉的东西都会列在 output 里，绝不静默丢弃。不传则不改行为（受 MDKDEBUG_COMPACT 影响）。"),
    },
    "max_lines": {
        "type": "integer",
        "description": (
            "限制返回的列表条数（只作用于元素为对象的列表，如 results/items/tools）："
            "最多 N 条，其余丢弃并在 output.truncated/dropped/hint 里如实上报。"
            "0 或省略＝不限（受 MDKDEBUG_MAX_LINES 影响）。"),
    },
    "full": {
        "type": "boolean",
        "description": (
            "强制返回全量：忽略 compact/max_lines 与对应环境变量的默认值。"
            "当上面两项让你只看到部分数据、而你要据此下结论时，用它取回完整结果。"),
    },
}


def split_args(args):
    """从工具参数里摘出输出控制参数，返回 (其余参数, 控制参数字典)。"""
    rest = dict(args or {})
    got = {}
    for k in OUT_PARAMS:
        if k in rest:
            got[k] = rest.pop(k)
    return rest, got


def env_defaults():
    """环境变量给的全局默认：MDKDEBUG_COMPACT / MDKDEBUG_MAX_LINES。"""
    out = {"compact": None, "max_lines": None}
    raw = (os.environ.get("MDKDEBUG_COMPACT") or "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        out["compact"] = True
    elif raw in ("0", "false", "no", "off"):
        out["compact"] = False
    raw = (os.environ.get("MDKDEBUG_MAX_LINES") or "").strip()
    if raw:
        try:
            n = int(raw)
            out["max_lines"] = n if n > 0 else None
        except ValueError:
            logger.warning("MDKDEBUG_MAX_LINES 不是整数（%s），已忽略", raw)
    return out


def resolve(compact=None, max_lines=None, full=False):
    """合并「显式参数 → 环境变量默认」，返回 (compact, max_lines, full, active)。

    full=True 时 active=False（不裁剪语义），其余参数忽略。
    """
    env = env_defaults()
    if full:
        return False, 0, True, False
    c = env["compact"] if compact is None else bool(compact)
    try:
        m = int(max_lines or 0)
    except (TypeError, ValueError):
        m = 0
    if m <= 0:
        m = int(env["max_lines"] or 0)
    active = bool(c) or m > 0
    return bool(c), max(0, m), False, active


def _is_empty(v):
    return v is None or v == "" or v == [] or v == {}


def _strip_empty(obj):
    """递归去掉空值字段（None/""/[]/{}），返回 (新对象, 删掉的字段路径列表)。"""
    removed = []

    def walk(node, path):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                p = "%s.%s" % (path, k) if path else str(k)
                nv = walk(v, p)
                if _is_empty(nv):
                    removed.append(p)
                    continue
                out[k] = nv
            return out
        if isinstance(node, list):
            return [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(node)]
        return node

    return walk(obj, ""), removed


def _hoist_shared(obj, min_len=3):
    """把列表元素里**取值完全相同**的字段提到 output.shared（元素中删除）。

    只对元素为对象、长度 >= min_len 的列表做；返回 (新对象, shared 字典)。
    """
    shared = {}

    def walk(node, path):
        if isinstance(node, dict):
            return {k: walk(v, "%s.%s" % (path, k) if path else str(k))
                    for k, v in node.items()}
        if isinstance(node, list):
            items = [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(node)]
            if len(items) >= min_len and all(isinstance(x, dict) for x in items):
                common = set(items[0].keys())
                for x in items[1:]:
                    common &= set(x.keys())
                pairs = {}
                for k in sorted(common):
                    vals = [x[k] for x in items]
                    try:
                        same = all(v == vals[0] for v in vals[1:])
                    except Exception:  # noqa: BLE001
                        same = False
                    if same:
                        pairs[k] = vals[0]
                if pairs and len(pairs) < len(items[0]):   # 全同就不动（提升没收益且更绕）
                    shared[path or "$"] = pairs
                    items = [{k: v for k, v in x.items() if k not in pairs} for x in items]
            return items
        return node

    return walk(obj, ""), shared


def _trim_text(obj, limit=TEXT_LIMIT):
    """截断「说明类」长文本字段；内容字段不动。返回 (新对象, 被截断项列表)。"""
    cut = []

    def walk(node, path):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                p = "%s.%s" % (path, k) if path else str(k)
                if isinstance(v, str) and k.lower() in _META_TEXT_KEYS and len(v) > limit:
                    cut.append({"path": p, "original_length": len(v)})
                    out[k] = v[:limit].rstrip() + "…"
                else:
                    out[k] = walk(v, p)
            return out
        if isinstance(node, list):
            return [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(node)]
        return node

    return walk(obj, ""), cut


def _trim_lists(obj, max_lines):
    """把「元素为对象的列表」截断到 max_lines 条；返回 (新对象, 裁剪记录)。"""
    trimmed = []

    def walk(node, path):
        if isinstance(node, dict):
            return {k: walk(v, "%s.%s" % (path, k) if path else str(k))
                    for k, v in node.items()}
        if isinstance(node, list):
            items = [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(node)]
            container = path.split(".")[-1].split("[")[0]
            if (len(items) > max_lines and all(isinstance(x, dict) for x in items)
                    and container not in _KEEP_FULL_KEYS):
                trimmed.append({"path": path, "total": len(items), "returned": max_lines})
                return items[:max_lines]
            return items
        return node

    return walk(obj, ""), trimmed


def _key_lines(text, limit=10):
    """从日志里挑出「关键行」（错误/警告/体积/耗时），给调用方省掉翻几万字。"""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or len(s) > 300:
            continue
        if _LOG_KEY_RE.search(s):
            out.append(s)
            if len(out) >= limit:
                break
    return out

def _excerpt_text(text, head=LOG_HEAD_LINES, tail=LOG_TAIL_LINES):
    """头 head 行 + 尾 tail 行 + 省略说明；必要时再按字符上限硬截。"""
    lines = text.splitlines()
    if len(lines) > head + tail:
        omitted = len(lines) - head - tail
        kept = ("\n".join(lines[:head])
                + "\n… [mdkdebug 已摘录日志：共 %d 行 / %d 字符，省略中间 %d 行；"
                  "要全量请传 full=true] …\n" % (len(lines), len(text), omitted)
                + "\n".join(lines[-tail:]))
    else:
        kept = text
    if len(kept) > LOG_KEEP_CHARS:
        kept = (kept[:LOG_KEEP_CHARS]
                + "\n… [mdkdebug 已按字符上限截断：原文共 %d 字符；要全量请传 full=true]"
                  % len(text))
    return kept

def _excerpt_logs(obj, head=LOG_HEAD_LINES, tail=LOG_TAIL_LINES):
    """把日志字段摘成「头+尾」，并把关键行抽出来。

    返回 ``(新对象, 摘录记录列表, 关键行列表)``。**非日志字段一律不动**——
    这是「不碰真值」底线的延伸：我们只动明确叫 output/log/stdout/stderr 的长字符串。
    """
    recs = []
    keys = []

    def walk(node, path):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                p = "%s.%s" % (path, k) if path else str(k)
                if (isinstance(v, str) and k.lower() in LOG_KEYS
                        and len(v) > LOG_TRIGGER_CHARS):
                    kept = _excerpt_text(v, head, tail)
                    out[k] = kept
                    recs.append({"path": p, "total_chars": len(v),
                                 "kept_chars": len(kept),
                                 "total_lines": len(v.splitlines())})
                    for ln in _key_lines(v):
                        if ln not in keys:
                            keys.append(ln)
                else:
                    out[k] = walk(v, p)
            return out
        if isinstance(node, list):
            return [walk(v, "%s[%d]" % (path, i)) for i, v in enumerate(node)]
        return node

    return walk(obj, ""), recs, keys

def apply(tool, payload, compact=None, max_lines=None, full=False):
    """对已解析的结果对象做输出控制。

    返回 ``(新 payload, meta 或 None)``；**没有任何控制生效时 meta 为 None**，
    调用方据此保持「默认行为完全不变」。payload 非 dict 时原样返回。
    """
    if not isinstance(payload, dict):
        return payload, None
    c, m, f, active = resolve(compact=compact, max_lines=max_lines, full=full)
    # 日志类工具默认摘录（full=true 时不摘，即「我要全量」）；其余工具行为完全不变
    log_mode = (tool in LOG_TOOLS) and not f
    if not active and not log_mode:
        return payload, None

    out = payload
    mode = "+".join([x for x in (("compact" if c else ""), ("max_lines" if m > 0 else "")) if x])
    if log_mode:
        mode = (mode + "+log") if mode else "log"
    meta = {"mode": mode, "tool": tool, "truncated": False, "dropped": 0}
    if log_mode:
        out, log_recs, log_keys = _excerpt_logs(out)
        if log_recs:
            meta["log_excerpted"] = log_recs
            meta["log_truncated"] = True
            meta["log_total_chars"] = sum(r["total_chars"] for r in log_recs)
            meta["log_kept_chars"] = sum(r["kept_chars"] for r in log_recs)
            meta["log_full_hint"] = ("日志已摘录（头 %d 行 + 尾 %d 行）："
                                     "要全量请传 full=true" % (LOG_HEAD_LINES, LOG_TAIL_LINES))
            if log_keys:
                meta["log_key_lines"] = log_keys[:10]
            meta["log_note"] = ("注意 log_key_lines 只是从日志里挑出的**关键行**，"
                                "不是完整结论；下结论前若需上下文请 full=true 取全量")
            meta["truncated"] = True
    # 日志没长到需要摘、又没有别的控制生效时，一个字段都不加——
    # 「默认行为完全不变」对短日志同样成立（日志类工具只在**真的摘了**的时候才发声）。
    if not active and not meta.get("log_excerpted"):
        return payload, None
    if c:
        out, removed = _strip_empty(out)
        out, shared = _hoist_shared(out)
        out, texts = _trim_text(out)
        if removed:
            meta["empty_fields_removed"] = len(removed)
        if shared:
            meta["shared"] = shared
        if texts:
            meta["text_truncated"] = texts
            meta["truncated"] = True
    if m > 0:
        out, trimmed = _trim_lists(out, m)
        if trimmed:
            meta["trimmed"] = trimmed
            meta["dropped"] = sum(t["total"] - t["returned"] for t in trimmed)
            meta["truncated"] = True
    hints = []
    if meta["truncated"]:
        if meta.get("trimmed"):
            hints.append("列表被 max_lines=%d 截断（见 output.trimmed）：要全量请 full=true（或 max_lines=0）；"
                         "返回体里原有的 count/total 等计数字段仍是**全量**数字，未按 max_lines 改写"
                         % m)
        if meta.get("text_truncated"):
            hints.append("部分说明性长文本被截断到 %d 字符（见 output.text_truncated，不涉及数值/内容字段）："
                         "要原文请 full=true" % TEXT_LIMIT)
        if meta.get("log_excerpted"):
            hints.append("编译/烧录日志已摘录为头 %d 行 + 尾 %d 行（共 %d 字符 -> %d 字符，"
                         "关键行见 log_key_lines）：要全量请 full=true"
                         % (LOG_HEAD_LINES, LOG_TAIL_LINES, meta["log_total_chars"],
                            meta["log_kept_chars"]))
    elif c:
        hints.append("本次仅做精简（去空值/提公共字段），未丢弃任何条目")
    elif meta.get("log_excerpted"):
        hints.append("编译/烧录日志已摘录为头 %d 行 + 尾 %d 行（共 %d 字符 -> %d 字符，"
                     "关键行见 log_key_lines）：要全量请 full=true"
                     % (LOG_HEAD_LINES, LOG_TAIL_LINES, meta["log_total_chars"],
                        meta["log_kept_chars"]))
    if hints:
        meta["hint"] = "；".join(hints)
    out = dict(out)
    # 编译类工具本身就有 output（UV4 日志）字段，不能再被 meta 顶掉
    meta_key = "output" if "output" not in out else "output_control"
    meta["meta_key"] = meta_key
    out[meta_key] = meta
    return out, meta


def apply_to_result(result, tool, params):
    """把输出控制作用到 MCP 的 CallToolResult 上（就地改 text 与 structured_content）。"""
    content = getattr(result, "content", None)
    if not content:
        return result
    item = content[0]
    text = getattr(item, "text", None)
    if not isinstance(text, str) or not text.lstrip().startswith(("{", "[")):
        return result
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return result
    new, meta = apply(tool, obj, compact=params.get("compact"),
                      max_lines=params.get("max_lines"), full=params.get("full"))
    if meta is None or new == obj:
        return result
    new_text = json.dumps(new, ensure_ascii=False, default=str)
    try:
        item.text = new_text
    except Exception:  # noqa: BLE001
        try:
            content[0] = type(item)(type="text", text=new_text)
        except Exception as e:  # noqa: BLE001
            logger.debug("输出控制回写失败（%s）：%s", tool, e)
            return result
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        for k, v in list(sc.items()):
            if isinstance(v, str) and v.strip() == text.strip():
                sc[k] = new_text
    return result


def inject_params(server, names=None) -> int:
    """给受控工具的 schema 追加 compact/max_lines/full（幂等），返回改动数。"""
    tm = getattr(server, "_tool_manager", None)
    tools = getattr(tm, "_tools", None)
    if not tools:
        return 0
    want = HIGH_OUTPUT if names is None else set(names)
    n = 0
    for nm, info in tools.items():
        if nm not in want:
            continue
        params = getattr(info, "parameters", None)
        if not isinstance(params, dict):
            continue
        props = params.setdefault("properties", {})
        if not isinstance(props, dict):
            continue
        added = []
        for k in OUT_PARAMS:
            if k not in props:
                props[k] = dict(_PARAM_SCHEMAS[k])
                added.append(k)
        if added:
            n += 1
        desc = getattr(info, "description", "") or ""
        if "\n【输出控制】" not in desc:
            try:
                info.description = desc + (
                    "\n【输出控制】本工具返回体可能较大，额外接受三个可选参数："
                    "compact=true（精简）/ max_lines=N（限制列表条数）/ full=true（强制全量）。"
                    "默认都不传＝行为不变；被裁掉的内容一定会在返回体的 output 字段里如实上报"
                    "（truncated/dropped/trimmed/hint），不会静默丢数据。"
                    "也可用环境变量 MDKDEBUG_COMPACT=1 / MDKDEBUG_MAX_LINES=N 设全局默认。")
            except Exception:  # noqa: BLE001
                logger.debug("写入输出控制说明失败：%s", nm, exc_info=True)
    if n:
        logger.info("已为 %d 个高输出工具补充 compact/max_lines/full 参数", n)
    return n


def summary() -> dict:
    """给 capabilities 用的现状摘要。"""
    env = env_defaults()
    return {
        "controlled_tools": len(HIGH_OUTPUT),
        "log_tools": sorted(LOG_TOOLS),
        "log_excerpt": {"head_lines": LOG_HEAD_LINES, "tail_lines": LOG_TAIL_LINES,
                        "trigger_chars": LOG_TRIGGER_CHARS, "keep_chars": LOG_KEEP_CHARS,
                        "note": "这类工具默认摘录日志（用户反馈「关键结论 5 行、日志几万字」），"
                                "full=true 取全量；摘录情况会在 output.log_* 字段如实上报。"},
        "params": list(OUT_PARAMS),
        "text_limit": TEXT_LIMIT,
        "env": {"MDKDEBUG_COMPACT": os.environ.get("MDKDEBUG_COMPACT", ""),
                "MDKDEBUG_MAX_LINES": os.environ.get("MDKDEBUG_MAX_LINES", "")},
        "env_defaults": env,
        "note": "默认不传参数时行为与以前完全一致；裁剪结果会在返回体 output 字段如实上报。",
    }
