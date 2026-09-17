# -*- coding: utf-8 -*-
"""参数名别名兼容层（第 9 轮建议②）。

用户反馈原文：「list_tools 只是缓解参数名不统一（find_symbol 用 query、read_mem 用
addr/n_bytes、run_timeout 用 timeout_ms）。根子上还是建议收敛成少数几种固定名。」

做法：**不重命名主名**（改名属破坏性变更，会让已写好的调用与文档失效），而是让每个
工具额外接受一组统一别名——AI 按直觉写 `query` / `name` / `expression` / `address` /
`timeout_ms` 都能落地。`list_tools` 会在描述里列出「主名 ← 别名」，不必靠报错学习签名。

三条约束：
1. **别名不会遮蔽真实参数**：与某工具自身真实参数同名的别名会被自动剔除（在
   server 侧结合工具真实签名过滤），例如 read_mem 有真实参数 length，就不再拿
   length 当 n_bytes 的别名。
2. **主名优先**：主名与别名同时给出时只认主名，不静默改写。
3. **单位类别名做换算**：主名是毫秒的也接受秒写法（×1000），反之亦然。
"""

# 别名分组：同一语义的参数在各工具里写法很多，这里集中定义，避免逐个罗列时漏项
_LOCATE = ["query", "name", "symbol", "expression", "var", "variable",
           "target", "location", "func", "function", "pattern", "keyword"]
_ADDRESS = ["addr", "address", "symbol", "name", "expression", "location",
            "target", "pc"]
_NAMES = ["vars", "variables", "names", "exprs", "expressions", "globals",
          "watches"]
_PROJECT = ["proj", "project_path", "uvprojx", "path", "project_file"]

# 工具 → {主名: [候选别名]}
_SPEC = {
    # ---- 表达式 / 变量 ----
    "calc_expression": {"expr": _LOCATE},
    "read_variable": {"name": _LOCATE + ["arr", "varname"],
                      "count": ["n", "num", "items", "length"]},
    "read_struct": {"name": _LOCATE + ["struct", "type"],
                    "max_fields": ["max", "limit", "fields", "max_count"]},
    "watch": {"expressions": _NAMES + ["expr_list", "list"],
              "globals": _NAMES},
    "snapshot": {"globals": _NAMES, "source_context": ["context", "source", "lines"]},
    "snapshot_diff": {"globals": _NAMES},
    "diagnose": {"globals": _NAMES,
                 "disasm_count": ["disasm", "count", "code_lines"]},
    # ---- 断点 / 观察点 ----
    "set_breakpoint": {"expr": _LOCATE + _ADDRESS},
    "set_conditional_breakpoint": {"expr": _LOCATE + _ADDRESS,
                                   "condition": ["cond", "when", "if_expr"],
                                   "count": ["hits", "times", "rcount"]},
    "set_watchpoint": {"expr": _LOCATE + _ADDRESS,
                       "access": ["mode", "type", "on"],
                       "count": ["hits", "times"]},
    "clear_watchpoint": {"expr": _LOCATE + _ADDRESS,
                         "bp_id": ["id", "breakpoint_id", "bp", "wp_id"]},
    "clear_breakpoint": {"expr": _LOCATE + _ADDRESS,
                         "bp_id": ["id", "breakpoint_id", "bp"],
                         "keil_number": ["keil_id", "number", "num", "keil_no"]},
    "wait_breakpoint": {"symbol": _LOCATE + _ADDRESS,
                        "address": _ADDRESS,
                        "timeout_s": ["timeout", "seconds"],
                        "poll_ms": ["poll", "interval_ms", "poll_interval_ms"]},
    "run_to_line": {"target": _LOCATE + _ADDRESS + ["line", "file_line"]},
    "profile_function": {"func": _LOCATE + _ADDRESS,
                         "max_ms": ["timeout_ms", "max", "duration_ms", "timeout"]},
    # ---- 内存 / 外设 ----
    "read_mem": {"addr": _ADDRESS,
                 "n_bytes": ["nbytes", "bytes", "size", "count"]},
    "write_mem": {"addr": _ADDRESS,
                  "data_hex": ["data", "hex", "bytes", "value"]},
    "fill_mem": {"addr": _ADDRESS,
                 "byte": ["value", "val", "fill", "pattern", "data"],
                 "count": ["n", "length", "size", "bytes"]},
    "read_mem_multi": {"addresses": _ADDRESS + ["addrs", "addr_list", "list"],
                       "n_bytes": ["nbytes", "bytes", "size", "length"]},
    "search_mem": {"start": ["start_addr", "from", "begin", "addr", "address"],
                   "end": ["end_addr", "to", "stop", "limit_addr"],
                   "pattern_hex": ["pattern", "hex", "bytes_hex", "data_hex"],
                   "pattern_text": ["text", "pattern_str", "str", "string"],
                   "max_results": ["limit", "max", "count"],
                   "encoding": ["charset", "codec"]},
    "query_memory_map": {"addr": _ADDRESS},
    "disassemble": {"addr": _ADDRESS,
                    "count": ["n", "num", "length", "instructions"]},
    "read_peripheral": {"periph": ["peripheral", "dev", "name", "periph_name"],
                        "regs": ["registers", "reg", "reg_names"]},
    "write_peripheral": {"periph": ["peripheral", "dev", "name"],
                         "reg": ["register", "reg_name"],
                         "value": ["val", "v", "data"]},
    "list_peripherals": {},
    # ---- 会话 / 工程 / 构建 ----
    "set_symbol_file": {"path": ["axf", "file", "axf_path", "symbol_file"]},
    "set_reloc_delta": {"delta": ["reloc", "value", "offset", "reloc_delta"]},
    "find_symbol": {"query": _LOCATE,
                    "limit": ["max", "max_results", "count"],
                    "kind": ["type", "category"],
                    "reloc_delta": ["delta", "reloc"]},
    "list_tools": {"keyword": ["query", "name", "filter", "search"]},
    "read_console_output": {"clear": ["reset", "flush", "drain"]},
    "read_async_messages": {"clear": ["reset", "flush", "drain"]},
    "set_register": {"register": ["reg", "name", "r"],
                     "value": ["val", "v"]},
    "itm_trace": {"port": ["channel", "itm_port", "stimulus_port"],
                  "size": ["bytes", "n", "length", "count"]},
    "step": {"mode": ["type", "kind", "over_or_into"]},
    "reset_connection": {"reason": ["why", "message", "note"]},
    "batch": {"commands": ["cmds", "calls", "actions", "list"],
              "stop_on_error": ["abort_on_error", "stop", "fail_fast"]},
    "project_targets": {"project": _PROJECT},
    "set_debug_target": {"target": ["name", "target_name", "cfg"]},
    "read_project_config": {"project": _PROJECT,
                            "target": ["target_name", "cfg", "name"]},
    "build_project": {"project": _PROJECT, "target": ["target_name", "cfg", "name"],
                      "timeout_s": ["timeout", "seconds"],
                      "ensure_debug_channel": ["ensure_debug", "keep_channel"]},
    "rebuild_project": {"project": _PROJECT, "target": ["target_name", "cfg", "name"],
                        "timeout_s": ["timeout", "seconds"],
                        "ensure_debug_channel": ["ensure_debug", "keep_channel"]},
    "flash_download": {"project": _PROJECT, "target": ["target_name", "cfg", "name"],
                       "timeout_s": ["timeout", "seconds"],
                       "ensure_debug_channel": ["ensure_debug", "keep_channel"]},
    "build_and_flash": {"project": _PROJECT, "target": ["target_name", "cfg", "name"],
                        "timeout_s": ["timeout", "seconds"],
                        "ensure_debug_channel": ["ensure_debug", "keep_channel"]},
    "flash_debug": {"project": _PROJECT, "target": ["target_name", "cfg", "name"]},
    "launch_uvision": {"project": _PROJECT},
    "restart_keil": {"project": _PROJECT,
                     "force": ["kill", "hard"],
                     "wait_ready": ["wait", "wait_uvsock"]},
    "close_uvision": {"force": ["kill", "hard"], "project": _PROJECT,
                      "keep": ["retain", "keep_one", "keeponly"]},
    "list_uvision_instances": {"project": _PROJECT},
    "list_uvoptx_breakpoints": {"project": _PROJECT},
    "clear_uvoptx_breakpoints": {"project": _PROJECT,
                                 "backup": ["save_backup", "keep_backup"]},
    "clear_all_breakpoints": {"include_uvoptx": ["uvoptx", "with_uvoptx"],
                              "hard": ["force", "hard_clear"]},
    "clear_all_watchpoints": {"hard": ["force", "hard_clear"]},
    "run_timeout": {"timeout_ms": ["timeout", "ms", "duration_ms", "max_ms"]},
    "wait_fault": {"timeout_ms": ["timeout", "ms", "wait_ms"]},
    "profile_sampling": {"duration_ms": ["timeout_ms", "timeout", "duration_s"],
                         "interval_ms": ["interval", "period_ms", "interval_s"],
                         "max_samples": ["max", "samples", "limit", "count"]},
    "parse_build_errors": {"errors_text": ["text", "log", "output", "errors",
                                           "build_log"]},
}

# 时间参数的等价族。同族内「任意前缀 × 任意写法」都指向该工具的主时间名：
#   族 A（超时族）timeout / duration / max / wait —— 互相等价；
#   族 B（间隔族）poll / interval —— 只在主名本身就是间隔参数时互相等价。
# 刻意不把族 B 并入族 A：把「采样/轮询间隔」映射成「超时」会静默改变行为，宁可报错。
#
# 单位后缀是最强的语义线索：带 _s 的一律按秒解释、带 _ms 的一律按毫秒解释，
# 与主名单位无关（timeout_ms 的工具收到 timeout_s=2 就按 2000 ms 用）。
# 不带后缀（如 timeout=5）只能按主名单位解释 —— 所以 list_tools 必须把主名单位
# 标出来，否则 AI 会以为 timeout=5 是 5 秒。
_TIMEOUT_FAMILY = ("timeout", "duration", "max", "wait")
_INTERVAL_FAMILY = ("poll", "interval")
_TIME_UNIT_SUFFIXES = ("", "_ms", "_s")

def _time_family_of(name: str):
    """名字属于哪个时间族；不是时间参数则返回 None。"""
    if not name:
        return None
    for family in (_TIMEOUT_FAMILY, _INTERVAL_FAMILY):
        for prefix in family:
            if name == prefix or name in (prefix + "_ms", prefix + "_s"):
                return family
    return None

def _unit_suffix(name: str) -> str:
    """取名字的单位后缀（"_ms" / "_s" / ""）。"""
    if name.endswith("_ms"):
        return "_ms"
    if name.endswith("_s"):
        return "_s"
    return ""


def _build():
    """把 _SPEC 展开成 {工具: {别名: 主名}}，并补上时间单位别名。"""
    table = {}
    for tool, primaries in _SPEC.items():
        amap = {}
        for primary, cands in primaries.items():
            for c in cands:
                if c and c != primary:
                    amap.setdefault(c, primary)
        # 时间参数：同族前缀 × 全部写法（无后缀 / _ms / _s）互为别名。
        # 第 9 轮反馈说「别名层只做了一半，AI 会在时间单位上撞墙」——原来只给
        # 主名换算同名的另一种单位（timeout_ms↔timeout_s），换个前缀就撞墙，
        # 例如 run_timeout 收下 duration_ms 却不认 duration_s。这里按族展开成笛卡尔积。
        for primary in primaries:
            family = _time_family_of(primary)
            if not family:
                continue
            for prefix in family:
                for suffix in _TIME_UNIT_SUFFIXES:
                    alias = prefix + suffix
                    if alias != primary:
                        amap.setdefault(alias, primary)
        if amap:
            table[tool] = amap
    return table


TOOL_ALIASES = _build()


def aliases_of(tool: str) -> dict:
    """返回该工具的 {别名: 主名} 副本（未定义别名时为空 dict）。"""
    return dict(TOOL_ALIASES.get(tool) or {})


def is_time_pair(primary: str, alias: str) -> int:
    """主名/别名是否构成时间单位换算：返回 1000（秒→毫秒）、-1（毫秒→秒）或 0。

    以**别名自带的后缀**为准（这是调用方的真实意图），而不是主名的单位：
    别名写 _s 而主名是 _ms 就 ×1000，反之 ÷1000；别名不带后缀则不换算（按主名单位）。
    """
    fam = _time_family_of(primary)
    if not fam or _time_family_of(alias) is not fam:
        return 0        # 非时间参数，或跨族（poll_ms ← timeout_s）→ 不换算
    p_suf, a_suf = _unit_suffix(primary), _unit_suffix(alias)
    if a_suf and p_suf and a_suf != p_suf:
        return 1000 if a_suf == "_s" else -1
    return 0


def convert_time(primary: str, alias: str, value):
    """按单位换算时间值；非数值原样返回（交给下游报错，不在这里静默吞掉）。"""
    factor = is_time_pair(primary, alias)
    if not factor:
        return value
    try:
        if factor == 1000:
            return int(round(float(value) * 1000))
        return float(value) / 1000.0
    except (TypeError, ValueError):
        return value


def alias_note(tool: str, allowed=None) -> str:
    """生成「主名 ← 别名」说明文本（用于 list_tools 展示）。

    allowed 为该工具真实参数名集合：与其冲突的别名不展示（也不会生效）。
    """
    amap = aliases_of(tool)
    if not amap:
        return ""
    rev = {}
    for alias, primary in amap.items():
        if allowed is not None and alias in allowed:
            continue
        rev.setdefault(primary, []).append(alias)
    if not rev:
        return ""
    parts = []
    converts = False
    for primary, aliases in rev.items():
        unit = ""
        if primary.endswith("_ms"):
            unit = "（毫秒）"
        elif primary.endswith("_s"):
            unit = "（秒）"
        p_suf = _unit_suffix(primary)
        for a in aliases:
            a_suf = _unit_suffix(a)
            if a_suf and a_suf != p_suf:
                converts = True
        parts.append("%s%s ← %s" % (primary, unit, "/".join(sorted(aliases))))
    note = "；".join(parts)
    if converts:
        note += "；带 _s/_ms 的别名按后缀换算（_s=秒、_ms=毫秒）"
    return note
