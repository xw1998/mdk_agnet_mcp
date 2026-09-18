# -*- coding: utf-8 -*-
"""工具面按需加载：分组、默认精简、运行期装卸。

背景
----
工具数到了 154 个，每个工具的 description 都要进上下文。上层场景往往是
「这次只做串口抓日志」「这次只编译烧录」，用不到其余工具，却要为全部描述
付冷启动成本——对小模型的注意力尤其不友好。

此前已有 `MDKDEBUG_TOOLSETS` 分组裁剪，但**默认全开**，等于没帮到默认用户。
这里把默认改成精简，并补上运行期的按需装卸。

设计原则（防翻车）
------------------
1. **默认精简**：不设 `MDKDEBUG_TOOLSETS` 时只暴露 `core` 组 + 引导工具；
   要用别的组，调 `toolset(action="load", toolsets="mem,trace")` 装回来。
2. **显式设了但认不出来 → 不裁剪（全开）+ 告警**：宁可少裁不错杀。
   一个手滑的组名不该静默缩减用户的工具面（那会让人以为"配置生效了"）。
3. **`list_tools` / `get_version` / `capabilities` / `toolset` 永远保留**：
   否则 AI 连「现在有哪些工具、怎么装回来」都问不出来，会陷入瞎试。
4. **未归类的工具一律保留**，只裁「明确归到别的组」的工具。
5. 装卸都按原始注册顺序重排，并对调用方明说「客户端可能缓存了工具列表」。

实现说明：本模块直接操作 `MCPServer._tool_manager._tools`。SDK 是 mcp 2.x，
`Tool` 是 pydantic 模型且 `_handle_list_tools` 每次实时读该表，所以
「把 Tool 对象原样存起来 / 原样放回去」是无损的（连 schema、注解、
批次34 注入的输出控制参数一起保留），比 remove 再用 `add_tool` 重建更可靠——
重建会丢掉 `structured_output` 等无法从函数签名反推的元数据。
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("mdkdebug")

# ----------------------------------------------------------------------
# 工具集分组。**每个工具最多归一组**；没有归组的工具永远是「常驻」。
# 组名即 `MDKDEBUG_TOOLSETS` / `toolset(toolsets=...)` 里用的名字。
# ----------------------------------------------------------------------
TOOLSETS = {
    "core": {
        "enter_debug", "exit_debug", "get_status", "run", "stop", "step", "reset",
        "run_timeout", "reset_connection", "wait_state", "wait_breakpoint",
        "set_breakpoint", "clear_breakpoint", "clear_all_breakpoints", "list_breakpoints",
        "read_mem", "write_mem", "calc_expression", "read_variable",
        "keil_command", "batch_debug_script", "keil_health", "diagnose",
        "restart_keil", "launch_uvision", "close_uvision", "list_uvision_instances",
        "read_console_output", "read_async_messages", "dismiss_dialog",
        "mdk_guide", "target_info", "session_state",
    },
    "mem": {
        "read_mem_multi", "fill_mem", "search_mem", "snapshot", "snapshot_diff",
        "read_struct", "read_locals", "read_registers", "set_register", "cache_info",
    },
    "symbol": {
        "set_symbol_file", "list_symbol_projects", "find_symbol", "address_for_line",
        "get_current_location", "run_to_line", "disassemble", "parse_map",
    },
    "build": {
        "build_project", "rebuild_project", "clean_project", "flash_download",
        "build_and_flash", "flash_debug", "parse_build_errors", "explain_build_error",
        "uvprojx_read", "uvprojx_edit", "project_targets", "set_debug_target",
        "read_project_config",
    },
    "serial": {
        "serial_list_ports", "serial_monitor_start", "serial_monitor_status",
        "serial_monitor_stop", "serial_read", "serial_write", "serial_expect",
        # Modbus 主站（批次44）：规范功能码 + 裸帧/旁听。放在串口组里，
        # 因为「这次调串口」的场景里日志与 Modbus 往往同时要用。
        "modbus_read", "modbus_write", "modbus_raw", "modbus_decode",
        "modbus_scan", "modbus_sniff", "modbus_session",
    },
    "advanced": {
        "clear_faults", "fault_report", "wait_fault", "watch_reset", "dwt",
        "profile_function",
        "profile_sampling", "itm_trace", "list_peripherals", "read_peripheral",
        "write_peripheral", "query_memory_map", "svd_list", "svd_decode",
        "watchdog_freeze", "watch", "set_watchpoint", "clear_watchpoint",
        "clear_all_watchpoints", "list_watchpoints", "breakpoint_stats",
        "set_conditional_breakpoint", "clear_uvoptx_breakpoints",
        "list_uvoptx_breakpoints", "batch", "set_reloc_delta",
    },
    # ---- 非 MDK 能力族（批次36）----
    # 这四个组的存在意义：调 RISC-V / ESP32 这类不用 Keil 的目标时，
    # toolset(toolsets="toolchain,target,ocd,trace") 即可把上下文压到只剩
    # 这一条链路，不必让近百个 Keil 工具的描述挤占窗口。
    "toolchain": {
        "toolchain_list", "toolchain_env", "toolchain_run",
        "toolchain_detect_project", "toolchain_build", "toolchain_compile",
        "toolchain_elf_info", "toolchain_size", "toolchain_objcopy",
        "toolchain_errors",
    },
    "target": {
        "target_list", "target_show", "target_guess", "debug_config",
    },
    "ocd": {
        "ocd_start", "ocd_stop", "ocd_status", "ocd_cmd", "ocd_cfg_list",
        "ocd_probe", "ocd_control", "ocd_read_mem", "ocd_write_mem", "ocd_reg",
        "ocd_bp", "ocd_wp", "ocd_flash", "ocd_flash_info", "ocd_load",
        "ocd_gdb", "ocd_log",
    },
    "trace": {
        "trace_guide", "trace_status", "trace_swo_start", "trace_swo_read",
        "trace_swo_stop", "trace_decode", "trace_events", "trace_clear",
        "trace_rtt_find", "trace_rtt_attach", "trace_rtt_read", "trace_rtt_write",
        "trace_rtt_detach", "trace_profile", "trace_dwt_counters",
        "trace_instrument", "trace_scope_start", "trace_scope_read",
        "trace_scope_stop", "trace_pcsample",
    },
    # RTOS 任务感知：跨两条链路（Keil / OpenOCD），所以单独成组。
    "rtos": {
        "rtos_info", "rtos_tasks", "rtos_objects",
    },
}

# 永远保留：这四个是「问工具面」的入口，裁掉它们 AI 会陷入瞎试。
ALWAYS = {"list_tools", "get_version", "capabilities", "toolset"}

# 默认（不设 MDKDEBUG_TOOLSETS 时）暴露的组：调试核心 + 环境引导。
DEFAULT_GROUPS = ("core",)

# 全开的写法（向后兼容旧行为）。
FULL_ALIASES = ("all", "full", "*")

# 组的一句话用途，给 status/工具描述用。
GROUP_NOTES = {
    "core": "调试核心：进/出调试、运行控制、断点、内存读写、Keil 健康、环境引导",
    "mem": "内存进阶：批量读、搜索、填充、快照对比、结构体/局部变量/寄存器",
    "symbol": "符号与反汇编：查符号、行号定位、断点位置、反汇编、map 解析",
    "build": "编译烧录：build/rebuild/clean、下载、工程(.uvprojx)读写、多目标",
    "serial": "串口：列端口、启停监视、读日志、写命令、等应答、Modbus 主站（RTU/ASCII + 裸帧旁听）",
    "advanced": "进阶：异常现场、watch、数据断点、SVD 外设、批量脚本、DWT",
    "toolchain": "非 MDK 构建：gcc/make/cmake 工具链探测、编译、ELF 分析",
    "target": "目标档案：RISC-V/ESP32 等目标型号、调试配置推断",
    "ocd": "OpenOCD：启停、命令直通、内存/寄存器/断点/烧录、GDB server",
    "trace": "trace：SWO/ITM、RTT、变量时间线、DWT 计数、PC 采样、插桩",
    "rtos": "RTOS 任务感知：任务列表/状态、栈水位、队列信号量对象",
}


def assigned_names() -> set:
    out = set()
    for names in TOOLSETS.values():
        out |= set(names)
    return out


def env_raw() -> str:
    return (os.environ.get("MDKDEBUG_TOOLSETS") or "").strip()


def parse_groups(spec) -> tuple:
    """把 "mem, trace" 解析成 (known, unknown)。组名大小写不敏感。"""
    toks = [t.lower() for t in
            str(spec or "").replace(",", " ").replace(";", " ").split()]
    known = [t for t in toks if t in TOOLSETS]
    unknown = sorted({t for t in toks if t not in TOOLSETS})
    # 去重但保持顺序
    seen, want = set(), []
    for t in known:
        if t not in seen:
            seen.add(t)
            want.append(t)
    return want, unknown


def plan(tool_names=None, spec=None, source="env") -> dict:
    """算出该保留/移除哪些工具。

    spec=None 表示「没给」（用默认 profile）；spec 给 `all` 表示全开；
    给了组名但一个都认不出来，按不裁剪处理（宁可少裁不错杀）。
    """
    names = set(tool_names or [])
    assigned = assigned_names()
    unassigned = sorted(n for n in names if n not in assigned) if names else []
    base = {"available_groups": sorted(TOOLSETS),
            "unassigned": unassigned, "source": source}
    if spec is None:
        want, unknown, on = list(DEFAULT_GROUPS), [], True
        note = ("未设 MDKDEBUG_TOOLSETS：按默认精简暴露（%s）。"
                "要用别的组调 toolset(action=\"load\", toolsets=\"mem,trace\")"
                % ",".join(DEFAULT_GROUPS))
    elif str(spec).strip().lower() in FULL_ALIASES:
        return dict(base, on=False, requested=[], unknown_groups=[],
                    removed=[], kept=sorted(names),
                    note="显式要求全开（%s）" % spec)
    else:
        want, unknown = parse_groups(spec)
        if not want:
            return dict(base, on=False, requested=[], unknown_groups=unknown,
                        removed=[], kept=sorted(names),
                        note="组名一个都没认出来，按不裁剪处理（宁可少裁不错杀）")
        on, note = True, "按 MDKDEBUG_TOOLSETS 指定组裁剪"
    keep = set(ALWAYS) | set(unassigned)
    for g in want:
        keep |= set(TOOLSETS[g])
    removed = sorted(n for n in names if n not in keep)
    return dict(base, on=on, requested=want, unknown_groups=unknown,
                removed=removed, kept=sorted(n for n in names if n in keep),
                note=note)


# ----------------------------------------------------------------------
# 运行期装卸
#
# 账本是**按 server 记的**，不是进程级单例——同一个进程里建两个 server
# （测试就这么干）时，进程级单例会让「对 A 的 toolset 调用去改 B 的工具表」，
# 表现成 A 怎么装都装不动。真实部署一个进程一个 server，但账本不该靠这一点活着。
# ----------------------------------------------------------------------
class Toolbox:
    """一个 server 的工具面账本：全量快照 + 当前被收起来的那部分。"""

    def __init__(self, server):
        self.server = server
        self.tm = getattr(server, "_tool_manager", None)
        self.all = {}          # 全部工具的快照（name -> Tool），保持注册顺序
        self.order = ()
        self.inactive = {}     # 当前被收起来的工具（name -> Tool）
        self.requested = ()
        self.source = "default"
        self.ready = False

    # -- 启动：快照 + 按 plan 收起 -------------------------------------
    def install(self, spec=None, source="default") -> dict:
        if spec is None:
            r = env_raw()
            if r:
                spec, source = r, "env"
            else:
                source = "default"
        elif source == "default":
            # 调用方显式传了 spec（create_server(toolsets=...)）：如实标来源，
            # 免得 status 把「参数指定」误报成 default，让人以为没生效
            source = "param"
        tm = self.tm
        if tm is None or not hasattr(tm, "_tools"):
            logger.warning("该 MCP SDK 版本没有 _tool_manager._tools，工具面按需加载不可用")
            return {"ok": False, "error": "该 MCP SDK 版本不支持工具面按需加载"}
        tools = dict(tm._tools or {})
        self.all = tools
        self.order = tuple(tools)
        self.inactive = {}
        self.ready = True
        self.source = source
        p = plan(list(tools), spec=spec, source=source)
        removed = set(p.get("removed") or [])
        for nm in list(tools):
            if nm in removed:
                self.inactive[nm] = tools[nm]
                tm._tools.pop(nm, None)
        self.requested = tuple(p.get("requested") or ())
        p["ok"] = True
        p["exposed"] = len(tm._tools)
        p["hidden"] = len(self.inactive)
        logger.info("工具面：%s；暴露 %d 个 / 收起 %d 个（保留组：%s，来源：%s）",
                    p.get("note"), p["exposed"], p["hidden"],
                    ",".join(p.get("requested") or []) or "-", source)
        if p.get("unknown_groups"):
            logger.warning("MDKDEBUG_TOOLSETS 里有未知组名：%s（可用：%s）",
                           ",".join(p["unknown_groups"]), ",".join(sorted(TOOLSETS)))
        return p

    # -- 查询 ---------------------------------------------------------
    def loaded_groups(self) -> list:
        """当前整组都暴露着的组。未归组的常驻工具不算任何组。"""
        return sorted(g for g, names in TOOLSETS.items()
                      if all(n not in self.inactive for n in names))

    def status(self) -> dict:
        exposed = len(self.all) - len(self.inactive)
        groups = {}
        for g, names in sorted(TOOLSETS.items()):
            on = [n for n in names if n not in self.inactive]
            groups[g] = {"size": len(names), "exposed": len(on),
                         "loaded": len(on) == len(names),
                         "note": GROUP_NOTES.get(g, "")}
        return {
            "ok": True,
            "ready": self.ready,
            "exposed": exposed,
            "hidden": len(self.inactive),
            "total_registered": len(self.all),
            "loaded_groups": self.loaded_groups(),
            "default_groups": list(DEFAULT_GROUPS),
            "available_groups": sorted(TOOLSETS),
            "groups": groups,
            "requested": list(self.requested),
            "source": self.source,
            "env": env_raw(),
            "hidden_tools": sorted(self.inactive),
            "hint": ("需要某组工具时调 toolset(action=load, toolsets=mem)；"
                     "toolset(action=load, toolsets=all) 一次全装；"
                     "toolset(action=unload, toolsets=mem) 收起来；"
                     "toolset(action=status) 看现状。"
                     "启动即全开用 MDKDEBUG_TOOLSETS=all。"),
            "client_note": ("装载/卸载后工具面立即变化，但 MCP 客户端可能缓存了工具列表——"
                            "若调用新工具报「未知工具」，先重新拉一次 tools/list。"),
        }

    # -- 装卸 ---------------------------------------------------------
    def _resort(self) -> None:
        """按原始注册顺序重排内部表，避免「卸了再装 → 跑到列表最后」的漂移。"""
        tm = self.tm
        if tm is None:
            return
        cur = tm._tools
        ordered = {n: cur[n] for n in self.order if n in cur}
        for n, t in cur.items():
            if n not in ordered:
                ordered[n] = t
        tm._tools = ordered

    def _grab(self, groups, want_load: bool) -> dict:
        added, removed, already, kept = [], [], [], []
        for g in groups:
            for nm in sorted(TOOLSETS[g]):
                if nm in ALWAYS:
                    kept.append(nm)
                    continue
                if want_load:
                    if nm in self.tm._tools:
                        already.append(nm)
                        continue
                    t = self.inactive.pop(nm, None)
                    if t is None:
                        continue
                    self.tm._tools[nm] = t
                    added.append(nm)
                else:
                    t = self.tm._tools.pop(nm, None)
                    if t is None:
                        continue
                    self.inactive[nm] = t
                    removed.append(nm)
        return {"added": sorted(added), "removed": sorted(removed),
                "already": sorted(already), "kept_always": sorted(set(kept))}

    def _bad_groups(self, spec, unknown) -> dict:
        return {"ok": False,
                "error": "没有可识别的组名：%s" % ("、".join(unknown) or "(空)"),
                "reason": "toolset-unknown-group", "unknown_groups": unknown,
                "available_groups": sorted(TOOLSETS),
                "hint": "可用的组：%s（也可以直接写 all）" % "、".join(sorted(TOOLSETS))}

    def load(self, spec) -> dict:
        """把若干组工具装回工具面（幂等：已经在的不重复装）。spec=all 即全装。"""
        if not self.ready:
            return {"ok": False, "error": "工具面还没初始化", "reason": "toolset-not-ready"}
        groups, unknown = _groups_of(spec)
        if not groups:
            return self._bad_groups(spec, unknown)
        r = self._grab(groups, want_load=True)
        self._resort()
        st = self.status()
        return {"ok": True, "action": "load", "groups": groups,
                "loaded": r["added"], "already_loaded": r["already"],
                "always_kept": r["kept_always"], "unknown_groups": unknown,
                "exposed": st["exposed"], "hidden": st["hidden"],
                "loaded_groups": st["loaded_groups"],
                "note": ("已装载 %d 个工具（%s）" % (len(r["added"]), "、".join(groups))
                         if r["added"] else "这些组的工具本来就都在，无需装载"),
                "client_note": st["client_note"]}

    def unload(self, spec) -> dict:
        """把若干组工具收起来（常驻工具不受影响）。spec=all 即只留常驻。"""
        if not self.ready:
            return {"ok": False, "error": "工具面还没初始化", "reason": "toolset-not-ready"}
        groups, unknown = _groups_of(spec)
        if not groups:
            return self._bad_groups(spec, unknown)
        r = self._grab(groups, want_load=False)
        self._resort()
        st = self.status()
        return {"ok": True, "action": "unload", "groups": groups,
                "unloaded": r["removed"], "always_kept": r["kept_always"],
                "unknown_groups": unknown,
                "exposed": st["exposed"], "hidden": st["hidden"],
                "loaded_groups": st["loaded_groups"],
                "note": ("已收起 %d 个工具（%s）" % (len(r["removed"]), "、".join(groups))
                         if r["removed"] else "这些组的工具本来就不在"),
                "client_note": st["client_note"]}


def _groups_of(spec) -> tuple:
    """解析组名；spec 写 all/full/* 时展开成全部组。"""
    if str(spec or "").strip().lower() in FULL_ALIASES:
        return sorted(TOOLSETS), []
    return parse_groups(spec)


_BY_MGR = {}   # id(ToolManager) -> (ToolManager, Toolbox)，强引用防 id 复用
_LAST = None   # 最近一次 install 的账本，供没带 server 的老调用点用


def install(server, spec=None, source="default") -> dict:
    """启动时调用：给这个 server 建账本、快照全部工具，再按 plan 收起不要的。"""
    global _LAST
    tm = getattr(server, "_tool_manager", None)
    tb = None
    if tm is not None:
        ent = _BY_MGR.get(id(tm))
        if ent is not None and ent[0] is tm:
            tb = ent[1]
    if tb is None:
        tb = Toolbox(server)
        if tm is not None:
            _BY_MGR[id(tm)] = (tm, tb)
    _LAST = tb
    return tb.install(spec=spec, source=source)


def _pick(server=None) -> Toolbox | None:
    if server is not None:
        tm = getattr(server, "_tool_manager", None)
        if tm is not None:
            ent = _BY_MGR.get(id(tm))
            if ent is not None and ent[0] is tm:
                return ent[1]
    return _LAST


def loaded_groups(server=None) -> list:
    tb = _pick(server)
    return tb.loaded_groups() if tb else []


def status(server=None) -> dict:
    """当前工具面：暴露/收起数量、各组装载情况、怎么装回来。"""
    tb = _pick(server)
    if tb is None:
        return {"ok": False, "error": "工具面还没初始化", "reason": "toolset-not-ready",
                "available_groups": sorted(TOOLSETS),
                "hint": "这是内部状态问题：启动时 toolbox.install 没跑成"}
    return tb.status()


def load(spec, server=None) -> dict:
    tb = _pick(server)
    if tb is None:
        return {"ok": False, "error": "工具面还没初始化", "reason": "toolset-not-ready"}
    return tb.load(spec)


def unload(spec, server=None) -> dict:
    tb = _pick(server)
    if tb is None:
        return {"ok": False, "error": "工具面还没初始化", "reason": "toolset-not-ready"}
    return tb.unload(spec)
