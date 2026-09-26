# -*- coding: utf-8 -*-
"""MCP 官方工具注解（tool annotations）——把「风险词汇表」交给客户端。

吸收来源
--------
MCP 规范里的 tool annotations：`readOnlyHint` / `destructiveHint` /
`idempotentHint` / `openWorldHint`。规范与社区的一致口径是：
**注解不是安全边界，而是风险词汇表**——让客户端与 AI 在调用之前就能判断
「要不要弹确认框」「能不能自动放行」「能不能并发调用」，而不是去解析工具描述里的中文。

本项目此前只有描述里的中文【风险】段（批次33，给人看的）；这里补的是机器可读的那一份，
由 `server.list_tools()` 统一挂到 `Tool.annotations` 上——**一层覆盖全部工具**，
新增工具自动继承，不必逐个改注册代码。

为什么用「只读白名单」而不是「可写黑名单」
------------------------------------------
默认必须保守：**新工具在没被显式归类前，应当被当成「会改东西」**。
反过来（只列可写工具）会让漏归类的新工具静默变成 read_only=true，
那是把风险标注做成了假的安全感，比不标注更糟——所以这里列的是"确认为只读"的白名单。
"""
from __future__ import annotations

# ----------------------------------------------------------------------
# 只读白名单：调用它们不改变任何持久状态（不改目标内存/Flash、不改用户文件、
# 不起停进程、不占用共享资源）。**不在表里 = 会被标成非只读。**
# ----------------------------------------------------------------------
READONLY = {
    # 工具面查询（批次56）：只读——看有哪些组、当前装了什么
    "tools_groups",
    # Keil / UVSOCK 侧：查询与解析
    "get_version", "get_status", "keil_health", "calc_expression", "read_variable",
    "read_mem", "read_mem_multi", "find_symbol", "get_current_location", "read_locals",
    "snapshot", "watch", "read_struct", "read_registers", "read_peripheral",
    "read_console_output", "read_async_messages", "list_peripherals", "list_breakpoints",
    "list_watchpoints", "list_uvoptx_breakpoints", "list_symbol_projects",
    "list_uvision_instances", "project_targets", "read_project_config", "target_info",
    "query_memory_map", "search_mem", "disassemble", "fault_report", "diagnose",
    "breakpoint_stats", "cache_info", "address_for_line", "parse_map",
    # 重定位偏移校验：只读 ELF + 读目标内存，不改任何状态。
    "reloc_check",
    # 环境一致性体检：只读 DEV_ID/CPUID/Flash 指纹/寄存器，不起停目标、不下断点。
    "env_check",
    "parse_build_errors", "explain_build_error", "snapshot_diff", "wait_breakpoint",
    "wait_state", "mdk_guide", "capabilities", "list_tools",
    "list_peripherals", "svd_list", "svd_decode", "uvprojx_read",
    # 分散加载文件：读结构与静态校验都不写文件；scatter_edit 才写。
    "scatter_read", "scatter_check",
    # 非 MDK 链路：探测与解析（不 bind 端口、不起进程）
    "toolchain_list", "toolchain_detect_project", "toolchain_elf_info",
    "toolchain_size", "toolchain_errors", "target_list", "target_show", "target_guess",
    "debug_config",
    "trace_scope_read",
    # 覆盖率：只有「读快照」是纯只读；start/stop/clear 会起停后台线程、
    # 并可能改写 DEMCR/DWT_CTRL（restore=true 时会恢复原值，但仍是写目标）。
    "coverage_read",
    # 多核：列举与读 CPUID 都不改目标状态；core_select 才动。
    "core_list", "core_info",
    # ETM 探测：只读 ROM table / ID 块，不写任何目标寄存器。
    "trace_etm_probe",
    # 代码结构索引（批次68）：查索引库 + 读本机源码文件，不碰目标、不写任何文件。
    # （code_index 会建/删索引文件，所以它不在这里，排在下面的 MUTATING。）
    "code_status", "code_files", "code_query", "code_node",
    # 批次69：关系/影响面只查索引库 + 读本机源码，不碰目标、不写任何文件。
    "code_relations", "code_impact",
    "ocd_cfg_list", "ocd_status", "ocd_log", "ocd_probe", "ocd_flash_info",
    "ocd_read_mem",
    "trace_guide", "trace_status", "trace_decode", "trace_events",
    # Event Recorder（批次53）：只读目标 RAM 缓冲 + 本地 .axf，不改目标状态、不占资源。
    "trace_eventrec",
    # 目标侧静态环形缓冲（批次55）：只读目标 RAM + 本地 .axf。工具自身不 halt 目标，
    # 也不搬数据（搬运由固件在运行时完成），纯粹「搬出来看」。
    "trace_buff_status", "trace_buff_dump",
    # SWD 无缝流（批次56）：status/read 只读目标 RAM 控制块与环，并把搬走的字节
    # 通过写 drained 回报目标——写的是**读数游标**（协议自身的一部分），不动用户数据。
    "trace_swd_status", "trace_swd_read", "trace_swd_tasks",
    # 节拍预算（批次66）：只读两次控制块（间隔 sample_ms）测速率，不搬字节、
    # 不动游标、不停机，所以同样属只读。
    "trace_swd_next",
    # 分析层（批次72）：在已有事件上算结论 / 跑规则，不改目标状态；
    # source="buff" 时也只读目标 RAM（trace_buff_dump 本身是只读）。
    "trace_stats", "trace_diagnose",
    # 条件触发层（批次75）：test/status 只读已录事件与主机侧状态；arm/clear 只动主机侧
    # 条件；wait 内部调 trace_swd_read（同样只搬字节 + 回报 drained 游标），不动用户数据。
    "trace_watch",
    "trace_rtt_find", "trace_swo_read",
    # 可视化说明（批次59）：纯返回文本，不写任何文件。
    "view_guide",
    # 串口：只列端口与读日志
    "serial_list_ports", "serial_monitor_status", "serial_read",
    # Modbus：只有「离线解析报文」是纯只读（不碰端口、不发字节）。
    # modbus_read 虽是读语义，但会**占用串口**并发字节到总线，
    # 按本文件的口径（只读 = 不改状态且不占共享资源）不列入白名单。
    "modbus_decode",
    # RTOS 任务感知：只读目标内存 + 本地 .axf，不改目标状态
    "rtos_info", "rtos_tasks", "rtos_objects",
    # 复位观测：只读 DHCSR（+ 可选读一个复位标志寄存器），不停目标、不改状态。
    # sample_pc=true 时会短暂停一下再恢复，属瞬时副作用（与 wait_breakpoint 同口径）。
    "watch_reset",
}

# ----------------------------------------------------------------------
# 不可逆：会改写目标 Flash/内存、覆盖用户工程文件，或强行关掉用户的 Keil。
# 对应描述里的【风险】高。
# ----------------------------------------------------------------------
DESTRUCTIVE = {
    # Keil 侧
    "flash_download", "flash_debug", "build_and_flash", "clean_project",
    "fill_mem", "write_peripheral", "close_uvision", "restart_keil",
    "reset", "set_breakpoint", "clear_all_breakpoints", "write_mem",
    "batch_debug_script",
    # 非 MDK 侧：写目标 Flash/RAM、覆盖用户工程里的插桩文件
    "ocd_flash", "ocd_write_mem", "ocd_load", "trace_instrument",
}

# ----------------------------------------------------------------------
# 非幂等：同样的调用重复一次，效果**不等价于只调一次**（会累积/重复动作）。
# 规范要求该提示只在 readOnlyHint=false 时有意义。
# ----------------------------------------------------------------------
NON_IDEMPOTENT = {
    "serial_write", "serial_expect", "launch_uvision", "restart_keil",
    # modbus_raw 可能发的是写请求（内容不限，工具不知道语义）；
    # modbus_session 的 open/close 会改变端口持有状态。
    "modbus_raw", "modbus_session",
    "close_uvision", "ocd_start", "ocd_stop", "run", "run_timeout", "step",
    "wait_fault", "trace_instrument", "toolchain_env", "session_state",
    "uvprojx_edit", "batch", "batch_debug_script", "flash_debug",
    # 渲染默认每次生成一个带时间戳的新文件（重复调用会攒出多个页面），
    # 因此不是幂等——与 session_state 同口径。
    "view_render",
    "scatter_edit", "core_select",
    "restart_keil", "reset_connection", "trace_swo_start", "trace_swo_stop",
    "trace_profile", "profile_function", "profile_sampling",
    "trace_scope_start", "trace_scope_stop", "trace_pcsample",
    "coverage_start", "coverage_stop", "coverage_clear",
}

# ----------------------------------------------------------------------
# 会改变状态的完整名单。它对应描述里的【风险】中——与 READONLY 的关系是：
#   READONLY ∩ MUTATING = ∅，READONLY ∪ MUTATING = 全部工具
# 两者分开写是有意的：annotations 用白名单（新工具默认保守），
# 风险文案用这张显式表（漏归类时宁可不标，也不要误标成"中风险"）。
# `check_surface()` 会把这个不变式真的校一遍，别只写在注释里。
# ----------------------------------------------------------------------
MUTATING = {
    # 工具面装卸（批次56）：改变上下文里的工具面，属于改状态
    "tools_load",
    "batch", "batch_debug_script", "build_and_flash", "build_project",
    "clean_project", "clear_all_breakpoints", "clear_all_watchpoints",
    "clear_breakpoint", "clear_faults", "clear_uvoptx_breakpoints",
    "clear_watchpoint", "close_uvision", "dismiss_dialog", "dwt",
    "enter_debug", "exit_debug", "fill_mem", "flash_debug", "flash_download",
    "itm_trace", "keil_command", "launch_uvision", "ocd_bp", "ocd_cmd",
    "ocd_control", "ocd_flash", "ocd_gdb", "ocd_load", "ocd_reg", "ocd_start",
    "ocd_stop", "ocd_wp", "ocd_write_mem", "profile_function",
    "profile_sampling", "rebuild_project", "reset", "reset_connection",
    "restart_keil", "run", "run_timeout", "run_to_line", "serial_expect",
    "serial_monitor_start", "serial_monitor_stop", "serial_write",
    "modbus_read", "modbus_write", "modbus_raw", "modbus_scan", "modbus_sniff",
    "modbus_session",
    "session_state", "set_breakpoint", "set_conditional_breakpoint",
    "set_debug_target", "set_register", "set_reloc_delta", "set_symbol_file",
    "set_watchpoint", "step", "stop", "toolchain_build", "toolchain_compile",
    "toolchain_env", "toolchain_objcopy", "toolchain_run", "toolset", "trace_clear",
    "trace_dwt_counters", "trace_instrument", "trace_profile",
    "trace_rtt_attach", "trace_rtt_detach", "trace_rtt_read", "trace_rtt_write",
    "trace_swo_start", "trace_swo_stop", "trace_scope_start",
    "trace_scope_stop", "trace_pcsample",
    "coverage_start", "coverage_stop", "coverage_clear",
    "uvprojx_edit", "wait_fault",
    "scatter_edit", "core_select",
    "watchdog_freeze", "write_mem", "write_peripheral",
    # 批次49：函数运行时线录制会下/撤硬件断点并 halt/resume 目标；
    # D-Cache 维护会写 SCB 的 DCCMVAC/DCIMVAC（不改用户数据，但确实写目标状态）。
    "trace_record", "dcache_maintain",
    # 目标侧缓冲复位（批次55）：往目标 RAM 的控制块写 reset_req，确实改目标状态；
    # 且是延迟生效（下一条记录才处理），重复写不等价于一次写。
    "trace_buff_reset",
    # SWD 无缝流复位（批次56）：同样写 reset_req，目标重开一段录制（清环、清字典、
    # seq+1、写 SYNC 标记）。同样是延迟生效。
    "trace_swd_reset",
    # 可视化渲染（批次59）：**不动目标**（不碰内存/Flash/调试会话），但会往
    # 本机磁盘写一个 html（默认 ./mdkdebug_views/），按本文件口径（只读＝不改任何
    # 持久状态，含用户文件）不属于只读；out 也可能覆盖已有文件。
    "view_render",
    # 代码索引维护（批次68）：build/sync 会建库写盘、drop 会删索引文件，属改状态。
    # **不列入 DESTRUCTIVE**：它只动自己的索引库（~/.mdkdebug 或 <项目>/.mdkdebug），
    # 一个字都不碰用户源码，且删了重建即可——所以 risk 是 medium 而不是 high。
    "code_index",
}

# 本服务面向**本机**的开发环境（Keil 进程、调试探针、本地工具链、本地文件），
# 不访问开放网络，因此全部 openWorldHint=false。留一个集合是为了以后真要
# 加"联网取器件包"这类工具时有地方可放。
OPEN_WORLD: set = set()


def annotations_for(name: str) -> dict:
    """返回某个工具的注解字典（可直接展开进 ToolAnnotations 构造）。"""
    n = str(name or "")
    read_only = n in READONLY
    return {
        "readOnlyHint": read_only,
        "destructiveHint": (n in DESTRUCTIVE) if not read_only else False,
        "idempotentHint": True if read_only else (n not in NON_IDEMPOTENT),
        "openWorldHint": n in OPEN_WORLD,
    }


def check_surface(names) -> list:
    """自检：两张表是否把工具面完整且不重不漏地覆盖。返回问题描述列表（空＝OK）。"""
    names = set(names)
    bad = []
    both = sorted(READONLY & MUTATING)
    if both:
        bad.append("同时被标为只读与会改：%s" % "、".join(both))
    uncovered = sorted(names - READONLY - MUTATING)
    if uncovered:
        bad.append("未被归类的工具：%s" % "、".join(uncovered))
    ghost = sorted((READONLY | MUTATING | NON_IDEMPOTENT) - names)
    if ghost:
        bad.append("表里写了但服务里没有的工具（改名/删工具后没同步？）：%s" % "、".join(ghost))
    return bad


def summary() -> dict:
    """给 capabilities / 自检用的统计：只读 / 会改 / 不可逆各有多少。"""
    return {
        "readonly": len(READONLY),
        "mutating": len(MUTATING),
        "destructive": len(DESTRUCTIVE),
        "non_idempotent": len(NON_IDEMPOTENT),
        "table_version": 1,
    }
