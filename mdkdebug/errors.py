# -*- coding: utf-8 -*-
"""统一结果信封 + 字符串错误码（批次33）。

为什么需要这一层
----------------
吸收自两个开源项目的同一做法：

- `embeddedskills` 规定所有子命令返回同一个信封
  `{status, action, summary, details, artifacts, metrics, next_actions, timing}`；
- `keil-project-tools` 定义了一组**字符串**错误码（`target-not-found` /
  `environment-missing` / `partial-failure`…），并规定 message 里要带候选列表。

它们的共同动机是：**调用方（AI）不该靠解析中文报错来决定下一步**。
本项目此前只有逐工具零散的 `hint` / `note` / `warning`，以及各不相同的 `ok` 语义——
「报错后给下一步动作」是这套工具最值钱的部分，却是「某些工具恰好有」，不是契约。

这一层做两件事，且**只做加法**（不改动任何既有字段，避免破坏已有调用与测试）：

1. 给所有工具的结果补上 `status`（ok / warn / error）；
2. 失败时补 `error_code`（稳定的机器可读串）+ `error_hint`，并把散落的
   `hint` / `*_hint` / `suggestion` 归拢成 `next_actions` 数组。

另外补 `risk`：高风险工具（会改目标 Flash/内存、会关掉用户的 Keil）在结果里
明确标出来，省得调用方在长链路里忘记自己刚做了一次不可逆操作。
"""
from __future__ import annotations

import logging
import re

from . import annotate as _annotate

logger = logging.getLogger("mdkdebug.errors")

# ----------------------------------------------------------------------
# 风险分级（吸收 embeddedskills 的 operation_mode：低/中/高）
# ----------------------------------------------------------------------
# 风险分级的数据源统一放在 annotate（批次37）：那里是**按整个工具面**归类过的，
# 含非 MDK 工具族（ocd_/toolchain_/trace_/target_）。
# 在此之前，这批工具因为不在下面两张表里，风险字段是空的——
# 于是 ocd_flash / ocd_write_mem 这种真写 Flash 的工具**没有风险提示**，
# 而 readOnlyHint 一旦也沿用同一套数据，就会被误标成"只读"：这是本轮修掉的缺口。
RISK_HIGH = set(_annotate.DESTRUCTIVE)
RISK_MEDIUM = set(_annotate.MUTATING) - RISK_HIGH

# ----------------------------------------------------------------------
# 字符串错误码字典
# ----------------------------------------------------------------------
ERROR_CODES = {
    "uvsock-unavailable": {
        "text": "调试通道不可用：Keil 未运行，或 UVSOCK 未开启",
        "next_actions": [
            "调 keil_health 看清断在哪一环（进程 / 端口 / 模态框）",
            "Keil 未启动则 restart_keil；已启动则确认 Edit→Configuration→Other→UVSOCK Enabled 且端口为 4823",
        ],
    },
    "keil-not-running": {
        "text": "Keil uVision 没有在运行",
        "next_actions": ["调 restart_keil 拉起 Keil 并等待 UVSOCK 就绪", "或 launch_uvision 以可见方式打开工程"],
    },
    "keil-busy": {
        "text": "Keil/UV4 被占用（工程正被另一个实例打开，或 UV4 命令行无法访问）",
        "next_actions": [
            "调 list_uvision_instances 看清有哪些实例、分别开着什么工程",
            "调 close_uvision 关闭占用实例后重试；需要保留则改在该实例里手工操作",
        ],
    },
    "uv4-not-found": {
        "text": "未定位到 UV4.exe",
        "next_actions": ["启动服务时用 --uv4-path 指定 UV4.exe 的完整路径", "确认 Keil 安装目录未被移动"],
    },
    "project-required": {
        "text": "没有指定工程，也没有可用的默认工程",
        "next_actions": ["传入 project（.uvprojx 完整路径）", "或用启动参数 --default-project 配置默认工程"],
    },
    "project-not-found": {
        "text": "工程文件不存在或打不开",
        "next_actions": [
            "核对 project 路径（可先用 read_project_config 看当前配置的工程）",
            "确认工程没有被 Keil 独占打开（close_uvision 后再试）",
        ],
    },
    "build-failed": {
        "text": "编译未通过（产物未生成或未更新）",
        "next_actions": ["读 output 里的第一条 error 行定位问题（metrics.errors 给出错误总数）",
                         "改完后重试 build_project / rebuild_project；怀疑增量残留可先 clean_project"],
    },
    "toolchain-not-ready": {
        "text": "工具链未就绪（器件包缺失 / 许可证问题 / UV4 环境异常）",
        "next_actions": ["用 Keil 打开工程手工构建一次，按弹窗提示处理", "确认对应器件的 Device Family Pack 已安装"],
    },
    "output-write-failed": {
        "text": "构建产物写入失败（输出目录只读 / 磁盘满 / 文件被占用）",
        "next_actions": ["检查 Objects/Listings 等输出目录权限与磁盘空间", "关闭占用产物文件的程序（调试器、烧录工具、hex 查看器）后重试"],
    },
    "not-debugging": {
        "text": "当前不在调试会话中，该操作需要调试态",
        "next_actions": ["先 enter_debug；若刚烧录过，注意旧会话的符号已过期", "调 get_status 确认 debugging 字段"],
    },
    "already-debugging": {
        "text": "目标已处于调试态，该操作与当前状态冲突",
        "next_actions": ["需要重新进入时先 exit_debug，或用 restart_keil 一键重置", "调 get_status 确认当前状态后再决定"],
    },
    "symbol-stale": {
        "text": "调试会话的符号已过期（编译/烧录后 .axf 已重生成，旧会话求值会报解析错误）",
        "next_actions": ["exit_debug 后重新 enter_debug 刷新符号", "或按返回值里的 symbol_stale_warning 提示处理"],
    },
    "enter-debug-not-ready": {
        "text": "进入了调试流程但未确认调试态，后续命令可能全部报「未处于调试状态」",
        "next_actions": [
            "用 keil_health 看 Keil 是否有模态框阻塞、UVSOCK 是否已就绪",
            "若该实例残留过命令脚本（进完调试又自己退出）：close_uvision(force=true) → "
            "launch_uvision → enter_debug，用干净实例重进",
            "确认目标板与调试器连接正常（target_info 看 IDCODE/DEV_ID）后重试",
        ],
    },
    "debug-info-missing": {
        "text": "当前 PC 所在函数没有可用的局部变量调试信息（不是『调试通道坏了』）",
        "next_actions": [
            "多为编译优化把局部变量优化掉了（read_project_config 看 optimization，-Otime/-O3 常见）：调低优化级别重新编译再试",
            "先 get_current_location 确认停在函数体内（停在库函数/启动代码里通常本就没有局部信息）",
            "看全局变量用 read_variable，看固定地址的值用 read_mem（不依赖调试信息）",
        ],
    },
    "symbol-missing": {
        "text": "缺少调试符号（未定位到 .axf 或符号表为空）",
        "next_actions": [
            "先编译一次生成 .axf（build_project 或 toolchain_build），再用 set_symbol_file 指定",
            "传过工程就会有符号：任何带 project 参数的工具（如 launch_uvision/build_project）都会顺带把符号挂上，可先用 read_project_config 确认工程路径",
            "用 list_symbol_projects 看内置/注入的符号工程，核对构建输出目录里确实有 .axf",
        ],
    },
    "breakpoint-address-unresolved": {
        "text": "断点地址不在已加载镜像内（Keil 报 error 57）",
        "next_actions": ["确认传入的是**运行地址**；裸地址需自带 Thumb 位（0x…401 这类奇数）或改用符号名", "用 find_symbol 先确认符号的地址与所在镜像段"],
    },
    "breakpoint-limit": {
        "text": "断点数量超出硬件限制（Keil 报 error 65）",
        "next_actions": ["先 clear_all_breakpoints 或删除不再需要的断点", "改用 watchpoint / 条件断点减少占用"],
    },
    "breakpoint-not-found": {
        "text": "要清除的断点不存在（Keil 报 error 72）",
        "next_actions": ["用 list_breakpoints 取真实断点编号后再清（按地址清不掉）", "若目标是数据断点，用 clear_watchpoint"],
    },
    "breakpoint-exists": {
        "text": "断点已存在（Keil 报 error 145，属幂等可忽略）",
        "next_actions": ["无需处理：断点已在位，可直接 wait_breakpoint 等待命中"],
    },
    "serial-expect-timeout-no-data": {
        "text": "串口等待超时，且期间**一个字节都没有新增**（不是 pattern 的问题）",
        "next_actions": [
            "确认这次请求真的发出去了：看返回里的 sent_hex / sent 字段（sent=false 说明只是纯等待）",
            "核对波特率与接线（TX/RX 是否交叉、GND 是否共地），并用 serial_monitor_status 看 bytes_total 是否在涨",
            "目标可能不在输出：用 serial_read(since=0) 回看缓冲区，确认它到底有没有在说话",
        ],
    },
    "serial-expect-timeout-no-match": {
        "text": "串口等待超时：期间有新增内容但对不上 pattern",
        "next_actions": [
            "把 pattern 放宽：regex=false 按字面匹配，或 case_sensitive=false 忽略大小写",
            "直接读返回的 lines（本次新增原文）当线索，据此改 pattern；必要时加大 timeout_s",
        ],
    },
    "serial-not-monitoring": {
        "text": "当前没有串口监听在运行",
        "next_actions": ["先 serial_monitor_start(port=...) 打开端口（收与发共用一个句柄）", "用 serial_list_ports 确认 COM 号"],
    },
    "serial-port-not-found": {
        "text": "未发现可用串口，或指定的串口不存在",
        "next_actions": ["调 serial_list_ports 看本机串口与芯片推断（确认 USB-TTL 插好、驱动已装）", "确认波特率无关：口不存在是设备/驱动问题"],
    },
    "serial-port-busy": {
        "text": "串口被其他程序占用（打开失败，WinError=5）",
        "next_actions": ["关闭 Keil 的串口窗口 / 其他串口工具（同一时刻只能一个进程持有）", "若占用者是本服务，reopen_count 会自动重连，稍后重试即可"],
    },
    # ---- Modbus（批次44）----
    # 这一族的关键是「收不到」与「收到但不对」必须分开：前者查接线/波特率/从站号，
    # 后者查串口参数/帧长度/是不是别的协议。混成一句「失败」会让人在两个方向上乱试。
    "modbus-no-session": {
        "text": "还没有打开的 Modbus 会话，且本次没给 port",
        "next_actions": [
            "带上 port（如 port=\"COM9\"）与 baud / serial_format 重新调用",
            "不确定是哪个口：先 serial_list_ports 看端口与芯片推断",
            "想先确认能打开：modbus_session(action=\"open\", port=\"COM9\", baud=9600)",
        ],
    },
    "modbus-no-port": {
        "text": "给了串口参数但没给 port，无法判断参数作用在哪个口上",
        "next_actions": ["把 port 一起给上（串口参数只在打开/切换端口时有意义）",
                         "或用 modbus_session(action=\"status\") 看当前会话在哪个口"],
    },
    "modbus-port-held-by-monitor": {
        "text": "该串口正被 serial_monitor_start 的日志监听占着（同一时刻只能一个持有者）",
        "next_actions": [
            "先 serial_monitor_stop() 释放端口，再调 modbus_*",
            "调完 Modbus 想接着看日志：modbus_session(action=\"close\") 再 serial_monitor_start",
        ],
    },
    "modbus-session-closed": {
        "text": "Modbus 会话当前没有持有端口（已空闲自动释放或被关闭）",
        "next_actions": ["带上 port 重新调用任意 modbus_* 工具即可重开（同参数会复用，不会重复初始化）",
                         "用 modbus_session(action=\"status\") 确认会话状态与释放原因"],
    },
    "modbus-port-readonly": {
        "text": "串口是以只读方式打开的，发不出 Modbus 请求",
        "next_actions": ["确认端口没被别的程序（Keil 串口窗口 / 其他串口工具）独占",
                         "modbus_session(action=\"close\") 后重开一次；仍只读则检查驱动是否允许写"],
    },
    "modbus-timeout-no-response": {
        "text": "请求已发出，但在超时时间内**一个字节都没收到**（不是帧格式问题）",
        "next_actions": [
            "核对串口参数：波特率、校验位（Modbus 常用 9600 8E1 / 19200 8N1）、停止位、数据位",
            "核对从站号（用 modbus_scan 扫一遍），并确认目标设备确实支持该功能码/地址",
            "接线：A/B 是否交叉、GND 是否共地、终端电阻；必要时 modbus_sniff 旁听总线看有没有数据在跑",
            "加大 timeout_ms（低速从站 + 长帧时 1000ms 可能不够）",
        ],
    },
    "modbus-bad-crc": {
        "text": "收到了 RTU 应答，但 CRC16 校验不过（帧被改过/被截断/参数不匹配）",
        "next_actions": [
            "先核对串口参数与波特率（校验位/停止位错会稳定地算不过 CRC）",
            "看返回的 raw_hex：若长度不对，多半是超时太短被截断——加大 timeout_ms 或给 expect_len",
            "总线上有多个设备/别的协议混跑时用 modbus_sniff 看原始帧，确认是不是抓错了对象",
        ],
    },
    "modbus-bad-lrc": {
        "text": "收到了 ASCII 应答，但 LRC 校验不过",
        "next_actions": ["核对串口参数（ASCII 模式常见 7E1/8E1）与帧边界（':' 起、CRLF 止）",
                         "modbus_decode 离线核对一遍这段报文的 LRC 算法是否与设备一致"],
    },
    "modbus-bad-frame": {
        "text": "收到的字节不是一帧完整的 Modbus 报文（长度不足/半帧/非该协议）",
        "next_actions": [
            "加大 timeout_ms 或给 expect_len（知道应答应有长度时让它收够再返回）",
            "用 modbus_sniff 按静默切帧看总线上真实出现的帧边界",
            "确认对端确实说 Modbus：非规范/私有协议请用 modbus_raw 直接看 hex",
        ],
    },
    "modbus-exception": {
        "text": "从站返回了异常帧：通信是通的，它收到了请求但拒绝了",
        "next_actions": [
            "按 exception_code 对号入座：0x01 功能码不支持 / 0x02 地址越界 / 0x03 数量或取值非法 / 0x06 从站忙",
            "0x02 常见于从站号对但寄存器地址基址不同（有的设备是 1-based）、或该型号没有这个寄存器",
            "0x06/0x05 属于「稍后重试」类，等设备处理完再发，不要连发",
        ],
    },
    "timeout": {
        "text": "操作超时",
        "next_actions": ["调 keil_health 看 Keil 侧是否被模态框阻塞 / 端口是否还在监听", "确认目标是否在运行、命令是否本就耗时较长（可调大超时参数）"],
    },
    # 批次38 真机实测：run_to_line 到「已执行过的地址」时断点永不命中，
    # 旧实现拿陈旧 PC 报成功（假成功）。现在如实失败并给出这条路该怎么走。
    "run-to-target-timeout": {
        "text": "运行到目标位置超时：临时断点未命中（目标没走到该处，或该地址已执行过）",
        "next_actions": [
            "想让程序回到起点再跑：先 reset(run_after=false)，再 run_to_line / run",
            "想确认某函数是否被调用：set_breakpoint(expr=\"函数名\") + run + wait_breakpoint",
            "确认地址/行号是否真的可达：get_current_location 看当前停在哪，"
            "disassemble 核对地址处是否可执行",
            "目标已停下（本工具已发 stop），要它继续跑请调 run",
        ],
    },
    # 批次48：DWT 比较器回读仍在武装时落过 unknown-error，next_actions 指向
    # keil_health / 读日志——而真正该做的是直接写 DWT_FUNCTIONn=0，方向完全不同。
    "dwt-not-cleared": {
        "text": "DWT 数据观察点比较器未能关闭（Keil 断点表已清，硬件比较器还在）",
        "next_actions": [
            "用 set_register 直接写 DWT_FUNCTION0..3=0（地址 0xE0001028+0x10n）后重读一次",
            "确认目标处于停止状态再写：运行中写 DWT 寄存器不生效（先 stop）",
            "确认 DEMCR.TRCENA 未被清；若整片 DWT 都读不到，说明当前不在调试态",
        ],
    },
    # 真机阶段7 实测：wait_state 超时（matched=False + timeout_kind）过去没有对应码，
    # 落进 unknown-error → next_actions 指 keil_health，而真正该做的是看 observed 现场。
    "wait-state-timeout": {
        "text": "等待超时：在 timeout_s 内没等到目标状态（工具本身没坏）",
        "next_actions": [
            "看返回的 observed：observed=running 说明目标没停到你等的状态，"
            "先判断是不是断点/条件没命中（要等断点命中请改用 wait_breakpoint）",
            "确认调试态还在：get_status；目标可能已跑飞或被看门狗复位（fault_report）",
            "确认目标确实会走到该状态后，把 timeout_s 调大重试",
        ],
    },
    # 真机阶段7 实测：profile_function 报「运行 800ms 未到达函数入口」时落 unknown-error，
    # 调用方拿到的下一步是「读 OpenOCD/Keil 输出」——与真实原因（函数没被调用/跑过了）不搭。
    "function-not-reached": {
        "text": "运行到超时仍未命中函数入口断点（函数没被调用，或入口地址不对）",
        "next_actions": [
            "确认该函数真会被执行到：先用 run_to_line / 断点验证调用路径",
            "若程序已经跑过它，先 reset 再 run（断点只在设置之后命中）",
            "核对符号：find_symbol 查入口地址，注意内联/优化后符号可能不可用",
            "确认目标在跑（wait_state(running)）后再重试，必要时调大 max_ms",
        ],
    },
    # RTOS 工具族（批次41）。三条都对应真机/裸机实测过的路径：
    # 传了裸机 .axf（rtos_tasks）、内核没开队列注册表（rtos_objects）、
    # Keil 与 OpenOCD 两条链路都没有活着的会话。
    "rtos-not-present": {
        "text": "这个 .axf 里没有 RTOS 符号：固件是裸机，或传错了 .axf",
        "next_actions": [
            "确认 axf 就是目标板上正在跑的那个固件（rtos_info 先看探测结果）",
            "裸机工程没有任务可列，这是正常结论不是错误；要列任务得先编进 RTOS 内核",
            "用的是 Zephyr / ThreadX / osek 等其它 RTOS 的话目前不支持——说明用哪个再补",
        ],
    },
    "rtos-no-queue-registry": {
        "text": "FreeRTOS 内核没有维护队列注册表，主机侧无法枚举队列/信号量",
        "next_actions": [
            "这不是工具缺陷而是内核限制：configQUEUE_REGISTRY_SIZE 为 0 时 FreeRTOS 根本不定义 xQueueRegistry",
            "要枚举队列/信号量：把 configQUEUE_REGISTRY_SIZE 设为 ≥ 队列数，并在创建后调用 vQueueAddToRegistry()",
            "不想改固件就换手段：对某个已知句柄用 read_struct 直接看 Queue_t（需先 find_symbol 拿地址）",
        ],
    },
    "rtos-no-mem-link": {
        "text": "Keil(UVSOCK) 与 OpenOCD 两条链路都没有活着的调试会话，读不到目标内存",
        "next_actions": [
            "Keil 目标：launch_uvision + enter_debug 先把 UVSOCK 会话跑起来",
            "非 MDK 目标：ocd_start(profile=...) + ocd_control(action=\"halt\") 后重试",
            "也可以直接用 link=\"keil\" 或 link=\"ocd\" 指定链路，报错里会分别给出两条链路的缺失原因",
        ],
    },
    "toolset-unknown-group": {
        "text": "toolset 的 toolsets 参数里没有可识别的组名",
        "next_actions": [
            "可用组只有这 11 个：core mem symbol build serial advanced toolchain target ocd trace rtos",
            "不确定就先调 toolset(action=status)：它会列出每个组的工具数与当前装载情况",
        ],
    },
    "toolset-not-ready": {
        "text": "工具面按需加载在当前 MCP SDK 上不可用（找不到预期的工具注册表接口）",
        "next_actions": [
            "这是 SDK 兼容性问题，不是工程配置问题：此时全部工具都还在，能力一个不少",
            "用 capabilities 看 tool_surface 的 tool_count 确认当前工具面",
            "要固定成全开：启动前设环境变量 MDKDEBUG_TOOLSETS=all",
        ],
    },
    "toolset-bad-action": {
        "text": "toolset 的 action 只能是 status / load / unload",
        "next_actions": [
            "看当前工具面：toolset(action=status)",
            "装回某组：toolset(action=load, toolsets=mem,trace)",
            "收起某组：toolset(action=unload, toolsets=trace)",
        ],
    },
    "invalid-argument": {
        "text": "参数不合法或缺失",
        "next_actions": ["用 list_tools(keyword=...) 查该工具的参数签名与最小调用示例 example_args", "参数名/类型都做了容忍，仍报错请按规范名传参"],
    },
    "halt-dirty-pc": {
        "text": "刚停止时读到的是脏值（PC 未收敛）",
        "next_actions": ["稍等片刻重读一次（工具已默认做读数收敛判定）", "确认看门狗冻结位已置位，避免 halt 期间被复位"],
    },
    # ------------------------------------------------------------------
    # 非 MDK 链路（OpenOCD / 交叉工具链 / trace）
    #
    # 为什么要单独立码：Keil 侧的通用码（timeout / unknown-error）的
    # next_actions 全都指向 keil_health / read_async_messages，对 OpenOCD 链路是
    # **方向性错误**——真机实测：ocd_read_mem 读不全被归成 output-write-failed
    # （next_actions 指向 Objects/Listings 目录权限），ocd_write_mem / ocd_reg 失败
    # 归成 unknown-error（指向 keil_health）。错误的下一步比没有下一步更坑。
    # ------------------------------------------------------------------
    "ocd-not-running": {
        "text": "OpenOCD 会话没在运行（非 MDK 侧没有调试通道）",
        "next_actions": [
            "先 ocd_start(profile=\"stm32f401\" 之类) 把会话起起来；不确定档案用 target_list",
            "若刚被 ocd_stop / 进程自己退了，读 ocd_log 看退出原因（探针被占、cfg 路径错）",
        ],
    },
    "ocd-session-exists": {
        "text": "本服务已有一个 OpenOCD 会话在跑（同一根探针同时只能一个实例）",
        "next_actions": [
            "继续用现有会话（ocd_status 看它跑的是哪个档案），或 ocd_stop 后再起",
            "需要换配置直接用 ocd_start(restart=true)",
        ],
    },
    "ocd-probe-busy": {
        "text": "调试探针被占用（另一个进程持着 DAP，常见是 Keil 正在调试）",
        "next_actions": [
            "先退出 Keil 的调试会话（或 close_uvision），再 ocd_start",
            "确认没有其它 OpenOCD / pyOCD / 厂商 IDE 在后台占着同一根探针",
        ],
    },
    "ocd-telnet-unreachable": {
        "text": "连不上 OpenOCD 的 telnet 命令口（进程没起来 / 端口不对 / 已退出）",
        "next_actions": [
            "读 ocd_log 看 openocd 自己的报错（cfg 找不到、探针未被识别最常在这）",
            "用 ocd_status 看进程与端口；端口被占就在 ocd_start 里换 telnet_port",
            "探针插口/驱动问题不属于本链路：先确认 DAP 在设备管理器里能看到",
        ],
    },
    "ocd-command-failed": {
        "text": "OpenOCD 拒绝了这条命令（目标配置或目标当前状态不允许）",
        "next_actions": [
            "读返回里的 output：OpenOCD 把 `Error: ...` 原文留在那里（本工具不替它编原因）",
            "地址类命令先 ocd_control(action=\"halt\")；目标没停住时读内存/下断点会失败",
            "批量发命令时用 ocd_cmd_many 一条条看，定位是哪一条开始不对",
        ],
    },
    "ocd-read-short": {
        "text": "内存没读全（实际读到的字节数少于请求）",
        "next_actions": [
            "先 ocd_control(action=\"halt\") 再读：目标在跑时 DAP 直读会失败或读到半截",
            "核对地址在有效区间（ocd_map / ocd_flash_info 看布局），外设区可能不可读",
            "Cortex-M7/H7 开着 D-Cache 时直读 RAM 可能拿不到最新值，必要时先清 Cache",
        ],
    },
    "ocd-write-verify-read-failed": {
        "text": "写后回读校验本身失败（读不回来，不代表写入失败）",
        "next_actions": [
            "核对地址是否在可读区间：RAM 越界 / 未映射区域上 OpenOCD 的**写命令不报错**，只有读回才报",
            "用 ocd_map（或 target_show 的布局信息）确认这颗芯片的 RAM/Flash 区间后再选地址",
            "目标没停住时也读不回来：先 ocd_control(action=\"halt\")",
        ],
    },
    "ocd-write-verify-mismatch": {
        "text": "写后读不一致（写入未生效或回读被缓存干扰）",
        "next_actions": [
            "目标可能在跑：先 halt 再写；写 Flash 前要先擦除对应扇区",
            "该地址可能只读（外设寄存器中锁定的域、未解锁的 Flash 区域）",
            "H7 这类带 D-Cache 的目标，直写 RAM 可能被脏行回写覆盖，先清 Cache",
        ],
    },
    "ocd-no-flash-bank": {
        "text": "没有可用的 Flash bank（target cfg 不匹配或该芯片需要额外 cfg）",
        "next_actions": [
            "用 target_show / target_list 看档案选的 interface/target cfg 是否对应这颗芯片",
            "部分 ESP32 / RISC-V 目标要专门的 cfg（如 esp32.cfg）才会注册 Flash driver",
            "确认目标已上电且已被识别：ocd_probe 看 targets 列表里有没有 CPU",
        ],
    },
    "ocd-script-missing": {
        "text": "找不到 OpenOCD 的 scripts 目录（interface/target cfg 都在里面）",
        "next_actions": [
            "确认解压出来的 xpack-openocd 目录完整（share/openocd/scripts 要在）",
            "用 toolchain_list 看本服务认到的 openocd 根目录是不是你期望的那个",
        ],
    },
    "ocd-start-failed": {
        "text": "OpenOCD 没起来就退了（退出码非 0）——真正的失败原因在 openocd 的日志里",
        "next_actions": [
            "读返回里的 log_tail（或 ocd_log）：openocd 会把 Invalid argument / "
            "can't find xxx.cfg 这类真因写在最后几行",
            "看 scripts_dir_warning：没传 -s scripts 目录时 cfg 找不到，报错只有一句 exit code 1",
            "调低速度或换接口 cfg：adapter speed 的参是**裸 kHz 数字**（写 1000 不写 1k）",
            "确认探针没被 Keil / 另一个 OpenOCD 占着（ocd_status 看是否有残留会话）",
        ],
    },
    "ocd-target-running": {
        "text": "目标正在运行，这个操作要求先停核（Cortex-M 的 core 寄存器只在 halted 时可见）",
        "next_actions": [
            "ocd_control(action=\"halt\") 停核后重试；读寄存器/设断点/单步都要求 halt",
            "读内存**不需要** halt（DAP 直读 RAM）：变量 scope 这类观测别去停核",
            "只想看运行中的函数分布用 trace_pcsample（不 halt）",
        ],
    },
    "toolchain-missing": {
        "text": "没找到要用的工具链可执行文件",
        "next_actions": [
            "用 toolchain_list 看本机已装了什么（本服务会扫描 D:/Tools/mdk_agent_toolchains）",
            "按架构选对家族：arm-none-eabi / riscv-none-elf / riscv32-esp-elf / xtensa-esp-elf",
            "也可能命令名字不对：看看 toolchain_where 能不能定位",
        ],
    },
    "target-unknown": {
        "text": "目标档案没命中（profile 不是已知档案）",
        "next_actions": [
            "先 target_list 看档案清单（含各档案的接口/目标 cfg 与默认 transport）",
            "没有合适的就手给 interface/target cfg：ocd_start(interface=..., target=...)",
        ],
    },
    "file-not-found": {
        "text": "文件不存在或路径不对",
        "next_actions": [
            "核对路径（Windows 路径带空格要引号；本工具参数直接传字符串即可）",
            "若是构建产物：先构建一次（toolchain_build / build_project），再引用产物",
        ],
    },
    "trace-not-attached": {
        "text": "还没 attach RTT（没有可用的上行/下行通道）",
        "next_actions": [
            "先 trace_rtt_attach：目标里必须已经跑着 RTT 组件（trace_instrument 可复制到工程）",
            "不确定控制块地址用 trace_rtt_find 在 RAM 里扫（它认 `SEGGER RTT` 魔数）",
        ],
    },
    "trace-rtt-not-found": {
        "text": "RAM 里没扫到 RTT 控制块",
        "next_actions": [
            "确认固件真的带了 RTT 组件并已初始化（_SEGGER_RTT 符号在 ELF 里）",
            "优先用 elf 定位（trace_rtt_find(elf=...)），比盲扫快且准",
            "目标停在复位前/没跑起来时控制块还没建，先 resume 让它跑一会儿再扫",
        ],
    },
    "trace-rtt-invalid": {
        "text": "这个地址不是合法的 RTT 控制块（魔数/字段不匹配）",
        "next_actions": [
            "换成 trace_rtt_find 用 elf 的 _SEGGER_RTT 符号定位，不要手工猜地址",
            "若地址是别人给的：确认它指向的是控制块开头（不是通道缓冲）",
        ],
    },
    "trace-swo-not-running": {
        "text": "当前没有正在进行的 SWO 采集",
        "next_actions": [
            "先 trace_swo_start（要 coreclk 与 baud；TPIU 上 SWO 要接线正确）",
            "读已落盘的采集用 trace_swo_read(file=...)（采集结束后仍可回看）",
        ],
    },
    "no-recording": {
        "text": "本进程还没有做过 trace_record 录制，没有可回看的时间线",
        "next_actions": [
            "先 trace_record(action=\"run\", funcs=...) 录一次：read/status 只看得到"
            "**同一进程里**刚录完的那份报告，跨进程不保留",
            "函数名不确定：find_symbol 或 list_tools(keyword=\"symbol\") 先找到目标函数",
            "只要「整体热点占比」、不需要进入/退出事件：改用 trace_pcsample 或 trace_profile",
        ],
    },
    "unknown-error": {
        "text": "未归类的失败",
        "next_actions": ["调 keil_health 看 Keil 侧状态", "用 read_async_messages 读 Keil 的异步报错原文"],
    },
}

# 分类规则：按顺序匹配，先具体后笼统
_RULES = (
    # ---- 非 MDK 链路（OpenOCD / 工具链 / trace）----
    # 必须排在 Keil 通用规则之前：后面的 `未运行|无法连接|连接失败` 是给 UVSOCK 写的，
    # 会把「OpenOCD 没在运行」「连接 telnet 失败」抢走，指向完全错的下一步。
    (r"OpenOCD\s*(没在|未|不)运行|openocd.*not\s*running", "ocd-not-running"),
    (r"已有 OpenOCD 在运行", "ocd-session-exists"),
    (r"探针.*(被占用|被占|被另一个)|Failed to open.*(CMSIS|dap)|no device found",
     "ocd-probe-busy"),
    (r"连接 OpenOCD telnet|等待 telnet 端口超时|telnet.*(连接|connect).*(失败|refused)",
     "ocd-telnet-unreachable"),
    (r"只读到\s*\d+\s*/\s*\d+\s*字节", "ocd-read-short"),
    (r"写后读不一致", "ocd-write-verify-mismatch"),
    (r"没有 Flash bank|没有可用的 Flash bank", "ocd-no-flash-bank"),
    (r"找不到 OpenOCD scripts 目录", "ocd-script-missing"),
    (r"openocd 进程已退出|openocd.*退出码|failed to open|can't find .*\.cfg|Invalid command argument",
     "ocd-start-failed"),
    # 真机撞到：目标在跑时读寄存器，openocd 只在输出里写
    # `Could not read register 'pc'`（status 仍为 0/成功），旧规则全不命中，
    # 落到 unknown-error，next_actions 指到“读 output 自己看”——方向完全不对。
    (r"Could not read register|Could not read register|Target not halted|target .{0,12}not halted|must be halted",
     "ocd-target-running"),
    (r"不支持的 transport|未知档案|既没给 profile 也没给 interface", "target-unknown"),
    (r"找不到工具\s|本机没找到|找不到\s*\S*\s*的\s*(gcc|objcopy)|该工具不在放行白名单",
     "toolchain-missing"),
    (r"还没 attach RTT", "trace-not-attached"),
    (r"没找到 RTT 控制块", "trace-rtt-not-found"),
    (r"不是 RTT 控制块|控制块字段不合理|控制块太短|控制块数据不足", "trace-rtt-invalid"),
    (r"没有正在进行的 SWO 采集", "trace-swo-not-running"),
    (r"OpenOCD 拒绝了|^\s*Error\s*:", "ocd-command-failed"),
    # ---- MDK / Keil 链路 ----
    (r"未定位到 UV4|UV4\.exe.*(不存在|找不到)|找不到 UV4", "uv4-not-found"),
    # 「正则编译失败」含「编译失败」子串，必须先于 build-failed 规则，否则会被误判成编译挂了
    (r"正则编译失败|正则.*(无效|不合法)|pattern.*(无效|不合法)", "invalid-argument"),
    # 真机阶段7 实测：set_register(register="r99") 报「不支持的寄存器名: r99」，
    # 旧规则全不命中 → unknown-error（next_actions 指 keil_health），其实是纯参数错。
    (r"不支持的寄存器名|无法解析数值|不支持的寄存器", "invalid-argument"),
    (r"未到达函数入口", "function-not-reached"),
    (r"正被串口日志监听占用", "modbus-port-held-by-monitor"),
    (r"从站返回异常码", "modbus-exception"),
    (r"CRC 校验失败", "modbus-bad-crc"),
    (r"LRC 校验失败", "modbus-bad-lrc"),
    (r"Modbus 会话当前未打开|会话当前未打开端口", "modbus-session-closed"),
    (r"一个字节都没有新增", "serial-expect-timeout-no-data"),
    (r"行但都不匹配", "serial-expect-timeout-no-match"),
    (r"没有串口监听在运行", "serial-not-monitoring"),
    (r"本机未发现任何串口|未发现任何串口", "serial-port-not-found"),
    (r"不在本机串口列表中", "serial-port-not-found"),
    (r"WinError\s*=?\s*5\b|拒绝访问|被别的程序占用|已被占用|端口被占用|被占用", "serial-port-busy"),
    (r"symbol_stale|符号.*过期|status\s*13", "symbol-stale"),
    (r"未从 \.axf 定位到当前函数或变量信息|无局部变量调试信息|未定位到当前函数",
     "debug-info-missing"),
    (r"未定位到 \.axf|符号文件不可用|符号表为空|符号定位未就绪|缺少 \.axf 调试符号", "symbol-missing"),
    (r"data_hex 非法|非法十六进制字节串", "invalid-argument"),
    (r"error\s*57", "breakpoint-address-unresolved"),
    (r"error\s*65", "breakpoint-limit"),
    (r"error\s*72", "breakpoint-not-found"),
    (r"error\s*145", "breakpoint-exists"),
    (r"未指定工程路径|未指定工程|没有可用的默认工程", "project-required"),
    (r"工程.*(不存在|找不到|打不开)|无法打开工程", "project-not-found"),
    # 文件类出错统一码：放在 project-not-found 之后，避免把「工程文件不存在」抢走
    (r"不存在：|文件不存在|找不到文件|no such file", "file-not-found"),
    (r"编译未通过|编译失败|构建失败|build\s*(failed|error)", "build-failed"),
    (r"设备数据库|器件库|Device Family Pack", "toolchain-not-ready"),
    # 删掉裸的「只读」：它会把 ocd_read_mem 的「只读**到** 0/16 字节」误判成
    # 输出目录只读（真机实测踩到）。Keil 侧的原文是「写入错误（输出目录只读 / 磁盘空间不足）」，
    # 下面这两条已经能盖住。
    (r"写入错误|磁盘空间|输出目录.*只读|只读.*(目录|文件系统|属性)", "output-write-failed"),
    (r"UV4 访问错误|已有实例占用", "keil-busy"),
    (r"已处于调试|已在调试态|调试会话已存在", "already-debugging"),
    (r"未进入调试|不在调试|需要调试态|not in debug", "not-debugging"),
    (r"超时|timeout", "timeout"),
    (r"未检测到 Keil|Keil 未运行|未运行|UVSOCK|4823|无法连接|连接失败|Connection refused",
     "uvsock-unavailable"),
    # 「至少要给一个/至少给一个/二者传其一」是真机踩到的漏网：target_guess 无参时报
    # 「elf 与 name 至少要给一个」，旧规则里没有「至少」这一支，落进 unknown-error 后
    # next_actions 指向「读 OpenOCD output」，把一个纯参数问题指去了非 MDK 方向。
    (r"至少要给|至少给\S{0,4}一个|至少\S{0,4}(其一|选一|传一)|二者\S{0,4}(其一|选一|传一)|二选一",
     "invalid-argument"),
    (r"参数|Field required|缺少|不能为空|参数不足", "invalid-argument"),
)

_COMPILED = tuple((re.compile(p, re.IGNORECASE), c) for p, c in _RULES)

# 归拢成 next_actions 的字段名（note 是叙述性说明，不是动作，故排除）
_HINT_KEYS = ("hint", "suggestion", "next_step", "eol_hint", "no_echo_hint",
              "port_choice_hint", "hint_1", "hint_2")
_HINT_SUFFIX = "_hint"


def classify_error(text: str) -> str:
    """从报错文本推断字符串错误码。无法归类返回 unknown-error。"""
    t = str(text or "")
    if not t.strip():
        return "unknown-error"
    for rx, code in _COMPILED:
        if rx.search(t):
            return code
    return "unknown-error"


def _classify_structured(obj: dict) -> str:
    """从工具返回的结构化标识直接定码——比从中文文本猜准得多。

    没有这一步时，serial_expect 超时的结果（只有 timeout/timeout_kind，没有 error 文本）
    会落进 unknown-error，next_actions 指向 keil_health，方向完全不对（真机实测踩到）。
    非 MDK 链路同理：ocd_read_mem 用 complete/expected_bytes 自述“没读全”，
    ocd_write_mem 用 verified/mismatch 自述“写后不一致”，都比去猜中文措辞靠谱。
    """
    if obj.get("timeout") is True and "timeout_kind" in obj:
        return ("serial-expect-timeout-no-data" if obj.get("timeout_kind") == "no-data"
                else "serial-expect-timeout-no-match")
    # wait_state 超时：工具自带 matched=False + timeout_kind + observed 现场，
    # 用结构化字段定码比猜中文 hint 准（真机阶段7 实测踩到 unknown-error）。
    if obj.get("matched") is False and "timeout_kind" in obj and "observed" in obj:
        _tk = obj.get("timeout_kind")
        if _tk == "unreachable":
            return "uvsock-unavailable"
        if _tk == "never_debugging":
            return "not-debugging"
        return "wait-state-timeout"
    # 非 MDK：工具自带的结构化结论优先
    if obj.get("complete") is False and "expected_bytes" in obj:
        return "ocd-read-short"
    if obj.get("verified") is False and "mismatch" in obj:
        return "ocd-write-verify-mismatch"
    if obj.get("verify_error") and obj.get("verified") is None:
        return "ocd-write-verify-read-failed"
    if isinstance(obj.get("parsed_banks"), list) and not obj.get("parsed_banks"):
        return "ocd-no-flash-bank"
    # RTOS 工具（批次41）：工具自己带 reason，直接定码，不去猜中文措辞。
    # 没有这一步时「传给 rtos_tasks 的是裸机 .axf」会落进 unknown-error，
    # 下一步指向 keil_health/读日志——方向完全不对。
    _rr = obj.get("reason")
    if _rr == "no-rtos-symbols":
        return "rtos-not-present"
    if _rr == "no-queue-registry":
        return "rtos-no-queue-registry"
    if _rr == "no-mem-link":
        return "rtos-no-mem-link"
    # 工具面（批次42）：reason 里已经写了码，直接透传，别让分类器去猜中文
    if isinstance(_rr, str) and _rr.startswith("toolset-"):
        return _rr
    return ""

# 非 MDK 工具名前缀：这些工具用不到 Keil 侧的下一步动作（keil_health / UVSOCK 那套）
_NON_MDK_PREFIXES = ("ocd_", "toolchain_", "trace_", "target_")

# 通用码在非 MDK 链路上的替代动作（同码不同链路，下一步完全不一样）
_NON_MDK_ACTIONS = {
    "timeout": [
        "调 ocd_log 看 OpenOCD 侧最后在干什么（卡在擦除/编程很常见）",
        "擦除/烧录/大批量读取本就慢：把 timeout 参数调大后重试",
        "确认会话还在：ocd_status；探针被拔或目标掉电会让命令一直挂住",
    ],
    "unknown-error": [
        "读返回里的 output / raw：OpenOCD 与工具链的原始输出在那里，不要猜原因",
        "用 ocd_status / toolchain_list 确认会话与工具链状态后重试",
    ],
    "invalid-argument": [
        "用 list_tools(keyword=...) 查该工具的参数签名与 example_args 示例",
        "地址类参数支持 0x 前缀；宽度只接受 8/16/32；target 只在多目标时需要",
    ],
}

# Modbus 族（modbus_*）在通用码上的下一步：不要指向 keil_health / UVSOCK，
# 那一条链跟串口 Modbus 没有任何关系。
_MODBUS_ACTIONS = {
    "timeout": [
        "加大 timeout_ms 后重试（低速从站 + 长帧本来就慢）",
        "确认请求真的发出去了：返回里的 request_hex / sent_bytes",
        "总线被别人占着（另一个主站）时也会一直等不到应答——modbus_sniff 看总线",
    ],
    "unknown-error": [
        "读返回里的 request_hex / response_hex / frames：Modbus 侧的证据都在原始字节里，不要猜",
        "离线用 modbus_decode 把这段报文解一遍，确认帧结构本身对不对",
    ],
    "invalid-argument": [
        "用 list_tools(keyword=\"modbus\") 查参数签名与 example_args",
        "功能码限定：读用 01/02/03/04，写用 05/06/0F/10；其余走 modbus_raw 裸帧",
        "地址/数量上限按规范（读寄存器一次 ≤125、读线圈 ≤2000、写寄存器 ≤123）",
    ],
}

def is_modbus_tool(tool_name: str) -> bool:
    return str(tool_name or "").startswith("modbus_")

def is_non_mdk_tool(tool_name: str) -> bool:
    return str(tool_name or "").startswith(_NON_MDK_PREFIXES)

# trace_* 是**双链路**工具族（Keil 与 OpenOCD 都能跑，见 trace_guide(topic=...)）：
# 一律按 OpenOCD 给下一步，会把 Keil 链路上的用户指向 ocd_status —— 方向错。
# 这里只给链路无关的动作：先查 trace_guide 讲清该链路支持到哪一步。
_TRACE_ACTIONS = {
    "unknown-error": [
        "先 trace_guide 看该链路（keil / ocd）支持到哪一步、缺什么前置条件",
        "读返回里的 output / raw 拿原始报错再判断，不要替目标猜原因",
        "keil 链路的 trace 工具多数要目标处于调试态（先 enter_debug）；"
        "ocd 链路先 ocd_status 确认会话还在",
    ],
}

def code_actions(tool_name: str, code: str) -> list:
    """取某个错误码在该链路下的下一步动作（非 MDK 族对通用码做替换）。"""
    if not code:
        return []
    if is_modbus_tool(tool_name) and code in _MODBUS_ACTIONS:
        return list(_MODBUS_ACTIONS[code])
    if str(tool_name or "").startswith("trace_") and code in _TRACE_ACTIONS:
        return list(_TRACE_ACTIONS[code])
    if is_non_mdk_tool(tool_name) and code in _NON_MDK_ACTIONS:
        return list(_NON_MDK_ACTIONS[code])
    info = ERROR_CODES.get(code)
    return list(info["next_actions"]) if info else []

def _status_of(obj: dict) -> str:
    ok = obj.get("ok")
    if isinstance(ok, str):
        low = ok.strip().lower()
        if low in ("ok", "true", "yes"):
            return "ok"
        if low in ("conflict", "partial", "warn", "warning"):
            return "warn"
        return "error"
    if ok is None:
        # 没有 ok 字段的工具：有 error 判失败，否则按成功
        return "error" if obj.get("error") else "ok"
    return "ok" if ok else "error"


def _collect_hints(obj: dict) -> list:
    out = []
    for k, v in obj.items():
        if not isinstance(v, str) or not v.strip():
            continue
        if k in _HINT_KEYS or k.endswith(_HINT_SUFFIX):
            out.append(v.strip())
    return out


def _error_text(obj: dict) -> str:
    parts = []
    # note 只在失败路径被调用，此时它写的就是诊断正文（如「一个字节都没有新增」）
    for k in ("error", "error_hint", "status_text", "exit_code_text",
              "exit_code_meaning", "warning", "last_error", "symbol_stale_note", "note"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v)
    return " | ".join(parts)


def normalize(tool_name: str, obj: dict) -> dict:
    """给单个工具结果补统一信封。纯函数，不改动既有字段。"""
    if not isinstance(obj, dict):
        return obj
    out = dict(obj)
    status = _status_of(out)
    out["status"] = status

    if status == "error":
        # 工具自己给的 error_code 优先（比从文本猜的更准），没有才按文本归类
        code = (out.get("error_code") or _classify_structured(out)
                or classify_error(_error_text(out)))
        out["error_code"] = code
        info = ERROR_CODES.get(code)
        if info and not out.get("error_hint"):
            out["error_hint"] = info["text"]

    acts = []
    existing = out.get("next_actions")
    if isinstance(existing, (list, tuple)):
        acts.extend([str(x) for x in existing if str(x).strip()])
    elif isinstance(existing, str) and existing.strip():
        acts.append(existing.strip())
    acts.extend(_collect_hints(out))
    if status == "error":
        acts.extend(code_actions(tool_name, out.get("error_code") or ""))
    # 去重保序；并剔除与 error / error_hint 原文重复的项（它们本身不是「动作」）
    seen = set(x for x in (out.get("error"), out.get("error_hint")) if isinstance(x, str))
    final = []
    for a in acts:
        if a not in seen:
            seen.add(a)
            final.append(a)
    if final:
        out["next_actions"] = final

    risk = "high" if tool_name in RISK_HIGH else (
        "medium" if tool_name in RISK_MEDIUM else None)
    if risk:
        out["risk"] = risk
        out["reversible"] = risk != "high"
    return out


def apply_to_result(tool_name: str, result):
    """把信封作用到 MCP 的 CallToolResult 上（就地改 text 与 structured_content）。"""
    content = getattr(result, "content", None)
    if not content:
        return result
    item = content[0]
    text = getattr(item, "text", None)
    if not isinstance(text, str) or not text.lstrip().startswith(("{", "[")):
        return result
    import json
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return result
    if not isinstance(obj, dict):
        return result
    new = normalize(tool_name, obj)
    if new == obj:
        return result
    new_text = json.dumps(new, ensure_ascii=False, default=str)
    try:
        item.text = new_text
    except Exception:  # noqa: BLE001
        try:
            content[0] = type(item)(type="text", text=new_text)
        except Exception as e:  # noqa: BLE001
            logger.debug("信封回写失败（%s）：%s", tool_name, e)
            return result
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        for k, v in list(sc.items()):
            if isinstance(v, str) and v.strip() == text.strip():
                sc[k] = new_text
    return result
