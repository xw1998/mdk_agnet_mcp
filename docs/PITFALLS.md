# 踩坑与实测指南（PITFALLS）

> 本文档收录**真机实测结论、踩过的坑，以及由此形成的可靠性约定**，面向排障与二次开发。
> 想快速上手请直接看 [README](../README.md)；每个坑对应的工具行为也已在 README 的工具表里给出结论。

## 目录

- [一、真实 Keil 实测要点](#一真实-keil-实测要点)
- [二、并发调用与串行化](#二并发调用与串行化)
- [三、读到的东西到底算不算数（脏读防护 / 停止确证 / 粘滞位）](#三读到的东西到底算不算数脏读防护--停止确证--粘滞位)
- [四、串口占用与释放（用完就还 / 一边收一边发）](#四串口占用与释放用完就还--一边收一边发)
- [五、历次改进留档（按批次）](#五历次改进留档按批次)

## 一、真实 Keil 实测要点


- **`EXEC_CMD` 的 data 必须是完整 EXECCMD 结构（292 字节）**，而非简化的 `nLen + 命令`：
  `flags(4) + reserved[7](28) + SSTR{nLen(4) + char[256]}`。若只发 `nLen + 命令`，Keil 会从错误
  偏移解析导致命令**静默失败**——TCP 层仍返回 `status=0`（请求被接受），但界面不会出现断点。
  **`status=0` 不代表命令真正执行。** 修正为完整结构后，`BS main` 在真实 Keil 界面正确出现断点标记。
- `UV_DBG_EXIT` 在目标处于运行状态时会被拒绝（返回"目标正在运行"，`status=11`），需先 `stop` 再 `exit_debug`；
- `EXEC_CMD` 的**响应体**确实不带命令输出（真实 Keil 对 `BL` 的响应 `data` 为空），但**命令窗口的文本
  输出会经 0x5020 命令输出通道回传**——批次 20 据此实现了 `list_breakpoints` 的 `real` 字段（见下文）；
- `run` 后目标会命中 `main` 断点而停止；断点在退出并重新 `enter_debug` 后依然保留生效；
- **用 `flash_debug` 保证调试的是新固件**：`build_and_flash` 只负责编烧，若此前 Keil 还开着旧工程窗口，直接 `enter_debug` 会调试到旧代码；
  `flash_debug` 会先关闭所有 Keil 实例再编烧、重开工程、进调试，从机制上规避该问题。
- **`enter_debug` 是异步的**：真机实测命令返回 `status=0` 后约 **0.6~0.7s** 才真正进入调试态，
  期间 `read_mem` / `calc_expression` / `BS` 一律返回 `status=6`（Target is not in debug mode），
  表现为"enter_debug 成功但紧接着读不了内存"。现在 `enter_debug` 会轮询 `get_status` 直到确认就绪
  （默认最多 6s），返回 `ready` / `ready_waited_ms`，未就绪时给 `warning` 而不是假装成功。
- **断点命令的成功返回码不是 0**：真机 `BS` 成功时可能返回 `status=22`（断点已创建），
  `BK` 可能返回 `23`（已删除）/`24`（未找到）。现在这些断点类返回码统一归一化为成功
  （附 `note` 说明实际返回码），避免"断点其实已设上却报失败"；响应里携带的二进制断点结构
  改走 `output_hex`，不再解码成乱码文本。
- **halt 之后首个 PC 可能是上一轮的残留值**：真机实测 `run_timeout`/`stop` 后**第一次**读到的 PC
  常还是上一次 halt 的地址（例：上轮停在 `0x08000db4`，本轮首次仍读 `0x08000db4`、第二次才变成真实的
  `0x08000444`），而同一响应里的 LR/SP 已是新值。旧的"PC 落在 FLASH 段即认可"启发式挡不住这类脏值
  （复位向量 `0x0800024c` 同样在 FLASH 内）。现在改为按**读数收敛**判定：连续两次 PC/LR/SP 完全一致才采纳，
  并返回 `pc_confidence: high/low`；`low` 表示未收敛，PC 不可信。
- **调试是 halt 式的，挂停时现象会停滞**：只要保持调试连接，目标要么被挂起、要么被断点拦停，
  LED/串口输出等外设现象随之静止——这是调试本质，不是工具缺陷。观察真实运行现象请在 `run` 之后
  不再 stop/读内存，或 `exit_debug` 让目标自由运行。
- **编译/烧录超时可配**：`build_project` / `rebuild_project` / `flash_download` / `build_and_flash`
  新增 `timeout_s`（0 = 默认：编译 1800s、烧录 600s）。旧默认 300s 会把大型工程的"还在编译"误判成失败；
  超时现在返回 `exit_code=-1` 与明确说明。
- **响应帧配对（防"拿到上一条命令的响应"）**：Keil 的响应队列可能残留历史请求的响应
  （跨会话/命令被拒后尤其明显），旧实现会把残留帧当成本次响应，出现读内存报 `status=6`、
  断点报 `22` 等错位现象。协议层现按响应帧头 `r_cmd == 请求命令码` 配对，不匹配的陈旧帧丢弃
  （上限 64 个，防死等），真机日志可见"跳过 N 个陈旧响应帧后取到 0x.... 的响应"。
- 目标运行期间 UVSOCK 会推送异步消息，堆积在 socket 缓冲会导致后续命令读响应错位
  （典型报错"AMEM 响应数据过短"）。本实现已在发送请求前自动清空残留。
- **`UV_DBG_STATUS` 的 r_status（响应码）恒为 0，真实运行状态在响应 `data` 低字节**
  （`data[0]==0` 停止、`data[0]==1` 执行中）。若用 r_status 判断，会在 run 后误报"已停止"、
  退出调试后误报"执行中"（把错误消息 data 首字节 `0x01` 当运行标志）。
  正确做法（见 `mdkdebug/client.py` 的 `get_status`）：仅当 r_status 为成功时才解析 `data[0]`，
  `status=6`（未处于调试）等错误状态优先正确反映。
- **编译/烧录自带"前置健康检查 + 自愈"**：`build_project` / `rebuild_project` / `flash_download` /
  `build_and_flash` 执行前先取一次调试通道健康快照，执行后再取一次；**仅当"编译前通道可用、编译后不可用"**
  时自动重启 Keil 并重建 UVSOCK 会话（`launch_detached` → 等 4823 监听 → 丢弃旧连接），
  省掉"编译成功但调试连不上、得再手工 restart_keil 一轮"的往返。结果里始终带 `keil_before` / `keil_after`，
  发生恢复时附 `keil_recovered` / `keil_wait_ms` / `keil_note`。用户本来就没开 Keil（前后都不可用）时
  **不会**擅自拉起，避免无谓弹窗打断；`ensure_debug_channel=false` 可整体关闭该行为。
  > 真机实测：构造"编译完成即关闭 GUI 实例"的故障点后，工具在 **3.7s** 内自动重启 Keil（PID 换新）、
  > 恢复 4823 监听并重建连接，随后 UVSOCK 命令立即可用。另两次常规验证（`launch_detached` 启动 /
  > 普通 `Popen` 启动 GUI 实例）下 `UV4 -r` 均**未**带走 GUI 实例——"命令行编译带走实例"的根因是实例
  > 继承了调用链的 job，批次16 改用 `CREATE_BREAKAWAY_FROM_JOB` 启动已从根上规避，自愈负责兜底。
- **`BL` 输出其实经命令窗口通道回传（批次20 修正前述结论）**：`BL` 的文本会经**命令输出通道（0x5020）**
  回传，格式形如 `0: (E 0x08000DB4) '..\main.c\77', CNT=1, enabled`（执行断点）、
  `3: (A WR 0x20000000 len=1) '0x20000000', CNT=1, enabled`（**数据观察点**）。
  现在 `list_breakpoints` 新增 `real` / `real_total` 字段给出**板上真实断点表**（Keil 断点编号、
  类型 exec/access、访问方式 WR/RD、地址、长度、表达式、命中计数、启用状态），
  这也是"清除数据观察点必须按编号"的依据。
- **`BL` 的 `CNT` 不是命中次数（批次22 真机结论，修正前述理解）**：同一断点连续命中 3 次，
  `BL` 输出的 `CNT` 恒为 `1`；观察点命中后同样不变。结合 `.uvoptx` 里的 `break_if_rcount="1"`，
  该字段是**断点的计数条件设置值**，不是命中计数，不能用来判断「哪个断点命中了」。
  因此 `wait_breakpoint` 的命中判定为：① 先按 PC 匹配代码候选（命中即 `hit_kind=code`，
  并从断点表快照里补出 `hit_entry`，来源标 `source=pc`）；② 若某条断点 `CNT` 确实递增
  （其他 Keil 版本可能如此），以它为准，来源标 `source=cnt`；③ 否则当「目标已停止 + PC 不在任何
  代码候选 + 存在数据观察点」时判为观察点命中（`hit_kind=watch`，`hit_entry.source=inferred`，
  并给 `cnt_note` 说明依据已降级）。真机实测观察点场景：`hit=true` / `hit_kind=watch` /
  `hit_entry.kind=access` / `cnt_note` 点明 CNT 不可用——**此前「实测已命中仍报 hit:false」的问题已修复**。
- **数据观察点按地址清不掉，必须按 Keil 编号清（批次20 真机缺陷）**：真机 `BK 0x20000000` 时
  UVSOCK 层回 `status=0`「成功」，命令窗口却报 `*** error 72: invalid item number`，断点依旧生效——
  只看 `status` 会把「没清掉」当成功上报，AI 据此继续调试会莫名停在旧断点上。现在命令窗口命令统一走
  **窗口级校验**：执行后一并取回窗口输出，命中 `*** error N: ...` 即判失败并附 `console` / `errors`；
  `clear_watchpoint` / `clear_all_watchpoints` 先用 `BL` 解析真实编号再 `BK <编号>`（返回
  `cleared_by` / `bp_number` / `resolve_note`），解析不出才回退按地址 / 符号。
- **`BK *` 一键清空（`hard=true`）**：`.uvoptx` 会携带上次会话的持久化断点 / 观察点，进入调试后照旧生效——
  本项目例程就曾在 scatter 拷贝阶段被一个 `0x20001000` 写观察点拦停，表面却表现为
  「`wait_breakpoint(main)` 等不到命中」（PC 实际停在 `0x80001d8` 的 `!!handler_copy`）。
  `clear_all_breakpoints(hard=true)` / `clear_all_watchpoints(hard=true)` 执行 `BK *` 一次性清空
  Keil 侧全部断点，并返回 `real_after` 作为「是否真清干净」的复核证据；因会连带清掉非本服务设置的断点，
  故设为**显式**参数而非默认行为。
- **`BS` 对已存在断点报 `error 145`，应视为成功**：真机重复 `BS main` 时窗口报
  `*** error 145: Redefinition: item already exists`。对「设置断点」语义而言断点确实存在，
  故归一化为 `ok=true` + `already_exists=true` + `note`，避免 AI 无谓重试。
- **`enter_debug` 遇「已在调试态」不再报失败**：目标本来就在调试态（`status=10`）时旧实现会报「进入失败」，
  现在返回 `ok=true` + `already_in_debug=true` + `note`，省掉一轮无意义的 `exit` / `enter`。
- **`wait_breakpoint` 未命中不再静默**：目标已停止但 PC 不在候选断点地址时，除 `hit=false` 外还给出
  `note`（说明当前 PC 与候选地址），并附可操作建议：先 `run` 再 `wait_breakpoint`；或用
  `list_breakpoints` 核对断点是否还在、`.axf` 与板上固件是否一致（符号漂移会导致地址对不上）。
- **已用 STM32F4 例程完成 20+ 个工具端到端全功能真机测试**：版本/状态、表达式、内存读写、
  运行控制（run/stop/reset/step/run_timeout/run_to_line）、断点管理（set/clear/list）、进出调试、
  状态快照（`snapshot`）、变量组（`watch`）、结构体字段概览（`read_struct`）、数据断点
  （`set_watchpoint` 读触发暂停）、局部变量读取（`read_locals`）、寄存器组（`read_registers`）、
  反汇编（`disassemble`，地址与符号名两种路径）、一键诊断（`diagnose`）等全部通过。
  > 说明：`read_struct` 对**局部**结构体的字段值读取依赖正确停靠帧（reset 后首次进入函数内部）；
  > 全局符号 / 正确停靠下的结构体则稳定返回布局与运行时值。
- **进入调试时 Keil 会自己烧录（`Update Target before Debugging`）**：Keil 的 `Utilities` 页勾选该选项时
  （`.uvprojx` 写作 `<Utilities><Flash1><UpdateFlashBeforeDebugging>1</UpdateFlashBeforeDebugging>`，
  Keil 默认勾选），**点 Debug 进调试前 Keil 会自动把最新 .axf 下载进 Flash**——等价于一次烧录。
  所以「编译完直接进调试」就够了，不必先 `flash_download` 再 `enter_debug`；反过来说
  `enter_debug` 本身就是**有烧录副作用**的操作，工具描述里已如实标注。
  该选项的取值可由 `read_project_config` 的 `update_flash_before_debugging` 字段查询；
  `flash_debug` 据此自动选路：勾选 → 只编译（`flash_plan=debug_download`），未勾选 → 显式烧录
  （`flash_plan=explicit_flash`），两条路径都保证进入调试时跑的是新固件。
- **第 1 部分全功能回归 66 项、第 2 部分（编译 / 烧录 / Keil 连接管理）17 项，真机全部通过**
  （2026-09-17，STM32F401 例程 + UVSOCK@4823）：环境自检、进出调试、符号与表达式、内存读写、
  寄存器与反汇编、断点与命中等待、运行控制与诊断、批量命令，以及
  `build_project` / `rebuild_project` / `flash_download` / `build_and_flash` / `flash_debug`
  与 `launch_uvision` / `close_uvision` / `restart_keil` / `reset_connection` / `keil_health`。
  > 备注：`launch_uvision` 后 UVSOCK 就绪需要数秒（脚本需轮询 `keil_health`，
  > `restart_keil` 已内置等待与重连，推荐直接用后者）。

- **`wait_breakpoint` 只把「新发生的停止」算命中（批次23 真机修复）**：`run_timeout(300)` 把目标停在
  某行后紧接着调 `wait_breakpoint`，旧实现会立刻返回 `hit=true` 且 PC 与上一次完全相同（把「进来时已停」
  当成「等到了命中」）。现在进入等待时先记住目标起始运行态，只接受等待期间新发生的停止，判据有三条
  （结果里 `new_stop_basis` 标明用了哪条）：① `ran_observed` 亲眼见到运行（真机常规路径，实测 `polls=6`
  才停）；② `run_issued` 最近一次 `run`/`step` 晚于最近一次「观察到停止」——真机上 `run` 后目标可能在
  一次 UVSOCK 往返内就命中断点，来不及看到运行态；③ `pc_moved` 停止时 PC 与调用时不同（手工在 Keil 点
  Run 也算）。三条都不成立 → `hit=false` + `stop_is_new=false` + `note`「目标在等待期间未曾运行」。
  起始就停着时先给 0.4s 宽限窗口只查状态（`run`/`step` 是异步命令），再读 PC 比对，避免误杀合法命中。
- **`read_peripheral` 的 `regs`/`fields` 兼容字符串数组（批次23）**：`regs: ["MODER","ODR"]` 过去会崩
  （`'list' object has no attribute 'replace'`），现在 `str` / `list` / `tuple` 都接受，分隔符支持
  逗号/分号/竖线/空格，数组里混用全名（`GPIOC_MODER`）与裸名也行；`fields=["off"]` 等价 `fields="off"`。
  注意类型标注已放宽为 `str | list`（否则框架层就按 `string` 校验并拒收数组）。
- **只读工具的输出体量（批次22）**：`read_peripheral` 默认全寄存器 + 位域解读，一次可达数千字符，
  真机实测 GPIOC 全量 7738 字符、只取 `MODER,OTYPER` 关位域后 351 字符（≈1/22）。上下文吃紧时优先用 `regs`。
- **App 侧重定位直接读符号（批次22）**：`set_reloc_delta(0x1000)` 后 `read_variable(test_array)`
  自动给出 `link_address=0x20000000` / `run_address=0x20001000`，不必再手工做 `- SVCRT_RELOC_DELTA` 换算；
  `find_symbol` 同步返回 `run_addr`。注意显式数字地址**不**做偏移（调用方给的通常已是运行地址）。
- **`run_timeout` 的时长口径（批次22）**：真机 `timeout_ms=1500` → `actual_run_ms=1500`、
  `stop_wait_ms=218`、`total_ms=1750`。此前反馈的「请求 137ms 实测 150~230ms」是 Windows sleep 粒度
  （≈15.6ms）与 `waited_ms` 混算 stop 确认耗时所致，现四段分开、`timing_note` 说明语义。


## 二、并发调用与串行化


**一条 UVSOCK 通道上并发发命令会互相穿插，写入可能被静默吞掉。** 真机踩过：并行发多条
`write_mem` 到同一 UVSOCK，其中一次写入被另一次静默覆盖，导致误判为「看门狗又复位了」，
绕了很大一圈。mdkdebug 现在从三层把这件事管住，调用方不必再靠「自己记得串行」：

| 层次 | 机制 | 能挡住什么 |
|------|------|-----------|
| 进程内 | `threading.RLock`（客户端连接层） | 同一服务进程内多线程/多任务交错发命令 |
| 跨进程 | 锁文件 `uvsock_<port>.lock`（`EndpointGuard`，可重入、超时降级） | **多个 mdkdebug/MCP 实例**各持一条连接抢同一台调试器 |
| 可观测 | 实例心跳 `inst_<pid>.json` + 遥测统计 | 让「还有谁在抢」**看得见**：`keil_health.mdkdebug_instances`、`get_status.serialization` |

要点：

- 闸门是**可重入**的，`batch` 内逐条调用子工具不会自锁；
- 闸门**从不阻塞到失败**：等锁超过 `LOCK_WAIT_DEFAULT`（15s）即降级放行，并把这次竞争如实
  记入 `stats`（`lock_timeouts` / `foreign_pid` / `degraded`），`keil_health` 会据此给出
  `concurrency_warning`——不为了「绝不阻塞」把工具卡死，也不假装没发生；
- 检测到**其他实例**（心跳新鲜且进程存活）时，警告会直接列出对手 PID：
  「检测到还有 N 个 mdkdebug 进程（PID …）在驱动同一 UVSOCK：并发调用会互相穿插，写入可能被
  静默覆盖。请只保留一个 MCP 服务实例（关掉多余的客户端连接/旧进程）后重试。」

**调用方建议**：

1. 需要严格顺序的多步写入，用 `batch` 一次提交（内部逐条串行），比并发单发更可靠；
2. 关键写入用 `write_mem` 的默认回读校验（`verified=false` 即「没写进去」，别据此推断目标行为）；
3. 出现可疑的「自己变了」现象时，先看 `keil_health` / `get_status` 的并发字段，再怀疑代码；
4. 同一个串口不要被两处同时打开（本服务串口监听 + Keil 串口窗口会互相抢占，报 WinError=5）。


## 三、读到的东西到底算不算数（脏读防护 / 停止确证 / 粘滞位）


调试工具最贵的一类错误是「**用不可信的数据下了结论**」——读到整帧 0 就说变量被清零、看到 `UsageFault` 位就说刚才跑飞了、`stop` 回 ok 就当目标已经停下来。批次30 针对这三件事各加了一道防线：

**① `read_mem` 的脏读防护（`verify`，默认 `auto`）**

- 触发复读的两个条件：首帧**整帧退化**（整片全 `0x00` / 全 `0xFF`），或距最近一次 `stop` 不足 1 秒（停止是异步生效的，这期间的读最容易拿到脏值）；
- 复读最多 3 次，**连续两次一致才采纳**（与 `get_current_location` 的 PC 收敛判定同一套语言）；
- 返回 `read_confidence`（`high`/`low`）、`reread_count`、`reread_consistent`、`degenerate`、`since_stop_s`；首帧是脏值时 `first_read_hex` 留证、`data_hex` 换成可靠值并附 `warning`；
- Flash 区段读出全 `0x00` 时另给专门提示（**已擦除的 Flash 应读出 `0xFF`**，全 0 更像读取失败）；
- 反过来，Flash 区**稳定**读出全 `0xFF` 按「已擦除」处理：给 `content_note` 说明这是预期内容、置信度保持 `high`（真机读 `0x08022000` 即如此，避免把正常内容误报成脏读）；
- `verify=true` 无条件确认（对某次结果不放心时），`verify=false` 关闭（大块搬运省时间）。

> **看到 `read_confidence=low` 或 `degenerate` 就不要据此下结论**，先 `get_status` 确认目标已停止再重读。

**② `stop` 的停止确证**

`stop` 命令返回不代表目标已停（真机实测 stop 回 ok 后紧跟的 `get_status` 仍报「执行中」，`run_timeout` 内部一直有 `wait_stopped` 而单独的 `stop` 没有）。现在 `stop` 默认轮询确证并返回 `stopped` / `stop_verified` / `waited_ms` / `state_after_stop`——**`stop_verified=false` 时不要读内存/寄存器、也不要据其下结论**。

**③ `CFSR`/`HFSR` 是粘滞位**

读到 `UsageFault` 不代表此刻正在 `UsageFault`：这两个寄存器**写 1 清除或复位才归零**，异常处理完不会自动清。故 `fault_report` 返回 `fault_timing`（且**无论是否置位都给出 `cfsr`/`hfsr` 字段**，避免把「字段缺失」误读成「读不到」）：

| `timeliness` | 含义 | 该怎么做 |
|--------------|------|----------|
| `current` | ICSR 显示目标正处在 fault handler 里 | 可以直接把 `cfsr.reasons` 当作本次异常原因 |
| `sticky` | 位置着，但当前不在任何 fault handler | **别当当前故障**；很可能是上次调试/上次上电以来的残位 |
| `none` | 两个寄存器都没置位 | 当前没有记录到故障 |

确证「是否还有新异常」的固定套路：

```text
clear_faults()                 # 清位（W1C），并记录 last_cleared
run()                          # 让程序继续跑一段
fault_report()                 # 位又置起来 → 新发生的；保持 0 → 原先那些是历史残位
```


## 四、串口占用与释放（用完就还 / 一边收一边发）


**调试完了串口还被 MCP 占着**，会导致 Keil 串口窗口、其他串口工具打不开（`WinError=5`）。
mdkdebug 的做法是：**把「端口占用」和「日志生命周期」拆开**——释放端口不等于丢日志。

| 触发点 | 说明 |
|--------|------|
| `exit_debug` 成功 | 调试这一段结束，顺带释放（返回 `serial_release`） |
| `flash_download` / `build_and_flash` | 有 `release_serial`（默认 `true`）；想边烧录边看日志可设 `false` |
| `flash_debug` / `close_uvision` / `restart_keil` | 关掉 Keil 实例后口自然该还（新实例/串口窗口可能要开这个口） |
| 空闲兜底 | `idle_release_s`（默认 900 秒，`0`=关闭）内无人访问即自动释放 |
| 进程退出 | `atexit` 钩子释放，不把 COM 口带走 |

**释放后日志还在**：ring buffer 不受释放影响，`serial_read` 照旧按 `since` 增量读；
返回值会带 `release_note` 说明「已释放 + 已收 N 行仍保留 + 需要继续采集请重新 start」。
重新 `serial_monitor_start()` 同端口同波特率会**复用同一实例**（`resumed=true`），不会丢已收日志。

```text
serial_monitor_start(port="COM9")          # 开始收日志
run()                                      # 跑一段
serial_read(since=上次 next_seq)            # 取增量
exit_debug()                               # 调试结束 → 自动释放 COM9（日志保留）
serial_read()                              # 仍能读到之前收到的行
```

### 一边收一边发：`serial_write`

只读的监听器覆盖不了「下发 shell 命令 / 给 bootloader 发指令 / 分段下发镜像」的用法。
现在端口按**可读可写**（`GENERIC_READ|GENERIC_WRITE`）打开，收与发共用同一个句柄；
拿不到写权限时自动退回只读（监听照常工作，`can_write=false` 明确告诉你这个口发不出去）。
`serial_monitor_start` / `serial_monitor_status` 返回 `port_ready`（端口是否已真正打开）与 `can_write`；
**启动接口会等端口就绪再返回**（真机实测 start 返回瞬间端口还没打开，`can_write` 会误报 `false`，
让人以为这个口只能收不能发——现在这两个字段可直接采信）。

```text
serial_monitor_start(port="COM9", baud=115200)   # 持有端口
serial_write(text="help")                        # 下发命令（默认追加 CRLF）
# → {written: 6, read_after: {count: 2, lines: ["msh />help", "   commands: ..."]}}
serial_write(hex="7e 01 00 ff", eol="none")      # 二进制/镜像片段
serial_read(since=上次 next_seq)                  # 长响应可继续增量取
```

#### 坑：`eol` 传转义字符被 `.strip()` 静默吃掉（批次31）

旧实现里 `eol` 先做 `str(eol).strip().lower()` 再匹配 `crlf` / `lf` / `cr` 三组关键字。
而 `"\r"`、`"\n"` 本身就是**空白字符**，`strip()` 之后变成空串，落进所有分支之外 ——
结果是**换行一个字节都没发出去，工具却照样返回 `ok:true`**，只能靠 `read_after`
「没有新行」间接暴露。真机实测（同一块板、同一根线）：

| 调用 | 旧 `written` | 旧结果 |
|------|-------------|--------|
| `text:"pool"`（不传 eol） | 6 | 执行成功（默认 crlf 生效） |
| `text:"pool", eol:"cr"` | 5 | 执行成功 |
| `text:"pool", eol:"\r"` | 4 | **命令不执行**（换行没发出去） |
| `text:"info", eol:"\r"` 后 `text:"help"` | 4 / 4 | 两次都没换行，行缓冲累积，直到改用 hex 发 `0x0D` 才执行，报 `Command not found: infohelphelp` |

更要命的是**「回显 ≠ 执行」**：目标对收到的每个字符照样回显，看着字节通了，命令却没跑。
现在的做法：

- `eol` 归一化**先取原始串、把真实控制字符映射成转义写法再比对**，`"\r"`（JSON 转义）
  与字面 `\\r` 等价，另收 `cr+lf` / `windows` / `dos` / `unix` / `mac` / `off` / `raw` 等别名；
- 无法识别的取值**明确返回 `eol_unrecognized` + `warning` + `eol_hint`**（列出全部可用取值），
  不再静默按默认值发；
- 返回值把「到底发出去了什么」摊开：`sent_hex` / `sent_bytes` / `eol_input` / `eol_applied` /
  `eol_bytes_hex`，口径与 `write_mem` 的 `verified` / `readback_hex` 对齐 ——
  行尾没发出去时 `eol_applied` 是 `null` 并附 `warning`；
- 回显判定改用**字节增量** `read_after.bytes_new`（比「新增了几行」灵敏，半行/逐字符回显也能察觉）；
- `eol="auto"`：先按 `crlf` 发，若毫无回显再补发单个 `\r`（SVCrtOS shell、RT-Thread msh 这类
  只认单 `\r` 的目标），返回 `eol_fallback:"cr"` 且 `sent_hex` 含两次下发；
- 没用 `auto` 又毫无回显时附 `no_echo_hint`，直接把可用取值与替代做法（`eol="cr"` 或走 hex）点出来。

> 教训：**参数归一化不要在有意义的字符上做 `strip()`**。「发出去的字节」必须可被调用方看见，
> 否则 `ok:true` 会掩盖「其实什么都没发」——这与 `write_mem` 需要 `verified` 是同一类问题。

## 五、历次改进留档（按批次）

> 以下条目是早期批次直接追加在 README 尾部的改进说明（原先错落在「参考与致谢」之后），
> 保留在此作为留档。其中大部分能力已并入上方章节与 README 工具表。

- **连接前先做健康自检，失败不再"干等"**：新增 `keil_health`（纯 ctypes 进程快照 + 端口探测，
  Keil 未运行时也能正常返回），给出 `keil_alive` / `uv4_pids` / `port_listening` / `uvsock_ready`
  与 `code`（`ok` / `keil_not_running` / `port_not_listening` / `port_occupied`）+ 可操作建议；
  检测到 Keil 模态对话框时列出标题（`modal_dialogs`）。连接失败与命令超时现在都会带上这份诊断，
  不再只抛裸 `WinError 10054` 或干等到超时。
- **一次超时/连接被重置后自动复位连接**：`reset_connection` 丢弃 UVSOCK 连接与接收缓冲，
  下次调用自动重连（无需重启 Keil）；`restart_keil` 则一步完成"关闭所有 Keil 实例 →
  脱离父进程重启 → 等 UVSOCK 就绪 → 重建连接"。真机实测：Keil 中途被杀后，原先只能靠人工
  "关掉再开"，现在命令秒级失败并给出原因。
- **拉起 Keil 必须脱离父进程 job**：UV4 用 `CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS |
  CREATE_NEW_PROCESS_GROUP` 启动，否则会随调用链（MCP 服务/脚本）一起被回收——这正是
  "Keil 反复被杀/操作了没反应"的根因。`launch_uvision` 已内置该方式并返回 `pid` / `breakaway`。
- **编译烧录与调试是两条通道**：`UV4 -b/-f` 命令行即使 Keil 已死也能成功（自己会新起实例），
  因此"编译成功"不代表调试连得上。现在 build/flash 结果里附带一份 Keil 健康快照（`keil` 字段），
  可据此判断调试通道是否可用。
- **PC 可信度必须显式标注，别让陈旧值把排查带偏**：真机踩过——目标明明在跑（串口实时响应），
  `run_timeout` 却报出 `main.c:107 HAL_Init`，或连续多次报同一个地址，据此怀疑「卡死/反复复位」
  会白绕一大圈。现在寄存器读取在收敛判定之外，读完还会**复查目标是否真的停着**（停止判定本身
  是异步的），并返回 `pc_confidence` / `halt_verified` / `stop_verified`；发现目标其实在跑就
  直接降级为「PC 不可信」并给 `warning`，不再把陈旧地址当停靠点。同一 PC 连续出现时附
  `repeat_count` / `repeat_warning` 提醒交叉确认。
- **`wait_breakpoint`：带超时地等断点命中**（不必再读 PC 猜「App 有没有调用到内核某函数」）。
  支持 `symbol` / `address`，都不传时用工程 `.uvoptx` 里的持久化断点作候选；命中返回
  `hit_address` / `hit_count` / `waited_ms` 并回落到源码位置，`breakpoint_stats` 可查累计命中次数。
- **`enter_debug` 主动报告 `.uvoptx` 遗留断点**：这些断点会随进调试被 Keil 自动恢复（软件断点
  命令清不掉），是「目标行为诡异」的隐蔽干扰源，现在进调试时就把数量与前几条报出来。
- **`exit_debug` 失败能给出生病部位**：不再只回一句连不上——会附 `keil_health` 快照，若判定
  Keil 已退出则明确说明「会话已丢失」并指向 `restart_keil`；若被模态框挡住则报出对话框标题。
- 细节：`search_mem` 支持 `pattern_text`（直接搜 `appstat` 这类字符串，不用手工转十六进制）；
  `read_peripheral` 的每条寄存器同时给裸名（`MODER`）与全名（`GPIOC_MODER`）字段。
