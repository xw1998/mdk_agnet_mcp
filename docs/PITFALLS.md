# 踩坑与实测指南（PITFALLS）

> 本文档收录**真机实测结论、踩过的坑，以及由此形成的可靠性约定**，面向排障与二次开发。
> 想快速上手请直接看 [README](../README.md)；每个坑对应的工具行为也已在 README 的工具表里给出结论。

## 目录

- [一、真实 Keil 实测要点](#一真实-keil-实测要点)
- [二、并发调用与串行化](#二并发调用与串行化)
- [三、读到的东西到底算不算数（脏读防护 / 停止确证 / 粘滞位）](#三读到的东西到底算不算数脏读防护--停止确证--粘滞位)
- [四、串口占用与释放（用完就还 / 一边收一边发）](#四串口占用与释放用完就还--一边收一边发)
- [五、断点地址 / 看门狗 / Cache（批次32 真机实测）](#五断点地址--看门狗--cache批次32-真机实测)
- [六、串口等待与统一信封（批次33 真机实测）](#六串口等待与统一信封批次33-真机实测)
- [七、UV4 命令行批处理调试（`-d` + 初始化文件，真机实测）](#七uv4-命令行批处理调试-d--初始化文件真机实测)
- [八、SVD 解码与工程文件编辑（批次35 真机实测）](#八svd-解码与工程文件编辑批次35-真机实测)
- [九、历次改进留档（按批次）](#九历次改进留档按批次)
- [十一、非 MDK 链路（工具链 / OpenOCD / trace）](#十一非-mdk-链路工具链--openocd--trace)

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

## 五、断点地址 / 看门狗 / Cache（批次32 真机实测）

### 坑：`error 57: illegal address` 的真身是 **Thumb 位**（bit0=1）

- 现象（第 17 轮反馈）：`set_breakpoint("0x080D9405")` 报 `error 57: illegal address`，
  而改成符号式 `set_breakpoint("main")` / `("stat_flow_push")` 就成功——
  「同一个地址，换个写法就不行」。
- 真机对照实验（同一函数 `main`，`calc_expression("&main")` = `0x08000DB4`）：

| 下断参数 | 真机结果 |
| --- | --- |
| `BS 0x8000DB4`（偶地址，即 `&main` 的原值） | 成功 |
| `BS 0x8000DB5`（即 `&main \| 1`） | `*** error 57: illegal address (0x08000DB5)` |
| `set_breakpoint("main")` | 成功（符号路径先 `calc_expression("&main")`，拿到的是**偶地址**） |

- 根因：函数指针 / `&符号 \| 1` 得到的值带 Thumb 位（bit0=1），Keil 的 `BS`
  **对奇数地址一律拒绝**。符号路径之所以「看起来没问题」，只是因为它经 `calc_expression`
  拿到的是偶地址——裸地址绕过了这一步，于是出现「符号能下、地址不能下」。
- 修法：`_thumb_even()` 只对**代码区（< 0x20000000）且为奇数**的地址清 bit0；
  `0x20000000` 以上的数据地址（数据观察点、App 重定位区）保持原样，
  避免把合法的奇数数据地址改坏。`set_breakpoint` / `set_conditional_breakpoint` /
  `clear_breakpoint` 三条路径都做了同一套归一，并返回 `thumb_bit_stripped` /
  `address_normalized` 说明「改过」，不静默改地址。
- 失败时不再只回一句 `error 57`：`diagnosis` 给出错误码含义（57 / 65 / 72 / 145）、
  地址落在哪个内存区、是否在当前 `.axf` 覆盖范围内，以及 4 条排查建议
  （镜像与符号是否匹配、用 `find_symbol` 搜符号、App 重定位用 `set_reloc_delta`、
  改用符号名下断）。
- 真机验证：`BS 0x8000DB5` 仍报 57（前置），而 `set_breakpoint("0x08000DB5")` 成功且实际下发
  `0x8000DB4`；`clear_breakpoint("0x08000DB5")` 同样成功。

> 教训：**「符号路径能用」不等于「地址路径也能用」**。同一语义的两条输入路径必须做同一套归一——
> 只修其中一条，用户就会撞上「同一个地址，换个写法就失败」。

### 坑：halt 期间看门狗（IWDG）照样跑，停久了现场被复位清掉

- 现象（第 17 轮反馈）：新会话 / 目标复位后 DBGMCU 冻结位会被清零，此时 halt 超过看门狗
  溢出时间就被 IWDG 复位、RAM 现场全丢，表现为「停下来看一会儿，变量就全变初值、断点也没了」。
- 真机实测（STM32F429，DEV_ID=0x433）：

| 寄存器 | 复位后实测值 | 含义 |
| --- | --- | --- |
| `DBGMCU_IDCODE` @0xE0042000 | `0x10016433` | DEV_ID=0x433，可用于探测基址 |
| `DBGMCU_CR` @0xE0042004 | `0x00000007` | 常规调试位 |
| `DBGMCU_APB1FZ` @0xE0042008 | `0x00000000` | **IWDG(bit12) / WWDG(bit11) 均未冻结** |
| H7 基址 @0x5C001000 | 读失败 | M4 上不存在，故基址**必须运行时探测** |

- 修法：`watchdog_freeze(action=status/enable/disable)` 读-改-写 `DBGMCU_APB1FZ` 并**回读确认**
  （返回 `before` / `after` / `verified` / `iwdg_stopped` / `wwdg_stopped` / `all_frozen`）；
  `stop` 与 `enter_debug` **默认自动置位**（`freeze_watchdogs=true`，可关），返回 `watchdog_freeze` 供核对。
  基址用「逐个候选读 IDCODE + 校验 DEV_ID 非 0/0xFFF」探测，而不是按内核型号硬编码——
  同内核家族的系列基址也可能不同（H7 在 `0x5C001000`）。
- 真机验证：`enable` 使 `APB1FZ` 由 `0x00000000` → `0x00001800` 且 `verified=true`；
  `stop` 后 `all_frozen=true`；`stop(freeze_watchdogs=false)` 确实不置位；`enter_debug` 同样自动置位。

> 注意：冻结位**只在调试暂停期间**生效，且**目标复位 / 新会话后会被清零**——
> 不能「进门设一次就完事」，必须挂在 `stop` / `enter_debug` 上自动补。

### 坑：D-Cache 开着时，DAP 直读 / 直写都不代表内存真实状态

- 现象（第 17 轮反馈）：H7 开着 D-Cache 时，DAP 直读 RAM 可能是陈旧值、直写可能被脏行回写覆盖，
  而工具**全程没有任何提示**。
- 真实机理：CPU 写 RAM 后新值可能还停在缓存脏行里未回写 → 调试器**直读内存读到的是旧值**；
  调试器写内存后，若 CPU 侧同一地址有脏行，该行稍后被回写会**覆盖掉刚写下的值**。
  **两种情况都不会报错**，「读到的 0」可能只是缓存没刷，「我写下去了」也可能稍后失效。
- 修法：`cache_info` 读 `SCB->CCR` 判定 DC / IC，并粗略解析 `CCSIDR` 得到行/路/组与容量；
  `read_mem` / `write_mem` 命中 **SRAM（0x2000_0000~0x3FFF_FFFF）** 且 DC=1 时附 `cache` 字段提示；
  探测结果带 5 秒 TTL 缓存，不给每次读写增加额外开销。M3/M4 无 D-Cache、M7 默认不开时
  **不产生任何噪声字段**（不误报）。
- 真机实测（STM32F429 / Cortex-M4）：`CCR = 0x00000200`，**DC=0、IC=0**——M4 既无 D-Cache
  也无 I-Cache（`0x00000200` 的 bit9 与缓存无关，别误当成缓存使能位）。此时 `read_mem` 读 SRAM
  不带 `cache` 字段，`cache_info` 给 `note` 而非 `warning`；真机 D-Cache 场景（M7）只能靠 mock 验证。

> 教训：**「读到的值」和「写下去的值」都要标注可信度**。D-Cache 场景下调试器只能保证「访问了内存」，
> 不能保证「这就是 CPU 视角的值」——必须显式告诉调用方，而不是让它在不知情的情况下据此下结论。

## 六、串口等待与统一信封（批次33 真机实测）

### 6.1 `serial_expect` 只认「调用之后新增」的输出

目标一直在刷日志时（本示例每秒一行 `hb <tick>`），"等某句话出现"最容易踩的坑是
**把缓冲区里早就在刷的老内容当成这次请求的响应**——那样任何请求都会"秒回成功"。
`serial_expect` 的基线取调用瞬间的 `next_seq`，只有显式传 `since=0` 才允许回看历史。

真机实测（COM9 / 115200，示例工程 USART2）：
- 纯等待心跳：`serial_expect(pattern="hb")` → 254ms 命中 `hb 7000`；
- 原子请求-响应：`serial_expect(pattern="pong", send="ping")` → 51ms 命中 `pong`，
  返回 `sent_hex=70696e670d0a` / `eol_applied=crlf`（到底发出去什么摆在明面上）；
- 命令侧：`info` → `devid=0x10016433 sysclk=16000000Hz`、`help`、`echo <带空格文本>`、
  未知命令回 `ERR unknown cmd`，全部按预期命中；
- 半行（不带 `\n` 的输出）靠 `include_partial` 兜住，命中时 `matched_source=partial`。

### 6.2 超时不是「失败」，两种超时必须分开（真机踩到）

`serial_expect` 超时**曾经**落进 `unknown-error`，`next_actions` 让调用方「调 keil_health /
读 Keil 异步消息」——而真实原因是串口没等到内容，方向完全不对。现在超时带机器可读标识：

| 场景 | `timeout_kind` | `error_code` | 下一步该做什么 |
|---|---|---|---|
| 一个字节都没新增 | `no-data` | `serial-expect-timeout-no-data` | 查下发是否成功（`sent`/`sent_hex`）、波特率与接线、目标是否在输出 |
| 有新增但对不上 pattern | `no-match` | `serial-expect-timeout-no-match` | 放宽 pattern（`regex=false` / `case_sensitive=false`）、读返回的 `lines` 当线索 |

配套的一条通用约定：**归类优先用工具给出的结构化标识，其次才按文本猜**。
只靠中文文本匹配时，"正则编译失败"会被"编译失败"规则抓成 `build-failed`——这类误判
加规则时极易引入；凡是有结构化字段（`timeout_kind`、退出码…）就不要再靠猜。

### 6.3 示例工程的地址不要写进测试常量

给示例工程加一个 `usart.c` 就会让 `main` 的链接地址移位，于是「断言 `main == 0x8000db4`」
这类测试会集体失效（本轮 2 个历史用例就是这么挂的）。正确做法是**从当前 `.axf` 现算**
（`Locator.symbol_addr("main")`）再断言，让测试跟着工程走。

### 6.4 真机验证记录（STM32F401RCTx / COM9 DAPLink VCP）

- `build_project` → `flash_download` 新固件上板：UV4 退出码 0；
- `serial_list_ports`：列出 COM9 + `likely_chip="mbed / DAPLink VCP"`（VID 0D28:PID 0204）；
- `clean_project`（`-c`）：`.axf/.hex/.o` 清空，`.map` 由 Keil 保留；
  `rebuild_project(clean_first=true)`（`-cr`）：产物恢复，0 错误 0 警告；
- 串口监听持口期间 `serial_list_ports` 标 `monitoring=true`，与其它工具共存无冲突。

## 七、UV4 命令行批处理调试（`-d` + 初始化文件，真机实测）

> 起因：有反馈说「Keil 还支持 cmd 指令方式调试，这种方式问题更少」。
> 实测结论：**这条路真实可用**，但它与 UVSOCK 交互通道是**互补关系**，不是替代关系。

### 7.1 正确姿势

- `UV4 <project> -d -j0 [-o logfile]`：进入调试模式执行初始化文件，脚本结尾用 `EXIT` 退出；
  真机退出码 0（正常结束）。
- **初始化文件不是命令行参数**，而是工程选项里的「Options for Target — Debug — Initialization File」，
  落盘位置是 `.uvoptx` 的 `<DebugOpt><tIfile>`（硬件调试）/ `<sIfile>`（仿真）。
  顺带纠正一个常见误传：`-i` 是**导入 XML 工程**（`project_import.xsd`），不是 ini。
  某开源项目把 ini 路径给了 `-o`（输出日志选项），它的 “official debug channel” 实际不执行脚本。
- **执行顺序（官方文档）**：加载映象 → 恢复调试会话设置 → **执行初始化文件** → run to main。
  所以在初始化文件里读 PC 拿到的是复位后的入口（实测 `0x080002E0`）；要停在 main 必须自己写 `g, main`
  （**逗号不能省**；实测写成 `Go main` 会让目标一路跑下去，脚本永远等不到下一行）。
- 输出落盘两条路：`LOG >>file`（命令窗口全文）/ `SLOG >>file`（串口窗口，需 `LOG OFF` 收尾）；
  `-o file` 抓的是会话输出（`Load ... / Erase Done ... / Verify OK / Application running ...`）。

### 7.2 能干什么（真机实测通过）

- `g, main` 运行到 main；`BS` / `BK` / `BL` 断点增删列：
  `BL` 输出形如 `0: (E 0x08003320) 'uart_poll', CNT=1, enabled`；
- `G` 会**阻塞到断点命中**再执行下一行（实测 `BS uart_poll` + `G` 后下一行读到 `PC=0x08003320`）
  → 脚本天然支持「跑到断点→取现场」；
- 单步命令是**缩写** `T` / `P` / `O`，写成 `Tstep` / `Pstep` / `Step` 会报
  `*** error 34, line N: undefined identifier`（Keil 把它当表达式解析）；
- `EVAL expr`、`printf(...)`、`_RWORD/_RDWORD(addr)`（无头下读内存**唯一稳妥**的方式，实测
  `printf("MEM32=0x%08X\n", _RDWORD(0x20000000))` 正常返回）；
- 结论：无人值守跑一遍「下载 → 停 main → 设点 → 跑到点 → 取现场 → 退出」是可行的。

### 7.3 别踩的坑

- **命令出错不影响退出码**：UV4 仍返回 0，错误只落在日志里（`*** error 34, line 11: undefined identifier`）。
  判成功必须解析日志、检测错误行；**只看 ERRORLEVEL 会把失败当成功**。
- **`DISPLAY` / `SAVE` 在 `-j0` 无头模式下会卡死**（本轮各挂死一次，只能超时杀进程）：
  二者依赖命令窗口 / 内存窗口 / 文件对话框。无头读内存用 `printf` + `_RDWORD`。
- **单步语义依赖窗口焦点**：无头没有焦点，实测退化为**指令级**（`T` 使 PC 从 `0x080030B0` → `0x080030B2`）。
  需要源码级单步还是走 UVSOCK 交互通道。
- 每次 `-d` 都是**完整一轮**：进调试 + 按工程设置下载 Flash（实测每轮 `Erase Done / Programming Done / Verify OK`），
  本机一轮约 15~25 s；不适合需要多次往返决策的探索式调试。
- 初始化文件路径含中文（本仓库路径里有「工作」二字）时，用不着折腾编码：**直接放到 ASCII 目录**
  （如 `%TEMP%`），ini 本体按 ANSI/GBK 写；`<tIfile>` 里不要塞 UTF-8 中文路径。
- 调试相关 uvoptx 字段（`tIfile` 等）**用完必须还原**：Keil 退出时会回写 uvoptx。

### 7.4 与 UVSOCK 通道的取舍

| 维度 | UVSOCK 交互（现有主通道） | `-d` 批处理（本轮实测） |
|---|---|---|
| 交互性 | 多轮、随 AI 判断推进 | 一次脚本一轮，中途无法决策 |
| 单轮耗时 | 毫秒~百毫秒 | 15~25 s（进调试 + 下载 Flash） |
| 能力面 | 全（寄存器/内存/断点/外设/串口/ITM） | 子集（EVAL/printf/断点/运行/单步/日志） |
| 协议风险 | 二进制结构、异步帧、status 竞态 | 官方命令层，风险低，但错误只在日志 |
| 适用 | 探索式调试、现场分析 | 可重复的冒烟/回归、UVSOCK 不可用时的降级通道 |

⇒ 结论：**两条腿都要**。批处理路线适合封成「一键批处理调试」工具（脚本生成 + 日志解析 +
错误行判定 + uvoptx 备份还原），而不是取代 UVSOCK。

## 八、SVD 解码与工程文件编辑（批次35 真机实测）

### 8.1 地址反查别用「固定窗口」拍脑袋（真机串台）

最初 `peripherals_at` 用「addr 落在 base ± 0x4000 窗口内」判归属。真机上外设基址**密集排布**：
`0x40003800`(SPI2) 与 `0x40004400`(USART2) 只隔 3 KB，固定窗口必然重叠，
实测把 USART2 的 `CR1`(`0x4000440C`) 判成了 **SPI2**。

改为两级判定：**① SVD 的 `<addressBlock>` 优先**（只有 addr 真落在块内才算命中，块越小越具体）；
**② 没有块命中才退化**为「最近前缀」（base 中取最大的 ≤ addr 者）。
另外别忘 `<addressBlock>` 会**随 `derivedFrom` 继承**——真机上 `USART2` 只是
`<peripheral derivedFrom="USART6">` 的空壳，不继承就永远走不到第一级。
结果里透出 `matched_by`（`addressBlock` / `nearest_base`）让调用方知道这一判定的把握有多大。

### 8.2 不指定器件时**绝不能**盲挑一份 .svd（比报错更危险）

真机实测：`svd_decode(address="0x40020000")` 未传器件，实现按发现顺序取了盘上第一份 `.svd`——
那是**别的芯片**的手册，于是把 GPIOA 判成 `TIMER2`，还给出了完整的寄存器清单。
**这种「看似权威的错答案」比直接报错危险得多**：AI 无法察觉自己看的是别的芯片的文档。

现在三层防护：① 不给器件时先按**当前工程的 `<Device>`**（读 uvprojx）推断；
② 推不出来且盘上候选 >1 份 → 拒绝盲挑，报错并列候选清单；③ 结果里透出 `svd_device` / `svd_file`，
选错文件一眼可见。定位包根也别猜：**`Keil_v5/ARM/PACK` 本机是空的**，
真包根在 `TOOLS.INI` 的 `RTEPATH=`；SVD 文件名按容量档（`STM32F401xE`）与订货型号（`STM32F401RCTx`）
互不包含，须按**公共前缀**匹配。

### 8.3 批处理通道的两条硬约定（都是真机踩出来的）

- **日志解析正则必须带 `re.M`**：错误行的 `*** error 34, line 4: ...` 后面必然还有别的行，
  而 `$` 默认只匹配整个字符串末尾 → **一条 error 也匹配不到**，`ok` 被误判成 `True`
  （「明明报错却报成功」，最坏的一类 bug）。同时 trace 日志与 `-o` 日志会**各记一份**，
  必须按 `(码, 行, 文本)` 保序去重，否则 `error_count` 翻倍、AI 以为踩了两个坑。
- **`.uvoptx` 还原必须是「字节级」的**：文本读入再写出会带回差异（`utf-8-sig` 读入再写出会
  **凭空多一个 BOM**），工程文件被悄悄改动。现在读前先留原始字节、`finally` 里原样写回，
  并返回 `uvoptx.byte_identical` 自证「跑完 == 没跑过」。
- 另：`<tIfile>` 唯一性校验不能拿 `subn(count=1)` 的返回值当判据——**它恒为 1**（只要有一处匹配），
  形同虚设；多 target 的 uvoptx 常有多个 `<tIfile>`，必须 `finditer` **先数再换**。

### 8.4 编辑用户的工程文件：宁可「什么都不做」也不能写坏

`uvprojx.py` 的 `_edit_tag` 曾把 `new=None` 当成新文本，于是「删除无匹配项」这种空改动会写出
`<IncludePath>None</IncludePath>`——**静默损坏用户工程**，且要等下次用 Keil 打开才发现。
现在：`new is None` 显式按 `changed=False` 处理并合并说明，空改动**不落盘**；
所有写操作前强制备份（`<工程名>.uvprojx.mdkdebug.bak`），文本级替换不重排整个工程文件，
锚点唯一性校验后再写。回归测试里专门加了「文件里不得出现字面量 `None`」的断言。

### 8.5 DWARF 的 0 号占位行会造出假地址

`address_for_line("main.c", 10)` 曾返回 `ok=true` + `address=0x00000000`：DWARF 行表会给
「文件起始」放一条**地址为 0** 的占位记录，靠前的行号会命中它。0 不是有效代码地址，
AI 会真的去 0 号地址下断点。现在 `line_to_addr` 跳过 `a<=0` 的占位行，工具侧再把 0 当作
「没有地址」→ 如实报错并给 `nearby_lines`。

### 8.6 mock 测试自身的坑：假 UV4 的 `.bat` 必须按 OEM 代码页写

用假 UV4（`.bat` + Python 回放 ini）跑全链路时，`.bat` 用 UTF-8 写会让 `cmd.exe` 按 OEM 代码页
读成乱码——含中文的解释器路径直接「系统找不到指定的路径」，退出码 1、日志为空，
表现为测试莫名其妙全红。`.bat` 用 `encoding="mbcs"` 写即可（`.py` 仍用 UTF-8）。

## 十、跨会话状态与输出控制（批次34 真机实测）

`session_state`（跨会话状态）与「高输出工具输出控制三件套」（`compact` / `max_lines` / `full`）
都是**主机侧**能力，不依赖 Keil 命令，真机验证的重点反而是「别把返回结构想当然」。

### 10.1 真机返回结构与 mock 不一样（写测试前先看一眼）

三条在真机上直接踩到的字段名差异，都是「测试脚本自己写错断言」型故障——工具本身没问题：

| 想当然的写法 | 真机实际 |
|---|---|
| `enter_debug(project=..., timeout=...)` | `enter_debug` **只接受** `freeze_watchdogs`；工程用默认工程或先 `set_debug_target` |
| `batch(commands=[{"tool": "x", "arguments": {...}}])` | 子命令的键是 **`args`**，`arguments` 会被当成未知参数拒绝 |
| `list_tools()` 的列表元素用 `name` / `input_schema` | 元素键是 **`tool`**，参数说明用 `required` / `optional` |
| `read_registers()` 返回 `R0..R15`、`SP`、`PC` | 键是**小写**的 `r0`~`r12` + `sp` / `lr` / `pc` / `xpsr`，共 **17 个**（`r13`/`r14` 以 `sp`/`lr` 命名，没有 `r13`/`r14` 这两个键） |
| `read_mem()` 返回 `data` / `bytes` / `hex` | 数据字段是 **`data_hex`** |

教训：真机脚本不要照抄「印象里的返回结构」，先用一次 `list_tools` 把签名看清；断言失败时
第一件事是确认「是工具错了还是我的预期错了」——批次34 首次真机跑出 14 个 FAIL，全是预期写错。

### 10.2 `compact` 的收益要看工具类型，别赌固定比例

`list_tools` 真机 24556 字符，单用 `compact` 只降到 20399（−17%）：它去掉 267 个空值字段、
截断 1 条长 `note`，但 99 条工具各自的 `usage` 是**互不相同**的，既升不到 `shared`，也大多是短文本。
真正的大头要靠 `max_lines`：`compact + max_lines=5` → **1937 字符**（−92%）。

结论：**`compact` 治「字段冗余」，`max_lines` 治「条数爆炸」**，两者叠加才有效；文档与技能里
别写成「`compact` 就能大幅瘦身」，那是过度承诺。

### 10.3 「公共字段提升」会改变元素的键集合（测试最容易踩）

`compact` 把列表元素间**取值完全相同**的字段提到 `output.shared`，元素里就不再出现该键。
所以「取 `tools[0]["usage"]` 做断言」在三个元素的 `usage` 相同时直接 `KeyError`。
真机上表现为：mock 测试自己构造的 payload 三元素同名 → 断言炸在取值处。

两个结论：

1. 断言公共字段提升时，payload 要**故意留一个非空的公共字段**（如 `category`），
   且注意**空值字段会被先行删除**——空 `dict` / 空串根本不是「公共字段」而是「空值」，`shared` 里不会有它；
2. 内容字段（`value` / `data` / 行号文本…）取值各不相同时才不会被提升，测「不截断内容字段」
   必须让它们各不相同。

### 10.4 参数写错时，是**抛错**还是 `ok=false`，两条都算「拒绝」

注入 `compact` / `max_lines` / `full` 后，真机验证要顺带确认「注入没有放松严格校验」：
`read_registers(compact=True, max_len=3)` 会在参数校验阶段直接 `ToolError`（消息里列明
可接受的参数名），而不是返回 `ok=false`。测试断言要同时接受这两种拒绝形式，
否则会把「严格拒绝」误判成「失败」。

### 10.5 `session_state`：只做主机侧、可逆、不猜

`save` 存的是**主机侧上下文**（工程路径、符号文件、UV4、串口、调试态、断点、数据断点、SVD 器件、
工具集、快照基线），其中采不到的项标 `available: false` + `note`，**不编造值**。
`load` 默认**只对比不应用**；`apply=true` 也只做一件事——切换符号文件（主机侧、可逆）；
断点 / 内存 / 运行态一律标 `never_auto_applied`。符号文件不存在时 `skipped` 并引导
`list_symbol_projects`，**不挑一个近似的顶上**（与 SVD「绝不盲挑第一份 .svd」同一条纪律）。

真机验证还要覆盖「防误判」的一侧：文件损坏 / 结构不符 / `schema` 不符都必须**明确报错**，
而不是静默当作「没有状态」——一个损坏的 state 文件如果被当成空状态，AI 会以为「上次没调过」，
进而重复走一遍已经做过的排查。

### 10.6 真机验证记录

- 目标：STM32F401RCTx + DAPLink（COM9）+ Keil UVSOCK@4823，工程 `example_mdk_project/mdk_test`；
- 结果：`_rt_b34.py` **28 项断言全过**（`enter_debug` → 输出控制各形态 → `session_state`
  save/show/load/apply → `batch` 子命令 → 非受控工具未被注入 → 收尾 `exit_debug`）；
- 收尾原则：**只退出脚本自己进入的调试态**，Keil 进程保持运行（不 `taskkill`，
  也不用 `close_uvision`——用户可能正开着窗口）。

## 十一、非 MDK 链路（工具链 / OpenOCD / trace）

本节记录批次36（非 MDK 扩展 + SWD/SWO trace）在写 mock 时提前逼出来的五类真机级缺陷——
它们有一个共同点：**不是靠猜，而是靠 mock 严格照抄真实 OpenOCD 的输出格式才暴露的**。

### 11.1 写后校验不能拿写命令去读

`ocd_write_mem` 原本用同一条写命令（`mww`）回读校验，结果 `verified` 恒为 `False`——
写命令的回显里根本没有读到的值。修法是按位宽换成对应的读命令：`mdb`(8) / `mdh`(16) / `mdw`(32)。

> 教训：**校验必须用独立的读路径**。同一命令既写又读，看起来"闭环了"，实际是自证。

### 11.2 裸地址带 Thumb 位必被拒（OpenOCD 与 Keil 同病）

`ocd_bp(0x08000401)` 会被 OpenOCD 判为非法地址——Cortex-M 的地址 bit0 是 Thumb 状态位，不是地址的一部分。
符号式断点没事，因为调试器求值回传的是偶数地址；裸地址则原样送下去。
修法：**仅对代码区（≥ `0x08000000` 或 < `0x00100000`）的奇数地址清 bit0**，并在返回里给 `note` 说明做过归一；
RISC-V 不受影响，不能无脑全局清。

这与批次32 在 Keil 侧踩到的是**同一个坑的两个面**（那时是 `error 57 illegal address`）。

### 11.3 不校验魔数，全 0 的 RAM 会被当成合法 RTT 控制块

RTT 控制块靠字符串 `SEGGER RTT\0` 标识。若 `rtt_parse_cb` 直接按结构体偏移解释一片全 0 的 RAM，
会"成功地"读出上下行通道，返回一个看似合法、实则纯属幻觉的结果——
这正是「宁可报错也不给看似权威的错答案」要杜绝的情形。
修法：解析前先校验 id 字符串以 `SEGGER RTT` 开头，不匹配就明确报「不是 RTT 控制块」并给排查提示。

### 11.4 三处解析正则与真实输出格式不符

| 解析点 | 原先要求 | 真实 OpenOCD 输出 |
|---|---|---|
| `probe()` 的 targets 列表 | `name: type`（带冒号） | 列对齐、无冒号，且含 `--` 分隔行 |
| `flash banks` | 多要求一个字段 | `#0 : name (driver) at 0x08000000, size 0x100000`（size 可选） |
| `reg` | 只认 `r0 = 0x...` | `(0) r0 (/32): 0x00000000 (dirty)`，RISC-V 为 `x0/zero` |

三处都改成按真实格式解析（`_FLASH_BANK_RE` 提到模块级，probe 与 `ocd_flash_info` 共用一份）。

### 11.5 提示符带尾空格，匹配不到就白等

`_has_prompt` 原先是 `text.endswith(">")`，而 OpenOCD 的提示符是 `"> "`（**带尾空格**）。
于是每次都匹配不上，只能等满 0.6s 空闲超时才返回——不影响正确性，但把每条命令都拖慢一个量级。
修法：**先 rstrip 尾部空白再判 `>`**。

### 11.6 元教训：这五条为什么能在 mock 阶段就被抓住

写 `tests/mock_openocd.py` 时只做了一个决定——**应答格式照抄真机，不做美化**：
`targets` 用列对齐、`flash banks` 带 `(driver) at ...` 与 `size`、`reg` 带 `(0) (/32) (dirty)`、
提示符带尾空格、未映射地址回 `Error: Failed to read memory at 0x...`、未知命令回
`Error: invalid command name "xxx"` 并附一段 Jim-Tcl 栈。

如果 mock 用"自己觉得合理"的格式应答，这五条一个也暴露不出来，会全部留到真机——
而真机只给一句报错，定位成本比改 mock 高出几个量级。
**mock 的价值不在"能跑通"，而在"照抄外部系统的怪癖"。**

### 11.7 telnet 通道里的两个行首噪声：IAC 与 NUL（真机取证）

首批 ocd_* 工具在 mock 上全绿，到真机（F401 + DAPLink，xPack OpenOCD 0.12.0）上却出现
三个“看着像工具坏了”的症状：`cpuid/partno/core` 全是 None、读内存只拿到 0/16 字节、
`ocd_reg(name="pc")` 失败。用 `_rt_dump.py` 抓原始字节才看到根因（**不猜，取证**）：

```
banner    b'\xff\xfb\x03\xff\xfb\x01\xff\xfd\x03\xff\xfe\x01Open On-Chip Debugger\r\n\r> '
命令回包  b'reg\r\n\x00===== arm v7m registers\r\n(0) r0 (/32): 0x000001b8\r\n...'
读内存    b'mdw 0x08000000 2\r\n\x000x08000000: 20000728 080002e1 \r\n\r> '
```

两段噪声都插在**行首**：`\xff`+`\xfb~\xfe`+option 是 telnet 的 WILL/WONT/DO/DONT 协商，
`\x00` 是 OpenOCD 给每条命令输出加的固定 NUL 前缀。而解析全部是行首锚定的正则
（`^\s*(0x...)` / `^\s*\(\d+\)\s*name` / `^#(\d+)\s*:`）——`\s` 不吃 NUL，
于是整行被丢弃，**raw 里明明有数据，解析出来是 0 条**。这是典型的静默错答案：
不报错、不抛异常，只是把「读不到」当成「没有」。

处置（三处，缺一不可）：

1. `_clean_telnet()`：字节层剥 IAC 序列（`\xff` 后跟 `\xfb~\xfe` 多吃一个 option 字节）
   与所有 NUL，`_read_until_prompt` 回包前统一过一遍；
2. 三个解析正则的 `^\s*` 换成 `^[\x00\s]*`，做二层防御——清洗漏一处也只丢一行，
   不会让整个解析静默变空；
3. **mock 也照抄这两段噪声**（默认开，`--no-telnet-noise` 可关）：
   不复现噪声，剥噪声的代码就永远没人测。加上之后 mock 阶段就能覆盖这条路径。

### 11.8 「读不回来」不是「写没生效」

真机测试里往 `0x2001FFF0`（F401 只有 96KB RAM，该地址越界）写 4 字节：
**写命令 `mww` 不报错**，只有读回时报 target 错误。若写工具的校验逻辑把
「读回结果为空」直接判成 mismatch，就会报出「写后读不一致：目标可能在跑 / 该地址只读 /
D-Cache 未回写」——三条全是猜的，真相是地址越界。

改法：校验前先分两条路——

- 读回命令本身失败或没解析出任何字 → `verified: null` + `verify_error`，错误码
  `ocd-write-verify-read-failed`，下一步指向「核对地址是否在可读区间」；
- 读回成功但值不同 → 才是 `ocd-write-verify-mismatch`。

同一条原则：**报错必须来自设备真实返回，不许替设备猜原因。**

### 11.9 错误码要分链路，通用码不能跨链路复用

统一信封的 `error_code` 是给 AI 看下一步用的。Keil 侧的通用码
（`timeout` / `unknown-error` / `invalid-argument`）的 `next_actions` 全都指向
`keil_health` / `read_async_messages` —— 用在 OpenOCD 链路就是**方向性错误**：

| 真机实测失败 | 修前归类 | next_actions 指向 | 修后归类 |
|---|---|---|---|
| `ocd_read_mem` 只读到 0/16 字节 | `output-write-failed` | Objects/Listings 目录权限 | `ocd-read-short` |
| `ocd_write_mem` 写后读不一致 | `unknown-error` | keil_health | `ocd-write-verify-mismatch` |
| `ocd_reg` 单读失败 | `unknown-error` | keil_health | （NUL 修好后自然恢复） |

两个具体修正：

1. 去掉 `output-write-failed` 规则里**裸的“只读”**——它把「只读**到** 0/16 字节」
   当成了输出目录只读；改成语境化的「输出目录.*只读 / 磁盘空间」；
2. 非 MDK 族（工具名前缀 `ocd_` / `toolchain_` / `trace_` / `target_`）在
   **通用码**上替换 `next_actions`（`_NON_MDK_ACTIONS`），并新增 14 个链路专用码
   （`ocd-not-running` / `ocd-probe-busy` / `ocd-telnet-unreachable` / `ocd-read-short` /
   `ocd-write-verify-*` / `ocd-no-flash-bank` / `toolchain-missing` / `trace-rtt-*` 等），
   规则**排在 Keil 通用规则之前**——否则「OpenOCD 不在运行」会被 `uvsock-unavailable`
   抢走（后者带“UVSOCK/4823”字样，对 OpenOCD 完全指错）。

### 11.10 telnet 只认行首 `Error:` 会漏掉「假成功」回包（RTT 端到端验证踩出）

真机烧一个自建固件时 `ocd_flash` 回了 `ok: true`，可 Flash 里的内容还是上一次的程序。
抓原始回包才看清 OpenOCD 打的是：

```
** Programming Started **
couldn't open D://git_project/mdk_agent/_rtt_proj/build/rtt_probe.elf
embedded:startup.tcl:1813: Error: ** Programming Failed **
```

三条都不是 `ok` 的依据——第一条像进度，第二条无前缀，第三条虽然写了 `Error:` 但**带位置前缀**
（`embedded:startup.tcl:1813: `），而 `_shape()` 当时用的是 `^\s*Error\s*:` 的 `match`。

修法（两层）：

1. `_ERR_RE` 从「行首」放宽为「词边界后」：`(?:^|[\s\[(\"'])(?:Error|error)\s*:`，改用 `search`；
2. 新增 `_FAIL_RE` 收编不带 `Error:` 的失败白话：`couldn't open` / `cannot open` /
   `unable to open` / `no flash bank` / `not enough space` / `** ...Failed... **`。

回归要同时守住**反向**：`** Programming Finished **` / `** Verified OK **` 不能被误判成失败
（mock 用例 C39–C41）。

### 11.11 OpenOCD 的 telnet 是 7-bit：路径里的中文传不过去

同一个坑的第二层：上一条里 `couldn't open` 的路径是 `D://git_project/...`，
而工具发出去的是 `D:/工作/git_project/...` —— **`工作` 这 6 个 UTF-8 字节在传输路上就没了**。
telnet（RFC 854）默认是 7-bit NVT，OpenOCD 并不协商 BINARY 选项，所以非 ASCII 字节到不了它。
把固件放到纯 ASCII 路径（`C:/Users/.../Temp/mdk_rtt_test/rtt_probe.elf`）后，
同一条命令立刻 `** Verified OK **`，RTT 控制块也读到 `SEGGER RTT`。

Windows 上中文工程目录太常见（本仓库就在 `D:\工作\...`），所以不是报错了事：

- `stage_ascii_path()`：路径含非 ASCII 时，把文件拷到 `%TEMP%/mdkdebug_stage/<sha1前8>_<安全名>`，
  用 ASCII 副本喂给 OpenOCD；`ocd_flash` / `ocd_load` 返回值里带 `staged_from` / `staged_path` /
  `path_note` 如实披露，绝不悄悄换文件；
- 拷不动（临时目录也非 ASCII 且无权限）才报错，并给「把固件放到纯英文路径」的 hint。

mock 侧同步保真：`_serve_line` 在 `telnet_noise` 打开时按 7-bit 语义丢掉非 ASCII 字符，
`program` 对打不开的路径回上面那三行——不这么做，剥噪声/暂存的代码永远没人测。

### 11.12 RTT 通道里是裸 MTF，别再找 ITM 报文头

RTT 通路闭环时 `trace_rtt_read` 明明读回了 `boot: mdkdebug rtt probe` 这类可读文本，
`trace_decode` 却给 `frames: []`——因为 `decode()` 只会先把字节当成 ITM 报文流
（`decode_itm`）再从 instrumentation 包里抽 MTF。RTT 上传的**就是 MTF 帧本体**，
外面没有 ITM 封装，于是「有数据、0 事件」这种静默错答案就出现了。

修法：

- `decode(..., fmt="auto"|"itm"|"mtf")`：`auto` 先按 ITM 找 instrumentation 包，
  一个都没有且流首立着 MTF 魔数 `0xA5`，就退回**裸 MTF** 再解一次，并在返回值里
  写明 `mode_used` 与 note；`fmt` 非法值直接报错，不猜格式；
- `rtt_read` 读到字节后顺手喂给**独立的** `rtt_decoder`（和 SWO 的 decoder 分开，
  避免两条通路的半帧状态互串），事件带 `source: "mtf-rtt"` 进缓冲，
  `trace_events` 立刻能看到内容。

真机闭环结果（STM32F401 + CMSIS-DAP，`toolchain_build` → `ocd_flash` → `trace_rtt_find`
→ `trace_rtt_attach` → `trace_rtt_read`）：9/9 通过，解出
`reset(init)` / `text("boot: ...")` / `event(0x1001 enter/exit, ts 8730/10403)` 等真实帧。

### 11.13 组件自身两个编译期缺陷（真机固件编出来的）

写一个最小 F401 固件把 trace 组件真正编一遍，才发现组件里有问题——这类缺陷在 mock
和语法检查里都看不见：

- `trace_instrument` 生成的配置把后端写成 `#define MDK_TRACE_BACKEND_RTT`（**没有值**），
  于是组件里所有 `#if MDK_TRACE_BACKEND_RTT` 都变成 `#if 与空` → `error: #if with no
  expression`；已改为 `#define MDK_TRACE_BACKEND_RTT 1`；
- `mdk_trace.c` 里 `MDK_TRACE_DEMCR` 定义成了裸常量 `0xE000EDFCu`，却按左值用
  （`MDK_TRACE_DEMCR |= ...`）→ `error: lvalue required as left operand of assignment`；
  已改为解引用宏 `(*(volatile uint32_t *)0xE000EDFCu)`；
- 顺手消掉 RTT 后端下 `_raw_out()` 的 unused variable 告警（循环变量下沉到各分支）。

## 九、历次改进留档（按批次）

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
