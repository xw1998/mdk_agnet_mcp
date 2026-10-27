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
- [九、跨会话状态与输出控制（批次34 真机实测）](#九跨会话状态与输出控制批次34-真机实测)
- [十、非 MDK 链路（工具链 / OpenOCD / trace）](#十非-mdk-链路工具链--openocd--trace)
- [十一、Keil 窗口复用 / 惰性符号 / 写入与回显（本轮真机实测）](#十一keil-窗口复用--惰性符号--写入与回显本轮真机实测)
- [十二、全量真机测试（批次37-38，F401 + Keil UVSOCK 实测）](#十二全量真机测试批次37-38f401--keil-uvsock-实测)
- [十三、OpenOCD 控制台的「无前缀失败回包」（批次39，F401 + DAPLink 实测）](#十三openocd-控制台的无前缀失败回包批次39f401--daplink-实测)
- [十四、RTOS 任务感知（批次40-41，F401 + DAPLink 实测）](#十四rtos-任务感知批次40-41f401--daplink-实测)
- [十五、环境一致性：符号同源 / 器件系列 / D-Cache（批次49）](#十五环境一致性符号同源--器件系列--d-cache批次49)
- [十六、目标侧插桩与 trace 后端（批次55，F401 + SVCrtOS 实测）](#十六目标侧插桩与-trace-后端批次55f401--svcrtos-实测)
- [十七、历次改进留档（按批次）](#十七历次改进留档按批次)
- [十八、SWD 无缝 stream：节拍与停机搬环（批次56 实测）](#十八swd-无缝-stream节拍与停机搬环批次56-实测)
- [十九、AC5（ARMCC 5）：编译成功 ≠ 那行代码生效（批次56 实测）](#十九ac5armcc-5编译成功--那行代码生效批次56-实测)
- [二十、宿主 Python 变量泄漏进外部工具子进程（批次57）](#二十宿主-python-变量泄漏进外部工具子进程批次57)
- [二十一、Keil 窗口与文件时序：模态框会堵死调试通道（批次57）](#二十一keil-窗口与文件时序模态框会堵死调试通道批次57)
- [二十二、部署完 ≠ 能链接：组件承诺提供符号却没人定义（批次57 实测）](#二十二部署完--能链接组件承诺提供符号却没人定义批次57-实测)
- [二十三、定位类「看似权威的错答案」三连（批次60）](#二十三定位类看似权威的错答案三连批次60)
- [二十四、全速运行时读 SRAM：会整段读回「同一个 4 字节字」（批次63，F427 实测）](#二十四全速运行时读-sram会整段读回同一个-4-字节字批次63f427-实测)
- [二十五、给「任务号」取名字：三个会给出**像样错名字/错沉默**的陷阱（批次64，F427 实测）](#二十五给任务号取名字三个会给出像样错名字错沉默的陷阱批次64f427-实测)
- [二十六、多份镜像联合取名：地址命中 ≠ 身份可信（批次64，F427 实测）](#二十六多份镜像联合取名地址命中--身份可信批次64f427-实测)
- [二十七、统计口径别写在绘图口径里：一个 badge 报出「事件 0」（批次64）](#二十七统计口径别写在绘图口径里一个-badge-报出事件-0批次64)
- [二十八、量化余数被丢掉：一条画得出来、却冻在原点的时间轴（批次64）](#二十八量化余数被丢掉一条画得出来却冻在原点的时间轴批次64)
- [二十九、分析层的四条「看着正常、实际是错的数」（批次72）](#二十九分析层的四条看着正常实际是错的数批次72)
- [三十、把外设「绕过固件」直接驱动：区分固件缺陷与核心/硬件楔死](#三十把外设绕过固件直接驱动区分固件缺陷与核心硬件楔死)

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
| `BS 0x8000DB5`（即 `&main` 按位或 `1`） | `*** error 57: illegal address (0x08000DB5)` |
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

## 九、跨会话状态与输出控制（批次34 真机实测）

`session_state`（跨会话状态）与「高输出工具输出控制三件套」（`compact` / `max_lines` / `full`）
都是**主机侧**能力，不依赖 Keil 命令，真机验证的重点反而是「别把返回结构想当然」。

### 9.1 真机返回结构与 mock 不一样（写测试前先看一眼）

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

### 9.2 `compact` 的收益要看工具类型，别赌固定比例

`list_tools` 真机 24556 字符，单用 `compact` 只降到 20399（−17%）：它去掉 267 个空值字段、
截断 1 条长 `note`，但 99 条工具各自的 `usage` 是**互不相同**的，既升不到 `shared`，也大多是短文本。
真正的大头要靠 `max_lines`：`compact + max_lines=5` → **1937 字符**（−92%）。

结论：**`compact` 治「字段冗余」，`max_lines` 治「条数爆炸」**，两者叠加才有效；文档与技能里
别写成「`compact` 就能大幅瘦身」，那是过度承诺。

### 9.3 「公共字段提升」会改变元素的键集合（测试最容易踩）

`compact` 把列表元素间**取值完全相同**的字段提到 `output.shared`，元素里就不再出现该键。
所以「取 `tools[0]["usage"]` 做断言」在三个元素的 `usage` 相同时直接 `KeyError`。
真机上表现为：mock 测试自己构造的 payload 三元素同名 → 断言炸在取值处。

两个结论：

1. 断言公共字段提升时，payload 要**故意留一个非空的公共字段**（如 `category`），
   且注意**空值字段会被先行删除**——空 `dict` / 空串根本不是「公共字段」而是「空值」，`shared` 里不会有它；
2. 内容字段（`value` / `data` / 行号文本…）取值各不相同时才不会被提升，测「不截断内容字段」
   必须让它们各不相同。

### 9.4 参数写错时，是**抛错**还是 `ok=false`，两条都算「拒绝」

注入 `compact` / `max_lines` / `full` 后，真机验证要顺带确认「注入没有放松严格校验」：
`read_registers(compact=True, max_len=3)` 会在参数校验阶段直接 `ToolError`（消息里列明
可接受的参数名），而不是返回 `ok=false`。测试断言要同时接受这两种拒绝形式，
否则会把「严格拒绝」误判成「失败」。

### 9.5 `session_state`：只做主机侧、可逆、不猜

`save` 存的是**主机侧上下文**（工程路径、符号文件、UV4、串口、调试态、断点、数据断点、SVD 器件、
工具集、快照基线），其中采不到的项标 `available: false` + `note`，**不编造值**。
`load` 默认**只对比不应用**；`apply=true` 也只做一件事——切换符号文件（主机侧、可逆）；
断点 / 内存 / 运行态一律标 `never_auto_applied`。符号文件不存在时 `skipped` 并引导
`list_symbol_projects`，**不挑一个近似的顶上**（与 SVD「绝不盲挑第一份 .svd」同一条纪律）。

真机验证还要覆盖「防误判」的一侧：文件损坏 / 结构不符 / `schema` 不符都必须**明确报错**，
而不是静默当作「没有状态」——一个损坏的 state 文件如果被当成空状态，AI 会以为「上次没调过」，
进而重复走一遍已经做过的排查。

### 9.6 真机验证记录

- 目标：STM32F401RCTx + DAPLink（COM9）+ Keil UVSOCK@4823，工程 `example_mdk_project/mdk_test`；
- 结果：`_rt_b34.py` **28 项断言全过**（`enter_debug` → 输出控制各形态 → `session_state`
  save/show/load/apply → `batch` 子命令 → 非受控工具未被注入 → 收尾 `exit_debug`）；
- 收尾原则：**只退出脚本自己进入的调试态**，Keil 进程保持运行（不 `taskkill`，
  也不用 `close_uvision`——用户可能正开着窗口）。

## 十、非 MDK 链路（工具链 / OpenOCD / trace）

本节记录批次36（非 MDK 扩展 + SWD/SWO trace）在写 mock 时提前逼出来的五类真机级缺陷——
它们有一个共同点：**不是靠猜，而是靠 mock 严格照抄真实 OpenOCD 的输出格式才暴露的**。

### 10.1 写后校验不能拿写命令去读

`ocd_write_mem` 原本用同一条写命令（`mww`）回读校验，结果 `verified` 恒为 `False`——
写命令的回显里根本没有读到的值。修法是按位宽换成对应的读命令：`mdb`(8) / `mdh`(16) / `mdw`(32)。

> 教训：**校验必须用独立的读路径**。同一命令既写又读，看起来"闭环了"，实际是自证。

### 10.2 裸地址带 Thumb 位必被拒（OpenOCD 与 Keil 同病）

`ocd_bp(0x08000401)` 会被 OpenOCD 判为非法地址——Cortex-M 的地址 bit0 是 Thumb 状态位，不是地址的一部分。
符号式断点没事，因为调试器求值回传的是偶数地址；裸地址则原样送下去。
修法：**仅对代码区（≥ `0x08000000` 或 < `0x00100000`）的奇数地址清 bit0**，并在返回里给 `note` 说明做过归一；
RISC-V 不受影响，不能无脑全局清。

这与批次32 在 Keil 侧踩到的是**同一个坑的两个面**（那时是 `error 57 illegal address`）。

### 10.3 不校验魔数，全 0 的 RAM 会被当成合法 RTT 控制块

RTT 控制块靠字符串 `SEGGER RTT\0` 标识。若 `rtt_parse_cb` 直接按结构体偏移解释一片全 0 的 RAM，
会"成功地"读出上下行通道，返回一个看似合法、实则纯属幻觉的结果——
这正是「宁可报错也不给看似权威的错答案」要杜绝的情形。
修法：解析前先校验 id 字符串以 `SEGGER RTT` 开头，不匹配就明确报「不是 RTT 控制块」并给排查提示。

### 10.4 三处解析正则与真实输出格式不符

| 解析点 | 原先要求 | 真实 OpenOCD 输出 |
|---|---|---|
| `probe()` 的 targets 列表 | `name: type`（带冒号） | 列对齐、无冒号，且含 `--` 分隔行 |
| `flash banks` | 多要求一个字段 | `#0 : name (driver) at 0x08000000, size 0x100000`（size 可选） |
| `reg` | 只认 `r0 = 0x...` | `(0) r0 (/32): 0x00000000 (dirty)`，RISC-V 为 `x0/zero` |

三处都改成按真实格式解析（`_FLASH_BANK_RE` 提到模块级，probe 与 `ocd_flash_info` 共用一份）。

### 10.5 提示符带尾空格，匹配不到就白等

`_has_prompt` 原先是 `text.endswith(">")`，而 OpenOCD 的提示符是 `"> "`（**带尾空格**）。
于是每次都匹配不上，只能等满 0.6s 空闲超时才返回——不影响正确性，但把每条命令都拖慢一个量级。
修法：**先 rstrip 尾部空白再判 `>`**。

### 10.6 元教训：这五条为什么能在 mock 阶段就被抓住

写 `tests/mock_openocd.py` 时只做了一个决定——**应答格式照抄真机，不做美化**：
——`targets` 用列对齐、`flash banks` 带 `(driver) at ...` 与 `size`、`reg` 带 `(0) (/32) (dirty)`、
提示符带尾空格。

> **这批描述后来被批次39 纠正过**：未映射地址的原文是裸的 `Failed to read memory at 0x...`、
> 未知命令是裸的 `invalid command name "xxx"`（后面跟一段 Jim-Tcl 栈），**都没有 `Error: ` 前缀**。
> mock 当时多加了前缀，反而让「只认 `Error:` 就够」的漏判在 mock 阶段一直看不出来——详见[十四.4](#144-元教训mock-的美化正是漏洞的藏身处)。

如果 mock 用"自己觉得合理"的格式应答，这五条一个也暴露不出来，会全部留到真机——
而真机只给一句报错，定位成本比改 mock 高出几个量级。
**mock 的价值不在"能跑通"，而在"照抄外部系统的怪癖"。**

### 10.7 telnet 通道里的两个行首噪声：IAC 与 NUL（真机取证）

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

### 10.8 「读不回来」不是「写没生效」

真机测试里往 `0x2001FFF0`（F401 只有 96KB RAM，该地址越界）写 4 字节：
**写命令 `mww` 不报错**，只有读回时报 target 错误。若写工具的校验逻辑把
「读回结果为空」直接判成 mismatch，就会报出「写后读不一致：目标可能在跑 / 该地址只读 /
D-Cache 未回写」——三条全是猜的，真相是地址越界。

改法：校验前先分两条路——

- 读回命令本身失败或没解析出任何字 → `verified: null` + `verify_error`，错误码
  `ocd-write-verify-read-failed`，下一步指向「核对地址是否在可读区间」；
- 读回成功但值不同 → 才是 `ocd-write-verify-mismatch`。

同一条原则：**报错必须来自设备真实返回，不许替设备猜原因。**

### 10.9 错误码要分链路，通用码不能跨链路复用

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

### 10.10 telnet 只认行首 `Error:` 会漏掉「假成功」回包（RTT 端到端验证踩出）

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

### 10.11 OpenOCD 的 telnet 是 7-bit：路径里的中文传不过去

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

### 10.12 RTT 通道里是裸 MTF，别再找 ITM 报文头

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

### 10.13 组件自身两个编译期缺陷（真机固件编出来的）

写一个最小 F401 固件把 trace 组件真正编一遍，才发现组件里有问题——这类缺陷在 mock
和语法检查里都看不见：

- `trace_instrument` 生成的配置把后端写成 `#define MDK_TRACE_BACKEND_RTT`（**没有值**），
  于是组件里所有 `#if MDK_TRACE_BACKEND_RTT` 都变成 `#if 与空` → `error: #if with no
  expression`；已改为 `#define MDK_TRACE_BACKEND_RTT 1`；
- `mdk_trace.c` 里 `MDK_TRACE_DEMCR` 定义成了裸常量 `0xE000EDFCu`，却按左值用
  （`MDK_TRACE_DEMCR |= ...`）→ `error: lvalue required as left operand of assignment`；
  已改为解引用宏 `(*(volatile uint32_t *)0xE000EDFCu)`；
- 顺手消掉 RTT 后端下 `_raw_out()` 的 unused variable 告警（循环变量下沉到各分支）。


### 10.14 「找工具」不能只认名字最短的那个，更不能跨架构凑（ESP 工具链复核踩出）

装完 ESP 的 crosstool-NG 包（`xtensa-esp-elf` / `riscv32-esp-elf`）做家族复核，发现两处：

- **认死短名会说「没有」**：`find_tool(fam, "gdb")` 只按 `gdb` 这个键查，而 ESP 的 gdb 包里
  根本没有无后缀的 `xtensa-esp-elf-gdb.exe`（只有 `-no-python` 和 `-3.x` 两种名字），于是
  「明明装了 gdb 却回 None」。新增 `find_gdb()`：按 `gdb → gdb-no-python → gdb-<版本(高优先)>`
  依次挑，并且**逐个真跑一次 `--version`**，坏候选记进 `tried` 跳过、在 `via` / `note` 里说清
  到底用了哪一个。
- **缺 gdb 时会掉到别的架构**：`ocd_gdb` 原来是「[ELF 家族] + 固定四个家族」顺次找，某个家族
  没有 gdb 就继续往下，arm 的 ELF 最终可能拿到 riscv/xtensa 的 gdb——一个**看起来像样的错答案**。
  现在改成：给了 `elf` 就只在**同架构**家族里找（`find_gdb` 内部限制），找不到就如实报错并附
  `tried` 与 `hint`；没给 `elf`（架构未知）才全找一遍，且回包标 `gdb_select: first-available`
  明说「这是碰上的，不是按架构挑的」。
- **自家挑出来的工具，自家白名单得放行**：`find_gdb` 选中的是 `xtensa-esp-elf-gdb-no-python.exe`，
  而 `run_tool` 的放行白名单是按「标准后缀」（`-gdb` / `-gcc` …）比对的，带变体或版本尾巴的
  名字一律判成「不在白名单」拒跑——**两层自相矛盾**：能找到、却跑不了。现在白名单补了一条正则，
  认得 `-no-python` / `-py3` / `-3.12` 这类尾巴，无关 exe（`calc.exe`）仍然拒。

### 10.15 复核工具可用性，别拿 shell 包装器的结果当结论

同一件事上面还有个小插曲：用 `bash` 里的 `timeout <exe> --version` 探 ESP 的 gdb，
输出是 `Python path configuration:`（像是启动器坏了）；换 `subprocess` 直接调（**也就是工具
真正会走的调用路径**）却一切正常。差异来自启动方式（`timeout` 包装改变了环境），不是工具本身
的问题——差点据此写出一条错误的「缺陷结论」写进代码注释。

教训：**验证「这个工具能不能用」必须走真实调用路径**（Python `subprocess` / MCP 工具本身），
别用 shell 包装器（`timeout`、管道、`env`）跑出来的结果下判断；两者不一致时，先怀疑包装器。
代码里仍保留了一道运行期失败特征判定（`_BROKEN_RE`，命中「起得来、退出码 0、其实没跑」的 exe
就判不可用），但注释只描述事实，不挂具体包的结论。

### 10.16 别再拿「工具名前缀」当链路归属：`trace_*` 是双链路工具族

统一信封里为了让「非 MDK 链路」的错误拿到对的下一步，按前缀把 `ocd_` / `toolchain_` /
`target_` / `trace_` 判成「非 MDK 工具」，于是这些工具报 `unknown-error` 时拿到的是
OpenOCD 兜底动作（「读返回里的 output / raw」「用 ocd_status / toolchain_list」）。

真机复现：Keil 链路下 `trace_record(action="read")` 在没录过的进程里失败，信封给的下一步
竟然指向 `ocd_status` —— 而本机根本没跑 OpenOCD，用户照着做就是白跑一趟。
根因是 `trace_*` **不是**「非 MDK 工具」：它们是**双链路**的（Keil 与 OpenOCD 都能跑，
本身就是「无法合并成同一个就分开支持」的产物），前缀切法在这里不成立。

修法两层：
1. 失败要有自己的码：`trace_record` 的「本进程还没录过」补 `error_code="no-recording"`
   （并给专属 `next_actions`：先跑 `action="run"` 录一次；只要占比就换 `trace_pcsample`）。
   工具自己给的 `error_code` 优先于文本猜码——这正是「宁可报错不给错答案」的落点。
2. 通用码要按**工具族**而不是前缀给动作：新增 `_TRACE_ACTIONS`，让 `trace_*` 的
   `unknown-error` 先指向 `trace_guide`（讲清该链路支持到哪一步），而不是 `ocd_status`。

教训：分类表按「名字前缀」划，早晚会碰上一个跨链路/跨族的名字。判据要跟着**实际语义**
（这个工具能不能跑在 Keil 上）走，而不是命名习惯。

## 十一、Keil 窗口复用 / 惰性符号 / 写入与回显（本轮真机实测）

本轮的坑都属同一类：**工具手里明明有信息却不拿去用，于是给出一份看起来很确定、实际是错的答案**。

### 1. `launch_uvision(reuse=True)` 仍然开新窗口：相对路径 vs 绝对路径

真机现象：同工程 Keil 窗口累积到 2 个（红线是「只保留一个窗口」）。根因在复用的同一性判定：
调用方传的是**相对路径**（`example_mdk_project/.../mdk_test.uvprojx`），而实例枚举从命令行
拿到的是**绝对路径**，旧 `_same_project` 只归一大小写与分隔符，相对/绝对不等 → 判不出同一工程
→ 又拉起一个。修法：比较前先 `abspath`。

验证：收敛后传相对路径、绝对路径调 `launch_uvision(reuse=True)`，两次都 `reused=true`、
`pid` 不变、`list_uvision_instances.count` 始终为 1。

### 2. 启动时没配工程 → 符号相关工具整族不可用

真机现象：MCP 服务启动只给了 UVSOCK 端口，没给 `--default-project` / `--axf`，于是
`find_symbol` / `snapshot` / `read_locals` / `get_current_location`（文件行号）全报「符号定位未就绪」，
而工程路径其实就在工具参数里（`launch_uvision(project=...)`）。

修法：符号定位改为**按需惰性解析**，优先序固定并记录来源（`get_status.symbol_source` 披露）：
本次会话用过的工程 > 服务默认工程 > 符号工程注册表里唯一存在 `.axf` 的那项 > 附近唯一可推断的工程。
**多候选就不替调用方决定**（保持未装载并记日志），宁可报错也不猜一个可能张冠李戴的符号。

### 3. `write_mem` 地址收 `0x` 前缀、值不收

`write_mem(addr="0x20001000", data="0x11223344")` 直接报 `non-hexadecimal ... at position 1`：
地址能写 `0x`、值不能，是人和模型都会踩的不一致。修法：统一容忍 `0x/0X` 前缀、空格、逗号、
下划线、分号、冒号（`0x11,0x22` 也拼得对），失败时给出期望写法，并归类到 `invalid-argument`
（原来落 `unknown-error`，`next_actions` 指去查 Keil 健康，方向完全错）。

### 4. OpenOCD telnet：孤立 IAC 吞掉数据字节 → 回显残片 + 结果串台

真机现象：`ocd_reg(pc)` 的 `raw` 是 `"eg pc\npc (/32): 0x080000f4"`，`ocd_reg(xpsr)` 的 `raw`
只有 `"rg xpsr"`（真实结果没到），看起来像目标没回话。两个独立根因：

- `_clean_telnet` 对孤立 IAC（`0xFF`）无条件 `i += 2`，把紧跟其后的**数据字节一起吞了**
  （`reg` 的首字符被吃）。修法：只有 `WILL/WONT/DO/DONT`+option 吃 3 字节、其它 telnet 命令吃 2 字节，
  **孤立 IAC 只吃它自己**。
- 上一条命令迟到的提示符让 `_read_until_prompt` 一见提示符就提前返回，下一条命令只拿到回显残片。
  修法：发命令前 `_drain()` 清空滞留字节（清掉的字节数记进 `stale_bytes`）；若整理后只剩回显，
  自动补读一轮，仍为空就如实返回空；回显判定放宽到「子序列且长度 ≥ 命令一半」以覆盖 `rg xpsr` 形态。

### 5. SWO 零字节不该只说「没数据」

`trace_swo_start` 回 ok、`trace_swo_read` 永远 0 字节——用户根本分不清是「引脚没接」「目标没使能 ITM」
还是「波特率不对」。修法：零字节时 DAP 直读 `DEMCR.TRCENA / ITM_TCR.ITMENA / ITM_TER / TPIU_ACPR`，
用 `coreclk/(ACPR+1)` 算实际 SWO 速率并和本次配置比，读不到的寄存器进 `unreadable`，
再给「引脚 / 插桩 / 端口」可查清单。**结论必须来自目标寄存器实读，不替设备编原因。**

### 6. `read_registers` 只能整组读

真机顺手试 `read_registers(regs=["pc"])` 直接被拒（参数名不被接受）。修法：加 `names`
（`"pc"` / `"pc,sp,lr"`，也接受 `r13/r14/r15`），并把 `regs/reg/registers/only/filter` 纳入别名层；
不认识的名单放进 `unknown_names` + 回 `supported_names`，**不静默忽略**。

## 十二、全量真机测试（批次37-38，F401 + Keil UVSOCK 实测）

这一轮的出发点不是某个具体反馈，而是「把 150 个工具在真机上逐个跑一遍」。跑出来的问题集中在一类：
**返回了一个看起来权威、实际不成立的答案**。以下每条都有真机现场。

### 1. `enter_debug` 报「已进入调试」，约 1 秒后 Keil 自己退出了调试

现场：`enter_debug` 回 `ok=true / ready=true`，紧接着的命令全报 `status=6 未处于调试状态`。
排查顺序（都不是原因）：不是 `read_registers` 引起的（对照实验）、不是 GetStatus 误报（用
`read_registers` 做功能真值）、Keil 确有可见窗口（ctypes 枚举窗口标题，排除隐藏批处理进程）。
定位：Keil 命令窗口里残留了本工具早前写的初始化脚本（`Include ...init.ini`、`LOG >>trace.log`、
`EXIT`、`LOG OFF`）——调试会话一建立就被自己的 `EXIT` 关掉了。用 `close_uvision(force)` →
`launch_uvision` 拿全新实例后不再出现。
修法（治标且更稳，不依赖用户去清实例）：`client.enter_debug(verify_stable=True)` 在就绪后
**复核**调试态（三态 `ok/lost/unknown`，查不了就不下结论），`lost` 时自动重发 `UV_DBG_ENTER`
一次再复核；两次都丢则如实报 `ok=false` + `error_code=enter-debug-not-ready`（server 层也
不再把 `ready=False` 报成 `ok=True`），诊断里给出 `close_uvision(force) → launch_uvision → enter_debug`。

### 2. `run_to_line` 的假成功（最隐蔽的一条）

现场：先 `run` 到 main 死循环（早已越过 `SystemInit`），再 `run_to_line("0x08002D60")` →
返回 **`ok=true` + `stopped_file=system_stm32f4xx.c` + `stopped_line=171`**，而紧接着的
`get_status` 是 `running=true`——目标根本没停。
根因：旧实现是「设临时断点 → run → 清断点 → 读 PC」，**不校验断点是否命中**；断点永不命中时
读到的是陈旧 PC（恰好等于刚设的断点地址），于是把「还在跑」报成「停在第 171 行」。
修法：改用 `client.wait_breakpoint([addr], timeout_s)` 等一个**真正的**命中事件（它内置「这次
停止是新发生的」三条证据与 PC 可信度），没等到就如实失败：`error_code=run-to-target-timeout`、
带 `observed` / `waited_ms` / `polls` 现场、**`stop()` 后用 `_wait_stopped` 确认**再回报
（`stop_verified`，stop 是异步生效的，发出去不等于停了），并清掉临时断点。新增 `timeout_s`
参数（别名 `timeout`）。
真机复核：同一序列现在回 `ok=false / run-to-target-timeout / observed=running / stop_verified=true`。

> 推广：任何「我让它走到 X」的语义，都必须以「观察到确实停在 X」为成功判据。

### 3. 三处错误归类把调用方指向错误方向

| 真机现象 | 旧归类 | 下一步（错） | 现归类 |
|---|---|---|---|
| `set_register(register="r99")` 不支持的寄存器名 | `unknown-error` | 去查 keil_health | `invalid-argument` + 可用寄存器候选 |
| `wait_state("stopped", timeout_s=3)` 超时 | `unknown-error` | 去查 keil_health | `wait-state-timeout`（看 `observed` 现场）；一直不在调试态 → `not-debugging` |
| `profile_function("main")` 未达函数入口 | `unknown-error` | 去读 Keil 输出 | `function-not-reached`（先 reset 再 run / 核对符号） |

做法沿用既有原则：**结构化字段优先**（工具直接给 `error_code`；`wait_state` 走
`matched=False + timeout_kind` 的结构化判定），文本规则只作兜底。

### 4. mock 也在给「假答案」

mock 的 `UV_DBG_STATUS` 过去**退出调试后仍回成功**，于是 `run`/`stop`/`get_status` 在「没进调试」
的情况下也能跑通——三个端到端用例（`test_e2e` / `test_mcp` / `test_stdio`）把这个不可能发生的
场景当成了正常路径。改成按真机语义回报（未在调试态回 `r_status=6`）后，三个用例补上了
`enter_debug` 前置。

### 5. `uvprojx_edit(remove_files)` 的宽正则会「一删一片」

真机实测（工程副本上）：`pattern="stm32f4xx_hal"` 一次命中二十多个文件（正则按 FilePath 匹配，
未锚定就吃一片）。行为本身合乎文档，但不提示很容易在真工程上误伤：现在一次命中 ≥5 个文件时
返回 `warning`，提醒逐条核对 `removed` 清单、备份仍在（可回滚），并建议收紧正则。

### 6. 本轮真机覆盖（F401RCTx + DAPLink，COM9）

- MDK/Keil 链路：进入调试、寄存器读写、内存读写、符号定位、断点/观察点、单步/运行/等待、
  snapshot/diagnose/反汇编、外设与 SVD、watch/struct、DWT、故障报告、ITM、内存地图/搜索/填充、
  工具族查询、会话状态、窗口管理（`launch/close/list` + `keil_health`）、命令窗口、
  编译/清理/重建/烧录/批量脚本（阶段 1-6）。
- 串口（COM9）：`serial_list_ports/start/status/read/write/expect/stop`；命中分支用固件命令口验证
  （心跳 `hb <n>` 606ms 命中；`send="help"` + 期望命令表 50ms 命中）。
- 非 MDK 链路：`gcc/make/cmake` 工具链、OpenOCD 全族、RTT、`trace_profile/scope`、DWT PCSR 采样。
- 阶段 7 补测：`set_register`（含非法名）、`run_to_line`（命中 / 未命中两条路径）、
  `wait_state`、`profile_function`、`profile_sampling`、`wait_fault`、`session_state`（save/show/load+apply）、
  `uvprojx_edit`（四个 action，副本上进行）、`serial_expect`（命中分支）。
- 单窗口约束：全程核对 `list_uvision_instances`，发现同工程开过两个窗口时用
  `close_uvision(keep="oldest")` 收敛（持 4823 端口的是**最早**的实例，不能按「留最新」关）。

## 十三、OpenOCD 控制台的「无前缀失败回包」（批次39，F401 + DAPLink 实测）

来源：回答「gcc 的调试链试了吗？」时把 GCC/OpenOCD 链路整条在真机上重跑了一遍，
顺手发现 `ocd_cmd` 会把**根本没执行的命令**报成 `ok=true`。

### 13.1 现象与真机取证

`ocd_cmd("monitor targets")` 返回 `ok=true`，而 `output` 是 `invalid command name "monitor"`。
继续横扫一批坏命令（原文逐字抄自 OpenOCD 0.12.0 控制台）：

| 命令 | 真机回包 | 修复前 | 修复后 |
|---|---|---|---|
| `monitor targets` | `invalid command name "monitor"` | ok=true | ok=false |
| `definitely_no_such_cmd_xyz` | `invalid command name "..."` | ok=true | ok=false |
| `wp 0x20000000` | `wp [address length [('r'/'w'/'a') [value [mask]]]]` | ok=true | ok=false |
| `read_memory 0xZZZZ 4` | `read_memory address width count ['phys']` | ok=true | ok=false |
| `reset nonsense_mode` | `cortex_m reset_config [...]` 等一串命令列表 | ok=true | ok=false |
| `reg no_such_reg_xyz` | `register X not found in current target` | ok=true | ok=false |
| `mdw 0x20000000 99999` | `Failed to read memory at 0x20018004` | ok=true | ok=false |

**这些回包全都不带 `Error: ` 前缀**，而失败判定当时只认 `Error\s*:` 与
`couldn't open|no flash bank|** ... Failed **`，于是整批漏判。
（`couldn't open` 那条正是上一轮 `ocd_flash` 踩过的同一个坑——只补了一个样例，没补这一类。）

### 13.2 修法：两类新标记 + 一条「用法行」判定

1. `_FAIL_RE` 增补真机取证过的原文：`invalid command name`、`not found in current target`、
   `Failed to read memory`；
2. 新增 `_USAGE_RE` + `_looks_like_usage(command, lines)`：Jim-Tcl 参数不足时会把**该命令的
   用法说明**打回来。判定收紧为「某行以**本命令的第一个词**开头，且带占位符（`<...>` 或 `[...]`）」——
   这样 `wp [...]` 算失败，而 `program <filename> [...]` 出现在 `wp` 的回包里不算（A11 用例守住这条）。
   加这一层的必要性：用法回包是**任意文本**，纯靠字符串黑名单永远补不全。

### 13.3 连带修复：越界读内存不再退化成裸回包

真机越界读（`mdw 0x2001FFF0 16`，F401 只有 96KB RAM）回包就是一行
`Failed to read memory at 0x2001fff4`、**0 行数据**。原先的写法是「命令失败就原样返回」，
结果是调用方拿不到 `got_bytes`/`complete`，错误码还掉进 `unknown-error`，
`next_actions` 反而指向「去读 output/raw」——方向完全反了。

改为：**命令失败也要继续走结构化回答**，输出 `ok=false` + `complete=false` +
`got_bytes=0/expected_bytes=64` + `openocd_error` 原文 + `error_code=invalid-argument`。
正常读、正常烧录不受影响（同一次真机复核里一并确认）。

### 13.4 元教训：mock 的「美化」正是漏洞的藏身处

`tests/mock_openocd.py` 里两处回包**比真机多加了 `Error: ` 前缀**：

```python
return ['Error: invalid command name "%s"' % cmd, ...]      # 真机其实没有前缀
return ["Error: Failed to read memory at 0x%08X" % a]       # 真机也没有
```

于是「只要有 `Error:` 就算失败」这条**假的安全感**在 mock 阶段一路全绿，
两次真机取证（批次37 的 `ocd_flash`、批次39 的 `ocd_cmd`）踩的都是同一类。
mock 已按真机原文改正。

> 与[十一.6](#116-元教训这五条为什么能在-mock-阶段就被抓住) 是同一个道理的反面注脚：
> mock 的价值在「照抄外部系统的怪癖」，**任何美化（补前缀、补字段、补格式）都等于替被测代码
> 掩盖一条真实路径**。改 mock 的原则是——不确定就去看真机原文，别自己觉得「这样更合理」。

## 十四、RTOS 任务感知（批次40-41，F401 + DAPLink 实测）

目标：`rtos_info` / `rtos_tasks` / `rtos_objects` 三个只读工具，纯主机侧读内存 + 解析 `.axf` 的
DWARF，不做目标侧配合。验证固件 `example_gcc_project/freertos_probe/`（FreeRTOS V11.1.0，
7 个任务 + 队列/计数信号量/互斥量，故意打开 `configUSE_TRACE_FACILITY` / `configUSE_MUTEXES` /
`configRECORD_STACK_HIGH_ADDRESS` 来逼「偏移取自 DWARF」这条路）。

**验收证据**：8 个任务全列出（`count == kernel_task_count == 8`），6 个任务的
`stack_free_words` 与固件里内核自报的 `uxTaskGetStackHighWaterMark` **逐项一致**
（105/62/97/71/103/223）；队列注册表 3 个对象的名字/`uxLength`/`uxItemSize` 全对。

### 14.1 FreeRTOS 的结构体在 DWARF 里不叫 `TCB_t`

- 源码是 `typedef struct tskTaskControlBlock {...} TCB_t;`，DWARF 里的**真名**是
  `tskTaskControlBlock` / `xLIST` / `xLIST_ITEM` / `QueueDefinition`。按 `TCB_t` 查类型表必然查不到。
- 而且 typedef 会**两跳**：`TCB_t -> tskTCB -> tskTaskControlBlock`、
  `Queue_t -> xQUEUE -> QueueDefinition`。只映射一跳仍然拿不到。
- **教训**：任何「按类型名取字段偏移」的取值函数都必须走完整的 typedef 链。本批就栽在这儿——
  `struct()` 走了链、`field()` 却直接查字典，于是 `_owner()` 恒返回 `None`，
  真机表现是「任务列表只剩 `pxCurrentTCB` 一个（IDLE），内核说 8 个」。
  这种错**不报错**，只少数据，最容易被当成「工具就这水平」放过去。

### 14.2 DWARF 里的前向声明会挡住真定义

- `struct tskTaskControlBlock;` 这类前向声明也会生成一个同名 DIE，**成员为空**。
  用 `setdefault` 登记结构体时，先遇到谁谁占位——真定义（有成员的那个）反而被挡在外面，
  结果是 `struct('TCB_t')` 返回 `{size: None, fields: {}}`。
- **修法**：只收有成员的 DIE，同名字段更多者胜出。

### 14.3 队列注册表的步长必须按 `QUEUE_REGISTRY_ITEM` 算

- `xQueueRegistry` 的元素是 `QUEUE_REGISTRY_ITEM_t{const char *pcQueueName; QueueHandle_t xHandle;}`
  （8 字节），而 `Queue_t` 是 80 字节。步长写成 `Queue_t` 的大小会跳到毫不相干的地址上，
  真机表现是**读出 7 个对象**：第一个是对的，后面全是 `@\x18` / `0xA5A5A5A5` 这类垃圾，
  还带着 `uxLength=536983554` 这种一眼假的数字。
- **教训**：相邻的十个字段里只要有一个「看着合理」，垃圾结果就可能被信。枚举类工具必须
  与「登记条数」和「未登记槽位是 0」两条一起对，才对得上真机的 3 个对象。

### 14.4 `portMAX_DELAY` 阻塞和 `vTaskSuspend` 在同一个链表上

- FreeRTOS V11 的 `prvAddCurrentTaskToDelayedList()` 把 `xTicksToWait == portMAX_DELAY` 的任务
  **放进 `xSuspendedTaskList`**，内核自己的 `eTaskState()` 也一律报 `eSuspended`。
- 主机侧能分：看 `xEventListItem.pxContainer` 是否非空——还挂在某个内核对象的等待链表上就是
  「无限阻塞」，空才是真被挂起。真机上 7 个任务里正好两种都有，分类结果与固件代码一致。
  返回里附 `state_note` 把这个内核 quirk 讲清楚，免得调用方以为工具在瞎猜。

### 14.5 `pxEndOfStack` 是「对齐取整后」的栈顶

- 真机上：`256` 字的栈报 `stack_size_words=255`，`128` 字的报 `127`。原因不是差一错误，
  而是 FreeRTOS 建栈时算完 `pxStack + (N-1)` 后**按 `portBYTE_ALIGNMENT` 向下取整**，
  再把这个地址记进 `pxEndOfStack`（8 字节对齐、栈深为偶数时正好少 1 个 word）。
- 所以 `pxStack`→`pxEndOfStack` 换算出来的「总大小」天生带 1~2 个 word 的偏差。
  **栈余量（`stack_free_words`）不受影响**（它就是与内核逐项对上的那个数）；
  `stack_used_pct` 由余量换算，偏差 1 个 word 级。结果里出一处 `stack_size_note` 说清，
  不把估算值当精确值卖。

### 14.6 归因别套模板：裸机固件不等于「内核没开注册表」

- 裸机 `.axf` 同样没有 `xQueueRegistry`。最初 `rtos_objects` 直接按「内核在
  `configQUEUE_REGISTRY_SIZE==0` 时根本不定义它」报错——文字没错，但方向错了：
  对一个根本没有 FreeRTOS 的固件谈注册表配置，等于把调用方引到 `FreeRTOSConfig.h` 去。
- 现在先 `detect()` 探一遍，没有内核就说「没探测到 FreeRTOS 符号」，两种失败给两种下一步。
  同时这三条错误路径都带上结构化 `reason`，由统一信封归成 `rtos-not-present` /
  `rtos-no-queue-registry` / `rtos-no-mem-link`，不再掉进 `unknown-error`（它会把下一步指向
  `keil_health`，方向完全不对）。

### 14.7 排障插曲：同一根 DAP 被两个 OpenOCD 抢时，「读内存」会给出会骗人的结果

真机验证中途一度以为解析器坏了：同一地址连读两次，第一次是对的、第二次变成 `0x40000000`，
任务链表走到第 3 项就断。实际原因是上一轮脚本异常退出后**残留了一个 OpenOCD 进程**，
新起的实例仍然「启动成功」（日志里甚至有 `Examination succeed`），却无法真正复位目标，
读回来的是 0 字节或垃圾。两个实例同时 LISTENING 4444/3333 是这个状态的标志。

**教训**：真机脚本要用 try/finally 收尾；怀疑读数时先 `netstat -ano | grep :4444`
看清有几个实例，**不要拿一个可能被抢占的会话去反推自己的代码有问题**。

## 十五、环境一致性：符号同源 / 器件系列 / D-Cache（批次49）

这一轮的三个反馈看起来是三件事，根因是同一个：**工具信任「工程配置」，却不核对「板上真实是什么」**。
跨仓库调试时，配置与实际不一致不会报错，只会输出**看似权威的错答案**——比没有数据更有害。

- **符号与固件不同源 → PC 全解析成「假符号」**。现象：`flash_download` 烧的是 special 工程，
  `enter_debug` 加载的却是 Keil 当前打开的**主固件**工程的 `.axf`；两套固件尺寸不同、函数地址错位，
  PC 被解析成 `rt_mq_send_wait L2909`，而这个函数在 special 的 map 里**早被链接器裁掉了**——纯误导。
  修法：烧录成功时记下「这次烧的是哪个工程/哪份 axf」，进调试时与当前符号文件做核验
  （文件同一性优先，必要时用 Flash 内容指纹 + PC 反推偏移做硬证据），不一致就给出
  `symbol_source_warning` 与 `next_actions`（`set_symbol_file` / `flash_debug` / `env_check`）。
  **不要靠调用者「自己意识到」**——踩过一次就知道这个坑有多贵。
- **器件系列配错 → 外设读数看着像样却全错**。现象：SVD 库装的是 F4 的、芯片是 H743，
  读 RCC 返回 base=`0x40023800`（F4 的 RCC）且值是 `0xAAAAAAAA`，查不到 H7 才有的
  `AHB3ENR`/`APB1LENR`。**内置寄存器表（periph.py）与内置内存地图同样是写死的 STM32F4 布局**，
  它们比 SVD 更隐蔽——因为没有任何「加载了什么」的迹象可循。修法：`read_peripheral` /
  `write_peripheral` / `list_peripherals` / `query_memory_map` / `svd_decode` 统一走设备守卫，
  先读 `DBGMCU->IDCODE` 的 DEV_ID + `SCB->CPUID` 交叉校验实测芯片，系列不符**默认拒绝执行**
  （`allow_mismatch=true` 可强读，但返回值会标注 mismatched 以免被当真值）。
- **判据要来自「目标/ELF 自己说」而不是「我们写死的型号表」**。同一类问题还出现在
  `is_code_address`：原来固定判 `0x08000000..0x081FFFFF`（STM32 布局 + 假设 Flash ≤2MB），
  换个内核（XIP 到 `0x60000000` 的 i.MX RT、Flash 在 `0x00000000` 的 nRF、代码跑 RAM 的 bootloader）
  就会误判，而它是**调用栈回溯的合法性判据**，误判会把真实 PC 当噪声丢掉。改为从 `.axf` 的
  ELF 节头读 `SHF_EXECINSTR` 段范围（链接器写下的事实），取不到才退回经验值并用
  `code_range_source` 标明本次用的是哪种判据。
- **M7 的 D-Cache：读到全 0 不一定是「变量被清零」**。DAP 直读走 AHB，目标 D-Cache 使能时
  可能读到**尚未回写的陈旧副本**；直写 RAM 也可能被脏行回写覆盖，两者都不报错。
  修法分两层：`read_mem`/`write_mem` 命中 SRAM 时附 `cache` 字段提示；退化读数的提示里
  补上因果与可执行动作（`cache_info` 看状态 → `dcache_maintain(action="clean_invalidate")`
  做 clean+invalidate → 重读对比）。
  **注意 D-Cache 维护不放在读路径里**：在读内存时顺手 clean+invalidate 并改用新值，
  等于把「写目标状态」藏进只读工具，还会多发一次目标读、扰动本就不稳的首帧读数序列。
  动手的动作必须是显式的独立工具。
- **「还没连」不等于「链路不可用」——体检工具因此会静默不体检**（批次50 真机发现）。
  `UVClient` 的 UVSOCK socket 是**懒连接**（首次真正用到才开），而 `rtrace._try_keil` 只看
  `phy.is_connected` 就判定链路不可用，于是 `env_check` 在「Keil 开着、UVSOCK 端口在监听、
  但本进程还没发过命令」时直接跳过芯片实测（`chip.confidence=none`），
  **器件守卫退化成 unknown、外设读数照常放行**——正好是器件系列配错最难防的那一格。
  修法：判定前先主动连一次（连 UVSOCK 只是开 TCP 与握手，**不进调试、不 halt、不碰目标**，
  与其余工具首次调用时行为一致），连不上再把底层真实原因带出来。
  另一条教训是**体检类工具必须自报「哪些检查没生效」**：`env_check` 现在透出
  `link_state` 与 `guard.active`，guard 未生效时明说「守卫本次没有生效、外设读数请自行核对型号」，
  别让调用方把「体检没报错」当成「一定没问题」。
- **「原子性」判据也要按字段而不是整字**（承接批次48）：F429 上 `DWT_FUNCTION1` 稳定读回
  `0x00000200`，写 0 也改不掉；该位落在 FUNCTION 字段（bit[3:0]）之外，按整字判「有没有武装」
  会假报警。宁可放宽到字段，也不要把硬件保留位残留报成「没清干净」。

## 十六、目标侧插桩与 trace 后端（批次55，F401 + SVCrtOS 实测）

> 这一节全部来自「在 F401 上真跑 SVCrtOS、用 trace 看任务切换」这件事。
> 结论先行：**不插桩、靠调试器轮询读 SRAM 去看高频事件，这条路是死的**——
> 目标全速运行时读回来的东西根本不可信，halt 读又会把现象本身冻住。
> 想要「看到目标自己是怎么跑的」，必须让目标自己攒证据（插桩 + 目标侧缓冲），
> 调试器只在事后把缓冲搬出来。

### 1. 全速运行时的内存读数是「看似权威的错答案」

- 目标全速跑的时候，经 UVSOCK 读 SRAM/FLASH **一律返回 0**：工具会标
  `read_confidence: low`、`degenerate: all_zero`，但**返回值的形状仍然是一段合法的内存**。
  如果调用方只看"读到了 256 字节"，会得出"这段内存是空的"这种彻底错误的结论——
  实际上缓冲里可能已经写满了事件。**`0` 在这里的语义是「没读到」，不是「没有」。**
- 正确判据：**先 halt，再读，再 resume**；读到 `all_zero` 一律按读失败处理，
  工具会报 `buff-read-degenerate` 并提示先 `stop`。
- 代价要认：一次 `halt → read → resume` 单次约 **320~510ms**；这期间目标时间是冻结的。
  想高频采样（每秒几十次）在物理上就不成立。

### 2. halt 会让「现场」消失，看门狗会让现场彻底消失

- 停机期间目标时间被冻结。用「主机墙钟」估算冻结时长会**系统性偏高**：
  工具上报 `paused_ms` 报 0.33~0.43s，而按目标自身 `wait` 计数反算，
  真实有效冻结约 0.27~0.30s。**目标侧计时与主机侧计时不能混用**，
  分析时间轴时只认目标侧时基。
- 更狠的一层：如果板上的**独立看门狗**（IWDG）没被冻结，halt 超时就直接被复位——
  现场不是"停住了"，是"没了"。所以 `stop` / `enter_debug` 会自动写 DBGMCU 的看门狗冻结位
  （详见[五、断点地址 / 看门狗 / Cache](#五断点地址--看门狗--cache批次32-真机实测)）。

### 3. `stop` 之后的第一读是脏帧

- `stop` 后紧跟的**第一次** `read_mem` 会读到全 0 脏帧，重读即正确。
  `read_mem` 没有收敛判定（`get_current_location` 对 PC 有），
  **必须重读复核再下结论**，否则会把"第一帧脏数据"当成目标内存的真实内容。

### 4. 时间戳不能用内核节拍，必须用 DWT_CYCCNT

- 最初拿 500µs 的内核节拍当时间戳，结果大量记录 `dt=0`：
  10µs 级的切片全部退化成 0，**时间轴直接失去分辨率**。
- 改用 `DWT_CYCCNT`（`0xE0001004`，84MHz 下约 11.9ns/拍）后，`dt` 才有意义。
- 但 DWT 默认是关的：**必须先使能 `DEMCR.TRCENA (1<<24)`**，否则 CYCCNT 永远是 0，
  会静默产出"所有事件同时发生"的假时间线。组件的 `trc_hw_init()` / `_arm_dwt_init()`
  已做幂等使能，自写插桩时别忘了这一步。

### 5. 环形缓冲一定会溢出，必须把 `lost` / `wrapped` 报出来

- 全速录的时候上溢是必然事件，不是异常。工具若只回一段记录，调用方会默认"这就是全程"。
- 因此控制块里必须有 `total` / `lost`，并有 `FLAG_WRAPPED`；
  `trace_buff_dump` 在回卷时会附 warning：「环形缓冲已回卷…看到的是一个窗口，不是全程」，
  丢记录时明说「这条时间线不完整」。
- **分块 dump 一定会撕裂时间线**：实测把 8 块 dump 拼起来，块与块之间有 7 段空洞、合计约 4.1s
  的事件永远看不到（dump 期间目标还在写，而 reset 又把缓冲清了）。
  要连续记录就只有一条路：**把缓冲开大**，一次读完，别指望分块拼。

### 6. 任务号打包成 4bit：好看，但有上限

- SWITCH 事件把 `from`/`to` 各压进 4bit（一个字节装下两个任务号），代价是
  **最多 14 个任务**（`0x0F` 留给空闲）。任务一多就得换成两字节或 varint。
- 这是个典型的"压缩换容量"取舍，写进接口时就要在文档里说清上限，别让用户撞上才发现在静默截断。

### 7. 「没插桩」不等于「没发生」

- `WAIT` 只覆盖了 `wait / wait_period / block` 三条阻塞路径。
  其它阻塞方式（未插桩的那些）在这条时间线上**完全不可见**，
  表现成"任务凭空消失了 20ms"。
- 所以插桩点清单本身就是这份 trace 的"可信边界"：
  **看到的是插了桩的那些事，不是全部的事**。工具与文档都要把这条说清楚。
- 反过来说，插桩的**收尾也要成对**：只有 ENTER 没有 EXIT 的作用域，
  在时间线上就是一条永不闭合的带子——比不插还误导。

### 8. 两种工作模式：stream 与 buff，别混着用

插桩分两种**互斥**的工作模式，选错了会白花很多时间：

| | stream（持续录持续读） | buff（全速录、事后搬） |
|---|---|---|
| 谁在搬数据 | 调试器按节奏读目标缓冲 | 目标自己往静态环形缓冲里写 |
| 调试器占用 | 全程占用（要看时间轴就得盯着） | 只在 dump 那一下占用 |
| 时间粒度 | 受读取节奏限制（毫秒级） | 目标侧 DWT，可到 **10ns 级** |
| 目标是否停 | 读的时候会 halt，目标被反复冻一下 | 运行期间完全不停、不 halt |
| 掉数据风险 | 缓冲小、读得慢就丢 | 缓冲大（默认 2048×12B=24KB），溢出才丢 |
| 适合 | 人在旁边盯着看的实时调试 | 全速跑一段、事后离线分析（**本次场景**） |

- **buff 模式的关键设计**：控制块（80B）+ 记录区（定长 12B/条）**放在一个连续 blob 里**，
  主机只要一个符号 `mdk_trace_buff_blob` 就能定位一切，记录区固定在 `ctrl+80`。
  记录 12 字节 = `type/kind/id(LE16)/arg(LE32)/dt(cycles>>ts_shift, LE32)`，
  解析无歧义、容量可精确计算。
- `reset_req` 是**延迟生效**的：写在控制块里，目标在下一次写记录时才处理。
  因此"写成功"≠"已清空"，工具必须区分 `applied` 与 `request_latched`
  （判据是 `seq` 有没有变），否则会出现"reset 了但读到老数据"。

### 9. 暖启动：复位前后的记录要留在同一条时间轴上

- 默认**不**在 `mdk_trace_buff_init()` 里清空缓冲（`MDK_TRACE_BUFF_CLEAR_ON_INIT=0`）。
- 原因很直接：**看门狗咬、HardFault 复位之后，复位前的那些记录是唯一的证据**，
  清掉就永远看不到了。
- 接缝要显式标出来：置 `FLAG_RESTARTED`、写一条 RESET 记录、把 `last_cycles` 重基到当前时刻，
  这样主机侧能把"复位前 / 复位后"两段画在同一条轴上而不至于算出一段荒唐的时间间隔。
- 一个副作用要注意：记录区的**前半段可能是复位前的旧字节**，如果按 `cap` 去解会凭空多出
  一段假时间线。`_buff_decode` 因此只解**实际读回的条数**（`len(recs)//12`），不按 `cap` 翻。

### 10. 关键插桩点：异常 handler 排第一

真要排障，桩的位置比桩的数量重要得多：

1. **异常 handler 的第一条指令**（HardFault / MemManage / BusFault / UsageFault）——
   `MDK_TRACE_FAULT_CAPTURE()` 会把异常返回帧（PC/LR/SP/xPSR）与 CFSR 一起落进缓冲，
   事后 dump 出来就是"死在哪儿、为什么死"的铁证。这是**性价比最高的一类桩**。
2. **喂狗点 + 复位原因**——把"怎么回来的"记下来，否则一切从 `Reset_Handler` 开始的故事都没法接。
3. **任务/上下文切换点**——看调度是否按预期跑（本次 SVCrtOS 用的是 `svcrt_sched_activate()`）。
4. **状态迁移点**——如"等待 → 就绪"，能解释任务为什么卡。
5. **不该插的地方**：高频中断的最内层、被优化成内联的小函数、时间敏感的临界区——
   插桩本身的开销会变成被观测系统的一部分。

## 十七、历次改进留档（按批次）

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

## 十八、SWD 无缝 stream：节拍与停机搬环（批次56 实测）

只接 SWD 两线（没有 SWO / ETM）时，要把事件流连续录下来：目标侧用「四元组字典 + varint」
把每条事件压到 1~3 字节写进环形缓冲，调试器按节奏停下来搬走。这一节是它在
STM32F401 + SVCrtOS 上真机撞出来的边界，配套工具见 `trace_swd_*` 与
`trace_guide(topic="time_granularity")`。

### 18.1 无缝的硬条件是节拍，不是缓冲大小

> **搬运间隔 < 环容量 / 事件率**

实测 8 KB 环、约 10k 事件/s（SysTick 500µs 拍 ×2 + PendSV 每次切换 2 条 + 阻塞事件），
窗口只有 0.22 s：

| 搬运间隔 | 真机结果 |
|---|---|
| 0.25 s | `lost_events = 29,015`（环溢出） |
| **0.12 s** | **`lost_events = 0`**：5.36 s 连续录制 / 56,355 事件 / 5,386 次切换 / 24,136 次中断进出 |

⇒ 把缓冲开大只是把窗口拉长，**节奏必须短于窗口**；两者要一起算，别只调一边。

### 18.2 丢是丢「整条」，不是覆盖：任何时刻停下，已录的那段都完整

写 token 前先查 `head - drained + n > cap - RESERVE(16)`，不够就**整条丢弃并计数**
（`lost_events` / `lost_bytes`），**绝不覆盖未读区**（`RESERVE` 只留给 `CTL`）。
所以「跑一段 → 停机搬走 → 继续跑」是安全的：压力大时丢的是事件，不是结构。

### 18.3 读环必须停机

Keil 链路全速运行时读 SRAM 可能**整片读回 0**（工具如实报 `swd-read-degenerate`）——
这是「没读到」，不是「缓冲是空的」。停机搬走不会丢数据，靠的就是 18.2 的背压语义。

### 18.4 失步要重对齐，不要硬解

字典不同步时继续解会解出**错误的 key**（看着像合理数据，是最危险的那种错）。
工具报 `swd-stream-desync`，正解是 `trace_swd_reset` 让目标重开一段录制
（清 head/drained/lost、`seq+1`、写 `CTL_SYNC`）。实测重置后 30/30 次搬运全部成功、可自愈。

### 18.5 时间粒度可调：三档真机实测

`trace_swd_reset(granularity=...)` 是**切换粒度的唯一入口**（写完粒度再写 `reset_req`，
延迟生效，需配一次重开录制）：

| 粒度写法 | 语义 | 实测字节/事件 |
|---|---|---|
| `cycle`（最细） | 每个 CPU 周期一个单位 | 3.69 |
| `500us`（内核 tick） | 量化到 500µs；量化后 `dt == 0` 自动走 1 字节 `HITN` | 1.61 |
| `none` | 只记顺序、不记时间：`dt_cycles=None`、`ts="none"`，**不推进虚拟时间** | 1.60 |

- `trace_swd_read(granularity=...)` **只做校验**，是防「读到的是按旧粒度量化过的流」：
  不符报 `swd-granularity-mismatch`，读到一半被改报 `swd-granularity-changed`，
  写法非法报 `swd-granularity-invalid`。
- **量化只损时间分辨力，不损事件顺序**：同一量化窗口内的多条事件 `dt` 全为 0，
  先后仍完整、间隔不可分辨。要定位抖动就别调粗。

## 十九、AC5（ARMCC 5）：编译成功 ≠ 那行代码生效（批次56 实测）

真机现象：控制块符号 `mdk_trace_swd_blob` 整片读回 `0x00`；换固件、改 halt 时机、
连读 5 次都一样。最后发现**板子跑的确实是新固件，但新固件里根本没有 SWD 后端**。

### 19.1 `__has_include` 在 AC5 里不是宏 → 工程配置头被静默跳过

```c
#if defined(__has_include)              /* 只有 GCC / AC6 把它当宏 */
#  if __has_include("mdk_trace_config.h")
#    include "mdk_trace_config.h"
#  endif
#elif defined(MDK_TRACE_USE_CONFIG_FILE)
#  include "mdk_trace_config.h"
#endif
```

armcc（AC5）里 `__has_include` 不是宏，`#if defined(__has_include)` 为假；第二个分支又要求
显式定义 `MDK_TRACE_USE_CONFIG_FILE`。两个都不成立 ⇒ 工程自己的
`mdk_trace_config.h`（写着 `MDK_TRACE_BACKEND_SWD 1`）**被静默跳过**，用的是默认头里的
ITM 后端 —— 一个要 SWO 引脚的别的后端。于是 `mdk_trace_swd_init()` 被整段编译掉，
blob 恒为 0，而**编译 0 Error**。

**解法**：AC5 工程必须在命令行加 `-DMDK_TRACE_USE_CONFIG_FILE`；库作者更该在
「检测到 AC5 且没定义该宏」时 `#warning`，把静默错答案变成响的（本仓库已按此改）。

### 19.2 uvprojx 的 `<Define>` 追加宏不进命令行 → 宏要走 `<MiscControls>`

实测：往 `<Cads>/<VariousControls>/<Define>` 里追加 `MDK_TRACE_SWD_EXTERNAL_PLATFORM`，
编译器仍走默认分支（表现为 `__get_PRIMASK` 这类 CMSIS 函数报隐式声明）；
同一处改成 `<MiscControls>-DMDK_TRACE_SWD_EXTERNAL_PLATFORM</MiscControls>` 立刻生效。

- `<Cads>` 在 uvprojx 约 315-345 行；`<MiscControls>` 340、`<Define>` 341、`<IncludePath>` 343。
- 结论：**宏走 `<MiscControls>`**。两边都写会重复，记得把 `<Define>` 里的删掉。

### 19.3 `register ... __asm("lr")` 语法能过，但会被绑到普通寄存器

`register uint32_t x __asm("lr");` 编译无错，`fromelf --disassemble` 看到的是
`STR r0,[r1]` 而**不是** `MOV r0, lr` —— 读到的不是 LR，却没有任何告警。

同类写法逐条实测：

| 写法 | 结果 |
|---|---|
| `register ... __asm("MSP"/"PSP"/"PRIMASK")` | `#1229 unknown register name`（报错，反而安全） |
| GCC 风格 `__asm volatile("MRS %0, PRIMASK":"=r"(v))` | `#18 expected a ")"` |
| `__ASM`（大写，无 CMSIS 时） | 未定义 |
| `__asm { MOV x, lr }` / `MOV x, r14` | `identifier lr is undefined` |

**可用且反汇编逐字核对过的写法**：

```c
__asm void My_Handler(void) {
    IMPORT sym;
    PUSH {r0-r3, r4, lr}
    MOV  r0, lr
    MRS  r1, MSP
    MRS  r2, PSP
    BL   sym
    POP  {r0-r3, r4, lr}
    B    other
}
```

- 嵌汇编函数里 `IMPORT` 可用；尾跳转会生成 `B.W`。
- `__asm { MRS pm, PRIMASK }` / `CPSID i` / `MSR PRIMASK, pm` / `MRS a, MSP|PSP` 都可用。
- **不能用 C 宏展开去生成 `__asm` 函数**（宏会把换行合成空格 → `A1207E: Bad or unknown attribute`），
  必须逐字写开。

### 19.4 判据与三件套

**判据**：符号在 axf 里存在、地址能从 ELF 解出来，但运行时恒为初始值 →
**先怀疑「这段代码根本没编进去」**，不要先怀疑目标没跑或内存读不对。

三件套（顺序别换）：

1. `fromelf --disassemble <file>.o` 看生成代码 —— 「能编译过」不构成证据；
2. 看 axf 里符号是否存在、地址能否从 ELF 解出；
3. 运行时读关键符号，确认它不是初始值。

> 一句话：**编译成功 ≠ 那行代码生效**。AC5 下凡是「配置没进来 / 寄存器没绑对 / 分支没走」，
> 都先按这三件套证实，再谈目标侧或调试链路的问题。


## 二十、宿主 Python 变量泄漏进外部工具子进程（批次57）

### 20.1 症状骗人：报错点在 SVCrtOS 的脚本上，根因在宿主环境

真机上「F401 工程 Before-Build 的 `py -3 tools/gen_scatter.py` 失败」，看到的是：

```
SyntaxError: f-string: unmatched '('
```

第一反应会去查脚本语法——**脚本没问题**。真正的证据链是：

1. `python -c "import site; print(site.__file__)"` 打印出的 `site.py` **来自 Python 3.12**，
   而实际解释器是 `py -3` 拉起的 **3.10.7**：两个版本的标准库被混着用；
2. `env -u PYTHONHOME -u PYTHONPATH py -3 tools/gen_scatter.py` 立刻跑通（打印「检查通过」）；
3. `reg query "HKCU\Environment"` / HKLM 里**都没有** `PYTHONHOME` —— 说明它不在系统环境里，
   而是**由宿主会话注入**（MCP 服务所在的 Python 进程带进来的）。

### 20.2 传播路径

```
宿主会话（注入 PYTHONHOME / PYTHONPATH）
  → MCP 服务进程继承
    → 我们启动的 UV4.exe 继承（launch_detached / _run_uv4 / ocd / toolchain 都算）
      → Keil 的 Before-Build 钩子 `py -3 xxx.py` 继承
        → 3.10 的解释器去加载 3.12 的 site.py → 崩在 site 初始化 / SyntaxError
```

同一个坑对 ESP-IDF 的 `idf.py` 同样成立：**凡是「我们的进程再拉起一个 python」的链条都会中招**。

### 20.3 约定：外部工具子进程一律走 `winutil.child_env()`

```python
HOST_PY_ENV_VARS = ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
                    "PYTHONUSERBASE", "VIRTUAL_ENV", "CONDA_PREFIX")
env = winutil.child_env()                 # 以 os.environ 为底，剥掉上面这些
env = winutil.child_env(base=env, extra={"PATH": ...})   # 已有环境再剥一遍 + 追加
```

落点（改完由 `tests/test_batch57.py` 的 B 段守住）：`winutil.launch_detached`（两处 Popen）、
`builder._run_uv4`、`ocd`、`toolchain.run_tool` / `probe_version`。

### 20.4 两条元教训

- **注释与实现两张皮**：`launch_detached` 的注释早就写着「避免继承被污染的环境」，
  但 `Popen` 根本没传 `env=`。**声称做了的事必须有断言看着**，否则等于没做。
- **报错点 ≠ 根因点**：跨进程/跨语言边界的报错，先证明「子进程看到的环境是什么」，
  再谈代码逻辑。

> 排查三件事：`site.__file__` 属于哪个版本、`env -u` 去掉变量是否就好、变量是否真在注册表里。

## 二十一、Keil 窗口与文件时序：模态框会堵死调试通道（批次57）

### 21.1 现场

调试 trace 的一轮里，Keil 被开出多个窗口，而且**弹出了模态框**；用户原话：

> 「又开始开多个 mdk 窗口了，而且窗口还有弹窗，感觉你是先开 mdk 再改代码的，
> 导致 mdk 弹窗说文件更新，之前不是说好只开一个 mdk 的吗？」

根因有两条，且是**不同层面**的：

1. **文件时序反了**：先 `launch_uvision` 打开工程，之后又去改源码/工程文件 → Keil 检测到
   外部修改，弹「文件已被外部修改」的**模态**对话框。模态框不止挡人，它会**把 UVSOCK
   通道一起堵住**，后续命令全部超时——表现成「调试通道假死」，很难联想到是弹窗造成的。
2. **窗口没有收敛机制**：`launch_uvision(reuse=True)` 只处理「同工程复用」，
   对「已经开着**别的**工程」没有任何拦阻，于是一次次调用就累积成多窗口（UV4 不是单实例程序）。

### 21.2 处置：把纪律做成机制，不靠自觉

| 层面 | 机制 | 失败时的表现 |
|------|------|-------------|
| 开窗口 | `launch_uvision(single=True)`（默认） | 已有**别的工程**的窗口 → 拒绝，`error_code=keil-multiple-instances`，返回 `open_instances` + 下一步；已有**同工程**窗口 → 强制复用（`reuse_forced=true`）；没给 `project` 且已有实例 → 同样拒绝（**无从比对就不猜**） |
| 关窗口 | `close_uvision(keep="all"/"latest"/"oldest")` | 收敛时用 `keep="oldest"`：**持 UVSOCK 4823 的是最早那个实例**，按「留最新」关会把通道关掉 |
| 改工程 | `uvprojx_edit` 先问「Keil 是否开着这个工程」 | 开着 → 拒绝，`error_code=project-open-in-keil`，给出 `open_instances` 与 `close_uvision` 建议；`force=true` 才放行 |
| 开窗口后的顺序 | `launch_uvision` 成功即返回 `order_hint` | 明写「**此刻起不要再改源码/工程文件**；要改先 `close_uvision`」 |

**为什么是「拒绝」而不是「自动关掉再开」**：关掉用户的 IDE 是不可逆动作，
必须由调用方显式决定（工具只负责把「现在有几个、都是什么工程」摆清楚）。
守则是**宁可报错，也不给看似权威的错答案**：宁可让调用方停下来看现场，也不悄悄制造多窗口/模态框。

### 21.3 真机验证与回归守卫

- 守卫的探测失败**不阻断写入**（`list_uvision_instances` 抛异常时放行）：守卫只做加法，
  不能让一个探测把功能锁死；
- `tests/test_batch26.py` 的 C 段覆盖 single 的四种组合（拒绝 / 强制复用 / `single=false` 放行 /
  无 `project` 时拒绝），`tests/test_batch57.py` 的 C、D 段覆盖 `uvprojx_edit` 守卫与 server 层透传；
- 另外把 `test_batch21` 补进闸门（它原先没设 `MDKDEBUG_TOOLSETS=all`，
  工具面默认精简后 `flash_debug` 根本不在表里，单独跑必挂——**闸门漏网比测试失败更危险**）。

## 二十二、部署完 ≠ 能链接：组件承诺提供符号却没人定义（批次57 实测）

**现象**：把 buff 后端接进真实工程，第一次编译就报 `L6218E: Undefined symbol
mdk_trace_buff_blob`。

**根因在组件，不在工具**：`components/trace/mdk_trace_buff.h` 里写了

```c
extern mdk_trace_buff_blob_t mdk_trace_buff_blob;
```

却没有任何 `.c` 定义它。同族的 SWD 后端有对称的一行
（`mdk_trace_swd.c`：`mdk_trace_swd_blob_t mdk_trace_swd_blob;`），是 buff 漏了。
两个后端的契约完全一样（头文件注释、README、PITFALLS 都写「blob 在 `.bss`、
链接后地址固定、主机只靠一个符号定位」）——SWD 自己提供了存储，buff 忘了。

也不是「生成物没入库」：`.gitignore` 里没有任何 blob / 生成文件规则，定义从来没进过仓库。

**为什么三层防线都没挡住（这才是教训）**

| 层 | 现状 | 后果 |
|---|---|---|
| 单测 | `test_batch55` 把 `_elf_symbol` / `read_mem_words` / `_write_mem` 全换成替身 | 只验「主机能不能解包」，从不编译 C 代码 —— 少个定义照样全绿 |
| 工具 | `trace_instrument` 只做「拷文件 + 生成配置头 / mk 片段」，next 里没提「存储谁定义」 | 没有「能不能链接」这一步，编译期错误被推迟到用户第一次真编译 |
| 文档 | §16 与 `components/trace/README` 只描述设计（blob 在 `.bss`、一个符号定位…） | 用户没有兜底线索，只能自己撞 |

注释里反复写「编译成功 ≠ 那行代码生效」，这条教训这次正好落在自己身上：
**测试全绿 ≠ 用户能编译**。

**修法**

1. **组件侧**：`mdk_trace_buff.c` 补上与 SWD 对称的定义。定义跟着后端走，
   Keil / CMake / Make 任何集成方式都直接可用，不依赖工具去改用户的工程文件。
2. **构建清单对齐**：`mdk_trace.mk` 与 `components/trace/CMakeLists.txt` 都漏了
   `mdk_trace_swd.c`（CMake 连 swd 的 `MDK_TRACE_BACKEND_SWD` 分支都没有）——
   同一类「承诺与清单不一致」，一起补。
3. **工具侧**：`trace_instrument` 部署后**就地编译 + 链接**做自检
   （`link_check`，默认开）。空壳提供 CMSIS 内在函数与入口，缺任何符号都在链接期
   以 `undefined reference` 现形（= `L6218E` 的等价物）。返回 `self_check`；
   缺符号时整体 `ok=false` + `error_code=component-link-failed`，并给出
   `missing_symbols` 与 `sources`（该进编译的文件清单）。
   **本机没有 C 编译器时 `self_check.checked=false`** —— 那是「没查」，
   不等于组件没问题，必须如实转述，不能当成通过。
4. **闸门**：`tests/test_component_link.py` 对五个后端各真编一遍并链接，含**反证**
   （删掉 blob 定义必须失败并点名该符号），已纳入 `tools/run_all_tests.py`。
   §19 那类「编译期静默」（AC5 `__has_include` 悄悄跳过配置头）能被同一道门禁一起挡。

**自查一句话**：只要组件新增了「主机靠符号定位」的东西，就必须有人定义它，
而且要**真编一遍再链接**才算验证过 —— 主机侧的 mock 再全绿都证明不了链接成立。


### 22.1 核查：批次55 的 buff「真机实测」到底编过没有

§16 的标题写着「F401 + SVCrtOS 实测」，但这个缺陷按理会让那次链接不出来。
本轮把证据翻了一遍（不猜）：

| 证据 | 结果 |
|---|---|
| 仓库历史里是否出现过定义 | `git log --all -S "mdk_trace_buff_blob_t mdk_trace_buff_blob;"` **零命中** —— 定义从来没进过仓库 |
| `D:\工作\git_project` 下有几份 `mdk_trace_buff.c` | 只有仓库那一份（`find` 全目录），不存在「本地手加定义」的副本 |
| SVCrtOS 工程里部署的是哪个后端 | `svcrtos_new/kernelsrc/components/mdk_trace/` 只有 `mdk_trace.c/.h` + `mdk_trace_swd.c/.h` + 平台头 —— **没有 buff 的文件** |
| 那台 F401 的编译产物 | `example/stm32f401/.../SVCRTOS_TEST/MDK-ARM/SVCRTOS_TEST/` 里只有 `mdk_trace.o` 与 `mdk_trace_swd.o`，**没有 `mdk_trace_buff.o`** |
| `example_mdk_project/mdk_test` | 从未部署过组件，`mdk_test.uvprojx` 的源文件清单里也没有 `mdk_trace*.c` |

**结论**：批次55 的 buff 后端**从来没有在真机上编译过**。当时 SVCrtOS 上部署并编译的是
批次56 的 swd 后端 —— 这也正好解释了为什么 swd 的定义在（它编过），而 buff 的缺定义
一直没人撞到（它没编过）。§16 里关于 buff 的段落是**设计约定**（blob 布局、`ctrl+80`、
暖启动保留记录）与主机侧解码行为的说明，不是「buff 固件在 F401 上跑过」的记录。

**教训**：文档标题里的「实测」要写清实测的是**哪条通路**——不同后端的编译验证不能互相顶替；
一个后端编过，不等于另一个后端的源文件齐全。


## 二十三、定位类「看似权威的错答案」三连（批次60）

三条属于同一族：**函数没崩、返回值也「像」，但结论把排查引向错误方向**（或干脆静默失效）。
均为本机/真机实测，不是推演。

### 23.1 UV4 找不到，其实是「查错了地方」

`find_uv4()` 的注册表分支只读默认（64 位）视图。而 **Keil MDK 是 32 位程序**，键注册在
`SOFTWARE\WOW6432Node\Keil\Products\MDK`。本机实测：

| 查询 | 结果 |
|---|---|
| `HKLM\SOFTWARE\Keil\Products\MDK`（64 位视图，旧实现走这条） | 找不到（错误码 2） |
| `HKLM\SOFTWARE\WOW6432Node\Keil\Products\MDK`（32 位视图） | 命中，`Version=V5.41`，`Path=D:\Keil_v5\ARM` |

也就是说注册表这条路在本机**等于没查**；`find_uv4()` 之所以还能返回
`D:\Keil_v5\UV4\UV4.exe`，纯粹因为候选列表里写死了 `D:\Keil_v5\...` 这一条。
Keil 装在 F: 盘或非标准目录时，两条路会**同时哑火**。另一个坑：`Path` 的值是**工具根**
（`...\Keil_v5\ARM`）而非安装根，旧实现拼 `Path\UV4\UV4.exe` 拼出的文件并不存在。

修法：`_logical_drives()` 枚举真实盘符 × `uv4_candidates()` 常见子目录动态生成候选；
`_uv4_from_registry()` 同时查 32/64 两个视图（`KEY_WOW64_32KEY` / `KEY_WOW64_64KEY`），
`Path` 兼容「本级 + 上提一级」两种拼接；找不到时返回**尝试记录**（查过哪些键/视图/值），
不静默。

### 23.2 一个缩进，让「启动时没配工程」这条兜底直接崩

`_find_project_candidates()` 原本写在 `create_server()` 内部（缩进 4 格），而模块级函数
`_ensure_locator()` 会调它做第 4 条兜底「附近自动发现」。于是：

```
NameError: name '_find_project_candidates' is not defined
```

触发条件**正是这段代码要解决的场景**（服务启动时既没给 `--axf` 也没给
`--default-project`、会话里没用过工程、符号工程注册表为空）。`call_tool` 对
`super().call_tool` 只有 `finally`（收并发计数）没有 `except`，异常直接穿透到框架——
既拿不到「附近唯一可推断的工程」的自动挂载，也拿不到设计好的「符号定位未就绪」提示。

顺带：候选搜索默认 `max_depth=2` 连本仓库自带的
`example_mdk_project/mdk_test/MDK-ARM/mdk_test.uvprojx`（第 3 层）都搜不到，却会回一句
「未在附近找到任何 .uvprojx」——又一条错答案。默认调至 4（目录数仍由 `cap` 兜住）。

### 23.3 `文件:行号` 解析：报错原因指错方向

`_parse_target_ex()` 用 `rsplit(":", 1)` 切目标，对 Windows 路径会把盘符当成文件名：

| 输入 | 旧行为 | 新行为 |
|---|---|---|
| `D:\proj\Core\Src\main.c`（漏行号） | 「行号不是整数：'\proj\Core\Src\main.c'」→ 把 AI 引去「修行号」 | 「看起来是源文件路径，但缺少行号」+ 写法提示 |
| `main.c` / `Core/Src/main.c` | 「无法识别的目标写法」 | 同上（缺行号） |
| `main.c:0` | 直接下传给 locator（0 没有对应指令） | 拒绝：行号必须 ≥ 1 |
| `main.c:` | 「行号不是整数：''」 | 「行号缺失（冒号后为空）」 |
| `:77` | 空文件名丢给 locator 去猜 | 「文件名缺失」 |

新增 `_looks_like_file()`（带路径分隔符，或后缀属源文件后缀）专门把「缺行号」与
「写法不认识」分开——这两者要补的东西完全不同。`run_to_line` 也改为优先透出解析器给的
`hint`，不再一律套用「写法尽量带目录」那条静态提示。

**共同教训**：错误信息的**方向**和错误信息的存在同样重要。报「行号不是整数」时 AI 会去
修行号；报「缺少行号」时它才会去补行号。凡是「解析失败」的分支都该问一句——
这句话会把排查引向哪里？

## 二十四、全速运行时读 SRAM：会整段读回「同一个 4 字节字」（批次63，F427 实测）

**现象**：无缝流（`trace_swd_*`）在 F427 + DAPLink + Keil UVSOCK 上持续丢事件，
`lost_events` 涨到 80 万+，`swd-stream-desync` 之后游标再也不推进、环立刻填满。
失步位置**恒定**在 `ring + 7912` = 绝对地址 `0x20004000`。

### 24.1 判据：停机读忠实，运行态读不忠实

| 实验 | 结果 |
|---|---|
| 停机读整环 | 8192 B、**tok = 8060 == 目标 `tokens` 8060**、零失步 |
| 运行态同一区间连读多遍 | 每遍都不同，失步 7912 / 7915 |
| 同一区间三种切法（一次读/对半切/1000 步进） | 7912 处**互相都不同** |
| 停机写入 ramp → run → 停机回读 | **图案完好** ⇒ 没有任何别的东西在写这块内存 |
| `head` 变化 | run 窗口内未前进（背压钳制不覆写）⇒ 不是「环被覆写」 |

### 24.2 坏区形状

在环内 `0x20003C00..0x20004100` 逐 64 B 写不同图案后 run 态连读三遍：

* `0x20003C00 … 0x20003FC0`（16 块）：三遍全对；
* `0x20004000` 及以上（16 块）：run#0 对、run#1/#2 错且互不相同。

伪值的形态**不是**全 0 / 全 FF，而是：**同一个 4 字节字在整段里重复**（`n≥8` 必现，
`n=4` 有时还对），且**换地址也是同一个字**——`0x20004000`、`0x20004100`、`0x20005000`、
`0x20010000`、甚至外设 `0x40020000` 全都返回它，该字还随读的推进单调地变。

跨总线对照（run 态）：`0x20000000` 忠实可重复、`0xE000ED00` 忠实（CPUID 正确）、
`0x08000000` 读回全 `00`、`0x10000000` 三读不一致。

### 24.3 为什么以前没被发现（F401 那次的真相）

批次56 在 **F401 上就撞过同一类故障**，当时的记录是「全速运行时读 SRAM 可能整片读回 0
（`swd-read-degenerate`）」，处置办法是**停机搬运**（「跑一段 → 停机搬走 → 继续跑」，
靠背压保证不丢）——所以 F401 的「零丢失」是停机搬运的战果，不是运行态读可靠的证据。
之后批次45 把 `need_halt_for_read()` 判成 `False`（理由是「运行态读得到、256 B 大块也稳」），
那次只覆盖了低 16 KB；`≥ 0x20004000` 用同样的大块读就是伪值。

另外，「F401 的环位置好」这个解释不成立：F401 的 ring 在 `0x200049D0..0x200069D0`，
**整段都在坏区里**，真按同一条规则只会更容易踩到。差别只在搬运方式。

### 24.4 修法（批次63）

1. **`trace_swd_read(consistent="halt")` 成为默认**：halt → 就地重读控制块（一致快照）
   → 搬 → 停机时把 `drained` 推上去（运行态写 SRAM 也可能不生效）→ resume。
   返回 `consistent` / `halt_ms` 如实交代。真机实测：14 轮共搬 73 658 B、
   折出 73 423 个 item、**`lost_events = 0`**；代价是每次停机 ~0.5 s（SWD 搬 5 KB 就那么久）。
2. **伪值签名**：`all_zero` / `all_ff` / **`repeated_word`**（扫描式，不假设 4 字节对齐，
   只有尾部坏也能认出；字节全同的 HITN 连发段不误判）。`consistent="run"` 撞上伪值
   直接报 `swd-read-untrusted`，不拿去解码。
3. `consistent="auto"`：先全速读，发现伪值自动停机重读，并在 `notes` 里说明「已改用停机搬运」。

**共同教训**：这条链路上「读得到」和「读得对」是两件事。任何把「全速运行时的内存读」
当成可信输入的路径，都必须要么改成停机一致快照，要么给出**能自证的忠实度判据**
（这里是目标自己的 `tokens` 计数器与伪值签名）——否则坏数据会伪装成正常字节流，
下游解出的「垃圾」看起来就跟「目标没数据」一样。

## 二十五、给「任务号」取名字：三个会给出**像样错名字/错沉默**的陷阱（批次64，F427 实测）

SVCrtOS 的调度事件只带 4 bit 任务号（0..14 是任务表下标、0xF 是 idle）。取名办法是读
`svcrt_task_table` 每项的 `entry`（函数指针）再反查 ELF 符号。三个坑都踩到了：

1. **`entry` 带 Thumb 位（bit0=1）是正常的**。ARMCC 把函数地址存进表里就带这个位，
   拿 `e & 1` 当「不可能的值」会把整张表判死。先 `e & ~1` 再匹配。
2. **「落在 ELF 代码区间之外」不是伪值证据**——SVCrtOS 的 app/驱动是**另外下发的镜像**，
   它们里面任务（例如 `led_blink_task` 之外的两个进 0x08043xxx）的入口本来就不在
   内核那份 `.axf` 里。F427 实测：0/1/2/5 能命名，3/4/6 落在 app 分区 → 用「代码区间」
   判伪值会把这份**正确**的快照整批判成 `tasks-snapshot-inconsistent`（连续 4 次复现）。
   正确做法：**精确匹配函数首地址**（不用「最近的下方符号」——那会给跨镜像地址安上
   一个像样的错名字），匹配不上就**留空**并在 `unmapped_slots`/`hint` 里说清楚，
   只有**所有**非空槽都匹配不上才整批拒绝（说明这一读大概不可信）。
3. **停机后紧跟的第一次读可能是整段 0**（与第二十四条同源）：一次脏读就把
   「没有名字」缓存一整个会话是白丢信息。读到伪值/短读时**停机重读一次**
   （真机 12840 字节读回 `all_zero` → 重读即正确），两次都不行才如实报失败。

**共同教训**：跨镜像的系统里，「地址不在我的符号表里」= **合法但无名**，不等于「错」。
把「我认不出」等同于「这是伪值」，会把正常现场判成坏数据；反过来把认不出硬编一个
`sub_XXXXXXXX`，又会给出看着合理却错的名字。两条都要避开：留空 + 说明怎么补名字。

## 二十六、多份镜像联合取名：地址命中 ≠ 身份可信（批次64，F427 实测）

第二十五条把「认不出 = 合法但无名」立住了，接下来自然要问：能不能把 app/驱动的 `.axf`
一起传进来，让那些跨镜像的入口也拿到名字？可以，但多了一层**身份**问题：

1. **`elf` 支持多份**（`;`/`,` 分隔，如 `elf="内核.axf;app.axf"`）。布局/任务表取
   **第一个具备者**，名字从**所有**镜像按**精确函数首地址**匹配；命中不在第一份时
   记 `sym_from`（来自哪份）。任一路径不存在 → `tasks-elf-missing` 并**点名**是哪个，
   不许默默少给几个名字。
2. **跨镜像的名字必须过内容核对才作数。** 地址精确匹配只证明「这个地址在**那份**
   `.axf` 里是个函数首地址」，不证明**板上跑的就是那份构建** —— 同一个地址换个构建
   完全可能是别的函数，拿符号名安上去就是一个「看着很权威的错答案」。
   做法：读板上该地址的若干字节（实测 16 B 够用），与 `.axf` 里同地址的字节比；
   核过 → `sym_verified="content-confirmed"`；**核不过或核不了（读不到 / 文件里取不到
   字节）→ 丢名**，进 `unconfirmed_slots`、槽位 note 说明原因，并**并入 `unmapped_slots`**。
   「核不了」≠「核过了」，这一点单独写了一条判据。
3. **不是所有情况下都能核对成功，也不是所有情况下都该核对。** 只对**跨镜像**命中做
   核对（第一份镜像自己的符号就是当前构建的符号，再核一遍只是浪费一次读）。
4. **对当前板子可能一无所获，而且这是对的结果。** F427 实测：把 example 下 5 份
   `.axf` 全扫一遍，板上 3/4/6 号入口（`0x08043D31/0x080403AD/0x08042291`）**在
   任何一份里都不是函数首地址** —— 那是因为这几个镜像当时并**不在**这些构建里。
   此时正确的产出就是「照旧 `ctx3/ctx4/ctx6` + 说明怎么补名字」，而不是编一个。

**教训**：跨镜像取名有两个独立的门槛 —— 「地址在这份符号表里」（匹配）和
「板上跑的确实是这份」（核对）。只过第一关就报名字，等于把「大概」当「确证」。

## 二十七、统计口径别写在绘图口径里：一个 badge 报出「事件 0」（批次64）

时间线渲染适配层用 `len(evs) * thinned` 报「事件」条数：没抽稀时 `thinned = 0`，
于是**满屏轨道配一个「事件 0」**；真抽稀时它又只是**估算**（8 条报成 10 条）。
同一处的 `limits` 还写着「统计口径仍是全量」，可 sched/fault 计数恰恰是在**抽稀后**
的子集上数的 —— 文案与事实相反。

处置：**抽稀前先把真值留下来**（`total_events = len(evs)`），badge 报总数、
类型计数一律走**全量事件列表**；文案改成「每 N 条抽 1 条**绘制**（总数与下面的计数
仍是全量）」。回归用例同时钉住两头：没抽稀时 badge == 条数（不能是 0），
抽稀时 badge 仍是全量条数。

**教训**：一个函数里同时存在「画几个点」和「发生过几次」两种口径时，任何
`len(抽稀后) × 步长` 之类的反推都是在猜——它既可能是 0，也可能不等于总数。
真值要在抽稀**之前**取，且不要把两种口径写进同一句话里。

## 二十八、量化余数被丢掉：一条画得出来、却冻在原点的时间轴（批次64）

F427 上录 SWD 无缝流，粒度 `500us`。页面出来了、时长报 44 s、上下文切换报 12081，
看着都对；用户一眼看出问题：**「任务切换怎么这么慢而且只有一次」**——泳道里只有
一两段，所有事件其实都堆在原点。

根因在**设备侧**，不在渲染侧：
`mdk_trace_swd_event()` 里 `dt = (now - s_last_cycles)`，然后
`dt = dt / c->dt_unit`（或 `>> ts_shift`）——**整数除法把余数丢掉，且不累加到下一次**。
粒度比事件间隔粗时每条都算出 0；`dt == 0` 走 HITN 分支，**只写 1 字节、不写 dt**，
宿主读回来就是 0。宿主按「与上一条的时间差」累加 dt，时间轴就永远停在原地。

几个容易把人带偏的点：

1. **`dt == 0` 本身不等于冻结**，它只表示「与上一条落在同一个量化桶里」。
   判据是「**本批全都**是 0」（宿主据此报 `time_axis_frozen`）。粒度 10 µs 时
   只有约 30% 的事件带增量，时间轴照样是真的——因为绝对时刻是累加出来的。
2. **这类错误是「看得见的错答案」**：页面上会画出一条平平的、有刻度的轴，
   而不是报错、不是空白图。所以宿主侧必须主动报 `time_axis_frozen`，渲染侧
   badge 报「冻结」并把说明写进 limits。
3. **换细粒度是有代价的，而且代价会正反馈**：粒度越细，每事件字节数越大
   （500us ≈ 1.01 B/事件 → 1us ≈ 2.33 B/事件 → cycle ≈ 3.33 B/事件），
   环 8192 B + 停机搬运 ~1 s/轮 ⇒ 可持续搬运约 6~9 KB/s。一旦生产超过搬运，
   丢一条 ⇒ 目标清字典 ⇒ 下一条必是 LIT（5+ 字节）⇒ 更快填满 ⇒ 丢更多。
   实测 F427 上 10 µs 是甜点（1.31 B/事件 ≈ 5.6 KB/s）。
4. **宿主侧的两个放大器**（都在批次64 被实测咬到）：
   - `limit` 给太大：`events` 是「会话最后 limit 条」，给 20 万时每轮都要把整个
     会话序列化成 JSON 喂回来，单次调用越来越慢 → 环在调用期间溢出。
     压到刚够盖住本批后，同一次 24 轮录制从 `lost +33570` 降到 `+2299`。
   - 直接 `events.extend(out["events"])`：那是**会话尾部（含前面调用的事件、互相重叠）**，
     不是本批新增。拼出来的「轨迹」是 N 个重叠窗口，条数好看但是重复计数。
     要拼线性轨迹必须取尾部 `new_events` 条（现在有显式开关 `only_new=true`）。

**教训**：把「采样真值（时间）」做成了有损量化，就必须同时给出**量化是否已经失效**的
判据与提示，否则下游拿到的是一个**结构正确、数值全错**的结果。另外：任何「循环搬运」
的采集姿势，慢一点点不是慢一点点，而是丢一堆。

## 二十九、分析层的四条「看着正常、实际是错的数」（批次72）

分析层（`trace_stats` / `trace_diagnose`）本身不采集，它坐在三种采集源之上。落地时撞到的
四类问题都不是「报错」，而是「算出一个像样的结果」，所以每条都要靠**约定**堵死。

1. **拿错时间基算占比**。MTF（SWO/RTT）事件只有主机到达时刻 `t`，里面混着链路缓冲与
   主机调度抖动。用它算 CPU 负载/任务时长，会得到一条看着正常的百分比曲线 —— 而真值
   只存在于目标侧时间戳里。处置：时间占比类指标**只认目标侧时间基**（`cycles`/`us`），
   源里没有就把相关指标整条丢进 `not_applicable`，并写明原因。计数类任何源都算。

2. **MTF 通路把语义帧解成 raw_hex**。`traceproto.MTF_TYPES` 原先只到 8，批次72 新增的
   9–12（fault/sched/sync/heap）没有对应项，解码时落到 `raw_hex` —— from/to、obj/op、
   CFSR **全丢**，而且不报错。处置：`MTF_TYPES` 与 `_PAYLOAD_FMT` 一并补 9–12
   （`<HI` → id/arg）。教训：**新增一个类型号，要把「主机侧认识它」的所有表都走一遍**
   （swd 的 `TYPES`、traceproto 的 `MTF_TYPES`/`_PAYLOAD_FMT`、trace 的 `_BUFF_TYPES`），
   少一张表就是一个静默的信息黑洞。

3. **一个键名两义**。批次56 的 `_swd_fold` 用 `type:"sync"` 表示「段重开标记」，批次72
   新增的 11 号语义事件类型也叫 `"sync"` —— 两者会在 `counts_by_type`、轨道分组里
   **静默合并**，把「重开录制段」和「同步原语」混成一类。处置：按「一个键名一义」，段
   标记改名 `type:"segment"`（`gap`=丢事件、`segment`=重开段）。改名要连 viz/adapters
   与所有测试的数据一起走，漏一处就是另一条静默错误。

4. **把「净额」当成「峰值」，把「没插桩」当成「没发生」**。堆只有分配/释放事件时，
   能算的是**净变化** `net_bytes`（分配 − 释放），**不是峰值占用** —— 峰值需要每次分配时
   知道堆的实时用量，协议没带，就不猜。同理 `heap` 事件为空只能说「没有堆事件」，不等于
   「没分配」；`sched` 为空不等于「目标没切换」；`sync` 为空不等于「没人阻塞」。这些全部
   落 `not_applicable` 并附原因，而不是给 0。

**共同点**：四条都属于「看似权威的错答案」在分析层的变体 —— 输出结构对、数值错或含义被
偷换。堵法也一致：**能证明的才算，算不了的进 `not_applicable` 并说清为什么**；同时用
`checked` / `not_applicable` 两个字段让调用方能区分「查过了没问题」和「根本没法查」。

## 三十、把外设「绕过固件」直接驱动：区分固件缺陷与核心/硬件楔死

真机排一套 USB 设备固件（STM32F401 + DWC2 OTG_FS，探针固件）时，卡在一类最难查的现象上：
**设备能枚举、控制端点正常、某一条 bulk IN 端点永远送不出数据**（主机只看到超时）。本文
记录从中提炼出的**可复用调试手法**与必须记住的寄存器级事实。

### 手法：CPU 停机 + 调试器直接武装外设，把固件整层排除掉

判据是「到底该怪固件还是怪外设/硬件」。做法（本工具链可直接完成）：

1. `halt`（停 CPU）—— 外设时钟与串行接口**不受 CPU 停机影响**，这是关键前提；
2. 用 `write_mem`（`mww`）按**手册顺序**把外设寄存器写到"应该能工作"的状态：填数据 FIFO、
   写传输长度寄存器、最后写控制寄存器的使能位；
3. 立刻回读这几个寄存器，确认写入**生效**（不是"写成功"）；
4. 主机侧发起一次真实传输，观察结果。

结论怎么读：

| 现象 | 结论 |
|---|---|
| 手工武装后主机收到数据 | 外设通路没问题 → 回去查固件的时序/状态机（谁把状态清了、谁抢先写 FIFO） |
| 手工武装后**仍然**送不出，寄存器也确认写对了 | 问题在**固件之外**——但不等于硬件坏。下一步必须做**主机侧管道复位**试验（见下方「未决」），别直接判成硬件砖 |
| 主机侧 `clear_halt(该端点)` / 端口复位后就通了 | 卡住的是**主机与设备间的端点状态**（数据翻转/管道 halted），不是 MCU 里的状态机——可软件恢复 |

本次实测的判据链：`DIEPTSIZ` 回读 `PKTCNT=1/XFRSIZ=7`、`DIEPCTL` 回读含 `EPENA=TYPE=Bulk`、
FIFO 空闲字从 64 掉到 62（数据确实进了该端点的 TX FIFO），而 `DIEPINT` 始终没有 `XFRC`、
主机始终收不到 —— 且**停机状态下由调试器直接武装同样如此**。于是"固件没把数据搬进去"这一
类猜测被彻底排除。

**两条通用提醒**：

- **停 CPU 会掩盖"固件在 ISR 里补救"的路径**。手工武装的前提是"这一笔本来不需要固件参与"
  （DWC2 的 IN 传输就是硬件自走）；需要 ISR 参与的流程不能这么测。
- **停机后回读寄存器要按手册确认读回窗口**。停止后的第一次读可能拿到脏值（见§三），
  本文的结论都用了"写后 2 次读一致"的方式。

### 必须记住的 DWC2/OTG_FS 寄存器事实（都踩过）

1. **`EPENA` 写 0 无效**：只有 `EPDIS` 能清使能位；**`EPENA=1` 时对 `DIEPTSIZ/DOEPTSIZ`
   的写入被核心整笔静默忽略**（不报错）。所以"先清长度再重武装"之前必须先 `EPDIS` 退场，
   否则得到的是一句假成功。
2. **FIFO flush 前等 `GRSTCTL.AHBIDLE`**，且**等待一律要有界**：这段代码常放在中断里，
   无界等一旦不返回就是整机哑（比原 bug 更难查）。
3. **`GRSTCTL` 的 `TXFNUM` 是字段不是位**，不能 `|=` 叠加。
4. **别使能自己不处理的中断位**：IN 端点的 `ITTXFE`（收到 IN token 而 FIFO 空）是电平型，
   没人消费就变成刷屏风暴，白烧 CPU 还打爆 trace 环。
5. **控制端点的 MPS 字段语义与其它端点不同**（EP0 上 0 就表示 64 字节），照抄会写错。
6. `DTXFSTS`（该端点 TX FIFO 空闲字数）是判断"数据到底进没进 FIFO"的**直接证据**，
   比"我调用过写函数"可靠得多。

### 未决 → 已复核修正（2026-09-26 晚）

**原结论**：「跨软件复位存活，只有断电重插能恢复」——**这条被推翻了**。

复核实验与结果：

| 处置 | 结果 |
|---|---|
| 经 SWD 对目标 MCU 整片复位（`reset run`） | 救不回 → 卡住的状态**不在 MCU 内** |
| 主机侧 `clear_halt(0x81)`（ClearFeature(ENDPOINT_HALT)） | **当场恢复**（`DAP_Info` 正常返回） |
| 主机侧 USB 端口复位 | 恢复 |

固件侧旁证：该外设的 vendor IN 端点**从不置 `EPCTL_STALL`**（只有控制端点会），所以不是
「设备 STALL 了端点没人清」。剩下的解释是 **EP IN 方向的数据翻转（data toggle）在主机与设备
之间失步**，只有主机重枚举/清管道才归零。

**触发条件未隔离（诚实记录）**：同一个 `clear_halt` 在另一次实验里反而打断了健康的端点；
「连写多笔不读」也没能稳定复现。自制主机采样壳自身的激进动作（取消读、`dev.reset()`、
`ClearHalt`）同样会改变状态，**不能单方面归因给固件**。

**可操作结论**：

1. 现场遇到这类「收得到命令、送不出应答」时，**先做主机侧端点清 halt / 端口复位**，不要直接
   判硬件砖、也不要急着改固件；
2. 报告硬件结论前，先找一台**规范主机**（如 OpenOCD）验证——本次 OpenOCD 对同一探针
   连续多轮全通（连接/halt/flash probe/AP 读写/300k~4000k），始终未出现楔死；
3. 真要做到自愈，方向是**保持 EP IN 的翻转与主机同步**：`EPDIS` 退场 + 重新 `EPENA` 会重置
   设备侧翻转，而主机侧翻转不受控；DWC2 可用 `DIEPCTL.SETD0PID`/`SETEVNFRM` 显式指定，
   但需先确定主机期望值。

---

## 三十一、端口探测：connect 探测会把活着的服务判成「没人监听」（批次80 收尾）

`port_listening()` 早先用 `socket.create_connection()` 连一下，连上就算有监听。这个做法在
本机被实测打穿：对**同一个活着的** mock（`listen(1)`）连探 60 次，**18 次失败，且全部是
`socket.timeout`，不是 `ConnectionRefusedError`**；同一时刻 accept 线程还活着、把 backlog 加到
16 之后仍是 27/40 成功。也就是说失败来自本机对瞬时 SYN 的干扰（防火墙/安全软件的常见行为），
不是服务端不在。

**为什么这不是「测试环境的小毛病」**：`port_listening` 的结论会被 `keil_health` /
`restart_keil` 拿去做「Keil 没跑就重启」的决定。把探测手段的抖动报成「端口未监听」，就会让
人/AI 去杀掉一个本来正常的 Keil 实例——这正是「宁可报错，不给错答案」要防的那类误判。

**改法**：Windows 上对本机回环 host **先查操作系统记账**——`GetExtendedTcpTable` 的
IPv4 监听表（`_tcp_listener_rows_v4` / `_listener_ports_v4`），表里有就是有；表查不到（非
Windows、远端 host、iphlpapi 失败）才回退 connect 探测（被拒重试 3 次，超时不重试）。
表是内核记账，不受 SYN 抖动影响。

同时修了测试夹具的两处「放大器」：

| 位置 | 原来 | 问题 |
|---|---|---|
| `tests/mock_uvsock_server.py` | `sock.listen(1)` | backlog 只有 1，短连接连探时队列满会丢/延后 SYN |
| 同文件的 `_accept_loop` | `except OSError: break` | 任何瞬时错误都会**永久杀死** accept 线程，而端口还在监听 → 之后所有探测都失败，看起来像服务没了 |

**可操作的判据**：要回答「这个端口有人在监听吗」，在 Windows 上不要用 connect 探测当唯一
证据；连接成功可以证明有监听，连接超时**不能**证明没有。

---

## 三十二、要吸收的是工具的口径，不是工具本身（Ghidra 反编译器）

2026-10 用户提「NSA 开源的逆向工具能不能吸收一下」，指的是 Ghidra。第一反应是接它的
`analyzeHeadless` 拿反编译结果——写下去才发现这条路本身就与这个项目的前提冲突：

- Ghidra 是 Java 体系，11 起要 **JDK 21**；整套发行包约 **400 MB**。接进来意味着
  「有 Keil 就能跑的工具」变成「还得装 JDK + 400 MB 逆向框架」。
- 实测本机下载速度 16 KB/s（GitHub 直连 30 KB/s、gh-proxy 峰值 455 KB/s 但持续掉到 16 KB/s），
  连「先跑通一次」都做不到——**没跑通就发货，等于把一个没验证过的东西写进 README**。

用户一句「不要增加依赖好吗？」把方向掰正了：**吸收口径，不引入工具**。于是只拿它两条思路，
用已有 capstone 自己实现：

| 口径 | 实现 |
|---|---|
| 函数体到**终止指令**为止（返回 / 跳出本区间的无条件跳转 / 间接跳转），不是「切到下一个已知入口」 | `_shape_function()`：按地址顺序走到第一个终止点；`body_basis` 记 `return` / `tail_call` / `indirect_branch` / `next_entry` |
| 按 AAPCS 用 `r0..r3` 的**首次访问是读还是写**估参数个数 | `_arg_hint()`：先读=参数，先写=局部变量；中间断档就不往后数 |
| thunk：整条函数只有一条跳到别处的无条件跳转 | `is_thunk` + `thunk_to`（去掉 Thumb 位） |

`example_mdk_project` 的 axf 上：175 个函数里 102 个以返回结束、17 个以尾调用结束、
3 个以间接跳转结束、3 个 thunk；45 个「非符号表边界」的函数里，控制流比「切到下一个入口」
一共少算 126 字节（`ptr_08003456` 从 262 收到 180，`__user_initial_stackheap` 从 36 收到 2）。

两条必须同时守住的纪律：

1. **不改老字段的含义**。`size_basis` 仍是 `symtab` / `next_entry`，形状结论另开
   `body_basis`——把老字段改含义，会让所有历史断言变成「碰巧还过」。
2. **推断不进签名**。头文件仍写 `void f(void)`，只在注释里写「推断 3 参/可能返回值」。
   按估计改原型，一旦猜错就是调用方传参错位的静默错误（比不给信息更坏）。

反编译器的**类型层**没有吸收，也不该在这里吸收：那是编译器优化的逆问题（内联、类型
擦除都不可逆）。但**表达式层与控制流层**是可逆的，批次84 已补上（见下第三十六节）。
要读原始语义，仍用 Ghidra/IDA 打开同一份 axf 对照更可靠。

---

## 三十三、跳转表没有「表有几项」这个数，项数还取决于守卫用的条件码

`tbb` / `tbh` 的编码里只有「表在哪」，**没有任何长度信息**；ARM 也没有类似 x86 的
边界。所以「这个 switch 有几个 case」只能靠前面那条守卫比较推。

第一版按 `cmp rN,#K` ⇒ `K+1` 项来做，在夹具的 `dispatch`（源码是 `switch (op)` 覆盖
`0..7` 共 8 个 case，默认分支 return -1）上恢复出 **9 项**，凭空多了一个 `case 8`
指向默认分支。根因是两步各加了一次一：`_bound_from_cmp` 先 `K+1` 当上界，
`_table_from_*` 又把这个上界当「项数」再 `+1`。

正确口径是看**守卫之后那条分支用什么条件码**：

| 守卫 | default 分支的条件 | 合法下标 | 项数 |
|---|---|---|---|
| `cmp rN,#8` | `bhs` / `bcs`（≥8 跳走） | 0..7 | **8（K 项）** |
| `cmp rN,#8` | `bhi`（>8 跳走） | 0..8 | **9（K+1 项）** |
| `cmp rN,#8` | 其它任何条件 | 说不清 | 未知：扫到越界为止，`confidence=weak` |

修法：`_bound_from_cmp` 返回 `(K, 项数或 None)`，`_table_from_*` 里 `limit = bound`
（不再 `+1`），并把依据写进每一条结果的 `length_basis`（「守卫条件 cmp #K ⇒ N 项」），
而不是只给一个数字。同一份 `dispatch` 现在稳定 8 项、0 个范围外目标。

**通用教训**：把「怎么算出来的」和「算出来是多少」一起输出。这里的错不是算术错，
是口径错；只输出数字的错误版本，事后无法从结果反推它错在哪。

## 三十四、capstone 的 `ldm` 没有 MEM 操作数，IT 块的 t/e 模式在助记符里

写伪 C 的提升层时踩到两处与「凭直觉写」完全相反的地方（capstone 5.0.7，ARM）：

| 现象 | 直觉写法 | 实际 |
|---|---|---|
| `ldm.w r0, {r1,r2}` | `op_str` 里第一个寄存器是目标基址，`{...}` 是数据 | 反过来的：`ins.operands` 是 `[REG r0, REG r1, REG r2]`，**首个是基址**，其余才是被写回的寄存器；而且**没有 MEM 类型的操作数**，写回（`!`）只能从 `op_str` 末尾那个叹号读 |
| `ite eq` / `itt ne` | 条件码在 `op_str`，模式在别处 | 条件码与 **t/e 模式全在助记符里**（`itt` / `ite` / `itte`），`op_str` 里只有寄存器与立即数 |

**影响**：把 `ldm` 的第一个操作数当数据寄存器，会写出「r0 = [r0]」这种既丢基址又丢其它
寄存器的伪代码，而且**看起来完全正常**。判据是拿一条真实的 `push {r4,lr}` / `ldm`
对照 `op_str` 手工演一遍，别只看输出像不像。

## 三十五、`.w` 后缀会让「写 flags」判断失效，整条进位链静默断掉

ARMv7-M 的 `s` 后缀表示「写 flags」，于是第一版用 `mnemonic.endswith("s")` 判断。
但 `subs.w`、`adds.w`、`movs.w` 这些带宽度后缀的写法**结尾是 `w` 不是 `s`**，
判断直接返回 False —— 后果不是「少一条标志位」，而是：

- 上一条 `subs` 没被记为「产生了进位」，`ctx["carry"]` 没有被更新；
- 下一条 `sbc` / `adc` 找不到进位来源，全部降级成 `/* 未支持 */`；
- 32 位除法这类「`sbcs` 一串 + `adc.w` 收尾」的代码整段不可读。

真镜像上这条链的修复效果是直接的：`_ll_udiv10` 从「一串未支持」变成完整进位链，全镜像
未支持从「多类大面积」降到 **4 处（`adcs` / `rrx` / `sbc.w`，3 个函数里）**。

正确做法是不看后缀，先剥出**基名**再查白名单：`_split_cond(mnemonic)` 拆掉 `.w` 与条件码，
得到 `sub` 后查 `_FLAGSET_MN`；白名单是必须的——`bls` 是分支（`b` + `ls`）不是 `bl+s`，
`bics`/`orns` 才是真写 flags 的。

还有一条更细的：**逻辑指令写 flags 时 C 位不可预测**（`and`/`orr`/`eor`/`mov`/`mul` 等）。
所以清进位链的规则不是「写 flags 就清」，而是「**基名在 `_C_UNKNOWN` 里才清**」——
否则 `lsls`（移位产生的 C 是良定义的）会被误清，`rrx` 立刻降级。

## 三十六、伪 C 里没有「类型」和「变量名」，也没有「原作者的写法」

寄存器级伪 C（批次84）能保真的是「表达式 + 控制流」；下面这些**结构上不可逆**，
别在上面建判据：

| 不可逆 | 表现 | 后果 |
|---|---|---|
| 类型 | 所有值都从 `uint32_t` 起步，指针就是一个整数 | 不能据此生成可编译的函数原型；改调用方就是静默错 |
| 变量名 / 作用域 | 只有 `r0..r12`、`sp`、`lr`、`loc_xxx` | 不能据此判断「这是同一个业务变量」 |
| 内联 | 内联进来的代码就是一串正常指令，`bl` 都不留 | 反内联无可操作判据，只能靠人看语义 |
| 结构体 | 只有「同基址 + 不同偏移」的聚类 | 成员名/嵌套/位域都是猜的 |

由此有两条纪律：

1. **判据不能写成「还原出的 C 和原 C 一致」**。能断言的是「把它编回去行为等价」，
   不是文本相同。同理，`n_unsupported=0` 也不代表「完整还原」——它只说明没有指令
   落进降级路径。
2. **降级要留痕**：`/* 未支持 */` 逐条写在源码里并计数；`flag_<cond>` 表示条件背后
   找不到比较；跳转表数据被当作数据剥掉时记下地址与条数。这些痕迹是给读的人判断
   「这一段能信多少」用的，不是噪音。

## 三十七、PE32 与 PE32+ 的数据目录不在同一个偏移（96 vs 112）

PE 的可选头里，`NumberOfRvaAndSizes` + 数据目录（导出表/导入表/重定位…）的位置
**随 magic 变**：

| 可选头 | `SizeOfOptionalHeader` | 数据目录偏移 |
|---|---|---|
| PE32（`0x10b`，32 位） | 224 | **96** |
| PE32+（`0x20b`，64 位） | 240 | **112** |

第一版写死 `opt+92` 找数据目录，PE32+ 的导出表就永远读不到——不是「没有导出」，
是**读到了别的字段**，`n_exports=0` 看起来像个正常结论。两种口径必须按 magic 分支，
且判「有没有导出表」要看 `NumberOfRvaAndSizes > 0` 再加表项非零，不能只信偏移里的值。

## 三十八、COFF 的字符串表起点是 `symptr + nsym*18`，不是「符号表之后」

很多「COFF 格式」教程按 `20 + nsec*40` 算符号表位置，那只是**没有可选头**时的常见情形。
真正的符号表位置由文件头 `PointerToSymbolTable` 给出，字符串表紧跟在
`symptr + NumberOfSymbols*18` 之后（18 字节一个 `IMAGE_SYMBOL`，不是 20）。

按「节表之后」算，短名符号恰好还能读对，**长名（`name[0]==0`，`name[4..8]` 是偏移）
就全错位**——读出来的是一段别的字节，看起来像名字但不是。另外：
- COFF **没有 magic**，只能结构自洽判（机器码已知 + `SizeOfOptionalHeader==0` +
  节数 1..96 + 符号表偏移在文件内）；
- 符号 `Value` 是**节内偏移**，不是 VA；`SectionNumber` 是 1 起算，0=未定义、
  负数=调试符号。

## 三十九、Mach-O 的「小端」说的是文件里那四个字节，`mach_header_64` 还多一个 `reserved`

两处都能一次写错而「解析看起来跑通了」：

1. **magic 的字节序**：小端 64 位文件的前四个字节是 `CF FA ED FE`，按小端读成整数是
   `0xFEEDFACF`。反过来写 `0xCFFAEDFE` 再 `struct.pack("<I")`，得到的是
   `FE ED FA CF`（大端文件）——文件能生成，读的时候 magic 对不上，于是全线错位。
   判据要拿**字节串**对，不要先转成「你以为的整数」。
2. **`mach_header_64` 是 8 个字段**：`magic cputype cpusubtype filetype ncmds sizeofcmds
   flags **reserved**`，共 32 字节。少写 `reserved` 会让第一个 load command 从错误
   偏移开始，`LC_SEGMENT_64`/`LC_SYMTAB`/`LC_MAIN` 全部读成垃圾值（`ncmds` 却还是对的，
   所以「找到了 N 个命令」这条自检不会报警）。

fat（`CA FE BA BE`）包里每个切片自带 `cputype/cpusubtype/offset/size/align`，
只取第一个切片时必须把这件事写进 notes——「只分析了其中一种架构」不能被读成
「这张图里只有一种架构」。

## 四十、指令指纹是「候选」，不是「等价」——地址归一化会洗掉一部分证据

函数匹配里最容易被误读的一条：把两条指令序列里的**代码区间内地址**都抹成 `<CODE>`
之后比对，命中率会明显变高，看起来像「找到了同一个函数」。这恰恰是它的限度所在：

- 抹掉地址是**必要的**（同一份库被链接到不同地址，不抹就一条也配不上）；
- 但抹掉之后，两个「调用了不同函数、但调用序列形状相同」的函数会撞成同一指纹；
- 所以 `state="candidate"` 只作线索：要当真必须再过 `bytes`（字节 SHA-256 + 区间有证据
  + 长度相等 + 两侧唯一 + 架构相同），或者看调用图/字符串这类旁证。

配套的两个反方向：外设地址（`0x40000000` 一带）、字符串、常量池偏移**不归一**——
否则两个真的不同的函数会被洗成同一个指纹。另外别把 `bx lr` 这种 2 字节桩的指纹当真：
它是「满街都是」的，所以候选要过 `min_insns`（默认 6）门槛。

## 四十一、符号长度与控制流终点差几个字节，就足以让字节匹配率莫名其妙地掉

同一份代码，用 `symtab` 的 size 切边界和用「走到终止指令」切边界，末端的字面量池
与对齐填充归谁不一定一致——差 2~4 个字节。于是 `bytes_sha256` 不同，`by_bytes` 归零，
报告看起来像「这份固件和上一版完全不同」，实际只是边界口径不同。

两条处置：
- 报告里每条都带 `size_trust`（`symtab` / `control_flow` / `guessed`）与两侧的 `size`，
  对不上时先看这两个数，不要先怀疑代码变了；
- 真正想判「改没改」时用**同一种口径的两侧**（都带符号对都带符号，都是裸固件对都裸），
  或者看 `insn_sha256` 得到候选后再人工确认。

`guessed`（切到「下一个入口」）这一档**不进字节配对**：那条边界本身就可能是错的，
拿它做「逐字节相同」的断言等于把猜测当证据。

## 四十二、重复指纹不能展开笛卡尔积——`bx lr` 桩会把配对全变成噪声

一侧有 3 个函数共用同一份字节（典型：多个 `bx lr` 桩、多个相同的 `__aeabi_*` 包装），
另一侧有 6 个。展开成 3×6 = 18 条配对能把「matched」数字做得很漂亮，但没有一条能追责。

正确做法是整组进 `unresolved`（带 `duplicate_bytes` / `duplicate_name` 与两侧的
`n_left`/`n_right`），只在报告里说明「这组指纹重复，需要更强证据」。
需要更进一步时用调用图、字符串引用或人工确认——**不靠把组合列出来**。
同理，`only_left` / `only_right` 只是「本次清单里没有精确对应」，
重命名、内联、strip、发现不全都能解释，**不证明源码有增删**。

## 四十三、向量表的 handler 区里能自己凑出「伪表」，所以扫描要带最小间距

在整颗 Flash dump 上扫 Cortex-M 向量表时，「SP 非 0 且 4 字节对齐、下一个字 bit0=1
且落在代码区」这两条太容易满足——一张真表的 handler 条目里，某些地址作为 `word0`
就是一个合法的 RAM 地址（`0x2000xxxx`），它后面那个字又常常是另一个 Thumb 地址。

结果是同一张表能被报成好几张，切分出来的「镜像」互相重叠。两条处置：

- 「已接受的表之后 `min_spacing`（默认 0x80）内不再接受新表」——表项间距远小于 0x80；
- 再加一条**内容协证**：随后的 6 个 handler 字里至少 75% 要「bit0=1 且落在代码区」。
  只有 SP+复位地址两个字的证据不足（空白区里的随机字节也能凑）。

另外别忘了一个反方向的坑：**没有给 RAM 窗口时，「SP 在 RAM 内」这条判据根本没法判**。
此时只能报 `plausible`，并在 `why` 里写「没有给 RAM 窗口：SP 只在『非 0 且对齐』这一层被判过」——
把判据退化这件事说出来，比给一个 `strong` 有用得多。

## 四十四、稀疏文本（HEX / S-record）铺平之后的 0x00 不是擦除态

Intel HEX 与 Motorola S-record 只记录「有数据的区间」。把它们铺成连续字节图再去做
熵/签名/擦除带分析时，**空隙被填成 0x00 或 0xFF**——那只是本工具为了让数组连续而做的
填充，跟 Flash 上的实际值没有任何关系。

后果：拿铺平后的字节图找擦除带，会在每一个「记录间隙」上找到一条假的擦除带，然后把
同一个镜像切碎。所以：

- HEX / S-record 输入**不做擦除带判定**（`erase_runs = []`），并把原因写进 `limitations`；
- 基址取自**记录自己**（HEX 的扩展线性地址 / S 记录的最小地址），不是调用方给的 `base`；
  `base` 只作为附加偏移。

## 四十五、把「解压长度」当成结果字典的长度——一次真实的静默错答案

求压缩流精确长度时写成：

```python
out = d.decompress(raw)          # out 是解压出来的 bytes
...
out = {"raw_bytes": len(out)}    # ⚠ 这一行之后，out 变成 dict 了
if isize == len(out):            # 这里量到的是 dict 的**键数**
```

`gzip` 的 ISIZE 校验因此恒假（`len(dict)` 总是 5），报告里每条 gzip 都被标成
「尾部声明与解压长度不符」——看起来像镜像坏了，其实只是量错了对象。修法是先把
`n_raw = len(out)` 记下来，再覆盖 `out`。

配套的判断：**流长度只能来自解到流尾**。没到 `eof`（被截断、或超过输出上限）时
不能报一个「看起来精确」的长度——那是最坏的一种输出：有数字、但没有证据。

## 四十六、把推导级的结论当成观察，就是把「看起来对」卖成事实

`recover_verify` 给出 `byte_identical=true` 之后，很容易顺手把所有相关结论都标成
「已验证」：布局一致、装载地址一致、向量表一致……但**它们不是同一件事**：

- `bytes.loadable` 是**观察**：真的把两份字节逐字节比过；
- `layout.regions` 是**推导**：由「同一份 bin 的两种读法」推出来，推导级就够；
- `vector.entry` 需要**再看一眼原镜像的前两个字**——字节一致只说明「工程里的向量表
  和镜像里的那段一样」，不说明「那段真的是一张向量表」。所以要用
  `image.check_vector_table` 判 SP 非 0/全 1、4 字节对齐、复位地址 bit0=1，
  并核对工程首区地址就是镜像首地址。

闭环台账（批次88）把这条写成硬规则：**`derived` 证据不能闭合要求 `observed` 的义务**。
一旦允许推导顶替观察，「我推出来的」和「我量到的」在报告里就再也分不开，而那些报告的
每一行看起来都一样权威。

## 四十七、把 `unknown` 当 `fail`（或当 `pass`）都会毁掉结论

「判不了」和「做不到」不是同一件事，也都不是失败：

- `unknown`：**判不了**——没传原镜像、没接硬件、没给 RAM/Flash 窗口；
- `unsupported`：**做不到**——机器码里没有 C 类型名/宏/局部变量名，优化时被擦掉了。

把 `unknown` 当 `fail`，所有诚实的结论都会变成噪音（每条都红），于是没人再看报告；
把 `unknown` 当 `pass`，猜测就被洗成事实。台账的处置是：两者**都不算通过、也不算失败**，
`ready` 只由 required 义务是否 `closed` 决定，未闭合的具名列出
（`summary.blocking_obligations`）并附 `required_next_evidence`——「缺什么」必须能行动。

## 四十八、`ready=false` 的理由必须具名，否则等于没说

只给一个 `ready: false` 的报告没有信息量：调用方无法区分「缺工具链」「没传原镜像」
「字节真的不一样」这三种完全不同的处境，也不知道下一步该做什么。所以台账里：

- 每条义务都留 `status` + `reason`（中文，说明证据强度与差距）；
- 缺证据时附 `required_next_evidence`（具体到「传 image=」「把 arm_bin 指到 Keil」）；
- `failed` 必须带**观察到的反证**（例如 `diff.diff_offsets` 的第一处偏移），
  不允许用推导级差异把人判死。

同一条纪律的另一面：`ready=true` 也要说清它**不**覆盖什么——不表示能跑、不表示是好固件、
不在清单里的能力（中断优先级、外设初始化顺序、时钟树）没有任何证据。

## 四十九、证据强度够，不等于来源能支撑这句主张

`closure_digest` 说「8 条义务里 5 条被 observed 闭合」，很容易被顺手读成「这份恢复是可靠的」，
然后拿去对外讲一句它其实没资格讲的话：**「我们在板上验证过它能跑」**。强度（`derived/observed`）
与来源（谁给出的这条证据）是两个轴，只有一个轴合格时的结论是错的：

- 字节一致（`bytes.loadable`）是 `observed`，但它的来源是**我们自己重链接的产物**；
  拿它去支撑 `live-observation`（板上跑过）就是偷换；
- 回放一份**已保存的** `verify.json` 能得到和实跑**完全相同的 digest**，
  于是「昨天跑过」和「今天跑过」在账本上长得一模一样——这件事本身不是缺陷（对账正需要它），
  但**不能因此宣称本次实跑过**；
- 反过来说，来源对也不代表强度够：`shipped-artifact` 能读到的只有交付字节，
  `layout.regions` 只是推导级，撑不起要求 observed 的主张。

因此在批次89 里，主张（`claim=`）与义务（`status`）严格分开：`claim_supported` 只在
「该主张覆盖的义务全闭合 + 证据来源在允许集合里 + 至少一条达到最低强度」时才为 true，
否则把不合格的那几条**具名**写进 `claim_blockers`（来源不合规的那行标 `claim_status=unknown`，
**不动它自己的 status**，digest 也不随之变）。判据里最贵的一句是「强度够不等于来源对」——
它把「看起来能证明」与「有资格这么说」拆开了。

## 五十、回放既有记录不等于本次实跑

`recover_ledger` 支持三种取证：真跑工具链、`verify_json=` 复评一份保存下来的 verify 输出、
`skip_build=true` 只盘点材料。三者都能出账本，**但语义不同**，混用会让记录悄悄变成谎话：

- 复评的 `source_mode=recorded-replay`，`claim_note` 必须写明「回放的是既有记录，不能顶替本次实跑」；
- 同理它不支撑 `live-observation` / `external` 两级主张（`controlled-replay` 不受限，
  本来就是我们重链接的产物），理由进 `claim_blockers`，而不是靠调用方猜；
- `skip_build=true` 的 `source_mode=no-build`，几乎没有义务能闭合——这时 `ready=true`
  是不可能的，如果出现了，说明有义务被错判成闭合，要先查那里；
- 同一份 verify 文件反复复评必须得到**同一个** `closure_digest`：这是它能当对账凭据的前提，
  也是「回放有意义」与「回放能冒充实跑」的分界线。

## 五十一、工具链只对一种架构成立时，闸门要放在入口

`recover_project_exact` 用 armasm + armlink 复刻并自证——这条命令链**只对 ARM 32 位成立**。
批次90 之前它不判架构：喂一份 x86_64 的 PE，它照样返回 `ok=true`，生成一份 `DCB` 字节表
（字节层面「对」），直到 `recover_verify` 跑到 armlink 才失败，而错误是
「链接失败（见 steps[-1] 的 stderr）」、`hint=null`——调用方只能从开发者级别的 stderr 里猜是
工具链找不到、参数不对，还是**目标根本不是 ARM**。RISC-V 的 MCU 固件（现在一点都不稀罕）
会走同一条死路。

三条处置：

- **闸门放在最早能判的地方**（`project_exact` / `project` 入口，`makedirs` 之前），
  拒的同时把「还能做什么」写出来（本仓库里能分析任意架构的工具是哪几个）；
- **老产物也要挡**：`verify_project` 读 manifest 里记的架构，非 ARM 直接拒，
  不再白跑一遍工具链；
- **「未判定」不等于「不是」**：裸 bin 没有头，判不出来时仍然放行，但把
  「这条链的目标对不对没有证据」写进 limitations——宁可少拒，不可把未知当已知。

同一条纪律的另一面：**能分析 ≠ 能出工程**。分析层（probe / symbols / disasm / diff / split）
吃十来个架构，复刻层只吃 ARM；把两层的能力混成一句话宣传，就是在给调用方埋坑。

## 五十二、裁视图要裁字段，不能裁结论；截断要喊出来

一份 14 KB 的固件，`recover_probe` 的完整剖析就是 45 KB JSON，其中 33 KB 是 60 个函数各自
十几个字段（`terminals` / `arg_basis` / `callers` / `stack_slots`…）。这不是 bug，但一次工具
调用就能把上下文吃掉一大块；1000 个函数的固件会到几百 KB。

裁剪时最容易犯的两个错：

- **裁掉了结论**：为了让 JSON 小而去掉 `functions.total` / `counts` / `verdict` / `gaps`，
  调用方就只剩「看到几个函数」——那不是紧凑，那是不完整。`compact_view` 只动**列表长度与
  字段宽度**，计数与结论逐字不差；
- **悄悄少了**：裁掉 40 条却不写 `omitted`，调用方会以为「就这么多」。凡是裁剪，被裁掉的
  条数必须写出来（函数 `omitted`、字符串 `omitted`、调用图 `view` 说明只留计数）。

同一个毛病的另一张脸是**静默截断**：深度扫描触到 `max_insns` 上限就停，函数表看起来「很少」
但没有任何提示。`max_insns` / `max_functions` 这类预算参数，触顶就必须进 `gaps`
（「只扫了一部分代码，要看全就调大」）——预算由调用方定，**工具不替调用方猜**，
更不能用「看着没报错」冒充「扫完了」。

## 五十三、推出来的窗口只能当下界，不能拿来判错

批次91 让 `recover_ledger` 不用再人工传 Flash/RAM 窗口：Flash 按 manifest 的 `chunks`
**覆盖范围**推、RAM 按 `manifest.windows.ram`（出件时由 ELF 的 RW 段算出）推。
省事的同时埋了一个陷阱——**这两个窗口不是器件手册上的容量，只是「我手上这些字节/节」的范围。**

拿它去判对错就会毁掉好固件：一份只 dump 了前 16 KB 的固件，复位地址 `0x08008001`
落在外面，`check_vector_table` 会给出 `reset_in_flash=false` → `invalid` → 台账判
「向量表与复位地址不是取自原镜像」**failed**。可那份固件很可能完全正常，只是剩下的
Flash 没被读出来。**「落在我没 dump 到的那一段」和「向量表坏了」是两件事。**

处置（三条，缺一条就会重新变成假答案）：

- **标来源**：每个窗口带 `basis`，推出来的写清依据（chunks 覆盖 / manifest.windows.ram /
  现读 ELF），台账输出 `windows.derived` 点名哪几个是推的；
- **降级不判错**：推出来的窗口只负责把判据从 `unverified` **抬到** `plausible`（说明「没落空」），
  落空时退回 `unverified` 并写明「不判 invalid」；显式给的窗口才保留判 `invalid` 的权力；
- **硬错误不豁免**：`sp_nonzero` / `sp_4byte_aligned` / `reset_thumb_bit` 这几条与窗口无关，
  推出来的窗口一律不能把它们洗成通过（SP=0、复位地址 bit0=0 照样 `invalid`）。

反例测试是必须的：同样一份字节，**推窗口 → 记未核**、**显式给窄窗口 → 判 failed**，
两条同时成立才算没放水。另一个同源细节：裸 bin 的 `base` 没给时取 manifest 的首块地址——
「这份字节放在哪」manifest 里已经记了，再让调用方抄一遍就是给错答案留门。

## 五十四、推断层的每个结论都要带依据，冲突就写 unknown

伪 C 从「寄存器级」往「像人写的代码」走一步，就多一类**看起来像事实的猜测**：
变量叫 `i`、类型写 `int32_t`、字段写 `f_0x8`。这三样一旦不带依据，读的人会当成
还原结果去用，而它们全都可能是错的。

处置（三条）：

- **名字带 basis**：`a0..a3`（入口参数位）/ `i`,`j`（回边自增 + `cmp`）/ `p0`,`p1`
  （同基址 ≥2 个非零偏移）/ `v<N>`（兜底），每条改名在 `renamed[]` 里写清是哪一条
  判据；`a0..a3` 无条件映射（哪怕没用到），否则签名会出现 `a0, a1, r2, r3` 这种混排。
- **符号性只认单向证据，双向证据判 unknown**：`ldrsb/ldrsh/asr/有符号分支` ⇒ signed，
  `ldrb/ldrh/lsr/无符号分支` ⇒ unsigned；两向都在就 `signed=null` + `note`。
  猜一个默认值比留空更糟——留空至少读者知道要去核。
- **改名不能动注释**：`/* ... */` 里的 `rN` 是汇编注记，用来和反汇编对照；
  把注释里的 `bx r3` 改成 `bx a3` 会让读者拿注释去 grep 指令时对不上。改名按注释
  切段，只改代码段。

同源的一条：**内联只能标边界，不能反演**。「这段指令和另一个函数逐条指纹相同、
且窗口里有 `bl`」能说明「这里要么被内联了、要么与它共享尾段」，两种情况都**没有
调用点**可还原，所以措辞必须两种都承认；把它写成 `call X()` 就是把猜测当事实。

## 五十五、多指令集不是「多写几套提升器」，翻译层的保真度要自己举证

批次93 让伪 C 从只有 Cortex-M 扩到 RISC-V / MIPS / ARM 模式。做法是**翻译层**
（`lift_isa.py`）：把别的指令集按等价语义翻成「ARM 形状的统一 IR」，再喂给同一个
提升器。好处是一套语义（类型/命名/结构体/内联/跨函数）对所有家族生效，不会四条
分支各自腐烂；代价是**「翻译」这一步成了新的证据义务**——翻错了，上层的类型与
结构体推断会把错的东西讲得头头是道。四条硬约定：

- **翻不动要留痕、要计数**：翻不动的形态出 `/* 未支持: <mn> <op_str> */` 并计入
  `n_unsupported`，绝不静默丢。静默丢的后果比「留个显眼的注释」严重得多——
  读者会以为这段代码本来就没有这几条指令。同理，写零寄存器（`x0`/`$zero`）出的
  是 `/* 结果丢弃 ... */` 并计数，**不能**渲染成 `zero = 0x1;`：那会把恒零寄存器
  伪装成一个可追踪的变量。
- **延迟槽是语义，不是排版**：MIPS 的分支延迟槽里那条指令**先于**分支生效。只在
  输出里把顺序换一下就够了吗？不够——交换必须发生在**分组粒度**（延迟槽整组提到
  分支组之前），且计数只算真搬动了指令的情况；`jr $ra` 后面跟 `nop` 时把 nop 丢掉
  但不能算「搬了一次」。这类「换算子了还是没换」的地方，测试要断言顺序（延迟槽行
  必须在 `cmp` 之前），只断言「出现了 a0+1」是抓不住的。
- **家族闸门是两件事，不能一起放开**：`decomp` 的提升闸门（伪 C，本批放开
  riscv/mips）与 `recover.py` 的 armasm/armlink 复刻闸门（出可编译工程，仍只对
  ARM）是两条独立的路。前者放开不代表后者成立——复刻链里的伪指令、ELF 布局、
  启动代码全是 ARM 的细节。
- **做不到的家族要写清理由**，不要给「看着像」的结果：`arm64` 卡在 32 位类型层，
  `x86` 卡在子寄存器与隐式栈，`ppc` 卡在 CR 字段，`m68k` 卡在两套寄存器组加自增
  寻址，`sparc` 卡在寄存器窗口，`mos65xx` 是 8 位累加器机。理由写进
  `NOT_LIFTABLE`，拒绝时连同「可用家族」一起返回。

还有一条不是坑但容易忘的：**RISC-V 的 RVC（压缩指令）必须开**。不开
`CS_MODE_RISCVC` 时 2 字节指令会被当坏字节跳过，表象是「这个函数只有一条指令、
还有一堆坏字节」——看着像正常的降级，其实是解码器配置漏了一项。

## 五十六、读字节必须有出处；跨段读不许静默拼接

批次94 的现场：`recover_disasm` 请求 `0x08052118`，实际读到偏 `+0x1000` 的字节，
标签还写原地址，`status` 照样 `ok`。指令流、分支目标、字面量池全错位——**最坏的一类
错答案：结果看起来完全正常**。这里记三条可复用的做法：

- **`data[off:off+n]` 这种裸切片在「地址 → 文件偏移」的映射上是错的**。一段地址只能
  映射到一个段（`[start, end)`），越过 `end` 的字节在文件里紧邻着**别的节**，它们不是
  这些地址上的内容。正确做法是「最多读到段尾」，并把 `clipped/got/reason` 透给调用方；
  调用方要能把「只有 4 字节」和「一共就 4 字节」分开——这两件事在结果里长得一模一样。
- **回填校验是这类缺陷唯一的兜底**：解码用的字节，必须能按它自己的地址从源里重新读到、
  且逐字节相同。它不依赖「我算偏移的代码是对的」这个前提，所以能抓住整体平移、跨段
  拼接、以及任何「声称读了 A、其实是 B」的实现。校验不过就 `ok=false`，别做「差不多」
  的降级——反汇编错位的产物比报错危险得多（伪 C 会引用镜像里根本不存在的字面量）。
- **`base` 必须能自证有没有生效**：ELF / Intel HEX / S-record 自带地址，`base` 对它们
  不叠加；裸 bin 才有基地址。以前这类输入收到 `base` 就**静默忽略**，调用方以为平移过
  了，于是自己再算一次偏移——这才是「base 被重复应用」的来源。现在输出里明写
  `address_map{base_applied, note, spans}`，三种容器三种口径各写一句，别让人猜。

顺带一条口径：`source.file_offset` 报的是**文件偏移**不是地址，测试要用手算的
`offset_of(addr)` 去对，不要拿 `addr - base` 去对（那正好把 bug 当成正确答案）。

## 五十七、base 是参数不是事实：到货值 / 实际用值 / 容器自带值必须分开报

批次95 的现场：用户传 `base=0x08005000`，报错文本里写的是 `base=0x08004000`，于是判
「工具自动识别了 base、忽略了我传的值」。实际全仓只有 `self.base = int(base or 0)`
一处赋值，没有任何推断逻辑——那个数字就是**到达工具的参数**（或 HEX/ELF 自带的地址）。

三条可复用做法：

- **同一个名字承载两个值，读数的人一定会混**。`base` 至少有三种含义：调用方传的、
  实际用来寻址的、容器里写的。把它们拆成 `base_received_hex` / `base_hex` /
  `base_conflict.container_hex` 三个字段，而不是一句 note 里塞一个数字。
- **「容器自带地址 ≠ 传入 base」必须显式报冲突，不能只在 note 里说「被忽略」**。
  用户看到的「忽略」是「参数没生效」；真实含义是「文件里写的是另一个地址」。
  带上 `delta` 与一句人话，才分得清这两件事。
- **能自检的就自检，但只提示不改正**。裸 BIN + ARM 上读前 8 字节做 Cortex-M 向量表
  合法性判断（SP 对齐/范围、复位地址 bit0 与是否落在镜像内），不通过就 `hint`。
  工具替用户改 base 是另一种「自作主张的错答案」；报出来让人核对才是可证据化的做法。

顺带：调试这类「偏一页」现场时，别用 `file_offset` 反推 base——在 HEX/ELF 上
`addr - base` 本来就不等于文件偏移，反推出来的 base 一定是错的。

## 五十八、显示十六进制要补零；映射表要拿生成物核对，不要凭下拉框猜

三个都在同一轮报出来的小问题，根因同类：**给人看的数字没按人期望的形态出现**。

- **地址一律 `0x%08X`**：`end(0x8052018)` 少一位零，读者要自己数位才能判断是哪个地址。
  地址是定宽概念，宽度不写死就会在 `0x8000000` 与 `0x8052018` 之间跳。文件偏移/字节数
  才可以用 `0x%X`（它们本来就不定宽），但一个输出里混两种宽度时要说明哪个是哪种。
- **文档说「可省略」的参数，就必须有可用的省略路径**：`base` 写着可省略，但裸 BIN 省略后
  直接报「地址不在映射范围」，等于文档在骗人。补推断可以，但必须**标注来源**
  （`base_source="inferred"` + 证据），且显式传值永远优先、不像向量表时不许猜。
- **枚举 → 命令行选项的映射必须用生成物核对**：`Optim` 到底是 0-based 还是 1-based，
  读源码/猜下拉框都不算证据。打开 `CreateBatchFile` 让 uVision 自己生成 `.bat` 与
  `.__i`，里面写着真实命令行；再逐档构建、比**指令文本**哈希（不是对象整文件 SHA，
  后者含 File Name/group 段哈希）。本轮实测：`<Optim>` 1..4 → `-O0..-O3`，
  `-Otime` 来自 `<Cads><oTime>` 而非 `<OptFeed>`。
- **越界值要报错，不要回落默认**：映射表外（0/5/非数字）静默给空串或猜一个，会让
  「读到的配置」变成「工具以为的配置」。给 `optimization_error` 并留空，调用方才知道要复核。

---

## 五十九、工程文件被「重存一次」就可能打不开：编码 / BOM / 行尾是内容的一部分

`.uvprojx` / `.uvoptx` 是 XML，于是很容易被当成「普通文本」处理：读出来、改一行、写回去。
可真机上不止一次出现「AI 改完工程，uVision 打开就报错/分组丢失」。这类损坏的共同点是
**四个都在字节层面成立、在编辑器里完全看不出来**：

- **BOM 丢失**：用 `utf-8-sig` 读（BOM 被吃掉）、用 `utf-8` 写（不补回来）。文件短了 3 字节，
  编辑器里一个字都不差。
- **行尾被换**：text 模式不带 `newline=""` 时，Windows 上 Python 会把 `\n` 翻成 `\r\n`；
  往本来就是 CRLF 的文件里再插 `\r\n` 就成 `\r\r\n`。反过来把 CRLF 文件整体写成 LF 更常见。
- **同一文件混进两种行尾**：改的时候只插了几行 `\n` 拼的新内容，原文件是 CRLF，于是
  「一半 CRLF 一半 LF」。uVision 对此容错很差。
- **非 ASCII 字符被静默替换**：解码走 `latin-1` 兜底或 `errors="replace"`，写回时
  `errors="replace"` 把编不出的字符写成 `?`。中文路径/中文 target 名当场变成 `???`。

四条修法（本仓库落实在 `mdkdebug/projectfile.py`，uvprojx/uvoptx/cmdscript 三个写点全走它）：

1. **写前做往返校验**：`old_text.encode(检测到的编码) == 磁盘原始字节`。不成立就说明
   「你读到的文本」已经不等于「磁盘上的字节」（典型是走过 `replace`/`latin-1`），**拒绝写**。
2. **用原编码严格编码新内容**：`encode` 抛 `UnicodeEncodeError` 就报 `encode-failed` 并指出
   是哪个字符附近——不再用 `errors="replace"` 兜底。
3. **只归一化「本次改动区间」的行尾**：按最长公共前后缀切出插入段，把这段里的换行按原文件风格
   补齐；文件其余部分一个字节都不动（工程里本来就存在两种行尾时，全文件统一是破坏）。
4. **写后回读核对**：读回字节必须与写入字节**逐字节相同**（`verify="byte-identical"`），
   再解析一次 XML。写入「没报错」不等于「文件正确」。

另外两条口径：

- **XML 校验要按「实际编码」解析，不能按 XML 声明解析**。中文工程很常见的真实形态是
  「声明写着 `encoding="UTF-8"`，路径里的中文其实是 GBK 字节」——严格按声明解会解不开，
  可 uVision 自己毫不在意。把严格解析当写入闸门，会把正常工程判死。
- **同一工程里 `.uvprojx` 是 LF、`.uvoptx` 是 CRLF 是正常的**（实测：19340 字节全 LF /
  16446 字节全 CRLF）。任何「统一行尾」的动作都是无授权修改。

判断「这次改成功没有」的一句话：`project_file_check` 里 `encoding`/`bom`/`newline` 与改前
一致、`xml_ok=true`、`sha256` 已变——三者同时成立才算改成功。

---

## 六十、把行尾的「标签」当成分隔符写进文件：XML 合法、体检也查不出来

批次97 引入的「按原文件风格补齐新增行行尾」有一个致命写法：`detect()` 把行尾**标签**
（`"CRLF"` / `"LF"`）和真正的**字符序列**（`"\r\n"` / `"\n"`）混成了一个字段，
写回时 `want = meta["newline"]` 拿到的是标签，于是每插入一个换行就往工程里塞进两个
可见字符：

```xml
</Group>LF        <Group>LF        <GroupName>Core</GroupName>LF        <Files>LF
```

三个反直觉的地方，值得记牢：

1. **XML 仍然合法**。这些 `LF` 只是文字节点里多出来的字符，`ET.fromstring` 照过，
   `xml_ok=true`、写入闸门全绿、`verify=byte-identical` 也成立——五道闸门一个都没拦住。
2. **测试也绿**。当时的断言是「CRLF 文件写完后裸 LF 数为 0、BOM 还在、`newline_fixed>=4`」，
   字面量 `LF` 同样满足这三条。**「没有裸 LF」不等于「换行是对的」**。
3. **uVision 里表现为「内容挤在一行/分组看着乱」**，不是报错，很容易被当成 UI 问题去查。

正确做法（批次99）：

- **标签与序列分开两个字段**：`newline` 给人看（`"CRLF"`/`"LF"`），`newline_seq` 给代码用
  （`"\r\n"`/`"\n"`）；
- **在归一化函数入口硬校验**：只接受 `"\n"` / `"\r\n"`，来别的当场 `ValueError`；
- **断言要落在结构上**：不只是「没有裸 LF」，而是「`<File>`、`<FileName>` 各自独占一行」；
- **给已损坏的文件留修复路径**：签名是 `>LF` / `>CRLF` 紧跟空白再跟 `<`，
  `project_file_repair` 只替换这些位置（`<FilePath>../Core/LF/main.c` 这种文件名不会被误伤），
  默认 `dry_run` 只报数，写前备份并走五道闸门。

## 六十一、带 BOM 的 .uvprojx：uVision 只回 exit 15，而且退出码表本身写错了

真机事故（2026-10）：一份 `.uvprojx` 被写成 **UTF-8 with BOM**。uVision 打不开，
命令行 `UV4 -b` 只回 `exit 15`，日志只有一句 `error reading the project file`。
文件本身完全合法：XML 能解析、编码自洽、往返校验通过、五道写入闸门全绿。

三个反直觉点：

- **BOM 不是「无害差异」**：对 uVision 的工程文件它就是致命错误，而我们的体检当时把
  `bom: utf-8` 报成 `level=ok`——「XML 能解析」被当成了「健康」。
- **退出码 15 的含义被记错了**：官方文档是「读取工程文件（导入 XML）时出错」，
  旧表写成「UV4 被占用」，于是 next_actions 让人去 `close_uvision`——方向完全错，
  而且找不到原因时只能靠二分（换文件、去 BOM、换 target）一个个试。
- **写死的换行与缩进是同一类病**：`add_files` 用 `"\n"` 拼模板、写死 8/10 空格，
  在一个 12/14 空格缩进的工程里既错位、又要靠写入器事后补行尾；补丁漏一层就留下
  字面量 `LF`。行尾与缩进都该**从文件里量**，而不是从代码里假设。

正确做法：

- 体检把 BOM 判 `error`，并在提示里直接给出「`exit 15` / uVision 打不开」的因果；
- 写入口写回时顺手去掉 UTF-8 BOM（`bom_stripped`），UTF-16 拒绝并说明要转码；
- 退出码表按官方文档对齐，`exit 15` → `project-read-failed` / `project-unreadable`，
  `next_actions` 指向 `project_file_check` → `project_file_repair`；
- 新增行**逐行拼装**：行尾取 `newline_seq`、缩进取文件里第一个同类标签的缩进；
- 修复工具做成「一类缺陷一个开关、默认 dry_run」：BOM 与字面量换行可分别开关，
  一次调用能把两类一起修完并各自报数。

## 六十二、宿主 PYTHONPATH 让 python 死在 site 初始化，程序自己救不了

真机现象（2026-10）：MCP 宿主把自己的 `PYTHONPATH` 传给子进程后，`python run_server.py` 直接退出，
stderr 是：

```
Fatal Python error: init_import_site: Failed to import the site module
  ... __editable___xxx_finder.py ... pathlib ... fnmatch ... import re
  File "<毒化目录>/re.py", line 1: ImportError: SRE module mismatch
```

四个反直觉点：

- **崩在 `site` 初始化**，连 `run_server.py` 的第一行都没执行——所以「在程序里 try/except」
  或「在 bootstrap 里清理环境」**全都来不及**。唯一的解是**进程外**先清变量：
  `run_server.cmd` / `run_server.sh` 里 `set "PYTHONPATH="` 再 `python -E -s`。
- **触发者是 `.pth` 里的 editable finder**：`addpackage` 会 `import` 那些 finder，
  于是 `pathlib → fnmatch → re`——这就是「明明没 import re 却崩在 re」的来历。
- **不能用 `-I`**：CPython 3.11 起 `-I` 隐含 `-P`，会把**脚本所在目录**从 `sys.path` 去掉，
  源码树 `python run_server.py` 反而 `ModuleNotFoundError: mdkdebug`。用 `-E -s`。
- **`-E` 会连带忽略 `PYTHONIOENCODING`/`PYTHONUTF8`**：Windows 回落到 cp936，
  MCP 的 UTF-8 JSON 里中文就变问号。所以清环境要**白名单**（只剥影响 import 的
  `PYTHONPATH`/`PYTHONHOME`/… ，保留 IO 类），并且 stdio 显式 `reconfigure(encoding="utf-8")`。
- Windows 上 `os.execve` 会把 argv 用空格简单拼接，解释器路径带空格（`...\WPS 灵犀\python-env\...`）
  就被重新拆开，报 `can't open file ...\灵犀\python-env\python.exe`。改用 `subprocess.call(cmd, env=...)`
  + `SystemExit(rc)`（stdio 管道继承，MCP 不受影响）。

## 六十三、证据产物长得像源码，就会被编进工程

真机现象：`recover_project` 出的 `src/pseudo_c.c` 被顺手挂进工程，编译居然过了一部分，
于是整个工程变成「一半真源码、一半寄存器级提升」，后续谁也分不清哪行是证据（用户原话：变成 `Ported/`）。

要点：

- **注释拦不住**：长得像源码就是会被人和 AI 当源码用。要**编译期闸门**——
  文件里 `#ifndef MDKDEBUG_ALLOW_EVIDENCE_ONLY / #error ...`，不显式定义就编不过，
  「悄悄编进去」这件事物理失败。
- **元数据也要有**：`report.json` / `manifest.json` 顶层 `evidence_only: true` + 逐文件同名标志，
  下游（脚本 / AI）不用读注释就能判。
- **落盘位置要拦**：目标目录名属于 `App`/`Core`/`Src`/`Drivers`… 或位于某个 Keil 工程内 →
  直接拒绝并给下一步。但**判据只看目标目录自身名字 + 有限的祖先层级，且共享根（`%TEMP%`、`~`）
  不当工程边界**——自测时 `%TEMP%` 里躺着一个别人的 `mix.uvprojx`，按祖先判会把整块临时目录
  全判成禁区（假阳性比漏判更难查）。
