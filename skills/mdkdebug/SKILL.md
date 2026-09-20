---
name: mdkdebug
description: 用 mdkdebug MCP 驱动 Keil uVision 做在线调试——读变量/内存、断点与运行控制、编译烧录、串口日志、SVD 寄存器解码、工程文件受控编辑。当用户提到 Keil、MDK、uVision、UVSOCK、单步/断点/看变量、烧录固件、Cortex-M 在线调试时使用。
---

# mdkdebug —— Keil 在线调试的组合拳

mdkdebug 是一个把 Keil uVision 变成「可被 AI 调用」的 MCP 服务，共 189 个工具。
本技能告诉你**先调什么、按什么顺序调、遇到问题找谁**，避免在近百个工具里瞎试。

## 一、动手前的四条纪律

1. **冷启动先对齐环境**，不要凭印象直接下命令：
   - `capabilities` —— 有哪些通道可用（UVSOCK / UV4 命令行 / SVD / 串口 / 构建），当前工程与符号状态；
   - `list_tools(keyword=...)` —— 复杂工具的参数名不统一（`query/expr/addr/n_bytes`），
     这里有必填参数 + `example_args`，照抄即可；
   - `mdk_guide` —— 典型工作流与常见坑的入口。
2. **不可逆操作先确认目标**：`flash_download` / `build_and_flash` / `write_mem` /
   `close_uvision` / `restart_keil` 这类工具的返回体会带 `risk` 字段；动手前核对
   工程路径、符号文件、目标器件是否就是用户要的那一份。
3. **读到可疑数据不要急着下结论**：整帧 0、`UsageFault` 置位、读值与预期不符时，
   先看返回体里的 `note` / `next_actions` / `cache_info`，再复读一次或复位后对比。
4. **Keil 只开一个窗口，且「先改文件、后开 Keil」**——顺序反了会自己把通道堵死：
   - 正确顺序：`改源码/改工程 → launch_uvision → 调试 → close_uvision`。**先开 Keil 再改文件**
     会让 Keil 弹「文件已被外部修改」的**模态框**，模态框会把 UVSOCK 通道一起堵住
     （后续命令全超时，表现成「调试通道假死」）。
   - `launch_uvision` 默认 `single=true`：已经开着**别的工程**的窗口时**直接拒绝**
     （`error_code=keil-multiple-instances`，返回既有实例与下一步），不代替你关窗口；
     已有**同工程**窗口则强制复用（`reuse_forced=true`）。确实要同时开多个窗口才传 `single=false`。
   - `uvprojx_edit` 在 Keil 开着同一工程时同样会被拦下（`project-open-in-keil`）：先
     `close_uvision` 再改，或显式 `force=true`（不推荐，Keil 里那份仍是旧内容）。
   - 收窗口用 `close_uvision(keep="oldest")`：**持 UVSOCK 4823 的是最早那个实例**，
     别按「留最新」关。

## 二、五条主线工作流

### 1. 编译 → 烧录 → 进调试 → 看现象（最常用）

```
build_project / rebuild_project        # 先看编译是否过，失败用 parse_build_errors
  → (失败) explain_build_error         # 按错误码/诊断文本给原因与改法
flash_download / build_and_flash       # 烧录（会自动处理调试会话与串口占用）
enter_debug → run_to_line / set_breakpoint → run → wait_breakpoint
read_variable / watch / read_struct / read_registers
```

要点：
- 断点优先用**符号名**（`set_breakpoint(expr="main")`），裸地址会走 Thumb 位归一与
  地址合法性检查，失败时返回 `error 57` 的专属排查提示；
- `run_timeout` 的超时看 `pc_confidence`：PC 读数不收敛时它会给低置信，别当结论用；
- 停机过久怕被看门狗复位：`stop` / `enter_debug` 已自动冻结 IWDG/WWDG，失败会在
  `warning` 里说清。
- 三个烧录类工具的返回值里带 **`symbol_rebind`**（烧录＝符号漂移的源头，服务端顺手对齐）：
  `rebound` ＝ 符号已自动钉到刚烧的 `.axf`；`kept-explicit` ＝ 你此前 `set_symbol_file`
  显式选过，服务端**没覆盖**（要继续调新固件就按 `next_actions` 切，做 App 重定位/双工程
  对比调试就保持）；`already-current` / `skipped` 会如实说明为什么没动。

### 2. 只读排查（不动目标）

```
keil_health → get_status → diagnose         # 通道通不通、现在什么状态、一键聚合体检
snapshot → 改配置 → snapshot_diff           # 内存/寄存器快照对比
query_memory_map / read_peripheral / svd_decode   # 地址属于哪块、外设寄存器什么值
fault_report / wait_fault                   # 异常与硬件错误现场
watch_reset                                 # 反复复位/启动即死：按间隔读 DHCSR.S_RESET_ST（可传 flags_addr 交叉验证）
coverage_start → coverage_read → coverage_stop   # 跑到哪些函数/行：DWT PC 采样，不停目标
trace_etm_probe                             # 先问「这块板能不能抓指令 trace」：只探测不抓取，抓不到直说
trace_eventrec                              # 读 MDK 原生 Event Recorder 缓冲（纯 SWD 可用；要目标插桩，没插桩会说清）
view_render(data_file=...)                  # 把上面任意采集结果渲染成一张能缩放/回放的单文件网页：别手写 HTML
```

**多核目标先问是哪个核**：`core_info`（我连的这个核是哪一款内核）/ `core_list` + `core_select`（OpenOCD 链路真列真切；Keil 链路如实报不支持——一条 UVSOCK 会话就绑当前调试的那个核，双核要分别在两个 target/工程里连）。两个核的 SCS 地址完全一样，**读到的现场属于谁只由调试器当前挂的 AP/target 决定**。

### 3. 串口日志（宿主机侧，不经 Keil）

```
serial_list_ports → serial_monitor_start(port=..., baud=...)   # 常驻采集，落环形缓冲
serial_read(since=<上次的 next_seq>, max_items=200)            # 增量读，不重复刷屏
serial_expect(pattern="msh />", send="help", eol="auto")        # 发命令 + 等回显
serial_write(text="...", eol="crlf")                            # 裸写
serial_monitor_stop                                             # 收工释放 COM 口
```

要点：`eol` 是关键参数（`crlf`/`cr`/`lf`/`auto`），照抄示例免得设备不回话；
进调试/烧录/重启 Keil 会自动释放串口占用，已收日志仍可继续 `serial_read`。

### 4. Modbus（规范 RTU/ASCII + 非规范裸帧）

串口日志监听（`serial_*`）是**按行**切分的，接不了二进制帧协议——调 Modbus 走这一条：

```
modbus_scan(slaves="1-16", port="COM9", baud=9600, serial_format="8E1")  # 先确认从站号/波特率
modbus_read(slave=1, func=3, addr=0, count=10)      # 首次给 port，之后同会话可省略
modbus_write(slave=1, func=6, addr=0x10, value="0x1234", verify=True)
modbus_raw(req="01 03 00 00 00 01", auto_crc=True) # 私有协议裸帧
modbus_sniff(duration_ms=3000)                      # 旁听（不发字节）
modbus_session(action="close")                     # 用完还口
```

要点：
- **失败分类别混着猜**：一个字节都没收到 → `modbus-timeout-no-response`（接线 / 波特率 / 从站号）；
  收到了但 CRC 不过 → `modbus-bad-crc`（串口参数 / 串扰）；从站回了异常帧 → `modbus-exception`
  （**它在线，只是拒绝了参数**，按异常码改地址/数量/取值，别当通信故障查）。
- 拿不准帧结构先用 `modbus_decode` **离线**解一遍（不占端口、不发字节），再去动总线。
  它会**自动判方向**（先按应答解、不符再按请求解）：旁听抓到的帧多半是主站请求，
  结果里的 `direction=response/request` 告诉你是哪边发的；`05`/`06`/`08`/`16` 这类
  请求与应答**同形**的功能码如实标 `ambiguous`，不硬指一个方向。
- Modbus 会话会**独占** COM 口（空闲 900s 自动释放）；要接着看日志或开串口助手，先
  `modbus_session(action="close")`，否则会 `WinError=5`。

### 5. UVSOCK 不可用时的降级通道（命令行批处理）

UVSOCK 被模态框、端口冲突或 Keil 未启动挡住时，用 UV4 的 `-d` 批处理：

```
batch_debug_script(init_file=...)   # 每轮 15~25s；命令报错不改退出码，需读 trace
```

注意三条硬限制（工具会做静态告警）：命令报错不改退出码、`DISPLAY`/`SAVE` 与
`Go main` 会挂死。可重复的冒烟回归适合它，交互式调试仍应走 UVSOCK。

## 三、接续上一次的上下文

MCP 工具无状态，会话一断，工程/符号/断点清单就没了。开工与收工各一次：

```
session_state(action="show")                        # 当前上下文 vs 磁盘态差异
session_state(action="save")                        # 收工落盘（原子写，旧文件备份 .bak）
session_state(action="load", apply=true)            # 开工接续：只恢复主机侧可逆项（符号文件）
```

`load` 默认**只读不应用**；断点/内存/运行态等目标侧状态永不自动重放——
需要时按 `context` 里的 `expr` 自己重新下命令。

## 四、省上下文的三个旋钮（高输出工具通用）

`list_tools`、`snapshot`、`read_mem_multi`、`batch`、`parse_map` 等一批高输出工具的返回体
可能很大，它们都接受：

- `max_lines=N` —— 列表最多返回 N 条；
- `compact=true` —— 去空值字段、公共字段提升、说明性长文本截断到 200 字符；
- `full=true` —— 强制全量（覆盖上面两项与环境变量默认）。

**裁剪绝不静默**：只要丢过东西，返回体里必有 `output.truncated/dropped/trimmed/hint`，
还会提醒你 `count/total` 等计数字段仍是全量数字。要下结论时用 `full=true` 再看一遍。
也可以用环境变量 `MDKDEBUG_COMPACT=1`、`MDKDEBUG_MAX_LINES=200` 设全局默认。

## 五、参数与工具面的约定

### trace / 观测类工具的 `link` 参数

RTT、变量 scope、halt 采样、DWT 计数、PC 采样这些**观测**工具在 Keil 与 OpenOCD 两条链路上通用，都接受 `link=auto|keil|ocd`（默认 `auto`）：

- `auto`：哪条链路有活会话用哪条（两条都有时优先 Keil）；
- Keil 侧先 `enter_debug`，非 MDK 侧先 `ocd_start`；
- **显式指定而那条不可用时不换另一条顶上**，直接报错并给出两条链路各自的原因与起法；
- 读回来的数据带 `read_confidence`/`while_running`/`degenerate`：**读到的 0 不等于数据是 0**，可疑时先看这些字段再下结论。

只有 SWO（`trace_swo_*`）本身依赖 OpenOCD（TPIU 配置与落盘在那里）；Keil 用户做printf trace 用 `itm_trace`（读 Keil 的 Trace 缓冲，已带 ITM 结构化解码）。

### 运行态读写内存：`running=live|halt`

`read_mem` / `write_mem` 的 `running` 默认 `live`——**不要求目标已停**（Keil 链路真机实测：全速跑时读 SRAM / 外设 / 256 B 大块均成功，连读 `SysTick->VAL` 能拿到真实的递减值）。

- `live`：直接读 / 写，结果附 `while_running`。运行态读数会自动复读比对，两次不一致时给 `read_confidence=medium` + `read_unstable`，并**同时列出两种解释**（地址本来就在被 CPU 改写 / 读的中途被运行中的目标打断），不替调用者下结论。
- `halt`：**停-读-走**（或停-写-校验-走）快照——自动 `stop` → 操作 → `run`，返回 `sampling` / `was_running` / `paused_ms` / `resumed` / `halt_note`；**会打断目标、改变现场，属有副作用操作**，只在确实需要「某一瞬间的一致快照」时显式使用。

- **参数别名**：`query`/`name`/`expression`、`addr`/`address`、`timeout_ms`/`timeout_s`
  这类直觉写法都能落地；但**未列出的参数名会被拒绝**（不会静默用默认值），报错里会列出可用参数。
- **工具面默认精简**：默认只暴露 42 个（`core` 36 个 + 6 个元工具），其余 147 个按需装载——
  `toolset(action="load", toolsets="mem,trace")` 装回来、`toolset(action="status")` 看现状；
  启动时也可用 `MDKDEBUG_TOOLSETS=serial` 指定（参数优先），`=all` 全开。可用组名见 `capabilities`；
  `tools_groups()` 列组/档总览、`tools_load(group="mem")` 等价装卸（新入口，参数更少）。
  **符号修复手段都在 `symbol` 组**：`set_symbol_file` / `list_symbol_projects` 默认不在面上——
  `env_check` 报「符号与固件不同源」时，它的 `next_actions` 会把「先 `toolset(action="load", toolsets="symbol")`」这一步一并写出来；
  自己手工切符号时也记得先装这一组，否则只会撞「未知工具」。
- **上下文不够时的两把刀**：`nano` 极简档（`MDKDEBUG_TOOLSETS=nano`，19 个工具 / 约 4.6 千字符
  描述，自动用 `min` 描述档；含 `mdk_guide`，正文取回不用另外装）＋ **描述分层** `MDKDEBUG_DESC=full|lean|min`（默认 `full`，只有 `nano` 档自动用 `min`；要省上下文得显式选 `lean`/`min`）。
  描述分层只把「参考手册」式长正文挪出上下文，正文一字不改地归档，
  用 `mdk_guide(topic="tool", name="read_mem")` 可逐字取回；**结构化尾块
  （【输出控制】/【参数】/【风险】）与正文结尾的关键告警一定保留**——
  宁可多留字符，也不让描述出现「参数在、说明没了」。
- **统一信封**：所有工具返回体都带 `status`（ok/error/…) 与 `next_actions`（下一步建议）；
  失败时还有 `error_code` 与 `error_hint`。

### 插桩 trace 的两种工作模式：stream 与 buff

内核/固件往往跑得比调试器读得快——**不插桩、靠轮询读 SRAM 看高频事件是走不通的**
（全速跑时读回全 0，halt 读又把现象冻住）。正确做法是让目标自己攒证据：

| | `backend="buff"`（全速录、事后搬） | `backend="rtt"` 等（持续录持续读） |
|---|---|---|
| 谁在搬 | 目标写静态环形缓冲，调试器只在 dump 时读一次 | 调试器按节奏持续读 |
| 目标是否停 | **运行期间完全不停、不 halt** | 读的时候会 halt，目标被反复冻一下 |
| 时间粒度 | 目标侧 DWT，可到 **10ns 级**（`buff_ts_shift=0`） | 受读取节奏限制 |
| 适合 | 全速跑一段、事后离线分析（任务切换、异常现场） | 人在旁边盯着看的实时调试 |

工作流：

```
trace_instrument(backend="buff", buff_records=2048, buff_ts_shift=0,
                 buff_clear_on_init=false, fault_frame=true)   # 生成组件+配置，编烧
  → 跑目标（跑多久都行，目标不停）
  → trace_buff_status(elf=..., addr=...)     # 先看控制块：total/lost/wrapped/是否有新记录
  → trace_buff_dump(elf=..., addr=..., out_file="trace.json", names="0x10=switch")
  → trace_buff_reset(elf=..., addr=...)      # 下一轮前清空
```

硬规矩（都是真板上撞出来的，详见 [PITFALLS 第十七节](../docs/PITFALLS.md)）：

- **读回全 0 不等于缓冲是空的**——目标全速跑时经调试器读 SRAM 一律返回 0，
  工具会报 `buff-read-degenerate` 并要求先 `stop`。**`0` 的语义是「没读到」，不是「没有」。**
- `stop` 后**第一次** `read_mem` 是脏帧，必须重读复核。
- 用 `lost` / `wrapped` 判完整性：回卷时看到的是**一个窗口，不是全程**；
  分块 dump 之间必有空洞，要连续记录只能**把缓冲开大**、一次读完。
- 时间戳必须用 DWT_CYCCNT（组件已幂等使能 `DEMCR.TRCENA`）；拿内核节拍当时间戳会让
  10µs 级切片全退化成 `dt=0`。
- `trace_buff_reset` 是**延迟生效**的（目标在下一次写记录时才处理），
  返回体用 `applied` / `request_latched` 区分「已清空」与「只落了请求」，别把后者当成功。
- **「没插桩」不等于「没发生」**：`WAIT` 只覆盖 `wait/wait_period/block` 三条路径，
  其余阻塞在这条时间线上不可见。桩点清单本身就是这份 trace 的可信边界。

**第三种：SWD 无缝 stream（只接 SWD 两线，批次56）**——目标侧用「四元组字典 + varint」
把事件压到 1~3 字节写进环形缓冲，调试器按节奏**停机搬走**（既不是 buff 的「全速录到事后一次读」，
也不是 rtt 的「持续读」）。三条硬规矩（真机撞出来的，详见 [PITFALLS 第十八节](../docs/PITFALLS.md)）：

- **搬运间隔必须短于「环容量 / 事件率」**：8 KB 环 @ 约 10k 事件/s 只有 0.22 s 窗口——
  0.25 s 节奏丢 29,015 条，**0.12 s 节奏 `lost_events = 0`**。缓冲开大只是把窗口拉长，
  节奏不对照样丢，两个数要一起算。
- **读环必须停机**：目标全速跑时读 SRAM 可能整片读回 0（如实报 `swd-read-degenerate`）——
  **丢的是「没读到」，不是「没有」**。停机搬走不会丢数据（背压保证任何时刻已录的那段都完整，
  丢的只是事件，不是结构）。
- **时间粒度可调**：`trace_swd_reset(granularity=...)` 是唯一入口（`cycle` / `500us` /
  `none` / `1ms` / `1us`…，见 `trace_guide(topic="time_granularity")`），实测
  **3.69 / 1.61 / 1.60 字节每事件**。调粗只损时间分辨力：**事件顺序完整，但同一量化窗口内
  的先后不可分辨**。`trace_swd_read(granularity=...)` 只做校验，不符会报
  `swd-granularity-mismatch` / `-changed` / `-invalid`。失步报 `swd-stream-desync`，
  正解是 `trace_swd_reset` 重对齐（别硬解，字典不同步会解出看着合理的错误 key）。
- **任务名是主机侧「用 DWARF 反查」出来的，固件一个字节都不用改**：`trace_swd_read(tasks=auto)`
  会按 `svcrt_task_table` 的元素类型（`svcrt_task_t`，**匿名 typedef 结构体**）取出 `entry`
  字段偏移，逐槽读 TCB 入口指针、反查 ELF 函数符号，给 `sched`/`wait`/`ready`/`create`/
  `exit` 事件补上 `from_name`/`to_name`/`task_name`/`name`（数字 id 原样保留，`task_names`
  给出整张表）。**名字后到会回头补**：解析成功那一刻之前的历史事件也会被重命名一遍。
  **只认精确符号**（入口地址 = 函数首地址）：跨镜像的入口（SVCrtOS 的 app/驱动是
  另外下发的镜像，任务入口不在这份内核 `.axf` 里）**合法但无名**——这种槽位留空不编，
  给 `unmapped_slots` + `hint` 说明怎么取名；名字查不到就**不写名字**（不是写 `?`），
  只有**所有**非空槽都落不到符号表里才整批拒绝（`tasks-snapshot-inconsistent`）。
  `trace_swd_tasks` 单独看这张表为什么没名字（`read_mode`/`errors`/逐槽 `entry`）。
- **要连 app/驱动的名字一起拿，就把多份 `.axf` 一起传**：`elf="内核.axf;app.axf"`
  （`;` 或 `,` 分隔）。布局/任务表取**第一个具备者**，名字从所有镜像按精确首地址匹配，
  命中不在第一份时记 `sym_from`；**跨镜像的名字必须过内容核对**（板上该地址的机器码 ==
  那份 `.axf` 同地址的字节）才写上去——地址命中只说明「那地址在那份构建里是函数首地址」，
  不说明**板上跑的就是那份构建**，核不过/核不了就丢名、计入 `unconfirmed_slots`。
  任一路径不存在报 `tasks-elf-missing` 并点名。返回 `elf` 是第一份、`elfs` 是全部；
  真实情况里「一个名字都补不上」很常见（镜像根本不在手上），那时照旧 `ctxN` + 说明。
- **渲染不用自己喂任务名**：`view_render(data_file=…)` 会自己从返回体的 `task_names`
  里取名字，任务泳道直接是人可读的名字；idle 按 `idle_id` 单独命名，中断轨道走
  另一套命名（异常号），不会被任务名污染。

**桩该插在哪儿**（`trace_guide(topic="instrument_points")` 有完整版）：异常 handler 第一条指令
（`MDK_TRACE_FAULT_CAPTURE()`，一次拿到 PC/LR/SP/xPSR + CFSR，性价比最高）→ 喂狗点与复位原因
→ 任务/上下文切换点 → 状态迁移点。高频中断最内层、被内联的小函数、时间敏感临界区不要插。

## 六、给人看图：`view_render` / `view_guide`

上面采集回来的都是 JSON。要给人看（汇报、贴图、解释「为什么死在这」），**不要从头手写网页**——
把采集结果直接丢给 `view_render`，它出一张单文件 HTML（无外部依赖，`file://` 可开、可直接转发）：

```
trace_buff_dump(elf=..., out_file="trace.json", names="0x10=switch")
view_render(data_file="trace.json", title="任务切换")   # → path，打开即可

view_render(data={...})                  # 也可以内联 JSON，不必落盘
view_render(data={...}, view="scope")    # 已经知道该出哪种图时显式指定
view_guide(topic="howto")                # 不知道该配哪张图？先问它（howto/views/spec/limits/all）
```

四种视图（`view=auto` 按数据形状自认）：

| 视图 | 适合的数据 | 图上有什么 |
|------|------------|------------|
| `timeline` | 任务切换/中断/异常事件流（`trace_buff_dump`、`trace_swd_read`、`trace_record`） | 泳道 + 切换时刻标记（放大后标出切给谁）+ 中断进出区间 + 异常虚线 + **缺口斜纹带** |
| `scope` | 变量/波形样本（`trace_scope_read`）、自写 spec 的算法波形 | 每通道一带；模拟量折线、布尔/枚举阶梯；左侧给 min/max/变化次数/游标当前值 |
| `bars` | 函数/命中的占比排名（`trace_pcsample`、`trace_profile`、`coverage_read`） | 横向条形榜 + 绝对值 + 占比 |
| `report` | `{sections:[...]}` 自组结论页 | 结论块（ok/warn/bad）+ 段落 + 列表 + **可嵌套上面任一种图** |

页面自带：滚轮**以鼠标为锚**缩放、拖动平移、单击定位游标（读数跟着游标走）、双击全览、
`▶ 回放`（按原始时间 1:1 走一遍）、按轨道开关显隐。**每个图都带「边界」栏**：时间轴口径、
抽稀/合并/上限、丢失计数都摊在页面上——**图上看不到的，只能说没被记录/没插桩，不等于没发生**。

三条规矩：

- **认不出来就报错（`view-unknown-data`），不画空图**——空图会被读成「这段时间什么都没发生」。
- **自己写 spec 也要能直接出图**：`{"kind":"timeline"|"scope"|"bars"|"report", ...}`，
  字段说明看 `view_guide(topic="spec")`；结构不对报 `view-bad-spec`，不静默画个半截图。
- **省 token 的用法**：AI 只说「把这个结果渲染出来」，不写一行 HTML/CSS/JS。

## 七、出问题先看这几个工具

| 现象 | 先调 |
|------|------|
| 连不上 / 时通时不通 | `keil_health`、`get_status`、`list_uvision_instances` |
| 表达式集体解析失败 | `get_status` 看 `symbol_stale`，必要时 `set_symbol_file`（在 `symbol` 组、默认不暴露：先 `toolset(action="load", toolsets="symbol")`） |
| 断点/PC 解析出「板上不存在的函数」（假符号） | `get_current_location` 看 `symbol_verified`，再 `env_check` 看 `firmware_symbol` → 按它的 `next_actions` 装 `symbol` 组并 `set_symbol_file` 切到与刚烧录固件同源的那份 |
| 函数名/行号**解析出来了**，但不确定是不是假符号 | `get_current_location` 的 `symbol_verified`：false ＝ 本会话**没核对过**这份符号与板上固件是否同源（解析成功 ≠ 名字可信），跑一次 `env_check` 才会变成 true |
| 断点下不上（error 57/65/145） | 返回体里的 `checks` 与 `hints`，或 `find_symbol` 核对符号 |
| 编译失败看不懂 | `parse_build_errors`、`explain_build_error` |
| 外设寄存器值看不懂 | `svd_list` / `svd_decode`（自动按工程器件推断 SVD） |
| 读到的内存值可疑 | `cache_info`（H7 D-Cache 直读可能是旧值）、`snapshot_diff` 对比 |
| Keil 弹了模态框卡住 | `dismiss_dialog`、`keil_health` |
| 烧进去跑不起来 / 反复复位 | `watch_reset`（复位循环识别，`flags_addr` 给出芯片复位标志寄存器可坐实有没有复位）、`watchdog_freeze`（先冻住看门狗再复现）。注意 Keil 的 `reset` 命令**不产生真实复位**（DWT CYCCNT 不归零、`RCC_CSR` 不置新标志），用它复现复位现象会白测 |
| 想知道「测试跑到哪些函数/行」 | `coverage_start` → 跑流程 → `coverage_read` / `coverage_stop`（PC 采样，不停目标）。结论读 `unseen`（**没看到**，不是「未覆盖」）；采样器不工作/无符号表时会明确报错，不给一份看着像样的分布 |
| 双核 / 怕看的是另一个核 | `core_info`、`core_list`、`core_select`（Keil 链路只给"不支持 + 怎么办"，不假装切了核） |
| 问能不能抓 ETM 指令级 trace | `trace_etm_probe`（给 `present` 与 `supported` 两个**分开**的答案，并给替代方案）；`trace_guide` 看这台机器上实际有哪些 trace 手段 |
| 要改 .sct / 校验分散加载文件 | `scatter_read` → `scatter_check` → `scatter_edit`（改前备份、改后重解析校验，校验不过不落盘） |
| 想看任务切换 / 上下文切换的完整过程 | `trace_instrument(backend="buff")` 插桩 → 跑 → `trace_buff_dump`（全速录不停目标、10ns 粒度）。读回全 0 是「没读到」不是「没有」，先 `stop` |
| 想看异常为什么死 | 在 handler 第一条指令放 `MDK_TRACE_FAULT_CAPTURE()`，事后 `trace_buff_dump` 拿 PC/LR/SP/xPSR + CFSR 分位 |
| 要给人看波形/时间线/排名（不想手写网页） | `view_render(data_file=..., view="auto")`；不知配哪张图先 `view_guide(topic="views")` |

## 八、一条总原则

**宁可报错，也不给「看似权威的错答案」**：信息不足时这些工具会明确报错、返回
`available: false` 或标注低置信（`matched_by` / `pc_confidence` / `conflict` 之类），
并且**不会替你猜**一个像样的结果。看到这类字段时，照它的 `hint` 补齐证据再下结论。
