---
name: mdkdebug
description: 用 mdkdebug MCP 驱动 Keil uVision 做在线调试——读变量/内存、断点与运行控制、编译烧录、串口日志、SVD 寄存器解码、工程文件受控编辑。当用户提到 Keil、MDK、uVision、UVSOCK、单步/断点/看变量、烧录固件、Cortex-M 在线调试时使用。
---

# mdkdebug —— Keil 在线调试的组合拳

mdkdebug 是一个把 Keil uVision 变成「可被 AI 调用」的 MCP 服务，共 178 个工具。
本技能告诉你**先调什么、按什么顺序调、遇到问题找谁**，避免在近百个工具里瞎试。

## 一、动手前的三条纪律

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
- **工具面默认精简**：默认只暴露 38 个（`core` 34 个 + 4 个元工具），其余 140 个按需装载——
  `toolset(action="load", toolsets="mem,trace")` 装回来、`toolset(action="status")` 看现状；
  启动时也可用 `MDKDEBUG_TOOLSETS=serial` 指定（参数优先），`=all` 全开。可用组名见 `capabilities`。
- **统一信封**：所有工具返回体都带 `status`（ok/error/…) 与 `next_actions`（下一步建议）；
  失败时还有 `error_code` 与 `error_hint`。

## 六、出问题先看这几个工具

| 现象 | 先调 |
|------|------|
| 连不上 / 时通时不通 | `keil_health`、`get_status`、`list_uvision_instances` |
| 表达式集体解析失败 | `get_status` 看 `symbol_stale`，必要时 `set_symbol_file` |
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

## 七、一条总原则

**宁可报错，也不给「看似权威的错答案」**：信息不足时这些工具会明确报错、返回
`available: false` 或标注低置信（`matched_by` / `pc_confidence` / `conflict` 之类），
并且**不会替你猜**一个像样的结果。看到这类字段时，照它的 `hint` 补齐证据再下结论。
