---
name: mdkdebug
description: 用 mdkdebug MCP 驱动 Keil uVision 做在线调试——读变量/内存、断点与运行控制、编译烧录、串口日志、SVD 寄存器解码、工程文件受控编辑。当用户提到 Keil、MDK、uVision、UVSOCK、单步/断点/看变量、烧录固件、Cortex-M 在线调试时使用。
---

# mdkdebug —— Keil 在线调试的组合拳

mdkdebug 是一个把 Keil uVision 变成「可被 AI 调用」的 MCP 服务，共 154 个工具。
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

## 二、四条主线工作流

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
```

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

### 4. UVSOCK 不可用时的降级通道（命令行批处理）

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

`list_tools`、`snapshot`、`read_mem_multi`、`batch`、`parse_map` 等 36 个工具的返回体
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

- **参数别名**：`query`/`name`/`expression`、`addr`/`address`、`timeout_ms`/`timeout_s`
  这类直觉写法都能落地；但**未列出的参数名会被拒绝**（不会静默用默认值），报错里会列出可用参数。
- **工具面默认精简**：默认只暴露 37 个（`core` 33 个 + 4 个元工具），其余 117 个按需装载——
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

## 七、一条总原则

**宁可报错，也不给「看似权威的错答案」**：信息不足时这些工具会明确报错、返回
`available: false` 或标注低置信（`matched_by` / `pc_confidence` / `conflict` 之类），
并且**不会替你猜**一个像样的结果。看到这类字段时，照它的 `hint` 补齐证据再下结论。
