# Mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务

> **你只要把线接好，剩下的交给 AI。**

通过 **UVSOCK/TCP** 协议连接 Keil uVision 调试器，以 **MCP（Model Context Protocol）Server**
形式，向 Claude、灵犀等 AI 工具暴露嵌入式在线调试能力：读变量 / 表达式、读写目标内存、
运行控制（运行 / 暂停 / 复位 / 单步）、断点管理，以及自动进入 / 退出调试模式。

适用于 Cortex-M 等 ARM 目标板的在线调试。协议层参考自
[KeilAssistant](https://gitee.com/keyoushide/keil-assistant) 的 UVSOCK 实现。

---

## 功能特性

- **MCP Server**：以标准 `stdio` 或 `streamable HTTP` 传输方式暴露调试能力，AI 工具可直接调用；
- **表达式 / 变量读取**：`calc_expression` 读全局变量、寄存器、指针解引用（如 `SData_UA`、`*(uint32_t*)0x20000000`）；
- **内存读写**：任意地址读 / 写，超过单次上限（16 KB）自动分块，规避 Keil 协议长度限制；
- **运行控制**：全速运行、暂停、复位、单步（`into` / `over` / `out` / `instruction`）、`run_to_line` 运行到指定行；单步/运行到行后**自动附带当前停靠位置（`文件:行号`）+ 源码上下文 + 调用栈**，让 AI 单步进函数 / 出函数后立即看到效果，不必再额外查询；
- **像人一样看代码位置**：`get_current_location` 读取当前 PC，基于 `.axf` 调试符号定位到 `源文件:行号`，返回该行附近源码上下文与**完整调用栈回溯**（PC/LR/SP + 栈启发式扫描，多级调用链），让 AI 像人一样知道程序停在哪、是谁调进来的；并检测源码是否比 `.axf` 新（漂移时提示先重编译）；
- **局部变量读取**：`read_locals` 基于 DWARF 解析当前 PC 所在函数的参数与局部变量，用 `calc_expression` 在当前上下文求值，让 AI 看到当前函数的局部状态（而非仅全局变量）；
- **断点命中与定时运行**：程序停在 `set_breakpoint` 所设断点时返回命中反馈（含命中次数）；`run_timeout` 全速运行 N 毫秒后自动暂停并返回停靠位置，便于验证时序；
- **断点带位置**：`set_breakpoint` 自动反查断点对应的 `文件:行号`，`list_breakpoints` 返回断点列表含位置信息；
- **断点管理**：设 / 删 / 列断点，基于 Keil 命令窗口命令（`BS` / `BK` / `BL`）；断点列表解析自窗口 `BL` 的**真实输出**（含代码断点与数据观察点、Keil 断点编号、命中计数），清除时优先**按 Keil 断点编号**执行（数据观察点按地址会报 `error 72` 清不掉），并提供 `hard=true` 一键清空 Keil 侧全部断点；
- **数据断点（watchpoint）**：`set_watchpoint` 在变量 / 地址处设 读 / 写 / 读写 访问断点（Keil `BS READ/WRITE/READWRITE`），命中即暂停，用于观察某内存被访问的时机；
- **状态快照**：`snapshot` 一次性返回当前位置（文件行 + PC）+ 源码上下文 + 完整调用栈 + 局部变量 + 指定全局变量，让 AI 一眼看清程序卡在哪、处于什么状态；
- **变量组**：`watch` 批量读取一组表达式的当前值，便于固定观察多路信号；
- **结构体字段概览**：`read_struct` 基于 DWARF 解析结构体的字段布局（类型 / 偏移 / 大小），并用基址 + 偏移读取各字段运行时值，让 AI 看清一个结构体的完整内容；
- **寄存器组 + AAPCS**：`read_registers` 批量读取 R0-R12/SP/LR/PC/xPSR 并解读 AAPCS 调用约定（R0-R3 入参、R0 返回值、LR 返回地址），排查函数参数传错 / 返回值不对 / 寄存器被踩；
- **反汇编**：`disassemble` 用 capstone 反汇编目标代码（支持 `0x地址` / 符号名 / 文件:行 / 缺省 PC），排查死循环、跑飞、启动流程与优化后行为；
- **内存分析套件**：内存地图（`query_memory_map`）+ 字节搜索（`search_mem`）+ 批量填充（`fill_mem`）+ 外设写（`write_peripheral`）+ 状态 diff（`snapshot_diff`）+ 函数耗时（`profile_function`）+ 异常自动抓取（`wait_fault`），覆盖从定位地址、找魔数到观察运行变化、复现崩溃的全链路；
- **工程产物解析**：`parse_build_errors` 把编译错误/警告解析为结构化列表（兼容 AC5/AC6 两种格式），`parse_map` 解析 .map 的 FLASH/RAM 占用、符号地址与栈使用；
- **批量命令**：`read_mem_multi` 一次读取多个地址内存、`batch` 一次提交多条只读命令（read_mem/read_variable/calc_expression/get_status/read_registers）聚合返回，显著减少 AI 往返；
- **多 target / 工程配置**：`project_targets` 枚举工程全部 target + 当前 target + 调试 target，`set_debug_target` 切换调试目标，`read_project_config` 解析各 target 的编译器（AC5/AC6）、优化级别（-O0~-Otime）、编译宏 Define 与包含路径——排查“不同 target 行为不同”时对比宏/优化差异；
- **采样剖析**：`profile_sampling` 基于 PC 统计采样定位热点函数（按 .axf 符号表归函数算占比），找“哪个函数占 CPU 最多”的性能瓶颈；`profile_function`/`dwt` 做函数级精确计时；
- **目标器件信息**：`target_info` 实时读 DBGMCU->IDCODE 判芯片 DEV_ID/REV_ID + SCB->CPUID 判内核类型，返回标称 Flash/RAM 容量与内存布局，排查资源吃紧/选错型号/容量不符；
- **环境自检 + 工作流引导**：`mdk_guide` 一键自检 Keil/UVSOCK/UV4/.axf/源码漂移/调试态/RTOS 类型，并返回推荐调试工作流与各场景应调用的工具——AI 落地的第一个工具，避免盲目试错；
- **一键诊断**：`diagnose` 聚合寄存器组 + PC 反汇编 + 源码上下文 + 调用栈 + 局部变量 + 指定全局变量，AI 接到 bug 报告后一次调用即可看清现场；
- **符号检索**：`find_symbol` 从 .axf ELF 符号表模糊检索函数/全局变量（地址+类型），AI 读任意符号不再靠猜名字；
- **写寄存器 / 改 PC**：`set_register` 写 CPU 寄存器并读回验证，可修正现场、改返回值、改 PC 跳转执行；
- **性能分析**：`dwt` 读 DWT 周期计数器（自动使能），配合两次采样测代码段执行时间；
- **HardFault / 异常定位**：`fault_report` 读 SCB 寄存器判异常类型与原因，并从异常栈帧恢复现场（PC/LR/R0-R3），排查死机/跑飞/复位循环；
- **条件断点**：`set_conditional_breakpoint` 设 C 表达式条件/命中次数断点，只在特定条件或第 N 次命中才停；
- **外设寄存器一键读（SFR）**：`read_peripheral` 内置 STM32F4 常用外设寄存器表（RCC/GPIO/USART/SPI/I2C/TIM/ADC/PWR/FLASH/SysTick/SCB/NVIC/DWT/EXTI/SYSCFG），一键读指定外设全部寄存器当前值并解析关键位域（时钟使能/波特率/GPIO 模式/定时器计数），`list_peripherals` 列出可用外设——排查时钟没使能、GPIO 模式配置错、串口波特率不对等场景，**不依赖外部 SVD 文件、离线可用**；
- **ITM / Debug(printf) Viewer trace**：`itm_trace` 检查 Trace 配置（DEMCR.TRCENA / ITM->TCR / ITM->TER）是否就绪，并经 UVSOCK 串口通道拉取 Debug(printf) Viewer 收到的 ITM 打印文本——printf 走 SWO 输出时无需占用 UART，排查实时日志/运行状态；真实 ITM 输出需 Keil 已配置 Trace（Core Clock + Stimulus Port0）且调试器（ST-Link/J-Link）SWO 引脚已连接；
- **自动进出调试模式**：`enter_debug` / `exit_debug`，支持 AI 驱动"进入 → 设断点 → 运行到断点 → 读变量 → 退出"完整闭环；
- **编译 / 烧录闭环**：基于 Keil 官方 `UV4.exe` 命令行，提供 `build_project`（编译）、`rebuild_project`（重编译）、`flash_download`（烧录）、`build_and_flash`（编译成功后自动烧录），支持 AI 自主"改代码 → 编译 → 烧录 → 上板"全流程闭环；
- **后台静默编译**：编译 / 烧录以隐藏窗口方式启动 UV4，**不会闪现新的 Keil 界面**，用户已打开的实例不受打扰；
- **AI 管理 Keil 开关（闭环）**：`launch_uvision` 拉起 Keil 打开工程（已有同工程窗口则复用，不新开），`close_uvision` 关闭 Keil（默认优雅关闭、残留自动强制），Keil 的开启/关闭全部由 AI 闭环管理，无需手动操作；
- **Keil 窗口不累积**：UV4.exe **不是**单实例程序（真机实测同工程可并存 6 个窗口），因此 `launch_uvision`、编译后调试通道自愈都先查已有实例、复用而不新开；`list_uvision_instances` 可随时清点，`close_uvision(keep="latest")` 把多余的收敛成一个，保证「只开一个窗口调试」；
- **规避旧窗口调试旧代码**：`flash_debug` 自动按「关闭所有 Keil → 让新固件上板 → 重新打开本工程 → 进入调试」顺序执行，避免因残留旧工程窗口导致调试到旧代码（即使 AI 不记得先关旧窗口也能保证加载的是新固件符号）；上板方式**自动选路**：工程勾选了 Keil 的 `Update Target before Debugging`（`.uvprojx` 的 `UpdateFlashBeforeDebugging=1`，Keil 默认）时，进入调试会由 Keil 自己把最新程序下载进 Flash，于是只编译、不再显式烧录（省掉一次全片擦写与 `UV4 -f` 往返），返回 `flash_plan=debug_download`；未勾选时才退回显式烧录（`flash_plan=explicit_flash`）；
- **编译烧录输出集中返回**：每次编译/烧录的完整日志（含警告/错误）经 `-o` 捕获并由 AI 完整返回，在对话中即可查看，无需盯 Keil 窗口；
- **UV4 自动探测**：优先显式 `--uv4-path`，其次探测常见安装目录，再查 Windows 注册表；
- **连接缓存**：常驻服务内共享一条 TCP 连接，空闲自动断开、下次调用自动重连；
- **并发调用可安全并行**：所有 UVSOCK 命令经**统一闸门串行化**——进程内 RLock（同进程多线程）+ 跨进程锁文件（多个 mdkdebug 实例共用同一调试通道时也只允许一个发命令），超时降级并如实记入遥测；`get_status` / `keil_health` 会回报**其他 mdkdebug 实例**（PID + 心跳年龄）并在有竞争时给出 `concurrency_warning`，把「写入被静默吞掉」从猜测变成可见证据；详见 [docs/PITFALLS.md](./docs/PITFALLS.md)；
- **随附模拟调试器**：无需硬件即可离线联调与跑测试。

## 工作原理

### 架构

```
┌──────────────┐  MCP(stdio/http)  ┌──────────────────┐  UVSOCK/TCP  ┌─────────────────┐
│  AI 工具客户端 │ ────────────────► │  Mdkdebug MCP Server │ ─────────────► │  Keil uVision   │
│ (Claude/灵犀) │                  │     (mdkdebug)     │  127.0.0.1:4823 │  + UVSOCK 插件  │
└──────────────┘                  └──────────────────┘               └─────────────────┘
```

AI 客户端通过 MCP 协议把用户/模型意图转成工具调用；`mdkdebug` 收到后，按 **UVSOCK** 二进制
协议把请求编码成命令帧，通过 TCP 发送给 Keil uVision 中加载的 UVSOCK 调试插件执行，并回传结果。

### UVSOCK 协议要点

- 默认监听 `127.0.0.1:4823`；
- 命令帧：头部 32 字节（`m_nTotalLen` / `m_eCmd` / `m_nBufLen` / `cycles` / `tStamp` / `m_Id`）+ 数据段；
  响应帧头部在此基础上多 8 字节（`r_cmd` / `r_status`），地址小端；
- 关键命令码：

| 命令 | 码值 | 说明 |
|------|------|------|
| `UV_DBG_ENTER` | `0x2000` | 进入调试模式 |
| `UV_DBG_EXIT` | `0x2001` | 退出调试模式 |
| `UV_DBG_START_EXECUTION` | `0x2002` | 全速运行 |
| `UV_DBG_STOP_EXECUTION` | `0x2003` | 暂停 |
| `UV_DBG_STATUS` | `0x2004` | 查询调试/目标状态 |
| `UV_DBG_RESET` | `0x2005` | 复位 |
| `UV_DBG_STEP_INTO` | `0x2007` | 单步进入 |
| `UV_DBG_CALC_EXPRESSION` | `0x200A` | 计算表达式 / 读变量 |
| `UV_DBG_MEM_READ` | `0x200B` | 读内存 |
| `UV_DBG_MEM_WRITE` | `0x200C` | 写内存 |
| `UV_DBG_EXEC_CMD` | `0x2020` | 执行命令窗口命令（`BS`/`BK`/`BL`/`EVAL`） |

> `UV_DBG_STATUS` 的响应码语义为 **`0`=已停止、`1`=执行中**（区别于通用 `UV_STATUS` 错误码）。

## 环境与依赖

### 环境要求

| 项 | 要求 |
|----|------|
| 操作系统 | Windows（Keil uVision 运行环境） |
| Python | ≥ 3.11（开发 / 验证于 3.12） |
| Keil | uVision 5，且已配置 UVSOCK 调试插件（见"对接真实 Keil"） |
| Keil UV4 | `UV4.exe` 用于编译 / 烧录，可自动探测或 `--uv4-path` 指定（通常随 Keil 安装于 `UV4/UV4.exe`） |

### Python 组件依赖

见 `requirements.txt`，核心依赖：

| 包 | 版本 | 作用 |
|----|------|------|
| `mcp` | ≥ 2.0（验证于 2.2.0） | MCP Server 框架（`MCPServer`） |
| `pydantic` | ≥ 2.8（验证于 2.13.5） | MCP 依赖的类型模型 |
| `pyelftools` | ≥ 0.30（验证于 0.33） | 解析 `.axf` 调试符号，供 `get_current_location` / `run_to_line` / 断点位置定位使用 |
| `capstone` | ≥ 5.0（验证于 5.0.9） | Thumb 反汇编，供 `disassemble` / `diagnose` 使用 |

安装（两种方式任选其一）：

```bash
# 方式一：仅装依赖，从源码运行
pip install -r requirements.txt
python run_server.py

# 方式二：打包安装（推荐，可执行 mdkdebug 命令）
pip install -e .
mdkdebug --version
```

> 注：`mcp 2.x` 中 `FastMCP` 已改名为 `MCPServer`（`from mcp.server.mcpserver import MCPServer`），
> 工具通过 `@server.tool()` + 类型注解注册。

## 目录结构

```
mdk_agent/
├── run_server.py             # 启动入口薄壳（转发到 mdkdebug.cli）
├── pyproject.toml            # 打包配置（pip install -e .）
├── requirements.txt          # Python 依赖
├── README.md
├── mdkdebug/
│   ├── __init__.py           # 包初始化（版本号 0.0.5）
│   ├── cli.py                # 命令行入口（main，mdkdebug 命令）
│   ├── uvsock.py             # UVSOCK 协议：命令码、VSET/AMEM/EXECCMD 打包与解析
│   ├── interface.py          # TCP 物理接口层（含异步消息残留清理）
│   ├── client.py             # UVClient：调试能力封装 + 连接缓存
│   ├── builder.py            # UV4 命令行：编译 / 重编译 / 烧录 / 编译烧录闭环
│   ├── locator.py             # 基于 .axf DWARF 的符号定位（地址↔文件:行 双向 + 源码读取）
│   ├── periph.py             # 内置 STM32F4 常用外设寄存器表（RCC/GPIO/USART/SPI/I2C/TIM/...）+ 内存区域地图
│   ├── mapfile.py            # .map 链接映射文件解析（Program Size/sections/symbols/栈使用/未用段）
│   └── server.py             # MCP Server 与 83 个工具定义
├── tests/
│   ├── mock_uvsock_server.py # 模拟 Keil 调试器的 UVSOCK 服务器（离线联调）
│   ├── test_e2e.py           # UVClient 协议闭环测试
│   ├── test_batch1.py        # 批次1：find_symbol/set_register/dwt
│   ├── test_batch2.py        # 批次2：fault_report/条件断点
│   ├── test_batch3.py        # 批次3：read_peripheral/list_peripherals/itm_trace
│   ├── test_batch4.py        # 批次4：query_memory_map/search_mem/fill_mem/snapshot_diff/profile_function/write_peripheral/wait_fault/parse_build_errors/parse_map
│   ├── test_batch5.py        # 批次5：read_mem_multi/batch/project_targets/set_debug_target/read_project_config
│   ├── test_batch6.py        # 批次6：target_info/profile_sampling/mdk_guide
│   ├── test_mcp.py           # MCP Server 工具注册与调用测试
│   └── test_stdio.py         # stdio 全链路客户端握手测试
└── example_mdk_project/      # 随附 STM32F4 HAL 例程（真机调试验证目标，随项目一并开源）
```

## 快速开始

### 启动 MCP Server

**方式一：stdio（MCP 客户端标准方式）**

```bash
python run_server.py                              # 默认连 127.0.0.1:4823
python run_server.py --port 4823 --idle-timeout 30
```

**方式二：Streamable HTTP（便于远程 / 网页 MCP 客户端）**

```bash
python run_server.py --transport http --http-port 8300
```

参数说明：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--host` / `--port` | `127.0.0.1` / `4823` | Keil **UVSOCK 插件**监听的地址 |
| `--idle-timeout` | `30.0` | 连接缓存空闲断开秒数（`0` 表示不主动断开） |
| `--transport` | `stdio` | `stdio` 或 `http` |
| `--http-host` / `--http-port` | `127.0.0.1` / `8300` | HTTP 传输时的监听地址 |
| `--uv4-path` | 自动探测 | Keil `UV4.exe` 绝对路径，缺省时自动探测（如 `D:/Keil_v5/UV4/UV4.exe`） |
| `--default-project` | 无 | 默认待编译 / 烧录的 `.uvprojx` 工程路径，工具调用可省略 `project` 参数 |

## 暴露的 MCP 工具

共 **85** 个（调试读写 / 断点与命中等待 / 外设与内存 / 符号定位 / 工程分析 / 编译烧录 / Keil 生命周期管理 / **宿主机串口日志** / **看门狗冻结与 Cache 感知** / 环境自检引导）：

| 工具 | 说明 | 主要参数 |
|------|------|----------|
| `get_version` | 查询 UVSOCK 插件版本 | — |
| `get_status` | 查询是否处于调试、目标是否运行、状态码，并附**当前符号文件路径 + 时间戳**（`symbol_file`/`symbol_mtime_text`）、**符号陈旧判定**（`symbol_stale` + `symbol_stale_warning`：编译/烧录后旧会话符号过期，求值会报 status 13）、**串行化与并发视图**（`serialization`，含其他 mdkdebug 实例清点） | — |
| `calc_expression` | 计算并读取表达式 / 变量值 | `expr` |
| `read_variable` | 按变量名查地址/值/大小，支持数组逐元素与整块内存；App 侧重定位场景可配 `reloc_delta` 自动换算运行地址 | `name`、`count?`、`reloc_delta?` |
| `read_mem` | 读取目标内存（`n_bytes` 可写作别名 `length`；`reloc_delta` 用于 App 侧重定位后按运行地址读）。**脏读防护**（`verify`，默认 `auto`）：stop 后紧跟的首次读可能整帧返 0（真机实测 0x08022000 读出 16 个 `00`，重读即正确）——`auto` 在「首帧整帧退化（全 `0x00`/全 `0xFF`）或距最近一次 stop 不足 1 秒」时自动复读、**连续两次一致才采纳**，并返回 `read_confidence`/`reread_count`/`reread_consistent`/`degenerate`/`since_stop_s`；首帧是脏值时用 `first_read_hex` 留证。`verify=true` 强制确认、`false` 关闭（**布尔/字符串都收**，`verify=false` 与 `"false"` 等价）；Flash 区稳定读出全 `0xFF` 判为**已擦除的预期内容**（`content_note`，不降置信度）。**D-Cache 感知**：读 SRAM 且目标 D-Cache 已使能时附 `cache` 字段，提醒「DAP 直读可能拿到内存旧值（CPU 新值还在脏行里）」 | `addr`（`0x…` 或十进制）、`n_bytes`、`reloc_delta?`、`verify?`（默认 `auto`，可传布尔） |
| `write_mem` | 写入目标内存，**默认写后回读校验**（`verify=true` → `verified`/`readback_hex`）：写入被静默忽略（目标运行中/只读区/另一实例并发写）时给出 `verified=false` 与原因，不再「看着成功其实没写进去」。**D-Cache 感知**：写 SRAM 且目标 D-Cache 已使能时附 `cache` 字段，提醒「写下的值可能稍后被脏行回写覆盖（写入仍报成功）」 | `addr`、`data_hex`（十六进制串，可带空格）、`verify?`（默认 true） |
| `cache_info` | 读 `SCB->CCR` 判定目标是否使能 D-Cache / I-Cache（并粗略解析 CCSIDR 得到行/路/组与容量）。**为什么重要**：D-Cache 开着时 DAP **直读 RAM 可能是陈旧值**、**直写 RAM 可能被脏行回写覆盖**，两者都不报错——`read_mem`/`write_mem` 命中 SRAM 时也会附 `cache` 字段提示（探测结果 5 秒 TTL 缓存，不额外拖慢读写）；M3/M4 无 D-Cache、M7 默认不开，此时不产生任何噪声字段 | — |
| `run` | 全速运行 | — |
| `run_timeout` | 全速运行 N 毫秒后自动暂停并返回停靠位置，用于验证时序；返回 `requested_run_ms` / `actual_run_ms` / `stop_wait_ms` / `total_ms` 四段计时，排查时序不再只能看一个含糊的 `waited_ms` | `timeout_ms`（默认 1000） |
| `stop` | 暂停执行，**默认带停止确证**：停止是异步生效的（真机实测 stop 回 ok 后紧跟的 `get_status` 仍报「执行中」），故返回 `stopped`/`stop_verified`/`waited_ms`/`state_after_stop`，`verify=false` 可只发命令不确认。**看门狗防御**：暂停期间看门狗（IWDG）仍在计数，halt 超过溢出时间就被复位、RAM 现场全丢——默认自动置位 DBGMCU 冻结位并返回 `watchdog_freeze`，`freeze_watchdogs=false` 可关闭 | `verify?`（默认 true）、`timeout?`、`freeze_watchdogs?`（默认 true） |
| `watchdog_freeze` | 查询/置位 DBGMCU 的 IWDG/WWDG **调试冻结位**。新会话/目标复位后冻结位会被清零（真机实测 APB1FZ=0x00000000），此时 halt 超过看门狗溢出时间就被复位、RAM 现场全丢；置位后 halt 期间看门狗停止计数。基址**运行时探测**（读 IDCODE 校验 DEV_ID，兼顾 F1/F4/F7 的 0xE0042000 与 H7 的 0x5C001000），不按内核硬编码 | `action?`：`status`（默认）/`enable`/`disable`（含 `on`/`off`/`get` 等别名） |
| `reset` | 复位目标（变量回初值、断点保留）。**真机实测：复位后停在复位向量、处于停止态，不会自行往下跑**——必须再 `run`（或 `run_timeout`/`run_to_line`）才开始执行；返回 `state_after_reset`/`stopped_after_reset` 与 `hint`；`run_after=true` 可复位后自动 run | `run_after?`（默认 false） |
| `step` | 单步执行，成功后自动附带停靠位置（`stopped_file`/`stopped_line`/`stopped_address`）+ 源码上下文 + 调用栈 | `mode`：`into`/`over`/`out`/`instruction` |
| `run_to_line` | 运行到指定行（run to cursor），接受 `文件:行号` 或 `0x地址` | `target`（如 `main.c:77`） |
| `get_current_location` | 读取当前 PC，定位到 文件:行号 + 源码上下文 + 完整调用栈回溯 + 源码漂移提示 + 断点命中反馈 | — |
| `read_locals` | 读取当前函数 参数+局部变量 及其值（DWARF 解析变量名，`calc_expression` 在当前上下文求值） | — |
| `snapshot` | 状态快照：位置（文件行+PC）+ 源码上下文 + 完整调用栈 + 局部变量 + 指定全局变量，一站式看清当前运行状态 | `globals`、`source_context` |
| `watch` | 变量组：批量读取多个表达式/变量的当前值，便于固定观察一组信号 | `exprs` |
| `read_struct` | 结构体字段概览：基于 DWARF 解析字段布局（类型/偏移/大小），并用基址+偏移读各字段运行时值 | `name`、`max_fields` |
| `set_watchpoint` | 数据断点：在变量/地址处设 读/写/读写 访问断点，命中即暂停（`BS READ/WRITE/READWRITE`） | `expr`、`access`、`count` |
| `clear_watchpoint` | 清除数据断点：先解析 Keil 真实断点编号再 `BK <编号>`（按地址会报 `error 72` 清不掉），返回 `cleared_by` | `expr` |
| `list_watchpoints` | 列出当前数据断点（含地址、访问类型、位置） | — |
| `read_registers` | 批量读取 CPU 核心寄存器 R0-R12/SP/LR/PC/xPSR 及当前值，并按 AAPCS 解读 R0-R3 入参、R0 返回值、LR 返回地址，排查参数/返回值/寄存器被踩 | — |
| `disassemble` | capstone 反汇编目标代码：地址 `0x…` / 符号名 / 文件:行 / 缺省当前 PC，排查死循环、跑飞、启动流程、优化行为 | `addr`、`count`（默认 8） |
| `diagnose` | 一键诊断：聚合寄存器组(含 AAPCS) + PC 处反汇编 + 源码上下文 + 完整调用栈 + 局部变量 + 指定全局变量，一次调用看清现场 | `globals`、`disasm_count`、`source_context` |
| `find_symbol` | 符号检索：从 .axf ELF 符号表模糊检索函数/全局变量（返回名字/类型/地址/大小），AI 读符号不再靠猜名字；`query` 可写作别名 `name`，配 `reloc_delta` 时附 `run_addr` | `query`、`kind`（all/func/object/global/local）、`limit`、`reloc_delta?` |
| `set_register` | 写寄存器/改 PC：向 R0-R12/SP/LR/PC/xPSR 写值并读回验证，可修正现场、改返回值、改 PC 跳转执行 | `register`、`value` |
| `dwt` | DWT 周期计数器：读 CYCCNT（自动使能），配合两次采样算代码段执行周期数与耗时 | — |
| `fault_report` | HardFault/异常定位：读 SCB（ICSR/HFSR/CFSR/MMFAR/BFAR）判异常类型+原因，从异常栈帧恢复 PC/LR/R0-R3/xPSR，排查死机/跑飞。**CFSR/HFSR 是粘滞位**（写 1 清除或复位才归零），故返回 `fault_timing`：`timeliness`=`current`（正处在 fault handler，即当下故障）/`sticky`（很可能只是历史残位，别当当前故障）/`none`，并给出 `first_seen`/`last_seen`/`last_cleared` | — |
| `clear_faults` | 清除 CFSR/HFSR 粘滞位（W1C，写 `0xFFFFFFFF`，同时清 MMFAR/BFAR 的 VALID），返回 `before`/`after`/`cleared` 供对照——用于**区分新旧异常**：清位 → 跑一段 → 重新 `fault_report`，位又置起来才是新发生的 | — |
| `set_conditional_breakpoint` | 条件断点：仅在 condition（C 表达式如 R0==5）成立/第 count 次命中时才停，减少无关中断 | `expr`、`condition`、`count` |
| `read_peripheral` | 外设寄存器一键读：内置 STM32F4 外设表（RCC/GPIO/USART/SPI/I2C/TIM/...），读指定外设寄存器并解析关键位域；`regs` 只取指定寄存器（如 `MODER,OTYPER`，裸名/前缀名都可，**也接受字符串数组 `["MODER","ODR"]`**）、`fields=off` 关位域解读，避免整表输出撑爆上下文 | `periph`、`regs?`、`fields?` |
| `list_peripherals` | 列出内置外设寄存器表（外设名+基址+说明） | — |
| `itm_trace` | ITM/Debug(printf) Viewer trace：检查 Trace 配置(DEMCR/ITM->TCR/TER)是否就绪 + 拉取串口窗口缓冲中的 ITM 打印文本 | `port`、`size` |
| `query_memory_map` | 内存区域地图：FLASH/SRAM/外设/ITM/DWT/SCS 地址范围，可标注某地址落在哪个区域，防止把外设区当 RAM 读 | `addr`（可选） |
| `search_mem` | 在内存范围内扫描字节序列，返回所有命中地址（分块读、块间重叠防跨块漏匹配），找魔数 / 定位被越界写坏的缓冲 | `start`、`end`、`pattern_hex`、`pattern_text`（直接搜文本，如 `appstat`，免手工转十六进制） |
| `fill_mem` | 批量填充 / 清零内存：连续写入 count 个相同字节，清零大块缓冲 / 初始化 SRAM | `addr`、`byte`、`count` |
| `snapshot_diff` | 状态快照 diff：首次建基线（globals + 寄存器），之后对比输出 changed / unchanged / unreadable，定位被意外改写的状态 | `globals` |
| `profile_function` | 函数执行耗时分析：自动设入口断点 → 运行到入口记 DWT CYCCNT → step out 再记 → 差值，函数级性能分析 | `func`、`max_ms` |
| `write_peripheral` | 写入外设单个寄存器并读回确认：置时钟使能 / 改 GPIO 模式 / 配波特率 / 改定时器 | `periph`、`reg`、`value` |
| `wait_fault` | 运行至异常 / 断点并自动诊断：轮询等待停止，若停异常则读 ICSR/CFSR 判类型 + 收集现场，复现崩溃自动抓现场 | `timeout_ms` |
| `parse_build_errors` | 解析编译错误 / 警告为结构化列表（文件:行:列 + 消息），兼容 AC5 `path(line):` 与 AC6 `path:line:col:` 两种格式 | `errors_text` |
| `parse_map` | 解析 .map 链接映射文件：Program Size / sections / symbols / 栈使用 / 未用段，检查 FLASH/RAM 占用与栈溢出风险 | — |
| `read_mem_multi` | 一次读取多个地址的内存（每项 {addr, n_bytes}，缺省 32），减少 AI 往返 | `addresses` |
| `batch` | 一次提交多条只读命令聚合返回（read_mem/read_variable/calc_expression/get_status/read_registers），减少往返 | `commands` |
| `project_targets` | 枚举工程全部 target + 当前 target + 调试 target（UV_PRJ_ENUM_TARGETS/GET_CUR_TARGET/GET_DEBUG_TARGET） | — |
| `set_debug_target` | 切换调试 target（UV_PRJ_SET_DEBUG_TARGET），多 target 工程切目标后重新进调试 | `target` |
| `read_project_config` | 读取工程配置：各 target 编译器（AC5/AC6）、优化级别（-O0~-Otime）、编译宏 Define、包含路径、`update_flash_before_debugging`（调试前是否自动下载程序）（.uvprojx 解析） | `project`、`target`（可选） |
| `target_info` | 查询目标器件信息：实时读 DBGMCU->IDCODE 判 DEV_ID/REV_ID 映射型号 + SCB->CPUID 判内核 + 标称 Flash/RAM 容量与内存布局，排查资源吃紧/选错型号/容量不符 | — |
| `profile_sampling` | 采样剖析定位热点：让目标运行，周期性暂停采 PC 归到函数统计占比（run/stop 采样，非硬件 ETM，会轻微扰动时序），找哪个函数占 CPU 最多 | `duration_ms`、`interval_ms`、`max_samples` |
| `mdk_guide` | 环境自检+工作流引导：一键自检 Keil/UVSOCK/UV4/.axf/源码漂移/调试态/RTOS 类型，返回推荐调试工作流与各场景应调用的工具，AI 落地第一件事先调它 | — |
| `enter_debug` | 自动进入 Keil 调试模式；**已在调试态时返回 `already_in_debug=true`**，不再报失败（省一轮 `exit`/`enter`）；注意副作用：工程勾选 Update Target before Debugging 时会**自动下载最新程序进 Flash**。进调试后**默认自动冻结看门狗**（`freeze_watchdogs`） | `freeze_watchdogs?`（默认 true）；进调试时会**报告 `.uvoptx` 遗留断点**（这些断点会随进调试被 Keil 自动恢复，软件断点命令清不掉，是「目标行为诡异」的隐蔽干扰源） |
| `exit_debug` | 自动退出 Keil 调试模式 | — |
| `set_breakpoint` | 在符号 / 地址处设软件断点；已存在时 Keil 报 `error 145`，按成功处理并附 `already_exists`。**地址路径与符号路径同一套归一**：入参地址带 Thumb 位（bit0=1）时自动按偶地址下断并返回 `thumb_bit_stripped`/`address_normalized`（真机实测 Keil 的 `BS` 对奇数地址一律报 `error 57: illegal address`）；失败时返回 `diagnosis`（错误码含义 + 地址落在哪个内存区 + 是否在 .axf 覆盖范围 + 下一步建议） | `expr`（如 `main`、`0x08001034`；奇地址会自动清 bit0） |
| `clear_breakpoint` | 清除断点：`expr`（符号/地址）、`bp_id`（内部 id）、`keil_number`（Keil 界面/BL 里的**真实断点编号**，数据观察点只能这样清）；`bp_id` 在内部表找不到时自动按 Keil 编号处理并给 `resolve_note` | `expr?`、`bp_id?`、`keil_number?` |
| `list_breakpoints` | 列出断点（含对应的 文件:行号 位置）；`real` / `real_total` 给出 Keil 侧**真实断点表**（编号/类型/访问方式/地址/长度/命中计数/启用状态） | — |
| `launch_uvision` | 可见方式拉起 Keil 打开工程；已有同工程窗口则**复用并前置**，不新开；以 `CREATE_BREAKAWAY_FROM_JOB` **脱离父进程 job** 启动，不会随调用链被回收 | `project`、`reuse?`（默认 true） |
| `list_uvision_instances` | 列出当前 Keil 实例（PID / 启动时间 / 打开的工程），一眼看清是否残留多个窗口 | `project?` |
| `close_uvision` | 关闭 Keil 实例；`keep="latest"/"oldest"` 可**只保留一个窗口**、其余关闭 | `force?`、`keep?`、`project?` |
| `build_project` | 编译工程（`UV4 -b`，后台隐藏窗口；编译后自动检查调试通道） | `project`、`target`、`timeout_s`、`ensure_debug_channel` |
| `rebuild_project` | 全量重编译（`UV4 -r`，编译后自动检查调试通道） | `project`、`target`、`timeout_s`、`ensure_debug_channel` |
| `flash_download` | 烧录到目标 Flash（`UV4 -f`，烧录后自动检查调试通道）；**烧录后若仍在调试态则自动退出调试**（`exit_debug_after`，旧会话符号已过期），返回值 `debug_session` 说明处理过程 | `project`、`target`、`timeout_s`、`ensure_debug_channel`、`exit_debug_after` |
| `build_and_flash` | 编译成功后才烧录，AI 全流程闭环（自带通道自愈）；烧录后同样自动退出旧调试会话（`exit_debug_after`，返回 `debug_session`） | `project`、`target`、`timeout_s`、`ensure_debug_channel`、`exit_debug_after` |
| `flash_debug` | 「关旧 Keil→新固件上板→开新→进调试」一体闭环，规避旧窗口调试旧代码；上板方式自动选路（`flash_plan`：`debug_download` 由 Keil 进调试时自动下载 / `explicit_flash` 显式烧录） | `project`、`target` |
| `read_console_output` | 读取命令窗口输出 | `clear?` |
| `read_async_messages` | 读取异步消息/报错 | `clear?` |
| `serial_monitor_start` | **宿主机串口日志监听**（后台线程收 → 按行切分 → ring buffer）：`port` 可写 `"COM9"` 或 `9`（留空取第一个可用口），`baud` 默认 115200，`capacity` 默认保留 2000 行；端口不存在/被占用时 `ok=false` 并附 `available_ports`，不会静默失败；重复 start 时 `restart=false` 可避免抢占。**用完就还**：`idle_release_s`（默认 900s，0=不自动）为无人访问多久后自动释放端口——释放只放掉 COM 口，已收日志仍保留、可继续 `serial_read`，需要接着采集重新 start 会复用同一实例（`resumed=true`）不丢日志 | `port?`、`baud?`、`databits?`、`parity?`、`stopbits?`、`capacity?`、`encoding?`、`label?`、`restart?`、`idle_release_s?` |
| `serial_write` | **向串口下发数据（一边收一边发）**：`text` 与 `hex` 二选一，`eol` 控制行尾——`crlf`（默认）/ `lf` / `cr` / `none` / `auto`，**也接受转义写法 `"\r"`、`"\n"`、`"\r\n"` 与 `cr+lf`/`windows`/`unix`/`dos` 等别名**；`read_after=true`（默认）时把这次下发之后**新增的回显行**一起返回（按写前 `next_seq` 增量取，不重复老日志）。**「到底发出去了什么」摆在返回值里**：`sent_hex`/`sent_bytes`/`eol_input`/`eol_applied`/`eol_bytes_hex`，外加回显判定 `read_after.bytes_new`——行尾没发出去时 `eol_applied=null` 并附 `warning`，`eol` 不可识别时给 `eol_unrecognized` 与可用取值提示（不再出现「看着 ok 其实换行根本没发」）。`eol="auto"` = 先按 `crlf` 发，若无任何回显（按字节增量判，比行数灵敏）再补发单个 `\r`，兼顾 SVCrtOS shell / RT-Thread msh 这类只认单 `\r` 的目标。用于下发 shell/msh 命令、给 bootloader 发指令、分段下发镜像 | `text?`、`hex?`、`eol?`、`encoding?`、`wait_ms?`、`read_after?`、`max_items?` |
| `serial_read` | 读取串口日志，**支持增量**：把上次返回的 `next_seq` 当 `since` 传入即只取新行，配合 `rt_kprintf`/ULOG 做迭代调试；返回 `items`/`lines`/`dropped`/`partial`（未满一行的半行） | `max_items?`、`clear?`、`since?` |
| `serial_monitor_status` | 串口监听状态（`state`/`bytes_total`/`lines`/`dropped`/`reopen_count`/`last_error`、是否**仍占着口** `port_held`、端口是否**真正打开** `port_ready`、`auto_released`/`release_reason`/`idle_s`、能否下发 `can_write`）+ 本机全部可用串口；**未监听时不报错**（`running=false`），适合先探再启 | — |
| `serial_monitor_stop` | 停止监听并**释放串口**（不释放的话 Keil 串口窗口/其他工具会打不开，报 WinError=5）。**默认保留已收日志**（`clear_buffer=true` 才清空），释放后 `serial_read` 仍可读、重新 start 复用同一实例；正常情况下不必手工调它——调试/烧录/关 Keil 都会自动释放；未监听时也返回 `ok=true` | `clear_buffer?` |
| `list_uvoptx_breakpoints` | 读取持久化断点(.uvoptx) | `project?` |
| `clear_uvoptx_breakpoints` | 清除持久化断点(.uvoptx) | `project?`、`backup?` |
| `clear_all_breakpoints` | 清除全部软件断点；`hard=true` 用 `BK *` 一次性清空 Keil 侧全部断点（含 .uvoptx 持久化断点），附 `real_after` 复核 | `include_uvoptx?`、`hard?` |
| `clear_all_watchpoints` | 清除全部数据断点（按真实编号逐个清）；`hard=true` 用 `BK *` 清空 | `hard?` |
| `set_symbol_file` | 设置/切换当前调试符号文件 | `path` |
| `list_symbol_projects` | 列出预登记候选符号工程 | — |
| `set_reloc_delta` | 设置 App 侧重定位偏移（运行地址 = 链接地址 + delta，如 SVCrtOS 的 `0xF000`）：设一次全局生效，`read_variable` / `read_mem` / `find_symbol` / `wait_breakpoint` 会按符号名自动换算；**只偏移符号名，显式数字地址不偏移** | `delta`（`0x` 或十进制，可负，`0x0` 清除） |
| `list_tools` | 列出全部工具的名称/用途/**必填参数**/别名与最小调用示例（`example_args` 可直接照抄成 args），`keyword` 按工具名或用途过滤——AI 冷启动不必再靠 `Field required` 报错试错 | `keyword?` |
| `wait_breakpoint` | 带超时等待断点命中（symbol/address 或 .uvoptx 持久化断点），命中即回源码位置并计数；支持**数据观察点命中判定**（返回 `hit_kind` = code/watch、`hit_entry` 命中断点项与来源、`cnt_note` 判定依据强度）；**只认等待期间新发生的停止**（调用时目标已停着则 `hit=false`、`stop_is_new=false`、`new_stop_basis=not_new`，`note` 说明「目标在等待期间未曾运行」）；未命中时给 `note` 说明 PC 与候选地址并提示下一步 | `symbol?`、`address?`、`timeout_s?`、`poll_ms?`、`use_project_breakpoints?`、`project?`、`reloc_delta?` |
| `breakpoint_stats` | 断点命中统计 | — |
| `keil_health` | Keil 调试通道健康自检（UV4 进程 / UVSOCK 端口 / 模态框），Keil 未运行也能返回；检测到模态框时给出**正文（`message`）与可点按钮（`button_texts`）** | — |
| `dismiss_dialog` | 读取并关闭阻塞 Keil 的模态对话框：读出框内正文与全部按钮，按 `button` 点关（省略则按 确定/OK/是/关闭 自动挑，无按钮退化 WM_CLOSE）；命令不返回且 `keil_health` 报 `modal_blocked_suspected` 时用它自愈 | `button?`、`title?`、`index?` |
| `reset_connection` | 只重置 UVSOCK 连接（不重启 Keil）：丢弃 socket 与残留缓冲，下次调用自动重连 | `reason?` |
| `restart_keil` | 一键重启 Keil：关全部实例 → 脱离父进程重启 → 等 UVSOCK 就绪 → 重连 | `project?`、`force?`、`wait_ready?` |

> 编译烧录工具均以**隐藏窗口**后台执行，不闪现 Keil 界面；`launch_uvision` 则以**可见**方式打开 Keil 供调试查看。

> 编译烧录 / Keil 启动工具的 `project` 均可省略：省略时使用启动参数 `--default-project` 指定的默认工程。

### 参数约定（别名 / 类型宽容 / 单位换算）

工具签名面向「AI 直接写」设计，参数名与类型都做了容忍，不必靠报错反推签名：

- **名称列表参数**（`globals`、`regs`、`fields`、`expressions`、`addresses`、`commands`…）
  同时接受数组、JSON 数组字符串、以及逗号 / 分号 / 竖线 / 空格分隔的字符串，
  例如 `regs: ["MODER","ODR"]` 与 `regs: "MODER,ODR"` 等价；
- **地址类参数**（`addr`/`address`/`start`/`end`/`expr`/`target`…）
  同时接受整数（`0x20000000`）、`"0x…"`、十进制串与符号名，
  `read_mem(addr=0x20000000, n_bytes=8)` 可直接写；
- **参数别名**：主名保持不变（不破坏已有调用与文档），但每个工具额外接受一组统一别名
  （如 `expr ← expression/var/variable`、`addr ← address/location`、`query ← keyword/name`）。
  `list_tools` 的描述里会附一段【参数别名】，并写明**规范名以上方【参数】行为准、未列出的
  参数名会被拒绝**——别名是兼容写法，不是「参数名随便写都行」的许可证；
- **时间参数单位换算**：时间参数按族展开，`timeout` / `duration` / `max` / `wait` 属同一族，
  族内「任意前缀 × 任意写法（无后缀 / `_ms` / `_s`）」都能落地：
  `run_timeout(duration_s=2)` ≡ `run_timeout(timeout_ms=2000)`。
  单位以**别名自带的后缀**为准（`_s` = 秒、`_ms` = 毫秒）；不带后缀时按主名单位解释，
  所以 `list_tools` 会把主名单位标出来（如 `timeout_ms（毫秒）`）；
  `interval_` / `poll_` 自成一族（采样间隔），刻意不与超时族互通，避免静默改变行为；
- **未知参数显式拒绝**：框架默认静默忽略未知参数，打错键名会悄悄拿到默认值。本服务改为直接报错，
  并在消息里列出该工具接受的参数与可用别名（`_` 前缀的元参数除外）；
- **别名不遮蔽真实参数，且主名优先**：与某工具真实参数同名的别名会被剔除（如 `read_mem` 真有
  `length` 就不再拿它当 `n_bytes` 的别名）；主名与别名同时出现时只认主名。

## 接入 AI 工具客户端

以支持 MCP 的客户端为例，在 MCP 配置中加入该服务：

```json
{
  "mcpServers": {
    "mdkdebug": {
      "command": "python",
      "args": ["D:/工作/git_project/mdk_agent/run_server.py", "--idle-timeout", "30"]
    }
  }
}
```

> 请将示例中的绝对路径替换为你的工程实际路径。
#### 注入自定义符号工程

可切换的符号工程（供 `list_symbol_projects` 列表、配合 `set_symbol_file` 切换）默认仅含仓库内置的
`mdk_test`（路径相对仓库根自动推导，`clone` 后编译出 `.axf` 即自动可用，不写死本机绝对路径）。
本机或仓库外工程的符号文件**无需改代码**，用以下任一方式追加注入：

- **启动参数**（可多次指定）：
  `--symbol-project 名字:.axf路径:.map路径:flash起始16进制:flash大小16进制`
- **环境变量** `MDKDEBUG_SYMBOL_PROJECTS`（JSON 数组，`flash_start`/`flash_size` 为十进制整数）：
  ```json
  [{"name":"myproj","axf":"D:/board/out.axf","map":"D:/board/out.map","flash_start":134217728,"flash_size":1048576}]
  ```

示例（同时保留内置 mdk_test，并追加一个本机工程）：

```bash
python run_server.py --symbol-project myboard:D:/board/out.axf:D:/board/out.map:0x08000000:0x100000
```

## 对接真实 Keil

> ⚠️ **必须先开启 UVSOCK，否则无法在线调试**
>
> 本工具的所有调试能力（读变量 / 表达式、读写内存、断点、进出 debug、运行控制）**全部依赖** Keil 的
> **UVSOCK 服务**（默认监听 `127.0.0.1:4823`）。**不开 UVSOCK = 无法调试**，连读一个变量都会失败。
>
> 开启方法（Keil uVision5）：菜单 `Edit → Configuration...` → 切到 **Other** 选项卡 → 勾选 **UVSOCK Enabled**
> → 确认端口为 **4823** → 点 OK → **重启 Keil** 使设置生效。
>
> 若未开启 UVSOCK，调用调试工具会直接返回上述开启指引（提示你如何打开），不会静默失败或抛无意义的报错。

1. 在 Keil uVision 中开启 **UVSOCK**：菜单 `Edit → Configuration...`，切到 **Other** 选项卡，
   勾选 **UVSOCK Enabled**，确认端口为 **4823**，点 OK 后**重启 Keil** 使设置生效；
   之后它会在 `127.0.0.1:4823` 监听（供本服务连接调试）。若未开启，连接类工具会返回开启指引；
2. 进入调试会话后，启动本 MCP Server，即可由 AI 调用上述工具进行在线调试；
3. `calc_expression` 可直接使用工程内变量名；读写内存地址按目标映射（如 `0x20000000` 为 SRAM）；
4. 断点 / 进出 debug 的命令与语义如下：
   - 断点：`set_breakpoint`（`BS`）、`clear_breakpoint`（`BK`）、`list_breakpoints`（`BL`）——经 `UV_DBG_EXEC_CMD` 下发；
   - 进出：`enter_debug` / `exit_debug`——走 `UV_DBG_ENTER` / `UV_DBG_EXIT`。

## 使用示例（完整调试闭环）

假设目标停在调试入口，向 AI 工具发起如下调用序列，即可完成一次"设断点 → 运行到断点 → 读变量 → 退出"：

```
1. enter_debug            # 自动进入调试模式
2. set_breakpoint(main)   # 在 main 设断点
3. run                    # 全速运行，命中 main 断点后停止
4. calc_expression(SData_UA)   # 读取变量值
5. stop                   # 暂停
6. exit_debug             # 退出调试模式
```

> `example_mdk_project/mdk_test` 为随附的 STM32F4 HAL 例程（main 中 while(1) 翻转 GPIOC PIN13），
> 供真机验证与入门参考，随项目一并开源。

### 编译 → 烧录 → 调试 完整闭环

AI 修改代码后，可按如下顺序实现"自己编译、自己烧录、自己验证"的全流程闭环：

```
1. build_and_flash(project="")   # 先编译，成功后自动烧录到目标 Flash
   # 或拆开：build_project → flash_download
2. enter_debug                    # 自动进入调试模式
3. set_breakpoint(main)           # 在入口设断点
4. run                            # 全速运行到断点
5. calc_expression(...)           # 读取变量验证改动是否生效
6. exit_debug                     # 退出调试模式
```

> 注：`build_and_flash` 返回结构含 `build` 与 `flash` 两个子结果；仅当编译退出码为 0/1（无致命错误）才执行烧录，否则跳过烧录并报错。

## 测试

无需真实 Keil，使用 `tests/mock_uvsock_server.py` 模拟调试器：

```bash
python tests/test_e2e.py     # UVClient 协议闭环（25 项）
python tests/test_mcp.py     # MCP Server 工具注册与调用（19 项）
python tests/test_stdio.py   # stdio 全链路客户端握手（7 项）
```

单独启动模拟调试器供人工联调：

```bash
python -m tests.mock_uvsock_server --port 4823
```

## 可靠性约定（读前必看）

调试工具最贵的一类错误是「**用不可信的数据下了结论**」——读到整帧 0 就说变量被清零、
看到 `UsageFault` 位就说刚才跑飞了、`stop` 回 ok 就当目标已经停下来。以下约定直接决定
「什么结果算数」，细节、真机实测数据与踩坑过程见 [**docs/PITFALLS.md**](./docs/PITFALLS.md)。

| 场景 | 约定 | 看到什么不要当真 |
|------|------|------------------|
| 读内存 | `read_mem` 默认带脏读防护（`verify=auto`）：首帧整帧退化、或距最近一次 `stop` 不足 1 秒时自动复读，**连续两次一致才采纳**，并回报 `read_confidence` / `reread_count` / `degenerate` / `since_stop_s`；首帧是脏值时用 `first_read_hex` 留证 | `read_confidence=low` 或带 `degenerate` 的结果；Flash 区稳定全 `0xFF` 是**已擦除的预期内容**（`content_note`），不是脏读 |
| 停目标 | `stop` 默认轮询确证，返回 `stopped` / `stop_verified` / `waited_ms` / `state_after_stop` | `stop_verified=false` 时别读内存/寄存器，也别据其下结论 |
| 看故障 | `CFSR`/`HFSR` 是粘滞位，`fault_report` 用 `fault_timing.timeliness` 区分 `current`（正在 fault handler 里）/ `sticky`（历史残位）/ `none` | `timeliness=sticky` 时别当当前故障处理。确证新异常：`clear_faults()` → `run()` → `fault_report()` |
| 并发调用 | 所有 UVSOCK 命令经统一闸门串行化（进程内 `RLock` + 跨进程锁文件），多实例竞争会在 `keil_health` / `get_status` 里报出来 | 同一台调试器上跑多个 MCP 实例时，写入可能被静默覆盖；需要严格顺序的多步写入请用 `batch` 一次提交 |
| 串口占用 | 调试结束 / 烧录 / 关 Keil 时自动释放端口（**释放只还口、日志保留**），另有空闲超时与进程退出兜底 | 同一个串口别被两处同时打开（本服务 + Keil 串口窗口会互相抢占，`WinError=5`） |

**串口可收也可发**：端口按可读可写打开，收与发共用同一句柄；拿不到写权限时退回只读并置
`can_write=false`。`serial_monitor_start` 会**等端口就绪再返回**，其 `port_ready` / `can_write`
可直接采信。

```text
serial_monitor_start(port="COM9", baud=115200)   # 持有端口
serial_write(text="help")                        # 下发命令（默认追加 CRLF），并带回新增回显
serial_write(hex="7e 01 00 ff", eol="none")      # 二进制 / 镜像片段
serial_read(since=上次 next_seq)                  # 长响应继续增量取
exit_debug()                                     # 调试结束 → 自动还口，日志仍保留
```
## 设计要点

- **连接缓存**：常驻服务内共享一条 TCP 连接，`idle_timeout` 空闲自动断开、下次调用自动重连，兼顾实时性与资源释放；
- **可靠性优先**：不可信的数据不参与结论（脏读防护 / 停止确证 / 粘滞位时效）、并发调用统一串行化、串口用完就还——速查见上节「可靠性约定」，实测数据与踩坑过程见 [docs/PITFALLS.md](./docs/PITFALLS.md)；
- **内存读写分块**：超过单次上限（16 KB）自动分块读，规避 Keil 协议长度限制；
- **地址解析**：工具层统一支持 `0x` / `0b` / `0o` 前缀或纯十进制；
- **编译烧录选型**：采用 Keil 官方 `UV4.exe` 命令行（`-b`/`-r`/`-f`/`-o`），退出码 0=成功、1=成功有警告、2=有错误、≥3=不完整；编译输出经 `-o` 重定向到临时日志文件捕获；`build_and_flash` 在编译成功后自动接烧录，形成闭环；
- **窗口策略**：编译 / 烧录用 `STARTUPINFO(SW_HIDE)` 隐藏新进程窗口（不闪现），`launch_uvision` 用可见方式打开 Keil 供调试（已有同工程实例则复用前景化，不新开窗口）；隐藏的是本次新建的 UV4 进程，不影响用户已打开实例；
- **UV4 与 UVSOCK 共存**：编译烧录与在线调试共用同一 Keil 实例；建议先 `build_and_flash`（此时 Keil 处于非调试态）再 `enter_debug` 进入调试，避免调试态下编译冲突。

## 已知限制

- `list_breakpoints` 的 `real` 字段解析自 Keil 命令窗口 `BL` 的输出文本，格式可能随 Keil 版本变化；
  解析不到时会退化为内部记录并在 `note` 中说明（不影响断点本身的设置与清除）；
- 断点管理依赖 Keil 命令窗口命令语义，仅适用于 Keil 支持的表达式 / 地址；
- UV4.exe **不是**单实例程序：早期版本误以为同工程会复用，实际每次可见启动都会新开窗口
  （真机曾累积 6 个同工程实例）。现已改为默认复用已有窗口，并提供实例清点与收敛工具；
  同工程窗口的识别依据是主窗口标题里的工程全路径，若 Keil 改版改变标题格式会退化识别为
  「不同工程」（此时 `close_uvision(keep=...)` 仍可用，只是 `project` 过滤可能不命中）；
- `enter_debug` 受工程 `Load` / `Flash Download` / `Run-to-main` 设置影响，属有副作用的操作。

## 许可证

本项目采用 **MIT License**。完整许可证正文见 [LICENSE](./LICENSE)。

```text
MIT License
Copyright (c) 2026 <春雫>
```


## 参考与致谢

- [KeilAssistant](https://gitee.com/keyoushide/keil-assistant)：UVSOCK/TCP 协议参考实现
- [debug-keil-uvsc](https://github.com/)：uvsc DLL 封装，提供完整 `EXECCMD` / `SSTR` 结构定义与命令窗口断点语义
