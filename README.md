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
- **断点管理**：设 / 删 / 列断点，基于 Keil 命令窗口命令（`BS` / `BK` / `BL`）；
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
- **AI 管理 Keil 开关（闭环）**：`launch_uvision` 拉起 Keil 打开工程（复用已有实例），`close_uvision` 关闭 Keil（默认优雅关闭、残留自动强制），Keil 的开启/关闭全部由 AI 闭环管理，无需手动操作；
- **规避旧窗口调试旧代码**：`flash_debug` 自动按「关闭所有 Keil → 编译并烧录新固件 → 重新打开本工程 → 进入调试」顺序执行，避免因残留旧工程窗口导致调试到旧代码（即使 AI 不记得先关旧窗口也能保证加载的是新固件符号）；
- **编译烧录输出集中返回**：每次编译/烧录的完整日志（含警告/错误）经 `-o` 捕获并由 AI 完整返回，在对话中即可查看，无需盯 Keil 窗口；
- **UV4 自动探测**：优先显式 `--uv4-path`，其次探测常见安装目录，再查 Windows 注册表；
- **连接缓存**：常驻服务内共享一条 TCP 连接，空闲自动断开、下次调用自动重连；
- **线程安全**：连接状态以锁保护，可被 MCP 并发调用；
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
│   ├── __init__.py           # 包初始化（版本号 0.2.0）
│   ├── cli.py                # 命令行入口（main，mdkdebug 命令）
│   ├── uvsock.py             # UVSOCK 协议：命令码、VSET/AMEM/EXECCMD 打包与解析
│   ├── interface.py          # TCP 物理接口层（含异步消息残留清理）
│   ├── client.py             # UVClient：调试能力封装 + 连接缓存
│   ├── builder.py            # UV4 命令行：编译 / 重编译 / 烧录 / 编译烧录闭环
│   ├── locator.py             # 基于 .axf DWARF 的符号定位（地址↔文件:行 双向 + 源码读取）
│   ├── periph.py             # 内置 STM32F4 常用外设寄存器表（RCC/GPIO/USART/SPI/I2C/TIM/...）+ 内存区域地图
│   ├── mapfile.py            # .map 链接映射文件解析（Program Size/sections/symbols/栈使用/未用段）
│   └── server.py             # MCP Server 与 73 个工具定义
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

共 **73** 个（调试读写 / 断点与命中等待 / 外设与内存 / 符号定位 / 工程分析 / 编译烧录 / Keil 生命周期管理 / 环境自检引导）：

| 工具 | 说明 | 主要参数 |
|------|------|----------|
| `get_version` | 查询 UVSOCK 插件版本 | — |
| `get_status` | 查询是否处于调试、目标是否运行、状态码 | — |
| `calc_expression` | 计算并读取表达式 / 变量值 | `expr` |
| `read_variable` | 按变量名查地址/值/大小，支持数组逐元素与整块内存 | `name`、`count` |
| `read_mem` | 读取目标内存 | `addr`（`0x…` 或十进制）、`n_bytes` |
| `write_mem` | 写入目标内存 | `addr`、`data_hex`（十六进制串，可带空格） |
| `run` | 全速运行 | — |
| `run_timeout` | 全速运行 N 毫秒后自动暂停并返回停靠位置，用于验证时序 | `timeout_ms`（默认 1000） |
| `stop` | 暂停执行 | — |
| `reset` | 复位目标 | — |
| `step` | 单步执行，成功后自动附带停靠位置（`stopped_file`/`stopped_line`/`stopped_address`）+ 源码上下文 + 调用栈 | `mode`：`into`/`over`/`out`/`instruction` |
| `run_to_line` | 运行到指定行（run to cursor），接受 `文件:行号` 或 `0x地址` | `target`（如 `main.c:77`） |
| `get_current_location` | 读取当前 PC，定位到 文件:行号 + 源码上下文 + 完整调用栈回溯 + 源码漂移提示 + 断点命中反馈 | — |
| `read_locals` | 读取当前函数 参数+局部变量 及其值（DWARF 解析变量名，`calc_expression` 在当前上下文求值） | — |
| `snapshot` | 状态快照：位置（文件行+PC）+ 源码上下文 + 完整调用栈 + 局部变量 + 指定全局变量，一站式看清当前运行状态 | `globals`、`source_context` |
| `watch` | 变量组：批量读取多个表达式/变量的当前值，便于固定观察一组信号 | `exprs` |
| `read_struct` | 结构体字段概览：基于 DWARF 解析字段布局（类型/偏移/大小），并用基址+偏移读各字段运行时值 | `name`、`max_fields` |
| `set_watchpoint` | 数据断点：在变量/地址处设 读/写/读写 访问断点，命中即暂停（`BS READ/WRITE/READWRITE`） | `expr`、`access`、`count` |
| `clear_watchpoint` | 清除数据断点 | `expr` |
| `list_watchpoints` | 列出当前数据断点（含地址、访问类型、位置） | — |
| `read_registers` | 批量读取 CPU 核心寄存器 R0-R12/SP/LR/PC/xPSR 及当前值，并按 AAPCS 解读 R0-R3 入参、R0 返回值、LR 返回地址，排查参数/返回值/寄存器被踩 | — |
| `disassemble` | capstone 反汇编目标代码：地址 `0x…` / 符号名 / 文件:行 / 缺省当前 PC，排查死循环、跑飞、启动流程、优化行为 | `addr`、`count`（默认 8） |
| `diagnose` | 一键诊断：聚合寄存器组(含 AAPCS) + PC 处反汇编 + 源码上下文 + 完整调用栈 + 局部变量 + 指定全局变量，一次调用看清现场 | `globals`、`disasm_count`、`source_context` |
| `find_symbol` | 符号检索：从 .axf ELF 符号表模糊检索函数/全局变量（返回名字/类型/地址/大小），AI 读符号不再靠猜名字 | `query`、`kind`（all/func/object/global/local）、`limit` |
| `set_register` | 写寄存器/改 PC：向 R0-R12/SP/LR/PC/xPSR 写值并读回验证，可修正现场、改返回值、改 PC 跳转执行 | `register`、`value` |
| `dwt` | DWT 周期计数器：读 CYCCNT（自动使能），配合两次采样算代码段执行周期数与耗时 | — |
| `fault_report` | HardFault/异常定位：读 SCB（ICSR/HFSR/CFSR/MMFAR/BFAR）判异常类型+原因，从异常栈帧恢复 PC/LR/R0-R3/xPSR，排查死机/跑飞 | — |
| `set_conditional_breakpoint` | 条件断点：仅在 condition（C 表达式如 R0==5）成立/第 count 次命中时才停，减少无关中断 | `expr`、`condition`、`count` |
| `read_peripheral` | 外设寄存器一键读：内置 STM32F4 外设表（RCC/GPIO/USART/SPI/I2C/TIM/...），读指定外设全部寄存器并解析关键位域（时钟使能/波特率/GPIO 模式/定时器计数），排查时钟没使能/配置错 | `periph` |
| `list_peripherals` | 列出内置外设寄存器表（外设名+基址+说明） | — |
| `itm_trace` | ITM/Debug(printf) Viewer trace：检查 Trace 配置(DEMCR/ITM->TCR/TER)是否就绪 + 拉取串口窗口缓冲中的 ITM 打印文本 | `port`、`size` |
| `query_memory_map` | 内存区域地图：FLASH/SRAM/外设/ITM/DWT/SCS 地址范围，可标注某地址落在哪个区域，防止把外设区当 RAM 读 | `addr`（可选） |
| `search_mem` | 在内存范围内扫描字节序列，返回所有命中地址（分块读、块间重叠防跨块漏匹配），找魔数 / 定位被越界写坏的缓冲 | `start`、`end`、`pattern_hex` |
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
| `read_project_config` | 读取工程配置：各 target 编译器（AC5/AC6）、优化级别（-O0~-Otime）、编译宏 Define、包含路径（.uvprojx 解析） | `project`、`target`（可选） |
| `target_info` | 查询目标器件信息：实时读 DBGMCU->IDCODE 判 DEV_ID/REV_ID 映射型号 + SCB->CPUID 判内核 + 标称 Flash/RAM 容量与内存布局，排查资源吃紧/选错型号/容量不符 | — |
| `profile_sampling` | 采样剖析定位热点：让目标运行，周期性暂停采 PC 归到函数统计占比（run/stop 采样，非硬件 ETM，会轻微扰动时序），找哪个函数占 CPU 最多 | `duration_ms`、`interval_ms`、`max_samples` |
| `mdk_guide` | 环境自检+工作流引导：一键自检 Keil/UVSOCK/UV4/.axf/源码漂移/调试态/RTOS 类型，返回推荐调试工作流与各场景应调用的工具，AI 落地第一件事先调它 | — |
| `enter_debug` | 自动进入 Keil 调试模式 | — |
| `exit_debug` | 自动退出 Keil 调试模式 | — |
| `set_breakpoint` | 在符号 / 地址处设软件断点 | `expr`（如 `main`、`0x08001034`） |
| `clear_breakpoint` | 清除断点（符号名或断点编号） | `expr` |
| `list_breakpoints` | 列出断点（含对应的 文件:行号 位置） | — |
| `launch_uvision` | 可见方式拉起 Keil 打开工程，复用已有实例 | `project` |
| `close_uvision` | 关闭所有 Keil 实例（默认优雅，残留强制） | `force` |
| `build_project` | 编译工程（`UV4 -b`，后台隐藏窗口） | `project`、`target` |
| `rebuild_project` | 全量重编译（`UV4 -r`） | `project`、`target` |
| `flash_download` | 烧录到目标 Flash（`UV4 -f`） | `project`、`target` |
| `build_and_flash` | 编译成功后才烧录，AI 全流程闭环 | `project`、`target` |
| `flash_debug` | 「关旧 Keil→编烧→开新→进调试」一体闭环，规避旧窗口调试旧代码 | `project`、`target` |

| `read_console_output` | 读取命令窗口输出 | clear? |
| `read_async_messages` | 读取异步消息/报错 | clear? |
| `list_uvoptx_breakpoints` | 读取持久化断点(.uvoptx) | project? |
| `clear_uvoptx_breakpoints` | 清除持久化断点(.uvoptx) | project?、backup? |
| `clear_all_breakpoints` | 清除全部软件断点 | include_uvoptx? |
| `clear_all_watchpoints` | 清除全部数据断点 | — |
| `set_symbol_file` | 设置/切换当前调试符号文件 | path |
| `list_symbol_projects` | 列出预登记候选符号工程 | — |
| `wait_breakpoint` | 带超时等待断点命中（symbol/address 或 .uvoptx 持久化断点），命中即回源码位置并计数 | symbol?、address?、timeout_s?、poll_ms?、use_project_breakpoints?、project? |
| `breakpoint_stats` | 断点命中统计 | — |
| `keil_health` | Keil 调试通道健康自检（UV4 进程 / UVSOCK 端口 / 模态框），Keil 未运行也能返回 | — |
| `reset_connection` | 只重置 UVSOCK 连接（不重启 Keil）：丢弃 socket 与残留缓冲，下次调用自动重连 | reason? |
| `restart_keil` | 一键重启 Keil：关全部实例 → 脱离父进程重启 → 等 UVSOCK 就绪 → 重连 | project?、force?、wait_ready? |

> 编译烧录工具均以**隐藏窗口**后台执行，不闪现 Keil 界面；`launch_uvision` 则以**可见**方式打开 Keil 供调试查看。

> 编译烧录 / Keil 启动工具的 `project` 均可省略：省略时使用启动参数 `--default-project` 指定的默认工程。

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

### 真实 Keil 实测要点（已用 STM32F4 例程验证）

- **`EXEC_CMD` 的 data 必须是完整 EXECCMD 结构（292 字节）**，而非简化的 `nLen + 命令`：
  `flags(4) + reserved[7](28) + SSTR{nLen(4) + char[256]}`。若只发 `nLen + 命令`，Keil 会从错误
  偏移解析导致命令**静默失败**——TCP 层仍返回 `status=0`（请求被接受），但界面不会出现断点。
  **`status=0` 不代表命令真正执行。** 修正为完整结构后，`BS main` 在真实 Keil 界面正确出现断点标记。
- `UV_DBG_EXIT` 在目标处于运行状态时会被拒绝（返回"目标正在运行"，`status=11`），需先 `stop` 再 `exit_debug`；
- `EXEC_CMD` 响应**不回传命令输出**：真实 Keil 对 `BL` 的响应 `data` 为空，拿不到断点列表文本
  （模拟调试器 mock 才会返回 `output`）。因此 `list_breakpoints` 在真实环境拿不到列表，`ok=true` 仅表示命令被接受；
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
- **已用 STM32F4 例程完成 20+ 个工具端到端全功能真机测试**：版本/状态、表达式、内存读写、
  运行控制（run/stop/reset/step/run_timeout/run_to_line）、断点管理（set/clear/list）、进出调试、
  状态快照（`snapshot`）、变量组（`watch`）、结构体字段概览（`read_struct`）、数据断点
  （`set_watchpoint` 读触发暂停）、局部变量读取（`read_locals`）、寄存器组（`read_registers`）、
  反汇编（`disassemble`，地址与符号名两种路径）、一键诊断（`diagnose`）等全部通过。
  > 说明：`read_struct` 对**局部**结构体的字段值读取依赖正确停靠帧（reset 后首次进入函数内部）；
  > 全局符号 / 正确停靠下的结构体则稳定返回布局与运行时值。

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

## 设计要点

- **连接缓存**：常驻服务内共享一条 TCP 连接，`idle_timeout` 空闲自动断开、下次调用自动重连，兼顾实时性与资源释放；
- **线程安全**：连接状态以锁保护，可被 MCP 并发调用；
- **内存读写分块**：超过单次上限（16 KB）自动分块读，规避 Keil 协议长度限制；
- **地址解析**：工具层统一支持 `0x` / `0b` / `0o` 前缀或纯十进制；
- **编译烧录选型**：采用 Keil 官方 `UV4.exe` 命令行（`-b`/`-r`/`-f`/`-o`），退出码 0=成功、1=成功有警告、2=有错误、≥3=不完整；编译输出经 `-o` 重定向到临时日志文件捕获；`build_and_flash` 在编译成功后自动接烧录，形成闭环；
- **窗口策略**：编译 / 烧录用 `STARTUPINFO(SW_HIDE)` 隐藏新进程窗口（不闪现），`launch_uvision` 用可见方式打开 Keil 供调试；隐藏的是本次新建的 UV4 进程，不影响用户已打开实例；
- **UV4 与 UVSOCK 共存**：编译烧录与在线调试共用同一 Keil 实例；建议先 `build_and_flash`（此时 Keil 处于非调试态）再 `enter_debug` 进入调试，避免调试态下编译冲突。

## 已知限制

- `list_breakpoints` 在真实 Keil 下无法通过 `BL` 回传断点列表（协议层不回传命令输出）；
- 断点管理依赖 Keil 命令窗口命令语义，仅适用于 Keil 支持的表达式 / 地址；
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
