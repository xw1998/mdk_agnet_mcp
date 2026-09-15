# Mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务

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
- **运行控制**：全速运行、暂停、复位、单步（`into` / `over` / `out` / `instruction`）；
- **断点管理**：设 / 删 / 列断点，基于 Keil 命令窗口命令（`BS` / `BK` / `BL`）；
- **自动进出调试模式**：`enter_debug` / `exit_debug`，支持 AI 驱动"进入 → 设断点 → 运行到断点 → 读变量 → 退出"完整闭环；
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

### Python 组件依赖

见 `requirements.txt`，核心依赖：

| 包 | 版本 | 作用 |
|----|------|------|
| `mcp` | ≥ 2.0（验证于 2.2.0） | MCP Server 框架（`MCPServer`） |
| `pydantic` | ≥ 2.8（验证于 2.13.5） | MCP 依赖的类型模型 |

安装：

```bash
pip install -r requirements.txt
```

> 注：`mcp 2.x` 中 `FastMCP` 已改名为 `MCPServer`（`from mcp.server.mcpserver import MCPServer`），
> 工具通过 `@server.tool()` + 类型注解注册。

## 目录结构

```
mdk_agent/
├── run_server.py             # MCP Server 启动入口（stdio / http）
├── requirements.txt          # Python 依赖
├── README.md
├── mdkdebug/
│   ├── __init__.py           # 包初始化（版本号 0.1.0）
│   ├── uvsock.py             # UVSOCK 协议：命令码、VSET/AMEM/EXECCMD 打包与解析
│   ├── interface.py          # TCP 物理接口层（含异步消息残留清理）
│   ├── client.py             # UVClient：调试能力封装 + 连接缓存
│   └── server.py             # MCP Server 与 14 个工具定义
├── tests/
│   ├── mock_uvsock_server.py # 模拟 Keil 调试器的 UVSOCK 服务器（离线联调）
│   ├── test_e2e.py           # UVClient 协议闭环测试
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

## 暴露的 MCP 工具

共 **14** 个：

| 工具 | 说明 | 主要参数 |
|------|------|----------|
| `get_version` | 查询 UVSOCK 插件版本 | — |
| `get_status` | 查询是否处于调试、目标是否运行、状态码 | — |
| `calc_expression` | 计算并读取表达式 / 变量值 | `expr` |
| `read_mem` | 读取目标内存 | `addr`（`0x…` 或十进制）、`n_bytes` |
| `write_mem` | 写入目标内存 | `addr`、`data_hex`（十六进制串，可带空格） |
| `run` | 全速运行 | — |
| `stop` | 暂停执行 | — |
| `reset` | 复位目标 | — |
| `step` | 单步执行 | `mode`：`into`/`over`/`out`/`instruction` |
| `enter_debug` | 自动进入 Keil 调试模式 | — |
| `exit_debug` | 自动退出 Keil 调试模式 | — |
| `set_breakpoint` | 在符号 / 地址处设软件断点 | `expr`（如 `main`、`0x08001034`） |
| `clear_breakpoint` | 清除断点（符号名或断点编号） | `expr` |
| `list_breakpoints` | 列出当前断点 | — |

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

## 对接真实 Keil

1. 在 Keil uVision 中加载并启动 **UVSOCK** 调试插件（`Tools` 菜单 / 插件管理器），使其在
   `127.0.0.1:4823` 监听（参考 KeilAssistant 的 `setup.ini`）；
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
- 目标运行期间 UVSOCK 会推送异步消息，堆积在 socket 缓冲会导致后续命令读响应错位
  （典型报错"AMEM 响应数据过短"）。本实现已在发送请求前自动清空残留。
- **`UV_DBG_STATUS` 的 r_status（响应码）恒为 0，真实运行状态在响应 `data` 低字节**
  （`data[0]==0` 停止、`data[0]==1` 执行中）。若用 r_status 判断，会在 run 后误报"已停止"、
  退出调试后误报"执行中"（把错误消息 data 首字节 `0x01` 当运行标志）。
  正确做法（见 `mdkdebug/client.py` 的 `get_status`）：仅当 r_status 为成功时才解析 `data[0]`，
  `status=6`（未处于调试）等错误状态优先正确反映。
- **已用 STM32F4 例程完成 14 个工具端到端全功能真机测试**：版本/状态、表达式、内存读写、
  运行控制（run/stop/reset/step）、断点管理（set/clear/list）、进出调试，全部通过。

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
- **地址解析**：工具层统一支持 `0x` / `0b` / `0o` 前缀或纯十进制。

## 已知限制

- `list_breakpoints` 在真实 Keil 下无法通过 `BL` 回传断点列表（协议层不回传命令输出）；
- 断点管理依赖 Keil 命令窗口命令语义，仅适用于 Keil 支持的表达式 / 地址；
- `enter_debug` 受工程 `Load` / `Flash Download` / `Run-to-main` 设置影响，属有副作用的操作。

## 许可证

本项目采用 **MIT License**。完整许可证正文见 [LICENSE](./LICENSE)。

```text
MIT License
Copyright (c) 2026 <Your Name or Organization>
```

> 发布前请将 LICENSE 文件中的 `<Your Name or Organization>` 替换为你的真实姓名 / 组织。

## 参考与致谢

- [KeilAssistant](https://gitee.com/keyoushide/keil-assistant)：UVSOCK/TCP 协议参考实现
- [debug-keil-uvsc](https://github.com/)：uvsc DLL 封装，提供完整 `EXECCMD` / `SSTR` 结构定义与命令窗口断点语义
