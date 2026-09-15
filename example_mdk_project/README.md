# mdk_test —— mdkdebug 一键验证示例工程

> 一个可直接编译、烧录、调试的 STM32 最小示例工程，用于快速验证 mdkdebug 是否在你的板子上跑通。

- **芯片**：STM32F401RCTx（`MDK-ARM/mdk_test.uvprojx`）
- **行为**：`main()` 里 `while(1)` 每 500ms 翻转 GPIOC PIN13（板载 LED 闪烁）
- **演示变量**：`main.c` 中 `volatile uint32_t test_array[8] = {0x11111111..0x88888888}`，
  供 `read_variable` / `read_mem` / `snapshot` 等工具读数组演示

## 一键验证（三步）

先确认：Keil uVision 已开启 UVSOCK（`Edit → Configuration... → Other → 勾选 UVSOCK Enabled → 端口 4823 → 重启 Keil`），并用 ST-Link/J-Link 连接板子。

```bat
:: 0) 安装本仓库（根目录）
pip install -e .

:: 1) 起服务（常驻；--default-project 指定本示例工程）
mdkdebug --default-project example_mdk_project/mdk_test/MDK-ARM/mdk_test.uvprojx
```

> 服务命令是**常驻**的：它一边监听 MCP 客户端（stdio/http），一边用 UV4 命令行完成编译、烧录、进调试。
> 也可以不启服务、仅编烧：

```bat
:: 只编烧（UV4 -b 成功后 -f），再用任意 AI 工具接服务进调试
python -m mdkdebug.cli --default-project example_mdk_project/mdk_test/MDK-ARM/mdk_test.uvprojx
```

## 验证什么

进入调试后，可依次验证 mdkdebug 的核心能力：

| 验证点 | 工具 | 预期 |
|--------|------|------|
| 状态 | `get_status` | `debugging:true`、目标停止 |
| 读全局变量 | `read_variable(test_array)` | 8 元素 `0x11111111..0x88888888` |
| 读内存 | `read_mem(0x20000000)` | 命中 SRAM 内容 |
| 定位停靠点 | `get_current_location` | PC → `main.c:101` + 源码上下文 |
| 单步 | `step` | 停靠行推进，附源码上下文 |
| 读寄存器 | `read_registers` | R0-R12/SP/LR/PC/xPSR + AAPCS 解读 |
| 反汇编 | `disassemble` | PC 处 Thumb 指令 |
| 周期计数 | `dwt` | 返回 CYCCNT 与估算秒数 |
| 外设 | `read_peripheral(GPIOC)` | GPIO 模式/ODR 解析 |
| 一键诊断 | `diagnose` | 聚合现场报告 |

## 版本

对应 mdkdebug `0.2.0`。
