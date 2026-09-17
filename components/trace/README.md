# mdk_trace — 目标侧插桩组件

这是 mdkdebug 的**目标侧**配套组件：跑在被调试芯片里，把结构化事件打包后经
SWO / RTT / 串口送到主机，由 `mdkdebug` 的 `trace_*` 系列工具解包。

一句话说明为什么需要它：**SWO 和 RTT 只是通道，芯片不会自己说话**。没有这层
插桩，`trace_swo_*` 拿到的只是一堆无意义的字节。

## 目录内容

| 文件 | 作用 |
|------|------|
| `mdk_trace.h` | 对外 API：初始化、事件、计数器、ISR、scope 宏 |
| `mdk_trace.c` | 时间戳源（DWT / `mcycle`）、MTF 组帧、ITM / RTT / UART 三个后端 |
| `mdk_trace_rtt.h` / `.c` | SEGGER 兼容的 RTT 控制块与环形缓冲 |
| `mdk_trace_config_default.h` | 全部配置项的兜底默认值（每个宏都是 `#ifndef`） |
| `CMakeLists.txt` | CMake 工程，产出一个静态库 `mdk_trace` |

代码注释一律用英文：Keil ARMCC（AC5）在部分设置下会把 UTF-8 中文注释渲染成乱码，
而这个组件是要被丢进别人的工程里编译的。文档用中文。

## 快速上手

最简单的方式是让 mdkdebug 自己装：

```
trace_instrument(target_dir="D:/proj/src/trace", backend="rtt", coreclk=84000000)
```

它会把组件拷过去，并按你的参数生成 `mdk_trace_config.h`（后端、ITM 端口、RTT
通道与缓冲大小、主频）和 `mdk_trace.mk`（Makefile 集成片段）。

不借助工具也可以：把本目录整个拷进工程，自己写一个 `mdk_trace_config.h`，
或直接在编译选项里定义需要的宏。

然后在 `main()` 里：

```c
#include "mdk_trace.h"

int main(void)
{
    board_init();
    mdk_trace_init();          /* 打开后端与时间戳 */

    mdk_trace_text("boot ok");
    for (;;) {
        MDK_TRACE_SCOPE(0x1001);       /* 进/出自动成对发事件 */
        control_loop();
    }
}
```

中断里：

```c
void TIM2_IRQHandler(void)
{
    MDK_TRACE_ISR_ENTER(0x2001);
    ...
    MDK_TRACE_ISR_EXIT(0x2001);
}
```

拿到主机侧：

```
trace_rtt_find(elf="build/app.elf")
trace_rtt_attach(elf="build/app.elf")
trace_rtt_read()          # 结构化事件列表
```

## 硬件接线

- **SWD 通路（RTT / SWD 采样）**：SWCLK、SWDIO、GND、3V3 参考。没别的了，不需要
  SWO 引脚，这是 ESP32 这类芯片的首选。
- **SWO 通路（ITM）**：再加第五根 SWO（Cortex-M 上多半是 PB3 / TDO 复用），且
  调试器得支持 —— DAPLink、J-Link、ST-Link V2-1 支持，廉价 ST-Link 克隆品
  通常没有这个脚。SWO 引脚还要在芯片侧打开：STM32 上由 `DBGMCU_CR` 的
  `TRACE_IOEN` 控制，组件里的 `mdk_trace_init()` 已经做了（见
  `MDK_TRACE_DBGMCU_CR`）。

## 配置项

全部在 `mdk_trace_config_default.h` 里，用 `#ifndef` 守护，所以命令行的
`-D`、Keil 工程的 Define 栏、或生成的 `mdk_trace_config.h` 都能覆盖。

| 宏 | 默认 | 说明 |
|----|------|------|
| `MDK_TRACE_ENABLE` | `1` | 总开关，设 0 则整个组件编成空壳 |
| `MDK_TRACE_BACKEND_ITM` / `_RTT` / `_UART` / `_NONE` | ITM | 选一个后端 |
| `MDK_TRACE_ITM_PORT` | `1` | ITM 激励端口，用 1 可以与 printf 的 0 号端口分开 |
| `MDK_TRACE_RTT_UP_CHANNELS` / `_DOWN_CHANNELS` | 2 / 1 | RTT 通道数 |
| `MDK_TRACE_RTT_BUF_SIZE` | `1024` | 每个通道的环形缓冲字节数 |
| `MDK_TRACE_TEXT_BUF_SIZE` | `128` | 单帧文本上限（必须 ≤ 256） |
| `MDK_TRACE_CPU_HZ` | `0` | 主频，ITM 后端用它算 TPIU 分频；0 = 不碰 TPIU |
| `MDK_TRACE_SWO_BAUD` | `2000000` | SWO 波特率，必须与主机 `tpiu config` 一致 |
| `MDK_TRACE_DBGMCU_CR` | `0xE0042004` | STM32 的 DBGMCU_CR 地址，0 = 不碰 |
| `MDK_TRACE_USE_DWT` | `1` | 用 DWT 周期计数器（RISC-V 上是 `mcycle`）当时间戳 |
| `MDK_TRACE_DWT_EVENTS` | `0` | 打开 DWT 硬件事件计数器（异常/CPI/睡眠/LSU） |
| `MDK_TRACE_DWT_PCSAMPLE` | `0` | 打开 DWT PC 采样（只在停机/单步时出数据） |

## 帧格式（MTF）

```
0xA5 | (version<<4 | type) | len | payload[len] | crc8
```

`crc8` 覆盖 magic 到 payload 末尾，多项式 `0x07`、初值 `0x00`、无反射。
`len` 是一个字节，所以单帧载荷上限 255 字节，超长文本由组件切帧。

**CRC 不是可选项**：SWO 丢包是常态，没有校验位就没法区分「数据被链路截断」和
「本来就是这样」，主机只能给出看似权威的错结论。

`type` 取值与主机侧 `mdkdebug/traceproto.py` 的 `MTF_TYPES` 必须一致：

| type | 名称 | 载荷（小端） |
|------|------|-------------|
| 0 | raw | 原始字节 |
| 1 | text | UTF-8 文本 |
| 2 | event | `id:u16, kind:u8, ts:u32, arg:u32` |
| 3 | counter | `id:u16, value:u32` |
| 4 | isr | `id:u16, kind:u8, ts:u32` |
| 5 | mark | `tag:u32` |
| 6 | ts | `ts:u32` |
| 7 | kv | `key:i16, value:i32` |
| 8 | reset | 原因字符串 |

`kind`：`0=enter`、`1=exit`、`2=point`、`3=abort`。

## 三条通路的取舍

| 通路 | 需要什么 | 带宽 | 代价 |
|------|---------|------|------|
| SWO / ITM | 多一根 SWO 脚 + 支持 SWO 的调试器 | 最高，可带时间戳 | 引脚受限 |
| RTT | 只要能读写 RAM 的调试器 | 高，双向 | 占一块 RAM，主机要不停读 |
| SWD 采样 | 什么都不要 | 低 | **侵入式**：反复停机读 PC，改变被测程序时序 |

SWD 采样由主机侧的 `trace_profile` 实现（不止停读 PC），不需要这个组件；
DWT 周期计数器则被这里用作事件时间戳。

## 两个容易踩的坑

1. **RTT 控制块被链接器回收**。`_SEGGER_RTT` 在 `mdk_trace_rtt.c` 里定义并标了
   `used`，但 `--gc-sections` 加上未引用的段仍可能被丢掉。稳妥做法是在链接脚本里
   `KEEP(*(.bss._SEGGER_RTT))`，或者确认 `mdk_trace_init()` 确实被调用了。
2. **主机读完不推进 `RdOff`**。RTT 上行缓冲满不满，是拿 `WrOff - RdOff` 算的；
   主机读完必须把 `RdOff` 推到 `WrOff`，否则目标会一直认为缓冲是满的并持续丢数据。
   `mdkdebug` 的 `trace_rtt_read` 已经这么做了。目标侧**绝不要**写 `RdOff`——
   那是主机的地盘，目标写会产生竞争。

## 丢包是会被报出来的

组件里所有发送路径都是非阻塞的：通道满了就丢帧并累加 `dropped`，绝不自旋等待。
自旋会拉长被测代码的时序，那就不是为了测量而插桩，而是为了插桩而改变被测对象了。

`mdk_trace_get_stats()` 返回 `frames` / `bytes` / `dropped`。主机侧还会统计
ITM Overflow 包、MTF CRC 错误和 `dropped_bytes`。这些数字进返回结果，明确告诉你
「事件可能不全」，而不是让你拿着残缺时间线去下结论。
