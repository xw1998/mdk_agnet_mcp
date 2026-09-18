# mdk_trace — 目标侧插桩组件

这是 mdkdebug 的**目标侧**配套组件：跑在被调试芯片里，把结构化事件打包后经
SWO / RTT / 串口送到主机（**stream 模式**），或者只写进本地 RAM 环形缓冲、
等主机事后一次性读回（**buff 模式**），由 `mdkdebug` 的 `trace_*` 系列工具解包。

一句话说明为什么需要它：**SWO 和 RTT 只是通道，芯片不会自己说话**。没有这层
插桩，`trace_swo_*` 拿到的只是一堆无意义的字节。

同样地，**芯片也不会自己告诉你它为什么 HardFault**——所以这份组件里还有一组
异常插桩 API（`mdk_trace_fault_capture()`），能在 fault handler 的第一条语句把
PC/LR/SP/xPSR/HFSR/MMFAR/BFAR 落进缓冲。这是整套东西里最值钱的几行代码。

## 目录内容

| 文件 | 作用 |
|------|------|
| `mdk_trace.h` | 对外 API：初始化、事件、计数器、ISR、scope、sched、fault 捕获 |
| `mdk_trace.c` | 时间戳源（DWT / `mcycle`）、MTF 组帧、ITM / RTT / UART / buff 分派 |
| `mdk_trace_rtt.h` / `.c` | SEGGER 兼容的 RTT 控制块与环形缓冲（stream 模式） |
| `mdk_trace_buff.h` / `.c` | RAM 环形缓冲后端（**buff 模式**：全速录、事后读回） |
| `mdk_trace_config_default.h` | 全部配置项的兜底默认值（每个宏都是 `#ifndef`） |
| `CMakeLists.txt` | CMake 工程，产出一个静态库 `mdk_trace` |

后端的源文件都是「未选中就编成空目标文件」（内容裹在 `#if` 里），所以
`mdk_trace.c` + `mdk_trace_rtt.c` + `mdk_trace_buff.c` 可以无脑一起加进工程，
真正生效的只有 `MDK_TRACE_BACKEND_*` 选中的那一个。

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

拿到主机侧（stream 模式）：

```
trace_rtt_find(elf="build/app.elf")
trace_rtt_attach(elf="build/app.elf")
trace_rtt_read()          # 结构化事件列表
```

buff 模式（全速录、事后读回）则是另一条链路：

```
trace_instrument(target_dir="D:/proj/src/trace", backend="buff",
                 coreclk=84000000, buff_records=2048)
# 目标跑一段（或出事之后）
trace_buff_status(elf="build/app.axf")   # 容量 / 已录 / 丢没丢 / 回卷没
trace_buff_dump(elf="build/app.axf", out_file="trace.json",
                names="0x10=switch,0x11=wait")   # 解成时间线
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
| `MDK_TRACE_BACKEND_ITM` / `_RTT` / `_UART` / `_BUFF` / `_NONE` | ITM | 选一个后端；`_BUFF` = 全速录、事后读回 |
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
| `MDK_TRACE_BUFF_RECORDS` | `2048` | buff 模式记录条数；× 12 字节 = 静态 RAM 占用 |
| `MDK_TRACE_BUFF_TS_SHIFT` | `0` | buff 模式 dt 的右移位数；0 = 每 CPU 周期（最细） |
| `MDK_TRACE_BUFF_CLEAR_ON_INIT` | `0` | 0 = 复位后保留上一次运行的记录（异常复位时唯一证据） |
| `MDK_TRACE_FAULT_FRAME` | `1` | fault handler 里多存一份寄存器现场 |

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
| 9 | fault | `class:u16, cfsr:u32` |
| 10 | sched | `from:u16, to:u32` |

`kind`：`0=enter`、`1=exit`、`2=point`、`3=abort`。
`fault` 的 `class`：`0=HardFault`、`1=MemManage`、`2=BusFault`、`3=UsageFault`。
寄存器转储走 `counter` 类型，id 用保留区间 `0xFF01..0xFF07`
（pc / lr / sp / hfsr / mmfar / bfar / xpsr）。

## 两种工作模式：stream 与 buff

区别只在**事件什么时候离开芯片**。

| 模式 | 后端 | 事件去向 | 需要什么 | 代价 |
|------|------|---------|---------|------|
| **stream** | ITM / RTT / UART | 一发生就立刻推出芯片 | SWO 脚（ITM）或只要能读写 RAM（RTT） | 带宽有限、主机要跟得上、读取要抢目标时间 |
| **buff** | `MDK_TRACE_BACKEND_BUFF` | 只写进本 RAM 环形缓冲，**字节不出芯片** | 只要调试器能读写 RAM | 容量有限，写满覆盖最旧的；文本帧放不下；时间戳只存差值 |

两种模式的**插桩点完全相同**（同一份代码、同一套宏），区别只在改一个
`MDK_TRACE_BACKEND_*` 重编。

### buff 模式：全速录，事后一次性读回

目标侧只有十来个 store（`mdk_trace_buff_put()`），不阻塞、不碰外设、不看主机脸色，
所以可以**全速跑**；因为不占任何传输带宽，时间粒度可以开到最小——
`MDK_TRACE_BUFF_TS_SHIFT=0` 就是每 CPU 周期（F401 84MHz 上 11.9ns）。

主机侧定位方式：固件里有一个静态分配的 `mdk_trace_buff_blob`，开头是
80 字节控制块，紧接着就是记录区（固定在 `ctrl + 80`）。**只需要一个符号**，
不需要翻 map 文件找第二个地址。

```c
typedef struct {
    char     magic[8];    /* 0   "MDKTBUF1"  */
    uint32_t version;     /* 8   */
    uint32_t rec_size;    /* 12  必须 = 12 */
    uint32_t cap;         /* 16  记录槽数 */
    uint32_t recs_addr;   /* 20  记录区地址 */
    uint32_t head;        /* 24  下一个写入槽位 */
    uint32_t total;       /* 28  累计写入条数 */
    uint32_t lost;        /* 32  没有时间基而丢掉的条数 */
    uint32_t text_dropped;/* 36  12 字节装不下的文本帧数 */
    uint32_t ts_shift;    /* 40  dt 的右移位数 */
    uint32_t cpu_hz;      /* 44  每秒周期数 */
    uint32_t last_cycles; /* 48  最新一条的绝对时间戳 */
    uint32_t flags;       /* 52  ENABLED / WRAPPED / RESTARTED */
    uint32_t reset_req;   /* 56  主机写 1 = 请求清空 */
    uint32_t seq;         /* 60  复位代数 */
    uint32_t reserved[4]; /* 64  保持 80 字节 */
} mdk_trace_buff_ctrl_t;
```

记录是**定长 12 字节**（小端）：

| 偏移 | 类型 | 含义 |
|------|------|------|
| 0 | u8 | type（与 MTF 类型同一编号） |
| 1 | u8 | kind（enter / exit / point / abort） |
| 2–3 | u16 | id（应用自定） |
| 4–7 | u32 | arg（自由载荷） |
| 8–11 | u32 | dt = 与上一条的周期差，已右移 `ts_shift` |

存**差值**而不是绝对时间戳，是记录能做到 12 字节的关键。绝对时刻由控制块的
`last_cycles`（最新一条的绝对时间戳）向前回推得到。

主机侧三个工具：`trace_buff_status`（控制块健康快照）/ `trace_buff_dump`
（全量读回并解成时间线，带 fault 现场）/ `trace_buff_reset`（请目标开一段新录制）。

**暖启动**：`MDK_TRACE_BUFF_CLEAR_ON_INIT` 默认为 0。复位（尤其看门狗咬、
fault 复位）之后 `mdk_trace_buff_init()` **保留**上一次运行的记录，只重基时间原点
并置 `RESTARTED`、`seq++`。因为对「为什么会复位」这类问题，复位前的记录才是
唯一证据，而默认清空会正好把它抹掉。代价是时间轴上有接缝——主机把接缝标出来，
不会假装时间连续。

## 插桩点该往哪儿放

「桩插在哪儿」比「怎么读」更决定这次 trace 有没有用。按对排查的价值排序：

1. **异常 handler：第一优先级，而且必须插在第一条语句**
   ```c
   void HardFault_Handler(void)
   {
       MDK_TRACE_FAULT_CAPTURE();   /* 必须是第一条语句 */
       for (;;) { }                 /* 再进你的死循环 */
   }
   ```
   它读 LR / MSP / PSP，按 `EXC_RETURN` 选对栈（bit2=1 说明出事时在 PSP 上，
   也就是在线程/任务里），再从异常栈帧取 PC / LR / xPSR，并读 CFSR / HFSR /
   MMFAR / BFAR；按 CFSR 各字段非零分类，否则如实报 HardFault。
   **越早越好**：栈再被压一层、或你在 handler 里又调了函数，现场就变了。
2. **看门狗喂狗点 + 复位原因**。喂狗点用 `MDK_TRACE_MARK()`；喂狗停了，
   录到的最后一次喂狗与它前后的时间差就是「卡了多久」的直接证据。
   复位后第一件事（main 里、外设初始化之前）打一个 MARK，配合默认的暖启动，
   上一次运行的记录就全在。
3. **任务 / 线程切换点**。`MDK_TRACE_SCHED(from, to)`；同时给任务主体循环打
   一对 `SCOPE_BEGIN/END`，任务级耗时与切换频率都能算出来。
   阻塞原语里打 `mdk_trace_wait()` 一类的 WAIT —— **只插一部分阻塞路径的话，
   时间线上那段就是盲区**，看图的人会把「没插桩」当成「没发生」。
4. **关键状态迁移 / 协议节点**。状态机迁移、通信帧头尾、中断进出，用成对的
   `SCOPE_BEGIN/SCOPE_END` 夹住，ID 自己编号，主机侧用
   `names="0x10=switch,0x11=wait"` 译成名字。

别插的地方：高频内循环（每毫秒上千次，buff 会回卷、stream 会丢，插桩本身还开始
影响时序）、fault 之后还可能再次异常的代码路径、优先级高于被测中断的地方。

一条硬规矩：**插桩点只做「记一笔」**，不要在里面调 printf 级别的重逻辑。
buff 模式一次记录就是十来个 store，这才是它敢全速录的前提。

## 踩过的坑（都是真板上撞出来的）

1. **RTT 控制块被链接器回收**。`_SEGGER_RTT` 在 `mdk_trace_rtt.c` 里定义并标了
   `used`，但 `--gc-sections` 加上未引用的段仍可能被丢掉。稳妥做法是在链接脚本里
   `KEEP(*(.bss._SEGGER_RTT))`，或者确认 `mdk_trace_init()` 确实被调用了。
2. **主机读完不推进 `RdOff`**。RTT 上行缓冲满不满，是拿 `WrOff - RdOff` 算的；
   主机读完必须把 `RdOff` 推到 `WrOff`，否则目标会一直认为缓冲是满的并持续丢数据。
   `mdkdebug` 的 `trace_rtt_read` 已经这么做了。目标侧**绝不要**写 `RdOff`——
   那是主机的地盘，目标写会产生竞争。
3. **目标全速运行时经 SWD 读 RAM，可能整片读回 0**（Keil 链路实测如此）。
   这**不等于那片内存是 0**，更不等于「缓冲是空的」。这种时候工具会报
   `degenerate` / `read_confidence=low`；buff 工具会直接报 `buff-read-degenerate`
   并让你先 halt。**不要把 0 当结论**。好在 buff 的记录就在 RAM 里，停机不会丢。
4. **`stop` 之后的第一次 `read_mem` 会读到全 0 脏帧**，重读才对
   （`read_mem_verified` 会自带复读判定；自己手搓内存读时尤其要注意）。
5. **halt→读→resume 的代价**：单次约 320～510ms，停机期间目标时间被冻结。
   工具上报的 `paused_ms` 偏高（实测报 0.33～0.43s，按目标自身计数反算真实有效
   冻结约 0.27～0.30s）——**要用目标侧的时间戳算，不要用主机时钟**。
6. **不要用内核 tick 当时间戳**。500µs 的节拍会让大量相邻事件的 dt = 0，
   10µs 级的切片全部退化成 0，时间线看着就像坏了。用 DWT `CYCCNT`
   （84MHz 上 11.9ns），而且得先使能 `DEMCR.TRCENA(1<<24)`，否则计数不动。
7. **环形缓冲一定会溢出**。必须把 `lost` / `wrapped` 透出来。分块 dump + reset
   拼时间线一定会留空洞（实测 8 块之间 7 段空洞、合计 4.1s）——
   空洞要在图上画出来，不要连成一条直线骗人。
8. **用 4bit 打包任务号，上限就是 14 个任务**（`0x0F` 要留给空闲）。
   任务多了要么换字段宽度，要么先裁掉不关心的任务。
9. **没插桩的地方不等于没发生**。「任务 A 消失了 200ms」可能只是那条阻塞路径
   没插桩——这是「没测不等于没有」的原型，任何采集类工具都要防这一手。

## 丢包是会被报出来的

组件里所有发送路径都是非阻塞的：通道满了就丢帧并累加 `dropped`，绝不自旋等待。
自旋会拉长被测代码的时序，那就不是为了测量而插桩，而是为了插桩而改变被测对象了。

`mdk_trace_get_stats()` 返回 `frames` / `bytes` / `dropped`。主机侧还会统计
ITM Overflow 包、MTF CRC 错误和 `dropped_bytes`。这些数字进返回结果，明确告诉你
「事件可能不全」，而不是让你拿着残缺时间线去下结论。
