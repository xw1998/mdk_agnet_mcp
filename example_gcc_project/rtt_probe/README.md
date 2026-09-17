# rtt_probe —— RTT 端到端验证固件（F401，GCC + Make）

一个最小 Cortex-M4 固件，用来验证 **mdkdebug 的非 Keil 链路**：目标侧持续往
SEGGER RTT 的 up 通道写 MTF（mdkdebug trace frame）帧，主机经 **SWD** 把数据读回来。
不需要 Keil、不需要串口，只靠 DAPLink + OpenOCD。

## 目录

| 文件 | 说明 |
|------|------|
| `main.c` | SysTick 1ms 节拍 + 主循环里发事件/计数/文本帧（`MDK_TRACE_SCOPE` / `mdk_trace_kv` / `mdk_trace_printf`） |
| `startup.c` | 极简启动：`.isr_vector` + Reset_Handler（搬 `.data`、清 `.bss`、跳 `main`），不依赖 CMSIS |
| `link.ld` | FLASH 512K @ `0x08000000`、RAM 96K @ `0x20000000`（F401RE 的排布） |
| `trace_config/mdk_trace_config.h` | 由 mdkdebug 的 `trace_instrument` 生成的配置（后端=RTT、上下行通道数、缓冲区大小、CPU 主频） |
| `Makefile` | 直接用仓库的 `../../components/trace`，**不复制组件源码** |

## 构建

```bash
# 1) 让工具链进入 PATH（也可在 Makefile 里传 TOOLCHAIN=<bin 目录>）
#    工具侧：toolchain_env(families="all")
# 2) 构建（可以只用 mdkdebug 的构建工具，不必手敲 make）
#    toolchain_build({"project": "example_gcc_project/rtt_probe"})
make
```

产物在 `build/`：`rtt_probe.elf` / `rtt_probe.bin`。

## 上板验证（F401 + DAPLink）

```
ocd_start(profile="stm32f401")
ocd_flash(elf=".../build/rtt_probe.elf", verify=true)
trace_rtt_find()        # 控制块地址（默认 0x2000001C，来自 ELF 符号 _SEGGER_RTT）
trace_rtt_attach()      # 3 个通道：TRACE / TRACE1 / CMD
trace_rtt_read(n_bytes=100)
trace_decode(fmt="auto")   # 认出裸 MTF，出 5 帧（reset / boot 文本 / 事件 0x1001）
trace_events()
ocd_stop()
```

真机实测结论：`_SEGGER_RTT` 控制块魔数 `53454747455220525454`（"SEGGER RTT"），
`nup=2 / ndown=1`；帧序列为 reset(init) → `text("boot: mdkdebug rtt probe")` →
`text("clock=84000000 hz, backend=rtt")` → 事件 `0x1001` enter(ts 8730)/exit(ts 10403)。

## 注意

- `TOOLCHAIN` 默认留空，按 PATH 找 `arm-none-eabi-gcc`；若显式指定，指到 `.../bin` 目录。
- 本固件按 **16MHz HSI** 配置 SysTick（复位后默认时钟），配置头里的 `MDK_TRACE_CPU_HZ`
  是 84MHz——它只影响帧里的时间戳换算，不影响链路验证。
