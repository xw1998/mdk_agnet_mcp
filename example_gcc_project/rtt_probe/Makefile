# mdkdebug RTT 端到端验证固件（arm-none-eabi-gcc + make）
#
# 用途：目标侧持续往 RTT up 通道写 MTF 帧，主机经 SWD 把数据读回，验证
#       ocd_* + trace_rtt_* 整条链路（真机 F401 上跑过，见 docs/PITFALLS.md 11.x）。
#
# trace 组件**不复制**进来，直接用仓库里的 ../../components/trace，
# 免得同一份组件源码在两处维护（真踩过：部署副本停留在旧版本，缺陷已修但副本没跟上）。
# 工程里只保留由 `trace_instrument` 生成的 mdk_trace_config.h（trace_config/）。
#
# 配方行用 '>' 开头（.RECIPEPREFIX），避免制表符在补丁/复制中丢失
.RECIPEPREFIX = >
# 目录规则写在 all 之前，会把 build 变成默认目标（make 只建个空目录就收工），
# 所以显式钉死默认目标
.DEFAULT_GOAL := all

# 工具链 bin 目录：不写死就自动从 PATH 找（先跑 toolchain_env(families="all") 注入）
TOOLCHAIN ?=
CC        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-gcc,arm-none-eabi-gcc)
OC        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-objcopy,arm-none-eabi-objcopy)
SZ        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-size,arm-none-eabi-size)

TRACE_DIR := ../../components/trace
CFG_DIR   := trace_config
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/rtt_probe

C_SOURCES  := main.c startup.c $(TRACE_DIR)/mdk_trace.c $(TRACE_DIR)/mdk_trace_rtt.c
C_INCLUDES := -I$(CFG_DIR) -I$(TRACE_DIR) -I.

CPUFLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
CFLAGS   := $(CPUFLAGS) -O1 -g3 -Wall -ffunction-sections -fdata-sections -std=c99
LDFLAGS  := $(CPUFLAGS) -Tlink.ld -nostartfiles -Wl,--gc-sections -Wl,-Map=$(TARGET).map

# build/ 用 order-only 依赖保证先建目录：ld 写 map 文件不会自己建目录，
# `make clean && make` 会因为没有目录直接失败（真踩过）。
$(BUILD_DIR):
> mkdir -p $(BUILD_DIR)

all: $(TARGET).elf $(TARGET).bin

$(TARGET).elf: $(C_SOURCES) link.ld $(CFG_DIR)/mdk_trace_config.h | $(BUILD_DIR)
> $(CC) $(CFLAGS) $(C_INCLUDES) $(C_SOURCES) $(LDFLAGS) -o $@
> $(SZ) $@

$(TARGET).bin: $(TARGET).elf
> $(OC) -O binary $< $@

.PHONY: all clean
clean:
> $(RM) -r $(BUILD_DIR)
