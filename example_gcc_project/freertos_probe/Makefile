# mdkdebug「RTOS 任务感知」验证固件（arm-none-eabi-gcc + make）
#
# 这块固件跑真正的 FreeRTOS-Kernel，用来验证 rtos_info / rtos_tasks /
# rtos_objects 三个工具在真机上的解析是否正确（对照见 main.c 里内核自报的
# g_kernel_hwm[]）。真机为 F401（Cortex-M4，512K Flash / 96K RAM）。
#
# FreeRTOS 内核**不随仓库提交**（避免把 1.4MB 第三方源码塞进仓库）。
# 首次构建前先取一份内核，再把路径告诉 make：
#     git clone --depth 1 https://github.com/FreeRTOS/FreeRTOS-Kernel.git ~/FreeRTOS-Kernel
#     make FREERTOS_KERNEL=~/FreeRTOS-Kernel
# 或者用环境变量 FREERTOS_KERNEL / MDKDEBUG_FREERTOS_KERNEL 指定。
#
# 配方行用 '>' 开头（.RECIPEPREFIX），避免制表符在补丁/复制中丢失。
.RECIPEPREFIX = >
.DEFAULT_GOAL := all

FREERTOS_KERNEL ?= $(if $(MDKDEBUG_FREERTOS_KERNEL),$(MDKDEBUG_FREERTOS_KERNEL),$(HOME)/FreeRTOS-Kernel)

TOOLCHAIN ?=
CC        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-gcc,arm-none-eabi-gcc)
OC        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-objcopy,arm-none-eabi-objcopy)
SZ        := $(if $(TOOLCHAIN),$(TOOLCHAIN)/arm-none-eabi-size,arm-none-eabi-size)

KERNEL    := $(FREERTOS_KERNEL)
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/freertos_probe

C_SOURCES  := main.c startup.c \
              $(KERNEL)/tasks.c $(KERNEL)/list.c $(KERNEL)/queue.c \
              $(KERNEL)/portable/GCC/ARM_CM4F/port.c \
              $(KERNEL)/portable/MemMang/heap_4.c
C_INCLUDES := -I. -I$(KERNEL)/include -I$(KERNEL)/portable/GCC/ARM_CM4F

CPUFLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
CFLAGS   := $(CPUFLAGS) -O1 -g3 -Wall -ffunction-sections -fdata-sections -std=c99
LDFLAGS  := $(CPUFLAGS) -Tlink.ld -nostartfiles -Wl,--gc-sections -Wl,-Map=$(TARGET).map

$(BUILD_DIR):
> mkdir -p $(BUILD_DIR)

# 内核路径没配好时给出人话提示，而不是让 gcc 报一堆 "No such file"
_check_kernel:
> @test -f "$(KERNEL)/tasks.c" || { echo "找不到 FreeRTOS 内核：$(KERNEL)"; echo "用法：make FREERTOS_KERNEL=/path/to/FreeRTOS-Kernel"; echo "获取：git clone --depth 1 https://github.com/FreeRTOS/FreeRTOS-Kernel.git"; exit 1; }

all: $(TARGET).elf $(TARGET).bin

$(TARGET).elf: $(C_SOURCES) link.ld FreeRTOSConfig.h _check_kernel | $(BUILD_DIR)
> $(CC) $(CFLAGS) $(C_INCLUDES) $(C_SOURCES) $(LDFLAGS) -o $@
> $(SZ) $@

$(TARGET).bin: $(TARGET).elf
> $(OC) -O binary $< $@

.PHONY: all clean _check_kernel
clean:
> $(RM) -r $(BUILD_DIR)
