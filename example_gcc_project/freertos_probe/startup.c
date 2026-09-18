/* 最小启动文件（FreeRTOS 版）：向量表 + 复位入口，不依赖 CMSIS / HAL。
 *
 * 与 rtt_probe 的 startup.c 的关键差别：SysTick / PendSV / SVCall 三个异常
 * **必须**接到 FreeRTOS 移植层的处理函数上。这里也是真踩过的地方——
 * 一旦写错，调度器根本起不来（PendSV 不触发 = 永远只跑第一个任务）。
 */
#include <stdint.h>

extern uint32_t _estack;
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

int main(void);

void Reset_Handler(void);
void Default_Handler(void);

/* FreeRTOS ARM_CM4F 移植层的异常入口（port.c 导出） */
void vPortSVCHandler(void);
void xPortPendSVHandler(void);
void xPortSysTickHandler(void);

__attribute__((section(".isr_vector"), used))
void (*const g_vectors[])(void) = {
    (void (*)(void))(&_estack),
    Reset_Handler,
    Default_Handler,       /* NMI */
    Default_Handler,       /* HardFault */
    Default_Handler,       /* MemManage */
    Default_Handler,       /* BusFault */
    Default_Handler,       /* UsageFault */
    0, 0, 0, 0,            /* 保留 */
    vPortSVCHandler,       /* SVCall：调度器启动时用 SVC 切到第一个任务 */
    Default_Handler,       /* DebugMonitor */
    0,                     /* 保留 */
    xPortPendSVHandler,    /* PendSV：任务切换 */
    xPortSysTickHandler,   /* SysTick：系统节拍 */
};

void Default_Handler(void)
{
    for (;;) {
    }
}

void Reset_Handler(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;

    while (dst < &_edata) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss;) {
        *dst++ = 0u;
    }
    (void)main();
    for (;;) {
    }
}
