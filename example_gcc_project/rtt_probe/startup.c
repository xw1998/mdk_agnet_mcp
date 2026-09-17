/* 最小启动文件：向量表 + 复位入口（不依赖 CMSIS / HAL） */
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

__attribute__((section(".isr_vector"), used))
void (*const g_vectors[])(void) = {
    (void (*)(void))(&_estack),
    Reset_Handler,
    Default_Handler,   /* NMI */
    Default_Handler,   /* HardFault */
    Default_Handler,   /* MemManage */
    Default_Handler,   /* BusFault */
    Default_Handler,   /* UsageFault */
    0, 0, 0, 0,        /* 保留 */
    Default_Handler,   /* SVCall */
    Default_Handler,   /* DebugMonitor */
    0,                 /* 保留 */
    Default_Handler,   /* PendSV */
    Default_Handler,   /* SysTick */
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
