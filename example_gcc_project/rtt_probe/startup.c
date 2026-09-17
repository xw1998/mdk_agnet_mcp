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
void SysTick_Handler(void);

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
    /* SysTick 必须接 main.c 里的 SysTick_Handler：
     * 这里原本写成 Default_Handler，结果 SysTick 一使能（main 里 systick_init_16mhz）
     * 第一个 1ms 中断就把 CPU 甩进 Default_Handler 的死循环，main 再也不往前走。
     * 真机上表现为「RTT 只出来开机那两条、g_state.ms 恒为 0、PC 采样值恒定」。
     * 这个 bug 就是靠 trace_pcsample 报“采样值几乎不变”+ trace_profile 显示
     * Default_Handler 100% 才定位到的，不是猜的。 */
    SysTick_Handler,
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
