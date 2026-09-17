/* mdkdebug RTT 端到端验证固件
 * 目标：目标侧持续往 RTT up 通道 0 写 MTF 帧，主机经 SWD 把数据读回。 */
#include "mdk_trace.h"

typedef struct {
    volatile uint32_t ms;
    volatile uint32_t ticks;
} t_state_t;

static t_state_t g_state;

/* SysTick 走默认 16MHz HSI（复位后的时钟），1ms 一个中断 */
static void systick_init_16mhz(void)
{
    volatile uint32_t *const syst_csr = (volatile uint32_t *)0xE000E010u;
    volatile uint32_t *const syst_rvr = (volatile uint32_t *)0xE000E014u;
    volatile uint32_t *const syst_cvr = (volatile uint32_t *)0xE000E018u;

    *syst_rvr = 16000u - 1u;
    *syst_cvr = 0u;
    *syst_csr = 0x7u;   /* ENABLE | TICKINT | CLKSOURCE(core) */
}

void SysTick_Handler(void)
{
    g_state.ms++;
    g_state.ticks++;
}

int main(void)
{
    int i = 0;

    systick_init_16mhz();
    mdk_trace_init();

    mdk_trace_text("boot: mdkdebug rtt probe");
    mdk_trace_printf("clock=%d hz, backend=%s", (int)mdk_trace_hz(),
                     mdk_trace_backend_name());

    for (;;) {
        volatile uint32_t spin;

        MDK_TRACE_SCOPE(0x1001) {
            i++;
            if ((i % 16) == 0) {
                mdk_trace_counter(0x1010, (uint32_t)i);
                mdk_trace_printf("tick %d uptime %d ms", i, (int)g_state.ms);
            } else if ((i % 4) == 0) {
                mdk_trace_kv(1, i);
            }
        }

        for (spin = 0u; spin < 200000u; spin++) {
            __asm volatile("nop");
        }
    }
}
