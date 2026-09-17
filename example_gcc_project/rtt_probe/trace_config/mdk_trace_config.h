#ifndef MDK_TRACE_CONFIG_H
#define MDK_TRACE_CONFIG_H
/* 由 mdkdebug 的 trace_instrument 生成；改这里不用改组件源码。 */

#define MDK_TRACE_ENABLE          1
#define MDK_TRACE_BACKEND_RTT 1
#define MDK_TRACE_ITM_PORT        1
#define MDK_TRACE_RTT_UP_CHANNELS   2
#define MDK_TRACE_RTT_DOWN_CHANNELS 1
#define MDK_TRACE_RTT_BUF_SIZE      1024
#define MDK_TRACE_TEXT_BUF_SIZE     128
#define MDK_TRACE_CPU_HZ            84000000
#define MDK_TRACE_SWO_BAUD          2000000
#define MDK_TRACE_DBGMCU_CR         0xE0042004u
/* 事件 ID 区间（主机侧按区间分派语义） */
#define MDK_TRACE_ID_APP_BASE      0x1000
#define MDK_TRACE_ID_ISR_BASE      0x2000

#endif /* MDK_TRACE_CONFIG_H */
