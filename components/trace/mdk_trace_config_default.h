/* mdk_trace_config_default.h - baked in defaults for the trace component.
 *
 * Every macro is guarded with #ifndef, so both of these work:
 *   - define them on the compiler command line / project settings, or
 *   - let the mdkdebug `trace_instrument` tool generate a mdk_trace_config.h.
 *
 * Keep this file ASCII only, same reason as mdk_trace.h.
 */

#ifndef MDK_TRACE_CONFIG_DEFAULT_H
#define MDK_TRACE_CONFIG_DEFAULT_H

/* Master switch. Set to 0 to compile the whole component into empty stubs. */
#ifndef MDK_TRACE_ENABLE
#  define MDK_TRACE_ENABLE 1
#endif

/* Backend selection. Pick exactly one.
 *   MDK_TRACE_BACKEND_ITM   Cortex-M SWO pin, needs an ITM capable probe
 *   MDK_TRACE_BACKEND_RTT   any core, host pokes RAM through the probe
 *   MDK_TRACE_BACKEND_UART  plain serial, host reads the COM port
 *   MDK_TRACE_BACKEND_NONE  compile but emit nowhere (useful for sizing)
 *
 * A generated mdk_trace_config.h only defines the one backend it selected, so
 * the ITM fallback must not fire when any backend was already chosen.
 */
#if !defined(MDK_TRACE_BACKEND_ITM) && !defined(MDK_TRACE_BACKEND_RTT) && \
    !defined(MDK_TRACE_BACKEND_UART) && !defined(MDK_TRACE_BACKEND_NONE)
#  define MDK_TRACE_BACKEND_ITM 1
#endif
#ifndef MDK_TRACE_BACKEND_ITM
#  define MDK_TRACE_BACKEND_ITM 0
#endif
#ifndef MDK_TRACE_BACKEND_RTT
#  define MDK_TRACE_BACKEND_RTT 0
#endif
#ifndef MDK_TRACE_BACKEND_UART
#  define MDK_TRACE_BACKEND_UART 0
#endif
#ifndef MDK_TRACE_BACKEND_NONE
#  define MDK_TRACE_BACKEND_NONE 0
#endif

/* ITM stimulus port used for frames. Port 0 is what `itm port 0 on` expects;
 * use 1..31 to keep the application frames apart from printf style output. */
#ifndef MDK_TRACE_ITM_PORT
#  define MDK_TRACE_ITM_PORT 1
#endif

/* RTT ring buffers. MDK_TRACE_RTT_BUF_SIZE is per channel. */
#ifndef MDK_TRACE_RTT_UP_CHANNELS
#  define MDK_TRACE_RTT_UP_CHANNELS 2
#endif
#ifndef MDK_TRACE_RTT_DOWN_CHANNELS
#  define MDK_TRACE_RTT_DOWN_CHANNELS 1
#endif
#ifndef MDK_TRACE_RTT_BUF_SIZE
#  define MDK_TRACE_RTT_BUF_SIZE 1024
#endif
/* Channel 0 name. The host prints it so you can tell channels apart. */
#ifndef MDK_TRACE_RTT_UP_NAME0
#  define MDK_TRACE_RTT_UP_NAME0 "TRACE"
#endif
#ifndef MDK_TRACE_RTT_DOWN_NAME0
#  define MDK_TRACE_RTT_DOWN_NAME0 "CMD"
#endif

/* Text frames are split at this size. Keep it well under 255 so the framing
 * bytes still fit in one MTF frame. */
#ifndef MDK_TRACE_TEXT_BUF_SIZE
#  define MDK_TRACE_TEXT_BUF_SIZE 128
#endif

/* CPU clock in Hz. Required by the ITM backend to program the TPIU prescaler,
 * and used to convert DWT cycles into microseconds on the host.
 * 0 = do not touch the TPIU (somebody else already configured it). */
#ifndef MDK_TRACE_CPU_HZ
#  define MDK_TRACE_CPU_HZ 0
#endif

/* SWO output baud rate. Must match the `tpiu config` line the host sends. */
#ifndef MDK_TRACE_SWO_BAUD
#  define MDK_TRACE_SWO_BAUD 2000000
#endif

/* Address of the DBGMCU_CR register on STM32 parts (0xE0042004 on F4/F7,
 * 0xE0042004 on most others, 0x40015804 on some L4). 0 = leave it alone.
 * On STM32 the SWO pin stays a GPIO until TRACE_IOEN is set here. */
#ifndef MDK_TRACE_DBGMCU_CR
#  define MDK_TRACE_DBGMCU_CR 0xE0042004u
#endif

/* Enable DWT hardware event counters (exception trace, CPI, sleep, LSU, fold).
 * Adds ITM hardware source packets; costs a little bandwidth. */
#ifndef MDK_TRACE_DWT_EVENTS
#  define MDK_TRACE_DWT_EVENTS 0
#endif

/* Enable DWT PC sampling. Useful for flat profilers without an SWO pin, but it
 * only produces samples while the target is halted or stepping. */
#ifndef MDK_TRACE_DWT_PCSAMPLE
#  define MDK_TRACE_DWT_PCSAMPLE 0
#endif

/* Include the DWT cycle counter as a local timestamp on every event. */
#ifndef MDK_TRACE_USE_DWT
#  define MDK_TRACE_USE_DWT 1
#endif

/* UART backend hook: the application provides a blocking or non-blocking byte
 * sink. Ignored by the ITM and RTT backends. */
#ifndef MDK_TRACE_UART_PUTC
#  define MDK_TRACE_UART_PUTC(c) ((void)(c))
#endif

#endif /* MDK_TRACE_CONFIG_DEFAULT_H */
