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
 *   MDK_TRACE_BACKEND_BUFF  RAM ring buffer only, host dumps it afterwards
 *   MDK_TRACE_BACKEND_SWD   compressed RAM ring, host drains it over SWD
 *   MDK_TRACE_BACKEND_NONE  compile but emit nowhere (useful for sizing)
 *
 * ITM / RTT / UART are *stream* backends: the event leaves the chip as it
 * happens and the host has to keep up. BUFF and SWD are the two in-chip
 * backends: nothing leaves the chip, the core pays a few stores per event and
 * the run keeps its real timing. Pick stream to watch a live system, buff to
 * dump one window after the fact, swd to record continuously without ever
 * losing the run (the host drains it in slices and the ring recycles).
 *
 * A generated mdk_trace_config.h only defines the one backend it selected, so
 * the ITM fallback must not fire when any backend was already chosen.
 */
#if !defined(MDK_TRACE_BACKEND_ITM) && !defined(MDK_TRACE_BACKEND_RTT) && \
    !defined(MDK_TRACE_BACKEND_UART) && !defined(MDK_TRACE_BACKEND_BUFF) && \
    !defined(MDK_TRACE_BACKEND_SWD) && !defined(MDK_TRACE_BACKEND_NONE)
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
#ifndef MDK_TRACE_BACKEND_BUFF
#  define MDK_TRACE_BACKEND_BUFF 0
#endif
#ifndef MDK_TRACE_BACKEND_SWD
#  define MDK_TRACE_BACKEND_SWD 0
#endif
#ifndef MDK_TRACE_BACKEND_NONE
#  define MDK_TRACE_BACKEND_NONE 0
#endif

/* ------------------------------------------------------------- swd backend
 * Backend SWD only. Same idea as BUFF (an in-chip ring located by the symbol
 * `mdk_trace_swd_blob`) but with two differences that matter:
 *
 *   1. the ring is a *byte* ring of compressed tokens, not fixed 12 byte
 *      records, so a typical event costs ~2.3 bytes instead of 12;
 *   2. the target never overwrites what the host has not read yet. When the
 *      ring is full it DROPS the new event and counts it in lost_events, so
 *      whatever is already recorded stays readable and the host can keep
 *      draining forever. That is what makes a lossless continuous recording
 *      possible on two SWD wires.
 *
 * MDK_TRACE_SWD_BYTES must be a power of two (the ring index is a mask, not a
 * modulo - a divide inside an ISR is not worth it). 8192 bytes holds roughly
 * 3400 events at the measured ~2.35 bytes/event.
 */
#ifndef MDK_TRACE_SWD_BYTES
#  define MDK_TRACE_SWD_BYTES 8192
#endif

/* dt = DWT cycles >> MDK_TRACE_SWD_TS_SHIFT. Narrower than the BUFF knob on
 * purpose: 0 (one cycle resolution) is the right answer unless a single gap
 * exceeds 2^32 cycles, and in a continuous recording the host anchors the
 * timeline on the control block's absolute cycle count anyway.
 */
#ifndef MDK_TRACE_SWD_TS_SHIFT
#  define MDK_TRACE_SWD_TS_SHIFT 0
#endif

/* 1 (default) - clear the ring on init.
 *
 * This is the opposite of the BUFF default, and deliberately so. A seamless
 * host reads from drained towards head; stale bytes from a previous run would
 * be spliced onto the new run with no visible seam at all - no reset record,
 * no sequence marker, just a timeline that quietly lies. Clearing is the only
 * safe default here; the host can still ask for a clip with trace_swd_reset.
 */
#ifndef MDK_TRACE_SWD_CLEAR_ON_INIT
#  define MDK_TRACE_SWD_CLEAR_ON_INIT 1
#endif

/* ---------------------------------------------------------------- buff mode
 * Backend BUFF only. The ring lives in .bss and its address is fixed after
 * linking, which is what lets the host find it from the symbol
 * `mdk_trace_buff_blob` with no map file digging.
 *
 * A record is 12 bytes, so MDK_TRACE_BUFF_RECORDS * 12 is the RAM bill:
 *   2048 records = 24 KB, at ~1000 events/s that is ~2 s of history.
 * Size it for the window you need, not for the whole run - when the ring
 * wraps the oldest records are gone and FLAG_WRAPPED says so.
 */
#ifndef MDK_TRACE_BUFF_RECORDS
#  define MDK_TRACE_BUFF_RECORDS 2048
#endif

/* dt is stored as "cycles since the previous record" in 32 bits. Shift it
 * right to widen the representable gap at the cost of resolution:
 *   shift 0 -> 1 cycle resolution, max gap 2^32 cycles (51 s at 84 MHz)
 *   shift 6 -> 64 cycle resolution (0.76 us at 84 MHz), max gap 55 min
 * 0 is the right answer unless your events can be minutes apart. */
#ifndef MDK_TRACE_BUFF_TS_SHIFT
#  define MDK_TRACE_BUFF_TS_SHIFT 0
#endif

/* What mdk_trace_init() does to a buffer that already holds records.
 *
 * 0 (default) - keep them. After a watchdog bite or a fault-triggered reset
 *               the records from *before* the reset are the only evidence
 *               there is, and a startup path that calls mdk_trace_init()
 *               again would otherwise erase exactly that. The host sees a
 *               RESET record and a RESTARTED flag, and marks the hole rather
 *               than pretending the timeline is continuous.
 * 1           - clear on every init, i.e. each init starts a fresh history.
 *               Use it when the buffer should only ever describe the current
 *               session. Ask the host to clear instead (trace_buff_reset)
 *               if you only need it occasionally.
 */
#ifndef MDK_TRACE_BUFF_CLEAR_ON_INIT
#  define MDK_TRACE_BUFF_CLEAR_ON_INIT 0
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

/* Capture the exception stack frame when a fault handler calls
 * MDK_TRACE_FAULT_CAPTURE(). Without it the fault path still records the
 * class and the fault status register, just not PC/LR/SP. Costs a little
 * code, no RAM. */
#ifndef MDK_TRACE_FAULT_FRAME
#  define MDK_TRACE_FAULT_FRAME 1
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

/* ------------------------------------------------- SVCrtOS kernel hooks
 * 1 = mdk_trace_svcrt.c emits the kernel's own events (context switches, task
 * lifecycle, object wait/signal/timeout, mutex ownership, ISR enter/exit,
 * heap). The kernel has to call the adapter at its five hook points - see
 * mdk_trace_svcrt.h; the adapter itself only forwards to the same primitives
 * application code uses, so the backend decides what it costs.
 *
 * 0 (default) = the adapter still exists and still links, but compiles to
 * empty bodies. A firmware that calls it and forgot this macro builds fine and
 * produces a trace with no kernel events; trace_diagnose says exactly that
 * instead of leaving an empty timeline looking like a quiet system. */
#ifndef MDK_TRACE_SVCRT_HOOKS
#  define MDK_TRACE_SVCRT_HOOKS 0
#endif

#endif /* MDK_TRACE_CONFIG_DEFAULT_H */
