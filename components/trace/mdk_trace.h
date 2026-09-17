/* mdk_trace.h - target side instrumentation component for mdkdebug
 *
 * Collects structured trace events on the target and ships them to the host
 * over one of three backends:
 *
 *   ITM/SWO  - Cortex-M only. Writes bytes to an ITM stimulus port; the host
 *              captures them through the SWO pin (OpenOCD `tpiu config ...`).
 *   RTT      - any core with a debug probe that can touch RAM. The host reads
 *              and writes a SEGGER-compatible control block directly in RAM.
 *   UART     - plain serial; the host reads the port instead of the probe.
 *
 * Frame format (MTF, kept in sync with host side mdkdebug/traceproto.py):
 *
 *   0xA5 | (version<<4 | type) | len | payload[len] | crc8
 *
 *   crc8 covers magic..end of payload, poly 0x07, init 0x00, no reflection.
 *   len is one byte, so a single frame carries at most 255 payload bytes;
 *   longer text is split by this component.
 *
 * Design notes:
 *   - Every emit path is non-blocking. Instrumentation must never change the
 *     timing of the code under test, so when the transport is full the event
 *     is dropped and counted instead of spinning.
 *   - Drop counters are reported, not hidden. A trace that silently loses
 *     events is worse than one that tells you it did.
 *   - Nothing here depends on CMSIS or on a HAL; register access is done with
 *     raw volatile pointers so the component drops into any project.
 *
 * Comments in this component are deliberately ASCII-only: Keil ARMCC (AC5)
 * mis-renders UTF-8 in some setups, and this component is expected to be
 * dropped into arbitrary third party projects.
 */

#ifndef MDK_TRACE_H
#define MDK_TRACE_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ config
 * A project either relies on the baked-in defaults, or drops in a generated
 * mdk_trace_config.h (created by the mdkdebug `trace_instrument` tool).
 * The generated file is picked up automatically when the compiler can answer
 * __has_include (GCC, Clang, armclang/AC6). AC5 users add
 * MDK_TRACE_USE_CONFIG_FILE to their project defines instead.
 */
#if defined(__has_include)
#  if __has_include("mdk_trace_config.h")
#    include "mdk_trace_config.h"
#  endif
#elif defined(MDK_TRACE_USE_CONFIG_FILE)
#  include "mdk_trace_config.h"
#endif

#include "mdk_trace_config_default.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MDK_TRACE_VERSION_MAJOR   1
#define MDK_TRACE_VERSION_MINOR   0

/* --------------------------------------------------------------- constants
 * Frame types. Must match MTF_TYPES in mdkdebug/traceproto.py.
 */
#define MDK_TRACE_TYPE_RAW      0u
#define MDK_TRACE_TYPE_TEXT     1u
#define MDK_TRACE_TYPE_EVENT    2u
#define MDK_TRACE_TYPE_COUNTER  3u
#define MDK_TRACE_TYPE_ISR      4u
#define MDK_TRACE_TYPE_MARK     5u
#define MDK_TRACE_TYPE_TS       6u
#define MDK_TRACE_TYPE_KV       7u
#define MDK_TRACE_TYPE_RESET    8u

/* Event / ISR sub kinds. Must match MTF_KINDS in traceproto.py. */
#define MDK_TRACE_KIND_ENTER    0u
#define MDK_TRACE_KIND_EXIT     1u
#define MDK_TRACE_KIND_POINT    2u
#define MDK_TRACE_KIND_ABORT    3u

#define MDK_TRACE_MTF_MAGIC     0xA5u
#define MDK_TRACE_MTF_VERSION   1u

/* ---------------------------------------------------------------- lifecycle
 * mdk_trace_init() enables the backend and the timestamp source. It is safe to
 * call more than once; the second call is a no-op.
 */
void mdk_trace_init(void);
void mdk_trace_deinit(void);
int  mdk_trace_is_ready(void);

/* Backend tag, useful when a single firmware is built for several boards. */
const char *mdk_trace_backend_name(void);

/* --------------------------------------------------------------- primitives
 * Raw frame out. `len` is capped at 255 by the protocol; split longer payload
 * yourself or use mdk_trace_text().
 */
void mdk_trace_send(uint8_t type, const uint8_t *payload, uint8_t len);

/* Text on the debug channel. Truncates beyond MDK_TRACE_TEXT_BUF_SIZE and
 * splits into several frames when needed. */
void mdk_trace_text(const char *s);
void mdk_trace_printf(const char *fmt, ...);

/* Structured events. `id` is chosen by the application, `arg` is free form. */
void mdk_trace_event(uint16_t id, uint8_t kind, uint32_t arg);
void mdk_trace_counter(uint16_t id, uint32_t value);
void mdk_trace_kv(int16_t key, int32_t value);
void mdk_trace_mark(uint32_t tag);
void mdk_trace_timestamp(void);

/* Interrupt side. Kept separate from mdk_trace_event so the host can pair
 * enter/exit without relying on ids being globally unique. */
void mdk_trace_isr(uint16_t id, uint8_t kind);

/* Time base in ticks (cycles). Returns 0 when no time base is available, e.g.
 * on a core without DWT and without a cycle CSR. */
uint32_t mdk_trace_now(void);
uint32_t mdk_trace_hz(void);

/* ------------------------------------------------------------------ counters
 * Runtime health. Drops are expected under load; what matters is that the host
 * learns about them instead of drawing wrong conclusions from partial data.
 */
typedef struct {
    uint32_t frames;        /* frames handed to the transport            */
    uint32_t bytes;         /* payload + framing bytes                   */
    uint32_t dropped;       /* frames dropped because the transport is full */
    uint32_t crc_errors;    /* host side only, always 0 here             */
} mdk_trace_stats_t;

void mdk_trace_get_stats(mdk_trace_stats_t *out);
void mdk_trace_reset_stats(void);

/* ------------------------------------------------------------- RTT specifics
 * Only meaningful with the RTT backend. Declared here so a single include is
 * enough for application code.
 */
int  mdk_trace_rtt_getc(void);          /* <0 when the down channel is empty */
int  mdk_trace_rtt_putc(int c);
unsigned mdk_trace_rtt_pending(void);   /* bytes waiting in the up channel   */

/* ------------------------------------------------------- convenience macros
 * Explicit begin/end pair. The id has to be a compile time constant so the
 * host can map it back to a symbol file offline.
 */
#define MDK_TRACE_SCOPE_BEGIN(id)  do { mdk_trace_event((id), MDK_TRACE_KIND_ENTER, 0u); } while (0)
#define MDK_TRACE_SCOPE_END(id)    do { mdk_trace_event((id), MDK_TRACE_KIND_EXIT,  0u); } while (0)

/* C99 for-scope: emits enter on entry and exit on every way out of the block,
 * including break/return/goto, because the increment runs before leaving. */
#define MDK_TRACE_SCOPE(id)                                                   \
    for (int mdk_tr_once_ = (mdk_trace_event((id), MDK_TRACE_KIND_ENTER, 0u), 1); \
         mdk_tr_once_ != 0;                                                   \
         mdk_tr_once_ = (mdk_trace_event((id), MDK_TRACE_KIND_EXIT, 0u), 0))

#define MDK_TRACE_ISR_ENTER(id)  do { mdk_trace_isr((id), MDK_TRACE_KIND_ENTER); } while (0)
#define MDK_TRACE_ISR_EXIT(id)   do { mdk_trace_isr((id), MDK_TRACE_KIND_EXIT);  } while (0)

/* Instantaneous value probe: packed as a counter so the host can plot it. */
#define MDK_TRACE_VALUE(id, v)   do { mdk_trace_counter((id), (uint32_t)(v)); } while (0)

/* Compile time switch so a release build pays exactly nothing. */
#ifdef MDK_TRACE_ENABLE
#  define MDK_TRACE_IF_ENABLED(x)  do { x; } while (0)
#else
#  define MDK_TRACE_IF_ENABLED(x)  do { } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* MDK_TRACE_H */
