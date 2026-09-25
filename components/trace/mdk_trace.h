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
 *   BUFF     - nothing leaves the chip: events go into a RAM ring buffer and
 *              the host dumps the whole window afterwards (mdk_trace_buff.h).
 *
 * The first three are *stream* modes (record and read continuously, at the
 * cost of dropping under load). BUFF is *buff* mode (record flat out at full
 * time resolution, read once, bounded by the buffer size). trace_guide with
 * topic=instrument_modes explains when each one is the right answer.
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
#define MDK_TRACE_TYPE_FAULT    9u
#define MDK_TRACE_TYPE_SCHED   10u
#define MDK_TRACE_TYPE_SYNC    11u
#define MDK_TRACE_TYPE_HEAP    12u

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

/* ------------------------------------------------------------------ faults
 * A fault is the one event you cannot afford to reconstruct after the fact,
 * and the one where the interesting state (which stack, which PC, which fault
 * status bit) disappears the moment you restart. These two calls exist so the
 * first line of your fault handler is enough to preserve it.
 *
 * MDK_TRACE_FAULT_CAPTURE() must be the FIRST statement of the handler: it
 * reads LR (EXC_RETURN), MSP and PSP, and from those it walks the exception
 * stack frame to recover PC / LR / xPSR. Anything the handler does before the
 * snapshot can destroy the very state we are here to record.
 *
 * It emits one FAULT record (class + CFSR) followed by counter records with
 * ids 0xFF01.. (PC, LR, SP, HFSR, MMFAR, BFAR, xPSR). Both stream and buff
 * backends carry it; in buff mode the history is still there after the chip
 * has been reset, which is exactly the case that matters.
 */
void mdk_trace_fault(uint16_t cls, uint32_t cfsr);
void mdk_trace_fault_capture(uint32_t exc_return, uint32_t msp, uint32_t psp);

/* Context switch / scheduler hook. `from` and `to` are application task ids;
 * record it wherever your scheduler actually performs the switch, so the
 * trace shows ownership of the CPU rather than a guess derived from ISRs. */
void mdk_trace_sched(uint16_t from, uint16_t to);

/* ------------------------------------------------- synchronisation objects
 * A context switch says a switch happened; it does not say WHY. Without the
 * second half, a trace can show that task A stopped running but not that it
 * was blocked on a semaphore held by task B - which is the one question a
 * priority inversion investigation actually asks.
 *
 * mdk_trace_sync() carries both halves in one record: `obj` is the object
 * handle (your own id for that semaphore / queue / mutex / event group) and
 * `op` says what happened to it, with `val` free for a waiter count, a
 * timeout in ticks or the task id that got it.
 *
 * On the wire the record is exactly one 12 byte buff record / one swd token:
 * id = (obj << MDK_TRACE_SYNC_OBJ_SHIFT) | op, arg = val. Nothing is truncated:
 * obj gets 13 bits (0..8191 objects) and val keeps all 32. `kind` is NOT reused
 * for the operation, because the compressed stream only has two bits for it.
 *
 *   MDK_TRACE_SYNC_WAIT(obj, val)     about to block on obj
 *   MDK_TRACE_SYNC_SIGNAL(obj, val)   released / posted obj
 *   MDK_TRACE_SYNC_TIMEOUT(obj, val)  gave up waiting on obj (this is the one
 *                                     that turns "stuck" into "blocked
 *                                     forever because nobody signals")
 *   MDK_TRACE_SYNC_ACQUIRE(obj, val)  took ownership (mutex held by whom)
 *   MDK_TRACE_SYNC_RELEASE(obj, val)  gave ownership back
 *   MDK_TRACE_SYNC_CREATE(obj, val)   object created (val = initial state)
 *   MDK_TRACE_SYNC_DELETE(obj, val)   object deleted
 */
void mdk_trace_sync(uint16_t obj, uint8_t op, uint32_t val);

#define MDK_TRACE_SYNC_WAIT     0u
#define MDK_TRACE_SYNC_SIGNAL   1u
#define MDK_TRACE_SYNC_ACQUIRE  2u
#define MDK_TRACE_SYNC_RELEASE  3u
#define MDK_TRACE_SYNC_TIMEOUT  4u
#define MDK_TRACE_SYNC_CREATE   5u
#define MDK_TRACE_SYNC_DELETE   6u

/* How the operation and the object share the record's id field. */
#define MDK_TRACE_SYNC_OBJ_SHIFT 3u
#define MDK_TRACE_SYNC_OP_MASK   0x7u

/* ------------------------------------------------------------ heap events
 * Allocation and free, with the size. Two ids is all it takes to answer
 * "is this leaking?" from a trace: the host accumulates net bytes and the
 * largest single block, and reports the peak only as far as it can prove it.
 */
void mdk_trace_heap(uint8_t op, uint32_t size);

#define MDK_TRACE_HEAP_ALLOC    0u
#define MDK_TRACE_HEAP_FREE     1u

#define MDK_TRACE_FAULT_CLASS_HARD      0u
#define MDK_TRACE_FAULT_CLASS_MEMMANAGE 1u
#define MDK_TRACE_FAULT_CLASS_BUS       2u
#define MDK_TRACE_FAULT_CLASS_USAGE     3u

/* Reserved ids for the register dump that follows a FAULT record. They are
 * ordinary counter events so both backends carry them with no extra code, and
 * the 0xFF00.. range is reserved: application ids must stay below 0xFE00. */
#define MDK_TRACE_FAULT_REG_PC     0xFF01u
#define MDK_TRACE_FAULT_REG_LR     0xFF02u
#define MDK_TRACE_FAULT_REG_SP     0xFF03u
#define MDK_TRACE_FAULT_REG_HFSR   0xFF04u
#define MDK_TRACE_FAULT_REG_MMFAR  0xFF05u
#define MDK_TRACE_FAULT_REG_BFAR   0xFF06u
#define MDK_TRACE_FAULT_REG_XPSR   0xFF07u

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

/* Context switch hook. Put it in the scheduler, right where the outgoing task
 * is replaced by the incoming one - not in the tick handler, or the trace will
 * claim a switch happened on every tick even when the same task continued. */
#define MDK_TRACE_SCHED(from, to)  do { mdk_trace_sched((from), (to)); } while (0)

/* Synchronisation object hooks. Put WAIT/SIGNAL around the blocking and
 * releasing operations of your kernel, and ACQUIRE/RELEASE where ownership
 * moves. "val" is free form (waiter count, timeout in ticks, owning task). */
#define MDK_TRACE_SYNC(obj, op, val) do { mdk_trace_sync((obj), (op), (val)); } while (0)
#define MDK_TRACE_OBJ_WAIT(obj, val)     MDK_TRACE_SYNC((obj), MDK_TRACE_SYNC_WAIT, (val))
#define MDK_TRACE_OBJ_SIGNAL(obj, val)   MDK_TRACE_SYNC((obj), MDK_TRACE_SYNC_SIGNAL, (val))
#define MDK_TRACE_OBJ_TIMEOUT(obj, val)  MDK_TRACE_SYNC((obj), MDK_TRACE_SYNC_TIMEOUT, (val))
#define MDK_TRACE_OBJ_ACQUIRE(obj, val)  MDK_TRACE_SYNC((obj), MDK_TRACE_SYNC_ACQUIRE, (val))
#define MDK_TRACE_OBJ_RELEASE(obj, val)  MDK_TRACE_SYNC((obj), MDK_TRACE_SYNC_RELEASE, (val))
#define MDK_TRACE_HEAP_CHANGE(op, size)  do { mdk_trace_heap((op), (size)); } while (0)

/* Fault snapshot. GCC / Clang / ARMClang (AC6) read the registers inline.
 * ARMCC 5 cannot: its inline assembler rejects lr/r14 as an operand, and
 * "register uint32_t x __asm(\"lr\")" is silently given a normal register
 * (it emits STR r0, not MOV r0, lr), so the values would be invented. There
 * the snapshot degrades to "class + CFSR only" - use
 * mdk_trace_fault_capture(exc, msp, psp) from an assembly vector thunk when
 * the full frame is needed on AC5. */
#if defined(__CC_ARM) && !defined(__clang__)
#  define MDK_TRACE_FAULT_CAPTURE()  mdk_trace_fault(0u, 0u)
#elif defined(__arm__) || defined(__ARM_ARCH) || defined(__ARMCC_VERSION)
#  define MDK_TRACE_FAULT_CAPTURE()                                           \
    do {                                                                      \
        uint32_t mdk_tr_lr_, mdk_tr_msp_, mdk_tr_psp_;                        \
        __asm volatile ("MOV %0, LR"      : "=r" (mdk_tr_lr_));               \
        __asm volatile ("MRS %0, MSP"     : "=r" (mdk_tr_msp_));              \
        __asm volatile ("MRS %0, PSP"     : "=r" (mdk_tr_psp_));              \
        mdk_trace_fault_capture(mdk_tr_lr_, mdk_tr_msp_, mdk_tr_psp_);        \
    } while (0)
#else
#  define MDK_TRACE_FAULT_CAPTURE()  mdk_trace_fault(0u, 0u)
#endif

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
