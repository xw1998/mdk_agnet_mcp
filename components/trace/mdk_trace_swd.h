/* mdk_trace_swd.h - SWD seamless stream trace backend.
 *
 * ITM / SWO needs a pin and RTT needs the host to poll constantly. When all
 * you have is the two SWD wires and you still want one continuous, lossless
 * recording of a whole run, the only way left is: the target compresses events
 * into a RAM ring, the host drains the encoded bytes over SWD in slices and
 * writes back how far it has read. The ring then recycles, and as long as the
 * host's average drain rate keeps up with the event rate, the recording never
 * ends and never loses anything. That is what "seamless" means here.
 *
 * Two properties carry the design:
 *
 *   1. Back-pressure, not overwrite. When the ring is full the target DROPS
 *      the new event and counts it; it never overwrites the region the host
 *      has not read yet. Recorded data is therefore never corrupted mid-way.
 *      The price is that a slow host loses events - reported honestly as
 *      lost_events, never silently.
 *
 *   2. Compression. A flat 12-byte record per event cannot be pushed through
 *      a debug link. Event streams are extremely repetitive in their
 *      (type, kind, id, arg) tuple, so a 64-slot direct-mapped dictionary plus
 *      LEB128 varints brings a typical event down to 2 bytes.
 *
 * The host only needs ONE symbol: mdk_trace_swd_blob. The control block sits
 * at its base and the ring follows immediately after (ring_off == ctrl size).
 *
 * This file is deliberately self-contained (stdint.h only) so the same source
 * can be compiled on a PC and byte-for-byte compared against the Python
 * reference implementation in tools/.
 */

#ifndef MDK_TRACE_SWD_H
#define MDK_TRACE_SWD_H

#include <stdint.h>

#define MDK_TRACE_SWD_MAGIC_STR   "MDKSWD1"
#define MDK_TRACE_SWD_VERSION     1u
#define MDK_TRACE_SWD_NSLOT       64u
#define MDK_TRACE_SWD_CTRL_BYTES  80u
#define MDK_TRACE_SWD_RESERVE     16u   /* bytes kept free for CTL tokens */

/* Ring capacity in bytes. Must be a power of two (the index is masked, not
 * divided). 8 KB holds roughly 3400 events at ~2.35 bytes each. */
#ifndef MDK_TRACE_SWD_BYTES
#define MDK_TRACE_SWD_BYTES       8192u
#endif

#if ((MDK_TRACE_SWD_BYTES & (MDK_TRACE_SWD_BYTES - 1u)) != 0u)
#error "MDK_TRACE_SWD_BYTES must be a power of two"
#endif

/* dt is (DWT cycles >> TS_SHIFT). 0 keeps the finest possible resolution; a
 * single gap longer than 2^32 cycles (51 s at 84 MHz) needs it raised. */
#ifndef MDK_TRACE_SWD_TS_SHIFT
#define MDK_TRACE_SWD_TS_SHIFT    0u
#endif

#ifndef MDK_TRACE_SWD_CPU_HZ
#define MDK_TRACE_SWD_CPU_HZ      0u
#endif

#define MDK_TRACE_SWD_FLAG_ENABLED    (1u << 0)
#define MDK_TRACE_SWD_FLAG_SEQ_KNOWN  (1u << 1)

/* One token tag lives in the top two bits of the first byte of a token. */
#define MDK_TRACE_SWD_TAG_HIT   0u   /* [00|slot]                      varint(dt) */
#define MDK_TRACE_SWD_TAG_LIT   1u   /* [01|000000] type kind id varint(arg) varint(dt) */
#define MDK_TRACE_SWD_TAG_CTL   2u   /* [10|subcmd]                    <payload> */
#define MDK_TRACE_SWD_TAG_RSV   3u

/* CTL sub-commands. */
#define MDK_TRACE_SWD_CTL_SYNC  0u   /* payload: varint(seq) */
#define MDK_TRACE_SWD_CTL_LOST  1u   /* payload: varint(events dropped here) */

/* Event types, kept in sync with mdk_trace.h so the host decodes both the
 * same way. */
#define MDK_TRACE_SWD_T_RAW      0u
#define MDK_TRACE_SWD_T_TEXT     1u
#define MDK_TRACE_SWD_T_EVENT    2u
#define MDK_TRACE_SWD_T_COUNTER  3u
#define MDK_TRACE_SWD_T_ISR      4u
#define MDK_TRACE_SWD_T_MARK     5u
#define MDK_TRACE_SWD_T_TS       6u
#define MDK_TRACE_SWD_T_KV       7u
#define MDK_TRACE_SWD_T_RESET    8u
#define MDK_TRACE_SWD_T_FAULT    9u
#define MDK_TRACE_SWD_T_SCHED   10u

/* Kinds. */
#define MDK_TRACE_SWD_K_ENTER    0u
#define MDK_TRACE_SWD_K_EXIT     1u
#define MDK_TRACE_SWD_K_POINT    2u
#define MDK_TRACE_SWD_K_ABORT    3u

/* Fault classes, encoded in the id field as 0xFE00 | class. */
#define MDK_TRACE_SWD_FAULT_BASE 0xFE00u
#define MDK_TRACE_SWD_FAULT_HARD     0u
#define MDK_TRACE_SWD_FAULT_MEMMANAGE 1u
#define MDK_TRACE_SWD_FAULT_BUS      2u
#define MDK_TRACE_SWD_FAULT_USAGE    3u

/* Register ids emitted by MDK_TRACE_SWD_FAULT_CAPTURE(); 0xFF01.. follows the
 * same numbering mdk_trace.h uses, so the host decodes both the same way. */
#define MDK_TRACE_SWD_REG_PC     0xFF01u
#define MDK_TRACE_SWD_REG_LR     0xFF02u
#define MDK_TRACE_SWD_REG_SP     0xFF03u
#define MDK_TRACE_SWD_REG_HFSR   0xFF04u
#define MDK_TRACE_SWD_REG_MMFAR  0xFF05u
#define MDK_TRACE_SWD_REG_BFAR   0xFF06u
#define MDK_TRACE_SWD_REG_XPSR   0xFF07u
#define MDK_TRACE_SWD_REG_CFSR   0xFF08u

/* Control block: exactly 80 bytes, read by the host with a single SWD read.
 *
 * head and drained are LOGICAL byte cursors that wrap naturally modulo 2^32;
 * the physical index is (cursor & (cap - 1)). Because 2^32 is a multiple of
 * any power-of-two cap, wrapping never breaks the index maths - which is why
 * cap must stay a power of two.
 *
 * lost_events / lost_bytes are deliberately two fields: they carry different
 * units and sharing one name would silently mix them downstream.
 *
 * reset_req is the host's "start a new recording" handshake, in the same
 * spirit as the buff backend's: the host sets it, the target acts on it at
 * its next event. It lives here rather than in a helper function because the
 * host can only write memory - it cannot call anything on the target. It is
 * also the ONLY way to resynchronise: HIT tokens carry a slot number, so a
 * host whose dictionary has drifted would decode every later event to the
 * WRONG key. Clearing both dictionaries at once is the only correct fix, and
 * only the target can trigger it. */
typedef struct {
    uint8_t  magic[8];
    uint16_t version;
    uint16_t ctrl_bytes;
    uint32_t cap;            /* ring capacity in bytes */
    uint32_t ring_off;       /* ring offset inside the blob (== ctrl_bytes) */
    uint32_t head;           /* logical write cursor; always on a token boundary */
    uint32_t drained;        /* logical read cursor; the HOST advances this */
    uint32_t lost_events;    /* events dropped because the host fell behind */
    uint32_t lost_bytes;     /* bytes those dropped events would have used */
    uint32_t events;         /* events successfully encoded */
    uint32_t tokens;         /* tokens written (>= events / 1) */
    uint32_t seq;            /* recording sequence number, bumped per init */
    uint32_t ts_shift;       /* dt is DWT cycles >> ts_shift */
    uint32_t cpu_hz;         /* core clock, for turning cycles into seconds */
    uint32_t cycles;         /* absolute DWT cycle of the most recent event */
    uint32_t flags;
    uint32_t reset_req;      /* host -> target: 1 asks for a fresh recording */
    uint32_t reserved[3];    /* pads the block out to exactly ctrl_bytes */
} mdk_trace_swd_ctrl_t;

/* Offset of reset_req inside the control block, for hosts that write it by
 * address instead of by struct. */
#define MDK_TRACE_SWD_RESET_REQ_OFF 64u

/* The whole thing. The host locates "mdk_trace_swd_blob", reads the control
 * block, then reads (cap) bytes starting at blob + ring_off. */
typedef struct {
    mdk_trace_swd_ctrl_t ctrl;
    uint8_t ring[MDK_TRACE_SWD_BYTES];
} mdk_trace_swd_blob_t;

extern mdk_trace_swd_blob_t mdk_trace_swd_blob;

/* ------------------------------------------------------------------ API */

/* Initialise the backend. Safe to call more than once. Clears the ring and
 * starts a new recording sequence unless MDK_TRACE_SWD_CLEAR_ON_INIT is 0. */
void mdk_trace_swd_init(void);

/* Record one event. Cheap, reentrancy-safe (guarded by a critical section)
 * and allocation-free, so it is fine to call from an ISR. */
void mdk_trace_swd_event(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg);

/* Bytes waiting to be drained. The host can compute this itself from the
 * control block; this is for target-side diagnostics. */
uint32_t mdk_trace_swd_pending(void);

/* True (and clears the flag) when the host has asked for a new recording.
 * Called from the event path, so the request takes effect as soon as the
 * target produces its next event - never immediately. */
uint32_t mdk_trace_swd_take_reset_req(void);

/* Start a new recording marker in the stream without clearing history. */
void mdk_trace_swd_restart(uint32_t seq);

/* ------------------------------------------------------------- helpers */

#define MDK_TRACE_SWD_MARK(id)          mdk_trace_swd_event(MDK_TRACE_SWD_T_MARK, MDK_TRACE_SWD_K_POINT, (uint16_t)(id), 0u)
#define MDK_TRACE_SWD_KV(id, v)         mdk_trace_swd_event(MDK_TRACE_SWD_T_KV, MDK_TRACE_SWD_K_POINT, (uint16_t)(id), (uint32_t)(v))
#define MDK_TRACE_SWD_COUNTER(id, v)    mdk_trace_swd_event(MDK_TRACE_SWD_T_COUNTER, MDK_TRACE_SWD_K_POINT, (uint16_t)(id), (uint32_t)(v))
#define MDK_TRACE_SWD_SCOPE_BEGIN(id)   mdk_trace_swd_event(MDK_TRACE_SWD_T_EVENT, MDK_TRACE_SWD_K_ENTER, (uint16_t)(id), 0u)
#define MDK_TRACE_SWD_SCOPE_END(id)     mdk_trace_swd_event(MDK_TRACE_SWD_T_EVENT, MDK_TRACE_SWD_K_EXIT, (uint16_t)(id), 0u)
#define MDK_TRACE_SWD_ISR_ENTER(id)     mdk_trace_swd_event(MDK_TRACE_SWD_T_ISR, MDK_TRACE_SWD_K_ENTER, (uint16_t)(id), 0u)
#define MDK_TRACE_SWD_ISR_EXIT(id)      mdk_trace_swd_event(MDK_TRACE_SWD_T_ISR, MDK_TRACE_SWD_K_EXIT, (uint16_t)(id), 0u)

/* from / to are 4-bit task ids packed into arg; 0x0F means "idle". */
#define MDK_TRACE_SWD_SCHED(from, to)   mdk_trace_swd_event(MDK_TRACE_SWD_T_SCHED, MDK_TRACE_SWD_K_POINT, 0u, \
    ((((uint32_t)(from)) & 0x0Fu) << 4) | (((uint32_t)(to)) & 0x0Fu))

#define MDK_TRACE_SWD_FAULT(cls, cfsr)  mdk_trace_swd_event(MDK_TRACE_SWD_T_FAULT, MDK_TRACE_SWD_K_ABORT, \
    (uint16_t)(MDK_TRACE_SWD_FAULT_BASE | ((uint32_t)(cls) & 0xFFu)), (uint32_t)(cfsr))

/* Capture the fault the way a debugger would: the exception frame holds the
 * address that was running and the values of the registers at the time. Must
 * be called as the FIRST statement of the handler - once you push another
 * frame or call anything, the frame you are standing on is no longer the one
 * that faulted. */
#define MDK_TRACE_SWD_FAULT_CAPTURE()   mdk_trace_swd_fault_capture()

void mdk_trace_swd_fault_capture(void);

#endif /* MDK_TRACE_SWD_H */
