/* mdk_trace_buff.h - RAM ring buffer backend for the mdk_trace component.
 *
 * WHY THIS EXISTS
 * ---------------
 * The ITM / RTT / UART backends are *stream* backends: every event leaves the
 * chip as soon as it happens, and the host has to keep up. That is the right
 * shape when you want to watch a live system, and the wrong shape when you
 * want to know exactly what happened at full speed:
 *
 *   - a stream backend is bandwidth limited, so at high event rates it drops;
 *   - RTT/UART reads steal time from the target;
 *   - SWO needs a pin most boards do not have wired.
 *
 * This backend is the *buff* mode: events go into a statically allocated ring
 * buffer in RAM and nothing leaves the chip. The core never waits, never
 * blocks, never touches a peripheral. When the run is over the host reads the
 * buffer out in one go through the debug probe.
 *
 * What you pay for it: the buffer is finite (cap records), the newest records
 * overwrite the oldest once it wraps, and text frames are not supported
 * (a 12 byte record cannot carry a string). All three are reported, never
 * silently swallowed.
 *
 * RECORD FORMAT (12 bytes, little endian):
 *
 *   0  u8   type      event class, same numbering as MTF types
 *   1  u8   kind      enter / exit / point / abort
 *   2  u16  id        event id chosen by the application
 *   4  u32  arg       free form payload
 *   8  u32  dt        cycles since the previous record, right shifted by
 *                     MDK_TRACE_BUFF_TS_SHIFT
 *
 * Storing the *difference* instead of an absolute timestamp is what makes the
 * record this small. With MDK_TRACE_BUFF_TS_SHIFT == 0 (the default) the time
 * resolution is one CPU cycle - 11.9 ns on a 84 MHz part - which is the
 * finest any instrumented trace can offer. Raise the shift only if a single
 * gap between two records can exceed 2^32 cycles (51 s at 84 MHz).
 *
 * The host finds the buffer through one symbol, `mdk_trace_buff_blob`, and
 * reads the control block described below. Everything the host needs - the
 * record array address, the capacity, the wrap state, the lost counters - is
 * in there, so a single symbol lookup is enough and no linker map digging is
 * needed.
 *
 * ASCII only, see mdk_trace.h for the reason.
 */

#ifndef MDK_TRACE_BUFF_H
#define MDK_TRACE_BUFF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MDK_TRACE_BUFF_MAGIC_STR  "MDKTBUF1"
#define MDK_TRACE_BUFF_MAGIC_LEN  8
#define MDK_TRACE_BUFF_VERSION    1u
#define MDK_TRACE_BUFF_REC_SIZE   12u

/* Control block field offsets. The host side (mdkdebug/trace.py) hard codes
 * these, so they must only ever change together with the host parser. */
#define MDK_TRACE_BUFF_CTRL_BYTES 80u

#define MDK_TRACE_BUFF_FLAG_ENABLED  (1u << 0)
#define MDK_TRACE_BUFF_FLAG_WRAPPED  (1u << 1)
/* Set when init() found a live buffer from before a reset and kept it. The
 * records are still meaningful, but the timeline has a hole in it where the
 * reset happened; the host marks it instead of pretending time is continuous. */
#define MDK_TRACE_BUFF_FLAG_RESTARTED (1u << 2)

/* Reserved event id ranges. Application ids must stay below 0xFE00. */
#define MDK_TRACE_ID_FAULT_BASE    0xFE00u   /* fault class in the FAULT record */
#define MDK_TRACE_ID_FAULT_REG     0xFF00u   /* 0xFF01.. = fault register dump  */

/* The MDK_TRACE_FAULT_REG_* ids used by mdk_trace_fault_capture() live in
 * mdk_trace.h: they are event semantics, not something the buff backend
 * invents, and a stream build emits exactly the same ids. */

/* ------------------------------------------------------------------ control
 * Layout is fixed and mirrored by the host. Adding a field means bumping
 * MDK_TRACE_BUFF_VERSION and teaching the host parser about it.
 */
typedef struct {
    char     magic[MDK_TRACE_BUFF_MAGIC_LEN];  /* 0  "MDKTBUF1"            */
    uint32_t version;                          /* 8                        */
    uint32_t rec_size;                         /* 12 must equal 12         */
    uint32_t cap;                              /* 16 record slots          */
    uint32_t recs_addr;                        /* 20 address of the array  */
    uint32_t head;                             /* 24 next slot to write    */
    uint32_t total;                            /* 28 records ever written  */
    uint32_t lost;                             /* 32 no time base / resume */
    uint32_t text_dropped;                     /* 36 text/raw frames seen  */
    uint32_t ts_shift;                         /* 40 dt right shift        */
    uint32_t cpu_hz;                           /* 44 cycles per second     */
    uint32_t last_cycles;                      /* 48 newest timestamp      */
    uint32_t flags;                            /* 52 see FLAG_ above       */
    uint32_t reset_req;                        /* 56 host writes 1 = clear */
    uint32_t seq;                              /* 60 reset generation      */
    uint32_t reserved[4];                      /* 64 keep at 80 bytes      */
} mdk_trace_buff_ctrl_t;

/* Statically allocated so the address is fixed after linking: the host finds
 * `mdk_trace_buff_blob`, reads the control block at its start, and reads the
 * record array at ctrl + MDK_TRACE_BUFF_CTRL_BYTES. One symbol lookup is all
 * it takes - no linker map digging, no second address to keep in sync. */
typedef struct {
    mdk_trace_buff_ctrl_t ctrl;
    uint8_t recs[MDK_TRACE_BUFF_RECORDS][MDK_TRACE_BUFF_REC_SIZE];
} mdk_trace_buff_blob_t;

extern mdk_trace_buff_blob_t mdk_trace_buff_blob;

/* ---------------------------------------------------------------- lifecycle
 * Called by mdk_trace_init(); safe to call twice. buff_init() also clears the
 * buffer, so a target that re-runs init starts from an empty history instead
 * of mixing two runs.
 */
void mdk_trace_buff_init(void);
void mdk_trace_buff_reset(void);

/* Append one record. Non-blocking, no branches on peripheral state: this is
 * the only place the target pays for buff mode, and it is a handful of
 * stores. Dropped (not recorded) when the time base is missing, because a
 * record without a usable timestamp silently corrupts every gap after it.
 */
void mdk_trace_buff_put(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg);

/* Text / raw frames cannot be represented in a 12 byte record. The core calls
 * this so the host can report "N frames were not representable" instead of
 * quietly showing a trace that looks complete but is not. */
void mdk_trace_buff_note_unsupported(void);

/* Health, for on-target assertions or a shell command. */
uint32_t mdk_trace_buff_total(void);
uint32_t mdk_trace_buff_lost(void);
uint32_t mdk_trace_buff_capacity(void);

#ifdef __cplusplus
}
#endif

#endif /* MDK_TRACE_BUFF_H */
