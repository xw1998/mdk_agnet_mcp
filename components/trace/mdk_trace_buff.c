/* mdk_trace_buff.c - RAM ring buffer backend ("buff mode").
 *
 * The whole point of this file is that it is boring. One append path made of
 * a few stores, no branching on peripheral state, no allocation, no locking
 * primitives, no calls out to anything. That is what lets the instrumented
 * code keep running at full speed while it is being recorded.
 *
 * Consequences that the host is told about rather than left to discover:
 *   - when the ring wraps the oldest records are gone -> ctrl.flags gets
 *     FLAG_WRAPPED and ctrl.total keeps counting, so the host can tell
 *     "capped at N" from "only N events happened";
 *   - a record with a broken timestamp is worse than a missing record, so
 *     when there is no time base (DWT off, mcycle unavailable) the record is
 *     dropped and ctrl.lost is bumped;
 *   - text and raw frames cannot be represented in a 12 byte record, so they
 *     are dropped and counted in ctrl.text_dropped.
 *
 * ASCII only, see mdk_trace.h for the reason.
 */

#include "mdk_trace.h"

#if MDK_TRACE_ENABLE && MDK_TRACE_BACKEND_BUFF

#include "mdk_trace_buff.h"

/* ------------------------------------------------------------ state */

/* The host locates the entire buffer through this ONE symbol: control block
 * at its start, record array right behind it at ctrl + CTRL_BYTES. It has to
 * be defined here (not declared only in the header) or nothing links -- this
 * is the same contract mdk_trace_swd.c keeps for mdk_trace_swd_blob. */
mdk_trace_buff_blob_t mdk_trace_buff_blob;

static void _zero_bytes(void *dst, uint32_t n)
{
    uint8_t *p = (uint8_t *)dst;

    while (n-- > 0u) {
        *p++ = 0u;
    }
}

static void _magic_copy(void)
{
    static const char m[MDK_TRACE_BUFF_MAGIC_LEN] = MDK_TRACE_BUFF_MAGIC_STR;
    uint32_t i;

    for (i = 0u; i < MDK_TRACE_BUFF_MAGIC_LEN; i++) {
        mdk_trace_buff_blob.ctrl.magic[i] = m[i];
    }
}

/* Declared here rather than pulled from mdk_trace.h so this backend also
 * compiles when the core is built with a different backend selected. */
uint32_t mdk_trace_now(void);

static int _is_live_buffer(void)
{
    static const char m[MDK_TRACE_BUFF_MAGIC_LEN] = MDK_TRACE_BUFF_MAGIC_STR;
    uint32_t i;

    for (i = 0u; i < MDK_TRACE_BUFF_MAGIC_LEN; i++) {
        if (mdk_trace_buff_blob.ctrl.magic[i] != m[i]) {
            return 0;
        }
    }
    /* Same magic bytes but a different build: the layout may have moved, so
     * treat it as garbage rather than parse somebody else's struct. */
    if (mdk_trace_buff_blob.ctrl.version != MDK_TRACE_BUFF_VERSION) {
        return 0;
    }
    if (mdk_trace_buff_blob.ctrl.cap != (uint32_t)MDK_TRACE_BUFF_RECORDS) {
        return 0;
    }
    if (mdk_trace_buff_blob.ctrl.rec_size != MDK_TRACE_BUFF_REC_SIZE) {
        return 0;
    }
    return 1;
}

static void _cold_start(void)
{
    _zero_bytes(&mdk_trace_buff_blob.ctrl, MDK_TRACE_BUFF_CTRL_BYTES);
    _zero_bytes(mdk_trace_buff_blob.recs, (uint32_t)sizeof(mdk_trace_buff_blob.recs));

    _magic_copy();
    mdk_trace_buff_blob.ctrl.version  = MDK_TRACE_BUFF_VERSION;
    mdk_trace_buff_blob.ctrl.rec_size = MDK_TRACE_BUFF_REC_SIZE;
    mdk_trace_buff_blob.ctrl.cap      = MDK_TRACE_BUFF_RECORDS;
    mdk_trace_buff_blob.ctrl.recs_addr =
        (uint32_t)(uintptr_t)&mdk_trace_buff_blob.recs[0][0];
    mdk_trace_buff_blob.ctrl.ts_shift = MDK_TRACE_BUFF_TS_SHIFT;
    mdk_trace_buff_blob.ctrl.cpu_hz   = MDK_TRACE_CPU_HZ;
    mdk_trace_buff_blob.ctrl.flags    = MDK_TRACE_BUFF_FLAG_ENABLED;
    mdk_trace_buff_blob.ctrl.seq      = 1u;
}

void mdk_trace_buff_init(void)
{
#if MDK_TRACE_BUFF_CLEAR_ON_INIT
    _cold_start();
#else
    if (_is_live_buffer()) {
        /* Warm start: the records from before the reset are the interesting
         * ones, so only re-arm. last_cycles is re-based so the first record
         * of this session gets a sane dt instead of a wrapped one, and the
         * RESET record the core sends right after init() marks the seam. */
        mdk_trace_buff_blob.ctrl.flags |= MDK_TRACE_BUFF_FLAG_RESTARTED;
        mdk_trace_buff_blob.ctrl.flags |= MDK_TRACE_BUFF_FLAG_ENABLED;
        mdk_trace_buff_blob.ctrl.reset_req = 0u;
        mdk_trace_buff_blob.ctrl.last_cycles =
#if MDK_TRACE_USE_DWT
            mdk_trace_now();
#else
            0u;
#endif
        mdk_trace_buff_blob.ctrl.seq++;
        return;
    }
    _cold_start();
#endif

    /* Re-base the time origin. Nothing has been recorded yet, so the next
     * record's dt is measured from here rather than from a counter that may
     * already have been running for hours. */
#if MDK_TRACE_USE_DWT
    mdk_trace_buff_blob.ctrl.last_cycles = mdk_trace_now();
#endif
}

void mdk_trace_buff_reset(void)
{
    mdk_trace_buff_blob.ctrl.head        = 0u;
    mdk_trace_buff_blob.ctrl.total       = 0u;
    mdk_trace_buff_blob.ctrl.lost        = 0u;
    mdk_trace_buff_blob.ctrl.text_dropped = 0u;
    mdk_trace_buff_blob.ctrl.last_cycles = 0u;
    mdk_trace_buff_blob.ctrl.flags       = MDK_TRACE_BUFF_FLAG_ENABLED;
    mdk_trace_buff_blob.ctrl.reset_req   = 0u;
    mdk_trace_buff_blob.ctrl.seq++;
}

void mdk_trace_buff_put(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg)
{
    mdk_trace_buff_ctrl_t *c = &mdk_trace_buff_blob.ctrl;
    uint8_t *r;
    uint32_t now, dt, slot;

    /* The host asks for a fresh run by setting reset_req. Honouring it here,
     * inside the one function every record goes through, is as close to
     * atomic as it gets without disabling interrupts - and it can never
     * corrupt the ring, at worst it drops records that were in flight. */
    if (c->reset_req != 0u) {
        mdk_trace_buff_reset();
    }

#if MDK_TRACE_USE_DWT
    now = mdk_trace_now();
    dt  = now - c->last_cycles;
#else
    /* No time base at all: refuse to fabricate one. A record whose timestamp
     * is made up silently corrupts every gap measured after it. */
    now = 0u;
    dt  = 0u;
    c->lost++;
    return;
#endif

    slot = c->head;
    r = &mdk_trace_buff_blob.recs[slot][0];

    r[0] = type;
    r[1] = kind;
    r[2] = (uint8_t)(id & 0xFFu);
    r[3] = (uint8_t)((id >> 8) & 0xFFu);
    /* Little endian payload, same byte order the MTF frames use, so one host
     * parser can serve both modes. */
    r[4] = (uint8_t)(arg & 0xFFu);
    r[5] = (uint8_t)((arg >> 8) & 0xFFu);
    r[6] = (uint8_t)((arg >> 16) & 0xFFu);
    r[7] = (uint8_t)((arg >> 24) & 0xFFu);

    dt = dt >> MDK_TRACE_BUFF_TS_SHIFT;
    r[8]  = (uint8_t)(dt & 0xFFu);
    r[9]  = (uint8_t)((dt >> 8) & 0xFFu);
    r[10] = (uint8_t)((dt >> 16) & 0xFFu);
    r[11] = (uint8_t)((dt >> 24) & 0xFFu);

    c->last_cycles = now;

    slot++;
    if (slot >= c->cap) {
        slot = 0u;
        /* Ring is full: the slot we are about to reuse held the oldest record,
         * so from here on the history is a window, not the whole run. */
        if (c->total >= c->cap) {
            c->flags |= MDK_TRACE_BUFF_FLAG_WRAPPED;
        }
    }
    c->head  = slot;
    c->total++;
}

void mdk_trace_buff_note_unsupported(void)
{
    mdk_trace_buff_blob.ctrl.text_dropped++;
}

uint32_t mdk_trace_buff_total(void)
{
    return mdk_trace_buff_blob.ctrl.total;
}

uint32_t mdk_trace_buff_lost(void)
{
    return mdk_trace_buff_blob.ctrl.lost + mdk_trace_buff_blob.ctrl.text_dropped;
}

uint32_t mdk_trace_buff_capacity(void)
{
    return mdk_trace_buff_blob.ctrl.cap;
}

#endif /* MDK_TRACE_ENABLE && MDK_TRACE_BACKEND_BUFF */
