/* mdk_trace_swd.c - SWD seamless stream trace backend.
 *
 * Byte-for-byte compatible with tools/swd_codec.py (the reference
 * implementation). Keep the two in step: run the host-side comparison after
 * touching either one.
 *
 * Everything here is allocation-free and bounded, so it is safe to call from
 * an ISR. The only shared state between target and host is the control block
 * and the ring, both inside mdk_trace_swd_blob.
 *
 * Compiler note: the fault snapshot reads EXC_RETURN with inline assembly that
 * only GCC / Clang / armclang (AC6) accept. Under Keil ARMCC 5 that read is
 * impossible from C, so the SWD fault entry point degrades to class + CFSR.
 * See MDK_TRACE_SWD_FAULT_CAPTURE below.
 */

#include "mdk_trace_swd.h"

/* The host reads exactly ctrl_bytes and then jumps to blob + ring_off. If the
 * struct ever drifts from the published size, that read lands in the wrong
 * place and every field after it is garbage - so fail the build, loudly. */
typedef char swd_ctrl_size_check[
    (sizeof(mdk_trace_swd_ctrl_t) == MDK_TRACE_SWD_CTRL_BYTES) ? 1 : -1];

/* ------------------------------------------------------------ platform */

#if defined(MDK_TRACE_SWD_HOSTTEST)

/* On a PC the time source and the critical section come from the test driver,
 * so the encoder can be compared against the Python model head to head. */
extern uint32_t mdk_trace_swd_test_now(void);
extern uint32_t mdk_trace_swd_test_crit_enter(void);
extern void     mdk_trace_swd_test_crit_exit(uint32_t pm);
#define SWD_NOW()          mdk_trace_swd_test_now()
#define SWD_CRIT_ENTER()   mdk_trace_swd_test_crit_enter()
#define SWD_CRIT_EXIT(pm)  mdk_trace_swd_test_crit_exit(pm)

#elif defined(MDK_TRACE_SWD_EXTERNAL_PLATFORM)

/* The host project supplies the four platform primitives through its own
 * header: SWD_NOW(), SWD_CRIT_ENTER(), SWD_CRIT_EXIT(pm), and the fault
 * status register addresses SWD_SCB_CFSR / HFSR / MMFAR / BFAR.
 *
 * Use this when the kernel must not pull in a vendor CMSIS header to get
 * __get_PRIMASK()/__get_PSP(), or when the project already has its own
 * critical section macro. Same contract as the built-in path: SWD_CRIT_ENTER
 * returns a value that SWD_CRIT_EXIT takes to restore the previous state, and
 * SWD_NOW() must be a plain load (it is called from an ISR). */
#include "mdk_trace_swd_platform.h"

#else

/* DWT cycle counter. Enabled by the trace component's init path; reading it
 * is a plain load, which is what makes the timestamps cheap enough to take
 * inside an ISR. */
#define SWD_DWT_CYCCNT     (*((volatile uint32_t *)0xE0001004u))
#define SWD_SCB_CFSR       (*((volatile uint32_t *)0xE000ED28u))
#define SWD_SCB_HFSR       (*((volatile uint32_t *)0xE000ED2Cu))
#define SWD_SCB_MMFAR      (*((volatile uint32_t *)0xE000ED34u))
#define SWD_SCB_BFAR       (*((volatile uint32_t *)0xE000ED38u))

#define SWD_NOW()          (SWD_DWT_CYCCNT)

static uint32_t swd_crit_enter(void)
{
    uint32_t pm = __get_PRIMASK();
    __disable_irq();
    return pm;
}
#define SWD_CRIT_ENTER()   swd_crit_enter()
#define SWD_CRIT_EXIT(pm)  __set_PRIMASK(pm)

/* Stack pointer accessors used by the fault snapshot. Kept as macros so a
 * project without CMSIS can override them the same way it overrides the
 * critical section. */
#define SWD_PSP()          __get_PSP()
#define SWD_MSP()          __get_MSP()

#endif

#ifndef MDK_TRACE_SWD_CLEAR_ON_INIT
#define MDK_TRACE_SWD_CLEAR_ON_INIT  1
#endif

/* ------------------------------------------------------------ state */

mdk_trace_swd_blob_t mdk_trace_swd_blob;

static uint64_t s_slot_key[MDK_TRACE_SWD_NSLOT];
static uint8_t  s_slot_used[MDK_TRACE_SWD_NSLOT];
static uint32_t s_last_cycles;
static uint32_t s_pending_lost;

/* ------------------------------------------------------------ encoder */

/* Pack (type, kind, id, arg) into one comparable 64-bit value. 54 bits are
 * used; the rest stays zero so equality is a single compare. */
static uint64_t swd_pack(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg)
{
    return ((uint64_t)(type & 0x0Fu) << 50)
         | ((uint64_t)(kind & 0x03u) << 48)
         | ((uint64_t)id << 32)
         | (uint64_t)arg;
}

/* Direct-mapped slot, O(1) and fixed cost - no linear probing, because this
 * runs inside ISRs and the timing has to be predictable.
 *
 * Must match slot_of() in tools/swd_codec.py exactly. */
static uint8_t swd_slot_of(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg)
{
    uint32_t x = (uint32_t)type * 0x9E3779B1u
               + (uint32_t)kind * 0x85EBCA6Bu
               + (uint32_t)id   * 0xC2B2AE35u
               + arg;
    x ^= x >> 13;
    x ^= x >> 23;
    return (uint8_t)(x & (MDK_TRACE_SWD_NSLOT - 1u));
}

static uint32_t swd_varint_put(uint8_t *p, uint32_t v)
{
    uint32_t n = 0u;
    do {
        uint8_t b = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v != 0u) { b = (uint8_t)(b | 0x80u); }
        p[n++] = b;
    } while (v != 0u);
    return n;
}

static void swd_dict_clear(void)
{
    uint32_t i;
    for (i = 0u; i < MDK_TRACE_SWD_NSLOT; i++) {
        s_slot_used[i] = 0u;
    }
}

/* Append one token. Returns 0 if it did not fit (in which case, for data
 * tokens, the event is counted as lost).
 *
 * Two limits are in play: ordinary data may not eat into the reserve, while
 * CTL tokens may. The reserve guarantees that a CTL_LOST - the marker that
 * tells the host "your dictionary is stale, drop it" - can always be written,
 * even when the ring is otherwise completely full. */
static uint8_t swd_put(const uint8_t *buf, uint32_t n, uint8_t is_ctl, uint32_t ev_count)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint32_t limit = (is_ctl != 0u) ? c->cap : (c->cap - MDK_TRACE_SWD_RESERVE);
    uint32_t pending = c->head - c->drained;
    uint32_t i;

    if (pending + n > limit) {
        if (is_ctl == 0u) {
            c->lost_events += ev_count;
            c->lost_bytes  += n;
        }
        return 0u;
    }

    for (i = 0u; i < n; i++) {
        mdk_trace_swd_blob.ring[(c->head + i) & (c->cap - 1u)] = buf[i];
    }
    c->head += n;
    if (is_ctl == 0u) {
        c->tokens += 1u;
    }
    return 1u;
}

static void swd_flush_lost(void)
{
    uint8_t buf[6];
    uint32_t n;

    if (s_pending_lost == 0u) { return; }

    buf[0] = (uint8_t)(MDK_TRACE_SWD_TAG_CTL << 6) | (uint8_t)MDK_TRACE_SWD_CTL_LOST;
    n = 1u + swd_varint_put(&buf[1], s_pending_lost);
    if (swd_put(buf, n, 1u, 0u) != 0u) {
        s_pending_lost = 0u;
    }
}

/* ------------------------------------------------------------ API */

/* Wipe the ring and begin a new recording. Must be called inside a critical
 * section (both callers below already are).
 *
 * The CTL_SYNC token is what makes this recovery possible rather than just a
 * data loss: it tells the host "my dictionary is empty from here on", so a
 * host that was decoding HIT tokens against a stale dictionary stops before
 * it produces a single wrong key. */
static void swd_begin_new_recording(void)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint8_t buf[6];
    uint32_t n;

    c->head        = 0u;
    c->drained     = 0u;
    c->lost_events = 0u;
    c->lost_bytes  = 0u;
    c->events      = 0u;
    c->tokens      = 0u;
    c->seq        += 1u;
    c->cycles      = 0u;

    s_last_cycles  = SWD_NOW();
    s_pending_lost = 0u;
    swd_dict_clear();

    buf[0] = (uint8_t)(MDK_TRACE_SWD_TAG_CTL << 6) | (uint8_t)MDK_TRACE_SWD_CTL_SYNC;
    n = 1u + swd_varint_put(&buf[1], c->seq);
    (void)swd_put(buf, n, 1u, 0u);
}

uint32_t mdk_trace_swd_take_reset_req(void)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint32_t pm = SWD_CRIT_ENTER();
    uint32_t req = c->reset_req;

    if (req != 0u) {
        c->reset_req = 0u;
        swd_begin_new_recording();
    }
    SWD_CRIT_EXIT(pm);
    return req;
}

void mdk_trace_swd_event(uint8_t type, uint8_t kind, uint16_t id, uint32_t arg)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint8_t buf[14];
    uint8_t h;
    uint32_t n;
    uint32_t pm;
    uint32_t now;
    uint32_t dt;
    uint64_t key;

    if ((c->flags & MDK_TRACE_SWD_FLAG_ENABLED) == 0u) { return; }

    pm = SWD_CRIT_ENTER();

    /* Honour a pending host request before touching anything else, so the new
     * recording starts clean rather than inheriting half of this batch. */
    if (c->reset_req != 0u) {
        c->reset_req = 0u;
        swd_begin_new_recording();
    }

    /* Timestamps stay on the DWT cycle counter: a 500 us kernel tick as the
     * time base collapses every interesting interval to dt = 0. */
    now = SWD_NOW();
    dt  = now - s_last_cycles;
    s_last_cycles = now;
    c->cycles = now;
    dt >>= MDK_TRACE_SWD_TS_SHIFT;

    /* Report an earlier overflow before encoding anything else, so the host
     * sees the discontinuity in the right place. */
    swd_flush_lost();

    key = swd_pack(type, kind, id, arg);
    h = swd_slot_of(type, kind, id, arg);

    if ((s_slot_used[h] != 0u) && (s_slot_key[h] == key)) {
        buf[0] = (uint8_t)((MDK_TRACE_SWD_TAG_HIT << 6) | h);
        n = 1u + swd_varint_put(&buf[1], dt);
    } else {
        s_slot_key[h]  = key;
        s_slot_used[h] = 1u;
        buf[0] = (uint8_t)(MDK_TRACE_SWD_TAG_LIT << 6);
        buf[1] = (uint8_t)(type & 0x0Fu);
        buf[2] = (uint8_t)(kind & 0x03u);
        buf[3] = (uint8_t)(id & 0xFFu);
        buf[4] = (uint8_t)((id >> 8) & 0xFFu);
        n = 5u;
        n += swd_varint_put(&buf[n], arg);
        n += swd_varint_put(&buf[n], dt);
    }

    if (swd_put(buf, n, 0u, 1u) != 0u) {
        c->events += 1u;
    } else {
        /* The host fell behind. HIT tokens carry only a slot number, so once
         * a LIT disappears the host's dictionary no longer matches ours and
         * every later HIT would decode to the WRONG key - a wrong answer,
         * which is worse than a missing one. Signal the break and resync. */
        s_pending_lost += 1u;
        swd_dict_clear();
    }

    SWD_CRIT_EXIT(pm);
}

uint32_t mdk_trace_swd_pending(void)
{
    return (uint32_t)(mdk_trace_swd_blob.ctrl.head - mdk_trace_swd_blob.ctrl.drained);
}

static uint8_t swd_magic_ok(const mdk_trace_swd_ctrl_t *c)
{
    static const char m[8] = MDK_TRACE_SWD_MAGIC_STR;
    uint32_t i;
    for (i = 0u; i < 8u; i++) {
        if (c->magic[i] != (uint8_t)m[i]) { return 0u; }
    }
    return 1u;
}

void mdk_trace_swd_restart(uint32_t seq)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint8_t buf[6];
    uint32_t pm = SWD_CRIT_ENTER();

    c->seq = seq;
    s_pending_lost = 0u;
    swd_dict_clear();

    buf[0] = (uint8_t)(MDK_TRACE_SWD_TAG_CTL << 6) | (uint8_t)MDK_TRACE_SWD_CTL_SYNC;
    (void)swd_varint_put(&buf[1], seq);
    (void)swd_put(buf, 2u, 1u, 0u);

    SWD_CRIT_EXIT(pm);
}

void mdk_trace_swd_init(void)
{
    mdk_trace_swd_ctrl_t *c = &mdk_trace_swd_blob.ctrl;
    uint32_t pm = SWD_CRIT_ENTER();
    uint32_t i;

    if (swd_magic_ok(c) == 0u) {
        static const char m[8] = MDK_TRACE_SWD_MAGIC_STR;
        for (i = 0u; i < 8u; i++) { c->magic[i] = (uint8_t)m[i]; }
        c->version    = MDK_TRACE_SWD_VERSION;
        c->ctrl_bytes = (uint16_t)MDK_TRACE_SWD_CTRL_BYTES;
        c->cap        = MDK_TRACE_SWD_BYTES;
        c->ring_off   = MDK_TRACE_SWD_CTRL_BYTES;
        c->seq        = 0u;
        c->ts_shift   = MDK_TRACE_SWD_TS_SHIFT;
        c->cpu_hz     = MDK_TRACE_SWD_CPU_HZ;
    }

    c->flags = MDK_TRACE_SWD_FLAG_ENABLED | MDK_TRACE_SWD_FLAG_SEQ_KNOWN;

#if MDK_TRACE_SWD_CLEAR_ON_INIT
    /* A seamless host reads from drained towards head; leaving stale bytes
     * from a previous run in the ring would splice two unrelated runs
     * together with no visible seam - no reset record, no marker, just a
     * timeline that quietly lies. Start clean. */
    swd_begin_new_recording();
#else
    /* Keep the history: bump the sequence, clear the dictionary on both sides
     * and drop a SYNC so the host knows the tokens from here on use a fresh
     * dictionary. Sequence changes without a ring wipe are exactly the case
     * the SYNC token exists for. */
    {
        uint8_t sync[6];
        c->seq += 1u;
        c->cycles = 0u;
        s_last_cycles  = SWD_NOW();
        s_pending_lost = 0u;
        swd_dict_clear();
        sync[0] = (uint8_t)(MDK_TRACE_SWD_TAG_CTL << 6) | (uint8_t)MDK_TRACE_SWD_CTL_SYNC;
        (void)swd_varint_put(&sync[1], c->seq);
        (void)swd_put(sync, 2u, 1u, 0u);
    }
#endif

    SWD_CRIT_EXIT(pm);
}

/* ------------------------------------------------------------ fault */

#if defined(MDK_TRACE_SWD_HOSTTEST)

void mdk_trace_swd_fault_capture(void)
{
    /* Not exercised on the host; the codec is what is being compared. */
}

#elif defined(__CC_ARM) && !defined(__clang__)

void mdk_trace_swd_fault_capture(void)
{
    /* ARMCC 5 cannot read LR from C at all: its inline assembler rejects
     * lr/r14 as an operand, and "register uint32_t x __asm(\"lr\")" is
     * silently bound to a normal register instead - it emits STR r0, not
     * MOV r0, lr. Recording the resulting EXC_RETURN would pick the wrong
     * stack and hand back a plausible but wrong PC, so this entry point
     * reports the fault class and CFSR only.
     *
     * A project that needs the full frame under AC5 reads LR in an assembly
     * vector thunk and calls mdk_trace_fault_capture() itself; see the
     * SVCrtOS STM32F401 board file for a worked example. */
    MDK_TRACE_SWD_FAULT((uint32_t)MDK_TRACE_SWD_FAULT_HARD, SWD_SCB_CFSR);
}

#else

void mdk_trace_swd_fault_capture(void)
{
    /* Read EXC_RETURN straight out of LR. Must happen before this function
     * pushes anything, which is why the macro expands at the top of the
     * handler rather than being called later. */
    register uint32_t lr __asm("lr");
    uint32_t exc_return = lr;
    uint32_t sp = ((exc_return & 0x4u) != 0u) ? SWD_PSP() : SWD_MSP();
    const uint32_t *f = (const uint32_t *)sp;
    uint32_t cfsr  = SWD_SCB_CFSR;
    uint32_t cls   = (uint32_t)MDK_TRACE_SWD_FAULT_HARD;

    /* Classify from CFSR, most specific first. Never guess: if no bit says
     * what it was, report HardFault rather than inventing a cause. */
    if ((cfsr & 0x0000FF00u) != 0u) {
        cls = (uint32_t)MDK_TRACE_SWD_FAULT_BUS;
    } else if ((cfsr & 0x000000FFu) != 0u) {
        cls = (uint32_t)MDK_TRACE_SWD_FAULT_MEMMANAGE;
    } else if ((cfsr & 0xFF000000u) != 0u) {
        cls = (uint32_t)MDK_TRACE_SWD_FAULT_USAGE;
    }

    MDK_TRACE_SWD_FAULT(cls, cfsr);
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_PC,   f[6]);        /* stacked PC */
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_LR,   f[5]);        /* stacked LR */
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_XPSR, f[7]);        /* stacked xPSR */
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_SP,   sp);
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_HFSR, SWD_SCB_HFSR);
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_MMFAR, SWD_SCB_MMFAR);
    MDK_TRACE_SWD_KV(MDK_TRACE_SWD_REG_BFAR, SWD_SCB_BFAR);
}

#endif /* MDK_TRACE_SWD_HOSTTEST */
