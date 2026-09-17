/* mdk_trace_rtt.c - SEGGER RTT compatible ring buffers.
 *
 * The host (mdkdebug) reads and writes this control block straight out of RAM
 * with `mdw`/`mww`, which is why the layout matters more than the API here.
 *
 * Two rules that are easy to get wrong and expensive to debug:
 *
 *   1. The control block must survive --gc-sections. It is referenced from
 *      mdk_trace_init() and declared `used`, and the linker script should KEEP
 *      it. If it gets collected, the host sees garbage where the id string
 *      should be and reports "no RTT control block found".
 *
 *   2. The host advances RdOff after reading. The target must never write to
 *      RdOff: a target side write would race with the host and can make the
 *      host re-read or skip a region. The field is volatile for that reason.
 *
 * ASCII only, see mdk_trace.h for the reason.
 */

#include "mdk_trace.h"
#include "mdk_trace_rtt.h"

#if MDK_TRACE_ENABLE && MDK_TRACE_BACKEND_RTT

/* 32 bit targets only: the host parser assumes 4 byte pointers. A 64 bit build
 * would silently produce a control block the host mis-reads, so fail loudly. */
#if defined(__SIZEOF_POINTER__) && (__SIZEOF_POINTER__ != 4)
#  error "mdk_trace RTT backend requires 32 bit pointers"
#endif

#if (MDK_TRACE_RTT_UP_CHANNELS < 1) || (MDK_TRACE_RTT_DOWN_CHANNELS < 1)
#  error "mdk_trace RTT needs at least one up and one down channel"
#endif

/* Name table. Kept separate from the control block so the strings live in
 * .rodata and the control block stays a plain writable object. */
static const char *const _up_names[MDK_TRACE_RTT_UP_CHANNELS] = {
    MDK_TRACE_RTT_UP_NAME0
#if MDK_TRACE_RTT_UP_CHANNELS > 1
    , "TRACE1"
#endif
#if MDK_TRACE_RTT_UP_CHANNELS > 2
    , "TRACE2"
#endif
#if MDK_TRACE_RTT_UP_CHANNELS > 3
    , "TRACE3"
#endif
};

static const char *const _down_names[MDK_TRACE_RTT_DOWN_CHANNELS] = {
    MDK_TRACE_RTT_DOWN_NAME0
#if MDK_TRACE_RTT_DOWN_CHANNELS > 1
    , "CMD1"
#endif
#if MDK_TRACE_RTT_DOWN_CHANNELS > 2
    , "CMD2"
#endif
#if MDK_TRACE_RTT_DOWN_CHANNELS > 3
    , "CMD3"
#endif
};

static char _up_buf[MDK_TRACE_RTT_UP_CHANNELS][MDK_TRACE_RTT_BUF_SIZE];
static char _down_buf[MDK_TRACE_RTT_DOWN_CHANNELS][MDK_TRACE_RTT_BUF_SIZE];

/* Force the control block into the image and keep it out of the optimiser. */
#if defined(__GNUC__)
#  define MDK_TRACE_USED __attribute__((used))
#elif defined(__CC_ARM)
#  define MDK_TRACE_USED __attribute__((used))
#else
#  define MDK_TRACE_USED
#endif

MDK_TRACE_USED mdk_trace_rtt_cb_t _SEGGER_RTT;

void mdk_trace_rtt_init(void)
{
    unsigned i;

    /* Id string: 16 bytes, the tail is zero padded by the initialiser. */
    {
        static const char id[] = MDK_TRACE_RTT_ID;
        for (i = 0; i < sizeof(_SEGGER_RTT.acID); i++) {
            _SEGGER_RTT.acID[i] = (i < sizeof(id) - 1u) ? id[i] : '\0';
        }
    }
    _SEGGER_RTT.MaxNumUpBuffers   = (int)MDK_TRACE_RTT_UP_CHANNELS;
    _SEGGER_RTT.MaxNumDownBuffers = (int)MDK_TRACE_RTT_DOWN_CHANNELS;

    for (i = 0; i < (unsigned)MDK_TRACE_RTT_UP_CHANNELS; i++) {
        _SEGGER_RTT.aUp[i].sName   = _up_names[i];
        _SEGGER_RTT.aUp[i].pBuffer = _up_buf[i];
        _SEGGER_RTT.aUp[i].Size    = MDK_TRACE_RTT_BUF_SIZE;
        _SEGGER_RTT.aUp[i].WrOff   = 0u;
        _SEGGER_RTT.aUp[i].RdOff   = 0u;
        /* Never block. Blocking a producer changes the timing of the code
         * under test, which is exactly what instrumentation must not do. */
        _SEGGER_RTT.aUp[i].Flags   = MDK_TRACE_RTT_FLAG_TRIM_ON_OVER;
    }
    for (i = 0; i < (unsigned)MDK_TRACE_RTT_DOWN_CHANNELS; i++) {
        _SEGGER_RTT.aDown[i].sName   = _down_names[i];
        _SEGGER_RTT.aDown[i].pBuffer = _down_buf[i];
        _SEGGER_RTT.aDown[i].Size    = MDK_TRACE_RTT_BUF_SIZE;
        _SEGGER_RTT.aDown[i].WrOff   = 0u;
        _SEGGER_RTT.aDown[i].RdOff   = 0u;
        _SEGGER_RTT.aDown[i].Flags   = 0u;
    }
}

/* WrOff / RdOff are unsigned and only ever compared, so the natural wrap of
 * the counter is harmless: the buffer index is the modulo at the point of use
 * and the difference of the two offsets is the fill level. Doing it this way
 * avoids two separate modulus computations on every byte. */
int mdk_trace_rtt_write(unsigned channel, const char *data, unsigned len)
{
    mdk_trace_rtt_ch_t *ch;
    unsigned size, wr, rd, free_space, i;

    if (channel >= (unsigned)MDK_TRACE_RTT_UP_CHANNELS) {
        return 0;
    }
    ch = &_SEGGER_RTT.aUp[channel];
    size = ch->Size;
    if (size == 0u) {
        return 0;
    }
    wr = ch->WrOff;
    rd = ch->RdOff;                 /* host owned, read it once */
    free_space = size - (unsigned)(wr - rd) - 1u;

    if (len > free_space) {
        /* Report the truncation honestly: the caller counts the shortfall and
         * the host gets a drop counter instead of a silently short frame. */
        len = free_space;
    }
    for (i = 0; i < len; i++) {
        ch->pBuffer[(wr + i) % size] = data[i];
    }
    ch->WrOff = wr + len;
    return (int)len;
}

int mdk_trace_rtt_putc_ch(unsigned channel, char c)
{
    return mdk_trace_rtt_write(channel, &c, 1u) == 1 ? (int)(unsigned char)c : -1;
}

int mdk_trace_rtt_read(unsigned channel, char *out, unsigned max)
{
    mdk_trace_rtt_ch_t *ch;
    unsigned size, wr, rd, avail, i;

    if (channel >= (unsigned)MDK_TRACE_RTT_DOWN_CHANNELS) {
        return -1;
    }
    ch = &_SEGGER_RTT.aDown[channel];
    size = ch->Size;
    if (size == 0u) {
        return -1;
    }
    wr = ch->WrOff;                 /* host owned on the down channel */
    rd = ch->RdOff;                 /* ours */
    avail = (unsigned)(wr - rd);
    if (avail > max) {
        avail = max;
    }
    if (avail == 0u) {
        return 0;
    }
    for (i = 0; i < avail; i++) {
        out[i] = ch->pBuffer[(rd + i) % size];
    }
    ch->RdOff = rd + avail;
    return (int)avail;
}

int mdk_trace_rtt_getc_ch(unsigned channel)
{
    char c;
    return mdk_trace_rtt_read(channel, &c, 1u) == 1 ? (int)(unsigned char)c : -1;
}

unsigned mdk_trace_rtt_pending_ch(unsigned channel)
{
    const mdk_trace_rtt_ch_t *ch;
    if (channel >= (unsigned)MDK_TRACE_RTT_UP_CHANNELS) {
        return 0u;
    }
    ch = &_SEGGER_RTT.aUp[channel];
    return (unsigned)(ch->WrOff - ch->RdOff);
}

#endif /* MDK_TRACE_ENABLE && MDK_TRACE_BACKEND_RTT */
