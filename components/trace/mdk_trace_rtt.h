/* mdk_trace_rtt.h - SEGGER RTT compatible ring buffers for the host side reader.
 *
 * The layout has to stay byte compatible with what mdkdebug reads out of RAM:
 *
 *   struct { char acID[16]; int MaxNumUpBuffers; int MaxNumDownBuffers;
 *            channel up[..]; channel down[..]; }
 *   channel = { const char *sName; char *pBuffer; unsigned Size;
 *               unsigned WrOff; volatile unsigned RdOff; unsigned Flags; }
 *
 * That is exactly the SEGGER layout, which is worth keeping even though this
 * implementation is our own: any existing RTT viewer can then read the buffer
 * as a fallback, and the host code in mdkdebug does not need a private format.
 *
 * ASCII only, see mdk_trace.h for the reason.
 */

#ifndef MDK_TRACE_RTT_H
#define MDK_TRACE_RTT_H

#include <stdint.h>
#include "mdk_trace_config_default.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Control block id. The host scans RAM for this string when it has no ELF. */
#define MDK_TRACE_RTT_ID "SEGGER RTT"

/* Channel Flags. Only the two SEGGER defined ones are used. */
#define MDK_TRACE_RTT_FLAG_BLOCK_IF_FULL (1u << 0)
#define MDK_TRACE_RTT_FLAG_TRIM_ON_OVER  (1u << 1)

typedef struct {
    const char       *sName;
    char             *pBuffer;
    unsigned          Size;
    unsigned          WrOff;
    volatile unsigned RdOff;
    unsigned          Flags;
} mdk_trace_rtt_ch_t;

typedef struct {
    char acID[16];
    int  MaxNumUpBuffers;
    int  MaxNumDownBuffers;
    mdk_trace_rtt_ch_t aUp[MDK_TRACE_RTT_UP_CHANNELS];
    mdk_trace_rtt_ch_t aDown[MDK_TRACE_RTT_DOWN_CHANNELS];
} mdk_trace_rtt_cb_t;

/* The control block itself. Declared here so a linker script can KEEP it, and
 * so `trace_rtt_find` can find it through the _SEGGER_RTT symbol. */
extern mdk_trace_rtt_cb_t _SEGGER_RTT;

/* Bring the ring buffers up. Called from mdk_trace_init(). */
void     mdk_trace_rtt_init(void);

/* Up channel (target -> host). Returns 0 when the buffer is full, i.e. the
 * event was dropped; the caller counts it. */
int      mdk_trace_rtt_write(unsigned channel, const char *data, unsigned len);
int      mdk_trace_rtt_putc_ch(unsigned channel, char c);

/* Down channel (host -> target). Non-blocking. */
int      mdk_trace_rtt_read(unsigned channel, char *out, unsigned max);
int      mdk_trace_rtt_getc_ch(unsigned channel);

/* Bytes currently waiting in an up channel. */
unsigned mdk_trace_rtt_pending_ch(unsigned channel);

#ifdef __cplusplus
}
#endif

#endif /* MDK_TRACE_RTT_H */
