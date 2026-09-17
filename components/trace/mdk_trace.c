/* mdk_trace.c - target side instrumentation core.
 *
 * Responsibilities:
 *   - timestamp source (DWT cycle counter on ARM, mcycle CSR on RISC-V)
 *   - MTF framing and the byte level transports (ITM/SWO, RTT, UART)
 *   - non-blocking emit paths plus honest drop accounting
 *
 * Everything is written against raw volatile registers so the component does
 * not pull in CMSIS, a HAL or a board header. It compiles for Cortex-M0..M85,
 * RISC-V (RV32/RV64) and any other target where the backends are stubbed.
 *
 * Stack cost: mdk_trace_text() and mdk_trace_printf() use one
 * MDK_TRACE_TEXT_BUF_SIZE buffer on the caller's stack. Frames themselves are
 * assembled in a few bytes, so calling mdk_trace_send() from an ISR is safe.
 *
 * ASCII only, see mdk_trace.h for the reason.
 */

#include "mdk_trace.h"

#if MDK_TRACE_ENABLE

#include <stdarg.h>

#if MDK_TRACE_BACKEND_RTT
#  include "mdk_trace_rtt.h"
#endif

/* A frame length field is one byte, so a payload above 255 would silently wrap
 * and produce garbage on the host. Fail at build time instead. */
#if MDK_TRACE_TEXT_BUF_SIZE > 256
#  error "MDK_TRACE_TEXT_BUF_SIZE must stay <= 256 (MTF length field is 1 byte)"
#endif

/* ============================================================ book keeping */

static mdk_trace_stats_t _stats;
static int _ready;

/* =================================================================== arch */

#if defined(__arm__) || defined(__ARM_ARCH) || defined(__ARMCC_VERSION) || \
    defined(__ICCARM__) || defined(__TI_ARM__)
#  define MDK_TRACE_ARCH_ARM 1
#else
#  define MDK_TRACE_ARCH_ARM 0
#endif

#if defined(__riscv)
#  define MDK_TRACE_ARCH_RISCV 1
#else
#  define MDK_TRACE_ARCH_RISCV 0
#endif

/* ------------------------------------------------------------------- ARM */
#if MDK_TRACE_ARCH_ARM

/* Private peripheral bus. Bare addresses on purpose: including CMSIS just for
 * four register pointers would make the component heavier than it needs to be
 * and would tie it to a specific CMSIS version. */
#define MDK_TRACE_ITM_BASE   0xE0000000u
#define MDK_TRACE_DWT_BASE   0xE0001000u
#define MDK_TRACE_DEMCR      (*(volatile uint32_t *)0xE000EDFCu)
#define MDK_TRACE_TPIU_BASE  0xE0040000u

#define MDK_TRACE_ITM_STIM(n)  (*(volatile uint32_t *)(MDK_TRACE_ITM_BASE + 0x000u + ((n) * 4u)))
#define MDK_TRACE_ITM_TER(n)   (*(volatile uint32_t *)(MDK_TRACE_ITM_BASE + 0xE00u + ((n) * 4u)))
#define MDK_TRACE_ITM_TPR      (*(volatile uint32_t *)(MDK_TRACE_ITM_BASE + 0xE40u))
#define MDK_TRACE_ITM_TCR      (*(volatile uint32_t *)(MDK_TRACE_ITM_BASE + 0xE80u))
#define MDK_TRACE_ITM_LAR      (*(volatile uint32_t *)(MDK_TRACE_ITM_BASE + 0xFB0u))

#define MDK_TRACE_DWT_CTRL     (*(volatile uint32_t *)(MDK_TRACE_DWT_BASE + 0x00u))
#define MDK_TRACE_DWT_CYCCNT   (*(volatile uint32_t *)(MDK_TRACE_DWT_BASE + 0x04u))

#define MDK_TRACE_TPIU_CSPSR   (*(volatile uint32_t *)(MDK_TRACE_TPIU_BASE + 0x004u))
#define MDK_TRACE_TPIU_ACPR    (*(volatile uint32_t *)(MDK_TRACE_TPIU_BASE + 0x008u))
#define MDK_TRACE_TPIU_SPPR    (*(volatile uint32_t *)(MDK_TRACE_TPIU_BASE + 0x0F0u))
#define MDK_TRACE_TPIU_FFCR    (*(volatile uint32_t *)(MDK_TRACE_TPIU_BASE + 0x304u))
#define MDK_TRACE_TPIU_LAR     (*(volatile uint32_t *)(MDK_TRACE_TPIU_BASE + 0xFB0u))

#define MDK_TRACE_DEMCR_TRCENA      (1u << 24)
#define MDK_TRACE_ITM_TCR_ITMENA    (1u << 0)
#define MDK_TRACE_ITM_TCR_TSENA     (1u << 1)
#define MDK_TRACE_ITM_TCR_SYNCENA   (1u << 2)
#define MDK_TRACE_ITM_TCR_TXENA     (1u << 3)
#define MDK_TRACE_ITM_TCR_SWOENA    (1u << 4)
#define MDK_TRACE_ITM_TCR_DWTENA    (1u << 5)   /* Cortex-M7 and later */
#define MDK_TRACE_ITM_LAR_KEY       0xC5ACCE55u
#define MDK_TRACE_TPIU_LAR_KEY      0xC5ACCE55u

#define MDK_TRACE_DWT_CYCCNTENA     (1u << 0)
#define MDK_TRACE_DWT_PCSAMPLENA    (1u << 10)
#define MDK_TRACE_DWT_EXCTRCENA     (1u << 13)
#define MDK_TRACE_DWT_CPIEVTENA     (1u << 16)
#define MDK_TRACE_DWT_EXCEVTENA     (1u << 17)
#define MDK_TRACE_DWT_SLEEPEVTENA   (1u << 18)
#define MDK_TRACE_DWT_LSUEVTENA     (1u << 19)
#define MDK_TRACE_DWT_FOLDEVTENA    (1u << 20)
#define MDK_TRACE_DWT_CYCEVTENA     (1u << 21)

static void _arm_dbgmcu_init(void)
{
#if MDK_TRACE_DBGMCU_CR
    /* STM32 keeps the SWO pin as a GPIO until TRACE_IOEN is set. Async mode
     * (TRACE_MODE = 00) is what OpenOCD's `tpiu config ... uart off` expects. */
    volatile uint32_t *cr = (volatile uint32_t *)(uintptr_t)MDK_TRACE_DBGMCU_CR;
    *cr |= (1u << 5);
#endif
}

static void _arm_dwt_init(void)
{
    uint32_t ctrl = 0u;

    MDK_TRACE_DEMCR |= MDK_TRACE_DEMCR_TRCENA;

#if MDK_TRACE_USE_DWT
    MDK_TRACE_DWT_CYCCNT = 0u;
    ctrl |= MDK_TRACE_DWT_CYCCNTENA;
#endif
#if MDK_TRACE_DWT_PCSAMPLE
    ctrl |= MDK_TRACE_DWT_PCSAMPLENA;
#endif
#if MDK_TRACE_DWT_EVENTS
    ctrl |= MDK_TRACE_DWT_EXCTRCENA;
    ctrl |= MDK_TRACE_DWT_CPIEVTENA | MDK_TRACE_DWT_EXCEVTENA;
    ctrl |= MDK_TRACE_DWT_SLEEPEVTENA | MDK_TRACE_DWT_LSUEVTENA;
    ctrl |= MDK_TRACE_DWT_FOLDEVTENA | MDK_TRACE_DWT_CYCEVTENA;
#endif
    if (ctrl != 0u) {
        MDK_TRACE_DWT_CTRL |= ctrl;
    }
}

static uint32_t _arm_cycles(void)
{
#if MDK_TRACE_USE_DWT
    return MDK_TRACE_DWT_CYCCNT;
#else
    return 0u;
#endif
}

#if MDK_TRACE_BACKEND_ITM
static void _arm_tpiu_init(uint32_t cpu_hz)
{
    uint32_t prescale;

    if (cpu_hz == 0u || MDK_TRACE_SWO_BAUD == 0u) {
        /* No clock given: assume somebody else (startup code, debugger script)
         * already programmed the TPIU. Writing a wrong prescaler here would
         * break their setup, so leave it alone. */
        return;
    }
    prescale = cpu_hz / MDK_TRACE_SWO_BAUD;
    if (prescale == 0u) {
        prescale = 1u;
    }

    MDK_TRACE_TPIU_LAR = MDK_TRACE_TPIU_LAR_KEY;    /* unlock */
    MDK_TRACE_TPIU_CSPSR = 0x00000001u;             /* one bit wide, async */
    MDK_TRACE_TPIU_SPPR = 0x00000002u;              /* NRZ, UART style */
    MDK_TRACE_TPIU_ACPR = prescale - 1u;
    /* Matches what ST's own SWO examples write. Continuous formatting off keeps
     * the SWO stream free of extra sync packets. */
    MDK_TRACE_TPIU_FFCR = 0x00000100u;
}

static void _arm_itm_init(void)
{
    uint32_t tcr, port;

    port = (uint32_t)MDK_TRACE_ITM_PORT & 0x1Fu;

    MDK_TRACE_ITM_LAR = MDK_TRACE_ITM_LAR_KEY;   /* unlock, harmless if absent */
    MDK_TRACE_ITM_TPR = 0x00000000u;             /* privileged writers only */

    tcr = MDK_TRACE_ITM_TCR_ITMENA | MDK_TRACE_ITM_TCR_TSENA |
          MDK_TRACE_ITM_TCR_SYNCENA | MDK_TRACE_ITM_TCR_TXENA |
          MDK_TRACE_ITM_TCR_SWOENA;
#if MDK_TRACE_DWT_EVENTS
    tcr |= MDK_TRACE_ITM_TCR_DWTENA;
#endif
    MDK_TRACE_ITM_TCR = tcr;

    MDK_TRACE_ITM_TER(port / 32u) = (1u << (port % 32u));
}

static void _arm_itm_byte(uint8_t b)
{
    volatile uint32_t *p = &MDK_TRACE_ITM_STIM((uint32_t)MDK_TRACE_ITM_PORT & 0x1Fu);

    /* Reading a stimulus port yields 0 when the port is disabled or the FIFO
     * has no room. Both cases mean "cannot send right now", and spinning would
     * stretch the very timing we are measuring, so the byte is dropped and
     * counted. A large drop count is the signal that either the ITM was never
     * clocked or the SWO link cannot keep up with the trace rate. */
    if (*p == 0u) {
        _stats.dropped++;
        return;
    }
    *p = (uint32_t)b;
}
#endif /* MDK_TRACE_BACKEND_ITM */

#endif /* MDK_TRACE_ARCH_ARM */

/* ----------------------------------------------------------------- RISC-V */
#if MDK_TRACE_ARCH_RISCV
static uint32_t _rv_cycles(void)
{
#if MDK_TRACE_USE_DWT
    /* mcycle is the RISC-V equivalent of DWT->CYCCNT. Available on any core
     * that implements the counters (all ESP32-C/S and most RV32 cores do).
     * XLEN wide, so widen the register and truncate afterwards. */
    unsigned long v;
    __asm__ volatile ("csrr %0, mcycle" : "=r"(v));
    return (uint32_t)v;
#else
    return 0u;
#endif
}
#endif /* MDK_TRACE_ARCH_RISCV */

/* ================================================================ CRC + MTF */

/* CRC-8, poly 0x07, init 0x00, no reflection, no final xor.
 * Bit by bit on purpose: a table or nibble variant saves cycles this path does
 * not need, and this stays obviously identical to the host implementation. */
static uint8_t _crc8_upd(uint8_t crc, const uint8_t *p, uint32_t n)
{
    uint32_t i;
    int b;

    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (b = 0; b < 8; b++) {
            crc = (uint8_t)((crc & 0x80u) ? ((uint8_t)(crc << 1) ^ 0x07u)
                                          : (uint8_t)(crc << 1));
        }
    }
    return crc;
}

/* ================================================================ backends */

static void _raw_out(const uint8_t *p, uint32_t n)
{
#if MDK_TRACE_BACKEND_ITM
    for (uint32_t i = 0; i < n; i++) {
        _arm_itm_byte(p[i]);
    }
#elif MDK_TRACE_BACKEND_RTT
    {
        int w = mdk_trace_rtt_write(0u, (const char *)p, n);
        if (w < (int)n) {
            _stats.dropped += (uint32_t)n - (uint32_t)(w < 0 ? 0 : w);
        }
    }
#elif MDK_TRACE_BACKEND_UART
    for (uint32_t i = 0; i < n; i++) {
        MDK_TRACE_UART_PUTC(p[i]);
    }
#else
    (void)p;
    (void)n;
#endif
}

void mdk_trace_send(uint8_t type, const uint8_t *payload, uint8_t len)
{
    uint8_t hdr[3];
    uint8_t crc;

    if (!_ready) {
        return;
    }
    hdr[0] = (uint8_t)MDK_TRACE_MTF_MAGIC;
    hdr[1] = (uint8_t)(((uint8_t)MDK_TRACE_MTF_VERSION << 4) | (type & 0x0Fu));
    hdr[2] = len;

    /* CRC over magic..payload, accumulated in place so no assembly buffer is
     * needed: the header is on the stack, the payload belongs to the caller. */
    crc = _crc8_upd(0x00u, hdr, 3u);
    if (len > 0u) {
        crc = _crc8_upd(crc, payload, (uint32_t)len);
    }

    _raw_out(hdr, 3u);
    if (len > 0u) {
        _raw_out(payload, (uint32_t)len);
    }
    _raw_out(&crc, 1u);

    _stats.frames++;
    _stats.bytes += 4u + (uint32_t)len;
}

/* -------------------------------------------------------------- primitives */

void mdk_trace_text(const char *s)
{
    uint8_t payload[MDK_TRACE_TEXT_BUF_SIZE];
    uint32_t n = 0;

    if (s == NULL) {
        return;
    }
    while (*s != '\0') {
        /* Split long strings instead of truncating: a truncated trace line is
         * a wrong trace line, and the host would have no way to notice. */
        if (n >= (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
            mdk_trace_send((uint8_t)MDK_TRACE_TYPE_TEXT, payload, (uint8_t)n);
            n = 0;
        }
        payload[n++] = (uint8_t)(*s++);
    }
    if (n > 0u) {
        mdk_trace_send((uint8_t)MDK_TRACE_TYPE_TEXT, payload, (uint8_t)n);
    }
}

/* Minimal formatter. No float, no locale, no libc: pulling in vsnprintf on a
 * Cortex-M0 can add several kB, and a trace component has to stay cheap enough
 * to leave enabled in a real build.
 * Supported: %s %c %d %i %u %x %X %p %% with optional zero pad and width. */
void mdk_trace_printf(const char *fmt, ...)
{
    char out[MDK_TRACE_TEXT_BUF_SIZE];
    uint32_t n = 0;
    va_list ap;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    while (*fmt != '\0' && n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
        char c;

        if (*fmt != '%') {
            out[n++] = *fmt++;
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            out[n++] = '%';
            fmt++;
            continue;
        }

        {
            int zero = 0;
            int width = 0;
            char tmp[16];
            int tn = 0;
            int neg = 0;
            unsigned long val = 0;
            unsigned long base = 10ul;
            int upper = 0;
            int is_num = 0;

            if (*fmt == '0') {
                zero = 1;
                fmt++;
            }
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (int)(*fmt - '0');
                fmt++;
            }
            c = *fmt;
            if (c == '\0') {
                break;
            }
            fmt++;

            if (c == 's') {
                const char *sp = va_arg(ap, const char *);
                if (sp == NULL) {
                    sp = "(null)";
                }
                while (*sp != '\0' && n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = *sp++;
                }
                continue;
            }
            if (c == 'c') {
                if (n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = (char)va_arg(ap, int);
                }
                continue;
            }
            if (c == 'd' || c == 'i') {
                long v = (long)va_arg(ap, int);
                if (v < 0) {
                    neg = 1;
                    val = (unsigned long)(-v);
                } else {
                    val = (unsigned long)v;
                }
                is_num = 1;
            } else if (c == 'u') {
                val = (unsigned long)va_arg(ap, unsigned int);
                is_num = 1;
            } else if (c == 'x' || c == 'X') {
                val = (unsigned long)va_arg(ap, unsigned int);
                base = 16ul;
                upper = (c == 'X');
                is_num = 1;
            } else if (c == 'p') {
                val = (unsigned long)(uintptr_t)va_arg(ap, void *);
                base = 16ul;
                zero = 1;
                width = 8;
                is_num = 1;
            } else {
                out[n++] = '%';
                if (n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = c;
                }
                continue;
            }

            if (is_num) {
                /* Digits are produced least significant first, then reversed. */
                if (val == 0ul) {
                    tmp[tn++] = '0';
                }
                while (val != 0ul && tn < 15) {
                    unsigned long d = val % base;
                    val /= base;
                    tmp[tn++] = (char)(d < 10ul ? (int)('0' + d)
                                                : (int)((upper ? 'A' : 'a') + (d - 10ul)));
                }
                if (neg && n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = '-';
                }
                while (tn < width && n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = zero ? '0' : ' ';
                    width--;
                }
                while (tn > 0 && n < (uint32_t)(MDK_TRACE_TEXT_BUF_SIZE - 1)) {
                    out[n++] = tmp[--tn];
                }
            }
        }
    }
    va_end(ap);
    out[n] = '\0';
    mdk_trace_text(out);
}

/* ------------------------------------------------------------ MTF payloads
 * Little endian everywhere: the host unpacks with struct format "<HBII" and
 * friends, so both sides must agree exactly. Field order is fixed by the host
 * parser and must not be reshuffled here.
 */
static void _put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void _put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

void mdk_trace_event(uint16_t id, uint8_t kind, uint32_t arg)
{
    uint8_t p[11];                      /* id, kind, ts, arg = 11 bytes */
    _put_u16(p, id);
    p[2] = kind;
    _put_u32(p + 3, mdk_trace_now());
    _put_u32(p + 7, arg);
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_EVENT, p, 11u);
}

void mdk_trace_counter(uint16_t id, uint32_t value)
{
    uint8_t p[6];                       /* id, value = 6 bytes */
    _put_u16(p, id);
    _put_u32(p + 2, value);
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_COUNTER, p, 6u);
}

void mdk_trace_kv(int16_t key, int32_t value)
{
    uint8_t p[6];                       /* key, value = 6 bytes */
    _put_u16(p, (uint16_t)key);
    _put_u32(p + 2, (uint32_t)value);
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_KV, p, 6u);
}

void mdk_trace_mark(uint32_t tag)
{
    uint8_t p[4];
    _put_u32(p, tag);
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_MARK, p, 4u);
}

void mdk_trace_timestamp(void)
{
    uint8_t p[4];
    _put_u32(p, mdk_trace_now());
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_TS, p, 4u);
}

void mdk_trace_isr(uint16_t id, uint8_t kind)
{
    uint8_t p[7];                       /* id, kind, ts = 7 bytes */
    _put_u16(p, id);
    p[2] = kind;
    _put_u32(p + 3, mdk_trace_now());
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_ISR, p, 7u);
}

/* ------------------------------------------------------------- timestamps */

uint32_t mdk_trace_now(void)
{
#if MDK_TRACE_ARCH_ARM
    return _arm_cycles();
#elif MDK_TRACE_ARCH_RISCV
    return _rv_cycles();
#else
    return 0u;
#endif
}

uint32_t mdk_trace_hz(void)
{
    return (uint32_t)MDK_TRACE_CPU_HZ;
}

/* --------------------------------------------------------------- lifecycle */

const char *mdk_trace_backend_name(void)
{
#if MDK_TRACE_BACKEND_ITM
    return "itm";
#elif MDK_TRACE_BACKEND_RTT
    return "rtt";
#elif MDK_TRACE_BACKEND_UART
    return "uart";
#else
    return "none";
#endif
}

void mdk_trace_init(void)
{
    if (_ready) {
        return;
    }
    _stats.frames = 0u;
    _stats.bytes = 0u;
    _stats.dropped = 0u;
    _stats.crc_errors = 0u;

#if MDK_TRACE_BACKEND_RTT
    mdk_trace_rtt_init();
#endif

#if MDK_TRACE_ARCH_ARM
    _arm_dbgmcu_init();
    _arm_dwt_init();
#  if MDK_TRACE_BACKEND_ITM
    _arm_tpiu_init((uint32_t)MDK_TRACE_CPU_HZ);
    _arm_itm_init();
#  endif
#endif

    _ready = 1;

    /* Announce the session so the host can tell a restarted target from a
     * freshly attached one, and drop whatever it had buffered before. */
    mdk_trace_send((uint8_t)MDK_TRACE_TYPE_RESET, (const uint8_t *)"init", 4u);
}

void mdk_trace_deinit(void)
{
#if MDK_TRACE_ARCH_ARM
#  if MDK_TRACE_USE_DWT
    MDK_TRACE_DWT_CTRL &= ~MDK_TRACE_DWT_CYCCNTENA;
#  endif
#  if MDK_TRACE_BACKEND_ITM
    MDK_TRACE_ITM_TCR = 0u;
    MDK_TRACE_ITM_TER((uint32_t)MDK_TRACE_ITM_PORT / 32u) = 0u;
#  endif
#endif
    _ready = 0;
}

int mdk_trace_is_ready(void)
{
    return _ready;
}

/* ---------------------------------------------------------------- counters */

void mdk_trace_get_stats(mdk_trace_stats_t *out)
{
    if (out != NULL) {
        *out = _stats;
    }
}

void mdk_trace_reset_stats(void)
{
    _stats.frames = 0u;
    _stats.bytes = 0u;
    _stats.dropped = 0u;
    _stats.crc_errors = 0u;
}

/* ---------------------------------------------------------- RTT shortcuts */

int mdk_trace_rtt_getc(void)
{
#if MDK_TRACE_BACKEND_RTT
    return mdk_trace_rtt_getc_ch(0u);
#else
    return -1;
#endif
}

int mdk_trace_rtt_putc(int c)
{
#if MDK_TRACE_BACKEND_RTT
    int r = mdk_trace_rtt_putc_ch(0u, (char)c);
    if (r < 0) {
        _stats.dropped++;
    }
    return r;
#else
    (void)c;
    return -1;
#endif
}

unsigned mdk_trace_rtt_pending(void)
{
#if MDK_TRACE_BACKEND_RTT
    return mdk_trace_rtt_pending_ch(0u);
#else
    return 0u;
#endif
}

#endif /* MDK_TRACE_ENABLE */
