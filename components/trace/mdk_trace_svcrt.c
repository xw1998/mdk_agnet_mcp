/* mdk_trace_svcrt.c - SVCrtOS kernel hook adapter. See mdk_trace_svcrt.h for
 * the five call sites and why they belong in the kernel rather than the
 * application.
 *
 * With MDK_TRACE_SVCRT_HOOKS at 0 every function below still exists and still
 * links, but compiles to an empty body. That is deliberate: a firmware that
 * calls them and forgot the macro keeps building, and the host sees "no kernel
 * events" - a diagnosis it can name - rather than a link error the user has to
 * decode. mdk_trace_svcrt_enabled() exists so a shell command can report which
 * of the two builds it is, instead of anyone having to guess.
 *
 * ASCII only, same reason as mdk_trace.h.
 */

/* Include mdk_trace.h FIRST and let it pull in the config: it reads the
 * project's mdk_trace_config.h before falling back to its own defaults, so a
 * project that sets MDK_TRACE_SVCRT_HOOKS=1 is honoured. Including
 * mdk_trace_config_default.h here instead would define the macro (and its
 * #ifndef guard) at 0 first, and the project's later define would be dropped
 * - the option would be silently ignored. */
#include "mdk_trace.h"
#include "mdk_trace_svcrt.h"

#if MDK_TRACE_SVCRT_HOOKS && MDK_TRACE_ENABLE

#define MDK_TRACE_SVCRT_INIT_TAG  0x5356u   /* 'S','V' */

void mdk_trace_svcrt_init(void)
{
    mdk_trace_mark(MDK_TRACE_SVCRT_INIT_TAG);
}

void mdk_trace_svcrt_task_switch(uint32_t from, uint32_t to)
{
    /* Task numbers are 4 bit on the wire (0..14 plus idle) - the record format
     * and the compressed stream are built around that. Clamping here would
     * invent a switch between two wrong tasks, so an out of range number is
     * dropped: the host reports the gap, which is the truth. */
    if (from > 0xFu || to > 0xFu) {
        return;
    }
    mdk_trace_sched((uint16_t)from, (uint16_t)to);
}

void mdk_trace_svcrt_task_create(uint32_t slot, uint32_t entry)
{
    if (slot > 0xFu) {
        return;
    }
    mdk_trace_event((uint16_t)MDK_TRACE_SVCRT_EV_CREATE, MDK_TRACE_KIND_POINT,
                    slot);
    if (entry) {
        /* The entry address travels as a KV pair: it does not fit the task
         * number slot, and a slot whose entry has no symbol in this image is
         * exactly the case where the host has to say "kernel image has no name
         * for this task" instead of inventing one. */
        mdk_trace_kv((int16_t)(MDK_TRACE_SVCRT_KV_ENTRY + (slot & 0x3Fu)),
                     (int32_t)entry);
    }
}

void mdk_trace_svcrt_task_exit(uint32_t slot)
{
    if (slot > 0xFu) {
        return;
    }
    mdk_trace_event((uint16_t)MDK_TRACE_SVCRT_EV_EXIT, MDK_TRACE_KIND_POINT, slot);
}

void mdk_trace_svcrt_obj_wait(uint16_t obj, uint8_t cls)
{
    /* Only the sync record. The host decodes the task-argument event ids
     * (0x11/0x12/0x13/0x14) by reading `arg` as a TASK SLOT and resolving it
     * to a task name, so emitting 0x11 here with an object index would label
     * the event with whichever task happens to own that slot number - a wrong
     * name presented as fact. Tasks that block are reported by the kernel's
     * own wait event; what this call adds is the object that was waited on. */
    mdk_trace_sync(MDK_TRACE_SVCRT_OBJ(cls, obj), MDK_TRACE_SYNC_WAIT, 0u);
}

void mdk_trace_svcrt_obj_timeout(uint16_t obj, uint8_t cls)
{
    mdk_trace_sync(MDK_TRACE_SVCRT_OBJ(cls, obj), MDK_TRACE_SYNC_TIMEOUT, 0u);
}

void mdk_trace_svcrt_obj_signal(uint16_t obj, uint8_t cls)
{
    /* Sync record only - see the note in mdk_trace_svcrt_obj_wait(). */
    mdk_trace_sync(MDK_TRACE_SVCRT_OBJ(cls, obj), MDK_TRACE_SYNC_SIGNAL, 0u);
}

void mdk_trace_svcrt_mutex_acquire(uint16_t obj)
{
    mdk_trace_sync(MDK_TRACE_SVCRT_OBJ(MDK_TRACE_SVCRT_CLASS_MUTEX, obj),
                   MDK_TRACE_SYNC_ACQUIRE, 0u);
}

void mdk_trace_svcrt_mutex_release(uint16_t obj)
{
    mdk_trace_sync(MDK_TRACE_SVCRT_OBJ(MDK_TRACE_SVCRT_CLASS_MUTEX, obj),
                   MDK_TRACE_SYNC_RELEASE, 0u);
}

void mdk_trace_svcrt_isr_enter(uint32_t irq)
{
    if (irq > 0xFFFu) {
        return;
    }
    mdk_trace_isr((uint16_t)irq, MDK_TRACE_KIND_ENTER);
}

void mdk_trace_svcrt_isr_exit(uint32_t irq)
{
    if (irq > 0xFFFu) {
        return;
    }
    mdk_trace_isr((uint16_t)irq, MDK_TRACE_KIND_EXIT);
}

void mdk_trace_svcrt_heap(uint32_t alloc_op, uint32_t size)
{
    mdk_trace_heap((uint8_t)(alloc_op ? MDK_TRACE_HEAP_FREE : MDK_TRACE_HEAP_ALLOC),
                   size);
}

int mdk_trace_svcrt_enabled(void)
{
    return 1;
}

#else  /* hooks off, or tracing off entirely */

/* Same signatures, empty bodies: a firmware that calls them still links. */
void mdk_trace_svcrt_init(void) { }
void mdk_trace_svcrt_task_switch(uint32_t from, uint32_t to)
{
    (void)from; (void)to;
}
void mdk_trace_svcrt_task_create(uint32_t slot, uint32_t entry)
{
    (void)slot; (void)entry;
}
void mdk_trace_svcrt_task_exit(uint32_t slot) { (void)slot; }
void mdk_trace_svcrt_obj_wait(uint16_t obj, uint8_t cls)
{
    (void)obj; (void)cls;
}
void mdk_trace_svcrt_obj_timeout(uint16_t obj, uint8_t cls)
{
    (void)obj; (void)cls;
}
void mdk_trace_svcrt_obj_signal(uint16_t obj, uint8_t cls)
{
    (void)obj; (void)cls;
}
void mdk_trace_svcrt_mutex_acquire(uint16_t obj) { (void)obj; }
void mdk_trace_svcrt_mutex_release(uint16_t obj) { (void)obj; }
void mdk_trace_svcrt_isr_enter(uint32_t irq) { (void)irq; }
void mdk_trace_svcrt_isr_exit(uint32_t irq) { (void)irq; }
void mdk_trace_svcrt_heap(uint32_t alloc_op, uint32_t size)
{
    (void)alloc_op; (void)size;
}
int mdk_trace_svcrt_enabled(void) { return 0; }

#endif /* MDK_TRACE_SVCRT_HOOKS && MDK_TRACE_ENABLE */
