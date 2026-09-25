/* mdk_trace_svcrt.h - SVCrtOS kernel hook adapter for the mdk_trace component.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Every other trace setup expects the application to place probes by hand.
 * That is fine for application code, but the kernel already knows all of this
 * information: it is the thing doing the switching, the blocking and the
 * waking up. So the kernel reports it, once, and every task in the system -
 * including tasks whose code you are not touching - shows up in the trace
 * with no call site added by the user at all.
 *
 * This is the same idea as an RTOS shipping with a recorder built in (RTX5
 * with CMSIS Event Recorder, embOS with SystemView): the events exist because
 * the kernel creates them, not because someone remembered to instrument.
 *
 * HOW TO WIRE IT (5 call sites, all inside the kernel)
 * ---------------------------------------------------
 *   1. task switch        svcrt_sched / the PendSV handler, right where the
 *                         outgoing task is replaced by the incoming one
 *                         -> mdk_trace_svcrt_task_switch(from, to)
 *   2. task create/exit   wherever a TCB becomes runnable / is reclaimed
 *                         -> mdk_trace_svcrt_task_create(slot, entry)
 *                            mdk_trace_svcrt_task_exit(slot)
 *   3. blocking           the place where a task is put on a wait queue
 *                         -> mdk_trace_svcrt_obj_wait(obj, cls)
 *                            mdk_trace_svcrt_obj_timeout(obj, cls)  (gave up)
 *   4. wake up            where the object is posted / released
 *                         -> mdk_trace_svcrt_obj_signal(obj, cls)
 *                            mdk_trace_svcrt_mutex_acquire / _release(obj)
 *   5. fault handler      first statement of each fault handler
 *                         -> MDK_TRACE_FAULT_CAPTURE()  (a macro, not a
 *                         call - see the note at the bottom of this header)
 *
 * The call sites are deliberately in the *kernel*, not in the trace
 * component: a hook that lives outside the thing being scheduled can only
 * guess from interrupt activity, which is exactly the "looks like a switch
 * happened on every tick" failure the component warns about.
 *
 * COST: a handful of stores per event. No allocation, no blocking, no
 * peripheral access - the adapter only calls the same primitives application
 * code calls, so the backend (buff / swd / itm / rtt) decides what it costs.
 *
 * Turn it on with MDK_TRACE_SVCRT_HOOKS=1 in mdk_trace_config.h. With the
 * macro at 0 (the default) every function below still exists and still links,
 * but compiles to an empty body - so a firmware that calls them and forgot the
 * macro gets a build that runs and a trace with no kernel events, instead of a
 * link error. The host reports "no kernel events" as a diagnosis, not as a
 * silent empty timeline.
 *
 * ASCII only, same reason as mdk_trace.h.
 */

#ifndef MDK_TRACE_SVCRT_H
#define MDK_TRACE_SVCRT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Object classes. They share the record's 13 bit object field with the index,
 * so the host can say "semaphore 3" instead of "object 3075". */
#define MDK_TRACE_SVCRT_CLASS_SEM    0u
#define MDK_TRACE_SVCRT_CLASS_MUTEX  1u
#define MDK_TRACE_SVCRT_CLASS_QUEUE  2u
#define MDK_TRACE_SVCRT_CLASS_EVENT  3u
#define MDK_TRACE_SVCRT_CLASS_FS     4u
#define MDK_TRACE_SVCRT_CLASS_DEV    5u
#define MDK_TRACE_SVCRT_CLASS_COND   6u   /* condition variable: sleeps on the cond, re-locks its mutex */

/* class (3 bits) + index (10 bits) = the 13 bit object handle in the record. */
#define MDK_TRACE_SVCRT_OBJ(cls, idx) \
    ((uint16_t)((((uint16_t)(cls) & 0x7u) << 10) | ((uint16_t)(idx) & 0x3FFu)))

/* Event ids for TASK LIFECYCLE, with the task slot in `arg`. These match the
 * ids svcrt_trace.h already used, so the host's existing task-name lookup
 * applies to them unchanged.
 *
 * 0x11 (WAIT) and 0x12 (READY) are listed for completeness only: they are the
 * kernel's own task-level events, and the adapter must NOT emit them from the
 * object hooks. The host reads the arg of these four ids as a task slot, so an
 * object index there would be shown as the name of an unrelated task. Object
 * waits travel as sync records instead, where the object identity has a field
 * of its own. */
#define MDK_TRACE_SVCRT_EV_WAIT    0x11u
#define MDK_TRACE_SVCRT_EV_READY   0x12u
#define MDK_TRACE_SVCRT_EV_CREATE  0x13u
#define MDK_TRACE_SVCRT_EV_EXIT    0x14u
#define MDK_TRACE_SVCRT_EV_START   0x15u

/* KV keys for what the event ids cannot carry (kv key = base + slot). */
#define MDK_TRACE_SVCRT_KV_ENTRY   0x2100u

/* One-time marker. Emits a MARK so a trace can be cut at "kernel hooks were
 * installed here" instead of at an arbitrary first event. */
void mdk_trace_svcrt_init(void);

/* 1. Context switch. from / to are task numbers as the kernel knows them
 * (the same numbers the host resolves to names through svcrt_task_table). */
void mdk_trace_svcrt_task_switch(uint32_t from, uint32_t to);

/* 2. Task lifecycle. entry is the task entry address, so a slot that has no
 * symbol in the kernel image can still be recognised later. */
void mdk_trace_svcrt_task_create(uint32_t slot, uint32_t entry);
void mdk_trace_svcrt_task_exit(uint32_t slot);

/* 3./4. Synchronisation. */
void mdk_trace_svcrt_obj_wait(uint16_t obj, uint8_t cls);
void mdk_trace_svcrt_obj_timeout(uint16_t obj, uint8_t cls);
void mdk_trace_svcrt_obj_signal(uint16_t obj, uint8_t cls);
void mdk_trace_svcrt_mutex_acquire(uint16_t obj);
void mdk_trace_svcrt_mutex_release(uint16_t obj);

/* Interrupt side, for ISR response time and nesting depth. */
void mdk_trace_svcrt_isr_enter(uint32_t irq);
void mdk_trace_svcrt_isr_exit(uint32_t irq);

/* Heap allocation, if the kernel has one. `size` is the block size, in bytes,
 * for both alloc and free, so the host can compute net bytes without knowing
 * the allocator's internals. */
void mdk_trace_svcrt_heap(uint32_t alloc_op, uint32_t size);

/* 5. Fault snapshot - there is deliberately NO function here.
 *
 * A wrapper function cannot capture a fault. MDK_TRACE_FAULT_CAPTURE() reads
 * the CURRENT function's LR (EXC_RETURN) and walks the exception stack frame
 * from it. A call into this adapter runs first, which pushes a frame and
 * replaces LR with the return address - so the macro would snapshot the
 * adapter instead of the fault site, producing a plausible looking PC that is
 * not where the fault happened. That is worse than no record at all.
 *
 * The fault hook is therefore the MACRO itself: write MDK_TRACE_FAULT_CAPTURE()
 * as the FIRST statement of each fault handler. SVCrtOS already does this via
 * its own SVCRT_TRACE_FAULT_CAPTURE(); on AC5 a bare macro degrades to
 * "class + CFSR only", and an assembly vector thunk calling
 * mdk_trace_fault_capture(exc, msp, psp) is what recovers the full frame. */

/* True when MDK_TRACE_SVCRT_HOOKS is 1 and the traces are actually emitted.
 * A firmware can report this over its own shell instead of assuming. */
int mdk_trace_svcrt_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* MDK_TRACE_SVCRT_H */
