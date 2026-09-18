/* FreeRTOS 配置：为 mdkdebug 的 rtos_* 工具做真机验证固件。
 *
 * 这里故意把几个「会改变 TCB_t / Queue_t 布局」的选项都打开：
 *   configUSE_TRACE_FACILITY        -> TCB 里多出 uxTCBNumber / uxTaskNumber / ulRunTimeCounter
 *   configUSE_MUTEXES               -> 多出 uxBasePriority / uxMutexesHeld
 *   configRECORD_STACK_HIGH_ADDRESS -> 多出 pxEndOfStack
 *   configQUEUE_REGISTRY_SIZE > 0   -> 内核维护 xQueueRegistry，主机侧才可能枚举队列
 * 这样 rtos_tasks/rtos_objects 就**必须**走 DWARF 取偏移才可能算对；
 * 任何写死偏移的实现都会在这里读出垃圾。
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stdint.h>

extern uint32_t SystemCoreClock;

#define configUSE_PREEMPTION                     1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION  0
#define configUSE_TICKLESS_IDLE                  0
#define configCPU_CLOCK_HZ                       ( 16000000UL )   /* 复位后默认 HSI 16MHz */
#define configTICK_RATE_HZ                       ( 1000U )
#define configMAX_PRIORITIES                     ( 5 )
#define configMINIMAL_STACK_SIZE                 ( 128 )
#define configTOTAL_HEAP_SIZE                    ( ( size_t ) ( 24 * 1024 ) )
#define configMAX_TASK_NAME_LEN                  ( 16 )
#define configUSE_16_BIT_TICKS                   0
#define configIDLE_SHOULD_YIELD                  1

#define configUSE_MUTEXES                        1
#define configUSE_RECURSIVE_MUTEXES              1
#define configUSE_COUNTING_SEMAPHORES            1
#define configQUEUE_REGISTRY_SIZE                8
#define configUSE_QUEUE_SETS                     0
#define configUSE_TASK_NOTIFICATIONS             1
#define configUSE_TIME_SLICING                   1
#define configUSE_NEWLIB_REENTRANT               0
#define configENABLE_BACKWARD_COMPATIBILITY      0
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS  0
#define configSTACK_DEPTH_TYPE                   uint16_t
#define configMESSAGE_BUFFER_LENGTH_TYPE         size_t
#define configUSE_C_RUNTIME_TLS_SUPPORT          0

#define configUSE_TRACE_FACILITY                 1
#define configUSE_STATS_FORMATTING_FUNCTIONS     0
#define configRECORD_STACK_HIGH_ADDRESS          1
#define configGENERATE_RUN_TIME_STATS            0

#define configSUPPORT_STATIC_ALLOCATION          0
#define configSUPPORT_DYNAMIC_ALLOCATION         1
#define configCHECK_FOR_STACK_OVERFLOW           0
#define configUSE_MALLOC_FAILED_HOOK             1
#define configUSE_IDLE_HOOK                      0
#define configUSE_TICK_HOOK                      0
#define configUSE_TIMERS                         0
#define configNUMBER_OF_CORES                    1
#define configUSE_POSIX_ERRNO                    0

#define INCLUDE_vTaskPrioritySet                 1
#define INCLUDE_uxTaskPriorityGet                1
#define INCLUDE_vTaskDelete                      1
#define INCLUDE_vTaskSuspend                     1
#define INCLUDE_vTaskDelayUntil                  1
#define INCLUDE_vTaskDelay                       1
#define INCLUDE_xTaskGetSchedulerState           1
#define INCLUDE_xTaskGetCurrentTaskHandle        1
#define INCLUDE_uxTaskGetStackHighWaterMark      1
#define INCLUDE_xTaskGetIdleTaskHandle           1

#define configASSERT( x ) \
    if( ( x ) == 0 ) { taskDISABLE_INTERRUPTS(); for( ;; ) { } }

/* 中断优先级：Cortex-M4 用 4 位优先级 */
#define configPRIO_BITS                          4
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY      15
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 5
#define configKERNEL_INTERRUPT_PRIORITY \
    ( configLIBRARY_LOWEST_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )
#define configMAX_SYSCALL_INTERRUPT_PRIORITY \
    ( configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )

#endif /* FREERTOS_CONFIG_H */
