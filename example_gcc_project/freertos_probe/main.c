/* mdkdebug「RTOS 任务感知」真机验证固件
 * =========================================
 * 目的：让 mdkdebug 的 rtos_info / rtos_tasks / rtos_objects 有一块**真的在跑
 * FreeRTOS** 的目标可以验证，而不是只在 mock 上自说自话。
 *
 * 这个固件刻意造出几种「主机侧必须能分辨」的现场：
 *   led    —— 周期任务（vTaskDelay），都在就绪/阻塞之间来回
 *   prod   —— 往队列发消息（优先级最高）
 *   work   —— 收队列 + 拿互斥量（验证队列与互斥量状态）
 *   deep   —— 递归吃栈，栈水位接近用满（验证 0xA5 填充计数与告警）
 *   stuck  —— 用 portMAX_DELAY 无限阻塞在一个永不释放的信号量上
 *             （FreeRTOS 会把这种任务放进 xSuspendedTaskList，很容易被误报成
 *              「被挂起」——主机侧要靠 xEventListItem.pvContainer 分辨）
 *   susp   —— 真的被 vTaskSuspend 挂起（对照 stuck）
 *
 * 另外 `rep` 任务每秒把**内核自己算的** uxTaskGetStackHighWaterMark 写进
 * g_kernel_hwm[]，主机侧读出来就能和 rtos_tasks 报的水位逐项对照——
 * 一致性是算出来的，不是声明出来的。
 */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* ---- 目标侧自报的对照数据（主机读这些全局符号） ---- */
#define HWM_N 6
TaskHandle_t g_probe_handles[HWM_N];
volatile uint16_t g_kernel_hwm[HWM_N];       /* 单位：字（word），内核自己算的 */
volatile uint32_t g_led_ticks;               /* 心跳：证明调度器在跑、不只是起来了 */
volatile uint32_t g_work_msgs;               /* worker 收了几条消息 */

/* 队列 / 信号量 / 互斥量：都登记进内核注册表，主机侧才枚举得到 */
QueueHandle_t   g_q_sensor;
SemaphoreHandle_t g_sem_stuck;               /* 计数初值 0，永不 give —— stuck 卡在这 */
SemaphoreHandle_t g_mtx_bus;                 /* work 持有 */

/* SysTick 走复位后的 HSI 16MHz（与 configCPU_CLOCK_HZ 一致） */
static void systick_init_16mhz(void)
{
    volatile uint32_t *const syst_csr = (volatile uint32_t *)0xE000E010u;
    volatile uint32_t *const syst_rvr = (volatile uint32_t *)0xE000E014u;
    volatile uint32_t *const syst_cvr = (volatile uint32_t *)0xE000E018u;

    *syst_rvr = 16000u - 1u;
    *syst_cvr = 0u;
    *syst_csr = 0x7u;
}

static void busy_spin(volatile uint32_t n)
{
    while (n-- != 0u) {
        __asm volatile("nop");
    }
}

/* ---- 任务 ---- */
static void led_task(void *arg)
{
    (void)arg;
    for (;;) {
        g_led_ticks++;
        busy_spin(20000u);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

static void prod_task(void *arg)
{
    uint32_t v = 0u;
    (void)arg;
    for (;;) {
        v++;
        (void)xQueueSend(g_q_sensor, &v, 0u);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void work_task(void *arg)
{
    uint32_t v = 0u;
    (void)arg;
    for (;;) {
        if (xQueueReceive(g_q_sensor, &v, pdMS_TO_TICKS(200)) == pdPASS) {
            if (xSemaphoreTake(g_mtx_bus, pdMS_TO_TICKS(50)) == pdPASS) {
                g_work_msgs++;
                busy_spin(5000u);
                (void)xSemaphoreGive(g_mtx_bus);
            }
        }
    }
}

/* 递归吃栈：3 层，每层一个 48 字的局部数组，栈只给 160 字 —— 水位应接近用满 */
static volatile uint32_t deep_sink;

static void deep_recurse(int level)
{
    volatile uint32_t buf[40];
    uint32_t i;

    for (i = 0u; i < 40u; i++) {
        buf[i] = i + (uint32_t)level;
    }
    if (level > 0) {
        deep_recurse(level - 1);
    }
    deep_sink = buf[0] + buf[39];
}

static void deep_task(void *arg)
{
    (void)arg;
    for (;;) {
        deep_recurse(2);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

static void stuck_task(void *arg)
{
    (void)arg;
    /* 初值 0 的信号量 + 无限等待 = 永远停在这条等待链表上 */
    (void)xSemaphoreTake(g_sem_stuck, portMAX_DELAY);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static void susp_task(void *arg)
{
    (void)arg;
    /* 自己把自己挂起：之后一直停在 xSuspendedTaskList 上（对照 stuck 的无限阻塞） */
    vTaskDelay(pdMS_TO_TICKS(200));
    vTaskSuspend(NULL);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static void rep_task(void *arg)
{
    int i;
    (void)arg;
    for (;;) {
        for (i = 0; i < HWM_N; i++) {
            if (g_probe_handles[i] != NULL) {
                g_kernel_hwm[i] = (uint16_t)uxTaskGetStackHighWaterMark(g_probe_handles[i]);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void vApplicationMallocFailedHook(void)
{
    for (;;) {
    }
}

int main(void)
{
    systick_init_16mhz();

    g_q_sensor  = xQueueCreate(4, sizeof(uint32_t));
    g_sem_stuck = xSemaphoreCreateCounting(1, 0);   /* 初值 0 */
    g_mtx_bus   = xSemaphoreCreateMutex();

    if ((g_q_sensor == NULL) || (g_sem_stuck == NULL) || (g_mtx_bus == NULL)) {
        for (;;) {
        }
    }

    /* 内核注册表：只有登记过的队列/信号量，主机侧才枚举得到 */
    vQueueAddToRegistry(g_q_sensor, "q_sensor");
    vQueueAddToRegistry(g_sem_stuck, "sem_stuck");
    vQueueAddToRegistry(g_mtx_bus, "mtx_bus");

    (void)xTaskCreate(led_task,   "led",   128, NULL, 2, &g_probe_handles[0]);
    (void)xTaskCreate(deep_task,  "deep",  192, NULL, 1, &g_probe_handles[1]);
    (void)xTaskCreate(stuck_task, "stuck", 128, NULL, 1, &g_probe_handles[2]);
    (void)xTaskCreate(susp_task,  "susp",   96, NULL, 1, &g_probe_handles[3]);
    (void)xTaskCreate(prod_task,  "prod",  128, NULL, 3, &g_probe_handles[4]);
    (void)xTaskCreate(work_task,  "work",  256, NULL, 2, &g_probe_handles[5]);
    (void)xTaskCreate(rep_task,   "rep",   192, NULL, 1, NULL);

    vTaskStartScheduler();

    /* 走到这里只可能是堆不够 */
    for (;;) {
    }
}
