/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    usart.c
  * @brief   USART2 调试串口：中断收 1 字节 + 行缓冲，阻塞发送。
  *
  * 设计取舍：
  *   - 接收走中断 + 行缓冲，命令解析放主循环（ISR 里不做长打印，避免阻塞）。
  *   - 发送走阻塞 HAL_UART_Transmit（日志量小，简单可靠，不会丢字符）。
  *   - 行太长时整行丢弃并计数，避免半截命令黏成诡异指令（rx_overflow 可见）。
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "usart.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* USER CODE BEGIN 0 */

#define UART_LINE_MAX 64

UART_HandleTypeDef huart2;

static uint8_t  rx_byte;                       /* 中断接收的当前字节 */
static char     rx_line[UART_LINE_MAX];        /* 行缓冲 */
static uint16_t rx_len;
static volatile uint8_t  rx_line_ready;        /* ISR 置位，主循环清 */
static volatile uint32_t rx_total;             /* 累计字节数 */
static volatile uint32_t rx_overflow;          /* 超长丢弃次数 */

/* USER CODE END 0 */

/**
  * @brief  USART2 初始化：115200 8N1，开中断接收。
  */
void MX_USART2_UART_Init(void)
{
  huart2.Instance          = USART2;
  huart2.Init.BaudRate     = 115200;
  huart2.Init.WordLength   = UART_WORDLENGTH_8B;
  huart2.Init.StopBits     = UART_STOPBITS_1;
  huart2.Init.Parity       = UART_PARITY_NONE;
  huart2.Init.Mode         = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl    = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* 先挂上一次接收，之后每个字节在回调里续挂 */
  if (HAL_UART_Receive_IT(&huart2, &rx_byte, 1) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief  USART2 底层初始化：时钟 / GPIO / NVIC。
  *         PA2 = USART2_TX，PA3 = USART2_RX（AF7）。
  */
void HAL_UART_MspInit(UART_HandleTypeDef* huart)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  if (huart->Instance == USART2)
  {
    __HAL_RCC_USART2_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitStruct.Pin       = GPIO_PIN_2 | GPIO_PIN_3;
    GPIO_InitStruct.Mode      = GPIO_MODE_AF_PP;
    /* RX 上拉：悬空时不至于收到一堆噪声字节（没接线时表现为乱码） */
    GPIO_InitStruct.Pull      = GPIO_PULLUP;
    GPIO_InitStruct.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    HAL_NVIC_SetPriority(USART2_IRQn, 1, 0);
    HAL_NVIC_EnableIRQ(USART2_IRQn);
  }
}

void HAL_UART_MspDeInit(UART_HandleTypeDef* huart)
{
  if (huart->Instance == USART2)
  {
    __HAL_RCC_USART2_CLK_DISABLE();
    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_2 | GPIO_PIN_3);
    HAL_NVIC_DisableIRQ(USART2_IRQn);
  }
}

/**
  * @brief  收到一个字节：组行，遇 \r 或 \n 交行给主循环。
  */
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
  if (huart->Instance == USART2)
  {
    rx_total++;

    if (rx_byte == '\r' || rx_byte == '\n')
    {
      if (rx_len > 0 && !rx_line_ready)
      {
        rx_line[rx_len] = '\0';
        rx_line_ready = 1;          /* 上一行还没被主循环取走时不覆盖 */
      }
      else if (rx_line_ready)
      {
        rx_overflow++;
        rx_len = 0;
      }
    }
    else if (rx_len < (UART_LINE_MAX - 1))
    {
      rx_line[rx_len++] = (char)rx_byte;
    }
    else
    {
      rx_overflow++;                /* 行太长：整行丢弃，避免半截命令 */
      rx_len = 0;
    }

    HAL_UART_Receive_IT(&huart2, &rx_byte, 1);
  }
}

/* -------------------------------------------------------------------- */
/* 发送                                                                  */
/* -------------------------------------------------------------------- */
void uart_puts(const char *s)
{
  if (s == NULL)
  {
    return;
  }
  (void)HAL_UART_Transmit(&huart2, (uint8_t *)s, (uint16_t)strlen(s), 1000);
}

void uart_printf(const char *fmt, ...)
{
  char buf[128];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n > 0)
  {
    if (n > (int)(sizeof(buf) - 1))
    {
      n = (int)(sizeof(buf) - 1);   /* 截断，不漏掉结尾 */
    }
    (void)HAL_UART_Transmit(&huart2, (uint8_t *)buf, (uint16_t)n, 1000);
  }
}

uint32_t uart_rx_total(void)
{
  return rx_total;
}

uint32_t uart_rx_overflow(void)
{
  return rx_overflow;
}

void uart_banner(void)
{
  uart_puts("\r\n");
  uart_puts("=== mdk_test debug uart ===\r\n");
  uart_puts("USART2  PA2=TX  PA3=RX  115200 8N1  (wire crossed, GND common)\r\n");
  uart_puts("type 'help' for commands\r\n");
}

/* -------------------------------------------------------------------- */
/* 命令解析（主循环上下文）                                              */
/* -------------------------------------------------------------------- */
static void uart_handle_line(char *line)
{
  if (line[0] == '\0')
  {
    return;
  }

  if (strcmp(line, "help") == 0)
  {
    uart_puts("commands: help | ping | info | tick | echo <text> | rx\r\n");
  }
  else if (strcmp(line, "ping") == 0)
  {
    uart_puts("pong\r\n");
  }
  else if (strcmp(line, "info") == 0)
  {
    uint32_t devid = *(volatile uint32_t *)0xE0042000UL;   /* DBGMCU_IDCODE */
    uart_printf("info: devid=0x%08lX sysclk=%luHz tick=%lums rx=%lu ovf=%lu\r\n",
                (unsigned long)devid,
                (unsigned long)HAL_RCC_GetSysClockFreq(),
                (unsigned long)HAL_GetTick(),
                (unsigned long)rx_total,
                (unsigned long)rx_overflow);
  }
  else if (strcmp(line, "tick") == 0)
  {
    uart_printf("tick=%lu\r\n", (unsigned long)HAL_GetTick());
  }
  else if (strcmp(line, "rx") == 0)
  {
    uart_printf("rx_total=%lu overflow=%lu\r\n",
                (unsigned long)rx_total, (unsigned long)rx_overflow);
  }
  else if (strncmp(line, "echo ", 5) == 0)
  {
    uart_printf("%s\r\n", line + 5);
  }
  else
  {
    uart_printf("ERR unknown cmd '%s' (try: help)\r\n", line);
  }
}

/**
  * @brief  主循环轮询：取走整行命令并响应；每 1s 打一行心跳。
  *         心跳的用处：不确定线接对没有时，只要有周期输出就说明 RX/TX 通了。
  */
void uart_poll(void)
{
  static uint32_t last_hb = 0;
  uint32_t now = HAL_GetTick();

  if (rx_line_ready)
  {
    char line[UART_LINE_MAX];
    uint16_t n = rx_len;

    if (n >= UART_LINE_MAX)
    {
      n = UART_LINE_MAX - 1;
    }
    memcpy(line, rx_line, n);
    line[n] = '\0';
    rx_len = 0;
    rx_line_ready = 0;
    uart_handle_line(line);
  }

  if (now - last_hb >= 1000U)
  {
    last_hb = now;
    uart_printf("hb %lu\r\n", (unsigned long)now);
  }
}
