/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    usart.h
  * @brief   USART2 调试串口（PA2 = TX / PA3 = RX，115200 8N1）
  *
  * 接线（务必交叉）：外部模块 TX -> PA3（MCU 的 RX），
  *                   模块 RX -> PA2（MCU 的 TX），GND 必须共地。
  * 选 USART2 而不是 USART1：不占 SWD 的 PA13/PA14，且与 NUCLEO 板载
  * VCP 的惯用走线一致；PA9/PA10 在 F401 上与 USB_OTG_FS 复用，留给以后。
  ******************************************************************************
  */
/* USER CODE END Header */

#ifndef __USART_H__
#define __USART_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"

extern UART_HandleTypeDef huart2;

/* 初始化 USART2（含 GPIO/时钟/中断）并开始接收 */
void MX_USART2_UART_Init(void);

/* 阻塞发送：日志用，短字符串即可 */
void uart_puts(const char *s);

/* 带格式发送（内部 128 字节缓冲，超长自动截断） */
void uart_printf(const char *fmt, ...);

/* 主循环轮询：处理收到的一整行命令 + 每秒心跳（hb <tick>） */
void uart_poll(void);

/* 上电 banner（打印引脚与波特率，便于确认线接对没有） */
void uart_banner(void);

/* 累计收到的字节数 / 超长丢弃次数（可用于真机验证读变量） */
uint32_t uart_rx_total(void);
uint32_t uart_rx_overflow(void);

#ifdef __cplusplus
}
#endif

#endif /* __USART_H__ */
