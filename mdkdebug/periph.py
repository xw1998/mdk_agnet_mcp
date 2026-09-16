# -*- coding: utf-8 -*-
"""
periph —— STM32F4 常用外设寄存器内置表。

不依赖外部 SVD 文件（ST 官方 SVD 反爬、cmsis-svd 网络不稳、本地常无 DFP），
离线内置 STM32F4 系列常用外设（RCC/GPIO/USART/SPI/I2C/TIM/ADC/PWR/FLASH/
SysTick/SCB/NVIC/DWT/EXTI/SYSCFG 等）的寄存器基址、偏移与关键位域，供
read_peripheral / list_peripherals 工具按地址实时读取目标内存并解读。

覆盖型号：STM32F401/F411/F427/F429 等 F4 系列（外设基址一致）。
"""

from __future__ import annotations

# 外设寄存器表：
#   name -> {
#     "base": 外设基址,
#     "desc": 一句话说明,
#     "regs": { reg名: {"off": 寄存器偏移, "fields": [(位域名, lsb, 宽度, 可选取值枚举dict或None), ...]} }
#   }
PERIPHERALS: dict = {
    "RCC": {
        "base": 0x40023800,
        "desc": "复位与时钟控制（时钟使能/分频/锁相环配置）",
        "regs": {
            "CR": {"off": 0x00, "fields": [
                ("HSION", 0, 1, None), ("HSIRDY", 1, 1, None),
                ("HSEON", 16, 1, None), ("HSERDY", 17, 1, None),
                ("HSEBYP", 18, 1, None), ("CSSON", 19, 1, None),
                ("PLLON", 24, 1, None), ("PLLRDY", 25, 1, None)]},
            "PLLCFGR": {"off": 0x04, "fields": [
                ("PLLM", 0, 6, None), ("PLLN", 6, 9, None),
                ("PLLP", 16, 2, {0: "x2", 1: "x4", 2: "x6", 3: "x8"}),
                ("PLLSRC", 22, 1, {0: "HSI", 1: "HSE"}),
                ("PLLQ", 24, 4, None)]},
            "CFGR": {"off": 0x08, "fields": [
                ("SW", 0, 2, {0: "HSI", 1: "HSE", 2: "PLL"}),
                ("SWS", 2, 2, {0: "HSI", 1: "HSE", 2: "PLL"}),
                ("HPRE", 4, 4, None), ("PPRE1", 10, 3, None), ("PPRE2", 13, 3, None),
                ("MCO1", 21, 2, None), ("MCO1PRE", 24, 3, None),
                ("MCO2PRE", 27, 3, None), ("MCO2", 30, 1, None)]},
            "AHB1ENR": {"off": 0x30, "fields": [
                ("GPIOAEN", 0, 1, None), ("GPIOBEN", 1, 1, None), ("GPIOCEN", 2, 1, None),
                ("GPIODEN", 3, 1, None), ("GPIOEEN", 4, 1, None), ("GPIOFEN", 5, 1, None),
                ("GPIOGEN", 6, 1, None), ("GPIOHEN", 7, 1, None),
                ("DMA1EN", 21, 1, None), ("DMA2EN", 22, 1, None)]},
            "AHB2ENR": {"off": 0x34, "fields": [
                ("OTGFSEN", 7, 1, None)]},
            "APB1ENR": {"off": 0x40, "fields": [
                ("TIM2EN", 0, 1, None), ("TIM3EN", 1, 1, None), ("TIM4EN", 2, 1, None),
                ("TIM5EN", 3, 1, None), ("TIM6EN", 4, 1, None),
                ("WWDGEN", 11, 1, None), ("SPI2EN", 14, 1, None), ("SPI3EN", 15, 1, None),
                ("USART2EN", 17, 1, None), ("I2C1EN", 21, 1, None),
                ("I2C2EN", 22, 1, None), ("I2C3EN", 23, 1, None),
                ("PWREN", 28, 1, None)]},
            "APB2ENR": {"off": 0x44, "fields": [
                ("TIM1EN", 0, 1, None), ("USART1EN", 4, 1, None), ("USART6EN", 5, 1, None),
                ("ADC1EN", 8, 1, None), ("SPI1EN", 12, 1, None),
                ("SYSCFGEN", 14, 1, None), ("EXTIEN", 15, 1, None),
                ("TIM9EN", 16, 1, None), ("TIM10EN", 17, 1, None), ("TIM11EN", 18, 1, None)]},
            "BDCR": {"off": 0x70, "fields": [
                ("LSEON", 0, 1, None), ("LSERDY", 1, 1, None), ("RTCSEL", 8, 2, None),
                ("RTCEN", 15, 1, None)]},
            "CSR": {"off": 0x74, "fields": [
                ("LSION", 0, 1, None), ("LSIRDY", 1, 1, None),
                ("RMVF", 24, 1, None), ("PINRSTF", 26, 1, None),
                ("PORRSTF", 27, 1, None), ("SFTF", 28, 1, None),
                ("IWDGRSTF", 29, 1, None), ("WWDGRSTF", 30, 1, None),
                ("LPWRRSTF", 31, 1, None)]},
        },
    },

    "GPIOA": {"base": 0x40020000, "desc": "通用 IO 端口 A", "gpio": True},
    "GPIOB": {"base": 0x40020400, "desc": "通用 IO 端口 B", "gpio": True},
    "GPIOC": {"base": 0x40020800, "desc": "通用 IO 端口 C", "gpio": True},
    "GPIOD": {"base": 0x40020C00, "desc": "通用 IO 端口 D", "gpio": True},
    "GPIOE": {"base": 0x40021000, "desc": "通用 IO 端口 E", "gpio": True},
    "GPIOF": {"base": 0x40021400, "desc": "通用 IO 端口 F", "gpio": True},
    "GPIOG": {"base": 0x40021800, "desc": "通用 IO 端口 G", "gpio": True},
    "GPIOH": {"base": 0x40021C00, "desc": "通用 IO 端口 H", "gpio": True},

    "USART1": {"base": 0x40011000, "desc": "通用同步/异步收发器 1", "usart": True},
    "USART2": {"base": 0x40004400, "desc": "通用同步/异步收发器 2", "usart": True},
    "USART6": {"base": 0x40011400, "desc": "通用同步/异步收发器 6", "usart": True},

    "SPI1": {"base": 0x40013000, "desc": "串行外设接口 1", "spi": True},
    "SPI2": {"base": 0x40003800, "desc": "串行外设接口 2", "spi": True},
    "SPI3": {"base": 0x40003C00, "desc": "串行外设接口 3", "spi": True},

    "I2C1": {"base": 0x40005400, "desc": "I2C 总线 1", "i2c": True},
    "I2C2": {"base": 0x40005800, "desc": "I2C 总线 2", "i2c": True},
    "I2C3": {"base": 0x40005C00, "desc": "I2C 总线 3", "i2c": True},

    "TIM1": {"base": 0x40010000, "desc": "高级定时器 1", "tim": True, "advanced": True},
    "TIM2": {"base": 0x40000000, "desc": "通用定时器 2", "tim": True},
    "TIM3": {"base": 0x40000400, "desc": "通用定时器 3", "tim": True},
    "TIM4": {"base": 0x40000800, "desc": "通用定时器 4", "tim": True},
    "TIM5": {"base": 0x40000C00, "desc": "通用定时器 5", "tim": True},
    "TIM6": {"base": 0x40001000, "desc": "基本定时器 6", "tim": True},

    "ADC1": {"base": 0x40012000, "desc": "模数转换器 1", "adc": True},

    "PWR": {"base": 0x40007000, "desc": "电源控制", "pwr": True},
    "FLASH": {"base": 0x40023C00, "desc": "Flash 接口（等待周期/预取）", "flash": True},
    "SysTick": {"base": 0xE000E010, "desc": "系统嘀嗒定时器", "systick": True},
    "SCB": {"base": 0xE000ED00, "desc": "系统控制块（中断/异常）", "scb": True},
    "NVIC": {"base": 0xE000E100, "desc": "嵌套向量中断控制器", "nvic": True},
    "DWT": {"base": 0xE0001000, "desc": "数据观察点与跟踪", "dwt": True},
    "EXTI": {"base": 0x40013C00, "desc": "外部中断/事件控制器", "exti": True},
    "SYSCFG": {"base": 0x40013800, "desc": "系统配置控制器", "syscfg": True},
}

# ---------------- 模板外设寄存器定义 ----------------
_GPIO_FIELDS = {0: "输入", 1: "输出", 2: "复用", 3: "模拟"}
_GPIO_REG_MAP = {
    "MODER": {"off": 0x00, "fields": [(f"MODER{p}", p * 2, 2, _GPIO_FIELDS) for p in range(16)]},
    "OTYPER": {"off": 0x04, "fields": [(f"OT{p}", p, 1, {0: "推挽", 1: "开漏"}) for p in range(16)]},
    "OSPEEDR": {"off": 0x08, "fields": [(f"OSPEED{p}", p * 2, 2, None) for p in range(16)]},
    "PUPDR": {"off": 0x0C, "fields": [(f"PUP{p}", p * 2, 2, {0: "无上拉/下拉", 1: "上拉", 2: "下拉"}) for p in range(16)]},
    "IDR": {"off": 0x10, "fields": [(f"ID{p}", p, 1, None) for p in range(16)]},
    "ODR": {"off": 0x14, "fields": [(f"OD{p}", p, 1, None) for p in range(16)]},
    "BSRR": {"off": 0x18, "fields": []},
    "LCKR": {"off": 0x1C, "fields": [(f"LCK{p}", p, 1, None) for p in range(16)]},
    "AFRL": {"off": 0x20, "fields": [(f"AF{p}", p * 4, 4, None) for p in range(8)]},
    "AFRH": {"off": 0x24, "fields": [(f"AF{p}", (p - 8) * 4, 4, None) for p in range(8, 16)]},
}

_USART_REG_MAP = {
    "SR": {"off": 0x00, "fields": [
        ("PE", 0, 1, None), ("FE", 1, 1, None), ("NE", 2, 1, None), ("ORE", 3, 1, None),
        ("IDLE", 4, 1, None), ("RXNE", 5, 1, None), ("TC", 6, 1, None), ("TXE", 7, 1, None)]},
    "DR": {"off": 0x04, "fields": [("DATA", 0, 9, None)]},
    "BRR": {"off": 0x08, "fields": [("DIV", 0, 16, None)]},
    "CR1": {"off": 0x0C, "fields": [
        ("SBK", 0, 1, None), ("RWU", 1, 1, None), ("RE", 2, 1, None), ("TE", 3, 1, None),
        ("IDLEIE", 4, 1, None), ("RXNEIE", 5, 1, None), ("TCIE", 6, 1, None),
        ("TXEIE", 7, 1, None), ("PEIE", 8, 1, None), ("PS", 9, 1, {0: "偶校验", 1: "奇校验"}),
        ("PCE", 10, 1, None), ("WAKE", 11, 1, None), ("M", 12, 1, {0: "8位", 1: "9位"}),
        ("UE", 13, 1, None)]},
    "CR2": {"off": 0x10, "fields": [
        ("STOP", 12, 2, {0: "1停止位", 1: "0.5", 2: "2", 3: "1.5"}), ("LINEN", 14, 1, None)]},
    "CR3": {"off": 0x14, "fields": [
        ("EIE", 0, 1, None), ("IREN", 1, 1, None), ("IRLP", 2, 1, None), ("HDSEL", 3, 1, None),
        ("DMAR", 6, 1, None), ("DMAT", 7, 1, None), ("RTSE", 8, 1, None), ("CTSE", 9, 1, None)]},
    "GTPR": {"off": 0x18, "fields": []},
}

_SPI_REG_MAP = {
    "CR1": {"off": 0x00, "fields": [
        ("CPHA", 0, 1, {0: "第1个边沿", 1: "第2个边沿"}),
        ("CPOL", 1, 1, {0: "空闲低", 1: "空闲高"}),
        ("MSTR", 2, 1, {0: "从模式", 1: "主模式"}),
        ("BR", 3, 3, None), ("SPE", 6, 1, None), ("LSBFIRST", 7, 1, None),
        ("SSI", 8, 1, None), ("SSM", 9, 1, None), ("RXONLY", 10, 1, None),
        ("DFF", 11, 1, {0: "8位", 1: "16位"}), ("CRCNEXT", 12, 1, None),
        ("CRCEN", 13, 1, None), ("BIDIOE", 14, 1, None), ("BIDIMODE", 15, 1, None)]},
    "CR2": {"off": 0x04, "fields": [
        ("RXDMAEN", 0, 1, None), ("TXDMAEN", 1, 1, None), ("SSOE", 2, 1, None),
        ("FRF", 4, 1, None), ("ERRIE", 5, 1, None), ("RXNEIE", 6, 1, None), ("TXEIE", 7, 1, None)]},
    "SR": {"off": 0x08, "fields": [
        ("RXNFF", 0, 1, None), ("TXE", 1, 1, None), ("CHSIDE", 2, 1, None),
        ("UDR", 3, 1, None), ("CRCERR", 4, 1, None), ("MODF", 5, 1, None),
        ("OVR", 6, 1, None), ("BSY", 7, 1, None), ("FRE", 8, 1, None)]},
    "DR": {"off": 0x0C, "fields": [("DATA", 0, 16, None)]},
    "CRCPR": {"off": 0x10, "fields": []},
    "RXCRCR": {"off": 0x14, "fields": []},
    "TXCRCR": {"off": 0x18, "fields": []},
}

_I2C_REG_MAP = {
    "CR1": {"off": 0x00, "fields": [
        ("PE", 0, 1, None), ("SMBUS", 1, 1, None), ("ENARP", 4, 1, None),
        ("ENPEC", 5, 1, None), ("ENGC", 6, 1, None), ("NOSTRETCH", 7, 1, None),
        ("START", 8, 1, None), ("STOP", 9, 1, None), ("ACK", 10, 1, None),
        ("PEC", 12, 1, None), ("SWRST", 15, 1, None)]},
    "CR2": {"off": 0x04, "fields": [
        ("FREQ", 0, 6, None), ("ITERREN", 8, 1, None), ("ITEVTEN", 9, 1, None),
        ("ITBUFEN", 10, 1, None), ("DMAEN", 11, 1, None)]},
    "OAR1": {"off": 0x08, "fields": [("ADD", 1, 9, None), ("ADDMODE", 15, 1, None)]},
    "OAR2": {"off": 0x0C, "fields": [("ADD2", 1, 7, None)]},
    "DR": {"off": 0x10, "fields": [("DR", 0, 8, None)]},
    "SR1": {"off": 0x14, "fields": [
        ("SB", 0, 1, None), ("ADDR", 1, 1, None), ("BTF", 2, 1, None),
        ("STOPF", 4, 1, None), ("RxNE", 6, 1, None), ("TxE", 7, 1, None),
        ("BERR", 8, 1, None), ("ARLO", 9, 1, None), ("AF", 10, 1, None),
        ("OVR", 11, 1, None), ("PECERR", 12, 1, None)]},
    "SR2": {"off": 0x18, "fields": [
        ("MSL", 0, 1, {0: "从模式", 1: "主模式"}), ("BUSY", 1, 1, None),
        ("TRA", 2, 1, None), ("PEC", 8, 8, None)]},
    "CCR": {"off": 0x1C, "fields": [
        ("CCR", 0, 12, None), ("DUTY", 14, 1, None), ("F/S", 15, 1, {0: "标准模式", 1: "快速模式"})]},
    "TRISE": {"off": 0x20, "fields": [("TRISE", 0, 6, None)]},
}

_TIM_REG_MAP = {
    "CR1": {"off": 0x00, "fields": [
        ("CEN", 0, 1, None), ("UDIS", 1, 1, None), ("URS", 2, 1, None),
        ("OPM", 3, 1, None), ("DIR", 4, 1, {0: "向上", 1: "向下"}),
        ("CMS", 5, 2, None), ("ARPE", 7, 1, None), ("CKD", 8, 2, None)]},
    "CR2": {"off": 0x04, "fields": [("MMS", 4, 3, None)]},
    "SMCR": {"off": 0x08, "fields": [("SMS", 0, 3, None), ("TS", 4, 3, None)]},
    "DIER": {"off": 0x0C, "fields": [
        ("UIE", 0, 1, None), ("CC1IE", 1, 1, None), ("CC2IE", 2, 1, None),
        ("CC3IE", 3, 1, None), ("CC4IE", 4, 1, None)]},
    "SR": {"off": 0x10, "fields": [
        ("UIF", 0, 1, None), ("CC1IF", 1, 1, None), ("CC2IF", 2, 1, None),
        ("CC3IF", 3, 1, None), ("CC4IF", 4, 1, None)]},
    "EGR": {"off": 0x14, "fields": [("UG", 0, 1, None)]},
    "CCMR1": {"off": 0x18, "fields": [("CC1S", 0, 2, None), ("CC2S", 8, 2, None)]},
    "CCMR2": {"off": 0x1C, "fields": [("CC3S", 0, 2, None), ("CC4S", 8, 2, None)]},
    "CCER": {"off": 0x20, "fields": [
        ("CC1E", 0, 1, None), ("CC1P", 1, 1, None), ("CC2E", 4, 1, None), ("CC2P", 5, 1, None),
        ("CC3E", 8, 1, None), ("CC3P", 9, 1, None), ("CC4E", 12, 1, None), ("CC4P", 13, 1, None)]},
    "CNT": {"off": 0x24, "fields": [("CNT", 0, 16, None)]},
    "PSC": {"off": 0x28, "fields": [("PSC", 0, 16, None)]},
    "ARR": {"off": 0x2C, "fields": [("ARR", 0, 16, None)]},
    "CCR1": {"off": 0x34, "fields": [("CCR1", 0, 16, None)]},
    "CCR2": {"off": 0x38, "fields": [("CCR2", 0, 16, None)]},
    "CCR3": {"off": 0x3C, "fields": [("CCR3", 0, 16, None)]},
    "CCR4": {"off": 0x40, "fields": [("CCR4", 0, 16, None)]},
}
_TIM_ADV_EXTRA = {
    "RCR": {"off": 0x30, "fields": [("REP", 0, 8, None)]},
    "BDTR": {"off": 0x44, "fields": [
        ("MOE", 15, 1, None), ("AOE", 14, 1, None), ("BKP", 13, 1, None)]},
}

_ADC_REG_MAP = {
    "SR": {"off": 0x00, "fields": [
        ("AWD", 0, 1, None), ("EOC", 1, 1, None), ("JEOC", 2, 1, None),
        ("JSTRT", 3, 1, None), ("STRT", 4, 1, None), ("OVR", 5, 1, None)]},
    "CR1": {"off": 0x04, "fields": [
        ("AWDCH", 0, 5, None), ("EOCIE", 5, 1, None), ("AWDIE", 6, 1, None),
        ("JEOCIE", 7, 1, None), ("SCAN", 8, 1, None), ("DISCEN", 11, 1, None),
        ("JAUTO", 10, 1, None), ("DISCNUM", 13, 3, None), ("JAWDEN", 22, 1, None),
        ("AWDEN", 23, 1, None)]},
    "CR2": {"off": 0x08, "fields": [
        ("ADON", 0, 1, None), ("CONT", 1, 1, None), ("DMA", 8, 1, None),
        ("ALIGN", 11, 1, {0: "右对齐", 1: "左对齐"}),
        ("EXTSEL", 17, 4, None), ("EXTTRIG", 20, 1, None),
        ("SWSTART", 30, 1, None)]},
    "SMPR1": {"off": 0x0C, "fields": [("SMP10", 0, 3, None), ("SMP11", 3, 3, None), ("SMP12", 6, 3, None), ("SMP13", 9, 3, None), ("SMP14", 12, 3, None), ("SMP15", 15, 3, None), ("SMP16", 18, 3, None), ("SMP17", 21, 3, None), ("SMP18", 24, 3, None)]},
    "SMPR2": {"off": 0x10, "fields": [("SMP0", 0, 3, None), ("SMP1", 3, 3, None), ("SMP2", 6, 3, None), ("SMP3", 9, 3, None), ("SMP4", 12, 3, None), ("SMP5", 15, 3, None), ("SMP6", 18, 3, None), ("SMP7", 21, 3, None), ("SMP8", 24, 3, None), ("SMP9", 27, 3, None)]},
    "SQR3": {"off": 0x34, "fields": [("SQ1", 0, 5, None), ("SQ2", 5, 5, None), ("SQ3", 10, 5, None), ("SQ4", 15, 5, None), ("SQ5", 20, 5, None), ("SQ6", 25, 5, None)]},
    "SQR2": {"off": 0x30, "fields": [("SQ7", 0, 5, None), ("SQ8", 5, 5, None), ("SQ9", 10, 5, None), ("SQ10", 15, 5, None), ("SQ11", 20, 5, None), ("SQ12", 25, 5, None)]},
    "SQR1": {"off": 0x2C, "fields": [("SQ13", 0, 5, None), ("SQ14", 5, 5, None), ("SQ15", 10, 5, None), ("SQ16", 15, 5, None), ("L", 20, 4, None)]},
    "DR": {"off": 0x4C, "fields": [("DATA", 0, 16, None)]},
}

_PWR_REG_MAP = {
    "CR": {"off": 0x00, "fields": [
        ("LPDS", 0, 1, None), ("PDDS", 1, 1, None), ("CWUF", 2, 1, None),
        ("CSBF", 3, 1, None), ("PVDE", 4, 1, None), ("PLS", 5, 3, None),
        ("DBP", 8, 1, None), ("FPDS", 9, 1, None), ("VOS", 14, 2, None)]},
    "CSR": {"off": 0x04, "fields": [
        ("WUF", 0, 1, None), ("SBF", 1, 1, None), ("PVDO", 2, 1, None), ("BRR", 3, 1, None),
        ("EWUP", 8, 1, None), ("BRE", 9, 1, None)]},
}

_FLASH_REG_MAP = {
    "ACR": {"off": 0x00, "fields": [
        ("LATENCY", 0, 3, {0: "0等待", 1: "1等待", 2: "2等待", 3: "3等待", 4: "4等待", 5: "5等待"}),
        ("PRFTEN", 8, 1, None), ("ICEN", 9, 1, None), ("DCEN", 10, 1, None)]},
    "KEYR": {"off": 0x04, "fields": []},
    "OPTKEYR": {"off": 0x08, "fields": []},
    "SR": {"off": 0x0C, "fields": [
        ("BSY", 0, 1, None), ("PGERR", 2, 1, None), ("WRPERR", 4, 1, None), ("EOP", 5, 1, None)]},
    "CR": {"off": 0x10, "fields": [
        ("PG", 0, 1, None), ("SER", 1, 1, None), ("MER", 2, 1, None),
        ("SNB", 3, 4, None), ("PSIZE", 8, 2, None), ("STRT", 16, 1, None),
        ("EOPIE", 24, 1, None), ("LOCK", 31, 1, None)]},
    "OPTCR": {"off": 0x14, "fields": []},
}

_SYSTICK_REG_MAP = {
    "CTRL": {"off": 0x00, "fields": [
        ("ENABLE", 0, 1, None), ("TICKINT", 1, 1, None),
        ("CLKSOURCE", 2, 1, {0: "HCLK/8", 1: "HCLK"}), ("COUNTFLAG", 16, 1, None)]},
    "LOAD": {"off": 0x04, "fields": [("RELOAD", 0, 24, None)]},
    "VAL": {"off": 0x08, "fields": [("CURRENT", 0, 24, None)]},
    "CALIB": {"off": 0x0C, "fields": []},
}

_SCB_REG_MAP = {
    "ICSR": {"off": 0x04, "fields": [
        ("VECTACTIVE", 0, 9, None), ("RETTOBASE", 11, 1, None),
        ("VECTPENDING", 12, 9, None), ("ISRPENDING", 22, 1, None),
        ("PENDSTCLR", 25, 1, None), ("PENDSTSET", 26, 1, None),
        ("PENDSVCLR", 27, 1, None), ("PENDSVSET", 28, 1, None), ("NMIPENDSET", 31, 1, None)]},
    "VTOR": {"off": 0x08, "fields": [("TBLOFF", 7, 25, None)]},
    "AIRCR": {"off": 0x0C, "fields": [
        ("VECTRESET", 0, 1, None), ("VECTCLRACTIVE", 1, 1, None),
        ("SYSRESETREQ", 2, 1, None), ("PRIGROUP", 8, 3, None),
        ("ENDIANESS", 15, 1, None), ("VECTKEY", 16, 16, None)]},
    "SCR": {"off": 0x10, "fields": [
        ("SLEEPONEXIT", 1, 1, None), ("SLEEPDEEP", 2, 1, None), ("SEVONPEND", 4, 1, None)]},
    "CCR": {"off": 0x14, "fields": [
        ("UNALIGN_TRP", 3, 1, None), ("DIV_0_TRP", 4, 1, None), ("STKALIGN", 9, 1, None)]},
    "SHCSR": {"off": 0x24, "fields": [
        ("MEMFAULTACT", 0, 1, None), ("BUSFAULTACT", 1, 1, None),
        ("USGFAULTACT", 2, 1, None), ("SVCALLACT", 7, 1, None),
        ("PENDSVACT", 10, 1, None), ("SYSTICKACT", 11, 1, None),
        ("USGFAULTPEND", 20, 1, None), ("MEMFAULTPEND", 21, 1, None),
        ("BUSFAULTPEND", 22, 1, None), ("SVCALLPEND", 23, 1, None),
        ("MEMFAULTENA", 16, 1, None), ("BUSFAULTENA", 17, 1, None),
        ("USGFAULTENA", 18, 1, None)]},
    "CFSR": {"off": 0x28, "fields": [
        ("MMFSR", 0, 8, None), ("BFSR", 8, 8, None), ("UFSR", 16, 16, None)]},
    "HFSR": {"off": 0x2C, "fields": [
        ("VECTTBL", 1, 1, None), ("FORCED", 30, 1, None), ("DEBUGEVT", 31, 1, None)]},
    "MMFAR": {"off": 0x34, "fields": [("ADDRESS", 0, 32, None)]},
    "BFAR": {"off": 0x38, "fields": [("ADDRESS", 0, 32, None)]},
}

_DWT_REG_MAP = {
    "CTRL": {"off": 0x00, "fields": [
        ("CYCCNTENA", 0, 1, None), ("POSTPRESET", 1, 4, None), ("CYCCNTENA_FREE", 0, 1, None)]},
    "CYCCNT": {"off": 0x04, "fields": [("CYCCNT", 0, 32, None)]},
    "CPICNT": {"off": 0x08, "fields": []},
    "EXCCNT": {"off": 0x0C, "fields": []},
    "SLEEPCNT": {"off": 0x10, "fields": []},
    "LSUCNT": {"off": 0x14, "fields": []},
    "FOLDCNT": {"off": 0x18, "fields": []},
    "PCSR": {"off": 0x1C, "fields": [("PCSAMPLE", 0, 32, None)]},
}

_EXTI_REG_MAP = {
    "IMR": {"off": 0x00, "fields": [(f"MR{i}", i, 1, None) for i in range(23)]},
    "EMR": {"off": 0x04, "fields": [(f"MR{i}", i, 1, None) for i in range(23)]},
    "RTSR": {"off": 0x08, "fields": [(f"TR{i}", i, 1, None) for i in range(23)]},
    "FTSR": {"off": 0x0C, "fields": [(f"TR{i}", i, 1, None) for i in range(23)]},
    "SWIER": {"off": 0x10, "fields": [(f"SWIER{i}", i, 1, None) for i in range(23)]},
    "PR": {"off": 0x14, "fields": [(f"PR{i}", i, 1, None) for i in range(23)]},
}

_SYSCFG_REG_MAP = {
    "MEMRMP": {"off": 0x00, "fields": [("MEM_MODE", 0, 2, None)]},
    "PMC": {"off": 0x04, "fields": []},
    "EXTICR1": {"off": 0x08, "fields": []},
    "EXTICR2": {"off": 0x0C, "fields": []},
    "EXTICR3": {"off": 0x10, "fields": []},
    "EXTICR4": {"off": 0x14, "fields": []},
    "CMPCR": {"off": 0x20, "fields": []},
}

_NVIC_ISER = {"ISER0": 0x00, "ISER1": 0x04, "ISER2": 0x08, "ISER3": 0x0C,
              "ISER4": 0x10, "ISER5": 0x14, "ISER6": 0x18, "ISER7": 0x1C}
_NVIC_ISPR = {"ISPR0": 0x100, "ISPR1": 0x104, "ISPR2": 0x108, "ISPR3": 0x10C,
              "ISPR4": 0x110, "ISPR5": 0x114, "ISPR6": 0x118, "ISPR7": 0x11C}
_NVIC_ICPR = {"ICPR0": 0x180, "ICPR1": 0x184, "ICPR2": 0x188, "ICPR3": 0x18C,
              "ICPR4": 0x190, "ICPR5": 0x194, "ICPR6": 0x198, "ICPR7": 0x19C}


def _resolve_regmap(periph: dict) -> dict:
    """根据外设的模板标记（gpio/usart/spi/i2c/tim/...）返回完整寄存器表。"""
    if periph.get("gpio"):
        return dict(_GPIO_REG_MAP)
    if periph.get("usart"):
        return dict(_USART_REG_MAP)
    if periph.get("spi"):
        return dict(_SPI_REG_MAP)
    if periph.get("i2c"):
        return dict(_I2C_REG_MAP)
    if periph.get("tim"):
        m = dict(_TIM_REG_MAP)
        if periph.get("advanced"):
            m.update(_TIM_ADV_EXTRA)
        return m
    if periph.get("adc"):
        return dict(_ADC_REG_MAP)
    if periph.get("pwr"):
        return dict(_PWR_REG_MAP)
    if periph.get("flash"):
        return dict(_FLASH_REG_MAP)
    if periph.get("systick"):
        return dict(_SYSTICK_REG_MAP)
    if periph.get("scb"):
        return dict(_SCB_REG_MAP)
    if periph.get("dwt"):
        return dict(_DWT_REG_MAP)
    if periph.get("exti"):
        return dict(_EXTI_REG_MAP)
    if periph.get("syscfg"):
        return dict(_SYSCFG_REG_MAP)
    if periph.get("nvic"):
        m = {k: {"off": v, "fields": []} for k, v in {**_NVIC_ISER, **_NVIC_ISPR, **_NVIC_ICPR}.items()}
        return m
    # 显式 regs 表
    return dict(periph.get("regs", {}))


def list_peripherals() -> list:
    """返回所有内置外设的 [{name, base, desc}] 列表。"""
    return [{"name": k, "base": v["base"], "desc": v["desc"]}
            for k, v in sorted(PERIPHERALS.items(), key=lambda kv: kv[1]["base"])]


def get_peripheral(name: str) -> dict | None:
    """按名字（大小写不敏感）查外设，返回 {name, base, desc, regs}。"""
    key = name.strip().upper()
    p = PERIPHERALS.get(key)
    if not p:
        # 兼容 GPIOx / USARTx / TIMx 大小写
        for k, v in PERIPHERALS.items():
            if k.upper() == key:
                p = v
                key = k
                break
    if not p:
        return None
    return {"name": key, "base": p["base"], "desc": p["desc"],
            "regs": _resolve_regmap(p)}


# ----------------------------------------------------------------------------
# 内存区域地图（Cortex-M4 / STM32F4 通用地址映射）
# ----------------------------------------------------------------------------
MEMORY_MAP: list = [
    {"name": "FLASH", "start": 0x08000000, "end": 0x081FFFFF,
     "desc": "片上 Flash（代码/常量），典型 256KB~2MB", "perms": "R-X"},
    {"name": "SRAM1", "start": 0x20000000, "end": 0x2001FFFF,
     "desc": "片上 SRAM（主 RAM，全局/栈/堆），典型 64KB~192KB", "perms": "RW"},
    {"name": "SRAM2", "start": 0x10000000, "end": 0x1000FFFF,
     "desc": "片上 SRAM2（部分型号），典型 4KB~64KB", "perms": "RW"},
    {"name": "APB1_PERIPH", "start": 0x40000000, "end": 0x4000FFFF,
     "desc": "APB1 外设（USART2/3、TIM2-7、SPI2/3、I2C1-3、PWR 等）", "perms": "RW"},
    {"name": "APB2_PERIPH", "start": 0x40010000, "end": 0x4001FFFF,
     "desc": "APB2 外设（USART1/6、TIM1/9-11、SPI1、ADC1-3、EXTI、SYSCFG）", "perms": "RW"},
    {"name": "AHB1_PERIPH", "start": 0x40020000, "end": 0x4002FFFF,
     "desc": "AHB1 外设（GPIOA-H、RCC、DMA1/2、CRC、FLASH 接口）", "perms": "RW"},
    {"name": "AHB2_PERIPH", "start": 0x50000000, "end": 0x5FFFFFFF,
     "desc": "AHB2 外设（OTG FS/HS 等）", "perms": "RW"},
    {"name": "ITM", "start": 0xE0000000, "end": 0xE0000FFF,
     "desc": "Instrumentation Trace Macrocell（ITM）", "perms": "RW"},
    {"name": "DWT", "start": 0xE0001000, "end": 0xE0001FFF,
     "desc": "Data Watchpoint and Trace（CYCCNT 周期计数器）", "perms": "RW"},
    {"name": "SCS", "start": 0xE000E000, "end": 0xE000EFFF,
     "desc": "System Control Space（SCB/ICSR/AIRCR/CFSR/DEMCR 等）", "perms": "RW"},
]

def query_memory_map(addr: int | None = None) -> dict:
    """返回内存区域地图；addr 非空时标注该地址落在哪个区域。

    供 AI 在 read_mem/write_mem 前判断目标地址属于 FLASH / SRAM / 外设，
    避免把外设区当 RAM 读或把越界地址当合法地址。
    """
    if addr is None:
        return {"ok": True, "count": len(MEMORY_MAP),
                "regions": [{**r, "start_hex": f"0x{r['start']:08X}",
                             "end_hex": f"0x{r['end']:08X}"} for r in MEMORY_MAP]}
    hit = None
    for r in MEMORY_MAP:
        if r["start"] <= addr <= r["end"]:
            hit = r
            break
    return {"ok": True, "addr": addr, "addr_hex": f"0x{addr:08X}",
            "region": hit, "matched": bool(hit)}
