# -*- coding: utf-8 -*-
"""批次3 增强工具测试：read_peripheral / list_peripherals。

覆盖本批新增的 2 类工具：
- list_peripherals  列出内置外设寄存器表
- read_peripheral   一键读取指定外设全部寄存器并解析关键位域
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14839
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {'' if ok else detail}")

async def call(server, name, args):
    res = await server.call_tool(name, args)
    return "".join(getattr(c, "text", "") or "" for c in res.content)

def load(r):
    try:
        return json.loads(r)
    except Exception:
        return {}

async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                               axf_path=_AXF if os.path.isfile(_AXF) else None)
        tools = {t.name: t for t in await server.list_tools()}
        names = set(tools)
        need = {"list_peripherals", "read_peripheral"}
        check("新工具已注册", need.issubset(names), sorted(need - names))

        # ---- list_peripherals ----
        r = await call(server, "list_peripherals", {})
        d = load(r)
        check("list_peripherals 返回外设列表",
              d.get("ok") is True and d.get("count", 0) > 10, r[:300])
        pnames = {p["name"] for p in d.get("peripherals", [])}
        for expect in ("RCC", "GPIOA", "USART1", "TIM2", "SysTick", "SCB", "DWT"):
            check(f"list_peripherals 含 {expect}", expect in pnames)
        check("peripherals 带 base/desc 字段",
              all({"name", "base", "desc"} <= set(p) for p in d.get("peripherals", [])),
              str(d.get("peripherals", [{}])[0])[:200])

        # ---- read_peripheral: RCC（使能位） ----
        r = await call(server, "read_peripheral", {"periph": "RCC"})
        d = load(r)
        check("read_peripheral RCC 返回", d.get("ok") is True and d.get("peripheral") == "RCC", r[:300])
        regs = {x["reg"]: x for x in d.get("regs", [])}
        check("RCC 含 AHB1ENR/APB2ENR", "AHB1ENR" in regs and "APB2ENR" in regs)
        ahb1 = regs.get("AHB1ENR", {})
        # 预置 0x3 → GPIOAEN bit0=1、GPIOBEN bit1=1，field 解读到位
        fmap = {f["name"]: f for f in ahb1.get("fields", [])}
        check("AHB1ENR.GPIOAEN=1(使能)", fmap.get("GPIOAEN", {}).get("value") == 1,
              str(ahb1.get("fields"))[:300])
        check("AHB1ENR 原始值 0x3", ahb1.get("value") == "0x00000003", str(ahb1.get("value")))

        # ---- read_peripheral: GPIOA（模式/输出解读） ----
        r = await call(server, "read_peripheral", {"periph": "gpioa"})  # 大小写不敏感
        d = load(r)
        check("read_peripheral GPIOA(小写) 返回", d.get("ok") is True and d.get("peripheral") == "GPIOA", r[:300])
        regs = {x["reg"]: x for x in d.get("regs", [])}
        for expect in ("MODER", "OTYPER", "IDR", "ODR", "AFRL"):
            check(f"GPIOA 含 {expect}", expect in regs)
        moder = regs.get("MODER", {})
        fm = {f["name"]: f for f in moder.get("fields", [])}
        # MODER=0x55555555 → 每引脚 2bit=01=输出，带 desc
        check("GPIOA MODER0=输出(desc)", fm.get("MODER0", {}).get("desc") == "输出",
              str(moder.get("fields"))[:300])
        check("GPIOA ODR=0xFFFF", regs.get("ODR", {}).get("value") == "0x0000FFFF")

        # ---- read_peripheral: USART1（波特率/控制） ----
        r = await call(server, "read_peripheral", {"periph": "USART1"})
        d = load(r)
        check("read_peripheral USART1 返回", d.get("ok") is True, r[:300])
        regs = {x["reg"]: x for x in d.get("regs", [])}
        cr1 = regs.get("CR1", {})
        fcr1 = {f["name"]: f for f in cr1.get("fields", [])}
        check("USART1 CR1.UE=1", fcr1.get("UE", {}).get("value") == 1, str(cr1.get("fields"))[:300])
        check("USART1 CR1.TE=1/RE=1",
              fcr1.get("TE", {}).get("value") == 1 and fcr1.get("RE", {}).get("value") == 1)
        check("USART1 BRR=0x111", regs.get("BRR", {}).get("value") == "0x00000111")

        # ---- read_peripheral: TIM2（计数运行） ----
        r = await call(server, "read_peripheral", {"periph": "TIM2"})
        d = load(r)
        regs = {x["reg"]: x for x in d.get("regs", [])}
        check("TIM2 CNT=0x1000", regs.get("CNT", {}).get("value") == "0x00001000")
        check("TIM2 ARR=0xFFFF", regs.get("ARR", {}).get("value") == "0x0000FFFF")
        check("TIM2 PSC=0xF", regs.get("PSC", {}).get("value") == "0x0000000F")
        cr1 = {f["name"]: f for f in regs.get("CR1", {}).get("fields", [])}
        check("TIM2 CR1.CEN=0(未使能)", cr1.get("CEN", {}).get("value") == 0)

        # ---- read_peripheral: SysTick / SCB（系统段） ----
        r = await call(server, "read_peripheral", {"periph": "SysTick"})
        d = load(r)
        check("read_peripheral SysTick 返回", d.get("ok") is True, r[:300])
        regs = {x["reg"]: x for x in d.get("regs", [])}
        check("SysTick CTRL=0x7", regs.get("CTRL", {}).get("value") == "0x00000007")
        ctrl = {f["name"]: f for f in regs.get("CTRL", {}).get("fields", [])}
        check("SysTick CTRL.CLKSOURCE=HCLK", ctrl.get("CLKSOURCE", {}).get("desc") == "HCLK",
              str(regs.get("CTRL", {}).get("fields"))[:200])
        check("SysTick LOAD=0xFF", regs.get("LOAD", {}).get("value") == "0x000000FF")

        r = await call(server, "read_peripheral", {"periph": "SCB"})
        d = load(r)
        regs = {x["reg"]: x for x in d.get("regs", [])}
        check("SCB 含 ICSR/AIRCR/CFSR", all(k in regs for k in ("ICSR", "AIRCR", "CFSR")))

        # ---- 未知外设 ----
        r = await call(server, "read_peripheral", {"periph": "NOPE"})
        d = load(r)
        check("未知外设报错并给可用列表", d.get("ok") is False and "可用" in d.get("error", ""), r[:300])

        print(f"\n批次3结果: {len(PASS)} 通过, {len(FAIL)} 失败")
        if FAIL:
            print("失败项:", FAIL)
            raise SystemExit(1)
    finally:
        srv.stop()

if __name__ == "__main__":
    asyncio.run(main())
