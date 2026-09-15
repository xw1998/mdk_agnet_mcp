# -*- coding: utf-8 -*-
"""批次1 增强工具测试：find_symbol / set_register / dwt。

覆盖本批新增的 3 类工具：
- find_symbol   从 .axf ELF 符号表模糊检索函数/全局变量
- set_register  写 CPU 寄存器 / 改 PC（走 Watch 表达式赋值 + 读回验证）
- dwt           DWT 周期计数器测代码段执行时间
"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14827
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {'' if ok else detail}")

async def call(server, name, args):
    res = await server.call_tool(name, args)
    return "".join(getattr(c, "text", "") or "" for c in res.content)

async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                               axf_path=_AXF if os.path.isfile(_AXF) else None)
        tools = {t.name: t for t in await server.list_tools()}
        names = set(tools)
        need = {"find_symbol", "set_register", "dwt"}
        check("新工具已注册", need.issubset(names), sorted(need - names))

        # ---- find_symbol：符号检索 ----
        r = await call(server, "find_symbol", {"query": "SystemClock"})
        check("find_symbol 返回结果", '"ok": true' in r and '"symbols"' in r, r[:300])
        # 真实 .axf 存在时应命中 SystemClock_Config 等符号
        if os.path.isfile(_AXF):
            check("find_symbol 命中 SystemClock",
                  '"SystemClock' in r, r[:400])
            check("find_symbol 含地址/类型", '"addr"' in r and '"type"' in r, r[:400])
        # kind=func 过滤
        r = await call(server, "find_symbol", {"query": "Clock", "kind": "func"})
        check("find_symbol kind=func 过滤", '"ok": true' in r, r[:200])

        # ---- set_register：写寄存器 / 改 PC ----
        r = await call(server, "set_register", {"register": "R1", "value": "0x2B"})
        check("set_register 写入并读回",
              '"ok": true' in r and '"readback": 43' in r, r[:300])
        # 验证写后寄存器已更新（read_registers 的 r1 应变 0x2B）
        r = await call(server, "read_registers", {})
        check("set_register 持久生效(r1=0x2B)",
              '"r1": 43' in r, r[:300])
        # 改 PC（跳到 0x08000000）
        r = await call(server, "set_register", {"register": "PC", "value": "0x08000000"})
        check("set_register 改 PC", '"ok": true' in r and '"pc' in r.lower()
              and '"readback": 134217728' in r, r[:300])
        # 非法寄存器名
        r = await call(server, "set_register", {"register": "FOO", "value": "1"})
        check("set_register 非法寄存器名拒绝", '"ok": false' in r, r[:200])

        # ---- dwt：DWT 周期计数器 ----
        r = await call(server, "dwt", {})
        check("dwt 返回周期计数", '"ok": true' in r and '"cycles"' in r, r[:300])
        # mock 预置 cyccnt=0x1234=4660
        check("dwt 读到 cyccnt=4660", '"cycles": 4660' in r, r[:300])
        check("dwt 含频率换算提示", '"frequency_hz"' in r and '"usage"' in r, r[:300])
    finally:
        srv.stop()

if __name__ == "__main__":
    asyncio.run(main())
    print(f"======== 结果 ========\n通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")
