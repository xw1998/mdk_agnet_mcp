# -*- coding: utf-8 -*-
"""诊断类增强工具测试：read_registers / disassemble / diagnose。

覆盖本批新增的 3 类工具：
- read_registers   批量读 R0-R12/SP/LR/PC/xPSR + AAPCS 解读
- disassemble      反汇编指定地址（capstone，Thumb/Thumb-2）
- diagnose         一键诊断现场（寄存器+反汇编+调用栈+源码+关键变量）
"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14826
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
        need = {"read_registers", "disassemble", "diagnose"}
        check("新工具已注册", need.issubset(names), sorted(need - names))

        # ---- read_registers：批量读寄存器 + AAPCS ----
        r = await call(server, "read_registers", {})
        check("read_registers 返回寄存器组",
              '"ok": true' in r and '"registers"' in r, r[:300])
        check("read_registers 含 r0-r12/xPSR",
              all(f'"{k}"' in r for k in ("r0", "r1", "r12", "xpsr")), r[:300])
        check("read_registers AAPCS 解读",
              '"aapcs"' in r and '"arg1"' in r and '"return_value"' in r
              and '"return_address"' in r, r[:300])
        check("read_registers R0 值正确",
              '"r0": 536870912' in r, r[:300])  # 0x20000000

        # ---- disassemble：反汇编预置 Thumb 指令（0x08000000）----
        r = await call(server, "disassemble", {"addr": "0x08000000", "count": 4})
        check("disassemble 反汇编出指令",
              '"ok": true' in r and '"instructions"' in r
              and 'mnemonic' in r, r[:400])
        # 预置字节 0000 1c08 1c ff e7 → movs/adds/adds/b(循环)
        check("disassemble 指令内容",
              '"movs' in r.lower() or '"adds' in r.lower() or '"b ' in r, r[:500])

        # ---- diagnose：一键诊断现场 ----
        r = await call(server, "diagnose", {"globals": ["v1", "arr[0]"]})
        check("diagnose 返回现场报告",
              '"ok": true' in r and '"registers"' in r and '"aapcs"' in r, r[:300])
        check("diagnose 含调用栈/源码", '"callstack"' in r and '"file"' in r, r[:300])
        check("diagnose 含反汇编", '"disassembly"' in r, r[:300])
        check("diagnose 含关键全局变量", '"globals"' in r, r[:500])
    finally:
        srv.stop()

if __name__ == "__main__":
    asyncio.run(main())
    print(f"======== 结果 ========\n通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")
