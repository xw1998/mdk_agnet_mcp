# -*- coding: utf-8 -*-
"""增强功能测试：snapshot / watch / read_struct / set_watchpoint（含真实 .axf 符号定位）。

覆盖本批新增的 4 类工具：
- snapshot        状态快照（位置+源码+调用栈+局部变量+指定全局变量）
- watch           批量读多个表达式
- read_struct     结构体字段概览（基于 DWARF）
- set/clear/list_watchpoints  数据断点
"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug.locator import Locator  # noqa: E402

PORT = 14825
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
        need = {"snapshot", "watch", "read_struct",
                "set_watchpoint", "clear_watchpoint", "list_watchpoints"}
        check("新工具已注册", need.issubset(names), sorted(need - names))

        # ---- watch：一趟读回多个表达式 ----
        r = await call(server, "watch", {"expressions": ["v1", "arr[0]", "v2"]})
        check("watch 批量读表达式",
              '"value": 3735928559' in r and '"value": 10' in r and '"value_type"' in r, r)

        # ---- snapshot：完整路径（mock PC=0x8000db4 → main.c:77）----
        r = await call(server, "snapshot", {"globals": ["v1", "v2"]})
        check("snapshot 含位置+调用栈",
              '"ok": true' in r and '"file"' in r and '"callstack"' in r, r[:400])
        check("snapshot 含指定全局变量", '"globals"' in r, r[:400])

        # ---- set_watchpoint：数据断点 ----
        r = await call(server, "set_watchpoint", {"expr": "v1", "access": "write"})
        check("set_watchpoint 设数据断点",
              '"ok": true' in r and '"address": "0x20000004"' in r and 'BS WRITE' in r, r)
        r = await call(server, "list_watchpoints", {})
        check("list_watchpoints 记录", '"watchpoints"' in r, r)
        r = await call(server, "clear_watchpoint", {"expr": "v1"})
        check("clear_watchpoint 清除", '"ok"' in r, r)

        # ---- read_struct：真实 .axf 结构体解析 + 非结构体降级 ----
        loc = Locator(_AXF, project_dir="example_mdk_project/mdk_test")
        m = loc.struct_members("RCC_OscInitStruct")
        check("locator 解析 RCC_OscInitStruct(7字段)",
              bool(m and m.get("fields") and len(m["fields"]) == 7
                   and m["fields"][0]["name"] == "OscillatorType"), str(m)[:200])
        r = await call(server, "read_struct", {"name": "SystemCoreClock"})
        check("read_struct 非结构体降级返回提示", '"error"' in r, r)
    finally:
        srv.stop()


if __name__ == "__main__":
    asyncio.run(main())
    print(f"======== 结果 ========\n通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")
