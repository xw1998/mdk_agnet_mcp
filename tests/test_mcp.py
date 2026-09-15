# -*- coding: utf-8 -*-
"""MCP Server 层测试：验证工具注册、schema 生成与真实工具调用。"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14824
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {'' if ok else detail}")


async def call(server, name, args):
    res = await server.call_tool(name, args)
    # CallToolResult: 取内容
    txt = ""
    for c in res.content:
        txt += getattr(c, "text", "") or ""
    return txt


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0)

        tools = {t.name: t for t in await server.list_tools()}
        names = sorted(tools.keys())
        expected = {"get_version", "get_status", "calc_expression",
                    "read_mem", "write_mem", "run", "stop", "reset", "step"}
        check("工具全部注册", expected.issubset(set(names)), names)
        print("       已注册:", names)

        # 工具 schema 生成（参数）
        t = tools["read_mem"]
        has_schema = getattr(t, "input_schema", None) or getattr(t, "parameters", None)
        check("read_mem 生成参数 schema", has_schema is not None)

        # ---- 真实工具调用 ----
        r = await call(server, "get_version", {})
        check("MCP get_version", '"ok": true' in r and r.strip().startswith("{"), r)

        r = await call(server, "calc_expression", {"expr": "v1"})
        check("MCP calc_expression", '"value": 3735928559' in r, r)

        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
        check("MCP read_mem(hex地址)", '"ok": true' in r and '"data_hex"' in r, r)

        r = await call(server, "read_mem", {"addr": "536870912", "n_bytes": 4})
        check("MCP read_mem(十进制地址)", '"ok": true' in r, r)

        r = await call(server, "write_mem", {"addr": "0x20002000", "data_hex": "a1b2c3d4"})
        check("MCP write_mem", '"written": 4' in r, r)

        r = await call(server, "run", {})
        check("MCP run", '"ok": true' in r, r)
        r = await call(server, "get_status", {})
        check("MCP run 后 running", '"running": true' in r, r)
        r = await call(server, "stop", {})
        check("MCP stop", '"ok": true' in r, r)
        r = await call(server, "step", {"mode": "into"})
        check("MCP step into", '"ok": true' in r, r)

        # 错误路径
        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": -1})
        check("MCP read_mem 负数防护", '"ok": false' in r, r)
        r = await call(server, "write_mem", {"addr": "0x1", "data_hex": "zz"})
        check("MCP write_mem 非法hex防护", '"ok": false' in r, r)
        r = await call(server, "calc_expression", {"expr": "not_exist"})
        check("MCP 未知变量报错", '"ok": false' in r, r)

        # 断点/进出 debug
        r = await call(server, "enter_debug", {})
        check("MCP enter_debug", '"ok": true' in r, r)
        r = await call(server, "set_breakpoint", {"expr": "main"})
        check("MCP set_breakpoint", '"ok": true' in r, r)
        r = await call(server, "list_breakpoints", {})
        check("MCP list_breakpoints 含 main", '0: main' in r, r)
        r = await call(server, "clear_breakpoint", {"expr": "main"})
        check("MCP clear_breakpoint", '"ok": true' in r, r)
        r = await call(server, "exit_debug", {})
        check("MCP exit_debug", '"ok": true' in r, r)

    finally:
        srv.stop()

    print(f"\n结果: 通过 {len(PASS)} 失败 {len(FAIL)}")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")


if __name__ == "__main__":
    asyncio.run(main())
