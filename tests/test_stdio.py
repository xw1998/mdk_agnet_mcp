# -*- coding: utf-8 -*-
"""stdio 全链路测试：以 MCP 客户端连接 run_server.py 子进程，做真实握手与工具调用。"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

PORT = 14825
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {'' if ok else detail}")


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=["run_server.py", "--port", str(PORT), "--idle-timeout", "10"],
            cwd=ROOT,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                check("MCP 握手 initialize 成功", True)

                tools = await session.list_tools()
                names = [t.name for t in tools.tools]
                expected = {"get_version", "get_status", "calc_expression",
                            "read_mem", "write_mem", "run", "stop", "reset", "step"}
                check("stdio 工具列表完整", expected.issubset(set(names)), names)

                r = await session.call_tool("calc_expression", {"expr": "v0"})
                txt = "".join(c.text or "" for c in r.content)
                check("stdio calc_expression v0", '"value": 287454020' in txt, txt)

                r = await session.call_tool("read_mem",
                                            {"addr": "0x20000000", "n_bytes": 4})
                txt = "".join(c.text or "" for c in r.content)
                check("stdio read_mem", '"ok": true' in txt, txt)

                r = await session.call_tool("write_mem",
                                            {"addr": "0x20003000", "data_hex": "aabbccdd"})
                txt = "".join(c.text or "" for c in r.content)
                check("stdio write_mem", '"written": 4' in txt, txt)

                r = await session.call_tool("run", {})
                txt = "".join(c.text or "" for c in r.content)
                check("stdio run", '"ok": true' in txt, txt)

                r = await session.call_tool("get_status", {})
                txt = "".join(c.text or "" for c in r.content)
                check("stdio 状态 running", '"running": true' in txt, txt)
    finally:
        srv.stop()

    print(f"\n结果: 通过 {len(PASS)} 失败 {len(FAIL)}")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")


if __name__ == "__main__":
    asyncio.run(main())
