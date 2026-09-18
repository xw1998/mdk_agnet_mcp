# -*- coding: utf-8 -*-
"""批次9 mock 测试：命令窗口输出/报错信息闭环。

根因：interface 把 UV_DBG_CMD_OUTPUT(0x5020)/UV_ASYNC_MSG(0x4000) 异步帧丢弃，
AI 读不到 Keil command 窗口输出与报错。
改：_drain_async + recv 均解析缓存异步帧到 console_log/async_log，新增
read_console_output / read_async_messages 工具实现闭环。

覆盖：
- 新增 read_console_output / read_async_messages 两个工具（64 → 66）
- server 层：set_breakpoint 的 BS 命令输出可经 read_console_output 读到（工具转发链路）
- interface 层：BL 命令输出进 console_log，EVAL 未定义报错进 async_log（根因修复）
- clear 参数清空缓存
- 工具描述含注意点说明
"""
import os
import sys
import time
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug.client import UVClient  # noqa: E402

PORT = 14864
PASS, FAIL = [], []

_MDK_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

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
                               axf_path=_MDK_AXF if os.path.isfile(_MDK_AXF) else None)
        tools = {t.name: t for t in await server.list_tools()}

        # 1. 新工具已注册（64 → 66）
        check("read_console_output 已注册", "read_console_output" in tools, "")
        check("read_async_messages 已注册", "read_async_messages" in tools, "")
        check("工具总数=153", len(tools) == 153, f"实际 {len(tools)}")

        # 2. server 层：set_breakpoint 发 BS 命令，其命令输出可经 read_console_output 读到
        sb = load(await call(server, "set_breakpoint", {"expr": "main"}))
        check("set_breakpoint(main) 成功", bool(sb.get("ok")), str(sb)[:120])
        co = load(await call(server, "read_console_output", {}))
        check("read_console_output ok", bool(co.get("ok")), str(co)[:160])
        lines = co.get("lines") or []
        check("read_console_output 读到 BS 命令输出",
              any("BS" in (l or "") for l in lines), f"lines={lines}")

        # 3. interface 层核心（根因修复）：BL 输出进 console_log，EVAL 报错进 async_log
        c = UVClient(host="127.0.0.1", port=PORT)
        c.exec_command("BS main")            # 设断点
        c.exec_command("BL")                 # 列断点
        cons = c.phy.get_console_output()
        check("BL 命令输出进入 console_log",
              any("BL" in (m.get("text") or "") for m in cons), f"cons={cons}")
        check("BL 断点列表进入 console_log",
              any("main" in (m.get("text") or "") for m in cons), f"cons={cons}")

        c.exec_command("EVAL nonexist_xyz")  # 未定义标识符 → 0x4000 报错
        aync = c.phy.get_async_messages()
        check("EVAL 未定义报错进入 async_log",
              any("error 34" in (m.get("text") or "") or "nonexist_xyz" in (m.get("text") or "")
                  for m in aync), f"aync={aync}")
        check("async_log 条目含 cmd_code/status",
              all("cmd_code" in m and "status" in m for m in aync) and len(aync) > 0,
              f"aync={aync}")
        # 命令输出(0x5020)与报错(0x4000)分流：EVAL 报错文本也应出现在 console_log
        cons2 = c.phy.get_console_output()
        check("EVAL 报错同时出现在 console_log(0x5020)",
              any("nonexist_xyz" in (m.get("text") or "") for m in cons2), f"cons2={cons2}")
        c.close()

        # 4. clear 参数清空缓存（server 工具层）
        co2 = load(await call(server, "read_console_output", {"clear": True}))
        check("clear 后 read_console_output ok", bool(co2.get("ok")), str(co2)[:120])
        co3 = load(await call(server, "read_console_output", {}))
        check("clear 后缓存已清空", bool(co3.get("ok")) and len(co3.get("lines") or []) == 0,
              f"lines={co3.get('lines')}")

        # 5. 工具描述含注意点说明
        check("read_console_output 描述含异步提示",
              "异步" in (tools["read_console_output"].description or ""), "")
        check("read_async_messages 描述含报错说明",
              "报错" in (tools["read_async_messages"].description or ""), "")

    finally:
        srv.stop()

    print(f"\n批次9 mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")

if __name__ == "__main__":
    asyncio.run(main())
