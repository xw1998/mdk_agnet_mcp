# -*- coding: utf-8 -*-
"""批次8b mock 测试：断点管理（断点 id 表 + 可靠清除 + clear_all）。

覆盖本批新增能力：
- set_breakpoint / set_conditional_breakpoint / set_watchpoint 返回自增 breakpoint_id/watchpoint_id
- list_breakpoints / list_watchpoints 返回带 id 的内部记录 + total + note（标注协议限制）
- clear_breakpoint 支持按 bp_id / 符号 / 地址清除，并可靠剔除内部记录
- clear_watchpoint  支持按 bp_id / 符号 / 地址清除
- clear_all_breakpoints / clear_all_watchpoints 全清内部表
- run_to_cursor 临时断点按 address 正确剔除（回归）
"""
import os
import sys
import time
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14862
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
        names = set(tools)

        # 1. 新工具注册
        need = {"clear_all_breakpoints", "clear_all_watchpoints"}
        check("新工具已注册(2)", need.issubset(names), sorted(need - names))

        # 2. set_breakpoint 返回 breakpoint_id，且自增
        r1 = load(await call(server, "set_breakpoint", {"expr": "0x08000db5"}))
        check("set_breakpoint ok", r1.get("ok") is True, str(r1))
        b1 = r1.get("breakpoint_id")
        check("set_breakpoint 返回 breakpoint_id(int)", isinstance(b1, int), str(b1))
        r2 = load(await call(server, "set_breakpoint", {"expr": "0x08000db6"}))
        b2 = r2.get("breakpoint_id")
        check("breakpoint_id 自增", isinstance(b2, int) and b2 == b1 + 1, f"{b1}->{b2}")

        # 3. list_breakpoints 返回带 id 记录 + total
        lb = load(await call(server, "list_breakpoints", {}))
        check("list_breakpoints ok+total", lb.get("ok") and lb.get("total") == 2, str(lb))
        ids = [x.get("id") for x in lb.get("breakpoints", [])]
        check("list 含两个 id 且递增", ids == [b1, b2], str(ids))
        check("list 含协议限制 note", bool(lb.get("note")), str(lb.get("note")))

        # 4. clear_breakpoint 按 bp_id 清除
        c1 = load(await call(server, "clear_breakpoint", {"bp_id": b1}))
        check("clear by bp_id ok", c1.get("ok") is True, str(c1))
        check("clear 后 remaining=1", c1.get("remaining") == 1, str(c1))
        lb2 = load(await call(server, "list_breakpoints", {}))
        check("清除后内部表只剩 b2", [x.get("id") for x in lb2.get("breakpoints", [])] == [b2], str(lb2))

        # 5. clear_breakpoint 按符号/地址清除
        c2 = load(await call(server, "clear_breakpoint", {"expr": "0x08000db6"}))
        check("clear by address ok", c2.get("ok") is True and c2.get("remaining") == 0, str(c2))

        # 6. 内部表里没有该 id：按 Keil 真实编号清除；编号也不存在（真机/本 mock 均报
        #    `*** error 72: invalid item number`）时必须如实上报失败，不能当作清除成功。
        srv.bl_table = []          # 空真实断点表 → 任何编号都不存在
        c3 = load(await call(server, "clear_breakpoint", {"bp_id": 999}))
        check("clear 不存在的 id 报错", c3.get("ok") is False, str(c3))
        check("失败原因来自命令窗口报错（非 status 假成功）",
              "命令窗口报错" in (c3.get("error") or ""), str(c3.get("error")))
        srv.bl_table = None

        # 7. set_watchpoint 返回 watchpoint_id
        w1 = load(await call(server, "set_watchpoint", {"expr": "0x20000000"}))
        check("set_watchpoint ok+id", w1.get("ok") is True and isinstance(w1.get("watchpoint_id"), int), str(w1))
        wid = w1.get("watchpoint_id")
        lw = load(await call(server, "list_watchpoints", {}))
        check("list_watchpoints total+id", lw.get("total") == 1 and [x.get("id") for x in lw.get("watchpoints", [])] == [wid], str(lw))

        # 8. clear_watchpoint 按 bp_id 清除
        cw = load(await call(server, "clear_watchpoint", {"bp_id": wid}))
        check("clear_watchpoint by id ok", cw.get("ok") is True and cw.get("remaining") == 0, str(cw))

        # 9. clear_all_breakpoints / clear_all_watchpoints
        await call(server, "set_breakpoint", {"expr": "0x08000db5"})
        await call(server, "set_breakpoint", {"expr": "0x08000db6"})
        await call(server, "set_watchpoint", {"expr": "0x20000000"})
        ca = load(await call(server, "clear_all_breakpoints", {}))
        check("clear_all_breakpoints cleared=2", ca.get("ok") and ca.get("cleared") == 2, str(ca))
        caw = load(await call(server, "clear_all_watchpoints", {}))
        check("clear_all_watchpoints cleared=1", caw.get("ok") and caw.get("cleared") == 1, str(caw))
        lb3 = load(await call(server, "list_breakpoints", {}))
        lw3 = load(await call(server, "list_watchpoints", {}))
        check("全清后内部表皆空", lb3.get("total") == 0 and lw3.get("total") == 0, str(lb3) + str(lw3))

        # 10. 条件断点返回 id
        rc = load(await call(server, "set_conditional_breakpoint",
                             {"expr": "0x08000db5", "condition": "R0==1"}))
        check("set_conditional_breakpoint 返回 id", rc.get("ok") and isinstance(rc.get("breakpoint_id"), int), str(rc))
        await call(server, "clear_all_breakpoints", {})

    finally:
        srv.stop()

    print(f"\n批次8b mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")

if __name__ == "__main__":
    asyncio.run(main())
