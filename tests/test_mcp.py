# -*- coding: utf-8 -*-
"""MCP Server 层测试：验证工具注册、schema 生成与真实工具调用。"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug.server import create_server  # noqa: E402

REAL_PROJ = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))),
    "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test.uvprojx")
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
                    "read_mem", "write_mem", "run", "stop", "reset", "step",
                    "read_variable", "enter_debug", "exit_debug",
                    "launch_uvision", "close_uvision", "flash_debug",
                    "build_project", "rebuild_project", "flash_download",
                    "build_and_flash", "get_current_location", "run_to_line"}
        check("工具全部注册", expected.issubset(set(names)), names)
        print("       已注册:", names)

        # UVSOCK 未开启时：连接失败应返回开启指引（而非裸 ConnectionRefused）
        from mdkdebug.client import UVClient, UVSOCKConnectError
        cold = UVClient(host="127.0.0.1", port=48231)  # 无监听端口，模拟未开启
        got_hint = False
        msg_hint = ""
        try:
            cold.get_version()
        except UVSOCKConnectError as e:
            msg_hint = str(e)
            got_hint = ("UVSOCK" in msg_hint and "Edit" in msg_hint
                        and "Configuration" in msg_hint and "4823" in msg_hint)
        check("UVSOCK 未开启返回开启指引", got_hint, msg_hint)

        # 工具 schema 生成（参数）
        t = tools["read_mem"]
        has_schema = getattr(t, "input_schema", None) or getattr(t, "parameters", None)
        check("read_mem 生成参数 schema", has_schema is not None)

        # ---- 真实工具调用 ----
        r = await call(server, "get_version", {})
        check("MCP get_version", '"ok": true' in r and r.strip().startswith("{"), r)

        r = await call(server, "calc_expression", {"expr": "v1"})
        check("MCP calc_expression", '"value": 3735928559' in r, r)

        # 按变量名查询地址与内容
        r = await call(server, "read_variable", {"name": "v1"})
        check("MCP read_variable 地址", '"address": "0x20000004"' in r, r)
        check("MCP read_variable 值", '"value": 3735928559' in r, r)
        r = await call(server, "read_variable", {"name": "not_exist"})
        check("MCP read_variable 未知变量", '"ok": false' in r, r)

        # 数组读取：sizeof + 逐元素 + 内存
        r = await call(server, "read_variable", {"name": "arr", "count": 4})
        check("MCP read_variable 数组 size", '"size_bytes": 32' in r, r)
        check("MCP read_variable 数组元素", '"index": 1, "value": 20' in r, r)
        check("MCP read_variable 数组元素[3]", '"index": 3, "value": 40' in r, r)
        check("MCP read_variable 数组内存", '"memory_hex"' in r, r)
        r = await call(server, "read_variable", {"name": "arr", "count": 8})
        check("MCP read_variable 数组8元素", r.count('"index"') == 8, r)

        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
        check("MCP read_mem(hex地址)", '"ok": true' in r and '"data_hex"' in r, r)

        r = await call(server, "read_mem", {"addr": "536870912", "n_bytes": 4})
        check("MCP read_mem(十进制地址)", '"ok": true' in r, r)

        r = await call(server, "write_mem", {"addr": "0x20002000", "data_hex": "a1b2c3d4"})
        check("MCP write_mem", '"written": 4' in r, r)

        # 真机语义：run/stop/step 都要先在调试态
        r = await call(server, "enter_debug", {})
        check("MCP enter_debug(运行控制前置)", '"ok": true' in r, r)
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
        check("MCP list_breakpoints 含 main", '"expr": "main"' in r, r)
        r = await call(server, "clear_breakpoint", {"expr": "main"})
        check("MCP clear_breakpoint", '"ok": true' in r, r)
        r = await call(server, "exit_debug", {})
        check("MCP exit_debug", '"ok": true' in r, r)

        # flash_debug 编译失败分支：不重开工程、不进调试（monkeypatch 编译失败）
        import mdkdebug.server as _srv
        _orig_close = _srv.builder.close_uvision
        _orig_bf = _srv.builder.build_and_flash
        _orig_bp = _srv.builder.build_project
        _orig_launch = _srv.builder.launch_uvision
        _srv.builder.close_uvision = lambda force=False, timeout=10: {"ok": True, "closed": 0}
        _srv.builder.build_and_flash = lambda *a, **k: {"ok": False, "stage": "编译", "status_text": "编译未通过"}
        # 工程勾选 Update Target before Debugging 时 flash_debug 只编译不显式烧录
        # （走 build_project），两条路径都要打桩，否则会真的去调 UV4。
        _srv.builder.build_project = lambda *a, **k: {"ok": False, "stage": "编译", "status_text": "编译未通过"}
        _srv.builder.launch_uvision = lambda *a, **k: {"ok": True}
        try:
            r = await call(server, "flash_debug", {"project": REAL_PROJ})
            ok_fail = ('"stage": "编译"' in r and '"ok": false' in r
                       and "未重开工程进入调试" in r and "launch_uvision" not in r)
            check("flash_debug 编译失败不重开不进调试", ok_fail, r)
        finally:
            _srv.builder.close_uvision = _orig_close
            _srv.builder.build_and_flash = _orig_bf
            _srv.builder.build_project = _orig_bp
            _srv.builder.launch_uvision = _orig_launch

        # Locator 符号定位：地址↔文件:行 往返 + 源码读取
        from mdkdebug.locator import Locator
        _axf = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
        _pdir = "example_mdk_project/mdk_test/MDK-ARM"
        if os.path.isfile(_axf):
            _loc = Locator(_axf, project_dir=_pdir)
            # 同样不写死地址：取 main（Thumb 位清掉后的偶数地址），带上 bit0 探测往返
            _main = (_loc.symbol_addr("main") or {}).get("addr")
            _probe = (_main | 1) if _main else 0x8000db5
            _lm = _loc.addr_to_location(_probe)
            _round = _loc.line_to_addr(_lm["file"], _lm["line"]) if _lm else None
            check("Locator addr↔line 往返", bool(_lm) and _round == (_main or 0x8000db4),
                  f"lm={_lm} round={_round}")
            _src = _loc.read_source(_lm["file"], _lm["line"], 1) if _lm else None
            check("Locator 读源码上下文", bool(_src) and any(
                s["lineno"] == _lm["line"] for s in _src["source"]), str(_src)[:160])
        else:
            print("  [skip] .axf 不存在，跳过 Locator 测试")

    finally:
        srv.stop()

    print(f"\n结果: 通过 {len(PASS)} 失败 {len(FAIL)}")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")


if __name__ == "__main__":
    asyncio.run(main())
