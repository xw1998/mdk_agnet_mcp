# -*- coding: utf-8 -*-
"""批次5 mock 测试：批量命令 / 多 target / 工程配置读取。

覆盖本批新增的 5 个工具：
- read_mem_multi   一次读取多个地址的内存
- batch            批量执行多条读类命令（read_mem/read_variable/calc_expression/get_status/read_registers）
- project_targets  枚举工程 target + 当前/调试 target（UV_PRJ_ENUM_TARGETS/GET_CUR_TARGET/GET_DEBUG_TARGET）
- set_debug_target 切换调试 target（UV_PRJ_SET_DEBUG_TARGET）
- read_project_config 读取工程配置（编译器 AC5/AC6、优化级别、编译宏、包含路径）——纯 .uvprojx XML 解析

target 相关命令（UV_PRJ_*）在 mock_uvsock_server 中模拟；read_project_config 用真实 mdk_test.uvprojx 解析。
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14850
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
_UVPX = "example_mdk_project/mdk_test/MDK-ARM/mdk_test.uvprojx"


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
        need = {"read_mem_multi", "batch", "project_targets",
                "set_debug_target", "read_project_config"}
        check("新工具已注册(5)", need.issubset(names), sorted(need - names))

        # ---- read_mem_multi：一次读多个地址 ----
        r = await call(server, "read_mem_multi",
                       {"addresses": [{"addr": "0x20000000", "n_bytes": 4},
                                      {"addr": "0x20000004", "n_bytes": 4},
                                      {"addr": "0x20000010", "n_bytes": 8}]})
        d = load(r)
        check("read_mem_multi ok+count=3",
              d.get("ok") is True and d.get("count") == 3, r[:200])
        res = d.get("results", [])
        check("read_mem_multi 地址正确",
              res[0].get("addr") == "0x20000000" and res[1].get("addr") == "0x20000004"
              and res[2].get("addr") == "0x20000010")
        # mock v0=int 0x11223344(小端 44332211)、v1=uint 0xDEADBEEF(小端 efbeadde)
        check("read_mem_multi v0 读回魔数", res[0].get("data_hex") == "44332211",
              res[0].get("data_hex", ""))
        check("read_mem_multi v1 读回魔数", res[1].get("data_hex") == "efbeadde",
              res[1].get("data_hex", ""))

        # ---- batch：聚合多条读类命令 ----
        commands = [
            {"tool": "read_mem", "args": {"addr": "0x20000000", "n_bytes": 4}},
            {"tool": "read_mem", "args": {"addr": "0x20000004", "n_bytes": 4}},
            {"tool": "read_variable", "args": {"name": "v0"}},
            {"tool": "get_status", "args": {}},
            {"tool": "read_registers", "args": {}},
            {"tool": "nonsense", "args": {}},
        ]
        r = await call(server, "batch", {"commands": commands})
        d = load(r)
        check("batch ok+count=6", d.get("ok") is True and d.get("count") == 6, r[:200])
        res = d.get("results", [])
        check("batch read_mem[0] 命中", res[0].get("ok") is True
              and res[0].get("data_hex") == "44332211", res[0].get("data_hex", ""))
        check("batch read_variable v0", res[2].get("ok") is True
              and res[2].get("value") == 0x11223344, r[:200])
        check("batch get_status ok", res[3].get("ok") is True)
        check("batch read_registers 有寄存器", res[4].get("ok") is True
              and bool(res[4].get("registers")))
        check("batch 不支持工具报错", res[5].get("ok") is False
              and "不支持" in res[5].get("error", ""), res[5].get("error", ""))

        # ---- project_targets：枚举 + 当前 + 调试 target ----
        r = await call(server, "project_targets", {})
        d = load(r)
        check("project_targets ok", d.get("ok") is True, r[:200])
        check("project_targets 含3个target",
              d.get("targets") == ["mdk_test", "Debug", "Release"], r[:200])
        check("project_targets 当前=mdk_test", d.get("current_target") == "mdk_test")
        check("project_targets 调试=mdk_test", d.get("debug_target") == "mdk_test")

        # ---- set_debug_target：切换调试 target ----
        r = await call(server, "set_debug_target", {"target": "Debug"})
        d = load(r)
        check("set_debug_target ok", d.get("ok") is True, r[:200])
        r = await call(server, "project_targets", {})
        d = load(r)
        check("set_debug_target 后调试=Debug", d.get("debug_target") == "Debug")
        r = await call(server, "set_debug_target", {"target": "Nope"})
        d = load(r)
        check("set_debug_target 非法名 ok=False", d.get("ok") is False, r[:200])

        # ---- read_project_config：真实 uvprojx 解析（纯文件） ----
        if os.path.isfile(_UVPX):
            r = await call(server, "read_project_config", {"project": _UVPX})
            d = load(r)
            check("read_project_config ok", d.get("ok") is True, r[:300])
            cur = d.get("current", {})
            check("read_project_config 编译器=ARMCC(AC5)",
                  cur.get("compiler") == "ARMCC(AC5)", cur.get("compiler", ""))
            check("read_project_config 优化=-Otime",
                  cur.get("optimization_level") == "-Otime", cur.get("optimization_level", ""))
            defs = cur.get("defines", [])
            check("read_project_config 宏含 USE_HAL_DRIVER/STM32F401xC",
                  "USE_HAL_DRIVER" in defs and "STM32F401xC" in defs, str(defs))
            check("read_project_config targets数>=1", d.get("count", 0) >= 1)
            # 指定 target
            r = await call(server, "read_project_config", {"project": _UVPX, "target": "mdk_test"})
            check("read_project_config 指定target", load(r).get("current", {}).get("name") == "mdk_test")
        else:
            check("read_project_config 无真实uvprojx(跳过真值断言)", True)

        # ---- 全量工具数 ----
        check("工具总数>=57", len(names) >= 57, f"{len(names)}")

    finally:
        srv.stop()

    print(f"\n===== 批次5 mock 测试汇总: {len(PASS)} 通过 / {len(FAIL)} 失败 =====")
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
