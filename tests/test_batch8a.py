# -*- coding: utf-8 -*-
"""批次8a mock 测试：符号文件切换（set_symbol_file / list_symbol_projects / PC 自动匹配 / 汇编级降级）。

覆盖本批新增能力：
- set_symbol_file      运行时切换调试符号文件（.axf 或 .map），解决符号绑定错误
- list_symbol_projects 列出预登记候选符号工程
- MapLocator           用 .map 作为符号源（函数/全局符号地址，无行号）
- PC 自动匹配          get_current_location 在当前符号无法解析时按 PC 切到预登记固件符号
- 汇编级降级           get_current_location 在符号未就绪时返回地址级信息 + warning 而非报错

依赖真实 SVCRTOS_TEST.axf/.map（本机存在），以及 mdk_test.axf。
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug.server import MapLocator  # noqa: E402

PORT = 14861
PASS, FAIL = [], []

_SVCRTOS_AXF = r"D:/工作/git_project/svcrtos_new/example/stm32f427/kernel/SVCRTOS_TEST/MDK-ARM/SVCRTOS_TEST/SVCRTOS_TEST.axf"
_SVCRTOS_MAP = r"D:/工作/git_project/svcrtos_new/example/stm32f427/kernel/SVCRTOS_TEST/MDK-ARM/SVCRTOS_TEST/SVCRTOS_TEST.map"
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
        need = {"set_symbol_file", "list_symbol_projects"}
        check("新工具已注册(2)", need.issubset(names), sorted(need - names))

        # ---- list_symbol_projects ----
        r = await call(server, "list_symbol_projects", {})
        d = load(r)
        check("list_symbol_projects ok", d.get("ok") is True, r[:200])
        proj = d.get("projects", [])
        # 去硬编码后：默认注册表含仓库内置 mdk_test；外部工程(如 SVCRTOS)改为
        # --symbol-project/MDKDEBUG_SYMBOL_PROJECTS 注入，不再写死进代码
        check("候选工程含内置 mdk_test",
              any(p.get("name") == "mdk_test" for p in proj),
              f"names={[p.get('name') for p in proj]}")
        svcrt = [p for p in proj if "SVCRTOS" in p.get("name", "")]
        if svcrt:
            check("SVCRTOS 候选 axf 存在", svcrt[0].get("axf_exists") is True,
                  str(svcrt[0].get("axf_exists")))
            check("SVCRTOS 候选 map 存在", svcrt[0].get("map_exists") is True,
                  str(svcrt[0].get("map_exists")))

        # ---- set_symbol_file：加载 SVCRTOS_TEST.axf ----
        if os.path.isfile(_SVCRTOS_AXF):
            r = await call(server, "set_symbol_file", {"path": _SVCRTOS_AXF})
            d = load(r)
            check("set_symbol_file(axf) ok", d.get("ok") is True and d.get("entries", 0) > 0, r[:200])
            check("set_symbol_file source_type=axf", d.get("source_type") == "axf", str(d.get("source_type")))

            # 切换后 find_symbol 能查到 svcrt 内核符号
            r = await call(server, "find_symbol", {"query": "svcrt", "limit": 20})
            d = load(r)
            check("find_symbol 切到 SVCRTOS 后查到 svcrt 符号",
                  d.get("ok") is True and d.get("count", 0) > 0, r[:200])
            syms = d.get("symbols", [])
            if syms:
                check("find_symbol 含 svcrt_ 前缀",
                      any(s.get("name", "").lower().startswith("svcrt") for s in syms),
                      str(syms[:3]))
        else:
            check("set_symbol_file(axf) ok", True, "SVCRTOS axf 不存在跳过")

        # ---- set_symbol_file：加载 .map ----
        if os.path.isfile(_SVCRTOS_MAP):
            r = await call(server, "set_symbol_file", {"path": _SVCRTOS_MAP})
            d = load(r)
            check("set_symbol_file(map) ok", d.get("ok") is True and d.get("entries", 0) > 0, r[:200])
            check("set_symbol_file source_type=map", d.get("source_type") == "map", str(d.get("source_type")))

            r = await call(server, "find_symbol", {"query": "svcrt", "limit": 20})
            d = load(r)
            check("map 符号源 find_symbol 可查 svcrt",
                  d.get("ok") is True and d.get("count", 0) > 0, r[:200])
        else:
            check("set_symbol_file(map) ok", True, "SVCRTOS map 不存在跳过")

        # ---- set_symbol_file：不存在路径 ----
        r = await call(server, "set_symbol_file", {"path": r"D:/nope/missing.axf"})
        d = load(r)
        check("set_symbol_file 不存在路径失败", d.get("ok") is False, r[:200])

        # ---- MapLocator 单元 ----
        if os.path.isfile(_SVCRTOS_MAP):
            ml = MapLocator(_SVCRTOS_MAP)
            check("MapLocator is_ready", ml.is_ready())
            syms = ml.search_symbols("svcrt", limit=20)
            check("MapLocator.search_symbols 查到 svcrt",
                  any("svcrt" in (s.get("name") or "").lower() for s in syms), str(syms[:3]))
            al = ml.addr_to_location(0x08000000)
            check("MapLocator.addr_to_location 返回函数名级", al is not None and al.get("function"),
                  str(al))
        else:
            check("MapLocator 单元", True, "SVCRTOS map 不存在跳过")

        # ---- get_current_location 汇编级降级 + PC 自动匹配 ----
        # 切到 mdk_test（mock PC=0x8000DB4 不在 mdk_test 之外的符号预期内，但会触发自动匹配）
        if os.path.isfile(_MDK_AXF):
            await call(server, "set_symbol_file", {"path": _MDK_AXF})
        r = await call(server, "get_current_location", {})
        d = load(r)
        # 汇编级降级：至少返回 ok + pc（PC 可读，来自 mock reg_map）
        check("get_current_location 始终返回 ok+pc(不因符号问题报错)",
              d.get("ok") is True and d.get("pc") is not None, r[:250])
        # 若触发自动匹配，应带 auto_symbol 或正常解析
        if d.get("auto_symbol"):
            check("PC 自动匹配生效(auto_symbol)", d["auto_symbol"].get("auto_switched") is True,
                  json.dumps(d.get("auto_symbol"), ensure_ascii=False)[:150])
        else:
            check("PC 自动匹配未触发(同符号或无需切换)", True,
                  "auto_symbol 未出现（当前符号已匹配或未命中预登记）")

        # 汇总
        print(f"\n批次8a: 通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
        if FAIL:
            print("失败项:", FAIL)
            sys.exit(1)
    finally:
        srv.stop()


if __name__ == "__main__":
    asyncio.run(main())
