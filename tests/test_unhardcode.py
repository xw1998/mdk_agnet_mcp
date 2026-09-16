# -*- coding: utf-8 -*-
"""去硬编码 mock 测试：开源跨机可用的符号工程注入。

根因：server._SYMBOL_PROJECTS 把本机绝对路径（D:/工作/git_project/svcrtos_new 等）
写死进代码，换机子 clone 后失效。
改：仓库内置 mdk_test 用相对仓库根推导；本机/外部工程通过
MDKDEBUG_SYMBOL_PROJECTS 环境变量（JSON 数组）或 --symbol-project 启动参数注入。

覆盖：
- _builtin_symbol_projects：mdk_test 用相对仓库根推导，不写死本机绝对路径
- _symbol_projects_from_env：环境变量 JSON 数组注入 / 空 / 非法 / 丢弃无 name 项
- create_server 合并：内置 + 环境变量 + 启动参数 symbol_projects
- list_symbol_projects 工具能看到注入的外部工程（mock 集成）
"""
import os
import sys
import time
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _builtin_symbol_projects, \
    _symbol_projects_from_env, _REPO_ROOT  # noqa: E402
from mdkdebug.client import UVClient  # noqa: E402

PORT = 14866
PASS, FAIL = [], []

# 外部注入工程的示例（模拟用户本机工程，未编译也可注入登记）
_EXTERNAL = {
    "name": "myboard_app",
    "axf": r"D:/some/other/board/out/app.axf",
    "map": r"D:/some/other/board/out/app.map",
    "flash_start": 0x08000000,
    "flash_size": 0x100000,
}


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
    # ---------- 1. 内置符号工程：相对仓库根推导，不写死本机路径 ----------
    builtin = _builtin_symbol_projects()
    check("内置工程=1(mdk_test)", len(builtin) == 1, f"got {len(builtin)}")
    m = builtin[0] if builtin else {}
    check("内置 name=mdk_test", m.get("name") == "mdk_test", str(m)[:80])
    axf = m.get("axf") or ""
    check("内置 axf 相对仓库根推导",
          "example_mdk_project" in axf and "mdk_test.axf" in axf, axf)
    # 关键：默认内置不再写死本机【外部工程】(svcrtos_new) 的绝对路径
    check("默认不含外部 svcrtos_new 写死路径",
          "svcrtos_new" not in axf and "SVCRTOS" not in json.dumps(builtin),
          axf)
    check("内置路径基于 _REPO_ROOT(clone 后自动正确)",
          os.path.normpath(axf).startswith(os.path.normpath(_REPO_ROOT)), axf)

    # ---------- 2. 环境变量注入 ----------
    # 2a. 无环境变量 → 空
    old = os.environ.pop("MDKDEBUG_SYMBOL_PROJECTS", None)
    try:
        check("无 env → 空列表", _symbol_projects_from_env() == [], "")
    finally:
        if old is not None:
            os.environ["MDKDEBUG_SYMBOL_PROJECTS"] = old
    # 2b. 合法 JSON 数组 → 注入
    os.environ["MDKDEBUG_SYMBOL_PROJECTS"] = json.dumps([_EXTERNAL])
    try:
        got = _symbol_projects_from_env()
        check("env 注入 1 项", len(got) == 1, f"got {len(got)}")
        check("env 注入 name/axf 正确",
              got and got[0]["name"] == "myboard_app"
              and "app.axf" in got[0]["axf"], f"got={got}")
    finally:
        os.environ.pop("MDKDEBUG_SYMBOL_PROJECTS", None)
    # 2c. 非法 JSON → 空且不抛异常
    os.environ["MDKDEBUG_SYMBOL_PROJECTS"] = "{not valid json"
    try:
        check("env 非法 JSON → 空", _symbol_projects_from_env() == [], "")
    finally:
        os.environ.pop("MDKDEBUG_SYMBOL_PROJECTS", None)
    # 2d. 丢弃无 name 项
    os.environ["MDKDEBUG_SYMBOL_PROJECTS"] = json.dumps(
        [{"axf": "x.axf"}, _EXTERNAL])
    try:
        got = _symbol_projects_from_env()
        check("env 丢弃无 name 项",
              len(got) == 1 and got[0]["name"] == "myboard_app", f"got={got}")
    finally:
        os.environ.pop("MDKDEBUG_SYMBOL_PROJECTS", None)

    # ---------- 3. create_server 合并：内置 + env + 参数 ----------
    os.environ["MDKDEBUG_SYMBOL_PROJECTS"] = json.dumps([_EXTERNAL])
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                               symbol_projects=[_EXTERNAL])
        tools = {t.name: t for t in await server.list_tools()}
        check("list_symbol_projects 已注册",
              "list_symbol_projects" in tools, "")

        # 3a. 合并后含 3 项：内置 mdk_test + env 注入 + 参数注入
        lst = load(await call(server, "list_symbol_projects", {}))
        names = [p.get("name") for p in lst.get("projects") or []]
        check("合并含 mdk_test 内置", "mdk_test" in names, f"names={names}")
        check("合并含 env 注入(myboard_app)",
              names.count("myboard_app") >= 1, f"names={names}")
        check("合并共 3 项", len(lst.get("projects") or []) == 3,
              f"n={len(lst.get('projects') or [])} names={names}")

        # 3b. list_symbol_projects 文本能看到注入工程名
        txt = lst.get("text") or json.dumps(lst)
        check("文本含注入工程名", "myboard_app" in txt, txt[:120])
    finally:
        os.environ.pop("MDKDEBUG_SYMBOL_PROJECTS", None)
        srv.stop()

    print(f"\n去硬编码 mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
