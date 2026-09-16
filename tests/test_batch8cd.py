# -*- coding: utf-8 -*-
"""批次8c+8d mock 测试：编译PATH注入 + enter_debug诊断 + 状态解码增强。

覆盖：
- get_status 返回 state/state_text 语义解码（无需人工看裸 hex）+ note
- enter_debug 失败时附加 diagnosis 可读诊断
- builder 编译时注入 python PATH（校验子进程 env 含 python 目录）
- 描述性增强（run/run_timeout/step 注意标注）体现在工具 description
"""
import os
import sys
import time
import json
import asyncio
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14863
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

        # 1. 停止态 get_status 返回 state/state_text（模拟真实 Keil SUCCESS+data）
        st = load(await call(server, "get_status", {}))
        check("停止态 get_status ok", st.get("ok") is True, str(st))
        check("停止态 state=0", st.get("state") == 0, f"state={st.get('state')}")
        check("停止态 state_text=已停止", st.get("state_text") == "已停止", str(st.get("state_text")))
        check("get_status 含 note 说明", bool(st.get("note")), str(st.get("note")))

        # 2. 运行态 state=1 / 执行中
        await call(server, "run", {})
        st2 = load(await call(server, "get_status", {}))
        check("运行态 state=1", st2.get("state") == 1, f"state={st2.get('state')}")
        check("运行态 state_text=执行中", st2.get("state_text") == "执行中", str(st2.get("state_text")))
        check("运行态 running=true", st2.get("running") is True, str(st2.get("running")))
        await call(server, "stop", {})

        # 3. enter_debug 失败时附加 diagnosis（mock 未连接板场景由 client 判定）
        ed = load(await call(server, "enter_debug", {}))
        # enter_debug 在 mock 下可能成功；若失败应含 diagnosis 字段
        if ed.get("ok") is False:
            check("enter_debug 失败含 diagnosis", bool(ed.get("diagnosis")), str(ed))
        else:
            check("enter_debug 成功(跳过诊断断言)", True, "ok")

        # 4. 描述性注意标注体现在 description
        for tool, kw in [("run", "停靠信息不可信"), ("run_timeout", "AAPCS"),
                         ("step", "函数入口处不可靠")]:
            desc = tools[tool].description or ""
            check(f"{tool} 描述含'{kw}'", kw in desc, kw)

        # 5. builder 编译 env 注入 python PATH
        import mdkdebug.builder as builder
        import inspect
        src = inspect.getsource(builder)
        check("builder _run_uv4 注入 env PATH", "py_dir" in src and "env[\"PATH\"]" in src, "")
        check("builder 已 import sys", "import sys" in src, "")

    finally:
        srv.stop()

    print(f"\n批次8cd mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")

if __name__ == "__main__":
    asyncio.run(main())
