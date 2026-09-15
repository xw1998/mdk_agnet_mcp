# -*- coding: utf-8 -*-
"""批次2 增强工具测试：fault_report / set_conditional_breakpoint。

覆盖本批新增的 2 类工具：
- fault_report  HardFault/异常现场定位（SCB 寄存器 + 异常栈帧恢复）
- set_conditional_breakpoint  条件断点（仅条件/次数满足才停）
"""
import os
import sys
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14828
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
        need = {"fault_report", "set_conditional_breakpoint"}
        check("新工具已注册", need.issubset(names), sorted(need - names))

        # ---- fault_report：异常现场定位 ----
        # 先设 LR=0xFFFFFFE8（EXC_RETURN，bit2=0 → 用 MSP）指向预置异常帧
        r = await call(server, "set_register", {"register": "LR", "value": "0xFFFFFFE8"})
        check("准备 LR=EXC_RETURN(MSP)", '"ok": true' in r, r[:200])
        r = await call(server, "fault_report", {})
        check("fault_report 返回异常报告", '"ok": true' in r and '"exception"' in r, r[:300])
        check("fault_report 识别 HardFault",
              '"name": "HardFault"' in r or "HardFault" in r, r[:400])
        check("fault_report 给出除零原因", "DIVBYZERO" in r and "除零" in r, r[:500])
        check("fault_report 识别 FORCED 强制异常", "FORCED" in r, r[:500])
        check("fault_report 恢复异常栈帧",
              '"fault_frame"' in r and '"pc": "0x08000def"' in r, r[:500])

        # ---- set_conditional_breakpoint：条件断点 ----
        r = await call(server, "set_conditional_breakpoint",
                       {"expr": "v1", "condition": "v1==5", "count": 1})
        check("条件断点设置成功", '"ok": true' in r and '"command"' in r, r[:300])
        check("条件断点命令含条件", "v1==5" in r and "BS" in r, r[:300])
        check("条件断点解析地址", '"address"' in r, r[:300])
        # count>1 时命令附计数
        r = await call(server, "set_conditional_breakpoint",
                       {"expr": "v1", "condition": "v1==5", "count": 3})
        check("条件断点带命中计数", ", 3" in r, r[:300])
        # 空 condition 拒绝
        r = await call(server, "set_conditional_breakpoint",
                       {"expr": "v1", "condition": ""})
        check("空 condition 拒绝", '"ok": false' in r, r[:200])
    finally:
        srv.stop()

if __name__ == "__main__":
    asyncio.run(main())
    print(f"======== 结果 ========\n通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
    if FAIL:
        print("失败:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")
