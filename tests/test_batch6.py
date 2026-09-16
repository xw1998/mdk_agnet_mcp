# -*- coding: utf-8 -*-
"""批次6 mock 测试：目标器件信息 / 采样剖析 / 环境自检引导。

覆盖本批新增的 3 个工具：
- target_info       查询目标器件信息（读 DBGMCU IDCODE 判型号 + Flash/RAM 容量 + 内存布局）
- profile_sampling  采样剖析：周期性 run/stop 采 PC → 按 .axf 符号表归到函数 → 热点统计
- mdk_guide         环境自检 + 调试工作流引导（Keil/UVSOCK/UV4/.axf/调试态/RTOS 类型）

target_info 的 IDCODE 读取在 mock_uvsock_server 中模拟（0xE0042000 → 0x423）。
profile_sampling 依赖真实 mdk_test.axf 符号表把 PC 归到函数。
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14860
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

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
        need = {"target_info", "profile_sampling", "mdk_guide"}
        check("新工具已注册(3)", need.issubset(names), sorted(need - names))

        # ---- mdk_guide：环境自检（未进入调试时也能返回环境概览） ----
        r = await call(server, "mdk_guide", {})
        d = load(r)
        check("mdk_guide ok", d.get("ok") is True, r[:200])
        env = d.get("environment", {})
        check("mdk_guide keil可达(mock)", env.get("keil_uvsocket_reachable") is True,
              str(env.get("keil_uvsocket_reachable")))
        check("mdk_guide axf就绪", env.get("axf_configured") is True and env.get("symbol_ready") is True,
              str(env.get("symbol_ready")))
        check("mdk_guide rtos探测(裸机→none)",
              any(x.get("rtos") == "none" for x in env.get("rtos", [])), str(env.get("rtos")))
        check("mdk_guide 工作流非空",
              isinstance(d.get("recommended_workflow"), list) and len(d.get("recommended_workflow")) >= 3)
        check("mdk_guide 场景工具映射非空", isinstance(d.get("scene_tools"), dict) and len(d.get("scene_tools")) >= 3)

        # ---- 进入调试后再自检，应看到 debugging=True ----
        await call(server, "enter_debug", {})
        d2 = load(await call(server, "mdk_guide", {}))
        check("mdk_guide 调试态识别", d2.get("environment", {}).get("debugging") is True,
              str(d2.get("environment", {}).get("debugging")))

        # ---- target_info：实时读 DBGMCU IDCODE → STM32F401 ----
        r = await call(server, "target_info", {})
        d = load(r)
        check("target_info ok+source实时", d.get("ok") is True and d.get("source") == "IDCODE实时读取",
              r[:200])
        check("target_info idcode映射F401",
              d.get("dev_id") == "0x0423" and "F401" in (d.get("device_name") or ""),
              f"{d.get('dev_id')}/{d.get('device_name')}")
        check("target_info Flash/RAM标称", d.get("flash_kb") == 512 and d.get("ram_kb") == 96,
              f"{d.get('flash_kb')}/{d.get('ram_kb')}")
        check("target_info 内存布局", d.get("memory_layout", {}).get("code_base") == "0x08000000")

        # ---- profile_sampling：run/stop 采 PC → 归到函数 ----
        r = await call(server, "profile_sampling",
                       {"duration_ms": 300, "interval_ms": 5, "max_samples": 20})
        d = load(r)
        check("profile_sampling ok", d.get("ok") is True, r[:200])
        check("profile_sampling 采到样本",
              d.get("total_samples", 0) > 0 and d.get("sampled_pcs", 0) > 0,
              f"total={d.get('total_samples')} pcs={d.get('sampled_pcs')}")
        hot = d.get("hot_functions", [])
        check("profile_sampling 热点非空", isinstance(hot, list) and len(hot) >= 1, str(hot)[:200])
        check("profile_sampling 热点有函数名与占比",
              bool(hot) and hot[0].get("function") and isinstance(hot[0].get("percent"), (int, float)),
              str(hot[0]) if hot else "")
        total_pct = round(sum(h.get("percent", 0) for h in hot), 1)
        check("profile_sampling 占比合计100", abs(total_pct - 100.0) < 0.2, f"pct={total_pct}")
        # 采样后目标应处于停止态（finally stop）
        st = load(await call(server, "get_status", {}))
        check("profile_sampling 结束后目标停止", st.get("running") is not True,
              str(st.get("running")))

        # ---- target_info 退出调试后也应安全返回（结构完整） ----
        await call(server, "exit_debug", {})
        r = await call(server, "target_info", {})
        d = load(r)
        check("target_info 退出调试后安全返回",
              d.get("ok") is True and "memory_layout" in d, r[:200])

        print(f"\n批次6结果：PASS={len(PASS)} FAIL={len(FAIL)}")
        if FAIL:
            print("失败项：", FAIL)
            raise SystemExit(1)
    finally:
        srv.stop()

if __name__ == "__main__":
    asyncio.run(main())
