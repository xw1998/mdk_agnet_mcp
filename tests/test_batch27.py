# -*- coding: utf-8 -*-
"""批次27 mock 测试：时间别名族做全 + list_tools 明确规范名口径（第 10 轮反馈）。

用户反馈原文：
    「批次 25 的别名层完成度不足：只做了一半，反而会让 AI 觉得『既然有别名层，
     那我随便写应该也行』，然后在时间单位上撞墙。要么做全，要么在 list_tools 里
     把规范名显著标出。」

本批两条都做：时间参数按「前缀族 × 写法」展开成笛卡尔积（跨前缀也能用），
并在 list_tools 里写明「规范名以【参数】行为准、未列出的写法会被拒绝」。

  A 时间族完备：同一族内任意前缀 × 任意单位写法都能用
  B 归一 + 单位换算：带 _s/_ms 的按后缀换算，不带后缀的按主名单位
  C 跨族不串：poll/interval 不会冒充 timeout，反之亦然
  D 别名不遮蔽真实参数 / 未知参数仍被拒绝
  E list_tools 口径：显著标出规范名与拒绝策略

运行：python -m tests.test_batch27
"""
import os
import sys
import json
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug import aliases as _aliases  # noqa: E402

PORT = 14899
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:280]), flush=True)

async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:300]}

def norm(server, tool, args):
    """只看归一结果（不执行工具），便于断言参数映射与换算。"""
    return server.normalize_arguments(tool, args)

def amap(tool):
    return _aliases.aliases_of(tool)

async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    await call(server, "enter_debug", {})

    # ---------------- A. 时间族完备 ----------------
    print("A. 时间参数按族展开（换个前缀不再撞墙）")
    check("A1 run_timeout 认 duration_s", amap("run_timeout").get("duration_s") == "timeout_ms",
          amap("run_timeout").get("duration_s"))
    check("A2 run_timeout 认 wait_s / max_ms",
          amap("run_timeout").get("wait_s") == "timeout_ms"
          and amap("run_timeout").get("max_ms") == "timeout_ms")
    check("A3 build_project 认 timeout_ms", amap("build_project").get("timeout_ms") == "timeout_s",
          amap("build_project").get("timeout_ms"))
    check("A4 profile_function 认 timeout_s",
          amap("profile_function").get("timeout_s") == "max_ms",
          amap("profile_function").get("timeout_s"))
    check("A5 wait_breakpoint 认 duration_ms",
          amap("wait_breakpoint").get("duration_ms") == "timeout_s",
          amap("wait_breakpoint").get("duration_ms"))
    check("A6 wait_fault 认 max_s", amap("wait_fault").get("max_s") == "timeout_ms",
          amap("wait_fault").get("max_s"))
    check("A7 四个同族前缀（timeout/duration/max/wait）× 三种写法都齐",
          all(amap("run_timeout").get(p + s) == "timeout_ms"
              for p in ("timeout", "duration", "max", "wait") for s in ("", "_ms", "_s")
              if p + s != "timeout_ms"))

    # ---------------- B. 归一 + 换算 ----------------
    print("B. 归一与单位换算")
    args, applied = norm(server, "run_timeout", {"timeout_s": 2})
    check("B1 run_timeout(timeout_s=2) → timeout_ms=2000",
          args.get("timeout_ms") == 2000 and any("timeout_s" in s for s in applied), (args, applied))
    args, _ = norm(server, "run_timeout", {"duration_s": 0.5})
    check("B2 duration_s 换前缀也换算（0.5s → 500ms）", args.get("timeout_ms") == 500, args)
    args, _ = norm(server, "build_project", {"timeout": 60})
    check("B3 不带后缀的别名按主名单位（timeout=60 → timeout_s=60）",
          args.get("timeout_s") == 60, args)
    args, _ = norm(server, "build_project", {"timeout_ms": 60000})
    check("B4 主名是秒时收毫秒写法（60000ms → 60.0s）", args.get("timeout_s") == 60.0, args)
    args, _ = norm(server, "profile_sampling", {"max_s": 3})
    check("B5 profile_sampling(max_s=3) → duration_ms=3000",
          args.get("duration_ms") == 3000, args)

    # ---------------- C. 跨族不串 ----------------
    print("C. 跨族不串（间隔 ≠ 超时）")
    check("C1 poll_ms 不认 timeout_s", "timeout_s" not in amap("wait_breakpoint") or
          amap("wait_breakpoint").get("poll_ms") == "poll_ms" or
          _aliases.aliases_of("wait_breakpoint").get("timeout_s") != "poll_ms")
    check("C2 interval_ms 与 poll_ms 同族互换",
          amap("profile_sampling").get("poll_ms") == "interval_ms",
          amap("profile_sampling").get("poll_ms"))
    check("C3 interval_s 指向 interval_ms 而不是 duration_ms",
          amap("profile_sampling").get("interval_s") == "interval_ms",
          amap("profile_sampling").get("interval_s"))
    check("C4 convert_time 跨族不换算", _aliases.convert_time("poll_ms", "timeout_s", 2) == 2,
          _aliases.convert_time("poll_ms", "timeout_s", 2))
    check("C5 convert_time 同族换算照旧",
          _aliases.convert_time("timeout_ms", "timeout_s", 2) == 2000
          and _aliases.convert_time("timeout_s", "timeout_ms", 2500) == 2.5)

    # ---------------- D. 遮蔽与未知参数 ----------------
    print("D. 别名不遮蔽真实参数 / 未知参数被拒绝")
    check("D1 read_mem 的真实参数 length 仍是真实参数（不当别名展示）",
          "length" not in _aliases.alias_note("read_mem", {"addr", "n_bytes", "length", "reloc_delta"}))
    bad = await call(server, "run_timeout", {"timeouts_s": 5})
    check("D2 拼错的 timeouts_s 被拒绝且报错列出可用参数",
          "_exc" in bad and "timeouts_s" in str(bad) and "timeout_ms" in str(bad), bad)
    ok = await call(server, "run_timeout", {"duration_s": 0.05})
    check("D3 别名写法真能落到工具上（真调一次 run_timeout）",
          ok.get("ok") is not None or ok.get("timeout_ms") == 50, ok)

    # ---------------- E. list_tools 口径 ----------------
    print("E. list_tools 把规范名与拒绝策略说清楚")
    tools = await server.list_tools()
    d = {t.name: (t.description or "") for t in tools}
    check("E1 描述里出现【参数别名】", "【参数别名】" in d.get("run_timeout", ""))
    check("E2 明确规范名的权威位置",
          "规范名以上方【参数】行为准" in d.get("run_timeout", ""))
    check("E3 明确未列出的写法会被拒绝",
          "未列出的参数名会被拒绝，不会静默忽略" in d.get("run_timeout", ""))
    check("E4 时间参数标出单位换算规则",
          "带 _s/_ms 的别名按后缀换算" in d.get("run_timeout", ""), d.get("run_timeout", "")[-160:])
    check("E5 主名带单位标注（毫秒）", "timeout_ms（毫秒）" in d.get("run_timeout", ""))
    d2 = {t.name: (t.description or "") for t in await server.list_tools()}
    check("E6 重复 list_tools 不叠加说明",
          d2.get("run_timeout", "").count("【参数别名】") == 1,
          d2.get("run_timeout", "").count("【参数别名】"))
    check("E7 无参数工具不加别名块", "【参数别名】" not in d.get("get_status", ""))

    await call(server, "exit_debug", {})
    srv.stop()

    print("\n==== 批次27 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
