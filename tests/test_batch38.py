# -*- coding: utf-8 -*-
"""批次38 mock 测试：真机「阶段7 全量测试」暴露的三处错误归类缺口。

真机发现（F401 + Keil UVSOCK）：
1) `set_register(register="r99")` 报「不支持的寄存器名: r99」，但 error_code 落进
   unknown-error，next_actions 指向 keil_health —— 一个纯参数错误被指去查调试通道，
   **方向完全错的下一步比没有下一步更坑**。
2) `wait_state(state="stopped", timeout_s=3)` 超时（返回里明明有 matched=False +
   timeout_kind=timeout + observed=running）却同样落进 unknown-error / keil_health，
   而调用方真正该看的是 observed 现场。
3) `profile_function("main", 800ms)` 报「未到达函数入口（函数可能未被调用）」，
   同样落 unknown-error。

修复（只做加法，不改既有字段）：
- errors.ERROR_CODES 新增 `wait-state-timeout` / `function-not-reached`；
- _classify_structured 认 wait_state 的 matched=False + timeout_kind + observed；
- _RULES 补「不支持的寄存器名 / 无法解析数值 / 未到达函数入口」三条文本兜底；
- server.set_register / profile_function 直接给出结构化 error_code（比文本猜更准）。

另外两组来自同一轮真机「把没测到的全测完」：
4) **run_to_line 假成功**：先 run 到 main 死循环，再 run_to_line 一个早已跑过的地址
   （0x08002D60），旧实现返回 ok=true + 停在第 171 行，而 get_status 显示 running=true
   ——目标根本没停。改为用 wait_breakpoint 校验真命中，未命中就如实失败
   （run-to-target-timeout）并把目标 stop（stop_verified 确认过才写「已停止」）；
5) **uvprojx_edit 四个 action 在副本上全跑通**，并补上「未锚定正则一次删一大片」的告警
   （真机实测 pattern="stm32f4xx_hal" 一次命中二十多个文件）。

分组：C 参数错误归类 / D wait_state 超时 / E profile_function 未达入口 /
      F 既有映射回归 / G run_to_line 防假成功 / H uvprojx_edit 受控编辑

运行：python -m tests.test_batch38
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer     # noqa: E402
from mdkdebug.server import create_server                 # noqa: E402
from mdkdebug import errors as errs                        # noqa: E402

PORT = 14912
PASS, FAIL = [], []
_MDK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MDK_PROJ = os.path.join(_MDK_ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvprojx")
_MDK_AXF = os.path.join(_MDK_ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                        "mdk_test", "mdk_test.axf")

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

async def call(server, name, args=None):
    res = await server.call_tool(name, args or {})
    return json.loads("".join(getattr(c, "text", "") or "" for c in res.content))

def _no_keil_health(actions):
    """下一步动作里不能出现「去查 Keil/调试通道」这类方向性错误。"""
    bad = ("keil_health", "read_async_messages", "restart_keil")
    return not any(any(b in str(a) for b in bad) for a in (actions or []))

def test_register_arg_error(server):
    """C：set_register 参数错误 → invalid-argument（而不是 unknown-error）。"""
    asyncio.run(call(server, "enter_debug", {}))
    r = asyncio.run(call(server, "set_register", {"register": "r99", "value": "1"}))
    check("C1 不支持的寄存器名：error_code=invalid-argument",
          r.get("error_code") == "invalid-argument", r)
    check("C2 error_hint 是「参数不合法或缺失」，不是「未归类的失败」",
          r.get("error_hint") == "参数不合法或缺失", r)
    check("C3 next_actions 不再指向 keil_health（方向正确）",
          _no_keil_health(r.get("next_actions")), r)
    check("C4 列出可用的寄存器名候选（调用方一眼能改对）",
          bool(r.get("available")), r)

    r = asyncio.run(call(server, "set_register", {"register": "r0", "value": "zzz"}))
    check("C5 数值解析失败：error_code=invalid-argument",
          r.get("error_code") == "invalid-argument", r)
    check("C6 给出 value 的写法提示",
          any("0x" in str(a) or "十进制" in str(a) for a in (r.get("next_actions") or [])), r)

    r = asyncio.run(call(server, "set_register", {"register": "r0", "value": "0x1234"}))
    check("C7 正常路径不受影响：写成功且读回一致（信封不添噪声）",
          r.get("ok") is True and r.get("status") == "ok" and not r.get("error_code"), r)

def test_wait_state_timeout_code(server):
    """D：wait_state 超时 → 结构化归类（看 observed，而不是去查调试通道）。"""
    asyncio.run(call(server, "run", {}))
    r = asyncio.run(call(server, "wait_state",
                         {"state": "stopped", "timeout_s": 1, "poll_ms": 100}))
    check("D1 超时：error_code=wait-state-timeout",
          r.get("error_code") == "wait-state-timeout", r)
    check("D2 如实带上现场（timeout_kind / observed）",
          r.get("timeout_kind") == "timeout" and r.get("observed") == "running", r)
    check("D3 next_actions 指向 observed / wait_breakpoint 这条正确路径",
          any("observed" in str(a) or "wait_breakpoint" in str(a)
              for a in (r.get("next_actions") or [])), r)
    check("D4 next_actions 不再指向 keil_health",
          _no_keil_health(r.get("next_actions")), r)
    asyncio.run(call(server, "stop", {}))

    asyncio.run(call(server, "exit_debug", {}))
    r = asyncio.run(call(server, "wait_state", {"state": "stopped", "timeout_s": 1}))
    check("D5 一直不在调试态：归类为 not-debugging",
          r.get("error_code") == "not-debugging", r)
    check("D6 下一步是 enter_debug",
          any("enter_debug" in str(a) for a in (r.get("next_actions") or [])), r)
    asyncio.run(call(server, "enter_debug", {}))

def test_profile_function_code(server):
    """E：profile_function 未达入口 → function-not-reached（可执行的下一步）。"""
    r = asyncio.run(call(server, "profile_function",
                         {"func": "0x8000DB4", "max_ms": 400}))
    check("E1 未到达函数入口：error_code=function-not-reached",
          r.get("error_code") == "function-not-reached", r)
    check("E2 回填函数名与入口地址（便于核对是不是符号错了）",
          r.get("function") == "0x8000DB4" and bool(r.get("entry")), r)
    check("E3 next_actions 给出「确认调用路径 / 先 reset」这类可执行动作",
          any(("reset" in str(a) or "run_to_line" in str(a) or "find_symbol" in str(a))
              for a in (r.get("next_actions") or [])), r)
    check("E4 next_actions 不再指向 keil_health",
          _no_keil_health(r.get("next_actions")), r)

    r = asyncio.run(call(server, "profile_function", {"func": "这个符号不存在"}))
    check("E5 入口地址解析不了：error_code=invalid-argument",
          r.get("error_code") == "invalid-argument", r)
    asyncio.run(call(server, "exit_debug", {}))

def test_run_to_line_guard(server, mock):
    """G：run_to_line 必须校验「真命中」，不许拿陈旧 PC 报假成功。

    真机阶段7 实测：先 run 到 main 死循环，再 run_to_line 到一个「早就跑过去」的
    地址（0x08002D60），旧实现返回 ok=true + stopped_file/line=第 171 行，而紧跟着
    的 get_status 显示 running=true —— 目标根本没停，是典型的「看似权威的错答案」。
    """
    asyncio.run(call(server, "enter_debug", {}))

    # G1-G5 断点永不命中（模拟「该地址已执行过」：目标一直在跑）
    mock.auto_stop_reads = None
    mock.auto_stop_pc = None
    r = asyncio.run(call(server, "run_to_line",
                         {"target": "0x08000DB4", "timeout_s": 1}))
    check("G1 未命中：ok=false 且 error_code=run-to-target-timeout",
          r.get("ok") is False and r.get("error_code") == "run-to-target-timeout", r)
    check("G2 带上现场（observed / waited_ms / ran_during_wait）",
          r.get("observed") in ("running", "stopped-elsewhere")
          and r.get("waited_ms") is not None, r)
    check("G3 不再回一个「停在第 N 行」的假答案",
          not r.get("stopped_file") and not r.get("stopped_line"), r)
    check("G4 next_actions 指到 reset / set_breakpoint（不是去查调试通道）",
          _no_keil_health(r.get("next_actions"))
          and any("reset" in str(a) or "set_breakpoint" in str(a)
                  for a in (r.get("next_actions") or [])), r)
    st = asyncio.run(call(server, "get_status", {}))
    check("G5 失败后目标已停下（不把「还在跑」留给调用方）",
          st.get("running") is False, st)
    check("G5b stop_verified=true：停止状态是确认过的，不是「发出去了就算」",
          r.get("stop_verified") is True, r)

    # G6-G7 真命中路径：mock 在 1 次状态查询后停下，PC 落在目标地址
    mock.auto_stop_reads = 1
    mock.auto_stop_pc = 0x08000DB4
    r = asyncio.run(call(server, "run_to_line",
                         {"target": "0x08000DB4", "timeout_s": 3}))
    check("G6 命中：ok=true，且透出命中地址/依据/置信度",
          r.get("ok") is True and r.get("hit_address") is not None
          and bool(r.get("new_stop_basis")) and r.get("waited_ms") is not None, r)
    check("G7 命中时仍给停靠位置（原有 stopped_file/line 能力不回退）",
          bool(r.get("stopped_file")) and bool(r.get("stopped_line")), r)

    # G8 timeout 别名可用（秒类别名走同一套超时语义）
    mock.auto_stop_reads = None
    mock.auto_stop_pc = None
    r = asyncio.run(call(server, "run_to_line",
                         {"target": "0x08000DB4", "timeout": 1}))
    check("G8 timeout 别名可用（同一套超时语义）",
          r.get("ok") is False and r.get("error_code") == "run-to-target-timeout", r)
    asyncio.run(call(server, "stop", {}))
    asyncio.run(call(server, "exit_debug", {}))


def test_uvprojx_edit_actions(server):
    """H：uvprojx_edit 四个 action 在**工程副本**上跑一遍（真机阶段7 补测）。

    真机实测的额外收获：remove_files 的 pattern 是正则且作用于 FilePath，
    `pattern="stm32f4xx_hal"` 一次删掉二十多个文件 → 命中过多时必须告警。
    """
    if not os.path.isfile(_MDK_AXF):
        check("H0 存在可用的真实工程样例", False, _MDK_AXF)
        return
    work = tempfile.mkdtemp(prefix="mdkdebug_b38_")
    copy = os.path.join(work, "mdk_test.uvprojx")
    shutil.copy2(_MDK_PROJ, copy)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "add_include_path", "project": copy, "paths": "../B38/Inc"}))
    check("H1 add_include_path：写入且自动备份",
          r.get("ok") and r.get("changed") and os.path.isfile(r.get("backup") or ""), r)
    r = asyncio.run(call(server, "uvprojx_read", {"project": copy, "what": "config"}))
    check("H2 写回后读得到（不是只回了 ok）",
          "B38" in str(r.get("config", {}).get("include_path") or ""), r)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "del_include_path", "project": copy, "pattern": "B38"}))
    check("H3 del_include_path：按正则删除", r.get("ok") and r.get("removed"), r)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "add_files", "project": copy, "group": "_probe",
        "files": "../Core/Src/_b38_probe.c"}))
    check("H4 add_files：分组不存在时自动新建",
          r.get("ok") and r.get("created_group") is True, r)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "remove_files", "project": copy, "pattern": "_probe"}))
    check("H5 remove_files：单个命中不误报宽正则告警",
          r.get("ok") and not r.get("warning"), r)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "remove_files", "project": copy, "pattern": "stm32f4xx"}))
    check("H6 宽正则一次命中一大片时给出 warning（真机踩到：一删二十多个）",
          r.get("ok") and len(r.get("removed") or []) >= 5 and r.get("warning"), r)
    check("H7 告警里提醒了备份还在（可回滚）",
          "backup" in str(r.get("warning")), r)

    r = asyncio.run(call(server, "uvprojx_edit", {
        "action": "explode", "project": copy}))
    check("H8 未知 action 拒绝并列出可用值",
          r.get("ok") is False and r.get("available"), r)
    shutil.rmtree(work, ignore_errors=True)


def test_legacy_mapping_unchanged():
    """F：新规则不得抢走既有映射（回归）。"""
    check("F1 serial_expect 的 timeout 结构化判定没被 wait_state 分支抢走",
          errs._classify_structured({"timeout": True, "timeout_kind": "no-data"})
          == "serial-expect-timeout-no-data", "")
    check("F2 ocd_read_mem 的 complete=False 仍归 ocd-read-short",
          errs._classify_structured({"complete": False, "expected_bytes": 16})
          == "ocd-read-short", "")
    check("F3 老文本规则仍生效（编译失败 → build-failed）",
          errs.classify_error("编译未通过：main.c error #20") == "build-failed", "")
    check("F4 老文本规则仍生效（未进入调试 → not-debugging）",
          errs.classify_error("当前未进入调试状态") == "not-debugging", "")
    check("F5 wait_state 结构体缺 observed 时不误判",
          errs._classify_structured({"matched": False, "timeout_kind": "timeout"}) == "", "")

def main():
    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=60.0,
                               axf_path=_MDK_AXF if os.path.isfile(_MDK_AXF) else None)
        print("-- C set_register 参数错误归类 --")
        test_register_arg_error(server)
        print("-- D wait_state 超时归类 --")
        test_wait_state_timeout_code(server)
        print("-- E profile_function 未达入口归类 --")
        test_profile_function_code(server)
        print("-- F 既有映射回归 --")
        test_legacy_mapping_unchanged()
        print("-- G run_to_line 防「假成功」 --")
        test_run_to_line_guard(server, mock)
        print("-- H uvprojx_edit 受控编辑 --")
        test_uvprojx_edit_actions(server)
    finally:
        mock.stop()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
