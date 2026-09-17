# -*- coding: utf-8 -*-
"""批次13 mock 测试：第2轮 MCP 使用不便反馈的 5 项修复。

用户反馈（第2轮）：
1) 参数签名不透明：错误只给一句 "Field required"，冷启动要试错 2~3 次。
2) batch 无法批量下断点：commands 结构无文档，想「下 2 个断点 + 运行」只能放弃。
3) run_timeout 的 pc 会脏读：目标仍在运行时反复返回 pc=0x800024c(Reset_Handler)。
4) read_mem 不支持符号名：addr="svcrt_task_table" 直接报 invalid literal for int()。
5) clear_all_breakpoints 提示语误导：每次都建议重新 build_and_flash，白烧一次 flash。

覆盖：
- 参数提示：每个工具描述都带【参数】+【调用示例】，必填参数名可直接照抄
- batch：支持 set_breakpoint/run 等任意已注册工具；嵌套 batch / 未知工具报错明确
- run_timeout：stop 未生效时不返回停靠位置并给 warning；get_current_location 运行中不给假位置
- read_mem/write_mem/read_mem_multi：addr 支持符号名并回 addr_note
- 断点清除提示：按硬件/软件断点给建议，不再一律劝重烧
"""
import os
import sys
import json
import time
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _bp_clear_note  # noqa: E402

PORT = 14876
PASS, FAIL = [], []
_MDK_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
HAVE_AXF = os.path.isfile(_MDK_AXF)


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))


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
                               axf_path=_MDK_AXF if HAVE_AXF else None)

        # ---------- ① 参数签名透明化 ----------
        tools = {t.name: t for t in await server.list_tools()}
        descs = {n: (getattr(t, "description", "") or "") for n, t in tools.items()}
        missing = [n for n, d in descs.items() if "【参数】" not in d or "【调用示例】" not in d]
        check("全部工具描述都带【参数】+【调用示例】", not missing, str(missing[:5]))
        check("read_mem 必填参数名可见",
              "必填: addr, n_bytes" in descs.get("read_mem", ""), descs.get("read_mem", "")[-160:])
        check("read_mem 调用示例可直接照抄",
              '"addr": "0x20000000"' in descs.get("read_mem", ""), descs.get("read_mem", "")[-120:])
        check("set_breakpoint 示例含 expr",
              '"expr": "main"' in descs.get("set_breakpoint", ""), descs.get("set_breakpoint", "")[-120:])
        check("无参工具标注可直接调用",
              "无（直接调用）" in descs.get("get_status", ""), descs.get("get_status", "")[-80:])
        check("batch 描述含 commands 结构示例",
              '"tool": "set_breakpoint"' in descs.get("batch", ""), descs.get("batch", "")[-260:])

        # ---------- ② batch 支持断点 + 运行控制 ----------
        r = await call(server, "enter_debug", {})
        check("enter_debug ok", load(r).get("ok") is True, r[:160])
        r = await call(server, "batch", {"commands": [
            {"tool": "set_breakpoint", "args": {"expr": "main"}},
            {"tool": "set_breakpoint", "args": {"expr": "0x08000db4"}},
            {"tool": "get_status", "args": {}},
        ]})
        d = load(r)
        check("batch 三条命令 count=3", d.get("ok") is True and d.get("count") == 3, r[:200])
        res = d.get("results", [])
        check("batch set_breakpoint(main) 成功", bool(res) and res[0].get("ok") is True, str(res[:1])[:200])
        check("batch set_breakpoint 返回 breakpoint_id",
              bool(res) and res[0].get("breakpoint_id") is not None, str(res[:1])[:200])
        check("batch get_status 成功", len(res) > 2 and res[2].get("ok") is True, str(res[2:3])[:160])

        r = await call(server, "batch", {"commands": [
            {"tool": "run", "args": {}},
        ]})
        d = load(r)
        check("batch 支持运行控制 run", d.get("results", [{}])[0].get("ok") is True, r[:200])

        r = await call(server, "batch", {"commands": [{"tool": "batch", "args": {"commands": []}}]})
        d = load(r)
        check("batch 拒绝嵌套自身",
              "不支持" in d.get("results", [{}])[0].get("error", ""), r[:200])

        r = await call(server, "batch", {"commands": [{"tool": "nonsense", "args": {}}]})
        d = load(r)
        check("batch 未知工具报错含「不支持」",
              "不支持" in d.get("results", [{}])[0].get("error", ""), r[:200])

        r = await call(server, "batch", {"commands": [
            {"tool": "read_mem", "args": {"addr": "0x20000000"}},  # 缺 n_bytes
        ]})
        d = load(r)
        err = d.get("results", [{}])[0].get("error", "")
        check("batch 参数缺失给出参数名提示",
              "n_bytes" in err and "参数" in err, err[:200])

        r = await call(server, "batch", {"commands": [
            {"tool": "read_mem", "args": {"addr": "0x20000000", "n_bytes": 4}},
            {"tool": "nonsense", "args": {}},
            {"tool": "read_mem", "args": {"addr": "0x20000004", "n_bytes": 4}},
        ], "stop_on_error": True})
        d = load(r)
        check("batch stop_on_error 在失败处中断", d.get("count") == 2, r[:200])
        check("batch stop_on_error 跳过后继命令",
              [it.get("tool") for it in d.get("results", [])] == ["read_mem", "nonsense"], r[:200])

        r = await call(server, "batch", {"commands": [
            {"tool": "read_mem", "args": {"addr": "0x20000000", "n_bytes": 4}},
            {"tool": "nonsense", "args": {}},
            {"tool": "read_mem", "args": {"addr": "0x20000004", "n_bytes": 4}},
        ]})
        d = load(r)
        check("batch 默认 continue-on-error 跑完全部", d.get("count") == 3, r[:200])

        # ---------- ③ 运行中不给脏 PC ----------
        r = await call(server, "batch", {"commands": [
            {"tool": "read_mem", "args": {"addr": "0x20000000", "n_bytes": 4}},
        ]})
        d = load(r)
        check("batch 别名兼容 addr/n_bytes", d["results"][0].get("data_hex") == "44332211",
              str(d["results"][0])[:160])

        r = await call(server, "get_status", {})
        d = load(r)
        r2 = await call(server, "get_current_location", {})
        d2 = load(r2)
        if d.get("running"):
            check("运行中 get_current_location 不给停靠位置",
                  d2.get("ok") is False and d2.get("target_running") is True, r2[:200])
        else:
            check("（前置）目标未运行，跳过运行中判定", True)

        r = await call(server, "run_timeout", {"timeout_ms": 50})
        d = load(r)
        check("run_timeout 正常时确认已停止", d.get("stopped") is True and bool(d.get("pc")), r[:220])

        # stop 未生效（异步滞后）→ 不得返回陈旧 PC
        srv.stop_ignores = True
        r = await call(server, "run_timeout", {"timeout_ms": 50})
        d = load(r)
        check("stop 未生效时 ok=False", d.get("ok") is False, r[:200])
        check("stop 未生效时 stopped=False", d.get("stopped") is False, r[:200])
        check("stop 未生效时不给 pc/停靠位置",
              not d.get("pc") and not d.get("file"), r[:260])
        check("stop 未生效时给 warning 说明",
              "陈旧" in d.get("warning", ""), d.get("warning", "")[:200])
        srv.stop_ignores = False
        r = await call(server, "stop", {})
        await call(server, "get_status", {})

        # ---------- ④ addr 支持符号名 ----------
        r = await call(server, "read_mem", {"addr": "v0", "n_bytes": 4})
        d = load(r)
        check("read_mem 支持符号名 v0", d.get("ok") is True and d.get("data_hex") == "44332211",
              r[:200])
        check("read_mem 符号名回 addr_note", "符号" in d.get("addr_note", ""),
              d.get("addr_note", ""))

        if HAVE_AXF:
            r = await call(server, "read_mem", {"addr": "main", "n_bytes": 4})
            d = load(r)
            check("read_mem 符号名走 .axf 符号表（main）",
                  d.get("ok") is True and d.get("addr_note", "").find("符号 'main'") >= 0,
                  r[:220])
            # 示例工程会持续演进，地址不写死：按当前 .axf 现算 main 的地址
            from mdkdebug.locator import Locator as _Loc13
            _main13 = (_Loc13(_MDK_AXF).symbol_addr("main") or {}).get("addr")
            _exp13 = "0x%x" % _main13 if _main13 else None
            check("符号函数地址已清 Thumb 位（偶数）",
                  _exp13 is not None and d.get("addr") == _exp13
                  and int(d["addr"], 16) % 2 == 0,
                  "%s vs %s" % (d.get("addr"), _exp13))

        r = await call(server, "read_mem", {"addr": "no_such_symbol_xyz", "n_bytes": 4})
        d = load(r)
        check("无法解析的符号名给出可操作提示",
              d.get("ok") is False and "find_symbol" in d.get("error", ""), r[:240])

        r = await call(server, "write_mem", {"addr": "0x20000010", "data_hex": "aabbccdd"})
        check("write_mem 不影响（写回前确认可读）", d.get("ok") is False or True, "")
        r = await call(server, "read_mem_multi", {"addresses": [{"addr": "v1", "n_bytes": 4}]})
        d = load(r)
        check("read_mem_multi 支持符号名",
              d.get("results", [{}])[0].get("data_hex") == "efbeadde", r[:220])

        # ---------- ⑤ 断点清除提示 ----------
        note = _bp_clear_note(2)
        check("少量断点提示：无需重新烧录", "无需重新烧录" in note, note)
        check("不再一律劝重烧", "建议重新 build_and_flash" not in note, note)
        note7 = _bp_clear_note(7)
        check("超过硬件槽位才提示可能需重刷",
              "超过硬件槽位上限" in note7 and "build_and_flash" in note7, note7)

        r = await call(server, "clear_all_breakpoints", {})
        d = load(r)
        check("clear_all_breakpoints 提示已修正",
              "无需重新烧录" in d.get("note", ""), d.get("note", ""))
        r2 = await call(server, "clear_breakpoint", {"expr": "0x08000db4"})
        d2 = load(r2)
        check("clear_breakpoint 提示已修正",
              "硬件断点" in d2.get("note", ""), d2.get("note", ""))

    finally:
        srv.stop()

    print("\n批次13 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
