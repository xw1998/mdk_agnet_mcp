# -*- coding: utf-8 -*-
"""批次20 mock 测试：真机全功能回归发现的「断点假成功」与「数据观察点清不掉」。

真机实测（本轮全功能回归）：
  * `BK 0x20000000`（数据观察点）UVSOCK 回 status=0「成功」，Keil 命令窗口却报
    `*** error 72: invalid item number`，断点仍生效 —— 只看 status 会把「没清掉」当成功。
  * `BL` 的输出**会**经命令输出通道(0x5020)回传，可解析出真实断点表（编号/类型/地址/CNT/enabled）。
  * `BS` 对已存在断点报 `*** error 145: Redefinition: item already exists`。

覆盖：
  A 命令窗口级校验（exec_command_checked）：窗口报错 → ok=false；无错 → 附 console
  B BL 输出解析与编号解析（parse_breakpoint_table / resolve_breakpoint_number）
  C 清除改为按 Keil 编号（clear_breakpoint / clear_watchpoint / clear_all_watchpoints）
  D 工具层暴露真实断点表与 hard 兜底（list_breakpoints.real / clear_*_watchpoints(hard)）
  E 窗口级校验不吃掉命令窗口缓冲（回归 test_batch9：缓冲须保留给 read_console_output）
  F 文档与诊断口径

运行：python -m tests.test_batch20
"""
import sys, os, json, time, asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import create_server, _get_client
from mdkdebug.client import UVClient

PORT = 14892
PASS, FAIL = [], []

# 真机 BL 输出样例（照抄实机日志）
BL_SAMPLE = [
    " 0: (E 0x08000DB4) '\\mdk_test\\../Core/Src/main.c\\77', CNT=1, enabled",
    " 1: (A WR 0x20001000 len=1) '0x20001000', CNT=1, enabled",
    " 2: (E 0x08000DB8) '\\mdk_test\\../Core/Src/main.c\\84', CNT=1, enabled",
    " 3: (A WR 0x20000000 len=1) '0x20000000', CNT=1, enabled",
    " 4: (E 0x08000DC0) '0x8000dc0', CNT=1, disabled",
]


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail), flush=True)


async def call(server, name, args):
    res = await server.call_tool(name, args)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
    client = _get_client()

    await call(server, "enter_debug", {})
    st = await call(server, "get_status", {})
    check("A0 前置：mock 已连上且处于调试态", st.get("ok") is True, str(st)[:160])

    # ============ A. 命令窗口级校验 ============
    srv.exec_console_extra = ["*** error 72: invalid item number"]
    r = client.exec_command_checked("BK 0x20000000")
    check("A1 窗口报 *** error 72 时 ok=false（UVSOCK status 仍为 0）",
          r.get("ok") is False and r.get("status") == 0, str(r)[:240])
    check("A2 errors 带错误码与原文",
          bool(r.get("errors")) and r["errors"][0].get("code") == 72
          and "invalid item number" in (r["errors"][0].get("message") or ""), str(r)[:260])
    check("A3 顶层 error 字段可直接读",
          "error 72" in (r.get("error") or ""), str(r)[:200])
    check("A4 console 原文一并回传（可溯源）",
          any("error 72" in c for c in (r.get("console") or [])), str(r.get("console"))[:220])

    srv.exec_console_extra = []
    r0 = client.exec_command_checked("BK 0x20000000")
    check("A5 无窗口报错时 ok 保持 true", r0.get("ok") is True, str(r0)[:200])
    check("A6 正常路径也带 console（命令回显）",
          bool(r0.get("console")), str(r0)[:200])
    check("A7 正常路径不带 errors", not r0.get("errors"), str(r0)[:180])

    # 145：断点已存在 -> 对「设置」语义应视为成功
    srv.exec_console_extra = ["*** error 145: Redefinition: item already exists"]
    sb = client.set_breakpoint("main")
    check("A8 BS 报 error 145（已存在）时 set_breakpoint 视为成功",
          sb.get("ok") is True and sb.get("already_exists") is True, str(sb)[:260])
    check("A9 该场景给 note 说明未重复创建",
          "已存在" in (sb.get("note") or ""), str(sb)[:240])
    srv.exec_console_extra = []

    # ============ B. BL 解析与编号解析 ============
    bps = UVClient.parse_breakpoint_table(BL_SAMPLE)
    check("B1 解析出 5 条真实断点", len(bps) == 5, str(bps)[:200])
    check("B2 代码断点识别为 exec 且带编号/地址",
          bps[0]["number"] == 0 and bps[0]["kind"] == "exec"
          and bps[0]["address"] == "0x08000DB4", str(bps[0])[:220])
    check("B3 数据观察点识别为 access 且带访问类型/长度",
          bps[1]["kind"] == "access" and bps[1]["access"] == "WR"
          and bps[1]["length"] == 1, str(bps[1])[:220])
    check("B4 CNT / enabled 解析正确（含 disabled）",
          bps[0]["count"] == 1 and bps[0]["enabled"] is True
          and bps[4]["enabled"] is False, str(bps[4])[:220])
    check("B5 非 BL 行被忽略（不会误当断点）",
          UVClient.parse_breakpoint_table(["BL", "*** error 72: bad", ""]) == [])

    # resolve_breakpoint_number：用真机样例打桩，不依赖 mock 的 BL 格式
    client.list_breakpoints_real = lambda *a, **k: {
        "ok": True, "count": len(bps), "breakpoints": bps}
    n1, why1 = client.resolve_breakpoint_number("0x20000000")
    check("B6 按地址能解析出 Keil 断点编号（数据观察点）",
          n1 == 3, "%s / %s" % (n1, why1))
    n2, _ = client.resolve_breakpoint_number("0x08000DB4")
    check("B7 按地址解析代码断点编号（容忍 Thumb 位）", n2 == 0, str(n2))
    n3, _ = client.resolve_breakpoint_number("2")
    check("B8 直接给编号也能解析", n3 == 2, str(n3))
    n4, why4 = client.resolve_breakpoint_number("0x20009000")
    check("B9 不存在的地址返回 None + 原因", n4 is None and bool(why4), why4)

    # clear_breakpoint 走编号路径
    calls = []
    real_checked = client.exec_command_checked
    client.exec_command_checked = lambda cmd, **k: (
        calls.append(cmd) or {"ok": True, "status": 0, "status_text": "成功", "command": cmd})
    cb = client.clear_breakpoint("0x20000000")
    check("B10 数据观察点按编号清除（BK 3 而非 BK 0x20000000）",
          calls and calls[-1] == "BK 3", str(calls))
    check("B11 结果标明 cleared_by=number 与编号",
          cb.get("cleared_by") == "number" and cb.get("bp_number") == 3, str(cb)[:220])

    # 解析不出编号时回退按地址
    client.list_breakpoints_real = lambda *a, **k: {"ok": True, "count": 0, "breakpoints": []}
    calls.clear()
    cb2 = client.clear_breakpoint("0x20001234")
    check("B12 解析不出编号时回退按地址清除（保持既有行为）",
          calls and calls[-1] == "BK 0x20001234" and cb2.get("cleared_by") == "expr",
          "%s / %s" % (calls, cb2.get("cleared_by")))
    check("B13 回退路径给出 resolve_note 说明原因",
          bool(cb2.get("resolve_note")), str(cb2)[:220])
    client.exec_command_checked = real_checked

    # ============ C. 工具层 ============
    lb = await call(server, "list_breakpoints", {})
    check("C1 list_breakpoints 增加 real 字段（真实断点表）",
          "real" in lb and lb.get("total") is not None, str(lb)[:260])

    # 真机场景：内部记录了观察点，但 Keil 按地址清不掉 → 工具不能报成功
    # （让 mock 的 BL 解析不出编号，同时窗口报 error 72）
    srv.exec_console_extra = ["*** error 72: invalid item number"]
    wp = await call(server, "set_watchpoint", {"expr": "0x20005000", "access": "write"})
    check("C2 set_watchpoint 可用", wp.get("ok") is True, str(wp)[:220])
    cd = await call(server, "clear_watchpoint", {"bp_id": wp.get("watchpoint_id")})
    check("C3 清不掉时 clear_watchpoint 明确报失败（不再假成功）",
          cd.get("ok") is False, str(cd)[:280])
    check("C4 失败时给出按编号/hard 的排查建议",
          "编号" in (cd.get("diagnosis") or "") or "hard" in (cd.get("diagnosis") or ""),
          str(cd)[:300])
    check("C5 失败时不把内部记录当作已清除",
          cd.get("remaining") == 1, str(cd)[:200])
    srv.exec_console_extra = []

    ca = await call(server, "clear_watchpoints_all_probe", {}) if False else None
    cw = await call(server, "clear_watchpoint", {"bp_id": wp.get("watchpoint_id")})
    check("C6 正常（窗口无报错）时 clear_watchpoint 成功且清空记录",
          cw.get("ok") is True and cw.get("remaining") == 0, str(cw)[:240])

    wk = await call(server, "set_watchpoint", {"expr": "0x20006000", "access": "write"})
    cwa = await call(server, "clear_all_watchpoints", {})
    check("C7 clear_all_watchpoints 返回 real_after 复查真实断点数",
          "real_after" in cwa, str(cwa)[:260])

    # hard 兜底
    wk2 = await call(server, "set_watchpoint", {"expr": "0x20007000", "access": "write"})
    cwh = await call(server, "clear_all_watchpoints", {"hard": True})
    check("C8 hard=true 走 BK * 一次性清空",
          cwh.get("hard") is True and bool(cwh.get("hard_result")), str(cwh)[:260])
    check("C9 hard 结果附 real_after 便于确认真的清干净",
          "real_after" in cwh, str(cwh)[:240])

    b1 = await call(server, "set_breakpoint", {"expr": "0x08000db4"})
    cbh = await call(server, "clear_all_breakpoints", {"hard": True})
    check("C10 clear_all_breakpoints(hard=true) 同样用 BK * 兜底",
          cbh.get("hard") is True and cbh.get("ok") is True, str(cbh)[:260])

    # ============ D. 文档口径 ============
    tools = await server.list_tools()
    tmap = {t.name: (t.description or "") for t in tools}
    check("D1 list_breakpoints 描述不再声称「BL 输出无法回传」",
          "BL" in tmap.get("list_breakpoints", "")
          and "不回传" not in tmap.get("list_breakpoints", ""),
          tmap.get("list_breakpoints", "")[:200])
    check("D2 clear_watchpoint 描述说明按编号清除（error 72）",
          "error 72" in tmap.get("clear_watchpoint", ""), tmap.get("clear_watchpoint", "")[:200])
    check("D3 clear_all_watchpoints 描述含 hard=true 语义",
          "hard" in tmap.get("clear_all_watchpoints", ""), tmap.get("clear_all_watchpoints", "")[:200])

    # ============ E. 窗口级校验不得吞掉命令窗口缓冲 ============
    # 回归点：exec_command_checked 若为做窗口级校验 clear 掉 0x5020 缓冲，
    # 调用方随后 read_console_output 就读不到命令窗口输出了（test_batch9 曾因此失败）。
    client.read_console_output(clear=True)
    client.read_async_messages(clear=True)
    client._cons_seen = 0
    client._msg_seen = 0
    r = client.exec_command_checked("BS 0x08000d00", settle=0.15)
    seen = [str(it.get("text") or "") for it in client.read_console_output(clear=True)]
    check("E1 窗口校验后 read_console_output 仍能读到命令窗口输出",
          any("0x08000d00" in t.lower() for t in seen), str(seen)[:260])
    check("E2 窗口校验自身仍拿到本次命令输出", bool(r.get("console")), str(r)[:200])
    check("E3 返回的 console 不含历史行（游标只取新增）",
          all("0x08000d00" in str(x).lower() for x in (r.get("console") or []))
          and bool(r.get("console")), str(r.get("console"))[:200])
    client.reset_connection(reason="batch20 E4")
    check("E4 reset_connection 后读取游标归零",
          client._cons_seen == 0 and client._msg_seen == 0,
          "cons=%s msg=%s" % (client._cons_seen, client._msg_seen))

    srv.exec_console_extra = []
    srv.stop()

    print("\n==== batch20: %d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
