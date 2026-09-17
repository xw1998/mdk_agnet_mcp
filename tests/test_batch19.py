# -*- coding: utf-8 -*-
"""批次19 mock 测试：全功能真机回归暴露的两处体验缺陷修复。

覆盖：
  A wait_breakpoint 在「目标已停止但 PC 不在候选断点」时不再静默 hit=false，
    而是给出可操作 note（先 run 再等 / 核对断点与符号漂移）；命中时不应带 note。
  B enter_debug 在目标已处于调试态（status=10 正在调试）时不再报失败，
    而是确认就绪后返回 ok=true + already_in_debug=true + note；
    但要严格区分「真的是已在调试态」与「其他失败」——后者仍如实报失败。

运行：python -m tests.test_batch19
"""
import sys, os, json, time, asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import create_server, _get_client
from mdkdebug import uvsock

PORT = 14891
PASS, FAIL = [], []


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

    # ================= A. wait_breakpoint 未命中时的引导 note =================
    srv.running = False
    regs = client.read_cpu_registers_stable(retries=10, delay=0.02)
    pc = regs.get("pc")
    check("A1 前置：停止态读到可信 PC", isinstance(pc, int) and pc != 0x08001234,
          "pc=%s" % regs.get("pc"))

    wb = client.wait_breakpoint([0x08001234], timeout_s=1.0, poll=0.02)
    note = wb.get("note") or ""
    check("A2 目标已停止但 PC 不在候选地址 -> 不报命中但仍 ok=True",
          wb.get("ok") is True and wb.get("hit") is False and wb.get("stopped") is True,
          str(wb)[:220])
    check("A3 此时带 note（不再静默）", bool(note), str(wb)[:220])
    check("A4 note 点明「目标当前已停止」与「不在候选地址」",
          "已停止" in note and "不在候选断点地址" in note, note[:200])
    check("A5 note 给出「先 run 再 wait」的下一步动作",
          "先 run" in note and "wait_breakpoint" in note, note[:200])
    check("A6 note 给出核对断点 / 符号漂移的排查建议",
          "list_breakpoints" in note and "符号漂移" in note, note[:220])
    cands = wb.get("candidates") or []
    check("A7 note 里带上实际 PC 与候选断点地址",
          bool(wb.get("pc")) and (wb.get("pc") or "") in note
          and bool(cands) and all(c in note for c in cands), note[:220])
    check("A8 未命中时不误报 hit_address/hit_count",
          "hit_address" not in wb and "hit_count" not in wb, str(wb)[:200])

    # 命中时不应带 note（避免噪声）
    client._bp_hits = {}
    wb_hit = client.wait_breakpoint([pc], timeout_s=1.0, poll=0.02)
    check("A9 命中时正常返回 hit_address/hit_count 且不带 note",
          wb_hit.get("hit") is True and wb_hit.get("hit_address") == hex(pc)
          and not wb_hit.get("note"), str(wb_hit)[:220])

    # 未给候选断点时「停下即命中」的既有语义不受影响
    wb_none = client.wait_breakpoint([], timeout_s=1.0, poll=0.02)
    check("A10 未给候选断点时仍是「停下即命中」（既有语义不变）",
          wb_none.get("hit") is True and wb_none.get("hit_address") == hex(pc)
          and not wb_none.get("note"), str(wb_none)[:220])

    # 工具层透出 note
    tw = await call(server, "wait_breakpoint", {"address": "0x08001234", "timeout_s": 1.0})
    check("A11 wait_breakpoint 工具层把 note 透出给调用方",
          tw.get("hit") is False and bool(tw.get("note")), str(tw)[:220])
    check("A12 工具层 note 与 client 层文案一致（含 list_breakpoints）",
          "list_breakpoints" in (tw.get("note") or ""), str(tw)[:200])

    # ================= B. enter_debug 识别「已在调试态」 =================
    real_enter = client.enter_debug
    real_status = client.get_status

    # B1: status=10 且确认确实在调试态 -> 视为成功
    client.enter_debug = lambda *a, **k: {
        "ok": False, "status": uvsock.UV_STATUS_DEBUGGING,
        "status_text": "正在调试", "cmd": "UV_DBG_ENTER"}
    client.get_status = lambda *a, **k: {
        "ok": True, "status": 0, "debugging": True, "running": False,
        "status_text": "已停止"}
    r = await call(server, "enter_debug", {})
    check("B1 status=10 且确认在调试态 -> ok=true",
          r.get("ok") is True, str(r)[:260])
    check("B2 带 already_in_debug=true 与 ready=true",
          r.get("already_in_debug") is True and r.get("ready") is True, str(r)[:260])
    check("B3 status_text 改写为「已在调试态」", r.get("status_text") == "已在调试态",
          str(r)[:220])
    check("B4 给出 note 说明无需重新进入 / 如何重开",
          "已处于调试态" in (r.get("note") or "") and "exit_debug" in (r.get("note") or ""),
          str(r)[:260])
    check("B5 此时不再给 diagnosis（不误导为失败）",
          not r.get("diagnosis"), str(r)[:260])

    # B6: status=10 但复查并未在调试态 -> 仍如实报失败
    client.get_status = lambda *a, **k: {
        "ok": False, "status": 6, "debugging": False, "running": None,
        "status_text": "未处于调试状态"}
    r6 = await call(server, "enter_debug", {})
    check("B6 status=10 但复查未在调试态 -> 仍报失败",
          r6.get("ok") is False and bool(r6.get("diagnosis")), str(r6)[:260])
    check("B7 该分支不误加 already_in_debug", not r6.get("already_in_debug"),
          str(r6)[:220])

    # B8: 其他失败码 + 复查在调试态 -> 不能据此判成功（严格只认 status=10）
    client.enter_debug = lambda *a, **k: {
        "ok": False, "status": uvsock.UV_STATUS_FAILED,
        "status_text": "失败", "cmd": "UV_DBG_ENTER"}
    client.get_status = lambda *a, **k: {
        "ok": True, "status": 0, "debugging": True, "running": False,
        "status_text": "已停止"}
    r8 = await call(server, "enter_debug", {})
    check("B8 其他失败码不会被伪装成成功（只认 status=10）",
          r8.get("ok") is False and bool(r8.get("diagnosis")), str(r8)[:260])

    # B9: 复查 get_status 抛异常 -> 不能崩，如实报失败
    def _boom(*a, **k):
        raise RuntimeError("channel dead")
    client.get_status = _boom
    r9 = await call(server, "enter_debug", {})
    check("B9 复查 get_status 抛异常时不崩、仍如实报失败",
          r9.get("ok") is False and bool(r9.get("diagnosis")), str(r9)[:260])

    # B10: 正常成功路径不受影响（无 already_in_debug 噪声）
    client.enter_debug = lambda *a, **k: {
        "ok": True, "status": 0, "ready": True, "ready_waited_ms": 672,
        "cmd": "UV_DBG_ENTER"}
    client.get_status = real_status
    r10 = await call(server, "enter_debug", {})
    check("B10 正常成功路径仍 ok=true 且不带 already_in_debug",
          r10.get("ok") is True and not r10.get("already_in_debug")
          and not r10.get("diagnosis"), str(r10)[:260])

    # 恢复真实方法，避免影响后续
    client.enter_debug = real_enter
    client.get_status = real_status

    # B11: 工具描述里写清了这套语义（免得 AI 只看名字猜）
    tools = await server.list_tools()
    desc = ""
    for t in tools:
        if t.name == "enter_debug":
            desc = t.description or ""
            break
    check("B11 enter_debug description 说明 status=10 不报失败",
          "already_in_debug" in desc and "status=10" in desc, desc[:200])

    srv.stop()

    print("\n==== batch19: %d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
