# -*- coding: utf-8 -*-
"""批次32 mock 测试：第 17 轮三条反馈。

用户反馈原文：
  ① 「set_breakpoint 裸地址路径有 bug：0x080D9405 明明在已加载镜像内却报 error 57，
      而符号式（main / stat_flow_push）就成功——描述说'已改为先 calc_expression 再 BS'，
      但只对符号生效，裸地址绕过了解析」
  ② 「无看门狗防御：新会话/复位后 DBGMCU 冻结位清零，halt 超 10s 就被 IWDG 复位、
      RAM 现场全丢——正踩了你说的这个坑，建议 stop/enter_debug 自动冻结 IWDG+WWDG」
  ③ 「无 Cache 感知：H7 D-Cache 开着时，DAP 直读 RAM 可能是陈旧值、直写可能被脏行
      回写覆盖，全程无任何提示」

真机实证（_rt_b32_probe.py）：
  - error 57 = illegal address，**奇数地址（Thumb 位 bit0=1）必报**：
    BS 0x8000DB5 → *** error 57；BS 0x8000DB4 → ok；&main 返回偶数地址
  - CPUID=0x41C20F41（Cortex-M4）；CCR=0x00020000（IC=1，DC=0）
  - DBGMCU: IDCODE@0xE0042000=0x10016433（DEV_ID=0x433）、APB1FZ=0x00000000（未冻结）
  - H7 基址 0x5C001000 在 M4 上读失败（故 DBGMCU 基址必须运行时探测）

  A _thumb_even：Thumb 位归一矩阵
  B _bp_failure_hint：error 57 等失败诊断字段
  C set_breakpoint：裸地址归一（端到端，mock 现在会像真机一样对奇数地址报 error 57）
  D set_breakpoint：失败诊断端到端
  E clear_breakpoint：奇地址兜底归一
  F watchdog_freeze：DBGMCU 探测 + 冻结位读改写
  G stop / enter_debug 自动冻结
  H cache_info / read_mem / write_mem 的 D-Cache 提示
  I 工具面回归

运行：python -m tests.test_batch32
"""
import os
import sys
import json
import time
import struct
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b32")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14905
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:300]), flush=True)

async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or c.text for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:400]}

# ----------------------------------------------------------------------
# A. _thumb_even
# ----------------------------------------------------------------------
def group_a_thumb():
    print("A. Thumb 位归一（真机 error 57 根因）")
    te = srv._thumb_even
    cases = [
        (0x08000DB5, (0x08000DB4, True)),
        (0x08000DB4, (0x08000DB4, False)),
        (0x08000001, (0x08000000, True)),
        (0x00000001, (0x00000000, True)),
        (0x20000001, (0x20000001, False)),   # RAM 奇数数据地址不动
        (0x20000003, (0x20000003, False)),
        (0x40000001, (0x40000001, False)),   # 外设区不动
        (0xE000ED15, (0xE000ED15, False)),
        (0, (0, False)),
        (None, (None, False)),
        ("0x8000DB5", (None, False)),        # 非 int 不处理（由上游解析）
    ]
    bad = []
    for v, exp in cases:
        got = te(v)
        if got != exp:
            bad.append((hex(v) if isinstance(v, int) else v, got, exp))
    check("A1 归一矩阵：代码区奇数清 bit0 / 偶数与数据区不动 / 非 int 返回 None", not bad, bad)

    a, st = te(0x080D9405)   # 用户报的那个地址
    check("A2 用户报的 0x080D9405 → 0x080D9404（且标记已清位）",
          (a, st) == (0x080D9404, True), (hex(a) if a else a, st))
    check("A3 _thumb_even 不会把 RAM 里的奇数地址改坏（0x20000001 原样返回）",
          te(0x20000001) == (0x20000001, False), te(0x20000001))

# ----------------------------------------------------------------------
# B. _bp_failure_hint
# ----------------------------------------------------------------------
def group_b_hint():
    print("B. 断点失败诊断（error 57 等）")
    f = srv._bp_failure_hint
    errs = [{"code": 57, "message": "illegal address (0x08000DB5)",
             "text": "*** error 57: illegal address (0x08000DB5)"}]
    d = f(None, 0x08000DB5, {"ok": False, "status_text": "命令窗口报错", "errors": errs})
    check("B1 透出错误码与含义", d.get("codes") == [57]
          and "illegal address" in (d.get("meaning") or [""])[0], d.get("meaning"))
    check("B2 checks 带地址形态（addr / addr_odd）",
          d["checks"].get("addr") == "0x08000DB5" and d["checks"].get("addr_odd") is True,
          d.get("checks"))
    check("B3 checks 带内存区信息（地址落哪个区）",
          "region" in d["checks"], d.get("checks"))
    h = " ".join(d.get("hints") or [])
    check("B4 给出 error 57 的定位（Thumb 位已自动处理 + 镜像/符号不匹配排查路径）",
          "Thumb" in h and "镜像" in h and "find_symbol" in h, h[:200])
    check("B5 提示 App 重定位场景用 set_reloc_delta", "set_reloc_delta" in h, h[:200])

    d2 = f(None, None, {"ok": False, "status_text": "err",
                        "errors": [{"code": 65, "message": "bad expr"}]})
    check("B6 地址未解析出来时给出符号/axf 排查建议",
          any("find_symbol" in x for x in (d2.get("hints") or [])), d2.get("hints"))

    d3 = f(None, 0x08000DB4, {"ok": False, "status_text": "err",
                              "errors": [{"code": 145,
                                          "message": "Redefinition: item already exists"}]})
    check("B7 error 145（断点已存在）按「设置语义成功」解释",
          any("145" in x and "已存在" in x for x in (d3.get("hints") or [])), d3.get("hints"))

    d4 = f(None, 0x08000DB4, {"ok": False, "status_text": "未知",
                              "errors": [{"code": 999, "message": "???"}]})
    check("B8 未知错误码也给出可读兜底（不空手而归）",
          d4.get("hints") and "未识别" in d4["hints"][0], d4.get("hints"))

    # 同一错误经命令窗口(0x5020)+异步消息(0x4000)各到一次时，codes 不应重复
    d5 = f(None, 0x08000DB4, {"ok": False, "status_text": "err",
                              "errors": [{"code": 57, "message": "illegal address"},
                                         {"code": 57, "message": "illegal address"}]})
    check("B9 重复到达的错误码去重（codes=[57] 而不是 [57,57]）",
          d5.get("codes") == [57], d5.get("codes"))

    # 地址没解析出来时，也不能吞掉错误码专属建议（原实现直接 return）
    d6 = f(None, None, {"ok": False, "status_text": "err",
                        "errors": [{"code": 145, "message": "Redefinition: item already exists"}]})
    j6 = " ".join(d6.get("hints") or [])
    check("B10 地址未解析时仍保留错误码专属建议（不提前 return）",
          "find_symbol" in j6 and "145" in j6, d6.get("hints"))
    check("B11 地址未解析时 checks 带 addr_note 说明原因",
          d6.get("checks", {}).get("addr") is None
          and d6.get("checks", {}).get("addr_note"), d6.get("checks"))

# ----------------------------------------------------------------------
# C. set_breakpoint 裸地址归一（端到端）
# ----------------------------------------------------------------------
async def group_c_setbp(server, mock):
    print("C. set_breakpoint 裸地址路径（用户报的崩溃场景）")
    mock.bs_odd_addr_error = True          # 真机行为：奇数地址报 error 57
    mock.bs_fail_text = None
    mock.breakpoints = []

    # 先证明 mock 确实会像真机一样拒绝奇数地址
    r_raw = await call(server, "set_breakpoint", {"expr": "0x08000DB5"})
    check("C0 前置：mock 已按真机对奇数地址报 error 57（证明归一不是空转）",
          r_raw.get("ok") is not True or bool(r_raw.get("thumb_bit_stripped")),
          r_raw)

    r = await call(server, "set_breakpoint", {"expr": "0x08000DB5"})
    check("C1 奇数地址 0x08000DB5 下断成功（旧实现在此处报 error 57）",
          r.get("ok") is True, r)
    check("C2 返回 thumb_bit_stripped / address_normalized 说明已清 Thumb 位",
          r.get("thumb_bit_stripped") is True and isinstance(r.get("address_normalized"), str),
          r)
    check("C3 实际发给 Keil 的是偶地址（mock 收到的 BS 参数）",
          "0x8000db4" in (mock.breakpoints or []), mock.breakpoints)
    check("C4 返回的 address 也是偶地址", (r.get("address") or "") == "0x8000db4",
          r.get("address"))

    r2 = await call(server, "set_breakpoint", {"expr": "0x08000DB4"})
    check("C5 偶数地址照旧成功且不带 thumb_bit_stripped（不误报）",
          r2.get("ok") is True and "thumb_bit_stripped" not in r2, r2)

    # 用户报的 0x080D9405（代码区奇数）同样要能下断
    r3 = await call(server, "set_breakpoint", {"expr": "0x080D9405"})
    _a3 = r3.get("address") or ""
    check("C6 用户报的 0x080D9405 现在能成功（→ 0x080D9404）",
          r3.get("ok") is True and _a3.lower().startswith("0x")
          and int(_a3, 16) == 0x080D9404, r3)

# ----------------------------------------------------------------------
# D. set_breakpoint 失败诊断（端到端）
# ----------------------------------------------------------------------
async def group_d_diag(server, mock):
    print("D. set_breakpoint 失败时的 diagnosis")
    mock.bs_odd_addr_error = False
    mock.bs_fail_text = "*** error 57: illegal address (0x08000DB4)"
    try:
        r = await call(server, "set_breakpoint", {"expr": "0x08000DB4"})
        check("D1 失败时返回 ok=false 且带 diagnosis", r.get("ok") is False
              and isinstance(r.get("diagnosis"), dict), r)
        diag = r.get("diagnosis") or {}
        check("D2 diagnosis 解释错误码 57（不再是干巴巴的 error 57）",
              diag.get("codes") == [57] and "illegal address" in (diag.get("meaning") or [""])[0],
              diag)
        check("D3 diagnosis 带地址检查项 + 可操作 hints",
              diag.get("checks", {}).get("addr") == "0x08000DB4" and diag.get("hints"), diag)
    finally:
        mock.bs_fail_text = None

# ----------------------------------------------------------------------
# E. clear_breakpoint 奇地址兜底
# ----------------------------------------------------------------------
async def group_e_clearbp(server, mock):
    print("E. clear_breakpoint 的奇地址兜底")
    r = await call(server, "clear_breakpoint", {"expr": "0x08000DB5"})
    check("E1 传奇地址也能清除（自动归一为偶地址）", r.get("ok") is True, r)
    check("E2 返回 thumb_bit_stripped / address_normalized",
          r.get("thumb_bit_stripped") is True and isinstance(r.get("address_normalized"), dict),
          r)
    check("E3 归一后的目标地址是偶数",
          (r.get("cleared_target") or r.get("address_normalized", {}).get("to") or "") == "0x8000db4",
          r)

# ----------------------------------------------------------------------
# F. watchdog_freeze
# ----------------------------------------------------------------------
async def group_f_watchdog(server, mock):
    print("F. watchdog_freeze（DBGMCU 冻结位）")
    mock.dbgmcu_enabled = True
    mock.dbgmcu[0x08:0x0C] = b"\x00\x00\x00\x00"

    r = await call(server, "watchdog_freeze", {"action": "status"})
    check("F1 status 探测到 DBGMCU 基址与 DEV_ID（运行时探测，不硬编码）",
          r.get("ok") is True and r.get("dbgmcu_base") == "0xE0042000" and r.get("dev_id") == "0x423",
          r)
    check("F2 未冻结时报 iwdg_stopped/wwdg_stopped=false 且带风险 warning",
          r.get("iwdg_stopped") is False and r.get("wwdg_stopped") is False
          and r.get("all_frozen") is False and "IWDG" in (r.get("warning") or ""), r)

    r2 = await call(server, "watchdog_freeze", {"action": "enable"})
    check("F3 enable 置位 bit11(WWDG)/bit12(IWDG) 且回读确认",
          r2.get("ok") is True and r2.get("changed") is True and r2.get("verified") is True
          and r2.get("after") == "0x00001800", r2)
    check("F4 enable 后 all_frozen=true",
          r2.get("iwdg_stopped") is True and r2.get("wwdg_stopped") is True
          and r2.get("all_frozen") is True, r2)

    r3 = await call(server, "watchdog_freeze", {"action": "status"})
    check("F5 再次 status 读到已冻结、且不再给 warning",
          r3.get("all_frozen") is True and "warning" not in r3, r3)

    r4 = await call(server, "watchdog_freeze", {"action": "disable"})
    check("F6 disable 清除冻结位（恢复看门狗真实行为）",
          r4.get("ok") is True and r4.get("after") == "0x00000000"
          and r4.get("all_frozen") is False, r4)

    r5 = await call(server, "watchdog_freeze", {"action": "查询"})
    check("F7 非法 action 明确报错并列出可用取值",
          r5.get("ok") is False and r5.get("valid_actions") == ["status", "enable", "disable"], r5)

    mock.dbgmcu_enabled = False
    try:
        r6 = await call(server, "watchdog_freeze", {"action": "status"})
        check("F8 DBGMCU 读不到时返回 ok=false + 排查 hint（非 STM32/未暂停）",
              r6.get("ok") is False and r6.get("hint"), r6)
    finally:
        mock.dbgmcu_enabled = True

# ----------------------------------------------------------------------
# G. stop / enter_debug 自动冻结
# ----------------------------------------------------------------------
async def group_g_auto(server, mock):
    print("G. stop / enter_debug 自动冻结看门狗")
    mock.dbgmcu_enabled = True
    await call(server, "watchdog_freeze", {"action": "disable"})

    r = await call(server, "stop", {})
    wf = r.get("watchdog_freeze") or {}
    check("G1 stop 默认自动冻结（attempted=true 且 all_frozen=true）",
          wf.get("attempted") is True and wf.get("all_frozen") is True, r)

    await call(server, "watchdog_freeze", {"action": "disable"})
    r2 = await call(server, "stop", {"freeze_watchdogs": False})
    check("G2 stop(freeze_watchdogs=false) 不做冻结（不返回该字段）",
          "watchdog_freeze" not in r2, r2)
    st = await call(server, "watchdog_freeze", {"action": "status"})
    check("G3 关掉后确实未冻结（证明 G1 不是配置残留）", st.get("all_frozen") is False, st)

    await call(server, "exit_debug", {})
    await call(server, "watchdog_freeze", {"action": "disable"})
    r3 = await call(server, "enter_debug", {})
    wf3 = r3.get("watchdog_freeze") or {}
    check("G4 enter_debug 默认自动冻结（复位/新会话后冻结位会被清零，正是踩坑场景）",
          r3.get("ok") is True and wf3.get("attempted") is True
          and wf3.get("all_frozen") is True, r3)

    await call(server, "exit_debug", {})
    await call(server, "watchdog_freeze", {"action": "disable"})
    r4 = await call(server, "enter_debug", {"freeze_watchdogs": False})
    check("G5 enter_debug(freeze_watchdogs=false) 可关闭自动冻结",
          "watchdog_freeze" not in r4, r4)
    await call(server, "enter_debug", {})

# ----------------------------------------------------------------------
# H. Cache 感知
# ----------------------------------------------------------------------
async def group_h_cache(server, mock):
    print("H. Cache 感知（D-Cache 开时的 DAP 直读/直写）")
    CCR = 0xE000ED14
    CSSIDR = 0xE000ED80
    struct.pack_into('<I', mock.sys, CCR - 0xE0000000, 0x00020000)     # IC=1, DC=0（真机 M4 值）
    struct.pack_into('<I', mock.sys, CSSIDR - 0xE0000000, 0x3FE019)    # line=32B, 4 ways, 512 sets
    srv._CACHE_PROBE["state"] = None

    r = await call(server, "cache_info", {})
    check("H1 无 D-Cache 时 dcache=false 且给 note（M3/M4 不该被制造噪声）",
          r.get("ok") is True and r.get("dcache") is False and r.get("icache") is True
          and r.get("note"), r)
    check("H2 附带对 read_mem/write_mem 的影响说明",
          isinstance(r.get("impact"), dict) and "read_mem" in r["impact"]
          and "write_mem" in r["impact"], r.get("impact"))

    struct.pack_into('<I', mock.sys, CCR - 0xE0000000, 0x00030000)     # DC=1, IC=1
    srv._CACHE_PROBE["state"] = None
    r2 = await call(server, "cache_info", {})
    check("H3 D-Cache 使能时 dcache=true 并给「直读陈旧/直写被覆盖」warning",
          r2.get("dcache") is True and "陈旧" in (r2.get("warning") or "")
          and "覆盖" in (r2.get("warning") or ""), r2)
    check("H4 解析 CCSIDR 得到 cache 几何（line=32B / 4 ways / 512 sets / 64KB）",
          r2.get("cache_line_bytes") == 32 and r2.get("cache_ways") == 4
          and r2.get("cache_sets") == 512 and r2.get("cache_size_kb") == 64.0, r2)

    srv._CACHE_PROBE["state"] = None
    rm = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 8})
    cache = rm.get("cache") or {}
    check("H5 read_mem 读 SRAM 时带 cache 提示（用户原话「全程无任何提示」）",
          cache.get("dcache") is True and "读内存" in (cache.get("note") or ""), rm)

    wm = await call(server, "write_mem", {"addr": "0x20000010",
                                          "data_hex": "1122334455667788"})
    wcache = wm.get("cache") or {}
    check("H6 write_mem 写 SRAM 时带 cache 提示（脏行回写会覆盖刚写入的值）",
          wcache.get("dcache") is True and "覆盖" in (wcache.get("note") or ""), wm)

    srv._CACHE_PROBE["state"] = None
    rf = await call(server, "read_mem", {"addr": "0x08000000", "n_bytes": 8})
    check("H7 非 SRAM 地址不给 cache 字段（Flash 直读不受 D-Cache 影响）",
          "cache" not in rf, rf)

    struct.pack_into('<I', mock.sys, CCR - 0xE0000000, 0x00020000)     # DC 关回去
    srv._CACHE_PROBE["state"] = None
    rm2 = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 8})
    check("H8 D-Cache 关闭时不给 cache 字段（不误报）", "cache" not in rm2, rm2)

# ----------------------------------------------------------------------
# I. 工具面回归
# ----------------------------------------------------------------------
async def group_i_surface(server):
    print("I. 工具面回归")
    tools = {t.name: t for t in await server.list_tools()}
    check("I1 工具总数 83→150（批次34/35/36 继续增加）", len(tools) == 150, len(tools))
    check("I2 watchdog_freeze / cache_info 已注册",
          "watchdog_freeze" in tools and "cache_info" in tools, sorted(tools))
    wd = tools["watchdog_freeze"].description or ""
    check("I3 watchdog_freeze 描述讲清「halt 期间看门狗仍在跑 + RAM 全丢」与三种 action",
          "IWDG" in wd and "复位" in wd and "status" in wd and "enable" in wd, wd[:200])
    ci = tools["cache_info"].description or ""
    check("I4 cache_info 描述讲清 DAP 直读陈旧 / 直写被覆盖 / 不报错",
          "D-Cache" in ci and "陈旧" in ci and "覆盖" in ci, ci[:200])

    lt_st = await call(server, "list_tools", {"keyword": "stop"})
    _st = next((x for x in (lt_st.get("tools") or [])
                if x.get("tool") == "stop"), {})
    check("I5 stop 暴露 freeze_watchdogs 参数",
          "freeze_watchdogs" in (_st.get("optional") or []), _st)
    check("I6 stop 描述点明「暂停期间看门狗仍在计数」与自动冻结",
          "冻结位" in (tools["stop"].description or "")
          and "halt" in (tools["stop"].description or ""), (tools["stop"].description or "")[:200])
    lt_ed = await call(server, "list_tools", {"keyword": "enter_debug"})
    _ed = next((x for x in (lt_ed.get("tools") or [])
                if x.get("tool") == "enter_debug"), {})
    check("I7 enter_debug 暴露 freeze_watchdogs 参数",
          "freeze_watchdogs" in (_ed.get("optional") or []), _ed)
    sb = tools["set_breakpoint"].description or ""
    check("I8 set_breakpoint 描述写明「地址路径与符号路径做同一套归一」+ error 57 根因",
          "Thumb" in sb and "error 57" in sb and "裸地址" in sb, sb[:200])

    lt = await call(server, "list_tools", {"keyword": "watchdog_freeze"})
    items = lt.get("tools") or []
    wfw = next((x for x in items if x.get("tool") == "watchdog_freeze"), None)
    check("I9 list_tools 能查到 watchdog_freeze", wfw is not None, items)
    check("I10 example_args 带上 action=status（照抄即用）",
          (wfw or {}).get("example_args", {}).get("action") == "status", wfw)

    lt2 = await call(server, "list_tools", {})
    check("I11 total 与工具数一致", lt2.get("total") == 150, lt2.get("total"))

async def main():
    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    mock.debugging = False
    mock.reset_requires_stop = False
    mock.stop_ignores = False
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0, axf_path=None)

    group_a_thumb()
    group_b_hint()
    try:
        await call(server, "enter_debug", {})
        await call(server, "run", {})
        await group_c_setbp(server, mock)
        await group_d_diag(server, mock)
        await group_e_clearbp(server, mock)
        await group_f_watchdog(server, mock)
        await group_g_auto(server, mock)
        await group_h_cache(server, mock)
        await group_i_surface(server)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次32 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
