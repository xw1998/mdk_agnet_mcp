# -*- coding: utf-8 -*-
"""批次23 mock 测试：wait_breakpoint 只认「等待期间新发生的停止」/ read_peripheral 兼容数组参数。

对应第 8 轮反馈的两个问题：
  1. read_peripheral 的 regs 只接受字符串，传数组会崩（'list' object has no attribute 'replace'）
  2. wait_breakpoint 在目标本来就处于停止态时误报命中——实测 run_timeout 停在某行后紧接着调
     本工具，立刻返回 hit=true 且 PC 与上一次完全相同，把「进来时已停」当成了「等到了命中」

运行：python -m tests.test_batch23
"""
import sys, os, json, time, asyncio, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import create_server, _get_client, _watchpoints, _breakpoints

PORT = 14895
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail), flush=True)


async def call(server, name, args=None):
    res = await server.call_tool(name, args or {})
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}


def set_pc(srv, pc):
    srv.reg_map["__currentPC()"] = pc
    srv.reg_map["PC"] = pc
    srv.reg_map["R15"] = pc


def arm_stop_after(srv, pc):
    """模拟「目标运行中、随后停在该 PC」：下一次 STATUS 查询仍报运行态，再下一次转停。"""
    set_pc(srv, pc)
    srv.running = True
    srv.auto_stop_reads = 1
    srv.auto_stop_pc = pc


BP_ADDR = 0x08000DB4
EXEC_BP = {"number": 0, "kind": "exec", "address": "0x08000DB4",
           "expr": "..\\main.c\\77", "count": 1, "enabled": True}
# 真机 BL 里数据观察点行的 expr 就是地址（不是符号名）——按符号名 BK 会清不掉
WATCH_BP = {"number": 2, "kind": "access", "address": "0x20000000",
            "expr": "0x20000000", "count": 1, "enabled": True}


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
    client = _get_client()
    await call(server, "enter_debug", {})

    # ============ A. wait_breakpoint 不接受「进来时就已经停着」的旧停止 ============
    print("A. wait_breakpoint 只认等待期间新发生的停止")
    srv.bl_table = [dict(EXEC_BP)]
    client._bp_hits = {}

    # A1: 用户反馈的原始场景——目标已经停在候选断点地址上，直接调 wait_breakpoint
    #     （旧实现会立刻返回 hit=true、PC 与上一次完全相同）
    set_pc(srv, BP_ADDR)
    srv.running = False
    t0 = time.time()
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    dt = time.time() - t0
    check("A1 目标进来就停着 → hit=false（不再误报命中）",
          r.get("hit") is False, json.dumps(r, ensure_ascii=False)[:260])
    check("A1b 明确标注 stop_is_new=false / ran_during_wait=false",
          r.get("stop_is_new") is False and r.get("ran_during_wait") is False,
          json.dumps({k: r.get(k) for k in ("stop_is_new", "ran_during_wait")}, ensure_ascii=False))
    check("A1c note 说明「目标在等待期间未曾运行」",
          "未曾运行" in (r.get("note") or ""), str(r.get("note"))[:220])
    check("A1d 未命中时不返回 hit_address/hit_count（不制造假数据）",
          "hit_address" not in r and "hit_count" not in r, str(r)[:220])
    check("A1e 仍报 ok=true/stopped=true（调用本身成功，只是没等到命中）",
          r.get("ok") is True and r.get("stopped") is True, str(r)[:200])
    check("A1f 宽限窗口不拖长：结论在 1.5s 内给出", dt < 1.5, "耗时 %.2fs" % dt)

    # A2: 同一场景但目标确实跑过再停 → 正常判命中
    client._bp_hits = {}
    arm_stop_after(srv, BP_ADDR)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A2 目标先运行再停在断点 → hit=true/hit_kind=code",
          r.get("hit") is True and r.get("hit_kind") == "code",
          json.dumps(r, ensure_ascii=False)[:260])
    check("A2b ran_during_wait=true / stop_is_new=true",
          r.get("ran_during_wait") is True and r.get("stop_is_new") is True,
          json.dumps({k: r.get(k) for k in ("ran_during_wait", "stop_is_new")}, ensure_ascii=False))

    # A3: 进来就停着、且 PC 不在候选上 → 既有的「未命中引导 note」仍要有
    set_pc(srv, 0x0800AAAA)
    srv.running = False
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    note = r.get("note") or ""
    check("A3 未命中仍给出候选与 PC（note 里带地址与排查建议）",
          r.get("hit") is False and "0x8000db4" in note and "0x800aaaa" in note,
          note[:240])
    check("A3b note 给出「先 run」的下一步与 list_breakpoints 排查建议",
          "先 run" in note and "list_breakpoints" in note, note[:240])

    # A4: 进来时停着，但 PC 相对调用时移动过（run 后立刻命中、宽限窗口没抓到运行态）
    #     → 这属于新发生的停止，必须照常判命中（避免误杀）
    set_pc(srv, 0x0800AAAA)
    srv.running = False
    def _move_pc():
        set_pc(srv, BP_ADDR)
    th = threading.Timer(0.1, _move_pc)
    th.daemon = True
    th.start()
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0, "address": "0x08000DB4"})
    check("A4 PC 相对调用时已移动 → 仍判为新停止并命中（不误杀）",
          r.get("hit") is True and r.get("stop_is_new") is True,
          json.dumps(r, ensure_ascii=False)[:260])

    # A5: 目标是运行态时停止 → 正常判定（既有时序不变）
    client._bp_hits = {}
    arm_stop_after(srv, BP_ADDR)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A5 运行中等到停止 → hit=true 且 ran_during_wait=true",
          r.get("hit") is True and r.get("ran_during_wait") is True,
          json.dumps(r, ensure_ascii=False)[:220])

    # A6: 短超时 + 目标已停 → 返回「未曾运行」而不是把责任推给超时
    set_pc(srv, BP_ADDR)
    srv.running = False
    r = await call(server, "wait_breakpoint", {"timeout_s": 0.2, "address": "0x08000DB4"})
    check("A6 短超时下仍给出「未曾运行」结论（不是超时错误）",
          r.get("hit") is False and "未曾运行" in (r.get("note") or ""),
          json.dumps(r, ensure_ascii=False)[:220])

    srv.bl_table = None
    srv.running = False

    # ============ C. 真机路径：run_timeout 之后误报命中 / 刚 run 就命中断点 ============
    print("C. 真机路径复现（用户实测的两个时序）")
    srv.bl_table = [dict(EXEC_BP)]
    client._bp_hits = {}
    client._exec_ts = 0.0
    client._last_stop_obs_ts = 0.0

    # C1: 用户实测时序——run_timeout 把目标停在某行（PC 就是断点地址），紧接着调
    #     wait_breakpoint：旧实现立刻返回 hit=true 且 PC 与上一次完全相同。
    set_pc(srv, BP_ADDR)
    srv.running = False
    rt = await call(server, "run_timeout", {"timeout_ms": 120})
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("C1 run_timeout 停在断点地址后再 wait → 不再误报命中",
          r.get("hit") is False, json.dumps(r, ensure_ascii=False)[:260])
    check("C1b new_stop_basis=not_new（明确告诉调用方这是旧停止）",
          r.get("new_stop_basis") == "not_new" and r.get("stop_is_new") is False,
          json.dumps({k: r.get(k) for k in ("new_stop_basis", "stop_is_new")}, ensure_ascii=False))
    check("C1c 不累计命中次数（没命中就不该计数）",
          client.breakpoint_hits() == {}, str(client.breakpoint_hits()))

    # C2: 刚发过 run、目标在一次往返内就停住 → 属于新停止，照常判命中（run_issued 证据）
    set_pc(srv, BP_ADDR)
    srv.running = False
    await call(server, "run", {})
    srv.auto_stop_reads = 0      # 下一次状态查询即报「已停止」，模拟来不及观察到运行态
    srv.auto_stop_pc = BP_ADDR
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0, "address": "0x08000DB4"})
    check("C2 run 已发出、没抓到运行态 → 仍判为新停止并命中",
          r.get("hit") is True and r.get("stop_is_new") is True,
          json.dumps(r, ensure_ascii=False)[:260])
    check("C2b new_stop_basis=run_issued（依据可追溯）",
          r.get("new_stop_basis") == "run_issued",
          str(r.get("new_stop_basis")))

    srv.bl_table = None
    srv.running = False

    # ============ B. read_peripheral 参数兼容数组 ============
    print("B. read_peripheral 的 regs/fields 兼容字符串数组")
    r_str = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "MODER,ODR"})
    r_lst = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": ["MODER", "ODR"]})
    check("B1 regs 传数组不再崩（用户反馈的 'list' object has no attribute 'replace'）",
          r_lst.get("ok") is True and not r_lst.get("error"),
          json.dumps(r_lst, ensure_ascii=False)[:220])
    check("B2 数组写法与字符串写法结果一致",
          r_lst.get("reg_count") == r_str.get("reg_count") == 2
          and sorted(x.get("reg") for x in r_lst.get("regs") or [])
          == sorted(x.get("reg") for x in r_str.get("regs") or []),
          "str=%s list=%s" % (r_str.get("reg_count"), r_lst.get("reg_count")))
    check("B3 reg_filter 回显数组里的名字",
          [x.upper() for x in (r_lst.get("reg_filter") or [])] == ["MODER", "ODR"],
          str(r_lst.get("reg_filter")))

    r_mix = await call(server, "read_peripheral", {"periph": "GPIOC",
                                                   "regs": ["GPIOC_MODER", "ODR"]})
    check("B4 数组里混用全名/裸名同样命中",
          r_mix.get("ok") is True and r_mix.get("reg_count") == 2
          and not r_mix.get("not_found_regs"),
          json.dumps(r_mix, ensure_ascii=False)[:220])

    r_tup = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": ("MODER",)})
    check("B5 元组写法也可用（reg_count=1）",
          r_tup.get("ok") is True and r_tup.get("reg_count") == 1,
          json.dumps(r_tup, ensure_ascii=False)[:200])

    r_sp = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "MODER ODR"})
    check("B6 空格分隔也兼容（顺手放宽）",
          r_sp.get("ok") is True and r_sp.get("reg_count") == 2,
          json.dumps(r_sp, ensure_ascii=False)[:200])

    r_off = await call(server, "read_peripheral", {"periph": "GPIOC",
                                                   "regs": ["MODER"], "fields": ["off"]})
    check("B7 fields 传数组等价于字符串（不输出位域）",
          r_off.get("ok") is True and r_off.get("fields_mode") == "off"
          and "fields" not in ((r_off.get("regs") or [{}])[0]),
          json.dumps(r_off, ensure_ascii=False)[:220])

    r_miss = await call(server, "read_peripheral", {"periph": "GPIOC",
                                                    "regs": ["MODER", "NOPE"]})
    check("B8 数组写法下 not_found_regs 仍如实列出拼错的寄存器",
          r_miss.get("ok") is True and (r_miss.get("not_found_regs") or []) == ["NOPE"],
          json.dumps(r_miss, ensure_ascii=False)[:220])

    # ============ D. 按符号名清数据断点（全量真机回归暴露） ============
    print("D. 按符号名清除数据/代码断点时改用记录里的地址")
    srv.bl_table = [dict(WATCH_BP)]
    _watchpoints[:] = [dict(id=7, expr="test_array", address="0x20000000",
                            access="read", count=1)]
    r = await call(server, "clear_watchpoint", {"expr": "test_array"})
    check("D1 数据断点按符号名清除成功（不再 BK test_array 报 error 72）",
          r.get("ok") is True, json.dumps(r, ensure_ascii=False)[:300])
    check("D1b 实际按 Keil 编号清除（cleared_by=number）",
          r.get("cleared_by") == "number", str(r.get("cleared_by")))
    check("D1c resolve_note 说明符号名已换成记录地址",
          "0x20000000" in (r.get("resolve_note") or ""),
          str(r.get("resolve_note"))[:200])
    check("D1d 内部观察点记录已回收", _watchpoints == [], str(_watchpoints))

    srv.bl_table = [dict(EXEC_BP)]
    _breakpoints[:] = [dict(id=9, expr="main", address="0x08000DB4")]
    r = await call(server, "clear_breakpoint", {"expr": "main"})
    check("D2 代码断点按符号名清除也走编号路径（实际下发 BK <编号>）",
          r.get("ok") is True and r.get("command") == "BK 0"
          and r.get("cleared_target") == "0x08000DB4",
          json.dumps(r, ensure_ascii=False)[:300])
    check("D2b resolve_note 记录了地址替换",
          "0x08000db4" in (r.get("resolve_note") or "").lower(),
          str(r.get("resolve_note"))[:200])
    _breakpoints[:] = []
    srv.bl_table = None

    print("\n批次23 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)), flush=True)
    if FAIL:
        print("失败项:", FAIL, flush=True)
    srv.stop()


if __name__ == "__main__":
    asyncio.run(main())
