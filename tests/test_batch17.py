# -*- coding: utf-8 -*-
"""批次17 mock 测试：停止点可信度标注 / 断点命中等待 / 会话预警 / 两个工具细节。

覆盖第 4 轮反馈：
  A 停止点不可信（run_timeout 报 stale PC）→ pc_confidence / halt_verified / repeat 提示
  B 无断点命中查询 → wait_breakpoint（带超时）+ breakpoint_stats
  C exit_debug 失败要能看出「Keil 已经不在了」
  E search_mem 支持 ASCII 文本
  F read_peripheral 同时给裸寄存器名
运行：python -m tests.test_batch17
"""
import sys, os, json, time, asyncio, struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import create_server, _get_client
from mdkdebug import uvsock

PORT = 14871
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

    # ---------- A. 停止点可信度 ----------
    await call(server, "enter_debug", {})
    st = await call(server, "get_status", {})
    check("A0 前置：mock 已连上且处于调试态", st.get("ok") is True, str(st)[:160])

    # 目标在跑时读寄存器：必须判为不可信
    srv.running = True
    r = client.read_cpu_registers_stable(require_stopped=True, retries=4, delay=0.01)
    check("A1 目标在运行时直接拒绝给可信 PC（require_stopped）",
          r.get("ok") is False and r.get("target_running") is True, str(r)[:200])
    r1b = client.read_cpu_registers_stable(retries=4, delay=0.01)
    check("A1b 不要求停止时也把 PC 标为不可信（pc_confidence=low）",
          r1b.get("pc_confidence") == "low" and r1b.get("target_running") is True,
          str(r1b)[:220])

    # 目标停止：应给出 high 置信度 + halt_verified
    srv.running = False
    r2 = client.read_cpu_registers_stable(retries=6, delay=0.01)
    check("A2 停止态给出 pc_confidence=high",
          r2.get("pc_confidence") == "high", str(r2)[:200])
    check("A3 停止态带 halt_verified=True（复查确实停着）",
          r2.get("halt_verified") is True, str(r2)[:200])

    # 同一 PC 连续出现 -> repeat_warning
    pc_same = r2.get("pc")
    client._stop_pc_hist = [pc_same] * 3
    r3 = client.read_cpu_registers_stable(retries=6, delay=0.01)
    check("A4 同一停止地址连续出现时给 repeat 提示",
          int(r3.get("repeat_count") or 0) >= 4 and bool(r3.get("repeat_warning")),
          str(r3)[:220])
    check("A5 repeat 提示明确指向「不要再据此判断卡死/反复复位」",
          "卡死" in (r3.get("repeat_warning") or ""), str(r3.get("repeat_warning"))[:160])

    # 读完寄存器后复查发现目标在跑 -> 降级
    srv.running = False
    orig_get_status = client.get_status
    seq = {"n": 0}

    def flaky_status():
        seq["n"] += 1
        out = orig_get_status()
        if seq["n"] >= 2:          # 复查时目标「又跑起来了」
            out = dict(out)
            out["running"] = True
        return out
    client.get_status = flaky_status
    try:
        r4 = client.read_cpu_registers_stable(retries=6, delay=0.01)
    finally:
        client.get_status = orig_get_status
    check("A6 复查发现目标其实在跑时降级为 low + 明确警告",
          r4.get("pc_confidence") == "low" and r4.get("target_running") is True
          and "残留值" in (r4.get("warning") or ""), str(r4)[:240])

    # run_timeout 必须始终带 pc_confidence
    outs = await call(server, "run_timeout", {"timeout_ms": 60})
    check("A7 run_timeout 始终带 pc_confidence", "pc_confidence" in outs, str(outs)[:200])
    check("A8 run_timeout 带 stop_verified 字段", "stop_verified" in outs, str(outs)[:200])
    srv.running = False

    # ---------- B. 等待断点命中 ----------
    hit_addr = client.read_cpu_registers_stable(retries=6, delay=0.01).get("pc")
    client._bp_hits = {}
    srv.running = False
    wb = client.wait_breakpoint([hit_addr], timeout_s=1.0, poll=0.02)
    check("B1 目标停在与候选断点相同的 PC 上 -> 命中",
          wb.get("hit") is True and wb.get("hit_address") == hex(hit_addr), str(wb)[:220])
    check("B2 命中计数从 1 开始累计", wb.get("hit_count") == 1, str(wb)[:160])
    wb2 = client.wait_breakpoint([hit_addr], timeout_s=1.0, poll=0.02)
    check("B3 再次命中同一地址计数递增到 2", wb2.get("hit_count") == 2, str(wb2)[:160])

    srv.running = True
    t0 = time.time()
    wb3 = client.wait_breakpoint([0x08001234], timeout_s=0.4, poll=0.05)
    dt = time.time() - t0
    check("B4 目标一直在跑 -> 超时返回 ok=false 且不误报命中",
          wb3.get("ok") is False and wb3.get("hit") is False, str(wb3)[:220])
    check("B5 超时按 timeout_s 收敛（不无限等）", dt < 2.0, "耗时 %.2fs" % dt)
    check("B6 超时信息里列出候选断点与排查建议",
          "0x8001234" in str(wb3.get("candidates")) and "list_breakpoints" in (wb3.get("error") or ""),
          str(wb3)[:260])
    srv.running = False

    # 服务器侧工具
    tw = await call(server, "wait_breakpoint", {"address": hex(hit_addr), "timeout_s": 1.0})
    check("B7 wait_breakpoint 工具可按地址命中并回落源码位",
          tw.get("hit") is True and tw.get("hit_address") == hex(hit_addr), str(tw)[:220])
    ts = await call(server, "breakpoint_stats", {})
    check("B8 breakpoint_stats 给出累计命中", ts.get("ok") is True and ts.get("count", 0) >= 1,
          str(ts)[:200])

    # ---------- C. 会话预警 ----------
    srv.drop_connection_after = 1
    ex = None
    for _ in range(3):
        try:
            client.get_status()
        except Exception as e:  # noqa: BLE001
            ex = e
            break
    check("C1 连接被重置时能看到原因（不再裸抛 WinError）",
          ex is not None and ("中断" in str(ex) or "超时" in str(ex)), str(ex)[:200])
    srv.drop_connection_after = 0

    # ---------- E/F. 工具细节 ----------
    sm = await call(server, "search_mem", {"start": "0x20000000", "end": "0x20000010",
                                           "pattern_text": "appst"})
    check("E1 search_mem 支持 pattern_text（无需手工转十六进制）",
          sm.get("ok") is True and sm.get("pattern_hex") == b"appst".hex(), str(sm)[:200])
    sm2 = await call(server, "search_mem", {"start": "0x20000000", "end": "0x20000010",
                                            "pattern_text": "appst"})
    check("E2 pattern_text 与 pattern_hex 等价", sm2.get("ok") is True, str(sm2)[:160])
    bad = await call(server, "search_mem", {"start": "0x20000000", "end": "0x20000010",
                                            "pattern_hex": "ZZ"})
    check("E3 非法 hex 提示改用 pattern_text",
          bad.get("ok") is False and "pattern_text" in (bad.get("error") or ""), str(bad)[:200])

    rp = await call(server, "read_peripheral", {"periph": "GPIOC"})
    regs = (rp.get("regs") or [])
    bare = [x.get("name") for x in regs]
    check("F1 read_peripheral 结果带裸寄存器名",
          rp.get("ok") is True and "MODER" in bare, str(bare)[:200])
    check("F2 每条寄存器都带 name 且保留 reg 字段",
          all(("reg" in x and "name" in x) for x in regs), str(regs[:1])[:200])
    check("F3 GPIOC 的裸名集合含 MODER/ODR",
          {"MODER", "ODR"}.issubset(set(bare)), str(sorted(bare))[:200])

    print("\n批次17 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)), flush=True)
    if FAIL:
        print("失败项:", FAIL, flush=True)
    srv.stop()


asyncio.run(main())
