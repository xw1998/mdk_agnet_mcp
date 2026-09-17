# -*- coding: utf-8 -*-
"""批次24 mock 测试：名称列表 / 结构化列表参数的类型通则（第 9 轮建议①）。

背景（用户反馈原文）：
    「regs 类参数的类型宽容是被动补的。建议做个通则：所有接受『名称列表』的参数
     （regs、symbols、fields）都同时接受字符串与数组，不要让 AI 靠报错来学习签名。」

本批把下面这些列表型参数一律做成「数组 / JSON 字符串 / 分隔符字符串」通吃，
并同步放宽类型标注（否则框架层先按 string 拒收）：
  - snapshot.globals / diagnose.globals / snapshot_diff.globals  名称列表
  - watch.expressions                                            表达式列表
  - read_mem_multi.addresses                                     结构化列表
  - batch.commands                                               结构化列表（JSON 字符串）

运行：python -m tests.test_batch24
"""
import os
import sys
import json
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _watchpoints  # noqa: E402

PORT = 14896
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"


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


def exprs_of(r):
    return [x.get("expression") for x in (r.get("results") or [])]


def globals_of(r):
    return [x.get("name") for x in (r.get("globals") or [])]


def arm_stop_after(srv, pc, dfsr=None):
    """模拟「目标运行中、随后停在该 PC」；dfsr 非空时同时置位 DFSR 对应位。"""
    for k in ("__currentPC()", "PC", "R15"):
        srv.reg_map[k] = pc
    srv.running = True
    srv.auto_stop_reads = 1
    srv.auto_stop_pc = pc
    srv.auto_stop_dfsr = dfsr


def watch_addr_of():
    for w in list(_watchpoints):
        try:
            return int(str(w.get("address")), 16)
        except Exception:  # noqa: BLE001
            continue
    return None


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    await call(server, "enter_debug", {})

    # ============ A. watch.expressions：数组 / 逗号 / 分号 / 单值 / 空串 ============
    print("A. watch.expressions 类型通则")
    r_arr = await call(server, "watch", {"expressions": ["v1", "arr[0]", "v2"]})
    check("A1 数组写法正常（原语义不回归）",
          r_arr.get("ok") is True and len(r_arr.get("results") or []) == 3,
          json.dumps(r_arr, ensure_ascii=False)[:200])
    vals_arr = [x.get("value") for x in (r_arr.get("results") or [])]

    r_csv = await call(server, "watch", {"expressions": "v1,arr[0],v2"})
    check("A2 逗号分隔字符串与数组等价",
          r_csv.get("ok") is True and exprs_of(r_csv) == ["v1", "arr[0]", "v2"]
          and [x.get("value") for x in (r_csv.get("results") or [])] == vals_arr,
          json.dumps(r_csv, ensure_ascii=False)[:240])

    r_semi = await call(server, "watch", {"expressions": "v1; arr[0] ; v2"})
    check("A3 分号分隔字符串（含空格）也等价",
          r_semi.get("ok") is True and exprs_of(r_semi) == ["v1", "arr[0]", "v2"],
          json.dumps(r_semi, ensure_ascii=False)[:240])

    r_one = await call(server, "watch", {"expressions": "v1"})
    check("A4 单个名称字符串（无分隔符）→ 1 条结果",
          r_one.get("ok") is True and exprs_of(r_one) == ["v1"],
          json.dumps(r_one, ensure_ascii=False)[:200])

    r_empty = await call(server, "watch", {"expressions": ""})
    check("A5 空字符串 → ok=false + 明确提示（不崩、不抛）",
          r_empty.get("ok") is False and "expressions" in str(r_empty.get("error", "")),
          json.dumps(r_empty, ensure_ascii=False)[:200])

    try:
        await call(server, "watch", {"expressions": None})
        a6_ok, a6_detail = False, "传 null 竟然没报错"
    except Exception as e:  # noqa: BLE001
        # 框架层拒绝即可（必填参数不接受 null）；关键是错误里要给出 list/string 两种类型提示
        msg = str(e)
        a6_ok = "list" in msg and "string" in msg
        a6_detail = msg[:200]
    check("A6 传 null 被框架拒绝且提示 list/str 两种类型", a6_ok, a6_detail)

    # ============ B. snapshot.globals：数组 / 分隔符字符串 ============
    print("B. snapshot.globals 类型通则")
    b_arr = await call(server, "snapshot", {"globals": ["v1", "v2"]})
    check("B1 数组写法正常",
          b_arr.get("ok") is True and globals_of(b_arr) == ["v1", "v2"],
          json.dumps(b_arr, ensure_ascii=False)[:240])
    b_csv = await call(server, "snapshot", {"globals": "v1,v2"})
    check("B2 逗号字符串与数组等价",
          b_csv.get("ok") is True and globals_of(b_csv) == ["v1", "v2"],
          json.dumps(b_csv, ensure_ascii=False)[:240])
    b_semi = await call(server, "snapshot", {"globals": "v1; v2"})
    check("B3 分号字符串与数组等价",
          b_semi.get("ok") is True and globals_of(b_semi) == ["v1", "v2"],
          json.dumps(b_semi, ensure_ascii=False)[:240])
    b_one = await call(server, "snapshot", {"globals": "v1"})
    check("B4 单个名称字符串 → 1 项",
          b_one.get("ok") is True and globals_of(b_one) == ["v1"],
          json.dumps(b_one, ensure_ascii=False)[:240])

    # ============ C. diagnose.globals ============
    print("C. diagnose.globals 类型通则")
    c_csv = await call(server, "diagnose", {"globals": "v1,v2"})
    check("C1 逗号字符串 → globals 两项",
          c_csv.get("ok") is True and globals_of(c_csv) == ["v1", "v2"],
          json.dumps(c_csv, ensure_ascii=False)[:260])
    c_arr = await call(server, "diagnose", {"globals": ["v1", "v2"]})
    check("C2 数组写法不回归",
          c_arr.get("ok") is True and globals_of(c_arr) == ["v1", "v2"],
          json.dumps(c_arr, ensure_ascii=False)[:260])

    # ============ D. snapshot_diff.globals ============
    print("D. snapshot_diff.globals 类型通则")
    d1 = await call(server, "snapshot_diff", {"globals": "v1,v2"})
    check("D1 字符串 globals 建基线成功", d1.get("ok") is True,
          json.dumps(d1, ensure_ascii=False)[:260])
    d2 = await call(server, "snapshot_diff", {"globals": "v1,v2"})
    check("D2 第二次调用（字符串写法）能对比",
          d2.get("ok") is True, json.dumps(d2, ensure_ascii=False)[:260])

    # ============ E. read_mem_multi.addresses ============
    print("E. read_mem_multi.addresses 类型通则")
    e_arr = await call(server, "read_mem_multi",
                       {"addresses": [{"addr": "0x20000000", "n_bytes": 4},
                                      {"addr": "0x20000004", "n_bytes": 4}]})
    check("E1 数组写法不回归",
          e_arr.get("ok") is True and e_arr.get("count") == 2,
          json.dumps(e_arr, ensure_ascii=False)[:200])

    e_csv = await call(server, "read_mem_multi", {"addresses": "0x20000000,0x20000004"})
    res = e_csv.get("results") or []
    check("E2 逗号地址字符串 → 2 处、每处按 n_bytes=32 读",
          e_csv.get("ok") is True and e_csv.get("count") == 2
          and [x.get("addr") for x in res] == ["0x20000000", "0x20000004"]
          and all(x.get("size") == 32 for x in res),
          json.dumps(e_csv, ensure_ascii=False)[:260])

    e_semi = await call(server, "read_mem_multi", {"addresses": "0x20000000; 0x20000004"})
    check("E3 分号地址字符串等价",
          e_semi.get("ok") is True and e_semi.get("count") == 2,
          json.dumps(e_semi, ensure_ascii=False)[:200])

    e_json = await call(server, "read_mem_multi",
                        {"addresses": '[{"addr": "0x20000000", "n_bytes": 4}]'})
    jres = e_json.get("results") or []
    check("E4 JSON 数组字符串 → 1 处、size=4",
          e_json.get("ok") is True and e_json.get("count") == 1
          and jres and jres[0].get("size") == 4,
          json.dumps(e_json, ensure_ascii=False)[:240])

    e_one = await call(server, "read_mem_multi", {"addresses": "0x20000010"})
    check("E5 单个地址字符串 → 1 处",
          e_one.get("ok") is True and e_one.get("count") == 1,
          json.dumps(e_one, ensure_ascii=False)[:200])

    e_bad = await call(server, "read_mem_multi", {"addresses": '[{"addr": '})
    check("E6 非法 JSON 字符串 → ok=false + 说明含 JSON（不崩）",
          e_bad.get("ok") is False and "JSON" in str(e_bad.get("error", "")),
          json.dumps(e_bad, ensure_ascii=False)[:240])

    try:
        await call(server, "read_mem_multi", {"addresses": None})
        e7_ok, e7_detail = False, "传 null 竟然没报错"
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        e7_ok = "list" in msg and "string" in msg
        e7_detail = msg[:200]
    check("E7 传 null 被框架拒绝且提示 list/str 两种类型", e7_ok, e7_detail)

    # ============ F. batch.commands ============
    print("F. batch.commands 类型通则")
    cmds = [{"tool": "get_status", "args": {}}, {"tool": "read_registers", "args": {}}]
    f_arr = await call(server, "batch", {"commands": cmds})
    check("F1 数组写法不回归",
          f_arr.get("ok") is True and f_arr.get("count") == 2,
          json.dumps(f_arr, ensure_ascii=False)[:200])

    f_json = await call(server, "batch", {"commands": json.dumps(cmds)})
    check("F2 JSON 数组字符串 → 正常执行 2 条",
          f_json.get("ok") is True and f_json.get("count") == 2
          and all(x.get("ok") for x in (f_json.get("results") or [])),
          json.dumps(f_json, ensure_ascii=False)[:260])

    # ============ H. 数据观察点命中升级为 verified（DFSR 硬证据，第 9 轮建议③）============
    print("H. 数据观察点命中：DFSR.DWTTRAP 硬证据")
    r = await call(server, "set_watchpoint", {"expr": "v1", "access": "write"})
    check("H0 设数据观察点成功", r.get("ok") is True,
          json.dumps(r, ensure_ascii=False)[:200])
    waddr = watch_addr_of()
    check("H0b 记录到观察点地址", isinstance(waddr, int), str(list(_watchpoints))[:200])

    # H1：DFSR 残留 VCATCH(0x08)，命中时 DWTTRAP(0x04) 置位 → 硬证据 verified
    srv.bl_table = []
    srv.dfsr = 0x08
    srv.dwt_comps = [waddr, 0, 0, 0]
    arm_stop_after(srv, 0x08000ABC, dfsr=0x04)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    check("H1 DWTTRAP 置位 → hit=true + hit_kind=watch",
          r.get("hit") is True and r.get("hit_kind") == "watch",
          json.dumps(r, ensure_ascii=False)[:260])
    check("H1b 命中强度升级为 verified",
          r.get("hit_confidence") == "verified",
          json.dumps(r, ensure_ascii=False)[:260])
    check("H1c hit_entry.source=dfsr（硬件证据，不再是 inferred）",
          (r.get("hit_entry") or {}).get("source") == "dfsr",
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:260])
    check("H1d 等待前已清零残留 DFSR 位（dwt_comps 定位到观察点）",
          (r.get("dfsr") or {}).get("dwt_trap") is True
          and "已清零" in str(r.get("dfsr_note"))
          and "DWT_COMP 匹配到观察点地址" in str((r.get("hit_entry") or {}).get("note")),
          json.dumps({k: r.get(k) for k in ("dfsr", "dfsr_note", "hit_entry")},
                     ensure_ascii=False)[:300])

    # H2：DFSR 读到了但只有 BKPT 位（非 DWT 触发）→ 保持推断强度
    srv.dfsr = 0
    srv.dwt_comps = [0, 0, 0, 0]
    arm_stop_after(srv, 0x08000ABC, dfsr=0x02)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    check("H2 DWTTRAP=0 → 仍判观察点命中但强度为 inferred",
          r.get("hit") is True and r.get("hit_confidence") == "inferred"
          and (r.get("hit_entry") or {}).get("source") == "inferred",
          json.dumps(r, ensure_ascii=False)[:280])
    check("H2b 说明里指出 DFSR 已读到但 DWTTRAP=0",
          "DWTTRAP=0" in str((r.get("hit_entry") or {}).get("note")),
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:260])

    # H3：DWT_COMP 对不上候选 → 退回首个候选并说明
    srv.dfsr = 0
    srv.dwt_comps = [0, 0, 0, 0]
    arm_stop_after(srv, 0x08000ABC, dfsr=0x04)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    check("H3 DWT_COMP 未匹配 → 退回首个候选并如实说明",
          r.get("hit") is True and r.get("hit_confidence") == "verified"
          and "未匹配到候选" in str((r.get("hit_entry") or {}).get("note")),
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:280])

    # H4：代码断点按 PC 命中 → verified，且 DFSR 如实报告 BKPT
    srv.dfsr = 0
    srv.dwt_comps = [0, 0, 0, 0]
    arm_stop_after(srv, 0x08000DB4, dfsr=0x02)
    r = await call(server, "wait_breakpoint",
                   {"address": "0x08000DB4", "timeout_s": 2.0})
    check("H4 代码断点 PC 命中 → hit_kind=code + verified",
          r.get("hit") is True and r.get("hit_kind") == "code"
          and r.get("hit_confidence") == "verified",
          json.dumps(r, ensure_ascii=False)[:280])
    check("H4b dfsr 报告 BKPT 位置位",
          (r.get("dfsr") or {}).get("bkpt") is True,
          json.dumps(r.get("dfsr"), ensure_ascii=False)[:200])

    # ===== I. 值变化数据侧实证（真机 Keil 读不到 DWTTRAP 时唯一可核对的路径）=====
    print("I. 值变化 → 数据侧实证（DFSR.DWTTRAP=0 时）")
    import struct as _struct
    waddr2 = watch_addr_of()
    _off = waddr2 - 0x20000000
    _struct.pack_into('<I', srv.mem, _off, 0x11111111)
    await call(server, "set_watchpoint", {"expr": "v1", "access": "write"})  # 重新设点=记录基线

    srv.bl_table = []
    srv.dfsr = 0                      # 真机实测：Keil 在 halt 后已读走 DWTTRAP
    srv.dwt_comps = [waddr2, 0, 0, 0]  # 但比较器确实装的是观察地址
    srv.auto_stop_writes = [(waddr2, 0x22222222, 4)]
    arm_stop_after(srv, 0x08000ABC, dfsr=0)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    _e = r.get("hit_entry") or {}
    check("I1 DWTTRAP=0 但值被改写 → hit=true + hit_kind=watch",
          r.get("hit") is True and r.get("hit_kind") == "watch",
          json.dumps(r, ensure_ascii=False)[:260])
    check("I2 证据来源为 value_changed",
          _e.get("source") == "value_changed", json.dumps(_e, ensure_ascii=False)[:260])
    check("I3 有可核对证据 → hit_confidence=verified",
          r.get("hit_confidence") == "verified",
          json.dumps(r.get("hit_confidence"), ensure_ascii=False))
    check("I4 命中地址就是被改写的观察地址",
          str(_e.get("address")).lower() == hex(waddr2).lower(),
          json.dumps(_e, ensure_ascii=False)[:200])
    check("I5 watch_value_check 给出 before/after 且 changed=true",
          ((r.get("watch_value_check") or {}).get(hex(waddr2)) or {}).get("changed") is True,
          json.dumps(r.get("watch_value_check"), ensure_ascii=False)[:240])
    check("I6 note 如实标注「数据侧实证、非 DWT 硬件命中位」",
          "数据侧实证" in str(_e.get("note")) and "非 DWT 硬件命中位" in str(_e.get("note")),
          json.dumps(_e, ensure_ascii=False)[:300])
    check("I7 dwt_watch_loaded 作为旁证报告观察点已装载",
          (r.get("dwt_watch_loaded") or {}).get("any_loaded") is True,
          json.dumps(r.get("dwt_watch_loaded"), ensure_ascii=False)[:240])

    # I8：反例 —— DFSR 无 DWTTRAP 且值未被改写 → 只能推断（不得冒充实证）
    srv.auto_stop_writes = None
    _struct.pack_into('<I', srv.mem, _off, 0x11111111)
    await call(server, "set_watchpoint", {"expr": "v1", "access": "write"})  # 基线=0x11111111
    srv.dfsr = 0
    arm_stop_after(srv, 0x08000ABC, dfsr=0)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    _e2 = r.get("hit_entry") or {}
    check("I8 无 DFSR、无值变化 → 强度退回 inferred",
          r.get("hit") is True and r.get("hit_confidence") == "inferred"
          and _e2.get("source") == "inferred",
          json.dumps(r, ensure_ascii=False)[:260])
    check("I9 说明里点明值与基线一致（未观察到改写）",
          "未观察到改写" in str(_e2.get("note")),
          json.dumps(_e2, ensure_ascii=False)[:280])

    # ===== J. 真机竞态：run 后变量先被写、目标随即停下（基线快照已错过变动）=====
    print("J. 基线取自设点时刻 → 竞态下仍能拿到值变化证据")
    _struct.pack_into('<I', srv.mem, _off, 0xAAAAAAAA)
    await call(server, "set_watchpoint", {"expr": "v1", "access": "write"})  # 基线=AAAAAAAA
    _struct.pack_into('<I', srv.mem, _off, 0xBBBBBBBB)  # 模拟：目标已写、等待才开始
    srv.bl_table = []
    srv.dfsr = 0
    srv.dwt_comps = [waddr2, 0, 0, 0]
    srv.auto_stop_writes = None
    arm_stop_after(srv, 0x08000ABC, dfsr=0)
    r = await call(server, "wait_breakpoint", {"timeout_s": 2.0})
    _j = (r.get("watch_value_check") or {}).get(hex(waddr2)) or {}
    check("J1 现场值与基线不同 → 判为被改写（changed=true）",
          _j.get("changed") is True, json.dumps(r.get("watch_value_check"), ensure_ascii=False)[:240])
    check("J2 基线来自历史记录（设为 AAAAAAAA）、当前为 BBBBBBBB",
          str(_j.get("before")).lower() == "aaaaaaaa" and str(_j.get("after")).lower() == "bbbbbbbb",
          json.dumps(_j, ensure_ascii=False)[:200])
    check("J3 证据来源 value_changed + 强度 verified",
          (r.get("hit_entry") or {}).get("source") == "value_changed"
          and r.get("hit_confidence") == "verified",
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:260])
    check("J4 note 交代基线取自设点/上一停止点的历史记录",
          "历史记录" in str((r.get("hit_entry") or {}).get("note")),
          json.dumps((r.get("hit_entry") or {}).get("note"), ensure_ascii=False)[:260])

    await call(server, "clear_watchpoint", {"expr": "v1"})

    # ============ G. 描述与 schema 层 ============
    print("G. 描述文案与 schema 放宽")
    tools = {t.name: t for t in await server.list_tools()}
    def _schema_text(t):
        s = getattr(t, "input_schema", None)
        if s is None:
            s = getattr(t, "inputSchema", None)
        return json.dumps(s, ensure_ascii=False, default=str)

    schema_dsc = {n: _schema_text(tools[n])
                  for n in ("snapshot", "watch", "diagnose", "snapshot_diff",
                            "read_mem_multi", "batch") if n in tools}
    check("G1 六个工具的 list 型参数 schema 已放宽（不再是纯 array）",
          all("str" in schema_dsc.get(n, "") for n in
              ("snapshot", "watch", "diagnose", "snapshot_diff",
               "read_mem_multi", "batch")),
          json.dumps(schema_dsc, ensure_ascii=False)[:400])

    desc_need = {
        "snapshot": "分隔字符串",
        "watch": "分隔符字符串",
        "diagnose": "分隔字符串",
        "snapshot_diff": "分隔字符串",
        "read_mem_multi": "地址字符串",
    }
    for name, kw in desc_need.items():
        d = (tools[name].description or "") if name in tools else ""
        check("G2 %s 描述写明字符串写法兼容" % name, kw in d, d[:200])
    d_batch = tools["batch"].description or "" if "batch" in tools else ""
    check("G3 batch 描述写明接受 JSON 数组字符串", "JSON 数组字符串" in d_batch, d_batch[:200])
    d_wait = tools["wait_breakpoint"].description or ""
    check("G4 wait_breakpoint 描述说明 DFSR 硬证据与 hit_confidence",
          "DFSR" in d_wait and "hit_confidence" in d_wait, d_wait[:200])

    srv.stop()
    print("\n==== 批次24 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
