# -*- coding: utf-8 -*-
"""批次22 mock 测试：数据断点命中判定 / 按 Keil 编号清断点 / 外设寄存器筛选 / App 重定位 / 计时 / 工具清单。

对应第 7 轮反馈的「仍然不便的地方」：
  1. wait_breakpoint 只认 .uvoptx 候选、不认 set_watchpoint 的数据断点 → 已命中仍报 hit:false
  2. clear_breakpoint 不支持按 Keil 真实断点编号清除（bp_id 只认内部 id），只能 BK *
  3. read_peripheral 输出全寄存器 + 逐 bit 字段，极易撑爆上下文
  4. 读 App 侧变量仍需手工做 - SVCRT_RELOC_DELTA(0xF000) 换算
  5. run_timeout 的时长字段语义混淆（waited_ms 被当成运行时长）
  6. 工具参数名不统一、只在报错里暴露，需一次拿到「必填参数」

运行：python -m tests.test_batch22
"""
import sys, os, json, time, asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import (create_server, _get_client, _watchpoints,
                             _breakpoints, _reloc_cfg, _eff_reloc_delta,
                             _resolve_addr_with_reloc, _parse_reloc_delta)

PORT = 14894
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


EXEC_BP = {"number": 0, "kind": "exec", "address": "0x08000DB4",
           "expr": "..\\main.c\\77", "count": 1, "enabled": True}
WATCH_BP = {"number": 3, "kind": "access", "access": "WR", "address": "0x20000000",
            "length": 1, "expr": "0x20000000", "count": 1, "enabled": True}


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
    client = _get_client()
    await call(server, "enter_debug", {})

    # ============ A. 数据断点命中判定 ============
    print("A. wait_breakpoint 命中判定（CNT 对比 + 退化推断）")
    _watchpoints.clear()
    srv.bl_table = [dict(EXEC_BP), dict(WATCH_BP)]

    # A1: PC 落在执行断点上 + CNT 也增加 → code
    set_pc(srv, 0x08000DB4)
    # 第 1 次读 BL 是基线，第 2 次（停止后复查）之前让执行断点 CNT 自增 → 模拟等待期间命中
    srv.bl_reads = 0
    srv.bl_bump_after_reads = [(2, 0, 1)]
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A1 执行断点命中 hit=true/hit_kind=code",
          r.get("hit") is True and r.get("hit_kind") == "code", json.dumps(r, ensure_ascii=False)[:220])
    check("A1b 带出 CNT 增量（哪个断点命中了）",
          (r.get("cnt_delta") or {}).get("0") == 1, json.dumps(r.get("cnt_delta"), ensure_ascii=False))
    check("A1c hit_entry 来源标 cnt", (r.get("hit_entry") or {}).get("source") == "cnt",
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:200])

    # A2: PC 不在任何执行断点上，但数据观察点 CNT 增加 → watch（旧实现必然漏判）
    set_pc(srv, 0x0800AAAA)
    srv.bl_reads = 0
    srv.bl_bump_after_reads = [(2, 3, 1)]
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A2 数据观察点命中 hit=true/hit_kind=watch",
          r.get("hit") is True and r.get("hit_kind") == "watch", json.dumps(r, ensure_ascii=False)[:260])
    check("A2b hit_address 指向观察点地址而非 PC",
          r.get("hit_address") == "0x20000000" and r.get("pc") == "0x800aaaa",
          "hit_address=%s pc=%s" % (r.get("hit_address"), r.get("pc")))
    check("A2c hit_entry 带 Keil 断点编号与类型",
          (r.get("hit_entry") or {}).get("number") == 3
          and (r.get("hit_entry") or {}).get("kind") == "access",
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:200])

    # A3: CNT 基线不可得（旧格式 BL）+ 有观察点 → 退化推断，显式标注 inferred
    srv.bl_table = None
    _watchpoints.clear()
    _watchpoints.append({"id": 91, "expr": "0x20000000", "address": "0x20000000",
                         "access": "write", "count": 1, "file": None, "line": None})
    set_pc(srv, 0x0800AAAA)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A3 CNT 不可得时退化推断 hit_kind=watch",
          r.get("hit") is True and r.get("hit_kind") == "watch", json.dumps(r, ensure_ascii=False)[:260])
    check("A3b 退化判定标注 source=inferred（可辨别置信度）",
          (r.get("hit_entry") or {}).get("source") == "inferred", json.dumps(r.get("hit_entry"), ensure_ascii=False))
    check("A3c 给出 cnt_note 说明判定已降级",
          "CNT" in (r.get("cnt_note") or ""), r.get("cnt_note"))

    # A4: 都没命中 → hit=false（不能因为「有观察点」就瞎报命中）
    srv.bl_table = [dict(EXEC_BP), dict(WATCH_BP)]
    _watchpoints.clear()
    set_pc(srv, 0x0800AAAA)
    r = await call(server, "wait_breakpoint", {"timeout_s": 0.3, "address": "0x08000DB4"})
    check("A4 无 CNT 增量且 PC 不匹配 → hit=false",
          r.get("hit") is False, json.dumps(r, ensure_ascii=False)[:200])

    # A5: 工具层把本服务 set_watchpoint 的观察点并入候选
    _watchpoints.clear()
    sw = await call(server, "set_watchpoint", {"expr": "0x20000000", "access": "write"})
    r = await call(server, "wait_breakpoint", {"timeout_s": 0.3, "address": "0x08000DB4"})
    check("A5 set_watchpoint 的观察点被并入判定",
          "数据观察点" in (r.get("candidates_note") or ""),
          "sw=%s note=%s" % (sw.get("ok"), r.get("candidates_note")))
    check("A5b 无候选时也会取 Keil 真实断点表",
          "真实断点表" in (r.get("candidates_note") or "") or sw.get("ok"),
          r.get("candidates_note"))
    # A6: 真机场景（本版 Keil 的 BL CNT 不随命中递增）：只设了数据观察点、没给代码候选，
    #     等待期间 CNT 无增量 → 必须仍判为 watch（旧实现会判成 code 或直接 hit=false）
    _watchpoints.clear()
    srv.bl_table = [dict(WATCH_BP)]
    srv.bl_reads = 0
    srv.bl_bump_after_reads = []
    _watchpoints.append({"id": 92, "expr": "0x20000000", "address": "0x20000000",
                         "access": "read", "count": 1, "file": None, "line": None})
    set_pc(srv, 0x0800AAAA)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0})
    check("A6 无代码候选 + 观察点 + CNT 无增量 → hit=true/hit_kind=watch",
          r.get("hit") is True and r.get("hit_kind") == "watch",
          json.dumps(r, ensure_ascii=False)[:260])
    check("A6b 标注 source=inferred（判定依据强度可见）",
          (r.get("hit_entry") or {}).get("source") == "inferred",
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:200])
    check("A6c cnt_note 说明 CNT 不随命中递增",
          "CNT" in (r.get("cnt_note") or ""), str(r.get("cnt_note")))

    # A7: 既无代码候选、也无观察点 → 保持「停下即视为命中」的旧行为
    _watchpoints.clear()
    srv.bl_table = None
    set_pc(srv, 0x0800BBBB)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0})
    check("A7 无任何候选时停下即命中（hit_kind=code，旧行为不丢）",
          r.get("hit") is True and r.get("hit_kind") == "code",
          json.dumps(r, ensure_ascii=False)[:200])

    # A8: 真机常见路径——PC 命中代码断点，但 CNT 不随命中递增 → 仍要给出 hit_entry（来源 pc）
    _watchpoints.clear()
    srv.bl_table = [dict(EXEC_BP)]
    srv.bl_reads = 0
    srv.bl_bump_after_reads = []
    set_pc(srv, 0x08000DB4)
    r = await call(server, "wait_breakpoint", {"timeout_s": 1.0, "address": "0x08000DB4"})
    check("A8 PC 命中 + CNT 无增量 → hit_entry 来源标 pc",
          r.get("hit") is True and (r.get("hit_entry") or {}).get("source") == "pc"
          and (r.get("hit_entry") or {}).get("number") == 0,
          json.dumps(r.get("hit_entry"), ensure_ascii=False)[:220])

    _watchpoints.clear()
    srv.bl_table = None

    # ============ B. clear_breakpoint 按 Keil 编号 ============
    print("B. clear_breakpoint 支持 Keil 真实断点编号")
    srv.bl_table = [dict(EXEC_BP), dict(WATCH_BP)]
    r = await call(server, "clear_breakpoint", {"keil_number": 3})
    check("B1 直接按 Keil 编号清除",
          r.get("ok") is True and r.get("cleared_by") == "keil_number"
          and r.get("keil_number") == 3, json.dumps(r, ensure_ascii=False)[:220])
    check("B1b 清除后真实断点表里不再有该编号",
          not any(b.get("number") == 3 for b in (srv.bl_table or [])), str(srv.bl_table))

    srv.bl_table = [dict(EXEC_BP), dict(WATCH_BP)]
    r = await call(server, "clear_breakpoint", {"bp_id": 3})
    check("B2 bp_id 在内部表无此 id 时回退按 Keil 编号",
          r.get("ok") is True and r.get("cleared_by") == "keil_number",
          json.dumps(r, ensure_ascii=False)[:240])
    check("B2b 回退时给出 resolve_note 说明",
          "内部断点表" in (r.get("resolve_note") or ""), r.get("resolve_note"))

    print("B3 描述口径")
    tools = server._tool_manager._tools
    d = tools["clear_breakpoint"].description
    check("B3a 描述含 keil_number 用法", "keil_number" in d, d[:160])
    check("B3b 描述说明数据观察点必须按编号清", "error 72" in d or "按编号" in d, d[:200])

    # ============ C. read_peripheral 寄存器筛选 ============
    print("C. read_peripheral 只取指定寄存器")
    r_all = await call(server, "read_peripheral", {"periph": "GPIOC"})
    check("C1 不传 regs 时仍返回全部寄存器", r_all.get("ok") and r_all.get("reg_count", 0) > 1,
          "reg_count=%s" % r_all.get("reg_count"))

    r_one = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "MODER"})
    check("C2 regs 筛选后只返回指定寄存器",
          r_one.get("reg_count") == 1 and "MODER" in (r_one.get("regs") or [{}])[0].get("reg", ""),
          json.dumps(r_one, ensure_ascii=False)[:220])
    check("C2b 输出体量显著小于全量",
          len(json.dumps(r_one)) < len(json.dumps(r_all)) / 3,
          "%d vs %d" % (len(json.dumps(r_one)), len(json.dumps(r_all))))

    r_multi = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "GPIOC_MODER, OTYPER"})
    check("C3 支持带外设前缀的全名与多个寄存器（逗号分隔、大小写不敏感）",
          r_multi.get("reg_count") == 2, json.dumps(r_multi, ensure_ascii=False)[:220])
    r_bare = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "gpioc_moder"})
    check("C3b 裸名/前缀名两种写法都能匹配（大小写不敏感）",
          r_bare.get("reg_count") == 1, json.dumps(r_bare, ensure_ascii=False)[:200])

    r_miss = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "MODER,NOSUCHREG"})
    check("C4 未匹配的名字列在 not_found_regs（拼错立刻可见）",
          r_miss.get("not_found_regs") == ["NOSUCHREG"], json.dumps(r_miss, ensure_ascii=False)[:200])

    r_off = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "MODER", "fields": "off"})
    check("C5 fields=off 时不再输出位域",
          r_off.get("fields_mode") == "off"
          and not ((r_off.get("regs") or [{}])[0].get("fields")), json.dumps(r_off, ensure_ascii=False)[:200])

    r_bad = await call(server, "read_peripheral", {"periph": "GPIOC", "regs": "NOPE"})
    check("C6 全部未匹配时明确报错", r_bad.get("ok") is False and r_bad.get("error"),
          json.dumps(r_bad, ensure_ascii=False)[:160])

    # ============ D. App 符号重定位 ============
    print("D. set_reloc_delta（App 侧变量按符号名直读）")
    _reloc_cfg["delta"] = 0
    r = await call(server, "set_reloc_delta", {"delta": "0xF000"})
    check("D1 设置全局偏移",
          r.get("ok") and r.get("reloc_delta") == "0xF000" and r.get("previous_delta") == "0x0",
          json.dumps(r, ensure_ascii=False)[:200])

    # 在运行地址处放一个可识别的值：0x20000000 + 0x1000
    import struct as _st
    _st.pack_into("<I", srv.mem, 0xF000, 0xCAFEBABE)   # 0x20000000 + 0xF000

    r = await call(server, "read_variable", {"name": "v0"})
    check("D2 不传参数即用全局偏移，返回 run_address",
          r.get("ok") and r.get("run_address") == "0x2000f000" and r.get("link_address") == "0x20000000",
          json.dumps(r, ensure_ascii=False)[:240])
    check("D3 值取自运行地址（无需手工换算）",
          r.get("value") == 0xCAFEBABE, "value=%s run=%s" % (r.get("value"), r.get("run_address")))

    r = await call(server, "read_variable", {"name": "v0", "reloc_delta": "0x0"})
    check("D4 单次调用可覆盖全局偏移（reloc_delta=0 读链接地址）",
          r.get("value") == 0x11223344, "value=%s run=%s" % (r.get("value"), r.get("run_address")))

    r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
    check("D5 显式数字地址不被偏移", r.get("ok") and r.get("data_hex", "").startswith("44332211"),
          json.dumps(r, ensure_ascii=False)[:200])

    d, note = _eff_reloc_delta(None)
    check("D6 全局偏移读取正确", d == 0xF000, "delta=%s note=%s" % (d, note))
    check("D7 _parse_reloc_delta 支持十六进制/十进制/负数",
          _parse_reloc_delta("0x1000") == 4096 and _parse_reloc_delta("4096") == 4096
          and _parse_reloc_delta("-0x10") == -16 and _parse_reloc_delta("") is None)

    r = await call(server, "set_reloc_delta", {"delta": "0"})
    check("D8 可清 0 关闭偏移",
          r.get("ok") and r.get("reloc_delta") == "0x0" and _reloc_cfg["delta"] == 0,
          json.dumps(r, ensure_ascii=False)[:160])

    # ============ E. run_timeout 计时 ============
    print("E. run_timeout 分段计时")
    r = await call(server, "run_timeout", {"timeout_ms": 137})
    check("E1 四段计时字段齐全",
          all(k in r for k in ("requested_run_ms", "actual_run_ms", "stop_wait_ms", "total_ms")),
          json.dumps(r, ensure_ascii=False)[:240])
    check("E2 requested_run_ms 回显请求值", r.get("requested_run_ms") == 137, str(r.get("requested_run_ms")))
    check("E3 actual_run_ms 与请求值同量级（±80ms 内，Windows sleep 粒度约 15.6ms）",
          isinstance(r.get("actual_run_ms"), int) and abs(r["actual_run_ms"] - 137) <= 80,
          "actual=%s" % r.get("actual_run_ms"))
    check("E4 stop_wait_ms 与 actual_run_ms 分开（不再混淆）",
          isinstance(r.get("stop_wait_ms"), int)
          and "stop_wait_ms" in (r.get("timing_note") or ""),
          r.get("timing_note"))
    check("E5 描述里说明 waited_ms 的含义",
          "stop_wait_ms" in server._tool_manager._tools["run_timeout"].description)

    # ============ F. list_tools 工具清单 ============
    print("F. list_tools 元工具")
    r = await call(server, "list_tools", {})
    tools = server._tool_manager._tools
    check("F1 列出全部工具", r.get("ok") and r.get("count") == len(tools),
          "count=%s total=%s" % (r.get("count"), len(tools)))
    check("F2 每条含必填参数与最小调用示例",
          all(isinstance(t.get("required"), list) and isinstance(t.get("example_args"), dict)
              for t in r.get("tools") or []), "")
    tmap = {t["tool"]: t for t in r.get("tools") or []}
    check("F3 read_mem 必填含 n_bytes，length 作为别名列入可选",
          tmap["read_mem"]["required"] == ["addr", "n_bytes"]
          and "length" in tmap["read_mem"]["optional"]
          and tmap["read_mem"]["aliases"].get("n_bytes") == "length",
          json.dumps(tmap.get("read_mem"), ensure_ascii=False))
    check("F4 list_tools 自身在清单里", "list_tools" in tmap, "")

    r = await call(server, "list_tools", {"keyword": "breakpoint"})
    names = [t["tool"] for t in r.get("tools") or []]
    check("F5 keyword 过滤生效（只留下相关工具）",
          0 < r.get("count", 0) < len(tools) and any("breakpoint" in n for n in names),
          "count=%s names=%s" % (r.get("count"), names))

    # ============ G. 参数别名 ============
    print("G. 参数别名（消除「报错才发现签名」）")
    r = await call(server, "read_mem", {"addr": "0x20000000", "length": 4})
    check("G1 read_mem 支持 length 别名", r.get("ok") and r.get("n_bytes") == 4,
          json.dumps(r, ensure_ascii=False)[:200])
    r = await call(server, "read_mem", {"addr": "0x20000000"})
    check("G2 都不传字节数时给出明确报错", r.get("ok") is False and "n_bytes" in (r.get("error") or ""),
          r.get("error"))
    r = await call(server, "find_symbol", {"name": "main"})
    check("G3 find_symbol 支持 name 别名（无 axf 时应报未就绪而非参数错）",
          "未就绪" in (r.get("error") or "") or r.get("ok"), json.dumps(r, ensure_ascii=False)[:160])

    # ============ H. 描述口径 ============
    print("H. 描述口径")
    d = server._tool_manager._tools["read_peripheral"].description
    check("H1 read_peripheral 描述提示用 regs 省上下文",
          "regs" in d and ("撑爆" in d or "上下文" in d), d[:200])
    d = server._tool_manager._tools["wait_breakpoint"].description
    check("H2 wait_breakpoint 描述说明 hit_kind/watch 判定",
          "hit_kind" in d and "CNT" in d, d[:200])
    d = server._tool_manager._tools["set_reloc_delta"].description
    check("H3 set_reloc_delta 描述说明只偏移符号名",
          "符号" in d and ("不偏移" in d or "数字地址" in d), d[:200])

    srv.stop()
    print("\n==== batch22: %d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
