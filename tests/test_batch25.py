# -*- coding: utf-8 -*-
"""批次25 mock 测试：参数名别名兼容层（第 9 轮建议②「参数名收敛」）。

用户反馈原文：
    「list_tools 只是缓解参数名不统一（find_symbol 用 query、read_mem 用 addr/n_bytes、
     run_timeout 用 timeout_ms）。根子上还是建议收敛成少数几种固定名。」
    「建议做个通则：所有接受『名称列表』的参数（regs、symbols、fields）都同时接受
     字符串与数组，不要让 AI 靠报错来学习签名。」

本批采取「主名不变 + 统一别名」的兼容层路线：
  A 定位/表达式类别名生效（expr ← expression/query/symbol/...）
  B 地址/长度类参数别名生效，且不遮蔽真实参数
  C 时间单位别名做换算（timeout_s ↔ timeout_ms 等）
  D 主名优先 / 未知参数照旧报错（不静默吞）
  E list_tools 展示「主名 ← 别名」，且不重复追加、不展示被遮蔽的别名

运行：python -m tests.test_batch25
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

PORT = 14897
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


def aliases_of_tool(tool):
    return _aliases.aliases_of(tool)

def norm(server, tool, args):
    """直接看归一结果（不经过工具执行），便于断言参数映射。"""
    a, applied = server.normalize_arguments(tool, args)
    return a, applied


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    await call(server, "enter_debug", {})

    # ============ A. 取值位置的参数别名 ============
    print("A. 定位/表达式类别名生效")
    r1 = await call(server, "calc_expression", {"expr": "v1"})
    r2 = await call(server, "calc_expression", {"expression": "v1"})
    check("A1 calc_expression：expression= 与 expr= 等价",
          r1.get("ok") is True and r2.get("ok") is True
          and r1.get("value") == r2.get("value"),
          json.dumps([r1, r2], ensure_ascii=False, default=str)[:260])

    rv1 = await call(server, "read_variable", {"name": "v1"})
    rv2 = await call(server, "read_variable", {"symbol": "v1"})
    check("A2 read_variable：symbol= 也可用",
          rv1.get("ok") is True and rv2.get("ok") is True
          and rv1.get("address") == rv2.get("address"),
          json.dumps([rv1, rv2], ensure_ascii=False, default=str)[:260])

    a, applied = norm(server, "find_symbol", {"keyword": "HAL_Init"})
    check("A3 find_symbol：keyword= → query=",
          a.get("query") == "HAL_Init" and "query" in "".join(applied),
          json.dumps([a, applied], ensure_ascii=False)[:200])
    a, applied = norm(server, "find_symbol", {"name": "HAL_Init"})
    check("A4 find_symbol：name= 是真实参数（不被别名层改写，工具内部本就兼容）",
          "name" in a and "query" not in a,
          json.dumps([a, applied], ensure_ascii=False)[:200])

    a, applied = norm(server, "set_breakpoint", {"symbol": "main"})
    check("A5 set_breakpoint：symbol= → expr=",
          a.get("expr") == "main", json.dumps([a, applied], ensure_ascii=False)[:200])
    a, applied = norm(server, "run_to_line", {"line": "main.c:42"})
    check("A6 run_to_line：line= → target=",
          a.get("target") == "main.c:42", json.dumps([a, applied], ensure_ascii=False)[:200])

    # ============ B. 地址/长度类别名，且不遮蔽真实参数 ============
    print("B. 地址/长度类别名与真实参数遮蔽保护")
    a, applied = norm(server, "read_mem", {"address": "0x20000000", "nbytes": 8})
    check("B1 read_mem：address=/nbytes= → addr=/n_bytes=",
          a.get("addr") == "0x20000000" and a.get("n_bytes") == 8,
          json.dumps([a, applied], ensure_ascii=False)[:200])

    a, applied = norm(server, "read_mem", {"addr": "0x20000000", "length": 16})
    check("B2 read_mem：length 是真实参数，不被抢去当 n_bytes",
          a.get("length") == 16 and "n_bytes" not in a,
          json.dumps([a, applied], ensure_ascii=False)[:200])

    ra = await call(server, "read_mem", {"address": "0x20000000", "nbytes": 4})
    rb = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
    check("B3 read_mem 别名写法与主名写法结果一致",
          ra.get("ok") is True and ra.get("data_hex") == rb.get("data_hex"),
          json.dumps([ra, rb], ensure_ascii=False, default=str)[:260])

    a, _ap = norm(server, "fill_mem", {"address": "0x20000100", "value": 170,
                                       "size": 16})
    check("B4 fill_mem：value=/size= → byte=/count=",
          a.get("byte") == 170 and a.get("count") == 16,
          json.dumps(a, ensure_ascii=False)[:200])

    a, _ap = norm(server, "read_mem_multi", {"addrs": ["0x20000000", "0x20000004"]})
    check("B5 read_mem_multi：addrs= → addresses=",
          a.get("addresses") == ["0x20000000", "0x20000004"],
          json.dumps(a, ensure_ascii=False)[:200])

    a, _ap = norm(server, "watch", {"exprs": ["v1", "v2"]})
    check("B6 watch：exprs= → expressions=",
          a.get("expressions") == ["v1", "v2"],
          json.dumps(a, ensure_ascii=False)[:200])

    a, _ap = norm(server, "read_peripheral", {"peripheral": "GPIOA", "registers": "MODER"})
    check("B7 read_peripheral：peripheral=/registers= → periph=/regs=",
          a.get("periph") == "GPIOA" and a.get("regs") == "MODER",
          json.dumps(a, ensure_ascii=False)[:200])

    # ============ C. 时间单位换算 ============
    print("C. 时间单位别名换算")
    a, applied = norm(server, "run_timeout", {"timeout_s": 0.05})
    check("C1 run_timeout：timeout_s=0.05 → timeout_ms=50",
          a.get("timeout_ms") == 50, json.dumps([a, applied], ensure_ascii=False)[:200])
    a, _ap = norm(server, "wait_fault", {"timeout_s": 2})
    check("C2 wait_fault：timeout_s=2 → timeout_ms=2000",
          a.get("timeout_ms") == 2000, json.dumps(a, ensure_ascii=False)[:160])
    a, _ap = norm(server, "wait_breakpoint", {"timeout_ms": 1500})
    check("C3 wait_breakpoint：timeout_ms=1500 → timeout_s=1.5",
          abs(float(a.get("timeout_s")) - 1.5) < 1e-9,
          json.dumps(a, ensure_ascii=False)[:160])
    a, _ap = norm(server, "build_project", {"project": "x.uvprojx", "timeout_ms": 90000})
    check("C4 build_project：timeout_ms=90000 → timeout_s=90",
          abs(float(a.get("timeout_s")) - 90.0) < 1e-9,
          json.dumps(a, ensure_ascii=False)[:160])
    a, _ap = norm(server, "wait_breakpoint", {"poll_s": 0.2})
    check("C5 poll_s 换算（0.2s → 200ms）",
          a.get("poll_ms") == 200, json.dumps(a, ensure_ascii=False)[:160])
    check("C6 convert_time 单元：秒→毫秒 / 毫秒→秒 / 非数值原样",
          _aliases.convert_time("timeout_ms", "timeout_s", 1.5) == 1500
          and _aliases.convert_time("timeout_s", "timeout_ms", 2500) == 2.5
          and _aliases.convert_time("timeout_ms", "timeout_s", "abc") == "abc",
          "")

    # ============ D. 主名优先 / 不静默 ============
    print("D. 主名优先与未知参数")
    a, applied = norm(server, "watch", {"expressions": ["v1"], "exprs": ["NOPE"]})
    # 批次28 收紧：主名优先的语义 = 丢弃别名键、取主名值（并在 applied 里如实记录）。
    # 旧行为把别名键留在参数里，会被 unknown_params 判成"未知参数"直接拒绝——
    # read_mem(address=…, size=…) 这种"真名+旧别名"混写就因此报错，而 size 分明是 n_bytes 的别名。
    check("D1 主名与别名同时给出时只认主名（别名键丢弃并记录，不留成未知参数）",
          a.get("expressions") == ["v1"] and "exprs" not in a
          and any("exprs" in s for s in applied),
          json.dumps([a, applied], ensure_ascii=False)[:200])

    a, applied = norm(server, "get_status", {"expr": "v1"})
    check("D2 未定义别名的工具不归一如常（交给框架校验）",
          a == {"expr": "v1"} and applied == [],
          json.dumps([a, applied], ensure_ascii=False)[:160])

    r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4, "bogus": 1})
    _t = json.dumps(r, ensure_ascii=False)
    check("D3 未知参数被显式拒绝且列出可用参数（不再静默忽略）",
          "_exc" in r and "bogus" in _t and "n_bytes" in _t, _t[:280])
    r = await call(server, "calc_expression", {"exprs": "v1"})
    check("D4 别名的近形拼错也被拦下并给出正确名字/别名",
          "_exc" in r and "expr" in json.dumps(r, ensure_ascii=False),
          json.dumps(r, ensure_ascii=False)[:260])

    # ============ F. 地址/表达式参数接受整数（真机暴露） ============
    print("F. 地址/表达式参数接受整数")
    # 真机：read_mem(addr=0x20000000) 曾被框架判 "Input should be a valid string"
    r1 = await call(server, "read_mem", {"addr": 0x20000000, "n_bytes": 4})
    r2 = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
    check("F1 read_mem：addr 传整数与传 0x 字符串等价",
          r1.get("ok") is True and r2.get("ok") is True
          and r1.get("data_hex") == r2.get("data_hex"),
          json.dumps([r1, r2], ensure_ascii=False, default=str)[:260])

    # 参数名归一只管名字，类型归一到 _addr_arg 在工具体内完成
    check("F2 整数地址在工具内被正确解析（回显地址指向 0x20000000）",
          str(r1.get("addr")).lower() in ("0x20000000", "536870912"), r1)
    a, _ap = norm(server, "read_mem", {"addr": 536870912, "n_bytes": 4})
    check("F2b 参数名归一不越权改类型（原样交给框架校验）",
          a.get("addr") == 536870912, a)

    rwd = await call(server, "read_mem", {"address": 0x20000000, "length": 4})
    check("F3 整数地址 + 别名混用（address= 整数）",
          rwd.get("ok") is True and rwd.get("data_hex") == r2.get("data_hex"), rwd)

    rf = await call(server, "fill_mem", {"addr": 0x20002000, "byte": 0, "count": 4})
    check("F4 fill_mem：addr 传整数可用", rf.get("ok") is True, rf)

    rq = await call(server, "query_memory_map", {"addr": 0x20000000})
    check("F5 query_memory_map：addr 传整数可用", rq.get("ok") is True, rq)

    rb = await call(server, "set_breakpoint", {"expr": 0x08000100})
    ok_bp = rb.get("ok") is True
    if ok_bp:
        await call(server, "clear_breakpoint", {"expr": 0x08000100})
    check("F6 set_breakpoint：expr 传整数可用（0x08000100）", ok_bp, rb)

    # ============ G. 同单位时间同义词 ============
    print("G. 同单位时间同义词（duration_/max_/wait_ ↔ timeout_）")
    for alias, want in (("duration_ms", 50), ("max_ms", 50), ("wait_ms", 50)):
        a, applied = norm(server, "run_timeout", {alias: want})
        check("G1 run_timeout：%s= → timeout_ms=%d（同单位不换算）"
              % (alias, want),
              a.get("timeout_ms") == want and any(alias in x for x in applied),
              (a, applied))

    a, applied = norm(server, "build_project", {"duration_s": 30})
    check("G2 build_project：duration_s= → timeout_s=30",
          a.get("timeout_s") == 30 and bool(applied), (a, applied))
    a, applied = norm(server, "build_project", {"timeout_ms": 30000})
    check("G3 build_project：timeout_ms=30000 → timeout_s=30（跨单位换算）",
          abs(float(a.get("timeout_s", 0)) - 30) < 1e-6, (a, applied))
    a, applied = norm(server, "profile_function", {"timeout_ms": 200, "func": "main"})
    check("G4 profile_function：timeout_ms= → max_ms=200",
          a.get("max_ms") == 200, (a, applied))
    check("G5 interval_/poll_ 不参与同义词（避免静默改变语义）",
          "interval_ms" not in aliases_of_tool("profile_sampling")
          or aliases_of_tool("profile_sampling").get("interval_ms") is None,
          aliases_of_tool("profile_sampling"))

    # ============ E. list_tools 展示 ============
    print("E. list_tools 别名展示")
    tools = {t.name: t for t in await server.list_tools()}

    def desc(n):
        return str(getattr(tools[n], "description", "") or "")

    check("E1 calc_expression 描述含「主名 ← 别名」",
          "参数别名" in desc("calc_expression") and "expr ← " in desc("calc_expression"),
          desc("calc_expression")[-200:])
    check("E2 run_timeout 描述注明毫秒单位与秒别名",
          "timeout_ms（毫秒）" in desc("run_timeout")
          and "timeout_s" in desc("run_timeout"),
          desc("run_timeout")[-200:])
    check("E3 find_symbol 不把真实参数 name 展示为 query 的别名",
          "name" not in desc("find_symbol").split("参数别名")[-1],
          desc("find_symbol")[-260:])
    check("E4 read_mem 不把真实参数 length 展示为 n_bytes 的别名",
          "length" not in desc("read_mem").split("参数别名")[-1],
          desc("read_mem")[-260:])
    d1 = desc("batch")
    await server.list_tools()
    d2 = desc("batch")
    check("E5 重复 list_tools 不叠加别名说明",
          d1 == d2 and d1.count("参数别名") == 1,
          "count=%d" % d1.count("参数别名"))
    check("E6 未定义别名的工具描述不变（如 get_status）",
          "参数别名" not in desc("get_status"), desc("get_status")[-120:])

    print("\n==== 批次25 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
