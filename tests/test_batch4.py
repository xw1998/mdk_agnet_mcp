# -*- coding: utf-8 -*-
"""批次4 增强工具测试：内存地图/搜索/填充/状态对比/函数耗时/编译错误/map/写外设/异常等待。

覆盖本批新增的 9 个工具：
- query_memory_map  查询内存区域地图
- search_mem        在内存范围内搜索字节序列
- fill_mem          批量填充/清零内存
- snapshot_diff     对比调试状态快照（diff）
- profile_function  函数执行耗时（周期数）分析
- parse_build_errors 解析编译错误输出（AC5/AC6 两种格式）
- parse_map         解析 .map 链接映射文件
- write_peripheral  写入外设寄存器
- wait_fault        运行至异常/断点并自动诊断

profile_function / wait_fault 在 mock 中 run 后目标不会自动停止，
故验证其可调用 + 超时优雅失败路径；成功路径由真机验证。
"""
import os
import sys
import asyncio
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug import mapfile  # noqa: E402

PORT = 14840
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {'' if ok else detail}")


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
                               axf_path=_AXF if os.path.isfile(_AXF) else None)
        tools = {t.name: t for t in await server.list_tools()}
        names = set(tools)
        need = {"query_memory_map", "search_mem", "fill_mem", "snapshot_diff",
                "profile_function", "parse_build_errors", "parse_map",
                "write_peripheral", "wait_fault"}
        check("新工具已注册(9)", need.issubset(names), sorted(need - names))

        # ---- query_memory_map ----
        r = await call(server, "query_memory_map", {})
        d = load(r)
        check("query_memory_map 返回区域列表",
              d.get("ok") is True and d.get("count", 0) >= 9, r[:200])
        regions = {x["name"] for x in d.get("regions", [])}
        for expect in ("FLASH", "SRAM1", "APB1_PERIPH", "DWT", "SCS"):
            check(f"query_memory_map 含 {expect}", expect in regions)
        r = await call(server, "query_memory_map", {"addr": "0x20000000"})
        d = load(r)
        check("query_memory_map 定位 SRAM1", d.get("matched") is True
              and d.get("region", {}).get("name") == "SRAM1", r[:200])
        r = await call(server, "query_memory_map", {"addr": "0xE000ED04"})
        d = load(r)
        check("query_memory_map 定位 SCS", d.get("matched") is True
              and d.get("region", {}).get("name") == "SCS", r[:200])

        # ---- search_mem：先写入魔数再搜索 ----
        wr = await call(server, "write_mem", {"addr": "0x20001000", "data_hex": "DEADBEEF"})
        check("search_mem 前置 write_mem", load(wr).get("ok") is True, r[:200])
        r = await call(server, "search_mem",
                       {"start": "0x20000000", "end": "0x20002000",
                        "pattern_hex": "DEADBEEF"})
        d = load(r)
        check("search_mem 命中魔数地址",
              d.get("ok") is True and d.get("count", 0) >= 1
              and "0x20001000" in d.get("addresses", []), r[:200])
        r = await call(server, "search_mem",
                       {"start": "0x20000000", "end": "0x20002000",
                        "pattern_hex": "01020304"})
        d = load(r)
        check("search_mem 未命中返回 count=0",
              d.get("ok") is True and d.get("count", -1) == 0, r[:200])

        # ---- fill_mem：填充后读回验证 ----
        r = await call(server, "fill_mem", {"addr": "0x20000000", "byte": 170, "count": 64})
        d = load(r)
        check("fill_mem 写入 64 字节", d.get("ok") is True
              and d.get("written", 0) == 64, r[:200])
        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 64})
        d = load(r)
        check("fill_mem 读回为 AA 填充",
              d.get("ok") is True and d.get("data_hex") == "aa" * 64, r[:200])

        # ---- write_peripheral：USART1.BRR 写读回 ----
        r = await call(server, "write_peripheral",
                       {"periph": "USART1", "reg": "BRR", "value": "0x1D4C"})
        d = load(r)
        check("write_peripheral 写读回一致",
              d.get("ok") is True and d.get("match") is True, r[:200])
        r = await call(server, "write_peripheral",
                       {"periph": "USART1", "reg": "NOPE", "value": "0x1"})
        d = load(r)
        check("write_peripheral 未知寄存器报错", d.get("ok") is False
              and "无寄存器" in d.get("error", ""), r[:200])

        # ---- snapshot_diff：首次建基线，二次对比 ----
        r = await call(server, "snapshot_diff", {"globals": []})
        d = load(r)
        if d.get("ok") is False and "符号定位未就绪" in d.get("error", ""):
            check("snapshot_diff 无 .axf 时优雅报错", True)
        else:
            check("snapshot_diff 首次创建基线", d.get("created") is True, r[:200])
            r = await call(server, "snapshot_diff", {"globals": []})
            d = load(r)
            check("snapshot_diff 二次对比", d.get("created") is False
                  and "changed_registers" in d, r[:200])

        # ---- profile_function：mock run 后不停 -> 超时优雅失败 ----
        r = await call(server, "profile_function", {"func": "0x8000DB4", "max_ms": 500})
        d = load(r)
        check("profile_function 可调用(超时优雅失败)", d.get("ok") is False
              and ("未到达" in d.get("error", "") or "超时" in d.get("error", "")), r[:300])

        # ---- wait_fault：mock run 后不停 -> 超时优雅失败 ----
        r = await call(server, "wait_fault", {"timeout_ms": 500})
        d = load(r)
        check("wait_fault 可调用(超时优雅失败)", d.get("ok") is False
              and "未停止" in d.get("error", ""), r[:300])

        # ---- parse_build_errors：AC6 + AC5 混合 ----
        text = (
            "C:/proj/main.c:12:5: error: use of undeclared identifier 'x'\n"
            "C:/proj/main.c(20): warning:  #188-D: enumerated type mixed with another type\n"
            "C:/proj/uart.c:8:3: warning: unused variable 'tmp'\n"
        )
        r = await call(server, "parse_build_errors", {"errors_text": text})
        d = load(r)
        check("parse_build_errors 解析 AC6+AC5",
              d.get("ok") is True and d.get("count", 0) == 3
              and d.get("error_count", 0) == 1 and d.get("warning_count", 0) == 2, r[:300])
        items = d.get("items", [])
        check("parse_build_errors 字段完整",
              all({"file", "line", "level", "message"} <= set(i) for i in items), r[:300])

        # ---- parse_map：无 .map 时报错 + 单元解析 ----
        r = await call(server, "parse_map", {})
        d = load(r)
        if d.get("ok") is True:
            check("parse_map 解析成功", "program_size" in d or "sections" in d, r[:300])
        else:
            check("parse_map 无 .map 时报错", "未找到" in d.get("error", ""), r[:300])
        mp = mapfile.parse_map_text(
            "Program Size: Code=1234 RO-data=10 RW-data=20 ZI-data=100\n"
            "  Section          Base    Size     Type  Attr  Object\n"
            "  .text           08000000 00000428 Data  RO   main.o\n")
        check("mapfile.parse_map_text 解析 Program Size",
              mp.get("ok") is True and mp.get("program_size", {}).get("code") == 1234,
              str(mp)[:200])

        # ---- 汇总 ----
        print(f"\n===== 批次4 mock 测试汇总: {len(PASS)} 通过 / {len(FAIL)} 失败 =====")
        if FAIL:
            print("失败项:", FAIL)
            sys.exit(1)
    finally:
        srv.stop()


if __name__ == "__main__":
    asyncio.run(main())
