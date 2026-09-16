# -*- coding: utf-8 -*-
"""批次10 mock 测试：.uvoptx 持久化断点的读取/清理（工具 66→68）。

背景：Keil 把断点持久化写入工程 .uvoptx，下次进调试自动恢复；命令窗口 BK 清不掉，
导致 clear_breakpoint 返回成功但断点仍生效（用户反馈的最大盲区）。
新增 uvoptx 模块 + list_uvoptx_breakpoints / clear_uvoptx_breakpoints 工具；
list_breakpoints 附加 uvoptx 字段；clear_all_breakpoints 支持 include_uvoptx。

覆盖：
- 新工具注册（66→68）
- 解析 .uvoptx 持久断点（number/address/line/filename/enabled）
- 编码容错（UTF-8 与 GBK 均可读）
- 清理：removed 数、备份生成、其余节点保留、清理后再解析为 0
- list_breakpoints 附加 uvoptx 字段
- clear_all_breakpoints(include_uvoptx=True) 一并清理默认工程 .uvoptx
"""
import os
import sys
import time
import json
import asyncio
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402
from mdkdebug import uvoptx as U  # noqa: E402

PORT = 14868
PASS, FAIL = [], []

_UVOPTX_TMPL = """<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<ProjectOpt xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="project_optx.xsd">
  <SchemaVersion>1.0</SchemaVersion>
  <Breakpoint>
    <Bp>
      <Number>0</Number>
      <Type>0</Type>
      <LineNumber>161</LineNumber>
      <EnabledFlag>1</EnabledFlag>
      <Address>134219356</Address>
      <ByteObject>0</ByteObject>
      <BreakByAccess>0</BreakByAccess>
      <BreakIfRCount>1</BreakIfRCount>
      <Filename>D:\\proj\\Src\\%s.c</Filename>
      <Expression>\\\\proj\\../Src/%s.c\\161</Expression>
    </Bp>
    <Bp>
      <Number>1</Number>
      <Type>0</Type>
      <LineNumber>77</LineNumber>
      <EnabledFlag>1</EnabledFlag>
      <Address>134219188</Address>
      <BreakByAccess>0</BreakByAccess>
      <BreakIfRCount>1</BreakIfRCount>
      <Filename>D:\\proj\\Src\\main.c</Filename>
      <Expression>\\\\proj\\../Src/main.c\\77</Expression>
    </Bp>
    <Bp>
      <Number>2</Number>
      <Type>2</Type>
      <LineNumber>0</LineNumber>
      <EnabledFlag>0</EnabledFlag>
      <Address>536870912</Address>
      <BreakByAccess>1</BreakByAccess>
      <BreakIfRCount>1</BreakIfRCount>
      <Filename></Filename>
      <Expression></Expression>
    </Bp>
  </Breakpoint>
  <Tracepoint>
    <THDelay>0</THDelay>
  </Tracepoint>
  <DebugFlag>
    <trace>0</trace>
  </DebugFlag>
</ProjectOpt>
"""


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


def make_sample(d, name="proj", encoding="utf-8"):
    uvoptx = os.path.join(d, f"{name}.uvoptx")
    content = _UVOPTX_TMPL % (name, name)
    with open(uvoptx, "w", encoding=encoding, newline="") as f:
        f.write(content)
    uvprojx = os.path.join(d, f"{name}.uvprojx")
    with open(uvprojx, "w", encoding="utf-8") as f:
        f.write("<Project></Project>")
    return uvprojx, uvoptx


async def main():
    # ---------- 1. 模块级：解析 & 编码容错 ----------
    with tempfile.TemporaryDirectory() as d:
        _, uvoptx = make_sample(d, "proj", "utf-8")
        bps = U.parse_uvoptx_breakpoints(uvoptx)
        check("解析持久断点=3", len(bps) == 3, f"got {len(bps)}")
        check("首条 address_hex=0x800065c", bps[0]["address_hex"] == "0x800065c",
              str(bps[0]))
        check("首条 line=161", bps[0]["line"] == 161, str(bps[0]))
        check("数据断点 enabled=False", bps[2]["enabled"] is False, str(bps[2]))
        check("filename 解析正确", bps[0]["filename"].endswith("proj.c"), str(bps[0]))

        # GBK 编码样本也能读
        d2 = os.path.join(d, "gbk")
        os.makedirs(d2, exist_ok=True)
        _, uvoptx_g = make_sample(d2, "proj", "gbk")
        bps_g = U.parse_uvoptx_breakpoints(uvoptx_g)
        check("GBK 样本解析=3", len(bps_g) == 3, f"got {len(bps_g)}")

        # ---------- 2. 清理：removed/备份/保留/再解析为0 ----------
        r = U.clear_uvoptx_breakpoints(uvoptx)
        check("清理 ok 且 removed=3", r["ok"] and r["removed"] == 3, str(r))
        check("清理生成备份", bool(r["backup"]) and os.path.isfile(r["backup"]), str(r))
        check("清理后解析=0", U.parse_uvoptx_breakpoints(uvoptx) == [], "")
        txt = open(uvoptx, encoding="utf-8").read()
        check("空<Breakpoint>节点保留",
              "<Breakpoint>" in txt and "</Breakpoint>" in txt, "")
        check("其余节点保留(<DebugFlag>)", "<DebugFlag>" in txt, "")
        check("备份保留原断点",
              len(U.parse_uvoptx_breakpoints(r["backup"])) == 3, "")

        # ---------- 3. server 工具层 ----------
        uvprojx2, uvoptx2 = make_sample(d, "proj", "utf-8")
        srv = MockUVSOCKServer("127.0.0.1", PORT).start()
        time.sleep(0.2)
        try:
            server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                                   default_project=uvprojx2)
            tools = {t.name: t for t in await server.list_tools()}
            check("list_uvoptx_breakpoints 已注册",
                  "list_uvoptx_breakpoints" in tools, "")
            check("clear_uvoptx_breakpoints 已注册",
                  "clear_uvoptx_breakpoints" in tools, "")
            check("工具总数=68", len(tools) == 68, f"实际 {len(tools)}")

            # 3a. 读取（project 显式传）
            lv = load(await call(server, "list_uvoptx_breakpoints", {"project": uvoptx2}))
            check("list_uvoptx ok 且 count=3",
                  lv.get("ok") and lv.get("count") == 3, str(lv)[:160])

            # 3b. list_breakpoints 附加 uvoptx 字段（走 default_project）
            lb = load(await call(server, "list_breakpoints", {}))
            check("list_breakpoints 含 uvoptx 字段",
                  isinstance(lb.get("uvoptx"), dict), str(lb)[:160])
            check("list_breakpoints.uvoptx.count=3",
                  (lb.get("uvoptx") or {}).get("count") == 3, str(lb)[:200])

            # 3c. clear_all_breakpoints(include_uvoptx=True) 清理 default_project 的 uvoptx
            ca = load(await call(server, "clear_all_breakpoints", {"include_uvoptx": True}))
            check("clear_all include_uvoptx 清理 uvoptx",
                  (ca.get("uvoptx") or {}).get("removed") == 3, str(ca)[:200])
            after = load(await call(server, "list_breakpoints", {}))
            check("清理后 list_breakpoints.uvoptx.count=0",
                  (after.get("uvoptx") or {}).get("count") == 0, str(after)[:200])

            # 3d. 不存在文件 → ok=False
            nf = load(await call(server, "clear_uvoptx_breakpoints",
                                 {"project": os.path.join(d, "nope.uvoptx")}))
            check("清理不存在文件 ok=False", nf.get("ok") is False, str(nf)[:160])
        finally:
            srv.stop()

    print(f"\n批次10 mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
