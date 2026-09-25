# -*- coding: utf-8 -*-
"""批次65 mock 测试：按 docs/mcp-issues.md 的台账修掉两条真缺陷 + 两条「文案与事实不符」。

来源：F427 一轮 SWD trace 调试（2026-09-20）的台账，仍未修项里最便宜、也最容易再咬人的两条：

  #5 reset_connection 之后直接用 trace 报「没有活着的调试会话」
     根因：UVClient 的 socket 是**懒连接**，而 reset_connection 之后 phy.is_connected 是
     False——linkio._try_keil / rtos 只看这一个标志，就把「还没连」当成「链路不可用」
     （rtrace 早在 batch50 修过同一处，另两处漏了）。报错还把人带去查硬件/重启 Keil。
     修法：把「先主动建链」收成 linkio.keil_client()，三处共用。

  #4 max_session_events 在 MCP 面上不存在
     根因：trace.py::swd_read() 的 Python 签名有它，@server.tool 包装的 trace_swd_read
     没接出来——调用方看不到也传不进去（「修复手段不在默认工具面上」的同类）。

顺带两处「文案与事实不符」（都会把人带偏）：
  - consistent="run" 在描述里仍只是「可选」，而真机实测：目标在跑时稳定报 swd-read-untrusted；
  - serial 提示写死 port="COM9"，而同一份返回的 available_ports 是 COM3。

运行：python -m tests.test_batch65
"""
import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

from mdkdebug import server as SV          # noqa: E402
from mdkdebug import linkio as LK          # noqa: E402
from mdkdebug import serialmon as SM       # noqa: E402
from mdkdebug import trace as TR           # noqa: E402

PORT = 15515
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def src(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()

def call(srv, name, args=None):
    r = asyncio.run(srv.call_tool(name, args or {}))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:
        return {"_raw": txt[:400]}

# ---------------------------------------------------------------- 假客户端
class FakePhy:
    def __init__(self):
        self.is_connected = False
        self.opens = 0
    def open(self):
        self.opens += 1
        self.is_connected = True
    def close(self):
        self.is_connected = False

class FakeClient:
    """够用的替身：只有 keil_client 会碰的那几个属性。"""
    def __init__(self, raise_on_ensure=None):
        self.phy = FakePhy()
        self.idle_timeout = 300.0
        self._last_used = 0.0
        self.ensure_calls = 0
        self._raise = raise_on_ensure
    def _ensure_connected(self):
        self.ensure_calls += 1
        if self._raise:
            raise self._raise
        if not self.phy.is_connected:
            self.phy.open()

# ======================================================================
def group_a():
    print("A. #5：链路选择要主动建链（reset_connection 之后不该再要「预热」）")
    old = getattr(SV, "_client", None)
    try:
        # ---- A1/A2 未连接 -> 自动建链，链路可用 ----
        c = FakeClient()
        SV._client = c
        lk, err = LK._try_keil()
        check("A1 phy 未连接时不再是「会话没连着」，而是自动建好链并可用",
              lk is not None and err is None and c.phy.opens == 1, (err, c.phy.opens))

        # ---- A3 已连接 -> 不重复建链 ----
        c2 = FakeClient()
        c2.phy.is_connected = True
        SV._client = c2
        lk2, err2 = LK._try_keil()
        check("A3 已经连着时完全不碰建链（不白开一次 TCP）",
              lk2 is not None and c2.ensure_calls == 0 and c2.phy.opens == 0,
              (err2, c2.ensure_calls, c2.phy.opens))

        # ---- A4 建链失败 -> 透出真实原因（不许再含糊成「先 enter_debug」） ----
        SV._client = FakeClient(raise_on_ensure=RuntimeError("ConnectionRefusedError: 10061"))
        lk3, err3 = LK._try_keil()
        check("A4 建链真失败时说的是「连不上 UVSOCK」并带原始原因（方向对）",
              lk3 is None and "连不上 Keil UVSOCK" in str(err3)
              and "10061" in str(err3), err3)

        # ---- A5 没客户端实例也要说清楚 ----
        SV._client = None
        lk4, err4 = LK._try_keil()
        check("A5 本进程还没有客户端实例 -> 说清是这一层（不是链路坏了）",
              lk4 is None and "还没有 Keil 客户端实例" in str(err4), err4)

        # ---- A6 三处共用一份实现（否则漏一处就复现同一个坑） ----
        lk_src, rt_src, rtrace_src = (src("mdkdebug/linkio.py"), src("mdkdebug/rtos.py"),
                                      src("mdkdebug/rtrace.py"))
        check("A6 linkio 里 _ensure_connected 只出现一处（就是 keil_client）",
              lk_src.count("c._ensure_connected()") == 1, lk_src.count("c._ensure_connected()"))
        check("A7 rtrace / rtos 都改走 linkio.keil_client（不再各自裸判 is_connected）",
              rtrace_src.count("_linkio.keil_client()") == 1
              and rt_src.count("_linkio.keil_client()") == 1, None)
        check("A8 全仓再没有「只看 phy.is_connected 就判链路不可用」的地方",
              rtrace_src.count("c.phy.is_connected") == 0
              and rt_src.count('phy, "is_connected"') == 0, None)
    finally:
        SV._client = old

# ======================================================================
def group_b():
    print("B. #4：max_session_events 必须真的在工具面上、且传得进去")
    srv = SV.create_server(port=PORT, toolsets="all")
    tools = {}
    for t in asyncio.run(srv.list_tools()):
        tools[t.name] = t
    t = tools.get("trace_swd_read")
    check("B1 trace_swd_read 在工具面上", t is not None, sorted(tools)[:5])
    if t:
        props = set((getattr(t, "input_schema", None) or {}).get("properties", {}))
        check("B2 工具签名里有 max_session_events（此前只在 Python 签名里有）",
              "max_session_events" in props, sorted(props))
        check("B3 描述里写明它是会话内存上限、以及「比压 limit 对症」",
              "会话内存上限" in (t.description or "")
              and "session_events_dropped" in (t.description or ""),
              (t.description or "")[:120])
    orig = TR.swd_read
    seen = {}
    try:
        TR.swd_read = lambda **kw: (seen.update(kw) or {"ok": True})
        r = call(srv, "trace_swd_read", {"max_session_events": 1234})
        check("B4 传进去的值真的到了 swd_read（不是被包装吞掉）",
              seen.get("max_session_events") == 1234, (r, seen))
        seen.clear()
        r2 = call(srv, "trace_swd_read", {})
        check("B5 不传时用服务端默认（500000），不是 0/None",
              seen.get("max_session_events") == 500000, seen)
    finally:
        TR.swd_read = orig

# ======================================================================
def group_c():
    print("C. 文案与事实对齐：run 的实测结论、reset_connection 的自述")
    tr_src = src("mdkdebug/trace.py")
    check("C1 consistent=run 的实测结论写进描述（F427 上稳定报 swd-read-untrusted）",
          "实测结论（F427 + DAPLink）" in tr_src and "别为了省那几毫秒去选它" in tr_src, None)
    cl_src = src("mdkdebug/client.py")
    check("C2 reset_connection 的 msg 改成事实：下次调用会自动建链（不必预热）",
          "自动重新建立" in cl_src and "不必先做一次读来预热" in cl_src, None)

# ======================================================================
def group_d():
    print("D. 串口提示：有真值就用真值，别写死一个示例号")
    old_mon, old_lp = SM._monitor, SM.list_ports
    try:
        SM._monitor = None
        SM.list_ports = lambda: [{"port": "COM3", "desc": "STLink VCP"}]
        out = SM.read_lines()
        check("D1 提示写本机真实端口（COM3），不再是写死的 COM9",
              "COM3" in out["hint"] and "COM9" not in out["hint"], out["hint"])
        out2 = SM.write_bytes(b"x", wait_ms=0)
        check("D2 serial_write 同理", "COM3" in out2["hint"] and "COM9" not in out2["hint"],
              out2["hint"])
        SM.list_ports = lambda: []
        out3 = SM.read_lines()
        check("D3 一个口都没有时不硬编示例号，改为指向 serial_list_ports",
              "COM9" not in out3["hint"] and "serial_list_ports" in out3["hint"], out3["hint"])
    finally:
        SM._monitor, SM.list_ports = old_mon, old_lp
    err_src = src("mdkdebug/errors.py")
    check("D4 modbus-no-session 的下一步不再写死端口号（没有事实可依时不冒充事实）",
          'port=\\"COM9\\", baud=9600' not in err_src
          and "别照抄示例号" in err_src, None)

def main():
    print("批次65：台账两条真缺陷（#5 链路建链 / #4 参数出不来）+ 两处文案与事实不符")
    group_a(); group_b(); group_c(); group_d()
    print("\n==== 批次65 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
