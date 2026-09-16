# -*- coding: utf-8 -*-
"""批次12 mock 测试：reset 自动 stop + read_locals 函数入口参数回退。

用户反馈：
1) 目标已在运行时 reset 直接报 status=11 失败 —— 应自动先 stop 再复位。
2) read_locals 在函数入口读第 5 个及之后的栈传参（如 period_ms）返回 0 —— 疑似
   prologue 阶段 DWARF 位置描述不准，应退化到寄存器/栈回退读取。

改：
- client.reset()：复位失败且目标在运行时，自动 stop 后重试复位，成功则标 auto_stopped。
- Locator.local_var_meta(pc)：返回函数 {low_pc, high_pc, vars:[{name,is_param,param_index}]}，
  形参按声明顺序编号，供 AAPCS 回退定位。
- server：_near_function_entry(pc, meta) 判断是否位于函数入口；
  _aapcs_param_fallback(client, idx, regs) 按 AAPCS 回退（前4个 R0-R3，第5个起栈）；
  read_locals 仅在"入口 + 参数求值取不到有效值"时回退，并在输出里标注 param_fallback。
"""
import os
import sys
import time
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import (  # noqa: E402
    create_server, _near_function_entry, _aapcs_param_fallback,
)
from mdkdebug.locator import Locator  # noqa: E402

PORT = 14880
PASS, FAIL = [], []
_MDK_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
HAVE_AXF = os.path.isfile(_MDK_AXF)

MAIN_PC = 0x08000DB4          # main 入口（Thumb 对齐后）
WP_PC = 0x08000634            # HAL_GPIO_WritePin（3 个形参）


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


class FakeClient:
    """只实现参数回退需要的 calc_expression / read_mem。"""

    def __init__(self, regs=None, mem=None):
        self.regs = regs or {}
        self.mem = mem or {}

    def calc_expression(self, name):
        if name in self.regs:
            return {"ok": True, "value": self.regs[name], "value_type": "uint"}
        return {"ok": False, "value": None}

    def read_mem(self, addr, n):
        if addr in self.mem:
            return {"ok": True, "data_hex": int(self.mem[addr]).to_bytes(4, "little").hex()}
        return {"ok": False, "data_hex": ""}


async def main():
    # ---------- 1. _near_function_entry ----------
    meta = {"low_pc": 0x08000DB5, "high_pc": 0x08000DF0, "vars": []}
    check("入口首字节判 True", _near_function_entry(0x08000DB4, meta) is True)
    check("入口+8 判 True", _near_function_entry(0x08000DBC, meta) is True)
    check("入口+100 判 False", _near_function_entry(0x08000E20, meta) is False)
    check("meta=None 判 False", _near_function_entry(0x08000DB4, None) is False)
    check("pc 非 int 判 False", _near_function_entry("x", meta) is False)

    # ---------- 2. _aapcs_param_fallback ----------
    fc = FakeClient(regs={"R0": 0x2A}, mem={0x2002FF10: 1234})
    fb0 = _aapcs_param_fallback(fc, 0, {})
    check("idx0 从 R0 回退", bool(fb0) and fb0["value"] == 0x2A
          and fb0["source"] == "register:R0" and fb0["fallback"] is True, str(fb0))
    check("idx0 用 regs 的 r0", (_aapcs_param_fallback(FakeClient(), 0, {"r0": 0x55}) or {}).get("value") == 0x55)
    check("idx0 值为 0 不回退", _aapcs_param_fallback(FakeClient(regs={"R0": 0}), 0, {}) is None)
    fb4 = _aapcs_param_fallback(fc, 4, {"sp": 0x2002FF10})
    check("idx4 从栈回退", bool(fb4) and fb4["value"] == 1234
          and fb4["source"].startswith("stack:"), str(fb4))
    fb5 = _aapcs_param_fallback(fc, 5, {"sp": 0x2002FF0C})
    check("idx5 栈偏移正确(+4)", bool(fb5) and fb5["value"] == 1234, str(fb5))
    check("idx4 无 sp 不回退", _aapcs_param_fallback(fc, 4, {}) is None)
    check("idx=None 不回退", _aapcs_param_fallback(fc, None, {}) is None)
    check("idx 负数不回退", _aapcs_param_fallback(fc, -1, {}) is None)

    # ---------- 3. Locator.local_var_meta ----------
    if HAVE_AXF:
        loc = Locator(_MDK_AXF)
        m_main = loc.local_var_meta(MAIN_PC)
        check("local_var_meta 定位 main",
              bool(m_main) and (m_main["low_pc"] & ~1) == MAIN_PC, str(m_main)[:120])
        check("local_var_meta 含变量", bool(m_main) and len(m_main["vars"]) >= 1, str(m_main)[:120])
        check("local_var_meta 无函数地址返回 None", loc.local_var_meta(0x09000000) is None)
        m_wp = loc.local_var_meta(WP_PC)
        if m_wp:
            ps = [v for v in m_wp["vars"] if v.get("is_param")]
            check("形参按声明顺序编号 0/1/2",
                  [p.get("param_index") for p in ps[:3]] == [0, 1, 2], str(ps[:4]))
            check("非形参 param_index 为 None",
                  all(v.get("param_index") is None for v in m_wp["vars"] if not v.get("is_param")), "")
        else:
            check("local_var_meta 能定位 HAL_GPIO_WritePin", False, "返回 None")
        check("local_variables 仍兼容", loc.local_variables(MAIN_PC) is not None)
    else:
        print("跳过：未找到 mdk_test.axf")

    # ---------- 4. reset 自动 stop（端到端） ----------
    srv = MockUVSOCKServer("127.0.0.1", PORT)
    srv.reset_requires_stop = True
    srv.start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                               axf_path=_MDK_AXF if HAVE_AXF else None)
        r = load(await call(server, "run", {}))
        check("run 成功", bool(r.get("ok")), str(r)[:120])
        check("mock 处于运行状态", srv.running is True, str(srv.running))
        r2 = load(await call(server, "reset", {}))
        check("运行中 reset 最终成功", r2.get("ok") is True, str(r2)[:200])
        check("标注 auto_stopped", r2.get("auto_stopped") is True, str(r2)[:200])
        check("reset 尝试了 2 次", srv.reset_calls == 2, str(srv.reset_calls))
        check("mock 已停止", srv.running is False, str(srv.running))

        # 已停止时复位：一次成功，无 auto_stopped
        srv.reset_calls = 0
        r3 = load(await call(server, "reset", {}))
        check("停止态 reset 直接成功", r3.get("ok") is True, str(r3)[:160])
        check("停止态无 auto_stopped", not r3.get("auto_stopped"), str(r3)[:160])
        check("停止态只调 1 次", srv.reset_calls == 1, str(srv.reset_calls))

        # ---------- 5. read_locals 端到端（入口处不误触发回退） ----------
        if HAVE_AXF:
            rl = load(await call(server, "read_locals", {}))
            check("read_locals ok", rl.get("ok") is True, str(rl)[:200])
            check("read_locals 返回 locals 列表", isinstance(rl.get("locals"), list), str(rl)[:160])
            check("main 无参数时不触发回退", not rl.get("param_fallback"), str(rl)[:200])
    finally:
        srv.stop()

    print(f"\n批次12 mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
