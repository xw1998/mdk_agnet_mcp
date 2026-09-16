# -*- coding: utf-8 -*-
"""批次11 mock 测试：地址符号覆盖判定 + 调用栈置信度标注。

用户反馈：
1) set_breakpoint 对符号表覆盖不到的地址（如 App 区 0x08080011）会返回毫不相关的
   file/line（报成内核某文件某行），易误导。
2) 调用栈启发式在栈内容陈旧时给出错误帧（野地址混在真实帧中间）。

改：
- Locator 增加 _load_code_ranges/is_covered/locate；断点系列改用 locate，未覆盖时
  给 location_note（仅按地址下断），不报无关 file/line。
- _backtrace 每帧带 origin(pc/lr/stack) 与 confidence(high/low)，栈扫描遇到未覆盖/
  无法解析的帧标 low 并停止后续扫描（截断）。

覆盖：
- is_covered/locate：符号内→covered=True 且有 file/line；符号外→False 且 file/line=None
- _backtrace：PC/LR 帧 high；栈内有效帧 high；栈内野地址帧 low 且其后截断
- set_breakpoint：符号外地址返回 location_note、无 file/line；符号内地址正常给 file/line
"""
import os
import sys
import time
import json
import asyncio
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _backtrace  # noqa: E402
from mdkdebug.locator import Locator  # noqa: E402

PORT = 14870
PASS, FAIL = [], []
_MDK_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
HAVE_AXF = os.path.isfile(_MDK_AXF)


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
    """只实现 _backtrace 需要的 read_mem。"""
    def __init__(self, raw: bytes):
        self.raw = raw

    def read_mem(self, addr, n):
        return {"ok": True, "data_hex": self.raw[:n].hex()}


async def main():
    if not HAVE_AXF:
        print("跳过：未找到 mdk_test.axf")
        return

    loc = Locator(_MDK_AXF)

    # ---------- 1. 符号覆盖判定 ----------
    syms = loc.search_symbols("main", limit=10)
    m = [s for s in syms if s["name"] == "main"]
    check("能取到 main 符号", bool(m), str(syms[:3]))
    in_addr = int(m[0]["addr"], 16) if m else 0x08000db5
    check(f"符号内 {hex(in_addr)} covered=True", loc.is_covered(in_addr) is True, "")
    l_in = loc.locate(in_addr)
    check("符号内 locate 有 file/line",
          bool(l_in.get("file")) and l_in.get("line") is not None, str(l_in))

    out_addr = 0x08080011  # 用户例子：App 区，内核 axf 覆盖不到
    check(f"符号外 {hex(out_addr)} covered=False", loc.is_covered(out_addr) is False, "")
    l_out = loc.locate(out_addr)
    check("符号外 locate 无 file/line 且 covered=False",
          l_out.get("file") is None and l_out.get("line") is None
          and l_out.get("covered") is False, str(l_out))
    check("符号外 locate 保留 nearest_file 供参考",
          "nearest_file" in l_out, str(l_out))

    check("全 0 地址覆盖判据不误报", loc.is_covered(0x09000000) is False, "")

    # Thumb 位对齐：Cortex-M 函数符号 st_value 的 bit0=1，而 Keil/行号表用偶数地址，
    # 二者相差 1 字节，不应被判成"不在符号范围"。
    if m:
        even = in_addr & ~1
        check(f"Thumb 偶数地址 {hex(even)} covered=True", loc.is_covered(even) is True, "")
        l_even = loc.locate(even)
        check("Thumb 偶数地址 locate 有 file/line",
              bool(l_even.get("file")) and l_even.get("line") is not None, str(l_even))
    check("符号外地址清 Thumb 位后仍 covered=False",
          loc.is_covered(out_addr & ~1) is False, "")

    # ---------- 2. _backtrace 置信度标注 ----------
    # 栈：[符号内返回地址, 野地址 0x08080011]，LR=None
    stk = struct.pack("<II", 0x08000195, out_addr)
    frames = _backtrace(FakeClient(stk), loc, in_addr, None, 0x20000000, stack_bytes=8)
    check(f"帧数=3(PC+栈有效+栈野值截断) 实际={len(frames)}", len(frames) == 3, str(frames))
    check("帧0 origin=pc/confidence=high",
          frames and frames[0]["origin"] == "pc" and frames[0]["confidence"] == "high",
          str(frames[0]) if frames else "")
    if len(frames) >= 2:
        check("帧1 origin=stack/confidence=high",
              frames[1]["origin"] == "stack" and frames[1]["confidence"] == "high",
              str(frames[1]))
    if len(frames) >= 3:
        check("帧2 野地址 confidence=low",
              frames[2]["confidence"] == "low", str(frames[2]))
        check("帧2 带 note 说明",
              bool(frames[2].get("note")), str(frames[2]))
        check("低置信度帧后已截断(无更多帧)", len(frames) == 3, "")

    # ---------- 3. set_breakpoint 使用覆盖判定 ----------
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=5.0,
                               axf_path=_MDK_AXF)
        # 3a. 符号外地址 → location_note，无 file/line
        r1 = load(await call(server, "set_breakpoint", {"expr": hex(out_addr)}))
        check("符号外断点 ok", bool(r1.get("ok")), str(r1)[:160])
        check("符号外断点给 location_note", bool(r1.get("location_note")), str(r1)[:200])
        check("符号外断点无 file/line",
              not r1.get("file") and not r1.get("line"), str(r1)[:200])
        # 3b. 符号内地址 → 正常 file/line，无 location_note
        r2 = load(await call(server, "set_breakpoint", {"expr": hex(in_addr)}))
        check("符号内断点有 file/line",
              bool(r2.get("file")) and r2.get("line") is not None, str(r2)[:200])
        check("符号内断点无 location_note", not r2.get("location_note"), "")
    finally:
        srv.stop()

    print(f"\n批次11 mock: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
