# -*- coding: utf-8 -*-
"""批次48 mock 测试：状态一致性五项硬伤。

来源：用户真机踩到的五个坑，全归到「工具记录的状态与真实硬件/真实布局不同步」：

  ① clear_all_watchpoints 只清 Keil 断点表、不清 DWT 硬件比较器 → 「run 即停」的鬼魂断点
  ② reloc_delta 跨编译静默失效 → 读出全 0 却没有任何告警，差点被引向「变量被清零」
  ③ run_to_line 的 file:line 会撞同名行号 → 解析到物理上不可能的地址，白费一次触发
  ④ 符号解析双轨不打通：read_variable 走 Keil 表达式挂了，find_symbol 走 ELF 却能查到
  ⑤ flash_debug 返回体过肥：几万字 build 日志埋掉 5 行关键结论

   A 工具面：注册总数 174、reloc_check 归 symbol 组、只读注解、outctl 登记
   B reloc 纯逻辑：段挑选避开退化块 / 指纹比对 / delta 反推
   C reloc.verify：confirmed / likely-wrong / unreadable / no-sample，且 ok 与 confirmed 分开
   D reloc.derive_from_pc：唯一命中算出 delta；多处命中不猜；找不到如实说；没有 PC 不冒充
   E DWT 槽位：armed 判定 / 清完回读复核 / 写不进不撒谎 / 读不到不冒充已清
   F 工具集成：clear_all_watchpoints 报 ghost_slots、dwt=false 不碰硬件、
     写不进时 ok=false；clear_watchpoint 的鬼魂兜底
   G read_variable 双轨打通：Keil 挂 → ELF 兜底；两轨都不通 → 如实报错；成员表达式不硬兜
   H run_to_line 触发前守卫：四类可疑目标默认拒绝且**不设断点**、allow_suspect 放行、
     拿不到 PC 时注明 skipped
   I locator.line_to_addr_ex / func_at：同名歧义、fuzz、区间反查
   J outctl 日志摘录：默认摘（头+尾+关键行）、full=true 原样、短日志完全不变

运行：python -m tests.test_batch48
"""
import os
import sys
import json
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import outctl as O            # noqa: E402
from mdkdebug import reloc as R             # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug.locator import Locator        # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def gsize(g):
    return len(TB.TOOLSETS.get(g) or [])

def call(srv, name, args):
    r = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:
        return {"_raw": txt}

# ======================================================================
class MemClient:
    """稀疏内存模型：regions 是 {基址: bytes}，支持跨块读、覆盖写。"""

    def __init__(self, regions=None, write_fail=(), read_fail=()):
        self.regions = dict(regions or {})
        self.write_fail = set(int(x) for x in write_fail)
        self.read_fail = set(int(x) for x in read_fail)
        self.reads = []
        self.writes = []
        self.bp_calls = []
        self.cleared_bp = []

    def _base(self, addr):
        best = None
        for b, data in self.regions.items():
            if b <= addr < b + len(data) and (best is None or b > best):
                best = b
        return best

    def read_mem(self, addr, n):
        addr, n = int(addr), int(n)
        self.reads.append((addr, n))
        if addr in self.read_fail:
            return {"ok": False, "error": "读失败(mock) @0x%X" % addr}
        b = self._base(addr)
        if b is None:
            return {"ok": False, "error": "无模拟内存(mock) @0x%X" % addr}
        d = self.regions[b][addr - b:addr - b + n]
        if len(d) < n:
            return {"ok": False, "error": "越界(mock) @0x%X" % addr}
        return {"ok": True, "data_hex": d.hex(), "ascii": "", "address": hex(addr),
                "n_bytes": n}

    def write_mem(self, addr, data):
        addr, data = int(addr), bytes(data)
        self.writes.append((addr, data))
        if addr in self.write_fail:
            return {"ok": False, "error": "写失败(mock) @0x%X" % addr}
        b = self._base(addr)
        if b is None:
            # 未映射地址写不进去：真实硬件上写不存在的区域同样不成功。
            # 这里不能假装成功，否则「DWT 读不到」的用例会被 mock 自己伪造出可回读的 0。
            return {"ok": False, "error": "无模拟内存(mock) @0x%X" % addr}
        buf = bytearray(self.regions[b])
        off = addr - b
        if off + len(data) > len(buf):
            buf.extend(b"\x00" * (off + len(data) - len(buf)))
        buf[off:off + len(data)] = data
        self.regions[b] = bytes(buf)
        return {"ok": True}

    # ---- Keil/UVSOCK 侧够用的桩 ----
    def set_breakpoint(self, target, *a, **k):
        self.bp_calls.append(target)
        return {"ok": True, "address": str(target), "cleared_by": "keil_number"}

    def clear_breakpoint(self, target, *a, **k):
        self.cleared_bp.append(target)
        return {"ok": True, "cleared_by": "keil_number", "status_text": "ok(mock)"}

    def list_breakpoints_real(self):
        return {"ok": True, "count": 0, "breakpoints": []}

    def exec_command_checked(self, cmd, settle=0.2):
        return {"ok": True, "command": cmd, "status_text": "ok(mock)"}

    def calc_expression(self, expr):
        return {"ok": False, "expression": expr, "error": "表达式不可用(mock)"}

    def get_status(self):
        return {"running": False, "status_text": "stopped(mock)"}

    def read_cpu_registers_stable(self):
        return {"ok": True, "pc": 0x08000120}

    def run(self):
        return {"ok": True, "status": 22}

    def wait_breakpoint(self, addrs, timeout_s=10.0):
        return {"ok": True, "hit": True, "hit_address": addrs[0] if addrs else None,
                "waited_ms": 3, "new_stop_basis": "mock", "hit_confidence": "high",
                "pc_confidence": "high",
                "registers": {"pc": addrs[0] if addrs else 0x08000120}}

    def read_variable(self, name, count=0, read_memory=True):
        return {"ok": False, "name": name, "error": "变量不存在(mock)"}

class FakeLocator:
    """够用的假定位器：行号解析与函数反查都可注入。"""

    def __init__(self, line_ex=None, funcs=None, symbols=None, covered=True):
        self._line_ex = line_ex
        self._funcs = funcs or {}          # addr -> {name,start,end}
        self._symbols = symbols or {}      # name -> {addr,type,size}
        self._covered = covered

    def is_ready(self):
        return True

    def line_to_addr_ex(self, file, line):
        d = dict(self._line_ex or {})
        d.setdefault("file", file)
        d.setdefault("line", line)
        d.setdefault("addr", None)
        return d

    def func_at(self, addr):
        return self._funcs.get(int(addr) & ~1)

    def is_covered(self, addr):
        return self._covered

    def symbol_addr(self, name):
        return self._symbols.get(name)

    def addr_to_location(self, addr):
        return {"address": int(addr), "file": "main.c", "line": 12}

    def read_source(self, file, line, context=3):
        return {"file": file, "line": line, "source": [{"lineno": line, "code": "x();"}]}

def use_locator(loc):
    old = SV._symbol_cfg.get("locator")
    SV._symbol_cfg["locator"] = loc
    return lambda: SV._symbol_cfg.__setitem__("locator", old)

def use_client(c):
    old = SV._client
    SV._client = c
    return lambda: setattr(SV, "_client", old)

def patch_segments(segs):
    old = R.load_segments
    R.load_segments = lambda path: segs
    return lambda: setattr(R, "load_segments", old)

# ======================================================================
def section_a():
    print("A. 工具面与注解")
    total = sum(len(v) for v in TB.TOOLSETS.values()) + len(TB.ALWAYS)
    check("A1 注册工具总数 174（分组表 170 + 常驻元工具 4）", total == 174, total)
    check("A2 reloc_check 归在 symbol 组（组规模 8->9）",
          "reloc_check" in (TB.TOOLSETS.get("symbol") or []) and gsize("symbol") == 9,
          gsize("symbol"))
    an = A.annotations_for("reloc_check")
    check("A3 reloc_check 标只读（只读 ELF + 读内存，不改状态）",
          an.get("readOnlyHint") is True and an.get("destructiveHint") is False, an)
    allnames = set(TB.ALWAYS)
    for v in TB.TOOLSETS.values():
        allnames |= set(v)
    bad = A.check_surface(sorted(allnames))
    check("A4 annotate.check_surface 在 174 个工具上无问题", not bad, bad)
    check("A5 outctl 把编译/烧录系列登记为日志类工具",
          O.LOG_TOOLS == {"flash_debug", "build_project", "rebuild_project",
                          "clean_project", "flash_download", "build_and_flash"},
          sorted(O.LOG_TOOLS))
    for t in sorted(O.LOG_TOOLS):
        check("A6 %s 同时在高输出与日志两类里（才能拿到 full 参数）"
              % t, t in O.HIGH_OUTPUT and t in O.LOG_TOOLS, "")
    su = O.summary()
    check("A7 outctl.summary 如实报日志摘录参数",
          su.get("log_tools") and su["log_excerpt"]["head_lines"] == O.LOG_HEAD_LINES
          and "full=true" in su["log_excerpt"]["note"], su.get("log_excerpt"))

def section_b():
    print("B. reloc 纯逻辑")
    segs = [{"name": ".text", "vaddr": 0x08000000, "size": 64, "offset": 0,
             "data": bytes(range(64))}]
    picks = R._pick_samples(segs, 16, 4)
    check("B1 取样块全部来自段内且长度正确",
          len(picks) >= 2 and all(len(c) == 16 and 0x08000000 <= a < 0x08000040
                                  for a, c in picks), picks)
    deg = [{"name": ".bss", "vaddr": 0x20000000, "size": 128, "offset": 0,
            "data": b"\x00" * 128}]
    check("B2 全 0x00/全 0xFF 的段不产生指纹（在哪儿都长得一样，会给出假确定感）",
          R._pick_samples(deg, 16, 4) == [], R._pick_samples(deg, 16, 4))
    mixed = [{"name": ".text", "vaddr": 0x08000000, "size": 64, "offset": 0,
              "data": bytes([1, 2, 3, 4] * 16)},
             {"name": ".bss", "vaddr": 0x20000000, "size": 64, "offset": 0,
              "data": b"\xff" * 64}]
    check("B3 退化段被跳过、非退化段照用",
          all(a < 0x20000000 for a, _ in R._pick_samples(mixed, 16, 8)), "")
    check("B4 _is_degenerate 判定", R._is_degenerate(b"\x00" * 4)
          and R._is_degenerate(b"\xff" * 4) and not R._is_degenerate(b"\x00\x01"))
    check("B5 delta 格式化/有符号化",
          R._fmt_delta(0xF000) == "0xF000" and R._signed(0xF000) == 0xF000
          and R._signed(0xFFFFFF00) == -256, (R._fmt_delta(0xF000),
                                              R._signed(0xFFFFFF00)))
    hits = R._find_pattern_in_elf(
        [{"name": ".text", "vaddr": 0x1000, "size": 12, "offset": 0,
          "data": b"aabbAABBccdd"}], b"AABB", limit=4)
    check("B6 在 ELF 段里定位字节模式得到链接地址",
          hits == [{"link_address": 0x1004, "segment": ".text"}], hits)
    check("B7 ELF 段读不到时 image_bytes_at 返回 None 而不是抛错",
          R.image_bytes_at("不存在的文件.axf", 0x1000, 4) is None)

def section_c():
    print("C. reloc.verify 的结论（ok 只表示检查跑完，confirmed 才表示偏移被证实）")
    img = bytes([(i * 37 + 11) & 0xFF for i in range(512)])
    segs = [{"name": ".text", "vaddr": 0x08000000, "size": 512, "offset": 0,
             "data": img}]
    undo = patch_segments(segs)
    try:
        good = MemClient({0x08000000 + 0xF000: img})
        v = R.verify(good, "x.axf", 0xF000)
        check("C1 偏移正确 -> delta-confirmed 且 confirmed=true",
              v["verdict"] == "delta-confirmed" and v["confirmed"] is True
              and v["matched"] == v["samples"] > 0, v)
        wrong = MemClient({0x08000000 + 0xF000: img, 0x08000000: b"\x00" * 512})
        v2 = R.verify(wrong, "x.axf", 0)
        check("C2 偏移错误 -> delta-likely-wrong，且话里点明「不要把全 0 当变量被清零」",
              v2["verdict"] == "delta-likely-wrong" and v2["confirmed"] is False
              and "被清零" in v2["note"] and v2["ok"] is True, v2)
        none = MemClient({})
        v3 = R.verify(none, "x.axf", 0xF000)
        check("C3 一个样本都读不到 -> unreadable 且 ok=false（不冒充已验证）",
              v3["verdict"] == "unreadable" and v3["ok"] is False, v3)
        v4 = R.verify(none, "x.axf", 0, samples=8)
        check("C4 没有可用指纹 -> no-sample 且 ok=false",
              v4["verdict"] in ("unreadable", "no-sample") and v4["ok"] is False, v4)
        undo2 = patch_segments([{"name": ".bss", "vaddr": 0x20000000, "size": 256,
                                 "offset": 0, "data": b"\x00" * 256}])
        try:
            v5 = R.verify(MemClient({0x20000000: b"\x00" * 256}), "x.axf", 0)
            check("C5 段全是退化内容 -> no-sample（明说无区分度，别据下结论）",
                  v5["verdict"] == "no-sample" and v5["ok"] is False
                  and "区分度" in v5["reason"], v5)
        finally:
            undo2()
        check("C6 返回里带逐样本证据（链接地址/运行地址/ELF 与内存字节）",
              v["details"] and all("link_address" in d and "run_address" in d
                                   and "elf_hex" in d for d in v["details"]), "")
    finally:
        undo()

def section_d():
    print("D. reloc.derive_from_pc：从 PC 处代码反推 delta")
    pat = bytes(range(96))
    segs = [{"name": ".text", "vaddr": 0x08001000, "size": 0x300, "offset": 0,
             "data": b"\xAA" * 0x100 + pat + b"\xBB" * 0x100}]
    undo = patch_segments(segs)
    try:
        pc = 0x08010100
        c = MemClient({pc: pat})
        d = R.derive_from_pc(c, "x.axf", pc=pc)
        check("D1 唯一命中 -> delta = PC - 链接地址",
              d["ok"] and d["delta_int"] == 0xF000 and d["delta"] == "0xF000"
              and d["ambiguous"] is False, d)
        twice = [{"name": ".text", "vaddr": 0x08001000, "size": 0x400, "offset": 0,
                  "data": b"\xAA" * 0x100 + pat + b"\xBB" * 0x30 + pat}]
        undo2 = patch_segments(twice)
        try:
            d2 = R.derive_from_pc(MemClient({pc: pat}), "x.axf", pc=pc)
            check("D2 多处命中 -> 如实说定不了（不替你猜一个 delta）",
                  d2["ok"] is True and d2["ambiguous"] is True and d2["delta"] is None
                  and "不替你猜" in d2["reason"], d2)
        finally:
            undo2()
        undo3 = patch_segments([{"name": ".text", "vaddr": 0x08001000, "size": 0x100,
                                 "offset": 0, "data": b"\x5A" * 0x100}])
        try:
            d3 = R.derive_from_pc(MemClient({pc: pat}), "x.axf", pc=pc)
            check("D3 找不到匹配 -> 提示 .axf 与板上固件不同源（别拿它算偏移）",
                  d3["ok"] is False and d3["delta"] is None
                  and "同一次编译" in d3["reason"], d3)
        finally:
            undo3()
        nopc = R.derive_from_pc(object(), "x.axf")
        check("D4 拿不到 PC -> ok=false 且说清拿不到（不冒充）",
              nopc["ok"] is False and nopc["delta"] is None
              and "拿不到" in nopc["reason"], nopc)
    finally:
        undo()

def section_e():
    print("E. DWT 硬件比较器槽位")
    zero = bytearray(0x100)
    # DWT_COMP0=0xE0001020，槽 n 的 FUNCTION = 0xE0001028 + 0x10n
    base = 0xE0001000
    def mk(armed_slots=(), write_fail=()):
        buf = bytearray(zero)
        for n in armed_slots:
            off = (0xE0001028 + 0x10 * n) - base
            buf[off:off + 4] = (6).to_bytes(4, "little")
        return MemClient({base: bytes(buf)}, write_fail=write_fail)
    c = mk([1, 3])
    slots = SV._dwt_watch_slots(c)
    check("E1 槽位 armed 判定：FUNCTION != 0 才算武装",
          [s["slot"] for s in slots if s["armed"]] == [1, 3]
          and all(s["readable"] for s in slots), slots)
    res = SV._dwt_clear_watch_slots(c)
    check("E2 清槽后回读复核：armed_after 为空、cleared=true",
          res["armed_before"] == [1, 3] and res["armed_after"] == []
          and res["cleared"] is True, res)
    after = SV._dwt_watch_slots(c)
    check("E3 清的是 COMPn/MASKn/FUNCTIONn 三件套",
          all(s["function_raw"] == 0 and s["comp_raw"] == 0 for s in after), after)
    bad = mk([0], write_fail=[0xE0001028])
    res2 = SV._dwt_clear_watch_slots(bad)
    check("E4 写不进 FUNCTION0 -> cleared=false（说清了其实没清，必须露出来）",
          res2["cleared"] is False and res2["armed_after"] == [0]
          and "仍有槽位武装" in res2["note"], res2)
    noread = MemClient({})
    res3 = SV._dwt_clear_watch_slots(noread)
    check("E5 DWT 读不到 -> cleared=None 且 note 说明无法确认（不冒充已清干净）",
          res3["cleared"] is None and res3["readable"] is False
          and "无法确认" in res3["note"], res3)
    check("E6 槽位地址按 0x10 步长派生（FUNCTIONn = 0xE0001028 + 0x10n）",
          SV._dwt_slot_addrs(0)["function"] == 0xE0001028
          and SV._dwt_slot_addrs(3)["function"] == 0xE0001058, "")

    # 真机（F429 + Keil @4823）：FUNCTION1 稳定读回 0x00000200，写 0 也改不掉。
    # 0x200 在 FUNCTION 字段（bit[3:0]）之外，字段=0 即未启用——按整字判武装会误报鬼魂。
    class ReservedBitClient(MemClient):
        LOCKED = 0x200

        def write_mem(self, addr, data):
            i = int(addr)
            off = i - 0xE0001028
            if 0 <= off <= 0x30 and off % 0x10 == 0 and len(bytes(data)) == 4:
                b = self._base(i)
                if b is not None and len(self.regions[b]) >= (i - b) + 4:
                    old = int.from_bytes(self.regions[b][i - b:i - b + 4], "little")
                    new = int.from_bytes(bytes(data), "little")
                    data = ((new & ~self.LOCKED) | (old & self.LOCKED)).to_bytes(4, "little")
            return MemClient.write_mem(self, addr, data)

    buf = bytearray(zero)
    o = 0xE0001038 - base
    buf[o:o + 4] = (0x200).to_bytes(4, "little")
    rc = ReservedBitClient({base: bytes(buf)})
    sr = SV._dwt_watch_slots(rc)
    check("E7 字段外的位不算武装（FUNCTION 字段 bit[3:0]=0 即未启用）",
          [x["slot"] for x in sr if x["armed"]] == []
          and sr[1]["function_field"] == 0
          and sr[1]["function_extra"] == 0x200, sr[1])
    cr = SV._dwt_clear_watch_slots(rc)
    check("E8 只有字段外的只读位残留时 -> cleared=true（不把保留位当成没清干净）",
          cr["cleared"] is True and cr["armed_after"] == []
          and "FUNCTION 字段=0" in cr["note"], cr["note"])

def section_f():
    print("F. clear_all_watchpoints / clear_watchpoint 的鬼魂断点处置")
    srv = SV.create_server()
    base = 0xE0001000
    def mk(armed_slots=(), write_fail=()):
        buf = bytearray(0x100)
        for n in armed_slots:
            off = (0xE0001028 + 0x10 * n) - base
            buf[off:off + 4] = (6).to_bytes(4, "little")
        return MemClient({base: bytes(buf)}, write_fail=write_fail)
    try:
        undo = use_client(mk([0, 3]))
        try:
            SV._watchpoints[:] = []
            r = call(srv, "clear_all_watchpoints", {})
            check("F1 默认 dwt=true：内部记录为空但比较器仍武装 -> 全部清除",
                  r.get("ok") is True and r.get("dwt_armed_before") == [0, 3]
                  and (r.get("dwt") or {}).get("armed_after") == [], r)
            check("F2 明确报 ghost_slots 指出鬼魂来源（run 即停的根因）",
                  r.get("ghost_slots") == [0, 3] and "鬼魂" in (r.get("ghost_note") or ""), r)
        finally:
            undo()
        undo = use_client(mk([1]))
        try:
            r = call(srv, "clear_all_watchpoints", {"dwt": False})
            check("F3 dwt=false 完全不碰 DWT（外部工具在用比较器时用）",
                  (r.get("dwt") or {}).get("skipped") is True
                  and "ghost_slots" not in r, r)
        finally:
            undo()
        undo = use_client(mk([2], write_fail=[0xE0001028 + 0x10 * 2]))
        try:
            r = call(srv, "clear_all_watchpoints", {})
            check("F4 DWT 清不掉时 ok=false 并给可执行的诊断（不谎报清干净）",
                  r.get("ok") is False and r.get("error_code") == "dwt-not-cleared"
                  and "DWT_FUNCTION" in (r.get("diagnosis") or ""), r)
        finally:
            undo()
        undo = use_client(MemClient({}))
        try:
            r = call(srv, "clear_all_watchpoints", {})
            check("F5 DWT 读不到时不崩、如实给 dwt_warning",
                  r.get("ok") is True and "dwt_warning" in r, r)
        finally:
            undo()
        undo = use_client(mk([2]))
        try:
            c = SV._get_client()
            r = call(srv, "clear_watchpoint", {"expr": "0x20000000"})
            check("F6 clear_watchpoint 清完后回读 DWT 并报 armed 列表",
                  r.get("dwt_armed_after") == [2] and "dwt_slots_after" in r, r)
            check("F7 内部记录已空但比较器仍武装 -> 兜底清掉并报 ghost_slots_cleared",
                  ((r.get("ghost_slots_cleared") or {}).get("cleared") is True)
                  and "鬼魂" in (r.get("ghost_note") or ""), r)
        finally:
            undo()
    finally:
        undo_loc = use_locator(None)
        undo_loc()

def section_g():
    print("G. read_variable 双轨打通（Keil 表达式 / .axf 符号表）")
    srv = SV.create_server()
    mem = {0x20000000: (1234).to_bytes(4, "little") + b"\x00" * 60}
    loc = FakeLocator(symbols={"SData_UA": {"addr": 0x20000000, "type": "object",
                                            "size": 4, "name": "SData_UA"}})
    try:
        undo_c = use_client(MemClient(mem))
        undo_l = use_locator(loc)
        try:
            r = call(srv, "read_variable", {"name": "SData_UA"})
            check("G1 Keil 表达式挂掉 -> 自动走 .axf 符号表 + read_mem 拿到值",
                  r.get("ok") is True and r.get("value") == 1234
                  and r.get("fallback") == ".axf 符号表 + read_mem"
                  and "自动改用" in (r.get("fallback_reason") or ""), r)
            check("G2 换轨原因可追溯：原轨道的失败信息留在 keil_path",
                  isinstance(r.get("keil_path"), dict)
                  and r["keil_path"].get("ok") is False, r.get("keil_path"))
            r2 = call(srv, "read_variable", {"name": "不存在的符号"})
            check("G3 两条轨道都不通 -> 如实报错，不给假值",
                  r2.get("ok") is False and r2.get("value") is None, r2)
            r3 = call(srv, "read_variable", {"name": "timer.sec"})
            check("G4 成员表达式不做 ELF 硬兜底（交给 Keil 表达式那一侧）",
                  r3.get("ok") is False and "fallback" not in r3, r3)
        finally:
            undo_l()
            undo_c()
        # 退化读数必须告警：偏移错了只会读到全 0
        loc2 = FakeLocator(symbols={"Z": {"addr": 0x20000100, "type": "object",
                                          "size": 4, "name": "Z"}})
        undo_c = use_client(MemClient({0x20000100: b"\x00" * 16}))
        undo_l = use_locator(loc2)
        try:
            r = call(srv, "read_variable", {"name": "Z"})
            check("G5 兜底读到整帧 0 -> value_suspect 告警（别据此判定「被清零」）",
                  r.get("ok") is True and r.get("value_suspect") is True
                  and "被清零" in (r.get("value_warning") or ""), r)
        finally:
            undo_l()
            undo_c()
    finally:
        pass

def section_h():
    print("H. run_to_line 触发前守卫")
    srv = SV.create_server()
    base_line = {"addr": 0x08000120, "matched_file": "app.c", "matched_line": 33,
                 "fuzz": 1, "ambiguous": False, "files": ["app.c"], "kind": "line"}
    funcs = {0x08000100: {"name": "main", "start": 0x08000100, "end": 0x08000140},
             0x08000120: {"name": "app_step", "start": 0x08000120, "end": 0x08000130}}
    try:
        # H1 同名歧义
        amb = dict(base_line, ambiguous=True, files=["a/task_algo.c", "b/task_algo.c"],
                   file="task_algo.c", line=719, candidates=[{"addr": "0x080c952c"}])
        undoC = use_client(MemClient({}))
        undoL = use_locator(FakeLocator(line_ex=amb, funcs=funcs))
        try:
            r = call(srv, "run_to_line", {"target": "task_algo.c:719"})
            check("H1 同名文件撞行号 -> 拒绝(ambiguous-line) 并列出候选文件",
                  r.get("ok") is False and r.get("error_code") == "ambiguous-line"
                  and "撞到同名文件" in r.get("error", "") and r.get("rejected") is True, r)
            check("H2 被拒绝时**没有设置断点**（不白费一次触发）",
                  SV._get_client().bp_calls == [], SV._get_client().bp_calls)
        finally:
            undoL()
            undoC()
        # H3 fuzz 过大
        fz = dict(base_line, fuzz=900, matched_line=3)
        undoC = use_client(MemClient({}))
        undoL = use_locator(FakeLocator(line_ex=fz, funcs=funcs))
        try:
            r = call(srv, "run_to_line", {"target": "app.c:900"})
            check("H3 命中行比目标行早太多 -> 拒绝(line-fuzzy)",
                  r.get("ok") is False and r.get("error_code") == "line-fuzzy", r)
        finally:
            undoL()
            undoC()
        # H4 不在符号区间
        undoC = use_client(MemClient({}))
        undoL = use_locator(FakeLocator(line_ex=base_line, funcs=funcs, covered=False))
        try:
            r = call(srv, "run_to_line", {"target": "app.c:33"})
            check("H4 地址不在任何符号区间 -> 拒绝(not-in-symbols)",
                  r.get("ok") is False and r.get("error_code") == "not-in-symbols", r)
        finally:
            undoL()
            undoC()
        # H5 与 PC 跨函数且更早
        susp = dict(base_line, addr=0x08000080, matched_file="其它.c", matched_line=719)
        undoC = use_client(MemClient({}))          # PC = 0x08000120 -> app_step 入口 0x08000120
        undoL = use_locator(FakeLocator(
            line_ex=susp,
            funcs={0x08000120: {"name": "app_step", "start": 0x08000120, "end": 0x08000130},
                   0x08000080: {"name": "其它", "start": 0x08000080, "end": 0x08000090}}))
        try:
            r = call(srv, "run_to_line", {"target": "其它.c:719"})
            check("H5 目标比当前函数入口还早且不同函数 -> 拒绝(suspicious-target)并给 PC 证据",
                  r.get("ok") is False and r.get("error_code") == "suspicious-target"
                  and r["evidence"].get("pc_function") == "app_step", r)
            check("H6 证据里 pc_check=done（真的校验过，不是嘴上说说）",
                  r["evidence"].get("pc_check") == "done", r.get("evidence"))
        finally:
            undoL()
            undoC()
        # H7 allow_suspect 放行
        undoC = use_client(MemClient({}))
        undoL = use_locator(FakeLocator(
            line_ex=susp,
            funcs={0x08000120: {"name": "app_step", "start": 0x08000120, "end": 0x08000130},
                   0x08000080: {"name": "其它", "start": 0x08000080, "end": 0x08000090}}))
        try:
            r = call(srv, "run_to_line", {"target": "其它.c:719", "allow_suspect": True})
            check("H7 allow_suspect=true 时放行并照常触发",
                  r.get("ok") is True and r.get("hit_address"), r)
        finally:
            undoL()
            undoC()
        # H8 拿不到 PC
        class NoPC(MemClient):
            def read_cpu_registers_stable(self):
                return {"ok": False, "error": "读不到(mock)"}
        undoC = use_client(NoPC({}))
        undoL = use_locator(FakeLocator(line_ex=base_line, funcs=funcs))
        try:
            r = call(srv, "run_to_line", {"target": "app.c:33"})
            tc = r.get("target_check") or {}
            check("H8 拿不到 PC -> pc_check=skipped 且注明未做校验（不冒充已校验）",
                  tc.get("pc_check") == "skipped" and "未做函数边界一致性校验" in
                  (tc.get("pc_check_note") or ""), r)
            check("H9 跳过 PC 校验时仍照常执行（不因缺证据就罢工）",
                  r.get("ok") is True, r)
        finally:
            undoL()
            undoC()
    finally:
        pass

def section_i():
    print("I. locator.line_to_addr_ex / func_at")
    rows = [(0x08000100, "a/main.c", 10), (0x08000108, "a/main.c", 111),
            (0x08000120, "b/main.c", 33), (0x08000130, "b/main.c", 34),
            (0x08000140, "other.c", 5), (0, "a/main.c", 1)]
    loc = Locator.__new__(Locator)
    loc._rows = rows
    loc._loaded = True
    loc._func_ranges = [(0x08000100, 0x08000120, "main"), (0x08000120, 0x08000140, "app")]
    loc._code_ranges = [(0x08000100, 0x08000140)]
    ex = loc.line_to_addr_ex("main.c", 112)
    check("I1 命中最近 <= 行；行距(fuzz)如实给出",
          ex["addr"] == 0x08000108 and ex["matched_line"] == 111 and ex["fuzz"] == 1, ex)
    check("I2 同名文件多个 -> ambiguous=true 且列出参与匹配的文件",
          ex["ambiguous"] is True and len(ex["files"]) == 2, ex.get("files"))
    check("I3 候选列表带地址/文件/行（拒绝时可作证据）",
          ex["candidates"] and {"addr", "file", "line", "fuzz"} <= set(ex["candidates"][0]), "")
    ex2 = loc.line_to_addr_ex("other.c", 5)
    check("I4 唯一文件匹配时不误报歧义",
          ex2["ambiguous"] is False and ex2["addr"] == 0x08000140, ex2)
    ex3 = loc.line_to_addr_ex("nope.c", 5)
    check("I5 没匹配到 -> addr=None 且有 reason",
          ex3["addr"] is None and ex3["reason"], ex3)
    check("I6 line_to_addr 仍只回地址（向后兼容）",
          loc.line_to_addr("other.c", 5) == 0x08000140, loc.line_to_addr("other.c", 5))
    check("I7 地址 0 的 DWARF 占位行仍被跳过",
          loc.line_to_addr_ex("main.c", 2)["addr"] is None, loc.line_to_addr_ex("main.c", 2))
    f = loc.func_at(0x08000121)
    check("I8 func_at 反查函数（含区间内偏移）",
          f and f["name"] == "app" and f["start"] == 0x08000120 and f["offset"] == 0, f)
    check("I9 func_at 区间外返回 None（不硬凑最近的函数）",
          loc.func_at(0x08000199) is None and loc.func_at(0x08000000) is None, "")

def section_j():
    print("J. outctl 编译日志摘录（第五项硬伤）")
    log = "\n".join(["compiling mod%d.c..." % i for i in range(300)]
                    + ["Main.c(42): error: #20: identifier x is undefined",
                       "Program Size: Code=12345 RO-data=1200",
                       '"./MDK-ARM/x.axf" - 1 Error(s), 2 Warning(s).',
                       "Build Time Elapsed:  00:00:12"])
    payload = {"ok": True, "action": "build_project", "status_text": "1 Error(s)",
               "output": log}
    new, meta = O.apply("build_project", payload)
    check("J1 默认就摘（不必先传参数）——用户反馈「日志几万字、结论 5 行」",
          meta is not None and meta.get("log_truncated") is True
          and meta.get("log_excerpted"), meta)
    out = new.get("output")
    check("J2 头 40 行 + 尾 25 行都保留，中间明确标注省略",
          "compiling mod0.c" in out and "compiling mod299.c" in out
          and "已摘录日志" in out and "full=true" in out, out[:200])
    check("J3 关键行被抽出来（错误/体积/耗时），省掉翻几万字",
          any("error" in l.lower() for l in meta.get("log_key_lines") or [])
          and any("Program Size" in l for l in meta.get("log_key_lines") or [])
          and any("Build Time" in l for l in meta.get("log_key_lines") or []),
          meta.get("log_key_lines"))
    check("J4 摘录幅度如实上报（原字符数/保留字符数/取回全量的办法）",
          meta.get("log_total_chars") == len(log)
          and meta.get("log_kept_chars") < len(log)
          and "full=true" in (meta.get("log_full_hint") or ""), meta)
    check("J5 日志字段本身没被顶掉，meta 让位到 output_control",
          isinstance(new.get("output"), str) and "compiling" in new["output"]
          and new.get("output_control") is meta and meta.get("meta_key") == "output_control",
          sorted(new.keys()))
    full, m2 = O.apply("build_project", payload, full=True)
    check("J6 full=true 原样返回（一条都不摘）",
          m2 is None and full["output"] == log, m2)
    short, m3 = O.apply("build_project", {"ok": True, "output": "short log\n"})
    check("J7 短日志完全不动（连 output_control 都不加，默认行为不变）",
          m3 is None and "output_control" not in short, (m3, sorted(short.keys())))
    plain, m4 = O.apply("read_mem", {"ok": True, "data_hex": "00" * 4000})
    check("J8 非日志类工具不受影响（read_mem 的大 data_hex 是内容字段，不动）",
          m4 is None and plain["data_hex"] == "00" * 4000, m4)
    nested, m5 = O.apply("flash_debug", {"ok": True, "build": {"output": log},
                                         "flash": {"output": log}})
    check("J9 嵌套在 build/flash 子结构里的日志同样被摘",
          len(m5.get("log_excerpted") or []) == 2
          and "已摘录日志" in nested["build"]["output"]
          and "已摘录日志" in nested["flash"]["output"], m5.get("log_excerpted"))
    tr, m6 = O.apply("build_project", payload, compact=True, max_lines=5)
    check("J10 与 compact/max_lines 叠加时 mode 记成 log+compact",
          "log" in (m6 or {}).get("mode", "") and "compact" in (m6 or {}).get("mode", ""),
          m6.get("mode"))
    check("J11 摘录实现不碰非日志字段的任何字符",
          new["status_text"] == payload["status_text"]
          and new["action"] == payload["action"], new.get("status_text"))

def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    section_h()
    section_i()
    section_j()
    print("\n批次48 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：", FAIL)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
