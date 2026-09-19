# -*- coding: utf-8 -*-
"""批次49 mock 测试：裸机函数时间线录制 + 环境一致性护栏（通用工具不许写死）。

用户反馈的两个"环境一致性"硬伤其实同一个根因：**工具信任"工程配置"，而不核对
"板上真实是什么"**：

  ① 符号自动绑定错位：flash_download 烧的是 special 工程，enter_debug 加载的却是
     当前打开的主固件工程的 .axf —— PC 全被解析成**假符号**（停在 special 的 map 里
     早被链接器裁掉的函数上），纯误导。
  ② SVD 芯片配错：SVD/内置表是 STM32F4 的，芯片是 STM32H743 —— 读出 F4 的 RCC base
     0x40023800、0xAAAAAAAA，还查不到 H7 才有的 APB1LENR。**看着像样却完全错**，
     比"没有数据"更有害。
  ③ 需求：裸机也要能录「函数运行状态」这类细粒度事件，MDK 与 OpenOCD **都支持**
     （用户明确「无法合并成同一个，可以分开支持」）。
  ④ 同类复查：通用工具里不许写死型号/内存布局（本轮修掉 is_code_address 的
     0x08000000..0x081FFFFF 与 query_memory_map 缺设备守卫）。

   A 工具面：注册总数 188 / 三新工具归组 / 注解覆盖 / 默认仍只暴露 42
   B rtrecord 纯逻辑：函数区间表 / 事件分类 / caller / 栈深 / CYCCNT 回绕 / 环形缓冲
   C chipid 系列比对：三种 verdict、置信度不足不当结论
   D chipid 芯片身份：单候选 high、多候选 low、读不到 unknown、内核-系列矛盾降级
   E chipid 固件同源：指纹全中 / 一条不中（假符号告警）/ 读不到
   F chipid 设备守卫：不匹配默认拒绝、allow_mismatch 放行并标不可信
   G rtrace 选路：坏名字 / 显式链路不可用不换另一条顶上 / auto 都没有
   H rtrace 驱动：槽位裁剪、断点失败、halt/resume 失败、动态补 exit、清理与残留
   I client D-Cache：状态位解析、clean→invalidate 顺序、失败如实报
   J locator 判据来源：ELF 节头（事实）优先，取不到才退经验值（并标明来源）
   K server 侧三工具：参数校验 / status / read 过滤 / env_check 汇总 / dcache 维护
   L 读路径不偷改：退化帧只给 D-Cache 线索，不额外访问目标、不替用户做维护

运行：python -m tests.test_batch49
"""
import os
import sys
import json
import time
import struct
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import chipid as C            # noqa: E402
from mdkdebug import client as uvclient     # noqa: E402
from mdkdebug import locator as LOC         # noqa: E402
from mdkdebug import reloc as R             # noqa: E402
from mdkdebug import rtrecord as RR         # noqa: E402
from mdkdebug import rtrace as RT           # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402

PORT = 15490

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
    except Exception:  # noqa: BLE001
        return {"_raw": txt}

# ======================================================================
class MemClient:
    """稀疏内存模型：regions = {基址: bytes}，支持跨块读、可注入读写失败。"""

    def __init__(self, regions=None, write_fail=(), read_fail=()):
        self.regions = dict(regions or {})
        self.write_fail = set(int(x) for x in write_fail)
        self.read_fail = set(int(x) for x in read_fail)
        self.reads = []
        self.writes = []
        self._running = False

    def _base(self, addr):
        best = None
        for b, d in self.regions.items():
            if b <= addr < b + len(d) and (best is None or b > best):
                best = b
        return best

    def read_mem(self, addr, n):
        addr, n = int(addr), int(n)
        self.reads.append((addr, n))
        if addr in self.read_fail:
            return {"ok": False, "status_text": "读失败(mock) @0x%X" % addr}
        b = self._base(addr)
        if b is None:
            return {"ok": False, "status_text": "无模拟内存(mock) @0x%X" % addr}
        d = self.regions[b][addr - b:addr - b + n]
        if len(d) < n:
            return {"ok": False, "status_text": "越界(mock) @0x%X" % addr}
        return {"ok": True, "data_hex": d.hex(), "ascii": "", "address": hex(addr),
                "n_bytes": n}

    def write_mem(self, addr, data):
        addr, data = int(addr), bytes(data)
        self.writes.append((addr, data))
        if addr in self.write_fail:
            return {"ok": False, "status_text": "写失败(mock) @0x%X" % addr}
        b = self._base(addr)
        if b is None:
            return {"ok": False, "status_text": "无模拟内存(mock) @0x%X" % addr}
        buf = bytearray(self.regions[b])
        off = addr - b
        if off + len(data) > len(buf):
            buf.extend(b"\x00" * (off + len(data) - len(buf)))
        buf[off:off + len(data)] = data
        self.regions[b] = bytes(buf)
        return {"ok": True}

    # Keil 侧够用的桩
    def set_breakpoint(self, target, *a, **k):
        return {"ok": True, "address": str(target), "cleared_by": "keil_number"}

    def clear_breakpoint(self, target, *a, **k):
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

    def running_cached(self, ttl=1.0, fresh=False):
        return self._running

    def dcache_status(self):
        r = self.read_mem(0xE000ED14, 4)
        if not r.get("ok"):
            return {"ok": False, "error": r.get("status_text")}
        v = int.from_bytes(bytes.fromhex(r["data_hex"]), "little")
        return {"ok": True, "ccr": "0x%08X" % v, "dcache": bool(v & (1 << 16)),
                "icache": bool(v & (1 << 17)), "source": "SCB->CCR(mock)"}

    def cache_clean_invalidate(self, addr):
        ops = []
        ok_all = True
        for name, reg in (("clean(DCCMVAC)", 0xE000EF68),
                          ("invalidate(DCIMVAC)", 0xE000EF5C)):
            w = self.write_mem(reg, struct.pack("<I", int(addr) & 0xFFFFFFFF))
            ops.append({"op": name, "reg": "0x%08X" % reg, "ok": bool(w.get("ok")),
                        "error": None if w.get("ok") else w.get("status_text")})
            ok_all = ok_all and bool(w.get("ok"))
        return {"ok": ok_all, "addr": "0x%X" % int(addr), "ops": ops}

    def run(self):
        return {"ok": True, "status": 22}

    def halt(self):
        return {"ok": True, "status": 20}

    def wait_breakpoint(self, addresses=None, timeout_s=10.0, **k):
        return {"ok": True, "hit": False, "hit_address": None, "waited_ms": 1,
                "pc_confidence": "high", "registers": {}}


def rd32_regions(addr_val):
    """把 {地址: 32位值} 变成 {地址: 4 字节小端} 的 regions。"""
    return {int(a): struct.pack("<I", int(v) & 0xFFFFFFFF) for a, v in addr_val.items()}


class FakeBackend(RT.Backend):
    """rtrace 驱动用的假链路：hit 脚本可控、每个动作都留痕。"""

    name = "keil"
    label = "Keil/UVSOCK(mock)"

    def __init__(self, hits=None, slots_n=4, bp_ok=True, halt_ok=True,
                 resume_ok=True, clear_ok=True, cyc=None, name=None):
        self.hits = list(hits or [])
        self._slots = int(slots_n)
        self.bp_ok = bp_ok
        self.halt_ok = halt_ok
        self.resume_ok = resume_ok
        self.clear_ok = clear_ok
        self.cyc = cyc
        if name:
            self.name = name
        self.planted = []
        self.cleared = []
        self.halt_calls = 0
        self.resume_calls = 0

    def available(self):
        return True

    def describe(self):
        return {"name": self.name, "label": self.label, "mock": True}

    def slots(self):
        return self._slots

    def halt(self):
        self.halt_calls += 1
        return {"ok": self.halt_ok, "was_running": False,
                "error": None if self.halt_ok else "halt 失败(mock)"}

    def resume(self):
        self.resume_calls += 1
        return {"ok": self.resume_ok,
                "error": None if self.resume_ok else "resume 失败(mock)"}

    def regs(self, names=("pc", "lr", "sp")):
        return {"ok": True, "pc": 0x100, "lr": 0x200, "sp": 0x20001000}

    def read_u32(self, addr):
        if self.cyc is None:
            return None, {"error": "读不到 CYCCNT(mock)"}
        return self.cyc, {}

    def set_bp(self, addr):
        if not self.bp_ok:
            return False, {"error": "槽位不足(mock)", "addr": "0x%X" % int(addr)}
        self.planted.append(int(addr))
        return True, {"addr": "0x%X" % int(addr)}

    def clear_bp(self, addr):
        self.cleared.append(int(addr))
        return self.clear_ok, {"addr": "0x%X" % int(addr)}

    def wait_hit(self, addrs, timeout_s=10.0):
        if not self.hits:
            return {"ok": True, "hit": False, "link": self.name}
        h = self.hits.pop(0)
        return {"ok": True, "hit": True, "link": self.name,
                "hit_address": h.get("pc"), "registers": h}


class FakeLocator:
    """够用的假定位器：函数区间表 + 可注入的解析失败。"""

    def __init__(self, ranges=None, line_ex=None):
        self._ranges = list(ranges or [])
        self._line_ex = line_ex or {}

    def is_ready(self):
        return True

    def _load_func_ranges(self):
        return list(self._ranges)

    def line_to_addr_ex(self, file, line):
        d = dict(self._line_ex)
        d.setdefault("file", file)
        d.setdefault("line", line)
        d.setdefault("addr", None)
        return d

    def func_at(self, addr):
        for st, en, nm in self._ranges:
            if st <= int(addr) & ~1 < en:
                return {"name": nm, "start": st, "end": en}
        return None

    def code_range_source(self):
        return "elf-sections"


def use_client(c):
    old = SV._client
    SV._client = c
    return lambda: setattr(SV, "_client", old)

def use_locator(loc):
    old = SV._symbol_cfg.get("locator")
    SV._symbol_cfg["locator"] = loc
    return lambda: SV._symbol_cfg.__setitem__("locator", old)

def use_pick(be, err=None):
    old = RT.pick
    RT.pick = lambda link="auto", who="": (be, err)
    return lambda: setattr(RT, "pick", old)

def use_attr(obj, name, val):
    old = getattr(obj, name)
    setattr(obj, name, val)
    return lambda: setattr(obj, name, old)

# ======================================================================
def section_a():
    print("A. 工具面与注解")
    total = sum(len(v) for v in TB.TOOLSETS.values()) + len(TB.ALWAYS)
    check("A1 注册总数 188（分组表 180 + 常驻 6）", total == 188, total)
    check("A2 trace_record 归 trace 组（批次55 加 3 个 buff 到 30，批次56 再加 3 个 swd 到 33）",
          "trace_record" in (TB.TOOLSETS.get("trace") or []) and gsize("trace") == 33,
          gsize("trace"))
    check("A3 env_check 归 core 组（组规模 33->36）",
          "env_check" in (TB.TOOLSETS.get("core") or []) and gsize("core") == 36,
          gsize("core"))
    check("A4 dcache_maintain 归 mem 组（组规模 10->11）",
          "dcache_maintain" in (TB.TOOLSETS.get("mem") or []) and gsize("mem") == 11,
          gsize("mem"))
    an = A.annotations_for("env_check")
    check("A5 env_check 标只读（只读芯片/内存，不改目标状态）",
          an.get("readOnlyHint") is True and an.get("destructiveHint") is False, an)
    an2 = A.annotations_for("trace_record")
    check("A6 trace_record 标为会改状态（下/撤断点、跑停目标）",
          an2.get("readOnlyHint") is False, an2)
    an3 = A.annotations_for("dcache_maintain")
    check("A7 dcache_maintain 标为会改状态（写 SCB 寄存器）",
          an3.get("readOnlyHint") is False, an3)
    allnames = set(TB.ALWAYS)
    for v in TB.TOOLSETS.values():
        allnames |= set(v)
    bad = A.check_surface(sorted(allnames))
    check("A8 check_surface 在 188 个工具上无问题", not bad, bad)
    # 默认面：core + ALWAYS，其余收起
    exposed = gsize("core") + len(TB.ALWAYS)
    check("A9 默认暴露 core 36 + 常驻 6 = 42（新增工具进 core 后自动生效）",
          exposed == 42, exposed)
    check("A10 默认收起 146（188-40）", 188 - exposed == 146, 188 - exposed)


def section_b():
    print("B. rtrecord 纯逻辑（链路无关）")
    idx = RR.make_func_index({"task_a": (0x100, 0x200), "task_b": (0x300, 0x400)})
    check("B1 make_func_index 支持 dict 形态且按起点排序",
          [(s, e, n) for s, e, n in idx] == [(0x100, 0x200, "task_a"),
                                             (0x300, 0x400, "task_b")], idx)
    idx2 = RR.make_func_index([(0x200, 0x280, "inner"), (0x200, 0x300, "outer"),
                               (0x400, 0x500, None)])
    check("B2 支持 list-of-tuple；无名字时用地址当名字（不编造）",
          sorted(n for _s, _e, n in idx2) == ["0x400", "inner", "outer"], idx2)
    check("B3 退化的区间（end<=start / 非整数）被丢掉，不留半个函数",
          RR.make_func_index({"x": (0x10, 0x10), "y": ("a", 2)}) == [],
          RR.make_func_index({"x": (0x10, 0x10), "y": ("a", 2)}))
    got = RR.func_at(idx2, 0x210)
    check("B4 func_at 取**最内层**区间（嵌套时选起点更大的）",
          got and got["name"] == "inner" and got["offset"] == 0x10, got)
    check("B5 func_at 不在任何区间 → None（不硬塞一个最近的名字）",
          RR.func_at(idx2, 0x600) is None, RR.func_at(idx2, 0x600))
    check("B6 func_at 非整数入参 → None（不抛异常）",
          RR.func_at(idx2, None) is None and RR.func_at(idx2, "0x210") is None, "")

    r = RR.Recorder([(0x100, 0x200, "task_a"), (0x300, 0x400, "caller_fn")],
                    exits=[0x350], max_events=3)
    e1 = r.on_hit(0x110, cyc=None, lr=0x351, sp=0x20002000)
    check("B7 命中已知函数区间 → kind=enter 且带函数名",
          e1["kind"] == "enter" and e1["func"] == "task_a", e1)
    check("B8 caller 由 LR 落在哪个函数推得（LR 的 Thumb 位先清掉）",
          e1["caller"] == "caller_fn", e1)
    check("B9 首次命中即为栈深基线 depth_est=0",
          e1["depth_est"] == 0, e1)
    check("B10 首次命中没有上一次，gap_cyc=None（不编一个 0 出来）",
          e1["gap_cyc"] is None, e1)
    e2 = r.on_hit(0x350, cyc=None, lr=0x100, sp=0x20002008)
    check("B11 命中 exit 集合 → kind=exit，且仍在函数区间里就照给函数名",
          e2["kind"] == "exit" and e2["func"] == "caller_fn", e2)
    check("B12 栈深按 (SP-基线)//8 估计且带 _est 后缀",
          e2["depth_est"] == 1, e2)
    e3 = r.on_hit(0x900, cyc=None, lr=0x351, sp=0x20002000)
    check("B13 不落在任何已知函数区间的命中 → kind=unknown、func=None（假符号场景）",
          e3["kind"] == "unknown" and e3["func"] is None, e3)
    e4 = r.on_hit(0x110, cyc=None, kind_hint="watch", sp=0x20002000)
    check("B14 kind_hint 优先（数据观察点命中可显式声明）",
          e4["kind"] == "watch", e4)
    check("B15 环形缓冲满后开始计 dropped，且 events_kept 不涨",
          r.dropped == 1 and len(r.events) == 3 and r.total == 4,
          (r.dropped, len(r.events), r.total))
    st = r.stats
    tot_stat = sum(v["count"] for v in st.values())
    check("B16 统计是全量的（缓冲只留 3 条，4 次命中仍全部计入统计）",
          tot_stat == 4 and st["task_a"]["count"] == 2,
          (tot_stat, st.get("task_a")))
    check("B17 unknown 命中单独成桶，不混进任何函数名",
          st.get("_unknown_", {}).get("unknown") == 1, sorted(st))

    r2 = RR.Recorder([(0x100, 0x200, "f")], max_events=10)
    r2.on_hit(0x100, cyc=1000)
    g1 = r2.on_hit(0x100, cyc=1050)["gap_cyc"]
    g2 = r2.on_hit(0x100, cyc=10)["gap_cyc"]
    r2.on_hit(0x100, cyc=30)
    check("B18 gap_cyc 是相邻命中差值，不是函数耗时（字段名就说明白了）",
          g1 == 50, g1)
    check("B19 CYCCNT 回绕（差为负）→ gap_cyc=None，不猜",
          g2 is None, g2)
    rep = r2.report(limit=2)
    check("B20 report 如实给 events_total/kept/dropped 与 by_func/top_calls",
          rep["events_total"] == 4 and rep["events_kept"] == 4
          and rep["by_func"][0]["func"] == "f" and rep["by_func"][0]["count"] == 4,
          {k: rep[k] for k in ("events_total", "events_kept", "funcs_seen")})
    check("B21 report.note 写明 gap_cyc/depth_est/caller 的口径（防被当精确值）",
          "不是函数精确耗时" in rep["note"] and "估计值" in rep["note"], rep["note"])
    check("B22 timeline 支持 kind/func 过滤与 limit（取末尾 N 条）",
          len(r2.timeline(limit=2)) == 2 and len(r2.timeline(kind="enter")) == 4
          and r2.timeline(func="f")[-1]["i"] == 3,
          len(r2.timeline(limit=2)))
    rep3 = RR.Recorder([(0x100, 0x200, "f")]).report()
    check("B23 没有 unknown 命中时不给 unknown_hits（不凭空加字段）",
          "unknown_hits" not in rep3, sorted(rep3.keys()))
    r4 = RR.Recorder([(0x100, 0x200, "f")], max_events=2)
    r4.on_hit(0x900, cyc=1)
    check("B24 有 unknown 命中时给 unknown_hits 并提示「别把它当函数名」",
          "unknown_hits" in r4.report()
          and "别把它当成函数名" in r4.report()["unknown_hits"]["note"],
          r4.report().get("unknown_hits"))
    hp = RR.hit_payload({"pc": 0x110, "lr": 0x351, "sp": 0x20002000}, 0x110, cyc=7)
    check("B25 hit_payload 从寄存器取 pc/lr/sp（两条链路共用同一入口）",
          hp == {"addr": 0x110, "cyc": 7, "lr": 0x351, "sp": 0x20002000, "ts": None},
          hp)
    check("B26 hit_payload 缺寄存器时留 None，不去猜",
          RR.hit_payload({}, 0x110)["lr"] is None, RR.hit_payload({}, 0x110))


def section_c():
    print("C. chipid：型号名 → 系列，以及三态比对")
    check("C1 STM32H743xx → STM32H7",
          C.series_of_name("STM32H743xx")["series"] == "STM32H7",
          C.series_of_name("STM32H743xx"))
    check("C2 STM32F407IGTx → STM32F4（截到系列档位，不纠结封装后缀）",
          C.series_of_name("STM32F407IGTx")["series"] == "STM32F4",
          C.series_of_name("STM32F407IGTx"))
    check("C3 只给厂牌不给档位 → series=None 且说明原因，不硬凑",
          C.series_of_name("STM32H")["series"] is None
          and "只认出厂牌" in C.series_of_name("STM32H")["reason"],
          C.series_of_name("STM32H"))
    check("C4 非 STM32 型号（GD32 等）如实说本判据不覆盖",
          C.series_of_name("GD32F303")["series"] is None
          and "本判据只覆盖 STM32" in C.series_of_name("GD32F303")["reason"],
          C.series_of_name("GD32F303"))
    chip_h7 = {"series": "STM32H7", "confidence": "high", "dev_id_hex": "0x450"}
    m = C.series_match("STM32H743xx", chip_h7)
    check("C5 一致 → matched", m["verdict"] == "matched", m)
    m2 = C.series_match("STM32F407IGTx", chip_h7)
    check("C6 不一致 → mismatched，且原因点明「看着像样但完全是别的芯片的布局」",
          m2["verdict"] == "mismatched" and "别的芯片的布局" in m2["reason"], m2)
    m3 = C.series_match("STM32F407IGTx", {"series": "STM32H7", "confidence": "low"})
    check("C7 实测置信度不足 → unknown（不拿低置信证据去否配置）",
          m3["verdict"] == "unknown" and "置信度" in m3["reason"], m3)
    m4 = C.series_match("STM32F407IGTx", {"series": None, "confidence": "none",
                                          "reason": "读不到 IDCODE"})
    check("C8 未实测出系列 → unknown，并警告不许拿工程配置冒充实测",
          m4["verdict"] == "unknown" and "不要" in m4["reason"], m4)
    m5 = C.series_match("GD32F303", chip_h7)
    check("C9 配置侧推不出系列 → unknown，不误判成 mismatched",
          m5["verdict"] == "unknown", m5)
    check("C10 cpu_partno 从 CPUID bits[15:4] 读内核名",
          C.cpu_partno(0x410FC241) == "Cortex-M4"
          and C.cpu_partno(0x411FC271) == "Cortex-M7", C.cpu_partno(0x410FC241))
    check("C11 cpu_partno 未收录/非整数 → 空串（不猜内核）",
          C.cpu_partno(0x12345678) == "" and C.cpu_partno(None) == "", "")


def section_d():
    print("D. chipid.probe_chip：拿目标说话")
    h7 = MemClient(rd32_regions({0x5C001000: 0x10036450, C.CPUID_ADDR: 0x411FC271}))
    p = C.probe_chip(h7)
    check("D1 H7 区读到 DEV_ID 0x450 → STM32H74x/75x / STM32H7",
          p["series"] == "STM32H7" and p["model"].startswith("STM32H74"),
          {k: p[k] for k in ("series", "model", "dev_id_hex", "revision")})
    check("D2 只有一处候选命中 → confidence=high，并记下 IDCODE 出处",
          p["confidence"] == "high" and p["idcode_from"] == "0x5c001000",
          (p["confidence"], p.get("idcode_from")))
    check("D3 CPUID 交叉校验通过（M7 与 H7 相容）",
          p["cross_check"]["ok"] is True, p.get("cross_check"))

    f4 = MemClient(rd32_regions({0xE0042000: 0x10006413, C.CPUID_ADDR: 0x410FC241}))
    p2 = C.probe_chip(f4)
    check("D4 F4 区读到 DEV_ID 0x413 → STM32F40x/41x / STM32F4",
          p2["series"] == "STM32F4" and p2["confidence"] == "high",
          (p2["series"], p2["confidence"]))

    both = MemClient(rd32_regions({0x5C001000: 0x10036450, 0xE0042000: 0x10006413,
                                   C.CPUID_ADDR: 0x411FC271}))
    p3 = C.probe_chip(both)
    check("D5 多处候选都读出已知 DEV_ID → confidence=low（谁是真的说不准）",
          p3["confidence"] == "low" and p3["series"] is None
          and "谁是真的说不准" in p3["reason"], p3["reason"])

    bad = MemClient(rd32_regions({0xE0042000: 0xFFFFFFFF, 0x5C001000: 0x00000000}))
    p4 = C.probe_chip(bad)
    check("D6 读出全 0 / 全 F → 识别为「不像 IDCODE」而非当成有效 DEV_ID",
          p4["confidence"] == "none" and p4["series"] is None
          and any("不像 IDCODE" in (x.get("note") or "") for x in p4["probes"]),
          p4["probes"])

    none_cli = MemClient()
    p5 = C.probe_chip(none_cli)
    check("D7 一个候选都读不到 → confidence=none，如实说未读出（不猜系列）",
          p5["confidence"] == "none" and p5["series"] is None
          and "未能读出可识别的 DBGMCU DEV_ID" in p5["reason"], p5["reason"])

    contra = MemClient(rd32_regions({0x5C001000: 0x10006413,
                                     C.CPUID_ADDR: 0x411FC271}))
    p6 = C.probe_chip(contra)
    check("D8 DEV_ID 说 F4、CPUID 说 M7（矛盾）→ 置信度下调到 low 并说明",
          p6["confidence"] == "low" and p6["cross_check"]["ok"] is False
          and "证据互相矛盾" in p6["cross_check"]["note"], p6.get("cross_check"))

    no_cpuid = MemClient(rd32_regions({0xE0042000: 0x10006413}))
    p7 = C.probe_chip(no_cpuid)
    check("D9 有 DEV_ID 但读不到 CPUID → medium 且说明未交叉校验",
          p7["confidence"] == "medium" and "未能交叉校验" in p7["reason"],
          (p7["confidence"], p7["reason"]))

    unknown_dev = MemClient(rd32_regions({0xE0042000: 0x10000FFF}))
    p8 = C.probe_chip(unknown_dev)
    check("D10 DEV_ID 不在表里 → 不猜系列，probes 里注明「未收录」",
          p8["series"] is None
          and any("不在已知表内" in (x.get("note") or "") for x in p8["probes"]),
          p8["probes"])


def section_e():
    print("E. chipid.firmware_match：符号与板上固件是否同源")
    old_v, old_d = R.verify, R.derive_from_pc
    try:
        R.verify = lambda client, elf, delta, samples=8: {"verdict": "delta-confirmed"}
        m = C.firmware_match(MemClient(), "x.axf", 0)
        check("E1 指纹全中 → firmware-confirmed（符号可用）",
              m["verdict"] == "firmware-confirmed" and "符号可用" in m["note"], m)
    finally:
        R.verify, R.derive_from_pc = old_v, old_d

    try:
        calls = {"n": 0}

        def fake_verify(client, elf, delta, samples=8):
            calls["n"] += 1
            if int(delta) == 0xF000:
                return {"verdict": "delta-confirmed"}
            return {"verdict": "delta-likely-wrong"}

        R.verify = fake_verify
        R.derive_from_pc = lambda client, elf: {"ok": True, "delta_int": 0xF000,
                                                "delta": "0xF000"}
        m = C.firmware_match(MemClient(), "x.axf", 0)
        check("E2 给定 delta 不对但按 PC 反推出的 delta 指纹全中 → 判固件同源，"
              "并给出应改的 delta",
              m["verdict"] == "firmware-confirmed"
              and m.get("suggested_delta") == "0xF000", m)
    finally:
        R.verify, R.derive_from_pc = old_v, old_d

    try:
        R.verify = lambda client, elf, delta, samples=8: {"verdict": "delta-likely-wrong"}
        R.derive_from_pc = lambda client, elf: {"ok": False, "reason": "没有 PC"}
        m = C.firmware_match(MemClient(), "special.axf", 0)
        check("E3 指纹一条都没中且反推不出 → firmware-mismatch + 假符号告警",
              m["verdict"] == "firmware-mismatch"
              and "假符号" in m["note"] and "裁剪" in m["note"], m["note"])
        check("E4 告警里给出可执行动作（set_symbol_file 切到对应 .axf）",
              "set_symbol_file" in m["note"], m["note"])
    finally:
        R.verify, R.derive_from_pc = old_v, old_d

    try:
        R.verify = lambda client, elf, delta, samples=8: {"verdict": "unreadable"}
        m = C.firmware_match(MemClient(), "x.axf", 0)
        check("E5 读不到目标内存 → verdict=unreadable，明确说「本次未验证」",
              m["verdict"] == "unreadable" and "未验证" in m["note"], m)
    finally:
        R.verify, R.derive_from_pc = old_v, old_d

    try:
        R.verify = lambda client, elf, delta, samples=8: {"verdict": "partial"}
        m = C.firmware_match(MemClient(), "x.axf", 0)
        check("E6 只有部分指纹命中 → firmware-uncertain，禁止据此下结论",
              m["verdict"] == "firmware-uncertain" and "别据此下结论" in m["note"], m)
    finally:
        R.verify, R.derive_from_pc = old_v, old_d


def section_f():
    print("F. chipid.guard_configured_device：外设操作前的环境校验")
    chip_f4 = {"series": "STM32F4", "confidence": "high", "dev_id_hex": "0x413"}
    chip_h7 = {"series": "STM32H7", "confidence": "high", "dev_id_hex": "0x450",
               "reason": ""}
    g = C.guard_configured_device(MemClient(), "STM32H743xx", chip=chip_f4)
    check("F1 配置 F4、实测 H7（就是真机那例）→ 默认**拒绝**执行",
          g["allowed"] is False and g["verdict"] == "mismatched"
          and g["error_code"] == "svd-device-mismatch", g)
    check("F2 拒绝时给出确认型号/换 SVD 的可执行说明",
          "svd_list" in (g.get("note") or "") and "allow_mismatch" in (g.get("note") or ""),
          g.get("note"))
    check("F2b 拒绝时也给机器可读的 next_actions，且按实测系列给具体器件名提示"
          "（batch50）",
          isinstance(g.get("next_actions"), list) and g["next_actions"]
          and any("STM32F429xx" in a for a in g["next_actions"])
          and any("allow_mismatch" in a for a in g["next_actions"]), g.get("next_actions"))
    g2 = C.guard_configured_device(MemClient(), "STM32H743xx", allow_mismatch=True,
                                   chip=chip_f4)
    check("F3 allow_mismatch=true → 放行但明确标注本次结果不可信",
          g2["allowed"] is True and "不可信" in (g2.get("note") or ""), g2)
    check("F3b 强读放行时同样给出「换成实测系列那份 SVD」的 next_actions（batch50）",
          isinstance(g2.get("next_actions"), list) and g2["next_actions"]
          and any("svd_list" in a or "svd_file" in a for a in g2["next_actions"]),
          g2.get("next_actions"))
    g3 = C.guard_configured_device(MemClient(), "STM32H743xx", chip=chip_h7)
    check("F4 型号一致 → 放行且不带错误码",
          g3["allowed"] is True and g3["verdict"] == "matched"
          and "error_code" not in g3, g3)
    g4 = C.guard_configured_device(MemClient(), "STM32H743xx",
                                   chip={"series": None, "confidence": "none"})
    check("F5 实测系列未知 → 放行但提示自行核对（不假装校验过）",
          g4["allowed"] is True and g4["verdict"] == "unknown"
          and "自行核对" in (g4.get("note") or ""), g4)
    calls = {"n": 0}

    def boom(c):
        calls["n"] += 1
        return {"series": "STM32H7", "confidence": "high"}

    g5 = C.guard_configured_device(MemClient(), "STM32F4", chip=None)
    check("F6 chip 未传时自行探测（本用例读不到 → unknown，不误拒）",
          g5["allowed"] is True, g5)


# ======================================================================
def section_g():
    print("G. rtrace 选路：不换另一条链路顶上")
    saved = SV._client
    try:
        SV._client = None
        be, err = RT.pick("bogus")
        check("G1 链路名不认识 → 明确报错并列出可用取值",
              be is None and err["reason"] == "bad-link-name"
              and "auto / keil / ocd" in err["error"]
              and "auto" in err["hint"], err)
        be, err = RT.pick("keil")
        check("G2 显式要 keil 而没有会话 → 报 no-keil-link，**不会**拿 ocd 顶上",
              be is None and err["reason"] == "no-keil-link"
              and "指定的链路不可用" in err["error"], err)
        be, err = RT.pick("ocd")
        check("G3 显式要 ocd 而没有会话 → 报 no-ocd-link",
              be is None and err["reason"] == "no-ocd-link", err)
        be, err = RT.pick("auto")
        check("G4 auto 两条链路都没有 → 报 no-mem-link 并分别说明两边原因",
              be is None and err["reason"] == "no-mem-link"
              and err.get("keil") and err.get("ocd"), err)
        check("G5 失败提示给出下一步（Keil: enter_debug / 非 MDK: ocd_start）",
              "enter_debug" in err["hint"] and "ocd_start" in err["hint"], err["hint"])
    finally:
        SV._client = saved
    check("G6 Backend 子类各自声明链路名（机制分开实现，接口对齐）",
          RT.KeilBackend.name == "keil" and RT.OcdBackend.name == "ocd", "")

    # G7/G8（batch50）：UVSOCK 的 socket 是懒连接，没连 ≠ 链路不可用
    class _Phy:
        is_connected = False
    class _FakeCli:
        def __init__(self):
            self.phy = _Phy()
            self.tried = 0
        def _ensure_connected(self):
            self.tried += 1
            self.phy.is_connected = True
    saved = SV._client
    try:
        fc = _FakeCli()
        SV._client = fc
        be, err = RT.pick("keil")
        check("G7 懒连接尚未发生时先主动连一次，不当成「链路不可用」"
              "（env_check 因此才不会连芯片都不去实测）",
              be is not None and err is None and fc.tried == 1, (be, err, fc.tried))
    finally:
        SV._client = saved

    class _BadCli:
        def __init__(self):
            self.phy = _Phy()
        def _ensure_connected(self):
            raise OSError("Connection refused(mock)")
    try:
        SV._client = _BadCli()
        be, err = RT.pick("keil")
        check("G8 真连不上 → 报底层真实原因（不替 Keil 猜），且不换另一条链路顶上",
              be is None and err["reason"] == "no-keil-link"
              and "连不上" in err["error"] and "Connection refused(mock)" in err["error"], err)
    finally:
        SV._client = saved


def section_h():
    print("H. rtrace.record：一次录制的调度与诚实边界")
    r = RT.record([], [], backend=None)
    check("H1 没有后端 → 直接报错（不假装录到了空结果）",
          r["ok"] is False and "没有可用的链路后端" in r["error"], r)
    be = FakeBackend()
    r = RT.record([], [], backend=be)
    check("H2 没有入口地址 → 报错说清「确认符号已加载、funcs 选到函数」",
          r["ok"] is False and "没有可监控的入口地址" in r["error"], r)

    idx = RR.make_func_index([(0x100, 0x200, "task_a"), (0x300, 0x400, "caller_fn")])
    be = FakeBackend(hits=[{"pc": 0x100, "lr": 0, "sp": 0}], slots_n=4)
    r = RT.record(idx, [0x101, 0x300, 0x500, 0x700], backend=be,
                  max_breakpoints=2, max_ms=200)
    check("H3 入口地址先清 Thumb 位再布断点（BS 对奇数地址会报 error 57）",
          0x100 in be.planted and 0x101 not in be.planted, be.planted)
    check("H4 要监控的比槽位多时只布前 N 个，armed/skipped 如实分列",
          r["armed"] == ["0x100", "0x300"] and r["skipped"] == ["0x500", "0x700"],
          (r["armed"], r["skipped"]))
    check("H5 槽位不足时给出说明（并提示分批或调大 max_breakpoints）",
          "slots_note" in r and "只布了前" in r["slots_note"], r.get("slots_note"))
    check("H6 收尾撤掉自己布的断点，清理干净时 breakpoints_left 为空",
          r["breakpoints_left"] == [] and sorted(be.cleared) == [0x100, 0x300],
          (r["breakpoints_left"], be.cleared))
    check("H7 本链路固有限制照样披露（exit 依赖槽位 / 时间粒度 / 会丢事件）",
          set(r["link_limits"]) == {"exit_events", "timing", "loss"}, r["link_limits"])
    check("H8 目标停在入口时按 PC 记事件（first hit 就是 armed 里的地址）",
          r["timeline"] and r["timeline"][0]["pc"] == "0x100"
          and r["timeline"][0]["kind"] == "enter", r["timeline"])
    check("H9 halt→布点→resume→再 halt 的调度顺序至少各发生一次",
          be.halt_calls >= 2 and be.resume_calls >= 1,
          (be.halt_calls, be.resume_calls))

    # 槽位有余量时，用命中入口的 LR 动态补一个返回地址断点，从而拿到 exit 事件
    ben = FakeBackend(hits=[{"pc": 0x100, "lr": 0x351, "sp": 0x20001000},
                            {"pc": 0x350, "lr": 0x100, "sp": 0x20001008}],
                      slots_n=4, cyc=1000)
    rn = RT.record(idx, [0x100], backend=ben, max_breakpoints=3, max_ms=200,
                   watch_exit=True)
    check("H10 exit 靠 LR 动态补断点：0x351 的 Thumb 位清掉后补在 0x350",
          rn["planted_exits"] == ["0x350"] and 0x350 in ben.planted,
          (rn["planted_exits"], ben.planted))
    check("H11 事件按函数归类：入口是 enter@task_a、返回点按它所属函数记 exit",
          [(e["func"], e["kind"]) for e in rn["timeline"]] == [("task_a", "enter"),
                                                             ("caller_fn", "exit")],
          rn["timeline"])
    check("H12 CYCCNT 读得到时事件带 cyc，且 cyccnt_available=true",
          rn["cyccnt_available"] is True and rn["timeline"][0]["cyc"] == 1000,
          rn["cyccnt_available"])
    check("H13 两轮都用同一条链路名对外（link/link_label 来自 Backend 自称）",
          rn["link"] == "keil" and rn["link_label"] == "Keil/UVSOCK(mock)",
          (rn["link"], rn["link_label"]))

    be2 = FakeBackend(hits=[{"pc": 0x100, "lr": 0, "sp": 0x20001000}], cyc=None)
    r2 = RT.record(idx, [0x100], backend=be2, max_ms=100)
    check("H11 读不到 CYCCNT → 明确说别编周期数，时间轴以 t_ms 为准",
          r2["cyccnt_available"] is False and "不要编造" in r2["cyccnt_note"],
          r2.get("cyccnt_note"))

    be3 = FakeBackend(bp_ok=False)
    r3 = RT.record(idx, [0x100, 0x300], backend=be3, max_ms=100)
    check("H12 断点一个都没布上 → ok=false 且提示调小监控点数量",
          r3["ok"] is False and "断点一个都没布上" in r3["error"], r3["error"])
    check("H13 布点失败逐个记进 bp_failed（哪个地址、什么原因）",
          len(r3["bp_failed"]) == 2 and r3["bp_failed"][0]["addr"] in ("0x100", "0x300"),
          r3["bp_failed"])

    be4 = FakeBackend(halt_ok=False)
    r4 = RT.record(idx, [0x100], backend=be4, max_ms=100)
    check("H14 halt 失败 → 报「布断点前 halt 失败」，不继续往下走",
          r4["ok"] is False and "布断点前 halt 失败" in r4["error"], r4["error"])

    be5 = FakeBackend(resume_ok=False, hits=[{"pc": 0x100, "lr": 0, "sp": 0}])
    r5 = RT.record(idx, [0x100], backend=be5, max_ms=100, cleanup=False,
                   leave_halted=False)
    check("H15 resume 失败 → 报「目标没跑起来就不会有事件」",
          "resume 失败" in (r5.get("error") or ""), r5.get("error"))

    be6 = FakeBackend(hits=[{"pc": 0x100, "lr": 0, "sp": 0}], clear_ok=False)
    r6 = RT.record(idx, [0x100], backend=be6, max_ms=100)
    check("H16 断点撤不干净 → 如实列进 breakpoints_left 并给手工清理提示",
          r6["breakpoints_left"] == ["0x100"] and "手工清掉" in r6["cleanup_note"],
          (r6["breakpoints_left"], r6.get("cleanup_note")))

    lim_keil = RT._limits(FakeBackend())
    lim_ocd = RT._limits(FakeBackend(name="ocd"))
    check("H17 两条链路各自披露自己的时间粒度限制（不是同一段文案）",
          lim_keil["timing"] != lim_ocd["timing"]
          and "profile_function" in lim_keil["timing"], (lim_keil, lim_ocd))


def section_i():
    print("I. client D-Cache 原语")
    c = uvclient.UVClient(host="127.0.0.1", port=PORT)
    c.read_mem = lambda a, n: {"ok": True, "data_hex": struct.pack("<I", 1 << 16).hex(),
                               "n_bytes": 4}
    st = c.dcache_status()
    check("I1 读 SCB->CCR bit16 判 D-Cache 使能",
          st["ok"] and st["dcache"] is True and st["icache"] is False, st)
    c.read_mem = lambda a, n: {"ok": False, "status_text": "读不到(mock)"}
    st2 = c.dcache_status()
    check("I2 读不到 SCB->CCR → ok=false 且如实说读不到（不猜 dcache=false）",
          st2["ok"] is False and "读不到" in st2["error"], st2)

    writes = []

    def fake_write(a, d):
        writes.append((int(a), bytes(d)))
        return {"ok": True}

    c.write_mem = fake_write
    r = c.cache_clean_invalidate(0x20001000)
    check("I3 维护顺序必须是 clean(DCCMVAC) → invalidate(DCIMVAC)",
          [w[0] for w in writes] == [uvclient.UVClient._SCB_DCCMVAC,
                                     uvclient.UVClient._SCB_DCIMVAC], writes)
    check("I4 clean/invalidate 写入的是目标地址本体",
          all(struct.unpack("<I", w[1])[0] == 0x20001000 for w in writes), writes)
    check("I5 两步都成功才 ok=true", r["ok"] is True and len(r["ops"]) == 2, r)

    writes.clear()
    c.write_mem = lambda a, d: {"ok": False, "status_text": "写失败(mock)"}
    r2 = c.cache_clean_invalidate(0x20001000)
    check("I6 写 SCB 失败 → ok=false 且逐条记失败原因（不假装做过）",
          r2["ok"] is False and all(not o["ok"] for o in r2["ops"])
          and "写失败" in r2["ops"][0]["error"], r2)


def _mk_elf(path, text_addr=0x60000000, text_size=0x100):
    """手搓一个最小 ELF32：一个 SHF_EXECINSTR 段，用来验证判据来自节头而非硬编码。"""
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    shstr = b"\x00.text\x00.shstrtab\x00"
    ehsize, shentsize = 52, 40
    shoff = ehsize
    str_off = shoff + 3 * shentsize
    eh = ident + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, (text_addr | 1), 0,
                             shoff, 0, ehsize, 0, 0, shentsize, 3, 2)
    assert len(eh) == 52, len(eh)
    sh_null = b"\x00" * 40
    sh_text = struct.pack("<IIIIIIIIII", 1, 1, 0x2 | 0x4, text_addr, 0,
                          text_size, 0, 0, 4, 0)
    sh_str = struct.pack("<IIIIIIIIII", 7, 3, 0, 0, str_off, len(shstr), 0, 0, 1, 0)
    with open(path, "wb") as f:
        f.write(eh + sh_null + sh_text + sh_str + shstr)
    return path


def section_j():
    print("J. locator：代码区判据来自 .axf 事实，不写死 STM32 布局")
    axf = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                       "mdk_test", "mdk_test.axf")
    loc = LOC.Locator(axf)
    check("J1 有 .axf 时判据来源标为 elf-sections（链接器写下的事实）",
          loc.code_range_source == "elf-sections", loc.code_range_source)
    rng = loc._exec_ranges()
    check("J2 代码范围来自 ELF 可执行段（ER_IROM1: 0x08000000+0x36EC）",
          rng == [(0x08000000, 0x080036EC)], rng)
    check("J3 段内地址判为代码（Thumb 位先清掉）",
          loc.is_code_address(0x08000000) and loc.is_code_address(0x08000101), "")
    check("J4 同属 Flash 但**不在**可执行段内的地址判为非代码"
          "（经验值 0x08000000..0x081FFFFF 会误判成代码）",
          loc.is_code_address(0x08020000) is False, loc.is_code_address(0x08020000))
    check("J5 RAM 地址判为非代码", loc.is_code_address(0x20000000) is False, "")

    tmpd = tempfile.mkdtemp(prefix="mdk49elf")
    p = _mk_elf(os.path.join(tmpd, "xip.elf"), text_addr=0x60000000, text_size=0x200)
    loc2 = LOC.Locator(p)
    check("J6 换基址（0x60000000 的 XIP 镜像）→ 按该 .axf 的段判定，不认 0x08000000",
          loc2.is_code_address(0x60000010) is True
          and loc2.is_code_address(0x08000000) is False
          and loc2.code_range_source == "elf-sections",
          (loc2._exec_ranges(), loc2.is_code_address(0x60000010)))
    loc3 = LOC.Locator(p)          # 缓存按 (路径, mtime) 命中，结果应稳定
    check("J7 同一 .axf 的结果稳定（(路径, mtime) 缓存）",
          loc3._exec_ranges() == loc2._exec_ranges(), loc3._exec_ranges())

    _sym_ranges = loc._load_code_ranges()
    check("J7b 判据方法名不与既有 _code_ranges（符号区间缓存）撞名——"
          "撞名会让 _load_code_ranges 把 bound method 当区间列表迭代，"
          "连带 is_covered / locate / 调用栈回溯全挂",
          not callable(getattr(loc, "_code_ranges", None))
          and isinstance(_sym_ranges, list)
          and isinstance(loc.is_covered(0x08000000), bool),
          (type(getattr(loc, "_code_ranges", None)).__name__,
           type(_sym_ranges).__name__))

    c = uvclient.UVClient(host="127.0.0.1", port=PORT)
    c.read_mem = lambda a, n: {"ok": False, "status_text": "读不到(mock)"}
    c._last_stop_obs_ts = 0.0
    c.running_cached = lambda ttl=1.0, fresh=False: False
    r = c.read_mem_verified(0x20000000, 16, verify="true")
    reads_before = 0
    calls = []

    def counting(a, n):
        calls.append(int(a))
        return {"ok": True, "data_hex": ("00" * 16), "n_bytes": 16}

    c.read_mem = counting
    r2 = c.read_mem_verified(0x20000000, 16)
    check("J8 退化帧只**复读**，不去读 SCB->CCR（读路径零额外目标访问）",
          len(calls) >= 2 and all(x != c.read_mem.__self__._SCB_CCR if False else
                                  x != uvclient.UVClient._SCB_CCR for x in calls),
          calls)
    check("J9 退化帧 + RAM 区 → 给 D-Cache 因果线索并指向 dcache_maintain",
          "dcache_maintain" in (r2.get("cache_note") or "")
          and "cache_info" in (r2.get("cache_note") or ""), r2.get("cache_note"))
    check("J10 线索只解释成因，不替用户改值：data_hex 仍是目标真实回读的整帧 0",
          r2["data_hex"] == "00" * 16, r2["data_hex"])
    check("J11 Flash 区的退化帧不给 D-Cache 线索（不是 cache 问题，别乱指）",
          "cache_note" not in (c.read_mem_verified(0x08000000, 16) or {}), "")


def section_k():
    print("K. server 侧三工具")
    srv = SV.create_server(port=PORT + 1)

    # --- trace_record 参数与状态 ---
    r = call(srv, "trace_record", {"action": "status"})
    check("K1 没录过就查 status → 明确报错并指向 action=run",
          r.get("ok") is False and "还没有录制过" in r.get("error", ""), r)
    r = call(srv, "trace_record", {"action": "nope"})
    check("K2 未知 action → 列出可用取值",
          r.get("ok") is False and r.get("available") == ["run", "status", "read", "stop"],
          r)

    loc = FakeLocator(ranges=[(0x100, 0x200, "task_a"), (0x300, 0x400, "task_b")])
    rest_loc = use_locator(loc)
    try:
        r = call(srv, "trace_record", {"action": "run"})
        check("K3 funcs/pattern 都为空 → 报错并给示例函数名（不下全表断点）",
              r.get("ok") is False and "没有指定要监控的函数" in r.get("error", "")
              and r.get("examples"), r)
        r = call(srv, "trace_record", {"action": "run", "funcs": "no_such_fn"})
        check("K4 名字对不上 → 报「没匹配到任何函数」并列出未知名",
              r.get("ok") is False and r.get("unknown_names") == ["no_such_fn"], r)

        loc2 = FakeLocator(ranges=[])
        rest_loc2 = use_locator(loc2)
        r = call(srv, "trace_record", {"action": "run", "funcs": "task_a"})
        rest_loc2()
        check("K5 符号里没有函数区间（只有 .map）→ 报错说清需要 .axf",
              r.get("ok") is False and ".axf" in r.get("error", ""), r)

        be = FakeBackend(hits=[{"pc": 0x100, "lr": 0x351, "sp": 0x20001000}],
                         slots_n=4)
        rest_pick = use_pick(be)
        rest_cli = use_client(MemClient(rd32_regions({}) ))
        rest_sc = use_attr(SV, "_symbol_source_check",
                           lambda client=None, axf="", deep="auto", server=None:
                           {"verdict": "different", "warning": "符号不是刚烧的那份"})
        try:
            r = call(srv, "trace_record", {"action": "run", "funcs": "task_a",
                                           "pattern": "task_*", "max_breakpoints": 2})
            check("K6 run 成功：selected 列出「函数名@运行地址」，action=run"
                  "（funcs 精确选 + pattern 通配选并集，去重）",
                  r.get("ok") is True and r.get("action") == "run"
                  and r.get("selected") == ["task_a@0x100", "task_b@0x300"],
                  r.get("selected"))
            check("K7 返回值写明本次实际走了哪条链路",
                  r.get("link") == "keil" and "keil" in (r.get("link_label") or "").lower(),
                  (r.get("link"), r.get("link_label")))
            check("K8 事件里的函数名带「可能与板上固件不同源」的口径提示",
                  "假符号" in (r.get("symbol_note") or ""), r.get("symbol_note"))
            check("K9 check_symbols 默认开：符号核对结论一并带上，警告单独置顶",
                  r.get("symbol_check", {}).get("verdict") == "different"
                  and "符号不是刚烧的那份" in (r.get("symbol_check_warning") or ""), r)
            check("K10 这次生效的 reloc_delta 与来源说明都回显",
                  r.get("reloc_delta") == "0x0" and r.get("reloc_note"), r.get("reloc_note"))
            st = call(srv, "trace_record", {"action": "status"})
            check("K11 status 给上次报告摘要但**不带** timeline（免得刷屏）",
                  st.get("action") == "status" and "timeline" not in st
                  and "timeline_hint" in st, sorted(st.keys()))
            rd = call(srv, "trace_record", {"action": "read", "kind": "enter"})
            check("K12 read 可按 kind 过滤时间线，并说明过滤只作用于已保留窗口",
                  rd.get("action") == "read" and len(rd.get("timeline") or []) == 1
                  and "events_kept" in (rd.get("timeline_note") or ""), rd.get("timeline_note"))
            rd2 = call(srv, "trace_record", {"action": "read", "kind": "exit"})
            check("K13 read 过滤掉全部事件时给空列表（不伪造事件）",
                  rd2.get("timeline") == [], rd2.get("timeline"))
            sp = call(srv, "trace_record", {"action": "stop"})
            check("K14 stop：停目标并撤掉上次残留的断点",
                  sp.get("ok") is True and sp.get("action") == "stop"
                  and sp.get("breakpoints_left") == [], sp)
        finally:
            rest_sc()
            rest_cli()
            rest_pick()
    finally:
        rest_loc()

    # --- env_check ---
    rest_pick = use_pick(None, {"ok": False, "reason": "no-mem-link",
                                "error": "两个链路都没有活着的调试会话"})
    rest_cli = use_client(None)
    try:
        r = call(srv, "env_check", {})
        check("K15 没有活会话时如实报 link=null + link_error，而不是假装体检过",
              r.get("ok") is True and r.get("link") is None
              and r.get("link_error"), r.get("link_error"))
        check("K16 chip 明确说「本工具只在 Keil 链路读 IDCODE」并给 OCD 侧替代做法",
              r["chip"]["confidence"] == "none" and "ocd_probe" in r["chip"]["reason"],
              r["chip"])
        check("K17 配置侧把内置寄存器表的系列也列出来（它也是会配错的一环）",
              r["configured"]["builtin_regmap"] == "STM32F4", r["configured"])
        check("K18 未加载 SVD 时给出加载指引",
              "svd_list" in (r["configured"].get("svd_note") or ""), r["configured"])
        check("K19 读不到芯片身份 → problems 里有 chip-identity 且带错误码",
              any(p.get("what") == "chip-identity"
                  and p.get("error_code") == "chip-unknown" for p in r["problems"]),
              r["problems"])
        check("K20 verdict 不会因为「没发现问题」而说 consistent",
              r.get("verdict") in ("mismatch", "unverified"), r.get("verdict"))
        check("K21 note 讲清 consistent/unverified 的含义边界",
              "没发现问题" in (r.get("note") or ""), r.get("note"))
        check("K21b link_state 把「链路不可用」与「已连通」分开说（batch50）",
              r.get("link_state") == "unavailable", r.get("link_state"))
        check("K21c 没实测出芯片 → guard.active=false，并**明说守卫本次没生效**、"
              "别把「体检没报错」当成「一定没问题」",
              r["guard"]["active"] is False
              and "没有生效" in r["guard"]["note"]
              and "自行核对型号" in r["guard"]["note"]
              and any("enter_debug" in a for a in r["guard"]["next_actions"]),
              r.get("guard"))
    finally:
        rest_pick()
        rest_cli()

    chip_h7 = {"series": "STM32H7", "confidence": "high", "dev_id_hex": "0x450",
               "model": "STM32H74x/75x", "reason": ""}
    rest_pick = use_pick(FakeBackend(), None)
    rest_cli = use_client(MemClient())
    rest_probe = use_attr(SV, "_probe_chip_cached", lambda client, ttl=5.0: dict(chip_h7))
    rest_sc = use_attr(SV, "_symbol_source_check",
                       lambda client=None, axf="", deep="auto", server=None:
                       {"verdict": "content-mismatch", "warning": "符号与板上固件不同源",
                        "next_actions": ["set_symbol_file 切到对应 .axf"]})
    try:
        r = call(srv, "env_check", {})
        ms = [c for c in r["checks"] if c.get("verdict") == "mismatched"]
        check("K22 实测 H7 + 内置表 F4 → 逐项 checks 标出 mismatched 并带 what",
              any(c.get("what") == "builtin_regmap" for c in ms), r["checks"])
        check("K23 不一致汇总进 problems 并给出「按实测系列换 SVD」的动作",
              any(p.get("error_code") == "svd-device-mismatch" for p in r["problems"])
              and any("换寄存器表/SVD" in a for a in r["next_actions"]), r["next_actions"])
        check("K24 符号与固件不同源时 problems 里单列一项并接上 next_actions",
              any(p.get("what") == "symbol-as-firmware" for p in r["problems"])
              and "set_symbol_file 切到对应 .axf" in r["next_actions"],
              r["problems"])
        check("K25 有真问题时 verdict=mismatch（不吞掉）",
              r.get("verdict") == "mismatch", r.get("verdict"))
        check("K25b 实测出芯片系列 → guard.active=true，说明守卫生效（batch50）",
              r["guard"]["active"] is True and r["guard"]["next_actions"] == []
              and "守卫生效" in r["guard"]["note"], r.get("guard"))
    finally:
        rest_sc()
        rest_probe()
        rest_cli()
        rest_pick()

    # --- dcache_maintain ---
    mc = MemClient({0xE000ED14: struct.pack("<I", 1 << 16),
                    0xE000EF00: b"\x00" * 0x100,
                    0x20001000: b"\x11" * 64})
    rest_cli = use_client(mc)
    try:
        r = call(srv, "dcache_maintain", {})
        check("K26 status 报出 D-Cache 使能状态并带上可执行 hint",
              r.get("ok") is True and r.get("dcache") is True
              and "clean_invalidate" in (r.get("hint") or ""), r)
        r = call(srv, "dcache_maintain", {"action": "clean_invalidate"})
        check("K27 clean_invalidate 缺 addr → 报错说清要按地址定位 cache 行",
              r.get("ok") is False and "addr 必填" in r.get("error", ""), r)
        r = call(srv, "dcache_maintain", {"action": "clean_invalidate", "addr": "zzz"})
        check("K28 addr 解析失败 → 明确报解析失败，不静默按 0 处理",
              r.get("ok") is False and "addr 解析失败" in r.get("error", ""), r)
        r = call(srv, "dcache_maintain", {"action": "clean_invalidate",
                                          "addr": "0x20001000", "n_bytes": 8})
        check("K29 维护前后各读一遍并对比：changed=false 时明说「不是缓存陈旧造成」",
              r.get("ok") is True and r.get("changed") is False
              and "不是缓存陈旧" in (r.get("note") or ""), r.get("note"))
        check("K30 ops 里两步操作都留痕（clean/invalidate 各自成败）",
              len(r.get("ops") or []) == 2, r.get("ops"))
        mc2 = MemClient({0xE000EF00: b"\x00" * 0x100, 0x20001000: b"\x11" * 64})
        mc2.running_cached = lambda ttl=1.0, fresh=False: True
        rest_cli2 = use_client(mc2)

        def fake_ci(a):
            mc2.regions[0x20001000] = b"\x22" * 64
            return {"ok": True, "ops": [{"op": "clean(DCCMVAC)", "ok": True},
                                        {"op": "invalidate(DCIMVAC)", "ok": True}]}

        mc2.cache_clean_invalidate = fake_ci
        r = call(srv, "dcache_maintain", {"action": "clean_invalidate",
                                          "addr": "0x20001000"})
        rest_cli2()
        check("K31 维护后内容变了 → 判定「此前那次读确实取到陈旧副本」",
              r.get("changed") is True and "陈旧副本" in (r.get("note") or ""),
              (r.get("changed"), r.get("note")))
        check("K32 目标在全速运行 → 警告写 SCB 可能未生效（不谎报已维护）",
              r.get("target_running") is True and "未生效" in (r.get("warning") or ""),
              r.get("warning"))
    finally:
        rest_cli()

    # --- query_memory_map 补上设备守卫（批次49 复查项） ---
    src = open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    seg = src[src.find('name="query_memory_map"'):]
    seg = seg[:seg.find('name="', 200)]
    check("K33 query_memory_map 也做了器件识别守卫（原来只有外设类工具有）",
          "_periph_device_guard" in seg and "allow_mismatch" in seg, seg[:200])


def section_m():
    print("M. 批次51 trace 文档缺口与「没录过」的下一步")
    from mdkdebug import errors as ERR
    from mdkdebug import trace as TRC

    g = TRC.GUIDE
    howto = g.get("howto") or ""
    limits = g.get("swd_limits") or ""
    check("M1 howto 讲清 SWD 两线也能录函数进入/退出（不再是只有采样）",
          "trace_record" in howto and "FPB" in howto and "CYCCNT" in howto, howto[-200:])
    check("M2 swd_limits 明确 trace_record 是侵入式且受 FPB 槽位限制",
          "trace_record" in limits and "侵入式" in limits and "FPB" in limits,
          limits[-200:])
    check("M3 说明它不需要 SWO 引脚、也不需要目标侧 RTT 代码（别让用户白接线）",
          "不需要 SWO" in limits and "RTT" in limits, "")
    check("M4 结论行把 trace_record 归进 SWD 两线能做到的事",
          "trace_record" in limits.split("结论：")[-1], limits[-160:])
    check("M5 同时给出选型口径（事件用 record / 占比用 pcsample）",
          "两者怎么选" in limits, "")

    srv = SV.create_server(port=PORT + 3)
    r = call(srv, "trace_record", {"action": "read"})
    check("M6 「没录过」带机器可读错误码 no-recording（不靠中文猜）",
          r.get("ok") is False and r.get("error_code") == "no-recording", r)
    env = ERR.normalize("trace_record", {"ok": False, "error_code": "no-recording",
                                         "error": "本进程还没有录制过"})
    joined = " ".join(env.get("next_actions") or [])
    check("M7 信封不再把 trace_record 的失败指去 ocd_status/OpenOCD",
          "ocd_status" not in joined and "OpenOCD" not in joined, joined)
    check("M8 但给出的是「先跑 run 录一次」这条真正该做的",
          "action=\"run\"" in joined, joined)
    check("M9 trace_record 的通用未归类错误先指向 trace_guide（双链路都指得对）",
          "trace_guide" in " ".join(ERR.code_actions("trace_record", "unknown-error")), "")
    other = " ".join(ERR.code_actions("trace_swo_status", "unknown-error"))
    check("M10 其他 trace_ 工具同样先指 trace_guide，不再给 OpenOCD 兜底那一套",
          "trace_guide" in other and "toolchain_list" not in other, other)
    check("M11 非 trace_ 的非 MDK 工具仍按 OpenOCD 给（别改坏原行为）",
          "ocd_status" in " ".join(ERR.code_actions("ocd_status", "unknown-error")), "")

    links = g.get("links") or ""
    check("M12 swd_limits 收录 MDK 原生那条（Event Recorder/Event Statistics），"
          "并说清它不占 SWO 引脚",
          "Event Recorder" in limits and "Event Statistics" in limits
          and "不是 SWO 引脚" in limits, "")
    check("M13 明确它是插桩式（不调 API 的地方不会自动有记录），不许被当成自动捕获",
          "必须插桩" in limits and "不是**自动捕获所有函数" in limits, "")
    check("M14 把「侵入式」拆成插桩/停机两个维度，并点明 RTT 不停机",
          "插桩" in limits and "停机" in limits and "停机但不停机" not in limits
          and "RTT / Event Recorder **不会**" in limits, "")
    check("M15 给出四类选型口径（改代码与否 × 停机与否 + 无损那条）",
          "选型：SWD 两线做函数级观测" in limits and "全自动、无损、每跳都记" in limits, "")
    check("M16 links 说明 MDK 原生缓冲现在由 trace_eventrec 直接解码（批次53）",
          "Event Recorder" in links and "trace_eventrec" in links
          and "能直接解码" in links, "")
    check("M17 结论行三类手段齐全（非侵入观测 / 免插桩停机 / 插桩不停机）",
          all(x in limits.split("结论：")[-1] for x in
              ("trace_scope", "trace_record", "Event Recorder")), "")


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
    section_k()
    section_m()
    print("\n批次49 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
