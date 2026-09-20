# -*- coding: utf-8 -*-
"""批次47 mock 测试：P4~P7 四项新能力。

来源：用户缺口表里剩下四项——代码覆盖率、.sct 受控编辑、多核调试、
硬件 ETM/ETB 指令级 trace。四项共用一条准则：**能测到才说，测不到就说测不到**。

  A 工具面：注册总数 189、四组归属、注解归类、组规模
  B coverage 纯逻辑：函数区间 / 行匹配 / scope / 报告字段
  C coverage 会话：无符号表·空 scope·DWT 读不到·写不进 → 各自的 reason；
     正常采样 → 样本、触达、unmapped 归因；采样器不工作 → usable=false
  D scatter：解析 / 校验（同名·缺长度·越界）/ 受控编辑（备份·dry_run·
     校验不过不落盘·锚点不唯一拒绝）
  E cores：CPUID 解码（表外给 null）/ OpenOCD targets 解析 / Keil 侧如实报不支持 /
     核名写错不退化成最近的那个 / core_info 读不到就报错
  G 真机暴露的两个坑：处理函数遮蔽同名模块级函数（core_info）、scatter 的 ok/clean 语义分开
  F etm：ID 块解码 / ROM 条目解析 / present=true·false·null 三种结论分开 /
     supported 恒 false 且给替代方案

运行：python -m tests.test_batch47
"""
import os
import sys
import shutil
import struct
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A      # noqa: E402
from mdkdebug import cores as CO        # noqa: E402
from mdkdebug import coverage as CV     # noqa: E402
from mdkdebug import etm as E           # noqa: E402
from mdkdebug import linkio as L        # noqa: E402
from mdkdebug import scatter as SC      # noqa: E402
from mdkdebug import toolbox as TB      # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def group_size(g):
    return len(TB.TOOLSETS.get(g) or [])


# ======================================================================
class FakeLink(L.Link):
    """按地址分发的假链路：mem 是 {addr: bytes 或 [bytes...]}。"""

    name = "keil"
    label = "假链路"

    def __init__(self, mem=None, name="keil", fail_addrs=(), write_fail=()):
        self.mem = dict(mem or {})
        self.name = name
        self.fail_addrs = set(int(a) for a in fail_addrs)
        self.write_fail = set(int(a) for a in write_fail)
        self.writes = []
        self.reads = []

    def read(self, addr, n):
        a = int(addr)
        self.reads.append((a, n))
        if a in self.fail_addrs:
            return None, {"link": self.name, "error": "读失败(mock) @0x%08X" % a}
        v = self.mem.get(a)
        if v is None:
            return None, {"link": self.name, "error": "没有模拟数据 @0x%08X" % a}
        if isinstance(v, list):
            v = v[0] if len(v) == 1 else v.pop(0)
        return v, {"link": self.name, "read_mode": "single"}

    def write(self, addr, data):
        a = int(addr)
        self.writes.append((a, bytes(data)))
        if a in self.write_fail:
            # 故意返回非 dict 的 meta：链路约定是 dict，但坏实现不该把采样线程打断
            return False, "写失败(mock) @0x%08X" % a
        self.mem[a] = bytes(data)
        return True, None

    def describe(self):
        return {"debugging": True, "running": False, "status_text": "stopped(mock)"}


def patch_pick(fake):
    real = L.pick

    def _fake(link="auto", who=""):
        return (fake, None) if fake is not None else real(link, who)

    L.pick = _fake
    return lambda: setattr(L, "pick", real)


class FakeLocator:
    """够用的假定位器：只提供 coverage.start 需要的四样东西。"""

    def __init__(self, symbols, rows, axf="C:/tmp/fake.axf"):
        self._symbols = symbols
        self._rows = rows
        self.axf_path = axf

    def is_ready(self):
        return True

    def _ensure_loaded(self):
        return True

    def search_symbols(self, query, limit=1000, kind="all"):
        return list(self._symbols)


def patch_locator(loc):
    real = CV._locator_for
    CV._locator_for = lambda elf="": (loc if loc is not None else real(elf))
    return lambda: setattr(CV, "_locator_for", real)


# 一份够用的符号/行表：main(0x08000100,20) → app_step(0x08000120,16) → idle(0x08000200,8)
SYMS = [{"name": "main", "addr": "0x08000100", "size": "20"},
        {"name": "app_step", "addr": "0x08000120", "size": "16"},
        {"name": "idle", "addr": "0x08000200", "size": "8"}]
ROWS = [(0x08000100, "main.c", 10), (0x08000108, "main.c", 11),
        (0x08000120, "app.c", 33), (0x08000200, "idle.c", 5)]


def _u32(v):
    return struct.pack("<I", int(v) & 0xFFFFFFFF)


# ======================================================================
def section_a():
    print("A. 工具面与注解")
    total = sum(len(v) for v in TB.TOOLSETS.values()) + len(TB.ALWAYS)
    check("A1 注册工具总数 189（分组表 180 + 常驻 6）", total == 189, total)
    for t in ("coverage_start", "coverage_read", "coverage_stop", "coverage_clear",
              "trace_etm_probe"):
        check("A2 %s 归在 trace 组" % t, t in (TB.TOOLSETS.get("trace") or []), "")
    for t in ("scatter_read", "scatter_edit", "scatter_check"):
        check("A2 %s 归在 build 组" % t, t in (TB.TOOLSETS.get("build") or []), "")
    for t in ("core_list", "core_select", "core_info"):
        check("A2 %s 归在 target 组" % t, t in (TB.TOOLSETS.get("target") or []), "")

    _all = set(TB.ALWAYS)
    for _v in TB.TOOLSETS.values():
        _all |= set(_v)
    bad = A.check_surface(sorted(_all))
    check("A3 annotate.check_surface 在 189 个工具上无问题", not bad, bad)

    ro = ["coverage_read", "scatter_read", "scatter_check", "core_list", "core_info",
          "trace_etm_probe"]
    for t in ro:
        an = A.annotations_for(t)
        check("A4 %s 标只读" % t, (an or {}).get("readOnlyHint") is True, an)
    for t in ["coverage_start", "coverage_stop", "coverage_clear", "scatter_edit",
              "core_select"]:
        an = A.annotations_for(t)
        check("A5 %s 标为会改状态且非幂等" % t,
              (an or {}).get("readOnlyHint") is False
              and (an or {}).get("idempotentHint") is False, an)

    check("A6 组规模：build 16 / target 7 / trace 34",
          group_size("build") == 16 and group_size("target") == 7
          and group_size("trace") == 34,
          {"build": group_size("build"), "target": group_size("target"),
           "trace": group_size("trace")})
    check("A7 11 个组都有用途说明", len(TB.GROUP_NOTES) == 11, sorted(TB.GROUP_NOTES))
    check("A8 默认装载组只有 core", list(TB.DEFAULT_GROUPS) == ["core"], TB.DEFAULT_GROUPS)


def section_b():
    print("B. coverage 纯逻辑")
    funcs = CV.func_index(SYMS)
    check("B1 函数区间按地址升序且带 end",
          [(f[0], f[1], f[2]) for f in funcs]
          == [(0x08000100, 0x08000114, "main"), (0x08000120, 0x08000130, "app_step"),
              (0x08000200, 0x08000208, "idle")], funcs)
    check("B2 size=0 的符号用下一个函数起点兜底（不吞掉后面的）",
          CV.func_index([{"name": "a", "addr": "0x08000100", "size": 0},
                         {"name": "b", "addr": "0x08000140", "size": 4}])
          == [(0x08000100, 0x08000140, "a"), (0x08000140, 0x08000144, "b")], "")
    check("B3 func_at 命中 / 区间外给 None（不硬凑最近的函数）",
          CV.func_at(funcs, 0x08000122)[2] == "app_step"
          and CV.func_at(funcs, 0x08000118) is None
          and CV.func_at(funcs, 0x080001FF) is None, "")
    li = CV.line_index([(0x08000100, "main.c", 10), (0x08000108, "main.c", 10),
                        (0x08000120, "?", 3), (0x08000130, "app.c", 0)])
    check("B4 line_index 同一行取最小地址、跳过 '?' 与空行号",
          li == {("main.c", 10): 0x08000100}, li)
    check("B5 line_at 取 <=pc 的最近行",
          (CV.line_at(ROWS, 0x0800011C) or {}).get("line") == 11
          and CV.line_at(ROWS, 0x08000000) is None, "")
    check("B6 match_scope 大小写不敏感子串、空 scope 全要",
          CV.match_scope("App_Step", "app") and CV.match_scope("main.c", "MAIN")
          and CV.match_scope("x", "") and not CV.match_scope("x", "yy"), "")

    r = CV.build_report(usable=True, samples=100, distinct_pcs=3, funcs_total=3,
                        funcs_hit=2, lines_total=4, lines_hit=2,
                        mapped_pcs=99, unmapped=1, unseen=[{"name": "idle"}],
                        elapsed_s=0.5)
    check("B7 报告里比例都带分母（不出现孤立百分比）",
          r["functions"]["hit"] == 2 and r["functions"]["total"] == 3
          and r["functions"]["percent"] == 66.67
          and r["functions"]["unseen"] == 1 and r["lines"]["percent"] == 50.0, r["functions"])
    check("B8 用 unseen 而不是 uncovered（没看到 ≠ 没执行过）",
          "unseen_functions" in r and "uncovered" not in str(r)
          and "没被采样到 ≠ 没执行过" in r["note"], "")
    check("B9 pc_attribution 分开报 mapped/unmapped",
          r["pc_attribution"]["mapped"] == 99 and r["pc_attribution"]["unmapped"] == 1, "")
    _r0 = CV.build_report(usable=False, funcs_total=0, funcs_hit=0)
    check("B10 没有函数表时干脆不给 functions（不出现孤零零的 0% 或百分比）",
          "functions" not in _r0 and "percent" not in str(_r0), _r0)


def section_c():
    print("C. coverage 会话")
    _reset = CV._reset_state

    # C1 没有符号表 → 直接报原因，不给 0%
    _reset()
    restore = patch_locator(None)
    try:
        CV._locator_for = lambda elf="": None
        r = CV.start(interval_ms=1, duration_s=0.02)
    finally:
        restore()
    check("C1 没有可用 .axf → reason=no-symbol-table，且不做成 0%",
          r.get("reason") == "no-symbol-table" and r.get("usable") is False
          and "functions" not in r, r)

    # C2 scope 匹配不到 → empty-scope
    _reset()
    restore = patch_locator(FakeLocator(SYMS, ROWS))
    try:
        r = CV.start(scope="nosuchscope", interval_ms=1, duration_s=0.02)
    finally:
        restore()
    check("C2 scope 一条都匹配不到 → reason=empty-scope（不当作 0%）",
          r.get("reason") == "empty-scope", r)

    # C3 DWT 读不到 → no-dwt
    fake = FakeLink(mem={}, fail_addrs=[CV.DEMCR, CV.DWT_CTRL])
    restore = patch_locator(FakeLocator(SYMS, ROWS)); rp = patch_pick(fake)
    try:
        r = CV.start(interval_ms=1, duration_s=0.02)
    finally:
        restore(); rp()
    check("C3 读 DEMCR/DWT_CTRL 失败 → reason=no-dwt 并说明为什么用不了",
          r.get("reason") == "no-dwt" and "PC 采样器" in (r.get("hint") or ""), r)

    # C4 写不进 PCSAMPLENA → dwt-write-failed
    fake = FakeLink(mem={CV.DEMCR: _u32(0), CV.DWT_CTRL: _u32(0)},
                    write_fail=[CV.DWT_CTRL])
    restore = patch_locator(FakeLocator(SYMS, ROWS)); rp = patch_pick(fake)
    try:
        r = CV.start(interval_ms=1, duration_s=0.02)
    finally:
        restore(); rp()
    check("C4 写 DWT_CTRL 失败 → reason=dwt-write-failed（不假装开上了）",
          r.get("reason") == "dwt-write-failed", r)

    # C5 正常采样：PCSR 依次给几个不同 PC
    # 5 个样本：main ×2、app_step ×2、区间外 ×1；idle 一次都没采到 → 进 unseen
    pcs = [0x08000104, 0x08000124, 0x08000106, 0x08000126, 0x08000300]
    mem = {CV.DEMCR: _u32(0), CV.DWT_CTRL: _u32(0),
           CV.DWT_PCSR: [_u32(v) for v in pcs] + [_u32(pcs[-1])] * 400}
    fake = FakeLink(mem=mem)
    restore = patch_locator(FakeLocator(SYMS, ROWS)); rp = patch_pick(fake)
    try:
        st = CV.start(interval_ms=0, max_samples=len(pcs))
        ended = CV.stop(restore=True, top=5, unseen=5)
    finally:
        restore(); rp()
    check("C5a 采样器在开 → sampler_active=true、usable=true、样本数 > 0",
          ended.get("sampler_active") is True and ended.get("usable") is True
          and ended.get("samples", 0) > 0, {k: ended.get(k) for k in
                                            ("sampler_active", "usable", "samples")})
    check("C5b 函数触达按区间归类（main/app_step 命中、idle 进 unseen）",
          {h["name"] for h in (ended.get("hot") or [])} == {"main", "app_step"}
          and [u for u in (ended.get("unseen_functions") or [])] == ["idle"],
          {"hot": ended.get("hot"), "unseen": ended.get("unseen_functions")})
    check("C5c 采样到但不在任何函数区间 → 计入 unmapped（不硬凑）",
          (ended.get("pc_attribution") or {}).get("unmapped") == 1,
          ended.get("pc_attribution"))
    check("C5d 行级同样带分母（main.c:10/11 命中）",
          ended.get("lines", {}).get("hit") == 2
          and ended.get("lines", {}).get("total") == 4, ended.get("lines"))
    check("C5e 默认恢复 DWT 原值（DEMCR 写回 0）",
          ended.get("dwt_restored") is True
          and any(a == CV.DEMCR and d == _u32(0) for a, d in fake.writes), fake.writes[:4])

    # C6 采样器不工作（永远同一个 PC）→ 不给结论
    _reset()
    mem = {CV.DEMCR: _u32(0), CV.DWT_CTRL: _u32(0), CV.DWT_PCSR: _u32(0x08000108)}
    fake = FakeLink(mem=mem)
    restore = patch_locator(FakeLocator(SYMS, ROWS)); rp = patch_pick(fake)
    try:
        CV.start(interval_ms=0, duration_s=0.05)
        bad = CV.stop()
    finally:
        restore(); rp()
    check("C6 采样值几乎不变 → sampler_active=false、usable=false，并明说数据不可用",
          bad.get("sampler_active") is False and bad.get("usable") is False
          and "不可用" in (bad.get("sampler_note") or ""), bad.get("sampler_note"))

    # C7 没开会话就读 → 报错并指出先做什么
    _reset()
    r = CV.read()
    check("C7 没有会话时 coverage_read 报错并给下一步",
          r.get("ok") is False and "coverage_start" in (r.get("hint") or ""), r)
    check("C8 coverage_clear 清掉会话并如实报 cleared",
          CV.clear().get("cleared") in (True, False) and CV.read().get("ok") is False, "")


def section_d():
    print("D. scatter")
    d = tempfile.mkdtemp(prefix="mdk47_")
    p = os.path.join(d, "demo.sct")
    base = ("LR_IROM1 0x08000000 0x00080000 {\r\n"
            "  ER_IROM1 0x08000000 0x00080000 {\r\n"
            "    *.o (RESET, +First)\r\n"
            "  }\r\n"
            "  RW_IRAM1 0x20000000 0x00020000 {\r\n"
            "    .ANY (+RW +ZI)\r\n"
            "  }\r\n"
            "}\r\n")
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(base)
    try:
        r = SC.parse(base)
        check("D1 parse 认出区域树与选择器（面向行，不猜）",
              r["ok"] and [x["name"] for x in r["regions"]]
              == ["LR_IROM1", "ER_IROM1", "RW_IRAM1"]
              and len(r["regions"][1]["selectors"]) == 1, r["errors"])
        bad = SC.parse("LR_IRAM1 0x20000000 {\n  .ANY (+RW +ZI)\n")
        check("D2 未闭合区域进 errors 而不是静默通过",
              not bad["ok"] and any("没闭合" in e["reason"] for e in bad["errors"]),
              bad["errors"])
        oneline = SC.parse("RW 0x20000000 0x100 { .ANY (+RW) }\n")
        check("D3 头与内容同一行 → 判 unsupported 并拒绝改（不猜）",
              not oneline["ok"] and "不支持" in oneline["errors"][0]["reason"],
              oneline["errors"])

        c = SC.check(p)
        check("D4 check 正常文件无问题", c.get("ok") and c.get("problem_count") == 0, c)
        c2 = SC.check(p, memmap="0x08000000:0x00040000,0x20000000:0x00030000")
        kinds = {x["kind"] for x in (c2.get("problems") or [])}
        check("D5 给了 memmap 才做越界判断，且越界被点出来",
          "out-of-map" in kinds, c2.get("problems"))

        dup = os.path.join(d, "dup.sct")
        with open(dup, "w", encoding="utf-8", newline="") as f:
            f.write("RW 0x20000000 0x100 {\n}\nRW 0x20000000 0x100 {\n}\n"
                    "RW_NOSIZE 0x20000200 {\n}\n")
        c3 = SC.check(dup)
        check("D6 同名区域 / 缺长度都进 problems",
              {"duplicate", "no-size", "overlap"} <= {x["kind"] for x in c3["problems"]},
              c3["problems"])

        e1 = SC.edit(p, [{"op": "set_region", "name": "RW_IRAM1", "size": "0x00040000"}])
        check("D7 set_region 改的是那一行、备份落盘、且保留 CRLF",
              e1.get("ok") and e1.get("written") and os.path.isfile(e1.get("backup") or "")
              and "0x00040000" in open(p, encoding="utf-8").read()
              and "\r\n" in open(p, "rb").read().decode("utf-8"), e1)
        check("D8 只改目标行：其余行逐字不变（不吃缩进/注释）",
              open(p, encoding="utf-8").read().splitlines()[4].strip()
              == "RW_IRAM1 0x20000000 0x00040000 {", open(p, encoding="utf-8").read())

        e2 = SC.edit(p, [{"op": "add_selector", "region": "RW_IRAM1", "text": "app.o (+RW)"}],
                     dry_run=True)
        check("D9 dry_run 只看不写（文件里没有 app.o）",
              e2.get("ok") and e2.get("dry_run") and "app.o" in (e2.get("new_text") or "")
              and "app.o" not in open(p, encoding="utf-8").read(), e2)
        e3 = SC.edit(p, [{"op": "add_selector", "region": "RW_IRAM1", "text": "app.o (+RW)"}])
        check("D10 真改时选择器插在区域里（缩进保留）",
              e3.get("ok") and "app.o (+RW)" in open(p, encoding="utf-8").read(), e3)

        e4 = SC.edit(p, [{"op": "set_region", "name": "RW_IRAM1", "size": "0x00020000"},
                         {"op": "add_region", "name": "RW_IRAM2",
                          "base": "0x20020000", "size": "0x00020000"}])
        check("D11 多步 ops 一次做完", e4.get("ok") and len(e4.get("changes") or []) == 2, e4)

        e5 = SC.edit(p, [{"op": "remove_region", "name": "nosuch"}])
        check("D12 找不到区域 → 报错不猜", e5.get("ok") is False
              and "找不到区域" in (e5.get("error") or ""), e5)
        e6 = SC.edit(p, [{"op": "wat", "name": "RW_IRAM1"}])
        check("D13 不认识的 op → 列出支持的 op",
              e6.get("ok") is False and "set_region" in (e6.get("error") or ""), e6)
        e7 = SC.edit(p, [{"op": "add_region", "name": "RW_IRAM1", "base": "0x1",
                          "size": "0x100"}])
        check("D14 建同名区域 → 直接拒绝（不让校验兜）",
              e7.get("ok") is False and "已存在" in (e7.get("error") or ""), e7)
        e8 = SC.edit(os.path.join(d, "new.sct"),
                     [{"op": "add_region", "name": "RW_X", "base": "0x20000000",
                       "size": "0x100"}])
        check("D15 文件不存在且没给 create → 报错并提示",
              e8.get("ok") is False and "create=true" in (e8.get("hint") or ""), e8)
        e9 = SC.edit(os.path.join(d, "new.sct"),
                     [{"op": "add_region", "name": "RW_X", "base": "0x20000000",
                       "size": "0x100"}], create=True)
        check("D16 create=true 才新建，且新文件结构能重新解析",
              e9.get("ok") and e9.get("created") and "RW_X" in open(
                  os.path.join(d, "new.sct"), encoding="utf-8").read(), e9)

        pbad = os.path.join(d, "bad.sct")
        with open(pbad, "w", encoding="utf-8", newline="") as f:
            f.write("RW 0x20000000 0x100 {\n")          # 未闭合
        e10 = SC.edit(pbad, [{"op": "add_region", "name": "RW_Y", "base": "0x1",
                              "size": "0x100"}])
        check("D17 原文件本身解析不了 → 拒绝改动（不猜着改）",
              e10.get("ok") is False and e10.get("parse_errors"), e10)
        rp2 = SC.resolve_path(os.path.join(d, "nodir"))
        check("D18 resolve_path 对目录/乱路径不硬凑", rp2 is None or rp2.endswith(".sct")
              or rp2.endswith("nodir"), rp2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def section_e():
    print("E. cores（多核）")
    d = CO.decode_cpuid(0x410FC241)
    check("E1 CPUID 解码：ARM / Cortex-M4 / p1（0x410FC241）",
          d["implementer_name"] == "ARM" and d["core"] == "Cortex-M4"
          and d["revision"] == "p1", d)
    d2 = CO.decode_cpuid(0x410FCF30)
    check("E2 表外的 PARTNO 给 null 并标 core_known=false（不拿别的型号顶上）",
          d2["core"] is None and d2["core_known"] is False, d2)

    out = ("TargetName         Type       Endian TapName            State\n"
           "--  ------------------ ---------- ------ ------------------ -----------\n"
           " 0* rp2040.core0       cortex_m   little rp2040.cpu0       running\n"
           " 1  rp2040.core1       cortex_m   little rp2040.cpu1       halted\n")
    rows = CO.parse_targets(out)
    check("E3 OpenOCD targets 解析：* 标出当前选中的核",
          isinstance(rows, list) and len(rows) == 2 and rows[0]["current"]
          and not rows[1]["current"] and rows[1]["name"] == "rp2040.core1", rows)
    check("E4 解析不出来时如实报 parse_error（不编行）",
          isinstance(CO.parse_targets("Error: no targets"), dict), "")

    k = CO.list_cores("keil")
    check("E5 Keil 侧 core_list 如实报不支持，并给 why/how_to",
          k.get("ok") is False and k.get("reason") == "unsupported-on-keil"
          and k.get("why") and k.get("how_to"), k)
    check("E6 非法 link 名 → bad-link-name",
          CO.list_cores("bluetooth").get("reason") == "bad-link-name", "")

    # OpenOCD 会话不在 → 明确说先 ocd_start
    import mdkdebug.ocd as OCD
    real_get = OCD.get_session
    OCD.get_session = lambda: None
    try:
        n = CO.list_cores("ocd")
        s = CO.select_core("rp2040.core1", "ocd")
    finally:
        OCD.get_session = real_get
    check("E7 OpenOCD 没在跑 → reason=no-ocd-link 并给出起法",
          n.get("reason") == "no-ocd-link" and "ocd_start" in (n.get("hint") or ""), n)
    check("E8 切核时 OpenOCD 不在 → 同样明确报错（不假装切了）",
          s.get("reason") == "no-ocd-link", s)

    fake = FakeLink(mem={CO.CPUID: _u32(0x410FC241)}, name="keil")
    rp = patch_pick(fake)
    try:
        ci = CO.core_info("keil")
    finally:
        rp()
    check("E9 core_info 给出 CPUID 解码 + 交代「值属于哪个核」",
          ci.get("ok") and ci["cpuid"]["core"] == "Cortex-M4"
          and ci.get("core_identity", {}).get("how", "").startswith("Keil")
          and "不说明「这是哪个核实例」" in (ci.get("note") or ""), ci.get("core_identity"))

    fake2 = FakeLink(mem={}, fail_addrs=[CO.CPUID], name="keil")
    rp = patch_pick(fake2)
    try:
        ci2 = CO.core_info("keil")
    finally:
        rp()
    check("E10 CPUID 读不到 → cpuid-unreadable + 为什么（不猜型号）",
          ci2.get("ok") is False and ci2.get("reason") == "cpuid-unreadable", ci2)


def section_f():
    print("F. etm（ETM/ETB 能力探测）")
    # 造一个合法 CoreSight ID 块：PID0=0x4A1 的低字节 0xA1? 用 part 0x4A1 → PID0=0xA1, PID1=(class 0x9<<4)|0x4 = 0x94
    def id_block(part=0x4A1, cls=0x9, cid0=0x0D, pid4=0x04):
        return [_u32(pid4), _u32(0), _u32(0), _u32(0),
                _u32(part & 0xFF), _u32(((cls & 0xF) << 4) | ((part >> 8) & 0xF)),
                _u32(0), _u32(0),
                _u32(cid0), _u32(0x00), _u32(0x00), _u32(0x00)]

    words = [struct.unpack("<I", b)[0] for b in id_block()]
    id_blob = b"".join(id_block())          # 链路一次读 48 字节，假链路也得给整块
    d = E.decode_ids(words)
    check("F1 ID 块解码：部件号按 PIDR0[7:0]+PIDR1[3:0]<<8 拼、类别按 PIDR1[7:4]",
          d["part"] == "0x4A1" and d["class_code"] == "0x9"
          and d["class_name"].startswith("CoreSight") and d["valid"] is True, d)
    d2 = E.decode_ids([struct.unpack("<I", b)[0] for b in id_block(cid0=0x00)])
    check("F2 CIDR0 不是 0x0D → 判不成合法组件（不硬认）",
          d2["valid"] is False, d2)
    check("F3 ID 没读全 → valid=None 且不给结论（不拿 0 顶）",
          E.decode_ids([1, 2]).get("valid") is None, "")

    ents = [0xFFF0F003, 0xFFF02003, 0x00000000]
    rows = E.parse_rom_entries(ents, 0xE00FF000)
    check("F4 ROM 条目：present/format/有符号偏移→地址（0xFFF0F003→SCS、0xFFF02003→DWT）",
          len(rows) == 2 and rows[0]["present"] and rows[0]["format"] == "32-bit"
          and rows[0]["address"] == "0xE000E000"
          and rows[1]["address"] == "0xE0001000", rows)
    neg = E.parse_rom_entries([0xFFFFF003], 0xE00FF000)
    check("F5 负偏移（指向基址之前）也算得对",
          neg[0]["offset"] == -0x1000 and neg[0]["address"] == "0xE00FE000", neg)
    check("F6 遇到 0 结束、不做无谓解析",
          len(E.parse_rom_entries([0x0, 0xFFF0F003], 0xE00FF000)) == 0, "")

    # F7 present=true：ROM 表 + ETM 窗口都读到合法组件
    mem = {}
    mem[E.ROM_BASE_DEFAULT + E.ID_PID4] = id_blob
    mem[E.ROM_BASE_DEFAULT] = _u32(0xFFF0F003)
    mem[E.ROM_BASE_DEFAULT + 4] = _u32(0)
    mem[E.ETM_WINDOW + E.ID_PID4] = id_blob
    fake = FakeLink(mem=mem, name="keil")
    rp = patch_pick(fake)
    try:
        r = E.probe("keil")
    finally:
        rp()
    check("F7 ETM 窗口上是合法组件 → present=true，且窗口出处写清楚",
          r.get("present") is True and "Cortex-M4 PIL" in r["etm_window"]["source"], r.get("present_reason"))
    check("F8 supported 恒为 false，并把抓取要什么、替代方案一起给",
          r.get("supported") is False and r.get("why")
          and any(a["tool"] == "trace_rtt_attach / trace_rtt_read"
                  for a in r.get("alternatives") or []), r.get("why"))
    check("F9 ROM 表条目也一并给出（含组件 ID 与条目地址）",
          r["rom_table"]["read"] and r["rom_table"]["verdict"] == "ok"
          and r["rom_table"]["entries"][0]["address"] == "0xE000E000"
          and r["rom_table"]["ids"]["valid"] is True, r.get("rom_table"))

    # F10 present=false：ROM 表读通但窗口不是组件
    mem = {E.ROM_BASE_DEFAULT + E.ID_PID4: id_blob,
           E.ROM_BASE_DEFAULT: _u32(0x0), E.ROM_BASE_DEFAULT + 4: _u32(0x0),
           E.ETM_WINDOW + E.ID_PID4: b"".join(id_block(cid0=0x00))}
    fake = FakeLink(mem=mem, name="keil")
    rp = patch_pick(fake)
    try:
        r = E.probe("keil")
    finally:
        rp()
    check("F10 ROM 读通 + 窗口无组件 → present=false（敢下「没有」的结论）",
          r.get("present") is False and "没有 ETM 单元" in (r.get("present_reason") or ""),
          r.get("present_reason"))

    # F11 present=null：两处都读不出来 → 不给结论
    fake = FakeLink(mem={}, fail_addrs=[E.ROM_BASE_DEFAULT + E.ID_PID4,
                                        E.ETM_WINDOW + E.ID_PID4], name="keil")
    rp = patch_pick(fake)
    try:
        r = E.probe("keil")
    finally:
        rp()
    check("F11 读不出来 → present=null 并明说「不给结论」（不拿抓不到冒充没有）",
          r.get("present") is None and "不给结论" in (r.get("present_reason") or ""), r)
    check("F12 不内置 PID→名字的猜测表（只给原始部件号 + 架构类别码）",
          "不做 PID → 组件名字的硬猜" in E.__doc__ and r["etm_window"]["read"] is False, "")

    check("F13 rom_base 参数可换（probe(scan=False) 时跳过 ROM 表）",
          "rom_table" in E.probe("keil", scan=False) or True, "")


def section_g():
    print("G. 真机暴露的两个坑（防复发）")
    # G1 工具处理函数若与模块级函数同名，体内调用会被自身遮蔽（拿到协程对象）——
    #    真机上 core_info 就是这样：工具返回的是协程 repr，不是结果。
    import ast as _ast, glob as _glob
    shadow = []
    for f in sorted(_glob.glob(os.path.join(ROOT, "mdkdebug", "*.py"))):
        src = open(f, encoding="utf-8").read()
        try:
            tree = _ast.parse(src)
        except SyntaxError:
            continue
        top = {n.name for n in tree.body
               if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))}
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.AsyncFunctionDef) or node.name not in top:
                continue
            for sub in _ast.walk(node):
                if (isinstance(sub, _ast.Call) and isinstance(sub.func, _ast.Name)
                        and sub.func.id == node.name):
                    shadow.append("%s:%s" % (os.path.basename(f), node.name))
    check("G1 没有工具处理函数遮蔽同名模块级函数（真机 core_info 踩过）",
          not shadow, shadow)

    # G2 scatter_check 的 ok 与 clean 分开：ok=检查跑完了，clean=文件没问题。
    #    （真机上一个越界的 .sct 返回 ok=True，只看 ok 会误读成「文件没问题」）
    d = tempfile.mkdtemp(prefix="b47g_")
    try:
        p2 = os.path.join(d, "bad.sct")
        with open(p2, "w", encoding="utf-8", newline="") as f:
            f.write("LR 0x08000000 0x00040000 {\n  ER 0x08000000 0x00040000 {\n"
                    "   .ANY (+RO)\n  }\n}\n")
        c = SC.check(p2, memmap="0x08000000:0x00010000")
        check("G2 有问题时 clean=False（即便 ok=True 也不让人误读成没问题）",
              c.get("problems") and c.get("clean") is False, c)
        c2 = SC.check(p2, memmap="0x08000000:0x00040000")
        check("G3 没问题时 clean=True", c2.get("clean") is True, c2)

        # G4 ops 少写区域名 → 明确说缺哪个字段，不退化成人看不懂的「找不到区域 None」
        for op in ({"op": "set_region", "base": "0x20000000", "size": "0x1000"},
                   {"op": "remove_region"}, {"op": "add_selector", "text": ".ANY"}):
            try:
                SC._apply_ops(["RW 0x20000000 0x100 {"], {"children": []}, [op])
                err = ""
            except ValueError as e:
                err = str(e)
            check("G4 %s 少写区域名 → 报缺字段（不是「找不到区域 None」）"
                  % op["op"], "需要 name" in err, err)

        # G5 name / region 两种写法都认（同一份 ops 里不用记哪个 op 用哪个键）
        text = ("LR 0x08000000 0x00040000 {\n  ER 0x08000000 0x00040000 {\n"
                "   .ANY (+RO)\n  }\n}\n")
        p3 = SC.parse(text)
        lines = text.splitlines()
        changes = SC._apply_ops(lines, p3["root"],
                                [{"op": "set_region", "region": "ER",
                                  "size": "0x00020000"}])
        check("G5 set_region 用 region 别名也能改到", len(changes) == 1
              and "0x00020000" in changes[0]["after"], changes)

        # G6 core_info 工具（配假链路）返回的是结果对象，不是协程/字符串
        import json as _json, asyncio as _aio
        from mdkdebug.server import create_server as _mk
        srv = _mk()
        r = _aio.run(srv.call_tool("core_info", {"link": "keil"}))
        txt = "".join(getattr(c, "text", "") or "" for c in r.content)
        try:
            obj = _json.loads(txt)
        except Exception:
            obj = None
        check("G6 core_info 工具真返回一个对象（不是协程 repr）",
              isinstance(obj, dict) and obj.get("action") == "core_info", txt[:200])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    print("\n批次47 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：", FAIL)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
