# -*- coding: utf-8 -*-
"""批次67 mock 测试：三条来自「另一个 AI 的 H7 + J-Link 反馈」的改进。

背景（原文三句）：`set_symbol_file` 暴露出来、`BK *` 后校验 J-Link 硬件断点寄存器、
检测「同一断点短时间反复命中」并提示可能是复位循环。

三条的共同点是：以前 MCP 给的信号**本身诚实**，但「错误符号绑定 + 断点残留 + 缓存脏读」
叠在一起会掩盖真相，人只能靠猜。所以这一批不新增工具，只让已有工具**给出可查的事实**
和**确定的下一步动作**：

- **P0 链路↔符号对照**（`get_status.uvsock_binding` / `env_check`）：4823 被一个加载了
  别的工程的旧 Keil 实例占着时，符号解析/断点/单步全部落在错误的镜像上（假符号 + error 57
  + 单步退化成指令级）。以前没有任何工具能看出这一点。两条如实披露：① 端口归属或窗口标题
  取不到时留空并说明「无法对照」，不拿符号文件名顶替；② 链路工程与符号工程不一致**不等于**
  出错（正在调 App 时符号本就该是 App 的 .axf），文案必须带这条例外，否则是新的假警报。

- **P1 FPB 硬件断点寄存器**（`clear_all_breakpoints(hard=True).fpb` /
  `list_breakpoints.hardware`）：`BK *` 只清 Keil 的**逻辑**表，清不掉调试器写进**硬件**
  断点单元的项，J-Link 会一直报 "two breakpoints at the same address"。**读不到就报
  unavailable，绝不当成「干净」**（没测 ≠ 没有）。

- **P2 复位循环三态**（`wait_breakpoint.reset_loop` / `breakpoint_stats.rapid`）：
  「断点再次命中」可能是复位循环在重跑启动。判定必须三态——有复位证据才是 True，
  反复命中但分不清复位循环与正常热循环时给 **null**，并明确与 `repeat_warning`
  （语义恰好相反：疑似 halt 残留值、别当反复复位看）区分开。

  A P0 端口归属与工程对照：状态机、诚实留空、例外条款、next_actions
  B P1 FPB：clean / residue / unavailable（读不到、只读到一部分、字段为 0）
  C P1 残留对照：orphans 与 Keil 逻辑表的差集；拿不到逻辑表时「无法对照」
  D P2 命中历史与快速命中统计（含 CYCCNT 回退）
  E P2 启动锚点：向量表的合法校验收敛
  F P2 三态判定 + 与 repeat_warning 的区别
  G 工具面：新字段写进描述、两个符号工具在默认面、错误码就位

运行：python -m tests.test_batch67
"""
import io
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import client as CL          # noqa: E402
from mdkdebug import errors as ER          # noqa: E402
from mdkdebug import server as SV          # noqa: E402
from mdkdebug import toolbox as TB         # noqa: E402
from mdkdebug import winutil as WU         # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def js(o):
    import json
    return json.dumps(o, ensure_ascii=False, default=str)

def src_text():
    with io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8") as f:
        return f.read()

class FakeMem:
    """只认登记过的地址的读内存替身；未登记就报错——宁可报错不给假数据。"""

    def __init__(self, mem=None, zero_first=None):
        self.mem = {}
        for k, v in (mem or {}).items():
            self.mem[int(k)] = v if isinstance(v, bytes) else int(v).to_bytes(4, "little")
        self.zero_first = {int(k): int(v) for k, v in (zero_first or {}).items()}
        self.reads = []

    def read_mem(self, addr, n):
        a = int(addr)
        self.reads.append((a, n))
        if self.zero_first.get(a, 0) > 0:
            self.zero_first[a] -= 1
            return {"ok": True, "data_hex": (b"\x00" * n).hex()}
        b = self.mem.get(a)
        if b is None:
            return {"ok": False, "error": "未登记的地址 %s" % hex(a)}
        return {"ok": True, "data_hex": b[:n].hex()}

class FakeLoc:
    """只实现 _image_base/_reset_anchor 用到的两个接口。"""

    def __init__(self, ranges=None):
        self.ranges = list(ranges or [])

    def _exec_ranges(self):
        return list(self.ranges)

    def is_code_address(self, addr):
        a = int(addr) & ~1
        return any(s <= a < e for s, e in self.ranges)

# FPB：FP_CTRL = NUM_CODE(5) → 6 个代码比较器、NUM_LIT(2) → 3 个字面量比较器、ENABLE=1
FP_CTRL_OK = 0x00000251
FP_COMP0 = 0xE0002008

def fpb_mem(comps, ctrl=FP_CTRL_OK):
    mem = {0xE0002000: ctrl}
    for i, v in enumerate(comps):
        if v is not None:
            mem[FP_COMP0 + 4 * i] = v
    return mem

# ======================================================================
def group_a():
    """A. P0 端口归属与工程对照。"""
    print("== A P0 链路↔符号对照 ==", flush=True)

    # _proj_key：basename 去扩展名再小写
    check("A1 _proj_key 归一：工程文件 → 短名",
          SV._proj_key(r"D:\x\SVCRTOS_TEST.uvprojx") == "svcrtos_test"
          and SV._proj_key("app.axf") == "app"
          and SV._proj_key("PATH/TO/mdk_test.MAP") == "mdk_test", None)
    check("A2 _proj_key 空值不炸、不返回 None",
          SV._proj_key("") == "" and SV._proj_key(None) == "", None)
    check("A3 _proj_key 容忍带引号的路径",
          SV._proj_key('"C:/a/b/foo.uvproj"') == "foo", None)

    # uvsock_binding 状态机（替身，不碰真机）
    real_owner = WU.uvsock_owner
    real_inst = WU.uv4_instances
    real_listen = WU.port_listening
    try:
        WU.uvsock_owner = lambda port=0: {"ok": False, "port": int(port),
                                          "reason": "GetExtendedTcpTable 探测失败（返回 5）"}
        b = WU.uvsock_binding(4823)
        check("A4 端口归属查不到 → state=unknown 且明说「无法判定链路的归属」",
              b.get("state") == "unknown" and "无法判定" in (b.get("note") or ""), b)

        WU.uvsock_owner = lambda port=0: {"ok": True, "port": int(port), "pid": None,
                                          "pids": [], "method": "test"}
        WU.port_listening = lambda port=0: False
        b = WU.uvsock_binding(4823)
        check("A5 没人监听 → state=not-listening（Keil 未起 / UVSOCK 未开）",
              b.get("state") == "not-listening", b)

        WU.port_listening = lambda port=0: True
        b = WU.uvsock_binding(4823)
        check("A6 有人在监听但不是 UV4 → state=foreign-owner（别把命令继续往下发）",
              b.get("state") == "foreign-owner" and "不是 UV4.exe" in (b.get("note") or ""), b)

        WU.uvsock_owner = lambda port=0: {"ok": True, "port": int(port), "pid": 22508,
                                          "pids": [22508], "method": "test"}
        WU.uv4_instances = lambda: [{"pid": 22508, "project": r"D:\p\SVCRTOS_TEST.uvprojx",
                                     "has_window": True, "created": 1758337174}]
        b = WU.uvsock_binding(4823)
        check("A7 归属清晰 → state=bound + 工程名 + 启动时间",
              b.get("state") == "bound"
              and b.get("owner_project") == r"D:\p\SVCRTOS_TEST.uvprojx"
              and b.get("owner_created_str"), b)

        WU.uv4_instances = lambda: [{"pid": 22508, "project": None,
                                     "has_window": False, "created": None}]
        b = WU.uvsock_binding(4823)
        check("A8 实例没有窗口标题 → owner_project 留空并说明「取不到」",
              b.get("state") == "bound" and not b.get("owner_project")
              and "取不到它打开的工程" in (b.get("note") or ""), b)

        WU.uvsock_owner = lambda port=0: {"ok": True, "port": int(port), "pid": 1,
                                          "pids": [1, 2], "method": "test"}
        WU.uv4_instances = lambda: []
        b = WU.uvsock_binding(4823)
        check("A9 多个监听者 → 如实说出「命令发给哪一个不受控」",
              "多个进程同时监听" in (b.get("note") or ""), b)
    finally:
        WU.uvsock_owner = real_owner
        WU.uv4_instances = real_inst
        WU.port_listening = real_listen

    # _binding_state：链路工程 vs 符号工程
    saved_cfg, saved_proj = SV._symbol_cfg, SV._SYMBOL_PROJECTS
    real_binding = WU.uvsock_binding
    try:
        WU.uvsock_binding = lambda port=0: {
            "port": int(port), "state": "bound", "owner_pid": 22508,
            "owner_project": r"D:\p\SVCRTOS_TEST.uvprojx", "note": ""}
        SV._SYMBOL_PROJECTS = [{"name": "mdk_test", "axf": r"D:\p\mdk_test\MDK-ARM\mdk_test\mdk_test.axf"},
                               {"name": "SVCRTOS_TEST", "axf": r"D:\p\svcrtos\SVCRTOS_TEST.axf"}]

        SV._symbol_cfg = {"locator": None, "axf": r"D:\p\mdk_test\MDK-ARM\mdk_test\mdk_test.axf",
                          "source_type": "axf"}
        st = SV._binding_state(4823)
        check("A10 符号 .axf 命中登记表 → matched_by=axf-path、两边工程名都给出",
              st.get("symbol_project") == "mdk_test"
              and st.get("symbol_project_matched_by") == "axf-path"
              and st.get("owner_project_key") == "svcrtos_test"
              and st.get("symbol_project_key") == "mdk_test", st)
        check("A11 链路工程 ≠ 符号工程 → mismatch=instance-vs-symbol",
              st.get("mismatch") == "instance-vs-symbol", st)
        check("A12 警示里给了「假符号 / error 57 / 单步退化」这组真机症状",
              all(k in (st.get("warning") or "")
                  for k in ("error 57", "单步", "假符号")), st.get("warning"))
        check("A13 警示里必须带例外条款：调 App 时不一致本就正常（否则是新的假警报）",
              "调 App" in (st.get("warning") or "") or "有意" in (st.get("warning") or ""),
              st.get("warning"))
        check("A14 next_actions 指向「看清实例 → 收敛窗口 → 重开工程」",
              any("list_uvision_instances" in a for a in (st.get("next_actions") or []))
              and any("close_uvision" in a for a in (st.get("next_actions") or [])), st)

        SV._symbol_cfg = {"locator": None, "axf": r"D:\p\svcrtos\SVCRTOS_TEST.axf",
                          "source_type": "axf"}
        st = SV._binding_state(4823)
        check("A15 两边一致 → 不报 mismatch（不制造噪音）",
              st.get("mismatch") is None and not st.get("warning"), st)

        WU.uvsock_binding = lambda port=0: {
            "port": int(port), "state": "bound", "owner_pid": 22508,
            "owner_project": None, "note": "取不到工程"}
        st = SV._binding_state(4823)
        check("A16 工程名取不到 → 如实说「无法对照」，绝不用符号名顶替",
              st.get("mismatch") is None and "无法与符号来源对照" in (st.get("note") or "")
              and not st.get("owner_project_key"), st)

        SV._symbol_cfg = {"locator": None, "axf": None, "source_type": None}
        WU.uvsock_binding = lambda port=0: {
            "port": int(port), "state": "bound", "owner_pid": 22508,
            "owner_project": r"D:\p\SVCRTOS_TEST.uvprojx", "note": ""}
        st = SV._binding_state(4823)
        check("A17 没加载符号 → 说「无法对照」，不报 mismatch",
              st.get("mismatch") is None and "未加载符号" in (st.get("note") or ""), st)

        def _boom(port=0):
            raise OSError("模拟查询异常")
        WU.uvsock_binding = _boom
        st = SV._binding_state(4823)
        check("A18 查询本身抛异常 → state=unknown 且不改写 mismatch（不猜）",
              st.get("state") == "unknown" and st.get("mismatch") is None, st)

        # 不在登记表里的 .axf（例如 set_symbol_file 指到别处）也要如实说
        WU.uvsock_binding = lambda port=0: {
            "port": int(port), "state": "bound", "owner_pid": 1,
            "owner_project": r"D:\p\SVCRTOS_TEST.uvprojx", "note": ""}
        SV._symbol_cfg = {"locator": None, "axf": r"D:\tmp\wrong.axf", "source_type": "axf"}
        st = SV._binding_state(4823)
        check("A19 符号不在登记表里 → matched_by=None（说清依据是「按文件名比」而不是登记表）",
              st.get("symbol_project") is None
              and st.get("symbol_project_matched_by") is None
              and st.get("symbol_project_key") == "wrong", st)
        check("A19b 但文件名确实不同 → 仍报 mismatch（依据是两边 basename，不是猜）",
              st.get("mismatch") == "instance-vs-symbol", st.get("mismatch"))
    finally:
        SV._symbol_cfg, SV._SYMBOL_PROJECTS = saved_cfg, saved_proj
        WU.uvsock_binding = real_binding

# ======================================================================
def group_b():
    """B. P1 FPB 解码：三态与「没测 ≠ 没有」。"""
    print("== B P1 FPB 解码 ==", flush=True)

    d = SV._fpb_decode(None, [])
    check("B1 读不到 FP_CTRL → unavailable（不是 clean）",
          d.get("check") == "unavailable" and d.get("reason"), d)

    d = SV._fpb_decode(0x00000000, [])
    check("B2 NUM_CODE 字段为 0（1 个 / 未实现两种解释都通）→ unavailable",
          d.get("check") == "unavailable" and "NUM_CODE" in (d.get("reason") or ""), d)

    d = SV._fpb_decode(FP_CTRL_OK, [0x08000DB4] * 6)
    check("B3 全部比较器未启用 → clean，且槽位数按「字段+1」解出（6 代码 / 3 字面量）",
          d.get("check") == "clean" and d.get("code_slots") == 6
          and d.get("lit_slots") == 3 and d.get("unit_enabled") is True, d)
    check("B3b 槽位数附 counts_note 声明口径与不确定性（不把推导值说成权威结论）",
          "个数 - 1" in (d.get("counts_note") or "")
          and "enabled" in (d.get("counts_note") or ""), d.get("counts_note"))
    check("B4 clean 时不给 error_code（不制造假警报）",
          not d.get("error_code"), d)

    d = SV._fpb_decode(FP_CTRL_OK, [0x08000DB5, 0x08000DB4, 0x0, 0x0, 0x0, 0x0])
    check("B5 bit0=1 的比较器即「启用」→ residue",
          d.get("check") == "residue" and d.get("enabled_count") == 1, d)
    check("B6 地址按 bits[31:1] 还原（清掉启用位）",
          d.get("enabled_addrs") == ["0x08000DB4"], d.get("enabled_addrs"))
    check("B7 residue 带 error_code=breakpoint-residue 供信封归类",
          d.get("error_code") == "breakpoint-residue", d)

    d = SV._fpb_decode(FP_CTRL_OK, [None] * 6)
    check("B8 比较器一个都没读到 → unavailable，**不是** clean（没测 ≠ 没有）",
          d.get("check") == "unavailable" and "读失败" in (d.get("reason") or ""), d)

    d = SV._fpb_decode(FP_CTRL_OK, [0x08000DB5] + [None] * 5)
    check("B9 只读到一部分：有启用项仍判 residue（证据优先）",
          d.get("check") == "residue" and d.get("enabled_count") == 1, d)

    d = SV._fpb_decode(FP_CTRL_OK & ~1, [0x08000DB4] * 6)
    check("B10 单元 ENABLE=0 但比较器都未启用 → clean，并把 unit_enabled 如实给出",
          d.get("check") == "clean" and d.get("unit_enabled") is False, d)

    # _fpb_state：读寄存器（含 halt 首读脏帧的重读）
    m = FakeMem(fpb_mem([0x08000DB5, 0x08000DB4, 0x0, 0x0, 0x0, 0x0]))
    st = SV._fpb_state(m)
    check("B11 _fpb_state 读 FP_CTRL + 6 个 FP_COMPn（1+6 次读）",
          st.get("check") == "residue" and len(m.reads) == 7, (st, m.reads))
    check("B12 寄存器地址如实给出（FP_CTRL@0xE0002000 / FP_COMP0@0xE0002008）",
          (st.get("registers") or {}).get("fp_ctrl") == "0xE0002000"
          and (st.get("registers") or {}).get("fp_comp0") == "0xE0002008", st.get("registers"))

    m = FakeMem(fpb_mem([0x08000DB5] + [0x0] * 5), zero_first={0xE0002000: 1})
    st = SV._fpb_state(m)
    check("B13 halt 后首次读可能全 0 脏帧 → 重读一次，结论仍为 residue",
          st.get("check") == "residue" and st.get("reread") is True, (st, m.reads))

    m = FakeMem(fpb_mem([0x0] * 6), zero_first={0xE0002000: 5})
    st = SV._fpb_state(m)
    check("B14 重读仍是全 0 → unavailable 并点明「脏读帧或该核没有 FPB」",
          st.get("check") == "unavailable" and "脏读" in (st.get("note") or ""), st)

    m = FakeMem({})
    st = SV._fpb_state(m)
    check("B15 寄存器读不到 → unavailable（不当作干净）",
          st.get("check") == "unavailable", st)

# ======================================================================
def group_c():
    """C. P1 残留对照（orphans）。"""
    print("== C P1 与 Keil 逻辑表对照 ==", flush=True)

    hw = {"check": "residue", "enabled_addrs": ["0x08000DB4", "0x08001234"]}
    real = {"ok": True, "breakpoints": [{"number": 1, "address": "0x08001234",
                                         "kind": "exec"}]}
    orph = SV._fpb_orphans(hw, real)
    check("C1 硬件里有、Keil 逻辑表里没有的地址 = 残留（BK * 清不掉的）",
          orph == ["0x08000DB4"], orph)

    real = {"ok": True, "breakpoints": [{"number": 1, "address": "0x08000DB5"},
                                        {"number": 2, "address": "0x08001234"}]}
    check("C2 Thumb 位不对齐也要认成同一条（别把在用的断点误报成残留）",
          SV._fpb_orphans(hw, real) == [], SV._fpb_orphans(hw, real))

    check("C3 拿不到 Keil 逻辑表 → 返回 None「无法对照」，而不是「没有孤儿」",
          SV._fpb_orphans(hw, {"ok": False, "error": "未进入调试"}) is None, None)
    check("C4 没有残留时压根不给 orphans（不空转）",
          SV._fpb_orphans({"check": "clean"}, real) is None, None)
    check("C5 _as_int 认 0x / 十进制 / int，认不出返回 None",
          SV._as_int("0x10") == 16 and SV._as_int("16") == 16
          and SV._as_int(16) == 16 and SV._as_int("zz") is None
          and SV._as_int(None) is None and SV._as_int(True) is None, None)

# ======================================================================
def group_d():
    """D. P2 命中历史与快速命中统计。"""
    print("== D P2 命中历史 / rapid_hit_stats ==", flush=True)

    c = CL.UVClient(host="127.0.0.1", port=4823)
    check("D1 命中历史初始为空（不预置任何东西）",
          c._bp_hit_hist == [], c._bp_hit_hist)

    now = time.monotonic()
    c._bp_hit_hist = [(now - 2.4, 0x08000DB4, 0x1000),
                      (now - 1.4, 0x08000DB4, 0x2000),
                      (now - 0.4, 0x08000DB4, 0x0040),   # CYCCNT 回退
                      (now - 0.3, 0x08001234, 0x3000),
                      (now - 9.0, 0x0800AAAA, 0x4000)]   # 窗口外
    st = c.rapid_hit_stats(0x08000DB4, window_s=3.0)
    item = (st.get("checked") or {}).get('0x8000db4')
    check("D2 只统计时间窗内的同址命中（窗口外的老记录不算）",
          item and item.get("hits") == 3, st)
    check("D3 CYCCNT 回退被识别（除溢出外只增，回退 = 内核复位过）",
          item.get("cyccnt_backwards") is True, item)
    check("D4 达阈值（≥3）的地址进 rapid_addrs",
          st.get("rapid_addrs") == ['0x8000db4'], st.get("rapid_addrs"))

    st = c.rapid_hit_stats(window_s=3.0)
    check("D5 不指定地址时给出窗口内所有地址的分布",
          set((st.get("checked") or {})) == {'0x8000db4', '0x8001234'}, st.get("checked"))
    check("D6 只出现 1 次的地址不进 rapid_addrs",
          st.get("rapid_addrs") == ['0x8000db4'], st.get("rapid_addrs"))

    c._bp_hit_hist = [(now - 0.2, 0x08000DB4, None), (now - 0.1, 0x08000DB4, None)]
    item = (c.rapid_hit_stats(0x08000DB4).get("checked") or {}).get('0x8000db4')
    check("D7 CYCCNT 没读到时 back=None 并说明「样本不足」，不冒充「没回退」",
          item.get("cyccnt_backwards") is None and item.get("cyccnt_note"), item)

    c._bp_hit_hist = [(now - 0.2, 0x08000DB4, None)]
    st = c.rapid_hit_stats(0x08001234)
    check("D8 窗口内没有该地址的命中 → 明说「没有记录」",
          not (st.get("checked") or {}) and st.get("reason"), st)

    # note_breakpoint_hit：计数 + 历史一起走
    c2 = CL.UVClient(host="127.0.0.1", port=4823)
    c2._read_cyccnt = lambda: 0x1234          # 不碰真机
    n1 = c2.note_breakpoint_hit(0x08000DB4)
    n2 = c2.note_breakpoint_hit(0x08000DB4)
    check("D9 计数按地址累计，每条命中都进历史",
          n1 == 1 and n2 == 2 and len(c2._bp_hit_hist) == 2, (n1, n2, c2._bp_hit_hist))
    c2b = CL.UVClient(host="127.0.0.1", port=4823)
    c2b._bp_hit_hist = [(time.monotonic(), 0x08000DB4, 1),
                        (time.monotonic(), 0x08000DB5, 2)]
    _it = (c2b.rapid_hit_stats(0x08000DB4).get("checked") or {}).get("0x8000db4")
    check("D9b 带 Thumb 位的命中在统计里归一到同一地址（历史里的两条算一处）",
          _it and _it.get("hits") == 2, _it)
    check("D10 历史里记下 CYCCNT（判复位循环要用）",
          c2._bp_hit_hist[-1][2] == 0x1234, c2._bp_hit_hist)
    for _i in range(90):
        c2.note_breakpoint_hit(0x08000DB4)
    check("D11 历史有上限（只留最近 64 条），不会无限涨",
          len(c2._bp_hit_hist) == 64, len(c2._bp_hit_hist))

    c3 = CL.UVClient(host="127.0.0.1", port=4823)
    c3.read_mem = lambda addr, n: {"ok": False, "error": "目标在跑"}
    check("D12 CYCCNT 读不到就记 None，不编数、不抛异常",
          c3.note_breakpoint_hit(0x100) == 1 and c3._bp_hit_hist[0][2] is None,
          c3._bp_hit_hist)

# ======================================================================
def group_e():
    """E. P2 启动锚点（向量表）。"""
    print("== E P2 向量表锚点 ==", flush=True)

    loc = FakeLoc([(0x08000000, 0x08010000)])
    mem = FakeMem({0x08000000: (0x20001000).to_bytes(4, "little")
                   + (0x08000109).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E1 合法向量表 → ok，给出 image_base / initial_sp / reset_handler",
          a.get("ok") and a.get("image_base") == "0x08000000"
          and a.get("initial_sp") == "0x20001000"
          and a.get("reset_handler") == "0x08000109"
          and a.get("reset_handler_in_image") is True, a)

    mem = FakeMem({0x08000000: (0x00001000).to_bytes(4, "little")
                   + (0x08000109).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E2 word0 不在 SRAM → ok=False 并说明反向，不拿它当锚点",
          a.get("ok") is False and "SRAM" in (a.get("reason") or ""), a)

    mem = FakeMem({0x08000000: (0x20001002).to_bytes(4, "little")
                   + (0x08000109).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E3 word0 未 4 字节对齐 → ok=False",
          a.get("ok") is False and "4 字节对齐" in (a.get("reason") or ""), a)

    mem = FakeMem({0x08000000: (0x20001000).to_bytes(4, "little")
                   + (0x08000108).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E4 word1 的 Thumb 位不是 1 → ok=False（Cortex-M 复位向量必须带 bit0）",
          a.get("ok") is False and "bit0" in (a.get("reason") or ""), a)

    mem = FakeMem({0x08000000: (0x20001000).to_bytes(4, "little")
                   + (0x20000209).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E5 word1 不在镜像可执行段 → ok=False",
          a.get("ok") is False and "可执行段" in (a.get("reason") or ""), a)

    mem = FakeMem({0x08000000: (0x20001000).to_bytes(4, "little")})
    a = SV._reset_anchor(mem, loc)
    check("E6 只能读到 4 字节 → 明说读到的字节数，不半猜",
          a.get("ok") is False and "4 字节" in (a.get("reason") or ""), a)

    a = SV._reset_anchor(FakeMem({}), FakeLoc([]))
    check("E7 取不到镜像基址 → ok=False 并说明「不用猜的基址」",
          a.get("ok") is False and "镜像基址" in (a.get("reason") or ""), a)

    check("E8 _image_base 取可执行段最小起始地址；无段返回 None",
          SV._image_base(FakeLoc([(0x08000000, 0x1000), (0x08010000, 0x100)])) == 0x08000000
          and SV._image_base(FakeLoc([])) is None, None)

# ======================================================================
def group_f():
    """F. P2 三态判定。"""
    print("== F P2 reset_loop 三态 ==", flush=True)

    anchor = {"ok": True, "reset_handler": "0x08000109", "reset_handler_int": 0x08000109,
              "initial_sp": "0x20001000", "initial_sp_int": 0x20001000}

    j = SV._reset_loop_judge({"hits": 2, "span_s": 1.0}, sp=0x20001000, anchor=anchor,
                             hit_addr=0x08000108)
    check("F1 命中次数不到阈值 → suspected=False（不硬扯复位循环）",
          j.get("suspected") is False, j)

    j = SV._reset_loop_judge({"hits": 4, "span_s": 1.2, "cyccnt_backwards": False},
                             sp=0x20001000, anchor=anchor, hit_addr=0x08000108)
    check("F2 命中 Reset_Handler（兼容 Thumb 位）+ SP==initial SP → suspected=True",
          j.get("suspected") is True and len(j.get("evidence") or []) >= 2, j)
    check("F3 说明里明确「别把这次命中当成正常执行到该处」",
          "正常执行到该处" in (j.get("note") or ""), j.get("note"))
    check("F4 下一步指向启动时序核对（读初始化计数 / 串口 / RCC 复位标志）",
          any("read_variable" in a for a in (j.get("next_actions") or []))
          and any("serial_monitor_start" in a for a in (j.get("next_actions") or [])), j)

    j = SV._reset_loop_judge({"hits": 3, "span_s": 2.0, "cyccnt_backwards": True},
                             sp=0x2000FFFF, anchor=None, hit_addr=0x08005010)
    check("F5 仅 CYCCNT 回退这一条硬证据 → 也判 True",
          j.get("suspected") is True
          and any("CYCCNT 回退" in e for e in (j.get("evidence") or [])), j)

    j = SV._reset_loop_judge({"hits": 3, "span_s": 2.0, "cyccnt_backwards": None},
                             sp=0x2000FFFF, anchor=None, hit_addr=0x08005010)
    check("F6 反复命中但一条复位证据都没有 → suspected=None（分不清，别硬判）",
          j.get("suspected") is None, j)
    check("F7 这一档要点明「主机侧分不清复位循环与正常热循环」并给可证的手段",
          "分不清" in (j.get("note") or "") and "Reset_Handler" in (j.get("note") or ""), j.get("note"))

    j = SV._reset_loop_judge({"hits": 3, "span_s": 2.0, "cyccnt_backwards": False},
                             sp=0x2000FFFF, anchor={"ok": False, "reason": "读不到向量表"},
                             hit_addr=0x08005010)
    check("F8 锚点取不到时把它列进 not_checked（缺位要明说，不能当「没有证据」）",
          j.get("suspected") is None
          and any("向量表" in x for x in (j.get("not_checked") or [])), j)

    j = SV._reset_loop_judge({"hits": 3, "span_s": 2.0, "cyccnt_backwards": False},
                             sp=0x20001000, anchor={"ok": True, "initial_sp": "0x20001000",
                                                    "initial_sp_int": 0x20001000},
                             hit_addr=0x08005010)
    check("F9 SP 单独一条也能作为证据（栈被重新装载过）",
          j.get("suspected") is True
          and any("initial SP" in e for e in (j.get("evidence") or [])), j)

    for hits in (0, None):
        j = SV._reset_loop_judge({"hits": hits} if hits is not None else None)
        check("F10 没有命中记录 → suspected=False（不给 None 添乱）",
              j.get("suspected") is False, j)

    j = SV._reset_loop_judge({"hits": 5, "span_s": 1.0, "cyccnt_backwards": True})
    check("F11 必须显式声明与 repeat_warning 的区别（前提相反，不可互相顶替）",
          "repeat_warning" in (j.get("note_vs_repeat_warning") or "")
          and "halt 残留" in (j.get("note_vs_repeat_warning") or ""),
          j.get("note_vs_repeat_warning"))

def group_g():
    """G. 工具面与接线。"""
    print("== G 工具面 / 接线 ==", flush=True)

    names = [t.name for t in __import__("asyncio").run(
        SV.create_server(toolsets="all").list_tools())]
    check("G1 本批不新增工具（总数仍 195）", len(names) == 195, len(names))

    core = TB.TOOLSETS.get("core") or set()
    check("G2 两个符号工具提到默认面 core（钥匙要放在够得着的地方）",
          {"list_symbol_projects", "set_symbol_file"} <= set(core),
          sorted(x for x in core if "symbol" in x))
    check("G3 core 组 38 个 → 默认面 44（core 38 + 常驻 6）",
          len(core) == 38, len(core))
    saved = os.environ.pop("MDKDEBUG_TOOLSETS", None)
    try:
        dn = [t.name for t in __import__("asyncio").run(SV.create_server().list_tools())]
        check("G4 不设环境变量时默认暴露 44 个",
              len(dn) == 44 and "set_symbol_file" in dn, (len(dn), "set_symbol_file" in dn))
    finally:
        if saved is not None:
            os.environ["MDKDEBUG_TOOLSETS"] = saved

    tools = {t.name: (t.description or "") for t in __import__("asyncio").run(
        SV.create_server(toolsets="all").list_tools())}
    check("G5 list_breakpoints 描述交代 hardware 字段（逻辑表 vs 硬件是两回事）",
          "hardware" in tools["list_breakpoints"] and "FPB" in tools["list_breakpoints"]
          and "J-Link" in tools["list_breakpoints"], tools["list_breakpoints"][:120])
    check("G6 clear_all_breakpoints 描述交代 fpb 复核与 breakpoint-residue",
          "FPB" in tools["clear_all_breakpoints"]
          and "breakpoint-residue" in tools["clear_all_breakpoints"], None)
    check("G7 wait_breakpoint 描述交代 reset_loop 三态与 repeat_warning 的区别",
          "reset_loop" in tools["wait_breakpoint"]
          and "repeat_warning" in tools["wait_breakpoint"]
          and "null" in tools["wait_breakpoint"], None)
    check("G8 breakpoint_stats 描述交代 rapid 字段",
          "rapid" in tools["breakpoint_stats"], None)

    check("G9 get_status 结果里带 uvsock_binding（接线到位）",
          'out["uvsock_binding"]' in src_text(), None)
    check("G10 env_check 把 binding-mismatch 归进 problems（error_code 就位）",
          '"binding-mismatch"' in src_text(), None)
    check("G11 断点工具里真去读了 FPB（不是只写在描述里）",
          "out[\"hardware\"] = hw" in src_text() and "out[\"fpb\"] = hw" in src_text(), None)
    check("G12 wait_breakpoint 里真去算了 reset_loop",
          'out["reset_loop"] = j' in src_text(), None)

    check("G13 errors 里有 binding-mismatch（带 next_actions）",
          (ER.ERROR_CODES.get("binding-mismatch") or {}).get("next_actions"), None)
    check("G14 errors 里有 breakpoint-residue（带 next_actions）",
          (ER.ERROR_CODES.get("breakpoint-residue") or {}).get("next_actions"), None)
    check("G15 error 57 文案补上了「链路连到了别的实例/工程」这个成因",
          "binding" in js(ER.ERROR_CODES.get("breakpoint-address-unresolved") or {})
          or "实例" in js(ER.ERROR_CODES.get("breakpoint-address-unresolved") or {}),
          ER.ERROR_CODES.get("breakpoint-address-unresolved"))

def main():
    print("批次67：链路↔符号对照（P0）+ FPB 硬件断点校验（P1）+ 复位循环三态（P2）")
    group_a(); group_b(); group_c(); group_d(); group_e(); group_f(); group_g()
    print("\n==== 批次67 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
