# -*- coding: utf-8 -*-
"""批次56 mock 测试：小上下文下的工具面（描述分层 + nano 档 + 装卸元工具）。

背景：用户反馈「上下文较小的大模型装不全 MCP 工具」。工具数只是成本的一半，
另一半是**每个工具的描述**（199 个工具 ~9.5 万字符，八成是参考手册式长文）。
本批给三条路：

  * **描述分层**：常驻层只留一句话 + 【输出控制】/【参数】块，长正文归档，
    `mdk_guide(topic="tool", name=...)` 逐字取回。档位 `full`(默认) / `lean` / `min`。
  * **`nano` 档位**：19 个工具（15 个最短入口 + 6 个元工具），自动用 `min` 描述档。
  * **两个装卸元工具**：`tools_groups` / `tools_load`（参数比 `toolset` 更少）。

  A 工具面：注册总数 199 / 常驻元工具 6 / 默认暴露 44 / nano 19
  B 组名解析：nano 是已知档位（不再被误报未知组），真未知组照旧报出
  C 描述档位：full 是默认、nano 走 min、认不出的写法按默认并告警
  D 瘦身不变量：结构化尾块整段保留、尾部关键告警保留、归档可逐字取回、full 档不动
  E 元工具：mdk_guide / tools_groups / tools_load 的行为与错误码
  F 无缝流时间粒度：resolve_granularity 全档位映射 + cpu_hz=0 明确报错
  G 协议 v2：版本号/偏移/标志位常量，HITN 只在量化后 dt==0 时用（省字节）
  H 宿主折时间轴三分支：TS_OFF 绝不编假时间、dt_unit 精确除法、ts_shift 移位
  I 文档同步：README / SKILL 写上 nano 档与描述分层

运行：python -m tests.test_batch56
"""
import os
import sys
import json
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import swd as SWD             # noqa: E402
from mdkdebug import thin as TH             # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402

PORT = 15496

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def names(srv):
    return sorted(srv._tool_manager._tools)

def tool_of(srv, nm):
    return srv._tool_manager._tools[nm]

def call_sync(server, name, args=None):
    async def _go():
        r = await server.call_tool(name, args or {})
        parts = []
        for c in getattr(r, "content", []) or []:
            t = getattr(c, "text", None)
            if t is not None:
                parts.append(t)
        txt = "\n".join(parts) if parts else str(r)
        try:
            return json.loads(txt)
        except Exception:
            return {"_raw": txt}
    return asyncio.run(_go())

def desc_chars(srv):
    return sum(len((t.description or "")) for t in srv._tool_manager._tools.values())

def fresh(**kw):
    """建一个 server（清掉上次的环境残留影响，靠显式 toolsets 语义）。

    desc= 显式指定描述档位（默认不设 → 走产品默认档 full）。
    描述档位在 create_server 期间读环境变量，所以这里临时设、建完立刻还原。
    """
    desc = kw.pop("desc", None)
    saved = os.environ.pop("MDKDEBUG_DESC", None)
    try:
        if desc:
            os.environ["MDKDEBUG_DESC"] = desc
        return SV.create_server(port=PORT, **kw)
    finally:
        os.environ.pop("MDKDEBUG_DESC", None)
        if saved is not None:
            os.environ["MDKDEBUG_DESC"] = saved

# ----------------------------------------------------------------------
def section_a():
    print("A. 工具面规模")
    srv = fresh(toolsets="all")
    allnames = names(srv)
    check("A1 注册总数 199", len(allnames) == 199, len(allnames))
    check("A2 常驻元工具 6 个（含 tools_groups/tools_load）",
          TB.ALWAYS == {"list_tools", "get_version", "capabilities", "toolset",
                        "tools_groups", "tools_load"}, sorted(TB.ALWAYS))
    check("A3 两个新元工具确实注册了",
          "tools_groups" in allnames and "tools_load" in allnames)
    check("A4 annotate 对全部 199 个工具无问题",
          not A.check_surface(allnames), A.check_surface(allnames)[:3])
    check("A5 tools_groups 标只读、tools_load 标可写",
          A.annotations_for("tools_groups").get("readOnlyHint") is True
          and A.annotations_for("tools_load").get("readOnlyHint") is False,
          (A.annotations_for("tools_groups"), A.annotations_for("tools_load")))

    saved = os.environ.pop("MDKDEBUG_TOOLSETS", None)
    try:
        d = fresh(toolsets=None)
        dn = names(d)
        check("A6 默认暴露 44 个（core 38 + 常驻 6）", len(dn) == 44, len(dn))
        check("A7 默认面上有 6 个元工具",
              set(TB.ALWAYS) <= set(dn), sorted(set(TB.ALWAYS) - set(dn)))
        check("A8 默认不含 trace 组工具（按需装载）",
              "trace_swd_read" not in dn and "ocd_start" not in dn)
        st = call_sync(d, "toolset", {"action": "status"})
        check("A9 status 自述一致（暴露 44 / 收起 155 / 注册 199）",
              st.get("exposed") == 44 and st.get("hidden") == 155
              and st.get("total_registered") == 199, st)
    finally:
        if saved is not None:
            os.environ["MDKDEBUG_TOOLSETS"] = saved

    n = fresh(toolsets="nano")
    nn = names(n)
    want_nano = len(set(TB.NANO_TOOLS) | set(TB.ALWAYS))
    check("A10 nano 档 %d 个（15 常用 + 6 元工具，其中 2 个重叠）" % want_nano,
          len(nn) == want_nano == 19, len(nn))
    check("A11 nano 含最短入口与元工具",
          set(TB.NANO_TOOLS) <= set(nn) and set(TB.ALWAYS) <= set(nn),
          sorted(set(TB.NANO_TOOLS) - set(nn)))
    check("A12 nano 不含大块头工具（ocd/trace 重型）",
          "ocd_start" not in nn and "trace_swd_reset" not in nn)
    check("A13 取回入口在 nano 档内（指针不能指向装不上的工具）",
          "mdk_guide" in nn)

def section_b():
    print("B. 组名 / 档位解析")
    want, unk = TB.parse_groups("nano")
    check("B1 parse_groups('nano') 认它是已知档位、无未知组",
          want == ["nano"] and unk == [], (want, unk))
    want, unk = TB.parse_groups("nano,mem")
    check("B2 档位与组名可混写", want == ["nano", "mem"] and unk == [], (want, unk))
    want, unk = TB.parse_groups("mem,nope")
    check("B3 真未知组仍被报出（不静默吞掉）",
          want == ["mem"] and unk == ["nope"], (want, unk))
    check("B4 nano 出现在 available_groups 里",
          "nano" in TB._ALL_GROUP_NAMES, TB._ALL_GROUP_NAMES)
    check("B5 tools_of('nano') 返回 14 个工具；未知组返回 None",
          len(TB.tools_of("nano") or []) == len(TB.NANO_TOOLS)
          and TB.tools_of("nope") is None)
    plan = TB.plan(tool_names=["list_tools", "read_mem", "ocd_start"],
                   spec="nano", source="test")
    check("B6 plan(spec=nano) 保留 nano 工具、收起 ocd_start",
          "read_mem" in plan["kept"] and "ocd_start" in plan["removed"], plan["removed"])

def section_c():
    print("C. 描述档位")
    check("C1 MODES = full/lean/min，默认 full（默认描述不改写）",
          TH.MODES == ("full", "lean", "min") and TH.DEFAULT_MODE == "full",
          (TH.MODES, TH.DEFAULT_MODE))
    check("C2 别名：long/orig→full、short/brief→lean、tiny/none→min",
          (TH._ALIAS.get("long") == "full" and TH._ALIAS.get("orig") == "full"
           and TH._ALIAS.get("short") == "lean" and TH._ALIAS.get("brief") == "lean"
           and TH._ALIAS.get("tiny") == "min" and TH._ALIAS.get("none") == "min"),
          TH._ALIAS)
    saved = os.environ.pop("MDKDEBUG_DESC", None)
    try:
        check("C3 没设环境变量 → 默认档 full", TH.mode_from_env() == "full",
              TH.mode_from_env())
        os.environ["MDKDEBUG_DESC"] = "min"
        check("C4 MDKDEBUG_DESC=min 生效", TH.mode_from_env() == "min")
        os.environ["MDKDEBUG_DESC"] = "tiny"
        check("C5 别名 tiny → min", TH.mode_from_env() == "min")
        os.environ["MDKDEBUG_DESC"] = "bogus"
        check("C6 认不出的写法按默认档处理（不静默变别的档）",
              TH.mode_from_env() == "full", TH.mode_from_env())
        os.environ["MDKDEBUG_DESC"] = "full"
        check("C7 full 显式生效", TH.mode_from_env() == "full")
    finally:
        os.environ.pop("MDKDEBUG_DESC", None)
        if saved is not None:
            os.environ["MDKDEBUG_DESC"] = saved
    check("C8 desc_default_for：纯 nano → min，其余 → full",
          TB.desc_default_for("nano") == "min"
          and TB.desc_default_for("nano,core") == "full"
          and TB.desc_default_for("all") == "full"
          and TB.desc_default_for(None) == "full",
          (TB.desc_default_for("nano"), TB.desc_default_for(None)))

def section_d():
    print("D. 瘦身不变量（宁可多留字符，也不给错答案）")
    srv = fresh(toolsets="all", desc="lean")   # 瘦身路径要显式选档（默认 full 不改写）
    d_rm = tool_of(srv, "read_mem").description or ""
    f_rm = TH.full_of("read_mem") or ""
    check("D1 瘦身后仍带取回指针（【完整说明】…mdk_guide）",
          "【完整说明】" in d_rm and "mdk_guide" in d_rm)
    check("D2 结构化尾块整段保留：【输出控制】/【参数】都在",
          "【输出控制】" in d_rm and "【参数】" in d_rm)
    check("D3 正文尾部关键告警没被截掉（置信度低不要据此下结论）",
          "不要据此下结论" in d_rm)
    check("D4 归档存的是原文（含告警句与【输出控制】），且比常驻层长",
          "不要据此下结论" in f_rm and "【输出控制】" in f_rm
          and len(f_rm) > len(d_rm), (len(f_rm), len(d_rm)))

    missing, bad_tail = [], []
    for nm, tool in srv._tool_manager._tools.items():
        f = TH.full_of(nm)
        if not f:
            continue
        d = tool.description or ""
        for mk in TH._KEEP_MARKERS:
            if mk in f and mk not in d:
                missing.append((nm, mk.strip()))
        i = TH._split_at(f)
        tf = f[i:] if i >= 0 else ""
        if tf and not d.endswith(tf):
            bad_tail.append(nm)
    check("D5 全部瘦身工具：结构化尾块一个不漏", not missing, missing[:3])
    check("D6 全部瘦身工具：尾块逐字保留在描述末尾", not bad_tail, bad_tail[:3])

    # 取回 = 逐字无损：常驻层去掉指针后，必须是原文的前缀/后缀组合
    ptr = d_rm[len(d_rm) - d_rm[::-1].find("mdk_guide") - 9:] if "mdk_guide" in d_rm else ""
    check("D7 常驻层正文来自原文（去掉指针后仍是原文片段）",
          d_rm.split("【完整说明】")[0].strip()[:60] in f_rm, d_rm[:80])

    check("D8 _split_at 对无标记的纯正文返回 -1",
          TH._split_at("这是一段没有结构化尾块的说明。") == -1)
    check("D9 _clip 短正文原样返回（不做任何改写）",
          TH._clip("短说明。") == "短说明。")
    long_body = "第一句说明。" + "中间的细节。" * 80 + "最后一句告警：不要据此下结论。"
    clipped = TH._clip(long_body)
    check("D10 长正文截断后保留段首与段末（含最后那句告警）",
          len(clipped) < len(long_body) and clipped.startswith("第一句说明。")
          and clipped.rstrip().endswith("不要据此下结论。"), clipped[-60:])

    srvn = fresh(toolsets="nano")
    check("D11 nano 档自动用 min 档描述", TH.stats()["mode"] == "min",
          TH.stats()["mode"])
    check("D12 nano 档描述体积极小（< 6000 字符）", desc_chars(srvn) < 6000,
          desc_chars(srvn))
    check("D13 nano 档也能取回完整说明（归档没丢）",
          bool(TH.full_of("read_mem")) and "不要据此下结论" in TH.full_of("read_mem"))

def section_e():
    print("E. 元工具")
    srv = fresh(toolsets="nano")
    g = call_sync(srv, "tools_groups", {})
    check("E1 tools_groups 总览：列出组、档位与当前暴露数",
          g.get("ok") and "core" in (g.get("groups") or {})
          and (g.get("profiles") or {}).get("nano"), g)
    g2 = call_sync(srv, "tools_groups", {"group": "nano"})
    check("E2 tools_groups(group=nano) 列出该档全部工具",
          g2.get("ok") and set(g2.get("tools") or []) == set(TB.NANO_TOOLS),
          g2.get("size"))
    g3 = call_sync(srv, "tools_groups", {"group": "nope"})
    check("E3 未知组 → toolset-unknown-group", g3.get("error_code") == "toolset-unknown-group",
          g3)
    r = call_sync(srv, "tools_load", {"group": "mem"})
    check("E4 tools_load 装组生效", r.get("ok") and r.get("exposed") == 19 + len(
        TB.TOOLSETS["mem"]), r.get("exposed"))
    r2 = call_sync(srv, "tools_load", {"group": "mem", "unload": True})
    check("E5 tools_load(unload=True) 收起生效",
          "read_struct" not in names(srv) and r2.get("action") == "unload", r2.get("exposed"))
    r3 = call_sync(srv, "toolset", {"action": "load", "toolsets": "nano"})
    check("E6 toolset 也认 nano（老入口不落后）",
          r3.get("ok") and r3.get("exposed") == 19, r3.get("exposed"))

    r4 = call_sync(srv, "mdk_guide", {"topic": "tool", "name": "read_mem"})
    check("E7 mdk_guide(topic=tool) 取回完整说明",
          r4.get("ok") and r4.get("thinned") and "不要据此下结论" in (r4.get("description") or ""),
          len(r4.get("description") or ""))
    r5 = call_sync(srv, "mdk_guide", {"topic": "tool", "name": "no_such_tool"})
    check("E8 未知工具名 → guide-unknown-tool",
          r5.get("error_code") == "guide-unknown-tool", r5.get("error_code"))
    r6 = call_sync(srv, "mdk_guide", {"topic": "tool"})
    check("E9 mdk_guide(topic=tool) 无 name → 归档索引",
          r6.get("ok") and r6.get("thinned_tools", 0) > 50, r6.get("thinned_tools"))
    r7 = call_sync(srv, "mdk_guide", {})
    check("E10 mdk_guide 不带 topic 时仍是环境自检（老语义没被描述分层顶掉）",
          r7.get("ok") and bool(r7.get("environment")), str(r7)[:120])
    big = fresh(toolsets="all")
    r8 = call_sync(big, "trace_guide", {"topic": "time_granularity"})
    check("E11 trace_guide(topic=time_granularity) 仍在（粒度文档入口）",
          r8.get("ok") and "粒度" in str(r8), str(r8)[:160])

def section_f():
    print("F. 时间粒度映射")
    cases = [
        (None, 84000000, (None, None, None)),
        ("cycle", 84000000, (0, 0, False)),
        ("none", 84000000, (0, 0, True)),
        ("500us", 84000000, (0, 42000, False)),      # 内核 tick：不是 2 的幂
        ("1ms", 84000000, (0, 84000, False)),
        ("84ns", 84000000, (0, 7, False)),
        (2, 84000000, (0, 168, False)),              # 数字按微秒
        ("1us", 2000000, (1, 0, False)),             # unit=2 → 恰为 2 的幂，走移位
        ("1us", 84000000, (0, 84, False)),           # unit=84 → 84=4*21 不是 2 的幂
        (0, 84000000, (0, 0, False)),                # 比一个周期还细 → 按最小
    ]
    for spec, hz, want in cases:
        try:
            got = SWD.resolve_granularity(spec, hz)[:3]
        except Exception as e:  # noqa: BLE001
            got = "raise:%s" % e
        check("F resolve_granularity(%r, %d) → %r" % (spec, hz, want), got == want, got)
    # "1us" 在 84MHz 下 unit=84 非 2 的幂 → 走除法
    got = SWD.resolve_granularity("1us", 84000000)[:3]
    check("F9 84 周期不是 2 的幂 → 走整数除法（不凑成 2 的幂）",
          got == (0, 84, False), got)
    for spec, hz, frag in (("500us", 0, "cpu_hz"), ("bogus", 84000000, "不认识")):
        try:
            SWD.resolve_granularity(spec, hz)
            check("F10 %r@%d 应报错" % (spec, hz), False, "没报错")
        except ValueError as e:
            check("F10 %r@%d 明确报错（%s）" % (spec, hz, frag), frag in str(e), str(e))
    note = SWD.resolve_granularity("500us", 84000000)[3]
    check("F11 note 如实写明走了哪条路径（不让人猜）",
          "42000" in note and ("除法" in note or "整数" in note), note)
    note2 = SWD.resolve_granularity("none", 0)[3]
    check("F12 none 档的 note 说明「不能画成等距就等于有时间」",
          "时间" in note2, note2)

def section_g():
    print("G. 协议 v2 与 HITN 省字节")
    check("G1 控制块版本 = 2，兼容 1/2", SWD.VERSION == 2 and set(SWD.SUPPORTED_VERSIONS) == {1, 2},
          (SWD.VERSION, SWD.SUPPORTED_VERSIONS))
    check("G2 dt_unit 偏移 = 68、reset_req = 64（宿主写）",
          SWD.OFF_DT_UNIT == 68 and SWD.OFF_RESET_REQ == 64,
          (SWD.OFF_DT_UNIT, SWD.OFF_RESET_REQ))
    check("G3 FLAG_TS_OFF = bit2（宿主写）", SWD.FLAG_TS_OFF == 1 << 2, SWD.FLAG_TS_OFF)
    check("G4 TAG_HITN = 3（复用空闲 tag，1 字节无 dt）", SWD.TAG_HITN == 3, SWD.TAG_HITN)

    e = SWD.Encoder()
    key = (0, 0, 1, 0)
    warm = e.encode([(key, 5)])
    check("G5 首次见到的 key 走 LIT（必带 dt）", e.stats["lit"] == 1 and len(warm) > 2,
          len(warm))
    hitn = e.encode([(key, 0)])
    check("G6 命中且 dt==0 → HITN 恰好 1 字节",
          e.stats["hitn"] == 1 and len(hitn) == 1
          and (hitn[0] >> 6) == SWD.TAG_HITN, list(hitn))
    hit = e.encode([(key, 9)])
    check("G7 命中但 dt!=0 → HIT + varint（时间不能丢）",
          e.stats["hit"] == 1 and len(hit) == 2 and (hit[0] >> 6) == SWD.TAG_HIT,
          list(hit))

    d = SWD.Decoder()
    evs = d.feed(warm + hitn + hit)
    check("G8 解码回 3 条事件且 key 一致",
          len(evs) == 3 and all(k == key for k, _ in evs), evs)
    check("G9 解码器统计到 1 次 hitn/1 次 hit/1 次 lit",
          (d.hitn, d.hit, d.lit) == (1, 1, 1), (d.hitn, d.hit, d.lit))

    # 粒度调粗后「dt==0」的机会变多 → HITN 自动省字节（不需要额外开关）
    e2 = SWD.Encoder()
    coarse = e2.encode([(key, 0)] * 200)
    e3 = SWD.Encoder()
    fine = e3.encode([(key, 1)] * 200)
    check("G10 粒度调粗（dt 量化成 0）时字节数显著更少（实测省约一半）",
          len(coarse) < len(fine) * 0.6, (len(coarse), len(fine)))

def section_h():
    print("H. 宿主折时间轴三分支")
    key = (0, 0, 1, 0)

    def fold(dt_unit=0, ts_shift=0, ts_off=False, cpu_hz=84000000, dt=3):
        s = {"rel_cycles": 0, "syncs": 0, "events_seen": 0}
        items = [("ev", key, dt)]
        out = TRC._swd_fold(s, items, ts_shift, cpu_hz, {}, dt_unit=dt_unit, ts_off=ts_off)
        return s, out[0]

    s, ev = fold(ts_shift=7)
    check("H1 ts_shift 分支：dt<<7", ev.get("dt_cycles") == 3 << 7 and s["rel_cycles"] == 384, ev)
    s, ev = fold(dt_unit=42000)
    check("H2 dt_unit 分支：dt*42000（精确 tick，不是移位）",
          ev.get("dt_cycles") == 126000 and s["rel_cycles"] == 126000, ev)
    s, ev = fold(ts_off=True, dt_unit=42000)
    check("H3 TS_OFF：dt_cycles 为 None、ts=none",
          ev.get("dt_cycles") is None and ev.get("ts") == "none", ev)
    check("H4 TS_OFF：绝不推进虚拟时间（不编等距假时间）",
          s["rel_cycles"] == 0 and "rel_cycles" not in ev, s["rel_cycles"])
    s, ev = fold(ts_shift=0, dt_unit=0, dt=3)
    check("H5 两者都为 0（最细粒度）：1 周期 / 单位", ev.get("dt_cycles") == 3, ev)
    s, ev = fold(ts_shift=7, cpu_hz=84000000, dt=20)
    check("H6 有时间戳时给出 t_us（按 cpu_hz 换算）",
          abs(ev.get("t_us", 0) - round((20 << 7) * 1e6 / 84000000, 3)) < 1e-6, ev)

def section_i():
    print("I. 文档同步")
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    skill = open(os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md"), encoding="utf-8").read()
    check("I1 README 写了 nano 档与描述分层",
          "nano" in readme and "MDKDEBUG_DESC" in readme, "")
    check("I2 README 写了两个新元工具",
          "tools_groups" in readme and "tools_load" in readme, "")
    check("I3 README 工具数同步为 199（199 个 + 收起 155）",
          "199 个" in readme and "155 个" in readme and "184 个" not in readme, "")
    check("I4 SKILL 写了 nano 档与描述分层",
          "nano" in skill and "MDKDEBUG_DESC" in skill and "mdk_guide" in skill, "")
    check("I5 SKILL 工具数同步为 199", "199 个工具" in skill and "184 个工具" not in skill, "")

def main():
    for fn in (section_a, section_b, section_c, section_d, section_e,
               section_f, section_g, section_h, section_i):
        fn()
    print("\n批次56 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
