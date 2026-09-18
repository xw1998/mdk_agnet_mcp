# -*- coding: utf-8 -*-
"""批次42 mock 测试：工具面按需加载（默认精简 + 运行期装卸）。

来源：用户在真机反馈里提的两条——「默认 150 个工具全量暴露，对上下文预算和小模型
不友好（有裁剪机制但默认全开）」。处置：

  * 默认**只暴露 core 组 + 4 个常驻入口**（37 个），其余 10 组用
    `toolset(action="load", toolsets="mem,trace")` 现装；
  * `MDKDEBUG_TOOLSETS` 仍然有效，`all` / `full` / `*` 仍是全开；
  * 显式设了组名却一个都认不出来 → **不裁剪**（宁可少裁不错杀）并告警。

本文件锁住的是这批改动的行为边界：
  A 默认精简：37 个、core 齐全、其余组不在、status/capabilities/list_tools 三处自述一致
  B 运行期装卸：load 幂等、unload 还原、装卸后顺序不漂、常驻四件套永在
  C 显式配置：all / serial / core,mem / bogus 四种取值 + create_server(toolsets=) 优先级
  D 分组表完备性：无重复归属、无幽灵名、未归类恰好是四个常驻入口、与 annotate 一致
  E 失败归类：toolset 的三种失败各自落对 error_code（不落 unknown-error）

运行：python -m tests.test_batch42
"""
import asyncio
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug.server import create_server          # noqa: E402
from mdkdebug import toolbox as TB                 # noqa: E402
from mdkdebug import annotate as AN                # noqa: E402
from mdkdebug import errors as ERR                 # noqa: E402

PORT_A, PORT_B, PORT_SUB = 14930, 14931, 14932

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def order(srv):
    """当前暴露的工具名，按注册顺序（不是字典序）。"""
    return [t.name for t in asyncio.run(srv.list_tools())]

def names(srv):
    return sorted(order(srv))

async def call(srv, n, a):
    res = await srv.call_tool(n, a)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    return json.loads(txt)

def call_sync(srv, n, a):
    return asyncio.run(call(srv, n, a))

STAY = {"list_tools", "get_version", "capabilities", "toolset"}

# ======================================================================
# A/B. 默认工具面 + 运行期装卸（同一个 server 实例）
# ======================================================================
def group_ab():
    print("A. 默认工具面（精简）")
    os.environ.pop("MDKDEBUG_TOOLSETS", None)
    srv = create_server(port=PORT_A, toolsets=None)
    ns = names(srv)
    check("A1 默认只暴露 37 个（core 33 + 常驻 4）", len(ns) == 37, len(ns))
    for t in ("enter_debug", "read_mem", "write_mem", "mdk_guide", "session_state",
              "keil_health", "diagnose", "target_info") + tuple(STAY):
        check("A2 默认含 %s" % t, t in ns, "")
    for t in ("serial_read", "build_project", "read_struct", "svd_decode", "watch",
              "trace_swo_read", "trace_scope_start", "ocd_start", "rtos_tasks",
              "toolchain_build", "target_list", "uvprojx_read", "find_symbol"):
        check("A3 默认不含未装载组的 %s" % t, t not in ns, "")

    st = call_sync(srv, "toolset", {"action": "status"})
    check("A4 status 自述一致（core 已装载 / 收起 137 / 注册 174 / 来源 default）",
          st.get("ok") and st.get("loaded_groups") == ["core"]
          and st.get("hidden") == 137 and st.get("total_registered") == 174
          and st.get("source") == "default", {k: st.get(k) for k in
                                              ("loaded_groups", "hidden", "total_registered", "source")})
    g = st.get("groups") or {}
    check("A5 status 列全 11 个组且各组规模正确",
          len(g) == 11 and g.get("core", {}).get("size") == 33
          and g.get("trace", {}).get("size") == 25 and g.get("ocd", {}).get("size") == 17
          and g.get("target", {}).get("size") == 7
          and g.get("rtos", {}).get("size") == 3
          and g.get("serial", {}).get("size") == 14, {k: v.get("size") for k, v in g.items()})
    check("A6 status 给出隐藏工具清单与装回来的办法",
          len(st.get("hidden_tools") or []) == 137 and "toolset" in (st.get("hint") or ""), "")

    cap = call_sync(srv, "capabilities", {})
    su = cap.get("tool_surface") or {}
    check("A7 capabilities 如实报注册总数 / 收起数 / 未装载组",
          su.get("registered_total") == 174 and su.get("hidden") == 137
          and su.get("loaded_groups") == ["core"]
          and "trace" in (su.get("not_loaded_groups") or []), su)
    lt = call_sync(srv, "list_tools", {})
    check("A8 list_tools 只列当前暴露的（total=37）", lt.get("total") == 37, lt.get("total"))

    print("B. 运行期装卸")
    r = call_sync(srv, "toolset", {"action": "load", "toolsets": "mem,rtos"})
    check("B1 load mem,rtos 装回 13 个、暴露数 50",
          r.get("ok") and len(r.get("loaded") or []) == 13 and r.get("exposed") == 50, r)
    ns2 = names(srv)
    check("B2 装回后立即可见（read_struct / rtos_tasks）",
          "read_struct" in ns2 and "rtos_tasks" in ns2, "")
    lt2 = call_sync(srv, "list_tools", {"keyword": "rtos"})
    got3 = set(t["tool"] for t in (lt2.get("tools") or []))
    check("B3 list_tools 立即可按新工具过滤（三个 rtos 工具都命中，面仍是 50）",
          lt2.get("total") == 50
          and {"rtos_info", "rtos_tasks", "rtos_objects"} <= got3, sorted(got3))

    r2 = call_sync(srv, "toolset", {"action": "load", "toolsets": "mem"})
    check("B4 重复装载幂等（loaded 空 / already_loaded 10 个）",
          r2.get("ok") and not (r2.get("loaded") or []) and len(r2.get("already_loaded") or []) == 10, r2)

    r3 = call_sync(srv, "toolset", {"action": "unload", "toolsets": "mem,rtos"})
    check("B5 unload 还原到 37", r3.get("ok") and r3.get("exposed") == 37
          and len(r3.get("unloaded") or []) == 13, r3)

    r4 = call_sync(srv, "toolset", {"action": "load", "toolsets": "all"})
    check("B6 toolsets=all 一次全装到 174", r4.get("ok") and r4.get("exposed") == 174, r4)
    srv_all = create_server(port=PORT_B, toolsets="all")
    check("B7 装卸若干轮后，工具顺序仍与全量面完全一致（不把工具甩到队尾）",
          order(srv) == order(srv_all), "本地 %d / 全量 %d" % (len(order(srv)), len(order(srv_all))))

    r5 = call_sync(srv, "toolset", {"action": "unload", "toolsets": "all"})
    check("B8 全收后只剩 4 个常驻入口",
          r5.get("ok") and r5.get("exposed") == 4 and set(names(srv)) == STAY, names(srv))
    check("B9 只剩常驻时 status 仍可用（它自己就是常驻）",
          call_sync(srv, "toolset", {"action": "status"}).get("exposed") == 4, "")
    check("B10 只剩常驻时 list_tools 仍可问出工具面",
          call_sync(srv, "list_tools", {}).get("total") == 4, "")
    r6 = call_sync(srv, "toolset", {"action": "unload", "toolsets": "core"})
    check("B11 卸载常驻组（core）不会把常驻入口一起收走",
          r6.get("ok") and set(names(srv)) == STAY, names(srv))
    call_sync(srv, "toolset", {"action": "load", "toolsets": "core"})
    check("B12 装回 core 后回到 37", len(names(srv)) == 37, len(names(srv)))
    return srv, srv_all

# ======================================================================
# C. 显式配置（子进程：环境变量在 create_server 时读取）
# ======================================================================
CODE = ("import asyncio;from mdkdebug import server as s;"
        "srv=s.create_server(port=%d);"
        "print(len(asyncio.run(srv.list_tools())))" % PORT_SUB)
CODE_ARG = ("import asyncio;from mdkdebug import server as s;"
            "srv=s.create_server(port=%d, toolsets='serial');"
            "print(len(asyncio.run(srv.list_tools())))" % PORT_SUB)

CODE_SRC = ("import asyncio;from mdkdebug import server as s;"
            "srv=s.create_server(port=%d, toolsets='serial');"
            "print('SRC', s._toolbox.status(srv).get('source'))" % PORT_SUB)

def _run(code, env):
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180)
    return out.stdout.strip(), (out.stdout + out.stderr)

def group_c():
    print("C. 显式配置")
    base = {k: v for k, v in os.environ.items() if k != "MDKDEBUG_TOOLSETS"}
    for spec, want, label in (("all", "174", "MDKDEBUG_TOOLSETS=all 仍是全开"),
                              ("serial", "18", "=serial 只留 14 串口 + 4 常驻"),
                              ("core,mem", "47", "=core,mem 组合生效"),
                              ("bogus", "174", "=bogus 组名认不出 → 不裁剪（宁可少裁不错杀）")):
        got, _ = _run(CODE, dict(base, MDKDEBUG_TOOLSETS=spec))
        check("C1 %s（期望 %s）" % (label, want), got.endswith(want), got)
    got, allout = _run(CODE, base)
    check("C2 不设环境变量 → 默认精简 37", got.endswith("37"), got)
    got, allout = _run(CODE, dict(base, MDKDEBUG_TOOLSETS="bogus"))
    check("C3 组名认不出时有告警（不静默）", "未知组名" in allout, allout[-300:])
    got, _ = _run(CODE_ARG, dict(base, MDKDEBUG_TOOLSETS="all"))
    check("C4 create_server(toolsets=) 参数优先于环境变量（all + serial → 18）",
          got.endswith("18"), got)
    got, _ = _run(CODE_SRC, dict(base, MDKDEBUG_TOOLSETS="all"))
    check("C5 显式参数时来源如实报 param（不误报 default）", "SRC param" in got, got)

# ======================================================================
# D. 分组表完备性
# ======================================================================
def group_d(srv_all):
    print("D. 分组表完备性")
    full = set(order(srv_all))
    seen, dup = set(), []
    for grp, members in TB.TOOLSETS.items():
        for m in members:
            if m in seen:
                dup.append("%s@%s" % (m, grp))
            seen.add(m)
    check("D1 每个工具最多归属一个组（无重复）", not dup, dup)
    check("D2 分组表里没有不存在的工具（无幽灵）", not (seen - full), sorted(seen - full))
    check("D3 未归类工具恰好是四个常驻入口",
          set(TB.ALWAYS) == (full - seen) and 4 == len(TB.ALWAYS), sorted(full - seen))
    check("D4 常驻表与分组表不重叠（常驻不靠组来保）", not (TB.ALWAYS & seen), sorted(TB.ALWAYS & seen))
    check("D5 11 个组都有用途说明", len(TB.GROUP_NOTES) == len(TB.TOOLSETS), len(TB.GROUP_NOTES))
    check("D6 默认组只有 core，且 core 在分组表里",
          list(TB.DEFAULT_GROUPS) == ["core"] and "core" in TB.TOOLSETS, TB.DEFAULT_GROUPS)
    check("D7 toolset 被 annotate 归为会改状态的工具（不给假的只读感）",
          "toolset" in AN.MUTATING and "toolset" not in AN.READONLY
          and "toolset" not in AN.DESTRUCTIVE, "")
    bad = AN.check_surface(full)
    check("D8 annotate.check_surface 在 174 个工具上无问题", not bad, bad)

# ======================================================================
# E. 失败归类
# ======================================================================
def group_e(srv):
    print("E. 失败归类")
    call_sync(srv, "toolset", {"action": "load", "toolsets": "all"})
    p = call_sync(srv, "toolset", {"action": "load", "toolsets": "nope"})
    check("E1 未知组 → error_code=toolset-unknown-group",
          p.get("error_code") == "toolset-unknown-group", p.get("error_code"))
    check("E2 未知组的下一步指向 toolset(status) 而不是 keil_health",
          any("status" in a for a in (p.get("next_actions") or []))
          and not any("keil_health" in a for a in (p.get("next_actions") or [])),
          p.get("next_actions"))
    q = call_sync(srv, "toolset", {"action": "bogus"})
    check("E3 坏 action → error_code=toolset-bad-action",
          q.get("error_code") == "toolset-bad-action", q.get("error_code"))
    check("E4 三个 toolset 码都登记在 ERROR_CODES 里",
          all(k in ERR.ERROR_CODES for k in
              ("toolset-unknown-group", "toolset-not-ready", "toolset-bad-action")), "")
    check("E5 结构化 reason 优先于文本猜（helper 直接透传）",
          ERR._classify_structured({"reason": "toolset-unknown-group"}) == "toolset-unknown-group", "")
    e = ERR.normalize("toolset", {"ok": False, "reason": "toolset-not-ready"})
    check("E6 toolset-not-ready 的下一步提醒「能力一个不少」（不制造恐慌）",
          any("一个不少" in a for a in (e.get("next_actions") or [])), e.get("next_actions"))

# ======================================================================
def main():
    srv, srv_all = group_ab()
    group_c()
    group_d(srv_all)
    group_e(srv)
    print("\n==== 批次42 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
