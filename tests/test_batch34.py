# -*- coding: utf-8 -*-
"""批次34 mock 测试：跨会话状态 state.json + 高输出工具 compact/max_lines/full。

来源：批次34 计划（state.json 跨会话状态 / companion 技能 / 高输出三件套）。
真机验证见 _rt_b34.py（走 UVSOCK@4823），本文件全部离线跑。

  A/B 会话状态：路径解析 / 原子写与备份 / 损坏文件不猜 / diff 语义
  C   session_state 工具：show/save/load/apply/clear/未知 action/路径覆盖
  D   输出控制纯逻辑：默认不变 / compact 规则 / max_lines / full / env 默认
  E   服务面：工具总数 99、schema 注入、直调与 batch 内生效、未知参数仍被拒、工具集
  F   文档与 companion 技能

运行：python -m tests.test_batch34
"""
import asyncio
import io
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMPROOT = tempfile.mkdtemp(prefix="mdkdebug_b34_")
STATE_FILE = os.path.join(TMPROOT, "state.json")
os.environ["MDKDEBUG_STATE_FILE"] = STATE_FILE
os.environ.pop("MDKDEBUG_COMPACT", None)
os.environ.pop("MDKDEBUG_MAX_LINES", None)

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import session as _session  # noqa: E402
from mdkdebug import outctl as _outctl  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14908
REAL_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvprojx")
REAL_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                        "mdk_test", "mdk_test.axf")
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or c.text for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:400], "_err": getattr(res, "is_error", None)}

# ----------------------------------------------------------------------
# A/B. 会话状态（纯逻辑层）
# ----------------------------------------------------------------------
def group_ab_session():
    print("A/B. 会话状态存储层")

    # 路径解析
    saved_env = os.environ.pop("MDKDEBUG_STATE_FILE", None)
    try:
        p = _session.state_path()
        check("A1 默认路径为 ~/.mdkdebug/state.json",
              p.replace("\\", "/").endswith("/.mdkdebug/state.json"), p)
        check("A2 显式 path 优先于环境变量",
              _session.state_path("D:/x/y.json").replace("\\", "/") == "D:/x/y.json",
              _session.state_path("D:/x/y.json"))
    finally:
        if saved_env:
            os.environ["MDKDEBUG_STATE_FILE"] = saved_env
    check("A3 环境变量 MDKDEBUG_STATE_FILE 生效",
          _session.state_path() == os.path.abspath(STATE_FILE), _session.state_path())

    # 首次 save：原子写、无 .tmp 残留
    ctx1 = {"project": {"path": "P1", "exists": True}, "symbol": {"path": "A1"},
            "breakpoints": [{"id": 1, "expr": "main"}]}
    r1 = _session.save(ctx1, STATE_FILE)
    check("A4 save 成功且返回 schema/字节数",
          r1.get("ok") and r1.get("schema") == 1 and (r1.get("bytes") or 0) > 0, r1)
    check("A5 原子写：不留 .tmp 残留", not os.path.isfile(STATE_FILE + ".tmp"), None)
    check("A6 首次 save 不产生 .bak（没有旧文件可备份）",
          not os.path.isfile(STATE_FILE + ".bak"), None)

    # 二次 save：旧内容进 .bak
    ctx2 = {"project": {"path": "P2", "exists": True}, "symbol": {"path": "A2"},
            "breakpoints": []}
    _session.save(ctx2, STATE_FILE)
    bak = STATE_FILE + ".bak"
    old = json.loads(io.open(bak, "r", encoding="utf-8").read())
    check("A7 二次 save 把上一版备份为 .bak（内容确实是上一版）",
          old.get("context", {}).get("project", {}).get("path") == "P1", old.get("context"))

    # load
    got = _session.load(STATE_FILE)
    check("A8 load 读回 context 与写入一致",
          got.get("ok") and got["context"]["project"]["path"] == "P2", got)

    # 损坏 / 结构不符 / schema 不符
    bad = os.path.join(TMPROOT, "bad.json")
    io.open(bad, "w", encoding="utf-8").write("{not json")
    rb = _session.load(bad)
    check("A9 文件损坏时明确报错（不静默当「没有状态」）",
          (not rb.get("ok")) and rb.get("exists") and "解析失败" in (rb.get("error") or ""), rb)

    other = os.path.join(TMPROOT, "other.json")
    io.open(other, "w", encoding="utf-8").write(json.dumps({"hello": 1}))
    ro = _session.load(other)
    check("A10 结构不是本工具格式时报错并列明缺 context，不猜内容",
          (not ro.get("ok")) and "context" in (ro.get("error") or ""), ro)

    old_schema = os.path.join(TMPROOT, "oldschema.json")
    io.open(old_schema, "w", encoding="utf-8").write(json.dumps(
        {"schema": 0, "saved_at": "t", "context": {"a": 1}}))
    rs = _session.load(old_schema)
    check("A11 schema 不同时给出 warning（不假装兼容）",
          rs.get("ok") and "schema" in (rs.get("warning") or ""), rs)

    # 缺失文件
    rm = _session.load(os.path.join(TMPROOT, "nope.json"))
    check("A12 文件不存在：exists=false 且错误说明可读",
          (not rm.get("ok")) and rm.get("exists") is False and rm.get("error"), rm)

    # clear
    rc = _session.clear(os.path.join(TMPROOT, "nope.json"))
    check("A13 clear 不存在的文件：ok=true 且 removed=false（说明无需删除）",
          rc.get("ok") and rc.get("removed") is False, rc)
    rc2 = _session.clear(STATE_FILE)
    check("A14 clear 已存在的文件：removed=true 且文件消失",
          rc2.get("ok") and rc2.get("removed") and
          not os.path.isfile(STATE_FILE), rc2)

    # diff 语义
    d = _session.diff({"a": 1, "b": 2, "gone": 3}, {"a": 1, "b": 9, "new": 4})
    check("A15 diff 正确区分 same/changed/only_in_file/only_in_current",
          d["same"] == {"a": 1} and d["changed"]["b"] == {"saved": 2, "current": 9}
          and d["only_in_file"] == {"gone": 3} and d["only_in_current"] == {"new": 4}, d)
    d2 = _session.diff({"a": 1}, {"a": 1})
    check("A16 diff 完全一致时 identical=true", d2["identical"] is True, d2)

# ----------------------------------------------------------------------
# D. 输出控制（纯逻辑层）
# ----------------------------------------------------------------------
def group_d_outctl():
    print("D. 输出控制纯逻辑")

    payload = {
        "ok": True, "count": 3, "note": None, "extra": "",
        "tools": [
            {"tool": "a", "usage": "u" * 300 + "a", "aliases": {}, "category": "core",
             "value": "V" * 300 + "a", "req": ["x"]},
            {"tool": "b", "usage": "u" * 300 + "b", "aliases": {}, "category": "core",
             "value": "V" * 300 + "b", "req": ["y"]},
            {"tool": "c", "usage": "u" * 300 + "c", "aliases": {}, "category": "core",
             "value": "V" * 300 + "c", "req": ["z"]},
        ],
        "next_actions": ["先做 A", "再做 B"],
    }
    _, meta0 = _outctl.apply("list_tools", payload)
    check("D1 不传控制参数时 meta=None（默认行为完全不变）", meta0 is None, meta0)

    comp, meta1 = _outctl.apply("list_tools", payload, compact=True)
    check("D2 compact 去掉空值字段并计数上报",
          (meta1 or {}).get("empty_fields_removed", 0) >= 1 and "note" not in comp, meta1)
    check("D3 compact 截断说明性长文本（usage）并列出原文长度",
          comp["tools"][0]["usage"].endswith("…") and
          (meta1 or {}).get("text_truncated"), (comp["tools"][0]["usage"], meta1))
    check("D3b compact 把列表元素里取值完全相同的非空字段提到 output.shared（元素内不再重复）",
          "category" in (meta1 or {}).get("shared", {}).get("tools", {}) and
          "category" not in comp["tools"][0] and len(comp["tools"]) == 3,
          (meta1 or {}).get("shared"))
    check("D3c compact 先删空值字段（空 dict），再提公共字段",
          "aliases" not in comp["tools"][0], comp["tools"][0])
    check("D4 compact 绝不截断内容字段（value 原样 301 字符）",
          comp["tools"][0]["value"] == "V" * 300 + "a", len(comp["tools"][0]["value"]))
    check("D5 compact 保留 next_actions（结构性字段不动）",
          comp.get("next_actions") == ["先做 A", "再做 B"], comp.get("next_actions"))

    trim, meta2 = _outctl.apply("list_tools", payload, max_lines=2)
    check("D6 max_lines 截断列表并如实上报 total/returned/dropped",
          len(trim["tools"]) == 2 and meta2["dropped"] == 1 and
          meta2["trimmed"][0]["total"] == 3, meta2)
    check("D7 截断时的 hint 说明「count/total 仍是全量数字」+ 如何取全量",
          "全量" in meta2.get("hint", "") and "full=true" in meta2.get("hint", ""),
          meta2.get("hint"))
    check("D8 未截断时 truncated=false（不虚报）",
          _outctl.apply("list_tools", payload, max_lines=10)[1]["truncated"] is False, None)

    full, meta3 = _outctl.apply("list_tools", payload, compact=True, max_lines=1, full=True)
    check("D9 full=true 覆盖 compact/max_lines（返回全量且不加 output 字段）",
          meta3 is None and len(full["tools"]) == 3 and "output" not in full, meta3)

    # 环境变量默认
    os.environ["MDKDEBUG_COMPACT"] = "1"
    os.environ["MDKDEBUG_MAX_LINES"] = "2"
    try:
        _, meta4 = _outctl.apply("list_tools", payload)
        check("D10 环境变量 MDKDEBUG_COMPACT/MDKDEBUG_MAX_LINES 作为全局默认生效",
              meta4 is not None and "compact" in meta4["mode"] and
              len(_outctl.apply("list_tools", payload)[0]["tools"]) == 2, meta4)
        _, meta5 = _outctl.apply("list_tools", payload, compact=False, max_lines=0,
                                 full=True)
        check("D11 显式 full=true 仍能压过环境变量默认", meta5 is None, meta5)
    finally:
        os.environ.pop("MDKDEBUG_COMPACT", None)
        os.environ.pop("MDKDEBUG_MAX_LINES", None)

    check("D12 resolve：非整数 max_lines 被忽略而非崩溃",
          _outctl.resolve(max_lines="abc")[1] == 0, _outctl.resolve(max_lines="abc"))
    check("D13 apply 对非 dict（字符串结果）原样返回",
          _outctl.apply("x", "raw", compact=True) == ("raw", None), None)
    check("D14 split_args 只摘三个控制参数，其余不动",
          _outctl.split_args({"a": 1, "compact": True, "full": False}) ==
          ({"a": 1}, {"compact": True, "full": False}), None)
    check("D15 受控工具表含 list_tools/snapshot/batch/serial_read，不含写类工具风险项",
          {"list_tools", "snapshot", "batch", "serial_read"} <= _outctl.HIGH_OUTPUT, None)

# ----------------------------------------------------------------------
# C/E. 服务面（mock 调试器 + 别名层）
# ----------------------------------------------------------------------
async def group_c_session(server):
    print("C. session_state 工具")

    r = await call(server, "session_state", {"action": "save"})
    check("C1 save 返回路径/备份位/落盘字段清单",
          r.get("ok") and r.get("path") and "symbol" in (r.get("saved_keys") or []), r)
    check("C2 save 后文件真的在（且路径与 state_path 一致）",
          os.path.isfile(_session.state_path()), _session.state_path())

    r = await call(server, "session_state", {"action": "show"})
    check("C3 show 同时给出磁盘态与当前上下文，diff 一致",
          r.get("ok") and r.get("state_file", {}).get("exists") and
          (r.get("diff") or {}).get("identical") is True, r)

    r = await call(server, "session_state", {"action": "load"})
    plan = r.get("apply_plan") or []
    check("C4 load 默认只读不应用，apply_plan 只给「会做什么」的预告",
          r.get("ok") and plan and all(a.get("action") != "applied" for a in plan) and
          "默认只读不应用" in (r.get("note") or ""), r)

    r = await call(server, "session_state", {"action": "load", "apply": True})
    plan = r.get("apply_plan") or []
    sym_act = [a for a in plan if a.get("item") == "symbol_file"]
    check("C5 load+apply：符号文件项要么 applied/already_current，要么明确说明为何不做",
          sym_act and sym_act[0].get("action") in
          ("applied", "already_current", "skipped", "failed", "pending"),
          plan)

    r = await call(server, "session_state", {"action": "banana"})
    check("C6 未知 action 被拒并列出可用值（不猜默认行为）",
          (not r.get("ok")) and "show" in (r.get("error") or ""), r)

    r = await call(server, "session_state", {"action": "clear"})
    check("C7 clear 未确认时拒绝执行", (not r.get("ok")) and "confirm" in (r.get("error") or ""), r)
    r = await call(server, "session_state", {"action": "clear", "confirm": True})
    check("C8 clear+confirm 真的删掉文件",
          r.get("ok") and r.get("removed") and not os.path.isfile(_session.state_path()), r)

    # 状态里符号文件已不存在 -> skipped，不猜替代
    ghost = os.path.join(TMPROOT, "ghost.json")
    _session.save({"symbol": {"path": os.path.join(TMPROOT, "not_here.axf"),
                              "source_type": "axf", "exists": False}},
                  ghost)
    r = await call(server, "session_state", {"action": "load", "path": ghost, "apply": True})
    sym = [a for a in (r.get("apply_plan") or []) if a.get("item") == "symbol_file"]
    check("C9 状态里符号文件不存在时不猜替代品，明确 skipped + 引导 list_symbol_projects",
          sym and sym[0].get("action") == "skipped" and "list_symbol_projects" in (sym[0].get("reason") or ""),
          sym)
    check("C10 path 参数可指向任意状态文件（多工程各存一份）",
          r.get("path") == os.path.abspath(ghost), r.get("path"))

    r = await call(server, "session_state", {"action": "load", "path": os.path.join(TMPROOT, "none.json")})
    check("C11 文件缺失时 load 报错并给出重建建议（不猜内容）",
          (not r.get("ok")) and "save" in (r.get("hint") or ""), r)

async def group_e_surface(server):
    print("E. 服务面：工具数 / schema 注入 / 直调与 batch / 工具集")

    tools = await server.list_tools()
    names = sorted(t.name for t in tools)
    check("E1 工具总数 161（批次36 再 +46，批次40 +3，批次42 +1）", len(names) == 161, len(names))
    check("E2 session_state 已注册", "session_state" in names, names)
    by = {t.name: t for t in tools}
    props = (by["list_tools"].input_schema or {}).get("properties") or {}
    check("E3 高输出工具的 schema 已注入 compact/max_lines/full",
          {"compact", "max_lines", "full"} <= set(props), sorted(props))
    check("E4 工具描述含【输出控制】说明（AI 冷启动可见）",
          "【输出控制】" in (by["list_tools"].description or ""), None)
    check("E5 非受控工具不注入（write_mem 保持原样）",
          not ({"compact"} <= set(((by["write_mem"].input_schema or {}).get("properties") or {}))),
          None)

    full = await call(server, "list_tools", {})
    check("E6 默认调用不带 output 字段（行为不变）", "output" not in full, None)

    t5 = await call(server, "list_tools", {"max_lines": 5})
    check("E7 直调 max_lines：列表 5 条而 count 仍是全量（并说明计数字段口径）",
          len(t5.get("tools") or []) == 5 and t5.get("count") == 161 and
          (t5.get("output") or {}).get("truncated") is True and
          "全量" in (t5.get("output") or {}).get("hint", ""), t5.get("output"))

    c = await call(server, "list_tools", {"compact": True, "max_lines": 5})
    full_len = len(json.dumps(full, ensure_ascii=False))
    comp_len = len(json.dumps(c, ensure_ascii=False))
    check("E8 compact+max_lines 明显减小体积（且如实上报 mode/trimmed）",
          comp_len < full_len * 0.35 and (c.get("output") or {}).get("mode") == "compact+max_lines",
          (comp_len, full_len))

    big = await call(server, "list_tools", {"compact": True, "max_lines": 5, "full": True})
    check("E9 full=true 直调取回全量 161 条且无 output",
          big.get("count") == 161 and len(big.get("tools") or []) == 161 and "output" not in big,
          big.get("count"))

    bad = await call(server, "list_tools", {"max_line": 5})
    check("E10 打错参数名仍被拒（注入的别名不掩盖严格校验）",
          ("_exc" in bad) or (not bad.get("ok")) or bad.get("error_code"), bad)

    rr = await call(server, "batch", {"commands": [
        {"tool": "list_tools", "args": {"max_lines": 3}}]})
    sub = (rr.get("results") or [{}])[0]
    check("E11 batch 内子命令支持输出控制（与单工具直调等价）",
          len(sub.get("tools") or []) == 3 and (sub.get("output") or {}).get("truncated") is True,
          sub.get("output"))

    cap = await call(server, "capabilities", {})
    check("E12 capabilities 暴露 session 模块（状态文件路径/是否已保存）",
          (cap.get("modules") or {}).get("session", {}).get("available") is True and
          (cap.get("modules") or {}).get("session", {}).get("state_file"), cap.get("modules", {}).get("session"))
    check("E13 capabilities 暴露 output_control 现状（受控工具数/环境默认）",
          (cap.get("modules") or {}).get("output_control", {}).get("controlled_tools", 0) >= 20,
          cap.get("modules", {}).get("output_control"))

    # 工具集裁剪：session_state 归 core
    env = dict(os.environ, MDKDEBUG_TOOLSETS="core")
    code = ("import asyncio;from mdkdebug import server as s;"
            "srv=s.create_server(port=14998);"
            "ns=[t.name for t in asyncio.run(srv.list_tools())];"
            "print('session_state' in ns, 'serial_read' in ns, 'list_tools' in ns)")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180)
    check("E14 裁剪到 core 时 session_state/list_tools 保留、serial_read 移除",
          out.stdout.strip().endswith("True False True"),
          out.stdout[-200:] + out.stderr[-200:])

# ----------------------------------------------------------------------
# F. 文档与 companion 技能
# ----------------------------------------------------------------------
def group_f_docs():
    print("F. 文档与 companion 技能")
    sk = os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md")
    check("F1 companion 技能 skills/mdkdebug/SKILL.md 存在", os.path.isfile(sk), sk)
    if not os.path.isfile(sk):
        return
    txt = io.open(sk, "r", encoding="utf-8").read()
    check("F2 技能带 name/description frontmatter（能被技能系统识别）",
          txt.startswith("---") and "name: mdkdebug" in txt and "description:" in txt, None)
    for tool in ("capabilities", "list_tools", "session_state", "batch_debug_script",
                 "mdk_guide", "serial_expect", "svd_decode", "keil_health"):
        check("F3 技能提到关键工具 %s" % tool, tool in txt, None)
    check("F4 技能写明默认行为不变与裁剪会如实上报",
          "truncated" in txt and "full=true" in txt, None)

# ----------------------------------------------------------------------
async def main():
    group_ab_session()
    group_d_outctl()
    group_f_docs()

    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=(REAL_AXF if os.path.isfile(REAL_AXF) else None),
                           default_project=REAL_PROJ)
    try:
        await group_c_session(server)
        await group_e_surface(server)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次34 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    print("临时工作目录（保留供排查）:", TMPROOT)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
