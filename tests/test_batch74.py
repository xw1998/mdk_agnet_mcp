# -*- coding: utf-8 -*-
"""批次74 mock 测试：工具面瘦身三刀（结构 / 默认档 / 指针）。

背景：AI 反馈「工具规模太大，不利于上下文与注意力机制」。批次56 已做描述分层
（默认 full），本批把 tools/list 的线上载荷再砍三刀：

  * **刀一 结构瘦身**（`mdkdebug/surface.py`）：只改 wire 副本——去掉恒定样板的
    `outputSchema`、inputSchema 里递归的纯注释 `title`、annotations 里等于规范
    默认值/只读工具上无语义的字段。活的注册对象与调用路径一个字不动
    （`fn_metadata.output_schema` 决定 structuredContent 包装，改它=改返回形态）。
    逃生口 `MDKDEBUG_SURFACE=off` 关掉即回到逐字节历史行为。
  * **刀二 默认档 full→lean**（`thin.DEFAULT_MODE` / `toolbox.desc_default_for`）：
    常驻层保住段首+结构化尾块，只把参考手册式背景挪走并留取回指针；
    `MDKDEBUG_DESC=full` 可逐字节还原。**这是对批次56 口径的显式反转。**
  * **刀三 指针瘦身**：`【完整说明】`指针从 ~82 字符压到 ~69 字符。

  A 刀一·wire：outputSchema/title 归零、活对象未动、调用结果不变
  B 刀一·A/B 对照：MDKDEBUG_SURFACE=off 时逐字段保留、瘦身前后只差预期键
  C annotations 裁剪：规范默认值语义等价、只读工具去无语义字段、陌生字段保留
  D 刀二·默认档：默认 lean、nano 仍 min、full 可逐字节还原
  E 刀三·指针：取回指针含工具名与 mdk_guide 入口
  F 体积：core 线上载荷显著小于 off 基线（阈值只防回归，不锁死数字）

运行：python -m tests.test_batch74
"""
import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import server as SV           # noqa: E402
from mdkdebug import surface as SF          # noqa: E402
from mdkdebug import thin as TH             # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402

PORT = 15574

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def fresh(**kw):
    """建一个 server；desc=/surface= 显式指定（环境变量建完即还原）。"""
    desc = kw.pop("desc", None)
    surface = kw.pop("surface", None)
    saved_d = os.environ.pop("MDKDEBUG_DESC", None)
    saved_s = os.environ.pop("MDKDEBUG_SURFACE", None)
    try:
        if desc:
            os.environ["MDKDEBUG_DESC"] = desc
        if surface is not None:
            os.environ["MDKDEBUG_SURFACE"] = surface
        return SV.create_server(port=PORT, **kw)
    finally:
        os.environ.pop("MDKDEBUG_DESC", None)
        os.environ.pop("MDKDEBUG_SURFACE", None)
        if saved_d is not None:
            os.environ["MDKDEBUG_DESC"] = saved_d
        if saved_s is not None:
            os.environ["MDKDEBUG_SURFACE"] = saved_s

def wire(srv):
    return asyncio.run(srv.list_tools())

def wire_json(tools):
    return [t.model_dump(by_alias=True, mode="json", exclude_none=True)
            for t in tools]

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

# ----------------------------------------------------------------------
def section_a():
    print("A. 刀一·wire 结构瘦身（默认开）")
    srv = fresh()
    ws = wire(srv)
    check("A1 wire 上没有 outputSchema（44 个全去）",
          len(ws) == 44 and all(getattr(t, "output_schema", None) is None
                                for t in ws), len(ws))
    check("A2 wire 上 inputSchema 里 title 归零",
          all(SF.count_titles(getattr(t, "input_schema", None) or {}) == 0
              for t in ws))

    live = srv._tool_manager._tools
    have_out = [nm for nm, t in live.items()
                if getattr(t, "output_schema", None) is not None]
    check("A3 活注册对象的 output_schema 未被动过（调用路径不改形态）",
          len(have_out) == 44, len(have_out))
    live_titles = sum(SF.count_titles(t.parameters or {})
                      for t in live.values())
    check("A4 活注册对象的 inputSchema（含 title）未被动过",
          live_titles > 0, live_titles)

    st = call_sync(srv, "toolset", {"action": "status"})
    check("A5 瘦身后调用照常返回（信封 ok / 结构化返回仍在）",
          st.get("status") == "ok" and st.get("exposed") == 44, st)
    ws2 = wire(srv)
    check("A6 wire 副本每次新造（改它不累积污染活对象）",
          all(getattr(t, "output_schema", None) is None for t in ws2))

def section_b():
    print("B. 刀一·A/B 对照（MDKDEBUG_SURFACE=off = 历史行为）")
    check("B1 默认 enabled() 为真、off 词表关闭",
          SF.enabled() and not os.environ.get(SF.ENV_SWITCH))

    saved = os.environ.pop("MDKDEBUG_SURFACE", None)
    srv = fresh()
    os.environ[SF.ENV_SWITCH] = "off"
    try:
        ws_off = wire_json(wire(srv))
    finally:
        os.environ.pop(SF.ENV_SWITCH, None)
        if saved is not None:
            os.environ[SF.ENV_SWITCH] = saved
    # off：字段齐全
    check("B2 off 时 outputSchema 保留（44 个全在）",
          len(ws_off) == 44
          and all(w.get("outputSchema") for w in ws_off),
          sum(1 for w in ws_off if w.get("outputSchema")))
    check("B3 off 时 inputSchema 里 title 保留（>0）",
          sum(SF.count_titles(w.get("inputSchema") or {}) for w in ws_off) > 0)

    # 同一 server，on/off 两态逐字段对比：只允许差在预期键上
    os.environ[SF.ENV_SWITCH] = "off"
    try:
        ws_a = {w["name"]: w for w in wire_json(wire(srv))}
    finally:
        os.environ.pop(SF.ENV_SWITCH, None)
        if saved is not None:
            os.environ[SF.ENV_SWITCH] = saved
    ws_b = {w["name"]: w for w in wire_json(wire(srv))}   # 瘦身开
    check("B4 两态工具名单一致", sorted(ws_a) == sorted(ws_b),
          (len(ws_a), len(ws_b)))
    same_desc = all(ws_a[n]["description"] == ws_b[n]["description"]
                    for n in ws_a)
    check("B5 两态 description 逐字节一致（刀一只动结构键）", same_desc)
    only_expected = True
    bad = []
    for n in ws_a:
        ka, kb = set(ws_a[n]), set(ws_b[n])
        if ka - kb <= {"outputSchema"} and kb - ka <= set():
            # inputSchema 差异只允许少 title
            sa = dict(ws_a[n].get("inputSchema") or {})
            sb = dict(ws_b[n].get("inputSchema") or {})
            if json.dumps(sa, sort_keys=True, ensure_ascii=False) != \
               json.dumps(sb, sort_keys=True, ensure_ascii=False):
                # 重新给 sb 塞回 title 应与 sa 一致 —— title 是纯注释
                # 这里只校验：两者去掉 title 后一致
                def strip(x):
                    def rec(n_):
                        if isinstance(n_, dict):
                            return {k: rec(v) for k, v in n_.items()
                                    if k != "title"}
                        if isinstance(n_, list):
                            return [rec(v) for v in n_]
                        return n_
                    return rec(x)
                if strip(sa) != strip(sb):
                    only_expected = False
                    bad.append(n)
        else:
            only_expected = False
            bad.append((n, ka - kb, kb - ka))
    check("B6 两态只差 outputSchema 与 inputSchema.title（其余键逐字节同）",
          only_expected, bad[:3])

def section_c():
    print("C. annotations 规范语义裁剪")
    a = SF.slim_annotations({"readOnlyHint": False, "destructiveHint": True,
                             "idempotentHint": False, "openWorldHint": True})
    check("C1 全部等于规范默认值 → 全裁（语义不变，缺省由默认补齐）",
          a == {}, a)
    a = SF.slim_annotations({"readOnlyHint": True, "destructiveHint": True,
                             "idempotentHint": False})
    check("C2 只读工具上 destructive/idempotent 无语义 → 裁",
          a == {"readOnlyHint": True}, a)
    a = SF.slim_annotations({"readOnlyHint": False, "destructiveHint": False,
                             "idempotentHint": True})
    check("C3 非默认值保留（readOnlyHint=False 是规范默认值、可缺省）",
          a == {"destructiveHint": False, "idempotentHint": True}, a)
    a = SF.slim_annotations({"readOnlyHint": True, "futureHint": 1})
    check("C4 陌生字段原样保留（不越权丢信息）",
          a == {"readOnlyHint": True, "futureHint": 1}, a)

def section_d():
    print("D. 刀二·默认档 lean")
    check("D1 thin.DEFAULT_MODE = lean、toolbox 默认档 = lean",
          TH.DEFAULT_MODE == "lean" and TB.desc_default_for(None) == "lean"
          and TB.desc_default_for("core") == "lean"
          and TB.desc_default_for("all") == "lean",
          (TH.DEFAULT_MODE, TB.desc_default_for(None)))
    check("D2 纯 nano 仍走 min 档",
          TB.desc_default_for("nano") == "min"
          and TB.desc_default_for("nano,core") == "lean",
          (TB.desc_default_for("nano"), TB.desc_default_for("nano,core")))

    srv = fresh()                                   # 默认档 lean
    d_rm = srv._tool_manager._tools["read_mem"].description or ""
    f_rm = TH.full_of("read_mem") or ""
    check("D3 默认面 read_mem 描述 ≠ 全文（lean 生效）",
          len(d_rm) < len(f_rm) and "【完整说明】" in d_rm,
          (len(d_rm), len(f_rm)))
    srv_full = fresh(desc="full")
    d_full = srv_full._tool_manager._tools["read_mem"].description or ""
    check("D4 MDKDEBUG_DESC=full 逐字节还原全文（逃生口）",
          d_full == f_rm, (len(d_full), len(f_rm)))

def section_e():
    print("E. 刀三·指针瘦身")
    p = TH._pointer("read_mem")
    check("E1 指针含工具名与取回入口",
          "read_mem" in p and "mdk_guide" in p, p)
    check("E2 指针压到 ~69 字符（<78，刀三生效）", len(p) < 78, len(p))

def section_f():
    print("F. 体积")
    saved = os.environ.pop("MDKDEBUG_SURFACE", None)
    try:
        srv = fresh()
        on = len(json.dumps(wire_json(wire(srv)), ensure_ascii=False))
        os.environ[SF.ENV_SWITCH] = "off"
        off = len(json.dumps(wire_json(wire(srv)), ensure_ascii=False))
    finally:
        os.environ.pop(SF.ENV_SWITCH, None)
        if saved is not None:
            os.environ[SF.ENV_SWITCH] = saved
    check("F1 core 线上载荷：瘦身显著小于 off 基线（<90%）",
          on < off * 0.9, (on, off))
    check("F2 core 线上载荷阈值（<70k，防回归）", on < 70000, on)

# ----------------------------------------------------------------------
def main():
    for fn in (section_a, section_b, section_c, section_d,
               section_e, section_f):
        try:
            fn()
        except Exception as e:                       # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常: %r" % (fn.__name__, e))
    print("\n==== test_batch74: %d pass / %d fail ====" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAIL:", f)
        sys.exit(1)

if __name__ == "__main__":
    main()
