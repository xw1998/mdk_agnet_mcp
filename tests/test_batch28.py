# -*- coding: utf-8 -*-
"""批次28 mock 测试：batch 与单工具一致性 + 模态框正文/按钮可读可关（第 11 轮反馈）。

用户反馈原文：
    「发现一个真 bug：batch 绕过了参数别名归一化层。单工具直调 run_timeout(timeout_s=0.5)
     接受，同一参数放进 batch 报 'unexpected keyword argument'… 建议给 batch 加一条与单工具
     一致性的回归用例：同一组参数，直调与经 batch 必须得到相同结果。」
    「只给标题、不给正文这点仍未改…我用 Win32 EnumChildWindows 十行代码就取到了
     Static＝Create File -o '…' failed. 与 Button＝确定，建议把它补进
     modal_dialogs[].message / .buttons，再配一个 dismiss_dialog。」

  A batch 与单工具一致性（别名生效、单位换算、未知参数拒绝方式一致）
  B 模态框：正文/按钮解析、按按钮关闭、按钮匹配不到不擅自改点
  C 服务层：dismiss_dialog 工具与 keil_health 的正文输出

运行：python -m tests.test_batch28
"""
import os
import sys
import json
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug.server import create_server  # noqa: E402
from mdkdebug import winutil as wu  # noqa: E402

PORT = 14901
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:280]), flush=True)

async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or c.text for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:400]}

async def one(server, tool, args=None):
    """经 batch 调一个工具，返回那一条结果。"""
    r = await call(server, "batch", {"commands": [{"tool": tool, "args": args or {}}]})
    items = r.get("results") or [{}]
    return items[0]

# ------------------------------------------------------------------
async def group_a(server):
    print("A. batch 与单工具直调必须完全一致（本轮 bug 的回归用例）")
    direct = await call(server, "run_timeout", {"timeout_s": 0.05})
    check("A1 直调 run_timeout(timeout_s=0.05) 可用（基线）",
          "_exc" not in direct and direct.get("timeout_ms") == 50, direct)

    batched = await one(server, "run_timeout", {"timeout_s": 0.05})
    check("A2 batch 内同一参数也生效（不再 unexpected keyword）",
          "_exc" not in batched and "unexpected keyword" not in str(batched.get("error", "")),
          batched)
    check("A3 batch 与直调结果一致（ok / timeout_ms 相同）",
          batched.get("ok") == direct.get("ok")
          and batched.get("timeout_ms") == direct.get("timeout_ms"),
          {"direct": direct, "batch": batched})
    check("A4 batch 命中别名时回报 param_alias",
          any("timeout_s" in s for s in (batched.get("param_alias") or [])),
          batched.get("param_alias"))

    b2 = await one(server, "run_timeout", {"duration_ms": 20})
    check("A5 batch 内换族前缀 duration_ms 同样换算到 20ms",
          b2.get("timeout_ms") == 20, b2)
    b3 = await one(server, "run_timeout", {"wait_s": 0.1})
    check("A6 batch 内 wait_s 同样换算到 100ms", b3.get("timeout_ms") == 100, b3)

    d = await call(server, "run_timeout", {"timeout_ms": 30, "timeout_s": 5})
    bd = await one(server, "run_timeout", {"timeout_ms": 30, "timeout_s": 5})
    check("A7 主名与别名同时给出时主名优先（直调与 batch 一致，均取 30）",
          d.get("timeout_ms") == 30 and bd.get("timeout_ms") == 30, {"d": d, "b": bd})

    bad = await one(server, "run_timeout", {"timeouts_s": 5})
    check("A8 batch 内拼错的参数被显式拒绝（并列出可用参数）",
          "参数名不被接受" in str(bad.get("error", ""))
          and "timeout_ms" in str(bad.get("error", "")), bad)
    check("A9 batch 内未知参数的报错与直调同口径（不是 TypeError）",
          "unexpected keyword" not in str(bad.get("error", "")), bad)

    rm = await one(server, "read_mem", {"address": "0x20000000", "size": 16})
    check("A10 batch 内 name-list/地址别名（address/size）仍生效",
          rm.get("ok") is True and "data_hex" in rm, rm)
    wm = await one(server, "run_timeout", {"timeout": 0.05})
    check("A11 batch 内无后缀别名按主名单位解释（timeout=0.05 不×1000，被 clamp 到 1ms）",
          "_exc" not in wm and wm.get("timeout_ms") == 1, wm)

    nope = await one(server, "no_such_tool", {})
    check("A12 batch 内未知工具名仍被拒（回归）",
          "不是本服务已注册的工具名" in str(nope.get("error", "")), nope)
    nest = await one(server, "batch", {})
    check("A13 batch 内嵌套 batch 仍被拒（回归）",
          "不支持嵌套" in str(nest.get("error", "")), nest)

    # 真机 A9 暴露：无参数工具（get_status）收到多余参数时，以前会落到框架报
    # "unexpected keyword argument"；现在直接说清"不接受任何参数"。
    nod = await one(server, "get_status", {"timeout_ms": 1})
    nd = await call(server, "get_status", {"timeout_ms": 1})
    check("A14 无参数工具的多余参数被显式拒绝（batch 与直调同口径）",
          "参数名不被接受" in str(nod.get("error", ""))
          and "不接受任何参数" in str(nod.get("error", ""))
          and "参数名不被接受" in str(nd.get("_exc", "")), {"b": nod, "d": nd})

def group_b():
    print("B. 模态框：正文/按钮解析 + 点关")
    btns = [{"hwnd": 101, "text": "确定(&O)"}, {"hwnd": 102, "text": "取消"}]
    check("B1 _pick_button 精确匹配", (wu._pick_button(btns, "取消") or {}).get("hwnd") == 102)
    check("B2 _pick_button 部分匹配（确定 命中 确定(&O)）",
          (wu._pick_button(btns, "确定") or {}).get("hwnd") == 101)
    check("B3 _pick_button 匹配不到返回 None（不擅自改点别的）",
          wu._pick_button(btns, "重试") is None)
    check("B4 _pick_button 默认序优先确认语义（确定 优先于 取消）",
          (wu._pick_button(btns, "") or {}).get("text") == "确定(&O)")
    check("B5 无按钮时 _pick_button 返回 None", wu._pick_button([], "确定") is None)

    orig_children = wu._child_controls
    try:
        wu._child_controls = lambda hwnd: [
            {"hwnd": 1, "class": "Static", "text": "Create File -o 'C:/tmp/x.txt' failed."},
            {"hwnd": 2, "class": "Static", "text": ""},
            {"hwnd": 3, "class": "Button", "text": "确定"},
            {"hwnd": 4, "class": "Edit", "text": "ignored"},
        ]
        content = wu.dialog_content(777)
        check("B6 dialog_content 取到正文（Static → message）",
              content["message"].startswith("Create File -o"), content)
        check("B7 dialog_content 取到按钮（Button → buttons/button_texts）",
              content["button_texts"] == ["确定"], content)
    finally:
        wu._child_controls = orig_children

    orig_find, orig_click, orig_post = (wu.find_modal_dialogs, wu._click_control, wu._post_close)
    clicks, posts = [], []
    DLG = {"pid": 4321, "hwnd": 555, "title": "µVision",
           "message": "Create File -o 'D:/tmp/build.log' failed.",
           "buttons": [{"hwnd": 11, "text": "确定"}], "button_texts": ["确定"], "statics": []}
    state = {"open": False}
    try:
        def fake_find():
            return [DLG] if state["open"] else []
        wu.find_modal_dialogs = fake_find

        def fake_click(hwnd, timeout_ms=2000):
            """真按钮回调会销毁对话框；这里同样把窗口标记为已关，供 dismissal 判定。"""
            clicks.append(hwnd)
            state["open"] = False
            return True

        def fake_post(hwnd):
            posts.append(hwnd)
            state["open"] = False
            return True

        wu._click_control = fake_click
        wu._post_close = fake_post

        r0 = wu.dismiss_modal_dialog()
        check("B8 没有模态框时如实返回 no_dialog",
              r0.get("code") == "no_dialog" and r0.get("ok") is False, r0)

        state["open"] = True
        r = wu.dismiss_modal_dialog()
        check("B9 未指定 button 时自动点确认按钮并确认已消失",
              r.get("dismissed") is True and r.get("clicked") == "确定"
              and r.get("method") == "BM_CLICK", r)
        check("B10 对话框正文随结果一起回传（AI 不必再去界面看）",
              "Create File -o" in (r.get("dialog", {}).get("message") or ""), r)
        check("B11 点的是按钮句柄", clicks == [11], clicks)

        state["open"] = True
        clicks[:] = []
        rn = wu.dismiss_modal_dialog(button="重试")
        check("B12 指定 button 匹配不到 → button_not_found 且不点任何按钮",
              rn.get("code") == "button_not_found" and clicks == [], (rn, clicks))
        check("B13 button_not_found 时列出可用按钮",
              rn.get("dialog", {}).get("buttons") == ["确定"], rn)

        state["open"] = True
        clicks[:] = []
        rb = wu.dismiss_modal_dialog(button="确")
        check("B14 指定 button 命中时按指定按钮点击",
              rb.get("dismissed") is True and clicks == [11], (rb, clicks))

        DLG_NOBTN = dict(DLG, buttons=[], button_texts=[])
        state["open"] = True
        posts[:] = []
        def fake_find_nobtn():
            return [DLG_NOBTN] if state["open"] else []
        wu.find_modal_dialogs = fake_find_nobtn
        rc = wu.dismiss_modal_dialog()
        check("B15 没有可点按钮时退化为 WM_CLOSE",
              rc.get("method") == "WM_CLOSE" and posts == [555] and rc.get("dismissed") is True,
              (rc, posts))
        wu.find_modal_dialogs = fake_find
    finally:
        wu.find_modal_dialogs, wu._click_control, wu._post_close = orig_find, orig_click, orig_post

    orig_pids, orig_pl, orig_find2 = wu.uv4_pids, wu.port_listening, wu.find_modal_dialogs
    try:
        wu.uv4_pids = lambda: [4321]
        wu.port_listening = lambda *a, **k: True
        wu.find_modal_dialogs = lambda: [DLG]
        state["open"] = True
        h = wu.keil_health(with_dialogs=True)
        check("B16 keil_health(with_dialogs=True) 带出 modal_dialogs 与正文",
              h.get("modal_blocked_suspected") is True
              and "Create File -o" in (h["modal_dialogs"][0].get("message") or ""), h)
        check("B17 端口正常但有模态框时诊断话术点明症状",
              "模态" in h.get("diagnosis", ""), h.get("diagnosis"))
        h2 = wu.keil_health()
        check("B18 默认不带模态框探测（保持廉价路径不变）",
              "modal_dialogs" not in h2, list(h2.keys()))
    finally:
        wu.uv4_pids, wu.port_listening = orig_pids, orig_pl
        wu.find_modal_dialogs = orig_find2

async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    await call(server, "enter_debug", {})

    await group_a(server)
    group_b()
    await group_c_async(server)

    await call(server, "exit_debug", {})
    srv.stop()

    print("\n==== 批次28 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

async def group_c_async(server):
    print("C. 服务层：dismiss_dialog 工具")
    tools = await server.list_tools()
    names = [t.name for t in tools]
    check("C1 dismiss_dialog 已注册", "dismiss_dialog" in names, "缺失")
    check("C2 工具总数 76→184", len(names) == 184, len(names))
    d = {t.name: (t.description or "") for t in tools}
    check("C3 描述说明会读正文与按钮",
          "正文" in d.get("dismiss_dialog", "") and "按钮" in d.get("dismiss_dialog", ""))
    check("C4 描述说明匹配不到时不擅自改点别的按钮",
          "button_not_found" in d.get("dismiss_dialog", ""))
    check("C5 keil_health 描述提到正文与按钮",
          "message" in d.get("keil_health", "") and "button_texts" in d.get("keil_health", ""))

    orig_find, orig_click = wu.find_modal_dialogs, wu._click_control
    clicks = []
    DLG = {"pid": 1, "hwnd": 999, "title": "µVision",
           "message": "Create File -o 'x' failed.",
           "buttons": [{"hwnd": 21, "text": "确定"}], "button_texts": ["确定"], "statics": []}
    state = {"open": True}
    try:
        wu.find_modal_dialogs = lambda: ([DLG] if state["open"] else [])

        def fake_click2(hwnd, timeout_ms=2000):
            clicks.append(hwnd)
            state["open"] = False
            return True

        wu._click_control = fake_click2
        r = await call(server, "dismiss_dialog", {"button": "确定"})
        check("C6 工具端到端可用（读正文 + 点按钮 + 确认关闭）",
              r.get("dismissed") is True and clicks == [21], r)
        check("C7 工具返回 remaining（关完为空）", r.get("remaining") == [], r)
    finally:
        wu.find_modal_dialogs, wu._click_control = orig_find, orig_click

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
