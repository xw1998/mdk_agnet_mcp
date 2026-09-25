# -*- coding: utf-8 -*-
"""批次57 mock 测试：宿主 python 变量隔离 + Keil 窗口/工程写入闭环。

用户反馈原文：
    「又发现你开始开多个mdk窗口了，而且窗口还有弹窗，感觉你是先开mdk再改代码的
      导致mdk弹窗说文件更新，之前不是说好只开一个mdk的吗？感觉控制逻辑还是没有闭环」

本批把三件事做成机制（不是靠自觉）：
  A winutil.child_env：启动外部工具前剥掉宿主 python 变量（PYTHONHOME 泄漏真机复现过）
  B 子进程 env 闭环：launch_detached / builder / ocd / toolchain 全部走 child_env
  C uvprojx_edit 守卫：Keil 开着同工程时拒绝写 .uvprojx（模态框会堵死调试通道）
  D launch_uvision single：只保留一个 Keil 窗口（拒绝新开 / 强制复用 / 显式放行）
  E 错误码登记与统一信封

纪律：本用例**不得真正启动 Keil GUI**（会在桌面留下窗口且无人收）。main() 入口即把
launch_detached 换成抛异常的桩，需要走启动路径的分支必须显式打桩。

运行：python -m tests.test_batch57
"""
import os
import sys
import json
import shutil
import tempfile
import asyncio
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

import os as _os_env  # noqa: E402
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import builder, winutil, errors, toolchain, ocd  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14899
PASS, FAIL = [], []
PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                    "mdk_test.uvprojx")
_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                    "mdk_test", "mdk_test.axf")

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:300]), flush=True)

async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:300]}

def main():
    # 测试禁止真正启动 Keil GUI：任何漏打桩的启动路径立即失败，而不是在桌面留下窗口
    _real_launch_detached = winutil.launch_detached

    def _no_gui(*a, **kw):
        raise AssertionError(
            "测试不得真正启动 Keil GUI：launch_detached 未被打桩（会多留一个 Keil 窗口）")

    winutil.launch_detached = _no_gui

    # ============ A. child_env ============
    print("A. winutil.child_env：剥掉宿主 python 变量")
    saved = {}
    for k in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
        saved[k] = os.environ.get(k)
        os.environ[k] = r"C:\host\py-env"
    try:
        env = winutil.child_env()
        check("A1 PYTHONHOME/PYTHONPATH/VIRTUAL_ENV 全部剥离",
              not any(k in env for k in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV")),
              [k for k in env if k.startswith("PYTHON") or k == "VIRTUAL_ENV"])
        check("A2 PATH 等宿主必需变量保留",
              "PATH" in env and "SYSTEMROOT" in env, sorted(env)[:8])
        check("A3 不改动宿主 os.environ（纯函数）",
              os.environ.get("PYTHONHOME") == r"C:\host\py-env")
        e2 = winutil.child_env(extra={"PATH": r"C:\x", "N": 1})
        check("A4 extra 叠加且值字符串化（int → str）",
              e2.get("PATH") == r"C:\x" and e2.get("N") == "1", (e2.get("PATH"), e2.get("N")))
        e3 = winutil.child_env(base={"PYTHONHOME": "h", "ONLY": "1"})
        check("A5 base 分支：以 base 为底、仍剥 python 变量、不混入宿主变量",
              "PYTHONHOME" not in e3 and e3.get("ONLY") == "1" and "PATH" not in e3, e3)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ============ B. 子进程 env 闭环 ============
    print("B. 子进程 env 闭环：三个模块都走 child_env")
    os.environ["PYTHONHOME"] = r"C:\host\py-env"
    os.environ["PYTHONPATH"] = r"C:\host\lib"
    captured = {}
    real_sub = winutil.subprocess

    class _Proc:
        pid = 4242

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        captured["env"] = kw.get("env")
        return _Proc()

    winutil.subprocess = types.SimpleNamespace(
        Popen=fake_popen, DEVNULL=-3, DETACHED_PROCESS=0x8,
        CREATE_NEW_PROCESS_GROUP=0x200, CREATE_BREAKAWAY_FROM_JOB=0x1000000)
    try:
        r = _real_launch_detached(r"C:\fake\UV4.exe", PROJ)
        check("B1 launch_detached 启动 UV4 时 env 里没有宿主 PYTHONHOME/PYTHONPATH",
              r.get("ok") is True and isinstance(captured.get("env"), dict)
              and "PYTHONHOME" not in captured["env"]
              and "PYTHONPATH" not in captured["env"], (r, captured.get("env")))
    finally:
        winutil.subprocess = real_sub
        os.environ.pop("PYTHONHOME", None)
        os.environ.pop("PYTHONPATH", None)

    src = {}
    for name in ("winutil", "builder", "ocd", "toolchain"):
        src[name] = open(os.path.join(ROOT, "mdkdebug", name + ".py"),
                         encoding="utf-8").read()
    check("B2 winutil 里两处 Popen 都显式传 env=child_env()",
          src["winutil"].count("env=child_env()") == 2,
          src["winutil"].count("env=child_env()"))
    check("B3 builder（UV4 编译子进程）用 winutil.child_env()",
          "winutil.child_env()" in src["builder"])
    check("B4 ocd（OpenOCD 子进程）用 winutil.child_env(base=env)",
          "winutil.child_env(base=env)" in src["ocd"])
    check("B5 toolchain（gcc/make 子进程）用 winutil.child_env(extra=...)",
          "winutil.child_env(extra=env_extra)" in src["toolchain"])
    check("B6 winutil 已 import os（child_env 依赖）",
          "import os" in src["winutil"])

    # ============ C. uvprojx_edit 守卫 ============
    print("C. uvprojx_edit：Keil 开着同工程时不写工程文件")
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    loop = asyncio.new_event_loop()

    real_lui = builder.list_uvision_instances
    builder.list_uvision_instances = lambda project="": {
        "ok": True, "count": 1, "total": 1,
        "instances": [{"pid": 4321, "project": PROJ, "has_window": True}]}
    try:
        r = loop.run_until_complete(call(server, "uvprojx_edit", {
            "action": "add_include_path", "project": PROJ, "paths": "Inc"}))
        check("C1 Keil 开着同一工程 → 拒绝写入并给出 project-open-in-keil",
              r.get("ok") is False and r.get("error_code") == "project-open-in-keil", r)
        check("C2 拒绝时列出占用进程与可执行的下一步",
              r.get("open_instances") == [4321]
              and any("close_uvision" in a for a in r.get("next_actions", [])), r)
    finally:
        builder.list_uvision_instances = real_lui

    # 探测失败不阻断写入（不能让探测把功能锁死）
    builder.list_uvision_instances = lambda project="": (_ for _ in ()).throw(
        RuntimeError("boom"))
    try:
        tmpd = tempfile.mkdtemp(prefix="b57_")
        tproj = os.path.join(tmpd, "t.uvprojx")
        shutil.copyfile(PROJ, tproj)
        r2 = loop.run_until_complete(call(server, "uvprojx_edit", {
            "action": "add_include_path", "project": tproj, "paths": "IncXyz",
            "backup": False}))
        check("C3 实例探测失败不阻断写入（守卫只做加法，不锁死功能）",
              r2.get("ok") is True and "IncXyz" in open(tproj, encoding="utf-8").read(), r2)
        r3 = loop.run_until_complete(call(server, "uvprojx_edit", {
            "action": "add_include_path", "project": tproj, "paths": "IncForce",
            "backup": False, "force": True}))
        check("C4 force=true 显式放行（Keil 开着也照写，调用方承担后果）",
              r3.get("ok") is True, r3)
        shutil.rmtree(tmpd, ignore_errors=True)
    finally:
        builder.list_uvision_instances = real_lui

    # ============ D. launch_uvision single ============
    print("D. launch_uvision single：只保留一个 Keil 窗口")
    other = os.path.join(os.path.dirname(PROJ), "other.uvprojx")
    real_inst = winutil.uv4_instances
    winutil.uv4_instances = lambda: [
        {"pid": 11, "created": 100.0, "project": other, "hwnd": 111, "has_window": True}]
    try:
        r4 = loop.run_until_complete(call(server, "launch_uvision", {"project": PROJ}))
        check("D1 server 层默认 single=true → 别的工程在开时拒绝新开",
              r4.get("ok") is False and r4.get("error_code") == "keil-multiple-instances", r4)
        check("D2 拒绝经统一信封补出 error_hint 与 next_actions",
              bool(r4.get("error_hint")) and any("close_uvision" in a
                                                 for a in r4.get("next_actions", [])), r4)
        real_ld = winutil.launch_detached
        launched = []

        def _fake_launch(uv4, project="", extra_args=None):
            launched.append((uv4, project))
            return {"ok": True, "pid": 999, "breakaway": True,
                    "creationflags": "0x1020208"}

        winutil.launch_detached = _fake_launch
        try:
            r5 = loop.run_until_complete(call(server, "launch_uvision",
                                              {"project": PROJ, "single": False}))
        finally:
            winutil.launch_detached = real_ld
        check("D3 single=false 才放行（server 透传到 builder，且真的走了启动路径）",
              r5.get("ok") is True and r5.get("reused") is False
              and launched and launched[0][1] == PROJ, (r5, launched))
    finally:
        winutil.uv4_instances = real_inst

    # 工具 schema 里能看见 single 参数
    tools = loop.run_until_complete(server.list_tools())
    tmap = {t.name: t for t in tools}
    lv = tmap.get("launch_uvision")
    schema = (getattr(lv, "inputSchema", None) or getattr(lv, "input_schema", {}) or {})
    props = (schema.get("properties") or {})
    check("D4 工具 schema 暴露 single 参数（默认 true）",
          "single" in props and props["single"].get("default") is True, props.get("single"))
    check("D5 描述里讲清 single 的闭环语义",
          "keil-multiple-instances" in (lv.description or "")
          and "single=false" in (lv.description or ""), (lv.description or "")[:200])

    # ============ E. 错误码登记 ============
    print("E. 错误码登记与统一信封")
    check("E1 ERROR_CODES 登记三个新码",
          all(c in errors.ERROR_CODES for c in ("keil-multiple-instances",
                                                "keil-launch-failed",
                                                "project-open-in-keil")),
          [c for c in ("keil-multiple-instances", "keil-launch-failed",
                       "project-open-in-keil") if c not in errors.ERROR_CODES])
    n = errors.normalize("launch_uvision",
                         {"ok": False, "error": "已有别的工程在开",
                          "error_code": "keil-multiple-instances"})
    check("E2 normalize 补 status=error / error_hint / next_actions",
          n.get("status") == "error" and bool(n.get("error_hint"))
          and bool(n.get("next_actions")), n)
    check("E3 next_actions 里带「谁占着 UVSOCK」这类可执行信息",
          any("close_uvision" in a for a in n.get("next_actions", [])), n.get("next_actions"))

    print("\n==== 批次57 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
