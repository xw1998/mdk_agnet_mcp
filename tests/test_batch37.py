# -*- coding: utf-8 -*-
"""批次37 mock 测试：真机阶段7 暴露的两处「看似权威的错答案」。

真机发现（F401 + Keil UVSOCK，阶段7 全量测试）：
A) `enter_debug` 报了 ok=true / ready=true，但约 1s 后 Keil **自己**把目标停了并退出调试
   （异步消息里看得到 `Stopping target...` → `Exited debug mode`）。根因是该 Keil 实例里
   残留了命令脚本（Keil 命令窗口的 .ini，以 EXIT / LOG OFF 结尾），脚本排在队列里，
   等我们进完调试才执行。此时「只确认一次」的 ready 是假就绪——调用方随后每条命令
   都返回 status=6，却完全看不到原因。
B) `flash_debug` 失败时顶层只有 `{"ok": false}`，真实原因只藏在 `enter_debug` /
   `build_flash` 子字段里，调用方无法直接知道失败原因与下一步。

修复：
- client.enter_debug 就绪后做一次**就绪复核**（debug_session_alive）：短暂停留后调试态
  还在不在；丢了则自动重发一次 UV_DBG_ENTER，仍不稳则 ready=False + warning 如实汇报。
- server.enter_debug 在 ready=False 时不再报 ok=true：补 error / error_code =
  enter-debug-not-ready / diagnosis。
- server.flash_debug 失败时把原因提到顶层：error / error_code / next_actions，
  并披露 launch_reused / launch_pid / uvision_instances。

运行：python -m tests.test_batch37
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer     # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug.server import create_server, _get_client    # noqa: E402
from mdkdebug import server as srv                        # noqa: E402

PORT = 14911
PASS, FAIL = [], []
_MDK_AXF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test", "mdk_test.axf")

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

async def call(server, name, args=None):
    res = await server.call_tool(name, args or {})
    return json.loads("".join(getattr(c, "text", "") or "" for c in res.content))

def test_enter_debug_session_lost(mock):
    """A：假就绪——就绪后调试态自己消失。"""
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_MDK_AXF if os.path.isfile(_MDK_AXF) else None)

    # A1/A2：丢一次后重试成功 → 如实披露 ready_retry，最终 ready=True
    mock.lose_debug_after = 2
    mock.lose_debug_repeat = False
    r = asyncio.run(call(server, "enter_debug", {}))
    check("A1 首次就绪后调试态消失 → 自动重试一次", r.get("ready_retry") is True, r)
    check("A2 重试后站稳：ready=True / ready_stable=ok，且 ok 仍为真",
          r.get("ok") is True and r.get("ready") is True
          and r.get("ready_stable") == "ok", r)
    check("A3 给出 note 说明曾重试、并提醒该实例可能有残留脚本",
          "残留命令脚本" in (r.get("note") or ""), r)
    check("A4 重试成功后不再给 warning（不误报失败）", not r.get("warning"), r)
    check("A5 会话确实可用：就绪后 read_mem 立即可读",
          asyncio.run(call(server, "read_mem",
                           {"addr": "0x20000000", "n_bytes": 4})).get("ok") is True, "")

    # A6-A9：两次都丢 → 如实报失败，绝不假装成功
    asyncio.run(call(server, "exit_debug", {}))
    mock.lose_debug_after = 2
    mock.lose_debug_repeat = True
    r = asyncio.run(call(server, "enter_debug", {}))
    check("A6 两次都丢 → ok=False（不再报看似成功的错答案）",
          r.get("ok") is False, r)
    check("A7 ready/ready_stable 如实标 False/lost",
          r.get("ready") is False and r.get("ready_stable") == "lost", r)
    check("A8 error_code=enter-debug-not-ready 且给 diagnosis",
          r.get("error_code") == "enter-debug-not-ready" and bool(r.get("diagnosis")), r)
    check("A9 next_actions 指向 close_uvision + launch_uvision 重开干净实例",
          any("close_uvision" in a for a in (r.get("next_actions") or [])), r)
    check("A10 warning 点明根因（残留命令脚本）",
          "残留" in (r.get("warning") or ""), r)

    # A11：正常路径不受影响
    mock.lose_debug_after = 0
    mock._lose_countdown = 0
    mock._force_not_debug = False
    r = asyncio.run(call(server, "enter_debug", {}))
    check("A11 正常路径 ready_stable=ok、无 retry 噪声",
          r.get("ok") is True and r.get("ready_stable") == "ok"
          and not r.get("ready_retry"), r)
    asyncio.run(call(server, "exit_debug", {}))

def test_flash_debug_top_error(mock):
    """B：flash_debug 失败时顶层必须有原因与下一步。"""
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           uv4_path=srv.builder.DEFAULT_UV4 if hasattr(srv.builder, "DEFAULT_UV4") else None)
    # _resolve_project / _parse_uvprojx_config 是 create_server 内部的闭包，外部改不到；
    # 这里直接喂真实的 .uvprojx，让它们按真实逻辑跑。
    proj = os.path.join(os.path.dirname(_MDK_AXF), "..", "mdk_test.uvprojx")
    proj = os.path.normpath(proj)
    if not os.path.isfile(proj):
        print("  [SKIP] 未找到真实工程，跳过 B 组")
        return
    cfg = dict(srv._builder_cfg)
    orig_uv4 = cfg.get("uv4")
    if srv._builder_cfg.get("uv4") is None:
        srv._builder_cfg["uv4"] = "UV4.exe"
    orig_build = srv.builder.build_project
    orig_close = srv.builder.close_uvision
    orig_launch = srv.builder.launch_uvision
    orig_client = srv._get_client
    srv.builder.close_uvision = lambda **k: {"ok": True, "closed": 0, "kept": []}
    try:
        # B1-B3：编译失败
        srv.builder.build_project = lambda *a, **k: {"ok": False, "error": "编译未通过：main.c error #20"}
        r = asyncio.run(call(server, "flash_debug", {"project": proj}))
        check("B1 编译失败：ok=False 且顶层有 error",
              r.get("ok") is False and bool(r.get("error")), r)
        check("B2 顶层 error_code 归类为 build-failed",
              r.get("error_code") == "build-failed", r)
        check("B3 顶层 status_text 说明未重开工程",
              "未重开工程" in (r.get("status_text") or ""), r)
        check("B4 不误报进入调试", not r.get("enter_debug"), r)

        # B5-B9：编译通过但进调试失败
        srv.builder.build_project = lambda *a, **k: {"ok": True, "exit_code": 0}
        srv.builder.launch_uvision = lambda *a, **k: {"ok": True, "reused": True,
                                                      "pid": 4242, "instances": 1}

        class FakeClient:
            def enter_debug(self):
                raise RuntimeError("UVSOCK 未就绪（4823 未监听）")

        srv._get_client = lambda: FakeClient()
        r = asyncio.run(call(server, "flash_debug", {"project": proj}))
        check("B5 进调试失败：顶层有 error（不再只有 ok=false）",
              r.get("ok") is False and bool(r.get("error")), r)
        check("B6 error_code 指向 uvsock-unavailable",
              r.get("error_code") == "uvsock-unavailable", r)
        check("B7 next_actions 给可执行下一步",
              len(r.get("next_actions") or []) >= 2, r)
        check("B8 披露窗口处置（reused/pid/instances）",
              r.get("launch_reused") is True and r.get("launch_pid") == 4242
              and r.get("uvision_instances") == 1, r)
        check("B9 编译阶段结果仍完整可见（build 字段在）",
              isinstance(r.get("build"), dict) and r["build"].get("ok") is True, r)
    finally:
        srv.builder.build_project = orig_build
        srv.builder.close_uvision = orig_close
        srv.builder.launch_uvision = orig_launch
        srv._get_client = orig_client
        if orig_uv4 is None:
            srv._builder_cfg.pop("uv4", None)
        else:
            srv._builder_cfg["uv4"] = orig_uv4

def main():
    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    try:
        print("-- A enter_debug 假就绪 --")
        test_enter_debug_session_lost(mock)
        print("-- B flash_debug 顶层错误 --")
        test_flash_debug_top_error(mock)
    finally:
        mock.stop()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
