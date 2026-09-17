# -*- coding: utf-8 -*-
"""批次18 mock 测试：编译/烧录的前置健康检查与编译后自愈（第 6 轮反馈）。

用户反馈：
1. rebuild_project 之后 Keil 进程消失——编译成功返回，但同一次响应的 keil 字段显示
   keil_alive=false、4823 无监听。UV4 命令行编译结束后把 GUI 实例一起带走，
   导致紧接着的烧录必须先 restart_keil。=> 编译类工具结束后自动检查并拉起 UVSOCK 会话。
2. 建议给编译/烧录工具加"前置健康检查 + 自愈"：工具内部先 keil_health 再决定是否重启，
   省掉一整轮 restart_keil 往返。

设计边界（本测试重点覆盖）：
- 前置快照 → 执行 → 后置快照；**仅当"编译前通道可用、编译后不可用"**才自动恢复，
  避免用户本来没开 Keil 时被擅自弹窗；
- 自愈动作 = 脱离 job 拉起 Keil → 等 4823 监听 → 丢弃旧 UVSOCK 连接（经注入钩子）；
- 结果始终带 keil_before / keil_after，让"编译成功但调试连不上"一眼可辨；
- ensure_debug_channel=false 可整体关闭自愈。
"""
import io
import os
import sys
import json
import time
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _get_client  # noqa: E402
from mdkdebug import builder, winutil  # noqa: E402

PORT = 14882
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))


async def call(server, name, args):
    res = await server.call_tool(name, args)
    return "".join(getattr(c, "text", "") or "" for c in res.content)


def load(r):
    try:
        return json.loads(r)
    except Exception:
        return {}


def snap(ready, code=None):
    """构造健康快照。"""
    c = code or ("ok" if ready else "keil_not_running")
    return {"ok": True, "code": c, "keil_alive": bool(ready), "uv4_pids": [1] if ready else [],
            "port_listening": bool(ready), "uvsock_ready": bool(ready),
            "modal_dialogs": [], "diagnosis": "stub", "suggestion": "stub"}


class Env:
    """统一打桩：健康快照序列、launch/wait、连接复位钩子。"""

    def __init__(self):
        self.snaps = []
        self.launched = []
        self.waited = []
        self.reset_calls = []
        self.wait_result = True

    def __enter__(self):
        self._real = (winutil.keil_health, winutil.launch_detached,
                      winutil.wait_port_listening, builder._reset_connection_hook)

        def fake_health(port=winutil.DEFAULT_UVSOCK_PORT):
            return self.snaps.pop(0) if self.snaps else snap(False)

        def fake_launch(uv4, project="", extra_args=None):
            self.launched.append((uv4, project))
            return {"ok": True, "pid": 999, "breakaway": True, "creationflags": "0x1020208"}

        def fake_wait(port=winutil.DEFAULT_UVSOCK_PORT, timeout=20.0, interval=0.2):
            self.waited.append((port, timeout))
            return self.wait_result

        winutil.keil_health = fake_health
        winutil.launch_detached = fake_launch
        winutil.wait_port_listening = fake_wait
        builder.set_reset_connection_hook(lambda reason: self.reset_calls.append(reason))
        return self

    def __exit__(self, *exc):
        (winutil.keil_health, winutil.launch_detached,
         winutil.wait_port_listening, builder._reset_connection_hook) = self._real
        return False


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
        client = _get_client()

        # ---------- A. 快照工具的健壮性 ----------
        with Env() as e:
            e.snaps = [snap(True)]
            s = builder._channel_snapshot()
            check("A1 _channel_snapshot 返回结构化快照", s.get("uvsock_ready") is True, str(s)[:160])

            def boom(port=winutil.DEFAULT_UVSOCK_PORT):
                raise OSError("probe failed")
            winutil.keil_health = boom
            s2 = builder._channel_snapshot()
            check("A2 探测抛异常时不外抛、返回 error 快照",
                  s2.get("uvsock_ready") is False and s2.get("code") == "error", str(s2)[:200])

        # ---------- B. _result 的四条分支 ----------
        with Env() as e:
            before = snap(True)
            e.snaps = [snap(False)]          # 后置：通道丢失
            e.wait_result = True
            r = builder._result("重新编译", 0, "", keil_before=before, uv4="C:/fake/UV4.exe",
                                project="C:/fake/x.uvprojx")
            check("B1 前可用→后不可用：触发自愈并置 keil_recovered=true",
                  r.get("keil_recovered") is True, str(r)[:300])
            check("B2 自愈调用 launch_detached（带工程）",
                  e.launched and e.launched[0][1] == "C:/fake/x.uvprojx", str(e.launched))
            check("B3 自愈等待 4823 监听", e.waited and e.waited[0][0] == winutil.DEFAULT_UVSOCK_PORT,
                  str(e.waited))
            check("B4 自愈重置 UVSOCK 连接", len(e.reset_calls) == 1, str(e.reset_calls))
            check("B5 返回 keil_before / keil_after 均可查",
                  isinstance(r.get("keil_before"), dict) and isinstance(r.get("keil_after"), dict),
                  str(list(r))[:200])
            check("B6 keil_wait_ms 有值且 keil_note 说明已恢复",
                  isinstance(r.get("keil_wait_ms"), int) and "自动重启" in str(r.get("keil_note")),
                  str(r.get("keil_note"))[:200])

        with Env() as e:
            e.snaps = [snap(False)]          # 前后都不可用（用户本就没开 Keil）
            r = builder._result("编译", 0, "", keil_before=snap(False), uv4="C:/fake/UV4.exe")
            check("B7 前不可用→后不可用：不擅自拉起 Keil",
                  not e.launched and "keil_recovered" not in r, str(r)[:200])
            check("B8 但仍给出通道不可用提示", "keil_note" in r, str(r)[:200])

        with Env() as e:
            e.snaps = [snap(True)]           # 前后都可用
            r = builder._result("编译", 0, "", keil_before=snap(True), uv4="C:/fake/UV4.exe")
            check("B9 前可用→后可用：不做任何动作",
                  not e.launched and not e.reset_calls and "keil_recovered" not in r, str(r)[:200])

        with Env() as e:
            e.snaps = [snap(False)]
            r = builder._result("编译", 0, "", keil_before=snap(True), uv4="C:/fake/UV4.exe",
                                ensure_debug_channel=False)
            check("B10 ensure_debug_channel=false 关闭自愈",
                  not e.launched and r.get("ensure_debug_channel") is False, str(r)[:200])

        with Env() as e:
            e.snaps = [snap(True)]           # 无前置快照（老调用方）
            r = builder._result("编译", 0, "")
            check("B11 老签名调用仍可用（keil 字段保留）",
                  isinstance(r.get("keil"), dict) and r.get("ok") is True, str(r)[:200])
            check("B12 无前置快照时不触发自愈（无法判定，保持保守）",
                  not e.launched, str(e.launched))

        # ---------- C. 自愈未成功时的诚实报告 ----------
        with Env() as e:
            e.snaps = [snap(False)]
            e.wait_result = False            # 端口等不到
            r = builder._result("烧录", 0, "", keil_before=snap(True), uv4="C:/fake/UV4.exe")
            check("C1 拉起后端口仍未监听：keil_recovered=false",
                  r.get("keil_recovered") is False, str(r)[:300])
            check("C2 不谎报成功且提示可 restart_keil",
                  "restart_keil" in str(r.get("keil_note")), str(r.get("keil_note"))[:200])
            check("C3 keil_recovery 明细含 launched/port_listening/connection_reset",
                  all(k in (r.get("keil_recovery") or {})
                      for k in ("launched", "port_listening", "connection_reset")),
                  str(r.get("keil_recovery"))[:200])
            check("C4 端口没起来时不重置连接（避免无谓动作）",
                  not e.reset_calls, str(e.reset_calls))

        # ---------- D. builder 各入口都带前置快照 ----------
        real_run = builder._run_uv4
        builder._run_uv4 = lambda uv4, args, timeout, visible=False: (0, "0 Error(s)")
        try:
            with Env() as e:
                e.snaps = [snap(True), snap(True)]
                r = builder.build_project("C:/fake/UV4.exe", "C:/fake/x.uvprojx")
                check("D1 build_project 带 keil_before 快照",
                      isinstance(r.get("keil_before"), dict), str(r)[:200])
            with Env() as e:
                e.snaps = [snap(True), snap(True)]
                r = builder.rebuild_project("C:/fake/UV4.exe", "C:/fake/x.uvprojx")
                check("D2 rebuild_project 带 keil_before 快照",
                      isinstance(r.get("keil_before"), dict) and r.get("ok") is True, str(r)[:200])
            with Env() as e:
                e.snaps = [snap(True), snap(True)]
                r = builder.flash_download("C:/fake/UV4.exe", "C:/fake/x.uvprojx")
                check("D3 flash_download 带 keil_before 快照",
                      isinstance(r.get("keil_before"), dict), str(r)[:200])

            with Env() as e:
                e.snaps = [snap(True), snap(False)]   # build 阶段后通道丢失 → 自愈
                r = builder.build_and_flash("C:/fake/UV4.exe", "C:/fake/x.uvprojx")
                check("D4 build_and_flash 顶层汇总 keil_before/keil_after",
                      isinstance(r.get("keil_before"), dict) and isinstance(r.get("keil_after"), dict),
                      str(list(r))[:200])
                check("D5 build_and_flash 透传自愈结果",
                      r.get("keil_recovered") is True or r.get("ok") is True, str(r)[:200])
                check("D6 build_and_flash 两阶段都执行（build+flash 均在）",
                      "build" in r and "flash" in r, str(list(r))[:200])
        finally:
            builder._run_uv4 = real_run

        # ---------- E. 工具层参数透传 ----------
        real_build = builder.build_project
        captured = {}

        def fake_build(uv4, project, target=None, timeout=0, ensure_debug_channel=True):
            captured["ensure"] = ensure_debug_channel
            captured["uv4"] = uv4
            return {"ok": True, "action": "编译", "exit_code": 0, "status_text": "成功"}

        server_module = sys.modules["mdkdebug.server"]
        server_module._builder_cfg["uv4"] = "C:/fake/UV4.exe"
        builder.build_project = fake_build
        try:
            out = load(await call(server, "build_project",
                                  {"project": "C:/fake/x.uvprojx", "ensure_debug_channel": False}))
            check("E1 build_project 工具透传 ensure_debug_channel=false",
                  captured.get("ensure") is False, str(captured))
            out = load(await call(server, "build_project", {"project": "C:/fake/x.uvprojx"}))
            check("E2 默认 ensure_debug_channel=true", captured.get("ensure") is True, str(captured))

            real_baf = builder.build_and_flash

            def fake_baf(uv4, project, target=None, build_timeout=0, flash_timeout=0,
                         ensure_debug_channel=True):
                captured["baf_ensure"] = ensure_debug_channel
                return {"ok": True, "action": "编译并烧录", "stage": "烧录"}

            builder.build_and_flash = fake_baf
            try:
                await call(server, "build_and_flash",
                           {"project": "C:/fake/x.uvprojx", "ensure_debug_channel": False})
            finally:
                builder.build_and_flash = real_baf
            check("E3 build_and_flash 工具透传 ensure_debug_channel",
                  captured.get("baf_ensure") is False, str(captured))
        finally:
            builder.build_project = real_build

        # ---------- F. 工具签名与描述 ----------
        tools = {t.name: t for t in await server.list_tools()}
        for n in ("build_project", "rebuild_project", "flash_download", "build_and_flash"):
            props = (tools[n].input_schema or {}).get("properties", {}) if n in tools else {}
            check("F-%s 暴露 ensure_debug_channel 参数" % n,
                  "ensure_debug_channel" in props, str(list(props))[:200])
            d = (tools[n].description or "") if n in tools else ""
            check("F-%s 描述说明自愈行为" % n,
                  "ensure_debug_channel" in d and "keil_recovered" in d, d[:160])
        check("F1 工具数 81→83（批次30 新增 clear_faults / serial_write）", len(tools) == 83, str(len(tools)))

        # ---------- G. 钩子接线 ----------
        check("G1 server 已注入连接复位钩子",
              builder._reset_connection_hook is not None, "")
        with Env() as e:
            builder._reset_connection_hook("测试原因")
            check("G2 钩子可被替换与调用（可测性）", e.reset_calls == ["测试原因"], str(e.reset_calls))

        await call(server, "exit_debug", {})
    finally:
        try:
            srv.stop()
        except Exception:  # noqa: BLE001
            pass

    print("\n批次18 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
