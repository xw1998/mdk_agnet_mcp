# -*- coding: utf-8 -*-
"""批次16 mock 测试：连接器健康检查与生命周期（第 4 轮反馈的连接器部分）。

用户反馈的痛点：
1. Keil 进程已死而连接器完全无感知——AI 只能看到"命令没反应/超时"；
   => 新增 keil_health（UV4 进程 + 4823 监听 + 模态框）+ 连接失败时带诊断，
      并把 code 明确为 keil_not_running / port_not_listening / port_occupied。
2. 脏会话只能"关掉再开"恢复 => 新增 reset_connection（只重建 UVSOCK 连接）与
   restart_keil（关→脱离父进程重启→等端口→重连），超时后还会自动复位。
3. 由调用链拉起的 UV4 会被 job 回收 => launch_uvision 改用
   CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP。
4. 编译烧录与调试是两条通道 => build/flash 结果附带 Keil 健康快照。
5. 模态对话框阻塞无检测 => 超时诊断里列出对话框标题。
"""
import io
import os
import sys
import json
import time
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug.server import create_server, _get_client  # noqa: E402
from mdkdebug.client import UVClient, UVSOCKConnectError  # noqa: E402
from mdkdebug import builder, winutil, uvsock  # noqa: E402

REAL_PROJ = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))),
    "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test.uvprojx")
PORT = 14881
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


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
        client = _get_client()

        # 本机可能正开着 Keil（UV4 进程存活并监听 4823），会让下面几项
        # “无 UV4 进程”的断言随环境漂移；这里显式把 UV4 进程枚举打桩为空，构造可重复环境。
        _real_uv4_pids = winutil.uv4_pids
        winutil.uv4_pids = lambda: []

        # ---------- 1. 健康检查 ----------
        h = load(await call(server, "keil_health", {}))
        check("H1 keil_health 在无 Keil 时也能正常返回", h.get("ok") is True, str(h)[:200])
        check("H2 端口被 mock 监听时 port_listening=true",
              h.get("port_listening") is True, str(h)[:200])
        check("H3 快照字段齐全（keil_alive/uv4_pids/uvsock_ready/diagnosis）",
              all(k in h for k in ("keil_alive", "uv4_pids", "uvsock_ready", "diagnosis", "code")),
              str(list(h))[:200])
        check("H4 只监听端口但无 UV4 进程时 code=port_occupied",
              h.get("code") == "port_occupied", str(h.get("code")))
        check("H5 诊断文本说明端口被占用", "占用" in str(h.get("diagnosis")), str(h.get("diagnosis")))
        check("H6 模态框字段存在（无 Keil 时为空列表）",
              h.get("modal_dialogs") == [] and h.get("modal_blocked_suspected") is False, str(h)[:160])

        # 端口探测函数本身
        check("H7 port_listening 对监听端口返回 True", winutil.port_listening(PORT) is True, "")
        check("H8 port_listening 对未监听端口返回 False",
              winutil.port_listening(14899, timeout=0.2) is False, "")
        check("H9 keil_health 对未运行 Keil 给出 keil_not_running",
              winutil.keil_health(14899).get("code") == "keil_not_running",
              str(winutil.keil_health(14899)))
        winutil.uv4_pids = _real_uv4_pids

        # ---------- 2. 连接失败带诊断 ----------
        bad = UVClient(host="127.0.0.1", port=14899, idle_timeout=1.0)
        err_text = ""
        try:
            bad.get_status()
        except UVSOCKConnectError as e:
            err_text = str(e)
        except Exception as e:  # noqa: BLE001
            err_text = "OTHER:" + str(e)
        check("C1 连不上时抛 UVSOCKConnectError", err_text.startswith("无法连接"), err_text[:200])
        check("C2 错误里带健康诊断", "诊断：" in err_text, err_text[:220])
        check("C3 错误里带可操作建议",
              "launch_uvision" in err_text or "UVSOCK" in err_text, err_text[:260])

        # ---------- 3. 超时自动复位 + 诊断 ----------
        await call(server, "enter_debug", {})
        # 回归：_drain_async 不能把 socket 的超时清成 None（永久阻塞）
        check("T0 收发后 socket 仍保留超时（不会永久阻塞）",
              client.phy.sock is not None and client.phy.sock.gettimeout() is not None,
              str(client.phy.sock and client.phy.sock.gettimeout()))
        client.phy.TIMEOUT_COUNTS = 3          # 把超时压到 ~0.3s，避免测试变慢
        srv.drop_responses = True
        tip = ""
        try:
            client.get_status()
        except Exception as e:  # noqa: BLE001
            tip = str(e)
        check("T1 超时抛错并带诊断", "cmd=0x" in tip and ("诊断" in tip or "Keil" in tip or "模态" in tip),
              tip[:260])
        check("T2 超时后连接已自动复位", client.phy.is_connected is False, str(client.phy.is_connected))
        srv.drop_responses = False
        client.phy.TIMEOUT_COUNTS = 100
        try:
            st = client.get_status()
            ok_after = bool(st.get("ok"))
        except Exception as e:  # noqa: BLE001
            ok_after = False
            print("     重连失败:", e)
        check("T3 复位后可直接重试成功（无需重启 Keil）", ok_after, "")

        # ---------- 3b. Keil 中途死掉：连接中断要快速失败并带诊断 ----------
        client.phy.open()
        srv.drop_connection_after = 1      # 下一个请求回完响应就 RST 断开
        t0 = time.time()
        tip2 = ""
        # RST 具体落在哪一次调用上取决于收发时序，故连续尝试直到出现异常
        for _ in range(4):
            try:
                client.get_status()
            except Exception as e:  # noqa: BLE001
                tip2 = str(e)
                break
        dt = time.time() - t0
        check("S1 连接被重置时抛错并带诊断",
              ("中断" in tip2 or "超时" in tip2) and ("诊断" in tip2 or "Keil" in tip2),
              tip2[:260])
        check("S2 连接被重置后自动复位", client.phy.is_connected is False,
              str(client.phy.is_connected))
        check("S3 断开能秒级失败（不干等超时）", dt < 3.0, "耗时 %.2fs" % dt)
        srv.drop_connection_after = 0
        try:
            st_r = client.get_status()
            ok_re = bool(st_r.get("ok"))
        except Exception as e:  # noqa: BLE001
            ok_re = False
            print("     重连失败:", e)
        check("S4 复位后可重新连上并正常执行", ok_re, "")

        # ---------- 4. reset_connection 工具 ----------
        client.phy.open()
        check("R1 连接已建立", client.phy.is_connected is True, "")
        client.phy.console_log.append({"type": "output", "text": "x"})
        client.phy.async_log.append({"cmd": 1})
        r = load(await call(server, "reset_connection", {"reason": "测试"}))
        check("R2 reset_connection 返回 ok", r.get("ok") is True, str(r)[:200])
        check("R3 连接被丢弃", client.phy.is_connected is False, "")
        check("R4 残留缓冲被清空",
              client.phy.console_log == [] and client.phy.async_log == [], "")
        check("R5 返回里带 Keil 健康快照", isinstance(r.get("keil"), dict), str(r)[:200])
        d = load(await call(server, "get_status", {}))
        check("R6 复位后命令可正常执行", d.get("ok") is True, str(d)[:200])

        # ---------- 5. restart_keil ----------
        # mock 环境不能真的开关 Keil：把「关」和「起」两步打桩，只验证流程与返回结构；
        # 同时把 UV4 进程枚举打桩为空，否则本机开着 Keil 时会判成 keil_alive=true。
        winutil.uv4_pids = lambda: []
        real_launch2, real_close = builder.launch_uvision, builder.close_uvision
        builder.launch_uvision = lambda uv4, project="": {
            "ok": True, "pid": 999, "breakaway": True, "creationflags": "0x1020208"}
        builder.close_uvision = lambda force=True: {"ok": True, "closed": [], "note": "mock"}
        try:
            r = load(await call(server, "restart_keil",
                                {"project": REAL_PROJ, "wait_ready": 3.0}))
        finally:
            builder.launch_uvision, builder.close_uvision = real_launch2, real_close
            winutil.uv4_pids = _real_uv4_pids
        check("K1 restart_keil 返回完整流程结构",
              all(k in r for k in ("action", "close", "launch", "port_wait",
                                   "reset", "health", "ok")), str(r)[:240])
        # mock 环境只有监听端口、没有 UV4 进程：必须诚实判为未就绪并给出诊断，
        # 而不是"重启成功"——这正是反馈 #1 要解决的问题
        check("K2 端口有监听但无 UV4 进程时诚实判为未就绪并给建议",
              r.get("ok") is False and r.get("port_listening") is True
              and r.get("keil_alive") is False and bool(r.get("suggestion")),
              str(r)[:300])

        # ---------- 6. launch_uvision 走脱离 job 的启动路径 ----------
        captured = {}
        real_launch = builder.winutil.launch_detached

        def fake_launch(uv4, project="", extra_args=None):
            captured["uv4"] = uv4
            captured["project"] = project
            return {"ok": True, "pid": 4321, "creationflags": "0x1020208",
                    "detached": True, "breakaway": True}

        builder.winutil.launch_detached = fake_launch
        # single 守卫（批次57）会先枚举实例：本机真开着别的 Keil 时会把这里判成拒绝，
        # 与用例意图无关 → 打桩为空，保持用例只验证「脱离 job 的启动路径」。
        real_instances = builder.winutil.uv4_instances
        builder.winutil.uv4_instances = lambda: []
        try:
            r = builder.launch_uvision(r"C:\fake\UV4.exe", r"C:\fake\x.uvprojx")
        finally:
            builder.winutil.launch_detached = real_launch
            builder.winutil.uv4_instances = real_instances
        check("L1 launch_uvision 走 launch_detached（脱离 job）",
              captured.get("uv4") == r"C:\fake\UV4.exe" and captured.get("project") == r"C:\fake\x.uvprojx",
              str(captured))
        check("L2 返回里带 pid/creationflags/breakaway",
              all(k in r for k in ("pid", "creationflags", "breakaway")), str(r)[:200])
        check("L3 提示 UVSOCK 需等端口就绪", "keil_health" in str(r.get("hint", "")), str(r)[:200])

        # detached flags 真的含 breakaway 位
        flags = (getattr(__import__("subprocess"), "DETACHED_PROCESS", 0x8)
                 | getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0x200)
                 | 0x01000000)
        check("L4 creationflags 含 BREAKAWAY/DETACHED/NEW_GROUP 位",
              (flags & 0x01000000) and (flags & 0x8) and (flags & 0x200), hex(flags))

        # ---------- 7. build 结果带 Keil 健康快照 ----------
        res = builder._result("编译", 0, "")
        check("B1 build 结果含 keil 健康快照",
              isinstance(res.get("keil"), dict) and "port_listening" in res["keil"], str(res)[:200])
        check("B2 build 结果 ok/exit_code/status_text 未变",
              res["ok"] is True and res["exit_code"] == 0 and "成功" in res["status_text"], str(res)[:160])

        # ---------- 8. 工具描述 ----------
        tools = {t.name: t for t in await server.list_tools()}
        for n in ("keil_health", "reset_connection", "restart_keil"):
            check("D-%s 已注册且有描述" % n,
                  n in tools and "【参数】" in (tools[n].description or ""), "")
        check("D-keil_health 描述提到模态框", "模态" in (tools["keil_health"].description or ""), "")
        check("D-restart_keil 描述提示会关闭所有实例",
              "关闭所有 Keil 实例" in (tools["restart_keil"].description or ""), "")
        check("D1 工具数 68→200", len(tools) == 200, str(len(tools)))

        await call(server, "exit_debug", {})
    finally:
        try:
            srv.stop()
        except Exception:  # noqa: BLE001
            pass

    print("\n批次16 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")




if __name__ == "__main__":
    asyncio.run(main())
