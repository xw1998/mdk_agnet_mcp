# -*- coding: utf-8 -*-
"""批次29 mock 测试：并发串行化 / 符号文件陈旧告警 / 烧录后调试会话 / 串口日志监听。

用户反馈原文（第 13 轮评价）：
    「1. 并发调用不安全（最痛的一次）我并行发多条 write_mem 到同一 UVSOCK，结果互相竞争——
      sf_hist_total 的写入被另一条 write_mem 静默吞掉，直接导致我误判"看门狗又复位了"」
    「2. flash_download 之后，旧调试会话的符号就是陈旧的——但工具没有任何提醒」
    「3. flash_download 完成后如处于调试态，自动 exit 或返回显式提示」
    「4. 内置一个串口日志监听工具（这次 COM9 日志我是用外部 Python 抓的），做成 ring buffer + read 工具」

  A 并发串行化：闸门可重入 / 跨进程互斥 / 实例清点 / 遥测（服务层可见）
  B 符号文件：路径+时间戳、陈旧判定、求值失败附告警
  C 烧录后：write_mem 回读校验、debug_session 处理旧会话
  D 串口日志：ring buffer、增量读、4 个工具的注册与无监听退化路径

运行：python -m tests.test_batch29
"""
import os
import sys
import json
import time
import shutil
import struct
import asyncio
import tempfile
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# 测试用独立闸门目录，避免与真实服务/其他测试互相干扰
GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b29")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import guard, serialmon  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug import uvsock as uvproto  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14902
GUARD_PORT = 14999
PASS, FAIL = [], []
_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                    "mdk_test", "mdk_test.axf")
_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                     "mdk_test.uvprojx")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:300]), flush=True)


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
    return (r.get("results") or [{}])[0]


# ------------------------------------------------------------------
_SUBPORT_PLACEHOLDER = None

_CHILD_SRC = """
import os, sys, time
sys.path.insert(0, %(root)r)
from mdkdebug import guard
guard.touch_presence(%(port)d, {"project": "b29-child", "role": "test"}, throttle=0.0)
g = guard.EndpointGuard(host="127.0.0.1", port=%(port)d)
with g.hold(timeout=3.0):
    print("LOCKED", flush=True)
    time.sleep(%(hold).1f)
print("DONE", flush=True)
"""


def group_a_guard():
    print("A. UVSOCK 全局限流/串行化（跨进程互斥 + 实例清点 + 遥测）")

    # ---- A1/A2 可重入：batch 内嵌套调用不自锁 ----
    g = guard.EndpointGuard(host="127.0.0.1", port=GUARD_PORT)
    t0 = time.time()
    blew = None
    try:
        with g.hold(timeout=2.0):
            with g.hold(timeout=2.0):
                pass
    except Exception as e:  # noqa: BLE001
        blew = e
    dt = time.time() - t0
    check("A1 闸门可重入（嵌套 hold 不自锁、不阻塞）",
          blew is None and dt < 1.0, {"exc": str(blew), "dt": dt})
    snap = g.snapshot()
    check("A2 嵌套结束后深度归零、跨进程锁已释放（acquired=1、held=False）",
          snap["held"] is False and g.stats["acquired"] == 1, snap)
    check("A3 snapshot 暴露 lock_path 与统计字段",
          snap["lock_path"].endswith("uvsock_%d.lock" % GUARD_PORT)
          and all(k in snap for k in ("acquired", "waits", "lock_timeouts",
                                      "degraded", "foreign_pid")), snap)

    # ---- A4/A5/A6 跨进程互斥（真实子进程持锁） ----
    src = _CHILD_SRC % {"root": ROOT, "port": GUARD_PORT, "hold": 3.0}
    child = subprocess.Popen([sys.executable, "-u", "-c", src],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=dict(os.environ))
    locked = False
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            line = child.stdout.readline()
            if not line:
                break
            if "LOCKED" in line:
                locked = True
                break
        check("A4 子进程已持有跨进程锁", locked, "子进程未报 LOCKED（见 stderr）")
        if not locked:
            return None

        g2 = guard.EndpointGuard(host="127.0.0.1", port=GUARD_PORT)
        t0 = time.time()
        with g2.hold(timeout=0.3):
            pass
        dt = time.time() - t0
        check("A5 另一个进程持锁时，本进程等待到超时（≈0.3s）而不是立刻发命令",
              dt >= 0.28, "elapsed=%.3fs" % dt)
        check("A6 超时后降级放行并如实记数（lock_timeouts/degraded/foreign_pid）",
              g2.stats["lock_timeouts"] >= 1 and g2.stats["degraded"] is True
              and int(g2.stats["foreign_pid"] or 0) == child.pid, g2.snapshot())

        # ---- A7 实例清点与并发警告 ----
        inst = guard.live_instances(port=GUARD_PORT)
        pids = [i.get("pid") for i in inst]
        check("A7 live_instances 清点到子进程（心跳新鲜 + PID 存活）",
              child.pid in pids, {"instances": inst, "child": child.pid})
        rep = guard.concurrency_report(GUARD_PORT, g2)
        check("A8 concurrency_report 给出 other_instances 与 warning（含对手 PID）",
              rep.get("other_instance_count", 0) >= 1
              and str(child.pid) in (rep.get("warning") or "")
              and "静默覆盖" in (rep.get("warning") or ""), rep.get("warning"))
        check("A9 report 说明双保险机制（in_process / cross_process）",
              "RLock" in (rep.get("in_process") or "")
              and "lock file" in (rep.get("cross_process") or ""), rep)
    finally:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
    after = [i.get("pid") for i in guard.live_instances(port=GUARD_PORT)]
    check("A10 子进程退出后不再被清点为活跃实例",
          child.pid not in after, {"after": after, "child": child.pid})
    return g2


async def group_b_symbol(server, tmp_axf):
    print("B. 符号文件路径/时间戳 + 陈旧告警（反馈②）")
    st = await call(server, "get_status")
    check("B1 get_status 带当前符号文件路径",
          st.get("symbol_file") and os.path.samefile(st["symbol_file"], tmp_axf),
          st.get("symbol_file"))
    check("B2 get_status 带符号文件时间戳（数值 + 可读文本）",
          isinstance(st.get("symbol_mtime"), float) and bool(st.get("symbol_mtime_text")), st)
    check("B3 get_status 带串行化视图（serialization）",
          isinstance(st.get("serialization"), dict)
          and "in_process" in st["serialization"], st.get("serialization"))
    check("B4 未进调试时不误报符号陈旧", st.get("symbol_stale") is False, st)

    await call(server, "enter_debug", {})
    st2 = await call(server, "get_status")
    check("B5 enter_debug 后记录调试会话符号基线（debug_session_symbol/since）",
          st2.get("debug_session_symbol") and st2.get("debug_session_since"), st2)

    # 模拟「编译/烧录后 .axf 被重新生成」
    t = time.time() + 30
    os.utime(tmp_axf, (t, t))
    st3 = await call(server, "get_status")
    check("B6 .axf 被重新生成后 get_status 报 symbol_stale",
          st3.get("symbol_stale") is True, st3)
    warn = st3.get("symbol_stale_warning") or ""
    check("B7 陈旧告警说清症状（status 13 解析错误）与处置（exit/enter 或 flash_debug）",
          "status 13" in warn and ("enter_debug" in warn and "flash_debug" in warn), warn)

    ce = await call(server, "calc_expression", {"expr": "no_such_var_b29"})
    check("B8 calc_expression 失败时附 symbol_stale_warning（不再让人猜别的原因）",
          not ce.get("ok") and "status 13" in (ce.get("symbol_stale_warning") or ""), ce)

    rv = await call(server, "read_variable", {"name": "no_such_var_b29"})
    check("B9 read_variable 失败时同样附 symbol_stale_warning",
          not rv.get("ok") and "status 13" in (rv.get("symbol_stale_warning") or ""), rv)

    await call(server, "exit_debug", {})
    st4 = await call(server, "get_status")
    check("B10 exit_debug 后清空会话基线、不再误报陈旧",
          st4.get("debug_session_since") is None and st4.get("symbol_stale") is False, st4)


async def group_c_flash_and_write(server):
    print("C. write_mem 回读校验 + 烧录后旧调试会话处理（反馈①②③）")
    wr = await call(server, "write_mem",
                    {"addr": "0x20000100", "data_hex": "deadbeef"})
    check("C1 write_mem 默认回读校验：写入落地 verified=true + readback_hex",
          wr.get("ok") and wr.get("verified") is True
          and wr.get("readback_hex") == "deadbeef", wr)

    wr2 = await call(server, "write_mem",
                     {"addr": "0x20000104", "data_hex": "11223344", "verify": False})
    check("C2 verify=false 时 verified=null 并说明无法确认（保留旧行为可用）",
          wr2.get("ok") and wr2.get("verified") is None
          and "跳过回读校验" in (wr2.get("verify_note") or ""), wr2)

    # 模拟「写入被静默吞掉」：回读拿到与写入不同的内容
    orig_read = srv.UVClient.read_mem

    def tamper_read(self, addr, n):
        r = dict(orig_read(self, addr, n))
        if r.get("ok") and r.get("data_hex"):
            r["data_hex"] = "00" * n
        return r

    try:
        srv.UVClient.read_mem = tamper_read
        wr3 = await call(server, "write_mem",
                         {"addr": "0x20000108", "data_hex": "aabbccdd"})
        check("C3 回读不一致时 verified=false 且点明没真正落地（含三类原因）",
              wr3.get("ok") and wr3.get("verified") is False
              and "没有真正落地" in (wr3.get("verify_note") or "")
              and "并发" in (wr3.get("warning") or ""), wr3)
    finally:
        srv.UVClient.read_mem = orig_read

    client = srv._get_client()
    # ---- 未调试态：不折腾，也不误报 ----
    out0 = srv._post_flash_debug_state(client, do_exit=True)
    check("C4 烧录前未处于调试态：debug_session 说明无旧符号残留",
          out0.get("debugging_before") is False and "未处于调试态" in (out0.get("note") or ""),
          out0)

    # ---- 调试态 + 保留会话：必须显式提示符号已过期 ----
    await call(server, "enter_debug", {})
    out1 = srv._post_flash_debug_state(client, do_exit=False)
    check("C5 exit_debug_after=false：保留会话但显式警告符号已过期",
          out1.get("debugging_before") is True and out1.get("exited_debug") is False
          and "符号已过期" in (out1.get("note") or "")
          and "status 13" in (out1.get("note") or ""), out1)

    # ---- 调试态 + 自动退出：默认行为 ----
    out2 = srv._post_flash_debug_state(client, do_exit=True)
    check("C6 exit_debug_after=true（默认）：自动退出调试以刷新符号",
          out2.get("exited_debug") is True
          and (out2.get("exit_debug") or {}).get("ok") is True, out2)
    check("C7 自动退出后说明如何重新加载符号（enter_debug / flash_debug）",
          "enter_debug" in (out2.get("note") or "")
          and "flash_debug" in (out2.get("note") or ""), out2.get("note"))

    # ---- 工具层接线：flash_download 必须带出 debug_session ----
    orig_flash = srv.builder.flash_download
    orig_baf = srv.builder.build_and_flash
    try:
        srv.builder.flash_download = lambda *a, **k: {"ok": True, "flash": "stub"}
        srv.builder.build_and_flash = lambda *a, **k: {"ok": True, "build": "stub",
                                                       "flash": "stub"}
        await call(server, "enter_debug", {})
        r = await call(server, "flash_download",
                       {"project": _PROJ, "exit_debug_after": False})
        check("C8 flash_download 返回 debug_session（并透传 exit_debug_after）",
              (r.get("debug_session") or {}).get("exit_debug_after") is False
              and (r.get("debug_session") or {}).get("debugging_before") is True, r)
        r2 = await call(server, "build_and_flash", {"project": _PROJ})
        check("C9 build_and_flash 默认自动退出调试并给出 debug_session",
              (r2.get("debug_session") or {}).get("exited_debug") is True, r2)
        r3 = await call(server, "flash_download", {"project": _PROJ})
        check("C10 烧录后 get_status 的 last_firmware_event 记录本次固件更换",
              (r3.get("debug_session") or {}).get("checked") is True
              and (await call(server, "get_status")).get("last_firmware_event"), r3)
    finally:
        srv.builder.flash_download = orig_flash
        srv.builder.build_and_flash = orig_baf


def group_d_serial():
    print("D. 串口日志监听（ring buffer + 增量读）")
    rb = serialmon.RingBuffer(capacity=3)
    for i in range(5):
        rb.append({"seq": i, "text": "L%d" % i})
    st = rb.stats()
    check("D1 ring buffer 超容量丢最旧行并计入 dropped",
          st["size"] == 3 and st["dropped"] == 2 and st["first_seq"] == 2
          and st["next_seq"] == 5, st)
    r = rb.read(max_items=10)
    check("D2 read 返回 items/count/next_seq/first_seq",
          r["count"] == 3 and [x["text"] for x in r["items"]] == ["L2", "L3", "L4"]
          and r["next_seq"] == 5, r)
    r2 = rb.read(since=4)
    check("D3 since 增量读只返回新行（配合 next_seq 不重复）",
          [x["text"] for x in r2["items"]] == ["L4"], r2)

    m = serialmon.SerialMonitor("COM_FAKE_B29", baud=115200, capacity=10)
    m.feed(b"hello\r\nworld\npart")
    check("D4 行切分：\\r\\n 与 \\n 都算换行，未满一行留 partial",
          [x.get("text") for x in m.read().get("items")] == ["hello", "world"]
          and m.partial == "part", m.read())
    m.feed(b"ial tail\n")
    items = m.read().get("items")
    check("D5 后续数据补齐半行并入 buffer（part + ial tail）",
          [x.get("text") for x in items] == ["hello", "world", "partial tail"], items)
    n = m.read(clear=True)["count"]
    check("D6 clear=true 读后清空（buffer 归零、seq 不回退）",
          n == 3 and m.read()["count"] == 0, m.read())
    stt = m.status()
    check("D7 status 暴露 state/bytes_total/lines/reopen_count/last_error 等",
          stt["bytes_total"] == 26 and stt["lines"] == 0 and stt["state"] == "stopped", stt)


async def group_d_tools(server):
    tools = await server.list_tools()
    names = [t.name for t in tools]
    for nm in ("serial_monitor_start", "serial_read",
               "serial_monitor_status", "serial_monitor_stop"):
        check("D8 工具已注册：%s" % nm, nm in names)
    check("D9 工具总数 77→174（批次29 串口 4 + 批次30 加 2 + 批次32 加 2 + 批次35 加 10 + 批次34 加 1 + 批次36 非MDK族 46 + 批次40 rtos 3 + 批次42 toolset 1）", len(names) == 174, len(names))

    st = await call(server, "serial_monitor_status")
    check("D10 无监听时 status 不报错（ok=true、running=false、附可用串口）",
          st.get("ok") is True and st.get("running") is False
          and "available_ports" in st, st)

    rd = await call(server, "serial_read", {})
    check("D11 无监听时 read 明确失败并指路（先 start）",
          rd.get("ok") is False and "serial_monitor_start" in (rd.get("hint") or ""), rd)

    sp = await call(server, "serial_monitor_stop", {})
    check("D12 无监听时 stop 幂等返回（不报错）", sp.get("ok") is True, sp)

    # 不存在的端口：必须 ok=false 且给出 last_error（不能静默失败）
    bad = await call(server, "serial_monitor_start", {"port": "COM199", "baud": 115200})
    check("D13 打不开的端口：ok=false + last_error + 可用端口清单（不静默失败）",
          bad.get("ok") is False and bool(bad.get("last_error"))
          and "available_ports" in bad, bad)
    serialmon.stop_monitor()

    # 注入假 monitor（不真开串口）→ 验证工具层增量读接线
    fake = serialmon.SerialMonitor("COM_FAKE_B29", capacity=10)
    fake.feed(b"boot\nRT-Thread\n")
    serialmon._monitor = fake
    try:
        r1 = await call(server, "serial_read", {})
        check("D14 serial_read 读到行（lines 直接是文本数组，便于阅读）",
              r1.get("ok") is not False and r1.get("lines") == ["boot", "RT-Thread"], r1)
        fake.feed(b"tick 1\ntick 2\n")
        r2 = await call(server, "serial_read", {"since": r1.get("next_seq")})
        check("D15 增量读：传上次 next_seq 只拿新行、不重复",
              r2.get("lines") == ["tick 1", "tick 2"], r2)
        b1 = await one(server, "serial_monitor_status", {})
        d1 = await call(server, "serial_monitor_status")
        check("D16 batch 内调 serial_monitor_status 与直调一致（入口一致性回归）",
              b1.get("bytes_total") == d1.get("bytes_total")
              and b1.get("running") == d1.get("running"), {"b": b1, "d": d1})
    finally:
        serialmon._monitor = None


def _fake_running_monitor(port="COM_FAKE_B29R", lines=("boot ok", "wdt reset"),
                          idle_release_s=900.0):
    """造一个「正占着串口」的假监听（不真开 COM 口），用于验证释放链路。"""
    m = serialmon.SerialMonitor(port, baud=115200, capacity=50,
                                idle_release_s=idle_release_s)
    for ln in lines:
        m.feed((ln + "\n").encode("utf-8"))
    m.state = "running"
    m.started_at = time.time()
    m.last_access = time.time()
    serialmon._monitor = m
    return m


def group_e_release():
    print("E. 串口「用完就还」：释放端口但保留已收日志（用户第 14 条反馈）")
    # ---- 空闲超时自动释放 ----
    m = serialmon.SerialMonitor("COM_FAKE_B29E", capacity=20, idle_release_s=0.3)
    m.feed(b"A\nB\nC\n")
    m.state = "running"
    m.started_at = time.time()
    m.last_access = time.time()
    check("E1 占用中 port_held=true 且未标记释放",
          m.status()["port_held"] is True and m.status()["auto_released"] is False,
          m.status())
    m.last_access -= 5.0                      # 假装 5 秒没访问
    st = m.status()
    check("E2 空闲超时（idle_release_s）自动释放端口，release_reason 说明原因",
          st["port_held"] is False and st["auto_released"] is True
          and "空闲" in st["release_reason"], st)
    check("E3 释放后已收日志仍在（ring buffer 不随释放清空）+ release_note 指路",
          st["lines"] == 3 and "仍保留" in (st.get("release_note") or "")
          and "serial_monitor_start" in (st.get("release_note") or ""), st)
    r = m.read()
    check("E4 释放后 serial_read 仍能读到释放前的行（reading 不受释放影响）",
          r["count"] == 3 and r["lines"] == ["A", "B", "C"] and r["port_held"] is False
          and "仍保留" in (r.get("release_note") or ""), r)

    # ---- 重新 start 复用同一实例：不丢已收日志 ----
    serialmon._monitor = m          # 把上面这个「已释放但仍留存日志」的实例登记为当前监听
    st2 = serialmon.start_monitor("COM_FAKE_B29E", baud=115200, idle_release_s=0)
    check("E5 重新 start 复用被释放的同一实例（resumed=true）且日志不丢",
          st2.get("resumed") is True and st2.get("lines") == 3
          and serialmon.current().read()["count"] == 3, st2)
    st3 = serialmon.stop_monitor()
    check("E6 显式 stop 释放端口但保留日志（release_note 指路）",
          st3.get("ok") is True and st3.get("released") is True
          and st3.get("lines") == 3 and "仍保留" in (st3.get("note") or ""), st3)
    st4 = serialmon.stop_monitor()
    check("E7 stop 幂等：再次 stop 仍 ok=true、running=false，日志仍在",
          st4.get("ok") is True and st4.get("running") is False
          and st4.get("lines") == 3, st4)
    st5 = serialmon.stop_monitor(clear_buffer=True)
    check("E8 clear_buffer=true 才清空缓存（默认保留）",
          st5.get("ok") is True and serialmon.has_monitor() is False, st5)

    # ---- 无监听时是 no-op，不打扰主流程 ----
    serialmon._monitor = None
    noop = serialmon.release_monitor("无监听")
    check("E9 无监听时释放是 no-op（ok=true、released=false）",
          noop.get("ok") is True and noop.get("released") is False, noop)
    check("E10 _release_serial 在无监听时返回 {}（不给调用方加噪声字段）",
          srv._release_serial("无监听") == {}, srv._release_serial("无监听"))

    # ---- 进程退出兜底 ----
    m = _fake_running_monitor()
    serialmon._release_on_exit()
    check("E11 进程退出钩子（atexit）会把占着的串口释放掉，日志保留",
          m.state == "stopped" and m.auto_released is True
          and m.read()["count"] == 2 and "进程退出" in m.release_reason,
          m.status())
    serialmon._monitor = None


async def group_e_lifecycle(server):
    print("E. 调试生命周期触发释放（exit_debug / 烧录 / 关 Keil / 重启 Keil）")

    # ---- exit_debug 成功 → 释放 ----
    m = _fake_running_monitor()
    r = await call(server, "exit_debug", {})
    check("E12 exit_debug 成功时顺带释放串口（返回 serial_release，日志保留）",
          r.get("ok") is True and (r.get("serial_release") or {}).get("released") is True
          and m.state == "stopped" and m.read()["count"] == 2, r)
    check("E13 释放提示写明「日志仍保留」并给出继续采集的办法",
          "仍保留" in ((r.get("serial_release") or {}).get("release_note") or "")
          and "serial_monitor_start" in
          ((r.get("serial_release") or {}).get("release_note") or ""),
          r.get("serial_release"))

    # ---- 烧录：默认释放，显式关掉则保留 ----
    orig_flash = srv.builder.flash_download
    orig_close = srv.builder.close_uvision
    orig_baf = srv.builder.build_and_flash
    try:
        srv.builder.flash_download = lambda *a, **k: {"ok": True, "flash": "stub"}
        srv.builder.build_and_flash = lambda *a, **k: {"ok": True, "build": "stub",
                                                       "flash": "stub"}
        srv.builder.close_uvision = lambda **k: {"ok": True, "closed": []}

        m = _fake_running_monitor()
        r2 = await call(server, "flash_download", {"project": _PROJ})
        check("E14 flash_download 默认释放串口（release_serial 回执可见）",
              (r2.get("serial_release") or {}).get("released") is True
              and m.state == "stopped", r2.get("serial_release"))

        m = _fake_running_monitor()
        r3 = await call(server, "flash_download",
                        {"project": _PROJ, "release_serial": False})
        check("E15 release_serial=false 时保留占用（想边烧录边看日志的场合）",
              not (r3.get("serial_release") or {}).get("released")
              and m.state != "stopped", r3.get("serial_release"))

        m = _fake_running_monitor()
        r4 = await call(server, "build_and_flash", {"project": _PROJ})
        check("E16 build_and_flash 同样默认释放串口",
              (r4.get("serial_release") or {}).get("released") is True
              and m.state == "stopped", r4.get("serial_release"))

        m = _fake_running_monitor()
        r5 = await call(server, "close_uvision", {})
        check("E17 close_uvision 后串口不再被占（Keil 串口窗口要能打开）",
              r5.get("ok") is True
              and (r5.get("serial_release") or {}).get("released") is True
              and m.state == "stopped", r5.get("serial_release"))

        # ---- restart_keil（把外部副作用全 stub 掉） ----
        orig_uv4 = srv._builder_cfg.get("uv4")
        orig_wait = srv.winutil.wait_uv4_exit
        orig_launch = srv.builder.launch_uvision
        orig_waitport = srv.winutil.wait_port_listening
        orig_health = srv.winutil.keil_health
        orig_pids = srv.winutil.uv4_pids
        orig_reset = srv.UVClient.reset_connection
        try:
            srv._builder_cfg["uv4"] = "stub-uv4"
            srv.winutil.wait_uv4_exit = lambda timeout=0: {"ok": True}
            srv.builder.launch_uvision = lambda *a, **k: {"ok": True}
            srv.winutil.wait_port_listening = lambda port, timeout=0: {"ok": True}
            srv.winutil.keil_health = lambda port, **k: {
                "uvsock_ready": True, "keil_alive": True, "port_listening": True,
                "diagnosis": "", "suggestion": ""}
            srv.winutil.uv4_pids = lambda: []
            srv.UVClient.reset_connection = lambda self, **k: {"ok": True}
            m = _fake_running_monitor()
            r6 = await call(server, "restart_keil", {"project": _PROJ})
            check("E18 restart_keil 后串口被释放（新实例要能开这个口）",
                  r6.get("ok") is True
                  and (r6.get("serial_release") or {}).get("released") is True
                  and m.state == "stopped", r6.get("serial_release") or r6)
        finally:
            srv._builder_cfg["uv4"] = orig_uv4
            srv.winutil.wait_uv4_exit = orig_wait
            srv.builder.launch_uvision = orig_launch
            srv.winutil.wait_port_listening = orig_waitport
            srv.winutil.keil_health = orig_health
            srv.winutil.uv4_pids = orig_pids
            srv.UVClient.reset_connection = orig_reset
    finally:
        srv.builder.flash_download = orig_flash
        srv.builder.build_and_flash = orig_baf
        srv.builder.close_uvision = orig_close
        serialmon._monitor = None

    # ---- 工具面：参数可见、描述讲清「用完就还」 ----
    tools = {t.name: t for t in await server.list_tools()}
    props = ((tools.get("serial_monitor_start").input_schema or {}).get("properties") or {})
    check("E19 serial_monitor_start 暴露 idle_release_s 参数（可调空闲自动释放）",
          "idle_release_s" in props, list(props))
    props2 = ((tools.get("serial_monitor_stop").input_schema or {}).get("properties") or {})
    check("E20 serial_monitor_stop 暴露 clear_buffer 参数（默认保留日志）",
          "clear_buffer" in props2, list(props2))
    desc_start = tools.get("serial_monitor_start").description or ""
    desc_exit = tools.get("exit_debug").description or ""
    desc_stop = tools.get("serial_monitor_stop").description or ""
    check("E21 描述里讲明「释放端口但保留日志」与「哪些操作会自动释放」",
          "仍保留" in desc_start and "exit_debug" in desc_start
          and "保留" in desc_stop and "clear_buffer" in desc_stop, desc_stop[:60])
    check("E22 exit_debug 描述里点明会顺带释放串口（不必翻文档才知道）",
          "释放" in desc_exit and "串口" in desc_exit, desc_exit[:80])


async def main():
    tmpdir = tempfile.mkdtemp(prefix="mdkdebug_b29_")
    tmp_axf = os.path.join(tmpdir, "b29.axf")
    have_axf = os.path.isfile(_AXF)
    if have_axf:
        shutil.copy2(_AXF, tmp_axf)

    srv._debug_session.update({"axf": None, "mtime": None, "mtime_text": None,
                               "since": None, "reason": None})
    srv._firmware_events.clear()

    srv_obj = MockUVSOCKServer("127.0.0.1", PORT).start()
    # mock 的 UV_DBG_STATUS 默认恒返回成功（等价"永远在调试"），无法验证退出会话后的
    # 行为。改写为"不在调试态则回 status=6 Target is not in debug mode"，与真机一致。
    _orig_dispatch = srv_obj._dispatch

    def _dispatch_realistic(cmd, data):
        if cmd == uvproto.UV_DBG_STATUS and not srv_obj.debugging:
            body = b"Target is not in debug mode\x00"
            return uvproto.UV_STATUS_NOT_DEBUGGING, struct.pack("<i", len(body)) + body
        return _orig_dispatch(cmd, data)

    srv_obj._dispatch = _dispatch_realistic
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=tmp_axf if have_axf else None)

    g2 = group_a_guard()

    if have_axf:
        await group_b_symbol(server, tmp_axf)
    else:
        print("  [SKIP] B 组：仓库内未找到 .axf")

    await group_c_flash_and_write(server)
    await call(server, "exit_debug", {})

    group_d_serial()
    await group_d_tools(server)

    group_e_release()
    await group_e_lifecycle(server)

    srv_obj.stop()
    shutil.rmtree(tmpdir, ignore_errors=True)

    # A 组若在 B/C 之前抛错，仍要保证无残留
    if g2 is not None:
        g2._release_file_lock()

    print("\n==== 批次29 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
