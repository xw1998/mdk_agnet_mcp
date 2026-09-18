# -*- coding: utf-8 -*-
"""批次30 mock 测试：读内存脏读防护 / 停止确证 / 故障位时效 / 复位语义 / 串口下发。

用户反馈原文（第 15 轮复验）：
    ① 「read_mem 没有脏读防护。stop 之后紧跟的第一次读，两次都返回整帧全 0
       （0x08022000 读出 16 个 00），重读即正确。get_current_location 已经为 PC 做了
       收敛判定，read_mem 没有——这会直接导致"读到 0 就下结论"的误判」
    ② 「stop 与 get_status 竞争。batch 里 stop 回 ok，紧接着的 get_status 仍报"执行中"。
       run_timeout 内部有 wait_stopped 确认，单独 stop 没有等价字段」
    ③ 「fault_report 的 CFSR 是粘滞位，且没有"时效/来源"提示……差点当成当前故障；
       实际更像历史残留位。建议给出 first_seen/last_cleared 之类，或明确标注"粘滞，可能来自更早的异常"」
    ④ 「reset 的行为与描述不符。描述说"复位后程序从复位向量重新运行"，实测复位后 get_status 是
       已停止，必须再 run 才有串口输出……建议改为"复位后停在复位向量，需再 run"」
    ⑤ 「我需要一边收一边发（shell 命令 + 下发镜像），只有读能力的监听器覆盖不了这个用法」

  A client.read_mem_verified：脏读判定逻辑（纯逻辑，monkeypatch 读数序列）
  B server read_mem：verify 参数透传与真机路径
  C stop：停止确证字段与「没能确证」的告警
  D fault_report：粘滞位标注 + 时效判定 + clear_faults
  E reset：行为描述对齐 + run_after
  F 串口下发：HostSerial/SerialMonitor 写能力 + serial_write 工具
  G 工具面：注册与工具总数

运行：python -m tests.test_batch30
"""
import os
import sys
import json
import time
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b30")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import serialmon  # noqa: E402
from mdkdebug import client as uvclient  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug import uvsock as uvproto  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14903
PASS, FAIL = [], []

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

# ----------------------------------------------------------------------
# A. client.read_mem_verified（纯逻辑，读数序列可控）
# ----------------------------------------------------------------------
def _mk_client(seq):
    """构造一个 UVClient（不真连），read_mem 依次吐出 seq 里的字节串。"""
    c = uvclient.UVClient(host="127.0.0.1", port=PORT)
    calls = []
    items = list(seq)

    def fake_read_mem(addr, n):
        calls.append((addr, n))
        item = items.pop(0) if items else b"\x00" * n
        if isinstance(item, dict):
            return item
        return {"status": 0, "ok": True, "addr": addr, "n_bytes": n,
                "data_hex": item.hex(), "ascii": ""}

    c.read_mem = fake_read_mem
    c._last_stop_obs_ts = 0.0        # 默认「很久没 stop 过」
    return c, calls

def group_a_read_verified():
    print("A. read_mem 脏读防护（反馈①）")

    # A1 正常数据 + 无近期 stop → 不复读（不做无条件双倍开销）
    good = bytes(range(16))
    c, calls = _mk_client([good])
    r = c.read_mem_verified(0x20000000, 16)
    check("A1 数据正常且无近期 stop：不复读、confidence=high、verify 回显",
          len(calls) == 1 and r["reread_count"] == 0
          and r["read_confidence"] == "high" and r["verify"] == "auto"
          and r["data_hex"] == good.hex() and "warning" not in r, r)

    # A2 首帧整帧全 0（真机现象）→ 复读替换，留证 first_read_hex
    c, calls = _mk_client([b"\x00" * 16, good, good])
    r = c.read_mem_verified(0x20000000, 16)
    check("A2 首帧整帧全 0：自动复读、连续两次一致才采纳",
          len(calls) == 3 and r["reread_count"] == 2
          and r["reread_consistent"] is True and r["read_confidence"] == "high", r)
    check("A3 首帧脏值留证：data_hex 换成可靠值、first_read_hex 记原值、warning 说明已替换",
          r["data_hex"] == good.hex() and r.get("first_read_hex") == ("00" * 16)
          and "脏" in (r.get("warning") or "") and "degenerate" not in r, r)

    # A4 Flash 区段全 0 的专门提示
    c, _ = _mk_client([b"\x00" * 16] * 3)
    r = c.read_mem_verified(0x08022000, 16)
    check("A4 Flash 区段读出全 0（已擦除应为 0xFF）：持退化标记 + 专门提示 + 降级",
          r.get("degenerate") == "all_zero" and "Flash" in (r.get("degenerate_note") or "")
          and r["read_confidence"] == "low" and "仍然" in (r.get("warning") or "")
          or (r.get("degenerate") == "all_zero"
              and "Flash" in (r.get("degenerate_note") or "")
              and r["read_confidence"] == "low"), r)

    # A5 整帧全 0xFF
    c, _ = _mk_client([b"\xff" * 16] * 3)
    r = c.read_mem_verified(0x20000100, 16)
    check("A5 整帧全 0xFF 同样识别为退化", r.get("degenerate") == "all_ff", r)

    # A6 verify=false：不复读，且明确说结果不可信
    c, calls = _mk_client([b"\x00" * 16] * 3)
    r = c.read_mem_verified(0x20000000, 16, verify="false")
    check("A6 verify=false 关闭复读（1 次读），但仍提示不可信",
          len(calls) == 1 and r["verify"] == "false" and r["reread_count"] == 0
          and r["read_confidence"] == "low" and "verify" in (r.get("warning") or ""), r)

    # A7 verify=true：即使数据正常也强制确认
    c, calls = _mk_client([good, good])
    r = c.read_mem_verified(0x20000000, 16, verify="true")
    check("A7 verify=true 无条件复读（数据正常也确认）",
          len(calls) == 2 and r["reread_count"] == 1 and r["reread_consistent"] is True
          and r["read_confidence"] == "high", r)

    # A8 刚 stop 过（<1s）→ 即使数据正常也复读
    c, calls = _mk_client([good, good])
    c._last_stop_obs_ts = time.time()
    r = c.read_mem_verified(0x20000000, 16)
    check("A8 距最近一次 stop 不足 1 秒：自动复读（since_stop_s 透出）",
          len(calls) == 2 and r["reread_count"] == 1
          and isinstance(r.get("since_stop_s"), float) and r["since_stop_s"] < 1.0, r)

    # A9 读数一直变 → 不可信（用 verify=true 强制进入复读路径：
    # auto 只在「退化帧 / 刚 stop 过」时才复读，非退化的静默错值需显式要求确认）
    c, calls = _mk_client([b"\x11" * 16, b"\x22" * 16, b"\x33" * 16])
    r = c.read_mem_verified(0x20000000, 16, verify="true")
    check("A9 复读三次都不一致：confidence=low 且明确「不要据此下结论」",
          r["reread_consistent"] is False and r["read_confidence"] == "low"
          and "不可信" in (r.get("warning") or "") and len(calls) == 3, r)

    # A10 首读失败 → 原样透出
    c, calls = _mk_client([{"status": 1, "ok": False, "status_text": "读取失败",
                            "addr": 0, "n_bytes": 16, "data_hex": "", "ascii": ""}])
    r = c.read_mem_verified(0x20000000, 16)
    check("A10 首读失败时原样透出（不进入复读）",
          r["ok"] is False and r["read_confidence"] == "low" and len(calls) == 1, r)

    # A11 verify 别名归一化
    c, _ = _mk_client([good, good])
    r1 = c.read_mem_verified(0x20000000, 16, verify="off")
    c, _ = _mk_client([good, good])
    r2 = c.read_mem_verified(0x20000000, 16, verify="always")
    check("A11 verify 别名归一化（off→false / always→true）",
          r1["verify"] == "false" and r2["verify"] == "true", (r1["verify"], r2["verify"]))

async def group_b_server_read(server):
    print("B. server read_mem 的 verify 透传（反馈①）")
    await call(server, "enter_debug", {})
    await call(server, "stop", {})

    c, _ = _mk_client([b"deadbeef" * 4, b"deadbeef" * 4])
    await call(server, "write_mem", {"addr": "0x20000100", "data_hex": "deadbeefcafebabe"})
    r = await call(server, "read_mem", {"addr": "0x20000100", "n_bytes": 8})
    check("B1 默认 verify=auto，返回带 read_confidence/reread_count",
          r.get("verify") == "auto" and r.get("read_confidence") in ("high", "low")
          and "reread_count" in r and r.get("data_hex", "").startswith("deadbeef"), r)

    r = await call(server, "read_mem", {"addr": "0x20000100", "n_bytes": 8,
                                        "verify": "false"})
    check("B2 verify=false 透传到 client（不复读）",
          r.get("verify") == "false" and r.get("reread_count") == 0, r)

    r = await call(server, "read_mem", {"addr": "0x20000200", "n_bytes": 16})
    check("B3 未初始化区读出整帧全 0：给出 degenerate 与 low 置信度（挡住「读到 0 就下结论」）",
          r.get("ok") and r.get("degenerate") == "all_zero"
          and r.get("read_confidence") == "low", r)

async def group_c_stop(server):
    print("C. stop 的停止确证（反馈②）")
    await call(server, "run", {})
    r = await call(server, "stop", {})
    check("C1 stop 默认确证：返回 stopped / stop_verified / waited_ms / state_after_stop",
          r.get("ok") and r.get("stop_verified") is True and r.get("stopped") is True
          and isinstance(r.get("waited_ms"), int)
          and r.get("state_after_stop") == "stopped", r)

    r = await call(server, "stop", {"verify": False})
    check("C2 verify=false 只发命令不做确认（不出现 stop_verified）",
          r.get("ok") and "stop_verified" not in r and "waited_ms" not in r, r)

    # 模拟真机异步滞后：stop 响应照回，但目标仍在运行
    srv_obj = srv._SERVER_LOCK_OBJ if False else None  # noqa: F841
    return None

async def group_c_stop_ignores(server, mock):
    mock.running = True
    mock.stop_ignores = True
    try:
        r = await call(server, "stop", {})
        check("C3 stop 未被确证时如实报 stop_verified=false 并给出告警（不假装停成功）",
              r.get("ok") and r.get("stop_verified") is False
              and r.get("state_after_stop") == "running"
              and "未确证" in (r.get("warning") or ""), r)
    finally:
        mock.stop_ignores = False
        mock.running = False
    r = await call(server, "stop", {})
    check("C4 恢复同步停止后 stop_verified 恢复为 true", r.get("stop_verified") is True, r)

async def group_d_fault(server, mock):
    print("D. fault_report 粘滞位时效 + clear_faults（反馈③）")

    # 当前正处在 HardFault handler 里 → current
    mock.scb.update({"icsr": 0x3, "cfsr": 0x2000000, "hfsr": 0x40000000})
    srv._FAULT_TRACK.update({"cfsr_first_seen": None, "cfsr_last_seen": None,
                             "cfsr_last_value": 0, "hfsr_last_value": 0,
                             "last_cleared": None})
    r = await call(server, "fault_report")
    check("D1 ICSR 处于 fault handler：timeliness=current（可直接当作本次故障）",
          r.get("fault_timing", {}).get("timeliness") == "current"
          and "当前故障" in (r["fault_timing"].get("note") or ""), r.get("fault_timing"))

    check("D2 CFSR 标注为粘滞位（sticky=true + 说明）",
          r.get("cfsr", {}).get("sticky") is True
          and "粘滞" in (r["cfsr"].get("sticky_note") or ""), r.get("cfsr"))

    check("D3 fault_timing 给出 first_seen/last_seen/last_cleared 追踪字段",
          r["fault_timing"].get("first_seen") and r["fault_timing"].get("last_seen")
          and "last_cleared" in r["fault_timing"], r.get("fault_timing"))

    # ICSR 不在 fault handler，但粘滞位置着 → sticky（反馈原场景）
    mock.scb["icsr"] = 0x0
    r = await call(server, "fault_report")
    ft = r.get("fault_timing", {})
    check("D4 ICSR 不在 fault handler：timeliness=sticky 且明确「不能当作当前故障」",
          ft.get("timeliness") == "sticky" and "不能当作当前故障" in (ft.get("note") or ""), ft)
    check("D5 sticky 时给出可执行的 hint（先 clear_faults 再复现）",
          "clear_faults" in (r.get("hint") or ""), r.get("hint"))

    # clear_faults：W1C 清位
    r = await call(server, "clear_faults", {})
    check("D6 clear_faults 清位成功（before 非 0、after=0、cleared 均为 true）",
          r.get("ok") and r.get("before", {}).get("cfsr") not in (None, "0x00000000")
          and r.get("after", {}).get("cfsr") == "0x00000000"
          and r.get("after", {}).get("hfsr") == "0x00000000"
          and r.get("cleared", {}).get("cfsr") is True, r)

    r2 = await call(server, "fault_report")
    check("D7 清位后 fault_report 不再报故障（timeliness=none、cfsr 为 0）",
          r2.get("fault_timing", {}).get("timeliness") == "none"
          and r2.get("cfsr", {}).get("value") == "0x00000000", r2.get("fault_timing"))

    check("D8 clear_faults 记录 last_cleared（供后续 fault_report 判断时效）",
          bool(srv._FAULT_TRACK.get("last_cleared"))
          and srv._FAULT_TRACK.get("cfsr_first_seen") is None,
          srv._FAULT_TRACK)

    # 清位后重新置位 → 归为「新发生」
    mock.scb["cfsr"] = 0x10000
    mock.scb["icsr"] = 0x0
    r3 = await call(server, "fault_report")
    check("D9 清位后再置位：first_seen 重新计时（与上一次 clear 可区分）",
          r3.get("fault_timing", {}).get("first_seen") is not None
          and r3.get("cfsr", {}).get("value") == "0x00010000", r3.get("fault_timing"))
    mock.scb.update({"icsr": 0x3, "cfsr": 0x2000000, "hfsr": 0x40000000})

async def group_e_reset(server, mock):
    print("E. reset 行为对齐描述（反馈④）")
    from mdkdebug.server import create_server as _cs  # noqa: F401
    tools = {t.name: t for t in await server.list_tools()}
    desc = tools["reset"].description or ""
    check("E1 reset 描述改为「复位后停在复位向量、处于停止态，需再 run」",
          "停在复位向量" in desc and "run" in desc and "重新运行" not in desc, desc[:200])

    await call(server, "run", {})
    r = await call(server, "reset", {})
    check("E2 reset 返回 state_after_reset=stopped + stopped_after_reset + hint",
          r.get("ok") and r.get("state_after_reset") == "stopped"
          and r.get("stopped_after_reset") is True
          and "停在复位向量" in (r.get("hint") or ""), r)

    st = await call(server, "get_status", {})
    check("E3 reset 之后 get_status 确实是「已停止」（与描述一致）",
          st.get("running") is False, st)

    r = await call(server, "reset", {"run_after": True})
    check("E4 run_after=true：复位后自动 run（ran=true + hint 说明）",
          r.get("ok") and r.get("ran") is True
          and "run_after" in (r.get("hint") or ""), r)
    st = await call(server, "get_status", {})
    check("E5 run_after=true 之后目标确实在运行", st.get("running") is True, st)
    await call(server, "stop", {})

# ----------------------------------------------------------------------
# F. 串口下发
# ----------------------------------------------------------------------
class FakeDev:
    """假串口设备：记录写入内容，并把预设回显喂回监听器（模拟目标回显）。"""

    def __init__(self, monitor, reply=b"", can_write=True):
        self.monitor = monitor
        self.reply = reply
        self.sent = []
        self.can_write = can_write

    def write(self, data):
        if not self.can_write:
            raise OSError("串口以只读方式打开")
        self.sent.append(bytes(data))
        if self.reply:
            self.monitor.feed(self.reply)
        return len(data)

def _install_fake_monitor(reply=b"msh />help\r\n   commands: help/list/ps\r\n"):
    m = serialmon.SerialMonitor("COM_TEST", baud=115200)
    dev = FakeDev(m, reply=reply)
    m._set_dev(dev)
    m.state = "running"
    old = serialmon._monitor
    serialmon._monitor = m
    return m, dev, old

def _restore(old):
    serialmon._monitor = old

async def group_f_serial_write(server):
    print("F. 串口「一边收一边发」（反馈⑤）")

    # F1 HostSerial 具备写能力（未打开时报错而非静默）
    hs = serialmon.HostSerial("COM_TEST")
    check("F1 HostSerial 暴露 can_write 与 write（无第三方依赖的 ctypes 实现）",
          hasattr(hs, "can_write") and hs.can_write is False
          and callable(getattr(hs, "write", None)), vars(hs))
    blew = None
    try:
        hs.write(b"x")
    except OSError as e:
        blew = str(e)
    check("F2 未打开时 write 抛 OSError（不静默吞掉）", blew is not None, blew)

    # F3 SerialMonitor.write 无设备时不假装成功
    m = serialmon.SerialMonitor("COM_TEST", baud=115200)
    r = m.write(b"a")
    check("F3 SerialMonitor 未持有设备时 write 返回 ok=false + hint",
          r.get("ok") is False and "hint" in r and "未打开" in (r.get("error") or ""), r)

    # F4/F5/F6 假设备：下发文本 + 写后增量读回显
    mm, dev, old = _install_fake_monitor()
    try:
        mm.feed(b"boot ok\r\n")          # 先有一段"老日志"
        r = serialmon.write_bytes(b"help\r\n", wait_ms=0, read_after=False)
        check("F4 write_bytes 写入字节数正确、next_seq_before 为写前游标",
              r.get("ok") and r.get("written") == 6
              and r.get("bytes_sent") == 6
              and isinstance(r.get("next_seq_before"), int)
              and "since=" in (r.get("next_seq_hint") or ""), r)

        r = serialmon.write_bytes(b"help\r\n", wait_ms=0)
        ra = r.get("read_after") or {}
        check("F5 read_after 只带回「写之后新增」的行（不重复老日志）",
              ra.get("count") == 2 and ra.get("lines") == ["msh />help",
                                                           "   commands: help/list/ps"], ra)
        check("F6 回显行带 seq/next_seq，可直接作为下次 serial_read 的 since",
              isinstance(ra.get("next_seq"), int) and ra["next_seq"] > r["next_seq_before"],
              ra)

        # F7 假只读设备 → 明确报「发不出去」
        mm2 = serialmon.SerialMonitor("COM_TEST", baud=115200)
        mm2._set_dev(FakeDev(mm2, can_write=False))
        mm2.state = "running"
        serialmon._monitor = mm2
        r = serialmon.write_bytes(b"x", wait_ms=0)
        check("F7 端口只读（can_write=false）时给出明确错误而不是静默丢数据",
              r.get("ok") is False and "只读" in (r.get("error") or ""), r)
        check("F8 status 透出 can_write（供调用方判断这个口能不能发）",
              "can_write" in mm2._status_raw(), mm2._status_raw())
    finally:
        _restore(old)

    # F9 无监听时 write_bytes 指路
    old = serialmon._monitor
    serialmon._monitor = None
    try:
        r = serialmon.write_bytes(b"x", wait_ms=0)
        check("F9 没有监听时 ok=false，并提示先 serial_monitor_start",
              r.get("ok") is False and "serial_monitor_start" in (r.get("hint") or "")
              and "available_ports" in r, r)
        r = await call(server, "serial_write", {"text": "help"})
        check("F10 server serial_write 无监听时同样指路（不报异常）",
              r.get("ok") is False and "serial_monitor_start" in (r.get("hint") or ""), r)
    finally:
        serialmon._monitor = old

    # F11~F15 有假监听时的 server 工具路径
    mm, dev, old = _install_fake_monitor()
    try:
        r = await call(server, "serial_write", {"text": "help", "wait_ms": 0})
        ra = r.get("read_after") or {}
        check("F11 text 默认按 crlf 追加行尾（6 字节），并返回回显",
              r.get("ok") and r.get("written") == 6 and ra.get("count") == 2, r)
        check("F12 回显直接跟着返回（省掉再调一次 serial_read）",
              "commands: help/list/ps" in (ra.get("lines") or [""])[-1], ra)

        r = await call(server, "serial_write", {"text": "help", "eol": "lf", "wait_ms": 0})
        check("F13 eol=lf 只追加 \\n（5 字节）", r.get("written") == 5, r)
        r = await call(server, "serial_write", {"text": "help", "eol": "none", "wait_ms": 0})
        check("F14 eol=none 不追加行尾（4 字节）", r.get("written") == 4, r)

        r = await call(server, "serial_write", {"hex": "7e 01 00 ff", "wait_ms": 0})
        check("F15 hex 路径支持空格分隔、原样下发二进制（4 字节）",
              r.get("ok") and r.get("written") == 4 and dev.sent[-1] == b"\x7e\x01\x00\xff", r)

        r = await call(server, "serial_write", {})
        check("F16 text 与 hex 都不给时明确报参数不足",
              r.get("ok") is False and "参数不足" in (r.get("error") or ""), r)
        r = await call(server, "serial_write", {"hex": "zz9"})
        check("F17 hex 非法时给出解析错误（不抛异常）",
              r.get("ok") is False and "hex 解析失败" in (r.get("error") or ""), r)
    finally:
        _restore(old)

async def group_g_tools(server):
    print("G. 工具面")
    tools = {t.name: t for t in await server.list_tools()}
    for nm in ("clear_faults", "serial_write"):
        check("G1 工具已注册：%s" % nm, nm in tools)
    check("G2 工具总数 177（批次33 再 +3，批次35 +10，批次34 +1，批次36 +46，批次40 +3，批次42 +1）",
          len(tools) == 177, len(tools))
    d = tools["serial_write"].description or ""
    check("G3 serial_write 描述点明「一边收一边发」与依赖监听持口",
          "一边收一边发" in d and "serial_monitor_start" in d, d[:160])
    d = tools["fault_report"].description or ""
    check("G4 fault_report 描述点明粘滞位与确认新异常的做法",
          "粘滞" in d and "clear_faults" in d, d[:160])
    d = tools["stop"].description or ""
    check("G5 stop 描述点明「命令返回不代表已停」与 stop_verified",
          "stop_verified" in d and "异步" in d, d[:160])
    d = tools["read_mem"].description or ""
    check("G6 read_mem 描述点明脏读防护与 read_confidence",
          "脏读" in d and "read_confidence" in d, d[:160])


# ----------------------------------------------------------------------
# H. 真机复验暴露问题的修补回归（b30b）
# ----------------------------------------------------------------------
def group_h_tristate():
    print("H. verify 三态归一（真机传布尔被参数校验拒绝的修补）")
    nt = srv._norm_tristate
    check("H1 布尔/字符串 false 侧归一为 false（false/off/no/0）",
          nt(False) == "false" and nt("off") == "false" and nt("no") == "false"
          and nt("0") == "false", None)
    check("H2 布尔/字符串 true 侧归一为 true（true/on/yes/1）",
          nt(True) == "true" and nt("on") == "true" and nt("1") == "true", None)
    check("H3 auto/未识别/None 归一为 auto",
          nt("auto") == "auto" and nt(None) == "auto" and nt("whatever") == "auto", None)

def group_h_flash_ff():
    print("H. Flash 区全 0xFF 是「已擦除」的预期内容（真机误报 low 的修补）")
    c, _ = _mk_client([b"\xff" * 16] * 3)
    r = c.read_mem_verified(0x08022000, 16)
    check("H4 Flash 区稳定全 0xFF：confidence=high + content_note 说明是预期内容",
          r.get("read_confidence") == "high"
          and "预期内容" in (r.get("content_note") or "")
          and "warning" not in r, r)
    c, _ = _mk_client([b"\xff" * 16] * 3)
    r = c.read_mem_verified(0x2000F000, 16)
    check("H5 SRAM 区全 0xFF 仍按可疑处理（不误判成预期内容）",
          r.get("read_confidence") == "low" and not r.get("content_note"), r)

def group_h_serial_ready():
    print("H. start() 等端口就绪（真机 can_write 误报 false 的修补）")
    class _IdleDev(FakeDev):
        """打开后读线程会持续轮询——给个不产出数据的 read()，模拟真实串口的空读。"""
        def read(self):
            time.sleep(0.05)
            return b""

    m = serialmon.SerialMonitor("COM_TEST", baud=115200, idle_release_s=0)
    dev = _IdleDev(m)

    def slow_open():
        time.sleep(0.3)
        return dev

    m._open = slow_open
    t0 = time.time()
    st = m.start()
    dt = time.time() - t0
    check("H6 start() 等端口真正打开再返回（port_ready=true，耗时不小于 0.3s）",
          st.get("port_ready") is True and dt >= 0.28, {"st_port_ready": st.get("port_ready"),
                                                        "dt": round(dt, 2)})
    check("H7 就绪后 can_write 如实为真（不再误报「只能收不能发」）",
          st.get("can_write") is True, st)
    m.stop()
    nr = serialmon.SerialMonitor("COM_X", idle_release_s=0).wait_ready(timeout=0.3)
    check("H8 端口没打开时 wait_ready 不卡死，如实返回 port_ready=false",
          nr.get("port_ready") is False, nr)

async def group_h_server(server):
    print("H. 布尔 verify 走工具层 / fault_report 恒给 hfsr")
    r = await call(server, "read_mem", {"addr": "0x2000F000", "n_bytes": 8, "verify": False})
    check("H9 verify 传 JSON 布尔 false 不再被参数校验拒绝（真机 A5 复现点）",
          "_exc" not in r and r.get("verify") == "false", r)
    r = await call(server, "read_mem", {"addr": "0x2000F000", "n_bytes": 8, "verify": True})
    check("H10 verify 传布尔 true 归一为 true 并强制复读",
          r.get("verify") == "true" and r.get("reread_consistent") is True, r)
    fr = await call(server, "fault_report")
    check("H11 fault_report 是否置位都给 hfsr 字段（避免把「字段缺失」当成「读不到」）",
          isinstance(fr.get("hfsr"), dict) and "value" in (fr.get("hfsr") or {}), fr.get("hfsr"))
    st = await call(server, "get_status")
    check("H12 get_status 相关路径未受修补影响（工具连通）",
          "_exc" not in st, st)

async def main():
    srv._debug_session.update({"axf": None, "mtime": None, "mtime_text": None,
                               "since": None, "reason": None})
    srv._firmware_events.clear()

    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    _orig = mock._dispatch

    def _dispatch_realistic(cmd, data):
        if cmd == uvproto.UV_DBG_STATUS and not mock.debugging:
            body = b"Target is not in debug mode\x00"
            return uvproto.UV_STATUS_NOT_DEBUGGING, __import__("struct").pack("<i", len(body)) + body
        return _orig(cmd, data)

    mock._dispatch = _dispatch_realistic
    mock.stop_ignores = False
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0, axf_path=None)

    group_a_read_verified()

    try:
        await group_b_server_read(server)
        await call(server, "run", {})
        await group_c_stop(server)
        await group_c_stop_ignores(server, mock)
        await group_d_fault(server, mock)
        await group_e_reset(server, mock)
        await call(server, "stop", {})
        await group_f_serial_write(server)
        await group_g_tools(server)
        group_h_tristate()
        group_h_flash_ff()
        group_h_serial_ready()
        await group_h_server(server)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次30 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
