# -*- coding: utf-8 -*-
"""批次33 mock 测试：开源项目经验整合（能力缺口 + 统一契约）。

来源：docs/oss-absorption.md（对 keil-project-tools / embeddedskills / Serial-Agent /
Keil UVSC MCP 的逐项对照结论；SAP mdk-mcp-server 属误报，已排除）。

  A 串口枚举与选口：list_ports_detailed / pick_port / 芯片推断
  B serialmon.expect：只认新内容、半行命中、超时分类
  C server 工具：serial_list_ports / serial_expect / clean_project
  D builder：UV4 退出码完整表 + clean(-c) / rebuild(-cr) + metrics / artifacts
  E errors：统一信封（status / error_code / next_actions / risk）
  F 工具面：注册、总数、风险标注、示例参数

运行：python -m tests.test_batch33
"""
import os
import sys
import json
import time
import shutil
import asyncio
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b33")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import serialmon  # noqa: E402
from mdkdebug import builder  # noqa: E402
from mdkdebug import errors  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug import uvsock as uvproto  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14906
REAL_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvprojx")
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
# 假串口设备（与批次30 同一套手法）
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

def _feed_later(mon, data, delay=0.15):
    """等 expect 建立基线之后再喂数据（否则老日志语义测不出来）。"""
    def go():
        time.sleep(delay)
        mon.feed(data)
    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t

# ----------------------------------------------------------------------
# A. 串口枚举与选口
# ----------------------------------------------------------------------
def group_a_ports():
    print("A. 串口枚举与选口（吸收 embeddedskills / Serial-Agent 的选口 playbook）")

    p3 = [{"port": "COM3", "likely_chip": "CH340"},
          {"port": "COM9", "likely_chip": "DAPLink VCP"}]

    r = serialmon.pick_port("COM9", p3)
    check("A1 显式指定命中：source=explicit 且不标 auto",
          r["port"] == "COM9" and r["auto"] is False and r["need_choice"] is False
          and r["source"] == "explicit", r)
    r = serialmon.pick_port("9", p3)
    check("A2 显式指定容忍裸数字（9 → COM9）", r["port"] == "COM9", r)
    r = serialmon.pick_port("com9", p3)
    check("A3 显式指定容忍大小写", r["port"] == "COM9", r)

    r = serialmon.pick_port("COM7", p3)
    check("A4 显式指定的口不存在：不悄悄换一个，need_choice=true 且候选摊开",
          r["port"] == "" and r["need_choice"] is True
          and r["candidates"] == ["COM3", "COM9"] and "不在本机串口列表" in r["reason"], r)

    r = serialmon.pick_port("", [{"port": "COM9"}])
    check("A5 唯一候选才自动采用（auto=true）",
          r["port"] == "COM9" and r["auto"] is True
          and "已自动采用" in r["reason"], r)

    r = serialmon.pick_port("", p3)
    check("A6 多候选不替调用方决定：port 为空 + need_choice=true",
          r["port"] == "" and r["need_choice"] is True and r["auto"] is False
          and "多候选不自动选择" in r["reason"], r)

    r = serialmon.pick_port("", [])
    check("A7 无候选：不报异常，reason 说明未发现",
          r["port"] == "" and r["need_choice"] is False and "未发现" in r["reason"], r)

    # 芯片推断表（不依赖真机）
    check("A8 VID/PID 表命中常见桥片（CH340 / CP2102 / DAPLink / STM32 VCP）",
          serialmon._chip_from("USB VID_1A86&PID_7523", "").startswith("CH340")
          and serialmon._chip_from("USB VID_10C4&PID_EA60", "").startswith("CP2102")
          and serialmon._chip_from("VID_0D28&PID_0204", "") == "mbed / DAPLink VCP"
          and serialmon._chip_from("VID_0483&PID_5740", "").startswith("STM32"),
          [serialmon._chip_from(w, "") for w in
           ("USB VID_1A86&PID_7523", "USB VID_10C4&PID_EA60",
            "VID_0D28&PID_0204", "VID_0483&PID_5740")])
    check("A9 只认 VID/PID 后四位十六进制、形式宽容（大小写/位置）",
          serialmon._chip_from("usb vid_1a86&pid_7523 x", "").startswith("CH340")
          and serialmon._chip_from("VID_1A86&PID_7523", "").startswith("CH340"), None)
    check("A10 未收录的 VID/PID 明说是未收录（不冒充已知芯片）",
          serialmon._chip_from("VID_FFFF&PID_0001", "").startswith("未收录的 VID/PID"),
          serialmon._chip_from("VID_FFFF&PID_0001", ""))
    check("A11 无 VID/PID 时按描述关键词兜底、都没有则留空",
          serialmon._chip_from("", "USB-SERIAL CH340 (COM3)").startswith("CH340")
          and "CP210" in serialmon._chip_from("", "Silicon Labs CP210x")
          and serialmon._chip_from("", "some random name") == "", None)

    ports = serialmon.list_ports_detailed()
    check("A12 list_ports_detailed 返回结构化记录（port/description/vid/pid/likely_chip/source）",
          isinstance(ports, list)
          and all({"port", "description", "hwid", "vid", "pid", "likely_chip",
                   "source"} <= set(p) for p in ports), ports[:2])
    print("     本机串口：%s" % json.dumps(ports, ensure_ascii=False)[:300])

# ----------------------------------------------------------------------
# B. serialmon.expect（等待侧）
# ----------------------------------------------------------------------
def group_b_expect():
    print("B. serialmon.expect：只认新内容 / 半行命中 / 超时分类")

    # B0 无监听时指路，而不是静默等待
    old0 = serialmon._monitor
    serialmon._monitor = None
    try:
        r = serialmon.expect("x", timeout_s=0.2)
        check("B0 无监听：ok=false + hint 指向 serial_monitor_start + 附可用串口",
              r.get("ok") is False and r.get("matched") is False
              and "serial_monitor_start" in (r.get("hint") or "")
              and "available_ports" in r, r)
    finally:
        serialmon._monitor = old0

    mm, dev, old = _install_fake_monitor(reply=b"")
    try:
        # B0b 空 pattern：有监听时明确报参数不足（而不是干等满超时）
        r = serialmon.expect("", timeout_s=0.2)
        check("B0b 空 pattern：明确报参数不足", "参数不足" in (r.get("error") or ""), r)

        # B1 命中整行
        _feed_later(mm, b"msh />\r\n", 0.15)
        r = serialmon.expect("msh />", timeout_s=2.0, poll_ms=20)
        check("B1 命中等待期间新出现的整行（matched_source=line）",
              r.get("ok") and r.get("matched") and r.get("matched_source") == "line"
              and r.get("matched_line") == "msh />" and r.get("matched_text") == "msh />", r)
        check("B1b 命中带 port / next_seq / waited_ms / note（可回溯这次等了什么）",
              r.get("port") == "COM_TEST" and isinstance(r.get("next_seq"), int)
              and isinstance(r.get("waited_ms"), int) and "since=" in (r.get("note") or ""), r)

        # B2 捕获组
        _feed_later(mm, b"boot v1.2.3 ok\r\n", 0.15)
        r = serialmon.expect(r"boot v(\d+\.\d+\.\d+)", timeout_s=2.0, poll_ms=20)
        check("B2 正则捕获组透出 matched_group",
              r.get("matched") and r.get("matched_group") == "1.2.3", r)

        # B3 老日志不算命中（与 wait_breakpoint 同一口径）
        mm.feed(b"OLD_MARK: early log\r\n")
        t0 = time.time()
        r = serialmon.expect("OLD_MARK", timeout_s=0.4, poll_ms=20)
        check("B3 缓冲区里的老内容不算命中（只认本次等待期间新出现的）",
              r.get("ok") is False and r.get("matched") is False, r)
        check("B3b 零字节新增时 note 明说「一个字节都没有新增」并提示可能是请求没被接受",
              "一个字节都没有新增" in (r.get("note") or ""), r.get("note"))
        check("B3c 确实等满了 timeout_s（不是立刻返回）",
              time.time() - t0 >= 0.35, time.time() - t0)
        check("B3d 零字节新增给 timeout_kind=no-data + 专属错误码（与「有输出但不匹配」分开）",
              r.get("timeout") is True and r.get("timeout_kind") == "no-data"
              and r.get("error_code") == "serial-expect-timeout-no-data", r.get("error_code"))

        # B4 since=0 明确要看老内容
        r = serialmon.expect("OLD_MARK", timeout_s=0.4, since=0, poll_ms=20)
        check("B4 since=0 时才允许命中缓冲区老内容（显式回看）",
              r.get("matched") and r.get("since") == 0, r)

        # B5 有新增但不匹配 → 区分于「零字节新增」
        _feed_later(mm, b"irrelevant line\r\n", 0.15)
        r = serialmon.expect("NOPE_NOT_THERE", timeout_s=0.8, poll_ms=20)
        check("B5 有新增但不匹配时 note 明说「有新增但都不匹配」并给出放宽建议",
              r.get("matched") is False and "都不匹配" in (r.get("note") or "")
              and (r.get("count") and r["count"] > 0 and r.get("new_lines") > 0
                   if "count" in r else True), r.get("note"))
        check("B5b 该场景给 timeout_kind=no-match + 专属错误码",
              r.get("timeout_kind") == "no-match"
              and r.get("error_code") == "serial-expect-timeout-no-match", r.get("error_code"))

        # B6 半行命中（rt_kprintf 不带 \n 的情形）
        _feed_later(mm, b"no-newline-token-OK", 0.15)
        r = serialmon.expect("token-OK", timeout_s=2.0, poll_ms=20)
        check("B6 半行也能命中（include_partial 默认 true，matched_source=partial）",
              r.get("matched") and r.get("matched_source") == "partial"
              and "token-OK" in (r.get("matched_line") or ""), r)
        check("B6b 半行命中也带 partial 原文（便于确认不是残留）",
              "token-OK" in (r.get("partial") or ""), r.get("partial"))

        # B7 include_partial=false 时半行不参与匹配
        r = serialmon.expect("token-OK", timeout_s=0.4, include_partial=False,
                             since=0, poll_ms=20)
        check("B7 include_partial=false 时半行不命中（把开关交给调用方）",
              r.get("matched") is False, r.get("matched_source"))

        # B8 regex=false 按字面匹配，不必转义
        _feed_later(mm, b"len[12] = 34\r\n", 0.15)
        r = serialmon.expect("len[12]", timeout_s=2.0, regex=False, poll_ms=20)
        check("B8 regex=false 按字面匹配（[ ] 不用转义）",
              r.get("matched") and r.get("matched_text") == "len[12]", r)

        # B9 非法正则：明确报错并给退路，不抛异常
        r = serialmon.expect("([a-z", timeout_s=0.2)
        check("B9 非法正则：ok=false + 说明可传 regex=false",
              r.get("ok") is False and "正则编译失败" in (r.get("error") or "")
              and "regex=false" in (r.get("error") or ""), r)

        # B10 case_sensitive=false
        _feed_later(mm, b"MiXeD CaSe\r\n", 0.15)
        r = serialmon.expect("mixed case", timeout_s=2.0, case_sensitive=False, poll_ms=20)
        check("B10 case_sensitive=false 时不区分大小写",
              r.get("matched") and r.get("case_sensitive") is False, r)
    finally:
        _restore(old)

# ----------------------------------------------------------------------
# C. server 串口工具
# ----------------------------------------------------------------------
async def group_c_serial_tools(server):
    print("C. server 串口工具（serial_list_ports / serial_expect）")

    r = await call(server, "serial_list_ports", {})
    check("C1 serial_list_ports 返回 ports/candidates/auto_select/need_choice/selection_rule",
          r.get("ok") and isinstance(r.get("ports"), list)
          and "candidates" in r and "auto_select" in r and "need_choice" in r
          and "selection_rule" in r, r)
    r2 = await call(server, "serial_list_ports", {"detail": False})
    check("C2 detail=false 只返回端口名（更快）",
          r2.get("ok") and r2.get("count") == len(r2.get("ports") or [])
          and all(set(p) == {"port"} for p in (r2.get("ports") or [])), r2)

    mm, dev, old = _install_fake_monitor(reply=b"")
    try:
        # C3 send + 等待（一次调用拿全「发了什么 + 等到了什么」）
        _feed_later(mm, b"msh />help\r\n   commands: help/list/ps\r\n", 0.15)
        r = await call(server, "serial_expect",
                       {"pattern": "commands:", "send": "help", "timeout_s": 2,
                        "poll_ms": 20})
        check("C3 pattern+send 一次调用完成下发与等待，命中回显",
              r.get("matched") and r.get("sent") is True, r)
        check("C3b 返回 sent_hex/sent_bytes，且 eol 默认 crlf（6 字节）",
              r.get("sent_bytes") == 6 and r.get("sent_hex") == b"help\r\n".hex(), r)
        check("C3c 明文回显行随结果返回（省掉再调 serial_read）",
              any("commands:" in (x or "") for x in (r.get("lines") or [])), r.get("lines"))

        # C4 不下发时 sent=false 且 note 说明是纯等待
        _feed_later(mm, b"pure-wait-token\r\n", 0.15)
        r = await call(server, "serial_expect",
                       {"pattern": "pure-wait-token", "timeout_s": 2, "poll_ms": 20})
        check("C4 只等不发：sent=false 且 note 说明是纯等待",
              r.get("matched") and r.get("sent") is False
              and "未下发数据" in (r.get("note") or ""), r)

        # C5 eol=none
        _feed_later(mm, b"noeol\r\n", 0.15)
        r = await call(server, "serial_expect",
                       {"pattern": "noeol", "send": "help", "eol": "none",
                        "timeout_s": 2, "poll_ms": 20})
        check("C5 eol=none 时按 4 字节下发（eol 语义与 serial_write 一致）",
              r.get("sent_bytes") == 4 and r.get("eol_applied") == "none", r)

        # C6 hex 下发
        _feed_later(mm, b"bin-ok\r\n", 0.15)
        r = await call(server, "serial_expect",
                       {"pattern": "bin-ok", "hex": "7e 01 00 ff", "timeout_s": 2,
                        "poll_ms": 20})
        check("C6 hex 下发原样透传（4 字节）",
              r.get("sent_bytes") == 4 and dev.sent[-1] == b"\x7e\x01\x00\xff"
              and r.get("matched"), r)
        check("C6b hex-only 下发不崩且说明未追加行尾（eol 只对 send 文本生效）",
              r.get("eol_bytes_hex") == "" and "未追加行尾" in (r.get("eol_note") or ""), r)

        # C7 未命中不静默
        r = await call(server, "serial_expect", {"pattern": "决不可能出现的串",
                                                 "timeout_s": 0.3, "poll_ms": 20})
        check("C7 未命中：matched=false + note 给出分类线索（不静默返回空）",
              r.get("ok") is not None and r.get("matched") is False
              and bool(r.get("note")), r.get("note"))

        # C8 非法 hex 与空 pattern
        r = await call(server, "serial_expect", {"hex": "zz9"})
        check("C8 hex 非法时给出解析错误（不抛异常）",
              r.get("ok") is False and "hex 解析失败" in (r.get("error") or ""), r)
        r = await call(server, "serial_expect", {"timeout_s": 0.2})
        check("C9 pattern 为空时明确报参数不足",
              r.get("ok") is False and "参数不足" in (r.get("error") or "")
              and r.get("matched") is False, r)

        # C10 信封：串口写入类风险为中，可逆
        r = await call(server, "serial_expect", {"pattern": "x", "timeout_s": 0.2})
        check("C10 serial_expect 结果带 risk=medium / reversible=true（统一风险标注）",
              r.get("risk") == "medium" and r.get("reversible") is True, r)
    finally:
        _restore(old)

    # C11 无监听时工具不抛异常
    old = serialmon._monitor
    serialmon._monitor = None
    try:
        r = await call(server, "serial_expect", {"pattern": "x", "timeout_s": 0.2})
        check("C11 无监听时 serial_expect 指路 serial_monitor_start（不抛异常）",
              r.get("ok") is False and "serial_monitor_start" in (r.get("hint") or ""), r)
    finally:
        serialmon._monitor = old

# ----------------------------------------------------------------------
# D. builder：UV4 退出码表 / clean(-c) / rebuild(-cr) / metrics / artifacts
# ----------------------------------------------------------------------
def group_d_builder():
    print("D. builder：退出码完整表 + clean / rebuild + metrics / artifacts")

    em = builder._exit_meaning
    check("D1 UV4 退出码表覆盖关键码并给出机器可读名（不再是笼统的「失败」）",
          em(0) == "success" and em(1) == "warning" and em(2) == "build-error"
          and em(11) == "project-open-failed" and em(12) == "device-db-missing"
          and em(13) == "write-error" and em(15) == "uv4-busy"
          and em(99) == "unmapped-exit-code",
          [em(c) for c in (0, 1, 2, 11, 12, 13, 15, 99)])
    check("D2 人读文本也齐全（3/4/5 与 -1/-2/-3 都不再是裸数字）",
          "超时" in builder._status_text(-1) and "UV4" in builder._status_text(-2)
          and "成功" in builder._status_text(1) and "失败" in builder._status_text(3)
          and "写入错误" in builder._status_text(13), None)
    check("D3 每个失败码都给 next_actions（失败不再只有一句「失败」）",
          all(builder._exit_next_actions(c, "编译") for c in (2, 11, 12, 13, 15, -1, -2)),
          [c for c in (2, 11, 12, 13, 15, -1, -2)
           if not builder._exit_next_actions(c, "编译")])

    check("D4 metrics 解析 0 Error(s), 2 Warning(s)",
          builder._parse_build_metrics("... 0 Error(s), 2 Warning(s).") ==
          {"errors": 0, "warnings": 2, "source": "parsed-from-output"}, None)
    check("D5 metrics 容错式二次匹配（Errors/Warnings 复数写法）",
          builder._parse_build_metrics("3 Errors, 1 Warning") ==
          {"errors": 3, "warnings": 1, "source": "parsed-from-output"}, None)
    check("D6 日志里没有统计行时返回空（不编造 0）",
          builder._parse_build_metrics("Build Time Elapsed: 00:00:01") == {}, None)

    arts = builder._find_artifacts(REAL_PROJ)
    check("D7 artifacts 在工程目录有界递归里找到产物（键为扩展名）",
          "axf" in arts and Path_ok(arts["axf"].get("path")), arts)
    check("D8 artifacts 只收与工程同名主干（不误收别的工程产物）",
          all(Path_name(v["path"]).lower().startswith("mdk_test")
              or Path_suffix(v["path"]).lower() in (".map", ".htm")
              for v in arts.values()), arts)

    # 用假 UV4 运行器测命令行构造与失败分桶
    orig_run = builder._run_uv4
    state = {"code": 0, "out": "Build Time Elapsed: 00:00:01\r\n0 Error(s), 0 Warning(s).",
             "calls": []}

    def fake_run(uv4, args, timeout, visible=False):
        state["calls"].append({"args": list(args), "timeout": timeout})
        return state["code"], state["out"]

    builder._run_uv4 = fake_run
    try:
        r = builder.clean_project("C:/fake/UV4.exe", REAL_PROJ,
                                  ensure_debug_channel=False)
        check("D9 clean_project 走 UV4 -c（等价 Keil 的 Clean Targets）",
              state["calls"][-1]["args"] == ["-c", REAL_PROJ], state["calls"][-1])
        check("D10 clean 成功时 note 提醒「必须重新编译才有镜像」（有副作用不藏着）",
              r.get("ok") and "必须重新编译" in (r.get("note") or ""), r.get("note"))
        check("D11 clean 默认超时用 DEFAULT_CLEAN_TIMEOUT，且该值小于编译超时",
              state["calls"][-1]["timeout"] == builder.DEFAULT_CLEAN_TIMEOUT
              and builder.DEFAULT_CLEAN_TIMEOUT <= builder.DEFAULT_BUILD_TIMEOUT,
              state["calls"][-1])

        r = builder.clean_project("C:/fake/UV4.exe", REAL_PROJ, "Flash",
                                  ensure_debug_channel=False)
        check("D12 clean_project 带 target 时追加 -t（与编译路径写法一致）",
              state["calls"][-1]["args"] == ["-c", REAL_PROJ, "-t", "Flash"],
              state["calls"][-1]["args"])

        r = builder.rebuild_project("C:/fake/UV4.exe", REAL_PROJ,
                                    ensure_debug_channel=False)
        check("D13 rebuild 默认仍用 -r（不改变既有语义）",
              state["calls"][-1]["args"][0] == "-r" and r.get("clean_first") is False
              and r.get("uv4_args") == "-r", state["calls"][-1]["args"])
        r = builder.rebuild_project("C:/fake/UV4.exe", REAL_PROJ,
                                    ensure_debug_channel=False, clean_first=True)
        check("D14 clean_first=true 改走 -cr（先清后编，比 -r 更彻底）",
              state["calls"][-1]["args"][0] == "-cr" and r.get("clean_first") is True
              and r.get("uv4_args") == "-cr" and "清理并重新编译" in (r.get("action") or ""), r)

        check("D15 成功的构建结果带 metrics（调用方不必自己翻日志数错误）",
              (r.get("metrics") or {}).get("errors") == 0
              and (r.get("metrics") or {}).get("warnings") == 0, r.get("metrics"))
        check("D16 成功的构建结果带 exit_code_text / exit_code_meaning / status",
              r.get("status") == "ok" and r.get("exit_code_meaning")
              and r.get("exit_code_text"), {k: r.get(k) for k in
                                            ("status", "exit_code_meaning")})

        state["code"] = 15
        r = builder.rebuild_project("C:/fake/UV4.exe", REAL_PROJ,
                                    ensure_debug_channel=False)
        check("D17 退出码 15 → failure_bucket=keil-busy（可机读的失败分类）",
              r.get("ok") is False and r.get("failure_bucket") == "keil-busy"
              and r.get("next_actions"), r.get("failure_bucket"))
        for code, bucket in ((11, "project-unavailable"), (12, "toolchain-not-ready"),
                             (13, "output-write-failed"), (2, "build-failed"),
                             (-1, "timeout")):
            state["code"] = code
            r = builder.build_project("C:/fake/UV4.exe", REAL_PROJ,
                                      ensure_debug_channel=False)
            check("D18 退出码 %d → failure_bucket=%s" % (code, bucket),
                  r.get("failure_bucket") == bucket, r.get("failure_bucket"))

        state["code"] = 1
        state["out"] = "..\\main.c(12): warning:  #177-D: variable was declared but never referenced\r\n1 Error(s), 0 Warning(s)."
        r = builder.build_project("C:/fake/UV4.exe", REAL_PROJ,
                                  ensure_debug_channel=False)
        check("D19 退出码 1（有警告）仍算成功，并给出「可继续烧录」的下一步",
              r.get("ok") is True and r.get("next_actions")
              and "flash_download" in " ".join(r["next_actions"]), r.get("next_actions"))
    finally:
        builder._run_uv4 = orig_run

def Path_name(p):
    return os.path.basename(str(p))

def Path_suffix(p):
    return os.path.splitext(str(p))[1]

def Path_ok(p):
    return bool(p) and os.path.isfile(str(p))

# ----------------------------------------------------------------------
# E. 统一结果信封（errors.py）
# ----------------------------------------------------------------------
class _FakeCallToolResult:
    def __init__(self, text):
        self.content = [type("C", (), {"text": text})()]
        self.structured_content = {"result": text}

def group_e_envelope():
    print("E. 统一结果信封（status / error_code / next_actions / risk）")

    r = errors.normalize("read_mem",
                         {"ok": False, "error": "无法连接 UVSOCK（端口 4823 未监听）"})
    check("E1 失败结果补 status=error + 字符串 error_code + error_hint",
          r.get("status") == "error" and r.get("error_code") == "uvsock-unavailable"
          and r.get("error_hint"), r)
    check("E2 error_code 自带 next_actions（下一步可机读，不必靠翻文档）",
          any("keil_health" in a for a in (r.get("next_actions") or [])),
          r.get("next_actions"))

    check("E3 缺监听 → serial-not-monitoring",
          errors.normalize("serial_read", {"ok": False,
                                           "error": "当前没有串口监听在运行"}
                           ).get("error_code") == "serial-not-monitoring", None)
    check("E4 参数不足 → invalid-argument",
          errors.normalize("x", {"ok": False, "error": "参数不足：pattern 不能为空"}
                           ).get("error_code") == "invalid-argument", None)
    check("E5 Keil 断点 error 57 → breakpoint-address-unresolved",
          errors.normalize("set_breakpoint", {"ok": False,
                                              "error": "设置断点失败 error 57"}
                           ).get("error_code") == "breakpoint-address-unresolved", None)
    check("E6 未收录的报错回落 unknown-error（不硬猜）",
          errors.normalize("x", {"ok": False, "error": "某个没见过的问题"}
                           ).get("error_code") == "unknown-error", None)

    r = errors.normalize("flash_download", {"ok": True})
    check("E7 高风险工具标 risk=high 且 reversible=false（不可逆操作要显眼）",
          r.get("risk") == "high" and r.get("reversible") is False, r)
    r = errors.normalize("build_project", {"ok": True})
    check("E8 中风险工具标 risk=medium 且 reversible=true",
          r.get("risk") == "medium" and r.get("reversible") is True, r)
    r = errors.normalize("read_mem", {"ok": True})
    check("E9 只读工具不硬塞风险标注", "risk" not in r and "reversible" not in r, r)
    r = errors.normalize("clean_project", {"ok": False, "error": "x"})
    check("E10 clean_project 属高风险（会删掉构建产物）",
          r.get("risk") == "high" and r.get("reversible") is False, r)

    r = errors.normalize("serial_monitor_start", {"ok": "conflict", "error": "端口被占用"})
    check("E11 三态 ok（字符串）识别为 warn，且 warn 不产生 error_code",
          r.get("status") == "warn" and "error_code" not in r, r)

    r = errors.normalize("serial_write",
                         {"ok": False, "error": "参数不足：text 与 hex 都不给",
                          "hint": "先 serial_monitor_start 打开端口"})
    check("E12 next_actions 归拢 hint 但不回抄 error 原文（动作≠报错）",
          "先 serial_monitor_start 打开端口" in (r.get("next_actions") or [])
          and r["error"] not in (r.get("next_actions") or []), r.get("next_actions"))

    # E14~E16：真机暴露的错分类（serial_expect 超时曾被判 unknown-error，
    # next_actions 指去调 keil_health —— 方向完全不对）
    r = errors.normalize("serial_expect",
                         {"ok": False, "matched": False, "timeout": True,
                          "timeout_kind": "no-match", "error_code": "serial-expect-timeout-no-match",
                          "note": "800ms 内新增 1 行但都不匹配"})
    check("E14 串口等待超时不再落 unknown-error，且下一步是放宽 pattern / 读 lines",
          r.get("error_code") == "serial-expect-timeout-no-match"
          and any("放宽" in a or "lines" in a for a in (r.get("next_actions") or []))
          and not any("keil_health" in a for a in (r.get("next_actions") or [])),
          r.get("next_actions"))
    check("E15 工具自带 error_code 时也补 error_hint（码表是一件事，不是两件）",
          bool(r.get("error_hint")), r.get("error_hint"))

    r = errors.normalize("serial_expect",
                         {"ok": False, "matched": False, "timeout": True,
                          "timeout_kind": "no-data"})
    check("E16 零字节新增的下一步指向「确认下发/波特率接线」，不指 Keil",
          r.get("error_code") == "serial-expect-timeout-no-data"
          and any("波特率" in a or "接线" in a for a in (r.get("next_actions") or [])),
          r.get("next_actions"))

    check("E17 「正则编译失败」不会被「编译失败」规则误判成 build-failed",
          errors.classify_error("正则编译失败（pattern=([a-z）：unterminated") == "invalid-argument"
          and errors.classify_error("Build failed: 2 Errors") == "build-failed", None)

    src = {"ok": True, "port": "COM9", "count": 3, "note": "叙述性说明"}
    r = errors.normalize("serial_read", src)
    check("E13 信封只做加法：既有字段（含 note）一个不动",
          all(r.get(k) == v for k, v in src.items()) and r.get("status") == "ok", r)
    check("E14 note 是叙述而非动作，不进 next_actions",
          "叙述性说明" not in (r.get("next_actions") or []), r.get("next_actions"))

    # apply_to_result：就地回写（文本与 structured_content 同步）
    payload = json.dumps({"ok": False, "error": "参数不足：pattern 不能为空"})
    res = _FakeCallToolResult(payload)
    errors.apply_to_result("serial_expect", res)
    new = json.loads(res.content[0].text)
    check("E15 apply_to_result 就地回写 JSON 文本（工具代码无需逐处改动）",
          new.get("status") == "error" and new.get("error_code") == "invalid-argument", new)
    check("E16 structured_content 里同一份 JSON 同步更新（两条通道不打架）",
          json.loads(res.structured_content["result"]).get("status") == "error",
          res.structured_content)

    res = _FakeCallToolResult("这不是 JSON")
    errors.apply_to_result("x", res)
    check("E17 非 JSON 文本原样放过（不误改自由文本返回）",
          res.content[0].text == "这不是 JSON", res.content[0].text)

# ----------------------------------------------------------------------
# F. 工具面
# ----------------------------------------------------------------------
async def group_f_surface(server):
    print("F. 工具面")
    tools = {t.name: t for t in await server.list_tools()}
    for nm in ("serial_list_ports", "serial_expect", "clean_project"):
        check("F1 工具已注册：%s" % nm, nm in tools)

    n = len(tools)
    check("F2 工具总数 199（批次35 +10 + 批次34 +1 + 批次36 +46 + 批次40 +3 + 批次42 +1）", n == 199, n)

    d = tools["flash_download"].description or ""
    check("F3 高风险工具描述带【风险】高并点明不可逆",
          "【风险】高" in d and "不可逆" in d, d[-220:])
    d = tools["build_project"].description or ""
    check("F4 中风险工具描述带【风险】中", "【风险】中" in d, d[-220:])
    d = tools["read_mem"].description or ""
    check("F5 只读工具不带风险标注（避免标注通胀）", "【风险】" not in d, d[-160:])

    d = tools["serial_expect"].description or ""
    check("F6 serial_expect 描述点明「只认等待期间新内容」与半行匹配",
          "只认本次等待期间新出现的内容" in d and "include_partial" in d, d[:200])
    d = tools["serial_list_ports"].description or ""
    check("F7 serial_list_ports 描述点明「多候选不替调用方决定」",
          "不替调用方决定" in d and "likely_chip" in d, d[:200])
    d = tools["clean_project"].description or ""
    check("F8 clean_project 描述点明有副作用（清理后必须重编）与适用场合",
          "必须重新编译" in d and "增量构建" in d, d[:200])

    r = await call(server, "list_tools", {"keyword": "serial_expect"})
    item = next((t for t in (r.get("tools") or []) if t.get("tool") == "serial_expect"), None)
    ea = (item or {}).get("example_args") or {}
    check("F9 example_args 带上 pattern/send/eol（冷启动照抄即用）",
          ea.get("pattern") and ea.get("send") and ea.get("eol") == "auto", ea)
    check("F10 serial_expect 已进串口工具族（usage 摘要可检索到）",
          item is not None and bool((item or {}).get("usage")), item)

# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
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

    group_a_ports()
    group_b_expect()
    group_d_builder()
    group_e_envelope()

    try:
        await group_c_serial_tools(server)
        await group_f_surface(server)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次33 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
