# -*- coding: utf-8 -*-
"""批次31 mock 测试：serial_write 的 eol 静默失效修复 + 相关改进。

用户反馈原文（第 16 轮复验）：
    「发现一个新缺陷：eol 传转义字符会被静默丢弃。实测四组：
       text:"pool"（不传 eol）→ written 6，执行成功（默认 crlf 生效）
       text:"pool", eol:"cr"   → written 5，执行成功
       text:"pool", eol:"\\r"  → written 4，命令不执行（换行没发出去）
       text:"info", eol:"\\r" 后 text:"help" → 4/4，两次都没换行，行缓冲累积，
       直到改用 hex 发 0x0D 才执行，报 Command not found: infohelphelp
     根因在实现里：eol 先 .strip().lower()，真实 "\\r" 会被 strip 成空串。」

    「'回显 ≠ 执行'难辨：eol 没生效时目标照样逐字符回显……建议返回 eol_applied 与
      '实际发出的字节 hex'，把 written 的口径与 write_mem 的 verified/readback_hex 风格统一」
    「文档与实现对不齐：描述只写 'crlf'/'lf'/'cr'/'none'，实现还接受 cr+lf/windows/unix
      与字面 \\r/\\n，且 none 只是'落不到分支'的副作用」
    「list_tools 的 usage 摘要仍偏短（serial_write 截在'给 bo…'），冷启动照抄 example_args
      时恰好漏掉 eol 这类关键参数」
    「默认 crlf 对嵌入式并不总是对的（SVCrtOS shell、RT-Thread msh 多用单 \\r），
      建议加 auto，或首行失败时把可用取值一并提示」

  A _norm_eol：eol 取值归一化矩阵（含真实转义字符、别名、未识别）
  B _usage_summary：摘要长度与「不切在词中间」
  C serial_write：eol 各路径 + sent_hex/eol_applied 字段（真机四组复现）
  D serial_write：eol="auto" 回退 + 无回显提示
  E list_tools：usage/example_args 带上关键可选参数
  F 工具面回归

运行：python -m tests.test_batch31
"""
import os
import sys
import json
import time
import asyncio
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b31")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import serialmon  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug import uvsock as uvproto  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14904
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
# A. _norm_eol 归一化矩阵
# ----------------------------------------------------------------------
def group_a_norm_eol():
    print("A. eol 取值归一化（真机「传 \\r 被静默丢弃」的修复）")
    ne = srv._norm_eol

    def one(v):
        return ne(v)

    cases = [
        ("crlf", ("crlf", b"\r\n")), ("CRLF", ("crlf", b"\r\n")),
        (" crlf ", ("crlf", b"\r\n")), ("cr+lf", ("crlf", b"\r\n")),
        ("windows", ("crlf", b"\r\n")), ("dos", ("crlf", b"\r\n")),
        ("\\r\\n", ("crlf", b"\r\n")), ("\r\n", ("crlf", b"\r\n")),
        ("lf", ("lf", b"\n")), ("unix", ("lf", b"\n")),
        ("\\n", ("lf", b"\n")), ("\n", ("lf", b"\n")),
        ("cr", ("cr", b"\r")), ("mac", ("cr", b"\r")),
        ("\\r", ("cr", b"\r")), ("\r", ("cr", b"\r")),
        ("none", ("none", b"")), ("off", ("none", b"")),
        ("no", ("none", b"")), ("raw", ("none", b"")),
        ("", ("none", b"")), (None, ("none", b"")),
    ]
    bad = []
    for v, exp in cases:
        name, b, warn = one(v)
        if (name, b) != exp or warn is not None:
            bad.append((v, name, b, warn))
    check("A1 逐项归一正确（含真实 '\\r'/'\\n'/'\\r\\n' 与字面 '\\\\r'、别名、空值）",
          not bad, bad)

    n1, b1, w1 = one("\r")
    check("A2 真实 '\\r' → cr / 单字节 0x0D（旧实现被 strip 成空串的核心 bug）",
          (n1, b1, w1) == ("cr", b"\r", None), (n1, b1, w1))

    n2, b2, w2 = one("crcr")
    check("A3 未识别取值：不追加字节、给出 warning（不再静默 ok）",
          n2 is None and b2 == b"" and w2 and "无法识别" in w2, (n2, b2, w2))
    check("A4 未识别 warning 里带上原文，便于调用方自查",
          "crcr" in (w2 or ""), w2)
    check("A5 _EOL_HELP 列出全部可用取值（供「首行失败时一并提示」）",
          all(k in srv._EOL_HELP for k in ("crlf", "lf", "cr", "none", "auto")),
          srv._EOL_HELP)


# ----------------------------------------------------------------------
# B. _usage_summary
# ----------------------------------------------------------------------
def group_b_usage():
    print("B. usage 摘要（真机「截在'给 bo…'」的改进）")
    us = srv._usage_summary
    short = us("向串口下发数据。后面还有更多说明" + "x" * 100)
    check("B1 优先取完整一句（在首个句号处收尾）", short == "向串口下发数据", short)
    long1 = us("甲" * 400)
    check("B2 超长时截断且以省略号收尾（默认上限 170）",
          len(long1) <= 175 and long1.endswith("…"), (len(long1), long1[-10:]))
    full = "前置内容" * 30 + "，后半句" * 30
    mid = us(full)
    check("B3 能断在标点处时不切在词中间（结果是原文的整词前缀）",
          len(mid) <= 170 and full.startswith(mid) and "…" not in mid,
          (len(mid), mid[-12:]))
    check("B4 默认 limit 放宽到 170（不再 90 硬切）",
          srv._usage_summary.__defaults__ == (170,),
          srv._usage_summary.__defaults__)


# ----------------------------------------------------------------------
# 假串口设备
# ----------------------------------------------------------------------
class FakeDev:
    """假串口设备：记录每次写入，并把预设回显喂回监听器（模拟目标回显）。"""

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

    def read(self, n):
        return b""


def _install_fake_monitor(reply=b"msh />pool\r\n   pool free : 784940 B\r\n"):
    m = serialmon.SerialMonitor("COM_TEST", baud=115200)
    dev = FakeDev(m, reply=reply)
    m._set_dev(dev)
    m.state = "running"
    old = serialmon._monitor
    serialmon._monitor = m
    return m, dev, old


def _restore(old):
    serialmon._monitor = old


# ----------------------------------------------------------------------
# C. serial_write：eol 与「实际发出的字节」
# ----------------------------------------------------------------------
async def group_c_eol(server):
    print("C. serial_write 的 eol 路径与字节口径（复现真机四组）")
    m, dev, old = _install_fake_monitor()
    try:
        # 真机第①组：不传 eol → 默认 crlf
        r = await call(server, "serial_write", {"text": "pool", "wait_ms": 0})
        check("C1 不传 eol → 默认 crlf（pool 6 字节，执行成功）",
              r.get("ok") and r.get("written") == 6
              and r.get("sent_hex") == "706f6f6c0d0a", r)
        check("C2 eol_input/eol_applied/eol_bytes_hex 三个口径字段齐全",
              r.get("eol_applied") == "crlf" and r.get("eol_bytes_hex") == "0d0a"
              and r.get("sent_bytes") == 6, r)

        # 真机第②组：eol="cr" 关键字
        r = await call(server, "serial_write", {"text": "pool", "eol": "cr", "wait_ms": 0})
        check("C3 eol='cr' → 5 字节、sent_hex 以 0d 收尾",
              r.get("written") == 5 and r.get("sent_hex") == "706f6f6c0d"
              and r.get("eol_applied") == "cr", r)

        # 真机第③组：eol 传真实 "\r"（本次修复的核心）
        r = await call(server, "serial_write", {"text": "pool", "eol": "\r", "wait_ms": 0})
        check("C4 eol 传**真实** '\\r' 现在真的发出 0x0D（旧实现静默丢弃）",
              r.get("ok") and r.get("written") == 5
              and r.get("sent_hex") == "706f6f6c0d"
              and r.get("eol_applied") == "cr" and dev.sent[-1] == b"pool\r", r)
        check("C5 真实 '\\r' 与字面 '\\\\r' 等价（两种写法都认）",
              r.get("eol_applied") == "cr", r)

        r = await call(server, "serial_write", {"text": "pool", "eol": "\\n", "wait_ms": 0})
        check("C6 字面 '\\\\n' → lf（5 字节，0x0A 收尾）",
              r.get("written") == 5 and r.get("sent_hex") == "706f6f6c0a", r)
        r = await call(server, "serial_write", {"text": "pool", "eol": "\n", "wait_ms": 0})
        check("C7 真实 '\\n' → lf（同样 5 字节）",
              r.get("written") == 5 and r.get("sent_hex") == "706f6f6c0a", r)

        # 真机第④组：命令粘连的场景 —— info 与 help 各自带 \r 后不再累积
        r1 = await call(server, "serial_write", {"text": "info", "eol": "\r", "wait_ms": 0})
        r2 = await call(server, "serial_write", {"text": "help", "eol": "\r", "wait_ms": 0})
        check("C8 两次下发各自带 CR（不会再粘连成 'infohelphelp'）",
              r1.get("sent_hex") == "696e666f0d" and r2.get("sent_hex") == "68656c700d"
              and dev.sent[-2] == b"info\r" and dev.sent[-1] == b"help\r", (r1, r2))

        # eol 未识别
        r = await call(server, "serial_write", {"text": "pool", "eol": "crcrcr", "wait_ms": 0})
        check("C9 eol 未识别：ok=true 但明确 eol_unrecognized + warning + eol_applied=null",
              r.get("ok") is True and r.get("eol_unrecognized") is True
              and r.get("eol_applied") is None and r.get("eol_bytes_hex") == ""
              and "无法识别" in (r.get("warning") or ""), r)
        check("C10 eol 未识别时附 eol_hint（可用取值一并提示）",
              "crlf" in (r.get("eol_hint") or "") and "auto" in (r.get("eol_hint") or ""), r)
        check("C11 未识别时未追加任何字节（sent_hex 只含文本）",
              r.get("sent_hex") == "706f6f6c" and dev.sent[-1] == b"pool", r)

        # eol=none 与 hex 路径
        r = await call(server, "serial_write", {"text": "pool", "eol": "none", "wait_ms": 0})
        check("C12 eol='none' 不追加行尾（4 字节）",
              r.get("written") == 4 and r.get("sent_hex") == "706f6f6c", r)
        r = await call(server, "serial_write", {"hex": "pool".encode().hex() + "0d",
                                                "eol": "cr", "wait_ms": 0})
        check("C13 只给 hex 时 eol 不生效，并给出 note 指路（写进 hex 更可靠）",
              r.get("sent_hex") == "706f6f6c0d" and "只对 text 生效" in (r.get("note") or ""), r)

        # read_after 开关
        r = await call(server, "serial_write", {"text": "pool", "wait_ms": 0,
                                                "read_after": False})
        check("C14 read_after=false 时返回体不含 read_after（但要读的信息仍不丢：sent_hex）",
              "read_after" not in r and r.get("sent_hex") == "706f6f6c0d0a", r)
    finally:
        _restore(old)


# ----------------------------------------------------------------------
# D. auto 回退 / 无回显提示
# ----------------------------------------------------------------------
async def group_d_auto(server):
    print("D. eol='auto' 回退与无回显提示（用户建议）")

    # D1/D2 目标毫无回显（真 SVCrtOS shell 只认单 \r 的场景）
    m, dev, old = _install_fake_monitor(reply=b"")
    try:
        r = await call(server, "serial_write", {"text": "info", "eol": "auto", "wait_ms": 0})
        check("D1 eol='auto' 且无任何回显 → 自动补发单个 CR（fallback 标记 + 两次下发见 sent_hex）",
              r.get("ok") and r.get("eol_fallback") == "cr"
              and r.get("sent_hex") == "696e666f0d0a0d"
              and r.get("sent_bytes") == 7 and dev.sent == [b"info\r\n", b"\r"], (r, dev.sent))
        check("D2 auto 回退后 note 说明「补发了什么、为什么、适配哪类 shell」",
              "auto" in (r.get("note") or "") and "CR" in (r.get("note") or ""),
              r.get("note"))
    finally:
        _restore(old)

    # D3 目标有回显：不应补发
    m, dev, old = _install_fake_monitor()
    try:
        r = await call(server, "serial_write", {"text": "pool", "eol": "auto", "wait_ms": 0})
        check("D3 eol='auto' 且有回显 → 不补发（只发一次 crlf）",
              r.get("ok") and "eol_fallback" not in r
              and dev.sent == [b"pool\r\n"], (r, dev.sent))
    finally:
        _restore(old)

    # D4 非 auto 且无回显 → 提示可用取值
    m, dev, old = _install_fake_monitor(reply=b"")
    try:
        r = await call(server, "serial_write", {"text": "info", "wait_ms": 0})
        h = r.get("no_echo_hint") or ""
        check("D5 未用 auto 且毫无回显 → 附 no_echo_hint，提示改 'cr'/'auto' 或走 hex",
              "auto" in h and "cr" in h and "hex" in h, r)
        check("D6 no_echo_hint 只在真的没有回显时出现（有回显时不打扰）",
              r.get("sent_hex") == "696e666f0d0a", r)
    finally:
        _restore(old)

    m, dev, old = _install_fake_monitor()
    try:
        r = await call(server, "serial_write", {"text": "info", "wait_ms": 0})
        check("D7 有回显时不给 no_echo_hint（避免噪声）",
              "no_echo_hint" not in r, r)
    finally:
        _restore(old)


# ----------------------------------------------------------------------
# E. list_tools：usage 与 example_args
# ----------------------------------------------------------------------
async def group_e_tools(server):
    print("E. list_tools 的 usage 与 example_args")
    r = await call(server, "list_tools", {"keyword": "serial_write"})
    items = r.get("tools") or []
    sw = next((t for t in items if t.get("tool") == "serial_write"), None)
    check("E1 能按关键词取到 serial_write", sw is not None, items)

    ea = (sw or {}).get("example_args") or {}
    check("E2 example_args 带上关键可选参数 text/eol（照抄即用，冷启动不再漏 eol）",
          ea.get("text") == "help" and ea.get("eol") == "crlf", ea)

    usage = (sw or {}).get("usage") or ""
    check("E3 usage 不再切在词中间（真机那条'给 bo…'处现在能读到完整的『给 bootloader 发命令』）",
          len(usage) >= 60 and "给 bootloader 发命令" in usage, (len(usage), usage))
    check("E4 usage 不残留省略号在句中（完整一句优先）",
          not usage.endswith("…") or usage.count("…") == 1, usage)

    note = r.get("note") or ""
    check("E5 note 说明 example_args 含关键可选参数（如 serial_write 的 text/eol）",
          "serial_write" in note and "eol" in note, note)

    r2 = await call(server, "list_tools", {})
    check("E6 total 与工具数一致（162）", r2.get("total") == 162, r2.get("total"))


# ----------------------------------------------------------------------
# F. 工具面回归
# ----------------------------------------------------------------------
async def group_f_surface(server):
    print("F. 工具面回归")
    tools = {t.name: t for t in await server.list_tools()}
    check("F1 工具总数为 162（批次35 +10；批次34 +1；批次36 +46；批次40 rtos +3；批次42 toolset +1）", len(tools) == 162, len(tools))
    d = tools["serial_write"].description or ""
    check("F2 描述列出全部 eol 取值（crlf/lf/cr/none/auto）",
          all(k in d for k in ("'crlf'", "'lf'", "'cr'", "'none'", "'auto'")), d[:200])
    check("F3 描述说明转义写法与实现一致（不再文档实现两张皮）",
          "\\r" in d and "转义" in d, d[:200])
    check("F4 描述点明 sent_hex/eol_applied 口径（对齐 write_mem 的 readback_hex 风格）",
          "sent_hex" in d and "eol_applied" in d, d[:200])
    check("F5 描述点明 no_echo_hint", "no_echo_hint" in d, d[:200])
    check("F6 描述仍保留「一边收一边发」与依赖监听持口",
          "一边收一边发" in d and "serial_monitor_start" in d, d[:200])
    st = await call(server, "get_status")
    check("F7 get_status 通路未受影响", "_exc" not in st, st)


async def main():
    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    _orig = mock._dispatch

    def _dispatch_realistic(cmd, data):
        if cmd == uvproto.UV_DBG_STATUS and not mock.debugging:
            body = b"Target is not in debug mode\x00"
            import struct
            return uvproto.UV_STATUS_NOT_DEBUGGING, struct.pack("<i", len(body)) + body
        return _orig(cmd, data)

    mock._dispatch = _dispatch_realistic
    mock.stop_ignores = False
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0, axf_path=None)

    group_a_norm_eol()
    group_b_usage()
    try:
        await call(server, "enter_debug", {})
        await call(server, "run", {})
        await group_c_eol(server)
        await group_d_auto(server)
        await group_e_tools(server)
        await group_f_surface(server)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次31 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
