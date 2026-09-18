# -*- coding: utf-8 -*-
"""批次44 mock 测试：Modbus 串口支持（规范 RTU/ASCII + 非规范裸帧）。

来源：用户反馈「在添加串口规范modbus支持与不规范modbus支持」。
此前工具面只有 serialmon 的**按行切分**日志监听，对二进制帧无能为力
（\\x00 被当字符、帧尾没有换行、多从站应答混成一坨），调 Modbus 只能另写脚本。

本文件锁住的都是「会给出看似权威的错答案」的坑：
  A 协议层：CRC16/LRC 已知向量、组帧字节序、异常帧翻译、规范上限、时序常量
  B 请求装配：功能码/参数绑定、缺参数报错、裸 PDU 逃生口
  C 传输层：提前收满就返回、无响应 vs 收到但 CRC 不过**分开报**、
    半帧不当成功、按静默切帧、drain 丢残帧、只读口/未开端口
  D 会话管理：同参数复用不重开口、换参数 replaced、被 serialmon 占口要报错（不抢口）
  E 工具面：7 个工具注册在 serial 组、只读/非幂等注解、默认精简下按需装载、
    端到端工具调用（读/写/写后回读/裸帧/离线解码/扫描/旁听）

运行：python -m tests.test_batch44
"""
import os
import sys
import json
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
# 批次42：工具面默认精简（只开 core）；本批要校验全量工具面
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import modbus as MB       # noqa: E402
from mdkdebug import serialmon          # noqa: E402
from mdkdebug import server as S        # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

# ======================================================================
# 假的宿主机串口：不碰真口，按脚本/应答函数喂字节
# ======================================================================
class FakeDev:
    def __init__(self, can_write=True):
        self.chunks = []        # 每项 (bytes, delay_s)：模拟「读粒度 + 字节间隔」
        self.can_write = can_write
        self.written = []
        self.closed = False

    def feed(self, data, delay=0.0):
        self.chunks.append((bytes(data), float(delay)))

    def read(self, n=4096):
        if not self.chunks:
            return b""
        data, delay = self.chunks.pop(0)
        if delay:
            time.sleep(delay)
        return data

    def write(self, data):
        if not self.can_write:
            raise OSError("串口以只读方式打开（测试构造）")
        self.written.append(bytes(data))
        return len(data)

    def close(self):
        self.closed = True


class FakeHostSerial:
    """替掉 serialmon.HostSerial（modbus 在调用点查模块属性，所以能替换）。"""
    opened = 0
    fail_next = ""
    responder = None        # f(request_bytes) -> [(bytes, delay) ...]
    on_open_chunks = []     # open 之后立刻喂进去的块（sniff 用）
    last = None

    def __init__(self, port, baud=9600, databits=8, parity="none", stopbits=1):
        self.port_in = port
        self.path = serialmon.resolve_port(port)
        self.baud = baud
        self.databits = databits
        self.parity = parity
        self.stopbits = stopbits
        self.can_write = True
        self.handle = None
        self.dev = None
        FakeHostSerial.last = self

    def open(self):
        if FakeHostSerial.fail_next:
            msg, FakeHostSerial.fail_next = FakeHostSerial.fail_next, ""
            raise OSError(msg)
        FakeHostSerial.opened += 1
        self.dev = FakeDev()
        self.handle = 1
        for ch in FakeHostSerial.on_open_chunks:
            self.dev.chunks.append(ch)

    def read(self, n=4096):
        return self.dev.read(n) if self.dev is not None else b""

    def write(self, data):
        n = self.dev.write(data)
        if callable(FakeHostSerial.responder):
            for ch in (FakeHostSerial.responder(bytes(data)) or []):
                self.dev.chunks.append(ch)
        return n

    def close(self):
        if self.dev is not None:
            self.dev.close()
        self.dev = None
        self.handle = None


def reset_fake(responder=None, chunks=None, can_write=True, fail=""):
    FakeHostSerial.opened = 0
    FakeHostSerial.responder = responder
    FakeHostSerial.on_open_chunks = list(chunks or [])
    FakeHostSerial.fail_next = fail
    FakeHostSerial.last = None


def new_sess(baud=9600, mode="rtu", timeout_s=0.25, can_write=True, gap_s=None):
    """直接造会话并塞入假串口（跳过 open_session 的端口冲突检查）。"""
    s = MB.ModbusSession("COM_T44", baud=baud, mode=mode, timeout_s=timeout_s)
    fs = FakeHostSerial("COM_T44", baud=baud)
    fs.open()
    fs.can_write = bool(can_write)   # 会话的 can_write 读的是 HostSerial 层
    s.dev = fs
    s.opened_at = time.time()
    s.last_access = s.opened_at
    return s


def call(srv, name, **args):
    res = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    return json.loads(txt)


# 标准向量
REQ_03_1 = "01 03 00 00 00 01 84 0A"          # 读 1 个保持寄存器
RESP_03 = MB.pack_rtu(1, bytes.fromhex("03021234"))   # 正常应答：0x1234
RESP_03_EXC = MB.pack_rtu(1, bytes.fromhex("8302"))   # 异常帧：地址越界


# ======================================================================
def section_a():
    print("\n-- A 协议层：校验/组帧/解码/上限/时序 --")
    check("A1 CRC16 已知向量 01 03 00 00 00 01 → 0x0A84",
          MB.crc16(bytes.fromhex("010300000001")) == 0x0A84,
          "%04X" % MB.crc16(bytes.fromhex("010300000001")))
    check("A2 CRC 低字节在前（01 03 00 00 00 01 84 0A）",
          MB.pack_rtu(1, bytes.fromhex("0300000001")).hex(" ").upper() == REQ_03_1,
          MB.pack_rtu(1, bytes.fromhex("0300000001")).hex(" "))
    check("A3 LRC 二进制补码（010300000001 → FB）",
          MB.lrc(bytes.fromhex("010300000001")) == 0xFB, MB.lrc(bytes.fromhex("010300000001")))
    check("A4 pack_ascii 帧形如 :010300000001FB",
          MB.pack_ascii(1, bytes.fromhex("0300000001")) == b":010300000001FB\r\n",
          MB.pack_ascii(1, bytes.fromhex("0300000001")))

    p = MB.parse_rtu(RESP_03)
    check("A5 parse_rtu 正常应答解出寄存器 0x1234",
          p["ok"] and p["crc_ok"] and p["decode"]["registers"] == [0x1234], p)
    check("A6 parse_rtu 也给出原始 hex 与从站/功能码",
          p["raw_hex"].startswith("01 03") and p["slave"] == 1 and p["func"] == 3, p)
    bad = MB.parse_rtu(bytes.fromhex("0103021234FFFF"))
    check("A7 CRC 错 → ok=False + error_code=modbus-bad-crc",
          bad["ok"] is False and bad["error_code"] == "modbus-bad-crc", bad)
    short = MB.parse_rtu(b"\x01\x03")
    check("A8 帧太短 → modbus-bad-frame（不硬解）",
          short["ok"] is False and short["error_code"] == "modbus-bad-frame", short)

    a_ok = MB.parse_ascii(b":" + (bytes.fromhex("0103021234")
                                  + bytes([MB.lrc(bytes.fromhex("0103021234"))])).hex().upper().encode() + b"\r\n")
    check("A9 parse_ascii 正常应答 + lrc_ok",
          a_ok["ok"] and a_ok["lrc_ok"] and a_ok["decode"]["registers"] == [0x1234], a_ok)
    a_bad = MB.parse_ascii(b":01030212ZZ\r\n")
    check("A10 ASCII 帧含非 hex → modbus-bad-frame",
          a_bad["ok"] is False and a_bad["error_code"] == "modbus-bad-frame", a_bad)
    a_lrc = MB.parse_ascii(b":010302123400\r\n")
    check("A11 LRC 错 → modbus-bad-lrc",
          a_lrc["ok"] is False and a_lrc["error_code"] == "modbus-bad-lrc", a_lrc)

    exc = MB.parse_rtu(RESP_03_EXC)
    check("A12 异常帧：is_exception + 异常码译成中文",
          exc["is_exception"] and exc["exception_code"] == 2 and "地址越界" in exc["exception_text"], exc)
    check("A13 parse_frame auto 认 ASCII（':' 起）",
          MB.parse_frame(b":0103021234B4\r\n", "auto")["mode"] == "ascii", None)

    bits = MB.decode_payload(1, bytes.fromhex("020501"))   # 2 字节、位模式 0b101 + 5 个 0
    check("A14 位读解码：byte_count/位数/置位数",
          bits["byte_count"] == 2 and bits["count"] == 16 and bits["true_count"] == 3, bits)
    try:
        MB.decode_payload(3, bytes.fromhex("031234"))
        ok = False
    except ValueError as e:
        ok = "byte_count" in str(e)
    check("A15 长度与 byte_count 不符 → 报错（不猜）", ok, None)
    try:
        MB.decode_payload(3, bytes.fromhex("0112"))
        ok = False
    except ValueError as e:
        ok = "奇数" in str(e)
    check("A16 寄存器 byte_count 为奇数 → 报错", ok, None)

    check("A17 parse_hex 接受 0x/逗号/空格混写",
          MB.parse_hex("0x01, 03  00 00 00 01") == bytes.fromhex("010300000001"), None)
    for text, tok in (("010", "奇数"), ("01 0G", "非法")):
        try:
            MB.parse_hex(text); ok = False; msg = ""
        except ValueError as e:
            ok, msg = True, str(e)
        check("A18 parse_hex 拒绝 %r（%s）" % (text, tok), ok and tok in msg, msg)

    check("A19 parse_serial_format 8E1 → (8, even, 1)",
          MB.parse_serial_format("8E1") == (8, "even", 1), MB.parse_serial_format("8E1"))
    try:
        MB.parse_serial_format("9X9"); ok = False
    except ValueError:
        ok = True
    check("A20 串口格式认不出来就报错（不猜 8N1）", ok, None)

    check("A21 parse_slave_range 支持 1-3,10",
          MB.parse_slave_range("1-3,10") == [1, 2, 3, 10], MB.parse_slave_range("1-3,10"))
    check("A22 空 → 全范围 1~247", len(MB.parse_slave_range("")) == 247, None)
    for spec in ("1-300", "0", "3-1-2", "abc"):
        try:
            MB.parse_slave_range(spec); ok = False
        except ValueError:
            ok = True
        check("A23 从站范围 %r 非法 → 报错" % spec, ok, None)

    try:
        MB.pdu_read(3, 0, 126); ok = False; msg = ""
    except ValueError as e:
        ok, msg = True, str(e)
    check("A24 读寄存器一次 ≤125 → 126 直接报错", ok and "125" in msg, msg)
    try:
        MB.pdu_write_multiple_registers(0, [0] * 124); ok = False
    except ValueError:
        ok = True
    check("A25 写寄存器一次 ≤123 → 124 报错", ok, None)

    # 8N1 = 1 起始 + 8 数据 + 1 停止 = 10 位；t3.5 = 3.5 × 字符时间
    check("A26 9600 波特 8N1 下 t3.5 ≈ 3.65ms",
          abs(MB.inter_frame_gap_s(9600) - 3.5 * 10 / 9600) < 1e-9
          and MB.inter_frame_gap_s(9600) >= MB.GAP_T35_S, MB.inter_frame_gap_s(9600))
    check("A27 波特率 >19200 时 t3.5 固定 1.75ms",
          abs(MB.inter_frame_gap_s(115200) - 1.75e-3) < 1e-9, MB.inter_frame_gap_s(115200))
    check("A28 应答应有长度：RTU 7 / ASCII 15（count=1）",
          (MB.expected_response_len("rtu", 3, count=1),
           MB.expected_response_len("ascii", 3, count=1)) == (7, 15),
          (MB.expected_response_len("rtu", 3, count=1),
           MB.expected_response_len("ascii", 3, count=1)))
    check("A29 变长应答（0x11/0x0C/0x18）不给长度 → None（由超时兜底）",
          MB.expected_response_len("rtu", 0x11) is None
          and MB.expected_response_len("rtu", 0x18) is None, None)


def section_b():
    print("\n-- B 请求装配 --")
    r = MB.make_request("rtu", 1, 3, addr=0, count=1)
    check("B1 func3 帧与已知向量一致，expected_len=7",
          r["request_hex"] == REQ_03_1 and r["expected_len"] == 7 and r["is_write"] is False, r)
    r5 = MB.make_request("rtu", 1, 5, addr=0x10, value="on")
    # 帧 = 从站(1) + 功能码(1) + 地址(2) + 值(2) + CRC(2)，值在 [4:6]
    check("B2 线圈 on→0xFF00 / off→0x0000",
          r5["request"][4:6] == b"\xff\x00" and r5["request"][2:4] == b"\x00\x10"
          and MB.make_request("rtu", 1, 5, addr=0x10, value="off")["request"][4:6] == b"\x00\x00",
          r5["request_hex"])
    try:
        MB.make_request("rtu", 1, 6, addr=0); ok = False; msg = ""
    except ValueError as e:
        ok, msg = True, str(e)
    check("B3 缺 value 报错并点名缺谁", ok and "value" in msg, msg)
    r15 = MB.make_request("rtu", 1, 0x0F, addr=0, values="1,0,1")
    # 帧 = 从站+功能码+地址(2)+数量(2)+byte_count(1)+数据，故 [4:9]
    check("B4 写多线圈：数量=3、byte_count=1 且位模式 0b101",
          r15["request"][4:8] == bytes([0, 3, 1, 0x05]), r15["request_hex"])
    r16 = MB.make_request("rtu", 1, 0x10, addr=0, values=[0x1234, 0x5678])
    check("B5 写多寄存器：数量=2、H 在前、byte_count=4",
          r16["request"][4:11] == bytes([0, 2, 4, 0x12, 0x34, 0x56, 0x78]), r16["request_hex"])
    try:
        MB.make_request("rtu", 1, 0x2B); ok = False
    except ValueError as e:
        ok = "0x2B" in str(e)
    check("B6 暂不支持的标准功能码 → 报错并指出走裸帧", ok, None)
    rp = MB.make_request("rtu", 1, 0, pdu=bytes.fromhex("2B0E01"))
    check("B7 裸 PDU 逃生口不校验字段",
          rp["request_hex"].startswith("01 2B 0E 01"), rp["request_hex"])
    ra = MB.make_request("ascii", 1, 3, addr=0, count=1)
    check("B8 ASCII 模式请求帧形如 :010300000001FB\\r\\n",
          ra["request"] == b":010300000001FB\r\n" and ra["expected_len"] == 15, ra)
    rq = MB.make_request("rtu", 1, 6, addr="0x0010", value="0x1234")
    check("B9 地址/取值接受 0x 十六进制（现场拷来的值不用手算十进制）",
          rq["request"][2:6] == bytes.fromhex("00101234"), rq["request_hex"])
    rq2 = MB.make_request("rtu", 1, 0x10, addr=0, values=["0x1234", "0X5678"])
    check("B10 多点写也认 0x 前缀",
          rq2["request"][7:11] == bytes.fromhex("12345678"), rq2["request_hex"])

# ======================================================================
def section_c():
    print("\n-- C 传输层：收帧/切帧/失败分类 --")
    req = bytes.fromhex("010300000001840A")   # 完整请求（含 CRC）

    reset_fake(responder=lambda r: [(RESP_03, 0.0)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.3, expected_len=7)
    check("C1 收满应答应有长度即返回，且请求字节真的写出去了",
          res["ok"] and res["frame_count"] == 1
          and (FakeHostSerial.last.dev.written or [b""])[0].hex(" ").upper() == REQ_03_1
          and res["response_hex"].upper().startswith("01 03"), res)

    reset_fake()
    s = new_sess()
    res = s.transact(req, timeout_s=0.05, expected_len=7)
    check("C2 无响应 → modbus-timeout-no-response + no_response=True",
          res["ok"] is False and res["error_code"] == "modbus-timeout-no-response"
          and res.get("no_response") is True, res)

    reset_fake(responder=lambda r: [(b"\x01\x03\x02", 0.0)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.3, expected_len=7)
    check("C3 半帧（只回来 3 字节）→ 传输 ok 但 parsed_ok=False（不当成功）",
          res["ok"] is True and res["parsed_ok"] is False
          and res["parse_error_code"] == "modbus-bad-frame", res)

    reset_fake(responder=lambda r: [(bytes.fromhex("0103021234FFFF"), 0.0)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.3, expected_len=7)
    check("C4 CRC 不过 → parsed_ok=False + modbus-bad-crc（区别于「没响应」）",
          res["ok"] is True and res["parsed_ok"] is False
          and res["parse_error_code"] == "modbus-bad-crc", res)

    reset_fake(responder=lambda r: [(RESP_03, 0.0), (RESP_03, 0.06)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.6, max_frames=2)
    check("C5 两段字节按 60ms 静默切出两帧，且记录帧间隔",
          res["frame_count"] == 2 and res["frames"][0].get("gap_ms", 0) > 40
          and res.get("multi_frame_note"), res)

    reset_fake(responder=lambda r: [(RESP_03, 0.0)], chunks=[(b"\xaa\xbb", 0.0)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.3, expected_len=7)
    check("C6 发前 drain 掉滞留残帧（discarded_before_tx=2）",
          res["discarded_before_tx"] == 2 and res["parsed_ok"] is True, res)

    reset_fake()
    s = new_sess(can_write=False)
    res = s.transact(req, timeout_s=0.05, expected_len=7)
    check("C7 只读口 → modbus-port-readonly（不发字节）",
          res["ok"] is False and res["error_code"] == "modbus-port-readonly"
          and FakeHostSerial.last.dev.written == [], res)

    reset_fake()
    s = new_sess()
    s.close("测试关闭")
    res = s.transact(req, timeout_s=0.05, expected_len=7)
    check("C8 端口已关 → modbus-session-closed（不静默乱发）",
          res["ok"] is False and res["error_code"] == "modbus-session-closed", res)

    reset_fake(chunks=[(RESP_03, 0.0)])
    s = new_sess()
    res = s.sniff(duration_s=0.2, max_frames=4)
    check("C9 sniff 只收不发：一个字节都没写出去",
          res["ok"] and res["frame_count"] == 1
          and FakeHostSerial.last.dev.written == [], res)

    reset_fake(chunks=[(RESP_03, 0.0), (RESP_03, 0.06)])
    s = new_sess()
    res = s.sniff(duration_s=0.4, max_frames=4)
    check("C10 sniff 按静默切出两帧", res["frame_count"] == 2, res)

    reset_fake(chunks=[(RESP_03, 0.0), (RESP_03, 0.06), (RESP_03, 0.06)])
    s = new_sess()
    res = s.sniff(duration_s=0.6, max_frames=1)
    check("C11 sniff max_frames 生效（满了就返回）", res["frame_count"] == 1, res)

    reset_fake(responder=lambda r: [(RESP_03_EXC, 0.0)])
    s = new_sess()
    res = s.transact(req, timeout_s=0.3, expected_len=7)
    check("C12 异常帧算「收到了合法应答」（parsed_ok=True, is_exception）",
          res["ok"] and res["parsed_ok"] is True
          and (res.get("response_parsed") or {}).get("is_exception"), res)

# ======================================================================
def section_d():
    print("\n-- D 会话管理：复用/换口/冲突/报错 --")
    orig_hs, orig_cur = serialmon.HostSerial, serialmon.current
    serialmon.HostSerial = FakeHostSerial
    try:
        reset_fake()
        MB.close_session()
        r1 = MB.open_session("COM44", baud=9600)
        r2 = MB.open_session("COM44", baud=9600)
        check("D1 同口同参数复用，不重开口（避免 DTR 抖动复位目标板）",
              r1["opened"] is True and r2["reused"] is True and r2["opened"] is False
              and FakeHostSerial.opened == 1, (r1, r2, FakeHostSerial.opened))

        r3 = MB.open_session("COM44", baud=19200)
        check("D2 换参数 → 重开口并说明 replaced",
              r3["opened"] is True and r3.get("replaced", {}).get("port") == "COM44"
              and FakeHostSerial.opened == 2, r3)

        class _Mon:
            port_held = True
            port = "COM44"
        serialmon.current = lambda: _Mon()
        MB.close_session()
        r = MB.open_session("COM44")
        check("D3 端口被串口日志监听占着 → modbus-port-held-by-monitor（不抢口）",
              r["ok"] is False and r["error_code"] == "modbus-port-held-by-monitor", r)
        serialmon.current = orig_cur

        MB.close_session()
        r = MB.ensure("")
        check("D4 没开会话又没给 port → modbus-no-session",
              r["ok"] is False and r["error_code"] == "modbus-no-session", r)

        reset_fake()
        MB._set_session(new_sess())
        r = MB.ensure("", baud=19200)
        check("D5 给了串口参数却不给 port → modbus-no-port（不静默套用当前会话）",
              r["ok"] is False and r["error_code"] == "modbus-no-port", r)

        c = MB.close_session()
        check("D6 close_session 释放端口",
              c["closed"] is True and MB.session_status()["port_held"] is False, c)

        reset_fake(fail="打开串口失败: [WinError=5] 拒绝访问")
        MB.close_session()
        r = MB.open_session("COM44")
        check("D7 打开失败按 WinError=5 判 serial-port-busy（不是「找不到口」）",
              r["ok"] is False and r["error_code"] == "serial-port-busy", r)

        reset_fake()
        MB.close_session()
        r = MB.ensure("COM44", serial_format="9X9")
        check("D8 串口格式认不出来 → invalid-argument（不猜 8N1）",
              r["ok"] is False and r["error_code"] == "invalid-argument", r)
    finally:
        serialmon.HostSerial, serialmon.current = orig_hs, orig_cur
        MB.close_session()

# ======================================================================
MODBUS_TOOLS = {"modbus_read", "modbus_write", "modbus_raw", "modbus_decode",
                "modbus_scan", "modbus_sniff", "modbus_session"}

def section_e():
    print("\n-- E 工具面：注册/分组/注解/端到端 --")
    from mdkdebug import toolbox as _tb
    from mdkdebug import annotate as _an
    from mdkdebug import errors as _er

    srv = S.create_server(port=14934)
    tl = srv._tool_manager.list_tools()
    if asyncio.iscoroutine(tl):
        tl = asyncio.run(tl)
    names = sorted(t.name for t in tl)
    check("E1 注册工具总数 162（154 + Modbus 7）", len(names) == 162, len(names))
    check("E2 7 个 Modbus 工具全部注册",
          MODBUS_TOOLS <= set(names), sorted(MODBUS_TOOLS - set(names)))
    check("E3 7 个 Modbus 工具都登记在 serial 组",
          MODBUS_TOOLS <= set(_tb.TOOLSETS["serial"]), None)
    check("E4 只读/变更注解覆盖时不变式仍成立",
          MODBUS_TOOLS <= (_an.READONLY | _an.MUTATING)
          and not (MODBUS_TOOLS & _an.READONLY & _an.MUTATING)
          and not (_an.READONLY & _an.MUTATING)
          and "modbus_decode" in _an.READONLY and "modbus_read" in _an.MUTATING, None)
    check("E5 默认精简下 modbus 收在 serial 组里，按需装载才出现",
          _tb.DEFAULT_GROUPS == ("core",)
          and "modbus_read" in _tb.plan(tool_names=names, spec=None)["removed"]
          and "modbus_read" in _tb.plan(tool_names=names, spec="serial")["kept"]
          and not (MODBUS_TOOLS & set(_tb.ALWAYS)), None)

    def _arm(responder=None, chunks=None, **kw):
        reset_fake(responder=responder, chunks=chunks)
        s = new_sess(**kw)
        MB._set_session(s)
        return s

    def _wresp(r):
        # 写类应答应是「从站 + 功能码 + 地址(2) + 值/数量(2) + CRC」，即回显请求的前 5 字节 PDU
        f = r[1] if len(r) > 1 else 0
        if f in (0x05, 0x06, 0x0F, 0x10):
            return [(MB.pack_rtu(r[0], r[1:6]), 0.0)]
        return [(RESP_03, 0.0)]

    def _sresp(r):
        return [(RESP_03, 0.0)] if r and r[0] == 1 else []

    _arm(responder=lambda r: [(RESP_03, 0.0)])
    res = call(srv, "modbus_read", slave=1, func=3, addr=0, count=1)
    check("E6 modbus_read 端到端：值 + 收发原始帧",
          res["ok"] and res["values"] == [0x1234] and res["request_hex"] == REQ_03_1
          and res["response_hex"].upper().startswith("01 03"), res)

    _arm(responder=lambda r: [(RESP_03_EXC, 0.0)])
    res = call(srv, "modbus_read", slave=1, func=3, addr=0, count=1)
    check("E7 从站异常帧 → ok=False + modbus-exception + 中文原因（不当成功）",
          res["ok"] is False and res["is_exception"] is True
          and res["error_code"] == "modbus-exception" and "地址越界" in res["exception_text"], res)

    _arm()
    res = call(srv, "modbus_read", slave=1, func=3, addr=0, count=1, timeout_ms=50)
    check("E8 无响应 → modbus-timeout-no-response（工具层不改写设备结论）",
          res["ok"] is False and res["error_code"] == "modbus-timeout-no-response", res)

    _arm(responder=_wresp)
    res = call(srv, "modbus_write", slave=1, func=6, addr=0, value="0x1234")
    check("E9 modbus_write 单寄存器：写回显解出 value=0x1234",
          res["ok"] and (res.get("write_echo") or {}).get("value") == 0x1234, res)

    _arm(responder=_wresp)
    res = call(srv, "modbus_write", slave=1, func=6, addr=0, value="0x1234", verify=True)
    check("E10 verify=True 写后回读一致",
          res["ok"] and res["verify"]["ok"] and res["verify"]["read_back"] == [0x1234], res)

    _arm(responder=_wresp)
    res = call(srv, "modbus_write", slave=1, func=6, addr=0)
    check("E11 写单点缺 value → invalid-argument（不静默写 0）",
          res["ok"] is False and res["error_code"] == "invalid-argument", res)

    _arm(responder=lambda r: [(RESP_03, 0.0)])
    res = call(srv, "modbus_raw", req="01 03 00 00 00 01", auto_crc=True)
    check("E12 modbus_raw auto_crc 自动补 CRC16，字节与标准向量一致",
          res["ok"] and "CRC16" in (res.get("crc_note") or "")
          and (FakeHostSerial.last.dev.written or [b""])[-1].hex(" ").upper() == REQ_03_1, res)

    res = call(srv, "modbus_raw", req="")
    check("E13 modbus_raw 空帧 → invalid-argument",
          res["ok"] is False and res["error_code"] == "invalid-argument", res)

    MB._set_session(None)
    res = call(srv, "modbus_decode", frame=RESP_03.hex(" ").upper())
    check("E14 modbus_decode 离线解帧（不占端口）：解出 0x1234",
          res["ok"] and res["frames"][0]["decode"]["registers"] == [0x1234], res)

    res = call(srv, "modbus_decode", frame=RESP_03.hex(" ").upper() + "\n01 03 02 12")
    check("E15 modbus_decode 多行批量：坏帧计入 bad_frames 且整体 ok=False",
          res["count"] == 2 and res["bad_frames"] == 1 and res["ok"] is False, res)

    _arm(responder=_sresp)
    res = call(srv, "modbus_scan", slaves="1-2", timeout_ms=40)
    check("E16 modbus_scan 只报有应答的从站（1 在线、2 静默）",
          res["ok"] and res["scanned"] == 2 and res["found_count"] == 1
          and res["found"][0]["slave"] == 1 and res["no_response_count"] == 1, res)

    res = call(srv, "modbus_scan", slaves="1-247", max_slaves=4)
    check("E17 扫描范围超上限 → 直接报错（不静默少扫还报「完成」）",
          res["ok"] is False and res["error_code"] == "invalid-argument"
          and "247" in res["error"], res)

    _arm(chunks=[(RESP_03, 0.0)])
    res = call(srv, "modbus_sniff", duration_ms=200, max_frames=4)
    check("E18 modbus_sniff 旁听不发字节，收到 1 帧",
          res["ok"] and res["frame_count"] >= 1
          and FakeHostSerial.last.dev.written == [], res)

    s = _arm()
    res = call(srv, "modbus_session", action="status")
    ok_st = res["ok"] and res["port_held"] and res["serial_format"] == "8N1"
    res2 = call(srv, "modbus_session", action="close")
    check("E19 modbus_session status 报占用；close 释放端口",
          ok_st and res2["closed"] is True, (res, res2))

    a_mod = _er.code_actions("modbus_read", "timeout")
    a_mdk = _er.code_actions("read_mem", "timeout")
    check("E20 Modbus 工具的错误下一步指向串口侧，不误导向 keil_health",
          a_mod and a_mod != a_mdk
          and not any("keil_health" in x for x in a_mod), (a_mod, a_mdk))

# ======================================================================
# F 方向识别：旁听到的帧多半是主站请求，只按应答解会把最常见的读请求
#     一律标成「载荷不符」——那种「看似说了什么、其实没用」的输出正是要避的
# ======================================================================
def section_f():
    print("\n== F 方向识别（请求/应答/分不清） ==")
    srv = S.create_server()

    def rtu(slave, pdu_hex):
        return MB.pack_rtu(slave, bytes.fromhex(pdu_hex.replace(" ", "")))

    def dec(frame, mode="rtu"):
        return MB.parse_frame(frame, mode)

    p = dec(rtu(1, "03 00 00 00 01"))
    check("F1 读保持寄存器请求解成 read_request（不再是「载荷不符」）",
          p["ok"] and p["decoded"] and p["direction"] == "request"
          and p["decode"]["kind"] == "read_request"
          and p["decode"]["addr"] == 0 and p["decode"]["count"] == 1, p)

    p = dec(rtu(1, "01 00 13 00 25"))
    check("F2 读线圈请求：addr=0x13、count=0x25",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["addr"] == 0x13 and p["decode"]["count"] == 0x25, p)

    p = dec(rtu(1, "06 00 10 12 34"))
    check("F3 写单寄存器请求与应答同形 → 如实标 ambiguous，不硬指方向",
          p["decoded"] and p["direction"] == "ambiguous"
          and p["direction_note"] and p["decode"]["value"] == 0x1234, p)

    p = dec(rtu(1, "10 00 00 00 02 04 12 34 56 78"))
    check("F4 写多寄存器请求：count=2、byte_count=4、数据 4 字节",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["kind"] == "write_multiple_request"
          and p["decode"]["count"] == 2 and p["decode"]["byte_count"] == 4
          and p["decode"]["data_hex"] == "12 34 56 78", p)

    p = dec(rtu(1, "0F 00 00 00 0A 02 CD 01"))
    check("F5 写多线圈请求：10 个线圈只占 2 字节（按位算）",
          p["decoded"] and p["decode"]["count"] == 10
          and p["decode"]["byte_count"] == 2, p)

    p = dec(rtu(1, "17 00 01 00 02 00 03 00 02 04 11 11 22 22"))
    check("F6 读写多寄存器请求：读出读/写两段地址与数量",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["read_addr"] == 1 and p["decode"]["read_count"] == 2
          and p["decode"]["write_addr"] == 3 and p["decode"]["write_count"] == 2, p)

    p = dec(rtu(1, "0B 00 0D"))
    check("F7 通信事件计数请求（2 字节）与应答（4 字节）分得开",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["sub_function"] == 13, p)

    p = dec(rtu(1, "18 00 10"))
    check("F8 读 FIFO 队列请求：报出 FIFO 指针地址",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["fifo_pointer"] == 0x10, p)

    p = dec(rtu(1, "07"))
    check("F9 读异常状态请求（无载荷）也认得出来",
          p["decoded"] and p["direction"] == "request"
          and p["decode"]["kind"] == "no_payload_request", p)

    p = dec(rtu(1, "11"))
    check("F10 读从站标识请求（无载荷）也认得出来",
          p["decoded"] and p["direction"] == "request", p)

    p = dec(rtu(1, "03 02 12 34"))
    check("F11 正常应答仍标 response（新增请求分支未造成漂移）",
          p["decoded"] and p["direction"] == "response"
          and p["decode"]["registers"] == [0x1234], p)

    bad = 0
    try:
        MB.decode_payload(0x03, bytes.fromhex("00000001"), "response")
    except ValueError:
        bad += 1
    try:
        MB.decode_payload(0x03, bytes.fromhex("021234"), "request")
    except ValueError:
        bad += 1
    check("F12 把方向说死时，解反了就要报错（不许将错就错）", bad == 2, bad)

    p = dec(rtu(1, "10 00 00 00 02 03 12 34 56"))
    check("F13 字节数与数量对不上的写请求：不当请求认，如实报「两边都不像」",
          p["ok"] and p["decoded"] is False
          and "按应答解" in p["decode_error"] and "按请求解" in p["decode_error"], p)

    p = dec(rtu(1, "03 00 00 00 00"))
    check("F14 读数量为 0：不像合法请求，不硬认",
          p["ok"] and p["decoded"] is False, p)

    p = dec(MB.pack_ascii(1, bytes.fromhex("0300000001")), "ascii")
    check("F15 ASCII 请求帧同样认得方向",
          p["ok"] and p["decoded"] and p["direction"] == "request"
          and p["decode"]["kind"] == "read_request", p)

    res = call(srv, "modbus_decode", frame=rtu(1, "03 00 00 00 01").hex(" ").upper())
    check("F16 modbus_decode 工具：请求帧 decoded=True 且带 direction",
          res["ok"] and res["decoded"] == 1 and res["direction"] == "request", res)

    res = call(srv, "modbus_decode", frame=rtu(1, "06 00 10 12 34").hex(" ").upper())
    check("F17 modbus_decode 工具：同形帧标 ambiguous 并附说明",
          res["ok"] and res["direction"] == "ambiguous"
          and res["direction_note"], res)

    p = dec(rtu(1, "18 01 02 03 04 05"))
    check("F18 读 FIFO 载荷 byte_count 不足且非合法请求 → 不硬认",
          p["ok"] and p["decoded"] is False, p)

    # 真机上发现的：open 的回执里端口/参数被外层信封的同名键盖掉了，只剩一句「开了」
    _hs = serialmon.HostSerial
    serialmon.HostSerial = FakeHostSerial
    try:
        MB.close_session()
        res = call(srv, "modbus_session", action="open", port="COM_T44", baud=9600)
        check("F19 session(open) 的回执必须带 port/参数（不只说「开了」）",
              res.get("ok") and res.get("port") == "COM_T44" and res.get("port_held")
              and res.get("serial_format") == "8N1", res)
        MB.close_session()
    finally:
        serialmon.HostSerial = _hs

# ======================================================================
def main():
    print("批次44 mock 测试：Modbus 串口支持（RTU/ASCII + 裸帧）")
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    print("\n通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for n in FAIL:
            print("  - %s" % n)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
