# -*- coding: utf-8 -*-
"""Modbus 串口主站支持：规范 RTU/ASCII + 非规范裸帧。

为什么需要
----------
调试嵌入式设备时，串口上跑的不只有日志：仪表、传感器、自研从机大量走 Modbus。
此前工具面只有「按行切分的日志监听」（serialmon），对二进制帧完全无能为力——
按行切分会把帧切碎、把 ``\\x00`` 当字符、还要求帧尾有换行，Modbus 三条都不满足。
结果每次调 Modbus 都得在 MCP 之外另写一个 Python 脚本，调试闭环又缺一段。

这里补两层能力：

- **规范层**：RTU(CRC16) / ASCII(LRC) 两种模式，功能码 01/02/03/04/05/06/0F/10 的
  请求构造与响应解码，异常帧（``func|0x80`` + 异常码）如实翻译成中文原因。
- **非规范层**：``raw`` 直接下发任意字节并回收响应（按帧间静默自动切帧）；
  ``sniff`` 被动旁听总线。厂商私有协议、半双工乱时序、根本没有 CRC 的野协议都能看。

设计要点
--------
1. **纯协议层与传输层分离**：本模块的编解码函数全是纯函数（不碰端口），
   所以既能离线单测，也能用来解析别人抓下来的报文（``modbus_decode``）。
2. **端口独占要显式**：Modbus 会话自己持有 COM 口。若 serialmon 正监听同一个口，
   直接报错并指路（先 stop 监听），**不做「偷偷抢口」**——那种"成功"会收到错数据。
3. **收不到 vs 收错要分开**：超时且一个字节都没收到，与「收到了但 CRC 校验不过」
   是两类完全不同的问题，分别给 ``modbus-timeout-no-response`` / ``modbus-bad-crc``，
   不混成一句「失败」让人去猜接线还是猜协议。
4. **帧按静默切分**：同一条总线上多个从站应答、或从站号写错导致应答错位时，
   一次 transact 可能收到好几段。这里按帧间间隔（t3.5，>19200 波特固定 1.75ms）
   切帧后**全部列出**，而不是硬拼成一串 hex 让人自己数。
5. **非规范不等于随便**：``raw`` 也把能判的都判出来（CRC 对不对、能不能按
   Modbus 解、异常码是什么），判断不了的字段留空并标 ``decoded=False``，
   不猜一个像样的答案。
"""
from __future__ import annotations

import atexit
import logging
import re
import threading
import time

from . import serialmon

logger = logging.getLogger("mdkdebug.modbus")

# ----------------------------------------------------------------------
# 常量：功能码 / 异常码 / 规范上限
# ----------------------------------------------------------------------
# 功能码 → (名字, 中文说明, 是否写操作)
FUNC_TABLE = {
    0x01: ("read_coils", "读线圈（可读写位）", False),
    0x02: ("read_discrete_inputs", "读离散输入（只读位）", False),
    0x03: ("read_holding_registers", "读保持寄存器（可读写字）", False),
    0x04: ("read_input_registers", "读输入寄存器（只读字）", False),
    0x05: ("write_single_coil", "写单个线圈", True),
    0x06: ("write_single_register", "写单个保持寄存器", True),
    0x07: ("read_exception_status", "读异常状态", False),
    0x08: ("diagnostics", "诊断（子功能码）", False),
    0x0B: ("get_comm_event_counter", "读通信事件计数器", False),
    0x0C: ("get_comm_event_log", "读通信事件日志", False),
    0x0F: ("write_multiple_coils", "写多个线圈", True),
    0x10: ("write_multiple_registers", "写多个保持寄存器", True),
    0x11: ("report_server_id", "读从站标识", False),
    0x14: ("read_file_record", "读文件记录", False),
    0x15: ("write_file_record", "写文件记录", True),
    0x16: ("mask_write_register", "掩码写保持寄存器", True),
    0x17: ("read_write_multiple_registers", "读/写多个保持寄存器（原子）", True),
    0x18: ("read_fifo_queue", "读 FIFO 队列", False),
    0x2B: ("encapsulated_interface_transport", "封装接口传输（MEI）", False),
}

EXCEPTION_TABLE = {
    0x01: ("illegal function", "从站不支持该功能码"),
    0x02: ("illegal data address", "地址越界：该从站没有这个寄存器/线圈"),
    0x03: ("illegal data value", "数据值不合法：数量或取值超出从站允许范围"),
    0x04: ("server device failure", "从站执行时内部故障"),
    0x05: ("acknowledge", "从站已受理、正在处理，需要稍后轮询"),
    0x06: ("server device busy", "从站忙，请稍后重试"),
    0x07: ("negative acknowledge", "从站拒绝该编程请求"),
    0x08: ("memory parity error", "从站存储校验错"),
    0x0A: ("gateway path unavailable", "网关路径不可用：目标从站未挂上"),
    0x0B: ("gateway target device failed to respond", "网关侧目标从站无应答"),
}

# 规范上限（超了直接报错，而不是发出去让对方回异常码 03）
LIMITS = {
    0x01: ("count", 2000), 0x02: ("count", 2000),
    0x03: ("count", 125), 0x04: ("count", 125),
    0x0F: ("count", 1968), 0x10: ("count", 123),
}

STANDARD_BAUD_FOR_GAP = 19200   # 波特率高于此值时 t1.5/t3.5 固定为 750us/1.75ms
GAP_T35_S = 1.75e-3
GAP_T15_S = 0.75e-3
MIN_GAP_S = 4e-3                # 切帧判据下限：宿主机读粒度约 20ms，取太小无意义

# 常用串口格式简写：Modbus 设备大量用 8E1
SERIAL_FORMATS = {
    "8n1": (8, "none", 1), "8e1": (8, "even", 1), "8o1": (8, "odd", 1),
    "8n2": (8, "none", 2), "8e2": (8, "even", 2), "7e1": (7, "even", 1),
    "7o1": (7, "odd", 1), "7n2": (7, "none", 2), "8o2": (8, "odd", 2),
}


def parse_serial_format(text: str) -> tuple:
    """把 '8E1' 解析成 (databits, parity, stopbits)；认不出来报错（不猜）。"""
    key = str(text or "").strip().lower().replace("-", "").replace("_", "")
    if not key:
        return (None, None, None)
    if key in SERIAL_FORMATS:
        return SERIAL_FORMATS[key]
    raise ValueError("串口格式只支持形如 8N1 / 8E1 / 8O1 / 8N2 的写法，收到: %s" % text)


def func_name(func: int) -> str:
    ent = FUNC_TABLE.get(int(func) & 0x7F)
    return ent[0] if ent else "unknown_0x%02X" % (int(func) & 0x7F)


def func_desc(func: int) -> str:
    ent = FUNC_TABLE.get(int(func) & 0x7F)
    return ent[1] if ent else "未知功能码"


def exception_text(code: int) -> str:
    ent = EXCEPTION_TABLE.get(int(code))
    return "%s（%s）" % (ent[0], ent[1]) if ent else "未知异常码 0x%02X" % int(code)


# ----------------------------------------------------------------------
# 校验：CRC16 / LRC
# ----------------------------------------------------------------------
def crc16(data) -> int:
    """Modbus RTU 的 CRC16（多项式 0xA001 反射，初值 0xFFFF）。

    注意：**规范里低字节先发**，所以打包时是 ``crc & 0xFF`` 在前，
    这里返回的是数值本身，别拿返回值的字节序直接拼帧。
    """
    crc = 0xFFFF
    for b in bytes(data):
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def lrc(data) -> int:
    """Modbus ASCII 的 LRC：所有字节和的二进制补码（单字节）。"""
    return (-sum(bytes(data))) & 0xFF


def hexdump(data) -> str:
    """空格分隔的大写 hex，日志/返回值里统一用这个格式。"""
    return " ".join("%02X" % b for b in bytes(data))


def ascii_show(data) -> str:
    """把字节渲染成可见文本：可打印字符原样，其余用「.」占位。"""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bytes(data))


def parse_hex(text) -> bytes:
    """宽松解析 hex 串：接受空格/逗号/0x 前缀/换行分隔，也接受纯数字连写。

    解析不出来就报错——**不要**默默截断成能解析的那一半，
    否则会发出去一个「看着像」的帧，排查时极难定位。
    """
    s = str(text or "").strip()
    if not s:
        return b""
    s = re.sub(r"0[xX]", "", s)
    s = re.sub(r"[\s,;:_\-]+", "", s)
    if not re.fullmatch(r"[0-9a-fA-F]*", s):
        bad = sorted(set(re.findall(r"[^0-9a-fA-F]", str(text))))
        raise ValueError("hex 串里有非法字符 %s（只接受 0-9 a-f A-F 与分隔符）" % "".join(bad))
    if len(s) % 2:
        raise ValueError("hex 串长度为奇数（%d 个半字节），无法按字节解析：%s" % (len(s), text))
    return bytes.fromhex(s)


# ----------------------------------------------------------------------
# 时序：字符时间与帧间间隔（RTU 靠静默分帧，这个必须算对）
# ----------------------------------------------------------------------
def char_time_s(baud: int, databits: int = 8, parity: str = "none",
                stopbits=1) -> float:
    """一个字符的传输时间：1 起始位 + 数据位 + 校验位 + 停止位。"""
    b = int(baud or 9600)
    if b <= 0:
        b = 9600
    db = int(databits or 8)
    pb = 0 if str(parity or "none").strip().lower() in ("", "none", "n") else 1
    try:
        sb = float(stopbits or 1)
    except (TypeError, ValueError):
        sb = 1.0
    bits = 1 + db + pb + sb
    return bits / float(b)


def inter_frame_gap_s(baud: int, databits: int = 8, parity: str = "none",
                      stopbits=1) -> float:
    """RTU 帧间静默 t3.5：波特率 >19200 时规范固定为 1.75ms。"""
    b = int(baud or 9600)
    if b > STANDARD_BAUD_FOR_GAP:
        return GAP_T35_S
    return max(3.5 * char_time_s(b, databits, parity, stopbits), GAP_T35_S)


def inter_char_gap_s(baud: int, databits: int = 8, parity: str = "none",
                     stopbits=1) -> float:
    """RTU 帧内字符间隔 t1.5：超过它意味着这一帧已经不合法了。"""
    b = int(baud or 9600)
    if b > STANDARD_BAUD_FOR_GAP:
        return GAP_T15_S
    return max(1.5 * char_time_s(b, databits, parity, stopbits), GAP_T15_S)


# ----------------------------------------------------------------------
# PDU 构造（不含从站号与校验）
# ----------------------------------------------------------------------
def _int_literal(v):
    """把取值转成 int：十进制之外还认 0x/0X（十六进制）与 0b（二进制）前缀。

    现场拷到的寄存器值多半写成 0x1234，逼用户手算十进制既费事又容易错。
    认不出来就抛 ValueError，**不猜**。
    """
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v or "").strip().replace("_", "")
    if not s:
        raise ValueError("空值")
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    low = s.lower()
    if low.startswith("0x"):
        return -int(s[2:], 16) if neg else int(s[2:], 16)
    if low.startswith("0b"):
        return -int(s[2:], 2) if neg else int(s[2:], 2)
    return int(s, 10)


def _u16(v, name="value") -> int:
    try:
        iv = _int_literal(v)
    except (TypeError, ValueError):
        raise ValueError("%s 需要 0~65535 的整数（也认 0x 十六进制），收到: %r" % (name, v))
    if not 0 <= iv <= 0xFFFF:
        raise ValueError("%s 越界（%d）：Modbus 寄存器是 16 位无符号" % (name, iv))
    return iv


def _addr(v, name="addr") -> int:
    iv = _u16(v, name)
    if iv > 0xFFFF:
        raise ValueError("%s 越界" % name)
    return iv


def _u8(v, name) -> int:
    try:
        iv = _int_literal(v)
    except (TypeError, ValueError):
        raise ValueError("%s 需要 0~255 的整数（也认 0x 十六进制），收到: %r" % (name, v))
    if not 0 <= iv <= 0xFF:
        raise ValueError("%s 越界（%d）：该字段只有 1 字节" % (name, iv))
    return iv


def _check_count(func: int, count: int) -> int:
    n = int(count)
    if n <= 0:
        raise ValueError("count 必须 ≥1（Modbus 不允许一次读 0 个）")
    cap = LIMITS.get(int(func), ("count", 0x7FFF))[1]
    if n > cap:
        raise ValueError("func 0x%02X 的 count 上限是 %d（规范规定），收到 %d；"
                         "超限请拆成多次请求" % (int(func), cap, n))
    return n


def pdu_read(func: int, addr: int, count: int) -> bytes:
    """01/02/03/04 的请求 PDU。"""
    if int(func) not in (0x01, 0x02, 0x03, 0x04):
        raise ValueError("pdu_read 只支持 01/02/03/04，收到 0x%02X" % int(func))
    n = _check_count(func, count)
    return bytes([int(func)]) + _addr(addr).to_bytes(2, "big") + n.to_bytes(2, "big")


def pdu_write_single_coil(addr: int, value) -> bytes:
    on = _coil_on(value)
    return bytes([0x05]) + _addr(addr).to_bytes(2, "big") + (0xFF00 if on else 0x0000).to_bytes(2, "big")


def pdu_write_single_register(addr: int, value) -> bytes:
    return bytes([0x06]) + _addr(addr).to_bytes(2, "big") + _u16(value).to_bytes(2, "big")


def pdu_write_multiple_coils(addr: int, values) -> bytes:
    bits = [_coil_on(v) for v in _as_list(values, "values")]
    n = _check_count(0x0F, len(bits))
    packed = bytearray((n + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            packed[i // 8] |= 1 << (i % 8)
    return (bytes([0x0F]) + _addr(addr).to_bytes(2, "big")
            + n.to_bytes(2, "big") + bytes([len(packed)]) + bytes(packed))


def pdu_write_multiple_registers(addr: int, values) -> bytes:
    regs = [_u16(v, "values[%d]" % i) for i, v in enumerate(_as_list(values, "values"))]
    n = _check_count(0x10, len(regs))
    payload = b"".join(r.to_bytes(2, "big") for r in regs)
    return (bytes([0x10]) + _addr(addr).to_bytes(2, "big")
            + n.to_bytes(2, "big") + bytes([len(payload)]) + payload)


def pdu_read_write_multiple_registers(read_addr: int, read_count: int,
                                      write_addr: int, write_values) -> bytes:
    """0x17：一次请求里先写后读（原子），常用于「改参数并立即回读」。"""
    regs = [_u16(v, "write_values[%d]" % i) for i, v in enumerate(_as_list(write_values, "write_values"))]
    rn = _check_count(0x03, read_count)
    wn = _check_count(0x10, len(regs))
    payload = b"".join(r.to_bytes(2, "big") for r in regs)
    return (bytes([0x17]) + _addr(read_addr).to_bytes(2, "big") + rn.to_bytes(2, "big")
            + _addr(write_addr).to_bytes(2, "big") + wn.to_bytes(2, "big")
            + bytes([len(payload)]) + payload)


def pdu_mask_write_register(addr: int, and_mask: int, or_mask: int) -> bytes:
    return (bytes([0x16]) + _addr(addr).to_bytes(2, "big")
            + _u16(and_mask, "and_mask").to_bytes(2, "big")
            + _u16(or_mask, "or_mask").to_bytes(2, "big"))


def pdu_diagnostics(sub_function: int, data: int = 0) -> bytes:
    return (bytes([0x08]) + _u16(sub_function, "sub_function").to_bytes(2, "big")
            + _u16(data, "data").to_bytes(2, "big"))


def pdu_simple(func: int) -> bytes:
    """无参功能码：07 / 0B / 0C / 11。"""
    f = int(func)
    if f not in (0x07, 0x0B, 0x0C, 0x11):
        raise ValueError("这些功能码不需要参数：07/0B/0C/11；0x%02X 请用专用构造" % f)
    return bytes([f])


def pdu_read_fifo_queue(addr: int) -> bytes:
    return bytes([0x18]) + _addr(addr).to_bytes(2, "big")


def pdu_raw(payload) -> bytes:
    """非规范：把裸 PDU（功能码 + 数据）原样当请求体，不做任何字段校验。"""
    b = bytes(payload)
    if not b:
        raise ValueError("裸 PDU 不能为空（至少要有一个功能码字节）")
    return b


def _as_list(values, name: str) -> list:
    if values is None:
        raise ValueError("%s 不能为空" % name)
    if isinstance(values, (bytes, bytearray)):
        return list(values)
    if isinstance(values, str):
        txt = values.strip()
        if not txt:
            raise ValueError("%s 为空" % name)
        return [t for t in re.split(r"[\s,;]+", txt) if t]
    try:
        return list(values)
    except TypeError:
        raise ValueError("%s 需要是列表/逗号分隔字符串，收到: %r" % (name, values))


def parse_values(values) -> list:
    """公开版取值解析：把数组/逗号分隔字符串统一成列表（工具层用来数个数）。"""
    return _as_list(values, "values")


def _coil_on(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return int(v) != 0
    s = str(v or "").strip().lower()
    if s in ("1", "on", "true", "yes", "set", "high", "开"):
        return True
    if s in ("0", "off", "false", "no", "clear", "low", "关"):
        return False
    raise ValueError("线圈取值只接受 true/false/1/0/on/off，收到: %r" % v)


# ----------------------------------------------------------------------
# 组帧 / 解帧
# ----------------------------------------------------------------------
def pack_rtu(slave: int, pdu) -> bytes:
    """从站号 + PDU + CRC16（低字节在前）。"""
    body = bytes([_u8(slave, "slave")]) + bytes(pdu)
    c = crc16(body)
    return body + bytes([c & 0xFF, (c >> 8) & 0xFF])


def pack_ascii(slave: int, pdu) -> bytes:
    """':' + hex(从站号+PDU+LRC) + CRLF。"""
    body = bytes([_u8(slave, "slave")]) + bytes(pdu)
    body = body + bytes([lrc(body)])
    return b":" + body.hex().upper().encode("ascii") + b"\r\n"


def pack(mode: str, slave: int, pdu) -> bytes:
    m = norm_mode(mode)
    return pack_rtu(slave, pdu) if m == "rtu" else pack_ascii(slave, pdu)


def norm_mode(mode: str) -> str:
    m = str(mode or "rtu").strip().lower()
    if m in ("rtu", "r"):
        return "rtu"
    if m in ("ascii", "a", "asc"):
        return "ascii"
    raise ValueError("模式只支持 rtu / ascii，收到: %s" % mode)


def looks_ascii_frame(data) -> bool:
    """能不能当成 Modbus ASCII 帧：以 ':' 起、以 CR/LF 结束、中间全是 hex 字符。"""
    b = bytes(data)
    if not b or b[0:1] != b":":
        return False
    end = b.find(b"\r")
    if end < 0:
        end = b.find(b"\n")
    if end < 0:
        end = len(b)
    core = b[1:end]
    if not core:
        return False
    return re.fullmatch(rb"[0-9A-Fa-f]+", core) is not None


def strip_ascii_frame(data) -> bytes:
    """剥掉 ':' 与 CRLF，返回中间的 ASCII hex 字节。"""
    b = bytes(data)
    if b[:1] == b":":
        b = b[1:]
    return b.strip(b"\r\n \t")


def parse_rtu(frame) -> dict:
    """解析一帧 RTU：校验 CRC、拆出从站/功能码/数据，异常帧单独标出。"""
    b = bytes(frame)
    out = {"mode": "rtu", "raw_hex": hexdump(b), "length": len(b), "ok": False}
    if len(b) < 4:
        out.update(error="帧太短（%d 字节）：RTU 最短合法帧是 4 字节（从站+功能码+CRC）" % len(b),
                   error_code="modbus-bad-frame")
        return out
    body, got = b[:-2], b[-2] | (b[-1] << 8)
    want = crc16(body)
    out.update(slave=body[0], func=body[1], func_name=func_name(body[1]),
               func_desc=func_desc(body[1]), data=body[2:],
               data_hex=hexdump(body[2:]),
               crc_received="%04X" % got, crc_computed="%04X" % want,
               crc_ok=(got == want))
    if got != want:
        out.update(error="CRC 校验失败：帧内 0x%04X，按内容算是 0x%04X"
                         "（多半是串口参数不对/接线串扰/帧被截断）" % (got, want),
                   error_code="modbus-bad-crc")
        return out
    _fill_common(out)
    return out


def parse_ascii(frame) -> dict:
    """解析一帧 ASCII：校验 LRC、拆字段。"""
    b = bytes(frame)
    out = {"mode": "ascii", "raw_hex": hexdump(b),
           "raw_text": b.decode("ascii", "replace"), "length": len(b), "ok": False}
    core = strip_ascii_frame(b)
    if len(core) % 2:
        out.update(error="ASCII 帧的 hex 字符个数是奇数（%d），无法按字节解析" % len(core),
                   error_code="modbus-bad-frame")
        return out
    try:
        body = bytes.fromhex(core.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        out.update(error="ASCII 帧里有非 hex 字符，不是合法的 Modbus ASCII 帧",
                   error_code="modbus-bad-frame")
        return out
    if len(body) < 3:
        out.update(error="ASCII 帧太短：至少要有从站号+功能码+LRC（3 字节）",
                   error_code="modbus-bad-frame")
        return out
    payload, got = body[:-1], body[-1]
    want = lrc(payload)
    out.update(slave=payload[0], func=payload[1], func_name=func_name(payload[1]),
               func_desc=func_desc(payload[1]), data=payload[2:],
               data_hex=hexdump(payload[2:]),
               lrc_received="%02X" % got, lrc_computed="%02X" % want,
               lrc_ok=(got == want))
    if got != want:
        out.update(error="LRC 校验失败：帧内 0x%02X，按内容算是 0x%02X"
                         % (got, want), error_code="modbus-bad-lrc")
        return out
    _fill_common(out)
    return out


def _fill_common(out: dict) -> None:
    """补上异常帧判定与载荷解码（RTU/ASCII 共用）。"""
    f = out["func"]
    if f & 0x80:
        out.update(is_exception=True,
                   exception_code=(out["data"][0] if out["data"] else None),
                   ok=False)
        code = out["exception_code"]
        if code is None:
            out["error"] = "异常帧里没有异常码字节（长度不足）"
            out["error_code"] = "modbus-bad-frame"
        else:
            out["exception_text"] = exception_text(code)
            out["error"] = "从站返回异常码 0x%02X：%s" % (code, out["exception_text"])
            out["error_code"] = "modbus-exception"
            out["decoded"] = True
            out["decode"] = {"kind": "exception", "exception_code": code,
                             "exception_text": out["exception_text"]}
        return
    out["is_exception"] = False
    payload = out["data"]
    # 应答与请求都认：旁听时抓到的多半是主站请求，只认应答会把读请求判成「载荷不符」
    try:
        dec = decode_payload(f, payload)
        out["decode"] = dec
        out["direction"] = dec.get("direction")
        if dec.get("direction_note"):
            out["direction_note"] = dec["direction_note"]
        out["decoded"] = True
        out["ok"] = True
    except ValueError as e:
        out["decoded"] = False
        out["decode_error"] = str(e)
        # 解不了不代表帧坏了（可能是厂商标注不规范的私有载荷），如实标出来
        out["ok"] = True
        out["note"] = ("帧结构与校验都对，但载荷既不符合标准 Modbus 的应答布局、"
                       "也不符合请求布局：%s" % e)


def parse_frame(data, mode: str = "auto") -> dict:
    """自动/指定模式解析一帧。``mode='auto'`` 时按首字节是不是 ':' 判断。"""
    m = str(mode or "auto").strip().lower()
    if m in ("auto", "", "a?"):
        m = "ascii" if looks_ascii_frame(data) else "rtu"
    return parse_ascii(data) if norm_mode(m) == "ascii" else parse_rtu(data)


def _dec_response(func: int, payload) -> dict:
    """按功能码解码**应答**载荷（不含从站号与校验）。解不了抛 ValueError。"""
    f = int(func) & 0x7F
    d = bytes(payload)
    if f in (0x01, 0x02):
        return _dec_bits(f, d)
    if f in (0x03, 0x04):
        return _dec_regs(d)
    if f == 0x05:
        return _dec_write_echo(f, d, coil=True)
    if f == 0x06:
        return _dec_write_echo(f, d, coil=False)
    if f in (0x0F, 0x10):
        return _dec_write_echo_multi(f, d)
    if f == 0x17:
        return _dec_regs(d)
    if f == 0x16:
        if len(d) != 6:
            raise ValueError("掩码写应答应为 6 字节（地址+AND+OR），实际 %d" % len(d))
        return {"kind": "mask_write", "addr": int.from_bytes(d[0:2], "big"),
                "and_mask": "0x%04X" % int.from_bytes(d[2:4], "big"),
                "or_mask": "0x%04X" % int.from_bytes(d[4:6], "big")}
    if f == 0x08:
        if len(d) != 4:
            raise ValueError("诊断应答应为 4 字节（子功能+数据），实际 %d" % len(d))
        return {"kind": "diagnostics", "sub_function": int.from_bytes(d[0:2], "big"),
                "data": int.from_bytes(d[2:4], "big")}
    if f == 0x07:
        if len(d) != 1:
            raise ValueError("读异常状态应答应为 1 字节，实际 %d" % len(d))
        return {"kind": "exception_status", "status": "0x%02X" % d[0],
                "faults": _bits_of(d[0], 8)}
    if f == 0x0B:
        if len(d) != 4:
            raise ValueError("通信事件计数应答应为 4 字节，实际 %d" % len(d))
        return {"kind": "comm_event_counter", "status": int.from_bytes(d[0:2], "big"),
                "count": int.from_bytes(d[2:4], "big")}
    if f == 0x11:
        return _dec_server_id(d)
    if f == 0x18:
        return _dec_fifo(d)
    # 07 之外认不出的：如实给出原始字节，不硬编
    return {"kind": "raw", "data_hex": hexdump(d), "data_text": ascii_show(d)}


# 请求与应答同形（回显）的功能码：单看一帧判不出方向，如实标 ambiguous
_AMBIGUOUS_FUNCS = {0x05, 0x06, 0x08, 0x16}


def _dec_request(func: int, payload) -> dict:
    """按功能码解码**请求**载荷（不含从站号与校验）。解不了抛 ValueError。

    旁听/抓包时抓到的帧多半是主站请求，只按应答解会把最常见的读请求
    一律标成「载荷不符」——所以请求方向也得认下来。
    """
    f = int(func) & 0x7F
    d = bytes(payload)
    if f in (0x01, 0x02, 0x03, 0x04):
        if len(d) != 4:
            raise ValueError("读请求载荷应为 4 字节（地址+数量），实际 %d" % len(d))
        addr = int.from_bytes(d[0:2], "big")
        qty = int.from_bytes(d[2:4], "big")
        cap = LIMITS[f][1]
        if qty < 1:
            raise ValueError("读请求的数量为 0，不合法")
        if qty > cap:
            raise ValueError("读请求的数量 %d 超过该功能码的标准上限 %d，不像请求帧" % (qty, cap))
        return {"kind": "read_request", "addr": addr, "count": qty}
    if f in (0x05, 0x06):
        if len(d) != 4:
            raise ValueError("写单个量请求载荷应为 4 字节（地址+取值），实际 %d" % len(d))
        return {"kind": "write_single_request",
                "addr": int.from_bytes(d[0:2], "big"),
                "value": int.from_bytes(d[2:4], "big")}
    if f in (0x0F, 0x10):
        if len(d) < 5:
            raise ValueError("写多个量请求载荷至少 5 字节（地址+数量+字节数+数据），实际 %d" % len(d))
        addr = int.from_bytes(d[0:2], "big")
        qty = int.from_bytes(d[2:4], "big")
        bc = d[4]
        if qty < 1:
            raise ValueError("写多个量的数量为 0，不合法")
        want = (qty + 7) // 8 if f == 0x0F else qty * 2
        if bc != want:
            raise ValueError("写多个量的字节数与数量对不上：写 %d 个应为 %d 字节，帧里写着 %d"
                             % (qty, want, bc))
        if len(d) != 5 + bc:
            raise ValueError("写多个量的数据长度与字节数字段不符：字节数 %d，实际数据 %d"
                             % (bc, len(d) - 5))
        return {"kind": "write_multiple_request", "addr": addr, "count": qty,
                "byte_count": bc, "data_hex": hexdump(d[5:])}
    if f == 0x17:
        if len(d) < 9:
            raise ValueError("读写多寄存器请求载荷至少 9 字节，实际 %d" % len(d))
        r_addr = int.from_bytes(d[0:2], "big")
        r_qty = int.from_bytes(d[2:4], "big")
        w_addr = int.from_bytes(d[4:6], "big")
        w_qty = int.from_bytes(d[6:8], "big")
        bc = d[8]
        if r_qty < 1 or w_qty < 1:
            raise ValueError("读写多寄存器的读数量/写数量都不能为 0")
        if bc != w_qty * 2 or len(d) != 9 + bc:
            raise ValueError("读写多寄存器的写数据长度与写数量不符：写 %d 个应为 %d 字节，"
                             "字节数字段 %d、实际数据 %d" % (w_qty, w_qty * 2, bc, len(d) - 9))
        return {"kind": "read_write_multiple_request", "read_addr": r_addr,
                "read_count": r_qty, "write_addr": w_addr, "write_count": w_qty,
                "data_hex": hexdump(d[9:])}
    if f == 0x0B:
        if len(d) != 2:
            raise ValueError("通信事件计数请求载荷应为 2 字节（子功能），实际 %d" % len(d))
        return {"kind": "comm_event_counter_request",
                "sub_function": int.from_bytes(d[0:2], "big")}
    if f == 0x18:
        if len(d) != 2:
            raise ValueError("读 FIFO 队列请求载荷应为 2 字节（FIFO 指针地址），实际 %d" % len(d))
        return {"kind": "read_fifo_queue_request",
                "fifo_pointer": int.from_bytes(d[0:2], "big")}
    if f in (0x07, 0x11):
        if d:
            raise ValueError("0x%02X 的请求不带数据（应 0 字节），实际 %d" % (f, len(d)))
        return {"kind": "no_payload_request"}
    raise ValueError("0x%02X (%s) 的请求帧布局未收录" % (f, func_name(f)))


def _mark_direction(out: dict, f: int, dirn: str) -> dict:
    """标出帧方向；请求/应答同形的功能码如实标 ambiguous，不硬指一个方向。"""
    if f in _AMBIGUOUS_FUNCS:
        out["direction"] = "ambiguous"
        out["direction_note"] = ("该功能码的请求与应答同形（回显），单看一帧分不出方向；"
                                 "载荷解读两者一致")
    else:
        out["direction"] = dirn
    return out


def decode_payload(func: int, payload, direction: str = "auto") -> dict:
    """解码载荷（不含从站号与校验），默认自动判方向。

    - ``direction="auto"``：先按应答解，不符再按请求解——旁听到的帧多半是请求，
      只认应答会把它们一律标成「载荷不符」；
    - ``"response"`` / ``"request"``：只按指定方向解（拿不准时用它把话说死）。

    推不出来的**不猜**：两个方向都失败就抛 ValueError，两边的原因都写进去。
    """
    f = int(func) & 0x7F
    d = bytes(payload)
    dirn = str(direction or "auto").strip().lower()
    if dirn == "request":
        return _mark_direction(_dec_request(f, d), f, "request")
    if dirn == "response":
        return _mark_direction(_dec_response(f, d), f, "response")
    try:
        return _mark_direction(_dec_response(f, d), f, "response")
    except ValueError as e_resp:
        try:
            return _mark_direction(_dec_request(f, d), f, "request")
        except ValueError as e_req:
            raise ValueError("按应答解：%s；按请求解：%s" % (e_resp, e_req))


def _bits_of(byte_val: int, width: int) -> list:
    return [bool((byte_val >> i) & 1) for i in range(width)]


def _dec_bits(func: int, d: bytes) -> dict:
    if len(d) < 1:
        raise ValueError("位读应答缺 byte_count 字段")
    bc = d[0]
    if len(d) != bc + 1:
        raise ValueError("位读应答长度不符：byte_count=%d，实际数据 %d 字节" % (bc, len(d) - 1))
    bits = []
    for i in range(bc):
        bits.extend(_bits_of(d[1 + i], 8))
    return {"kind": "bits", "byte_count": bc, "count": len(bits), "bits": bits,
            "packed_hex": hexdump(d[1:]), "true_count": sum(1 for b in bits if b)}


def _dec_regs(d: bytes) -> dict:
    if len(d) < 1:
        raise ValueError("寄存器读应答缺 byte_count 字段")
    bc = d[0]
    if len(d) != bc + 1:
        raise ValueError("寄存器读应答长度不符：byte_count=%d，实际数据 %d 字节" % (bc, len(d) - 1))
    if bc % 2:
        raise ValueError("寄存器读应答的 byte_count 是奇数（%d），不可能是 16 位寄存器" % bc)
    regs = [int.from_bytes(d[1 + i:3 + i], "big") for i in range(0, bc, 2)]
    return {"kind": "registers", "byte_count": bc, "count": len(regs),
            "registers": regs, "registers_hex": ["0x%04X" % r for r in regs],
            "words_hex": hexdump(d[1:]),
            "signed": [r - 0x10000 if r >= 0x8000 else r for r in regs]}


def _dec_write_echo(func: int, d: bytes, coil: bool) -> dict:
    if len(d) != 4:
        raise ValueError("写单个%s的应答应为 4 字节（地址+值），实际 %d"
                         % ("线圈" if coil else "寄存器", len(d)))
    addr = int.from_bytes(d[0:2], "big")
    val = int.from_bytes(d[2:4], "big")
    out = {"kind": "write_single", "addr": addr, "value": val,
           "value_hex": "0x%04X" % val}
    if coil:
        if val not in (0x0000, 0xFF00):
            raise ValueError("写单个线圈的应答值应为 0x0000/0xFF00，实际 0x%04X" % val)
        out["on"] = (val == 0xFF00)
    return out


def _dec_write_echo_multi(func: int, d: bytes) -> dict:
    if len(d) != 4:
        raise ValueError("写多个的应答应为 4 字节（地址+数量），实际 %d" % len(d))
    return {"kind": "write_multiple", "addr": int.from_bytes(d[0:2], "big"),
            "count": int.from_bytes(d[2:4], "big")}


def _dec_server_id(d: bytes) -> dict:
    if len(d) < 2:
        raise ValueError("读从站标识的应答至少 2 字节（byte_count+从站号），实际 %d" % len(d))
    bc = d[0]
    if len(d) != bc + 1:
        raise ValueError("读从站标识应答长度不符：byte_count=%d，实际 %d" % (bc, len(d) - 1))
    body = d[1:]
    text = body[1:].decode("ascii", "replace") if len(body) > 1 else ""
    return {"kind": "server_id", "slave_id": body[0], "run_indicator": "0x%02X" % body[0],
            "text": text, "data_hex": hexdump(body)}


def _dec_fifo(d: bytes) -> dict:
    if len(d) < 2:
        raise ValueError("读 FIFO 队列应答至少 2 字节（byte_count+FIFO 计数）")
    bc = d[0]
    if bc < 2:
        raise ValueError("读 FIFO 队列应答的 byte_count 至少 2（FIFO 计数），实际 %d" % bc)
    if len(d) != bc + 1:
        raise ValueError("读 FIFO 队列应答长度不符：byte_count=%d，实际 %d" % (bc, len(d) - 1))
    fifo_count = int.from_bytes(d[1:3], "big")

    regs = [int.from_bytes(d[3 + i:5 + i], "big") for i in range(0, max(0, len(d) - 3), 2)]
    return {"kind": "fifo_queue", "fifo_count": fifo_count, "values": regs,
            "values_hex": ["0x%04X" % r for r in regs]}


# ----------------------------------------------------------------------
# 请求装配：把「功能码 + 参数」变成一帧，并算出应答应有的长度
# ----------------------------------------------------------------------
def expected_response_len(mode: str, func: int, count=None, read_count=None) -> int:
    """标准功能码的应答帧长（用于提前收完就返回，不必等满超时）。

    算不出来（07/0C/11/18 这类变长应答）就返回 None，由超时兜底——
    这里不猜一个数，猜错会导致「提前截断」这种最难查的错。
    """
    f = int(func) & 0x7F
    data_len = None
    if f in (0x01, 0x02) and count:
        data_len = 1 + (int(count) + 7) // 8
    elif f in (0x03, 0x04) and count:
        data_len = 1 + int(count) * 2
    elif f in (0x05, 0x06, 0x0F, 0x10):
        data_len = 4
    elif f == 0x17 and read_count:
        data_len = 1 + int(read_count) * 2
    elif f == 0x16:
        data_len = 6
    elif f == 0x08:
        data_len = 4
    elif f == 0x07:
        data_len = 1
    elif f == 0x0B:
        data_len = 4
    if data_len is None:
        return None
    if norm_mode(mode) == "ascii":
        return 3 + 2 * (3 + data_len)
    return 4 + data_len


def make_request(mode: str, slave: int, func: int, addr=None, count=None,
                 value=None, values=None, read_addr=None, read_count=None,
                 write_addr=None, write_values=None, and_mask=None, or_mask=None,
                 sub_function=None, data=None, pdu=None) -> dict:
    """装配一帧请求。

    返回 {request, request_hex, mode, slave, func, func_name, is_write,
          expected_len, summary}。参数不全/越界一律 ValueError，不静默补默认值。
    """
    m = norm_mode(mode)
    f = _int_literal(func)
    # 摘要与组帧必须用同一套解析：否则帧算对了、summary 却炸在 int("0x10") 上
    if addr is not None:
        addr = _u16(addr, "addr")
    if count is not None:
        count = _u16(count, "count")
    if read_addr is not None:
        read_addr = _u16(read_addr, "read_addr")
    if read_count is not None:
        read_count = _u16(read_count, "read_count")
    if write_addr is not None:
        write_addr = _u16(write_addr, "write_addr")
    if pdu is not None:
        body = pdu_raw(pdu)
        f = body[0]
        exp = None
        summary = "裸 PDU（%s），不校验字段" % hexdump(body)
        is_write = bool(FUNC_TABLE.get(f & 0x7F, ("", "", True))[2])
    elif f in (0x01, 0x02, 0x03, 0x04):
        _need(f, addr=addr, count=count)
        body = pdu_read(f, addr, count)
        exp = expected_response_len(m, f, count=count)
        summary = "%s addr=%d count=%d" % (func_desc(f), _u16(addr, "addr"), _u16(count, "count"))
        is_write = False
    elif f == 0x05:
        _need(f, addr=addr, value=value)
        body = pdu_write_single_coil(addr, value)
        exp = expected_response_len(m, f)
        summary = "写线圈 addr=%d → %s" % (_u16(addr, "addr"), "ON" if _coil_on(value) else "OFF")
        is_write = True
    elif f == 0x06:
        _need(f, addr=addr, value=value)
        body = pdu_write_single_register(addr, value)
        exp = expected_response_len(m, f)
        summary = "写寄存器 addr=%d ← %d" % (_u16(addr, "addr"), _u16(value))
        is_write = True
    elif f == 0x0F:
        _need(f, addr=addr, values=values)
        body = pdu_write_multiple_coils(addr, values)
        exp = expected_response_len(m, f)
        summary = "写 %d 个线圈 addr=%d 起" % (len(_as_list(values, "values")), _u16(addr, "addr"))
        is_write = True
    elif f == 0x10:
        _need(f, addr=addr, values=values)
        body = pdu_write_multiple_registers(addr, values)
        exp = expected_response_len(m, f)
        summary = "写 %d 个寄存器 addr=%d 起" % (len(_as_list(values, "values")), _u16(addr, "addr"))
        is_write = True
    elif f == 0x17:
        _need(f, read_addr=read_addr, read_count=read_count, write_addr=write_addr,
              write_values=write_values)
        body = pdu_read_write_multiple_registers(read_addr, read_count,
                                                 write_addr, write_values)
        exp = expected_response_len(m, f, read_count=read_count)
        summary = "写 %d 个寄存器@%d 并读 %d 个@%d" % (
            len(_as_list(write_values, "write_values")), _u16(write_addr, "write_addr"),
            _u16(read_count, "read_count"), _u16(read_addr, "read_addr"))
        is_write = True
    elif f == 0x16:
        _need(f, addr=addr, and_mask=and_mask, or_mask=or_mask)
        body = pdu_mask_write_register(addr, and_mask, or_mask)
        exp = expected_response_len(m, f)
        summary = "掩码写寄存器 addr=%d AND=0x%04X OR=0x%04X" % (
            _u16(addr, "addr"), _u16(and_mask, "and_mask"), _u16(or_mask, "or_mask"))
        is_write = True
    elif f == 0x08:
        _need(f, sub_function=sub_function)
        body = pdu_diagnostics(sub_function, data or 0)
        exp = expected_response_len(m, f)
        summary = "诊断 sub=%d data=%d" % (_u16(sub_function, "sub_function"), _u16(data or 0, "data"))
        is_write = False
    elif f in (0x07, 0x0B, 0x0C, 0x11):
        body = pdu_simple(f)
        exp = expected_response_len(m, f)
        summary = func_desc(f)
        is_write = False
    elif f == 0x18:
        _need(f, addr=addr)
        body = pdu_read_fifo_queue(addr)
        exp = None
        summary = "读 FIFO 队列 addr=%d" % _u16(addr, "addr")
        is_write = False
    else:
        raise ValueError("暂不支持标准构造的功能码 0x%02X；私有/不常用功能码请用 pdu 参数"
                         "传裸 PDU，或走 modbus_raw" % f)
    req = pack(m, slave, body)
    return {"request": req, "request_hex": hexdump(req), "mode": m,
            "slave": _u8(slave, "slave"), "func": f, "func_name": func_name(f),
            "func_desc": func_desc(f), "is_write": is_write,
            "expected_len": exp, "summary": "%s | slave=%d %s" % (summary, _u8(slave, "slave"), m.upper()),
            "pdu_hex": hexdump(body)}


def _need(func: int, **kw) -> None:
    miss = [k for k, v in kw.items() if v is None]
    if miss:
        raise ValueError("func 0x%02X（%s）缺少参数：%s" % (int(func), func_desc(func), ", ".join(miss)))


# ----------------------------------------------------------------------
# 帧完整性判定（收够了就返回，不必干等超时）
# ----------------------------------------------------------------------
def frame_complete(buf, mode: str, expected_len=None) -> bool:
    b = bytes(buf)
    if not b:
        return False
    if norm_mode(mode) == "ascii":
        if b[:1] == b":":
            end = b.find(b"\n")
            if end >= 0:
                return True
            if b.find(b"\r") >= 0 and len(b) >= 3:
                return True
        return bool(expected_len and len(b) >= expected_len)
    # RTU：异常帧必然 5 字节；否则按 expected_len
    if len(b) >= 5 and (b[1] & 0x80):
        return True
    return bool(expected_len and len(b) >= expected_len)


# ----------------------------------------------------------------------
# 传输层：独占一个 COM 口的 Modbus 会话
# ----------------------------------------------------------------------
class ModbusSession:
    """一个 COM 口上的 Modbus 主站会话（RTU/ASCII 通用，收发共用同一句柄）。

    - 与 ``serialmon`` 的监听线程不同：这里不做按行切分，收的是**原始字节**，
      按帧间静默切帧（Modbus 是二进制协议，按行切分必然切坏）。
    - 端口是独占资源：同一时刻只能有一个持有者。
    """

    def __init__(self, port: str, baud: int = 9600, databits: int = 8,
                 parity: str = "none", stopbits=1, mode: str = "rtu",
                 timeout_s: float = 1.0, idle_release_s: float = 900.0):
        self.port_in = str(port)
        self.path = serialmon.resolve_port(port)
        self.port = self.path.replace("\\\\.\\", "")
        self.baud = int(baud or 9600)
        self.databits = int(databits or 8)
        self.parity = str(parity or "none").strip().lower()
        try:
            self.stopbits = float(stopbits)
        except (TypeError, ValueError):
            self.stopbits = 1.0
        self.mode = norm_mode(mode)
        self.timeout_s = float(timeout_s or 1.0)
        self.idle_release_s = float(idle_release_s if idle_release_s is not None else 900.0)
        self.dev = None
        self.lock = threading.RLock()
        self.opened_at = 0.0
        self.last_access = 0.0
        self.tx_frames = 0
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.last_error = ""
        self.auto_released = False
        self.release_reason = ""
        self.released_at = 0.0

    # ---- 生命周期 ----
    def open(self) -> dict:
        with self.lock:
            if self.dev is not None:
                return self.status()
            dev = serialmon.HostSerial(self.port_in, baud=self.baud,
                                       databits=self.databits, parity=self.parity,
                                       stopbits=self.stopbits)
            dev.open()
            self.dev = dev
            self.opened_at = time.time()
            self.last_access = self.opened_at
            self.auto_released = False
            self.release_reason = ""
            self.last_error = ""
            return self.status()

    def close(self, reason: str = "") -> dict:
        with self.lock:
            dev, self.dev = self.dev, None
            if dev is not None:
                try:
                    dev.close()
                except Exception:  # noqa: BLE001
                    pass
                self.released_at = time.time()
                self.release_reason = reason or "显式关闭"
            return self.status()

    @property
    def port_held(self) -> bool:
        return self.dev is not None

    @property
    def can_write(self) -> bool:
        return bool(self.dev is not None and self.dev.can_write)

    def touch(self) -> None:
        self.last_access = time.time()

    def _maybe_idle_release(self) -> None:
        if self.dev is None or self.idle_release_s <= 0:
            return
        idle = time.time() - (self.last_access or time.time())
        if idle >= self.idle_release_s:
            self.close("空闲 %.0f 秒未访问（idle_release_s=%g）"
                       % (idle, self.idle_release_s))

    def status(self) -> dict:
        held = self.port_held
        out = {"ok": True, "port": self.port, "baud": self.baud,
               "databits": self.databits, "parity": self.parity,
               "stopbits": self.stopbits,
               "serial_format": "%d%s%d" % (self.databits,
                                            {"none": "N", "even": "E", "odd": "O"}.get(self.parity, "?"),
                                            int(self.stopbits)),
               "mode": self.mode, "port_held": held, "can_write": self.can_write,
               "timeout_ms": int(self.timeout_s * 1000),
               "idle_release_s": self.idle_release_s,
               "tx_frames": self.tx_frames, "tx_bytes": self.tx_bytes,
               "rx_bytes": self.rx_bytes,
               "inter_frame_gap_ms": round(inter_frame_gap_s(
                   self.baud, self.databits, self.parity, self.stopbits) * 1000, 2)}
        if held and self.opened_at:
            out["held_for_s"] = round(time.time() - self.opened_at, 1)
        if not held and self.released_at:
            out["released"] = True
            out["release_reason"] = self.release_reason
        if self.last_error:
            out["last_error"] = self.last_error
        return out

    # ---- 收 ----
    def drain(self, wait_s: float = 0.05) -> int:
        """丢弃端口上滞留的旧字节（上一次超时的残帧会污染本次解析）。"""
        dropped = 0
        deadline = time.time() + max(0.0, wait_s)
        while time.time() < deadline:
            try:
                chunk = self.dev.read()
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
                break
            if not chunk:
                break
            dropped += len(chunk)
        if dropped:
            self.rx_bytes += dropped
        return dropped

    def _read_frames(self, timeout_s: float, max_frames: int = 1,
                     gap_s=None, expected_len=None) -> dict:
        """按帧间静默收帧。返回 {frames, leftover, elapsed_ms, silence_terminated}。"""
        gap = gap_s if gap_s is not None else max(
            inter_frame_gap_s(self.baud, self.databits, self.parity, self.stopbits),
            MIN_GAP_S)
        t0 = time.time()
        deadline = t0 + max(0.0, float(timeout_s))
        frames, buf, t_last = [], bytearray(), None
        silence_terminated = False
        while True:
            now = time.time()
            if now >= deadline:
                break
            try:
                chunk = self.dev.read()
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
                return {"frames": frames, "leftover": bytes(buf),
                        "elapsed_ms": int((time.time() - t0) * 1000),
                        "silence_terminated": silence_terminated,
                        "read_error": str(e)}
            t_read = time.time()
            if chunk:
                self.rx_bytes += len(chunk)
                prev = t_last
                if buf and prev is not None and (t_read - prev) > gap:
                    frames.append(self._frame(bytes(buf), t_read - prev, frames))
                    buf = bytearray()
                    if len(frames) >= max_frames:
                        break
                buf += chunk
                t_last = t_read
                if frame_complete(buf, self.mode, expected_len):
                    frames.append(self._frame(bytes(buf), 0.0, frames))
                    break
            else:
                if buf:
                    frames.append(self._frame(bytes(buf),
                                              (t_read - t_last) if t_last else 0.0, frames))
                    buf = bytearray()
                    if len(frames) >= max_frames:
                        break
                    silence_terminated = True
                    continue
                if frames:
                    silence_terminated = True
                    break
                # 一个字节都还没来：继续等（这才是正常的「等应答」状态）
        return {"frames": frames, "leftover": bytes(buf),
                "elapsed_ms": int((time.time() - t0) * 1000),
                "silence_terminated": silence_terminated,
                "gap_ms": round(gap * 1000, 2)}

    def _frame(self, data: bytes, gap_s: float, prior: list) -> dict:
        """把一段字节包成帧记录：原始 hex/ascii + 尽力解析（解析失败不影响收发）。"""
        parsed = None
        try:
            parsed = parse_frame(data, "auto")
        except Exception as e:  # noqa: BLE001
            parsed = {"ok": False, "error": str(e)}
        out = {"seq": len(prior), "length": len(data), "hex": hexdump(data),
               "ascii": ascii_show(data), "parsed": parsed}
        if gap_s:
            out["gap_ms"] = round(max(0.0, gap_s) * 1000, 1)
        if isinstance(parsed, dict) and parsed.get("ok"):
            out["slave"] = parsed.get("slave")
            out["func"] = parsed.get("func")
            out["func_name"] = parsed.get("func_name")
            if parsed.get("is_exception"):
                out["is_exception"] = True
                out["exception_code"] = parsed.get("exception_code")
                out["exception_text"] = parsed.get("exception_text")
        return out

    # ---- 发 ----
    def transact(self, request: bytes, timeout_s=None, expected_len=None,
                 max_frames: int = 1, gap_s=None, drain=True) -> dict:
        """发一帧、收应答（或按 max_frames 收多帧）。返回结构见模块文档。"""
        req = bytes(request)
        with self.lock:
            self._maybe_idle_release()
            if self.dev is None:
                return {"ok": False, "error": "Modbus 会话当前未打开端口（可能已空闲释放或被关闭）",
                        "error_code": "modbus-session-closed",
                        "hint": "重新调用任意 modbus_* 工具并带上 port 即可重开",
                        "port": self.port}
            if not self.can_write:
                return {"ok": False, "error": "串口以只读方式打开，发不出请求（端口可能被独占）",
                        "error_code": "modbus-port-readonly",
                        "hint": "确认没有别的程序（Keil 串口窗口/其他串口工具）占着该口",
                        "port": self.port}
            self.touch()
            dropped = self.drain() if drain else 0
            try:
                wrote = self.dev.write(req)
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
                return {"ok": False, "error": str(e), "port": self.port,
                        "error_code": "serial-port-busy",
                        "hint": "串口可能已被拔出或占用；serial_list_ports 确认端口还在"}
            self.tx_frames += 1
            self.tx_bytes += wrote
            got = self._read_frames(timeout_s if timeout_s is not None else self.timeout_s,
                                    max_frames=max_frames, gap_s=gap_s,
                                    expected_len=expected_len if max_frames == 1 else None)
            self.touch()
            frames = got["frames"]
            out = {"ok": bool(frames), "port": self.port, "mode": self.mode,
                   "baud": self.baud,
                   "request_hex": hexdump(req), "sent_bytes": wrote,
                   "elapsed_ms": got["elapsed_ms"], "frame_count": len(frames),
                   "frames": frames,
                   "silence_terminated": got["silence_terminated"],
                   "inter_frame_gap_ms": got.get("gap_ms"),
                   "discarded_before_tx": dropped}
            if frames:
                out["response_hex"] = frames[0]["hex"]
                out["response_parsed"] = frames[0].get("parsed")
                _p = frames[0].get("parsed") or {}
                if _p.get("ok"):
                    out["response"] = _p.get("decode")
                # 字节回来了不等于帧是对的：CRC 不过 / 半帧 / 非 Modbus 都要说清楚。
                # 这里给的是「解析结论」，真正的成败由上层工具按语义决定
                # （modbus_raw 收私有帧也算成功，modbus_read 则必须帧合法）。
                out["parsed_ok"] = bool(_p.get("ok") or _p.get("is_exception"))
                if not out["parsed_ok"]:
                    out["parse_error"] = _p.get("error") or "收到的帧不符合 Modbus 结构"
                    out["parse_error_code"] = _p.get("error_code") or "modbus-bad-frame"
                if len(frames) > 1:
                    out["multi_frame_note"] = ("收到 %d 段帧（按静默切分）：可能有多个从站应答、"
                                               "或上一次请求的残帧——请按 slave 字段核对"
                                               % len(frames))
            elif got.get("leftover"):
                out["error"] = ("收到 %d 字节但不是完整帧（帧间静默/超时先到）：%s"
                                % (len(got["leftover"]), hexdump(got["leftover"])))
                out["error_code"] = "modbus-bad-frame"
                out["response_hex"] = hexdump(got["leftover"])
            else:
                out["error"] = ("%.0fms 内一个字节都没收到（请求已发出 %d 字节）"
                                % (timeout_s if timeout_s is not None else self.timeout_s,
                                   wrote))
                out["error_code"] = "modbus-timeout-no-response"
                out["no_response"] = True
            if got.get("read_error"):
                out["error"] = "读串口失败：%s" % got["read_error"]
                out["error_code"] = "serial-port-busy"
            return out

    def sniff(self, duration_s: float = 3.0, max_frames: int = 200,
              gap_s=None) -> dict:
        """被动旁听：不发送任何字节，只按静默切分总线上出现的帧。"""
        with self.lock:
            self._maybe_idle_release()
            if self.dev is None:
                return {"ok": False, "error": "Modbus 会话当前未打开端口",
                        "error_code": "modbus-session-closed",
                        "hint": "带上 port 重新调用即可重开", "port": self.port}
            self.touch()
            got = self._read_frames(duration_s, max_frames=max_frames, gap_s=gap_s,
                                    expected_len=None)
            self.touch()
            return {"ok": True, "port": self.port, "mode": self.mode,
                    "duration_ms": int(duration_s * 1000),
                    "frame_count": len(got["frames"]), "frames": got["frames"],
                    "bytes": sum(f["length"] for f in got["frames"]),
                    "elapsed_ms": got["elapsed_ms"],
                    "leftover_hex": hexdump(got["leftover"]) if got["leftover"] else "",
                    "note": "被动旁听：本工具不发送任何字节；帧按静默间隔切分，"
                            "总线上没有别的请求时可能一帧都收不到"}


# ----------------------------------------------------------------------
# 会话管理（模块级单例：同一时刻只持有一个 COM 口）
# ----------------------------------------------------------------------
_SESSION = None
_SESS_LOCK = threading.RLock()


def current():
    with _SESS_LOCK:
        return _SESSION


def _set_session(s):
    global _SESSION
    with _SESS_LOCK:
        _SESSION = s


def _same_target(s, path: str, baud: int, databits: int, parity: str,
                 stopbits: float, mode: str) -> bool:
    return (s is not None and s.path == path and s.baud == int(baud)
            and s.databits == int(databits)
            and s.parity == str(parity or "none").strip().lower()
            and float(s.stopbits) == float(stopbits) and s.mode == mode)


def open_session(port: str, baud: int = 9600, databits: int = 8,
                 parity: str = "none", stopbits=1, mode: str = "rtu",
                 timeout_s: float = 1.0, serial_format: str = "",
                 force: bool = False) -> dict:
    """打开（或复用）一个 Modbus 会话。

    - 同口同参数 → **复用**，不重新打开（避免把串口关了又开、DTR 抖动复位目标板）。
    - 同口不同参数 / 换口 → 关掉旧的再开新的，并在返回里说明 ``replaced``。
    - 端口被 serialmon 的日志监听占着 → 明确报错，不抢口。
    """
    db, par, sb = parse_serial_format(serial_format)
    if db is not None:
        databits, parity, stopbits = db, par, sb
    m = norm_mode(mode)
    par = str(parity or "none").strip().lower()
    if par not in serialmon._PARITY:  # noqa: SLF001 —— 复用同一张表，避免两处定义漂移
        raise ValueError("校验位只支持 none/odd/even/mark/space，收到: %s" % parity)
    try:
        sb = float(stopbits)
    except (TypeError, ValueError):
        sb = 1.0
    if sb not in serialmon._STOPBITS:  # noqa: SLF001
        raise ValueError("停止位只支持 1 / 1.5 / 2，收到: %s" % stopbits)
    path = serialmon.resolve_port(port)
    if not path:
        return {"ok": False, "error": "port 为空：Modbus 要打开哪个串口？",
                "error_code": "serial-port-not-found",
                "hint": "先调 serial_list_ports 看本机串口与芯片推断"}
    # 与串口日志监听的口冲突：显式报错（抢口会导致两边都收到错数据）
    mon = serialmon.current()
    if mon is not None and getattr(mon, "port_held", False) and \
            serialmon.resolve_port(mon.port) == path:
        return {"ok": False,
                "error": "串口 %s 正被串口日志监听占用（同一时刻只能一个持有者）" % port,
                "error_code": "modbus-port-held-by-monitor",
                "hint": "先 serial_monitor_stop() 释放该口，再调 modbus_*；"
                        "Modbus 是二进制帧协议，按行切分的日志监听接不了它"}
    with _SESS_LOCK:
        cur = _SESSION
        if cur is not None and not force and _same_target(
                cur, path, baud, databits, par, sb, m):
            cur.touch()
            # 复用时不重开口（避免 DTR 抖动复位目标板），但超时要跟着本次参数走
            cur.timeout_s = float(timeout_s or 1.0)
            return {"ok": True, "session": cur, "reused": True, "opened": False,
                    "status": cur.status()}
        replaced = None
        if cur is not None:
            replaced = {"port": cur.port, "reason": "换口/换参数" if not force else "强制重开"}
            cur.close("被新的 Modbus 会话替换（%s）" % replaced["reason"])
        s = ModbusSession(port, baud=baud, databits=databits, parity=par,
                          stopbits=sb, mode=m, timeout_s=timeout_s)
        try:
            s.open()
        except Exception as e:  # noqa: BLE001
            _set_session(None)
            msg = str(e)
            code = "serial-port-busy" if ("WinError=5" in msg or "被占用" in msg) \
                else "serial-port-not-found"
            return {"ok": False, "error": "打开串口失败：%s" % msg, "error_code": code,
                    "hint": "确认口没被别的程序（Keil 串口窗口 / 其他串口工具）占用；"
                            "serial_list_ports 确认端口还在",
                    "port": port}
        _set_session(s)
        out = {"ok": True, "session": s, "reused": False, "opened": True,
               "status": s.status()}
        if replaced:
            out["replaced"] = replaced
        return out


def ensure(port: str = "", baud: int = 9600, databits: int = 8, parity: str = "none",
           stopbits=1, mode: str = "rtu", timeout_s: float = 1.0,
           serial_format: str = "") -> dict:
    """工具入口用：给了 port 就换/复用；没给就沿用已有会话。"""
    if not str(port or "").strip():
        cur = current()
        if cur is None:
            return {"ok": False, "error": "还没有打开的 Modbus 会话，且本次没给 port",
                    "error_code": "modbus-no-session",
                    "hint": "带上 port（如 port=\"COM9\"）与 baud/串口格式重新调用；"
                            "不确定口用 serial_list_ports"}
        if serial_format or baud != 9600 or parity != "none":
            # 显式给了串口参数却不给 port：不确定用户想改哪个口，直接问清楚
            return {"ok": False,
                    "error": "已给串口参数但没给 port，无法判断要作用在哪个口上",
                    "error_code": "modbus-no-port",
                    "hint": "要么只给 port，要么把 port 一起给上（当前会话在 %s）" % cur.port}
        cur.touch()
        return {"ok": True, "session": cur, "reused": True, "opened": False}
    try:
        return open_session(port, baud=baud, databits=databits, parity=parity,
                            stopbits=stopbits, mode=mode, timeout_s=timeout_s,
                            serial_format=serial_format)
    except ValueError as e:
        return {"ok": False, "error": str(e), "error_code": "invalid-argument"}


def close_session() -> dict:
    global _SESSION
    with _SESS_LOCK:
        s = _SESSION
        _SESSION = None
    if s is None:
        return {"ok": True, "closed": False, "note": "当前没有打开的 Modbus 会话"}
    st = s.close("显式关闭（modbus_session action=close）")
    return {"ok": True, "closed": True, "status": st}


def session_status() -> dict:
    s = current()
    if s is None:
        return {"ok": True, "port_held": False, "note": "当前没有打开的 Modbus 会话"}
    return s.status()


def _release_on_exit() -> None:
    s = current()
    if s is not None and s.port_held:
        try:
            s.close("进程退出自动释放")
        except Exception:  # noqa: BLE001
            pass


atexit.register(_release_on_exit)


# ----------------------------------------------------------------------
# 从站号范围解析（scan 用）
# ----------------------------------------------------------------------
def parse_slave_range(spec) -> list:
    """解析 '1-247' / '1,3,5' / '1-16,20' 成排好序的从站号列表。

    越界或格式错直接报错——**不静默丢弃**：少扫了几个从站却报「扫描完成」，
    比报错难查得多。
    """
    if spec is None or str(spec).strip() == "":
        return list(range(1, 248))
    if isinstance(spec, (list, tuple, set)):
        toks = [str(x) for x in spec]
    else:
        toks = [t for t in re.split(r"[\s,;]+", str(spec).strip()) if t]
    out = []
    for t in toks:
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", t)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            if a < 1 or b > 247:
                raise ValueError("从站号范围 %s 越界：Modbus 从站号是 1~247" % t)
            out.extend(range(a, b + 1))
            continue
        if not t.isdigit():
            raise ValueError("从站号写法不认识：%r（支持 3 / 1-16 / 1,3,5）" % t)
        v = int(t)
        if not 1 <= v <= 247:
            raise ValueError("从站号 %d 越界：Modbus 从站号是 1~247（0 是广播，不能单点查询）" % v)
        out.append(v)
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq
