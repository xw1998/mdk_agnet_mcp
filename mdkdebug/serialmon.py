# -*- coding: utf-8 -*-
"""宿主机串口日志监听：ring buffer + read（批次29 反馈④）。

为什么需要
----------
调 RT-Thread / 裸机日志时，最常用的通路是 USB-TTL 出来的 COM 口（不是调试器的
ITM/SWO）。此前只能"用外部 Python 脚本抓一份"，AI 自己看不到——每轮排查都要人肉
转达，等于整个调试闭环缺一段。这里把宿主机串口也纳入工具面：一个后台监听线程
持续读 COM 口，按行进 ring buffer，AI 用 ``serial_read`` 随时取增量。

设计要点
--------
- **零新依赖**：Windows 串口用 ctypes（CreateFile/SetCommState/ReadFile/WriteFile），不引入 pyserial，
  部署端不需要重装依赖。
- **ring buffer 而不是文件**：容量有限（默认 2000 行）、按 seq 增量读，
  支持 ``since``/``clear``，长时间监听不会把内存吃爆，也不会让 AI 反复重读全部日志。
- **断线自愈**：USB 串口拔插/被占用会报错，监听线程记录 ``last_error`` 并按退避重连，
  不静默死掉（``status`` 里能看到 ``reopen_count`` 与错误原因）。
- **默认按行切分**：日志是行导向的，半行留在 ``partial`` 里，状态查询可见。
- **可收也可发**：端口打开时优先按「可读可写」获取（``GENERIC_READ|GENERIC_WRITE``），
  因此能在同一条调试链路上「一边收日志、一边下发 shell 命令 / 镜像片段」；
  若驱动或占用只允许只读，则自动退回只读并置 ``can_write=False``，不影响监听（``serial_write``
  会明确告诉你该口当前不可写）。
- **用完就还**：调试/烧录一结束就主动释放 COM 口（否则 Keil 串口窗口等会被 WinError=5 挡住）。
  释放只放掉**端口**，ring buffer 里的日志照旧保留、``serial_read`` 继续可读；
  需要接着采集时重新 ``serial_monitor_start()``，同端口同波特率会**复用同一实例**，不丢已收日志。
  除显式 stop 外还有两个兜底：进程退出（atexit）与空闲超时（``idle_release_s``，默认 900 秒，0=不自动）。
"""
from __future__ import annotations

import atexit
import ctypes
import logging
import os
import re
import sys
import threading
import time

logger = logging.getLogger("mdkdebug.serialmon")

DEFAULT_CAPACITY = 2000
MAX_CAPACITY = 20000
DEFAULT_BAUD = 115200
DEFAULT_IDLE_RELEASE_S = 900.0   # 空闲多久自动释放端口（0=不自动释放）
_MAX_PARTIAL = 8192          # 单行上限：超长（无换行的刷屏）按行强制落盘，避免无限增长
_READ_BUF = 4096
_PARITY = {"none": 0, "n": 0, "odd": 1, "o": 1, "even": 2, "e": 2,
           "mark": 3, "m": 3, "space": 4, "s": 4}
_STOPBITS = {1: 0, 1.5: 1, 2: 2}

# ----------------------------------------------------------------------
# ring buffer
# ----------------------------------------------------------------------
class RingBuffer:
    """定长环形缓冲：保留最近 capacity 条，按自增 seq 支持增量读取。"""

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self.capacity = max(1, min(int(capacity or DEFAULT_CAPACITY), MAX_CAPACITY))
        self._buf: list = []
        self._start = 0          # _buf[0] 的全局序号
        self._next = 0           # 下一条的全局序号
        self.dropped = 0
        self._lock = threading.Lock()

    def append(self, item) -> bool:
        with self._lock:
            self._buf.append(item)
            self._next += 1
            over = len(self._buf) - self.capacity
            if over > 0:
                del self._buf[:over]
                self._start += over
                self.dropped += over
                return True
            return False

    def read(self, max_items: int = 200, clear: bool = False,
             since: int | None = None) -> dict:
        with self._lock:
            lo = self._start
            if since is not None:
                try:
                    lo = max(lo, int(since))
                except (TypeError, ValueError):
                    lo = self._start
            items = [it for it in self._buf if int(it.get("seq", 0)) >= lo]
            truncated = False
            if max_items and len(items) > int(max_items):
                items = items[-int(max_items):]
                truncated = True
            out = {"items": items, "count": len(items),
                   "next_seq": self._next, "first_seq": self._start,
                   "dropped": self.dropped, "truncated": truncated,
                   "capacity": self.capacity, "size": len(self._buf)}
            if clear:
                self._buf = []
                self._start = self._next
            return out

    def clear(self) -> None:
        with self._lock:
            self._buf = []
            self._start = self._next

    def stats(self) -> dict:
        with self._lock:
            return {"capacity": self.capacity, "size": len(self._buf),
                    "first_seq": self._start, "next_seq": self._next,
                    "dropped": self.dropped}

# ----------------------------------------------------------------------
# 宿主机串口（Windows / ctypes）
# ----------------------------------------------------------------------
class _COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [("ReadIntervalTimeout", ctypes.c_uint32),
                ("ReadTotalTimeoutMultiplier", ctypes.c_uint32),
                ("ReadTotalTimeoutConstant", ctypes.c_uint32),
                ("WriteTotalTimeoutMultiplier", ctypes.c_uint32),
                ("WriteTotalTimeoutConstant", ctypes.c_uint32)]

class _DCBFlags(ctypes.Structure):
    _fields_ = [("fBinary", ctypes.c_uint32, 1),
                ("fParity", ctypes.c_uint32, 1),
                ("fOutxCtsFlow", ctypes.c_uint32, 1),
                ("fOutxDsrFlow", ctypes.c_uint32, 1),
                ("fDtrControl", ctypes.c_uint32, 2),
                ("fDsrSensitivity", ctypes.c_uint32, 1),
                ("fTXContinueOnXoff", ctypes.c_uint32, 1),
                ("fOutX", ctypes.c_uint32, 1),
                ("fInX", ctypes.c_uint32, 1),
                ("fErrorChar", ctypes.c_uint32, 1),
                ("fNull", ctypes.c_uint32, 1),
                ("fRtsControl", ctypes.c_uint32, 2),
                ("fAbortOnError", ctypes.c_uint32, 1),
                ("fDummy2", ctypes.c_uint32, 17)]

class _DCB(ctypes.Structure):
    _fields_ = [("DCBlength", ctypes.c_uint32),
                ("BaudRate", ctypes.c_uint32),
                ("flags", _DCBFlags),
                ("wReserved", ctypes.c_uint16),
                ("XonLim", ctypes.c_uint16),
                ("XoffLim", ctypes.c_uint16),
                ("ByteSize", ctypes.c_uint8),
                ("Parity", ctypes.c_uint8),
                ("StopBits", ctypes.c_uint8),
                ("XonChar", ctypes.c_char),
                ("XoffChar", ctypes.c_char),
                ("ErrorChar", ctypes.c_char),
                ("EofChar", ctypes.c_char),
                ("EvtChar", ctypes.c_char),
                ("wReserved1", ctypes.c_uint16)]

def list_ports() -> list:
    """枚举本机串口（读注册表 DEVICEMAP\\SERIALCOMM；失败返回空表）。"""
    if sys.platform != "win32":
        return []
    out = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DEVICEMAP\SERIALCOMM") as k:
            i = 0
            while True:
                try:
                    _name, val, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append(str(val))
                i += 1
    except Exception:  # noqa: BLE001
        return []
    return sorted(set(out), key=lambda s: (len(s), s))

# ----------------------------------------------------------------------
# 串口详细枚举（批次33：吸收 embeddedskills / Serial-Agent 的「先列口再动手」）
# ----------------------------------------------------------------------
# 为什么需要单列一个「详细枚举」：只有 COM9/COM10 这样的名字时，AI 无从判断哪个口
# 才是目标板载 USB-TTL（还是调试器的 VCP、还是一个蓝牙虚拟口）。这里补上
# 「设备描述 + 硬件 ID(VID/PID) + 芯片推断」，让选口有依据，而不是靠试。
_CHIP_VIDPID = {
    "1A86:7523": "CH340（USB-TTL，最常见的廉价小板）",
    "1A86:7522": "CH340 变体",
    "1A86:5523": "CH341",
    "1A86:55D4": "CH9102（CH340 后续型号）",
    "10C4:EA60": "CP2102/CP210x（USB-TTL）",
    "10C4:EA70": "CP2105",
    "10C4:EA71": "CP2108",
    "0403:6001": "FT232R（USB-TTL）",
    "0403:6010": "FT2232（双通道，常用于调试器自带 VCP）",
    "0403:6011": "FT4232",
    "0403:6014": "FT232H",
    "0403:6015": "FT231X",
    "067B:2303": "PL2303（老款 USB-TTL）",
    "0483:5740": "STM32 Virtual COM Port（ST 官方 VCP，多为 ST-Link/板载 USB）",
    "2341:0043": "Arduino Uno",
    "2341:0001": "Arduino",
    "0D28:0204": "mbed / DAPLink VCP",
    "2E8A:0005": "Raspberry Pi Pico（PicoProbe VCP）",
}
# 描述不含 VID/PID 时（个别驱动只给名字）的关键词兜底
_CHIP_KEYWORDS = (
    ("ch340", "CH340（USB-TTL）"),
    ("ch341", "CH341"),
    ("ch9102", "CH9102"),
    ("cp210", "CP210x（USB-TTL）"),
    ("ft232", "FT232R"),
    ("pl2303", "PL2303"),
    ("stlink", "ST-Link（含 VCP）"),
    ("st-link", "ST-Link（含 VCP）"),
    ("jlink", "J-Link（含 VCP）"),
    ("virtual com", "虚拟串口（VCP，通常来自调试器或板载 USB）"),
    ("蓝牙", "蓝牙虚拟串口（通常不是目标板日志口）"),
    ("bluetooth", "蓝牙虚拟串口（通常不是目标板日志口）"),
)

class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_uint8 * 8)]

class _SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("ClassGuid", _GUID),
                ("DevInst", ctypes.c_uint32), ("Reserved", ctypes.c_size_t)]

# {86E0D1E0-8089-11D0-9CE4-08003E301F73} = GUID_DEVINTERFACE_COMPORT
_GUID_COMPORT = _GUID(0x86E0D1E0, 0x8089, 0x11D0,
                      (ctypes.c_uint8 * 8)(0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73))
_DIGCF_PRESENT = 0x02
_DIGCF_DEVICEINTERFACE = 0x10
_SPDRP_DEVICEDESC = 0x00
_SPDRP_HARDWAREID = 0x01
_SPDRP_FRIENDLYNAME = 0x0C
_DICS_FLAG_GLOBAL = 0x01
_DIREG_DEV = 0x01
_KEY_READ = 0x20019

def _dev_prop(setupapi, h, di, prop) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    need = ctypes.c_uint32(0)
    ok = setupapi.SetupDiGetDeviceRegistryPropertyW(
        h, ctypes.byref(di), ctypes.c_uint32(prop), None, buf,
        ctypes.c_uint32(ctypes.sizeof(buf)), ctypes.byref(need))
    if not ok:
        return ""
    return buf.value.strip()

def _dev_port(setupapi, advapi, h, di) -> str:
    key = setupapi.SetupDiOpenDevRegKey(h, ctypes.byref(di), ctypes.c_uint32(_DICS_FLAG_GLOBAL),
                                        ctypes.c_uint32(0), ctypes.c_uint32(_DIREG_DEV),
                                        ctypes.c_uint32(_KEY_READ))
    if not key or key == ctypes.c_void_p(-1).value:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(256)
        size = ctypes.c_uint32(ctypes.sizeof(buf))
        r = advapi.RegQueryValueExW(key, ctypes.c_wchar_p("PortName"), None, None,
                                    buf, ctypes.byref(size))
        if r != 0:
            return ""
        return buf.value.strip()
    finally:
        advapi.RegCloseKey(key)

def _chip_from(hwid: str, desc: str) -> str:
    m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", hwid or "",
                  re.IGNORECASE)
    if m:
        key = "%s:%s" % (m.group(1).upper(), m.group(2).upper())
        if key in _CHIP_VIDPID:
            return _CHIP_VIDPID[key]
        return "未收录的 VID/PID：%s" % key
    d = (desc or "").lower()
    for kw, name in _CHIP_KEYWORDS:
        if kw in d:
            return name
    return ""

def _setupapi_ports() -> list:
    """用 SetupAPI 枚举串口设备（描述 / 硬件 ID / PortName）。失败返回空表。"""
    if sys.platform != "win32":
        return []
    out = []
    try:
        setupapi = ctypes.WinDLL("setupapi")
        advapi = ctypes.WinDLL("advapi32")
        setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
        setupapi.SetupDiGetClassDevsW.argtypes = [
            ctypes.POINTER(_GUID), ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
        setupapi.SetupDiEnumDeviceInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_SP_DEVINFO_DATA)]
        setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_SP_DEVINFO_DATA), ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        setupapi.SetupDiOpenDevRegKey.restype = ctypes.c_void_p
        setupapi.SetupDiOpenDevRegKey.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_SP_DEVINFO_DATA), ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        h = setupapi.SetupDiGetClassDevsW(ctypes.byref(_GUID_COMPORT), None, None,
                                          _DIGCF_PRESENT | _DIGCF_DEVICEINTERFACE)
        if not h or h == ctypes.c_void_p(-1).value:
            return []
        try:
            i = 0
            while True:
                di = _SP_DEVINFO_DATA()
                di.cbSize = ctypes.sizeof(_SP_DEVINFO_DATA)
                if not setupapi.SetupDiEnumDeviceInfo(h, ctypes.c_uint32(i), ctypes.byref(di)):
                    break
                i += 1
                port = _dev_port(setupapi, advapi, h, di)
                if not port:
                    continue
                desc = _dev_prop(setupapi, h, di, _SPDRP_FRIENDLYNAME) or \
                       _dev_prop(setupapi, h, di, _SPDRP_DEVICEDESC)
                hwid = _dev_prop(setupapi, h, di, _SPDRP_HARDWAREID)
                vm = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", hwid or "")
                out.append({
                    "port": port,
                    "description": desc,
                    "hwid": hwid,
                    "vid": vm.group(1).upper() if vm else "",
                    "pid": vm.group(2).upper() if vm else "",
                    "likely_chip": _chip_from(hwid, desc),
                    "source": "setupapi",
                })
        finally:
            try:
                setupapi.SetupDiDestroyDeviceInfoList(ctypes.c_void_p(h))
            except Exception:  # noqa: BLE001
                pass
    except Exception as e:  # noqa: BLE001
        logger.debug("SetupAPI 枚举串口失败（退回注册表模式）：%s", e)
        return []
    return out

def list_ports_detailed() -> list:
    """枚举本机串口，附带描述 / VID / PID / 芯片推断。

    注册表（SERIALCOMM）为准——它列出的就是当前真正存在的 COM 名；
    SetupAPI 用来补描述与硬件 ID。两条路都没结果时返回空表（不抛错）。
    """
    detail = {}
    for d in _setupapi_ports():
        detail[str(d.get("port") or "").upper()] = d
    names = list_ports()
    out = []
    for p in names:
        d = detail.get(str(p).upper())
        if d:
            out.append(d)
        else:
            out.append({"port": p, "description": "", "hwid": "", "vid": "", "pid": "",
                        "likely_chip": "", "source": "registry"})
    for key, d in detail.items():
        if key not in {str(x).upper() for x in names}:
            out.append(d)
    return out

def pick_port(prefer: str = "", ports: list | None = None) -> dict:
    """按「显式优先 → 唯一候选自动 → 多候选列候选 → 无候选报错」选串口。

    这条规则吸收自 embeddedskills / Serial-Agent 的 playbook 第一条：
    多候选时**不许替调用方挑一个**，要把候选摊开让它确认。
    """
    plist = ports if ports is not None else list_ports_detailed()
    names = []
    for x in plist:
        n = str(x.get("port") if isinstance(x, dict) else x)
        if n:
            names.append(n)
    want = str(prefer or "").strip()
    if want:
        w = want.upper()
        wnum = w[3:] if w.startswith("COM") else w
        for n in names:
            nu = n.upper()
            if nu == w or (nu.startswith("COM") and nu[3:] == wnum):
                return {"port": n, "auto": False, "candidates": names, "need_choice": False,
                        "source": "explicit", "reason": "使用调用方显式指定的串口"}
        return {"port": "", "auto": False, "candidates": names, "need_choice": bool(names),
                "source": "explicit",
                "reason": "显式指定的 %s 不在本机串口列表中" % want}
    if len(names) == 1:
        return {"port": names[0], "auto": True, "candidates": names, "need_choice": False,
                "source": "auto", "reason": "本机只有一个串口，已自动采用"}
    if not names:
        return {"port": "", "auto": False, "candidates": [], "need_choice": False,
                "source": "auto", "reason": "本机未发现任何串口"}
    return {"port": "", "auto": False, "candidates": names, "need_choice": True,
            "source": "auto",
            "reason": "本机有 %d 个串口，多候选不自动选择，请按 candidates 显式指定" % len(names)}

def expect(pattern: str, timeout_s: float = 5.0, since: int | None = None,
           regex: bool = True, case_sensitive: bool = True,
           poll_ms: int = 50, max_lines: int = 200,
           include_partial: bool = True, encoding: str = "utf-8") -> dict:
    """等待串口出现匹配 pattern 的新内容（原子「发完就等」的等待侧）。

    与 wait_breakpoint 同一口径：**只认本次等待期间新出现的内容**——
    since 省略时取调用瞬间的 next_seq 作为基线，缓冲区里的老日志不会被当成命中，
    避免「目标早就在刷这句话」被误判成这次请求得到了响应。

    include_partial=True 时把「还没等到换行的半行」也纳入匹配：rt_kprintf 之类的
    输出常常没有 \n，只匹配整行会永远等不到（这是真实调试里最容易踩的一格）。
    """
    m = _monitor
    if m is None:
        return {"ok": False, "matched": False,
                "error": "当前没有串口监听在运行",
                "hint": "serial_expect 依赖监听持有端口：先 serial_monitor_start(port=..., baud=...)",
                "available_ports": list_ports()}
    if not str(pattern or ""):
        return {"ok": False, "matched": False,
                "error": "参数不足：pattern（要等待的内容）不能为空"}
    flags = 0 if case_sensitive else re.IGNORECASE
    if regex:
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"ok": False, "matched": False,
                    "error": "正则编译失败（pattern=%s）：%s。若想按字面文本匹配请传 regex=false"
                             % (pattern, e)}
    else:
        rx = re.compile(re.escape(pattern), flags)

    m.touch()
    base = m.rb.stats()["next_seq"] if since is None else int(since)
    bytes_before = m.bytes_total
    t0 = time.time()
    deadline = t0 + max(float(timeout_s or 0), 0.0)
    poll = max(0.01, min(float(poll_ms or 50) / 1000.0, 1.0))
    seen = {"count": 0, "next_seq": base, "last_error": None}
    while True:
        r = m.read(max_items=max(int(max_lines or 200), 1), since=base)
        seen["count"] = r.get("count") or 0
        seen["next_seq"] = r.get("next_seq")
        seen["last_error"] = r.get("last_error")
        lines = [str(x) for x in (r.get("lines") or [])]
        partial = str(r.get("partial") or "")
        text = "\n".join(lines)
        hit = None
        where = ""
        mo = rx.search(text)
        if mo is not None:
            hit, where = mo, "line"
        elif include_partial and partial:
            mo2 = rx.search(partial)
            if mo2 is not None:
                hit, where = mo2, "partial"
        if hit is not None:
            idx = text[:hit.start()].count("\n") if where == "line" else len(lines)
            return {
                "ok": True, "matched": True, "pattern": pattern,
                "regex": bool(regex), "case_sensitive": bool(case_sensitive),
                "matched_text": hit.group(0), "matched_group": (
                    hit.group(1) if hit.groups() else None),
                "matched_source": where,
                "matched_line": (lines[idx] if (where == "line" and idx < len(lines)) else partial),
                "matched_index": idx if where == "line" else None,
                "waited_ms": int((time.time() - t0) * 1000),
                "timeout_s": float(timeout_s or 0), "since": base,
                "next_seq": r.get("next_seq"),
                "new_lines": seen["count"],
                "items": r.get("items"), "lines": lines,
                "bytes_new": int(m.bytes_total) - bytes_before,
                "first_seq": r.get("first_seq"), "dropped": r.get("dropped"),
                "truncated": r.get("truncated"), "partial": partial,
                "port": m.port,
                "note": "命中等待期间新出现的内容（since=%d）；matched_source=%s" % (base, where),
            }
        if time.time() >= deadline:
            break
        time.sleep(poll)

    waited = int((time.time() - t0) * 1000)
    r = m.read(max_items=max(int(max_lines or 200), 1), since=base)
    lines = [str(x) for x in (r.get("lines") or [])]
    out = {
        "ok": False, "matched": False, "pattern": pattern,
        "regex": bool(regex), "case_sensitive": bool(case_sensitive),
        "waited_ms": waited, "timeout_s": float(timeout_s or 0), "since": base,
        "next_seq": r.get("next_seq"), "new_lines": r.get("count"),
        "items": r.get("items"), "lines": lines,
        "bytes_new": int(m.bytes_total) - bytes_before,
        "first_seq": r.get("first_seq"), "dropped": r.get("dropped"),
        "truncated": r.get("truncated"), "partial": r.get("partial") or "",
        "port": m.port, "last_error": seen.get("last_error"),
    }
    # 超时不是「调用失败」而是「没等到」——给出机器可读的区分，别让它落进 unknown-error：
    # no-data  = 一个字节都没新增（目标没输出 / 下发没被接受 / 波特率接线不对）
    # no-match = 有输出但对不上 pattern（pattern 太严或等错了内容）
    no_data = (not int(r.get("count") or 0)) and (not (int(m.bytes_total) - bytes_before))
    out["timeout"] = True
    out["timeout_kind"] = "no-data" if no_data else "no-match"
    out["error_code"] = ("serial-expect-timeout-no-data" if no_data
                         else "serial-expect-timeout-no-match")
    if no_data:
        out["note"] = ("%dms 内串口**一个字节都没有新增**：目标可能没在输出、"
                       "或本次请求根本没被目标接受（先确认下发是否成功、波特率是否正确）。"
                       "当前缓冲区里的老日志会被刻意忽略，不作为命中。" % waited)
    else:
        out["note"] = ("%dms 内新增 %s 行但都不匹配：把 pattern 放宽（regex=false 按字面匹配、"
                       "或不区分大小写），也可加大 timeout_s 或把上述 lines 作为线索。"
                       % (waited, r.get("count")))
    return out

def resolve_port(port) -> str:
    """把 'COM9' / 9 / '\\\\.\\COM9' 统一成 CreateFile 可用的 '\\\\.\\COM9'。"""
    p = str(port or "").strip().strip('"')
    if not p:
        return ""
    if p.upper().startswith("\\\\.\\"):
        return p
    if p.isdigit():
        p = "COM" + p
    if not p.upper().startswith("COM"):
        p = "COM" + p
    return "\\\\.\\" + p.upper()

class HostSerial:
    """最小的 Windows 串口读写封装（ctypes，无第三方依赖）。"""

    def __init__(self, port: str, baud: int = DEFAULT_BAUD, databits: int = 8,
                 parity: str = "none", stopbits=1):
        self.port_in = str(port)
        self.path = resolve_port(port)
        self.baud = int(baud or DEFAULT_BAUD)
        self.databits = int(databits or 8)
        par = str(parity or "none").strip().lower()
        if par not in _PARITY:
            raise ValueError("parity 只支持 none/odd/even/mark/space，收到: %s" % parity)
        self.parity = _PARITY[par]
        self.parity_name = par
        try:
            sb = float(stopbits)
        except (TypeError, ValueError):
            sb = 1.0
        if sb not in _STOPBITS:
            sb = 1.0
        self.stopbits = sb
        self.handle = None
        self._k32 = None
        self.can_write = False          # 打开时是否拿到了写权限（批次30 反馈⑤）
        self._wlock = threading.Lock()  # 串行化写入，避免与监听线程互相穿插

    # ---- 打开 / 关闭 ----
    def open(self) -> None:
        if sys.platform != "win32":
            raise OSError("宿主机串口监听目前仅支持 Windows（当前平台 %s）" % sys.platform)
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32 = self._k32
        k32.CreateFileW.restype = ctypes.c_void_p
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        # 优先「可读可写」：调 shell / 下发镜像需要能写（批次30 反馈⑤）。拿不到写权限
        # 时退回只读，宁可能收日志但发不出去，也不要整个监听打不开。
        h = k32.CreateFileW(ctypes.c_wchar_p(self.path), GENERIC_READ | GENERIC_WRITE,
                            0, None, OPEN_EXISTING, 0, None)
        self.can_write = True
        if not h or h == ctypes.c_void_p(-1).value:
            h = k32.CreateFileW(ctypes.c_wchar_p(self.path), GENERIC_READ, 0, None,
                                OPEN_EXISTING, 0, None)
            self.can_write = False
        if not h or h == ctypes.c_void_p(-1).value:
            err = ctypes.get_last_error()
            raise OSError(self._explain_open_error(err))
        self.handle = h
        try:
            dcb = _DCB()
            dcb.DCBlength = ctypes.sizeof(_DCB)
            if not k32.GetCommState(ctypes.c_void_p(h), ctypes.byref(dcb)):
                raise OSError("GetCommState 失败（err=%d）" % ctypes.get_last_error())
            dcb.BaudRate = self.baud
            dcb.ByteSize = self.databits
            dcb.Parity = self.parity
            dcb.StopBits = _STOPBITS[int(self.stopbits)] if self.stopbits in (1.0, 2.0) \
                else _STOPBITS.get(self.stopbits, 0)
            dcb.flags.fBinary = 1
            dcb.flags.fParity = 1 if self.parity else 0
            dcb.flags.fDtrControl = 1        # DTR_CONTROL_ENABLE：多数 USB-TTL 需要拉 DTR
            dcb.flags.fRtsControl = 1        # RTS_CONTROL_ENABLE
            dcb.flags.fAbortOnError = 0
            if not k32.SetCommState(ctypes.c_void_p(h), ctypes.byref(dcb)):
                raise OSError("SetCommState 失败（err=%d，检查波特率/校验位是否被驱动支持）"
                              % ctypes.get_last_error())
            to = _COMMTIMEOUTS(20, 0, 100, 0, 1000)   # 最多阻塞 ~120ms，便于线程及时退出
            if not k32.SetCommTimeouts(ctypes.c_void_p(h), ctypes.byref(to)):
                raise OSError("SetCommTimeouts 失败（err=%d）" % ctypes.get_last_error())
        except Exception:
            self.close()
            raise

    @staticmethod
    def _explain_open_error(err: int) -> str:
        if err == 2:
            msg = "端口不存在"
        elif err == 5:
            msg = "端口被占用或权限不足（已有串口工具/另一个监听在用它，请先关闭）"
        elif err == 3:
            msg = "路径无效"
        else:
            msg = "打开失败"
        return "%s（WinError=%d，路径 %s）" % (msg, err, "\\\\.\\COMx")

    def read(self, n: int = _READ_BUF) -> bytes:
        if self.handle is None:
            raise OSError("串口未打开")
        k32 = self._k32
        buf = ctypes.create_string_buffer(int(n))
        got = ctypes.c_uint32(0)
        ok = k32.ReadFile(ctypes.c_void_p(self.handle), buf, int(n),
                          ctypes.byref(got), None)
        if not ok:
            raise OSError("ReadFile 失败（err=%d）：串口可能已被拔出/关闭"
                          % ctypes.get_last_error())
        return buf.raw[:int(got.value)]

    _WRITE_CHUNK = 4096

    def write(self, data: bytes) -> int:
        """向串口写入字节（分块 + 串行化）。返回实际写入的字节数。"""
        if self.handle is None:
            raise OSError("串口未打开")
        if not data:
            return 0
        if not self.can_write:
            raise OSError("串口以只读方式打开（该口打开时未拿到写权限），无法下发数据；"
                          "请确认端口未被独占，或改用支持双向的口/驱动")
        k32 = self._k32
        buf = bytes(data)
        total = 0
        with self._wlock:
            while total < len(buf):
                blk = buf[total:total + self._WRITE_CHUNK]
                wrote = ctypes.c_uint32(0)
                ok = k32.WriteFile(ctypes.c_void_p(self.handle), blk, len(blk),
                                   ctypes.byref(wrote), None)
                if not ok:
                    raise OSError("WriteFile 失败（err=%d）：串口可能已被拔出/关闭"
                                  % ctypes.get_last_error())
                if int(wrote.value) <= 0:
                    raise OSError("WriteFile 未写入任何字节（已写 %d/%d）：端口可能已断开"
                                  % (total, len(buf)))
                total += int(wrote.value)
                if total < len(buf):
                    time.sleep(0.002)
        return total

    def close(self) -> None:
        h, self.handle = self.handle, None
        if h is not None and self._k32 is not None:
            try:
                self._k32.CloseHandle(ctypes.c_void_p(h))
            except Exception:  # noqa: BLE001
                pass

# ----------------------------------------------------------------------
# 监听器
# ----------------------------------------------------------------------
def _release_note(m) -> str:
    """释放后的统一提示：端口已还，但日志还在、还能接着采集。"""
    try:
        n = m.rb.stats()["size"]
    except Exception:  # noqa: BLE001
        n = 0
    return ("串口 %s 已释放（%s）；已收 %d 行日志仍保留，serial_read 继续可读。"
            "需要继续采集请重新 serial_monitor_start()——同端口同波特率会复用同一实例，"
            "不会丢已收日志。" % (m.port, m.release_reason or "已释放", n))


class SerialMonitor:
    """后台线程把串口数据切成行、推进 ring buffer；工具层只与它打交道。"""

    def __init__(self, port: str, baud: int = DEFAULT_BAUD, databits: int = 8,
                 parity: str = "none", stopbits=1, capacity: int = DEFAULT_CAPACITY,
                 encoding: str = "utf-8", errors: str = "replace",
                 label: str = "", reopen_delay: float = 1.0,
                 idle_release_s: float = DEFAULT_IDLE_RELEASE_S):
        self.port = str(port)
        self.baud = int(baud or DEFAULT_BAUD)
        self.databits = int(databits or 8)
        self.parity = str(parity or "none")
        self.stopbits = stopbits
        self.encoding = encoding or "utf-8"
        self.errors = errors or "replace"
        self.label = label or ""
        self.reopen_delay = float(reopen_delay)
        self.idle_release_s = float(idle_release_s or 0)
        self.last_access = time.time()   # 最近一次被访问（用于空闲自动释放）
        self.auto_released = False       # 是否已是「已释放」状态（日志仍保留）
        self.release_reason = ""
        self.released_at = None
        self.held_for_s = 0.0
        self._releasing = False          # 防重入：release 内部会走 stop/status
        self.rb = RingBuffer(capacity)
        self.state = "stopped"           # stopped / running / error
        self.last_error = ""
        self.reopen_count = 0
        self.bytes_total = 0
        self.started_at = None
        self.partial = ""
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._dev = None                 # 当前打开的设备（由 _loop 发布给写入方）
        self._dev_lock = threading.Lock()

    # ---- 数据入口（线程与测试共用） ----
    def feed(self, data: bytes) -> int:
        """把原始字节切分成行入 buffer，返回新增行数。"""
        if not data:
            return 0
        self.bytes_total += len(data)
        text = self.partial + data.decode(self.encoding, self.errors)
        self.partial = ""
        lines = text.split("\n")
        self.partial = lines.pop() if lines else ""
        if len(self.partial) > _MAX_PARTIAL:      # 无换行刷屏：强制落盘，别把内存吃满
            lines.append(self.partial)
            self.partial = ""
        n = 0
        for ln in lines:
            self._push(ln.rstrip("\r"), partial=False)
            n += 1
        return n

    def _push(self, text: str, partial: bool = False) -> None:
        item = {"seq": self.rb._next, "text": text, "t": time.time(),
                "time_text": time.strftime("%H:%M:%S", time.localtime())}
        if partial:
            item["partial"] = True
        self.rb.append(item)

    def flush_partial(self) -> int:
        """把当前半行也作为一条落进来（人工收尾时用）。"""
        if not self.partial:
            return 0
        self._push(self.partial, partial=True)
        self.partial = ""
        return 1

    # ---- 启动 / 停止 ----
    def start(self) -> dict:
        with self._lock:
            if self.state == "running" and self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self.state = "running"
            self.started_at = time.time()
            self.last_access = time.time()
            self._thread = threading.Thread(target=self._loop, name="mdkdebug-serial",
                                            daemon=True)
            self._thread.start()
        # 真机反馈：start() 返回的瞬间端口还没真正打开（_dev 仍是 None，约 0.2s 后才就绪），
        # 此时返回的 can_write 会误报 false，让人以为「这个口只能收不能发」。
        # 这里等端口就绪（或明确报错）再返回，并带上 port_ready 说明。
        return self.wait_ready()

    def wait_ready(self, timeout: float = 1.5) -> dict:
        """等端口真正打开（_dev 就绪）或明确报错，返回最新状态；超时不算失败、如实反映。

        真机实测：SerialMonitor.start() 立即返回时 _dev 尚未建立、can_write=false，
        0.2s 后才变为 true。调用方若据此判断「发不出去」会被误导。
        """
        deadline = time.time() + max(0.0, float(timeout))
        while time.time() < deadline:
            with self._dev_lock:
                if self._dev is not None:
                    break
            if self.state == "error" and self.last_error:
                break
            time.sleep(0.02)
        return self.status()

    def _open(self):
        dev = HostSerial(self.port, baud=self.baud, databits=self.databits,
                         parity=self.parity, stopbits=self.stopbits)
        dev.open()
        return dev

    def _set_dev(self, dev) -> None:
        with self._dev_lock:
            self._dev = dev

    @property
    def port_ready(self) -> bool:
        """端口是否已真正打开（此刻可读；是否可写另看 can_write）。"""
        with self._dev_lock:
            return self._dev is not None

    @property
    def can_write(self) -> bool:
        """当前是否可下发数据（端口打开且拿到了写权限）。"""
        with self._dev_lock:
            return bool(self._dev is not None and self._dev.can_write)

    def write(self, data: bytes) -> dict:
        """向串口下发数据（收与发共用同一个已打开的句柄，互不干扰）。"""
        with self._dev_lock:
            dev = self._dev
        if dev is None:
            return {"ok": False, "error": "串口当前未打开（监听未运行或正在重连）",
                    "state": self.state, "last_error": self.last_error,
                    "hint": "请先 serial_monitor_start() 打开端口，或用 serial_monitor_status 查看 last_error"}
        try:
            n = dev.write(data)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e), "port": self.port}
        return {"ok": True, "written": n, "port": self.port}

    def _loop(self) -> None:
        dev = None
        while not self._stop.is_set():
            if dev is None:
                try:
                    dev = self._open()
                    self._set_dev(dev)
                    if self.last_error:
                        self.reopen_count += 1
                    self.last_error = ""
                    self.state = "running"
                except Exception as e:  # noqa: BLE001
                    self.last_error = str(e)
                    self.state = "error"
                    self._stop.wait(max(0.2, self.reopen_delay))
                    continue
            try:
                data = dev.read()
                if data:
                    self.feed(data)
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
                self.state = "error"
                try:
                    dev.close()
                except Exception:  # noqa: BLE001
                    pass
                dev = None
                self._set_dev(None)
                self._stop.wait(max(0.2, self.reopen_delay))
        self._set_dev(None)
        if dev is not None:
            try:
                dev.close()
            except Exception:  # noqa: BLE001
                pass
        self.state = "stopped"

    def stop(self, timeout: float = 2.0) -> dict:
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout)
        self.flush_partial()
        with self._lock:
            if not (t and t.is_alive()):
                self.state = "stopped"
        return self._status_raw()

    # ---- 占有 / 释放（「用完就还」） ----
    def touch(self) -> None:
        """记一次访问，重置空闲计时。"""
        self.last_access = time.time()

    @property
    def port_held(self) -> bool:
        return self.state != "stopped"

    def release(self, reason: str = "") -> dict:
        """释放串口：停线程、flush 半行，但**保留 ring buffer** —— 日志不因释放而丢。"""
        was_held = self.state != "stopped"
        self.stop()
        self.auto_released = True
        self.release_reason = reason or "已释放"
        self.released_at = time.time()
        if self.started_at:
            self.held_for_s = round(self.released_at - self.started_at, 1)
        st = self._status_raw()
        st["ok"] = True
        st["released"] = was_held
        st["release_note"] = _release_note(self)
        return st

    def _maybe_idle_release(self) -> bool:
        """空闲超时则自动释放端口（日志保留）。返回是否发生了释放。"""
        if self._releasing or self.idle_release_s <= 0 or self.state == "stopped":
            return False
        idle = time.time() - self.last_access
        if idle < self.idle_release_s:
            return False
        self._releasing = True
        try:
            self.release("空闲 %.0f 秒未访问（idle_release_s=%g）"
                         % (idle, self.idle_release_s))
        finally:
            self._releasing = False
        return True

    # ---- 查询 ----
    def status(self) -> dict:
        self._maybe_idle_release()
        return self._status_raw()

    def _status_raw(self) -> dict:
        alive = bool(self._thread and self._thread.is_alive())
        st = self.rb.stats()
        out = {"port": self.port, "baud": self.baud, "databits": self.databits,
               "parity": self.parity, "stopbits": self.stopbits,
               "label": self.label,
               "state": self.state, "running": bool(alive and self.state != "stopped"),
               "thread_alive": alive,
               "bytes_total": self.bytes_total,
               "lines": st["size"], "capacity": st["capacity"],
               "dropped": st["dropped"], "next_seq": st["next_seq"],
               "first_seq": st["first_seq"],
               "partial_len": len(self.partial),
               "partial": self.partial[-200:],
               "reopen_count": self.reopen_count,
               "last_error": self.last_error,
               "started_at": (time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(self.started_at))
                              if self.started_at else None),
               "port_held": self.state != "stopped",
               "port_ready": self.port_ready,
               "can_write": self.can_write,
               "idle_release_s": self.idle_release_s,
               "idle_s": round(time.time() - self.last_access, 1),
               "auto_released": self.auto_released,
               "release_reason": self.release_reason,
               "held_for_s": (round(time.time() - self.started_at, 1)
                              if (self.state != "stopped" and self.started_at)
                              else self.held_for_s),
               "released_at": (time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(self.released_at))
                               if self.released_at else None)}
        if self.auto_released and self.state == "stopped":
            out["release_note"] = _release_note(self)
        return out

    def read(self, max_items: int = 200, clear: bool = False,
             since: int | None = None, with_text: bool = True) -> dict:
        self._maybe_idle_release()
        self.touch()
        r = self.rb.read(max_items=max_items, clear=clear, since=since)
        if with_text:
            r["lines"] = [it.get("text") for it in r["items"]]
        r.update({"port": self.port, "running": self.state != "stopped",
                  "port_held": self.state != "stopped",
                  "port_ready": self.port_ready,
                  "can_write": self.can_write,
                  "last_error": self.last_error, "bytes_total": self.bytes_total,
                  "partial": self.partial[-200:],
                  "auto_released": self.auto_released,
                  "release_reason": self.release_reason,
                  "idle_release_s": self.idle_release_s})
        if self.auto_released and self.state == "stopped":
            r["release_note"] = _release_note(self)
        return r

# ----------------------------------------------------------------------
# 单例（同一进程只监听一个串口；重复 start 视为切换）
# ----------------------------------------------------------------------
_monitor: SerialMonitor | None = None
_monitor_lock = threading.Lock()

def current() -> SerialMonitor | None:
    return _monitor

def has_monitor() -> bool:
    """是否已有监听实例（无论此刻是否占着串口）。"""
    return _monitor is not None

def start_monitor(port: str, baud: int = DEFAULT_BAUD, databits: int = 8,
                  parity: str = "none", stopbits=1, capacity: int = DEFAULT_CAPACITY,
                  encoding: str = "utf-8", label: str = "",
                  restart: bool = True,
                  idle_release_s: float = DEFAULT_IDLE_RELEASE_S) -> dict:
    """启动（或切换/复用）串口监听。

    - 同端口同波特率且**已被释放**时复用同一实例（保留已收日志），只重新占口；
    - ``idle_release_s>0``：超过该秒数无人访问则自动释放端口（日志仍保留），0=不自动。

    返回体带 ``port_ready``（端口是否已真正打开）与 ``can_write``（是否拿到写权限）：
    本函数会等端口就绪再返回，所以这两个字段可直接采信。
    """
    global _monitor
    with _monitor_lock:
        if _monitor is not None:
            same = (resolve_port(_monitor.port).upper() == resolve_port(port).upper()
                    and int(_monitor.baud) == int(baud))
            if same:
                _monitor.idle_release_s = float(idle_release_s or 0)
                if _monitor.state != "stopped":
                    _monitor.touch()
                    return _monitor.status()
                # 之前已被释放（自动或显式 stop）：复用同一实例，已收日志不丢
                _monitor.auto_released = False
                _monitor.release_reason = ""
                _monitor.released_at = None
                if label:
                    _monitor.label = label
                st = _monitor.start()
                st["resumed"] = True
                st["note"] = "复用先前被释放的同一监听实例，已收日志仍保留"
                return st
            if _monitor.state != "stopped" and not restart:
                cur = _monitor.status()
                cur["conflict"] = "已有监听在运行（%s@%d），如需切换请 restart=true" % (
                    _monitor.port, _monitor.baud)
                return cur
            _monitor.stop()
        _monitor = SerialMonitor(port, baud=baud, databits=databits, parity=parity,
                                 stopbits=stopbits, capacity=capacity,
                                 encoding=encoding, label=label,
                                 idle_release_s=idle_release_s)
        return _monitor.start()

def release_monitor(reason: str = "") -> dict:
    """释放端口但**保留日志**（供 exit_debug / 烧录 / 关 Keil 等生命周期工具调用）。"""
    m = _monitor
    if m is None:
        return {"ok": True, "released": False, "note": "当前没有串口监听在运行"}
    return m.release(reason)

def stop_monitor(clear_buffer: bool = False) -> dict:
    """停止监听并释放串口；默认**保留已收日志**（serial_read 仍可读）。"""
    global _monitor
    with _monitor_lock:
        if _monitor is None:
            return {"ok": True, "running": False, "note": "当前没有串口监听在运行"}
        st = _monitor.release("显式 stop")
        st["running"] = False
        if clear_buffer:
            _monitor = None
            st["note"] = "已停止、释放串口并清空缓存"
        else:
            st["note"] = ("已停止并释放串口 %s；已收 %d 行日志仍保留，serial_read 继续可读，"
                          "需要继续采集直接 serial_monitor_start() 复用即可"
                          % (st.get("port"), st.get("lines", 0)))
        return st

def _release_on_exit() -> None:
    """进程退出兜底：别把 COM 口带走（否则下次启动/其他工具打不开）。"""
    m = _monitor
    if m is not None and m.state != "stopped":
        try:
            m.release("进程退出（atexit）")
        except Exception:  # noqa: BLE001
            pass

atexit.register(_release_on_exit)

def _port_hint(prefix: str) -> str:
    """提示里要出现端口号时，优先写**本机真实存在的口**，而不是一个写死的示例号。

    真机反馈：提示写死 port="COM9"，而同一份返回里的 available_ports 明明是 COM3——
    文案与事实不符，照着做只会再失败一次（属于「看似权威的错答案」）。有真值就用真值，
    一个口都没有时才退回「先 list_ports 看看」的说法。
    """
    names = [str(p.get("port")) for p in list_ports()
             if isinstance(p, dict) and p.get("port")]
    if names:
        return "%s（本机可用：%s）" % (prefix, "、".join(names[:4]))
    return "%s；先用 serial_list_ports 确认本机有哪个口" % prefix


def read_lines(max_items: int = 200, clear: bool = False,
               since: int | None = None) -> dict:
    m = _monitor
    if m is None:
        return {"ok": False, "error": "当前没有串口监听在运行",
                "hint": _port_hint("先调 serial_monitor_start(port=..., baud=115200) 启动监听"),
                "available_ports": list_ports()}
    out = m.read(max_items=max_items, clear=clear, since=since)
    out["ok"] = True
    return out

def write_bytes(data: bytes, wait_ms: int = 300, max_items: int = 200,
                read_after: bool = True) -> dict:
    """向监听中的串口下发字节；默认「写后等一小会儿，把新增日志行一起带回来」。

    服务「一边收一边发」的用法（下发 shell 命令 / 镜像片段后立刻看回显），
    省掉调用方再补一次 serial_read。
    """
    m = _monitor
    if m is None:
        return {"ok": False, "error": "当前没有串口监听在运行",
                "hint": _port_hint("serial_write 依赖监听持有端口（收与发用同一个句柄）："
                                   "先调 serial_monitor_start(port=..., baud=115200) 再下发"),
                "available_ports": list_ports()}
    m.touch()
    before = m.rb.stats()["next_seq"]
    bytes_before = m.bytes_total          # 用于判断「有没有任何回显」（比行数更灵敏）
    res = m.write(data)
    res["bytes_sent"] = len(data)
    res["next_seq_before"] = before
    if not res.get("ok"):
        res.setdefault("port", m.port)
        return res
    if read_after:
        if int(wait_ms) > 0:
            time.sleep(min(max(int(wait_ms), 0), 10000) / 1000.0)
        r = m.read(max_items=max_items, since=before)
        ra = {"ok": True, "count": r.get("count"), "items": r.get("items"),
              "lines": r.get("lines"), "first_seq": r.get("first_seq"),
              "bytes_new": int(m.bytes_total) - bytes_before,
              "next_seq": r.get("next_seq"), "truncated": r.get("truncated"),
              "dropped": r.get("dropped"), "partial": r.get("partial")}
        if not r.get("count"):
            ra["note"] = ("写完等了 %dms 没有新行：可能目标没有回显（不是命令口/未开启回显），"
                          "也可能响应更慢；可加大 wait_ms，或用 serial_read(since=%d) 稍后再取。"
                          % (int(wait_ms), before))
        res["read_after"] = ra
    else:
        res["next_seq_hint"] = "稍后用 serial_read(since=%d) 取本次下发之后的新行" % before
    return res

def status() -> dict:
    m = _monitor
    if m is None:
        return {"ok": True, "running": False, "available_ports": list_ports(),
                "note": "当前没有串口监听在运行"}
    out = m.status()
    out["ok"] = True
    out["available_ports"] = list_ports()
    return out

def selftest(port: str | None = None, baud: int = DEFAULT_BAUD) -> dict:
    """自检：尝试打开端口并读一小段（用于确认驱动/线序/波特率是否可用）。"""
    ports = list_ports()
    p = port or (ports[0] if ports else "")
    if not p:
        return {"ok": False, "error": "未发现任何串口", "available_ports": ports}
    dev = None
    try:
        dev = HostSerial(p, baud=baud)
        dev.open()
        time.sleep(0.15)
        data = dev.read()
        return {"ok": True, "port": p, "baud": baud, "bytes_read": len(data),
                "sample": data[:200].decode("utf-8", "replace"),
                "note": "端口可打开；bytes_read 为 0 说明当前没有数据在流（不代表不能用）"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "port": p, "error": str(e), "available_ports": ports}
    finally:
        if dev is not None:
            dev.close()
