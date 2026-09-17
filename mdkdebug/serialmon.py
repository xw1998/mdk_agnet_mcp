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
- **零新依赖**：Windows 串口用 ctypes（CreateFile/SetCommState/ReadFile），不引入 pyserial，
  部署端不需要重装依赖。
- **ring buffer 而不是文件**：容量有限（默认 2000 行）、按 seq 增量读，
  支持 ``since``/``clear``，长时间监听不会把内存吃爆，也不会让 AI 反复重读全部日志。
- **断线自愈**：USB 串口拔插/被占用会报错，监听线程记录 ``last_error`` 并按退避重连，
  不静默死掉（``status`` 里能看到 ``reopen_count`` 与错误原因）。
- **默认按行切分**：日志是行导向的，半行留在 ``partial`` 里，状态查询可见。
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

    # ---- 打开 / 关闭 ----
    def open(self) -> None:
        if sys.platform != "win32":
            raise OSError("宿主机串口监听目前仅支持 Windows（当前平台 %s）" % sys.platform)
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32 = self._k32
        k32.CreateFileW.restype = ctypes.c_void_p
        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        h = k32.CreateFileW(ctypes.c_wchar_p(self.path), GENERIC_READ, 0, None,
                            OPEN_EXISTING, 0, None)
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
        return self.status()

    def _open(self):
        dev = HostSerial(self.port, baud=self.baud, databits=self.databits,
                         parity=self.parity, stopbits=self.stopbits)
        dev.open()
        return dev

    def _loop(self) -> None:
        dev = None
        while not self._stop.is_set():
            if dev is None:
                try:
                    dev = self._open()
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
                self._stop.wait(max(0.2, self.reopen_delay))
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

def read_lines(max_items: int = 200, clear: bool = False,
               since: int | None = None) -> dict:
    m = _monitor
    if m is None:
        return {"ok": False, "error": "当前没有串口监听在运行",
                "hint": "先调 serial_monitor_start(port=\"COM9\", baud=115200) 启动监听",
                "available_ports": list_ports()}
    out = m.read(max_items=max_items, clear=clear, since=since)
    out["ok"] = True
    return out

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
