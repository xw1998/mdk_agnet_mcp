# -*- coding: utf-8 -*-
"""Windows 侧进程 / 窗口 / 端口探测与 Keil 启动工具。

纯 ctypes + socket 实现，不依赖 tasklist / netstat 等外部命令。存在的理由：

1. **Keil 可能已死而调用方无感知**：UV4 进程没了、4823 也不再监听时，
   旧实现只能等到命令超时才报"没反应"。廉价健康检查让每次调用都能给出明确状态
   （keil_not_running / port_not_listening），而不是干等。
2. **模态对话框会让 UVSOCK"连得上但不干活"**：Keil 弹出
   "Cannot read project file" 之类模态框时端口照样监听、命令却不执行也不报错，
   只能靠窗口枚举（类名 #32770）识别。
3. **由调用方 job 拉起的 UV4 会随调用链被回收**：必须用
   CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP 脱离。
"""
from __future__ import annotations

import ctypes
import re
import socket
import subprocess
import sys
import time
from ctypes import wintypes

DEFAULT_UVSOCK_PORT = 4823
_UV4_EXE = "uv4.exe"


def uv4_pids() -> list:
    """枚举当前所有 UV4.exe 的 PID（Toolhelp 快照）。"""
    if sys.platform != "win32":
        return []
    try:
        TH32CS_SNAPPROCESS = 0x00000002
        kernel32 = ctypes.windll.kernel32

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        pids = []
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == ctypes.c_void_p(-1).value or snap == -1:
            return pids
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
                while True:
                    try:
                        name = pe.szExeFile
                    except Exception:  # noqa: BLE001
                        break
                    if name.lower() == _UV4_EXE:
                        pids.append(int(pe.th32ProcessID))
                    if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                        break
        finally:
            kernel32.CloseHandle(snap)
        return pids
    except Exception:  # noqa: BLE001
        return []


_UV_PROJ_RE = re.compile(r"([A-Za-z]:\\[^<>|?*\"]*?\.uv(?:projx|proj|mpw))", re.IGNORECASE)


def uv4_windows() -> list:
    """枚举属于 UV4 进程的可见顶层窗口：[{pid, hwnd, title}]。

    Keil 主窗口标题形如 "<工程全路径>.uvprojx - µVision"，是判断"同一工程被开了几个窗口"
    最可靠的本地信号（不需要 wmic / PowerShell 之类的命令行探测）。
    """
    if sys.platform != "win32":
        return []
    try:
        pids = set(uv4_pids())
        if not pids:
            return []
        user32 = ctypes.windll.user32
        out = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def _cb(hwnd, _lparam):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if int(pid.value) not in pids:
                    return True
                buf = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, buf, 512)
                out.append({"pid": int(pid.value), "hwnd": int(hwnd), "title": buf.value})
            except Exception:  # noqa: BLE001
                pass
            return True

        user32.EnumWindows(_cb, 0)
        return out
    except Exception:  # noqa: BLE001
        return []


def uv4_process_created(pid: int):
    """UV4 进程创建时间（epoch 秒）；取不到返回 None。用于判定"最新 / 最早"实例。"""
    if sys.platform != "win32":
        return None
    try:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD),
                        ("dwHighDateTime", wintypes.DWORD)]

        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return None
        try:
            c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if not kernel32.GetProcessTimes(handle, ctypes.byref(c), ctypes.byref(e),
                                            ctypes.byref(k), ctypes.byref(u)):
                return None
            ticks = (int(c.dwHighDateTime) << 32) | int(c.dwLowDateTime)
            return ticks / 1e7 - 11644473600.0        # 1601-01-01 → Unix epoch
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001
        return None


def parse_project_from_title(title: str) -> str:
    """从 Keil 主窗口标题解析工程路径（标题形如 "<完整路径>.uvprojx - µVision"）。"""
    if not title:
        return ""
    m = _UV_PROJ_RE.search(title)
    return m.group(1) if m else ""


def uv4_instances() -> list:
    """列出所有 UV4.exe 实例，按创建时间升序：

    [{pid, created, project, title, hwnd, has_window}]

    真机实测：UV4.exe **不是**单实例程序——同一工程可以被反复打开成多个窗口且互不回收
    （曾累积 6 个同工程实例）。所以需要能"看见"当前到底开了几个。
    """
    pids = uv4_pids()
    if not pids:
        return []
    by_pid = {}
    for w in uv4_windows():
        by_pid.setdefault(w["pid"], []).append(w)
    out = []
    for pid in pids:
        ws = by_pid.get(int(pid)) or []
        title, hwnd = "", 0
        for w in ws:
            if w.get("title"):
                title, hwnd = w["title"], w["hwnd"]
                break
        out.append({"pid": int(pid), "created": uv4_process_created(pid),
                    "project": parse_project_from_title(title), "title": title,
                    "hwnd": hwnd, "has_window": bool(ws)})
    out.sort(key=lambda x: (x["created"] is None, x["created"] or 0.0, x["pid"]))
    return out


def focus_window(hwnd) -> bool:
    """把窗口恢复并前置（复用已有实例时让用户看到"就是这一个窗口"）。"""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        user32 = ctypes.windll.user32
        user32.ShowWindow(int(hwnd), 9)          # SW_RESTORE
        return bool(user32.SetForegroundWindow(int(hwnd)))
    except Exception:  # noqa: BLE001
        return False


def port_listening(port: int = DEFAULT_UVSOCK_PORT, host: str = "127.0.0.1",
                   timeout: float = 0.3) -> bool:
    """探测端口是否有服务监听（connect 探测，比 netstat 快且不依赖外部命令）。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def keil_health(port: int = DEFAULT_UVSOCK_PORT) -> dict:
    """廉价健康检查：UV4 进程 + UVSOCK 端口，并给出可操作诊断。

    返回 keil_alive / uv4_pids / port_listening / uvsock_ready / diagnosis / suggestion。
    设计为"永不抛异常"——健康检查本身崩掉就失去意义了。
    """
    try:
        pids = uv4_pids()
    except Exception:  # noqa: BLE001
        pids = []
    try:
        listening = port_listening(port)
    except Exception:  # noqa: BLE001
        listening = False

    if pids and listening:
        diagnosis = "Keil 与 UVSOCK 均就绪"
        suggestion = ""
        code = "ok"
    elif not pids and not listening:
        diagnosis = "Keil 未运行（无 UV4.exe 进程，%d 端口未监听）" % port
        suggestion = ("请先拉起 Keil 并打开工程：launch_uvision（或用 restart_keil 一步完成"
                      "关闭→重启→等待 UVSOCK→重建连接）；若 Keil 已开着，请在 Keil 菜单 "
                      "Edit → Configuration（部分版本为 Project → Options for Target）"
                      "→ Debug → Settings 里确认 UVSOCK 已启用（端口 %d）。" % port)
        code = "keil_not_running"
    elif pids and not listening:
        diagnosis = "Keil 在运行，但 UVSOCK 未开启（%d 端口未监听）" % port
        suggestion = ("请在 Keil 里启用 UVSOCK：菜单 Edit → Configuration（部分版本为 "
                      "Project → Options for Target）→ Debug → Settings → 勾选 UVSOCK 并"
                      "设端口 %d；或直接 restart_keil 让连接器重启并等待端口就绪。" % port)
        code = "port_not_listening"
    else:
        diagnosis = "%d 端口有监听但未发现 UV4.exe 进程（可能是残留监听或端口被其它程序占用）" % port
        suggestion = "可尝试 restart_keil 清场重启；若仍异常，检查是否有其它程序占用该端口。"
        code = "port_occupied"

    return {
        "ok": True,
        "code": code,
        "keil_alive": bool(pids),
        "uv4_pids": pids,
        "port": port,
        "port_listening": listening,
        "uvsock_ready": bool(pids and listening),
        "diagnosis": diagnosis,
        "suggestion": suggestion,
    }


def find_modal_dialogs() -> list:
    """枚举属于 UV4 进程的可见对话框窗口（类名 #32770）。

    Keil 弹出模态框时 UVSOCK 仍能连上，但命令不执行也不报错——只能靠窗口识别。
    返回 [{"pid":..., "title":...}, ...]。
    """
    if sys.platform != "win32":
        return []
    try:
        pids = set(uv4_pids())
        if not pids:
            return []
        user32 = ctypes.windll.user32
        out = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def _cb(hwnd, _lparam):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if int(pid.value) not in pids:
                    return True
                buf = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, buf, 256)
                if buf.value != "#32770":          # 标准对话框窗口类
                    return True
                tbuf = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, tbuf, 512)
                out.append({"pid": int(pid.value), "title": tbuf.value})
            except Exception:  # noqa: BLE001
                pass
            return True

        user32.EnumWindows(_cb, 0)
        return out
    except Exception:  # noqa: BLE001
        return []


def launch_detached(uv4: str, project: str = "", extra_args: list = None) -> dict:
    """以"脱离调用方 job"的方式启动 UV4，避免进程随调用链被回收。

    关键 creationflags：
    - CREATE_BREAKAWAY_FROM_JOB(0x01000000)：脱离调用方所在的 job object
      （MCP 服务进程若在 job 里，普通子进程会随之被一起杀掉）；
    - DETACHED_PROCESS(0x00000008)：不继承控制台；
    - CREATE_NEW_PROCESS_GROUP(0x00000200)：独立进程组。
    同时把 stdin/stdout/stderr 接到 DEVNULL，避免继承调用方的管道
    （也顺带避免 Keil 的 BeforeMake 钩子继承被污染的 PYTHONHOME 等环境）。
    """
    if not uv4:
        return {"ok": False, "error": "未定位到 UV4.exe"}
    cmd = [uv4] + ([project] if project else []) + list(extra_args or [])
    base = (getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
    full = base | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
    devnull = subprocess.DEVNULL if hasattr(subprocess, "DEVNULL") else open("nul", "wb")  # noqa: SIM115
    try:
        proc = subprocess.Popen(cmd, creationflags=full, close_fds=True,
                                stdin=devnull, stdout=devnull, stderr=devnull)
        return {"ok": True, "pid": proc.pid, "creationflags": hex(full),
                "detached": True, "breakaway": True, "command": " ".join(cmd)}
    except OSError as e:
        # 某些环境不允许 breakaway（如已在 job 且 job 设了限制），退化为不带该标志
        try:
            proc = subprocess.Popen(cmd, creationflags=base, close_fds=True,
                                    stdin=devnull, stdout=devnull, stderr=devnull)
            return {"ok": True, "pid": proc.pid, "creationflags": hex(base),
                    "detached": True, "breakaway": False, "breakaway_error": str(e),
                    "command": " ".join(cmd)}
        except Exception as e2:  # noqa: BLE001
            return {"ok": False, "error": "启动 Keil 失败：%s（breakaway 失败：%s）" % (e2, e)}


def wait_port_listening(port: int = DEFAULT_UVSOCK_PORT, timeout: float = 20.0,
                        interval: float = 0.3) -> dict:
    """等待端口进入监听。返回 {ok, waited_ms, listening}。"""
    t0 = time.monotonic()
    while True:
        if port_listening(port):
            return {"ok": True, "listening": True,
                    "waited_ms": int((time.monotonic() - t0) * 1000)}
        if time.monotonic() - t0 >= timeout:
            return {"ok": False, "listening": False,
                    "waited_ms": int((time.monotonic() - t0) * 1000)}
        time.sleep(interval)


def wait_uv4_exit(timeout: float = 12.0, interval: float = 0.3) -> dict:
    """等待所有 UV4.exe 退出。返回 {ok, remaining, waited_ms}。"""
    t0 = time.monotonic()
    while True:
        remain = uv4_pids()
        if not remain:
            return {"ok": True, "remaining": [], "waited_ms": int((time.monotonic() - t0) * 1000)}
        if time.monotonic() - t0 >= timeout:
            return {"ok": False, "remaining": remain,
                    "waited_ms": int((time.monotonic() - t0) * 1000)}
        time.sleep(interval)
