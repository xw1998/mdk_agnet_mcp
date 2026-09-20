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
import os
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


# ----------------------------------------------------------------------
# UVSOCK 端口归属：4823 到底是谁在监听（哪个 UV4 实例、开着哪个工程）
# ----------------------------------------------------------------------
# 存在的理由（真机反馈）：4823 被一个**旧的** Keil 实例占着（那上面加载的是另一个工程），
# 之后即使重开正确的工程窗口，调试依然连到旧实例上——于是符号解析、下断点、单步全都落在
# 错误的镜像上（表现为「假符号 + error 57 + 单步退化成指令级」）。这类问题的第一问永远是
# 「这条链路此刻服务的是哪个 PID / 哪个工程」，工具必须能直接回答，而不是让调用方自己猜。
#
# 不依赖 netstat（进程外命令慢、且沙箱里可能不可用）：走 iphlpapi 的
# GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)，纯 ctypes。端口归属是**操作系统
# 记账**，比看窗口标题可靠；工程名再按 PID 与 uv4_instances() 对齐得到。
_TCP_TABLE_OWNER_PID_LISTENER = 3
_AF_INET = 2


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


def _listening_pids_v4(port: int) -> dict:
    """IPv4 监听表里占着该端口的 PID 列表。

    返回 {ok, pids, method} / {ok: False, reason}。**只查 IPv4 监听表**（如实声明）：
    UVSOCK 监听 127.0.0.1，真机实测在 IPv4 表里；表里没有 ≠ 端口没人监听（只说明不是
    IPv4 监听者），所以调用方还要用 port_listening 兜一下。
    """
    if sys.platform != "win32":
        return {"ok": False, "reason": "仅 Windows 支持端口归属查询（iphlpapi）"}
    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = wintypes.DWORD(0)
        ret = iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                           _AF_INET, _TCP_TABLE_OWNER_PID_LISTENER, 0)
        # 0 = 表为空（尺寸 0）；122 = ERROR_INSUFFICIENT_BUFFER（正常路径，带回所需尺寸）
        if ret not in (0, 122):
            return {"ok": False, "reason": "GetExtendedTcpTable 探测失败（返回 %d）" % ret}
        if not size.value:
            return {"ok": True, "pids": [], "method": "GetExtendedTcpTable-ipv4-listener"}
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False,
                                           _AF_INET, _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if ret != 0:
            return {"ok": False, "reason": "GetExtendedTcpTable 失败（返回 %d）" % ret}
        n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
        rows = ctypes.cast(ctypes.addressof(buf) + ctypes.sizeof(wintypes.DWORD),
                           ctypes.POINTER(_MIB_TCPROW_OWNER_PID))
        pids = []
        for i in range(int(n)):
            row = rows[i]
            try:
                # dwLocalPort 的端口号在低 16 位、且是网络字节序
                local_port = socket.ntohs(int(row.dwLocalPort) & 0xFFFF)
            except Exception:            # noqa: BLE001
                continue
            if local_port == int(port) and int(row.dwOwningPid):
                pids.append(int(row.dwOwningPid))
        return {"ok": True, "pids": pids, "method": "GetExtendedTcpTable-ipv4-listener"}
    except Exception as e:               # noqa: BLE001
        return {"ok": False, "reason": "端口归属查询异常：%s" % e}


def uvsock_owner(port: int = DEFAULT_UVSOCK_PORT) -> dict:
    """谁在监听 UVSOCK 端口：{ok, port, pid, pids, method} / {ok: False, reason}。

    多个 PID 同时监听同一端口是可能的（SO_REUSEADDR / 多实例），故除首选的 pid 外
    把 pids 也带出来——命令实际发给哪一个不受本工具控制，这一点必须如实暴露。
    """
    r = _listening_pids_v4(port)
    if not r.get("ok"):
        return {"ok": False, "port": int(port), "reason": r.get("reason")}
    pids = list(r.get("pids") or [])
    return {"ok": True, "port": int(port), "pid": (pids[0] if pids else None),
            "pids": pids, "method": r.get("method")}


def uvsock_binding(port: int = DEFAULT_UVSOCK_PORT) -> dict:
    """当前 UVSOCK 链路的归属：端口 → 占用它的 UV4 实例（PID / 工程 / 窗口 / 启动时间）。

    owner_project 来自该实例的主窗口标题（Keil 标题形如 "<工程全路径>.uvprojx - µVision"），
    所以**无窗口的实例（后台/最小化启动）给不出工程名**——那时如实留空并说明，不猜。
    """
    owner = uvsock_owner(port)
    try:
        insts = uv4_instances()
    except Exception:                    # noqa: BLE001
        insts = []
    me = None
    if owner.get("ok") and owner.get("pid"):
        for i in insts:
            if int(i.get("pid") or 0) == int(owner["pid"]):
                me = i
                break
    created = (me or {}).get("created")
    out = {
        "port": int(port),
        "owner_pid": owner.get("pid") if owner.get("ok") else None,
        "owner_pid_source": owner.get("method") if owner.get("ok") else None,
        "owner_project": (me or {}).get("project") or None,
        "owner_created": created,
        "owner_created_str": (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created))
                              if created else None),
        "owner_has_window": bool((me or {}).get("has_window")),
        "instances": [{"pid": i.get("pid"), "project": i.get("project"),
                       "has_window": bool(i.get("has_window"))} for i in insts],
        "instances_total": len(insts),
    }
    if not owner.get("ok"):
        out["state"] = "unknown"
        out["note"] = ("拿不到端口归属（%s）：**无法判定这条链路服务的是哪个 Keil 实例**，"
                       "别把符号/断点解析出来的东西当成板上事实。"
                       % (owner.get("reason") or "未知原因"))
    elif not owner.get("pids"):
        listening = port_listening(port)
        out["state"] = "not-listening" if not listening else "foreign-owner"
        if not listening:
            out["note"] = ("端口 %d 没有监听者：Keil 未运行或 UVSOCK 未开启"
                           "（restart_keil 可一步拉起并等待就绪）。" % int(port))
        else:
            out["note"] = ("端口 %d 有服务在监听，但监听它的进程不是 UV4.exe：**可能有"
                           "别的程序占着这个端口**，命令会被发给它或直接超时——"
                           "用 keil_health 看诊断。" % int(port))
    else:
        out["state"] = "bound"
        pids = owner.get("pids") or []
        if len(pids) > 1:
            out["note"] = ("有多个进程同时监听端口 %d（PID %s）：命令实际发给哪一个不受本工具"
                           "控制，调试前先收敛到一个实例。"
                           % (int(port), "、".join(str(p) for p in pids)))
        elif not me:
            out["note"] = ("监听者 PID=%s 不在 UV4 实例列表里（实例可能刚退出/刚启动）："
                           "取不到它打开的工程。" % owner.get("pid"))
        elif not (me or {}).get("project"):
            out["note"] = ("监听者 PID=%s 没有可用的窗口标题：**取不到它打开的工程**"
                           "（后台/最小化启动的实例常见）——工程名请以 Keil 界面为准。"
                           % owner.get("pid"))
        else:
            out["note"] = ("这条 UVSOCK 链路由 PID=%s 的 Keil 实例服务，它打开的是 %s。"
                           % (out["owner_pid"], out["owner_project"]))
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


def keil_health(port: int = DEFAULT_UVSOCK_PORT, with_dialogs: bool = False) -> dict:
    """廉价健康检查：UV4 进程 + UVSOCK 端口，并给出可操作诊断。

    返回 keil_alive / uv4_pids / port_listening / uvsock_ready / diagnosis / suggestion。

    with_dialogs=True 时**一并枚举模态对话框**（含正文与按钮），并给出
    modal_dialogs / modal_blocked_suspected：模态框下的"端口正常、命令不返回"是最难自己
    看出来的一种故障，提前探测能让调用方直接看到"框里写了什么"。

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

    out = {
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
    if with_dialogs:
        # 字段**始终存在**：没有 UV4 进程时给空列表，调用方才能区分"没探测"与"没有框"
        try:
            dialogs = find_modal_dialogs() if pids else []
        except Exception:  # noqa: BLE001
            dialogs = []
        out["modal_dialogs"] = dialogs
        out["modal_blocked_suspected"] = bool(dialogs)
        if dialogs:
            shown = []
            for d in dialogs[:3]:
                txt = (d.get("message") or "").strip()
                btns = "、".join(d.get("button_texts") or [])
                shown.append("%s%s%s" % (d.get("title") or "(无标题)",
                                         ("：" + txt) if txt else "（正文未取到）",
                                         ("[按钮: %s]" % btns) if btns else ""))
            if code == "ok":
                out["diagnosis"] = ("Keil 与 UVSOCK 均就绪，但有 %d 个模态对话框在阻塞命令"
                                    "（端口正常、命令不返回正是模态框的典型症状）" % len(dialogs))
            out["suggestion"] = ((out.get("suggestion") or "")
                                 + " 检测到 Keil 模态对话框，很可能阻塞命令执行："
                                 + "；".join(shown)
                                 + "。可直接用 dismiss_dialog 读取正文并按按钮关闭，"
                                   "或在 Keil 界面手动处理。")
    return out


def _child_controls(hwnd) -> list:
    """枚举窗口的全部子控件（EnumChildWindows，含嵌套）：[{hwnd, class, text}]。

    只靠窗口标题看不到"框里写什么"，必须下钻到子控件：标准对话框（#32770）的正文是
    Static 控件、按钮是 Button 控件。
    """
    if sys.platform != "win32" or not hwnd:
        return []
    out = []
    try:
        user32 = ctypes.windll.user32

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def _cb(ch, _lparam):
            try:
                cbuf = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(ch, cbuf, 256)
                tbuf = ctypes.create_unicode_buffer(2048)
                user32.GetWindowTextW(ch, tbuf, 2048)
                out.append({"hwnd": int(ch), "class": cbuf.value, "text": tbuf.value})
            except Exception:  # noqa: BLE001
                pass
            return True

        user32.EnumChildWindows(int(hwnd), _cb, 0)
    except Exception:  # noqa: BLE001
        return []
    return out


def dialog_content(hwnd) -> dict:
    """读一个对话框的正文与按钮：{"message", "buttons":[{hwnd,text}], "button_texts",
    "statics", "child_count"}。

    Keil 的模态框正文（Static）通常就是唯一有用的一句话，如
    "Create File -o '…' failed."；按钮（Button）给出可选项（确定/取消/重试）。
    """
    kids = _child_controls(hwnd)
    statics, buttons = [], []
    for k in kids:
        cls, txt = (k.get("class") or ""), (k.get("text") or "").strip()
        if not txt:
            continue
        if cls == "Static":
            if txt not in statics:
                statics.append(txt)
        elif cls == "Button":
            buttons.append({"hwnd": k.get("hwnd"), "text": txt})
    return {"message": " ".join(statics), "buttons": buttons,
            "button_texts": [b["text"] for b in buttons],
            "statics": statics, "child_count": len(kids)}


def find_modal_dialogs() -> list:
    """枚举属于 UV4 进程的可见对话框窗口（类名 #32770），并读出正文与按钮。

    Keil 弹出模态框时 UVSOCK 仍能连上，但命令不执行也不报错——只能靠窗口识别。
    只给标题帮助有限（"有个 μVision 框"仍不知该点什么），故一并返回：
      [{pid, hwnd, title, message, buttons:[{hwnd,text}], button_texts, statics}]
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
                item = {"pid": int(pid.value), "hwnd": int(hwnd), "title": tbuf.value}
                item.update(dialog_content(hwnd))  # message / buttons / button_texts
                out.append(item)
            except Exception:  # noqa: BLE001
                pass
            return True

        user32.EnumWindows(_cb, 0)
        return out
    except Exception:  # noqa: BLE001
        return []


# 宿主进程（MCP 服务跑在宿主的 Python 里）可能带着 PYTHONHOME/PYTHONPATH 等变量。
# 被启动的外部工具若再「另起一个 python」——Keil 的 BeforeMake 钩子 `py -3 xxx.py`、
# ESP-IDF 的 idf.py——会拿宿主的变量去定位标准库，而解释器版本往往对不上：
# 真机上表现为 site 初始化失败、刷一屏 traceback，把真正的结论淹没。
# 所以凡是我们启动的外部工具，一律剥掉宿主 python 变量。
HOST_PY_ENV_VARS = ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
                    "PYTHONUSERBASE", "VIRTUAL_ENV", "CONDA_PREFIX")

def child_env(base=None, extra=None) -> dict:
    """外部工具子进程的环境变量：剥掉宿主 python 变量，可再叠加 extra。

    base=None 时以 os.environ 为底（复制，不改动宿主）；给 base 时以它为底
    （用于调用方已构造好环境、只想再剥一遍的场景）。extra 最后覆盖。
    """
    env = dict(os.environ if base is None else base)
    for _k in HOST_PY_ENV_VARS:
        env.pop(_k, None)
    for _k, _v in (extra or {}).items():
        env[str(_k)] = str(_v)
    return env


def launch_detached(uv4: str, project: str = "", extra_args: list = None) -> dict:
    """以"脱离调用方 job"的方式启动 UV4，避免进程随调用链被回收。

    关键 creationflags：
    - CREATE_BREAKAWAY_FROM_JOB(0x01000000)：脱离调用方所在的 job object
      （MCP 服务进程若在 job 里，普通子进程会随之被一起杀掉）；
    - DETACHED_PROCESS(0x00000008)：不继承控制台；
    - CREATE_NEW_PROCESS_GROUP(0x00000200)：独立进程组。
    同时把 stdin/stdout/stderr 接到 DEVNULL，避免继承调用方的管道；
    并用 child_env() 剥掉宿主 python 变量（否则 Keil 的 BeforeMake 钩子会继承
    被污染的 PYTHONHOME，`py -3 xxx.py` 直接崩在 site 初始化上）。
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
                                stdin=devnull, stdout=devnull, stderr=devnull,
                                env=child_env())
        return {"ok": True, "pid": proc.pid, "creationflags": hex(full),
                "detached": True, "breakaway": True, "command": " ".join(cmd)}
    except OSError as e:
        # 某些环境不允许 breakaway（如已在 job 且 job 设了限制），退化为不带该标志
        try:
            proc = subprocess.Popen(cmd, creationflags=base, close_fds=True,
                                    stdin=devnull, stdout=devnull, stderr=devnull,
                                    env=child_env())
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


# 模态框"默认按钮"偏好顺序：这些是"确认/关闭"语义，点了不会改变构建结果，
# 只解除阻塞（先精确匹配再包含匹配，见 _pick_button）。
_OK_BUTTON_HINTS = ("确定", "OK", "是", "Yes", "关闭", "Close", "继续", "Continue",
                    "重试", "Retry")

def _pick_button(buttons: list, wanted: str = ""):
    """从 [{hwnd,text}] 里挑按钮。

    wanted 非空时只认它（精确 → 忽略大小写 → 包含），挑不到返回 None——
    **不替用户改点别的按钮**，否则就成了"以为点了确定、实际点了取消"。
    wanted 为空时按 _OK_BUTTON_HINTS 的确认语义顺序自动挑。
    """
    if not buttons:
        return None
    if wanted and wanted.strip():
        w = wanted.strip().lower()
        for b in buttons:
            if (b.get("text") or "").strip().lower() == w:
                return b
        for b in buttons:
            if w in (b.get("text") or "").strip().lower():
                return b
        return None
    for hint in _OK_BUTTON_HINTS:
        h = hint.lower()
        for b in buttons:
            if (b.get("text") or "").strip().lower() == h:
                return b
    for hint in _OK_BUTTON_HINTS:
        h = hint.lower()
        for b in buttons:
            if h in (b.get("text") or "").strip().lower():
                return b
    return None

def _click_control(hwnd, timeout_ms: int = 2000) -> bool:
    """点按钮（BM_CLICK）。用 SendMessageTimeout(ABORTIFHUNG) 而非 SendMessage，
    避免目标线程卡死时把调用方一起挂住。

    注意返回值只表示"消息送出去了"：按钮回调会销毁对话框，SendMessage 可能因此返回 0，
    所以**判断是否关掉要看窗口是否真的消失**，不能看这个返回值。
    """
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        BM_CLICK = 0x00F5
        SMTO_ABORTIFHUNG = 0x0002
        res = wintypes.DWORD(0)
        r = ctypes.windll.user32.SendMessageTimeoutW(
            int(hwnd), BM_CLICK, 0, 0, SMTO_ABORTIFHUNG, int(timeout_ms), ctypes.byref(res))
        return bool(r)
    except Exception:  # noqa: BLE001
        return False

def _post_close(hwnd) -> bool:
    """退路：给对话框发 WM_CLOSE（没有可点的 Button 时用）。"""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        return bool(ctypes.windll.user32.PostMessageW(int(hwnd), 0x0010, 0, 0))
    except Exception:  # noqa: BLE001
        return False

def dialog_brief(d: dict) -> dict:
    """对话框摘要（去掉 hwnd 细节，便于回传）。"""
    return {"pid": d.get("pid"), "hwnd": d.get("hwnd"), "title": d.get("title", ""),
            "message": d.get("message", ""), "buttons": (d.get("button_texts") or [])}

def _wait_dialog_gone(hwnd, timeout: float = 3.0, interval: float = 0.15) -> bool:
    """等对话框窗口消失（点完按钮后需要一点时间让目标线程处理）。"""
    t0 = time.monotonic()
    while True:
        left = [d for d in find_modal_dialogs() if int(d.get("hwnd") or 0) == int(hwnd)]
        if not left:
            return True
        if time.monotonic() - t0 >= timeout:
            return False
        time.sleep(interval)

def dismiss_modal_dialog(button: str = "", title: str = "", index: int = 0,
                         wait: float = 3.0) -> dict:
    """读取 Keil 模态对话框的正文/按钮并把它关掉（AI 自愈闭环的最后一步）。

    - button 指定按钮文字（部分匹配亦可，如 "确定"）；给定却找不到 → 直接报
      button_not_found 并列出可用按钮，**不擅自改点别的**；
    - 未指定 button 时按确定/OK/是/关闭/重试 的语义顺序自动挑，挑不到退化为 WM_CLOSE；
    - 关掉与否以"窗口是否真的消失"为准，不看点击调用的返回值。
    """
    dialogs = find_modal_dialogs()
    if not dialogs:
        return {"ok": False, "code": "no_dialog",
                "error": ("未发现 Keil(UV4) 模态对话框——命令不返回可能是别的原因，"
                          "可用 keil_health 看进程/端口/调试态"),
                "modal_dialogs": []}
    if title and title.strip():
        key = title.strip().lower()
        target = next((d for d in dialogs if key in (d.get("title") or "").lower()), None)
        if target is None:
            return {"ok": False, "code": "dialog_not_found",
                    "error": "未找到标题含 %r 的对话框" % title,
                    "modal_dialogs": [dialog_brief(d) for d in dialogs]}
    else:
        i = max(0, min(int(index or 0), len(dialogs) - 1))
        target = dialogs[i]

    btns = target.get("buttons") or []
    hwnd = int(target.get("hwnd") or 0)
    if button and button.strip():
        btn = _pick_button(btns, button)
        if btn is None:
            return {"ok": False, "code": "button_not_found",
                    "error": "对话框里没有文字匹配 %r 的按钮" % button,
                    "dialog": dialog_brief(target),
                    "hint": "可用 button 传其中之一，或省略 button 走默认（确定/OK/是/关闭）。"}
        method, clicked = "BM_CLICK", btn.get("text", "")
        _click_control(btn.get("hwnd"))
    else:
        btn = _pick_button(btns, "")
        if btn is not None:
            method, clicked = "BM_CLICK", btn.get("text", "")
            _click_control(btn.get("hwnd"))
        elif hwnd:
            method, clicked = "WM_CLOSE", ""
            _post_close(hwnd)
        else:
            return {"ok": False, "code": "no_button",
                    "error": "该对话框没有可点的按钮，也取不到窗口句柄",
                    "dialog": dialog_brief(target)}

    dismissed = _wait_dialog_gone(hwnd, wait)
    remaining = [dialog_brief(d) for d in find_modal_dialogs()]
    out = {"ok": dismissed, "code": "dismissed" if dismissed else "still_open",
           "dismissed": dismissed, "method": method, "clicked": clicked,
           "dialog": dialog_brief(target), "remaining": remaining}
    if dismissed:
        out["note"] = ("已关闭模态框，阻塞应已解除，可重试之前的命令。"
                       "注意：关框只解除阻塞，不代表问题已修——"
                       "请按对话框正文处置（例如正文说输出文件写不进去，就要先解决写权限/占用）。")
    else:
        out["note"] = ("点了 %s 但对话框仍在，可能被别的对话框挡住或 Keil 无响应；"
                       "可在 Keil 界面手动处理，或 restart_keil 重启。" % (clicked or method))
    return out
