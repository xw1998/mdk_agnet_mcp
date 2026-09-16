# -*- coding: utf-8 -*-
"""
UV4 命令行构建封装 —— 编译 / 重编译 / 烧录 Keil 工程。

基于 Keil 官方 UV4.exe 命令行接口：
    UV4 -b project.uvprojx [-t target]   # 编译
    UV4 -r project.uvprojx [-t target]   # 重新编译
    UV4 -f project.uvprojx [-t target]   # 烧录（Flash Download）
    UV4 -c project.uvprojx               # 清理
    UV4 -o out.txt                       # 把构建输出重定向到文件

UV4 退出码约定：0=成功，1=成功但有警告，2=有错误，>=3=构建不完整/其他错误。
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# 常见 Keil 安装路径（用于自动探测 UV4.exe）
_UV4_CANDIDATES = [
    r"C:\Keil_v5\UV4\UV4.exe",
    r"C:\Keil\UV4\UV4.exe",
    r"D:\Keil_v5\UV4\UV4.exe",
    r"E:\Keil_v5\UV4\UV4.exe",
    r"C:\Program Files\Keil_v5\UV4\UV4.exe",
    r"C:\Program Files (x86)\Keil_v5\UV4\UV4.exe",
]


def find_uv4(explicit: str | None = None) -> str | None:
    """定位 UV4.exe。优先显式路径，其次探测常见路径，再查注册表。"""
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        logger.warning("指定 UV4 路径不存在：%s", explicit)
    for cand in _UV4_CANDIDATES:
        if os.path.isfile(cand):
            logger.info("探测到 UV4.exe：%s", cand)
            return cand
    try:
        import winreg  # noqa: PLC0415
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, r"SOFTWARE\Keil\Products\MDK") as key:
                    root, _ = winreg.QueryValueEx(key, "Path")
                uv4 = os.path.join(root, "UV4", "UV4.exe")
                if os.path.isfile(uv4):
                    logger.info("注册表定位到 UV4.exe：%s", uv4)
                    return uv4
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return None


# 编译/烧录默认超时（秒）。
# 旧默认 300s 对大型工程 / 首次全量编译 / 带预处理脚本（gen_scatter.py 等）的工程
# 明显不够，会把"还在编译"误判成失败。默认放宽，并允许调用方按工程调整。
DEFAULT_BUILD_TIMEOUT = 1800
DEFAULT_FLASH_TIMEOUT = 600


def _status_text(exit_code: int) -> str:
    """把 UV4 退出码映射为可读文本。"""
    if exit_code == 0:
        return "成功"
    if exit_code == 1:
        return "成功（有警告）"
    if exit_code == 2:
        return "有错误"
    if exit_code == 3:
        return "构建不完整（可能缺少工具链）"
    if exit_code == -1:
        return "超时（UV4 未在限定时间内退出，本次进程已被终止）"
    if exit_code == -2:
        return "找不到 UV4 可执行文件"
    if exit_code == -3:
        return "调用 UV4 失败"
    return f"失败（退出码 {exit_code}）"


def _run_uv4(uv4: str, args: list[str], timeout: int,
             visible: bool = False) -> tuple[int, str]:
    """运行 UV4，捕获输出，返回 (退出码, 输出文本)。

    visible=False 时以隐藏窗口方式启动 UV4，避免编译/烧录时闪现新的
    Keil 界面（用户常已打开一个 uVision 实例，不应再弹窗打扰）。
    隐藏的是本次新建的 UV4 进程窗口，不影响用户已打开实例的显示。
    """
    # 用 -o 把构建输出重定向到临时文件（UV4 的 GUI 构建日志不走 stdout）
    log_fd, log_path = tempfile.mkstemp(suffix=".log")
    os.close(log_fd)
    cmd = [uv4] + args + ["-o", log_path]
    out_text = ""
    # 隐藏新进程主窗口（GUI 程序；SW_HIDE 不产生控制台，也不影响既有实例）
    startupinfo = None
    if os.name == "nt" and not visible:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
    # UV4 子进程用 Windows 系统 PATH 查找 python 以执行 gen_scatter.py 等预处理脚本；
    # 若 python 不在系统 PATH（venv / Git Bash 内解释器），会报 CreateProcess failed。
    # 注入当前解释器目录到 PATH 前部，保证 UV4 能找到 python。
    env = None
    if os.name == "nt":
        env = os.environ.copy()
        py_dir = os.path.dirname(sys.executable)
        if py_dir:
            cur = env.get("PATH", "")
            env["PATH"] = py_dir + (os.pathsep + cur if cur else "")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False, startupinfo=startupinfo, env=env,
        )
        parts = [s for s in (proc.stdout, proc.stderr) if s]
        out_text = "".join(parts)
        if os.path.isfile(log_path):
            try:
                with open(log_path, encoding="utf-8", errors="replace") as f:
                    file_text = f.read()
                if file_text.strip():
                    out_text = (out_text + "\n" + file_text).strip()
            except OSError:
                pass
        return proc.returncode, out_text
    except subprocess.TimeoutExpired:
        return -1, (
            "超时：UV4 未在 %d 秒内退出，本次进程已终止。\n"
            "大型工程、首次全量编译或带预处理脚本的工程可能超过该上限；"
            "可调大工具的 timeout_s 参数后重试（如 timeout_s=3600）。" % timeout)
    except FileNotFoundError:
        return -2, f"找不到 UV4 可执行文件：{uv4}"
    except Exception as e:  # noqa: BLE001
        return -3, f"调用 UV4 失败：{e}"
    finally:
        try:
            if os.path.isfile(log_path):
                os.remove(log_path)
        except OSError:
            pass


def _result(action: str, exit_code: int, output: str) -> dict:
    return {
        "ok": exit_code in (0, 1),
        "exit_code": exit_code,
        "status_text": _status_text(exit_code),
        "action": action,
        "output": output.strip() or "",
    }


def build_project(uv4: str, project: str, target: str | None = None,
                  timeout: int = DEFAULT_BUILD_TIMEOUT) -> dict:
    """编译工程（UV4 -b）。"""
    args = ["-b", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("编译", code, out)


def rebuild_project(uv4: str, project: str, target: str | None = None,
                    timeout: int = DEFAULT_BUILD_TIMEOUT) -> dict:
    """重新编译工程（UV4 -r，全量重编）。"""
    args = ["-r", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("重新编译", code, out)


def flash_download(uv4: str, project: str, target: str | None = None,
                   timeout: int = DEFAULT_FLASH_TIMEOUT) -> dict:
    """烧录工程到目标 Flash（UV4 -f，Flash Download）。"""
    args = ["-f", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("烧录", code, out)


def launch_uvision(uv4: str, project: str) -> dict:
    """可见方式启动 Keil uVision 并打开指定工程（供调试查看界面）。

    UV4.exe 是 uVision 单实例程序：若已有一个 uVision 运行且打开相同工程，
    本次启动会复用已有实例（新进程随即退出），不会另开窗口。
    用 Popen 异步启动、立即返回，不阻塞调用方。
    """
    if not uv4:
        return {"ok": False, "error": "未定位到 UV4.exe"}
    cmd = [uv4, project]
    try:
        proc = subprocess.Popen(cmd)
        return {
            "ok": True,
            "pid": proc.pid,
            "msg": "已启动 Keil uVision 并打开工程（若已运行同工程则复用已有实例）",
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"启动 Keil uVision 失败：{e}"}


def _uv4_pids() -> list[int]:
    """用 Toolhelp 快照枚举当前所有 UV4.exe 的 PID（纯 ctypes，不依赖 tasklist）。"""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return []
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
                except Exception:
                    break
                if name.lower() == "uv4.exe":
                    pids.append(int(pe.th32ProcessID))
                if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return pids


def _close_uvision_graceful(pid: int) -> bool:
    """向指定 PID 的可见主窗口发送 WM_CLOSE（优雅关闭）。返回是否找到窗口。"""
    try:
        import ctypes
        from ctypes import wintypes
        WM_CLOSE = 0x0010
        user32 = ctypes.windll.user32
        found = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def _cb(hwnd, _lparam):
            pid_win = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_win))
            if pid_win.value == pid and user32.IsWindowVisible(hwnd):
                found.append(hwnd)
                return False
            return True

        user32.EnumWindows(_cb, 0)
        if found:
            user32.PostMessage(found[0], WM_CLOSE, 0, 0)
            return True
        return False
    except Exception:
        return False


def _terminate_uvision(pid: int) -> None:
    """强制终止指定 PID 的进程（TerminateProcess，纯 ctypes）。"""
    try:
        import ctypes
        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if handle:
            kernel32.TerminateProcess(handle, 1)
            kernel32.CloseHandle(handle)
    except Exception:
        pass


def _wait_pids_settle(wait: float = 2.0) -> list[int]:
    """强制终止后短暂轮询，等待 UV4 进程真正退出，避免返回时误报残留 PID。"""
    import time as _time
    deadline = _time.time() + wait
    while _time.time() < deadline:
        remain = _uv4_pids()
        if not remain:
            return []
        _time.sleep(0.1)
    return _uv4_pids()

def close_uvision(force: bool = False, timeout: int = 10) -> dict:
    """关闭所有 Keil uVision 实例（AI 管理 Keil 开关的闭环，纯 ctypes 不依赖 taskkill）。

    force=False：先对每个实例的可见主窗口发 WM_CLOSE 优雅关闭，等待退出；
    超时后残留实例强制终止。force=True：直接强制终止所有 UV4.exe。
    注意：会关闭所有 Keil 实例；未保存的调试会话/源码改动可能丢失，调用前请确保已保存。
    """
    import time as _time
    before = _uv4_pids()
    if not before:
        return {"ok": True, "action": "关闭Keil", "closed": 0, "msg": "当前无 Keil uVision 实例"}
    try:
        if not force:
            for pid in before:
                _close_uvision_graceful(pid)
            # 等待优雅退出
            deadline = _time.time() + timeout
            while _time.time() < deadline:
                if not _uv4_pids():
                    break
                _time.sleep(0.3)
            remain = _uv4_pids()
            if remain:
                for pid in remain:
                    _terminate_uvision(pid)
                remain = _wait_pids_settle()
                return {"ok": len(remain) == 0, "action": "关闭Keil",
                        "closed": len(before), "force_fallback": True, "remaining": remain}
            return {"ok": True, "action": "关闭Keil", "closed": len(before), "force": False}
        for pid in before:
            _terminate_uvision(pid)
        remain = _wait_pids_settle()
        return {"ok": len(remain) == 0, "action": "关闭Keil",
                "closed": len(before), "force": True, "remaining": remain}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"关闭 Keil 失败：{e}"}


def build_and_flash(uv4: str, project: str, target: str | None = None,
                    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
                  flash_timeout: int = DEFAULT_FLASH_TIMEOUT) -> dict:
    """编译 + 烧录闭环：编译成功后才烧录。"""
    build = build_project(uv4, project, target, build_timeout)
    if not build["ok"]:
        return {
            "ok": False, "action": "编译并烧录",
            "stage": "编译", "build": build,
            "status_text": "编译未通过，未执行烧录",
        }
    flash = flash_download(uv4, project, target, flash_timeout)
    return {
        "ok": flash["ok"], "action": "编译并烧录",
        "stage": "烧录", "build": build, "flash": flash,
        "status_text": ("烧录成功" if flash["ok"] else "编译成功但烧录失败"),
    }
