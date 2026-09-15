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
import subprocess
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
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False, startupinfo=startupinfo,
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
        return -1, "构建超时（UV4 未在限定时间内退出）"
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
                  timeout: int = 300) -> dict:
    """编译工程（UV4 -b）。"""
    args = ["-b", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("编译", code, out)


def rebuild_project(uv4: str, project: str, target: str | None = None,
                    timeout: int = 300) -> dict:
    """重新编译工程（UV4 -r，全量重编）。"""
    args = ["-r", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("重新编译", code, out)


def flash_download(uv4: str, project: str, target: str | None = None,
                   timeout: int = 300) -> dict:
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


def build_and_flash(uv4: str, project: str, target: str | None = None,
                    build_timeout: int = 300, flash_timeout: int = 300) -> dict:
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
