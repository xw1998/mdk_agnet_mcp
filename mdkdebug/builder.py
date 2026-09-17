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
import time
from pathlib import Path

from . import winutil

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
        # 清掉会干扰 Keil BeforeMake 钩子（py -3 xxx.py）的 Python 环境变量：
        # MCP 服务进程若带 PYTHONHOME/PYTHONPATH，钩子里的 python 会因解释器定位错乱
        # 抛出多帧 traceback，把真正的编译结论（0 Error(s)）淹没在噪声里。
        for _k in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"):
            env.pop(_k, None)
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


_reset_connection_hook = None


def set_reset_connection_hook(fn) -> None:
    """由 server 层注入"丢弃旧 UVSOCK 连接"的能力。

    builder 不反向依赖 server（避免模块耦合），自愈时经此钩子调用；
    单测可直接替换钩子打桩。
    """
    global _reset_connection_hook
    _reset_connection_hook = fn


def _call_reset_connection(reason: str) -> None:
    """丢弃当前 UVSOCK 连接（优先用注入钩子，未注入时延迟导入 server 兜底）。"""
    if _reset_connection_hook is not None:
        _reset_connection_hook(reason)
        return
    from . import server as _server
    _server._get_client().reset_connection(reason=reason)


def _channel_snapshot() -> dict:
    """调试通道（UVSOCK）健康快照；永不抛异常（探测失败也返回结构化结果）。"""
    try:
        return winutil.keil_health()
    except Exception as e:  # noqa: BLE001
        return {"code": "error", "keil_alive": None, "port_listening": None,
                "uvsock_ready": False, "error": str(e)}


def _recover_debug_channel(uv4: str, project: str = "", wait: float = 20.0) -> dict:
    """编译/烧录后调试通道丢失时尝试原地恢复（无需用户手工 restart_keil）。

    步骤：脱离调用方 job 拉起 Keil → 等 4823 进入监听 → 丢弃旧 UVSOCK 连接（下次调用重建）。
    仅在"编译前通道可用、编译后不可用"时才被调用（见 _result），避免用户本就没开 Keil 时擅自弹窗。
    """
    t0 = time.time()
    out = {"attempted": True, "launched": None, "port_listening": False,
           "connection_reset": False, "error": None, "wait_ms": 0}
    try:
        # 与 launch_uvision 同一条路径：已有同工程窗口则复用，避免每次自愈都多开一个窗口
        lr = launch_uvision(uv4, project or "")
        out["launched"] = lr
        out["reused_window"] = bool(lr.get("reused"))
        if not lr.get("ok"):
            out["error"] = "拉起 Keil 失败：%s" % lr.get("error")
    except Exception as e:  # noqa: BLE001
        out["error"] = "拉起 Keil 失败：%s" % e
    try:
        out["port_listening"] = bool(winutil.wait_port_listening(
            winutil.DEFAULT_UVSOCK_PORT, timeout=wait))
    except Exception as e:  # noqa: BLE001
        out["error"] = out["error"] or ("等待 UVSOCK 端口失败：%s" % e)
    if out["port_listening"]:
        try:
            _call_reset_connection("编译/烧录后调试通道丢失，自动恢复")
            out["connection_reset"] = True
        except Exception as e:  # noqa: BLE001
            out["error"] = out["error"] or ("重置 UVSOCK 连接失败：%s" % e)
    out["wait_ms"] = int((time.time() - t0) * 1000)
    out["keil_after"] = _channel_snapshot()
    out["recovered"] = bool(out["port_listening"] and out["connection_reset"])
    return out


def _result(action: str, exit_code: int, output: str, keil_before: dict | None = None,
            uv4: str = "", ensure_debug_channel: bool = True,
            project: str = "", recover_wait: float = 20.0) -> dict:
    """统一结果封装。

    编译/烧录（UV4 命令行）与在线调试（UVSOCK）是两条独立通道：前者自己起实例、跑完即退，
    部分情况下（已有 GUI 实例时）UV4 命令行会把 GUI 实例一并带走，于是出现
    「编译成功但 4823 无人监听」——调试紧接着就失败。这里在编译前后各取一次健康快照，
    并**仅当"编译前通道可用、编译后不可用"**时自动恢复（拉起 Keil + 等端口 + 重置连接），
    避免用户本就没开 Keil 时被擅自弹窗。
    """
    keil_after = _channel_snapshot()
    recovery = None
    if (ensure_debug_channel and uv4 and isinstance(keil_before, dict)
            and keil_before.get("uvsock_ready") and not keil_after.get("uvsock_ready")):
        recovery = _recover_debug_channel(uv4, project, recover_wait)
        if recovery.get("keil_after"):
            keil_after = recovery["keil_after"]
    d = {
        "ok": exit_code in (0, 1),
        "exit_code": exit_code,
        "status_text": _status_text(exit_code),
        "action": action,
        "output": output.strip() or "",
        "keil": keil_after,
        "keil_before": keil_before,
        "keil_after": keil_after,
        "ensure_debug_channel": bool(ensure_debug_channel),
    }
    if not ensure_debug_channel:
        d["keil_note"] = "本次未启用调试通道自愈（ensure_debug_channel=false）"
    elif recovery is not None:
        d["keil_recovered"] = bool(recovery.get("recovered"))
        d["keil_wait_ms"] = recovery.get("wait_ms")
        d["keil_recovery"] = recovery
        if recovery.get("recovered"):
            d["keil_note"] = ("检测到编译前调试通道可用、编译后丢失，已自动重启 Keil 并重建连接"
                              "（耗时约 %d ms）" % recovery.get("wait_ms", 0))
        else:
            d["keil_note"] = ("检测到编译后调试通道丢失，自动恢复未成功；"
                              "可调用 restart_keil 或 keil_health 进一步排查")
    elif not keil_after.get("uvsock_ready"):
        d["keil_note"] = ("调试通道当前不可用（code=%s）；若需调试请先 restart_keil 或"
                          "用 keil_health 查看建议" % keil_after.get("code"))
    return d


def build_project(uv4: str, project: str, target: str | None = None,
                  timeout: int = DEFAULT_BUILD_TIMEOUT,
                  ensure_debug_channel: bool = True) -> dict:
    """编译工程（UV4 -b）。

    ensure_debug_channel=True 时：执行前记录调试通道健康快照，执行后若发现
    "编译前可用、编译后丢失"，则自动拉起 Keil 并重建 UVSOCK 连接。
    """
    keil_before = _channel_snapshot()
    args = ["-b", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("编译", code, out, keil_before=keil_before, uv4=uv4,
                   ensure_debug_channel=ensure_debug_channel, project=project)


def rebuild_project(uv4: str, project: str, target: str | None = None,
                    timeout: int = DEFAULT_BUILD_TIMEOUT,
                    ensure_debug_channel: bool = True) -> dict:
    """重新编译工程（UV4 -r，全量重编）。

    ensure_debug_channel=True 时：执行前记录调试通道健康快照，执行后若发现
    "编译前可用、编译后丢失"，则自动拉起 Keil 并重建 UVSOCK 连接。
    """
    keil_before = _channel_snapshot()
    args = ["-r", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("重新编译", code, out, keil_before=keil_before, uv4=uv4,
                   ensure_debug_channel=ensure_debug_channel, project=project)


def flash_download(uv4: str, project: str, target: str | None = None,
                   timeout: int = DEFAULT_FLASH_TIMEOUT,
                   ensure_debug_channel: bool = True) -> dict:
    """烧录工程到目标 Flash（UV4 -f，Flash Download）。

    ensure_debug_channel=True 时：执行前记录调试通道健康快照，执行后若发现
    "烧录前可用、烧录后丢失"，则自动拉起 Keil 并重建 UVSOCK 连接。
    """
    keil_before = _channel_snapshot()
    args = ["-f", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    return _result("烧录", code, out, keil_before=keil_before, uv4=uv4,
                   ensure_debug_channel=ensure_debug_channel, project=project)


def _same_project(a, b) -> bool:
    """两个工程路径是否指向同一文件（大小写 / 分隔符 / 相对片段归一后再比）。"""
    if not a or not b:
        return False
    try:
        return (os.path.normcase(os.path.normpath(str(a)))
                == os.path.normcase(os.path.normpath(str(b))))
    except Exception:  # noqa: BLE001
        return str(a).strip().lower() == str(b).strip().lower()


def list_uvision_instances(project: str = "") -> dict:
    """列出当前 Keil uVision 实例（PID / 启动时间 / 打开的工程 / 是否有窗口）。

    存在的理由（真机实测）：UV4.exe **不是**单实例程序，同一工程可以被反复打开成多个
    窗口且互不回收——每调用一次可见方式启动就可能多一个窗口。先把"现在开了几个"摆出来，
    再决定要不要收敛。project 非空时只统计该工程的实例。
    """
    items = winutil.uv4_instances()
    matched = [i for i in items if _same_project(i.get("project"), project)] if project else items
    out = {
        "ok": True,
        "action": "列出Keil实例",
        "count": len(matched),
        "total": len(items),
        "instances": [{
            "pid": i.get("pid"),
            "created": i.get("created"),
            "created_str": (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i["created"]))
                            if i.get("created") else None),
            "project": i.get("project", ""),
            "has_window": bool(i.get("has_window")),
        } for i in matched],
    }
    if project:
        out["project_filter"] = project
    if len(matched) > 1:
        out["note"] = ("同一工程已开 %d 个窗口（UV4 并非单实例程序）。"
                       '如需收敛为一个：close_uvision(keep="latest")。' % len(matched))
    return out


def launch_uvision(uv4: str, project: str, reuse: bool = True) -> dict:
    """可见方式启动 Keil uVision 并打开指定工程（供调试查看界面）。

    以**脱离调用方 job** 的方式启动（CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS |
    CREATE_NEW_PROCESS_GROUP），并把标准流接到 DEVNULL。否则由 MCP 服务拉起的 UV4 会
    随调用链所在的 job 一起被回收（现象："刚拉起就没了"），标准流也会继承被污染的环境。

    真机实测修正：UV4.exe **不是**单实例程序——同一工程可以被反复打开成多个窗口且互不
    回收（曾累积 6 个同工程实例）。因此这里先枚举已有实例：
    - reuse=True（默认）：已有同工程窗口则**复用**（前置该窗口）并如实返回 reused=true，
      不再新开窗口；
    - reuse=False：无条件新开一个窗口（仅在确实需要第二个窗口时使用）。
    """
    if reuse and project:
        same = [i for i in winutil.uv4_instances()
                if _same_project(i.get("project"), project)]
        if same:
            cur = same[-1]                      # 列表按创建时间升序 → 末位为最新
            focused = winutil.focus_window(cur.get("hwnd"))
            return {
                "ok": True, "reused": True, "pid": cur.get("pid"),
                "instances": len(same), "focused": focused,
                "msg": "已有同工程 Keil 实例，复用该窗口（未新开；当前同工程窗口 %d 个）"
                       % len(same),
                "hint": ('如需收敛到单窗口：close_uvision(keep="latest")；'
                         "如需看全部实例：list_uvision_instances。"),
            }
    r = winutil.launch_detached(uv4, project)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error", "启动 Keil 失败")}
    return {
        "ok": True, "reused": False,
        "pid": r.get("pid"),
        "creationflags": r.get("creationflags"),
        "breakaway": r.get("breakaway"),
        "msg": "已脱离父进程启动 Keil uVision 并打开工程",
        "hint": "UVSOCK 需数秒才监听；可用 keil_health 确认 port_listening，"
                "或用 restart_keil 一步完成关闭→重启→等待→重连。",
    }


def _uv4_pids() -> list[int]:
    """枚举 UV4.exe 的 PID（委托 winutil；保留函数名以兼容既有引用与测试）。"""
    return winutil.uv4_pids()

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

def close_uvision(force: bool = False, timeout: int = 10, keep: str = "all",
                  project: str = "") -> dict:
    """关闭 Keil uVision 实例（AI 管理 Keil 开关的闭环，纯 ctypes 不依赖 taskkill）。

    - keep="all"（默认）：关闭全部实例；
    - keep="latest" / "oldest"：**只保留一个**实例（最新 / 最早启动的那个），其余关闭——
      用于把"反复打开累积的多个同工程窗口"收敛成一个，只开一个窗口调试；
    - project 非空：只处理打开该工程的实例（默认处理所有实例）。
    force=False：先对每个实例的可见主窗口发 WM_CLOSE 优雅关闭，等待退出；
    超时后残留实例强制终止。force=True：直接强制终止。
    注意：未保存的调试会话/源码改动可能丢失，调用前请确保已保存。
    """
    import time as _time
    inst = winutil.uv4_instances()
    if project:
        inst = [i for i in inst if _same_project(i.get("project"), project)]
    before = [i["pid"] for i in inst] if inst else _uv4_pids()
    if not before:
        return {"ok": True, "action": "关闭Keil", "closed": 0, "kept": [],
                "msg": "当前无 Keil uVision 实例"}
    keep = str(keep or "all").lower()
    keep_pid = None
    if keep in ("latest", "oldest"):
        if len(before) == 1:
            keep_pid = before[0]
        else:
            ordered = sorted(inst, key=lambda x: (x.get("created") is None,
                                                  x.get("created") or 0.0, x["pid"]))
            keep_pid = ordered[-1]["pid"] if keep == "latest" else ordered[0]["pid"]
    targets = [p for p in before if p != keep_pid]
    kept = [keep_pid] if keep_pid else []
    if not targets:
        return {"ok": True, "action": "关闭Keil", "closed": 0, "kept": kept, "keep": keep,
                "total_before": len(before), "msg": "已是单个实例，无需关闭"}
    try:
        if not force:
            for pid in targets:
                _close_uvision_graceful(pid)
            # 等待优雅退出（只看本次目标，保留的实例不算残留）
            deadline = _time.time() + timeout
            while _time.time() < deadline:
                if not [p for p in _uv4_pids() if p in targets]:
                    break
                _time.sleep(0.3)
            remain = [p for p in _uv4_pids() if p in targets]
            if remain:
                for pid in remain:
                    _terminate_uvision(pid)
                remain = [p for p in _wait_pids_settle() if p in targets]
                return {"ok": len(remain) == 0, "action": "关闭Keil", "keep": keep,
                        "closed": len(targets), "kept": kept, "total_before": len(before),
                        "force_fallback": True, "remaining": remain}
            return {"ok": True, "action": "关闭Keil", "keep": keep,
                    "closed": len(targets), "kept": kept, "total_before": len(before),
                    "force": False}
        for pid in targets:
            _terminate_uvision(pid)
        remain = [p for p in _wait_pids_settle() if p in targets]
        return {"ok": len(remain) == 0, "action": "关闭Keil", "keep": keep,
                "closed": len(targets), "kept": kept, "total_before": len(before),
                "force": True, "remaining": remain}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"关闭 Keil 失败：{e}"}


def build_and_flash(uv4: str, project: str, target: str | None = None,
                    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
                  flash_timeout: int = DEFAULT_FLASH_TIMEOUT,
                  ensure_debug_channel: bool = True) -> dict:
    """编译 + 烧录闭环：编译成功后才烧录。

    两个阶段各自带"前置健康快照 + 编译后按需自愈"（见 _result）。
    顶层汇总 keil_before（进入本调用前的通道状态）与 keil_after（收尾时状态），
    便于一眼区分「编译成功」与「调试通道是否还活着」。
    """
    build = build_project(uv4, project, target, build_timeout,
                          ensure_debug_channel=ensure_debug_channel)
    if not build["ok"]:
        return {
            "ok": False, "action": "编译并烧录",
            "stage": "编译", "build": build,
            "keil_before": build.get("keil_before"),
            "keil_after": build.get("keil_after"),
            "status_text": "编译未通过，未执行烧录",
        }
    flash = flash_download(uv4, project, target, flash_timeout,
                           ensure_debug_channel=ensure_debug_channel)
    out = {
        "ok": flash["ok"], "action": "编译并烧录",
        "stage": "烧录", "build": build, "flash": flash,
        "keil_before": build.get("keil_before"),
        "keil_after": flash.get("keil_after"),
        "ensure_debug_channel": bool(ensure_debug_channel),
        "status_text": ("烧录成功" if flash["ok"] else "编译成功但烧录失败"),
    }
    if flash.get("keil_recovered"):
        out["keil_recovered"] = True
        out["keil_wait_ms"] = flash.get("keil_wait_ms")
    return out
