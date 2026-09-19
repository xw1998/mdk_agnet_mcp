# -*- coding: utf-8 -*-
"""
UV4 命令行构建封装 —— 编译 / 重编译 / 烧录 Keil 工程。

基于 Keil 官方 UV4.exe 命令行接口：
    UV4 -b project.uvprojx [-t target]   # 编译
    UV4 -r project.uvprojx [-t target]   # 重新编译
    UV4 -f project.uvprojx [-t target]   # 烧录（Flash Download）
    UV4 -c project.uvprojx               # 清理
    UV4 -o out.txt                       # 把构建输出重定向到文件

UV4 退出码约定（完整表见 `_UV4_EXIT_MEANING`）：0=成功，1=成功但有警告，2=有错误，
3=致命错误，11=工程打不开，12=器件库缺失，13=写入错误，15=UV4 被占用，20=未知。
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

# 常见 Keil 安装子目录（相对某个盘符根，如 D:\ → D:\Keil_v5\UV4\UV4.exe）
_KEIL_UV4_SUBDIRS = (
    r"Keil_v5\UV4\UV4.exe",
    r"Keil\UV4\UV4.exe",
    r"Keil_v4\UV4\UV4.exe",
    r"Program Files\Keil_v5\UV4\UV4.exe",
    r"Program Files (x86)\Keil_v5\UV4\UV4.exe",
)

# 盘符枚举结果缓存（一次进程内不变；非 Windows 为空表）
_DRIVE_CACHE: list[str] | None = None


def _logical_drives() -> list[str]:
    """本机存在的盘符根，形如 ['C:\\', 'D:\\']。

    真机踩坑：旧实现把候选写死成 C:/D:/E: 那几条——Keil 装在别处（F: 盘、移动盘、
    第二个系统）时连候选都没有；注册表那一路又查错视图（见 _uv4_from_registry），
    于是 `find_uv4()` 在本机其实「靠巧合」才命中。这里枚举真实盘符，候选随机器走。
    """
    global _DRIVE_CACHE
    if _DRIVE_CACHE is not None:
        return _DRIVE_CACHE
    drives: list[str] = []
    if os.name == "nt":
        for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            root = "%s:\\" % ch
            try:
                if os.path.isdir(root):
                    drives.append(root)
            except OSError:
                continue
    _DRIVE_CACHE = drives
    return drives


def uv4_candidates(extra: list[str] | None = None) -> list[str]:
    """UV4.exe 候选路径：盘符枚举 × 常见安装子目录（去重保序）。

    候选全部**动态**算出，不再依赖写死的盘符；extra 用于追加调用方已知的目录。
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(path: str) -> None:
        q = str(path or "")
        if q and q not in seen:
            seen.add(q)
            out.append(q)

    for d in (extra or []):
        _add(d)
    for root in _logical_drives():
        for sub in _KEIL_UV4_SUBDIRS:
            _add(os.path.join(root, sub))
    return out


# 注册表里 Keil 的 Path 值有的指安装根（...\Keil_v5），有的指工具根（...\Keil_v5\ARM），
# UV4 在两者的 UV4\ 子目录下——两类都要试，见 _uv4_from_registry。
_KEIL_REG_KEYS = (
    r"SOFTWARE\Keil\Products\MDK",
    r"SOFTWARE\Keil\Products\Keil",
)


def _keil_reg_views() -> list[tuple[str, int]]:
    """(视图名, 访问标志) 列表：32 位 + 64 位两个注册表视图。

    Keil MDK 是 32 位程序 → 注册到 `SOFTWARE\\WOW6432Node\\...`；64 位 Python 默认
    按 64 位视图读 `SOFTWARE\\...`，**必然查不到**。旧实现只读默认视图，等于没查。
    """
    try:
        import winreg  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return []
    views = []
    for name, flag in (("32 位视图", getattr(winreg, "KEY_WOW64_32KEY", 0)),
                       ("64 位视图", getattr(winreg, "KEY_WOW64_64KEY", 0))):
        if flag:
            views.append((name, winreg.KEY_READ | flag))
    if not views:
        views.append(("默认视图", winreg.KEY_READ))
    return views


def _uv4_from_registry() -> tuple[str | None, list[str]]:
    """查注册表定位 UV4.exe。返回 (路径或 None, 尝试记录)。

    两个坑（本机实测）：
    1. 只查一个视图 → `HKLM\\SOFTWARE\\Keil\\Products\\MDK` 在 64 位视图下报
       「找不到（错误码 2）」，值只在 WOW6432Node（32 位视图）里。
    2. `Path` 的值是 `D:\\Keil_v5\\ARM`（**工具根**，不是安装根），旧实现拼
       `Path\\UV4\\UV4.exe` 拼出的文件根本不存在；上提一级才是真路径。
    找不到时把「试过哪些键/视图/值」一并返回——报错要有证据，不静默。
    """
    try:
        import winreg  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None, ["非 Windows：无注册表"]
    views = _keil_reg_views()
    if not views:
        return None, ["非 Windows：无注册表"]
    tried: list[str] = []
    for sub in _KEIL_REG_KEYS:
        for hive, hname in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"),
                            (winreg.HKEY_CURRENT_USER, "HKCU")):
            for vname, access in views:
                try:
                    with winreg.OpenKey(hive, sub, 0, access) as key:
                        root, _ = winreg.QueryValueEx(key, "Path")
                except OSError as e:
                    tried.append("%s\\%s（%s）：取不到（%s）"
                                 % (hname, sub, vname, getattr(e, "winerror", e)))
                    continue
                base = str(root or "").rstrip("\\/")
                if not base:
                    tried.append("%s\\%s（%s）：Path 值为空" % (hname, sub, vname))
                    continue
                for cand_root in (base, os.path.dirname(base)):
                    uv4 = os.path.join(cand_root, "UV4", "UV4.exe")
                    if os.path.isfile(uv4):
                        logger.info("注册表定位到 UV4.exe：%s（%s\\%s，%s）",
                                    uv4, hname, sub, vname)
                        return uv4, tried
                tried.append("%s\\%s（%s）：Path=%s，其下没有 UV4\\UV4.exe"
                             % (hname, sub, vname, base))
    return None, tried


def find_uv4_detailed(explicit: str | None = None) -> dict:
    """定位 UV4.exe，并把「试过哪些地方」一并返回（找不到时要有证据，不静默）。"""
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return {"uv4": str(p), "source": "显式路径", "tried": []}
        logger.warning("指定 UV4 路径不存在：%s", explicit)
    for cand in uv4_candidates():
        if os.path.isfile(cand):
            logger.info("探测到 UV4.exe：%s", cand)
            return {"uv4": cand, "source": "盘符候选", "tried": []}
    reg_uv4, tried = _uv4_from_registry()
    if reg_uv4:
        return {"uv4": reg_uv4, "source": "注册表", "tried": tried}
    return {"uv4": None, "source": None, "tried": tried}


def find_uv4(explicit: str | None = None) -> str | None:
    """定位 UV4.exe。优先显式路径，其次枚举盘符的常见安装位置，最后查注册表。"""
    return find_uv4_detailed(explicit)["uv4"]

# 编译/烧录默认超时（秒）。
# 旧默认 300s 对大型工程 / 首次全量编译 / 带预处理脚本（gen_scatter.py 等）的工程
# 明显不够，会把"还在编译"误判成失败。默认放宽，并允许调用方按工程调整。
DEFAULT_BUILD_TIMEOUT = 1800
DEFAULT_FLASH_TIMEOUT = 600
DEFAULT_CLEAN_TIMEOUT = 300


# ----------------------------------------------------------------------
# UV4 退出码完整表（批次33：吸收 keil-project-tools/references/compiler-notes.md）
# ----------------------------------------------------------------------
# 为什么值得单独做成表：旧实现只认识 0/1/2/3，其余一律「失败（退出码 N）」——
# 而 11/12/13/15 是**四个各不相同的故障**，处置办法完全不一样：
# 工程打不开要查路径与占用、器件库缺失要装 Pack、写入错误要看输出目录权限、
# UV4 被占用要先去关实例。只说「退出码 15」等于让调用方从头排查一遍。
# 负数是我们自己的合成码（进程级失败），与 UV4 无关，一并列在这里免得混淆。
_UV4_EXIT_MEANING = {
    0: ("success", "无错误、无警告"),
    1: ("warning", "有警告，构建产物已生成"),
    2: ("build-error", "有错误，构建失败"),
    3: ("fatal", "致命错误：许可证缺失 / 工程损坏 / 工具链不可用"),
    4: ("fatal", "致命错误（UV4 报告构建未完成）"),
    5: ("fatal", "致命错误（UV4 报告构建未完成）"),
    11: ("project-open-failed", "无法打开工程文件（路径错误、被占用或文件损坏）"),
    12: ("device-db-missing", "设备数据库缺失（对应 Device Family Pack 未安装）"),
    13: ("write-error", "写入错误（输出目录只读 / 磁盘空间不足 / 产物文件被占用）"),
    15: ("uv4-busy", "UV4 访问错误：已有实例占用（该工程正被另一个 Keil 实例打开着）"),
    20: ("unknown-error", "未知错误"),
    -1: ("timeout", "超时（UV4 未在限定时间内退出，进程已被终止）"),
    -2: ("uv4-not-found", "找不到 UV4 可执行文件"),
    -3: ("launch-failed", "调用 UV4 失败"),
}

def _exit_meaning(exit_code: int) -> str:
    """返回 UV4 退出码的机器可读名（status code）。"""
    info = _UV4_EXIT_MEANING.get(int(exit_code))
    return info[0] if info else "unmapped-exit-code"

def _status_text(exit_code: int) -> str:
    """把 UV4 退出码映射为可读文本（含完整码表）。"""
    if exit_code == 0:
        return "成功"
    if exit_code == 1:
        return "成功（有警告）"
    info = _UV4_EXIT_MEANING.get(int(exit_code))
    if info:
        return "失败：%s（退出码 %d）" % (info[1], int(exit_code))
    return "失败（退出码 %d，未收录的 UV4 退出码）" % int(exit_code)

def _exit_next_actions(exit_code: int, action: str = "") -> list:
    """按退出码给出「下一步做什么」——这是本工具链最值钱的部分，做成表统一给。"""
    code = int(exit_code)
    if code in (0, 1):
        return []
    table = {
        2: ["读 output 里的第一条 error 行定位问题", "改完代码后重试本工具"],
        3: ["确认 Keil 许可证状态（UV4 能正常打开该工程且能手工构建）",
            "确认工程未被损坏：用 Keil 打开一次看是否有弹窗报错"],
        4: ["用 Keil 打开工程手工构建一次，看弹窗提示（多半是工具链/许可证问题）"],
        5: ["用 Keil 打开工程手工构建一次，看弹窗提示（多半是工具链/许可证问题）"],
        11: ["确认 project 路径拼写正确、文件确实存在（用 read_project_config 或 list_uvision_instances 核对）",
             "若工程正被 Keil 打开着导致占用，先 close_uvision 再重试"],
        12: ["安装对应器件的 Device Family Pack（Keil Pack Installer），"
             "或确认 target 名与已安装器件匹配（read_project_config 可看当前 target）"],
        13: ["检查输出目录（Objects/Listings 等）是否只读、磁盘是否已满",
             "关闭可能占用产物文件的程序（Keil 调试器、hex 查看器、烧录工具）后重试"],
        15: ["Keil 已有实例占用该工程：先 keil_health 看清状态，再 close_uvision 关闭实例后重试",
             "若需保留当前实例，改为在该实例里手工构建"],
        20: ["用 Keil 打开工程手工构建一次取得更明确的报错", "调 keil_health 排查调试通道与模态框"],
        -1: ["调大 timeout_s 后重试（大型工程/首次全量编译常超默认上限）"],
        -2: ["用 --uv4-path 指定 UV4.exe 路径，或确认 Keil 安装目录未被移动"],
        -3: ["确认 UV4.exe 可正常启动（手工双击一次）", "调 keil_health 看是否有模态框阻塞"],
    }
    acts = list(table.get(code, []))
    if not acts:
        acts = ["调 keil_health 查看 Keil 侧状态", "用 Keil 打开工程手工执行一次以取得更明确的报错"]
    if action:
        acts = acts + ["%s成功后可接着 flash_download / enter_debug 验证板上行为" % action]
    return acts



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
    # 统一走 winutil.child_env：剥掉宿主 python 变量（Keil BeforeMake 钩子的
    # `py -3 gen_scatter.py` 若继承 PYTHONHOME，会加载宿主的标准库而崩在 site 初始化上）。
    env = winutil.child_env()
    if os.name == "nt":
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
    ok = exit_code in (0, 1)
    d = {
        "ok": ok,
        "status": ("ok" if ok else "error"),
        "exit_code": exit_code,
        "exit_code_text": _status_text(exit_code),
        "exit_code_meaning": _exit_meaning(exit_code),
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
    # 统一的 next_actions：失败时按退出码给下一步；半成功（有警告）也给一句。
    acts = _exit_next_actions(exit_code, action)
    if not ok:
        d["next_actions"] = acts
        if exit_code == 15:
            d["failure_bucket"] = "keil-busy"
        elif exit_code == 11:
            d["failure_bucket"] = "project-unavailable"
        elif exit_code == 12:
            d["failure_bucket"] = "toolchain-not-ready"
        elif exit_code == 13:
            d["failure_bucket"] = "output-write-failed"
        elif exit_code in (2, 4, 5, 20):
            d["failure_bucket"] = "build-failed"
        elif exit_code == -1:
            d["failure_bucket"] = "timeout"
        else:
            d["failure_bucket"] = "toolchain-not-ready"
    elif exit_code == 1:
        d["next_actions"] = ["有警告但产物已生成，可继续 flash_download / enter_debug；"
                             "若行为异常再回看 output 里的 warning"]
    met = _parse_build_metrics(output)
    if met:
        d["metrics"] = met
    arts = _find_artifacts(project)
    if arts:
        d["artifacts"] = arts
        if not ok:
            d["artifacts_note"] = ("本次构建未成功，下列产物可能是**上一次**留下的——"
                                   "不要据此认为镜像已更新。")
    return d


# ----------------------------------------------------------------------
# 构建产物与编译统计（批次33：对齐 embeddedskills 信封的 artifacts / metrics）
# ----------------------------------------------------------------------
# 为什么值得做：调用方拿到的如果只有一段几十上百行的编译日志，就得自己去找
# 「错误几个、警告几个、产物在哪」——而这三件事恰恰是决定下一步做什么的全部依据。
# 这里把它们从日志里结构化出来，日志照旧原样返回（不丢信息，只多给索引）。
_METRIC_RX = re.compile(r"(\d+)\s*Error\(s\)\s*,?\s*(\d+)\s*Warning\(s\)", re.IGNORECASE)
_METRIC_RX2 = re.compile(r"(\d+)\s*Errors?\s*,?\s*(\d+)\s*Warnings?", re.IGNORECASE)
_ARTIFACT_EXT = (".axf", ".hex", ".bin", ".map", ".elf", ".sct", ".htm")

def _parse_build_metrics(output: str) -> dict:
    """从 UV4 构建日志里提取 错误数 / 警告数。"""
    txt = str(output or "")
    m = _METRIC_RX.search(txt) or _METRIC_RX2.search(txt)
    if not m:
        return {}
    try:
        return {"errors": int(m.group(1)), "warnings": int(m.group(2)),
                "source": "parsed-from-output"}
    except (TypeError, ValueError):
        return {}

def _find_artifacts(project: str, max_depth: int = 2) -> dict:
    """在工程目录下有界递归查找构建产物。

    输出目录名不是固定的（Keil 默认 Objects，但工程常被改成与工程同名的目录，
    如 MDK-ARM/mdk_test/），写死几个候选目录一定会漏，故改用有界递归
    （工程目录起 2 层），并按文件名主干过滤，避免把别的工程的产物算进来。
    """
    if not project:
        return {}
    base = Path(project).parent
    stem = Path(project).stem
    out = {}
    seen = set()

    def _walk(d: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        for p in entries:
            if p.is_dir():
                _walk(p, depth + 1)
                continue
            ext = p.suffix.lower()
            if ext not in _ARTIFACT_EXT:
                continue
            # 只收与工程同名的产物；.map/.htm 允许任意主干（UV4 命名不完全一致）
            if p.stem.lower() != stem.lower() and ext not in (".map", ".htm"):
                continue
            key = ext.lstrip(".")
            if key in seen:
                continue
            seen.add(key)
            try:
                st = p.stat()
                out[key] = {"path": str(p), "size": st.st_size,
                            "mtime": int(st.st_mtime)}
            except OSError:
                out[key] = {"path": str(p)}

    _walk(base, 0)
    return out

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


def clean_project(uv4: str, project: str, target: str | None = None,
                  timeout: int = DEFAULT_CLEAN_TIMEOUT,
                  ensure_debug_channel: bool = True) -> dict:
    """清理工程构建产物（UV4 -c）。

    **有副作用**：会删掉该 target 的中间文件与产物（.axf/.hex/.o 等），
    清理后必须重新编译才能烧录。用于「怀疑增量构建残留导致行为诡异」的场合，
    等价于 Keil 菜单的 Clean Targets。
    """
    keil_before = _channel_snapshot()
    args = ["-c", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    d = _result("清理", code, out, keil_before=keil_before, uv4=uv4,
                ensure_debug_channel=ensure_debug_channel, project=project)
    if d.get("ok"):
        d["note"] = ("已清理构建产物：后续必须重新编译（build_project / rebuild_project）"
                     "才能烧录或调试，否则没有可下载的镜像。")
    return d

def rebuild_project(uv4: str, project: str, target: str | None = None,
                    timeout: int = DEFAULT_BUILD_TIMEOUT,
                    ensure_debug_channel: bool = True,
                    clean_first: bool = False) -> dict:
    """重新编译工程（UV4 -r 全量重编；clean_first=True 时用 -cr 先清理再重建）。

    ensure_debug_channel=True 时：执行前记录调试通道健康快照，执行后若发现
    "编译前可用、编译后丢失"，则自动拉起 Keil 并重建 UVSOCK 连接。

    clean_first=True（-cr）比 -r 更彻底：-r 只是不做增量，仍可能复用未被判定为
    过期的产物；-cr 先删掉全部产物再重建，用于「改了构建配置/预编译脚本（如
    gen_scatter.py）后结果不对」这类场合。
    """
    keil_before = _channel_snapshot()
    args = ["-cr" if clean_first else "-r", project] + (["-t", target] if target else [])
    code, out = _run_uv4(uv4, args, timeout)
    act = "清理并重新编译" if clean_first else "重新编译"
    d = _result(act, code, out, keil_before=keil_before, uv4=uv4,
                ensure_debug_channel=ensure_debug_channel, project=project)
    d["clean_first"] = bool(clean_first)
    d["uv4_args"] = args[0]
    return d


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
    """两个工程路径是否指向同一文件（相对/绝对、大小写、分隔符归一后再比）。

    真机踩坑：调用方传的是**相对路径**（如 example_mdk_project/.../mdk_test.uvprojx），
    而实例枚举拿到的是**绝对路径**，旧实现只归一大小写/分隔符，于是判不出同一个工程，
    `launch_uvision(reuse=True)` 又开出一个新窗口（真机实测同工程窗口累积到 2 个）。
    这里先 abspath 再比，并额外退一步比 basename（路径写法千差万别时的兼容）。
    """
    if not a or not b:
        return False
    try:
        pa = os.path.normcase(os.path.abspath(os.path.normpath(str(a))))
        pb = os.path.normcase(os.path.abspath(os.path.normpath(str(b))))
        return pa == pb
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


def _keil_multi_refusal(inst, others, project) -> dict:
    """拒绝新开窗口时的统一返回：摆出既有实例 + 机器可读错误码 + 下一步动作。"""
    if project:
        why = ("已有 %d 个 Keil 实例打开的是**其它**工程：%s。再开一个会累积成多窗口"
               "（真机实测曾累积到 6 个），已拒绝。"
               % (len(others), "；".join("pid=%s %s" % (i.get("pid"), i.get("project"))
                                         for i in others)))
    else:
        why = ("本次调用没给 project，无法判断要打开的是不是既有实例的那个工程。"
               "当前已有 %d 个 Keil 实例，为避免多窗口已拒绝。"
               % len(inst))
    return {
        "ok": False,
        "error": why,
        "error_code": "keil-multiple-instances",
        "single": True,
        "requested_project": project or None,
        "open_instances": [{"pid": i.get("pid"), "project": i.get("project")}
                           for i in inst],
        "next_actions": [
            '先 close_uvision(keep="oldest") 收掉窗口再打开目标工程'
            '（持 UVSOCK 4823 的是**最早**那个实例，别按「留最新」关）',
            "确实要同时开多个工程窗口：传 single=false",
        ],
    }

def launch_uvision(uv4: str, project: str, reuse: bool = True,
                   uvsock_port: int | None = None,
                   no_layout: bool = False, single: bool = True) -> dict:
    """可见方式启动 Keil uVision 并打开指定工程（供调试查看界面）。

    两个官方命令行开关（吸收自 dsh-keil-mcp / McuBuddy 的痛点）：
    - ``uvsock_port=<端口>`` → 追加 ``-s <端口>``：让**这次拉起的实例**在指定端口上开
      UVSOCK。默认（不开 -s）用的是 Options 里保存的 UVSOCK 设置；当用户的 Keil 里
      UVSOCK 没打开/端口被改过时，光"拉起 Keil"仍然连不上，-s 能一步到位。
    - ``no_layout=True`` → 追加 ``-sg``：禁用 uvguix 布局文件。用户改过窗口布局后，
      布局文件损坏或与工程不匹配时 UV4 可能起得极慢甚至报错布局，-sg 可绕开。

    以**脱离调用方 job** 的方式启动（CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS |
    CREATE_NEW_PROCESS_GROUP），并把标准流接到 DEVNULL。否则由 MCP 服务拉起的 UV4 会
    随调用链所在的 job 一起被回收（现象："刚拉起就没了"），标准流也会继承被污染的环境。

    真机实测修正：UV4.exe **不是**单实例程序——同一工程可以被反复打开成多个窗口且互不
    回收（曾累积 6 个同工程实例）。因此这里先枚举已有实例：
    - reuse=True（默认）：已有同工程窗口则**复用**（前置该窗口）并如实返回 reused=true，
      不再新开窗口；
    - reuse=False：无条件新开一个窗口（仅在确实需要第二个窗口时使用）。

    single（默认 True）——把「只保留一个 Keil 窗口」这条工程纪律**做成机制**：
    - 已有**其它工程**的窗口 → 直接拒绝（error_code=keil-multiple-instances），返回既有
      实例清单与下一步动作；不做「先关再开」的隐式动作（关窗口是不可逆操作，必须由调用方
      显式决定）；
    - 已有**同工程**窗口 → 复用（reuse=False 时也复用，返回 reuse_forced=true 并说明），
      因为此刻再开就是多窗口；
    - 本次没给 project 且已有实例 → 无从比对，同样拒绝（宁可报错也不猜）；
    - 确实要同时开多个窗口：传 single=False，显式承担窗口堆积的后果。
    """
    inst = winutil.uv4_instances()
    same = [i for i in inst if project and _same_project(i.get("project"), project)]
    others = [i for i in inst
              if not (project and _same_project(i.get("project"), project))]
    if single and others:
        return _keil_multi_refusal(inst, others, project)
    if same and (reuse or single):
        cur = same[-1]                          # 列表按创建时间升序 → 末位为最新
        focused = winutil.focus_window(cur.get("hwnd"))
        out = {
            "ok": True, "reused": True, "pid": cur.get("pid"),
            "instances": len(same), "focused": focused,
            "msg": "已有同工程 Keil 实例，复用该窗口（未新开；当前同工程窗口 %d 个）"
                   % len(same),
            "hint": ('如需收敛到单窗口：close_uvision(keep="latest")；'
                     "如需看全部实例：list_uvision_instances。"),
        }
        if not reuse:
            out["reuse_forced"] = True
            out["hint"] = ("single=true 下不新开窗口，已强制复用同工程窗口"
                           "（reuse=false 被否决）；确实要第二个窗口请传 single=false。")
        return out
    extra = []
    if uvsock_port:
        extra += ["-s", str(int(uvsock_port))]
    if no_layout:
        extra.append("-sg")
    r = winutil.launch_detached(uv4, project, extra_args=extra)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error", "启动 Keil 失败")}
    out = {
        "ok": True, "reused": False,
        "pid": r.get("pid"),
        "creationflags": r.get("creationflags"),
        "breakaway": r.get("breakaway"),
        "extra_args": extra,
        "msg": "已脱离父进程启动 Keil uVision 并打开工程",
        "hint": "UVSOCK 需数秒才监听；可用 keil_health 确认 port_listening，"
                "或用 restart_keil 一步完成关闭→重启→等待→重连。",
        "order_hint": "Keil 已打开该工程：**此刻起不要再改源码/工程文件**——"
                      "Keil 会弹「文件已被外部修改」模态框并堵住调试通道。"
                      "要改就先 close_uvision 收窗口，改完再回来 launch。",
    }
    if uvsock_port:
        out["uvsock_port"] = int(uvsock_port)
        out["hint"] = ("已用 -s %d 让本实例在指定端口开 UVSOCK；"
                       "请把 MCP 服务的 UVSOCK 端口也设成一致（--port / 服务参数）。"
                       % int(uvsock_port))
    if no_layout:
        out["no_layout"] = True
    return out


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
