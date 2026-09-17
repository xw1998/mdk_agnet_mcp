# -*- coding: utf-8 -*-
"""跨进程互斥与实例清点（批次29）——让「命令并发」不再静默地吃掉写入。

为什么需要
----------
UVSOCK 背后是**一台调试器、一份目标状态**。两个 mdkdebug 进程（或多开的调试会话）同时
驱动同一个 4823 端口时，命令会互相穿插：本进程的 write_mem 落地后，另一条命令紧接着
写到同一处/把会话搅乱，表现就是「写入被静默吞掉」——最坏的是工具还返回成功，调用方
据此得出「看门狗又复位了」这类错误结论，排查代价极高。

客户端原有的 ``threading.RLock`` 只能管住**本进程内**的线程，管不住跨进程。这里补两层：

1. **跨进程互斥**：对 ``<temp>/mdkdebug_guard/uvsock_<port>.lock`` 加文件锁
   （Windows 用 ``msvcrt.locking``，POSIX 用 ``fcntl.flock``）。谁在发命令谁持锁，
   持锁期间另一个进程只能等（带超时与遥测）。拿不到锁时**不假装成功**：记下超时次数
   与对方 PID，并把这一次当作「降级执行」如实上报。
2. **实例清点**：每个进程在 ``<temp>/mdkdebug_guard/inst_<pid>.json`` 留心跳，
   keil_health / get_status 据此报出「还有别的 mdkdebug 进程在用同一调试通道」，
   把静默竞争变成显式警告。

设计约束
--------
- **永不抛异常**：这是链路级保护，自身崩掉就失去意义；所有异常都降级为统计/日志。
- **不影响正常路径**：无竞争时只多一次 open + 一次文件锁系统调用（微秒级）。
- 目录可用环境变量 ``MDKDEBUG_GUARD_DIR`` 覆盖（测试与沙箱用）。
"""
from __future__ import annotations

import atexit
import ctypes
import json
import logging
import os
import sys
import tempfile
import threading
import time

logger = logging.getLogger("mdkdebug.guard")

DEFAULT_UVSOCK_PORT = 4823
# 竞争判定阈值：等待超过这么久才计入 waits（无竞争时的锁开销不该算成"等过"）
CONTENTION_MS = 20.0
LOCK_WAIT_DEFAULT = 15.0
PRESENCE_STALE_S = 90.0
PRESENCE_THROTTLE_S = 5.0

def guard_dir() -> str:
    """互斥/心跳文件所在目录（可用 MDKDEBUG_GUARD_DIR 覆盖）。"""
    d = os.environ.get("MDKDEBUG_GUARD_DIR") or os.path.join(
        tempfile.gettempdir(), "mdkdebug_guard")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d

def pid_alive(pid) -> bool:
    """判断 PID 是否仍存活（跨平台，失败时按"不存活"处理）。"""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            kernel32 = ctypes.windll.kernel32
            h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return False
            try:
                code = ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return int(code.value) == STILL_ACTIVE
                return True
            finally:
                kernel32.CloseHandle(h)
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

class EndpointGuard:
    """同一个 UVSOCK 端点的跨进程互斥闸门。

    用法：``with guard.hold(): ...发命令...``。闸门**可重入**（同进程同线程嵌套调用不会
    自锁，batch 里逐条调用子工具就是这种情形），且**从不阻塞到失败**：超时即降级放行，
    并把这次竞争如实记进统计（不要为了"绝不阻塞"而让工具卡死，也不要假装没发生）。
    """

    _proc_locks: dict = {}
    _proc_locks_guard = threading.Lock()

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_UVSOCK_PORT,
                 directory: str | None = None):
        self.host = str(host or "127.0.0.1")
        self.port = int(port or DEFAULT_UVSOCK_PORT)
        self.directory = directory or guard_dir()
        self.lock_path = os.path.join(self.directory, "uvsock_%d.lock" % self.port)
        # 持有者信息另存 sidecar：Windows 上被 LockFile 锁住的文件，其他进程
        # 连 open(...,"rb") 都会被拒（EACCES），从锁文件里读不出「谁在占着」。
        self.holder_path = self.lock_path + ".holder"
        self._proc_lock = self._proc_lock_for(self.lock_path)
        self._depth = 0
        self._fd = None
        self.stats = {
            "acquired": 0,          # 成功持锁次数（跨进程锁真正拿到）
            "waits": 0,             # 等待超过 CONTENTION_MS 的次数（本进程内 + 跨进程）
            "total_wait_ms": 0.0,
            "max_wait_ms": 0.0,
            "last_wait_ms": 0.0,
            "lock_timeouts": 0,     # 等超时后降级放行的次数（说明确实有别的进程在抢）
            "foreign_pid": None,    # 最近一次争用对手的 PID
            "degraded": False,      # 最近一次是否在未拿到跨进程锁的情况下执行
        }

    # ---- 进程内闸门（按锁文件路径共享，避免同进程多实例互锁） ----
    @classmethod
    def _proc_lock_for(cls, path: str) -> threading.RLock:
        with cls._proc_locks_guard:
            lk = cls._proc_locks.get(path)
            if lk is None:
                lk = threading.RLock()
                cls._proc_locks[path] = lk
            return lk

    # ---- 跨进程锁 ----
    def _try_lock_fd(self, fd: int) -> None:
        """非阻塞独占锁（失败抛 OSError）。"""
        os.lseek(fd, 0, os.SEEK_SET)
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_fd(self, fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)

    def _write_holder(self, fd: int) -> None:
        """记录「谁在占着这个端点」：锁文件内写一份 + 侧车文件写一份。

        侧车（<lock>.holder）不参与加锁，等待方才能读到对手 PID；
        锁文件内那份保留给"能读到就更好"的场景。
        """
        try:
            info = json.dumps({"pid": os.getpid(), "port": self.port,
                               "ts": time.time()}).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, info.ljust(128, b" ")[:128])
        except OSError:
            pass
        try:
            with open(self.holder_path, "w", encoding="utf-8") as f:
                json.dump({"pid": os.getpid(), "port": self.port,
                           "ts": time.time()}, f)
        except OSError:
            pass

    def holder(self) -> dict | None:
        """读出记录的持有者（无人持锁时可能读到上次的残留）。"""
        for path, binary in ((self.holder_path, False), (self.lock_path, True)):
            try:
                if binary:
                    with open(path, "rb") as f:
                        data = json.loads(f.read(256).decode("utf-8", "ignore").strip() or "{}")
                else:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                if isinstance(data, dict) and data.get("pid"):
                    return data
            except Exception:  # noqa: BLE001  锁文件常因被锁而读不到，属预期
                continue
        return None

    def _acquire_file_lock(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        first = True
        while True:
            fd = None
            try:
                fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o666)
                self._try_lock_fd(fd)
                self._fd = fd
                self._write_holder(fd)
                self.stats["acquired"] += 1
                self.stats["degraded"] = False
                return True
            except OSError:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if first:
                    first = False
                    h = self.holder()
                    if h and int(h.get("pid") or 0) != os.getpid():
                        self.stats["foreign_pid"] = h.get("pid")
                if time.monotonic() >= deadline:
                    self.stats["lock_timeouts"] += 1
                    self.stats["degraded"] = True
                    logger.warning(
                        "未能在 %.1fs 内取得 UVSOCK 跨进程锁（%s，对手 PID=%s）——"
                        "本进程仍有另一个 mdkdebug 实例在用同一调试通道，"
                        "命令可能相互穿插。可用 keil_health 查看实例清点。",
                        timeout, self.lock_path, self.stats.get("foreign_pid"))
                    return False
                time.sleep(0.02)
            except Exception as e:  # noqa: BLE001
                logger.debug("加锁异常（按降级处理）：%s", e)
                self.stats["degraded"] = True
                return False

    def _release_file_lock(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            self._unlock_fd(fd)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        try:                       # 只清掉自己的记录，别抹掉后来者的
            h = self.holder()
            if h and int(h.get("pid") or 0) == os.getpid():
                os.remove(self.holder_path)
        except OSError:
            pass

    # ---- 对外：持锁上下文 ----
    def hold(self, timeout: float = LOCK_WAIT_DEFAULT):
        return _Hold(self, float(timeout))

    def snapshot(self) -> dict:
        s = dict(self.stats)
        s["lock_path"] = self.lock_path
        s["held"] = bool(self._depth > 0 and self._fd is not None)
        s["total_wait_ms"] = round(float(s["total_wait_ms"]), 2)
        s["max_wait_ms"] = round(float(s["max_wait_ms"]), 2)
        s["last_wait_ms"] = round(float(s["last_wait_ms"]), 2)
        return s

    def reset_stats(self) -> None:
        for k in ("acquired", "waits", "total_wait_ms", "max_wait_ms",
                  "last_wait_ms", "lock_timeouts", "foreign_pid", "degraded"):
            self.stats[k] = 0.0 if k.endswith("_ms") else (
                None if k == "foreign_pid" else (False if k == "degraded" else 0))

class _Hold:
    """``with guard.hold():`` 的上下文对象（可重入、不抛异常）。"""

    def __init__(self, guard: EndpointGuard, timeout: float):
        self._g = guard
        self._timeout = timeout

    def __enter__(self):
        g = self._g
        try:
            t0 = time.monotonic()
            g._proc_lock.acquire()
            waited_ms = (time.monotonic() - t0) * 1000.0
            try:
                if g._depth == 0:
                    t1 = time.monotonic()
                    g._acquire_file_lock(self._timeout)
                    waited_ms += (time.monotonic() - t1) * 1000.0
                g._depth += 1
            finally:
                if waited_ms >= CONTENTION_MS:
                    st = g.stats
                    st["waits"] += 1
                    st["total_wait_ms"] += waited_ms
                    st["max_wait_ms"] = max(float(st["max_wait_ms"]), waited_ms)
                    st["last_wait_ms"] = waited_ms
                    logger.info("UVSOCK 闸门等待 %.1fms（可能有并发调用/其他实例）", waited_ms)
        except Exception as e:  # noqa: BLE001  闸门故障不得阻断调试
            logger.debug("闸门加锁失败，按无闸门执行：%s", e)
            g._depth = max(1, g._depth)     # 保证退出时配对
        return self

    def __exit__(self, exc_type, exc, tb):
        g = self._g
        try:
            g._depth = max(0, g._depth - 1)
            if g._depth == 0:
                g._release_file_lock()
        except Exception as e:  # noqa: BLE001
            logger.debug("闸门解锁失败（忽略）：%s", e)
        try:
            g._proc_lock.release()
        except RuntimeError:
            pass
        return False

# ----------------------------------------------------------------------
# 实例清点（心跳）
# ----------------------------------------------------------------------
_presence_state = {"path": None, "last": 0.0}

def _presence_path(pid: int) -> str:
    return os.path.join(guard_dir(), "inst_%d.json" % int(pid))

def touch_presence(port: int = DEFAULT_UVSOCK_PORT, extra: dict | None = None,
                   throttle: float = PRESENCE_THROTTLE_S) -> dict | None:
    """刷新本进程的心跳文件（带节流）。返回本次写入的内容（被节流时返回 None）。"""
    now = time.monotonic()
    if _presence_state["path"] and now - _presence_state["last"] < throttle:
        return None
    pid = os.getpid()
    info = {"pid": pid, "port": int(port), "ts": time.time()}
    if extra:
        for k, v in extra.items():
            if v not in (None, "", []):
                info[k] = v
    try:
        path = _presence_path(pid)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False)
        _presence_state["path"] = path
        _presence_state["last"] = now
        return info
    except OSError as e:
        logger.debug("写实例心跳失败：%s", e)
        return None

def clear_presence(pid: int | None = None) -> None:
    """删除本进程（或指定进程）的心跳文件。"""
    p = int(pid or os.getpid())
    try:
        os.remove(_presence_path(p))
    except OSError:
        pass

def live_instances(port: int | None = None, stale_after: float = PRESENCE_STALE_S,
                   include_self: bool = False) -> list:
    """列出仍在使用同一 UVSOCK 的 mdkdebug 进程（心跳新鲜且 PID 存活）。

    这是「写入被静默吞掉」最可能的成因的**直接证据**：多个服务进程各持一条 UVSOCK
    连接在抢同一台调试器。
    """
    out = []
    try:
        files = os.listdir(guard_dir())
    except OSError:
        return out
    now = time.time()
    me = os.getpid()
    for fn in files:
        if not (fn.startswith("inst_") and fn.endswith(".json")):
            continue
        path = os.path.join(guard_dir(), fn)
        try:
            with open(path, "r", encoding="utf-8") as f:
                info = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(info, dict):
            continue
        pid = int(info.get("pid") or 0)
        if pid <= 0:
            continue
        if pid == me and not include_self:
            continue
        if port is not None and int(info.get("port") or 0) not in (0, int(port)):
            continue
        ts = float(info.get("ts") or 0)
        fresh = (now - ts) <= stale_after
        if fresh and pid_alive(pid):
            out.append(info)
        elif not fresh and not pid_alive(pid):
            try:                       # 清理死亡残留，避免误报
                os.remove(path)
            except OSError:
                pass
    return out

def concurrency_report(port: int = DEFAULT_UVSOCK_PORT,
                       guard: EndpointGuard | None = None) -> dict:
    """给 get_status / keil_health 用的聚合视图：串行化方式 + 竞争遥测 + 其他实例。"""
    others = live_instances(port=port)
    out = {
        "mode": "serialized",
        "in_process": "thread RLock（单进程内所有 UVSOCK 命令串行）",
        "cross_process": "lock file（同一时刻只允许一个 mdkdebug 进程发命令）",
        "other_instances": [{"pid": o.get("pid"), "port": o.get("port"),
                             "age_s": round(max(0.0, time.time() - float(o.get("ts") or 0)), 1),
                             "project": o.get("project")}
                            for o in others],
        "other_instance_count": len(others),
        "warning": "",
    }
    if guard is not None:
        out["stats"] = guard.snapshot()
    if others:
        pids = "、".join(str(o.get("pid")) for o in others)
        out["warning"] = (
            "检测到还有 %d 个 mdkdebug 进程（PID %s）在驱动同一 UVSOCK：并发调用会互相"
            "穿插，写入可能被静默覆盖。请只保留一个 MCP 服务实例（关掉多余的客户端连接/"
            "旧进程）后重试。" % (len(others), pids))
    return out

def _atexit_clear() -> None:
    clear_presence()

atexit.register(_atexit_clear)
