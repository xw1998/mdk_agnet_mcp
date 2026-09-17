# -*- coding: utf-8 -*-
"""OpenOCD 客户端层：进程托管 + telnet(4444) 命令通道 + ocd_* 工具族。

为什么要这一层：MDK 侧有 UVSOCK 这条现成通道，而非 MDK 目标（RISC-V、ESP32、
以及不想开 Keil 的 Cortex-M）只能靠 OpenOCD。OpenOCD 本身是个**服务器**——
它独占调试探针，对外开三条口：
    4444 telnet（人/脚本发命令，本模块走这条）
    3333 gdb   （给 GDB 用，本模块的 ocd_gdb 会批处理调它）
    6666 tcl   （给脚本用，TCL 语义，本模块不碰）
关键约束：**同一根探针同一时刻只能被一个 OpenOCD 进程占用**，所以进程做成
全局单例，重复 ocd_start 会先停旧的（除非显式要求复用）。

协议要点（真机踩坑后固化）：
  - telnet 通道是**行命令 + 提示符 `> `**：发一行、读到提示符为止，
    中间会回显自己发的命令（解析时要先剔掉回显行）；
  - 出错不改退出码，而是在输出里打 `Error: ...`，还常带 Jim-Tcl 的调用栈
    （`in procedure ... called at file ...`），这些栈行不是新错误，要折叠；
  - `mdw/mdh/mdb` 输出格式是 `0xADDR: w0 w1 w2 w3`，一行 4 个，**地址列必须校验**，
    否则读失败时会把上一行的数当成数据；
  - 写内存没有批量命令，用 `;` 串多条 `mww`，再读回校验。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time

from . import targets as _targets

__all__ = ["OCDTelnet", "OCDSession", "get_session", "register"]

_CACHE = {"sess": None}
_OPENOCD_ENV_ARGS = ("MDKDEBUG_OPENOCD_ARGS",)

# 端口默认值（与 OpenOCD 默认一致；改了要一起改 ocd_start 的默认参数）
DEF_TELNET = 4444
DEF_GDB = 3333
DEF_TCL = 6666

_ERR_RE = re.compile(r"(?:^|[\s\[\(\"'])(?:Error|error)\s*:", re.M)
_STACK_RE = re.compile(r"^\s*(?:in procedure|at file|called at file|while executing)")

# OpenOCD / Jim-Tcl 有些失败**不带 `Error:` 前缀**，而是直接打一行大白话。
# 只用 `^Error:` 判定会把这些回包判成 ok=true——`ocd_flash` 曾经因此把
# 「文件根本没打开」报成「烧录成功」（真机取证：`couldn't open <path>` +
# `embedded:startup.tcl:1813: Error: ** Programming Failed **`，而工具返回 ok=true）。
_FAIL_RE = re.compile(
    r"(?:couldn't open|cannot open|can't open|unable to open|"
    r"no flash bank|not enough space|"
    r"\*\*[^*]*Failed[^*]*\*\*)",
    re.I)


# ================================================================ telnet 客户端

class OCDTelnet:
    """OpenOCD telnet 客户端：一条命令一次往返，读到提示符为止。"""

    def __init__(self, host: str = "127.0.0.1", port: int = DEF_TELNET,
                 timeout: float = 10.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.sock = None
        self.banner = ""
        self.last_error = None

    # ---------------------------------------------------------- 连接
    def connect(self, timeout: float | None = None) -> dict:
        t = float(timeout if timeout is not None else self.timeout)
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=t)
            self.sock.settimeout(0.3)
            self.banner = self._read_until_prompt(t)
            return {"ok": True, "banner": self.banner}
        except OSError as e:
            self.close()
            self.last_error = str(e)
            return {"ok": False, "error": "连接 OpenOCD telnet %s:%d 失败：%s"
                    % (self.host, self.port, e)}

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def alive(self) -> bool:
        if not self.sock:
            return False
        try:
            self.sock.getpeername()
            return True
        except OSError:
            return False

    # ---------------------------------------------------------- 收发
    def _read_until_prompt(self, timeout: float) -> str:
        """读到提示符 `> `（或超时/对端关闭）为止。

        返回前先过 `_clean_telnet`：telnet 通道里混着 IAC 协商与 NUL 前缀，
        不清掉会让行首锚定的解析正则全部失效（详见 `_clean_telnet` 的取证）。
        """
        if not self.sock:
            return ""
        buf = b""
        deadline = time.time() + max(0.2, float(timeout))
        idle_deadline = time.time() + 0.6
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                if buf and time.time() > idle_deadline:
                    break
                if not buf and time.time() > deadline:
                    break
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if _has_prompt(buf):
                break
            idle_deadline = time.time() + 0.6
        return _strip_prompt(_clean_telnet(buf).decode("utf-8", "replace"))

    def cmd(self, command: str, timeout: float | None = None) -> dict:
        """发一条命令，返回 {ok, command, output, lines, error, raw}。"""
        command = (command or "").strip()
        if not command:
            return {"ok": False, "command": command, "error": "命令为空"}
        if not self.alive():
            r = self.connect(timeout)
            if not r.get("ok"):
                return {"ok": False, "command": command, "error": r.get("error")}
        t = float(timeout if timeout is not None else self.timeout)
        try:
            self.sock.sendall((command + "\n").encode("utf-8"))
        except OSError as e:
            self.close()
            return {"ok": False, "command": command,
                    "error": "发送失败（连接已断？）：%s" % e}
        raw = self._read_until_prompt(t)
        return _shape(command, raw)

    def cmd_many(self, commands, timeout: float | None = None) -> dict:
        """多条命令逐条发，聚合结果（任一条报错则整体 ok=false）。"""
        if isinstance(commands, str):
            commands = _split_commands(commands)
        results, ok = [], True
        for c in commands:
            r = self.cmd(c, timeout=timeout)
            results.append(r)
            if not r.get("ok"):
                ok = False
        return {"ok": ok, "count": len(results), "results": results,
                "output": "\n".join(r.get("output") or "" for r in results)}


def _clean_telnet(buf: bytes) -> bytes:
    """清掉 telnet 协议噪声：IAC 协商序列 + OpenOCD 的 NUL 前缀。

    真机取证（xPack OpenOCD 0.12.0 + CMSIS-DAPv2，用 `_rt_dump.py` 抓原始字节）：

        banner    b'\\xff\\xfb\\x03\\xff\\xfb\\x01\\xff\\xfd\\x03\\xff\\xfe\\x01'
                  b'Open On-Chip Debugger\\r\\n\\r> '
        命令回包  b'reg\\r\\n\\x00===== arm v7m registers\\r\\n(0) r0 (/32): 0x000001b8\\r\\n...'
        读内存    b'mdw 0x08000000 2\\r\\n\\x000x08000000: 20000728 080002e1 \\r\\n\\r> '

    两类噪声都插在**行首**：
      - `\\xff` + `\\xfb~\\xfe` + option：telnet WILL/WONT/DO/DONT 协商（RFC 854）；
      - `\\x00`：OpenOCD telnet 给每条命令的输出加的固定 NUL 前缀。

    不清掉它们，`^\\s*` 这类行首锚定的解析正则一律匹配不上——症状是
    「raw 里明明有数据，解析出来 0 条」，属于**静默错答案**，比报错更危险。
    """
    out = bytearray()
    i, n = 0, len(buf)
    while i < n:
        b = buf[i]
        if b == 0xFF and i + 1 < n:
            i += 3 if 0xFB <= buf[i + 1] <= 0xFE else 2
            continue
        if b == 0x00:
            i += 1
            continue
        out.append(b)
        i += 1
    return bytes(out)

def _has_prompt(buf: bytes) -> bool:
    """尾部是否已出现 OpenOCD 提示符。

    真实 OpenOCD 的提示符是 `> `（**带一个空格**），所以必须先 rstrip 掉尾随空白
    再判 `>`，否则永远匹配不上，每条命令都要白等 0.6s 空闲超时才返回。
    `>` 之前必须是行首或换行（避免把 `0x1>` 这种数据行当提示符）。
    """
    if not buf:
        return False
    stripped = buf.rstrip(b" \r\n\t")
    if not stripped.endswith(b">"):
        return False
    before = stripped[:-1]
    return (not before) or before.endswith(b"\n") or before.endswith(b"\r")


def _strip_prompt(text: str) -> str:
    # 兜底再剔一次 NUL：`_clean_telnet` 在字节层已经清过，但这条函数也会被
    # 单元测试/调用方直接喂原始文本，保持自身健壮。
    text = text.replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    # 去掉结尾空行与提示符行
    while lines and lines[-1].strip() in ("", ">"):
        lines.pop()
    if lines and lines[-1].endswith(">"):
        lines[-1] = lines[-1][:-1].rstrip()
        if not lines[-1].strip():
            lines.pop()
    return "\n".join(lines)


def _shape(command: str, raw: str) -> dict:
    """把原始回包整理成结构化结果：剔回显、折叠 Tcl 栈、提取错误。"""
    lines = raw.split("\n")
    # 1) 剔掉回显行（OpenOCD telnet 会把命令行原样回显）
    out = []
    for i, ln in enumerate(lines):
        if i == 0 and ln.strip() == command.strip():
            continue
        out.append(ln)
    # 2) 折叠 Jim-Tcl 调用栈（它跟随在 Error 行后面，对新错误没信息量）
    kept, in_stack = [], False
    for ln in out:
        if _STACK_RE.match(ln):
            in_stack = True
            continue
        if ln.strip() == "":
            in_stack = False
            kept.append(ln)
            continue
        in_stack = False
        kept.append(ln)
    text = "\n".join(kept).strip("\n")
    errs = [ln.strip() for ln in kept
            if _ERR_RE.search(ln) or _FAIL_RE.search(ln)]
    # `Warn :` 不算失败（OpenOCD 大量正常路径会告警，例如 flash 保护位）
    warns = [ln.strip() for ln in kept if ln.strip().startswith(("Warn :", "warn :"))]
    res = {"ok": not errs, "command": command, "output": text,
           "lines": [ln for ln in kept if ln.strip()],
           "error": errs[0] if errs else None}
    if len(errs) > 1:
        res["errors"] = errs
    if warns:
        res["warnings"] = warns
    return res


def _split_commands(text: str) -> list:
    if not text:
        return []
    parts = []
    for ln in str(text).replace(";", "\n").split("\n"):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts.append(ln)
    return parts


# ================================================================ 进程会话

class OCDSession:
    """一个 OpenOCD 进程 + 一条 telnet 长连接。全局单例（探针独占）。"""

    def __init__(self):
        self.proc = None
        self.exe = ""
        self.args = []
        self.cwd = ""
        self.ports = {"telnet": DEF_TELNET, "gdb": DEF_GDB, "tcl": DEF_TCL}
        self.log_path = ""
        self.started_at = 0.0
        self.profile = ""
        self.tel = None
        self._log_fp = None

    # ---------------------------------------------------------- 生命周期
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, args, exe: str = "", cwd: str = "", log_path: str = "",
              wait: float = 20.0, port: int = DEF_TELNET, env=None) -> dict:
        from . import toolchain as _tc
        if not exe:
            exe = _tc.find_tool("openocd", "openocd") or ""
        if not exe:
            return {"ok": False, "error": "本机没找到 openocd",
                    "hint": "下载 xPack OpenOCD 解压到 D:/Tools/mdk_agent_toolchains/，"
                            "再用 toolchain_env(families=\"openocd\") 注入 PATH"}
        if not os.path.isfile(exe):
            return {"ok": False, "error": "openocd 路径不存在：%s" % exe}
        if self.running():
            return {"ok": False, "error": "已有 OpenOCD 在运行（同一探针只能一个实例）",
                    "pid": self.proc.pid, "hint": "先 ocd_stop，或 ocd_start(restart=true)"}

        if not log_path:
            d = os.path.join(tempfile.gettempdir(), "mdkdebug_ocd")
            os.makedirs(d, exist_ok=True)
            log_path = os.path.join(d, "openocd_%d.log" % int(time.time()))
        try:
            self._log_fp = open(log_path, "wb")
        except OSError as e:
            return {"ok": False, "error": "打不开日志文件：%s" % e}
        argv = [exe] + [str(a) for a in (args or [])]
        try:
            self.proc = subprocess.Popen(
                argv, stdout=self._log_fp, stderr=subprocess.STDOUT,
                cwd=cwd or None, env=env or os.environ.copy(), stdin=subprocess.DEVNULL)
        except Exception as e:  # noqa: BLE001
            self._log_fp.close()
            self._log_fp = None
            return {"ok": False, "error": "启动 openocd 失败：%s" % e}
        self.exe, self.args, self.cwd = exe, argv[1:], cwd or ""
        self.log_path, self.started_at = log_path, time.time()
        self.ports["telnet"] = int(port)

        ready = self.wait_ready(wait, port)
        ready.update({"pid": self.proc.pid, "exe": exe, "args": argv[1:],
                      "log": log_path})
        return ready

    def wait_ready(self, timeout: float = 20.0, port: int = DEF_TELNET) -> dict:
        """等 telnet 端口可连（OpenOCD 起来后要读 cfg、复位、探测，需要几秒）。"""
        deadline = time.time() + max(1.0, float(timeout))
        last = None
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return {"ok": False, "error": "openocd 进程已退出（退出码 %s），看日志"
                        % self.proc.returncode,
                        "log_tail": self.tail(20), "log": self.log_path}
            try:
                s = socket.create_connection(("127.0.0.1", int(port)), timeout=0.5)
                s.close()
                return {"ok": True, "port": int(port),
                        "ready_s": round(time.time() - (self.started_at or time.time()), 2),
                        "note": "telnet 已就绪；真正连上目标还要看日志里有没有 "
                                "'Examined' / 错误"}
            except OSError as e:
                last = e
            time.sleep(0.2)
        return {"ok": False, "error": "等待 telnet 端口超时（%.0fs）：%s"
                % (float(timeout), last), "log_tail": self.tail(20),
                "log": self.log_path}

    def stop(self, graceful: bool = True, wait: float = 6.0) -> dict:
        out = {"ok": True, "was_running": self.running()}
        if not self.running():
            self._cleanup_handles()
            out["note"] = "没有在运行的 OpenOCD"
            return out
        pid = self.proc.pid
        if graceful:
            try:
                t = OCDTelnet(port=self.ports["telnet"])
                if t.connect(timeout=2).get("ok"):
                    t.cmd("shutdown", timeout=3)
                    t.close()
            except Exception:  # noqa: BLE001
                pass
            deadline = time.time() + max(1.0, float(wait))
            while time.time() < deadline and self.proc.poll() is None:
                time.sleep(0.2)
        if self.proc.poll() is None:
            out["graceful"] = False
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            deadline = time.time() + 3.0
            while time.time() < deadline and self.proc.poll() is None:
                time.sleep(0.2)
        if self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        out["exit_code"] = self.proc.poll()
        out["pid"] = pid
        out["stopped"] = self.proc.poll() is not None
        self._cleanup_handles()
        return out

    def _cleanup_handles(self) -> None:
        if self.tel:
            self.tel.close()
            self.tel = None
        if self._log_fp:
            try:
                self._log_fp.close()
            except OSError:
                pass
            self._log_fp = None
        self.proc = None

    # ---------------------------------------------------------- 日志
    def tail(self, lines: int = 40, keyword: str = "") -> str:
        if not self.log_path or not os.path.isfile(self.log_path):
            return ""
        try:
            with open(self.log_path, "rb") as f:
                data = f.read()
        except OSError:
            return ""
        text = data.decode("utf-8", "replace")
        rows = text.splitlines()
        if keyword:
            rows = [r for r in rows if keyword.lower() in r.lower()]
        return "\n".join(rows[-max(1, int(lines)):])

    # ---------------------------------------------------------- 命令
    def telnet(self, timeout: float = 10.0) -> OCDTelnet:
        if self.tel is None or not self.tel.alive():
            self.tel = OCDTelnet(port=self.ports["telnet"], timeout=timeout)
            self.tel.connect(timeout=timeout)
        else:
            self.tel.timeout = float(timeout)
        return self.tel

    def cmd(self, command: str, timeout: float = 10.0) -> dict:
        if not self.running():
            return {"ok": False, "command": command,
                    "error": "OpenOCD 没在运行",
                    "hint": "先 ocd_start(profile=\"stm32f401\") 之类把会话起起来"}
        return self.telnet(timeout).cmd(command, timeout=timeout)

    def cmd_many(self, commands, timeout: float = 10.0) -> dict:
        if not self.running():
            return {"ok": False, "error": "OpenOCD 没在运行",
                    "hint": "先 ocd_start"}
        return self.telnet(timeout).cmd_many(commands, timeout=timeout)

    def info(self) -> dict:
        if self.proc is None:
            return {"ok": True, "running": False}
        return {"ok": True, "running": self.running(), "pid": self.proc.pid,
                "exit_code": self.proc.poll(), "exe": self.exe,
                "args": self.args, "ports": dict(self.ports),
                "uptime_s": round(time.time() - self.started_at, 1)
                if self.started_at else 0,
                "profile": self.profile, "log": self.log_path}


def session_info() -> dict:
    """当前 OpenOCD 会话的紧凑状态（给 capabilities 这类冷启动工具用）。"""
    return get_session().info()

def get_session() -> OCDSession:
    if _CACHE["sess"] is None:
        _CACHE["sess"] = OCDSession()
    return _CACHE["sess"]


# ================================================================ 解析辅助

# 行首额外容忍 NUL（`_clean_telnet` 之外的二层防御）：清洗若漏了一处，
# 也只丢一行，不会让整个解析静默变空。
_LEAD = r"^[\x00\s]*"
_MEM_LINE = re.compile(_LEAD + r"(0x[0-9a-fA-F]+)\s*:\s*(.*)$")

# 真实 `flash banks` 输出：
#   #0 : stm32f4x.flash (stm32f2x) at 0x08000000, size 0x00100000, buswidth 0, ...
# 注意 driver 的括号后面**直接就是 at**，中间没有别的字段；size 是可选的。
_FLASH_BANK_RE = re.compile(
    _LEAD + r"#(\d+)\s*:\s*(\S+)\s*\(([^)]*)\)\s+at\s+(0x[0-9a-fA-F]+)"
    r"(?:\s*,\s*size\s+(0x[0-9a-fA-F]+))?")


def _parse_mem(text: str, addr: int, count: int, width: int) -> dict:
    """解析 mdw/mdh/mdb 输出。地址列必须核对，避免把上一行数据当成本次结果。"""
    hexlen = width // 4
    words, bad = [], []
    for ln in (text or "").split("\n"):
        m = _MEM_LINE.match(ln)
        if not m:
            continue
        try:
            line_addr = int(m.group(1), 16)
        except ValueError:
            continue
        toks = re.findall(r"\b[0-9a-fA-F]{%d}\b" % hexlen, m.group(2))
        if not toks:
            continue
        if abs(line_addr - (addr + width // 8 * len(words))) > width // 8 * 4:
            bad.append(line_addr)
        for t in toks:
            words.append(int(t, 16))
    words = words[:count]
    got = len(words)
    return {"words": words, "got": got, "expected": count,
            "complete": got >= count, "misaligned_lines": bad[:4]}


def _mem_to_bytes(words, width: int, n_bytes: int) -> bytes:
    n = width // 8
    buf = bytearray()
    for w in words:
        buf += int(w).to_bytes(n, "little", signed=False)
    return bytes(buf[:n_bytes])


def _norm_code_addr(a: int):
    """代码地址的 Thumb 位归一。

    Cortex-M 的函数**指针**低位置 1 是 Thumb 标记，不是地址的一部分。
    Keil/UVSOCK 那条路上我们已经被 `error 57 illegal address` 教过一次；
    OpenOCD 的 `bp` 拿到奇数地址同样会报 "not aligned" 或下到错的地方。
    只在「看着像代码区」（Flash 或 0 地址起的别名区）时清零，
    RISC-V / Xtensa 没有 Thumb 约定，奇数地址原样保留。
    """
    if (a & 1) and (a >= 0x08000000 or a < 0x00100000):
        return a & ~1, True
    return a, False

_REG_LINE = re.compile(
    _LEAD + r"(?:\(\d+\)\s*)?([A-Za-z_][\w./]*)\s*(?:\([^)]*\))?\s*[:=]\s*"
    r"(0x[0-9a-fA-F]+|[0-9]+)\b")

def _parse_regs(text: str) -> dict:
    """解析 `reg` / `reg <name>` 的输出。

    真实 OpenOCD 打的是 `(0) r0 (/32): 0x00000000 (dirty)`：**有序号前缀**、
    宽度写成 `(/32)`、末尾还可能带 `(dirty)`；RISC-V 的寄存器名是 `x0/zero`
    这种带斜杠的写法。这些都要能吃掉，否则读全部寄存器会静默返回空表。
    """
    regs = {}
    for ln in (text or "").split("\n"):
        m = _REG_LINE.match(ln)
        if m:
            name = m.group(1)
            v = m.group(2)
            try:
                regs[name] = int(v, 16) if v.lower().startswith("0x") else int(v)
            except ValueError:
                continue
    return regs


# ================================================================ 复合操作

def _cpuid_info(addr: int = 0xE000ED00) -> dict:
    """读 SCB->CPUID（Cortex-M 专属），解出内核型号。失败就返回 {}。"""
    s = get_session()
    r = s.cmd("mdw 0x%08X 1" % addr, timeout=6)
    if not r.get("ok"):
        return {}
    p = _parse_mem(r.get("output") or "", addr, 1, 32)
    if not p["words"]:
        return {}
    v = p["words"][0]
    partno = (v >> 4) & 0xFFF
    return {"cpuid": "0x%08X" % v, "partno": "0x%03X" % partno,
            "core": _targets.CORE_BY_PARTNO.get(partno),
            "implementer": "0x%02X" % ((v >> 24) & 0xFF),
            "variant": (v >> 20) & 0xF, "revision": v & 0xF}


def probe() -> dict:
    """一次性把「连上的是谁」问清楚：targets / CPUID / DAP / flash banks。"""
    s = get_session()
    if not s.running():
        return {"ok": False, "error": "OpenOCD 没在运行", "hint": "先 ocd_start"}
    out = {"ok": True, "targets": [], "flash_banks": [], "ids": []}
    r = s.cmd("targets", timeout=6)
    out["targets_raw"] = r.get("output")
    for ln in (r.get("output") or "").split("\n"):
        # 真实 `targets` 是列对齐输出：
        #     TargetName         Type       Endian TapName            State
        #  --  ------------------ ---------- ------ ------------------ ----------
        #   0* stm32f4x.cpu       hla_target little stm32f4x.cpu       halted
        # name 与 type 之间**没有冒号**（早期版本才有 `name: type`），两种都要认。
        if not ln.strip() or ln.lstrip().startswith("--"):
            continue
        m = re.match(r"^\s*(\d+)\s*(\*?)\s*(\S+)\s*:?\s+(\S+)", ln)
        if m:
            out["targets"].append({"index": int(m.group(1)), "name": m.group(3),
                                   "type": m.group(4),
                                   "current": bool(m.group(2))})
    r = s.cmd("flash banks", timeout=6)
    out["flash_banks_raw"] = r.get("output")
    for ln in (r.get("output") or "").split("\n"):
        m = _FLASH_BANK_RE.match(ln)
        if m:
            out["flash_banks"].append({"bank": int(m.group(1)), "name": m.group(2),
                                       "driver": m.group(3), "base": m.group(4),
                                       "size": m.group(5)})
    # CPUID（Cortex-M 才有；RISC-V/Xtensa 上会报错，属正常）
    cp = _cpuid_info()
    if cp:
        out.update(cp)
    # DAP 信息（CMSIS-DAP 适配器才有）
    r = s.cmd("dap info", timeout=6)
    if r.get("ok") and r.get("output") and "Error" not in (r.get("output") or ""):
        out["dap_info"] = r.get("output")
    r = s.cmd("version", timeout=6)
    if r.get("ok"):
        out["openocd_version"] = (r.get("output") or "").strip().split("\n")[0]
    if not out["targets"]:
        out["ok"] = False
        out["error"] = "没枚举到 target：多半是 cfg 没加载对或探针没连上"
        out["hint"] = "看 ocd_log 里有没有 'Error:'；确认 interface/target cfg 存在"
    return out


# ================================================================ MCP 注册

def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="ocd_start",
        title="启动 OpenOCD 会话（非 MDK 目标的调试总入口）",
        description=(
            "启动一个 OpenOCD 进程并等它把 telnet 端口开起来，之后所有 ocd_* 工具都"
            "作用于这个会话。**同一根调试探针同一时刻只能有一个 OpenOCD 实例**，"
            "重复启动会明确报错（要换配置就 ocd_stop 或 restart=true）。\n"
            "两种用法：\n"
            "1. 给 profile（推荐）——用 target_list 里的档案名，自动组出 "
            "interface/target cfg、transport、adapter speed；\n"
            "2. 给 interface/target——自己指定 cfg 相对路径（先用 ocd_cfg_list 核实"
            "文件名，各版本 OpenOCD 的脚本名有差异）。\n"
            "commands 可追加启动时执行的 OpenOCD 命令（分号或换行分隔），例如 "
            "\"init; reset halt\"；默认不自动 init，让 AI 自己控制节奏。\n"
            "返回：pid、telnet/gdb/tcl 端口、就绪耗时、**日志尾部**（连不上目标时"
            "第一时间能看出是 cfg 错、线没插还是目标没供电）。"
        ),
    )
    async def ocd_start(profile: str = "", interface: str = "", target: str = "",
                        transport: str = "", speed: float = 0,
                        extra_cfg: str = "", commands: str = "",
                        telnet_port: int = DEF_TELNET, gdb_port: int = DEF_GDB,
                        tcl_port: int = DEF_TCL, cwd: str = "", exe: str = "",
                        restart: bool = False, wait: float = 20.0,
                        log_file: str = "") -> str:
        try:
            from . import toolchain as _tc
            _tc.apply_env(["openocd", "all"])
            s = get_session()
            if s.running() and not restart:
                return _js({"ok": False, "error": "已有 OpenOCD 在运行",
                            "session": s.info(),
                            "hint": "ocd_stop 停掉，或 ocd_start(restart=true) 换配置重启"})
            if s.running() and restart:
                s.stop()
            extra = [x for x in re.split(r"[;,|]", extra_cfg or "") if x.strip()]
            ag = _targets.openocd_args(profile=profile, interface=interface,
                                       target=target, transport=transport,
                                       speed=speed, extra_cfg=extra)
            if not ag.get("ok"):
                return _js(ag)
            args = list(ag["args"])
            # 端口显式指定，避免与已占用的 4444 撞车（同时开第二个 OpenOCD 时）
            args += ["-c", "telnet_port %d" % int(telnet_port),
                     "-c", "gdb_port %d" % int(gdb_port),
                     "-c", "tcl_port %d" % int(tcl_port)]
            for c in _split_commands(commands):
                args += ["-c", c]
            if not cwd and ag.get("arch") == "riscv":
                pass
            r = s.start(args, exe=exe, cwd=cwd, log_path=log_file,
                        wait=float(wait), port=int(telnet_port))
            s.ports.update({"gdb": int(gdb_port), "tcl": int(tcl_port)})
            s.profile = profile or ""
            out = dict(r)
            out["profile"] = profile or None
            out["openocd_args"] = ag
            out["toolchain_hint"] = ag.get("toolchain_hint")
            out["log_tail"] = s.tail(25)
            if r.get("ok"):
                out["next"] = ["ocd_probe（确认连上的是谁）", "ocd_control(action=\"reset_halt\")"]
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_stop",
        title="停止 OpenOCD 会话",
        description=(
            "优雅停止：先经 telnet 发 shutdown（让 OpenOCD 正常释放探针、复位目标"
            "调试引脚），等一段时间没退出才 terminate/kill。**调试结束后应当显式调它**"
            "——探针被占着会挡住 Keil / 其它 OpenOCD 实例。"
        ),
    )
    async def ocd_stop(graceful: bool = True, timeout: float = 6.0) -> str:
        try:
            return _js(get_session().stop(graceful=bool(graceful),
                                          wait=float(timeout)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_status",
        title="OpenOCD 会话状态（进程 / 端口 / 目标状态）",
        description=(
            "看会话是否还在、pid、各端口、已运行时长；并顺手问一次目标状态"
            "（poll）。running=false 时给出日志尾部——OpenOCD 崩了几乎总是因为在"
            "日志里写了原因，比任何猜测都准。"
        ),
    )
    async def ocd_status(probe_target: bool = True) -> str:
        try:
            s = get_session()
            out = s.info()
            if out.get("running") and probe_target:
                r = s.cmd("poll", timeout=4)
                out["poll"] = r.get("output")
                out["target_ok"] = r.get("ok")
                r2 = s.cmd("targets", timeout=4)
                out["targets"] = r2.get("output")
            if not out.get("running"):
                out["log_tail"] = s.tail(30)
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_cmd",
        title="执行 OpenOCD 命令（原始通道，什么都能问）",
        description=(
            "在运行中的会话上执行任意 OpenOCD/Jim-Tcl 命令。命令可用分号或换行分隔"
            "多条，逐条执行并聚合结果（任一条报错整体 ok=false）。\n"
            "常用命令速查：`targets`（目标列表）、`reg`/`reg pc`、`mdw <addr> <n>`、"
            "`mww <addr> <v>`、`bp <addr> [len]`、`rbp <addr>`、`wp <addr> [len] [r|w|a]`、"
            "`flash banks`、`flash info 0`、`program <file> [verify] [reset]`、"
            "`load_image <file> [addr]`、`reset halt`、`resume`、`step`、`poll`、"
            "`tpiu config ...`、`itm port 0 on`、`rtt setup/start/channels`。\n"
            "**报错只体现在输出文本里**（OpenOCD 不改退出码），本工具会把 `Error:` 行"
            "提成 error 字段，并把 Jim-Tcl 的调用栈折叠掉（那些栈行不是新错误）。"
        ),
    )
    async def ocd_cmd(command: str, timeout: float = 10.0) -> str:
        try:
            s = get_session()
            cmds = _split_commands(command)
            if not cmds:
                return _js({"ok": False, "error": "command 不能为空"})
            if len(cmds) == 1:
                r = s.cmd(cmds[0], timeout=float(timeout))
                if not r.get("ok") and r.get("error") is None and r.get("output"):
                    pass
                return _js(r)
            r = s.cmd_many(cmds, timeout=float(timeout))
            r["commands"] = cmds
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "command": command, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_cfg_list",
        title="列出 OpenOCD 自带的 interface / target / board 配置",
        description=(
            "列出 OpenOCD scripts 目录下真实存在的 cfg 文件（相对路径，可直接作为 "
            "-f 参数用）。**这是选型的唯一事实来源**：目标档案里记的 cfg 名只是首选"
            "建议，各版本 OpenOCD 的脚本名会变（上游版与 xPack 版就不同），"
            "启动前对着这份清单核实一遍能省掉大半「Error: Can't find target cfg」。\n"
            "kind=interface（探针）/ target（芯片）/ board（官方整板配置，一次把"
            "interface+target 都配好）。keyword 按相对路径子串过滤，如 \"stm32f4\"、"
            "\"cmsis-dap\"、\"riscv\"。"
        ),
    )
    async def ocd_cfg_list(kind: str = "target", keyword: str = "") -> str:
        try:
            return _js(_targets.list_cfg(kind=kind, keyword=keyword))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_probe",
        title="探测目标身份（targets / CPUID / flash banks / DAP）",
        description=(
            "连上以后第一件事：一次问清「对面是谁」。返回 target 列表（名字/类型/当前选中）、"
            "Flash 控制器（bank/driver/base）、OpenOCD 版本、DAP 适配器信息；"
            "若能读到 SCB->CPUID（Cortex-M）则解出内核型号（partno → Cortex-Mx）"
            "与 implementer。\n"
            "为什么要它：ELF 里没有芯片型号，工程名也可能骗人；CPUID/IDCODE 才是"
            "硬证据。ESP32 这类没有 CPUID 寄存器的目标会自然少这几项，不是错误。"
        ),
    )
    async def ocd_probe() -> str:
        try:
            return _js(probe())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_control",
        title="运行控制（halt / resume / reset / step / wait）",
        description=(
            "目标运行控制统一入口，action 取值：\n"
            "- `halt`：暂停（等真正停下再返回，带超时）\n"
            "- `resume`：继续运行\n"
            "- `reset_run`：复位后直接跑（等价 reset run）\n"
            "- `reset_halt`：复位后停在复位向量（**最常用的调试起点**）\n"
            "- `reset_init`：复位到 init 状态（部分目标支持）\n"
            "- `step`：单步一条指令；`step_over`：`step` 的别名（OpenOCD 无源码级单步）\n"
            "- `wait_halt`：等到目标停住（配合外部触发的断点/异常）\n"
            "- `poll`：只查当前状态\n"
            "返回逐条命令的输出与 target 状态。**halt 会短暂占住目标**，"
            "在多主控/看门狗场景下注意超时。"
        ),
    )
    async def ocd_control(action: str, target: str = "", timeout: float = 10.0) -> str:
        try:
            a = (action or "").strip().lower()
            tgt = ("%s " % target.strip()) if target.strip() else ""
            table = {
                "halt": "halt",
                "resume": "resume",
                "reset_run": "reset run",
                "reset": "reset run",
                "reset_halt": "reset halt",
                "reset_init": "reset init",
                "step": "step",
                "step_over": "step",
                "wait_halt": "wait_halt %s" % (timeout or 10),
                "poll": "poll",
            }
            if a not in table:
                return _js({"ok": False, "action": action,
                            "error": "未知 action", "available": sorted(table)})
            s = get_session()
            if a == "wait_halt":
                cmd = "wait_halt %d" % int(timeout or 10)
            else:
                cmd = tgt + table[a]
            r = s.cmd(cmd, timeout=float(timeout) + 2)
            rr = s.cmd("poll", timeout=4)
            r["action"] = a
            r["target_state"] = rr.get("output")
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_read_mem",
        title="读目标内存（OpenOCD 通道）",
        description=(
            "读内存并**解码成字节**返回：data_hex（小端）与 words 列表。width 支持 "
            "8/16/32（对应 OpenOCD 的 mdb/mdh/mdw）。\n"
            "与 read_mem（MDK 通道）的区别：这条不需要 Keil，只要有 OpenOCD 会话，"
            "RISC-V / ESP32 也能用。n_bytes 必须显式给（不猜）。\n"
            "内部会校验回显的地址列：读失败时 OpenOCD 会少打几行，"
            "只按行数取数会把上一行数据当结果，所以 complete=false 一律要当"
            "读取失败处理（附 got/expected）。"
        ),
    )
    async def ocd_read_mem(addr: str, n_bytes: int, width: int = 32,
                           target: str = "", timeout: float = 10.0) -> str:
        try:
            a = _parse_addr(addr)
            if a is None:
                return _js({"ok": False, "addr": addr, "error": "地址无法解析"})
            w = int(width)
            if w not in (8, 16, 32):
                return _js({"ok": False, "error": "width 只能是 8 / 16 / 32"})
            nb = int(n_bytes)
            if nb <= 0:
                return _js({"ok": False, "error": "n_bytes 必须 > 0"})
            cmd_name = {8: "mdb", 16: "mdh", 32: "mdw"}[w]
            count = (nb + w // 8 - 1) // (w // 8)
            tgt = ("%s " % target.strip()) if target.strip() else ""
            s = get_session()
            r = s.cmd("%s%s 0x%X %d" % (tgt, cmd_name, a, count), timeout=float(timeout))
            if not r.get("ok"):
                return _js(r)
            p = _parse_mem(r.get("output") or "", a, count, w)
            data = _mem_to_bytes(p["words"], w, nb)
            out = {"ok": p["complete"], "addr": "0x%X" % a, "n_bytes": nb,
                   "width": w, "words": ["0x%X" % x for x in p["words"]],
                   "data_hex": data.hex(), "got_bytes": len(data),
                   "expected_bytes": nb, "complete": p["complete"],
                   "raw": r.get("output")}
            if not p["complete"]:
                out["error"] = ("只读到 %d/%d 字节：目标没停住、地址非法或该区域"
                                "不可读" % (len(data), nb))
                out["hint"] = "先 ocd_control(action=\"halt\")，再确认地址在有效区间"
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": addr, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_write_mem",
        title="写目标内存（OpenOCD 通道，写后校验）",
        description=(
            "写内存。两种给数据的方式：\n"
            "- `data_hex`：十六进制串（如 \"00112233\"，按小端切成 width 宽的字）；\n"
            "- `words`：十进制/十六进制字列表（如 \"0x20000000,0x12345678\"）。\n"
            "OpenOCD 没有批量写命令，内部按 `;` 串多条 mww/mwh/mwb 再发，"
            "默认 verify=true 读回比对（写 Flash/RAM 都建议留着，"
            "缓存一致性问题在 H7 这类目标上真实存在）。"
        ),
    )
    async def ocd_write_mem(addr: str, data_hex: str = "", words: str = "",
                            width: int = 32, verify: bool = True,
                            target: str = "", timeout: float = 15.0) -> str:
        try:
            a = _parse_addr(addr)
            if a is None:
                return _js({"ok": False, "addr": addr, "error": "地址无法解析"})
            w = int(width)
            if w not in (8, 16, 32):
                return _js({"ok": False, "error": "width 只能是 8 / 16 / 32"})
            vals = _words_from_input(data_hex, words, w)
            if not vals:
                return _js({"ok": False, "error": "data_hex 与 words 至少要给一个"})
            cmd_name = {8: "mwb", 16: "mwh", 32: "mww"}[w]
            s = get_session()
            step = w // 8
            errs, sent = [], 0
            for i in range(0, len(vals), 32):
                chunk = vals[i:i + 32]
                parts = []
                for j, v in enumerate(chunk):
                    parts.append("%s 0x%X 0x%X" % (cmd_name, a + (i + j) * step, v))
                r = s.cmd("; ".join(parts), timeout=float(timeout))
                sent += len(chunk)
                if not r.get("ok"):
                    errs.append(r.get("error") or "写失败")
                    break
            out = {"ok": not errs, "addr": "0x%X" % a, "count": sent,
                   "bytes": sent * step, "width": w, "errors": errs}
            if verify and not errs:
                # 读回必须用**读**命令（mdb/mdh/mdw）；拿写命令去"读"等于又写了一遍，
                # 回读永远拿不到数据、一定报"写后读不一致"。
                rd_name = {8: "mdb", 16: "mdh", 32: "mdw"}[w]
                back = s.cmd("%s 0x%X %d" % (rd_name, a, len(vals)),
                             timeout=float(timeout))
                p = _parse_mem(back.get("output") or "", a, len(vals), w)
                if not back.get("ok") or not p["words"]:
                    # 「读不回来」与「写没生效」是两件事，不能合并报。
                    # 真机实测：往 RAM 越界地址 mww，OpenOCD 的写命令**不报错**，
                    # 只有在读回时才报 target 错误。此时若一口报成「写后读不一致」，
                    # 就是替设备编原因了（地址越界才是真相）。
                    out["ok"] = False
                    out["verified"] = None
                    out["verify_error"] = back.get("error") or "读回无数据"
                    out["read_back_raw"] = back.get("output")
                    out["hint"] = ("写命令没报错，但**读回校验本身失败**：该地址可能"
                                   "不在可读区间（RAM 越界 / 未映射），不是写失败。"
                                   "先确认区间再重试")
                    return _js(out)
                same = p["words"] == vals
                out["verified"] = same
                if not same:
                    out["ok"] = False
                    out["mismatch"] = [
                        {"addr": "0x%X" % (a + i * step),
                         "wrote": "0x%X" % vals[i],
                         "read": ("0x%X" % p["words"][i]) if i < len(p["words"]) else None}
                        for i in range(min(len(vals), len(p["words"]) + 1))
                        if i >= len(p["words"]) or p["words"][i] != vals[i]][:10]
                    out["hint"] = ("写后读不一致：目标可能在跑（先 halt）、"
                                   "该地址只读、或 D-Cache 未回写")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": addr, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_reg",
        title="读/写目标寄存器（OpenOCD 通道）",
        description=(
            "不带 name：读**全部**寄存器，返回 {名字: 值}（含 0x 与原值字符串）；\n"
            "给 name 不给 value：读单个；给 name + value：写单个。\n"
            "寄存器名随架构不同（Cortex-M 有 r0~r12/sp/lr/pc/xpsr；RISC-V 有 "
            "x0~x31/pc，部分实现带 csr 名）。不确定名字时先读全部看一遍，"
            "别猜。"
        ),
    )
    async def ocd_reg(name: str = "", value: str = "", target: str = "",
                      timeout: float = 8.0) -> str:
        try:
            tgt = ("%s " % target.strip()) if target.strip() else ""
            s = get_session()
            if not name:
                r = s.cmd(tgt + "reg", timeout=float(timeout))
                if not r.get("ok"):
                    return _js(r)
                regs = _parse_regs(r.get("output") or "")
                return _js({"ok": bool(regs), "count": len(regs),
                            "registers": regs,
                            "registers_hex": {k: "0x%X" % v for k, v in regs.items()},
                            "raw": r.get("output")})
            if value == "":
                r = s.cmd("%sreg %s" % (tgt, name), timeout=float(timeout))
                if not r.get("ok"):
                    return _js(r)
                regs = _parse_regs(r.get("output") or "")
                v = regs.get(name)
                return _js({"ok": v is not None, "name": name, "value": v,
                            "value_hex": ("0x%X" % v) if v is not None else None,
                            "raw": r.get("output")})
            vv = _parse_int(value)
            if vv is None:
                return _js({"ok": False, "name": name, "error": "value 无法解析"})
            r = s.cmd("%sreg %s 0x%X" % (tgt, name, vv), timeout=float(timeout))
            chk = s.cmd("%sreg %s" % (tgt, name), timeout=float(timeout))
            regs = _parse_regs(chk.get("output") or "")
            got = regs.get(name)
            return _js({"ok": r.get("ok") and (got == vv),
                        "name": name, "wrote": "0x%X" % vv,
                        "read_back": got, "verified": got == vv,
                        "raw": r.get("output")})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "name": name, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_bp",
        title="断点管理（OpenOCD 通道）",
        description=(
            "action=set：下断点，`bp <addr> [length]`；length 省略时按指令宽度（4/2）。"
            "action=clear：撤掉某个，`rbp <addr>`；action=clear_all：对已记录地址逐个撤；"
            "action=list：列出本工具记下的（OpenOCD 没有枚举断点的命令，"
            "所以这里返回的是**本会话经本工具下的**断点）。\n"
            "软/硬断点：OpenOCD 的 `bp` 会在硬件断点用尽时退化到 Flash 断点（需 "
            "flash 驱动），`hla` 适配器另有一套。想强制硬件用 hw=true（内部走 "
            "`bp` 并在失败时提示）；RISC-V 上只支持硬件断点。"
        ),
    )
    async def ocd_bp(action: str = "list", addr: str = "", length: int = 0,
                     hw: bool = True, target: str = "",
                     timeout: float = 8.0) -> str:
        try:
            a = (action or "list").strip().lower()
            s = get_session()
            tgt = ("%s " % target.strip()) if target.strip() else ""
            book = _OCD_BP.setdefault(id(s), [])
            if a == "list":
                return _js({"ok": True, "count": len(book), "breakpoints": book,
                            "note": "只列本会话经本工具下的断点（OpenOCD 无枚举命令）"})
            if a in ("clear_all", "clearall"):
                results = []
                for b in list(book):
                    r = s.cmd("%srbp 0x%X" % (tgt, b["addr"]), timeout=float(timeout))
                    results.append({"addr": b["addr"], "ok": r.get("ok"),
                                    "output": r.get("output")})
                    if r.get("ok"):
                        book.remove(b)
                return _js({"ok": all(x["ok"] for x in results) if results else True,
                            "cleared": len(results), "results": results})
            a2 = _parse_addr(addr)
            if a2 is None:
                return _js({"ok": False, "action": a, "error": "addr 无法解析"})
            if a == "set":
                a2, thumb_fixed = _norm_code_addr(a2)
                cmd = "%sbp 0x%X" % (tgt, a2)
                if length:
                    cmd += " %d" % int(length)
                r = s.cmd(cmd, timeout=float(timeout))
                if r.get("ok"):
                    book.append({"addr": a2, "addr_hex": "0x%X" % a2,
                                 "length": int(length) or None})
                    if thumb_fixed:
                        r["note"] = ("给的地址 bit0=1（Thumb 标记）已清零后再下断点："
                                     "0x%X -> 0x%X" % (_parse_addr(addr) or a2 | 1, a2))
                else:
                    r["hint"] = ("硬件断点资源有限（Cortex-M0 只有 4 个）；"
                                 "用尽时可用 Flash 断点（需 flash 驱动），"
                                 "或先 ocd_bp(action=\"clear\")")
                return _js(r)
            if a in ("clear", "del", "delete"):
                r = s.cmd("%srbp 0x%X" % (tgt, a2), timeout=float(timeout))
                book[:] = [b for b in book if b["addr"] != a2]
                return _js(r)
            return _js({"ok": False, "action": action,
                        "error": "未知 action",
                        "available": ["set", "clear", "clear_all", "list"]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_wp",
        title="观察点/数据断点（OpenOCD 通道）",
        description=(
            "action=set：`wp <addr> [length] [r|w|a]`，kind 取 r（读）/w（写）/a（读写），"
            "默认 w——**数据断点是排查「谁改了我的变量」的唯一硬手段**。"
            "action=clear：`rwp <addr>`；action=list：列本会话记下的观察点。\n"
            "长度限制：Cortex-M 的 DWT 只支持 1/2/4 字节且地址需对齐；"
            "RISC-V 视实现而定，失败会原样返回 OpenOCD 的报错。"
        ),
    )
    async def ocd_wp(action: str = "list", addr: str = "", length: int = 4,
                     kind: str = "w", target: str = "",
                     timeout: float = 8.0) -> str:
        try:
            a = (action or "list").strip().lower()
            s = get_session()
            tgt = ("%s " % target.strip()) if target.strip() else ""
            book = _OCD_WP.setdefault(id(s), [])
            if a == "list":
                return _js({"ok": True, "count": len(book), "watchpoints": book})
            a2 = _parse_addr(addr)
            if a2 is None:
                return _js({"ok": False, "action": a, "error": "addr 无法解析"})
            if a == "set":
                k = (kind or "w").strip().lower()
                if k not in ("r", "w", "a"):
                    return _js({"ok": False, "error": "kind 只能是 r/w/a"})
                r = s.cmd("%swp 0x%X %d %s" % (tgt, a2, int(length or 4), k),
                          timeout=float(timeout))
                if r.get("ok"):
                    book.append({"addr": "0x%X" % a2, "length": int(length or 4),
                                 "kind": k})
                return _js(r)
            if a in ("clear", "del", "delete"):
                r = s.cmd("%srwp 0x%X" % (tgt, a2), timeout=float(timeout))
                book[:] = [b for b in book if _parse_addr(b["addr"]) != a2]
                return _js(r)
            return _js({"ok": False, "action": action,
                        "available": ["set", "clear", "list"]})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "action": action, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_flash",
        title="烧录固件（OpenOCD program / flash write_image）",
        description=(
            "把 ELF/HEX/BIN 烧进目标 Flash。默认走 `program <file> [verify] [reset]`"
            "——OpenOCD 会自动识别格式、按需擦除并校验；烧 BIN 时必须给 addr"
            "（BIN 里没有地址信息，给了 addr 就走 `flash write_image erase`）。\n"
            "**先看 ocd_flash_info 确认 driver/base 对不对**：Flash 驱动选错是"
            "最常见的一次性变砖/写坏原因。返回烧录字节数、耗时与验证结论。"
        ),
    )
    async def ocd_flash(file: str, addr: str = "", verify: bool = True,
                        reset: bool = True, erase: bool = True,
                        target: str = "", timeout: float = 180.0) -> str:
        try:
            if not file or not os.path.isfile(file):
                return _js({"ok": False, "file": file, "error": "固件文件不存在"})
            st = stage_ascii_path(file)
            if not st.get("ok"):
                return _js({"ok": False, "file": os.path.abspath(file),
                            **{k: v for k, v in st.items() if k != "ok"}})
            src = st["path"]
            s = get_session()
            tgt = ("%s " % target.strip()) if target.strip() else ""
            a = _parse_addr(addr) if addr else None
            if a is not None:
                cmd = "%sflash write_image %s0x%X %s" % (
                    tgt, "erase " if erase else "", a, _q(src))
            else:
                cmd = "%sprogram %s %s%s" % (
                    tgt, _q(src), "verify " if verify else "",
                    "reset" if reset else "")
                cmd = cmd.strip()
            t0 = time.time()
            r = s.cmd(cmd, timeout=float(timeout))
            r["file"] = os.path.abspath(file)
            if st["staged"]:
                r["staged_from"] = st["orig"]
                r["staged_path"] = st["path"]
                r["path_note"] = st["note"]
            r["addr"] = ("0x%X" % a) if a is not None else None
            r["duration_s"] = round(time.time() - t0, 2)
            r["mode"] = "flash write_image" if a is not None else "program"
            if not r.get("ok"):
                r["hint"] = ("烧录失败常见原因：Flash 驱动/base 不对（先 ocd_flash_info）、"
                             "目标没 halt、读保护未解除、供电不足")
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "file": file, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_flash_info",
        title="Flash 控制器信息（banks / 驱动 / 扇区）",
        description=(
            "返回 `flash banks`（bank、驱动名、器件名、基址）与 `flash info 0`"
            "（扇区布局、写保护状态）。**烧录前的必查项**：driver/base 不对就烧不进去，"
            "强行烧还可能写坏其它区域；写保护位（WRP）开着会表现为「写入无变化」，"
            "这里能一眼看到。"
        ),
    )
    async def ocd_flash_info(bank: int = 0, timeout: float = 10.0) -> str:
        try:
            s = get_session()
            r1 = s.cmd("flash banks", timeout=float(timeout))
            r2 = s.cmd("flash info %d" % int(bank), timeout=float(timeout))
            out = {"ok": r1.get("ok"), "banks": r1.get("output"),
                   "info": r2.get("output")}
            banks = []
            for ln in (r1.get("output") or "").split("\n"):
                m = _FLASH_BANK_RE.match(ln)
                if m:
                    banks.append({"bank": int(m.group(1)), "name": m.group(2),
                                  "driver": m.group(3), "base": m.group(4),
                                  "size": m.group(5)})
            # 未 probe 的 bank：部分目标（ESP32 / 部分 RISC-V cfg）不会在 examine 时
            # 自动探测 Flash，此时 `flash banks` 会给出 size 0、`flash info` 也拿不到
            # 扇区。只在**确实异常**时补发 `flash probe`（常见路径不增加往返）。
            if not banks or not any((b.get("size") or "").strip("0x")
                                    not in ("", "0") for b in banks):
                pr = s.cmd("flash probe %d" % int(bank), timeout=float(timeout))
                if pr.get("ok"):
                    out["probe"] = pr.get("output")
                    out["probed"] = True
                    r1b = s.cmd("flash banks", timeout=float(timeout))
                    if r1b.get("ok"):
                        out["banks"] = r1b.get("output")
                        r2 = s.cmd("flash info %d" % int(bank), timeout=float(timeout))
                        out["info"] = r2.get("output")
                        banks = []
                        for ln in (out["banks"] or "").split("\n"):
                            m = _FLASH_BANK_RE.match(ln)
                            if m:
                                banks.append({"bank": int(m.group(1)),
                                              "name": m.group(2),
                                              "driver": m.group(3),
                                              "base": m.group(4),
                                              "size": m.group(5)})
            # 无论走没走 probe 分支，都把最终解析结果回填（常见路径也要有）
            out["parsed_banks"] = banks
            if not banks:
                out["ok"] = False
                out["hint"] = ("没有 Flash bank：target cfg 没选对，或这颗芯片的"
                               "Flash 需要额外 cfg（部分 ESP32/RISC-V 目标用 "
                               "esp32.cfg 才有）")
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_load",
        title="加载可执行文件到目标（load_image，通常用于 RAM 调试）",
        description=(
            "`load_image <file> [addr]`：把 ELF/BIN 载入目标内存。主要用于"
            "**RAM 里跑**（不烧 Flash，反复改代码的快速迭代），也用于把数据文件"
            "灌到指定地址。给 addr 时按原始二进制处理，不给 addr 时按 ELF 段布局载入。"
        ),
    )
    async def ocd_load(file: str, addr: str = "", timeout: float = 60.0) -> str:
        try:
            if not file or not os.path.isfile(file):
                return _js({"ok": False, "file": file, "error": "文件不存在"})
            st = stage_ascii_path(file)
            if not st.get("ok"):
                return _js({"ok": False, "file": os.path.abspath(file),
                            **{k: v for k, v in st.items() if k != "ok"}})
            s = get_session()
            a = _parse_addr(addr) if addr else None
            cmd = "load_image %s%s" % (_q(st["path"]),
                                      (" 0x%X" % a) if a is not None else "")
            r = s.cmd(cmd, timeout=float(timeout))
            r["file"] = os.path.abspath(file)
            if st["staged"]:
                r["staged_from"] = st["orig"]
                r["staged_path"] = st["path"]
                r["path_note"] = st["note"]
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "file": file, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_gdb",
        title="GDB 批处理（通过 gdb_port 连 OpenOCD）",
        description=(
            "用 GDB 的批处理模式（`-batch -ex ...`）连上正在运行的 OpenOCD 的 gdb 端口，"
            "执行若干 GDB 命令后退出。适合做**只有 GDB 才擅长**的事：加载 ELF 符号、"
            "`info threads`（RTOS 多任务）、`thread apply all bt`（各任务调用栈）、"
            "`monitor` 透传 OpenOCD 命令、`load` 走 GDB 通道烧录。\n"
            "gdb 省略时按 elf 的架构自动挑（arm-none-eabi-gdb / riscv32-esp-elf-gdb "
            "等）；commands 用分号或换行分隔，会自动展开成多个 -ex。"
            "`-batch` 下不会进交互，别发需要人工确认的命令。"
        ),
    )
    async def ocd_gdb(commands: str, elf: str = "", gdb: str = "",
                      port: int = DEF_GDB, timeout: float = 60.0) -> str:
        try:
            from . import toolchain as _tc
            _tc.apply_env(["all"])
            exe = gdb
            if not exe:
                fam = ""
                if elf:
                    g = _targets.guess_from_elf(elf)
                    if g.get("ok"):
                        fam = g.get("family") or ""
                for f in ([fam] if fam else []) + ["arm-none-eabi", "riscv-none-elf",
                                                   "riscv32-esp-elf", "xtensa-esp-elf"]:
                    exe = _tc.find_tool(f, "gdb") or ""
                    if exe:
                        break
            if not exe:
                return _js({"ok": False, "error": "本机没找到 gdb",
                            "hint": "装 xPack gcc（自带 gdb）或 esp-elf-gdb，"
                                    "再用 toolchain_env(families=\"all\") 注入"})
            cmds = _split_commands(commands)
            if not cmds:
                return _js({"ok": False, "error": "commands 不能为空"})
            argv = ["-batch"]
            if elf:
                argv.append(elf)
            argv += ["-ex", "target extended-remote 127.0.0.1:%d" % int(port)]
            for c in cmds:
                argv += ["-ex", c]
            r = _tc.run_tool(exe, argv, timeout=float(timeout))
            r["gdb"] = exe
            r["commands"] = cmds
            if not r.get("ok"):
                r["hint"] = ("连不上 gdb_port：确认 ocd_start 起着的会话的 gdb_port，"
                             "以及目标已 halt；OpenOCD 的日志里会有 gdb 连接记录")
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="ocd_log",
        title="OpenOCD 日志（连不上时第一个该看的地方）",
        description=(
            "读 OpenOCD 进程的日志尾部。keyword 过滤关键字（如 \"Error\"、\"Info : "
            "Examined\"、\"flash\"），lines 控制行数。\n"
            "**为什么把它做成独立工具**：OpenOCD 的很多问题（cfg 选错、探针被占用、"
            "目标没供电、Flash 驱动不匹配、SWO 引脚没接）都不会让进程退出，"
            "只体现在日志里；telnet 通道反而看不到这些早期日志。"
        ),
    )
    async def ocd_log(lines: int = 60, keyword: str = "") -> str:
        try:
            s = get_session()
            txt = s.tail(int(lines), keyword=keyword)
            return _js({"ok": bool(txt), "log": s.log_path, "keyword": keyword,
                        "lines": len(txt.splitlines()) if txt else 0,
                        "text": txt,
                        "note": "日志文件路径在 log 字段；running=%s" % s.running()})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n


_OCD_BP = {}
_OCD_WP = {}


def _q(p: str) -> str:
    p = str(p).replace("\\", "/")
    return '{%s}' % p if (" " in p) else p


def _as_ascii_path(path: str) -> str:
    """把文件名（不是目录）里的非 ASCII 字符换成 `_`，保留扩展名。"""
    base = os.path.basename(str(path))
    stem, ext = os.path.splitext(base)
    def _san(s: str) -> str:
        return "".join(ch if (ch.isascii() and (ch.isalnum() or ch in "._-"))
                       else "_" for ch in s)
    out = _san(stem) + (_san(ext) if ext.isascii() else ".bin")
    return out or "firmware.bin"


def stage_ascii_path(path: str) -> dict:
    """把路径里带非 ASCII 字符的文件拷到纯 ASCII 目录，供 OpenOCD 使用。

    为什么必须这样：OpenOCD 的 telnet 口是 7-bit NVT（RFC 854 默认协商），
    非 ASCII 字节**在发给 OpenOCD 的路上就丢了**。真机取证（xPack OpenOCD
    0.12.0 + CMSIS-DAPv2 / STM32F401）：

        program "D:/工作/git_project/.../rtt_probe.elf" verify
          回显成  D://git_project/.../rtt_probe.elf   <- 6 个 UTF-8 字节没了
          OpenOCD: couldn't open D://git_project/.../rtt_probe.elf
          embedded:startup.tcl:1813: Error: ** Programming Failed **

    Windows 上带中文的工程目录太常见（本机就是「工作」），所以不报错了事：
    拷一份 ASCII 副本再喂给它，并把 staging 路径如实回传，避免任何静默行为。

    返回 {ok, path, staged, orig, note} 或 {ok: False, error, hint}。
    """
    src = os.path.abspath(path)
    if src.isascii():
        return {"ok": True, "path": src, "staged": False, "orig": src}
    root = tempfile.gettempdir()
    if not root or not root.isascii():
        root = (os.path.splitdrive(src)[0] or "C:") + os.sep
    stage = os.path.join(root, "mdkdebug_stage")
    tag = hashlib.sha1(src.encode("utf-8")).hexdigest()[:8]
    dest = os.path.join(stage, "%s_%s" % (tag, _as_ascii_path(src)))
    try:
        os.makedirs(stage, exist_ok=True)
        shutil.copyfile(src, dest)
    except OSError as e:
        return {"ok": False, "orig": src,
                "error": "路径含非 ASCII 字符，且暂存到 ASCII 目录失败：%s" % e,
                "hint": "OpenOCD 的 telnet 口是 7-bit，非 ASCII 路径传不过去。"
                        "请把固件放到纯英文路径再试（如 C:/fw/app.elf）。"}
    return {"ok": True, "path": os.path.abspath(dest), "staged": True,
            "orig": src, "stage_dir": stage,
            "note": "原路径含非 ASCII 字符（OpenOCD 的 telnet 是 7-bit，直接传会"
                    "被截断且报错含糊），已自动拷一份 ASCII 副本给 OpenOCD"}


def _parse_addr(s) -> int | None:
    if s is None:
        return None
    if isinstance(s, int):
        return s
    t = str(s).strip()
    if not t:
        return None
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t, 0)
    except ValueError:
        return None


def _parse_int(s) -> int | None:
    return _parse_addr(s)


def _words_from_input(data_hex: str, words: str, width: int) -> list:
    step = width // 8
    vals = []
    if data_hex:
        h = re.sub(r"[^0-9a-fA-F]", "", data_hex)
        if len(h) % 2:
            h = "0" + h
        raw = bytes.fromhex(h)
        for i in range(0, len(raw), step):
            chunk = raw[i:i + step]
            if len(chunk) < step:
                chunk = chunk + b"\x00" * (step - len(chunk))
            vals.append(int.from_bytes(chunk, "little"))
    if words:
        toks = re.split(r"[,\s]+", str(words).strip())
        for t in toks:
            if not t:
                continue
            v = _parse_addr(t)
            if v is None:
                continue
            vals.append(v & ((1 << width) - 1))
    return vals
