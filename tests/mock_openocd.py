# -*- coding: utf-8 -*-
"""内存版 OpenOCD telnet 假服务器（mock）。

用途：在没有真实探针/目标的情况下，让 ocd_* / trace_* 系列工具走完整链路
（发命令 -> 收包 -> 解析 -> 结构化输出），覆盖解析逻辑与错误路径。

行为对着真实 OpenOCD 0.12 的输出格式写。以下是踩过坑、刻意保持真实的几处：

- 连接时先发 telnet IAC 协商字节（``\xff\xfb\x03...``），每条命令的**回显之后、
  正文之前**固定插一个 ``\x00``。两者都插在行首位置，客户端不剥就会让行首锚定的
  解析正则全部失效（症状：raw 里有数据，解析出来 0 条）。真机抓包复现，默认开启，
  ``--no-telnet-noise`` / ``telnet_noise=False`` 可关。
- 提示符是 ``> ``（**带一个空格**）。客户端若先判 ``endswith(">")`` 再 rstrip，
  就永远匹配不上，每条命令都要白等一次空闲超时。
- ``targets`` 是**列对齐**输出，name 与 type 之间没有冒号
  （早期版本才有 ``name: type``）。
- ``flash banks`` 是 ``#0 : name (driver) at 0x08000000, size ...``——
  驱动括号后面**直接就是 at**，中间没有别的字段。
- ``reg`` 每行带序号前缀 ``(0) r0 (/32): 0x00000000 (dirty)``。
- ``mdw`` 每行 ``0x20000000: xxxxxxxx xxxxxxxx ...``，一行 4 个。
- 未知命令回 ``Error: invalid command name "xxx"`` 加若干 Jim-Tcl 栈行。
"""

import os
import socket
import struct
import tempfile
import threading
import time

# ---------------------------------------------------------------- 内存布局

RAM_BASE = 0x20000000
RAM_SIZE = 0x20000
FLASH_BASE = 0x08000000
FLASH_SIZE = 0x100000

# RTT 控制块与两个通道缓冲（测试用固定地址，便于断言）
RTT_CB_ADDR = 0x20001000
RTT_UP_BUF = 0x20002000
RTT_DOWN_BUF = 0x20003000
RTT_NAME_ADDR = 0x20000200

_SEGGER_MAGIC = b"SEGGER RTT\x00"
_CH_FMT = "<IIIIII"      # name_ptr, buf_ptr, size, wr, rd, flags
_CH_SIZE = 24


class MockTarget(object):
    """假目标：稀疏内存 + 寄存器 + 断点/观察点 + 命令副作用的记录。"""

    CPUID_ADDR = 0xE000ED00
    CPUID_VALUE = 0x410FC241      # partno 0xC24 -> Cortex-M4

    def __init__(self):
        self.mem = {}
        self.halted = True
        self.regs = [("r0", 0), ("r1", 0), ("r2", 0), ("r3", 0), ("r4", 0),
                     ("r5", 0), ("r6", 0), ("r7", 0), ("r8", 0), ("r9", 0),
                     ("r10", 0), ("r11", 0), ("r12", 0),
                     ("sp", 0x20020000), ("lr", 0x080003FD), ("pc", 0x08000400),
                     ("xpsr", 0x01000000)]
        self.bps = []
        self.wps = []
        self.programmed = []
        self.written_images = []
        self.loaded = []
        self.tpiu = []
        self.itm_port_cmds = []
        self.resets = []
        self.reason = "debug-request"
        self.poke(self.CPUID_ADDR, struct.pack("<I", self.CPUID_VALUE))

    # -------------------------------------------------- 内存
    def poke(self, addr, data):
        data = bytes(bytearray(data))
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def peek(self, addr, n):
        return bytes(self.mem.get(addr + i, 0) for i in range(n))

    def mapped(self, addr, n):
        for i in range(n):
            a = addr + i
            if RAM_BASE <= a < RAM_BASE + RAM_SIZE:
                continue
            if FLASH_BASE <= a < FLASH_BASE + FLASH_SIZE:
                continue
            if a in self.mem:
                continue
            return False
        return True

    def word(self, addr):
        return int.from_bytes(self.peek(addr, 4), "little")

    # -------------------------------------------------- RTT 预置
    def install_rtt(self, up_payload=b"", up_size=256, with_names=True):
        """在内存里摆一个合法的 SEGGER RTT 控制块 + 上行通道载荷。"""
        if len(up_payload) > up_size:
            raise ValueError("up_payload 比通道还大")
        cb = struct.pack("<16sii", _SEGGER_MAGIC, 1, 1)
        name_up = RTT_NAME_ADDR
        name_down = RTT_NAME_ADDR + 16
        if with_names:
            self.poke(name_up, b"Terminal\x00")
            self.poke(name_down, b"Input\x00")
        cb += struct.pack(_CH_FMT, name_up, RTT_UP_BUF, up_size,
                          len(up_payload), 0, 0)
        cb += struct.pack(_CH_FMT, name_down, RTT_DOWN_BUF, 64, 0, 0, 0)
        self.poke(RTT_CB_ADDR, cb)
        self.poke(RTT_UP_BUF, up_payload)

    def rtt_up_state(self):
        """读回上行通道 (wr, rd, buf_ptr, size)。"""
        raw = self.peek(RTT_CB_ADDR, 24 + 2 * _CH_SIZE)
        _magic, nup, _ndown = struct.unpack("<16sii", raw[:24])
        out = []
        for i in range(nup):
            off = 24 + i * _CH_SIZE
            nm, bp, sz, wr, rd, fl = struct.unpack("<IIIIII", raw[off:off + _CH_SIZE])
            out.append({"name_ptr": nm, "buf_ptr": bp, "size": sz,
                        "wr": wr, "rd": rd, "flags": fl})
        return out


# ---------------------------------------------------------------- 假进程


class MockProc(object):
    """够 OCDSession 用的假进程对象（只用到 poll/pid/terminate/kill）。"""

    def __init__(self, srv):
        self._srv = srv
        self.pid = 42424
        self.returncode = None

    def poll(self):
        if self._srv.alive:
            return None
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self):
        self.returncode = 0
        self._srv.shutdown_server()
        return 0

    def kill(self):
        return self.terminate()


# ---------------------------------------------------------------- 假服务器

_PROMPT = b"\r\n> "

# 真实 OpenOCD telnet 连上时先发的 IAC 协商字节（IAC WILL SGA / WILL ECHO /
# DO SGA / DONT ECHO），真机抓包原文，不要改。
_IAC_HELLO = b"\xff\xfb\x03\xff\xfb\x01\xff\xfd\x03\xff\xfe\x01"

_HELP = [
    "shutdown", "version", "targets", "poll", "halt", "resume", "reset",
    "step", "reg", "bp", "rbp", "wp", "rwp", "mdw", "mdb", "mwh", "mww",
    "flash", "program", "load_image", "dap", "tpiu", "itm", "sleep", "echo",
]


class MockOpenOCD(object):
    """监听一个 TCP 端口，按 OpenOCD 的 telnet 协议应答。

    port=0 时由系统分配，真实端口在 ``.port``。
    ``.target`` 是假目标，``.log`` 是收到过的命令行（测试断言用）。
    """

    def __init__(self, host="127.0.0.1", port=0, banner=True, telnet_noise=True):
        self.host = host
        self.banner = banner
        # 默认按真机发 IAC 协商 + NUL 前缀（保真优先，见模块文档）
        self.telnet_noise = telnet_noise
        self.target = MockTarget()
        self.log = []
        self.alive = True
        self._clients = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, int(port)))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._th = threading.Thread(target=self._accept_loop)
        self._th.daemon = True
        self._th.start()

    # -------------------------------------------------- 生命周期
    def shutdown_server(self):
        self.alive = False
        try:
            self._srv.close()
        except OSError:
            pass
        for c in list(self._clients):
            try:
                c.close()
            except OSError:
                pass

    def _accept_loop(self):
        while self.alive:
            try:
                self._srv.settimeout(0.2)
                cs, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._clients.append(cs)
            t = threading.Thread(target=self._client_loop, args=(cs,))
            t.daemon = True
            t.start()

    def _client_loop(self, cs):
        cs.settimeout(0.2)
        try:
            if self.banner:
                # 真实 OpenOCD 连上先做 telnet 协商（IAC WILL/DO…）再吐 banner。
                # 真机抓包原文：
                #   b'\xff\xfb\x03\xff\xfb\x01\xff\xfd\x03\xff\xfe\x01Open On-Chip Debugger\r\n\r> '
                # 不复现这段，客户端里剥 IAC 的代码就永远没人测。
                if self.telnet_noise:
                    cs.sendall(_IAC_HELLO + b"Open On-Chip Debugger\r\n")
                else:
                    cs.sendall(b"Open On-Chip Debugger\r\n")
            cs.sendall(_PROMPT)
        except OSError:
            try:
                cs.close()
            except OSError:
                pass
            return
        try:
            buf = b""
            while self.alive:
                try:
                    chunk = cs.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", "replace").rstrip("\r")
                    self._serve_line(cs, text)
                    if not self.alive:
                        break
            if self.alive:
                try:
                    cs.sendall(_PROMPT)
                except Exception:                      # noqa: BLE001
                    pass
        finally:
            try:
                cs.close()
            except OSError:
                pass

    # -------------------------------------------------- 分发
    def _serve_line(self, cs, text):
        text = text.strip()
        if not text:
            return
        # telnet 是 7-bit NVT：非 ASCII 字节到不了 OpenOCD。真机取证
        # （xPack 0.12.0 + CMSIS-DAPv2）：`program "D:/工作/.../a.elf"` 的回显
        # 就是 `D://.../a.elf`——6 个 UTF-8 字节直接没了。
        if self.telnet_noise and not text.isascii():
            text = text.encode("ascii", "ignore").decode("ascii")
        out = []
        for piece in text.split(";"):
            piece = piece.strip()
            if not piece or piece.startswith("#"):
                continue
            self.log.append(piece)
            out.extend(self._handle(piece))
        body = "".join(l.rstrip("\r\n") + "\r\n" for l in out)
        try:
            cs.sendall(("%s\r\n" % text).encode("utf-8"))   # 回显
            # 真实 OpenOCD 在回显之后、正文之前固定插一个 NUL（真机抓包：
            # b'mdw 0x08000000 2\r\n\x000x08000000: 20000728 080002e1 \r\n\r> '）。
            # 它是行首锚定正则的杀手——客户端不清掉就会把整行数据丢掉。
            if self.telnet_noise:
                cs.sendall(b"\x00")
            cs.sendall(body.encode("utf-8"))
            if self.alive:
                cs.sendall(_PROMPT)
        except OSError:
            pass

    def _err(self, cmd):
        return ['Error: invalid command name "%s"' % cmd,
                "in procedure '%s' " % cmd,
                "in procedure 'unknown' "]

    # -------------------------------------------------- 命令实现
    def _handle(self, line):
        parts = line.split()
        c = parts[0]
        args = parts[1:]
        t = self.target

        if c in ("version", "help"):
            return ["Open On-Chip Debugger 0.12.0",
                    "Licensed under GNU GPL v2",
                    "For bug reports, read",
                    "        http://openocd.org/doc/doxygen/bugs.html"]
        if c == "targets":
            state = "halted" if t.halted else "running"
            return ["    TargetName         Type       Endian TapName            "
                    "State       ",
                    "--  ------------------ ---------- ------ ------------------ "
                    "----------  ",
                    " 0* stm32f4x.cpu       hla_target little stm32f4x.cpu       %s"
                    % state]
        if c == "poll":
            return ["target state: %s" % ("halted" if t.halted else "running")]
        if c == "halt":
            t.halted = True
            t.reason = "debug-request"
            return ["target halted due to debug-request, current mode: Thread ",
                    "xPSR: 0x%08X pc: 0x%08X msp: 0x%08X"
                    % (dict(t.regs).get("xpsr", 0), dict(t.regs).get("pc", 0),
                       dict(t.regs).get("sp", 0))]
        if c == "resume":
            t.halted = False
            return ["Target 0 halted"]
        if c == "reset":
            which = args[0] if args else "run"
            t.resets.append(which)
            if which in ("halt", "init"):
                t.halted = True
                t.reason = "debug-request"
                t.regs = [(k, (0x08000400 if k == "pc" else v))
                          for k, v in t.regs]
                return ["target halted due to debug-request, current mode: Thread ",
                        "xPSR: 0x%08X pc: 0x%08X msp: 0x%08X"
                        % (dict(t.regs).get("xpsr", 0),
                           dict(t.regs).get("pc", 0),
                           dict(t.regs).get("sp", 0))]
            t.halted = False
            return []
        if c == "step":
            t.halted = True
            t.reason = "single-step"
            d = dict(t.regs)
            t.regs = [(k, (d[k] + 2 if k == "pc" else v)) for k, v in t.regs]
            return ["target halted due to single-step, current mode: Thread ",
                    "xPSR: 0x%08X pc: 0x%08X msp: 0x%08X"
                    % (d.get("xpsr", 0), d.get("pc", 0), d.get("sp", 0))]
        if c == "wait_halt":
            t.halted = True
            t.reason = "breakpoint"
            return ["target halted due to breakpoint, current mode: Thread "]
        if c in ("mdw", "mdh", "mdb"):
            return self._dump(c, args)
        if c in ("mww", "mwh", "mwb"):
            return self._store(c, args)
        if c == "reg":
            return self._reg(args)
        if c == "bp":
            if len(args) < 1:
                return ['Error: bp: missing required argument']
            a = self._num(args[0])
            ln = self._num(args[1]) if len(args) > 1 else 0
            if a is None:
                return ['Error: invalid number "%s"' % args[0]]
            t.bps.append({"addr": a, "length": ln})
            return []
        if c == "rbp":
            a = self._num(args[0]) if args else None
            if a is None:
                return ['Error: rbp: missing required argument']
            t.bps = [b for b in t.bps if b["addr"] != a]
            return []
        if c == "wp":
            if len(args) < 1:
                return ['Error: wp: missing required argument']
            a = self._num(args[0])
            ln = self._num(args[1]) if len(args) > 1 else 4
            k = args[2] if len(args) > 2 else "w"
            if a is None:
                return ['Error: invalid number "%s"' % args[0]]
            if k not in ("r", "w", "a"):
                return ['Error: wp: option must be r, w or a']
            if ln not in (1, 2, 4):
                return ['Error: watchpoint length must be 1, 2 or 4']
            t.wps.append({"addr": a, "length": ln, "kind": k})
            return []
        if c == "rwp":
            a = self._num(args[0]) if args else None
            if a is None:
                return ['Error: rwp: missing required argument']
            t.wps = [w for w in t.wps if w["addr"] != a]
            return []
        if c == "flash":
            sub = args[0] if args else ""
            if sub == "banks":
                return ["#0 : stm32f4x.flash (stm32f2x) at 0x%08X, size 0x%08X, "
                        "buswidth 0, chipwidth 0" % (FLASH_BASE, FLASH_SIZE)]
            if sub == "info":
                bank = args[1] if len(args) > 1 else "0"
                if bank != "0":
                    return ['Error: flash bank %s not found' % bank]
                rows = ["#0 : stm32f4x.flash (stm32f2x) at 0x%08X, size 0x%08X, "
                        "buswidth 0, chipwidth 0" % (FLASH_BASE, FLASH_SIZE)]
                for i in range(4):
                    rows.append(" #  %d: 0x%08X (0x4000 16kB) not protected"
                                % (i, i * 0x4000))
                return rows
            if sub == "write_image":
                t.written_images.append({"args": args[1:], "line": line})
                return ["wrote %d bytes from file %s in 0.123456s (%.3f KiB/s)"
                        % (FLASH_SIZE // 64, os.path.basename(args[-1]), 12.5),
                        "** Verified OK **"]
            if sub == "erase":
                return ["erased sectors 0 through 3 on flash bank 0 in 0.05s"]
            if sub == "probe":
                return ["flash 'stm32f2x' found at 0x%08X" % FLASH_BASE]
            return self._err("flash %s" % sub)
        if c == "program":
            if len(args) < 1:
                return ['Error: program: missing required argument']
            # 真机保真：文件打不开时 OpenOCD 是
            #   ** Programming Started **
            #   couldn't open <path>
            #   embedded:startup.tcl:1813: Error: ** Programming Failed **
            # 注意第一、三行都不带行首 `Error:`（第三行带位置前缀），只用
            # `^Error:` 判定会把失败当成成功（真机就这么骗过 ocd_flash）。
            # 路径里的非 ASCII 字符已在 _serve_line 按 7-bit telnet 语义丢掉，
            # 所以「中文路径」在本 mock 里的失败形态与真机一致。
            p = args[0].replace("/", os.sep)
            if not os.path.isfile(p):
                return ["** Programming Started **",
                        "couldn't open %s" % args[0],
                        "embedded:startup.tcl:1813: "
                        "Error: ** Programming Failed **"]
            t.programmed.append({"args": list(args), "line": line})
            return ["** Programming Started **",
                    "** Programming Finished **",
                    "** Verify Started **",
                    "** Verified OK **",
                    "** Resetting Target **"]
        if c == "load_image":
            if len(args) < 1:
                return ['Error: load_image: missing required argument']
            t.loaded.append(list(args))
            return []
        if c == "dap":
            if args and args[0] == "info":
                return ["AP ID register 0x24770011",
                        "        Type is MEM-AP AHB3"]
            return self._err("dap %s" % (args[0] if args else ""))
        if c == "tpiu":
            t.tpiu.append(line)
            if len(args) >= 6 and args[0] == "config":
                return []
            return []
        if c == "itm":
            t.itm_port_cmds.append(line)
            return []
        if c == "shutdown":
            self.shutdown_server()
            return []
        if c in ("sleep", "echo"):
            return [" ".join(args)]
        return self._err(c)

    # -------------------------------------------------- 子命令
    @staticmethod
    def _num(s):
        try:
            return int(str(s), 16) if str(s).lower().startswith("0x") else int(s, 0)
        except ValueError:
            return None

    def _dump(self, c, args):
        width = {"mdb": 8, "mdh": 16, "mdw": 32}[c]
        if not args:
            return ["usage: %s <address> [count]" % c]
        a = self._num(args[0])
        if a is None:
            return ['Error: invalid number "%s"' % args[0]]
        n = self._num(args[1]) if len(args) > 1 else 1
        if n is None or n <= 0:
            return ['Error: invalid count "%s"' % args[1]]
        step = width // 8
        if not self.target.mapped(a, n * step):
            return ["Error: Failed to read memory at 0x%08X" % a]
        per = {8: 16, 16: 8, 32: 4}[width]
        digits = {8: 2, 16: 4, 32: 8}[width]
        rows, i = [], 0
        while i < n:
            k = min(per, n - i)
            base = a + i * step
            vals = []
            for j in range(k):
                vals.append("%0*x" % (digits, int.from_bytes(
                    self.target.peek(base + j * step, step), "little")))
            rows.append("0x%08X: %s " % (base, " ".join(vals)))
            i += k
        return rows

    def _store(self, c, args):
        width = {"mwb": 8, "mwh": 16, "mww": 32}[c]
        if len(args) < 2:
            return ["usage: %s <address> <value>" % c]
        a = self._num(args[0])
        v = self._num(args[1])
        if a is None or v is None:
            return ['Error: invalid number']
        step = width // 8
        if not self.target.mapped(a, step):
            return ["Error: Failed to write memory at 0x%08X" % a]
        self.target.poke(a, int(v & ((1 << width) - 1)).to_bytes(step, "little"))
        return []

    def _reg(self, args):
        t = self.target
        d = dict(t.regs)
        order = [k for k, _ in t.regs]
        if not args:
            rows = ["===== arm v7m registers"]
            for i, k in enumerate(order):
                rows.append("(%d) %s (/32): 0x%08X (dirty)" % (i, k, d.get(k, 0)))
            return rows
        name = args[0]
        if name not in d:
            return ['Error: register "%s" not found' % name]
        if len(args) == 1:
            i = order.index(name)
            return ["(%d) %s (/32): 0x%08X (dirty)" % (i, name, d[name])]
        v = self._num(args[1])
        if v is None:
            return ['Error: invalid number "%s"' % args[1]]
        t.regs = [(k, (v if k == name else val)) for k, val in t.regs]
        return []


# ---------------------------------------------------------------- 会话挂接


def attach(srv, sess=None, profile="stm32f401", log_text="", args=None):
    """把假服务器挂到一个 OCDSession 上（跳过真的 openocd 进程）。

    只设置 OCDSession 用到的那些字段；``proc`` 换成 MockProc，
    这样 ``running()`` / ``stop()`` 都能正常工作。
    """
    if sess is None:
        from mdkdebug import ocd as _ocd
        sess = _ocd.get_session()
    d = os.path.join(tempfile.gettempdir(), "mdkdebug_ocd")
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    if not log_text:
        log_text = ("Info : Listening on port %d for telnet sessions\r\n"
                    "Info : Examined Cortex-M4 r0p1\r\n" % srv.port)
    log_path = os.path.join(d, "mock_openocd_%d.log" % srv.port)
    with open(log_path, "wb") as f:
        f.write((log_text or "").encode("utf-8"))
    sess.proc = MockProc(srv)
    sess.exe = "C:/fake/openocd.exe"
    sess.args = list(args or ["-f", "interface/cmsis-dap.cfg",
                              "-f", "target/stm32f4x.cfg"])
    sess.cwd = ""
    sess.ports = {"telnet": srv.port, "gdb": 3333, "tcl": 6666}
    sess.log_path = log_path
    sess.started_at = time.time()
    sess.profile = profile
    sess.tel = None
    return sess


def detach(sess=None, srv=None):
    """清理：关 telnet 连接、清会话、停假服务器。"""
    from mdkdebug import ocd as _ocd
    if sess is None:
        sess = _ocd.get_session()
    if sess.tel is not None:
        try:
            sess.tel.close()
        except Exception:                                  # noqa: BLE001
            pass
        sess.tel = None
    sess.proc = None
    sess.exe = ""
    if srv is not None:
        srv.shutdown_server()


# ======================================================================
# 命令行入口：人工联调用
#   python -m tests.mock_openocd --port 4444 --rtt
# 启动后把实际监听端口打在标准输出，可用 telnet / ocd_cmd 手工连进来。
# ======================================================================
def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="模拟 OpenOCD 的 telnet 服务器")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 表示由系统分配")
    ap.add_argument("--no-banner", action="store_true", help="不发送版本 banner")
    ap.add_argument("--no-telnet-noise", action="store_true",
                    help="不发 IAC 协商与 NUL 前缀（对照用，默认按真机发）")
    ap.add_argument("--rtt", action="store_true", help="预置一段 RTT 上行数据")
    ap.add_argument("--rtt-text", default="boot ok", help="与 --rtt 搭配的文本内容")
    args = ap.parse_args(argv)

    srv = MockOpenOCD(host=args.host, port=args.port, banner=not args.no_banner,
                      telnet_noise=not args.no_telnet_noise)
    if args.rtt:
        srv.target.install_rtt(up_payload=args.rtt_text.encode("utf-8"),
                               up_size=256)
    print("mock openocd listening on %s:%d (telnet)" % (srv.host, srv.port),
          flush=True)
    if args.rtt:
        print("RTT control block @ 0x%X" % RTT_CB_ADDR, flush=True)
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown_server()
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_main())
