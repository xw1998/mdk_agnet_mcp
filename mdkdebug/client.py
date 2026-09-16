# -*- coding: utf-8 -*-
"""
UVClient：高层封装 Keil UVSOCK 调试能力，并内置“连接缓存 + 空闲自动断开”。

连接策略（服务 + 缓存）：
- 首次调用时建立 TCP 连接；
- 后续调用若距上次使用未超过 idle_timeout，则复用连接；
- 超过 idle_timeout 未使用，或遇到连接已失效，则断开后重连；
- 显式 close() 立即断开。
线程安全：通过 threading.Lock 保护连接状态，可被 MCP 并发调用。
"""

from __future__ import annotations

import logging
import struct
import threading
import time

from . import uvsock
from .interface import UVInterface
from .uvsock import (
    UVSOCK_CMD, UV_STATUS_SUCCESS, UV_STATUS_TEXT, status_text, UVError, UVStatusError,
)

logger = logging.getLogger("mdkdebug.client")

# 允许单次读内存的最大分块（Keil 协议限制）
MAX_CHUNK = 16384


# UVSOCK 开启指引：连接失败时提示用户如何在 Keil 中开启 UVSOCK 插件
UVSOCK_HINT = (
    "请在 Keil uVision 中开启 UVSOCK：菜单 Edit → Configuration... → 切到 Other 选项卡 → "
    "勾选 UVSOCK Enabled → 确认端口为 4823 → 点 OK，然后重启 Keil 使设置生效，再重新调用本工具。"
)

class UVSOCKConnectError(UVError):
    """无法连接 Keil UVSOCK 服务（通常因 UVSOCK 插件未开启）。"""
    def __init__(self, host: str, port: int, cause: Exception):
        super().__init__(
            f"无法连接 Keil UVSOCK 服务（{host}:{port}）：{cause}。{UVSOCK_HINT}"
        )

class UVClient:
    """线程安全的 UVSOCK 调试客户端（含连接缓存）。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 4823,
                 idle_timeout: float = 30.0):
        self.host = host
        self.port = port
        self.idle_timeout = idle_timeout  # 秒，空闲超过则断开
        self._lock = threading.Lock()
        self._last_used = 0.0
        self.phy = UVInterface(host=host, port=port)

    # ------------------------------------------------------------------
    # 连接生命周期
    # ------------------------------------------------------------------
    def _ensure_connected(self) -> None:
        now = time.monotonic()
        if self.phy.is_connected:
            if now - self._last_used <= self.idle_timeout:
                return
            # 空闲超时，断开以便重连
            logger.info("连接空闲超过 %.1fs，断开重连", self.idle_timeout)
            self.phy.close()
        try:
            self.phy.open()
        except OSError as e:  # 连接被拒/超时：UVSOCK 未开启
            raise UVSOCKConnectError(self.host, self.port, e) from e
        self._last_used = now

    def _request(self, cmd_code: int, data: bytes = b'',
                 expect_status: bool = True):
        """加锁执行一次命令，返回 (r_status, 响应数据解析结果)。"""
        with self._lock:
            self._ensure_connected()
            uv = UVSOCK_CMD(cmd_code, data=data)
            raw = self.phy.send(uv.pack())
            self._last_used = time.monotonic()
            if raw is None:
                # 连接可能已失效，尝试重连一次
                self.phy.close()
                raise UVStatusError(uvsock.UV_STATUS_TIMEOUT,
                                    f"cmd=0x{cmd_code:04X}")
            resp = uv.unpack(raw)
            # resp = (totalLen, eCmd, bufLen, cycles, tStamp, id, r_cmd, r_status, data)
            return resp[7], resp[8]

    def close(self) -> None:
        with self._lock:
            self.phy.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 状态 / 版本
    # ------------------------------------------------------------------
    def get_version(self) -> dict:
        status, m_data = self._request(uvsock.UV_GEN_GET_VERSION)
        version = m_data.hex()
        return {"status": status, "ok": status == UV_STATUS_SUCCESS,
                "version_hex": version,
                "status_text": status_text(status)}

    def get_status(self) -> dict:
        """查询调试状态。

        真实 Keil 的 UV_DBG_STATUS 响应：r_status 恒为 0，真正的运行状态在响应
        data 的低字节（1=执行中，0=已停止）；mock 则直接用 r_status 表示状态。
        因此优先从 data 解析，data 为空时回退到 r_status。
        """
        status, m_data = self._request(uvsock.UV_DBG_STATUS)
        # 仅当 r_status 为成功时，data 低字节才表示运行状态（真实 Keil）
        if status == uvsock.UV_STATUS_SUCCESS:
            state = m_data[0] if len(m_data) >= 1 else None
            if state is not None:
                running = (state == 1)
                if state == 0:
                    st = "已停止"
                elif state == 1:
                    st = "执行中"
                else:
                    st = f"运行状态码({state})"
                return {
                    "ok": True, "status": status,
                    "status_text": "执行中" if running else "已停止",
                    "running": running, "debugging": True,
                    "state": state, "state_text": st,
                    "data": m_data.hex() if m_data else "",
                    "note": "state 为 UV_DBG_STATUS 响应 data 低字节：0=已停止,1=执行中；"
                            "running/debugging/state_text 已据此解码，无需再人工看裸 hex。",
                }
        # 非成功 / 兼容 mock：按 r_status 直接判断运行状态
        running = status in (uvsock.DBG_EXECUTING,
                             uvsock.UV_STATUS_TARGET_EXECUTING,
                             uvsock.UV_STATUS_DEBUGGING)
        if status == uvsock.DBG_EXECUTING:
            text, debugging = "执行中", True
        elif status in (uvsock.DBG_STOPPED, uvsock.UV_STATUS_TARGET_STOPPED):
            text, debugging = "已停止", True
        elif status == uvsock.UV_STATUS_NOT_DEBUGGING:
            text, debugging = "未处于调试状态", False
        else:
            text, debugging = status_text(status), False
        return {
            "ok": True, "status": status,
            "status_text": text,
            "running": running, "debugging": debugging,
            "data": m_data.hex() if m_data else "",
        }

    # ------------------------------------------------------------------
    # 表达式 / 变量
    # ------------------------------------------------------------------
    def calc_expression(self, expr: str) -> dict:
        """读取/计算调试表达式（变量、寄存器、指针解引用等）。"""
        from .uvsock import VSET
        ve = VSET()
        data = ve.pack(expr)
        status, m_data = self._request(uvsock.UV_DBG_CALC_EXPRESSION, data=data)
        if status != UV_STATUS_SUCCESS:
            return {"status": status, "ok": False,
                    "status_text": status_text(status)}
        val_type, val, name = ve.unpack(m_data)
        type_name = uvsock.VTT_TYPE_NAME.get(val_type, f"type_{val_type}")
        return {
            "status": status, "ok": True,
            "expression": expr,
            "value_type": type_name,
            "value": val,
            "value_raw": name,
        }

    def read_variable(self, name: str, count: int = 0,
                     read_memory: bool = True) -> dict:
        """按变量名查询其地址与内容（值），支持数组等类型。

        用 `&name` 取地址、`name` 取值，并尝试 `sizeof(name)` 获取字节大小。
        - count>0：按数组读取 `name[0..count-1]`，返回各元素值（便于查看数组内容）；
        - read_memory：结合基地址与 sizeof，用 read_mem 读出变量所在连续内存
          （十六进制 + ASCII），覆盖结构体/大块数据查看。
        返回 {name, address, value, value_type, size_bytes, elements, memory_hex, ascii}。
        """
        name = name.strip()
        if not name:
            return {"ok": False, "name": "", "error": "变量名不能为空"}

        result: dict = {"ok": False, "name": name}

        # 地址：&name
        addr_r = self.calc_expression(f"&{name}")
        address = addr_r.get("value") if addr_r.get("ok") else None
        if addr_r.get("ok"):
            result["address"] = hex(address) if isinstance(address, int) else address

        # 值：name
        val_r = self.calc_expression(name)
        if val_r.get("ok"):
            result["value"] = val_r.get("value")
            result["value_type"] = val_r.get("value_type")
            result["value_raw"] = val_r.get("value_raw")

        # 大小：sizeof(name)（尝试，失败忽略）
        sz_r = self.calc_expression(f"sizeof({name})")
        size_bytes = sz_r.get("value") if sz_r.get("ok") else None
        if size_bytes is not None and isinstance(size_bytes, int):
            result["size_bytes"] = size_bytes

        # 数组元素：count>0 时逐个读 name[i]
        if count and count > 0:
            elements = []
            for i in range(count):
                e = self.calc_expression(f"{name}[{i}]")
                if e.get("ok"):
                    elements.append({"index": i, "value": e.get("value"),
                                     "value_type": e.get("value_type")})
                else:
                    elements.append({"index": i, "error": "读取失败"})
                    break
            result["elements"] = elements

        # 读取变量内存（基地址 + 大小均可得时）
        if read_memory and isinstance(address, int) and size_bytes:
            cap = min(size_bytes, 16 * 1024)  # 防超长
            mem = self.read_mem(address, cap)
            if mem.get("ok"):
                result["memory_hex"] = mem.get("data_hex")
                result["ascii"] = mem.get("ascii")

        if not result.get("ok") and address is None and not val_r.get("ok"):
            return {
                "ok": False, "name": name,
                "message": "无法解析变量（变量不存在或未处于调试状态）",
                "detail": {"addr": addr_r, "value": val_r},
            }
        result["ok"] = True
        return result


    # ------------------------------------------------------------------
    # 内存读写
    # ------------------------------------------------------------------
    def read_mem(self, addr: int, n_bytes: int) -> dict:
        """读取指定地址的 n_bytes 内存（自动分块）。返回十六进制字节串。"""
        if n_bytes <= 0:
            return {"status": uvsock.UV_STATUS_OUT_OF_RANGE, "ok": False,
                    "status_text": "n_bytes 必须为正整数", "addr": addr,
                    "n_bytes": n_bytes, "data_hex": "", "ascii": ""}
        result = b""
        offset = 0
        while offset < n_bytes:
            chunk = min(MAX_CHUNK, n_bytes - offset)
            am = uvsock.AMEM()
            status, m_data = self._request(uvsock.UV_DBG_MEM_READ,
                                           data=am.pack_read(addr + offset, chunk))
            if status != UV_STATUS_SUCCESS:
                return {"status": status, "ok": False,
                        "status_text": status_text(status), "addr": addr,
                        "n_bytes": n_bytes, "data_hex": result.hex(),
                        "ascii": self._to_ascii(result)}
            nAddr, ErrAddr, nErr, payload = am.unpack(m_data)
            result += payload
            offset += chunk
        return {"status": UV_STATUS_SUCCESS, "ok": True, "addr": addr,
                "n_bytes": n_bytes, "data_hex": result.hex(),
                "ascii": self._to_ascii(result)}

    def write_mem(self, addr: int, data: bytes) -> dict:
        """向指定地址写入字节（自动分块，支持大块/批量填充）。返回实际写入长度。"""
        if not data:
            return {"status": uvsock.UV_STATUS_OUT_OF_RANGE, "ok": False,
                    "status_text": "data 不能为空", "addr": addr,
                    "written": 0}
        total = 0
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_CHUNK]
            am = uvsock.AMEM()
            status, m_data = self._request(uvsock.UV_DBG_MEM_WRITE,
                                           data=am.pack_write(addr + offset, chunk))
            if status != UV_STATUS_SUCCESS:
                return {"status": status, "ok": False,
                        "status_text": status_text(status), "addr": addr,
                        "requested": len(data), "written": total}
            total += len(chunk)
            offset += len(chunk)
        return {"status": UV_STATUS_SUCCESS, "ok": True, "addr": addr,
                "written": total}

    def search_mem(self, start: int, end: int, pattern: bytes,
                   max_results: int = 20) -> dict:
        """在 [start, end) 地址范围内扫描字节序列，返回所有命中偏移。

        分块读取并逐块查找；块间留 pattern-1 字节重叠，避免命中落在块边界被漏掉。
        用于找魔数、定位被越界写坏的缓冲、搜索特定数据结构等。
        """
        if end <= start:
            return {"ok": False, "error": "end 必须大于 start", "start": start,
                    "end": end}
        if not pattern:
            return {"ok": False, "error": "pattern 不能为空"}
        max_results = max(1, min(max_results, 1000))
        hits: list[int] = []
        pos = start
        overlap = max(0, len(pattern) - 1)
        step = max(1, MAX_CHUNK - overlap)
        while pos < end and len(hits) < max_results:
            n = min(MAX_CHUNK, end - pos)
            r = self.read_mem(pos, n)
            if not r.get("ok"):
                break
            try:
                data = bytes.fromhex("".join((r.get("data_hex") or "").split()))
            except ValueError:
                break
            idx = 0
            while True:
                i = data.find(pattern, idx)
                if i < 0:
                    break
                hits.append(pos + i)
                idx = i + 1
                if len(hits) >= max_results:
                    break
            pos += step
        return {
            "ok": True, "start": start, "end": end,
            "pattern_hex": pattern.hex(), "count": len(hits),
            "addresses": [hex(h) for h in hits],
            "truncated": len(hits) >= max_results,
        }

    def fill_mem(self, addr: int, byte: int, count: int) -> dict:
        """从 addr 起连续写入 count 个相同字节（批量填充/清零大块内存）。"""
        if not 0 <= byte <= 255:
            return {"ok": False, "error": "byte 须为 0~255 的单字节值", "byte": byte}
        if count <= 0:
            return {"ok": False, "error": "count 必须为正整数", "count": count}
        chunk = bytes([byte]) * min(count, MAX_CHUNK)
        written = 0
        while written < count:
            n = min(MAX_CHUNK, count - written)
            r = self.write_mem(addr + written, chunk[:n])
            if not r.get("ok"):
                return {"ok": False, "addr": addr, "byte": byte, "count": count,
                        "written": written, "error": r.get("status_text")}
            written += n
        return {"ok": True, "addr": addr, "byte": byte, "count": count,
                "written": written}

    # ------------------------------------------------------------------
    # 调试会话控制（进入/退出）
    # ------------------------------------------------------------------
    def enter_debug(self) -> dict:
        """进入调试模式（UV_DBG_ENTER）。受工程的 Load/Flash/Run-to-main 设置影响。"""
        return self._control(uvsock.UV_DBG_ENTER, "进入调试")

    def exit_debug(self) -> dict:
        """退出调试模式（UV_DBG_EXIT）。"""
        return self._control(uvsock.UV_DBG_EXIT, "退出调试")

    # ------------------------------------------------------------------
    # 断点管理（基于 Keil 命令窗口命令）
    # ------------------------------------------------------------------
    def exec_command(self, command: str) -> dict:
        """执行一条 Keil 命令窗口命令（BS/BK/BL/EVAL 等）。"""
        if any(c in command for c in "\r\n\0"):
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": "每次只能发送一条调试命令", "command": command}
        from .uvsock import EXECCMD
        status, m_data = self._request(uvsock.UV_DBG_EXEC_CMD,
                                       data=EXECCMD.pack(command))
        out = {"status": status, "ok": status == uvsock.UV_STATUS_SUCCESS,
               "status_text": status_text(status), "command": command}
        # 若响应带输出文本则附上
        if m_data:
            try:
                out["output"] = m_data.rstrip(b"\x00").decode("UTF-8", "replace")
            except Exception:
                out["output_hex"] = m_data.hex()
        return out

    def set_breakpoint(self, expr: str) -> dict:
        """在符号/地址处设置软件断点（命令窗口 BS）。"""
        return self.exec_command(f"BS {expr}")

    def clear_breakpoint(self, expr: str) -> dict:
        """清除断点（命令窗口 BK，可传符号名或断点编号）。"""
        return self.exec_command(f"BK {expr}")

    def list_breakpoints(self) -> dict:
        """列出当前所有断点（命令窗口 BL）。"""
        return self.exec_command("BL")

    def read_console_output(self, clear: bool = False) -> list:
        """读取 Keil 命令窗口输出缓存（UV_DBG_CMD_OUTPUT, 0x5020）。"""
        return self.phy.get_console_output(clear=clear)

    def read_async_messages(self, clear: bool = False) -> list:
        """读取 Keil 异步消息/报错缓存（UV_ASYNC_MSG, 0x4000）。"""
        return self.phy.get_async_messages(clear=clear)

    def read_cpu_registers(self) -> dict:
        """读取 CPU 核心寄存器 PC/LR/SP（R15/R14/R13）。多候选表达式以兼容不同 Keil 版本。"""
        candidates = {
            "pc": ("__currentPC()", "PC", "R15"),
            "lr": ("__currentLR()", "LR", "R14"),
            "sp": ("__currentSP()", "SP", "R13"),
        }
        regs = {}
        for name, exprs in candidates.items():
            for expr in exprs:
                try:
                    r = self.calc_expression(expr)
                except Exception:  # noqa: BLE001 单候选解析失败继续下一个
                    continue
                if r.get("ok") and isinstance(r.get("value"), int):
                    regs[name] = r["value"]
                    break
        if not regs:
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": "无法读取寄存器（未处于调试状态或表达式不可用）",
                    "registers": {}}
        out = {"status": uvsock.UV_STATUS_SUCCESS, "ok": True, "registers": regs}
        out.update(regs)
        return out

    def read_cpu_registers_stable(self, retries: int = 12, delay: float = 0.3) -> dict:
        """读取 CPU 寄存器并排除停止瞬间的脏 PC 值。

        Keil 在 run/step 到断点停止的瞬间，"PC" 表达式可能短暂返回脏值
        （实测为 1 或 SRAM 地址），需重试直到读到 FLASH 代码段地址才返回。
        最多重试 retries 次，期间每次间隔 delay 秒；若始终未读到合理值则返回最后一次结果。
        """
        last: dict = {}
        for _ in range(max(1, retries)):
            r = self.read_cpu_registers()
            last = r
            if not r.get("ok"):
                return r  # 读取本身失败（如未在调试态）立即返回，不重试
            pc = r.get("pc")
            if isinstance(pc, int):
                # 真实 PC 总指向 FLASH 代码段；SRAM 地址是脏值（可能读到 SP/栈内容）
                in_flash = 0x08000000 <= pc <= 0x081FFFFF
                if pc not in (0, 1) and in_flash:
                    return r
            time.sleep(delay)
        return last

    # ------------------------------------------------------------------
    # 运行控制
    # ------------------------------------------------------------------
    def run(self) -> dict:
        return self._control(uvsock.UV_DBG_START_EXECUTION, "运行")

    def stop(self) -> dict:
        return self._control(uvsock.UV_DBG_STOP_EXECUTION, "暂停")

    def reset(self) -> dict:
        return self._control(uvsock.UV_DBG_RESET, "复位")

    def step(self, mode: str = "into") -> dict:
        mode = (mode or "into").lower()
        cmd_map = {
            "into": uvsock.UV_DBG_STEP_INTO,
            "instruction": uvsock.UV_DBG_STEP_INSTRUCTION,
            "over": uvsock.UV_DBG_STEP_HLL,
            "out": uvsock.UV_DBG_STEP_OUT,
        }
        if mode not in cmd_map:
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": f"不支持的 step 模式: {mode}",
                    "mode": mode}
        return self._control(cmd_map[mode], f"单步({mode})", extra={"mode": mode})

    def _control(self, cmd_code: int, label: str, extra: dict | None = None) -> dict:
        status, m_data = self._request(cmd_code)
        out = {"status": status, "ok": status == UV_STATUS_SUCCESS,
               "status_text": status_text(status), "action": label}
        if extra:
            out.update(extra)
        return out

    # ------------------------------------------------------------------
    # 串口 / ITM（Instrumentation Trace Macrocell）数据读写
    # ------------------------------------------------------------------
    def serial_get(self, port: int = 0, size: int = 4096) -> dict:
        """从 Keil 串口窗口读取数据（含 Debug(printf) Viewer / ITM 输出）。

        经 UV_DBG_SERIAL_GET(0x2011) 拉取指定串口窗口当前缓冲内容。
        port: 串口窗口编号（Keil 的 Serial Windows 序号，通常 0=UART#1，
              Debug(printf) Viewer 对应其中一个编号）；size: 最多读取字节数。
        返回 {ok, port, size, data_hex, ascii}。

        注意：真实 ITM 输出需 Keil 已配置 Trace（Core Clock + Stimulus Port0）
        且调试器 SWO 引脚已使能，否则读到的缓冲可能为空。
        """
        if size <= 0 or size > 65536:
            return {"ok": False, "error": "size 需在 1~65536 之间", "size": size}
        # 请求 data = 目标串口窗口号(4B 小端) + 期望字节数(4B 小端)
        data = struct.pack('<II', port & 0xFFFFFFFF, size)
        status, m_data = self._request(uvsock.UV_DBG_SERIAL_GET, data=data)
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS,
               "status": status, "status_text": status_text(status),
               "port": port, "size": size,
               "data_hex": m_data.hex(), "ascii": self._to_ascii(m_data)}
        if status != uvsock.UV_STATUS_SUCCESS:
            out["data_hex"] = ""
            out["ascii"] = ""
        return out

    def serial_put(self, port: int = 0, data: bytes = b'') -> dict:
        """向 Keil 串口窗口写入数据（向目标仿真串口 / ITM 输入通道下发）。

        经 UV_DBG_SERIAL_PUT(0x2012) 将字节写入指定串口窗口。
        port: 串口窗口编号；data: 要写入的原始字节。
        返回 {ok, port, written}。
        """
        if not data:
            return {"ok": False, "error": "data 不能为空", "port": port}
        if len(data) > 65536:
            return {"ok": False, "error": "data 过长(>65536)", "port": port}
        req = struct.pack('<I', port & 0xFFFFFFFF) + data
        status, m_data = self._request(uvsock.UV_DBG_SERIAL_PUT, data=req)
        return {"ok": status == uvsock.UV_STATUS_SUCCESS,
                "status": status, "status_text": status_text(status),
                "port": port, "written": len(data)}

    # ------------------------------------------------------------------
    # target / 工程多目标
    # ------------------------------------------------------------------
    def _prj_text(self, cmd_code: int, data: bytes = b'', label: str = "") -> dict:
        """发送一条 UV_PRJ_* 命令，把响应 data 解码为文本返回（UTF-8 优先，GBK 回退）。

        真实 Keil 的 UV_PRJ_* 文本响应为“4字节小端长度头 + 字符串”格式，解析前先跳过头。
        """
        status, m_data = self._request(cmd_code, data=data)
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS, "status": status,
               "status_text": status_text(status), "command": label,
               "data_hex": m_data.hex()}
        if status == uvsock.UV_STATUS_SUCCESS and m_data:
            payload = m_data
            if len(payload) >= 4:
                ln = struct.unpack('<I', payload[:4])[0]
                if 0 < ln <= len(payload) - 4:
                    payload = payload[4:4 + ln]
            txt = None
            for enc in ("utf-8", "gbk", "latin-1"):
                try:
                    t = payload.decode(enc).rstrip("\x00").strip()
                    if t:
                        txt = t
                        break
                except (UnicodeDecodeError, ValueError):
                    continue
            out["text"] = txt if txt is not None else ""
        return out

    def get_cur_target(self) -> dict:
        """查询当前工程当前 target 名（UV_PRJ_GET_CUR_TARGET 0x1017）。"""
        r = self._prj_text(uvsock.UV_PRJ_GET_CUR_TARGET, label="get_cur_target")
        if r.get("ok"):
            r["target"] = r.get("text", "")
        return r

    def enum_targets(self) -> dict:
        """枚举当前工程所有 target（UV_PRJ_ENUM_TARGETS 0x1015）。"""
        r = self._prj_text(uvsock.UV_PRJ_ENUM_TARGETS, label="enum_targets")
        if r.get("ok") and r.get("text"):
            lines = [ln.strip() for ln in r["text"].splitlines() if ln.strip()]
            r["targets"] = lines
        return r

    def get_debug_target(self) -> dict:
        """查询当前调试 target（UV_PRJ_GET_DEBUG_TARGET 0x100B）。"""
        r = self._prj_text(uvsock.UV_PRJ_GET_DEBUG_TARGET, label="get_debug_target")
        if r.get("ok"):
            r["target"] = r.get("text", "")
        return r

    def set_debug_target(self, target: str) -> dict:
        """设置调试 target（UV_PRJ_SET_DEBUG_TARGET 0x100C）。target 为 target 名或索引。"""
        from .uvsock import VSET
        ve = VSET()
        status, m_data = self._request(uvsock.UV_PRJ_SET_DEBUG_TARGET, data=ve.pack(target))
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS, "status": status,
               "status_text": status_text(status), "target": target,
               "data_hex": m_data.hex()}
        if status == uvsock.UV_STATUS_SUCCESS:
            txt = m_data.decode("utf-8", "replace").rstrip("\x00").strip()
            out["text"] = txt
        return out

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def _to_ascii(data: bytes) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
