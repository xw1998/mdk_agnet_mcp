# -*- coding: utf-8 -*-
"""UVSOCK 的 TCP 物理接口层：建立 socket 连接并收发命令帧。"""

from __future__ import annotations

import socket
import struct
import time
import logging

from .uvsock import (UVError, UV_DBG_CMD_OUTPUT, UV_ASYNC_MSG, UV_DBG_CALLBACK,
                     _HEADER_SIZE)

# 异步推送命令码：读取响应时遇到这些帧缓存到 console_log/async_log，而非当响应返回
_ASYNC_CMDS = frozenset((UV_DBG_CMD_OUTPUT, UV_ASYNC_MSG, UV_DBG_CALLBACK))

logger = logging.getLogger("mdkdebug.interface")


class UVInterface:
    """与 Keil UVSOCK 调试插件之间的 TCP 连接。"""

    MAX_RECV = 65536        # 单次 recv 最大字节数
    TIMEOUT_UNIT = 0.1      # socket 超时（秒）
    TIMEOUT_COUNTS = 100    # 允许的最大超时次数
    MAX_STALE_FRAMES = 64   # 响应配对时最多丢弃的陈旧响应帧数（防死等）

    def __init__(self, host: str = "127.0.0.1", port: int = 4823):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.recv_buf = b""
        self.console_log: list = []  # 命令窗口输出缓存（0x5020）
        self.async_log: list = []    # 异步消息/报错缓存（0x4000）"

    # ---- 连接管理 ----
    def open(self) -> None:
        if self.sock is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.TIMEOUT_UNIT)
        s.connect((self.host, self.port))
        self.sock = s
        self.recv_buf = b""
        logger.info("已连接到 UVSOCK @ %s:%d", self.host, self.port)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.recv_buf = b""

    @property
    def is_connected(self) -> bool:
        return self.sock is not None

    # ---- 收发 ----
    def _drain_async(self) -> None:
        """
        非阻塞读取 socket 中堆积的异步消息并解析缓存（命令输出/报错闭环）。

        Keil UVSOCK 在目标运行或执行命令时会推送异步消息：命令输出(0x5020)、
        异步状态/报错(0x4000)。这些消息堆积在 OS socket 缓冲中，若不消费会导致
        下次读响应错位。本方法把堆积的异步帧解析后按类型缓存到 console_log /
        async_log，供 read_console_output / read_async_messages 读取，实现
        command 窗口调试输出与报错信息的闭环。非异步残留帧忽略。
        """
        if self.sock is None:
            return
        self.sock.setblocking(False)
        pending = b""
        try:
            while True:
                try:
                    chunk = self.sock.recv(self.MAX_RECV)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                pending += chunk
        finally:
            self.sock.setblocking(True)
        self._parse_frames(pending)

    def _parse_frames(self, buf: bytes) -> None:
        """按帧长切分字节流，识别并缓存命令输出(0x5020)/异步消息(0x4000)。"""
        off = 0
        while off + _HEADER_SIZE <= len(buf):
            total = struct.unpack('<I', buf[off:off + 4])[0]
            if total < _HEADER_SIZE or off + total > len(buf):
                break
            ecmd = struct.unpack('<I', buf[off + 4:off + 8])[0]
            data = buf[off + _HEADER_SIZE:off + total]
            if ecmd == UV_DBG_CMD_OUTPUT:      # 0x5020 命令输出（SSTR）
                txt = self._decode_sstr(data)
                if txt is not None:
                    self.console_log.append({"type": "output", "text": txt})
            elif ecmd == UV_ASYNC_MSG:         # 0x4000 异步状态/报错
                m = self._parse_async(data)
                if m:
                    self.async_log.append(m)
            off += total

    @staticmethod
    def _decode_sstr(data: bytes):
        """解析 SSTR(nLen+str)：返回字符串或 None。"""
        if len(data) < 4:
            return None
        nlen = struct.unpack('<i', data[:4])[0]
        if nlen <= 0 or nlen > len(data) - 4:
            return None
        return data[4:4 + nlen].rstrip(b'\x00').decode('utf-8', 'replace')

    @staticmethod
    def _extract_text(raw: bytes) -> str:
        """提取字节流中可读文本（ASCII 可打印 + 多字节），忽略控制字节。"""
        parts = []
        cur = bytearray()
        for b in raw:
            if 32 <= b < 127 or b >= 0x80:
                cur.append(b)
            else:
                if cur:
                    parts.append(bytes(cur))
                    cur = bytearray()
        if cur:
            parts.append(bytes(cur))
        return "".join(p.decode('utf-8', 'replace') for p in parts)

    def _parse_async(self, data: bytes) -> dict:
        """解析 0x4000 异步消息：cmd_code(4)+status(4)+文本。"""
        cmd_code = struct.unpack('<I', data[:4])[0] if len(data) >= 4 else None
        status = struct.unpack('<i', data[4:8])[0] if len(data) >= 8 else None
        return {"type": "async", "cmd_code": cmd_code, "status": status,
                "text": self._extract_text(data[8:])}

    def get_console_output(self, clear: bool = False) -> list:
        """读取缓存的命令窗口输出（0x5020）。"""
        self._drain_async()
        out = list(self.console_log)
        if clear:
            self.console_log.clear()
        return out

    def get_async_messages(self, clear: bool = False) -> list:
        """读取缓存的异步消息/报错（0x4000）。"""
        self._drain_async()
        out = list(self.async_log)
        if clear:
            self.async_log.clear()
        return out

    def send(self, data: bytes, expect_cmd: int | None = None) -> bytes | None:
        """发送已打包的命令，并阻塞接收完整响应帧（或 None，超时/异常）。

        expect_cmd 传本次请求的命令码时，recv 会丢弃 r_cmd 不匹配的陈旧响应帧。
        真实 Keil 的响应队列可能残留历史请求的响应（跨会话/命令被拒后尤其明显），
        不做配对就会"拿到上一条命令的响应"，表现为读内存返回 status=6 或断点返回 22，
        但同一会话里的其他命令其实都正常。
        """
        if self.sock is None:
            raise UVError("连接未建立，请先 open()")
        self._drain_async()                 # 收集 socket 中堆积的异步帧
        self._parse_frames(self.recv_buf)   # 处理上次 recv 残留帧，缓存其中异步帧
        self.recv_buf = b""
        self.sock.sendall(data)
        return self.recv(ack=None, expect_cmd=expect_cmd)

    def recv(self, ack=None, expect_cmd: int | None = None):
        """
        接收响应。按帧切分字节流：异步推送帧（0x5020/0x4000/0x5002）解析缓存到
        console_log/async_log 后继续读；首个非异步的 UV_CMD_RESPONSE 响应帧返回。
        这样读响应时不会因混入异步帧而解析错位，命令输出/报错也能闭环读到。
        超时累计超过上限则返回 None。

        expect_cmd 非 None 时做"请求-响应"配对：响应帧头 r_cmd 必须等于请求命令码，
        不匹配的帧视为陈旧残留并丢弃（最多 MAX_STALE_FRAMES 个，避免死等）。
        真机实测 r_cmd 恒等于请求命令码（GET_VERSION/MEM_READ/STATUS/EXEC_CMD 等均一致，
        而 m_Id 不回显），故 r_cmd 是可靠的配对依据。
        """
        timeout_counts = 0
        stale = 0
        while timeout_counts < self.TIMEOUT_COUNTS:
            try:
                chunk = self.sock.recv(self.MAX_RECV)
                if chunk:
                    self.recv_buf += chunk
                    timeout_counts = 0
                    while len(self.recv_buf) >= 4:
                        m_nTotalLen = struct.unpack('<I', self.recv_buf[:4])[0]
                        if m_nTotalLen < _HEADER_SIZE or len(self.recv_buf) < m_nTotalLen:
                            break
                        frame = self.recv_buf[:m_nTotalLen]
                        self.recv_buf = self.recv_buf[m_nTotalLen:]
                        ecmd = struct.unpack('<I', frame[4:8])[0]
                        if ecmd in _ASYNC_CMDS:
                            self._parse_frames(frame)   # 缓存命令输出/报错
                            continue
                        if expect_cmd is not None and len(frame) >= 40:
                            r_cmd = struct.unpack('<I', frame[32:36])[0]
                            if r_cmd != expect_cmd:
                                stale += 1
                                if stale <= self.MAX_STALE_FRAMES:
                                    continue     # 陈旧/错位响应，丢弃继续等
                                logger.warning(
                                    "丢弃 %d 个不匹配响应帧后仍未等到 0x%04X 的响应，"
                                    "返回最后一个 r_cmd=0x%04X", stale, expect_cmd, r_cmd)
                            elif stale:
                                logger.info("跳过 %d 个陈旧响应帧后取到 0x%04X 的响应",
                                            stale, expect_cmd)
                        return frame                    # 响应帧
                    if ack is not None and ack in self.recv_buf:
                        return self.recv_buf
            except socket.timeout:
                timeout_counts += 1
                time.sleep(self.TIMEOUT_UNIT)
            except OSError:
                timeout_counts += 1
                time.sleep(self.TIMEOUT_UNIT)
        logger.error("等待 UVSOCK 响应超时（%s:%d）", self.host, self.port)
        return None
