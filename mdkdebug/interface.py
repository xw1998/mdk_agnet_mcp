# -*- coding: utf-8 -*-
"""UVSOCK 的 TCP 物理接口层：建立 socket 连接并收发命令帧。"""

from __future__ import annotations

import socket
import struct
import time
import logging

from .uvsock import UVError

logger = logging.getLogger("mdkdebug.interface")


class UVInterface:
    """与 Keil UVSOCK 调试插件之间的 TCP 连接。"""

    MAX_RECV = 65536        # 单次 recv 最大字节数
    TIMEOUT_UNIT = 0.1      # socket 超时（秒）
    TIMEOUT_COUNTS = 100    # 允许的最大超时次数

    def __init__(self, host: str = "127.0.0.1", port: int = 4823):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.recv_buf = b""

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
        非阻塞清空 socket 中堆积的异步消息。

        Keil UVSOCK 在目标运行时会持续向连接推送异步消息（回调、串口输出、
        状态事件等）。同步请求-响应客户端不消费这些消息，它们会堆积在 OS
        socket 缓冲中，导致下一次读响应时拿到的是残留异步帧而解析错位。
        因此在每次发送请求前先非阻塞读空这些残留。
        """
        if self.sock is None:
            return
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.sock.recv(self.MAX_RECV)
                except BlockingIOError:
                    break  # 已清空
                if not chunk:
                    break
        finally:
            self.sock.setblocking(True)

    def send(self, data: bytes) -> bytes | None:
        """发送已打包的命令，并阻塞接收完整响应帧（或 None，超时/异常）。"""
        self.recv_buf = b""
        if self.sock is None:
            raise UVError("连接未建立，请先 open()")
        self._drain_async()
        self.sock.sendall(data)
        return self.recv(ack=None)

    def recv(self, ack=None):
        """
        接收响应。依据帧头前 4 字节的 m_nTotalLen 确定整包长度后返回。
        超时累计超过上限则返回 None。
        """
        timeout_counts = 0
        while timeout_counts < self.TIMEOUT_COUNTS:
            try:
                chunk = self.sock.recv(self.MAX_RECV)
                if chunk:
                    self.recv_buf += chunk
                    timeout_counts = 0
                    if len(self.recv_buf) >= 4:
                        m_nTotalLen = struct.unpack('<I', self.recv_buf[:4])[0]
                        if len(self.recv_buf) >= m_nTotalLen:
                            return self.recv_buf
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
