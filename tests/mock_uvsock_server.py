# -*- coding: utf-8 -*-
"""
mock UVSOCK server —— 模拟 Keil uVision 的 UVSOCK 调试插件，用于脱离真实
Keil 环境做端到端联调测试。维护一块模拟内存和几个模拟变量。

用法:
    python -m tests.mock_uvsock_server [--port 4823]
"""
from __future__ import annotations

import argparse
import socket
import struct
import threading

from mdkdebug import uvsock


class MockUVSOCKServer:
    """内存模拟的 UVSOCK 服务器。"""

    def __init__(self, host="127.0.0.1", port=4823):
        self.host = host
        self.port = port
        # 模拟 64KB 内存
        self.mem = bytearray(64 * 1024)
        # 预置一些 "变量" 所在内存：v0..v3 放在 0x20000000 起
        base = 0x20000000
        struct.pack_into('<i', self.mem, base - 0x20000000, 0x11223344)        # int
        struct.pack_into('<I', self.mem, base - 0x20000000 + 4, 0xDEADBEEF)   # uint
        struct.pack_into('<f', self.mem, base - 0x20000000 + 8, 3.14)          # float
        struct.pack_into('<H', self.mem, base - 0x20000000 + 12, 0xABCD)       # ushort
        self.var_table = {
            "v0": (uvsock.VTT_int, base, 4),
            "v1": (uvsock.VTT_uint, base + 4, 4),
            "v2": (uvsock.VTT_float, base + 8, 4),
            "v3": (uvsock.VTT_ushort, base + 12, 2),
        }
        self.running = False
        self.debugging = False
        self.breakpoints = []  # 断点符号/地址列表
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(f"[mock] UVSOCK 模拟服务器监听 {self.host}:{self.port}")
        return self

    def stop(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    # ------------------------------------------------------------------
    def _handle(self, conn):
        buf = b""
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                buf += data
                while len(buf) >= 32:
                    total = struct.unpack('<I', buf[:4])[0]
                    if len(buf) < total:
                        break
                    frame = buf[:total]
                    buf = buf[total:]
                    self._process(conn, frame)
        except (OSError, ConnectionResetError):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _process(self, conn, frame):
        m_nTotalLen, cmd, nBufLen, cycles, tStamp, m_Id = \
            struct.unpack('<3IQdI', frame[:32])
        data = frame[32:]
        try:
            status, resp_data = self._dispatch(cmd, data)
        except Exception as e:  # noqa: BLE001
            status = uvsock.UV_STATUS_FAILED
            resp_data = b""
            print(f"[mock] 处理命令 0x{cmd:04X} 出错: {e}")
        conn.sendall(self._pack_response(cmd, status, resp_data))

    @staticmethod
    def _pack_response(cmd, status, resp_data):
        total = 32 + 8 + len(resp_data)
        header = struct.pack('<3IQdI', total, cmd, len(resp_data), 0, 0.0, 0)
        return header + struct.pack('<II', cmd, status) + resp_data

    # ------------------------------------------------------------------
    def _dispatch(self, cmd, data):
        """返回 (status, resp_data)。"""
        if cmd == uvsock.UV_GEN_GET_VERSION:
            return uvsock.UV_STATUS_SUCCESS, b"V5.2.0"

        if cmd == uvsock.UV_DBG_STATUS:
            st = (uvsock.UV_STATUS_TARGET_EXECUTING
                  if self.running else uvsock.UV_STATUS_TARGET_STOPPED)
            return st, b""

        if cmd == uvsock.UV_DBG_CALC_EXPRESSION:
            return self._calc_expression(data)

        if cmd == uvsock.UV_DBG_MEM_READ:
            return self._mem_read(data)

        if cmd == uvsock.UV_DBG_MEM_WRITE:
            return self._mem_write(data)

        if cmd in (uvsock.UV_DBG_START_EXECUTION, uvsock.UV_DBG_STOP_EXECUTION,
                   uvsock.UV_DBG_RESET, uvsock.UV_DBG_STEP_INTO,
                   uvsock.UV_DBG_STEP_HLL, uvsock.UV_DBG_STEP_INSTRUCTION,
                   uvsock.UV_DBG_STEP_OUT):
            if cmd == uvsock.UV_DBG_START_EXECUTION:
                self.running = True
            elif cmd == uvsock.UV_DBG_STOP_EXECUTION:
                self.running = False
            elif cmd == uvsock.UV_DBG_RESET:
                self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_ENTER:
            self.debugging = True
            self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_EXIT:
            self.debugging = False
            self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_EXEC_CMD:
            return self._exec_cmd(data)

        # 未知命令
        return uvsock.UV_STATUS_NOT_SUPPORTED, b""

    def _exec_cmd(self, data):
        """解析并执行命令窗口命令（BS/BK/BL）。data 为完整 EXECCMD 结构。"""
        # flags(4) + reserved(28) + SSTR{nLen(4) + char[256]}
        nlen = struct.unpack('<i', data[32:36])[0]
        cmd = data[36:36 + nlen].decode('UTF-8', 'replace').rstrip('\x00')
        parts = cmd.split()
        if not parts:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        op, rest = parts[0].upper(), parts[1:]
        if op == 'BS' and rest:
            if rest[0] not in self.breakpoints:
                self.breakpoints.append(rest[0])
            return uvsock.UV_STATUS_SUCCESS, b""
        if op == 'BK' and rest:
            if rest[0].isdigit() and int(rest[0]) < len(self.breakpoints):
                self.breakpoints.pop(int(rest[0]))
            elif rest[0] in self.breakpoints:
                self.breakpoints.remove(rest[0])
            return uvsock.UV_STATUS_SUCCESS, b""
        if op == 'BL':
            text = "\n".join(
                f"{i}: {bp}" for i, bp in enumerate(self.breakpoints)) or ""
            return uvsock.UV_STATUS_SUCCESS, text.encode('UTF-8') + b"\x00"
        if op == 'EVAL' and rest:
            # 简单返回变量值（若命中预置变量）
            return uvsock.UV_STATUS_SUCCESS, b""
        return uvsock.UV_STATUS_PARSE_ERROR, b""

    # ---- 具体处理 ----
    def _calc_expression(self, data):
        # 解析 VSET：vType(4) + union(8) + nLen(4) + str
        nlen = struct.unpack('<i', data[12:16])[0]
        name = data[16:16 + nlen].decode("UTF-8", "replace").rstrip('\x00')
        # 支持 &name 取地址（供 read_variable 用）
        if name.startswith("&"):
            varname = name[1:]
            if varname not in self.var_table:
                return uvsock.UV_STATUS_PARSE_ERROR, b""
            _, addr, _size = self.var_table[varname]
            resp = struct.pack('<i', uvsock.VTT_uint) \
                + struct.pack('<Q', addr) \
                + struct.pack('<i', len(name)) + name.encode()
            return uvsock.UV_STATUS_SUCCESS, resp
        if name not in self.var_table:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        vtype, addr, size = self.var_table[name]
        off = addr - 0x20000000
        code = uvsock.VTT_TYPE_MAP[vtype]
        val = struct.unpack_from(f'<{code}', self.mem, off)[0]
        # 返回 VSET：vType(4) + union(8) + nLen(4) + name
        # union 8 字节按类型打包到前 val_size，其余补零
        val_size = struct.calcsize(f'<{code}')
        union = struct.pack(f'<{code}', val) + b'\x00' * (8 - val_size)
        resp = struct.pack('<i', vtype) + union \
            + struct.pack('<i', len(name)) + name.encode()
        return uvsock.UV_STATUS_SUCCESS, resp

    def _mem_read(self, data):
        nAddr, nBytes = struct.unpack('<QI', data[:12])
        off = nAddr - 0x20000000
        if off < 0 or off + nBytes > len(self.mem):
            return uvsock.UV_STATUS_NO_MEM_ACCESS, b""
        payload = bytes(self.mem[off:off + nBytes])
        resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0) + payload
        return uvsock.UV_STATUS_SUCCESS, resp

    def _mem_write(self, data):
        nAddr, nBytes, ErrAddr, nErr = struct.unpack('<QIQI', data[:24])
        payload = data[24:24 + nBytes]
        off = nAddr - 0x20000000
        if off < 0 or off + len(payload) > len(self.mem):
            return uvsock.UV_STATUS_NO_MEM_ACCESS, b""
        self.mem[off:off + len(payload)] = payload
        resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
        return uvsock.UV_STATUS_SUCCESS, resp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4823)
    args = parser.parse_args()
    srv = MockUVSOCKServer(args.host, args.port)
    srv.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
