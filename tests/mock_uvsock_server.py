# -*- coding: utf-8 -*-
"""
mock UVSOCK server —— 模拟 Keil uVision 的 UVSOCK 调试插件，用于脱离真实
Keil 环境做端到端联调测试。维护一块模拟内存和几个模拟变量。

用法:
    python -m tests.mock_uvsock_server [--port 4823]
"""
from __future__ import annotations

import argparse
import re
import socket
import struct
import threading

from mdkdebug import uvsock


class MockUVSOCKServer:
    """内存模拟的 UVSOCK 服务器。"""

    def __init__(self, host="127.0.0.1", port=4823):
        self.host = host
        self.port = port
        # 模拟 64KB SRAM（0x20000000 起）
        self.mem = bytearray(64 * 1024)
        # 模拟 FLASH 代码段（0x08000000 起，用于反汇编等）
        self.flash = bytearray(64 * 1024)
        # 预置一段真实 Thumb 指令（对应 PC 0x08000000 附近）：
        #   00 00   MOVS r0, r0
        #   01 1c   ADDS r1, r0, #0
        #   08 1c   ADDS r0, r1, #0
        #   ff e7   B .-2  (死循环)
        for i, b in enumerate(bytes.fromhex("00001c081cffe7")):
            self.flash[0x08000000 - 0x08000000 + i] = b
        # 预置一些 "变量" 所在内存：v0..v3 放在 0x20000000 起
        base = 0x20000000
        struct.pack_into('<i', self.mem, base - 0x20000000, 0x11223344)        # int
        struct.pack_into('<I', self.mem, base - 0x20000000 + 4, 0xDEADBEEF)   # uint
        struct.pack_into('<f', self.mem, base - 0x20000000 + 8, 3.14)          # float
        struct.pack_into('<H', self.mem, base - 0x20000000 + 12, 0xABCD)       # ushort
        # 数组示例：arr 为 8 个 uint32，位于 base+16，共 32 字节
        for i in range(8):
            struct.pack_into('<I', self.mem, base - 0x20000000 + 16 + i * 4, 10 + i * 10)
        self.var_table = {  # (vtype, addr, total_size, count, elem_size)
            "v0": (uvsock.VTT_int, base, 4, 1, 4),
            "v1": (uvsock.VTT_uint, base + 4, 4, 1, 4),
            "v2": (uvsock.VTT_float, base + 8, 4, 1, 4),
            "v3": (uvsock.VTT_ushort, base + 12, 2, 1, 2),
            "arr": (uvsock.VTT_uint, base + 16, 32, 8, 4),
        }
        # CPU 寄存器（供 read_registers / set_register），R0=返回值/首参，R1-R3=后续参数
        self.reg_map = {"__currentPC()": 0x8000DB4, "PC": 0x8000DB4, "R15": 0x8000DB4,
                        "__currentLR()": 0x8000DC4, "LR": 0x8000DC4, "R14": 0x8000DC4,
                        "__currentSP()": 0x2002FF00, "SP": 0x2002FF00, "R13": 0x2002FF00,
                        "MSP": 0x20000040, "PSP": 0x2002FF00,
                        "R0": 0x20000000, "R1": 0x0000002A, "R2": 0x00000001, "R3": 0x00000000,
                        "R4": 0xDEADBEEF, "R5": 0x00000007, "R6": 0x00000000, "R7": 0x00000000,
                        "R8": 0x00000000, "R9": 0x00000000, "R10": 0x00000000, "R11": 0x00000000,
                        "R12": 0x00000000, "xPSR": 0x21000000}
        # DWT/SCS 调试寄存器（供 dwt 周期计数器）
        self.dwt = {"demcr": 0, "ctrl": 0, "cyccnt": 0x1234}
        # SCB 异常寄存器（供 fault_report）：模拟 HardFault + FORCED + 除零
        self.scb = {"icsr": 0x3, "cfsr": 0x2000000, "hfsr": 0x40000000,
                    "mmfar": 0, "bfar": 0}
        # 外设寄存器内存（供 read_peripheral）：0x40000000 段与 0xE0000000 段
        self.periph = bytearray(0x100000)      # 0x40000000 - 0x400FFFFF
        self.sys = bytearray(0x20000)          # 0xE0000000 - 0xE001FFFF (SysTick/NVIC/SCB/...)
        self._init_periph_regs()
        # 在 0x20000040 预置一段异常栈帧（R0,R1,R2,R3,R12,LR,PC,xPSR 自低地址到高）
        fbase = 0x20000040 - 0x20000000
        for i, v in enumerate([0x11, 0x22, 0x33, 0x44, 0x55,
                               0x08000abc, 0x08000def, 0x21000000]):
            struct.pack_into('<I', self.mem, fbase + i * 4, v)
        self.running = False
        self.debugging = False
        self.breakpoints = []  # 断点符号/地址列表
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)
        self._thread = None

    def _init_periph_regs(self):
        """预置少量外设寄存器值，供 read_peripheral 联调。
        段内偏移 = 目标地址 - 段基址（0x40000000 / 0xE0000000）。"""
        def w32(buf, segbase, addr, val):
            struct.pack_into('<I', buf, addr - segbase, val & 0xFFFFFFFF)
        # RCC：AHB1ENR 使能 GPIOA/B，APB2ENR 使能 TIM1，APB1ENR 使能 TIM2
        w32(self.periph, 0x40000000, 0x40023800 + 0x30, 0x00000003)   # AHB1ENR
        w32(self.periph, 0x40000000, 0x40023800 + 0x44, 0x00000001)   # APB2ENR
        w32(self.periph, 0x40000000, 0x40023800 + 0x40, 0x00000001)   # APB1ENR
        # GPIOA：MODER 全为输出(0x55..)、ODR 高、IDR 低
        w32(self.periph, 0x40000000, 0x40020000 + 0x00, 0x55555555)   # MODER
        w32(self.periph, 0x40000000, 0x40020000 + 0x14, 0x0000FFFF)   # ODR
        w32(self.periph, 0x40000000, 0x40020000 + 0x10, 0x00000000)   # IDR
        # USART1：BRR、CR1=UE|TE|RE
        w32(self.periph, 0x40000000, 0x40011000 + 0x08, 0x00000111)   # BRR
        w32(self.periph, 0x40000000, 0x40011000 + 0x0C, 0x0000200D)   # CR1
        # TIM2：PSC=0x0F、ARR=0xFFFF、CNT=0x1000
        w32(self.periph, 0x40000000, 0x40000000 + 0x28, 0x0000000F)   # PSC
        w32(self.periph, 0x40000000, 0x40000000 + 0x2C, 0x0000FFFF)   # ARR
        w32(self.periph, 0x40000000, 0x40000000 + 0x24, 0x00001000)   # CNT
        # SCB：AIRCR 带 VECTKEY + PRIGROUP
        w32(self.sys, 0xE0000000, 0xE000ED00 + 0x0C, 0xFA050000)
        # SysTick：CTRL=ENABLE|CLKSOURCE、LOAD=0xFF、VAL=0x80
        w32(self.sys, 0xE0000000, 0xE000E010 + 0x00, 0x00000007)      # CTRL
        w32(self.sys, 0xE0000000, 0xE000E010 + 0x04, 0x000000FF)      # LOAD
        w32(self.sys, 0xE0000000, 0xE000E010 + 0x08, 0x00000080)      # VAL
        # DWT：CYCCNT 使能并跑一个值
        w32(self.sys, 0xE0000000, 0xE0001000 + 0x00, 0x00000001)      # CTRL
        w32(self.sys, 0xE0000000, 0xE0001000 + 0x04, 0x00001234)      # CYCCNT

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

        # 寄存器表达式（供 read_cpu_registers/get_current_location/snapshot 定位）
        # 先处理赋值表达式：R0 = <value>（供 set_register）
        am = re.match(r"^([A-Za-z_]\w*)\s*=\s*(-?\d+)$", name)
        if am:
            reg = am.group(1).upper()
            if reg in self.reg_map:
                self.reg_map[reg] = int(am.group(2))
                val = self.reg_map[reg]
                resp = struct.pack('<i', uvsock.VTT_uint) \
                    + struct.pack('<Q', val) \
                    + struct.pack('<i', len(name)) + name.encode()
                return uvsock.UV_STATUS_SUCCESS, resp
        if name in self.reg_map:
            val = self.reg_map[name]
            resp = struct.pack('<i', uvsock.VTT_uint) \
                + struct.pack('<Q', val) \
                + struct.pack('<i', len(name)) + name.encode()
            return uvsock.UV_STATUS_SUCCESS, resp

        # &name 取地址（供 read_variable）
        if name.startswith("&"):
            varname = name[1:]
            if varname not in self.var_table:
                return uvsock.UV_STATUS_PARSE_ERROR, b""
            _, addr, _size, _c, _es = self.var_table[varname]
            resp = struct.pack('<i', uvsock.VTT_uint)                 + struct.pack('<Q', addr)                 + struct.pack('<i', len(name)) + name.encode()
            return uvsock.UV_STATUS_SUCCESS, resp

        # sizeof(name) 返回字节大小
        m = re.match(r"sizeof\((\w+)\)", name)
        if m:
            varname = m.group(1)
            if varname not in self.var_table:
                return uvsock.UV_STATUS_PARSE_ERROR, b""
            _vt, _a, size, _c, _es = self.var_table[varname]
            resp = struct.pack('<i', uvsock.VTT_uint)                 + struct.pack('<Q', size)                 + struct.pack('<i', len(name)) + name.encode()
            return uvsock.UV_STATUS_SUCCESS, resp

        # name[i] 数组元素
        m = re.match(r"(\w+)\[(\d+)\]", name)
        if m:
            varname, idx = m.group(1), int(m.group(2))
            if varname not in self.var_table:
                return uvsock.UV_STATUS_PARSE_ERROR, b""
            vtype, addr, _size, count, es = self.var_table[varname]
            if idx < 0 or idx >= count:
                return uvsock.UV_STATUS_PARSE_ERROR, b""
            off = addr - 0x20000000 + idx * es
            code = uvsock.VTT_TYPE_MAP[vtype]
            val = struct.unpack_from(f'<{code}', self.mem, off)[0]
            val_size = struct.calcsize(f'<{code}')
            union = struct.pack(f'<{code}', val) + b'\x00' * (8 - val_size)
            resp = struct.pack('<i', vtype) + union \
                + struct.pack('<i', len(name)) + name.encode()
            return uvsock.UV_STATUS_SUCCESS, resp

        if name not in self.var_table:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        vtype, addr, _size, _c, _es = self.var_table[name]
        off = addr - 0x20000000
        code = uvsock.VTT_TYPE_MAP[vtype]
        val = struct.unpack_from(f'<{code}', self.mem, off)[0]
        val_size = struct.calcsize(f'<{code}')
        union = struct.pack(f'<{code}', val) + b'\x00' * (8 - val_size)
        resp = struct.pack('<i', vtype) + union \
            + struct.pack('<i', len(name)) + name.encode()
        return uvsock.UV_STATUS_SUCCESS, resp

    def _mem_read(self, data):
        nAddr, nBytes = struct.unpack('<QI', data[:12])
        payload = b""
        if 0x20000000 <= nAddr < 0x20000000 + len(self.mem):
            off = nAddr - 0x20000000
            payload = bytes(self.mem[off:off + nBytes])
        elif 0x08000000 <= nAddr < 0x08000000 + len(self.flash):
            off = nAddr - 0x08000000
            payload = bytes(self.flash[off:off + nBytes])
        elif nAddr in (0xE000EDFC, 0xE0001000, 0xE0001004):  # DWT/SCS 调试寄存器
            key = {0xE000EDFC: "demcr", 0xE0001000: "ctrl", 0xE0001004: "cyccnt"}[nAddr]
            payload = struct.pack('<I', self.dwt[key] & 0xFFFFFFFF)
        elif nAddr in (0xE000ED04, 0xE000ED28, 0xE000ED2C, 0xE000ED34, 0xE000ED38):  # SCB 异常寄存器
            key = {0xE000ED04: "icsr", 0xE000ED28: "cfsr", 0xE000ED2C: "hfsr",
                   0xE000ED34: "mmfar", 0xE000ED38: "bfar"}[nAddr]
            payload = struct.pack('<I', self.scb[key] & 0xFFFFFFFF)
        elif 0x40000000 <= nAddr < 0x40000000 + len(self.periph):  # 外设段
            off = nAddr - 0x40000000
            payload = bytes(self.periph[off:off + nBytes])
        elif 0xE0000000 <= nAddr < 0xE0000000 + len(self.sys):  # 系统外设段
            off = nAddr - 0xE0000000
            payload = bytes(self.sys[off:off + nBytes])
        if not payload:
            return uvsock.UV_STATUS_NO_MEM_ACCESS, b""
        resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0) + payload
        return uvsock.UV_STATUS_SUCCESS, resp

    def _mem_write(self, data):
        nAddr, nBytes, ErrAddr, nErr = struct.unpack('<QIQI', data[:24])
        payload = data[24:24 + nBytes]
        if nAddr in (0xE000EDFC, 0xE0001000, 0xE0001004):  # DWT/SCS 调试寄存器
            key = {0xE000EDFC: "demcr", 0xE0001000: "ctrl", 0xE0001004: "cyccnt"}[nAddr]
            self.dwt[key] = struct.unpack('<I', payload[:4])[0]
            resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
            return uvsock.UV_STATUS_SUCCESS, resp
        if 0x40000000 <= nAddr < 0x40000000 + len(self.periph):
            self.periph[nAddr - 0x40000000: nAddr - 0x40000000 + len(payload)] = payload
            resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
            return uvsock.UV_STATUS_SUCCESS, resp
        if 0xE0000000 <= nAddr < 0xE0000000 + len(self.sys):
            self.sys[nAddr - 0xE0000000: nAddr - 0xE0000000 + len(payload)] = payload
            resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
            return uvsock.UV_STATUS_SUCCESS, resp
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
