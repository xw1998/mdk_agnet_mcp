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
        # 模拟工程多 target（供 UV_PRJ_* target 命令）
        self.targets = ["mdk_test", "Debug", "Release"]
        self.cur_target = "mdk_test"
        self.debug_target = "mdk_test"
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
        self.pending_async = []  # 模拟 Keil 异步推送队列（0x5020 输出 / 0x4000 报错）
        # True 时模拟真实 Keil：目标处于运行状态时拒绝复位（status=11 UV_STATUS_TARGET_EXECUTING）
        self.reset_requires_stop = False
        self.reset_calls = 0
        # True 时模拟「stop 异步未生效」：命令有响应但目标仍在跑（用于验证脏 PC 防护）
        self.stop_ignores = False
        self.var_table = {  # (vtype, addr, total_size, count, elem_size)
            "v0": (uvsock.VTT_int, base, 4, 1, 4),
            "v1": (uvsock.VTT_uint, base + 4, 4, 1, 4),
            "v2": (uvsock.VTT_float, base + 8, 4, 1, 4),
            "v3": (uvsock.VTT_ushort, base + 12, 2, 1, 2),
            "arr": (uvsock.VTT_uint, base + 16, 32, 8, 4),
            "main": (uvsock.VTT_uint, 0x08000DB5, 4, 1, 4),  # 供 set_breakpoint 解析 &main
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
        # DBGMCU IDCODE（供 target_info）：DEV_ID=0x423(STM32F401)、REV_ID=0x0000
        self.idcode = 0x00000423
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
        # 批次23：「目标运行中、随后自动停在该 PC」钩子——供 wait_breakpoint 的
        # 「只认等待期间新发生的停止」测试用（确定性，不依赖 sleep 计时）。
        # auto_stop_reads 为还剩几次 STATUS 查询仍报运行态，之后转为停止并落到 auto_stop_pc。
        self.auto_stop_reads = None
        self.auto_stop_pc = None
        # 停止时置位的 DFSR 位（批次24）：模拟「数据观察点命中 → DWTTRAP(bit2) 置位」。
        # 例如 auto_stop_dfsr = 0x04 即表示这次停止是 DWT 比较器触发的。
        self.auto_stop_dfsr = None
        # 批次24：停止瞬间改写内存，模拟「数据观察点在等待期间被写」（值变化证据链路）。
        # 形如 [(addr, value_int, size_bytes), ...]
        self.auto_stop_writes = None
        # DFSR（0xE000ED30）：真实硬件为 W1C（写 1 清位），这里如实模拟。
        self.dfsr = 0
        # DWT 比较器比较地址（COMP0..3 @ 0xE0001020 + 0x10n），供观察点定位测试。
        self.dwt_comps = [0, 0, 0, 0]
        # --- 真机行为模拟钩子（供批次14 测试 A/B 修复）---
        # >0 时：每个请求的响应前先发 N 个 r_cmd 不匹配的陈旧响应帧（模拟真机响应队列残留）
        self.stale_frames = 0
        # >0 时：enter_debug 后仍需 N 次 STATUS 查询才报"已进入调试态"（模拟异步就绪）
        self.enter_ready_delay = 0
        self._enter_pending = 0
        # BS 命令返回码覆盖（真机成功时可能返回 22 BP_CREATED 而非 0）
        self.bs_status = None
        # True 时 BS 响应携带二进制 payload（模拟真机断点结构，考察 output 乱码处理）
        self.bs_binary_output = False
        # True 时对所有请求都不回响应（模拟命令超时 / Keil 被模态框阻塞）
        self.drop_responses = False
        # 处理完 N 个请求后强行断开连接（模拟 Keil 进程中途死掉，socket 被重置）
        self.drop_connection_after = 0
        self._req_count = 0
        # PC 取值队列：非空时每次读 PC 表达式依次取一个值（模拟 halt 后 PC 滞后一帧，
        # 首次读到上一轮 halt 的旧值、随后收敛）；队列空则沿用 reg_map 当前值
        self.pc_queue = []
        self.breakpoints = []  # 断点符号/地址列表
        # 命令窗口额外输出行（复现真机「UVSOCK 回成功、窗口里却是 *** error N」）
        self.exec_console_extra = []
        # 真机格式断点表（批次22）：非 None 时 BL 按真机格式输出并带 CNT，
        # 每条为 {"number", "kind": "exec"/"access", "access", "address", "length",
        #          "expr", "count", "enabled"}，供 wait_breakpoint 的 CNT 命中判定测试。
        self.bl_table = None
        # BL 被读取的次数（批次22）：配合 bl_bump_after_reads 模拟「等待期间断点命中」——
        # 基线读取看到旧 CNT，第 N 次读取后 CNT 自增，于是停止后的读取能看到增量。
        self.bl_reads = 0
        self.bl_bump_after_reads = []   # [(第几次读之后, 断点编号, 增量), ...]
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
        # ITM：DEMCR.TRCENA + ITM->TCR(ITMENA|TSENA|SWOENA|SYNCENA)
        #   + ITM->TER(Stimulus Port0 使能) + 一条预置 ITM 输出缓冲
        # 注意 DEMCR 同时被 self.dwt["demcr"] 分支接管（_mem_read 0xE000EDFC），需同步
        self.dwt["demcr"] = 0x01000000                              # DEMCR TRCENA
        w32(self.sys, 0xE0000000, 0xE0000E80 + 0x00, 0x00400783)      # ITM->TCR: ITMENA|TSENA|SWOENA|bits5-10
        w32(self.sys, 0xE0000000, 0xE0000E00 + 0x00, 0x00000001)      # ITM->TER port0
        # 串口窗口缓冲（模拟 Debug(printf) Viewer 收到的 ITM 输出）
        self.serial_buf = [bytearray(b'') for _ in range(4)]
        self.serial_buf[0] = bytearray(b'Hello from ITM port0!\r\nSysTick tick 100\r\n')

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

    # ---- 异步推送（模拟真实 Keil：先推命令输出/报错，再回命令响应）----
    def _push_console(self, text):
        """入队一条 0x5020 命令输出异步帧（SSTR 编码，含 NULL 结尾）。"""
        payload = struct.pack('<i', len(text) + 1) + text.encode("utf-8") + b"\x00"
        self.pending_async.append((uvsock.UV_DBG_CMD_OUTPUT, payload))

    def _push_async(self, cmd_code, status, text):
        """入队一条 0x4000 异步消息帧：cmd_code(4)+status(4)+文本。"""
        payload = struct.pack('<II', cmd_code, status) + text.encode("utf-8")
        self.pending_async.append((uvsock.UV_ASYNC_MSG, payload))

    @staticmethod
    def _pack_async(ecmd, payload):
        total = 32 + len(payload)
        header = struct.pack('<3IQdI', total, ecmd, len(payload), 0, 0.0, 0)
        return header + payload

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
        # 先推送积压的异步帧（命令输出/报错），再回命令响应，贴近真实 Keil
        for ecmd, payload in self.pending_async:
            conn.sendall(self._pack_async(ecmd, payload))
        self.pending_async.clear()
        if self.stale_frames:
            # 模拟真机：响应队列里残留了历史请求的响应（命令码完全不同）
            for _ in range(self.stale_frames):
                conn.sendall(self._pack_response(
                    0x7F01, uvsock.UV_STATUS_NOT_DEBUGGING, b""))
            self.stale_frames = 0
        if self.drop_responses:
            return          # 什么都不回，让调用方等到超时
        if self.drop_connection_after:
            self._req_count += 1
            if self._req_count >= self.drop_connection_after:
                self._req_count = 0
                self.drop_connection_after = 0
                conn.sendall(self._pack_response(cmd, status, resp_data))
                # SO_LINGER=0 + close => 发 RST，让对端立刻感知连接中断
                try:
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                    struct.pack('ii', 1, 0))
                except Exception:  # noqa: BLE001
                    pass
                conn.close()
                return
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
            if self._enter_pending > 0:
                # 模拟真实 Keil：enter_debug 是异步的，未就绪时 STATUS 返回
                # r_status=6 + "Target is not in debug mode"
                self._enter_pending -= 1
                if self._enter_pending == 0:
                    self.debugging = True
                body = b"Target is not in debug mode\x00"
                return uvsock.UV_STATUS_NOT_DEBUGGING, struct.pack('<i', len(body)) + body
            if self.running and self.auto_stop_reads is not None:
                if self.auto_stop_reads > 0:
                    self.auto_stop_reads -= 1
                else:
                    self.running = False
                    if self.auto_stop_pc is not None:
                        for _k in ("__currentPC()", "PC", "R15"):
                            self.reg_map[_k] = self.auto_stop_pc
                    if self.auto_stop_dfsr:
                        self.dfsr |= self.auto_stop_dfsr
                    if self.auto_stop_writes:
                        for _wa, _wv, _ws in self.auto_stop_writes:
                            _off = _wa - 0x20000000
                            if 0 <= _off and _off + _ws <= len(self.mem):
                                _fmt = {1: '<B', 2: '<H', 4: '<I'}.get(_ws, '<I')
                                try:
                                    struct.pack_into(_fmt, self.mem, _off, _wv)
                                except Exception:
                                    pass
                    self.auto_stop_reads = None
            # 模拟真实 Keil：r_status 恒为成功，运行状态在响应 data 低字节（0=停止,1=执行中）
            data = b"\x01" if self.running else b"\x00"
            return uvsock.UV_STATUS_SUCCESS, data

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
                # stop_ignores=True 模拟真实 Keil 的异步滞后：响应照回，但目标仍在运行
                if not self.stop_ignores:
                    self.running = False
            elif cmd == uvsock.UV_DBG_RESET:
                self.reset_calls += 1
                # 真实 Keil：目标运行中直接复位会被拒（status=11），需先 stop
                if self.running and self.reset_requires_stop:
                    return uvsock.UV_STATUS_TARGET_EXECUTING, b""
                self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_ENTER:
            if self.enter_ready_delay > 0:
                self.debugging = False
                self._enter_pending = self.enter_ready_delay
            else:
                self.debugging = True
            self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_EXIT:
            self.debugging = False
            self.running = False
            return uvsock.UV_STATUS_SUCCESS, b""

        if cmd == uvsock.UV_DBG_EXEC_CMD:
            return self._exec_cmd(data)

        if cmd == uvsock.UV_DBG_SERIAL_GET:
            return self._serial_get(data)

        if cmd == uvsock.UV_DBG_SERIAL_PUT:
            return self._serial_put(data)

        if cmd == uvsock.UV_PRJ_ENUM_TARGETS:
            return uvsock.UV_STATUS_SUCCESS, ("\n".join(self.targets)).encode("utf-8")
        if cmd == uvsock.UV_PRJ_GET_CUR_TARGET:
            return uvsock.UV_STATUS_SUCCESS, self.cur_target.encode("utf-8")
        if cmd == uvsock.UV_PRJ_GET_DEBUG_TARGET:
            return uvsock.UV_STATUS_SUCCESS, self.debug_target.encode("utf-8")
        if cmd == uvsock.UV_PRJ_SET_DEBUG_TARGET:
            # 请求 data 为 VSET 结构：vType(4)+union(8)+nLen(4)+str
            if len(data) >= 16:
                nlen = struct.unpack('<i', data[12:16])[0]
                name = data[16:16 + nlen].decode("UTF-8", "replace").rstrip('\x00')
            else:
                name = ""
            if name and name in self.targets:
                self.debug_target = name
                return uvsock.UV_STATUS_SUCCESS, name.encode("utf-8")
            return uvsock.UV_STATUS_NOT_FOUND, b""

        # 未知命令
        return uvsock.UV_STATUS_NOT_SUPPORTED, b""

    # ---- 真机格式断点表（批次22） ----

    def _render_bl_row(self, b):
        """按真机 BL 输出格式渲染一条断点（须能被 client._BP_LINE_RE 解析）。

        真机样例：
          0: (E 0x08000DB4) '..\\main.c\\77', CNT=1, enabled
          3: (A WR 0x20000000 len=1) '0x20000000', CNT=1, enabled
        """
        if (b.get("kind") or "exec") == "access":
            head = "A %s %s len=%s" % (b.get("access", "WR"), b.get("address", "0x0"),
                                       b.get("length", 1))
        else:
            head = "E %s" % (b.get("address", "0x0"),)
        return "%s: (%s) '%s', CNT=%s, %s" % (
            b.get("number", 0), head, b.get("expr", ""), b.get("count", 0),
            "enabled" if b.get("enabled", True) else "disabled")

    def bump_bp_count(self, number, delta=1):
        """模拟断点命中：把编号对应断点的 CNT 增加 delta。返回是否找到。"""
        for b in (self.bl_table or []):
            if b.get("number") == number:
                b["count"] = int(b.get("count") or 0) + delta
                return True
        return False

    def _exec_cmd(self, data):
        """解析并执行命令窗口命令（BS/BK/BL）。data 为完整 EXECCMD 结构。"""
        # flags(4) + reserved(28) + SSTR{nLen(4) + char[256]}
        nlen = struct.unpack('<i', data[32:36])[0]
        cmd = data[36:36 + nlen].decode('UTF-8', 'replace').rstrip('\x00')
        parts = cmd.split()
        if not parts:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        op, rest = parts[0].upper(), parts[1:]
        # 模拟真实 Keil：任何 EXEC_CMD 先回显命令名（0x5020 第一帧）
        self._push_console(cmd)
        for t in self.exec_console_extra:
            self._push_console(t)      # 窗口报错行（如 *** error 72: invalid item number）
            self._push_async(uvsock.UV_DBG_EXEC_CMD, uvsock.UV_STATUS_FAILED, t)
        if op == 'BS' and rest:
            if rest[0] not in self.breakpoints:
                self.breakpoints.append(rest[0])
            st = self.bs_status if self.bs_status is not None else uvsock.UV_STATUS_SUCCESS
            payload = b""
            if self.bs_binary_output:
                payload = (struct.pack('<IIII', 1, 1, 1, 1)
                           + (0x08000DB4).to_bytes(4, 'little') + (33).to_bytes(4, 'little')
                           + b"\\mdk_test\\../Core/Src/main.c")
            return st, payload
        if op == 'BK' and rest:
            if rest[0] == '*' and self.bl_table is not None:
                self.bl_table = []
                self.breakpoints = []
                return uvsock.UV_STATUS_SUCCESS, b""
            if self.bl_table is not None and rest[0].isdigit():
                n = int(rest[0])
                if not any(b.get("number") == n for b in self.bl_table):
                    # 真机：编号不存在时报 error（按地址清数据观察点即 error 72）
                    err = "*** error 72: invalid item number"
                    self._push_console(err)
                    self._push_async(uvsock.UV_DBG_EXEC_CMD, uvsock.UV_STATUS_FAILED, err)
                    return uvsock.UV_STATUS_SUCCESS, b""
                self.bl_table = [b for b in self.bl_table if b.get("number") != n]
                return uvsock.UV_STATUS_SUCCESS, b""
            if rest[0].isdigit() and int(rest[0]) < len(self.breakpoints):
                self.breakpoints.pop(int(rest[0]))
            elif rest[0] in self.breakpoints:
                self.breakpoints.remove(rest[0])
            return uvsock.UV_STATUS_SUCCESS, b""
        if op == 'BL':
            if self.bl_table is not None:
                # 先按「本次是第几次读」结算自增，再渲染，这样第 N 次读就能看到增量
                self.bl_reads += 1
                for item in list(self.bl_bump_after_reads):
                    after_n, num, delta = item
                    if self.bl_reads >= after_n:
                        self.bump_bp_count(num, delta)
                        self.bl_bump_after_reads.remove(item)
                for b in self.bl_table:
                    self._push_console(self._render_bl_row(b))   # 真机：每条断点一行
            else:
                for i, bp in enumerate(self.breakpoints):
                    self._push_console(f"{i}: {bp}")
            return uvsock.UV_STATUS_SUCCESS, b""
        if op == 'EVAL' and rest:
            name = rest[0]
            if name in self.var_table:
                _vt, addr, _s, _c, _es = self.var_table[name]
                self._push_console(f"{name} = 0x{addr:08X}")  # EVAL 结果作为命令输出
                return uvsock.UV_STATUS_SUCCESS, b""
            # 未定义标识符：模拟 Keil 报错（0x4000 异步消息）
            err = f"*** error 34: undefined identifier '{name}'"
            self._push_console(err)
            self._push_async(uvsock.UV_DBG_EXEC_CMD, uvsock.UV_STATUS_FAILED, err)
            return uvsock.UV_STATUS_SUCCESS, b""
        return uvsock.UV_STATUS_PARSE_ERROR, b""

    # ---- 串口 / ITM 缓冲 ----
    def _serial_get(self, data):
        """读取指定串口窗口缓冲。请求 data = port(4B 小端) + size(4B 小端)。"""
        if len(data) < 8:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        port, size = struct.unpack('<II', data[:8])
        if port >= len(self.serial_buf):
            return uvsock.UV_STATUS_NOT_FOUND, b""
        buf = self.serial_buf[port]
        return uvsock.UV_STATUS_SUCCESS, bytes(buf[:size])

    def _serial_put(self, data):
        """写入串口窗口缓冲（模拟向目标串口/ITM 输入通道下发）。
        请求 data = port(4B 小端) + 载荷字节。"""
        if len(data) < 5:
            return uvsock.UV_STATUS_PARSE_ERROR, b""
        port = struct.unpack('<I', data[:4])[0]
        if port >= len(self.serial_buf):
            return uvsock.UV_STATUS_NOT_FOUND, b""
        payload = data[4:]
        self.serial_buf[port].extend(payload)
        return uvsock.UV_STATUS_SUCCESS, b""

    # ---- 具体处理 ----
    def _calc_expression(self, data):
        # 解析 VSET：vType(4) + union(8) + nLen(4) + str
        nlen = struct.unpack('<i', data[12:16])[0]
        name = data[16:16 + nlen].decode("UTF-8", "replace").rstrip('\x00')

        if self.pc_queue and name in ("__currentPC()", "PC", "R15"):
            v = self.pc_queue.pop(0)
            for k in ("__currentPC()", "PC", "R15"):
                self.reg_map[k] = v

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
        elif nAddr == 0xE000ED30:  # DFSR（Debug Fault Status Register，W1C）
            payload = struct.pack('<I', self.dfsr & 0xFFFFFFFF)
        elif nAddr in (0xE0001020, 0xE0001030, 0xE0001040, 0xE0001050):  # DWT_COMP0..3
            _i = (nAddr - 0xE0001020) // 0x10
            payload = struct.pack('<I', self.dwt_comps[_i] & 0xFFFFFFFF)
        elif nAddr == 0xE0042000:  # DBGMCU->IDCODE（供 target_info）
            payload = struct.pack('<I', self.idcode & 0xFFFFFFFF)
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
        if nAddr == 0xE000ED30:  # DFSR：W1C，写 1 清位
            _val = struct.unpack('<I', payload[:4])[0]
            self.dfsr &= (~_val) & 0xFFFFFFFF
            resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
            return uvsock.UV_STATUS_SUCCESS, resp
        if nAddr in (0xE000ED28, 0xE000ED2C):  # CFSR / HFSR：同样是 W1C（真机行为）
            _k = {0xE000ED28: "cfsr", 0xE000ED2C: "hfsr"}[nAddr]
            _val = struct.unpack('<I', payload[:4])[0]
            self.scb[_k] &= (~_val) & 0xFFFFFFFF
            resp = struct.pack('<QIQI', nAddr, nBytes, 0, 0)
            return uvsock.UV_STATUS_SUCCESS, resp
        if nAddr in (0xE0001020, 0xE0001030, 0xE0001040, 0xE0001050):  # DWT_COMP0..3
            _i = (nAddr - 0xE0001020) // 0x10
            self.dwt_comps[_i] = struct.unpack('<I', payload[:4])[0]
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
