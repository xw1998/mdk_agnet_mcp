# -*- coding: utf-8 -*-
"""
UVSOCK 协议实现（用于与 Keil uVision 的 UVSOCK 调试插件通过 TCP 通信）。

协议参考自 KeilAssistant (keil-assistant)，命令帧结构如下:

    typedef struct _tag_UVSOCK_CMD {
        UINT      m_nTotalLen;  // 4 字节，整包长度（含本字段）
        UV_OP     m_eCmd;       // 4 字节，命令码
        UINT      m_nBufLen;    // 4 字节，数据区长度
        xU64      cycles;       // 8 字节，周期值（仅仿真模式）
        double    tStamp;       // 8 字节，时间戳（仅仿真模式）
        UINT      m_Id;         // 4 字节，保留
        BYTE      data[];       // 数据区（与命令码相关）
    } UVSOCK_CMD;
    头部固定 32 字节。

地址一律小端（little-endian）打包。
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# UV_OPERATION —— 命令码
# ---------------------------------------------------------------------------
UV_NULL_CMD = 0x0000
UV_GEN_GET_VERSION = 0x0001
UV_GEN_UI_UNLOCK = 0x0002
UV_GEN_UI_LOCK = 0x0003
UV_GEN_HIDE = 0x0004
UV_GEN_SHOW = 0x0005
UV_GEN_RESTORE = 0x0006
UV_GEN_MINIMIZE = 0x0007
UV_GEN_MAXIMIZE = 0x0008
UV_GEN_EXIT = 0x0009
UV_GEN_GET_EXTVERSION = 0x000A
UV_GEN_CHECK_LICENSE = 0x000B
UV_GEN_CPLX_COMPLETE = 0x000C
UV_GEN_SET_OPTIONS = 0x000D
UV_PRJ_LOAD = 0x1000
UV_PRJ_CLOSE = 0x1001
UV_PRJ_BUILD = 0x1006
UV_PRJ_REBUILD = 0x1007
UV_PRJ_CLEAN = 0x1008
UV_PRJ_BUILD_CANCEL = 0x1009
UV_PRJ_FLASH_DOWNLOAD = 0x100A
UV_PRJ_GET_DEBUG_TARGET = 0x100B
UV_PRJ_SET_DEBUG_TARGET = 0x100C
UV_PRJ_ENUM_GROUPS = 0x100F
UV_PRJ_ENUM_FILES = 0x1010
UV_PRJ_ENUM_TARGETS = 0x1015
UV_PRJ_GET_CUR_TARGET = 0x1017
UV_DBG_ENTER = 0x2000
UV_DBG_EXIT = 0x2001
UV_DBG_START_EXECUTION = 0x2002   # 全速运行
UV_DBG_RUN_TO_ADDRESS = 0x2102
UV_DBG_STOP_EXECUTION = 0x2003    # 暂停
UV_DBG_STATUS = 0x2004            # 查询目标/调试状态
UV_DBG_RESET = 0x2005             # 复位
UV_DBG_STEP_HLL = 0x2006
UV_DBG_STEP_INTO = 0x2007
UV_DBG_STEP_INSTRUCTION = 0x2008
UV_DBG_STEP_OUT = 0x2009
UV_DBG_CALC_EXPRESSION = 0x200A   # 计算表达式/读取变量
UV_DBG_MEM_READ = 0x200B          # 读内存
UV_DBG_MEM_WRITE = 0x200C         # 写内存
UV_DBG_TIME_INFO = 0x200D
UV_DBG_SET_CALLBACK = 0x200E
UV_DBG_VTR_GET = 0x200F
UV_DBG_VTR_SET = 0x2010
UV_DBG_SERIAL_GET = 0x2011
UV_DBG_SERIAL_PUT = 0x2012
UV_DBG_VERIFY_CODE = 0x2013
UV_DBG_CREATE_BP = 0x2014
UV_DBG_ENUMERATE_BP = 0x2015
UV_DBG_CHANGE_BP = 0x2016
UV_DBG_ENUM_STACK = 0x2019
UV_DBG_EXEC_CMD = 0x2020
UV_DBG_EVAL_EXPRESSION_TO_STR = 0x2024
UV_DBG_FILELINE_TO_ADR = 0x2025
UV_DBG_ENUM_REGISTER_GROUPS = 0x2026
UV_DBG_ENUM_REGISTERS = 0x2027
UV_DBG_READ_REGISTERS = 0x2028
UV_DBG_REGISTER_SET = 0x2029
UV_CMD_RESPONSE = 0x3000
UV_ASYNC_MSG = 0x4000
UV_DBG_CALLBACK = 0x5002
UV_DBG_CMD_OUTPUT = 0x5020

# ---------------------------------------------------------------------------
# UV_STATUS —— 命令执行状态
# ---------------------------------------------------------------------------
UV_STATUS_SUCCESS = 0
UV_STATUS_FAILED = 1
UV_STATUS_NO_PROJECT = 2
UV_STATUS_WRITE_PROTECTED = 3
UV_STATUS_NO_TARGET = 4
UV_STATUS_NO_TOOLSET = 5
UV_STATUS_NOT_DEBUGGING = 6
UV_STATUS_ALREADY_PRESENT = 7
UV_STATUS_INVALID_NAME = 8
UV_STATUS_NOT_FOUND = 9
UV_STATUS_DEBUGGING = 10
UV_STATUS_TARGET_EXECUTING = 11
UV_STATUS_TARGET_STOPPED = 12
UV_STATUS_PARSE_ERROR = 13
UV_STATUS_OUT_OF_RANGE = 14
UV_STATUS_BP_CANCELLED = 15
UV_STATUS_BP_BADADDRESS = 16
UV_STATUS_BP_NOTSUPPORTED = 17
UV_STATUS_BP_FAILED = 18
UV_STATUS_BP_REDEFINED = 19
UV_STATUS_BP_DISABLED = 20
UV_STATUS_BP_ENABLED = 21
UV_STATUS_BP_CREATED = 22
UV_STATUS_BP_DELETED = 23
UV_STATUS_BP_NOTFOUND = 24
UV_STATUS_BUILD_OK_WARNINGS = 25
UV_STATUS_BUILD_FAILED = 26
UV_STATUS_BUILD_CANCELLED = 27
UV_STATUS_NOT_SUPPORTED = 28
UV_STATUS_TIMEOUT = 29
UV_STATUS_UNEXPECTED_MSG = 30
UV_STATUS_VERIFY_FAILED = 31
UV_STATUS_NO_ADRMAP = 32
UV_STATUS_INFO = 33
UV_STATUS_NO_MEM_ACCESS = 34
UV_STATUS_FLASH_DOWNLOAD = 35
UV_STATUS_BUILDING = 36
UV_STATUS_HARDWARE = 37
UV_STATUS_SIMULATOR = 38
UV_STATUS_BUFFER_TOO_SMALL = 39
UV_STATUS_EVTR_FAILED = 40

UV_STATUS_TEXT = {
    UV_STATUS_SUCCESS: "成功",
    UV_STATUS_FAILED: "失败",
    UV_STATUS_NO_PROJECT: "没有打开工程",
    UV_STATUS_WRITE_PROTECTED: "写保护",
    UV_STATUS_NO_TARGET: "没有目标",
    UV_STATUS_NO_TOOLSET: "没有工具链",
    UV_STATUS_NOT_DEBUGGING: "未处于调试状态",
    UV_STATUS_ALREADY_PRESENT: "已存在",
    UV_STATUS_INVALID_NAME: "非法名称",
    UV_STATUS_NOT_FOUND: "未找到",
    UV_STATUS_DEBUGGING: "正在调试",
    UV_STATUS_TARGET_EXECUTING: "目标正在运行",
    UV_STATUS_TARGET_STOPPED: "目标已停止",
    UV_STATUS_PARSE_ERROR: "表达式解析错误",
    UV_STATUS_OUT_OF_RANGE: "越界",
    UV_STATUS_BP_CANCELLED: "断点已取消",
    UV_STATUS_BP_BADADDRESS: "断点地址非法",
    UV_STATUS_BP_NOTSUPPORTED: "断点不支持",
    UV_STATUS_BP_FAILED: "断点设置失败",
    UV_STATUS_BP_REDEFINED: "断点重复定义",
    UV_STATUS_BP_DISABLED: "断点已禁用",
    UV_STATUS_BP_ENABLED: "断点已启用",
    UV_STATUS_BP_CREATED: "断点已创建",
    UV_STATUS_BP_DELETED: "断点已删除",
    UV_STATUS_BP_NOTFOUND: "断点未找到",
    UV_STATUS_BUILD_OK_WARNINGS: "编译成功(有警告)",
    UV_STATUS_BUILD_FAILED: "编译失败",
    UV_STATUS_BUILD_CANCELLED: "编译取消",
    UV_STATUS_NOT_SUPPORTED: "不支持",
    UV_STATUS_TIMEOUT: "超时",
    UV_STATUS_UNEXPECTED_MSG: "意外消息",
    UV_STATUS_VERIFY_FAILED: "校验失败",
    UV_STATUS_NO_ADRMAP: "无地址映射",
    UV_STATUS_INFO: "信息",
    UV_STATUS_NO_MEM_ACCESS: "无内存访问权限",
    UV_STATUS_FLASH_DOWNLOAD: "正在下载 Flash",
    UV_STATUS_BUILDING: "正在编译",
    UV_STATUS_HARDWARE: "硬件调试",
    UV_STATUS_SIMULATOR: "仿真器调试",
    UV_STATUS_BUFFER_TOO_SMALL: "缓冲区过小",
    UV_STATUS_EVTR_FAILED: "事件追踪失败",
}

# ---------------------------------------------------------------------------
# VTT_TYPE —— 变量类型
# ---------------------------------------------------------------------------
VTT_void = 0
VTT_bit = 1
VTT_char = 2
VTT_uchar = 3
VTT_int = 4
VTT_uint = 5
VTT_short = 6
VTT_ushort = 7
VTT_long = 8
VTT_ulong = 9
VTT_float = 10
VTT_double = 11
VTT_ptr = 12
VTT_union = 13
VTT_struct = 14
VTT_func = 15
VTT_string = 16
VTT_enum = 17
VTT_field = 18
VTT_int64 = 19
VTT_uint64 = 20

# VTT_TYPE -> struct 格式符（用于解出 union 中的标量值）
VTT_TYPE_MAP = {
    VTT_void: 'Q',
    VTT_bit: "L",
    VTT_char: "c",
    VTT_uchar: "B",
    VTT_int: "i",
    VTT_uint: "I",
    VTT_short: "h",
    VTT_ushort: "H",
    VTT_long: "l",
    VTT_ulong: "L",
    VTT_float: "f",
    VTT_double: "d",
    VTT_ptr: "L",
    VTT_union: "unused",
    VTT_struct: "unused",
    VTT_func: "unused",
    VTT_string: "unused",
    VTT_enum: "unused",
    VTT_field: "unused",
    VTT_int64: "q",
    VTT_uint64: "Q",
}

VTT_TYPE_NAME = {
    VTT_void: "void",
    VTT_bit: "bit",
    VTT_char: "char",
    VTT_uchar: "unsigned char",
    VTT_int: "int",
    VTT_uint: "unsigned int",
    VTT_short: "short",
    VTT_ushort: "unsigned short",
    VTT_long: "long",
    VTT_ulong: "unsigned long",
    VTT_float: "float",
    VTT_double: "double",
    VTT_ptr: "pointer",
    VTT_union: "union",
    VTT_struct: "struct",
    VTT_func: "function",
    VTT_string: "string",
    VTT_enum: "enum",
    VTT_field: "bitfield",
    VTT_int64: "int64",
    VTT_uint64: "uint64",
}

_HEADER_FMT = '<3IQdI'       # m_nTotalLen, m_eCmd, m_nBufLen, cycles, tStamp, m_Id
_HEADER_SIZE = 32


class UVError(Exception):
    """UVSOCK 协议/通信错误基类。"""


class UVStatusError(UVError):
    """命令执行返回非成功状态。"""

    def __init__(self, status: int, cmd: str = ""):
        self.status = status
        self.cmd = cmd
        text = UV_STATUS_TEXT.get(status, "未知状态")
        super().__init__(f"命令 {cmd} 执行失败 [UV_STATUS={status}: {text}]")


def status_text(status: int) -> str:
    return UV_STATUS_TEXT.get(status, f"未知状态({status})")


class VSET:
    """
    typedef struct vset_t {
        TVAL val;        // 值类型 + 值
        SSTR str;        // 名称字符串
    } VSET;

    TVAL = { VTT_TYPE vType; union{ ul/sc/uc/i16/u16/l/i/i64/u64/f/d } v; }
    SSTR = { int nLen; char szStr[256]; }
    """

    def __init__(self) -> None:
        pass

    def pack(self, sstr: str) -> bytes:
        """
        打包一个 VSET（用于发送表达式名称）。
        布局固定为 vType(4) + union(8, 按 double/int64 对齐) + nLen(4) + str，
        与 unpack 中的偏移保持一致。发送时 vType 用 VTT_void、union 置 0。
        """
        b_sstr = sstr.encode("UTF-8")
        return struct.pack('<iQi{}s'.format(len(b_sstr)),
                           VTT_void, 0, len(b_sstr), b_sstr)

    def unpack(self, data: bytes):
        """
        解析返回的 VSET。
        返回: (val_type, val, name)
        """
        if len(data) < 8:
            raise UVError("VSET 数据过短")
        val_type = struct.unpack('<I', data[:4])[0]
        code = VTT_TYPE_MAP.get(val_type)
        if code is None or code == "unused":
            # 复合类型，仅返回类型与名称
            return val_type, None, ""
        val_size = struct.calcsize(f'<{code}')
        if len(data) < 4 + val_size:
            raise UVError("VSET 数据不完整")
        val = struct.unpack(f'<{code}', data[4:4 + val_size])[0]
        # SSTR: nLen(4) + str
        nlen_off = 4 + 8 + 4  # vType(4)+union最大槽(8)+nLen(4)
        # 计算偏移：TVAL 大小为 4 + union 大小。union 为 8 字节对齐。
        # union 成员中最大的是 double(8) / int64(8)，故 union 占 8 字节。
        off = 4 + 8  # 4(vType) + 8(union)
        if len(data) < off + 4:
            return val_type, val, ""
        nlen = struct.unpack('<i', data[off:off + 4])[0]
        if nlen > 0:
            name = data[off + 4:off + 4 + nlen].decode("UTF-8", "replace").rstrip('\x00')
        else:
            name = ""
        return val_type, val, name


class AMEM:
    """
    typedef struct amem {
        xU64 nAddr;      // 8 字节
        UINT nBytes;     // 4 字节
        xU64 ErrAddr;    // 8 字节
        UINT nErr;       // 4 字节
        xUC8 aBytes[1];  // nBytes 数据
    } AMEM;
    头部 24 字节。
    """

    @staticmethod
    def pack_read(nAddr: int, nBytes: int) -> bytes:
        """读内存请求的数据区：仅需 nAddr + nBytes。"""
        return struct.pack('<QI', nAddr & 0xFFFFFFFFFFFFFFFF, nBytes)

    @staticmethod
    def pack_write(nAddr: int, data: bytes) -> bytes:
        """写内存请求的数据区：完整 AMEM，aBytes 为要写入的字节。"""
        return struct.pack('<QIQI', nAddr & 0xFFFFFFFFFFFFFFFF,
                           len(data), 0, 0) + data

    @staticmethod
    def unpack(data: bytes):
        """
        解析内存读写响应。
        返回: (nAddr, ErrAddr, nErr, payload)
        """
        if len(data) < 24:
            raise UVError("AMEM 响应数据过短")
        nAddr, nBytes, ErrAddr, nErr = struct.unpack('<QIQI', data[:24])
        payload = data[24:24 + nBytes]
        return nAddr, ErrAddr, nErr, payload


class UVSOCK_CMD:
    """一条 UVSOCK 命令帧。"""

    def __init__(self, m_eCmd: int, data: bytes = b''):
        self.m_eCmd = m_eCmd
        self.data = data
        self.m_nTotalLen = _HEADER_SIZE + len(data)
        self.m_nBufLen = len(data)
        self.m_cycles = 0
        self.m_tStamp = 0.0
        self.m_Id = 0

    def pack(self) -> bytes:
        fmt = f'<{_HEADER_FMT[1:]}{len(self.data)}s' if self.data else _HEADER_FMT
        if self.data:
            return struct.pack(fmt, self.m_nTotalLen, self.m_eCmd,
                               self.m_nBufLen, self.m_cycles, self.m_tStamp,
                               self.m_Id, self.data)
        return struct.pack(_HEADER_FMT, self.m_nTotalLen, self.m_eCmd,
                           self.m_nBufLen, self.m_cycles, self.m_tStamp,
                           self.m_Id)

    @staticmethod
    def unpack(data: bytes):
        """
        解析响应帧。响应头部多出 r_cmd(4) + r_status(4) 两个字段：
            UVSOCK_CMD 32B + UINT r_cmd + UINT r_status + data
        返回: (m_nTotalLen, m_eCmd, m_nBufLen, cycles, tStamp, m_Id,
               r_cmd, r_status, data)
        """
        if len(data) < _HEADER_SIZE + 8:
            raise UVError("响应帧过短")
        m_nTotalLen, m_eCmd, m_nBufLen, cycles, tStamp, m_Id = \
            struct.unpack(_HEADER_FMT, data[:_HEADER_SIZE])
        r_cmd, r_status = struct.unpack('<II', data[_HEADER_SIZE:_HEADER_SIZE + 8])
        m_data = data[_HEADER_SIZE + 8:]
        return m_nTotalLen, m_eCmd, m_nBufLen, cycles, tStamp, m_Id, r_cmd, r_status, m_data

    # ---- 各类命令的响应解析 ----

    def retrive_version(self, data: bytes):
        *_, r_cmd, r_status, m_data = self.unpack(data)
        return r_status, m_data.hex()

    def retrive_expression(self, data: bytes):
        *_, r_cmd, r_status, m_data = self.unpack(data)
        if r_status != UV_STATUS_SUCCESS:
            return r_status, None, None, ""
        val_type, val, name = VSET().unpack(m_data)
        return r_status, val_type, val, name

    def retrive_mem_data(self, data: bytes):
        *_, r_cmd, r_status, m_data = self.unpack(data)
        if r_status != UV_STATUS_SUCCESS:
            return r_status, None, 0, 0, b''
        nAddr, ErrAddr, nErr, payload = AMEM.unpack(m_data)
        return r_status, nAddr, ErrAddr, nErr, payload


if __name__ == "__main__":
    # 自测打包
    uv = UVSOCK_CMD(UV_GEN_GET_VERSION)
    d = uv.pack()
    print("packed len:", len(d), d.hex())
    assert len(d) == _HEADER_SIZE


class EXECCMD:
    """
    UV_DBG_EXEC_CMD 的数据区：执行一条 Keil 命令窗口命令（如 BS/BK/BL/EVAL）。

    打包格式沿用 TCP UVSOCK 的 SSTR 风格：nLen(4, 含终止符) + 命令字节(NULL 结尾)。
    Keil 命令窗口命令语义（与 UVSC 桥接实现一致）：
        BS <expr>   设置软件断点
        BK <expr>   清除断点（或断点编号）
        BL          列出断点
        EVAL <expr> 计算表达式
    """

    @staticmethod
    def pack(command: str) -> bytes:
        # 完整 EXECCMD 结构：flags(4) + reserved[7](28) + SSTR{nLen(4) + char[256]}
        # 共 4+28+4+256 = 292 字节（与 UVSC DLL 的 sizeof(EXECCMD)==292 一致）
        b_cmd = command.encode("UTF-8") + b"\x00"
        nlen = len(b_cmd)          # 含 NULL 终止符
        if nlen > 256:
            b_cmd = b_cmd[:256]
            b_cmd = b_cmd[:-1] + b"\x00"
            nlen = 256
        return (struct.pack('<I', 0)        # flags
                + b'\x00' * 28              # reserved[7]
                + struct.pack('<i', nlen)   # SSTR.nLen
                + b_cmd
                + b'\x00' * (256 - nlen))   # SSTR.szStr 剩余


# UV_DBG_STATUS 返回的目标运行状态（TCP UVSOCK 语义：0=停止, 1=执行中）
DBG_STOPPED = 0
DBG_EXECUTING = 1
