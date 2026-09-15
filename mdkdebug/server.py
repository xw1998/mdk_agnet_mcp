# -*- coding: utf-8 -*-
"""
Mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务（MCP Server）。

通过 UVSOCK/TCP 连接 Keil uVision 调试器，向 MCP 客户端（Claude、灵犀等）
暴露如下调试工具：
  - get_version    查询 UVSOCK 插件版本
  - get_status     查询调试 / 目标运行状态
  - calc_expression 读取表达式 / 变量值
  - read_mem       读取目标内存
  - write_mem      写入目标内存
  - run / stop / reset / step  运行控制

运行形态：常驻服务 + 空闲自动断开连接缓存。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from mcp.server.mcpserver import MCPServer

from .client import UVClient
from . import __version__

logger = logging.getLogger("mdkdebug.server")

# 全局共享一个带连接缓存的客户端（线程安全）
_client: UVClient | None = None


def _get_client() -> UVClient:
    global _client
    if _client is None:
        raise RuntimeError("客户端未初始化，请先调用 create_server()")
    return _client


def _parse_addr(s: str | int) -> int:
    """把地址参数解析为整数，支持 0x/0b/0o 前缀或纯十进制。"""
    if isinstance(s, int):
        return s
    s = (s or "").strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.lower().startswith("0b"):
        return int(s, 2)
    if s.lower().startswith("0o"):
        return int(s, 8)
    return int(s, 10)


def _js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def create_server(host: str = "127.0.0.1", port: int = 4823,
                  idle_timeout: float = 30.0) -> MCPServer:
    global _client
    _client = UVClient(host=host, port=port, idle_timeout=idle_timeout)
    logger.info("Mdkdebug 已就绪：UVSOCK@%s:%d  idle_timeout=%ss", host, port, idle_timeout)

    server = MCPServer(
        name="mdkdebug",
        title="Keil uVision Debug (Mdkdebug)",
        version=__version__,
        description=(
            "通过 UVSOCK/TCP 连接 Keil uVision 调试器，提供读变量/表达式、"
            "读写目标内存、运行控制（运行/暂停/复位/单步）和状态查询能力。"
            "适用于 Cortex-M 等 ARM 目标板的在线调试。"
        ),
        log_level="INFO",
    )

    # ---------------- 状态 / 版本 ----------------
    @server.tool(
        name="get_version",
        title="查询调试插件版本",
        description="查询 Keil UVSOCK 插件的版本信息，返回十六进制版本串。",
    )
    async def get_version() -> str:
        try:
            return _js(_get_client().get_version())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="get_status",
        title="查询调试/目标状态",
        description=(
            "查询当前调试状态：是否处于调试会话、目标是否在运行、"
            "以及 UVSOCK 状态码。可用于判断可否安全读写内存。"
        ),
    )
    async def get_status() -> str:
        try:
            return _js(_get_client().get_status())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 表达式 / 变量 ----------------
    @server.tool(
        name="calc_expression",
        title="读取表达式 / 变量值",
        description=(
            "计算并读取调试器中的一个表达式（变量名、寄存器、指针解引用等）。"
            "例如传入全局变量名 'SData_UA'、'timer.sec'，或 '*(uint32_t*)0x20000000'。"
            "返回表达式在当前断点处的值及其类型。"
        ),
    )
    async def calc_expression(expr: str) -> str:
        try:
            return _js(_get_client().calc_expression(expr))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expression": expr, "error": str(e)})

    # ---------------- 内存读写 ----------------
    @server.tool(
        name="read_mem",
        title="读取目标内存",
        description=(
            "从指定内存地址读取 n_bytes 个字节。"
            "addr 支持十六进制（如 '0x20000000'）或十进制；返回十六进制字节串及 ASCII 视图。"
        ),
    )
    async def read_mem(addr: str, n_bytes: int) -> str:
        try:
            a = _parse_addr(addr)
            return _js(_get_client().read_mem(a, int(n_bytes)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    @server.tool(
        name="write_mem",
        title="写入目标内存",
        description=(
            "向指定内存地址写入字节。data_hex 为十六进制字节串（偶数长度），"
            "如 'de ad be ef' 或 'deadbeef'（自动去空格）。返回实际写入长度。"
        ),
    )
    async def write_mem(addr: str, data_hex: str) -> str:
        try:
            a = _parse_addr(addr)
            hex_str = "".join((data_hex or "").split())
            payload = bytes.fromhex(hex_str)
            return _js(_get_client().write_mem(a, payload))
        except ValueError as e:
            return _js({"ok": False, "addr": str(addr), "error": f"data_hex 非法: {e}"})
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "addr": str(addr), "error": str(e)})

    # ---------------- 调试会话控制 ----------------
    @server.tool(
        name="enter_debug",
        title="进入调试模式",
        description=(
            "自动进入 Keil 调试模式（UV_DBG_ENTER）。"
            "受工程 Load/Flash Download/Run-to-main 设置影响，属于有副作用的操作；"
            "进入后即可设断点、读变量、运行控制。"
        ),
    )
    async def enter_debug() -> str:
        try:
            return _js(_get_client().enter_debug())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="exit_debug",
        title="退出调试模式",
        description="自动退出 Keil 调试模式（UV_DBG_EXIT）。",
    )
    async def exit_debug() -> str:
        try:
            return _js(_get_client().exit_debug())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 断点管理 ----------------
    @server.tool(
        name="set_breakpoint",
        title="设置断点",
        description=(
            "在指定符号或地址处设置软件断点。expr 可为函数名/变量名"
            "（如 'main'）或地址（如 '0x08001034'）。返回是否成功。"
        ),
    )
    async def set_breakpoint(expr: str) -> str:
        try:
            return _js(_get_client().set_breakpoint(expr))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="clear_breakpoint",
        title="清除断点",
        description="清除指定符号或断点编号处的断点（命令窗口 BK）。",
    )
    async def clear_breakpoint(expr: str) -> str:
        try:
            return _js(_get_client().clear_breakpoint(expr))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "expr": expr, "error": str(e)})

    @server.tool(
        name="list_breakpoints",
        title="列出断点",
        description="列出当前调试会话中的所有断点（命令窗口 BL）。",
    )
    async def list_breakpoints() -> str:
        try:
            return _js(_get_client().list_breakpoints())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    # ---------------- 运行控制 ----------------
    @server.tool(
        name="run",
        title="全速运行",
        description="让目标 MCU 全速运行（启动执行）。",
    )
    async def run() -> str:
        try:
            return _js(_get_client().run())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="stop",
        title="暂停执行",
        description="暂停目标 MCU 的执行（进入断点/挂起状态）。",
    )
    async def stop() -> str:
        try:
            return _js(_get_client().stop())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="reset",
        title="复位目标",
        description="复位目标 MCU。",
    )
    async def reset() -> str:
        try:
            return _js(_get_client().reset())
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    @server.tool(
        name="step",
        title="单步执行",
        description=(
            "单步执行。mode 可选：'into'（单步进入）、'over'（单步跳过）、"
            "'out'（跳出）、'instruction'（指令级）。默认 'into'。"
        ),
    )
    async def step(mode: str = "into") -> str:
        try:
            return _js(_get_client().step(mode))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})

    return server


async def run_stdio(host: str = "127.0.0.1", port: int = 4823,
                    idle_timeout: float = 30.0) -> None:
    """以标准输入/输出方式运行（MCP 客户端常用方式）。"""
    server = create_server(host=host, port=port, idle_timeout=idle_timeout)
    await server.run_stdio_async()


async def run_http(host: str = "127.0.0.1", port: int = 4823,
                   idle_timeout: float = 30.0,
                   http_host: str = "127.0.0.1", http_port: int = 8300) -> None:
    """以 Streamable HTTP 方式运行（可被远程/浏览器 MCP 客户端连接）。"""
    import uvicorn
    server = create_server(host=host, port=port, idle_timeout=idle_timeout)
    app = server.streamable_http_app()
    config = uvicorn.Config(app, host=http_host, port=http_port, log_level="info")
    uvicorn.Server(config).run()
