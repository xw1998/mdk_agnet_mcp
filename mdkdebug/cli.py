# -*- coding: utf-8 -*-
"""
mdkdebug MCP Server 命令行入口。

安装本包后可执行 `mdkdebug` 命令，或在仓库根目录执行 `python run_server.py`
（run_server.py 为指向本模块的薄壳，二者等价）。

用法:
    mdkdebug                                    # stdio 方式（MCP 客户端标准方式）
    mdkdebug --host 127.0.0.1 --port 4823       # 指定 UVSOCK 地址 / 空闲超时
    mdkdebug --transport http --http-port 8300  # Streamable HTTP 方式
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from . import __version__


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mdkdebug",
        description="可被 AI 工具调用的 Keil uVision 调试服务（MCP Server）",
    )
    parser.add_argument("--version", action="version", version=f"mdkdebug {__version__}")
    parser.add_argument("--host", default="127.0.0.1", help="UVSOCK 主机 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4823, help="UVSOCK 端口 (默认 4823)")
    parser.add_argument("--idle-timeout", type=float, default=30.0,
                        help="连接缓存空闲断开秒数 (默认 30)")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio",
                        help="传输方式：stdio（MCP 标准）或 http（Streamable HTTP）")
    parser.add_argument("--http-host", default="127.0.0.1", help="HTTP 监听主机 (默认 127.0.0.1)")
    parser.add_argument("--http-port", type=int, default=8300, help="HTTP 监听端口 (默认 8300)")
    parser.add_argument("--uv4-path", default=None,
                        help="Keil UV4.exe 绝对路径，缺省时自动探测 (如 D:/Keil_v5/UV4/UV4.exe)")
    parser.add_argument("--default-project", default=None,
                        help="默认待编译/烧录的 Keil 工程 (.uvprojx) 路径")
    parser.add_argument("--axf-path", default=None,
                        help="调试符号文件 .axf 路径，缺省时从默认工程自动推断")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        stream=sys.stderr,
    )

    from .server import run_stdio, run_http

    if args.transport == "http":
        run_http(host=args.host, port=args.port, idle_timeout=args.idle_timeout,
                 http_host=args.http_host, http_port=args.http_port,
                 uv4_path=args.uv4_path, default_project=args.default_project,
                 axf_path=args.axf_path)
        return 0

    asyncio.run(run_stdio(host=args.host, port=args.port,
                          idle_timeout=args.idle_timeout,
                          uv4_path=args.uv4_path,
                          default_project=args.default_project,
                          axf_path=args.axf_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
