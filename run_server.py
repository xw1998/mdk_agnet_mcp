# -*- coding: utf-8 -*-
"""
Mdkdebug MCP Server 启动入口。

用法:
    # 以 stdio 方式运行（MCP 客户端标准方式，如 Claude Desktop / 灵犀）
    python run_server.py

    # 指定 UVSOCK 地址 / 空闲超时
    python run_server.py --host 127.0.0.1 --port 4823 --idle-timeout 30

    # 以 Streamable HTTP 方式运行（便于远程连接 / 网页调试）
    python run_server.py --transport http --http-port 8300

说明:
    --host/--port 是 Keil UVSOCK 调试插件监听的地址（默认 127.0.0.1:4823）。
    --idle-timeout 是连接缓存的空闲断开时间（秒，默认 30）。
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mdkdebug",
        description="可被 AI 工具调用的 Keil uVision 调试服务（MCP Server）",
    )
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
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        stream=sys.stderr,
    )

    from mdkdebug.server import run_stdio, run_http

    if args.transport == "http":
        run_http(host=args.host, port=args.port, idle_timeout=args.idle_timeout,
                 http_host=args.http_host, http_port=args.http_port,
                 uv4_path=args.uv4_path, default_project=args.default_project)
        return 0

    asyncio.run(run_stdio(host=args.host, port=args.port,
                          idle_timeout=args.idle_timeout,
                          uv4_path=args.uv4_path,
                          default_project=args.default_project))
    return 0


if __name__ == "__main__":
    sys.exit(main())
