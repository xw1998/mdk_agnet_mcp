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
    parser.add_argument("--symbol-project", action="append", default=None,
                        metavar="NAME:AXF[:MAP[:FLASH_START[:FLASH_SIZE]]]",
                        help=("追加自定义符号工程（可多次指定），格式 "
                              "'名字:.axf路径:.map路径:flash起始16进制:flash大小16进制'，"
                              "如 'myproj:D:/p/out.axf:D:/p/out.map:0x08000000:0x100000'。"
                              "用于在非本机/仓库外工程注入可切换符号，避免写死路径"))
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        stream=sys.stderr,
    )

    from .server import run_stdio, run_http

    # 解析 --symbol-project 追加项为 dict 列表
    symbol_projects = []
    for sp in (args.symbol_project or []):
        parts = sp.split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            print(f"忽略非法 --symbol-project: {sp}", file=sys.stderr)
            continue
        name, axf = parts[0], parts[1]
        mp = parts[2] if len(parts) > 2 and parts[2] else None
        fs = int(parts[3], 16) if len(parts) > 3 and parts[3] else 0x08000000
        fsz = int(parts[4], 16) if len(parts) > 4 and parts[4] else 0x100000
        symbol_projects.append({"name": name, "axf": axf, "map": mp,
                                "flash_start": fs, "flash_size": fsz})

    if args.transport == "http":
        run_http(host=args.host, port=args.port, idle_timeout=args.idle_timeout,
                 http_host=args.http_host, http_port=args.http_port,
                 uv4_path=args.uv4_path, default_project=args.default_project,
                 axf_path=args.axf_path, symbol_projects=symbol_projects)
        return 0

    asyncio.run(run_stdio(host=args.host, port=args.port,
                          idle_timeout=args.idle_timeout,
                          uv4_path=args.uv4_path,
                          default_project=args.default_project,
                          axf_path=args.axf_path,
                          symbol_projects=symbol_projects))
    return 0


if __name__ == "__main__":
    sys.exit(main())
