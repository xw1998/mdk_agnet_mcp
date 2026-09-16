# -*- coding: utf-8 -*-
"""
mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务。

通过 UVSOCK/TCP 连接 Keil uVision 调试器，以 MCP Server 形式向 AI 客户端
暴露调试能力（读变量、读写内存、运行控制、状态查询）。
"""

__version__ = "0.0.4"

from .client import UVClient
from . import uvsock, interface

__all__ = ["UVClient", "uvsock", "interface", "__version__"]
