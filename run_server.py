# -*- coding: utf-8 -*-
"""
Mdkdebug MCP Server 启动入口（薄壳，逻辑见 mdkdebug.cli）。

本文件仅为仓库根目录直接运行 `python run_server.py` 保留的兼容入口；
真实实现已收敛到 `mdkdebug.cli:main`，`pip install .` 后亦可用 `mdkdebug` 命令替代。
"""

from __future__ import annotations

import sys

from mdkdebug.cli import main

if __name__ == "__main__":
    sys.exit(main())
