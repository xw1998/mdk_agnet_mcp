# -*- coding: utf-8 -*-
"""
Mdkdebug MCP Server 启动入口（薄壳，逻辑见 mdkdebug.cli）。

本文件仅为仓库根目录直接运行 `python run_server.py` 保留的兼容入口；
真实实现已收敛到 `mdkdebug.cli:main`，`pip install .` 后亦可用 `mdkdebug` 命令替代。

启动前会做**环境自愈**（mdkdebug.bootstrap）：宿主若把 PYTHONPATH / PYTHONHOME 传进来，
这里用 `-E -s` 隔离模式重启一次自己，否则 `import re` 会拿到别人的 stdlib 而崩
（SRE module mismatch）。所以本文件只 import 标准库里最安全的两个模块。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mdkdebug.bootstrap import ensure_isolated  # noqa: E402

ensure_isolated()                               # 污染环境下不会返回（exec 重启）

from mdkdebug.cli import main                   # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
