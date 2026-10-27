# -*- coding: utf-8 -*-
"""`python -m mdkdebug` 入口（与 `mdkdebug` / `python run_server.py` 等价）。"""

from __future__ import annotations

import sys

from .bootstrap import ensure_isolated

ensure_isolated()

from .cli import main  # noqa: E402

sys.exit(main())
