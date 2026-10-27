# -*- coding: utf-8 -*-
"""数值入参的统一口径：整数、`0x` 十六进制字符串、`0b` / `0o`，全角空格容错。

为什么要有这个模块：MCP 的调用方（AI 或脚本）几乎一定把地址写成 `"0x08000000"`，
而工具签名写的是 `int`。旧实现直接 `int(v)`，于是 `"0x08000000"` 抛
`ValueError: invalid literal for int()`，调用方看到的是「参数错误」而不是「这里接受十六进制」。

约定（宁可报错，不猜）：

- `0x` / `0X` 前缀 → 十六进制；`0b` / `0o` → 二进制 / 八进制；纯数字 → 十进制；
  允许 `_` 分隔符与首尾空白；负数按同样规则处理。
- **不做**「看着像十六进制就按十六进制」的猜测：`08000000` 就是十进制 8000000，
  因为同一个字符串在别的调用里可能是十进制计数。要十六进制请写 `0x`。
"""

from __future__ import annotations

INT_HELP = "接受整数、`0x...`（十六进制）、`0b...`（二进制）、`0o...`（八进制）或十进制字符串"


def parse_int(v, *, name: str = "value", default=None, allow_none: bool = True):
    """把整数或字符串解析成 int；`None`/空串按 ``default`` 处理。

    解析失败抛 ``ValueError``，消息里带参数名与正确写法——不返回 0、不吞错。
    """
    if v is None:
        return default
    if isinstance(v, bool):
        raise ValueError("%s 需要整数或数值字符串，收到布尔值 %r（%s）" % (name, v, INT_HELP))
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if int(v) != v:
            raise ValueError("%s 需要整数，收到小数 %r" % (name, v))
        return int(v)
    if not isinstance(v, str):
        raise ValueError("%s 需要整数或数值字符串，收到 %s（%s）"
                         % (name, type(v).__name__, INT_HELP))
    t = v.strip().replace("_", "")
    if not t:
        if allow_none:
            return default
        raise ValueError("%s 不能为空（%s）" % (name, INT_HELP))
    try:
        return int(t, 0) if t.lower().lstrip("-+").startswith(("0x", "0b", "0o")) else int(t, 10)
    except ValueError:
        raise ValueError("%s 解析不了：%r（%s）" % (name, v, INT_HELP)) from None


def hexstr(n) -> str:
    """统一的十六进制展示：``0x08000000``（大写、无多余 0）。"""
    if n is None:
        return ""
    return "0x%X" % int(n)
