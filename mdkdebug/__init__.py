# -*- coding: utf-8 -*-
"""
mdkdebug —— 可被 AI 工具调用的 Keil uVision 调试服务。

通过 UVSOCK/TCP 连接 Keil uVision 调试器，以 MCP Server 形式向 AI 客户端
暴露调试能力（读变量、读写内存、运行控制、状态查询）。

注意：本文件**故意不做重导入**。`mdkdebug.bootstrap` 必须能在「宿主 PYTHONPATH 污染」
的环境里被最先 import 到——那时 `re` 可能是别人的、`client` 一导入就崩。因此
`UVClient` / `uvsock` / `interface` 改成 PEP 562 惰性属性，用到才取。
"""

__version__ = "0.2.26"

__all__ = ["UVClient", "uvsock", "interface", "__version__"]

_LAZY = {"UVClient": ".client", "uvsock": ".uvsock", "interface": ".interface"}


def __getattr__(name):
    mod_path = _LAZY.get(name)
    if mod_path is None:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    import importlib
    mod = importlib.import_module(mod_path, __name__)
    val = getattr(mod, name) if name != "UVClient" else mod.UVClient
    globals()[name] = val
    return val


def __dir__():
    return sorted(__all__)
