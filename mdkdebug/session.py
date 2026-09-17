# -*- coding: utf-8 -*-
"""跨会话状态：把「这次调试是怎么配起来的」落到 state.json（批次34）。

为什么需要
----------
MCP 工具本身是无状态的，而一次真实调试要配一堆上下文：工程文件、符号文件（.axf/.map）、
debug target、SVD 器件、串口端口/波特率、断点与数据断点清单。会话一断、客户端一重启，
这些就全丢了——AI 只能靠再问一遍、或从零摸索，代价高且容易接错（最典型的是**符号文件
漂移**：接着上次的会话调试，却加载了别的 .axf，于是表达式集体解析失败）。

这里把这份上下文落盘成 ``state.json``，由 ``session_state`` 工具读写。三条设计底线：

1. **只存「观察到的」，不存「猜的」**：每个字段都带来源与采集时间；采不到就写
   ``available: false`` 与原因，绝不用默认值假装采集成功。
2. **读回来不自动应用**：``load`` 默认只对比、只报告；``apply=true`` 才动手，且只做
   **主机侧可逆动作**（切符号文件），逐项回报 ok/失败原因。
3. **写盘要原子**：先写临时文件再 ``os.replace``，旧文件留一份 ``.bak``；文件损坏时
   明确报错（含路径与解析错误），不静默当「没有状态」。

文件位置：``MDKDEBUG_STATE_FILE`` 指定，默认 ``~/.mdkdebug/state.json``。
"""
from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger("mdkdebug.session")

#: 状态文件格式版本（字段增删时递增，读取端据此判断兼容性）
SCHEMA = 1

def state_path(path: str | None = None) -> str:
    """状态文件路径：显式 path > MDKDEBUG_STATE_FILE > ~/.mdkdebug/state.json。"""
    p = (path or "").strip()
    if p:
        return os.path.abspath(os.path.expanduser(p))
    env = (os.environ.get("MDKDEBUG_STATE_FILE") or "").strip()
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.abspath(os.path.expanduser(os.path.join("~", ".mdkdebug", "state.json")))

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def load(path: str | None = None) -> dict:
    """读状态文件。返回 {ok, exists, path, schema, saved_at, context, size, error}。"""
    p = state_path(path)
    out = {"ok": False, "exists": False, "path": p, "schema": None,
           "saved_at": None, "context": None, "size": None, "error": None}
    if not os.path.isfile(p):
        out["error"] = "状态文件不存在（还没保存过，或已被 clear）"
        return out
    out["exists"] = True
    try:
        out["size"] = os.path.getsize(p)
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:  # noqa: BLE001
        out["error"] = ("状态文件存在但解析失败：%s（路径 %s）。"
                        "请检查文件是否被外部破坏，或用 session_state(action=\"save\") 覆盖重建"
                        % (e, p))
        return out
    if not isinstance(data, dict) or "context" not in data:
        out["error"] = ("状态文件结构不是本工具写的格式（缺 context 字段）：%s。"
                        "不猜测其内容，请确认路径是否正确" % p)
        return out
    out["schema"] = data.get("schema")
    out["saved_at"] = data.get("saved_at")
    out["context"] = data.get("context")
    out["saved_by"] = data.get("saved_by")
    out["ok"] = True
    if out["schema"] != SCHEMA:
        out["warning"] = ("状态文件 schema=%s 与当前支持的 %s 不同："
                          "字段可能不全或语义有变，建议重新 save" % (out["schema"], SCHEMA))
    return out

def save(context: dict, path: str | None = None, saved_by: str = "mdkdebug") -> dict:
    """原子写状态文件（旧文件备份为 <path>.bak）。返回 {ok, path, backup, bytes, saved_at, error}。"""
    p = state_path(path)
    payload = {"schema": SCHEMA, "saved_at": _now(), "saved_by": saved_by,
               "context": context}
    d = os.path.dirname(p) or "."
    tmp = p + ".tmp"
    backup = None
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        return {"ok": False, "path": p, "error": "无法创建目录 %s：%s" % (d, e)}
    if os.path.isfile(p):
        backup = p + ".bak"
        try:
            with open(p, "rb") as src, open(backup, "wb") as dst:
                dst.write(src.read())
        except OSError as e:
            backup = None
            logger.warning("备份旧状态文件失败（继续写新文件）：%s", e)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, p)
    except Exception as e:  # noqa: BLE001
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return {"ok": False, "path": p, "error": "写状态文件失败：%s" % e}
    try:
        size = os.path.getsize(p)
    except OSError:
        size = None
    return {"ok": True, "path": p, "backup": backup, "bytes": size,
            "saved_at": payload["saved_at"], "schema": SCHEMA}

def clear(path: str | None = None) -> dict:
    """删除状态文件（不动 .bak，便于反悔）。返回 {ok, path, removed, error}。"""
    p = state_path(path)
    if not os.path.isfile(p):
        return {"ok": True, "path": p, "removed": False,
                "note": "状态文件本就不存在，无需删除"}
    try:
        os.remove(p)
    except OSError as e:
        return {"ok": False, "path": p, "removed": False, "error": "删除失败：%s" % e}
    return {"ok": True, "path": p, "removed": True,
            "note": "已删除 %s（若之前 save 过，旧内容仍在同名 .bak 里）" % p}

def diff(saved: dict | None, current: dict, keys=None) -> dict:
    """对比磁盘态与当前态，返回 {相同, 变化, 仅存于文件的字段, 仅存于当前的字段}。

    只做**逐字段等值比较**，不判断谁对谁错——这是给调用方决定「要不要 apply」用的
    客观依据（避免工具替 AI 猜「应该是哪个」）。
    """
    saved = saved or {}
    keys = list(keys) if keys else sorted(set(saved) | set(current))
    same, changed, only_saved, only_current = {}, {}, {}, {}
    for k in keys:
        in_s = k in saved
        in_c = k in current
        if in_s and in_c:
            if saved[k] == current[k]:
                same[k] = saved[k]
            else:
                changed[k] = {"saved": saved[k], "current": current[k]}
        elif in_s:
            only_saved[k] = saved[k]
        else:
            only_current[k] = current[k]
    return {"same": same, "changed": changed,
            "only_in_file": only_saved, "only_in_current": only_current,
            "identical": not changed and not only_saved and not only_current}
