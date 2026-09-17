# -*- coding: utf-8 -*-
"""工程现场发现层：从「工程里已经写好的调试配置」把参数捞出来。

为什么要有这一层：MDK 的芯片知识躺在 .uvprojx 里，Keil 侧工具直接读它就行；
GCC/OpenOCD 世界没有等价物，于是每次都要人工把 profile / interface / target cfg
敲一遍。但绝大多数 GCC 工程其实**已经写过一份调试配置**——VS Code 的
`.vscode/launch.json`（cortex-debug 扩展）。里面 device / interface /
configFiles / executable / svdFile / armToolchainPath 都是现成的，
复用它能省掉一整轮「猜 cfg 名 → 猜错 → 再猜」。

这个做法参考了开源项目 openocd-mcp 的思路（它直接拿 launch.json 当调试目标来源），
但本模块额外做了三件它没做的事：

1. **显式披露来源**：返回里一定有 `config_source`，写清楚每个字段是
   从 launch.json 的哪个键来的、还是回落到档案默认值——不能让人以为
   这些参数是「引擎猜出来的」。
2. **参数优先级链**：显式参数 > 环境变量 > 工程配置(launch.json) > 内置档案默认值。
   这与 MCP 生态的通行做法一致，也让 `ocd_start` 的自动补充可预期、可关闭。
3. **不假装知道不知道的事**：launch.json 里 servertype 是 jlink/pyocd 时，
   照实说「这不是 OpenOCD 配置，只能借出芯片型号/接口/可执行文件」，
   而不是硬把它翻译成一份 OpenOCD 启动参数。

**只读**：本模块只解析，不写回任何工程文件。
"""

from __future__ import annotations

import json
import os
import re

from . import targets as _targets

__all__ = ["find_launch_json", "read_launch_json", "list_configs",
           "resolve_config", "guess_from_workspace", "register"]

_MAX_UP = 8          # 向上最多找几层
_MAX_BYTES = 1 << 20  # launch.json 一般几 KB；超过 1MB 直接拒绝，避免卡死

# launch.json 里对我们有用的键（用于「来源披露」，不是白名单）
_KEYS = ("name", "type", "request", "servertype", "serverpath", "cwd",
         "executable", "device", "interface", "configFiles", "searchDir",
         "svdFile", "armToolchainPath", "openOCDLaunchCommands", "rtos",
         "objdumpPath", "gdbPath", "preLaunchTask", "runToEntryPoint",
         "showDevDebugOutput", "numberOfProcessors", "targetProcessor",
         "jlinkscript", "deviceName")


def _strip_jsonc(text: str) -> str:
    """去掉 // 与 /* */ 注释：VS Code 允许注释，json.loads 不允许。

    只做最朴素的扫描——launch.json 里出现 `//` 而**不在字符串中**的情况
    几乎只有注释，够用；真遇到复杂情况解析失败会如实报错，不做猜测修复。
    """
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_launch_json(start: str = "") -> dict:
    """从 start（默认 cwd）向上找最近的 `.vscode/launch.json`。

    返回带 `path` 与 `workspace`（= .vscode 的父目录）的结果；
    找不到时 ok=False 并给出找过的位置（不是静默返回空）。
    """
    cur = os.path.abspath(start or os.getcwd())
    if os.path.isfile(cur):
        cur = os.path.dirname(cur)
    tried = []
    for _ in range(_MAX_UP):
        cand = os.path.join(cur, ".vscode", "launch.json")
        tried.append(cand)
        if os.path.isfile(cand):
            return {"ok": True, "path": cand, "workspace": cur, "tried": tried}
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return {"ok": False, "error": "向上%s层都没找到 .vscode/launch.json" % _MAX_UP,
            "start": os.path.abspath(start or os.getcwd()), "tried": tried,
            "hint": "直接把 launch.json 的路径传给 path，或改用 target_list 选档案"}


def read_launch_json(path: str) -> dict:
    """读并解析 launch.json（支持 VS Code 的 JSONC 注释）。"""
    p = os.path.abspath(os.path.expanduser(path or ""))
    if not p:
        return {"ok": False, "error": "path 不能为空"}
    if not os.path.isfile(p):
        return {"ok": False, "error": "文件不存在：%s" % p}
    try:
        sz = os.path.getsize(p)
        if sz > _MAX_BYTES:
            return {"ok": False, "error": "文件过大（%d 字节），拒绝解析" % sz}
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        return {"ok": False, "error": "读取失败：%s" % e}
    try:
        data = json.loads(_strip_jsonc(raw))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "JSON 解析失败：%s" % e, "path": p,
                "hint": "确认是合法的 launch.json（允许 // 与 /* */ 注释）"}
    if not isinstance(data, dict):
        return {"ok": False, "error": "顶层不是对象", "path": p}
    cfgs = data.get("configurations")
    if cfgs is None:
        return {"ok": False, "error": "没有 configurations 数组", "path": p}
    if not isinstance(cfgs, list):
        return {"ok": False, "error": "configurations 不是数组", "path": p}
    return {"ok": True, "path": p, "data": data, "configurations": cfgs,
            "count": len(cfgs)}


def _expand(val, workspace: str, search_dirs=None):
    """展开 ${workspaceFolder} / ${workspaceRoot} / ${env:VAR}。

    只展开认得出来的，认不出来的一律**原样保留**（不猜、不清空）。
    """
    if isinstance(val, list):
        return [_expand(v, workspace, search_dirs) for v in val]
    if not isinstance(val, str):
        return val
    out = val
    out = out.replace("${workspaceFolder}", workspace)
    out = out.replace("${workspaceRoot}", workspace)
    out = out.replace("${workspaceFolderBasename}", os.path.basename(workspace))
    def _env(m):
        return os.environ.get(m.group(1), m.group(0))
    out = re.sub(r"\$\{env:([^}]+)\}", _env, out)
    if "${" in out:
        # 还有未展开的变量（如 ${config:xxx}）：保留，但在上层披露出来
        pass
    if not os.path.isabs(out) and os.path.sep not in out and "/" not in out:
        return out
    if not os.path.isabs(out) and search_dirs:
        for d in search_dirs:
            cand = os.path.normpath(os.path.join(d, out))
            if os.path.exists(cand):
                return cand
    return out


def list_configs(path: str = "") -> dict:
    """列出 launch.json 里的调试配置（只列 cortex-debug 能识别的那类也一并列出）。"""
    if path and os.path.isfile(os.path.abspath(os.path.expanduser(path))):
        r = read_launch_json(path)
    else:
        f = find_launch_json(path)
        if not f.get("ok"):
            return f
        r = read_launch_json(f["path"])
    if not r.get("ok"):
        return r
    ws = os.path.dirname(os.path.dirname(r["path"]))
    items = []
    for c in r["configurations"]:
        if not isinstance(c, dict):
            continue
        items.append({
            "name": c.get("name"), "type": c.get("type"),
            "servertype": c.get("servertype"), "device": c.get("device"),
            "interface": c.get("interface"),
            "executable": _expand(c.get("executable"), ws),
            "configFiles": c.get("configFiles"),
            "svdFile": _expand(c.get("svdFile"), ws),
            "openocd_like": _is_openocd(c),
        })
    return {"ok": True, "path": r["path"], "workspace": ws,
            "count": len(items), "configurations": items,
            "note": "openocd_like=true 的配置可以直接借来组 ocd_start 参数；"
                    "其它 servertype（jlink/pyocd/stlink）只能借芯片型号与可执行文件"}


def _is_openocd(cfg: dict) -> bool:
    """servertype 是不是 openocd。只有它才谈得上「直接借来启动」。"""
    return str(cfg.get("servertype") or "").lower() == "openocd"


def _pick_profile(device: str, executable: str) -> dict:
    """由 device 名（或可执行文件）挑一份目标档案；挑不到就如实说挑不到。"""
    by = []
    if device:
        g = _targets.guess_from_name(device)
        if g.get("ok"):
            by = list(g["profiles"])
    if not by and executable and os.path.isfile(executable):
        g = _targets.guess_from_elf(executable)
        if g.get("ok"):
            by = [p for p in (g.get("profile_candidates") or [])
                  if p in _targets.PROFILES]
    if not by:
        return {"profile": "", "profile_source": None,
                "profile_reason": "device=%r 在档案表里没有匹配项，也没能从 ELF 推出"
                                  % (device or "")}
    return {"profile": by[0], "profile_source": "device" if device else "elf",
            "profile_alternatives": by[:5]}


def resolve_config(path: str = "", name: str = "", start_dir: str = "") -> dict:
    """把一份 launch.json 配置解析成「能喂给 ocd_start / 工具链」的参数。

    返回值里一定有 `config_source`：逐字段说明来源（launch.json 的哪个键 /
    档案默认值 / 用户显式参数），避免出现「看着像权威结果、其实是猜的」。
    """
    if path:
        r = read_launch_json(path)
    else:
        f = find_launch_json(start_dir)
        if not f.get("ok"):
            return f
        r = read_launch_json(f["path"])
    if not r.get("ok"):
        return r
    ws = os.path.dirname(os.path.dirname(r["path"]))
    cfgs = [c for c in r["configurations"] if isinstance(c, dict)]
    if not cfgs:
        return {"ok": False, "error": "launch.json 里没有可用的配置", "path": r["path"]}
    chosen, how = None, None
    if name:
        for c in cfgs:
            if str(c.get("name") or "") == name:
                chosen, how = c, "name 精确匹配"
                break
        if chosen is None:
            for c in cfgs:
                if name.lower() in str(c.get("name") or "").lower():
                    chosen, how = c, "name 模糊匹配"
                    break
        if chosen is None:
            return {"ok": False, "error": "没有名为 %r 的配置" % name,
                    "path": r["path"],
                    "available": [c.get("name") for c in cfgs]}
    else:
        for c in cfgs:
            if _is_openocd(c):
                chosen, how = c, "第一个 servertype=openocd 的配置"
                break
        if chosen is None:
            chosen, how = cfgs[0], "默认取第一个配置（没有 openocd 配置）"

    search_dirs = [ws]
    if isinstance(cfg_sd := chosen.get("searchDir"), list):
        search_dirs += [_expand(x, ws) for x in cfg_sd if isinstance(x, str)]
    exe = _expand(chosen.get("executable"), ws, search_dirs)
    device = str(chosen.get("device") or "")
    pr = _pick_profile(device, exe)

    cfgs_files = [str(x) for x in (chosen.get("configFiles") or [])
                  if isinstance(x, str)]
    iface = ""
    tgt = ""
    extra = []
    for cf in cfgs_files:
        low = cf.lower().replace("\\", "/")
        if "interface" in low and not iface:
            iface = cf
        elif "target" in low and not tgt:
            tgt = cf
        else:
            extra.append(cf)

    src = {
        "name": "launch.json:%s" % chosen.get("name"),
        "file": r["path"],
        "workspace": ws,
        "chosen_by": how,
        "servertype": chosen.get("servertype"),
        "device": device or None,
        "interface_cfg": iface or None,
        "target_cfg": tgt or None,
        "executable": exe or None,
        "svd": _expand(chosen.get("svdFile"), ws) or None,
        "arm_toolchain_path": _expand(chosen.get("armToolchainPath"), ws) or None,
        "profile": pr.get("profile") or None,
        "profile_from": pr.get("profile_source"),
        "unexpanded_keys": sorted(k for k in _KEYS
                                  if isinstance(chosen.get(k), str)
                                  and "${" in str(chosen.get(k))),
    }
    return {"ok": True, "path": r["path"], "workspace": ws,
            "config": {k: chosen.get(k) for k in _KEYS if k in chosen},
            "resolved": {
                "profile": pr.get("profile") or "",
                "profile_alternatives": pr.get("profile_alternatives") or [],
                "interface": iface, "target": tgt, "extra_cfg": extra,
                "transport": (str(chosen.get("interface") or "").lower() or None),
                "executable": exe or "", "svd": src["svd"] or "",
                "toolchain_path": src["arm_toolchain_path"] or "",
                "openocd_serverpath": _expand(chosen.get("serverpath"), ws) or "",
                "launch_commands": chosen.get("openOCDLaunchCommands") or [],
            },
            "config_source": src,
            "servertype_is_openocd": _is_openocd(chosen),
            "note": (None if _is_openocd(chosen) else
                     "该配置的 servertype=%s 不是 OpenOCD：只能借出芯片型号/接口/"
                     "可执行文件，OpenOCD 启动参数请用 target_list + ocd_cfg_list 组"
                     % chosen.get("servertype")),
            "profile_reason": pr.get("profile_reason")}


def guess_from_workspace(start_dir: str = "", name: str = "") -> dict:
    """给 ocd_start 用的自动补充：从工程现场的 launch.json 推 profile/interface/target。

    只在**调用方一个连接参数都没给**时被用到；任何一步失败都返回 ok=False
    并说明原因，由调用方决定是否报错——不静默换一套参数。
    """
    r = resolve_config(name=name, start_dir=start_dir)
    if not r.get("ok"):
        return r
    if not r.get("servertype_is_openocd"):
        return {"ok": False, "found": True, "path": r.get("path"),
                "error": "工程里的 launch.json 不是 OpenOCD 配置（servertype=%s）"
                         % ((r.get("config") or {}).get("servertype")),
                "resolved": r.get("resolved")}
    res = r["resolved"]
    if not res.get("profile") and not (res.get("interface") and res.get("target")):
        return {"ok": False, "found": True, "path": r.get("path"),
                "error": "launch.json 里既没推出档案、也没给出 interface/target cfg",
                "config_source": r.get("config_source")}
    return {"ok": True, "found": True, "path": r.get("path"),
            "profile": res.get("profile") or "",
            "interface": res.get("interface") or "",
            "target": res.get("target") or "",
            "transport": res.get("transport") or "",
            "extra_cfg": res.get("extra_cfg") or [],
            "executable": res.get("executable") or "",
            "svd": res.get("svd") or "",
            "config_source": r.get("config_source"),
            "note": "参数来自工程现场的 launch.json（不是档案默认值），"
                    "config_source.file 是出处；要覆盖就显式传参"}


# ---------------------------------------------------------------- MCP 注册

def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    """注册工程配置发现工具。"""
    _js = js or _default_js
    n = 0

    @server.tool(
        name="debug_config",
        title="从工程现场发现调试配置（.vscode/launch.json / cortex-debug）",
        description=(
            "GCC 工程里通常已经写过一份 VS Code 调试配置，里面 device / interface / "
            "configFiles / executable / svdFile 都是现成的。本工具把它解析出来，"
            "直接给出可喂给 ocd_start 的 profile / interface / target cfg，"
            "省掉「猜 cfg 名 → 猜错 → 再猜」那一轮。\n"
            "用法：不传 path 就从当前目录向上找最近的 .vscode/launch.json；"
            "传 name 挑具体哪个配置（不传则取第一个 servertype=openocd 的）。\n"
            "**返回值里的 config_source 一定看**：它逐字段说明参数是从 "
            "launch.json 的哪个键来的、还是回落到档案默认值——"
            "不要把这些参数当成引擎自己推断的结果。"
            "servertype 不是 openocd（jlink/pyocd/stlink）时会明确说明只能借出"
            "芯片型号与可执行文件，不会硬翻译成一份 OpenOCD 启动参数。"
        ),
    )
    async def debug_config(path: str = "", name: str = "",
                           start_dir: str = "", list_only: bool = False) -> str:
        try:
            if list_only:
                return _js(list_configs(path or start_dir))
            return _js(resolve_config(path=path, name=name, start_dir=start_dir))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
