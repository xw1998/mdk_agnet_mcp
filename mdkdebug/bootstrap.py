# -*- coding: utf-8 -*-
"""启动期环境隔离：宿主污染 `PYTHONPATH` / `PYTHONHOME` 时自愈，不把坑留给使用者。

真实事故：MCP 宿主把自己的 Python 环境变量传给了子进程，`PYTHONPATH` 指到另一套
标准库上。本服务 `import re` 时拿到的是**别人的** `re.py`，`_sre` 版本对不上，
于是还没进主程序就崩：

    ImportError: cannot import name 'SRE_Pattern'
    # 或 RuntimeError: SRE module mismatch / No module named 'sre_constants'

使用者的绕法是在启动命令前手写 `env -u PYTHONPATH -u PYTHONHOME`——这不该由使用者承担。

做法：**在任何会 import `re` 的模块之前**检查环境；一旦发现 `PYTHON*` 变量，就用
`-E -s`（忽略 PYTHON* 变量、不加载 user site）重新 exec 自己一次，argv 与 stdio 原样
带过去（`os.execve` 不换 PID，MCP 的 stdin/stdout 管道仍然有效）。

两条边界，如实写明：

- 如果 python **在解释器初始化阶段**就死了（连本文件都执行不到），进程内无解，
  只能由调用方给干净环境；这是 CPython 的启动顺序决定的，不是本模块能绕开的。
- 之所以用 `-E -s` 而不是 `-I`：CPython 3.11 起 `-I` 隐含 `-P`，会把**脚本所在目录**
  从 `sys.path` 里去掉，于是未安装的源码树（`python run_server.py`）反而找不到自己。
"""

from __future__ import annotations

import os
import sys

GUARD_VAR = "MDKDEBUG_ENV_CLEAN"       # 已重启过 / 环境本来就干净
SKIP_VAR = "MDKDEBUG_NO_REEXEC"        # 调试用：禁止自愈式重启

# 会改变**模块搜索路径 / stdlib 位置**的变量：这些才需要剥（真机崩的就是 PYTHONPATH）。
STRIP_VARS = {
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
    "PYTHONUSERBASE", "PYTHONNOUSERSITE", "PYTHONPLATLIBDIR", "PYTHONSAFEPATH",
}

# 只管 IO/缓冲、不影响 import 的变量：**保留**（剥掉会改变 stdout 编码，
# MCP 的 JSON 里带中文时会被本地代码页写成乱码）。
KEEP_VARS = {
    "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONUNBUFFERED",
    "PYTHONLEGACYWINDOWSFSENCODING", "PYTHONLEGACYWINDOWSSTDIO",
}


def pollution(env: dict | None = None) -> dict:
    """返回环境里会污染解释器模块搜索的变量（键名原样保留）。"""
    env = os.environ if env is None else env
    return {k: v for k, v in env.items()
            if k.upper() in STRIP_VARS and k.upper() not in KEEP_VARS}


def clean_env(env: dict | None = None) -> dict:
    """剥掉污染变量，并打上「已经隔离过」的守卫（防止无限重启）。"""
    out = dict(os.environ if env is None else env)
    for k in list(out):
        ku = k.upper()
        if ku in STRIP_VARS and ku not in KEEP_VARS:
            out.pop(k, None)
    out.pop(SKIP_VAR, None)
    out[GUARD_VAR] = "1"
    return out


def configure_stdio() -> None:
    """把 stdio 固定成 UTF-8。

    `-E`（隔离重启）会让子进程**忽略 PYTHONIOENCODING / PYTHONUTF8**，Windows 上
    默认回到本地代码页（cp936）。MCP 说的是 UTF-8 JSON，中文一多就会变成问号——
    所以不靠环境变量，直接 reconfigure。
    """
    for name, errs in (("stdin", "replace"), ("stdout", "strict"), ("stderr", "replace")):
        stream = getattr(sys, name, None)
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors=errs)
        except Exception:                              # noqa: BLE001
            pass


def is_isolated(env: dict | None = None) -> bool:
    """当前进程是否已经是干净环境（-E 生效过，或本模块已经重启过一次）。"""
    if getattr(sys.flags, "ignore_environment", False):
        return True
    env = os.environ if env is None else env
    return str(env.get(GUARD_VAR) or "") == "1"


def reexec_command(argv: list | None = None, exe: str | None = None) -> list:
    """构造自愈用的命令行（`-E -s` + 原 argv 形态）。可单独测试，不执行。

    三种形态分开处理：

    - `python -m mdkdebug`：``argv[0]`` 是包里的 `__main__.py`，**不能**当脚本路径重启
      （那样 `mdkdebug` 就不在 `sys.path` 上），必须保持 `-m mdkdebug`；
    - 真实脚本（`python run_server.py`）：按绝对路径重启；
    - `python -c`：没有可重启的脚本，退回模块入口。
    """
    argv = list(sys.argv if argv is None else argv)
    exe = exe or sys.executable
    if argv and os.path.basename(argv[0]).lower() == "__main__.py":
        return [exe, "-E", "-s", "-m", "mdkdebug"] + argv[1:]
    if argv and os.path.isfile(argv[0]):
        return [exe, "-E", "-s", os.path.abspath(argv[0])] + argv[1:]
    if argv[:1] == ["-c"]:
        # `python -c "..."`：`-c` 的代码不能跟着重启（重跑一遍会把业务再跑一次），
        # 只退回模块入口，剩下的参数原样带过去。
        return [exe, "-E", "-s", "-m", "mdkdebug"] + argv[2:]
    return [exe, "-E", "-s", "-m", "mdkdebug"] + argv[1:]


def ensure_isolated(argv: list | None = None, env: dict | None = None,
                    exe: str | None = None) -> dict:
    """污染环境下重启自己（不返回，除非 exec 失败）。

    返回的 dict 只在「没重启」时有用：
    ``{"reexeced": False, "reason": "clean"|"already-clean"|"skip", "stripped": [...]}``
    """
    env = os.environ if env is None else env
    stripped = sorted(pollution(env))
    info = {"reexeced": False, "stripped": stripped}
    if str(env.get(SKIP_VAR) or "") == "1":
        info["reason"] = "skip"
        return info
    if is_isolated(env):
        info["reason"] = "already-clean"
        return info
    if not stripped:
        info["reason"] = "clean"
        return info

    cmd = reexec_command(argv, exe)
    info["command"] = cmd
    info["reason"] = "reexec"
    try:
        sys.stderr.write("[mdkdebug] 检测到宿主 Python 环境变量污染：%s\n"
                         "           用隔离模式重启：%s\n"
                         % (", ".join(stripped), " ".join(cmd[:4]) + " ..."))
        sys.stderr.flush()
        sys.stdout.flush()
    except Exception:                                  # noqa: BLE001
        pass
    new_env = clean_env(env)
    if os.name == "nt":
        # Windows 上 `os.execv*` 会把 argv 用空格简单拼接，解释器路径里带空格
        # （真机：`C:\\Users\\...\\WPS 灵犀\\python-env\\python.exe`）就会被重新拆开，
        # 变成 "can't open file ...\灵犀\python-env\python.exe"。用 subprocess 传 list 才安全；
        # 子进程继承同一组 stdio，父进程等它结束并透传退出码即可（MCP 管道不受影响）。
        import subprocess
        info["reexeced"] = True
        raise SystemExit(subprocess.call(cmd, env=new_env))
    os.execve(cmd[0], cmd, new_env)                     # POSIX：直接换映像，不返回
    info["reexeced"] = True
    return info
