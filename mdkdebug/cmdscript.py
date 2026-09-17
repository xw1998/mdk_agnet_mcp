# -*- coding: utf-8 -*-
"""UV4 命令行批处理调试（``-d`` + 初始化文件）——"cmd 指令方式"通道。

为什么单独做一条通道
--------------------
UVSOCK 是**交互式**通道：一步一请求、可以中途改主意，但它要求 Keil 处于
调试态、且贵（每条命令一个往返）。本模块走的是 Keil 官方的**批处理**通道：

    UV4.exe -d <工程> -j0 -o <日志>        # -d = 进入调试并执行初始化文件

官方手册对 ``-d`` 的定义就是 *for automated test procedures*——把一串调试命令
写进 **Initialization File（初始化文件）**，UV4 启动后自动进调试、依次执行、遇
``EXIT`` 退出。适合**可重复的固定脚本**（冒烟、回归、复位后现场采集），不依赖
UVSOCK 是否开启，也就不受"连接被占/空闲断连"影响。

真机实测结论（docs/PITFALLS.md 第七章，本机 mdk_test 上 10 轮实验）
-------------------------------------------------------------------
可用：``g, main`` 运行到 main、``BS <符号>`` / ``BL``、``G`` 阻塞到断点命中、
``T``/``P``/``O`` 单步、``EVAL``、``printf``、``_RDWORD(addr)``、``LOG >>file``、``BK *``。

**必须绕开的坑**：
1. ``Go main`` / ``Go`` 会**挂死**（官方语法是 ``g, main``，逗号不可省）；
2. ``DISPLAY`` / ``SAVE`` 在 ``-j0`` 无头模式下**挂死**（读内存改用
   ``printf`` + ``_RDWORD``）；
3. 命令报错**不改退出码**（UV4 恒回 0），成败只能看日志里的
   ``*** error N, line M: message``；
4. 无窗口焦点时单步退化为**指令级**（``T`` 会进到函数里逐条指令走）；
5. 每轮 15~25s（含进调试 + Erase/Program/Verify），比 UVSOCK 慢得多。
故本通道与 UVSOCK 是**互补**关系：脚本化冒烟/回归用它，交互式排查用 UVSOCK。
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile

from . import uvoptx as _uvoptx

# 初始化文件里的挂载点（硬件调试用 tIfile，仿真用 sIfile）
_TIFILE_RE = re.compile(r"<tIfile>.*?</tIfile>", re.S)
# 命令窗口报错：`*** error 34, line 11: undefined identifier`
# re.M 不能省：`$` 默认只匹配整个字符串末尾，而真机日志里报错行后面必然还有别的行，
# 少了 re.M 会一条 error 都匹配不到（实测把 ok 误判成 True）。
_ERR_RE = re.compile(r"\*\*\*\s*error\s+(\d+)\s*(?:,\s*line\s*(\d+))?\s*[:：]?\s*(.*)$",
                     re.M)
# 每条命令后插入的完成标记
_DONE_RE = re.compile(r"__mdkdebug_done_(\d+)__")

# 官方语法陷阱：这些写法真机会挂死，提前拦下并把正确写法告诉调用方
_FORBIDDEN = [
    (re.compile(r"^go(\s+main)?\s*$", re.I),
     "`Go` / `Go main` 会让 UV4 挂死；官方语法是 `g, main`（逗号不可省），"
     "或 `g` 从当前 PC 继续"),
    (re.compile(r"^(display|save)\b", re.I),
     "`DISPLAY` / `SAVE` 在 -j0 无头模式下会挂死；读内存请用 `printf(\"%08X\", _RDWORD(0x地址))`"),
    (re.compile(r"^(step|tstep|pstep|ostep)\b", re.I),
     "单步的官方缩写是 `T`(进) / `P`(过) / `O`(出)；`Step`/`Tstep`/`Pstep` 会报 "
     "`*** error 34: undefined identifier`"),
]

# 硬门槛：这些命令会**永久**改变工程/整机状态，不适合放进无人值守脚本
def _split_commands(commands) -> list:
    """接受 list[str] 或换行分隔的字符串，去空行与注释行。"""
    if isinstance(commands, str):
        raw = commands.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    else:
        raw = []
        for c in (commands or []):
            raw.extend(str(c).replace("\r\n", "\n").replace("\r", "\n").split("\n"))
    out = []
    for line in raw:
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("//"):
            continue
        out.append(s)
    return out

def lint_commands(commands) -> list:
    """静态检查命令清单，返回告警列表（不阻断，交给调用方决定）。"""
    warns = []
    for i, c in enumerate(commands or []):
        for pat, msg in _FORBIDDEN:
            if pat.match(c.strip()):
                warns.append({"index": i, "command": c, "warning": msg})
                break
    cmds = [c.strip().upper() for c in (commands or [])]
    if cmds.count("EXIT") == 0:
        warns.append({"warning": "脚本没有 EXIT：UV4 会停在里面不退出，最终超时被杀。"
                                 "本工具会自动补一条 EXIT。"})
    return warns

def run_debug_script(uv4: str, project: str, commands, timeout: int = 240,
                     visible: bool = False, extra_args: list | None = None) -> dict:
    """执行一段 UV4 ``-d`` 批处理调试脚本，返回结构化结果。

    实现要点：
    - 初始化文件与 trace 日志都写在**系统临时目录**（ASCII 路径）——真机实测中文路径
      写入会 UnicodeEncodeError；
    - 往 ``.uvoptx`` 的 ``<tIfile>`` 挂载初始化文件，**前置备份、finally 还原**
      （Keil 退出会回写 uvoptx，不还原会污染工程）；
    - 每条命令后插一条 ``printf("__mdkdebug_done_N__")``，用于判断"这条到底执行到没有"
      （命令报错不会中断脚本，光看 error 行无法区分"没执行"与"执行了但失败"）；
    - 成败判定**只认日志**：UV4 退出码恒为 0，必须解析 ``*** error N, line M``。
    """
    from .builder import _run_uv4          # 复用其 PATH 注入 / 隐藏窗口逻辑

    res = {"ok": False, "channel": "uv4-cmdline", "project": project,
           "commands": [], "errors": [], "warnings": [], "artifacts": {}}
    if not uv4:
        res["error"] = "未定位到 UV4.exe（构建/批处理通道不可用）"
        return res
    if not project or not os.path.isfile(project):
        res["error"] = "工程文件不存在：%s" % project
        return res

    cmds = _split_commands(commands)
    if not cmds:
        res["error"] = "命令清单为空"
        return res
    res["warnings"].extend(lint_commands(cmds))
    if not any(c.strip().upper() == "EXIT" for c in cmds):
        cmds = cmds + ["EXIT"]

    uvoptx_path = _uvoptx.uvoptx_path_for(project)
    if not os.path.isfile(uvoptx_path):
        res["error"] = ("未找到 %s —— 初始化文件是挂在 .uvoptx 的 <tIfile> 上的，"
                        "缺这个文件无法走 -d 批处理通道" % uvoptx_path)
        return res

    # 1) 读原 uvoptx（编码容错），稍后还原
    #    还原必须**按原始字节**写回：文本读-写会带来 BOM/换行的可观差异
    #    （实测 utf-8-sig 读入再写出会凭空多一个 BOM，工程文件被悄悄改动）。
    try:
        with open(uvoptx_path, "rb") as f:
            raw_before = f.read()
        original, enc = _uvoptx._read_text(uvoptx_path)
    except Exception as e:  # noqa: BLE001
        res["error"] = "读取 .uvoptx 失败：%s" % e
        return res

    workdir = tempfile.mkdtemp(prefix="mdkdebug_cmd_")
    ini_path = os.path.join(workdir, "init.ini")
    trace_path = os.path.join(workdir, "trace.log")
    res["artifacts"].update({"workdir": workdir, "init_file": ini_path,
                             "trace_log": trace_path})

    # 2) 生成初始化文件
    lines = ["LOG >>%s" % trace_path]
    index_of_line = {}          # ini 行号(1基) -> 命令序号
    for i, c in enumerate(cmds):
        index_of_line[len(lines) + 1] = i
        lines.append(c)
        lines.append('printf("__mdkdebug_done_%d__")' % i)
    lines.append("LOG OFF")
    text = "\r\n".join(lines) + "\r\n"
    non_ascii = [c for c in cmds if any(ord(ch) > 127 for ch in c)]
    if non_ascii:
        res["warnings"].append(
            {"warning": "命令含非 ASCII 字符，初始化文件按 ASCII 写入可能被替换：%s"
                        % non_ascii[:3]})
    try:
        with open(ini_path, "w", encoding="ascii", errors="replace", newline="") as f:
            f.write(text)
    except OSError as e:
        res["error"] = "写入初始化文件失败：%s" % e
        return res

    # 3) 挂载到 <tIfile>（锚点唯一性必须校验，否则会改坏工程）
    # 唯一性必须**先数再换**：subn(count=1) 的返回值恒为 1（只要有一处匹配），
    # 拿它当"唯一性校验"是假的——多 target 的 uvoptx 常常有多个 <tIfile>。
    hits = list(_TIFILE_RE.finditer(original))
    if len(hits) != 1:
        res["error"] = ("未在 %s 里找到唯一的 <tIfile> 节点（找到 %d 个），"
                        "拒绝改写工程文件以免损坏；可先用 list_uvoptx_breakpoints "
                        "确认工程与 target 是否正确" % (uvoptx_path, len(hits)))
        return res
    patched = _TIFILE_RE.sub(lambda m: "<tIfile>%s</tIfile>" % ini_path,
                             original, count=1)
    res["uvoptx"] = {"path": uvoptx_path, "encoding": enc, "restored": False}

    try:
        with open(uvoptx_path, "w", encoding=enc, errors="replace", newline="") as f:
            f.write(patched)
    except OSError as e:
        res["error"] = "改写 .uvoptx 失败：%s" % e
        return res

    # 4) 跑 UV4 -d（-o 由 builder 统一附加）
    args = ["-d", project, "-j0"] + list(extra_args or [])
    res["argv"] = " ".join([os.path.basename(uv4)] + args)
    try:
        code, out_text = _run_uv4(uv4, args, timeout, visible=visible)
    except TypeError:
        code, out_text = _run_uv4(uv4, args, timeout); visible = False
    finally:
        # 5) 还原 uvoptx（无论成败）——Keil 退出会把内存里的设置回写，不还原就是脏工程
        #    字节级还原，保证「跑完 == 没跑过」。
        try:
            with open(uvoptx_path, "wb") as f:
                f.write(raw_before)
            res["uvoptx"]["byte_identical"] = (
                open(uvoptx_path, "rb").read() == raw_before)
            res["uvoptx"]["restored"] = True
        except OSError as e:  # noqa: BLE001
            res["warnings"].append({"warning": "还原 .uvoptx 失败：%s" % e})

    res["exit_code"] = code
    res["timed_out"] = (code == -1)

    # 6) 解析 trace 日志（主证据）与 -o 日志（兜底）
    trace_text = ""
    try:
        if os.path.isfile(trace_path):
            with open(trace_path, encoding="utf-8", errors="replace") as f:
                trace_text = f.read()
    except OSError:
        pass
    if not trace_text.strip():
        res["warnings"].append(
            {"warning": "初始化文件的 LOG 没有产出内容（可能第一条命令就卡住/UV4 未进调试），"
                        "已退回解析 UV4 自身的 -o 日志；信息量会少很多"})
    combined = (trace_text or "") + "\n" + (out_text or "")
    res["log_source"] = "init-file LOG" if trace_text.strip() else "UV4 -o log"

    done = {int(m.group(1)) for m in _DONE_RE.finditer(combined)}
    errors = []
    for m in _ERR_RE.finditer(combined):
        code_n, line_n, msg = m.group(1), m.group(2), (m.group(3) or "").strip()
        idx = None
        if line_n:
            ln = int(line_n)
            # 报错行可能是命令行本身，也可能是它后面那条 printf 行
            idx = index_of_line.get(ln, index_of_line.get(ln - 1))
        errors.append({"code": int(code_n), "line": (int(line_n) if line_n else None),
                       "message": msg, "command_index": idx,
                       "command": (cmds[idx] if idx is not None and idx < len(cmds) else None),
                       "text": m.group(0).strip()})
    # trace 与 -o 日志会就同一条报错各记一份，必须去重，否则 error_count
    # 翻倍、AI 会以为踩了两个坑。按 (码, 行, 文本) 保序去重。
    seen_err, uniq = set(), []
    for e in errors:
        key = (e["code"], e["line"], e["text"])
        if key in seen_err:
            continue
        seen_err.add(key)
        uniq.append(e)
    res["errors"] = uniq
    res["error_count"] = len(uniq)

    items = []
    for i, c in enumerate(cmds):
        items.append({"index": i, "command": c,
                      "completed": i in done,
                      "errors": [e for e in errors if e.get("command_index") == i]})
    res["commands"] = items
    res["completed"] = sum(1 for it in items if it["completed"])
    res["pending"] = [it["command"] for it in items if not it["completed"]]

    # 7) 结论：命令报错不改退出码，故 ok = 无 error 且所有命令都走到完成标记
    res["ok"] = (not errors) and res["completed"] == len(items) and not res["timed_out"]
    if res["timed_out"]:
        res["error"] = ("UV4 未在 %d 秒内退出（已终止）。无头模式最容易挂死的是 "
                        "DISPLAY / SAVE / `Go main`——请核对命令；"
                        "并把 trace_log / init_file 路径留作现场。" % timeout)
    elif errors:
        res["error"] = "脚本执行中出现 %d 条命令报错（注意：UV4 退出码恒为 0，只有本字段能反映失败）" % len(errors)
    elif res["completed"] != len(items):
        res["error"] = "有 %d 条命令没有走到完成标记（可能被卡住或脚本中途结束）" % (
            len(items) - res["completed"])
    res["log_tail"] = "\n".join((combined or "").strip().splitlines()[-25:])
    res["next_actions"] = []
    if errors:
        res["next_actions"].append("把 errors[].code / text 交给 explain_build_error"
                                   "（kind=command）拿到含义与处置")
    if res["timed_out"]:
        res["next_actions"].append("核对是否用了 DISPLAY/SAVE/`Go main` 这类会挂死的写法")
    if not res["ok"] and not res["timed_out"] and not errors:
        res["next_actions"].append("看 log_tail 与 artifacts.trace_log 现场；"
                                   "也可以改用 UVSOCK 通道（enter_debug + keil_command）逐步排查")
    return res

def cleanup_workdir(path: str) -> bool:
    """删除本次运行的工作目录（调用方在用户同意后手工清理时使用）。"""
    try:
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            return not os.path.isdir(path)
    except OSError:
        pass
    return False
