# -*- coding: utf-8 -*-
"""「这是证据，不是代码」——生成物的硬标记与落盘位置护栏。

真机反馈：`src/pseudo_c.c` 长得太像源码，AI/人顺手把它挂进工程，编译通过了一部分，
于是整个工程变成 `Ported/`（一半真源码、一半寄存器级提升），后续没人分得清哪行是证据。

三条措施（缺一不可）：

1. **文件里带硬标记**：`pseudo_c.c` 头注释写明 evidence_only，并带
   `#error` 编译期闸门——不显式定义 `MDKDEBUG_ALLOW_EVIDENCE_ONLY` 就**编不过**，
   杜绝「悄悄编进去」；
2. **元数据带机读标志**：`report.json` / `manifest.json` 里 `evidence_only: true`，
   逐文件也带；
3. **落盘位置护栏**：目标目录是源码/构建目录（`App/`、`Core/`、`Src/`、`Drivers/`…）
   或位于某个真实 Keil 工程目录内时，**直接拒绝**，让调用方换一个独立目录。

护栏只在**调用方指定目标目录**的入口生效；本服务自己往证据目录里写 `src/pseudo_c.c`
不受影响（那本来就是证据目录，`report.json` 在那儿）。
"""

from __future__ import annotations

import os
import tempfile

# 这些目录名是「真工程」的源码/构建目录：证据产物落进去，就会和源码混成人造 Ported/
BLOCK_DIRS = {
    "app", "application", "applications", "core", "src", "source", "sources",
    "inc", "include", "includes", "user", "main", "hal", "bsp",
    "drivers", "driver", "middlewares", "middleware", "components", "lib",
    "libraries", "cmsis", "startup", "obj", "objects", "output", "build",
}

PROJECT_SUFFIXES = (".uvprojx", ".uvoptx", ".uvmpw", ".ioc", ".ewp", ".eww")

# 「这个目录里真的装着源码」的证据：有这些文件才把目录名当构建目录看。
# 只看名字会误伤：证据产物自己的布局就是 `<out>/src/pseudo_c.c`，
# 而临时目录里一个空 `src/` 也常被拿来做别的事（批次101 自测踩到）。
SOURCE_SUFFIXES = (".c", ".h", ".cpp", ".hpp", ".cc", ".s", ".asm", ".icf", ".sct")
EVIDENCE_FILES = ("report.json", "manifest.json")

# 编译期闸门：没有显式开关就编不过。这是「标记」与「真的不让编」的分界。
C_GUARD = """\
#ifndef MDKDEBUG_ALLOW_EVIDENCE_ONLY
#error "pseudo_c.c is a mdkdebug evidence artifact (evidence_only=true), NOT source code. Define MDKDEBUG_ALLOW_EVIDENCE_ONLY only if you really mean to compile evidence."
#endif
"""


def _shared_roots() -> set:
    """「共享/临时根」：这些目录不是工程边界，里面的 .uvprojx 不能当证据落盘的拦截依据。

    真机反例（批次101 自测踩到的）：``%TEMP%`` 里留着一个 ``mix.uvprojx``（别的测试/别的工具
    留下的），于是 ``%TEMP%`` 下**任何**新目录都被判成「位于 Keil 工程内」，出件全被拒。
    自家 home 也一样：谁把工程放在桌面/用户目录下，整个用户目录就都成了禁区。
    """
    roots = set()
    for raw in (tempfile.gettempdir(),
                os.path.expanduser("~"),
                os.environ.get("TEMP"), os.environ.get("TMP"),
                os.environ.get("TMPDIR")):
        if raw:
            try:
                roots.add(os.path.normcase(os.path.abspath(raw)))
            except OSError:
                pass
    return roots


def is_evidence_dir(path: str) -> bool:
    """本服务自己的证据目录（有 report.json / manifest.json）。"""
    d = os.path.abspath(path or ".")
    return any(os.path.isfile(os.path.join(d, name)) for name in EVIDENCE_FILES)


def _looks_like_source_dir(path: str) -> bool:
    """目录里是否真的有源码/工程文件（只看一层，够用且不慢）。"""
    try:
        names = os.listdir(path)
    except OSError:
        return False
    for name in names:
        low = name.lower()
        if low.endswith(PROJECT_SUFFIXES) or low.endswith(SOURCE_SUFFIXES):
            return True
    # 一层子目录：`App/Src`、`Core/Inc` 这种「代码在下一层」的布局也算（工程常见样子）
    for name in names:
        if name.lower() in BLOCK_DIRS and os.path.isdir(os.path.join(path, name)):
            return True
    return False


def _has_project_file(path: str) -> str:
    try:
        names = os.listdir(path)
    except OSError:
        return ""
    for name in names:
        if name.lower().endswith(PROJECT_SUFFIXES):
            return os.path.join(path, name)
    return ""


def violation(target: str, *, depth: int = 3) -> dict | None:
    """目标目录是否「不该放证据产物」。返回 None=允许，否则返回可机读的原因。

    判据（任一命中即拒绝）：

    - 目标目录自身或近 3 级父目录里存在 `.uvprojx` / `.uvoptx` / `.ioc` 等工程文件，
      且目标目录本身不是本服务的证据目录（没有 `report.json` / `manifest.json`）；
    - 目标目录名属于 ``BLOCK_DIRS``（`App` / `Core` / `Src` / `Drivers` …），
      且不是证据目录；
    - 目标目录**在**这样一个源码目录之内（如 `Core/Src/rep`）：新起的子目录名不会
      命中 BLOCK_DIRS，但产物照样落在源码树里，一样会被顺手挂进工程。
    """
    d = os.path.abspath(target or ".")
    if is_evidence_dir(d):
        return None
    shared = _shared_roots()
    cur, hops, proj, srcdir = d, 0, "", ""
    while cur and hops <= depth:
        if os.path.normcase(cur) in shared:
            break                     # 到共享根就停：这里不是工程边界
        proj = _has_project_file(cur)
        if proj:
            break
        # 只看**目录自己的名字**是否像构建目录：`C:\Users\...` 里那个 `Users`
        # 不是构建目录，按祖先判会把整块磁盘都判成禁区（批次101 自测踩到的假阳性）。
        leaf = os.path.basename(os.path.normpath(cur))
        if leaf.lower() in BLOCK_DIRS and _looks_like_source_dir(cur):
            srcdir = cur
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur, hops = parent, hops + 1
    if proj:
        return {"code": "evidence-in-build-dir", "target": d,
                "project_file": proj,
                "reason": "目标目录位于 Keil 工程内（找到 %s）" % os.path.basename(proj)}
    if srcdir:
        leaf = os.path.basename(os.path.normpath(srcdir))
        if os.path.normcase(srcdir) == os.path.normcase(d):
            reason = "目标目录名 `%s` 且里面确实有源码" % leaf
        else:
            reason = ("目标目录位于源码目录 `%s` 之内（该目录里确实有源码）"
                      % srcdir)
        return {"code": "evidence-in-build-dir", "target": d,
                "blocked_component": leaf,
                "reason": reason}
    return None


def refusal(target: str, v: dict) -> dict:
    """把 ``violation`` 的结果变成工具返回（带明确的下一步）。"""
    return {
        "ok": False,
        "error_code": v["code"],
        "error": "拒绝把证据产物写进工程目录：%s（%s）" % (v["target"], v["reason"]),
        "hint": "证据产物（伪 C / 反汇编 / 重建骨架）一律放到**独立目录**，"
                "例如 `<工程>/recovered/` 或磁盘上任何不在源码树里的位置；"
                "它带 `evidence_only` 标记与编译期闸门，本来就不该和 App/、Core/ 混在一起。",
        "evidence_only": True,
    }
