# -*- coding: utf-8 -*-
"""工具链层：GCC / make / cmake / ninja 的探测、环境注入与构建驱动。

面向「不依赖 MDK 的目标」——RISC-V、ESP32（Xtensa）、以及任何用 GCC 工具链
的 Cortex-M 工程。与 MDK 侧的关系：MDK 侧走 UV4/UVSOCK（builder.py），
本模块负责 GCC 世界；两者共用上层统一信封（server 的 _js / errors.normalize）
与输出控制（outctl），所以返回结构与 MDK 侧工具保持同一套约定。

三层结构：
  1. 探测（discover）——扫盘找工具链，拿到路径与版本；
  2. 环境（env）——把工具链 bin 目录注入本服务进程的 PATH，
     后续所有子进程（make / cmake / openocd）都能直接找到；
  3. 驱动（build / compile / objcopy / size）——真正跑构建与产物处理。

设计约束（踩过的坑）：
  - **探测必须带缓存**：一次全盘扫描上百个 exe 各跑一次 --version 要好几秒，
    版本探测按「路径 + mtime」缓存，进程内只探一次；
  - **绝不吞输出**：构建失败时 stdout/stderr 原样回传（带长度上限），
    错误另做结构化解析，让 AI 既能读原文也能按行号定位；
  - **命令一律走列表参数**（shell=False），不走字符串拼接，避免空格路径踩坑。
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import time

__all__ = [
    "FAMILIES", "discover", "find_tool", "find_gdb", "apply_env", "env_state",
    "run_tool", "detect_project", "build", "parse_gcc_output",
    "elf_info", "size_report", "objcopy", "register",
]

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- 家族定义
# prefix：该家族工具的前缀（arm-none-eabi-gcc 里的 arm-none-eabi-）
# dirs  ：在哪层目录找（相对工具链根的 glob，覆盖 xPack / 官方 / GCC ARM 官方包）
# 说明：dirs 只用于「提示性定位」，实际扫描是按目录树递归找 exe 再按前缀归类，
#       所以用户把包解压成什么形状都能被认出来。
FAMILIES = {
    "arm-none-eabi": {
        "title": "ARM Cortex-M GCC（arm-none-eabi）",
        "prefix": "arm-none-eabi-",
        "arch": "arm",
        "cpus": ["cortex-m0", "cortex-m0plus", "cortex-m3", "cortex-m4", "cortex-m7",
                 "cortex-m33", "cortex-a9"],
        "dirs": ["xpack-arm-none-eabi-gcc-*", "arm-none-eabi-gcc-*",
                 "gcc-arm-none-eabi-*", "arm-gnu-toolchain-*"],
        "note": "STM32 等 Cortex-M 主力工具链；也可编 Cortex-A/R",
    },
    "riscv-none-elf": {
        "title": "RISC-V GCC（riscv-none-elf）",
        "prefix": "riscv-none-elf-",
        "arch": "riscv",
        "cpus": ["rv32i", "rv32imac", "rv32imafc", "rv64imac"],
        "dirs": ["xpack-riscv-none-elf-gcc-*", "riscv-none-elf-gcc-*"],
        "note": "通用 RISC-V（含 RV32/RV64），OpenOCD 目标 cfg 配套",
    },
    "riscv32-esp-elf": {
        "title": "ESP32-C3/C6/H2 RISC-V GCC",
        "prefix": "riscv32-esp-elf-",
        "arch": "riscv",
        "cpus": ["rv32imc"],
        "dirs": ["riscv32-esp-elf-*"],
        "note": "乐鑫 RISC-V 版（ESP32-C3/C6/H2）；官方 crosstool-NG 包",
    },
    "xtensa-esp-elf": {
        "title": "ESP32/ESP32-S Xtensa GCC",
        "prefix": "xtensa-esp-elf-",
        "arch": "xtensa",
        "cpus": ["esp32", "esp32s2", "esp32s3"],
        "dirs": ["xtensa-esp-elf-*", "xtensa-esp32-elf-*"],
        "note": "乐鑫 Xtensa 版（ESP32 / S2 / S3）；官方 crosstool-NG 包",
    },
    "xtensa-esp32-elf": {
        "title": "ESP32 Xtensa GCC（旧命名 xtensa-esp32-elf）",
        "prefix": "xtensa-esp32-elf-",
        "arch": "xtensa",
        "cpus": ["esp32"],
        "dirs": ["xtensa-esp32-elf-*"],
        "note": "旧版 ESP-IDF 工具链命名，仅作兼容识别",
    },
    "make": {
        "title": "GNU Make",
        "prefix": None,
        "tools": ["make.exe", "make", "mingw32-make.exe", "mingw32-make"],
        "dirs": ["xpack-windows-build-tools-*", "make-*", "mingw*"],
        "note": "xPack windows-build-tools 里带；也可用系统里的 make",
    },
    "cmake": {
        "title": "CMake",
        "prefix": None,
        "tools": ["cmake.exe", "cmake"],
        "dirs": ["cmake-*"],
        "note": "Kitware 官方免安装 zip 解压即用",
    },
    "ninja": {
        "title": "Ninja",
        "prefix": None,
        "tools": ["ninja.exe", "ninja"],
        "dirs": ["ninja-*"],
        "note": "CMake 最快的生成器后端；没有时退化用 MinGW Makefiles",
    },
    "openocd": {
        "title": "OpenOCD",
        "prefix": None,
        "tools": ["openocd.exe", "openocd"],
        "dirs": ["xpack-openocd-*", "openocd-*"],
        "note": "调试/烧录/采集 trace 的后端；xPack 版自带大量 interface/target cfg",
    },
    "gdb": {
        "title": "GDB",
        "prefix": None,
        "suffixes": ["-gdb"],
        "dirs": ["esp-elf-gdb-*", "*gdb*"],
        "note": "批处理调试用（gdb -batch -ex ...）；一般跟工具链一起装",
    },
}

# 可直接运行的「安全」工具后缀白名单（toolchain_run 只放行这些）
_RUNNABLE_SUFFIXES = (
    "-gcc", "-g++", "-cpp", "-c++", "-clang", "-objcopy", "-objdump", "-size",
    "-nm", "-readelf", "-ar", "-ranlib", "-strip", "-ld", "-as", "-gdb", "-gcov",
)
_RUNNABLE_EXACT = ("make", "mingw32-make", "cmake", "ctest", "ninja", "python",
                   "python3", "bash", "sh", "elf2bin")
# 上面那串后缀只覆盖「标准名」。ESP 官方包里的 gdb 叫 xtensa-esp-elf-gdb-no-python /
# -gdb-3.12 这类**带变体或版本尾巴**的名字（find_gdb 挑出来的就是它们），光按后缀
# 比对会把自家选出来的工具判成「不在白名单」（曾真踩：find_gdb 给了 -no-python，
# run_tool 当场拒跑）。这里补一条正则把尾巴也认了。
_RUNNABLE_RE = re.compile(
    r"-(?:gcc|g\+\+|cpp|c\+\+|clang|objcopy|objdump|size|nm|readelf|ar|ranlib|"
    r"strip|ld|as|gdb|gcov)(?:-no-python|-py\d?|-\d+(?:\.\d+)*)?$", re.I)

_VERSION_ARGS = {
    "make": ["--version"],
    "mingw32-make": ["--version"],
}
# 运行期失败特征：这些 exe「起得来、退出码 0」但根本没正常跑（只在 stdout 上露馅）。
# 用途：探测可用性别只看退出码。本机见过 exe 只打一行运行时错误就退出、rc 仍为 0，
# 这种必须按输出特征判掉，否则 toolchain_list 会把它当可用工具报出去。
_BROKEN_RE = re.compile(
    r"(Python path configuration|Fatal Python error|"
    r"could not find (?:the )?interpreter|"
    r"not a valid Win32 application|"
    r"unable to start correctly|"
    r"is not recognized as an internal or external command)",
    re.I)

# gdb 键的挑选顺序：gdb → gdb-no-python → gdb-<版本>（高版本优先）
_GDB_KEY_RE = re.compile(r"^gdb(-no-python|-\d+(?:\.\d+)*)?$")


def _gdb_sort_key(tk: str):
    """本家族内 gdb 候选的排序键：先无后缀，再 -no-python，最后按版本从高到低。"""
    if tk == "gdb":
        return (0, (), 0)
    if tk == "gdb-no-python":
        return (1, (), 0)
    m = re.match(r"^gdb-(\d+(?:\.\d+)*)$", tk or "")
    if m:
        return (2, tuple(-int(x) for x in m.group(1).split(".")), 0)
    return (3, (), 0)


_FAMILY_PROBE_ORDER = ("arm-none-eabi", "riscv-none-elf", "riscv32-esp-elf",
                       "xtensa-esp-elf", "xtensa-esp32-elf")
_PROBE_TOOLS = ("gcc", "g++", "objcopy", "size", "nm", "readelf", "gdb", "ar")

# ---------------------------------------------------------------- 根目录

def _roots() -> list:
    """工具链根目录候选（去重，保持顺序）。"""
    out = []
    env = (os.environ.get("MDKDEBUG_TOOLCHAIN_ROOT") or "").strip()
    if env:
        out.extend([p for p in env.split(os.pathsep) if p.strip()])
    out += [
        "D:/Tools/mdk_agent_toolchains",
        "C:/Tools/mdk_agent_toolchains",
        os.path.join(os.path.expanduser("~"), ".mdkdebug", "toolchains"),
        os.path.join(_REPO_ROOT, "toolchains"),
    ]
    seen, res = set(), []
    for p in out:
        p = os.path.normpath(os.path.expanduser(p))
        key = p.lower()
        if key not in seen and os.path.isdir(p):
            seen.add(key)
            res.append(p)
    return res


def _extra_bin_dirs() -> list:
    """额外直接当作 bin 目录看待的路径（用户机器上已有的零散工具链）。"""
    out = []
    env = (os.environ.get("MDKDEBUG_TOOLCHAIN_BIN") or "").strip()
    if env:
        out.extend([p for p in env.split(os.pathsep) if p.strip()])
    out += [
        "D:/env/tools/gnu_gcc/arm_gcc/bin",
        "D:/env/tools/bin",
    ]
    res = []
    for p in out:
        p = os.path.normpath(os.path.expanduser(p))
        if os.path.isdir(p):
            res.append(p)
    return res


def _candidate_bin_dirs(root: str) -> list:
    """在一个工具链根下找出所有「可能是 bin 目录」的目录。

    覆盖这些解压形状：
      <root>/<pkg>/bin
      <root>/<pkg>/<triple>/bin
      <root>/<pkg>/bin/bin
      <root>/bin
    """
    cand = []
    if os.path.isdir(os.path.join(root, "bin")):
        cand.append(os.path.join(root, "bin"))

    def _add(p):
        if os.path.isdir(p):
            p = os.path.normpath(p)
            if p not in cand:
                cand.append(p)

    sub = []
    for pat in ("*", "*/*"):
        try:
            sub.extend(glob.glob(os.path.join(root, pat)))
        except OSError:
            continue
    for d in sub:
        if not os.path.isdir(d):
            continue
        _add(d)
        _add(os.path.join(d, "bin"))
        _add(os.path.join(d, "bin", "bin"))
        try:
            for inner in glob.glob(os.path.join(d, "*", "bin")):
                _add(inner)
        except OSError:
            continue
    return cand


# ---------------------------------------------------------------- 扫描与归类

_EXE_EXT = (".exe", ".cmd", ".bat", ".com")


def _strip_ext(name: str) -> str:
    low = name.lower()
    for e in _EXE_EXT:
        if low.endswith(e):
            return name[: -len(e)]
    return name


def _family_of(tool: str) -> str | None:
    """按 exe 名归类到家族；认不出来返回 None。"""
    low = tool.lower()
    if low in ("make", "mingw32-make"):
        return "make"
    if low == "cmake":
        return "cmake"
    if low == "ctest":
        return "cmake"
    if low == "ninja":
        return "ninja"
    if low in ("openocd",):
        return "openocd"
    # 带前缀的家族（长前缀优先，避免 riscv32-esp-elf 被 riscv-none-elf 抢不到；
    # 这里按前缀长度排序后逐个 match）
    for fam in sorted(FAMILIES, key=lambda f: -len(FAMILIES[f].get("prefix") or "")):
        pfx = FAMILIES[fam].get("prefix")
        if pfx and low.startswith(pfx.lower()):
            return fam
    for fam, spec in FAMILIES.items():
        for sfx in spec.get("suffixes") or ():
            if low.endswith(sfx):
                return fam
    return None


def _tool_key(family: str, tool: str) -> str:
    """把 arm-none-eabi-gcc → gcc（家族内的短名）。"""
    pfx = FAMILIES.get(family, {}).get("prefix")
    low = tool.lower()
    if pfx and low.startswith(pfx.lower()):
        return low[len(pfx):]
    return low


_SCAN_CACHE = {"ts": 0.0, "sig": "", "index": None}
_VER_CACHE: dict = {}


def scan(refresh: bool = False, max_age: float = 20.0) -> dict:
    """扫盘建立索引：{family: {tool_key: {"tool": 名, "path": 路径}}}。

    结果按 20 秒缓存（构建过程中反复调用不必反复扫盘）。
    """
    now = time.time()
    if (not refresh and _SCAN_CACHE["index"] is not None
            and now - _SCAN_CACHE["ts"] < max_age):
        return _SCAN_CACHE["index"]

    index: dict = {}
    dirs = []
    for r in _roots():
        dirs.extend(_candidate_bin_dirs(r))
    dirs.extend(_extra_bin_dirs())
    seen_dirs = set()
    for d in dirs:
        key = d.lower()
        if key in seen_dirs:
            continue
        seen_dirs.add(key)
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            base_no_ext = _strip_ext(n)
            if "." in base_no_ext and not n.lower().endswith(_EXE_EXT):
                # 过滤掉非可执行噪声（.dll / .cfg / 说明文件）
                continue
            fam = _family_of(base_no_ext)
            if not fam:
                continue
            full = os.path.join(d, n)
            if not os.path.isfile(full):
                continue
            tk = _tool_key(fam, base_no_ext)
            slot = index.setdefault(fam, {}).setdefault(tk, [])
            slot.append(full)

    # 同一 tool 有多个候选时：不是 xPack 老目录的优先，其次路径短的优先
    for fam, tools in index.items():
        for tk, paths in tools.items():
            paths.sort(key=lambda p: (0 if "xpack" in p.lower() else 1, len(p)))
            tools[tk] = paths
    _SCAN_CACHE.update(ts=now, index=index)
    return index


def find_tool(family: str, tool: str) -> str | None:
    """找某个家族里的某个工具（tool 用短名，如 gcc）。"""
    fam = FAMILIES.get(family) or {}
    idx = scan().get(family) or {}
    if tool in idx:
        return idx[tool][0]
    # tool 给了全名（arm-none-eabi-gcc）也认
    tk = _tool_key(family, tool)
    if tk in idx:
        return idx[tk][0]
    pfx = fam.get("prefix") or ""
    if tk in idx:
        return idx[tk][0]
    for tk2, paths in idx.items():
        if tk2 == tk or tk2.endswith("-" + tk) or (pfx and tk2 == tk.lower()):
            return paths[0]
    return None


def _gdb_paths(family: str) -> list:
    """某家族里所有 gdb 候选（按 _gdb_sort_key 排好序）。"""
    idx = scan().get(family) or {}
    keys = [k for k in idx if _GDB_KEY_RE.match(k or "")]
    keys.sort(key=_gdb_sort_key)
    return [(k, idx[k][0]) for k in keys]


def find_gdb(family: str = "", probe: bool = True) -> dict:
    """挑一个**真能跑**的 gdb（不是「名字最像」的那个）。

    为什么会挑到不能跑的：ESP 官方 gdb 包把无后缀名留给 python 启动器，
    它需要 PYTHONHOME 才能跑；真正的 gdb 叫 -no-python 或 -3.x。
    另外 xtensa-esp-elf 家族里压根没有无后缀的 gdb 键。

    规则：
      - family 给了 → 只在该家族与其**同架构**兄弟家族里找（arm 的 ELF 绝不
        会拿到 riscv/xtensa 的 gdb）；family 空 → 按 _FAMILY_PROBE_ORDER 全找，
        但会标 is_arch_known=False 提示调用方「架构未知，是碰上的」。
      - 候选逐个真跑一次 --version（走 probe_version 缓存），坏的记进 tried 跳过。
    """
    family = (family or "").strip()
    if family and family not in FAMILIES:
        return {"ok": False, "gdb_select": "bad-family", "path": None,
                "error": "未知的工具链家族：%s" % family,
                "known_families": [f for f in FAMILIES if "gdb" in f or f in _FAMILY_PROBE_ORDER]}
    arch = (FAMILIES.get(family) or {}).get("arch") if family else None
    if family:
        same_arch = [f for f in FAMILIES
                     if f != family and FAMILIES[f].get("arch") == arch
                     and (FAMILIES[f].get("prefix") or f in ("gdb",))]
        fams = [family] + sorted(same_arch)
    else:
        fams = list(_FAMILY_PROBE_ORDER)
    tried = []
    for f in fams:
        for key, path in _gdb_paths(f):
            info = probe_version(path) if probe else {"ok": True}
            good = bool(info.get("ok"))
            tried.append({"family": f, "key": key, "path": path, "ok": good,
                          "reason": info.get("error") or None})
            if not good:
                continue
            same = (f == family) or not family
            note = None
            if key != "gdb":
                bad = [t for t in tried if t["key"] == "gdb" and not t["ok"]]
                note = ("本家族的无后缀 gdb 起不来（%s），改用 %s"
                        % (bad[0]["reason"], key)) if bad else ("选用 %s（无无后缀 gdb）" % key)
            if family and not same:
                note = ("%s家族里没有能跑的 gdb，用了同架构的 %s（%s）"
                        % (family, f, key))
            return {"ok": True, "path": path, "family": f, "via": key,
                    "arch": FAMILIES.get(f, {}).get("arch"),
                    "is_arch_known": bool(family),
                    "gdb_select": "elf-family" if family else "first-available",
                    "note": note, "tried": tried}
    return {"ok": False, "path": None, "family": family or None, "arch": arch,
            "is_arch_known": bool(family),
            "gdb_select": "elf-family" if family else "first-available",
            "error": ("本机没找到 %s 能跑的 gdb" % family) if family else "本机没找到能跑的 gdb",
            "tried": tried,
            "hint": "装 xPack gcc（自带 gdb）或 esp-elf-gdb 后 toolchain_env(families=\"all\") 注入；"
                    "也可以用 gdb= 直接给绝对路径"}


def probe_version(path: str, refresh: bool = False) -> dict:
    """跑 --version 拿版本字符串（按路径+mtime 缓存）。"""
    try:
        st = os.stat(path)
        sig = "%s|%s|%s" % (path.lower(), st.st_mtime, st.st_size)
    except OSError:
        sig = path.lower()
    if not refresh and sig in _VER_CACHE:
        return _VER_CACHE[sig]
    base = _strip_ext(os.path.basename(path)).lower()
    args = list(_VERSION_ARGS.get(base) or ["--version"])
    info = {"tool": os.path.basename(path), "path": path, "ok": False,
            "version": None, "first_line": None, "error": None}
    try:
        p = subprocess.run([path] + args, capture_output=True, timeout=20,
                           cwd=os.path.dirname(path) or None)
        raw = (p.stdout or b"") + (p.stderr or b"")
        text = raw.decode("utf-8", "replace")
        first = ""
        for line in text.splitlines():
            if line.strip():
                first = line.strip()
                break
        info["first_line"] = first
        info["ok"] = bool(first)
        info["version"] = _extract_version(first)
        if first and _BROKEN_RE.search(text):
            info.update(ok=False, version=None, broken=True,
                        error="这个 exe 起不来（命中运行期失败特征）：%s" % first[:120])
    except Exception as e:  # noqa: BLE001
        info["error"] = str(e)
    _VER_CACHE[sig] = info
    return info


def _extract_version(line: str):
    if not line:
        return None
    m = re.search(r"(?:version\s+)?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)", line)
    return m.group(1) if m else None


def discover(family: str = "", refresh: bool = False, with_version: bool = True) -> dict:
    """返回探测结果：{family: {tool, path, version, ok}} 与缺件提示。"""
    idx = scan(refresh=refresh)
    fams = [f for f in FAMILIES if not family or f == family]
    out, missing = {}, []
    for f in fams:
        spec = FAMILIES[f]
        entry = {"title": spec["title"], "arch": spec.get("arch"),
                 "note": spec.get("note"), "bin_dir": None, "tools": {}}
        tools = idx.get(f) or {}
        if not tools:
            missing.append(f)
            out[f] = entry
            continue
        for tk in sorted(tools):
            path = tools[tk][0]
            rec = {"path": path}
            if with_version:
                v = probe_version(path, refresh=refresh)
                rec["version"] = v.get("version")
                rec["version_line"] = v.get("first_line")
                rec["ok"] = bool(v.get("ok"))
            entry["tools"][tk] = rec
            if entry["bin_dir"] is None:
                entry["bin_dir"] = os.path.dirname(path)
        out[f] = entry
    return {"families": out, "missing": missing, "roots": _roots(),
            "extra_bin_dirs": _extra_bin_dirs()}


def resolve_paths(families) -> list:
    """把家族名列表解析成 bin 目录列表（用于 PATH 注入）。"""
    if isinstance(families, str):
        families = [x for x in re.split(r"[,;|]", families) if x.strip()]
    idx = scan()
    dirs = []
    for f in families or []:
        f = f.strip()
        if not f:
            continue
        if f in ("all", "*"):
            for fam in _FAMILY_PROBE_ORDER:
                for paths in (idx.get(fam) or {}).values():
                    dirs.append(os.path.dirname(paths[0]))
            for fam in ("make", "cmake", "ninja", "openocd", "gdb"):
                for paths in (idx.get(fam) or {}).values():
                    dirs.append(os.path.dirname(paths[0]))
            continue
        for paths in (idx.get(f) or {}).values():
            dirs.append(os.path.dirname(paths[0]))
        # 家族没装但给了显式目录也接受
        if os.path.isdir(f):
            dirs.append(os.path.normpath(f))
    res, seen = [], set()
    for d in dirs:
        k = d.lower()
        if k not in seen:
            seen.add(k)
            res.append(d)
    return res


# ---------------------------------------------------------------- 环境注入

_ENV_STATE = {"families": [], "path_extra": [], "applied": []}


def apply_env(families=None, path_extra=None, reset: bool = False) -> dict:
    """把工具链 bin 目录注入本服务进程 PATH。

    只加不删（reset=True 时先移除本次已注入的项），后加的在前面。
    注入后所有子进程（make / cmake / openocd / gcc）都能直接按名字找到工具。
    """
    if reset:
        cur = os.environ.get("PATH", "").split(os.pathsep)
        drop = {os.path.normpath(p).lower() for p in _ENV_STATE["applied"]}
        os.environ["PATH"] = os.pathsep.join(
            [p for p in cur if os.path.normpath(p).lower() not in drop])
        _ENV_STATE["applied"] = []

    if families is not None:
        if isinstance(families, str):
            families = [x for x in re.split(r"[,;|]", families) if x.strip()]
        _ENV_STATE["families"] = list(families or [])
    if path_extra is not None:
        _ENV_STATE["path_extra"] = [p for p in str(path_extra).split(os.pathsep) if p.strip()]

    want = resolve_paths(_ENV_STATE["families"]) + list(_ENV_STATE["path_extra"])
    cur = os.environ.get("PATH", "").split(os.pathsep)
    cur_low = {os.path.normpath(p).lower() for p in cur if p}
    added = []
    for d in want:
        d = os.path.normpath(d)
        if d.lower() in cur_low:
            continue
        cur.insert(0, d)
        cur_low.add(d.lower())
        added.append(d)
    if added:
        os.environ["PATH"] = os.pathsep.join(cur)
    _ENV_STATE["applied"] = list(_ENV_STATE["applied"]) + added
    return env_state(added=added)


def env_state(added=None) -> dict:
    return {"ok": True, "families": list(_ENV_STATE["families"]),
            "path_extra": list(_ENV_STATE["path_extra"]),
            "applied": list(_ENV_STATE["applied"]),
            "added_now": list(added or [])}


# ---------------------------------------------------------------- 运行

def resolve_command(tool: str, family: str = "") -> dict:
    """把「家族 + 工具名」或「绝对路径 / PATH 上的名字」解析为可执行路径。"""
    if not tool or not str(tool).strip():
        return {"ok": False, "error": "tool 不能为空"}
    tool = str(tool).strip()
    if os.path.isabs(tool) or "/" in tool or "\\" in tool:
        if os.path.isfile(tool):
            return {"ok": True, "path": os.path.normpath(tool), "family": family}
        return {"ok": False, "error": "文件不存在：%s" % tool}
    if _strip_ext(tool).lower() == "gdb":
        g = find_gdb(family=family)
        if g.get("ok"):
            return {"ok": True, "path": g["path"], "family": g["family"],
                    "via": g.get("via"), "note": g.get("note"),
                    "gdb_select": g.get("gdb_select")}
        return {"ok": False, "error": g.get("error"), "hint": g.get("hint"),
                "tried": g.get("tried")}
    fams = [family] if family else list(FAMILIES)
    for f in fams:
        p = find_tool(f, tool)
        if p:
            return {"ok": True, "path": p, "family": f}
    # 退化到 PATH
    from shutil import which
    p = which(tool) or which(tool + ".exe")
    if p:
        return {"ok": True, "path": p, "family": family}
    return {"ok": False, "error": "找不到工具 %s（可用 toolchain_list 看本机已装了什么）" % tool}


def is_runnable(tool: str) -> bool:
    base = _strip_ext(os.path.basename(str(tool))).lower()
    if base in _RUNNABLE_EXACT:
        return True
    for sfx in _RUNNABLE_SUFFIXES:
        if base.endswith(sfx):
            return True
    return bool(_RUNNABLE_RE.search(base))


def run_tool(tool: str, args=None, cwd: str = "", timeout: float = 300,
             family: str = "", env_extra=None, max_output: int = 200000,
             input_text: str = "") -> dict:
    """跑一个工具链工具（shell=False，列表参数）。"""
    r = resolve_command(tool, family=family)
    if not r.get("ok"):
        return {"ok": False, "tool": tool, "error": r.get("error"),
                "hint": "先 toolchain_list 看本机有哪些工具链，再用 toolchain_env 注入 PATH"}
    exe = r["path"]
    if not is_runnable(exe):
        return {"ok": False, "tool": tool, "path": exe,
                "error": "该工具不在放行白名单内（只允许编译器/构建器/调试器类）",
                "allowed": list(_RUNNABLE_EXACT) + list(_RUNNABLE_SUFFIXES)}
    if isinstance(args, str):
        args = _split_args(args)
    argv = [exe] + [str(a) for a in (args or [])]
    env = os.environ.copy()
    for k, v in (env_extra or {}).items():
        env[str(k)] = str(v)
    t0 = time.time()
    out = {"ok": False, "tool": os.path.basename(exe), "path": exe,
           "args": argv[1:], "cmd": " ".join(_quote(a) for a in argv),
           "cwd": os.path.normpath(cwd) if cwd else os.getcwd()}
    try:
        p = subprocess.run(argv, capture_output=True, timeout=max(1.0, float(timeout)),
                           cwd=cwd or None, env=env,
                           input=(input_text.encode("utf-8") if input_text else None))
        out["returncode"] = p.returncode
        out["stdout"] = _clip((p.stdout or b"").decode("utf-8", "replace"), max_output)
        out["stderr"] = _clip((p.stderr or b"").decode("utf-8", "replace"), max_output)
        out["ok"] = (p.returncode == 0)
    except subprocess.TimeoutExpired:
        out["timeout"] = True
        out["error"] = "命令超时（%.0fs）" % float(timeout)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    out["duration_s"] = round(time.time() - t0, 3)
    if not out["ok"] and not out.get("error"):
        out["error"] = "退出码 %s" % out.get("returncode")
    return out


def _quote(s: str) -> str:
    s = str(s)
    return '"%s"' % s if (" " in s or "\t" in s) else s


def _clip(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[:limit] + "\n... [已截断，原始 %d 字符]" % len(text)
    return text


def _split_args(s: str) -> list:
    """按 shell 习惯切参数（支持引号），不做变量展开。"""
    import shlex
    try:
        return shlex.split(s, posix=False)
    except ValueError:
        return s.split()


# ---------------------------------------------------------------- 工程识别

_BUILD_KINDS = ("cmake", "make", "mdk", "none")


def detect_project(path: str = "", max_up: int = 3) -> dict:
    """识别工程构建方式：cmake / make / mdk / none。"""
    p = os.path.abspath(os.path.expanduser(path or "."))
    info = {"input": p, "kind": "none", "root": None, "evidence": [],
            "elf_candidates": [], "build_dir_hint": None, "note": None}
    if os.path.isfile(p):
        base = os.path.basename(p).lower()
        root = os.path.dirname(p)
        if base == "cmakelists.txt":
            info.update(kind="cmake", root=root, evidence=[p])
        elif base in ("makefile", "gnumakefile") or base.endswith(".mk"):
            info.update(kind="make", root=root, evidence=[p])
        elif base.endswith(".uvprojx"):
            info.update(kind="mdk", root=root, evidence=[p])
        elif base.endswith(".elf"):
            info.update(kind="none", root=root, evidence=[p],
                        note="这是产物不是工程；用 toolchain_elf_info 看它，"
                             "或用 toolchain_objcopy 转 bin")
            return info
        else:
            info["note"] = "无法从这个文件判断构建方式"
            return info
    else:
        if not os.path.isdir(p):
            info["note"] = "路径不存在"
            return info
        root, cur = None, p
        for _ in range(max_up + 1):
            if os.path.isfile(os.path.join(cur, "CMakeLists.txt")):
                root, kind, ev = cur, "cmake", os.path.join(cur, "CMakeLists.txt")
                break
            mk = [f for f in os.listdir(cur)
                  if f.lower() in ("makefile", "gnumakefile") or f.lower().endswith(".mk")]
            if mk:
                root, kind, ev = cur, "make", os.path.join(cur, sorted(mk)[0])
                break
            uv = glob.glob(os.path.join(cur, "*.uvprojx"))
            if uv:
                root, kind, ev = cur, "mdk", uv[0]
                break
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        if not root:
            info["note"] = ("向上 %d 层没找到 CMakeLists.txt / Makefile / *.uvprojx"
                            % max_up)
            return info
        info.update(kind=kind, root=root, evidence=[ev])

    # 顺带把可能的 ELF 产物找出来，方便 objcopy / 烧录
    root = info["root"]
    if root:
        cands = []
        for pat in ("*.elf", "build/*.elf", "build/*/*.elf", "out/*.elf",
                    "Debug/*.elf", "Release/*.elf"):
            cands.extend(glob.glob(os.path.join(root, pat)))
        cands = [c for c in cands if os.path.isfile(c)]
        cands.sort(key=lambda c: -os.path.getmtime(c))
        info["elf_candidates"] = cands[:5]
        for d in ("build", "out", "Debug", "Release"):
            if os.path.isdir(os.path.join(root, d)):
                info["build_dir_hint"] = os.path.join(root, d)
                break
    return info


# ---------------------------------------------------------------- GCC 输出解析

_GCC_LINE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+)(?::(?P<col>\d+))?:\s*"
    r"(?P<sev>fatal error|error|warning|note|remark)\s*:\s*(?P<msg>.*)$")
_LD_UNDEF = re.compile(r"(?P<file>[^:\n]+):(?P<line>\d+):\s*undefined reference to\s*[`'\"](?P<sym>[^`'\"]+)")
_NOTE_MAP = {
    "undeclared": "标识符未声明：多半是缺 #include 或拼写错（也检查是否漏了头文件目录 -I）",
    "undefined reference": "链接期找不到符号：检查是否漏编源文件/漏链库（-l），"
                           "C++ 调用 C 函数要加 extern \"C\"",
    "no such file or directory": "文件找不到：检查 -I/-L 路径与文件名大小写",
    "implicit declaration": "隐式声明：缺头文件，C99 起会告警、C11 起报错",
    "expected": "语法错误：看该行前一行是否少分号/括号",
    "multiple definition": "重复定义：同一符号被两个源文件定义（常见于把函数写在头文件里）",
    "region `FLASH' overflowed": "Flash 放不下：裁剪代码或调整链接脚本里的 MEMORY",
    "region `RAM' overflowed": "RAM 放不下：降低栈/堆或减小静态缓冲",
    "cannot find -l": "库找不到：检查 -L 路径与库名（libxxx.a → -lxxx）",
    "unknown type name": "类型不认识：缺头文件或 C/C++ 混编问题",
    "conflicting types": "类型冲突：函数声明与定义不一致",
}


def parse_gcc_output(text: str, limit: int = 200) -> dict:
    """把 gcc/make/cmake 的输出解析成结构化错误列表。"""
    errors, warnings, notes = [], [], []
    if not text:
        return {"ok": True, "count": 0, "errors": [], "warnings": [],
                "notes": [], "summary": {"error": 0, "warning": 0}}
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        m = _GCC_LINE.match(line.strip()) if line.strip() else None
        if m:
            sev = m.group("sev")
            item = {"file": m.group("file"), "line": int(m.group("line")),
                    "col": int(m.group("col")) if m.group("col") else None,
                    "severity": "error" if "error" in sev else sev,
                    "message": m.group("msg").strip(),
                    "raw": line.strip()}
            item["hint"] = _hint_for(item["message"])
            if item["severity"] == "error":
                errors.append(item)
            elif sev == "warning":
                warnings.append(item)
            else:
                notes.append(item)
            continue
        if re.search(r"undefined reference|multiple definition|ld\.exe|ld returned",
                     line):
            item = {"file": None, "line": None, "col": None, "severity": "error",
                    "message": line.strip(), "raw": line.strip(),
                    "hint": _hint_for(line)}
            mm = _LD_UNDEF.search(line)
            if mm:
                item.update(file=mm.group("file"), line=int(mm.group("line")),
                            symbol=mm.group("sym"))
            errors.append(item)
            continue
        if re.search(r"region `?\w+'? overflowed", line) or re.search(r"\.text.*overflow", line):
            errors.append({"file": None, "line": None, "col": None,
                           "severity": "error", "message": line.strip(),
                           "raw": line.strip(), "hint": _hint_for(line)})
    seen = set()
    dedup_errors = []
    for e in errors:
        key = (e.get("file"), e.get("line"), e.get("message"))
        if key in seen:
            continue
        seen.add(key)
        dedup_errors.append(e)
    return {"ok": not dedup_errors, "count": len(dedup_errors),
            "errors": dedup_errors[:limit],
            "warnings": warnings[:limit], "notes": notes[:limit],
            "summary": {"error": len(dedup_errors), "warning": len(warnings)},
            "first_error": dedup_errors[0] if dedup_errors else None}


def _hint_for(msg: str) -> str | None:
    low = (msg or "").lower()
    for k, v in _NOTE_MAP.items():
        if k.lower() in low:
            return v
    return None


# ---------------------------------------------------------------- 构建

def build(project: str = "", build_dir: str = "", target: str = "",
          jobs: int = 0, clean: bool = False, generator: str = "",
          config_args: str = "", timeout: float = 900, families: str = "",
          dry_run: bool = False, extra_make_args: str = "") -> dict:
    """按识别出的构建方式执行构建（cmake 或 make）。"""
    fams = families or "arm-none-eabi,make,cmake,ninja"
    if families is None or families == "":
        apply_env(["all"])
    else:
        apply_env(fams)
    info = detect_project(project)
    if info["kind"] == "none":
        return {"ok": False, "kind": "none", "detect": info,
                "error": info.get("note") or "没法识别构建方式",
                "hint": "可用 toolchain_compile 直接喂源文件编译，或先在工程里放 "
                        "CMakeLists.txt / Makefile"}
    if info["kind"] == "mdk":
        return {"ok": False, "kind": "mdk", "detect": info,
                "error": "这是 Keil 工程（.uvprojx），应走 MDK 侧工具",
                "hint": "用 build_project / rebuild_project（UV4 批处理），"
                        "不要在 GCC 工具链上编 Keil 工程"}
    root = info["root"]
    steps = []
    ok = True

    if info["kind"] == "make":
        mk_name = os.path.basename(info["evidence"][0])
        mk = find_tool("make", "make") or find_tool("make", "mingw32-make")
        if not mk:
            return {"ok": False, "kind": "make", "detect": info,
                    "error": "本机没找到 make",
                    "hint": "装 xPack windows-build-tools（含 make），或用 toolchain_env 注入"}
        jobs = int(jobs) if jobs and int(jobs) > 0 else (os.cpu_count() or 4)
        if clean:
            steps.append(run_tool(mk, ["-f", mk_name, "clean"], cwd=root,
                                  timeout=timeout))
            if not steps[-1]["ok"]:
                ok = False
        if not (clean and not target and ok is False):
            argv = ["-f", mk_name, "-j%d" % jobs]
            if target:
                argv.append(target)
            if extra_make_args:
                argv.extend(_split_args(extra_make_args))
            if not dry_run:
                steps.append(run_tool(mk, argv, cwd=root, timeout=timeout))
                ok = ok and steps[-1]["ok"]
            else:
                steps.append({"ok": True, "cmd": " ".join(argv), "dry_run": True})
    else:  # cmake
        cm = find_tool("cmake", "cmake")
        if not cm:
            return {"ok": False, "kind": "cmake", "detect": info,
                    "error": "本机没找到 cmake",
                    "hint": "下载 Kitware 免安装 zip 解压到 D:/Tools/mdk_agent_toolchains/"}
        bd = build_dir or info.get("build_dir_hint") or os.path.join(root, "build")
        gen = generator
        if not gen:
            gen = "Ninja" if find_tool("ninja", "ninja") else "MinGW Makefiles"
        cache = os.path.join(bd, "CMakeCache.txt")
        if clean and os.path.isdir(bd):
            import shutil as _sh
            try:
                _sh.rmtree(bd)
            except OSError as e:
                return {"ok": False, "kind": "cmake", "detect": info,
                        "error": "清理构建目录失败：%s" % e}
        need_cfg = not os.path.isfile(cache)
        if need_cfg:
            cargv = ["-S", root, "-B", bd, "-G", gen]
            if config_args:
                cargv.extend(_split_args(config_args))
            if dry_run:
                steps.append({"ok": True, "cmd": " ".join(cargv), "dry_run": True,
                              "stage": "configure"})
            else:
                steps.append(run_tool(cm, cargv, cwd=root, timeout=timeout))
                steps[-1]["stage"] = "configure"
                ok = ok and steps[-1]["ok"]
        if ok or not need_cfg:
            bargv = ["--build", bd]
            if target:
                bargv += ["--target", target]
            if jobs and int(jobs) > 0:
                bargv += ["-j", str(int(jobs))]
            if dry_run:
                steps.append({"ok": True, "cmd": " ".join(bargv), "dry_run": True,
                              "stage": "build"})
            else:
                steps.append(run_tool(cm, bargv, cwd=root, timeout=timeout))
                steps[-1]["stage"] = "build"
                ok = ok and steps[-1]["ok"]

    text = "\n".join((s.get("stdout") or "") + "\n" + (s.get("stderr") or "")
                     for s in steps if not s.get("dry_run"))
    parsed = parse_gcc_output(text)
    out = {"ok": bool(ok) and not parsed["errors"], "kind": info["kind"],
           "root": root, "detect": info, "steps": steps,
           "errors": parsed["errors"], "warnings": parsed["warnings"],
           "summary": parsed["summary"],
           "stdout": _clip(text, 20000)}
    if dry_run:
        out["note"] = "dry_run：只回显将执行的命令，没有真正构建"
    if not out["ok"] and parsed.get("first_error"):
        out["hint"] = ("首个错误：%s:%s %s"
                       % (parsed["first_error"].get("file") or "?",
                          parsed["first_error"].get("line") or "?",
                          parsed["first_error"].get("message")))
    return out


# ---------------------------------------------------------------- 编译 / 产物

_DEF_FLAGS = {
    "cortex-m0": ["-mcpu=cortex-m0", "-mthumb"],
    "cortex-m0plus": ["-mcpu=cortex-m0plus", "-mthumb"],
    "cortex-m3": ["-mcpu=cortex-m3", "-mthumb"],
    "cortex-m4": ["-mcpu=cortex-m4", "-mthumb"],
    "cortex-m7": ["-mcpu=cortex-m7", "-mthumb"],
    "cortex-m33": ["-mcpu=cortex-m33", "-mthumb"],
}


def cpu_flags(cpu: str, fpu: str = "", float_abi: str = "") -> list:
    """按 cpu 名生成 -mcpu/-mfpu/-mfloat-abi（也认已带 - 的原始 flag）。"""
    out = []
    cpu = (cpu or "").strip()
    if cpu.startswith("-"):
        out += _split_args(cpu)
    elif cpu:
        if cpu in _DEF_FLAGS:
            out += _DEF_FLAGS[cpu]
        elif cpu.startswith("rv"):
            out += ["-march=%s" % cpu]
        elif cpu.startswith("esp32"):
            out += []  # xtensa 由工具链默认 target 决定
        else:
            out += ["-mcpu=%s" % cpu]
    if fpu:
        out += ["-mfpu=%s" % fpu] if not fpu.startswith("-") else _split_args(fpu)
    if float_abi:
        out += (["-mfloat-abi=%s" % float_abi] if not float_abi.startswith("-")
                else _split_args(float_abi))
    return out


def compile_files(files, family: str = "arm-none-eabi", out: str = "",
                  defs: str = "", includes: str = "", flags: str = "",
                  cpu: str = "", fpu: str = "", float_abi: str = "",
                  syntax_only: bool = False, cwd: str = "",
                  timeout: float = 300, extra_args: str = "",
                  objdir: str = "") -> dict:
    """直接用 gcc 编译（不依赖 make/cmake）。语法校验用 syntax_only=True。"""
    if isinstance(files, str):
        files = [x for x in re.split(r"[;|]", files) if x.strip()]
    files = [f for f in (files or []) if str(f).strip()]
    if not files:
        return {"ok": False, "error": "files 不能为空"}
    apply_env(["all"])
    gcc = find_tool(family, "gcc")
    if not gcc:
        return {"ok": False, "family": family, "error": "找不到 %s 的 gcc" % family,
                "hint": "toolchain_list 看本机有哪些工具链"}
    argv = []
    if syntax_only:
        argv += ["-fsyntax-only"]
    else:
        argv += ["-c"]
    argv += cpu_flags(cpu, fpu, float_abi)
    for d in [x for x in re.split(r"[;,|]", defs or "") if x.strip()]:
        argv.append("-D%s" % d.strip())
    for inc in [x for x in re.split(r"[;,|]", includes or "") if x.strip()]:
        argv.append("-I%s" % inc.strip())
    if flags:
        argv += _split_args(flags)
    if extra_args:
        argv += _split_args(extra_args)
    argv += [str(f) for f in files]
    if not syntax_only:
        if objdir:
            argv += ["-o", os.path.join(objdir, "%s.o" % os.path.splitext(
                os.path.basename(str(files[0])))[0])]
        elif out:
            argv += ["-o", out]
        else:
            argv += ["-o", os.path.join(cwd or os.getcwd(), "out.o")]
    r = run_tool(gcc, argv, cwd=cwd, timeout=timeout)
    parsed = parse_gcc_output((r.get("stdout") or "") + "\n" + (r.get("stderr") or ""))
    r.update({"family": family, "files": files,
              "errors": parsed["errors"], "warnings": parsed["warnings"],
              "summary": parsed["summary"], "command": r.get("cmd")})
    if not r["ok"]:
        r["ok"] = False
    return r


def elf_info(elf: str) -> dict:
    """用 pyelftools 解析 ELF 概要（架构、入口、段）。"""
    if not elf or not os.path.isfile(elf):
        return {"ok": False, "error": "ELF 不存在：%s" % elf}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.constants import P_FLAGS
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "pyelftools 不可用：%s" % e}
    out = {"ok": True, "path": os.path.abspath(elf),
           "size": os.path.getsize(elf), "mtime": os.path.getmtime(elf)}
    try:
        with open(elf, "rb") as f:
            e = ELFFile(f)
            out["class"] = e.elfclass
            out["little_endian"] = bool(e.little_endian)
            out["machine"] = e.header.get("e_machine")
            out["type"] = e.header.get("e_type")
            out["entry_hex"] = "0x%08X" % e.header.get("e_entry", 0)
            secs = []
            for s in e.iter_sections():
                if s["sh_flags"] & 0x2 and s["sh_size"]:  # SHF_ALLOC
                    secs.append({"name": s.name, "addr": "0x%08X" % s["sh_addr"],
                                 "size": s["sh_size"]})
            out["alloc_sections"] = secs
            try:
                for seg in e.iter_segments():
                    pass
            except Exception:  # noqa: BLE001
                pass
            # 符号概况
            nsym = 0
            try:
                for sec in e.iter_sections():
                    if sec.name in (".symtab", ".dynsym"):
                        nsym += sum(1 for _ in sec.iter_symbols())
            except Exception:  # noqa: BLE001
                pass
            out["symbols"] = nsym
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "path": elf, "error": "解析失败：%s" % e}
    # 顺手给个架构推断，方便选 openocd target
    mt = str(out.get("machine"))
    if "ARM" in mt:
        out["arch"] = "arm"
    elif "RISCV" in mt or "RISC-V" in mt:
        out["arch"] = "riscv"
    elif "XTENSA" in mt:
        out["arch"] = "xtensa"
    return out


def size_report(elf: str, family: str = "arm-none-eabi", by_section: bool = True,
                top: int = 15) -> dict:
    """段大小报告：优先用 toolchain size 工具，退化为 pyelftools 统计。"""
    if not elf or not os.path.isfile(elf):
        return {"ok": False, "error": "ELF 不存在：%s" % elf}
    apply_env(["all"])
    size = find_tool(family, "size")
    if size:
        args = ["-A", elf] if by_section else ["-B", elf]
        r = run_tool(size, args, timeout=60)
        if r.get("ok"):
            r["mode"] = "size -A" if by_section else "size -B"
            r["text"] = r.get("stdout")
            return r
    info = elf_info(elf)
    if not info.get("ok"):
        return info
    tot = {}
    for s in info.get("alloc_sections") or []:
        nm = s["name"]
        key = ("flash" if (s["addr"] >= "0x08" or nm.startswith((".text", ".rodata",
                                                                ".isr", ".vectors")))
               else "ram")
        tot[key] = tot.get(key, 0) + s["size"]
    return {"ok": True, "mode": "pyelftools", "elf": elf, "bytes": tot,
            "note": "用 size 工具更准（含 region 细分）；本机没找到 size 时退化为按段汇总",
            "sections": info.get("alloc_sections")}


def objcopy(elf: str, fmt: str = "bin", out: str = "",
            family: str = "arm-none-eabi", extra: str = "") -> dict:
    """ELF → bin/hex/ihex/srec。"""
    if not elf or not os.path.isfile(elf):
        return {"ok": False, "error": "ELF 不存在：%s" % elf}
    apply_env(["all"])
    oc = find_tool(family, "objcopy")
    if not oc:
        return {"ok": False, "family": family, "error": "找不到 %s 的 objcopy" % family}
    fmt = (fmt or "bin").strip().lower()
    if fmt not in ("bin", "binary", "hex", "ihex", "srec", "elf", "verilog"):
        return {"ok": False, "error": "不支持的格式：%s（bin/hex/ihex/srec）" % fmt}
    ofmt = {"bin": "binary", "binary": "binary", "hex": "ihex",
            "ihex": "ihex", "srec": "srec", "elf": "elf32-littlearm"}.get(fmt, fmt)
    outp = out or os.path.splitext(elf)[0] + "." + ("bin" if ofmt == "binary" else fmt)
    args = ["-O", ofmt, elf, outp]
    if extra:
        args = _split_args(extra) + args
    r = run_tool(oc, args, timeout=120)
    r["out"] = outp
    if r.get("ok") and os.path.isfile(outp):
        r["bytes"] = os.path.getsize(outp)
    return r

# ================================================================ MCP 注册

def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)

def register(server, js=None) -> int:
    """把工具链/构建相关工具注册到 MCP server，返回注册数量。"""
    _js = js or _default_js
    n = 0

    @server.tool(
        name="toolchain_list",
        title="探测本机有哪些交叉工具链（gcc / make / cmake / ninja / openocd / gdb）",
        description=(
            "扫描本机的工具链安装位置，按**家族**归类列出可执行文件与版本："
            "arm-none-eabi、riscv-none-elf、riscv32-esp-elf、xtensa-esp-elf、"
            "xtensa-esp32-elf（编译器），以及 make、cmake、ninja、openocd、gdb"
            "（构建与调试工具）。\n"
            "搜索顺序：环境变量 MDKDEBUG_TOOLCHAIN_ROOT 指定的根 → "
            "D:/Tools/mdk_agent_toolchains 下各包 → 环境变量 MDKDEBUG_TOOLCHAIN_BIN "
            "与常见的手工安装目录（D:/env/tools/...）。解压形状不限：按目录树递归找 "
            "可执行文件再按前缀归类，所以 <pkg>/bin、<pkg>/<triple>/bin 都能认出来。\n"
            "用法：family 过滤某个家族（如 family=\"riscv\" 做子串匹配），"
            "with_version=false 可跳过跑 --version（快很多，首次扫描建议先跳过）。"
            "**返回为空就说明没装**，不要假设系统里一定有 —— 缺什么可以用 "
            "toolchain_run 之外的方式自行安装到 D:/Tools/mdk_agent_toolchains/。"
        ),
    )
    async def toolchain_list(family: str = "", refresh: bool = False,
                             with_version: bool = True) -> str:
        try:
            return _js(discover(family=family, refresh=bool(refresh),
                                with_version=bool(with_version)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_env",
        title="把工具链注入 PATH（让子进程能直接调到 gcc/make/cmake/openocd）",
        description=(
            "把探测到的工具链 bin 目录写进当前进程的 PATH，后续通过本 MCP 起的所有"
            "子进程都能直接按名字调用（gcc/make/cmake/openocd 等）。\n"
            "families 用逗号分隔指定家族，\"all\" 表示全部；path_extra 追加自定义"
            "目录（多个用 os.pathsep 或逗号分隔）；reset=true 先恢复成进程启动时的"
            "PATH 再注入，避免多次调用层层叠加。\n"
            "**为什么需要它**：交叉编译的老大难不是编译本身，而是构建脚本里"
            "`arm-none-eabi-gcc` 找不到、make 里调 python 找不到、cmake 找不到"
            "编译器。先把 PATH 铺好，后面 toolchain_build / toolchain_run 才稳。\n"
            "只改本进程环境，不动系统 PATH，绝不写注册表。"
        ),
    )
    async def toolchain_env(families: str = "", path_extra: str = "",
                            reset: bool = False, show_only: bool = False) -> str:
        try:
            if show_only:
                return _js({"ok": True, "state": env_state()})
            fams = "" if families in ("", "all") else families
            extra = [p for p in re.split(r"[;|]", path_extra or "") if p.strip()]
            r = apply_env(fams or None, path_extra=extra or None, reset=bool(reset))
            r["state"] = env_state()
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_run",
        title="直接跑一个工具链命令（参数走列表，不经 shell）",
        description=(
            "按白名单执行一个工具链工具并回收输出。tool 可以是家族前缀形式"
            "（arm-none-eabi-gcc、riscv-none-elf-objdump）或裸名（make、cmake、"
            "openocd）。args 可给列表或用字符串（按 shell 习惯切词，支持引号，"
            "**不做变量展开**）。\n"
            "安全边界：只放行编译器/构建器/调试器这类工具（gcc/objdump/size/nm/"
            "objcopy/make/cmake/ninja/openocd/gdb/readelf 等，含各交叉前缀），"
            "shell=False 不经解释器，所以 `;`、`&&`、管道都不会被当成命令分隔符——"
            "想串命令请分多次调用。\n"
            "用 input_text 可从 stdin 喂数据（比如给 gdb 喂 -batch 的脚本）。"
            "超时默认 300s，构建类命令记得调大。"
        ),
    )
    async def toolchain_run(tool: str, args: str = "", cwd: str = "",
                            timeout: float = 300, family: str = "",
                            env_extra: str = "", input_text: str = "") -> str:
        try:
            import shlex
            try:
                argv = shlex.split(args, posix=False) if args else []
            except ValueError:
                argv = (args or "").split()
            envx = {}
            for pair in (env_extra or "").split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    envx[k.strip()] = v.strip()
            return _js(run_tool(tool, argv, cwd=cwd, timeout=float(timeout),
                                family=family, env_extra=envx or None,
                                input_text=input_text or ""))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "tool": tool, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_detect_project",
        title="识别一个目录的构建方式（cmake / make / mdk / none）",
        description=(
            "从给定目录（或文件）往上找几层，判断这个工程怎么构建："
            "有 CMakeLists.txt → cmake；有 Makefile/makefile/*.mk → make；"
            "有 *.uvprojx/*.uvproj → mdk；都没有 → none。同时给出可能的 ELF 产物"
            "路径与建议的构建目录。\n"
            "**identify 判断顺序很重要**：Keil 工程不要拿去用 GCC 构建（那是两套"
            "编译模型），识别出 mdk 时会明确让你走 build_project / rebuild_project。\n"
            "max_up 控制往上搜的层数（默认 3），在子目录里调用时不必手工 cd 到根。"
        ),
    )
    async def toolchain_detect_project(path: str = "", max_up: int = 3) -> str:
        try:
            return _js(detect_project(path, max_up=int(max_up)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "path": path, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_build",
        title="构建非 MDK 工程（cmake 自动 configure+build / make 直接 -j）",
        description=(
            "按 toolchain_detect_project 识别出的构建方式执行构建。cmake 工程会先 "
            "configure（默认缓存到 build_dir，已配置过就跳过）再 build；make 工程按 "
            "-f <Makefile> -jN 跑。\n"
            "**为什么值得用而不是 toolchain_run 手敲**：它做了三件容易忘的事——"
            "（1）构建前把工具链 PATH 铺好，避免 make 里调 gcc/python 找不到；"
            "（2）编译错误用 toolchain_errors 那套规则解析，返回结构化错误而不是"
            "几百行原始日志；（3）返回产物路径与实际耗时。\n"
            "generator 不指定时优先 Ninja（装了的话），否则 MinGW Makefiles；"
            "target 指定构建目标（如 all/clean/某可执行文件）；jobs=0 表示按 CPU "
            "核数；clean=true 先清理；dry_run=true 只打印将要执行的命令不真跑——"
            "**不确定它会干什么的时候先 dry_run**。"
        ),
    )
    async def toolchain_build(project: str = "", build_dir: str = "",
                              target: str = "", jobs: int = 0,
                              clean: bool = False, generator: str = "",
                              config_args: str = "", timeout: float = 900,
                              families: str = "", dry_run: bool = False,
                              extra_make_args: str = "") -> str:
        try:
            return _js(build(project=project, build_dir=build_dir, target=target,
                             jobs=int(jobs), clean=bool(clean), generator=generator,
                             config_args=config_args, timeout=float(timeout),
                             families=families, dry_run=bool(dry_run),
                             extra_make_args=extra_make_args))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "project": project, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_compile",
        title="直接用 gcc 编译源文件（不依赖 make/cmake，可只做语法校验）",
        description=(
            "把源文件列表直接喂给某个家族的 gcc。适合没有构建系统的小工程、"
            "单文件试编、以及 CI 里只验语法。\n"
            "family 选编译器家族（arm-none-eabi / riscv-none-elf / riscv32-esp-elf / "
            "xtensa-esp-elf）；defs/includes/flags 分别是 -D/-I/其它参数（字符串，"
            "多值用空格或分号分隔）；cpu/fpu/float_abi 走内置的 CPU 参数表"
            "（如 cpu=\"cortex-m4\" + fpu=\"fpv4-sp-d16\" + float_abi=\"hard\"）。\n"
            "**syntax_only=true 是关键能力**：只做 -fsyntax-only，不产生产物、不需要"
            "链接脚本，用来在一批改动后快速确认「能不能编过」，比整工程构建快一个"
            "数量级。\n"
            "只给文件不给 out 时产物落在 objdir（默认源文件旁）。"
        ),
    )
    async def toolchain_compile(files: str = "", family: str = "arm-none-eabi",
                                out: str = "", defs: str = "", includes: str = "",
                                flags: str = "", cpu: str = "", fpu: str = "",
                                float_abi: str = "", syntax_only: bool = False,
                                cwd: str = "", timeout: float = 300,
                                extra_args: str = "", objdir: str = "") -> str:
        try:
            return _js(compile_files(files, family=family, out=out, defs=defs,
                                     includes=includes, flags=flags, cpu=cpu, fpu=fpu,
                                     float_abi=float_abi,
                                     syntax_only=bool(syntax_only), cwd=cwd,
                                     timeout=float(timeout), extra_args=extra_args,
                                     objdir=objdir))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "family": family, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_elf_info",
        title="读 ELF 概览（架构 / 入口 / 段表 / 符号数）",
        description=(
            "用 pyelftools 直接解析 ELF，不依赖 objdump 是否装了：返回架构与机器类型、"
            "入口地址、段与节的区间、是否含调试信息、符号数量。\n"
            "**为什么不用 toolchain_run objdump**：objdump 的输出格式随版本变，"
            "解析容易出错；pyelftools 拿的是结构化的真值。需要反汇编时再走 "
            "toolchain_run（objdump -d）或 MDK 侧的 disassemble。\n"
            "用途：确认构建产物是预期的那颗芯片的（架构对不对）、确认调试信息在不在"
            "（没有 .debug_info 就没法做符号级调试）、拿入口地址做校验。"
        ),
    )
    async def toolchain_elf_info(elf: str) -> str:
        try:
            return _js(elf_info(elf))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "elf": elf, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_size",
        title="段大小报告（Flash/RAM 占用，按段与按符号）",
        description=(
            "报告 ELF 的 Flash/RAM 占用：优先用工具链的 size 工具拿 text/data/bss，"
            "退化为 pyelftools 统计。by_section=true 时给出按段明细，top 控制按大小"
            "排序返回多少个最大的符号。\n"
            "用途：评估还能不能再塞功能、排查「改了一行代码 Flash 涨了 8K」这类问题"
            "（多半是某张大表被拉进来了）。注意 size 的 text 口径含只读数据，"
            "与链接脚本的 FLASH 区大小不是一回事，判断溢出要看 map 文件。"
        ),
    )
    async def toolchain_size(elf: str, family: str = "arm-none-eabi",
                             by_section: bool = True, top: int = 15) -> str:
        try:
            return _js(size_report(elf, family=family,
                                   by_section=bool(by_section), top=int(top)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "elf": elf, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_objcopy",
        title="ELF 转 bin / hex / srec（烧录用产物）",
        description=(
            "调用工具链的 objcopy 把 ELF 转成裸镜像：bin（binary）、hex（ihex）、"
            "srec。out 不给就按 ELF 同名生成。\n"
            "常见坑：bin 是**纯地址空间转储**，起始地址不是 0x08000000 时"
            "（比如有 bootloader 或从 0x08004000 起），生成的 bin 需要按偏移烧写，"
            "烧录地址错了芯片就起不来——那种情况用 hex 更安全，它自带地址信息。"
        ),
    )
    async def toolchain_objcopy(elf: str, fmt: str = "bin", out: str = "",
                                family: str = "arm-none-eabi", extra: str = "") -> str:
        try:
            return _js(objcopy(elf, fmt=fmt, out=out, family=family, extra=extra))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "elf": elf, "error": str(e)})
    n += 1

    @server.tool(
        name="toolchain_errors",
        title="解析 gcc/ld 输出成结构化错误（含中文提示与建议）",
        description=(
            "把原始编译日志（toolchain_build / toolchain_compile / toolchain_run 的 "
            "stdout+stderr 拼起来）解析成结构化错误列表：文件、行号、列号、级别、"
            "原始消息，外加常见错误的**中文解释与处理建议**（未声明标识符、未定义引用、"
            "区域溢出、重复定义、头文件找不到等）。\n"
            "**为什么单独做一个工具**：gcc 的错误信息量很大且带颜色/多行上下文，"
            "直接塞给模型既费 token 又容易看串行；先解析成 (文件,行,级别,消息) 的"
            "列表，再按需要看原文，定位效率高得多。\n"
            "text 也可以直接给一段你手里的日志；limit 控制最多返回多少条。"
        ),
    )
    async def toolchain_errors(text: str = "", limit: int = 200) -> str:
        try:
            return _js(parse_gcc_output(text, limit=int(limit)))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
