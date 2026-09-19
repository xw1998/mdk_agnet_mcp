# -*- coding: utf-8 -*-
"""批次60 mock/本机测试：UV4 定位不再靠「巧合」、候选函数不再 NameError、目标解析不再指错方向。

反馈/复核来源（别人报的第一条 + 我复核时补的第二、三条）：
  1. builder.py：`_logical_drives()` / `uv4_candidates()` / `_uv4_from_registry()`
     ——多盘符候选 + 注册表探测，含 WoW6432Node 坑
  2. server.py：模块级 `_find_project_candidates`（从 create_server 内提升出来），
     否则模块级的 `_ensure_locator()` 调到它只会抛 NameError
  3. 目标解析的 `looks_like_file` / 行号 0 / 缺行号三类误导性原因

本机实测（Windows + 64 位 Python + Keil on D:）：
  * `HKLM\\SOFTWARE\\Keil\\Products\\MDK` 在 64 位视图下不存在（错误码 2），
    值只在 WOW6432Node（32 位视图）里 → 旧实现注册表这路等于没查
  * 该键的 `Path` 是 `D:\\Keil_v5\\ARM`（工具根，不是安装根）→ 旧实现拼出的路径不存在
  * 旧默认 max_depth=2 连本仓库自带的 example_mdk_project 都搜不到（它在第 3 层）

运行：python -m tests.test_batch60
"""
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import builder  # noqa: E402
from mdkdebug import server  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:300]), flush=True)


# ---------------------------------------------------------------- 假 winreg
class _FWinKey:
    def __init__(self, root):
        self._root = root

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _make_fake_winreg(entries):
    """entries: {(hive, sub, view): Path 值}；未命中的组合报 OSError(winerror=2)。"""
    m = types.ModuleType("winreg")
    m.HKEY_LOCAL_MACHINE = "HKLM"
    m.HKEY_CURRENT_USER = "HKCU"
    m.KEY_READ = 0x20019
    m.KEY_WOW64_32KEY = 0x0200
    m.KEY_WOW64_64KEY = 0x0100

    def _view(access):
        if access & m.KEY_WOW64_32KEY:
            return "32"
        if access & m.KEY_WOW64_64KEY:
            return "64"
        return "64"

    def OpenKey(hive, sub, reserved=0, access=0):
        key = (hive, sub, _view(access))
        if key not in entries:
            err = OSError(2, "系统找不到指定的文件。")
            err.winerror = 2
            raise err
        return _FWinKey(entries[key])

    def QueryValueEx(key, name):  # noqa: N802
        return (key._root, 1)

    m.OpenKey = OpenKey
    m.QueryValueEx = QueryValueEx
    return m


class _SwapWinreg:
    """把 sys.modules['winreg'] 换成假的，退出时还原。"""

    def __init__(self, entries):
        self._fake = _make_fake_winreg(entries)
        self._saved = None

    def __enter__(self):
        self._saved = sys.modules.get("winreg")
        sys.modules["winreg"] = self._fake
        return self._fake

    def __exit__(self, *a):
        if self._saved is None:
            sys.modules.pop("winreg", None)
        else:
            sys.modules["winreg"] = self._saved
        return False


# ---------------------------------------------------------------- 假 locator
class _StubLocator:
    def __init__(self):
        self.calls = []

    def line_to_addr_ex(self, file, line):
        self.calls.append((file, line))
        return {"addr": 0x08000000 + line, "file": file, "line": line,
                "matched_file": file, "matched_line": line, "fuzz": 0,
                "candidates": [{"addr": "0x%08x" % (0x08000000 + line),
                                "file": file, "line": line, "fuzz": 0}],
                "ambiguous": False, "files": [file], "reason": None}


def main():
    print("=" * 72)
    print("批次60：UV4 定位 + 模块级候选 + 目标解析判别")
    print("=" * 72)

    # ============ A. builder：UV4 定位 ============
    print("A. builder：UV4 定位（多盘符 + 注册表双视图 + Path 语义）")
    builder._DRIVE_CACHE = None
    drives = builder._logical_drives()
    if os.name == "nt":
        check("A1 盘符枚举非空且形如 'X:\\\\'",
              bool(drives) and all(len(d) == 3 and d.endswith(":\\") for d in drives),
              drives)
        check("A2 枚举到的盘符都真实存在",
              all(os.path.isdir(d) for d in drives), drives)
    else:
        check("A1 非 Windows：盘符枚举为空表", drives == [], drives)
        check("A2 非 Windows：空表不报错", True)

    cands = builder.uv4_candidates()
    check("A3 候选覆盖每个盘符的常见安装子目录",
          all(any(c.lower().startswith(d.lower()) for c in cands) for d in drives)
          and len(cands) >= len(drives) * len(builder._KEIL_UV4_SUBDIRS),
          {"drives": drives, "n": len(cands)})
    check("A4 候选去重", len(cands) == len(set(cands)), len(cands) - len(set(cands)))
    check("A5 候选不再写死盘符常量（_UV4_CANDIDATES 已移除）",
          not hasattr(builder, "_UV4_CANDIDATES"), dir(builder)[:0])
    extra = ["Z:\\nope\\UV4\\UV4.exe"]
    check("A6 extra 追加在最前",
          builder.uv4_candidates(extra)[0] == extra[0],
          builder.uv4_candidates(extra)[:2])

    check("A7 注册表视图含 32 位与 64 位两个",
          (os.name != "nt")
          or [n for n, _f in builder._keil_reg_views()][:2]
          == ["32 位视图", "64 位视图"],
          builder._keil_reg_views())

    if os.name == "nt":
        # A8：真注册表下不抛异常，且「命中即真实存在」（Keil 是 32 位程序，值只在
        #     WOW6432Node 里——旧实现按 64 位视图查，本机必然一无所获）
        got_real, tried_real = builder._uv4_from_registry()
        check("A8 真注册表：不抛异常，命中则路径真实存在",
              got_real is None or os.path.isfile(got_real),
              {"got": got_real, "tried": tried_real[:2]})
        check("A9 真注册表：证据可读（找不到时说明查过哪些键/视图）",
              got_real is not None or len(tried_real) >= 1, tried_real[:2])

        # A10~A13：仅 32 位视图有值（本机真实情况）+ Path 指工具根（...\Keil_v5\ARM）
        import tempfile
        tmp = tempfile.mkdtemp(prefix="mdk60_")
        try:
            uv4_dir = os.path.join(tmp, "Keil_v5", "UV4")
            os.makedirs(uv4_dir)
            exe = os.path.join(uv4_dir, "UV4.exe")
            open(exe, "wb").close()
            arm_root = os.path.join(tmp, "Keil_v5", "ARM")
            os.makedirs(arm_root)
            with _SwapWinreg({("HKLM", r"SOFTWARE\Keil\Products\MDK", "32"): arm_root}):
                got, tried = builder._uv4_from_registry()
            check("A10 值只注册在 32 位视图时也能命中（证明确实查了 WOW6432Node 视图）",
                  bool(got) and os.path.normcase(got) == os.path.normcase(exe),
                  {"got": got, "want": exe, "tried": tried[:2]})
            check("A11 Path 指工具根（...Keil_v5\\ARM）时上提一级才拼得出真路径",
                  bool(got) and os.path.normcase(os.path.dirname(os.path.dirname(got)))
                  == os.path.normcase(os.path.join(tmp, "Keil_v5")), got)
            with _SwapWinreg({}):
                got2, tried2 = builder._uv4_from_registry()
            check("A12 一个都对不上时返回 None + 非空证据",
                  got2 is None and len(tried2) >= 4, {"tried": tried2[:3]})
            check("A13 证据里写明查过哪些键/视图",
                  all(("视图" in t and "MDK" in t) for t in tried2[:4]) if tried2 else False,
                  tried2[:2])
            with _SwapWinreg({("HKLM", r"SOFTWARE\Keil\Products\MDK", "32"): arm_root}):
                det = builder.find_uv4_detailed()
            check("A14 find_uv4_detailed 给出来源（盘符候选或注册表）",
                  det.get("uv4") is not None
                  and det.get("source") in ("盘符候选", "注册表"), det)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

        exe_here = None
        for c in cands:
            if os.path.isfile(c):
                exe_here = c
                break
        check("A17 本机能找到 UV4 时不依赖写死盘符（走盘符候选或注册表）",
              (exe_here is None) or (builder.find_uv4_detailed().get("uv4") is not None),
              {"cand_found": exe_here})

        # A14：显式路径优先；显式路径不存在时仍能回退
        tmp2 = None
        import tempfile as _tf
        tmp2 = _tf.mkdtemp(prefix="mdk60b_")
        try:
            fake_exe = os.path.join(tmp2, "UV4.exe")
            open(fake_exe, "wb").close()
            det = builder.find_uv4_detailed(fake_exe)
            check("A15 显式路径存在时直接用（source=显式路径）",
                  det.get("uv4") == fake_exe and det.get("source") == "显式路径", det)
            det2 = builder.find_uv4_detailed(os.path.join(tmp2, "nonexistent.exe"))
            check("A16 显式路径不存在时静默回退到探测",
                  det2.get("source") != "显式路径" or det2.get("uv4") is None, det2)
        finally:
            import shutil as _sh
            _sh.rmtree(tmp2, ignore_errors=True)

    # ============ B. server：候选函数模块级 ============
    print("B. server：_find_project_candidates 必须是模块级")
    f = getattr(server, "_find_project_candidates", None)
    check("B1 server 模块上有 _find_project_candidates", callable(f),
          type(f).__name__)
    check("B2 它不是嵌套函数（__qualname__ 无 <locals>、无外层类）",
          bool(f) and "<locals>" not in f.__qualname__ and "." not in f.__qualname__,
          getattr(f, "__qualname__", None))

    saved = list(server._SYMBOL_PROJECTS or [])
    try:
        server._SYMBOL_PROJECTS = []
        try:
            r = server._ensure_locator()
            err = None
        except NameError as e:  # noqa: BLE001
            r, err = None, e
        except Exception as e:  # noqa: BLE001
            r, err = None, e
        check("B3 空注册表时 _ensure_locator 不再抛 NameError",
              err is None, err)
        check("B4 返回值只可能是 Locator 或 None（不冒假值、不抛）",
              err is None and (r is None or type(r).__name__ == "Locator"),
              type(r).__name__)
    finally:
        server._SYMBOL_PROJECTS = saved

    import tempfile
    tmp = tempfile.mkdtemp(prefix="mdk60p_")
    cwd0 = os.getcwd()
    try:
        deep = os.path.join(tmp, "example_mdk_project", "mdk_test", "MDK-ARM")
        os.makedirs(deep)
        proj = os.path.join(deep, "mdk_test.uvprojx")
        open(proj, "w", encoding="utf-8").close()
        os.chdir(tmp)
        server._SYMBOL_PROJECTS = []
        # 前面那次调用会把结果缓存在 _symbol_cfg['locator'] 里，这里要一起清掉，
        # 否则测的是缓存而不是「附近自动发现」这条路
        _cfg_bak = dict(server._symbol_cfg)
        server._symbol_cfg["locator"] = None
        try:
            empty = server._ensure_locator()
            empty_err = None
        except Exception as e:  # noqa: BLE001
            empty, empty_err = None, e
        check("B4b 附近确实没有工程时返回 None（不猜、不崩）",
              empty is None and empty_err is None, empty_err or type(empty).__name__)
        found = server._find_project_candidates()
        check("B5 默认深度能搜到 <仓库>/<工程>/MDK-ARM/x.uvprojx（第 3 层）",
              any(os.path.normcase(x) == os.path.normcase(proj) for x in found),
              found)
        os.chdir(cwd0)
        shallow = server._find_project_candidates(max_depth=1)
        check("B6 深度上限仍然有效（max_depth=1 搜不到第 3 层）",
              all(os.path.normcase(x) != os.path.normcase(proj) for x in shallow),
              shallow)
        check("B7 返回条数有上限（默认 ≤20）",
              len(server._find_project_candidates()) <= 20, "")
    finally:
        os.chdir(cwd0)
        server._SYMBOL_PROJECTS = saved
        server._symbol_cfg.clear()
        server._symbol_cfg.update(_cfg_bak)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    # ============ C. 目标解析 ============
    print("C. _parse_target_ex：缺行号 / 行号 0 / 文件名缺失 三类判别")

    def parse(t):
        loc = _StubLocator()
        return server._parse_target_ex(loc, t), loc

    ex, _ = parse(r"D:\proj\Core\Src\main.c")
    check("C1 绝对路径漏行号 → 报「缺少行号」而不是「行号不是整数」",
          ex["addr"] is None and "缺少行号" in (ex.get("reason") or "")
          and "行号不是整数" not in (ex.get("reason") or ""), ex)
    check("C2 该情况下给出「文件:行号」写法的 hint",
          "文件:行号" in (ex.get("hint") or ""), ex.get("hint"))
    check("C3 报错里保留原始写法（可核对自己传了什么）",
          repr(r"D:\proj\Core\Src\main.c") in (ex.get("reason") or ""),
          ex.get("reason"))

    ex, _ = parse("main.c")
    check("C4 无冒号的源文件名 → 同样提示缺行号",
          ex["addr"] is None and "缺少行号" in (ex.get("reason") or ""), ex)
    ex, _ = parse("Core/Src/main.c")
    check("C5 无冒号的路径写法 → 同样提示缺行号",
          ex["addr"] is None and "缺少行号" in (ex.get("reason") or ""), ex)

    ex, loc = parse("main.c:0")
    check("C6 行号 0 被拒绝（不再下传给 locator）",
          ex["addr"] is None and ">= 1" in (ex.get("reason") or "") and not loc.calls,
          {"ex": ex, "calls": loc.calls})
    ex, loc = parse("main.c:-3")
    check("C7 负数行号被拒绝",
          ex["addr"] is None and ">= 1" in (ex.get("reason") or "") and not loc.calls,
          {"ex": ex, "calls": loc.calls})
    ex, loc = parse("main.c:")
    check("C8 冒号后为空 → 明确说「行号缺失」",
          ex["addr"] is None and "行号缺失" in (ex.get("reason") or ""), ex)
    ex, loc = parse(":77")
    check("C9 文件名缺失 → 明确说「文件名缺失」且不丢给 locator",
          ex["addr"] is None and "文件名缺失" in (ex.get("reason") or "")
          and not loc.calls, {"ex": ex, "calls": loc.calls})

    ex, loc = parse("main.c:77")
    check("C10 正常写法仍可解析（未误伤）",
          ex["addr"] == 0x08000000 + 77 and loc.calls == [("main.c", 77)],
          {"ex": ex, "calls": loc.calls})
    ex, _ = parse(r"C:\proj\main.c:1")
    check("C11 盘符绝对路径 + 行号仍可解析", ex["addr"] == 0x08000000 + 1, ex)
    ex, _ = parse("0x8000")
    check("C12 0x 地址不受影响", ex["addr"] == 0x8000 and ex["kind"] == "address", ex)
    ex, _ = parse("svcrt_task_table")
    check("C13 符号名不被误判成文件（仍是 unknown + 原错误文案）",
          ex["addr"] is None and ex["kind"] == "unknown"
          and "无法识别" in (ex.get("reason") or ""), ex)
    ex, _ = parse("")
    check("C14 空目标仍是 unknown", ex["kind"] == "unknown", ex)

    # ============ D. 接线自检 ============
    print("D. 接线：hint 透出 / 旧常量无残留")
    src = open(os.path.join(ROOT, "mdkdebug", "server.py"),
               encoding="utf-8").read()
    check("D1 run_to_line 优先透出解析器给的 hint",
          'ex.get("hint")' in src, "")
    check("D2 _looks_like_file 已落地", "_looks_like_file" in src, "")
    bsrc = open(os.path.join(ROOT, "mdkdebug", "builder.py"),
                encoding="utf-8").read()
    check("D3 builder 不再引用被删掉的 _UV4_CANDIDATES",
          "_UV4_CANDIDATES" not in bsrc, "")
    check("D4 builder 保留 find_uv4 对外签名（返回 str|None）",
          callable(getattr(builder, "find_uv4", None)), "")

    print("\n==== 批次60 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
