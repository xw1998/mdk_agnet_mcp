# -*- coding: utf-8 -*-
"""批次77 mock 测试：固件契约预检 + 闭环上板验证 + 工程编辑补齐。

来由：对照 GitHub 上的 STM32_AutoDebug_Universal_Kit（MIT，v2.4.3），把它的三处
工程化做法吸收进来——① 上板**前**先做固件契约预检；② 「编译→开串口→烧录→等令牌」
一条命令闭环（顺序才是关键）；③ 工程编辑补齐改 Define 与调试信息。

  A uvprojx：add_defines/del_defines/set_debug_information/debug_information
             （必须只写 <Cads> 那一份，不碰汇编器的 Aads；幂等；错误 target 报错）
  B precheck：编码判定 / 字面量扫描 / 端到端 verdict（含 AC5+UTF-8 中文字面量 → blocked）
  C verify  ：run_closed_loop 八种 verdict 的注入式判定（无硬件也全可测）
  D 工具面  ：注册 / 分组 / 注解归类 / 预检工具端到端

运行：python -m tests.test_batch77
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import uvprojx as UV          # noqa: E402
from mdkdebug import precheck as PC          # noqa: E402
from mdkdebug import verify as VF            # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402
from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import server as SV            # noqa: E402

PORT = 15577
EXAMPLE = os.path.join(ROOT, "example_mdk_project", "mdk_test",
                       "MDK-ARM", "mdk_test.uvprojx")
PASS, FAIL = [], []
_TMP = []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def _mkproj():
    """把例程工程复制到临时目录，返回副本路径（改动只在副本上发生）。"""
    d = tempfile.mkdtemp(prefix="mdk77_")
    _TMP.append(d)
    sub = os.path.join(d, "MDK-ARM")
    os.makedirs(sub)
    p = os.path.join(sub, "mdk_test.uvprojx")
    shutil.copy2(EXAMPLE, p)
    return d, p

def _first_source_dir(project):
    """返回工程实际引用的第一个存在的源文件所在目录（放合成源文件用）。"""
    for g in UV.list_groups(project):
        for f in (g.get("files") or []):
            ap = os.path.normpath(os.path.join(os.path.dirname(project),
                                               str(f.get("path") or "")))
            if os.path.isfile(ap):
                return os.path.dirname(ap)
    return os.path.dirname(project)

# ==================================================================
def section_a():
    print("A. uvprojx：Define 与调试信息")
    d, p = _mkproj()
    base_cfg = UV.read_config(p, "mdk_test")
    check("A0 副本工程可读且 Define 有值", base_cfg.get("ok") and base_cfg.get("define"),
          base_cfg)

    r = UV.add_defines(p, ["BOARD_V2", "USE_HAL_DRIVER"], "mdk_test")
    check("A1 add_defines 新增 + 已存在的跳过",
          r.get("ok") and r.get("changed") and r.get("added") == ["BOARD_V2"]
          and r.get("skipped") == ["USE_HAL_DRIVER"], r)

    # 只改了 Cads 那一份：用 ElementTree 分别看 Cads / Aads 的 Define
    tree = ET.parse(p)
    cads = tree.find(".//Targets/Target/TargetOption/TargetArmAds/Cads/VariousControls/Define")
    aads = tree.find(".//Targets/Target/TargetOption/TargetArmAds/Aads/VariousControls/Define")
    c_text = (cads.text or "") if cads is not None else ""
    a_text = (aads.text or "") if aads is not None else ""
    check("A2 新宏写进 Cads 的 Define",
          "BOARD_V2" in c_text, c_text)
    check("A3 汇编器那份 Aads 的 Define 没被动过",
          "BOARD_V2" not in a_text, a_text)

    r2 = UV.add_defines(p, ["BOARD_V2"], "mdk_test")
    check("A4 重复添加幂等（changed=False、added 空）",
          r2.get("ok") and r2.get("changed") is False and r2.get("added") == [], r2)

    r3 = UV.del_defines(p, r"BOARD_.*", "mdk_test")
    check("A5 del_defines 按正则删除", r3.get("ok") and r3.get("removed") == ["BOARD_V2"], r3)
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    check("A6 删完文本里 BOARD_V2 已消失", "BOARD_V2" not in raw)

    r4 = UV.del_defines(p, "NOSUCH_.*", "mdk_test")
    check("A7 没匹配到时 changed=False", r4.get("ok") and r4.get("changed") is False, r4)

    r5 = UV.set_debug_information(p, False, "mdk_test")
    check("A8 set_debug_information(false) 生效",
          r5.get("ok") and r5.get("changed") and r5.get("after") == "0", r5)
    check("A9 debug_information 只读回读一致",
          UV.debug_information(p, "mdk_test").get("enabled") is False,
          UV.debug_information(p, "mdk_test"))
    UV.set_debug_information(p, True, "mdk_test")
    check("A10 复位回 1", UV.debug_information(p, "mdk_test").get("enabled") is True, "")

    r6 = UV.add_defines(p, ["X"], "__no_such_target__")
    check("A11 错误 target 明确报错、不改文件",
          r6.get("ok") is False and "targets" in r6, r6)

    # XML 仍然可解析（文本级替换没把文件洗坏）
    try:
        ET.parse(p)
        check("A12 改动后仍是合法 XML", True)
    except Exception as e:                                        # noqa: BLE001
        check("A12 改动后仍是合法 XML", False, e)

# ==================================================================
def section_b():
    print("B. precheck：编码 / 字面量 / 端到端")
    check("B1 ascii 判定", PC.classify_encoding(b"int x;\n") == "ascii")
    check("B2 utf-8 判定", PC.classify_encoding("中".encode("utf-8")) == "utf-8")
    check("B3 gbk 判定", PC.classify_encoding("中".encode("gbk")) == "gbk")
    check("B4 unknown 判定", PC.classify_encoding(b"\xff\xfe\x01\x02") == "unknown")

    lits = PC.scan_literals('const char *s = "中文";\n')
    check("B5 字面量里的中文被抓到",
          any(x.get("non_ascii") and x.get("kind") == "literal" for x in lits), lits)
    check("B6 纯注释里的中文不算",
          PC.scan_literals("// 这是中文注释\nint x;\n") == [])
    check("B7 纯 ascii 字面量不算",
          PC.scan_literals('const char *s = "hello";\n') == [])

    # 端到端：例程工程（没有通过令牌 → warn，但不 blocked）
    r = PC.precheck(EXAMPLE, "mdk_test")
    check("B8 例程工程可预检且 target 是真名",
          r.get("ok") is not None and r.get("target") == "mdk_test", r.get("target"))
    ids = {c["id"]: c.get("status") for c in (r.get("checks") or [])}
    check("B9 四项检查齐全",
          set(ids) == {"ac5_non_ascii_literal", "pass_token",
                       "debug_information", "serial"}, ids)
    check("B10 例程工程 verdict=warn（无通过令牌）",
          r.get("verdict") == "warn" and "pass_token" in r.get("warned", []), r.get("verdict"))

    # 造一个 AC5 + UTF-8 中文字面量 → blocked
    d, p = _mkproj()
    srcdir = _first_source_dir(p)
    cpath = os.path.join(srcdir, "batch77_cn.c")
    with open(cpath, "wb") as f:
        f.write('const char *g_msg = "中文测试串";\n'.encode("utf-8"))
    UV.add_files(p, "Application/User/Core", [os.path.relpath(cpath, os.path.dirname(p))],
                 backup=False)
    r2 = PC.precheck(p, "mdk_test")
    check("B11 UTF-8 中文字面量 → blocked",
          r2.get("verdict") == "blocked"
          and "ac5_non_ascii_literal" in r2.get("failed", []), r2.get("verdict"))
    lit_find = [c for c in r2.get("checks") or []
                if c["id"] == "ac5_non_ascii_literal"][0]
    check("B12 findings 里给出文件名与行号",
          lit_find.get("findings") and lit_find["findings"][0].get("line") == 1,
          lit_find.get("findings"))

# ==================================================================
def _run(**kw):
    return VF.run_closed_loop(**kw)

def section_c():
    print("C. verify：八种 verdict")
    # C1 编译失败
    flashed = {"n": 0}
    r = _run(token="T",
             build_fn=lambda: {"ok": False, "exit_code": 2},
             flash_fn=lambda: flashed.__setitem__("n", flashed["n"] + 1) or {"ok": True},
             monitor_start_fn=lambda: {"ok": True})
    check("C1 编译失败 → build_failed 且不烧录",
          r["verdict"] == "build_failed" and flashed["n"] == 0, r["verdict"])

    # C2 串口不可用 → 不烧录
    flashed = {"n": 0}
    r = _run(token="T",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": False, "error": "no port"},
             flash_fn=lambda: flashed.__setitem__("n", flashed["n"] + 1) or {"ok": True},
             expect_fn=lambda *a: {"matched": True})
    check("C2 串口不可用 → serial_unavailable 且不烧录",
          r["verdict"] == "serial_unavailable" and flashed["n"] == 0, r["verdict"])

    # C3 烧录失败
    r = _run(token="T",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": False, "error": "erase failed"},
             expect_fn=lambda *a: {"matched": True})
    check("C3 烧录失败 → flash_failed", r["verdict"] == "flash_failed", r["verdict"])

    # C4 通过（令牌在烧录之后）
    r = _run(token="[ALL TESTS PASSED]",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": True},
             cursor_fn=lambda: 0,
             expect_fn=lambda tok, to, since: {
                 "matched": True, "matched_line": "...[ALL TESTS PASSED]",
                 "items": [{"t": time.time() + 10, "line": "..."}], "matched_index": 0},
             tail_fn=lambda n: ["...", "[ALL TESTS PASSED]"])
    check("C4 烧录后收到令牌 → passed（ok=True、无可执行的 next_actions）",
          r["verdict"] == "passed" and r["ok"] is True and r["next_actions"] == [],
          r["verdict"])

    # C5 令牌是旧的（在烧录之前）→ token_stale
    r = _run(token="T",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": True},
             expect_fn=lambda *a: {"matched": True, "matched_line": "old",
                                   "items": [{"t": 1.0, "line": "old"}], "matched_index": 0})
    check("C5 令牌出现在烧录之前 → token_stale",
          r["verdict"] == "token_stale" and r.get("token_after_flash") is False,
          r["verdict"])

    # C6 有输出但等不到令牌
    r = _run(token="T",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": True},
             expect_fn=lambda *a: {"matched": False, "timeout_kind": "timeout"})
    check("C6 有输出无令牌 → token_timeout", r["verdict"] == "token_timeout", r["verdict"])

    # C7 一个字节都没有
    r = _run(token="T",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": True},
             expect_fn=lambda *a: {"matched": False, "timeout_kind": "no-data"})
    check("C7 无任何新增 → no_output", r["verdict"] == "no_output", r["verdict"])

    # C8 未配令牌 → captured（不作判定）
    r = _run(token="",
             build_fn=lambda: {"ok": True},
             monitor_start_fn=lambda: {"ok": True},
             flash_fn=lambda: {"ok": True},
             expect_fn=lambda *a: {"lines": ["boot ok"]})
    check("C8 token 为空 → captured 且 ok=False",
          r["verdict"] == "captured" and r["ok"] is False, r["verdict"])

    check("C9 verdict 表含全部取值",
          set(VF.VERDICTS) >= {"build_failed", "serial_unavailable", "flash_failed",
                               "passed", "token_stale", "token_timeout",
                               "no_output", "captured"})

# ==================================================================
def section_d():
    print("D. 工具面")
    build = TB.tools_of("build")
    check("D1 firmware_precheck 在 build 组", "firmware_precheck" in build, len(build))
    check("D2 build_flash_verify 在 build 组", "build_flash_verify" in build, len(build))
    check("D3 build 组规模 18", len(TB.TOOLSETS["build"]) == 18, len(TB.TOOLSETS["build"]))

    all_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="all").list_tools()))
    core_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="core").list_tools()))
    check("D4 注册总数 202", all_n == 202, all_n)
    check("D5 默认面仍 44（两个新工具不在默认面）", core_n == 44, core_n)

    a_pre = AN.annotations_for("firmware_precheck")
    check("D6 firmware_precheck 标为只读",
          a_pre["readOnlyHint"] is True and a_pre["destructiveHint"] is False, a_pre)
    a_blv = AN.annotations_for("build_flash_verify")
    check("D7 build_flash_verify 标为会改/不可逆/非幂等",
          a_blv["readOnlyHint"] is False and a_blv["destructiveHint"] is True
          and a_blv["idempotentHint"] is False, a_blv)

    names = [t for t in asyncio.run(SV.create_server(port=PORT, toolsets="all").list_tools())]
    bad = AN.check_surface([t.name for t in names])
    check("D8 注解表全覆盖（check_surface 无问题）", not bad, bad)

    # 端到端：例程工程跑一次预检
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "firmware_precheck", {"project": EXAMPLE, "target": "mdk_test"})).content[0].text)
    check("D9 firmware_precheck 工具端到端返回 verdict",
          r.get("verdict") in ("ready", "warn", "blocked") and r.get("checks"), r.get("verdict"))

    # uvprojx_edit 的未知 action 要列出 3 个新 action
    r = json.loads(asyncio.run(SV.create_server(port=PORT, toolsets="all").call_tool(
        "uvprojx_edit", {"action": "nosuch", "project": EXAMPLE})).content[0].text)
    avail = r.get("available") or []
    check("D10 uvprojx_edit 报错时列出 add_defines/del_defines/set_debug_information",
          "add_defines" in avail and "del_defines" in avail
          and "set_debug_information" in avail, avail)

# ==================================================================
def main():
    for fn in (section_a, section_b, section_c, section_d):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常: %r" % (fn.__name__, e))
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)
    print("\n==== test_batch77: %d pass / %d fail ====" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAIL:", f)
        sys.exit(1)

if __name__ == "__main__":
    main()
