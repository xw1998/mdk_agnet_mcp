# -*- coding: utf-8 -*-
"""批次62 mock 测试：方案4（透出符号未核对状态）+ 方案3（烧录后自动重钉符号）。

背景（批次61 收尾时列出的两条残留问题，同一根问题的两半）：
  「符号修复手段不在默认工具面上」修完之后，检测器与钥匙都到位了，但还有两处缺口：
    缺口A（方案4）：**解析成功 ≠ 名字可信**。get_current_location 只在「PC 解析不出来」
      时才告警；而假符号最隐蔽的形态恰恰是「解析得很成功」——PC 落在另一套固件的函数里，
      名字看着像样，其实是板上早被链接器裁掉的函数（真机踩过 rt_mq_send_wait）。
    缺口B（方案3）：**烧录就是符号漂移的源头**，可服务端在源头处什么都不做，只在事后由
      env_check / trace_record 报「符号可能不同源」，还要调用方自己动手。

本批次两条都做，各自守住一条底线：
  - 方案4 不改行为、只透出可信度：_symbol_verify 记「本会话核对过没有」，_build_location
    在解析成功路径上也附 symbol_verified；**只有 same / content-confirmed 才算数**，
    其余一律清空（没测 ≠ 通过）。
  - 方案3 带显式优先规则：当前符号是调用方显式 set_symbol_file 装的 -> 不覆盖，只回
    kept-explicit + 可执行动作；其余（启动/推断/自动匹配/上次重钉）才重钉到刚烧的 .axf。

运行：python -m tests.test_batch62
"""
import os
import sys
import json
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import server as SV          # noqa: E402

PORT = 15511
AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
MAP = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.map")

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def snapshot():
    return (dict(SV._symbol_cfg), dict(SV._symbol_verify), dict(SV._fw_cfg))

def restore(snap):
    SV._symbol_cfg.clear(); SV._symbol_cfg.update(snap[0])
    SV._symbol_verify.clear(); SV._symbol_verify.update(snap[1])
    SV._fw_cfg.clear(); SV._fw_cfg.update(snap[2])

def stub_loader(rec):
    """替身：不真解析 .axf，只记下调用参数并回报成功。"""
    def _f(path, source="set_symbol_file"):
        rec.append({"path": path, "source": source})
        SV._symbol_cfg.update({"locator": "stub", "axf": os.path.abspath(path),
                               "source_type": "axf", "axf_source": source})
        return True, "stub 已加载 %s" % os.path.basename(path), 7
    return _f

# 需要「一个真实存在的 .axf」时直接用仓库内示例工程的产物：不往仓库根写临时文件
# （测试留下的垃圾会被 git status 看见，也污染别人的工作区）。

# ======================================================================
def group_a():
    print("A. _rebind_symbol_to_flashed：显式优先，不许悄悄替调用方做决定")
    snap = snapshot()
    orig = SV._load_symbol_file
    try:
        rec = []
        SV._load_symbol_file = stub_loader(rec)

        # ---- A1/A2 显式装的符号不被覆盖 ----
        SV._symbol_cfg.update({"locator": "stub", "axf": r"D:\fwA\app.axf",
                               "source_type": "axf", "axf_source": "set_symbol_file"})
        out = SV._rebind_symbol_to_flashed(AXF, "flash_download")
        check("A1 显式 set_symbol_file 装过 → kept-explicit（不覆盖）",
              out.get("action") == "kept-explicit", out)
        check("A2 kept-explicit 时当前符号原样保留（服务端不替调用方改回去）",
              SV._symbol_cfg.get("axf") == r"D:\fwA\app.axf" and rec == [],
              (SV._symbol_cfg.get("axf"), rec))
        check("A3 kept-explicit 给出可执行的切换动作（不是只抱怨）",
              isinstance(out.get("next_actions"), list)
              and any("set_symbol_file" in a for a in out["next_actions"]), out)
        check("A4 kept-explicit 说明里点出「显式选择优先」与两种合法场景",
              "显式选择优先" in (out.get("note") or "")
              and "App 重定位" in (out.get("note") or ""), out.get("note"))

        # ---- A5/A6 非显式 -> 重钉 ----
        SV._symbol_cfg.update({"locator": None, "axf": None, "source_type": None,
                               "axf_source": "从默认工程推断：D:\\x\\y.uvprojx"})
        rec[:] = []
        out2 = SV._rebind_symbol_to_flashed(AXF, "build_and_flash")
        check("A5 非显式（启动推断/自动匹配）→ rebound，切到刚烧的 .axf",
              out2.get("action") == "rebound"
              and SV._symbol_cfg.get("axf") == os.path.abspath(AXF), out2)
        check("A6 重钉时记下来源（下次烧录据此判断「是不是显式选的」）",
              rec and rec[0]["source"].startswith("随烧录自动重钉")
              and "build_and_flash" in rec[0]["source"], rec)
        check("A7 重钉成功即视为已核对（刚烧的固件与这份 .axf 是同一次编译产物）",
              SV._symbol_verify.get("verdict") == "same"
              and SV._symbol_verify.get("axf") == os.path.abspath(AXF),
              SV._symbol_verify)

        # ---- A8 已经是刚烧那份 ----
        SV._symbol_cfg.update({"locator": "stub", "axf": os.path.abspath(AXF),
                               "source_type": "axf", "axf_source": "set_symbol_file"})
        rec[:] = []
        out3 = SV._rebind_symbol_to_flashed(AXF, "flash_download")
        check("A8 当前符号已是刚烧那 .axf → already-current，不重复加载",
              out3.get("action") == "already-current" and rec == [], (out3, rec))

        # ---- A9/A10 推不出 / 不存在 ----
        out4 = SV._rebind_symbol_to_flashed("", "flash_download")
        check("A9 推不出 .axf → skipped，并指向 list_symbol_projects（不猜替代品）",
              out4.get("action") == "skipped" and "list_symbol_projects" in (out4.get("note") or ""),
              out4)
        out5 = SV._rebind_symbol_to_flashed(os.path.join(ROOT, "_t62_nope.axf"), "flash_debug")
        check("A10 .axf 不存在 → skipped（拿死路径当符号用会给假答案）",
              out5.get("action") == "skipped" and "不存在" in (out5.get("note") or ""), out5)

        # ---- A11 加载失败不静默 ----
        SV._symbol_cfg.update({"locator": None, "axf": None, "source_type": None,
                               "axf_source": ""})
        SV._load_symbol_file = lambda p, source="": (False, "解析失败", 0)
        out6 = SV._rebind_symbol_to_flashed(AXF, "flash_download")
        check("A11 重钉失败 → action=failed 且带 error（不假装成功）",
              out6.get("action") == "failed" and "解析失败" in (out6.get("error") or ""), out6)
    finally:
        SV._load_symbol_file = orig
        restore(snap)

# ======================================================================
def group_b():
    print("B. _load_symbol_file 记 axf_source：符号是「谁装的」必须可追")
    snap = snapshot()
    try:
        ok_file = os.path.isfile(AXF)
        check("B1 仓库内示例工程 .axf 存在（本组依赖真实符号文件）", ok_file, AXF)
        if ok_file:
            ok, msg, n = SV._load_symbol_file(AXF, source="set_symbol_file")
            check("B2 真实 .axf 加载成功", ok and n > 0, msg)
            check("B3 显式指定的来源被记进 _symbol_cfg['axf_source']",
                  SV._symbol_cfg.get("axf_source") == "set_symbol_file",
                  SV._symbol_cfg)
            ok2, msg2, _ = SV._load_symbol_file(AXF, source="§自测§")
            check("B4 换来源再装一次会覆盖（后一次是谁装的就是谁）",
                  ok2 and SV._symbol_cfg.get("axf_source") == "§自测§", SV._symbol_cfg)
        ok3, msg3, _ = SV._load_symbol_file(os.path.join(ROOT, "_t62_missing.axf"))
        check("B5 文件不存在时失败且不动状态（不会留下半个配置）",
              (not ok3) and SV._symbol_cfg.get("axf_source") == ("§自测§" if ok_file else None),
              (ok3, msg3, SV._symbol_cfg.get("axf_source")))
    finally:
        restore(snap)

# ======================================================================
def group_c():
    print("C. _record_flashed_firmware：换固件＝旧核对结论作废，并顺手重钉")
    snap = snapshot()
    try:
        SV._symbol_verify.update({"axf": AXF, "verdict": "same", "ts": time.time(),
                                  "reason": "上一轮核对"})
        out = SV._record_flashed_firmware(os.path.join(ROOT, "_t62_no_such.uvprojx"),
                                          "", "flash_download")
        check("C1 返回值里带 symbol_rebind（调用方拿得到「符号动没动」）",
              isinstance(out.get("symbol_rebind"), dict), out)
        check("C2 换固件了：上一次的「已核对」结论被清空（旧结论对新固件无效）",
              SV._symbol_verify.get("verdict") is None
              and SV._symbol_verify.get("axf") is None, SV._symbol_verify)
        check("C3 推不出 .axf 时不抛异常，如实 skipped",
              out["symbol_rebind"].get("action") == "skipped", out.get("symbol_rebind"))
        check("C4 仍照旧记下「刚烧的是什么」（缺口 B 的前提）",
              out.get("project") and out.get("reason") == "flash_download", out)
    finally:
        restore(snap)

# ======================================================================
def group_d():
    print("D. _symbol_source_check 薄包装：只有证明同源才记账，其余一律清空")
    snap = snapshot()
    orig_impl = SV._symbol_source_check_impl
    try:
        for verdict, expect in (("same", True), ("content-confirmed", True),
                                ("different", False), ("content-mismatch", False),
                                ("no-symbols", False), ("no-flash-record", False),
                                ("unknown", False)):
            SV._symbol_verify.update({"axf": r"D:\old\x.axf", "verdict": "same",
                                      "ts": 1.0, "reason": "旧结论"})
            SV._symbol_source_check_impl = (
                lambda *a, _v=verdict, **k: {"verdict": _v, "symbol_axf": AXF})
            out = SV._symbol_source_check()
            got = SV._symbol_verify.get("verdict") is not None
            check("D-%s verdict=%s → %s" % (verdict, verdict,
                                            "记入" if expect else "清空"),
                  got is expect, (out, SV._symbol_verify))

        # 真实链路的 same 分支（不 stub impl，只把符号与烧录记录对齐）
        SV._symbol_source_check_impl = orig_impl
        SV._symbol_verify.update({"axf": None, "verdict": None, "ts": 0.0, "reason": None})
        SV._symbol_cfg.update({"locator": "stub", "axf": AXF,
                               "source_type": "axf", "axf_source": "set_symbol_file"})
        SV._fw_cfg.update({"project": None, "target": None, "axf": AXF, "reason": "test",
                           "ts": time.time(), "time_text": None})
        out = SV._symbol_source_check()
        check("D8 真实链路：符号就是刚烧录的那份 → verdict=same 且记入 _symbol_verify",
              out.get("verdict") == "same" and SV._symbol_verify.get("verdict") == "same", out)
        check("D9 记的是「本次同源核对」，理由可读（不是一句『已核对』就完事）",
              "刚烧录的那份" in (SV._symbol_verify.get("reason") or ""), SV._symbol_verify)

        # 换成另一份符号 -> 旧结论不得留下
        SV._fw_cfg.update({"axf": AXF})
        SV._symbol_cfg.update({"axf": os.path.join(ROOT, "_t62_other.axf")})
        out2 = SV._symbol_source_check(deep="false")
        check("D10 换了符号文件后再核对（different）→ 旧 green 标记被清掉",
              out2.get("verdict") == "different"
              and SV._symbol_verify.get("verdict") is None, out2.get("verdict"))
    finally:
        SV._symbol_source_check_impl = orig_impl
        restore(snap)

# ======================================================================
def group_e():
    print("E. _build_location：解析成功路径也要透出「这份符号核对过没有」")
    snap = snapshot()
    try:
        SV._symbol_cfg.update({"locator": "stub", "axf": AXF, "source_type": "axf",
                               "axf_source": "set_symbol_file"})
        SV._symbol_verify.update({"axf": AXF, "verdict": "same", "ts": time.time(),
                                  "reason": "符号就是刚烧录的那份 .axf"})
        r1 = {}
        SV._note_symbol_verified(r1)
        check("E1 已核对且就是当前这份 → symbol_verified=true + 说明",
              r1.get("symbol_verified") is True and "同源" in r1.get("symbol_verified_note", ""),
              r1)

        SV._symbol_verify.update({"axf": r"D:\other\b.axf", "verdict": "same"})
        r2 = {}
        SV._note_symbol_verified(r2)
        check("E2 核对结论是别的一份 .axf → false（换了符号文件，旧结论不算数）",
              r2.get("symbol_verified") is False, r2)

        SV._symbol_verify.update({"axf": None, "verdict": None, "ts": 0.0, "reason": None})
        r3 = {}
        SV._note_symbol_verified(r3)
        check("E3 从未核对 → false，且提示词点出「假符号」与怎么办",
              r3.get("symbol_verified") is False
              and "假符号" in r3.get("symbol_verified_note", "")
              and "env_check" in r3.get("symbol_verified_note", "")
              and "set_symbol_file" in r3.get("symbol_verified_note", ""), r3)

        src = open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
        check("E4 _build_location 在「解析成功」分支就调用（不是只在失败时告警）",
              src.count("    if cur:\n        _note_symbol_verified(result)\n") == 1,
              src.count("_note_symbol_verified(result)"))
        check("E5 _note_symbol_verified 只透出可信度、不改行为（无副作用调用点）",
              src.count("_note_symbol_verified(") == 2, src.count("_note_symbol_verified("))
    finally:
        restore(snap)

# ======================================================================
def group_f():
    print("F. 接线自检：三处烧录出口都要把 symbol_rebind 交给调用方")
    src = open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("F1 flash_download / build_and_flash 都取返回值并透出",
          src.count('out["symbol_rebind"] = fw["symbol_rebind"]') == 2,
          src.count('out["symbol_rebind"] = fw["symbol_rebind"]'))
    check("F2 flash_debug 的 payload 带 symbol_rebind（变量在 payload 前已初始化）",
          '"symbol_rebind": symbol_rebind,' in src
          and "symbol_rebind = None\n            if enter.get(\"ok\"):" in src, "")
    check("F3 三个 _load_symbol_file 调用点各自标明来源（默认值只留给显式切换）",
          src.count('_load_symbol_file(\n                        axf, source=') == 1
          and src.count('source="会话恢复（状态快照里记录的符号）"') == 1
          and src.count('def _load_symbol_file(path: str, source: str = "set_symbol_file")') == 1,
          "")
    check("F4 _record_flashed_firmware 一定调用重钉（否则烧录出口拿不到东西）",
          src.count("out[\"symbol_rebind\"] = _rebind_symbol_to_flashed(") == 1, "")
    check("F5 重钉的实现只有一份（不许在工具层再写一遍优先级）",
          src.count("def _rebind_symbol_to_flashed(") == 1, "")

# ======================================================================
def group_g():
    print("G. 端到端：flash_download 成功 → 返回值里能看到符号被钉到新固件")
    snap = snapshot()
    srv = SV.create_server(port=PORT, toolsets="all")
    orig_fd = SV.builder.flash_download
    try:
        proj = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test.uvprojx")
        SV.builder.flash_download = lambda *a, **k: {"ok": True, "flash": "stub"}
        if not os.path.isfile(AXF):
            check("G1 示例工程已编译（本组需要真实 .axf）", False, AXF)
            return
        SV._symbol_cfg.update({"locator": None, "axf": None, "source_type": None,
                               "axf_source": "从默认工程推断：别的工程"})
        import asyncio as _a
        res = _a.run(srv.call_tool("flash_download", {"project": proj}))
        txt = "".join(getattr(c, "text", "") or "" for c in res.content)
        out = json.loads(txt)
        rb = out.get("symbol_rebind") or {}
        check("G1 flash_download 返回值带 symbol_rebind", bool(rb), out.get("symbol_rebind"))
        check("G2 非显式符号 → 自动重钉到该工程刚烧的 .axf",
              rb.get("action") == "rebound"
              and SV._symbol_cfg.get("axf") == os.path.abspath(AXF), rb)
        check("G3 重钉后 _symbol_verify 已标记同源（后续停靠位置不再唱「未核对」）",
              SV._symbol_verify.get("verdict") == "same", SV._symbol_verify)

        # 显式场景：调一次 set_symbol_file 换一份**不同**的符号（.map，故意与刚烧的 .axf
        # 不是同一份文件），再烧一次，此时必须 kept-explicit。
        r2 = _a.run(srv.call_tool("set_symbol_file", {"path": MAP}))
        txt2 = "".join(getattr(c, "text", "") or "" for c in r2.content)
        check("G4 set_symbol_file 走真实加载（默认面外工具，直接调用仍可用）",
              json.loads(txt2).get("ok") is True, txt2[:200])
        check("G4b 当前符号换成了 .map（与即将烧的 .axf 不同一份）",
              SV._symbol_cfg.get("source_type") == "map"
              and SV._symbol_cfg.get("axf") is None, SV._symbol_cfg)
        r3 = _a.run(srv.call_tool("flash_download", {"project": proj}))
        out3 = json.loads("".join(getattr(c, "text", "") or "" for c in r3.content))
        rb3 = out3.get("symbol_rebind") or {}
        check("G5 显式 set_symbol_file 之后烧录 → kept-explicit（不推翻调用方的选择）",
              rb3.get("action") == "kept-explicit", rb3)
    finally:
        SV.builder.flash_download = orig_fd
        restore(snap)

def main():
    print("批次62：方案4（透出符号未核对状态）+ 方案3（烧录后自动重钉，显式优先）")
    group_a(); group_b(); group_c(); group_d(); group_e(); group_f(); group_g()
    print("\n==== 批次62 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
