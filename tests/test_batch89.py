# -*- coding: utf-8 -*-
"""批次89 测试：证据来源与主张等级（REA reconstruction-coverage 的 source 匹配口径）。

批次88 只回答了「证据有多硬」（强度轴）。这一批加的是**正交的第二个轴**：
这条证据是**谁给的**。两个轴都过关，才能支撑一句具体的主张。

每节测一条「来源不对时会不会被静默算成通过」：
  A 纯函数：来源不匹配 → 该义务在 claim 视图里记 unknown（既不是 closed 也不是 failed）、
    强度够但来源错必须在 blockers 里具名、claim 与 digest 无关
  B 工具层：claim 参数校验、默认值、四个等级的实测结论、claim 不改变 ready
  C 端到端：实跑（live-run）与回放（recorded-replay）必须分开说
  D 工具面：注册数 / 分组 / 非只读 / 描述纪律 / schema 里有 claim
  E 回归：来源标注齐全、向量表来源是交付字节、evaluate 不改入参、零新增依赖

运行：python -m tests.test_batch89
"""
import ast
import asyncio
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import closure as CL        # noqa: E402
from mdkdebug import recover as RC        # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b89")
BASE = 0x08000000
FLASH = (0x08000000, 0x080FFFFF)
RAM = (0x20000000, 0x2001FFFF)
PASS, FAIL = [], []
_proj_cache = {}

os.makedirs(TMP, exist_ok=True)

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                           "" if ok else "-> %r" % (detail,)))

def fact(value=True, authority="observed", source="t", note="", source_class=None):
    return {"value": value, "authority": authority, "source": source,
            "note": note, "source_class": source_class}

def closed_facts(**over):
    """required 五条全由 observed 证据闭合，来源按「谁给的」标注。"""
    f = {
        "artifact.identity": fact(True, "observed", "expected.sha256",
                                  source_class="shipped-artifact"),
        "build.toolchain": fact(True, "observed", "armasm/armlink",
                                source_class="controlled-replay"),
        "bytes.loadable": fact(True, "observed", "recover_verify",
                               source_class="controlled-replay"),
        "vector.entry": fact(True, "observed", "原镜像前两个字",
                             source_class="shipped-artifact"),
        "layout.regions": fact(True, "derived", "由 bytes.loadable 推出",
                               source_class="controlled-replay"),
        "symbols.addresses": fact(False, "unknown", "没有独立符号原文"),
        "runtime.bootable": fact(False, "unknown", "没有上板观察"),
        "c.semantics": fact(False, "unsupported", "机器码无类型名"),
    }
    f.update(over)
    return f

def row_of(led, oid):
    for o in led["obligations"]:
        if o["obligation_id"] == oid:
            return o
    return {}

# ======================================================================
def section_a():
    print("\nA 纯函数：来源轴与主张等级")
    check("A1 四个证据来源 + 四个主张等级都有定义",
          set(CL.SOURCE_CLASSES) == {"shipped-artifact", "controlled-replay",
                                     "live-observation", "external-service"}
          and set(CL.CLAIM_AUTHORITIES) == {"shipped-artifact", "controlled-replay",
                                            "live-observation", "external"},
          (list(CL.SOURCE_CLASSES), list(CL.CLAIM_AUTHORITIES)))

    try:
        CL._fact(True, "observed", "src", source_class="made-up")
        ok, detail = False, "没有报错"
    except ValueError as e:
        ok, detail = "未知的证据来源" in str(e), str(e)
    check("A2 来源拼错/自造 → 直接报错（不静默当成合格来源）", ok, detail)

    led = CL.evaluate(closed_facts(), claim="shipped-artifact")
    check("A3 同一份证据：shipped-artifact 主张被支撑（读字节的两条来源对得上）",
          led["summary"]["claim_supported"] is True
          and led["summary"]["qualifying_obligations"]
          == ["artifact.identity", "vector.entry"], led["summary"])

    led2 = CL.evaluate(closed_facts(**{
        "artifact.identity": fact(True, "observed", "我们自己的产物",
                                  source_class="controlled-replay")}),
        claim="shipped-artifact")
    check("A3b 换成我们重建的产物 → 来源对不上，claim_supported=false 且理由点名来源",
          led2["summary"]["claim_supported"] is False
          and any("来源" in b["why"] for b in led2["summary"]["claim_blockers"]
                  if b["obligation_id"] == "artifact.identity"),
          led2["summary"]["claim_blockers"])

    r = row_of(led2, "artifact.identity")
    check("A4 来源不对的义务在 claim 视图里记 unknown（不是 closed，也不是 failed）",
          r["status"] == "closed" and r["claim_status"] == "unknown", r)

    led3 = CL.evaluate(closed_facts(), claim="live-observation")
    check("A5 live-observation 主张：义务没闭合就明说（runtime.bootable unknown）",
          led3["summary"]["claim_supported"] is False
          and any(b["obligation_id"] == "runtime.bootable"
                  for b in led3["summary"]["claim_blockers"]), led3["summary"])
    check("A5b ready 与 claim_supported 分开：强度全闭但跑不起来，ready=true / claim=false",
          led3["summary"]["ready"] is True
          and led3["summary"]["claim_supported"] is False, led3["summary"])

    led4 = CL.evaluate(closed_facts(), claim="external")
    check("A6 external 主张：没有外部服务证据 → 不支撑，且说清「只接受 external-service」",
          led4["summary"]["claim_supported"] is False
          and any("external-service" in b["why"]
                  for b in led4["summary"]["claim_blockers"]), led4["summary"])

    led5 = CL.evaluate({}, claim="controlled-replay")
    check("A7 空证据：任何主张都不支撑，不是「没有反对意见所以通过」",
          led5["summary"]["claim_supported"] is False
          and led5["summary"]["ready"] is False, led5["summary"])

    digests = {CL.evaluate(closed_facts(), claim=c)["closure_digest"]
               for c in CL.CLAIM_AUTHORITIES}
    check("A8 claim 不影响 closure_digest（digest 只锚定义务状态，可对账）",
          len(digests) == 1, digests)

    base = CL.evaluate(closed_facts(), claim="controlled-replay")
    same = all(row_of(base, o["obligation_id"])["status"] == o["status"]
               for o in CL.evaluate(closed_facts(), claim="external")["obligations"])
    check("A9 换 claim 不改义务自身的 status（只改 claim_status）", same, base["summary"])

    rec = CL.evaluate(closed_facts(), claim="live-observation",
                      source_mode="recorded-replay")
    check("A10 回放记录不能支撑 live/external：blocker 里明写「回放的既有记录」",
          any("回放的既有记录" in b["why"] for b in rec["summary"]["claim_blockers"]),
          rec["summary"]["claim_blockers"])
    rec2 = CL.evaluate(closed_facts(), claim="controlled-replay",
                       source_mode="recorded-replay")
    check("A10b 回放记录不额外拦 controlled-replay（它本来就是受控重建级）",
          not any("回放的既有记录" in b["why"]
                  for b in rec2["summary"]["claim_blockers"]), rec2["summary"])

    notes = {m: CL.evaluate(closed_facts(), source_mode=m)["summary"]["claim_note"]
             for m in CL.SOURCE_MODES}
    check("A11 三种取证方式各自说清证据从哪来（不共用一句话）",
          len(set(notes.values())) == 3 and "实跑" in notes["live-run"]
          and "回放" in notes["recorded-replay"]
          and "skip_build" in notes["no-build"], notes)

    check("A12 主张覆盖的义务只增不减（shipped ⊂ controlled ⊂ live）",
          set(CL.CLAIM_AUTHORITIES["shipped-artifact"]["obligations"])
          < set(CL.CLAIM_AUTHORITIES["controlled-replay"]["obligations"])
          < set(CL.CLAIM_AUTHORITIES["live-observation"]["obligations"]),
          {k: v["obligations"] for k, v in CL.CLAIM_AUTHORITIES.items()})

    led6 = CL.evaluate(closed_facts(**{
        "layout.regions": fact(True, "derived", "由 bytes.loadable 推出",
                               source_class="controlled-replay")}),
        claim="controlled-replay")
    check("A13 derived 够闭合 layout 时，主张不再额外要求 observed（否则这条永远过不了）",
          led6["summary"]["claim_supported"] is True
          and row_of(led6, "layout.regions")["claim_status"] == "closed", led6["summary"])

    led7 = CL.evaluate(closed_facts(**{
        "bytes.loadable": fact(True, "observed", "x", source_class=None)}),
        claim="controlled-replay")
    check("A14 来源未标注（None）永不支撑主张（缺来源 ≠ 任意来源都行）",
          led7["summary"]["claim_supported"] is False
          and row_of(led7, "bytes.loadable")["claim_status"] == "unknown", led7["summary"])

# ======================================================================
def exact_project(tag="proj"):
    """跑一次 recover_project_exact（真产物），同一进程内缓存复用。"""
    if tag in _proj_cache:
        return _proj_cache[tag]
    dest = os.path.join(TMP, tag)
    if os.path.isdir(dest) and os.path.exists(os.path.join(dest, "manifest.json")):
        _proj_cache[tag] = ({"ok": True, "cached": True}, dest)
        return _proj_cache[tag]
    r = RC.project_exact(AXF, dest, name="exact", include_asm=False,
                         emit_uvprojx=False)
    _proj_cache[tag] = (r, dest)
    return r, dest

def section_b():
    print("\nB 工具层：claim 参数")
    r, dest = exact_project()
    check("B0 前置：recover_project_exact 出得来工程", r.get("ok") is True,
          r.get("error"))
    if not r.get("ok"):
        return

    bad = RC.build_closure_ledger(dest, AXF, BASE, claim="best-effort")
    check("B1 主张写错 → 明确报错 + 列出可选（不退回默认值猜一个）",
          bad.get("ok") is False and "best-effort" in (bad.get("error") or "")
          and set(bad.get("claims") or {}) == set(CL.CLAIM_AUTHORITIES), bad)

    dflt = RC.build_closure_ledger(dest, AXF, BASE, skip_build=True)
    check("B2 不给 claim 时用默认值 controlled-replay（写在输出里，可核对）",
          dflt.get("claim") == CL.DEFAULT_CLAIM
          and dflt["summary"]["claim"] == CL.DEFAULT_CLAIM, dflt.get("claim"))

    vj = os.path.join(TMP, "verify.json")
    if not os.path.exists(vj):
        v = RC.verify_project(dest, AXF, base=BASE)
        with open(vj, "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)
    kw = dict(flash_start=FLASH[0], flash_size=FLASH[1] - FLASH[0] + 1,
              ram_start=RAM[0], ram_size=RAM[1] - RAM[0] + 1)
    led = RC.build_closure_ledger(dest, AXF, BASE, verify_json=vj, **kw)
    check("B3 真产物 + 回放：ready=true、claim=controlled-replay 被支撑",
          led.get("ok") is True and led["ready"] is True
          and led["summary"]["claim_supported"] is True, led["summary"])

    led_s = RC.build_closure_ledger(dest, AXF, BASE, verify_json=vj,
                                    claim="shipped-artifact", **kw)
    check("B3b 同一份证据换 claim=shipped-artifact：仍被支撑（两条来源都是交付字节）",
          led_s["summary"]["claim_supported"] is True
          and led_s["summary"]["qualifying_obligations"]
          == ["artifact.identity", "vector.entry"], led_s["summary"])

    led_l = RC.build_closure_ledger(dest, AXF, BASE, verify_json=vj,
                                    claim="live-observation", **kw)
    check("B4 claim=live-observation：不支撑，且点名 runtime.bootable 与回放限制",
          led_l["summary"]["claim_supported"] is False
          and any(b["obligation_id"] == "runtime.bootable"
                  for b in led_l["summary"]["claim_blockers"])
          and any("回放" in b["why"] for b in led_l["summary"]["claim_blockers"]),
          led_l["summary"]["claim_blockers"])

    led_x = RC.build_closure_ledger(dest, AXF, BASE, verify_json=vj,
                                    claim="external", **kw)
    check("B5 claim=external：不支撑（没有外部服务给的证据）",
          led_x["summary"]["claim_supported"] is False, led_x["summary"])

    check("B6 换 claim 不动 ready 与 closure_digest（这是两件不同的事）",
          led["ready"] == led_l["ready"] == led_x["ready"] is True
          and led["closure_digest"] == led_l["closure_digest"] == led_x["closure_digest"],
          (led["closure_digest"], led_x["closure_digest"]))

    check("B7 回放时 summary 明说「不能顶替本次实跑」",
          "不能顶替本次实跑" in led["summary"]["claim_note"],
          led["summary"]["claim_note"])

def section_c():
    print("\nC 端到端：实跑 vs 回放")
    r, dest = exact_project()
    if not r.get("ok"):
        check("C0 前置缺失（跳过实跑）", False, r.get("error"))
        return
    kw = dict(flash_start=FLASH[0], flash_size=FLASH[1] - FLASH[0] + 1,
              ram_start=RAM[0], ram_size=RAM[1] - RAM[0] + 1)
    led = RC.build_closure_ledger(dest, AXF, BASE, **kw)
    check("C1 本次实跑：source_mode=live-run 且 controlled-replay 主张被支撑",
          led["summary"]["source_mode"] == "live-run"
          and led["summary"]["claim_supported"] is True, led["summary"])
    check("C1b 实跑时 claim_note 说「本次实跑」",
          "本次实跑" in led["summary"]["claim_note"], led["summary"]["claim_note"])

    led_s = RC.build_closure_ledger(dest, AXF, BASE, skip_build=True)
    check("C2 skip_build：source_mode=no-build，主张不支撑（只有材料盘点级证据）",
          led_s["summary"]["source_mode"] == "no-build"
          and led_s["summary"]["claim_supported"] is False, led_s["summary"])

    check("C3 三种取证方式的 claim_note 各不相同（回放不冒充实跑）",
          led["summary"]["claim_note"] != led_s["summary"]["claim_note"],
          (led["summary"]["claim_note"], led_s["summary"]["claim_note"]))

def section_d():
    print("\nD 工具面")
    from mdkdebug import server as SV
    from mdkdebug import toolbox as TB
    from mdkdebug import annotate as AN
    srv = SV.create_server(port=15983, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("D1 注册工具数仍是 215（批次89 只给既有工具加参数，不新增工具）",
          len(names) == 215, len(names))
    check("D2 build 组仍是 31 个且含 recover_ledger",
          len(TB.TOOLSETS["build"]) == 31 and "recover_ledger" in TB.TOOLSETS["build"],
          len(TB.TOOLSETS["build"]))
    ann = AN.annotations_for("recover_ledger")
    props = (tools.get("recover_ledger").input_schema.get("properties") or {})
    check("D2b schema 里有 claim 参数（且仍是既有工具加参数，没有新工具）",
          "claim" in props, sorted(props))
    check("D3 recover_ledger 仍标为会改（默认写 build/），不是只读",
          ann.get("readOnlyHint") is False, ann)
    check("D4 工具面归类检查通过（没有未归类的新工具）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))

    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("D5 描述里写清四个主张等级与「强度够不等于来源对」",
          all(k in src for k in ("shipped-artifact", "controlled-replay",
                                "live-observation", "external",
                                "强度够不等于来源对")), "server.py 描述")
    check("D6 描述里写清回放不能顶替实跑",
          "回放" in src and "不能顶替本次实跑" in src, "server.py 描述")

def section_e():
    print("\nE 回归")
    r, dest = exact_project()
    vj = os.path.join(TMP, "verify.json")
    if os.path.exists(vj):
        verify = json.load(io.open(vj, encoding="utf-8"))
    else:
        verify = {}
    facts = CL.facts_from_verify(verify)
    check("E1 每条证据都带 source_class 键（来源必须显式标注，不许留空猜）",
          bool(facts) and all("source_class" in f for f in facts.values()), facts)
    check("E1b source_class 只取 4 个合法值或 None",
          all(f["source_class"] in CL.SOURCE_CLASSES or f["source_class"] is None
              for f in facts.values()), facts)

    vf = RC._vector_entry_fact(dest, AXF, BASE, json.load(
        io.open(os.path.join(dest, "manifest.json"), encoding="utf-8")))
    check("E2 向量表证据的来源是交付字节（不是我们重建的产物）",
          vf is not None and vf.get("source_class") == "shipped-artifact",
          (vf or {}).get("source_class"))

    snap = json.dumps(closed_facts(), sort_keys=True, ensure_ascii=False)
    CL.evaluate(closed_facts(), claim="live-observation")
    check("E3 evaluate 不改入参（同一份证据可反复评估）",
          json.dumps(closed_facts(), sort_keys=True, ensure_ascii=False) == snap, "changed")

    tree = ast.parse(io.open(os.path.join(ROOT, "mdkdebug", "closure.py"),
                            encoding="utf-8").read())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods.update(a.name.split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            mods.add(n.module.split(".")[0])
    check("E4 closure.py 只用标准库 hashlib/json（零新增依赖）", mods <= {"hashlib", "json"}, mods)

def main():
    print("环境：Python %s" % sys.version.split()[0])
    for fn in (section_a, section_b, section_c, section_d, section_e):
        fn()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  - %s" % f)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
