# -*- coding: utf-8 -*-
"""批次88 测试：固件恢复的闭环台账（REA obligation-ledger 的 fail-closed 口径）。

每节都在测一条「怎么把推导卖成事实」：
  A 纯函数判据：derived 不能闭合 observed 义务、unknown/unsupported 不算通过、
    缺证据是 open 不是 failed、digest 可复算、optional 不阻塞 ready
  B verify → 证据的映射：没有期望字节时不是「一致」，manifest_match=false 是反证
  C 向量表证据：读原镜像的前两个字 + 工程首区必须从同一个地址起
  D 端到端：真工具链闭合 5 条 required；证据复评得同一个 digest；skip_build 只开一个口
  E 工具面：注册数、分组、非只读、描述纪律
  F 回归：recover_verify 输出不变、零新增依赖、evaluate 不改入参

运行：python -m tests.test_batch88
"""
import asyncio
import copy
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
SREC = os.path.join(ROOT, "tests", "fixtures", "decomp", "decomp_fx.srec")
TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b88")
BASE = 0x08000000
FLASH = (0x08000000, 0x080FFFFF)
RAM = (0x20000000, 0x2001FFFF)
PASS, FAIL = [], []

os.makedirs(TMP, exist_ok=True)

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                           "" if ok else "-> %r" % (detail,)))

def fact(value=True, authority="observed", source="t", note=""):
    return {"value": value, "authority": authority, "source": source, "note": note}

def all_closed(**over):
    """一份「required 全被 observed 证据闭合」的证据集合（可按义务 id 覆盖）。"""
    f = {ob["id"]: fact() for ob in CL.OBLIGATIONS}
    f.update(over)
    return f

def status_of(led, oid):
    for o in led["obligations"]:
        if o["obligation_id"] == oid:
            return o["status"]
    return None

def row_of(led, oid):
    for o in led["obligations"]:
        if o["obligation_id"] == oid:
            return o
    return {}

# ==================================================================
def section_a():
    print("\nA 纯函数判据")
    led = CL.evaluate(all_closed())
    check("A1 required 全闭 → ready=true，blocking 为空",
          led["summary"]["ready"] is True
          and led["summary"]["required_closed"] == led["summary"]["required_total"]
          and led["summary"]["blocking_obligations"] == [], led["summary"])
    check("A1b 台账带 8 条义务与 9 条口径（口径随结果走；批次89 加了 3 条来源/主张纪律）",
          len(led["obligations"]) == 8 and len(led["rules"]) == 9, len(led["rules"]))

    led = CL.evaluate(all_closed(**{"bytes.loadable": fact(True, "derived")}))
    check("A2 derived 证据不能闭合要求 observed 的义务（open，不是通过）",
          status_of(led, "bytes.loadable") == "open"
          and "低于" in row_of(led, "bytes.loadable")["reason"], row_of(led, "bytes.loadable"))

    led = CL.evaluate(all_closed(**{"layout.regions": fact(True, "derived")}))
    check("A3 requires=derived 的义务可以被推导闭合（不是一刀切要 observed）",
          status_of(led, "layout.regions") == "closed", row_of(led, "layout.regions"))

    led = CL.evaluate(all_closed(**{"bytes.loadable": fact(False, "observed")}))
    check("A4 observed 级反证 → failed，且 ready=false",
          status_of(led, "bytes.loadable") == "failed"
          and led["summary"]["ready"] is False
          and "bytes.loadable" in led["summary"]["blocking_obligations"],
          row_of(led, "bytes.loadable"))

    led = CL.evaluate(all_closed(**{"bytes.loadable": fact(False, "derived")}))
    check("A5 只有推导级反证 → open（不足以判失败），并说清为什么",
          status_of(led, "bytes.loadable") == "open"
          and "推导级" in row_of(led, "bytes.loadable")["reason"],
          row_of(led, "bytes.loadable"))

    facts = all_closed()
    del facts["vector.entry"]
    led = CL.evaluate(facts)
    check("A6 缺证据 → open + required_next_evidence（不是 failed，也不是通过）",
          status_of(led, "vector.entry") == "open"
          and bool(row_of(led, "vector.entry").get("required_next_evidence")),
          row_of(led, "vector.entry"))

    led = CL.evaluate(all_closed(**{"c.semantics": fact(False, "unsupported")}))
    check("A7 unsupported 不算通过：状态是 unsupported，且不进 closed 计数",
          status_of(led, "c.semantics") == "unsupported"
          and led["summary"]["unsupported"] == 1
          and led["summary"]["closed"] == 7, led["summary"])

    led = CL.evaluate(all_closed(**{"runtime.bootable": fact(False, "unknown")}))
    check("A8 unknown 不阻塞 ready（不是 fail），但也不计入 closed",
          led["summary"]["ready"] is True and led["summary"]["unknown"] == 1
          and led["summary"]["closed"] == 7, led["summary"])

    a = CL.evaluate(all_closed())
    b = CL.evaluate(all_closed())
    c = CL.evaluate(all_closed(**{"bytes.loadable": fact(False, "observed")}))
    check("A9 closure_digest 可复算：同证据同值，状态变了就变",
          a["closure_digest"] == b["closure_digest"]
          and a["ledger_id"] == b["ledger_id"]
          and a["closure_digest"] != c["closure_digest"]
          and CL.canonical_digest(a) == CL.canonical_digest(b), a["closure_digest"])

    led = CL.evaluate(all_closed(**{"symbols.addresses": fact(False, "unknown")}))
    check("A10 optional 义务未闭合不阻塞 ready（也不被数量冲淡）",
          led["summary"]["ready"] is True
          and "symbols.addresses" not in led["summary"]["blocking_obligations"],
          led["summary"])

    led = CL.evaluate(all_closed(**{"symbols.addresses": fact(False, "observed")}))
    check("A11 任何 failed（含 optional）都让 ready=false",
          led["summary"]["ready"] is False and led["summary"]["failed"] == 1,
          led["summary"])

    led = CL.evaluate(all_closed(), include_optional_in_summary=False)
    check("A12 include_optional_in_summary=false 时计数只算 required（ready 不受影响）",
          led["summary"]["ready"] is True and led["summary"]["unknown"] == 0
          and led["summary"]["closed"] == 5, led["summary"])

# ==================================================================
def section_b():
    print("\nB verify → 证据的映射")
    facts = CL.facts_from_verify({})
    check("B1 空 verify：只给三条与输入无关的结论，其余全 open",
          set(facts) == {"c.semantics", "runtime.bootable", "symbols.addresses"}
          and facts["c.semantics"]["authority"] == "unsupported"
          and facts["runtime.bootable"]["authority"] == "unknown", sorted(facts))

    v = {"ok": True, "steps": [{"step": "armasm", "ok": True},
                               {"step": "armlink", "ok": True},
                               {"step": "fromelf --bin", "ok": True}],
         "build": {"bin": "x.bin"},
         "diff": {"byte_identical": True},
         "expected": {"sha256": "ab" * 32, "manifest_match": True},
         "expected_source": "fromelf --bin a.axf"}
    led = CL.evaluate(CL.facts_from_verify(v))
    check("B2 真跑+产物存在 → build.toolchain 与 bytes.loadable 都 observed 闭合",
          status_of(led, "build.toolchain") == "closed"
          and status_of(led, "bytes.loadable") == "closed"
          and status_of(led, "layout.regions") == "closed", led["summary"])

    v2 = dict(v, diff={"byte_identical": False, "diff_offsets": [0x11]})
    led = CL.evaluate(CL.facts_from_verify(v2))
    check("B3 字节不同 → bytes.loadable failed（observed 反证）+ ready=false",
          status_of(led, "bytes.loadable") == "failed"
          and led["summary"]["ready"] is False,
          row_of(led, "bytes.loadable"))

    v3 = dict(v, diff={"byte_identical": None})
    led = CL.evaluate(CL.facts_from_verify(v3))
    check("B4 没有期望字节（byte_identical=null）→ open，绝不当成一致",
          status_of(led, "bytes.loadable") == "open", row_of(led, "bytes.loadable"))

    v4 = {"ok": False, "failed_step": "armasm", "steps": [{"step": "armasm", "ok": False}]}
    led = CL.evaluate(CL.facts_from_verify(v4))
    check("B5 工具链报错 → build.toolchain failed（不是 open）",
          status_of(led, "build.toolchain") == "failed", row_of(led, "build.toolchain"))

    v5 = dict(v, expected={"sha256": "ab" * 32, "manifest_match": False})
    led = CL.evaluate(CL.facts_from_verify(v5))
    check("B6 传入的 image 与 manifest 不是同一份 → artifact.identity failed",
          status_of(led, "artifact.identity") == "failed",
          row_of(led, "artifact.identity"))

    v6 = dict(v, diff={"byte_identical": True, "alignment_padding": 2})
    f6 = CL.facts_from_verify(v6)
    check("B7 对齐填充要写进 note（差异说清楚，不是抹平）",
          "填充" in f6["bytes.loadable"]["note"], f6["bytes.loadable"]["note"])

    man = {"vector_table": {"sp": 1}, "symbols": ["a", "b", "c"]}
    f7 = CL.facts_from_verify(v, manifest=man)
    check("B8 manifest 里没有的键不凭想象取：symbols/vector 不从 manifest 认领",
          f7["symbols.addresses"]["authority"] == "unknown"
          and "vector.entry" not in f7, sorted(f7))

    led = CL.evaluate(f7)
    check("B9 同一份证据里 c.semantics 恒 unsupported、runtime.bootable 恒 unknown",
          status_of(led, "c.semantics") == "unsupported"
          and status_of(led, "runtime.bootable") == "unknown", led["summary"])

# ==================================================================
def section_c():
    print("\nC 向量表证据（读原镜像的字节）")
    man = {"format": "mdkdebug.recover_exact/1", "name": "exact",
           "chunks": [{"addr": "0x08000000", "size": 16},
                      {"addr": "0x08001000", "size": 16}],
           "base": 0x08000000}
    f = RC._vector_entry_fact(TMP, AXF, BASE, man, ram=RAM, flash=FLASH)
    check("C1 真 axf：SP/reset 取自镜像字节，判据 plausible，与工程首区一致 → 观察到",
          f is not None and f["value"] is True
          and f["vector_table"]["verdict"] == "plausible"
          and f["vector_table"]["addr"] == "0x08000000", f)

    f2 = RC._vector_entry_fact(TMP, AXF, BASE, man)
    check("C2 不给 RAM/Flash 窗口 → 判据只到 unverified，并把「未核」写进 note",
          f2 is not None and f2["value"] is True
          and f2["vector_table"]["verdict"] == "unverified"
          and "未核" in f2["note"], f2 and f2["note"])

    fake = os.path.join(TMP, "sp0.bin")
    with open(fake, "wb") as fh:
        fh.write(b"\x00" * 8 + b"\x00\xbf" * 8)
    f3 = RC._vector_entry_fact(TMP, fake, BASE, man, ram=RAM, flash=FLASH)
    check("C3 SP=0 的字节不是向量表 → 反证（value=false，判据 invalid）",
          f3 is not None and f3["value"] is False
          and f3["vector_table"]["verdict"] == "invalid", f3)

    man2 = dict(man, chunks=[{"addr": "0x08010000", "size": 16}])
    f4 = RC._vector_entry_fact(TMP, AXF, BASE, man2, ram=RAM, flash=FLASH)
    check("C4 工程首区不在镜像首地址 → 向量表不在工程上（反证）",
          f4 is not None and f4["value"] is False and "不一致" in f4["note"], f4)

    f5 = RC._vector_entry_fact(os.path.join(TMP, "no_such_proj"), "", 0, man,
                               ram=RAM, flash=FLASH)
    check("C5 没有原镜像也没有 original.bin → 没有证据（None → open），不猜",
          f5 is None, f5)

    led = CL.evaluate(CL.facts_from_verify({}, ) | {"vector.entry": f3})
    check("C6 向量表反证进台账就是 failed（observed）",
          status_of(led, "vector.entry") == "failed", row_of(led, "vector.entry"))

# ==================================================================
_proj_cache = {}

def exact_project(tag="proj"):
    """跑一次 recover_project_exact（真产物），同一进程内缓存复用。"""
    if tag in _proj_cache:
        return _proj_cache[tag]
    dest = os.path.join(TMP, tag)
    if os.path.isdir(dest):
        dest = dest + "_%d" % len(os.listdir(TMP))
    r = RC.project_exact(AXF, dest, name="exact", include_asm=False,
                         emit_uvprojx=False)
    _proj_cache[tag] = (r, dest)
    return r, dest

def section_d():
    print("\nD 端到端（真 armasm + armlink + fromelf）")
    r, dest = exact_project()
    check("D0 前置：recover_project_exact 出得来工程", r.get("ok") is True,
          r.get("error"))
    if not r.get("ok"):
        return
    led = RC.build_closure_ledger(dest, AXF, BASE, flash_start=FLASH[0],
                                  flash_size=FLASH[1] - FLASH[0] + 1,
                                  ram_start=RAM[0], ram_size=RAM[1] - RAM[0] + 1)
    check("D1 端到端：ready=true，5 条 required 全闭，verify 逐字节相同",
          led.get("ok") is True and led.get("ready") is True
          and led["summary"]["required_closed"] == 5
          and led["verify"]["byte_identical"] is True, led.get("summary"))
    check("D1b 每条 closed 都带证据来源（source 非空）",
          all(o["evidence"] and o["evidence"].get("source")
              for o in led["obligations"] if o["status"] == "closed"), led["obligations"])
    check("D1c c.semantics 是 unsupported、runtime.bootable 是 unknown（两条都不算通过）",
          status_of(led, "c.semantics") == "unsupported"
          and status_of(led, "runtime.bootable") == "unknown", led["summary"])
    check("D1d verdict 不含「成功」这类空话，只说闭合范围",
          "不说明" in led["verdict"] or "闭合" in led["verdict"], led["verdict"])

    import hashlib
    mp = os.path.join(dest, "manifest.json")
    digest = hashlib.sha256(open(mp, "rb").read()).hexdigest()
    check("D2 manifest.digest 是 manifest.json 的真实 SHA-256（结论可锚定）",
          led["manifest"]["digest"] == digest
          and led["manifest"]["base"] == "0x08000000", led["manifest"])

    vp = os.path.join(TMP, "verify.json")
    verify = RC.verify_project(dest, AXF, base=BASE)
    with open(vp, "w", encoding="utf-8") as f:
        json.dump(verify, f, ensure_ascii=False)
    led2 = RC.build_closure_ledger(dest, AXF, BASE, verify_json=vp,
                                   flash_start=FLASH[0],
                                   flash_size=FLASH[1] - FLASH[0] + 1,
                                   ram_start=RAM[0], ram_size=RAM[1] - RAM[0] + 1)
    check("D3 证据复评（verify_json）得同一个 closure_digest（可复算）",
          led2.get("ok") is True and led2["closure_digest"] == led["closure_digest"]
          and led2["ready"] is True, (led2.get("closure_digest"),
                                      led["closure_digest"]))
    check("D3b 复评时明说「没有重新取证」",
          "未重跑" in led2["evidence_source"], led2["evidence_source"])

    led3 = RC.build_closure_ledger(dest, AXF, BASE, skip_build=True)
    check("D4 skip_build：ready=false 且 blocking 里有 bytes.loadable（不假装量过）",
          led3.get("ok") is True and led3["ready"] is False
          and "bytes.loadable" in led3["summary"]["blocking_obligations"]
          and status_of(led3, "build.toolchain") == "open", led3["summary"])

    led4 = RC.build_closure_ledger(dest, SREC, BASE)
    check("D5 换成另一份镜像 → bytes.loadable failed、artifact.identity failed",
          status_of(led4, "bytes.loadable") == "failed"
          and status_of(led4, "artifact.identity") == "failed"
          and led4["ready"] is False, led4["summary"])

    bad = os.path.join(TMP, "empty_dir")
    os.makedirs(bad, exist_ok=True)
    led5 = RC.build_closure_ledger(bad)
    check("D6 目录里没有 manifest.json → 明确报错并给 hint（不给半份台账）",
          led5.get("ok") is False and "manifest.json" in led5.get("error", "")
          and bool(led5.get("hint")), led5)

    led6 = RC.build_closure_ledger(dest, AXF, verify_json=os.path.join(TMP, "nope.json"))
    check("D7 verify_json 不存在 → 明确报错", led6.get("ok") is False, led6)

# ==================================================================
def section_e():
    print("\nE 工具面")
    from mdkdebug import annotate as AN
    from mdkdebug import server as SV
    srv = SV.create_server(port=15981, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    check("E1 注册总数 214（批次88 +1）", len(tools) == 214, len(tools))
    props = (tools.get("recover_ledger").input_schema.get("properties") or {})
    check("E2 参数齐全（project_dir/image/base/verify_json/arm_bin/skip_build/窗口）",
          all(k in props for k in ("project_dir", "image", "base", "verify_json",
                                   "arm_bin", "skip_build", "via_uvprojx",
                                   "flash_start", "flash_size", "ram_start",
                                   "ram_size")), sorted(props))
    check("E3 在 build 组（30 个）、不在默认面",
          "recover_ledger" in SV._toolbox.TOOLSETS.get("build", set())
          and len(SV._toolbox.TOOLSETS.get("build", ())) == 30
          and "recover_ledger" not in {t.name for t in
                                       asyncio.run(SV.create_server(port=15980).list_tools())},
          len(SV._toolbox.TOOLSETS.get("build", ())))
    check("E4 不标只读（默认会写 build/ 并调 armasm/armlink）",
          AN.annotations_for("recover_ledger")["readOnlyHint"] is False,
          AN.annotations_for("recover_ledger"))

    # 描述在 lean 档位会被改写（体积瘦身），所以核的是 server.py 里的原文
    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("E5 描述写清三句纪律：unknown 不算通过 / ready 不表示能跑 / 默认写 build/",
          "永不算通过" in src and "不表示它能跑" in src
          and "不是只读工具" in src, "")

    payload = json.loads(asyncio.run(srv.call_tool("recover_ledger", {
        "project_dir": exact_project()[1], "image": AXF, "base": BASE,
        "skip_build": True})).content[0].text)
    check("E6 工具真返回对象（不是协程 repr），skip_build 下 ready=false 且带 summary",
          isinstance(payload, dict) and payload.get("ok") is True
          and payload.get("ready") is False
          and payload["summary"]["required_total"] == 5, payload.get("summary"))

# ==================================================================
def section_f():
    print("\nF 回归")
    r, dest = exact_project()
    v = RC.verify_project(dest, AXF, base=BASE)
    check("F1 recover_verify 的输出结构不变（ok/byte_identical/diff/build/steps/verdict）",
          v.get("ok") is True and v.get("byte_identical") is True
          and {"length_expected", "length_actual"} <= set(v.get("diff") or {})
          and "via" in (v.get("build") or {}) and v.get("steps")
          and "verdict" in v, sorted(v))

    src = io.open(os.path.join(ROOT, "mdkdebug", "closure.py"), encoding="utf-8").read()
    banned = [m for m in ("capstone", "elftools", "pefile", "numpy", "requests")
              if ("import %s" % m) in src or ("from %s" % m) in src]
    check("F2 零新增依赖（closure.py 只用 hashlib/json）", not banned, banned)

    facts = all_closed()
    snap = copy.deepcopy(facts)
    CL.evaluate(facts)
    check("F3 evaluate 不改入参（同一份证据可以反复评估）", facts == snap)

    led = RC.build_closure_ledger(dest, AXF, BASE, skip_build=True)
    check("F4 顶层 ready == summary.ready（一键一义）",
          led.get("ready") == led["summary"]["ready"], (led.get("ready"),
                                                        led["summary"]["ready"]))

    check("F5 closure_digest 是 64 位小写 hex", len(led["closure_digest"]) == 64
          and led["closure_digest"] == led["closure_digest"].lower(),
          led["closure_digest"])
    check("F6 ledger_id 由 digest 派生（可对账）",
          led["ledger_id"] == "closure-" + led["closure_digest"][:16], led["ledger_id"])

def main():
    print("环境：Python %s" % sys.version.split()[0])
    for fn in (section_a, section_b, section_c, section_d,
               section_e, section_f):
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
