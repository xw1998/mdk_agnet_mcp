# -*- coding: utf-8 -*-
"""批次86 测试：库指纹与函数匹配（吸收 Ghidra FID / REA match_native_functions 的口径）。

判据都是「怎么算错答案」倒推出来的，所以每节都在测一条纪律：

  A 指纹口径：什么区间才配叫函数体、字节指纹为什么不归一化、自动名不是名字
  B 匹配口径（纯函数，手写索引）：名字≠代码、重复不展开、候选不是等价、门槛
  C 指纹库文件：不覆盖、版本对齐、写完回读
  D 端到端：真镜像自比对、改一个函数、容器不同、库文件复用
  E 工具面：注册 213、在 build 组且不在默认面、参数与文案
  F 回归：内部字段不外泄、既有输出不变、不新增依赖

运行：python -m tests.test_batch86
"""
import hashlib
import json
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import fid as FD          # noqa: E402
from mdkdebug import recover as RC      # noqa: E402

FXD = os.path.join(ROOT, "tests", "fixtures", "decomp")
FX = os.path.join(FXD, "decomp_fx.axf")
FX_SREC = os.path.join(FXD, "decomp_fx.srec")
EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")
TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b86")
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))


def _tmp(name):
    os.makedirs(TMP, exist_ok=True)
    return os.path.join(TMP, name)


def _patch(src: str, dst: str, addr: int, new: bytes) -> str:
    """把镜像里 addr 处的字节换掉（保持长度）：用来造「改过一个函数」的版本。"""
    data = bytearray(open(src, "rb").read())
    unit = RC._unit_from_data(bytes(data), "x", 0)
    off = None
    for a, b, fo in unit.spans:
        if a <= addr and addr + len(new) <= b:
            off = fo + (addr - a)
            break
    if off is None:
        raise AssertionError("0x%08X 不在任何映射区间里" % addr)
    data[off:off + len(new)] = new
    with open(dst, "wb") as f:
        f.write(bytes(data))
    return dst


def _fn(name, addr, size, body_hex="", insn="", trust="symtab", conf="observed",
        n=10, cfg="c1"):
    """手写一条指纹记录（B 节用：只看匹配规则，不碰镜像）。"""
    return {"name": name, "addr_hex": "0x%08X" % addr, "size": size,
            "size_basis": "symtab" if trust == "symtab" else "",
            "size_trust": trust, "body_basis": "return" if trust != "guessed"
            else "next_entry", "confidence": conf, "is_thunk": False,
            "n_callees": 0, "insn_count": n,
            "bytes_sha256": body_hex, "insn_sha256": insn, "cfg_sha256": cfg,
            "strings_sha256": "", "n_strings": 0}


def _idx(fns, family="arm"):
    return {"format": FD.SIG_FORMAT, "version": FD.FP_VERSION,
            "arch": {"family": family, "bits": 32, "endian": "little", "thumb": True},
            "container": "elf", "functions": fns,
            "fingerprint_rule": list(FD.FINGERPRINT_RULE), "notes": []}


# ==================================================================
def section_a():
    print("\nA 指纹口径")
    b = RC.build_signature(EXAMPLE_AXF)
    check("A1 真镜像出指纹库（175 条）", b.get("ok") and len(b["sig"]["functions"]) == 175,
          len((b.get("sig") or {}).get("functions") or []))
    fns = b["sig"]["functions"]
    n_bytes = sum(1 for f in fns if f["bytes_sha256"])
    n_insn = sum(1 for f in fns if f["insn_sha256"])
    check("A2 指令指纹全覆盖、字节指纹只给有证据的边界",
          n_insn == 175 and 100 <= n_bytes < 175, (n_insn, n_bytes))
    guessed = [f for f in fns if f["size_trust"] == "guessed"]
    check("A3 size_trust=guessed 的一条字节指纹都不给",
          all(not f["bytes_sha256"] for f in guessed), len(guessed))
    b2 = RC.build_signature(EXAMPLE_AXF)
    same = [f1["bytes_sha256"] for f1 in fns] == \
        [f2["bytes_sha256"] for f2 in b2["sig"]["functions"]]
    check("A4 指纹可复现（同一份镜像两次算出同样的值）", same)
    rule = b["sig"].get("fingerprint_rule") or []
    check("A5 fingerprint_rule 跟着输出（口径随结果一起走）",
          len(rule) == 4 and "只在" in rule[0] and "否则留空" in rule[0], rule[:1])

    # 归一化：只有落在可执行区间里的地址才抹成 <CODE>
    ranges = [(0x08000000, 0x08000100)]
    a = FD.normalize_operands("#0x08000020", ranges)
    c = FD.normalize_operands("#0x40000000", ranges)
    # 立即数前缀 `#` 是操作数语法的一部分，归一化只替换地址本身
    check("A6 代码内地址归一成 <CODE>、外设地址保留",
          a == "#<CODE>" and c == "#0x40000000", (a, c))
    check("A7 自动名与真实符号名分得开",
          FD.is_auto_name("sub_08000A1C") and FD.is_auto_name("ptr_08003456")
          and FD.is_auto_name("handler_17")
          and not FD.is_auto_name("Reset_Handler") and not FD.is_auto_name("main"))
    check("A8 size_trust 三档按证据分（symtab / control_flow / guessed）",
          FD.size_trust({"size_basis": "symtab", "body_basis": "return"}) == "symtab"
          and FD.size_trust({"size_basis": "next_entry", "body_basis": "return"})
          == "control_flow"
          and FD.size_trust({"size_basis": "next_entry", "body_basis": "next_entry"})
          == "guessed")
    check("A9 指纹按「函数体字节 + 指令 + 控制流 + 字符串」四路分开记",
          all(k in fns[0] for k in ("bytes_sha256", "insn_sha256", "cfg_sha256",
                                    "strings_sha256")))


# ==================================================================
def section_b():
    print("\nB 匹配口径（纯函数）")
    L = _idx([_fn("alpha", 0x100, 10, "bA", "iA"),
              _fn("beta", 0x200, 20, "bB", "iB"),
              _fn("gamma", 0x300, 30, "bC", "iC")])
    R = _idx([_fn("alpha", 0x110, 10, "bA", "iA"),
              _fn("beta", 0x210, 20, "bZ", "iZ"),      # 名字同、代码不同
              _fn("delta", 0x310, 30, "bC", "iC")])    # 名字不同、字节同
    m = FD.match(L, R)
    by = {(x["basis"], x["left"]["name"]): x for x in m["matches"]}
    check("B1 唯一精确名配对，(name, alpha) 字节也相同",
          by[("name", "alpha")]["bytes_equal"] is True)
    check("B2 名字相同但字节不同 → bytes_equal=false（不谎称没变）",
          by[("name", "beta")]["bytes_equal"] is False)
    check("B3 名字配不上但字节相同 → basis=bytes（delta/gamma）",
          by.get(("bytes", "gamma"), {}).get("right", {}).get("name") == "delta")
    check("B4 计数分开记（by_name=2 / by_bytes=1）",
          m["counts"]["by_name"] == 2 and m["counts"]["by_bytes"] == 1,
          m["counts"])

    # 区间证据不足时，名字配上了也判不了字节
    L2 = _idx([_fn("alpha", 0x100, 10, "", "iA", trust="guessed")])
    R2 = _idx([_fn("alpha", 0x100, 10, "", "iA", trust="guessed")])
    m2 = FD.match(L2, R2)
    check("B5 区间证据不足 → bytes_equal=null（判不了就说判不了）",
          m2["matches"][0]["bytes_equal"] is None)

    # 重名：不展开笛卡尔积
    L3 = _idx([_fn("dup", 0x100, 10, "x1", "i1"), _fn("dup", 0x200, 10, "x2", "i2")])
    R3 = _idx([_fn("dup", 0x100, 10, "x1", "i1")])
    m3 = FD.match(L3, R3)
    check("B6 一侧重名 → unresolved 组，不做 2×1 展开",
          not m3["matches"] and len(m3["unresolved"]) == 1
          and m3["unresolved"][0]["reason"] == "duplicate_name"
          and m3["unresolved"][0]["n_left"] == 2, m3["unresolved"])

    # 字节重复：两侧都多 → unresolved
    L4 = _idx([_fn("f1", 0x100, 10, "same", "i1"), _fn("f2", 0x110, 10, "same", "i2")])
    R4 = _idx([_fn("g1", 0x100, 10, "same", "i3"), _fn("g2", 0x110, 10, "same", "i4")])
    m4 = FD.match(L4, R4)
    check("B7 字节指纹重复 → unresolved(duplicate_bytes)，记两侧条数",
          m4["counts"]["matched"] == 0 and m4["counts"]["by_bytes"] == 0
          and any(u["reason"] == "duplicate_bytes" and u["n_left"] == 2
                  for u in m4["unresolved"]), m4["counts"])

    # guessed 边界即使字节相同也不进 bytes 配对
    L5 = _idx([_fn("f", 0x100, 10, "zz", "i1", trust="guessed", conf="weak")])
    R5 = _idx([_fn("g", 0x100, 10, "zz", "i1", trust="guessed", conf="weak")])
    m5 = FD.match(L5, R5)
    check("B8 guessed 边界不给字节配对（改走候选或 only_*）",
          m5["counts"]["by_bytes"] == 0, m5["counts"])

    # 候选：指令同、字节不同
    L6 = _idx([_fn("f", 0x100, 40, "AA", "INS", conf="weak")])
    R6 = _idx([_fn("g", 0x900, 40, "BB", "INS", conf="weak")])
    m6 = FD.match(L6, R6)
    hit = m6["matches"][0]
    check("B9 指令指纹相同、字节不同 → state=candidate（不作等价断言）",
          hit["state"] == "candidate" and hit["basis"] == "insn_fingerprint"
          and "**不是**字节相同" in hit["note"], hit.get("note"))
    # 太短的不给候选
    L7 = _idx([_fn("f", 0x100, 2, "", "SHORT", conf="weak", n=2)])
    R7 = _idx([_fn("g", 0x100, 2, "", "SHORT", conf="weak", n=2)])
    m7 = FD.match(L7, R7)
    check("B10 少于 min_insns 条的不给候选（两条指令满街都是）",
          m7["counts"]["candidates"] == 0 and m7["counts"]["only_left"] == 1,
          m7["counts"])

    bad = FD.match(_idx([_fn("f", 0x100, 4)]), _idx([_fn("g", 0x100, 4)], family="x86"))
    check("B11 两侧架构不同 → 直接报错（不给跨指令集比对）",
          bad.get("ok") is False and "架构不同" in (bad.get("error") or ""),
          bad.get("error"))

    m8 = FD.match(_idx([_fn("onlyhere", 0x100, 10, "q1", "q1")]), _idx([]))
    check("B12 only_left 只表示「本次清单里没有对应」，限制里写明不证明增删",
          m8["counts"]["only_left"] == 1
          and any("不证明源码有增删" in x for x in m8["limitations"]))
    check("B13 覆盖度恒报 inventory_complete=false（不知道本该有多少个）",
          m8["coverage"]["inventory_complete"] is False
          and m8["coverage"]["left"]["functions"] == 1)


# ==================================================================
def section_c():
    print("\nC 指纹库文件")
    p = _tmp("lib.sig.json")
    if os.path.exists(p):
        os.remove(p)
    s = RC.save_signature(FX, p)
    check("C1 指纹库存盘并回读校验", s.get("ok") and s["signature"]["functions"] == 13,
          s.get("error"))
    on_disk = open(p, "rb").read()
    check("C2 返回的 SHA-256 与磁盘内容一致",
          hashlib.sha256(on_disk).hexdigest() == s["signature"]["sha256"])
    again = RC.save_signature(FX, p)
    check("C3 默认不覆盖既有库（旧库是证据）",
          again.get("ok") is False and "已存在" in (again.get("error") or ""),
          again.get("error"))
    over = RC.save_signature(FX, p, overwrite=True)
    check("C4 overwrite=true 才覆盖", over.get("ok") is True)
    loaded = FD.load_sig(p)
    check("C5 load_sig 读回同一份（format/version/functions 齐）",
          loaded.get("ok") and loaded["format"] == FD.SIG_FORMAT
          and len(loaded["functions"]) == 13)
    bad_p = _tmp("not-sig.json")
    with open(bad_p, "w", encoding="utf-8") as f:
        f.write('{"hello": 1}')
    r = FD.load_sig(bad_p)
    check("C6 不是指纹库 → 明确报错（不猜）",
          r.get("ok") is False and "指纹库" in (r.get("error") or ""), r.get("error"))
    ver_p = _tmp("old-ver.json")
    with open(ver_p, "w", encoding="utf-8") as f:
        json.dump({"format": FD.SIG_FORMAT, "version": FD.FP_VERSION + 1,
                   "functions": []}, f)
    r2 = FD.load_sig(ver_p)
    check("C7 版本不符 → 拒用（不混两代指纹）",
          r2.get("ok") is False and "版本" in (r2.get("error") or ""), r2.get("error"))


# ==================================================================
def section_d():
    print("\nD 端到端")
    self_cmp = RC.compare_images(FX, FX)
    c = self_cmp["counts"]
    check("D1 自比对：13 条全部配上，无 only_*",
          c["matched"] + c["candidates"] == 13 and c["only_left"] == 0
          and c["only_right"] == 0, c)
    check("D2 自比对全走名字，且字节相等",
          c["by_name"] == 13
          and all(m["bytes_equal"] is True for m in self_cmp["matches"]), c)

    patched = _patch(FX, _tmp("fx_patched.axf"), 0x0800008C,
                     bytes.fromhex("9bfb0200"))   # mla → mls（同样是 2 字节一条）
    diff = RC.compare_images(FX, patched)
    hit = next((m for m in diff["matches"] if m["left"]["name"] == "mac"), None)
    check("D3 改一个函数：该函数名字配上但 bytes_equal=false",
          hit is not None and hit["basis"] == "name"
          and hit["bytes_equal"] is False, hit)
    others = [m for m in diff["matches"] if m["left"]["name"] != "mac"]
    check("D4 其余函数仍字节相等，且没有函数「被消失」",
          all(m["bytes_equal"] is True for m in others)
          and diff["counts"]["only_left"] == 0
          and diff["counts"]["only_right"] == 0, diff["counts"])

    sr = RC.compare_images(FX, FX_SREC, arch="arm", thumb=True, entry=0x08000000)
    check("D5 容器不同也能比（S-record 侧坦白只有 1 个可恢复入口）",
          sr.get("ok") and sr["target"]["counts"]["functions"] == 1
          and sr["counts"]["only_left"] == 13, sr.get("counts"))

    lib = _tmp("fx_lib.sig.json")
    if os.path.exists(lib):
        os.remove(lib)
    r1 = RC.compare_images(FX, patched, save_reference_sig=lib)
    r2 = RC.compare_images("", patched, reference_sig=lib)
    check("D6 指纹库复用：与当场分析得到同样的计数",
          r1.get("ok") and r2.get("ok")
          and r1["counts"] == r2["counts"], (r1.get("counts"), r2.get("counts")))
    check("D7 指纹库记录的来源可追溯（input sha256）",
          (r1.get("reference_signature") or {}).get("path") and
          os.path.isfile(lib))

    full = RC.compare_images(FX, patched, full=True)
    cut = RC.compare_images(FX, patched, full=False, max_rows=2)
    check("D8 默认只给前若干条，total 与 truncated 照实报",
          len(cut["matches"]) == 2 and cut["matches_total"] == 13
          and cut["matches_truncated"] is True
          and len(full["matches"]) == 13, (len(cut["matches"]), cut["matches_total"]))


# ==================================================================
def section_e():
    print("\nE 工具面")
    import asyncio
    from mdkdebug import server as SV
    from mdkdebug import annotate as AN
    srv = SV.create_server(port=15886, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    check("E1 注册总数 213（批次86 +1）", len(tools) == 213, len(tools))
    check("E2 recover_diff 已注册", "recover_diff" in tools)
    props = (tools.get("recover_diff").input_schema.get("properties") or {})
    check("E3 参数齐全（reference/target/sig/base/arch/min_insns/full）",
          all(k in props for k in ("reference", "target", "reference_sig", "target_sig",
                                   "save_reference_sig", "reference_base", "target_base",
                                   "arch", "endian", "bits", "thumb", "entry",
                                   "min_insns", "full", "max_rows")), sorted(props))
    desc = tools.get("recover_diff").description or ""
    # lean 档位会改写描述（"工具描述分层"），所以纪律原文从注册源文里核；
    # 返回给模型的描述至少要还在说指纹/字节这两件事。
    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"),
                  encoding="utf-8").read()
    check("E4 描述里把三条关键纪律写明（名字≠代码 / only 不代表增删 / 候选非等价）",
          "不是「代码没变」" in src and "不证明源码有增删" in src
          and "不作等价断言" in src
          and ("指纹" in desc or "字节" in desc), (desc[:60], len(desc)))
    default_srv = SV.create_server(port=15887)
    dnames = {t.name for t in asyncio.run(default_srv.list_tools())}
    check("E5 不在默认面（逆向场景按需装载），默认面仍是 44 个",
          len(dnames) == 44 and "recover_diff" not in dnames, len(dnames))
    check("E6 归属 build 组", "recover_diff" in SV._toolbox.TOOLSETS.get("build", set()))
    a = AN.annotations_for("recover_diff")
    check("E7 标为只读工具（不写文件除非显式 save_reference_sig）",
          a["readOnlyHint"] is True, a)

    r = json.loads(asyncio.run(srv.call_tool(
        "recover_diff", {"reference": FX, "target": FX})).content[0].text)
    check("E8 端到端调用：自比对 13 条全配、覆盖度照实报",
          r.get("ok") and r["counts"]["matched"] == 13
          and r["coverage"]["inventory_complete"] is False, r.get("error"))
    r2 = json.loads(asyncio.run(srv.call_tool(
        "recover_diff", {"reference": FX, "target": _tmp("nope.bin")})).content[0].text)
    check("E9 目标不存在 → 明确报错、不给半份结果",
          r2.get("ok") is False and "不存在" in (r2.get("error") or ""), r2.get("error"))


# ==================================================================
def section_f():
    print("\nF 回归")
    an = RC.analyze(EXAMPLE_AXF)
    rec = an["_recover"]
    check("F1 既有函数盘点不变（175 函数、observed 172）",
          rec["total"] == 175 and rec["counts"]["observed"] == 172, rec["counts"])
    syms = RC.recover_symbols if hasattr(RC, "recover_symbols") else None
    check("F2 内部字段 _insns 只在 _recover 里（给指纹用），不在顶层",
          isinstance(rec.get("_insns"), dict) and len(rec["_insns"]) > 1000
          and "_insns" not in an, len(rec.get("_insns") or {}))
    import asyncio
    from mdkdebug import server as SV
    srv = SV.create_server(port=15888, toolsets="all")
    txt = asyncio.run(srv.call_tool(
        "recover_symbols", {"path": EXAMPLE_AXF})).content[0].text
    check("F3 recover_symbols 的输出里没有 _insns（内部数据不外泄）",
          "_insns" not in txt and len(txt) < 2_000_000, len(txt))
    src = open(os.path.join(ROOT, "mdkdebug", "fid.py"), encoding="utf-8").read()
    third = [m for m in ("capstone", "elftools", "pefile", "macholib")
             if ("import %s" % m) in src]
    check("F4 不新增依赖（fid.py 不 import capstone/elftools/pefile/macholib）",
          not third, third)


# ==================================================================
def main():
    try:
        section_a()
        section_b()
        section_c()
        section_d()
        section_e()
        section_f()
    finally:
        print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
        if FAIL:
            print("失败：")
            for f in FAIL:
                print("  - %s" % f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
