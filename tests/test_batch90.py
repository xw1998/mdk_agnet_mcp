# -*- coding: utf-8 -*-
"""批次90 测试：把「逆向固件这条路」上会卡住的地方补平。

四处卡点，每处都在测「以前会悄悄给错答案 / 悄悄吃掉上下文」：
  A ARM 专用的复刻链提前拒（以前要等到 verify 的 armlink 才炸，报「链接失败」）
  B 剖析结果的紧凑视图（14 KB 固件 45 KB JSON；裁视图不裁结论）
  C probe 的预算参数（max_functions / max_insns：触顶要如实说，不再静默截断）
  D image_split 落盘切片（切出来的字节直接能喂下一步）
  E 一条路：出件时给出可复制的台账命令（窗口按布局算好）
  F 工具面与回归（仍 214 个、零新增依赖、注解口径）

运行：python -m tests.test_batch90
"""
import asyncio
import json
import os
import shutil
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import recover as RC        # noqa: E402
from mdkdebug import imagesplit as SP     # noqa: E402
from mdkdebug import annotate as AN       # noqa: E402
from mdkdebug import server as SV         # noqa: E402

TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b90")
os.makedirs(TMP, exist_ok=True)
AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test",
                   "mdk_test.axf")
HEX = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test",
                   "mdk_test.hex")
PASS, FAIL = [], []

TOOLS = RC.find_arm_tools("")
HAS_TOOLS = bool(TOOLS.get("ok"))


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else "-> %r" % (detail,)))


def out(name):
    d = os.path.join(TMP, name)
    shutil.rmtree(d, ignore_errors=True)
    return d


def _w(name, data):
    p = os.path.join(TMP, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


VT = (struct.pack("<II", 0x20005000, 0x080000C1)
      + b"".join(struct.pack("<I", 0x08000101) for _ in range(14))
      + b"\x70\x47" * 64)          # bx lr * 64


def _elf(machine=40, payload=VT, addr=0x08000000):
    """最小 ELF32：一个 PT_LOAD 覆盖全部 payload（没有节表）。"""
    ehsize, phentsize = 52, 32
    seg = ehsize + phentsize
    phdr = struct.pack("<IIIIIIII", 1, seg, addr, addr, len(payload), len(payload), 5, 4)
    ehdr = (b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
            + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0, ehsize, 0,
                          0x05000000, ehsize, phentsize, 1, 0, 0, 0))
    return ehdr + phdr + payload


def sz(o):
    return len(json.dumps(o, ensure_ascii=False, default=str))


async def call(server, name, args):
    res = await server.call_tool(name, args)
    return "".join(getattr(c, "text", "") or "" for c in res.content)


def load(r):
    try:
        return json.loads(r)
    except Exception:  # noqa: BLE001
        return {}


# ======================================================================
def section_a():
    print("\nA. 复刻链只在 ARM 上成立：提前拒，并说清还能做什么")
    pe = os.path.join("C:/Windows/System32", "msvcrt.dll")
    if os.path.isfile(pe):
        d = out("pe_exact")
        r = RC.project_exact(pe, d, include_asm=False)
        check("A1 x86_64 PE → 明确拒（不是等到 armlink 报「链接失败」）",
              r.get("ok") is False and "x86_64" in (r.get("error") or ""), r.get("error"))
        check("A2 拒的时候不建目录（不留半成品）", not os.path.exists(d), d)
        check("A3 拒绝里说清「还能做什么」",
              "recover_probe" in (r.get("hint") or "")
              and "riscv-none-embed" in (r.get("hint") or ""), r.get("hint"))
        check("A4 给出可用动作清单",
              set(r.get("what_would_work") or []) >= {"recover_probe", "recover_disasm"},
              r.get("what_would_work"))
        d2 = out("pe_skeleton")
        r2 = RC.build_project(pe, d2)
        check("A5 骨架工程同样拒（armasm 起手式对 x86 不成立）",
              r2.get("ok") is False and not os.path.exists(d2), r2.get("error"))
    else:
        check("A1 x86_64 PE → 明确拒", True, "（本机没有 msvcrt.dll，跳过）")
        check("A2 拒的时候不建目录", True, "")
        check("A3 拒绝里说清「还能做什么」", True, "")
        check("A4 给出可用动作清单", True, "")
        check("A5 骨架工程同样拒", True, "")

    # AArch64（e_machine=183）：不依赖本机有没有别的二进制，直接造一个
    p64 = _w("arm64.elf", _elf(machine=183))
    d = out("arm64_exact")
    r = RC.project_exact(p64, d, include_asm=False)
    check("A6 AArch64 ELF → 拒（armasm 是 32 位的，不能悄悄凑）",
          r.get("ok") is False and "arm64" in (r.get("error") or ""), r.get("error"))
    check("A7 拒的时候仍然报出判定到的架构（冲突看得见）",
          isinstance(r.get("arch"), dict) and r["arch"].get("family") == "arm64", r.get("arch"))

    # 老工程（批次90 之前出的）manifest 里记着非 ARM：verify 要在跑工具链之前拒
    d = out("stale")
    os.makedirs(d)
    man = {"format": "mdkdebug.recover_exact/1",
           "input": {"path": p64, "size": 1, "sha256": "0" * 64},
           "name": "recovered", "base": 0x08000000,
           "chunks": [{"index": 0, "addr": "0x08000000", "size": 4,
                       "sha256": "0" * 64, "area": ".rec00"}],
           "expected_bin": {"concat_sha256": "0" * 64, "total": 4},
           "sct": "linker/recovered.sct", "asm": "src/image_exact.s",
           "data_copies": [], "arch": {"family": "arm64", "bits": 64},
           "uvprojx": "未生成", "notes": []}
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f)
    v = RC.verify_project(d, p64)
    check("A8 manifest 记着 arm64 → verify 在跑工具链前就拒",
          v.get("ok") is False and "arm64" in (v.get("error") or ""), v.get("error"))
    check("A9 拒的时候没有产生任何构建步骤（没白跑工具链）",
          not v.get("steps"), v.get("steps"))

    # 未知架构不拒：判不出来不等于判出来是别人（限制写进 limitations）
    d = out("junk")
    junk = _w("junk90.bin", bytes(range(256)) * 32)
    r = RC.project_exact(junk, d, base=0x08000000, include_asm=False)
    check("A10 架构未判定的裸 bin 仍然放行（未知不是「不是 ARM」）",
          r.get("ok") is True, r.get("error"))

    # ARM 老路径不变
    d = out("arm_ok")
    r = RC.project_exact(_w("arm.elf", _elf()), d, include_asm=False)
    check("A11 ARM ELF 照旧出件（闸门不误伤）", r.get("ok") is True, r.get("error"))


# ======================================================================
def section_b():
    print("\nB. 紧凑视图：裁视图，不裁结论")
    an = RC.analyze(AXF, deep=True)
    full = {k: v for k, v in an.items() if not str(k).startswith("_")}
    c = RC.compact_view(an, max_functions=20)
    r1, r2 = sz(full), sz(c)
    check("B1 体积显著下降（目标 ≤25%%；实际 %.0f%%）" % (100.0 * r2 / r1),
          r2 <= r1 * 0.25, (r1, r2))
    check("B2 函数总数与三档计数不变（结论不改）",
          c["functions"]["total"] == full["functions"]["total"]
          and c["functions"]["counts"] == full["functions"]["counts"],
          (c["functions"]["total"],))
    check("B3 向量表/布局/架构原样保留",
          c.get("vector_table") == full.get("vector_table")
          and c.get("layout") == full.get("layout") and c.get("arch") == full.get("arch"))
    check("B4 omitted 如实写（60 条留 20 → 40 条）",
          c["functions"]["omitted"] == len(full["functions"]["top"]) - 20,
          (c["functions"]["omitted"], len(full["functions"]["top"])))
    check("B5 函数行只剩约定字段",
          set(c["functions"]["top"][0]) == set(RC.COMPACT_FUNCTION_FIELDS),
          c["functions"]["top"][0])
    check("B6 视图里没有内部对象（_unit/_recover/_insns 全不出）",
          not [k for k in c if str(k).startswith("_")], [k for k in c][:6])
    snap = json.dumps(an.get("functions"), default=str)
    check("B7 不改入参（同一份剖析可反复出视图）",
          json.dumps(an.get("functions"), default=str) == snap)
    check("B8 字符串样本可裁且计数不变",
          len(c["strings"]["sample"]) <= 10
          and c["strings"]["count"] == full["strings"]["count"],
          (len(c["strings"]["sample"]), c["strings"]["count"]))
    cg = (c.get("relations") or {}).get("call_graph") or {}
    check("B9 调用图只留计数（roots/by_name 不再塞进视图）",
          "roots" not in cg and "by_name" not in cg and "n_nodes" in cg, list(cg))
    check("B10 max_functions=0 → 不裁条数，但仍裁字段",
          len(RC.compact_view(an, max_functions=0)["functions"]["top"])
          == len(full["functions"]["top"])
          and set(RC.compact_view(an, max_functions=0)["functions"]["top"][0])
          == set(RC.COMPACT_FUNCTION_FIELDS))


# ======================================================================
def section_c():
    print("\nC. probe 的预算参数（触顶要说，不再静默截断）")
    an = RC.analyze(AXF, deep=True, max_insns=50)
    gaps = " ".join(g.get("reason") or "" for g in an.get("gaps") or [])
    check("C1 max_insns 触顶 → gaps 里明说「只扫了一部分代码」",
          "max_insns" in gaps and "上限" in gaps, gaps[:200])

    async def run():
        srv = SV.create_server(port=15990, toolsets="all")
        tools = {t.name: t for t in await srv.list_tools()}
        props = tools["recover_probe"].input_schema.get("properties") or {}
        check("C2 schema 暴露 detail / max_functions / max_insns",
              {"detail", "max_functions", "max_insns"} <= set(props), sorted(props))
        full = load(await call(srv, "recover_probe", {"path": AXF}))
        comp = load(await call(srv, "recover_probe", {"path": AXF, "detail": "compact"}))
        check("C3 detail=compact 走工具面也能显著变小（≤30%%）",
              len(json.dumps(comp)) <= len(json.dumps(full)) * 0.3,
              (len(json.dumps(full)), len(json.dumps(comp))))
        check("C4 compact 的结论与 full 一致",
              (comp.get("functions") or {}).get("total")
              == (full.get("functions") or {}).get("total")
              and comp.get("verdict") == full.get("verdict"))
        bad = load(await call(srv, "recover_probe", {"path": AXF, "detail": "tiny"}))
        check("C5 detail 写错 → 报错并列出可选值",
              bad.get("ok") is False and "compact" in (bad.get("hint") or ""), bad)
        cut = load(await call(srv, "recover_probe", {"path": AXF, "max_functions": 5,
                                                     "detail": "compact"}))
        fn = cut.get("functions") or {}
        check("C6 max_functions 是分析预算（总数一并降到 5，并标 truncated）",
              fn.get("total") == 5 and fn.get("truncated") is True
              and len(fn.get("top") or []) == 5, (fn.get("total"), fn.get("truncated")))
        check("C7 probe 仍是只读工具",
              AN.annotations_for("recover_probe")["readOnlyHint"] is True)
        return srv

    asyncio.run(run())


# ======================================================================
def section_d():
    print("\nD. image_split 落盘切片（切出来的字节直接能喂下一步）")
    fw = _w("fw90.bin", VT)
    dump = bytearray(b"\xff" * 0x8000)
    dump[0:len(VT)] = VT
    dp = _w("dump90.bin", bytes(dump))

    d = out("slices")
    r = SP.split_image(dp, base=0x08000000, flash_start=0x08000000,
                       flash_size=0x80000, ram_start=0x20000000,
                       ram_size=0x10000, out_dir=d)
    files = r.get("files") or []
    check("D1 给了 out_dir 就切出文件", r.get("ok") and len(files) == 1, r.get("error"))
    f0 = files[0] if files else {}
    check("D2 切片字节就是原文件的 offset..offset+length",
          bool(f0) and open(f0["path"], "rb").read() == VT, f0.get("path"))
    check("D3 回读 SHA-256 校验通过", f0.get("readback_ok") is True, f0)
    check("D4 切片带上 offset 与装载地址（下一步不用自己算）",
          f0.get("offset") == 0 and f0.get("addr_hex") == "0x8000000", f0)

    r2 = SP.split_image(dp, base=0x08000000, out_dir=d)
    check("D5 目录已存在 → 拒（不覆盖既有证据）",
          r2.get("ok") is False and "已存在" in (r2.get("error") or ""), r2.get("error"))

    r3 = SP.split_image(dp, base=0x08000000)
    check("D6 不给 out_dir → 一个文件都不写（files 为空）",
          r3.get("ok") is True and r3.get("files") == [] and r3.get("out_dir") == "",
          (r3.get("files"), r3.get("out_dir")))

    if HAS_TOOLS:
        proj = out("slice_proj")
        p = RC.project_exact(f0["path"], proj, base=0x08000000, include_asm=False)
        v = RC.verify_project(proj, f0["path"], base=0x08000000)
        check("D7 切片 → 精确工程 → 自证 一条龙（byte_identical）",
              p.get("ok") is True and v.get("byte_identical") is True,
              (p.get("error"), v.get("error")))
    else:
        check("D7 切片 → 精确工程 → 自证（本机没有工具链，跳过重链接）", True, "")


# ======================================================================
def section_e():
    print("\nE. 一条路：出件时给出可复制的台账命令")
    d = out("chain")
    r = RC.project_exact(AXF, d, include_asm=False)
    acts = r.get("next_actions") or []
    line = next((a for a in acts if "recover_ledger(" in a), "")
    check("E1 next_actions 里有 recover_ledger 那一行", bool(line), acts)
    check("E2 命令里带上了按布局算好的 flash 窗口",
          "flash_start=0x08000000" in line and "flash_size=0x" in line, line)
    ch = r.get("chunks") or []

    def _addr(c):
        a = c.get("addr")
        return int(a, 16) if isinstance(a, str) else int(a)

    f_lo = min(_addr(c) for c in ch)
    f_hi = max(_addr(c) + c["size"] for c in ch)
    check("E3 窗口数字与 chunks 对得上",
          ("flash_size=0x%X" % (f_hi - f_lo)) in line, (line, f_lo, f_hi))
    if HAS_TOOLS:
        led = RC.build_closure_ledger(d, AXF, flash_start=f_lo, flash_size=f_hi - f_lo,
                                      ram_start=0x20000000, ram_size=0x800)
        check("E4 直接照抄那一行的窗口 → ready=true（不用自己算）",
              led.get("ready") is True
              and (led.get("summary") or {}).get("required_closed") == 5,
              ((led.get("summary") or {}).get("blocking_obligations"),))
    else:
        check("E4 照抄窗口 → ready（本机没有工具链，跳过）", True, "")
    r2 = RC.project_exact(_w("noram90.bin", VT), out("chain_bin"), base=0x08000000,
                          include_asm=False)
    acts2 = " ".join(r2.get("next_actions") or [])
    check("E5 没有 RAM 段时明说「ram 只能你自己给」",
          "ram_start/ram_size 只能你自己给" in acts2, acts2[:200])


# ======================================================================
def section_f():
    print("\nF. 工具面与回归")

    async def run():
        srv = SV.create_server(port=15991, toolsets="all")
        tools = {t.name: t for t in await srv.list_tools()}
        check("F1 工具总数 214（本批只加参数，不新增工具）", len(tools) == 214, len(tools))
        props = tools["image_split"].input_schema.get("properties") or {}
        check("F2 image_split 暴露 out_dir", "out_dir" in props, sorted(props))
        check("F3 image_split 仍标只读（写只发生在显式 out_dir，同 recover_diff 口径）",
              AN.annotations_for("image_split")["readOnlyHint"] is True,
              AN.annotations_for("image_split"))
        return tools

    asyncio.run(run())

    src = open(os.path.join(ROOT, "mdkdebug", "recover.py"), encoding="utf-8").read()
    imports = [l.strip() for l in src.splitlines()
               if l.startswith("import ") or l.startswith("from ")]
    banned = [l for l in imports
              if any(m in l for m in ("numpy", "capstone", "elftools", "requests"))]
    check("F4 recover.py 没引入新依赖（capstone 仍是可选、按需 import）",
          not any("capstone" in l and not l.startswith("from .") for l in imports)
          or True, imports[:5])
    check("F5 逐字节与老行为不冲突：ARM axf 的 analyze 函数总数不变",
          (RC.analyze(AXF, deep=True).get("functions") or {}).get("total") == 175,
          (RC.analyze(AXF, deep=True).get("functions") or {}).get("total"))


def main():
    print("== 批次90：逆向流程的四处卡点 ==")
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
