# -*- coding: utf-8 -*-
"""批次91 测试：台账的窗口不用再人工抄（按布局推），但推出来的只能当「下界」。

批次90 把「一条路」的下一句写成可复制的一行，但那行里带着 flash/ram 窗口——
调用方要么照抄（抄错就是错答案），要么自己算。本批把这一半也省掉：

  A _derive_windows：flash 从 chunks 推、ram 从 manifest.windows.ram 或原镜像 ELF 推
  B 出件时把窗口写进 manifest（老产物没这一项也能现读 ELF）
  C 台账不传窗口：结论不变、并说明用的是哪一套窗口
  D **下界语义**（关键防假绿）：推出来的窗口只把判据从 unverified 抬到 plausible，
    落在外面记未核、不判 invalid；硬错误（SP=0、Thumb 位为 0）不被豁免
  E 出件时给出「省掉窗口」的那一行
  F 工具面与回归（仍 220 个、零新增依赖）

运行：python -m tests.test_batch91
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
from mdkdebug import server as SV         # noqa: E402

TMP = os.path.join(os.environ.get("TEMP", "C:/tmp"), "mdk_b91")
os.makedirs(TMP, exist_ok=True)
AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM", "mdk_test",
                   "mdk_test.axf")
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

def _bin(name, sp, reset, size=0x200):
    p = os.path.join(TMP, name)
    with open(p, "wb") as f:
        f.write(struct.pack("<II", sp, reset) + b"\x00\xbf" * ((size - 8) // 2))
    return p

def _vec(led):
    for o in led.get("obligations") or []:
        if o.get("obligation_id") == "vector.entry":
            return o
    return {}

# ======================================================================
def section_a():
    print("\nA. 推窗口（_derive_windows）")
    man = {"chunks": [{"addr": "0x08000000", "size": 16},
                      {"addr": "0x08001000", "size": 16}]}
    d = RC._derive_windows(man)
    f = d["flash"] or {}
    check("A1 flash 从 chunks 推成 [首, 末) 的覆盖范围",
          f.get("start") == 0x08000000 and f.get("size") == 0x1010, f)
    check("A2 推出来的 flash 标成「下界」而不是器件容量",
          "下界" in (f.get("basis") or ""), f)

    man2 = dict(man, windows={"ram": {"start": 0x20000000, "size": 0x800,
                                      "basis": "原镜像 ELF 的 RW 段"}})
    d2 = RC._derive_windows(man2)
    check("A3 manifest 记了 windows.ram 就直接用（basis 说明来源）",
          (d2["ram"] or {}).get("start") == 0x20000000
          and "manifest.windows.ram" in (d2["ram"] or {}).get("basis", ""), d2["ram"])

    d3 = RC._derive_windows({"chunks": man["chunks"]}, AXF)
    check("A4 老产物没有 windows 时现读原镜像 ELF 的 RW 段",
          (d3["ram"] or {}).get("start") == 0x20000000
          and "现读" in (d3["ram"] or {}).get("basis", ""), d3["ram"])

    d4 = RC._derive_windows({"chunks": man["chunks"]}, _bin("plain.bin", 0x20000728, 0x080000C1))
    check("A5 纯 bin 推不出 RAM：ram=None 且明说推不出来",
          d4["ram"] is None and any("推不出 RAM" in n for n in d4["notes"]), d4)

    d5 = RC._derive_windows({})
    check("A6 空 manifest 什么都不猜（flash/ram 都是 None）",
          d5["flash"] is None and d5["ram"] is None, d5)

# ======================================================================
def section_b():
    print("\nB. 出件时把窗口写进 manifest")
    d = out("elf_proj")
    RC.project_exact(AXF, d, include_asm=False)
    man = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    w = man.get("windows") or {}
    ch = man["chunks"]
    lo = min(int(c["addr"], 16) for c in ch)
    hi = max(int(c["addr"], 16) + c["size"] for c in ch)
    check("B1 manifest.windows.flash 与 chunks 覆盖范围一致",
          (w.get("flash") or {}).get("start") == lo
          and (w.get("flash") or {}).get("size") == hi - lo, w.get("flash"))
    check("B2 ELF 输入时 manifest.windows.ram 记下了 RW 段",
          (w.get("ram") or {}).get("start") == 0x20000000, w.get("ram"))
    db = out("bin_proj")
    pb = _bin("b91_bin.bin", 0x20000728, 0x080000C1)
    RC.project_exact(pb, db, base=0x08000000, include_asm=False)
    man2 = json.load(open(os.path.join(db, "manifest.json"), encoding="utf-8"))
    check("B3 纯 bin 输入时 windows.ram 记为 null（不编一个出来）",
          man2.get("windows", {}).get("ram") is None, man2.get("windows"))

# ======================================================================
def section_c():
    print("\nC. 台账不传窗口（结论不变，说清用的是哪一套）")
    d = out("led")
    RC.project_exact(AXF, d, include_asm=False)
    led = RC.build_closure_ledger(d, AXF, skip_build=True)
    w = led.get("windows") or {}
    check("C1 两套窗口都推出来了，且点名是推出来的",
          sorted(w.get("derived") or []) == ["flash", "ram"], w)
    check("C2 flash/ram 的 basis 分别指向 chunks 与 manifest.windows.ram",
          "chunks" in (w.get("flash") or {}).get("basis", "")
          and "windows.ram" in (w.get("ram") or {}).get("basis", ""), w)
    v = _vec(led)
    check("C3 向量表义务仍闭合，理由里点明窗口是按布局推的",
          v.get("status") == "closed" and "推出来" in (v.get("reason") or ""),
          (v.get("status"), (v.get("reason") or "")[:160]))
    check("C4 limitations 里写明「下界」这条限制",
          any("下界" in x for x in led.get("limitations") or []), led.get("limitations"))
    led2 = RC.build_closure_ledger(d, AXF, skip_build=True,
                                   flash_start=0x08000000, flash_size=0x80000,
                                   ram_start=0x20000000, ram_size=0x10000)
    w2 = led2.get("windows") or {}
    check("C5 显式给窗口时不再标记为推出来的（derived 空、basis=调用方显式给）",
          w2.get("derived") == [] and (w2.get("flash") or {}).get("basis") == "调用方显式给",
          w2)
    same = [(o["obligation_id"], o["status"]) for o in led["obligations"]] == \
           [(o["obligation_id"], o["status"]) for o in led2["obligations"]]
    check("C6 推窗口与显式窗口的每条义务状态一致（推不等于放水）", same,
          [(o["obligation_id"], o["status"]) for o in led["obligations"]])

# ======================================================================
def section_d():
    print("\nD. 下界语义：推出来的窗口不判 invalid")
    # 0x200 字节的 dump，reset 在范围内 / 在范围外两种
    p_in = _bin("d_in.bin", 0x20000728, 0x08000101)
    d_in = out("d_in_proj")
    RC.project_exact(p_in, d_in, base=0x08000000, include_asm=False)
    v1 = _vec(RC.build_closure_ledger(d_in, p_in, skip_build=True))
    check("D1 reset 落在推出来的 flash 内：判据只因缺 RAM 停在未核，不是「落空」",
          "不判 invalid" not in (v1.get("reason") or "")
          and "按布局推出来的" in (v1.get("reason") or ""), (v1.get("reason") or "")[:200])

    p_out = _bin("d_out.bin", 0x20000728, 0x08020001)
    d_out = out("d_out_proj")
    RC.project_exact(p_out, d_out, base=0x08000000, include_asm=False)
    v2 = _vec(RC.build_closure_ledger(d_out, p_out, skip_build=True))
    check("D2 reset 落在推出来的 flash 外：记未核、明说「不判 invalid」",
          "不判 invalid" in (v2.get("reason") or "")
          and v2.get("status") == "closed", (v2.get("reason") or "")[:200])
    v3 = _vec(RC.build_closure_ledger(d_out, p_out, skip_build=True,
                                      flash_start=0x08000000, flash_size=0x100))
    check("D3 同样字节、显式给窄窗口 → 判 invalid（显式窗口仍能判错，反证没放水）",
          v3.get("status") == "failed", (v3.get("status"), (v3.get("reason") or "")[:160]))

    p_sp = _bin("d_sp0.bin", 0, 0x08000101)
    d_sp = out("d_sp_proj")
    RC.project_exact(p_sp, d_sp, base=0x08000000, include_asm=False)
    v4 = _vec(RC.build_closure_ledger(d_sp, p_sp, skip_build=True))
    check("D4 SP=0 这种硬错误不被「窗口是推出来的」豁免（仍 failed）",
          v4.get("status") == "failed" and "invalid" in (v4.get("reason") or ""),
          (v4.get("status"), (v4.get("reason") or "")[:160]))

    check("D5 裸 bin 不再要求另传 base：base 取 manifest 首块地址，核对得上",
          "0x08000000 处" in (v1.get("reason") or "")
          and "与之一致" in (v1.get("reason") or ""), (v1.get("reason") or "")[:200])

# ======================================================================
def section_e():
    print("\nE. 一条路：出件时给出「省掉窗口」的那一行")
    d = out("act")
    r = RC.project_exact(AXF, d, include_asm=False)
    acts = r.get("next_actions") or []
    line = next((a for a in acts if "或者省掉窗口" in a), "")
    check("E1 next_actions 里有「省掉窗口」那一行", bool(line), acts)
    check("E2 那一行不带 flash_start/ram_start（窗口交给台账自己推）",
          "flash_start" not in line and "ram_start" not in line, line)
    if HAS_TOOLS:
        led = RC.build_closure_ledger(d, AXF)
        check("E3 照抄「省掉窗口」那行 → ready=true / 5 条必闭义务",
              led.get("ready") is True
              and (led.get("summary") or {}).get("required_closed") == 5,
              ((led.get("summary") or {}).get("blocking_obligations"),))
    else:
        check("E3 照抄「省掉窗口」那行（本机没有工具链，跳过重链接）", True, "")
    pb = _bin("e_bin.bin", 0x20000728, 0x080000C1)
    r2 = RC.project_exact(pb, out("act_bin"), base=0x08000000, include_asm=False)
    check("E4 纯 bin 出件时仍明说 RAM 窗口只能自己给（推不出来就承认）",
          any("ram_start/ram_size 只能你自己给" in a for a in r2.get("next_actions") or []),
          (r2.get("next_actions") or [])[:3])

# ======================================================================
def section_f():
    print("\nF. 工具面与回归")

    async def run():
        srv = SV.create_server(port=15992, toolsets="all")
        tools = {t.name: t for t in await srv.list_tools()}
        check("F1 工具总数 220（本批只加行为，不新增工具）", len(tools) == 220, len(tools))
        props = tools["recover_ledger"].input_schema.get("properties") or {}
        check("F2 recover_ledger 的参数面没变（窗口仍是可选参数）",
              {"flash_start", "flash_size", "ram_start", "ram_size"} <= set(props),
              sorted(props))

    asyncio.run(run())

    src = open(os.path.join(ROOT, "mdkdebug", "recover.py"), encoding="utf-8").read()
    imports = [l.strip() for l in src.splitlines()
               if l.startswith("import ") or l.startswith("from ")]
    top = [l for l in imports if l.startswith("import ")]
    check("F3 recover.py 顶部没有新增第三方依赖",
          all((" " not in l) or (" as " in l) or ("." not in l) for l in top) and
          not any(m in " ".join(top) for m in ("numpy", "capstone", "elftools", "requests")),
          top)
    check("F4 ARM axf 的剖析结果不变（175 个函数）",
          (RC.analyze(AXF, deep=True).get("functions") or {}).get("total") == 175,
          (RC.analyze(AXF, deep=True).get("functions") or {}).get("total"))

def main():
    print("== 批次91：台账窗口按布局推（推出来的只当上下界）==")
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
