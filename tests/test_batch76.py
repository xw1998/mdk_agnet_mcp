# -*- coding: utf-8 -*-
"""批次76 mock 测试：`toolset` 描述的「组数 + 组名清单」从 TOOLSETS 现取。

来由（一条 AI 面向的错口径）：`toolset` 是 AI 找工具面的入口，它的说明里此前**手写**着
「按 11 个组划分」并枚举了 11 个组。`code` 组（批次68-70 的代码索引）加入后这句话没同步：
实际 12 个组，枚举里也没有 `code` —— AI 读到的是一份**看似权威的错清单**，还因此压根
不知道「省 token 应对大型工程」的那一组存在。

修法不是把 11 改成 12，而是**从 `toolbox.TOOLSETS` 现取**（组数与组名都不再手写），
这样以后加组/删组描述自动跟着变，这一类腐烂不会再来。

注意 lean 档会裁掉描述中段（只留段首+段末），所以：
  - 组数在**默认档**可见（段首）→ 用默认档断言；
  - 组名清单落在中段，要**full 档**才看得到 → 用 full 档断言。

  A 默认档：组数是现取的（12），旧错口径「11 个组」不再出现
  B full 档：枚举覆盖每一个组（含此前漏掉的 code）
  C group_catalog() 自身：覆盖全组、不多不少、每项「组名 标签」
  D 不变量：注册 200 / 默认面 44 / core 38 / trace 38（防止顺手改坏）

运行：python -m tests.test_batch76
"""
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import server as SV           # noqa: E402

PORT = 15576
PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def desc_of(desc_mode=None):
    """建 server 取 `toolset` 的描述；desc_mode="full" 时按全文档建。"""
    saved = os.environ.pop("MDKDEBUG_DESC", None)
    try:
        if desc_mode:
            os.environ["MDKDEBUG_DESC"] = desc_mode
        srv = SV.create_server(port=PORT)
        return srv._tool_manager._tools["toolset"].description or ""
    finally:
        os.environ.pop("MDKDEBUG_DESC", None)
        if saved is not None:
            os.environ["MDKDEBUG_DESC"] = saved

# ------------------------------------------------------------------
def section_a():
    print("A. 默认档：组数是现取的")
    d = desc_of()
    n = len(TB.TOOLSETS)
    check("A1 默认档描述里出现「按 %d 个组划分」" % n,
          ("按 %d 个组划分" % n) in d, d[:220])
    check("A2 旧的错口径「11 个组」不再出现", "11 个组" not in d, d[:220])
    check("A3 组数本身确实不是 11（要修的就是它）", n != 11, n)

def section_b():
    print("B. full 档：枚举不漏组")
    d = desc_of("full")
    missing = [g for g in sorted(TB.TOOLSETS) if g not in d]
    check("B1 每个组名都出现在全文描述里", not missing, missing)
    check("B2 code 组在枚举里（此前漏的就是它）", "code" in d)
    check("B3 全文里的组数表述与 len(TOOLSETS) 一致",
          ("按 %d 个组划分" % len(TB.TOOLSETS)) in d, len(TB.TOOLSETS))

def section_c():
    print("C. group_catalog() 自身")
    parts = [p.strip() for p in TB.group_catalog().split("、") if p.strip()]
    names = [p.split(" ")[0] for p in parts]
    check("C1 每项都是「组名 标签」",
          all(len(p.split(" ")) >= 2 and p.split(" ")[1] for p in parts), parts)
    check("C2 覆盖全部组且不多不少",
          sorted(names) == sorted(TB.TOOLSETS), names)
    check("C3 不含未知组", not (set(names) - set(TB.TOOLSETS)), names)

def section_d():
    print("D. 工具面不变量")
    all_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="all").list_tools()))
    core_n = len(asyncio.run(SV.create_server(port=PORT, toolsets="core").list_tools()))
    check("D1 注册总数 200", all_n == 200, all_n)
    check("D2 默认面 44（core 38 + 6 个永远保留的入口）", core_n == 44, core_n)
    check("D3 core 组 38", len(TB.TOOLSETS["core"]) == 38, len(TB.TOOLSETS["core"]))
    check("D4 trace 组 38", len(TB.TOOLSETS["trace"]) == 38, len(TB.TOOLSETS["trace"]))

# ------------------------------------------------------------------
def main():
    for fn in (section_a, section_b, section_c, section_d):
        try:
            fn()
        except Exception as e:                                # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常: %r" % (fn.__name__, e))
    print("\n==== test_batch76: %d pass / %d fail ====" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAIL:", f)
        sys.exit(1)

if __name__ == "__main__":
    main()
