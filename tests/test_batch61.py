# -*- coding: utf-8 -*-
"""批次61 mock 测试：报错给的「切符号」动作必须按**真实工具面**决定带不带装卸步骤。

批次67 追加（这条教训的最终落点）：`set_symbol_file` / `list_symbol_projects` 已上移到
`core`，**默认面上就能切符号**，所以默认动作清单不再有装卸那一步；装卸分支保留，改由
「启动时把 core 收起来的裁剪面」（如 `MDKDEBUG_TOOLSETS=mem`）覆盖——坑的形状没变，
只是默认配置不再踩它。

问题来源（用户转述某个 AI 的三层分析，我按代码逐条核对后确认的那一层）：
  env_check 在**默认可见的 core 组**，职责就含「符号与板上固件是否同源」的核对；
  可它在符号不一致时给出的 next_actions 是「set_symbol_file 切到…」——而
  set_symbol_file 在**默认不暴露的 symbol 组**（toolbox.DEFAULT_GROUPS=("core",)）。
  调用方照着做只会撞「未知工具」，而「要先装 symbol 组」这条线索当时只写在 toolset
  工具的描述里，不在报错里、也不在体检结论里：
  **能告诉你坏了，没法动手修，还不告诉你钥匙在哪。**

本批次只做「把钥匙一起递过去」（方案1，不动分组、不动自动切换语义）：
  A tool_hidden 三态：True 已收起 / False 在面上 / None 拿不到账本（不知道 ≠ 没有）
  B _symbol_switch_actions：按**真实账面**决定要不要带装卸那一步，拿不到账本时不猜
  C _symbol_source_check 三个分支都接上（no-symbols 原先**根本没有** next_actions）
  D 端到端：装上 symbol 组之后再报，指引自动收敛（装了就闭嘴，不啰嗦）
  E 接线自检：core 组工具的提示也接上了（set_breakpoint / get_current_location）

运行：python -m tests.test_batch61
"""
import os
import sys
import json
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import server as SV          # noqa: E402
from mdkdebug import toolbox as TB         # noqa: E402

PORT = 15497

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


def call(srv, name, args):
    r = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}


def main():
    print("批次61：切符号指引必须按真实账面带（或不带）装卸步骤")

    # ============ A. tool_hidden 三态 ============
    print("A. toolbox.tool_hidden：已收起 / 在面上 / 拿不到账本（三态不混用）")
    srv_core = SV.create_server(port=PORT, toolsets="core")
    srv_all = SV.create_server(port=PORT + 1, toolsets="all")
    srv_mem = SV.create_server(port=PORT + 2, toolsets="mem")   # core 被收起的裁剪面

    check("A1 默认面（core）：set_symbol_file 已在面上 → False（批次67 起它属于 core）",
          TB.tool_hidden("set_symbol_file", srv_core) is False,
          TB.tool_hidden("set_symbol_file", srv_core))
    check("A1b 裁剪面（只装 mem / core 被收起）：set_symbol_file 已被收起 → True",
          TB.tool_hidden("set_symbol_file", srv_mem) is True,
          TB.tool_hidden("set_symbol_file", srv_mem))
    check("A2 默认面（core）：env_check 在面上 → False（检测器默认可见＝问题所在）",
          TB.tool_hidden("env_check", srv_core) is False,
          TB.tool_hidden("env_check", srv_core))
    check("A3 全开面（all）：set_symbol_file 在面上 → False",
          TB.tool_hidden("set_symbol_file", srv_all) is False,
          TB.tool_hidden("set_symbol_file", srv_all))
    check("A4 没注册过的工具名 → False（「没注册」不算「被收起」）",
          TB.tool_hidden("no_such_tool_xyz", srv_core) is False,
          TB.tool_hidden("no_such_tool_xyz", srv_core))

    bak_last = TB._LAST
    try:
        TB._LAST = None
        check("A5 拿不到账本（工具面未初始化）→ None：是「不知道」不是「没有」",
              TB.tool_hidden("set_symbol_file", None) is None,
              TB.tool_hidden("set_symbol_file", None))
    finally:
        TB._LAST = bak_last

    # ============ B. _symbol_switch_actions 的三种口径 ============
    print("B. _symbol_switch_actions：按真实账面给步骤，不猜")
    a_core = SV._symbol_switch_actions(srv_core)
    a_all = SV._symbol_switch_actions(srv_all)
    a_mem = SV._symbol_switch_actions(srv_mem)
    check("B1 默认面：不需要装卸，直接给切符号（手段已在 core 面上）",
          a_core == ["set_symbol_file 切到与刚烧录固件同源的 .axf"], a_core)
    check("B1b 裁剪面（core 被收起）：第一步就是装卸（含 toolsets=\"symbol\"）",
          'toolsets="symbol"' in a_mem[0] and len(a_mem) == 2, a_mem)
    check("B2 末步仍是「切符号」本身（装卸只是前置，不替换动作）",
          a_core[-1] == "set_symbol_file 切到与刚烧录固件同源的 .axf", a_core)
    check("B3 全开面：不再啰嗦装卸，只给切符号这一步",
          a_all == ["set_symbol_file 切到与刚烧录固件同源的 .axf"], a_all)

    try:
        TB._LAST = None
        a_none = SV._symbol_switch_actions(None)
        check("B4 账本不可用：按「可能不在面上」措辞，不硬说「已被收起」",
              "若不在当前工具面上" in a_none[0] and "已被收起" not in a_none[0],
              a_none)
        check("B5 账本不可用也照样给出 toolsets=\"symbol\" 这条路（不因未知就省掉）",
              'toolsets="symbol"' in a_none[0], a_none)
    finally:
        TB._LAST = bak_last

    # ============ C/D. _symbol_source_check 三个分支 + 装了就闭嘴 ============
    print("C. _symbol_source_check：三个分支都接上（服务器状态注入，不读目标）")
    bak_fw = dict(SV._fw_cfg)
    bak_sym = dict(SV._symbol_cfg)
    bak_reloc = SV._eff_reloc_delta
    bak_fm = SV._chipid.firmware_match
    try:
        # -- C1/C2/C3：符号与固件不是同一份（different） --
        SV._fw_cfg.update({"project": r"D:\fwA\a.uvprojx", "target": "t1",
                           "axf": r"D:\fwA\a.axf", "reason": "flash_download",
                           "ts": 1.0, "time_text": "t"})
        SV._symbol_cfg.update({"locator": "stub", "axf": r"D:\fwB\b.axf",
                               "source_type": "axf"})
        sc = SV._symbol_source_check(deep="false", server=srv_core)
        check("C1 different 分支：第一条就是切符号（默认面上手段已可用，不再前置装卸）",
              sc.get("verdict") == "different"
              and sc["next_actions"][0] == "set_symbol_file 切到与刚烧录固件同源的 .axf",
              sc.get("next_actions"))
        check("C2 装完（all 面）再问同一问题：指引自动收敛，不再出现装卸步骤",
              SV._symbol_source_check(deep="false", server=srv_all)["next_actions"][0]
              == "set_symbol_file 切到与刚烧录固件同源的 .axf",
              SV._symbol_source_check(deep="false", server=srv_all)["next_actions"])

        # -- C3：本会话没加载符号（no-symbols），旧版没有 next_actions --
        SV._symbol_cfg.update({"locator": None, "axf": None, "source_type": None})
        sc = SV._symbol_source_check(deep="false", server=srv_core)
        check("C3 no-symbols 分支：补上了 next_actions（旧版只有 warning，没给动作）",
              sc.get("verdict") == "no-symbols"
              and isinstance(sc.get("next_actions"), list) and sc["next_actions"]
              and sc["next_actions"][0].startswith("set_symbol_file 切到"), sc)

        # -- C4：内容指纹判「不是板上那份」（content-mismatch） --
        SV._symbol_cfg.update({"locator": "stub", "axf": r"D:\fwC\c.axf",
                               "source_type": "axf"})
        SV._eff_reloc_delta = lambda: (0xF000, "mock delta")
        SV._chipid.firmware_match = lambda client, ref, delta: {
            "verdict": "firmware-mismatch", "note": "指纹一条都没中"}
        sc = SV._symbol_source_check(client=object(), deep="auto", server=srv_core)
        check("C4 content-mismatch 分支：第一条同样是切符号（假符号场景最常见）",
              sc.get("verdict") == "content-mismatch"
              and sc["next_actions"][0] == "set_symbol_file 切到与刚烧录固件同源的 .axf",
              sc.get("next_actions"))
        check("C5 content-mismatch 的 next_actions 保留原有的后两条动作（没被覆盖掉）",
              any("flash_debug" in a for a in sc["next_actions"])
              and any("env_check" in a for a in sc["next_actions"]), sc["next_actions"])

        # -- D：端到端「装了就闭嘴」：真的调 toolset 装 symbol 组 --
        r = call(srv_mem, "toolset", {"action": "load", "toolsets": "core"})
        check("D1 裁剪面上 load core 真把 set_symbol_file 装上了（装卸分支端到端可用）",
              r.get("ok") is True and "set_symbol_file" in (r.get("loaded") or []),
              r)
        r2 = call(srv_mem, "toolset", {"action": "load", "toolsets": "symbol"})
        check("D1b symbol 组仍可单独装载（组内还有 7 个，set_symbol_file 已不在此组）",
              r2.get("ok") is True and "find_symbol" in (r2.get("loaded") or [])
              and "set_symbol_file" not in (r2.get("loaded") or []), r2)
        check("D1c 默认面上 set_symbol_file 本来就在（不靠装 symbol 组）",
              TB.tool_hidden("set_symbol_file", srv_core) is False,
              TB.tool_hidden("set_symbol_file", srv_core))
        check("D2 裁剪面装回 core 后 tool_hidden 立刻变 False（状态跟随真实工具面）",
              TB.tool_hidden("set_symbol_file", srv_mem) is False,
              TB.tool_hidden("set_symbol_file", srv_mem))
        sc = SV._symbol_source_check(client=object(), deep="auto", server=srv_mem)
        check("D3 装完后再报同一问题：指引不再说「会报未知工具」，只给切符号",
              sc["next_actions"][0]
              == "set_symbol_file 切到与刚烧录固件同源的 .axf", sc["next_actions"])
    finally:
        SV._fw_cfg.clear()
        SV._fw_cfg.update(bak_fw)
        SV._symbol_cfg.clear()
        SV._symbol_cfg.update(bak_sym)
        SV._eff_reloc_delta = bak_reloc
        SV._chipid.firmware_match = bak_fm

    # ============ E. 接线自检 ============
    print("E. 接线：core 组工具的提示也接上（源码级核对）")
    src = open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("E1 三处 _symbol_source_check 调用都透传 server（否则账面判断会取错 server）",
          src.count("_symbol_source_check(client=_get_client(), server=server)") == 1
          and src.count("_symbol_source_check(client=client, server=server)") == 1
          and src.count("server=server)") >= 1,
          src.count("server=server)"))
    check("E2 三个分支的 next_actions 都走同一 helper（不再各写一份文案）",
          src.count('out["next_actions"] = _symbol_switch_actions(server)') == 3,
          src.count('out["next_actions"] = _symbol_switch_actions(server)'))
    check("E3 core 组工具的提示内嵌了装卸指引（get_current_location ×2 + set_breakpoint ×1）",
          src.count("_symbol_switch_hint()") >= 3, src.count("_symbol_switch_hint()"))
    tb_src = open(os.path.join(ROOT, "mdkdebug", "toolbox.py"), encoding="utf-8").read()
    check("E4 tool_hidden 落在 toolbox 且 server 参数贯穿 _pick",
          "def tool_hidden(" in tb_src and "tb = _pick(server)" in tb_src, "")

    print("\n==== 批次61 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
