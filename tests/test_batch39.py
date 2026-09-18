# -*- coding: utf-8 -*-
"""批次39 mock 测试：OpenOCD 控制台「假成功」修复 + 错误归类。

来源：用户「gcc的调试链试了吗？」——真机复核 GCC/OpenOCD 链路时发现
`ocd_cmd("monitor targets")` 在 OpenOCD 明确报 `invalid command name` 的情况下
仍返回 ok=true（典型的「看似权威的错答案」）。

真机取证（F401 + DAPLink + OpenOCD 0.12.0，2026-09-18）：
  monitor targets                 -> `invalid command name "monitor"`
  definitely_no_such_cmd_xyz      -> `invalid command name "..."`
  wp 0x20000000                   -> 用法说明 `wp [address length [...]]`
  read_memory 0xZZZZ 4            -> 用法说明 `read_memory address width count ['phys']`
  reset nonsense_mode             -> 一串命令列表（含 `reset [run|halt|init]`）
  reg no_such_reg_xyz             -> `register X not found in current target`
  mdw 0x20000000 99999            -> `Failed to read memory at 0x20018004`
以上都不带 `Error: ` 前缀，早期只按 `Error:`/`couldn't open` 判定，全部漏判。

  A _shape 层：真机原文逐条判定（A1–A9）
  B ocd_cmd 端到端：失败不再报 ok=true；正常命令不受影响（B1–B6）
  C 连带不回归：ocd_read_mem 半成功仍给结构化 complete/got_bytes（C1–C4）
  D mock 与真机一致性：未知命令回包不带 `Error: ` 前缀（D1–D2）
  E trace_rtt_find/attach 缺参归类 invalid-argument（E1–E2）

运行：python -m tests.test_batch39
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b39")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests import mock_openocd as MOC            # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import ocd as _ocd                 # noqa: E402
from mdkdebug.server import create_server        # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:                                   # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:                                        # noqa: BLE001
        return {"_raw": txt[:400]}


# 真机原文（逐字复制，含换行）
REAL_CASES = [
    ("monitor targets",
     'invalid command name "monitor"\n',
     True),
    ("definitely_no_such_cmd_xyz",
     'invalid command name "definitely_no_such_cmd_xyz"\n',
     True),
    ("wp 0x20000000",
     "rwp 'all' | address\nwp [address length [('r'|'w'|'a') [value [mask]]]]\n",
     True),
    ("read_memory 0xZZZZ 4",
     "read_memory address width count ['phys']\n"
     "  stm32f4x.cpu read_memory address width count ['phys']\n",
     True),
    ("reset nonsense_mode",
     "cortex_m reset_config ['sysresetreq'|'vectreset']\n"
     "power_restore\n"
     "program <filename> [address] [preverify] [verify] [reset] [exit]\n"
     "reset [run|halt|init]\n"
     "reset_config [none|trst_only|srst_only|trst_and_srst]\n",
     True),
    ("reg no_such_reg_xyz",
     "register no_such_reg_xyz not found in current target\n",
     True),
    # 正常输出：绝不能被新规则误判
    ("targets",
     "TargetName         Type       Endian TapName            State       \n"
     "--  ------------------ ---------- ------ -------- -------\n"
     "0* stm32f4x.cpu       cortex_m   little stm32f4x.cpu     halted\n",
     False),
    ("wp",
     "0x20000000 length 4, watchpoint 'w' (value 0x0, mask 0x0)\n",
     False),
    ("mdw 0x08000000 4",
     "0x08000000: 20018000 0800010d 08000109 08000109 \n",
     False),
]


def test_shape():
    """A 组：_shape 直接吃真机原文。"""
    for i, (cmd, raw, want_fail) in enumerate(REAL_CASES, 1):
        r = _ocd._shape(cmd, raw)
        got_fail = not r.get("ok")
        check("A%d _shape(%r) 判定=%s" % (i, cmd, "失败" if want_fail else "成功"),
              got_fail is want_fail,
              {"ok": r.get("ok"), "error": r.get("error"),
             "lines": r.get("lines")})


def test_usage_helper():
    """A 组补：用法判定只认「本命令的第一个词」开头的占位符行。"""
    check("A10 用法行识别：wp [...]",
          _ocd._looks_like_usage("wp 0x20000000", ["wp [address length]"]))
    check("A11 用法行识别：别的命令的用法行不算",
          not _ocd._looks_like_usage("wp 0x20000000",
                                     ["program <filename> [address]"]))
    check("A12 已 halted 的正常回包不算用法",
          not _ocd._looks_like_usage(
              "halt", ["[stm32f4x.cpu] halted due to debug-request"]))


async def test_ocd_cmd(server):
    """B 组：端到端。"""
    r = await call(server, "ocd_cmd", {"command": "no_such_cmd_xyz"})
    check("B1 未知命令 ok=false", r.get("ok") is False, r)
    check("B2 未知命令 error 里带原文",
          "invalid command name" in json.dumps(r, ensure_ascii=False), r)

    r = await call(server, "ocd_cmd", {"command": "targets"})
    check("B3 正常命令仍 ok=true", r.get("ok") is True, r)
    check("B4 正常命令 output 有目标表",
          "stm32f4x.cpu" in (r.get("output") or ""), r)

    r = await call(server, "ocd_cmd", {"command": "version; targets"})
    check("B5 多命令正常路径不受影响", r.get("ok") is True, r)

    r = await call(server, "ocd_cmd", {"command": "version; no_such_xyz"})
    check("B6 多命令里一条错则整体 ok=false", r.get("ok") is False, r)


async def test_read_mem_regress(server):
    """C 组：越界读仍要给结构化「只读到 N/M 字节」，不能退化成裸回包。"""
    r = await call(server, "ocd_read_mem",
                   {"addr": "0x20000000", "n_bytes": 16, "width": 32})
    check("C1 正常读 ok=true 且 complete",
          r.get("ok") is True and r.get("complete") is True, r)

    # 越界：RAM 只有 0x20000，读到 0x20010000 之外
    r = await call(server, "ocd_read_mem",
                   {"addr": "0x2001FFF0", "n_bytes": 64, "width": 32})
    check("C2 越界读 ok=false", r.get("ok") is False, r)
    check("C3 越界读仍给出 got_bytes/expected_bytes（不是裸回包）",
          "got_bytes" in r and "expected_bytes" in r, r)
    check("C4 越界读 complete=false", r.get("complete") is False, r)


async def test_mock_fidelity(server):
    """D 组：mock 回包必须与真机同形（不带 `Error: ` 前缀）。"""
    check("D1 mock 未知命令回包不含 `Error: ` 前缀",
          not any("Error:" in ln for ln in MOC.MockOpenOCD()._err("xxx")),
          MOC.MockOpenOCD()._err("xxx"))
    check("D2 mock 未知名回包=真机原文形",
          MOC.MockOpenOCD()._err("monitor")[0] == 'invalid command name "monitor"',
          MOC.MockOpenOCD()._err("monitor"))


async def test_trace_args(server):
    """E 组：RTT 定位缺参归类 invalid-argument（之前是 unknown-error）。"""
    for i, tool in enumerate(("trace_rtt_find", "trace_rtt_attach"), 1):
        r = await call(server, tool, {})
        check("E%d %s 缺参 error_code=invalid-argument" % (i, tool),
              r.get("error_code") == "invalid-argument", r)
        check("E%da %s 仍给出可操作 hint" % (i, tool),
              bool(r.get("hint") or r.get("error")), r)


async def main():
    mock = MOC.MockOpenOCD()
    sess = MOC.attach(mock)
    try:
        server = create_server(host="127.0.0.1", port=0, idle_timeout=5.0)
        print("-- A _shape 层（真机原文）--")
        test_shape()
        test_usage_helper()
        print("\n-- B ocd_cmd 端到端 --")
        await test_ocd_cmd(server)
        print("\n-- C 读内存不回归 --")
        await test_read_mem_regress(server)
        print("\n-- D mock 与真机一致性 --")
        await test_mock_fidelity(server)
        print("\n-- E trace 缺参归类 --")
        await test_trace_args(server)
    finally:
        MOC.detach(sess, mock)

    print("\n" + "=" * 72)
    print("通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
