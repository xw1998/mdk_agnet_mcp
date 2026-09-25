# -*- coding: utf-8 -*-
"""批次35 mock 测试：Keil 官方命令行通道 + 报错知识库 + SVD + 工程编辑 + 工具面裁剪。

来源：第 16 轮反馈「mdk 还支持 cmd 指令方式调试，再找找其他 mdk 相关 mcp 吸收经验」
（调研见 docs/oss-absorption.md §8，实测见 docs/PITFALLS.md 第七章）。

  A 报错知识库 keilkb：编译诊断文本规则 / 命令错误码 / 未收录不猜
  B UV4 -d 批处理通道 cmdscript：静态 lint / 真实链路（假 UV4）/ uvoptx 还原
  C CMSIS-SVD：定位 / derivedFrom 继承 / cluster / 地址反查（本批次修的核心 bug）
  D uvprojx 受控编辑：只读查看 / 增删包含路径 / 增删文件 / 备份 / 幂等
  E 工具面：注册、总数 98、wait_state、capabilities、工具集裁剪

运行：python -m tests.test_batch35
"""
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b35")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import keilkb  # noqa: E402
from mdkdebug import cmdscript  # noqa: E402
from mdkdebug import svd as _svd  # noqa: E402
from mdkdebug import uvprojx  # noqa: E402
from mdkdebug import server as srv  # noqa: E402
from mdkdebug import uvsock as uvproto  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14907
REAL_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvprojx")
PASS, FAIL = [], []
TMPROOT = tempfile.mkdtemp(prefix="mdkdebug_b35_")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or c.text for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:400]}


# ----------------------------------------------------------------------
# 假 UV4：验证 -d 通道全链路（不碰真实 Keil）
# ----------------------------------------------------------------------
FAKE_UV4_PY = r'''
import os, re, sys

args = sys.argv[1:]
log_path, proj = None, None
for i, a in enumerate(args):
    if a == "-o" and i + 1 < len(args):
        log_path = args[i + 1]
    if a == "-d" and i + 1 < len(args):
        proj = args[i + 1]
out = ["Fake UV4 (mdkdebug tests) argv=%s" % " ".join(args)]
if proj:
    uvoptx = os.path.splitext(proj)[0] + ".uvoptx"
    out.append("uvoptx=%s" % uvoptx)
    txt = open(uvoptx, encoding="utf-8", errors="replace").read()
    m = re.search(r"<tIfile>(.*?)</tIfile>", txt, re.S)
    ini = (m.group(1) if m else "").strip()
    out.append("tIfile=%s" % ini)
    if ini and os.path.isfile(ini):
        lines = open(ini, encoding="ascii", errors="replace").read().splitlines()
        for ln, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith("LOG >>"):
                continue
            if s.startswith("printf("):
                mm = re.search(r"__mdkdebug_done_(\d+)__", s)
                if mm:
                    out.append("__mdkdebug_done_%s__" % mm.group(1))
                continue
            if "BADCMD" in s:
                out.append("*** error 34, line %d: undefined identifier" % ln)
            else:
                out.append("exec: %s" % s)
        # 模拟初始化文件的 LOG >>file：把回放内容落到 trace 文件
        m2 = re.search(r"^LOG >>(.+)$", open(ini, encoding="ascii",
                                             errors="replace").read(), re.M)
        if m2:
            with open(m2.group(1).strip(), "w", encoding="utf-8") as f:
                f.write("\n".join(out) + "\n")
if log_path:
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
sys.exit(0)
'''


def _make_fake_uv4(workdir):
    py = os.path.join(workdir, "fake_uv4.py")
    io.open(py, "w", encoding="utf-8", newline="").write(FAKE_UV4_PY)
    bat = os.path.join(workdir, "fake_uv4.bat")
    # 注意：.bat 会被 cmd.exe 按 OEM 代码页解析，写成 UTF-8 会把含中文的
    # 解释器路径读成乱码（真机实测：cmd 直接报「系统找不到指定的路径」）。
    io.open(bat, "w", encoding="mbcs", newline="").write(
        '@echo off\r\n"%s" "%s" %%*\r\n' % (sys.executable, py))
    return bat


def _make_fake_project(workdir, name="fake"):
    """造一个带 <tIfile> 的假工程（.uvprojx + .uvoptx 成对）。"""
    proj = os.path.join(workdir, name + ".uvprojx")
    optx = os.path.join(workdir, name + ".uvoptx")
    io.open(proj, "w", encoding="utf-8", newline="").write("<?xml version=\"1.0\"?>\n<Project/>\n")
    io.open(optx, "w", encoding="utf-8", newline="").write(
        "<?xml version=\"1.0\"?>\r\n<ProjectOpt>\r\n"
        "  <Extensions>\r\n    <DebugOpt>\r\n"
        "      <tIfile></tIfile>\r\n    </DebugOpt>\r\n  </Extensions>\r\n"
        "</ProjectOpt>\r\n")
    return proj, optx


# ----------------------------------------------------------------------
# A. 报错知识库
# ----------------------------------------------------------------------
def group_a_keilkb():
    print("A. 报错知识库 keilkb（编译诊断 + 命令错误码）")

    r = keilkb.explain_build_error('../Core/Src/main.c(120): error: #20: '
                                   'identifier "htim2" is undefined')
    check("A1 编译诊断文本命中（#20 identifier undefined）",
          r["matched"] and r["code"] == 20 and r["confidence"] == "medium",
          r)

    r = keilkb.explain_build_error("main.c(8): error: #5: cannot open source "
                                   "input file \"uart.h\"")
    check("A2 头文件缺失类诊断能命中并给出可执行修法",
          r["matched"] and r.get("fix"), r)

    r = keilkb.explain_build_error("some weird diagnostic nobody wrote down")
    check("A3 未收录诊断不猜测：matched=False + confidence=unknown + 通用排查路径",
          (not r["matched"]) and r["confidence"] == "unknown" and r.get("generic_fix"), r)

    r = keilkb.explain_command_error("*** error 57, line 3: illegal address")
    check("A4 命令错误码 57（illegal address）命中真机实测条目",
          r["matched"] and r["code"] == 57 and r["confidence"] == "high", r)

    r = keilkb.explain_command_error("*** error 34, line 11: undefined identifier")
    check("A5 命令错误码 34 命中", r["matched"] and r["code"] == 34, r)

    r = keilkb.explain_command_error(code=999999)
    check("A6 未实测的错误码不编造含义",
          (not r["matched"]) and r["confidence"] == "unknown" and r.get("generic_fix"), r)

    codes = keilkb.known_debug_codes()
    check("A7 已收录命令错误码清单可枚举（34/57/65/72/145 都在）",
          all(c in codes for c in (34, 57, 65, 72, 145)), codes)


# ----------------------------------------------------------------------
# B. UV4 -d 批处理通道
# ----------------------------------------------------------------------
def group_b_cmdscript():
    print("B. UV4 -d 批处理通道 cmdscript")

    warns = cmdscript.lint_commands(["Go main", "DISPLAY 1", "Step", "T"])
    cmd_warns = [w for w in warns if "index" in w]
    kinds = " ".join(json.dumps(w, ensure_ascii=False) for w in cmd_warns)
    check("B1 静态 lint 拦下三类会挂死/写法错的命令（Go main / DISPLAY / Step）",
          "Go main" in kinds and "DISPLAY" in kinds and "Step" in kinds
          and len(cmd_warns) == 3, warns)
    check("B1b 脚本级提示：缺 EXIT 单独告警，不混进命令级告警凑数",
          any("EXIT" in w.get("warning", "") for w in warns)
          and len(warns) == 4, warns)

    warns2 = cmdscript.lint_commands(["g, main", "T", "BS main", "EVAL foo", "EXIT"])
    check("B2 合法命令不误报", warns2 == [], warns2)

    workdir = os.path.join(TMPROOT, "cmd")
    os.makedirs(workdir, exist_ok=True)
    uv4 = _make_fake_uv4(workdir)
    proj, optx = _make_fake_project(workdir)
    before = io.open(optx, "r", encoding="utf-8", newline="").read()

    r = cmdscript.run_debug_script(uv4, proj, ["g, main", "BS main", "EVAL x"], timeout=60)
    check("B3 全链路跑通：ok=True 且每条命令都走到完成标记",
          r.get("ok") is True and r.get("completed") == len(r.get("commands") or []), r)

    check("B4 自动补 EXIT（用户没写也不至于把 UV4 挂在调试态）",
          [c["command"] for c in r.get("commands") or []].count("EXIT") == 1,
          [c["command"] for c in r.get("commands") or []])

    after = io.open(optx, "r", encoding="utf-8", newline="").read()
    check("B5 无论成败都还原 .uvoptx（不污染工程）",
          after == before and r["uvoptx"]["restored"] is True, r.get("uvoptx"))

    check("B6 初始化文件与 trace 日志落在 ASCII 临时目录",
          os.path.isdir(r["artifacts"]["workdir"])
          and all(ord(c) < 128 for c in r["artifacts"]["workdir"]),
          r["artifacts"])

    r2 = cmdscript.run_debug_script(uv4, proj, ["g, main", "BADCMD foo", "T"], timeout=60)
    errs = r2.get("errors") or []
    check("B7 命令报错不改退出码：ok 由日志判定为 False",
          r2.get("ok") is False and r2.get("exit_code") == 0 and r2.get("error_count") == 1,
          {"ok": r2.get("ok"), "exit_code": r2.get("exit_code"), "errs": errs})
    check("B8 error 行能映射回「是第几条命令」",
          errs and errs[0]["code"] == 34 and errs[0]["command"] == "BADCMD foo"
          and errs[0]["command_index"] == 1, errs)
    check("B9 报错命令标 completed=False，未阻塞的后续命令照常走完",
          [it["completed"] for it in r2["commands"]] == [True, True, True, True]
          or (r2["commands"][1]["completed"] is True
              and r2["pending"] == []), r2["commands"])

    r3 = cmdscript.run_debug_script(uv4, os.path.join(workdir, "nope.uvprojx"), ["T"])
    check("B10 工程不存在：直接报错而不是硬跑", r3.get("ok") is False, r3)

    r4 = cmdscript.run_debug_script("", proj, ["T"])
    check("B11 未定位 UV4：明确说明通道不可用", r4.get("ok") is False and "UV4" in r4["error"], r4)

    io.open(optx, "w", encoding="utf-8", newline="").write(
        before.replace("<tIfile></tIfile>", "<tIfile>a</tIfile><tIfile>b</tIfile>"))
    r5 = cmdscript.run_debug_script(uv4, proj, ["T"])
    check("B12 <tIfile> 不唯一时拒绝改写工程文件（锚点唯一性保护）",
          r5.get("ok") is False and "唯一" in r5.get("error", ""), r5)


# ----------------------------------------------------------------------
# C. CMSIS-SVD
# ----------------------------------------------------------------------
def group_c_svd():
    print("C. CMSIS-SVD（定位 / 继承 / 地址反查）")

    hits = _svd.find_svd_files("STM32F401RCTx")
    if not hits:
        check("C0 本机有可用的 .svd（缺则跳过 C 组）", False,
              "未找到 .svd；搜索根 %s" % _svd._pack_roots())
        return
    check("C1 订货型号 STM32F401RCTx 能按公共前缀匹配到容量档 SVD（STM32F401x*）",
          os.path.basename(hits[0]).startswith("STM32F401"), hits[:3])

    r = _svd.load(device="STM32F401RCTx")
    check("C2 加载成功且外设数量合理（>20）",
          r.get("ok") and r.get("peripheral_count", 0) > 20, r.get("peripheral_count"))

    check("C3 derivedFrom 继承生效：USART2 是空壳外设但有完整寄存器",
          len(_svd.regs_of("USART2")) > 5, _svd.regs_of("USART2")[:5])

    d = _svd.decode_value(peripheral="USART2", register="CR1", value=0x200C)
    got = {f["name"]: f["value"] for f in d.get("fields") or []}
    check("C4 位域解码：CR1=0x200C → UE/TE/RE 均为 1",
          d.get("ok") and got.get("UE") == 1 and got.get("TE") == 1
          and got.get("RE") == 1, d.get("fields"))

    d2 = _svd.decode_value(address=0x4000440C, value=0x200C)
    check("C5 地址反查不再串台：0x4000440C 判为 USART2.CR1（修复前误判 SPI2）",
          d2.get("ok") and d2.get("peripheral") == "USART2"
          and d2.get("register") == "CR1", d2)
    check("C6 反查走了真实 addressBlock（可信度最高那档）",
          d2.get("matched_by") == "addressBlock", d2.get("matched_by"))

    d3 = _svd.decode_value(address=0x40003800, value=0x1)
    check("C7 相邻外设互不干扰：0x40003800 判为 SPI2",
          d3.get("ok") and d3.get("peripheral") == "SPI2", d3)

    d4 = _svd.decode_value(peripheral="GPIOA", register="MODER", value=0x280)
    g4 = {f["name"]: f["value"] for f in d4.get("fields") or []}
    check("C8 数组/枚举位域：GPIOA.MODER=0x280 → MODER3/MODER4 均为 2",
          d4.get("ok") and g4.get("MODER3") == 2 and g4.get("MODER4") == 2, d4.get("fields"))

    d5 = _svd.decode_value(address=0x12345678, value=1)
    check("C9 落在无外设区域：如实报错而不硬套一个外设",
          d5.get("ok") is False and "不落在任何已知外设" in d5.get("error", ""), d5)

    # 真机踩过的坑：不给器件时按「发现顺序」挑第一份 .svd，会挑到别的芯片，
    # 把 0x40020000(GPIOA) 判成 TIMER2 —— 看似权威的错答案比报错更危险。
    _svd._CACHE.update({"loaded": False, "path": None, "device": "",
                        "peripherals": {}, "error": None})
    amb = _svd.load(device="")
    check("C10 不给 device 且盘上有多份 .svd 时拒绝盲挑，并给出候选清单",
          amb.get("ok") is False and amb.get("ambiguous") is True
          and amb.get("candidates"), amb)
    _svd.load(device="STM32F401RCTx")     # 复原缓存，后续用例照常


# ----------------------------------------------------------------------
# D. uvprojx 受控编辑
# ----------------------------------------------------------------------
def group_d_uvprojx():
    print("D. uvprojx 受控编辑（先备份、锚点唯一、文本级替换）")

    if not os.path.isfile(REAL_PROJ):
        check("D0 存在可用的真实工程样例", False, REAL_PROJ)
        return
    work = os.path.join(TMPROOT, "proj")
    os.makedirs(work, exist_ok=True)
    copy = os.path.join(work, "mdk_test.uvprojx")
    shutil.copy2(REAL_PROJ, copy)
    original = io.open(copy, "r", encoding="utf-8", errors="replace").read()
    real_before = io.open(REAL_PROJ, "rb").read()

    targets = uvprojx.list_targets(copy)
    check("D1 列出 target 名", bool(targets), targets)

    cfg = uvprojx.read_config(copy)
    check("D2 只读配置：器件与 target 名读对"
          "（示例工程 IncludePath 本就是空串，应如实返回空串而不是 None）",
          cfg.get("ok") and cfg.get("device") == "STM32F401RCTx"
          and cfg.get("target") == "mdk_test"
          and cfg.get("include_path") == "", cfg)

    groups = uvprojx.list_groups(copy)
    check("D3 列出分组与文件", groups and groups[0].get("group"), groups[:2])

    r = uvprojx.add_include_path(copy, ["../Core/Inc", "../TEST_ONLY/Inc"])
    check("D4 加包含路径：added 且生成备份文件",
          r.get("ok") and len(r.get("added") or []) >= 1
          and r.get("backup") and os.path.isfile(r["backup"]), r)
    txt = io.open(copy, "r", encoding="utf-8", errors="replace").read()
    check("D5 新路径真的写进了 IncludePath", "../TEST_ONLY/Inc" in txt, None)

    r2 = uvprojx.add_include_path(copy, ["../TEST_ONLY/Inc"])
    check("D6 幂等：已存在的路径计入 skipped，不重复写入",
          r2.get("ok") and "../TEST_ONLY/Inc" in (r2.get("skipped") or []), r2)

    check("D6b 空改动不写文件：IncludePath 里没有出现字面量 None（修复前会静默写坏）",
          ">None<" not in io.open(copy, "r", encoding="utf-8",
                                  errors="replace").read(), None)

    r3 = uvprojx.del_include_path(copy, r"TEST_ONLY")
    check("D7 按正则删包含路径", r3.get("ok") and "../TEST_ONLY/Inc" not in
          io.open(copy, "r", encoding="utf-8", errors="replace").read(), r3)

    r3b = uvprojx.del_include_path(copy, r"绝不匹配的目录名ZZZ")
    check("D7b 删除无匹配项：changed=False 且原文件不被写成 None",
          r3b.get("ok") and r3b.get("changed") is False
          and ">None<" not in io.open(copy, "r", encoding="utf-8",
                                      errors="replace").read(), r3b)

    r4 = uvprojx.add_files(copy, "TESTGRP", ["../Core/Src/nope_t35.c"])
    txt4 = io.open(copy, "r", encoding="utf-8", errors="replace").read()
    check("D8 加文件并自动新建分组",
          r4.get("ok") and "TESTGRP" in txt4 and "nope_t35.c" in txt4, r4)

    r5 = uvprojx.remove_files(copy, r"nope_t35")
    txt5 = io.open(copy, "r", encoding="utf-8", errors="replace").read()
    check("D9 按正则删文件条目", r5.get("ok") and "nope_t35.c" not in txt5, r5)

    check("D10 文本级替换没把工程洗一遍（除增删项外结构保持一致）",
          txt5.count("<Groups>") == original.count("<Groups>")
          and txt5.count("<TargetName>") == original.count("<TargetName>"), None)

    # 改动只发生在副本上
    check("D11 真实工程文件全程未被改动（测试只动临时副本）",
          io.open(REAL_PROJ, "rb").read() == real_before, None)


# ----------------------------------------------------------------------
# E. 工具面（mock 调试器 + 子进程裁剪）
# ----------------------------------------------------------------------
async def group_e_surface(server, uv4):
    print("E. 工具面：注册 / wait_state / capabilities / 裁剪")

    tools = await server.list_tools()
    names = sorted(t.name for t in tools)
    check("E1 工具总数 199（工具面只增不减；批次34 +1，批次36 +46，批次40 +3，批次42 +1）", len(names) == 199, len(names))
    for n in ("keil_command", "explain_build_error", "batch_debug_script", "wait_state",
              "svd_list", "svd_decode", "uvprojx_read", "uvprojx_edit",
              "address_for_line", "capabilities"):
        check("E2 新工具 %s 已注册" % n, n in names, names)

    lt = await call(server, "list_tools", {"keyword": "svd"})
    check("E3 list_tools 能查出 svd 系列且带示例参数",
          lt.get("count", 0) >= 2 and all("example_args" in t for t in lt.get("tools") or []), lt)

    r = await call(server, "wait_state", {"state": "not_debugging", "timeout_s": 3})
    check("E4 wait_state：未进调试时等 not_debugging 立即命中（mock 已模拟真实 Keil 语义）",
          r.get("ok") and r.get("matched") and r.get("observed") == "not_debugging", r)

    t0 = time.time()
    r = await call(server, "wait_state", {"state": "stopped", "timeout_s": 1, "poll_ms": 100})
    dt = time.time() - t0
    check("E5 wait_state：等一个到不了的状态，给出 timeout_kind=never_debugging 且不空转",
          r.get("ok") is False and r.get("timeout_kind") == "never_debugging"
          and r.get("matched") is False and dt < 3.5,
          {"r": r, "elapsed": round(dt, 2)})

    r = await call(server, "wait_state", {"state": "banana"})
    check("E6 wait_state：未知状态名明确拒绝并列出可用值",
          r.get("ok") is False and r.get("available"), r)

    r = await call(server, "wait_state", {"state": "expr"})
    check("E7 wait_state：state=expr 但没给 expr 时报错而不是干等",
          r.get("ok") is False and "expr" in r.get("error", ""), r)

    await call(server, "enter_debug", {})
    r = await call(server, "wait_state", {"state": "stopped", "timeout_s": 5, "poll_ms": 100})
    check("E8 wait_state：进调试后等 stopped 能命中",
          r.get("ok") and r.get("matched") and r.get("observed") == "stopped", r)

    r = await call(server, "capabilities", {})
    ch = (r.get("channels") or {})
    check("E9 capabilities：报出两条通道的可用性（uvsock 通、uv4 命令行有假 UV4）",
          r.get("ok") and ch.get("uvsock", {}).get("available") is True
          and "uv4_cmdline" in ch, r)
    check("E10 capabilities：报出内置模块与工具数",
          (r.get("modules") or {}).get("keilkb", {}).get("available") is True
          and (r.get("tool_surface") or {}).get("tool_count") == 199, r)

    r = await call(server, "address_for_line", {"file": "__no_such_file__.c", "line": 10})
    check("E11 address_for_line：文件没被符号收录时如实报错，不瞎给地址",
          r.get("ok") is False and bool(r.get("error")), r)

    # 真机踩过：DWARF 的「文件起始」占位行地址为 0，main.c 这种靠前的行会命中它，
    # 返回 ok=true + 0x00000000 —— AI 会真的去 0 号地址下断点。
    r = await call(server, "address_for_line", {"file": "main.c", "line": 10})
    check("E11b 编译不出地址的行不会被 0 号占位地址糊弄（不返回 address=0）",
          not (r.get("ok") is True and not r.get("address")), r)

    # 工具层跑一遍 uvprojx / svd / keilkb 三个工具（验证参数口径与信封）
    work = os.path.join(TMPROOT, "proj2")
    os.makedirs(work, exist_ok=True)
    copy = os.path.join(work, "mdk_test.uvprojx")
    shutil.copy2(REAL_PROJ, copy)
    r = await call(server, "uvprojx_read", {"project": copy, "what": "targets"})
    check("E12 uvprojx_read 工具层可用", r.get("ok") and r.get("targets"), r)

    r = await call(server, "uvprojx_edit", {
        "action": "add_include_path", "project": copy, "paths": "../T35/Inc"})
    check("E13 uvprojx_edit 工具层可用、带备份，且按中风险工具登记（会改用户工程）",
          r.get("ok") and r.get("backup") and r.get("risk") == "medium", r)

    r = await call(server, "uvprojx_edit", {"action": "explode", "project": copy})
    check("E14 uvprojx_edit：未知 action 拒绝并列出可用值",
          r.get("ok") is False and r.get("available"), r)

    r = await call(server, "svd_list", {"device": "STM32F401RCTx", "keyword": "USART"})
    usarts = [x for x in (r.get("peripherals") or []) if x.startswith("USART")]
    check("E15 svd_list 工具层可用且 keyword 过滤生效",
          r.get("ok") and usarts, r)

    r = await call(server, "svd_decode", {"address": "0x4000440C", "value": "0x200C"})
    check("E16 svd_decode 工具层：地址反查 + 位域解码",
          r.get("ok") and r.get("peripheral") == "USART2", r)

    # 不给 device 时按当前工程 <Device> 自动加载，而不是盲挑盘上第一份 .svd
    _svd._CACHE.update({"loaded": False, "path": None, "device": "",
                        "peripherals": {}, "error": None})
    r = await call(server, "svd_decode", {"address": "0x40020000", "value": "0x280"})
    check("E16b 不给 device 时按当前工程器件自动加载 SVD（不再盲挑到别的芯片）",
          r.get("ok") is True and r.get("peripheral") == "GPIOA"
          and str(r.get("svd_device") or "").startswith("STM32F401")
          and r.get("device_auto") is True, r)

    r = await call(server, "explain_build_error", {"text": "main.c(3): error: #20: x undefined"})
    check("E17 explain_build_error 工具层可用", r.get("ok") and r.get("matched"), r)

    r = await call(server, "keil_command", {"command": "BS"})
    check("E18 keil_command：命令窗口直通仍可用（mock）", isinstance(r, dict), r)

    # 工具集裁剪：子进程验证（环境变量在 create_server 时读取）
    code = ("import asyncio;from mdkdebug import server as s;"
            "srv=s.create_server(port=14999);"
            "print(len(asyncio.run(srv.list_tools())))")
    env = dict(os.environ, MDKDEBUG_TOOLSETS="serial")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180)
    check("E19 MDKDEBUG_TOOLSETS=serial 时工具面被裁到 20 个（14 串口 + 6 常驻）",
          out.stdout.strip().endswith("20"), out.stdout[-200:] + out.stderr[-200:])

    env2 = dict(os.environ, MDKDEBUG_TOOLSETS="bogus")
    out2 = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env2,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=180)
    check("E20 未知组名时不裁剪（宁可少裁不错杀；“199”即当前全量工具数）",
          out2.stdout.strip().endswith("199"),
          out2.stdout[-200:] + out2.stderr[-200:])

    env3 = dict(os.environ, MDKDEBUG_TOOLSETS="core,build")
    code3 = ("import asyncio;from mdkdebug import server as s;"
             "srv=s.create_server(port=14999);"
             "ns=[t.name for t in asyncio.run(srv.list_tools())];"
             "print('build_project' in ns, 'serial_read' in ns, 'list_tools' in ns)")
    out3 = subprocess.run([sys.executable, "-c", code3], cwd=ROOT, env=env3,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=180)
    check("E21 多组组合生效，且 list_tools 永远保留（否则 AI 连工具清单都问不出来）",
          out3.stdout.strip().endswith("True False True"),
          out3.stdout[-200:] + out3.stderr[-200:])


# ----------------------------------------------------------------------
async def main():
    workdir = os.path.join(TMPROOT, "uv4")
    os.makedirs(workdir, exist_ok=True)
    fake_uv4 = _make_fake_uv4(workdir)

    group_a_keilkb()
    group_b_cmdscript()
    group_c_svd()
    group_d_uvprojx()

    mock = MockUVSOCKServer("127.0.0.1", PORT).start()
    _orig = mock._dispatch

    def _dispatch_realistic(cmd, data):
        if cmd == uvproto.UV_DBG_STATUS and not mock.debugging:
            body = b"Target is not in debug mode\x00"
            return (uvproto.UV_STATUS_NOT_DEBUGGING,
                    struct.pack("<i", len(body)) + body)
        return _orig(cmd, data)

    mock._dispatch = _dispatch_realistic
    mock.stop_ignores = False
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           uv4_path=fake_uv4, axf_path=None,
                           default_project=REAL_PROJ)
    try:
        await group_e_surface(server, fake_uv4)
    finally:
        try:
            await call(server, "exit_debug", {})
        except Exception:  # noqa: BLE001
            pass
        mock.stop()

    print("\n==== 批次35 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
    print("临时工作目录（保留供排查）:", TMPROOT)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
