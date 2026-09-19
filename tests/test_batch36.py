# -*- coding: utf-8 -*-
"""批次36 mock 测试：非 MDK 芯片调试族（工具链 / 目标档案 / OpenOCD / trace）。

来源：用户「拓展 riscv 和 esp32 等不依赖 mdk 芯片的调试，要会操作 gcc/make/cmake
和 ocd 调试，同类 mcp 全部吸收；再实现 SWD 接口下和 SWO 接口下的 trace
（需要往代码里插桩组件）」。

  A 工具链族 toolchain_*：探测 / 环境 / 运行 / 工程识别 / 编译 / ELF / 尺寸 / 报错解析
  B 目标档案 target_*：18 份档案 / 取档 / 由 ELF 或名字反推
  C OpenOCD ocd_*：假 telnet 服务器全链路（探针 / 内存 / 寄存器 / 断点 / 观察点 /
    烧录 / 日志 / 多命令聚合 / 错误路径）
  D trace 族：SWO 采集与 ITM+MTF 解码 / RTT（主机侧读写控制块并推进 RdOff）/
    采样剖析 / DWT / 组件部署
  E 工具面：注册总数 188、五族齐全、capabilities.non_mdk
  F gdb 解析：只挑**真能跑**的 gdb、绝不到别的架构去凑（ESP 工具链复核）

真机（F401 + DAPLink）验证单独做，见 docs/PITFALLS.md。

运行：python -m tests.test_batch36
"""
import asyncio
import io
import json
import os
import shutil
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUARD_DIR = os.path.join(tempfile.gettempdir(), "mdkdebug_guard_test_b36")
os.makedirs(GUARD_DIR, exist_ok=True)
os.environ["MDKDEBUG_GUARD_DIR"] = GUARD_DIR

from tests import mock_openocd as MOC            # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import ocd as _ocd                  # noqa: E402
from mdkdebug import targets as _tg               # noqa: E402
from mdkdebug import toolchain as _tc             # noqa: E402
from mdkdebug import trace as _tr                 # noqa: E402
from mdkdebug import traceproto as _tp            # noqa: E402
from mdkdebug import server as srv                # noqa: E402
from mdkdebug.server import create_server         # noqa: E402

REAL_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                        "mdk_test", "mdk_test.axf")
REAL_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM")
PASS, FAIL = [], []
TMPROOT = tempfile.mkdtemp(prefix="mdkdebug_b36_")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def good(r):
    """统一成"成功与否"：少数工具只给 status 不给 ok。"""
    return r.get("ok") is True or (r.get("ok") is None and r.get("status") == "ok")


async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:                                   # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or c.text for c in res.content)
    try:
        return json.loads(txt)
    except Exception:                                        # noqa: BLE001
        return {"_raw": txt[:400]}


def itm_pack(port, data):
    """把一段字节按 ITM instrumentation 包打成 SWO 流（4/2/1 字节一组）。

    载荷 3 字节没有对应的 ss 编码（00 是保留值），必须拆成 2+1。
    """
    out = b""
    i = 0
    n = len(data)
    while i < n:
        left = n - i
        take = 4 if left >= 4 else (2 if left >= 2 else 1)
        chunk = data[i:i + take]
        code = {1: 1, 2: 2, 4: 3}[len(chunk)]
        out += bytes([(port << 3) | code]) + chunk
        i += take
    return out


_MTF_ID = {v: k for k, v in _tp.MTF_TYPES.items()}     # 名字 -> 编号


def mtf_text(text):
    return _tp.mtf_frame(_MTF_ID["text"], text.encode("utf-8"))


def mtf_counter(cid, value):
    return _tp.mtf_frame(_MTF_ID["counter"], struct.pack("<HI", cid, value))


# ======================================================================
# A 工具链族
# ======================================================================
def test_toolchain(server):
    r = asyncio.run(call(server, "toolchain_list", {"with_version": False}))
    fams = r.get("families") or {}
    check("A1 toolchain_list 有结构且不抛", isinstance(fams, dict) and bool(fams),
          list(r)[:8])
    r = asyncio.run(call(server, "toolchain_list",
                         {"family": "arm-none-eabi", "with_version": False}))
    check("A2 单家族查询", "arm-none-eabi" in (r.get("families") or {}), list(r)[:8])

    r = asyncio.run(call(server, "toolchain_env", {"show_only": True}))
    check("A3 toolchain_env show_only 只读不改环境",
          r.get("ok") is True and isinstance(r.get("state"), dict), r)

    r = asyncio.run(call(server, "toolchain_run", {"tool": "no-such-tool-xyz"}))
    check("A4 不存在的工具如实报错（不给看似权威的结果）",
          r.get("ok") is False and r.get("error"), r)

    r = asyncio.run(call(server, "toolchain_detect_project", {"path": REAL_PROJ}))
    check("A5 识别 Keil 工程（uvprojx -> kind=mdk）",
          good(r) and r.get("kind") == "mdk", r)

    cmake_dir = os.path.join(TMPROOT, "proj_cmake")
    os.makedirs(cmake_dir, exist_ok=True)
    io.open(os.path.join(cmake_dir, "CMakeLists.txt"), "w",
            encoding="utf-8").write("project(demo C)\n")
    r = asyncio.run(call(server, "toolchain_detect_project", {"path": cmake_dir}))
    check("A6 识别 CMake 工程", r.get("kind") == "cmake", r)

    make_dir = os.path.join(TMPROOT, "proj_make")
    os.makedirs(make_dir, exist_ok=True)
    io.open(os.path.join(make_dir, "Makefile"), "w",
            encoding="utf-8").write("all:\n\t@echo hi\n")
    r = asyncio.run(call(server, "toolchain_detect_project", {"path": make_dir}))
    check("A7 识别 Make 工程", r.get("kind") == "make", r)

    empty = os.path.join(TMPROOT, "proj_none")
    os.makedirs(empty, exist_ok=True)
    r = asyncio.run(call(server, "toolchain_detect_project", {"path": empty}))
    check("A8 认不出就说 none（不硬猜）", r.get("kind") == "none", r)

    r = asyncio.run(call(server, "toolchain_build",
                         {"project": make_dir, "dry_run": True}))
    steps = r.get("steps") or []
    check("A9 dry_run 只给命令不真跑",
          bool(steps) and all(s.get("dry_run") for s in steps), r)

    gcc_err = (
        "/proj/src/main.c:12:5: error: 'foo' undeclared (first use in this function)\n"
        "/proj/src/main.c:20:1: warning: control reaches end of non-void function "
        "[-Wreturn-type]\n"
        "/proj/src/led.c:7:10: fatal error: stm32f4xx.h: No such file or directory\n"
        "/proj/src/a.c:3:1: error: unknown type name 'uint32_t'; did you mean 'uint32_t'?\n"
        "undefined reference to `HAL_Init'\n"
        "collect2: error: ld returned 1 exit status\n")
    r = asyncio.run(call(server, "toolchain_errors", {"text": gcc_err}))
    errs = r.get("errors") or r.get("items") or []
    check("A10 gcc 报错解析出条目（有报错时 ok=False 是设计）",
          r.get("count") == 5 and len(errs) == 5, r)
    allit = (r.get("errors") or []) + (r.get("warnings") or [])
    sev = [e.get("severity") for e in allit]
    check("A11 区分 error/warning（warning 不混进 errors）",
          "warning" in sev and "error" in sev and not any(
              e.get("severity") == "warning" for e in r.get("errors") or []), sev)
    notes = json.dumps(r, ensure_ascii=False)
    check("A12 缺头文件给出中文提示", "include" in notes.lower() or "路径" in notes,
          notes[:200])

    if os.path.isfile(REAL_AXF):
        r = asyncio.run(call(server, "toolchain_elf_info", {"elf": REAL_AXF}))
        check("A13 读真实 ELF（mdk_test.axf）",
              r.get("ok") is True and (r.get("machine") or r.get("arch")), r)
        r = asyncio.run(call(server, "toolchain_size", {"elf": REAL_AXF}))
        has = any(k in r for k in ("sections", "totals", "total", "regions",
                                  "text"))
        check("A14 尺寸统计给出分区数据",
              good(r) and has and "size.exe" in str(r.get("tool")), r)
    else:
        check("A13/A14 真实 axf 不存在，跳过", True, "skip")
        check("A13/A14 跳过（占位）", True, "skip")

    r = asyncio.run(call(server, "toolchain_elf_info", {"elf": "/nope/x.elf"}))
    check("A15 不存在的 ELF 如实报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "toolchain_compile", {"files": "/nope/x.c"}))
    check("A16 编译不存在的源文件如实报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "toolchain_objcopy", {"elf": "/nope/x.elf"}))
    check("A17 objcopy 不存在的 ELF 如实报错", r.get("ok") is False, r)


# ======================================================================
# B 目标档案
# ======================================================================
def test_targets(server):
    r = asyncio.run(call(server, "target_list", {}))
    prof = r.get("profiles") or r.get("items") or []
    check("B1 target_list 返回档案表", good(r) and len(prof) >= 20, len(prof))
    check("B2 档案数 = 20（含本批新增的 F407/F446）",
          len(prof) == 20, r.get("count"))
    names = json.dumps(prof, ensure_ascii=False)
    for pid in ("stm32f401", "stm32f407", "esp32c3", "riscv-generic",
                "rp2040"):
        check("B3 含档案 %s" % pid, pid in names, names[:200])

    r = asyncio.run(call(server, "target_list", {"arch": "riscv"}))
    prof2 = r.get("profiles") or []
    check("B4 按架构过滤（riscv）",
          0 < len(prof2) < len(prof) and all(p.get("arch") == "riscv" for p in prof2),
          r)

    r = asyncio.run(call(server, "target_show", {"profile": "stm32f401"}))
    check("B5 取档 stm32f401（cpu + 真实 OpenOCD 参数）",
          good(r) and "m4" in str(r.get("cpu")).lower()
          and r.get("target") == "target/stm32f4x.cfg"
          and "stm32f4x.cfg" in json.dumps(r.get("openocd_args"),
                                          ensure_ascii=False),
          json.dumps(r.get("openocd_args"), ensure_ascii=False)[:300])

    r = asyncio.run(call(server, "target_show", {"profile": "no-such-chip"}))
    check("B6 未知档案如实报错并给可选值",
          r.get("ok") is False and (r.get("suggest") or r.get("hint")), r)

    r = asyncio.run(call(server, "target_show",
                         {"profile": "esp32c3", "speed": 2000}))
    check("B7 esp32c3 走 riscv + openocd 参数",
          r.get("ok") is True and "riscv" in json.dumps(r, ensure_ascii=False), r)

    r = asyncio.run(call(server, "target_guess", {"name": "STM32F407ZGT6"}))
    check("B8 由型号名反推档案（F407 本批新增）",
          ((r.get("by_name") or {}).get("profiles") or [])[:1] == ["stm32f407"], r)
    r = asyncio.run(call(server, "target_guess", {"name": "ESP32-S3"}))
    check("B9 由名字反推 ESP32-S3",
          "s3" in json.dumps(r, ensure_ascii=False).lower(), r)
    r = asyncio.run(call(server, "target_guess", {"name": "unknownpart-xyz"}))
    check("B10 认不出就明确认不出（by_name.ok=False）",
          (r.get("by_name") or {}).get("ok") is False
          and not (r.get("by_name") or {}).get("profiles"), r)


# ======================================================================
# C OpenOCD（假服务器）
# ======================================================================
def test_ocd(server, mock):
    r = asyncio.run(call(server, "ocd_status", {"probe_target": False}))
    check("C1 ocd_status 报告会话运行中",
          r.get("ok") is True and r.get("running") is True, r)
    check("C2 ports/log 都在", r.get("ports", {}).get("telnet") == mock.port
          and r.get("log") or r.get("log_path"), r)

    r = asyncio.run(call(server, "ocd_probe", {}))
    check("C3 ocd_probe 认出 target（列对齐输出可解析）",
          r.get("ok") is True and r.get("targets")
          and r.get("targets")[0].get("name") == "stm32f4x.cpu", r)
    check("C4 CPUID 解出 Cortex-M4 / partno 0xC24",
          r.get("cpuid") == "0x410FC241" and r.get("partno") == "0xC24"
          and "M4" in str(r.get("core")),
          {k: r.get(k) for k in ("cpuid", "partno", "core")})
    check("C5 flash banks 解析出 base/size（driver 括号后直接 at）",
          r.get("flash_banks") and r["flash_banks"][0].get("base") == "0x08000000"
          and r["flash_banks"][0].get("size") == "0x00100000", r.get("flash_banks"))

    r = asyncio.run(call(server, "ocd_read_mem",
                         {"addr": "0xE000ED00", "n_bytes": 4}))
    check("C6 读 CPUID 内存值正确（小端 41c20f41）",
          r.get("ok") is True and (r.get("data_hex") or "").lower() == "41c20f41", r)

    r = asyncio.run(call(server, "ocd_read_mem",
                         {"addr": "0x50000000", "n_bytes": 4}))
    check("C7 读未映射地址如实报错（不返回假 0）",
          r.get("ok") is False and "read memory" in json.dumps(r).lower(), r)

    r = asyncio.run(call(server, "ocd_write_mem",
                         {"addr": "0x20000040", "data_hex": "deadbeef",
                          "verify": True}))
    check("C8 写内存并回读校验", r.get("ok") is True
          and (r.get("verified") is True or r.get("verify") is True), r)
    check("C9 目标内存真的变了",
          mock.target.peek(0x20000040, 4) == b"\xde\xad\xbe\xef",
          mock.target.peek(0x20000040, 4))

    r = asyncio.run(call(server, "ocd_write_mem",
                         {"addr": "0x20000050", "words": "0x11223344 0x55667788"}))
    check("C10 words 形式写入", r.get("ok") is True
          and mock.target.peek(0x20000050, 8) == b"\x44\x33\x22\x11\x88\x77\x66\x55", r)

    r = asyncio.run(call(server, "ocd_reg", {}))
    hexs = r.get("registers_hex") or {}
    check("C11 读全部寄存器（带 (0) 序号前缀也能解析）",
          r.get("ok") is True and int(hexs.get("pc") or "0", 16) == 0x08000400,
          {k: hexs.get(k) for k in ("pc", "sp", "xpsr")})
    check("C12 寄存器表含 xpsr/sp", "xpsr" in hexs and "sp" in hexs, list(hexs)[:20])

    r = asyncio.run(call(server, "ocd_reg", {"name": "pc"}))
    check("C13 读单个寄存器",
          r.get("ok") is True and int(r.get("value_hex") or "0", 16) == 0x08000400, r)

    r = asyncio.run(call(server, "ocd_reg", {"name": "r0", "value": "0x1234"}))
    check("C14 写寄存器并回读", r.get("ok") is True, r)
    check("C15 目标寄存器真的变了",
          dict(mock.target.regs).get("r0") == 0x1234, dict(mock.target.regs).get("r0"))

    r = asyncio.run(call(server, "ocd_control", {"action": "reset_halt"}))
    check("C16 reset_halt 后目标停住",
          r.get("ok") is True and "halted" in str(r.get("target_state"))
          and dict(mock.target.regs).get("pc") == 0x08000400, r)

    r = asyncio.run(call(server, "ocd_control", {"action": "step"}))
    check("C17 step 后 pc 前进", r.get("ok") is True
          and dict(mock.target.regs).get("pc") == 0x08000402, r)

    r = asyncio.run(call(server, "ocd_control", {"action": "resume"}))
    check("C18 resume 后 running", r.get("ok") is True
          and mock.target.halted is False, r)
    r = asyncio.run(call(server, "ocd_control", {"action": "halt"}))
    check("C19 halt 后停住", r.get("ok") is True and mock.target.halted is True, r)
    r = asyncio.run(call(server, "ocd_control", {"action": "bogus"}))
    check("C20 非法 action 如实报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "ocd_bp",
                         {"action": "set", "addr": "0x08000401", "length": 4}))
    check("C21 设断点成功", r.get("ok") is True, r)
    check("C22 奇数代码地址的 Thumb 位被清零（本批修）",
          bool(mock.target.bps) and mock.target.bps[-1]["addr"] == 0x08000400
          and "bit0" in str(r.get("note")), (mock.target.bps, r.get("note")))
    r = asyncio.run(call(server, "ocd_bp", {"action": "list"}))
    check("C23 列出断点", r.get("ok") is True and (r.get("breakpoints") or r.get("items")), r)
    r = asyncio.run(call(server, "ocd_bp", {"action": "clear", "addr": "0x08000400"}))
    check("C24 清断点", r.get("ok") is True
          and not any(b["addr"] == 0x08000400 for b in mock.target.bps), r)
    r = asyncio.run(call(server, "ocd_bp", {"action": "bogus"}))
    check("C25 非法断点 action 报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "ocd_wp",
                         {"action": "set", "addr": "0x20000040", "length": 4,
                          "kind": "w"}))
    check("C26 设数据观察点", r.get("ok") is True and mock.target.wps, r)
    r = asyncio.run(call(server, "ocd_wp", {"action": "list"}))
    check("C27 列出观察点", r.get("ok") is True, r)
    r = asyncio.run(call(server, "ocd_wp",
                         {"action": "clear", "addr": "0x20000040"}))
    check("C28 清观察点", r.get("ok") is True and not mock.target.wps, r)

    r = asyncio.run(call(server, "ocd_flash_info", {}))
    check("C29 flash info 解出 bank（driver 括号后直接 at 也能解析）",
          r.get("ok") is True
          and (r.get("parsed_banks") or [{}])[0].get("base") == "0x08000000",
          r.get("parsed_banks"))

    if os.path.isfile(REAL_AXF):
        r = asyncio.run(call(server, "ocd_flash",
                             {"file": REAL_AXF, "addr": "0x08000000"}))
        check("C30 烧录走到目标（mock 记录到 program/write_image）",
              r.get("ok") is True
              and (mock.target.programmed or mock.target.written_images), r)
        r = asyncio.run(call(server, "ocd_load",
                             {"file": REAL_AXF, "addr": "0x08000000"}))
        check("C31 load_image 走到目标", r.get("ok") is True
              and mock.target.loaded, r)
    else:
        check("C30/C31 无真实 axf，跳过", True, "skip")
        check("C30/C31 跳过（占位）", True, "skip")

    r = asyncio.run(call(server, "ocd_flash", {"file": "/nope/x.elf"}))
    check("C32 烧录不存在的文件如实报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "ocd_cmd",
                         {"command": "version; targets"}))
    check("C33 多命令一次下发并聚合输出",
          r.get("ok") is True and len(r.get("results") or r.get("commands") or []) == 2,
          r)
    r = asyncio.run(call(server, "ocd_cmd", {"command": "no_such_cmd"}))
    check("C34 命令报错如实透出（含 Error 行，栈行已折叠）",
          r.get("ok") is False and "invalid command name" in json.dumps(r), r)

    r = asyncio.run(call(server, "ocd_log", {"lines": 20}))
    check("C35 ocd_log 读回 OpenOCD 日志",
          r.get("ok") is True and "Listening" in (r.get("text") or ""), r)

    r = asyncio.run(call(server, "ocd_cfg_list", {"kind": "target"}))
    check("C36 ocd_cfg_list 有结构（装没装都给出可用信息）",
          "ok" in r and ("files" in r or "error" in r), r)

    r = asyncio.run(call(server, "ocd_start", {"profile": "stm32f401"}))
    check("C37 已在运行时 ocd_start 明确拒绝（不重复拉进程）",
          r.get("ok") is False and r.get("error"), r)

    r = asyncio.run(call(server, "ocd_gdb", {"commands": "info registers"}))
    check("C38 没有 gdb 时如实报错并给 hint（不假装成功）",
          r.get("ok") is False and (r.get("hint") or r.get("error")), r)

    # ---- 假成功防线：真机 RTT 端到端验证踩出来的两个坑 ----
    # 坑 1：OpenOCD 的失败回包不一定是行首 `Error:`。真机 `program` 打的是
    #       `couldn't open ...` + `embedded:startup.tcl:1813: Error: ** Programming Failed **`，
    #       只看行首会让 ok 留在 true——「烧录失败却报成功」。
    r = asyncio.run(call(server, "ocd_cmd", {"command": "program /nope/x.elf"}))
    check("C39 带位置前缀的 Error / couldn't open 也算失败（不让假成功漏过）",
          r.get("ok") is False and "Programming Failed" in json.dumps(r), r)
    shp = _ocd._shape("x", "** Programming Started **\ncouldn't open D://x.elf\n"
                          "embedded:startup.tcl:1813: Error: ** Programming Failed **")
    check("C40 _shape 结构化错误列表非空", shp.get("ok") is False and shp.get("errors"), shp)
    shp = _ocd._shape("x", "** Programming Finished **\n** Verify Started **\n** Verified OK **")
    check("C41 成功回包（Finished / Verified OK）不被误判成失败",
          shp.get("ok") is True, shp)

    # 坑 2：OpenOCD 的 telnet 口是 7-bit NVT，路径里的非 ASCII 字符传不过去
    #      （真机回显 `D:/工作/...` -> `D://...`，6 个字节消失）。工具要自动
    #      暂存成 ASCII 副本，且必须披露暂存路径——不能悄悄换文件。
    cn_dir = os.path.join(TMPROOT, "中文目录")
    os.makedirs(cn_dir, exist_ok=True)
    cn_elf = os.path.join(cn_dir, "验证固件.elf")
    with open(cn_elf, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
    r = asyncio.run(call(server, "ocd_flash", {"file": cn_elf, "verify": True}))
    check("C42 非 ASCII 路径自动暂存成 ASCII 副本再烧，并披露暂存路径",
          r.get("ok") is True and r.get("staged_from") == cn_elf
          and str(r.get("staged_path", "")).isascii()
          and mock.target.programmed
          and str(mock.target.programmed[-1]["args"][0]).isascii(), r)
    r = asyncio.run(call(server, "ocd_cmd",
                         {"command": "program %s" % cn_elf.replace(chr(92), "/")}))
    check("C43 绕过暂存直发中文路径确实会失败（说明暂存不是多余的）",
          r.get("ok") is False, r)
    r = asyncio.run(call(server, "ocd_load", {"file": cn_elf, "addr": "0x20000000"}))
    check("C44 ocd_load 同样走 ASCII 暂存",
          r.get("ok") is True and r.get("staged_from") == cn_elf, r)

    # ---- telnet 噪声与回显残片（真机 `reg xpsr` -> `rg xpsr` 踩出来的） ----
    check("C45 孤立 IAC 后面那个数据字节不被吞掉",
          _ocd._clean_telnet(b"\xffreg pc\r\n> ").startswith(b"reg pc"),
          _ocd._clean_telnet(b"\xffreg pc\r\n> "))
    shp = _ocd._shape("reg xpsr", "rg xpsr\nxPSR = 0x61000000")
    check("C46 回显残片被剔掉、真实结果保留",
          shp.get("lines") == ["xPSR = 0x61000000"], shp)
    shp = _ocd._shape("reg xpsr", "rg xpsr")
    check("C47 只收到回显残片时标记 _echo_only（触发补读）",
          shp.get("_echo_only") is True, shp)
    shp = _ocd._shape("halt", "")
    check("C48 本来就不输出的命令不误触补读（不白等）",
          shp.get("_echo_only") is False, shp)
    shp = _ocd._shape("mdw 0x08000000 1", "mdw 0x08000000 1\n0x08000000: 20000728")
    check("C49 正常回包不因残片规则被误删",
          shp.get("lines") == ["0x08000000: 20000728"], shp)


# ======================================================================
# D trace 族
# ======================================================================
def test_trace(server, mock):
    r = asyncio.run(call(server, "trace_guide", {"topic": "swd_wiring"}))
    check("D1 trace_guide 讲清接线", r.get("ok") is True
          and "SWO" in json.dumps(r, ensure_ascii=False), r)
    r = asyncio.run(call(server, "trace_guide", {"topic": "bogus"}))
    check("D2 未知 topic 时列出可选值（不静默给空）",
          bool(r.get("topics")) and not r.get("text"), list(r)[:8])

    # ---- SWO / ITM ----
    cap = os.path.join(TMPROOT, "swo.bin")
    r = asyncio.run(call(server, "trace_swo_start",
                         {"file": cap, "profile": "stm32f401"}))
    check("D3 swo_start 配 TPIU + 开 ITM 端口",
          r.get("ok") is True and any("tpiu config" in c for c in mock.target.tpiu)
          and any(c.startswith("itm port") for c in mock.target.itm_port_cmds), r)

    frames = mtf_text("boot ok") + mtf_counter(1, 0x1234) + mtf_text("tick")
    with open(cap, "ab") as f:
        f.write(b"\x00\x00")                       # 前置同步包，考验解码器
        f.write(itm_pack(1, frames))
    r = asyncio.run(call(server, "trace_swo_read", {"max_events": 50}))
    evs = (r.get("new_events") or r.get("events") or [])
    check("D4 SWO 增量读解出 MTF 事件",
          r.get("ok") is True and len(evs) >= 3, r)
    kinds = [e.get("kind") or e.get("type_name") for e in evs]
    check("D5 事件类型区分 text/counter", "text" in kinds and "counter" in kinds, kinds)
    dec0 = r.get("decoder") or (r.get("state") or {}).get("decoder") or {}
    check("D6 帧完整（无 CRC 错、无残渣）",
          dec0.get("crc_errors") == 0 and dec0.get("dropped_bytes") == 0, dec0)

    r2 = asyncio.run(call(server, "trace_swo_read", {"max_events": 50}))
    check("D7 增量语义：第二次不再重复给同一批",
          len(r2.get("new_events") or r2.get("events") or []) == 0, r2)

    # ---- 零字节时必须上目标取证，而不是笼统说「没数据」（真机踩坑） ----
    for off, val in ((0xE000EDFC, 0x00000000),   # DEMCR.TRCENA=0
                     (0xE0000E80, 0x00000003),   # ITM_TCR
                     (0xE0000E00, 0x00000002),   # ITM_TER：只使能了 port1
                     (0xE0040010, 0x0000000F),   # TPIU_ACPR
                     (0xE00400F0, 0x00000002)):  # TPIU_SPPR
        mock.target.poke(off, struct.pack("<I", val))
    (_tr._T.get("swo") or {}).pop("_diag", None)      # 绕开 5s 缓存
    r = asyncio.run(call(server, "trace_swo_read", {"max_events": 10}))
    vs = r.get("verdict") or []
    check("D7b 零字节时点出『目标没使能 trace』（TRCENA=0）",
          any("TRCENA" in v for v in vs), r)
    diag = r.get("diagnostics") or {}
    check("D7c 诊断如实带出读到的寄存器值",
          (diag.get("registers") or {}).get("DEMCR") == "0x00000000"
          and (diag.get("registers") or {}).get("ITM_TER") == "0x00000002", diag)
    check("D7d 给不出结论时也有可查清单（引脚/插桩/端口）",
          len(diag.get("checks") or []) >= 3 and bool(r.get("hint")), r)

    # 造一个坏帧（CRC 错）与一个 ITM Overflow，验证"如实上报不完整"
    with open(cap, "ab") as f:
        f.write(b"\x70")                                       # ITM Overflow
        bad = bytearray(mtf_text("broken"))
        bad[-1] ^= 0xFF
        f.write(itm_pack(1, bytes(bad)))
    r = asyncio.run(call(server, "trace_swo_read", {"max_events": 50}))
    dec = r.get("decoder") or (r.get("state") or {}).get("decoder") or {}
    check("D8 坏帧被记成 crc_errors（不当成正常数据）",
          r.get("ok") is True and (dec.get("crc_errors") or 0) >= 1, r)
    ovf = ((r.get("state") or {}).get("itm_overflow") or r.get("overflow") or 0)
    check("D9 ITM 溢出被计数（丢包必须报出来）",
          ovf >= 1
          or any(e.get("kind") == "overflow" for e in (r.get("events") or [])),
          {k: r.get(k) for k in ("overflow", "state")})

    r = asyncio.run(call(server, "trace_decode",
                         {"data_hex": itm_pack(1, mtf_text("x")).hex()}))
    check("D10 离线复解按 hex 输入", r.get("ok") is True and r.get("frames"), r)

    r = asyncio.run(call(server, "trace_events", {"limit": 100}))
    check("D11 trace_events 聚合事件",
          r.get("ok") is True and r.get("total_matched")
          and r.get("buffer_total") is not None, r)

    r = asyncio.run(call(server, "trace_status", {}))
    check("D12 trace_status 是紧凑状态（events 只是计数不是列表）",
          r.get("ok") is True and isinstance(r.get("events"), int), list(r)[:15])

    r = asyncio.run(call(server, "trace_profile", {"samples": 5, "top": 5}))
    check("D13 采样剖析明确标注侵入式",
          r.get("ok") is True and r.get("intrusive") is True and r.get("warning"), r)

    # DWT 寄存器（poke 进假目标）
    for off, val in ((0x00, 1), (0x04, 0x0000ABCD), (0x08, 0), (0x0C, 0),
                     (0x10, 0), (0x14, 0), (0x18, 7)):
        mock.target.poke(0xE0001000 + off, struct.pack("<I", val))
    r = asyncio.run(call(server, "trace_dwt_counters", {}))
    check("D14 读 DWT（CYCCNT 使能位解出）",
          r.get("ok") is True and r.get("cyccnt_ena") is True, r)

    r = asyncio.run(call(server, "trace_swo_stop", {}))
    check("D15 swo_stop 关端口", r.get("ok") is True
          and any("off" in c for c in mock.target.itm_port_cmds), r)

    # ---- RTT（主机侧自研） ----
    payload = mtf_text("rtt hello") + mtf_counter(2, 42)
    mock.target.install_rtt(up_payload=payload, up_size=256)
    r = asyncio.run(call(server, "trace_rtt_find",
                         {"ranges": "0x20000000-0x20010000"}))
    check("D16 RAM 扫描找到 RTT 控制块",
          r.get("ok") is True and r.get("addr") == MOC.RTT_CB_ADDR
          and r.get("addr_hex") == "0x%X" % MOC.RTT_CB_ADDR, r)

    r = asyncio.run(call(server, "trace_rtt_find",
                         {"ranges": "0x20010000-0x20020000"}))
    check("D17 扫不到就说没找到（不硬猜地址）",
          r.get("ok") is False or not r.get("addr"), r)

    r = asyncio.run(call(server, "trace_rtt_attach",
                         {"addr": "0x%X" % MOC.RTT_CB_ADDR}))
    check("D18 attach 认出上下行通道",
          r.get("ok") is True and r.get("up_channels") == 1
          and r.get("down_channels") == 1, r)
    rbad = asyncio.run(call(server, "trace_rtt_attach", {"addr": "0x20004000"}))
    check("D18b 地址不对时如实报「不是 RTT 控制块」（不让全 0 冒充合法块）",
          rbad.get("ok") is False
          and "SEGGER RTT" in json.dumps(rbad, ensure_ascii=False), rbad)

    check("D19 通道名读出来了",
          any(c.get("name") == "Terminal" for c in r.get("channels") or []), r)

    r = asyncio.run(call(server, "trace_rtt_read", {"channel": 0, "max_bytes": 256}))
    data = bytes.fromhex(r.get("data_hex") or r.get("hex") or "")
    check("D20 RTT 读到目标写的字节", r.get("ok") is True and data == payload, r)
    st = mock.target.rtt_up_state()[0]
    check("D21 读完推进了 RdOff（不写回目标会永久丢数据）",
          st["rd"] == len(payload), st)

    r = asyncio.run(call(server, "trace_rtt_read", {"channel": 0}))
    check("D22 空读不报错（wr==rd 就是没数据）",
          r.get("ok") is True and not (r.get("data_hex") or ""), r)

    r = asyncio.run(call(server, "trace_rtt_write", {"channel": 0, "data": "hi"}))
    check("D23 写下行通道", r.get("ok") is True and r.get("written") == 2, r)
    check("D24 目标下行缓冲真的有数据",
          mock.target.peek(MOC.RTT_DOWN_BUF, 2) == b"hi",
          mock.target.peek(MOC.RTT_DOWN_BUF, 2))

    r = asyncio.run(call(server, "trace_rtt_write",
                         {"channel": 0, "hex_data": "0102"}))
    check("D25 hex_data 发二进制", r.get("ok") is True, r)

    r = asyncio.run(call(server, "trace_rtt_read", {"channel": 5}))
    check("D26 不存在的通道如实报错", r.get("ok") is False, r)

    r = asyncio.run(call(server, "trace_rtt_detach", {}))
    check("D27 detach 返回本次统计", r.get("ok") is True, r)

    # ---- RTT 帧解码：RTT 通道里是**裸 MTF**，外面没有 ITM 封装 ----
    # 早期实现让 RTT 字节也去找 ITM 报文头，包里明明有可读文本却解出 0 个事件
    # （静默错答案），真机端到端验证时被抓住。
    r = asyncio.run(call(server, "trace_decode",
                         {"data_hex": payload.hex(), "fmt": "mtf"}))
    check("D27a fmt=mtf 能解出裸 MTF 帧", r.get("ok") is True
          and r.get("frames_total") == 2 and r.get("mode_used") == "mtf", r)
    r = asyncio.run(call(server, "trace_decode", {"data_hex": payload.hex()}))
    check("D27b auto 模式自动认出裸 MTF（ITM 找不到包就退回 MTF）",
          r.get("ok") is True and r.get("mode_used") == "mtf"
          and r.get("frames_total") == 2, r)
    r = asyncio.run(call(server, "trace_decode",
                         {"data_hex": payload.hex(), "fmt": "nope"}))
    check("D27c fmt 非法值如实报错（不猜格式）", r.get("ok") is False, r)
    r = asyncio.run(call(server, "trace_events", {"limit": 50}))
    rtt_evs = [e for e in (r.get("events") or [])
               if e.get("source") == "mtf-rtt"]
    check("D27d rtt_read 顺手把帧塞进事件缓冲（trace_events 看得到内容）",
          r.get("ok") is True
          and any(e.get("text") == "rtt hello" for e in rtt_evs), r)

    # ---- 组件部署 ----
    tdir = os.path.join(TMPROOT, "comp")
    r = asyncio.run(call(server, "trace_instrument",
                         {"target_dir": tdir, "backend": "rtt", "coreclk": 84000000,
                          "swo_baud": 4000000}))
    check("D28 部署组件成功", r.get("ok") is True and r.get("copied"), r)
    need = ("mdk_trace.h", "mdk_trace.c", "mdk_trace_config.h", "mdk_trace.mk")
    missing = [f for f in need if not os.path.isfile(os.path.join(tdir, f))]
    check("D29 关键文件都落地", not missing, missing)
    conf = ""
    p = os.path.join(tdir, "mdk_trace_config.h")
    if os.path.isfile(p):
        conf = io.open(p, encoding="utf-8", errors="replace").read()
    check("D30 生成的配置里后端是 RTT（不会双后端）",
          "MDK_TRACE_BACKEND_RTT" in conf and "MDK_TRACE_BACKEND_ITM" not in conf, conf[:300])
    check("D31 配置带上 SWO 波特率与主频",
          "4000000" in conf and "84000000" in conf, conf[:300])
    r2 = asyncio.run(call(server, "trace_instrument", {"target_dir": tdir}))
    check("D32 重复部署默认 SKIP，不覆盖已有配置",
          not r2.get("copied") and r2.get("skipped")
          and bool(r2.get("skip_note")), r2)

    r = asyncio.run(call(server, "trace_instrument",
                         {"target_dir": os.path.join(TMPROOT, "comp2"),
                          "backend": "itm", "itm_port": 3}))
    check("D33 ITM 后端参数生效",
          r.get("ok") is True and "MDK_TRACE_ITM_PORT" in io.open(
              os.path.join(TMPROOT, "comp2", "mdk_trace_config.h"),
              encoding="utf-8").read(), r)

    r = asyncio.run(call(server, "trace_clear", {"reset": True}))
    check("D34 trace_clear 复位", r.get("ok") is True, r)


# ======================================================================
# E 工具面
# ======================================================================
def test_surface(server):
    r = asyncio.run(call(server, "list_tools", {}))
    tools = r.get("tools") or []
    names = [t.get("tool") if isinstance(t, dict) else t for t in tools]
    check("E1 工具总数 188", len(names) == 188, len(names))
    check("E1b 工程配置发现工具在册", "debug_config" in names)
    # target_ 前缀共 4 个：本批新增 target_list/show/guess 3 个，
    # 另有历史工具 target_info（MDK 侧调试目标信息），故计 4。
    for pre, cnt in (("toolchain_", 10), ("target_", 4), ("ocd_", 17),
                     ("trace_", 29)):
        got = [n for n in names if n.startswith(pre)]
        check("E2 %s* 共 %d 个" % (pre, cnt), len(got) == cnt, len(got))

    r = asyncio.run(call(server, "capabilities", {}))
    nm = r.get("non_mdk") or {}
    check("E3 capabilities 暴露 non_mdk", bool(nm), list(r)[:12])
    check("E4 non_mdk 报工具链现状",
          "found" in json.dumps(nm.get("toolchain") or {}, ensure_ascii=False)
          or "families_found" in (nm.get("toolchain") or {}), nm.get("toolchain"))
    check("E5 non_mdk 报档案数 20",
          (nm.get("targets") or {}).get("profiles") == 20, nm.get("targets"))
    check("E6 non_mdk 报 openocd 与会话状态",
          isinstance(nm.get("openocd"), dict) and "running" in nm["openocd"],
          nm.get("openocd"))
    check("E7 non_mdk 报 trace 紧凑状态",
          isinstance(nm.get("trace"), dict) and "mode" in nm["trace"], nm.get("trace"))
    check("E8 capabilities 给出非 MDK 链路建议",
          "when_to_use" in nm, list(nm)[:12])

    import mdkdebug
    import re as _re
    _ver = str(getattr(mdkdebug, "__version__", ""))
    check("E9 版本号形如 x.y.z（不写死具体版本）",
          bool(_re.fullmatch(r"\d+\.\d+\.\d+", _ver)), _ver)

def test_gdb_pick(server):
    """F gdb 解析：只挑真能跑的、且不跨架构。

    来源：ESP 工具链装完复核时发现的缺陷——
      * find_tool(fam, "gdb") 认死短名，xtensa-esp-elf 家族里根本没有无后缀 gdb 键，
        于是「有 gdb 却说没有」；
      * ocd_gdb 按 [elf 家族] + [固定四个家族] 顺序找，某个家族缺 gdb 时会**掉到别的
        架构**上（arm 的 ELF 拿 riscv/xtensa 的 gdb），拿到的是个看起来像样的错答案。
    """
    real_scan, real_probe, real_sub, real_find = (
        _tc.scan, _tc.probe_version, _tc.subprocess, _tc.find_gdb)
    try:
        fake_idx = {
            "riscv32-esp-elf": {
                "gcc": [r"C:\fake\riscv32-esp-elf-gcc.exe"],
                "gdb": [r"C:\fake\riscv32-esp-elf-gdb.exe"],
                "gdb-no-python": [r"C:\fake\riscv32-esp-elf-gdb-no-python.exe"],
            },
            "riscv-none-elf": {"gcc": [r"C:\fake\riscv-none-elf-gcc.exe"]},
            "arm-none-eabi": {
                "gcc": [r"C:\fake\arm-none-eabi-gcc.exe"],
                "gdb": [r"C:\fake\arm-none-eabi-gdb.exe"],
            },
        }
        _tc.scan = lambda refresh=False, max_age=20.0: fake_idx

        def fake_probe(path, refresh=False):
            bad = "no-python" not in path
            return {"tool": os.path.basename(path), "path": path, "ok": not bad,
                    "version": None if bad else "14.2",
                    "first_line": None,
                    "error": "起不来" if bad else None}

        _tc.probe_version = fake_probe

        g = _tc.find_gdb(family="riscv32-esp-elf")
        check("F1 无后缀 gdb 起不来时自动改用能跑的那个",
              g.get("ok") is True and g.get("via") == "gdb-no-python"
              and "no-python" in (g.get("path") or ""), g)
        # 两层必须自洽：find_gdb 挑出来的，run_tool 的白名单也得放行
        check("F1b find_gdb 选中的能被 run_tool 白名单放行",
              _tc.is_runnable(g.get("path") or ""), g.get("path"))
        check("F2 选中的不是坏候选，且坏候选留在 tried 里可追溯",
              [t for t in (g.get("tried") or []) if not t.get("ok")]
              and g.get("note"), g)

        g2 = _tc.find_gdb(family="arm-none-eabi")
        check("F3 本家族 gdb 全起不来时如实报错，不跨架构去凑",
              g2.get("ok") is False and g2.get("path") is None
              and bool(g2.get("tried"))
              and all(t.get("family") == "arm-none-eabi" for t in (g2.get("tried") or [])),
              g2)
        check("F4 报错里带 tried 与 hint（能自己往下查）",
              bool(g2.get("tried")) and bool(g2.get("hint")), g2)

        g3 = _tc.find_gdb(family="no-such-family-xyz")
        check("F5 家族名写错时明确报未知家族",
              g3.get("ok") is False and g3.get("gdb_select") == "bad-family", g3)

        # ocd_gdb：给了 elf 就必须按 elf 的家族去找
        seen = []

        def recorder(family="", probe=True):
            seen.append(family)
            return {"ok": False, "path": None, "family": family or None,
                    "error": "本机没找到 %s 能跑的 gdb" % (family or "任何家族"),
                    "hint": "装 xPack gcc 或 esp-elf-gdb", "tried": [],
                    "gdb_select": "elf-family" if family else "first-available"}

        _tc.find_gdb = recorder
        r = asyncio.run(call(server, "ocd_gdb", {"commands": "info registers"}))
        check("F6 没给 elf 时如实标注架构未知（first-available）",
              seen and seen[-1] == "" and r.get("gdb_select") == "first-available"
              and r.get("ok") is False, {"seen": seen, "r": r})
        if os.path.isfile(REAL_AXF):
            r2 = asyncio.run(call(server, "ocd_gdb",
                                  {"commands": "info registers", "elf": REAL_AXF}))
            check("F7 给了 arm 的 elf 就只在 arm-none-eabi 里找 gdb",
                  seen and seen[-1] == "arm-none-eabi" and r2.get("ok") is False, seen)

        # 放行白名单：ESP 的 gdb 名字带变体/版本尾巴（-no-python / -3.12）
        check("F9 带变体/版本尾巴的 gdb 名能过白名单，无关 exe 仍被拒",
              _tc.is_runnable("xtensa-esp-elf-gdb-no-python.exe")
              and _tc.is_runnable("xtensa-esp-elf-gdb-3.12.exe")
              and _tc.is_runnable("arm-none-eabi-gdb-py3.exe")
              and not _tc.is_runnable("calc.exe")
              and not _tc.is_runnable("mystery-tool.exe"), None)
        # 这一段要查本机真实安装情况，先把前面几段装上去的假件全部换回真的
        _tc.find_gdb = real_find
        _tc.scan, _tc.probe_version = real_scan, real_probe
        esp_gdb = _tc.find_gdb(family="xtensa-esp-elf")   # 本机没装则 ok=False，跳过
        if esp_gdb.get("ok"):
            rr = _tc.run_tool(esp_gdb["path"], args="--version", timeout=30)
            check("F10 find_gdb 选出的 gdb 真能被 run_tool 跑起来（不是白名单误伤）",
                  rr.get("ok") is True and "gdb" in (rr.get("stdout") or "").lower(),
                  {k: rr.get(k) for k in ("ok", "error", "path", "stdout")})

        # probe_version：退出码 0 但根本没跑起来，必须判成不可用
        _tc.probe_version = real_probe   # 先换回真探针，再假掉它的 subprocess
        class _P(object):
            stdout = b"Python path configuration:\n"
            stderr = b""

        _tc.subprocess = type("S", (), {"run": staticmethod(lambda *a, **k: _P())})
        _tc._VER_CACHE.clear()
        pv = _tc.probe_version(r"C:\fake\xxx-gdb.exe", refresh=True)
        check("F11 退出码 0 但输出命中运行期失败特征 → 判不可用",
              pv.get("ok") is False and pv.get("broken") is True, pv)
    finally:
        _tc.scan, _tc.probe_version = real_scan, real_probe
        _tc.subprocess, _tc.find_gdb = real_sub, real_find



# ======================================================================
def main():
    print("=" * 72)
    print("批次36 mock 测试：非 MDK 芯片调试族（工具链/档案/OpenOCD/trace）")
    print("=" * 72)
    mock = MOC.MockOpenOCD()
    sess = MOC.attach(mock)
    server = create_server(host="127.0.0.1", port=mock.port, idle_timeout=5.0,
                           uv4_path=None, default_project=REAL_PROJ,
                           axf_path=REAL_AXF if os.path.isfile(REAL_AXF) else None)
    try:
        print("\n-- A 工具链族 --")
        test_toolchain(server)
        print("\n-- B 目标档案 --")
        test_targets(server)
        print("\n-- C OpenOCD --")
        test_ocd(server, mock)
        print("\n-- D trace --")
        test_trace(server, mock)
        print("\n-- E 工具面 --")
        test_surface(server)
        print("\n-- F gdb 解析（ESP 复核）--")
        test_gdb_pick(server)
    finally:
        MOC.detach(sess, mock)
        shutil.rmtree(TMPROOT, ignore_errors=True)

    print("\n" + "=" * 72)
    # 汇总格式与其它批次保持一致（闸门靠「通过 N 失败 M」解析；
    # 写成 PASS/FAIL 风格会被闸门当成无法解析而退化成全文计数，误报失败）
    print("通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
