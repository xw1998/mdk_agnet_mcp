# -*- coding: utf-8 -*-
"""批次21 mock 测试：Keil「调试前更新目标」识别，避免多余的显式烧录。

背景（用户实测经验）：Keil 点 Debug 进调试时会自动把最新程序下载进 Flash，不必先烧录再 Debug。
工程文件证据：<Utilities><Flash1><UpdateFlashBeforeDebugging>1</UpdateFlashBeforeDebugging>。

覆盖：
  A 工程解析：update_flash_before_debugging 取 1/0/缺失 → true/false/None
  B flash_debug 自动选路：勾选时只编译（Keil 进调试时自动下载），未勾选时才显式烧录
  C 返回结构与文案：flash_plan / flash_note / build / flash 字段
  D 工具描述口径：enter_debug / flash_debug / read_project_config 均说明该机制

运行：python -m tests.test_batch21
"""
import sys, os, json, time, asyncio, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

# 批次42 起工具面默认精简（只暴露 core 组），本批校验的是**全量**工具面里的 flash_debug
# 等工具，必须显式要求不裁剪——否则单独跑本文件时 flash_debug 根本不在工具表里。
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from tests.mock_uvsock_server import MockUVSOCKServer
from mdkdebug.server import create_server, _get_client, _parse_uvprojx_config, _builder_cfg
from mdkdebug import builder

PORT = 14893
PASS, FAIL = [], []

UVPROJ_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<Project>
  <Targets>
    <Target>
      <TargetName>t1</TargetName>
      <uAC6>0</uAC6>
      <TargetOption>
        <TargetCommonOption>
          <Cads>
            <Optim>2</Optim>
            <VariousControls><Define>A,B</Define><IncludePath>inc</IncludePath></VariousControls>
          </Cads>
        </TargetCommonOption>
        <Utilities>
          <Flash1>%s</Flash1>
        </Utilities>
      </TargetOption>
    </Target>
  </Targets>
</Project>
"""

# 临时工程一律放进**专用子目录**：直接往系统临时目录根扔 .uvprojx 会污染其它测试
# （test_batch36 的 A8「认不出就说 none」会向上层目录找工程文件证据），并发跑时随机失败。
TMPDIR = tempfile.mkdtemp(prefix="mdkdebug_b21_")

def make_project(flag):
    """生成临时 .uvprojx；flag 为 '1' / '0' / None（不含该节点）。"""
    inner = "" if flag is None else ("<UpdateFlashBeforeDebugging>%s</UpdateFlashBeforeDebugging>" % flag)
    fd, path = tempfile.mkstemp(dir=TMPDIR, suffix=".uvprojx")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(UVPROJ_TMPL % inner)
    return path

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail), flush=True)

async def call(server, name, args):
    res = await server.call_tool(name, args)
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}

async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0)
    _builder_cfg["uv4"] = r"C:\fake\UV4.exe"   # 本测试全部打桩，不真的调 UV4

    p_on, p_off, p_none = make_project("1"), make_project("0"), make_project(None)

    # ============ A. 工程解析 ============
    a1 = _parse_uvprojx_config(p_on)
    a2 = _parse_uvprojx_config(p_off)
    a3 = _parse_uvprojx_config(p_none)
    check("A1 UpdateFlashBeforeDebugging=1 -> true",
          (a1.get("current") or {}).get("update_flash_before_debugging") is True, str(a1)[:240])
    check("A2 =0 -> false",
          (a2.get("current") or {}).get("update_flash_before_debugging") is False, str(a2)[:240])
    check("A3 缺失 -> None（不臆断）",
          (a3.get("current") or {}).get("update_flash_before_debugging") is None, str(a3)[:240])
    check("A4 原有字段不受影响（宏/优化/包含路径）",
          (a1.get("current") or {}).get("defines") == ["A", "B"]
          and (a1.get("current") or {}).get("optimization") == "2", str(a1)[:240])

    # ============ B. flash_debug 自动选路 ============
    calls = []
    real = {"close": builder.close_uvision, "build": builder.build_project,
            "bf": builder.build_and_flash, "launch": builder.launch_uvision}
    builder.close_uvision = lambda force=True: (calls.append("close"),
                                                {"ok": True, "closed": []})[1]
    builder.build_project = lambda uv4, proj, target=None, *a, **k: (
        calls.append("build"), {"ok": True, "action": "编译", "exit_code": 0})[1]
    builder.build_and_flash = lambda uv4, proj, target=None, *a, **k: (
        calls.append("build_and_flash"),
        {"ok": True, "action": "编译并烧录", "build": {"ok": True}, "flash": {"ok": True}})[1]
    builder.launch_uvision = lambda uv4, proj="": (calls.append("launch"),
                                                   {"ok": True, "pid": 1})[1]
    try:
        calls.clear()
        r1 = await call(server, "flash_debug", {"project": p_on})
        check("B1 勾选工程：只编译，不显式烧录（Keil 进调试时自动下载）",
              "build" in calls and "build_and_flash" not in calls, str(calls)[:200])
        check("B2 flash_plan 标为 debug_download",
              r1.get("flash_plan") == "debug_download", str(r1)[:240])
        check("B3 该路径下 flash 阶段为空（无显式烧录结果）",
              r1.get("flash") is None, str(r1)[:240])
        check("B4 仍完成关Keil→开新→进调试闭环",
              r1.get("ok") is True and r1.get("stage") == "调试"
              and "close" in calls and "launch" in calls, str(r1)[:260])
        check("B5 附 flash_note 说明「未显式烧录」的原因",
              "自动下载" in str(r1.get("flash_note") or ""), str(r1.get("flash_note"))[:200])

        calls.clear()
        r2 = await call(server, "flash_debug", {"project": p_off})
        check("B6 未勾选工程：退回显式 UV4 -f 烧录",
              "build_and_flash" in calls, str(calls)[:200])
        check("B7 flash_plan 标为 explicit_flash",
              r2.get("flash_plan") == "explicit_flash", str(r2)[:240])
        check("B8 显式路径保留 build/flash 两段结果",
              bool(r2.get("build")) and bool(r2.get("flash")), str(r2)[:240])

        # 编译失败时不重开工程、不进调试
        builder.build_project = lambda uv4, proj, target=None, *a, **k: (
            calls.append("build"), {"ok": False, "exit_code": 2, "output": "err"})[1]
        calls.clear()
        r3 = await call(server, "flash_debug", {"project": p_on})
        check("B9 编译失败：不重开工程、不进调试",
              r3.get("ok") is False and "launch" not in calls, str(r3)[:240])
        check("B10 失败时同样带 flash_plan 便于定位",
              r3.get("flash_plan") == "debug_download", str(r3)[:240])
    finally:
        builder.close_uvision = real["close"]
        builder.build_project = real["build"]
        builder.build_and_flash = real["bf"]
        builder.launch_uvision = real["launch"]

    # ============ C. 工具层描述口径 ============
    tools = await server.list_tools()
    tmap = {t.name: (t.description or "") for t in tools}
    check("C1 enter_debug 描述说明「进调试会自动下载程序」的副作用",
          "Update Target before Debugging" in tmap.get("enter_debug", "")
          and "自动" in tmap.get("enter_debug", ""), tmap.get("enter_debug", "")[:200])
    check("C2 enter_debug 描述给出可查字段 read_project_config",
          "read_project_config" in tmap.get("enter_debug", ""), tmap.get("enter_debug", "")[:200])
    check("C3 flash_debug 描述说明自动选路与 flash_plan",
          "debug_download" in tmap.get("flash_debug", "")
          and "explicit_flash" in tmap.get("flash_debug", ""), tmap.get("flash_debug", "")[:200])
    check("C4 read_project_config 描述包含 update_flash_before_debugging",
          "update_flash_before_debugging" in tmap.get("read_project_config", ""),
          tmap.get("read_project_config", "")[:200])

    for f in (p_on, p_off, p_none):
        try:
            os.remove(f)
        except OSError:
            pass
    srv.stop()

    print("\n==== batch21: %d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：" + ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    _rc = asyncio.run(main())
    shutil.rmtree(TMPDIR, ignore_errors=True)
    sys.exit(_rc)
