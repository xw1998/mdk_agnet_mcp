# -*- coding: utf-8 -*-
"""批次15 mock 测试：第 3 轮反馈中的 3 项可离线验证的改动。

真机实测（F401 + Keil UVSOCK）发现的规律：
A) run_timeout/stop 之后**首次**读到的 PC 常是上一次 halt 的残留值（LR/SP 已是新值），
   旧实现用"PC 落在 FLASH 段(0x08000000~0x081FFFFF)即认可"的启发式，挡不住这类脏值
   （复位向量 0x0800024c 同样在 FLASH 段内）。现在改为按**读数收敛**判定：
   连续两次 (PC, LR, SP) 完全一致才采纳，并透出 pc_confidence = high/low。
B) build_project/rebuild_project/flash_download/build_and_flash 的 300s 写死超时
   会把大型工程的"还在编译"误判成失败。现暴露 timeout_s（0=默认），默认放宽到
   编译 1800s / 烧录 600s，超时返回 exit_code=-1 并说明。
C) batch 早已支持全部已注册工具（含 disassemble），此处加用例锁住该行为，避免回归。
"""
import os
import re
import sys
import json
import time
import inspect
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug.server import create_server, _get_client  # noqa: E402
from mdkdebug import builder  # noqa: E402

PORT = 14880
PASS, FAIL = [], []
_MDK_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
HAVE_AXF = os.path.isfile(_MDK_AXF)


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))


async def call(server, name, args):
    res = await server.call_tool(name, args)
    return "".join(getattr(c, "text", "") or "" for c in res.content)


def load(r):
    try:
        return json.loads(r)
    except Exception:
        return {}


async def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                               axf_path=_MDK_AXF if HAVE_AXF else None)
        client = _get_client()
        await call(server, "enter_debug", {})

        # ---------- A: PC 采样收敛 ----------
        srv.pc_queue = [0x08000DB4, 0x08000444]     # 首次滞后一帧，随后收敛
        r = client.read_cpu_registers_stable(retries=8, delay=0.01)
        check("A1 PC 首次滞后时仍取到收敛值", r.get("pc") == 0x08000444, str(r)[:220])
        check("A2 收敛时标记 stable=true 并给出采样次数",
              r.get("stable") is True and r.get("samples") >= 3, str(r)[:220])

        srv.pc_queue = [0x08000000 + i * 4 for i in range(1, 40)]
        r = client.read_cpu_registers_stable(retries=8, delay=0.01)
        check("A3 PC 持续变化时不冒充稳定（stable=false）", r.get("stable") is False, str(r)[:220])
        check("A4 未收敛时给出可操作 warning", bool(r.get("warning")), str(r)[:220])

        srv.pc_queue = []
        srv.reg_map["__currentPC()"] = 0x08000DB4
        for k in ("PC", "R15"):
            srv.reg_map[k] = 0x08000DB4
        r = client.read_cpu_registers_stable(retries=8, delay=0.01)
        check("A5 PC 稳定时仍正常返回 stable=true",
              r.get("stable") is True and r.get("pc") == 0x08000DB4, str(r)[:220])

        # 运行中：require_stopped 闸门优先（PC 是残留值，直接拒答）
        await call(server, "run", {})
        r = client.read_cpu_registers_stable(require_stopped=True, retries=4, delay=0.01)
        check("A6 目标运行时拒答且说明 PC 不可信",
              r.get("ok") is False and r.get("target_running") is True, str(r)[:220])
        await call(server, "stop", {})
        time.sleep(0.3)

        # ---------- A7/A8: pc_confidence 透出到停靠位置 ----------
        srv.pc_queue = []
        d = load(await call(server, "get_current_location", {}))
        check("A7 get_current_location 透出 pc_confidence",
              d.get("pc_confidence") in ("high", "low"), str(d)[:220])

        srv.pc_queue = [0x08000000 + i * 4 for i in range(1, 60)]
        d = load(await call(server, "get_current_location", {}))
        check("A8 未收敛时 pc_confidence=low 且带 pc_warning",
              d.get("pc_confidence") == "low" and bool(d.get("pc_warning")), str(d)[:260])
        srv.pc_queue = []

        d = load(await call(server, "run_timeout", {"timeout_ms": 80}))
        check("A9 run_timeout 也透出 pc_confidence",
              d.get("pc_confidence") in ("high", "low"), str(d)[:260])

        # ---------- B: 编译/烧录超时可配 ----------
        tools = {t.name: t for t in await server.list_tools()}
        for n in ("build_project", "rebuild_project", "flash_download", "build_and_flash"):
            props = ((getattr(tools.get(n), "input_schema", None)
                  or getattr(tools.get(n), "inputSchema", None) or {}).get("properties", {})
                 if tools.get(n) else {})
            check("B1 %s 暴露 timeout_s 参数" % n, "timeout_s" in props, str(list(props)))
        check("B2 默认构建超时放宽到 1800s",
              builder.DEFAULT_BUILD_TIMEOUT == 1800, str(builder.DEFAULT_BUILD_TIMEOUT))
        check("B3 默认烧录超时 600s",
              builder.DEFAULT_FLASH_TIMEOUT == 600, str(builder.DEFAULT_FLASH_TIMEOUT))
        check("B4 超时状态文本明确可读",
              "超时" in builder._status_text(-1), builder._status_text(-1))
        # 批次18 起 build_project 末尾多了 ensure_debug_channel 参数，不能再靠
        # __defaults__[-1] 取超时默认值；改为按参数名取（断言语义不变）。
        _bp_sig = inspect.signature(builder.build_project)
        check("B5 build_project 默认超时用常量",
              _bp_sig.parameters["timeout"].default == builder.DEFAULT_BUILD_TIMEOUT,
              str(_bp_sig))
        check("B6 描述里说明了 timeout_s 与超时秒数",
              "timeout_s" in (tools["build_and_flash"].description or "")
              and "1800" in (tools["build_and_flash"].description or ""),
              (tools["build_and_flash"].description or "")[:160])

        # ---------- C: batch 支持全部已注册工具 ----------
        print("  [INFO] 工具总数 %d，含【参数】提示 %d" % (
            len(tools), sum(1 for t in tools.values() if "【参数】" in (t.description or ""))))
        print("  [INFO] 缺【参数】的工具: %s" % [
            n for n, t in tools.items() if "【参数】" not in (t.description or "")])
        d = load(await call(server, "batch", {"commands": [
            {"tool": "disassemble", "args": {"addr": "main", "count": 3}},
            {"tool": "read_mem", "args": {"addr": "0x20000000", "n_bytes": 4}},
        ]}))
        it = (d.get("results") or [{}])[0]
        check("C1 batch 支持 disassemble", it.get("ok") is True, str(it)[:260])
        check("C2 batch 内 disassemble 返回指令序列",
              len(it.get("instructions") or []) == 3, str(it)[:200])
        check("C3 batch 描述说明支持全部工具",
              "全部工具都支持" in (tools["batch"].description or ""),
              (tools["batch"].description or "")[:200])

        d = load(await call(server, "batch", {"commands": [
            {"tool": "disassemble", "args": {"addr": "main"}},
        ]}))
        check("C4 batch 内 disassemble 省略 count 走默认 8",
              (d.get("results") or [{}])[0].get("count") == 8, str(d)[:200])

        # ---------- 文档语义（挂停冻结） ----------
        run_desc = tools["run"].description or ""
        check("D1 run 描述说明 halt 式调试会冻结外设现象",
              "停滞" in run_desc and "自由运行" in run_desc, run_desc[:200])
        check("D2 read_registers 描述说明采样收敛与 stable 标记",
              "stable" in (tools["read_registers"].description or ""),
              (tools["read_registers"].description or "")[:200])

        await call(server, "stop", {})
        await call(server, "exit_debug", {})
    finally:
        try:
            srv.stop()
        except Exception:  # noqa: BLE001
            pass

    print("\n批次15 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
