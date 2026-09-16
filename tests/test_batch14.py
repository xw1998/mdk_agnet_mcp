# -*- coding: utf-8 -*-
"""批次14 mock 测试：真机验证中发现的 A/B 两个问题的修复。

真机发现（F401 + Keil UVSOCK）：
A) enter_debug 是**异步**的：命令返回 status=0 后约 0.6~0.7s 才真正进入调试态，
   期间 read_mem/calc_expression/BS 等一律返回 status=6（Target is not in debug mode）。
   真机表现为"enter_debug 成功但紧接着读内存报未处于调试状态"。
B) BS 命令成功时真机可能返回 status=22（断点已创建）而非 0，旧代码按 ==0 判定,
   于是 ok=False、断点被当成没设上（真机上还会带一段二进制断点结构，被解码成乱码 output）。

修复：
- client.enter_debug 成功后轮询 get_status 直到 debugging 为真（wait_debugging，默认 6s），
  返回 ready/ready_waited_ms；超时则给出 warning（不假装成功）。
- 协议层加"请求-响应"配对：响应帧 r_cmd 必须等于请求命令码，不匹配的陈旧帧丢弃
  （MAX_STALE_FRAMES=64 兜底），根治"拿到上一条命令的响应"造成的错位。
- set_breakpoint/clear_breakpoint 把断点类返回码（20/21/22/23，BK 另加 24）归一化为成功。
- exec_command 响应的二进制 payload 走 output_hex，不再 decode 成乱码文本。
"""
import os
import sys
import json
import time
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.server import create_server, _get_client  # noqa: E402
from mdkdebug.client import UVClient  # noqa: E402

PORT = 14878
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

        # ---------- A: enter_debug 异步就绪 ----------
        srv.enter_ready_delay = 3        # 前 3 次 STATUS 仍报"未处于调试状态"
        r = await call(server, "enter_debug", {})
        d = load(r)
        check("A1 enter_debug 返回成功", d.get("ok") is True, r[:200])
        check("A2 自动等待到真正进入调试态", d.get("ready") is True, r[:200])
        check("A3 回填等待耗时 ready_waited_ms",
              isinstance(d.get("ready_waited_ms"), int), r[:200])
        check("A4 正常就绪时不给 warning", not d.get("warning"), r[:200])

        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
        d = load(r)
        check("A5 就绪后 read_mem 立即可用（不再 status=6）",
              d.get("ok") is True and d.get("data_hex") == "44332211", r[:200])

        # 超时场景：目标始终不就绪 -> ready=False + warning，且不超时很久
        await call(server, "exit_debug", {})
        srv.enter_ready_delay = 0
        srv._enter_pending = 0
        srv.enter_ready_delay = 10000
        t0 = time.time()
        d = client.enter_debug(wait_ready=0.6)
        dt = time.time() - t0
        check("A6 未就绪时 ready=False 且给 warning",
              d.get("ok") is True and d.get("ready") is False and bool(d.get("warning")),
              json.dumps(d, ensure_ascii=False)[:250])
        check("A7 等待时间受 wait_ready 约束", dt < 2.5, "%.2fs" % dt)

        # 恢复并重新进入调试态
        srv.enter_ready_delay = 0
        srv._enter_pending = 0
        d = load(await call(server, "enter_debug", {}))
        check("A8 恢复后能正常进入调试态", d.get("ready") is True, str(d)[:200])

        # ---------- B: 响应帧配对（陈旧响应不再错位） ----------
        srv.stale_frames = 2                  # 下一个响应前先塞 2 个陈旧帧
        r = await call(server, "read_mem", {"addr": "0x20000000", "n_bytes": 4})
        d = load(r)
        check("B1 丢弃 2 个陈旧响应帧后取到正确数据",
              d.get("ok") is True and d.get("data_hex") == "44332211", r[:250])

        srv.stale_frames = 3
        r = await call(server, "read_mem", {"addr": "0x20000004", "n_bytes": 4})
        d = load(r)
        check("B2 丢弃 3 个陈旧响应帧后取到正确数据",
              d.get("ok") is True and d.get("data_hex") == "efbeadde", r[:250])

        # ---------- B: 断点命令返回码归一化 ----------
        srv.bs_status = 22                    # 真机 BS 成功返回 BP_CREATED
        srv.bs_binary_output = True           # 且响应带二进制断点结构
        r = await call(server, "set_breakpoint", {"expr": "main"})
        d = load(r)
        check("B4 BS 返回 22(BP_CREATED) 视为成功", d.get("ok") is True, r[:250])
        check("B5 归一化时说明返回码", "视为成功" in str(d.get("note", "")), r[:250])
        check("B6 断点 id 仍正常回填", bool(d.get("breakpoint_id")), r[:250])
        check("B7 二进制响应给 output_hex 而非乱码 output",
              "output_hex" in d and "output" not in d, r[:250])

        srv.bs_status = None
        srv.bs_binary_output = False
        r = await call(server, "set_breakpoint", {"expr": "main"})
        d = load(r)
        check("B8 返回码为 0 时行为不变", d.get("ok") is True, r[:250])

        r = await call(server, "clear_breakpoint", {"expr": "main"})
        check("B9 clear_breakpoint 正常成功", load(r).get("ok") is True, r[:250])

        for code, name in ((20, "BP_DISABLED"), (21, "BP_ENABLED"),
                           (22, "BP_CREATED"), (23, "BP_DELETED")):
            n = UVClient._norm_bp_result({"ok": False, "status": code, "status_text": name})
            check("B10 set 归一化 %s(%d)" % (name, code), n.get("ok") is True, str(n)[:150])
        n = UVClient._norm_bp_result({"ok": False, "status": 24, "status_text": "断点未找到"},
                                     extra_ok=(24,))
        check("B11 BK 的 24(BP_NOTFOUND) 也视为成功", n.get("ok") is True, str(n)[:150])
        n = UVClient._norm_bp_result({"ok": False, "status": 6, "status_text": "未处于调试状态"})
        check("B12 非断点类返回码不被误归一化", n.get("ok") is False, str(n)[:150])

        # ---------- B3: 陈旧帧超上限时不挂死（放最后：极端场景会让 socket 持续残留） ----------
        srv.stale_frames = 70                 # 超过 MAX_STALE_FRAMES(64) 上限
        t0 = time.time()
        load(await call(server, "get_status", {}))
        dt = time.time() - t0
        check("B3 陈旧帧超上限时不挂死（有兜底）", dt < 5.0, "%.2fs" % dt)

        srv.stale_frames = 0
        return_value = (len(PASS), len(FAIL))
    finally:
        try:
            srv.stop()
        except Exception:  # noqa: BLE001
            pass

    print("\n批次14 mock: %d 通过, %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
