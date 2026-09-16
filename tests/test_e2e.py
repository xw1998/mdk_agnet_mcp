# -*- coding: utf-8 -*-
"""端到端联调测试：启动 mock UVSOCK 服务器，用 UVClient 全量调用各调试工具。"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.mock_uvsock_server import MockUVSOCKServer  # noqa: E402
from mdkdebug.client import UVClient  # noqa: E402

PORT = 14823  # 用非常用端口避免与真实 Keil 冲突
PASS = []
FAIL = []


def check(name, ok, detail=""):
    if ok:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}  {detail}")


def main():
    srv = MockUVSOCKServer("127.0.0.1", PORT).start()
    time.sleep(0.2)
    try:
        client = UVClient(host="127.0.0.1", port=PORT, idle_timeout=1.0)

        # 1. 版本
        r = client.get_version()
        check("get_version", r["ok"] and r["version_hex"] != "", r)

        # 2. 状态（未运行）
        r = client.get_status()
        check("get_status(stop)", r["ok"] and not r["running"], r)

        # 3. 读表达式 / 变量
        r = client.calc_expression("v0")
        check("calc_expression v0", r["ok"] and r["value"] == 0x11223344, r)
        r = client.calc_expression("v2")
        check("calc_expression v2(float)", r["ok"] and abs(r["value"] - 3.14) < 0.01, r)
        r = client.calc_expression("no_such_var")
        check("calc_expression 未知变量报错", (not r["ok"]), r)

        # 4. 读内存
        r = client.read_mem(0x20000000, 8)
        check("read_mem 8B", r["ok"] and len(bytes.fromhex(r["data_hex"])) == 8, r)

        # 5. 写内存
        r = client.write_mem(0x20001000, bytes.fromhex("deadbeefcafef00d"))
        check("write_mem", r["ok"] and r["written"] == 8, r)
        r = client.read_mem(0x20001000, 8)
        check("write->read 回读一致",
              r["ok"] and r["data_hex"] == "deadbeefcafef00d", r)

        # 6. 运行控制
        r = client.run()
        check("run", r["ok"], r)
        r = client.get_status()
        check("run 后状态 running", r["ok"] and r["running"], r)
        r = client.stop()
        check("stop", r["ok"], r)
        r = client.reset()
        check("reset", r["ok"], r)
        r = client.step("into")
        check("step into", r["ok"], r)
        r = client.step("badmode")
        check("step 非法模式报错", not r["ok"], r)

        # 6b. 进出 debug 模式
        r = client.enter_debug()
        check("enter_debug", r["ok"], r)
        r = client.exit_debug()
        check("exit_debug", r["ok"], r)

        # 6c. 断点管理（命令窗口 BS/BK/BL）
        r = client.set_breakpoint("main")
        check("set_breakpoint main", r["ok"], r)
        r = client.set_breakpoint("main")
        check("set_breakpoint 重复设置", r["ok"], r)
        r = client.list_breakpoints()
        check("list_breakpoints(BL)", r["ok"], r)
        blout = client.read_console_output(clear=True)
        check("BL 输出读到 main(命令窗口闭环)",
              any("main" in (m.get("text") or "") for m in blout), blout)
        r = client.clear_breakpoint("main")
        check("clear_breakpoint main", r["ok"], r)
        r = client.list_breakpoints()
        check("list_breakpoints(BL) 清空后", r["ok"], r)
        r = client.exec_command("badcmd")
        check("exec_command 非法命令报错", not r["ok"], r)
        r = client.exec_command("BS main\nBS foo")
        check("exec_command 含换行被拒", not r["ok"], r)

        # 7. 连接缓存：空闲超时自动断开并重连
        print("  ... 等待 idle_timeout(1s) 让连接自动断开 ...")
        time.sleep(1.5)
        r = client.get_version()
        check("空闲超时后自动重连", r["ok"], r)

        client.close()
        check("close 正常", True)

    finally:
        srv.stop()

    print("\n======== 结果 ========")
    print(f"通过 {len(PASS)} 项, 失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)
    print("全部通过 ✔")


if __name__ == "__main__":
    main()
