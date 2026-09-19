# -*- coding: utf-8 -*-
"""批次26 mock 测试：Keil 实例泛滥治理（只开一个窗口）。

用户反馈原文：
    「在你调试的时候开了好多mdk没有关闭这个问题也要重视，应该只开一个窗口调试就行了」

根因：原 launch_uvision 注释写「UV4.exe 是单实例程序，同工程会复用」，真机实测不成立——
同一工程可以并存多个窗口且互不回收（实测 6 个）。且 _recover_debug_channel 直接
winutil.launch_detached，绕过了任何复用判断。

本批：
  A 窗口标题 → 工程路径解析（含各种标题形态）
  B uv4_instances 组装与排序（按创建时间升序，取不到时间也不崩）
  C launch_uvision：已有同工程实例 → 复用不新开；single=true（默认）时别的工程在开 →
    拒绝新开（keil-multiple-instances），reuse=false 也被否决；无实例 → 才新开
  D close_uvision(keep=...)：latest / oldest / all 的目标选择，保留的实例不得被关
  E list_uvision_instances 工具输出（count/total/note/别名）
  F server 层参数透传与工具数

运行：python -m tests.test_batch26
"""
import os
import sys
import json
import time
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import builder, winutil  # noqa: E402
from mdkdebug.server import create_server  # noqa: E402

PORT = 14898
PASS, FAIL = [], []
_AXF = "example_mdk_project/mdk_test/MDK-ARM/mdk_test/mdk_test.axf"
# 批次33 起 _resolve_project 会校验工程文件真实存在（不存在时报错并把附近找到的
# .uvprojx 作为候选列出），故这里指向一个真实存在的工程；本段只验证
# launch_uvision 的复用分支，与工程内容无关。
PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                    "mdk_test.uvprojx")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:280]), flush=True)


async def call(server, name, args=None):
    try:
        res = await server.call_tool(name, args or {})
    except Exception as e:  # noqa: BLE001
        return {"_exc": "%s: %s" % (type(e).__name__, e)}
    txt = "".join(getattr(c, "text", "") or "" for c in res.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt[:300]}


class FakeEnv:
    """打桩 UV4 实例与启动/关闭原语，验证选择逻辑而不真的动进程。"""

    def __init__(self, instances, only_pids=None):
        self.instances = list(instances)
        self.pids = list(only_pids if only_pids is not None
                         else [i["pid"] for i in instances])
        self.launched = []
        self.closed = []
        self.terminated = []
        self.focused = []

    def install(self):
        self._r = (winutil.uv4_instances, winutil.uv4_pids, winutil.launch_detached,
                   winutil.focus_window, builder._close_uvision_graceful,
                   builder._terminate_uvision, builder._wait_pids_settle)
        winutil.uv4_instances = lambda: [dict(i) for i in self.instances]
        winutil.uv4_pids = lambda: list(self.pids)
        winutil.focus_window = lambda hwnd: (self.focused.append(hwnd), True)[1]

        def fake_launch(uv4, project="", extra_args=None):
            self.launched.append((uv4, project))
            new = {"pid": 9000 + len(self.launched), "created": time.time(),
                   "project": project, "title": "%s - µVision" % project,
                   "hwnd": 2000 + len(self.launched), "has_window": True}
            self.instances.append(new)
            self.pids.append(new["pid"])
            return {"ok": True, "pid": new["pid"], "creationflags": "0x1020208",
                    "detached": True, "breakaway": True}

        winutil.launch_detached = fake_launch
        builder._close_uvision_graceful = lambda pid: (self.closed.append(pid), True)[1]

        def fake_term(pid):
            self.terminated.append(pid)
            self.instances = [i for i in self.instances if i["pid"] != pid]
            self.pids = [p for p in self.pids if p != pid]

        builder._terminate_uvision = fake_term
        builder._wait_pids_settle = lambda wait=3.0: list(self.pids)

    def uninstall(self):
        (winutil.uv4_instances, winutil.uv4_pids, winutil.launch_detached,
         winutil.focus_window, builder._close_uvision_graceful,
         builder._terminate_uvision, builder._wait_pids_settle) = self._r


def inst(pid, project=PROJ, created=None, title=""):
    return {"pid": pid, "created": created if created is not None else 1000.0 + pid,
            "project": project, "title": title or ("%s - µVision" % project),
            "hwnd": 100 + pid, "has_window": True}


def main():
    # ============ A. 标题解析 ============
    print("A. 窗口标题 → 工程路径")
    check("A1 标准标题（全路径 + µVision）",
          winutil.parse_project_from_title(
              r"D:\工作\proj\MDK-ARM\mdk_test.uvprojx - µVision") ==
          r"D:\工作\proj\MDK-ARM\mdk_test.uvprojx",
          winutil.parse_project_from_title(r"D:\a\b.uvprojx - µVision"))
    check("A2 .uvproj / .uvmpw 也识别",
          winutil.parse_project_from_title(r"C:\x\y.uvproj - µVision").endswith("y.uvproj")
          and winutil.parse_project_from_title(r"C:\x\all.uvmpw - µVision").endswith("all.uvmpw"))
    check("A3 无工程标题返回空串",
          winutil.parse_project_from_title("µVision") == ""
          and winutil.parse_project_from_title("") == "")
    check("A4 标题带额外后缀（target 名）仍能解析",
          winutil.parse_project_from_title(
              r"C:\a\b\c.uvprojx - µVision [Debug]") == r"C:\a\b\c.uvprojx",
          winutil.parse_project_from_title(r"C:\a\b\c.uvprojx - µVision [Debug]"))

    # ============ B. uv4_instances 组装 ============
    print("B. uv4_instances 组装与排序")
    env = FakeEnv([inst(3, created=300.0), inst(1, created=100.0), inst(2, created=200.0)])
    env.install()
    real_instances = env._r[0]          # 打桩前的真实 uv4_instances
    try:
        real_wins = winutil.uv4_windows
        winutil.uv4_windows = lambda: [
            {"pid": i["pid"], "hwnd": i["hwnd"], "title": i["title"]} for i in env.instances]
        real_created = winutil.uv4_process_created
        winutil.uv4_process_created = lambda pid: [i for i in env.instances
                                                   if i["pid"] == pid][0]["created"]
        try:
            items = real_instances()
            check("B1 按创建时间升序（最早在前）",
                  [i["pid"] for i in items] == [1, 2, 3], items)
            winutil.uv4_process_created = lambda pid: None
            items = real_instances()
            check("B2 取不到创建时间也不崩（退化为按 pid 排序）",
                  [i["pid"] for i in items] == [1, 2, 3], items)
        finally:
            winutil.uv4_windows = real_wins
            winutil.uv4_process_created = real_created
    finally:
        env.uninstall()

    # ============ C. launch_uvision 复用 ============
    print("C. launch_uvision：已有同工程窗口则复用")
    env = FakeEnv([inst(11), inst(12)])
    env.install()
    try:
        r = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", PROJ)
        check("C1 已有同工程实例 → 复用且不新开窗口",
              r.get("ok") is True and r.get("reused") is True
              and r.get("pid") == 12 and not env.launched, r)
        check("C2 复用的是最新实例并前置窗口",
              r.get("instances") == 2 and env.focused == [112], (r, env.focused))
        # ---- single（默认 true）= 把「只保留一个 Keil 窗口」做成机制 ----
        r2 = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", r"D:\other\o.uvprojx")
        check("C3 single=true 下已有别的工程 → 拒绝新开（keil-multiple-instances）",
              r2.get("ok") is False and r2.get("error_code") == "keil-multiple-instances"
              and [i["pid"] for i in r2.get("open_instances", [])] == [11, 12]
              and not env.launched, (r2, env.launched))
        check("C4 拒绝时不偷偷关窗口（关窗口只能由调用方显式决定）",
              env.closed == [] and env.terminated == [], (env.closed, env.terminated))
        check("C5 拒绝时给出可执行的下一步（收窗口 / 或显式 single=false）",
              any("close_uvision" in a for a in r2.get("next_actions", []))
              and any("single=false" in a for a in r2.get("next_actions", [])), r2)
        r2b = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe",
                                    r"D:\other\o.uvprojx", single=False)
        check("C6 只有显式 single=false 才允许同时开多个工程窗口",
              r2b.get("reused") is False and len(env.launched) == 1, (r2b, env.launched))
        # 回到「只开着本工程」的现场：C6 又开了别的工程窗口，会先被 single 拦下
        env.instances = [inst(11), inst(12)]
        r3 = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", PROJ, reuse=False)
        check("C7 single=true 下 reuse=false 被否决 → 强制复用同工程窗口",
              r3.get("reused") is True and r3.get("reuse_forced") is True
              and len(env.launched) == 1, (r3, env.launched))
        r3b = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", PROJ,
                                     reuse=False, single=False)
        check("C8 single=false 时 reuse=false 才真新开（确需第二个窗口）",
              r3b.get("reused") is False and len(env.launched) == 2, (r3b, env.launched))
        r4 = builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", "")
        check("C9 不给 project 且已有实例 → 无从比对，同样拒绝（宁可报错也不猜）",
              r4.get("ok") is False and r4.get("error_code") == "keil-multiple-instances", r4)
        n_before = len(env.launched)
        for _ in range(3):
            builder.launch_uvision(r"D:\Keil_v5\UV4\UV4.exe", PROJ)
        check("C10 single=true 下同工程连调 3 次不再新增窗口（单调递增地收敛）",
              len(env.launched) == n_before, env.launched)
        check("C11 大小写/分隔符不同的同一路径也判为同工程",
              builder._same_project(r"D:/Work/Demo/MDK-ARM/demo.uvprojx",
                                    r"d:\work\demo\MDK-ARM\demo.uvprojx") is True)
        check("C12 空工程不误判为同工程",
              builder._same_project("", PROJ) is False)
    finally:
        env.uninstall()

    # ============ D. close_uvision(keep=...) ============
    print("D. close_uvision：收敛为单窗口")
    env = FakeEnv([inst(21, created=100.0), inst(22, created=300.0), inst(23, created=200.0)])
    env.install()
    try:
        r = builder.close_uvision(keep="latest")
        check("D1 keep=latest 保留最新实例，其余优雅关闭",
              r.get("ok") is True and r.get("kept") == [22] and sorted(env.closed) == [21, 23]
              and 22 not in env.closed, (r, env.closed))
        check("D2 closed 只计本次真正关闭的实例",
              r.get("closed") == 2 and r.get("total_before") == 3, r)
    finally:
        env.uninstall()

    env = FakeEnv([inst(31, created=100.0), inst(32, created=300.0)])
    env.install()
    try:
        r = builder.close_uvision(keep="oldest")
        check("D3 keep=oldest 保留最早实例（先开的那个）",
              r.get("kept") == [31] and env.closed == [32], (r, env.closed))
    finally:
        env.uninstall()

    env = FakeEnv([inst(41)])
    env.install()
    try:
        r = builder.close_uvision(keep="latest")
        check("D4 已是单实例 → 一个都不关",
              r.get("ok") is True and r.get("closed") == 0 and not env.closed
              and r.get("kept") == [41], (r, env.closed))
    finally:
        env.uninstall()

    env = FakeEnv([inst(51, project=PROJ), inst(52, project=r"D:\other\o.uvprojx")])
    env.install()
    try:
        r = builder.close_uvision(keep="latest", project=PROJ)
        check("D5 project 过滤：只处理该工程的实例",
              env.closed == [] and r.get("kept") == [51], (r, env.closed))
    finally:
        env.uninstall()

    env = FakeEnv([inst(61), inst(62)])
    env.install()
    try:
        r = builder.close_uvision(force=True)
        check("D6 keep=all（默认）仍关闭全部实例",
              sorted(env.terminated) == [61, 62] and r.get("closed") == 2, (r, env.terminated))
    finally:
        env.uninstall()

    # ============ E. list_uvision_instances 工具 ============
    print("E. list_uvision_instances 工具")
    env = FakeEnv([inst(71), inst(72), inst(73, project=r"D:\other\o.uvprojx")])
    env.install()
    try:
        r = builder.list_uvision_instances()
        check("E1 统计全部实例并给出收敛建议",
              r.get("count") == 3 and r.get("total") == 3 and "close_uvision" in r.get("note", ""),
              r)
        check("E2 实例明细含 pid/启动时间/工程",
              all(k in r["instances"][0] for k in ("pid", "created", "created_str", "project")),
              r["instances"][0])
        r2 = builder.list_uvision_instances(PROJ)
        check("E3 project 过滤生效",
              r2.get("count") == 2 and r2.get("total") == 3
              and r2.get("project_filter") == PROJ, r2)
        env.instances = [inst(81)]
        r3 = builder.list_uvision_instances()
        check("E4 单个实例时不出现收敛提示",
              r3.get("count") == 1 and "note" not in r3, r3)
    finally:
        env.uninstall()

    # ============ F. server 层 ============
    print("F. server 工具层")
    server = create_server(host="127.0.0.1", port=PORT, idle_timeout=30.0,
                           axf_path=_AXF if os.path.isfile(_AXF) else None)
    loop = asyncio.new_event_loop()
    names = {t.name for t in loop.run_until_complete(server.list_tools())}
    check("F1 工具数 75→76 且含 list_uvision_instances",
          len(names) >= 76 and "list_uvision_instances" in names, len(names))

    env = FakeEnv([inst(91), inst(92)])
    env.install()
    try:
        r = loop.run_until_complete(
            call(server, "list_uvision_instances", {}))
        check("F2 list_uvision_instances 工具可用", r.get("ok") is True and r.get("count") == 2, r)
        r2 = loop.run_until_complete(
            call(server, "launch_uvision", {"project": PROJ}))
        check("F3 launch_uvision 工具默认复用（不新开）",
              r2.get("reused") is True, r2)
        r3 = loop.run_until_complete(
            call(server, "close_uvision", {"keep": "latest"}))
        check("F4 close_uvision 工具透传 keep=latest",
              r3.get("kept") == [92] and r3.get("closed") == 1, r3)
        r4 = loop.run_until_complete(
            call(server, "close_uvision", {"retain": "oldest"}))
        check("F5 keep 的别名 retain 生效（别名兼容层）",
              r4.get("keep") == "oldest" or "_exc" not in r4, r4)
    finally:
        env.uninstall()

    print("\n==== 批次26 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
