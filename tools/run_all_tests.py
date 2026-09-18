# -*- coding: utf-8 -*-
"""仓库统一测试闸门：先做一致性检查，再跑各批次 mock 测试并汇总。

用法：
    python tools/run_all_tests.py              # 一致性检查 + 全部测试（默认 4 路并发）
    python tools/run_all_tests.py --fast       # 只跑关键几批（改一两个模块时用，分钟级→十几秒）
    python tools/run_all_tests.py --only test_batch36,test_batch35
    python tools/run_all_tests.py --jobs 1     # 退化成串行（排查并发疑似干扰时用）
    python tools/run_all_tests.py --no-run     # 只做一致性检查（秒级）
    python tools/run_all_tests.py --list       # 只列清单

为什么能并发：每个测试模块自己起 mock 服务器、端口各不相同、临时目录也各自独立。
唯一的例外是**共享守卫端口**的模块（见 EXCLUSIVE_GROUPS），它们会被自动排到串行尾巴上，
免得互相把对方的端口占掉、跑出假失败。

一致性检查（防止"加了工具忘了改断言"这类静默腐烂）：
  1. 以 mdkdebug.server.create_server() 实际注册的工具数为唯一事实来源
  2. 扫描 tests/test_*.py 里写死的工具总数断言，必须都等于实际值
  3. 扫描 README.md 里对工具数的描述，必须等于实际值
  4. 列出 tests/ 下存在但未纳入闸门的模块（信息提示，不判失败）
"""
import asyncio
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 闸门内的测试模块（顺序即执行顺序；新增批次后请加到这里）
BATCHES = [
    "test_e2e", "test_mcp", "test_stdio", "test_unhardcode",
    "test_batch9", "test_batch10", "test_batch13", "test_batch14",
    "test_batch15", "test_batch16", "test_batch18", "test_batch25",
    "test_batch26", "test_batch28", "test_batch29", "test_batch30",
    "test_batch31", "test_batch32", "test_batch33", "test_batch34",
    "test_batch35", "test_batch36", "test_batch37",
    "test_batch38",
    "test_batch39",
]

# --fast：改一两个模块时先跑这几批（覆盖协议层/统一信封/非 MDK 链路），全绿再跑全量
FAST_SET = ["test_e2e", "test_mcp", "test_batch33", "test_batch35", "test_batch36",
            "test_batch37", "test_batch38", "test_batch39"]

# 并发禁区：这些模块共用同一个「守卫端口」，同时跑会互相干扰（真检查过端口占用）：
#   test_batch29 断言 14999 没在监听，test_batch35 的子进程会去 bind 14999
EXCLUSIVE_GROUPS = [["test_batch29", "test_batch35"]]
EXCLUSIVE = {n for g in EXCLUSIVE_GROUPS for n in g}
DEFAULT_JOBS = 4

PATTERNS = [
    re.compile(r"通过\s*(\d+)\s*失败\s*(\d+)"),
    re.compile(r"(\d+)\s*通过\s*/\s*(\d+)\s*失败"),
    re.compile(r"通过\s*[:：]\s*(\d+).{0,20}?失败\s*[:：]\s*(\d+)", re.S),
    re.compile(r"(\d+)\s*(?:passed|pass)\D{0,20}?(\d+)\s*(?:failed|fail)", re.I),
]

README_COUNT_PATTERNS = [
    re.compile(r"与\s*(\d+)\s*个工具定义"),
    re.compile(r"共\s*\*\*(\d+)\*\*\s*个"),
]


def dec(b):
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return (b or b"").decode("utf-8", "replace")


def actual_tool_count():
    """唯一事实来源：真起一个 server 数注册了多少个工具。"""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from mdkdebug import server as srv  # noqa: E402
    server = srv.create_server()
    return len(asyncio.run(server.list_tools()))


def scan_test_counts(n):
    """返回 [(文件, 行号, 行文本, 断言值)]。

    认两种写法：
      • 同一行内同时有『工具数(总)』与 `== N`；
      • 断言标签在上一行、`== N` 在下一行（多行 check 写法）——
        这类最容易被漏掉，正是本检查要防的情况。
    """
    hits = []
    tdir = os.path.join(ROOT, "tests")
    for fn in sorted(os.listdir(tdir)):
        if not (fn.startswith("test_") and fn.endswith(".py")):
            continue
        path = os.path.join(tdir, fn)
        text = dec(open(path, "rb").read())
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            if not re.search(r"工具(?:总|个)?数", line):
                continue
            seg = line if "==" in line else "\n".join(lines[i - 1:i + 2])
            for v in re.findall(r"==\s*(\d+)\b", seg):
                hits.append((fn, i, line.strip(), int(v)))
    return hits


def scan_readme_counts(n=None):
    hits = []
    path = os.path.join(ROOT, "README.md")
    if not os.path.exists(path):
        return hits
    text = dec(open(path, "rb").read())
    for i, line in enumerate(text.splitlines(), 1):
        for pat in README_COUNT_PATTERNS:
            for v in pat.findall(line):
                hits.append(("README.md", i, line.strip(), int(v)))
    return hits


def discover_ungated():
    tdir = os.path.join(ROOT, "tests")
    gated = set(BATCHES)
    out = []
    for fn in sorted(os.listdir(tdir)):
        if fn.startswith("test_") and fn.endswith(".py"):
            mod = fn[:-3]
            if mod not in gated:
                out.append(mod)
    return out


def consistency():
    print("== 一致性检查 ==")
    n = actual_tool_count()
    print("实际注册工具数：%d（来源：create_server().list_tools()）" % n)
    bad = 0

    hits = scan_test_counts(n)
    wrong = [h for h in hits if h[3] != n]
    print("tests 里写死的工具数断言：%d 处，%s" % (len(hits), "全部一致" if not wrong else "有不一致"))
    for fn, i, line, v in wrong:
        bad += 1
        print("  [不一致] tests/%s:%d 断言 %d  != 实际 %d\n            %s" % (fn, i, v, n, line))
    if not hits:
        bad += 1
        print("  [不一致] 没扫到任何工具数断言，检查扫描规则是否失效")

    rhits = scan_readme_counts()
    rwrong = [h for h in rhits if h[3] != n]
    print("README 里的工具数描述：%d 处，%s" % (len(rhits), "全部一致" if not rwrong else "有不一致"))
    for fn, i, line, v in rwrong:
        bad += 1
        print("  [不一致] %s:%d 写的是 %d  != 实际 %d\n            %s" % (fn, i, v, n, line))
    if not rhits:
        bad += 1
        print("  [不一致] README 没扫到工具数描述，检查扫描规则是否失效")

    ungated = discover_ungated()
    if ungated:
        print("存在但未纳入闸门的测试模块（信息提示）：%s" % ", ".join(ungated))

    print("一致性检查：%s" % ("通过" if not bad else "发现 %d 处问题" % bad))
    return bad


def run_one(name, timeout):
    """跑一个测试模块，返回 (名称, 通过, 失败, rc, 秒, 输出)。"""
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable, "-m", "tests." + name],
                           cwd=ROOT, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        out, rc = dec(p.stdout), p.returncode
    except subprocess.TimeoutExpired as e:
        out, rc = dec(e.output) + "\n[gate] 超时 %ss" % timeout, 124
    ok = ng = None
    for pat in PATTERNS:
        m = pat.findall(out)
        if m:
            ok, ng = m[-1]
            break
    if ok is None:
        ok = str(len(re.findall(r"\[PASS\]|\bPASS\b", out)))
        ng = str(len(re.findall(r"\[FAIL\]|\bFAIL\b", out)))
    return name, ok, ng, rc, time.time() - t0, out


def run_gate(names=None, jobs=DEFAULT_JOBS, timeout=900):
    names = list(names or BATCHES)
    jobs = max(1, int(jobs or 1))
    # 共享守卫端口的模块抽出来串行跑，其余并发
    par = [n for n in names if n not in EXCLUSIVE]
    ser = [n for n in names if n in EXCLUSIVE]
    how = "串行" if jobs == 1 or len(par) <= 1 else "%d 路并发" % min(jobs, len(par))
    print("\n== 闸门测试（%s，共 %d 个模块%s）==" % (
        how, len(names), "，其中 %d 个因共享端口串行" % len(ser) if ser else ""))
    results = {}
    t_all = time.time()
    if jobs == 1 or len(par) <= 1:
        for n in par:
            results[n] = run_one(n, timeout)
            print("  %-16s %5.1fs" % (n, results[n][4]), flush=True)
    else:
        with ThreadPoolExecutor(max_workers=min(jobs, len(par))) as ex:
            for r in ex.map(lambda n: run_one(n, timeout), par):
                results[r[0]] = r
                print("  %-16s %5.1fs" % (r[0], r[4]), flush=True)
    for n in ser:
        results[n] = run_one(n, timeout)
        print("  %-16s %5.1fs" % (n, results[n][4]), flush=True)

    bad, slow = [], []
    for n in names:
        _, ok, ng, rc, sec, out = results[n]
        print("%-16s 通过 %-4s 失败 %-4s rc=%-3d %.1fs" % (n, ok, ng, rc, sec))
        slow.append((sec, n))
        if rc != 0 or ng not in ("0",):
            bad.append(n)
            tail = [ln for ln in out.splitlines() if "FAIL" in ln][:6]
            for ln in tail:
                print("     %s" % ln.strip()[:160])
    slow.sort(reverse=True)
    print("----")
    print("总计 %d 个测试文件，异常/失败 %d 个，总耗时 %.1fs（最慢：%s）" % (
        len(names), len(bad), time.time() - t_all,
        "、".join("%s %.1fs" % (n, s) for s, n in slow[:3])))
    if bad:
        print("问题文件：" + ", ".join(bad))
    return bad


def _pick(argv, flag, default=""):
    """取 --flag 的值（支持 --flag=v 与 --flag v 两种写法）。"""
    for i, a in enumerate(argv):
        if a == flag and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return default


def main():
    argv = sys.argv[1:]
    if "--list" in argv:
        for name in BATCHES:
            print(name)
        print("未纳入闸门：" + ", ".join(discover_ungated()))
        return 0

    names = list(BATCHES)
    if "--fast" in argv:
        names = list(FAST_SET)
    names = [n.strip() for n in _pick(argv, "--only").split(",") if n.strip()] or names
    unknown = [n for n in names if n not in BATCHES]
    if unknown:
        print("不认识的测试模块：%s（可用 --list 看清单）" % ", ".join(unknown))
        return 2
    jobs = 1 if "--serial" in argv else int(_pick(argv, "--jobs", str(DEFAULT_JOBS)) or 1)
    timeout = float(_pick(argv, "--timeout", "900") or 900)

    bad = consistency()
    if "--no-run" in argv:
        return 1 if bad else 0
    bad += len(run_gate(names, jobs=jobs, timeout=timeout))
    print("\n结论：%s" % ("全部通过" if not bad else "存在问题，见上"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
