# -*- coding: utf-8 -*-
"""组件链接自检：部署完 ≠ 能编译、能链接。

背景（本轮真机踩到）：
    components/trace/mdk_trace_buff.h 里声明了
        extern mdk_trace_buff_blob_t mdk_trace_buff_blob;
    但整个仓库没有任何 .c 定义它。同族的 swd 后端在 mdk_trace_swd.c 里有对称的一行，
    buff 漏了（批次55 引入，批次56 写 swd 时写对了）。主机侧 mock 用例只造替身符号，
    少一个定义照样全绿，直到用户第一次真编译才炸：
        L6218E: Undefined symbol mdk_trace_buff_blob

本用例把「能不能链接」变成闸门里的一条，分三段：
    A component_sources 与构建清单（mk 片段 / CMakeLists）三处一致，防清单再漂移
    B 对每个后端真编译 + 链接；含反证——删掉 blob 定义必须失败
    C deploy_component 的部署后自检接线（缺符号 → ok=false + component-link-failed）

没有 C 编译器时 B 段明确 SKIP 并说明「没查」，不冒充通过。

运行：python -m tests.test_component_link
"""
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import errors, trace  # noqa: E402

COMPONENT_DIR = os.path.join(ROOT, "components", "trace")
BACKENDS = ("itm", "rtt", "uart", "buff", "swd")
PASS, FAIL, SKIP = [], [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, "" if ok else str(detail)[:300]),
          flush=True)


def skip(name, why):
    SKIP.append(name)
    print("  [SKIP] %s —— %s（没查，不等于通过）" % (name, why), flush=True)


# 定义行：每个后端自己的 blob 就定义在自己那个 .c 里
BLOB_DEF = {
    "buff": ("mdk_trace_buff.c", "mdk_trace_buff_blob_t mdk_trace_buff_blob;"),
    "swd": ("mdk_trace_swd.c", "mdk_trace_swd_blob_t mdk_trace_swd_blob;"),
}


def _strip_blob_def(src_dir, backend):
    """把某后端 .c 里的 blob 定义删掉，用于反证自检真的能挡住缺符号。"""
    fn, line = BLOB_DEF[backend]
    p = os.path.join(src_dir, fn)
    text = open(p, encoding="utf-8").read()
    assert line in text, "反证前提不成立：%s 里没有 %s" % (fn, line)
    out = [ln for ln in text.splitlines(True) if ln.strip() != line]
    open(p, "w", encoding="utf-8", newline="").write("".join(out))


def main():
    # ============ A. 源文件清单三处一致 ============
    print("A. component_sources 与 mk / CMakeLists 清单一致")
    expect = {
        "itm": ["mdk_trace.c"],
        "rtt": ["mdk_trace.c", "mdk_trace_rtt.c"],
        "uart": ["mdk_trace.c", "mdk_trace_rtt.c"],
        "buff": ["mdk_trace.c", "mdk_trace_buff.c"],
        "swd": ["mdk_trace.c", "mdk_trace_swd.c"],
    }
    bad = {b: trace.component_sources(b) for b in BACKENDS
           if trace.component_sources(b) != expect[b]}
    check("A1 component_sources 对五个后端给出正确的编译清单", not bad, bad)

    mk = trace._gen_make_fragment()
    missing_mk = [f for f in ("mdk_trace.c", "mdk_trace_rtt.c", "mdk_trace_buff.c",
                              "mdk_trace_swd.c") if f not in mk]
    check("A2 mdk_trace.mk 片段列出全部四个源文件（swd 曾漏）", not missing_mk, missing_mk)

    cml = open(os.path.join(COMPONENT_DIR, "CMakeLists.txt"), encoding="utf-8").read()
    missing_cml = [f for f in ("mdk_trace_rtt.c", "mdk_trace_buff.c", "mdk_trace_swd.c")
                   if f not in cml]
    check("A3 CMakeLists 把三个后端 .c 都加进 target_sources", not missing_cml, missing_cml)
    check("A4 CMakeLists 有 swd 的 MDK_TRACE_BACKEND_SWD 分支",
          "MDK_TRACE_BACKEND_SWD" in cml and 'STREQUAL "swd"' in cml,
          [ln for ln in cml.splitlines() if "swd" in ln.lower()][:3])

    for b, (fn, line) in BLOB_DEF.items():
        text = open(os.path.join(COMPONENT_DIR, fn), encoding="utf-8").read()
        check("A5 %s 在自己的 .c 里定义 %s（不是只声明）" % (b, line.split()[-1][:-1]),
              line in text, fn)

    # ============ B. 真编译 + 链接 ============
    print("B. 每个后端真编译 + 链接（缺符号当场现形）")
    checked_any = False
    for b in BACKENDS:
        r = trace.component_link_check(backend=b, src_dir=COMPONENT_DIR)
        if not r.get("checked"):
            skip("B 链接自检 %s" % b, r.get("reason") or "未提供原因")
            continue
        checked_any = True
        check("B 链接自检 %s：能编能链，符号齐全" % b, r.get("ok") is True, r)

    tmp = tempfile.mkdtemp(prefix="mdkdebug_linkchk_")
    try:
        # 反证：删掉 buff 的 blob 定义，自检必须失败并点名缺哪个符号
        neg = os.path.join(tmp, "neg")
        shutil.copytree(COMPONENT_DIR, neg)
        _strip_blob_def(neg, "buff")
        rn = trace.component_link_check(backend="buff", src_dir=neg)
        if not rn.get("checked"):
            skip("B 反证：删掉 blob 定义必须失败", "本机没有 C 编译器")
        else:
            check("B1 反证：删掉 buff blob 定义 → 链接失败并点名该符号",
                  rn.get("ok") is False
                  and "mdk_trace_buff_blob" in (rn.get("missing_symbols") or []), rn)
            check("B2 自检失败时给的是可执行下一步（hint 指向组件自己的 .c）",
                  "mdk_trace_buff_blob" in (rn.get("hint") or ""), rn.get("hint"))

        # ============ C. deploy_component 的部署后自检 ============
        print("C. deploy_component 部署后自检接线")
        tgt = os.path.join(tmp, "proj", "components", "trace")
        out = trace.deploy_component(tgt, backend="buff", overwrite=True)
        chk = out.get("self_check") or {}
        check("C1 部署时默认做链接自检（self_check.checked=true）",
              chk.get("checked") is True, chk)
        if chk.get("checked"):
            check("C2 组件齐全时部署自检通过、整体 ok=true",
                  chk.get("ok") is True and out.get("ok") is True, out)
            check("C3 返回里给出该后端要进编译的 source 清单",
                  out.get("sources") == expect["buff"], out.get("sources"))

            # 破坏目标目录里的定义 → 部署自检必须把整体判失败
            _strip_blob_def(tgt, "buff")
            out2 = trace.deploy_component(tgt, backend="buff", overwrite=False)
            check("C4 目标目录缺 blob 定义 → ok=false + component-link-failed",
                  out2.get("ok") is False
                  and out2.get("error_code") == "component-link-failed",
                  {k: out2.get(k) for k in ("ok", "error_code", "error")})
            check("C5 失败时列出 missing_symbols 供直接定位",
                  "mdk_trace_buff_blob" in (out2.get("missing_symbols") or []),
                  out2.get("missing_symbols"))

        # link_check=false 是显式关闭，必须如实标成「没查」而不是「通过」
        tgt2 = os.path.join(tmp, "proj2", "components", "trace")
        out3 = trace.deploy_component(tgt2, backend="itm", overwrite=True, link_check=False)
        check("C6 link_check=false 时如实标未检查（不是伪装成通过）",
              (out3.get("self_check") or {}).get("checked") is False, out3.get("self_check"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ============ D. 错误码与工具面 ============
    print("D. 错误码登记与工具面")
    check("D1 ERROR_CODES 登记 component-link-failed",
          "component-link-failed" in errors.ERROR_CODES, list(errors.ERROR_CODES)[:5])
    n = errors.normalize("trace_instrument",
                         {"ok": False, "error": "组件缺符号",
                          "error_code": "component-link-failed"})
    check("D2 统一信封补出 error_hint 与 next_actions",
          bool(n.get("error_hint")) and len(n.get("next_actions") or []) >= 2, n)

    import asyncio
    from mdkdebug.server import create_server
    srv = create_server(host="127.0.0.1", port=14921, idle_timeout=30.0)
    loop = asyncio.new_event_loop()
    try:
        tools = loop.run_until_complete(srv.list_tools())
        ti = {t.name: t for t in tools}.get("trace_instrument")
        schema = (getattr(ti, "inputSchema", None) or getattr(ti, "input_schema", {}) or {})
        props = schema.get("properties") or {}
        check("D3 trace_instrument 暴露 link_check 参数（默认 true）",
              "link_check" in props and props["link_check"].get("default") is True,
              props.get("link_check"))
        check("D4 描述里讲清 self_check 语义（含「没查≠通过」）",
              "self_check" in (ti.description or "")
              and "component-link-failed" in (ti.description or ""),
              (ti.description or "")[:200])
    finally:
        loop.close()

    print("\n==== 组件链接自检 %d 通过 / %d 失败 / %d 跳过 ===="
          % (len(PASS), len(FAIL), len(SKIP)))
    for s in SKIP:
        print("  [SKIP] %s" % s)
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  - %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
