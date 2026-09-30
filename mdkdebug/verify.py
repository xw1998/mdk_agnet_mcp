# -*- coding: utf-8 -*-
"""闭环上板判定（批次77）——**把「顺序」固化成代码，而不是靠调用方记得**。

为什么值得单独做
--------------
固件复位后几十毫秒就输出启动信息，而主机打开串口要经历设备枚举与参数配置，更慢。
所以「烧录 → 放开内核 → 再开串口」这个顺序**必然丢掉启动段输出**，现象是
「固件明明正确、闭环却一直超时」——一个纯粹的时序问题，会被读成固件缺陷，
于是 AI 去改本来正确的代码。

本模块采取的顺序是**先开串口、再烧录**：
    编译 → 打开串口监听 → 记下游标 → 烧录（复位并运行） → 等通过令牌 → 判定
比"烧录后把内核按在暂停态"更简单，且**一个字节都不会丢**：复位发生在串口已经就绪之后。
配合 ``since`` 游标，「缓冲区里的老日志」不会被当成本次命中。

判定用的是**硬证据**，不是文本感觉：``no_data``（一个字节都没新增）与
``no_match``（有输出但对不上令牌）被刻意分开——前者是串口/接线/重定向的问题，
后者才可能是测试没跑到输出点。这两件事的下一步动作完全不同。

判定结果没有含糊档：``passed`` 只有一种走法，就是**真的在烧录之后收到了令牌**。
"""
from __future__ import annotations

DEFAULT_TOKEN = "[ALL TESTS PASSED]"

# 判定结果（verdict）取值与含义——写全，避免调用方猜
VERDICTS = {
    "build_failed": "编译没通过：先改代码，别上板",
    "serial_unavailable": "串口不可用：**未烧录**（烧了也无法判定），先把串口搞定",
    "flash_failed": "烧录失败：这是探针/接线/供电/读保护的问题，**不是代码问题**",
    "passed": "烧录后在串口收到了通过令牌（且有新鲜度证据）",
    "token_stale": "等到的令牌出现在烧录完成之前——那是旧固件还在刷，不算本次通过",
    "token_timeout": "串口有新增输出，但等不到通过令牌：测试可能没跑到输出点",
    "no_output": "烧录后串口一个字节都没有新增：串口重定向/接线/波特率的问题",
    "captured": "未配置通过令牌，只捕获了启动输出，**不作通过/失败判定**",
}

def run_closed_loop(*, build_fn=None, flash_fn=None, monitor_start_fn=None,
                    cursor_fn=None, expect_fn=None, tail_fn=None,
                    flash_done_fn=None, precheck_fn=None,
                    token: str = "", timeout_s: float = 20.0,
                    do_build: bool = True, do_flash: bool = True,
                    release_serial: bool = False) -> dict:
    """跑一次「编译→开串口→烧录→等令牌→判定」。

    所有 ``*_fn`` 都是**可注入的回调**（无硬件也能完整测判定逻辑）：
      - ``build_fn()`` / ``flash_fn()`` → 返回 dict，``ok`` 为假即失败；
      - ``monitor_start_fn()`` → 返回 dict，``ok`` 为假表示串口没起来；
      - ``cursor_fn()`` → 返回当前串口游标（整数），用于「只认新的输出」；
      - ``expect_fn(pattern, timeout_s, since)`` → 返回串口等待结果；
      - ``tail_fn(n)`` → 返回最近 n 行（判定失败时给人看）；
      - ``flash_done_fn()`` → 返回烧录完成时刻（epoch 秒），用于新鲜度判定。
    """
    import time as _t
    tok = (token or "").strip()
    steps, notes = [], []
    t_start = _t.time()

    def _step(name, ok, detail=None, ms=None):
        steps.append({"step": name, "ok": bool(ok),
                      "detail": (detail if detail is not None else {}),
                      "ms": ms})

    def _verdict(kind, **extra):
        out = {
            "ok": kind == "passed",
            "verdict": kind,
            "verdict_meaning": VERDICTS.get(kind, ""),
            "token": tok or None,
            "steps": steps,
            "elapsed_ms": int((_t.time() - t_start) * 1000),
            "notes": notes,
        }
        out.update(extra)
        return _finalize(out)

    # 1) 编译
    if do_build and build_fn is not None:
        t0 = _t.time()
        r = dict(build_fn() or {})
        _step("build", r.get("ok", False), _brief(r), int((_t.time() - t0) * 1000))
        if not r.get("ok", False):
            return _verdict("build_failed", build=r,
                            next_actions=["先按编译错误改代码（explain_build_error / parse_build_errors），"
                                          "本轮不烧录、不上板。"])
    else:
        _step("build", True, {"skipped": True})

    # 2) 串口必须**先**就绪——这是整个顺序的关键
    if monitor_start_fn is not None:
        t0 = _t.time()
        m = dict(monitor_start_fn() or {})
        ok = m.get("ok", True) is not False
        _step("serial_monitor_start", ok, _brief(m), int((_t.time() - t0) * 1000))
        if not ok:
            return _verdict(
                "serial_unavailable", serial=m,
                next_actions=[
                    "serial_list_ports 看有哪些口；确认波特率与接线（TX/RX/GND 三根即可）。",
                    "**先别烧录**：烧了也无法判定「测试是否通过」，只会多一次不可复核的副作用。",
                    "若暂时只能没有串口：firmware_precheck 会告诉你哪些判据因此不可得。",
                ])
    since = None
    if cursor_fn is not None:
        try:
            since = int(cursor_fn())
            _step("mark_cursor", True, {"since": since})
        except Exception as e:                                        # noqa: BLE001
            notes.append("读串口游标失败（%r）：将按「无法区分新旧输出」处理" % e)

    # 3) 烧录
    flash_done_t = None
    if do_flash and flash_fn is not None:
        t0 = _t.time()
        f = dict(flash_fn() or {})
        _step("flash", f.get("ok", False), _brief(f), int((_t.time() - t0) * 1000))
        flash_done_t = _t.time()
        if not f.get("ok", False):
            return _verdict(
                "flash_failed", flash=f,
                next_actions=["这是探针/接线/供电/读保护问题，**不要改源码**。",
                              "list_devices 看探针；确认没被 Keil / STM32CubeProgrammer 占着。"])
    elif flash_done_fn is not None:
        try:
            flash_done_t = float(flash_done_fn())
        except Exception:                                             # noqa: BLE001
            flash_done_t = None

    # 4) 等令牌
    if not tok:
        # 没配令牌：只捕获输出，**明确不作通过判定**
        if expect_fn is not None:
            r = dict(expect_fn("", float(timeout_s or 0), since) or {})
        else:
            r = {}
        lines = list(r.get("lines") or [])
        _step("capture", bool(lines), {"lines": len(lines)})
        notes.append("未配置通过令牌（token 为空）：本轮**只采集输出，不判定通过/失败**。"
                     "要让闭环能判定，请在固件的测试通过路径上输出一个固定令牌，"
                     "并把 token 传成它。")
        return _verdict("captured", serial=r, lines_tail=lines[-20:],
                        next_actions=["把 token 传成本工程实际使用的通过令牌；"
                                      "firmware_precheck 的 pass_token 一项会替你确认它存在。"])

    if expect_fn is None:
        return _verdict("captured", next_actions=["内部错误：没有可用的串口等待实现"])

    t0 = _t.time()
    r = dict(expect_fn(tok, float(timeout_s or 0), since) or {})
    waited = int((_t.time() - t0) * 1000)
    _step("expect_token", bool(r.get("matched")), _brief(r), waited)

    if r.get("matched"):
        fresh = _freshness(r, flash_done_t)
        if fresh is False:
            return _verdict(
                "token_stale", serial=r, token_after_flash=False,
                lines_tail=_tail(tail_fn, 20),
                next_actions=[
                    "这次等到的令牌出现在**烧录完成之前**：那是旧固件还在刷。",
                    "再调一次（或把 timeout_s 调大），让串口继续往后等新的输出。",
                ])
        return _verdict("passed", serial=r,
                        matched_line=r.get("matched_line"),
                        token_after_flash=fresh,
                        lines_tail=_tail(tail_fn, 20))

    kind = r.get("timeout_kind")
    verdict = "no_output" if kind == "no-data" else "token_timeout"
    nxt = []
    if verdict == "no_output":
        nxt += ["串口一个字节都没新增：确认串口重定向真的实现了、波特率对得上、TX 接到了 RX。",
                "firmware_precheck 的 serial 一项会检查本机串口。"]
    else:
        nxt += ["有输出但等不到令牌：**先确认固件里真的有这个令牌**（看 lines_tail 里跑到了哪一步）。",
                "令牌文本不一致也会导致这个结果——把 token 传成本工程实际用的那句。",
                "把 timeout_s 调大：初始化慢（时钟/外设/文件系统）时容易刚好超时。"]
    if precheck_fn is not None:
        try:
            pc = precheck_fn()
            blocked = pc.get("failed") or []
            if blocked:
                nxt.insert(0, "预检先报了会**注定判不出来**的问题：%s → 先修它" % ", ".join(blocked))
            for c in (pc.get("checks") or []):
                if c.get("id") == "pass_token" and c.get("status") != "pass":
                    nxt.insert(0, "预检没在源码里找到通过令牌：这就是超时的根因候选")
                    break
        except Exception as e:                                        # noqa: BLE001
            notes.append("附带预检失败（%r）：未纳入 next_actions" % e)
    return _verdict(verdict, serial=r, lines_tail=_tail(tail_fn, 30),
                    next_actions=nxt)

# ----------------------------------------------------------------------
def _freshness(expect_result: dict, flash_done_t) -> bool | None:
    """命中是「烧录之后的新输出」还是「旧固件还在刷」？

    True=有证据表明在烧录之后；False=有证据表明在烧录之前（旧固件）；
    None=拿不到时间戳（例如命中的是半行），**如实返回 None，不硬猜**。
    """
    if not flash_done_t:
        return None
    items = expect_result.get("items") or []
    idx = expect_result.get("matched_index")
    if idx is None or not isinstance(idx, int) or idx < 0 or idx >= len(items):
        return None
    t = (items[idx] or {}).get("t")
    if t is None:
        return None
    try:
        return float(t) >= float(flash_done_t)
    except (TypeError, ValueError):
        return None

def _tail(tail_fn, n: int) -> list:
    if tail_fn is None:
        return []
    try:
        return list(tail_fn(n) or [])
    except Exception:                                                 # noqa: BLE001
        return []

def _brief(d: dict) -> dict:
    """把一步的返回值收成给报告看的摘要（别把整个串口缓冲塞进来）。"""
    keep = ("ok", "error", "exit_code", "exit_code_meaning", "note", "message",
            "matched", "timeout_kind", "error_code", "port", "state", "elapsed_ms",
            "added", "matched_line", "now", "lines")
    out = {}
    for k in keep:
        if k in d:
            v = d[k]
            if k == "lines" and isinstance(v, list):
                v = v[-5:]
            out[k] = v
    return out

def _finalize(out: dict) -> dict:
    out.setdefault("next_actions", [])
    # 判定为通过时不留一串"下一步"——那会让调用方以为还有活要干
    if out.get("verdict") == "passed":
        out["next_actions"] = []
    out["verdict_table"] = VERDICTS
    return out
