# -*- coding: utf-8 -*-
"""代码覆盖率（批次47）：PC 采样法，函数级 + 行级触达统计。

为什么是「触达」而不是「覆盖」
------------------------------
本模块不往目标里插桩、也不改动用户工程，只做两件事：

1. 从 `.axf` 的调试信息里取出**函数区间**（符号表）与**可执行行表**（DWARF 行号程序），
   于是「这个工程的函数/行总共有多少」是**静态事实**，不是估计。
2. 运行期用 DWT 的硬件 PC 采样器（`DWT_PCSR`，见 trace 的 `trace_pcsample`）**不 halt
   目标**地反复读 PC，按上面两张表归属到函数与行。

所以能给出的结论是：**「这些函数/行被观测到执行过」**——
反方向的「没被采样到 = 没执行过」**不成立**，这是采样法固有的性质，本模块在返回值里
一律用 `unseen`（没看到）而不是 `uncovered`（未覆盖），并把这条边界写进 `note`。
要证明「没执行过」，需要断点命中或插桩这类逐次证据。

退化情形（一律如实报，不编一份像样的分布）
------------------------------------------
- **PC 采样器不工作**：部分 Cortex-M 修订版上 `DWT_PCSR` 恒为同一值。连续读够多次
  仍只有一个不同值即判 `sampler_inactive`，此时覆盖率为**无效数据**，返回里明确
  `usable=false`，并指向 `trace_profile`（halt→读 PC→resume 的侵入式兜底）。
- **没有 .axf / 没有 DWARF**：没有函数表就算了不出一行覆盖率——直接报
  `no-symbol-table`，不给 0%。
- **PC 落在任何函数区间外**（ROM 里的启动代码、库里没有符号的段）：单独计
  `unmapped`，不硬凑到最近的那个函数上。
"""
from __future__ import annotations

import bisect
import threading
import time

# Cortex-M 系统区（跨厂商一致）
DEMCR = 0xE000EDFC          # 调试异常与监视控制；TRCENA=bit24 是 DWT 的总开关
DWT_CTRL = 0xE0001000       # PCSAMPLENA=bit12，POSTPRESET=bits[4:1]
DWT_PCSR = 0xE000101C       # 硬件 PC 采样器当前值（只读）

# 连续读到这么多个样本还只有一个不同值，就判采样器没在工作。
# 取值依据：真机上采样器正常时，几百次随机读几乎不可能只有一个值；
# 而采样器死掉时会稳定返回同一个值（多为 0 或复位向量）。
_INACTIVE_MIN_SAMPLES = 25

_S = {}                     # 当前覆盖率会话（模块级，进程内单例）
_LOCK = threading.Lock()

# ----------------------------------------------------------------------
# 纯逻辑：静态表
# ----------------------------------------------------------------------
def func_index(symbols):
    """符号列表 -> 按地址升序的函数区间 [(start, end, name)]。

    `end` 优先取 `st_size`；size 为 0 的符号（部分汇编/局部符号没有 size）用
    **下一个函数起点**兜底，最后一个用 `start+1`——宁可区间保守，也不让它一直
    吃到地址空间末尾、把后面所有函数都吞掉。
    """
    items = []
    for s in symbols or []:
        try:
            a = int(str(s.get("addr")), 16) & ~1
        except (TypeError, ValueError):
            continue
        try:
            sz = int(s.get("size") or 0)
        except (TypeError, ValueError):
            sz = 0
        items.append((a, sz, s.get("name") or "?"))
    items.sort()
    out = []
    for i, (a, sz, nm) in enumerate(items):
        end = a + sz if sz > 0 else None
        if end is None or end <= a:
            end = items[i + 1][0] if i + 1 < len(items) else a + 1
            end = max(end, a + 1)
        out.append((a, end, nm))
    return out

def func_at(funcs, pc: int):
    """pc 落在哪个函数区间；落在区间外返回 None（不硬凑到最近的函数）。"""
    if not funcs:
        return None
    starts = [f[0] for f in funcs]
    i = bisect.bisect_right(starts, int(pc)) - 1
    if i < 0:
        return None
    a, b, nm = funcs[i]
    return (a, b, nm) if a <= int(pc) < b else None

def line_index(rows):
    """DWARF 行号表 -> {(file, line): 最小地址}。跳过没有文件名的条目（'?'）。"""
    out = {}
    for item in rows or []:
        try:
            a, f, l = item[0], item[1], item[2]
        except (TypeError, IndexError):
            continue
        if not f or f == "?" or not l:
            continue
        k = (f, int(l))
        if k not in out or int(a) < out[k]:
            out[k] = int(a)
    return out

def line_at(rows, pc: int):
    """pc 对应的源码行（取 <=pc 的最近行条目）。没有则 None。"""
    if not rows:
        return None
    idx = bisect.bisect_right(rows, (int(pc), "\uffff", 10 ** 9)) - 1
    if idx < 0:
        return None
    a, f, l = rows[idx]
    return {"file": f, "line": int(l), "address": int(a)}

def match_scope(name: str, scope: str) -> bool:
    """scope 是**大小写不敏感的子串**，同时对函数名与文件名生效；空 scope 全要。"""
    s = str(scope or "").strip().lower()
    if not s:
        return True
    return s in str(name or "").lower()

def build_report(*, usable, reason=None, error=None, elf=None, link=None,
                 scope="", samples=0, reads=0, read_fail=0, first_error=None,
                 distinct_pcs=0, sampler_active=None, sampler_note=None,
                 funcs_total=0, funcs_hit=0, lines_total=0, lines_hit=0,
                 hot=None, unseen=None, unseen_truncated=0, unmapped=0,
                 mapped_pcs=0, elapsed_s=0.0, restored=None, extra=None):
    """汇总成给 AI 看的结果。**所有比例都带分母**，不出现孤零零的百分比。"""
    out = {"ok": True, "action": "coverage", "usable": bool(usable)}
    if reason:
        out["reason"] = reason
    if error:
        out["ok"] = bool(usable)
        out["error"] = error
    if elf:
        out["elf"] = elf
    if link:
        out["link"] = link
    if scope:
        out["scope"] = scope
    out["samples"] = int(samples)
    if reads:
        out["reads"] = int(reads)
    if read_fail:
        out["read_fail"] = int(read_fail)
        if first_error:
            out["read_error"] = str(first_error)[:200]
    out["distinct_pcs"] = int(distinct_pcs)
    if sampler_active is not None:
        out["sampler_active"] = bool(sampler_active)
    if sampler_note:
        out["sampler_note"] = sampler_note
    if funcs_total or funcs_hit:
        out["functions"] = {"hit": int(funcs_hit), "total": int(funcs_total),
                            "percent": (round(100.0 * funcs_hit / funcs_total, 2)
                                        if funcs_total else None),
                            "unseen": int(funcs_total - funcs_hit)}
    if lines_total or lines_hit:
        out["lines"] = {"hit": int(lines_hit), "total": int(lines_total),
                        "percent": (round(100.0 * lines_hit / lines_total, 2)
                                    if lines_total else None),
                        "unseen": int(lines_total - lines_hit)}
    if hot:
        out["hot"] = hot
    if unseen:
        out["unseen_functions"] = unseen
    if unseen_truncated:
        out["unseen_truncated"] = int(unseen_truncated)
    if mapped_pcs or unmapped:
        out["pc_attribution"] = {"mapped": int(mapped_pcs), "unmapped": int(unmapped),
                                 "unmapped_note": "落在任何函数区间之外的 PC（启动代码、"
                                                  "无符号的库段等）。它们不参与函数覆盖率，"
                                                  "也不硬凑到最近的函数上。"}
    if restored is not None:
        out["dwt_restored"] = bool(restored)
    out["elapsed_s"] = round(float(elapsed_s), 3)
    out["note"] = ("这是 **PC 采样法**得出的「触达」统计，不是插桩覆盖率：被采样到 ⇒ 一定执行过；"
                   "**没被采样到 ≠ 没执行过**（采样器的采样点、窗口长度、快路径都可能漏）。"
                   "要证明某段没执行，请用断点命中或 trace_instrument 插桩。"
                   "样本量越大结论越稳：先把 duration_s/samples 加大，再下结论。")
    if extra:
        out.update(extra)
    return out

# ----------------------------------------------------------------------
# 会话：后台采样线程
# ----------------------------------------------------------------------
def _reset_state():
    with _LOCK:
        _S.clear()

def _get_state():
    return _S.get("cur")

def _locator_for(elf: str):
    """拿定位器。给了 elf 就现开一个；否则用服务器当前那份（与 set_symbol_file 同步）。"""
    if elf:
        try:
            from .locator import Locator
            return Locator(elf)
        except Exception as e:                                      # noqa: BLE001
            return {"error": "打开 elf 失败：%s" % e}
    try:
        from . import server as _srv
        loc = _srv._get_locator()
        return loc
    except Exception as e:                                          # noqa: BLE001
        return {"error": "取定位器失败：%s" % e}

def _meta_error(meta):
    """从链路返回的 meta 里取错误文本。链路约定给 dict，但坏实现/包装层可能给别的，
    这里不假设类型——拿不到就说拿不到，不让它变成 AttributeError 把整次采样打断。"""
    if isinstance(meta, dict):
        return meta.get("error")
    if meta is None:
        return None
    return str(meta)


def _read_u32(lk, addr):
    data, meta = lk.read(int(addr), 4)
    if data is None or len(data) < 4:
        return None, _meta_error(meta) or "读失败"
    return int.from_bytes(data[:4], "little"), None

def _write_u32(lk, addr, val):
    ok, meta = lk.write(int(addr), int(val).to_bytes(4, "little"))
    return bool(ok), _meta_error(meta)

def start(interval_ms: float = 10.0, elf: str = "", scope: str = "",
          link: str = "auto", max_samples: int = 0, duration_s: float = 0.0,
          enable_dwt: bool = True, restore: bool = True, timeout: float = 0.0):
    """开始一次覆盖率采集（后台线程，不 halt 目标）。"""
    from . import linkio as _link
    cur = _get_state()
    if cur and cur.get("thread") and cur["thread"].is_alive():
        return {"ok": False, "action": "coverage_start", "reason": "already-running",
                "error": "已经有一次覆盖率采集在跑",
                "hint": "先 coverage_stop 收尾，或 coverage_read 看进展；"
                        "同一条调试链路上不要并发采样"}

    # 先建静态表：表都建不出来就没必要开采样了（不给 0%，直接报原因）。
    loc = _locator_for(elf)
    if isinstance(loc, dict):
        return {"ok": False, "action": "coverage_start", "reason": "no-symbol-table",
                "error": loc.get("error"), "usable": False}
    if loc is None or not getattr(loc, "is_ready", lambda: False)():
        return {"ok": False, "action": "coverage_start", "reason": "no-symbol-table",
                "usable": False,
                "error": "没有可用的调试信息（.axf）：定位器未就绪",
                "hint": "先 enter_debug/compile 让工程产出 .axf，或用 elf 参数显式指定；"
                        "没有函数表就算不出一行覆盖率，本工具不会给你一个 0%。"}
    try:
        symbols = loc.search_symbols("", limit=200000, kind="func")
        loc._ensure_loaded()
        rows = list(getattr(loc, "_rows", []) or [])
    except Exception as e:                                          # noqa: BLE001
        return {"ok": False, "action": "coverage_start", "reason": "no-symbol-table",
                "usable": False, "error": "读取符号表/行表失败：%s" % e}
    funcs = func_index(symbols)
    lines = line_index(rows)
    if scope:
        funcs = [f for f in funcs if match_scope(f[2], scope)]
        lines = {k: v for k, v in lines.items() if match_scope(k[0], scope)}
        if not funcs and not lines:
            return {"ok": False, "action": "coverage_start", "reason": "empty-scope",
                    "usable": False,
                    "error": "scope=%r 在符号表/行表里一条都匹配不到" % scope,
                    "hint": "scope 是大小写不敏感的子串，比如 \"app\"、\"motor.c\"；"
                            "留空表示统计全部。本工具不会把「匹配不到」当成 0%。"}
    if not funcs:
        return {"ok": False, "action": "coverage_start", "reason": "no-symbol-table",
                "usable": False,
                "error": "符号表里没有任何带地址的函数符号（.axf 可能被 strip 过）"}

    lk, lerr = _link.pick(link, who="读 DWT_PCSR")
    if lk is None:
        out = dict(lerr)
        out["action"] = "coverage_start"
        out["usable"] = False
        return out

    demcr0, e1 = _read_u32(lk, DEMCR)
    ctrl0, e2 = _read_u32(lk, DWT_CTRL)
    if demcr0 is None or ctrl0 is None:
        return {"ok": False, "action": "coverage_start", "usable": False,
                "reason": "no-dwt", "link": lk.name,
                "error": "读 DEMCR/DWT_CTRL 失败：%s" % (e1 or e2),
                "hint": "PC 采样器是 DWT 的一部分，Cortex-M3 及以上才有；"
                        "RISC-V/Xtensa 用不了本工具（见 trace_guide）"}
    enabled, restore_note = [], None
    if enable_dwt:
        if not (demcr0 & (1 << 24)):
            ok, werr = _write_u32(lk, DEMCR, demcr0 | (1 << 24))
            if not ok:
                return {"ok": False, "action": "coverage_start", "usable": False,
                        "reason": "dwt-write-failed", "link": lk.name,
                        "error": "写 DEMCR.TRCENA 失败：%s" % werr,
                        "demcr": "0x%08X" % demcr0}
            enabled.append("DEMCR.TRCENA")
        # PCSAMPLENA=bit12；POSTPRESET 置 0xF 让采样器慢下来（否则主机读到的
        # 永远是同一个最新值，看不出分布），同时清 POSTCNT(bits[5:8])。
        want = (ctrl0 | (1 << 12) | (0xF << 1)) & ~(0xF << 5)
        ok, werr = _write_u32(lk, DWT_CTRL, want)
        if not ok:
            return {"ok": False, "action": "coverage_start", "usable": False,
                    "reason": "dwt-write-failed", "link": lk.name,
                    "error": "写 DWT_CTRL.PCSAMPLENA 失败：%s" % werr,
                    "dwt_ctrl": "0x%08X" % ctrl0,
                    "hint": "部分 Cortex-M 修订版不支持 PC 采样（PCSAMPLENA 恒 0）；"
                            "退回 trace_profile（halt→读 PC→resume）"}
        enabled.append("DWT_CTRL.PCSAMPLENA")

    st = {"link": lk.name, "elf": getattr(loc, "axf_path", None) or elf or None,
          "scope": scope, "funcs": funcs, "lines": lines,
          "rows": rows,
          "hits": {},                    # pc -> count
          "func_hits": {},               # name -> count
          "line_hits": {},               # (file, line) -> count
          "samples": 0, "reads": 0, "read_fail": 0, "first_error": None,
          "unmapped": 0, "mapped": 0,
          "demcr0": demcr0, "ctrl0": ctrl0, "enabled": enabled,
          "stop_ev": threading.Event(), "thread": None,
          "started_at": time.time(), "stopped_at": None,
          "max_samples": int(max_samples or 0), "duration_s": float(duration_s or 0),
          "interval_ms": max(0, int(interval_ms or 0)) if interval_ms else 0,
          "timeout": float(timeout or 0), "restore": bool(restore),
          "restored": None}
    _S["cur"] = st

    def _run():
        t0 = time.time()
        while not st["stop_ev"].is_set():
            if st["duration_s"] and time.time() - t0 >= st["duration_s"]:
                break
            if st["max_samples"] and st["samples"] >= st["max_samples"]:
                break
            v, err = _read_u32(lk, DWT_PCSR)
            if v is None:
                st["read_fail"] += 1
                if st["first_error"] is None:
                    st["first_error"] = err
                if st["read_fail"] >= 5:
                    break
            else:
                pc = int(v) & ~1
                st["reads"] += 1
                st["samples"] += 1
                st["hits"][pc] = st["hits"].get(pc, 0) + 1
                f = func_at(st["funcs"], pc)
                if f is None:
                    st["unmapped"] += 1
                else:
                    st["mapped"] += 1
                    st["func_hits"][f[2]] = st["func_hits"].get(f[2], 0) + 1
                    lc = line_at(st["rows"], pc)
                    if lc:
                        k = (lc["file"], lc["line"])
                        st["line_hits"][k] = st["line_hits"].get(k, 0) + 1
            iv = st["interval_ms"]
            if iv:
                time.sleep(min(iv / 1000.0, 1.0))
            if st["timeout"] and time.time() - t0 > st["timeout"]:
                break
        st["stopped_at"] = time.time()
        if st["restore"]:
            st["restored"] = _restore_dwt(lk, st)

    th = threading.Thread(target=_run, name="mdkdebug-coverage", daemon=True)
    st["thread"] = th
    th.start()
    time.sleep(min(max(st["interval_ms"], 1) / 1000.0 * 3, 0.4))
    out = read()
    out["enabled_by_us"] = enabled or None
    out["hint"] = ("用 coverage_read 看进展、coverage_stop 收尾。"
                   "采集期间目标**不停**（DWT 硬件采样器自己采）；"
                   "若 sampler_active=false，说明这台芯片的 PC 采样器不工作，"
                   "本次数据不可用，改用 trace_profile。")
    return out

def _restore_dwt(lk, st):
    """把 DEMCR/DWT_CTRL 恢复成开采样之前的样子（默认做，可关）。"""
    ok1 = ok2 = True
    if st.get("demcr0") is not None:
        ok1, _ = _write_u32(lk, DEMCR, st["demcr0"])
    if st.get("ctrl0") is not None:
        ok2, _ = _write_u32(lk, DWT_CTRL, st["ctrl0"])
    return bool(ok1 and ok2)

def _snapshot(st, top: int = 20, unseen: int = 20, now=None):
    now = now if now is not None else time.time()
    end = st.get("stopped_at") or now
    samples = st["samples"]
    distinct = len(st["hits"])
    inactive = bool(samples >= _INACTIVE_MIN_SAMPLES and distinct <= 1)
    sampled = bool(not st["thread"] or not st["thread"].is_alive())
    if samples < _INACTIVE_MIN_SAMPLES and st["thread"] and st["thread"].is_alive():
        # 采样还在跑且样本太少：不下结论
        sampler_active = None
        sampler_note = ("样本还太少（%d 个），暂时判断不了采样器有没有在工作；"
                        "再读几次 coverage_read 或把 duration_s 调大。" % samples)
    elif inactive:
        sampler_active = False
        sampler_note = ("连续 %d 个样本只见到 %d 个不同的 PC —— PC 采样器**没有在工作**"
                        "（部分 Cortex-M 修订版 PCSAMPLENA 恒 0）。本次覆盖率数据不可用，"
                        "不要据此说「代码没跑到」。" % (samples, distinct))
    else:
        sampler_active = True
        sampler_note = ("观测到 %d 个不同的 PC，采样器在工作。" % distinct)
    usable = bool(sampler_active and samples > 0 and st["funcs"])

    funcs_hit = len(st["func_hits"])
    funcs_total = len(st["funcs"])
    lines_hit = len(st["line_hits"])
    lines_total = len(st["lines"])
    hot = sorted(({"name": k, "hits": v} for k, v in st["func_hits"].items()),
                 key=lambda r: (-r["hits"], r["name"]))[:max(0, int(top))]
    unseen_list = sorted(n for _a, _b, n in st["funcs"]
                         if n not in st["func_hits"])
    cap = max(0, int(unseen))
    unseen_out = unseen_list[:cap] if cap else []
    return build_report(
        usable=usable, elf=st.get("elf"), link=st.get("link"), scope=st.get("scope"),
        samples=samples, reads=st["reads"], read_fail=st["read_fail"],
        first_error=st["first_error"], distinct_pcs=distinct,
        sampler_active=sampler_active, sampler_note=sampler_note,
        funcs_total=funcs_total, funcs_hit=funcs_hit,
        lines_total=lines_total, lines_hit=lines_hit,
        hot=hot, unseen=unseen_out, unseen_truncated=max(0, len(unseen_list) - len(unseen_out)),
        unmapped=st["unmapped"], mapped_pcs=st["mapped"],
        elapsed_s=end - st["started_at"], restored=st.get("restored"),
        extra={"running": bool(st["thread"] and st["thread"].is_alive()),
               "finished": sampled,
               "dwt_enabled_by_us": st.get("enabled") or None})

def read(top: int = 20, unseen: int = 20):
    st = _get_state()
    if not st:
        return {"ok": False, "action": "coverage_read",
                "error": "还没有覆盖率会话",
                "hint": "先 coverage_start(...)；只看一次性的分布也可以直接用 "
                        "trace_pcsample"}
    out = _snapshot(st, top=top, unseen=unseen)
    out["action"] = "coverage_read"
    return out

def stop(restore: bool = True, top: int = 20, unseen: int = 20):
    from . import linkio as _link
    st = _get_state()
    if not st:
        return {"ok": False, "action": "coverage_stop",
                "error": "还没有覆盖率会话",
                "hint": "先 coverage_start(...)"}
    st["restore"] = bool(restore)
    st["stop_ev"].set()
    th = st.get("thread")
    if th and th.is_alive():
        th.join(timeout=5.0)
    if st["restored"] is None and restore:
        lk, _err = _link.pick(st.get("link") or "auto", who="恢复 DWT 配置")
        if lk is not None:
            st["restored"] = _restore_dwt(lk, st)
    out = _snapshot(st, top=top, unseen=unseen)
    out["action"] = "coverage_stop"
    if not out.get("usable"):
        out["hint"] = ("本次数据不可用（采样器没工作或没采到样本）；"
                       "改用 trace_profile(samples=..., elf=...) 做侵入式兜底。")
    return out

def clear():
    """清掉当前会话的计数（保留一次会话的静态表需要重开，故整体重置）。"""
    had = bool(_get_state())
    _reset_state()
    return {"ok": True, "action": "coverage_clear", "cleared": had,
            "note": "计数与静态表都清掉了；下次 coverage_start 会重新读一遍 .axf。"
                    "正在跑的采集线程会随之失去引用，请先 coverage_stop。"}

# ----------------------------------------------------------------------
# MCP 工具注册
# ----------------------------------------------------------------------
def _default_js(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)

def register(server, js=None) -> int:
    """把覆盖率四个工具注册进 MCP server，返回注册数。"""
    _js = js or _default_js
    n = 0

    @server.tool(
        name="coverage_start",
        title="开始代码覆盖率采集（PC 采样法，不停目标）",
        description=(
            "从 `.axf` 取出**函数区间与可执行行表**（静态事实），再运行期用 DWT 硬件 PC 采样器"
            "（读 `DWT_PCSR`）**不 halt 目标**地反复采 PC，按表归属到函数与行，得到「触达」统计。"
            "适合嵌入式测试闭环里回答「这段代码到底跑到了没有」「回归有没有覆盖到新加的分支」。\n"
            "**它是采样法，不是插桩**：被采样到 ⇒ 一定执行过；**没被采样到 ≠ 没执行过**"
            "（采样点、窗口长度、快路径都会漏）。所以返回里叫 `unseen`（没看到）而不是"
            "`uncovered`（未覆盖）。要证明某段没执行，用断点命中或 trace_instrument。\n"
            "参数：interval_ms=主机读采样器的间隔（默认 10）、elf=指定 .axf（默认用服务器当前那份）、"
            "scope=只统计名字/文件名含该子串的范围（大小写不敏感，如 \"app\"、\"motor.c\"）、"
            "max_samples=采够这么多就自动停（默认 0=不限）、duration_s=采这么久自动停"
            "（默认 0=不限）、enable_dwt=自动开 DEMCR.TRCENA 与 DWT_CTRL.PCSAMPLENA"
            "（默认 true）、restore=收尾时把这两个寄存器恢复原值（默认 true）、link=auto/keil/ocd。\n"
            "**不编数据的三种情形**：① PC 采样器不工作（连续读到的 PC 全一样）→ "
            "`sampler_active=false`、`usable=false`；② 没有 .axf/DWARF → `no-symbol-table`，"
            "不给 0%；③ scope 一条都匹配不到 → `empty-scope`，不当成 0%。\n"
            "接着用 coverage_read 看进展、coverage_stop 收尾。"
        ),
    )
    async def coverage_start(interval_ms: float = 10.0, elf: str = "", scope: str = "",
                             max_samples: int = 0, duration_s: float = 0.0,
                             enable_dwt: bool = True, restore: bool = True,
                             link: str = "auto") -> str:
        try:
            return _js(start(interval_ms=interval_ms, elf=elf, scope=scope,
                             max_samples=max_samples, duration_s=duration_s,
                             enable_dwt=enable_dwt, restore=restore, link=link))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "coverage_start", "error": str(e)})
    n += 1

    @server.tool(
        name="coverage_read",
        title="看当前代码覆盖率（触达的函数/行）",
        description=(
            "读当前覆盖率会话的快照：函数命中数/总数、行命中数/总数、热点函数、"
            "**没被采样到的函数**清单，以及 PC 归属情况（落不到任何函数区间的 `unmapped`）。\n"
            "参数：top=热点函数列前几个（默认 20）、unseen=未触达函数列前几个（默认 20）。\n"
            "采样器没在工作时返回 `usable=false` —— 这份数据不可用，别拿它说「代码没跑到」。"
        ),
    )
    async def coverage_read(top: int = 20, unseen: int = 20) -> str:
        try:
            return _js(read(top=int(top), unseen=int(unseen)))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "coverage_read", "error": str(e)})
    n += 1

    @server.tool(
        name="coverage_stop",
        title="结束代码覆盖率采集并出最终结果",
        description=(
            "停掉后台采样线程，默认把 DEMCR/DWT_CTRL 恢复成开采样前的原值，"
            "返回最终覆盖率。参数：restore（默认 true）、top、unseen。"
        ),
    )
    async def coverage_stop(restore: bool = True, top: int = 20,
                            unseen: int = 20) -> str:
        try:
            return _js(stop(restore=restore, top=int(top), unseen=int(unseen)))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "coverage_stop", "error": str(e)})
    n += 1

    @server.tool(
        name="coverage_clear",
        title="清空代码覆盖率统计",
        description=(
            "把当前覆盖率会话的计数与静态表整体重置，下次 coverage_start 会重新读一遍 .axf。"
            "需要「重跑一遍、只统计这一轮」时用；正在采集的话请先 coverage_stop。"
        ),
    )
    async def coverage_clear() -> str:
        try:
            return _js(clear())
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "coverage_clear", "error": str(e)})
    n += 1
    return n
