# -*- coding: utf-8 -*-
"""复位循环 / 启动失败的自动识别（批次46）。

背景
----
`wait_fault` 抓的是「停下来」的那一次——异常或断点。但嵌入式现场另一种高频
故障形态是**目标反复复位**：启动即死、喂狗超时、HardFault 之后被看门狗兜底……
这类问题没有单次停靠可抓，用户看到的只是「串口一直在打印启动横幅」「烧进去
就是跑不起来」。本模块负责的就是这一种模式的识别。

判据（不依赖具体芯片）
----------------------
Cortex-M 的 DHCSR（0xE000EDF0）自带一个标准位：

- **S_RESET_ST(bit25)**：**读 DHCSR 会清它**；自上次读之后发生过复位则置位。
  于是「按固定间隔读 DHCSR」等价于「按固定间隔问一句：这段时间里复位过吗」。
  既不要求目标已停，也不需要用户提供地址或符号——这是它能跨芯片通用的原因。
- **S_LOCKUP(bit19)**：CPU 已锁死（未处理异常 / 取指失败的连锁）。它是一条硬
  事实，出现即说明存在未处理异常，可以直接指向 fault_report。

诚实边界（宁可说得少，也不编一个像样的结论）
--------------------------------------------
- 复位比采样间隔还快时，每次采样都会看到 S_RESET_ST：这只够得出「一直在复位」，
  **测不出间隔**。此时如实标 `too_fast`，不给中位数、不说「每 X ms 一次」。
- `at_ms` 是**主机侧**时间戳，不是目标时间；两次复位之间目标的时基不连续，
  它只能用来量「复位有多频繁」。
- 判定只到「反复复位 / 锁死」这一层。真正的复位来源（看门狗？掉电？软件 AIRCR？
  调试器复位？）不在推断范围内，只在 advice 里指向能查的工具。
"""
from __future__ import annotations

import asyncio
import time

# DHCSR：Debug Halting Control and Status Register（Cortex-M 系统区，跨厂商一致）
DHCSR = 0xE000EDF0

S_REGRDY = 1 << 16      # 寄存器就绪
S_HALT = 1 << 17        # 内核当前处于 halt
S_SLEEP = 1 << 18       # 内核处于 sleep
S_LOCKUP = 1 << 19      # 内核锁死（未处理异常/取指失败连锁）
S_RETIRE_ST = 1 << 24   # 自上次读以来退休过指令（读即清）
S_RESET_ST = 1 << 25    # 自上次读以来发生过复位（读即清）

# 判定「复位比采样间隔还快」的门槛：绝大多数采样都看见复位位
_TOO_FAST_RATIO = 0.8
_TOO_FAST_MIN_SAMPLES = 3

# 周期稳定性的门槛：最大间隔 / 最小间隔 不超过这个比值才算「间隔稳定」
_PERIODIC_RATIO = 1.3


def decode_dhcsr(v: int) -> dict:
    """把 DHCSR 原始值拆成命名位。返回的键都是 bool（除 raw）。"""
    v = int(v) & 0xFFFFFFFF
    return {
        "raw": "0x%08X" % v,
        "s_reset_st": bool(v & S_RESET_ST),
        "s_retire_st": bool(v & S_RETIRE_ST),
        "s_lockup": bool(v & S_LOCKUP),
        "s_sleep": bool(v & S_SLEEP),
        "s_halt": bool(v & S_HALT),
    }


def interval_stats(intervals_ms) -> dict:
    """相邻复位间隔的统计。样本为空时如实返回 count=0，不编数。"""
    vals = sorted(float(x) for x in intervals_ms if x is not None)
    n = len(vals)
    if n == 0:
        return {"count": 0}
    mid = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0
    out = {
        "count": n,
        "min_ms": round(vals[0], 1),
        "max_ms": round(vals[-1], 1),
        "median_ms": round(mid, 1),
        "mean_ms": round(sum(vals) / n, 1),
    }
    if vals[0] > 0:
        out["max_min_ratio"] = round(vals[-1] / vals[0], 3)
    return out


def classify(reset_count: int, intervals_ms, samples: int,
             too_fast: bool = False, flags_signal: bool = False) -> dict:
    """给出 pattern + verdict。**只依据手上真有的证据**，缺证据就不下结论。

    flags_signal：复位标志寄存器（粘滞位）在窗口内被硬件置起过。它是一份**独立证据**：
    DHCSR.S_RESET_ST 是读即清，Keil 链路在目标复位后会重新同步、自己读一次 DHCSR，
    位就没了；粘滞的复位标志不受这个影响。两者结论冲突时以能解释清楚的那个为准。
    """
    st = interval_stats(intervals_ms)
    if samples <= 0:
        return {"pattern": "no-data", "interval_stats": st,
                "verdict": "一次 DHCSR 都没读成功，这次观测没有可用证据。"}
    if reset_count <= 0:
        if flags_signal:
            return {"pattern": "flags-only", "interval_stats": st,
                    "verdict": ("DHCSR.S_RESET_ST 判据没抓到复位，但复位标志寄存器有位置起——"
                                "**窗口内确实发生过复位，是 DHCSR 判据这次漏报了**：Keil 链路在"
                                "目标复位后要重新同步，同步时它自己会读一次 DHCSR，而 "
                                "S_RESET_ST 是读即清，位就被抹掉了。这种情形以复位标志寄存器为准；"
                                "想量出周期就把 interval_ms 调小（如 20~30）多观测几轮，"
                                "或直接用标志位对应的复位源去查（如看门狗超时）。")}
        return {"pattern": "none", "interval_stats": st,
                "verdict": ("本次观测窗口内没有检测到复位（DHCSR.S_RESET_ST 从未置位）。"
                            "注意：该位读即清、且 Keil 链路在复位后会重同步自行读一次，"
                            "存在漏报可能；要坐实「有没有复位」，给一个 flags_addr"
                            "（芯片复位标志寄存器）做交叉验证。")}
    if too_fast:
        return {
            "pattern": "too_fast", "interval_stats": st,
            "verdict": ("复位频率高于采样间隔：%d 次采样里有 %d 次看到复位位。"
                        "这只能确定「目标一直在复位」，**测不出间隔**——"
                        "把 interval_ms 调小（如 20~30）再观测一次才量得准周期。"
                        % (samples, reset_count)),
        }
    if reset_count == 1:
        return {
            "pattern": "single", "interval_stats": st,
            "verdict": ("观测到 1 次复位，单次不足以判定复位循环——可能是一次手动复位/"
                        "上电，也可能是一次性异常后被看门狗兜底。把 duration_ms 调大"
                        "再观测一次才能区分。"),
        }
    if reset_count == 2:
        return {
            "pattern": "repeat", "interval_stats": st,
            "verdict": ("观测到 2 次复位，间隔约 %s ms。形态已接近复位循环，"
                        "但间隔样本只有 1 个，不足以断言周期稳定；把 duration_ms "
                        "调大再观测可确认。" % st.get("median_ms")),
        }
    ratio = st.get("max_min_ratio")
    if ratio is not None and ratio <= _PERIODIC_RATIO:
        return {
            "pattern": "periodic", "interval_stats": st,
            "verdict": ("**复位循环**：观测到 %d 次复位，间隔稳定在约 %s ms"
                        "（%s~%s ms，共 %d 个间隔样本）。稳定周期通常指向"
                        "「周期性事件把目标复位」——最常见是看门狗喂狗超时，"
                        "其次是启动过程反复死在同一处。"
                        % (reset_count, st.get("median_ms"), st.get("min_ms"),
                           st.get("max_ms"), st.get("count"))),
        }
    return {
        "pattern": "irregular", "interval_stats": st,
        "verdict": ("观测到 %d 次复位，但间隔忽长忽短（%s~%s ms），不像单一固定"
                    "周期的看门狗复位。可能是启动过程随机崩在不同位置，也可能存在"
                    "外部复位源抖动；建议结合 fault_report 看是否有残留异常现场。"
                    % (reset_count, st.get("min_ms"), st.get("max_ms"))),
    }


def advice(pattern: str, flags: dict, sample_pc: bool = False) -> list:
    """按 pattern 与观测到的标志给出下一步该查什么。不含泛泛的套话。"""
    out = []
    flags = flags or {}
    n_reset = pattern not in ("none", "no-data")
    if n_reset:
        out.append("先分辨复位来源：调 watchdog_freeze(action=\"enable\") 冻住 "
                   "IWDG/WWDG 后重跑。若冻住就不再复位，复位源基本就是喂狗超时。")
        out.append("看是不是未处理异常被兜底：fault_report 读 CFSR/HFSR（粘滞位，"
                   "fault_timing.timeliness=sticky 只代表历史上发生过），"
                   "确证要 clear_faults() → run() → fault_report()。")
        out.append("要抓一次完整现场：wait_fault(timeout_ms=...) 会在异常/断点停住时"
                   "自动收集寄存器与调用栈。")
        if not sample_pc:
            out.append("想看每次复位后死在哪儿：用 sample_pc=true 重跑本工具，"
                       "它会在检测到复位后停一下读 PC 与符号落点（**会打断目标**，"
                       "所以默认不开）。")
    if int(flags.get("lockup") or 0) > 0:
        out.append("本次观测里 DHCSR.S_LOCKUP 置位 %d 次——CPU 进过锁死状态"
                   "（未处理异常连锁），这是比普通复位更硬的证据，优先用 "
                   "fault_report / wait_fault 找出那个未处理异常。"
                   % int(flags.get("lockup")))
    if pattern == "too_fast":
        out.append("复位快到测不出周期时，先把 interval_ms 降到 20~30 再看，"
                   "否则「周期」这个结论是编出来的。")
    if pattern == "none":
        out.append("本次没看到复位，不等于没有：观测窗口可能太短，或目标当时压根"
                   "没在跑。确认目标确实在运行（get_status）后把 duration_ms 调大"
                   "（如 20000）再试。")
        out.append("要排除「DHCSR 判据漏报」，给一个 flags_addr（芯片复位标志寄存器，"
                   "如 STM32 的 RCC_CSR）做交叉验证——那类标志是粘滞位，"
                   "不受「读即清」与 Keil 重同步的影响。")
    if pattern == "flags-only":
        out.append("复位标志寄存器已经把「窗口内复位过」坐实了。下一步看标志位对应的"
                   "复位源（喂狗超时？软件复位？引脚复位？），按芯片手册解读 "
                   "reset_flags 里的 set_bits。")
        out.append("DHCSR 判据漏报在这里是可预期的：Keil 链路复位后会重同步并自行读一次 "
                   "DHCSR。要拿到周期，把 interval_ms 压到 20~30 多观测几轮，"
                   "或直接查复位源。")
    return out


def build_report(*, link_name: str, duration_ms: int, interval_ms: int,
                 samples: int, read_fail: int, reset_count: int, resets: list,
                 flags: dict, intervals_ms, too_fast: bool,
                 pc_samples=None, halt_info=None, read_error=None,
                 reset_flags=None) -> dict:
    """汇总成工具返回体。任何一项缺证据就如实留空/标 None，不补默认值。"""
    flags_signal = bool(reset_flags and reset_flags.get("set_bits"))
    cls = classify(reset_count, intervals_ms, samples, too_fast,
                   flags_signal=flags_signal)
    out = {
        "ok": True,
        "action": "watch_reset",
        "link": link_name,
        "duration_ms": duration_ms,
        "interval_ms": interval_ms,
        "samples": samples,
        "read_fail": read_fail,
        "reset_count": reset_count,
        "pattern": cls["pattern"],
        "verdict": cls["verdict"],
        "resets": resets,
        "interval_stats": cls["interval_stats"],
        "flags_seen": dict(flags or {}),
        "advice": advice(cls["pattern"], flags, sample_pc=bool(pc_samples is not None
                                                              or halt_info is not None)),
        "note": ("at_ms 是主机侧时间戳（不是目标时间）；判据是 DHCSR.S_RESET_ST"
                 "（读即清，每次采样代表「上一采样点到本次采样之间复位过」）。"
                 "该位可能被漏报：Keil 链路在目标复位后会重新同步并自行读一次 DHCSR，"
                 "把位清掉——所以 pattern=none 只代表「本次窗口没观测到」，"
                 "要坐实「有没有复位」请给 flags_addr 做交叉验证。"),
    }
    if reset_flags:
        out["reset_flags"] = reset_flags
    if pc_samples is not None:
        out["pc_samples"] = pc_samples
    if halt_info:
        out["halt_info"] = halt_info
    if read_error:
        out["read_error"] = read_error
    return out


# ----------------------------------------------------------------------
# MCP 工具注册
# ----------------------------------------------------------------------
def _default_js(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    """把 watch_reset 注册进 MCP server，返回注册的工具数。"""
    _js = js or _default_js
    from . import linkio as _link

    def _clamp(v, lo, hi, dft):
        try:
            n = int(v)
        except (TypeError, ValueError):
            return dft
        return max(lo, min(hi, n))

    def _locator():
        """取服务器当前那份 locator（set_symbol_file 换符号后是同一个实例）。

        惰性导入：server 会导入本模块，函数内导入避免循环；这里只用于把 PC 翻成
        函数/文件行，拿不到就只给地址，绝不因此让整个观测失败。
        """
        try:
            from . import server as _srv
            return _srv._get_locator()
        except Exception:                                           # noqa: BLE001
            return None

    @server.tool(
        name="watch_reset",
        title="复位循环 / 启动失败自动识别",
        description=(
            "按固定间隔读 Cortex-M 的 DHCSR.S_RESET_ST（一个**读即清**的标准位），"
            "识别「目标反复复位」这类没有单次停靠可抓的故障：启动即死、喂狗超时、"
            "HardFault 之后被看门狗兜底。不需要目标已停，也不需要地址或符号，跨芯片通用。\n"
            "参数：duration_ms=观测时长（默认 5000，200~600000）、interval_ms=采样间隔"
            "（默认 150，20~5000）、max_resets=记录到这么多次复位就提前收工（默认 20）、"
            "sample_pc=每次检测到复位后停一下读 PC 与符号落点（**默认 false**，"
            "开了会打断目标、有副作用）、settle_ms=sample_pc 时复位后等多久再读落点"
            "（默认 120）、link=auto/keil/ocd（本工具两条链路通用，与其它观测工具一致）、"
            "flags_addr=**复位标志寄存器地址**（可选，如 STM32F4 的 RCC_CSR=0x40023874）："
            "窗口前后各读一次，报出被置起/清掉的位置——这是一份**不依赖「读即清」的独立证据**，"
            "能坐实「有没有复位」并给出复位源线索（本工具不解释位含义，按芯片手册读）。\n"
            "返回 pattern / verdict / resets / interval_stats / flags_seen / advice。"
            "pattern 取值：none（窗口内没观测到复位）/ single（1 次，不足以判定循环）/ "
            "repeat（2 次）/ periodic（**复位循环**，间隔稳定）/ irregular（次数够但间隔乱）/ "
            "too_fast（**复位快过采样间隔，只能确定「一直在复位」，测不出周期**）/ "
            "flags-only（**DHCSR 没抓到、但复位标志寄存器有位置起——确实复位过，是前者漏报**）/ "
            "no-data（一次都没读成功）。\n"
            "诚实边界：① S_RESET_ST **读即清**，且 Keil 链路在目标复位后会重新同步并自行读一次 "
            "DHCSR，位会被抹掉——所以 pattern=none 只代表「本次窗口没观测到」，不代表一定没复位；"
            "要坐实请给 flags_addr。② at_ms 是主机侧时间戳（不是目标时间）。③ 本工具只判"
            "「反复复位 / 锁死」，复位来源要结合 reset_flags 的置起位与芯片手册。"
            "④ DHCSR 读不到时直接报错，不假装没有复位。"
        ),
    )
    async def watch_reset(duration_ms: int = 5000, interval_ms: int = 150,
                          max_resets: int = 20, sample_pc: bool = False,
                          settle_ms: int = 120, link: str = "auto",
                          flags_addr: str = "") -> str:
        try:
            lk, err = _link.pick(link, who="观测复位")
            if lk is None:
                return _js(err)
            dur = _clamp(duration_ms, 200, 600000, 5000)
            iv = _clamp(interval_ms, 20, 5000, 150)
            mx = _clamp(max_resets, 1, 200, 20)
            settle = _clamp(settle_ms, 0, 5000, 120)

            # 先空读一次把可能残留的 S_RESET_ST 清掉——否则「上次调试时复位过」
            # 会被算成本次观测窗口里的第一次复位。
            _, meta0 = lk.read_once(DHCSR, 4)
            if meta0 and meta0.get("error"):
                return _js({"ok": False, "link": lk.name, "action": "watch_reset",
                            "reason": "dhcsr-unreadable",
                            "error": "读 DHCSR(0x%08X) 失败：%s"
                                     % (DHCSR, meta0["error"]),
                            "hint": "本工具依赖读取 Cortex-M 系统区的 DHCSR；"
                                    "若当前链路读不到该区域，请改用 fault_report / "
                                    "wait_fault 排查，不要据此认为「目标没有复位」。",
                            "link_meta": meta0})

            # 可选：复位标志寄存器（粘滞位）交叉判据——不受 DHCSR「读即清」与
            # Keil 复位后重同步的影响，是唯一能坐实「窗口内复位过」的独立证据。
            fl_addr = 0
            fl_before = None
            if str(flags_addr or "").strip():
                try:
                    fl_addr = int(str(flags_addr).strip(), 0)
                except ValueError:
                    return _js({"ok": False, "action": "watch_reset",
                                "error_code": "invalid-argument",
                                "error": "flags_addr 必须是地址（0x... 或十进制）：%r"
                                         % (flags_addr,)})
                d, m = lk.read_once(fl_addr, 4)
                if d is None:
                    return _js({"ok": False, "action": "watch_reset", "link": lk.name,
                                "reason": "flags-unreadable",
                                "error": "读复位标志寄存器 0x%08X 失败：%s"
                                         % (fl_addr, (m or {}).get("error")),
                                "hint": "把 flags_addr 留空即可跳过这个附加判据；"
                                        "若地址给错，本工具不会替你猜一个。"})
                fl_before = int.from_bytes(d, "little")

            t0 = time.monotonic()
            resets, intervals = [], []
            flags = {"halt": 0, "sleep": 0, "lockup": 0}
            samples = read_fail = 0
            first_err = None
            last_at = None
            pc_samples = []
            halt_info = {"rounds": 0, "resumed": 0, "halt_failed": 0,
                         "resume_failed": 0}

            async def _one_pc_sample(ev):
                halt_info["rounds"] += 1
                if settle > 0:
                    await asyncio.sleep(settle / 1000.0)
                h = lk.halt() or {}
                if not (h.get("ok") or h.get("status") == 22):
                    halt_info["halt_failed"] += 1
                    ev["pc_error"] = h.get("error") or "停目标失败，读不到落点"
                    return
                r = lk.regs(("pc",)) or {}
                pc = r.get("pc")
                if r.get("ok") and isinstance(pc, int):
                    item = {"at_ms": ev["at_ms"], "pc": "0x%08X" % pc}
                    loc = _locator()
                    if loc is not None:
                        try:
                            if loc.is_ready():
                                cur = loc.locate(pc & ~1)
                                if isinstance(cur, dict):
                                    item["covered"] = cur.get("covered")
                                    if cur.get("file"):
                                        item["file"] = cur["file"]
                                        item["line"] = cur.get("line")
                                    elif cur.get("nearest_file"):
                                        item["nearest_file"] = cur["nearest_file"]
                                        item["nearest_line"] = cur.get("nearest_line")
                                        item["symbol_note"] = (
                                            "该地址不在符号表覆盖范围内，只给最近"
                                            "条目供参考，别当它就是当前函数")
                        except Exception as e:                      # noqa: BLE001
                            item["symbol_error"] = str(e)
                    pc_samples.append(item)
                    ev["pc"] = item["pc"]
                    if item.get("file"):
                        ev["pc_file"] = "%s:%s" % (item["file"], item.get("line"))
                else:
                    halt_info["halt_failed"] += 1
                    ev["pc_error"] = r.get("error") or "读 PC 失败"
                rr = lk.resume() or {}
                if rr.get("ok") or rr.get("status") == 22:
                    halt_info["resumed"] += 1
                else:
                    halt_info["resume_failed"] += 1
                    ev["resume_error"] = rr.get("error") or "恢复运行失败"

            while True:
                if (time.monotonic() - t0) * 1000.0 >= dur:
                    break
                data, meta = lk.read_once(DHCSR, 4)
                if data is None:
                    read_fail += 1
                    if first_err is None:
                        first_err = (meta or {}).get("error") or "读 DHCSR 失败"
                    if read_fail >= 3:
                        break
                else:
                    samples += 1
                    dec = decode_dhcsr(int.from_bytes(data, "little"))
                    for k in ("halt", "sleep", "lockup"):
                        if dec["s_" + k]:
                            flags[k] += 1
                    if dec["s_reset_st"] and len(resets) < mx:
                        at = (time.monotonic() - t0) * 1000.0
                        ev = {"at_ms": round(at, 1), "dhcsr": dec["raw"],
                              "lockup": dec["s_lockup"]}
                        if last_at is not None:
                            d = round(at - last_at, 1)
                            ev["since_prev_ms"] = d
                            intervals.append(d)
                        last_at = at
                        resets.append(ev)
                        if sample_pc:
                            await _one_pc_sample(ev)
                if len(resets) >= mx:
                    break
                await asyncio.sleep(iv / 1000.0)

            reset_flags = None
            if fl_addr:
                d2, m2 = lk.read_once(fl_addr, 4)
                if d2 is None:
                    reset_flags = {
                        "addr": "0x%08X" % fl_addr,
                        "before": "0x%08X" % fl_before,
                        "error": (m2 or {}).get("error") or "窗口结束时读不回",
                        "note": "这是交叉判据，读不回只说明本次没有拿到这份证据，"
                                "不代表没有复位。"}
                else:
                    fl_after = int.from_bytes(d2, "little")
                    changed = [i for i in range(32)
                               if ((fl_before ^ fl_after) >> i) & 1]
                    reset_flags = {
                        "addr": "0x%08X" % fl_addr,
                        "before": "0x%08X" % fl_before,
                        "after": "0x%08X" % fl_after,
                        "changed_bits": changed,
                        "set_bits": [i for i in changed if (fl_after >> i) & 1],
                        "note": "这些位是窗口内被硬件置起/清掉的复位源标志。"
                                "本工具**不解释位含义**（各厂商布局不同），按你芯片的"
                                "手册解读；例如 STM32 的 RCC_CSR：bit26 PINRSTF(NRST 引脚)、"
                                "bit27 PORRSTF(上电/掉电)、bit28 SFTRSTF(软件复位)、"
                                "bit29 IWDGRSTF(独立看门狗)、bit30 WWDGRSTF(窗口看门狗)、"
                                "bit31 LPWRRSTF(低功耗)。注意这些是粘滞位，"
                                "上一轮遗留的标志也会出现在 before 里——只看 changed_bits。"}

            too_fast = (samples >= _TOO_FAST_MIN_SAMPLES
                        and len(resets) >= max(2, int(samples * _TOO_FAST_RATIO)))
            out = build_report(
                link_name=lk.name, duration_ms=dur, interval_ms=iv,
                samples=samples, read_fail=read_fail, reset_count=len(resets),
                resets=resets, flags=flags, intervals_ms=intervals,
                too_fast=too_fast,
                pc_samples=(pc_samples if sample_pc else None),
                halt_info=(halt_info if sample_pc else None),
                read_error=(first_err if read_fail else None),
                reset_flags=reset_flags)
            if read_fail:
                out["warning"] = ("观测中有 %d 次读 DHCSR 失败（首次：%s）——"
                                  "这段窗口里漏掉多少次复位说不准。"
                                  % (read_fail, first_err))
            if len(resets) >= mx:
                out["stopped_early"] = ("达到 max_resets=%d 提前收工，"
                                        "实际复位次数可能更多。" % mx)
            return _js(out)
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "watch_reset", "error": str(e)})
    return 1
