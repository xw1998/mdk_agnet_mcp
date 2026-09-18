# -*- coding: utf-8 -*-
"""硬件 ETM/ETB 指令级 trace 的**能力探测**（批次47 / P7）。

这个模块解决的是一个**预期管理**问题
------------------------------------
「Cortex-M4/M7 带 ETM，能不能像 SWO/ITM 那样抓指令流？」——能不能，取决于三件互相独立的事：

1. **芯片上有没有这个单元**（IP 可选，很多 M4 根本没接 ETM 或没把 trace 引出来）；
2. **调试链路能不能配它**（需要 DAP 能写 ETM 的寄存器、能给 trace 时钟）；
3. **能不能把 trace 数据收上来**（TPIU/ATB 要接到探针的 trace 引脚，或经 ETB/ETR 落在 RAM 里）。

本工具只做**可以确实做到的事**：把 1 探测出来、把 2/3 的真实能力如实交代清楚。
它**不假装**做了一次指令 trace——抓不到就说抓不到，并给出这个场合真正能用的替代方案。

判据只依据**有出处的事实**，不硬猜
----------------------------------
- CoreSight 组件 ID 寄存器在组件内的固定偏移（0xFD0/0xFE0/0xFF0 起，共 12 个字），
  以及 `PIDR0[7:0] + PIDR1[3:0]<<8 = 部件号`、`CIDR0 == 0x0D` 表示是合法 CoreSight 组件：
  这是 CoreSight 架构规定的，不是本模块的发明。
- Cortex-M4 PIL 的调试内存地图里，`0xE0041000 - 0xE0041FFF` 就是 **ETM trace unit** 的窗口
  （见 Cortex-M4 TRM「Cortex-M4 PIL debug memory map」）。所以「这个窗口里有合法
  CoreSight 组件」就说明 ETM 单元在，且接在常规 PPB 窗口上。
- **不做 PID → 组件名字的硬猜**：本模块不内置一张未经验证的部件号名称表。
  取到的是原始部件号 + 组件类别（0x1 = ROM Table、0x9 = CoreSight 组件，这两个类别码是
  架构规定的），要确认具体是哪一款 ETM，请拿返回的地址/部件号对照芯片或内核 TRM。
"""
from __future__ import annotations

# CoreSight 组件 ID 块在组件内的偏移（架构固定）
ID_PID4 = 0xFD0          # PIDR4
ID_PID0 = 0xFE0          # PIDR0
ID_CID0 = 0xFF0          # CIDR0
ID_COUNT = 12            # 0xFD0 .. 0xFFC 共 12 个字（PID4..7 四个 + PID0..3 四个 + CID0..3 四个）

# Cortex-M 的 ROM table 常规基地址（Cortex-M3/M4/M7 都在这里；M0/M0+ 也可能有）
ROM_BASE_DEFAULT = 0xE00FF000

# Cortex-M4 PIL 调试内存地图：这个窗口就是 ETM trace unit
ETM_WINDOW = 0xE0041000
ETM_WINDOW_SIZE = 0x1000          # 0xE0041000 - 0xE0041FFF

# 组件类别（PIDR1[7:4]）。只收录架构明确规定的两档，其余给 None。
_CLASS = {
    0x1: "ROM Table（组件目录）",
    0x9: "CoreSight 组件（调试/跟踪单元）",
}

# ROM table 条目里"这个地址属于哪类东西"不做 PID 猜名，只按架构能说清的讲
_END_MARK = 0x00000000


def decode_ids(words) -> dict:
    """解一组 CoreSight 组件 ID 字（12 个字，从 0xFD0 起）。

    ``words`` 顺序：PID4, PID5, PID6, PID7, PID0, PID1, PID2, PID3, CID0, CID1, CID2, CID3。
    长度不足 12 时按有的算，缺的给 None——**不拿 0 顶替**，因为 0 是"读到 0"还是
    "没读到"对外是两码事。
    """
    def w(i):
        return int(words[i]) & 0xFFFFFFFF if i < len(words) else None
    pid = [w(4), w(5), w(6), w(7)]
    cid = [w(8), w(9), w(10), w(11)]
    out = {"pid": ["0x%08X" % x if x is not None else None for x in pid],
           "cid": ["0x%08X" % x if x is not None else None for x in cid],
           "pid4_7": ["0x%08X" % x if x is not None else None for x in (w(0), w(1), w(2), w(3))]}
    if pid[0] is None or pid[1] is None:
        out.update({"part": None, "class_code": None, "class_name": None,
                    "valid": None,
                    "note": "ID 没读全，判断不了——不给结论，不拿默认值顶。"})
        return out
    part = (pid[0] & 0xFF) | ((pid[1] & 0x0F) << 8)
    cls = (pid[1] >> 4) & 0xF
    out["part"] = "0x%03X" % part
    out["part_raw"] = part
    out["class_code"] = "0x%X" % cls
    out["class_name"] = _CLASS.get(cls)
    # CoreSight 合法组件的判据：CIDR0 低字节必须是 0x0D（前导码）
    out["valid"] = (cid[0] is not None and (cid[0] & 0xFF) == 0x0D)
    if not out["valid"]:
        out["note"] = ("ID 块不像合法 CoreSight 组件（CIDR0 低字节应为 0x0D）——"
                       "这个地址上大概不是标准组件，或读回来的是脏数据。")
    else:
        out["note"] = ("部件号是按 CoreSight 架构的拼法算的（PIDR0[7:0] + PIDR1[3:0]<<8）；"
                       "本模块不内置部件号→名字的猜测表，名称请对照芯片/内核 TRM，"
                       "类别按 PIDR1[7:4] 给。")
    return out


def parse_rom_entries(words, base: int = ROM_BASE_DEFAULT) -> list:
    """解 ROM table 的条目序列（每项一个 32 位字）。

    - bit0=1 表示该项有效；bit1=1 表示 32 位偏移格式；
    - bits[31:12] 是**相对本 ROM table 基址的有符号偏移**（负数是合法的，指向基址之前）；
    - 遇到 0 结束。
    解析不出来（项说有效但字段没意义）不编，只如实带出来。
    """
    rows = []
    for i, raw in enumerate(words or []):
        v = int(raw) & 0xFFFFFFFF
        if v == _END_MARK:
            break
        present = bool(v & 0x1)
        fmt32 = bool(v & 0x2)
        off = v & 0xFFFFF000
        if off & 0x80000000:                     # 有符号
            off -= 0x100000000
        rows.append({"index": i, "raw": "0x%08X" % v, "present": present,
                     "format": ("32-bit" if fmt32 else "8-bit"),
                     "offset": off,
                     "address": "0x%08X" % ((base + off) & 0xFFFFFFFF)})
        if len(rows) >= 32:                      # 正常 ROM table 到不了这么多
            break
    return rows


def looks_like_coresight(words) -> bool:
    """一个地址上读回来的 ID 块是不是合法 CoreSight 组件。"""
    return bool(decode_ids(words).get("valid"))


def _read_ids(link_obj, base: int):
    """读一个组件基址上的 ID 块，返回 (words, meta)。失败返回 (None, meta)。"""
    data, meta = link_obj.read(base + ID_PID4, ID_COUNT * 4)
    if not data or len(data) < ID_COUNT * 4:
        return None, meta
    return [int.from_bytes(data[i * 4:i * 4 + 4], "little") for i in range(ID_COUNT)], meta


def probe(link: str = "auto", rom_base: int = 0, scan: bool = True) -> dict:
    """探测 ETM：ROM table 走一遍 + 常规 ETM 窗口认一认 + 两条链路的抓取能力。

    返回里三件事分得很开，不要混着读：
    - ``present``：芯片上有没有这个单元。``True``/``False``/``None``（**None = 没测出来**）
    - ``supported``：当前链路能不能抓。恒为 ``False``，原因见 ``why``
    - ``alternatives``：这个场合真正能用的替代方案
    """
    from . import linkio as _link
    lk, lerr = _link.pick(link, who="探测 ETM")
    if lk is None:
        out = dict(lerr)
        out["action"] = "trace_etm_probe"
        return out

    out = {"ok": True, "action": "trace_etm_probe", "link": lk.name,
           "supported": False,
           "capture_answer": "抓不到指令级 trace（本工具不提供 ETM 抓取，理由见 why）"}

    # ---- 1) ROM table ----
    rb = int(rom_base) if rom_base else ROM_BASE_DEFAULT
    rom = {"base": "0x%08X" % rb, "read": False}
    if scan:
        words, meta = None, None
        try:
            words, meta = _read_ids(lk, rb)
        except Exception as e:                                        # noqa: BLE001
            meta = {"error": str(e)}
        if words is None:
            rom["error"] = (meta or {}).get("error") or "读 ID 块失败"
            rom["verdict"] = "unreadable"
            out["rom_table"] = rom
            out["present"] = None
            out["present_reason"] = ("ROM table 读不出来 → **不给结论**。"
                                     "读不到不等于没有，可能是目标没 halt、"
                                     "或者这条链路读 PPB 受限。")
        else:
            rom["read"] = True
            rom["ids"] = decode_ids(words)
            if not looks_like_coresight(words):
                rom["verdict"] = "not-a-rom-table"
                out["rom_table"] = rom
                out["present"] = None
                out["present_reason"] = ("0x%08X 上的 ID 块不是合法 CoreSight 组件，"
                                         "**不能据此判断有没有 ETM**。" % rb)
            else:
                rom["verdict"] = "ok"
                ent = []
                for e_i in range(0, 8):
                    try:
                        d, _m = lk.read(rb + e_i * 4, 4)
                    except Exception:                                 # noqa: BLE001
                        break
                    if not d or len(d) < 4:
                        break
                    ent.append(int.from_bytes(d[:4], "little"))
                rom["entries"] = parse_rom_entries(ent, rb)
                out["rom_table"] = rom
    else:
        out["rom_table"] = rom

    # ---- 2) 常规 ETM 窗口 ----
    win = {"base": "0x%08X" % ETM_WINDOW, "size": "0x%X" % ETM_WINDOW_SIZE,
           "source": "Cortex-M4 PIL 调试内存地图（0xE0041000-0xE0041FFF = ETM trace unit）"}
    wwords = None
    try:
        wwords, wmeta = _read_ids(lk, ETM_WINDOW)
    except Exception as e:                                            # noqa: BLE001
        wwords, wmeta = None, {"error": str(e)}
    if wwords is None:
        win["read"] = False
        win["error"] = (wmeta or {}).get("error") or "读 ID 块失败"
        win["verdict"] = "unreadable"
        if out.get("present") is None:
            out["present"] = None
            out.setdefault("present_reason",
                           "ROM table 与 ETM 窗口都读不出来 → **不给结论**，"
                           "只能说明这次探测没拿到证据。")
    else:
        win["read"] = True
        win["ids"] = decode_ids(wwords)
        if win["ids"].get("valid"):
            win["verdict"] = "etm-unit-present"
            out["present"] = True
            out["present_reason"] = ("0x%08X 上是合法 CoreSight 组件 → 这颗核**有** ETM 单元，"
                                     "且接在常规 PPB 窗口上。" % ETM_WINDOW)
        else:
            win["verdict"] = "no-component"
            if out.get("present") is None:
                # 只有「ROM table 确实读通了」才敢下「没有 ETM」的结论；
                # ROM table 没读通时，窗口读不到只能算「没测出来」。
                if out.get("rom_table", {}).get("verdict") == "ok":
                    out["present"] = False
                    out["present_reason"] = (
                        "ROM table 可读、但 0x%08X 上没有合法 CoreSight 组件 → "
                        "这颗核的常规窗口里**没有 ETM 单元**（IP 未实现，或没接在 PPB 上）。"
                        % ETM_WINDOW)
                else:
                    out["present"] = None
                    out["present_reason"] = "没拿到能下结论的证据 → 不给结论。"
    out["etm_window"] = win

    # ---- 3) 两条链路的抓取能力（真实情况，如实说）----
    out["why"] = ("ETM 抓到指令流需要三件事同时成立：单元在、链路能配、数据能收上来。"
                  "即使 present=true（单元在），本工具所在的两条链路都没有把 ETM 数据"
                  "收上来的通道：Keil/UVSOCK 协议里没有 trace 抓取接口（Keil 的 ETM/指令"
                  "trace 窗口走的是 ULINKpro 的 trace 数据流）；OpenOCD 对 Cortex-M 不提供 "
                  "ETM 指令 trace 的抓取驱动（它的 etm 驱动面向 ARM7/9 与部分 A/R）。"
                  "所以这里给 supported=false，而不是给你一份看起来像 trace 的空数据。")
    out["what_it_takes"] = [
        "探针要能收 trace：Keil 侧要 ULINKpro 这类带 trace 引脚的探针 + Keil 的 Trace 配置；"
        "OpenOCD 侧要探针支持 SWO/trace 引脚且目标把 TPIU 引出来",
        "目标要配好 ETM→TPIU（或 ETM→ETB/ETR 落 RAM）的通路，并且 trace 时钟要使能",
    ]
    out["alternatives"] = [
        {"tool": "trace_guide", "when": "先看这台机器/这条链路到底有哪些 trace 手段可用"},
        {"tool": "trace_swo_start / trace_events / trace_decode",
         "when": "有 SWO 引脚时抓 ITM printf 与事件，非停机（最常用）"},
        {"tool": "trace_rtt_attach / trace_rtt_read",
         "when": "有调试器数据通路时用 RTT，带宽比 SWO 高，也是非停机"},
        {"tool": "trace_pcsample / coverage_start",
         "when": "只想看「跑到哪些函数/行」——DWT PC 采样，不需要任何额外引脚"},
        {"tool": "trace_scope_start / profile_sampling",
         "when": "要看变量随时间怎么变、函数耗时分布（非停机轮询）"},
    ]
    out["note"] = ("present 与 supported 是两件事：present 说芯片上有没有这个单元，"
                   "supported 说当前链路能不能抓。这里 present 可能为 None——"
                   "**没测出来就说没测出来**，不拿「抓不到」冒充「没有」。")
    return out


# ----------------------------------------------------------------------
# MCP 工具注册
# ----------------------------------------------------------------------
def _default_js(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="trace_etm_probe",
        title="ETM/ETB 指令级 trace 能力探测",
        description=(
            "问「这块板子能不能抓 ETM 指令级 trace」，并给出**能站得住的答案**：\n"
            "1) 走一遍 CoreSight ROM table（默认 0xE00FF000），列出条目与各组件 ID；\n"
            "2) 认一认常规 ETM 窗口 0xE0041000（Cortex-M4 PIL 调试地图里这段就是 ETM trace "
            "unit），窗口上是合法 CoreSight 组件就说明**单元在**；\n"
            "3) 交代两条链路的真实抓取能力，并给出替代方案。\n"
            "判据分得很清：`present`（芯片上有没有）与 `supported`（当前链路能不能抓）是两件事；"
            "ROM table 读不出来时 `present=null` 并说明「没测出来」，**不拿「抓不到」冒充「没有」**。"
            "不做部件号→名字的硬猜：只给原始部件号与架构规定的组件类别码，名称请对照 TRM。"
            "本工具**不抓 trace**；supported 恒为 false，抓不到就不会给你一份像 trace 的空数据。"
        ),
    )
    async def trace_etm_probe(link: str = "auto", rom_base: str = "", scan: bool = True) -> str:
        try:
            rb = int(str(rom_base).strip(), 0) if str(rom_base or "").strip() else 0
        except Exception:                                             # noqa: BLE001
            return _js({"ok": False, "action": "trace_etm_probe",
                        "reason": "invalid-argument",
                        "error": "rom_base 认不出：%r（给 0x 开头的十六进制或十进制）" % rom_base})
        try:
            return _js(probe(link, rom_base=rb, scan=bool(scan)))
        except Exception as e:                                        # noqa: BLE001
            return _js({"ok": False, "action": "trace_etm_probe", "error": str(e)})
    n += 1
    return n
