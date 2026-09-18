# -*- coding: utf-8 -*-
"""多核目标的**核识别与区分**（批次47）。

为什么需要它
------------
H7 双核（CM7 + CM4）、RP2040 双核（M0+ × 2）这类目标上，最容易踩的坑不是「读不到」，
而是**读到了另一个核**：两个核的 SCS 地址完全一样（0xE000E000 这一段在各自的核里），
所以「读到的 CPUID / DHCSR / 断点」到底属于谁，取决于调试器当前挂在哪个 AP 上——
而不是取决于你写的地址。本模块做的事就是把这个前提**问清楚、说出来**。

两条链路的能力**不对称，而且这个不对称是真实的**
------------------------------------------------
- **OpenOCD**：支持列出与切换 target（`targets` / `targets <名>`），两个核是两个 target。
  所以 `core_list` / `core_select` 在它上面是真的能用。
- **Keil / UVSOCK**：一条 UVSOCK 会话绑的是**当前调试的那个工程/那个核**，
  协议里没有「换一个核」这种操作。所以 Keil 侧 `core_list` 会给
  `reason="unsupported-on-keil"` 并把替代做法讲清楚（双核要分别在两个 target/工程里连，
  切 target 用 `set_debug_target`），**不会假装做了一个核切换**。

`core_info` 则是两条链路都能做的：读 CPUID 报出内核型号，并明确「你现在连的是哪一个核」
——在单核芯片上这是确认，在双核芯片上是**提醒你别把另一个核的现场当成这个核的**。
"""
from __future__ import annotations

# CPUID（Cortex-M 的 SCS 内，跨厂商一致）
CPUID = 0xE000ED00

_IMPLEMENTER = {0x41: "ARM"}

# ARM 的 CPUID PARTNO（bits[15:4]）。这张表只收录确定的项，其余一律 unknown。
_PARTNO = {
    0xC20: "Cortex-M0",
    0xC21: "Cortex-M1",
    0xC23: "Cortex-M3",
    0xC24: "Cortex-M4",
    0xC27: "Cortex-M7",
    0xC60: "Cortex-M0+",
    0xD20: "Cortex-M23",
    0xD21: "Cortex-M33",
    0xD22: "Cortex-M55",
    0xD23: "Cortex-M85",
}

def decode_cpuid(v: int) -> dict:
    """解 CPUID：实现者、变体、型号、修订。未知型号如实标 unknown，不硬猜。"""
    v = int(v) & 0xFFFFFFFF
    impl = (v >> 24) & 0xFF
    partno = (v >> 4) & 0xFFF
    return {"raw": "0x%08X" % v,
            "implementer": "0x%02X" % impl,
            "implementer_name": _IMPLEMENTER.get(impl),
            "variant": "0x%X" % ((v >> 20) & 0xF),
            "partno": "0x%03X" % partno,
            "core": _PARTNO.get(partno),
            "revision": "p%d" % ((v >> 0) & 0xF),
            "core_known": partno in _PARTNO,
            "note": ("型号是按 ARM 的 CPUID PARTNO 表查的；表里没有的一律给 null，"
                     "不拿别的型号顶上。")}

_TARGET_ROW = None

def parse_targets(output: str) -> list:
    """解析 OpenOCD 的 ``targets`` 输出。

    典型：
    ```
        TargetName         Type       Endian TapName            State
    --  ------------------ ---------- ------ ------------------ -----------
     0* rp2040.core0       cortex_m   little rp2040.cpu0       running
     1  rp2040.core1       cortex_m   little rp2040.cpu1       halted
    ```
    行首的 ``0*`` 表示**当前选中的那个 target**（星号）。解析不出来的行直接跳过，
    不编。
    """
    import re
    rows = []
    seen_header = False
    for raw in str(output or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if "TargetName" in line:
            seen_header = True
            continue
        if set(line.strip()) <= set("- "):
            continue
        m = re.match(r"^\s*(\d+)\s*(\*?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
                     line)
        if not m:
            if not seen_header and "Error" in line:
                return {"parse_error": line.strip()}
            continue
        rows.append({"index": int(m.group(1)), "current": m.group(2) == "*",
                     "name": m.group(3), "type": m.group(4),
                     "endian": m.group(5), "tap": m.group(6), "state": m.group(7)})
    return rows

def _ocd_session():
    try:
        from . import ocd as _ocd
        s = _ocd.get_session()
        if s is None or not s.running():
            return None, "OpenOCD 没在运行（先 ocd_start）"
        return s, None
    except Exception as e:                                          # noqa: BLE001
        return None, "取 OpenOCD 会话失败：%s" % e

def list_cores(link: str = "auto") -> dict:
    """列出可用核。OpenOCD 侧是真列；Keil 侧如实报不支持并给替代做法。"""
    want = str(link or "auto").strip().lower()
    if want in ("keil", "mdk", "uvsock", "uv4"):
        want = "keil"
    elif want in ("ocd", "openocd", "daplink"):
        want = "ocd"
    elif want in ("auto", ""):
        want = "auto"
    else:
        return {"ok": False, "action": "core_list", "reason": "bad-link-name",
                "error": "link 只能是 auto / keil / ocd（收到 %r）" % (link,)}
    s, err = _ocd_session()
    if want == "keil":
        return _keil_unsupported("core_list")
    if s is None:
        if want == "ocd":
            return {"ok": False, "action": "core_list", "reason": "no-ocd-link",
                    "error": err,
                    "hint": "非 MDK 目标：ocd_start → ocd_control(\"halt\")；"
                            "Keil 侧则只有一个核（当前调试的那个）。"}
        # auto 且 OpenOCD 不在：Keil 侧本来就列不出多核
        return _keil_unsupported("core_list", extra="（auto 且 OpenOCD 没在运行）")
    r = s.cmd("targets", timeout=5)
    if not r.get("ok"):
        return {"ok": False, "action": "core_list", "link": "ocd",
                "error": (r.get("error") or r.get("output") or "targets 失败").strip()[:200]}
    rows = parse_targets(r.get("output") or "")
    if isinstance(rows, dict):
        return {"ok": False, "action": "core_list", "link": "ocd",
                "error": rows["parse_error"]}
    cur = next((x["name"] for x in rows if x["current"]), None)
    return {"ok": True, "action": "core_list", "link": "ocd",
            "targets": rows, "count": len(rows), "current": cur,
            "note": ("OpenOCD 里一个 target 就是一个核；带 * 的是**当前选中**的那个。"
                     "所有读内存/寄存器/断点命令都作用在选中的 target 上——"
                     "双核排查时先 core_list 确认选中的是谁，别把另一个核的现场当成这个核的。")}

def _keil_unsupported(action: str, extra: str = "") -> dict:
    return {"ok": False, "action": action, "reason": "unsupported-on-keil",
            "link": "keil",
            "error": "Keil/UVSOCK 链路没有「列出/切换核」的能力%s" % extra,
            "why": ("UVSOCK 的一条会话绑的是**当前调试的那个工程/那个核**，协议里没有"
                    "「换一个核」这种操作。双核芯片（H7 的 CM7+CM4、RP2040 的 M0+×2）"
                    "在 Keil 里是两个独立 target/工程，各自有自己的调试会话。"),
            "how_to": ["双核要分别连：用工程里对应的 target（`project_targets` 列出、"
                       "`set_debug_target` 切换）",
                       "想在一次会话里同时看两个核，用非 MDK 链路："
                       "`ocd_start` → `core_list` → `core_select`"],
            "note": "本工具不会假装做了一个核切换——切错了会给你另一个核的现场。"}

def select_core(name: str, link: str = "auto") -> dict:
    """选一个核（OpenOCD：``targets <名>``）。Keil 侧明确不支持。"""
    want = str(link or "auto").strip().lower()
    if want in ("keil", "mdk", "uvsock", "uv4"):
        return _keil_unsupported("core_select")
    s, err = _ocd_session()
    if s is None:
        return {"ok": False, "action": "core_select", "reason": "no-ocd-link",
                "error": err,
                "hint": "非 MDK 目标：ocd_start → ocd_control(\"halt\")"}
    want_name = str(name or "").strip()
    if not want_name:
        return {"ok": False, "action": "core_select", "reason": "invalid-argument",
                "error": "要选哪个核？name 不能为空",
                "hint": "先用 core_list 看有哪些（如 rp2040.core0 / rp2040.core1）"}
    cur = list_cores("ocd")
    names = [t["name"] for t in (cur.get("targets") or [])] if cur.get("ok") else []
    if names and want_name not in names:
        return {"ok": False, "action": "core_select", "reason": "bad-core-name",
                "error": "没有这个核：%r" % want_name, "available": names,
                "hint": "核名必须与 core_list 给的一字不差；本工具不会退化成最近的那个。"}
    r = s.cmd("targets %s" % want_name, timeout=5)
    if not r.get("ok"):
        return {"ok": False, "action": "core_select", "link": "ocd", "target": want_name,
                "error": (r.get("error") or r.get("output") or "targets 切换失败").strip()[:200]}
    after = list_cores("ocd")
    if not after.get("ok") or after.get("current") != want_name:
        return {"ok": False, "action": "core_select", "link": "ocd",
                "target": want_name,
                "error": "发完切换命令后，当前选中的仍不是 %r" % want_name,
                "current": after.get("current"),
                "hint": "不把「命令没报错」当成「切换成功」；请 core_list 复核。"}
    return {"ok": True, "action": "core_select", "link": "ocd", "target": want_name,
            "current": after.get("current"),
            "note": "后续所有读内存/寄存器/断点都作用在这个核上。"}

def core_info(link: str = "auto") -> dict:
    """读 CPUID，报出当前挂着的这个核是什么；并明确「多核下这不代表另一个核」。"""
    from . import linkio as _link
    lk, lerr = _link.pick(link, who="读 CPUID")
    if lk is None:
        out = dict(lerr)
        out["action"] = "core_info"
        return out
    data, meta = lk.read(CPUID, 4)
    if data is None or len(data) < 4:
        return {"ok": False, "action": "core_info", "link": lk.name,
                "reason": "cpuid-unreadable",
                "error": "读 CPUID(0x%08X) 失败：%s"
                         % (CPUID, (meta or {}).get("error")),
                "hint": "CPUID 在 Cortex-M 的 SCS 里；读不到通常说明目标没连上、"
                        "或者这不是 Cortex-M（RISC-V/Xtensa 用 mvendorid/marchid）。"}
    dec = decode_cpuid(int.from_bytes(data[:4], "little"))
    out = {"ok": True, "action": "core_info", "link": lk.name, "cpuid": dec}
    dc = lk.describe() if hasattr(lk, "describe") else {}
    if dc.get("debugging") is not None:
        out["link_state"] = {"debugging": dc.get("debugging"),
                             "running": dc.get("running"),
                             "status_text": dc.get("status_text")}
    if lk.name == "keil":
        out["core_identity"] = {
            "how": "Keil/UVSOCK：一条会话绑当前调试的那个工程/那个核",
            "note": ("CPUID 是**当前这条会话挂着的核**的。双核芯片上，另一个核有它自己的 "
                     "CPUID，地址一样、值可能不同——要确认「现在到底看的哪个核」，"
                     "得回到工程/target 层面（project_targets / set_debug_target）。")}
    else:
        cur = list_cores("ocd")
        out["core_identity"] = {
            "how": "OpenOCD：CPUID 属于**当前选中的 target**",
            "current_target": cur.get("current") if cur.get("ok") else None,
            "targets": ([t["name"] for t in cur["targets"]] if cur.get("ok") else None),
            "note": ("不是最后一个核就一定是你的核：core_list 里带 * 的才是当前选中的。"
                     "多核上建议每次读现场前先 core_list 复核一次。")}
    out["note"] = ("CPUID 只说明「这是哪一款内核」，不说明「这是哪个核实例」；"
                   "多核目标上后者只能由调试器的 AP/target 选择决定，本工具不猜。")
    return out

# ----------------------------------------------------------------------
# MCP 工具注册
# ----------------------------------------------------------------------
# 别名：register() 里的工具处理函数也叫 core_info，若不另起名字，
# 处理函数体内调用 core_info() 会被自身遮蔽（拿到协程对象）——真机暴露过。
_core_info_impl = core_info

def _default_js(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)

def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="core_list",
        title="列出可用核（多核目标）",
        description=(
            "H7 双核 / RP2040 双核这类目标上，先搞清楚**调试器现在挂的是哪个核**——"
            "两个核的 SCS 地址完全一样（0xE000E000 那段），所以「读到的 CPUID/断点是谁的」"
            "只由调试器当前选中的 AP/target 决定。\n"
            "OpenOCD 链路：真列（执行 `targets`），返回每个 target 的 名字/类型/状态，"
            "带 `*` 的是当前选中的那个。\n"
            "Keil/UVSOCK 链路：**如实报不支持**（`reason=\"unsupported-on-keil\"`）——"
            "UVSOCK 一条会话就绑当前调试的那个核，协议里没有换核操作；双核要分别在两个 "
            "target/工程里连（`project_targets` / `set_debug_target`）。"
            "本工具不会假装做了一次核切换。"
        ),
    )
    async def core_list(link: str = "auto") -> str:
        try:
            return _js(list_cores(link))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "core_list", "error": str(e)})
    n += 1

    @server.tool(
        name="core_select",
        title="选择调试的核（仅 OpenOCD 链路）",
        description=(
            "切换 OpenOCD 当前选中的 target（等价于换一个核）。核名必须与 `core_list` "
            "给的**一字不差**，给错了直接报 `bad-core-name` 并列出可用值——"
            "**不会退化成「最近的那个核」**，那等于把另一个核的现场端上来。\n"
            "切换后会**再查一遍**确认当前选中的确实是它，不把「命令没报错」当成功。\n"
            "Keil/UVSOCK 链路：如实报不支持（原因见返回值 `why`/`how_to`）。"
        ),
    )
    async def core_select(name: str, link: str = "auto") -> str:
        try:
            return _js(select_core(name, link))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "core_select", "error": str(e)})
    n += 1

    @server.tool(
        name="core_info",
        title="当前核是什么（CPUID 解码）",
        description=(
            "读 Cortex-M 的 CPUID（0xE000ED00）解出实现者 / 型号 / 修订，"
            "型号按 ARM 的 PARTNO 表查（M0/M0+/M3/M4/M7/M23/M33/M55/M85），"
            "**表里没有的一律给 null，不拿别的型号顶上**。\n"
            "同时交代「这个值属于哪个核」：Keil 链路说明它属于当前调试的那个工程/核；"
            "OpenOCD 链路会带上当前选中的 target 与全部 target 名单，提醒你"
            "**不是最后一个核就一定是你的核**。\n"
            "多核目标上的定位是**提醒**：它证明「这是哪一款内核」，"
            "不证明「这是哪个核实例」——后者只能由调试器的 AP/target 选择决定。"
        ),
    )
    async def core_info(link: str = "auto") -> str:
        try:
            return _js(_core_info_impl(link))
        except Exception as e:                                      # noqa: BLE001
            return _js({"ok": False, "action": "core_info", "error": str(e)})
    n += 1
    return n
