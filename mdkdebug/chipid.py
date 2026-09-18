# -*- coding: utf-8 -*-
"""芯片身份与环境一致性判定（批次49）。

两条真机反馈其实同一个根因：**工具信任"工程配置"，而不去核对"板上真实是什么"**。

* 符号自动绑定错位：烧的是 special 工程的固件，enter_debug 加载的却是当前打开的
  主固件工程的 .axf —— 两套代码尺寸不同、函数地址错位，PC 全被解析成**假符号**
  （停在 rt_mq_send_wait，而 special 的 map 里这个函数早被裁剪掉了），纯误导。
* SVD 芯片配错：SVD 装的是 STM32F4 的，芯片其实是 STM32H743 —— read_peripheral
  返回 F4 的 RCC base 0x40023800、读出 0xAAAAAAAA，还查不到 H7 才有的 APB1LENR。
  外设级读数全部不可用且**极具误导性**，跟"没有数据"完全不是一回事。

本模块提供「拿目标说话」的判据：

1. ``probe_chip``   读 DBGMCU_IDCODE + CPUID，得出**实测**器件系列（不是工程写的）
2. ``series_of_name`` 从器件名（SVD 的 device / uvprojx 的 Device）推系列
3. ``series_match`` 比对两者，给 matched / mismatched / unknown 三态
4. ``firmware_match`` 用 .axf 的 Flash 内容指纹与板上内存比对，判定「符号与板上固件
   是否同源」——这是 PC 能不能被解析成真符号的前提

判据一律保守：读不到就说 unknown，**绝不拿工程配置冒充实测结果**。
"""
from __future__ import annotations

import re

# ----------------------------------------------------------------------
# DBGMCU_IDCODE 的 DEV_ID（低 12 位）-> (型号描述, 系列)
# 只收录有把握的条目；表里没有的 DEV_ID 一律如实报「未收录」，不猜系列。
# ----------------------------------------------------------------------
DEV_ID_TABLE = {
    0x410: ("STM32F10x Medium-density", "STM32F1"),
    0x412: ("STM32F10x Low-density", "STM32F1"),
    0x414: ("STM32F10x High-density", "STM32F1"),
    0x418: ("STM32F105/107", "STM32F1"),
    0x420: ("STM32F10x Medium-density VL", "STM32F1"),
    0x430: ("STM32F10x XL-density", "STM32F1"),
    0x411: ("STM32F2xx", "STM32F2"),
    0x413: ("STM32F40x/41x", "STM32F4"),
    0x419: ("STM32F42x/43x", "STM32F4"),
    0x421: ("STM32F446", "STM32F4"),
    0x423: ("STM32F401xB/C", "STM32F4"),
    0x431: ("STM32F411", "STM32F4"),
    0x433: ("STM32F401xD/E", "STM32F4"),
    0x458: ("STM32F410", "STM32F4"),
    0x441: ("STM32F412", "STM32F4"),
    0x463: ("STM32F413/423", "STM32F4"),
    0x449: ("STM32F74x/75x", "STM32F7"),
    0x451: ("STM32F76x/77x", "STM32F7"),
    0x452: ("STM32F72x/73x", "STM32F7"),
    0x450: ("STM32H74x/75x", "STM32H7"),
    0x480: ("STM32H7Ax/Bx", "STM32H7"),
    0x483: ("STM32H72x/73x", "STM32H7"),
    0x415: ("STM32L47x/48x", "STM32L4"),
    0x461: ("STM32L49x/4Ax", "STM32L4"),
    0x462: ("STM32L45x/46x", "STM32L4"),
    0x464: ("STM32L41x/42x", "STM32L4"),
    0x470: ("STM32L4Rx/4Sx", "STM32L4"),
    0x435: ("STM32L43x/44x", "STM32L4"),
    0x417: ("STM32L05x/06x", "STM32L0"),
    0x447: ("STM32L07x", "STM32L0"),
    0x457: ("STM32L01x/02x", "STM32L0"),
    0x425: ("STM32L03x/04x", "STM32L0"),
    0x416: ("STM32L1xx", "STM32L1"),
    0x429: ("STM32L100/15x/16x", "STM32L1"),
    0x440: ("STM32F030x8", "STM32F0"),
    0x444: ("STM32F03x", "STM32F0"),
    0x445: ("STM32F04x", "STM32F0"),
    0x448: ("STM32F070/072", "STM32F0"),
    0x442: ("STM32F09x", "STM32F0"),
    0x439: ("STM32F0x1/0x2", "STM32F0"),
    0x422: ("STM32F30x", "STM32F3"),
    0x432: ("STM32F373/378", "STM32F3"),
    0x438: ("STM32F303", "STM32F3"),
    0x446: ("STM32F303", "STM32F3"),
}

# DBGMCU->IDCODE 的候选地址：**不同系列不在同一处**，逐个试。
# F1/F2/F4/F7/L4 在 0xE0042000；H7 在 0x5C001000；F0/L0 在 0x40015800。
IDCODE_PROBES = [
    (0x5C001000, "STM32H7 区（DBGMCU base 0x5C001000）"),
    (0xE0042000, "STM32F1/F2/F4/F7/L4 区（DBGMCU base 0xE0042000）"),
    (0x40015800, "STM32F0/L0 区（DBGMCU_IDCODE 0x40015800）"),
]

# Cortex-M 内核：CPUID 的 PARTNO（bits[15:4]）-> 名字
_PARTNO = {
    0xC20: "Cortex-M0", 0xC21: "Cortex-M1", 0xC23: "Cortex-M3", 0xC24: "Cortex-M4",
    0xC27: "Cortex-M7", 0xC60: "Cortex-M0+", 0xD20: "Cortex-M23", 0xD21: "Cortex-M33",
    0xD22: "Cortex-M35P", 0xD23: "Cortex-M55", 0xD24: "Cortex-M85",
}

# 内核 -> 可能的系列族（用于交叉校验，弱证据，只在 DEV_ID 未收录时辅助）
CORE_SERIES_HINT = {
    "Cortex-M7": ["STM32F7", "STM32H7"],
    "Cortex-M4": ["STM32F3", "STM32F4", "STM32L4", "STM32G4", "STM32L5"],
    "Cortex-M3": ["STM32F1", "STM32F2", "STM32L1"],
    "Cortex-M0": ["STM32F0", "STM32L0"],
    "Cortex-M0+": ["STM32F0", "STM32L0", "STM32G0", "STM32C0"],
}


def cpu_partno(cpuid) -> str:
    if not isinstance(cpuid, int):
        return ""
    return _PARTNO.get((cpuid >> 4) & 0xFFF, "")


def series_of_name(name: str) -> dict:
    """从器件名推系列：STM32H743xx -> STM32H7；STM32F407IGTx -> STM32F4。

    非 STM32 名字（或推不出）如实返回 series=None，不硬凑。
    """
    txt = str(name or "").strip()
    if not txt:
        return {"input": txt, "series": None, "reason": "空名字"}
    m = re.search(r"\b(STM32[A-Z])(\d)", txt.upper())
    if m:
        return {"input": txt, "series": m.group(1) + m.group(2), "reason": ""}
    m2 = re.search(r"\b(STM32)([A-Z]{1,2})", txt.upper())
    if m2:
        return {"input": txt, "series": None,
                "reason": "只认出厂牌 %s，型号档位不足以下结论" % m2.group(0)}
    return {"input": txt, "series": None, "reason": "不是 STM32 型号名（本判据只覆盖 STM32）"}


def series_match(svd_name: str, actual: dict) -> dict:
    """SVD/工程写的型号 vs 实测芯片：matched / mismatched / unknown。

    actual 为 probe_chip 的结果（含 series / dev_id / confidence）。
    """
    svd = series_of_name(svd_name)
    got = (actual or {}).get("series")
    conf = (actual or {}).get("confidence")
    out = {"svd_input": svd.get("input"), "svd_series": svd.get("series"),
           "actual_series": got, "actual_dev_id": (actual or {}).get("dev_id_hex"),
           "actual_confidence": conf}
    if not svd.get("series"):
        out["verdict"] = "unknown"
        out["reason"] = "无法从 %s 推出系列：%s" % (svd.get("input"), svd.get("reason"))
        return out
    if not got:
        out["verdict"] = "unknown"
        out["reason"] = ("未能实测出芯片系列（%s）；**不要**用工程配置里的型号代替实测结果"
                         % ((actual or {}).get("reason") or "读不到 IDCODE"))
        return out
    if conf != "high":
        out["verdict"] = "unknown"
        out["reason"] = ("实测系列 %s 的置信度是 %s（%s）：先按 unknown 处理，别急着用它否掉配置"
                         % (got, conf, (actual or {}).get("reason") or "证据不足"))
        return out
    out["verdict"] = "matched" if got == svd.get("series") else "mismatched"
    out["reason"] = ("实测 %s 与配置 %s 一致" % (got, svd.get("series")) if
                     out["verdict"] == "matched" else
                     "**实测芯片是 %s，而 SVD/工程配置写的是 %s**：外设地址与寄存器名对不上，"
                     "读出来的值看着像样但完全是别的芯片的布局"
                     % (got, svd.get("series")))
    return out


# ----------------------------------------------------------------------
# 固件 / 符号是否同源
# ----------------------------------------------------------------------
FLASH_BASE = 0x08000000


def vector_fingerprint(axf: str) -> dict:
    """从 .axf 取 Flash 起始处的向量表前 8 字节（初始 MSP + Reset_Handler）。

    ELF 的 e_entry 就是 Reset_Handler（Thumb 位置位）；初值 MSP 取不到符号时留空，
    只比对能比对的部分——不猜。
    """
    from . import reloc as _reloc
    out = {"axf": axf, "flash_base": hex(FLASH_BASE), "msp": None, "reset": None,
           "reset_hex": None, "source": None}
    try:
        segs = _reloc.load_segments(axf)
        raw = _reloc.image_bytes_at(axf, FLASH_BASE, 8)
        if raw and len(raw) >= 8:
            out["msp"] = int.from_bytes(raw[0:4], "little")
            out["reset"] = int.from_bytes(raw[4:8], "little")
            out["reset_hex"] = hex(out["reset"])
            out["source"] = "可加载段内容（链接期 Flash 起始 8 字节）"
        if out["reset"] is None:
            out["note"] = ("取不到链接期 Flash 起始字节（该 .axf 的可加载段没覆盖 "
                           "0x%08X）：本次不做向量表比对，**不猜**。" % FLASH_BASE)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def firmware_match(client, axf: str, delta: int = 0) -> dict:
    """板上固件与 .axf 是否同源——用内容指纹说话（复用 reloc.verify）。

    * verdict=firmware-confirmed  : 指纹全中，符号可以信
    * verdict=firmware-mismatch   : 指纹一条都没中（含"用 PC 反推的 delta 也对不上"）
                                    -> 当前 .axf 很可能不是板上跑的那份固件，
                                       **PC 解析出来的符号名不可信**
    * verdict=firmware-uncertain  : 指纹不全中（部分命中）
    * verdict=unreadable / no-sample : 读不到或没指纹，如实当作未验证
    """
    from . import reloc as _reloc
    ver = _reloc.verify(client, axf, delta, samples=8)
    out = {"axf": axf, "delta": "0x%X" % int(delta or 0), "verify": ver}
    v = ver.get("verdict")
    if v == "delta-confirmed":
        out["verdict"] = "firmware-confirmed"
        out["note"] = "板上内存内容与 .axf 的 Flash 指纹逐块一致：符号可用"
    elif v == "delta-likely-wrong":
        # 先让 PC 反推一次：能反推出自洽的 delta 说明"固件同源、只是偏移错"；
        # 反推不出来（或反推出的 delta 与给定值相同）才判固件不同源。
        der = _reloc.derive_from_pc(client, axf)
        out["derive"] = der
        d2 = der.get("delta_int")
        if isinstance(d2, int) and d2 != int(delta or 0):
            ver2 = _reloc.verify(client, axf, d2, samples=8)
            out["verify_derived"] = ver2
            if ver2.get("verdict") == "delta-confirmed":
                out["verdict"] = "firmware-confirmed"
                out["note"] = ("给定偏移不对，但用当前 PC 反推出 delta=0x%X 后指纹全中："
                               "固件与符号同源，只是 reloc_delta 要改" % d2)
                out["suggested_delta"] = "0x%X" % d2
                return out
        out["verdict"] = "firmware-mismatch"
        out["note"] = ("板上内存里找不到 .axf 的 Flash 指纹（连按当前 PC 反推的偏移也对不上）："
                       "**当前 .axf 很可能不是板上跑的那份固件**。此时 PC 解析出来的函数名/"
                       "行号都不可信（会出现「符号表里早被裁剪掉的函数」这种假符号），"
                       "请先 set_symbol_file 切到与刚烧录固件对应的 .axf，再解析位置。")
    elif v in ("unreadable", "no-sample"):
        out["verdict"] = "unreadable"
        out["note"] = "读不到目标内存或没有可用指纹，本次**未验证**符号与固件是否同源"
    else:
        out["verdict"] = "firmware-uncertain"
        out["note"] = "只有部分指纹命中：既不能确认也不能否定，别据此下结论"
    return out


# ----------------------------------------------------------------------
# 实测芯片身份（拿目标说话）
# ----------------------------------------------------------------------
CPUID_ADDR = 0xE000ED00


def _rd32(client, addr):
    try:
        r = client.read_mem(int(addr), 4)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(r, dict) or not r.get("ok"):
        return None
    try:
        b = bytes.fromhex(r.get("data_hex") or "")
    except ValueError:
        return None
    return int.from_bytes(b[:4], "little") if len(b) >= 4 else None


def probe_chip(client) -> dict:
    """读 DBGMCU_IDCODE + CPUID，给出**实测**器件身份；读不到就说 unknown，不猜。

    候选地址逐个试（不同系列 IDCODE 不在同一处）。多处理由：交叉校验 DEV_ID 推出的
    系列与 CPUID 推出的内核是否相容，不相容就把置信度压到 low——真机踩过的
    「SVD 是 F4、芯片是 H7」正是靠这个能提前发现。
    """
    out = {"probes": [], "dev_id": None, "dev_id_hex": None, "model": None,
           "series": None, "revision": None, "cpuid": None, "core": None,
           "confidence": "none", "reason": ""}
    cands = []
    for addr, desc in IDCODE_PROBES:
        v = _rd32(client, addr)
        rec = {"addr": hex(addr), "area": desc, "raw": None if v is None else "0x%08X" % v,
               "dev_id": None, "model": None, "series": None}
        if v is not None and v not in (0x00000000, 0xFFFFFFFF):
            dev = v & 0xFFF
            rec["dev_id"] = dev
            hit = DEV_ID_TABLE.get(dev)
            if hit:
                rec["model"], rec["series"] = hit
                cands.append((addr, v, dev))
            else:
                rec["note"] = "DEV_ID 0x%03X 不在已知表内（不猜系列）" % dev
        elif v is not None:
            rec["note"] = "读出全 0 / 全 F，不像 IDCODE"
        out["probes"].append(rec)
    cpuid = _rd32(client, CPUID_ADDR)
    if cpuid is not None:
        out["cpuid"] = "0x%08X" % cpuid
        out["core"] = cpu_partno(cpuid)
    if len(cands) == 1:
        addr, v, dev = cands[0]
        out["dev_id"] = dev
        out["dev_id_hex"] = "0x%03X" % dev
        out["revision"] = "0x%04X" % ((v >> 16) & 0xFFFF)
        out["model"], out["series"] = DEV_ID_TABLE[dev]
        out["idcode_from"] = hex(addr)
        out["confidence"] = "high"
    elif len(cands) > 1:
        out["reason"] = ("多个候选地址都读出了已知 DEV_ID（%s）：谁是真的说不准，"
                         "按 unknown 处理" % ", ".join(hex(a) for a, _, _ in cands))
        out["confidence"] = "low"
    else:
        out["reason"] = ("未能读出可识别的 DBGMCU DEV_ID（未进调试 / 该系列 IDCODE 地址未收录）")
    if out["series"] and out["core"]:
        hints = CORE_SERIES_HINT.get(out["core"])
        if hints and out["series"] not in hints:
            out["cross_check"] = {"ok": False,
                                  "note": ("DEV_ID 指向 %s，但 CPUID 说是 %s（该内核通常见于 %s）"
                                           "：证据互相矛盾，置信度下调" %
                                           (out["series"], out["core"], "/".join(hints)))}
            out["confidence"] = "low"
        elif hints:
            out["cross_check"] = {"ok": True,
                                  "note": "%s 与 %s 相容" % (out["series"], out["core"])}
    elif out["series"]:
        out["confidence"] = "medium"
        out["reason"] = out["reason"] or "有 DEV_ID 但读不到 CPUID，未能交叉校验"
    return out


def _series_to_device_hint(chip: dict) -> str:
    """实测系列 → 可用的 SVD 器件名提示（查不到就给系列名，让调用方自己 select）。

    只在「已知的常见系列」上给具体型号；不认识就退回系列名，不编型号。
    """
    s = str((chip or {}).get("series") or "")
    table = {"STM32F4": "STM32F429xx", "STM32F7": "STM32F767xx",
             "STM32H7": "STM32H743xx", "STM32L4": "STM32L476xx",
             "STM32F1": "STM32F103xx", "STM32F0": "STM32F072xx",
             "STM32G4": "STM32G474xx", "STM32L0": "STM32L073xx"}
    return table.get(s, s or "STM32H743xx")


def guard_configured_device(client, configured_name: str, allow_mismatch: bool = False,
                            what: str = "读外设", chip: dict = None) -> dict:
    """外设级操作前的环境校验：配置里的型号 vs 实测芯片。

    返回 {"allowed", "verdict", "chip", "match", "error", "note"}。
    verdict=mismatched 且未 allow_mismatch 时 allowed=False——**宁可不给数，也不给别的
    芯片布局下的"看着像样"的值**（真机反馈：F4 的 RCC base + 读出 0xAAAAAAAA）。
    """
    chip = chip if chip is not None else probe_chip(client)
    m = series_match(configured_name, chip)
    out = {"allowed": True, "verdict": m.get("verdict"), "match": m, "chip": chip,
           "configured": configured_name}
    if m.get("verdict") == "mismatched":
        out["allowed"] = bool(allow_mismatch)
        out["error_code"] = "svd-device-mismatch"
        if not out["allowed"]:
            out["error"] = ("器件识别不一致，已拒绝本次%s：%s" % (what, m.get("reason")))
            out["note"] = ("确认芯片型号后改用对应的 .svd（svd_list(device=「STM32H743xx」) "
                           "或 svd_file=）；确知自己在做什么时可传 allow_mismatch=true 强读，"
                           "此时返回值会标 mismatched 以免被当成真值。")
            # batch50：拒绝也要机器可读的下一步（与统一信封的 next_actions 对齐）
            out["next_actions"] = [
                "改用与实测系列一致的寄存器表/SVD：svd_list(device=「%s」) 或 svd_file="
                % _series_to_device_hint(chip),
                "或改用不依赖内置布局的读法：read_mem 直接按地址读，再自己对字段",
                "确知自己在做什么时可传 allow_mismatch=true 强读（结果会标 mismatched）",
            ]
        else:
            out["note"] = ("器件识别不一致但你要求强读：%s 本次结果**不可信**，别当真实布局用。"
                           % m.get("reason"))
            out["next_actions"] = [
                "把 SVD/寄存器表换成实测系列那一份后重跑（svd_list(device=…) 或 svd_file=）",
            ]
    elif m.get("verdict") == "unknown":
        out["note"] = ("无法比对配置型号与实测芯片（%s）：继续执行，但外设读数请自行核对。"
                       % m.get("reason"))
    return out
