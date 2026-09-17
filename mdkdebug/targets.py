# -*- coding: utf-8 -*-
"""目标档案：把「要调的那颗芯片」描述成一份可执行的配置。

MDK 侧的芯片知识藏在 .uvprojx / pack 里，GCC 世界没有这层，于是所有
「用哪个适配器、走哪条传输、加载哪个 OpenOCD target cfg、用哪个工具链、
SWO 该按多少核心时钟和波特率采样」都得有人告诉 AI。本模块就是这份知识。

一份档案（profile）回答四个问题：
  1. **怎么连**：transport（swd/jtag）+ interface cfg（cmsis-dap / stlink / ftdi…）
  2. **连上后加载什么**：target cfg（stm32f4x / esp32 / riscv）
  3. **用哪个工具链**：family（arm-none-eabi / riscv-none-elf / xtensa-esp-elf…）+ cpu
  4. **trace 怎么配**：SWO 核心时钟 / 波特率 / RTT 控制块搜索范围 / DWT 可用性

**不写死 cfg 文件名**：OpenOCD 各版本里 interface/target 脚本名会变（xPack 版
与上游版就有差异），所以 cfg 名只作为「首选建议」，真正启动前一律
用 ocd_cfg_list 对着 scripts 目录核实一遍，缺了会明确报出来而不是硬启。
"""

from __future__ import annotations

import glob
import json
import os
import re

__all__ = ["PROFILES", "CORE_BY_PARTNO", "list_profiles", "get_profile",
           "openocd_args", "scripts_dir", "list_cfg", "guess_from_elf",
           "guess_from_name", "register"]

# ---------------------------------------------------------------- 目标档案
# 字段说明：
#   transport : 默认传输方式（swd / jtag）
#   interface : OpenOCD interface cfg（首选建议，启动前核实）
#   interface_alt : 备选适配器（换根线就不用改档案）
#   target    : OpenOCD target cfg
#   arch      : arm / riscv / xtensa
#   family    : 对应工具链家族（toolchain.FAMILIES 的键）
#   cpu       : 默认 -mcpu / -march
#   swo       : SWO 采集参数（coreclk/baud 的单位分别是 Hz 与 bit/s）
#   rtt       : RTT 控制块搜索（addr 可为空=自动扫；size=搜索窗口）
#   dtrace    : 是否支持 SWO/ITM 硬件 trace（ESP32 系走 RTT/UART，不接 SWO 引脚）
PROFILES = {
    # ---------------- STM32（Cortex-M）----------------
    "stm32f401": {
        "title": "STM32F401（Cortex-M4，无 FPU 双精度；典型 Nucleo/F401CC）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg", "interface/stlink-v2-1.cfg"],
        "target": "target/stm32f4x.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m4", "fpu": "fpv4-sp-d16",
        "float_abi": "hard", "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 84000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400},
        "dtrace": True,
        "note": "本仓库 example_mdk_project/mdk_test 就是这颗；SWO 走 PB3(AF0)/SWO 引脚",
    },
    "stm32f411": {
        "title": "STM32F411（Cortex-M4F）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/stm32f4x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m4",
        "fpu": "fpv4-sp-d16", "float_abi": "hard",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 100000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "stm32f407": {
        "title": "STM32F407（Cortex-M4F，168MHz；最常见的 F4 型号）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg", "interface/stlink-v2-1.cfg"],
        "target": "target/stm32f4x.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m4", "fpu": "fpv4-sp-d16",
        "float_abi": "hard", "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 168000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "F407/F405 共用 target/stm32f4x.cfg；1MB Flash / 192KB RAM",
    },
    "stm32f446": {
        "title": "STM32F446（Cortex-M4F，180MHz）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg", "interface/stlink-v2-1.cfg"],
        "target": "target/stm32f4x.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m4", "fpu": "fpv4-sp-d16",
        "float_abi": "hard", "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 180000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "F446 也是 target/stm32f4x.cfg",
    },
    "stm32f429": {
        "title": "STM32F429（Cortex-M4F，2MB Flash）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/stm32f4x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m4",
        "fpu": "fpv4-sp-d16", "float_abi": "hard",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 180000000, "baud": 4000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "stm32f103": {
        "title": "STM32F103（Cortex-M3）",
        "transport": "swd", "interface": "interface/stlink.cfg",
        "interface_alt": ["interface/cmsis-dap.cfg"], "target": "target/stm32f1x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m3",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 72000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "stm32f7": {
        "title": "STM32F7（Cortex-M7）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/stm32f7x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m7",
        "fpu": "fpv5-d16", "float_abi": "hard",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 216000000, "baud": 4000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "H7/F7 开 D-Cache 时 DAP 直读可能是陈旧值，写前先 clean",
    },
    "stm32h7": {
        "title": "STM32H7（Cortex-M7）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/stm32h7x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m7",
        "fpu": "fpv5-d16", "float_abi": "hard",
        "flash_base": "0x08000000", "ram_base": "0x24000000",
        "swo": {"coreclk": 400000000, "baud": 8000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "stm32l4": {
        "title": "STM32L4（Cortex-M4 低功耗）",
        "transport": "swd", "interface": "interface/stlink.cfg",
        "interface_alt": ["interface/cmsis-dap.cfg"], "target": "target/stm32l4x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m4",
        "fpu": "fpv4-sp-d16", "float_abi": "hard",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 80000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "gd32f303": {
        "title": "GD32F303（Cortex-M4，STM32F1 引脚兼容）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/stm32f1x.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m4",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 120000000, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "GD32 用 stm32f1x.cfg 通常能连；Flash 编程算法可能要换 flash 驱动",
    },
    "cortex-m-generic": {
        "title": "通用 Cortex-M（只做内核级调试，不烧 Flash）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "interface_alt": ["interface/stlink.cfg"], "target": "target/cortex_m.cfg",
        "arch": "arm", "family": "arm-none-eabi", "cpu": "cortex-m4",
        "swo": {"coreclk": 0, "baud": 2000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "没有对应 target cfg 时用它——能 halt/读写内存/断点/RTT，但没有 Flash 驱动",
    },
    # ---------------- RISC-V ----------------
    "riscv-generic": {
        "title": "通用 RISC-V（OpenOCD target/riscv.cfg）",
        "transport": "jtag", "interface": "interface/ftdi/ftdi.cfg",
        "target": "target/riscv.cfg", "arch": "riscv",
        "family": "riscv-none-elf", "cpu": "rv32imac",
        "flash_base": "", "ram_base": "",
        "swo": {"coreclk": 0, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
        "note": "RISC-V 无 SWO/ITM；trace 走 RTT 或 DWT 派生不了，用 RTT + 采样剖析",
    },
    "esp32c3": {
        "title": "ESP32-C3（RISC-V RV32IMC，内置 USB-JTAG）",
        "transport": "jtag", "interface": "interface/esp_usb_jtag.cfg",
        "interface_alt": ["interface/ftdi/esp32_devkitj_v1.cfg"],
        "target": "target/esp32c3.cfg", "arch": "riscv",
        "family": "riscv32-esp-elf", "cpu": "rv32imc",
        "flash_base": "0x42000000", "ram_base": "0x3FC80000",
        "swo": {"coreclk": 160000000, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
        "note": "RTT 在 RISC-V target 上 OpenOCD 支持有限，优先直读内存版 RTT",
    },
    "esp32c6": {
        "title": "ESP32-C6（RISC-V）",
        "transport": "jtag", "interface": "interface/esp_usb_jtag.cfg",
        "target": "target/esp32c6.cfg", "arch": "riscv",
        "family": "riscv32-esp-elf", "cpu": "rv32imac",
        "flash_base": "0x42000000", "ram_base": "0x40800000",
        "swo": {"coreclk": 160000000, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
    },
    "esp32": {
        "title": "ESP32（Xtensa LX6）",
        "transport": "jtag", "interface": "interface/ftdi/esp32_devkitj_v1.cfg",
        "target": "target/esp32.cfg", "arch": "xtensa",
        "family": "xtensa-esp-elf", "cpu": "esp32",
        "flash_base": "0x400D0000", "ram_base": "0x3FFB0000",
        "swo": {"coreclk": 240000000, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
        "note": "Xtensa 无 ITM；OpenOCD 对 Xtensa 的内存/断点支持正常，RTT 用直读版",
    },
    "esp32s3": {
        "title": "ESP32-S3（Xtensa LX7，双核）",
        "transport": "jtag", "interface": "interface/esp_usb_jtag.cfg",
        "interface_alt": ["interface/ftdi/esp32_devkitj_v1.cfg"],
        "target": "target/esp32s3.cfg", "arch": "xtensa",
        "family": "xtensa-esp-elf", "cpu": "esp32s3",
        "flash_base": "0x42000000", "ram_base": "0x3FC80000",
        "swo": {"coreclk": 240000000, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
    },
    "esp32s2": {
        "title": "ESP32-S2（Xtensa LX7，单核）",
        "transport": "jtag", "interface": "interface/esp_usb_jtag.cfg",
        "target": "target/esp32s2.cfg", "arch": "xtensa",
        "family": "xtensa-esp-elf", "cpu": "esp32s2",
        "flash_base": "0x40080000", "ram_base": "0x3FFB0000",
        "swo": {"coreclk": 240000000, "baud": 0},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
    },
    # ---------------- 其它架构 ----------------
    "nrf52": {
        "title": "nRF52（Cortex-M4F，软件断点受 Flash 限制）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "target": "target/nrf52.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m4", "fpu": "fpv4-sp-d16",
        "float_abi": "hard", "flash_base": "0x00000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 64000000, "baud": 1000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
    },
    "rp2040": {
        "title": "RP2040（双核 Cortex-M0+）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "target": "target/rp2040.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m0plus",
        "flash_base": "0x10000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 125000000, "baud": 1000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": True,
        "note": "SWD 多核需要 target/rp2040.cfg 的 core1 配置",
    },
    "air001": {
        "title": "AIR001 / PY32（Cortex-M0+，超低成本）",
        "transport": "swd", "interface": "interface/cmsis-dap.cfg",
        "target": "target/cortex_m.cfg", "arch": "arm",
        "family": "arm-none-eabi", "cpu": "cortex-m0plus",
        "flash_base": "0x08000000", "ram_base": "0x20000000",
        "swo": {"coreclk": 24000000, "baud": 1000000},
        "rtt": {"addr": "", "size": 0x400}, "dtrace": False,
    },
}

# ARM CPUID 的 PARTNO（bits 15:4）→ 内核名；用于 ocd 连上后自报家门
CORE_BY_PARTNO = {
    0xC20: "Cortex-M0", 0xC21: "Cortex-M3", 0xC23: "Cortex-M7",
    0xC24: "Cortex-M4", 0xC27: "Cortex-M7", 0xC60: "Cortex-M0+",
    0xD20: "Cortex-M23", 0xD21: "Cortex-M33", 0xD22: "Cortex-M55",
    0xD23: "Cortex-M85",
    0xC05: "Cortex-A5", 0xC07: "Cortex-A7", 0xC0F: "Cortex-A15",
}


def _profiles(arch: str = "", keyword: str = "") -> dict:
    out = {}
    for pid, spec in PROFILES.items():
        if arch and (spec.get("arch") or "").lower() != arch.lower():
            continue
        if keyword:
            blob = (pid + " " + json.dumps(spec, ensure_ascii=False)).lower()
            if keyword.lower() not in blob:
                continue
        out[pid] = spec
    return out


def list_profiles(arch: str = "", keyword: str = "") -> dict:
    sel = _profiles(arch, keyword)
    items = []
    for pid, spec in sel.items():
        items.append({
            "profile": pid, "title": spec.get("title"), "arch": spec.get("arch"),
            "transport": spec.get("transport"),
            "openocd": {"interface": spec.get("interface"), "target": spec.get("target"),
                        "interface_alt": spec.get("interface_alt") or []},
            "toolchain": {"family": spec.get("family"), "cpu": spec.get("cpu"),
                          "fpu": spec.get("fpu"), "float_abi": spec.get("float_abi")},
            "swo": spec.get("swo"), "dtrace": bool(spec.get("dtrace")),
            "note": spec.get("note"),
        })
    items.sort(key=lambda x: (x["arch"] or "", x["profile"]))
    return {"ok": True, "count": len(items), "profiles": items,
            "archs": sorted({s.get("arch") for s in PROFILES.values() if s.get("arch")}),
            "note": "profile 只是首选建议：cfg 名各版本 OpenOCD 有差异，"
                    "启动前用 ocd_cfg_list 对着 scripts 目录核实；"
                    "没有对应档案就用 cortex-m-generic / riscv-generic"}


def get_profile(pid: str) -> dict:
    pid = (pid or "").strip().lower()
    if not pid:
        return {"ok": False, "error": "profile 不能为空",
                "available": sorted(PROFILES)}
    spec = PROFILES.get(pid)
    if not spec:
        # 允许模糊匹配（stm32f4 → stm32f401）
        cands = [k for k in PROFILES if k.startswith(pid) or pid in k]
        if len(cands) == 1:
            pid, spec = cands[0], PROFILES[cands[0]]
        else:
            return {"ok": False, "profile": pid, "error": "未知档案",
                    "suggest": sorted(cands)[:8] or sorted(PROFILES)[:8]}
    out = {"ok": True, "profile": pid}
    out.update(spec)
    return out


def openocd_args(profile: str = "", interface: str = "", target: str = "",
                 transport: str = "", speed: float = 0, extra_cfg=None,
                 adapter_serial: str = "", adapter_vid_pid: str = "") -> dict:
    """组装 openocd 的 -f 参数串。

    显式给了 interface/target 就用显式的（覆盖档案），都没有才用档案里的。
    """
    spec = {}
    if profile:
        r = get_profile(profile)
        if not r.get("ok"):
            return r
        spec = r
    ifs = interface or spec.get("interface")
    tgt = target or spec.get("target")
    tr = (transport or spec.get("transport") or "swd").lower()
    if not ifs and not tgt:
        return {"ok": False, "error": "既没给 profile 也没给 interface/target",
                "hint": "用 target_list 挑一个档案，或显式给 interface/target cfg"}
    cfg = []
    if tr not in ("swd", "jtag", "hla_swd", "hla_jtag", "srst_only", "dapdirect_swd"):
        return {"ok": False, "error": "不支持的 transport：%s" % tr}
    if ifs:
        cfg += ["-f", ifs]
    if tgt:
        cfg += ["-f", tgt]
    if tr:
        # transport 既可在 cfg 里选，也可命令行覆盖；显式给出更稳（避免 cfg 默认 jtag）
        cfg += ["-c", "transport select %s" % tr]
    if adapter_serial:
        cfg += ["-c", "adapter serial %s" % adapter_serial]
    if adapter_vid_pid:
        cfg += ["-c", "adapter usb vid_pid %s" % adapter_vid_pid]
    if speed and float(speed) > 0:
        cfg += ["-c", "adapter speed %s" % _fmt_speed(speed)]
    for e in (extra_cfg or []):
        if str(e).strip():
            cfg += ["-f", str(e).strip()]
    return {"ok": True, "profile": profile or None, "transport": tr,
            "interface": ifs, "target": tgt, "args": cfg,
            "arch": spec.get("arch"), "family": spec.get("family"),
            "cpu": spec.get("cpu"), "swo": spec.get("swo"),
            "toolchain_hint": _toolchain_hint(spec)}


def _fmt_speed(speed) -> str:
    try:
        v = float(speed)
    except (TypeError, ValueError):
        return str(speed)
    if v >= 1000000:
        return "%gk" % (v / 1000.0)
    return "%gk" % (v / 1000.0) if v >= 1000 else "%d" % int(v)


def _toolchain_hint(spec: dict) -> dict:
    fam = spec.get("family")
    if not fam:
        return {}
    tip = {"family": fam, "cpu": spec.get("cpu")}
    if spec.get("fpu"):
        tip["fpu"] = spec["fpu"]
        tip["float_abi"] = spec.get("float_abi")
    return tip


# ---------------------------------------------------------------- cfg 文件定位

def scripts_dir(openocd_path: str = "") -> str:
    """定位 OpenOCD 的 scripts 目录（interface/ target/ 的父目录）。"""
    exe = openocd_path
    if not exe:
        try:
            from . import toolchain as _tc
            exe = _tc.find_tool("openocd", "openocd") or ""
        except Exception:  # noqa: BLE001
            exe = ""
    if not exe:
        return ""
    base = os.path.dirname(os.path.abspath(exe))
    cands = [
        os.path.join(base, "..", "share", "openocd", "scripts"),
        os.path.join(base, "..", "scripts"),
        os.path.join(base, "scripts"),
        os.path.join(base, "..", "..", "share", "openocd", "scripts"),
        # xPack 版：bin/openocd.exe + share/openocd/scripts
        os.path.join(base, "..", "share", "openocd", "scripts"),
    ]
    # 再宽一点：往上一层找 share/openocd/scripts
    for up in ("..", "../.."):
        p = os.path.normpath(os.path.join(base, up))
        cands.append(os.path.join(p, "share", "openocd", "scripts"))
    for c in cands:
        c = os.path.normpath(c)
        if os.path.isdir(os.path.join(c, "target")) and os.path.isdir(os.path.join(c, "interface")):
            return c
    return ""


def list_cfg(kind: str = "target", keyword: str = "", limit: int = 200) -> dict:
    """列出 OpenOCD 自带的 interface/target/board cfg 文件（选型的唯一事实来源）。"""
    sd = scripts_dir()
    if not sd:
        return {"ok": False, "error": "找不到 OpenOCD scripts 目录",
                "hint": "先确认 openocd 已解压（toolchain_list 能列出它），"
                        "或本机 OpenOCD 是精简包（无 scripts）"}
    kind = (kind or "target").strip().lower()
    if kind not in ("interface", "target", "board"):
        return {"ok": False, "error": "kind 只能是 interface / target / board"}
    root = os.path.join(sd, kind)
    if not os.path.isdir(root):
        return {"ok": False, "root": root, "error": "该目录不存在"}
    files = []
    for pat in ("*.cfg", "*/*.cfg"):
        for p in glob.glob(os.path.join(root, pat)):
            rel = os.path.relpath(p, sd).replace("\\", "/")
            if keyword and keyword.lower() not in rel.lower():
                continue
            files.append(rel)
    files.sort()
    return {"ok": True, "scripts_dir": sd, "kind": kind, "count": len(files),
            "files": files[:limit], "truncated": len(files) > limit,
            "note": "这些是 -f 可直接用的相对路径（相对 scripts 目录），"
                    "OpenOCD 会自动在其 scripts 路径下查找"}


def _arch_of_text(text: str) -> str:
    t = (text or "").lower()
    if re.search(r"xtensa|esp32($|[^c0-9])|esp32s", t):
        return "xtensa"
    if re.search(r"riscv|risc-v|rv32|rv64|esp32c|esp32h|c3|c6|h2", t):
        return "riscv"
    return "arm"


def guess_from_elf(elf: str) -> dict:
    """按 ELF 的机器类型猜目标档案与工具链家族。"""
    try:
        from . import toolchain as _tc
        info = _tc.elf_info(elf)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    if not info.get("ok"):
        return info
    arch = info.get("arch")
    if arch == "riscv":
        fam = "riscv-none-elf"
        cands = ["riscv-generic", "esp32c3", "esp32c6"]
    elif arch == "xtensa":
        fam = "xtensa-esp-elf"
        cands = ["esp32", "esp32s3", "esp32s2"]
    else:
        fam = "arm-none-eabi"
        cands = ["cortex-m-generic", "stm32f401", "stm32f429", "nrf52", "rp2040"]
    return {"ok": True, "elf": os.path.abspath(elf), "arch": arch,
            "machine": info.get("machine"), "entry": info.get("entry_hex"),
            "family": fam, "profile_candidates": cands,
            "note": "ELF 只知道架构，不知道具体芯片型号；确定型号请用 "
                    "target_list 里的档案或让 OpenOCD 读 CPUID（ocd_probe）"}


def guess_from_name(name: str) -> dict:
    """按工程名/路径里的型号字样猜档案（stm32f401 / esp32c3 …）。"""
    t = (name or "").lower()
    hits = []
    for pid in PROFILES:
        key = pid.replace("-", "")
        if key and key in t.replace("-", ""):
            hits.append(pid)
    for tok in re.findall(r"(stm32[a-z]?\d{3}|gd32[a-z]?\d{3}|nrf5\d|rp2040|"
                          r"esp32[a-z0-9]*|air001)", t):
        for pid in PROFILES:
            if tok.replace("-", "") in pid.replace("-", "") and pid not in hits:
                hits.append(pid)
    return {"ok": bool(hits), "input": name, "profiles": hits[:5],
            "note": "按文件名猜的，仅供参考；以 ocd_probe 读到的芯片 ID 为准"}


# ---------------------------------------------------------------- MCP 注册

def _default_js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def register(server, js=None) -> int:
    """把目标档案相关工具注册到 MCP server，返回注册数量。"""
    _js = js or _default_js
    n = 0

    @server.tool(
        name="target_list",
        title="非 MDK 目标档案（芯片 → 连接方式 + 工具链 + trace 参数）",
        description=(
            "列出内置的**目标档案**：每份档案告诉你怎么连这颗芯片（SWD/JTAG + "
            "OpenOCD interface/target cfg）、用哪个 GCC 工具链家族、以及 trace 参数"
            "（SWO 核心时钟 / 波特率、是否支持 ITM）。覆盖 STM32 全系常用型号、"
            "GD32、nRF52、RP2040、通用 Cortex-M，以及 RISC-V（含 ESP32-C3/C6）"
            "与 Xtensa（ESP32/S2/S3）。\n"
            "用法：调试非 MDK 目标时先 target_list 挑档案，再把 profile 名喂给 "
            "ocd_start / toolchain_build。arch 可过滤 arm/riscv/xtensa，keyword 按"
            "型号或说明子串过滤（如 keyword=\"esp32\"、\"f4\"）。\n"
            "**档案不是真理**：cfg 文件名各版本 OpenOCD 有差异，档案给的只是首选建议，"
            "启动前用 ocd_cfg_list 对着实际 scripts 目录核实；型号不确定时用 ocd_probe "
            "读 CPUID/IDCODE 反查，别靠猜。"
        ),
    )
    async def target_list(arch: str = "", keyword: str = "") -> str:
        try:
            return _js(list_profiles(arch=arch, keyword=keyword))
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="target_show",
        title="展开一份目标档案（含将执行的 OpenOCD 参数与工具链建议）",
        description=(
            "把某份目标档案完整展开：连接方式、interface/target cfg、工具链家族与 "
            "cpu/fpu/float-abi、SWO 默认参数、RTT 搜索范围、Flash/RAM 基址、注意事项；"
            "并直接给出 openocd_args（真正要传给 openocd 的 -f / -c 列表）。\n"
            "profile 支持前缀模糊匹配（stm32f4 → stm32f401）。"
            "还能显式覆盖 interface / target / transport / speed，用来验证"
            "「换根调试器该传什么参数」，不用真去启 OpenOCD。"
        ),
    )
    async def target_show(profile: str, interface: str = "", target: str = "",
                          transport: str = "", speed: float = 0,
                          extra_cfg: str = "") -> str:
        try:
            r = get_profile(profile)
            if not r.get("ok"):
                return _js(r)
            extra = [x for x in re.split(r"[;,|]", extra_cfg or "") if x.strip()]
            args = openocd_args(profile=r.get("profile"), interface=interface,
                                target=target, transport=transport, speed=speed,
                                extra_cfg=extra)
            r["openocd_args"] = args
            return _js(r)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "profile": profile, "error": str(e)})
    n += 1

    @server.tool(
        name="target_guess",
        title="按 ELF 或工程名推测目标档案与工具链",
        description=(
            "两条推测路径：\n"
            "1. 给 elf（.elf/.axf 路径）——读 ELF 头的机器类型，得出架构"
            "（arm/riscv/xtensa）与应使用的工具链家族，并给候选档案；\n"
            "2. 给 name（工程名 / 目录名 / 文件名）——按型号字样（stm32f401、esp32c3…）"
            "匹配档案。\n"
            "两者可同时给。**这只是推测**：ELF 里没有芯片型号，"
            "最终以 ocd_probe 连上后读到的 CPUID/IDCODE 为准。"
        ),
    )
    async def target_guess(elf: str = "", name: str = "") -> str:
        try:
            out = {"ok": True}
            if elf:
                out["by_elf"] = guess_from_elf(elf)
            if name:
                out["by_name"] = guess_from_name(name)
            if not elf and not name:
                return _js({"ok": False, "error": "elf 与 name 至少要给一个"})
            return _js(out)
        except Exception as e:  # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
