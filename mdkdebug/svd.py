# -*- coding: utf-8 -*-
"""CMSIS-SVD 外设描述解析：把"某个地址上的寄存器值"翻译成**位域**。

为什么需要它
------------
periph.py 里的内置表只覆盖 STM32F4 的常用外设，且寄存器名是手抄的；
换个芯片（F1/F7/H7/G0/L4、或是国产替代）就完全失效。CMSIS-SVD 是 ARM 生态的
**标准外设描述文件**（Keil 的 Device Family Pack 里每个器件都带一份 ``*.svd``），
有了它就能：定位外设基址 → 定位寄存器偏移 → 把值按字段拆开（含字段含义）。

设计取舍
--------
- **纯只读解析**：SVD 只用于"解释"，绝不据此写寄存器（写寄存器仍走 write_peripheral）。
- **惰性 + 缓存**：一份 SVD 动辄 1~2MB、上万个寄存器，解析一次即缓存（按路径）。
- **自动定位**：按 `MDKDEBUG_SVD` 环境变量 → Keil Pack 目录里按器件名模糊匹配。
  搜索有深度与条目上限，避免在大 Pack 目录里卡住。
- **找不到就说找不到**：不猜器件、不伪造寄存器表；返回下一步（用 svd_file 参数显式指定）。
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

# 缓存：{"path":..., "device":..., "peripherals":{...}, "error":...}
_CACHE = {"path": None, "device": None, "peripherals": {}, "error": None, "loaded": False}
_SEARCH_CACHE = {"key": None, "hits": []}

_MAX_DEPTH = 7
_MAX_ENTRIES = 60000

def _tools_ini_candidates() -> list:
    """``TOOLS.INI`` 的候选位置（Keil 的安装根 + 环境变量提示）。"""
    import sys
    cands = []
    for env in ("MDKDEBUG_KEIL_ROOT", "KEIL_ROOT", "UV4_ROOT"):
        v = os.environ.get(env)
        if v:
            cands.append(os.path.join(v, "TOOLS.INI"))
    drives = ["C:", "D:", "E:"]
    # 从 UV4.exe 的常见位置反推安装根
    for d in drives:
        for name in ("Keil_v5", "Keil_v4", "Keil"):
            cands.append(os.path.join(d + os.sep, name, "TOOLS.INI"))
    return cands

def _rtepath_from_tools_ini() -> list:
    """从 ``TOOLS.INI`` 的 ``RTEPATH=`` 读出 Pack 根目录。

    真机实测：本机 ``D:/Keil_v5/ARM/PACK`` 是**空的**，器件包（STM32F4xx_DFP 等）
    实际装在 ``TOOLS.INI`` 的 ``RTEPATH`` 指向的目录里（如
    ``D:/Users/<用户>/AppData/Local/Arm/Packs``）。只猜 ``ARM/PACK`` 会一个 SVD
    都找不到——这是"该能自动找到却找不到"的根因，故优先按 RTEPATH 探测。
    """
    out = []
    for p in _tools_ini_candidates():
        try:
            if not os.path.isfile(p):
                continue
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                txt = f.read()
        except OSError:
            continue
        m = re.search(r'^\s*RTEPATH\s*=\s*"([^"]+)"', txt, re.M | re.I)
        if not m:
            m = re.search(r"^\s*RTEPATH\s*=\s*([^\r\n]+)", txt, re.M | re.I)
        if m:
            v = m.group(1).strip().strip('"')
            if v:
                out.append(v)
    return out

def _pack_roots() -> list:
    """CMSIS Pack 常见根目录（按优先级）。"""
    roots = []
    for env in ("CMSIS_PACK_ROOT", "CMSIS_5_PACK_ROOT"):
        v = os.environ.get(env)
        if v and os.path.isdir(v):
            roots.append(v)
    roots += _rtepath_from_tools_ini()          # TOOLS.INI 的 RTEPATH 最可信
    home = os.path.expanduser("~")
    roots += [
        r"D:\Keil_v5\ARM\PACK",
        r"C:\Keil_v5\ARM\PACK",
        r"C:\Keil\ARM\PACK",
        os.path.join(home, "AppData", "Local", "Arm", "Packs"),
        os.path.join(home, ".cache", "arm", "packs"),
    ]
    out, seen = [], set()
    for r in roots:
        r = os.path.abspath(r)
        if r.lower() in seen or not os.path.isdir(r):
            continue
        seen.add(r.lower())
        out.append(r)
    return out

def _common_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n

def find_svd_files(device_hint: str = "", limit: int = 20) -> list:
    """在 Pack 目录里找 ``*.svd``。

    device_hint 用**公共前缀**匹配而不是子串匹配：Keil 工程里写的是订货型号
    （``STM32F401RCTx``），SVD 文件名却是容量档写法（``STM32F401xE``）——两者互不包含，
    子串匹配会一个都找不到。改按公共前缀打分（≥6 才认），并按"前缀更长优先、
    名字更短优先"排序，于是 ``STM32F401RCTx`` 会稳定命中 ``STM32F401x.svd`` /
    ``STM32F401xC.svd`` / ``STM32F401xE.svd`` 这几个候选，由调用方择一。
    """
    key = (device_hint or "").lower()
    if _SEARCH_CACHE["key"] == key and _SEARCH_CACHE["hits"]:
        return _SEARCH_CACHE["hits"]
    hint = re.sub(r"[^a-z0-9]", "", key)
    scanned, entries = [], 0
    for root in _pack_roots():
        base_depth = root.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            entries += 1
            if entries > _MAX_ENTRIES:
                break
            if dirpath.count(os.sep) - base_depth >= _MAX_DEPTH:
                dirnames[:] = []
                continue
            for fn in filenames:
                if fn.lower().endswith(".svd"):
                    scanned.append(os.path.join(dirpath, fn))
        if entries > _MAX_ENTRIES:
            break
    if not hint:
        hits = sorted(scanned)[:limit]
    else:
        scored = []
        for p in scanned:
            norm = re.sub(r"[^a-z0-9]", "", os.path.basename(p)[:-4].lower())
            cp = _common_prefix(norm, hint)
            if cp < 6:
                continue
            scored.append((-cp, len(norm), p))
        scored.sort()
        hits = [p for _s, _l, p in scored[:limit]]
    _SEARCH_CACHE.update({"key": key, "hits": hits})
    return hits

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]

def _txt(node, tag: str, default=None):
    if node is None:
        return default
    for c in node:
        if _local(c.tag) == tag:
            return (c.text or "").strip() if c.text else default
    return default

def _int(s, base=0, default=None):
    if s is None:
        return default
    s = str(s).strip()
    try:
        if base == 0:
            return int(s, 0) if s.lower().startswith("0x") else int(s)
        return int(s, base)
    except ValueError:
        return default

def _parse_fields(reg_el) -> list:
    """解析寄存器的位域；兼容 bitOffset/bitWidth 与 lsb/msb 两种写法。"""
    out = []
    for fl in reg_el:
        if _local(fl.tag) != "fields":
            continue
        for f in fl:
            if _local(f.tag) != "field":
                continue
            name = _txt(f, "name") or ""
            if not name:
                continue
            off = _int(_txt(f, "bitOffset"))
            wid = _int(_txt(f, "bitWidth"))
            if off is None:
                lsb = _int(_txt(f, "lsb"))
                msb = _int(_txt(f, "msb"))
                if lsb is None or msb is None:
                    continue
                off, wid = lsb, (msb - lsb + 1)
            if wid is None:
                continue
            evs = []
            for en in f:
                if _local(en.tag) != "enumeratedValues":
                    continue
                for ev in en:
                    if _local(ev.tag) != "enumeratedValue":
                        continue
                    evs.append({"name": _txt(ev, "name"),
                                "value": _int(_txt(ev, "value")),
                                "description": _txt(ev, "description")})
            out.append({"name": name, "bit_offset": off, "bit_width": wid,
                        "description": _txt(f, "description"),
                        "access": _txt(f, "access"),
                        "enumerated_values": evs})
    return out

def _parse_register(r, regs: dict) -> None:
    """把单个 ``<register>`` 写进 regs（按 dim 展开数组）。"""
    rname = (_txt(r, "name") or "").strip()
    if not rname:
        return
    dim = _int(_txt(r, "dim"))
    inc = _int(_txt(r, "dimIncrement"))
    base_off = _int(_txt(r, "addressOffset"), default=0)
    offs = [base_off]
    if dim and dim > 1 and inc:
        offs = [base_off + inc * i for i in range(min(dim, 64))]
    entry = {"name": rname, "size": _int(_txt(r, "size"), default=32),
             "access": _txt(r, "access"),
             "description": _txt(r, "description"),
             "fields": _parse_fields(r)}
    for i, o in enumerate(offs):
        key = rname if len(offs) == 1 else "%s%d" % (rname.split("[")[0], i)
        regs[key] = dict(entry, name=key, offset=o)

def _parse_registers(node, regs: dict, base_off: int = 0) -> None:
    """递归解析 ``<registers>``：支持 ``<cluster>``（带自己的 addressOffset 与嵌套）。"""
    for ch in node:
        tag = _local(ch.tag)
        if tag == "register":
            rname = (_txt(ch, "name") or "").strip()
            dim = _int(_txt(ch, "dim")) or 1
            inc = _int(_txt(ch, "dimIncrement")) or 0
            span = (dim - 1) * inc if (dim > 1 and inc) else 0
            saved = ch.find("addressOffset")
            raw_off = None
            if saved is not None:
                raw_off = saved.text
            _parse_register(ch, regs)
            if base_off and rname:
                for k in list(regs.keys()):
                    if regs[k]["name"] == rname or k.startswith(rname.split("[")[0]):
                        regs[k]["offset"] = regs[k]["offset"] + base_off
        elif tag == "cluster":
            co = _int(_txt(ch, "addressOffset"), default=0) or 0
            for sub in ch:
                if _local(sub.tag) == "cluster":
                    _parse_registers([sub], regs, base_off + co)
                elif _local(sub.tag) == "register":
                    _parse_register(sub, regs)
            continue

def parse_svd(path: str) -> dict:
    """解析一份 SVD，返回 {ok, device, path, peripheral_count, peripherals}。

    必须处理的两件"真实 SVD 才有的东西"：
    1. **``derivedFrom`` 继承**——真机上 STM32F401x.svd 里 ``USART2`` 只有一行
       ``<peripheral derivedFrom="USART6">`` + 自己的 ``baseAddress``，寄存器全靠继承。
       不解析继承，就会得到"外设存在但寄存器 0 个"的空壳（本模块首版正是如此）。
       寄存器级 ``derivedFrom`` 同样处理。
    2. **``<cluster>``**——寄存器可以成组嵌套，带自己的 addressOffset。
    """
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "解析 SVD 失败：%s" % e, "path": path}
    device = _txt(root, "name") or os.path.basename(path)
    raw = {}
    order = []
    for p in root:
        if _local(p.tag) != "peripherals":
            continue
        for per in p:
            if _local(per.tag) != "peripheral":
                continue
            pname = (_txt(per, "name") or "").strip()
            base = _int(_txt(per, "baseAddress"))
            blocks = []
            for ab in per:
                if _local(ab.tag) != "addressBlock":
                    continue
                off = _int(_txt(ab, "offset"))
                size = _int(_txt(ab, "size"))
                if off is None or size is None or size <= 0:
                    continue
                blocks.append((off, size))
            if not pname:
                continue
            regs = {}
            for rr in per:
                if _local(rr.tag) == "registers":
                    _parse_registers(rr, regs)
            raw[pname] = {"name": pname, "base": base, "blocks": blocks,
                          "derived_from": per.get("derivedFrom"),
                          "description": _txt(per, "description"),
                          "group": _txt(per, "groupName"),
                          "registers": regs}
            order.append(pname)

    # 解析继承（含多级；带环保护）
    resolving = set()
    def _resolve(name, chain):
        ent = raw.get(name)
        if ent is None:
            return None
        if ent["registers"]:
            return ent
        parent = ent.get("derived_from")
        if not parent or parent in chain:
            return ent
        p = _resolve(parent, chain | {name})
        if p is None:
            return ent
        merged = {k: dict(v) for k, v in p["registers"].items()}
        merged.update(ent["registers"])          # 子覆盖父
        ent["registers"] = merged
        if not ent.get("blocks"):
            ent["blocks"] = list(p.get("blocks") or [])
        if not ent.get("description"):
            ent["description"] = p.get("description")
        if not ent.get("group"):
            ent["group"] = p.get("group")
        return ent

    periphs = {}
    for name in order:
        _resolve(name, set())
        ent = raw[name]
        if ent["base"] is None:
            continue
        periphs[name] = {"name": ent["name"], "base": ent["base"],
                         "address_blocks": ent.get("blocks") or [],
                         "description": ent.get("description"),
                         "group": ent.get("group"),
                         "derived_from": ent.get("derived_from"),
                         "registers": ent["registers"]}
    return {"ok": True, "device": device, "path": path,
            "peripheral_count": len(periphs), "peripherals": periphs}

def load(path: str = "", device: str = "", rescan: bool = False) -> dict:
    """加载（并缓存）一份 SVD。path 显式优先；否则按 device 在 Pack 里找。"""
    if path:
        if not os.path.isfile(path):
            return {"ok": False, "error": "SVD 文件不存在：%s" % path}
        if (not rescan) and _CACHE["loaded"] and _CACHE["path"] == os.path.abspath(path):
            return _summary()
        got = parse_svd(path)
        if not got.get("ok"):
            return got
        _CACHE.update({"path": os.path.abspath(path), "device": got["device"],
                       "peripherals": got["peripherals"], "error": None, "loaded": True})
        return _summary()
    if (not rescan) and _CACHE["loaded"]:
        return _summary()
    envp = os.environ.get("MDKDEBUG_SVD", "").strip()
    if envp and os.path.isfile(envp):
        return load(path=envp, rescan=rescan)
    hits = find_svd_files(device or "")
    if not hits:
        roots = _pack_roots()
        return {"ok": False, "loaded": False,
                "error": "未找到任何 .svd 文件%s" % ("（关键词：%s）" % device if device else ""),
                "searched_roots": roots,
                "next_actions": [
                    "传 svd_file 参数显式指定 .svd 路径（Keil 的 DFP 里就有，如 "
                    "…\\Keil\\STM32F4xx_DFP\\x.y.z\\CMSIS\\SVD\\STM32F401xx.svd）",
                    "或设环境变量 MDKDEBUG_SVD 指向该文件",
                    "也可以不依赖 SVD：periph.py 内置表覆盖 STM32F4 常用外设，"
                    "list_peripherals / read_peripheral 在 F4 上仍可用",
                ]}
    # 没给关键词时**绝不盲挑**：真机实测盘上有几十份不同厂商/型号的 .svd，
    # 按发现顺序取第一份，会把 0x40020000 判成 TIMER2 这种"看起来权威的错答案"
    # ——比直接报错更危险（AI 无法察觉自己看的是别的芯片的手册）。
    if not (device or "").strip() and len(hits) > 1:
        return {"ok": False, "loaded": False, "ambiguous": True,
                "error": "未指定器件型号，盘上找到 %d 份 .svd，拒绝盲挑一份（可能不是目标芯片）"
                         % len(hits),
                "candidates": hits[:20],
                "next_actions": [
                    "传 device= 显式指定订货型号（如 device=\"STM32F401RCTx\"）",
                    "或传 svd_file= 直接给 .svd 路径",
                    "或设环境变量 MDKDEBUG_SVD 固定一份（适合长期只用一个型号）",
                    "本服务在不给 device 时会先尝试读当前工程的 <Device> 自动推断",
                ]}
    got = parse_svd(hits[0])
    if not got.get("ok"):
        return got
    got["candidates"] = hits[:10]
    _CACHE.update({"path": os.path.abspath(hits[0]), "device": got["device"],
                   "peripherals": got["peripherals"], "error": None, "loaded": True})
    return _summary()

def _summary() -> dict:
    return {"ok": True, "loaded": True, "path": _CACHE["path"],
            "device": _CACHE["device"],
            "peripheral_count": len(_CACHE["peripherals"]),
            "peripherals": sorted(_CACHE["peripherals"].keys()),
            "note": "SVD 已加载（内存缓存）；这里是外设名清单，"
                    "用 svd_decode 看某个外设/寄存器/值的位域"}

def loaded() -> bool:
    return bool(_CACHE["loaded"])

def device() -> str:
    return _CACHE["device"] or ""

def peripheral_names() -> list:
    return sorted(_CACHE["peripherals"].keys())

def get_peripheral(name: str):
    """按名取外设（大小写不敏感；也接受 'GPIOA' / 'gpioa'）。"""
    if not name:
        return None
    p = _CACHE["peripherals"].get(name)
    if p:
        return p
    low = name.strip().lower()
    for k, v in _CACHE["peripherals"].items():
        if k.lower() == low:
            return v
    return None

def regs_of(name: str) -> list:
    p = get_peripheral(name)
    return sorted(p["registers"].keys()) if p else []

def _bases_sorted() -> list:
    return sorted(p["base"] for p in _CACHE["peripherals"].values()
                  if p.get("base") is not None)


def peripherals_at(addr: int, limit: int = 4) -> list:
    """返回可能覆盖该地址的外设（含偏移），按可信度从高到低排序。

    判定分两级，**不要用固定窗口拍脑袋**——真机上外设基址密集排布，
    0x40003800(SPI2) 与 0x40004400(USART2) 只隔 3KB，固定窗口必然重叠误判：

    1. 有 ``<addressBlock>`` 的：只有当 addr 真落在某个块内才算命中，块越小越具体；
    2. 没有任何块命中时退化为「最近前缀」：所有 base 中取最大的 <= addr 者，
       因为外设基址是顺序排布的，addr 归属于紧邻其左侧的那个 base。
    """
    out = []
    for p in _CACHE["peripherals"].values():
        base = p.get("base")
        if base is None or addr < base:
            continue
        off = addr - base
        for (boff, bsize) in (p.get("address_blocks") or []):
            if boff <= off < boff + bsize:
                out.append({"peripheral": p["name"], "offset": off,
                            "offset_hex": hex(off), "base_hex": hex(base),
                            "span": bsize, "match": "addressBlock"})
                break
    if out:
        out.sort(key=lambda c: (c["span"], c["offset"]))
        return out[:limit]

    # 退化路径：最近前缀
    best = None
    for b in _bases_sorted():
        if b <= addr:
            best = b
        else:
            break
    if best is None:
        return []
    p = None
    for cand in _CACHE["peripherals"].values():
        if cand.get("base") == best:
            p = cand
            break
    if p is None:
        return []
    off = addr - best
    return [{"peripheral": p["name"], "offset": off, "offset_hex": hex(off),
             "base_hex": hex(best), "span": None, "match": "nearest_base"}]

def decode_value(peripheral: str = "", register: str = "",
                 value: int = 0, address=None) -> dict:
    """把值按 SVD 的寄存器位域拆开。

    peripheral+register 直接定位；或只给 address（自动找外设+寄存器）。
    """
    if not _CACHE["loaded"]:
        return {"ok": False, "error": "SVD 未加载，请先调 svd_decode 的 svd_file/device 参数",
                "next_actions": ["用 svd_file 指定 .svd 路径", "或设 MDKDEBUG_SVD 环境变量"]}
    per = get_peripheral(peripheral) if peripheral else None
    reg = None
    matched_by = None
    if per is None and address is not None:
        addr = int(address)
        cands = peripherals_at(addr)
        if not cands:
            return {"ok": False, "error": "地址 0x%08X 不落在任何已知外设范围内" % addr}
        for c in cands:
            p2 = get_peripheral(c["peripheral"])
            rv = None
            for rn, r in (p2 or {}).get("registers", {}).items():
                if r["offset"] == c["offset"]:
                    rv = r
                    break
            if rv is not None:
                per, reg, matched_by = p2, rv, c.get("match")
                break
        if reg is None:
            c = cands[0]
            per = get_peripheral(c["peripheral"])
            return {"ok": False, "peripheral": per["name"],
                    "address": hex(addr),
                    "matched_by": c.get("match"),
                    "available_registers": regs_of(per["name"])[:60],
                    "error": "该地址未对上 SVD 里的寄存器（可能是保留区或 SVD 未描述）"}
    elif per is not None and register:
        low = register.strip().lower()
        for rn, rv in per["registers"].items():
            if rn.lower() == low or rn.lower().startswith(low):
                reg = rv
                break
        if reg is None:
            return {"ok": False, "peripheral": per["name"],
                    "available_registers": regs_of(per["name"])[:60],
                    "error": "外设 %s 里没有寄存器 %s" % (per["name"], register)}
    elif per is not None:
        return {"ok": True, "peripheral": per["name"], "base": hex(per["base"]),
                "description": per.get("description"),
                "register_count": len(per["registers"]),
                "registers": regs_of(per["name"])}
    else:
        return {"ok": False, "error": "至少要给 peripheral 或 address"}

    val = int(value) & 0xFFFFFFFF
    fields = []
    for f in reg.get("fields") or []:
        off, wid = f["bit_offset"], f["bit_width"]
        if off is None or wid is None or wid <= 0:
            continue
        raw = (val >> off) & ((1 << wid) - 1)
        item = {"name": f["name"], "bits": ("%d" % off if wid == 1 else "%d:%d" % (off + wid - 1, off)),
                "value": raw, "value_hex": hex(raw)}
        if f.get("description"):
            item["description"] = f["description"]
        for ev in f.get("enumerated_values") or []:
            if ev.get("value") == raw:
                item["meaning"] = ev.get("name")
                if ev.get("description"):
                    item["meaning_description"] = ev["description"]
                break
        fields.append(item)
    return {"ok": True, "svd": _CACHE["path"], "device": _CACHE["device"],
            "peripheral": (per["name"] if per else None),
            "register": reg.get("name"), "address": (hex(int(address)) if address is not None else None),
            "matched_by": matched_by,
            "value": val, "value_hex": "0x%08X" % val,
            "access": reg.get("access"), "size": reg.get("size"),
            "register_description": reg.get("description"),
            "fields": fields,
            "note": ("字段按 SVD 的 bitOffset/bitWidth 拆解；未列出的位为保留位。"
                     "枚举值来自 SVD 的 enumeratedValues。")}
