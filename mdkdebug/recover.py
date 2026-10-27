# -*- coding: utf-8 -*-
"""工程级逆向（批次79）——从 hex / bin / elf / lib / so 还原出**能用**的工程骨架。

为什么值得单独做
--------------
拿到一份别人的固件（或者自己半年前烧进去、源码已经丢了的那份），真正要回答的
不是「它多大」，而是**「这是什么工程」**：代码在哪段地址、有哪些函数、谁调谁、
哪些是中断、数据/字符串在哪、链接布局是什么、源文件叫什么。
回答了这些才能重建工程、才能在正确的地址上打断点、才能判断改动会不会踩到别人的函数。

本模块的口径（沿用批次78 的四条，另加两条逆向专有的）：

1. **身份先于解释**：一切结论挂在 ``path + size + sha256`` 上。
2. **观察 / 推导 / 未知三分**：符号表里的函数是**观察**（observed）；向量表与 BL
   目标推出来的入口是**推导**（inferred）；没有符号又没有交叉证据的字节是**未知**，
   不编名字、不猜类型。
3. **取件/出件不覆盖**：输出目录必须不存在（``xb`` 独占写 + 回读 SHA-256）。
4. **有界**：输入、反汇编条数、函数数、成员数都有上限，超了如实进 gaps。
5. **不假装恢复了语义**：反汇编能还原**地址、指令、控制流**，还原不了「这个函数在
   算什么东西」。所以生成的函数原型一律按「无参、void 返回」写字，并在文件头写明
   「原型是推断的」，避免下游把它当事实。
6. **尽量不引依赖**：ELF / ar / Intel HEX / 向量表 / 交叉引用**全部纯 ``struct`` 实现**；
   capstone 只用于「真要出汇编」的那一步，缺失就明确报错；pyelftools 只在有 DWARF
   时用来读源文件清单（缺了降级，不影响其它结论）。

公开入口
--------
``analyze(path)``        一次剖析（格式/架构/布局/符号/向量表/字符串/交叉引用）
``symbols_report(path)`` 符号恢复报告（三档置信）
``disasm_text(path)``    反汇编文本
``build_project(...)``   生成工程骨架目录
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct

from . import evidence as _evidence
from . import textio as _textio

from . import closure, containers, fid, reveng, rtypes
import subprocess

# ---- 上限：都是「防呆」，不是「性能调优」 ----
MAX_INPUT_BYTES = 128 * 1024 * 1024   # 与批次78 的镜像取证同口径
MAX_FUNCTIONS = 4000                  # 恢复函数数上限
MAX_INSNS = 400000                    # 单次反汇编指令数上限
MAX_MEMBERS = 256                     # ar 成员数上限
MAX_STRING_LEN = 200                  # 单个字符串采集上限
MIN_STRING_LEN = 4

# ELF 常量
_ET = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_EM = {0x03: "x86", 0x08: "MIPS", 0x28: "ARM", 0x2A: "SuperH", 0x3E: "x86-64",
       0xB7: "AArch64", 0xF3: "RISC-V", 0x14: "PowerPC", 0x2B: "SPARC"}
_SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
        6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM",
        14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
        18: "SYMTAB_SHNDX"}
_STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
        5: "COMMON", 6: "TLS"}
_STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}

# Cortex-M 异常名（前 16 个向量是内核固定的）
_EXC = ["Initial_SP", "Reset", "NMI", "HardFault", "MemManage", "BusFault",
        "UsageFault", "", "", "", "SVCall", "DebugMon", "", "PendSV", "SysTick"]


# ----------------------------------------------------------------------
# 身份
# ----------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _identity(path: str, data: bytes) -> dict:
    return {
        "path": os.path.abspath(path),
        "size": len(data),
        "sha256": sha256_bytes(data),
    }


def _read_file(path: str):
    """读入并做体积/存在性检查，返回 (data, error_dict_or_None)。"""
    if not path:
        return None, {"ok": False, "error": "缺少 path"}
    if not os.path.isfile(path):
        return None, {"ok": False, "error": "文件不存在：%s" % path}
    size = os.path.getsize(path)
    if size == 0:
        return None, {"ok": False, "path": os.path.abspath(path), "size": 0,
                      "error": "空文件：没有任何可判的事实"}
    if size > MAX_INPUT_BYTES:
        return None, {"ok": False, "path": os.path.abspath(path), "size": size,
                      "error": "输入超过 %d MiB 上限（本工具不读半个文件去猜整体）"
                               % (MAX_INPUT_BYTES // (1024 * 1024))}
    with open(path, "rb") as f:
        return f.read(), None


# ----------------------------------------------------------------------
# 容器判定
# ----------------------------------------------------------------------
def detect_container(head: bytes) -> str:
    """``ar`` / ``elf`` / ``ihex`` / ``srec`` / ``pe`` / ``coff`` / ``macho`` / ``bin``。

    真判定在 ``containers.detect``（返回 kind + 证据）；这里只保留「只要 kind」的老接口，
    不做第二套判据——两套判据迟早会给出两个答案。
    """
    return containers.detect(head)[0]


# ----------------------------------------------------------------------
# ELF（纯 struct，不用 pyelftools）
# ----------------------------------------------------------------------
def _cstr(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", "replace")


def parse_elf(data: bytes) -> dict:
    """解析 ELF32/64（小端/大端）的**头 + 节 + 符号 + 程序头**。

    刻意不用 pyelftools：这些字段位置在两种 class 里都是固定的，
    ``struct`` 足够，且 ``.lib`` 里每个成员都要解析一次——多一个包不值得。
    """
    if not data.startswith(b"\x7fELF"):
        return {"ok": False, "error": "不是 ELF"}
    if len(data) < 52:
        return {"ok": False, "error": "ELF 头不完整（短于 52 字节）"}
    cls, enc = data[4], data[5]
    if cls not in (1, 2):
        return {"ok": False, "error": "ELF class=%d 不认识" % cls}
    if enc not in (1, 2):
        return {"ok": False, "error": "ELF 字节序字段=%d 不认识" % enc}
    e = "<" if enc == 1 else ">"
    out = {
        "ok": True,
        "class": 32 if cls == 1 else 64,
        "endian": "little" if enc == 1 else "big",
        "relocatable": False,
    }
    e_type, e_machine, _ver = struct.unpack(e + "HHI", data[16:24])
    out["type"] = _ET.get(e_type, "type_%d" % e_type)
    out["type_id"] = e_type
    out["machine_id"] = e_machine
    out["machine"] = _EM.get(e_machine, "machine_0x%X" % e_machine)
    out["relocatable"] = e_type == 1
    if cls == 1:
        (e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack(e + "IIIIHHHHHH",
                                                           data[24:52])
    else:
        (e_entry, e_phoff, e_shoff, e_flags) = struct.unpack(e + "QQQI", data[24:48])
        (e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack(e + "HHHHHH", data[52:64])
    out.update({"entry": int(e_entry), "flags": int(e_flags)})

    # ---- 程序头 ----
    segs = []
    if e_phoff and e_phnum and e_phentsize:
        for i in range(min(e_phnum, 64)):
            b = data[e_phoff + i * e_phentsize: e_phoff + (i + 1) * e_phentsize]
            if len(b) < (32 if cls == 1 else 56):
                break
            if cls == 1:
                p_type, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags = \
                    struct.unpack(e + "IIIIIII", b[:28])
            else:
                p_type, p_flags = struct.unpack(e + "II", b[:8])
                p_off, p_vaddr, p_paddr, p_filesz, p_memsz = \
                    struct.unpack(e + "QQQQQ", b[8:48])
            segs.append({"type": int(p_type), "offset": int(p_off),
                         "vaddr": int(p_vaddr), "paddr": int(p_paddr),
                         "filesz": int(p_filesz), "memsz": int(p_memsz),
                         "flags": int(p_flags)})
    out["segments"] = segs

    # ---- 节头 ----
    secs = []
    sh = {}
    if e_shoff and e_shnum and e_shentsize:
        raw = data[e_shoff: e_shoff + e_shentsize * e_shnum]
        for i in range(e_shnum):
            b = raw[i * e_shentsize:(i + 1) * e_shentsize]
            if len(b) < (40 if cls == 1 else 64):
                break
            if cls == 1:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
                 sh_info, sh_addralign, sh_entsize) = struct.unpack(e + "IIIIIIIIII", b[:40])
            else:
                (sh_name, sh_type) = struct.unpack(e + "II", b[:8])
                (sh_flags, sh_addr, sh_offset, sh_size) = struct.unpack(e + "QQQQ", b[8:40])
                (sh_link, sh_info) = struct.unpack(e + "II", b[40:48])
                (sh_addralign, sh_entsize) = struct.unpack(e + "QQ", b[48:64])
            secs.append({"name_off": int(sh_name), "type": int(sh_type),
                         "flags": int(sh_flags), "addr": int(sh_addr),
                         "offset": int(sh_offset), "size": int(sh_size),
                         "link": int(sh_link), "info": int(sh_info),
                         "entsize": int(sh_entsize)})
        for s in secs:
            s["name"] = ""
        if e_shstrndx < len(secs):
            strtab = secs[e_shstrndx]
            blob = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            for s in secs:
                s["name"] = _cstr(blob, s["name_off"])
        for s in secs:
            s["type_name"] = _SHT.get(s["type"], "type_%d" % s["type"])
            s["exec"] = bool(s["flags"] & 0x4)
            s["writable"] = bool(s["flags"] & 0x1)
            s["alloc"] = bool(s["flags"] & 0x2)
    out["sections"] = secs

    # ---- 符号（.symtab / .dynsym） ----
    syms = []
    for s in secs:
        if s["type"] not in (2, 11):
            continue
        src = "symtab" if s["type"] == 2 else "dynsym"
        strblob = b""
        if s["link"] < len(secs):
            st = secs[s["link"]]
            strblob = data[st["offset"]:st["offset"] + st["size"]]
        entsize = s["entsize"] or (16 if cls == 1 else 24)
        n = min(s["size"] // entsize if entsize else 0, 200000)
        base = s["offset"]
        for i in range(1, n):   # 0 号是空符号
            b = data[base + i * entsize: base + (i + 1) * entsize]
            if len(b) < entsize:
                break
            if cls == 1:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack(e + "IIIBBH", b[:16])
            else:
                st_name, st_info, st_other, st_shndx = struct.unpack(e + "IBBH", b[:8])
                st_value, st_size = struct.unpack(e + "QQ", b[8:24])
            name = _cstr(strblob, int(st_name))
            if not name:
                continue
            syms.append({"name": name, "value": int(st_value), "size": int(st_size),
                         "type": _STT.get(st_info & 0xF, "t%d" % (st_info & 0xF)),
                         "bind": _STB.get(st_info >> 4, "b%d" % (st_info >> 4)),
                         "shndx": int(st_shndx), "source": src})
    out["symbols"] = syms
    return out


# ----------------------------------------------------------------------
# ar（Keil .lib / GNU .a）
# ----------------------------------------------------------------------
def parse_ar(data: bytes) -> dict:
    """解析 ``!<arch>`` 归档，处理 GNU 长名表（``//`` + ``/偏移``）与 BSD ``#1/len``。

    Keil 的 ``.lib`` 与 GNU ``.a`` 都是这个格式；成员一般是可重定位 ELF 目标文件。
    符号索引成员（``/``、``/SYM64/``、``__.SYMDEF``）不是数据，跳过。
    """
    if not data.startswith(b"!<arch>\n"):
        return {"ok": False, "error": "不是 ar 归档（缺 !<arch> 魔数）"}
    pos = 8
    longnames = b""
    members, gaps = [], []
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[0:16].decode("latin-1").rstrip()
        if hdr[58:60] not in (b"`\n", b"`\r"):
            gaps.append({"offset": pos, "reason": "成员头结尾不是 `\\n，归档可能被截断"})
            break
        try:
            size = int(hdr[48:58].decode("latin-1").strip() or 0)
        except ValueError:
            gaps.append({"offset": pos, "reason": "成员长度字段不可解析"})
            break
        body = data[pos + 60: pos + 60 + size]
        if len(body) < size:
            gaps.append({"offset": pos, "reason": "成员数据不足（文件被截断）"})
            break
        real = name
        payload = body
        if name == "//":
            longnames = body
            pos += 60 + size + (size & 1)
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            pos += 60 + size + (size & 1)
            continue
        if name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            if end < 0:
                end = longnames.find(b"\x00", off)
            if end < 0:
                end = len(longnames)
            real = longnames[off:end].decode("utf-8", "replace")
        elif name.startswith("#1/"):
            nlen = int(name[3:] or 0)
            real = body[:nlen].decode("utf-8", "replace").rstrip("\x00")
            payload = body[nlen:]
        elif name.endswith("/"):
            real = name[:-1]
        members.append({"name": real or "member_%d" % len(members),
                        "offset": pos + 60, "size": len(payload),
                        "sha256": sha256_bytes(payload), "data": payload})
        if len(members) >= MAX_MEMBERS:
            gaps.append({"offset": pos, "reason": "成员数超过 %d，未继续解析" % MAX_MEMBERS})
            break
        pos += 60 + size + (size & 1)
    if not members and not gaps:
        gaps.append({"offset": pos, "reason": "归档里没有可解析的成员（头部不完整或只有索引成员）"})
    elif pos < len(data) and not gaps:
        gaps.append({"offset": pos, "reason": "归档尾部剩 %d 字节（不足一个成员头），未解析"
                                              % (len(data) - pos)})
    return {"ok": True, "members": members, "gaps": gaps}


# ----------------------------------------------------------------------
# 扁平镜像（hex / bin）与地址空间
# ----------------------------------------------------------------------
def _flat_image(data: bytes, kind: str, base: int) -> dict:
    """把 hex/bin 变成 ``addr -> bytes`` 的连续块（带 base）。"""
    if kind == "ihex":
        from . import image as _image
        text = data.decode("latin-1")
        info = _image.parse_ihex(text)
        if not info["spans"]:
            return {"ok": False, "error": "HEX 里没有数据记录：没有任何可逆的字节"}
        payload = _image._hex_bytes_to_sparse(text)
        real_base = int(info["min_offset"] or 0)
        return {"ok": True, "data": payload, "base": real_base, "hex": info}
    if kind == "srec":
        return containers.srec_flat(data.decode("latin-1", "replace"), base)
    return {"ok": True, "data": data, "base": int(base), "hex": None}


# ----------------------------------------------------------------------
# 架构判定与地址映射
# ----------------------------------------------------------------------
# ELF e_machine -> family。family 用 capstone 的名字（_make_cs 按它建反汇编器）；
# 表里没有的明确报「不支持」，不猜。
_CS_ARCH = {0x03: "x86", 0x3E: "x86_64", 0x08: "mips", 0x14: "ppc",
            0x15: "ppc", 0x28: "arm", 0x2A: "sh", 0x2B: "sparc",
            0x04: "m68k", 0xB7: "arm64", 0xF3: "riscv", 0x16: "s390"}


def arch_of(elf: dict) -> dict:
    """CPU 判定：family / 位宽 / 端序 / Thumb。

    Thumb 判定**必须给依据**：Cortex-M 的函数地址末位为 1（指令集选择位），
    所以「入口是奇数」或「有奇数值的函数符号」都能证明是 Thumb。
    """
    if not elf or not elf.get("ok"):
        return {"family": "unknown", "bits": 32, "endian": "little",
                "thumb": False, "supported": False, "why": "不是 ELF，无法判架构"}
    mid = int(elf.get("machine_id") or 0)
    # PE/COFF/Mach-O 的 machine 编号与 ELF 的 e_machine 是两套编码，不能混查；
    # 容器解析层已经翻译过，带了 family 就直接用（并保留 why 说明来源）。
    family = elf.get("family") or _CS_ARCH.get(mid, "unknown")
    bits = int(elf.get("class") or 32)
    endian = elf.get("endian", "little")
    thumb = False
    why = ""
    if family == "arm":
        entry = int(elf.get("entry") or 0)
        odd_funcs = any((s["type"] == "FUNC" and (s["value"] & 1))
                        for s in elf.get("symbols", []))
        has_t = any(s["name"] in ("$t", "$t.1") for s in elf.get("symbols", []))
        thumb = bool(entry & 1) or odd_funcs or has_t
        why = ("入口地址末位=%d、函数符号有奇数地址=%s、有 $t 映射符号=%s ⇒ %s"
               % (entry & 1, odd_funcs, has_t, "Thumb" if thumb else "ARM"))
    if not why and elf.get("container"):
        why = "由 %s 的机器码字段判定（0x%X / %s）" % (
            elf["container"].upper(), mid, elf.get("machine") or "?")
    return {"family": family, "bits": bits, "endian": endian, "thumb": thumb,
            "supported": family in containers.CAPSTONE_FAMILIES,
            "why": why or "按 e_machine 判定"}


def _make_cs(arch: dict):
    """建 capstone 反汇编器。缺依赖时**报错**，不返回空结果冒充「没有指令」。"""
    try:
        import capstone
    except ImportError as ie:  # noqa: BLE001
        return None, "缺少 capstone 依赖（%s），无法反汇编；pip install capstone 后重试" % ie
    fam = arch.get("family")
    try:
        if fam == "arm":
            mode = capstone.CS_MODE_THUMB if arch.get("thumb") else capstone.CS_MODE_ARM
            if arch.get("thumb"):
                try:
                    capstone.Cs(capstone.CS_ARCH_ARM, mode | capstone.CS_MODE_MCLASS)
                    mode |= capstone.CS_MODE_MCLASS
                except Exception:  # noqa: BLE001
                    pass
            if arch.get("endian") == "big":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_ARM, mode), ""
        if fam == "arm64":
            mode = capstone.CS_MODE_ARM
            if arch.get("endian") == "big":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_ARM64, mode), ""
        if fam == "riscv":
            mode = capstone.CS_MODE_RISCV64 if arch.get("bits") == 64 else capstone.CS_MODE_RISCV32
            # RVC（压缩指令）是 RV32IC/RV64IC 的常态：真实固件里大量 c.addi/c.lw/c.j。
            # 不开它就会把 2 字节指令当坏字节跳掉（看着像「函数很短」）。
            mode |= getattr(capstone, "CS_MODE_RISCVC", 0)
            return capstone.Cs(capstone.CS_ARCH_RISCV, mode), ""
        if fam == "x86":
            mode = capstone.CS_MODE_64 if arch.get("bits") == 64 else capstone.CS_MODE_32
            return capstone.Cs(capstone.CS_ARCH_X86, mode), ""
        if fam == "x86_64":
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64), ""
        if fam == "mips":
            mode = capstone.CS_MODE_MIPS64 if arch.get("bits") == 64 else capstone.CS_MODE_MIPS32
            if arch.get("endian") == "big":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_MIPS, mode), ""
        if fam == "ppc":
            mode = capstone.CS_MODE_64 if arch.get("bits") == 64 else capstone.CS_MODE_32
            # PowerPC 默认大端；小端变体要靠 ELF 的 e_flags 判，这里只在明确小端时切
            if arch.get("endian") != "little":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_PPC, mode), ""
        if fam == "m68k":
            # 68k 是**大端**架构：按小端喂进去会得到一串看着像指令的垃圾
            return capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_BIG_ENDIAN), ""
        if fam == "sparc":
            return capstone.Cs(capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN), ""
        if fam == "mos65xx":
            return capstone.Cs(capstone.CS_ARCH_MOS65XX, 0), ""
    except Exception as e:  # noqa: BLE001
        return None, "capstone 初始化失败：%s" % e
    return None, ("不支持的架构：%s（capstone 后端可用的家族：%s；"
                  "不在其中的一律不给结果，而不是猜一个）"
                  % (fam, " / ".join(containers.CAPSTONE_FAMILIES)))


class Unit:
    """一份可分析的镜像：ELF、或 HEX/BIN 展开后的扁平字节。"""

    def __init__(self, data: bytes, name: str, base: int = 0, elf: dict | None = None,
                 infer_base: bool = True):
        self.data = data
        self.name = name
        self.elf = elf
        self.container = "elf" if elf else "bin"   # elf/pe/coff/macho/ihex/srec/bin/ar
        self.entry_hint = 0     # 调用方显式指定的入口（raw bin 靠它，不靠猜）
        self.base = int(base or 0)
        # 批次95：调用方**原样传进来**的 base（不做任何平移）——它与「实际用的 base」
        # 是两件事（S-record 会把它加到记录地址上；ELF/HEX 则完全不用它）。
        # 报错现场最常见的一句话是「我传了 X，它却用了 Y」，所以两个值都必须回显。
        self.base_received = int(base or 0)
        # 批次95：「实际用来寻址的基地址」。raw BIN 等于 base；HEX/S-record
        # 等于展开后的记录起始地址；ELF/PE 等等于容器里的最低段地址。
        self.base_used = int(base or 0)
        self.base_source = "arg"      # arg / container / container+arg
        self.relocatable = bool(elf and elf.get("relocatable"))
        self.spans = []          # [(start, end, file_offset)] 覆盖的地址区间
        self.code_ranges = []    # [(start, end)] 可执行区间
        self.arch = arch_of(elf) if elf else {
            "family": "unknown", "bits": 32, "endian": "little",
            "thumb": True, "supported": False,
            "why": "HEX/BIN 没有 ELF 头：CPU 只能由调用方指定或从向量表推断",
        }
        self.limitations = []
        # 批次94：base 到底有没有生效必须能自证（ELF/HEX/S-record 自带地址）
        self.base_applied = (not elf)
        self.base_note = ""
        self.base_inferred = None
        # 批次96：裸 BIN 不给 base 时，前 8 字节若明显是 Cortex-M 向量表且复位地址
        # 落在 [0, len) 之外，说明缺的不是推断能力而是 base——按 1KB 对齐推一个，
        # 并在输出里标成 base_source="inferred"，让人能复核。
        if elf is None and infer_base and not self.base:
            inf = _infer_base_from_vectors(data)
            if inf:
                self.base = inf["base"]
                self.base_used = inf["base"]
                self.base_source = "inferred"
                self.base_inferred = inf
                self.base_note = ("raw BIN 没有传 base：按前 8 字节（SP=%s、"
                                  "复位地址=%s）推断 base=%s（1KB 对齐，"
                                  "method=%s）；若不对请显式传 base"
                                  % (inf["sp_hex"], inf["reset_hex"],
                                     inf["base_hex"], inf["method"]))
        self._build_spans()
        if elf is None:
            self._infer_arch_from_vectors()

    def _infer_arch_from_vectors(self):
        """HEX/BIN 没有 ELF 头：只看前 8 字节——复位地址 bit0=1 说明是 Thumb（Cortex-M）。"""
        head = self.read(self.base, 8)
        if len(head) < 8:
            self.limitations.append("镜像短于 8 字节：连向量表都不完整")
            return
        sp = int.from_bytes(head[0:4], "little")
        reset = int.from_bytes(head[4:8], "little")
        if reset & 1:
            self.arch = {"family": "arm", "bits": 32, "endian": "little",
                         "thumb": True, "supported": True,
                         "why": "无 ELF 头，由向量表复位地址 bit0=1 推断为 Thumb（Cortex-M 形态）",
                         "basis": "inferred_from_vector_table"}
            self.limitations.append(
                "架构是从向量表**推断**的（不是 ELF 头声明的）：若这份 bin 的基地址给错，"
                "反汇编结果会整体错位")
        elif sp and reset:
            self.arch = {"family": "unknown", "bits": 32, "endian": "little",
                         "thumb": False, "supported": False,
                         "why": "向量表首字与复位地址都不像 Thumb 入口：架构未判定"}
        if self.arch.get("supported") and not self.is_exec_address(reset):
            self.limitations.append("复位地址不在镜像范围内：base 可能给错了")

    def _build_spans(self):
        if self.elf:
            for s in self.elf.get("sections", []):
                if not s.get("alloc") or s["type_name"] == "NOBITS" or not s["size"]:
                    continue
                self.spans.append((s["addr"], s["addr"] + s["size"], s["offset"]))
                if s.get("exec"):
                    self.code_ranges.append((s["addr"], s["addr"] + s["size"]))
            if not self.spans:
                for seg in self.elf.get("segments", []):
                    if seg["filesz"]:
                        self.spans.append((seg["vaddr"], seg["vaddr"] + seg["filesz"],
                                           seg["offset"]))
                        if seg["flags"] & 0x1:
                            self.code_ranges.append((seg["vaddr"],
                                                     seg["vaddr"] + seg["filesz"]))
        else:
            self.spans.append((self.base, self.base + len(self.data), 0))
            self.code_ranges.append((self.base, self.base + len(self.data)))
        self.spans.sort()
        self.code_ranges.sort()

    # ---- 地址访问 ----
    def _locate(self, addr: int):
        """地址 → ``(file_offset, 该段内还能连续读到多少字节, 段起点, 段终点)``。

        **base 只在这里应用一次**：span 的起点里已经含 base（见 ``_build_spans``），
        所以传进来的地址就是最终地址，这里不再做任何平移。找不到返回
        ``(None, 0, None, None)``。
        """
        for start, end, off in self.spans:
            if start <= addr < end:
                return off + (addr - start), end - addr, start, end
        return None, 0, None, None

    def offset_of(self, addr: int):
        off, _avail, _s, _e = self._locate(addr)
        return off

    def read(self, addr: int, n: int) -> bytes:
        """读 ``[addr, addr+n)``。**不跨地址空洞**：只读到所在段的结尾。

        批次94 之前这里是 ``data[off:off+n]`` 裸切片：一旦 ``addr`` 靠近段尾，切片会
        **越过段边界**，把文件里紧邻的其它节的字节当成这些地址的字节返回，而标签仍是
        原地址——指令流、分支目标、字面量池全错位，调用方却看不出任何异常。
        需要知道「为什么短了」用 :meth:`read_ex`。"""
        return self.read_ex(addr, n)["data"]

    def read_ex(self, addr: int, n: int) -> dict:
        """带出处的读：``{data, file_offset, span, requested, got, clipped, reason}``。

        ``file_offset`` 是这批字节在**文件里**的偏移（不是地址），用于自证；
        ``clipped`` 为真表示请求越过了所在段/文件尾，``reason`` 说明原因，
        调用方**必须**把这种情况透出去，不能当成读到了完整数据。
        """
        n = int(n or 0)
        addr = int(addr)
        off, avail, sp_start, sp_end = self._locate(addr)
        if off is None:
            return {"data": b"", "file_offset": None, "span": None,
                    "requested": n, "got": 0, "clipped": False,
                    "reason": "地址 0x%08X 不在镜像映射范围内" % addr}
        take = min(n, avail, max(0, len(self.data) - off))
        data = self.data[off:off + take]
        out = {"data": data, "file_offset": off,
               "span": {"start_hex": "0x%08X" % sp_start,
                        "end_hex": "0x%08X" % sp_end},
               "requested": n, "got": len(data), "clipped": len(data) < n,
               "reason": ""}
        if len(data) < n:
            if off + take >= len(self.data):
                out["reason"] = ("读到文件末尾：只返回 %d 字节（文件总长 %d），请求 %d 字节"
                                  % (len(data), len(self.data), n))
            else:
                out["reason"] = ("读越了所在段（0x%08X..0x%08X）的末尾：只返回段内 %d 字节，"
                                  % (sp_start, sp_end, len(data))
                                  + "**不把文件里紧邻的其它节当成这些地址的字节**")
        return out

    def in_code(self, addr: int) -> bool:
        return any(a <= addr < b for a, b in self.code_ranges)

    def is_exec_address(self, value: int) -> bool:
        """这个字**看起来**是代码指针吗：去 Thumb 位后落在可执行区间内。"""
        return self.in_code(value & ~1)

    def section_of(self, addr: int):
        if not self.elf:
            return None
        for s in self.elf.get("sections", []):
            if s.get("alloc") and s["size"] and s["addr"] <= addr < s["addr"] + s["size"]:
                return s
        return None


def _unit_from_data(data: bytes, name: str, base: int = 0) -> Unit:
    kind = detect_container(data[:4096])
    if kind == "elf":
        unit = Unit(data, name, base=base, elf=parse_elf(data), infer_base=False)
        unit.base_received = int(base or 0)
        unit.base_used = min((a for a, _b, _o in unit.spans), default=0)
        unit.base_applied = False
        unit.base_source = "container"
        if base:
            unit.base_note = ("ELF 自带地址映射：base=0x%08X **被忽略**（不叠加），"
                              "地址一律取自 sh_addr/p_vaddr" % int(base))
        return unit
    if kind in ("ihex", "srec"):
        flat = _flat_image(data, kind, base)
        if not flat.get("ok"):
            raise ValueError(flat.get("error", "HEX/S-record 解析失败"))
        unit = Unit(flat["data"], name, base=flat["base"], infer_base=False)
        unit.container = kind
        unit.base_received = int(base or 0)
        unit.base_used = int(flat["base"] or 0)
        unit.base_applied = (kind == "srec" and bool(base))
        unit.base_source = "container+arg" if kind == "srec" else "container"
        if kind == "ihex":
            unit.base_note = ("HEX 自带记录地址（min_offset=0x%08X）：base **被忽略**"
                              "（不叠加）" % int(flat["base"] or 0))
        elif base:
            unit.base_note = ("S-record 记录地址整体平移 base=0x%08X（**只应用一次**）"
                              % int(base))
        if kind == "srec":
            info = flat.get("srec") or {}
            if info.get("entry"):
                unit.arch = {"family": "arm", "bits": 32,
                             "endian": "little", "thumb": bool(info["entry"] & 1),
                             "supported": True,
                             "why": "S7/S8/S9 起始地址末位=%d ⇒ %s"
                                    % (info["entry"] & 1,
                                       "Thumb" if info["entry"] & 1 else "ARM"),
                             "basis": "inferred_from_srec_start"}
            if info.get("gap_bytes"):
                unit.limitations.append("S-record 有 %d 个地址空洞（未填字节按 0 放置）："
                                        "空洞里的字节不是镜像内容"
                                        % info["gap_bytes"])
        return unit
    if kind in ("pe", "coff", "macho"):
        parsed = {"pe": containers.parse_pe, "coff": containers.parse_coff,
                  "macho": containers.parse_macho}[kind](data)
        if not parsed.get("ok"):
            raise ValueError(parsed.get("error", "%s 解析失败" % kind))
        unit = Unit(data, name, base=base, elf=parsed, infer_base=False)
        unit.container = kind
        unit.base_received = int(base or 0)
        unit.base_used = min((a for a, _b, _o in unit.spans), default=0)
        unit.base_applied = False
        unit.base_source = "container"
        if base:
            unit.base_note = ("%s 自带地址映射：base=0x%08X **被忽略**（不叠加）"
                              % (kind.upper(), int(base)))
        for n in parsed.get("notes") or []:
            unit.limitations.append(n)
        return unit
    unit = Unit(data, name, base=base)
    unit.container = kind
    unit.base_applied = True
    if not unit.base_inferred:
        unit.base_note = ("raw %s 没有自带地址：base=0x%08X 作为基地址**只应用一次**"
                          % (kind.upper(), int(base or 0)))
    return unit


# ----------------------------------------------------------------------
# 向量表
# ----------------------------------------------------------------------
def vector_table(unit: Unit, base: int | None = None, max_entries: int = 128,
                 endian: str | None = None, skip_empty: bool = False) -> dict:
    """按 Cortex-M 约定读前 N 个字：初值 SP + 异常/中断入口。

    每一栏都是**观察到的事实**（地址、Thumb 位），但「这个入口属于哪个中断」只在
    前 16 个（内核固定）里成立；外部中断编号的语义取决于具体芯片，所以标
    ``semantics: "unverified"``——知道地址不等于知道它是哪个外设。
    """
    en = endian or (unit.arch.get("endian") or "little")
    if base is None:
        base = unit.base if not unit.elf else (unit.code_ranges[0][0] if unit.code_ranges else 0)
    out = {"base_hex": "0x%08X" % int(base), "entries": [], "sp": None,
           "reset": None, "count": 0, "semantics": "unverified", "gaps": [],
           "empty": []}
    first = unit.read(base, 4 * max_entries)
    if len(first) < 8:
        out["gaps"].append({"reason": "镜像在向量表地址处不足 8 字节，读不到 SP/复位地址"})
        return out
    words = []
    for i in range(len(first) // 4):
        words.append(int.from_bytes(first[i * 4:i * 4 + 4], en))
    sp = words[0]
    out["sp_hex"] = "0x%08X" % sp
    out["sp"] = sp
    if sp == 0 or sp == 0xFFFFFFFF:
        out["gaps"].append({"reason": "首字不是合理的栈顶（0 或 0xFFFFFFFF）："
                                      "该地址可能不是向量表，或镜像是压缩/加密的"})
    for i, w in enumerate(words):
        if i > 0 and (w == 0 or w == 0xFFFFFFFF):
            if skip_empty:
                # Cortex-M 的保留槽位（7..10）本来就常常是 0：当空槽跳过而**不**终止，
                # 否则 SysTick/外设中断入口整片丢在表外（会连带把它们调用的函数
                # 误判成不可达）。
                out["empty"].append(i)
                continue
            break
        if i == 0:
            continue
        if skip_empty and not unit.is_exec_address(w):
            # 向量表里出现「不是代码地址」的非零字 ⇒ 表到此结束（后面已是别的数据）
            out["gaps"].append({"reason": "第 %d 个槽位是非代码地址 0x%08X："
                                          "按会话约定这里视为向量表结束" % (i, w)})
            break
        name = _EXC[i] if i < len(_EXC) else ("IRQ%d" % (i - 16) if i >= 16 else "")
        entry = {
            "index": i,
            "handler_hex": "0x%08X" % w,
            "thumb": bool(w & 1),
            "in_code": unit.is_exec_address(w),
            "name": name or ("vector%d" % i),
        }
        out["entries"].append(entry)
        if i == 1:
            out["reset"] = w
            out["reset_hex"] = "0x%08X" % w
    out["count"] = len(out["entries"])
    if out["entries"] and not any(e["in_code"] for e in out["entries"]):
        out["gaps"].append({"reason": "所有入口地址都不落在可执行区间内："
                                      "要么 base 给错了，要么这不是一份可直接运行的镜像"})
    out["limitations"] = [
        "前 16 个是 Cortex-M 内核固定异常；IRQn 的**具体外设**取决于芯片，未判定",
        "读到 0/0xFFFFFFFF 即停止：中间的空洞不会让后面被误当入口",
    ]
    return out


# ----------------------------------------------------------------------
# 符号恢复
# ----------------------------------------------------------------------
def _norm_addr(v: int, thumb: bool) -> int:
    """Thumb 地址末位是「指令集选择位」，不是地址的一部分。"""
    return (v & ~1) if (thumb and (v & 1)) else v


def _clean_name(name: str) -> str:
    """过滤 ARM 映射符号（$t/$d/$a/$t.1）与编译器内部符号。"""
    n = name.strip()
    if n in ("$t", "$d", "$a") or n.startswith(("$t.", "$d.", "$a.")):
        return ""
    return n


def symbol_table(unit: Unit) -> dict:
    """把 ELF 符号表分成函数/对象/其它，并**保留绑定与来源**（观察事实）。"""
    funcs, objs, others = [], [], []
    mapping = []
    if not unit.elf:
        return {"functions": [], "objects": [], "other": 0, "mapping_symbols": 0,
                "counts": {"functions": 0, "objects": 0, "other": 0},
                "available": False,
                "why": "HEX/BIN 没有符号表：名字只能从向量表与交叉引用推断"}
    for s in unit.elf.get("symbols", []):
        raw = s["name"]
        if raw in ("$t", "$d", "$a") or raw.startswith(("$t.", "$d.", "$a.")):
            mapping.append({"name": raw, "value": s["value"]})
            continue
        name = _clean_name(raw)
        if not name:
            continue
        rec = {"name": name, "value": s["value"], "addr": _norm_addr(s["value"], True),
               "size": s["size"], "bind": s["bind"], "type": s["type"],
               "source": s["source"], "confidence": "observed"}
        if s["type"] == "FUNC":
            funcs.append(rec)
        elif s["type"] in ("OBJECT", "COMMON", "TLS"):
            objs.append(rec)
        else:
            others.append(rec)
    return {
        "available": True,
        "functions": funcs,
        "objects": objs,
        "other": len(others),
        "mapping_symbols": len(mapping),
        "counts": {"functions": len(funcs), "objects": len(objs),
                   "other": len(others), "mapping_symbols": len(mapping)},
        "limitations": ["符号表只能证明「这里有一个叫这个名字的函数」，"
                        "不证明函数体没被内联/裁剪过；st_size=0 的符号边界未知"],
    }


# ----------------------------------------------------------------------
# 反汇编
# ----------------------------------------------------------------------
_RET_MNEMONICS = {"bx": ("lr",), "pop": ("pc",), "mov": ("pc",),
                  "ret": None, "ldr": ("pc",), "jmp": None}


def _looks_like_return(mnemonic: str, op_str: str) -> bool:
    m = mnemonic.lower()
    if m in ("ret", "jr"):
        return m == "ret"
    if m == "bx":
        return op_str.strip().endswith("lr")
    if m == "pop":
        return "pc" in op_str
    if m == "mov":
        return op_str.strip().endswith("pc") or ", pc" in op_str
    if m == "ldr" and "pc" in op_str:
        return True
    return False


def _branch_target(mnemonic: str, op_str: str):
    """从 ``bl #0x8001234`` 这类操作数里取直接跳转目标（纯文本解析，跨架构通用）。"""
    m = mnemonic.lower()
    if m not in ("bl", "blx", "b", "b.w", "beq", "bne", "bcs", "bcc", "bmi",
                 "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble",
                 "bal", "jal", "j", "call", "cbnz", "cbz"):
        return None
    s = op_str.strip().lstrip("#")
    tok = s.split(",")[0].strip()
    if not tok:
        return None
    if tok.startswith("0x"):
        try:
            return int(tok, 16)
        except ValueError:
            return None
    return None


def _source_of(rd: dict, unit: Unit) -> dict:
    """把一次 :meth:`Unit.read_ex` 的出处整理成给调用方看的 ``source``。

    ``file_offset`` 是文件偏移、``span`` 是这次地址落在哪个映射段；
    ``clipped`` 为真时必须读 ``reason``——数据没读全，结论不能照用。
    """
    sp = rd.get("span") or {}
    off = rd.get("file_offset")
    return {"file_offset": off,
            "file_offset_hex": ("0x%X" % off) if off is not None else None,
            "span": sp, "requested": rd.get("requested"),
            "got": rd.get("got"), "clipped": bool(rd.get("clipped")),
            "reason": rd.get("reason") or "",
            "container": unit.container,
            "base_applied": bool(getattr(unit, "base_applied", False)),
            "base_note": getattr(unit, "base_note", "")}


def _infer_base_from_vectors(data: bytes) -> dict:
    """裸 BIN 没给 base 时，用前 8 字节推一个基地址。**不满足就返回 {}，不猜。**

    判据（全部满足才推）：
      - 首字是合理 SP（4 字节对齐、0x10000000–0x40000000）；
      - 复位地址 bit0=1（Cortex-M Thumb 入口）；
      - 复位地址**已经落在 [0, len) 之外**——在范围内说明 base=0 本来就对，不用推；
      - 复位地址按 1KB 向下取整得到候选 base，且该候选让复位地址落在镜像内
        （即复位向量距镜像起点 < min(len, 1KB)）。

    1KB 对齐是 Cortex-M 镜像的常见起点粒度；推出来的值一定会被标成
    ``base_source="inferred"`` 并进 notes，**不是**偷偷替换调用方的参数。
    """
    if len(data) < 8:
        return {}
    sp = int.from_bytes(data[0:4], "little")
    reset = int.from_bytes(data[4:8], "little")
    sp_ok = (sp & 3) == 0 and 0x10000000 <= sp <= 0x40000000
    if not sp_ok or not (reset & 1):
        return {}
    entry = reset & ~1
    if entry < len(data):
        return {}                      # 本来就有一个自洽的 base=0，别动
    cand = entry & ~0x3FF
    if cand <= 0 or not (cand <= entry < cand + len(data)):
        return {}
    return {"base": cand, "base_hex": "0x%08X" % cand,
            "method": "cortex_m_vector_table_1k_alignment",
            "sp_hex": "0x%08X" % sp, "reset_hex": "0x%08X" % reset,
            "reset_offset": entry - cand,
            "evidence": "首字是合理 SP 且复位地址 bit0=1，但复位地址不在 "
                        "[0,0x%X) 内 ⇒ 缺 base 而不是缺代码" % len(data)}

def _base_check(unit: Unit) -> dict:
    """raw BIN 的 base 自检：按这个 base 读到的前 8 字节像不像 Cortex-M 向量表？

    只对「没有自带地址」的容器有意义——ELF/HEX 的地址来自容器，不靠 base 猜。
    **只做提示，不改任何结果**：工具不会替你换 base，但要让「base 差一页」
    在输出里看得见，而不是等调用方从一堆看着正常的指令里发现。
    """
    if getattr(unit, "base_source", "arg") not in ("arg", "inferred"):
        return {"applicable": False,
                "why": "容器自带地址（%s）：地址不靠 base 猜，本自检不适用"
                       % unit.container}
    fam = (unit.arch or {}).get("family")
    if fam not in ("arm", "unknown", None):
        return {"applicable": False,
                "why": "架构是 %s：向量表约定是 Cortex-M 的，本自检不适用" % fam}
    head = unit.read_ex(unit.base, 8)["data"]
    if len(head) < 8:
        return {"applicable": True, "verdict": "too_short",
                "why": "镜像在该地址起不足 8 字节：连向量表都不完整"}
    sp = int.from_bytes(head[0:4], "little")
    reset = int.from_bytes(head[4:8], "little")
    sp_ok = (sp & 3) == 0 and 0x10000000 <= sp <= 0x40000000
    reset_in = unit.base <= (reset & ~1) < unit.base + len(unit.data)
    good = sp_ok and reset_in and bool(reset & 1)
    out = {"applicable": True,
           "sp_hex": "0x%08X" % sp, "sp_plausible": sp_ok,
           "reset_hex": "0x%08X" % reset, "reset_thumb_bit": bool(reset & 1),
           "reset_in_image": reset_in,
           "verdict": ("looks_like_cortex_m_vector_table" if good
                       else "not_a_vector_table"),
           "basis": "按 base 读到的前 8 字节（SP、复位地址），只做提示不参与判定"}
    if not good:
        out["hint"] = ("按这个 base 读到的前 8 字节不像 Cortex-M 向量表：base 差一页"
                       "或差整段都会这样。工具**不会**自动改 base——请核对 "
                       "address_map.base_received_hex（你传的）与 base_hex（实际用的）")
    return out


def _base_conflict(unit: Unit) -> dict:
    """容器自带地址 与 调用方传的 base 不一致时，把两个值摆出来。

    这种情况 base **按设计不叠加**（ELF/HEX），但「我传了 0x08005000 它却用了
    0x08004000」读起来就像工具忽略了参数——所以必须显式报，而不是只写在 note 里。
    """
    got = int(getattr(unit, "base_received", 0) or 0)
    if not got or getattr(unit, "base_source", "arg") != "container":
        return {}
    used = int(getattr(unit, "base_used", unit.base) or 0)
    if got == used:
        return {}
    return {"argument_hex": "0x%08X" % got,
            "container_hex": "0x%08X" % used,
            "delta": used - got,
            "note": "%s 自带地址（容器里写的就是 0x%08X）：你传的 base=0x%08X "
                    "被**忽略、不叠加**。两者相差 %d 字节（0x%X）——若你预期的"
                    "镜像起始地址是后者，说明容器记录/ELF 头写的是另一个地址，"
                    "不是 base 没生效"
                    % (unit.container, used, got, used - got, abs(used - got))}


def _address_map(unit: Unit) -> dict:
    """这次反汇编用的地址映射：容器 + base 有没有生效 + 段清单。

    批次94：ELF/HEX/S-record 自带地址，``base`` 对它们**不叠加**；
    以前是静默忽略（调用方以为平移过了），现在明写 ``base_applied``。
    批次95：再把「到货的 base」与「实际用的 base」分开报，并给容器冲突与向量表自检。
    """
    out = {"container": unit.container,
           "base_hex": "0x%08X" % int(
               getattr(unit, "base_used", unit.base) or 0),
           "base_received_hex": "0x%08X" % int(
               getattr(unit, "base_received", 0) or 0),
           "base_source": getattr(unit, "base_source", "arg"),
           "base_applied": bool(getattr(unit, "base_applied", False)),
           "base_inferred": getattr(unit, "base_inferred", None),
           "note": getattr(unit, "base_note", ""),
           "spans": ["0x%08X..0x%08X(file 0x%X)" % (a, b, o)
                     for a, b, o in unit.spans[:32]]}
    chk = _base_check(unit)
    if chk:
        out["base_check"] = chk
    conf = _base_conflict(unit)
    if conf:
        out["base_conflict"] = conf
    return out


def readback_mismatches(unit: Unit, items) -> list:
    """逐条核对「解码用的字节」与「按同一地址从文件重读的字节」。

    ``items`` 是 ``[(addr, size, bytes_hex), ...]``；返回不一致清单（最多 8 条），
    空清单 = 全部一致。批次94：这是「读错偏移却照常报 ok」的兜底。
    """
    bad = []
    for addr, size, hexs in items:
        chk = unit.read_ex(addr, size)
        if chk["data"].hex() != (hexs or ""):
            off = chk.get("file_offset")
            bad.append({"addr_hex": "0x%08X" % addr, "decoded": hexs or "",
                        "reread": chk["data"].hex(),
                        "file_offset_hex": ("0x%X" % off) if off is not None else None,
                        "reason": chk["reason"] or "重读字节与解码字节不同"})
            if len(bad) >= 8:
                break
    return bad


def disassemble(unit: Unit, start: int, end: int, *, md=None,
                max_insns: int = MAX_INSNS, with_regs: bool = False) -> dict:
    """反汇编 ``[start, end)``。capstone 缺失/架构不支持时**明确报错**。

    ``with_regs=True`` 时每条指令多带 ``reads`` / ``writes``（capstone 的寄存器访问集合，
    含隐式访问）。默认关闭：这两个字段只服务于调用约定推断（批次81），
    关掉可以让所有既有输出逐字节不变。
    """
    if md is None:
        md, why = _make_cs(unit.arch)
        if md is None:
            return {"ok": False, "error": why}
    got = unit.read_ex(start, end - start)
    blob = got["data"]
    if not blob:
        return {"ok": False, "error": got["reason"] or
                "地址 0x%08X 不在镜像的映射范围内" % start,
                "addr_hex": "0x%08X" % start,
                "source": _source_of(got, unit)}
    try:
        md.detail = True
    except Exception:  # noqa: BLE001
        pass
    insns, truncated = [], False
    unit_size = 2 if (unit.arch.get("thumb") or unit.arch.get("family") == "riscv") else 4
    pos, skipped, addr = 0, 0, start
    while pos < len(blob):
        progressed = False
        for ins in md.disasm(blob[pos:], start + pos):
            rec = {"addr": ins.address, "addr_hex": "0x%08X" % ins.address,
                   "mnemonic": ins.mnemonic, "op_str": ins.op_str,
                   "bytes": ins.bytes.hex(), "size": ins.size}
            tgt = _branch_target(ins.mnemonic, ins.op_str)
            if tgt is not None:
                rec["target"] = tgt
                rec["target_hex"] = "0x%08X" % tgt
            if _looks_like_return(ins.mnemonic, ins.op_str):
                rec["ends_function"] = True
            if with_regs:
                try:
                    rd, wr = ins.regs_access()
                    rec["reads"] = sorted({ins.reg_name(r) for r in rd})
                    rec["writes"] = sorted({ins.reg_name(r) for r in wr})
                except Exception:      # noqa: BLE001
                    # capstone 在某些架构/版本上不提供寄存器访问，就当「不知道」
                    rec["reads"], rec["writes"] = [], []
            insns.append(rec)
            addr = ins.address + ins.size
            pos = addr - start
            progressed = True
            if len(insns) >= max_insns:
                truncated = True
                break
        if truncated:
            break
        if not progressed or pos < len(blob):
            # capstone 遇到无法解码的字节会停下：**跳过对齐单元继续**，
            # 不把「一个坏字节」当成「这段再没有指令」（否则大段代码静默消失）。
            pos = min(pos + unit_size, len(blob))
            addr = start + pos
            skipped += 1
    # ---- 字节回填校验（批次94）----
    # 解码用的字节必须能**按同一地址从文件里重新读到**、且逐字节相同。
    # 这是「读错偏移却照常报 ok」的兜底：整体平移、跨段拼接都会在这里立刻对不上，
    # 宁可 ok=False 也不给一份看着正常的错汇编。
    bad = readback_mismatches(unit, [(x["addr"], x["size"], x["bytes"])
                                     for x in insns])
    if bad:
        return {"ok": False,
                "error": "字节回填校验失败：反汇编用的字节与按地址从文件重读的字节不一致"
                         "（读错偏移或跨段拼接都会这样），指令流/分支目标/字面量池都不可信",
                "start_hex": "0x%08X" % start, "end_hex": "0x%08X" % end,
                "mismatches": bad, "source": _source_of(got, unit),
                "hint": "先用 recover_probe 核对 base 与地址映射（address_map.base_applied）："
                        "ELF/HEX/S-record 自带地址，base 对它们不叠加"}
    out_skipped = skipped
    out = {"ok": True, "start_hex": "0x%08X" % start, "end_hex": "0x%08X" % end,
           "count": len(insns), "truncated": truncated, "insns": insns,
           "undefined_skips": out_skipped, "consumed": addr - start,
           "source": _source_of(got, unit)}
    if out_skipped:
        out["notes"] = ["有 %d 处无法解码的字节已跳过（指令对齐处继续），"
                        "该处指令未纳入结果" % out_skipped]
    if truncated:
        out["gaps"] = [{"reason": "指令数超过 %d 上限，反汇编在该点截断" % max_insns}]
    if got.get("clipped"):
        out["notes"] = (out.get("notes") or []) + [
            "只读到 0x%X 字节（请求 0x%X）：%s"
            % (got["got"], got["requested"], got["reason"])]
    return out


def disasm_text(unit: Unit, functions: list, *, max_insns: int = MAX_INSNS,
                per_function: int = 20000) -> dict:
    """给每个函数出汇编文本（带地址、机器码、符号名）。"""
    md, why = _make_cs(unit.arch)
    if md is None:
        return {"ok": False, "error": why}
    code_end = max((b for _, b in unit.code_ranges), default=unit.base)
    lines, blocks, truncated = [], [], False
    total = 0
    for f in functions:
        start = f["addr"]
        end = f.get("end_addr") or min(start + (f.get("size") or 0) or (code_end - start),
                                       code_end)
        if end <= start:
            continue
        if total >= max_insns:
            truncated = True
            break
        r = disassemble(unit, start, end, md=md,
                        max_insns=min(per_function, max_insns - total))
        if not r.get("ok"):
            blocks.append({"name": f["name"], "addr_hex": "0x%08X" % start,
                           "error": r.get("error")})
            continue
        total += r["count"]
        blocks.append({"name": f["name"], "addr_hex": "0x%08X" % start,
                       "end_hex": "0x%08X" % end, "count": r["count"],
                       "truncated": r["truncated"], "insns": r["insns"]})
        lines.append("")
        lines.append("; ---- %s  @ %s  size=%s  (%s)" % (
            f["name"], "0x%08X" % start, f.get("size") or "?", f.get("confidence")))
        lines.append("%s:" % f["name"])
        for ins in r["insns"]:
            mark = ""
            if "target" in ins:
                mark = "   ; -> 0x%08X" % ins["target"]
            lines.append("    %08X:  %-20s  %-24s%s" % (
                ins["addr"], ins["bytes"], (ins["mnemonic"] + " " + ins["op_str"]).strip(),
                mark))
    return {"ok": True, "text": "\n".join(lines).strip() + "\n", "blocks": blocks,
            "insn_count": total, "truncated": truncated}


# ----------------------------------------------------------------------
# 交叉引用与字符串
# ----------------------------------------------------------------------
def find_strings(unit: Unit, *, min_len: int = MIN_STRING_LEN,
                 max_strings: int = 2000) -> list:
    """扫描**所有已分配区间**找可打印字符串。

    为什么代码区也扫：MDK 的 axf 常常只有一个 ``ER_IROM1``（代码 + 只读数据同一节），
    只扫"非可执行区"会一个字符串都找不到——那是**漏**，不是"没有字符串"。
    所以代码区里的命中保留并标 ``in_code=True``（它可能只是指令字节凑巧可打印，
    也可能是字面量池里的常量字符串），交给调用方按需要过滤。
    """
    out, truncated = [], False
    for start, end, off in unit.spans:
        blob = unit.data[off:off + (end - start)]
        in_code = any(a <= start < b for a, b in unit.code_ranges)
        i = 0
        while i < len(blob):
            c = blob[i]
            if 0x20 <= c <= 0x7E or c == 0x09:
                j = i
                while j < len(blob) and (0x20 <= blob[j] <= 0x7E or blob[j] == 0x09):
                    j += 1
                if j - i >= min_len:
                    out.append({"addr": start + i, "addr_hex": "0x%08X" % (start + i),
                                "len": j - i, "in_code": in_code,
                                "text": blob[i:j][:MAX_STRING_LEN].decode("latin-1")})
                    if len(out) >= max_strings:
                        truncated = True
                        break
                i = j
            else:
                i += 1
        if truncated:
            break
    if truncated:
        out.append({"truncated": True, "reason": "字符串数超过 %d 上限" % max_strings})
    return out


def find_code_pointers(unit: Unit, *, max_hits: int = 4000,
                       exclude=None) -> dict:
    """扫 4 字节对齐的字，找出「值（去 Thumb 位）落在可执行区间内」的地址。

    这是**推导**：字面量池、跳转表、结构体里的函数指针都会命中，也可能有巧合。
    好处是剥离符号的固件里，它是唯一能证明「这个入口被当成指针用过」的证据。
    """
    hits, truncated = [], False
    en = unit.arch.get("endian", "little")
    for start, end, off in unit.spans:
        n = (end - start) // 4
        blob = unit.data[off:off + n * 4]
        for i in range(n):
            w = int.from_bytes(blob[i * 4:i * 4 + 4], en)
            from_addr = start + i * 4
            if exclude and any(a <= from_addr < b for a, b in exclude):
                continue   # 向量表自己的字天然指向代码，那不是「交叉引用」
            if exclude and any(a <= (w & ~1) < b for a, b in exclude):
                continue   # 指向向量表自身的指针不是函数入口
            if w and w != 0xFFFFFFFF and unit.is_exec_address(w):
                hits.append({"from": from_addr, "from_hex": "0x%08X" % from_addr,
                             "to": w & ~1, "to_hex": "0x%08X" % (w & ~1),
                             "thumb": bool(w & 1), "type": "code_pointer"})
                if len(hits) >= max_hits:
                    truncated = True
                    break
        if truncated:
            break
    return {"ok": True, "hits": hits, "count": len(hits), "truncated": truncated,
            "confidence": "inferred",
            "why": "4 字节字的值（去 Thumb 位）落在可执行区间内——是指针的**证据**，不是函数定义"}


# ----------------------------------------------------------------------
# DWARF（可选：只用来回答「原始工程有哪些源文件、函数住在哪一行」）
# ----------------------------------------------------------------------
def dwarf_info(path: str, *, max_cus: int = 64, max_files: int = 512,
               max_funcs: int = 4000) -> dict:
    """读 ``.debug_info``/``.debug_line``：源文件清单 + 函数的文件/行号。

    这是「工程级」逆向里**性价比最高**的一步：带 ``-g`` 编出来的 axf 里，
    函数的原始文件名与行号是**观察事实**，能直接把一堆地址组织成工程目录。
    没有 DWARF 就如实说没有——不猜源文件名。
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"available": False,
                "why": "pyelftools 未安装（可选依赖）：源文件清单不可得，"
                       "其它结论不受影响"}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return {"available": False,
                        "why": "没有 .debug_info：编译时未开调试信息（-g），"
                               "源文件名与行号**不可恢复**"}
            d = elf.get_dwarf_info()
            files, funcs, cus = [], [], []
            seen = set()
            for ci, cu in enumerate(d.iter_CUs()):
                if ci >= max_cus:
                    break
                top = cu.get_top_DIE()
                attrs = top.attributes
                cu_name = ""
                if "DW_AT_name" in attrs:
                    v = attrs["DW_AT_name"].value
                    cu_name = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
                try:
                    lp = d.line_program_for_CU(cu)
                except Exception:  # noqa: BLE001
                    lp = None
                if lp:
                    for fe in lp.header["file_entry"]:
                        nm = fe.name
                        nm = nm.decode("utf-8", "replace") if isinstance(nm, bytes) else str(nm)
                        if nm and nm not in seen:
                            seen.add(nm)
                            files.append(nm)
                            if len(files) >= max_files:
                                break
                cus.append({"name": cu_name, "n_files": len(files)})
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    a = die.attributes
                    nm = a.get("DW_AT_name")
                    lo = a.get("DW_AT_low_pc")
                    if not nm or lo is None:
                        continue
                    nm = nm.value
                    nm = nm.decode("utf-8", "replace") if isinstance(nm, bytes) else str(nm)
                    decl_file = a.get("DW_AT_decl_file")
                    decl_line = a.get("DW_AT_decl_line")
                    fn = ""
                    if decl_file is not None and lp:
                        idx = int(decl_file.value)
                        entries = lp.header["file_entry"]
                        if 0 <= idx < len(entries):
                            v = entries[idx].name
                            fn = (v.decode("utf-8", "replace") if isinstance(v, bytes)
                                  else str(v))
                    funcs.append({"name": nm, "low_pc": int(lo.value),
                                  "file": fn,
                                  "line": int(decl_line.value) if decl_line is not None else None})
                    if len(funcs) >= max_funcs:
                        break
            return {"available": True, "files": files, "functions": funcs,
                    "compilation_units": cus,
                    "limitations": ["DWARF 只覆盖**编译时存在的**函数/文件；"
                                    "内联、静态函数被裁剪后不可见",
                                    "源文件路径是编译时的字符串，可能指向不存在的目录"]}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "why": "DWARF 解析失败：%s" % e}


# ----------------------------------------------------------------------
# 函数恢复
# ----------------------------------------------------------------------
def _sweep(unit: Unit, md, *, max_insns: int = MAX_INSNS,
           with_regs: bool = False) -> dict:
    """线性扫过所有可执行区间，收集「调用目标 / 函数返回点 / 字面量引用」。

    ``with_regs=True`` 时每条指令带 ``reads`` / ``writes``（批次81 的调用约定推断要用）。
    """
    insns = {}
    truncated = False
    for start, end in unit.code_ranges:
        r = disassemble(unit, start, end, md=md, max_insns=max_insns,
                        with_regs=with_regs)
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error")}
        for ins in r["insns"]:
            insns[ins["addr"]] = ins
        if r.get("truncated"):
            truncated = True
            break
        max_insns -= r["count"]
        if max_insns <= 0:
            truncated = True
            break
    return {"ok": True, "insns": insns, "truncated": truncated}


def _imm_of(op_str: str):
    for tok in op_str.replace("]", "").split(","):
        tok = tok.strip()
        if tok.startswith("#"):
            try:
                return int(tok[1:], 0)
            except ValueError:
                return None
    return None


def _pc_ref(ins: dict):
    """识别 PC 相对寻址，返回 ``{"kind": ..., "addr": ...}``。

    ARMCC 引用字符串常量**不走 ldr 字面量池**，而是 ``adr r1, #0xa8``
    （地址 = 对齐后的 PC + 立即数）；只认 ldr 字面量会得出「0 处字符串引用」
    这种看着干净其实是漏的结论。
    ``kind="literal"`` 表示这条指令取的是**指针**（再读 4 字节才是目标）。
    """
    m = ins.get("mnemonic", "").lower()
    op = ins.get("op_str", "")
    pc = (ins["addr"] + 4) & ~3
    if m in ("adr", "adr.w", "adrl"):
        imm = _imm_of(op)
        return {"kind": "address", "addr": pc + imm} if imm is not None else None
    if m in ("ldr", "ldr.w") and "[pc" in op:
        imm = _imm_of(op)
        return {"kind": "literal", "addr": pc + imm} if imm is not None else None
    if m in ("add", "add.w", "adds") and "pc" in op:
        imm = _imm_of(op)
        return {"kind": "address", "addr": pc + imm} if imm is not None else None
    if m in ("sub", "sub.w") and "pc" in op:
        imm = _imm_of(op)
        return {"kind": "address", "addr": pc - imm} if imm is not None else None
    return None


# ----------------------------------------------------------------------
# 函数体形状与调用约定（批次81：吸收 Ghidra 的两条分析口径，零依赖）
#
# 这里吸收的是**思路**，不是代码：
#   ① 函数体到「终止指令」为止（返回 / 跳出本区的无条件跳转 / 间接跳转），
#      而不是「切到下一个已知入口」。线性扫描遇到数据岛时，后者会把数据算进函数体。
#   ② 按 AAPCS 看 r0..r3 的**首次访问是读还是写**来估参数个数（Ghidra 的 proto 分析做的
#      是同一件事，只是它带了完整的类型传播）。
# 两条都是**推断**：结果一律标证据与置信度，绝不写进「事实」字段。
# ----------------------------------------------------------------------
_UNCOND_BRANCH = ("b", "b.w", "j", "bal")
_INDIRECT_BRANCH = ("bx", "br")
_ARG_REGS = ("r0", "r1", "r2", "r3")

def _shape_function(insns_by_addr: dict, start: int, limit_end: int) -> dict:
    """沿**线性地址顺序**走到终止指令，给出函数体边界与终止点。"""
    out = {"end_addr": limit_end, "body_basis": "next_entry",
           "terminals": [], "thunk_to": None, "truncated_body": False}
    addrs = sorted(a for a in insns_by_addr if start <= a < limit_end)
    if not addrs:
        out["body_basis"] = "no_instructions"
        return out
    for a in addrs:
        ins = insns_by_addr[a]
        m = (ins.get("mnemonic") or "").lower()
        nxt = a + int(ins.get("size") or 2)
        why = "%s %s" % (ins.get("mnemonic") or "", ins.get("op_str") or "")
        if ins.get("ends_function"):
            out["terminals"].append({"addr_hex": ins["addr_hex"],
                                     "kind": "return", "how": why.strip()})
            out["end_addr"], out["body_basis"] = nxt, "return"
            break
        if m in _INDIRECT_BRANCH and not (ins.get("op_str") or "").strip().endswith("lr"):
            out["terminals"].append({"addr_hex": ins["addr_hex"],
                                     "kind": "indirect_branch", "how": why.strip()})
            out["end_addr"], out["body_basis"] = nxt, "indirect_branch"
            break
        tgt = ins.get("target")
        if tgt is not None and m in _UNCOND_BRANCH and not (start <= tgt < limit_end):
            # 跳出本区间的无条件跳转 = 尾调用：函数体在这里就结束了
            out["terminals"].append({"addr_hex": ins["addr_hex"],
                                     "kind": "tail_call", "how": why.strip(),
                                     "target_hex": ins.get("target_hex") or ""})
            out["end_addr"], out["body_basis"] = nxt, "tail_call"
            break
    if out["end_addr"] < start + 2:
        out["end_addr"], out["body_basis"] = limit_end, "next_entry"
    # thunk：整条函数只有一条指令，且是跳到本函数之外的无条件跳转
    one = insns_by_addr[addrs[0]]
    m0 = (one.get("mnemonic") or "").lower()
    t0 = one.get("target")
    if m0 in _UNCOND_BRANCH and t0 is not None and not (start <= t0 < start + 2):
        out["thunk_to"] = t0 & ~1
    return out

def _arg_hint(insns_by_addr: dict, start: int, end: int) -> dict:
    """估参数个数与「有没有返回值」：看 r0..r3 的首次访问是读还是写。"""
    first = {}
    for a in sorted(k for k in insns_by_addr if start <= k < end):
        ins = insns_by_addr[a]
        rd = set(ins.get("reads") or [])
        wr = set(ins.get("writes") or [])
        for r in _ARG_REGS:
            if r in first:
                continue
            if r in rd:
                first[r] = "read"
            elif r in wr:
                first[r] = "write"
    n = 0
    for i, r in enumerate(_ARG_REGS):
        if first.get(r) == "read":
            n = i + 1
        elif r in first:
            break          # 中间某个寄存器先被写：后面的不再算参数
    returns = ("likely_value" if first.get("r0") == "write"
               else "no_evidence" if "r0" in first else "unknown")
    return {"params": n, "returns": returns, "first_touch": first}

def recover_functions(unit: Unit, *, deep: bool = True,
                      max_functions: int = MAX_FUNCTIONS,
                      max_insns: int = MAX_INSNS) -> dict:
    """恢复函数入口，并把**证据来源**记在每条上（observed / inferred / weak）。"""
    st = symbol_table(unit)
    table: dict = {}
    notes, gaps = [], []

    def add(addr: int, name: str, source: str, *, size: int = 0,
            confidence: str = "inferred", kind: str = "function"):
        if addr <= 0:
            return None
        rec = table.get(addr)
        if rec is None:
            rec = {"addr": addr, "addr_hex": "0x%08X" % addr, "name": name,
                   "size": size, "sources": [source], "confidence": confidence,
                   "kind": kind, "bind": "", "file": "", "line": None}
            table[addr] = rec
        else:
            if source not in rec["sources"]:
                rec["sources"].append(source)
            if not rec["size"] and size:
                rec["size"] = size
            if confidence == "observed":
                rec["name"] = name
                rec["confidence"] = "observed"
        return rec

    # ① 符号表：观察
    for f in st["functions"]:
        rec = add(f["addr"], f["name"], f["source"], size=f["size"],
                  confidence="observed")
        if rec:
            rec["bind"] = f["bind"]
    # ② DWARF：观察（原始文件名与行号）
    dw = {"available": False}
    if unit.elf and unit.elf.get("type") in ("EXEC", "DYN"):
        try:
            dw = dwarf_info(unit.name)
        except Exception:  # noqa: BLE001
            dw = {"available": False, "why": "DWARF 解析异常"}
        if dw.get("available"):
            for f in dw["functions"]:
                rec = add(f["low_pc"], f["name"], "dwarf", confidence="observed")
                if rec and not rec["file"]:
                    rec["file"] = f.get("file") or ""
                    rec["line"] = f.get("line")
    # ③ 向量表：推导（中断入口天然是函数入口）
    vt = vector_table(unit)
    for e in vt["entries"]:
        if not e["in_code"]:
            continue
        addr = int(e["handler_hex"], 16) & ~1
        nm = e["name"]
        if e["index"] == 1:
            nm = "Reset_Handler"
        elif nm.startswith("IRQ"):
            nm = nm + "_Handler"
        elif nm:
            nm = nm + "_Handler"
        else:
            nm = "handler_%d" % e["index"]
        add(addr, nm, "vector_table", confidence="inferred")

    # ④ 反汇编：调用目标 / 返回点
    md, why = _make_cs(unit.arch)
    sweep, callers, string_refs = None, {}, []
    if not deep:
        gaps.append({"reason": "本次未做深度扫描（deep=False）：调用目标与代码指针"
                               "都没采集，函数只来自符号表与向量表"})
    elif md is None:
        gaps.append({"reason": "未做深度扫描：%s" % why})
    elif deep:
        # with_regs：调用约定推断要用寄存器读写集合（只在需要时才算，
        # 其它输出不受影响）
        sweep = _sweep(unit, md, max_insns=max_insns, with_regs=True)
        if not sweep.get("ok"):
            gaps.append({"reason": "反汇编失败，深度扫描跳过：%s" % sweep.get("error")})
            sweep = None
        elif sweep.get("truncated"):
            # 批次90：截断以前是静默的——调用方看到「函数很少」却不知道是没扫完。
            gaps.append({"reason": "深度扫描触到 max_insns=%d 上限，只扫了一部分代码："
                                   "函数/调用关系可能不全；要看全就把 max_insns 调大"
                                   "（代价是时间）" % int(max_insns)})
    strings = find_strings(unit)
    string_at = {s["addr"]: s for s in strings if "addr" in s}
    if sweep:
        for addr, ins in sweep["insns"].items():
            tgt = ins.get("target")
            if tgt is not None and ins["mnemonic"].lower() in ("bl", "blx", "call", "jal"):
                add(tgt & ~1, "sub_%08X" % (tgt & ~1), "call_target",
                    confidence="inferred")
                callers.setdefault(tgt & ~1, []).append(addr)
            ref = _pc_ref(ins)
            if ref is not None:
                target = ref["addr"]
                if ref["kind"] == "literal":
                    w = unit.read(target, 4)
                    target = (int.from_bytes(w, unit.arch.get("endian", "little"))
                              if len(w) == 4 else 0)
                st_rec = string_at.get(target)
                if st_rec:
                    string_refs.append({"from": addr, "from_hex": "0x%08X" % addr,
                                        "to": target, "to_hex": "0x%08X" % target,
                                        "type": "string_ref",
                                        "how": ref["kind"],
                                        "text": st_rec["text"]})
        if sweep.get("truncated"):
            gaps.append({"reason": "深度扫描达到 %d 条指令上限，其后未扫描" % max_insns})

    # ⑤ 代码指针：推导（弱证据——只有它一条时 confidence=weak）
    vt_base = int(vt["base_hex"], 16) if vt.get("base_hex") else 0
    vt_end = vt_base + 4 * (vt.get("count", 0) + 1)
    cps = find_code_pointers(unit, exclude=[(vt_base, vt_end)])
    for h in cps["hits"]:
        rec = add(h["to"], "ptr_%08X" % h["to"], "code_pointer", confidence="weak")

    # ⑤b 调用方显式指定的入口（raw bin / 无头镜像）：单独一个证据来源，
    #     不冒充 observed——「有人告诉我这里是入口」与「符号表写着」不是同一件事。
    hint = int(getattr(unit, "entry_hint", 0) or 0)
    if hint and (unit.arch or {}).get("family") != "arm":
        hint = hint          # 非 ARM 没有 Thumb 位，不能掩
    elif hint:
        hint &= ~1           # Thumb 位：入口地址末位是「指令集选择」，不是地址的一部分
    if hint and unit.in_code(hint):
        add(hint, "entry_%08X" % hint, "entry_hint", confidence="inferred")
        notes.append("入口 0x%08X 由调用方指定（entry_hint），不是从文件里读到的" % hint)

    # ⑥ 定边界：有 size 用 size；没有就用「下一个已知入口」
    funcs = sorted(table.values(), key=lambda r: r["addr"])
    code_end = max((b for _, b in unit.code_ranges), default=0)
    for i, f in enumerate(funcs):
        nxt = funcs[i + 1]["addr"] if i + 1 < len(funcs) else code_end
        if f["size"]:
            f["end_addr"] = f["addr"] + f["size"]
            f["size_basis"] = "symtab"
        else:
            f["end_addr"] = nxt
            f["size_basis"] = "next_entry"
        f["callees"] = sorted({c for c in callers.get(f["addr"], [])}) if callers else []
        f["n_callers"] = len(callers.get(f["addr"], []))
        # ⑦ 函数体形状 + 调用约定（批次81，吸收 Ghidra 的口径；只作推断，不改 size_basis）
        #    size_basis 保留原有语义（symtab / next_entry），形状另存 body_basis：
        #    既有字段一旦改含义，所有历史断言都会变成「碰巧过」。
        f.setdefault("body_basis", "not_analyzed")
        f.setdefault("terminals", [])
        f.setdefault("params_estimate", None)
        f.setdefault("returns_estimate", "unknown")
        if sweep and sweep.get("insns"):
            sh = _shape_function(sweep["insns"], f["addr"], f["end_addr"])
            hint = _arg_hint(sweep["insns"], f["addr"], sh["end_addr"])
            f["body_basis"] = sh["body_basis"]
            f["terminals"] = sh["terminals"][:4]
            f["params_estimate"] = hint["params"]
            f["returns_estimate"] = hint["returns"]
            f["arg_basis"] = "aapcs:r0..r3 首次访问为读"
            if f["size_basis"] != "symtab" and sh["end_addr"] < f["end_addr"]:
                # 控制流说这里就结束了：比「切到下一个入口」更有依据，缩到控制流边界
                f["end_addr"] = sh["end_addr"]
            if sh["thunk_to"]:
                f["is_thunk"] = True
                f["thunk_to"] = sh["thunk_to"]
                f["thunk_to_hex"] = "0x%08X" % sh["thunk_to"]
    # ⑧ 关系层（批次82）：交叉引用 / 调用图 / 跳转表与 switch
    #    吸收的是 Ghidra 的**产物口径**：一条关系必须能反查「谁碰过这个地址」，
    #    switch 的 case 目标不能因为「不经过 bl」就从结果里消失。
    rel = {"xrefs": None, "call_graph": None, "switches": None}
    if sweep and sweep.get("insns"):
        xr = reveng.build_xrefs(unit, sweep["insns"], funcs)
        cg = reveng.call_graph(funcs, xr["xrefs"])
        sw = reveng.switch_tables(unit, sweep["insns"], funcs)
        out_by, in_by = {}, {}
        for x in xr["xrefs"]:
            if x["kind"] == "call":
                out_by.setdefault(x["func"], []).append(x["to"])
                in_by.setdefault(x["to"], []).append(x["func"])
        for f in funcs:
            f["call_targets"] = sorted(set(out_by.get(f["addr"], [])))
            f["callers"] = sorted(set(in_by.get(f["addr"], [])))
            f["n_callers"] = len(f["callers"])
            f["n_cases"] = sum(s["n_cases"] for s in sw["switches"]
                               if s["func"] == f["addr"])
        ty = rtypes.analyze_types(sweep["insns"], funcs, xr)
        for f in funcs:
            fr = next((x for x in ty["stack_frames"] if x["func"] == f["addr"]), None)
            f["stack_slots"] = fr["n_slots"] if fr else 0
            f["frame_span"] = fr["frame_span"] if fr else 0
        rel.update({"xrefs": xr, "call_graph": cg, "switches": sw, "types": ty})
        if xr["truncated"]:
            gaps.append({"reason": "交叉引用达到上限，输出被截断"})
        if xr["n_unresolved"]:
            gaps.append({"reason": "有 %d 条访存/间接调用的基址寄存器值无法静态确定"
                                   "（不做符号执行就不猜）：这些**不是丢掉的证据**，"
                                   "已按「基址寄存器 + 偏移」记下来，供结构体成员恢复用"
                                   % xr["n_unresolved"]})

    # 置信度重算：observed > inferred(≥2 源) > weak
    for f in funcs:
        if f["confidence"] != "observed":
            strong = any(x in ("call_target", "vector_table") for x in f["sources"])
            f["confidence"] = "inferred" if (len(f["sources"]) >= 2 or strong) else "weak"
        f["callee_count"] = len(f.get("callees") or [])
    truncated = len(funcs) > max_functions
    if truncated:
        gaps.append({"reason": "函数数超过 %d 上限，输出被截断" % max_functions})
        funcs = funcs[:max_functions]
    counts = {"observed": 0, "inferred": 0, "weak": 0}
    for f in funcs:
        counts[f["confidence"]] = counts.get(f["confidence"], 0) + 1
    shape_counts = {}
    for f in funcs:
        shape_counts[f.get("body_basis") or "not_analyzed"] = \
            shape_counts.get(f.get("body_basis") or "not_analyzed", 0) + 1
    n_thunk = sum(1 for f in funcs if f.get("is_thunk"))
    if sweep and sweep.get("insns"):
        gaps.append({"reason": "参数个数与返回值是**推断**（AAPCS：r0..r3 首次访问为读 / "
                               "r0 是否先被写），不是从二进制里读出来的类型信息；"
                               "原型里仍按 void f(void) 声明，别信这里的签名"})
    return {
        "ok": True,
        "functions": funcs,
        "counts": counts,
        "total": len(funcs),
        "truncated": truncated,
        "symbols": {"available": st["available"],
                    "functions": st.get("counts", {}).get("functions", 0),
                    "objects": st.get("counts", {}).get("objects", 0),
                    "mapping_symbols": st.get("counts", {}).get("mapping_symbols", 0),
                    "why": st.get("why", "")},
        "dwarf": {k: dw.get(k) for k in ("available", "why")} if not dw.get("available")
                 else {"available": True, "files": len(dw.get("files") or [])},
        "shape": {"counts": shape_counts, "thunks": n_thunk,
                  "basis": "函数体到终止指令（返回/尾调用/间接跳转）为止；"
                           "参数按 AAPCS 寄存器首次访问推断"},
        "string_refs": string_refs[:2000],
        "relations": {
            "xref_counts": (rel["xrefs"]["counts"] if rel["xrefs"] else {}),
            "n_xrefs": (len(rel["xrefs"]["xrefs"]) if rel["xrefs"] else 0),
            "n_unresolved": (rel["xrefs"]["n_unresolved"] if rel["xrefs"] else 0),
            "call_graph": ({k: v for k, v in rel["call_graph"].items()
                            if k != "edges"} if rel["call_graph"] else None),
            "switch_counts": (rel["switches"]["counts"] if rel["switches"] else {}),
            "types": ({"n_frames": (rel["types"] or {}).get("n_frames", 0),
                       "n_slots": (rel["types"] or {}).get("n_slots", 0),
                       "n_struct_candidates": (rel["types"] or {}).get(
                           "n_struct_candidates", 0),
                       "n_globals": (rel["types"] or {}).get("n_globals", 0),
                       "array_elem_sizes": (rel["types"] or {}).get(
                           "array_elem_sizes", {})} if rel.get("types") else {}),
        },
        "_relations": rel,
        # 批次86：指纹要用「指令 + 操作数」算规范化序列，重扫一遍纯属浪费；
        # 这个字段只在内存里传给 fid，任何对外输出都会 pop 掉 _recover。
        "_insns": (sweep or {}).get("insns") or {},
        "code_pointers": {"count": cps["count"], "truncated": cps["truncated"]},
        "notes": notes,
        "gaps": gaps,
        "evidence_rule": [
            "observed = 符号表或 DWARF 直接写了这个入口与名字",
            "inferred = 向量表或调用目标（这两条任一条就足以证明「这里是一个入口」），"
            "或两条以上独立证据指向同一地址",
            "weak = 只有一条间接证据（通常是字面量池里的代码指针）",
        ],
    }


# ----------------------------------------------------------------------
# 批次90：剖析结果的紧凑视图（裁剪**视图**，不改任何结论）
# ----------------------------------------------------------------------
COMPACT_FUNCTION_FIELDS = ("addr_hex", "name", "size", "confidence", "sources",
                           "n_callers", "callee_count")


def compact_view(an: dict, *, max_functions: int = 40, max_strings: int = 10,
                 keep_relations_graph: bool = False) -> dict:
    """把 :func:`analyze` 的输出裁成能直接塞进上下文的那一份。

    只动**列表长度与字段宽度**：计数、结论、gaps、limitations 一个都不改，
    被裁掉的条数写进 ``omitted``，肉眼可见（不是「悄悄少了」）。

    为什么需要它：一份 14 KB 的固件，完整剖析就有 45 KB JSON，其中 33 KB 是
    60 个函数各自的十几个字段（``terminals`` / ``arg_basis`` / ``callers`` 这些）。
    1000 个函数的固件会到几百 KB，一次工具调用就把上下文吃掉。
    """
    import copy as _copy
    # 下划线开头的是内部对象（_unit / _recover / _relations / _insns）：既不可 JSON
    # 序列化，也不该出现在视图里——先剔掉再深拷贝，省一份几十 MB 的复制。
    out = {k: v for k, v in an.items() if not str(k).startswith("_")}
    for k in ("functions", "strings", "relations"):
        if isinstance(out.get(k), (dict, list)):
            out[k] = _copy.deepcopy(out[k])
    fn = out.get("functions")
    if isinstance(fn, dict):
        top = fn.get("top") or []
        keep = int(max_functions) if int(max_functions) > 0 else 0
        rows = []
        for f in top[:keep] if keep else top:
            rows.append({k: f.get(k) for k in COMPACT_FUNCTION_FIELDS if k in f})
        fn["top"] = rows
        fn["omitted"] = max(0, len(top) - len(rows))
        fn["view"] = "compact（字段裁到 %s；完整看 recover_symbols / 提高 max_functions）" \
                     % ", ".join(COMPACT_FUNCTION_FIELDS)
    st = out.get("strings")
    if isinstance(st, dict):
        sample = st.get("sample") or []
        keep = int(max_strings) if int(max_strings) >= 0 else len(sample)
        st["sample"] = sample[:keep]
        st["omitted"] = max(0, len(sample) - len(st["sample"]))
    rel = out.get("relations")
    if isinstance(rel, dict):
        cg = rel.get("call_graph")
        if isinstance(cg, dict) and not keep_relations_graph:
            rel["call_graph"] = {k: cg.get(k) for k in
                                 ("n_nodes", "n_edges", "n_leaves", "cycles",
                                  "max_depth", "truncated")}
            rel["call_graph"]["view"] = ("只留计数：roots/by_name 要看完整剖析"
                                         "（recover_symbols 的 report.json）")
    out["view"] = {"kind": "compact", "full_json_bytes": len(json.dumps(an, default=str))}
    return out


# ----------------------------------------------------------------------
# 顶层剖析
# ----------------------------------------------------------------------
def _layout_summary(unit: Unit) -> dict:
    out = {"spans": [{"start_hex": "0x%08X" % a, "end_hex": "0x%08X" % b,
                      "length": b - a} for a, b in
                     [(s, e) for s, e, _ in unit.spans]],
           "code_ranges": [{"start_hex": "0x%08X" % a, "end_hex": "0x%08X" % b}
                           for a, b in unit.code_ranges]}
    rom = [(a, b) for a, b in unit.code_ranges]
    out["rom"] = ({"start_hex": "0x%08X" % min(a for a, _ in rom),
                   "end_hex": "0x%08X" % max(b for _, b in rom),
                   "size": max(b for _, b in rom) - min(a for a, _ in rom)}
                  if rom else None)
    if unit.elf:
        rw = [s for s in unit.elf["sections"]
              if s.get("alloc") and (s.get("writable") or s["type_name"] == "NOBITS")
              and s["size"]]
        if rw:
            lo = min(s["addr"] for s in rw)
            hi = max(s["addr"] + s["size"] for s in rw)
            out["ram"] = {"start_hex": "0x%08X" % lo, "end_hex": "0x%08X" % hi,
                          "size": hi - lo}
    else:
        out["ram"] = None
        out["limitations"] = ["HEX/BIN 没有节表：ROM/RAM 边界只能从向量表与内容推断，"
                              "本次不猜，ram 为 null"]
    return out


def _sections_summary(unit: Unit, limit: int = 48) -> list:
    if not unit.elf:
        return []
    rows = []
    for s in unit.elf["sections"]:
        if s["type_name"] in ("NULL", "SYMTAB", "STRTAB", "SYMTAB_SHNDX"):
            continue
        rows.append({"name": s["name"], "type": s["type_name"],
                     "addr_hex": "0x%08X" % s["addr"], "size": s["size"],
                     "exec": s.get("exec", False), "writable": s.get("writable", False),
                     "alloc": s.get("alloc", False)})
    return rows[:limit]


def analyze(path: str, *, base: int = 0, deep: bool = True,
            max_functions: int = MAX_FUNCTIONS,
            max_insns: int = MAX_INSNS,
            arch: str = "", endian: str = "", bits: int = 0,
            thumb: bool | None = None, entry: int = 0) -> dict:
    """一次剖析：容器/架构/布局/向量表/符号/函数/字符串/交叉引用。

    ``deep=True`` 会做线性反汇编以找回调用目标（较慢但能补上剥离符号的固件）；
    ``deep=False`` 只读符号表与向量表，快且不依赖 capstone。
    """
    data, err = _read_file(path)
    if err:
        return err
    container = detect_container(data[:4096])
    out = {"ok": True}
    out.update(_identity(path, data))
    out["container"] = container

    if container == "ar":
        return _analyze_ar(path, data, deep=deep, max_functions=max_functions,
                           max_insns=max_insns, ident=out)
    try:
        unit = _unit_from_data(data, path, base)
    except ValueError as e:
        out.update({"ok": False, "error": str(e)})
        return out
    # 调用方显式指定架构：raw bin / 无头容器必须有这一条（没头就别猜）。
    # 显式值**优先**于文件头推断，但把两者都留在结果里，冲突要看得见。
    if arch:
        ex = containers.arch_from_name(arch, bits=bits, endian=endian, thumb=thumb)
        if not ex.get("ok"):
            out.update({"ok": False, "error": ex["error"]})
            return out
        out["arch_declared"] = unit.arch
        unit.arch = ex["arch"]
        # 向量表推断出来的那条限制已经不适用了（架构不再来自推断），必须撤掉——
        # 留着会让报告自相矛盾（「架构是推断的」+「架构由调用方指定」）。
        unit.limitations = [x for x in unit.limitations
                            if not x.startswith("架构是从向量表")]
        unit.limitations.append(
            "架构由调用方显式指定（%s）；文件头/向量表给出的说法是：%s"
            % (arch, (out.get("arch_declared") or {}).get("why") or "无"))
    if entry:
        unit.entry_hint = int(entry)

    limitations = list(unit.limitations)
    gaps = []
    if unit.elf and not unit.elf.get("ok"):
        out.update({"ok": False, "error": unit.elf.get("error", "ELF 解析失败")})
        return out
    if unit.elf:
        arch = unit.arch
        out["elf"] = {"class": unit.elf["class"], "type": unit.elf["type"],
                      "machine": unit.elf["machine"],
                      "entry_hex": "0x%08X" % unit.elf["entry"],
                      "relocatable": unit.relocatable,
                      "segments": len(unit.elf["segments"])}
        if unit.elf["type"] == "DYN":
            limitations.append("这是**共享对象/动态可执行**（.so/ET_DYN）：符号地址是"
                               "**相对加载基址**的偏移，加载基址未定——不要把这些地址当绝对地址用")
        if unit.relocatable:
            limitations.append("这是**可重定位目标文件**（.o/.lib 成员）："
                               "符号地址是节内偏移，不是最终地址；链接后才能定址")
    else:
        arch = unit.arch
    out["arch"] = arch
    out["layout"] = _layout_summary(unit)
    out["sections"] = _sections_summary(unit)
    out["vector_table"] = vector_table(unit)
    if unit.arch.get("family") == "unknown":
        limitations.append("CPU 架构未判定（没有 ELF 头）：后续反汇编需要显式指定架构，"
                           "否则不给结果而不是给错结果")
    elif unit.arch.get("family") != "arm":
        limitations.append("非 ARM 镜像：函数形状/参数推断按的是 **AAPCS（ARM）**口径，"
                           "换到 %s 上只保留了「控制流与调用目标」的部分——参数个数与"
                           "返回值不要按这里的结果读" % unit.arch.get("family"))
        limitations.append("非 ARM 上的深度扫描沿用的是 ARM 口径的启发式（bl 目标、"
                           "字面量池里的代码指针），收益很低：实测 600 KB 的 x86_64 DLL "
                           "deep=True 用 117 s 只多认出 5 个函数。只想看布局/节/符号就用 "
                           "deep=false；要读代码用 recover_disasm 指定区间")
    if not unit.code_ranges:
        gaps.append({"reason": "没有可执行区间：无法反汇编，函数只能来自符号表"})

    syms = symbol_table(unit)
    rec = recover_functions(unit, deep=deep, max_functions=max_functions,
                            max_insns=max_insns)
    gaps.extend(rec.get("gaps") or [])
    if rec.get("notes"):
        out["notes"] = (out.get("notes") or []) + list(rec["notes"])
    strings = find_strings(unit)
    out["symbols"] = {
        "available": syms["available"],
        "counts": syms.get("counts", {}),
        "why": syms.get("why", ""),
    }
    out["functions"] = {
        "total": rec["total"],
        "counts": rec["counts"],
        "truncated": rec["truncated"],
        "top": rec["functions"][:min(60, len(rec["functions"]))],
        "evidence_rule": rec["evidence_rule"],
    }
    out["shape"] = rec.get("shape") or {}
    out["dwarf"] = rec["dwarf"]
    out["strings"] = {"count": len([s for s in strings if "addr" in s]),
                      "sample": [s for s in strings if "addr" in s][:20],
                      "truncated": any(s.get("truncated") for s in strings)}
    out["xrefs"] = {"code_pointers": rec["code_pointers"],
                    "string_refs": len(rec["string_refs"])}
    out["relations"] = rec.get("relations") or {}
    _rel = rec.get("_relations") or {}
    out["switch_cases"] = ((_rel.get("switches") or {}).get("switches") or [])[:200]
    out["gaps"] = gaps
    out["limitations"] = limitations + [
        "本工具还原的是**地址、布局、控制流**，不是语义：函数原型按「无参 void」推断，"
        "名字只代表符号表里写的那串字符",
        "没有符号又没有交叉证据的字节保持未知，不编名字",
    ]
    out["verdict"] = "partial" if gaps else "ok"
    out["_unit"] = unit
    out["_recover"] = rec
    return out


def _analyze_ar(path: str, data: bytes, *, deep: bool, max_functions: int,
                max_insns: int, ident: dict) -> dict:
    """``.lib`` / ``.a``：逐成员剖析并汇总。成员字节可原样取出（不覆盖）。"""
    ar = parse_ar(data)
    out = dict(ident)
    out["container"] = "ar"
    if not ar.get("ok"):
        out.update({"ok": False, "error": ar.get("error")})
        return out
    members = []
    agg = {"observed": 0, "inferred": 0, "weak": 0}
    for m in ar["members"]:
        row = {"name": m["name"], "offset": m["offset"], "size": m["size"],
               "sha256": m["sha256"]}
        if m["data"][:4] == b"\x7fELF":
            e = parse_elf(m["data"])
            row["kind"] = "elf"
            if e.get("ok"):
                row["type"] = e["type"]
                row["machine"] = e["machine"]
                row["class"] = e["class"]
                fns = [s for s in e["symbols"] if s["type"] == "FUNC"]
                row["functions"] = len(fns)
                row["func_names"] = [s["name"] for s in fns][:40]
                agg["observed"] += len(fns)
                row["arch"] = arch_of(e)
            else:
                row["error"] = e.get("error")
        else:
            row["kind"] = "data"
        members.append(row)
    out["members"] = members
    out["member_count"] = len(members)
    out["gaps"] = ar.get("gaps") or []
    out["aggregate"] = {"functions_in_objects": agg["observed"]}
    out["verdict"] = "partial" if out["gaps"] else "ok"
    out["limitations"] = [
        "库成员是**可重定位目标文件**：函数地址是节内偏移，库里没有最终地址",
        "库成员之间可能重复定义同一符号（弱符号/多副本），本工具不去重",
        "要出反汇编请对单个成员用 recover_disasm（先 recover_project 取出成员）",
    ]
    out["_members_raw"] = ar["members"]
    return out


# ----------------------------------------------------------------------
# 工程骨架生成
# ----------------------------------------------------------------------
_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "asm",
}


def _c_name(name: str, used: set) -> str:
    """把任意符号名变成可编译的 C 标识符，并保证工程内唯一。"""
    s = "".join(c if (c.isalnum() or c == "_") else "_" for c in name) or "sym"
    if s[0].isdigit():
        s = "sym_" + s
    if s in _C_KEYWORDS:
        s = s + "_"
    base = s
    i = 2
    while s in used:
        s = "%s_%d" % (base, i)
        i += 1
    used.add(s)
    return s


def _emit(dest: str, rel: str, text: str, files: list, *, binary: bytes | None = None) -> dict:
    """独占写（``xb``）+ 回读 SHA-256。已存在即报错——绝不覆盖上一次的证据。"""
    full = os.path.join(dest, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(full) or dest, exist_ok=True)
    payload = binary if binary is not None else text.encode("utf-8")
    with open(full, "xb") as f:
        f.write(payload)
    with open(full, "rb") as f:
        back = f.read()
    rec = {"path": full, "rel": rel, "size": len(payload),
           "sha256": sha256_bytes(payload),
           "sha256_verified": sha256_bytes(back) == sha256_bytes(payload)}
    files.append(rec)
    return rec


def _round_up(n: int, unit: int = 1024) -> int:
    return ((int(n) + unit - 1) // unit) * unit


def _regions(unit: Unit) -> dict:
    """推出 FLASH/RAM 窗口：有节表用节表，HEX/BIN 只用 ROM 覆盖区间。"""
    rom_lo = rom_hi = None
    if unit.code_ranges:
        rom_lo = min(a for a, _ in unit.code_ranges)
        rom_hi = max(b for _, b in unit.code_ranges)
    else:
        rom_lo = unit.base
        rom_hi = unit.base + len(unit.data)
    ram_lo = ram_hi = None
    if unit.elf:
        rw = [s for s in unit.elf["sections"]
              if s.get("alloc") and (s.get("writable") or s["type_name"] == "NOBITS")
              and s["size"]]
        if rw:
            ram_lo = min(s["addr"] for s in rw)
            ram_hi = max(s["addr"] + s["size"] for s in rw)
    return {"flash_start": rom_lo, "flash_end": rom_hi,
            "flash_size": _round_up(rom_hi - rom_lo) if rom_lo is not None else None,
            "ram_start": ram_lo, "ram_end": ram_hi,
            "ram_size": _round_up(ram_hi - ram_lo) if ram_lo is not None else None,
            "basis": "sections" if unit.elf else "image_span"}


def _readme(an: dict, regions: dict, files_rel: list) -> str:
    f = an["functions"]
    counts = f["counts"]
    vt = an.get("vector_table") or {}
    arch = an.get("arch") or {}
    L = []
    L.append("# 逆向恢复的工程骨架：%s" % os.path.basename(an["path"]))
    L.append("")
    L.append("> 由 mdkdebug `recover_project` 生成。**地址、布局、控制流是事实；"
             "函数体语义没有恢复。**")
    L.append("")
    L.append("## 1. 输入身份（一切结论挂在这三个值上）")
    L.append("")
    L.append("| 项 | 值 |")
    L.append("| --- | --- |")
    L.append("| 路径 | `%s` |" % an["path"])
    L.append("| 大小 | %d 字节 |" % an["size"])
    L.append("| SHA-256 | `%s` |" % an["sha256"])
    L.append("| 容器 | %s |" % an.get("container"))
    L.append("| 架构 | %s / %s 位 / %s%s |" % (
        arch.get("family"), arch.get("bits"), arch.get("endian"),
        " / Thumb" if arch.get("thumb") else ""))
    L.append("")
    L.append("架构依据：%s" % (arch.get("why") or "（无）"))
    L.append("")
    L.append("## 2. 内存布局")
    L.append("")
    if regions.get("flash_start") is not None:
        L.append("- FLASH：`0x%08X` .. `0x%08X`（%d 字节，取整后 %s）" % (
            regions["flash_start"], regions["flash_end"],
            regions["flash_end"] - regions["flash_start"], regions["flash_size"]))
    if regions.get("ram_start") is not None:
        L.append("- RAM：`0x%08X` .. `0x%08X`（%d 字节，取整后 %s）" % (
            regions["ram_start"], regions["ram_end"],
            regions["ram_end"] - regions["ram_start"], regions["ram_size"]))
    else:
        L.append("- RAM：**未知**（HEX/BIN 无节表；不猜，`recovered.ld` 里用占位值并标注）")
    L.append("- 布局依据：%s" % regions["basis"])
    L.append("")
    L.append("## 3. 恢复出的函数（%d 个）" % f["total"])
    L.append("")
    L.append("| 置信度 | 含义 | 数量 |")
    L.append("| --- | --- | --- |")
    L.append("| observed | 符号表/DWARF 里直接写了 | %d |" % counts.get("observed", 0))
    L.append("| inferred | 至少两条独立证据指向同一地址 | %d |" % counts.get("inferred", 0))
    L.append("| weak | 只有一条间接证据（通常是字面量池里的代码指针） | %d |"
             % counts.get("weak", 0))
    L.append("")
    if vt.get("sp_hex"):
        L.append("向量表：SP=`%s`，复位=`%s`，读到 %d 个有效入口。"
                 % (vt.get("sp_hex"), vt.get("reset_hex"), vt.get("count", 0)))
        L.append("")
    dw = an.get("dwarf") or {}
    if dw.get("available"):
        L.append("## 4. 原始源码线索（DWARF）")
        L.append("")
        L.append("镜像里带着调试信息：**%d 个源文件**、函数的原始行号都在 "
                 "`map/functions.csv` 的 file/line 列。这是重建工程目录最直接的一手依据。"
                 % dw.get("files", 0))
        L.append("")
    L.append("## 5. 目录说明")
    L.append("")
    L.append("```")
    for rel in files_rel:
        L.append(rel)
    L.append("```")
    L.append("")
    L.append("## 6. 怎么用它")
    L.append("")
    L.append("**Keil（MDK）**：新建工程 → 加入 `src/*.c` → Options → Linker 取消"
             "「Use Memory Layout from Target Dialog」并选 `linker/recovered.sct` → "
             "按原镜像的 Flash/RAM 填 Target 页。")
    L.append("")
    L.append("**GNU 工具链**：`make`（需要 `arm-none-eabi-gcc`），产物在 `build/`。"
             "链接脚本 `linker/recovered.ld`。")
    L.append("")
    L.append("## 7. 没有恢复什么（必须知道）")
    L.append("")
    for lim in an.get("limitations") or []:
        L.append("- %s" % lim)
    if an.get("gaps"):
        L.append("")
        L.append("## 8. 未覆盖的区间（gaps）")
        L.append("")
        for g in an["gaps"]:
            L.append("- %s" % g.get("reason", g))
    L.append("")
    return "\n".join(L)


def _sct_text(regions: dict, note: str) -> str:
    fs = regions.get("flash_start") or 0
    fsz = regions.get("flash_size") or 0x40000
    rs = regions.get("ram_start") or 0x20000000
    rsz = regions.get("ram_size") or 0x10000
    return """\
; 由 mdkdebug recover_project 生成（批次79）——%s
; ROM/FAM 长度来自原镜像布局并向上取整到 1 KiB；实际容量请按芯片手册确认。
LR_IROM1 0x%08X 0x%08X  {
  ER_IROM1 0x%08X 0x%08X  {
   *.o (RESET, +First)
   *(InRoot$$Sections)
   .ANY (+RO)
   .ANY (+XO)
  }
  RW_IRAM1 0x%08X 0x%08X  {
   .ANY (+RW +ZI)
  }
}
""" % (note, fs, fsz, fs, fsz, rs, rsz)


def _ld_text(regions: dict, name: str, note: str) -> str:
    fs = regions.get("flash_start") or 0
    fsz = regions.get("flash_size") or 0x40000
    rs = regions.get("ram_start") or 0x20000000
    rsz = regions.get("ram_size") or 0x10000
    return """\
/* 由 mdkdebug recover_project 生成（批次79）——%s */
ENTRY(Reset_Handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x%08X, LENGTH = 0x%X
  RAM   (rwx) : ORIGIN = 0x%08X, LENGTH = 0x%X
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
  .isr_vector : {
    KEEP(*(.isr_vector))
  } > FLASH

  .text : {
    *(.text*)
    *(.rodata*)
  } > FLASH

  .data : {
    *(.data*)
  } > RAM AT > FLASH

  .bss : {
    *(.bss*)
    *(COMMON)
  } > RAM

  /DISCARD/ : { *(.comment) *(.ARM.attributes) }
}
""" % (note, fs, fsz, rs, rsz)


def _symbols_header(an: dict, funcs: list, objs: list, limit: int) -> str:
    vt = an.get("vector_table") or {}
    L = ["/* 自动生成（mdkdebug recover_project，批次79）。",
         " * 说明：地址取自镜像；**函数原型按「无参、void 返回」推断**——",
         " * 反汇编能还原地址与控制流，还原不了参数类型与返回值语义。",
         " * 每行注释里的「推断 n 参」是按 AAPCS 看 r0..r3 首次访问是读还是写算出来的",
         " * （批次81），只是个**估计**：函数可能少用/多用寄存器，也可能参数是指针结构。",
         " * 已知参数/返回值的函数请手工改这里的声明，不要相信这里的签名。 */",
         "#ifndef RECOVERED_SYMBOLS_H", "#define RECOVERED_SYMBOLS_H", "",
         "#include <stdint.h>", "",
         "#define REC_INITIAL_SP      0x%08Xu" % (vt.get("sp") or 0),
         "#define REC_RESET_HANDLER   0x%08Xu" % (
             (int(vt["reset_hex"], 16) & ~1) if vt.get("reset_hex") else 0),
         ""]
    used = set()
    L.append("/* ---- 函数（%d 个，此处列出 %d 个） ---- */" % (len(funcs), min(len(funcs), limit)))
    for f in funcs[:limit]:
        nm = _c_name(f["name"], used)
        hint = ""
        if f.get("params_estimate") is not None:
            hint = "  推断 %d 参/%s" % (
                f["params_estimate"],
                {"likely_value": "可能返回值", "no_evidence": "无返回值证据",
                 "unknown": "返回值不明"}.get(f.get("returns_estimate"), "?"))
        L.append("void %s(void);   /* 0x%08X  size=%s  %s  [%s]%s */" % (
            nm, f["addr"], f.get("size") or "?", f["confidence"],
            ",".join(f.get("sources") or []), hint))
    if len(funcs) > limit:
        L.append("/* ... 其余 %d 个见 map/functions.csv */" % (len(funcs) - limit))
    if objs:
        L.append("")
        L.append("/* ---- 数据对象（%d 个，此处列出 %d 个） ---- */" % (len(objs), min(len(objs), limit)))
        for o in objs[:limit]:
            nm = _c_name(o["name"], used)
            L.append("#define ADDR_%s 0x%08Xu   /* size=%s %s */" % (
                nm.upper(), o["addr"], o.get("size") or "?", o.get("bind")))
    L.append("")
    L.append("#endif /* RECOVERED_SYMBOLS_H */")
    return "\n".join(L) + "\n"


def _startup_text(an: dict, funcs: list, limit: int) -> str:
    vt = an.get("vector_table") or {}
    entries = vt.get("entries") or []
    used = set()
    names = {}
    by_addr = {f["addr"]: f for f in funcs}
    decls, table = [], []
    for e in entries[:limit]:
        addr = int(e["handler_hex"], 16) & ~1
        f = by_addr.get(addr)
        rawname = f["name"] if f else ("handler_%d" % e["index"])
        nm = _c_name(rawname, used)
        names[e["index"]] = (nm, addr)
        decls.append("void %s(void);" % nm)
        table.append("  (void *)%s,   /* [%02d] %-12s orig 0x%08X */" % (
            nm, e["index"], e["name"], addr))
    L = ["/* 自动生成（mdkdebug recover_project，批次79）。",
         " * 这张表**照抄原镜像的向量表**：序号与地址是观察事实；",
         " * 具体是哪个外设中断取决于芯片（未判定），不要把序号当结论。 */",
         '#include "recovered_symbols.h"', "",
         "void Default_Handler(void);",
         ""]
    L += decls
    L.append("")
    L.append("__attribute__((section(\".isr_vector\"), used))")
    L.append("const void *const g_recovered_vectors[] = {")
    L.append("  (void *)REC_INITIAL_SP,")
    L += table
    L.append("};")
    L.append("")
    L.append("void Default_Handler(void) { for (;;) { } }")
    L.append("")
    return "\n".join(L)


def _stubs_text(funcs: list, limit: int) -> str:
    used = set()
    L = ["/* 自动生成（mdkdebug recover_project，批次79）。",
         " * 这些是**占位实现**：原函数体没有恢复（反汇编不等于语义）。",
         " * 作用只有一个——让骨架能链接、能上板、能让别人在原来的地址上做事。",
         " * 全部是 weak：你自己写的同名强符号会覆盖它。 */",
         '#include "recovered_symbols.h"', ""]
    for f in funcs[:limit]:
        nm = _c_name(f["name"], used)
        L.append("__attribute__((weak)) void %s(void) { for (;;) { } }   /* 0x%08X */"
                 % (nm, f["addr"]))
    if len(funcs) > limit:
        L.append("/* ... 其余 %d 个未生成占位实现（可用 max_stubs 放宽） */"
                 % (len(funcs) - limit))
    L.append("")
    return "\n".join(L)


def _makefile(name: str) -> str:
    return """\
# 由 mdkdebug recover_project 生成（批次79）
# 需要 arm-none-eabi 工具链；链接脚本与原镜像布局一致。
NAME    ?= %s
BUILD   ?= build
CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
SIZE    := arm-none-eabi-size

CFLAGS  := -mcpu=cortex-m4 -mthumb -Os -g -ffunction-sections -fdata-sections \\
           -Iinclude -Wall
LDFLAGS := -T linker/recovered.ld -Wl,--gc-sections -nostartfiles

SRCS := $(wildcard src/*.c)
OBJS := $(patsubst src/%%.c,$(BUILD)/%%.o,$(SRCS))

all: $(BUILD)/$(NAME).elf $(BUILD)/$(NAME).bin

$(BUILD)/%%.o: src/%%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/$(NAME).elf: $(OBJS) linker/recovered.ld | $(BUILD)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@
	$(SIZE) $@

$(BUILD)/$(NAME).bin: $(BUILD)/$(NAME).elf
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all clean
""" % name


def _cmake_text(name: str) -> str:
    return """\
# 由 mdkdebug recover_project 生成（批次79）
cmake_minimum_required(VERSION 3.16)
project(%s C ASM)

set(CMAKE_C_STANDARD 11)
add_compile_options(-mcpu=cortex-m4 -mthumb -Os -g
                    -ffunction-sections -fdata-sections)
add_link_options(-T ${CMAKE_SOURCE_DIR}/linker/recovered.ld
                 -Wl,--gc-sections -nostartfiles)

file(GLOB SRCS ${CMAKE_SOURCE_DIR}/src/*.c)
add_executable(%s ${SRCS})
target_include_directories(%s PRIVATE ${CMAKE_SOURCE_DIR}/include)
""" % (name, name, name)


def _csv(header: list, rows: list) -> str:
    """CSV 文本：**无 BOM**、`\n` 行尾（统一走 mdkdebug.textio）。

    真机反馈：带 BOM 的 CSV 首列键是 ``'\ufeffaddr'``，下游按 ``addr`` 取列取不到，
    必须先按 utf-8-sig 读。本服务的产物是给程序读的证据，不该有 BOM。
    """
    return _textio.csv_text(header, rows)


def _jsonable(an: dict) -> dict:
    return {k: v for k, v in an.items() if not k.startswith("_")}


def build_project(path: str, out_dir: str, *, name: str = "recovered",
                  base: int = 0, deep: bool = True,
                  max_functions: int = MAX_FUNCTIONS, max_insns: int = MAX_INSNS,
                  max_stub_functions: int = 300, max_asm_functions: int = 200,
                  include_asm: bool = True, include_pseudo_c: bool = True,
                  max_pseudo_c_functions: int = 60) -> dict:
    """把一份固件变成**能打开的工程骨架**，写在 ``out_dir``（必须不存在）。"""
    if not out_dir:
        return {"ok": False, "error": "缺少 out_dir"}
    dest = os.path.abspath(out_dir)
    # 位置非法优先于"目录已存在"：落在构建目录里，说"位置非法"比说"已存在"有用得多
    bad = _evidence.violation(dest)
    if bad:
        return {**_evidence.refusal(dest, bad), "output_directory": dest}
    if os.path.exists(dest):
        return {"ok": False, "output_directory": dest,
                "error": "输出目录已存在：%s —— 本工具不覆盖任何既有内容，"
                         "请换一个不存在的新目录" % dest}
    data, err = _read_file(path)
    if err:
        return err
    ident = _identity(path, data)
    container = detect_container(data[:4096])

    if container == "ar":
        return _project_from_ar(path, data, dest, ident, deep=deep)
    try:
        unit = _unit_from_data(data, path, base)
    except ValueError as e:
        return {**ident, "ok": False, "error": str(e)}
    if unit.relocatable:
        # 骨架工程也一样：可重定位目标（ELF ET_REL / COFF .obj）里的地址是**节内偏移**，
        # 出工程只会得到一份地址全错的东西。宁可拒，不给错答案。
        return {**ident, "ok": False,
                "error": "这是可重定位目标文件（ET_REL / COFF .obj，如 .o / 库成员 / .obj）："
                         "没有最终地址，出不了可用的工程",
                "hint": "先链接成 axf/elf（Keil 里编译工程或 armlink）再对本工具用；"
                        "现在可以先 recover_probe 看节与符号"}
    bad = _arm_only_guard(unit, ident, "recover_project（骨架工程）")
    if bad:
        return bad
    an = analyze(path, base=base, deep=deep, max_functions=max_functions,
                 max_insns=max_insns)
    if not an.get("ok"):
        return an
    funcs = an["_recover"]["functions"]
    objs = symbol_table(unit)["objects"]
    regions = _regions(unit)
    os.makedirs(dest)

    files, notes = [], []
    note = "%s  %s  sha256=%s" % (os.path.basename(path), an["size"],
                                  an["sha256"][:16])

    # 1) 链接布局
    _emit(dest, "linker/recovered.sct", _sct_text(regions, note), files)
    _emit(dest, "linker/recovered.ld", _ld_text(regions, name, note), files)
    # 2) 头文件
    _emit(dest, "include/recovered_memory.h",
          "/* 自动生成（mdkdebug recover_project，批次79） */\n"
          "#ifndef RECOVERED_MEMORY_H\n#define RECOVERED_MEMORY_H\n\n"
          "#define REC_FLASH_BASE 0x%08Xu\n#define REC_FLASH_SIZE 0x%08Xu\n"
          "#define REC_RAM_BASE   0x%08Xu\n#define REC_RAM_SIZE   0x%08Xu\n\n"
          "#endif /* RECOVERED_MEMORY_H */\n" % (
              regions.get("flash_start") or 0, regions.get("flash_size") or 0,
              regions.get("ram_start") or 0, regions.get("ram_size") or 0), files)
    _emit(dest, "include/recovered_symbols.h",
          _symbols_header(an, funcs, objs, limit=max_stub_functions), files)
    # 3) 源文件
    _emit(dest, "src/startup_recovered.c", _startup_text(an, funcs, limit=64), files)
    _emit(dest, "src/recovered_stubs.c", _stubs_text(funcs, max_stub_functions), files)
    # 4) 汇编（可选，需要 capstone）
    asm_ok = False
    if include_asm and funcs:
        dt = disasm_text(unit, funcs[:max_asm_functions], max_insns=max_insns)
        if dt.get("ok"):
            _emit(dest, "asm/disassembly.asm",
                  "; 由 mdkdebug recover_project 生成（批次79）\n"
                  "; 反汇编不等于源码：这里只有地址、机器码与指令。\n" + dt["text"], files)
            asm_ok = True
            if dt.get("truncated"):
                notes.append("汇编输出达到指令上限，后续函数未写入 asm/")
        else:
            notes.append("未生成汇编：%s" % dt.get("error"))
    # 4b) 伪 C（批次84）：寄存器级 lifting；**不是**原始源码，类型/名字都是推断
    pseudo_ok = False
    if include_pseudo_c and funcs:
        from . import decomp as _decomp            # noqa: PLC0415
        try:
            sw0 = ((an.get("_recover") or {}).get("_relations") or {}).get("switches")
            pcr = _decomp.decompile(
                unit, funcs, max_funcs=max(1, int(max_pseudo_c_functions)),
                max_insns=max_insns,
                names={f["addr"]: f["name"] for f in funcs if f.get("name")},
                switches=(sw0 or {}).get("switches") if isinstance(sw0, dict) else None)
            if pcr.get("ok") and pcr.get("functions"):
                _rec = _emit(dest, "src/pseudo_c.c",
                             _decomp.pseudo_c_file(pcr, title=name), files)
                # 机读标志：这份产物是**证据**，不是可编译源码（文件里还有 #error 闸门）
                _rec["evidence_only"] = True
                pseudo_ok = True
                if pcr.get("n_failed"):
                    notes.append("%d 个函数没能提升成伪 C" % pcr["n_failed"])
                if pcr.get("truncated"):
                    notes.append("伪 C 只覆盖了前 %d 个函数（max_pseudo_c_functions 上限）"
                                 % len(pcr["functions"]))
                if pcr.get("n_unsupported"):
                    notes.append("伪 C 里有 %d 处指令未提升：%s"
                                 % (pcr["n_unsupported"],
                                    ", ".join(pcr.get("unsupported") or [])))
            else:
                notes.append("未生成伪 C：%s" % (pcr.get("error") or "无函数"))
        except Exception as e:                     # noqa: BLE001
            notes.append("伪 C 生成失败（已跳过，其余产物不受影响）：%s" % e)
    # 5) 表格
    # 新增列一律追加在末尾：既有列名与顺序是历史断言的一部分，不挪不改。
    _emit(dest, "map/functions.csv", _csv(
        ["addr", "end_addr", "name", "size", "size_basis", "confidence",
         "sources", "bind", "file", "line", "n_callers",
         "body_basis", "params", "returns", "thunk_to"],
        [[f["addr_hex"], "0x%08X" % (f.get("end_addr") or 0), f["name"],
          f.get("size") or "", f.get("size_basis") or "", f["confidence"],
          "|".join(f.get("sources") or []), f.get("bind") or "",
          f.get("file") or "", f.get("line") or "", f.get("n_callers") or 0,
          f.get("body_basis") or "", f.get("params_estimate")
          if f.get("params_estimate") is not None else "",
          f.get("returns_estimate") or "", f.get("thunk_to_hex") or ""]
         for f in funcs]), files)
    _emit(dest, "map/objects.csv", _csv(
        ["addr", "name", "size", "bind", "type"],
        [["0x%08X" % o["addr"], o["name"], o.get("size") or "", o.get("bind") or "",
          o.get("type") or ""] for o in objs]), files)
    vt = an.get("vector_table") or {}
    _emit(dest, "map/vector_table.csv", _csv(
        ["index", "name", "handler", "thumb", "in_code"],
        [[e["index"], e["name"], e["handler_hex"], int(e["thumb"]), int(e["in_code"])]
         for e in (vt.get("entries") or [])]), files)
    strings = find_strings(unit)
    _emit(dest, "map/strings.csv", _csv(
        ["addr", "len", "in_code", "text"],
        [["0x%08X" % s["addr"], s["len"], int(s["in_code"]), s["text"]]
         for s in strings if "addr" in s]), files)
    refs = an["_recover"].get("string_refs") or []
    cps = find_code_pointers(unit)
    rows = [["string_ref", r["from_hex"], r["to_hex"], r.get("how", ""), r["text"]]
            for r in refs]
    rows += [["code_pointer", h["from_hex"], h["to_hex"], "word", ""]
             for h in cps["hits"]]
    _emit(dest, "map/xrefs.csv", _csv(["type", "from", "to", "how", "text"], rows), files)
    # 5b) 关系层（批次82）：完整交叉引用 / 调用图 / 跳转表
    rel = (an.get("_recover") or {}).get("_relations") or {}
    xr = (rel.get("xrefs") or {}).get("xrefs") or []
    _emit(dest, "map/xrefs_full.csv", _csv(
        ["kind", "from", "to", "func", "func_name", "how", "confidence", "insn"],
        [[x["kind"], x["from_hex"], x.get("to_hex", ""), "0x%08X" % x["func"],
          x["func_name"], x.get("how", ""), x.get("confidence", ""), x["insn"]]
         for x in xr]), files)
    cg = rel.get("call_graph") or {}
    _emit(dest, "map/callgraph.csv", _csv(
        ["caller", "caller_name", "callee", "callee_name", "callsite", "confidence"],
        [[e["caller_hex"], e["caller_name"], e["callee_hex"], e["callee_name"],
          e["callsite_hex"], e["confidence"]] for e in (cg.get("edges") or [])]), files)
    sw = (rel.get("switches") or {}).get("switches") or []
    ty = rel.get("types") or {}
    _emit(dest, "map/stack_frames.csv", _csv(
        ["func", "func_name", "slot_offset", "width", "reads", "writes",
         "basis", "confidence"],
        [["0x%08X" % fr["func"], fr["func_name"], s1["offset"], s1["width"],
          s1["reads"], s1["writes"], s1["basis"], s1["confidence"]]
         for fr in (ty.get("stack_frames") or []) for s1 in fr["slots"]]), files)
    _emit(dest, "map/struct_candidates.csv", _csv(
        ["func", "func_name", "base_reg", "kind", "n_fields", "span",
         "offset", "width", "reads", "writes", "array_elem_size", "confidence"],
        [["0x%08X" % fn["func"], fn["func_name"], c["base_reg"], c["kind"],
          c["n_fields"], c["span"], f1["offset"], f1["width"], f1["reads"],
          f1["writes"], f1["array_elem_size"], c["confidence"]]
         for fn in (ty.get("structs") or []) for c in fn["candidates"]
         for f1 in c["fields"]]), files)
    _emit(dest, "map/globals.csv", _csv(
        ["addr", "size_at_least", "reads", "writes", "how", "funcs", "confidence"],
        [[g["addr_hex"], g["size_at_least"], g["reads"], g["writes"],
          " ".join(g["how"]), " ".join(g["funcs"]), g["confidence"]]
         for g in (ty.get("globals") or [])]), files)
    _emit(dest, "map/switches.csv", _csv(
        ["kind", "addr", "func", "func_name", "n_cases", "table_addr",
         "targets", "confidence", "length_basis"],
        [[s0["kind"], s0["addr_hex"], "0x%08X" % s0["func"], s0["func_name"],
          s0["n_cases"], s0.get("table_addr_hex", ""),
          " ".join(s0.get("targets_hex") or []), s0["confidence"],
          s0.get("length_basis", "")] for s0 in sw]), files)
    # 6. 构建脚本
    _emit(dest, "Makefile", _makefile(name), files)
    _emit(dest, "CMakeLists.txt", _cmake_text(name), files)
    # 7. 机器可读报告
    report = _jsonable(an)
    report["evidence_only"] = True
    report["artifact_kind"] = "evidence"       # 提醒：这是取证产物，不是源码工程
    report["evidence_only_files"] = [f["rel"] for f in files if f.get("evidence_only")]
    _emit(dest, "report.json",
          json.dumps(report, ensure_ascii=False, indent=1), files)
    # 8. 人读说明（最后写，好把文件清单列全）
    rels = [f["rel"] for f in files] + ["README.md"]
    _emit(dest, "README.md", _readme(an, regions, sorted(rels)), files)

    verified = all(f["sha256_verified"] for f in files)
    out = {
        "ok": True,
        "output_directory": dest,
        "input": {"path": an["path"], "size": an["size"], "sha256": an["sha256"]},
        "container": container,
        "arch": an.get("arch"),
        "regions": regions,
        "counts": an["functions"]["counts"],
        "functions": an["functions"]["total"],
        "files": files,
        "file_count": len(files),
        "sha256_verified": verified,
        "asm_generated": asm_ok,
        "pseudo_c_generated": pseudo_ok,
        "gaps": an.get("gaps") or [],
        "notes": notes,
        "limitations": an.get("limitations") or [],
        "what_this_is": [
            "可用工程骨架：链接布局（.sct/.ld）+ 向量表 + 符号头 + 占位实现 + 反汇编 + 表格",
            "能编译、能链接、能在原地址上继续做事；**不是**还原出原作者的 C 代码",
        ],
    }
    if not asm_ok:
        out["next_actions"] = ["装 capstone 后重跑可拿到 asm/disassembly.asm"]
    return out


def _project_from_ar(path: str, data: bytes, dest: str, ident: dict, *,
                     deep: bool) -> dict:
    """``.lib`` / ``.a``：把成员原样取出 + 每成员一份剖析，方便逐个反汇编。"""
    ar = parse_ar(data)
    if not ar.get("ok"):
        return {**ident, "ok": False, "error": ar.get("error")}
    os.makedirs(dest)
    files, members = [], []
    for i, m in enumerate(ar["members"]):
        nm = "".join(c if (c.isalnum() or c in "._-") else "_" for c in m["name"]) \
            or ("member_%d" % i)
        rel = "members/%02d_%s" % (i, nm)
        rec = _emit(dest, rel, "", files, binary=m["data"])
        row = {"name": m["name"], "file": rel, "size": m["size"],
               "sha256": m["sha256"], "sha256_verified": rec["sha256_verified"]}
        if m["data"][:4] == b"\x7fELF":
            e = parse_elf(m["data"])
            if e.get("ok"):
                row["type"] = e["type"]
                row["machine"] = e["machine"]
                row["functions"] = [s["name"] for s in e["symbols"] if s["type"] == "FUNC"][:200]
                row["objects"] = [s["name"] for s in e["symbols"]
                                  if s["type"] in ("OBJECT", "COMMON")][:200]
                row["arch"] = arch_of(e)
        members.append(row)
    _emit(dest, "members/manifest.json",
          json.dumps({"input": ident, "members": members,
                      "gaps": ar.get("gaps")}, ensure_ascii=False, indent=1), files)
    _emit(dest, "README.md",
          "# 库成员清单：%s\n\n"
          "成员已原样取出（每个都回读校验过 SHA-256），并附符号清单。\n\n"
          "成员是**可重定位目标文件**：里面的函数地址是节内偏移，不是最终地址。\n"
          "要对某个成员出汇编，单独跑 `recover_disasm` 指向 `members/NN_xxx.o`。\n\n"
          "| # | 成员 | 大小 | 函数数 |\n| --- | --- | --- | --- |\n%s\n"
          % (os.path.basename(path), "\n".join(
              "| %d | `%s` | %d | %d |" % (i, m["name"], m["size"],
                                           len(m.get("functions") or []))
              for i, m in enumerate(members))), files)
    return {"ok": True, "output_directory": dest, "input": ident,
            "container": "ar", "members": members, "member_count": len(members),
            "files": files, "file_count": len(files),
            "sha256_verified": all(f["sha256_verified"] for f in files),
            "gaps": ar.get("gaps") or [],
            "limitations": ["库成员是 relocatable：地址是节内偏移",
                            "成员之间可能重复定义同名符号（弱符号），本工具不去重"]}


def disasm_at(path: str, *, base: int = 0, start: int = 0, end: int = 0,
              symbol: str = "", max_insns: int = 5000, fmt: str = "",
              arch: str = "", endian: str = "", bits: int = 0,
              thumb: bool | None = None) -> dict:
    """按「符号名」或「地址区间」反汇编一段。符号找不到时**列出可选名字**再报错。

    输出里 ``input`` 回显**调用方原样传进来的参数**（path/size/sha256/base/start/end），
    ``address_map`` 说**实际用了什么**（base_received_hex vs base_hex、base_source、
    容器冲突、向量表自检）。两者分开报是刻意的：「我传了 X 它却用了 Y」这类现场，
    没有回显就只能靠猜。

    ``fmt`` 给 ``c`` / ``pseudo`` 时不返回指令表，而是返回**寄存器级伪 C**
    （批次84 的 lifting）：表达式与控制流保真，类型/结构体/变量名是推断。
    """
    data, err = _read_file(path)
    if err:
        return err
    kind = detect_container(data[:4096])
    if kind == "ar":
        return {"ok": False,
                "error": "这是库归档（.lib/.a），成员是独立目标文件："
                         "先用 recover_project 取出成员，再对该成员反汇编"}
    arg_start, arg_end = int(start or 0), int(end or 0)
    try:
        unit = _unit_from_data(data, path, base)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if arch:
        ex = containers.arch_from_name(arch, bits=bits, endian=endian, thumb=thumb)
        if not ex.get("ok"):
            return {"ok": False, "error": ex["error"]}
        unit.arch = ex["arch"]
    note = []
    if not start and not symbol:
        vt = vector_table(unit)
        if vt.get("reset_hex"):
            start = int(vt["reset_hex"], 16) & ~1
            note.append("未给 start/symbol，从向量表复位入口 0x%08X 开始" % start)
        elif unit.code_ranges:
            start = unit.code_ranges[0][0]
            note.append("未给 start/symbol，从可执行区间起点 0x%08X 开始" % start)
        else:
            return {"ok": False, "error": "没有可执行区间，也没有给 start"}
    if symbol:
        st = symbol_table(unit)
        hit = None
        for f in st["functions"]:
            if f["name"] == symbol:
                hit = f
                break
        if hit is None:
            near = [f["name"] for f in st["functions"]
                    if symbol.lower() in f["name"].lower()][:12]
            return {"ok": False,
                    "error": "符号 %r 不在符号表里" % symbol,
                    "hint": "含该子串的符号：" + (", ".join(near) if near else "（无）"),
                    "symbol_table": st["available"]}
        start = hit["addr"]
        if not end:
            end = start + (hit["size"] or 64)
            if not hit["size"]:
                note.append("该符号 st_size=0（编译器没给长度），按 64 字节试读；"
                            "要完整函数请给 end")
    if getattr(unit, "base_inferred", None):
        note.append("base 是**推断**的：%s（%s）——不对就显式传 base"
                    % (unit.base_inferred["base_hex"],
                       unit.base_inferred["method"]))
    if not end:
        code_end = max((b for _, b in unit.code_ranges), default=start + 256)
        end = min(code_end, start + max_insns * 4)
    if end <= start:
        return {"ok": False,
                "error": "end(0x%08X) 必须大于 start(0x%08X)" % (end, start)}

    want = (fmt or "").strip().lower()
    if want in ("c", "pseudo", "pseudo_c", "c_code"):
        from . import decomp as _decomp           # noqa: PLC0415
        st = symbol_table(unit)
        allf = [{"addr": f["addr"], "end_addr": f["addr"] + (f["size"] or 0),
                 "name": f["name"]} for f in st["functions"]]
        nm = symbol or next((f["name"] for f in allf if f["addr"] == start), "")
        one = _decomp.decompile_function(
            unit, {"addr": start, "end_addr": end, "name": nm},
            funcs=allf or [{"addr": start, "end_addr": end, "name": nm}],
            names={f["addr"]: f["name"] for f in allf if f["name"]},
            max_insns=max_insns)
        if not one.get("ok"):
            return one
        one["format"] = "pseudo_c"
        one["input"] = {"path": os.path.abspath(path), "size": len(data),
                        "sha256": sha256_bytes(data),
                        "base_received_hex": "0x%08X" % int(base or 0),
                        "start_received_hex": "0x%08X" % int(arg_start or 0),
                        "end_received_hex": "0x%08X" % int(arg_end or 0),
                        "symbol": symbol or ""}
        one["address_map"] = _address_map(unit)
        if one["address_map"].get("base_conflict"):
            one["notes"] = (one.get("notes") or []) + [
                "base 冲突：%s" % one["address_map"]["base_conflict"]["note"]]
        one["arch"] = unit.arch
        one["span"] = {"start_hex": "0x%08X" % start, "end_hex": "0x%08X" % end}
        one["notes"] = note + (one.get("notes") or [])
        # 调用约定按家族写：ARM 是 AAPCS（r0..r3），RISC-V/MIPS 是各自 ABI
        from . import lift_isa as _lisa           # noqa: PLC0415
        _fam = (unit.arch or {}).get("family")
        _d = _lisa.descriptor(_fam)
        if _fam == "arm" or not _d:
            _cc = "bl 按 AAPCS 传当前 r0..r3，返回值在 r0（多返回值/浮点未建模）"
        else:
            _an = _d.get("arg_names") or []
            _cc = ("bl 按 %s 传当前 %s..%s，返回值在 %s（多返回值/浮点未建模）"
                   % (_d.get("abi"), _an[0] if _an else "?",
                      _an[3] if len(_an) > 3 else (_an[-1] if _an else "?"),
                      _d.get("ret_name") or "?"))
        one["limitations"] = [
            "寄存器级伪 C：表达式与控制流保真；类型名/结构体/变量名是**推断**的",
            _cc,
            "间接跳转（函数指针、未恢复的跳转表）保留成注释，不编造分支",
            "只结构化「单块 if」与「单块 if/else」；循环保留 goto 并标回边",
        ]
        return one

    r = disassemble(unit, start, end, max_insns=max_insns)
    if not r.get("ok"):
        return r
    r["address_map"] = _address_map(unit)
    r["input"] = {"path": os.path.abspath(path), "size": len(data),
                  "sha256": sha256_bytes(data),
                  "base_received_hex": "0x%08X" % int(base or 0),
                  "start_received_hex": "0x%08X" % int(arg_start or 0),
                  "end_received_hex": "0x%08X" % int(arg_end or 0),
                  "symbol": symbol or ""}
    if r["address_map"].get("base_conflict"):
        r["notes"] = (r.get("notes") or []) + [
            "base 冲突：%s" % r["address_map"]["base_conflict"]["note"]]
    _bc = r["address_map"].get("base_check") or {}
    if _bc.get("hint"):
        r["notes"] = (r.get("notes") or []) + [_bc["hint"]]
    r["arch"] = unit.arch
    r["span"] = {"start_hex": "0x%08X" % start, "end_hex": "0x%08X" % end}
    r["notes"] = note + (r.get("notes") or [])
    cps = find_code_pointers(unit)
    names = {}
    if unit.elf:
        for s in symbol_table(unit)["functions"]:
            names[s["addr"]] = s["name"]
    for ins in r["insns"]:
        t = ins.get("target")
        if t is not None and (t & ~1) in names:
            ins["target_name"] = names[t & ~1]
    r["limits"] = ["反汇编只说明「这些字节被解码成这些指令」；"
                   "数据被误当代码（字面量池、跳转表）时会产出看着正常的垃圾指令"]
    return r


# ======================================================================
# 批次80：字节精确的可重链接工程（+ 用真工具链自证的 recover_verify）
#
# 批次79 出的是「骨架」：能编译，但里面没有原来的代码。这一节出的是
# 「重链接复现」：把原镜像的可加载字节按 AREA 复刻，用 armasm/armlink 重新
# 链接，再用 fromelf --bin 与原镜像的 bin 逐字节比对。**比对通过 = 地址、
# 布局、符号位置都对**；比对不过就如实报第一处差异，不粉饰。
# ======================================================================

ARM_TOOLS = ("armasm", "armlink", "fromelf")

# Keil 安装根下的工具链子目录（AC5 优先：批 79/80 的载体是 ARMCC 5 生成的 axf）
_ARM_BIN_SUBDIRS = (
    os.path.join("ARM", "ARMCC", "bin"),
    os.path.join("ARM", "ARMCLANG", "bin"),
    os.path.join("ARM", "ARMCC", "bin64"),
)


def find_arm_tools(explicit: str = "") -> dict:
    """定位 armasm / armlink / fromelf。

    三路来源，**按顺序**：调用方显式目录 → 环境变量 ``MDK_ARMCC_BIN`` →
    从 ``UV4.exe`` 反推安装根 + ``<root>\\ARM\\ARMCC\\bin``。

    找不到时**不猜**：返回 ``ok=False`` 与试过哪些地方，让上层明确报错。
    """
    cands: list[str] = []
    if explicit:
        cands.append(explicit)
    env = os.environ.get("MDK_ARMCC_BIN") or os.environ.get("ARMCC_BIN") or ""
    if env:
        cands.append(env)
    tried: list[str] = []
    try:
        from . import builder as _builder  # noqa: PLC0415
        found = _builder.find_uv4_detailed(None)
        uv4 = found.get("uv4") or ""
        if uv4:
            # <root>\UV4\UV4.exe → <root>\ARM\ARMCC\bin
            root = os.path.dirname(os.path.dirname(uv4))
            for sub in _ARM_BIN_SUBDIRS:
                cands.append(os.path.join(root, sub))
    except Exception as exc:  # noqa: BLE001
        tried.append("从 UV4 反推失败：%s" % exc)

    for d in cands:
        if not d:
            continue
        tried.append(d)
        tools = {t: os.path.join(d, t + (".exe" if os.name == "nt" else ""))
                 for t in ARM_TOOLS}
        if all(os.path.isfile(p) for p in tools.values()):
            return {"ok": True, "bin_dir": d, "tools": tools,
                    "version": _arm_tool_version(tools["armasm"]), "tried": tried}
    return {"ok": False, "bin_dir": "", "tools": {}, "tried": tried,
            "error": "找不到 armasm/armlink/fromelf（试过 %d 个目录）" % len(tried),
            "hint": "装 Keil MDK（含 ARMCC 5）或设 MDK_ARMCC_BIN=<...\\ARM\\ARMCC\\bin>；"
                    "只有 GNU 工具链时请用 linker/recovered.ld + Makefile"}


def _arm_tool_version(armasm: str) -> str:
    """取 armasm 版本行（只用于报告；取不到就空串，不算失败）。"""
    try:
        out = subprocess.run([armasm, "--vsn"], capture_output=True, text=True,
                             errors="replace", timeout=30)
        text = (out.stdout or "") + (out.stderr or "")
        for line in text.splitlines():
            if "version" in line.lower():
                return line.strip()[:80]
        return text.strip().splitlines()[0][:80] if text.strip() else ""
    except Exception:  # noqa: BLE001
        return ""


def load_chunks(unit: "Unit") -> list[dict]:
    """**可加载字节**的分块（按地址升序）。

    口径：ELF 用 ``PT_LOAD`` 段的 ``filesz``（段是"下载进 flash 的字节"的权威定义，
    节的 vaddr 会把 RAM 里的 .data 也报成 0x20000000 而字节其实在 ROM）；HEX/BIN 整块一块。

    为什么不用节表：MDK 的 axf 里 ``RW_IRAM1``(PROGBITS) 的 vaddr 是 0x20000000，
    但它的 64 字节初始值实际存放在 0x080036EC 的 ROM 里。按节表复刻会把同一批字节
    放到 RAM 地址上，链接结果就与原镜像不同了。
    """
    out: list[dict] = []
    if unit.elf:
        segs = [s for s in unit.elf.get("segments") or []
                if s.get("filesz") and s.get("offset") is not None]
        segs.sort(key=lambda s: (s.get("paddr") or s["vaddr"]))
        for i, s in enumerate(segs):
            raw = unit.data[s["offset"]:s["offset"] + s["filesz"]]
            if not raw:
                continue
            addr = int(s.get("paddr") or s["vaddr"])
            out.append({"addr": addr, "size": len(raw), "data": raw,
                        "name": "seg%d" % i, "load_addr": addr,
                        "vaddr": int(s["vaddr"]), "exec": bool(s["flags"] & 0x1)})
        if out:
            return out
        for i, s in enumerate(unit.elf.get("sections") or []):
            if not s.get("alloc") or s["type_name"] == "NOBITS" or not s["size"]:
                continue
            raw = unit.data[s["offset"]:s["offset"] + s["size"]]
            if raw:
                out.append({"addr": s["addr"], "size": len(raw), "data": raw,
                            "name": "sec%d" % i, "load_addr": s["addr"],
                            "vaddr": s["addr"], "exec": bool(s.get("exec"))})
        return out
    return [{"addr": unit.base, "size": len(unit.data), "data": unit.data,
             "name": "image", "load_addr": unit.base, "vaddr": unit.base,
             "exec": True}]


def data_copies(unit: "Unit", chunks: list[dict]) -> list[dict]:
    """.data 的「从 flash 拷到 RAM」目标表（只报告，不参与复刻）。

    原固件的启动代码本来就会做这件事；这份表是给**人**核对用的：
    字节在 ROM 的哪里、要搬到 RAM 的哪里、搬多少。
    """
    if not unit.elf:
        return []
    flash_lo = min((c["addr"] for c in chunks), default=0)
    flash_hi = max((c["addr"] + c["size"] for c in chunks), default=0)
    out = []
    for s in unit.elf.get("sections") or []:
        if not s.get("alloc") or not s.get("writable") or s["type_name"] == "NOBITS":
            continue
        if not s["size"]:
            continue
        if flash_lo <= s["addr"] < flash_hi:
            continue                      # 本来就在 ROM 里，不用搬
        out.append({"section": s["name"], "dst": "0x%08X" % s["addr"],
                    "size": s["size"],
                    "note": "初始值在镜像的可加载字节里；运行期由原启动代码拷到该地址"})
    return out


def _exact_symbol_labels(unit: "Unit", lo: int, hi: int) -> list[dict]:
    """给精确复刻的 DCB 插入标签/注释用的函数清单（按地址升序）。"""
    try:
        funcs = symbol_table(unit)["functions"] if unit.elf else []
    except Exception:  # noqa: BLE001
        funcs = []
    out = []
    for f in funcs:
        a = f["addr"]
        if lo <= a < hi:
            out.append({"addr": a, "name": f["name"], "size": f.get("size") or 0})
    out.sort(key=lambda f: f["addr"])
    return out


def _exact_asm(unit: "Unit", chunks: list[dict]) -> str:
    """生成 armasm 源码：每个可加载块一个 AREA，字节逐个 DCB，原函数起点插标签。

    为什么用 DCB 而不是反汇编文本：反汇编文本**无法保证原字节复现**
    （字面量池、对齐、adr 都被反汇编器改写成了等价但不同的编码）。
    这一份的用途是"把原固件重新链接出来"，所以只求字节一致；可读的指令在
    ``asm/disassembly.asm`` 里另给。
    """
    L = []
    L.append("; 由 mdkdebug recover_project_exact 生成（批次80）")
    L.append("; 这不是可读源码：字节逐个 DCB，目的是**重新链接出与原镜像逐字节相同的 bin**。")
    L.append("; 函数标签只是地址锚点，函数体语义没有恢复；要读指令请看 asm/disassembly.asm。")
    L.append("")
    L.append("        PRESERVE8")
    L.append("        THUMB")
    L.append("")
    used: set = set()
    for idx, c in enumerate(chunks):
        lo = c["addr"]
        hi = lo + c["size"]
        area = ".rec%02d" % idx
        L.append("; ---- 可加载块 %d：0x%08X .. 0x%08X（%d 字节）----"
                 % (idx, lo, hi, c["size"]))
        L.append("        AREA    |%s|, CODE, READONLY, ALIGN=2" % area)
        labels = {f["addr"]: f["name"] for f in _exact_symbol_labels(unit, lo, hi)}
        data = c["data"]
        for off in range(0, len(data), 16):
            addr = lo + off
            if addr in labels:
                name = _c_name(labels[addr], used)
                L.append("f_%s" % name)
            row = data[off:off + 16]
            L.append("        DCB     " + ",".join("0x%02X" % b for b in row))
        L.append("")
    # 不给 ENTRY：Cortex-M 的入口是**向量表里的复位地址**，不是 ELF entry；
    # armasm 的 ENTRY 在这种「整段 DCB」的 AREA 上会被 armlink 判成
    # 「does not point to an instruction」（L6204E），而那是我们自己造的麻烦。
    L.append("        END")
    return "\n".join(L) + "\n"


def _exact_sct(chunks: list[dict], ram: dict | None, note: str) -> str:
    """精确 sct：每个可加载块一个执行区，用输入段名选择器**钉死**放置位置。

    不用 ``*(+RO)``：那个选择器的放置顺序由链接器决定，块一多就可能挪位；
    这里每块单独一个 ``ER_xxxx`` + ``*(.recNN)`` 选择器，地址与大小都是原值。
    """
    L = []
    L.append("; 由 mdkdebug recover_project_exact 生成（批次80）——%s" % note)
    L.append("; 每个执行区的基址/大小取自原镜像的可加载块；**不要手工改这些数字**，")
    L.append("; 改了 recover_verify 会立刻报出第一处差异。")
    L.append("")
    for idx, c in enumerate(chunks):
        size = _round_up(c["size"], 4)
        L.append("LR_ROM%d 0x%08X 0x%08X  {" % (idx, c["addr"], size))
        L.append("  ER_ROM%d 0x%08X 0x%08X  {" % (idx, c["addr"], size))
        L.append("   *.o (.rec%02d)" % idx)
        L.append("  }")
        L.append("}")
        L.append("")
    if ram and ram.get("start") is not None:
        L.append("; 原镜像的 RAM 初值（.data）由原启动代码搬运；这里留一个空 RAM 区，")
        L.append("; 只为让链接器知道 RAM 窗口（复刻的是 flash 内容，RAM 内容运行期才有）。")
        L.append("LR_RAM 0x%08X 0x%08X  {" % (ram["start"], ram.get("size") or 0x1000))
        L.append("  RW_IRAM1 0x%08X 0x%08X  {" % (ram["start"], ram.get("size") or 0x1000))
        L.append("   .ANY (+RW +ZI)")
        L.append("  }")
        L.append("}")
        L.append("")
    return "\n".join(L)


def _keil_makefile(name: str) -> str:
    """给 Keil 工具链的构建脚本（与 GNU 的 Makefile 并存，互不覆盖）。"""
    return """\
# 由 mdkdebug recover_project_exact 生成（批次80）——字节精确重链接
# 用法：make -f Makefile.keil   （需 armasm/armlink/fromelf 在 PATH，或设 ARM_BIN）
# 产物：build/%(name)s.axf + build/%(name)s.bin；后者应与原镜像的 bin 逐字节相同。

ARM_BIN ?= $(dir $(shell where armasm 2>NUL))
ASM     := $(ARM_BIN)armasm
LINK    := $(ARM_BIN)armlink
ELF2BIN := $(ARM_BIN)fromelf
NAME    := %(name)s
BUILD   := build

all: $(BUILD)/$(NAME)s.bin

$(BUILD):
	mkdir $(BUILD)

$(BUILD)/image_exact.o: src/image_exact.s | $(BUILD)
	$(ASM) --32 --thumb -o $@ $<

$(BUILD)/$(NAME)s.axf: $(BUILD)/image_exact.o linker/recovered.sct
	$(LINK) --scatter linker/recovered.sct --info sizes -o $@ $<

$(BUILD)/$(NAME)s.bin: $(BUILD)/$(NAME)s.axf
	$(ELF2BIN) --bin -o $@ $^

clean:
	rm -rf $(BUILD)

.PHONY: all clean
""" % {"name": name}


def _uvprojx_text(template: str, name: str, asm_rel: str, sct_rel: str,
                  device: str = "", vendor: str = "", pack_id: str = "") -> str:
    """把仓库里那份**已知能编译**的工程模板改造成单文件 asm 工程。

    只改五处：器件（可留空=模板原值）、输出名、分散加载文件、文件组、RTE 目标名。
    改模板而不是凭空写 XML：Keil 的工程文件里有一堆会被校验的默认项，
    少一个就弹「工程文件非法」，而我看不到 UI。
    """
    text = template
    if device:
        text = re.sub(r"<Device>[^<]*</Device>", "<Device>%s</Device>" % device, text, count=1)
    if vendor:
        text = re.sub(r"<Vendor>[^<]*</Vendor>", "<Vendor>%s</Vendor>" % vendor, text, count=1)
    if pack_id:
        text = re.sub(r"<PackID>[^<]*</PackID>", "<PackID>%s</PackID>" % pack_id,
                      text, count=1)
    text = re.sub(r"<OutputName>[^<]*</OutputName>",
                  "<OutputName>%s</OutputName>" % name, text, count=1)
    # 注意：re.sub 的**替换串**会解释反斜杠转义（\r 变回车）——本文件里凡是
    # 带 Windows 路径的替换一律走 lambda，否则 Keil 拿到的是一条断掉的路径。
    text = re.sub(r"<OutputDirectory>[^<]*</OutputDirectory>",
                  lambda _m: "<OutputDirectory>build\\</OutputDirectory>", text, count=1)
    text = re.sub(r"<ScatterFile>[^<]*</ScatterFile>",
                  lambda _m: "<ScatterFile>%s</ScatterFile>" % sct_rel, text, count=1)
    # umfTarg=1 是「用 Target 对话框里的内存布局」，它会**忽略 ScatterFile** 自己生成
    # 一份 scatter（并要求 RESET 段）——真机踩过：工程能打开、一编译就 L6236E。
    text = re.sub(r"<umfTarg>[^<]*</umfTarg>", "<umfTarg>0</umfTarg>", text, count=1)
    group = ("""\
      <Groups>
        <Group>
          <GroupName>Recovered</GroupName>
          <Files>
            <File>
              <FileName>image_exact.s</FileName>
              <FileType>2</FileType>
              <FilePath>%s</FilePath>
            </File>
          </Files>
        </Group>
      </Groups>""" % asm_rel).replace("\n      <Files>", "\n      <Files>")
    # 整段替换 <Groups>…</Groups>（非贪婪，只第一处）
    # 用 lambda 做替换：替换串里有 Windows 反斜杠路径，直接传会被当转义序列
    text = re.sub(r"<Groups>.*?</Groups>", lambda _m: group, text, count=1, flags=re.S)
    text = re.sub(r"<targetInfo name=\"[^\"]*\"", "<targetInfo name=\"%s\"" % name, text)
    text = re.sub(r"<LayName>[^<]*</LayName>", "<LayName>%s</LayName>" % name, text, count=1)
    return text


def _exact_readme(an: dict, chunks: list[dict], copies: list[dict],
                  verify_hint: str) -> str:
    L = []
    L.append("# 字节精确的重链接工程：%s" % os.path.basename(an["path"]))
    L.append("")
    L.append("> 由 mdkdebug `recover_project_exact` 生成（批次80）。")
    L.append("> **这份工程的判据只有一条：重新链接出来的 bin 与原镜像的 bin 逐字节相同。**")
    L.append("> 通过与否不靠我说，跑 `recover_verify` 看 `byte_identical`。")
    L.append("")
    L.append("## 1. 输入身份")
    L.append("")
    L.append("| 项 | 值 |")
    L.append("| --- | --- |")
    L.append("| 路径 | `%s` |" % an["path"])
    L.append("| 大小 | %d 字节 |" % an["size"])
    L.append("| SHA-256 | `%s` |" % an["sha256"])
    L.append("")
    L.append("## 2. 复刻的可加载块")
    L.append("")
    L.append("| # | 起始地址 | 长度 | 说明 |")
    L.append("| --- | --- | --- | --- |")
    for i, c in enumerate(chunks):
        L.append("| %d | `0x%08X` | %d | %s |"
                 % (i, c["addr"], c["size"],
                    "可执行" if c.get("exec") else "只读数据"))
    L.append("")
    if copies:
        L.append("## 3. .data 的搬运目标（只报告，不参与复刻）")
        L.append("")
        L.append("| 节 | RAM 目标 | 长度 |")
        L.append("| --- | --- | --- |")
        for c in copies:
            L.append("| `%s` | `%s` | %d |" % (c["section"], c["dst"], c["size"]))
        L.append("")
        L.append("这些字节已经在 ROM 的可加载块里；运行期由**原固件的启动代码**搬过去。"
                 "本工程没有重建启动代码，所以烧进去能跑到原来那一步，"
                 "但 RAM 初值要靠原代码自己搬。")
        L.append("")
    L.append("## 4. 怎么用")
    L.append("")
    L.append("```")
    L.append("recover_verify(project_dir=..., image=...)   # 先自证：byte_identical 应为 true")
    L.append("make -f Makefile.keil                        # armasm + armlink + fromelf")
    L.append("```")
    L.append("")
    L.append(verify_hint)
    L.append("")
    L.append("## 5. 这份工程**没有**恢复什么")
    L.append("")
    L.append("- 可读的 C/汇编源码：`src/image_exact.s` 是 DCB 字节表，指令在 `asm/disassembly.asm`；")
    L.append("- 函数边界之外的东西：寄存器约定、参数个数与类型、结构体布局、宏、中断优先级；")
    L.append("- 启动代码与 .data 搬运：原代码自带，这里不重建也不改动；")
    L.append("- 可编译的 C 骨架：那是 `recover_project` 的产物，两者用途不同（一份能改，一份能证）。")
    L.append("")
    return "\n".join(L)


# 批次90：``armasm`` / ``armlink`` 是 ARM 32 位的工具链。判出来的家族不是 ARM 时，
# 复刻链**从第一步就不成立**——以前要等到 verify 的 armlink 才炸，报「链接失败」，
# 调用方只能从 stderr 里猜原因。这里提前拒，并说清楚「还能做什么」。
NON_ARM_FAMILIES = ("arm64", "x86", "x86_64", "riscv", "mips", "ppc", "m68k",
                    "sparc", "s390", "mos65xx")


def _arm_only_guard(unit: "Unit", ident: dict, what: str) -> dict | None:
    """家族明确不是 ARM ⇒ 返回拒收结果；ARM 或「未判定」⇒ None（放行）。

    「未判定」放行是刻意的：裸 bin 没有头，判不出来时按 ARM 复刻仍然是**字节上**
    成立的操作，只是这条链的目标对不对没有证据——那句限制由调用方写进 limitations。
    """
    fam = (unit.arch or {}).get("family") or "unknown"
    if fam in ("arm", "unknown"):
        return None
    return {**ident, "ok": False,
            "error": "这份镜像不是 ARM（判为 %s）：%s 用 armasm/armlink 复刻并自证，"
                     "这条命令链在 %s 上不成立" % (fam, what, fam),
            "hint": "① 只做分析：recover_probe / recover_symbols / recover_disasm "
                    "（反汇编后端支持 arm / arm64 / riscv / x86 / x86_64 / mips / ppc / "
                    "m68k / sparc / mos65xx），能看容器、布局、函数与控制流；"
                    "② 要出可重链接工程，得用该架构自己的工具链（例如 RISC-V 的 "
                    "riscv-none-embed-gcc + GNU ld），本仓库没有接；"
                    "③ 别用 armasm 硬凑——那样会得到一份「字节对、目标错」的工程。",
            "arch": unit.arch,
            "what_would_work": ["recover_probe", "recover_symbols", "recover_disasm",
                                "recover_diff", "image_split"]}


def _ram_window(unit: "Unit", chunks: list[dict]) -> dict | None:
    if not unit.elf:
        return None
    rw = [s for s in unit.elf.get("sections") or []
          if s.get("alloc") and (s.get("writable") or s["type_name"] == "NOBITS")
          and s["size"] and s["addr"] >= 0x20000000]
    if not rw:
        return None
    lo = min(s["addr"] for s in rw)
    hi = max(s["addr"] + s["size"] for s in rw)
    return {"start": lo, "size": _round_up(hi - lo)}

def _derive_windows(man: dict, image: str = "") -> dict:
    """从 manifest（必要时再读原镜像的 ELF）推 Flash / RAM 窗口（批次91）。

    这是「不用再人工抄窗口」的那一步，但有两条口径必须说死：

    - Flash 窗口 = manifest 里 chunks **实际覆盖**的字节范围，不是整片芯片的容量。
      所以它只是**下界**：复位地址落在外面，可能是我们没 dump 到的那一段，
      **不是**「向量表坏了」——判 invalid 需要器件级的窗口，而那是调用方的事。
    - RAM 窗口优先取 ``manifest.windows.ram``（出件时从 ELF 的 RW 段算出），
      老产物没有这一项就现读原镜像的 ELF；纯 bin 输入推不出来，就老实说推不出来。

    每个窗口都带 ``basis``，调用方据此决定它能不能当器件窗口用。
    """
    out = {"flash": None, "ram": None, "notes": []}
    spans = []
    for c in (man.get("chunks") or []):
        a = c.get("addr", 0)
        if isinstance(a, str):
            a = int(a, 16) if a.lower().startswith("0x") else int(a)
        n = int(c.get("size") or 0)
        if n:
            spans.append((int(a), int(a) + n))
    if spans:
        lo = min(s[0] for s in spans)
        hi = max(s[1] for s in spans)
        out["flash"] = {"start": lo, "size": hi - lo,
                        "basis": "manifest.chunks（这批镜像实际覆盖的字节范围，是下界、不是整片芯片）"}
    w = man.get("windows") if isinstance(man.get("windows"), dict) else {}
    ram = w.get("ram") if isinstance(w.get("ram"), dict) else None
    if ram and ram.get("start") and ram.get("size"):
        out["ram"] = {"start": int(ram["start"]), "size": int(ram["size"]),
                      "basis": "manifest.windows.ram（出件时从 ELF 的 RW 段算出）"}
    elif image and os.path.isfile(image):
        data, err = _read_file(image)
        if not err and detect_container(data[:4096]) == "elf":
            elf = parse_elf(data)
            rw = [s for s in elf.get("sections") or []
                  if s.get("alloc") and (s.get("writable") or s["type_name"] == "NOBITS")
                  and s["size"]]
            if rw:
                lo = min(s["addr"] for s in rw)
                hi = max(s["addr"] + s["size"] for s in rw)
                out["ram"] = {"start": lo, "size": _round_up(hi - lo),
                              "basis": "现读原镜像 ELF 的 RW 段"}
    if out["ram"] is None:
        out["notes"].append(
            "推不出 RAM 窗口：manifest 里没有 RW 段记录、原镜像也不是 ELF"
            "（纯 bin 没有地址信息）——SP 是否落在 RAM 这条判据只能停在 unverified")
    return out

def project_exact(path: str, out_dir: str, *, name: str = "recovered",
                  base: int = 0, device: str = "", vendor: str = "",
                  pack_id: str = "", emit_uvprojx: bool = True,
                  include_asm: bool = True, max_asm_functions: int = 400,
                  **kw) -> dict:
    """出「字节精确 + 可重链接」的工程（批次80）。

    与 :func:`build_project` 的分工：
    - ``build_project``：可读、可改的**骨架**（stub + 头文件 + 启动表），编译得过、
      但里面没有原代码；
    - ``project_exact``：**原样复刻**，重新链接出的 bin 与原镜像逐字节相同（用
      :func:`verify_project` 自证），代价是源码不可读。
    """
    data, err = _read_file(path)
    if err:
        return err
    _kind = detect_container(data[:4096])
    if _kind == "ar":
        return {"ok": False,
                "error": "这是 ar 归档（.lib/.a）：成员是可重定位目标文件，地址是**节内偏移**，"
                         "不是最终地址——直接复刻会得到一个地址全错的工程",
                "hint": "先用 recover_probe 看成员清单，再对单个成员用 recover_disasm；"
                        "把归档链接成 axf（Keil 里编译工程）之后再对 axf 用本工具"}
    unit = _unit_from_data(data, os.path.basename(path), base)
    if unit.relocatable:
        return {"ok": False,
                "error": "这是可重定位目标文件（ET_REL，如 .o / 库成员）：没有最终地址，无法复刻",
                "hint": "对单个目标文件用 recover_disasm 看指令；要出可链接工程请给已链接的 axf/elf"}
    bad = _arm_only_guard(unit, {"path": os.path.abspath(path),
                                "size": len(data),
                                "sha256": sha256_bytes(data)},
                          "recover_project_exact")
    if bad:
        return bad
    chunks = load_chunks(unit)
    if not chunks:
        return {"ok": False, "error": "没有可加载字节：这份输入里找不到能复刻的区间"}
    dest = os.path.abspath(out_dir)
    # 同上：位置非法优先于"目录已存在"
    bad = _evidence.violation(dest)
    if bad:
        return {**_evidence.refusal(dest, bad), "out_dir": dest}
    if os.path.exists(dest):
        return {"ok": False,
                "error": "输出目录已存在：%s" % dest,
                "hint": "出件绝不复用目录（不覆盖既有证据）；换一个不存在的路径"}
    os.makedirs(dest)

    # 要出可读反汇编就得做交叉引用扫描（deep）；只要字节复刻时可以关掉（快）
    an = analyze(path, base=base, deep=bool(include_asm),
                 max_functions=int(kw.get("max_functions") or MAX_FUNCTIONS),
                 max_insns=int(kw.get("max_insns") or MAX_INSNS))
    files: list = []
    copies = data_copies(unit, chunks)
    ram = _ram_window(unit, chunks)

    _emit(dest, "src/image_exact.s", _exact_asm(unit, chunks), files)
    _emit(dest, "linker/recovered.sct",
          _exact_sct(chunks, ram, "布局来自原镜像的可加载块"), files)
    _emit(dest, "Makefile.keil", _keil_makefile(name), files)

    funcs = (an.get("_recover") or {}).get("functions") or []
    used: set = set()
    hdr = ["/* 自动生成（mdkdebug recover_project_exact，批次80）。",
           " *",
           " * 地址来自原镜像；**函数原型与参数没有恢复**，一律按无参 void 登记。",
           " * 这些是 flash 里的地址常量，可直接用于调试器/上位机对位。 */",
           "#ifndef RECOVERED_SYMBOLS_H", "#define RECOVERED_SYMBOLS_H", ""]
    for f in funcs[:600]:
        hdr.append("#define ADDR_%s 0x%08Xu  /* %s, %s */"
                   % (_c_name(f["name"], used).upper(), f["addr"] & ~1,
                      f.get("confidence", "?"),
                      # 证据来源在 analyze 里叫 sources（列表），不是 source——
                      # 曾经这里写过 "?"，等于把「证据是什么」丢了（批次80 实测发现）。
                      ",".join(f.get("sources") or []) or f.get("source") or "?"))
    hdr += ["", "#endif", ""]
    _emit(dest, "include/recovered_symbols.h", "\n".join(hdr), files)

    # 可读反汇编（与精确复刻并存：一份能证、一份能读）
    asm_note = "未生成（include_asm=false）"
    if include_asm:
        try:
            r = disasm_text(unit, funcs[:max(0, int(max_asm_functions))],
                            max_insns=int(kw.get("max_insns") or MAX_INSNS))
            if r.get("ok") and r.get("text"):
                _emit(dest, "asm/disassembly.asm", r["text"], files)
                asm_note = "asm/disassembly.asm（%d 个函数 / %d 条指令）" % (
                    min(len(funcs), int(max_asm_functions)), r.get("insn_count") or 0)
            else:
                asm_note = "未生成：%s" % (r.get("error") or "反汇编为空")
        except Exception as exc:  # noqa: BLE001
            asm_note = "生成失败：%s" % exc

    uv_note = "未生成"
    if emit_uvprojx:
        tmpl = _uvprojx_template()
        if not tmpl.get("ok"):
            uv_note = "未生成：%s" % tmpl.get("error")
        else:
            text = _uvprojx_text(tmpl["text"], name, r"src\image_exact.s",
                                 r"linker\recovered.sct", device, vendor, pack_id)
            _emit(dest, "%s.uvprojx" % name, text, files)
            uv_note = "%s.uvprojx（器件 %s——%s）" % (
                name, device or tmpl.get("device") or "模板原值",
                "按参数设置" if device else "占位：编译不受影响，**烧录前必须改成本机芯片**")
    else:
        uv_note = "未生成（emit_uvprojx=false）"

    an2 = {"path": os.path.abspath(path), "size": len(data),
           "sha256": sha256_bytes(data), "arch": unit.arch}
    hint = ("**先跑 `recover_verify(project_dir=\"%s\", image=\"%s\")`**："
            "`byte_identical=true` 才说明这份工程真的复刻了原镜像。" % (dest, os.path.abspath(path)))
    # 批次90：把「一条路」的下一句写成能直接复制的一行——窗口不再要调用方自己算。
    # 漏窗口不是错答案，但会让向量表义务停在 unverified，值得在出件时就说清楚。
    _f_lo = min(c["addr"] for c in chunks)
    _f_hi = max(c["addr"] + c["size"] for c in chunks)
    _windows = "flash_start=0x%08X, flash_size=0x%X" % (_f_lo, _f_hi - _f_lo)
    if ram:
        _windows += ", ram_start=0x%08X, ram_size=0x%X" % (ram["start"], ram["size"])
    ledger_cmd = ('recover_ledger(project_dir="%s", image="%s", %s)'
                  % (dest, os.path.abspath(path), _windows))
    _emit(dest, "README.md", _exact_readme(an2, chunks, copies, hint), files)

    manifest = {
        "format": "mdkdebug.recover_exact/1",
        "input": {"path": os.path.abspath(path), "size": len(data),
                  "sha256": sha256_bytes(data)},
        "name": name,
        "base": chunks[0]["addr"],
        "chunks": [{"index": i, "addr": "0x%08X" % c["addr"], "size": c["size"],
                    "sha256": sha256_bytes(c["data"]),
                    "area": ".rec%02d" % i} for i, c in enumerate(chunks)],
        "expected_bin": {"concat_sha256": sha256_bytes(b"".join(c["data"] for c in chunks)),
                         "total": sum(c["size"] for c in chunks)},
        "windows": {"flash": {"start": _f_lo, "size": _f_hi - _f_lo,
                              "basis": "本镜像 chunks 覆盖的字节范围（下界）"},
                    "ram": ({"start": ram["start"], "size": ram["size"],
                             "basis": "原镜像 ELF 的 RW 段"} if ram else None)},
        "sct": "linker/recovered.sct",
        "asm": "src/image_exact.s",
        "data_copies": copies,
        "arch": unit.arch,
        "uvprojx": uv_note,
        "notes": [
            "复刻的是 flash 里的可加载字节，不是语义",
            "判据是 recover_verify 的 byte_identical，不是「看起来像」",
        ],
    }
    manifest["evidence_only"] = True
    manifest["artifact_kind"] = "evidence"
    manifest["evidence_only_files"] = [f["rel"] for f in files]
    _emit(dest, "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
          files)

    return {"ok": True,
            "out_dir": dest,
            "name": name,
            "input": manifest["input"],
            "chunks": manifest["chunks"],
            "files": files,
            "file_count": len(files),
            "uvprojx": uv_note,
            "asm": asm_note,
            "next_actions": [hint,
                             "闭环台账直接抄这一行（窗口已按这份镜像的布局算好）：%s"
                             % ledger_cmd,
                             '或者省掉窗口这一半：recover_ledger(project_dir="%s", '
                             'image="%s")——flash 从 manifest 的 chunks 推、ram 从 manifest 的 '
                             "RW 段推（批次91）；推出来的窗口是**下界**，只把判据从 unverified "
                             "抬到 plausible，不会因为落在外面就判 invalid"
                             % (dest, os.path.abspath(path))]
                            + ([] if ram else ["这份镜像里没有可写的节（没有 ELF 的 RW 段），"
                                               "ram_start/ram_size 只能你自己给——不给的话"
                                               "台账的向量表判据停在 unverified，不是通过"])
                            + ["自证通过后再改：Want 改代码就改 asm/disassembly.asm 里那一份，"
                               "但那样就不再逐字节相同了"],
            "limits": [
                "DCB 复刻 = 原字节原样，不表示这些字节的语义被恢复",
                "启动代码与 .data 搬运沿用原固件，本工程不重建",
                "多段 ROM（含间隔）时各段独立成区，与原镜像的拼接方式可能不同——以 verify 为准",
            ]}


def _uvprojx_template() -> dict:
    """仓库内已知能编译的工程模板（只做文本改造，不凭空生成 XML）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(root, "example_mdk_project", "mdk_test", "MDK-ARM",
                     "mdk_test.uvprojx")
    if not os.path.isfile(p):
        return {"ok": False,
                "error": "仓库内没有工程模板（%s）：宁可不出 uvprojx，也不给一个没验证过的 XML"
                         % p}
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.search(r"<Device>([^<]*)</Device>", text)
    return {"ok": True, "path": p, "text": text, "device": m.group(1) if m else ""}


def _run(cmd: list[str], cwd: str, timeout: float = 180.0) -> dict:
    """跑一条工具链命令，把 stdout/stderr 都带回来（不吞错误）。"""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return {"ok": p.returncode == 0, "rc": p.returncode,
                "stdout": (p.stdout or "")[-4000:], "stderr": (p.stderr or "")[-4000:],
                "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": None, "error": "超时（%.0fs）" % timeout,
                "cmd": " ".join(cmd)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "rc": None, "error": str(exc), "cmd": " ".join(cmd)}


def _diff_summary(a: bytes, b: bytes, limit: int = 8) -> dict:
    n = min(len(a), len(b))
    offs = []
    for i in range(n):
        if a[i] != b[i]:
            offs.append(i)
            if len(offs) >= limit:
                break
    return {"length_expected": len(a), "length_actual": len(b),
            "same_prefix_len": (offs[0] if offs else n),
            "diff_offsets": offs,
            "diff_count_first_scan": len(offs),
            "byte_identical": (len(a) == len(b) and not offs)}


def _build_via_keil(dest: str, name: str, timeout_s: float) -> dict:
    """用 UV4 批处理编译**生成的 .uvprojx**（证明这份工程文件本身可用）。

    UV4 的退出码：0 无错无警告 / 1 有警告但产物已生成 / ≥2 有错。
    只认 0/1 为成功，且以「产物文件真的存在」为准，不靠退出码猜。
    """
    try:
        from . import builder as _builder  # noqa: PLC0415
        uv4 = _builder.find_uv4(None)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "定位 UV4 失败：%s" % exc}
    if not uv4:
        return {"ok": False, "error": "找不到 UV4.exe：无法用 Keil 验证工程文件"}
    proj = os.path.join(dest, "%s.uvprojx" % name)
    if not os.path.isfile(proj):
        return {"ok": False, "error": "目录里没有 %s.uvprojx" % name}
    log = os.path.join(dest, "build", "keil_build.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    r = _run([uv4, "-b", proj, "-j0", "-o", log], dest, timeout_s)
    text = ""
    try:
        with open(log, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        text = (r.get("stdout") or "") + (r.get("stderr") or "")
    ok = r.get("rc") in (0, 1)
    return {"ok": bool(ok), "rc": r.get("rc"), "uv4": uv4, "log_path": log,
            "log": text[-3000:], "cmd": r.get("cmd"),
            "interpretation": ("UV4 rc=%s（0=无警告，1=有警告但产物已生成，≥2=有错误）"
                               % r.get("rc"))}


def verify_project(project_dir: str, image: str = "", *, base: int = 0,
                   arm_bin: str = "", timeout_s: float = 240.0,
                   keep_build: bool = True, via_uvprojx: bool = False) -> dict:
    """**用真工具链重链接一遍**，再与原镜像的 bin 逐字节比对。

    这是「工程级恢复」的判据本身：

    1. ``armasm`` 汇编 ``src/image_exact.s``；
    2. ``armlink`` 按 ``linker/recovered.sct`` 链接；
    3. ``fromelf --bin`` 出 bin；
    4. 与原镜像的 bin 比（ELF 用 ``fromelf --bin`` 抽，HEX 解码，BIN 直读）；
    5. 报 ``byte_identical`` 与第一处差异偏移。

    任何一步失败都**如实返回那一步的命令与 stderr**——不给「大概成功」。
    """
    dest = os.path.abspath(project_dir)
    man_path = os.path.join(dest, "manifest.json")
    if not os.path.isfile(man_path):
        return {"ok": False,
                "error": "目录里没有 manifest.json：%s" % dest,
                "hint": "这份目录不是 recover_project_exact 的产物；"
                        "骨架工程（recover_project）没有可重链接的字节表，无法这样自证"}
    try:
        with open(man_path, "r", encoding="utf-8") as f:
            man = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "manifest.json 读不出来：%s" % exc}

    tools = find_arm_tools(arm_bin)
    steps: list = []
    if not tools.get("ok"):
        return {"ok": False, "error": tools.get("error"),
                "hint": tools.get("hint"), "tried": tools.get("tried"),
                "manifest_input": man.get("input")}

    arch_doc = man.get("arch") if isinstance(man.get("arch"), dict) else {}
    fam = (arch_doc or {}).get("family") or "unknown"
    if fam in NON_ARM_FAMILIES:
        # 老工程（批次90 之前 project_exact 没有这道闸门）会走到这里：
        # 与其让 armlink 打一行看不懂的错，不如把「为什么必然失败」说清楚。
        return {"ok": False,
                "error": "manifest 记的架构是 %s：本工具的重链接链是 armasm + armlink"
                         "（ARM 32 位），对 %s 不成立" % (fam, fam),
                "hint": "这份工程只能当「字节与布局的记录」看；要验证得用 %s 自己的"
                        "工具链（本仓库未接）。同一份输入用 recover_probe / "
                        "recover_disasm 做分析是有效的。" % fam,
                "arch": arch_doc,
                "manifest_input": man.get("input")}

    build = os.path.join(dest, "build")
    os.makedirs(build, exist_ok=True)
    name = man.get("name") or "recovered"
    asm = man.get("asm") or "src/image_exact.s"
    sct = man.get("sct") or "linker/recovered.sct"
    obj = os.path.join(build, "image_exact.o")
    axf = os.path.join(build, "%s.axf" % name)
    binf = os.path.join(build, "%s.bin" % name)

    for f in (axf, binf):
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError:
            pass

    notes_entry = ""
    if via_uvprojx:
        # 走 Keil：编译**生成的工程文件**本身，再拿它的产物比对。
        # 这一路的证据最强——它同时证明了「工程文件可用」与「字节一致」。
        kb = _build_via_keil(dest, name, timeout_s)
        steps.append({"step": "UV4 -b（编译生成的 .uvprojx）",
                      "ok": kb.get("ok"), "rc": kb.get("rc"),
                      "cmd": kb.get("cmd"), "stderr": kb.get("log") or "",
                      "interpretation": kb.get("interpretation")})
        if not kb.get("ok"):
            return {"ok": False, "failed_step": "keil_build", "steps": steps,
                    "error": kb.get("error") or "Keil 编译失败（看 steps 里的日志）",
                    "log_path": kb.get("log_path")}
        if not os.path.isfile(axf):
            return {"ok": False, "failed_step": "keil_build", "steps": steps,
                    "error": "Keil 编译没报错但产物不存在：%s" % axf,
                    "hint": "看 log_path 里的完整日志；多半是 OutputName/OutputDirectory 被改过"}
        r3 = _run([tools["tools"]["fromelf"], "--bin", "-o", binf, axf], dest, timeout_s)
        steps.append({"step": "fromelf --bin（Keil 产物）", **r3})
        if not r3.get("ok") or not os.path.isfile(binf):
            return {"ok": False, "failed_step": "fromelf", "steps": steps,
                    "error": "fromelf --bin 失败（见 steps[-1] 的 stderr）"}
    else:
        r1 = _run([tools["tools"]["armasm"], "--32", "-o", obj, asm], dest, timeout_s)
        steps.append({"step": "armasm", **r1})
        if not r1.get("ok"):
            return {"ok": False, "failed_step": "armasm", "steps": steps,
                    "error": "汇编失败（见 steps[-1] 的 stderr）",
                    "arm_tools": {k: v for k, v in tools.items() if k != "tried"}}

        r2 = _run([tools["tools"]["armlink"], "--scatter", sct, "-o", axf, obj],
                  dest, timeout_s)
        steps.append({"step": "armlink", **r2})
        if not r2.get("ok") or not os.path.isfile(axf):
            return {"ok": False, "failed_step": "armlink", "steps": steps,
                    "error": "链接失败（见 steps[-1] 的 stderr）"}
        if "L6305W" in (r2.get("stderr") or ""):
            notes_entry = ("armlink 的 L6305W（没有入口点）是**预期**的：Cortex-M 的入口是"
                           "向量表里的复位地址，ELF entry 字段不参与启动")

        r3 = _run([tools["tools"]["fromelf"], "--bin", "-o", binf, axf], dest, timeout_s)
        steps.append({"step": "fromelf --bin", **r3})
        if not r3.get("ok") or not os.path.isfile(binf):
            return {"ok": False, "failed_step": "fromelf", "steps": steps,
                    "error": "fromelf --bin 失败（见 steps[-1] 的 stderr）"}

    with open(binf, "rb") as f:
        actual = f.read()

    # ---- 期望字节：优先用「真工具链抽原镜像」，抽不了才回退到 manifest 的拼接 ----
    src = image or (man.get("input") or {}).get("path") or ""
    expected = b""
    expected_source = ""
    notes: list = []
    if notes_entry:
        notes.append(notes_entry)
    if src and os.path.isfile(src):
        data, err = _read_file(src)
        if err:
            return {"ok": False, "error": err.get("error"), "steps": steps}
        kind = detect_container(data[:4096])
        if kind == "elf":
            tmp = os.path.join(build, "original.bin")
            rr = _run([tools["tools"]["fromelf"], "--bin", "-o", tmp, os.path.abspath(src)],
                      dest, timeout_s)
            steps.append({"step": "fromelf --bin 原镜像", **rr})
            if rr.get("ok") and os.path.isfile(tmp):
                with open(tmp, "rb") as f:
                    expected = f.read()
                expected_source = "fromelf --bin %s" % os.path.basename(src)
        elif kind == "ihex":
            flat = _flat_image(data, "ihex", base)
            expected = flat.get("data") or b""
            expected_source = "hex 解码（%s）" % os.path.basename(src)
        else:
            expected = data
            expected_source = "裸 bin 直读（%s）" % os.path.basename(src)
        if src and (man.get("input") or {}).get("sha256"):
            if sha256_bytes(data) != man["input"]["sha256"]:
                notes.append("image 与 manifest 记的输入**不是同一份**"
                             "（sha256 不符）：本次比对的是你给的那份")
    if not expected:
        expected_source = "（无，未提供可比的原镜像）"
        notes.append("没有可用的原镜像：**本次没有独立证据**——产物 bin 已生成在 "
                     "build/ 下，请传 image= 原文件再比一次")

    diff = _diff_summary(expected, actual) if expected else {
        "byte_identical": None, "note": "无期望字节"}
    # armasm 的 AREA 至少按 4 字节对齐：原镜像长度不是 4 的倍数时，重链接出的 bin
    # 会多出 1..3 个**全零**尾字节（链接器补齐，不是内容差异）。这不是“相同”的
    # 简化，而是把差异说清楚：前缀必须逐字节相同，多出来的只有在全是 0 且 <=3
    # 字节时才记为 alignment_padding；否则照样判不同。
    pad = len(actual) - len(expected)
    if expected and 0 < pad <= 3 and actual[len(expected):] == b"\x00" * pad \
            and actual[:len(expected)] == expected:
        diff["byte_identical"] = True
        diff["alignment_padding"] = pad
        notes.append("重链接产物比原镜像多 %d 个全零尾字节：armasm 的 AREA 4 字节对齐填充，"
                     "不属于镜像内容（原镜像长度 %d 不是 4 的倍数）" % (pad, len(expected)))
    concat_sha = (man.get("expected_bin") or {}).get("concat_sha256")
    manifest_match = (sha256_bytes(expected) == concat_sha) if (expected and concat_sha) else None
    if manifest_match is False:
        notes.append("原镜像抽出的 bin 与 manifest 记的 concat_sha256 不一致："
                     "要么传入的 image 不是当初那份，要么镜像变了")

    ok = bool(diff.get("byte_identical"))
    out = {
        "ok": True,
        "byte_identical": ok,
        "project_dir": dest,
        "image": os.path.abspath(src) if src else "",
        "expected_source": expected_source,
        "expected": {"size": len(expected), "sha256": sha256_bytes(expected) if expected else "",
                     "manifest_concat_sha256": concat_sha, "manifest_match": manifest_match},
        "actual": {"size": len(actual), "sha256": sha256_bytes(actual)},
        "diff": diff,
        "build": {"dir": build, "axf": axf, "bin": binf, "kept": keep_build,
                  "via": "uvprojx（Keil 编译生成的工程文件）" if via_uvprojx else "armasm+armlink"},
        "steps": steps,
        "arm_tools": {"bin_dir": tools.get("bin_dir"), "version": tools.get("version")},
        "notes": notes,
        "verdict": ("逐字节相同：地址、布局、可加载内容都复刻对了"
                    if ok else
                    "**不相同**：这份工程没有复刻成功，先看 diff.diff_offsets 的第一处差异"),
    }
    if not ok:
        out["next_actions"] = [
            "看 steps 里 armlink 的 stderr：区域放不下/重叠会在这里说清",
            "diff.diff_offsets 是 bin 内偏移；加上 base 才是地址",
            "长度不同（length_expected vs length_actual）通常是区域向上取整或原镜像有空洞",
        ]
    return out


# ----------------------------------------------------------------------
# 批次86：库指纹与函数匹配（吸收 Ghidra FID / REA match_native_functions 的口径）
# ----------------------------------------------------------------------
def build_signature(path: str, base: int = 0, *, arch: str = "", endian: str = "",
                    bits: int = 0, thumb: bool | None = None, entry: int = 0,
                    deep: bool = True, max_functions: int = MAX_FUNCTIONS,
                    max_insns: int = MAX_INSNS) -> dict:
    """分析一份镜像 → 函数指纹库（不写盘；写盘用 :func:`save_signature`）。

    指纹库的用途是 **FID**：拿一份**带符号**的 axf/elf 当「库」，去识别另一份
    剥离了符号的固件里哪些函数是同一份代码。所以指纹必须能被独立保存、跨会话复用。
    """
    an = analyze(path, base=base, deep=deep, max_functions=max_functions,
                 max_insns=max_insns, arch=arch, endian=endian, bits=bits,
                 thumb=thumb, entry=entry)
    if not an.get("ok"):
        return an
    unit = an.get("_unit")
    if unit is None:
        return {"ok": False,
                "error": "这份输入没有单一地址空间（ar 归档的成员各自从节内偏移算起，"
                         "不同成员会撞到同一个地址），出不了可比对的指纹库",
                "hint": "先链接成 axf/elf；或对单个成员用 recover_disasm 看代码"}
    rec = an.get("_recover") or {}
    if not (rec.get("functions") or []):
        return {"ok": False,
                "error": "没有恢复出任何函数：没有可比对的对象",
                "hint": "deep=true 会做线性反汇编找调用目标；裸 bin 记得给 arch（+entry）"}
    idx = fid.index_functions(unit, rec["functions"], rec.get("_insns") or {},
                              rec.get("string_refs") or [],
                              notes=an.get("notes") or [])
    sig = {k: idx[k] for k in ("format", "version", "arch", "container",
                               "functions", "fingerprint_rule", "notes")}
    return {
        "ok": True,
        "input": {"path": an.get("path"), "size": an.get("size"),
                  "sha256": an.get("sha256")},
        "container": an.get("container"),
        "arch": an.get("arch"),
        "counts": fid.side_coverage(idx["functions"]),
        "sig": sig,
        "limitations": (an.get("limitations") or []) + [
            "指纹只覆盖**恢复出来的函数**：没有被识别成函数的字节不进指纹库，"
            "所以「库里没有」不等于「固件里没有」",
        ],
        "gaps": an.get("gaps") or [],
    }


def save_signature(path: str, sig_path: str, *, base: int = 0, arch: str = "",
                   endian: str = "", bits: int = 0, thumb: bool | None = None,
                   entry: int = 0, deep: bool = True,
                   max_functions: int = MAX_FUNCTIONS, max_insns: int = MAX_INSNS,
                   overwrite: bool = False) -> dict:
    """分析一份镜像并把指纹库写到 ``sig_path``（默认不覆盖既有库）。"""
    b = build_signature(path, base, arch=arch, endian=endian, bits=bits, thumb=thumb,
                        entry=entry, deep=deep, max_functions=max_functions,
                        max_insns=max_insns)
    if not b.get("ok"):
        return b
    w = fid.save_sig(sig_path, b["sig"],
                     source={"input": b["input"], "container": b.get("container")},
                     overwrite=overwrite)
    if not w.get("ok"):
        return w
    return {"ok": True, "input": b["input"], "counts": b["counts"], "signature": w,
            "limitations": b["limitations"]}


def _sig_side(path: str, base: int, sig_path: str, *, arch: str, endian: str,
              bits: int, thumb, entry, max_functions: int, max_insns: int) -> dict:
    if sig_path:
        s = fid.load_sig(sig_path)
        if not s.get("ok"):
            return s
        return {"ok": True,
                "sig": {k: s.get(k) for k in ("format", "version", "arch", "container",
                                              "functions", "fingerprint_rule", "notes")},
                "input": {"path": sig_path, "via": "signature-file",
                          "source": s.get("source") or {}},
                "container": s.get("container"),
                "counts": fid.side_coverage(s.get("functions") or [])}
    return build_signature(path, base, arch=arch, endian=endian, bits=bits,
                           thumb=thumb, entry=entry, max_functions=max_functions,
                           max_insns=max_insns)


def compare_images(reference: str, target: str, *, reference_base: int = 0,
                   target_base: int = 0,
                   reference_sig: str = "", target_sig: str = "",
                   save_reference_sig: str = "", overwrite_sig: bool = False,
                   arch: str = "", endian: str = "", bits: int = 0,
                   thumb: bool | None = None, entry: int = 0,
                   min_insns: int = 6, max_functions: int = MAX_FUNCTIONS,
                   max_insns: int = MAX_INSNS, full: bool = False,
                   max_rows: int = 40) -> dict:
    """比对两份镜像的函数集合（同一芯片的两个固件版本，或「带符号库 vs 裸固件」）。

    每一侧都可以是**镜像路径**或**已保存的指纹库**（避免重复分析）。两侧的架构
    参数共用一套（同一颗芯片的两个版本）——两侧架构不同会直接报错，不做跨指令集比对。
    """
    lb = _sig_side(reference, reference_base, reference_sig, arch=arch, endian=endian, bits=bits,
                   thumb=thumb, entry=entry, max_functions=max_functions,
                   max_insns=max_insns)
    if not lb.get("ok"):
        return {**lb, "side": "reference"}
    rb = _sig_side(target, target_base, target_sig, arch=arch, endian=endian, bits=bits,
                   thumb=thumb, entry=entry, max_functions=max_functions,
                   max_insns=max_insns)
    if not rb.get("ok"):
        return {**rb, "side": "target"}
    rep = fid.match(lb["sig"], rb["sig"], min_insns=int(min_insns or 6))
    if not rep.get("ok"):
        return rep
    out = {
        "ok": True,
        "reference": {"input": lb["input"], "container": lb.get("container"),
                      "counts": lb["counts"]},
        "target": {"input": rb["input"], "container": rb.get("container"),
                   "counts": rb["counts"]},
        "counts": rep["counts"],
        "coverage": rep["coverage"],
        "fingerprint_rule": rep["fingerprint_rule"],
        "limitations": rep["limitations"],
    }
    cap = 0 if full else max(1, int(max_rows or 40))
    out["matches"] = rep["matches"] if not cap else rep["matches"][:cap]
    out["matches_total"] = len(rep["matches"])
    out["matches_truncated"] = bool(cap and len(rep["matches"]) > cap)
    out["unresolved"] = rep["unresolved"]
    out["unresolved_truncated"] = rep["unresolved_truncated"]
    out["only_left"] = rep["only_left"] if not cap else rep["only_left"][:cap]
    out["only_left_total"] = len(rep["only_left"])
    out["only_right"] = rep["only_right"] if not cap else rep["only_right"][:cap]
    out["only_right_total"] = len(rep["only_right"])
    if save_reference_sig:
        w = fid.save_sig(save_reference_sig, lb["sig"],
                         source={"input": lb["input"],
                                 "container": lb.get("container")},
                         overwrite=overwrite_sig)
        out["reference_signature"] = w
    return out

# ----------------------------------------------------------------------
# 批次88：固件恢复的闭环台账（吸收 REA obligation-ledger 的 fail-closed 口径）
# ----------------------------------------------------------------------
def _manifest_chunk0(man: dict) -> int:
    """manifest 里第一个可加载区的起始地址（写成字符串或整数都要认）。"""
    ch = (man.get("chunks") or [{}])[0]
    v = ch.get("addr", man.get("base") or 0)
    if isinstance(v, str):
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    return int(v or 0)

def _vector_words(image: str, base: int, project_dir: str) -> dict:
    """取「原镜像可加载字节」的开头 8 字节，并给出它落在哪个地址上。

    只做取字节，不做判断——判断在 :func:`_vector_entry_fact` 里，便于测试。
    """
    from . import image as _image  # noqa: PLC0415
    if image and os.path.isfile(image):
        data, err = _read_file(image)
        if err:
            return {"ok": False, "error": err.get("error")}
        kind = detect_container(data[:4096])
        if kind == "elf":
            elf = parse_elf(data)
            for seg in elf.get("segments") or []:
                if int(seg.get("type") or 0) != 1 or int(seg.get("filesz") or 0) < 8:
                    continue
                off = int(seg["offset"])
                addr = int(seg.get("paddr") or 0) or int(seg.get("vaddr") or 0)
                return {"ok": True, "head": data[off:off + 8], "addr": addr,
                        "source": "ELF 第一个 PT_LOAD（%s）" % os.path.basename(image)}
            return {"ok": False, "error": "ELF 里没有足够长的 PT_LOAD 段：取不到向量表两个字"}
        if kind in ("ihex", "srec"):
            flat = _flat_image(data, kind, base)
            if not flat.get("ok"):
                return {"ok": False, "error": flat.get("error") or "稀疏文本解码失败"}
            return {"ok": True, "head": (flat.get("data") or b"")[:8],
                    "addr": int(flat.get("base") or 0),
                    "source": "%s 解码后的首个数据字节" % kind}
        return {"ok": True, "head": data[:8], "addr": int(base or 0),
                "source": "裸 bin 的前 8 字节"}
    # 没有原镜像时，只能靠 verify 抽出来的 build/original.bin（ELF 输入会留这份）
    for name in ("original.bin",):
        p = os.path.join(project_dir, "build", name)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                head = f.read(8)
            return {"ok": True, "head": head, "addr": int(base or 0),
                    "source": "verify 抽出的 build/%s（ELF 的 fromelf --bin 产物）" % name}
    return {"ok": False, "error": "没有原镜像可取向量表两个字"}

def _vector_entry_fact(project_dir: str, image: str, base: int, man: dict, *,
                       ram=None, flash=None, derived_windows=()) -> dict | None:
    """向量表义务的证据：原镜像 base 处的前两个字 + 工程首区确实从 base 起。

    判据（全部要为真才算观察到）：
      1. 工程第一块 ``.rec00`` 的起始地址 == 原可加载字节的首地址（否则向量表不在 base 上）；
      2. ``image.check_vector_table`` 的 verdict 不是 ``invalid``
         （SP 非 0/全 1、4 字节对齐、复位地址 bit0=1；给了 RAM/Flash 窗口才核落点）。

    ``derived_windows`` 里点名的那几个窗口是**按布局推出来的下界**（批次91）：
    用它落点落空时只把判据退成 unverified（未核），**不判 invalid**——
    「落在我们没 dump 到的那一段」和「向量表是坏的」不是一回事。
    """
    from . import image as _image  # noqa: PLC0415
    c0 = _manifest_chunk0(man)
    # 裸 bin 里没有地址信息：base 没给就用 manifest 记的首块地址（批次91）——
    # 「这份字节被放在哪」manifest 里已经有了，不该再让调用方抄一遍。
    w = _vector_words(image, base or c0, project_dir)
    if not w.get("ok"):
        return None
    head = w.get("head") or b""
    if len(head) < 8:
        return None
    vt = _image.check_vector_table(head[0:4], head[4:8], ram=ram, flash=flash)
    base_ok = (int(w.get("addr") or 0) == c0)
    _derived = set(derived_windows or ())
    _downgraded = False
    if vt["verdict"] == "invalid" and _derived:
        _bad_contain = [k for k in ("sp_in_ram", "reset_in_flash")
                        if vt["checks"].get(k) is False]
        _bad_hard = [k for k, v in vt["checks"].items()
                     if v is False and k not in ("sp_in_ram", "reset_in_flash")]
        _derived_bad = [k for k in _bad_contain
                        if ("ram" if k == "sp_in_ram" else "flash") in _derived]
        if _derived_bad and not _bad_hard and len(_derived_bad) == len(_bad_contain):
            _downgraded = True
            vt = dict(vt, verdict="unverified",
                      why=list(vt.get("why") or []) + [
                          "这一条落点判据是拿**推出来的**窗口核的（%s）：推出来的只是"
                          "手上这些字节的范围，落在外面说明不了向量表是错的"
                          % "、".join(sorted(_derived_bad))])
    note = ("原镜像 0x%08X 处 SP=%s reset=%s（判据 %s）；工程首区 .rec00 起始 0x%08X %s"
            % (int(w.get("addr") or 0), vt["sp_hex"], vt["reset_hex"], vt["verdict"],
               c0, "与之一致" if base_ok else "**不一致**：向量表不在工程首区上"))
    if vt["verdict"] == "unverified":
        _miss = ([("SP 是否落在 RAM", "RAM")] if not ram else []) + \
                ([("复位地址是否落在 Flash", "Flash")] if not flash else [])
        if _miss:
            note += ("；没有 %s 窗口：%s 这条判据是 None（未核），给了窗口才是 plausible"
                     % ("/".join(m[1] for m in _miss), "、".join(m[0] for m in _miss)))
    if _downgraded:
        note += ("；按布局推出来的窗口（%s）核不上落点：这只能说明它落在我手上这些字节之外，"
                 "**不判 invalid**（判 invalid 要器件级窗口）" % "、".join(sorted(_derived)))
    elif _derived and vt["verdict"] == "plausible":
        note += ("；窗口是按布局推出来的（%s）：落点在范围内这一条只说明**没落空**，"
                 "不等于按器件手册核过" % "、".join(sorted(_derived)))
    elif _derived:
        note += "；用到的窗口是按布局推出来的（%s）" % "、".join(sorted(_derived))
    value = bool(base_ok and vt["verdict"] != "invalid")
    return {"value": value, "authority": "observed",
            "source": "%s + image.check_vector_table" % w.get("source"),
            # 来源是**交付字节本身**（我们读的是原镜像的前两个字），不是我们重建的产物；
            # 工程首区地址只用来核对「向量表在不在 base 上」，不改变这条证据的来源。
            "source_class": "shipped-artifact",
            "note": note,
            "vector_table": {"addr": "0x%08X" % int(w.get("addr") or 0),
                             "sp": vt["sp_hex"], "reset": vt["reset_hex"],
                             "verdict": vt["verdict"], "checks": vt["checks"]}}

def build_closure_ledger(project_dir: str, image: str = "", base: int = 0, *,
                         verify_json: str = "", arm_bin: str = "",
                         timeout_s: float = 240.0, skip_build: bool = False,
                         via_uvprojx: bool = False, keep_build: bool = True,
                         flash_start: int = 0, flash_size: int = 0,
                         ram_start: int = 0, ram_size: int = 0,
                         claim: str = "") -> dict:
    """对一份 ``recover_project_exact`` 产物出**闭环台账**：哪条义务被什么证据闭合。

    三种取证方式（按证据强度从强到弱）：

    1. 默认：跑 ``verify_project``（armasm+armlink+fromelf 或 UV4），拿到 observed 级证据；
    2. ``verify_json=``：读一份**已保存的** verify 输出（证据复评，不重跑工具链）；
    3. ``skip_build=true``：只盘点材料，不跑任何工具链（这时几乎没有义务能闭合）。

    ``ready=true`` 的含义严格限定为：**这份固件的字节/布局/工具链链路被观察证据闭合**，
    不表示它能跑（``runtime.bootable`` 恒为 unknown，除非另有一次上板观察）。

    ``claim=`` 是**主张等级**（批次89，口径见 REA reconstruction-coverage）：
    ``shipped-artifact`` / ``controlled-replay``（默认）/ ``live-observation`` /
    ``external``。它回答的是「这些证据能不能对外这么讲」——强度够但来源不对时
    ``summary.claim_supported=false`` 并逐条给出理由，绝不把证据改写成合格的样子。
    """
    if claim:
        if claim not in closure.CLAIM_AUTHORITIES:
            return {"ok": False,
                    "error": "未知的主张等级：%s" % claim,
                    "hint": "可选：%s" % "、".join(closure.CLAIM_AUTHORITIES),
                    "claims": {k: {"title": v["title"],
                                   "allowed_sources": v["allowed_sources"],
                                   "min_authority": v["min_authority"]}
                               for k, v in closure.CLAIM_AUTHORITIES.items()}}
    claim = claim or closure.DEFAULT_CLAIM
    dest = os.path.abspath(project_dir)
    man_path = os.path.join(dest, "manifest.json")
    if not os.path.isfile(man_path):
        return {"ok": False,
                "error": "目录里没有 manifest.json：%s" % dest,
                "hint": "台账只针对 recover_project_exact 的产物（有可重链接字节表那份）；"
                        "骨架工程（recover_project）没有可量的字节表"}
    try:
        with open(man_path, "r", encoding="utf-8") as f:
            man = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "manifest.json 读不出来：%s" % exc}

    notes: list = []
    if verify_json:
        p = os.path.abspath(verify_json)
        if not os.path.isfile(p):
            return {"ok": False, "error": "verify_json 不存在：%s" % p}
        try:
            with open(p, "r", encoding="utf-8") as f:
                verify = json.load(f)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": "verify_json 读不出来：%s" % exc}
        if not isinstance(verify, dict):
            return {"ok": False, "error": "verify_json 不是 JSON 对象"}
        evidence_source = "verify_json（复评已保存的证据，未重跑工具链）"
        source_mode = "recorded-replay"
        notes.append("证据来自 %s：本层没有重新取证，结论的强度取决于那次运行" % p)
    elif skip_build:
        verify = {}
        evidence_source = "skip_build（只盘点材料，没跑工具链）"
        source_mode = "no-build"
        notes.append("skip_build=true：没有重链接，所以字节一致/工具链两条义务都开不了")
    else:
        verify = verify_project(dest, image, base=base, arm_bin=arm_bin,
                                timeout_s=timeout_s, keep_build=keep_build,
                                via_uvprojx=via_uvprojx)
        evidence_source = "recover_verify（本次实跑 %s）" % (
            "UV4 -b" if via_uvprojx else "armasm+armlink+fromelf")
        source_mode = "live-run"

    facts = closure.facts_from_verify(verify, manifest=man)
    # 批次91：窗口可以不传——按 manifest（必要时读原镜像 ELF）推，并把「推出来的」
    # 与「调用方给的」分开记，因为前者只是下界，不能拿来判 invalid。
    win = {}
    derived = []
    der = _derive_windows(man, image)
    if flash_start and flash_size:
        win["flash"] = {"start": flash_start, "size": flash_size,
                        "basis": "调用方显式给"}
    elif der["flash"]:
        win["flash"] = der["flash"]
        flash_start, flash_size = der["flash"]["start"], der["flash"]["size"]
        derived.append("flash")
        notes.append("Flash 窗口没显式给，按%s推出 0x%08X+0x%X"
                     % (der["flash"]["basis"], flash_start, flash_size))
    if ram_start and ram_size:
        win["ram"] = {"start": ram_start, "size": ram_size, "basis": "调用方显式给"}
    elif der["ram"]:
        win["ram"] = der["ram"]
        ram_start, ram_size = der["ram"]["start"], der["ram"]["size"]
        derived.append("ram")
        notes.append("RAM 窗口没显式给，按%s推出 0x%08X+0x%X"
                     % (der["ram"]["basis"], ram_start, ram_size))
    if not der["ram"]:
        notes.extend(n for n in der["notes"] if n not in notes)
    ram = (ram_start, ram_start + ram_size - 1) if (ram_start and ram_size) else None
    flash = ((flash_start, flash_start + flash_size - 1)
             if (flash_start and flash_size) else None)
    vf = _vector_entry_fact(dest, image, base, man, ram=ram, flash=flash,
                            derived_windows=tuple(derived))
    if vf is not None:
        facts["vector.entry"] = vf
    led = closure.evaluate(facts, claim=claim, source_mode=source_mode)

    out = dict(led)
    out.update({
        "ok": True,
        "ready": led["summary"]["ready"],
        "project_dir": dest,
        "image": os.path.abspath(image) if image else "",
        "manifest": {"path": man_path, "digest": sha256_file(man_path),
                     "name": man.get("name"), "format": man.get("format"),
                     "input": man.get("input"),
                     "base": "0x%08X" % _manifest_chunk0(man)},
        "evidence_source": evidence_source,
        "claim": claim,
        "windows": {"flash": ({"start": "0x%08X" % win["flash"]["start"],
                               "size": "0x%X" % win["flash"]["size"],
                               "basis": win["flash"]["basis"]}
                              if win.get("flash") else None),
                    "ram": ({"start": "0x%08X" % win["ram"]["start"],
                             "size": "0x%X" % win["ram"]["size"],
                             "basis": win["ram"]["basis"]}
                            if win.get("ram") else None),
                    "derived": derived,
                    "note": ("推出来的窗口是下界（我们手上这些字节/节的范围），只用来把"
                             "判据从 unverified 抬到 plausible；判 invalid 必须给器件级窗口"
                             if derived else "窗口由调用方给")},
        "verify": {
            "ok": verify.get("ok"),
            "byte_identical": (verify.get("diff") or {}).get("byte_identical"),
            "failed_step": verify.get("failed_step"),
            "expected_source": verify.get("expected_source"),
            "via": (verify.get("build") or {}).get("via"),
            "error": verify.get("error"),
            "hint": verify.get("hint"),
            "steps": [{"step": s.get("step"), "ok": s.get("ok")}
                      for s in (verify.get("steps") or [])],
        },
        "notes": notes + (verify.get("notes") or [])[:4],
    })
    out["limitations"] = led["limitations"] + ([] if not derived else [
        "窗口 %s 是按布局推出来的下界（不是器件手册上的容量）：落在外面记未核，不判 invalid"
        % "、".join(sorted(derived))]) + [
        "台账里的 authority 由采集它的那一层判定（verify/manifest/本层读字节）；"
        "本层只做一致性聚合，不额外取证",
    ]
    return out
