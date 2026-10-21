"""containers —— 多容器识别与解析，零新增依赖。批次85。

吸收的是 Ghidra **加载器（loader）**的口径：一份「镜像」不一定是 ELF，工程里常见的还有
PE/COFF（Windows 侧 .exe/.dll/.obj）、Mach-O（macOS 侧 .dylib/.o）、S-record（很多
烧写器只认这种）。这些格式的**字段位置是固定的**，``struct`` 足够——不需要任何新依赖。

设计上只做一件事：**把别家容器翻译成 ELF 形状的中性描述**。
``parse_pe`` / ``parse_coff`` / ``parse_macho`` 返回的字典与 ``recover.parse_elf`` 同构
（``ok/class/endian/relocatable/type/machine_id/machine/entry/sections/symbols/segments``），
这样 ``Unit`` / ``arch_of`` / ``symbol_table`` / 交叉引用 / 伪 C 全部不需要改。

三条纪律（全项目一致）：

- **识别要看证据**：``detect`` 返回 ``(kind, evidence)``，写清「凭哪几个字节判成这个」；
  光凭扩展名不算证据。
- **解析不了要说清为什么**（``{"ok": False, "error": ...}``），不返回空表冒充「没有内容」。
- **地址空间不混用**：可重定位目标（COFF ``.obj``）的符号值是**节内偏移**，
  一律 ``relocatable=True`` 并写进 limitations；它不能拿去出工程（会被上层拒掉）。
"""

import struct

# ----------------------------------------------------------------------
# 识别
# ----------------------------------------------------------------------
_FAT_MAGIC = (0xCAFEBABE, 0xCAFEBABF)
_MACHO_MAGIC = {
    0xFEEDFACE: (32, "big"),
    0xFEEDFACF: (64, "big"),
    0xCEFAEDFE: (32, "little"),
    0xCFFAEDFE: (64, "little"),
}

_COFF_MACHINE = {
    0x014C: ("x86", "i386"),
    0x8664: ("x86_64", "amd64"),
    0x01C0: ("arm", "ARM"),
    0x01C2: ("arm", "THUMB"),
    0x01C4: ("arm", "ARMNT"),
    0xAA64: ("arm64", "ARM64"),
    0x0162: ("mips", "R3000"),
    0x0166: ("mips", "MIPS16"),
    0x0168: ("mips", "R4000"),
    0x0169: ("mips", "R10000"),
    0x0266: ("mips", "MIPS16-fpu"),
    0x0366: ("mips", "MIPS-fpu"),
    0x0466: ("mips", "MIPS-fpu16"),
    0x01F0: ("ppc", "POWERPC"),
    0x01F1: ("ppc", "POWERPCFP"),
    0x01A2: ("unknown", "SH3"),
    0x01A3: ("unknown", "SH3DSP"),
    0x01A4: ("unknown", "SH3E"),
    0x01A6: ("unknown", "SH4"),
    0x01A8: ("unknown", "SH5"),
    0x5032: ("riscv", "RISCV32"),
    0x5064: ("riscv", "RISCV64"),
    0x5128: ("riscv", "RISCV128"),
}

_MACHO_CPU = {
    7: ("x86", "i386"),
    0x01000007: ("x86_64", "x86_64"),
    12: ("arm", "ARM"),
    0x0100000C: ("arm64", "arm64"),
    8: ("mips", "MIPS"),
    18: ("ppc", "PPC"),
    0x01000012: ("ppc", "PPC64"),
    6: ("m68k", "MC680x0"),
    14: ("sparc", "SPARC"),
}

# 这些 family 的 capstone 后端存在；不在表里的明确报「不支持」，不猜
CAPSTONE_FAMILIES = ("arm", "arm64", "riscv", "x86", "x86_64", "mips", "ppc",
                     "m68k", "sparc", "mos65xx")


def detect(head: bytes, name: str = "") -> tuple:
    """``(kind, evidence)``。kind ∈ elf / ar / ihex / srec / pe / coff / macho / bin。

    ``name`` 只用来**否定**（扩展名说 .bin 但内容是 ELF 时以字节为准），
    不用来肯定任何一个结论。
    """
    h = head or b""
    if h.startswith(b"\x7fELF"):
        return "elf", "前 4 字节 7F 45 4C 46（ELF magic）"
    if h.startswith(b"!<arch>\n"):
        return "ar", "前 8 字节 !<arch>（ar 归档）"
    if len(h) >= 0x40 and h[:2] == b"MZ":
        e_lfanew = struct.unpack("<I", h[0x3C:0x40])[0]
        if 0 <= e_lfanew < (1 << 20):
            return "pe", ("DOS 头 MZ + e_lfanew=0x%X（PE 特征；"
                          "偏移处的 PE\\0\\0 需按整个文件复核）" % e_lfanew)
    if len(h) >= 4:
        magic = struct.unpack(">I", h[:4])[0]
        if magic in _FAT_MAGIC:
            return "macho", "前 4 字节 CA FE BA BE（Mach-O fat/universal）"
        if magic in _MACHO_MAGIC:
            bits, endian = _MACHO_MAGIC[magic]
            return "macho", ("前 4 字节 %08X（Mach-O %d 位，%s 端）"
                             % (magic, bits, endian))
    text = h[:4096].decode("latin-1", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines:
        hexish = sum(1 for ln in lines if ln.startswith(":"))
        if hexish >= max(1, len(lines) // 2):
            return "ihex", "%d/%d 行以 : 开头（Intel HEX 记录）" % (hexish, len(lines))
        sr = sum(1 for ln in lines if ln[:2] in ("S0", "S1", "S2", "S3", "S5",
                                                 "S6", "S7", "S8", "S9"))
        if sr >= max(1, len(lines) // 2):
            return "srec", "%d/%d 行以 S<digit> 开头（Motorola S-record）" % (sr, len(lines))
    kind = _guess_coff(head)
    if kind:
        return "coff", kind
    return "bin", "没有任何已知容器特征头，按扁平二进制处理"


def _guess_coff(head: bytes) -> str:
    """COFF 没有 magic，只能「结构自洽」判：机器码已知 + 可选头长为 0 + 表在文件内。

    这是**启发式**，所以要求四条同时成立，并把判据原样返回给调用方。
    """
    if len(head) < 20:
        return ""
    machine, nsec, _ts, symptr, nsym, optsz, _ch = struct.unpack("<HHIIIHH", head[:20])
    if machine not in _COFF_MACHINE:
        return ""
    if optsz != 0:
        return ""
    if not (1 <= nsec <= 96):
        return ""
    if nsym and not (20 < symptr < (1 << 32)):
        return ""
    return ("机器码 0x%04X（%s）+ 可选头长 0 + %d 个节 + 符号表偏移 0x%X："
            "符合 COFF 目标文件特征" % (machine, _COFF_MACHINE[machine][1], nsec, symptr))


# family -> (bits, endian, thumb)。**调用方显式指定架构**时用的默认值：
# raw bin / 无头容器必须显式给架构（这是 REA 的一条硬口径：没头就别猜）。
_ARCH_DEFAULTS = {
    "x86": (32, "little", False), "x86_64": (64, "little", False),
    "arm": (32, "little", True), "arm64": (64, "little", False),
    "riscv": (32, "little", False), "mips": (32, "little", False),
    "ppc": (32, "big", False), "m68k": (32, "big", False),
    "sparc": (32, "big", False), "mos65xx": (16, "little", False),
    "sh": (32, "little", False), "s390": (32, "big", False),
}


def arch_defaults(name: str):
    """``"x86_64"`` → ``(64, "little", False)``；不认识的返回 None（不猜）。"""
    return _ARCH_DEFAULTS.get((name or "").strip().lower())


def arch_from_name(name: str, *, bits: int = 0, endian: str = "",
                   thumb=None) -> dict:
    """把调用方指定的架构名变成 ``Unit.arch`` 形状。名字不认识就**报错**。"""
    fam = (name or "").strip().lower()
    d = _ARCH_DEFAULTS.get(fam)
    if not d:
        return {"ok": False,
                "error": "不认识的架构名：%r（可用：%s）"
                         % (name, " / ".join(sorted(_ARCH_DEFAULTS)))}
    dbits, dend, dthumb = d
    b = int(bits or dbits)
    e = (endian or dend).strip().lower()
    if e not in ("little", "big"):
        return {"ok": False, "error": "endian 只能是 little / big：%r" % endian}
    th = dthumb if thumb is None else bool(thumb)
    return {"ok": True, "arch": {
        "family": fam, "bits": b, "endian": e,
        "thumb": th if fam == "arm" else False,
        "supported": fam in CAPSTONE_FAMILIES,
        "why": "由调用方显式指定（不是从文件头读的）：%s / %d 位 / %s%s"
               % (fam, b, e, " / Thumb" if (fam == "arm" and th) else ""),
        "basis": "explicit",
    }}


def kind_needs_elf(kind: str) -> bool:
    return kind in ("elf", "pe", "coff", "macho")


# ----------------------------------------------------------------------
# 中性的「ELF 形状」字典
# ----------------------------------------------------------------------
def _blank_neutral(kind: str, bits: int, endian: str) -> dict:
    return {"ok": True, "container": kind, "class": bits, "endian": endian,
            "relocatable": False, "type": kind.upper(), "type_id": 0,
            "machine_id": 0, "machine": "", "entry": 0, "flags": 0,
            "family": "unknown", "segments": [], "sections": [], "symbols": [],
            "image_base": 0, "notes": []}


def _section(name, addr, size, offset, exec_, writable, alloc, type_name="PROGBITS"):
    return {"name": name, "addr": int(addr), "size": int(size),
            "offset": int(offset), "exec": bool(exec_),
            "writable": bool(writable), "alloc": bool(alloc),
            "type_name": type_name, "type": 0, "flags": 0}


# ----------------------------------------------------------------------
# PE / PE32+
# ----------------------------------------------------------------------
_SCN_CNT_CODE = 0x00000020
_SCN_CNT_UNINIT = 0x00000080
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_WRITE = 0x80000000
_SCN_MEM_READ = 0x40000000


def parse_pe(data: bytes) -> dict:
    """PE32 / PE32+（.exe/.dll/.sys）。地址一律换成 **VA = ImageBase + RVA**。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "error": "不是 PE（缺 MZ 头）"}
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"ok": False,
                "error": "MZ 头之后 0x%X 处没有 PE\\0\\0 签名（不是 PE，或文件被截断）"
                         % e_lfanew}
    coff = e_lfanew + 4
    machine, nsec, _ts, symptr, nsym, optsz, ch = struct.unpack(
        "<HHIIIHH", data[coff:coff + 20])
    if not (1 <= nsec <= 96):
        return {"ok": False, "error": "节数量 %d 不合理（1..96）" % nsec}
    opt = coff + 20
    if optsz < 2 or opt + optsz > len(data):
        return {"ok": False, "error": "可选头长度 %d 越界（PE 必须有可选头）" % optsz}
    magic = struct.unpack("<H", data[opt:opt + 2])[0]
    if magic == 0x10B:
        bits = 32
        image_base = struct.unpack("<I", data[opt + 28:opt + 32])[0]
    elif magic == 0x20B:
        bits = 64
        image_base = struct.unpack("<Q", data[opt + 24:opt + 32])[0]
    else:
        return {"ok": False, "error": "可选头 magic=0x%X 不是 PE32/PE32+" % magic}
    entry_rva = struct.unpack("<I", data[opt + 16:opt + 20])[0]
    size_of_headers = struct.unpack("<I", data[opt + 60:opt + 64])[0]

    fam, mach_name = _COFF_MACHINE.get(machine, ("unknown", "0x%04X" % machine))
    out = _blank_neutral("pe", bits, "little")
    out.update({"machine_id": machine, "machine": mach_name, "family": fam,
                "entry": image_base + entry_rva, "image_base": image_base,
                "type": "DLL" if (ch & 0x2000) else "EXE",
                "type_id": 2, "characteristics": ch,
                "relocatable": False})
    secs = []
    base = opt + optsz
    for i in range(nsec):
        b = data[base + i * 40: base + (i + 1) * 40]
        if len(b) < 40:
            return {"ok": False, "error": "节表在第 %d 项处被截断" % i}
        raw_name = b[:8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", b[8:24])
        chars = struct.unpack("<I", b[36:40])[0]
        size = rawsize or vsize
        secs.append(_section(
            raw_name or ("sec%d" % i), image_base + vaddr, size, rawptr,
            exec_=bool(chars & _SCN_MEM_EXECUTE) or bool(chars & _SCN_CNT_CODE),
            writable=bool(chars & _SCN_MEM_WRITE),
            alloc=bool(chars & (_SCN_MEM_READ | _SCN_MEM_EXECUTE | _SCN_MEM_WRITE)),
            type_name="NOBITS" if (chars & _SCN_CNT_UNINIT and not rawsize) else "PROGBITS"))
    out["sections"] = secs
    # 段视图：PE 的「段」就是节；给一份与 ELF segments 同形的表，供复刻层复用
    out["segments"] = [{"type": 1, "offset": s["offset"], "vaddr": s["addr"],
                        "paddr": s["addr"], "filesz": s["size"],
                        "memsz": s["size"],
                        "flags": (1 if s["exec"] else 0) | (2 if s["writable"] else 0)}
                       for s in secs if s["offset"] and s["size"]]

    syms = _pe_coff_symbols(data, symptr, nsym, secs, image_base)
    exp = _pe_exports(data, opt, optsz, image_base, secs, size_of_headers)
    for name, va in exp["names"]:
        syms.append({"name": name, "value": va, "size": 0, "type": "FUNC",
                     "bind": "GLOBAL", "shndx": 0, "source": "export"})
    out["symbols"] = syms
    if not syms:
        out["notes"].append("没有符号表也没有导出表：函数只能靠向量表/调用目标/token 找，"
                            "「observed」这一档会是空的")
    if exp.get("error"):
        out["notes"].append(exp["error"])
    out["notes"].append("PE 的地址是 ImageBase(0x%X)+RVA；ImageBase 与真实加载基址"
                        "（ASLR/重定位）可能不同" % image_base)
    return out


def _pe_coff_symbols(data, symptr, nsym, secs, image_base) -> list:
    """COFF 符号表（链接期保留时才在；值 = 节内偏移，要加上该节 VA）。"""
    if not symptr or not nsym or symptr + 18 > len(data):
        return []
    strtab = symptr + nsym * 18
    out = []
    i = 0
    while i < nsym:
        off = symptr + i * 18
        b = data[off:off + 18]
        if len(b) < 18:
            break
        name_raw, value, secnum, typ, sclass, naux = struct.unpack("<8sIhHBB", b)
        if name_raw[:4] == b"\x00\x00\x00\x00":
            so = struct.unpack("<I", name_raw[4:8])[0]
            name = _cstr_at(data, strtab + so) if so else ""
        else:
            name = name_raw.rstrip(b"\x00").decode("latin-1", "replace")
        i += 1 + naux
        if not name or sclass not in (2, 105, 3):   # EXTERNAL / STATIC / FUNCTION
            continue
        if secnum <= 0:      # UNDEF / ABS / DEBUG
            continue
        sec = secs[secnum - 1] if secnum - 1 < len(secs) else None
        va = (sec["addr"] + value) if sec else value
        if not sec or not sec["exec"]:
            if not (typ & 0x20):    # 不是函数就跳过（PE 里数据符号没有价值）
                continue
        out.append({"name": name, "value": va, "size": 0,
                    "type": "FUNC" if (typ & 0x20) or (sec and sec["exec"]) else "OBJECT",
                    "bind": "GLOBAL" if sclass in (2, 105) else "LOCAL",
                    "shndx": secnum, "source": "coff"})
    return out


def _pe_exports(data, opt, optsz, image_base, secs, headers) -> dict:
    """导出表：**observed** 级函数名的唯一来源（DLL/带导出 EXE）。

    数据目录的起点在 PE32 与 PE32+ 里**不是一个数**：PE32 是可选头内偏移 96，
    PE32+ 是 112（标准字段少 4 字节、ImageBase 多 4 字节）。按一个数读，
    在另一半上会读到整块的错误 RVA，然后表现为「没有导出」。
    """
    magic = struct.unpack("<H", data[opt:opt + 2])[0] if optsz >= 2 else 0
    dirs = 96 if magic == 0x10B else 112
    if optsz < dirs + 8:
        return {"names": []}
    nrva = struct.unpack("<I", data[opt + dirs:opt + dirs + 4])[0]
    if not nrva:
        return {"names": []}

    def at(rva):
        va = image_base + rva
        for s in secs:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        if 0 <= rva < headers:
            return rva
        return None

    eoff = at(nrva)
    if eoff is None or eoff + 40 > len(data):
        return {"names": [], "error": "导出目录 RVA 0x%X 无法映射到文件" % nrva}
    nfunc, nname = struct.unpack("<II", data[eoff + 20: eoff + 28])
    aof, aon, aoo = struct.unpack("<III", data[eoff + 28: eoff + 40])
    foff, noff, ooff = at(aof), at(aon), at(aoo)
    if None in (foff, noff, ooff):
        return {"names": [], "error": "导出表的三张子表有 RVA 落不进任何节"}
    names = []
    for i in range(min(nname, 20000)):
        nb = data[noff + i * 4: noff + i * 4 + 4]
        ob = data[ooff + i * 2: ooff + i * 2 + 2]
        if len(nb) < 4 or len(ob) < 2:
            break
        name = _cstr_at(data, at(struct.unpack("<I", nb)[0]) or 0)
        idx = struct.unpack("<H", ob)[0]
        fb = data[foff + idx * 4: foff + idx * 4 + 4]
        if not name or len(fb) < 4 or idx >= nfunc:
            continue
        rva = struct.unpack("<I", fb)[0]
        if rva:
            names.append((name, image_base + rva))
    return {"names": names}


def _cstr_at(data: bytes, off: int) -> str:
    if off <= 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = min(len(data), off + 256)
    return data[off:end].decode("latin-1", "replace")


# ----------------------------------------------------------------------
# COFF 目标文件（.obj）
# ----------------------------------------------------------------------
def parse_coff(data: bytes) -> dict:
    """MS COFF 目标文件：``relocatable=True``，符号值是**节内偏移**。"""
    why = _guess_coff(data[:4096])
    if not why:
        return {"ok": False, "error": "不是 COFF 目标文件（机器码/节数/可选头长不自洽）"}
    machine, nsec, _ts, symptr, nsym, _optsz, _ch = struct.unpack("<HHIIIHH", data[:20])
    fam, mach_name = _COFF_MACHINE[machine]
    out = _blank_neutral("coff", 32, "little")
    out.update({"machine_id": machine, "machine": mach_name, "family": fam,
                "relocatable": True, "type": "REL", "type_id": 1})
    if fam in ("x86_64", "arm64"):
        out["class"] = 64
    secs = []
    base = 20
    # 字符串表紧跟符号表之后（符号表位置由头部给出，节表之后可能有节数据/填充，
    # 所以「20 + nsec*40」只是**通常**成立——以 symptr 为准）
    strtab = (symptr + nsym * 18) if (symptr and nsym) else (20 + nsec * 40)
    for i in range(nsec):
        b = data[base + i * 40: base + (i + 1) * 40]
        if len(b) < 40:
            return {"ok": False, "error": "节表在第 %d 项处被截断" % i}
        raw_name = b[:8].rstrip(b"\x00").decode("latin-1", "replace")
        if raw_name.startswith("/") and raw_name[1:].isdigit():
            raw_name = _cstr_at(data, strtab + int(raw_name[1:])) or raw_name
        vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", b[8:24])
        chars = struct.unpack("<I", b[36:40])[0]
        # 可重定位目标里 addr 就是节内偏移（vaddr 通常为 0），保留原值
        secs.append(_section(raw_name, vaddr, rawsize or vsize, rawptr,
                             exec_=bool(chars & _SCN_MEM_EXECUTE) or
                             bool(chars & _SCN_CNT_CODE),
                             writable=bool(chars & _SCN_MEM_WRITE),
                             alloc=True,
                             type_name="NOBITS" if (chars & _SCN_CNT_UNINIT
                                                    and not rawsize) else "PROGBITS"))
    out["sections"] = secs
    out["segments"] = [{"type": 1, "offset": s["offset"], "vaddr": s["addr"],
                        "paddr": s["addr"], "filesz": s["size"], "memsz": s["size"],
                        "flags": 1 if s["exec"] else 0}
                       for s in secs if s["offset"] and s["size"]]
    syms = []
    if symptr and nsym:
        i = 0
        while i < nsym:
            b = data[symptr + i * 18: symptr + (i + 1) * 18]
            if len(b) < 18:
                break
            name_raw, value, secnum, typ, sclass, naux = struct.unpack("<8sIhHBB", b)
            if name_raw[:4] == b"\x00\x00\x00\x00":
                so = struct.unpack("<I", name_raw[4:8])[0]
                name = _cstr_at(data, strtab + so) if so else ""
            else:
                name = name_raw.rstrip(b"\x00").decode("latin-1", "replace")
            i += 1 + naux
            if not name or sclass not in (2, 105, 3) or secnum <= 0:
                continue
            sec = secs[secnum - 1] if secnum - 1 < len(secs) else None
            isfunc = bool(typ & 0x20) or bool(sec and sec["exec"])
            if not isfunc:
                continue
            syms.append({"name": name, "value": value, "size": 0, "type": "FUNC",
                         "bind": "GLOBAL" if sclass in (2, 105) else "LOCAL",
                         "shndx": secnum, "source": "coff"})
    out["symbols"] = syms
    out["notes"].append("COFF 目标文件：符号值是**节内偏移**，不是最终地址——先在 Keil 里"
                        "链接成 axf 再出工程；这里只做逐节看指令")
    return out


# ----------------------------------------------------------------------
# Mach-O（thin + fat）
# ----------------------------------------------------------------------
def parse_macho(data: bytes) -> dict:
    """Mach-O 32/64、小端/大端；fat 包取第一个切片并如实说明。"""
    if len(data) < 4:
        return {"ok": False, "error": "文件短于 4 字节"}
    magic = struct.unpack(">I", data[:4])[0]
    notes = []
    if magic in _FAT_MAGIC:
        nfat = struct.unpack(">I", data[4:8])[0] if len(data) >= 8 else 0
        if not (1 <= nfat <= 64) or len(data) < 8 + nfat * 20:
            return {"ok": False, "error": "fat 头里的切片数 %d 与文件长度不符" % nfat}
        slices = []
        for i in range(nfat):
            cpu, sub, off, size, align = struct.unpack(
                ">IIIII", data[8 + i * 20: 8 + (i + 1) * 20])
            slices.append({"cputype": cpu, "cpusubtype": sub, "offset": off,
                           "size": size, "align": align})
        pick = slices[0]
        notes.append("这是 fat（通用）二进制，共 %d 个切片：%s；本次只解析第一个"
                     % (nfat, ", ".join("%s" % (_MACHO_CPU.get(s["cputype"],
                                                              ("?", hex(s["cputype"])))[1])
                                        for s in slices)))
        if pick["offset"] + pick["size"] > len(data):
            return {"ok": False, "error": "fat 第一个切片越过文件末尾"}
        inner = data[pick["offset"]: pick["offset"] + pick["size"]]
        out = parse_macho(inner)
        if out.get("ok"):
            out.setdefault("notes", [])
            out["notes"] = notes + out["notes"]
            out["fat_slices"] = slices
            for s in out.get("segments", []):
                s["offset"] += pick["offset"]
            for s in out.get("sections", []):
                s["offset"] += pick["offset"]
        return out
    if magic not in _MACHO_MAGIC:
        return {"ok": False, "error": "前 4 字节 %08X 不是 Mach-O magic" % magic}
    bits, endian = _MACHO_MAGIC[magic]
    e = "<" if endian == "little" else ">"
    hdr = 28 if bits == 32 else 32
    if len(data) < hdr:
        return {"ok": False, "error": "Mach-O 头不完整"}
    _m, cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack(
        e + "IIIIIII", data[:28])
    fam, mach_name = _MACHO_CPU.get(cputype, ("unknown", "cpu_0x%X" % cputype))
    out = _blank_neutral("macho", bits, endian)
    out.update({"machine_id": cputype, "machine": mach_name, "family": fam,
                "type_id": filetype,
                "type": {1: "REL", 2: "EXEC", 6: "DYN"}.get(filetype,
                                                            "filetype_%d" % filetype),
                "relocatable": filetype == 1, "notes": notes})
    off = hdr
    text_vm = None
    symtab = None
    for _ in range(min(ncmds, 4096)):
        if off + 8 > len(data):
            return {"ok": False, "error": "load command 在 0x%X 处被截断" % off}
        cmd, size = struct.unpack(e + "II", data[off:off + 8])
        if size < 8 or off + size > len(data):
            return {"ok": False, "error": "load command 长度 %d 越界（cmd=0x%X）"
                                          % (size, cmd)}
        body = data[off + 8: off + size]
        if cmd in (0x1, 0x19):          # LC_SEGMENT / LC_SEGMENT_64
            if bits == 32 and len(body) >= 56:
                segname = body[:16].rstrip(b"\x00").decode("latin-1", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack(e + "IIII", body[16:32])
                maxprot, initprot, nsects, _sf = struct.unpack(e + "IIII", body[32:48])
                out["segments"].append({
                    "type": 1, "offset": int(fileoff), "vaddr": int(vmaddr),
                    "paddr": int(vmaddr), "filesz": int(filesize),
                    "memsz": int(vmsize),
                    "flags": (1 if initprot & 0x4 else 0) | (2 if initprot & 0x2 else 0),
                    "name": segname})
                if segname == "__TEXT" and text_vm is None:
                    text_vm = int(vmaddr)
                sbase = 48
                for i in range(nsects):
                    b = body[sbase + i * 68: sbase + (i + 1) * 68]
                    if len(b) < 68:
                        break
                    out["sections"].append(_macho_section(b, e, 32, int(vmaddr)))
            elif bits == 64 and len(body) >= 64:
                segname = body[:16].rstrip(b"\x00").decode("latin-1", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack(e + "QQQQ", body[16:48])
                maxprot, initprot, nsects, _sf = struct.unpack(e + "IIII", body[48:64])
                out["segments"].append({
                    "type": 1, "offset": int(fileoff), "vaddr": int(vmaddr),
                    "paddr": int(vmaddr), "filesz": int(filesize),
                    "memsz": int(vmsize),
                    "flags": (1 if initprot & 0x4 else 0) | (2 if initprot & 0x2 else 0),
                    "name": segname})
                if segname == "__TEXT" and text_vm is None:
                    text_vm = int(vmaddr)
                sbase = 64
                for i in range(nsects):
                    b = body[sbase + i * 80: sbase + (i + 1) * 80]
                    if len(b) < 80:
                        break
                    out["sections"].append(_macho_section(b, e, 64, int(vmaddr)))
        elif cmd == 0x2:                # LC_SYMTAB
            if len(body) >= 16:
                symtab = struct.unpack(e + "IIII", body[:16])
        elif cmd == 0x28:               # LC_MAIN
            if len(body) >= 8:
                entryoff = struct.unpack(e + "Q", body[:8])[0]
                if text_vm is not None:
                    out["entry"] = text_vm + int(entryoff)
                    out["notes"].append("入口来自 LC_MAIN（__TEXT 起始 + 0x%X）" % entryoff)
        off += size
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        out["symbols"] = _macho_symbols(data, e, bits, symoff, nsyms, stroff, strsize)
    if not out["symbols"]:
        out["notes"].append("没有 LC_SYMTAB 或符号全被剥：函数只能靠调用目标/向量表找")
    return out


def _macho_section(b, e, bits, seg_vm) -> dict:
    name = b[:16].rstrip(b"\x00").decode("latin-1", "replace")
    if bits == 32:
        addr, size, offset, align, reloff, nreloc, flags = struct.unpack(e + "IIIIIII", b[32:60])
    else:
        addr, size, offset = struct.unpack(e + "QQI", b[32:52])
        align, reloff, nreloc, flags = struct.unpack(e + "IIII", b[52:68])
    exec_ = bool(flags & 0x80000000) or bool(flags & 0x00000400)
    return _section(name, addr, size, offset, exec_,
                    writable=not exec_, alloc=True)


def _macho_symbols(data, e, bits, symoff, nsyms, stroff, strsize) -> list:
    out = []
    ent = 12 if bits == 32 else 16
    strblob = data[stroff: stroff + strsize] if strsize else b""
    for i in range(min(nsyms, 200000)):
        b = data[symoff + i * ent: symoff + (i + 1) * ent]
        if len(b) < ent:
            break
        strx = struct.unpack(e + "I", b[:4])[0]
        ntype, nsect, _desc = struct.unpack(e + "BBH", b[4:8])
        value = struct.unpack(e + ("I" if bits == 32 else "Q"), b[8:ent])[0]
        if ntype & 0xE0:            # N_STAB 调试符号
            continue
        if (ntype & 0x0E) != 0x0E:  # N_SECT：已定义
            continue
        name = strblob[strx:strblob.find(b"\x00", strx)].decode("latin-1", "replace") \
            if strx < len(strblob) else ""
        if not name:
            continue
        out.append({"name": name, "value": int(value), "size": 0, "type": "FUNC",
                    "bind": "GLOBAL" if (ntype & 0x01) else "LOCAL",
                    "shndx": nsect, "source": "symtab"})
    return out


# ----------------------------------------------------------------------
# Motorola S-record
# ----------------------------------------------------------------------
def parse_srec(text: str) -> dict:
    """S-record：S1/S2/S3 是数据（16/24/32 位地址），S7/S8/S9 给入口地址。"""
    out = {"ok": True, "records": 0, "data_records": 0, "data_bytes": 0,
           "lines_malformed": [], "checksum_errors": [], "entry": None,
           "min_addr": None, "max_addr": 0, "chunks": []}
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        if s[0] not in "Ss" or len(s) < 4:
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "不是 S 记录"})
            continue
        kind = s[1]
        out["records"] += 1
        try:
            raw = bytes.fromhex(s[2:])
        except ValueError:
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno, "reason": "非十六进制字符"})
            continue
        if len(raw) < 2 or raw[0] != len(raw) - 1:
            if len(out["lines_malformed"]) < 5:
                out["lines_malformed"].append({"line": lineno,
                                               "reason": "长度字段与记录不符"})
            continue
        if (sum(raw[:-1]) + raw[-1]) & 0xFF != 0xFF:
            if len(out["checksum_errors"]) < 5:
                out["checksum_errors"].append({"line": lineno})
            continue
        body = raw[1:-1]
        if kind in "123":
            alen = {"1": 2, "2": 3, "3": 4}[kind]
            if len(body) < alen:
                continue
            addr = int.from_bytes(body[:alen], "big")
            payload = body[alen:]
            out["data_records"] += 1
            out["data_bytes"] += len(payload)
            out["chunks"].append((addr, payload))
            out["min_addr"] = addr if out["min_addr"] is None else min(out["min_addr"], addr)
            out["max_addr"] = max(out["max_addr"], addr + len(payload))
        elif kind in "789":
            alen = {"7": 4, "8": 3, "9": 2}[kind]
            if len(body) >= alen:
                out["entry"] = int.from_bytes(body[:alen], "big")
        elif kind in "56":
            out["count_records"] = out.get("count_records", 0) + 1   # S5/S6：记录条数，不是数据
    return out


def srec_flat(text: str, base: int = 0) -> dict:
    """S-record → ``{"ok", "data", "base", "srec"}``（与 hex 的扁平化同形）。"""
    info = parse_srec(text)
    if not info["chunks"]:
        return {"ok": False, "error": "S-record 里没有数据记录（S1/S2/S3）"}
    lo = info["min_addr"] or 0
    hi = info["max_addr"] or 0
    if hi - lo > (1 << 26):
        return {"ok": False, "error": "S-record 覆盖 0x%X 字节，超出上限" % (hi - lo)}
    buf = bytearray(hi - lo)
    seen = bytearray(hi - lo)
    for addr, payload in info["chunks"]:
        for i, byte in enumerate(payload):
            if 0 <= addr - lo + i < len(buf):
                buf[addr - lo + i] = byte
                seen[addr - lo + i] = 1
    info["gap_bytes"] = seen.count(0)
    return {"ok": True, "data": bytes(buf), "base": lo + int(base or 0), "srec": info}
