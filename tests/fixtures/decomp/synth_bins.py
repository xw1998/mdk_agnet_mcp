"""synth_bins —— 按**规范逐字段构造**的最小 PE / COFF / Mach-O 夹具。

为什么要自己造：这几种容器在本机没有可用的编译器（没有 MSVC，也没有 Mach-O 工具链）。
与其把某个系统 DLL 拷进仓库（授权不清、还会随系统版本变），不如按格式规范逐字段写出
最小合法文件——**每一个字节都能在测试里指名道姓**。

诚实的边界：这些夹具证明的是「解析器按规范读字段」，不证明「能解析真实世界的所有变体」；
真实 PE 的额外验证在测试里用一条**可选冒烟**（本机 System32 里的 DLL）承担，那条只断言
结构不变量，不断言具体字节。
"""

import struct


# ----------------------------------------------------------------------
# PE32+
# ----------------------------------------------------------------------
def make_pe() -> bytes:
    """PE32+ / x86_64：2 个节、1 个导出（func_a）、1 个 COFF 符号（coff_sym）。"""
    image_base = 0x140000000
    e_lfanew = 0x80
    nsec = 2
    opt_sz = 0xF0
    sec_tab = e_lfanew + 4 + 20 + opt_sz          # 0x80+4+20+0xF0 = 0x188
    text_ptr, text_sz = 0x400, 0x200
    rdata_ptr, rdata_sz = 0x600, 0x200
    sym_ptr, n_sym = 0x800, 1

    f = bytearray(0x1000)
    # ---- DOS 头 ----
    f[0:2] = b"MZ"
    struct.pack_into("<I", f, 0x3C, e_lfanew)
    # ---- PE 签名 + COFF 头 ----
    f[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    struct.pack_into("<HHIIIHH", f, coff,
                     0x8664, nsec, 0, sym_ptr, n_sym, opt_sz, 0x0022)
    # ---- 可选头（PE32+）----
    opt = coff + 20
    struct.pack_into("<H", f, opt, 0x20B)
    struct.pack_into("<I", f, opt + 16, 0x1000)     # AddressOfEntryPoint
    struct.pack_into("<Q", f, opt + 24, image_base)  # ImageBase
    struct.pack_into("<I", f, opt + 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", f, opt + 36, 0x200)       # FileAlignment
    struct.pack_into("<I", f, opt + 56, 0x2000)      # SizeOfImage
    struct.pack_into("<I", f, opt + 60, 0x400)       # SizeOfHeaders
    struct.pack_into("<H", f, opt + 68, 3)           # Subsystem (CUI)
    struct.pack_into("<I", f, opt + 108, 16)         # NumberOfRvaAndSizes
    struct.pack_into("<I", f, opt + 112, 0x2000)     # DataDirectory[0] = 导出表 RVA
    # ---- 节表 ----
    f[sec_tab:sec_tab + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", f, sec_tab + 8, 0x180, 0x1000, text_sz, text_ptr)
    struct.pack_into("<I", f, sec_tab + 36, 0x60000020)   # CODE|EXECUTE|READ
    s2 = sec_tab + 40
    f[s2:s2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", f, s2 + 8, 0x200, 0x2000, rdata_sz, rdata_ptr)
    struct.pack_into("<I", f, s2 + 36, 0x40000040)        # INITIALIZED_DATA|READ

    # ---- .text：两条 ret 模样的指令（内容不重要，重要的是地址与可执行性）----
    f[text_ptr:text_ptr + 4] = b"\xC3\x90\xC3\x90"        # ret; nop; ret; nop

    # ---- .rdata：导出目录 + 三张子表 + 名字 ----
    base = rdata_ptr
    dir_rva = 0x2000
    # 导出目录 40 字节
    struct.pack_into("<IIHHIIIIIII", f, base,
                     0, 0, 0, 0, 0x2040, 1,        # Name RVA, Base
                     2, 1,                          # NumberOfFunctions/Names
                     0x2028, 0x2030, 0x2038)        # Functions/Names/Ordinals RVA
    struct.pack_into("<II", f, base + 0x28, 0x1000, 0x1010)   # AddressOfFunctions
    struct.pack_into("<I", f, base + 0x30, 0x2040)            # AddressOfNames[0]
    struct.pack_into("<H", f, base + 0x38, 0)                 # AddressOfNameOrdinals[0]
    f[base + 0x40:base + 0x47] = b"func_a\x00"
    f[base + 0x50:base + 0x55] = b"test\x00"

    # ---- COFF 符号表（1 条，名字在字符串表里）----
    struct.pack_into("<8sIhHBB", f, sym_ptr, b"coffsym\x00", 0x10, 1, 0x20, 2, 0)
    strtab = sym_ptr + 18
    struct.pack_into("<I", f, strtab, 4 + 9)
    f[strtab + 4:strtab + 4 + 9] = b"coff_sym\x00"
    return bytes(f)


def make_coff() -> bytes:
    """MS COFF 目标文件（i386）：1 个节、1 个外部函数符号。"""
    f = bytearray(0x100)
    struct.pack_into("<HHIIIHH", f, 0, 0x014C, 1, 0, 64, 1, 0, 0)
    f[20:28] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", f, 28, 4, 0, 4, 60)     # vsize, vaddr, rawsize, rawptr
    struct.pack_into("<I", f, 56, 0x60500020)         # CODE|EXECUTE|READ|ALIGN16
    f[60:64] = b"\x55\x89\xE5\xC3"                    # push ebp; mov ebp,esp; ret
    struct.pack_into("<8sIhHBB", f, 64, b"\x00\x00\x00\x00\x04\x00\x00\x00",
                     0, 1, 0x20, 2, 0)
    strtab = 64 + 18
    name = b"coff_obj_func\x00"
    struct.pack_into("<I", f, strtab, 4 + len(name))
    f[strtab + 4:strtab + 4 + len(name)] = name
    return bytes(f)


# ----------------------------------------------------------------------
# Mach-O
# ----------------------------------------------------------------------
def make_macho(fat: bool = False) -> bytes:
    """Mach-O 64 位（arm64）：__TEXT 一个节、LC_SYMTAB、LC_MAIN。"""
    vm_base = 0x100000000
    text_addr = vm_base + 0x200
    ncmds = 3
    seg_cmdsize = 72 + 80                # LC_SEGMENT_64 头 + 1 个 section_64
    sym_cmd = 24
    main_cmd = 24
    sizeofcmds = seg_cmdsize + sym_cmd + main_cmd
    f = bytearray(0x400)
    # mach_header_64 是 8 个字段（多一个 reserved），少写一个会让所有 load command
    # 整体错位 4 字节——读出来就是「load command 长度离谱」。
    # MH_MAGIC_64 = 0xFEEDFACF，按小端写出来是 CF FA ED FE —— 「小端文件」的标志是
    # 文件里那四个**字节**，不是 0xCFFAEDFE 这个数；把它当小端整数写进去，得到的是
    # 一个大端文件，于是后面按小端写的 load command 全部错位。
    struct.pack_into("<IiiIIIII", f, 0, 0xFEEDFACF, 0x0100000C, 0, 2,
                     ncmds, sizeofcmds, 0, 0)
    off = 32
    # LC_SEGMENT_64
    struct.pack_into("<II", f, off, 0x19, seg_cmdsize)
    f[off + 8:off + 24] = b"__TEXT\x00" + b"\x00" * 9
    struct.pack_into("<QQQQ", f, off + 24, vm_base, 0x1000, 0, 0x400)
    struct.pack_into("<iiII", f, off + 56, 7, 5, 1, 0)      # maxprot, initprot, nsects
    sec = off + 72
    f[sec:sec + 16] = b"__text\x00" + b"\x00" * 9
    f[sec + 16:sec + 32] = b"__TEXT\x00" + b"\x00" * 9
    struct.pack_into("<QQI", f, sec + 32, text_addr, 8, 0x200)
    struct.pack_into("<IIII", f, sec + 52, 4, 0, 0, 0x80000400)
    off += seg_cmdsize
    # LC_SYMTAB
    struct.pack_into("<IIIIII", f, off, 0x2, 24, 0x300, 1, 0x320, 16)
    off += 24
    # LC_MAIN
    struct.pack_into("<IIQQ", f, off, 0x28, 24, 0x200, 0)
    # 指令字节
    f[0x200:0x208] = b"\xFD\x7B\xBF\xA9\xFD\x03\x00\x91"
    # nlist_64
    struct.pack_into("<IBBHQ", f, 0x300, 1, 0x0F, 1, 0, text_addr)
    f[0x320:0x320 + 8] = b"\x00_main\x00\x00"
    thin = bytes(f)
    if not fat:
        return thin
    hdr = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">IIIII", 0x0100000C, 0, 0x1000, len(thin), 12)
    return hdr + arch + b"\x00" * (0x1000 - len(hdr) - len(arch)) + thin
