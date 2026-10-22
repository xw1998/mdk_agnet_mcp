# -*- coding: utf-8 -*-
"""批次94 测试：读字节必须有出处，且读到的字节要回填校验。

用户报的现象：``recover_disasm`` 读错偏移（请求 0x08052118，实际读了 +0x1000 的
字节）却照常报 ``ok``——指令流、分支目标、字面量池全错位，肉眼看不出来。
根因有两类，本批都堵上：

  1. ``Unit.read`` 是 ``data[off:off+n]`` 裸切片：靠近段尾时会**跨过段边界**，
     把文件里紧邻的其它节的字节当成这些地址的字节返回，标签仍是原地址；
  2. ``base`` 在自带地址的容器（ELF/HEX/S-record）上是**静默忽略**的，
     调用方以为平移过了，实际没有。

修法（用户指定）：``base`` 只应用一次；读到的字节回填校验，不一致就报错。

  A Unit.read 不跨段：跨段读被截断并说明原因，出处（file_offset/span）可查
  B disassemble 把截断透出去（source.clipped + notes），不再静默当作完整
  C 回填校验能抓到「批量读越界/整体平移」这类伪反汇编
  D base 只应用一次：raw BIN 生效一次、ELF/HEX 明写 base_applied=False
  E 真实 axf 上 source.file_offset 与手算一致、所有指令字节都能重读
  F 闸门：工具面仍 214、零新增依赖
  G base 到货值/实际用值/容器冲突分开报（批次95）
  H 裸 BIN 不传 base 时按向量表推断并标记（批次96）

运行：python -m tests.test_batch94
"""
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import decomp as DC          # noqa: E402
from mdkdebug import recover as RC         # noqa: E402

PASS, FAIL = [], []
TMP = []

EXAMPLE_AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                           "mdk_test", "mdk_test.axf")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else "-> %r" % (detail,)))


def tmpdir(prefix="mdk94_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def write(name, data):
    p = os.path.join(tmpdir(), name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def code_bytes():
    """16 字节 Thumb 代码：movs r0,#1 ; bx lr ; movs r0,#2 ; bx lr。"""
    return struct.pack("<HHHH", 0x2001, 0x4770, 0x2002, 0x4770) + \
        struct.pack("<HHHH", 0x2003, 0x4770, 0x2004, 0x4770)


def two_span_unit():
    """两段镜像：[0x08000000,0x08000010) + [0x20000000,0x20000040)。

    两段之间隔着 0xF0 字节的**别的节**（这里用 0xAA 填充当标记）——
    这正是「跨段裸切片会把外来字节当成这些地址的字节」的现场。
    """
    data = code_bytes() + b"\xAA" * 0xF0 + b"\x55" * 0x40
    u = RC.Unit(data, "two_span", base=0)
    u.spans = [(0x08000000, 0x08000010, 0),
               (0x20000000, 0x20000040, 0x100)]
    u.code_ranges = [(0x08000000, 0x08000010)]
    u.arch = {"family": "arm", "bits": 32, "endian": "little", "thumb": True,
              "supported": True, "why": "test fixture"}
    return u


class OldReadBug(RC.Unit):
    """复刻批次94 之前的 ``read``：跨段裸切片（读错偏移的典型形态）。"""

    def read_ex(self, addr, n):
        off, avail, s, e = RC.Unit._locate(self, addr)
        if off is None:
            return {"data": b"", "file_offset": None, "span": None,
                    "requested": n, "got": 0, "clipped": False,
                    "reason": "不在映射范围内"}
        data = self.data[off:off + n]           # 裸切片：越过段尾照样返回
        return {"data": data, "file_offset": off,
                "span": {"start_hex": "0x%08X" % s, "end_hex": "0x%08X" % e},
                "requested": n, "got": len(data), "clipped": False,
                "reason": ""}


def _rec(rtype, addr, data):
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rtype]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


# ======================================================================
def section_a():
    print("A. Unit.read 不跨段（批次94 之前的缺陷现场）")
    u = two_span_unit()
    r = u.read(0x0800000C, 8)        # 段内只剩 4 字节
    check("A1 跨段读只返回段内 4 字节", len(r) == 4 and r == code_bytes()[12:16], r)
    ex = u.read_ex(0x0800000C, 8)
    check("A2 read_ex 标 clipped 并给出原因",
          ex["clipped"] and ex["got"] == 4
          and "越了所在段" in ex["reason"], ex)
    check("A3 出处可查：file_offset=0x0C、span 就是所在段",
          ex["file_offset"] == 0x0C
          and ex["span"]["start_hex"] == "0x08000000"
          and ex["span"]["end_hex"] == "0x08000010", ex)
    old = u.data[0x0C:0x14]
    check("A4 旧写法确实混入了紧邻节的字节（0xAA）",
          len(old) == 8 and old[4:] == b"\xAA" * 4, old.hex())
    ex2 = u.read_ex(0x20000020, 4)
    check("A5 第二段的地址算到正确的 file_offset（0x120）",
          ex2["file_offset"] == 0x120 and ex2["data"] == b"\x55" * 4, ex2)
    ex3 = u.read_ex(0x08000020, 4)    # 两段之间的空洞
    check("A6 空洞地址不返回任何字节、也不给 file_offset",
          ex3["data"] == b"" and ex3["file_offset"] is None
          and "不在镜像映射范围内" in ex3["reason"], ex3)
    check("A7 段内完整读不误标 clipped",
          u.read_ex(0x08000000, 4)["clipped"] is False)


def section_b():
    print("B. disassemble 把「只读到多少」透出去")
    u = two_span_unit()
    r = RC.disassemble(u, 0x08000008, 0x08000020)   # 请求 0x18，段内只有 8
    check("B1 反汇编仍 ok（截断不是错误），但 source.clipped=True",
          r.get("ok") and r["source"]["clipped"] is True, r.get("error"))
    check("B2 source 给出请求/实得/原因",
          r["source"]["requested"] == 0x18 and r["source"]["got"] == 8
          and "越了所在段" in r["source"]["reason"], r["source"])
    check("B3 notes 里明写只读到多少字节",
          any("只读到" in n for n in r.get("notes") or []), r.get("notes"))
    check("B4 只解码段内指令（4 条 16 位 = 8 字节）",
          r["count"] == 4 and r["consumed"] == 8, (r["count"], r["consumed"]))
    check("B5 每条指令的字节都能按地址重读",
          RC.readback_mismatches(u, [(x["addr"], x["size"], x["bytes"])
                                     for x in r["insns"]]) == [])
    r2 = RC.disassemble(u, 0x08000020, 0x08000028)
    check("B6 空洞地址反汇编直接报错（不再返回空 ok）",
          r2.get("ok") is False and "不在镜像映射范围内" in r2.get("error", ""),
          r2)


def section_c():
    print("C. 回填校验挡住「读错偏移仍报 ok」")
    u = OldReadBug(two_span_unit().data, "buggy", base=0)
    u.spans = [(0x08000000, 0x08000010, 0), (0x20000000, 0x20000040, 0x100)]
    u.code_ranges = [(0x08000000, 0x08000010)]
    u.arch = {"family": "arm", "bits": 32, "endian": "little", "thumb": True,
              "supported": True, "why": "test fixture"}
    check("C1 夹具确实复刻了旧行为（跨段读出 0x18 字节）",
          len(u.read_ex(0x08000008, 0x18)["data"]) == 0x18)
    r = RC.disassemble(u, 0x08000008, 0x08000020)
    check("C2 反汇编判 ok=False 且点明回填校验失败",
          r.get("ok") is False and "回填校验失败" in r.get("error", ""),
          r.get("error"))
    check("C3 mismatches 给出地址/解码字节/重读字节",
          r.get("mismatches") and "addr_hex" in r["mismatches"][0]
          and "reread" in r["mismatches"][0], r.get("mismatches"))
    check("C4 不一致的是段外那些地址（重读为空）",
          all(m["reread"] == "" for m in r["mismatches"]), r["mismatches"])
    # 伪 C 走的是自己算的函数区间，夹具要让可执行区间越过段尾，
    # 才能重现「批量读越界」这条路径（真实 ELF 上段的边界不等于函数边界）
    u2 = OldReadBug(u.data, "buggy2", base=0)
    u2.spans = list(u.spans)
    u2.code_ranges = [(0x08000008, 0x08000020)]
    u2.arch = dict(u.arch)
    dc = DC.decompile_function(u2, {"addr": 0x08000008, "end_addr": 0x08000020,
                                   "name": "f"},
                               funcs=[{"addr": 0x08000008,
                                       "end_addr": 0x08000020, "name": "f"}])
    check("C5 伪 C 路径同样报错（不漏）",
          dc.get("ok") is False and "回填校验失败" in dc.get("error", ""),
          dc.get("error"))


def section_d():
    print("D. base 只应用一次，并自证有没有生效")
    blob = bytes(range(0x100))
    u = RC._unit_from_data(blob, "x.bin", 0x08006000)
    check("D1 raw BIN：base 进了 span 起点，且 base_applied=True",
          u.spans[0][0] == 0x08006000 and u.base_applied is True, u.spans)
    check("D2 raw BIN：地址→文件偏移只减一次 base",
          u.offset_of(0x08006010) == 0x10
          and u.read(0x08006010, 4) == blob[0x10:0x14],
          (u.offset_of(0x08006010), u.read(0x08006010, 4).hex()))
    check("D3 raw BIN：base=0 与 base=0x08006000 的偏移一致（不存在重复应用）",
          RC._unit_from_data(blob, "x.bin", 0).offset_of(0x10)
          == u.offset_of(0x08006010))

    txt = "\n".join([_rec(4, 0, b"\x08\x00"),
                     _rec(0, 0x1000, bytes(range(16))),
                     _rec(1, 0, b"")]) + "\n"
    phex = write("b94.hex", txt.encode("ascii"))
    uh = RC._unit_from_data(open(phex, "rb").read(), phex, 0x08005000)
    check("D4 HEX：自带记录地址 ⇒ base_applied=False 且说明忽略",
          uh.base_applied is False and "被忽略" in uh.base_note, uh.base_note)
    check("D5 HEX：地址取记录里的 0x08001000，字节没有被 base 平移",
          uh.read(0x08001000, 4) == bytes(range(4))
          and uh.read(0x08006000, 4) == b"", uh.spans)

    if os.path.isfile(EXAMPLE_AXF):
        data = open(EXAMPLE_AXF, "rb").read()
        ue = RC._unit_from_data(data, EXAMPLE_AXF, 0x08052118)
        check("D6 ELF：base 被忽略（不叠加），地址取容器里的",
              ue.base_applied is False and "被忽略" in ue.base_note
              and ue.spans[0][0] == 0x08000000, ue.base_note)
        sp0 = list(ue.spans)
        ue2 = RC._unit_from_data(data, EXAMPLE_AXF, 0)
        check("D7 ELF：带 base 与不带 base 的地址映射完全一致",
              sp0 == list(ue2.spans))
    else:
        check("D6 ELF 夹具存在", False, EXAMPLE_AXF)
        check("D7 ELF 夹具存在2", False, EXAMPLE_AXF)

    pbin = write("b94.bin", blob)
    d = RC.disasm_at(pbin, base=0x08006000, start=0x08006004, end=0x08006008,
                     arch="arm", thumb=True)
    check("D8 disasm_at 输出 address_map（容器/base 是否生效/段清单）",
          d.get("ok") and d["address_map"]["container"] == "bin"
          and d["address_map"]["base_applied"] is True
          and d["address_map"]["spans"], d.get("address_map") or d.get("error"))
    check("D9 disasm_at 的 source.base_applied 与 address_map 一致",
          d["source"]["base_applied"] is True
          and d["insns"][0]["addr"] == 0x08006004, d.get("source"))
    dh = RC.disasm_at(phex, base=0x08005000, start=0x08001000, end=0x08001004,
                      arch="arm", thumb=True)
    check("D10 HEX 上 disasm_at 的 address_map 明写 base 未生效",
          dh.get("ok") and dh["address_map"]["base_applied"] is False
          and "被忽略" in dh["address_map"]["note"],
          dh.get("address_map") or dh.get("error"))


def section_e():
    print("E. 真实 axf：出处与手算一致、每条指令都能重读")
    if not os.path.isfile(EXAMPLE_AXF):
        check("E0 axf 夹具存在", False, EXAMPLE_AXF)
        return
    data = open(EXAMPLE_AXF, "rb").read()
    u = RC._unit_from_data(data, EXAMPLE_AXF, 0)
    r = RC.disasm_at(EXAMPLE_AXF, symbol="uart_handle_line", max_insns=60)
    check("E1 反汇编 ok 且有 source", r.get("ok") and r.get("source"),
          r.get("error"))
    if not r.get("ok"):
        return
    start = r["insns"][0]["addr"]
    check("E2 source.file_offset 与手算 offset_of 一致",
          int(r["source"]["file_offset_hex"], 16) == u.offset_of(start),
          (r["source"]["file_offset_hex"], hex(u.offset_of(start))))
    check("E3 source.span 覆盖首条指令地址",
          int(r["source"]["span"]["start_hex"], 16) <= start
          < int(r["source"]["span"]["end_hex"], 16), r["source"]["span"])
    check("E4 每条指令字节都能按地址重读（0 处不一致）",
          RC.readback_mismatches(u, [(x["addr"], x["size"], x["bytes"])
                                     for x in r["insns"]]) == [])
    check("E5 没有截断时 source.clipped=False",
          r["source"]["clipped"] is False, r["source"])
    rc = RC.disasm_at(EXAMPLE_AXF, symbol="uart_handle_line", max_insns=60,
                      fmt="c")
    check("E6 伪 C 分支也带 address_map（同一套 base 口径）",
          rc.get("ok") and rc["address_map"]["container"] == "elf"
          and rc["address_map"]["base_applied"] is False,
          rc.get("address_map") or rc.get("error"))



def vector_bin(base_of_image):
    """0x300 字节 raw BIN：SP 合法、复位地址 0x08005201（真 base 0x08005000）。"""
    b = bytearray(0x300)
    b[0:4] = struct.pack("<I", 0x20005000)
    b[4:8] = struct.pack("<I", 0x08005201)
    return bytes(b)

def section_g():
    print("G. base 到货值 / 实际用值 / 容器冲突要分开报（批次95）")
    blob = vector_bin(None)
    pgood = write("b95_vec.bin", blob)
    d = RC.disasm_at(pgood, base=0x08005000, start=0x08005004, end=0x08005008,
                     arch="arm", thumb=True)
    am = d.get("address_map") or {}
    check("G1 raw BIN：input.base_received_hex 就是你传的值",
          d.get("ok") and (d.get("input") or {}).get("base_received_hex")
          == "0x08005000", d.get("input"))
    check("G2 raw BIN：base_received_hex / base_hex / base_source 三者一致",
          am.get("base_received_hex") == "0x08005000"
          and am.get("base_hex") == "0x08005000"
          and am.get("base_source") == "arg", am)
    check("G3 正确 base ⇒ 向量表自检 looks_like_cortex_m_vector_table",
          (am.get("base_check") or {}).get("verdict")
          == "looks_like_cortex_m_vector_table", am.get("base_check"))

    dw = RC.disasm_at(pgood, base=0x08004000, start=0x08004004, end=0x08004008,
                      arch="arm", thumb=True)
    amw = dw.get("address_map") or {}
    check("G4 差一页的 base ⇒ 自检 not_a_vector_table",
          dw.get("ok")
          and (amw.get("base_check") or {}).get("verdict") == "not_a_vector_table",
          amw.get("base_check") or dw.get("error"))
    check("G5 自检 hint 会出现在 notes 里（不是只在 address_map 深处）",
          any("base 差一页" in n for n in (dw.get("notes") or [])),
          dw.get("notes"))

    # 用户现场：同一地址在两种 base 下的文件偏移正好差一页（0x4D118 / 0x4E118）
    big = bytearray(0x4E400)
    big[0:4] = struct.pack("<I", 0x20005000)
    big[4:8] = struct.pack("<I", 0x08005101)
    pbig = write("b95_big.bin", bytes(big))
    o = {}
    for bs in (0x08005000, 0x08004000):
        rb = RC.disasm_at(pbig, base=bs, start=0x08052118, max_insns=4,
                          arch="arm", thumb=True)
        o[bs] = (rb.get("ok"), (rb.get("source") or {}).get("file_offset_hex"))
    check("G6 用户现场：传 0x08005000 读 0x4D118、传 0x08004000 读 0x4E118",
          o[0x08005000] == (True, "0x4D118")
          and o[0x08004000] == (True, "0x4E118"), o)

    hx = "\n".join([_rec(4, 0, b"\x08\x00"),
                    _rec(0, 0x4000, bytes(range(16))),
                    _rec(1, 0, b"")]) + "\n"
    ph = write("b95.hex", hx.encode("ascii"))
    dh = RC.disasm_at(ph, base=0x08005000, start=0x08004000, end=0x08004004,
                      arch="arm", thumb=True)
    amh = dh.get("address_map") or {}
    check("G7 HEX：base_source=container，传入值仍被回显",
          amh.get("base_source") == "container"
          and amh.get("base_received_hex") == "0x08005000"
          and amh.get("base_hex") == "0x08004000", amh)
    check("G8 HEX：base 与容器地址不一致 ⇒ base_conflict.delta=-0x1000",
          (amh.get("base_conflict") or {}).get("delta") == -0x1000,
          amh.get("base_conflict"))
    check("G9 HEX：冲突也写进 notes",
          any("base 冲突" in n for n in (dh.get("notes") or [])), dh.get("notes"))

    if os.path.isfile(EXAMPLE_AXF):
        de = RC.disasm_at(EXAMPLE_AXF, base=0x08052118, symbol="uart_handle_line",
                          max_insns=8)
        ame = de.get("address_map") or {}
        check("G10 ELF：base_source=container 且报出 base_conflict",
              ame.get("base_source") == "container"
              and ame.get("base_received_hex") == "0x08052118"
              and (ame.get("base_conflict") or {}).get("argument_hex")
              == "0x08052118", ame)
        dc = RC.disasm_at(EXAMPLE_AXF, base=0x08052118, symbol="uart_handle_line",
                          max_insns=8, fmt="c")
        check("G11 伪 C 分支也回显 input.base_received_hex",
              dc.get("ok") and (dc.get("input") or {}).get("base_received_hex")
              == "0x08052118", dc.get("input") or dc.get("error"))
        check("G12 伪 C 分支同样有 address_map.base_conflict",
              (dc.get("address_map") or {}).get("base_conflict") is not None,
              dc.get("address_map"))
        srec = os.path.join(ROOT, "tests", "fixtures", "decomp",
                            "decomp_fx.srec")
        if os.path.isfile(srec):
            us = RC._unit_from_data(open(srec, "rb").read(), srec, 0x08005000)
            check("G13 S-record：base_source=container+arg（记录地址整体平移）",
                  us.base_source == "container+arg"
                  and us.base_received == 0x08005000, us.base_source)
    else:
        for n in ("G10 ELF 夹具存在", "G11 ELF 夹具存在2", "G12 ELF 夹具存在3"):
            check(n, False, EXAMPLE_AXF)

    pm = write("b95_small.bin", blob)
    dmm = RC.disasm_at(pm, base=0x08005000, start=0x08005004, end=0x08005008,
                       arch="arm", thumb=True)
    check("G14 bin+base：address_map 的到货值与实际值相等（没有偷偷换 base）",
          dmm["address_map"]["base_received_hex"]
          == dmm["address_map"]["base_hex"], dmm["address_map"])


def section_h():
    print("H. 裸 BIN 不传 base：按向量表推断并明确标记（批次96）")
    blob = vector_bin(None)
    p = write("b96_nobase.bin", blob)
    r = RC.disasm_at(p, start=0x08005204, end=0x08005208,
                     arch="arm", thumb=True)
    am = r.get("address_map") or {}
    check("H1 没传 base ⇒ base_source=inferred、base_hex=0x08005000",
          r.get("ok") and am.get("base_source") == "inferred"
          and am.get("base_hex") == "0x08005000", am or r.get("error"))
    check("H2 推断后地址能正常映射（file_offset=0x204）",
          (r.get("source") or {}).get("file_offset_hex") == "0x204",
          r.get("source"))
    check("H3 notes 明说 base 是推断的",
          any("base 是**推断**的" in n for n in (r.get("notes") or [])),
          r.get("notes"))
    inf = am.get("base_inferred") or {}
    check("H4 base_inferred 带方法/证据（不是只有一个数字）",
          inf.get("method") == "cortex_m_vector_table_1k_alignment"
          and inf.get("sp_hex") and inf.get("reset_hex")
          and "缺 base" in (inf.get("evidence") or ""), inf)
    check("H5 inferred 上向量表自检仍适用且通过",
          (am.get("base_check") or {}).get("verdict")
          == "looks_like_cortex_m_vector_table", am.get("base_check"))

    r2 = RC.disasm_at(p, base=0x08005000, start=0x08005204, end=0x08005208,
                      arch="arm", thumb=True)
    check("H6 显式传 base 时不做推断（base_source=arg）",
          (r2.get("address_map") or {}).get("base_source") == "arg"
          and (r2.get("address_map") or {}).get("base_inferred") is None,
          r2.get("address_map"))

    # 复位地址本来就在 [0,len) 内 ⇒ base=0 自洽，不该被改写
    b2 = bytearray(0x300)
    b2[0:4] = struct.pack("<I", 0x20001000)
    b2[4:8] = struct.pack("<I", 0x00000101)
    p2 = write("b96_zero.bin", bytes(b2))
    u2 = RC._unit_from_data(bytes(b2), p2, 0)
    check("H7 复位地址在镜像内 ⇒ 不推断（base=0 自洽）",
          u2.base == 0 and u2.base_source == "arg" and u2.base_inferred is None,
          (u2.base, u2.base_source))

    # 乱字节：没有可信向量表 ⇒ 不猜
    junk = bytearray(0x300)
    junk[0:8] = struct.pack("<II", 0xDEADBEEF, 0x12345678)
    p3 = write("b96_junk.bin", bytes(junk))
    u3 = RC._unit_from_data(bytes(junk), p3, 0)
    check("H8 数据不像向量表 ⇒ 不推断、不猜 base",
          u3.base == 0 and u3.base_inferred is None, (u3.base, u3.base_source))

    e = RC.disasm_at(p, start=0x08005208, end=0x08005204,
                     arch="arm", thumb=True)
    check("H9 end<start 的报错地址补零到 8 位",
          "end(0x08005204)" in (e.get("error") or "")
          and "start(0x08005208)" in (e.get("error") or ""), e.get("error"))

def section_f():
    print("F. 闸门")
    import asyncio
    from mdkdebug import server as SV
    names = {t.name for t in asyncio.run(
        SV.create_server(port=15995, toolsets="all").list_tools())}
    check("F1 工具总数仍是 214（本批只改既有工具的行为）",
          len(names) == 214, len(names))
    check("F2 没有引入新依赖",
          not any(m in sys.modules for m in
                  ("unicorn", "keystone", "angr", "r2pipe", "lief")),
          [m for m in ("unicorn", "keystone", "angr", "r2pipe", "lief")
           if m in sys.modules])
    src = open(RC.__file__, encoding="utf-8").read()
    check("F3 Unit.read 不再裸切片到 data[off:off+n] 以外的地方",
          "data[off:off + take]" in src and "min(n, avail" in src)


def main():
    print("== 批次94：读字节的出处与回填校验 ==")
    try:
        section_a()
        section_b()
        section_c()
        section_d()
        section_e()
        section_g()
        section_h()
        section_f()
    finally:
        for d in TMP:
            for name in os.listdir(d):
                try:
                    os.remove(os.path.join(d, name))
                except OSError:
                    pass
            try:
                os.rmdir(d)
            except OSError:
                pass
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
