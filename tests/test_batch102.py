# -*- coding: utf-8 -*-
"""批次102 测试：逆向语义层（strings / deadcode / datatable）+ 两镜像差分 + 调用图栈深。

本批把「逆向能读到什么」从「反汇编 + 符号」推到「语义」：

  recover_strings     带引用证据的字符串清单（三重过滤：字符集 / 边界 / 引用）
  recover_deadcode    静态可达性：未引用函数与未引用区间（判词是 unreferenced）
  recover_datatable   数据表导成 C 并**逐元素回读自证**（crc32/array/records/指针表）
  recover_bindiff     两镜像逐函数差分（PASS / RESIDUE / FAIL，不是逐字节 diff）
  recover_stack       调用图 + 每个根的最坏调用链与栈深（static_bound/lower_bound/unbounded）

分节：

  A 工具面：5 个新工具注册、归组、注解、参数口径
  B strings：真镜像计数、三重过滤开关、GBK 两级、截断必须自报
  C deadcode：inventory 自洽、判词、确证路径、「不是死代码」的限制声明
  D datatable：四条路径的回读自证（含**曾经恒假绿**的回归）+ 证据落盘护栏
  E bindiff：三态判据、配对门槛 min_insns、窗口对比、三份报告落盘
  F stack：static_bound 才给 fits/margin、间接调用=下界、环=无界、动态帧
  G vector_table(skip_empty)：保留槽位跳过而不终止
  H 文档与零依赖闸门

运行：python -m tests.test_batch102
"""
import asyncio
import io
import json
import os
import re
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import bindiff as BD           # noqa: E402
from mdkdebug import callgraph as CG         # noqa: E402
from mdkdebug import recover as RC           # noqa: E402
from mdkdebug import semantics as SEM        # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402

AXF = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                   "mdk_test", "mdk_test.axf")
BASE = 0x08000000
NEW_TOOLS = ("recover_strings", "recover_deadcode", "recover_bindiff",
             "recover_datatable", "recover_stack")

PASS, FAIL = [], []
TMP = []
_CACHE = {}


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def tmpdir(prefix="mdk102_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def _w(data, name, d=None):
    d = d or tmpdir()
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return p


def _bl(pc, target):
    """Thumb-2 BL 编码（合成夹具里要真调一个函数，不能靠猜指令文本）。"""
    off = target - pc
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    imm10 = (off >> 12) & 0x3FF
    imm11 = (off >> 1) & 0x7FF
    j1 = (1 ^ (i1 ^ s)) & 1
    j2 = (1 ^ (i2 ^ s)) & 1
    return struct.pack("<HH", 0xF000 | (s << 10) | imm10,
                       0xD000 | (j1 << 13) | (j2 << 11) | imm11)


def _bin(name, code, tail=0x100, sp=0x20005000, reset=0x08):
    """合成固件：向量表(2 字) + code，后面补 0 到 tail 字节。"""
    blob = struct.pack("<II", sp, BASE + reset + 1) + code
    blob += b"\x00" * (tail + 0x100 - len(blob))
    return _w(blob, name)


# ---------------------------------------------------------------------------
# 夹具
# ---------------------------------------------------------------------------
_CRC_POLY = 0xEDB88320


def _crc32_table():
    out = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (_CRC_POLY if c & 1 else 0)
        out.append(c)
    return out


CRCOFF = 0x100


def crc_bin():
    """向量表 + 0x100 处 256 项 CRC32 现算表（fmt=auto 应当认出来）。"""
    if "crc" in _CACHE:
        return _CACHE["crc"]
    blob = bytearray(struct.pack("<II", 0x20005000, BASE + 9))
    blob += b"\x00" * (CRCOFF - len(blob))
    blob += b"".join(struct.pack("<I", v) for v in _crc32_table())
    _CACHE["crc"] = _w(bytes(blob), "crc.bin")
    return _CACHE["crc"]


def crc_bad_bin():
    if "crcbad" in _CACHE:
        return _CACHE["crcbad"]
    raw = bytearray(open(crc_bin(), "rb").read())
    raw[CRCOFF + 5] ^= 0x5A
    _CACHE["crcbad"] = _w(bytes(raw), "crc_bad.bin")
    return _CACHE["crcbad"]


def data_bin(name, payload):
    """在 0x100 处放任意 payload（用来测 array / records 两条路径）。"""
    blob = bytearray(struct.pack("<II", 0x20005000, BASE + 9))
    blob += b"\x00" * (CRCOFF - len(blob))
    blob += payload
    blob += b"\x00" * 64
    return _w(bytes(blob), name)


def crypto_path():
    """真镜像是 ELF；这条只是给「同一份镜像 base 给错也照样 PASS」用。"""
    return AXF


# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面：5 个新工具注册、归组、注解、参数口径")
    from mdkdebug import server as SV

    srv = SV.create_server(port=15971, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("A1 五个新工具都注册了",
          all(n in names for n in NEW_TOOLS), [n for n in NEW_TOOLS if n not in names])
    check("A2 注册总数 220（本批新增 5 个）", len(names) == 220, len(names))
    check("A3 build 组 36 个且五个都在 build 组",
          len(TB.TOOLSETS["build"]) == 36 and all(n in TB.TOOLSETS["build"]
                                                 for n in NEW_TOOLS),
          len(TB.TOOLSETS["build"]))
    check("A4 不在任何别的组里重复挂（一键一义：每个工具只归一组）",
          all(sum(1 for g in TB.TOOLSETS if n in TB.TOOLSETS[g]) == 1
              for n in NEW_TOOLS),
          {n: [g for g in TB.TOOLSETS if n in TB.TOOLSETS[g]] for n in NEW_TOOLS})

    check("A5 五个都是只读（READONLY）",
          all(n in AN.READONLY for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in AN.READONLY])
    check("A6 recover_bindiff 标为不可重复执行（out_dir 必须空目录，同 image_carve）",
          "recover_bindiff" in AN.NON_IDEMPOTENT, sorted(AN.NON_IDEMPOTENT)[:8])
    ann = AN.annotations_for("recover_bindiff")
    check("A7 bindiff 注解：只读 + 非幂等",
          ann.get("readOnlyHint") is True and ann.get("idempotentHint") is False, ann)
    check("A8 工具面归类完整（check_surface 无问题）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))

    want = {"recover_strings": ["base"],
            "recover_deadcode": ["base"],
            "recover_datatable": ["addr", "base"],
            "recover_bindiff": ["base", "base_target"],
            "recover_stack": ["base", "stack_size"]}
    bad = []
    for n, params in want.items():
        props = (tools[n].input_schema.get("properties") or {})
        for p in params:
            got = props.get(p) or {}
            if not (got.get("anyOf") or got.get("type")):
                bad.append("%s.%s=%r" % (n, p, got))
    check("A9 地址类参数一律 str|int 双形态（传 \"0x08000000\" 不失败）",
          not bad, bad)

    # 默认工具面（core 组 + 引导）：这 5 个按需装载，不能默认塞进上下文
    old = os.environ.pop("MDKDEBUG_TOOLSETS", None)
    try:
        d_srv = SV.create_server(port=15972)
        dflt = {t.name for t in asyncio.run(d_srv.list_tools())}
    finally:
        if old is not None:
            os.environ["MDKDEBUG_TOOLSETS"] = old
    check("A10 默认面仍是 44 个工具", len(dflt) == 44, len(dflt))
    check("A11 五个新工具默认收起（要 toolset 装载）",
          not (set(NEW_TOOLS) & dflt), sorted(set(NEW_TOOLS) & dflt))


# ---------------------------------------------------------------------------
# B strings
# ---------------------------------------------------------------------------
def section_b():
    print("\nB recover_strings：带引用证据的字符串清单")
    r = SEM.strings(AXF)
    c = r["counts"]
    check("B1 真镜像扫描计数与实测一致（candidates 560 / confirmed 10）",
          c["candidates"] == 560 and c["confirmed"] == 10 and c["kept"] == 560, c)
    check("B2 丢弃逐因计数，不静默减少（四项都出现）",
          all(k in c["dropped"] for k in ("in_code_no_boundary",
                                          "in_code_unreferenced",
                                          "loose_gbk", "undecodable")),
          sorted(c["dropped"]))
    check("B3 扫描阶段丢弃也计数（too_short / not_printable）",
          c["scan_dropped"].get("too_short", 0) > 0
          and "not_printable" in c["scan_dropped"], c["scan_dropped"])
    check("B4 filter_rule 写清三重过滤（字符集/边界/引用）",
          len(r["filter_rule"]) >= 4
          and any("字符集" in x for x in r["filter_rule"])
          and any("边界" in x for x in r["filter_rule"])
          and any("引用" in x for x in r["filter_rule"]), r["filter_rule"][:2])
    check("B5 limitations 声明「无引用 ≠ 没用」",
          any("不证明" in x for x in r["limitations"]), r["limitations"])

    ref = SEM.strings(AXF, referenced_only=True)
    check("B6 referenced_only=True 只留 confirmed，且都是 strong 引用",
          ref["counts"]["kept"] == 10
          and all(s["verdict"] == "confirmed" for s in ref["strings"])
          and all(s["ref_strength"] == "strong" for s in ref["strings"]),
          (ref["counts"]["kept"],
           {s["verdict"] for s in ref["strings"]},
           {s["ref_strength"] for s in ref["strings"]}))

    fmt = SEM.strings(AXF, kinds="format")
    check("B7 kinds=\"format\" 只留格式化串（3 条）",
          len(fmt["strings"]) == 3
          and all("format" in x["kinds"] for x in fmt["strings"]),
          (len(fmt["strings"]), [x["kinds"] for x in fmt["strings"]][:3]))
    check("B8 被 kinds 滤掉的进 kind_filtered 计数",
          fmt["counts"]["dropped"]["kind_filtered"] > 0,
          fmt["counts"]["dropped"])

    code = SEM.strings(AXF, code_strings=True)
    check("B9 code_strings=True 把「可执行区无引用」的候选放出来（in_code_unreferenced 归零）",
          code["counts"]["dropped"]["in_code_unreferenced"] == 0
          and len(code["strings"]) == 92,
          (code["counts"]["dropped"]["in_code_unreferenced"], len(code["strings"])))

    inc = SEM.strings(AXF, include_dropped=True)
    check("B10 include_dropped=True 把丢弃项也放进 strings（含 drop_reason）",
          len(inc["strings"]) >= len(r["strings"])
          and all(s.get("drop_reason") for s in inc["strings"]
                  if s["verdict"] == "dropped"), len(inc["strings"]))

    cut = SEM.strings(AXF, max_strings=100)
    check("B11 候选上限吃满必须自报不完整（truncated/complete/gaps 三处同步）",
          cut["truncated"] is True and cut["complete"] is False
          and any("max_strings=100" in g.get("reason", "") for g in cut["gaps"]),
          (cut["truncated"], cut["complete"], cut["gaps"][-1:]))

    check("B12 GB2312 区中文串按硬编码认出（不是 loose_gbk）",
          SEM._high_text("温度过高".encode("gbk")) [0] == "温度过高"
          and SEM._high_text("温度过高".encode("gbk"))[2] is False,
          SEM._high_text("温度过高".encode("gbk")))
    check("B13 分类：诊断串 → diagnostic，含 %s → format",
          "diagnostic" in SEM.classify("ERROR: uart init failed")["kinds"]
          and "format" in SEM.classify("USART2 PA2=TX %s\r\n")["kinds"],
          (SEM.classify("ERROR: uart init failed"),
           SEM.classify("USART2 PA2=TX %s\r\n")))

    # 裸 bin 的代码区间覆盖整个镜像 ⇒ 这两条串落成 in_code_unreferenced，
    # 要 code_strings=True 才列出来（这正是那个开关的意义）。
    syn = data_bin("str_syn.bin", b"HELLO-WORLD-TABLE\x00\x00"
                                 b"\xce\xc2\xb6\xc8\xb9\xfd\xb8\xdf\x00")
    s2 = SEM.strings(syn, base=BASE, code_strings=True)
    texts = [x["text"] for x in s2["strings"]]
    check("B14 合成镜像里 ASCII 串能读到",
          "HELLO-WORLD-TABLE" in texts, texts[:5])
    check("B15 同一个镜像里 GB2312 中文串也能读到（解码正确）",
          "温度过高" in texts, texts[:5])
    s3 = SEM.strings(syn, base=BASE, code_strings=True, allow_gbk=False)
    check("B16 allow_gbk=False 时中文不再进列表（同一份镜像，开关生效）",
          "温度过高" not in [x["text"] for x in s3["strings"]],
          [x["text"] for x in s3["strings"]][:6])


# ---------------------------------------------------------------------------
# C deadcode
# ---------------------------------------------------------------------------
def section_c():
    print("\nC recover_deadcode：静态可达性（判词是 unreferenced）")
    d = SEM.deadcode(AXF)
    inv = d["inventory"]
    check("C1 inventory 自洽：functions = reachable + unreachable",
          inv["functions"] == inv["reachable"] + inv["unreachable"] == 175,
          inv)
    check("C2 真镜像测到 13 个根 / 69 可达 / 106 无引用",
          inv["roots"] == 13 and inv["reachable"] == 69
          and inv["unreachable"] == 106, inv)
    check("C3 code_bytes 是函数体字节之和（>0）", inv["code_bytes"] > 0, inv)
    vs = {f["verdict"] for f in d["unreachable_functions"]}
    check("C4 判词只用三档（unreferenced / unreachable_but_called / "
          "unreachable_but_pointed）",
          vs and vs <= {"unreferenced", "unreachable_but_called",
                        "unreachable_but_pointed"}, vs)
    check("C5 每条无引用函数都带 basis（为什么判它无引用）",
          all(f.get("basis") for f in d["unreachable_functions"]),
          d["unreachable_functions"][0])
    check("C6 how_to_confirm 给「删掉重建、bin 逐字节相同」的确证路径",
          any("recover_project_exact" in x for x in d["how_to_confirm"])
          and any("recover_verify" in x for x in d["how_to_confirm"]),
          d["how_to_confirm"])
    check("C7 limitations 明说「不是死代码」（间接调用/函数指针/中断向量都能救活它）",
          any("不是" in x and "死代码" in x for x in d["limitations"]),
          d["limitations"])
    check("C8 unreferenced_ranges=0 时必须解释这条判据的适用范围（而不是「没有死代码」）",
          d["unreferenced_ranges"] == [] and d["ranges_note"]
          and ("不是没有死代码" in d["ranges_note"]
               or "没有可判定" in d["ranges_note"]), d["ranges_note"])
    check("C9 unreachable_function_bytes 与函数列表一致（>0）",
          d["unreachable_function_bytes"] > 0, d["unreachable_function_bytes"])

    d2 = SEM.deadcode(AXF, symbols="_printf_fp_hex_real")
    check("C10 symbols= 补的命名根真的抬了可达集（roots 13→14、reachable 69→74）",
          d2["inventory"]["roots"] == 14 and d2["inventory"]["reachable"] == 74,
          d2["inventory"])
    check("C11 补根后该函数从无引用列表里消失",
          all(f["name"] != "_printf_fp_hex_real"
              for f in d2["unreachable_functions"]),
          [f["name"] for f in d2["unreachable_functions"][:3]])


# ---------------------------------------------------------------------------
# D datatable
# ---------------------------------------------------------------------------
def section_d():
    print("\nD recover_datatable：导成 C 并逐元素回读自证")
    r = SEM.datatable(AXF)
    check("D1 缺 addr 直接报错（不拿镜像首字当默认值）",
          r["ok"] is False and "addr" in r["error"], r)

    ok = SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF)
    check("D2 fmt=auto 认出 CRC32 表（poly 0xEDB88320）且 256 项",
          ok["ok"] is True and ok["verified"] is True
          and ok["detected"] == {"kind": "crc32", "match": True,
                                 "poly_hex": "0xEDB88320"},
          ok.get("detected"))
    check("D3 生成的 C 里真的是 256 个值（table.elements 与实体一致）",
          ok["table"]["elements"] == 256 and ok["table"]["type"] == "u32", ok["table"])
    check("D4 回读规则写清「重新解析生成文本，逐元素与镜像字节比」",
          "重新解析" in ok["verify_rule"] and ok["mismatches"] == [], ok["verify_rule"])

    bad = SEM.datatable(crc_bad_bin(), base=BASE, addr=BASE + CRCOFF)
    check("D5 坏一个字节时 fmt=auto 不硬认（ok=False，不猜）",
          bad["ok"] is False, str(bad)[:200])
    bad2 = SEM.datatable(crc_bad_bin(), base=BASE, addr=BASE + CRCOFF, fmt="crc32")
    check("D6 显式 fmt=crc32 时错在哪一项都要列出来",
          bad2["ok"] is False and "不一致" in bad2["error"]
          and bad2["detected"]["match"] is False
          and bad2["detected"]["mismatch_index"], str(bad2)[:240])

    # 这条是本批次修掉的真缺陷：回读以前扫的是**整段生成文本**，
    # 文件头注释里的 0x08000000 / 0xEDB88320 会被当成第 0/1 个元素 ⇒ verified 恒 False；
    # 反过来 records 路先吃到 typedef 里的 uint16_t 的 16 ⇒ 恒假红。
    s32 = data_bin("s32.bin", b"".join(struct.pack("<i", v)
                                       for v in (1, -1, 0x7FFFFFFF, -2147483648)))
    r32 = SEM.datatable(s32, base=BASE, addr=BASE + CRCOFF, fmt="array",
                        count=4, elem=4, signed=True)
    check("D7 array+signed：打印用有符号视图、回读按同一口径比（-1 不失败）",
          r32["ok"] is True and r32["verified"] is True
          and r32["mismatches"] == [] and "int32_t" in r32["code"],
          (r32["ok"], r32["mismatches"]))
    check("D8 array 的值真的是有符号字面量（不是 0xFFFFFFFF）",
          "-1" in r32["code"] and "0xFFFFFFFF" not in r32["code"],
          r32["code"][-160:])

    recs = data_bin("recs.bin", b"".join(struct.pack("<HHh", *t)
                                         for t in ((1, 0x10, -5), (2, 0x20, -6),
                                                   (3, 0x30, 7))))
    rr = SEM.datatable(recs, base=BASE, addr=BASE + CRCOFF, fmt="records",
                       fields="id:u16,flags:u16,value:s16", count=3)
    check("D9 records：typedef 字段名/类型正确且回读自证通过",
          rr["ok"] is True and rr["verified"] is True
          and "int16_t value;" in rr["code"] and "{ 0x0001, 0x0010, -5 }" in rr["code"],
          rr["code"][-260:])
    check("D10 records 的 detect 记录 record_size 与字段",
          rr["detected"]["kind"] == "records"
          and rr["detected"]["record_size"] == 6, rr["detected"])

    chars = data_bin("chr.bin", b"".join(struct.pack("<I", a) + t
                                         for a, t in ((1, b"AB\x00\x00"),
                                                      (2, b"CD\x00\x00"))))
    rc2 = SEM.datatable(chars, base=BASE, addr=BASE + CRCOFF, fmt="records",
                        fields="id:u32,tag:char[4]", count=2)
    check("D11 records 带 char[] 字段：字节逐个比，不当数值解析",
          rc2["ok"] is True and rc2["verified"] is True
          and "char tag[4];" in rc2["code"], (rc2["ok"], rc2["mismatches"]))

    check("D12 坏参数不猜：elem 只支持 1/2/4",
          SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF, fmt="array",
                        count=2, elem=3)["ok"] is False)
    check("D13 fmt=records 没给 fields 直接报错",
          "fields" in SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF,
                                    fmt="records", count=2)["error"])

    d = tmpdir()
    outp = os.path.join(d, "table.c")
    wr = SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF, out=outp)
    raw = open(outp, "rb").read() if os.path.isfile(outp) else b""
    check("D14 落盘是 utf-8 无 BOM", wr["ok"] is True and raw[:3] != b"\xef\xbb\xbf",
          raw[:6])
    check("D15 证据硬标记：EVIDENCE ONLY 头 + #error 闸门",
          b"EVIDENCE ONLY" in raw and b"#error" in raw
          and b"MDKDEBUG_ALLOW_EVIDENCE_ONLY" in raw, raw[:120])
    check("D16 写盘后回填 out / out_bytes",
          wr.get("out") and wr.get("out_bytes") == len(raw), wr.get("out"))

    # 护栏：build/App/Core 这类目录里真有源码就拒写
    proj = tmpdir()
    os.makedirs(os.path.join(proj, "Core", "Src"))
    open(os.path.join(proj, "Core", "Src", "main.c"), "w", encoding="utf-8").write(
        "int main(void){return 0;}\n")
    g = SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF,
                      out=os.path.join(proj, "Core", "Src", "t.c"))
    check("D17 拒绝把证据产物写进工程目录（error_code=evidence-in-build-dir）",
          g["ok"] is False and g.get("error_code") == "evidence-in-build-dir",
          str(g)[:240])
    g2 = SEM.datatable(crc_bin(), base=BASE, addr=BASE + CRCOFF,
                       out=os.path.join(proj, "Core", "Src", "t.c"),
                       evidence_only=False)
    body = open(g2.get("out") or "/nonexistent", "rb").read() if g2.get("ok") else b""
    check("D18 evidence_only=False 才允许写进工程目录，且不再加 #error 闸门",
          g2["ok"] is True and b"#error" not in body and body[:3] != b"\xef\xbb\xbf",
          str(g2)[:200])


# ---------------------------------------------------------------------------
# E bindiff
# ---------------------------------------------------------------------------
def section_e():
    print("\nE recover_bindiff：两镜像逐函数差分")
    same = BD.compare(AXF, AXF)
    check("E1 同一份镜像逐函数 PASS 175（pairs 也是 175）",
          same["counts"]["PASS"] == 175 and same["counts"]["pairs"] == 175
          and same["counts"]["FAIL"] == 0, same["counts"])
    shifted = BD.compare(AXF, AXF, base_target=BASE + 0x1000)
    check("E2 base_target 给错 0x1000 也照样 PASS（字节不同 ≠ 代码改了）",
          shifted["counts"]["PASS"] == 175, shifted["counts"])
    check("E3 verdict_rule 写明三态与「PASS 只说明机器码没变」",
          len(same["verdict_rule"]) >= 4
          and any("normaliz" in x or "归一" in x for x in same["verdict_rule"]), None)
    check("E4 limitations 声明 missing_in_* 不单独证明源码增删",
          any("missing_in_" in x for x in same["limitations"]), same["limitations"])

    ins = [0xB500, 0x2001, 0x3005, 0x3006, 0xBD00]

    def fw(name, words, tail=64):
        return _bin(name, b"".join(struct.pack("<H", w) for w in words), tail=tail)

    a = fw("bi_a.bin", ins)
    b = fw("bi_b.bin", ins)
    r1 = BD.compare(a, b, base=BASE, base_target=BASE)
    check("E5 合成镜像逐字节相同 → PASS（basis=bytes）",
          r1["counts"]["PASS"] == 1 and r1["functions"][0]["basis"] == "bytes",
          r1["functions"][:1])

    imm = fw("bi_imm.bin", [0xB500, 0x2001, 0x3007, 0x3006, 0xBD00])
    r2 = BD.compare(a, imm, base=BASE, base_target=BASE)
    f2 = r2["functions"][0]
    check("E6 只改立即数 → RESIDUE(basis=insn_raw_norm, "
          "residue_kind=immediates_only)",
          f2["status"] == "RESIDUE" and f2["basis"] == "insn_raw_norm"
          and f2.get("residue_kind") == "immediates_only", f2)

    two = fw("bi_two.bin", [0xB500, 0x2001, 0x3100, 0x3101, 0xBD00])
    r3 = BD.compare(a, two, base=BASE, base_target=BASE, threshold=0.5)
    f3 = r3["functions"][0]
    check("E7 改两条指令 → 相似度兜底 RESIDUE(structural_shift) 并逐条列差异",
          f3["status"] == "RESIDUE" and f3["basis"] == "similarity"
          and f3.get("residue_kind") == "structural_shift"
          and len(f3["differences"]) == 2, f3)

    # 真镜像打补丁：唯一可复现的「配上了但 FAIL」
    raw = bytearray(open(AXF, "rb").read())
    off = 13240
    raw[off + 2] ^= 0x0F
    raw[off + 3] ^= 0x0F
    patched = _w(bytes(raw), "patched.axf")
    r4 = BD.compare(AXF, patched)
    fails = [f for f in r4["functions"] if f["status"] == "FAIL"]
    check("E8 真镜像改一个函数 → PASS 174 / FAIL 1",
          r4["counts"]["PASS"] == 174 and r4["counts"]["FAIL"] == 1, r4["counts"])
    check("E9 这条 FAIL 的 basis 是 name（不是相似度兜底），且指向 uart_printf",
          len(fails) == 1 and fails[0]["basis"] == "name"
          and fails[0]["left"]["name"] == "uart_printf", fails[:1])

    short = fw("bi_short.bin", [0xB500, 0x2001, 0xBD00])
    r5 = BD.compare(a, short, base=BASE, base_target=BASE)
    check("E10 n_insns < min_insns(4) 的函数不参与配对（落 missing_in_*，不硬配）",
          r5["counts"]["only_reference"] == 1 and r5["counts"]["only_target"] == 1
          and r5["counts"]["FAIL"] == 2, r5["counts"])

    w = BD.compare(a, a, base=BASE, base_target=BASE,
                   windows="GPIOA@0x40020000+0x400")
    win = w["windows"][0]
    check("E11 窗口写法 name@addr+size 能解析（偏移/次数对比）",
          win["name"] == "GPIOA" and win["size"] == 1024
          and win["verdict"] == "PASS" and win["reference_total"] == 0, win)
    badw = BD.compare(a, a, base=BASE, base_target=BASE, windows="bogus")
    check("E12 窗口写法认不出来就报错并给正确写法",
          badw["ok"] is False and "name@" in badw["error"], badw.get("error"))

    d = tmpdir()
    od = os.path.join(d, "reports")
    wr = BD.compare(a, imm, base=BASE, base_target=BASE, out_dir=od,
                    windows="GPIOA@0x40020000+0x400")
    check("E13 out_dir 落三份报告",
          wr["ok"] is True and wr["files"] == ["report.json", "report.md",
                                               "windows.csv"], wr.get("files"))
    files = {}
    for fn in ("report.json", "report.md", "windows.csv"):
        files[fn] = open(os.path.join(od, fn), "rb").read()
    check("E14 三份报告都不带 BOM",
          all(v[:3] != b"\xef\xbb\xbf" for v in files.values())
          and wr.get("wrote_bom") is False, {k: v[:6] for k, v in files.items()})
    j = json.loads(files["report.json"].decode("utf-8"))
    check("E15 report.json 带 evidence_only / artifact_kind / 文件清单",
          j.get("evidence_only") is True and j.get("artifact_kind") == "evidence"
          and j.get("evidence_only_files") == ["report.json", "report.md",
                                               "windows.csv"], list(j)[:6])
    check("E16 report.md 首行是 EVIDENCE ONLY 标记",
          files["report.md"].split(b"\n", 1)[0].find(b"EVIDENCE ONLY") >= 0,
          files["report.md"][:60])
    check("E17 windows.csv 有表头且列名稳定",
          files["windows.csv"].split(b"\n", 1)[0].startswith(
              b"window,start,end,verdict"), files["windows.csv"][:60])

    again = BD.compare(a, imm, base=BASE, base_target=BASE, out_dir=od)
    check("E18 out_dir 非空拒绝复用（不覆盖既有证据）",
          again["ok"] is False and "非空" in again.get("error", ""),
          again.get("error"))

    proj = tmpdir()
    os.makedirs(os.path.join(proj, "Core", "Src"))
    open(os.path.join(proj, "Core", "Src", "main.c"), "w", encoding="utf-8").write(
        "int main(void){return 0;}\n")
    guard = BD.compare(a, a, base=BASE, base_target=BASE,
                       out_dir=os.path.join(proj, "Core", "Src", "rep"))
    check("E19 报告也不许写进工程目录（同一道护栏）",
          guard["ok"] is False and guard.get("error_code") == "evidence-in-build-dir",
          str(guard)[:200])


# ---------------------------------------------------------------------------
# F stack
# ---------------------------------------------------------------------------
def section_f():
    print("\nF recover_stack：调用图与最坏调用链")
    reset, f2 = 0x08, 0x14
    code = struct.pack("<HH", 0xB580, 0xB082)
    code += _bl(reset + 4 + 4, f2)
    code += struct.pack("<HH", 0xB002, 0xBD80)
    code += struct.pack("<HHHH", 0xB5F0, 0xB090, 0xB010, 0xBCF0)
    two = _bin("st_two.bin", code)
    st = CG.analyze_stack(two, base=BASE, stack_size=512)
    worst = st["roots"][0]
    check("F1 合成两级调用：帧 16 + 84，最坏链 100 字节且 static_bound",
          worst["verdict"] == "static_bound"
          and worst["worst_depth_bytes"] == 100 and len(worst["chain"]) == 2, worst)
    check("F2 只有 static_bound 才给 fits/margin（512-32-100=380）",
          worst.get("fits") is True and worst.get("margin_bytes") == 380, worst)
    check("F3 frames.largest 按帧大小排序（最大 84、共 2 个）",
          st["frames"]["counted"] == 2 and st["frames"]["largest"][0]["frame"] == 84
          and st["frames"]["dynamic"] == 0, st["frames"]["largest"][:2])

    real = CG.analyze_stack(AXF)
    g = real["call_graph"]
    check("F4 真镜像调用图：175 节点 / 127 边 / 深度 8 / 无环",
          g["n_nodes"] == 175 and g["n_edges"] == 127
          and g["max_depth_levels"] == 8 and g["n_cycles"] == 0, g)
    check("F5 真镜像最坏根是 0x080030B0、384 字节、lower_bound",
          real["worst"]["root_hex"] == "0x080030B0"
          and real["worst"]["worst_depth_bytes"] == 384
          and real["worst"]["verdict"] == "lower_bound", real["worst"])
    check("F6 lower_bound 时不给 fits/margin（算不出来就不猜）",
          all("fits" not in r and "margin_bytes" not in r for r in real["roots"]),
          [r["verdict"] for r in real["roots"][:3]])
    check("F7 间接调用总数/涉及函数都报出来（不静默当成没调用）",
          real["indirect_calls"]["total"] == 24
          and real["indirect_calls"]["functions"] == 9
          and "下界" in real["indirect_calls"]["note"], real["indirect_calls"])

    rooted = CG.analyze_stack(AXF, roots="main")
    check("F8 roots=\"main\" 生效：main 进根列表且排在第一位",
          rooted["roots"][0]["name"] == "main", [r["name"] for r in rooted["roots"][:3]])
    check("F9 不传 stack_size 时 stack_size=0 且没有 fits",
          real["stack_size"] == 0
          and all("fits" not in r for r in real["roots"]), real["stack_size"])

    ind = _bin("st_ind.bin", struct.pack("<HHH", 0xB580, 0x4798, 0xBD80))
    si = CG.analyze_stack(ind, base=BASE, stack_size=1024)
    check("F10 链上有间接调用（blx r3）→ lower_bound、逐条列解析不了的点、不给 fits",
          si["roots"][0]["verdict"] == "lower_bound"
          and si["roots"][0].get("indirect_sites")
          and "fits" not in si["roots"][0], si["roots"][0])

    # 两个函数互相 BL，构成 2 节点环（帧 16 + 16）
    c1 = struct.pack("<HH", 0xB580, 0xB082) + _bl(0x10, 0x14) + struct.pack("<HH", 0xB002, 0xBD80)
    c2 = struct.pack("<HH", 0xB580, 0xB082) + _bl(0x1C, 0x08) + struct.pack("<HH", 0xB002, 0xBD80)
    cyc = _bin("st_cyc.bin", c1 + c2)
    sc = CG.analyze_stack(cyc, base=BASE, stack_size=1024)
    check("F11 调用链上有环 → unbounded（递归没有静态上界，不硬凑数字）",
          sc["roots"][0]["verdict"] == "unbounded"
          and sc["call_graph"]["n_cycles"] == 1, (sc["roots"][0], sc["call_graph"]))

    dyn = _bin("st_dyn.bin", struct.pack("<HHHH", 0xB580, 0x46BD, 0x46BD, 0xBD80))
    sd = CG.analyze_stack(dyn, base=BASE)
    check("F12 mov sp,rX → 记为动态帧（frames.dynamic 计数，不静默给数）",
          sd["frames"]["dynamic"] == 1, sd["frames"])

    check("F13 规则里写清「异常入栈 32 字节已预留」",
          any("32" in x for x in sc["rule"]), sc["rule"])


# ---------------------------------------------------------------------------
# G vector_table(skip_empty)
# ---------------------------------------------------------------------------
def section_g():
    print("\nG vector_table(skip_empty)：保留槽位跳过而不终止")
    words = [0x20005000]
    words += [BASE + 0x40 + (i - 1) * 4 for i in range(1, 7)]
    words += [0, 0, 0, 0]                    # Cortex-M 保留槽位 7..10
    words += [BASE + 0x60, 0xDEADBEEF]       # 11 有效 / 12 非代码
    blob = b"".join(struct.pack("<I", w) for w in words)
    blob += b"\x00" * (0x200 - len(blob))
    u = RC._unit_from_data(blob, "vt", BASE)

    vt = RC.vector_table(u, base=BASE, skip_empty=True)
    check("G1 skip_empty=True：保留槽位 7..10 记进 empty 但不终止",
          vt["empty"] == [7, 8, 9, 10] and vt["count"] == 7, (vt["empty"], vt["count"]))
    check("G2 跳过空槽后仍读到了 11 号槽（否则 SysTick/外设入口整片丢）",
          vt["entries"][-1]["index"] == 11, vt["entries"][-1])
    check("G3 遇到非代码地址才终止，并写 gaps 说明",
          len(vt["gaps"]) == 1 and "非代码地址" in vt["gaps"][0]["reason"], vt["gaps"])

    vt2 = RC.vector_table(u, base=BASE)
    check("G4 skip_empty=False 行为不变（读到 0 就停，count=6、empty 空）",
          vt2["count"] == 6 and vt2["empty"] == [] and vt2["gaps"] == [],
          (vt2["count"], vt2["empty"]))

    real = RC.vector_table(RC._unit_from_data(open(AXF, "rb").read(), "axf", BASE),
                           base=BASE, skip_empty=True)
    check("G5 真 axf 的复位地址是 Reset_Handler(0x080002E0|1)、SP 是 RAM 地址",
          real["reset"] in (0x080002E1, 0x080002E0)
          and 0x20000000 <= real["sp"] < 0x20080000, (real["sp_hex"], real["reset"]))


# ---------------------------------------------------------------------------
# H 文档与零依赖
# ---------------------------------------------------------------------------
def section_h():
    print("\nH 文档与零依赖闸门")
    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    skill = io.open(os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md"),
                    encoding="utf-8").read()
    check("H1 README 当前总数同步到 220", "220 个工具" in readme, None)
    check("H2 README 的默认收起数同步到 176", "176 个" in readme, None)
    check("H3 README 提到五个新工具名",
          all(n in readme for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in readme])
    check("H4 SKILL 同步到 220 个工具", "220 个工具" in skill, None)
    build_row = [ln for ln in readme.splitlines()
                 if ln.startswith("| `build` |")]
    check("H5 README build 组规模同步到 36 个（且列了新工具）",
          len(build_row) == 1 and "（36 个）" in build_row[0]
          and "调用图栈深" in build_row[0], build_row[:1])

    gates = io.open(os.path.join(ROOT, "tools", "run_all_tests.py"),
                    encoding="utf-8").read()
    check("H6 全量闸门里登记了 test_batch102", '"test_batch102",' in gates, None)

    stdlib = {"os", "re", "sys", "json", "struct", "math", "hashlib", "difflib",
              "base64", "binascii", "collections", "itertools", "shutil",
              "tempfile", "time", "copy", "io"}
    bad = []
    for mod in ("semantics.py", "bindiff.py", "callgraph.py"):
        src = io.open(os.path.join(ROOT, "mdkdebug", mod), encoding="utf-8").read()
        for m in re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", src, re.M):
            top = m.split(".")[0]
            if top and top not in stdlib and top != "mdkdebug":
                bad.append("%s: %s" % (mod, m))
    check("H7 三个新模块零新增依赖（只用标准库 + 包内模块）", not bad, bad)

    bad2 = []
    for mod in ("semantics.py", "bindiff.py"):
        src = io.open(os.path.join(ROOT, "mdkdebug", mod), encoding="utf-8").read()
        if "utf-8-sig" in src:
            bad2.append(mod)
        if re.search(r'open\([^)]*,\s*"w"', src):
            bad2.append(mod + ": 裸 open(...,\"w\")")
    check("H8 写盘一律走 textio（不裸 open + 不用 utf-8-sig，免得 BOM）",
          not bad2, bad2)

    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    check("H9 五个工具在 server.py 里都有 @server.tool 定义",
          all(('name="%s"' % n) in src for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if ('name="%s"' % n) not in src])
    check("H10 strings 描述里的开关都在签名上（code_strings/include_dropped）",
          "code_strings: bool = False" in src
          and "include_dropped: bool = False" in src, None)


# ---------------------------------------------------------------------------
def main():
    if not os.path.isfile(AXF):
        print("缺夹具镜像：%s" % AXF)
        return 2
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    section_h()
    for d in TMP:
        for root, _dirs, names in os.walk(d, topdown=False):
            for nm in names:
                try:
                    os.remove(os.path.join(root, nm))
                except OSError:
                    pass
            try:
                os.rmdir(root)
            except OSError:
                pass
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：%s" % "、".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
