# -*- coding: utf-8 -*-
"""批次97 测试：工程管理文件的编码纪律（体检 + 安全写入）。

用户报的现象：**不止一起**——AI 改 Keil 工程文件（``.uvprojx``/``.uvoptx``）时没注意
编码格式，写回后 uVision 打开工程异常。这类损坏在编辑器里看不出来，只在字节层面成立：

  * BOM 被丢（``utf-8-sig`` 读入、``utf-8`` 写出）；
  * CRLF 被换成 LF，或往 CRLF 文件里插进 LF 行 → 同一文件两种行尾；
  * 解码时走 ``latin-1``/``errors="replace"`` 兜底，写回时编不出的字符被静默写成 ``?``；
  * 写完不回读，于是「写入没报错」被当成「文件正确」。

本批把纪律做成**工具能执行的约束**（不只是写在 SKILL 里的一句话）：

  A 体检：编码/BOM/行尾/混合行尾/非 ASCII/U+FFFD/XML 可解析/sha256
  B 安全写入：往返校验、原编码严格编码、XML 校验、原子写、写后回读
  C 三个写入接入点（uvprojx / uvoptx / cmdscript）全部改走安全写入器
  D 工具层：project_file_check 只读体检工具（220 个工具、在 build 组、不在默认面）
  E 文档纪律：SKILL 硬规则 + PITFALLS + README
  F 闸门：零新增依赖

运行：python -m tests.test_batch97
"""
import asyncio
import hashlib
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# 单跑时默认只暴露 core 组，D 段要调 build 组的工具——先要全量（run_all 也这么做）
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import projectfile as PF      # noqa: E402
from mdkdebug import uvoptx as UO           # noqa: E402
from mdkdebug import uvprojx as UP          # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402

PASS, FAIL = [], []
TMP = []

REAL_PROJ = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvprojx")
REAL_OPTX = os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test.uvoptx")


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else "-> %r" % (detail,)))


def tmpdir(prefix="mdk97_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def put(name, data: bytes):
    p = os.path.join(tmpdir(), name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def real_raw():
    with open(REAL_PROJ, "rb") as f:
        return f.read()


def copy_real(name="copy.uvprojx"):
    return put(name, real_raw())


def rbytes(p):
    with open(p, "rb") as f:
        return f.read()


MIXED_UVOPTX = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="no" ?>\r\n'
    b'<ProjectOpt>\r\n'
    b'  <Target>\r\n'
    b'    <TargetName>Demo</TargetName>\r\n'
    b'    <Breakpoint>\r\n'
    b'      <Bp>\r\n        <Number>0</Number>\r\n        <Type>0</Type>\r\n'
    b'        <LineNumber>7</LineNumber>\r\n'
    b'        <Filename>..\\Src\\main.c</Filename>\r\n'
    b'      </Bp>\r\n'
    b'      <Bp>\r\n        <Number>1</Number>\r\n        <Type>0</Type>\r\n'
    b'        <LineNumber>9</LineNumber>\r\n'
    b'        <Filename>..\\Src\\main.c</Filename>\r\n'
    b'      </Bp>\r\n'
    b'    </Breakpoint>\r\n'
    b'  </Target>\r\n'
    b'</ProjectOpt>\r\n'
)


# ----------------------------------------------------------------------
# A. 体检
# ----------------------------------------------------------------------
def section_a():
    print("A. 体检：编码 / BOM / 行尾 / XML")
    raw = real_raw()
    p = copy_real()
    r = PF.inspect(p)
    check("A1 真实 .uvprojx：LF / 无 BOM / ASCII / XML 可解析 / level=ok",
          r["ok"] and r["newline"] == "LF" and r["bom"] == ""
          and r["non_ascii_bytes"] == 0 and r["xml_ok"] and r["level"] == "ok", r)

    r2 = PF.inspect(REAL_OPTX)
    check("A2 真实 .uvoptx：CRLF / 有 9 个非 ASCII 字节 / roundtrip_ok",
          r2["ok"] and r2["newline"] == "CRLF" and r2["non_ascii_bytes"] == 9
          and r2["roundtrip_ok"] and r2["xml_ok"], r2)
    check("A3 同一工程两种行尾要分别如实报告（不能统一格式化）",
          r["newline"] == "LF" and r2["newline"] == "CRLF", (r["newline"], r2["newline"]))

    p_bom = put("bom.uvprojx", b"\xef\xbb\xbf" + raw.replace(b"\r\n", b"\n")
                .replace(b"\n", b"\r\n"))
    rb = PF.inspect(p_bom)
    check("A4 UTF-8 BOM + CRLF 能检出（bom=utf-8 / newline=CRLF / xml_ok）",
          rb["bom"] == "utf-8" and rb["newline"] == "CRLF" and rb["xml_ok"], rb)

    # GBK：真实中文工程常见形态——XML 声明写着 UTF-8，字节却是 GBK
    gbk = raw.decode("utf-8").replace("<TargetName>", "<TargetName>中文_").encode("gbk")
    p_gbk = put("gbk.uvprojx", gbk)
    rg = PF.inspect(p_gbk)
    check("A5 GBK 工程：解出 gbk、XML 仍判可解析（不因声明写 UTF-8 就误判损坏）",
          rg["encoding"] == "gbk" and rg["xml_ok"] and rg["level"] == "ok", rg)

    p_bad = put("trunc.uvprojx", raw[:5000])
    rbad = PF.inspect(p_bad)
    check("A6 截断文件：xml_ok=False、level=error 且 notes 说明 uVision 打不开",
          (not rbad["xml_ok"]) and rbad["level"] == "error"
          and any("XML" in n for n in rbad["notes"]), rbad)

    damaged = raw.replace(b"<TargetName>", b"<TargetName>\xef\xbf\xbd", 1)
    p_dmg = put("fffd.uvprojx", damaged)
    rdmg = PF.inspect(p_dmg)
    check("A7 检出 U+FFFD（曾被 errors='replace' 写过的典型痕迹）并判 error",
          rdmg["replacement_chars"] == 1 and rdmg["level"] == "error"
          and any("U+FFFD" in n for n in rdmg["notes"]), rdmg)

    crlf_raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    p_mix = put("mixed.uvprojx", crlf_raw.replace(b"<TargetName>",
                                                 b"<TargetName>\n", 1))
    rmix = PF.inspect(p_mix)
    check("A8 混合行尾被检出并判 warn（不顺手统一，但会提示）",
          rmix["mixed_newline"] and rmix["level"] == "warn", rmix)

    check("A9 sha256/size 与实际字节一致",
          r["sha256"] == hashlib.sha256(raw).hexdigest() and r["size"] == len(raw),
          (r["sha256"], r["size"]))


# ----------------------------------------------------------------------
# B. 安全写入
# ----------------------------------------------------------------------
def section_b():
    print("B. 安全写入：往返校验 / 严格编码 / XML / 原子写 / 写后回读")

    # B1 BOM + CRLF 文件插入新行：**BOM 去掉**（批次100 纠正）、行尾按 CRLF 补齐。
    # 批次97 时以为 BOM 必须原样保留；真机事实相反——带 BOM 的 .uvprojx uVision 打不开
    # （命令行只回 exit 15）。所以写入时顺手去掉 BOM，并在结果里报告。
    raw = real_raw().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    p = put("bom_crlf.uvprojx", b"\xef\xbb\xbf" + raw)
    r = UP.add_files(p, "Core", ["..\\Core\\Src\\added.c"])
    b = rbytes(p)
    txt = b.decode("utf-8")
    check("B1 带 BOM 的工程写入后 BOM 被去掉（否则 uVision 打不开）、裸 LF 数为 0、"
          "新增行按 CRLF 补齐",
          r.get("ok") and r.get("changed") and not b.startswith(b"\xef\xbb\xbf")
          and r.get("bom_stripped") == "utf-8"
          and (b.count(b"\n") - b.count(b"\r\n")) == 0
          and r.get("verify") == "byte-identical", r)
    # 批次99：上面那条断言**抓不住**「换行被写成字面量 LF」——字面量也不会产生裸 LF。
    # 真正的判据是：写进去的每个结构行都单独成行，且文件里没有字面量痕迹。
    check("B1b 新增的文件项是真换行、不是字面量（<File> / <FileName> 各自独占一行）",
          "\r\n            <File>\r\n" in txt
          and "<FileName>added.c</FileName>\r\n" in txt
          and ">LF" not in txt and ">CRLF" not in txt
          and PF.count_literal_newlines(txt) == 0, txt[txt.find("added.c") - 120:][:200])

    # B2 除改动区外其余字节不变
    p2 = copy_real("diff.uvprojx")
    before = rbytes(p2)
    r2 = UP.add_defines(p2, "BATCH97_FLAG")
    after = rbytes(p2)
    check("B2 add_defines 只改 <Define> 一处，其余字节完全不变",
          r2.get("ok") and "BATCH97_FLAG" in (r2.get("after") or "")
          and after.replace(b",BATCH97_FLAG", b"") == before
          and len(after) - len(before) == 13, r2.get("error"))
    check("B3 返回值带文件格式事实（encoding/newline/verify/sha256）",
          r2.get("encoding") == "utf-8" and r2.get("newline") == "LF"
          and r2.get("verify") == "byte-identical"
          and r2.get("sha256_after") == hashlib.sha256(after).hexdigest(), r2)

    # B4 GBK 工程写入后中文仍是 GBK 字节
    gbk = real_raw().decode("utf-8").replace("<TargetName>", "<TargetName>中文_").encode("gbk")
    p3 = put("gbk.uvprojx", gbk)
    r3 = UP.add_defines(p3, "ABC")
    check("B4 GBK 工程：写入后中文仍是 GBK 字节、encoding 仍是 gbk",
          r3.get("ok") and r3.get("encoding") == "gbk"
          and "中文_".encode("gbk") in rbytes(p3), r3)

    # B5 编不出的字符：拒绝写，文件一字不动
    p4 = put("gbk2.uvprojx", gbk)
    text, _meta = PF.read_text(p4)
    snap = rbytes(p4)
    res = PF.write_text(p4, text.replace("<TargetName>", "<TargetName>\U00020000"),
                        old_text=text)
    check("B5 字符无法用原编码表示时拒绝写（encode-failed），不再写成 '?'",
          (not res.get("ok")) and res.get("error_code") == "encode-failed"
          and rbytes(p4) == snap, res.get("error"))
    check("B6 错误里点名「旧实现会用 errors='replace'」以解释为什么不再兜底",
          "replace" in (res.get("error") or ""), res.get("error"))

    # B7 old_text 与实际不符：拒绝写（防「读到的是被 replace 过的文本」）
    p5 = copy_real("stale.uvprojx")
    snap5 = rbytes(p5)
    res5 = PF.write_text(p5, "whatever", old_text="not-the-file")
    check("B7 往返校验失败（old_text 编不回原始字节）→ stale-content，不落盘",
          (not res5.get("ok")) and res5.get("error_code") == "stale-content"
          and rbytes(p5) == snap5, res5.get("error"))

    # B8 expected_sha 不符：拒绝写（并发保护）
    res8 = PF.write_text(p5, "whatever", old_text=snap5.decode("utf-8"),
                         expected_sha="deadbeef")
    check("B8 expected_sha 不符 → stale-sha，不落盘",
          (not res8.get("ok")) and res8.get("error_code") == "stale-sha"
          and rbytes(p5) == snap5, res8.get("error"))

    # B9 改坏 XML：拒绝写
    text5, _m = PF.read_text(p5)
    res9 = PF.write_text(p5, text5.replace("</Target>", "", 1), old_text=text5)
    check("B9 改后不是可解析 XML → xml-invalid，不落盘（uVision 会打不开）",
          (not res9.get("ok")) and res9.get("error_code") == "xml-invalid"
          and rbytes(p5) == snap5, res9.get("error"))

    # B10 无变化：不写文件
    text10, _m10 = PF.read_text(p5)
    res10 = PF.write_text(p5, text10, old_text=text10)
    check("B10 内容无变化时 changed=False，不写文件",
          res10.get("ok") and res10.get("changed") is False and rbytes(p5) == snap5, res10)

    # B11 备份与原始字节相同
    p11 = copy_real("bak.uvprojx")
    snap11 = rbytes(p11)
    r11 = UP.add_defines(p11, "BAK_CHECK")
    bak = r11.get("backup")
    check("B11 写入前备份、备份内容与原始字节逐字节相同",
          bak and os.path.isfile(bak) and rbytes(bak) == snap11, bak)

    # B12 原子写不留残骸
    junk = [n for n in os.listdir(os.path.dirname(p11)) if n.startswith(".mdkdebug_")]
    check("B12 原子写不留临时文件残骸", not junk, junk)


# ----------------------------------------------------------------------
# C. 三个写入接入点
# ----------------------------------------------------------------------
def section_c():
    print("C. 接入点：uvprojx / uvoptx / cmdscript 全走安全写入器")

    p = copy_real("inc.uvprojx")
    r1 = UP.add_include_path(p, ["..\\Core\\Inc97"])
    r2 = UP.del_include_path(p, r"Inc97")
    r3 = UP.set_debug_information(p, True)
    check("C1 uvprojx 写操作都返回 encoding/newline/verify=byte-identical",
          all(x.get("ok") for x in (r1, r2, r3))
          and r1.get("changed") and r2.get("changed")
          and r1.get("verify") == "byte-identical"
          and r1.get("encoding") == "utf-8" and r1.get("newline") == "LF", (r1, r2, r3))

    p2 = put("probe.uvoptx", MIXED_UVOPTX)
    r4 = UO.clear_uvoptx_breakpoints(p2)
    b = rbytes(p2)
    check("C2 uvoptx 清断点：CRLF 保住（裸 LF=0）、XML 仍可解析、removed=2",
          r4.get("ok") and r4.get("changed") and r4.get("removed") == 2
          and (b.count(b"\n") - b.count(b"\r\n")) == 0
          and PF.inspect(p2)["xml_ok"], r4)

    src_up = io.open(UP.__file__, encoding="utf-8").read()
    src_uo = io.open(UO.__file__, encoding="utf-8").read()
    src_cs = io.open(os.path.join(ROOT, "mdkdebug", "cmdscript.py"),
                     encoding="utf-8").read()
    check("C3 uvprojx.py 已无「文本模式裸写」的代码行，改走 projectfile.write_text",
          'with open(path, "w"' not in src_up
          and 'errors="replace", newline="") as f' not in src_up
          and "projectfile.write_text" in src_up)
    check("C4 uvoptx.py 改走 projectfile.write_text",
          "projectfile.write_text" in src_uo)
    check("C5 cmdscript.py 挂 <tIfile> 也走 projectfile.write_text（跑完仍按字节还原）",
          "projectfile.write_text" in src_cs
          and 'with open(uvoptx_path, "w"' not in src_cs
          and 'raw_before' in src_cs and "byte_identical" in src_cs)


# ----------------------------------------------------------------------
# D. 工具层
# ----------------------------------------------------------------------
def section_d():
    print("D. 工具层：project_file_check（只读）")
    from mdkdebug import server as SV

    async def run():
        srv = SV.create_server()
        tools = await srv.list_tools()
        names = sorted(t.name for t in tools)

        async def _call(args):
            res = await srv.call_tool("project_file_check", args)
            payload = res[0][0].text if isinstance(res, tuple) else res.content[0].text
            return json.loads(payload)

        out = {"count": len(names),
               "check": await _call({"project": REAL_PROJ}),
               "dir": await _call({"project": os.path.dirname(REAL_PROJ)})}
        return names, out

    names, out = asyncio.run(run())
    check("D1 project_file_check 已注册，工具总数 220",
          "project_file_check" in names and out["count"] == 220, out["count"])
    check("D2 在 build 组、不在默认面（会写工程的工具都不进默认面）",
          "project_file_check" in TB.TOOLSETS["build"]
          and "project_file_check" not in TB.TOOLSETS["core"], None)
    c = out["check"]
    check("D3 工具返回 .uvprojx + 同名 .uvoptx 两份体检（count=2）并给 level",
          c.get("ok") and c.get("count") == 2 and c.get("level") == "ok"
          and {f["newline"] for f in c["files"]} == {"LF", "CRLF"}, c.get("files"))
    check("D4 给目录时自动找出工程文件",
          out["dir"].get("ok") and out["dir"].get("count", 0) >= 1, out["dir"].get("error"))
    check("D5 返回里带「改工程走 uvprojx_edit」的纪律提示",
          "uvprojx_edit" in (c.get("next") or ""), c.get("next"))


# ----------------------------------------------------------------------
# G. 读入口自带格式基线（一眼看清，不用跑两趟）
# ----------------------------------------------------------------------
def section_g():
    print("G. 读入口自带格式基线：uvprojx_read / read_project_config / list_uvoptx_breakpoints")
    from mdkdebug import server as SV

    # 造一份「已损坏」的工程副本（截断），验证读入口会提醒
    broken = put("broken.uvprojx", real_raw()[:5000])

    async def run():
        srv = SV.create_server()

        async def _call(tool, args):
            res = await srv.call_tool(tool, args)
            payload = res[0][0].text if isinstance(res, tuple) else res.content[0].text
            return json.loads(payload)

        return {
            "read": await _call("uvprojx_read", {"project": REAL_PROJ, "what": "targets"}),
            "cfg": await _call("read_project_config", {"project": REAL_PROJ}),
            "optx": await _call("list_uvoptx_breakpoints", {"project": REAL_PROJ}),
            "broken": await _call("uvprojx_read", {"project": broken}),
        }

    out = asyncio.run(run())
    ff = out["read"].get("file_format") or {}
    ref = PF.describe(REAL_PROJ)
    check("G1 uvprojx_read 返回 file_format，sha256/encoding/newline 与项目体检一致",
          out["read"].get("ok") and ff.get("sha256") == ref["sha256"]
          and ff.get("encoding") == ref["encoding"] and ff.get("newline") == ref["newline"]
          and ff.get("level") == "ok", ff)
    check("G2 read_project_config 也带 file_format（读配置不必再跑一趟查格式）",
          out["cfg"].get("file_format", {}).get("sha256") == ref["sha256"],
          out["cfg"].get("file_format"))
    check("G3 list_uvoptx_breakpoints 带 .uvoptx 的 file_format（CRLF/非 ASCII 如实报告）",
          (out["optx"].get("file_format") or {}).get("newline") == "CRLF"
          and (out["optx"].get("file_format") or {}).get("non_ascii_bytes") == 9,
          out["optx"].get("file_format"))
    check("G4 被截断的工程：uvprojx_read 仍返回配置，但带 file_format_warning",
          out["broken"].get("ok") and "file_format_warning" in out["broken"]
          and out["broken"]["file_format"].get("xml_ok") is False,
          out["broken"].get("file_format_warning"))

    src = io.open(os.path.join(ROOT, "mdkdebug", "server.py"), encoding="utf-8").read()
    seg = src[src.find('name="uvprojx_edit"'):][:6000]
    order = [m for m in ("1. **先读后写", "2. **一定留着备份", "3. **改完要重编译",
                         "4. **Keil 开着同一工程", "5. **写回时不碰编码")
             if m in seg]
    pos = [seg.find(m) for m in order]
    check("G5 uvprojx_edit 文档里 5 条约定按序（改代码时别把编号插乱）",
          len(order) == 5 and pos == sorted(pos), pos)


# ----------------------------------------------------------------------
# H. 字面量换行：检出 + 修复（批次99 回归，防止「把行尾标签写进文件」）
# ----------------------------------------------------------------------
def section_h():
    print("H. 字面量换行（>LF / >CRLF）：真正的换行 vs 写进文件的标签")
    raw = real_raw()
    txt0 = raw.decode("utf-8")

    # H1 LF 文件：add_files 插入的多行必须各自成行
    p = put("lf.uvprojx", raw)
    r = UP.add_files(p, "Core", ["..\\Core\\Src\\h1.c"])
    txt = rbytes(p).decode("utf-8")
    check("H1 LF 文件里 add_files：<File>/<FileName>/<FileType> 各自独占一行、无字面量",
          r.get("ok") and r.get("changed")
          and "\n            <File>\n" in txt
          and "<FileName>h1.c</FileName>\n" in txt
          and PF.count_literal_newlines(txt) == 0, txt[txt.find("h1.c") - 100:][:180])

    # H2 CRLF 文件：同样，且不能混进裸 LF
    p2 = put("crlf.uvprojx", raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    r2 = UP.add_files(p2, "Core", ["..\\Core\\Src\\h2.c"])
    b2 = rbytes(p2)
    check("H2 CRLF 文件里 add_files：行尾仍是 CRLF（裸 LF=0）、无字面量",
          r2.get("ok") and (b2.count(b"\n") - b2.count(b"\r\n")) == 0
          and PF.count_literal_newlines(b2.decode("utf-8")) == 0, r2)

    # H3 把标签当分隔符传进去，必须当场报错（而不是写出字面量）
    threw = None
    try:
        PF.normalize_inserted_newlines("a\nb", "a\nX\nb", "LF")
    except ValueError as e:
        threw = str(e)
    check("H3 normalize 收到标签（'LF'）而不是换行符时抛 ValueError，不再静默写坏",
          threw is not None and "newline_seq" in threw, threw)

    # H4 体检能认出这种损坏（XML 仍是合法的，只能靠签名）
    broken = txt0.replace("</Group>\n", "</Group>LF")
    p4 = put("broken.uvprojx", broken.encode("utf-8"))
    r4 = PF.inspect(p4)
    check("H4 体检检出字面量换行：literal_newline_suspects>0、level=error，但 xml_ok 仍为 true",
          r4["literal_newline_suspects"] > 0 and r4["level"] == "error"
          and r4["xml_ok"] is True
          and any("字面量" in n for n in r4["notes"]), r4)

    # H5 dry_run 默认不写
    snap = rbytes(p4)
    r5 = PF.repair_literal_newlines(p4)
    check("H5 修复默认 dry_run：报处数与前几处上下文，但文件一字不动",
          r5.get("ok") and (r5.get("found") or {}).get("literal_newlines", 0) > 0
          and r5.get("changed") is False
          and r5.get("samples") and rbytes(p4) == snap, r5)

    # H6 真修：换行回来、XML 仍合法、有备份
    r6 = PF.repair_literal_newlines(p4, dry_run=False)
    fixed_txt = rbytes(p4).decode("utf-8")
    check("H6 真修：字面量清零、换行恢复、XML 仍可解析、备份存在",
          r6.get("ok") and r6.get("changed") and r6.get("verify") == "byte-identical"
          and PF.count_literal_newlines(fixed_txt) == 0
          and PF.inspect(p4)["xml_ok"] and os.path.isfile(r6.get("backup") or "")
          and r6.get("message", "").startswith("已修复"), r6)

    # H7 文件名里的 LF 不能被误伤
    p7 = put("path.uvprojx", txt0.replace("../Core/Src/main.c", "../Core/LF/main.c")
             .encode("utf-8"))
    r7 = PF.repair_literal_newlines(p7, dry_run=False)
    check("H7 只动「标签之间」的位置：<FilePath> 里的 LF 不被误改",
          r7.get("ok") and "../Core/LF/main.c" in rbytes(p7).decode("utf-8"), r7)

    # H8 工具层：注册 + 默认试跑
    from mdkdebug import server as SV

    async def run():
        srv = SV.create_server()
        tools = await srv.list_tools()
        names = sorted(t.name for t in tools)

        async def _call(tool, args):
            res = await srv.call_tool(tool, args)
            payload = res[0][0].text if isinstance(res, tuple) else res.content[0].text
            return json.loads(payload)

        snap_before = rbytes(p4)
        out = await _call("project_file_repair", {"project": p4})
        return names, out, rbytes(p4) == snap_before

    names, out, untouched = asyncio.run(run())
    check("H8 project_file_repair 已注册（工具总数 220），默认 dry_run 且不写文件",
          "project_file_repair" in names and len(names) == 220
          and out.get("dry_run") is True
          and all(f.get("changed") is False for f in out.get("files") or [])
          and untouched, out)


# ----------------------------------------------------------------------
# I. 批次100：BOM（uVision 打不开的真因）+ 逐行拼装 + 退出码 15
# ----------------------------------------------------------------------
def section_i():
    print("I. BOM / 逐行拼装 / 退出码 15")
    raw = real_raw()
    txt0 = raw.decode("utf-8")
    bom_raw = b"\xef\xbb\xbf" + raw

    # I1 体检：BOM 必须判 error（旧实现只报 bom: utf-8 并说 ok）
    p1 = put("bom.uvprojx", bom_raw)
    r1 = PF.inspect(p1)
    check("I1 体检把 BOM 判为 error（旧实现 level=ok，漏检了真正让 uVision 打不开的原因）",
          r1["bom"] == "utf-8" and r1["level"] == "error"
          and any("BOM" in n and "exit 15" in n for n in r1["notes"]), r1["notes"])

    # I2 任何写入口写一次就去掉 BOM（不留「打不开的工程」）
    r2 = PF.write_text(p1, txt0)
    after2 = rbytes(p1)
    check("I2 write_text 顺手去掉 UTF-8 BOM：报告 bom_stripped，磁盘上确实没有 BOM 了",
          r2.get("ok") and r2.get("bom_stripped") == "utf-8"
          and not after2.startswith(b"\xef\xbb\xbf")
          and r2.get("verify") == "byte-identical", r2)

    # I3 修复工具默认试跑：报 BOM，不写
    p3 = put("bom2.uvprojx", bom_raw)
    snap3 = rbytes(p3)
    r3 = PF.repair_project_file(p3)
    check("I3 repair_project_file 默认 dry_run：found.bom 报出来但不写文件",
          r3.get("ok") and (r3.get("found") or {}).get("bom") == "utf-8"
          and r3.get("changed") is False and rbytes(p3) == snap3, r3)

    # I4 真修：BOM 去掉、XML 仍合法、有备份
    r4 = PF.repair_project_file(p3, dry_run=False)
    check("I4 真修 BOM：去掉、XML 仍可解析、备份存在、message 说明修了什么",
          r4.get("ok") and r4.get("changed") and (r4.get("repaired") or {}).get("bom") == "utf-8"
          and not rbytes(p3).startswith(b"\xef\xbb\xbf")
          and PF.inspect(p3)["xml_ok"] and os.path.isfile(r4.get("backup") or "")
          and "BOM" in (r4.get("message") or ""), r4)

    # I5 两类缺陷一次修完
    p5 = put("both.uvprojx", ("\ufeff" + txt0.replace("</Group>\n", "</Group>LF"))
             .encode("utf-8"))
    r5 = PF.repair_project_file(p5)
    r5b = PF.repair_project_file(p5, dry_run=False)
    check("I5 BOM + 字面量换行同时存在时，一次修复两类并各自报数",
          (r5.get("found") or {}).get("bom") == "utf-8"
          and (r5.get("found") or {}).get("literal_newlines", 0) > 0
          and (r5b.get("repaired") or {}).get("bom") == "utf-8"
          and (r5b.get("repaired") or {}).get("literal_newlines", 0) > 0
          and PF.count_literal_newlines(rbytes(p5).decode("utf-8")) == 0, r5b)

    # I6 缩进跟着工程走：4 空格的工程不会被塞进 8 空格
    # 只缩进 XML 结构行（`<File>` 的替换会顺带命中 `<FilePath>`，必须显式列全标签）
    txt4 = re.sub(r"\n( +)(</?File>|<FileName>|<FileType>|<FilePath>|<Groups>|</Groups>"
                  r"|<Group>|</Group>|<GroupName>|<Files>|</Files>)",
                  lambda m: "\n" + m.group(1)[:-4] + m.group(2), txt0)
    p6 = put("indent4.uvprojx", txt4.encode("utf-8"))
    r6 = UP.add_files(p6, "Core", ["..\\Core\\Src\\i6.c"])
    t6 = rbytes(p6).decode("utf-8")
    seg6 = t6[t6.find("<FileName>i6.c</FileName>") - 60:t6.find("<FilePath>..\\Core\\Src\\i6.c") + 40]
    check("I6 add_files 的缩进取自工程本身（缩进 4 格后的工程写 8/10 空格，"
          "不再写死旧的 12/14）",
          r6.get("ok") and "\n        <File>\n          <FileName>i6.c</FileName>\n" in t6
          and "\n            <File>" not in t6, seg6)

    # I7 结构行各自独占一行（LF 与 CRLF 两种文件都成立）
    p7 = put("lines.uvprojx", raw)
    UP.add_files(p7, "Core", ["..\\Core\\Src\\i7.c"])
    t7 = rbytes(p7).decode("utf-8")
    i7 = t7.find("<FileName>i7.c</FileName>")
    blk7 = t7[i7 - 40:i7 + 160]
    check("I7 逐行拼装：<File>/<FileName>/<FileType>/<FilePath>/</File> 各占一行、无标签残渣",
          blk7.count("\n") >= 4 and "LF <" not in blk7 and ">LF" not in blk7
          and PF.count_literal_newlines(t7) == 0, blk7)

    # I8 退出码 15 的官方含义（读工程失败），不能再报成「被占用」
    from mdkdebug import builder as BD
    acts = BD._exit_next_actions(15)
    check("I8 退出码 15 = project-read-failed，next_actions 指向 project_file_check/repair",
          BD._exit_meaning(15) == "project-read-failed"
          and any("project_file_check" in a for a in acts)
          and any("project_file_repair" in a for a in acts), acts)

    # I9 错误归桶也认得这条
    from mdkdebug import errors as ER
    code = ER.classify_error("*** Error: error reading the project file")
    check("I9 报错文本「error reading the project file」归到 project-unreadable 桶",
          code == "project-unreadable", code)

# ----------------------------------------------------------------------
# E. 文档纪律
# ----------------------------------------------------------------------
def section_e():
    print("E. 文档：把纪律写成 AI 能照做的检查清单")
    skill = io.open(os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md"),
                    encoding="utf-8").read()
    pitfalls = io.open(os.path.join(ROOT, "docs", "PITFALLS.md"), encoding="utf-8").read()
    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("E1 SKILL 有「工程管理文件编辑纪律」硬规则段", "工程管理文件编辑纪律" in skill)
    check("E2 SKILL 点名 project_file_check 与 uvprojx_edit 的组合用法",
          "project_file_check" in skill and "uvprojx_edit" in skill)
    check("E3 SKILL 明确禁止：文本工具整体重写 / 统一行尾 / 丢 BOM",
          "整体重写" in skill and "行尾" in skill and "BOM" in skill)
    check("E4 PITFALLS 五十九讲编码/BOM/行尾是内容的一部分",
          "五十九" in pitfalls and "BOM" in pitfalls and "行尾" in pitfalls)
    check("E5 README 记录 project_file_check 与本批的写入校验",
          "project_file_check" in readme)
    check("E6 SKILL 讲明「BOM = 打不开」与 exit 15，README/PITFALLS 记录批次100",
          "BOM" in skill and "exit 15" in skill and "bom_stripped" in skill
          and "六十一" in pitfalls and "bom_stripped" in readme)


# ----------------------------------------------------------------------
# F. 闸门
# ----------------------------------------------------------------------
def section_f():
    print("F. 闸门：零新增依赖")
    src = io.open(PF.__file__, encoding="utf-8").read()
    imports = [ln for ln in src.splitlines()
               if ln.startswith("import ") or ln.startswith("from ")]
    allowed = ("codecs", "hashlib", "os", "re", "shutil", "tempfile",
               "xml.etree.ElementTree", "__future__")
    bad = [ln for ln in imports if not any(a in ln for a in allowed)]
    check("F1 projectfile 只 import 标准库（零新增依赖）", not bad, bad)
    check("F2 没有引入第三方 XML/编码库",
          not any(m in sys.modules for m in ("lxml", "chardet", "charset_normalizer")))


def main():
    print("== 批次97：工程管理文件编码纪律 ==")
    try:
        section_a()
        section_b()
        section_c()
        section_d()
        section_g()
        section_h()
        section_i()
        section_e()
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
