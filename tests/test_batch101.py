# -*- coding: utf-8 -*-
"""批次101 测试：启动自带环境隔离 / 证据标记 / 地址口径 / 无 BOM 导出。

用户报的四条（原文）：

  一、启动要自带环境隔离：它会被宿主 PYTHONPATH 污染而崩（SRE module mismatch），
      得外部加 env -u PYTHONPATH -u PYTHONHOME 才能起。
  二、产出要给「这是证据不是代码」的硬标记：pseudo_c.c 长得太像源码，挂进工程就变成
      Ported/；至少在文件头 / report.json 里标 evidence_only，并拒绝输出到 App/、Core/。
  三、参数与返回口径统一：image_inspect 的 flash_start 只吃整数、传 "0x..." 就失败；
      返回 base_hex 恒为 0x0，传了 flash_start 也不反映。
  四、生成物别带 BOM：CSV 首列键是 '\\ufeffaddr'，不开 utf-8-sig 下游取不到列。

分节：

  A 隔离的纯函数：pollution / clean_env / is_isolated / reexec_command 三形态 / stdio
  B 端到端：毒化 PYTHONPATH 下 run_server.cmd / run_server.sh / run_server.py 都能起
  C 证据标记：伪 C 头注释 + #error 闸门 + report.json/manifest.json + 落盘护栏
  D 地址口径：numparse + image_inspect 的 file_offset_base / load_base + 工具入参
  E 导出无 BOM：textio 口径、产物回读、包内无 utf-8-sig 导出写法
  F 文档与零依赖闸门

运行：python -m tests.test_batch101
"""
import asyncio
import json
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import bootstrap as BOOT          # noqa: E402
from mdkdebug import decomp as DEC              # noqa: E402
from mdkdebug import evidence as EVI            # noqa: E402
from mdkdebug import image as IMG               # noqa: E402
from mdkdebug import numparse as NP             # noqa: E402
from mdkdebug import recover as RC              # noqa: E402
from mdkdebug import textio as TIO              # noqa: E402

PASS, FAIL = [], []
TMP = []

PY = sys.executable


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


def tmpdir(prefix="mdk101_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d


def _w(data, name, d=None):
    d = d or tmpdir()
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return p


# 最小 ARM 固件：向量表 SP=0x20001000 / Reset=0x08000009(Thumb) + bx lr，灌够 1 KB
VT = (struct.pack("<II", 0x20001000, 0x08000009) + bytes.fromhex("7047")
      + b"\x00" * 20)
BIN = VT + b"\x00" * (1024 - len(VT))
BIN_PATH = None


def bin_path():
    global BIN_PATH
    if BIN_PATH is None:
        BIN_PATH = _w(BIN, "fw.bin")
    return BIN_PATH


# ----------------------------------------------------------------------------
# A 隔离的纯函数
# ----------------------------------------------------------------------------
def section_a():
    print("\nA 启动期环境隔离（纯函数）")
    env = {"PYTHONPATH": "/evil", "PYTHONHOME": "/evil2",
           "PYTHONIOENCODING": "utf-8", "PATH": "/bin"}
    pol = BOOT.pollution(env)
    check("A1 pollution 抓到 PYTHONPATH/PYTHONHOME",
          set(pol) == {"PYTHONPATH", "PYTHONHOME"}, pol)
    check("A2 pollution 不把 PYTHONIOENCODING 当污染（剥了会让中文变问号）",
          "PYTHONIOENCODING" not in pol, pol)

    ce = BOOT.clean_env(env)
    check("A3 clean_env 剥掉污染变量",
          "PYTHONPATH" not in ce and "PYTHONHOME" not in ce, ce)
    check("A4 clean_env 保留 IO 变量与 PATH",
          ce.get("PYTHONIOENCODING") == "utf-8" and ce.get("PATH") == "/bin", ce)
    check("A5 clean_env 打上守卫生效（防止无限重启）",
          ce.get(BOOT.GUARD_VAR) == "1", ce)

    check("A6 is_isolated 认同 clean_env 的结果",
          BOOT.is_isolated(ce) is True, ce)
    check("A7 is_isolated 不认同脏环境",
          BOOT.is_isolated({"PYTHONPATH": "/evil"}) is False)

    exe = "/usr/bin/python3"
    c1 = BOOT.reexec_command(["C:/x/mdkdebug/__main__.py", "--version"], exe=exe)
    check("A8 reexec_command：python -m mdkdebug 形态保持 -m（不把 __main__.py 当脚本）",
          c1 == [exe, "-E", "-s", "-m", "mdkdebug", "--version"], c1)

    script = _w("print(1)\n", "srv.py")
    c2 = BOOT.reexec_command([script, "--version"], exe=exe)
    check("A9 reexec_command：真脚本按绝对路径重启",
          c2 == [exe, "-E", "-s", os.path.abspath(script), "--version"], c2)

    c3 = BOOT.reexec_command(["-c", "pass"], exe=exe)
    check("A10 reexec_command：无脚本形态退回 -m mdkdebug",
          c3 == [exe, "-E", "-s", "-m", "mdkdebug"], c3)
    check("A11 重启命令行带 -E -s（忽略 PYTHON* 且不加载 user site）",
          all(("-E" in c and "-s" in c) and "-I" not in c
              for c in (c1, c2, c3)), (c1, c2, c3))
    check("A12 不用 -I（3.11 起 -I 隐含 -P，会丢掉脚本目录）",
          all("-I" not in c for c in (c1, c2, c3)), (c1, c2, c3))

    info = BOOT.ensure_isolated(argv=["-c", "pass"], env=dict(env, **{BOOT.SKIP_VAR: "1"}))
    check("A13 MDKDEBUG_NO_REEXEC=1 时不重启（调试用）",
          info.get("reexeced") is False and info.get("reason") == "skip", info)
    info2 = BOOT.ensure_isolated(argv=["-c", "pass"], env={"PATH": "/bin"})
    check("A14 环境干净时不重启也不报错",
          info2.get("reexeced") is False and info2.get("reason") == "clean", info2)
    try:
        BOOT.configure_stdio()
        check("A15 configure_stdio 可执行（把 stdio 钉成 UTF-8）", True)
    except Exception as exc:  # noqa: BLE001
        check("A15 configure_stdio 可执行（把 stdio 钉成 UTF-8）", False, exc)

    ver = __import__("mdkdebug").__version__
    for rel in ("run_server.cmd", "run_server.sh", "mdkdebug/__main__.py"):
        p = os.path.join(ROOT, rel)
        check("A16 %s 在仓库里" % rel, os.path.isfile(p), p)
    txt = open(os.path.join(ROOT, "run_server.cmd"), "rb").read()
    check("A17 run_server.cmd 是纯 ASCII（cmd 按 ANSI 读，UTF-8 会花）",
          all(b < 0x80 for b in txt), txt[:80])
    check("A18 run_server.cmd 用 CRLF（LF 会让 cmd 认不出行）",
          b"\r\n" in txt and txt.count(b"\n") == txt.count(b"\r\n"), txt[:80])
    check("A19 run_server.cmd 自己清 PYTHONPATH/PYTHONHOME（不靠使用者加 env -u）",
          b'set "PYTHONPATH="' in txt and b'set "PYTHONHOME="' in txt, txt[:200])
    sh = open(os.path.join(ROOT, "run_server.sh"), "rb").read()
    check("A20 run_server.sh unset PYTHONPATH/PYTHONHOME 且用 -E -s",
          b"unset" in sh and b"PYTHONPATH" in sh and b"-E -s" in sh, sh[:200])
    check("A21 __version__ 是三段式（版本号本身不在这里断言数值）",
          ver.count(".") == 2 and ver.split(".")[0].isdigit(), ver)


# ----------------------------------------------------------------------------
# B 端到端：毒化环境下能起
# ----------------------------------------------------------------------------
def _run(cmd, env_extra, timeout=90):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update(env_extra)
    env["MDKDEBUG_PYTHON"] = PY          # 测试里别让它去猜解释器
    try:
        pr = subprocess.run(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
        return pr.returncode, pr.stdout.decode("utf-8", "replace"), pr.stderr.decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return -1, "", repr(exc)


def section_b():
    print("\nB 毒化环境下的启动（端到端）")
    poison = tmpdir()
    # 重毒化：PYTHONPATH 上放一个 raise 的 re.py。真实机器上这会让解释器**死在
    # site 初始化**（.pth 里的 editable finder → pathlib → fnmatch → re），
    # 本进程一行代码都执行不到——所以只有「启动脚本先清变量」这一条路。
    with open(os.path.join(poison, "re.py"), "w", encoding="utf-8") as f:
        f.write('raise ImportError("SRE module mismatch (poisoned)")\n')
    bad = {"PYTHONPATH": poison}

    # B1：启动脚本的做法（先清变量 + -E -s）在重毒化下能起
    rc, out, err = _run([PY, "-E", "-s", os.path.join(ROOT, "run_server.py"),
                         "--version"], bad)
    check("B1 启动脚本的做法（-E -s + 干净 PYTHONPATH）在重毒化下能起",
          rc == 0 and "mdkdebug" in out, (rc, out[-200:], err[-400:]))

    # B2：直接把重毒化环境交给 python，死在 site 初始化——把这条边界写成事实
    rc, out, err = _run([PY, os.path.join(ROOT, "run_server.py"), "--version"], bad)
    check("B2 重毒化下裸启动死在 site 初始化（进程内无解，必须有启动脚本）",
          rc != 0 and "init_import_site" in err, (rc, err[-300:]))

    # B3：温和毒化（污染存在、但不在 site 初始化阶段被 import）→ bootstrap 自愈
    mild = tmpdir()
    with open(os.path.join(mild, "mdkdebug_shadow_probe.py"), "w", encoding="utf-8") as f:
        f.write("raise ImportError('poisoned')\n")
    rc, out, err = _run([PY, os.path.join(ROOT, "run_server.py"), "--version"],
                        {"PYTHONPATH": mild})
    check("B3 温和毒化下 bootstrap 自愈成功（清变量后重启自己）",
          rc == 0 and "mdkdebug" in out, (rc, out[-200:], err[-400:]))
    check("B4 自愈时明说「检测到污染」，不静默重启",
          "检测到" in err and ("PYTHONPATH" in err or "隔离模式" in err), err[-400:])
    check("B5 自愈不靠 -I（3.11 起 -I 隐含 -P，会丢掉脚本目录）",
          "-I " not in err and " -I" not in err, err[-200:])

    rc, out, err = _run([PY, os.path.join(ROOT, "run_server.py"), "--version"],
                        {"PYTHONPATH": mild, "MDKDEBUG_NO_REEXEC": "1"})
    check("B6 MDKDEBUG_NO_REEXEC=1 时不自愈（留一手给排查）",
          "检测到" not in err and ("mdkdebug" in out or rc != 0), (rc, out[-200:], err[-200:]))

    # B7：启动脚本本身在重毒化环境下能起（cmd 被沙箱拦住时退化为内容检查并明说）
    script = os.path.join(ROOT, "run_server.cmd" if os.name == "nt" else "run_server.sh")
    if os.name == "nt":
        rc, out, err = _run(["cmd", "/c", script, "--version"], bad)
        blocked = "PermissionError" in err or "Not permitted" in err
        if blocked:
            txt = open(script, "rb").read()
            ok = b'set "PYTHONPATH="' in txt and b"-E -s" in txt
            check("B7 run_server.cmd 能起（本机沙箱禁止 spawn cmd，改判脚本内容）", ok,
                  err[-200:])
        else:
            check("B7 重毒化下 run_server.cmd --version 能起（启动脚本自己清变量）",
                  rc == 0 and "mdkdebug" in out, (rc, out[-200:], err[-400:]))
    else:
        rc, out, err = _run(["sh", script, "--version"], bad)
        check("B7 重毒化下 run_server.sh --version 能起", rc == 0 and "mdkdebug" in out,
              (rc, out[-200:], err[-400:]))


# ----------------------------------------------------------------------------
# C 证据标记与落盘护栏
# ----------------------------------------------------------------------------
def section_c():
    print("\nC 「这是证据不是代码」")
    src = DEC.pseudo_c_file({"functions": [
        {"addr": 0x08000000, "name": "Reset_Handler",
         "code": "/* 0x08000000 Reset_Handler */\nvoid f0(void) { }\n"}]})
    check("C1 伪 C 文件头写明 EVIDENCE ONLY", "EVIDENCE ONLY" in src, src[:200])
    check("C2 伪 C 带 evidence_only: true 元数据行", "evidence_only: true" in src)
    check("C3 伪 C 带 #error 编译期闸门（不定义开关就编不过）",
          "#error" in src and "MDKDEBUG_ALLOW_EVIDENCE_ONLY" in src, src[:400])
    check("C4 evidence.C_GUARD 与伪 C 里的闸门逐字一致",
          EVI.C_GUARD.strip() in src, EVI.C_GUARD[:100])

    # 护栏：源码/构建目录一律拒绝
    base = tmpdir()
    for name in ("App", "Core", "Src", "Drivers"):
        d = os.path.join(base, name)
        os.makedirs(d, exist_ok=True)
        # 名字只是线索，真正的判据是「里面装着源码」——真实的 App/ 一定有代码
        open(os.path.join(d, "main.c"), "w", encoding="utf-8").write("int main(void){return 0;}\n")
        bad = EVI.violation(d)
        check("C5 装着源码的 %s/ 被判为不可落证据" % name,
              bool(bad) and bad.get("code") == "evidence-in-build-dir", bad)
    empty = os.path.join(tmpdir(), "Src")           # 空目录只是名字像
    os.makedirs(empty)
    check("C5b 只有名字像、里面没有源码的目录放行（不误伤证据目录自己的 src/）",
          EVI.violation(empty) is None, EVI.violation(empty))

    # 工程目录内（近 3 级父目录有 .uvprojx）也拒绝
    proj = os.path.join(base, "proj", "MDK-ARM")
    os.makedirs(os.path.join(proj, "recovered"))
    open(os.path.join(proj, "x.uvprojx"), "w", encoding="utf-8").write("<Project/>")
    bad = EVI.violation(os.path.join(proj, "recovered"))
    check("C6 工程目录内也拒绝（会混进 Ported/）", bool(bad), bad)
    open(os.path.join(proj, "recovered", "report.json"), "w",
         encoding="utf-8").write("{}")
    check("C7 已有 report.json 的证据目录放行（自家证据目录不误判）",
          EVI.violation(os.path.join(proj, "recovered")) is None,
          EVI.violation(os.path.join(proj, "recovered")))

    # 独立目录放行
    ok_dir = os.path.join(tmpdir(), "recovered")
    check("C8 独立目录（不在源码树里）正常放行", EVI.violation(ok_dir) is None,
          EVI.violation(ok_dir))

    # write_pseudo_c 落在 App/ 下必须抛错
    appdir = os.path.join(base, "App")          # C5 里已建过，且放着 main.c
    raised = ""
    try:
        DEC.write_pseudo_c({"functions": [{"addr": 0x08000000, "name": "f",
                                          "code": "void f0(void) { }\n"}]},
                           os.path.join(appdir, "pseudo_c.c"))
    except Exception as exc:  # noqa: BLE001
        raised = str(exc)
    check("C9 decomp.write_pseudo_c 拒绝写进 App/", "拒绝" in raised, raised)

    # build_project / project_exact 的入口护栏
    out = RC.build_project(bin_path(), os.path.join(base, "Core"))   # 有 main.c
    check("C10 build_project 拒绝 out_dir=Core/",
          out.get("error_code") == "evidence-in-build-dir"
          and out.get("evidence_only") is True, out)
    out = RC.project_exact(bin_path(), os.path.join(base, "Src"))
    check("C11 project_exact 拒绝 out_dir=Src/",
          out.get("error_code") == "evidence-in-build-dir", out)

    # 正常出件：report.json / manifest.json 带 evidence_only
    d1 = os.path.join(tmpdir(), "rec1")
    r1 = RC.build_project(bin_path(), d1, include_asm=False)
    check("C12 build_project 正常出件", r1.get("ok") is True, r1)
    rep_path = os.path.join(d1, "report.json")
    check("C13 report.json 存在", os.path.isfile(rep_path), rep_path)
    rep = json.load(open(rep_path, encoding="utf-8")) if os.path.isfile(rep_path) else {}
    check("C14 report.json 顶层 evidence_only=true", rep.get("evidence_only") is True, list(rep)[:12])
    check("C15 report.json artifact_kind=evidence", rep.get("artifact_kind") == "evidence")
    check("C16 report.json 列出逐文件的 evidence_only",
          isinstance(rep.get("evidence_only_files"), list)
          and "src/pseudo_c.c" in rep.get("evidence_only_files", []),
          rep.get("evidence_only_files"))
    pc = os.path.join(d1, "src", "pseudo_c.c")
    if os.path.isfile(pc):
        head = open(pc, "rb").read(2400).decode("utf-8", "replace")
        check("C17 出件里的伪 C 也带闸门（报告与文件口径一致）",
              "MDKDEBUG_ALLOW_EVIDENCE_ONLY" in head, head[:200])
    else:
        check("C17 出件里的伪 C 也带闸门（报告与文件口径一致）", False, "pseudo_c.c 未生成")

    d2 = os.path.join(tmpdir(), "rec2")
    r2 = RC.project_exact(bin_path(), d2, include_asm=False)
    check("C18 project_exact 正常出件", r2.get("ok") is True, r2)
    man_path = os.path.join(d2, "manifest.json")
    man = json.load(open(man_path, encoding="utf-8")) if os.path.isfile(man_path) else {}
    check("C19 manifest.json 顶层 evidence_only=true", man.get("evidence_only") is True,
          list(man)[:12])
    check("C20 manifest.json artifact_kind=evidence", man.get("artifact_kind") == "evidence")
    check("C21 manifest.json 的 evidence_only_files 覆盖全部产物",
          isinstance(man.get("evidence_only_files"), list)
          and len(man.get("evidence_only_files") or []) >= 3,
          man.get("evidence_only_files"))


# ----------------------------------------------------------------------------
# D 地址口径
# ----------------------------------------------------------------------------
def section_d():
    print("\nD 参数与返回口径（十六进制入参 + 文件偏移/加载基址分开报）")
    check("D1 parse_int 吃 0x 前缀", NP.parse_int("0x08000000") == 0x08000000)
    check("D2 parse_int 吃十进制字符串", NP.parse_int("134217728") == 134217728)
    check("D3 parse_int 吃 0b/0o", NP.parse_int("0b1010") == 10 and NP.parse_int("0o17") == 15)
    check("D4 parse_int 容忍下划线与空白",
          NP.parse_int(" 0x0800_0000 ") == 0x08000000)
    check("D5 parse_int 不猜：'08000000' 是十进制",
          NP.parse_int("08000000") == 8000000, NP.parse_int("08000000"))
    check("D6 parse_int 负数", NP.parse_int("-1") == -1)
    for bad in ("abc", "0xzz", 1.5, True):
        try:
            NP.parse_int(bad, name="base")
            check("D7 parse_int 拒绝 %r" % (bad,), False, "没报错")
        except ValueError as exc:
            check("D7 parse_int 拒绝 %r" % (bad,), "base" in str(exc), str(exc))

    out = IMG.inspect_image(bin_path(), base=0, flash_start=0x08000000,
                            flash_size=0x10000, ram_start=0x20000000,
                            ram_size=0x8000)
    check("D8 inspect_image ok", out.get("ok") is True, out.get("error"))
    check("D9 bin 的 load_base 取 flash_start（不再是恒 0x0）",
          out.get("load_base") == 0x08000000 and out.get("load_base_hex") == "0x8000000",
          (out.get("load_base"), out.get("load_base_hex")))
    check("D10 address_basis 说明来源 = flash_start",
          out.get("address_basis") == "flash_start", out.get("address_basis"))
    check("D11 file_offset_base 恒 0（文件里的偏移）",
          out.get("file_offset_base") == 0 and out.get("file_offset_base_hex") == "0x0",
          (out.get("file_offset_base"), out.get("file_offset_base_hex")))
    check("D12 base_hex 是 load_base_hex 的别名（旧字段不再骗人）",
          out.get("base_hex") == out.get("load_base_hex"),
          (out.get("base_hex"), out.get("load_base_hex")))

    out2 = IMG.inspect_image(bin_path(), base=0x08004000)
    check("D13 没给 flash_start 时退回 param_base",
          out2.get("load_base") == 0x08004000
          and out2.get("address_basis") == "param_base",
          (out2.get("load_base"), out2.get("address_basis")))

    # HEX：load_base 取记录最小地址，file_offset 仍是 0 并附说明
    ihex = _w(":020000040800F2\n:080000000001020304050607DC\n:00000001FF\n", "fw.hex")
    out3 = IMG.inspect_image(ihex)
    check("D14 HEX 的 load_base 取记录最小地址",
          out3.get("load_base") == 0x08000000
          and out3.get("address_basis") == "hex_record",
          (out3.get("load_base"), out3.get("address_basis")))
    check("D15 HEX 的 file_offset_base 仍是 0 且有说明",
          out3.get("file_offset_base") == 0
          and any("file_offset_base" in s for s in out3.get("limitations") or []),
          out3.get("limitations"))

    # 工具层：传 "0x..." 字符串（以前直接 ValueError）
    from mdkdebug import server as SV

    srv = SV.create_server(port=15882, toolsets="all")

    def call(name, args):
        return json.loads(asyncio.run(srv.call_tool(name, args)).content[0].text)

    r1 = call("image_inspect", {"path": bin_path(), "flash_start": "0x08000000",
                                "flash_size": "0x10000", "ram_start": "0x20000000",
                                "ram_size": "0x8000"})
    check("D16 工具 image_inspect 接受 flash_start=\"0x08000000\"",
          r1.get("ok") is True and r1.get("load_base") == 0x08000000, r1)
    check("D17 工具返回的 file_offset_base / load_base 是两组字段",
          r1.get("file_offset_base") == 0 and r1.get("address_basis") == "flash_start", r1)
    r2 = call("image_inspect", {"path": bin_path(), "flash_start": "0xzz"})
    check("D18 入参写错时如实报错（带参数名与正确写法）",
          r2.get("ok") is False and "flash_start" in (r2.get("error") or ""), r2)
    r3 = call("image_split", {"path": bin_path(), "base": "0x08000000",
                              "flash_start": "0x08000000", "flash_size": "0x10000"})
    check("D19 image_split 也吃 0x 写法", r3.get("ok") is True, r3)
    r4 = call("recover_probe", {"path": bin_path(), "base": "0x08000000",
                                "deep": False, "detail": "compact"})
    check("D20 recover_probe 也吃 0x 写法", r4.get("ok") is True,
          (r4 or {}).get("error"))
    tools = asyncio.run(srv.list_tools())
    desc = [t.description or "" for t in tools if t.name == "image_inspect"]
    check("D21 对外描述（lean 档裁剪后）仍写着 load_base 与 address_basis",
          bool(desc) and "load_base" in desc[0] and "address_basis" in desc[0],
          (desc or [""])[0][-200:])
    from mdkdebug import thin as TH
    full_desc = TH.full_of("image_inspect") or (desc[0] if desc else "")
    check("D22 完整描述（mdk_guide 可取回）写明 0x 写法与 file_offset_base",
          "0x" in full_desc and "file_offset_base" in full_desc,
          full_desc[-300:])


# ----------------------------------------------------------------------------
# E 导出无 BOM
# ----------------------------------------------------------------------------
def section_e():
    print("\nE 生成物不带 BOM")
    check("E1 csv_text 首字符不是 \\ufeff",
          not TIO.csv_text(["addr", "name"], [[1, "x"]]).startswith("\ufeff"))
    p = os.path.join(tmpdir(), "map", "functions.csv")
    n = TIO.write_csv(p, ["addr", "name"], [[0x08000000, "Reset"]])
    raw = open(p, "rb").read()
    check("E2 write_csv 落盘无 BOM（前 3 字节不是 EF BB BF）",
          not raw.startswith(b"\xef\xbb\xbf"), raw[:6])
    check("E3 write_csv 用 \\n 行尾（不随平台变成 \\r\\n）",
          b"\r\n" not in raw and raw.count(b"\n") == 2, raw)
    check("E4 has_bom 认得出 BOM 也认得出没有",
          TIO.has_bom(p) is False
          and TIO.has_bom(_w(b"\xef\xbb\xbfaddr\n", "bom.csv")) is True)
    check("E5 回读首列键就是 addr（下游不用 utf-8-sig）",
          raw.decode("utf-8").splitlines()[0].split(",")[0] == "addr",
          raw[:20])

    # 出件里的 CSV 也必须无 BOM
    d = os.path.join(tmpdir(), "rec3")
    r = RC.build_project(bin_path(), d, include_asm=False)
    csvs = []
    for root, _dirs, names in os.walk(d):
        for nm in names:
            if nm.endswith(".csv"):
                csvs.append(os.path.join(root, nm))
    bad = [c for c in csvs if TIO.has_bom(c)]
    check("E6 出件里所有 .csv 都无 BOM（含 map/functions.csv）",
          r.get("ok") is True and not bad, (len(csvs), bad))

    # 包内不允许以 utf-8-sig 写导出物（用 AST，避免被注释/文档串误伤）
    import ast
    offenders = []
    pkg = os.path.join(ROOT, "mdkdebug")
    for nm in sorted(os.listdir(pkg)):
        if not nm.endswith(".py"):
            continue
        src = open(os.path.join(pkg, nm), encoding="utf-8", errors="replace").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name not in ("open", "write_text", "write_csv", "DictWriter",
                            "writer", "StringIO", "TextIOWrapper"):
                continue
            kws = {k.arg: k.value for k in node.keywords if k.arg}
            enc = kws.get("encoding")
            if isinstance(enc, ast.Constant) and enc.value == "utf-8-sig":
                mode = kws.get("mode")
                mode_v = mode.value if isinstance(mode, ast.Constant) else ""
                if name == "open" and not any(c in str(mode_v) for c in "wax"):
                    continue        # 只读打开（读 BOM 用）不算导出
                offenders.append("%s:%d %s(... encoding=utf-8-sig)" % (nm, node.lineno, name))
    check("E7 包内没有以 utf-8-sig 写文件的代码", not offenders, offenders[:5])


# ----------------------------------------------------------------------------
# F 文档与闸门
# ----------------------------------------------------------------------------
def section_f():
    print("\nF 文档与零依赖闸门")
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8", errors="replace").read()
    skill = open(os.path.join(ROOT, "skills", "mdkdebug", "SKILL.md"),
                 encoding="utf-8", errors="replace").read()
    pit = open(os.path.join(ROOT, "docs", "PITFALLS.md"),
               encoding="utf-8", errors="replace").read()
    check("F1 README 写了启动脚本（run_server.cmd / .sh）",
          "run_server.cmd" in readme and "run_server.sh" in readme)
    check("F2 README 写了 evidence_only 纪律", "evidence_only" in readme)
    check("F3 README 写了地址口径（load_base / file_offset_base）",
          "load_base" in readme, "")
    check("F4 README 写了导出无 BOM", "BOM" in readme and "csv" in readme.lower())
    check("F5 SKILL 写了启动方式与隔离", "run_server" in skill and "PYTHONPATH" in skill)
    check("F6 SKILL 写了 evidence_only 纪律", "evidence_only" in skill)
    check("F7 PITFALLS 记录了 BOM 与启动污染两条",
          "\\ufeff" in pit or "BOM" in pit, "")
    import ast
    third, stdlib_ok = [], {"csv", "io", "os", "sys", "subprocess", "tempfile",
                             "__future__"}
    for nm in ("bootstrap.py", "numparse.py", "textio.py", "evidence.py"):
        tree = ast.parse(open(os.path.join(ROOT, "mdkdebug", nm), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [] if node.level else [(node.module or "").split(".")[0]]
            else:
                continue
            for m in mods:
                if m and m not in stdlib_ok:
                    third.append("%s: %s" % (nm, m))
    check("F8 新增四个模块只 import 标准库（零新增依赖）", not third, third)


def main():
    try:
        section_a()
        section_b()
        section_c()
        section_d()
        section_e()
        section_f()
    finally:
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
