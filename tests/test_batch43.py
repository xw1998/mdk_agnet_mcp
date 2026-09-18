# -*- coding: utf-8 -*-
"""批次43 mock 测试：Keil 链路的 trace 支持（链路原语层 + 观测类工具两条链路通用）。

来源：用户反馈「mdk 支持 trace 吗？不支持最好支持一下」——批次36 把变量 scope / RTT /
DWT / PC 采样做在了 OpenOCD 链路上，**Keil 用户（人数最多）反而看不到它们**。
本批抽出 `mdkdebug/linkio.py`（链路原语层），让同一套观测代码在两条链路上跑；
顺带把 itm_trace 接上 traceproto 的 ITM 结构化解码（增量 + 丢包告警）。

本文件锁住的都是「会给出看似权威的错答案」的坑：
  A 选路语义：显式指定链路不可用时**不换另一条顶上**（会读到另一个目标的现场）；
    拼错链路名不许静默退化成 auto。
  B KeilLink：读回来的可疑值要带 read_confidence / while_running；状态查询 1 秒 TTL。
  C OcdLink：mdw/mww 解析、PC Thumb 位归一、halt 判据。
  D 工具面：观测类工具都带 link 参数；rtt_attach 记住链路，rtt_read 沿用它。
  E ITM 解码：文本/报文两种口径、增量喂字节、overflow 与半包如实报。

运行：python -m tests.test_batch43
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import os as _os_env  # noqa: E402
# 批次42：工具面默认已改为「精简（只开 core）+ 按需加载」；
# 本批测试校验的是**全量**工具面，所以显式要求不裁剪。
_os_env.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import linkio as L           # noqa: E402
from mdkdebug import trace as T            # noqa: E402
from mdkdebug import traceproto as TP      # noqa: E402
from mdkdebug import server as S           # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)


# ======================================================================
# 夹具：假链路 / 假会话 / 假 Keil 客户端
# ======================================================================
MEM_BASE, MEM_SIZE = 0x20000000, 0x4000


class FakeLink(L.Link):
    """可控的假链路：内存 + 读写计数 + 可一键「拔线」。"""

    def __init__(self, mem=None, base=MEM_BASE, size=MEM_SIZE,
                 name="ocd", label="FakeLink", alive=True):
        super().__init__(session=object() if alive else None)
        self.mem = bytearray(mem or size)
        self.base = base
        self.name = name
        self.label = label
        self.alive = alive
        self.reads = 0
        self.writes = 0

    def available(self):
        return self.alive

    def read(self, addr, n_bytes):
        self.reads += 1
        if not self.alive:
            return None, {"link": self.name, "error": "链路已断开"}
        off = int(addr) - self.base
        if off < 0 or off + int(n_bytes) > len(self.mem):
            return None, {"link": self.name, "error": "越界（%d 字节）" % n_bytes}
        return bytes(self.mem[off:off + int(n_bytes)]), {
            "link": self.name, "read_confidence": "high", "while_running": False}

    def write(self, addr, data):
        self.writes += 1
        if not self.alive:
            return False, {"link": self.name, "error": "链路已断开"}
        off = int(addr) - self.base
        self.mem[off:off + len(data)] = bytes(data)
        return True, {"link": self.name, "written": len(data)}

    def regs(self, names=("pc",)):
        return {"ok": True, "link": self.name, "pc": 0x08000100}

    def halt(self):
        return {"ok": True, "link": self.name, "halted": True}

    def resume(self):
        return {"ok": True, "link": self.name, "running": True}


class FakePhy:
    def __init__(self, connected=True):
        self.is_connected = connected


class FakeKeilClient:
    """KeilLink 的最小客户端：只实现 linkio 用到的那几个方法。"""

    def __init__(self, mem=None, connected=True, running=False,
                 read_ok=True, data_hex=None):
        self.phy = FakePhy(connected)
        self.mem = bytearray(mem or MEM_SIZE)
        self.running = running
        self.read_ok = read_ok
        self.data_hex = data_hex
        self.status_calls = 0
        self.read_calls = 0
        self.writes = 0

    def get_status(self):
        self.status_calls += 1
        return {"ok": True, "debugging": True, "running": self.running,
                "status_text": "RUNNING" if self.running else "STOPPED"}

    def read_mem_verified(self, addr, n_bytes, verify="auto"):
        self.read_calls += 1
        if not self.read_ok:
            return {"ok": False, "error": "读失败", "status_text": "cannot read memory"}
        dh = self.data_hex
        if dh is None:
            off = int(addr) - MEM_BASE
            dh = bytes(self.mem[off:off + int(n_bytes)]).hex()
        return {"ok": True, "data_hex": dh, "read_confidence": "high",
                "reread_count": 1, "reread_consistent": True,
                "target_running": self.running, "since_stop_s": 0.3}

    def write_mem(self, addr, data):
        self.writes += 1
        return {"ok": True, "written": len(data)}

    def stop(self):
        self.running = False
        return {"ok": True, "stopped": True}

    def run(self):
        self.running = True
        return {"ok": True, "running": True}

    def read_cpu_registers_stable(self):
        return {"ok": True, "pc": 0x08000101}


class FakeOcdSession:
    """OpenOCD 会话的最小替身：mdw / mww / reg / halt / resume。"""

    def __init__(self, mem=None, halted=True):
        self.mem = bytearray(mem or MEM_SIZE)
        self.halted = halted
        self.cmds = []

    def running(self):
        return True

    def cmd(self, line, timeout=5):
        self.cmds.append(line)
        p = line.split()
        if p[0] == "mdw":
            addr, count = int(p[1], 16), int(p[2])
            off = addr - MEM_BASE
            words = []
            for i in range(count):
                w = 0
                if 0 <= off + i * 4 <= len(self.mem) - 4:
                    w = int.from_bytes(self.mem[off + i * 4:off + i * 4 + 4], "little")
                words.append(w)
            body = " ".join("%08X" % w for w in words)
            return {"ok": True, "output": "0x%08X: %s" % (addr, body)}
        if p[0] == "mww":
            addr, val = int(p[1], 16), int(p[2], 16)
            off = addr - MEM_BASE
            self.mem[off:off + 4] = val.to_bytes(4, "little")
            return {"ok": True, "output": ""}
        if p[0] == "reg":
            if not self.halted:
                return {"ok": False, "output": "target not halted"}
            return {"ok": True, "output": "pc (/32): 0x08000101"}
        if p[0] == "halt":
            self.halted = True
            return {"ok": True, "output": ""}
        if p[0] == "resume":
            self.halted = False
            return {"ok": True, "output": ""}
        return {"ok": False, "output": "unknown command"}


def mk_mem(patches):
    m = bytearray(MEM_SIZE)
    for addr, data in patches:
        off = addr - MEM_BASE
        m[off:off + len(data)] = data
    return m


def _patch_pick(keil, ocd):
    L._try_keil = lambda: keil
    L._try_ocd = lambda: ocd


def _restore_pick():
    L.__dict__.pop("_try_keil", None)
    L.__dict__.pop("_try_ocd", None)


# ======================================================================
def main():
    print("=" * 72)
    print("批次43：Keil 链路 trace 支持（linkio + trace 两条链路通用）")
    print("=" * 72)

    # ---------------------------------------------------------------- A
    print("\n-- A 选路语义：不猜、不换链路顶上 --")
    _patch_pick((None, "Keil 没会话"), (None, "OpenOCD 没跑"))
    try:
        lk, err = L.pick("auto")
        check("A1 两条链路都没有时不猜，reason=no-mem-link",
              lk is None and err.get("reason") == "no-mem-link", err)
        check("A2 两条链路的各自原因都带上",
              bool(err.get("keil")) and bool(err.get("ocd")), err)
        check("A3 提示同时给出两条链路的起法（enter_debug / ocd_start）",
              "enter_debug" in (err.get("hint") or "")
              and "ocd_start" in (err.get("hint") or ""), err.get("hint"))
        _, e2 = L.pick("keil")
        check("A4 显式 keil 不可用：reason=no-keil-link",
              e2.get("reason") == "no-keil-link", e2)
        _, e3 = L.pick("ocd")
        check("A5 显式 ocd 不可用：reason=no-ocd-link",
              e3.get("reason") == "no-ocd-link", e3)
        _, e4 = L.pick("keill")
        check("A6 链路名拼错不许静默退化成 auto：reason=bad-link-name",
              e4.get("reason") == "bad-link-name", e4)
        _, e5 = L.pick("")
        check("A7 空串按 auto 处理（reason=no-mem-link，不是 bad-link-name）",
              e5.get("reason") == "no-mem-link", e5)
    finally:
        _restore_pick()

    keil_lk = L.KeilLink(FakeKeilClient())
    _patch_pick((keil_lk, None), (None, "OpenOCD 没跑"))
    try:
        lk, err = L.pick("ocd")
        check("A8 显式 ocd 不可用而 keil 活着：不拿 keil 顶上",
              lk is None and err.get("reason") == "no-ocd-link", err)
        lk2, err2 = L.pick("auto")
        check("A9 auto 时 keil 活着就用 keil",
              lk2 is not None and lk2.name == "keil", err2)
        d = L.describe_links()
        check("A10 describe_links 给出两条链路的状态",
              "keil" in d and "ocd" in d and d["keil"].get("available") is True
              and d["ocd"].get("available") is False, d)
    finally:
        _restore_pick()

    # ---------------------------------------------------------------- B
    print("\n-- B KeilLink：可疑读值要披露，状态查询要有 TTL --")
    mem = mk_mem([(0x20000010, b"\xDE\xAD\xBE\xEF")])
    L._STATUS_MEM.pop("keil", None)   # 状态缓存按链路名共享（设计如此），先清干净
    c = FakeKeilClient(mem=mem, running=True)
    kl = L.KeilLink(c)
    check("B1 phy 连着 → available()", kl.available() is True, None)
    data, meta = kl.read(0x20000010, 4)
    check("B2 读回来的字节正确且 meta.link=keil",
          data == b"\xDE\xAD\xBE\xEF" and meta.get("link") == "keil", (data, meta))
    check("B3 meta 带读置信度（不许把读到的 0 当结论）",
          meta.get("read_confidence") == "high", meta)
    check("B4 meta 带「目标当时在不在跑」while_running=True",
          meta.get("while_running") is True, meta)
    check("B5 不再声明「读内存要求目标已停」（批次45 真机复核：运行态读得到）",
          kl.need_halt_for_read() is False, None)
    c2 = FakeKeilClient(read_ok=False)
    d2, m2 = L.KeilLink(c2).read(0x20000000, 4)
    check("B6 读失败返回 (None, meta)，meta 里有 error 与 error 文案",
          d2 is None and bool(m2.get("error")), m2)
    c3 = FakeKeilClient(data_hex="zz")
    d3, m3 = L.KeilLink(c3).read(0x20000000, 4)
    check("B7 data_hex 不合法时报错而不是崩（也不返回空数据当成功）",
          d3 is None and "十六进制" in (m3.get("error") or ""), m3)
    c4 = FakeKeilClient(connected=False)
    check("B8 phy 没连 → available() False",
          L.KeilLink(c4).available() is False, None)
    L._STATUS_MEM.pop("keil", None)
    c5 = FakeKeilClient()
    kl5 = L.KeilLink(c5)
    n0 = c5.status_calls
    kl5.target_running(); kl5.target_running(); kl5.target_running()
    check("B9 「目标在不在跑」1 秒 TTL：连续 3 次只查一次状态",
          c5.status_calls - n0 == 1, c5.status_calls - n0)
    kl5.resume()
    check("B10 halt/resume 后缓存失效（下个采样点拿到新状态）",
          kl5.target_running() is True and c5.status_calls > n0 + 1, c5.status_calls)

    # ---------------------------------------------------------------- C
    print("\n-- C OcdLink：mdw/mww 解析与 halt 判据 --")
    omem = mk_mem([(0x20000020, b"\x01\x02\x03\x04\x05\x06")])
    os_ = FakeOcdSession(mem=omem, halted=False)
    ol = L.OcdLink(os_)
    check("C1 会话在跑 → available()", ol.available() is True, None)
    data, meta = ol.read(0x20000020, 4)
    check("C2 mdw 解析出前 4 字节，meta.link=ocd",
          data == b"\x01\x02\x03\x04" and meta.get("link") == "ocd", (data, meta))
    data6, _ = ol.read(0x20000020, 6)
    check("C3 请求 6 字节按字读并裁到 6", data6 == b"\x01\x02\x03\x04\x05\x06", data6)
    ok, wmeta = ol.write(0x20000030, b"\xAA\xBB\xCC")
    check("C4 mww 写入并按 4 字节对齐补齐，written 报原始长度",
          ok and wmeta.get("written") == 3 and wmeta.get("padded") == 1, wmeta)
    os_.halted = True
    check("C5 PC 的 Thumb 位（bit0=1）被归一",
          ol.regs(("pc",)).get("pc") == 0x08000100, ol.regs(("pc",)))
    check("C6 OpenOCD 侧不要求为目标停核才能读", ol.need_halt_for_read() is False, None)
    os_.halted = False
    check("C7 非 halted 时 reg 失败 → target_running() 判为 True",
          ol.target_running() is True, None)
    os_.halted = True
    check("C8 halted 时能读 reg → target_running() 判为 False",
          ol.target_running() is False, None)
    oerr = L.OcdLink(FakeOcdSession(halted=False))
    oerr.session.cmd = lambda line, timeout=5: {"ok": False, "output": "oops"}
    check("C9 读失败是 (None, meta)，meta 里带 error",
          oerr.read(0x20000000, 4)[0] is None, oerr.read(0x20000000, 4))

    # ---------------------------------------------------------------- D
    print("\n-- D 工具面：观测类工具都带 link，RTT 记住链路 --")
    srv = S.create_server(host="127.0.0.1", port=14933, idle_timeout=5.0)
    tools = {t.name: t for t in srv._tool_manager.list_tools()}

    def props(nm):
        return set((tools[nm].parameters.get("properties") or {}).keys())

    for nm in ("trace_scope_start", "trace_pcsample", "trace_profile",
               "trace_dwt_counters", "trace_rtt_find", "trace_rtt_attach"):
        check("D1.%s 带 link 参数" % nm, "link" in props(nm), props(nm))
    check("D2 itm_trace 带 decode / port_filter / reset",
          {"decode", "port_filter", "reset"} <= props("itm_trace"), props("itm_trace"))
    check("D3 trace_guide 的 links 主题讲清两条链路与「不换链路顶上」",
          "links" in T.GUIDE and "不会悄悄换" in T.GUIDE["links"], T.GUIDE.get("links", "")[:80])
    check("D4 trace_status 描述里说明会给出当前链路",
          "link" in T.GUIDE["links"], None)

    # RTT：造一个真的控制块，验证 attach 记住链路、read 沿用
    cb = struct.pack("<16sii", b"SEGGER RTT\x00\x00\x00\x00\x00\x00", 1, 1)
    cb += struct.pack("<IIIIII", 0, 0x20000200, 64, 3, 0, 0)      # up 通道
    cb += struct.pack("<IIIIII", 0, 0x20000300, 64, 0, 0, 0)      # down 通道
    rmem = mk_mem([(0x20000100, cb), (0x20000200, b"abc" + b"\x00" * 61)])
    fl = FakeLink(mem=rmem, name="ocd", label="FakeLink")
    old_pick = L.pick
    L.pick = lambda link="auto", who="": (fl, None)
    try:
        T._T["rtt"] = None
        a = T.rtt_attach(addr=0x20000100, size=512, channel_names=False,
                         link="ocd")
        check("D5 rtt_attach 成功且回报实际用的链路",
              a.get("ok") and a.get("link") == "ocd", a)
        check("D6 链路名记进会话状态（rtt_read 才能沿用）",
              (T._T.get("rtt") or {}).get("link") == "ocd", T._T.get("rtt"))
        r0 = fl.reads
        rd = T.rtt_read(channel=0, max_bytes=16)
        check("D7 rtt_read 沿 attach 的链路读数据",
              rd.get("ok") and rd.get("text") == "abc" and fl.reads > r0, rd)
        check("D8 rtt_read 把 RdOff 写回目标（不写回是自制主机的经典错误）",
              rd.get("rd_writeback") and fl.writes > 0, rd)
        L.pick = lambda link="auto", who="": (
            None, {"ok": False, "reason": "no-ocd-link", "link": "ocd",
                   "error": "OCD 链路已断开"})
        rd2 = T.rtt_read(channel=0)
        check("D9 链路断了如实报错，并提示重新 attach（不假装读到空数据）",
              rd2.get("ok") is False and "trace_rtt_attach" in (rd2.get("hint") or ""),
              rd2)
    finally:
        L.pick = old_pick
        T._T["rtt"] = None

    # ---------------------------------------------------------------- E
    print("\n-- E ITM 解码：不是文本就按报文解，增量与丢包如实报 --")
    S._ITM_VIEW.update({"state": {}, "prev_hex": "", "prev_len": 0, "pulls": 0,
                          "fed_bytes": 0, "overflow": 0, "buffer_resets": 0})
    d = S._decode_itm_view(b"hello world\r\n", mode="auto", reset=True)
    check("E1 纯文本走 text 口径，decided_by=heuristic",
          d.get("mode") == "text" and d.get("decided_by") == "heuristic"
          and "hello" in d.get("text", ""), d)
    raw = b"\x01H\x01i\x01\n"
    d = S._decode_itm_view(raw, mode="auto", reset=True)
    check("E2 原始 ITM 流按报文解，port0 打印拼回 Hi",
          d.get("mode") == "itm" and d.get("text") == "Hi\n", d)
    check("E3 报文里带 header / port，且 data 已 JSON 化为 text/hex",
          d["packets"][0]["header"] == "0x01" and d["packets"][0]["port"] == 0
          and d["packets"][0].get("data_text") == "H", d["packets"][0])
    check("E4 summary 统计到 3 个 instrumentation 报文",
          d["summary"]["by_kind"].get("instrumentation") == 3, d["summary"])
    d = S._decode_itm_view(b"\x01H\x70\x01i", mode="itm", reset=True)
    check("E5 ITM Overflow 计入并给警告（不许把缺数据当完整）",
          d.get("overflow") == 1 and any("丢失" in w for w in d.get("warnings", [])),
          (d.get("overflow"), d.get("warnings")))
    d = S._decode_itm_view(b"\x01A\x01B", mode="itm", reset=True)
    n1 = d["fed_bytes"]
    d = S._decode_itm_view(b"\x01A\x01B\x01C", mode="itm")
    check("E6 增量：上次是本次前缀 → 只喂新增字节（\x01C 这 2 字节），delta=True",
          d.get("delta") is True and d.get("fed_bytes") == 2 and n1 == 4, d)
    d = S._decode_itm_view(b"\x01Z", mode="itm")
    check("E7 缓冲被换掉 → 整段重喂并如实标 delta=False + warning",
          d.get("delta") is False
          and any("不是增量" in w for w in d.get("warnings", [])), d)
    d = S._decode_itm_view(b"\x01H\x0A\x01", mode="itm", reset=True)
    check("E8 半包留到下次（leftover_bytes=2）并给 warning",
          d.get("leftover_bytes") == 2
          and any("未凑齐" in w for w in d.get("warnings", [])), d)
    d = S._decode_itm_view(b"\x01H\x01i", mode="itm", reset=True, port_filter=1)
    check("E9 port_filter 只留指定 stimulus port 的报文",
          d.get("packets_total") == 0, d)
    d = S._decode_itm_view(b"\x01H", mode="itm", reset=True, port_filter=0)
    check("E10 port_filter=0 保留 port0 报文", d.get("packets_total") == 1, d)
    d = S._decode_itm_view(b"x", mode="ipx", reset=True)
    check("E11 decode 取值非法时报错并带 error_code",
          d.get("ok") is False and d.get("error_code") == "bad-decode-mode", d)
    d = S._decode_itm_view(b"", mode="auto", reset=True)
    check("E12 空缓冲不装模作样：text 口径 + 0 字节", d.get("bytes") == 0, d)

    print("\n" + "=" * 72)
    print("通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
