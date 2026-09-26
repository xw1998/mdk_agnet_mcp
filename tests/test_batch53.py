# -*- coding: utf-8 -*-
"""批次53 mock 测试：读 CMSIS Event Recorder（MDK 原生、纯 SWD 可用的事件缓冲）。

背景：MDK 的 Event Recorder / Event Statistics 走的是「调试器读目标 RAM」这条路
（**不占 SWO 引脚**），SWD 两线接上就能用 —— 批次52 已经把这条通道写进
trace_guide(swd_limits)，但当时工具集只能「说清它是什么」，读不了它的缓冲。
本批补上 `trace_eventrec`：读 EventRecorderInfo / EventStatus，把环形缓冲里的
Event Record 解出来，并给出 Event Statistics 口径的聚合。

它的二进制格式**不在任何公开手册里**，只写在 Keil ARM_Compiler pack 的
EventRecorder.c 里。所以本测试的重点是「位域对不对」——猜错一位，解出来的
就是看着像样、其实是别的东西的事件流：

  A 工具面：注册总数 200 / 归 trace 组 / 只读注解 / 默认暴露 44
  B info 字位域：component/message/seq/dlen/IRQ/first/last/locked/valid/toggle
  C 记录重建：ts/val1/val2 的 bit31 是 toggle，真值高位在 info —— 必须能还原
  D 槽位事件反推：component=0xEF 那组能反推组别 A/B/C/D 与槽位，其他一律不给 level
  E 环形窗口：slot = index & (count-1)，跨回绕要按旧→新排出正确槽位序列
  F 缓冲解码：空槽按 empty 计、写一半（locked / toggle 不一致）按 partial 计，不当数据
  G 聚合（Event Statistics 口径）：成对 Start/Stop 的次数/总时间/最短/最长；落单如实报
  H 结构解析：EventRecorderInfo / EventStatus 的布局与长度不足时的拒绝
  I 目标读取全链路：status / read（跨回绕分段读）/ stats + 签名不符的 warning
  J locate：没给地址也没给 elf / elf 不存在 / 符号找不到（eventrec-symbol-missing）
  K 错误归类：eventrec-symbol-missing 不在 unknown-error 里漂，且下一步不指向 Keil/OpenOCD
  L server 工具层：action 校验、info_addr 解析、端到端
  M 文档同步：trace_guide 不再说「不解码」，README/SKILL 的工具数跟上

运行：python -m tests.test_batch53
"""
import os
import sys
import json
import struct
import asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import errors as ERR          # noqa: E402
from mdkdebug import eventrec as ER         # noqa: E402
from mdkdebug import linkio as L            # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402

PORT = 15493

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def gsize(g):
    return len(TB.TOOLSETS.get(g) or [])

def call(srv, name, args):
    r = asyncio.run(srv.call_tool(name, args))
    txt = "".join(getattr(c, "text", "") or "" for c in r.content)
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return {"_raw": txt}

# ======================================================================
class FakeLink:
    """按字节寻址的假链路：缺省字节给 0x00（真机上缓冲是清零过的）。"""

    name = "keil"
    label = "Keil(mock)"

    def __init__(self, base=0, blob=b"", fill=0x00):
        self.base = int(base)
        self.blob = bytes(blob)
        self.fill = int(fill)
        self.reads = []

    def read(self, addr, n):
        a = int(addr)
        self.reads.append((a, int(n)))
        out = bytearray()
        for i in range(int(n)):
            off = a + i - self.base
            if 0 <= off < len(self.blob):
                out.append(self.blob[off])
            else:
                out.append(self.fill)
        return bytes(out), {"link": self.name}

    def describe(self):
        return {"debugging": True, "running": False, "status_text": "stopped(mock)"}

def patch_pick(fake):
    real = L.pick

    def _fake(link="auto", who=""):
        return (fake, None) if fake is not None else real(link, who)

    L.pick = _fake
    return lambda: setattr(L, "pick", real)

# ----------------------------------------------------------------------
# 一块「目标 RAM」：EventRecorderInfo + EventStatus + 环形缓冲
INFO_A = 0x20000000
STATUS_A = 0x20000040
BUF_A = 0x20000100
COUNT = 8

def build_ram(records, record_index, written, ts_freq=16000000, count=COUNT,
              signature=ER.SIGNATURE, pad=None, info_addr=INFO_A,
              status_addr=STATUS_A, buf_addr=BUF_A):
    """records: {slot: bytes|None}；None 表示空槽（全 0）。返回 (link, info)。"""
    blob = bytearray(count * 16)
    for s, r in (records or {}).items():
        if r is None:
            continue
        off = (int(s) & (count - 1)) * 16
        blob[off:off + 16] = bytes(r)[:16]
    info = ER.encode_info(record_count=count, event_buffer=buf_addr,
                          event_status=status_addr, ts_source=0)
    st = ER.encode_status(record_index=record_index, records_written=written,
                          ts_freq=ts_freq, signature=signature)
    total = max(status_addr + ER.STATUS_SIZE,
                buf_addr + len(blob)) - info_addr
    ram = bytearray(total)
    ram[0:ER.INFO_SIZE] = info
    ram[status_addr - info_addr:status_addr - info_addr + ER.STATUS_SIZE] = st
    ram[buf_addr - info_addr:buf_addr - info_addr + len(blob)] = blob
    return FakeLink(base=info_addr, blob=bytes(ram)), info

def msg(group, kind, slot):
    """component=0xEF 那组的 message 字：bits[7:6]=组别 A/B/C/D，[5:4]=kind，[3:0]=槽位。"""
    return ((int(group) & 0x3) << 6) | ((int(kind) & 0x3) << 4) | (int(slot) & 0xF)

# ======================================================================
def section_a():
    print("A. 工具面与注解")
    total = sum(len(v) for v in TB.TOOLSETS.values()) + len(TB.ALWAYS)
    check("A1 注册总数 200（分组表 191 + 常驻 6）", total == 200, total)
    check("A2 trace_eventrec 归 trace 组（组规模 26->27，批次55 再加 3 个 buff 到 30，批次56 再加 3 个 swd 到 33，批次64 再加 1 个任务表到 34，批次72 再加 2 个分析层到 37，批次75 再加 trace_watch 到 38）",
          "trace_eventrec" in (TB.TOOLSETS.get("trace") or [])
          and gsize("trace") == 38, gsize("trace"))
    an = A.annotations_for("trace_eventrec")
    check("A3 标只读（只读目标 RAM + 本地 .axf，不改目标状态）",
          an.get("readOnlyHint") is True and an.get("destructiveHint") is False, an)
    allnames = set(TB.ALWAYS)
    for v in TB.TOOLSETS.values():
        allnames |= set(v)
    bad = A.check_surface(sorted(allnames))
    check("A4 check_surface 在 200 个工具上无问题", not bad, bad)
    exposed = gsize("core") + len(TB.ALWAYS)
    check("A5 默认暴露 44（批次59 可视化 + 批次67 符号工具进 core，仍在默认面）", exposed == 44, exposed)
    check("A6 默认收起 156（200-44）", 200 - exposed == 156, 200 - exposed)

def section_b():
    print("B. info 字位域")
    info = (ER.INFO_VALID | ER.INFO_LOCKED | (0x3 << ER.INFO_SEQ_POS)
            | ER.INFO_IRQ | (0x5 << 16) | ER.INFO_FIRST | ER.INFO_TBIT
            | (0x12 << 8) | 0x34)
    d = ER.parse_info(info)
    check("B1 component=[15:8] / message=[7:0]",
          d["component"] == 0x12 and d["message"] == 0x34 and d["id"] == 0x1234, d)
    check("B2 seq=[23:20]", d["seq"] == 3, d)
    check("B3 IRQ=[19]、first=[24]、locked=[26]、valid=[27]",
          d["irq"] and d["first"] and d["locked"] and d["valid"], d)
    check("B4 dlen/ctx=[18:16]", d["dlen_ctx"] == 5, d)
    check("B5 toggle=[31]（与 last 分开）",
          d["toggle"] == 1 and d["last"] is False, d)
    zero = ER.parse_info(0)
    check("B6 全 0 info 不报 valid（空槽判据）",
          zero["valid"] is False and zero["component"] == 0 and zero["message"] == 0, zero)

def section_c():
    print("C. 记录解码与高位重建")
    # ts=0x92345678 的 bit31 必须能从 info 的 MSB_TS 位还原
    raw = ER.encode_record(0x92345678, 0x00008123, 0x00004000,
                           component=0x01, message=0x02, seq=1, tbit=0)
    r = ER.decode_record(raw)
    check("C1 ts 重建正确（bit31 被换成 toggle 后仍能还原）",
          r["ts"] == 0x92345678, "0x%08X" % r["ts"])
    check("C2 val1/val2 在 bit31=0 时原样",
          r["val1"] == 0x00008123 and r["val2"] == 0x00004000, r)
    check("C3 toggle 一致（三条 raw 的 bit31 与 info 对齐）→ consistent",
          r["consistent"] is True, r)
    check("C4 记录里的 bit31 不是数据（ts_raw 高位是 toggle）",
          r["ts_raw"] & 0x80000000 == 0, "0x%08X" % r["ts_raw"])
    # val1 的 bit31 = 1 → MSB 走 info，重建后应回到 0x80000001
    r2 = ER.decode_record(ER.encode_record(10, 0x80000001, 0x40000002,
                                           component=0x03, message=0x04, tbit=1))
    check("C5 val1/val2 的 bit31 同理还原，toggle=1 也对",
          r2["val1"] == 0x80000001 and r2["val2"] == 0x40000002
          and r2["consistent"] is True and r2["toggle"] == 1, r2)
    # 写一半：把 ts 的 raw bit31 翻掉 → 与 info 的 toggle 不一致
    bad = bytearray(ER.encode_record(1, 2, 3, component=0x05, message=0x06, tbit=0))
    bad[3] ^= 0x80          # ts 那个 u32 的 bit31（小端：第 4 个字节）
    r3 = ER.decode_record(bytes(bad))
    check("C6 toggle 不一致 → consistent=False（写一半，别当真数据）",
          r3["ok"] is True and r3["consistent"] is False, r3)
    r4 = ER.decode_record(b"\x00" * 16)
    check("C7 VALID=0 的空槽 → ok=False，不当事件",
          r4["ok"] is False and "空槽" in r4["reason"], r4)
    r5 = ER.decode_record(b"\x00" * 8)
    check("C8 记录长度不足 16 字节 → 拒绝", r5["ok"] is False, r5)

def section_d():
    print("D. 槽位事件反推（level 不随记录存储）")
    d = ER.decode_slot_meta(ER.STAT_COMPONENT, msg(2, 0, 3))
    check("D1 comp=0xEF 时反推组别 C / level op / kind start / stat_slot 3",
          d.get("group") == "C" and d.get("level") == "op"
          and d.get("kind") == "start" and d.get("stat_slot") == 3, d)
    check("D2 Stop 变体（kind=3）也能认",
          ER.decode_slot_meta(ER.STAT_COMPONENT, msg(0, 3, 7)).get("kind") == "stop_v", "")
    check("D3 组别 A/B/C/D ↔ error/api/op/detail",
          [ER.decode_slot_meta(ER.STAT_COMPONENT, msg(g, 0, 0))["level"]
           for g in range(4)] == ["error", "api", "op", "detail"], "")
    check("D4 非 0xEF 的组件一律不给 level（记录里根本没存，宁可少给不猜）",
          ER.decode_slot_meta(0x12, 0xFF) == {}, ER.decode_slot_meta(0x12, 0xFF))
    r = ER.decode_record(ER.encode_record(10, 0, 0, component=0x12, message=0xFF))
    check("D5 普通组件的记录里不带 level/kind/stat_slot 字段",
          "level" not in r and "kind" not in r and "stat_slot" not in r, r)

def section_e():
    print("E. 环形窗口")
    check("E1 写满前只取已写的条数",
          ER.window_slots(5, 8, 0, 5) == [0, 1, 2, 3, 4], ER.window_slots(5, 8, 0, 5))
    check("E2 正好一圈：槽位 0..7",
          ER.window_slots(8, 8, 0, None) == list(range(8)),
          ER.window_slots(8, 8, 0, None))
    check("E3 跨回绕：index=10 → 槽位 2..7,0,1（旧→新）",
          ER.window_slots(10, 8, 0, None) == [2, 3, 4, 5, 6, 7, 0, 1],
          ER.window_slots(10, 8, 0, None))
    check("E4 limit 取最近 N 条",
          ER.window_slots(10, 8, 3, None) == [7, 0, 1],
          ER.window_slots(10, 8, 3, None))
    check("E5 count=0 → 空；written=0（确实没写过）→ 空；written=None（读不到状态）"
          "→ 按整圈扫，不谎报「没有记录」",
          ER.window_slots(0, 0, 0, None) == []
          and ER.window_slots(0, 8, 0, 0) == []
          and len(ER.window_slots(0, 8, 0, None)) == 8, "")

def section_f():
    print("F. 缓冲解码（空槽 / 写一半）")
    recs = {0: ER.encode_record(100, 1, 2, component=1, message=2)}
    recs[1] = None                                     # 空槽
    recs[2] = ER.encode_record(200, 3, 4, component=1, message=3, locked=True)
    bad = bytearray(ER.encode_record(300, 5, 6, component=1, message=4, tbit=0))
    bad[3] ^= 0x80                                     # toggle 不一致
    recs[3] = bytes(bad)
    blob = bytearray(8 * 16)
    for s, r in recs.items():
        if r is not None:
            blob[s * 16:s * 16 + 16] = r
    dec = ER.decode_buffer(bytes(blob), 8, 4, written=4, limit=0)
    check("F1 只留下完整的那条（4 槽里 1 空 + 1 locked + 1 半条）",
          dec["ok"] and len(dec["events"]) == 1 and dec["events"][0]["ts"] == 100, dec)
    check("F2 空槽与写一半分开计数",
          dec["skipped"]["empty"] == 1 and dec["skipped"]["partial"] == 2, dec["skipped"])
    check("F3 扫过的槽位数如实给出", dec["slots_scanned"] == 4, dec)
    # 真机暴露过的坑：环形槽位号与统计槽位若共用一个键名，stat_slot 会被
    # 环形槽位号覆盖，聚合就再也配不上对。
    stat_recs = [ER.encode_record(10, 0, 0, component=ER.STAT_COMPONENT, message=msg(2, 0, 0)),
                 ER.encode_record(20, 0, 0, component=ER.STAT_COMPONENT, message=msg(2, 2, 0))]
    sb = b"".join(stat_recs)
    sd = ER.decode_buffer(sb, 2, 2, written=2, slots=[4, 5])
    check("F4 环形槽位在 slot、统计槽位在 stat_slot（不共用键名）",
          [e.get("slot") for e in sd["events"]] == [4, 5]
          and [e.get("stat_slot") for e in sd["events"]] == [0, 0]
          and ER.aggregate(sd["events"], 0)["items"][0]["total_ticks"] == 10,
          [(e.get("slot"), e.get("stat_slot")) for e in sd["events"]])

def section_g():
    print("G. 聚合（Event Statistics 口径）")
    evs = [
        {"component": ER.STAT_COMPONENT, "ts": 1000, "kind": "start", "group": "C", "stat_slot": 0},
        {"component": ER.STAT_COMPONENT, "ts": 3000, "kind": "stop", "group": "C", "stat_slot": 0},
        {"component": ER.STAT_COMPONENT, "ts": 4000, "kind": "start", "group": "C", "stat_slot": 0},
        {"component": ER.STAT_COMPONENT, "ts": 5000, "kind": "stop", "group": "C", "stat_slot": 0},
        {"component": ER.STAT_COMPONENT, "ts": 6000, "kind": "stop", "group": "C", "stat_slot": 0},
        {"component": ER.STAT_COMPONENT, "ts": 7000, "kind": "start", "group": "A", "stat_slot": 1},
    ]
    agg = ER.aggregate(evs, ts_freq=16000000)
    it = (agg["items"] or [{}])[0]
    check("G1 成对区间聚出 count=2 / total=3000 ticks",
          it.get("count") == 2 and it.get("total_ticks") == 3000, it)
    check("G2 给出最短/最长（1000 / 2000，各 1 次）",
          it.get("min_ticks") == 1000 and it.get("max_ticks") == 2000, it)
    check("G3 ts_freq 换算成 ms（3000/16e6 → 0.1875ms）",
          abs((it.get("total_ms") or 0) - 0.1875) < 1e-3, it)
    check("G4 落单的 Stop 与开着没关的 Start 都如实报，不硬凑",
          agg["unpaired_stops"] == 1 and agg["open_starts"] == 1, agg)
    # 时间戳回绕：start 在 0xFFFFFF00，stop 在 0x00000100 → dt = 512
    wrap = [{"component": ER.STAT_COMPONENT, "ts": 0xFFFFFF00, "kind": "start", "group": "B", "stat_slot": 2},
            {"component": ER.STAT_COMPONENT, "ts": 0x00000100, "kind": "stop", "group": "B", "stat_slot": 2}]
    it2 = (ER.aggregate(wrap, ts_freq=0)["items"] or [{}])[0]
    check("G5 32 位时间戳回绕按 +2^32 算，不出现负数耗时",
          it2.get("total_ticks") == 512, it2)
    check("G6 非 0xEF 组件不参与统计",
          ER.aggregate([{"component": 0x12, "ts": 1, "kind": "start"}], 0)["items"] == [], "")

def section_h():
    print("H. 结构解析")
    raw = ER.encode_info(64, 0x20001000, event_filter=0x0F, event_status=0x20002000,
                         ts_source=0)
    d = ER.parse_info_struct(raw)
    check("H1 EventRecorderInfo 24B：协议 1.1(DAP) / count / 缓冲 / 状态 / ts 源",
          d["ok"] and d["protocol_type_name"] == "DAP"
          and d["protocol_version"] == "1.1" and d["record_count"] == 64
          and d["event_buffer"] == 0x20001000 and d["event_status"] == 0x20002000
          and d["ts_source_name"] == "DWT CYCCNT", d)
    check("H2 长度不足 → 拒绝并说清要多少字节",
          ER.parse_info_struct(b"\x00" * 10)["ok"] is False, "")
    st = ER.parse_status(ER.encode_status(record_index=9, records_written=9,
                                          ts_freq=16000000, ts_last=12345))
    check("H3 EventStatus 36B：index/written/freq/signature 校验",
          st["ok"] and st["record_index"] == 9 and st["records_written"] == 9
          and st["ts_freq"] == 16000000 and st["signature_ok"] is True
          and st["state_name"] == "recording", st)
    check("H4 签名不对 → signature_ok=False（未初始化过的结构不许当真）",
          ER.parse_status(ER.encode_status(1, 1, 0, signature=0xDEADBEEF))["signature_ok"] is False, "")
    check("H5 EventStatus 长度不足 → 拒绝", ER.parse_status(b"\x00")["ok"] is False, "")

def section_i():
    print("I. 目标读取全链路（mock 链路）")
    # 写满一圈：index=10 → 槽位 2..7,0,1
    recs = {}
    for i in range(8):
        recs[i] = ER.encode_record(1000 + i * 100, i, 0, component=0x01, message=i)
    link, _info = build_ram(recs, record_index=10, written=10)
    rp = patch_pick(link)
    try:
        st = ER.status(info_addr=INFO_A, link="keil")
        check("I1 status：info 解析 + 状态块 + 签名校验",
              st.get("ok") and st["info"]["record_count"] == 8
              and (st.get("event_status") or {}).get("record_index") == 10
              and (st.get("event_status") or {}).get("signature_ok") is True, st)
        r = ER.read(info_addr=INFO_A, limit=100, link="keil")
        check("I2 read：跨回绕的 8 条全解出来（旧→新），且每条挂对自己的槽位号",
              r.get("ok") and r.get("count") == 8
              and [e["ts"] for e in r["events"]] ==
                  [1000 + i * 100 for i in [2, 3, 4, 5, 6, 7, 0, 1]]
              and [e["slot"] for e in r["events"]] == [2, 3, 4, 5, 6, 7, 0, 1],
              [(e["slot"], e["ts"]) for e in (r.get("events") or [])])
        check("I3 跨回绕分成两段读（不整块拉）",
              len(r.get("segments") or []) == 2, r.get("segments"))
        # 直调模块不经统一信封：模块本身不得占用 status 这个键，
        # 否则经 server 时会被信封覆盖（回归由 L4 覆盖）。
        check("I4 read 的状态块放在 event_status 下，模块自身不占用 status 键",
              ((r.get("event_status") or {}).get("record_index") == 10
               and r.get("status") is None), (r.get("event_status"), r.get("status")))
        check("I4b read 的 note 说清 ts 是目标侧时间戳、level 不随记录存储",
              "不是主机时间" in (r.get("note") or "")
              and "level 不随记录存储" in (r.get("note") or ""), r.get("note"))
        # 未初始化：签名不符 → warning（仍给数据，但明确不可信）
        link2, _ = build_ram(recs, record_index=3, written=3, signature=0x12345678)
        rp2 = patch_pick(link2)
        st2 = ER.status(info_addr=INFO_A, link="keil")
        check("I5 EventStatus 签名不符 → warning 里点名「统计不可信」",
              "signature" in (st2.get("warning") or "")
              and "不可信" in (st2.get("warning") or ""), st2.get("warning"))
        rp2()
    finally:
        rp()
    # 读不到：链路没有会话（不换另一条顶上）
    rp3 = patch_pick(None)
    try:
        orig = L.pick

        def _none(link="auto", who=""):
            return None, {"ok": False, "reason": "no-mem-link",
                          "error": "两个链路都没有活着的调试会话"}

        L.pick = _none
        bad = ER.status(info_addr=INFO_A, link="keil")
        check("I6 读不到目标时如实报错，不编一份空事件流",
              bad.get("ok") is False and bad.get("hint"), bad)
        L.pick = orig
    finally:
        rp3()

def section_j():
    print("J. locate 的三条失败路径")
    r = ER.locate(elf="", info_addr=0)
    check("J1 既没地址也没 elf → invalid-argument（并给出两条路）",
          r.get("ok") is False and r.get("error_code") == "invalid-argument", r)
    r2 = ER.locate(elf=os.path.join(ROOT, "no_such_file.axf"), info_addr=0)
    check("J2 elf 不存在 → project-not-found", r2.get("error_code") == "project-not-found", r2)
    r3 = ER.locate(elf=os.path.join(ROOT, "pyproject.toml"), info_addr=0)
    check("J3 elf 里没有符号 → eventrec-symbol-missing（不是「没数据」也不是「地址错」）",
          r3.get("ok") is False and r3.get("error_code") == "eventrec-symbol-missing", r3)
    check("J4 那两种情况在 note 里点明（没插桩 / 被 --gc-sections 回收）",
          "没链 Event Recorder" in (r3.get("note") or "")
          and "gc-sections" in (r3.get("note") or ""), r3.get("note"))
    check("J5 给出替代方案（直接给地址 / 换 pcsample / record）",
          "info_addr" in " ".join(r3.get("next_actions") or [])
          and "trace_pcsample" in " ".join(r3.get("next_actions") or []), "")
    r4 = ER.locate(elf="", info_addr=0x20000000)
    check("J6 显式地址优先，不碰符号", r4.get("ok") and r4.get("method") == "explicit", r4)

def section_k():
    print("K. 错误归类与下一步")
    code = ERR.classify_error("在 app.axf 里没找到符号 EventRecorderInfo")
    check("K1 中文文本也能归到 eventrec-symbol-missing（不落 unknown-error）",
          code == "eventrec-symbol-missing", code)
    env = ERR.normalize("trace_eventrec",
                        {"ok": False, "error_code": "eventrec-symbol-missing",
                         "error": "在 app.axf 里没找到符号 EventRecorderInfo"})
    check("K2 机器可读码原样透出", env.get("error_code") == "eventrec-symbol-missing", env)
    joined = " ".join(env.get("next_actions") or [])
    check("K3 下一步说清「没插桩」与「给地址」两条真路",
          "EventRecord" in joined and "info_addr" in joined, joined)
    check("K4 不把它指去 Keil 状态/OpenOCD（这不是链路问题）",
          "keil_health" not in joined and "ocd_status" not in joined, joined)
    check("K5 该码本身登记在 ERROR_CODES（有文案与动作）",
          "eventrec-symbol-missing" in ERR.ERROR_CODES, "")

def section_l():
    print("L. server 工具层")
    srv = SV.create_server(port=PORT)
    r = call(srv, "trace_eventrec", {"action": "bogus"})
    check("L1 未知 action → 拒绝并列出可用值",
          r.get("ok") is False and set(r.get("available") or []) == {"status", "read", "stats"}, r)
    r2 = call(srv, "trace_eventrec", {"action": "status", "info_addr": "0xZZ"})
    check("L2 info_addr 解析失败 → 明确报解析错（不静默当 0）",
          r2.get("ok") is False and "解析失败" in (r2.get("error") or ""), r2)
    r3 = call(srv, "trace_eventrec", {"action": "status"})
    check("L3 没地址也没符号 → invalid-argument 一路传出来",
          r3.get("ok") is False and r3.get("error_code") == "invalid-argument", r3)
    # 端到端：十进制的 info_addr 也能用
    link, _ = build_ram({0: ER.encode_record(7, 0, 0, component=1, message=1)},
                        record_index=1, written=1)
    rp = patch_pick(link)
    try:
        r4 = call(srv, "trace_eventrec",
                  {"action": "status", "info_addr": str(INFO_A), "link": "keil"})
        check("L4 十进制 info_addr 也认；状态块经 server 仍在 event_status 下"
              "（不与信封的 status 字符串撞车）",
              r4.get("ok") and r4["info"]["record_count"] == 8
              and (r4.get("event_status") or {}).get("signature_ok") is True
              and r4.get("status") == "ok", r4)
        r5 = call(srv, "trace_eventrec",
                  {"action": "stats", "info_addr": "0x%X" % INFO_A, "link": "keil"})
        check("L5 stats 端到端：没有 0xEF 成对事件时给 note 而不是空表假象",
              r5.get("ok") and not (r5.get("stats") or {}).get("items")
              and "component=0xEF" in ((r5.get("stats") or {}).get("note") or ""), r5)
    finally:
        rp()

def section_m():
    print("M. 文档同步")
    g = TRC.GUIDE
    limits = g.get("swd_limits") or ""
    links = g.get("links") or ""
    check("M1 swd_limits 不再说「本工具集不解码」，而是给出 trace_eventrec",
          "trace_eventrec" in limits and "本工具集**不解码**" not in limits, "")
    check("M2 swd_limits 把它能读到什么说清（事件流 + Event Statistics 口径）",
          "action=read" in limits and "action=stats" in limits, "")
    check("M3 swd_limits 同时保留诚实边界（SCVD 事件名 / level 不随记录存 / 必须插桩）",
          "SCVD" in limits and "component=0xEF" in limits
          and "eventrec-symbol-missing" in limits, "")
    check("M4 links 段说明本工具集能直接解码这份缓冲",
          "trace_eventrec" in links and "能直接解码" in links, links)
    check("M5 trace_guide 描述提到 Event Recorder 也只要 SWD",
          "Event Recorder" in (TRC.GUIDE.get("swd_limits") or "")
          and "trace_eventrec" in str(TRC.GUIDE), "")

    def rd(p):
        with open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
            return f.read()

    readme = rd("README.md")
    skill = rd("skills/mdkdebug/SKILL.md")
    check("M6 README 写的是 200 个工具、收起 156",
          "200 个" in readme and "156 个" in readme and "178 个" not in readme
          and "139 个" not in readme, "")
    check("M7 README 工具表里有 trace_eventrec 一行（含 action 三个取值）",
          "trace_eventrec" in readme and "`status`/`read`/`stats`" in readme, "")
    check("M8 SKILL.md 工具数 200、收起 156、只读清单里有 trace_eventrec",
          "200 个工具" in skill and "156 个" in skill and "trace_eventrec" in skill, "")

def main():
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    section_f()
    section_g()
    section_h()
    section_i()
    section_j()
    section_k()
    section_l()
    section_m()
    print("\n批次53 结果：%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
