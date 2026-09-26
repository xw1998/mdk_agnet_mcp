# -*- coding: utf-8 -*-
"""批次66 mock 测试：节拍预算（A3）+ 中断名反查（C3）+ 环尺寸交叉校验（C1）。

三条都是「以前只能试错 / 只能看裸号 / 错了还看不出来」的欠账：

- **A3 节拍预算**：环会满、宿主搬得慢就丢事件，而「还能录多久」以前只能靠试。
  `trace_swd_next` 读两次控制块、用 `head` 的差值测**真实**写入速率，再除剩余空间。
  速率是**测出来的**：目标一个字节都没写就返回 `window_ms=null` 并说明「测不出」，
  绝不拿容量除一个猜的事件率——那是「看似权威的错答案」。

- **C3 中断名反查**：流里的 isr 只带异常号（实测出现过 17 / 5 / 4），看的人得自己
  数。名字的权威来源是**镜像的向量表**（表项 index == 异常号），纯主机侧就能读。
  两条不许越界：① 表尾之后是代码字节，读到「非 0 又不是任何函数首地址」的值就收手，
  否则会拿指令当函数地址解析出一堆看着像样的名字；② 一个地址挂着多个处理函数名，
  说明链接器把一堆空的 `*_IRQHandler` 折成了同一段代码（Keil 常态，本仓的 F427
  工程里 87 个符号同址），这时**分不清是哪一项**，取名等于编名字，一律留空。

- **C1 环尺寸交叉校验**：8192 B 的环是编译期常量（blob = ctrl 80 B + ring）。
  换了固件/换了 .axf 后两边不同源时读环会**静默错位**，解出一堆看着像事件的垃圾。
  校验式：ELF 里 blob 的符号尺寸 == 80 + 控制块自述的 cap（容忍尾部对齐填充）。

  A 节拍预算：测得出 / 测不出的分界，取样中途重开录制作废，环满先搬一次；
    「环快满 + head 不动」判为**背压**而不是「目标没在跑」（真机撞到过方向错的文案）
  B 环尺寸校验：一致 / 尾部填充 / 不同源报错 / 按地址读时跳过
  C trace_swd_next 端到端（假链路 + 假时钟，不碰真目标、不真的 sleep）
  D 中断名：向量表反查、表尾收敛、共享桩守卫、查不到如实说
  E trace_swd_read 的返回带上 irq_names（scenario 假链路）
  F viz：中断轨道吃 irq_names（键在 JSON 往返后是字符串，必须归一）
  G 工具面：trace_swd_next 已注册、在 trace 组、在只读白名单里

运行：python -m tests.test_batch66
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_DESC", "full")   # 批次74 起默认档为 lean；本模块的内容类断言按归档全文（mdk_guide 可取回）评估

os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as A          # noqa: E402
from mdkdebug import server as SV           # noqa: E402
from mdkdebug import swd as SWD             # noqa: E402
from mdkdebug import toolbox as TB          # noqa: E402
from mdkdebug import trace as TRC           # noqa: E402
from mdkdebug import viz as VZ              # noqa: E402
from mdkdebug.viz import adapters as AD     # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)

def js(o):
    import json
    return json.dumps(o, ensure_ascii=False, default=str)

def ctrl(cap=8192, pending=None, head=0, events=0, seq=7, lost=0, addr=0):
    """_swd_budget / _swd_blob_check 只认这几个字段，不必造真的控制块。"""
    return {"addr": addr, "cap": cap, "head": head, "pending":
            (head if pending is None else pending), "events": events,
            "seq": seq, "lost_events": lost, "ts_off": 0}

# ======================================================================
def group_a():
    """A. 节拍预算：测出来的速率，测不出就直说。"""
    print("== A 节拍预算（_swd_budget） ==", flush=True)

    # 8192 的环、已用 1024、剩 7168；0.1 s 里写了 600 B → 6000 B/s
    b = TRC._swd_budget(ctrl(head=0, events=0), ctrl(head=600, events=100, pending=1024), 0.1)
    check("A1 窗口 = 剩余空间 ÷ 实测速率（7168 / 6000 B/s = 1195 ms）",
          b.get("ok") and b.get("window_ms") == 1195, b)
    check("A2 建议节拍 = 窗口 ÷ 安全系数（1195 / 8 ≈ 149 ms）",
          b.get("suggest_pace_ms") == 149, b)
    check("A3 速率是测出来的：600 B / 0.1 s、100 条事件",
          b.get("sampled", {}).get("bytes") == 600
          and b.get("sampled", {}).get("bytes_per_s") == 6000.0, b.get("sampled"))
    check("A4 当前字节/事件 = 600 / 100 = 6 B",
          b.get("bytes_per_event_now") == 6.0, b)
    check("A5 剩余空间还能装多少条事件（7168 / 6 ≈ 1194）",
          b.get("headroom_events") == 1194, b)
    check("A6 headroom_bytes 就是 cap - pending", b.get("headroom_bytes") == 7168, b)
    check("A7 整体口径另算（600 B / 100 条 = 6.0）",
          b.get("bytes_per_event_overall") == 6.0, b)

    # 目标一个字节都没写 → 测不出窗口，**不是**「窗口无限大」
    b = TRC._swd_budget(ctrl(head=300, events=40), ctrl(head=300, events=40), 0.3)
    check("A8 目标没在写就报「测不出」而不是编一个窗口",
          b.get("ok") and b.get("window_ms") is None
          and "window_ms" in b and b.get("suggest_pace_ms") is None, b)
    check("A9 并且明说这不是「窗口无限大」",
          any("一个字节都没写" in w and "无限大" in w for w in b.get("warnings") or []),
          b.get("warnings"))

    # 取样期间目标重开录制：seq 变了 → 作废
    b = TRC._swd_budget(ctrl(head=0, seq=7), ctrl(head=600, seq=8), 0.1)
    check("A10 取样期间 seq 变了 → swd-sample-restarted，不硬算",
          b.get("ok") is False and b.get("error_code") == "swd-sample-restarted", b)

    b = TRC._swd_budget(ctrl(events=100), ctrl(events=20), 0.1)
    check("A11 事件计数倒退同样作废（重新对齐过的流）",
          b.get("ok") is False and b.get("error_code") == "swd-sample-restarted", b)

    b = TRC._swd_budget(ctrl(), ctrl(head=600), 0)
    check("A12 取样间隔为 0 给不出速率",
          b.get("ok") is False and b.get("error_code") == "invalid-argument", b)

    # 环满：先搬一次，别谈节拍
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=900, pending=8192), 0.1)
    check("A13 环已经满了 → window_ms=0 并直说此刻每条都在丢",
          b.get("window_ms") == 0
          and any("每条事件都在丢" in w for w in b.get("warnings") or []), b)

    # 已经丢过事件：窗口偏乐观，必须说
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=600, lost=40, pending=1024), 0.1)
    check("A14 已经丢过事件 → 提醒窗口偏乐观",
          any("偏乐观" in w for w in b.get("warnings") or []), b.get("warnings"))

    # 单轮成本对比
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=600, pending=1024), 0.1, round_ms=500)
    check("A15 单轮 500 ms > 建议节拍 149 ms → 明说按这个节拍也追不上",
          b.get("round_budget", {}).get("ok") is False
          and any("追不上" in w for w in b.get("warnings") or []), b.get("round_budget"))
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=600, pending=1024), 0.1, round_ms=50)
    check("A16 单轮 50 ms 追得上 → ok=true 并给出余量 99 ms",
          b.get("round_budget", {}).get("ok") is True
          and b.get("round_budget", {}).get("margin_ms") == 99, b.get("round_budget"))

    b = TRC._swd_budget(ctrl(head=0, events=0), ctrl(head=600, events=100, pending=1024),
                        0.1, batch_events=1000)
    check("A17 batch_events 估算：搬 1000 条约 6000 B、要攒 1000 ms",
          b.get("batch_estimate", {}).get("bytes") == 6000
          and b.get("batch_estimate", {}).get("accumulate_ms") == 1000, b.get("batch_estimate"))

    b = TRC._swd_budget(ctrl(head=300), ctrl(head=300), 0.3, round_ms=200)
    check("A18 窗口测不出时，单轮成本也就无从比较（ok=null，不冒充结论）",
          b.get("round_budget", {}).get("ok", "x") is None, b.get("round_budget"))

    # ---- 真机撞到的方向错的文案：环快满时 head 不动，被说成「目标没在跑」----
    # （F427 实测 pending=8191/8192、0.12 s 内 head 一个字节没动，目标其实跑得好好的）
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=0, pending=8191), 0.12)
    check("A19 环用到 >= 3/4 且 head 不动 → 判为背压（stalled=ring-nearly-full）",
          b.get("window_ms") is None and b.get("stalled") == "ring-nearly-full"
          and any("背压" in w for w in b.get("warnings") or []), b)
    check("A20 并且点明「这与目标没在跑是两回事」并给出下一步",
          any("两回事" in w and "trace_swd_read" in w for w in b.get("warnings") or []),
          b.get("warnings"))
    check("A21 环接近满时不再重复刷「>= 3/4」那条（上面已经说清楚）",
          sum(1 for w in b.get("warnings") or [] if ">= 3/4" in w) == 1,
          b.get("warnings"))

    b = TRC._swd_budget(ctrl(head=300), ctrl(head=300), 0.3)
    check("A22 环还空着且一个字节没写 → 才是「测不出窗口」（stalled=no-writes）",
          b.get("stalled") == "no-writes"
          and any("一个字节都没写" in w for w in b.get("warnings") or []), b)

    b = TRC._swd_budget(ctrl(head=0), ctrl(head=0, pending=8192), 0.1)
    check("A23 环满 → stalled=ring-full 且 window_ms=0",
          b.get("stalled") == "ring-full" and b.get("window_ms") == 0, b)

    # 真机正路径量到过：剩余 1 B、实测 10.7 KB/s → 窗口 0.09 ms
    b = TRC._swd_budget(ctrl(head=0), ctrl(head=1000, events=300, pending=8191), 0.0935)
    check("A25 窗口算出来不到 1 ms 就说「没有可调的节拍」，不给一个比窗口还大的节拍",
          b.get("window_ms") == 0 and b.get("suggest_pace_ms") == 0
          and "没有可调的节拍" in b.get("note", ""), b)

    b = TRC._swd_budget(ctrl(head=0), ctrl(head=0, pending=8192), 0.1, round_ms=500)
    check("A24 窗口就是 0 时单轮成本结论是确定的：追不上（不再说无从比较）",
          b.get("round_budget", {}).get("ok") is False
          and "追不上" in (b.get("round_budget") or {}).get("why", ""),
          b.get("round_budget"))

def group_b():
    """B. 环尺寸交叉校验：符号与板上固件不同源就报错。"""
    print("== B 环尺寸交叉校验（_swd_blob_check） ==", flush=True)
    loc = {"blob_bytes": SWD.CTRL_BYTES + 8192, "symbol": SWD.SYMBOL}
    check("B1 blob = ctrl(80) + cap(8192) 完全一致 → 放行",
          TRC._swd_blob_check(ctrl(cap=8192), loc) is None)
    loc7 = dict(loc, blob_bytes=SWD.CTRL_BYTES + 8192 + 7)
    check("B2 尾部对齐填充 7 B 以内容忍（不误报）",
          TRC._swd_blob_check(ctrl(cap=8192), loc7) is None)
    bad = TRC._swd_blob_check(ctrl(cap=4096), loc)
    check("B3 ELF 说是 8192、板上自述 4096 → swd-blob-size-mismatch",
          isinstance(bad, dict) and bad.get("error_code") == "swd-blob-size-mismatch", bad)
    check("B4 报错把两个数都摊开（谁跟谁不一致）",
          bad and bad.get("blob_bytes_in_elf") == 8272
          and bad.get("blob_bytes_expected") == 4176
          and bad.get("cap_on_target") == 4096, bad)
    check("B5 按地址读（没有符号尺寸）时跳过这层校验，不误报",
          TRC._swd_blob_check(ctrl(cap=8192), {"method": "addr"}) is None)

    # 接进 swd_status 的路径上（假链路）
    old_loc, old_ctrl = TRC._swd_locate, TRC._swd_read_ctrl
    TRC._swd_locate = lambda elf="", addr="": (0x200020C8,
                                               {"method": "elf_symbol",
                                                "blob_bytes": SWD.CTRL_BYTES + 8192})
    TRC._swd_read_ctrl = lambda a, link="auto": (dict(ctrl(cap=4096), addr=a), None)
    try:
        out = TRC.swd_status(elf="x.axf")
        check("B6 swd_status 走 blob 校验：不同源时直接报错、不再往下给数",
              out.get("ok") is False
              and out.get("error_code") == "swd-blob-size-mismatch", out)
    finally:
        TRC._swd_locate, TRC._swd_read_ctrl = old_loc, old_ctrl

def group_c():
    """C. trace_swd_next 端到端（假链路 + 假时钟）。"""
    print("== C trace_swd_next 端到端 ==", flush=True)
    infos = [dict(ctrl(head=0, events=0, pending=1024), addr=0x200020C8),
             dict(ctrl(head=600, events=100, pending=1024), addr=0x200020C8)]
    old_loc, old_ctrl, old_time = TRC._swd_locate, TRC._swd_read_ctrl, TRC.time
    seq = {"i": 0}

    def fake_ctrl(a, link="auto"):
        i = min(seq["i"], len(infos) - 1)
        seq["i"] += 1
        return dict(infos[i]), None

    class FakeTime:
        def __init__(self):
            self.t = 1000.0
        def monotonic(self):
            return self.t
        def sleep(self, s):
            self.t += float(s)

    TRC._swd_locate = lambda elf="", addr="": (0x200020C8, {"method": "addr"})
    TRC._swd_read_ctrl = fake_ctrl
    TRC.time = FakeTime()
    try:
        out = TRC.swd_next(addr="0x200020C8", sample_ms=100)
        check("C1 采样 100 ms → 窗口 1195 ms / 建议节拍 149 ms",
              out.get("ok") and out.get("window_ms") == 1195
              and out.get("suggest_pace_ms") == 149, out)
        check("C2 带上 locate 与时间粒度说明（下游画图/判读用）",
              out.get("locate") and "granularity" in out, sorted(out))
        check("C3 参数越界报错（sample_ms 上限 5000）",
              TRC.swd_next(addr="0x1", sample_ms=99999).get("error_code")
              == "invalid-argument")
        check("C4 safety < 1 报错（1 表示「一满就搬」，没有余量）",
              TRC.swd_next(addr="0x1", safety=0.5).get("error_code")
              == "invalid-argument")
        check("C5 swd_next 是只读的：不搬字节、不动游标",
              "bytes_drained" not in out and "cursor_after" not in out, sorted(out))
    finally:
        TRC._swd_locate, TRC._swd_read_ctrl, TRC.time = old_loc, old_ctrl, old_time

def group_d():
    """D. 中断名反查：向量表是权威，读不到就留空。"""
    print("== D 中断名反查（irq_names_for） ==", flush=True)

    got, why = TRC.irq_names_for("", [])
    check("D1 没有中断事件就不取名，并把「无需取名」说清楚",
          got == {} and "没有中断" in why, (got, why))

    got, why = TRC.irq_names_for("/no/such/file.axf", [53])
    check("D2 文件不存在 → 空表 + 说明（不编名字）",
          got == {} and why, (got, why))

    # 假符号表：53 有名字，300 是表里取不到的号，11/14 是内核异常号
    old = TRC._irq_names_from_elf
    TRC._irq_names_from_elf = lambda e: {53: "USART1_IRQHandler"}
    try:
        got, why = TRC.irq_names_for("whatever.axf", [11, 14, 53, 300])
        check("D3 取到的号给名字、内核异常号单独归类、取不到的明说哪个号",
              got == {53: "USART1_IRQHandler"} and "11, 14" in why and "300" in why,
              (got, why))
        check("D4 说明里点出「分不清是哪一个」的共享桩这类留空原因",
              "多个处理函数名" in why, why)
    finally:
        TRC._irq_names_from_elf = old

    # 真实镜像：F427 内核工程（本地有就用，没有就跳过）
    real = [os.path.join(ROOT, "example_mdk_project", "mdk_test", "MDK-ARM",
                         "mdk_test", "mdk_test.axf")]
    real.append(r"D:\工作\git_project\svcrtos_new\example\stm32f427\kernel"
                r"\SVCRTOS_TEST\MDK-ARM\SVCRTOS_TEST\SVCRTOS_TEST.axf")
    picked = [p for p in real if os.path.isfile(p)]
    if not picked:
        print("  [SKIP] D5+ 没有本地 .axf 可解析", flush=True)
        return
    for p in picked:
        m = TRC._irq_names_from_elf(p)
        tag = os.path.basename(p)
        if "SVCRTOS" in tag:
            check("D5 %s：USART1_IRQHandler 落在异常号 53（IRQ 37 + 16）" % tag,
                  m.get(53) == "USART1_IRQHandler", m)
        check("D6 %s：共享默认桩不许被当成某一路中断的名字（同址 87 个符号那种）" % tag,
              "ADC_IRQHandler" not in m.values(), sorted(m.items())[:12])
        check("D7 %s：表尾之后是代码字节，不许再往下解析出名字（数量收敛）" % tag,
              len(m) <= 8, sorted(m.items()))

def group_e():
    """E. trace_swd_read 的返回带上 irq_names。"""
    print("== E swd_read 带 irq_names ==", flush=True)
    try:
        from tests.test_batch64 import scenario, BLOB_ADDR
    except Exception as e:  # noqa: BLE001
        print("  [SKIP] 拿不到 batch64 的假链路：%s" % e, flush=True)
        return
    evs = [(SWD.make_key(4, 0, 53, 0), 0),      # isr enter 53
           (SWD.make_key(4, 1, 53, 0), 0),      # isr exit 53
           (SWD.make_key(10, 2, 0, 1), 0)]      # sched
    lk, hits, undo = scenario(evs)
    old = TRC._irq_names_from_elf
    TRC._irq_names_from_elf = lambda e: {53: "USART1_IRQHandler"}
    try:
        out = TRC.swd_read(elf=__file__, addr=BLOB_ADDR, tasks="off", limit=50)
        check("E1 返回里带 irq_names（中断号 → 处理函数名）",
              out.get("irq_names") == {53: "USART1_IRQHandler"}, out.get("irq_names"))
        check("E2 同时带来源说明（名字是从镜像向量表反查的）",
              "向量表" in str(out.get("irq_names_note")), out.get("irq_names_note"))
        check("E3 事件本身照旧不吃中断名（id_name 仍由 names= 决定）",
              all(e.get("id_name") is None for e in out["events"] if e.get("type") == "isr"),
              [(e.get("id"), e.get("id_name")) for e in out["events"]])
    finally:
        TRC._irq_names_from_elf = old
        undo()

    # 取不到名时如实说明
    lk, hits, undo = scenario(evs)
    old = TRC._irq_names_from_elf
    TRC._irq_names_from_elf = lambda e: {}
    try:
        out = TRC.swd_read(elf=__file__, addr=BLOB_ADDR, tasks="off", limit=50)
        check("E4 取不到名 → irq_names 为空且说明里讲清为什么",
              not out.get("irq_names")
              and "向量表" in str(out.get("irq_names_note")), out.get("irq_names_note"))
    finally:
        TRC._irq_names_from_elf = old
        undo()

def group_f():
    """F. viz：中断轨道吃 irq_names。"""
    print("== F viz 中断轨道命名 ==", flush=True)
    check("F1 键从 JSON 回来后是字符串，也要能按 int 查到",
          AD._irq_names_from_payload({"irq_names": {"53": "USART1_IRQHandler"}})
          == {53: "USART1_IRQHandler"})
    check("F2 没有 irq_names 时给空表（不炸）",
          AD._irq_names_from_payload({}) == {})

    PAY = {
        "ctrl": {"cpu_hz": 168000000},
        "events": [
            {"type": "isr", "kind": "enter", "id": 53, "t_us": 0},
            {"type": "isr", "kind": "exit", "id": 53, "t_us": 40},
            {"type": "segment", "kind": "point", "seq": 1, "t_us": 60},
        ],
        "irq_names": {"53": "USART1_IRQHandler"},
        "irq_names_note": "中断号 → 处理函数名取自镜像的向量表（异常号 >= 16 的外设段）",
    }
    r = VZ.adapt(PAY, view="timeline")
    tnames = {t["id"]: t.get("name") for t in (r.get("model") or {}).get("tracks") or []}
    check("F3 中断轨道用向量表反查到的处理函数名（不再是 IRQ53）",
          tnames.get("isr-53") == "USART1_IRQHandler", tnames)

    # 显式 names 优先于返回体里的 irq_names（调用方说了算）
    r4 = VZ.adapt(PAY, view="timeline", names={53: "MY_OVERRIDE"})
    t4 = {t["id"]: t.get("name")
          for t in ((r4.get("model") or {}).get("tracks") or [])}
    check("F4 显式 names 优先于返回体里的 irq_names（调用方说了算）",
          t4.get("isr-53") == "MY_OVERRIDE", t4)

    PAY2 = dict(PAY, irq_names={})
    r2 = VZ.adapt(PAY2, view="timeline")
    m2 = r2.get("model") or {}
    t2 = {t["id"]: t.get("name") for t in m2.get("tracks") or []}
    check("F5 取不到名时仍然画 IRQ53，并在 limits 里讲清原因（不静默）",
          t2.get("isr-53") == "IRQ53"
          and any("irq_names" in str(x) or "中断号" in str(x)
                  for x in m2.get("limits") or []), (t2, m2.get("limits")))

def group_g():
    """G. 工具面登记。"""
    print("== G 工具面 ==", flush=True)
    names_all = [t.name for t in __import__("asyncio").run(
        SV.create_server(toolsets="all").list_tools())]
    check("G1 trace_swd_next 已注册、总数 200",
          "trace_swd_next" in names_all and len(names_all) == 200,
          (len(names_all), "trace_swd_next" in names_all))
    trace_names = [t.name for t in __import__("asyncio").run(
        SV.create_server(toolsets="trace").list_tools())]
    check("G2 它跟 trace_swd_* 同组（装载 trace 组就该有它）",
          "trace_swd_next" in trace_names, [x for x in trace_names if "swd" in x])
    check("G3 归在 toolbox 的 trace 组里（不是孤儿工具）",
          "trace_swd_next" in (TB.TOOLSETS.get("trace") or set()),
          sorted(x for x in (TB.TOOLSETS.get("trace") or set()) if "swd" in x))
    check("G4 它在只读白名单里（只读两次控制块，不搬字节）",
          any(isinstance(v, set) and "trace_swd_next" in v for v in vars(A).values()))

    tools = {t.name: t for t in __import__("asyncio").run(
        SV.create_server(toolsets="all").list_tools())}
    t = tools.get("trace_swd_next")
    props = ((t.input_schema or {}).get("properties") or {}) if t else {}
    check("G5 参数齐：elf/addr/link/sample_ms/safety/round_ms/batch_events",
          set(props) >= {"elf", "addr", "link", "sample_ms", "safety",
                         "round_ms", "batch_events"}, sorted(props))
    desc = (t.description or "") if t else ""
    check("G6 描述里交代了「速率是测出来的、测不出就说测不出」",
          "测出来的" in desc and "window_ms=null" in desc, desc[:200])
    check("G7 描述里交代了「只读、不搬字节不停机」",
          "只读" in desc and "不搬字节" in desc, desc[:200])

def main():
    print("批次66：节拍预算（A3）+ 中断名反查（C3）+ 环尺寸交叉校验（C1）")
    group_a(); group_b(); group_c(); group_d(); group_e(); group_f(); group_g()
    print("\n==== 批次66 结果：%d 通过 / %d 失败 ====" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：%s" % ", ".join(FAIL))
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
