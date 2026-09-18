# -*- coding: utf-8 -*-
"""函数运行时线录制的**链路 I/O**（批次49）——MDK 与 OpenOCD 分开实现。

分工：``rtrecord.py`` 管「链路无关」的那一半（事件分类 / caller 归属 / 栈深估计 /
统计 / 环形缓冲）；本模块管另一半，也就是真正去动目标的那部分：

* ``KeilBackend``  UVSOCK  —— BS/BK 下撤断点 + wait_breakpoint 等命中 + 读核寄存器
* ``OcdBackend``   OpenOCD —— bp/rbp 下撤断点 + resume/wait_halt + reg

两条链路**没有一行共同的抓取代码**（用户明确「无法合并成同一个，可以分开支持」），
只在 ``Backend`` 这一层接口上对齐，好让 server 侧一个工具名就能选链路，
并在返回里写明这次实际走的是哪条链路、那条链路的限制是什么。

诚实边界（与全项目一致的「不猜」）
--------------------------------
* 断点槽位有限（Cortex-M 硬件断点一般 6 个，M0 只有 4 个）：要监控的函数多于槽位时
  **只布下能布下的**，armed / skipped / slots 如实说明，不假装全下上了。
* exit 事件靠「命中入口时拿 LR 看到的返回地址**动态补一个断点**」实现；槽位不够就不补，
  事件里自然没有 exit——返回里说明，不编出来。
* 轮询节奏决定丢不丢事件（长录制会丢），dropped 由 Recorder 如实累计。
"""
from __future__ import annotations

import time

from .rtrecord import Recorder

# 硬件断点槽位的**保守**默认：Cortex-M3/M4/M7 的 FPB 一般 6 个，M0 只有 4 个，
# 再加上调试器自身可能占用，默认只布 4 个——宁可少布并说明，也不要撞上「下不上」。
DEFAULT_SLOTS = 4

class Backend:
    """一条链路的抓取原语。子类各自实现，互不共享代码。"""

    name = "?"
    label = "?"
    supports_exit = True

    def available(self) -> bool:
        raise NotImplementedError

    def describe(self) -> dict:
        return {"name": self.name, "label": self.label}

    def halt(self) -> dict:
        raise NotImplementedError

    def resume(self) -> dict:
        raise NotImplementedError

    def regs(self, names=("pc", "lr", "sp")) -> dict:
        raise NotImplementedError

    def read_u32(self, addr: int):
        """读 32 位（读 CYCCNT 用）。返回 (value|None, meta)。"""
        raise NotImplementedError

    def set_bp(self, addr: int):
        """返回 (ok, info)。地址的 Thumb 位由本方法归一。"""
        raise NotImplementedError

    def clear_bp(self, addr: int):
        return False, {"error": "%s 链路不支持撤断点" % self.label}

    def wait_hit(self, addrs, timeout_s: float = 10.0) -> dict:
        """等到目标因断点而停下。返回 {ok, hit, hit_address, registers, ...}。"""
        raise NotImplementedError

    def slots(self) -> int:
        return DEFAULT_SLOTS

    def cyccnt(self):
        """读 DWT_CYCCNT（Cortex-M3+ 才有）。读不到返回 (None, meta)，不猜。"""
        v, meta = self.read_u32(0xE0001004)
        if v is None:
            return None, meta
        return v, meta

# ----------------------------------------------------------------------
# MDK / Keil（UVSOCK）
# ----------------------------------------------------------------------
class KeilBackend(Backend):
    """Keil 链路：命令窗口 BS/BK 下撤断点，UVSOCK 的 wait_breakpoint 等命中。"""

    name = "keil"
    label = "Keil/UVSOCK"
    supports_exit = True

    def __init__(self, client=None, link=None):
        from . import linkio as _link
        self.client = client
        self.link = link if link is not None else _link.KeilLink(client)

    def available(self) -> bool:
        try:
            return bool(self.link.available())
        except Exception:  # noqa: BLE001
            return False

    def describe(self) -> dict:
        d = super().describe()
        try:
            d.update(self.link.describe())
        except Exception:  # noqa: BLE001
            pass
        return d

    def halt(self) -> dict:
        return self.link.halt()

    def resume(self) -> dict:
        return self.link.resume()

    def regs(self, names=("pc", "lr", "sp")) -> dict:
        return self.link.regs(names)

    def read_u32(self, addr: int):
        data, meta = self.link.read_once(int(addr), 4)
        if data is None or len(data) < 4:
            return None, meta
        return int.from_bytes(data[:4], "little"), meta

    def set_bp(self, addr: int):
        a = int(addr) & ~1          # 真机实测：BS 对奇数地址报 error 57 illegal address
        try:
            r = self.client.set_breakpoint("0x%X" % a)
        except Exception as e:  # noqa: BLE001
            return False, {"error": "下断点异常：%s" % e}
        r = dict(r or {})
        r["addr"] = "0x%X" % a
        return bool(r.get("ok")), r

    def clear_bp(self, addr: int):
        a = int(addr) & ~1
        try:
            r = self.client.clear_breakpoint("0x%X" % a)
        except Exception as e:  # noqa: BLE001
            return False, {"error": "撤断点异常：%s" % e}
        r = dict(r or {})
        r["addr"] = "0x%X" % a
        return bool(r.get("ok")), r

    def wait_hit(self, addrs, timeout_s: float = 10.0) -> dict:
        try:
            r = self.client.wait_breakpoint(addresses=[int(a) for a in (addrs or [])],
                                            timeout_s=float(timeout_s))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "hit": False, "link": self.name,
                    "error": "等待命中异常：%s" % e}
        r = dict(r or {})
        r.setdefault("link", self.name)
        r["hit"] = bool(r.get("hit"))
        return r

# ----------------------------------------------------------------------
# OpenOCD（telnet）
# ----------------------------------------------------------------------
class OcdBackend(Backend):
    """OpenOCD 链路：telnet 的 bp/rbp 下撤断点，resume + wait_halt 等命中。"""

    name = "ocd"
    label = "OpenOCD"
    supports_exit = True

    def __init__(self, session=None, link=None):
        from . import linkio as _link
        self.session = session
        self.link = link if link is not None else _link.OcdLink(session)

    def available(self) -> bool:
        try:
            return bool(self.session is not None and self.session.running())
        except Exception:  # noqa: BLE001
            return False

    def halt(self) -> dict:
        return self.link.halt()

    def resume(self) -> dict:
        return self.link.resume()

    def regs(self, names=("pc", "lr", "sp")) -> dict:
        return self.link.regs(names)

    def read_u32(self, addr: int):
        data, meta = self.link.read(int(addr), 4)
        if data is None or len(data) < 4:
            return None, meta
        return int.from_bytes(data[:4], "little"), meta

    def set_bp(self, addr: int):
        from .ocd import _norm_code_addr
        a, thumb = _norm_code_addr(int(addr))
        r = self.session.cmd("bp 0x%X" % a, timeout=8)
        info = {"addr": "0x%X" % a, "raw": (r or {}).get("output")}
        if thumb:
            info["thumb_note"] = "地址 bit0=1（Thumb 标记）已清零后再下断点"
        if not (r or {}).get("ok"):
            info["error"] = ((r or {}).get("error") or (r or {}).get("output")
                             or "bp 失败")
            info["hint"] = ("硬件断点资源有限（Cortex-M0 只有 4 个）：可用 "
                            "trace_record(max_breakpoints=…) 调小监控点数量")
        return bool((r or {}).get("ok")), info

    def clear_bp(self, addr: int):
        from .ocd import _norm_code_addr
        a, _thumb = _norm_code_addr(int(addr))
        r = self.session.cmd("rbp 0x%X" % a, timeout=8)
        info = {"addr": "0x%X" % a}
        if not (r or {}).get("ok"):
            info["error"] = ((r or {}).get("error") or (r or {}).get("output")
                             or "rbp 失败")
        return bool((r or {}).get("ok")), info

    def wait_hit(self, addrs, timeout_s: float = 10.0) -> dict:
        ms = int(max(1.0, float(timeout_s)) * 1000)
        r = self.session.cmd("wait_halt %d" % ms, timeout=float(timeout_s) + 5)
        out = {"ok": bool((r or {}).get("ok")), "link": self.name,
               "raw": (r or {}).get("output")}
        # wait_halt 超时也会正常返回——**不能只信命令回显**，要用「读得到核寄存器」
        # 这条硬证据判目标是否真的停了（读不到 = 还在跑）。
        rr = self.regs(("pc", "lr", "sp"))
        if rr.get("ok"):
            out["hit"] = True
            out["hit_address"] = rr.get("pc")
            out["registers"] = rr
        else:
            out["hit"] = False
            out["reason"] = ("wait_halt 未等到停止（%s）"
                             % (rr.get("error") or "读不到核寄存器"))
        return out

# ----------------------------------------------------------------------
# 选路
# ----------------------------------------------------------------------
def pick(link: str = "auto", who: str = "录制函数时间线"):
    """选一条链路。返回 (Backend, None) 或 (None, 错误 dict)。

    显式指定链路而它不可用时**不换另一条顶上**——那会录到另一个目标的现场，
    比报错更有害（与 linkio.pick 同一套约定）。
    """
    want = str(link or "auto").strip().lower()
    if want in ("keil", "mdk", "uvsock", "uv4"):
        want = "keil"
    elif want in ("ocd", "openocd", "daplink"):
        want = "ocd"
    elif want in ("auto", ""):
        want = "auto"
    else:
        return None, {"ok": False, "reason": "bad-link-name",
                      "error": "link 只能是 auto / keil / ocd（收到 %r）" % (link,),
                      "hint": "auto=哪条链路有活会话用哪条；keil=Keil/UVSOCK；ocd=OpenOCD"}
    keil = kerr = ocd = oerr = None
    if want in ("auto", "keil"):
        keil, kerr = _try_keil()
    if want in ("auto", "ocd"):
        ocd, oerr = _try_ocd()
    if want == "keil":
        if keil:
            return keil, None
        return None, _fail(want, kerr, None)
    if want == "ocd":
        if ocd:
            return ocd, None
        return None, _fail(want, None, oerr)
    if keil:
        return keil, None
    if ocd:
        return ocd, None
    return None, _fail("auto", kerr, oerr)

def _try_keil():
    # batch50：UVClient 的 socket 是**懒连接**——首次真正用到才开。若只看
    # phy.is_connected，会把「还没连」误报成「链路不可用」，于是 env_check 连芯片都
    # 不去实测（守卫静默失效）。这里先主动连一次：连 UVSOCK 只是开 TCP 与握手，
    # **不进调试、不 halt、不碰目标**，与其余工具首次调用时的行为一致，无副作用。
    try:
        from . import server as _server
        c = getattr(_server, "_client", None)
        if c is None:
            return None, "本进程还没有 Keil 客户端实例（先创建 MCP 服务）"
        if not c.phy.is_connected:
            try:
                c._ensure_connected()
            except Exception as e:  # noqa: BLE001
                # 连不上就是真不可用；异常里已带端口/Keil 进程的体检结论，原样透出
                return None, "连不上 Keil UVSOCK：%s" % e
        b = KeilBackend(c)
        if b.available():
            return b, None
        return None, ("已连上 UVSOCK，但调试会话不可用（先 enter_debug；"
                      "若 Keil 侧弹了模态框/未启用 UVSOCK，用 keil_health 看断在哪一环）")
    except Exception as e:  # noqa: BLE001
        return None, "取 Keil 会话失败：%s" % e

def _try_ocd():
    try:
        from . import ocd as _ocd
        s = _ocd.get_session()
        b = OcdBackend(s)
        if b.available():
            return b, None
        return None, "OpenOCD 没在运行（先 ocd_start）"
    except Exception as e:  # noqa: BLE001
        return None, "取 OpenOCD 会话失败：%s" % e

def _fail(want, kerr, oerr):
    if want == "auto":
        return {"ok": False, "reason": "no-mem-link", "link": "auto",
                "error": "两个链路都没有活着的调试会话，无法录制函数时间线",
                "keil": kerr, "ocd": oerr,
                "hint": "Keil 侧先 enter_debug；非 MDK 目标先 ocd_start → ocd_control(\"halt\")"}
    return {"ok": False, "reason": "no-%s-link" % want, "link": want,
            "error": "指定的链路不可用（link=%s）：%s" % (want, kerr or oerr),
            "hint": ("Keil 侧：enter_debug；非 MDK 目标：ocd_start"
                     if want == "keil" else "非 MDK 目标：ocd_start")}

# ----------------------------------------------------------------------
# 驱动：一次完整录制（两条链路共用这段调度；I/O 全在 Backend 里）
# ----------------------------------------------------------------------
def record(func_index, entries, exits=(), backend=None, max_events: int = 2000,
           max_ms: float = 3000.0, max_breakpoints: int = DEFAULT_SLOTS,
           watch_exit: bool = True, halt_timeout: float = 10.0,
           leave_halted: bool = True, cleanup: bool = True,
           label: str = "", limit: int = 200) -> dict:
    """在 backend 上跑一次「函数运行时线」录制，返回报告 dict。

    entries : 要监控的**入口地址**列表（链接地址，调用方已加 reloc delta）
    exits   : 已知的出口地址（可选；不给也行，靠 watch_exit 动态补）
    """
    if backend is None:
        return {"ok": False, "error": "没有可用的链路后端（先 pick 一条）"}
    t_start = time.time()
    slots = max(1, int(max_breakpoints or backend.slots()))
    ent_all = list(dict.fromkeys(int(a) & ~1 for a in (entries or [])))
    armed = ent_all[:slots]
    skipped = ent_all[slots:]
    rec = Recorder(func_index, exits=set(int(a) & ~1 for a in (exits or [])),
                   max_events=max_events, max_ms=max_ms, label=label)
    out = {"ok": False, "link": backend.name, "link_label": backend.label,
           "slots": slots, "requested": len(ent_all), "armed": ["0x%X" % a for a in armed],
           "skipped": ["0x%X" % a for a in skipped],
           "bp_failed": [], "planted_exits": [], "left_halted": None,
           "breakpoints_left": [], "backend": backend.describe()}
    if skipped:
        out["slots_note"] = ("要监控 %d 个入口，但断点槽位只按 %d 个算：本次**只布了前 %d 个**"
                            "（skipped 里的没在录）。要覆盖更多请分批，或调大 "
                            "max_breakpoints（超出硬件能力时会在这里如实报 bp_failed）"
                            % (len(ent_all), slots, len(armed)))
    if not armed:
        out["error"] = "没有可监控的入口地址（确认符号已加载、funcs/pattern 选到了函数）"
        return out

    # 1) 先让目标停下才能布断点
    hl = backend.halt()
    if not hl.get("ok"):
        out["error"] = ("布断点前 halt 失败：%s"
                        % (hl.get("error") or hl.get("status_text") or "未知原因"))
        out["halt"] = hl
        return out
    out["halt"] = {"ok": True, "was_running": hl.get("was_running")}

    planted = []            # 已布下的断点地址（入口 + 动态出口）
    by_addr = {}
    for a in armed:
        ok, info = backend.set_bp(a)
        by_addr[a] = info
        if ok:
            planted.append(a)
        else:
            out["bp_failed"].append({"addr": "0x%X" % a, "info": info})
    if not planted:
        out["error"] = ("断点一个都没布上（多为槽位不足或地址非法）：先 stop 清干净，"
                        "再用 trace_record(max_breakpoints=…) 调小监控点数量")
        out["ok"] = False
        return out

    # 2) 跑起来，循环等命中
    rs = backend.resume()
    if not rs.get("ok"):
        out["error"] = ("resume 失败：%s（目标没跑起来就不会有事件）"
                        % (rs.get("error") or rs.get("status_text") or "未知原因"))
        return out
    deadline = t_start + max(0.05, float(max_ms) / 1000.0)
    polls = 0
    pending_divergence = 0
    while time.time() < deadline:
        remain = deadline - time.time()
        if remain <= 0:
            break
        cands = list(planted)
        h = backend.wait_hit(cands, timeout_s=min(remain, max(0.2, float(halt_timeout))))
        polls += 1
        if not h.get("hit"):
            break                      # 到点没命中：正常结束，不是错误
        cyc, cyc_meta = backend.cyccnt()
        regs = h.get("registers") or {}
        addr = h.get("hit_address")
        if not isinstance(addr, int):
            addr = regs.get("pc")
        ev = rec.on_hit(addr, cyc=cyc, lr=regs.get("lr"), sp=regs.get("sp"),
                        ts=time.time())
        # 出口事件：命中入口时，LR 就是本次调用的返回地址——动态补一个断点
        if watch_exit and backend.supports_exit and isinstance(regs.get("lr"), int):
            ret = regs["lr"] & ~1
            if ret and ret not in by_addr and len(planted) < slots:
                ok, info = backend.set_bp(ret)
                by_addr[ret] = info
                if ok:
                    planted.append(ret)
                    rec.exits.add(ret)
                    out["planted_exits"].append("0x%X" % ret)
        if rec.total >= rec.max_events:
            break
        if ev.get("cyc") is None:
            pending_divergence += 1
        rs2 = backend.resume()
        if not rs2.get("ok"):
            out["resume_error"] = (rs2.get("error") or rs2.get("status_text")
                                  or "resume 失败")
            break
    elapsed_ms = (time.time() - t_start) * 1000.0

    # 3) 收尾：目标停稳 + 撤掉自己布的断点（撤不掉的如实列出来）
    if leave_halted:
        backend.halt()
        st = backend.regs(("pc",))
        out["left_halted"] = bool(st.get("ok"))
    if cleanup:
        left = []
        for a in planted:
            ok, _info = backend.clear_bp(a)
            if not ok:
                left.append("0x%X" % a)
        out["breakpoints_left"] = left
        if left:
            out["cleanup_note"] = ("有断点没撤干净（%s）：它们会继续拦停目标，"
                                  "请用 clear_breakpoint / ocd_bp(action=\"clear\") 手工清掉"
                                  % "、".join(left))
    out.update(rec.report(limit=int(limit or 200), elapsed_ms=elapsed_ms))
    out["ok"] = True
    out["polls"] = polls
    out["cyccnt_available"] = any(e.get("cyc") is not None for e in rec.events)
    if not out["cyccnt_available"]:
        out["cyccnt_note"] = ("读不到 DWT_CYCCNT（未使能或该内核没有），所以事件里没有 cyc/"
                              "gap_cyc；时间轴请以 t_ms 为准，不要编造成周期数")
    if pending_divergence:
        out["divergence_note"] = "有 %d 次命中读不到 CYCCNT" % pending_divergence
    out["link_limits"] = _limits(backend)
    return out

def _limits(backend) -> dict:
    """本链路这次录制的固有限制，如实披露（免得被当成"没发生"）。"""
    if backend.name == "keil":
        return {"exit_events": "命中入口时用 LR 动态补返回地址断点得到；槽位不够就没有",
                "timing": "命中→读取→resume 的往返有毫秒级开销，事件间隔（gap_cyc）"
                          "不能当精确耗时；精确耗时用 profile_function",
                "loss": "长录制受轮询节奏影响会丢事件（dropped 已累计）"}
    return {"exit_events": "命中入口时用 LR 动态补返回地址断点得到；槽位不够就没有",
            "timing": "wait_halt 的粒度是毫秒级，事件间隔不能当精确耗时",
            "loss": "长录制会丢事件（dropped 已累计）"}
