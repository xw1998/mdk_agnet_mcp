# -*- coding: utf-8 -*-
"""链路原语层（link I/O）：把「读/写目标内存、读核寄存器、停/走」从具体调试链路里抽出来。

为什么需要它：SWO / RTT / 变量 scope / PC 采样这些**观测**能力，本质只需要
「能读目标 RAM」「能读核寄存器」，与背后是 Keil(UVSOCK) 还是 OpenOCD 无关。
批次36 把这套观测做在了 OpenOCD 链路上，于是**Keil 用户看不到它们**——
本模块让同一套观测代码在两条链路上跑（同一套语义、同一套披露字段）。

约定（三条，都是被真机教出来的）：

* `pick()` **不猜**：哪条链路上有活着的会话就用哪条；两条都没有就如实报错，
  并把两条链路各自的原因与「怎么把它起起来」都带上（`reason="no-mem-link"`）。
* 读回来的数据一定带 `meta`：可疑就读成脏值（`degenerate`）、置信度
  （`read_confidence`）、复读次数、目标当时是否在全速跑（`while_running`）——
  让上层能如实披露，而不是把「读到 0」当结论。
* 链路对象**不缓存跨调用状态**：每次 `pick()` 现查会话，会话没了立刻反映出来；
  只有「目标是否在跑」做了 1 秒 TTL 缓存，免得轮询时每个采样点都多打一次状态查询。

切换链路：观测类工具都接受 `link="auto|keil|ocd"`。显式指定而那条链路不可用时，
**不用另一条链路的会话顶上**（那会读到另一个目标），直接报错说清原因。
"""

from __future__ import annotations

import re
import time

__all__ = ["Link", "KeilLink", "OcdLink", "pick", "describe_links", "read_mem_mask"]

_STATUS_TTL = 1.0
# 「目标在不在跑」的状态缓存按链路名共享，跨 Link 实例有效：
# 变量 scope 每轮都新建链路对象，若各自缓存，轮询时每个采样点都要多打一次状态查询。
_STATUS_MEM = {}

# 上层（trace/rtos）用来判断「读失败的根因是不是目标在跑」的措辞
_HALT_LIKE = ("not halted", "target not halted", "cannot read memory")


def halt_like(err) -> bool:
    t = str(err or "").lower()
    return any(k in t for k in _HALT_LIKE)


class Link:
    """一条调试链路的原语接口。子类只实现自己支持的，不支持的老实报不支持。"""

    name = "?"
    label = "?"

    def __init__(self, session=None):
        self.session = session
        self._status_at = 0.0
        self._status = None

    # -- 能力探测 ------------------------------------------------------
    def available(self) -> bool:
        return self.session is not None

    def describe(self) -> dict:
        return {"name": self.name, "label": self.label}

    # -- 内存 ----------------------------------------------------------
    def read(self, addr: int, n_bytes: int):
        """返回 (bytes|None, meta)。失败时 bytes 为 None，meta 里必有 error。"""
        raise NotImplementedError

    def write(self, addr: int, data: bytes):
        """返回 (ok, meta)。"""
        raise NotImplementedError

    # -- 核寄存器 / 执行控制 -------------------------------------------
    def regs(self, names=("pc",)) -> dict:
        return {"ok": False, "link": self.name,
                "error": "%s 链路不支持读核寄存器" % self.label}

    def target_running(self):
        """True 全速跑 / False 已停 / None 判不出来（不猜）。"""
        return None

    def halt(self) -> dict:
        return {"ok": False, "link": self.name,
                "error": "%s 链路不支持 halt" % self.label}

    def resume(self) -> dict:
        return {"ok": False, "link": self.name,
                "error": "%s 链路不支持 resume" % self.label}

    def need_halt_for_read(self) -> bool:
        """读内存是否要求目标已停。Keil 在跑时读可能错位 → True。"""
        return False

    # -- 内部：状态查询 1 秒 TTL ---------------------------------------
    def _status_cached(self, ttl: float = _STATUS_TTL):
        now = time.time()
        hit = _STATUS_MEM.get(self.name)
        if hit is not None and now - hit[0] <= ttl:
            return hit[1]
        if self._status is not None and now - self._status_at <= ttl:
            return self._status
        try:
            self._status = self._status_query()
        except Exception as e:                                      # noqa: BLE001
            self._status = {"ok": False, "error": str(e)}
        self._status_at = now
        _STATUS_MEM[self.name] = (now, self._status)
        return self._status

    def _status_query(self) -> dict:
        return {}


class KeilLink(Link):
    """Keil / UVSOCK 链路：读走 read_mem_verified（自带脏读复读判定）。"""

    name = "keil"
    label = "Keil/UVSOCK"

    def __init__(self, client=None):
        super().__init__(client)
        self.client = client

    def available(self) -> bool:
        c = self.client
        return bool(c is not None and getattr(c.phy, "is_connected", False))

    def describe(self) -> dict:
        d = super().describe()
        st = self._status_cached()
        d.update({"debugging": st.get("debugging"),
                  "running": st.get("running"),
                  "status_text": st.get("status_text") or st.get("error")})
        return d

    def _status_query(self) -> dict:
        return self.client.get_status()

    def target_running(self):
        st = self._status_cached()
        if st.get("debugging") is False:
            return None                      # 没在调试，谈不上跑不跑
        return st.get("running")

    def need_halt_for_read(self) -> bool:
        # Keil 侧目标全速跑时读内存可能错位（UVSOCK 的固有性质），
        # 所以「在跑」时读要不要改走 halt 由上层决定，这里如实声明。
        return True

    def read(self, addr: int, n_bytes: int):
        c = self.client
        if c is None:
            return None, {"link": self.name, "error": "没有 Keil 会话"}
        r = c.read_mem_verified(int(addr), int(n_bytes), verify="auto")
        meta = {"link": self.name,
                "read_confidence": r.get("read_confidence"),
                "reread_count": r.get("reread_count"),
                "reread_consistent": r.get("reread_consistent"),
                "since_stop_s": r.get("since_stop_s"),
                "target_running": r.get("target_running")}
        for k in ("degenerate", "degenerate_note", "content_note", "warning", "cache"):
            if r.get(k) is not None:
                meta[k] = r[k]
        run = self.target_running()
        if run is not None:
            meta["while_running"] = bool(run)
        if not r.get("ok"):
            meta["error"] = (r.get("status_text") or r.get("error")
                             or "Keil 读内存失败")
            meta["error_code"] = r.get("error_code")
            return None, meta
        try:
            return bytes.fromhex(r.get("data_hex") or ""), meta
        except ValueError:
            meta["error"] = "Keil 返回的内存内容不是合法十六进制：%r" % (r.get("data_hex"),)
            return None, meta

    def write(self, addr: int, data: bytes):
        c = self.client
        if c is None:
            return False, {"link": self.name, "error": "没有 Keil 会话"}
        r = c.write_mem(int(addr), bytes(data))
        ok = bool(r.get("ok"))
        meta = {"link": self.name, "written": r.get("written"),
                "requested": len(data)}
        if not ok:
            meta["error"] = r.get("status_text") or r.get("error") or "Keil 写内存失败"
        return ok, meta

    def regs(self, names=("pc",)) -> dict:
        try:
            r = self.client.read_cpu_registers_stable()
        except Exception as e:                                      # noqa: BLE001
            return {"ok": False, "link": self.name, "error": "读核寄存器失败：%s" % e}
        if not r.get("ok"):
            return {"ok": False, "link": self.name,
                    "error": r.get("error") or r.get("status_text") or "读核寄存器失败",
                    "detail": r}
        out = {"ok": True, "link": self.name}
        for k in names:
            v = r.get(k)
            if isinstance(v, int):
                out[k] = v & ~1 if k == "pc" else v
        if "pc" in names and "pc" not in out:
            out["ok"] = False
            out["error"] = "Keil 没给出 PC（未处于调试状态？）"
        return out

    def halt(self) -> dict:
        _STATUS_MEM.pop(self.name, None)
        try:
            r = self.client.stop()
        except Exception as e:                                      # noqa: BLE001
            return {"ok": False, "link": self.name, "error": "halt 失败：%s" % e}
        r = dict(r or {})
        r.setdefault("link", self.name)
        self._status = None
        return r

    def resume(self) -> dict:
        _STATUS_MEM.pop(self.name, None)
        try:
            r = self.client.run()
        except Exception as e:                                      # noqa: BLE001
            return {"ok": False, "link": self.name, "error": "resume 失败：%s" % e}
        r = dict(r or {})
        r.setdefault("link", self.name)
        self._status = None
        return r


class OcdLink(Link):
    """OpenOCD 链路：mdw/mww + reg，与批次36 的行为保持一致。"""

    name = "ocd"
    label = "OpenOCD"

    def available(self) -> bool:
        s = self.session
        try:
            return bool(s is not None and s.running())
        except Exception:                                           # noqa: BLE001
            return False

    def describe(self) -> dict:
        d = super().describe()
        d.update({"running_session": self.available()})
        return d

    def read(self, addr: int, n_bytes: int):
        from . import ocd as _ocd
        s = self.session
        count = max(1, (int(n_bytes) + 3) // 4)
        r = s.cmd("mdw 0x%X %d" % (int(addr), count), timeout=5)
        if not r.get("ok"):
            err = (r.get("error") or r.get("output") or "mdw 失败").strip()
            return None, {"link": self.name, "error": err[:200],
                          "halt_like": halt_like(err)}
        p = _ocd._parse_mem(r.get("output") or "", int(addr), count, 32)
        if not p["complete"]:
            return None, {"link": self.name,
                          "error": "读取不完整（%d/%d 字）" % (p["got"], count)}
        return _ocd._mem_to_bytes(p["words"], 32, int(n_bytes)), {"link": self.name}

    def write(self, addr: int, data: bytes):
        from . import ocd as _ocd
        s = self.session
        buf = bytes(data)
        pad = (-len(buf)) % 4
        buf += b"\x00" * pad
        for i in range(0, len(buf), 4):
            w = int.from_bytes(buf[i:i + 4], "little")
            r = s.cmd("mww 0x%X 0x%X" % (int(addr) + i, w), timeout=5)
            if not r.get("ok"):
                err = (r.get("error") or r.get("output") or "mww 失败").strip()
                return False, {"link": self.name, "error": err[:200], "written": i}
        return True, {"link": self.name, "written": len(data), "padded": pad}

    def regs(self, names=("pc",)) -> dict:
        s = self.session
        out = {"ok": True, "link": self.name}
        for k in names:
            r = s.cmd("reg %s" % k, timeout=5)
            if not r.get("ok"):
                return {"ok": False, "link": self.name,
                        "error": (r.get("error") or r.get("output") or
                                  "reg %s 失败" % k).strip()[:200]}
            m = re.search(r"(0x[0-9a-fA-F]{4,})", r.get("output") or "")
            if not m:
                return {"ok": False, "link": self.name,
                        "error": "reg %s 输出里没有可解析的数值：%r"
                                 % (k, (r.get("output") or "")[:120])}
            v = int(m.group(1), 16)
            out[k] = v & ~1 if k == "pc" else v
        return out

    def target_running(self):
        # 证据来自「能不能读核寄存器」：halt 时才读得到。
        r = self.regs(("pc",))
        if r.get("ok"):
            return False
        if halt_like(r.get("error")):
            return True
        return None

    def halt(self) -> dict:
        r = self.session.cmd("halt", timeout=5)
        r = dict(r or {})
        r.setdefault("link", self.name)
        return r

    def resume(self) -> dict:
        r = self.session.cmd("resume", timeout=5)
        r = dict(r or {})
        r.setdefault("link", self.name)
        return r


# ==================================================================== 选路

def _try_keil():
    try:
        from . import server as _server
        c = getattr(_server, "_client", None)
        lk = KeilLink(c)
        if lk.available():
            return lk, None
        return None, "Keil 侧的 UVSOCK 会话没连着（先 enter_debug，或确认 Keil 已启动）"
    except Exception as e:                                          # noqa: BLE001
        return None, "取 Keil 会话失败：%s" % e


def _try_ocd():
    try:
        from . import ocd as _ocd
        s = _ocd.get_session()
        lk = OcdLink(s)
        if lk.available():
            return lk, None
        return None, "OpenOCD 没在运行（先 ocd_start）"
    except Exception as e:                                          # noqa: BLE001
        return None, "取 OpenOCD 会话失败：%s" % e


_HINTS = {
    "keil": "Keil 侧：enter_debug（会连带进调试，必要时先 compile/flash）",
    "ocd": "非 MDK 目标：ocd_start → ocd_control(\"halt\")",
}


def pick(link: str = "auto", who: str = "读目标内存"):
    """选一条链路。返回 (Link, None) 或 (None, 错误 dict)。

    显式指定链路而它不可用时**不换另一条顶上**——那会读到另一个目标的现场。
    """
    want = str(link or "auto").strip().lower()
    if want in ("keil", "mdk", "uvsock", "uv4"):
        want = "keil"
    elif want in ("ocd", "openocd", "daplink"):
        want = "ocd"
    elif want in ("auto", ""):
        want = "auto"
    else:
        # 拼错链路名不许静默退化成 auto：那等于把「另一个目标的现场」端上来。
        return None, {"ok": False, "link": link, "reason": "bad-link-name",
                      "error": "link 只能是 auto / keil / ocd（收到 %r）"
                               % (link,),
                      "hint": "auto=哪条链路有活会话用哪条；keil=Keil/UVSOCK；ocd=OpenOCD"}

    keil, kerr = _try_keil() if want in ("auto", "keil") else (None, None)
    ocd, oerr = _try_ocd() if want in ("auto", "ocd") else (None, None)

    if want == "keil":
        return (keil, None) if keil else (None, _fail(kerr, who, want, kerr, None))
    if want == "ocd":
        return (ocd, None) if ocd else (None, _fail(oerr, who, want, None, oerr))
    if keil:
        return keil, None
    if ocd:
        return ocd, None
    return None, _fail(None, who, "auto", kerr, oerr)


def _fail(err, who, want, kerr, oerr):
    if want == "auto":
        msg = "两个链路都没有活着的调试会话，无法%s" % who
        hint = "%s；%s" % (_HINTS["keil"], _HINTS["ocd"])
        reason = "no-mem-link"
    else:
        msg = "指定的链路不可用（link=%s），无法%s" % (want, who)
        hint = _HINTS.get(want, "")
        reason = "no-%s-link" % want
    return {"ok": False, "error": msg, "reason": reason,
            "link": want, "keil": kerr, "ocd": oerr,
            "hint": hint}


def describe_links() -> dict:
    """两条链路各自「有没有会话 / 目标在不在跑」，给 trace_status 之类做自述。"""
    out = {}
    for nm, fn in (("keil", _try_keil), ("ocd", _try_ocd)):
        lk, err = fn()
        out[nm] = lk.describe() if lk else {"name": nm, "available": False,
                                            "why": err}
        if lk:
            out[nm]["available"] = True
    return out


def read_mem_mask(link, addr: int, n_bytes: int):
    """薄封装：显式链路字符串/对象都收，返回 (data, meta)，meta 里必有 link。"""
    lk = link
    if not isinstance(link, Link):
        lk, err = pick(link)
        if lk is None:
            return None, err
    return lk.read(addr, n_bytes)
