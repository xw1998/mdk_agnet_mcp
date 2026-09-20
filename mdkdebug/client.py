# -*- coding: utf-8 -*-
"""
UVClient：高层封装 Keil UVSOCK 调试能力，并内置“连接缓存 + 空闲自动断开”。

连接策略（服务 + 缓存）：
- 首次调用时建立 TCP 连接；
- 后续调用若距上次使用未超过 idle_timeout，则复用连接；
- 超过 idle_timeout 未使用，或遇到连接已失效，则断开后重连；
- 显式 close() 立即断开。
线程安全：通过 threading.RLock 保护连接状态，可被 MCP 并发调用。
注意必须是可重入锁：_request 持锁期间会调用 reset_connection（它也加锁），
用普通 Lock 会自死锁——表现为「一次命令超时后整个服务卡死」。
"""

from __future__ import annotations

import logging
import re
import struct
import threading
import time

from . import uvsock
from . import winutil
from . import guard
from .interface import UVInterface
from .uvsock import (
    UVSOCK_CMD, UV_STATUS_SUCCESS, UV_STATUS_TEXT, status_text, UVError, UVStatusError,
)

logger = logging.getLogger("mdkdebug.client")

# 命令窗口报错行。真机 BK/BS 失败时 UVSOCK 仍回 status=0，错误只出现在命令窗口文本里，
# 形如 `*** error 72: invalid item number`；只看 status 会把失败当成功。
_CMD_ERROR_RE = re.compile(r"\*\*\*\s*error\s+(\d+)\s*:\s*(.*)", re.IGNORECASE)

# wait_breakpoint：调用时目标已处于停止态时，观察「它是否真的跑起来过」的宽限窗口（秒）。
# run/step 是异步命令（实测响应滞后），刚开始轮询时读到的可能仍是上一帧的停止态，
# 故不能一进来就凭「已停止 + PC 匹配」下命中结论。
_WAIT_RUN_GRACE_S = 0.4

# DFSR（Debug Fault Status Register，Cortex-M 系统控制空间 0xE000ED30）——最近一次调试
# 事件的硬证据。数据观察点（DWT 比较器）命中时 DWTTRAP(bit2) 置位，可把 wait_breakpoint
# 的观察点判定从「推断」升级为「实测」。
# 真机实测（STM32F429 + Keil UVSOCK@4823）：read_mem 读 0xE000ED30 可稳定读到（需已进入
# 调试、目标暂停）；DFSR 是 W1C（写 1 清位），故等待开始前先清一次，等待期间再置位的
# 就是本次事件——只看结果不区分历史残留会误判（实测刚进调试 DFSR 就可能已带 VCATCH 位）。
_DFSR_ADDR = 0xE000ED30
_DFSR_HALTED = 1 << 0     # 调试器挂起
_DFSR_BKPT = 1 << 1       # BKPT 指令命中（软件断点）
_DFSR_DWTTRAP = 1 << 2    # DWT 比较器命中（数据观察点）
_DFSR_VCATCH = 1 << 3     # Vector catch
_DFSR_EXTERNAL = 1 << 4   # 外部调试请求

# DWT 比较器逐个保持「比较地址 + 掩码 + 功能」三元组，间隔 0x10：COMPn@0xE0001020+0x10n。
_DWT_COMP_BASE = 0xE0001020
_DWT_FUNC_BASE = 0xE0001028

# Keil 命令窗口 BL 输出行，真机实测形如：
#   0: (E 0x08000DB4) '\\mdk_test\../Core/Src/main.c\77', CNT=1, enabled
#   3: (A WR 0x20000000 len=1) '0x20000000', CNT=1, enabled
# E=代码断点(E execution)，A=地址型断点(access，即数据观察点)，WR/RD 为访问类型。
_BP_LINE_RE = re.compile(
    r"^\s*(\d+):\s*\(\s*([A-Za-z]+)\s*([A-Za-z]{2})?\s*(0x[0-9A-Fa-f]+)"
    r"([^)]*)\)\s*'(.*?)'(?:\s*,\s*CNT=(\d+))?(?:\s*,\s*(\w+))?")

# 允许单次读内存的最大分块（Keil 协议限制）
MAX_CHUNK = 16384


# UVSOCK 开启指引：连接失败时提示用户如何在 Keil 中开启 UVSOCK 插件
UVSOCK_HINT = (
    "请在 Keil uVision 中开启 UVSOCK：菜单 Edit → Configuration... → 切到 Other 选项卡 → "
    "勾选 UVSOCK Enabled → 确认端口为 4823 → 点 OK，然后重启 Keil 使设置生效，再重新调用本工具。"
)

class UVSOCKConnectError(UVError):
    """无法连接 Keil UVSOCK 服务（Keil 未运行 / UVSOCK 未开启 / 端口未监听）。"""

    def __init__(self, host: str, port: int, cause: Exception,
                 health: dict | None = None):
        h = health or {}
        if h:
            detail = "诊断：" + h.get("diagnosis", "")
            if h.get("suggestion"):
                detail += " 建议：" + h["suggestion"]
        else:
            detail = UVSOCK_HINT
        super().__init__(
            f"无法连接 Keil UVSOCK 服务（{host}:{port}）：{cause}。{detail}"
        )

class UVClient:
    """线程安全的 UVSOCK 调试客户端（含连接缓存）。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 4823,
                 idle_timeout: float = 30.0):
        self.host = host
        self.port = port
        self.idle_timeout = idle_timeout  # 秒，空闲超过则断开
        self._lock = threading.RLock()
        # 批次23：「本次停止是不是等待期间新发生的」判定用的两条时间线。
        # _exec_ts: 最近一次 run/step 命令生效的时间；_last_stop_obs_ts: 最近一次
        # 「观察到目标处于停止态」的时间。前者晚于后者 → 当前停止是那次运行的结果。
        self._exec_ts = 0.0
        self._last_stop_obs_ts = 0.0
        # 批次45：运行态读取用的「目标在不在跑」1 秒 TTL 缓存——轮询采样时每次都
        # 打一轮 UV_DBG_STATUS 太亏，但读数要不要复读确认恰恰取决于它
        self._run_cache = None
        self._run_cache_at = 0.0
        self._last_used = 0.0
        self.phy = UVInterface(host=host, port=port)
        # 批次29：跨进程互斥闸门（多个 mdkdebug 实例抢同一 UVSOCK 时，命令会互相
        # 穿插并静默吃掉写入）+ 实例心跳（供 keil_health / get_status 清点）。
        self.guard = guard.EndpointGuard(host=host, port=port)
        self.presence_extra = {}
        self._stop_pc_hist = []   # 最近几次停止点 PC，用于识别「同一地址反复出现」
        self._bp_hits = {}        # 断点命中计数 {addr: count}（本进程内累计）
        # 批次67：命中**历史**（时刻, 地址, CYCCNT 或 None）。计数回答「命中过几次」，
        # 历史回答「是不是短时间内反复命中同一处」——后者才是复位循环的征兆。
        self._bp_hit_hist = []
        # 批次24：被观察地址的历史值（设点时 / 上一停止点读到的），作为数据观察点
        # 「本次运行窗口内是否被改写」的基线。真机实测：观察点打在频繁写入的变量上时，
        # run 后几微秒内变量就被写、目标随即被 Keil 停住，等待开始时的现场读取拿到的
        # 已是变动后的值，只有历史记录才能构成值变化证据。
        self._watch_value_cache = {}
        # 命令窗口/异步消息缓冲的读取游标：内部命令（BS/BK/BL）只取「新增」部分做窗口级
        # 校验，绝不 clear——否则 read_console_output 随后就读不到命令窗口输出了。
        self._cons_seen = 0
        self._msg_seen = 0

    # ------------------------------------------------------------------
    # 连接生命周期
    # ------------------------------------------------------------------
    def _ensure_connected(self) -> None:
        now = time.monotonic()
        if self.phy.is_connected:
            if now - self._last_used <= self.idle_timeout:
                return
            # 空闲超时，断开以便重连
            logger.info("连接空闲超过 %.1fs，断开重连", self.idle_timeout)
            self.phy.close()
        try:
            self.phy.open()
        except OSError as e:  # 连接被拒/超时：Keil 没起或 UVSOCK 未开启
            # 立刻做一次廉价健康检查，让调用方直接看到"断在哪一环"，
            # 而不是只拿到一句 ConnectionRefused。
            try:
                health = winutil.keil_health(self.port)
            except Exception:  # noqa: BLE001
                health = None
            raise UVSOCKConnectError(self.host, self.port, e, health=health) from e
        self._last_used = now

    def _request(self, cmd_code: int, data: bytes = b'',
                 expect_status: bool = True):
        """加锁执行一次命令，返回 (r_status, 响应数据解析结果)。"""
        # 两层锁：self._lock 管本进程的线程；guard.hold() 管**其他 mdkdebug 进程**
        # （文件锁）。缺少后者时，两个服务实例各持一条 UVSOCK 连接会互相穿插，
        # 典型后果是「write_mem 返回成功但值被另一条命令覆盖」的静默丢失。
        with self._lock, self.guard.hold():
            self._ensure_connected()
            guard.touch_presence(self.port, getattr(self, "presence_extra", None))
            uv = UVSOCK_CMD(cmd_code, data=data)
            try:
                raw = self.phy.send(uv.pack(), expect_cmd=cmd_code)
            except OSError as e:
                # Keil 进程在命令执行期间死掉：socket 被重置/断开。同样要给可操作诊断，
                # 而不是把裸 WinError 抛给调用方（那正是"操作了没反应"的由来）。
                reason = self._timeout_diagnostics(cmd_code)
                self.reset_connection(reason="连接中断")
                raise UVStatusError(uvsock.UV_STATUS_TIMEOUT,
                                    "cmd=0x%04X；UVSOCK 连接中断（%s）；%s"
                                    % (cmd_code, e, reason))
            self._last_used = time.monotonic()
            if raw is None:
                # 超时：UVSOCK 会话很可能已被弄脏（残留调试会话/异步堆积/模态框阻塞），
                # 只关 socket 不够——必须整体复位，否则后续命令会连续受影响。
                reason = self._timeout_diagnostics(cmd_code)
                self.reset_connection(reason="命令超时")
                raise UVStatusError(uvsock.UV_STATUS_TIMEOUT,
                                    f"cmd=0x{cmd_code:04X}；{reason}")
            resp = uv.unpack(raw)
            # resp = (totalLen, eCmd, bufLen, cycles, tStamp, id, r_cmd, r_status, data)
            return resp[7], resp[8]

    def reset_connection(self, reason: str = "") -> dict:
        """丢弃当前 UVSOCK 连接与全部接收缓冲，下次调用时重新建立连接。

        为什么需要：UVSOCK 是长连接，服务端会话被上一次操作弄脏后（调试会话残留、
        异步消息堆积、模态框阻塞），**新连接仍可能复用旧状态**——典型表现是一次超时
        之后后续命令连续受影响，只能靠"关掉 Keil 再开"恢复。这里给出无需重启 Keil 的
        原子复位能力（重启 Keil 见 restart_keil）。
        """
        with self._lock:
            try:
                self.phy.close()
            except Exception as e:  # noqa: BLE001
                logger.debug("关闭 UVSOCK 连接时出错（忽略）：%s", e)
            for attr in ("console_log", "async_log"):
                buf = getattr(self.phy, attr, None)
                if isinstance(buf, list):
                    buf.clear()
            self._cons_seen = 0
            self._msg_seen = 0
            self._last_used = 0.0
        try:
            health = winutil.keil_health(self.port)
        except Exception:  # noqa: BLE001
            health = None
        return {"ok": True, "action": "重置 UVSOCK 连接",
                "reason": reason or "手动复位",
                "msg": "连接已丢弃，下次调用会**自动重新建立**（不必先做一次读来预热；batch65 起链路选择会主动建链）；若仍异常可用 restart_keil 重启 Keil",
                "keil": health}

    def serialization_snapshot(self) -> dict:
        """当前串行化方式 + 并发竞争遥测 + 其他 mdkdebug 实例（get_status 用）。"""
        return guard.concurrency_report(self.port, self.guard)

    def _timeout_diagnostics(self, cmd_code: int) -> str:
        """命令超时时的可操作诊断：Keil 健康 + 模态对话框检测。"""
        parts = []
        try:
            health = winutil.keil_health(self.port)
            parts.append(health.get("diagnosis", ""))
            keil_alive = health.get("keil_alive")
        except Exception:  # noqa: BLE001
            keil_alive = None
        try:
            dialogs = winutil.find_modal_dialogs()
        except Exception:  # noqa: BLE001
            dialogs = []
        if dialogs:
            titles = "、".join((d.get("title") or "(无标题)") for d in dialogs[:3])
            parts.append("检测到 Keil 模态对话框，很可能正阻塞命令执行：%s"
                         "（请在 Keil 界面上处理该对话框后重试）" % titles)
        elif keil_alive:
            parts.append("未发现模态对话框；连接已自动复位，可直接重试该命令")
        else:
            parts.append("Keil 进程不存在，请先 launch_uvision / restart_keil 拉起")
        return "；".join(p for p in parts if p)

    def close(self) -> None:
        with self._lock:
            self.phy.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 状态 / 版本
    # ------------------------------------------------------------------
    def get_version(self) -> dict:
        status, m_data = self._request(uvsock.UV_GEN_GET_VERSION)
        version = m_data.hex()
        return {"status": status, "ok": status == UV_STATUS_SUCCESS,
                "version_hex": version,
                "status_text": status_text(status)}

    def get_status(self) -> dict:
        """查询调试状态。

        真实 Keil 的 UV_DBG_STATUS 响应：r_status 恒为 0，真正的运行状态在响应
        data 的低字节（1=执行中，0=已停止）；mock 则直接用 r_status 表示状态。
        因此优先从 data 解析，data 为空时回退到 r_status。
        """
        status, m_data = self._request(uvsock.UV_DBG_STATUS)
        # 每次读到「已停止」都记一次时间：这是判断后续停止是否为「新发生」的基线
        _now = time.time()
        # 仅当 r_status 为成功时，data 低字节才表示运行状态（真实 Keil）
        if status == uvsock.UV_STATUS_SUCCESS:
            state = m_data[0] if len(m_data) >= 1 else None
            if state is not None:
                running = (state == 1)
                if not running:
                    self._last_stop_obs_ts = _now
                if state == 0:
                    st = "已停止"
                elif state == 1:
                    st = "执行中"
                else:
                    st = f"运行状态码({state})"
                return {
                    "ok": True, "status": status,
                    "status_text": "执行中" if running else "已停止",
                    "running": running, "debugging": True,
                    "state": state, "state_text": st,
                    "data": m_data.hex() if m_data else "",
                    "note": "state 为 UV_DBG_STATUS 响应 data 低字节：0=已停止,1=执行中；"
                            "running/debugging/state_text 已据此解码，无需再人工看裸 hex。",
                }
        # 非成功 / 兼容 mock：按 r_status 直接判断运行状态
        running = status in (uvsock.DBG_EXECUTING,
                             uvsock.UV_STATUS_TARGET_EXECUTING,
                             uvsock.UV_STATUS_DEBUGGING)
        if not running and status in (uvsock.DBG_STOPPED, uvsock.UV_STATUS_TARGET_STOPPED):
            self._last_stop_obs_ts = _now
        if status == uvsock.DBG_EXECUTING:
            text, debugging = "执行中", True
        elif status in (uvsock.DBG_STOPPED, uvsock.UV_STATUS_TARGET_STOPPED):
            text, debugging = "已停止", True
        elif status == uvsock.UV_STATUS_NOT_DEBUGGING:
            text, debugging = "未处于调试状态", False
        else:
            text, debugging = status_text(status), False
        return {
            "ok": True, "status": status,
            "status_text": text,
            "running": running, "debugging": debugging,
            "data": m_data.hex() if m_data else "",
        }

    # ------------------------------------------------------------------
    # 表达式 / 变量
    # ------------------------------------------------------------------
    def calc_expression(self, expr: str) -> dict:
        """读取/计算调试表达式（变量、寄存器、指针解引用等）。"""
        from .uvsock import VSET
        ve = VSET()
        data = ve.pack(expr)
        status, m_data = self._request(uvsock.UV_DBG_CALC_EXPRESSION, data=data)
        if status != UV_STATUS_SUCCESS:
            return {"status": status, "ok": False,
                    "status_text": status_text(status)}
        val_type, val, name = ve.unpack(m_data)
        type_name = uvsock.VTT_TYPE_NAME.get(val_type, f"type_{val_type}")
        return {
            "status": status, "ok": True,
            "expression": expr,
            "value_type": type_name,
            "value": val,
            "value_raw": name,
        }

    def read_variable(self, name: str, count: int = 0,
                     read_memory: bool = True) -> dict:
        """按变量名查询其地址与内容（值），支持数组等类型。

        用 `&name` 取地址、`name` 取值，并尝试 `sizeof(name)` 获取字节大小。
        - count>0：按数组读取 `name[0..count-1]`，返回各元素值（便于查看数组内容）；
        - read_memory：结合基地址与 sizeof，用 read_mem 读出变量所在连续内存
          （十六进制 + ASCII），覆盖结构体/大块数据查看。
        返回 {name, address, value, value_type, size_bytes, elements, memory_hex, ascii}。
        """
        name = name.strip()
        if not name:
            return {"ok": False, "name": "", "error": "变量名不能为空"}

        result: dict = {"ok": False, "name": name}

        # 地址：&name
        addr_r = self.calc_expression(f"&{name}")
        address = addr_r.get("value") if addr_r.get("ok") else None
        if addr_r.get("ok"):
            result["address"] = hex(address) if isinstance(address, int) else address

        # 值：name
        val_r = self.calc_expression(name)
        if val_r.get("ok"):
            result["value"] = val_r.get("value")
            result["value_type"] = val_r.get("value_type")
            result["value_raw"] = val_r.get("value_raw")

        # 大小：sizeof(name)（尝试，失败忽略）
        sz_r = self.calc_expression(f"sizeof({name})")
        size_bytes = sz_r.get("value") if sz_r.get("ok") else None
        if size_bytes is not None and isinstance(size_bytes, int):
            result["size_bytes"] = size_bytes

        # 数组元素：count>0 时逐个读 name[i]
        if count and count > 0:
            elements = []
            for i in range(count):
                e = self.calc_expression(f"{name}[{i}]")
                if e.get("ok"):
                    elements.append({"index": i, "value": e.get("value"),
                                     "value_type": e.get("value_type")})
                else:
                    elements.append({"index": i, "error": "读取失败"})
                    break
            result["elements"] = elements

        # 读取变量内存（基地址 + 大小均可得时）
        if read_memory and isinstance(address, int) and size_bytes:
            cap = min(size_bytes, 16 * 1024)  # 防超长
            mem = self.read_mem(address, cap)
            if mem.get("ok"):
                result["memory_hex"] = mem.get("data_hex")
                result["ascii"] = mem.get("ascii")

        if not result.get("ok") and address is None and not val_r.get("ok"):
            return {
                "ok": False, "name": name,
                "message": "无法解析变量（变量不存在或未处于调试状态）",
                "detail": {"addr": addr_r, "value": val_r},
            }
        result["ok"] = True
        return result


    # ------------------------------------------------------------------
    # 内存读写
    # ------------------------------------------------------------------
    def read_mem(self, addr: int, n_bytes: int) -> dict:
        """读取指定地址的 n_bytes 内存（自动分块）。返回十六进制字节串。"""
        if n_bytes <= 0:
            return {"status": uvsock.UV_STATUS_OUT_OF_RANGE, "ok": False,
                    "status_text": "n_bytes 必须为正整数", "addr": addr,
                    "n_bytes": n_bytes, "data_hex": "", "ascii": ""}
        result = b""
        offset = 0
        while offset < n_bytes:
            chunk = min(MAX_CHUNK, n_bytes - offset)
            am = uvsock.AMEM()
            status, m_data = self._request(uvsock.UV_DBG_MEM_READ,
                                           data=am.pack_read(addr + offset, chunk))
            if status != UV_STATUS_SUCCESS:
                return {"status": status, "ok": False,
                        "status_text": status_text(status), "addr": addr,
                        "n_bytes": n_bytes, "data_hex": result.hex(),
                        "ascii": self._to_ascii(result)}
            nAddr, ErrAddr, nErr, payload = am.unpack(m_data)
            result += payload
            offset += chunk
        return {"status": UV_STATUS_SUCCESS, "ok": True, "addr": addr,
                "n_bytes": n_bytes, "data_hex": result.hex(),
                "ascii": self._to_ascii(result)}

    # ---- 带脏读防护的内存读取（批次30 反馈①） ----
    @staticmethod
    def _degenerate_kind(data: bytes) -> str:
        """识别「整帧退化」：整片全 0x00 / 全 0xFF / 整段重复同一个 4 字节字。

        真机实测（STM32F427 + Keil UVSOCK）：目标**全速运行时**经 SWD 读 SRAM 的
        某些区段会整段重复同一个 4 字节字——同一个字在换地址、换长度时都一样，
        且随读的推进而变（实测相邻读差约 1400）。它既不是全 0 也不是全 FF，
        旧检测认不出来，于是伪值被当正常字节流用，这是最危险的一类静默错答案。
        门槛取 16 字节（4 个相同的、字节不全同的字），避免把「真存了重复值的小数组」
        误判成脏读。
        """
        if not data:
            return ""
        if data[0] == 0x00 and all(b == 0x00 for b in data):
            return "all_zero"
        if data[0] == 0xFF and all(b == 0xFF for b in data):
            return "all_ff"
        if len(data) >= 16:
            word = data[:4]
            if len(set(word)) > 1 and all(
                    data[i:i + 4] == word for i in range(0, len(data) - 3, 4)):
                return "repeated_word"
        return ""

    def running_cached(self, ttl: float = 1.0, fresh: bool = False):
        """目标在不在全速跑，带 TTL 缓存。返回 True / False / None（判不出，不猜）。

        批次45：运行态读取要把「这次读是不是在全速运行时做的」如实告诉调用者，
        而每次读都打一轮 UV_DBG_STATUS 会让轮询采样变慢，所以默认 1 秒内复用上一次结果。
        """
        now = time.time()
        if not fresh and now - self._run_cache_at < max(0.0, float(ttl)):
            return self._run_cache
        try:
            st = self.get_status()
        except Exception:  # noqa: BLE001
            st = {"ok": False}
        if not st.get("ok") or st.get("debugging") is False:
            v = None
        else:
            v = st.get("running")
        self._run_cache = v if isinstance(v, bool) else None
        self._run_cache_at = now
        return self._run_cache

    # ---- D-Cache 一致性（批次49）----
    # 真机反馈：M7 上读线程栈（0x2400FB00 一类 AXI SRAM）连续全 0、confidence=low，
    # 而工具只给了泛泛的 degenerate 提示。根因是 DAP 直读走 AHB，命中的可能是
    # 尚未回写的 cache 行或陈旧副本。这里给出「读得出原因 + 有可执行动作」的处理。
    _SCB_CCR = 0xE000ED14
    _SCB_DCIMVAC = 0xE000EF5C
    _SCB_DCCMVAC = 0xE000EF68

    @staticmethod
    def _ram_like(addr) -> bool:
        """该地址像不像「走 D-Cache 的 RAM」（SRAM / DTCM / AXI / SRAM1..4）。"""
        a = int(addr)
        return (0x20000000 <= a < 0x40000000) or (0x00000000 <= a < 0x00010000)

    def dcache_status(self) -> dict:
        """D-Cache 是否使能（SCB->CCR bit16）。读不到就如实说读不到，不猜。"""
        m = self.read_mem(self._SCB_CCR, 4)
        if not m.get("ok"):
            return {"ok": False, "error": m.get("status_text") or "读 SCB->CCR 失败"}
        try:
            v = int.from_bytes(bytes.fromhex(m.get("data_hex") or ""), "little")
        except Exception:  # noqa: BLE001
            return {"ok": False, "error": "SCB->CCR 读数无法解析"}
        return {"ok": True, "ccr": "0x%08X" % v, "dcache": bool(v & (1 << 16)),
                "icache": bool(v & (1 << 17)),
                "source": "SCB->CCR(0xE000ED14) bit16=DC / bit17=IC"}

    def cache_clean_invalidate(self, addr: int) -> dict:
        """按地址维护 D-Cache：DCCMVAC（clean，脏行写回 RAM）→ DCIMVAC（invalidate）。

        先 clean 再 invalidate 的顺序是有意的：直接 invalidate 会把还没回写的脏数据丢掉。
        目标须停止（写 SCB 寄存器要调试态）；每步的成败都如实回报，不假装成功。
        """
        ops = []
        ok_all = True
        for name, reg in (("clean(DCCMVAC)", self._SCB_DCCMVAC),
                          ("invalidate(DCIMVAC)", self._SCB_DCIMVAC)):
            try:
                w = self.write_mem(reg, struct.pack("<I", int(addr) & 0xFFFFFFFF))
            except Exception as e:  # noqa: BLE001
                w = {"ok": False, "error": str(e)}
            ops.append({"op": name, "reg": "0x%08X" % reg, "ok": bool(w.get("ok")),
                        "error": None if w.get("ok") else
                        (w.get("status_text") or w.get("error") or "写失败")})
            ok_all = ok_all and bool(w.get("ok"))
        return {"ok": ok_all, "addr": "0x%X" % int(addr), "ops": ops}

    def read_mem_verified(self, addr: int, n_bytes: int, verify: str = "auto") -> dict:
        """带「脏读防护」的内存读取。

        来自真机反馈：stop 之后紧跟的第一次读，可能整帧返回全 0（实测 0x08022000
        连读两次都是 16 个 00，重读即正确）。get_current_location 已为 PC 做过
        「读数收敛判定」，内存读取同样需要——否则极易「读到 0 就下结论」，把排查带偏。

        策略：
        - verify="auto"（默认）只在**可疑**时才复读，不做无条件双倍开销：
          首帧整帧退化（全 0x00 / 全 0xFF），或距最近一次 stop 不足 1 秒
          （停止是异步生效的，这期间的读最容易拿到脏值）；
        - 复读最多 3 次，**连续两次一致**才采纳（与 _annotate_stop 同一套判定语言）；
        - verify=true 总是复读（对某次结果不放心时强制确认）；
          verify=false 完全关闭（大块搬运/读只读区时省时间）。

        在原 read_mem 结果上补：read_confidence(high/low/medium)、reread_count、
        reread_consistent、degenerate、since_stop_s、while_running，以及 warning /
        first_read_hex / read_unstable / degenerate_note（视情况）。

        批次45（运行态读取）：目标全速运行时也能读（真机实测 SRAM 与外设寄存器都读得到），
        但运转中的目标随时可能在改内存，所以运行态一律多复读一轮：
        - 两次一致 → 按正常结果给（read_confidence=high）；
        - 两次不一致 → read_confidence=medium + read_unstable=true，并把「可能是变量本身
          在变」与「可能是读被打断」两种解释都写进 warning，让调用者自己判断，
          而不是替它选一个。
        """
        mode = str(verify if verify is not None else "auto").strip().lower()
        if mode in ("0", "no", "off", "never"):
            mode = "false"
        elif mode in ("1", "yes", "on", "always", "force"):
            mode = "true"
        elif mode not in ("auto", "true", "false"):
            mode = "auto"
        first = self.read_mem(addr, n_bytes)
        out = dict(first)
        out["verify"] = mode
        out["read_confidence"] = "high" if first.get("ok") else "low"
        out["reread_count"] = 0
        out["reread_consistent"] = None
        if not first.get("ok"):
            return out
        data = bytes.fromhex(first.get("data_hex") or "")
        degenerate = self._degenerate_kind(data)
        since_stop = None
        if self._last_stop_obs_ts:
            since_stop = round(time.time() - self._last_stop_obs_ts, 3)
        out["since_stop_s"] = since_stop
        # 批次45：这次读是不是在目标全速运行时做的——Keil 链路实测**可以**运行态读内存
        #（含外设寄存器），但读到的可能落在「读的中途被 CPU 改写」的裂缝里，调用者得知道
        # 才能自己决定要不要停-读-走。放在 since_stop 之后算：get_status 本身会刷新
        # 「最近观察到停止」的时间线，先算 since_stop 才不会被它自己影响。
        run = self.running_cached()
        if run is not None:
            out["while_running"] = bool(run)
        flash_like = 0x08000000 <= addr < 0x20000000
        # Flash 区段读出全 0xFF 是「已擦除」的**预期内容**，不是脏读——
        # 真机实测读已擦除的 0x08022000 得到全 FF，若也判 low confidence 会造成误报。
        expected_ff = bool(degenerate == "all_ff" and flash_like)
        if degenerate:
            out["degenerate"] = degenerate
            if degenerate == "all_zero" and flash_like:
                out["degenerate_note"] = (
                    "整帧读出全 0x00，而该地址落在 Flash 区段：已擦除的 Flash 应读出 0xFF，"
                    "全 0 更像是读取失败（目标未真正停止 / 响应错位）造成的脏读，不可当真实内容。")
            elif expected_ff:
                out["content_note"] = (
                    "该地址落在 Flash 区段，已擦除的 Flash 读出全 0xFF 是**预期内容**"
                    "（不是脏读）；若此处本该有代码/常量，说明对应区域尚未烧写或被擦除。")
            elif degenerate == "repeated_word":
                out["degenerate_note"] = (
                    "整帧是同一个 4 字节字（0x%s）的重复：真机实测这是「目标全速运行时"
                    "经 SWD 读 SRAM」的伪值签名之一，不是真实内容。先 halt 再读（停机读"
                    "实测逐字节吻合），或换链路重试。" % data[:4].hex())
            else:
                out["degenerate_note"] = (
                    "整帧读出全 %s：整片同值通常不是真实内容，而是读取失败或该区域未初始化。"
                    % ("0x00" if degenerate == "all_zero" else "0xFF"))
            # 批次49：M7 的 D-Cache。退化读数的另一大来源是 cache——DAP 直读走 AHB，
            # 可能命中尚未回写的 cache 行或陈旧副本。这里**只给因果与可执行动作**，
            # 不在读路径里替用户做维护：一旦在这里 clean+invalidate 后改用新值，
            # 就等于把「写目标状态」藏进一个只读工具，且会额外发一次读、扰动读数序列。
            # 真要动手，用 dcache_maintain(action="clean_invalidate", addr=...) 显式做。
            if degenerate and self._ram_like(addr):
                # 这里**不**去读 SCB->CCR：读路径上任何额外的目标访问都会扰动读数序列
                # （stop 后的首读本就最容易脏），也会让「一次读内存」变得不可预期。
                # 所以只给线索与可执行动作，判 D-Cache 状态交给 cache_info / dcache_maintain。
                out["cache_note"] = (
                    "额外线索：若目标带 D-Cache（M7 等）且已使能，整帧退化也可能是 DAP "
                    "读到尚未回写的 cache 行 / 陈旧副本。核实办法：cache_info 看 D-Cache 状态，"
                    "再 dcache_maintain(action=\"clean_invalidate\", addr=0x%X) 做一次 "
                    "clean+invalidate（脏行写回内存、丢掉缓存副本）后重读本地址——"
                    "重读值变了，就说明首帧确实是缓存陈旧副本。" % int(addr))
        # 目标在跑时一律复读：运行态读最典型的坏结果不是「整帧退化」，而是读的中途
        # 被 CPU 改写（逐字节撕裂）——这种脏值不会退化，只有复读比对才看得出来
        need = (mode == "true" or bool(degenerate)
                or (since_stop is not None and since_stop < 1.0)
                or run is True)
        if mode == "false" or not need:
            if degenerate:
                out["read_confidence"] = "low"
                out["warning"] = (
                    "首帧整帧退化（%s），且本次未启用复读（verify=false）：该结果不可信，"
                    "建议改用 verify=\"auto\" 重读。" % degenerate)
            return out
        prev = data
        last = out
        for i in range(1, 3):
            time.sleep(0.05)
            nxt = self.read_mem(addr, n_bytes)
            out["reread_count"] = i
            if not nxt.get("ok"):
                out["reread_error"] = nxt.get("status_text") or "复读失败"
                break
            cur = bytes.fromhex(nxt.get("data_hex") or "")
            if cur == prev:
                out["reread_consistent"] = True
                out["data_hex"] = nxt.get("data_hex", "")
                out["ascii"] = nxt.get("ascii", "")
                if cur != data:
                    out.pop("degenerate", None)
                    out.pop("degenerate_note", None)
                    out["first_read_hex"] = data.hex()
                    out["read_confidence"] = "high"
                    out["warning"] = (
                        "首帧读数是脏值（真机实测 stop 后的首次读会整帧返 0），已自动复读并采用"
                        "连续 %d 次一致的值；首帧 data_hex=%s 不可信、已被替换。"
                        % (i + 1, data.hex()))
                elif degenerate:
                    if expected_ff:
                        # 已擦除 Flash 的稳定全 FF 是正常内容，不降置信度
                        out["read_confidence"] = "high"
                    else:
                        out["read_confidence"] = "low"
                        out["warning"] = (
                            "连续 %d 次读取都是整帧 %s：这不是单次脏读，可能是该区域确实如此，"
                            "也可能是读取通路异常；请结合 query_memory_map 或其他地址交叉确认。"
                            % (i + 1, degenerate))
                else:
                    out["read_confidence"] = "high"
                return out
            if run is True:
                # 目标在全速跑，两次读之间内容变了。两种解释都成立且分不开：
                # 该地址本来就在被 CPU 改写（正常），或本次读被打断（不可信）。
                # 所以既不断言「这就是最新值」，也不断言「读数坏了」——如实标出来。
                out["read_confidence"] = "medium"
                out["reread_consistent"] = False
                out["read_unstable"] = True
                out["first_read_hex"] = prev.hex()
                out["data_hex"] = nxt.get("data_hex", out.get("data_hex"))
                out["ascii"] = nxt.get("ascii", out.get("ascii"))
                out["warning"] = (
                    "目标正在全速运行，连续两次读到的内容不同：可能是该地址本来就在被 CPU"
                    "改写（变量本身在变，属正常），也可能是这次读被运行中的目标打断了。"
                    "要取某一瞬间的一致快照，改用 running=\"halt\" 做停-读-走；"
                    "若该地址本该是静态的，那这个读数不可信，先 stop 再读。")
                return out
            prev = cur
            last = nxt
        if out.get("reread_consistent") is None:
            out["reread_consistent"] = False
            out["read_confidence"] = "low"
            if last is not out:
                out["data_hex"] = last.get("data_hex", out.get("data_hex"))
                out["ascii"] = last.get("ascii", out.get("ascii"))
            out["warning"] = (
                "复读未能确认（%s）：当前读数不可信，请先 get_status 确认目标已停止"
                "（必要时 wait_until_stopped）后重读。" % (out.get("reread_error") or "读数一直在变"))
        return out

    def write_mem(self, addr: int, data: bytes) -> dict:
        """向指定地址写入字节（自动分块，支持大块/批量填充）。返回实际写入长度。"""
        if not data:
            return {"status": uvsock.UV_STATUS_OUT_OF_RANGE, "ok": False,
                    "status_text": "data 不能为空", "addr": addr,
                    "written": 0}
        total = 0
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MAX_CHUNK]
            am = uvsock.AMEM()
            status, m_data = self._request(uvsock.UV_DBG_MEM_WRITE,
                                           data=am.pack_write(addr + offset, chunk))
            if status != UV_STATUS_SUCCESS:
                return {"status": status, "ok": False,
                        "status_text": status_text(status), "addr": addr,
                        "requested": len(data), "written": total}
            total += len(chunk)
            offset += len(chunk)
        return {"status": UV_STATUS_SUCCESS, "ok": True, "addr": addr,
                "written": total}

    def search_mem(self, start: int, end: int, pattern: bytes,
                   max_results: int = 20) -> dict:
        """在 [start, end) 地址范围内扫描字节序列，返回所有命中偏移。

        分块读取并逐块查找；块间留 pattern-1 字节重叠，避免命中落在块边界被漏掉。
        用于找魔数、定位被越界写坏的缓冲、搜索特定数据结构等。
        """
        if end <= start:
            return {"ok": False, "error": "end 必须大于 start", "start": start,
                    "end": end}
        if not pattern:
            return {"ok": False, "error": "pattern 不能为空"}
        max_results = max(1, min(max_results, 1000))
        hits: list[int] = []
        pos = start
        overlap = max(0, len(pattern) - 1)
        step = max(1, MAX_CHUNK - overlap)
        while pos < end and len(hits) < max_results:
            n = min(MAX_CHUNK, end - pos)
            r = self.read_mem(pos, n)
            if not r.get("ok"):
                break
            try:
                data = bytes.fromhex("".join((r.get("data_hex") or "").split()))
            except ValueError:
                break
            idx = 0
            while True:
                i = data.find(pattern, idx)
                if i < 0:
                    break
                hits.append(pos + i)
                idx = i + 1
                if len(hits) >= max_results:
                    break
            pos += step
        return {
            "ok": True, "start": start, "end": end,
            "pattern_hex": pattern.hex(), "count": len(hits),
            "addresses": [hex(h) for h in hits],
            "truncated": len(hits) >= max_results,
        }

    def fill_mem(self, addr: int, byte: int, count: int) -> dict:
        """从 addr 起连续写入 count 个相同字节（批量填充/清零大块内存）。"""
        if not 0 <= byte <= 255:
            return {"ok": False, "error": "byte 须为 0~255 的单字节值", "byte": byte}
        if count <= 0:
            return {"ok": False, "error": "count 必须为正整数", "count": count}
        chunk = bytes([byte]) * min(count, MAX_CHUNK)
        written = 0
        while written < count:
            n = min(MAX_CHUNK, count - written)
            r = self.write_mem(addr + written, chunk[:n])
            if not r.get("ok"):
                return {"ok": False, "addr": addr, "byte": byte, "count": count,
                        "written": written, "error": r.get("status_text")}
            written += n
        return {"ok": True, "addr": addr, "byte": byte, "count": count,
                "written": written}

    # ------------------------------------------------------------------
    # 调试会话控制（进入/退出）
    # ------------------------------------------------------------------
    def debug_session_alive(self, settle: float = 0.6) -> str:
        """就绪复核：短暂停留后调试态还在不在。

        真机实测（批次37）：`enter_debug` 的 status 已报就绪、get_status 也返回
        debugging=True，但约 1s 后 Keil **自己**把目标停了并退出调试——
        异步消息里能看到 `Stopping target...` → `Exited debug mode`。
        根因是那个 Keil 实例里残留了命令脚本（Keil 命令窗口的 Include/宏脚本，
        例如以 `EXIT` / `LOG OFF` 结尾的 .ini）：脚本排在队列里，等我们进完调试才执行。
        此时「只确认一次」的 ready 是**假就绪**，调用方随后每条命令都返回 status=6
        却完全看不到原因。所以这里多看一眼，把结论如实透出。

        返回 "ok"（仍在调试态）/ "lost"（调试态消失）/ "unknown"（查不了，不下结论）。
        """
        time.sleep(max(0.0, settle))
        try:
            st = self.get_status()
        except Exception:  # noqa: BLE001
            return "unknown"
        if isinstance(st, dict) and st.get("debugging"):
            return "ok"
        return "lost"

    def _debug_lost_note(self) -> str:
        return ("进入调试后调试态随即消失（Keil 异步消息里通常有 Stopping target... → "
                "Exited debug mode）。常见原因是该 Keil 实例里残留了命令脚本"
                "（如以 EXIT / LOG OFF 结尾的 .ini）或调试被外部终止；"
                "重开一个干净实例可解：close_uvision(force=true) → launch_uvision → enter_debug。")

    def enter_debug(self, wait_ready: float = 6.0, verify_stable: bool = True) -> dict:
        """进入调试模式（UV_DBG_ENTER）。受工程的 Load/Flash/Run-to-main 设置影响。

        真机实测：进入调试是**异步**的——命令返回 status=0 时目标尚未挂载完成，
        约 0.6~0.7s 后才真正进入调试态；在这之前紧接的状态查询/读内存/表达式
        会返回 status=6（Target is not in debug mode），断点命令也可能落空。
        故命令成功后轮询 get_status 直到 debugging 为真（最多等 wait_ready 秒）。

        verify_stable=True 时再做一次**就绪复核**（见 debug_session_alive）：
        真机见过「报就绪后又自己退出调试」的假就绪，此时会重发一次 UV_DBG_ENTER；
        仍不稳则 ready=False + warning 如实汇报，绝不让调用方以为已经进了调试。
        """
        r = self._control(uvsock.UV_DBG_ENTER, "进入调试")
        if not r.get("ok"):
            return r
        try:
            w = self.wait_debugging(timeout=wait_ready)
        except Exception as e:  # noqa: BLE001
            r["warning"] = "等待调试态确认时出错：%s" % e
            return r
        r["ready"] = bool(w.get("debugging"))
        r["ready_waited_ms"] = w.get("waited_ms", 0)
        if r["ready"] and verify_stable:
            verdict = self.debug_session_alive()
            r["ready_stable"] = verdict
            if verdict == "lost":
                # 重试一次：残留脚本通常只执行一遍，第二次进入往往能站稳
                r["ready_retry"] = True
                r2 = self._control(uvsock.UV_DBG_ENTER, "重试进入调试")
                ok2 = False
                if r2.get("ok"):
                    try:
                        w2 = self.wait_debugging(timeout=wait_ready)
                    except Exception:  # noqa: BLE001
                        w2 = {}
                    ok2 = bool(w2.get("debugging"))
                    r["ready_waited_ms"] = w2.get("waited_ms", r["ready_waited_ms"])
                if ok2:
                    # 重试同样要复核：只确认一次又可能落进同一个假就绪
                    ok2 = self.debug_session_alive() == "ok"
                r["ready"] = ok2
                r["ready_stable"] = "ok" if ok2 else "lost"
                if ok2:
                    r["note"] = ("首次进入调试后调试态曾消失，已自动重试一次并确认稳定。"
                                 "该 Keil 实例里可能有残留命令脚本，建议收尾后重开实例。")
                else:
                    r["retry_status_text"] = r2.get("status_text")
                    r["warning"] = self._debug_lost_note()
        if not r["ready"]:
            r["warning"] = r.get("warning") or (
                "enter_debug 已发出但 %.1fs 内未确认进入调试态（get_status 仍报未调试）；"
                "后续读内存/表达式可能返回 status=6，请检查目标板连接或 Keil 是否弹窗待确认。"
                % wait_ready)
        return r

    def wait_debugging(self, timeout: float = 6.0, interval: float = 0.15) -> dict:
        """轮询 get_status 直到 debugging 为真；返回 {ok, debugging, waited_ms}。"""
        t0 = time.monotonic()
        last = {}
        while True:
            try:
                last = self.get_status()
            except Exception:  # noqa: BLE001
                last = {}
            if last.get("debugging"):
                return {"ok": True, "debugging": True,
                        "waited_ms": int((time.monotonic() - t0) * 1000),
                        "status": last}
            if time.monotonic() - t0 >= timeout:
                return {"ok": False, "debugging": False,
                        "waited_ms": int((time.monotonic() - t0) * 1000),
                        "status": last}
            time.sleep(interval)

    def exit_debug(self) -> dict:
        """退出调试模式（UV_DBG_EXIT）。"""
        return self._control(uvsock.UV_DBG_EXIT, "退出调试")

    # ------------------------------------------------------------------
    # 断点管理（基于 Keil 命令窗口命令）
    # ------------------------------------------------------------------
    def exec_command(self, command: str) -> dict:
        """执行一条 Keil 命令窗口命令（BS/BK/BL/EVAL 等）。"""
        if any(c in command for c in "\r\n\0"):
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": "每次只能发送一条调试命令", "command": command}
        from .uvsock import EXECCMD
        status, m_data = self._request(uvsock.UV_DBG_EXEC_CMD,
                                       data=EXECCMD.pack(command))
        out = {"status": status, "ok": status == uvsock.UV_STATUS_SUCCESS,
               "status_text": status_text(status), "command": command}
        # 若响应带输出文本则附上（真机 BS 的成功响应会带二进制断点结构，
        # 直接 decode 会得到乱码，故先判断可打印性）
        if m_data:
            body = m_data.rstrip(b"\x00")
            try:
                text_ = body.decode("UTF-8")
                printable = bool(text_) and sum(
                    1 for ch in text_ if ch.isprintable() or ch in "\t") >= len(text_) * 0.9
            except Exception:  # noqa: BLE001
                text_, printable = "", False
            if printable:
                out["output"] = text_
            else:
                out["output_hex"] = m_data.hex()
                out["output_note"] = "响应携带二进制数据（非命令文本），已给 output_hex 原始字节"
        return out

    def _drain_channels(self) -> tuple:
        """取出「自上次读取以来新增」的命令窗口输出(0x5020)与异步消息(0x4000)。

        用**游标推进**而不是 `clear=True`：内部命令（BS/BK/BL）既要读自己的窗口输出来
        判断窗口级报错，又不能把缓冲吃光——否则 read_console_output 随后就读不到命令
        窗口输出了（把批次9 建立的能力吃掉）。故这里只返回新增部分、缓冲保持完整。
        缓冲被外部 clear（read_console_output(clear=True) / reset_connection）后，
        游标会因超出长度自动回退到 0，不会把旧行误算成新行。
        """
        def _read(fn) -> list:
            try:
                return [str(it.get("text") or "").strip() for it in fn(clear=False)]
            except Exception:  # noqa: BLE001
                return []
        allc = _read(self.phy.get_console_output)
        allm = _read(self.phy.get_async_messages)
        if self._cons_seen > len(allc):
            self._cons_seen = 0
        if self._msg_seen > len(allm):
            self._msg_seen = 0
        cons = allc[self._cons_seen:]
        msgs = allm[self._msg_seen:]
        self._cons_seen = len(allc)
        self._msg_seen = len(allm)
        return [c for c in cons if c], [m for m in msgs if m]

    def exec_command_checked(self, command: str, settle: float = 0.12) -> dict:
        """执行命令窗口命令，并把窗口里的 `*** error N: ...` 一并判为失败。

        真机实测（批次20 全功能回归）：数据观察点的 `BK 0x20000000` 在 UVSOCK 层回
        status=0「成功」，而 Keil 命令窗口实际报 `*** error 72: invalid item number`，
        断点并未清除。只看 status 会把「没清掉」当成功上报，调用方据此继续调试会莫名
        停在旧断点上，故这里统一做一次窗口级校验：返回额外带 console/errors。
        """
        self._drain_channels()          # 先清缓存，避免历史输出被算到本次命令
        r = self.exec_command(command)
        if settle:
            time.sleep(settle)
        cons, msgs = self._drain_channels()
        if cons:
            r["console"] = cons
        errs = []
        for t in list(cons) + list(msgs):
            m = _CMD_ERROR_RE.search(t)
            if m:
                errs.append({"code": int(m.group(1)), "message": m.group(2).strip(),
                             "text": t})
        if errs:
            r["errors"] = errs
            r["ok"] = False
            r["error"] = "命令窗口报错：" + "；".join(
                "error %d: %s" % (e["code"], e["message"]) for e in errs)
        return r

    @staticmethod
    def parse_breakpoint_table(lines) -> list:
        """把 Keil 命令窗口 BL 输出解析成结构化断点表。

        真机实测：BL 输出**会**经命令输出通道(0x5020)回传，形如
        `0: (E 0x08000DB4) '(源码路径)\77', CNT=1, enabled`；
        `3: (A WR 0x20000000 len=1) '0x20000000', CNT=1, enabled` 为数据观察点。
        """
        out = []
        for t in lines or []:
            m = _BP_LINE_RE.match(str(t))
            if not m:
                continue
            num, kind, access, addr, extra, expr, cnt, state = m.groups()
            lm = re.search(r"len=(\d+)", extra or "")
            out.append({
                "number": int(num),
                "kind": "access" if (kind or "").upper().startswith("A") else "exec",
                "access": (access or "").upper() or None,
                "address": addr,
                "length": int(lm.group(1)) if lm else None,
                "expr": expr,
                "count": int(cnt) if cnt else None,
                "enabled": (state or "").lower() != "disabled",
                "raw": str(t).strip(),
            })
        return out

    def list_breakpoints_real(self, settle: float = 0.18) -> dict:
        """列出本会话中 Keil 的**真实**断点（解析命令窗口 BL 输出）。

        与内部 id 记录不同，这是板上/Keil 侧实际生效的断点表，包含 Keil 断点编号
        （清除数据观察点必须按编号）；.uvoptx 持久化断点也会出现在这里。
        """
        r = self.exec_command_checked("BL", settle=settle)
        # 真机是「每条断点一帧」，但一次读取也可能把多行合并在一个条目里，
        # 故先按行拆开再匹配，避免只解析出第一条。
        lines = []
        for item in (r.get("console") or []):
            for piece in str(item).splitlines():
                if ":" in piece and "(" in piece:
                    lines.append(piece)
        bps = self.parse_breakpoint_table(lines)
        return {"ok": bool(r.get("ok")), "count": len(bps), "breakpoints": bps,
                "console": r.get("console") or [],
                "errors": r.get("errors") or [],
                "note": "解析自 Keil 命令窗口 BL 输出（0x5020 通道）；number 为 Keil 断点编号，"
                        "清除数据观察点必须按编号 BK <number>（按地址会报 error 72）"}

    def resolve_breakpoint_number(self, target: str) -> tuple:
        """把断点编号/地址/符号解析成 Keil 断点编号；返回 (编号或 None, 说明)。"""
        t = (target or "").strip()
        if not t:
            return None, "空目标"
        try:
            real = self.list_breakpoints_real()
        except Exception as e:  # noqa: BLE001
            return None, "无法读取真实断点表：%s" % e
        bps = real.get("breakpoints") or []
        if not bps:
            return None, "Keil 当前无断点（或 BL 输出为空）"
        if t.isdigit():
            for b in bps:
                if b["number"] == int(t):
                    return int(t), "按编号命中"
            return None, "无编号为 %s 的断点" % t
        if re.match(r"^0x[0-9A-Fa-f]+$", t):
            want = int(t, 16)
            for b in bps:
                try:
                    have = int(b["address"], 16)
                except Exception:  # noqa: BLE001
                    continue
                if have == want or (have | 1) == want or have == (want | 1):
                    return b["number"], "按地址 %s 命中编号 %s" % (t, b["number"])
            return None, "无地址为 %s 的断点" % t
        for b in bps:
            if t in (b.get("expr") or "") or (b.get("expr") or "") == t:
                return b["number"], "按表达式命中编号 %s" % b["number"]
        return None, "无匹配断点"

    def set_breakpoint(self, expr: str) -> dict:
        """在符号/地址处设置软件断点（命令窗口 BS）。

        真机 BS 成功时可能返回 UV_STATUS_BP_CREATED(22) 而非 SUCCESS(0)
        （断点已创建/已启用等断点类返回码），需归一化为成功，
        否则会被误判为失败、导致断点 id 丢失。
        真机实测：对已存在的断点，BS 会报 `*** error 145: Redefinition: item already
        exists`——对「设置」语义应视为成功（断点确实在），只附 note 提醒。
        """
        r = self._norm_bp_result(self.exec_command_checked(f"BS {expr}"))
        for e in (r.get("errors") or []):
            if e.get("code") == 145:
                r["ok"] = True
                r["already_exists"] = True
                r["note"] = ("该断点已存在（Keil 报 error 145 Redefinition），本次未重复创建；"
                             "可用 list_breakpoints 的 real 字段查看真实断点表。")
                break
        return r

    def clear_breakpoint(self, expr: str) -> dict:
        """清除断点（命令窗口 BK）。

        真机实测（批次20）：**数据观察点按地址清不掉**——`BK 0x20000000` 时 UVSOCK 回
        status=0，命令窗口却报 `*** error 72: invalid item number`，断点依旧生效。
        故这里先用 BL 解析真实断点编号，按编号 `BK <number>` 清除；解析不出编号时才回退
        到原有的按地址/符号清除。
        另外：BK 成功可能返回 BP_DELETED(23) 等断点类返回码，归一化为成功；
        BP_NOTFOUND(24) 表示断点本就不存在，对"清除"语义同样视为成功。
        """
        num, why = self.resolve_breakpoint_number(expr)
        if num is not None:
            r = self._norm_bp_result(self.exec_command_checked(f"BK {num}"),
                                     extra_ok=(24,))
            r["cleared_by"] = "number"
            r["bp_number"] = num
            r["resolve_note"] = why
            if r.get("ok"):
                r["note"] = "已按 Keil 断点编号 %d 清除（%s）" % (num, why)
            return r
        r = self._norm_bp_result(self.exec_command_checked(f"BK {expr}"), extra_ok=(24,))
        r["cleared_by"] = "expr"
        r["resolve_note"] = why
        return r

    @staticmethod
    def _norm_bp_result(r: dict, extra_ok: tuple = ()) -> dict:
        """把断点命令的断点类返回码（22/23/20/21，可选 24）归一化为成功。"""
        bp_codes = (uvsock.UV_STATUS_BP_DISABLED, uvsock.UV_STATUS_BP_ENABLED,
                    uvsock.UV_STATUS_BP_CREATED, uvsock.UV_STATUS_BP_DELETED) + tuple(extra_ok)
        if not r.get("ok") and r.get("status") in bp_codes:
            r["ok"] = True
            r["note"] = ("断点命令返回码 %s(%s)，已视为成功"
                         % (r.get("status"), r.get("status_text")))
        return r

    def list_breakpoints(self) -> dict:
        """列出当前所有断点（命令窗口 BL）。"""
        return self.exec_command("BL")

    def read_console_output(self, clear: bool = False) -> list:
        """读取 Keil 命令窗口输出缓存（UV_DBG_CMD_OUTPUT, 0x5020）。"""
        return self.phy.get_console_output(clear=clear)

    def read_async_messages(self, clear: bool = False) -> list:
        """读取 Keil 异步消息/报错缓存（UV_ASYNC_MSG, 0x4000）。"""
        return self.phy.get_async_messages(clear=clear)

    def read_cpu_registers(self) -> dict:
        """读取 CPU 核心寄存器 PC/LR/SP（R15/R14/R13）。多候选表达式以兼容不同 Keil 版本。"""
        candidates = {
            "pc": ("__currentPC()", "PC", "R15"),
            "lr": ("__currentLR()", "LR", "R14"),
            "sp": ("__currentSP()", "SP", "R13"),
        }
        regs = {}
        for name, exprs in candidates.items():
            for expr in exprs:
                try:
                    r = self.calc_expression(expr)
                except Exception:  # noqa: BLE001 单候选解析失败继续下一个
                    continue
                if r.get("ok") and isinstance(r.get("value"), int):
                    regs[name] = r["value"]
                    break
        if not regs:
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": "无法读取寄存器（未处于调试状态或表达式不可用）",
                    "registers": {}}
        out = {"status": uvsock.UV_STATUS_SUCCESS, "ok": True, "registers": regs}
        out.update(regs)
        return out

    def read_cpu_registers_stable(self, retries: int = 20, delay: float = 0.05,
                                  require_stopped: bool = False,
                                  need_stable: int = 2,
                                  verify_halt: bool = True) -> dict:
        """读取 CPU 寄存器，并规避 halt 瞬间的滞后（陈旧）值。

        真机实测（F401）：run_timeout/stop 之后**首次**读到的 PC 往往还是上一次 halt 的
        旧值——例如上一轮停在 0x08000db4，本轮首次仍读 0x08000db4、第二次才变成真实的
        0x08000444，而同一响应里的 LR/SP 已经是新值。旧的"PC 落在 FLASH 段即认可"启发式
        完全挡不住这类脏值：复位向量附近的陈旧地址（如 0x0800024c Reset_Handler）
        同样落在 FLASH 段内。

        因此这里改为按**读数收敛**判定：连续 need_stable 次 (PC, LR, SP) 完全一致才认为
        稳定；不一致就继续采样。地址只做最低限度的合法性检查（None/0/1 视为无效）。

        require_stopped=True 时先确认目标已停止：目标运行中 Keil 只回 PC（LR/SP 为 None）
        且该 PC 是上次 halt 的残留值，此时直接返回 ok=False 并说明原因。

        返回值在寄存器字段外附加：
        - stable: 是否读到收敛值；False 时附 warning（PC 可能滞后，建议重试）
        - samples: 实际采样次数
        - halt_verified: 读完寄存器后复查确认目标确实停着；False 表示目标其实在运行，
          此时 PC 是上一次 halt 的残留值，绝不可用于定位
        - pc_confidence: high/low 的显式标注（低置信度时同时给 warning）
        - repeat_count/repeat_warning: 同一 PC 连续出现的次数（疑似陈旧值时的提示）
        """
        if require_stopped:
            try:
                st = self.get_status()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": "查询目标状态失败: %s" % e}
            if st.get("ok") and st.get("running"):
                return {"ok": False, "target_running": True,
                        "error": "目标正在运行，读到的 PC 是上一次 halt 的残留值不可信"
                                 "（实测会稳定返回上次停止地址，极易误判成停在复位）；"
                                 "请先 stop 并确认停止（可调 wait_until_stopped）后再读",
                        "status": st}
        last: dict = {}
        prev_sig = None
        same = 0
        samples = 0
        for _ in range(max(2, retries)):
            r = self.read_cpu_registers()
            last = r
            samples += 1
            if not r.get("ok"):
                return r  # 读取本身失败（如未在调试态）立即返回，不重试
            pc = r.get("pc")
            if not isinstance(pc, int) or pc in (0, 1):
                prev_sig, same = None, 0     # PC 明显无效，继续采样
                time.sleep(delay)
                continue
            sig = (pc, r.get("lr"), r.get("sp"))
            if sig == prev_sig:
                same += 1
                if same >= need_stable - 1:
                    r["stable"] = True
                    r["samples"] = samples
                    return self._annotate_stop(r, verify_halt)
            else:
                same = 0
                prev_sig = sig
            time.sleep(delay)
        last["stable"] = False
        last["samples"] = samples
        last["warning"] = ("连续 %d 次采样未收敛（PC/LR/SP 仍在变化），读到的 PC 可能是 halt "
                           "瞬间的滞后值，不可信；请重试，或先 get_status 确认已停止" % samples)
        return self._annotate_stop(last, verify_halt)

    def _annotate_stop(self, r: dict, verify_halt: bool = True) -> dict:
        """给一次寄存器读取补上「这个 PC 到底可不可信」的判定与交叉验证。

        来自真机反馈：run_timeout 报出的停靠点会把排查带偏——报 main.c:107 HAL_Init、
        或连续多次报同一个地址，而目标其实一直在跑（串口实时响应）。所以这里做两件事：

        1) 复查目标是否真的停着。停止判定本身可能滞后（stop/复位都是异步生效），
           读完寄存器后再采样状态；若发现目标在跑，直接降级为「PC 不可信」，
           而不是把陈旧地址当成停靠点报出去。
        2) 记录最近的停止点 PC，同一地址连续出现多次时给出 repeat 计数与提示。
           正常循环也可能反复停在同一处，但结合「目标在跑」的迹象时，
           应当优先怀疑这是上次 halt 的残留值。
        """
        pc = r.get("pc")
        if isinstance(pc, int) and pc not in (0, 1):
            hist = self._stop_pc_hist
            hist.append(pc)
            del hist[:-5]
            repeat = 0
            for v in reversed(hist):
                if v == pc:
                    repeat += 1
                else:
                    break
            r["repeat_count"] = repeat
            if repeat >= 3:
                r["repeat_warning"] = (
                    "同一停止地址已连续出现 %d 次（%s）：若怀疑目标其实一直在运行，"
                    "这个 PC 很可能是上一次 halt 的残留值，请勿据此判断「卡死/反复复位」，"
                    "可用 get_status、read_variable 或串口输出交叉确认"
                    % (repeat, hex(pc)))
        if not verify_halt:
            r["pc_confidence"] = "high" if r.get("stable") else "low"
            return r
        running = None
        samples = 0
        last_err = ""
        for _ in range(2):
            try:
                st = self.get_status()
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
                break
            samples += 1
            if st.get("ok") and st.get("running"):
                running = True
                break
            time.sleep(0.05)
        r["halt_verified"] = bool(samples >= 2 and not running)   # running=None 表示两次复查都没看到在跑
        if not r["halt_verified"]:
            r["halt_check"] = {"samples": samples, "target_running": bool(running),
                               "error": last_err}
        if running:
            r["stable"] = False
            r["target_running"] = True
            r["read_ok_before_verify"] = r.get("ok")
            r["pc_confidence"] = "low"
            r["warning"] = (
                "读完寄存器后复查发现目标其实仍在运行：此时读到的 PC 是上一次 halt 的残留值"
                "（实测会稳定返回同一地址，极易被误判成「停在某处」或「反复复位」），"
                "不可用于定位。请先 stop 并确认停止（wait_until_stopped），或改用 "
                "read_variable / 串口输出确认程序实际行为。")
        else:
            r["pc_confidence"] = "high" if r.get("stable") else "low"
        return r

    #: DWT 周期计数器：复位后从 0 起，除溢出外**只会单调增**——它回退即内核复位过。
    _DWT_CYCCNT = 0xE0001004

    def _read_cyccnt(self):
        """读 DWT_CYCCNT（0xE0001004）。读不到、或读到 0（未使能使能位）都返回 None。

        注意 0 与「未使能」在本判据里等价处理：真的从 0 起算也没什么可判的，
        返回 None 比返回一个会被当成「回退」的 0 更不容易造成假警报。
        """
        try:
            r = self.read_mem(self._DWT_CYCCNT, 4)
            if not r.get("ok"):
                return None
            v = int.from_bytes(bytes.fromhex(r["data_hex"]), "little")
            return v or None
        except Exception:  # noqa: BLE001
            return None

    def note_breakpoint_hit(self, addr: int, cyccnt=None) -> int:
        """记录一次断点命中，返回该地址在本进程内的累计命中次数。

        同时把 (时刻, 地址, CYCCNT) 压进命中历史（只留最近 64 条），
        供 rapid_hit_stats 判断「同一断点短时间内反复命中」。
        cyccnt 传 None 时会自己读一次；读不到就记 None，绝不编一个数。
        """
        key = int(addr)
        self._bp_hits[key] = self._bp_hits.get(key, 0) + 1
        try:
            cc = int(cyccnt) if cyccnt is not None else self._read_cyccnt()
        except Exception:  # noqa: BLE001
            cc = None
        hist = self._bp_hit_hist
        hist.append((time.monotonic(), key, cc))
        del hist[:-64]
        return self._bp_hits[key]

    def rapid_hit_stats(self, addr=None, window_s: float = 3.0) -> dict:
        """统计「短时间内反复命中同一断点」——复位循环的征兆（批次67 P2）。

        只做**能证的事**：给出窗口内每个地址的命中次数、跨度，以及 CYCCNT 是否回退
        （回退是内核复位过的硬证据）。是不是复位循环由调用方结合启动锚点判定——
        主机侧单看「反复命中」分不清复位循环与正常热循环，这里绝不替它下结论。
        """
        try:
            win = float(window_s)
        except (TypeError, ValueError):
            win = 3.0
        now = time.monotonic()
        want = None if addr is None else (int(addr) & 0xFFFFFFFE)
        per: dict = {}
        for t, a, cc in list(self._bp_hit_hist):
            if now - t > win:
                continue
            if want is not None and (a & 0xFFFFFFFE) != want:
                continue
            per.setdefault(a & 0xFFFFFFFE, []).append((t, cc))
        checked = {}
        for a, lst in per.items():
            ccs = [cc for _t, cc in lst if cc]
            back = None
            if len(ccs) >= 2:
                back = any(ccs[i] < ccs[i - 1] for i in range(1, len(ccs)))
            checked[hex(a)] = {
                "hits": len(lst),
                "span_s": round(lst[-1][0] - lst[0][0], 3),
                "cyccnt_backwards": back,
                "cyccnt_last": (hex(ccs[-1]) if ccs else None),
                "cyccnt_note": (None if len(ccs) >= 2 else
                                "样本不足（CYCCNT 未使能或没读到），无法据此判断复位"),
            }
        rapid = [k for k, v in checked.items() if v["hits"] >= 3]
        out = {"ok": True, "window_s": win, "threshold": 3,
               "checked": checked, "rapid_addrs": rapid,
               "hist_len": len(self._bp_hit_hist),
               "note": ("窗口 %.1fs 内命中 ≥3 次的地址：" % win) +
                       (",".join(rapid) if rapid else "无")}
        if addr is not None and not checked:
            out["reason"] = "窗口内没有 %s 的命中记录" % hex(int(addr))
        return out

    def breakpoint_hits(self) -> dict:
        """返回断点命中计数 {hex(addr): count}。"""
        return {hex(k): v for k, v in self._bp_hits.items()}

    def bp_count_snapshot(self):
        """读一次 Keil 真实断点表的命中计数(CNT)快照 {number: {"count": n, "entry": {...}}}。

        真机实测：BL 输出每条断点带 `CNT=<命中次数>`，是判断「到底哪个断点命中了」的
        唯一可靠依据——数据观察点命中时 PC 不会等于观察地址，只看 PC 必然漏判。
        目标正在运行 / 命令窗口不可用时返回 None，调用方应降级判定。
        """
        try:
            real = self.list_breakpoints_real()
        except Exception:  # noqa: BLE001
            return None
        if not real.get("ok"):
            return None
        snap = {}
        for b in real.get("breakpoints") or []:
            try:
                snap[int(b["number"])] = {"count": b.get("count"), "entry": b}
            except Exception:  # noqa: BLE001
                continue
        return snap or None

    def read_dfsr(self) -> dict:
        """读 DFSR（Debug Fault Status Register，0xE000ED30）——最近一次调试事件。

        数据观察点（DWT 比较器）命中时 dwt_trap(bit2) 置位，这是「数据断点真的命中了」
        的直接硬证据（第 9 轮反馈：希望把观察点命中从 inferred 升级为 verified）。
        需已进入调试且目标暂停；读不到时返回 ok=False，调用方应降级判定而非报错。
        注意 DFSR 是 W1C（写 1 清位），要判断「本次等待期间是否发生过」必须先清零。
        返回 {ok, value, value_hex, halted, bkpt, dwt_trap, vcatch, external}。
        """
        try:
            r = self.read_mem(_DFSR_ADDR, 4)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "value": None, "error": str(e)}
        if not r.get("ok"):
            return {"ok": False, "value": None, "status": r.get("status"),
                    "status_text": r.get("status_text"),
                    "error": "读取 DFSR 失败：%s" % (r.get("status_text") or r.get("status"))}
        v = int.from_bytes(bytes.fromhex(r["data_hex"]), "little")
        return {"ok": True, "value": v, "value_hex": "0x%08X" % v,
                "halted": bool(v & _DFSR_HALTED), "bkpt": bool(v & _DFSR_BKPT),
                "dwt_trap": bool(v & _DFSR_DWTTRAP), "vcatch": bool(v & _DFSR_VCATCH),
                "external": bool(v & _DFSR_EXTERNAL)}

    def clear_dfsr(self, mask: int | None = None) -> dict:
        """清 DFSR 指定位（W1C：写 1 清除）。默认清 HALTED/BKPT/DWTTRAP/VCATCH。"""
        if mask is None:
            mask = _DFSR_HALTED | _DFSR_BKPT | _DFSR_DWTTRAP | _DFSR_VCATCH
        try:
            r = self.write_mem(_DFSR_ADDR, struct.pack("<I", mask & 0xFFFFFFFF))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "mask": "0x%08X" % (mask & 0xFFFFFFFF), "error": str(e)}
        return {"ok": bool(r.get("ok")), "mask": "0x%08X" % (mask & 0xFFFFFFFF),
                "status": r.get("status"), "written": r.get("written", 0)}

    def dwt_comp_values(self, count: int = 4) -> list:
        """读 DWT_COMP0..n 的比较地址，用于把「观察点命中」定位到具体是哪一个比较器。

        读不到的位置返回 None，调用方自行降级。需目标暂停。
        """
        out = []
        for i in range(max(0, int(count))):
            addr = _DWT_COMP_BASE + 0x10 * i
            try:
                r = self.read_mem(addr, 4)
            except Exception:  # noqa: BLE001
                r = {"ok": False}
            if r.get("ok") and r.get("data_hex"):
                out.append(int.from_bytes(bytes.fromhex(r["data_hex"]), "little"))
            else:
                out.append(None)
        return out

    def dwt_func_values(self, count: int = 4) -> list:
        """读 DWT_FUNCTION0..n（含 MATCHED 状态位），用于交叉确认数据观察点触发。"""
        out = []
        for i in range(max(0, int(count))):
            addr = _DWT_FUNC_BASE + 0x10 * i
            try:
                r = self.read_mem(addr, 4)
            except Exception:  # noqa: BLE001
                r = {"ok": False}
            if r.get("ok") and r.get("data_hex"):
                out.append(int.from_bytes(bytes.fromhex(r["data_hex"]), "little"))
            else:
                out.append(None)
        return out

    def watch_value_snapshot(self, watch_addrs) -> dict:
        """读被观察地址的当前值（4 字节），作为「等待期间是否被改写」的基线。

        数据观察点是对某地址的访问触发：若等待期间该地址的值真的变了，那就是「写访问
        确实发生过」的数据侧证据（第 9 轮建议③的可行替代——真机实测 Keil 在 halt 后
        会自行读走 DFSR/MATCHED，硬件命中位拿不到）。
        """
        snap = {}
        for a in (watch_addrs or []):
            try:
                a = int(a)
                r = self.read_mem(a, 4)
            except Exception:  # noqa: BLE001
                continue
            if r.get("ok") and r.get("data_hex"):
                snap[a] = r["data_hex"]
        return snap

    def watch_remember_values(self, watch_addrs) -> dict:
        """在目标处于停止态时记录被观察地址的值，作为后续等待的基线。

        调用点：设置数据观察点成功后、以及每次等待结束时（把本次停止点的值留作
        下一次的基线）。目标运行中读到的值可能是陈旧值，不做记录意义不大，但记录
        也不会造成误判（值未变就不算证据）。
        """
        snap = self.watch_value_snapshot(watch_addrs)
        if not isinstance(getattr(self, "_watch_value_cache", None), dict):
            self._watch_value_cache = {}
        self._watch_value_cache.update(snap)
        return snap

    def watch_baseline(self, watch_addrs) -> dict:
        """取「本次等待期间地址是否被改写」的基线：优先历史记录，缺失的再现场读。

        历史记录来自 watch_remember_values（设点 / 上一停止点）；只有从未记录过的
        地址才回退到现场读取，并在返回值旁记录用了哪些历史值，便于如实措辞。
        """
        cache = getattr(self, "_watch_value_cache", None) or {}
        out, missing, cached = {}, [], []
        for a in (watch_addrs or []):
            try:
                a = int(a)
            except Exception:  # noqa: BLE001
                continue
            if a in cache:
                out[a] = cache[a]
                cached.append(hex(a))
            else:
                missing.append(a)
        if missing:
            out.update(self.watch_value_snapshot(missing))
        self._watch_baseline_cached = cached
        return out

    def watch_value_check(self, watch_addrs, before) -> dict:
        """对比被观察地址的「等待前 / 命中后」值，返回逐地址比对结果。

        命中后顺带把「停止点的值」写入历史记录：本次窗口结束，它就是下一次的基线。
        """
        out = {}
        for a in (watch_addrs or []):
            try:
                a = int(a)
                b = (before or {}).get(a)
                r = self.read_mem(a, 4)
            except Exception:  # noqa: BLE001
                continue
            after = r.get("data_hex") if r.get("ok") else None
            out[hex(a)] = {"before": b, "after": after,
                           "changed": bool(b and after and b != after)}
            if after and isinstance(getattr(self, "_watch_value_cache", None), dict):
                self._watch_value_cache[a] = after
        return out

    def watch_hw_loaded(self, watch_addrs) -> dict:
        """确认数据观察点是否已装载到 DWT 比较器（读 DWT_COMPn 与候选地址比对）。

        真机实测（UVSOCK@4823 + STM32F429）：Keil 用 DWT 比较器实现数据观察点，
        设点后 COMPn 会等于观察地址。可据此区分「Keil 没把观察点装进硬件」（此时再等
        也不可能命中）与「装了但本次未触发」，避免把两种情况一律归为推断。
        """
        comps = self.dwt_comp_values()
        loaded = {}
        for a in (watch_addrs or []):
            try:
                a = int(a)
            except Exception:  # noqa: BLE001
                continue
            loaded[hex(a)] = any(
                c is not None and (c == a or (c | 1) == a or c == (a | 1)) for c in comps)
        return {"loaded": loaded, "any_loaded": any(loaded.values()),
                "dwt_comp": [None if c is None else hex(c) for c in comps],
                "note": "DWT_COMPn 与观察地址匹配 = 观察点已装到硬件比较器；"
                        "注意 Keil 在 halt 后会自行读走 DFSR/MATCHED，硬件命中位通常读不到"}

    def _match_watch_candidate(self, watch_addrs) -> tuple:
        """已有 DFSR.DWTTRAP 硬证据时，用 DWT_COMPn 定位命中的是哪个观察点。

        返回 (matched_addr, note)；比较器读不到或对不上候选时退回候选列表首个地址，
        并在 note 里说明退回了（不静默改变依据强度）。
        """
        comps = self.dwt_comp_values()
        for c in comps:
            if c is None or c == 0:
                continue
            for a in watch_addrs:
                try:
                    a = int(a)
                except Exception:  # noqa: BLE001
                    continue
                if c == a or (c | 1) == a or c == (a | 1):
                    return a, "DWT_COMP 匹配到观察点地址 %s" % hex(a)
        known = [hex(c) for c in comps if c]
        vals = "、".join(known) if known else "无"
        return int(watch_addrs[0]), ("DWT_COMP 未匹配到候选观察点（读到 %s），"
                                     "已退回候选列表首个地址" % vals)

    def wait_breakpoint(self, addresses=None, timeout_s: float = 10.0,
                        poll: float = 0.1, watch_addresses=None,
                        use_cnt: bool = True) -> dict:
        """带超时地等待目标停在（给定）断点上。

        addresses: 候选断点地址列表（int）。传空表示「不限定地址」——目标停下即算命中，
        用于只想等一个停止事件的场景。地址匹配自动兼容 Thumb 位（pc 与 addr 差 1）。
        watch_addresses: 数据观察点地址列表（int）。数据断点命中时 PC 不等于观察地址，
        故不能按 PC 判定。判定顺序：① 等待前后各读一次 Keil 断点表的 CNT，若某条 CNT
        增加，该条即命中项（代码断点同样适用）；② 读 DFSR(0xE000ED30)，若 DWTTRAP(bit2)
        置位（等待开始前已清零，故代表本次事件）则判为观察点命中，hit_entry.source="dfsr"
        ——这是硬件证据，hit_confidence="verified"，并用 DWT_COMPn 定位是哪个观察点；
        ③ 两者都取不到时退化为「目标已停止 + PC 不在任何代码候选 + 存在数据观察点」
        推断为观察点命中，hit_entry.source="inferred"、hit_confidence="inferred"，
        cnt_note 说明依据强度。结果里附 dfsr / dfsr_note（读到时给出 DWTTRAP/BKPT 位，
        读不到时说明原因）。
        注意（真机实测 UVSOCK@4823 + STM32F401）：同一断点命中多次，BL 输出的 CNT 恒为 1
        ——该字段是断点的计数条件设置值（.uvoptx 的 break_if_rcount），不是命中次数，
        故②才是常见路径；hit_kind 给 "code"/"watch"，hit_entry 注明来源。
        use_cnt: 是否启用 CNT 判定（默认 True；置 False 可省掉两次 BL 读取）。

        判定链路刻意保守：先确认目标已停止，再用 read_cpu_registers_stable 读取
        （含收敛判定 + 复查仍在运行），因此返回的 pc_confidence 可信度可直接采信；
        若读到的是陈旧 PC 会带 warning，不会被当成命中。

        「只认新发生的停止」：调用时目标若已处于停止态（典型场景——刚被 run_timeout
        停在某行、紧接着调本工具），那次停止不是本次等待的产物，绝不算命中，否则会把
        「进来时已停」误报成「等到了命中」。判为「新停止」的三条证据（满足其一即可，
        结果里用 new_stop_basis 标明用的是哪条）：

        ① ran_observed：等待期间亲眼见到目标在运行（最可靠）；
        ② run_issued：最近一次 run/step 命令晚于最近一次「观察到目标停止」——真机上
           run 后目标可能在一次 UVSOCK 往返内就命中断点，来不及看到运行态；
        ③ pc_moved：停止时的 PC 与调用时不同（手工在 Keil 界面点 Run 也属这种情况）。

        三条都不成立时直接返回 hit=False（stop_is_new=False、ran_during_wait=False），
        note 说明「目标在等待期间未曾运行」。另外起始就处于停止态时，先给
        _WAIT_RUN_GRACE_S 的宽限窗口只查状态（run/step 命令是异步的，响应会滞后），
        窗口内没见运行再读 PC 比对。

        返回 {ok, hit, hit_address, hit_count, waited_ms, polls, candidates, registers,
        pc_confidence, hit_kind, hit_confidence, hit_entry, dfsr, dfsr_note,
        ran_during_wait, stop_is_new, new_stop_basis, warning, repeat_warning}；
        超时返回 ok=False 且给出候选清单与原因。
        """
        adrs = []
        for a in (addresses or []):
            try:
                adrs.append(int(a))
            except Exception:  # noqa: BLE001
                continue
        watch_addrs = []
        for a in (watch_addresses or []):
            try:
                watch_addrs.append(int(a))
            except Exception:  # noqa: BLE001
                continue
        t0 = time.time()
        # 起始运行态（用户反馈，第 8 轮）：目标本来就停着时，wait_breakpoint 会立刻返回
        # hit=true 且 PC 与上一次停止完全相同——把「进来时已停」当成了「等到了断点命中」。
        # 目标在现场刚被 run_timeout/stop 停下后再调本工具是常见动作，必须区分开。
        # 判断「新停止」的三条证据（满足其一即算新）：
        #   ① 等待期间亲眼见到目标在运行（seen_running）
        #   ② 最近一次 run/step 命令晚于最近一次「观察到目标停止」（exec_pending）——
        #      真机上 run 后目标可能在一次 UVSOCK 往返内就命中断点，来不及看到运行态
        #   ③ 停止时的 PC 与调用时的 PC 不同（pc_moved）——手工在 Keil 里点过 Run 也算
        prev_stop_obs = self._last_stop_obs_ts
        try:
            st0 = self.get_status()
        except Exception:  # noqa: BLE001
            st0 = {}
        started_stopped = st0.get("running") is False
        seen_running = st0.get("running") is True
        exec_pending = self._exec_ts > prev_stop_obs
        pc_entry = None
        if started_stopped and not exec_pending:
            # 基线 PC：目标若压根没跑起来，PC 不会变——这是「这次停止是旧的」的直接证据
            _r0 = self.read_cpu_registers()
            if isinstance(_r0.get("pc"), int):
                pc_entry = _r0["pc"]
        # 宽限窗口不超过调用方给的超时，避免 wait_breakpoint(timeout_s=0.2) 反而等更久
        grace_deadline = t0 + min(_WAIT_RUN_GRACE_S, max(0.0, float(timeout_s)))
        # DFSR 硬证据基线（第 9 轮建议③）：先读一次前值、再清零（W1C）——等待期间重新置位
        # 的就是本次事件（只看结果不区分历史残留会误判）。目标当时可能在运行，读不到就降级。
        dfsr_base = self.read_dfsr()
        dfsr_cleared = False
        if dfsr_base.get("ok"):
            dfsr_cleared = bool(self.clear_dfsr().get("ok"))
        # 数据观察点：等待开始前记录被观察地址的值，命中后比对（数据侧证据）
        # 值变化基线：优先「设点时 / 上一停止点」的历史值（现场读可能已是被改写后的值）
        watch_before = self.watch_baseline(watch_addrs) if watch_addrs else {}
        # 命中计数基线：等待期间目标可能在运行，读失败也只是降级，不影响主流程
        cnt_base = self.bp_count_snapshot() if use_cnt else None
        deadline = t0 + max(0.0, float(timeout_s))
        polls = 0
        last: dict = {}
        while True:
            polls += 1
            try:
                last = self.get_status()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "hit": False, "error": str(e),
                        "waited_ms": int((time.time() - t0) * 1000), "polls": polls,
                        "candidates": [hex(a) for a in adrs]}
            if last.get("running") is True:
                seen_running = True
            if last.get("ok") and last.get("running") is False:
                stop_is_new_unknown = started_stopped and not seen_running and not exec_pending
                if stop_is_new_unknown and time.time() < grace_deadline:
                    # 宽限窗口内只查状态、不读寄存器：先确认 run/step 是否真生效
                    time.sleep(min(max(0.01, float(poll)),
                                   max(0.0, grace_deadline - time.time())))
                    continue
                regs = self.read_cpu_registers_stable(retries=20, delay=0.03)
                # DFSR 当前值（目标已停，可读）：DWTTRAP=数据观察点触发、BKPT=软件断点。
                dfsr_now = self.read_dfsr()
                dfsr_used = False
                pc = regs.get("pc") if isinstance(regs.get("pc"), int) else None
                pc_moved = pc_entry is not None and pc is not None and pc != pc_entry
                if stop_is_new_unknown and not pc_moved:
                    # 没见它跑过、也没发过 run、PC 更原地未动 → 这是「进来时就已经停着」的旧停止
                    return self._wait_preexisting_stop(
                        t0, polls, pc, regs, adrs, watch_addrs)
                if seen_running:
                    new_stop_basis = "ran_observed"
                elif exec_pending:
                    new_stop_basis = "run_issued"
                elif pc_moved:
                    new_stop_basis = "pc_moved"
                else:
                    new_stop_basis = "not_new"
                matched = None
                if pc is not None and adrs:
                    for a in adrs:
                        if pc == a or (pc | 1) == a or pc == (a | 1):
                            matched = a
                            break
                elif pc is not None and not watch_addrs:
                    # 既无代码候选、也无数据观察点：停下即视为命中（不限定地址的等待）
                    matched = pc
                # 数据观察点命中时 PC 不会等于观察地址，只按 PC 判定必然漏判（用户反馈：
                # 「实测已命中仍报 hit:false」）。可靠依据是 Keil 断点表的 CNT：停止后与
                # 等待前各读一次，CNT 增加的那条就是命中项（代码断点与数据观察点都适用）。
                hit_kind = "code" if matched is not None else None
                hit_entry = None
                vcheck = None
                cnt_delta = {}
                cnt_after = self.bp_count_snapshot() if use_cnt else None
                if cnt_base and cnt_after:
                    for num, cur in cnt_after.items():
                        prev = (cnt_base.get(num) or {}).get("count")
                        now = cur.get("count")
                        if isinstance(prev, int) and isinstance(now, int) and now > prev:
                            cnt_delta[int(num)] = now - prev
                if cnt_delta:
                    num = max(cnt_delta, key=lambda k: cnt_delta[k])
                    hit_entry = dict(cnt_after[num].get("entry") or {})
                    hit_entry["source"] = "cnt"
                    if matched is None:
                        hit_kind = ("watch" if hit_entry.get("kind") == "access"
                                    else "code")
                        try:
                            matched = int(str(hit_entry.get("address")), 16)
                        except Exception:  # noqa: BLE001
                            matched = None
                elif matched is None and watch_addrs:
                    # 判定链路（证据强度递减）：
                    #   ① DFSR.DWTTRAP 置位 → 硬件命中位（等待前已清零，代表本次事件）；
                    #   ② 被观察地址的值在等待期间被改写 → 数据侧实证；
                    #   ③ 都拿不到 → 按「目标已停 + PC 不在代码候选 + 存在观察点」推断。
                    # 真机实测（UVSOCK@4823 + STM32F429）：Keil 用 DWT 比较器实现数据观察点
                    # （设点后 DWT_COMPn = 观察地址），但 halt 后 Keil 会自行读走 DFSR 与
                    # DWT_FUNCTIONn.MATCHED，硬件命中位通常读到恒为 0，故 ② 是真机可行路径。
                    if dfsr_now.get("ok") and dfsr_now.get("dwt_trap"):
                        hit_kind = "watch"
                        matched, _comp_note = self._match_watch_candidate(watch_addrs)
                        hit_entry = {
                            "kind": "access", "address": hex(int(matched)),
                            "source": "dfsr",
                            "note": ("DFSR.DWTTRAP=1（%s）：DWT 比较器触发，硬件证据"
                                     % dfsr_now.get("value_hex"))}
                        if _comp_note:
                            hit_entry["note"] += "；" + _comp_note
                        dfsr_used = True
                    else:
                        _chg = []
                        if watch_before:
                            vcheck = self.watch_value_check(watch_addrs, watch_before)
                            _chg = [k for k, v in vcheck.items() if v.get("changed")]
                        if _chg:
                            matched = int(_chg[0], 16)
                            hit_kind = "watch"
                            hit_entry = {
                                "kind": "access", "address": _chg[0],
                                "source": "value_changed",
                                "note": ("被观察地址 %s 的值由 %s 变为 %s：数据侧实证"
                                         "（该地址确实被写过）；非 DWT 硬件命中位。"
                                         "基线取自%s"
                                         % (_chg[0], vcheck[_chg[0]]["before"],
                                            vcheck[_chg[0]]["after"],
                                            ("设点/上一停止点的历史记录" if _chg[0] in
                                             (getattr(self, "_watch_baseline_cached", None) or [])
                                             else "等待开始时的现场读取")))}
                        else:
                            # 退步判定：CNT 增量不可用（或本版 Keil 的 BL CNT 并非命中次数）、
                            # 也拿不到数据侧证据时，按「目标已停 + PC 不在代码候选 + 有观察点」推断。
                            # 实测（UVSOCK@4823 + STM32F401）：同一断点命中 3 次，BL 输出的 CNT 恒为 1，
                            # 该字段是断点的计数条件设置值（.uvoptx 的 break_if_rcount），不是命中次数，
                            # 故这里以推断为主，并在 hit_entry/cnt_note 里标明依据强度。
                            if cnt_base and cnt_after:
                                why = ("断点表 CNT 未随命中递增（本版 Keil 的 BL CNT 是断点计数条件、"
                                       "不是命中次数），已按「目标已停止且 PC 不在任何代码候选上」推断")
                            else:
                                why = ("未能取得断点表 CNT（等待开始时目标可能在运行或命令窗口不可用），"
                                       "已按「目标已停止且 PC 不在任何代码候选上」推断")
                            if watch_before:
                                why += ("；被观察地址的值与基线一致、未观察到改写"
                                        "（读不到值变化证据）")
                            else:
                                why += "；未能取得被观察地址的基线值（等待开始时目标可能在运行）"
                            if dfsr_now.get("ok"):
                                why += "；DFSR 已读到但 DWTTRAP=0（%s）" % dfsr_now.get("value_hex")
                            else:
                                why += "；DFSR 读取失败（未进入调试或目标不支持）"
                            hit_kind = "watch"
                            matched = int(watch_addrs[0])
                            hit_entry = {"kind": "access", "address": hex(int(watch_addrs[0])),
                                         "source": "inferred", "note": why}
                if hit_entry is None and matched is not None and cnt_after:
                    # 真机实测本版 Keil 的 BL CNT 不随命中递增，此时按 PC 命中的代码断点
                    # 在 CNT 快照里找回同地址项，保证 hit=true 时也能说明"命中的是哪条"。
                    for _num, _cur in cnt_after.items():
                        _ent = dict(_cur.get("entry") or {})
                        try:
                            _ea = int(str(_ent.get("address")), 16)
                        except Exception:  # noqa: BLE001
                            continue
                        if _ea in (matched, matched | 1) or (_ea | 1) == matched:
                            _ent["source"] = "pc"
                            hit_entry = _ent
                            break
                waited = int((time.time() - t0) * 1000)
                out = {"ok": True, "hit": matched is not None, "stopped": True,
                       "pc": hex(pc) if pc is not None else None,
                       "waited_ms": waited, "polls": polls, "registers": regs,
                       "candidates": [hex(a) for a in adrs],
                       "pc_confidence": regs.get("pc_confidence"),
                       "ran_during_wait": bool(seen_running), "stop_is_new": True,
                       "new_stop_basis": new_stop_basis}
                if hit_kind:
                    out["hit_kind"] = hit_kind
                if hit_entry:
                    out["hit_entry"] = hit_entry
                if cnt_delta:
                    out["cnt_delta"] = {str(k): v for k, v in cnt_delta.items()}
                # 命中依据强度：PC / CNT / DFSR 都是可核对的实际证据 → verified；仅「目标已停 +
                # PC 不在候选 + 存在观察点」的纯推断 → inferred（第 9 轮反馈明确要求区分两者）。
                _src = (hit_entry or {}).get("source")
                if matched is not None and hit_kind:
                    out["hit_confidence"] = "inferred" if _src == "inferred" else "verified"
                if vcheck is not None:
                    out["watch_value_check"] = vcheck
                if watch_addrs:
                    try:
                        out["dwt_watch_loaded"] = self.watch_hw_loaded(watch_addrs)
                    except Exception as e:  # noqa: BLE001
                        out["dwt_watch_loaded"] = {"error": str(e)}
                if dfsr_now.get("ok"):
                    out["dfsr"] = dfsr_now
                    if dfsr_now.get("dwt_trap"):
                        _dfsr_what = "DWT 比较器触发（数据观察点）"
                    elif dfsr_now.get("bkpt"):
                        _dfsr_what = "软件断点命中"
                    elif dfsr_now.get("vcatch"):
                        _dfsr_what = "Vector catch"
                    else:
                        _dfsr_what = "无 DWT/BKPT 事件"
                    out["dfsr_note"] = ("等待开始前%s清零 DFSR；当前 %s（%s）"
                                       % ("已" if dfsr_cleared else "未能",
                                          dfsr_now.get("value_hex"), _dfsr_what))
                else:
                    out["dfsr_note"] = ("未能读到 DFSR（%s）：数据观察点命中判定保持推断强度，"
                                        "如需硬证据请确认已进入调试且目标暂停"
                                        % (dfsr_now.get("error") or "未知原因"))
                if use_cnt and not (cnt_base and cnt_after):
                    out["cnt_note"] = ("未能取得断点命中计数(CNT)基线（等待开始时目标可能在运行或"
                                       "命令窗口不可用），本次命中判定已降级；如需精确判定，"
                                       "可先 stop 再 wait_breakpoint")
                if hit_kind == "watch" and (hit_entry or {}).get("source") == "inferred":
                    out["cnt_note"] = ("本版 Keil 的 BL CNT 不随命中递增（是断点计数条件），"
                                       "数据观察点命中判定已降级为推断：hit_entry.source=inferred")
                if matched is None:
                    # 目标已停止但 PC 不在候选地址：静默返回 hit=false 会让调用方无从下手，
                    # 这里直接说明「为什么会没命中」以及下一步该做什么。
                    out["note"] = (
                        "目标当前已停止，但 PC(%s) 不在候选断点地址（%s）——本次未等到命中。"
                        "若期望目标跑到断点，请先 run（或 reset 后 run）再 wait_breakpoint；"
                        "若它本应停在断点处，请用 list_breakpoints 确认断点是否还在、"
                        ".axf 与板上固件是否一致（符号漂移会导致地址对不上）。"
                        % (out.get("pc"), "、".join(out.get("candidates") or []) or "未指定"))
                if matched is not None:
                    out["hit_address"] = hex(matched)
                    if hit_kind == "watch":
                        out["hit_address_note"] = ("这是命中的数据观察点地址（不是 PC）："
                                                   "数据断点触发时 PC 停在访问该地址的指令处")
                    out["hit_count"] = self.note_breakpoint_hit(matched)
                for k in ("warning", "repeat_warning"):
                    if regs.get(k):
                        out[k] = regs[k]
                return out
            if time.time() >= deadline:
                return {"ok": False, "hit": False,
                        "waited_ms": int((time.time() - t0) * 1000), "polls": polls,
                        "target_running": bool(last.get("running")),
                        "candidates": [hex(a) for a in adrs], "status": last,
                        "error": ("等待断点命中超时（%dms）：目标未停在候选断点上。"
                                  "排查建议：① 用 list_breakpoints / list_uvoptx_breakpoints "
                                  "确认断点确实存在且已启用（.uvoptx 遗留断点会干扰）；"
                                  "② App 侧若做了重定位，运行时地址与符号地址不同，"
                                  "应传实际运行地址；③ 目标可能一直没执行到该路径。"
                                  % int((time.time() - t0) * 1000))}
            time.sleep(poll)

    def _wait_preexisting_stop(self, t0, polls, pc, regs, adrs, watch_addrs) -> dict:
        """目标「进来时就已经停着」且等待期间没跑起来：那次停止不计为命中。

        用户反馈（第 8 轮）：run_timeout(250) 把目标停在 svcrt_loader.c:156 后紧接着
        调 wait_breakpoint，立刻返回 hit=true 且 PC 与上一次完全相同（repeat_count=2）
        ——把「进来时已停」当成了「等到了断点命中」。只在等待期间观察到目标运行过
        （或 PC 相对调用时移动过）才认这次停止，否则落到这里如实报 hit=False。
        """
        pc_s = hex(pc) if pc is not None else None
        cands = [hex(a) for a in adrs]
        note = ("目标在等待期间未曾运行：调用 wait_breakpoint 时它已停止（PC=%s），"
                "这次停止不是本次等待期间新发生的，故不计为命中（stop_is_new=false）。"
                "若期望等到断点命中，请先 run（或 reset 后 run）再调用本工具。"
                % pc_s)
        if pc is not None and pc not in adrs:
            note += ("当前 PC(%s) 也不在候选断点地址（%s）——可用 list_breakpoints 确认"
                     "断点是否还在、.axf 与板上固件是否一致（符号漂移会导致地址对不上）。"
                     % (pc_s, "、".join(cands) or "未指定"))
        if watch_addrs:
            note += ("本次另有 %d 个数据观察点候选，同样只有等待期间新发生的停止才算命中。"
                     % len(watch_addrs))
        out = {"ok": True, "hit": False, "stopped": True, "pc": pc_s,
               "waited_ms": int((time.time() - t0) * 1000), "polls": polls,
               "registers": regs, "candidates": cands,
               "pc_confidence": regs.get("pc_confidence"),
               "ran_during_wait": False, "stop_is_new": False,
               "new_stop_basis": "not_new", "note": note}
        for k in ("warning", "repeat_warning"):
            if regs.get(k):
                out[k] = regs[k]
        return out

    # ------------------------------------------------------------------
    # 运行控制
    # ------------------------------------------------------------------
    def run(self) -> dict:
        return self._control(uvsock.UV_DBG_START_EXECUTION, "运行",
                             accept=(uvsock.UV_STATUS_TARGET_EXECUTING,))

    def stop(self) -> dict:
        return self._control(uvsock.UV_DBG_STOP_EXECUTION, "暂停",
                             accept=(uvsock.UV_STATUS_TARGET_EXECUTING,
                                     uvsock.UV_STATUS_TARGET_STOPPED))

    def wait_until_stopped(self, timeout: float = 1.0, interval: float = 0.05) -> dict:
        """轮询等待目标"真正"停止（stop 是异步生效的）。

        真机实测：stop 命令返回时目标可能仍在运行（响应状态滞后），此时读到的 PC/
        寄存器是陈旧值——会稳定返回复位附近地址（如 0x0800024c Reset_Handler），
        而 LR/SP 却指向空闲循环，极易误判成"程序停在复位"。因此停止后需轮询
        UV_DBG_STATUS 直到 running 为假，再做后续读取。

        返回 {ok, stopped, waited_ms, status}；超时未停返回 ok=False 且 stopped=False。
        """
        t0 = time.time()
        deadline = t0 + max(0.0, float(timeout))
        while True:
            try:
                st = self.get_status()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "stopped": False, "error": str(e),
                        "waited_ms": int((time.time() - t0) * 1000)}
            waited = int((time.time() - t0) * 1000)
            if st.get("ok") and st.get("running") is False:
                return {"ok": True, "stopped": True, "waited_ms": waited, "status": st}
            if time.time() >= deadline:
                return {"ok": False, "stopped": False, "waited_ms": waited,
                        "error": "等待目标停止超时(%dms)：目标仍在运行，寄存器为陈旧值不可信" % waited,
                        "status": st}
            time.sleep(interval)

    def reset(self) -> dict:
        """复位目标。

        真实 Keil 在目标处于运行状态时会拒绝复位（status=11 UV_STATUS_TARGET_EXECUTING）；
        且 stop 是异步生效的，暂停后立即复位仍可能被拒。这里自动"暂停 → 等目标真正
        停下 → 复位"，最多重试 2 轮，成功时在返回里标 auto_stopped。
        """
        out = self._control(uvsock.UV_DBG_RESET, "复位")
        if out.get("ok"):
            return out
        running = out.get("status") in (uvsock.UV_STATUS_TARGET_EXECUTING,
                                        uvsock.DBG_EXECUTING)
        if not running:
            try:
                running = bool(self.get_status().get("running"))
            except Exception:  # noqa: BLE001
                running = False
        if not running:
            return out
        last = out
        for _ in range(3):
            stopped = self.stop()
            # stop 的响应状态可能滞后（真机实测会返回 status=11），不能据此判失败，
            # 改为轮询 get_status 确认目标是否真正停下；且 stop 异步生效，
            # 未停下就复位仍会被 Keil 以 status=11 拒绝。
            halted = False
            for _ in range(20):
                try:
                    st = self.get_status()
                except Exception:  # noqa: BLE001
                    halted = True
                    break
                if not st.get("running"):
                    halted = True
                    break
                time.sleep(0.05)
            if not halted:
                last["note"] = ("目标处于运行状态，已尝试暂停但仍未停下，复位未执行；"
                                "可稍后重试或显式调用 stop 后再 reset。")
                last["auto_stop"] = stopped
                return last
            retry = self._control(uvsock.UV_DBG_RESET, "复位")
            if retry.get("ok"):
                retry["auto_stopped"] = True
                retry["note"] = "目标原处于运行状态，已自动先暂停(stop)、等其停止后再复位。"
                return retry
            last = retry
        last["auto_stopped"] = True
        last["first_attempt"] = out
        last["note"] = ("目标原处于运行状态，已自动暂停并等待其停止，但仍未能复位"
                        "（目标可能反复自动运行）；可显式 stop 后稍等再 reset。")
        return last

    def step(self, mode: str = "into") -> dict:
        mode = (mode or "into").lower()
        cmd_map = {
            "into": uvsock.UV_DBG_STEP_INTO,
            "instruction": uvsock.UV_DBG_STEP_INSTRUCTION,
            "over": uvsock.UV_DBG_STEP_HLL,
            "out": uvsock.UV_DBG_STEP_OUT,
        }
        if mode not in cmd_map:
            return {"status": uvsock.UV_STATUS_INVALID_NAME, "ok": False,
                    "status_text": f"不支持的 step 模式: {mode}",
                    "mode": mode}
        return self._control(cmd_map[mode], f"单步({mode})", extra={"mode": mode},
                             accept=(uvsock.UV_STATUS_TARGET_EXECUTING,
                                     uvsock.UV_STATUS_TARGET_STOPPED))

    def _control(self, cmd_code: int, label: str, extra: dict | None = None,
                 accept: tuple = ()) -> dict:
        """执行运行控制命令。

        accept 为"除 status=0 外同样表示命令已生效"的状态码集合：真实 Keil 对
        run/stop/step 常回带目标当前状态码（11=正在运行 / 12=已停止），此时命令
        其实已经生效，不应判成失败（真机实测：step over 返回 12 且带完整停靠位置）。
        """
        status, m_data = self._request(cmd_code)
        ok = status == UV_STATUS_SUCCESS or status in accept
        if ok:
            _now = time.time()
            if cmd_code in (uvsock.UV_DBG_START_EXECUTION, uvsock.UV_DBG_STEP_INTO,
                            uvsock.UV_DBG_STEP_HLL, uvsock.UV_DBG_STEP_INSTRUCTION,
                            uvsock.UV_DBG_STEP_OUT):
                # 发出过 run/step：后续观察到的停止可能是它跑出来的结果（即使没抓到运行态）
                self._exec_ts = _now
            elif cmd_code == uvsock.UV_DBG_STOP_EXECUTION:
                # 我们主动暂停：这次停止算「已消化」，之后的停止需再有 run/step 才算新
                self._last_stop_obs_ts = _now
            # 运行状态刚被我们改过，缓存立即失效（别让后续读取拿过期的结论）
            self._run_cache_at = 0.0
        out = {"status": status, "ok": ok,
               "status_text": status_text(status), "action": label}
        if extra:
            out.update(extra)
        return out

    # ------------------------------------------------------------------
    # 串口 / ITM（Instrumentation Trace Macrocell）数据读写
    # ------------------------------------------------------------------
    def serial_get(self, port: int = 0, size: int = 4096) -> dict:
        """从 Keil 串口窗口读取数据（含 Debug(printf) Viewer / ITM 输出）。

        经 UV_DBG_SERIAL_GET(0x2011) 拉取指定串口窗口当前缓冲内容。
        port: 串口窗口编号（Keil 的 Serial Windows 序号，通常 0=UART#1，
              Debug(printf) Viewer 对应其中一个编号）；size: 最多读取字节数。
        返回 {ok, port, size, data_hex, ascii}。

        注意：真实 ITM 输出需 Keil 已配置 Trace（Core Clock + Stimulus Port0）
        且调试器 SWO 引脚已使能，否则读到的缓冲可能为空。
        """
        if size <= 0 or size > 65536:
            return {"ok": False, "error": "size 需在 1~65536 之间", "size": size}
        # 请求 data = 目标串口窗口号(4B 小端) + 期望字节数(4B 小端)
        data = struct.pack('<II', port & 0xFFFFFFFF, size)
        status, m_data = self._request(uvsock.UV_DBG_SERIAL_GET, data=data)
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS,
               "status": status, "status_text": status_text(status),
               "port": port, "size": size,
               "data_hex": m_data.hex(), "ascii": self._to_ascii(m_data)}
        if status != uvsock.UV_STATUS_SUCCESS:
            out["data_hex"] = ""
            out["ascii"] = ""
        return out

    def serial_put(self, port: int = 0, data: bytes = b'') -> dict:
        """向 Keil 串口窗口写入数据（向目标仿真串口 / ITM 输入通道下发）。

        经 UV_DBG_SERIAL_PUT(0x2012) 将字节写入指定串口窗口。
        port: 串口窗口编号；data: 要写入的原始字节。
        返回 {ok, port, written}。
        """
        if not data:
            return {"ok": False, "error": "data 不能为空", "port": port}
        if len(data) > 65536:
            return {"ok": False, "error": "data 过长(>65536)", "port": port}
        req = struct.pack('<I', port & 0xFFFFFFFF) + data
        status, m_data = self._request(uvsock.UV_DBG_SERIAL_PUT, data=req)
        return {"ok": status == uvsock.UV_STATUS_SUCCESS,
                "status": status, "status_text": status_text(status),
                "port": port, "written": len(data)}

    # ------------------------------------------------------------------
    # target / 工程多目标
    # ------------------------------------------------------------------
    def _prj_text(self, cmd_code: int, data: bytes = b'', label: str = "") -> dict:
        """发送一条 UV_PRJ_* 命令，把响应 data 解码为文本返回（UTF-8 优先，GBK 回退）。

        真实 Keil 的 UV_PRJ_* 文本响应为“4字节小端长度头 + 字符串”格式，解析前先跳过头。
        """
        status, m_data = self._request(cmd_code, data=data)
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS, "status": status,
               "status_text": status_text(status), "command": label,
               "data_hex": m_data.hex()}
        if status == uvsock.UV_STATUS_SUCCESS and m_data:
            payload = m_data
            if len(payload) >= 4:
                ln = struct.unpack('<I', payload[:4])[0]
                if 0 < ln <= len(payload) - 4:
                    payload = payload[4:4 + ln]
            txt = None
            for enc in ("utf-8", "gbk", "latin-1"):
                try:
                    t = payload.decode(enc).rstrip("\x00").strip()
                    if t:
                        txt = t
                        break
                except (UnicodeDecodeError, ValueError):
                    continue
            out["text"] = txt if txt is not None else ""
        return out

    def get_cur_target(self) -> dict:
        """查询当前工程当前 target 名（UV_PRJ_GET_CUR_TARGET 0x1017）。"""
        r = self._prj_text(uvsock.UV_PRJ_GET_CUR_TARGET, label="get_cur_target")
        if r.get("ok"):
            r["target"] = r.get("text", "")
        return r

    def enum_targets(self) -> dict:
        """枚举当前工程所有 target（UV_PRJ_ENUM_TARGETS 0x1015）。"""
        r = self._prj_text(uvsock.UV_PRJ_ENUM_TARGETS, label="enum_targets")
        if r.get("ok") and r.get("text"):
            lines = [ln.strip() for ln in r["text"].splitlines() if ln.strip()]
            r["targets"] = lines
        return r

    def get_debug_target(self) -> dict:
        """查询当前调试 target（UV_PRJ_GET_DEBUG_TARGET 0x100B）。"""
        r = self._prj_text(uvsock.UV_PRJ_GET_DEBUG_TARGET, label="get_debug_target")
        if r.get("ok"):
            r["target"] = r.get("text", "")
        return r

    def set_debug_target(self, target: str) -> dict:
        """设置调试 target（UV_PRJ_SET_DEBUG_TARGET 0x100C）。target 为 target 名或索引。"""
        from .uvsock import VSET
        ve = VSET()
        status, m_data = self._request(uvsock.UV_PRJ_SET_DEBUG_TARGET, data=ve.pack(target))
        out = {"ok": status == uvsock.UV_STATUS_SUCCESS, "status": status,
               "status_text": status_text(status), "target": target,
               "data_hex": m_data.hex()}
        if status == uvsock.UV_STATUS_SUCCESS:
            txt = m_data.decode("utf-8", "replace").rstrip("\x00").strip()
            out["text"] = txt
        return out

    # ------------------------------------------------------------------
    # DBGMCU 调试冻结位（批次32 反馈②：看门狗在 halt 期间继续跑）
    # ------------------------------------------------------------------
    #: DBGMCU 候选基址（按内核代数排序，运行时探测哪个可读）
    DBGMCU_BASES = ((0xE0042000, "Cortex-M3/M4/M7（STM32F1/F4/F7 等）"),
                    (0x5C001000, "Cortex-M7（STM32H7 系列）"))
    #: 冻结寄存器偏移与位定义（F4/F7/H7 的 IWDG/WWDG 停止位语义一致）
    DBGMCU_APB1FZ_OFF = 0x08
    DBGMCU_APB2FZ_OFF = 0x0C
    DBG_FREEZE_BITS = (("iwdg", 12), ("wwdg", 11))
    #: SCB->CCR（D-Cache 使能位）
    SCB_CCR_ADDR = 0xE000ED14
    SCB_CCR_DC = 1 << 16
    SCB_CCR_IC = 1 << 17

    def _u32(self, addr: int):
        """读一个 32 位小端寄存器，返回 (值, 错误信息)。"""
        r = self.read_mem(addr, 4)
        hx = (r.get("data_hex") or "")
        if not r.get("ok") or len(hx) < 8:
            return None, (r.get("status_text") or "读取失败")
        return int.from_bytes(bytes.fromhex(hx[:8]), "little"), None

    def dbgmcu_base(self) -> dict:
        """探测 DBGMCU 基址：逐个候选读 IDCODE 并校验 DEV_ID 是否合法。

        真机实测：STM32F4（Cortex-M4）在 0xE0042000 读到 IDCODE=0x10016433；
        0x5C001000（H7 基址）在 M4 上读失败——所以用「能读到且 DEV_ID 合法」作判据，
        比按内核型号硬编码更稳（同一内核家族的系列基址也可能不同）。
        """
        tried = []
        for base, desc in self.DBGMCU_BASES:
            val, err = self._u32(base)
            if val is None:
                tried.append({"base": "0x%08X" % base, "ok": False, "note": err})
                continue
            dev = val & 0x0FFF
            if dev in (0x000, 0xFFF):
                tried.append({"base": "0x%08X" % base, "ok": False,
                              "idcode": "0x%08X" % val,
                              "note": "DEV_ID 非法（该基址无 DBGMCU）"})
                continue
            return {"ok": True, "base": base, "desc": desc, "idcode": val,
                    "dev_id": dev, "rev_id": (val >> 16) & 0xFFFF, "tried": tried}
        return {"ok": False, "tried": tried,
                "error": "未找到可用的 DBGMCU 基址（已尝试：%s）。"
                         "目标可能不是 STM32，或读取被挡住（需先进入调试并暂停）。"
                         % (", ".join("%s %s" % (t.get("base"), t.get("note"))
                                      for t in tried) or "无")}

    def get_watchdog_freeze(self) -> dict:
        """读 DBGMCU 冻结位：halt 期间 IWDG/WWDG 是否被冻结。"""
        b = self.dbgmcu_base()
        if not b.get("ok"):
            return {"ok": False, "error": b.get("error"), "tried": b.get("tried")}
        base = b["base"]
        val, err = self._u32(base + self.DBGMCU_APB1FZ_OFF)
        if val is None:
            return {"ok": False, "error": "读取 DBGMCU_APB1FZ 失败：%s" % err,
                    "dbgmcu_base": "0x%08X" % base}
        bits = {name: bool(val & (1 << bit)) for name, bit in self.DBG_FREEZE_BITS}
        out = {"ok": True,
               "dbgmcu_base": "0x%08X" % base, "dbgmcu_desc": b["desc"],
               "dev_id": "0x%03X" % b["dev_id"], "rev_id": "0x%04X" % b["rev_id"],
               "apb1fz_addr": "0x%08X" % (base + self.DBGMCU_APB1FZ_OFF),
               "apb1fz": "0x%08X" % val,
               "iwdg_stopped": bits["iwdg"], "wwdg_stopped": bits["wwdg"],
               "all_frozen": bits["iwdg"] and bits["wwdg"]}
        if not out["all_frozen"]:
            out["warning"] = (
                "DBGMCU 冻结位未全部置起：目标暂停（halt）期间 IWDG/WWDG 仍继续计数，"
                "停机超过看门狗溢出时间就会被复位、RAM 现场全丢（真机踩过）。"
                "置位后 halt 期间看门狗停止计数。")
        return out

    def set_watchdog_freeze(self, enable: bool = True) -> dict:
        """置位/清除 DBGMCU 的 IWDG/WWDG 冻结位（读-改-写 + 回读确认）。

        注意：新会话 / 目标复位后 DBGMCU 冻结位会被清零，需要重新置位——
        所以 stop / enter_debug 现在会自动调用（见 server 侧）。
        """
        b = self.dbgmcu_base()
        if not b.get("ok"):
            return {"ok": False, "error": b.get("error"), "tried": b.get("tried")}
        base = b["base"]
        addr = base + self.DBGMCU_APB1FZ_OFF
        before, err = self._u32(addr)
        if before is None:
            return {"ok": False, "error": "读取 DBGMCU_APB1FZ 失败：%s" % err,
                    "dbgmcu_base": "0x%08X" % base, "addr": "0x%08X" % addr}
        mask = 0
        for _n, bit in self.DBG_FREEZE_BITS:
            mask |= (1 << bit)
        want = (before | mask) if enable else (before & ~mask)
        out = {"ok": True, "dbgmcu_base": "0x%08X" % base, "addr": "0x%08X" % addr,
               "before": "0x%08X" % before, "requested_enable": bool(enable)}
        after = before  # 未发生变更时下面直接用 before 当作 after（避免未定义）
        if want == before:
            out.update({"changed": False, "after": "0x%08X" % before, "verified": True})
        else:
            w = self.write_mem(addr, want.to_bytes(4, "little"))
            if not w.get("ok"):
                return {"ok": False, "error": "写 DBGMCU_APB1FZ 失败：%s"
                        % (w.get("status_text") or "未知"), **out}
            after, err2 = self._u32(addr)
            out.update({"changed": True,
                        "after": ("0x%08X" % after) if after is not None else None,
                        "verified": after == want,
                        "write_note": err2})
        val = after if out.get("after") else before
        if isinstance(val, str):
            val = int(val, 16)
        bits = {name: bool(val & (1 << bit)) for name, bit in self.DBG_FREEZE_BITS}
        out.update({"iwdg_stopped": bits["iwdg"], "wwdg_stopped": bits["wwdg"],
                    "all_frozen": bits["iwdg"] and bits["wwdg"]})
        if not out.get("verified"):
            out["warning"] = ("回读值与写入值不一致：该寄存器可能被硬件限制（部分位只读）"
                              "或写入被忽略，请用 watchdog_freeze(action='status') 复核。")
        return out

    # ------------------------------------------------------------------
    # Cache 状态（批次32 反馈③：H7 开 D-Cache 时 DAP 直读/直写不可信）
    # ------------------------------------------------------------------
    def get_cache_state(self) -> dict:
        """读 SCB->CCR 判定 I-Cache / D-Cache；D-Cache 开启时附维护建议。"""
        val, err = self._u32(self.SCB_CCR_ADDR)
        if val is None:
            return {"ok": False, "error": "读取 SCB->CCR 失败：%s" % err,
                    "ccr_addr": "0x%08X" % self.SCB_CCR_ADDR}
        dc = bool(val & self.SCB_CCR_DC)
        ic = bool(val & self.SCB_CCR_IC)
        out = {"ok": True, "ccr_addr": "0x%08X" % self.SCB_CCR_ADDR,
               "ccr": "0x%08X" % val, "dcache": dc, "icache": ic}
        # D-Cache 容量（CCSIDR + CLIDR，仅部分内核实现）
        cssidr, _e1 = self._u32(0xE000ED80)
        clidr, _e2 = self._u32(0xE000ED78)
        if cssidr:
            ls = (cssidr & 0x7) + 4               # LineSize = 2^(LS+4) bytes
            ways = ((cssidr >> 3) & 0x3FF) + 1
            sets = ((cssidr >> 13) & 0x7FFF) + 1
            size = ways * sets * (1 << ls)
            out.update({"cache_line_bytes": 1 << ls, "cache_ways": ways,
                        "cache_sets": sets, "cache_size_kb": round(size / 1024.0, 1)})
        if dc:
            out["warning"] = (
                "目标 D-Cache 已开启：调试器（DAP）**直读 RAM 可能读到缓存里的陈旧值**"
                "（内存被改过但脏行未回写），**直写 RAM 也可能被脏行回写覆盖**——"
                "读到的值/写下去的值都不代表内存真实状态，且不会报错。"
                "核对现场前建议先让目标经 SCB 维护（clean/invalidate），或改用"
                "cache_info 给出的判断口径，别仅凭一次直读下结论。")
        else:
            out["note"] = ("未检测到已使能的 D-Cache（CCR.DC=0）：直读/直写按内存真实状态生效。"
                           "Cortex-M3/M4 无 D-Cache；M7（H7 等）默认不开，需软件显式使能。")
        return out

    # ------------------------------------------------------------------
    # 工具
    # ------------------------------------------------------------------
    @staticmethod
    def _to_ascii(data: bytes) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
