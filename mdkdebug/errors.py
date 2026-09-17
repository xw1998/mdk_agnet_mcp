# -*- coding: utf-8 -*-
"""统一结果信封 + 字符串错误码（批次33）。

为什么需要这一层
----------------
吸收自两个开源项目的同一做法：

- `embeddedskills` 规定所有子命令返回同一个信封
  `{status, action, summary, details, artifacts, metrics, next_actions, timing}`；
- `keil-project-tools` 定义了一组**字符串**错误码（`target-not-found` /
  `environment-missing` / `partial-failure`…），并规定 message 里要带候选列表。

它们的共同动机是：**调用方（AI）不该靠解析中文报错来决定下一步**。
本项目此前只有逐工具零散的 `hint` / `note` / `warning`，以及各不相同的 `ok` 语义——
「报错后给下一步动作」是这套工具最值钱的部分，却是「某些工具恰好有」，不是契约。

这一层做两件事，且**只做加法**（不改动任何既有字段，避免破坏已有调用与测试）：

1. 给所有工具的结果补上 `status`（ok / warn / error）；
2. 失败时补 `error_code`（稳定的机器可读串）+ `error_hint`，并把散落的
   `hint` / `*_hint` / `suggestion` 归拢成 `next_actions` 数组。

另外补 `risk`：高风险工具（会改目标 Flash/内存、会关掉用户的 Keil）在结果里
明确标出来，省得调用方在长链路里忘记自己刚做了一次不可逆操作。
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("mdkdebug.errors")

# ----------------------------------------------------------------------
# 风险分级（吸收 embeddedskills 的 operation_mode：低/中/高）
# ----------------------------------------------------------------------
RISK_HIGH = {
    "flash_download", "flash_debug", "build_and_flash", "clean_project",
    "fill_mem", "write_peripheral", "close_uvision", "restart_keil",
    "reset", "set_breakpoint", "clear_all_breakpoints", "write_mem",
}
RISK_MEDIUM = {
    "build_project", "rebuild_project", "launch_uvision", "run", "stop",
    "step", "reset_connection", "dismiss_dialog", "serial_write", "serial_expect",
    "set_reloc_delta", "serial_monitor_start", "serial_monitor_stop",
}

# ----------------------------------------------------------------------
# 字符串错误码字典
# ----------------------------------------------------------------------
ERROR_CODES = {
    "uvsock-unavailable": {
        "text": "调试通道不可用：Keil 未运行，或 UVSOCK 未开启",
        "next_actions": [
            "调 keil_health 看清断在哪一环（进程 / 端口 / 模态框）",
            "Keil 未启动则 restart_keil；已启动则确认 Edit→Configuration→Other→UVSOCK Enabled 且端口为 4823",
        ],
    },
    "keil-not-running": {
        "text": "Keil uVision 没有在运行",
        "next_actions": ["调 restart_keil 拉起 Keil 并等待 UVSOCK 就绪", "或 launch_uvision 以可见方式打开工程"],
    },
    "keil-busy": {
        "text": "Keil/UV4 被占用（工程正被另一个实例打开，或 UV4 命令行无法访问）",
        "next_actions": [
            "调 list_uvision_instances 看清有哪些实例、分别开着什么工程",
            "调 close_uvision 关闭占用实例后重试；需要保留则改在该实例里手工操作",
        ],
    },
    "uv4-not-found": {
        "text": "未定位到 UV4.exe",
        "next_actions": ["启动服务时用 --uv4-path 指定 UV4.exe 的完整路径", "确认 Keil 安装目录未被移动"],
    },
    "project-required": {
        "text": "没有指定工程，也没有可用的默认工程",
        "next_actions": ["传入 project（.uvprojx 完整路径）", "或用启动参数 --default-project 配置默认工程"],
    },
    "project-not-found": {
        "text": "工程文件不存在或打不开",
        "next_actions": [
            "核对 project 路径（可先用 read_project_config 看当前配置的工程）",
            "确认工程没有被 Keil 独占打开（close_uvision 后再试）",
        ],
    },
    "build-failed": {
        "text": "编译未通过（产物未生成或未更新）",
        "next_actions": ["读 output 里的第一条 error 行定位问题（metrics.errors 给出错误总数）",
                         "改完后重试 build_project / rebuild_project；怀疑增量残留可先 clean_project"],
    },
    "toolchain-not-ready": {
        "text": "工具链未就绪（器件包缺失 / 许可证问题 / UV4 环境异常）",
        "next_actions": ["用 Keil 打开工程手工构建一次，按弹窗提示处理", "确认对应器件的 Device Family Pack 已安装"],
    },
    "output-write-failed": {
        "text": "构建产物写入失败（输出目录只读 / 磁盘满 / 文件被占用）",
        "next_actions": ["检查 Objects/Listings 等输出目录权限与磁盘空间", "关闭占用产物文件的程序（调试器、烧录工具、hex 查看器）后重试"],
    },
    "not-debugging": {
        "text": "当前不在调试会话中，该操作需要调试态",
        "next_actions": ["先 enter_debug；若刚烧录过，注意旧会话的符号已过期", "调 get_status 确认 debugging 字段"],
    },
    "already-debugging": {
        "text": "目标已处于调试态，该操作与当前状态冲突",
        "next_actions": ["需要重新进入时先 exit_debug，或用 restart_keil 一键重置", "调 get_status 确认当前状态后再决定"],
    },
    "symbol-stale": {
        "text": "调试会话的符号已过期（编译/烧录后 .axf 已重生成，旧会话求值会报解析错误）",
        "next_actions": ["exit_debug 后重新 enter_debug 刷新符号", "或按返回值里的 symbol_stale_warning 提示处理"],
    },
    "symbol-missing": {
        "text": "缺少调试符号（未定位到 .axf 或符号表为空）",
        "next_actions": ["先编译一次生成 .axf，再用 set_symbol_file 指定", "确认工程构建输出目录里确实有 .axf"],
    },
    "breakpoint-address-unresolved": {
        "text": "断点地址不在已加载镜像内（Keil 报 error 57）",
        "next_actions": ["确认传入的是**运行地址**；裸地址需自带 Thumb 位（0x…401 这类奇数）或改用符号名", "用 find_symbol 先确认符号的地址与所在镜像段"],
    },
    "breakpoint-limit": {
        "text": "断点数量超出硬件限制（Keil 报 error 65）",
        "next_actions": ["先 clear_all_breakpoints 或删除不再需要的断点", "改用 watchpoint / 条件断点减少占用"],
    },
    "breakpoint-not-found": {
        "text": "要清除的断点不存在（Keil 报 error 72）",
        "next_actions": ["用 list_breakpoints 取真实断点编号后再清（按地址清不掉）", "若目标是数据断点，用 clear_watchpoint"],
    },
    "breakpoint-exists": {
        "text": "断点已存在（Keil 报 error 145，属幂等可忽略）",
        "next_actions": ["无需处理：断点已在位，可直接 wait_breakpoint 等待命中"],
    },
    "serial-expect-timeout-no-data": {
        "text": "串口等待超时，且期间**一个字节都没有新增**（不是 pattern 的问题）",
        "next_actions": [
            "确认这次请求真的发出去了：看返回里的 sent_hex / sent 字段（sent=false 说明只是纯等待）",
            "核对波特率与接线（TX/RX 是否交叉、GND 是否共地），并用 serial_monitor_status 看 bytes_total 是否在涨",
            "目标可能不在输出：用 serial_read(since=0) 回看缓冲区，确认它到底有没有在说话",
        ],
    },
    "serial-expect-timeout-no-match": {
        "text": "串口等待超时：期间有新增内容但对不上 pattern",
        "next_actions": [
            "把 pattern 放宽：regex=false 按字面匹配，或 case_sensitive=false 忽略大小写",
            "直接读返回的 lines（本次新增原文）当线索，据此改 pattern；必要时加大 timeout_s",
        ],
    },
    "serial-not-monitoring": {
        "text": "当前没有串口监听在运行",
        "next_actions": ["先 serial_monitor_start(port=...) 打开端口（收与发共用一个句柄）", "用 serial_list_ports 确认 COM 号"],
    },
    "serial-port-not-found": {
        "text": "未发现可用串口，或指定的串口不存在",
        "next_actions": ["调 serial_list_ports 看本机串口与芯片推断（确认 USB-TTL 插好、驱动已装）", "确认波特率无关：口不存在是设备/驱动问题"],
    },
    "serial-port-busy": {
        "text": "串口被其他程序占用（打开失败，WinError=5）",
        "next_actions": ["关闭 Keil 的串口窗口 / 其他串口工具（同一时刻只能一个进程持有）", "若占用者是本服务，reopen_count 会自动重连，稍后重试即可"],
    },
    "timeout": {
        "text": "操作超时",
        "next_actions": ["调 keil_health 看 Keil 侧是否被模态框阻塞 / 端口是否还在监听", "确认目标是否在运行、命令是否本就耗时较长（可调大超时参数）"],
    },
    "invalid-argument": {
        "text": "参数不合法或缺失",
        "next_actions": ["用 list_tools(keyword=...) 查该工具的参数签名与最小调用示例 example_args", "参数名/类型都做了容忍，仍报错请按规范名传参"],
    },
    "halt-dirty-pc": {
        "text": "刚停止时读到的是脏值（PC 未收敛）",
        "next_actions": ["稍等片刻重读一次（工具已默认做读数收敛判定）", "确认看门狗冻结位已置位，避免 halt 期间被复位"],
    },
    "unknown-error": {
        "text": "未归类的失败",
        "next_actions": ["调 keil_health 看 Keil 侧状态", "用 read_async_messages 读 Keil 的异步报错原文"],
    },
}

# 分类规则：按顺序匹配，先具体后笼统
_RULES = (
    (r"未定位到 UV4|UV4\.exe.*(不存在|找不到)|找不到 UV4", "uv4-not-found"),
    # 「正则编译失败」含「编译失败」子串，必须先于 build-failed 规则，否则会被误判成编译挂了
    (r"正则编译失败|正则.*(无效|不合法)|pattern.*(无效|不合法)", "invalid-argument"),
    (r"一个字节都没有新增", "serial-expect-timeout-no-data"),
    (r"行但都不匹配", "serial-expect-timeout-no-match"),
    (r"没有串口监听在运行", "serial-not-monitoring"),
    (r"本机未发现任何串口|未发现任何串口", "serial-port-not-found"),
    (r"不在本机串口列表中", "serial-port-not-found"),
    (r"WinError\s*=?\s*5\b|拒绝访问|被别的程序占用|已被占用|端口被占用|被占用", "serial-port-busy"),
    (r"symbol_stale|符号.*过期|status\s*13", "symbol-stale"),
    (r"未定位到 \.axf|符号文件不可用|符号表为空", "symbol-missing"),
    (r"error\s*57", "breakpoint-address-unresolved"),
    (r"error\s*65", "breakpoint-limit"),
    (r"error\s*72", "breakpoint-not-found"),
    (r"error\s*145", "breakpoint-exists"),
    (r"未指定工程路径|未指定工程|没有可用的默认工程", "project-required"),
    (r"工程.*(不存在|找不到|打不开)|无法打开工程", "project-not-found"),
    (r"编译未通过|编译失败|构建失败|build\s*(failed|error)", "build-failed"),
    (r"设备数据库|器件库|Device Family Pack", "toolchain-not-ready"),
    (r"写入错误|只读|磁盘空间", "output-write-failed"),
    (r"UV4 访问错误|已有实例占用", "keil-busy"),
    (r"已处于调试|已在调试态|调试会话已存在", "already-debugging"),
    (r"未进入调试|不在调试|需要调试态|not in debug", "not-debugging"),
    (r"超时|timeout", "timeout"),
    (r"未检测到 Keil|Keil 未运行|未运行|UVSOCK|4823|无法连接|连接失败|Connection refused",
     "uvsock-unavailable"),
    (r"参数|Field required|缺少|不能为空|参数不足", "invalid-argument"),
)

_COMPILED = tuple((re.compile(p, re.IGNORECASE), c) for p, c in _RULES)

# 归拢成 next_actions 的字段名（note 是叙述性说明，不是动作，故排除）
_HINT_KEYS = ("hint", "suggestion", "next_step", "eol_hint", "no_echo_hint",
              "port_choice_hint", "hint_1", "hint_2")
_HINT_SUFFIX = "_hint"


def classify_error(text: str) -> str:
    """从报错文本推断字符串错误码。无法归类返回 unknown-error。"""
    t = str(text or "")
    if not t.strip():
        return "unknown-error"
    for rx, code in _COMPILED:
        if rx.search(t):
            return code
    return "unknown-error"


def _classify_structured(obj: dict) -> str:
    """从工具返回的结构化标识直接定码——比从中文文本猜准得多。

    没有这一步时，serial_expect 超时的结果（只有 timeout/timeout_kind，没有 error 文本）
    会落进 unknown-error，next_actions 指向 keil_health，方向完全不对（真机实测踩到）。
    """
    if obj.get("timeout") is True and "timeout_kind" in obj:
        return ("serial-expect-timeout-no-data" if obj.get("timeout_kind") == "no-data"
                else "serial-expect-timeout-no-match")
    return ""

def _status_of(obj: dict) -> str:
    ok = obj.get("ok")
    if isinstance(ok, str):
        low = ok.strip().lower()
        if low in ("ok", "true", "yes"):
            return "ok"
        if low in ("conflict", "partial", "warn", "warning"):
            return "warn"
        return "error"
    if ok is None:
        # 没有 ok 字段的工具：有 error 判失败，否则按成功
        return "error" if obj.get("error") else "ok"
    return "ok" if ok else "error"


def _collect_hints(obj: dict) -> list:
    out = []
    for k, v in obj.items():
        if not isinstance(v, str) or not v.strip():
            continue
        if k in _HINT_KEYS or k.endswith(_HINT_SUFFIX):
            out.append(v.strip())
    return out


def _error_text(obj: dict) -> str:
    parts = []
    # note 只在失败路径被调用，此时它写的就是诊断正文（如「一个字节都没有新增」）
    for k in ("error", "error_hint", "status_text", "exit_code_text",
              "exit_code_meaning", "warning", "last_error", "symbol_stale_note", "note"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v)
    return " | ".join(parts)


def normalize(tool_name: str, obj: dict) -> dict:
    """给单个工具结果补统一信封。纯函数，不改动既有字段。"""
    if not isinstance(obj, dict):
        return obj
    out = dict(obj)
    status = _status_of(out)
    out["status"] = status

    if status == "error":
        # 工具自己给的 error_code 优先（比从文本猜的更准），没有才按文本归类
        code = (out.get("error_code") or _classify_structured(out)
                or classify_error(_error_text(out)))
        out["error_code"] = code
        info = ERROR_CODES.get(code)
        if info and not out.get("error_hint"):
            out["error_hint"] = info["text"]

    acts = []
    existing = out.get("next_actions")
    if isinstance(existing, (list, tuple)):
        acts.extend([str(x) for x in existing if str(x).strip()])
    elif isinstance(existing, str) and existing.strip():
        acts.append(existing.strip())
    acts.extend(_collect_hints(out))
    if status == "error":
        code = out.get("error_code")
        info = ERROR_CODES.get(code) if code else None
        if info:
            acts.extend(info["next_actions"])
    # 去重保序；并剔除与 error / error_hint 原文重复的项（它们本身不是「动作」）
    seen = set(x for x in (out.get("error"), out.get("error_hint")) if isinstance(x, str))
    final = []
    for a in acts:
        if a not in seen:
            seen.add(a)
            final.append(a)
    if final:
        out["next_actions"] = final

    risk = "high" if tool_name in RISK_HIGH else (
        "medium" if tool_name in RISK_MEDIUM else None)
    if risk:
        out["risk"] = risk
        out["reversible"] = risk != "high"
    return out


def apply_to_result(tool_name: str, result):
    """把信封作用到 MCP 的 CallToolResult 上（就地改 text 与 structured_content）。"""
    content = getattr(result, "content", None)
    if not content:
        return result
    item = content[0]
    text = getattr(item, "text", None)
    if not isinstance(text, str) or not text.lstrip().startswith(("{", "[")):
        return result
    import json
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return result
    if not isinstance(obj, dict):
        return result
    new = normalize(tool_name, obj)
    if new == obj:
        return result
    new_text = json.dumps(new, ensure_ascii=False, default=str)
    try:
        item.text = new_text
    except Exception:  # noqa: BLE001
        try:
            content[0] = type(item)(type="text", text=new_text)
        except Exception as e:  # noqa: BLE001
            logger.debug("信封回写失败（%s）：%s", tool_name, e)
            return result
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        for k, v in list(sc.items()):
            if isinstance(v, str) and v.strip() == text.strip():
                sc[k] = new_text
    return result
