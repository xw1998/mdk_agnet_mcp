# -*- coding: utf-8 -*-
"""Keil 报错知识库：命令窗口 error 码 + ARM 编译诊断 -> 含义 / 常见原因 / 处置。

来源与口径（重要）
------------------
- **命令窗口 error 码**：Keil 调试命令（BS/BK/EVAL/…）失败时并不全是 UVSOCK 层错误，
  很多只在命令窗口回一行 ``*** error N: message``。Keil 官方手册**没有**公开完整码表，
  故本表**只收录 mdkdebug 真机实测过的码**（docs/PITFALLS.md 有实验记录），
  未收录的码一律不做猜测——只回原始 message，并明确告知"本码未实测收录"。
- **编译诊断码**：ARMCC5 / ARMCLANG 报 ``#20: identifier "x" is undefined`` 这类带
  ``#N`` 的诊断号。同号在 AC5/AC6 下语义一致但措辞不同，且很多诊断**无稳定 code**
  （AC6 更偏纯文本）。故本模块的匹配策略是：**文本模式优先，码号兜底**——
  先用已收录的文本特征（中英措辞）命中，再退回按码号查表。
- 所有解释都带 ``confidence`` 字段：``high``=真机实测或官方手册明载；
  ``medium``=编译器常见诊断；``unknown``=未收录，只给通用排查路径。**不编造原因。**
"""
from __future__ import annotations

import re

# ----------------------------------------------------------------------
# 一、Keil 命令窗口 error 码（全部来自真机实测）
# ----------------------------------------------------------------------
_DEBUG_CMD_ERRORS = {
    34: {
        "meaning": "undefined identifier（未定义的标识符）",
        "cause": "把命令当表达式解析时找不到这个名字。典型：用了不存在的缩写命令"
                 "（如 `Step`/`Tstep`/`Pstep`，正确缩写是 `T`/`P`/`O`），"
                 "或引用了当前作用域/符号表里没有的变量名。",
        "fix": ["单步用缩写 `T`（step in）/ `P`（step over）/ `O`（step out），不要写 `Step`",
                "求值变量前先确认它存在：find_symbol 或在 read_locals 的返回里点名",
                "代码区下断点用符号名，数据区观察用 watchpoint"],
        "confidence": "high",
    },
    57: {
        "meaning": "illegal address（非法地址）",
        "cause": "Keil 认为该地址不能下断点。真机最常见根因是 **Thumb 位**："
                 "`&func | 1` 得到的奇数地址（如 0x08000DB5）一律被拒；"
                 "另可能是地址不在已加载镜像内、或落在无代码的区段。",
        "fix": ["函数地址清掉 bit0 再用（符号路径经 calc_expression 拿到的本就是偶地址）",
                "确认传的是**运行地址**：App 重定位场景先 set_reloc_delta",
                "用 find_symbol 核对符号地址与所在镜像段",
                "确认镜像与符号一致（编译/烧录后旧会话符号已过期，需重进调试）"],
        "confidence": "high",
    },
    65: {
        "meaning": "断点数量超出硬件限制",
        "cause": "Cortex-M 的 FPB 硬件断点单元有限（通常 4~6 个），"
                 "数据观察点与指令断点共用，超限即报错。",
        "fix": ["clear_all_breakpoints 后重建，或改用条件断点/单点复用的策略",
                "用 list_breakpoints 看当前真实占用了几个（含 .uvoptx 持久化的）",
                "数据观察点很贵：能用一次性的 snapshot_diff 代替就别常驻 watchpoint"],
        "confidence": "high",
    },
    72: {
        "meaning": "invalid item number（条目编号无效）",
        "cause": "按**地址**清除断点/观察点，而 Keil 的 BK 只认**断点编号**；"
                 "或编号已被清除（重复清除）。",
        "fix": ["先 list_breakpoints 拿 Keil 编号，再 BK <编号>",
                "数据观察点必须按编号清（clear_watchpoint 已内置该逻辑）"],
        "confidence": "high",
    },
    145: {
        "meaning": "断点已存在（幂等，可忽略）",
        "cause": "同一位置重复下断点。",
        "fix": ["无需处理：断点已在位，直接 wait_breakpoint 等命中即可"],
        "confidence": "high",
    },
}

# ----------------------------------------------------------------------
# 二、编译诊断：文本特征优先（AC5/AC6 共用），码号兜底
# ----------------------------------------------------------------------
# 每条：(正则, 含义, 常见原因, [处置], 对应的 AC5 诊断号或 None)
_TEXT_RULES = [
    (r"identifier\s+\"?([^\"\n]+)\"?\s+is\s+undefined|use of undeclared identifier",
     "标识符未定义",
     "名字拼错、忘了 #include 对应头文件、变量作用域不对、或对应的 .c 没加进工程分组",
     ["核对拼写与大小写", "确认声明所在头文件已 #include（且该头文件确实在 Include Paths 里）",
      "确认定义所在 .c 已加入工程（否则链接期才报未定义）",
      "C99 下变量必须在块首声明，混用会连带报错"],
     20),
    (r"expected\s+a\s*[\"']?[;)]|expected\s+[\"']?(?:;|\)|,)",
     "语法错：缺少分号/右括号/逗号",
     "上一行漏分号；宏展开后括号不配对；中文标点混入（；／，／（））",
     ["看报错行的**上一行**末尾是否漏分号", "检查宏定义里的括号配对",
      "把中文标点替换成半角（这类错最难肉眼发现）"],
     65),
    (r"cannot\s+open\s+(?:source\s+)?input\s+file|No such file or directory|"
     r"cannot\s+find\s+file",
     "找不到源文件/头文件",
     "文件被移动或删除、Include Paths 没配、相对路径写错、路径含中文或空格",
     ["确认文件路径真实存在（注意大小写，Linux 下编译更敏感）",
      "在 Options for Target → C/C++ → Include Paths 里补上目录（可用 edit_project 工具）",
      "路径尽量用 ASCII，避免中文与空格"],
     5),
    (r"#error\s+directive|error directive:",
     "#error 指令被触发",
     "源码里的守卫条件不满足（常见：芯片宏没定义、HAL 配置不一致、条件编译走错分支）",
     ["看 #error 后面的自定义提示文字，它通常直接说明缺什么宏",
      "核对工程 target 的 Define 是否与板子一致（read_project_config 可对比不同 target）"],
     35),
    (r"incompatible\s+redefinition\s+of\s+macro|macro\s+redefined",
     "宏重复定义且不一致",
     "同一宏在头文件与工程 Define 里各定义一次且值不同（如 SVCRT_BOARD_CONFIG）",
     ["统一到一个来源：要么删头文件里的，要么删 Options 里的 Define",
      "临时遮蔽用 #undef 后再定义"],
     47),
    (r"has\s+already\s+been\s+declared|redefinition\s+of|"
     r"previous\s+definition\s+is\s+here",
     "重复声明/重定义",
     "变量或函数在头文件里**带定义**（应为 extern），或头文件缺 include guard 被多次包含",
     ["头文件里只放声明，定义放 .c；确实要在头文件定义就加 static 或 inline",
      "给头文件加 #ifndef / #pragma once"],
     101),
    (r"was\s+referenced\s+but\s+not\s+defined|undefined\s+(?:reference|symbol)|"
     r"Undefined symbol",
     "符号未定义（链接期常见）",
     "函数只声明未实现、实现所在的 .c 没加进工程、库没加（HAL 的 .c 常常忘加）、"
     "C/C++ 混用时缺 extern \"C\"",
     ["把实现所在的 .c 加入工程分组（CubeMX 新外设最容易漏这步）",
      "确认用到的 HAL 模块 .c 已进工程（如 stm32f4xx_hal_uart.c）",
      "链接报错看 parse_map 的未使用 section 与符号表"],
     None),
    (r"declaration\s+may\s+not\s+appear\s+after\s+executable\s+statement",
     "C89/C90 限制：声明必须出现在语句之前",
     "AC5 默认 C90 风格，块中间混写声明与语句会报错",
     ["把声明上移到块首；或改用 C99 模式（Options for Target → C/C++ → C99 Mode）"],
     268),
    (r"no\s+member\s+named\s+[\"']?([^\"'\n]+)|"
     r"has\s+no\s+member\s+[\"']?([^\"'\n]+)|"
     r"struct\s+[\"']?([^\"'\n]+)[\"']?\s+has\s+no\s+field",
     "结构体/联合体没有该成员",
     "成员名拼错、结构体定义与使用处的版本不一致、用错了结构体类型",
     ["跳到头文件核对成员名（read_struct 可看 DWARF 里的真实布局）",
      "确认使用处包含的是同一份头文件"],
     None),
    (r"too\s+(?:few|many)\s+arguments|not\s+enough\s+arguments|"
     r"argument\s+of\s+type\s+[\"']?([^\"'\n]+)[\"']?\s+is\s+incompatible",
     "函数调用实参不匹配",
     "原型改了但调用处没跟着改；参数类型不兼容（指针/整型混用、缺强制转换）",
     ["用 find_symbol 定位函数后核对原型", "指针与整型互转要显式强转"],
     None),
    (r"interrupt\s+handler|__vector_table|SysTick_Handler.*redefin",
     "中断向量/中断函数相关编译错",
     "启动文件与向量表重复定义中断函数，或函数名与向量表不符",
     ["确认中断函数名与 startup_xxx.s 向量表完全一致",
      "不要在 C 里重复定义启动文件已提供的 handler（weak 符号只能覆盖一次）"],
     None),
]

# AC5 诊断号 -> 文本规则的兜底（仅收录有把握的码）
_BUILD_CODE_HINTS = {
    5: "cannot open source input file（找不到源文件/头文件）",
    18: "expected a \")\"（括号不配对）",
    20: "identifier \"x\" is undefined（标识符未定义）",
    35: "#error directive 被触发",
    47: "incompatible redefinition of macro（宏重复定义）",
    65: "expected a \";\"（缺少分号）",
    101: "\"x\" has already been declared（重复声明/重定义）",
    114: "function \"x\" was referenced but not defined（被引用但未定义）",
    167: "argument 类型与形参不兼容",
    188: "enumerated type mixed with another type（枚举与其它类型混用）",
    268: "declaration may not appear after executable statement in block",
}

_CODE_RE = re.compile(r"#(\d+)\s*:")
_ANSI_STRIP = re.compile(r"\x1b\[[0-9;]*m")

def _clean(s: str) -> str:
    return _ANSI_STRIP.sub("", (s or "").strip())

def explain_build_error(text: str = "", code=None) -> dict:
    """解读一条编译错误/警告：返回 {ok, matched, ...}。

    text 传一行或多行原始诊断（如 ``../Core/Src/main.c(120): error: #20: identifier "x" is undefined``）；
    code 可直接传数字诊断号。匹配策略：文本特征优先 → 码号兜底 → 都没命中则 unknown。
    """
    raw = _clean(text)
    item = None
    if raw:
        for pat, meaning, cause, fix, cnum in _TEXT_RULES:
            m = re.search(pat, raw, re.I)
            if not m:
                continue
            item = {"meaning": meaning, "cause": cause, "fix": list(fix),
                    "code": cnum, "confidence": "medium",
                    "matched_text": (m.group(0) or "").strip()[:120]}
            break
    num = None
    if item is None:
        if code is not None:
            try:
                num = int(code)
            except (TypeError, ValueError):
                num = None
        if num is None and raw:
            m = _CODE_RE.search(raw)
            if m:
                num = int(m.group(1))
        if num is not None and num in _BUILD_CODE_HINTS:
            item = {"meaning": _BUILD_CODE_HINTS[num], "cause": None, "fix": [],
                    "code": num, "confidence": "medium",
                    "matched_text": "#%d" % num}
    if item is None:
        return {"ok": True, "matched": False, "confidence": "unknown",
                "code": num, "raw": raw or None,
                "note": "未收录该诊断（本知识库只收真机实测过的命令错误码与常见编译诊断，"
                        "不做猜测）。请结合原始 message 与出错行上下文判断："
                        "先看报错行**上一行**是否有遗漏（漏分号/漏闭括号最常在这），"
                        "再确认头文件与工程分组是否齐全。",
                "generic_fix": ["读原始 message 的**关键词**而不是整句：它通常直接指出缺什么",
                                "看报错行的上一行（语法错经常迟报一行）",
                                "确认报错文件是否真的在编译（工程分组/Include Paths）",
                                "编译前先 clean 一次，排除陈旧 .o/.d 干扰"]}
    item["ok"] = True
    item["matched"] = True
    item["raw"] = raw or None
    if not item.get("cause"):
        item["cause"] = "见原始 message（该诊断无稳定单一成因，需结合出错行上下文）"
    return item

def explain_command_error(text: str = "", code=None) -> dict:
    """解读一条 Keil **命令窗口**报错（``*** error N: message``）。

    code 可单独给。表内条目全部来自真机实测；未收录的码**只回原 message 不猜原因**。
    """
    raw = _clean(text)
    num = None
    if code is not None:
        try:
            num = int(code)
        except (TypeError, ValueError):
            num = None
    if num is None and raw:
        m = re.search(r"error\s+(\d+)", raw, re.I)
        if m:
            num = int(m.group(1))
    msg = raw
    m = re.search(r"\*\*\*\s*error\s+\d+\s*[:,]?\s*(.*)$", raw, re.I)
    if m and m.group(1).strip():
        msg = m.group(1).strip()
    ent = _DEBUG_CMD_ERRORS.get(num)
    if ent is None:
        return {"ok": True, "matched": False, "confidence": "unknown", "code": num,
                "message": msg or None,
                "note": "该命令错误码未收录（码表只收真机实测过的条目，不做猜测）。"
                        "通用排查：确认命令拼写是**官方缩写**（单步是 T/P/O，不是 Step）、"
                        "参数是运行地址而非文件偏移、目标处于暂停态、"
                        "并先用 list_breakpoints 看真实断点表而不是凭记忆。",
                "generic_fix": ["核对命令缩写与语法（官方 Debug Commands 章节）",
                                "确认目标已 halt（运行中很多命令不可用）",
                                "确认镜像与符号一致（重编译后需重进调试）"]}
    return {"ok": True, "matched": True, "confidence": ent["confidence"], "code": num,
            "message": msg or None, "meaning": ent["meaning"],
            "cause": ent["cause"], "fix": list(ent["fix"])}

def known_debug_codes() -> list:
    """返回已收录的命令错误码（升序），供工具自述用。"""
    return sorted(_DEBUG_CMD_ERRORS)
