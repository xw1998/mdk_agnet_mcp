# -*- coding: utf-8 -*-
"""固件恢复的闭环台账（批次88，吸收 REA obligation-ledger / coverage 的 fail-closed 口径）。

`recover_project_exact` + `recover_verify` 已经能证明「重链接出来的字节和原镜像一样」，
但**一句话的 verdict 不够用**：调用方真正要知道的是

    「这份『恢复好的工程』到底有哪些义务已经被证据闭合了，哪些还开着，为什么。」

REA 的三本台账（readiness / coverage / obligation-ledger）讲的是同一件事：
把结论拆成**具名义务**，每条义务要求**特定强度的证据**，只有「证据强度 ≥ 要求」
且证据本身通过，才算闭合；`unknown` / `unsupported` **永远不聚合为 pass**。

本模块只做这一件事：`evaluate(facts)` + `collect_facts(...)` + `ready` 判定。
零第三方依赖（只用 hashlib/json）。

证据强度（`authority`）从低到高：

    unsupported < unknown < derived < observed

- `observed`：这份文件/这次命令**真的量到了**（字节比对、符号表读数、工具链实跑）；
- `derived`：由观察到的事实**推出来**的（比如「布局一致」由字节一致推出来）；
- `unknown`：**判不了**（缺输入、缺硬件、缺窗口）；
- `unsupported`：这套输入/工具**根本做不到**（比如从机器码恢复 C 类型名）。

「判不了」与「做不到」都必须如实说，不能当成 `pass`，也不能当成 `fail`——
把 unknown 当 fail 会让所有诚实的结论都变成噪音，把 unknown 当 pass 会把猜测卖成事实。
"""
import hashlib
import json

LEDGER_VERSION = 1

# 证据强度排序（大者更强）
AUTHORITY_RANK = {"unsupported": 0, "unknown": 1, "derived": 2, "observed": 3}

# 义务状态：只有 closed 算闭合
STATUS_CLOSED = "closed"
STATUS_OPEN = "open"
STATUS_FAILED = "failed"
STATUS_UNKNOWN = "unknown"
STATUS_UNSUPPORTED = "unsupported"

# 固件恢复的核心义务清单。`requires` 是**闭合所需的最低证据强度**。
OBLIGATIONS = [
    {
        "id": "artifact.identity",
        "title": "被恢复的那份镜像有身份且本次比的是同一份",
        "requires": "observed",
        "required": True,
        "why": "结论必须挂在 path+size+SHA-256 上；输入换了，所有结论作废",
    },
    {
        "id": "build.toolchain",
        "title": "生成的工程能被真工具链编译链接",
        "requires": "observed",
        "required": True,
        "why": "「能打开」不等于「能编译」；没编过就不能说恢复成功",
    },
    {
        "id": "bytes.loadable",
        "title": "重链接产物与原镜像的可加载字节逐字节一致",
        "requires": "observed",
        "required": True,
        "why": "这是工程级恢复的判据本身：地址、布局、内容全对才算复刻",
    },
    {
        "id": "vector.entry",
        "title": "向量表与复位地址取自原镜像（不是推断出来的）",
        "requires": "observed",
        "required": True,
        "why": "复位地址错一位就是另一个程序；这条不能靠推导",
    },
    {
        "id": "symbols.addresses",
        "title": "函数/符号地址集合与原文对得上",
        "requires": "observed",
        "required": False,
        "why": "剥离符号的固件没有符号表可比：这条对这类输入是 unknown 而不是通过",
    },
    {
        "id": "layout.regions",
        "title": "区域划分与装载地址与原镜像一致",
        "requires": "derived",
        "required": True,
        "why": "字节一致即可推出布局一致（两者是同一份 bin 的两种读法）",
    },
    {
        "id": "runtime.bootable",
        "title": "恢复的工程在目标板上跑起来",
        "requires": "observed",
        "required": False,
        "why": "本工具不接硬件就没有这条证据；要说「能跑」得另有一次上板观察",
    },
    {
        "id": "c.semantics",
        "title": "C 语义（类型、结构体、局部变量名、宏、注释）",
        "requires": "observed",
        "required": False,
        "why": "优化会把这些擦除，输入里根本没有这段信息——永远 unsupported，不是「还没做」",
    },
]

OBLIGATION_BY_ID = {o["id"]: o for o in OBLIGATIONS}

RULES = [
    "义务只有『证据强度 ≥ 要求』且证据本身通过时才算闭合（closed）；"
    "derived 证据不能闭合要求 observed 的义务",
    "unknown / unsupported 永远不聚合为 ready：判不了就说判不了，做不到就说做不到",
    "required=true 的任一义务没有闭合，ledger.ready 就是 false（不被其它义务的数量冲淡）",
    "缺失证据一律是 open 并附 required_next_evidence，不当成 failed（fail 需要观察到反证）",
    "closure_digest 只由义务与状态决定：同样的证据重算一次得到同一个值（可复算、可比对）",
    "任何一条 failed（含 required=false）都会让 ready=false：观察到反证不能靠数量摊平",
]


def _fact(value, authority, source, note=""):
    return {"value": value, "authority": authority, "source": source, "note": note}


def _status_for(ob, fact):
    """单条义务的状态判定（fail-closed）。"""
    need = ob.get("requires") or "observed"
    if fact is None:
        return STATUS_OPEN, "没有这条证据", need
    auth = fact.get("authority") or "unknown"
    if auth == "unsupported":
        return STATUS_UNSUPPORTED, fact.get("note") or "输入/工具做不到这件事", need
    if auth == "unknown":
        return STATUS_UNKNOWN, fact.get("note") or "判不了（缺输入或缺窗口）", need
    value = fact.get("value")
    ok = value if isinstance(value, bool) else bool(value)
    if not ok:
        # 观察到反证才算 failed；derived 反证只能算 open
        if auth == "observed":
            return STATUS_FAILED, fact.get("note") or "证据显示不一致", need
        return STATUS_OPEN, "只有推导级反证，不足以判失败：" + (fact.get("note") or ""), need
    if AUTHORITY_RANK.get(auth, 0) < AUTHORITY_RANK.get(need, 3):
        return (STATUS_OPEN,
                "证据强度 %s 低于该义务要求的 %s（推导不能替代观察）" % (auth, need), need)
    return STATUS_CLOSED, fact.get("note") or "证据强度 %s ≥ 要求 %s" % (auth, need), need


def evaluate(facts, *, include_optional_in_summary=True) -> dict:
    """按义务清单评估一份证据集合，给出 fail-closed 的闭环结论。

    ``facts``：``{obligation_id: {"value": bool, "authority": "observed",
    "source": "…", "note": "…"}}``。没给到的义务视为**没有证据**（open）。
    """
    facts = facts or {}
    rows, required_open = [], []
    for ob in OBLIGATIONS:
        fact = facts.get(ob["id"])
        status, reason, need = _status_for(ob, fact)
        row = {
            "obligation_id": ob["id"],
            "title": ob["title"],
            "required": bool(ob["required"]),
            "requires_authority": need,
            "status": status,
            "reason": reason,
            "evidence": (None if fact is None else {
                "value": fact.get("value"),
                "authority": fact.get("authority"),
                "source": fact.get("source"),
            }),
        }
        if status in (STATUS_OPEN, STATUS_UNKNOWN, STATUS_UNSUPPORTED) and ob["required"]:
            required_open.append(ob["id"])
        if fact is None:
            row["required_next_evidence"] = {
                "artifact.identity": "传 image= 原镜像（或确认 manifest 里记的 sha256 就是它）",
                "build.toolchain": "把 arm_bin 指到 Keil 的 armasm/armlink 目录，或用 via_uvprojx",
                "bytes.loadable": "跑 recover_verify（必须带 image=），或给一份已保存的 verify JSON",
                "vector.entry": "传 image= 原镜像（本层要读它 base 处的前两个字），"
                                "或给 RAM/Flash 窗口让判据完整",
                "symbols.addresses": "可选义务：给一份独立来源的符号清单（原工程 map/axf）才能比",
                "layout.regions": "随 bytes.loadable 一起得到（字节一致即布局一致）",
                "runtime.bootable": "接探针：flash_download 后跑一次并留 trace 证据",
                "c.semantics": "没有输入能提供它（优化已擦除）；不要为它等证据",
            }.get(ob["id"], "按 reason 补证据")
        rows.append(row)

    required_rows = [r for r in rows if r["required"]]
    counts = {}
    for r in (rows if include_optional_in_summary else required_rows):
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    required_closed = [r for r in required_rows if r["status"] == STATUS_CLOSED]
    ready = (len(required_closed) == len(required_rows)
             and not any(r["status"] == STATUS_FAILED for r in rows))
    summary = {
        "ready": ready,
        "required_total": len(required_rows),
        "required_closed": len(required_closed),
        "closed": counts.get(STATUS_CLOSED, 0),
        "open": counts.get(STATUS_OPEN, 0),
        "failed": counts.get(STATUS_FAILED, 0),
        "unknown": counts.get(STATUS_UNKNOWN, 0),
        "unsupported": counts.get(STATUS_UNSUPPORTED, 0),
        "blocking_obligations": [r["obligation_id"] for r in required_rows
                                 if r["status"] != STATUS_CLOSED],
    }
    parts = ["%s=%s" % (r["obligation_id"], r["status"]) for r in rows]
    digest = hashlib.sha256(("%d|%s" % (LEDGER_VERSION, "|".join(parts))).encode("utf-8")
                            ).hexdigest()
    out = {
        "ok": True,
        "version": LEDGER_VERSION,
        "ledger_id": "closure-" + digest[:16],
        "closure_digest": digest,
        "summary": summary,
        "obligations": rows,
        "rules": list(RULES),
        "verdict": ("required 义务全部被证据闭合" if ready else
                    "**没有闭合**：%s" % "、".join(summary["blocking_obligations"])),
        "limitations": [
            "台账只覆盖上面列出的义务；这份清单就是「什么才算恢复成功」的定义，"
            "不在清单里的能力（例如中断优先级、外设初始化顺序）没有任何证据",
            "ready=true 只说明**这份固件**的字节/布局/工具链链路闭合，不说明它能跑、"
            "也不说明它是好固件",
            "evidence 的 authority 由采集它的工具判定；本层不做二次取证，只做一致性聚合",
        ],
    }
    return out


# ----------------------------------------------------------------------
# 从 recover_verify 的事实里收集证据
# ----------------------------------------------------------------------
def facts_from_verify(verify: dict, *, manifest: dict | None = None) -> dict:
    """把 ``recover_verify`` 的输出翻译成证据集合（不新增取证，只做映射）。

    映射规则全部写明，因为「哪些结论能当观察」是这条链最容易被放宽的地方：
      - 工具链实跑且产物存在 → ``build.toolchain`` observed；
      - ``byte_identical`` → ``bytes.loadable`` observed（这是真的比过字节）；
        为真时顺带把 ``layout.regions`` 记成 derived（同一份 bin 的两种读法）；
      - 没有期望字节（无 image）→ ``bytes.loadable`` **无证据**（open），绝不记 unknown 当通过。
    """
    facts = {}
    # 这两条与输入/工具链无关，恒有结论：
    #   机器码里没有 C 语义（unsupported，不是「还没做」）；
    #   没接硬件就没有上板证据（unknown，不是「通过」）。
    facts["c.semantics"] = _fact(False, "unsupported", "机器码不含类型/宏/变量名",
                                 "不是「还没做」，是输入里没有这段信息")
    facts["runtime.bootable"] = _fact(False, "unknown", "本次没有上板观察",
                                      "要说「能跑」需要 flash_download 后的一次真机 trace")
    if not verify:
        facts.setdefault("symbols.addresses", _fact(
            False, "unknown", "本次没有独立的符号原文可比",
            "可选义务：recover_project_exact 的符号是对同一份输入分析出的地址常量，"
            "与之一并比较属循环论证；stripped 固件更无从比。不闭合也不阻塞 ready"))
        return facts
    steps = verify.get("steps") or []
    built = bool(verify.get("build", {}).get("bin")) and any(
        s.get("ok") for s in steps if s.get("step"))
    toolchain_ran = any("armasm" in (s.get("step") or "") or "link" in (s.get("step") or "")
                        or "UV4" in (s.get("step") or "") for s in steps)
    if verify.get("failed_step") in ("keil_build", "armasm", "armlink"):
        facts["build.toolchain"] = _fact(False, "observed",
                                        "recover_verify 的 %s 步骤" % verify["failed_step"],
                                        "工具链报错（看 verify.steps 的 stderr）")
    elif built and toolchain_ran:
        facts["build.toolchain"] = _fact(True, "observed",
                                        "recover_verify：armasm/armlink（或 UV4）+ fromelf 产物存在")

    diff = verify.get("diff") or {}
    ident = diff.get("byte_identical")
    if ident is True:
        extra = ("（含 %d 字节对齐填充说明）" % diff["alignment_padding"]
                 if diff.get("alignment_padding") else "")
        facts["bytes.loadable"] = _fact(True, "observed",
                                        verify.get("expected_source") or "recover_verify",
                                        "逐字节相同" + extra)
        facts["layout.regions"] = _fact(True, "derived",
                                        "由 bytes.loadable 推出",
                                        "同一份 bin 的两种读法：字节一致 ⇒ 布局一致")
    elif ident is False:
        facts["bytes.loadable"] = _fact(False, "observed",
                                        verify.get("expected_source") or "recover_verify",
                                        "第一处差异在 bin 偏移 0x%X"
                                        % ((diff.get("diff_offsets") or [0])[0]))
    elif ident is None:
        facts["bytes.loadable"] = None   # 无期望字节：没有证据，不是「一致」

    exp = verify.get("expected") or {}
    if exp.get("sha256"):
        facts["artifact.identity"] = _fact(
            True, "observed", "recover_verify 的 expected.sha256",
            "本次比的就是 manifest 记的那一份" if exp.get("manifest_match") is not False
            else "⚠ manifest 记的输入与本次 image 不是同一份")
        if exp.get("manifest_match") is False:
            facts["artifact.identity"] = _fact(
                False, "observed", "expected.manifest_match=false",
                "传入的 image 与 manifest 的 concat_sha256 不符：结论要按新的那份重算")
    # 注意：manifest.json 里**没有**符号表/向量表字段——不要凭想象去取键。
    # 向量表证据必须由字节本身给出（见 recover.build_closure_ledger 的
    # `_vector_entry_fact`：读原镜像 base 处的前两个字并过 image.check_vector_table）；
    # 符号集合证据这里恒为 unknown：recover_project_exact 的符号是**对同一份输入**
    # 分析出来的地址常量，拿它跟同一份输入的符号表比是循环论证，不能当独立证据。
    facts.setdefault("symbols.addresses", _fact(
        False, "unknown", "本次没有独立的符号原文可比",
        "可选义务：recover_project_exact 的符号是对同一份输入分析出的地址常量，"
        "与之一并比较属循环论证；stripped 固件更无从比。不闭合也不阻塞 ready"))
    return facts


def canonical_digest(ledger: dict) -> str:
    """对整份台账做一次规范序列化后的 SHA-256（可复算、可比对）。"""
    lean = {"version": ledger.get("version"),
            "summary": {k: v for k, v in (ledger.get("summary") or {}).items()
                        if k != "blocking_obligations"},
            "obligations": [[o.get("obligation_id"), o.get("status")]
                            for o in ledger.get("obligations") or []]}
    blob = json.dumps(lean, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
