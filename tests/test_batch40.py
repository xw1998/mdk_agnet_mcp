# -*- coding: utf-8 -*-
"""批次40-41 mock 测试：RTOS 任务感知（FreeRTOS）。

来源：用户贴的「还差哪些功能（按价值排序）」里 ★★★ 第一条——`mdk_guide` 只探测
RTOS 类型，没有任务列表/栈水位/队列状态，而多任务卡死排查是高频刚需。

真机证据（F401 + DAPLink，example_gcc_project/freertos_probe，2026-09-18）：
  8 个任务全部列出（count==kernel_count==8，mismatch=False）；
  6 个任务的主机侧 stack_free_words 与固件里内核自报的 uxTaskGetStackHighWaterMark
  **逐项一致**（105/62/97/71/103/223）；portMAX_DELAY 阻塞的任务被从真挂起里分出来
  （靠 xEventListItem.pxContainer）；队列注册表 3 个对象名字/长度/单条大小全对。

本文件锁住的是**真机暴露过的那几个坑**，夹具按真机 DWARF 布局手写（不是为通过而美化）：
  A typedef 链与 DWARF 前向声明占位（真机上 TCB_t 查不到、size 为 None）
  B 走到 TCB 的整条路（_owner 恒返回 None 会让任务列表只剩 pxCurrentTCB 一个）
  C 栈水位算法与 pxEndOfStack 的对齐取整（256 字的栈真机报成 255）
  D 队列注册表步长必须是 QUEUE_REGISTRY_ITEM 的大小（8），不是 Queue_t 的大小（80）
  E 诚实性：裸机 .axf / 内核没开注册表 / 两条链路都没会话，都得说实话并给对下一步
  F 工具面：3 个只读工具注册且无幽灵、_CachedReader 真的在缓存

运行：python -m tests.test_batch40
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mdkdebug import errors as ERR          # noqa: E402
from mdkdebug import rtos as R              # noqa: E402

PASS, FAIL = [], []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

# ======================================================================
# 内存镜像：地址沿用真机（F401，0x20000000 起）
# ======================================================================
MEM_BASE, MEM_SIZE = 0x20000000, 0x4000
mem = bytearray(MEM_SIZE)

def W(addr, val):
    struct.pack_into("<I", mem, addr - MEM_BASE, val & 0xFFFFFFFF)

def W1(addr, val):
    mem[addr - MEM_BASE] = val & 0xFF

def Wn(addr, data):
    mem[addr - MEM_BASE:addr - MEM_BASE + len(data)] = data

def read(addr, n):
    off = addr - MEM_BASE
    if off < 0 or off + n > MEM_SIZE:
        return None
    return bytes(mem[off:off + n])

# ---- 真机 DWARF 出来的布局（ferertos_probe.elf，FreeRTOS V11.1.0）----
DEFS = {
    "xLIST":         (20, {"uxNumberOfItems": 0, "pxIndex": 4, "xListEnd": 8}, {}),
    "xLIST_ITEM":    (20, {"xItemValue": 0, "pxNext": 4, "pxPrevious": 8,
                           "pvOwner": 12, "pxContainer": 16}, {}),
    "xMINI_LIST_ITEM": (12, {"xItemValue": 0, "pxNext": 4, "pxPrevious": 8}, {}),
    "tskTaskControlBlock": (96, {
        "pxTopOfStack": 0, "xStateListItem": 4, "xEventListItem": 24, "uxPriority": 44,
        "pxStack": 48, "pcTaskName": 52, "pxEndOfStack": 68, "uxTCBNumber": 72,
        "uxTaskNumber": 76, "uxBasePriority": 80, "uxMutexesHeld": 84,
        "ulNotifiedValue": 88, "ucNotifyState": 92}, {"pcTaskName": 16}),
    "QueueDefinition": (80, {"pcHead": 0, "pcWriteTo": 4, "u": 8, "xTasksWaitingToSend": 16,
                             "xTasksWaitingToReceive": 36, "uxMessagesWaiting": 56,
                             "uxLength": 60, "uxItemSize": 64, "cRxLock": 68,
                             "cTxLock": 69, "uxQueueNumber": 72, "ucQueueType": 76}, {}),
    # 真机上 typedef 是两跳：QueueRegistryItem_t -> xQueueRegistryItem -> QUEUE_REGISTRY_ITEM
    "xQueueRegistryItem": (8, {"pcQueueName": 0, "xHandle": 4}, {}),
    "QUEUE_REGISTRY_ITEM": (8, {"pcQueueName": 0, "xHandle": 4}, {}),
}
TYPEDEFS = {
    "List_t": "xLIST", "ListItem_t": "xLIST_ITEM", "MiniListItem_t": "xMINI_LIST_ITEM",
    "TCB_t": "tskTCB", "tskTCB": "tskTaskControlBlock",
    "Queue_t": "xQUEUE", "xQUEUE": "QueueDefinition",
    "QueueRegistryItem_t": "xQueueRegistryItem",
}

# ---- 地址表（与真机同序，方便对照）----
A = {
    "uxCurrentNumberOfTasks": 0x20000068,
    "xSuspendedTaskList":     0x2000006C,
    "xTasksWaitingTermination": 0x20000084,
    "xPendingReadyList":      0x20000098,
    "pxDelayedTaskList":      0x200000B0,
    "pxOverflowDelayedTaskList": 0x200000B4,
    "xDelayedTaskList1":      0x200000C8,
    # 真机上这张表紧挨着，夹具里挪到 0x50（不与 ready 数组 0xDC 起 重叠）
    "xDelayedTaskList2":      0x20000050,
    "pxReadyTasksLists":      0x200000DC,
    "pxCurrentTCB":           0x20000140,
    "xQueueRegistry":         0x20000144,
}

VARS = {
    "pxCurrentTCB": {"kind": "ptr", "type": "tskTaskControlBlock", "count": None,
                     "size": 4, "pointee_kind": "struct"},
    "pxReadyTasksLists": {"kind": "array", "type": "xLIST", "count": 5,
                          "elem_size": 20, "size": 100},
    "xDelayedTaskList1": {"kind": "struct", "type": "xLIST", "count": None, "size": 20},
    "xDelayedTaskList2": {"kind": "struct", "type": "xLIST", "count": None, "size": 20},
    "pxDelayedTaskList": {"kind": "ptr", "type": "xLIST", "count": None, "size": 4,
                          "pointee_kind": "struct"},
    "pxOverflowDelayedTaskList": {"kind": "ptr", "type": "xLIST", "count": None,
                                  "size": 4, "pointee_kind": "struct"},
    "xSuspendedTaskList": {"kind": "struct", "type": "xLIST", "count": None, "size": 20},
    "xPendingReadyList": {"kind": "struct", "type": "xLIST", "count": None, "size": 20},
    "xTasksWaitingTermination": {"kind": "struct", "type": "xLIST", "count": None,
                                 "size": 20},
    "uxCurrentNumberOfTasks": {"kind": "base", "type": "long unsigned int",
                               "count": None, "size": 4},
    "xQueueRegistry": {"kind": "array", "type": "QUEUE_REGISTRY_ITEM", "count": 8,
                       "elem_size": 8, "size": 64},
}

def mk_index(syms=None, structs=True):
    """手搓一个 ElfIndex（不读文件），只带本测试要用的字段。"""
    idx = R.ElfIndex.__new__(R.ElfIndex)
    idx.path = "FAKE_FREERTOS_PROBE.elf"
    idx.error = None
    idx.syms = dict(syms if syms is not None else A)
    idx.structs, idx.typedefs, idx.vars = {}, {}, {}
    if structs:
        for name, (size, fields, arrlen) in DEFS.items():
            idx.structs[name] = {"size": size, "fields": dict(fields),
                                 "_arrlen": dict(arrlen)}
        idx.typedefs = dict(TYPEDEFS)
        idx.vars = dict(VARS)
    return idx

def mk_list(addr, items, values=None):
    """环形双向链表：xListEnd 在 +8，条目 pxNext/pxPrevious 在 +4/+8。"""
    W(addr + 0, len(items))
    W(addr + 4, addr + 8)
    end = addr + 8
    W(end + 0, 0xFFFFFFFF)
    W(end + 4, items[0] if items else end)
    W(end + 8, items[-1] if items else end)
    for i, it in enumerate(items):
        W(it + 0, (values[i] if values else 0))
        W(it + 4, items[i + 1] if i + 1 < len(items) else end)
        W(it + 8, items[i - 1] if i > 0 else end)

def mk_tcb(addr, name, prio, stack_base, size_words, free_words, number):
    """按真机 TCB_t 布局摆一个任务；栈水位用 0xA5 填充法造。"""
    W(addr + 0, stack_base + (size_words - 1) * 4)          # pxTopOfStack
    W(addr + 44, prio)                                      # uxPriority
    W(addr + 48, stack_base)                                # pxStack
    Wn(addr + 52, name.encode("ascii").ljust(16, b"\x00"))  # pcTaskName[16]
    # FreeRTOS 建栈时把栈顶按 portBYTE_ALIGNMENT 向下取整后才记进 pxEndOfStack：
    # 真机上 256 字的栈 pxEndOfStack 落在 base+(256-2)*4，所以对外报 255。
    W(addr + 68, stack_base + (size_words - 2) * 4)         # pxEndOfStack
    W(addr + 76, number)                                    # uxTaskNumber
    Wn(stack_base, b"\xA5" * (free_words * 4))              # 从栈底往上 N 个字还是填充
    W1(stack_base + free_words * 4, 0x11)                   # 第一个用过的字节
    return addr

def mk_queue(addr, messages, length, item_size):
    W(addr + 56, messages)
    W(addr + 60, length)
    W(addr + 64, item_size)
    return addr

# 任务：IDLE(running) / deep(blocked) / stuck(无限阻塞) / susp(真挂起)
T_IDLE = mk_tcb(0x20001960, "IDLE", 0, 0x20001000, 128, 101, 1)
T_DEEP = mk_tcb(0x20000F10, "deep", 1, 0x20002000, 192, 62, 2)
T_STUCK = mk_tcb(0x20000AB0, "stuck", 1, 0x20003000, 128, 97, 3)
T_SUSP = mk_tcb(0x20000CA0, "susp", 2, 0x20003800, 96, 71, 4)
TCBS = [T_IDLE, T_DEEP, T_STUCK, T_SUSP]

# ready[0] 放 IDLE（运行中的任务本来也在就绪表里，真机如此）
mk_list(A["pxReadyTasksLists"] + 0 * 20, [T_IDLE + 4])
for i in range(1, 5):
    mk_list(A["pxReadyTasksLists"] + i * 20, [])
mk_list(A["xDelayedTaskList1"], [T_DEEP + 4])
mk_list(A["xDelayedTaskList2"], [])
mk_list(A["xSuspendedTaskList"], [T_STUCK + 4, T_SUSP + 4])
mk_list(A["xPendingReadyList"], [])
mk_list(A["xTasksWaitingTermination"], [])

W(A["pxDelayedTaskList"], A["xDelayedTaskList1"])
W(A["pxOverflowDelayedTaskList"], A["xDelayedTaskList2"])
W(A["pxCurrentTCB"], T_IDLE)
W(A["uxCurrentNumberOfTasks"], 4)

for t in TCBS:                       # 让 xStateListItem 的 pvOwner 指回 TCB
    W(t + 4 + 12, t)
W(T_STUCK + 24 + 16, 0x2000031C)     # xEventListItem.pxContainer 非空 = 无限阻塞
W(T_SUSP + 24 + 16, 0)               # 空 = 真的被 vTaskSuspend 挂起

# 队列注册表：3 个登记 + 5 个空槽；**步长写错的探针会在 0x194 一带撞到 0xFF 垃圾**
Q_SENSOR, Q_SEM, Q_MTX = 0x20000300, 0x20000340, 0x20000380
mk_queue(Q_SENSOR, 2, 4, 4)
mk_queue(Q_SEM, 0, 1, 0)
mk_queue(Q_MTX, 1, 1, 0)
N_Q_SENSOR, N_Q_SEM, N_Q_MTX = 0x20000500, 0x20000520, 0x20000540
Wn(N_Q_SENSOR, b"q_sensor\x00")
Wn(N_Q_SEM, b"sem_stuck\x00")
Wn(N_Q_MTX, b"mtx_bus\x00")
for i, (nm, h) in enumerate(((N_Q_SENSOR, Q_SENSOR), (N_Q_SEM, Q_SEM), (N_Q_MTX, Q_MTX))):
    W(A["xQueueRegistry"] + i * 8, nm)
    W(A["xQueueRegistry"] + i * 8 + 4, h)
Wn(A["xQueueRegistry"] + 24, b"\x00" * 40)
# 错步长（80）会落到这里：若实现用 Queue_t 大小跳，就会读出下面这些"对象"
for probe in (0x20000194, 0x200001E4):
    W(probe, 0xFFFFFFFF)
    W(probe + 4, 0xFFFFFFFF)

IDX = mk_index()

# ======================================================================
def main():
    idx = IDX
    R.get_index = lambda p, _i=idx: _i        # 不读文件，直接用夹具

    print("\n-- A 结构体解析：typedef 链 + 前向声明占位 --")
    check("A1 field() 走 typedef 链（List_t）", idx.field("List_t", "xListEnd") == 8,
          idx.field("List_t", "xListEnd"))
    check("A2 field() 走两跳 typedef（TCB_t -> tskTCB -> tskTaskControlBlock）",
          idx.field("TCB_t", "pcTaskName") == 52, idx.field("TCB_t", "pcTaskName"))
    check("A3 field() 走 typedef 链（ListItem_t.pvOwner）",
          idx.field("ListItem_t", "pvOwner") == 12, idx.field("ListItem_t", "pvOwner"))
    check("A4 不存在的结构体仍返回 None", idx.field("Nope_t", "x") is None)
    check("A5 struct() 拿到真名下的布局", (idx.struct("TCB_t") or {}).get("size") == 96)
    check("A6 数组成员长度（pcTaskName[16]）",
          R._member_array_len(idx, "TCB_t", "pcTaskName") == 16,
          R._member_array_len(idx, "TCB_t", "pcTaskName"))

    print("\n-- B 任务列表：链表 -> pvOwner -> TCB --")
    check("B1 _owner 能拿到 TCB 地址（恒 None 时任务只剩 1 个）",
          R._owner(idx, read, T_IDLE + 4) == T_IDLE, R._owner(idx, read, T_IDLE + 4))
    where, notes = R._tcbs_from_lists(idx, read)
    check("B2 四条链表走全，凑出 4 个 TCB",
          sorted(k for k in where if k) == sorted(TCBS),
          [hex(k) if k else None for k in where])
    check("B3 走链无异常", not notes, notes)

    print("\n-- C 任务解析与栈水位 --")
    out = R.freertos_tasks("FAKE.elf", read)
    check("C1 ok 且 count == kernel_task_count", out.get("ok") and out.get("count") == 4
          and out.get("kernel_task_count") == 4 and not out.get("count_mismatch"), out)
    by = {t.get("name"): t for t in out.get("tasks", [])}
    check("C2 四个任务名齐全", sorted(by) == ["IDLE", "deep", "stuck", "susp"], sorted(by))
    check("C3 IDLE 运行中 / deep 阻塞 / susp 挂起",
          by["IDLE"]["state"] == "running" and by["deep"]["state"] == "blocked"
          and by["susp"]["state"] == "suspended",
          {k: v.get("state") for k, v in by.items()})
    check("C4 portMAX_DELAY 无限阻塞不报成挂起，并给出说明",
          by["stuck"]["state"] == "blocked" and by["stuck"].get("state_note"),
          by["stuck"])
    check("C5 栈水位与填充法一致（101/62/97/71）",
          [by[k]["stack_free_words"] for k in ("IDLE", "deep", "stuck", "susp")]
          == [101, 62, 97, 71],
          {k: by[k].get("stack_free_words") for k in by})
    check("C6 栈大小受 pxEndOfStack 对齐取整影响：192 字的栈报 191",
          by["deep"].get("stack_size_words") == 191, by["deep"].get("stack_size_words"))
    check("C7 结果里有一处对齐说明，不把 size/pct 说成精确值",
          "portBYTE_ALIGNMENT" in (out.get("stack_size_note") or ""),
          out.get("stack_size_note"))
    check("C8 优先级与就绪下标带上",
          by["susp"].get("priority") == 2 and by["IDLE"].get("ready_priority_index") == 0,
          by["susp"])
    check("C9 栈底不是 0xA5 时不装模作样：如实出 stack_note",
          _stack_note_case())

    print("\n-- D 队列注册表：步长必须按 QUEUE_REGISTRY_ITEM 走 --")
    objs = R.freertos_objects("FAKE.elf", read)
    names = [o.get("name") for o in objs.get("objects", [])]
    check("D1 只报 3 个登记过的对象（错步长会读出 0xFFFFFFFF 垃圾）",
          objs.get("ok") and objs.get("count") == 3 and names == ["q_sensor", "sem_stuck",
                                                                  "mtx_bus"], objs)
    q = objs["objects"][0]
    check("D2 队列字段正确（length 4 / item_size 4 / 排队 2）",
          (q.get("length"), q.get("item_size"), q.get("messages_waiting")) == (4, 4, 2), q)
    s = objs["objects"][1]
    check("D3 uxItemSize==0 判为信号量/互斥量，并给 kind",
          s.get("item_size") == 0 and s.get("kind") == "semaphore/mutex", s)
    check("D4 名字指向的字符串读对（不是把句柄当名字）",
          objs["objects"][2]["name"] == "mtx_bus", objs["objects"][2])

    print("\n-- E 诚实性：说不知道，并给对下一步 --")
    bare = mk_index(syms={"main": 0x8000101}, structs=False)
    R.get_index = lambda p, _b=bare: _b
    d = R.detect("BARE.elf")
    check("E1 无 RTOS 符号时 detect 说 None，不硬凑一个 RTOS",
          d.get("ok") and d.get("rtos") is None and d.get("found") == [], d)
    t = R.tasks("BARE.elf", read)
    check("E2 裸机固件：tasks() 如实报没有 RTOS 并带 reason",
          t.get("ok") is False and t.get("reason") == "no-rtos-symbols", t)
    o = R.freertos_objects("BARE.elf", read)
    check("E3 裸机固件：objects() 不把「没有内核」说成「没开注册表」",
          o.get("reason") == "no-rtos-symbols" and "xQueueRegistry" not in (o.get("error") or ""),
          o)
    e2 = ERR.normalize("rtos_tasks", t)
    check("E4 归类 rtos-not-present（不再落 unknown-error）",
          e2.get("error_code") == "rtos-not-present", e2.get("error_code"))
    check("E5 下一步指向核对 .axf / 说明 RTOS，不指向 keil_health",
          any("裸机" in a or "axf" in a.lower() for a in e2.get("next_actions", []))
          and not any("keil_health" in a for a in e2.get("next_actions", [])),
          e2.get("next_actions"))

    noreg = _noreg_case()
    check("E6 内核没开注册表：归类 rtos-no-queue-registry",
          noreg.get("code") == "rtos-no-queue-registry", noreg)
    check("E7 两条链路都没会话：归类 rtos-no-mem-link",
          _nolink_case() == "rtos-no-mem-link", _nolink_case())
    check("E8 Keil 侧错误文案指到 enter_debug",
          "enter_debug" in (_nolink_actions() or ""), _nolink_actions())

    print("\n-- F 工具面与缓存 --")
    check("F1 三个 RTOS 工具都被 annotate 归成只读",
          all(n in ERR._annotate.READONLY
              for n in ("rtos_info", "rtos_tasks", "rtos_objects")), None)
    check("F2 三个工具都不在破坏性/可写表里（只读工具不该带写风险）",
          not [n for n in ("rtos_info", "rtos_tasks", "rtos_objects")
               if n in ERR._annotate.DESTRUCTIVE or n in ERR._annotate.MUTATING], None)
    R.get_index = lambda p, _i=IDX: _i
    cr = R._CachedReader(read)
    cr(0x20000144, 8)
    cr(0x20000148, 4)
    cr(0x2000014C, 4)
    check("F3 _CachedReader 同块不重复往返（hits >= 2, calls == 1）",
          cr.hits >= 2 and cr.calls == 1, (cr.calls, cr.hits))
    check("F4 _pick_reader 两条链路都没有时不猜",
          R._pick_reader("auto")[0] is None, None)

    print("\n" + "=" * 72)
    print("通过 %d 失败 %d" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAIL: %s" % n)
    print("=" * 72)
    return 1 if FAIL else 0


def _stack_note_case():
    """把 deep 的栈底抹掉填充值：水位必须标记为不可信。"""
    base = 0x20002000
    save = mem[base - MEM_BASE]
    W1(base, 0x77)
    try:
        idx2 = mk_index()
        R.get_index = lambda p, _i=idx2: _i
        out = R.freertos_tasks("FAKE.elf", read)
        rec = [t for t in out["tasks"] if t.get("name") == "deep"][0]
        return bool(rec.get("stack_note"))
    finally:
        W1(base, save)
        R.get_index = lambda p, _i=IDX: _i


def _noreg_case():
    """内核没开 configQUEUE_REGISTRY_SIZE：准确报「没开注册表」。"""
    idx3 = mk_index(syms={k: v for k, v in A.items() if k != "xQueueRegistry"})
    R.get_index = lambda p, _i=idx3: _i
    o = R.freertos_objects("FAKE.elf", read)
    n = ERR.normalize("rtos_objects", o)
    return {"code": n.get("error_code"), "reason": o.get("reason"),
            "error": o.get("error"), "next": n.get("next_actions")}


def _nolink_case():
    R.get_index = lambda p, _i=IDX: _i
    rd, err = R._pick_reader("auto")
    if rd is not None:
        return "(本机有活着的调试会话，跳过)"
    _nolink_case.err = err
    return ERR.normalize("rtos_tasks", err).get("error_code")


_nolink_case.err = None


def _nolink_actions():
    if _nolink_case.err is None:
        return ""
    return " ".join(ERR.normalize("rtos_tasks", _nolink_case.err).get("next_actions", []))


if __name__ == "__main__":
    sys.exit(main())
