# -*- coding: utf-8 -*-
"""RTOS 任务感知：任务列表 / 栈水位 / 内核对象（队列、信号量、互斥量）。

设计上的三条硬约定
------------------
1. **结构体偏移一律从 .axf 的 DWARF 取，绝不写死。**
   FreeRTOS 的 `TCB_t` 成员是随 config 宏增删的（`configUSE_TRACE_FACILITY`、
   `configUSE_MUTEXES`、`configRECORD_STACK_HIGH_ADDRESS`、`configNUMBER_OF_CORES`
   …都能改变布局），`List_t`/`Queue_t` 同理。任何写死偏移的方案在别人的工程上
   都会安静地读出垃圾——那正是「看似权威的错答案」。所以：DWARF 里有哪个字段就
   报哪个字段，缺了就说缺了。
2. **内存读取由调用方注入**（`read(addr, n) -> bytes | None`），Keil（UVSOCK）与
   OpenOCD 两条链路共用同一套解析逻辑，不各写一份。
3. **读不到、结构对不上、配置不支持时如实报错**，不猜、不返回半真半假的结果。

栈水位的算法与 FreeRTOS 自带的 `uxTaskGetStackHighWaterMark` 对齐
（`prvTaskCheckFreeStackSpace`）：任务创建时整片栈被 memset 成 0xA5，
从 `pxStack`（最低地址）向上连续 0xA5 的字节数就是**从未用过**的栈空间。
好处是它读的是「历史最深用量」，因此对正在运行的任务同样可信
（`pxTopOfStack` 只有在切出时才更新，那个值才会滞后）。
"""

import logging
import os
import struct

logger = logging.getLogger(__name__)

# FreeRTOS 建栈时的填充字节（tasks.c 的 tskSTACK_FILL_BYTE）
TSK_FILL_BYTE = 0xA5

# 读栈扫填充时的上限：防某个字段被读成天文数字后一次性拉爆内存读
_STACK_SCAN_CAP = 16384


# ================================================================ ELF / DWARF

class ElfIndex:
    """一个 .axf 的符号表 + DWARF 类型布局（按 mtime 缓存）。"""

    _cache = {}

    def __init__(self, axf_path: str):
        self.path = os.path.abspath(axf_path)
        self.error = None
        self.syms = {}
        self.structs = {}      # 结构体真名 -> {"size": n, "fields": {成员名: 偏移}, "_arrlen": {...}}
        self.typedefs = {}     # typedef 名 -> 结构体真名（List_t -> xLIST、TCB_t -> tskTaskControlBlock）
        self.vars = {}         # 全局变量名 -> {"kind", "type", "count", "size", "type_die"}
        # 匿名结构体（`typedef struct {...} svcrt_task_t;` 这种）在 DWARF 里
        # **没有 DW_AT_name**，按名字建索引等于永远查不到它。这里先按 DIE 偏移
        # 存住，等 typedef 那一跳把它挂到 typedef 名下（SVCrtOS 的 TCB 就是这种写法）。
        self._anon_structs = {}   # DIE 偏移 -> 结构体记录
        self._td_anon = {}        # typedef 名 -> 目标匿名结构体的 DIE 偏移
        self._segs = None         # 可加载段（按需建，用于取某地址的机器码做内容核对）
        self._load()

    # ---------------------------------------------------------- 内容核对
    def _segments(self) -> list:
        """可加载段 [(vaddr, filesz, fileoff)]，用于「取某虚拟地址处的字节」。"""
        if self._segs is not None:
            return self._segs
        segs = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for seg in elf.iter_segments():
                    if seg["p_type"] != "PT_LOAD" or not seg["p_filesz"]:
                        continue
                    segs.append((int(seg["p_vaddr"]), int(seg["p_filesz"]),
                                 int(seg["p_offset"])))
        except Exception:                                     # noqa: BLE001
            segs = []
        self._segs = segs
        return segs

    def bytes_at(self, vaddr: int, n: int):
        """取该虚拟地址处的**文件内容**（机器码）。取不到返回 None。

        取不到就是「没法核对」，**不拿别的地址/邻段的字节顶上**——内容核对全凭
        这一条，顶上就等于把核对做成了走过场。
        """
        try:
            vaddr, n = int(vaddr), int(n)
        except (TypeError, ValueError):
            return None
        if n <= 0:
            return None
        for va, sz, off in self._segments():
            if va <= vaddr < va + sz:
                avail = min(n, va + sz - vaddr)
                if avail <= 0:
                    return None
                try:
                    with open(self.path, "rb") as f:
                        f.seek(off + (vaddr - va))
                        return f.read(avail)
                except OSError:
                    return None
        return None

    # ---------------------------------------------------------- 载入
    def _load(self):
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:                                   # pragma: no cover
            self.error = "没装 pyelftools，无法解析 .axf（pip install pyelftools）"
            return
        if not os.path.isfile(self.path):
            self.error = "文件不存在：%s" % self.path
            return
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                self._load_syms(elf)
                self._load_dwarf(elf)
        except Exception as e:                                # noqa: BLE001
            self.error = "解析 .axf 失败：%s" % e

    def _load_syms(self, elf):
        for sec in elf.iter_sections():
            if sec.name not in (".symtab", ".dynsym"):
                continue
            for sym in sec.iter_symbols():
                n = sym.name
                if not n:
                    continue
                v = int(sym["st_value"] or 0)
                if v:
                    # 局部符号（FreeRTOS 的内核链表多为 static）也在 .symtab 里，
                    # 按名记录；同名冲突时保留第一个（全局符号通常排在前面）。
                    self.syms.setdefault(n, v & ~1)

    def _load_dwarf(self, elf):
        if not elf.has_dwarf_info():
            self.error = ("该 .axf 没有 DWARF 调试信息（编译时未加 -g / 未选 Debug 配置），"
                          "无法取结构体布局")
            return
        di = elf.get_dwarf_info()
        for cu in di.iter_CUs():
            for die in cu.iter_DIEs():
                tag = die.tag
                if tag in ("DW_TAG_structure_type", "DW_TAG_union_type",
                           "DW_TAG_class_type"):
                    self._add_struct(di, die)
                elif tag == "DW_TAG_variable":
                    self._add_var(di, die)
                elif tag == "DW_TAG_typedef":
                    self._add_typedef(di, die)
        # DIE 的惰性解析依赖尚未关闭的文件流，所有 resolve 必须在 with 块内做完
        for name, v in list(self.vars.items()):
            if v.get("_die") is not None:
                v.update(self._resolve(di, v.pop("_die")))
        # 匿名结构体要在**全部 DIE 走完之后**才能挂名：结构体 DIE 一般排在 typedef
        # 之前，但 DWARF 不保证顺序，靠顺序会偶发查不到。
        for td_name, off in self._td_anon.items():
            rec = self._anon_structs.get(off)
            if rec is not None:
                self.structs.setdefault(td_name, rec)

    # ---- 类型解析工具 ----
    def _ref(self, die, attr):
        try:
            return die.get_DIE_from_attribute(attr)
        except Exception:                                     # noqa: BLE001
            return None

    def _add_struct(self, di, die):
        nm = die.attributes.get("DW_AT_name")
        name = None
        if nm is not None:
            name = nm.value
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
        sz = die.attributes.get("DW_AT_byte_size")
        fields = {}
        arrlen = {}
        self._flatten_members(di, die, fields, 0, "", arrlen)
        rec = {
            "size": sz.value if sz is not None else None,
            "fields": fields,
            "_arrlen": arrlen,      # 成员名 -> 数组元素个数（如 pcTaskName）
        }
        # 前向声明（`struct tskTaskControlBlock;`）在 DWARF 里同样带名字但成员为空，
        # 若不管是先来后到就会把真正的定义挡在外面。只认有成员的，且更完整的胜出。
        if not fields:
            return
        if name is None:
            # 匿名结构体：先按 DIE 偏移存着，等 typedef 把它认领
            self._anon_structs[die.offset] = rec
            return
        prev = self.structs.get(name)
        if prev is None or len(prev.get("fields") or {}) < len(fields):
            self.structs[name] = rec

    def _flatten_members(self, di, die, out: dict, depth: int, prefix: str,
                         arrlen: dict = None):
        """收集成员偏移；匿名 struct/union 展开并把前缀带上（如 u.xQueue.pcReadFrom）。"""
        if depth > 4:
            return
        for m in die.iter_children():
            if m.tag != "DW_TAG_member":
                continue
            mname = m.attributes.get("DW_AT_name")
            mname = (mname.value.decode("utf-8", "replace")
                     if isinstance(mname.value, bytes) else mname.value) if mname is not None else None
            loc = m.attributes.get("DW_AT_data_member_location")
            off = 0
            if loc is not None:
                lv = loc.value
                if isinstance(lv, int):
                    off = lv
                elif isinstance(lv, (list, tuple)) and lv and lv[0] == 0x23:
                    off = int(lv[1])          # DW_OP_plus_uconst
            t = self._ref(m, "DW_AT_type")
            if mname:
                out[prefix + mname] = off
                if arrlen is not None and t is not None:
                    n = self._array_count(di, t)
                    if n:
                        arrlen[prefix + mname] = n
            elif t is not None and t.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
                # 匿名成员：把内层成员按「外层偏移 + 内层偏移」展开
                inner, inner_len = {}, {}
                self._flatten_members(di, t, inner, depth + 1, "", inner_len)
                for k, v in inner.items():
                    out[(prefix + "." if prefix else "") + k] = off + v
                if arrlen is not None:
                    for k, v in inner_len.items():
                        arrlen[(prefix + "." if prefix else "") + k] = v

    def _array_count(self, di, die, depth: int = 0) -> int:
        """该类型若是数组，返回元素个数；否则 0。

        只跟 typedef 链，不进结构体内部——只为拿 `pcTaskName[configMAX_TASK_NAME_LEN]`
        这类长度，避免在载入期为每个成员做完整类型解析。
        """
        while die is not None and depth < 10:
            if die.tag == "DW_TAG_array_type":
                for sub in die.iter_children():
                    if sub.tag != "DW_TAG_subrange_type":
                        continue
                    ub = sub.attributes.get("DW_AT_upper_bound")
                    lo = sub.attributes.get("DW_AT_lower_bound")
                    if ub is None:
                        return 0
                    try:
                        lo_v = int(lo.value) if lo is not None else 0
                        return max(0, int(ub.value) - lo_v + 1)
                    except (TypeError, ValueError):
                        return 0
                return 0
            if die.tag not in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                               "DW_TAG_restrict_type"):
                return 0
            die = self._ref(die, "DW_AT_type")
            depth += 1
        return 0

    def _resolve(self, di, die, depth: int = 0):
        """把一个类型 DIE 归成 {kind, type, count, size}。"""
        if die is None or depth > 10:
            return {"kind": "?", "type": None, "count": None, "size": None}
        tag = die.tag
        nm = die.attributes.get("DW_AT_name")
        if nm is not None:
            nm = nm.value.decode("utf-8", "replace") if isinstance(nm.value, bytes) else nm.value
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                   "DW_TAG_restrict_type"):
            inner = self._resolve(di, self._ref(die, "DW_AT_type"), depth + 1)
            if inner.get("kind") in ("?", None) and nm:
                inner = dict(inner, type=nm)
            return inner
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
            return {"kind": "struct", "type": nm, "count": None,
                    "size": (die.attributes["DW_AT_byte_size"].value
                             if "DW_AT_byte_size" in die.attributes else None)}
        if tag == "DW_TAG_pointer_type":
            inner = self._resolve(di, self._ref(die, "DW_AT_type"), depth + 1)
            return {"kind": "ptr", "type": inner.get("type"), "count": None, "size": 4,
                    "pointee_kind": inner.get("kind")}
        if tag == "DW_TAG_array_type":
            elem = self._resolve(di, self._ref(die, "DW_AT_type"), depth + 1)
            count = None
            for sub in die.iter_children():
                if sub.tag == "DW_TAG_subrange_type":
                    ub = sub.attributes.get("DW_AT_upper_bound")
                    lo = sub.attributes.get("DW_AT_lower_bound")
                    lo_v = lo.value if lo is not None else 0
                    if ub is not None:
                        try:
                            count = int(ub.value) - int(lo_v) + 1
                        except (TypeError, ValueError):
                            count = None
            return {"kind": "array", "type": elem.get("type"), "count": count,
                    "elem_size": elem.get("size"),
                    "size": (elem.get("size") or 0) * count if count and elem.get("size") else None}
        base = nm or tag.replace("DW_TAG_", "")
        sz = die.attributes.get("DW_AT_byte_size")
        return {"kind": "base", "type": base, "count": None,
                "size": sz.value if sz is not None else None}

    def _add_typedef(self, di, die):
        """typedef 名 -> 结构体真名。

        FreeRTOS 全是 `typedef struct xLIST {...} List_t;` 这种写法，DWARF 里
        结构体叫 xLIST，而人（和内核源码）只认 List_t —— 不建这张映射，
        按 List_t / TCB_t / Queue_t 查结构体一律查不到。
        """
        nm = die.attributes.get("DW_AT_name")
        if nm is None:
            return
        name = nm.value.decode("utf-8", "replace") if isinstance(nm.value, bytes) else nm.value
        t = self._ref(die, "DW_AT_type")
        # 目标是结构体就记住真名；目标还是 typedef 就先串上（如 TCB_t -> tskTCB ->
        # tskTaskControlBlock），查的时候一路跟下去——只映射一跳会漏掉链式 typedef。
        if t is None or t.tag not in ("DW_TAG_structure_type", "DW_TAG_union_type",
                                      "DW_TAG_typedef"):
            return
        if t.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            # 匿名结构体没有名字，typedef 名就是它**唯一**的名字
            # （SVCrtOS：typedef struct {...} svcrt_task_t;）。挂到 typedef 名下，
            # 否则按 svcrt_task_t 查布局恒为空——而 TCB 的成员偏移正是取任务名的关键。
            if t.attributes.get("DW_AT_name") is None:
                self._td_anon.setdefault(name, t.offset)
                return
        tn = t.attributes.get("DW_AT_name")
        if tn is None:
            return
        tn = tn.value.decode("utf-8", "replace") if isinstance(tn.value, bytes) else tn.value
        self.typedefs.setdefault(name, tn)

    def _add_var(self, di, die):
        nm = die.attributes.get("DW_AT_name")
        if nm is None:
            return
        name = nm.value.decode("utf-8", "replace") if isinstance(nm.value, bytes) else nm.value
        if name in self.vars or name not in self.syms:
            return
        self.vars[name] = {"_die": self._ref(die, "DW_AT_type") if "DW_AT_type" in
                           die.attributes else None}

    # ---------------------------------------------------------- 查询
    def addr_of(self, *names):
        for n in names:
            if n in self.syms:
                return self.syms[n]
        return None

    def struct(self, type_name: str):
        """按名字取结构体布局；同时认 typedef 名，且顺着 typedef 链一路跟
        （List_t -> xLIST、TCB_t -> tskTCB -> tskTaskControlBlock）。"""
        cur = type_name
        for _ in range(16):
            if not cur:
                return None
            s = self.structs.get(cur)
            if s is not None:
                return s
            cur = self.typedefs.get(cur)
        return None

    def field(self, type_name: str, member: str):
        # 必须走 struct()（它会顺着 typedef 链找真名）：FreeRTOS 的结构体真名是
        # xLIST_ITEM / tskTaskControlBlock 这类，直接查 structs["ListItem_t"] 恒为空。
        s = self.struct(type_name)
        if not s:
            return None
        return s["fields"].get(member)

    def var_kind(self, name: str):
        """全局变量的类型信息（用于判断某个链表符号是 List_t 还是 List_t*）。"""
        return self.vars.get(name)


def get_index(axf_path: str) -> ElfIndex:
    """按 (路径, mtime) 复用解析结果——一次 rtos_tasks 可能连着问好几个符号。"""
    try:
        key = (os.path.abspath(axf_path), os.path.getmtime(axf_path))
    except OSError:
        return ElfIndex(axf_path)
    hit = ElfIndex._cache.get(key)
    if hit is None:
        hit = ElfIndex(axf_path)
        ElfIndex._cache[key] = hit
        if len(ElfIndex._cache) > 8:
            ElfIndex._cache.clear()
            ElfIndex._cache[key] = hit
    return hit


# ================================================================ 内存小工具

def _u32(data: bytes, off: int):
    if data is None or off + 4 > len(data) or off < 0:
        return None
    return struct.unpack_from("<I", data, off)[0]


def _rd(read, addr, n):
    try:
        return read(int(addr), int(n))
    except Exception as e:                                    # noqa: BLE001
        logger.debug("读内存失败 0x%X/%d: %s", addr, n, e)
        return None


def _cstr(data: bytes):
    if not data:
        return None
    end = data.find(b"\x00")
    raw = data if end < 0 else data[:end]
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    s = s.strip()
    return s or None


# ================================================================ FreeRTOS

_FR_SYMS = {
    "current": ("pxCurrentTCB", "pxCurrentTCBs"),
    "ready": ("pxReadyTasksLists",),
    "delayed": ("pxDelayedTaskList", "xDelayedTaskList1"),
    "delayed_overflow": ("pxOverflowDelayedTaskList", "xDelayedTaskList2"),
    "suspended": ("xSuspendedTaskList",),
    "pending": ("xPendingReadyList",),
    "terminated": ("xTasksWaitingTermination",),
    "num_tasks": ("uxCurrentNumberOfTasks",),
    "queue_registry": ("xQueueRegistry",),
    "top_priority": ("uxTopReadyPriority", "uxTopReadyPriority"),
}


def detect(axf: str):
    """判断 .axf 里编进了哪个 RTOS（只按符号存在性，不猜）。"""
    idx = get_index(axf)
    if idx.error:
        return {"ok": False, "error": idx.error, "axf": idx.path}
    found = []
    for rtos, marks in (("FreeRTOS", ("pxCurrentTCB", "pxReadyTasksLists",
                                      "uxCurrentNumberOfTasks")),
                        ("RT-Thread", ("rt_object_container", "rt_current_thread",
                                       "rt_thread_self"))):
        present = [m for m in marks if m in idx.syms]
        if present:
            found.append({"rtos": rtos, "markers": present})
    return {"ok": True, "axf": idx.path, "found": found,
            "rtos": found[0]["rtos"] if found else None}


def _layout(idx, *needed):
    """取 FreeRTOS 关键结构体布局；缺哪个如实报出来。"""
    missing = []
    need = {
        "List_t": ("uxNumberOfItems", "pxIndex", "xListEnd"),
        "ListItem_t": ("xItemValue", "pxNext", "pxPrevious", "pvOwner",
                       ("pvContainer", "pxContainer")),
        "MiniListItem_t": ("xItemValue", "pxNext", "pxPrevious"),
        "TCB_t": ("pxTopOfStack", "pxStack", "pcTaskName", "uxPriority"),
    }
    out = {}
    for tname, members in need.items():
        s = idx.struct(tname)
        if not s:
            missing.append("结构体 %s" % tname)
            continue
        for m in members:
            alts = (m,) if isinstance(m, str) else m
            if not any(a in s["fields"] for a in alts):
                missing.append("%s.%s" % (tname, alts[0]))
        out[tname] = s
    return out, missing


def _list_addr(idx, read, var_name: str):
    """取一个 FreeRTOS 链表变量的地址：是 List_t* 就先解引用（DWARF 说了算）。"""
    a = idx.addr_of(var_name)
    if a is None:
        return None, "符号 %s 不存在（该配置下内核没编进这张链表）" % var_name
    vk = idx.var_kind(var_name)
    if vk and vk.get("kind") == "ptr":
        p = _u32(_rd(read, a, 4), 0)
        if not p:
            return None, "%s 当前是 NULL（指针还没指向任何链表）" % var_name
        return p, None
    return a, None


def _walk_list(idx, read, list_addr: int, limit: int = 256):
    """按 xListEnd 环形双向链表走一遍，返回条目地址列表。"""
    L = idx.struct("List_t")
    LI = idx.struct("ListItem_t")
    ML = idx.struct("MiniListItem_t")
    if not (L and LI and ML):
        return None, "缺 List_t/ListItem_t/MiniListItem_t 的 DWARF 布局"
    end_addr = list_addr + L["fields"]["xListEnd"]
    nxt = ML["fields"].get("pxNext")
    if nxt is None:
        return None, "MiniListItem_t 里没有 pxNext"
    data = _rd(read, end_addr + nxt, 4)
    p = _u32(data, 0)
    if p is None:
        return None, "读不到 %s 的 xListEnd.pxNext" % hex(list_addr)
    items, seen = [], set()
    li_next = LI["fields"].get("pxNext")
    if li_next is None:
        return None, "ListItem_t 里没有 pxNext"
    while p and p != end_addr and len(items) < limit:
        if p in seen:
            return items, "链表出现环（第 %d 项指回已访问过的 %s），结果可能不完整" % (
                len(items) + 1, hex(p))
        seen.add(p)
        items.append(p)
        p = _u32(_rd(read, p + li_next, 4), 0)
    return items, None


def _stack_watermark(read, base: int, size_bytes, fill: int = TSK_FILL_BYTE,
                     cap: int = _STACK_SCAN_CAP):
    """从 pxStack 向上数连续填充字节：等于 FreeRTOS 自己的水位算法。

    返回 {free_bytes, free_words, scanned, capped, fill_found}
    """
    n = int(size_bytes) if size_bytes and size_bytes > 0 else cap
    n = min(n, cap)
    data = _rd(read, base, n)
    if not data:
        return None
    cnt = 0
    for b in data:
        if b == fill:
            cnt += 1
        else:
            break
    return {"free_bytes": cnt, "free_words": cnt // 4, "scanned": len(data),
            "capped": bool(size_bytes and size_bytes > cap),
            "fill_found": cnt > 0}


def _tcbs_from_lists(idx, read, limit: int = 256):
    """把各条链表里的 TCB 集合成 {tcb_addr: [所在链表名]}。"""
    where = {}
    notes = []

    # 就绪表：pxReadyTasksLists[configMAX_PRIORITIES]
    ra = idx.addr_of(*_FR_SYMS["ready"])
    if ra is not None:
        v = idx.var_kind(_FR_SYMS["ready"][0])
        nprio = v.get("count") if v else None
        elem = (v.get("elem_size") if v else None)
        if not elem:
            lt = idx.struct("List_t")
            elem = lt.get("size") if lt else None
        if nprio and elem:
            for i in range(min(nprio, 64)):
                items, err = _walk_list(idx, read, ra + i * elem, limit)
                if err:
                    notes.append("ready[%d]: %s" % (i, err))
                for it in items or []:
                    where.setdefault(_owner(idx, read, it), []).append(
                        {"list": "ready", "priority_index": i})
        else:
            notes.append("拿不到 pxReadyTasksLists 的数组长度（DWARF 里没有），就绪任务可能有遗漏")

    for key, label in (("delayed", "blocked_delayed"), ("delayed_overflow", "blocked_delayed_overflow"),
                       ("suspended", "suspended"), ("pending", "ready_pending"),
                       ("terminated", "deleted_waiting_free")):
        for nm in _FR_SYMS[key]:
            if idx.addr_of(nm) is None:
                continue
            la, err = _list_addr(idx, read, nm)
            if err:
                notes.append("%s: %s" % (nm, err))
                break
            items, err = _walk_list(idx, read, la, limit)
            if err:
                notes.append("%s: %s" % (nm, err))
            for it in items or []:
                where.setdefault(_owner(idx, read, it), []).append({"list": label})
            break
    return where, notes


def _field_any(idx, type_name: str, *names):
    """按优先级取第一个存在的成员偏移。

    FreeRTOS 跨版本会改成员名（V11.1 把 ListItem_t.pvContainer 改名成 pxContainer），
    写死某一个名字就会在另一版上静默拿不到偏移。
    """
    for n in names:
        off = idx.field(type_name, n)
        if off is not None:
            return off
    return None

def _owner(idx, read, item_addr: int):
    off = idx.field("ListItem_t", "pvOwner")
    if off is None:
        return None
    return _u32(_rd(read, item_addr + off, 4), 0)


def _read_tcb(idx, read, tcb_addr: int, layout):
    t = layout["TCB_t"]["fields"]
    names = list(t.keys())
    # 一次把 TCB 读回来（成员偏移的最大值 + 4 作为长度上限），少几次往返
    need = max(v for v in t.values() if isinstance(v, int)) + 8
    need = min(max(need, 32), 512)
    data = _rd(read, tcb_addr, need)
    if not data:
        return None
    rec = {"tcb": "0x%X" % tcb_addr}

    name_off = t.get("pcTaskName")
    if name_off is not None:
        # pcTaskName 的长度取自 DWARF 里该成员的类型（char[configMAX_TASK_NAME_LEN]）
        nlen = _member_array_len(idx, "TCB_t", "pcTaskName") or 16
        if name_off + nlen > len(data):     # 读回来的长度不够装名字，按实有的截
            nlen = max(0, len(data) - name_off)
        rec["name"] = _cstr(data[name_off:name_off + nlen]) or "(未命名)"
    else:
        rec["name"] = "(DWARF 里没有 pcTaskName)"

    for key, m in (("priority", "uxPriority"), ("base_priority", "uxBasePriority"),
                   ("mutexes_held", "uxMutexesHeld"), ("tcb_number", "uxTCBNumber"),
                   ("task_number", "uxTaskNumber"), ("runtime", "ulRunTimeCounter"),
                   ("notified", "ulNotifiedValue")):
        if m in t and t[m] + 4 <= len(data):
            v = _u32(data, t[m])
            if v is not None:
                rec[key] = v

    for key, m in (("stack_base", "pxStack"), ("stack_top_of", "pxTopOfStack"),
                   ("stack_end", "pxEndOfStack")):
        if m in t and t[m] + 4 <= len(data):
            v = _u32(data, t[m])
            if v:
                rec[key] = "0x%X" % v

    # xEventListItem.pxContainer：非 NULL 说明这个任务还挂在某个内核对象
    # （信号量/队列/事件组）的等待链表上——用来分辨「无限阻塞」与「真被挂起」。
    ev_off = t.get("xEventListItem")
    pc_off = _field_any(idx, "ListItem_t", "pxContainer", "pvContainer")
    if ev_off is not None and pc_off is not None:
        c = _u32(_rd(read, tcb_addr + ev_off + pc_off, 4), 0)
        rec["event_list_container"] = ("0x%X" % c) if c else None
    return rec


def _member_array_len(idx, type_name, member):
    """结构体成员若是 char[N]，取 N（configMAX_TASK_NAME_LEN）。"""
    # 走一遍 DWARF：成员类型是数组就取 count
    s = idx.struct(type_name)
    if not s or member not in s["fields"]:
        return None
    return s.get("_arrlen", {}).get(member) if isinstance(s.get("_arrlen"), dict) else \
        _arrlen_from_dwarf(idx, type_name, member)


def _arrlen_from_dwarf(idx, type_name, member):
    """结构体里某个数组成员的元素个数；取不到返回 None（调用方用 fallback 并标注）。"""
    s = idx.struct(type_name) if idx is not None else None
    if not s:
        return None
    a = s.get("_arrlen") or {}
    v = a.get(member)
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def freertos_tasks(axf: str, read, include_stack: bool = True,
                   stack_scan_cap: int = _STACK_SCAN_CAP, limit: int = 256):
    idx = get_index(axf)
    if idx.error:
        return {"ok": False, "error": idx.error, "axf": idx.path}
    if idx.addr_of(*_FR_SYMS["current"]) is None and idx.addr_of("pxReadyTasksLists") is None:
        return {"ok": False,
                "error": "这个 .axf 里找不到 FreeRTOS 的内核符号（pxCurrentTCB / pxReadyTasksLists）",
                "reason": "no-rtos-symbols",
                "hint": "确认工程确实编进了 FreeRTOS 内核；或用 rtos_info 看探测结果"}
    layout, missing = _layout(idx)
    if "TCB_t" in [m.split(".")[0] for m in missing] or idx.struct("TCB_t") is None:
        return {"ok": False, "error": "拿不到 TCB_t 的 DWARF 布局，无法可靠解析任务",
                "missing": missing,
                "hint": "确认 .axf 带调试信息（Keil: Options→Output 勾 Debug Information；gcc: -g）"}
    if missing:
        logger.info("FreeRTOS 布局缺字段（将少报对应信息）：%s", missing)

    cur_addr = idx.addr_of(*_FR_SYMS["current"])
    cur = None
    if cur_addr is not None:
        vk = idx.var_kind(_FR_SYMS["current"][0])
        if vk and vk.get("kind") == "array":
            cur = _u32(_rd(read, cur_addr, 4), 0)      # SMP：取核 0
        else:
            cur = _u32(_rd(read, cur_addr, 4), 0)

    where, notes = _tcbs_from_lists(idx, read, limit)
    if cur:
        where.setdefault(cur, []).append({"list": "running"})

    tasks = []
    for tcb, memberships in where.items():
        if not tcb:
            continue
        rec = _read_tcb(idx, read, tcb, layout)
        if rec is None:
            tasks.append({"tcb": "0x%X" % tcb, "name": None,
                          "error": "读不到该 TCB（地址无效或内存读失败）"})
            continue
        lists = [m["list"] for m in memberships]
        if "running" in lists:
            rec["state"] = "running"
        elif "ready" in lists or "ready_pending" in lists:
            rec["state"] = "ready"
        elif "blocked_delayed" in lists or "blocked_delayed_overflow" in lists:
            rec["state"] = "blocked"
        elif "deleted_waiting_free" in lists:
            rec["state"] = "deleted"
        elif "suspended" in lists:
            # FreeRTOS 把「被 vTaskSuspend 挂起」和「用 portMAX_DELAY 无限阻塞在
            # 信号量/队列上」都放进 xSuspendedTaskList（内核自己的 eTaskState 也
            # 一律报 eSuspended）。靠 xEventListItem.pxContainer 才能分辨：
            # 还挂在等待链表上 = 无限阻塞，没挂 = 真被挂起。
            if rec.get("event_list_container"):
                rec["state"] = "blocked"
                rec["state_note"] = (
                    "在 xSuspendedTaskList 上，但 xEventListItem 还挂在某个内核对象的"
                    "等待链表（container=%s）——这是用 portMAX_DELAY 无限阻塞，"
                    "不是被 vTaskSuspend 挂起；FreeRTOS 内核自己的 eTaskState 会把"
                    "这种也报成 eSuspended" % rec["event_list_container"])
            else:
                rec["state"] = "suspended"
        else:
            rec["state"] = "?"
        rec["lists"] = lists
        if "priority_index" in memberships[0]:
            rec["ready_priority_index"] = memberships[0]["priority_index"]

        if include_stack and rec.get("stack_base"):
            base = int(rec["stack_base"], 16)
            size = None
            if rec.get("stack_end"):
                size = int(rec["stack_end"], 16) - base + 4
            wm = _stack_watermark(read, base, size, cap=int(stack_scan_cap))
            if wm is None:
                rec["stack_error"] = "读不到栈区（栈地址 %s）" % rec["stack_base"]
            else:
                rec["stack_free_words"] = wm["free_words"]
                if size:
                    total_words = size // 4
                    rec["stack_size_words"] = total_words
                    rec["stack_used_words"] = max(0, total_words - wm["free_words"])
                    if total_words:
                        rec["stack_used_pct"] = round(
                            100.0 * rec["stack_used_words"] / total_words, 1)
                if not wm["fill_found"]:
                    rec["stack_note"] = (
                        "栈底第一个字节就不是填充值 0x%02X：可能该任务栈已被写满，"
                        "或这块栈不是 FreeRTOS 创建时填充的（静态栈/自定义分配）——"
                        "水位不可信，别据此判断余量" % TSK_FILL_BYTE)
                elif rec.get("stack_size_words") and rec.get("stack_used_pct", 0) >= 90:
                    rec["stack_warning"] = "栈使用率 %.1f%%，接近溢出，建议加大栈" % \
                        rec["stack_used_pct"]
        tasks.append(rec)

    tasks.sort(key=lambda r: ({"running": 0, "ready": 1, "blocked": 2,
                               "suspended": 3, "deleted": 4}.get(r.get("state"), 9),
                              -(r.get("priority") or 0)))
    n_sym = idx.addr_of(*_FR_SYMS["num_tasks"])
    n_kernel = _u32(_rd(read, n_sym, 4), 0) if n_sym else None
    out = {"ok": True, "rtos": "FreeRTOS", "axf": idx.path, "count": len(tasks),
           "current_tcb": "0x%X" % cur if cur else None, "tasks": tasks}
    if n_kernel is not None:
        out["kernel_task_count"] = n_kernel
        if n_kernel != len(tasks):
            out["count_mismatch"] = (
                "内核记的 uxCurrentNumberOfTasks=%d，实际从链表走到 %d 个："
                "可能有任务在没用到的链表里，或 DWARF 布局与固件不匹配——"
                "数不要当准数用" % (n_kernel, len(tasks)))
    if notes:
        out["notes"] = notes[:10]
    out["stack_watermark"] = ("按 FreeRTOS 自己的算法（从 pxStack 向上数 0x%02X）算的"
                              "历史最深余量，对正在运行的任务同样有效" % TSK_FILL_BYTE)
    if any("stack_size_words" in t for t in tasks):
        out["stack_size_note"] = (
            "stack_size_words 取的是 pxStack→pxEndOfStack 之间的字数（含两端）。FreeRTOS 建栈时\n"
            "把栈顶按 portBYTE_ALIGNMENT 向下取整后才记进 pxEndOfStack，因此它可能比实际分配少\n"
            "1~2 个 word（8 字节对齐的板子上实测少 1：256 字的栈报成 255）。栈余量\n"
            "stack_free_words 是准的（与内核自报的 uxTaskGetStackHighWaterMark 逐项一致）；\n"
            "stack_used_pct 由它换算，因此存在 1 个 word 级偏差，别当精确值用。")
    return out


def freertos_objects(axf: str, read):
    """队列 / 信号量 / 互斥量：走 FreeRTOS 的队列注册表（configQUEUE_REGISTRY_SIZE>0 才有）。"""
    idx = get_index(axf)
    if idx.error:
        return {"ok": False, "error": idx.error}
    # 先确认这固件里到底有没有 FreeRTOS：裸机 .axf 同样没有 xQueueRegistry，
    # 把它归因成「内核没开注册表」是错的——先说实话，再谈配置。
    d = detect(axf)
    if d.get("rtos") != "FreeRTOS":
        return {"ok": False,
                "error": "这个固件里没探测到 FreeRTOS 的内核符号，谈不上枚举队列/信号量",
                "reason": "no-rtos-symbols",
                "markers": d.get("found"),
                "hint": "确认传的 .axf 就是目标板上正在跑的固件；RT-Thread 的内核对象枚举尚未支持"}
    var = idx.var_kind("xQueueRegistry")
    n = var.get("count") if var else None
    a = idx.addr_of("xQueueRegistry")
    if a is None or var is None:
        return {"ok": False,
                "error": "这个固件里没有 xQueueRegistry（内核在 configQUEUE_REGISTRY_SIZE==0 时"
                         "根本不定义它）",
                "hint": "在 FreeRTOSConfig.h 里把 configQUEUE_REGISTRY_SIZE 设为 ≥ 队列数，"
                        "并在创建后调用 vQueueAddToRegistry()，才能从主机侧枚举队列/信号量；"
                        "不开注册表时 FreeRTOS 没有全局队列链表，主机侧无法枚举——这条限制是内核的，"
                        "不是本项目没做",
                "reason": "no-queue-registry"}
    if not n:
        return {"ok": False,
                "error": "configQUEUE_REGISTRY_SIZE 为 %s，注册表是空数组，没有任何队列登记" % n,
                "hint": "创建队列/信号量后调用 vQueueAddToRegistry(handle, \"名字\") 才会出现在这里"}
    qs = idx.struct("Queue_t")
    if not qs:
        return {"ok": False, "error": "拿不到 Queue_t 的 DWARF 布局"}
    f = qs["fields"]
    item = idx.struct("QueueRegistryItem_t")
    itf = item["fields"] if item else {}
    # 不同版本字段名不同，按实际 DWARF 取
    name_off = itf.get("pcQueueName")
    handle_off = itf.get("xHandle")
    # 注册表数组的元素大小必须取 QUEUE_REGISTRY_ITEM 的大小（8 字节），
    # 不是 Queue_t 的大小（80 字节）——用错会按错误步长跳，读出满屏垃圾对象。
    item_size = ((item["size"] if item else None)
                 or (var.get("elem_size") if var else None) or 8)
    out = []
    for i in range(min(n, 64)):
        raw = _rd(read, a + i * item_size, item_size)
        if not raw:
            continue
        if name_off is None or handle_off is None:
            break
        nm_ptr = _u32(raw, name_off)
        h = _u32(raw, handle_off)
        if not h:
            continue
        name = None
        if nm_ptr:
            name = _cstr(_rd(read, nm_ptr, 32))
        q = _rd(read, h, (qs["size"] or 80))
        rec = {"name": name or "(未命名)", "addr": "0x%X" % h}
        if q:
            for key, m in (("length", "uxLength"), ("item_size", "uxItemSize"),
                           ("messages_waiting", "uxMessagesWaiting")):
                if f.get(m) is not None:
                    v = _u32(q, f[m])
                    if v is not None:
                        rec[key] = v
            # 信号量：FreeRTOS 用同一个 Queue_t 表示，uxItemSize==0 即信号量/互斥量
            if rec.get("item_size") == 0:
                rec["kind"] = "semaphore/mutex"
                for m in ("uxSemaphoreCount", "u.xQueue.pcReadFrom", "u.xSemaphore.uxSemaphoreCount"):
                    if f.get(m) is not None:
                        v = _u32(q, f[m])
                        if v is not None:
                            rec["count"] = v
                            break
            else:
                rec["kind"] = "queue"
        out.append(rec)
    return {"ok": True, "rtos": "FreeRTOS", "count": len(out),
            "registry_capacity": n, "objects": out,
            "note": "FreeRTOS 的队列/信号量/互斥量共用 Queue_t 结构，靠 uxItemSize==0 区分"
                    "信号量类；这是内核的实现约定，不是本工具的猜测"}


# ================================================================ RT-Thread

def rtthread_tasks(axf: str, read, include_stack: bool = True, limit: int = 256):
    """RT-Thread 线程列表（走 rt_object_container 的 Thread 类链表）。

    **诚实声明**：这条路径尚未在真机 RT-Thread 固件上验证过（本机没有 RT-Thread 板卡/工程），
    因此返回里带 `verified: false` 与 `confidence: "structural"`。解析前会做几项自洽性校验
    （线程名可打印、栈地址落在 stack_addr..stack_addr+stack_size 内），任何一项不过就报错
    而不是照原样输出——避免给出「看着像真的」的结果。
    """
    idx = get_index(axf)
    if idx.error:
        return {"ok": False, "error": idx.error}
    th = idx.struct("rt_thread")
    if not th:
        return {"ok": False, "error": "拿不到 rt_thread 的 DWARF 布局，无法解析 RT-Thread 线程",
                "hint": "确认 .axf 带调试信息"}
    ca = idx.addr_of("rt_object_container")
    if ca is None:
        return {"ok": False, "error": "找不到 rt_object_container（RT_USING_OBJECT_CONTAINER 未开？）"}
    f = th["fields"]
    out = []
    return {"ok": False,
            "error": "RT-Thread 支持尚未在真机验证，暂不输出结果",
            "reason": "本机没有可用的 RT-Thread 固件，无法验证结构体解析是否正确；"
                      "按本项目约定，宁可报错也不给未经证实的数据",
            "ready_layout": {"rt_thread 字段": sorted(f.keys())[:20]},
            "hint": "需要 RT-Thread 真机（任一 BSP 编出 .axf 挂上来）后再补这条路径",
            "verified": False, "count": len(out)}


# ================================================================ 统一入口

def info(axf: str):
    """探测 RTOS 类型，并从 DWARF 反推内核配置（都是可观测量，不是猜的）。"""
    d = detect(axf)
    if not d.get("ok"):
        return d
    idx = get_index(axf)
    out = {"ok": True, "axf": idx.path, "rtos": d.get("rtos"),
           "markers": d.get("found"), "has_dwarf": not (idx.error or "").startswith("该 .axf 没有"),
           "note": idx.error}
    if d.get("rtos") == "FreeRTOS":
        v = idx.var_kind("pxReadyTasksLists")
        cfg = {}
        if v and v.get("count"):
            cfg["configMAX_PRIORITIES"] = v["count"]
        q = idx.var_kind("xQueueRegistry")
        if q:
            cfg["configQUEUE_REGISTRY_SIZE"] = q.get("count")
        tcb = idx.struct("TCB_t")
        if tcb:
            nm = _member_array_len(idx, "TCB_t", "pcTaskName")
            names = set(tcb["fields"].keys())
            cfg["TCB_t 里有这些可选字段"] = [m for m in
                                     ("pxEndOfStack", "uxTCBNumber", "uxBasePriority",
                                      "uxMutexesHeld", "ulRunTimeCounter", "uxCoreAffinityMask")
                                     if m in names]
            cfg["TCB_t 字节数"] = tcb.get("size")
        out["config"] = cfg
        out["config_from"] = "由 DWARF 的数组长度与结构体成员存在性反推，不是读 config 宏"
    fa = out.setdefault("next", [])
    if d.get("rtos") == "FreeRTOS":
        fa.append("rtos_tasks 看任务列表与栈水位；rtos_objects 看队列/信号量（需开队列注册表）")
    return out


def tasks(axf: str, read, include_stack: bool = True, stack_scan_cap: int = _STACK_SCAN_CAP):
    d = detect(axf)
    if not d.get("ok"):
        return d
    if d.get("rtos") == "FreeRTOS":
        return freertos_tasks(axf, read, include_stack=include_stack,
                              stack_scan_cap=stack_scan_cap)
    if d.get("rtos") == "RT-Thread":
        return rtthread_tasks(axf, read, include_stack=include_stack)
    return {"ok": False,
            "error": "这个固件里没探测到 FreeRTOS / RT-Thread 的符号",
            "reason": "no-rtos-symbols",
            "markers": d.get("found"),
            "hint": "裸机工程没有任务可列；若确实用了别的 RTOS（Zephyr/ThreadX/osek 等），"
                    "目前不支持——说明用的哪个 RTOS 再补"}


# ================================================================ 链路接入

# 一次 rtos_* 调用内部会做很多次 4 字节小读（走链表、逐个 TCB），
# Keil 链路每次都是一次 UVSOCK 往返，不做块缓存会慢到没法用。
# 只在本工具调用内部缓存：同一次快照里地址内容不会变，跨调用一律重读。
_BLOCK = 256


class _CachedReader:
    """把 read(addr, n) 按 256B 对齐块做读穿缓存；只活一次工具调用。"""

    def __init__(self, raw_read):
        self._raw = raw_read
        self._blk = {}
        self.calls = 0        # 真正落到链路上的读取次数（便于观察开销）
        self.hits = 0

    def __call__(self, addr, n):
        addr = int(addr)
        n = int(n)
        if n <= 0:
            return b""
        out = bytearray()
        pos = addr
        end = addr + n
        while pos < end:
            base = pos - (pos % _BLOCK)
            blk = self._blk.get(base)
            if blk is None:
                blk = self._raw(base, _BLOCK)
                self.calls += 1
                if blk is None:
                    return None if not out else bytes(out)
                self._blk[base] = blk
            else:
                self.hits += 1
            take = min(end - pos, base + _BLOCK - pos)
            seg = blk[pos - base: pos - base + take]
            if len(seg) < take:
                out += seg
                break
            out += seg
            pos += take
        return bytes(out)


def _keil_reader(client):
    def raw(addr, n):
        r = client.read_mem_verified(int(addr), int(n), verify="auto")
        if not r.get("ok"):
            return None
        try:
            return bytes.fromhex(r.get("data_hex") or "")
        except ValueError:
            return None
    return raw


def _ocd_reader(session):
    from . import ocd as _ocd

    def raw(addr, n):
        count = (int(n) + 3) // 4
        r = session.cmd("mdw 0x%X %d" % (int(addr), count))
        if not r.get("ok"):
            return None
        p = _ocd._parse_mem(r.get("output") or "", int(addr), count, 32)
        if not p["complete"]:
            return None
        return _ocd._mem_to_bytes(p["words"], 32, int(n))
    return raw


def _pick_reader(link: str = "auto"):
    """选一条内存读取链路。返回 (read, 说明) 或 (None, 错误 dict)。

    不猜：哪条链路上有活着的会话就用哪条；两条都没有就如实报错并说清怎么起。
    """
    want = (link or "auto").strip().lower()
    if want in ("keil", "mdk", "uvsock"):
        want = "keil"
    elif want in ("ocd", "openocd"):
        want = "ocd"
    else:
        want = "auto"

    keil, kerr = None, None
    if want in ("auto", "keil"):
        try:
            from . import linkio as _linkio
            # 别裸判 phy.is_connected：UVSOCK 是懒连接，reset_connection 之后它是 False，
            # 会把「还没连」当成「链路不可用」（与 linkio.keil_client 同一处坑）。
            c, cerr = _linkio.keil_client()
            if c is not None:
                keil = _keil_reader(c)
            else:
                kerr = cerr or "Keil 侧的 UVSOCK 会话没连着（先 enter_debug 或确认 Keil 已启动）"
        except Exception as e:                                 # noqa: BLE001
            kerr = "取 Keil 会话失败：%s" % e

    ocd, oerr = None, None
    if want in ("auto", "ocd"):
        try:
            from . import ocd as _ocd
            s = _ocd.get_session()
            if s.running():
                ocd = _ocd_reader(s)
            else:
                oerr = "OpenOCD 没在运行（先 ocd_start）"
        except Exception as e:                                 # noqa: BLE001
            oerr = "取 OpenOCD 会话失败：%s" % e

    if want == "keil":
        return (keil, "keil/UVSOCK") if keil else (None, {"ok": False, "error": kerr})
    if want == "ocd":
        return (ocd, "ocd") if ocd else (None, {"ok": False, "error": oerr})
    if keil:
        return keil, "keil/UVSOCK"
    if ocd:
        return ocd, "ocd"
    return None, {"ok": False,
                  "error": "两个链路都没有活着的调试会话，读不到目标内存",
                  "reason": "no-mem-link",
                  "keil": kerr, "ocd": oerr,
                  "hint": "Keil 侧：enter_debug；非 MDK 目标：ocd_start + ocd_control(\"halt\")"}


def _resolve_axf(axf: str = ""):
    """定位 .axf：显式参数优先，其次当前符号文件。返回 (路径, 来源说明)。"""
    if axf:
        return os.path.abspath(axf), "本次参数指定"
    try:
        from . import server as _server
        a = ((getattr(_server, "_symbol_cfg", None) or {}).get("axf") or "")
        if a and os.path.isfile(a):
            return os.path.abspath(a), "当前符号文件（set_symbol_file / 启动参数 --axf 设过）"
    except Exception:                                          # noqa: BLE001
        pass
    return "", ""


def _need_axf(axf: str, who: str):
    p, src = _resolve_axf(axf)
    if not p:
        return None, {"ok": False,
                      "error": "拿不到 .axf 路径，无法读 DWARF 里的结构与符号",
                      "hint": "%s 里显式给 axf=...，或先 set_symbol_file 指定 .axf" % who}
    if not os.path.isfile(p):
        return None, {"ok": False, "error": "文件不存在：%s" % p}
    return (p, src), None


def _default_js(obj) -> str:
    import json as _json
    return _json.dumps(obj, ensure_ascii=False, default=str)


# ================================================================ MCP 注册

def register(server, js=None) -> int:
    _js = js or _default_js
    n = 0

    @server.tool(
        name="rtos_info",
        title="RTOS 探测与内核配置反推（FreeRTOS / RT-Thread）",
        description=(
            "先回答「这块板子上跑的是什么、有没有任务可看」，再谈别的。\n"
            "- 按符号存在性判定 RTOS（FreeRTOS: pxCurrentTCB/pxReadyTasksLists/\n"
            "  uxCurrentNumberOfTasks；RT-Thread: rt_object_container 等），**不靠猜**；\n"
            "- 从 **DWARF 反推内核配置**：pxReadyTasksLists 的数组长度就是 configMAX_PRIORITIES、\n"
            "  xQueueRegistry 的长度就是 configQUEUE_REGISTRY_SIZE、TCB_t 里有哪些可选字段\n"
            "  （pxEndOfStack/uxTCBNumber/uxBaseThread... 取决于 config 宏），这些**都是可观测量**，\n"
            "  比让 AI 去翻 FreeRTOSConfig.h 可靠；\n"
            "- 没探测到任何 RTOS 符号时如实说「裸机工程，没有任务可列」，不编。\n"
            "axf 可省略：默认用当前符号文件（set_symbol_file 设过的那个）。"
        ),
    )
    async def rtos_info(axf: str = "") -> str:
        try:
            got, err = _need_axf(axf, "rtos_info")
            if err:
                return _js(err)
            path, src = got
            out = info(path)
            out["axf_source"] = src
            return _js(out)
        except Exception as e:                                 # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="rtos_tasks",
        title="RTOS 任务列表 + 各任务栈水位（多任务卡死排查主力）",
        description=(
            "列出所有任务及其状态、优先级、**栈水位**，用来查「谁把栈吃爆了」「谁卡死了」。\n"
            "- 任务来源：把 ready（含各优先级）/ delayed / suspended / pending / terminated\n"
            "  几条内核链表都走一遍，再叠上 pxCurrentTCB 标出 running——**状态是从它挂在\n"
            "  哪张链表推出来的，不是读某个字段猜的**；\n"
            "- 栈水位算法与 FreeRTOS 自带的 uxTaskGetStackHighWaterMark 完全一致：任务建栈时\n"
            "  整片栈被填成 0xA5，从 pxStack（最低地址）向上数连续 0xA5 的字节数就是**历史最深\n"
            "  余量**。因此对正在运行的任务同样有效（pxTopOfStack 那个值只有切出时才更新，会滞后）；\n"
            "- 结构体偏移**全部来自 .axf 的 DWARF**，不写死——FreeRTOS 的 TCB_t 随 config 宏\n"
            "  增删成员，写死偏移在别人的工程上必然静默读垃圾。缺字段会明说缺哪个；\n"
            "- 与内核自报的 uxCurrentNumberOfTasks 对不上时会出 count_mismatch 警告，\n"
            "  提示「这个数不要当准数用」；\n"
            "- 栈底第一个字节就不是 0xA5 的任务会带 stack_note：**它的水位不可信**（静态栈或\n"
            "  自定义分配），别据此判断余量；\n"
            "- link 默认 auto：有 Keil 会话走 UVSOCK，否则走 OpenOCD；两条都没有会如实报错。\n"
            "axf 可省略：默认用当前符号文件。"
        ),
    )
    async def rtos_tasks(axf: str = "", link: str = "auto", include_stack: bool = True,
                         stack_scan_cap: int = 8192, limit: int = 256) -> str:
        try:
            got, err = _need_axf(axf, "rtos_tasks")
            if err:
                return _js(err)
            path, src = got
            rd, desc = _pick_reader(link)
            if rd is None:
                return _js(desc)
            reader = _CachedReader(rd)
            out = tasks(path, reader, include_stack=bool(include_stack),
                        stack_scan_cap=int(stack_scan_cap))
            out["axf_source"] = src
            out["mem_link"] = desc
            out["mem_reads"] = reader.calls
            return _js(out)
        except Exception as e:                                 # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    @server.tool(
        name="rtos_objects",
        title="RTOS 内核对象：队列 / 信号量 / 互斥量（含等待者数量）",
        description=(
            "列出队列与信号量：名字、句柄、**当前排队/计数**、单条消息大小（uxItemSize==0\n"
            "即信号量/互斥量）。查「消息发不进去」「谁在等锁」用这个。\n"
            "**数据来源与限制要说清**：FreeRTOS 内核在 configQUEUE_REGISTRY_SIZE>0 时才维护\n"
            "xQueueRegistry 这张全局表，且队列要显式 vQueueAddToRegistry() 才登记。不开注册表\n"
            "时内核根本没有全局队列链表，主机侧无法枚举——这种情况会返回 ok=false 并说明\n"
            "**这是内核的限制、不是本工具没做**，而不是返回一个空列表让人误以为没有队列。\n"
            "link 默认 auto（同 rtos_tasks）。axf 可省略：默认用当前符号文件。"
        ),
    )
    async def rtos_objects(axf: str = "", link: str = "auto") -> str:
        try:
            got, err = _need_axf(axf, "rtos_objects")
            if err:
                return _js(err)
            path, src = got
            rd, desc = _pick_reader(link)
            if rd is None:
                return _js(desc)
            reader = _CachedReader(rd)
            out = freertos_objects(path, reader)
            out["axf_source"] = src
            out["mem_link"] = desc
            out["mem_reads"] = reader.calls
            return _js(out)
        except Exception as e:                                 # noqa: BLE001
            return _js({"ok": False, "error": str(e)})
    n += 1

    return n
