# -*- coding: utf-8 -*-
"""重定位偏移（reloc_delta）的自证与推导（批次48）。

为什么需要
----------
App 运行期重定位后：**运行地址 = .axf 链接地址 + delta**（SVCrtOS 里是 0xF000）。
delta 是**跨编译会变**的——布局一变偏移就错。旧实现下偏移错了不会报任何东西，
读出来只是「全 0」，调用方极易把「偏移失效」误判成「变量被清零」，被静默带沟里
（用户真实踩到）。

本模块把 delta 从「一个口头约定」变成**可证伪的事实**：

* :func:`verify` —— 拿 ELF 可加载段的**原始字节**当内容指纹，与目标内存逐样本比对，
  对 delta 给出 ``delta-confirmed`` / ``delta-likely-wrong`` / ``delta-uncertain``，
  而不是沉默。样本一律避开「全 0x00 / 全 0xFF」的退化块——那种块在哪儿都长得一样，
  拿它当指纹只会给出假的确定感。
* :func:`derive_from_pc` —— 读运行态 PC 处的代码字节，回到 ELF 里反查这段代码的
  链接地址，直接**算出** delta；匹配到多处或一处都匹配不上时如实说「定不了」，
  绝不猜一个像样的数字。

两条底线与全项目一致：**能测到才说、测不到就说测不到**；宁可报「验证不了」，
也不给「看似权威的错答案」。
"""
from __future__ import annotations

import logging
import os

from elftools.elf.elffile import ELFFile  # pyelftools
from elftools.elf.constants import SH_FLAGS

logger = logging.getLogger(__name__)

#: 内容指纹的默认块大小（字节）
SAMPLE_BYTES = 32

#: 默认取样条数
SAMPLE_COUNT = 8

#: 反推 delta 时读 PC 处代码的字节数
PC_PROBE_BYTES = 96

#: 段缓存：{path: (mtime, segments)}
_SEG_CACHE: dict = {}

def load_segments(elf_path: str):
    """加载 ELF 里**会被加载进内存**的段（SHF_ALLOC 且非 NOBITS），按 vaddr 排序。

    返回 [{name, vaddr, size, offset, data}]；data 为该段在文件里的原始字节。
    NOBITS（.bss）在文件里没有内容，不能当指纹，直接排除。
    """
    path = os.path.abspath(elf_path or "")
    if not path or not os.path.isfile(path):
        return []
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0
    hit = _SEG_CACHE.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    segs = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                try:
                    flags = sec["sh_flags"]
                    if not (flags & SH_FLAGS.SHF_ALLOC):
                        continue
                    if sec["sh_type"] == "SHT_NOBITS":
                        continue
                    size = int(sec["sh_size"])
                    off = int(sec["sh_offset"])
                    if size <= 0 or off < 0:
                        continue
                    f.seek(off)
                    data = f.read(size)
                except Exception as e:  # noqa: BLE001
                    logger.debug("跳过段 %s：%s", getattr(sec, "name", "?"), e)
                    continue
                if not data:
                    continue
                segs.append({"name": sec.name, "vaddr": int(sec["sh_addr"]),
                             "size": len(data), "offset": off, "data": data})
    except Exception as e:  # noqa: BLE001
        logger.warning("读取 ELF 段失败（%s）：%s", path, e)
        return []
    segs.sort(key=lambda s: s["vaddr"])
    _SEG_CACHE[path] = (mtime, segs)
    return segs

def image_bytes_at(elf_path: str, addr: int, n: int):
    """取 ELF 里「链接地址 addr 起 n 字节」的原始内容；不在任何可加载段内返回 None。"""
    want = int(addr)
    for s in load_segments(elf_path):
        if s["vaddr"] <= want < s["vaddr"] + s["size"]:
            off = want - s["vaddr"]
            return s["data"][off:off + int(n)]
    return None

def _read_mem_bytes(client, addr: int, n: int):
    """从目标读 n 字节；读不到/退化返回 None（由调用方决定怎么报）。"""
    try:
        r = client.read_mem(int(addr), int(n))
    except Exception as e:  # noqa: BLE001
        logger.debug("读目标内存失败 0x%X：%s", addr, e)
        return None
    if not isinstance(r, dict) or not r.get("ok"):
        return None
    hx = (r.get("data_hex") or "").strip()
    if not hx:
        return None
    try:
        b = bytes.fromhex(hx)
    except ValueError:
        return None
    return b or None

def _is_degenerate(chunk: bytes) -> bool:
    """全 0x00 / 全 0xFF 的块在哪儿都长得一样，不能当指纹。"""
    return bool(chunk) and (chunk.count(0) == len(chunk) or chunk.count(0xFF) == len(chunk))

def _pick_samples(segs, n: int, samples: int):
    """从可加载段里挑出「非退化」的 n 字节块，均匀取 samples 条。"""
    cands = []
    for s in segs:
        data = s["data"]
        for off in range(0, max(0, len(data) - n + 1), n):
            chunk = data[off:off + n]
            if len(chunk) < n or _is_degenerate(chunk):
                continue
            cands.append((s["vaddr"] + off, chunk))
    if len(cands) <= samples:
        return cands
    step = len(cands) / float(samples)
    return [cands[int(i * step)] for i in range(samples)]

def _fmt_delta(delta: int) -> str:
    d = int(delta) & 0xFFFFFFFF
    return "0x%X" % d

def _signed(delta: int) -> int:
    d = int(delta) & 0xFFFFFFFF
    return d - 0x100000000 if d >= 0x80000000 else d

def verify(client, elf_path: str, delta: int = 0, samples: int = SAMPLE_COUNT,
           n: int = SAMPLE_BYTES):
    """用内容指纹证实/证伪 delta。

    做法：ELF 里挑若干**非退化**的 n 字节块，按「链接地址 + delta」到目标读同样长度，
    逐字节比对。全中即 confirmed；一条都不中即 likely-wrong；部分命中给 uncertain。

    返回里 ``ok`` 只表示「检查跑完了」（不代表 delta 正确，看 ``verdict`` /
    ``confirmed``）——这是全项目统一的语义，免得把「跑完了」读成「没问题」。
    """
    out = {"ok": False, "elf": os.path.abspath(elf_path or ""),
           "delta": _fmt_delta(delta), "delta_int": _signed(delta),
           "sample_bytes": int(n), "samples": 0, "matched": 0,
           "confirmed": False, "verdict": "no-sample", "details": []}
    segs = load_segments(elf_path)
    if not segs:
        out["reason"] = "读不到 .axf 的可加载段（文件不存在 / 无内容 / 非 ELF）"
        return out
    want = max(1, int(samples or SAMPLE_COUNT))
    picks = _pick_samples(segs, max(4, int(n)), want)
    if not picks:
        out["reason"] = (".axf 可加载段里找不到可用的内容指纹（样本全是 0x00/0xFF，"
                         "没有区分度）——无法据此判断偏移，请勿据此下结论")
        return out
    out["samples"] = len(picks)
    details = []
    for link, chunk in picks:
        run = (link + int(delta)) & 0xFFFFFFFF
        mem = _read_mem_bytes(client, run, len(chunk))
        item = {"link_address": "0x%08X" % link, "run_address": "0x%08X" % run,
                "elf_hex": chunk.hex(), "matched": False}
        if mem is None:
            item["error"] = "目标内存读不到（目标在运行 / 地址不可读 / 未进入调试）"
        else:
            item["mem_hex"] = mem.hex()
            item["matched"] = (mem == chunk)
        details.append(item)
    out["details"] = details
    out["matched"] = sum(1 for d in details if d.get("matched"))
    readable = sum(1 for d in details if "mem_hex" in d)
    out["readable"] = readable
    if readable == 0:
        out["verdict"] = "unreadable"
        out["reason"] = "一个样本都没读到目标内存（目标在运行 / 未进入调试 / 地址不可读），无法验证偏移"
        return out
    out["ok"] = True
    if out["matched"] == out["samples"]:
        out["verdict"] = "delta-confirmed"
        out["note"] = ("%d/%d 个内容指纹与目标内存逐字节一致：reloc_delta=%s 与实际布局相符"
                       % (out["matched"], out["samples"], _fmt_delta(delta)))
    elif out["matched"] == 0:
        out["verdict"] = "delta-likely-wrong"
        out["note"] = ("%d/%d 个内容指纹**一条都没对上**：reloc_delta=%s 与实际布局不符"
                       "（跨编译后布局变了？）。**不要**把「读出全 0」当成「变量被清零」，"
                       "先用 derive/reloc_check 拿到正确的 delta。"
                       % (out["matched"], out["samples"], _fmt_delta(delta)))
    else:
        out["verdict"] = "delta-uncertain"
        out["note"] = ("%d/%d 个内容指纹命中：既不能确认也不能否定 reloc_delta=%s"
                       "（部分地址可能已被运行期改写）" % (out["matched"], out["samples"],
                                                          _fmt_delta(delta)))
    out["confirmed"] = (out["verdict"] == "delta-confirmed")
    return out

def _find_pattern_in_elf(segs, pattern: bytes, limit: int = 8):
    """在可加载段里找 pattern，返回 [{vaddr(链接地址), seg}]（最多 limit 条）。"""
    hits = []
    for s in segs:
        data = s["data"]
        start = 0
        while len(hits) < limit:
            i = data.find(pattern, start)
            if i < 0:
                break
            hits.append({"link_address": s["vaddr"] + i, "segment": s["name"]})
            start = i + 1
    return hits

def derive_from_pc(client, elf_path: str, pc=None, n: int = PC_PROBE_BYTES):
    """从当前 PC 处的代码字节反推 delta：delta = PC − ELF 里的链接地址。

    pc 不传则自动读 CPU 寄存器。匹配不到或用多处匹配时**如实报定不了**，不猜。
    """
    out = {"ok": False, "elf": os.path.abspath(elf_path or ""),
           "pc": None, "delta": None, "delta_int": None, "hits": []}
    if pc is None:
        try:
            regs = client.read_cpu_registers_stable()
            if isinstance(regs, dict) and isinstance(regs.get("pc"), int):
                pc = regs["pc"]
        except Exception as e:  # noqa: BLE001
            logger.debug("读 PC 失败：%s", e)
    if not isinstance(pc, int):
        out["reason"] = "拿不到当前 PC（未进入调试 / 目标在运行 / 寄存器读不到），无法反推 delta"
        return out
    pc = int(pc) & ~1
    out["pc"] = "0x%08X" % pc
    segs = load_segments(elf_path)
    if not segs:
        out["reason"] = "读不到 .axf 的可加载段，无法反推 delta"
        return out
    code = _read_mem_bytes(client, pc, max(16, int(n)))
    if not code:
        out["reason"] = ("读不到 PC=0x%08X 处的代码字节（目标在运行 / 该地址不可读）" % pc)
        return out
    hits = []
    used_len = 0
    for plen in (int(n), 64, 48, 32, 16):
        if plen > len(code):
            continue
        hits = _find_pattern_in_elf(segs, code[:plen])
        used_len = plen
        if hits:
            break
    out["pattern_bytes"] = used_len
    if not hits:
        out["reason"] = ("在 .axf 里找不到与 PC 处代码字节匹配的片段——"
                         "当前 .axf 与板上固件很可能不是同一次编译（符号已漂移），"
                         "先 set_symbol_file/重新编译，别拿它算偏移")
        return out
    if len(hits) > 1:
        out["ok"] = True
        out["ambiguous"] = True
        out["hits"] = [{"link_address": "0x%08X" % h["link_address"],
                        "segment": h["segment"]} for h in hits]
        out["reason"] = ("PC 处字节在 .axf 里匹配到 %d 处（重复代码/相同字面量），"
                         "无法唯一确定链接地址——不替你猜一个 delta" % len(hits))
        return out
    link = int(hits[0]["link_address"])
    delta = (pc - link) & 0xFFFFFFFF
    out["ok"] = True
    out["ambiguous"] = False
    out["link_address"] = "0x%08X" % link
    out["hits"] = [{"link_address": "0x%08X" % link, "segment": hits[0]["segment"]}]
    out["delta"] = _fmt_delta(delta)
    out["delta_int"] = _signed(delta)
    out["note"] = ("PC=0x%08X 处的代码在 .axf 里是链接地址 0x%08X（%s，匹配 %d 字节），"
                   "故 delta = %s" % (pc, link, hits[0]["segment"], used_len,
                                      _fmt_delta(delta)))
    return out
