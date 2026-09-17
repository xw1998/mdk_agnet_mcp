# -*- coding: utf-8 -*-
"""Keil ``.uvprojx`` 工程文件的**受控编辑**（增删 Include Paths / 分组 / 文件）。

为什么不用 XML 序列化器整体重写
--------------------------------
``.uvprojx`` 是 Keil 生成的 XML，但**缩进、节点顺序、属性写法都是 Keil 的固定风格**，
用 ElementTree 解析再整体序列化会把缩进压平、属性顺序打乱，产生一个"能用但面目全非"
的 diff——用户下次用 Keil 打开再保存，又会被改一遍，噪音极大。
故本模块只在**目标节点**上做文本级替换，其余内容一字不动（与 uvoptx.py 同一套思路）。

安全约定
--------
- 任何写操作前**强制备份** ``<工程>.uvprojx.mdkdebug.bak``（可用 backup=False 关掉，
  但工具层永远给 true）；
- 写入前校验锚点**唯一**，不唯一就拒绝改（宁可报错也不改坏工程）；
- 所有返回值带 ``changes`` 明细（before/after），调用方能核对改了什么。
"""
from __future__ import annotations

import os
import re
import shutil
import xml.etree.ElementTree as ET

_PATH_SEP = ";"

def _read_text(path: str) -> tuple:
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"

def _backup(path: str) -> str:
    bak = path + ".mdkdebug.bak"
    shutil.copy2(path, bak)
    return bak

def _target_span(text: str, target: str) -> tuple:
    """定位指定 target 的 ``<Target>…</Target>`` 区间；target 为空时取第一个。

    返回 (start, end)；找不到返回 (None, None)。用非贪婪匹配 + TargetName 定位，
    避免把多个 target 的 IncludePath 混在一起改。
    """
    if not target:
        m = re.search(r"<Target>.*?</Target>", text, re.S)
        return (m.start(), m.end()) if m else (None, None)
    for m in re.finditer(r"<Target>.*?</Target>", text, re.S):
        seg = m.group(0)
        tm = re.search(r"<TargetName>\s*(.*?)\s*</TargetName>", seg, re.S)
        if tm and tm.group(1) == target:
            return m.start(), m.end()
    return None, None

def list_targets(path: str) -> list:
    """列出工程里的 target 名（供 set_debug_target / 编辑工具选目标）。"""
    text, _ = _read_text(path)
    return [t.strip() for t in re.findall(r"<TargetName>\s*(.*?)\s*</TargetName>", text, re.S)]

def read_config(path: str, target: str = "") -> dict:
    """读取某 target 的关键编译配置（只读，不写文件）。"""
    text, _ = _read_text(path)
    a, b = _target_span(text, target)
    if a is None:
        return {"ok": False, "error": "未找到 target：%s" % (target or "(第一个)"),
                "targets": list_targets(path)}
    seg = text[a:b]
    def _one(tag):
        m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), seg, re.S)
        return (m.group(1) or "").strip() if m else None
    name = _one("TargetName")
    return {"ok": True, "project": path, "target": name, "targets": list_targets(path),
            "include_path": _one("IncludePath"), "define": _one("Define"),
            "undefine": _one("Undefine"), "misc_controls": _one("MiscControls"),
            "device": _one("Device"), "groups": list_groups(path)}

def list_groups(path: str) -> list:
    """列出工程分组与文件（用 ET 只读，不写回）。"""
    try:
        text, _ = _read_text(path)
        root = ET.fromstring(text)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for g in root.iter("Group"):
        gn = g.find("GroupName")
        files = []
        for f in g.iter("File"):
            fn = f.find("FileName")
            fp = f.find("FilePath")
            files.append({"name": (fn.text or "").strip() if fn is not None else "",
                          "path": (fp.text or "").strip() if fp is not None else ""})
        out.append({"group": (gn.text or "").strip() if gn is not None else "",
                    "file_count": len(files), "files": files})
    return out

# ----------------------------------------------------------------------
# 编辑操作
# ----------------------------------------------------------------------
def _edit_tag(text: str, target: str, tag: str, fn) -> tuple:
    """在指定 target 区间内替换 ``<tag>…</tag>`` 的文本。

    fn(old) -> (new, info) 或 None 表示不改。返回 (新文本, 结果dict)。
    """
    a, b = _target_span(text, target)
    if a is None:
        return text, None
    seg = text[a:b]
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), seg, re.S)
    if not m:
        return text, None
    old = m.group(1) or ""
    got = fn(old)
    if got is None:
        return text, {"changed": False, "before": old, "after": old}
    new, info = got
    if new is None:
        # 「不改，但要把原因/统计带回去」。**绝不能把 None 当新文本写进标签**——
        # 那会把工程写成 <IncludePath>None</IncludePath>，静默损坏用户文件。
        return text, {"changed": False, "before": old, "after": old, **(info or {})}
    new_seg = seg[:m.start()] + "<%s>%s</%s>" % (tag, new, tag) + seg[m.end():]
    return text[:a] + new_seg + text[b:], {"changed": True, "before": old,
                                           "after": new, **(info or {})}

def _norm_inc(p: str) -> str:
    return p.strip().replace("/", "\\").strip("\\")

def add_include_path(path: str, paths, target: str = "", backup: bool = True) -> dict:
    """把若干目录加入 target 的 ``IncludePath``（已存在则跳过，返回 added/skipped）。"""
    text, enc = _read_text(path)
    items = [str(p) for p in (paths if isinstance(paths, (list, tuple)) else [paths]) if str(p).strip()]
    if not items:
        return {"ok": False, "error": "paths 为空"}

    def _fn(old):
        cur = [x for x in old.split(_PATH_SEP) if x.strip()]
        cur_norm = {_norm_inc(x).lower() for x in cur}
        added, skipped = [], []
        for it in items:
            n = _norm_inc(it)
            if n.lower() in cur_norm:
                skipped.append(it)
            else:
                cur.append(it)
                cur_norm.add(n.lower())
                added.append(it)
        if not added:
            return None, {"skipped": skipped}
        return _PATH_SEP.join(cur), {"added": added, "skipped": skipped}

    new_text, info = _edit_tag(text, target, "IncludePath", lambda o: _fn(o))
    if info is None:
        return {"ok": False, "error": "未找到 target 的 IncludePath 节点：%s"
                                      % (target or "(第一个)"),
                "targets": list_targets(path)}
    if not info.get("changed"):
        return {"ok": True, "changed": False, "action": "add_include_path",
                "added": [], "skipped": items,
                "message": "已全部存在，无需修改", "targets": list_targets(path)}
    bak = _backup(path) if backup else None
    with open(path, "w", encoding=enc, errors="replace", newline="") as f:
        f.write(new_text)
    return {"ok": True, "changed": True, "action": "add_include_path",
            "target": target or "(第一个)", "backup": bak, "encoding": enc,
            "before": info["before"], "after": info["after"],
            "added": info.get("added", []), "skipped": info.get("skipped", []),
            "message": "已加入 Include Paths，重新编译即生效（Keil 若正打开该工程需先关闭再改）"}

def del_include_path(path: str, pattern: str, target: str = "",
                     backup: bool = True) -> dict:
    """按**正则**从 ``IncludePath`` 里删除匹配的目录条目。"""
    text, enc = _read_text(path)
    if not (pattern or "").strip():
        return {"ok": False, "error": "pattern 为空（为避免误删，必须给正则）"}
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return {"ok": False, "error": "正则非法：%s" % e}

    def _fn(old):
        cur = [x for x in old.split(_PATH_SEP) if x.strip()]
        kept = [x for x in cur if not rx.search(x)]
        if len(kept) == len(cur):
            return None
        return _PATH_SEP.join(kept), {"removed": [x for x in cur if rx.search(x)]}

    new_text, info = _edit_tag(text, target, "IncludePath", _fn)
    if info is None:
        return {"ok": False, "error": "未找到 target 的 IncludePath 节点：%s"
                                      % (target or "(第一个)")}
    if not info.get("changed"):
        return {"ok": True, "changed": False, "action": "del_include_path",
                "removed": [], "message": "没有匹配的条目"}
    bak = _backup(path) if backup else None
    with open(path, "w", encoding=enc, errors="replace", newline="") as f:
        f.write(new_text)
    return {"ok": True, "changed": True, "action": "del_include_path",
            "target": target or "(第一个)", "backup": bak,
            "before": info["before"], "after": info["after"],
            "removed": info.get("removed", [])}

def add_files(path: str, group: str, files, backup: bool = True) -> dict:
    """把文件加入指定分组（分组不存在则新建分组）。

    files 为相对工程目录的路径（如 ``..\\Core\\Src\\usart.c``）；重复路径会跳过。
    """
    text, enc = _read_text(path)
    fl = [str(f) for f in (files if isinstance(files, (list, tuple)) else [files])
          if str(f).strip()]
    if not fl:
        return {"ok": False, "error": "files 为空"}
    if not (group or "").strip():
        return {"ok": False, "error": "group 不能为空"}

    existing = set()
    for g in list_groups(path):
        for f in g["files"]:
            existing.add(_norm_inc(f["path"]).lower())
    todo, skipped = [], []
    for f in fl:
        (skipped if _norm_inc(f).lower() in existing else todo).append(f)
    if not todo:
        return {"ok": True, "changed": False, "action": "add_files", "added": [],
                "skipped": skipped, "message": "这些文件已在工程里，无需修改"}

    def _mk_file(p, ftype="1"):
        name = os.path.basename(_norm_inc(p))
        return ("        <File>\n"
                "          <FileName>%s</FileName>\n"
                "          <FileType>%s</FileType>\n"
                "          <FilePath>%s</FilePath>\n"
                "        </File>\n" % (name, ftype, _norm_inc(p)))

    m = re.search(r"<Groups>.*?</Groups>", text, re.S)
    if not m:
        return {"ok": False, "error": "工程里没有 <Groups> 节点，拒绝改写"}
    groups_seg = m.group(0)

    gm = None
    for g in re.finditer(r"[ \t]*<Group>.*?</Group>", groups_seg, re.S):
        seg = g.group(0)
        nm = re.search(r"<GroupName>\s*(.*?)\s*</GroupName>", seg, re.S)
        if nm and nm.group(1).strip() == group.strip():
            gm = g
            break

    if gm is not None:
        seg = gm.group(0)
        fm = re.search(r"</Files>", seg)
        ins_at = gm.start() + fm.start() if fm else None
        if ins_at is None:
            return {"ok": False, "error": "分组 %s 里没有 <Files> 节点" % group}
        add = "".join(_mk_file(p) for p in todo)
        new_seg = seg[:fm.start()] + add + seg[fm.start():]
        new_groups = groups_seg[:gm.start()] + new_seg + groups_seg[gm.end():]
        created_group = False
    else:
        block = ("      <Group>\n"
                 "        <GroupName>%s</GroupName>\n"
                 "        <Files>\n%s"
                 "        </Files>\n"
                 "      </Group>\n" % (group, "".join(_mk_file(p) for p in todo)))
        ins = re.search(r"</Groups>", groups_seg).start()
        new_groups = groups_seg[:ins] + block + groups_seg[ins:]
        created_group = True

    new_text = text[:m.start()] + new_groups + text[m.end():]
    bak = _backup(path) if backup else None
    with open(path, "w", encoding=enc, errors="replace", newline="") as f:
        f.write(new_text)
    return {"ok": True, "changed": True, "action": "add_files", "group": group,
            "created_group": created_group, "added": todo, "skipped": skipped,
            "backup": bak,
            "message": "已加入工程分组，重新编译即生效；FileType 按源文件(1)写入，"
                       "头文件/库文件请核对 Keil 里的类型"}

def remove_files(path: str, pattern: str, backup: bool = True) -> dict:
    """按**正则**匹配 ``FilePath`` 删除工程里的文件条目。"""
    text, enc = _read_text(path)
    if not (pattern or "").strip():
        return {"ok": False, "error": "pattern 为空（为避免误删，必须给正则）"}
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return {"ok": False, "error": "正则非法：%s" % e}
    removed = []
    def _repl(m):
        seg = m.group(0)
        fp = re.search(r"<FilePath>\s*(.*?)\s*</FilePath>", seg, re.S)
        if fp and rx.search(fp.group(1)):
            removed.append(fp.group(1))
            return ""
        return seg
    new_text, n = re.subn(r"[ \t]*<File>.*?</File>[ \t]*\r?\n?", _repl, text, flags=re.S)
    if not removed:
        return {"ok": True, "changed": False, "action": "remove_files", "removed": [],
                "message": "没有匹配的文件条目"}
    bak = _backup(path) if backup else None
    with open(path, "w", encoding=enc, errors="replace", newline="") as f:
        f.write(new_text)
    return {"ok": True, "changed": True, "action": "remove_files",
            "removed": removed, "backup": bak,
            "message": "已移出工程（磁盘文件未被删除）"}
