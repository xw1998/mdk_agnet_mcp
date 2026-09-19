# -*- coding: utf-8 -*-
"""把渲染模型组装成**单文件、离线** HTML 页面。

约束（与开源仓库其余部分一致）：
  · 页面不引用任何外部资源（无 CDN、无字体、无图片），file:// 双击即可用；
    开源站（gitee）只能预览源码，所以页面必须自带全部依赖。
  · 运行时（runtime.js）由本模块**读进来内联**，不落成第二个文件——
    用户拿到的是一个 html，不是「html + js 目录」。
  · 数据内联为 `window.__MDK_VIEW__`；`<` 一律转义，避免数据里出现 `</script>` 截断脚本。
"""
from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_RUNTIME = os.path.join(_HERE, "runtime.js")

CSS = """
:root{
  --bg:#0f1115; --panel:#161922; --panel2:#1d2130; --line:#2a3040;
  --fg:#e6e9f0; --dim:#8b93a7; --accent:#4a9eff; --ok:#2ed573;
  --warn:#ffb648; --bad:#ff5c69; --cursor:#ffd166;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:13px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
.mdk-wrap{max-width:1400px;margin:0 auto;padding:22px 20px 64px}
.mdk-head h1{font-size:20px;margin:0 0 6px;letter-spacing:.2px}
.mdk-head h1 small{font-weight:400;color:var(--dim);font-size:13px;margin-left:8px}
.mdk-badges{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px}
.mdk-badge{background:var(--panel);border:1px solid var(--line);border-radius:7px;
           padding:5px 10px;font-size:12px;display:flex;gap:6px;align-items:baseline}
.mdk-badge i{color:var(--dim);font-style:normal}
.mdk-badge b{font-weight:600}
.mdk-badge.ok b{color:var(--ok)} .mdk-badge.warn b{color:var(--warn)}
.mdk-badge.bad b{color:var(--bad)} .mdk-badge.dim b{color:var(--dim)}
.mdk-body{margin-top:14px}
.mdk-view{margin:12px 0 18px}
.mdk-cv{width:100%;display:block;background:var(--bg);border-radius:8px}
.mdk-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 2px}
.mdk-btn{background:var(--panel);color:var(--fg);border:1px solid var(--line);
         border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer}
.mdk-btn:hover{border-color:var(--accent)}
.mdk-btn.on{border-color:var(--accent);color:var(--accent)}
.mdk-hint{color:var(--dim);font-size:12px;margin-left:auto;font-variant-numeric:tabular-nums}
.mdk-verdict{display:flex;gap:10px;align-items:flex-start;background:var(--panel);
             border:1px solid var(--line);border-left-width:3px;border-radius:8px;
             padding:10px 14px;margin:14px 0 6px}
.mdk-verdict.ok{border-left-color:var(--ok)} .mdk-verdict.warn{border-left-color:var(--warn)}
.mdk-verdict.bad{border-left-color:var(--bad)} .mdk-verdict.dim{border-left-color:var(--dim)}
.mdk-vtag{color:var(--dim);font-size:12px;white-space:nowrap;padding-top:1px}
.mdk-verdict.bad .mdk-vtag{color:var(--bad)}
.mdk-verdict.warn .mdk-vtag{color:var(--warn)}
.mdk-verdict.ok .mdk-vtag{color:var(--ok)}
.mdk-vtxt{font-size:14px;line-height:1.55}
.mdk-sec{margin:22px 0}
.mdk-sec h2{font-size:14px;margin:0 0 8px;font-weight:600}
.mdk-sec p{margin:0 0 8px;color:#d5dae5}
.mdk-ul{margin:6px 0 8px;padding-left:20px;color:#d5dae5}
.mdk-ul li{margin:3px 0}
.mdk-ul.dim{color:var(--dim)}
.mdk-pre{background:#0c0f16;border:1px solid var(--line);border-radius:8px;
         padding:10px 12px;overflow:auto;font-size:12px;color:#cbd5e1;margin:8px 0 12px}
.mdk-sub{margin:10px 0 4px}
.mdk-foot{margin-top:30px;border-top:1px solid var(--line);padding-top:14px;color:var(--dim)}
.mdk-foot h3{font-size:12px;margin:12px 0 4px;color:var(--dim);font-weight:600}
.mdk-bars{margin:8px 0 4px}
.mdk-brow{display:flex;align-items:center;gap:10px;margin:4px 0}
.mdk-bname{width:230px;flex:0 0 230px;color:#c8cedd;font-size:12px;overflow:hidden;
           text-overflow:ellipsis;white-space:nowrap}
.mdk-bsub{color:var(--dim);font-size:10px}
.mdk-btrack{flex:1 1 auto;height:16px;background:#151922;border-radius:4px;overflow:hidden}
.mdk-bbar{height:100%;border-radius:4px;transition:width .15s}
.mdk-bval{width:150px;flex:0 0 150px;text-align:right;font-size:12px;
          font-variant-numeric:tabular-nums;color:#d5dae5}
.mdk-bshare{color:var(--dim)}
.mdk-empty{color:var(--dim);padding:14px;background:var(--panel);border-radius:8px;
           border:1px solid var(--line)}
"""


def runtime_js() -> str:
    with open(_RUNTIME, "r", encoding="utf-8") as f:
        return f.read()


def _safe_json(obj) -> str:
    """内联 JSON：转义 `<`/`>`/`&`，免得数据里出现 `</script>` 把脚本截断。"""
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return (s.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e"))


def build_html(model: dict) -> str:
    """模型 → 单文件 HTML（字符串）。"""
    title = str(model.get("title") or "mdkdebug 视图")
    note = ("<!-- 由 mdkdebug view_render 生成：单文件、无外部依赖、无网络请求。"
            "数据已内联。 -->")
    return (
        "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n%s\n"
        "<div class=\"mdk-wrap\"><div id=\"mdk-root\"></div></div>\n"
        "<script>window.__MDK_VIEW__ = %s;</script>\n<script>\n%s\n</script>\n</body>\n</html>\n"
        % (_esc(title), CSS, note, _safe_json(model), runtime_js())
    )


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def write_html(model: dict, path: str) -> dict:
    """落盘。目录不存在则创建。返回 {path, bytes}。"""
    p = os.path.abspath(path)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    html = build_html(model)
    with open(p, "w", encoding="utf-8") as f:
        f.write(html)
    return {"path": p, "bytes": len(html.encode("utf-8"))}
