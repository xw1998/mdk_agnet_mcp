/* mdk_visual_runtime.js —— mdkdebug 可视化运行时（离线单文件，无外部依赖、无网络请求）
 *
 * 契约：window.__MDK_VIEW__ = model（结构见 mdkdebug/viz/spec.py 的 build_model）
 * 时间一律用 **微秒（µs）** 作为内部单位，格式化时自动选 s / ms / µs。
 * 支持 kind：timeline / scope / bars / report（report 内可嵌前三种）。
 *
 * 设计原则（与工具链其余部分一致）：
 *   · 页面只画模型里**有**的东西，缺数据就留空并如实标注，不编造；
 *   · 视图内数量过多时自动切「密度条」而不是画糊成一片的竖线；
 *   · 前提/局限（limits）与规模（badges）摊在页面上，人会先看到可信度。
 */
(function () {
  "use strict";

  var M = window.__MDK_VIEW__ || {};

  var C = {
    bg: "#0f1115", panel: "#161922", panel2: "#1d2130", line: "#2a3040",
    fg: "#e6e9f0", dim: "#8b93a7", accent: "#4a9eff", ok: "#2ed573",
    warn: "#ffb648", bad: "#ff5c69", cursor: "#ffd166"
  };
  var PALETTE = ["#4a9eff", "#2ed573", "#ff9f43", "#a55eea", "#37d3d3",
                 "#ff5c69", "#e8b339", "#7bd389", "#f78fb3", "#6c7bff",
                 "#c3e88d", "#ff9fa1"];

  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined && txt !== null) e.textContent = String(txt);
    return e;
  }
  function colorOf(i, given) { return given || PALETTE[((i % PALETTE.length) + PALETTE.length) % PALETTE.length]; }

  function fmtT(us) {
    if (us === null || us === undefined || isNaN(us)) return "—";
    var a = Math.abs(us);
    if (a >= 1e6) return (us / 1e6).toFixed(3) + " s";
    if (a >= 1e3) return (us / 1e3).toFixed(3) + " ms";
    if (a >= 1) return us.toFixed(1) + " µs";
    return us.toFixed(3) + " µs";
  }
  function fmtInt(n) { return (n === null || n === undefined) ? "—" : Number(n).toLocaleString(); }
  function niceStep(span, px) {
    if (!(span > 0)) return 1;
    var raw = span / Math.max(1, px / 90);
    var e = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10));
    var m = raw / e;
    var s = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
    return s * e;
  }
  function el2(x) { return x === null || x === undefined ? "—" : String(x); }

  /* ================= 公共：时间轴视图（timeline / scope 共用） ================= */

  function TimeView(model, host, opts) {
    var self = this;
    this.m = model; this.o = opts || {};
    this.cv = el("canvas"); this.cv.className = "mdk-cv";
    this.app = el("div", "mdk-view"); this.app.appendChild(this.cv);
    this.bar = el("div", "mdk-bar"); this.app.appendChild(this.bar);
    this.lab = el("span", "mdk-hint"); this.bar.appendChild(this.lab);
    host.appendChild(this.app);
    this.ctx = this.cv.getContext("2d");
    this.padl = opts.padl || 150; this.padr = 16;
    this.span = model.span || [0, 1];
    this.full = [this.span[0], this.span[1]];
    this.v0 = this.full[0]; this.v1 = this.full[1];
    this.cur = this.full[0];
    this.playing = false; this._raf = 0; this._last = 0;
    this.show = {};                      // 轨道开关
    (model.tracks || []).forEach(function (t, i) { if (t.toggle !== false) self.show[t.id || i] = true; });

    this.mkButtons();
    this.bind();
    this.resize();
    window.addEventListener("resize", function () { self.resize(); });
  }

  TimeView.prototype.mkButtons = function () {
    var self = this;
    function btn(txt, fn, cls) {
      var b = el("button", "mdk-btn" + (cls ? " " + cls : ""), txt);
      b.onclick = fn; self.bar.appendChild(b); return b;
    }
    var play = btn("▶ 回放", function () { self.togglePlay(); }, "on");
    this.playBtn = play;
    btn("放大 +", function () { self.zoomBy(0.6); });
    btn("缩小 −", function () { self.zoomBy(1 / 0.6); });
    btn("全览", function () { self.fit(); });
    (this.m.tracks || []).forEach(function (t, i) {
      if (t.toggle === false) return;
      var id = t.id || i;
      var b = btn((t.name || ("轨道" + (i + 1))) + (t.count ? " " + fmtInt(t.count) : ""),
                  function () { self.show[id] = !self.show[id]; b.className = "mdk-btn" + (self.show[id] ? " on" : ""); self.draw(); },
                  self.show[id] ? "on" : "");
      b.title = t.sub || "";
    });
  };

  TimeView.prototype.bind = function () {
    var self = this, cv = this.cv;
    var drag = null;
    cv.addEventListener("wheel", function (e) {
      e.preventDefault();
      var r = cv.getBoundingClientRect();
      var mx = e.clientX - r.left;
      var span = self.v1 - self.v0;
      var minSpan = Math.max((self.full[1] - self.full[0]) / 1e6, 1e-3);
      var f = Math.exp((e.deltaY > 0 ? 1 : -1) * 0.18);
      var ns = Math.min(self.full[1] - self.full[0], Math.max(minSpan, span * f));
      var anchor = self.tof(mx);
      var k = (anchor - self.v0) / span;
      self.v0 = anchor - ns * k; self.v1 = self.v0 + ns;
      self.clamp(); self.draw();
    }, { passive: false });
    cv.addEventListener("mousedown", function (e) {
      drag = { x: e.clientX, v0: self.v0, v1: self.v1, moved: false };
    });
    window.addEventListener("mousemove", function (e) {
      if (!drag) return;
      var dx = e.clientX - drag.x;
      if (Math.abs(dx) > 3) drag.moved = true;
      var span = drag.v1 - drag.v0;
      var dt = -dx / (self.cvWidth()) * span;
      self.v0 = drag.v0 + dt; self.v1 = drag.v1 + dt;
      self.clamp(); self.draw();
    });
    window.addEventListener("mouseup", function (e) {
      if (drag && !drag.moved) {
        var r = cv.getBoundingClientRect();
        self.cur = self.tof(e.clientX - r.left);
        self.clampCur(); self.draw();
      }
      drag = null;
    });
    cv.addEventListener("dblclick", function () { self.fit(); });
  };

  TimeView.prototype.cvWidth = function () {
    return Math.max(200, (this.cv._w || this.cv.clientWidth || 900) - this.padl - this.padr);
  };
  TimeView.prototype.x = function (t) {
    return this.padl + (t - this.v0) / (this.v1 - this.v0) * this.cvWidth();
  };
  TimeView.prototype.tof = function (mx) {
    return this.v0 + (mx - this.padl) / this.cvWidth() * (this.v1 - this.v0);
  };
  TimeView.prototype.zoomBy = function (k) {
    var c = (this.v0 + this.v1) / 2, span = (this.v1 - this.v0) * k;
    var minSpan = Math.max((this.full[1] - this.full[0]) / 1e6, 1e-3);
    span = Math.min(this.full[1] - this.full[0], Math.max(minSpan, span));
    this.v0 = c - span / 2; this.v1 = this.v0 + span;
    this.clamp(); this.draw();
  };
  TimeView.prototype.fit = function () {
    this.v0 = this.full[0]; this.v1 = this.full[1]; this.draw();
  };
  TimeView.prototype.clamp = function () {
    var lo = this.full[0], hi = this.full[1], span = this.v1 - this.v0;
    if (this.v0 < lo) { this.v0 = lo; this.v1 = lo + span; }
    if (this.v1 > hi) { this.v1 = hi; this.v0 = hi - span; }
    if (this.v1 <= this.v0) { this.v1 = this.v0 + 1e-3; }
  };
  TimeView.prototype.clampCur = function () {
    this.cur = Math.min(this.full[1], Math.max(this.full[0], this.cur));
  };
  TimeView.prototype.togglePlay = function () {
    var self = this;
    this.playing = !this.playing;
    this.playBtn.textContent = this.playing ? "❚❚ 暂停" : "▶ 回放";
    if (!this.playing) { cancelAnimationFrame(this._raf); return; }
    this.cur = this.full[0];
    this._last = performance.now();
    var step = function (now) {
      if (!self.playing) return;
      var dtms = now - self._last; self._last = now;
      self.cur += dtms * 1000;                    // 1:1 实时（µs）
      if (self.cur >= self.full[1]) { self.cur = self.full[1]; self.togglePlay(); }
      // 游标跑出视窗就跟着推
      if (self.cur > self.v1) { var s = self.v1 - self.v0; self.v1 = self.cur + s * 0.1; self.v0 = self.v1 - s; self.clamp(); }
      self.draw();
      if (self.playing) self._raf = requestAnimationFrame(step);
    };
    this._raf = requestAnimationFrame(step);
  };
  TimeView.prototype.resize = function () {
    var w = this.cv.clientWidth || this.app.clientWidth || 900;
    var dpr = window.devicePixelRatio || 1;
    var h = this.totalH();
    this.cv.width = Math.round(w * dpr); this.cv.height = Math.round(h * dpr);
    this.cv.style.height = h + "px";
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.cv._w = w;
    this.draw();
  };
  TimeView.prototype.drawRuler = function (y, h, label) {
    var ctx = this.ctx, w = this.cv._w, span = this.v1 - this.v0;
    ctx.fillStyle = C.dim; ctx.font = "11px system-ui"; ctx.textAlign = "right";
    ctx.fillText(label, this.padl - 10, y + h / 2 + 4);
    var step = niceStep(span, this.cvWidth());
    ctx.textAlign = "center";
    for (var t = Math.ceil(this.v0 / step) * step; t <= this.v1; t += step) {
      var x = this.x(t);
      ctx.strokeStyle = "#232a38"; ctx.beginPath();
      ctx.moveTo(x, y + h - 6); ctx.lineTo(x, this.hContent); ctx.stroke();
      ctx.fillStyle = C.dim; ctx.fillText(fmtT(t), x, y + h / 2);
    }
  };
  TimeView.prototype.drawCursor = function () {
    var ctx = this.ctx, x = this.x(this.cur);
    if (x < this.padl - 1 || x > this.cv._w - this.padr + 1) return;
    ctx.strokeStyle = C.cursor; ctx.lineWidth = 1.4;
    ctx.beginPath(); ctx.moveTo(x, this.hTop); ctx.lineTo(x, this.hContent); ctx.stroke();
    ctx.lineWidth = 1;
  };
  TimeView.prototype.drawGaps = function () {
    var self = this, ctx = this.ctx;
    (this.m.gaps || []).forEach(function (g) {
      var x0 = self.x(g.t0), x1 = self.x(g.t1);
      if (x1 < self.padl || x0 > self.cv._w - self.padr) return;
      x0 = Math.max(x0, self.padl); x1 = Math.min(x1, self.cv._w - self.padr);
      ctx.save();
      ctx.beginPath(); ctx.rect(x0, self.hTop, Math.max(x1 - x0, 1), self.hContent - self.hTop);
      ctx.clip();
      ctx.fillStyle = "rgba(255,92,105,.10)"; ctx.fillRect(x0, self.hTop, x1 - x0, self.hContent - self.hTop);
      ctx.strokeStyle = "rgba(255,92,105,.45)"; ctx.lineWidth = 1;
      for (var d = -40; d < (x1 - x0) + (self.hContent - self.hTop); d += 8) {
        ctx.beginPath(); ctx.moveTo(x0 + d, self.hContent); ctx.lineTo(x0 + d + (self.hContent - self.hTop), self.hTop); ctx.stroke();
      }
      ctx.restore();
    });
  };
  TimeView.prototype.drawMarkers = function () {
    var self = this, ctx = this.ctx;
    (this.m.markers || []).forEach(function (mk) {
      var x = self.x(mk.t);
      if (x < self.padl - 40 || x > self.cv._w - self.padr + 40) return;
      var col = mk.level === "bad" ? C.bad : mk.level === "warn" ? C.warn : C.accent;
      ctx.strokeStyle = col; ctx.setLineDash([4, 3]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x, self.hTop); ctx.lineTo(x, self.hContent); ctx.stroke();
      ctx.setLineDash([]);
      if (mk.label && (self.v1 - self.v0) < (self.full[1] - self.full[0])) {
        ctx.fillStyle = col; ctx.font = "10px system-ui"; ctx.textAlign = "left";
        ctx.fillText(mk.label, x + 3, self.hTop + 10);
      }
    });
  };
  TimeView.prototype.hint = function (txt) { this.lab.textContent = txt; };

  /* ------------------------------ timeline ------------------------------ */

  function TimelineView(model, host) {
    TimeView.call(this, model, host, {});
    this.layout();
    this.resize();
  }
  TimelineView.prototype = Object.create(TimeView.prototype);
  TimelineView.prototype.constructor = TimelineView;

  TimelineView.prototype.layout = function () {
    this.hTop = 8; this.hRuler = this.hTop + 22;
    this.hMap = this.hRuler + 6; this.hMapH = 30;
    this.hTracks = this.hMap + this.hMapH + 10;
    var y = this.hTracks, self = this;
    this._tracks = [];
    (this.m.tracks || []).forEach(function (t, i) {
      var id = t.id || i;
      var type = t.type || "marks";
      var h = type === "intervals" || type === "density" ? 24 : 26;
      self._tracks.push({ t: t, id: id, y: y, h: h, i: i });
      y += h + 6;
    });
    this.hContent = y + 20;
  };
  TimelineView.prototype.totalH = function () { return this.hContent + 8; };

  TimelineView.prototype.draw = function () {
    if (!this._tracks) this.layout();
    var self = this, ctx = this.ctx, w = this.cv._w, P = this.padl;
    ctx.clearRect(0, 0, w, this.totalH());
    ctx.fillStyle = C.bg; ctx.fillRect(0, 0, w, this.totalH());
    ctx.font = "12px system-ui"; ctx.textBaseline = "middle";

    // 总览条：全时段里各轨道的活动（用第一/第二条 track 的颜色表达）
    ctx.fillStyle = "#0c0f16"; ctx.fillRect(P, this.hMap, w - P - this.padr, this.hMapH);
    var spanFull = this.full[1] - this.full[0] || 1;
    this._tracks.forEach(function (tk) {
      var t = tk.t;
      var list = (t.spans || []).concat(t.pairs || []);
      ctx.globalAlpha = 0.85;
      list.forEach(function (sp) {
        var x0 = P + (sp[0] - self.full[0]) / spanFull * self.cvWidth();
        var x1 = P + (sp[1] - self.full[0]) / spanFull * self.cvWidth();
        ctx.fillStyle = colorOf(tk.i, t.color);
        ctx.fillRect(x0, self.hMap + 4 + (tk.i % 3) * 8, Math.max(x1 - x0, 0.6), 7);
      });
      ctx.globalAlpha = 0.6;
      (t.marks || []).forEach(function (mk) {
        var x = P + (mk[0] - self.full[0]) / spanFull * self.cvWidth();
        ctx.fillStyle = colorOf(tk.i, t.color);
        ctx.fillRect(x, self.hMap + 4 + (tk.i % 3) * 8, 1, 7);
      });
      ctx.globalAlpha = 1;
    });
    ctx.strokeStyle = "#3a4256"; ctx.strokeRect(P + .5, this.hMap + .5, w - P - this.padr - 1, this.hMapH - 1);
    var vx0 = P + (this.v0 - this.full[0]) / spanFull * this.cvWidth();
    var vx1 = P + (this.v1 - this.full[0]) / spanFull * this.cvWidth();
    ctx.fillStyle = "rgba(74,158,255,.14)"; ctx.fillRect(vx0, this.hMap, Math.max(vx1 - vx0, 1), this.hMapH);
    ctx.strokeStyle = C.accent; ctx.strokeRect(vx0 + .5, this.hMap + .5, Math.max(vx1 - vx0 - 1, 1), this.hMapH - 1);
    ctx.fillStyle = C.dim; ctx.font = "11px system-ui"; ctx.textAlign = "right";
    ctx.fillText("总览", P - 10, this.hMap + this.hMapH / 2 + 4);

    this.drawGaps();
    this.drawMarkers();
    this.drawRuler(this.hRuler, 22, "时间");

    var zoomed = (this.v1 - this.v0) < spanFull / 6;
    this._tracks.forEach(function (tk) {
      var t = tk.t, on = self.show[tk.id];
      ctx.fillStyle = "#171b25"; ctx.fillRect(P, tk.y, w - P - self.padr, tk.h);
      ctx.textAlign = "right"; ctx.fillStyle = on ? "#c8cedd" : "#5b6377";
      ctx.font = "12px system-ui";
      ctx.fillText(t.name || ("轨道" + (tk.i + 1)), P - 10, tk.y + tk.h / 2 - 5);
      ctx.fillStyle = C.dim; ctx.font = "10px system-ui";
      ctx.fillText(el2(t.sub || (t.count !== undefined ? fmtInt(t.count) + " 个" : "")), P - 10, tk.y + tk.h / 2 + 9);
      ctx.font = "12px system-ui";
      if (!on) return;
      ctx.save(); ctx.beginPath(); ctx.rect(P, tk.y, w - P - self.padr, tk.h); ctx.clip();
      var col = colorOf(tk.i, t.color);
      var type = t.type || "marks";
      if (type === "spans") {
        (t.spans || []).forEach(function (sp) {
          if (sp[1] < self.v0 || sp[0] > self.v1) return;
          var x0 = self.x(sp[0]), x1 = self.x(sp[1]);
          ctx.fillStyle = col; ctx.fillRect(x0, tk.y + 3, Math.max(x1 - x0, 1), tk.h - 6);
        });
      } else if (type === "intervals") {
        var vis = 0, pairs = t.pairs || [];
        for (var i = 0; i < pairs.length; i++) if (pairs[i][1] >= self.v0 && pairs[i][0] <= self.v1) vis++;
        if (vis > 140) {
          var bins = 140, arr = [], mx = 1;
          for (var b = 0; b < bins; b++) arr.push(0);
          for (var j = 0; j < pairs.length; j++) {
            if (pairs[j][0] < self.v0 || pairs[j][0] > self.v1) continue;
            var bi = Math.min(bins - 1, Math.floor((pairs[j][0] - self.v0) / (self.v1 - self.v0) * bins));
            arr[bi]++; if (arr[bi] > mx) mx = arr[bi];
          }
          var bw = self.cvWidth() / bins;
          for (var k2 = 0; k2 < bins; k2++) {
            if (!arr[k2]) continue;
            ctx.globalAlpha = 0.25 + 0.75 * arr[k2] / mx;
            ctx.fillStyle = col; ctx.fillRect(P + k2 * bw, tk.y + 3, Math.max(bw - 0.6, 0.8), tk.h - 6);
          }
          ctx.globalAlpha = 1;
          ctx.fillStyle = C.dim; ctx.font = "10px system-ui"; ctx.textAlign = "right";
          ctx.fillText("视野内 " + fmtInt(vis) + " 段 → 密度条（放大看单个区间）", w - self.padr - 6, tk.y + tk.h - 8);
          ctx.font = "12px system-ui";
        } else {
          pairs.forEach(function (sp) {
            if (sp[1] < self.v0 || sp[0] > self.v1) return;
            var x0 = self.x(sp[0]), x1 = self.x(sp[1]);
            ctx.fillStyle = col; ctx.fillRect(x0, tk.y + 5, Math.max(x1 - x0, 1.2), tk.h - 10);
          });
        }
      } else if (type === "density") {
        var bins2 = 160, a2 = [], m2 = 1;
        for (var q = 0; q < bins2; q++) a2.push(0);
        (t.marks || []).forEach(function (mk) {
          if (mk[0] < self.v0 || mk[0] > self.v1) return;
          var ii = Math.min(bins2 - 1, Math.floor((mk[0] - self.v0) / (self.v1 - self.v0) * bins2));
          a2[ii]++; if (a2[ii] > m2) m2 = a2[ii];
        });
        var bw2 = self.cvWidth() / bins2;
        for (var z = 0; z < bins2; z++) {
          if (!a2[z]) continue;
          ctx.globalAlpha = 0.2 + 0.8 * a2[z] / m2;
          ctx.fillStyle = col; ctx.fillRect(P + z * bw2, tk.y + 3, Math.max(bw2 - 0.6, 0.8), tk.h - 6);
        }
        ctx.globalAlpha = 1;
      } else {
        (t.marks || []).forEach(function (mk) {
          if (mk[0] < self.v0 || mk[0] > self.v1) return;
          var x = self.x(mk[0]);
          ctx.strokeStyle = (mk.length > 1 && mk[1]) ? mk[1] : col;
          ctx.globalAlpha = .95;
          ctx.beginPath(); ctx.moveTo(x, tk.y + tk.h - 4); ctx.lineTo(x, tk.y + 5); ctx.stroke();
        });
        ctx.globalAlpha = 1;
        if (zoomed && t.targets) {
          t.targets.forEach(function (tg) {
            if (tg.t < self.v0 || tg.t > self.v1) return;
            var x = self.x(tg.t);
            ctx.fillStyle = colorOf(tg.i || 0, tg.color);
            ctx.fillRect(x + 1, tk.y + tk.h - 15, 2.5, 10);
          });
        }
      }
      ctx.restore();
    });

    this.drawCursor();
    var tip = "游标 " + fmtT(this.cur) + " ｜ 视窗 " + fmtT(this.v0) + " → " + fmtT(this.v1);
    this.hint(tip);
  };

  /* ------------------------------- scope -------------------------------- */

  function ScopeView(model, host) {
    TimeView.call(this, model, host, { padl: 150 });
    this.layout();
    this.resize();
  }
  ScopeView.prototype = Object.create(TimeView.prototype);
  ScopeView.prototype.constructor = ScopeView;

  ScopeView.prototype.layout = function () {
    this.hTop = 8; this.hRuler = this.hTop + 22;
    this.hTracks = this.hRuler + 8;
    var y = this.hTracks, self = this;
    this._ch = [];
    (this.m.channels || []).forEach(function (ch, i) {
      var h = ch.height || 86;
      self._ch.push({ ch: ch, i: i, y: y, h: h });
      y += h + 8;
    });
    if (!this._ch.length) y += 60;
    this.hContent = y + 16;
  };
  ScopeView.prototype.totalH = function () { return this.hContent + 8; };

  ScopeView.prototype.draw = function () {
    if (!this._ch) this.layout();
    var self = this, ctx = this.ctx, w = this.cv._w, P = this.padl;
    ctx.clearRect(0, 0, w, this.totalH());
    ctx.fillStyle = C.bg; ctx.fillRect(0, 0, w, this.totalH());
    ctx.font = "12px system-ui"; ctx.textBaseline = "middle";
    this.drawGaps();
    this.drawMarkers();
    this.drawRuler(this.hRuler, 22, this.m.time_label || "时间");

    var S = this.m.series || { t: [] }, T = S.t || [];
    var curIdx = -1;
    for (var q = 0; q < T.length; q++) { if (T[q] <= this.cur) curIdx = q; else break; }

    this._ch.forEach(function (item) {
      var ch = item.ch, i = item.i, y = item.y, h = item.h;
      var col = colorOf(i, ch.color);
      var vals = (S.v && (S.v[ch.name] || S.v[ch.name + ""])) || [];
      var type = ch.type || "analog";
      var top = y + 12, bot = y + h - 12;
      var lo = (ch.min !== undefined && ch.min !== null) ? ch.min : 0;
      var hi = (ch.max !== undefined && ch.max !== null) ? ch.max : 1;
      if (hi === lo) { hi = lo + 1; }
      var pad = (hi - lo) * 0.08; lo -= pad; hi += pad;
      function vy(v) { return bot - (v - lo) / (hi - lo) * (bot - top); }

      ctx.fillStyle = "#171b25"; ctx.fillRect(P, y, w - P - self.padr, h);
      ctx.textAlign = "right"; ctx.fillStyle = "#c8cedd"; ctx.font = "12px system-ui";
      ctx.fillText(ch.name, P - 10, y + 16);
      ctx.fillStyle = C.dim; ctx.font = "10px system-ui";
      ctx.fillText((ch.unit ? "[" + ch.unit + "] " : "") + "min " + el2(ch.min) + " / max " + el2(ch.max), P - 10, y + 30);
      ctx.fillText((ch.changes !== undefined ? "变 " + fmtInt(ch.changes) + " 次" : "") +
                   (ch.samples !== undefined ? " · " + fmtInt(ch.samples) + " 点" : ""), P - 10, y + 43);
      var cv1 = (curIdx >= 0 && curIdx < vals.length && vals[curIdx] !== null && vals[curIdx] !== undefined)
                ? vals[curIdx] : null;
      ctx.fillStyle = col; ctx.font = "12px system-ui";
      ctx.fillText(cv1 === null ? "—" : String(cv1), P - 10, y + h - 14);
      ctx.font = "12px system-ui";

      ctx.save(); ctx.beginPath(); ctx.rect(P, y, w - P - self.padr, h); ctx.clip();
      // 参考线
      ctx.strokeStyle = "#222836"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(P, (top + bot) / 2); ctx.lineTo(w - self.padr, (top + bot) / 2); ctx.stroke();
      if (!T.length) {
        ctx.fillStyle = C.dim; ctx.textAlign = "center";
        ctx.fillText("无样本", P + self.cvWidth() / 2, y + h / 2);
        ctx.restore(); return;
      }
      var first = 0, last = T.length - 1;
      for (var a = 0; a < T.length; a++) { if (T[a] >= self.v0) { first = a; break; } }
      for (var b = T.length - 1; b >= 0; b--) { if (T[b] <= self.v1) { last = b; break; } }
      if (first > 0) first--;
      if (last < T.length - 1) last++;
      var step = Math.max(1, Math.ceil((last - first + 1) / (self.cvWidth() * 2)));
      if (type === "analog") {
        ctx.strokeStyle = col; ctx.lineWidth = 1.6; ctx.beginPath();
        var started = false, pts = [];
        for (var i2 = first; i2 <= last; i2 += step) {
          var v = vals[i2];
          if (v === null || v === undefined) { started = false; continue; }
          var x = self.x(T[i2]), yy = vy(v);
          if (!started) { ctx.moveTo(x, yy); started = true; } else ctx.lineTo(x, yy);
          if (step > 1) pts.push([x, yy]);
        }
        ctx.stroke();
        ctx.fillStyle = col;
        pts.forEach(function (p) { ctx.fillRect(p[0] - 1.5, p[1] - 1.5, 3, 3); });
      } else {
        // bool / enum：阶梯 + 竖线
        ctx.strokeStyle = col; ctx.lineWidth = 1.6;
        var prevY = null, prevX = null;
        for (var i3 = first; i3 <= last; i3 += step) {
          var v3 = vals[i3];
          if (v3 === null || v3 === undefined) { prevX = null; prevY = null; continue; }
          var x3 = self.x(T[i3]), y3 = vy(v3);
          if (prevY === null) { ctx.beginPath(); ctx.moveTo(x3, y3); }
          else { ctx.lineTo(x3, prevY); ctx.lineTo(x3, y3); }
          prevY = y3; prevX = x3;
        }
        if (prevY !== null) ctx.stroke();
      }
      // 采样点稀疏时标出点
      if (T.length <= 400) {
        ctx.fillStyle = col;
        for (var i4 = first; i4 <= last; i4++) {
          var v4 = vals[i4]; if (v4 === null || v4 === undefined) continue;
          ctx.fillRect(self.x(T[i4]) - 1.2, vy(v4) - 1.2, 2.4, 2.4);
        }
      }
      ctx.restore();
    });

    this.drawCursor();
    this.hint("游标 " + fmtT(this.cur) + " ｜ 视窗 " + fmtT(this.v0) + " → " + fmtT(this.v1));
  };

  /* -------------------------------- bars -------------------------------- */

  function BarsView(model, host) {
    var self = this;
    this.m = model;
    this.app = el("div", "mdk-view");
    this.node = el("div", "mdk-bars");
    this.app.appendChild(this.node);
    host.appendChild(this.app);
    var B = model.bars || { items: [] };
    var items = B.items || [];
    var max = 1;
    items.forEach(function (it) { var v = Math.abs(it.value || 0); if (v > max) max = v; });
    var unit = B.unit ? " " + B.unit : "";
    items.forEach(function (it, i) {
      var row = el("div", "mdk-brow");
      var nm = el("div", "mdk-bname", it.name);
      if (it.sub) { var s = el("div", "mdk-bsub", it.sub); nm.appendChild(s); }
      var track = el("div", "mdk-btrack");
      var bar = el("div", "mdk-bbar");
      var wv = Math.max(1, Math.abs(it.value || 0) / max * 100);
      bar.style.width = wv.toFixed(2) + "%";
      if (it.color) bar.style.background = it.color;
      else bar.style.background = colorOf(i);
      track.appendChild(bar);
      var val = el("div", "mdk-bval", (it.value === null || it.value === undefined ? "—"
                    : (typeof it.value === "number" ? (Math.abs(it.value) >= 1000 ? it.value.toFixed(0) : it.value.toFixed(it.value < 10 ? 2 : 1)) : String(it.value))) + unit);
      if (it.share !== null && it.share !== undefined) {
        val.appendChild(el("span", "mdk-bshare", "  " + it.share + "%"));
      }
      row.appendChild(nm); row.appendChild(track); row.appendChild(val);
      self.node.appendChild(row);
    });
    if (!items.length) this.node.appendChild(el("div", "mdk-empty", "没有可展示的条目"));
  }

  /* ------------------------------- report ------------------------------- */

  function ReportView(model, host) {
    var self = this;
    this.m = model;
    var vd = model.verdict;
    if (typeof vd === "string") vd = { level: vd, text: "" };
    if (vd && (vd.text || (vd.level && vd.level !== "ok"))) {
      var lv = vd.level || "ok";
      var v = el("div", "mdk-verdict " + lv);
      v.appendChild(el("span", "mdk-vtag", ({ ok: "结论", warn: "注意", bad: "问题", dim: "信息" })[lv] || "结论"));
      if (vd.text) v.appendChild(el("span", "mdk-vtxt", vd.text));
      host.appendChild(v);
    }
    (model.sections || []).forEach(function (s) {
      // 单节写错（p 给了字符串、h2 这种别名）只影响这一节：过去一个 TypeError 会把
      // 后面所有节连同嵌图一起吞掉，页面上只剩页眉——看着像渲染成功，最坏的那种。
      try {
        var sec = el("section", "mdk-sec");
        var h = s.h || s.h2 || s.title;
        if (h) sec.appendChild(el("h2", null, h));
        var ps = s.p != null ? s.p : s.paragraphs;
        if (typeof ps === "string") ps = [ps];
        (ps || []).forEach(function (p) { sec.appendChild(el("p", null, p)); });
        var bl = s.bullets || s.ul;
        if (typeof bl === "string") bl = [bl];
        if (bl && bl.length) {
          var ul = el("ul", "mdk-ul");
          bl.forEach(function (b) { ul.appendChild(el("li", null, b)); });
          sec.appendChild(ul);
        }
        var code = s.code != null ? s.code : s.pre;
        if (code) { sec.appendChild(el("pre", "mdk-pre", code)); }
        if (s.view) {
          var sub = el("div", "mdk-sub");
          sec.appendChild(sub);
          mountView(s.view, sub);
        }
        host.appendChild(sec);
      } catch (e) {
        host.appendChild(el("div", "mdk-empty", "这一节渲染失败：" + e));
      }
    });
  }

  /* ================================ 装配 ================================ */

  function mountView(model, host) {
    try {
      if (!model) return null;
      if (model.kind === "timeline") return new TimelineView(model, host);
      if (model.kind === "scope") return new ScopeView(model, host);
      if (model.kind === "bars") return new BarsView(model, host);
      if (model.kind === "report") return new ReportView(model, host);
      host.appendChild(el("div", "mdk-empty", "未知视图类型：" + model.kind));
    } catch (e) {
      host.appendChild(el("div", "mdk-empty", "视图渲染失败：" + e));
    }
    return null;
  }

  function init() {
    var root = document.getElementById("mdk-root");
    if (!root) return;
    if (!M || !M.kind) {
      root.appendChild(el("div", "mdk-empty", "数据未注入（__MDK_VIEW__ 为空）"));
      return;
    }
    var head = el("header", "mdk-head");
    var h1 = el("h1", null, M.title || "mdkdebug 视图");
    if (M.subtitle) { var sm = el("small", null, M.subtitle); h1.appendChild(sm); }
    head.appendChild(h1);
    if (M.badges && M.badges.length) {
      var bd = el("div", "mdk-badges");
      M.badges.forEach(function (b) {
        var d = el("span", "mdk-badge" + (b.level ? " " + b.level : ""));
        d.appendChild(el("i", null, b.k));
        d.appendChild(el("b", null, el2(b.v)));
        bd.appendChild(d);
      });
      head.appendChild(bd);
    }
    root.appendChild(head);
    var body = el("div", "mdk-body");
    root.appendChild(body);
    try {
      if (M.kind === "report") new ReportView(M, body); else mountView(M, body);
    } catch (e) {
      body.appendChild(el("div", "mdk-empty", "视图渲染失败：" + e));
    }
    if ((M.notes && M.notes.length) || (M.limits && M.limits.length)) {
      var ft = el("div", "mdk-foot");
      if (M.limits && M.limits.length) {
        ft.appendChild(el("h3", null, "这说明不了什么（边界）"));
        var ul = el("ul", "mdk-ul dim");
        M.limits.forEach(function (x) { ul.appendChild(el("li", null, x)); });
        ft.appendChild(ul);
      }
      if (M.notes && M.notes.length) {
        ft.appendChild(el("h3", null, "说明"));
        var ul2 = el("ul", "mdk-ul");
        M.notes.forEach(function (x) { ul2.appendChild(el("li", null, x)); });
        ft.appendChild(ul2);
      }
      root.appendChild(ft);
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
