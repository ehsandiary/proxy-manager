(function () {
  // select-all + selected counter on the dashboard
  var all = document.getElementById("selall");
  var boxes = Array.prototype.slice.call(document.querySelectorAll(".sel"));
  var counter = document.getElementById("selcount");
  function count() {
    if (counter) counter.textContent = boxes.filter(function (b) { return b.checked; }).length + " selected";
  }
  if (all) all.addEventListener("change", function () { boxes.forEach(function (b) { b.checked = all.checked; }); count(); });
  boxes.forEach(function (b) { b.addEventListener("change", count); });

  // auto-refresh (remembered per browser; pauses while something is selected)
  var auto = document.getElementById("autorefresh");
  if (auto) {
    var on = true;
    try { on = localStorage.getItem("pm_autorefresh") !== "0"; } catch (e) {}
    auto.checked = on;
    auto.addEventListener("change", function () {
      try { localStorage.setItem("pm_autorefresh", auto.checked ? "1" : "0"); } catch (e) {}
    });
    setInterval(function () {
      var busy = boxes.some(function (b) { return b.checked; }) || document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)
        || (Date.now() - (window.pmLastEdit || 0) < 30000);
      if (auto.checked && !busy) location.reload();
    }, 20000);
  }

  // click-to-copy for code blocks
  document.querySelectorAll(".copy").forEach(function (el) {
    el.title = "Click to copy";
    el.addEventListener("click", function () {
      if (navigator.clipboard) navigator.clipboard.writeText(el.textContent.trim()).then(function () {
        var t = el.style.outline; el.style.outline = "2px solid var(--good)";
        setTimeout(function () { el.style.outline = t; }, 600);
      });
    });
  });

  // inline editing in the proxies table: use case + status
  var csrfEl = document.getElementById("csrf");
  var toastEl = document.getElementById("toast");
  var toastTimer = null;
  function toast(msg, ok) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.className = "toast " + (ok ? (msg.indexOf("⚠️") === 0 ? "warn" : "ok") : "err");
    toastEl.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.hidden = true; }, ok ? 5000 : 9000);
  }
  window.pmLastEdit = 0;
  function quick(id, field, value, extra) {
    var fd = new FormData();
    fd.append("csrf", csrfEl ? csrfEl.value : "");
    fd.append("field", field);
    fd.append("value", value);
    if (extra) Object.keys(extra).forEach(function (k) { fd.append(k, extra[k]); });
    window.pmLastEdit = Date.now();
    return fetch("/proxy/" + id + "/quick", { method: "POST", body: fd, credentials: "same-origin" })
      .then(function (r) { return r.json().catch(function () { return { ok: false, msg: "Session expired — reload the page." }; }); })
      .catch(function () { return { ok: false, msg: "Network error — not saved." }; });
  }
  function rowOf(el) { return el.closest("tr"); }
  function applyRow(tr, d) {
    var sel = tr.querySelector(".lc"), inp = tr.querySelector(".uc");
    if (sel && d.lifecycle) { sel.value = d.lifecycle; sel.dataset.was = d.lifecycle; sel.className = "lc lc-" + d.lifecycle; }
    if (inp) {
      inp.value = d.usecase || ""; inp.dataset.orig = inp.value;
      if (d.last_usecase && !d.usecase) inp.placeholder = "was " + d.last_usecase;
    }
  }
  document.querySelectorAll(".uc").forEach(function (inp) {
    inp.dataset.orig = inp.value;
    function save() {
      var v = inp.value.trim();
      if (v === inp.dataset.orig) return;
      if (!v && !confirm("Remove use case " + inp.dataset.orig + " from this proxy?")) { inp.value = inp.dataset.orig; return; }
      inp.classList.add("saving");
      quick(inp.dataset.id, "usecase", v).then(function (d) {
        inp.classList.remove("saving");
        toast(d.msg, d.ok);
        if (d.ok) { applyRow(rowOf(inp), d); inp.classList.add("saved"); setTimeout(function () { inp.classList.remove("saved"); }, 1200); }
        else inp.value = inp.dataset.orig;
      });
    }
    inp.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); inp.blur(); }
      if (e.key === "Escape") { inp.value = inp.dataset.orig; inp.blur(); }
    });
    inp.addEventListener("blur", save);
  });
  document.querySelectorAll(".lc").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var tr = rowOf(sel), inp = tr.querySelector(".uc");
      var uc = inp ? inp.value.trim() : "";
      if (sel.value === "ready" && uc && !confirm("Set to Ready? This removes use case " + uc + " from the proxy.")) { sel.value = sel.dataset.was; return; }
      quick(sel.dataset.id, "lifecycle", sel.value).then(function (d) {
        toast(d.msg, d.ok);
        if (d.ok) applyRow(tr, d); else sel.value = sel.dataset.was;
      });
    });
  });
  document.querySelectorAll(".copybtn").forEach(function (b) {
    b.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(b.dataset.copy).then(function () { toast("Copied " + b.dataset.copy.split(":").slice(0, 2).join(":") + " with credentials", true); });
    });
  });

  // latency chart on the proxy page (plain SVG, no external library)
  var dataEl = document.getElementById("chartdata");
  var box = document.getElementById("chart");
  if (dataEl && box) {
    var pts = JSON.parse(dataEl.textContent);
    if (!pts.length) { box.innerHTML = '<p class="sub">No checks in the last 24 hours yet.</p>'; return; }
    var W = box.clientWidth || 800, H = 220, L = 44, R = 10, T = 10, B = 26;
    var maxV = Math.max(50, Math.max.apply(null, pts.map(function (p) { return Math.max(p.l || 0, p.s || 0); })));
    maxV = Math.ceil(maxV * 1.15 / 10) * 10;
    var n = pts.length, iw = W - L - R, ih = H - T - B;
    var x = function (i) { return L + (n === 1 ? iw / 2 : i * iw / (n - 1)); };
    var y = function (v) { return T + ih - v / maxV * ih; };
    var path = function (key) {
      var d = "", pen = false;
      pts.forEach(function (p, i) {
        if (p[key] == null) { pen = false; return; }
        d += (pen ? "L" : "M") + x(i).toFixed(1) + " " + y(p[key]).toFixed(1);
        pen = true;
      });
      return d;
    };
    var svg = '<svg width="' + W + '" height="' + H + '" role="img" aria-label="Latency chart">';
    [0, 0.5, 1].forEach(function (f) {
      var v = Math.round(maxV * f), yy = y(v).toFixed(1);
      svg += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + yy + '" y2="' + yy + '" class="gl"/>';
      svg += '<text x="' + (L - 6) + '" y="' + yy + '" class="ax" text-anchor="end" dominant-baseline="middle">' + v + '</text>';
    });
    pts.forEach(function (p, i) {
      if (!p.ok) svg += '<rect x="' + (x(i) - 1).toFixed(1) + '" y="' + T + '" width="2" height="' + ih + '" class="failbar"><title>failed ' + new Date(p.t).toLocaleTimeString() + '</title></rect>';
    });
    svg += '<path d="' + path("s") + '" class="ln smtp"/><path d="' + path("l") + '" class="ln http"/>';
    var fmt = function (t) { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
    svg += '<text x="' + L + '" y="' + (H - 6) + '" class="ax">' + fmt(pts[0].t) + '</text>';
    svg += '<text x="' + (W - R) + '" y="' + (H - 6) + '" class="ax" text-anchor="end">' + fmt(pts[n - 1].t) + '</text>';
    svg += '</svg>';
    var hasSmtp = pts.some(function (p) { return p.s != null; });
    box.innerHTML = svg + '<div class="legend"><span class="k http"></span>HTTP ms ' + (hasSmtp ? '<span class="k smtp"></span>SMTP ms ' : '') + '<span class="k fail"></span>failed check</div>';
  }
})();
