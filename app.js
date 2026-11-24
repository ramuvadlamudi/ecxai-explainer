(function () {
  "use strict";
  var KB = window.ECX_ATTACK, ECX = window.ECX, EXAMPLES = window.ECX_EXAMPLES;
  var TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact"];
  var STATES = [["collected", "collected"], ["collected_empty", "collected, empty"],
    ["not_collected", "not collected"], ["query_failed", "query failed"]];
  var LIMITS = { items: 40, sources: 30, text: 4000 };

  function $(id) { return document.getElementById(id); }

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (a) {
      if (a === "text") n.textContent = attrs[a];
      else if (a === "class") n.className = attrs[a];
      else n.setAttribute(a, attrs[a]);
    });
    (kids || []).forEach(function (k) { n.appendChild(typeof k === "string" ? document.createTextNode(k) : k); });
    return n;
  }

  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function fmt(v, d) { return v == null ? "—" : Number(v).toFixed(d == null ? 2 : d); }
  function human(s) { return String(s).replace(/-/g, " ").replace(/_/g, " "); }
  function str(v) { return String(v == null ? "" : v).slice(0, LIMITS.text); }

  // ---------------------------------------------------------------- form building

  function input(cls, value, attrs) {
    var i = el("input", Object.assign({ type: "text", class: cls }, attrs || {}));
    i.value = value == null ? "" : value;
    return i;
  }

  function select(cls, options, value) {
    var s = el("select", { class: cls });
    options.forEach(function (o) { s.appendChild(el("option", { value: o[0], text: o[1] })); });
    s.value = value;
    return s;
  }

  function removeButton() {
    var b = el("button", { type: "button", class: "remove", "aria-label": "Remove row", text: "×" });
    b.addEventListener("click", function () { b.closest("tr").remove(); update(); });
    return b;
  }

  function addItemRow(it) {
    it = it || {};
    var tr = el("tr", {}, [
      el("td", {}, [input("f-name", it.name, { placeholder: "name" })]),
      el("td", {}, [input("f-value", it.value, { placeholder: "value" })]),
      el("td", {}, [select("f-direction", [["higher", "higher"], ["lower", "lower"]], it.direction || "higher")]),
      el("td", { class: "wide" }, [input("f-baseline", it.baseline, { placeholder: "values, or a share like 12%" })]),
      el("td", {}, [input("f-source", it.source, { placeholder: "source" })]),
      el("td", {}, [input("f-techniques", it.techniques, { placeholder: "none" })]),
      el("td", {}, [input("f-attribution", it.attribution, { placeholder: "none" })]),
      el("td", {}, [removeButton()])
    ]);
    $("items-table").tBodies[0].appendChild(tr);
  }

  function addSourceRow(s) {
    s = s || {};
    var tr = el("tr", {}, [
      el("td", {}, [input("f-sname", s.name, { placeholder: "source" })]),
      el("td", {}, [select("f-state", STATES, s.state || "collected")]),
      el("td", { class: "wide" }, [input("f-components", s.components,
        { placeholder: "e.g. Process Creation, Command Execution", list: "components" })]),
      el("td", {}, [removeButton()])
    ]);
    $("sources-table").tBodies[0].appendChild(tr);
  }

  function fill(state) {
    var a = state.alert || {};
    $("a-title").value = str(a.title); $("a-detector").value = str(a.detector);
    $("a-score").value = a.score == null ? "" : a.score; $("a-threshold").value = a.threshold == null ? "" : a.threshold;
    $("a-tactic").value = TACTICS.indexOf(a.tactic) >= 0 ? a.tactic : "lateral-movement";
    $("a-k").value = a.k || 3;
    clear($("items-table").tBodies[0]); clear($("sources-table").tBodies[0]);
    (state.items || []).slice(0, LIMITS.items).forEach(addItemRow);
    (state.sources || []).slice(0, LIMITS.sources).forEach(addSourceRow);
    update();
  }

  function read() {
    function rows(id, fields) {
      return Array.prototype.map.call($(id).tBodies[0].rows, function (tr) {
        var o = {};
        Object.keys(fields).forEach(function (k) { o[k] = str(tr.querySelector("." + fields[k]).value); });
        return o;
      });
    }
    return {
      alert: { title: str($("a-title").value), detector: str($("a-detector").value),
               score: $("a-score").value === "" ? null : Number($("a-score").value),
               threshold: $("a-threshold").value === "" ? null : Number($("a-threshold").value),
               tactic: $("a-tactic").value, k: Number($("a-k").value) || 3 },
      items: rows("items-table", { name: "f-name", value: "f-value", direction: "f-direction",
        baseline: "f-baseline", source: "f-source", techniques: "f-techniques", attribution: "f-attribution" }),
      sources: rows("sources-table", { name: "f-sname", state: "f-state", components: "f-components" })
    };
  }

  // ---------------------------------------------------------------- rendering

  function techLabel(t) { var r = KB.techniques[t]; return r ? t + " " + r.n : t + " (not in ATT&CK v16.1)"; }

  function renderNarrative(state, r) {
    var box = $("narrative"); clear(box);
    var a = state.alert, flag = {};
    r.metrics.forEach(function (m) { flag[m.id] = m; });
    var head = (a.title || "This alert") + " was raised by " + (a.detector || "the detector");
    if (a.score != null && a.threshold != null)
      head += " with score " + a.score + " against threshold " + a.threshold +
        " (logit margin " + (r.margin >= 0 ? "+" : "") + fmt(r.margin) + ")";
    box.appendChild(el("p", { text: head + "." }));

    if (!r.shown.length) {
      box.appendChild(el("p", { class: "callout info", text: "Add evidence items with a value and a normal baseline to get an explanation." }));
      return;
    }
    box.appendChild(el("p", { text: "The evidence that best separates it from normal activity:" }));
    var ul = el("ul");
    r.shown.forEach(function (it) {
      var bits = [it.name + " = " + it.value + ": "];
      bits.push(it.b === 0 ? "no normal activity in the baseline is this suspicious" :
        "only " + ECX.pct(it.b) + " of normal activity is at least this suspicious");
      if (it.source) bits.push(" (" + it.source + ")");
      if (it.techniques.length) bits.push(". ATT&CK: " + it.techniques.map(techLabel).join("; "));
      ul.appendChild(el("li", { text: bits.join("") + "." }));
    });
    box.appendChild(ul);

    var benignTop = r.items.filter(function (it) {
      return r.phiTop.indexOf(it.idx) >= 0 && it.b != null && it.b >= ECX.BETA;
    });
    if (flag.M2.flagged && benignTop.length)
      box.appendChild(el("p", { class: "callout", text: "Shortcut warning (M2 = " + fmt(flag.M2.value) + "): the detector leans on " +
        benignTop.map(function (it) { return it.name + ", which " + ECX.pct(it.b) + " of normal activity also shows"; }).join("; ") +
        ". Re-score with that item set to its normal value before acting on the model's ranking." }));
    if (flag.M1.flagged)
      box.appendChild(el("p", { class: "callout", text: "Weak specificity (M1 = " + fmt(flag.M1.value) +
        "): the shown evidence is common in normal activity. Treat this explanation as weak." }));
    if (r.missing.length)
      box.appendChild(el("p", { class: "callout", text: "Telemetry gap (M3 = " + fmt(flag.M3.value) + "): " +
        r.missing.map(function (s) { return s.name + " (" + human(s.state) + ")"; }).join(", ") +
        ". Absence of activity in these sources cannot be claimed. Request them and re-explain." }));
    if (r.blind.length)
      box.appendChild(el("p", { class: flag.M4.flagged ? "callout" : "callout info", text: "Blind spots (M4 = " + fmt(flag.M4.value) +
        "): no catalogue source provides " + r.blind.join(", ") + ", which ATT&CK lists for these techniques." }));
    if (flag.M5.flagged)
      box.appendChild(el("p", { class: "callout", text: "Off-threat (M5 = " + fmt(flag.M5.value) +
        "): most of the shown evidence does not map to " + human(a.tactic) + "." }));
    if (flag.M7.flagged)
      box.appendChild(el("p", { class: "callout", text: "Disagreement (M7 = 0): the model and the environment point to " +
        "different evidence. Both rankings are shown below. Send the alert to deeper checks." }));
    var absences = r.claims.filter(function (c) { return c.kind === "absence" && c.valid; });
    absences.forEach(function (c) { box.appendChild(el("p", { text: c.text + "." })); });
    if (r.abstain)
      box.appendChild(el("p", { class: "callout", text: "Fewer than two claims survive validation, so the explainer abstains." }));
    var flagged = r.metrics.filter(function (m) { return m.flagged; }).map(function (m) { return m.id; });
    box.appendChild(el("p", { class: flagged.length ? "callout info" : "callout good",
      text: flagged.length ? "Checks flagged: " + flagged.join(", ") + ". Actions are listed below."
                           : "No check flagged. The explanation is consistent with the record and the catalogue." }));
  }

  function renderMetrics(r) {
    var tb = $("metrics-table").tBodies[0]; clear(tb);
    r.metrics.forEach(function (m) {
      var pill = m.value == null ? el("span", { class: "pill na", text: m.note })
        : el("span", { class: "pill " + (m.flagged ? "bad" : "ok"), text: m.flagged ? "flag" : "pass" });
      tb.appendChild(el("tr", {}, [
        el("td", {}, [el("b", { text: m.id }), " " + m.name]), el("td", { text: m.question }),
        el("td", { class: "num", text: fmt(m.value) }), el("td", { class: "num", text: m.threshold }),
        el("td", {}, [pill]), el("td", { text: m.action || "—" })]));
    });
  }

  function renderRank(r) {
    var tb = $("rank-table").tBodies[0]; clear(tb);
    r.items.slice().sort(function (a, b) { return (b.w == null ? -1 : b.w) - (a.w == null ? -1 : a.w) || a.idx - b.idx; })
      .forEach(function (it) {
        var shown = r.shown.indexOf(it) >= 0;
        tb.appendChild(el("tr", {}, [
          el("td", {}, [shown ? el("b", { text: it.name }) : it.name]), el("td", { class: "num", text: str(it.value) }),
          el("td", { class: "num", text: it.b == null ? "—" : ECX.pct(it.b) }), el("td", { class: "num", text: fmt(it.w) }),
          el("td", { class: "num", text: fmt(it.phi) + (r.phiTop.indexOf(it.idx) >= 0 ? " (top)" : "") }),
          el("td", { text: it.techniques.length ? (it.inTactic ? "yes" : "no") : "unmapped" }),
          el("td", { text: shown ? "shown" : "" })]));
      });
  }

  function renderCoverage(r) {
    var box = $("coverage"); clear(box);
    box.appendChild(el("p", { text: "Techniques in scope: " + (r.scope.length ? r.scope.map(techLabel).join("; ") : "none mapped") + "." }));
    box.appendChild(el("p", { text: "Data components that detect them (K): " + (r.components.join(", ") || "none") + "." }));
    box.appendChild(el("p", { text: "Relevant sources: " + (r.relevant.map(function (s) {
      return s.name + " (" + human(s.state) + ")"; }).join(", ") || "none") + "." }));
  }

  function renderClaims(r) {
    var ul = $("claims"); clear(ul);
    r.claims.forEach(function (c) {
      ul.appendChild(el("li", { class: c.valid ? "valid" : "invalid" }, [
        el("span", { class: "mark", text: c.valid ? "✓" : "✗" }),
        c.kind + ": " + c.text + (c.valid ? "" : " — removed: " + c.why)]));
    });
  }

  function canonical(v) {
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (v && typeof v === "object")
      return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(v[k]); }).join(",") + "}";
    return JSON.stringify(v);
  }

  function sha256(text) {
    if (!(window.crypto && crypto.subtle)) return Promise.resolve(null);
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
  }

  var seq = 0;
  function renderFingerprint(state, r) {
    var mine = ++seq;
    var out = { metrics: r.metrics.map(function (m) { return [m.id, m.value == null ? null : +m.value.toFixed(6), m.flagged]; }),
                shown: r.shown.map(function (it) { return it.name; }),
                claims: r.claims.map(function (c) { return [c.text, c.valid]; }) };
    Promise.all([sha256(canonical(state)), sha256(canonical(out))]).then(function (h) {
      if (mine !== seq) return;
      var t = "Computed in " + (r.ms < 0.1 ? "under 0.1" : r.ms.toFixed(1)) + " ms in this browser.";
      $("fingerprint").textContent = h[0] ? "Input SHA-256: " + h[0] + "\nOutput SHA-256: " + h[1] + "\n" + t :
        t + " (Fingerprints need HTTPS or localhost.)";
    });
  }

  var timer = null;
  function update() { clearTimeout(timer); timer = setTimeout(run, 120); }

  function run() {
    var state = read();
    var r = ECX.compute({ items: state.items, sources: state.sources, tactic: state.alert.tactic, k: state.alert.k,
                          score: state.alert.score, threshold: state.alert.threshold }, KB);
    renderNarrative(state, r); renderMetrics(r); renderRank(r); renderCoverage(r); renderClaims(r);
    renderFingerprint(state, r);
    document.body.setAttribute("data-ready", "1");
  }

  // ---------------------------------------------------------------- sharing

  function toB64(s) {
    var bytes = new TextEncoder().encode(s), bin = "";
    bytes.forEach(function (b) { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    var bin = atob(s), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function sanitize(o) {
    if (!o || typeof o !== "object") throw new Error("not an object");
    var a = o.alert && typeof o.alert === "object" ? o.alert : {};
    function n(v) { var x = Number(v); return v === null || v === "" || !isFinite(x) ? null : x; }
    function rowsOf(list, keys, max) {
      return (Array.isArray(list) ? list : []).slice(0, max).map(function (r) {
        var out = {}; keys.forEach(function (k) { out[k] = str(r && r[k]); }); return out;
      });
    }
    return {
      alert: { title: str(a.title), detector: str(a.detector), score: n(a.score), threshold: n(a.threshold),
               tactic: TACTICS.indexOf(a.tactic) >= 0 ? a.tactic : "lateral-movement", k: Math.min(10, Math.max(1, n(a.k) || 3)) },
      items: rowsOf(o.items, ["name", "value", "direction", "baseline", "source", "techniques", "attribution"], LIMITS.items),
      sources: rowsOf(o.sources, ["name", "state", "components"], LIMITS.sources).map(function (s) {
        if (!STATES.some(function (x) { return x[0] === s.state; })) s.state = "not_collected"; return s; })
    };
  }

  function status(msg) { $("share-status").textContent = msg; }

  // ---------------------------------------------------------------- init

  function init() {
    TACTICS.forEach(function (t) { $("a-tactic").appendChild(el("option", { value: t, text: human(t) })); });
    KB.components.forEach(function (c) { $("components").appendChild(el("option", { value: c })); });
    EXAMPLES.forEach(function (ex) { $("example").appendChild(el("option", { value: ex.id, text: ex.label })); });

    $("load").addEventListener("click", function () {
      var ex = EXAMPLES.filter(function (e) { return e.id === $("example").value; })[0];
      $("example-note").textContent = "Illustrative inputs. " + ex.note;
      fill(ex);
    });
    $("blank").addEventListener("click", function () {
      $("example-note").textContent = "";
      fill({ alert: { tactic: $("a-tactic").value || "exfiltration", k: 3 }, items: [{}], sources: [{}] });
    });
    $("add-item").addEventListener("click", function () { addItemRow(); });
    $("add-source").addEventListener("click", function () { addSourceRow(); });
    document.querySelector("main").addEventListener("input", function (e) { if (e.target.id !== "json") update(); });
    document.querySelector("main").addEventListener("change", function (e) { if (e.target.id !== "json") update(); });

    $("share").addEventListener("click", function () {
      var url = location.href.split("#")[0] + "#s=" + toB64(JSON.stringify(read()));
      history.replaceState(null, "", url);
      if (navigator.clipboard) navigator.clipboard.writeText(url).then(function () { status("Link copied."); },
        function () { status("Link is in the address bar."); });
      else status("Link is in the address bar.");
    });
    $("export").addEventListener("click", function () {
      $("json").hidden = false; $("json").value = JSON.stringify(read(), null, 2); status("");
    });
    $("import").addEventListener("click", function () {
      if ($("json").hidden) { $("json").hidden = false; $("json").value = ""; status("Paste JSON, then press Load JSON again."); return; }
      try { fill(sanitize(JSON.parse($("json").value))); status("Loaded."); }
      catch (e) { status("Could not read that JSON."); }
    });

    var m = /#s=([A-Za-z0-9_-]+)/.exec(location.hash);
    if (m) {
      try { fill(sanitize(JSON.parse(fromB64(m[1])))); $("example-note").textContent = "Loaded from a shared link."; return; }
      catch (e) { $("example-note").textContent = "The shared link could not be read; showing an example instead."; }
    }
    $("example").value = EXAMPLES[0].id;
    $("load").click();
  }

  init();
})();
