/* EC-XAI explanation assurance: deterministic per-alert metrics M1–M7 bound to a data catalogue.
   Definitions follow the thesis (Section 4.11, Appendix G). Same input, same output: no randomness, no model. */
(function (root) {
  "use strict";

  var BETA = 0.10;                                   // benign share at which an item counts as benign-common
  var ABSENCE_ALLOWED = ["collected", "collected_empty"];
  var THRESHOLDS = {
    M1: { test: function (v) { return v < 0.90; }, text: "< 0.90" },
    M2: { test: function (v) { return v >= 0.50; }, text: "≥ 0.50" },
    M3: { test: function (v) { return v < 1; }, text: "< 1" },
    M4: { test: function (v) { return v < 0.50; }, text: "< 0.50" },
    M5: { test: function (v) { return v < 0.50; }, text: "< 0.50" },
    M6: { test: function (v) { return v < 1; }, text: "< 1" },
    M7: { test: function (v) { return v === 0; }, text: "= 0" }
  };
  var METRICS = {
    M1: ["Attack specificity", "Is the evidence specific to attacks, or common in normal activity?",
         "Demote the normal-looking items and show the next specific one."],
    M2: ["Shortcut exposure", "Does the detector lean on evidence that normal activity also shows?",
         "Warn, and re-score once with the most-attributed normal-looking item set to its normal value."],
    M3: ["Coverage-relative completeness", "Was the telemetry that could confirm or refute this alert collected?",
         "Hold absence claims, request the missing sources, and re-explain when they arrive."],
    M4: ["Observability", "Does this environment collect the data ATT&CK says detects these techniques?",
         "List the blind spots."],
    M5: ["Threat alignment", "Does the evidence point to the threat this detector is for?",
         "Label the explanation as off-threat."],
    M6: ["Grounding precision", "Is every proposed statement true of the alert record?",
         "Remove the invalid claims; abstain below two valid claims."],
    M7: ["Environment–model agreement", "Do the environment and the model point to the same evidence?",
         "Show both rankings, labelled, and send the alert to deeper checks."]
  };

  function parent(t) { return String(t).split(".")[0]; }

  function num(x) {
    var v = typeof x === "number" ? x : parseFloat(String(x).trim());
    return isFinite(v) ? v : null;
  }

  // b_e(x): share of the benign baseline at least as suspicious as x. Baseline is either "23.4%" or a list of values.
  function benignShare(item) {
    var base = String(item.baseline == null ? "" : item.baseline).trim();
    if (/%$/.test(base)) {
      var p = num(base.slice(0, -1));
      return p == null ? null : Math.min(1, Math.max(0, p / 100));
    }
    var xs = base.split(/[\s,;]+/).map(num).filter(function (v) { return v != null; });
    var x = num(item.value);
    if (!xs.length || x == null) return null;
    var higher = item.direction !== "lower";
    var n = xs.filter(function (v) { return higher ? v >= x : v <= x; }).length;
    return n / xs.length;
  }

  function techList(s) {
    return String(s || "").split(/[\s,;]+/).map(function (t) { return t.trim().toUpperCase(); })
      .filter(function (t) { return /^T\d{4}(\.\d{3})?$/.test(t); });
  }

  function compList(s) {
    return (Array.isArray(s) ? s : String(s || "").split(/[,;]+/)).map(function (c) { return String(c).trim(); })
      .filter(Boolean);
  }

  function inTactic(techs, tactic, kb) {
    return techs.some(function (t) {
      var r = kb.techniques[t] || kb.techniques[parent(t)];
      return r && r.ta.indexOf(tactic) >= 0;
    });
  }

  function componentsFor(techs, kb) {
    var out = {};
    techs.forEach(function (t) {
      [t, parent(t)].forEach(function (u) {
        var r = kb.techniques[u];
        if (r) r.dc.forEach(function (c) { out[c] = true; });
      });
    });
    return Object.keys(out).sort();
  }

  function topk(items, key, k) {
    return items.filter(function (it) { return it[key] != null && it[key] > 0; })
      .slice().sort(function (a, b) { return b[key] - a[key] || (a.idx - b.idx); })
      .slice(0, k).map(function (it) { return it.idx; });
  }

  function logit(p) { p = Math.min(1 - 1e-9, Math.max(1e-9, p)); return Math.log(p / (1 - p)); }

  function compute(input, kb) {
    var t0 = (typeof performance !== "undefined" ? performance : Date).now();
    var k = Math.max(1, Math.floor(num(input.k) || 3));
    var tactic = input.tactic;
    var sources = (input.sources || []).map(function (s) {
      return { name: String(s.name || "").trim(), state: s.state || "collected", components: compList(s.components) };
    }).filter(function (s) { return s.name; });
    var srcByName = {};
    sources.forEach(function (s) { srcByName[s.name] = s; });

    var items = (input.items || []).map(function (it, idx) {
      var b = benignShare(it);
      var techs = techList(it.techniques);
      var w = num(it.weight);
      return {
        idx: idx, name: String(it.name || "item " + (idx + 1)).trim(), value: it.value, direction: it.direction,
        source: String(it.source || "").trim(), techniques: techs, b: b,
        w: w != null ? w : (b == null ? null : 1 - b),
        phi: num(it.attribution), inTactic: inTactic(techs, tactic, kb)
      };
    });

    var shownIdx = topk(items, "w", k);
    var shown = shownIdx.map(function (i) { return items[i]; });

    // M1
    var bs = shown.map(function (it) { return it.b; }).filter(function (b) { return b != null; });
    var M1 = bs.length ? 1 - bs.reduce(function (a, b) { return a + b; }, 0) / bs.length : null;

    // M2 (needs attribution)
    var phis = items.filter(function (it) { return it.phi != null; });
    var pos = phis.reduce(function (a, it) { return a + Math.max(0, it.phi); }, 0);
    var M2 = phis.length && pos > 0 ? phis.reduce(function (a, it) {
      return a + (it.b != null && it.b >= BETA ? Math.max(0, it.phi) : 0);
    }, 0) / pos : null;

    // scope Ω: mapped techniques in the tactic, else all mapped techniques
    var mapped = {};
    items.forEach(function (it) { it.techniques.forEach(function (t) { mapped[t] = true; }); });
    var scope = Object.keys(mapped).filter(function (t) { return inTactic([t], tactic, kb); });
    if (!scope.length) scope = Object.keys(mapped);
    var techsK = scope.slice();
    shown.forEach(function (it) { it.techniques.forEach(function (t) { if (techsK.indexOf(t) < 0) techsK.push(t); }); });
    var K = componentsFor(techsK, kb);

    // M3
    var relevant = sources.filter(function (s) { return s.components.some(function (c) { return K.indexOf(c) >= 0; }); });
    var collected = relevant.filter(function (s) { return ABSENCE_ALLOWED.indexOf(s.state) >= 0; });
    var missing = relevant.filter(function (s) { return ABSENCE_ALLOWED.indexOf(s.state) < 0; });
    var M3 = relevant.length ? collected.length / relevant.length : null;

    // M4
    var provided = {};
    sources.forEach(function (s) { s.components.forEach(function (c) { provided[c] = true; }); });
    var seen = K.filter(function (c) { return provided[c]; });
    var blind = K.filter(function (c) { return !provided[c]; });
    var M4 = K.length ? seen.length / K.length : null;

    // M5
    var ws = shown.reduce(function (a, it) { return a + it.w; }, 0);
    var M5 = ws > 0 ? shown.reduce(function (a, it) { return a + (it.inTactic ? it.w : 0); }, 0) / ws : null;

    // M7 (needs attribution)
    var M7 = null, phiTop = [];
    if (phis.length) {
      phiTop = topk(items, "phi", k);
      M7 = shownIdx.filter(function (i) { return phiTop.indexOf(i) >= 0; }).length / k;
    }

    // claims: evidence, technique and absence claims, each checked against the record (M6)
    var claims = [];
    shown.forEach(function (it) {
      var src = srcByName[it.source];
      claims.push({ kind: "evidence", text: it.name + " = " + it.value + (it.b != null ?
        " (" + pct(it.b) + " of normal activity is at least this suspicious)" : ""),
        valid: !!src && ABSENCE_ALLOWED.indexOf(src.state) >= 0 && src.state !== "collected_empty",
        why: !src ? "its source is not in the data catalogue" : (src.state !== "collected" ?
          "its source is marked " + src.state.replace(/_/g, " ") : "") });
      it.techniques.forEach(function (t) {
        var r = kb.techniques[t];
        claims.push({ kind: "technique", text: it.name + " is evidence for " + t + (r ? " " + r.n : ""),
          valid: !!r, why: r ? "" : t + " is not an ATT&CK v16.1 technique" });
      });
    });
    relevant.forEach(function (s) {
      var hasShown = shown.some(function (it) { return it.source === s.name; });
      if (hasShown) return;
      var ok = ABSENCE_ALLOWED.indexOf(s.state) >= 0;
      claims.push({ kind: "absence", text: "No suspicious activity was observed in " + s.name,
        valid: ok, why: ok ? "" : s.name + (s.state === "query_failed" ? "'s query failed" : " was not collected") +
          ", so absence cannot be claimed" });
    });
    var nValid = claims.filter(function (c) { return c.valid; }).length;
    var M6 = claims.length ? nValid / claims.length : null;

    var values = { M1: M1, M2: M2, M3: M3, M4: M4, M5: M5, M6: M6, M7: M7 };
    var metrics = Object.keys(METRICS).map(function (id) {
      var v = values[id];
      var flagged = v != null && THRESHOLDS[id].test(v);
      return { id: id, name: METRICS[id][0], question: METRICS[id][1], value: v, threshold: THRESHOLDS[id].text,
               flagged: flagged, action: flagged ? METRICS[id][2] : null,
               note: v == null ? (id === "M2" || id === "M7" ? "needs model attribution" : "not computable") : null };
    });

    var score = num(input.score), thr = num(input.threshold);
    var margin = score != null && thr != null ? logit(score) - logit(thr) : null;
    var ms = (typeof performance !== "undefined" ? performance : Date).now() - t0;
    return {
      shown: shown, items: items, phiTop: phiTop, scope: scope, components: K, relevant: relevant,
      missing: missing, blind: blind, claims: claims, metrics: metrics, margin: margin, ms: ms,
      abstain: nValid < 2
    };
  }

  function pct(x) { return (100 * x).toFixed(x > 0 && x < 0.1 ? 1 : 0).replace(/\.0$/, "") + "%"; }

  var api = { compute: compute, benignShare: benignShare, pct: pct, METRICS: METRICS, THRESHOLDS: THRESHOLDS,
              BETA: BETA };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ECX = api;
})(this);
