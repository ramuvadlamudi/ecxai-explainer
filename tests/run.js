/* Hand-computed expectations for the worked examples. Open run.html; the page prints PASS or the failures. */
(function () {
  "use strict";
  var fails = [], lines = [];
  function near(a, b) { return a === b || (a != null && b != null && Math.abs(a - b) < 1e-9); }
  function check(name, got, want) {
    if (!near(got, want)) fails.push(name + ": got " + got + ", want " + want);
  }
  function run(id) {
    var ex = window.ECX_EXAMPLES.filter(function (e) { return e.id === id; })[0];
    var r = ECX.compute({ items: ex.items, sources: ex.sources, tactic: ex.alert.tactic, k: ex.alert.k,
                          score: ex.alert.score, threshold: ex.alert.threshold }, window.ECX_ATTACK);
    var m = {};
    r.metrics.forEach(function (x) { m[x.id] = x; });
    lines.push(id + ": shown=" + r.shown.map(function (i) { return i.name; }).join(",") + " " +
      r.metrics.map(function (x) { return x.id + "=" + (x.value == null ? "na" : x.value.toFixed(4)) + (x.flagged ? "!" : ""); }).join(" ") +
      " blind=" + r.blind.join("|") + " missing=" + r.missing.map(function (s) { return s.name; }).join("|"));
    return { r: r, m: m };
  }

  check("b list higher", ECX.benignShare({ value: "3", direction: "higher", baseline: "1 2 3 4" }), 0.5);
  check("b list lower", ECX.benignShare({ value: "2", direction: "lower", baseline: "1 2 3 4" }), 0.5);
  check("b percent", ECX.benignShare({ value: "1", baseline: "23.4%" }), 0.234);
  check("b empty", ECX.benignShare({ value: "1", baseline: "" }), null);

  var e = run("exfil");
  check("exfil shown", e.r.shown.map(function (i) { return i.name; }).join(","),
        "bytes_out_gb_1h,out_to_in_byte_ratio,upload_to_cloud_storage");
  check("exfil M1", e.m.M1.value, 1 - (0.025 + 0.025 + 0.04) / 3);
  check("exfil M2", e.m.M2.value, 0.55); check("exfil M2 flag", e.m.M2.flagged, true);
  check("exfil M3", e.m.M3.value, 3 / 5);
  check("exfil M5", e.m.M5.value, 1);
  check("exfil M6", e.m.M6.value, 8 / 10);
  check("exfil M7", e.m.M7.value, 2 / 3);
  check("exfil dns b", e.r.items[5].b, 12 / 25);

  var l = run("lateral");
  check("lateral shown", l.r.shown.map(function (i) { return i.name; }).join(","),
        "new_src_dst_pair,user_distinct_dst_24h,src_logons_1h");
  check("lateral M1", l.m.M1.value, 1 - (0.03 + 0.05 + 0.05) / 3);
  check("lateral M2", l.m.M2.value, 0.67);
  check("lateral M3", l.m.M3.value, 0.5);
  check("lateral M5", l.m.M5.value, 1);
  check("lateral M7", l.m.M7.value, 2 / 3);

  var s = run("spray");
  check("spray shown", s.r.shown.map(function (i) { return i.name; }).join(","),
        "failed_signins_10m,distinct_accounts_failed_10m,success_after_failures");
  check("spray M2", s.m.M2.value, null); check("spray M7", s.m.M7.value, null);
  check("spray M3", s.m.M3.value, 2 / 3);
  check("spray M5", s.m.M5.value, 2 / 2.98);
  check("spray M6", s.m.M6.value, 7 / 8);

  var w = run("weak");
  check("weak M1", w.m.M1.value, 1 - (0.09 + 0.12 + 0.18) / 3); check("weak M1 flag", w.m.M1.flagged, true);
  check("weak M2", w.m.M2.value, 0.98);
  check("weak M5", w.m.M5.value, 0); check("weak M5 flag", w.m.M5.flagged, true);
  check("weak M7", w.m.M7.value, 0); check("weak M7 flag", w.m.M7.flagged, true);

  var b = run("beacon");
  check("beacon M1", b.m.M1.value, 1 - (0 + 0.05 + 0.08) / 3);
  check("beacon M2", b.m.M2.value, 0.30);
  check("beacon M3", b.m.M3.value, 1);
  check("beacon M6", b.m.M6.value, 1);
  check("beacon M7", b.m.M7.value, 2 / 3);

  var a1 = JSON.stringify(run("exfil").r.metrics), a2 = JSON.stringify(run("exfil").r.metrics);
  check("deterministic", a1 === a2, true);

  document.getElementById("out").textContent = (fails.length ? "FAIL\n" + fails.join("\n") : "PASS") + "\n\n" + lines.join("\n");
})();
