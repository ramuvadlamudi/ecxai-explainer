# EC-XAI explainer

A single static page that explains a security alert and checks the explanation with seven fixed formulas (M1–M7).
Enter the alert, its evidence items with a normal baseline, and the telemetry sources you could query. The page
shows the most specific evidence, maps it to MITRE ATT&CK, lists telemetry gaps and blind spots, and removes claims
the record cannot support.

Same input, same output. There is no language model, no randomness and no network call. All processing happens in
the browser.

## Use

Open the page, load a worked example (data exfiltration, lateral movement, password spraying, a weak explanation,
C2 beaconing), then change the values or start blank. **Copy share link** puts the whole input in the URL fragment,
which browsers do not send to the server.

## The formulas

- Benign share `b(x)`: share of normal-activity values at least as suspicious as the alert's value, or a share
  entered directly (e.g. `23.4%`). Benign-common means `b ≥ 0.10`. Weight `w = 1 − b`. The top-k items by weight
  are shown.
- `K`: ATT&CK data components that detect the mapped techniques in the target tactic and the shown items'
  techniques. Relevant sources provide a component in `K`.

| Check | Formula | Flag when | Action |
|---|---|---|---|
| M1 Attack specificity | 1 − mean `b` over shown items | < 0.90 | Demote normal-looking items |
| M2 Shortcut exposure | attribution on benign-common items ÷ positive attribution | ≥ 0.50 | Counterfactual re-score |
| M3 Coverage-relative completeness | relevant sources collected ÷ relevant sources | < 1 | Hold absence claims, request telemetry |
| M4 Observability | components in `K` provided by a source ÷ `|K|` | < 0.50 | List blind spots |
| M5 Threat alignment | weight of shown items in the target tactic ÷ weight of shown items | < 0.50 | Label as off-threat |
| M6 Grounding precision | valid claims ÷ proposed claims | < 1 | Remove invalid claims; abstain below two |
| M7 Environment–model agreement | top-k by weight ∩ top-k by attribution ÷ k | = 0 | Deep checks |

## Limits

A teaching tool. The worked examples are illustrative inputs, not measured data. The checks test whether an
explanation is consistent with the alert record and the data catalogue, not whether the alert is a true attack.
They have not been validated with analysts. The weight here is simplified (1 − b); the thesis also uses threat
relevance and proximity.

## Tests

Open `tests/run.html` in a browser. It runs every worked example against hand-computed values and prints `PASS` or
the failures.

## Sources

Based on the MRes thesis *A Lightweight, Domain-Aware Explanation Sidecar for Cyber Threat Alerts: Real-Time SOC
Metrics Bound to the Data Catalogue*, Rama Vadlamudi, University of Canberra, 2026.

`attack.js` is derived from MITRE ATT&CK Enterprise v16.1. © The MITRE Corporation. This work is reproduced and
distributed with the permission of The MITRE Corporation. See the
[ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
