"""Single-file HTML scorecard: what each triager did, and what the policy allows."""
from __future__ import annotations

import html
from pathlib import Path

from .taxonomy import display

MODE_LABEL = {"auto_dismiss": "Auto-dismiss", "assist": "Analyst decides", "blocked": "Blocked"}

CSS = """
:root{--ink:#1b2430;--muted:#5b6673;--rule:#d9dee3;--paper:#fff;--steel:#3e6a8a;--ok:#2f7d4f;--warn:#a86a12;--bad:#b23b3b;--wash:#f3f5f7}
@media (prefers-color-scheme:dark){:root{--ink:#e6eaee;--muted:#9aa5b1;--rule:#34404c;--paper:#141a21;--steel:#7fa9c8;--ok:#5fb383;--warn:#d9a441;--bad:#e07474;--wash:#1b232c}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;font-variant-numeric:tabular-nums}
main{max-width:1080px;margin:0 auto;padding:40px 24px 64px}
h1{font-size:30px;line-height:1.2;margin:0 0 8px;font-weight:650;letter-spacing:-.01em}
h2{font-size:19px;margin:44px 0 6px;font-weight:650}
p.lede{font-size:18px;color:var(--muted);max-width:70ch;margin:0 0 8px}
p.note{color:var(--muted);max-width:75ch;margin:4px 0 14px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:720px}
th,td{padding:9px 10px;border-bottom:1px solid var(--rule);text-align:right;vertical-align:middle}
th:first-child,td:first-child,.l{text-align:left}
th{font-size:13px;color:var(--muted);font-weight:600}
tr.hl td{background:var(--wash)}
.mode{display:inline-block;padding:2px 9px;border-radius:3px;font-size:13px;font-weight:600;border:1px solid}
.m-auto_dismiss{color:var(--ok);border-color:var(--ok)}.m-assist{color:var(--warn);border-color:var(--warn)}.m-blocked{color:var(--bad);border-color:var(--bad)}
.why{color:var(--muted);font-size:13px;text-align:left;max-width:340px}
.bar{position:relative;height:12px;width:160px;background:var(--wash);border-radius:2px;display:inline-block;vertical-align:middle}
.bar i{position:absolute;top:0;bottom:0;left:0;background:var(--steel);border-radius:2px}
.bar b{position:absolute;top:-3px;bottom:-3px;width:2px;background:var(--bad)}
.headline{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1px;background:var(--rule);border:1px solid var(--rule);margin:26px 0 8px}
.headline div{background:var(--paper);padding:16px}
.headline strong{display:block;font-size:26px;font-weight:650}
.headline span{color:var(--muted);font-size:14px}
footer{margin-top:48px;color:var(--muted);font-size:13px;border-top:1px solid var(--rule);padding-top:14px}
code{font-family:ui-monospace,Consolas,monospace;font-size:13px}
"""


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _bar(upper: float, limit: float) -> str:
    scale = 0.25
    w = min(upper / scale, 1) * 100
    lim = min(limit / scale, 1) * 100
    return f'<span class="bar" title="95% upper bound {_pct(upper)}; limit {_pct(limit)}"><i style="width:{w:.1f}%"></i><b style="left:{lim:.1f}%"></b></span>'


def render(evals: list[dict], policy: dict | None, title: str = "AI triage scorecard") -> str:
    e = html.escape
    rows = []
    for ev in evals:
        m, meta = ev["overall"], ev["meta"]
        certified = policy and meta["triager"] == policy["triager"] and meta.get("model", "") == policy.get("model", "")
        rows.append(
            f'<tr class="{"hl" if certified else ""}"><td>{e(meta["triager"])}<br><code>{e(meta.get("model") or "")}</code></td>'
            f'<td>{m["n"]}</td><td>{meta["runs"]}</td><td>{_pct(m["false_dismissal_rate"])}<br><small>≤ {_pct(m["false_dismissal_upper95"])}</small></td>'
            f'<td>{_pct(m["noise_reduction"])}</td><td>{_pct(m["abstention_rate"])}</td><td>{_pct(m["decided_accuracy"])}</td>'
            f'<td>{_pct(m["consistency"])}</td><td>{_pct(m["queue_precision_before"])} → {_pct(m["queue_precision_after"])}</td>'
            f'<td>{m["analyst_hours_saved"]}</td></tr>')

    body_policy = ""
    headline = ""
    if policy:
        cert = next((ev for ev in evals if ev["meta"]["triager"] == policy["triager"]
                     and ev["meta"].get("model", "") == policy.get("model", "")), evals[0])
        cats = policy["categories"]
        auto = [c for c, v in cats.items() if v["mode"] == "auto_dismiss"]
        t = policy["thresholds"]
        auto_saved = sum(cert["by_category"][c]["analyst_hours_saved"] for c in auto if c in cert["by_category"])
        auto_fd = sum(cert["by_category"][c]["dismissed_real"] for c in auto if c in cert["by_category"])
        headline = (
            '<div class="headline">'
            f'<div><strong>{len(auto)} of {len(cats)}</strong><span>categories certified for auto-dismiss</span></div>'
            f'<div><strong>{auto_saved:g} h</strong><span>analyst time returned in certified categories</span></div>'
            f'<div><strong>{auto_fd}</strong><span>real vulnerabilities auto-dismissed in the evidence</span></div>'
            f'<div><strong>{e(policy["expires_at"][:10])}</strong><span>policy expiry, then re-certify</span></div></div>')
        prow = []
        for cat, v in sorted(cats.items(), key=lambda kv: (["auto_dismiss", "assist", "blocked"].index(kv[1]["mode"]), kv[0])):
            ev_ = v["evidence"]
            prow.append(
                f'<tr><td>{e(display(cat))}</td><td class="l"><span class="mode m-{v["mode"]}">{MODE_LABEL[v["mode"]]}</span></td>'
                f'<td>{ev_["n"]}</td><td>{ev_["n_real"]}</td><td>{_bar(ev_["false_dismissal_upper95"], t["max_false_dismissal_upper95"])} {_pct(ev_["false_dismissal_upper95"])}</td>'
                f'<td>{_pct(ev_["noise_reduction"])}</td><td>{_pct(ev_["consistency"])}</td><td class="why">{e(v["reason"])}</td></tr>')
        body_policy = f"""
<h2>Automation policy for {e(policy['triager'])} <code>{e(policy.get('model') or '')}</code></h2>
<p class="note">Auto-dismiss requires the 95% upper bound on false dismissals to stay under the red line
({_pct(t['max_false_dismissal_upper95'])}), at least {t['min_real_samples']} real vulnerabilities in the evidence,
{_pct(t['min_consistency'])} identical verdicts across repeated runs, and at least {_pct(t['min_noise_reduction'])} of the noise removed.
Everything else goes to an analyst.</p>
<div class="scroll"><table><thead><tr><th>Category</th><th class="l">Mode</th><th>Findings</th><th>Real</th><th>False dismissals, 95% upper</th><th>Noise removed</th><th>Consistency</th><th class="l">Why</th></tr></thead>
<tbody>{''.join(prow)}</tbody></table></div>"""

    ds = e(evals[0]["meta"].get("dataset", "")) if evals else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{e(title)}</h1>
<p class="lede">Which security findings can an AI close on its own, and which still need a person. Measured against ground truth, not vendor claims.</p>
{headline}
<h2>Triagers compared</h2>
<p class="note">Dataset: {ds}. False dismissal means a real vulnerability the triager would have closed.
Queue precision is the share of findings left for analysts that are real.</p>
<div class="scroll"><table><thead><tr><th>Triager</th><th>Findings</th><th>Runs</th><th>False dismissals</th><th>Noise removed</th><th>Abstained</th><th>Accuracy when decided</th><th>Consistency</th><th>Queue precision</th><th>Hours saved</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
{body_policy}
<footer>Generated by TriageTrust. Hours saved assume {evals[0]['meta'].get('minutes_per_finding', 10) if evals else 10} analyst minutes per dismissed false positive.</footer>
</main></body></html>"""


def write(path: str | Path, evals: list[dict], policy: dict | None, title: str = "AI triage scorecard") -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(render(evals, policy, title), encoding="utf-8")


def markdown(evals: list[dict], policy: dict | None) -> str:
    out = ["| Triager | Model | Findings | Runs | False dismissals (95% upper) | Noise removed | Abstained | Accuracy when decided | Consistency |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for ev in evals:
        m, meta = ev["overall"], ev["meta"]
        out.append(f"| {meta['triager']} | {meta.get('model') or '-'} | {m['n']} | {meta['runs']} | "
                   f"{_pct(m['false_dismissal_rate'])} ({_pct(m['false_dismissal_upper95'])}) | {_pct(m['noise_reduction'])} | "
                   f"{_pct(m['abstention_rate'])} | {_pct(m['decided_accuracy'])} | {_pct(m['consistency'])} |")
    if policy:
        out += ["", f"Policy for `{policy['triager']}` {policy.get('model') or ''}:", "",
                "| Category | Mode | Reason |", "|---|---|---|"]
        for cat, v in sorted(policy["categories"].items()):
            out.append(f"| {display(cat)} | {MODE_LABEL[v['mode']]} | {v['reason']} |")
    return "\n".join(out)
