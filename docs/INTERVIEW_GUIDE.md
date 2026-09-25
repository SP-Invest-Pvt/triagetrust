# Interview guide: TriageTrust

## The 30-second version

Every AppSec vendor now ships AI triage, and teams want to let it close findings because triage eats a large share of AppSec time. Nobody ships the control that decides when that is safe. I built it: TriageTrust measures any triager against findings with known answers, repeatedly, and certifies per vulnerability category whether the AI may auto-dismiss, may only assist, or is blocked. A gate then enforces that policy on live verdicts and writes a hash-chained audit log. The policy is pinned to the model and expires, because a model upgrade silently changes behaviour.

## Why this problem

* Scanner noise is real: on the evaluation set, 35% of real FindSecBugs findings are false positives.
* AI triage is being adopted anyway, and AI security tools are inconsistent: Contrast Labs found three AI scanners agreed on 5% of findings, and one scanner reproduced 17% of its own results across runs.
* The expensive failure is asymmetric. Dismissing a real vulnerability ships it. So the metric that matters is the false-dismissal rate, and its upper confidence bound, not accuracy.

## Design choices worth defending

| Choice | Why |
|---|---|
| Real scanner output, not "flag everything" | FindSecBugs results shipped with the OWASP Benchmark, joined to ground truth. Evaluating a triager on findings no scanner produced measures the wrong distribution. |
| Wilson upper bound decides | Zero mistakes on 20 samples does not prove anything. Certification needs enough real vulnerabilities in the sample for the bound to fall below the threshold. |
| Per-category policy | A model can be excellent on crypto configuration and dangerous on SQL injection data flow. One global number hides that. |
| "Uncertain" is allowed and measured | Abstaining is correct behaviour when evidence is thin; malformed output counts as uncertain, never silently dropped. |
| Repeated runs | Consistency is a trust property. A verdict that flips between runs cannot be audited. |
| Comments stripped | Benchmark comments say "get safe value back out". Without stripping, the score measures reading comments. |
| Pinned model, expiry | Vendors update models without notice. The gate refuses verdicts from a model it did not certify. |

## Questions to expect

**"Isn't the OWASP Benchmark synthetic?"** Yes: single-file servlets. It is the best public set with complete ground truth and real scanner output. The tool ingests Checkmarx One JSON and SARIF, and a team's own historical triage states (`NOT_EXPLOITABLE`, `CONFIRMED`) become ground truth, so the real test is on your own backlog.

**"The rules triager is 100% accurate when it decides. Suspicious?"** It only decides on configuration categories where the answer is in the code: algorithm names, cookie flags. It abstains on every data-flow category. The point is that the policy engine certified exactly one category and kept everything else with analysts.

**"How would you run this in production?"** Nightly: new findings go to the vendor or LLM triager, verdicts go through the gate, auto-dismissals only where policy allows, everything else to the queue. Re-certify monthly or on any model change, on a fresh labelled sample from the team's own triage decisions.

**"What would you add next?"** Drift monitoring (sample auto-dismissed findings for human re-check), cost per finding in the scorecard, and a Checkmarx One API connector so verdicts write back as proposed states instead of files.

**"What did you use AI for?"** I used AI assistance to write code faster. The problem framing, thresholds, metric choices and the decision to strip comments are mine, and I can walk through any module.

## Numbers to know

* 2,112 real scanner findings, 742 false positives (35%).
* Rules baseline: 0 real vulnerabilities dismissed; 12.5% of noise removed; certified only for weak cryptography (93 findings auto-closed).
* Your LLM run: fill in false-dismissal upper bound, noise removed, consistency and certified categories from `results/scorecard.md`.
