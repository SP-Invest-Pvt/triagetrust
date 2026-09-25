# Architecture

| Module | Responsibility |
|---|---|
| `ingest/owasp.py` | OWASP Benchmark ground truth; FindSecBugs/SpotBugs XML → findings (one per test case and category, as an analyst would triage them) |
| `ingest/checkmarx.py` | Checkmarx One results JSON; full source-to-sink node path plus code windows; triage state → label |
| `ingest/sarif.py` | SARIF 2.1.0; CWE from rule tags; code flows; suppressions → label |
| `context.py` | Code windows around relevant lines; licence-header stripping; comment stripping so annotations cannot leak the answer |
| `triagers/scanner.py` | Baseline: accept everything |
| `triagers/rules.py` | Deterministic rules for configuration-type weaknesses; abstains on data flow |
| `triagers/llm.py` | Prompt, strict JSON contract, explicit abstention |
| `providers.py` | Gemini, Anthropic, OpenAI-compatible, Ollama over stdlib HTTP; disk cache; retry with backoff on 429/5xx |
| `evaluate.py` | Stratified sampling, parallel repeated runs, majority vote (tie = uncertain), metrics |
| `stats.py` | Wilson score interval |
| `policy.py` | Thresholds → per-category mode; pinned triager/model; expiry |
| `gate.py` | Policy enforcement on live verdicts; hash-chained audit records |
| `report.py` | Self-contained HTML and Markdown scorecard |

## Metric definitions

For findings with ground truth, a triager's final verdict is the majority across runs (a tie is "uncertain").

* False-dismissal rate = real vulnerabilities marked false positive ÷ real vulnerabilities.
* Noise removed = false positives marked false positive ÷ false positives.
* Abstention rate = uncertain ÷ all findings.
* Accuracy when decided = correct ÷ findings with a verdict other than uncertain.
* Consistency = findings whose verdict was identical on every run ÷ all findings.
* Queue precision = real ÷ findings still left for analysts.
* Hours saved = correctly dismissed false positives × minutes per finding ÷ 60.

## Certification rule (defaults, all configurable)

A category is `auto_dismiss` only if all hold: at least 30 real vulnerabilities in the evidence; 95% upper bound on false dismissals ≤ 5%; consistency ≥ 95%; at least 25% of false positives removed. It is `blocked` if accuracy when decided < 60% or consistency < 80%. Otherwise `assist`. Categories where the scanner produced no false positives stay `assist`: there is nothing to automate. Policies expire after 90 days.

## Gate behaviour

| AI verdict | Category mode | Confidence | Action |
|---|---|---|---|
| true_positive | any | any | fix_queue |
| false_positive | auto_dismiss | ≥ 0.80 | auto_dismiss |
| false_positive | auto_dismiss | < 0.80 | human_review |
| any other | assist | any | human_review (AI suggestion shown) |
| any other | blocked | any | human_review (AI suggestion hidden) |

Each audit record includes the SHA-256 of the previous record, so deleting or editing one breaks the chain.
