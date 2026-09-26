# TriageTrust

Evidence-based governance for AI triage of security findings: measure when an AI may close SAST findings on its own, and prove it to an auditor.

[![tests](https://github.com/SP-Invest-Pvt/triagetrust/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml) [![codeql](https://github.com/SP-Invest-Pvt/triagetrust/actions/workflows/codeql.yml/badge.svg)](../../actions/workflows/codeql.yml)

## The problem

Every AppSec vendor now ships AI triage. Checkmarx announced Triage Assist in 2026, Datadog classifies SAST findings as likely true or false positives, and DefectDojo's Pro tier has AI triage. Teams want it because triage consumes a large share of AppSec time, and AI-assisted coding keeps increasing the volume of findings.

Nobody ships the control that decides whether that AI can be trusted. Contrast Labs' AppSec Overflow 2026 research found that three AI scanners analysing the same codebase agreed on only 5% of findings, and one scanner run three times reproduced only 17% of its own results. An AI that wrongly marks a real vulnerability as a false positive silently ships it to production, and "the vendor said it's accurate" is not audit evidence.

## What TriageTrust does

1. **Measures** any triager (an LLM, a vendor feature via its exported verdicts, or rules) against findings with ground truth, several times, and reports:
   * **False-dismissal rate** with a 95% Wilson upper bound: real vulnerabilities it would have closed.
   * **Noise removed**: share of scanner false positives it correctly dismissed, converted into analyst hours.
   * **Abstention rate**: how often it says "uncertain" instead of guessing.
   * **Consistency**: share of findings with the same verdict on every run.
2. **Certifies** a policy per vulnerability category: `auto_dismiss`, `assist` (analyst decides), or `blocked`. The policy is pinned to the exact triager and model, and it expires.
3. **Gates** live triage: auto-closes only what the policy allows, routes everything else to a person, refuses to run on an expired policy or a different model, and writes a hash-chained audit log.

```
scanner results ──> ingest ──> findings (+ ground truth)
 (FindSecBugs XML,              │
  Checkmarx One JSON, SARIF)    ▼
                     evaluate: triager × N runs ──> metrics per category
                                                    │
                                   certify ◄────────┘  thresholds: FDR bound, samples, consistency
                                      │
                                   policy.json (pinned model, expiry)
                                      │
 new AI verdicts ──────────────────> gate ──> auto_dismiss │ fix_queue │ human_review ──> audit log
```

## Evidence

The evaluation dataset is **real scanner output with ground truth for every finding**: FindSecBugs 1.4.6 results shipped with the [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava), joined to the Benchmark's labelled test cases. That produces 2,112 findings, of which 742 (35%) are false positives. A third of an analyst's day on this backlog is wasted.

Results (the baselines reproduce with `./scripts/run_all.sh` and need no API key):

| Triager | False dismissals (95% upper) | Noise removed | Abstained | Accuracy when decided |
|---|---:|---:|---:|---:|
| scanner-as-is | 0.0% (0.3%) | 0.0% | 0.0% | 64.9% |
| rules | 0.0% (0.3%) | 12.5% | 73.2% | 100.0% |
| LLM: Gemini `gemini-3.5-flash-lite` ([run](https://github.com/SP-Invest-Pvt/triagetrust/actions/runs/36081872467)) | 7.0% (12.7%) | 52.1% | 1.0% | 78.8% |

The rule-based triager is certified for auto-dismiss in exactly one category, weak cryptography: 93 false positives are closed automatically, saving 15.5 analyst hours, with zero real vulnerabilities dismissed. It abstains on every injection category because it cannot follow data flow, and the policy correctly keeps those with analysts.

Add an LLM and the scorecard answers the real question: which categories can it take over?

**A real LLM run** (Gemini `gemini-3.5-flash-lite`, 200 stratified findings × 3 runs = 600 verdicts, [workflow run](https://github.com/SP-Invest-Pvt/triagetrust/actions/runs/36081872467)): the model removed **52.1%** of the noise, but it also dismissed **9 of 129 real vulnerabilities** (7.0%, 95% upper bound 12.7%). Its answer was the same on all three runs for 91% of findings. **No category is certified for auto-dismiss.** Eight stay with analysts and three are blocked (LDAP injection, path traversal and XPath injection, where accuracy on decided findings was below 60%). The dismissed real vulnerabilities were path traversal (3), LDAP injection (2), XSS (2), OS command injection (1) and trust boundary (1). Put simply, the model looks productive, and the governance layer is what stops those from being closed silently. 9 of the 600 outputs were malformed and were scored as uncertain.

```bash
export GEMINI_API_KEY=...            # or ANTHROPIC_API_KEY / OPENAI_API_KEY
PROVIDER=gemini ./scripts/run_all.sh # 200 stratified findings × 3 runs
# free and local instead:  ./scripts/setup_ollama.sh && PROVIDER=ollama ./scripts/run_all.sh
```

Outputs land in `results/`: `scorecard.html`, `scorecard.md`, `policy.json`, `gate-audit.jsonl`, and every raw verdict in `results/*/verdicts.jsonl`.

## Quick start

Python 3.10+, no third-party dependencies.

```bash
git clone https://github.com/SP-Invest-Pvt/triagetrust && cd triagetrust
./scripts/run_all.sh                 # Windows: .\scripts\run_all.ps1
python -m unittest discover -s tests -t .
```

Use your own scan (only code you may process outside your organisation):

```bash
cx results show --scan-id <id> --report-format json --output-name cx   # Checkmarx One CLI
python -m triagetrust ingest --checkmarx cx.json --source-root ./repo -o work/mine.jsonl
python -m triagetrust evaluate --findings work/mine.jsonl --triager llm --provider gemini --runs 3 -o results/mine
```

Checkmarx states become ground truth: `NOT_EXPLOITABLE` is a false positive, `CONFIRMED` or `URGENT` is real. SARIF from Semgrep, CodeQL or any other tool works the same way with `--sarif`.

## Commands

| Command | Purpose |
|---|---|
| `dataset` | Build labelled findings from the OWASP Benchmark, optionally from a real scanner's XML |
| `ingest` | Checkmarx One JSON or SARIF into findings, with source-to-sink code context |
| `evaluate` | Run `scanner`, `rules` or `llm` (gemini, anthropic, openai, ollama) with repeated runs and stratified sampling |
| `certify` | Turn an evaluation into `policy.json` (thresholds are flags) |
| `report` | HTML and Markdown scorecard comparing triagers |
| `gate` | Apply the policy to verdicts, emit a hash-chained audit log, exit 2 on expired or mismatched policy |

## Design decisions

* **The upper bound decides, not the point estimate.** Zero mistakes on 20 samples is not proof. Certification uses the 95% Wilson upper bound on false dismissals and a minimum number of real vulnerabilities in the evidence.
* **"Uncertain" is a first-class answer.** The LLM prompt offers it explicitly, and malformed output is scored as uncertain rather than dropped.
* **No benchmark-specific hints, and no leaked answers.** The prompt defines categories in CWE terms only, and source comments are stripped before the model sees the code. OWASP Benchmark comments say things like "get safe value back out"; a model that reads them is grading the comment, not the code.
* **Trust expires and is pinned.** A model upgrade silently changes behaviour; the gate refuses verdicts from a model it did not certify.
* **Everything is reproducible.** LLM responses are cached per prompt and run, so re-scoring costs nothing and interrupted runs resume.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Known limits in [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Talking points in [docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md).

## Licence

MIT. The OWASP Benchmark is downloaded at run time and is not redistributed here.
