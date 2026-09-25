#!/usr/bin/env bash
# End-to-end run: dataset -> baselines -> LLM triager -> certify -> scorecard -> gate.
#   PROVIDER=gemini GEMINI_API_KEY=... ./scripts/run_all.sh
#   PROVIDER=ollama ./scripts/run_all.sh            (after scripts/setup_ollama.sh)
# Tunables: SAMPLE (default 200 findings), RUNS (default 3), MODEL, WORKERS (default 4)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
PROVIDER=${PROVIDER:-gemini}
SAMPLE=${SAMPLE:-200}
RUNS=${RUNS:-3}
WORKERS=${WORKERS:-4}
B=data/BenchmarkJava-master
SCAN=$B/results/Benchmark_1.2-findsecbugs-v1.4.6-122.xml

./scripts/fetch_benchmark.sh
mkdir -p results work
$PY -m triagetrust dataset --benchmark $B --scanner $SCAN -o work/findsecbugs.jsonl
$PY -m triagetrust evaluate --findings work/findsecbugs.jsonl --triager scanner -o results/scanner
$PY -m triagetrust evaluate --findings work/findsecbugs.jsonl --triager rules   -o results/rules

EVALS="--eval results/scanner --eval results/rules"
CERT=results/rules
if [ "$PROVIDER" = "gemini" ] && [ -z "${GEMINI_API_KEY:-${GOOGLE_API_KEY:-}}" ]; then
  echo "No GEMINI_API_KEY set: skipping the LLM run (baselines only)."
elif [ "$PROVIDER" = "anthropic" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "No ANTHROPIC_API_KEY set: skipping the LLM run (baselines only)."
else
  MODEL_ARG=${MODEL:+--model $MODEL}
  $PY -m triagetrust evaluate --findings work/findsecbugs.jsonl --triager llm --provider "$PROVIDER" $MODEL_ARG \
      --sample "$SAMPLE" --runs "$RUNS" --workers "$WORKERS" -o "results/llm-$PROVIDER"
  EVALS="$EVALS --eval results/llm-$PROVIDER"
  CERT=results/llm-$PROVIDER
fi

$PY -m triagetrust certify --eval "$CERT" -o results/policy.json
$PY -m triagetrust report $EVALS --policy results/policy.json --title "AI triage scorecard: OWASP Benchmark, FindSecBugs findings" -o results/scorecard.html
$PY -m triagetrust gate --policy results/policy.json --findings work/findsecbugs.jsonl --verdicts "$CERT/verdicts.jsonl" -o results/gate-audit.jsonl
echo "Done. Open results/scorecard.html"
