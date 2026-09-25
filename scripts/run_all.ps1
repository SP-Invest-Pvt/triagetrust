# Windows equivalent of run_all.sh.  $env:GEMINI_API_KEY="..."; .\scripts\run_all.ps1 -Provider gemini
param([string]$Provider = "gemini", [int]$Sample = 200, [int]$Runs = 3, [string]$Model = "", [int]$Workers = 4)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$B = "data/BenchmarkJava-master"
if (-not (Test-Path $B)) {
  New-Item -ItemType Directory -Force data | Out-Null
  Invoke-WebRequest https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/zip/refs/heads/master -OutFile data/bench.zip
  Expand-Archive data/bench.zip -DestinationPath data; Remove-Item data/bench.zip
}
$Scan = "$B/results/Benchmark_1.2-findsecbugs-v1.4.6-122.xml"
python -m triagetrust dataset --benchmark $B --scanner $Scan -o work/findsecbugs.jsonl
python -m triagetrust evaluate --findings work/findsecbugs.jsonl --triager scanner -o results/scanner
python -m triagetrust evaluate --findings work/findsecbugs.jsonl --triager rules -o results/rules
$evals = @("--eval", "results/scanner", "--eval", "results/rules"); $cert = "results/rules"
$haveKey = ($Provider -eq "ollama") -or ($Provider -eq "openai" -and $env:OPENAI_API_KEY) -or `
           ($Provider -eq "gemini" -and ($env:GEMINI_API_KEY -or $env:GOOGLE_API_KEY)) -or ($Provider -eq "anthropic" -and $env:ANTHROPIC_API_KEY)
if ($haveKey) {
  $args2 = @("--findings", "work/findsecbugs.jsonl", "--triager", "llm", "--provider", $Provider, "--sample", $Sample, "--runs", $Runs, "--workers", $Workers, "-o", "results/llm-$Provider")
  if ($Model) { $args2 += @("--model", $Model) }
  python -m triagetrust evaluate @args2
  $evals += @("--eval", "results/llm-$Provider"); $cert = "results/llm-$Provider"
} else { Write-Host "No API key for ${Provider}: baselines only." }
python -m triagetrust certify --eval $cert -o results/policy.json
python -m triagetrust report @evals --policy results/policy.json --title "AI triage scorecard: OWASP Benchmark, FindSecBugs findings" -o results/scorecard.html
python -m triagetrust gate --policy results/policy.json --findings work/findsecbugs.jsonl --verdicts "$cert/verdicts.jsonl" -o results/gate-audit.jsonl
Write-Host "Done. Open results/scorecard.html"
