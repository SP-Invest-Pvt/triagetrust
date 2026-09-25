"""Command-line interface.

  triagetrust dataset   --benchmark DIR [--scanner FINDSECBUGS.xml] -o findings.jsonl
  triagetrust ingest    --checkmarx results.json | --sarif results.sarif  --source-root DIR -o findings.jsonl
  triagetrust evaluate  --findings F --triager rules|scanner|llm [--provider gemini --model M --runs 3 --sample 200] -o runs/NAME
  triagetrust certify   --eval runs/NAME -o policy.json
  triagetrust report    --eval runs/A --eval runs/B [--policy policy.json] -o scorecard.html
  triagetrust gate      --policy policy.json --findings F --verdicts runs/NAME/verdicts.jsonl -o audit.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from . import gate as gate_mod
from . import policy as policy_mod
from . import report as report_mod
from .evaluate import load_eval, run_eval, stratified_sample
from .ingest import checkmarx, owasp, sarif
from .models import Verdict, load_findings, read_jsonl, write_jsonl
from .providers import get_provider
from .triagers.llm import LLMTriager
from .triagers.rules import RuleTriager
from .triagers.scanner import ScannerAsIs


def _summary(findings) -> str:
    c = Counter((f.label is True, f.label is False) for f in findings)
    return f"{len(findings)} findings ({c[(True, False)]} real, {c[(False, True)]} false positive, {c[(False, False)]} unlabelled)"


def cmd_dataset(a):
    findings = owasp.build_from_spotbugs(a.benchmark, a.scanner) if a.scanner else owasp.build_all(a.benchmark)
    write_jsonl(a.output, (f.to_dict() for f in findings))
    print(f"Wrote {_summary(findings)} -> {a.output}")


def cmd_ingest(a):
    if a.checkmarx:
        findings = checkmarx.load(a.checkmarx, a.source_root)
    elif a.sarif:
        findings = sarif.load(a.sarif, a.source_root)
    else:
        sys.exit("Give --checkmarx or --sarif")
    write_jsonl(a.output, (f.to_dict() for f in findings))
    print(f"Wrote {_summary(findings)} -> {a.output}")


def _triager(a):
    if a.triager == "scanner":
        return ScannerAsIs()
    if a.triager == "rules":
        return RuleTriager()
    provider = get_provider(a.provider, model=a.model, temperature=a.temperature, cache_dir=a.cache_dir)
    return LLMTriager(provider)


def cmd_evaluate(a):
    findings = [f for f in load_findings(a.findings) if f.label is not None]
    if a.category:
        findings = [f for f in findings if f.category in a.category]
    findings = stratified_sample(findings, a.sample, a.seed)
    tri = _triager(a)
    runs = 1 if tri.deterministic else a.runs
    print(f"Evaluating {tri.name} {getattr(tri, 'model', '')} on {_summary(findings)}, runs={runs}")
    res = run_eval(findings, tri, a.output, runs=a.runs, workers=a.workers,
                   minutes_per_finding=a.minutes, dataset=Path(a.findings).name)
    m = res["overall"]
    print(f"false dismissals {m['dismissed_real']}/{m['n_real']} (upper95 {m['false_dismissal_upper95']:.1%}) | "
          f"noise removed {m['noise_reduction']:.1%} | abstained {m['abstention_rate']:.1%} | "
          f"accuracy when decided {m['decided_accuracy']:.1%} | consistency {m['consistency']:.1%}")
    print(f"-> {a.output}")


def cmd_certify(a):
    t = policy_mod.Thresholds(max_false_dismissal_upper95=a.max_fdr, min_real_samples=a.min_real,
                              min_consistency=a.min_consistency, valid_days=a.valid_days)
    pol = policy_mod.certify(load_eval(a.eval), t)
    policy_mod.save(pol, a.output)
    modes = Counter(v["mode"] for v in pol["categories"].values())
    print(f"Policy for {pol['triager']} {pol['model']}: {dict(modes)} -> {a.output}")


def cmd_report(a):
    evals = [load_eval(p) for p in a.eval]
    pol = policy_mod.load(a.policy) if a.policy else None
    report_mod.write(a.output, evals, pol, a.title)
    md = Path(a.output).with_suffix(".md")
    md.write_text(report_mod.markdown(evals, pol) + "\n")
    print(f"-> {a.output} and {md}")


def cmd_gate(a):
    pol = policy_mod.load(a.policy)
    findings = {f.id: f for f in load_findings(a.findings)}
    verdicts = [Verdict.from_dict(d) for d in read_jsonl(a.verdicts)]
    if a.run is not None:
        verdicts = [v for v in verdicts if v.run == a.run]
    if not verdicts:
        sys.exit("No verdicts to gate")
    try:
        gate_mod.check_policy(pol, verdicts[0].triager, verdicts[0].model)
    except gate_mod.GateError as e:
        print(f"GATE REFUSED: {e}", file=sys.stderr)
        return 2
    records, counts = gate_mod.apply(pol, findings, verdicts)
    write_jsonl(a.output, records)
    print(f"{dict(counts)} -> {a.output} (hash-chained audit log)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triagetrust", description="Evaluate and govern AI triage of security findings.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("dataset", help="build a labelled dataset from the OWASP Benchmark")
    s.add_argument("--benchmark", required=True)
    s.add_argument("--scanner", help="FindSecBugs/SpotBugs XML from the Benchmark results folder")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_dataset)

    s = sub.add_parser("ingest", help="ingest Checkmarx One JSON or SARIF")
    s.add_argument("--checkmarx")
    s.add_argument("--sarif")
    s.add_argument("--source-root", default=".")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("evaluate", help="run a triager against labelled findings")
    s.add_argument("--findings", required=True)
    s.add_argument("--triager", choices=["scanner", "rules", "llm"], required=True)
    s.add_argument("--provider", default="gemini", choices=["gemini", "anthropic", "openai", "ollama"])
    s.add_argument("--model")
    s.add_argument("--temperature", type=float, default=0.2)
    s.add_argument("--runs", type=int, default=3)
    s.add_argument("--sample", type=int, help="stratified sample size")
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--category", action="append")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--minutes", type=float, default=10.0, help="analyst minutes per finding")
    s.add_argument("--cache-dir", default=".cache/llm")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("certify", help="derive an automation policy from an evaluation")
    s.add_argument("--eval", required=True)
    s.add_argument("--max-fdr", type=float, default=0.05)
    s.add_argument("--min-real", type=int, default=30)
    s.add_argument("--min-consistency", type=float, default=0.95)
    s.add_argument("--valid-days", type=int, default=90)
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_certify)

    s = sub.add_parser("report", help="HTML + Markdown scorecard")
    s.add_argument("--eval", action="append", required=True)
    s.add_argument("--policy")
    s.add_argument("--title", default="AI triage scorecard")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("gate", help="apply a policy to live verdicts")
    s.add_argument("--policy", required=True)
    s.add_argument("--findings", required=True)
    s.add_argument("--verdicts", required=True)
    s.add_argument("--run", type=int, default=0)
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(fn=cmd_gate)

    a = p.parse_args(argv)
    return a.fn(a) or 0
