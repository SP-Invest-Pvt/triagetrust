"""Run a triager over labelled findings (optionally several times) and score it.

Headline metrics, computed overall and per category:
  false_dismissal_rate  real vulnerabilities the triager would have closed. The number that
                        decides whether automation is safe. Reported with a 95% Wilson upper bound.
  noise_reduction       share of scanner false positives correctly dismissed. The business value.
  abstention_rate       findings the triager declined to decide. Honest, but still costs analyst time.
  consistency           share of findings with the same verdict on every repeated run.
  decided_accuracy      accuracy on the findings it did decide.
"""
from __future__ import annotations

import json
import random
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from .models import FP, TP, UNSURE, Finding, Verdict, read_jsonl, write_jsonl
from .providers import ProviderError
from .stats import ratio, wilson
from .triagers.base import Triager


def stratified_sample(findings: list[Finding], n: int | None, seed: int = 7) -> list[Finding]:
    if not n or n >= len(findings):
        return list(findings)
    rng = random.Random(seed)
    groups = defaultdict(list)
    for f in findings:
        groups[(f.category, f.label)].append(f)
    total = len(findings)
    picked = []
    for key in sorted(groups, key=str):
        g = groups[key]
        rng.shuffle(g)
        take = max(1, round(n * len(g) / total))
        picked.extend(g[:take])
    rng.shuffle(picked)
    return sorted(picked[:n], key=lambda f: f.id)


def majority(verdicts: list[str]) -> str:
    c = Counter(verdicts).most_common()
    if len(c) > 1 and c[0][1] == c[1][1]:
        return UNSURE
    return c[0][0]


def score(findings: list[Finding], by_id: dict[str, list[Verdict]], minutes_per_finding: float = 10.0) -> dict:
    def block(items: list[Finding]) -> dict:
        m = Counter()
        consistent = 0
        for f in items:
            vs = by_id.get(f.id, [])
            if not vs:
                continue
            labels = [v.verdict for v in vs]
            consistent += len(set(labels)) == 1
            final = majority(labels)
            m["n"] += 1
            kind = "real" if f.label else "fp"
            m[f"n_{kind}"] += 1
            m[f"{kind}_{final}"] += 1
        n, n_real, n_fp = m["n"], m["n_real"], m["n_fp"]
        fd = m[f"real_{FP}"]
        decided = n - m[f"real_{UNSURE}"] - m[f"fp_{UNSURE}"]
        correct = m[f"real_{TP}"] + m[f"fp_{FP}"]
        remaining = n - m[f"fp_{FP}"] - fd
        remaining_real = n_real - fd
        return {
            "n": n, "n_real": n_real, "n_false_positive": n_fp,
            "kept_real": m[f"real_{TP}"], "dismissed_real": fd, "uncertain_real": m[f"real_{UNSURE}"],
            "dismissed_fp": m[f"fp_{FP}"], "kept_fp": m[f"fp_{TP}"], "uncertain_fp": m[f"fp_{UNSURE}"],
            "false_dismissal_rate": ratio(fd, n_real),
            "false_dismissal_upper95": wilson(fd, n_real)[1] if n_real else 1.0,
            "noise_reduction": ratio(m[f"fp_{FP}"], n_fp),
            "abstention_rate": ratio(m[f"real_{UNSURE}"] + m[f"fp_{UNSURE}"], n),
            "decided_accuracy": ratio(correct, decided),
            "consistency": ratio(consistent, n),
            "queue_precision_before": ratio(n_real, n),
            "queue_precision_after": ratio(remaining_real, remaining),
            "analyst_hours_saved": round(m[f"fp_{FP}"] * minutes_per_finding / 60, 1),
        }

    labelled = [f for f in findings if f.label is not None]
    cats = sorted({f.category for f in labelled})
    return {"overall": block(labelled), "by_category": {c: block([f for f in labelled if f.category == c]) for c in cats}}


def run_eval(findings: list[Finding], triager: Triager, out_dir: str | Path, runs: int = 3,
             workers: int = 4, minutes_per_finding: float = 10.0, progress: bool = True,
             dataset: str = "") -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    runs = 1 if triager.deterministic else max(1, runs)
    jobs = [(f, r) for r in range(runs) for f in findings]
    verdicts: list[Verdict] = []
    errors = 0
    t0 = time.time()

    def work(job):
        f, r = job
        return triager.triage(f, run=r)

    with ThreadPoolExecutor(max_workers=max(1, workers if not triager.deterministic else 1)) as pool:
        futures = [pool.submit(work, j) for j in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                v = fut.result()
            except ProviderError as e:
                for other in futures:
                    other.cancel()
                raise SystemExit(f"Provider failed: {e}")
            errors += bool(v.error)
            verdicts.append(v)
            if progress and (i % 25 == 0 or i == len(jobs)):
                print(f"  {triager.name}: {i}/{len(jobs)} verdicts", flush=True)

    by_id: dict[str, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        by_id[v.finding_id].append(v)
    metrics = score(findings, by_id, minutes_per_finding)
    meta = {
        "triager": triager.name, "model": getattr(triager, "model", ""), "runs": runs,
        "findings": len(findings), "verdicts": len(verdicts), "malformed_outputs": errors,
        "dataset": dataset, "minutes_per_finding": minutes_per_finding,
        "elapsed_s": round(time.time() - t0, 1),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    write_jsonl(out / "verdicts.jsonl", (v.to_dict() for v in sorted(verdicts, key=lambda v: (v.finding_id, v.run))))
    (out / "metrics.json").write_text(json.dumps({"meta": meta, **metrics}, indent=2))
    return {"meta": meta, **metrics}


def load_eval(path: str | Path) -> dict:
    return json.loads((Path(path) / "metrics.json").read_text())


def rescore(findings: list[Finding], verdicts_path: str | Path, minutes: float = 10.0) -> dict:
    by_id: dict[str, list[Verdict]] = defaultdict(list)
    for d in read_jsonl(verdicts_path):
        v = Verdict.from_dict(d)
        by_id[v.finding_id].append(v)
    return score(findings, by_id, minutes)
