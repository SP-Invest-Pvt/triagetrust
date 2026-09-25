"""Turn evaluation evidence into an explicit automation policy.

Each category gets one of three modes:
  auto_dismiss  the triager may close false positives on its own. Requires enough real
                vulnerabilities in the evidence, a 95% upper bound on false dismissals below the
                threshold, and stable verdicts across runs.
  assist        the triager's verdict is shown to an analyst, who decides.
  blocked       the triager is too wrong or too unstable to show at all.

The policy is pinned to the triager and model it certified, and expires, so a silent model
upgrade or drift forces re-certification instead of inheriting trust.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class Thresholds:
    max_false_dismissal_upper95: float = 0.05
    min_real_samples: int = 30
    min_consistency: float = 0.95
    min_noise_reduction: float = 0.25
    block_below_accuracy: float = 0.60
    block_below_consistency: float = 0.80
    min_confidence: float = 0.80
    valid_days: int = 90


def decide(m: dict, t: Thresholds) -> tuple[str, str]:
    if m["n"] == 0:
        return "assist", "no evidence"
    if m["n_false_positive"] == 0:
        return "assist", "scanner produced no false positives here: nothing for AI to remove"
    decided = m["n"] * (1 - m["abstention_rate"])
    if decided and m["decided_accuracy"] < t.block_below_accuracy:
        return "blocked", f"decided accuracy {m['decided_accuracy']:.0%} < {t.block_below_accuracy:.0%}"
    if m["consistency"] < t.block_below_consistency:
        return "blocked", f"consistency {m['consistency']:.0%} < {t.block_below_consistency:.0%}"
    reasons = []
    if m["abstention_rate"] >= 0.9:
        return "assist", f"triager abstained on {m['abstention_rate']:.0%}: it cannot decide this category"
    if m["n_real"] < t.min_real_samples:
        reasons.append(f"only {m['n_real']} real vulnerabilities in evidence (need {t.min_real_samples})")
    if m["false_dismissal_upper95"] > t.max_false_dismissal_upper95:
        reasons.append(f"false-dismissal upper bound {m['false_dismissal_upper95']:.1%} > {t.max_false_dismissal_upper95:.0%}")
    if m["consistency"] < t.min_consistency:
        reasons.append(f"consistency {m['consistency']:.0%} < {t.min_consistency:.0%}")
    if m["noise_reduction"] < t.min_noise_reduction:
        reasons.append(f"removes only {m['noise_reduction']:.0%} of false positives")
    if reasons:
        return "assist", "; ".join(reasons)
    return "auto_dismiss", (f"false-dismissal upper bound {m['false_dismissal_upper95']:.1%}, "
                            f"removes {m['noise_reduction']:.0%} of noise, consistency {m['consistency']:.0%}")


def certify(eval_result: dict, t: Thresholds | None = None) -> dict:
    t = t or Thresholds()
    now = datetime.now(timezone.utc)
    cats = {}
    for cat, m in eval_result["by_category"].items():
        mode, why = decide(m, t)
        cats[cat] = {"mode": mode, "reason": why,
                     "evidence": {k: m[k] for k in ("n", "n_real", "false_dismissal_rate", "false_dismissal_upper95",
                                                   "noise_reduction", "consistency", "abstention_rate")}}
    meta = eval_result["meta"]
    return {
        "policy_version": 1,
        "triager": meta["triager"], "model": meta.get("model", ""),
        "dataset": meta.get("dataset", ""),
        "certified_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(days=t.valid_days)).isoformat(timespec="seconds"),
        "thresholds": asdict(t),
        "categories": cats,
        "default_mode": "assist",
    }


def save(policy: dict, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(policy, indent=2))


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())
