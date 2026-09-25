"""Apply a certified policy to live AI triage verdicts (e.g. in CI or a nightly triage job).

For every verdict the gate decides one action and writes an audit record:
  auto_dismiss   policy allows it, verdict is false_positive, confidence >= threshold
  fix_queue      verdict is true_positive: route to remediation
  human_review   everything else, with the reason
The gate refuses to run (exit 2) if the policy expired or the verdicts came from a different
triager/model than the one certified.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone

from .models import FP, TP, Finding, Verdict


class GateError(RuntimeError):
    pass


def check_policy(policy: dict, triager: str, model: str, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    if datetime.fromisoformat(policy["expires_at"]) < now:
        raise GateError(f"policy expired at {policy['expires_at']}: re-certify before automating")
    if policy["triager"] != triager or (policy.get("model") or "") != (model or ""):
        raise GateError(f"verdicts from {triager}/{model or '-'} but policy certifies "
                        f"{policy['triager']}/{policy.get('model') or '-'}")


def apply(policy: dict, findings: dict[str, Finding], verdicts: list[Verdict]) -> tuple[list[dict], Counter]:
    min_conf = policy["thresholds"]["min_confidence"]
    records, counts = [], Counter()
    prev = "0" * 64
    for v in verdicts:
        f = findings.get(v.finding_id)
        cat = f.category if f else "other"
        mode = policy["categories"].get(cat, {}).get("mode", policy.get("default_mode", "assist"))
        if v.verdict == TP:
            action, why = "fix_queue", "AI confirms the finding"
        elif v.verdict == FP and mode == "auto_dismiss" and v.confidence >= min_conf:
            action, why = "auto_dismiss", f"certified for {cat}; confidence {v.confidence:.2f}"
        elif mode == "blocked":
            action, why = "human_review", f"AI verdict hidden: triager blocked for {cat}"
        elif v.verdict == FP and mode == "auto_dismiss":
            action, why = "human_review", f"confidence {v.confidence:.2f} below {min_conf}"
        else:
            action, why = "human_review", f"{cat} is '{mode}': AI suggests {v.verdict}"
        rec = {"finding_id": v.finding_id, "category": cat, "ai_verdict": v.verdict,
               "confidence": v.confidence, "action": action, "reason": why,
               "ai_reasoning": v.reasoning, "triager": v.triager, "model": v.model,
               "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "prev": prev}
        prev = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        rec["hash"] = prev
        records.append(rec)
        counts[action] += 1
    return records, counts
