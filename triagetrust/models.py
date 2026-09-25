"""Core records: a scanner finding (with optional ground truth) and a triage verdict."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Iterable, Optional

TP = "true_positive"    # real issue: keep open
FP = "false_positive"   # not exploitable: candidate to dismiss
UNSURE = "uncertain"    # abstain: a person decides
VERDICTS = (TP, FP, UNSURE)


@dataclass
class Finding:
    id: str
    rule: str
    category: str
    cwe: Optional[int]
    file: str
    line: int = 1
    code: str = ""                  # source context shown to the triager
    label: Optional[bool] = None    # ground truth: True real, False false positive, None unknown
    source: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class Verdict:
    finding_id: str
    verdict: str
    confidence: float = 0.0
    reasoning: str = ""
    run: int = 0
    triager: str = ""
    model: str = ""
    latency_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Verdict":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


def write_jsonl(path, records: Iterable[dict]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_findings(path) -> list[Finding]:
    return [Finding.from_dict(d) for d in read_jsonl(path)]
