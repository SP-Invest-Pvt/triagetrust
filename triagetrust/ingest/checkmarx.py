"""Checkmarx One results ingestion.

Accepts the JSON produced by `cx results show --scan-id <id> --report-format json` (or the
equivalent REST payload). Each SAST result carries its full source-to-sink node path, so the
triager sees the data flow, not just the sink line.

Historical triage decisions become ground truth: NOT_EXPLOITABLE -> false positive,
CONFIRMED / URGENT -> true positive, anything else -> unlabelled. Only use scans of code you
are allowed to process outside your organisation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..context import read_source, window
from ..models import Finding
from ..taxonomy import category_for

LABELS = {"NOT_EXPLOITABLE": False, "CONFIRMED": True, "URGENT": True}


def _cwe(res: dict) -> Optional[int]:
    for key in ("cweId", "cwe"):
        v = (res.get("vulnerabilityDetails") or {}).get(key) or (res.get("data") or {}).get(key)
        if v:
            try:
                return int(str(v).lower().replace("cwe-", ""))
            except ValueError:
                pass
    return None


def load(path: str | Path, source_root: str | Path = ".", radius: int = 12) -> list[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    results = doc.get("results", doc if isinstance(doc, list) else [])
    findings = []
    for res in results:
        if str(res.get("type", "sast")).lower() != "sast":
            continue
        data = res.get("data") or {}
        nodes = data.get("nodes") or []
        query = data.get("queryName") or res.get("queryName") or "unknown"
        cwe = _cwe(res)
        files: dict[str, list[int]] = {}
        path_desc = []
        for n in nodes:
            fname = n.get("fileName", "").lstrip("/")
            ln = int(n.get("line", 1) or 1)
            files.setdefault(fname, []).append(ln)
            path_desc.append(f"{fname}:{ln} {n.get('name', '')} ({n.get('method', '')})")
        excerpts = []
        for fname, lines in files.items():
            src = read_source(source_root, fname)
            if src:
                excerpts.append(f"// ===== {fname} =====\n{window(src, lines, radius)}")
        sink = nodes[-1] if nodes else {}
        state = str(res.get("state", "")).upper()
        findings.append(Finding(
            id=str(res.get("similarityId") or res.get("id")), rule=query,
            category=category_for(cwe, query), cwe=cwe,
            file=sink.get("fileName", "").lstrip("/"), line=int(sink.get("line", 1) or 1),
            code="Data flow (source -> sink):\n" + "\n".join(path_desc) + "\n\n" + "\n\n".join(excerpts),
            label=LABELS.get(state), source="checkmarx-one",
            extra={"severity": res.get("severity"), "state": state, "status": res.get("status")}))
    return findings
