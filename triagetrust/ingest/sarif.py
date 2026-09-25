"""SARIF 2.1.0 ingestion (Semgrep, CodeQL, Checkmarx SARIF export, SpotBugs, and most modern SAST)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..context import read_source, window
from ..models import Finding
from ..taxonomy import category_for


def _cwe(tags: list[str]) -> Optional[int]:
    for t in tags or []:
        m = re.search(r"cwe[-_/ ]?(\d+)", str(t), re.I)
        if m:
            return int(m.group(1))
    return None


def load(path: str | Path, source_root: str | Path = ".", radius: int = 25) -> list[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "sarif")
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for i, res in enumerate(run.get("results", [])):
            rule_id = res.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            tags = (rule.get("properties", {}) or {}).get("tags", []) + (res.get("properties", {}) or {}).get("tags", [])
            cwe = _cwe(tags)
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = int(phys.get("region", {}).get("startLine", 1))
            flow_lines = []
            for flow in res.get("codeFlows", []) or []:
                for tf in flow.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        pl = loc.get("location", {}).get("physicalLocation", {})
                        if pl.get("artifactLocation", {}).get("uri", uri) == uri:
                            flow_lines.append(int(pl.get("region", {}).get("startLine", line)))
            src = read_source(source_root, uri)
            label = None
            sup = res.get("suppressions") or []
            if sup:
                label = not any(s.get("status", "accepted") == "accepted" for s in sup)
            findings.append(Finding(
                id=res.get("fingerprints", {}).get("primaryLocationLineHash") or f"{tool}:{rule_id}:{uri}:{line}:{i}",
                rule=rule_id, category=category_for(cwe, rule_id), cwe=cwe, file=uri, line=line,
                code=window(src, [line] + flow_lines, radius), label=label, source=tool,
                extra={"message": (res.get("message") or {}).get("text", "")}))
    return findings
