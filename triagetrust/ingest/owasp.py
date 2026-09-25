"""OWASP Benchmark ingestion.

The OWASP Benchmark (https://github.com/OWASP-Benchmark/BenchmarkJava) ships 2,740 Java test
cases, each labelled as a real vulnerability or not, plus historical output from real scanners.
That gives us what most triage pilots lack: findings produced by an actual SAST tool, with
ground truth for every one of them.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..context import strip_header
from ..models import Finding
from ..taxonomy import cwe_for

TESTCODE = "src/main/java/org/owasp/benchmark/testcode"

# SpotBugs / FindSecBugs bug types that correspond to Benchmark categories.
SPOTBUGS_TYPES = {
    "sqli": ["SQL_INJECTION", "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE",
             "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING"],
    "xss": ["XSS_SERVLET", "XSS_REQUEST_WRAPPER", "XSS_JSP_PRINT"],
    "cmdi": ["COMMAND_INJECTION"],
    "pathtraver": ["PATH_TRAVERSAL_IN", "PATH_TRAVERSAL_OUT"],
    "ldapi": ["LDAP_INJECTION"],
    "xpathi": ["XPATH_INJECTION"],
    "weakrand": ["PREDICTABLE_RANDOM"],
    "hash": ["WEAK_MESSAGE_DIGEST"],
    "crypto": ["DES_USAGE", "TDES_USAGE", "CIPHER_INTEGRITY", "ECB_MODE", "STATIC_IV",
               "PADDING_ORACLE", "NULL_CIPHER", "UNENCRYPTED_SOCKET"],
    "securecookie": ["INSECURE_COOKIE"],
    "trustbound": ["TRUST_BOUNDARY_VIOLATION"],
}


def _spotbugs_category(bug_type: str) -> Optional[str]:
    for cat, prefixes in SPOTBUGS_TYPES.items():
        if any(bug_type.startswith(p) for p in prefixes):
            return cat
    return None


def load_expected(bench_dir: str | Path) -> dict[str, tuple[str, bool, int]]:
    path = Path(bench_dir) / "expectedresults-1.2.csv"
    out = {}
    for row in path.read_text().splitlines():
        if not row or row.startswith("#"):
            continue
        name, cat, real, cwe = row.split(",")[:4]
        out[name] = (cat, real.strip() == "true", int(cwe))
    return out


def _code_for(bench_dir: Path, test: str) -> str:
    f = bench_dir / TESTCODE / f"{test}.java"
    return strip_header(f.read_text(encoding="utf-8")) if f.exists() else ""


def _props(bench_dir: Path) -> dict:
    p = bench_dir / "src/main/resources/benchmark.properties"
    props = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def build_all(bench_dir: str | Path) -> list[Finding]:
    """One finding per test case: an idealised scanner that flags every case in its category."""
    bench = Path(bench_dir)
    props = _props(bench)
    findings = []
    for test, (cat, real, cwe) in sorted(load_expected(bench).items()):
        findings.append(Finding(
            id=f"{test}:{cat}", rule=f"benchmark-{cat}", category=cat, cwe=cwe,
            file=f"{TESTCODE}/{test}.java", line=1, code=_code_for(bench, test), label=real,
            source="owasp-benchmark-1.2", extra={"test": test, "config": props}))
    return findings


def build_from_spotbugs(bench_dir: str | Path, xml_path: str | Path) -> list[Finding]:
    """Findings exactly as a real FindSecBugs run reported them, joined to ground truth.

    Several bug instances in the same test case and category collapse into one finding,
    which is how an analyst would triage them.
    """
    bench = Path(bench_dir)
    expected = load_expected(bench)
    props = _props(bench)
    text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
    seen: dict[str, Finding] = {}
    for m in re.finditer(r"<BugInstance\b[^>]*\btype='([^']+)'[^>]*>(.*?)</BugInstance>", text, re.S):
        bug_type, body = m.group(1), m.group(2)
        cat = _spotbugs_category(bug_type)
        if not cat:
            continue
        cls = re.search(r"classname='org\.owasp\.benchmark\.testcode\.(BenchmarkTest\d+)", body)
        if not cls:
            continue
        test = cls.group(1)
        truth = expected.get(test)
        if not truth or truth[0] != cat:
            continue  # flagged outside the case's intended category: not scorable
        line_m = re.search(r"<SourceLine[^>]*primary='true'[^>]*start='(\d+)'", body) or \
            re.search(r"<SourceLine[^>]*start='(\d+)'", body)
        fid = f"{test}:{cat}"
        if fid in seen:
            seen[fid].extra["rules"].append(bug_type)
            continue
        seen[fid] = Finding(
            id=fid, rule=bug_type, category=cat, cwe=cwe_for(cat) or truth[2],
            file=f"{TESTCODE}/{test}.java", line=int(line_m.group(1)) if line_m else 1,
            code=_code_for(bench, test), label=truth[1], source=f"findsecbugs:{Path(xml_path).name}",
            extra={"test": test, "rules": [bug_type], "config": props})
    return sorted(seen.values(), key=lambda f: f.id)
