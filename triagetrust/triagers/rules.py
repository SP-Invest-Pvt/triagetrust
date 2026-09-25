"""Deterministic rule-based triager.

It only decides where a finding's truth is visible in configuration-level facts (algorithm names,
RNG class, cookie flags) and abstains on data-flow questions it cannot answer. Abstaining is a
feature: it is how a triager should behave when it lacks evidence, and TriageTrust measures it.
"""
from __future__ import annotations

import re

from ..models import FP, TP, UNSURE, Finding, Verdict
from .base import Triager

WEAK_HASH = {"MD2", "MD4", "MD5", "SHA1", "SHA-1", "SHA"}
STRONG_HASH = {"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "SHA-512/256"}


def _resolve(expr: str, code: str, config: dict) -> str | None:
    expr = expr.strip()
    if expr.startswith('"'):
        return expr.strip('"')
    # variable assigned from a properties lookup: benchmarkprops.getProperty("hashAlg1", "SHA512")
    m = re.search(rf"\b{re.escape(expr)}\s*=\s*[\w.]*getProperty\(\s*\"([^\"]+)\"(?:\s*,\s*\"([^\"]*)\")?", code)
    if m:
        return config.get(m.group(1), m.group(2))
    m = re.search(rf"\b{re.escape(expr)}\s*=\s*\"([^\"]+)\"", code)
    return m.group(1) if m else None


def _norm_hash(a: str) -> str:
    a = a.upper()
    return {"SHA512": "SHA-512", "SHA256": "SHA-256", "SHA384": "SHA-384"}.get(a, a)


class RuleTriager(Triager):
    name = "rules"

    def triage(self, f: Finding, run: int = 0) -> Verdict:
        code, cfg = f.code, (f.extra or {}).get("config", {})
        fn = getattr(self, f"_{f.category}", None)
        verdict, conf, why = fn(code, cfg) if fn else (UNSURE, 0.0, "No deterministic rule for this category; data-flow judgement required.")
        return Verdict(f.id, verdict, conf, why, run, self.name)

    def _hash(self, code, cfg):
        algs = [_resolve(a, code, cfg) for a in re.findall(r"MessageDigest\.getInstance\(\s*([^,)]+)", code)]
        algs = [_norm_hash(a) for a in algs if a]
        if not algs:
            return UNSURE, 0.0, "Digest algorithm not resolvable statically."
        if any(a in WEAK_HASH for a in algs):
            return TP, 0.95, f"Weak digest in use: {algs}."
        if all(a in STRONG_HASH for a in algs):
            return FP, 0.9, f"Only strong digests in use: {algs}."
        return UNSURE, 0.3, f"Unrecognised digest: {algs}."

    def _crypto(self, code, cfg):
        algs = [_resolve(a, code, cfg) for a in re.findall(r"Cipher\.getInstance\(\s*([^,)]+)", code)]
        algs = [a.upper() for a in algs if a]
        if not algs:
            return UNSURE, 0.0, "Cipher transformation not resolvable statically."
        weak = [a for a in algs if a.startswith(("DES", "DESEDE", "RC2", "RC4", "BLOWFISH")) or "/ECB/" in a or a in {"AES", "DES"}]
        if weak:
            return TP, 0.95, f"Weak cipher or mode: {weak}."
        if all(a.startswith("AES/") and ("/GCM/" in a or "/CCM/" in a or "/CBC/" in a) for a in algs):
            return FP, 0.85, f"Modern AES transformation: {algs}."
        return UNSURE, 0.3, f"Unrecognised transformation: {algs}."

    def _weakrand(self, code, cfg):
        weak = re.search(r"new\s+java\.util\.Random\b|\bnew\s+Random\s*\(|Math\.random\(|ThreadLocalRandom", code)
        strong = re.search(r"SecureRandom", code)
        if weak:
            return TP, 0.9, f"Predictable PRNG used: {weak.group(0)}."
        if strong:
            return FP, 0.9, "Only SecureRandom used."
        return UNSURE, 0.0, "No random source found."

    def _securecookie(self, code, cfg):
        flags = re.findall(r"setSecure\(\s*(true|false)\s*\)", code)
        if "false" in flags:
            return TP, 0.95, "Cookie explicitly set with Secure=false."
        if flags and all(x == "true" for x in flags):
            return FP, 0.9, "Cookie set with Secure=true."
        return UNSURE, 0.2, "Secure flag not set explicitly."
