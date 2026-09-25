"""LLM triager: the thing TriageTrust exists to measure.

Design choices that matter for governance:
  * The model must return strict JSON with an explicit "uncertain" option, so it can abstain
    instead of guessing.
  * The prompt defines each category in CWE terms only. It contains no benchmark-specific hints,
    so a score on the OWASP Benchmark says something about behaviour on your code.
  * Source comments are stripped before the model sees the code (see context.strip_comments),
    so annotations like "safe value" cannot leak the answer.
  * Malformed output is recorded as "uncertain" with the error, never silently dropped.
"""
from __future__ import annotations

import time

from ..models import FP, TP, UNSURE, VERDICTS, Finding, Verdict
from ..context import strip_comments
from ..providers import Provider, ProviderError, parse_json
from ..taxonomy import display
from .base import Triager

SYSTEM = """You are a senior application security engineer triaging static analysis (SAST) findings.
Decide whether the finding is a REAL, EXPLOITABLE vulnerability in the code shown.

Method:
1. Identify the untrusted source (request parameters, headers, cookies, body, query string) if any.
2. Trace the value to the sink. Evaluate every branch, collection operation, overwrite and
   sanitiser on the path. Values replaced by constants, or branches that can never run, break the flow.
3. For configuration-type findings (crypto, hashing, randomness, cookies) judge the actual
   algorithm, mode, generator or flag used, resolving constants and properties where visible.
4. If the code shown is not enough to decide, answer "uncertain". A wrong "false_positive"
   hides a real vulnerability, so only use it when the evidence is clear.

Respond with JSON only:
{"verdict": "true_positive" | "false_positive" | "uncertain",
 "confidence": <number 0.0-1.0>,
 "reasoning": "<two or three sentences citing line numbers>"}"""

GUIDANCE = {
    "sqli": "Untrusted data concatenated into a SQL statement or query, not bound as a parameter.",
    "xss": "Untrusted data written to an HTML response without context-appropriate encoding.",
    "cmdi": "Untrusted data reaching an OS command or its arguments.",
    "pathtraver": "Untrusted data used to build a filesystem path that is opened, read or written.",
    "ldapi": "Untrusted data inserted into an LDAP filter or DN without escaping.",
    "xpathi": "Untrusted data inserted into an XPath expression without escaping.",
    "weakrand": "A predictable PRNG (e.g. java.util.Random, Math.random) generating a security-relevant value.",
    "hash": "A cryptographically weak hash (e.g. MD5, SHA-1) used where collision resistance matters.",
    "crypto": "A weak algorithm or mode (e.g. DES, 3DES, RC4, ECB) used for encryption.",
    "securecookie": "A cookie that can be sent over plain HTTP because Secure is not set to true.",
    "trustbound": "Untrusted data stored in a trusted context (e.g. the HTTP session) without validation.",
}


def build_prompt(f: Finding, keep_comments: bool = False) -> str:
    code = f.code if keep_comments else strip_comments(f.code)
    guide = GUIDANCE.get(f.category, "Judge whether the reported weakness is real and exploitable.")
    return (f"Finding\n  Rule: {f.rule}\n  Category: {display(f.category)} (CWE-{f.cwe})\n"
            f"  Definition: {guide}\n  Location: {f.file}:{f.line}\n\nCode:\n{code}\n")


class LLMTriager(Triager):
    deterministic = False

    def __init__(self, provider: Provider):
        self.provider = provider
        self.name = f"llm:{provider.name}"
        self.model = provider.model

    def triage(self, f: Finding, run: int = 0) -> Verdict:
        t0 = time.time()
        try:
            text = self.provider.complete(SYSTEM, build_prompt(f), run=run)
            data = parse_json(text)
            verdict = str(data.get("verdict", "")).strip().lower()
            if verdict not in VERDICTS:
                verdict, err = UNSURE, f"invalid verdict {verdict!r}"
            else:
                err = ""
            conf = float(data.get("confidence", 0) or 0)
            return Verdict(f.id, verdict, max(0.0, min(conf, 1.0)), str(data.get("reasoning", ""))[:800],
                           run, self.name, self.model, int((time.time() - t0) * 1000), err)
        except ProviderError:
            raise
        except Exception as e:  # malformed output counts against the model
            return Verdict(f.id, UNSURE, 0.0, "", run, self.name, self.model,
                           int((time.time() - t0) * 1000), f"parse error: {e}")


__all__ = ["LLMTriager", "SYSTEM", "build_prompt", "TP", "FP", "UNSURE"]
