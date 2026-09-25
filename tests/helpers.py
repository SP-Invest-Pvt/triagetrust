import random

from triagetrust.models import FP, TP, UNSURE, Finding, Verdict
from triagetrust.providers import Provider
from triagetrust.triagers.base import Triager


def finding(i, cat="sqli", label=True, code=""):
    return Finding(id=f"f{i}", rule="r", category=cat, cwe=89, file="a.java", line=1, code=code, label=label)


class Oracle(Triager):
    """Test double: correct except on a chosen set of ids; optionally noisy across runs."""
    name = "oracle"

    def __init__(self, wrong=(), noisy=(), abstain=()):
        self.wrong, self.noisy, self.abstain = set(wrong), set(noisy), set(abstain)
        self.deterministic = not self.noisy

    def triage(self, f, run=0):
        if f.id in self.abstain:
            return Verdict(f.id, UNSURE, 0.0, "", run, self.name)
        right = TP if f.label else FP
        wrong = FP if f.label else TP
        v = wrong if f.id in self.wrong else right
        if f.id in self.noisy and run % 2 == 1:
            v = wrong if v == right else right
        return Verdict(f.id, v, 0.9, "", run, self.name)


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, replies, **kw):
        super().__init__(model="fake-1", cache_dir=kw.pop("cache_dir"), **kw)
        self.replies = list(replies)
        self.calls = 0

    def _call(self, system, user):
        self.calls += 1
        return self.replies[(self.calls - 1) % len(self.replies)]
