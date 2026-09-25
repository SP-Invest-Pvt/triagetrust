"""Baseline: accept every scanner finding as real. This is what an untriaged backlog looks like."""
from __future__ import annotations

from ..models import TP, Finding, Verdict
from .base import Triager


class ScannerAsIs(Triager):
    name = "scanner-as-is"

    def triage(self, finding: Finding, run: int = 0) -> Verdict:
        return Verdict(finding.id, TP, 1.0, "No triage: scanner output accepted as-is.", run, self.name)
