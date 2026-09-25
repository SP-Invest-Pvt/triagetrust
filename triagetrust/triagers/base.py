from __future__ import annotations

from ..models import Finding, Verdict


class Triager:
    """A triager decides whether a finding is a real, exploitable vulnerability."""
    name = "base"
    model = ""
    deterministic = True

    def triage(self, finding: Finding, run: int = 0) -> Verdict:  # pragma: no cover
        raise NotImplementedError
