"""Sufficiency evaluation entry point (Stage 0 stub; NOT implemented).

Future role: run the fixed decision procedure of ``docs/formal_specification_v0.2.md``
§3 (Steps 0-5) for a ``Finding`` and return a ``VerdictResult``. The procedure is not
implemented at Stage 0. Whether a verdict is acceptable to a downstream consumer
(D-5) is outside the procedure and will never be decided here.
"""

from __future__ import annotations

from model import Finding
from reports.verdict import VerdictResult


def evaluate_finding(finding: Finding) -> VerdictResult:
    """Evaluate the evidence sufficiency of ``finding``. Not implemented at Stage 0."""
    raise NotImplementedError("Stage 0 stub: sufficiency evaluation is not implemented.")
