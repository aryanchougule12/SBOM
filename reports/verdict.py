"""Verdict types and report rendering (Stage 0: types and a stub only).

Per ``docs/formal_specification_v0.2.md`` §3 the verdict is exactly one of
Supported, Weak or Insufficient. "Cannot be established" and "contradictory
evidence" are rationale classes recorded in the rationale string, never extra
verdict categories. No verdict is computed here, and no rationale ordering or
rendering is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    """The three verdict categories of §3, and no others."""

    SUPPORTED = "Supported"
    WEAK = "Weak"
    INSUFFICIENT = "Insufficient"


class RationaleClass(str, Enum):
    """Rationale class tokens of §3 (sub-reasons, not verdicts).

    NOTE: the specification (docs/formal_specification_v0.2.md §3) defines a fourth class, NO_RULE_APPLIES, not yet reflected here — this must be added when rationale generation is implemented (Stage 3/4).
    """

    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    CANNOT_BE_ESTABLISHED = "CANNOT_BE_ESTABLISHED"
    BELOW_BAR = "BELOW_BAR"


@dataclass
class VerdictResult:
    """The ``(verdict, rationale)`` output of §3. ``rationale`` follows the grammar
    ``<CLASS>[CODE,...]: text``; producing it is a later stage."""

    verdict: Verdict
    rationale: str


def render_verdict(result: VerdictResult) -> str:
    """Render a ``VerdictResult`` as report text. Not implemented at Stage 0."""
    raise NotImplementedError("Stage 0 stub: verdict rendering is not implemented.")
