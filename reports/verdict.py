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

    ``NO_RULE_APPLIES`` is the class of the Step 4 no-rule default. It has no rule code,
    is emitted only when that default applies and never co-occurs with the codes of a
    triggered rule.
    """

    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    CANNOT_BE_ESTABLISHED = "CANNOT_BE_ESTABLISHED"
    BELOW_BAR = "BELOW_BAR"
    NO_RULE_APPLIES = "NO_RULE_APPLIES"


@dataclass
class VerdictResult:
    """The ``(verdict, codes, rationale)`` output of §3. ``codes`` are the triggered
    rule codes in the §3 output order (empty for Supported and for the no-rule default).
    ``rationale`` follows the grammar ``<CLASS>[CODE,...]: text``; an empty string means
    that no class applies (Supported). ``limitations`` lists, as ``<DIMENSION>=<State>``, the
    required dimensions whose state fails a Supported condition and is governed by no rule (for
    ``Req(component_not_present)``: MATCH Unknown; INV Absent, Incomplete, Ambiguous; DECL
    Absent, Ambiguous, Contradictory), which impose the Insufficient ceiling of section 3 Step 4
    (specification addendum v0.2.2). It is a separate field: no rule code or rationale class is
    added for it, and the verdict is the single final one."""

    verdict: Verdict
    rationale: str
    codes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


def render_verdict(result: VerdictResult) -> str:
    """Render a ``VerdictResult`` as report text. Not implemented at Stage 0."""
    raise NotImplementedError("Stage 0 stub: verdict rendering is not implemented.")
