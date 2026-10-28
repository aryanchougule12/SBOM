"""Sufficiency evaluation entry point.

``evaluate_finding`` runs the fixed decision procedure of ``docs/formal_specification_v0.2.md``
section 3 (Steps 0-5, as clarified by addendum v0.2.2) for the finding that an evaluator profile
selects, through the integrated pipeline of ``evidence.evaluator``. It returns an
``EvaluationOutcome`` (one final verdict) or an ``EvaluationRefusal`` (no verdict).

Intentional replacement of the Stage 0 stub: the stub was ``evaluate_finding(finding)``. A bare
``Finding`` cannot carry what the procedure needs (the scope S, the target component, the
document roles, the evaluator's assertions, the parsed SBOM records, an optional trusted
verification result), so the entry point now takes the validated profile, the candidate findings
and the Stage 1 index. Whether a verdict is acceptable to a downstream consumer (D-5) is outside
the procedure and is never decided here. Only ``component_not_present`` is evaluated; any other
justification is refused, not coerced.
"""

from __future__ import annotations

from typing import Optional, Sequence, Union

from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, evaluate
from evidence.profile import ValidatedProfile
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig
from model import Finding


def evaluate_finding(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    verification: Optional[VerificationConfig] = None,
) -> Union[EvaluationOutcome, EvaluationRefusal]:
    """Evaluate the evidence sufficiency of the finding selected by ``profile``."""
    return evaluate(profile, findings, index, verification)
