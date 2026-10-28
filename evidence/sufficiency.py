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
the procedure and is never decided here.

Two predicates are evaluated, selected by the justification of the finding the profile selects:
``component_not_present`` by ``evidence.evaluator`` and ``vulnerable_code_not_in_execute_path`` by
``evidence.reach_evaluator`` (which additionally takes the optional ``reachability`` evidence). A
finding carries one justification, so exactly one predicate runs; no combined verdict exists. Any
other justification is refused, not coerced, and ``reachability`` evidence supplied for a finding
that is not a reachability finding is refused (``EVAL_REACH_INPUT_NOT_APPLICABLE``), never
silently ignored.
"""

from __future__ import annotations

from typing import Optional, Sequence, Union

from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, RefusalCode, evaluate
from evidence.profile import ProfileError, ValidatedProfile, select_finding
from evidence.reach_evaluator import ReachOutcome, evaluate_reachability
from evidence.reach_inputs import ReachabilityEvidence
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig
from model import Finding, JustificationType


def evaluate_finding(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    verification: Optional[VerificationConfig] = None,
    reachability: Optional[ReachabilityEvidence] = None,
) -> Union[EvaluationOutcome, ReachOutcome, EvaluationRefusal]:
    """Evaluate the evidence sufficiency of the finding selected by ``profile``."""
    selected = _selected_finding(profile, findings)
    if selected is not None and selected.justification.justification == JustificationType.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value:
        return evaluate_reachability(profile, findings, index, reachability, verification)
    if selected is not None and reachability is not None:
        return EvaluationRefusal(RefusalCode.REACH_INPUT_NOT_APPLICABLE,
                                 "reachability evidence was supplied but the selected finding is not a "
                                 "vulnerable_code_not_in_execute_path finding")
    return evaluate(profile, findings, index, verification)


def _selected_finding(profile: ValidatedProfile, findings: Sequence[Finding]) -> Optional[Finding]:
    """The finding the profile selects, or ``None`` when the inputs are malformed or no single
    finding is selected: every such case falls through to the CNP evaluator's own refusals."""
    if not isinstance(profile, ValidatedProfile) or isinstance(findings, (str, bytes)) \
            or not isinstance(findings, Sequence) or not all(isinstance(f, Finding) for f in findings):
        return None
    try:
        return select_finding(profile, findings)
    except ProfileError:
        return None
