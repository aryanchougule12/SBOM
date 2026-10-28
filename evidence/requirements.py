"""Predicate entry points.

These mirror the two predicates of ``docs/formal_specification_v0.2.md``:

* ``Req(component_not_present)`` -- §4, rules N1-N17, tests NT1-NT25
* ``Req(vulnerable_code_not_in_execute_path)`` -- §5, rules R1-R13, tests RT1-RT13 (RT12-RT13: addendum v0.2.3)

Both are implemented as pure functions of already computed dimension states, so each takes its
engine's input record -- ``CnpInputs`` (``evidence.cnp_rules``; the integrated pipeline that
computes them from documents is ``evidence.evaluator``) or ``ReachInputs``
(``evidence.reach_rules``; the pipeline is ``evidence.reach_evaluator``) -- and returns the single
final ``VerdictResult``. This replaces the Stage 0 stubs that took a bare ``Finding``, which could
not carry the dimension states.
"""

from __future__ import annotations

from evidence.cnp_rules import CnpInputs, evaluate_cnp
from evidence.reach_rules import ReachInputs, evaluate_reach
from reports.verdict import VerdictResult


def req_component_not_present(inputs: CnpInputs) -> VerdictResult:
    """Evaluate ``Req(component_not_present)`` over already computed dimension states.

    Raises ``UnresolvedArtifactKindError`` for ``ArtifactKind.UNKNOWN`` (register G10).
    """
    if not isinstance(inputs, CnpInputs):
        raise TypeError(
            "req_component_not_present takes the engine's CnpInputs; the Stage 0 form that took a bare "
            "Finding was replaced (use evidence.evaluator.evaluate to start from documents)"
        )
    return evaluate_cnp(inputs).result


def req_vulnerable_code_not_in_execute_path(inputs: ReachInputs) -> VerdictResult:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)`` over already computed dimension inputs."""
    if not isinstance(inputs, ReachInputs):
        raise TypeError(
            "req_vulnerable_code_not_in_execute_path takes the engine's ReachInputs; the Stage 0 form that took a "
            "bare Finding was replaced (use evidence.sufficiency.evaluate_finding to start from documents)"
        )
    return evaluate_reach(inputs).result
