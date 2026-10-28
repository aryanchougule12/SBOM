"""Predicate entry points.

These mirror the two predicates of ``docs/formal_specification_v0.2.md``:

* ``Req(component_not_present)`` -- §4, rules N1-N17, tests NT1-NT23
* ``Req(vulnerable_code_not_in_execute_path)`` -- §5, rules R1-R13, tests RT1-RT11

``req_component_not_present`` is implemented: the predicate is a pure function of already
computed dimension states, so it takes the engine's ``CnpInputs`` (see ``evidence.cnp_rules``;
the integrated pipeline that computes them from documents is ``evidence.evaluator``) and returns
the single final ``VerdictResult``. This replaces the Stage 0 stub ``req_component_not_present(finding)``,
whose bare ``Finding`` could not carry the dimension states.

``req_vulnerable_code_not_in_execute_path`` is not implemented: reachability, hazard and
call-graph evidence are outside the current milestone (register G15). It raises
``NotImplementedError`` rather than guessing.
"""

from __future__ import annotations

from evidence.cnp_rules import CnpInputs, evaluate_cnp
from model import Finding
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


def req_vulnerable_code_not_in_execute_path(finding: Finding) -> VerdictResult:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)``. Not implemented."""
    raise NotImplementedError(
        "Req(vulnerable_code_not_in_execute_path) is not implemented: reachability, hazard and "
        "call-graph evidence are outside the current milestone."
    )
