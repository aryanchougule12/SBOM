"""Predicate entry points (Stage 0 stubs; NOT implemented).

These mirror the two predicates of ``docs/formal_specification_v0.2.md``:

* ``Req(component_not_present)`` -- §4, rules N1-N17, tests NT1-NT21
* ``Req(vulnerable_code_not_in_execute_path)`` -- §5, rules R1-R13, tests RT1-RT11

Neither predicate is implemented at Stage 0. No rule is evaluated and no verdict is
produced; the functions only declare the intended signatures.
"""

from __future__ import annotations

from model import Finding
from reports.verdict import VerdictResult


def req_component_not_present(finding: Finding) -> VerdictResult:
    """Evaluate ``Req(component_not_present)``. Not implemented at Stage 0."""
    raise NotImplementedError("Stage 0 stub: Req(component_not_present) is not implemented.")


def req_vulnerable_code_not_in_execute_path(finding: Finding) -> VerdictResult:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)``. Not implemented at
    Stage 0."""
    raise NotImplementedError(
        "Stage 0 stub: Req(vulnerable_code_not_in_execute_path) is not implemented."
    )
