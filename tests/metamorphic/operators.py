"""The mutation-operator registry. Each operator rewrites one kind of evidence in a deep copy of a scenario."""

from __future__ import annotations

from tests.metamorphic.core import Operator, Scenario


def _walk_components(components):
    for component in components or []:
        yield component
        yield from _walk_components(component.get("components"))


# ---- neutral operators (M-6): free text only -------------------------------------------------------------------------------------------

def _free_text_sbom(s: Scenario) -> Scenario:
    out = s.mutate()
    text = "Reviewed by an unrelated maintainer; no technical content."
    if s.sbom_format == "cdx":
        for component in _walk_components(out.sbom.get("components")):
            component["description"] = text
        out.sbom.setdefault("metadata", {}).setdefault("component", {})["description"] = text
    else:
        for package in out.sbom.get("packages", []):
            package["comment"] = text
            package["summary"] = text
            package["description"] = text
    return out


def _free_text_vex(s: Scenario) -> Scenario:
    out = s.mutate()
    for statement in out.vex.get("statements", []):
        statement["impact_statement"] = "Rewritten explanation text."
        statement["status_notes"] = "Additional free-text notes."
    return out


def _label_only(s: Scenario) -> Scenario:
    out = s.mutate()
    for assertion in out.profile.get("inv_assertions", []):
        assertion["entered_by"] = "a different reviewer label"
    return out


NEUTRAL = (
    Operator("N-SBOM-TEXT", "neutral", "rewrite description/comment free text of every SBOM component or package", ("cnp", "reach"), _free_text_sbom),
    Operator("N-VEX-TEXT", "neutral", "rewrite impact_statement and status_notes of every VEX statement", ("cnp", "reach"), _free_text_vex),
    Operator("N-LABEL", "neutral", "change the evaluator's entered_by labels (never used in a decision)", ("cnp", "reach"), _label_only,
             applies=lambda s: bool(s.profile.get("inv_assertions"))),
)

from tests.metamorphic.operators_cnp import CNP_OPERATORS
from tests.metamorphic.operators_reach import REACH_OPERATORS

OPERATORS = NEUTRAL + CNP_OPERATORS + REACH_OPERATORS
