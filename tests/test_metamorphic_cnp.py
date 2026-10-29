"""Checkpoint 2: security-semantic mutation operators for component_not_present and the relations M-1, M-2, M-4 over them."""

import pytest

from tests.metamorphic import core
from tests.metamorphic.campaign import run_campaign
from tests.metamorphic.operators import OPERATORS
from tests.metamorphic.operators_cnp import CNP_OPERATORS
from tests.metamorphic.scenarios import cnp_scenarios

SCENARIOS = cnp_scenarios()
BASES, PAIRS = run_campaign(SCENARIOS, OPERATORS)
# Mutations that never change the verdict of these bases, and why: the target's absence rests on the complete, bound, attributed inventory,
# not on dependency edges (a dependency edge is not membership), not on versions/identifiers of *other* components, and an unrelated orphan is
# simply one more member that does not match the target.
INERT = {"D-DEP-EDGE", "D-DEP-ALL", "D-VERSION", "D-IDENTIFIER", "G-VERSION", "G-ORPHAN"}


def test_the_campaign_covers_every_applicable_pair_and_counts_each_once():
    expected = sum(1 for s in SCENARIOS for o in OPERATORS if s.predicate in o.predicates and s.sbom_format in o.formats and o.applies(s))
    assert len(PAIRS) == expected == len({(p.scenario_id, p.op_id) for p in PAIRS})
    assert {p.kind for p in PAIRS} == {"neutral", "delete", "degrade", "inject_positive"}


def test_no_relation_is_violated_by_any_pair_and_every_base_is_deterministic():
    assert [(p.scenario_id, p.op_id, [(r.relation, r.detail) for r in p.violations]) for p in PAIRS if p.violations] == []
    assert all(r.holds for b in BASES for r in b.relations)


def test_degrading_or_deleting_evidence_never_raises_a_verdict_m1():
    for p in PAIRS:
        if p.kind in ("delete", "degrade") and p.mutant.rank is not None:
            assert p.mutant.rank <= p.base.rank, (p.scenario_id, p.op_id)


def test_deleting_evidence_never_creates_an_absent_state_m2():
    for p in PAIRS:
        if p.kind == "delete" and p.mutant.kind == "evaluated":
            base_absent = {d for d, s in p.base.dimension_states if s == "Absent"}
            assert {d for d, s in p.mutant.dimension_states if s == "Absent"} <= base_absent, (p.scenario_id, p.op_id)


def test_injecting_the_target_component_always_yields_insufficient_m4():
    injected = [p for p in PAIRS if p.kind == "inject_positive"]
    assert len(injected) >= 8
    for p in injected:
        assert p.mutant.verdict == "Insufficient" and "CLAIM_CONTRADICTED_BY_INVENTORY" in p.mutant.codes, (p.scenario_id, p.op_id)
        assert p.mutant.states()["MATCH"] == "Present"


def test_the_operators_are_effective_not_vacuous():
    changed = {op.op_id for op in CNP_OPERATORS} & {p.op_id for p in PAIRS if p.changed}
    never_changed = {op.op_id for op in CNP_OPERATORS} - changed
    assert never_changed == INERT, never_changed ^ INERT
    # the first (supported) base is lowered by every operator that is not inert, not a free-text change and not an injection of an equal state
    lowered = {p.op_id for p in PAIRS if p.scenario_id == "cnp-cdx-verified" and p.mutant.rank is not None and p.mutant.rank < p.base.rank}
    assert {"D-COMPONENT", "D-DECLARATION", "D-SUBJECT-DIGEST", "D-TOOL", "D-TIMESTAMP", "D-VERIFICATION", "D-ASSERTION", "G-DECL-INCOMPLETE",
            "G-DECL-UNKNOWN", "G-SUBJECT-DIGEST", "G-VERIFICATION", "G-DANGLING-EDGE", "I-TWIN"} <= lowered


def test_a_mutation_that_makes_the_input_unusable_has_no_verdict_and_cannot_raise_one():
    unusable = [p for p in PAIRS if p.mutant.kind != "evaluated"]
    assert {(p.op_id, p.mutant.kind) for p in unusable} >= {("D-VEX-JUSTIFICATION", "refused"), ("D-TIMESTAMP", "input_error")}
    assert all(p.mutant.verdict is None and not p.violations for p in unusable)


@pytest.mark.parametrize("operator", CNP_OPERATORS, ids=lambda o: o.op_id)
def test_every_operator_edits_a_copy_and_changes_the_input(operator):
    for scenario in SCENARIOS:
        if scenario.sbom_format in operator.formats and operator.applies(scenario):
            before = repr((scenario.sbom, scenario.vex, scenario.profile, scenario.verified_coverage))
            mutated = operator.apply(scenario)
            assert repr((scenario.sbom, scenario.vex, scenario.profile, scenario.verified_coverage)) == before
            assert repr((mutated.sbom, mutated.vex, mutated.profile, mutated.verified_coverage)) != before, (scenario.scenario_id, operator.op_id)


def test_an_injected_twin_is_found_whether_or_not_a_dependency_edge_reaches_it():
    by_op = {p.op_id: p for p in PAIRS if p.scenario_id == "cnp-cdx-verified"}
    assert by_op["I-ORPHAN-TWIN"].mutant.verdict == by_op["I-TWIN"].mutant.verdict == "Insufficient"
    assert core.observe(SCENARIOS[0]).verdict == "Supported"
