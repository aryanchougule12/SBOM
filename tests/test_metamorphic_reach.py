"""Checkpoint 3: mutation operators for vulnerable_code_not_in_execute_path and the relations over them."""

import pytest

from tests.metamorphic import core
from tests.metamorphic.campaign import run_campaign
from tests.metamorphic.operators import OPERATORS
from tests.metamorphic.operators_reach import REACH_OPERATORS
from tests.metamorphic.scenarios import reach_scenarios

SCENARIOS = reach_scenarios()
BASES, PAIRS = run_campaign(SCENARIOS, OPERATORS)
VERIFIED = [p for p in PAIRS if p.scenario_id == "reach-cdx-verified"]


def test_the_base_scenarios_start_from_supported_and_weak_and_every_dimension_is_satisfied():
    observed = {s.scenario_id: core.observe(s) for s in SCENARIOS}
    assert [o.verdict for o in observed.values()] == ["Supported", "Weak", "Supported"]
    assert dict(observed["reach-cdx-verified"].dimension_states) == {"BIND": "matched", "CFG": "declared", "ENTRY": "Present", "LOCUS": "Present", "REACH": "Absent"}
    assert observed["reach-cdx-unverified"].codes == ("ANALYSIS_PROVENANCE_BELOW_P3",)


def test_campaign_covers_each_applicable_pair_once_and_applies_neutral_operators_to_both_predicates():
    expected = sum(1 for s in SCENARIOS for o in OPERATORS if s.predicate in o.predicates and s.sbom_format in o.formats and o.applies(s))
    assert len(PAIRS) == expected == len({(p.scenario_id, p.op_id) for p in PAIRS})
    assert {p.op_id for p in PAIRS} == {o.op_id for o in OPERATORS if "reach" in o.predicates}


def test_no_relation_is_violated():
    assert [(p.scenario_id, p.op_id, [(r.relation, r.detail) for r in p.violations]) for p in PAIRS if p.violations] == []
    assert all(r.holds for b in BASES for r in b.relations)


def test_degrading_or_deleting_reachability_evidence_never_raises_a_verdict_m1():
    for p in PAIRS:
        if p.kind in ("delete", "degrade"):
            assert p.mutant.rank is None or p.mutant.rank <= p.base.rank, (p.scenario_id, p.op_id)


def test_every_reachability_operator_lowers_the_fully_supported_scenario():
    """Each condition of §5.5 is necessary: removing or degrading any single one leaves Supported."""
    for p in VERIFIED:
        if p.kind in ("delete", "degrade", "inject_positive"):
            assert p.mutant.rank < p.base.rank, p.op_id
    assert {p.op_id for p in VERIFIED if p.kind != "neutral"} == {o.op_id for o in REACH_OPERATORS}


def test_neutral_operators_do_not_change_reachability_verdicts():
    for p in PAIRS:
        if p.kind == "neutral":
            assert not p.changed, (p.scenario_id, p.op_id)


def test_injecting_a_positive_observation_of_any_kind_or_provenance_gives_insufficient_m4():
    injected = [p for p in PAIRS if p.kind == "inject_positive"]
    assert len(injected) == 12
    for p in injected:
        assert p.mutant.verdict == "Insufficient", (p.scenario_id, p.op_id)
        assert p.mutant.states()["REACH"] in ("Present", "Contradictory"), (p.scenario_id, p.op_id)
        assert {"CLAIM_CONTRADICTED_BY_PATH", "REACH_CONFLICT"} & set(p.mutant.codes)


def test_deleting_evidence_never_turns_unknown_into_absent_m2_and_removing_the_k1_report_gives_unknown():
    for p in PAIRS:
        if p.kind == "delete":
            assert not core.m2_no_absent_from_deletion(p.base, p.mutant).detail.startswith("new Absent"), (p.scenario_id, p.op_id)
    removed = next(p for p in VERIFIED if p.op_id == "DR-K1")
    assert removed.mutant.states()["REACH"] == "Unknown" and removed.mutant.verdict == "Insufficient"


def test_withdrawing_the_coverage_claim_never_leaves_absent():
    withdrawn = next(p for p in VERIFIED if p.op_id == "GR-COVERAGE")
    assert withdrawn.base.states()["REACH"] == "Absent" and withdrawn.mutant.states()["REACH"] == "Incomplete"


@pytest.mark.parametrize("operator", REACH_OPERATORS, ids=lambda o: o.op_id)
def test_every_operator_edits_a_copy_and_changes_the_input(operator):
    scenario = SCENARIOS[0]
    before = repr((scenario.reachability, scenario.verified_docs))
    mutated = operator.apply(scenario)
    assert repr((scenario.reachability, scenario.verified_docs)) == before
    assert repr((mutated.reachability, mutated.verified_docs)) != before
