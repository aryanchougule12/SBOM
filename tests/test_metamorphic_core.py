"""Checkpoint 1 of the metamorphic framework: vocabulary, base scenarios, neutral operators, determinism and rationale relations."""

import pytest

from tests.metamorphic import core
from tests.metamorphic.campaign import run_campaign
from tests.metamorphic.operators import NEUTRAL, OPERATORS
from tests.metamorphic.scenarios import all_scenarios

SCENARIOS = {s.scenario_id: s for s in all_scenarios()}


def test_the_base_scenarios_evaluate_and_start_from_different_verdicts():
    observed = {sid: core.observe(s) for sid, s in SCENARIOS.items()}
    assert all(o.kind == "evaluated" for o in observed.values())
    assert observed["cnp-cdx-verified"].verdict == "Supported" and observed["cnp-cdx-unverified"].verdict == "Weak" and observed["cnp-spdx"].verdict == "Weak"
    assert {o.verdict for o in observed.values()} >= {"Supported", "Weak"}


def test_mutation_never_changes_the_scenario_it_was_applied_to():
    for scenario in all_scenarios():
        before = (repr(scenario.sbom), repr(scenario.vex), repr(scenario.profile))
        for operator in OPERATORS:
            if scenario.predicate in operator.predicates and scenario.sbom_format in operator.formats and operator.applies(scenario):
                operator.apply(scenario)
        assert (repr(scenario.sbom), repr(scenario.vex), repr(scenario.profile)) == before


@pytest.mark.parametrize("sid", sorted(SCENARIOS))
def test_every_base_scenario_is_deterministic_and_lists_every_code(sid):
    base = core.observe(SCENARIOS[sid])
    assert core.m3_deterministic(base, core.observe(SCENARIOS[sid])).holds and core.m5_rationale_lists_every_code(base).holds


def test_neutral_operators_change_the_text_and_never_the_verdict_or_codes():
    bases, pairs = run_campaign(list(SCENARIOS.values()), NEUTRAL)
    assert len(pairs) == len(SCENARIOS) * len(NEUTRAL) - sum(1 for s in SCENARIOS.values() if not s.profile.get("inv_assertions")) * 1
    for pair in pairs:
        assert not pair.violations, (pair.scenario_id, pair.op_id, pair.violations)
        assert not pair.changed, (pair.scenario_id, pair.op_id)


def test_the_neutral_operators_really_modify_the_input():
    for scenario in SCENARIOS.values():
        for operator in NEUTRAL:
            if operator.applies(scenario):
                mutated = operator.apply(scenario)
                assert (mutated.sbom, mutated.vex, mutated.profile) != (scenario.sbom, scenario.vex, scenario.profile), (scenario.scenario_id, operator.op_id)


def test_the_relations_can_fail():
    """A framework that cannot report a violation proves nothing: feed each relation a violating pair."""
    up = core.Observation("evaluated", "Supported", (), "")
    down = core.Observation("evaluated", "Insufficient", ("X",), "X: text")
    assert not core.m1_never_raises(down, up).holds and core.m1_never_raises(up, down).holds
    assert not core.m4_positive_gives_insufficient(down, up).holds and core.m4_positive_gives_insufficient(up, down).holds
    assert not core.m6_neutral(up, down).holds and core.m6_neutral(up, up).holds
    assert not core.m5_rationale_lists_every_code(core.Observation("evaluated", "Weak", ("CODE_A",), "no such")).holds
    assert not core.m3_deterministic(up, down).holds
    refused = core.Observation("refused")
    assert core.m1_never_raises(up, refused).holds and core.m4_positive_gives_insufficient(up, refused).holds
    absent = core.Observation("evaluated", "Weak", dimension_states=(("MATCH", "Absent"),), item_states=(("MATCH", "Absent"),))
    unknown = core.Observation("evaluated", "Weak", dimension_states=(("MATCH", "Unknown"),), item_states=(("MATCH", "Unknown"),))
    assert not core.m2_no_absent_from_deletion(unknown, absent).holds and core.m2_no_absent_from_deletion(absent, unknown).holds


def test_unusable_mutated_input_is_reported_not_raised():
    broken = SCENARIOS["cnp-cdx-verified"].mutate(sbom={"bomFormat": "CycloneDX"})
    observation = core.observe(broken)
    assert observation.kind == "input_error" and observation.verdict is None and "specVersion" in observation.detail
    assert core.observe(SCENARIOS["cnp-cdx-verified"].mutate(vex={})).kind == "input_error"
