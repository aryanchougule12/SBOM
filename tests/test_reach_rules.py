"""Tests for evidence.reach_rules: the pure Req(vulnerable_code_not_in_execute_path) engine.

RT1-RT11 are encoded from ``docs/formal_specification_v0.2.md`` section 5.8 at the dimension level,
exactly as the specification states them, and every rule R1-R13 of section 5.4 is exercised on its
own, in combination, and against its negative boundary. The engine is a function of already computed
dimension states, so nothing here touches parsing, binding or provenance computation. The R1-R13 are
the reachability rules of section 5.4, unrelated to the inventory structural check "R1".
"""

import itertools
import re

import pytest

from evidence.cnp_rules import BindState
from evidence.reach_rules import (
    REACH_RULES,
    CfgState,
    HazardClass,
    HazardDisposition,
    HazardInput,
    ReachBasis,
    evaluate_reach,
    normalize_hazards,
)
from model import EvidenceState as S, ProvenanceLevel as P
from reports.verdict import RationaleClass, Verdict
from tests.reach_support import CLASS_NAMES, all_hazards, baseline_hazards, excluded, inputs, modeled

SUPPORTED, WEAK, INSUFFICIENT = Verdict.SUPPORTED, Verdict.WEAK, Verdict.INSUFFICIENT
UNKNOWN_HAZARD = HazardInput()
ALL_UNKNOWN = {}  # a missing class is Unknown (the section 5.2 default)
ALL_HAZARD_CODES = tuple(f"HAZARD_{name}" for name in CLASS_NAMES)

# ---- the rule table, restated from section 5.4 -------------------------------------------------------------

SPEC_TABLE = {
    "R1": (INSUFFICIENT, "CONTRADICTORY_EVIDENCE", "CLAIM_CONTRADICTED_BY_PATH"),
    "R2": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", None),  # MISSING_EDGE_IS_UNKNOWN or NO_ANALYSIS
    "R3": (INSUFFICIENT, "CONTRADICTORY_EVIDENCE", "REACH_CONFLICT"),
    "R4": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "NO_LOCUS"),
    "R5": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "ENTRYPOINTS_UNDECLARED"),
    "R6": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "SCOPE_UNBOUND"),
    "R7": (WEAK, "BELOW_BAR", "NON_EXHAUSTIVE_EVIDENCE"),
    "R8": (WEAK, "BELOW_BAR", "PARTIAL_OR_UNRESOLVED_CALLGRAPH"),
    "R9": (WEAK, "BELOW_BAR", "LOCUS_MAY_BE_UNDERAPPROXIMATE"),
    "R10": (WEAK, "BELOW_BAR", "ENTRYPOINTS_INCOMPLETE"),
    "R11": (WEAK, "BELOW_BAR", None),  # HAZARD_<CLASS> (+ the provenance code)
    "R12": (WEAK, "BELOW_BAR", "CONFIG_ASSUMPTION_UNDECLARED"),
    "R13": (WEAK, "BELOW_BAR", "ANALYSIS_PROVENANCE_BELOW_P3"),
}


def test_the_rule_table_is_section_5_4():
    assert [r.rule_id for r in REACH_RULES] == [f"R{n}" for n in range(1, 14)]
    for rule in REACH_RULES:
        ceiling, rationale_class, code = SPEC_TABLE[rule.rule_id]
        assert (rule.ceiling, rule.rationale_class.value) == (ceiling, rationale_class)
        if code is not None:
            assert rule.code == code


# ---- RT1-RT11 (section 5.8) -----------------------------------------------------------------------------------

def test_rt1_baseline_is_supported_with_no_codes():
    evaluation = evaluate_reach(inputs())
    assert evaluation.result.verdict is SUPPORTED
    assert evaluation.result.codes == () and evaluation.result.rationale == "" and evaluation.result.limitations == ()
    assert evaluation.supported_conditions_hold and evaluation.unmet_supported_conditions == ()


def test_rt2_only_k4_evidence():
    evaluation = evaluate_reach(inputs(reach=S.UNKNOWN, reach_basis=None, prov_reach=None, only_k4_evidence=True,
                                       entry=S.UNKNOWN, hazards=ALL_UNKNOWN))
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.rule_ids == ("R2", "R5", "R11")
    assert evaluation.result.codes == ("MISSING_EDGE_IS_UNKNOWN", "ENTRYPOINTS_UNDECLARED") + ALL_HAZARD_CODES


def test_rt3_reflection_unknown():
    evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.REFLECTION: UNKNOWN_HAZARD}))
    assert (evaluation.result.verdict, evaluation.result.codes) == (WEAK, ("HAZARD_REFLECTION",))
    assert evaluation.rule_ids == ("R11",)


def test_rt4_k1_absent_plus_k3_trace_hit_is_contradictory():
    evaluation = evaluate_reach(inputs(reach=S.CONTRADICTORY, reach_basis=None))
    assert (evaluation.result.verdict, evaluation.result.codes) == (INSUFFICIENT, ("REACH_CONFLICT",))
    assert evaluation.rule_ids == ("R3",)


@pytest.mark.parametrize("state", [S.INCOMPLETE, S.AMBIGUOUS], ids=["rt5_incomplete", "rt6_ambiguous"])
def test_rt5_rt6_k1_incomplete_or_ambiguous(state):
    evaluation = evaluate_reach(inputs(reach=state, reach_basis=ReachBasis.K1))
    assert (evaluation.result.verdict, evaluation.result.codes) == (WEAK, ("PARTIAL_OR_UNRESOLVED_CALLGRAPH",))
    assert evaluation.rule_ids == ("R8",)


def test_rt7_reflection_exclusion_basis_at_p0():
    evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.REFLECTION: excluded(P.P0)}))
    assert evaluation.result.verdict is WEAK
    assert evaluation.result.codes == ("HAZARD_REFLECTION", "HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION")


def test_rt8_prov_reach_p2():
    evaluation = evaluate_reach(inputs(prov_reach=P.P2))
    assert (evaluation.result.verdict, evaluation.result.codes) == (WEAK, ("ANALYSIS_PROVENANCE_BELOW_P3",))


@pytest.mark.parametrize("label", ["rt9_k3_no_hit", "rt10_k2_negative_p3"])
def test_rt9_rt10_no_k1_non_exhaustive_basis_at_p3(label):
    evaluation = evaluate_reach(inputs(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE,
                                       hazards=all_hazards(lambda: excluded(P.P1))))
    assert (evaluation.result.verdict, evaluation.result.codes) == (WEAK, ("NON_EXHAUSTIVE_EVIDENCE",))
    assert evaluation.rule_ids == ("R7",)  # R7 is the only rule that fires; R8 is limited to K1


def test_rt11_k2_negative_at_p0_is_no_analysis():
    evaluation = evaluate_reach(inputs(reach=S.UNKNOWN, reach_basis=None, prov_reach=None, only_k4_evidence=False,
                                       entry=S.UNKNOWN, hazards=ALL_UNKNOWN))
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.rule_ids == ("R2", "R5", "R11")
    assert evaluation.result.codes[0] == "NO_ANALYSIS" and "MISSING_EDGE_IS_UNKNOWN" not in evaluation.result.codes


def test_rt12_rt13_addendum_v0_2_3_ungoverned_locus_or_entry_state_caps_the_weak_provenance_rule():
    for changes, limitation in [(dict(locus=S.AMBIGUOUS), "LOCUS=Ambiguous"), (dict(entry=S.CONTRADICTORY), "ENTRY=Contradictory")]:
        capped = evaluate_reach(inputs(prov_reach=P.P2, **changes))
        assert (capped.result.verdict, capped.result.codes, capped.result.limitations) == (
            INSUFFICIENT, ("ANALYSIS_PROVENANCE_BELOW_P3",), (limitation,))
        # the same state at P3 gives the no-rule default Insufficient: lower provenance must not raise the verdict (P-3)
        at_p3 = evaluate_reach(inputs(prov_reach=P.P3, **changes))
        assert at_p3.result.verdict is INSUFFICIENT and at_p3.result.codes == () and at_p3.result.rationale.startswith("NO_RULE_APPLIES[]")


# ---- every rule on its own, from the RT1 baseline -----------------------------------------------------------------

SINGLE = [
    ("R1", dict(reach=S.PRESENT, reach_basis=None), "CLAIM_CONTRADICTED_BY_PATH"),
    ("R2", dict(reach=S.UNKNOWN, reach_basis=None, prov_reach=None), "NO_ANALYSIS"),
    ("R2", dict(reach=S.UNKNOWN, reach_basis=None, prov_reach=None, only_k4_evidence=True), "MISSING_EDGE_IS_UNKNOWN"),
    ("R3", dict(reach=S.CONTRADICTORY, reach_basis=None), "REACH_CONFLICT"),
    ("R4", dict(locus=S.UNKNOWN), "NO_LOCUS"),
    ("R5", dict(entry=S.UNKNOWN), "ENTRYPOINTS_UNDECLARED"),
    ("R6", dict(bind=BindState.UNKNOWN), "SCOPE_UNBOUND"),
    ("R6", dict(bind=BindState.MISMATCHED), "SCOPE_UNBOUND"),
    ("R7", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE), "NON_EXHAUSTIVE_EVIDENCE"),
    ("R8", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.K1), "PARTIAL_OR_UNRESOLVED_CALLGRAPH"),
    ("R8", dict(reach=S.AMBIGUOUS, reach_basis=ReachBasis.K1), "PARTIAL_OR_UNRESOLVED_CALLGRAPH"),
    ("R9", dict(locus=S.INCOMPLETE), "LOCUS_MAY_BE_UNDERAPPROXIMATE"),
    ("R10", dict(entry=S.INCOMPLETE), "ENTRYPOINTS_INCOMPLETE"),
    ("R11", dict(hazards={**baseline_hazards(), HazardClass.NATIVE_FFI: HazardInput(HazardDisposition.UNMODELED)}), "HAZARD_NATIVE_FFI"),
    ("R11", dict(hazards={k: v for k, v in baseline_hazards().items() if k is not HazardClass.GENERATED_CODE}), "HAZARD_GENERATED_CODE"),
    ("R12", dict(cfg=CfgState.UNDECLARED), "CONFIG_ASSUMPTION_UNDECLARED"),
    ("R12", dict(cfg=CfgState.EXTENDS_BEYOND), "CONFIG_ASSUMPTION_UNDECLARED"),
    ("R13", dict(prov_reach=P.P2), "ANALYSIS_PROVENANCE_BELOW_P3"),
    ("R13", dict(prov_reach=P.P1), "ANALYSIS_PROVENANCE_BELOW_P3"),
    ("R13", dict(prov_reach=P.P0), "ANALYSIS_PROVENANCE_BELOW_P3"),
]


@pytest.mark.parametrize("rule_id, changes, code", SINGLE, ids=[f"{r}-{n}" for n, (r, _, _) in enumerate(SINGLE)])
def test_each_rule_fires_alone_with_its_table_ceiling_class_and_code(rule_id, changes, code):
    evaluation = evaluate_reach(inputs(**changes))
    ceiling, rationale_class, _ = SPEC_TABLE[rule_id]
    assert evaluation.rule_ids == (rule_id,)
    assert evaluation.result.codes == (code,)
    assert evaluation.result.verdict is ceiling
    assert evaluation.result.rationale.startswith(f"{rationale_class}[{code}]: {rule_id}: ")
    assert evaluation.result.limitations == ()


# ---- negative boundaries: states that must not trigger a rule -----------------------------------------------------------

NOT_TRIGGERED = [
    ("R1", dict(reach=S.CONTRADICTORY, reach_basis=None)),
    ("R2", dict(reach=S.PRESENT, reach_basis=None)),
    ("R2", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE)),
    ("R3", dict(reach=S.PRESENT, reach_basis=None)),
    ("R4", dict(locus=S.INCOMPLETE)),
    ("R5", dict(entry=S.INCOMPLETE)),
    ("R6", dict()),
    ("R7", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.K1)),  # K1 Incomplete is R8, never R7
    ("R8", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE)),  # R7 only: the two never double-fire
    ("R8", dict(reach=S.ABSENT, reach_basis=ReachBasis.K1)),
    ("R9", dict(locus=S.UNKNOWN)),
    ("R10", dict(entry=S.UNKNOWN)),
    ("R11", dict(hazards=all_hazards(lambda: excluded(P.P1)))),
    ("R11", dict(hazards=all_hazards(modeled))),
    ("R12", dict(cfg=CfgState.NOT_COMPARED)),
    ("R13", dict(reach=S.UNKNOWN, reach_basis=None, prov_reach=None)),  # PROV_REACH is undefined when REACH is Unknown
    ("R13", dict(prov_reach=P.P3)),
]


@pytest.mark.parametrize("rule_id, changes", NOT_TRIGGERED, ids=[f"{r}-{n}" for n, (r, _) in enumerate(NOT_TRIGGERED)])
def test_rules_do_not_fire_outside_their_condition(rule_id, changes):
    assert rule_id not in evaluate_reach(inputs(**changes)).rule_ids


def test_r7_and_r8_never_double_fire_over_the_whole_reach_domain():
    for state, basis in itertools.product(S, (None, ReachBasis.K1, ReachBasis.NON_EXHAUSTIVE)):
        try:
            evaluation = evaluate_reach(inputs(reach=state, reach_basis=basis,
                                               prov_reach=None if state is S.UNKNOWN else P.P3))
        except ValueError:
            continue  # an input combination section 5.1 cannot produce
        assert not {"R7", "R8"} <= set(evaluation.rule_ids)


# ---- hazards: Step 1, R11 codes and their order ----------------------------------------------------------------------------

def test_step1_exclusion_basis_missing_unbound_or_below_p1_is_downgraded_to_unknown_with_the_provenance_code():
    cases = {
        "below_p1": HazardInput(HazardDisposition.EXCLUDED_BY_EVIDENCE, True, P.P0),
        "unbound": HazardInput(HazardDisposition.EXCLUDED_BY_EVIDENCE, False, P.P3),
        "missing": HazardInput(HazardDisposition.EXCLUDED_BY_EVIDENCE, True, None),
    }
    for label, claim in cases.items():
        evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.REFLECTION: claim}))
        reflection = next(h for h in evaluation.hazards if h.hazard_class is HazardClass.REFLECTION)
        assert (reflection.effective, reflection.provenance_downgrade) == (HazardDisposition.UNKNOWN, True), label
        assert evaluation.result.codes == ("HAZARD_REFLECTION", "HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION"), label


@pytest.mark.parametrize("ep", [P.P1, P.P2, P.P3])
def test_an_exclusion_with_a_bound_basis_at_p1_or_above_stands(ep):
    evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.REFLECTION: excluded(ep)}))
    assert evaluation.result.verdict is SUPPORTED


def test_a_modeled_claim_outside_a_k1_report_is_unknown_without_the_provenance_code():
    claim = HazardInput(HazardDisposition.MODELED_CONSERVATIVELY, declared_in_k1=False)
    evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.NATIVE_FFI: claim}))
    assert evaluation.result.codes == ("HAZARD_NATIVE_FFI",)
    assert next(h for h in evaluation.hazards if h.hazard_class is HazardClass.NATIVE_FFI).provenance_downgrade is False


def test_a_hazard_claim_never_improves_by_carrying_a_basis_it_does_not_need():
    # basis fields on an unmodeled/unknown claim are ignored: they cannot lift it
    claim = HazardInput(HazardDisposition.UNMODELED, True, P.P3, True)
    evaluation = evaluate_reach(inputs(hazards={**baseline_hazards(), HazardClass.REFLECTION: claim}))
    assert evaluation.result.codes == ("HAZARD_REFLECTION",)


def test_r11_codes_are_ordered_by_class_then_provenance_code_and_rule_ordering_is_numeric():
    hazards = {c: modeled() for c in HazardClass}
    hazards[HazardClass.REFLECTION] = excluded(P.P0)
    hazards[HazardClass.BUILD_TIME_PRUNING] = excluded(P.P0)
    hazards[HazardClass.NATIVE_FFI] = UNKNOWN_HAZARD
    evaluation = evaluate_reach(inputs(hazards=hazards, entry=S.INCOMPLETE, locus=S.INCOMPLETE, cfg=CfgState.UNDECLARED,
                                       prov_reach=P.P2, reach=S.INCOMPLETE, reach_basis=ReachBasis.K1))
    assert evaluation.result.codes == (
        "PARTIAL_OR_UNRESOLVED_CALLGRAPH",                       # R8
        "LOCUS_MAY_BE_UNDERAPPROXIMATE",                         # R9
        "ENTRYPOINTS_INCOMPLETE",                                # R10 (numeric suffix: after R9, before R11)
        "HAZARD_BUILD_TIME_PRUNING", "HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:BUILD_TIME_PRUNING",
        "HAZARD_NATIVE_FFI",
        "HAZARD_REFLECTION", "HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION",
        "CONFIG_ASSUMPTION_UNDECLARED",                          # R12
        "ANALYSIS_PROVENANCE_BELOW_P3",                          # R13
    )
    assert evaluation.rule_ids == ("R8", "R9", "R10", "R11", "R12", "R13")


def test_the_closed_hazard_enumeration_has_the_eight_classes_of_section_5_3():
    assert len(HazardClass) == 8 and "REFLECTION" in CLASS_NAMES
    assert len(normalize_hazards({})) == 8 and all(h.effective is HazardDisposition.UNKNOWN for h in normalize_hazards({}))


# ---- precedence and multi-rule behaviour ---------------------------------------------------------------------------------------

def test_the_verdict_is_the_minimum_ceiling_and_every_triggered_code_is_kept():
    evaluation = evaluate_reach(inputs(reach=S.PRESENT, reach_basis=None, prov_reach=P.P1, locus=S.INCOMPLETE))
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.rule_ids == ("R1", "R9", "R13")  # the Weak rules are not dropped by the Insufficient one
    assert evaluation.result.codes == ("CLAIM_CONTRADICTED_BY_PATH", "LOCUS_MAY_BE_UNDERAPPROXIMATE", "ANALYSIS_PROVENANCE_BELOW_P3")


def test_a_provenance_ceiling_and_a_reachability_rule_both_apply_without_order_dependence():
    # R13 (Weak) with R8 (Weak) and R3 (Insufficient): minimum ceiling, every code, class-rank order.
    evaluation = evaluate_reach(inputs(reach=S.CONTRADICTORY, reach_basis=None, prov_reach=P.P0, hazards={}))
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.rule_ids == ("R3", "R11", "R13")
    assert evaluation.result.rationale.split(" | ")[0].startswith("CONTRADICTORY_EVIDENCE[REACH_CONFLICT]")


def test_rationale_follows_the_grammar_one_segment_per_class_in_rank_order():
    evaluation = evaluate_reach(inputs(reach=S.PRESENT, reach_basis=None, locus=S.UNKNOWN, prov_reach=P.P2))
    segments = evaluation.result.rationale.split(" | ")
    assert [s.split("[")[0] for s in segments] == ["CONTRADICTORY_EVIDENCE", "CANNOT_BE_ESTABLISHED", "BELOW_BAR"]
    for segment in segments:
        assert re.fullmatch(r"(CONTRADICTORY_EVIDENCE|CANNOT_BE_ESTABLISHED|BELOW_BAR)\[[A-Z0-9_,:]+\]: .+", segment)


def test_the_no_rule_default_is_insufficient_with_no_code_and_no_triggered_rule():
    evaluation = evaluate_reach(inputs(locus=S.ABSENT))
    assert evaluation.result.verdict is INSUFFICIENT and evaluation.result.codes == () and evaluation.triggered == ()
    assert evaluation.result.rationale.startswith(f"{RationaleClass.NO_RULE_APPLIES.value}[]: ")
    assert evaluation.result.limitations == ("LOCUS=Absent",)


# ---- Supported requires ALL (section 5.5) ---------------------------------------------------------------------------------------------

SUPPORTED_BREAKERS = [
    ("reach", dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.K1)),
    ("locus", dict(locus=S.INCOMPLETE)),
    ("entry", dict(entry=S.INCOMPLETE)),
    ("hazard", dict(hazards={**baseline_hazards(), HazardClass.GENERATED_CODE: UNKNOWN_HAZARD})),
    ("cfg", dict(cfg=CfgState.UNDECLARED)),
    ("bind", dict(bind=BindState.UNKNOWN)),
    ("prov", dict(prov_reach=P.P2)),
]


@pytest.mark.parametrize("label, changes", SUPPORTED_BREAKERS, ids=[b[0] for b in SUPPORTED_BREAKERS])
def test_each_supported_condition_is_necessary(label, changes):
    evaluation = evaluate_reach(inputs(**changes))
    assert evaluation.result.verdict is not SUPPORTED and not evaluation.supported_conditions_hold
    assert evaluation.unmet_supported_conditions


# ---- the unresolved-dimension ceiling (register G18 for this predicate) --------------------------------------------------------------------

@pytest.mark.parametrize("dimension", ["locus", "entry"])
@pytest.mark.parametrize("state", [S.ABSENT, S.AMBIGUOUS, S.CONTRADICTORY])
def test_an_ungoverned_locus_or_entry_state_caps_a_weak_result_at_insufficient(dimension, state):
    evaluation = evaluate_reach(inputs(**{dimension: state}, prov_reach=P.P2))  # R13 alone would give Weak
    assert evaluation.rule_ids == ("R13",)
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.result.limitations == (f"{dimension.upper()}={state.value}",)
    assert evaluation.result.codes == ("ANALYSIS_PROVENANCE_BELOW_P3",)  # the ceiling adds no code


def test_cfg_not_compared_is_ungoverned_and_caps_at_insufficient():
    evaluation = evaluate_reach(inputs(cfg=CfgState.NOT_COMPARED, prov_reach=P.P2))
    assert evaluation.result.verdict is INSUFFICIENT and evaluation.result.limitations == ("CFG=not_compared",)


@pytest.mark.parametrize("changes", [
    dict(locus=S.INCOMPLETE), dict(entry=S.INCOMPLETE), dict(locus=S.UNKNOWN), dict(entry=S.UNKNOWN),
    dict(cfg=CfgState.UNDECLARED), dict(cfg=CfgState.EXTENDS_BEYOND),
    dict(reach=S.INCOMPLETE, reach_basis=ReachBasis.K1), dict(reach=S.AMBIGUOUS, reach_basis=ReachBasis.K1),
    dict(hazards={}),
])
def test_governed_states_keep_the_ceiling_the_table_gives_them_even_with_a_weak_provenance_rule(changes):
    evaluation = evaluate_reach(inputs(prov_reach=P.P2, **changes))
    expected = min((SPEC_TABLE[r][0] for r in evaluation.rule_ids), key=[INSUFFICIENT, WEAK, SUPPORTED].index)
    assert evaluation.result.limitations == ()
    assert evaluation.result.verdict is expected


def test_every_state_of_every_dimension_is_either_ok_governed_or_capped():
    """No required dimension state silently falls between the rules (the failure mode G18 describes)."""
    for locus, entry, cfg, bind in itertools.product(S, S, CfgState, BindState):
        evaluation = evaluate_reach(inputs(locus=locus, entry=entry, cfg=cfg, bind=bind, prov_reach=P.P2))
        failing = (locus is not S.PRESENT or entry is not S.PRESENT or cfg is not CfgState.DECLARED
                   or bind is not BindState.MATCHED)
        if not failing:
            continue
        governed_here = {r for r in evaluation.rule_ids} - {"R13"}
        capped = bool(evaluation.result.limitations)
        # the failing dimension is addressed by a rule or by the ceiling, and the verdict is never Supported
        assert governed_here or capped, (locus, entry, cfg, bind)
        assert evaluation.result.verdict is not SUPPORTED


# ---- P-3 / M-1: lowering never raises the verdict -----------------------------------------------------------------------------------------------

RANK = {INSUFFICIENT: 0, WEAK: 1, SUPPORTED: 2}


def _verdict(**changes):
    return RANK[evaluate_reach(inputs(**changes)).result.verdict]


def test_lowering_prov_reach_never_raises_the_verdict_over_a_wide_grid():
    levels = [P.P3, P.P2, P.P1, P.P0]
    reaches = [(S.ABSENT, ReachBasis.K1), (S.INCOMPLETE, ReachBasis.K1), (S.AMBIGUOUS, ReachBasis.K1),
               (S.INCOMPLETE, ReachBasis.NON_EXHAUSTIVE), (S.PRESENT, None), (S.CONTRADICTORY, None)]
    for (reach, basis), locus, entry, cfg, bind in itertools.product(reaches, S, S, CfgState, BindState):
        verdicts = [_verdict(reach=reach, reach_basis=basis, prov_reach=p, locus=locus, entry=entry, cfg=cfg, bind=bind)
                    for p in levels]
        assert verdicts == sorted(verdicts, reverse=True), (reach, locus, entry, cfg, bind)


def test_lowering_hazard_basis_provenance_or_binding_never_raises_the_verdict():
    for locus, entry, cfg, prov in itertools.product((S.PRESENT, S.INCOMPLETE, S.UNKNOWN, S.ABSENT), (S.PRESENT, S.INCOMPLETE),
                                                     CfgState, (P.P3, P.P2, P.P0)):
        chain = [excluded(P.P3), excluded(P.P1), excluded(P.P0), excluded(P.P3, bound=False), UNKNOWN_HAZARD]
        verdicts = [_verdict(hazards={**baseline_hazards(), HazardClass.REFLECTION: h}, locus=locus, entry=entry, cfg=cfg,
                             prov_reach=prov) for h in chain]
        assert verdicts[0] >= verdicts[1] >= verdicts[2], (locus, entry, cfg, prov)
        assert verdicts[0] >= verdicts[3] >= 0 and verdicts[0] >= verdicts[4]


# each chain lists states from the claim-favourable end to the claim-unfavourable end (U-10)
CHAINS = {
    "locus": [S.PRESENT, S.INCOMPLETE, S.UNKNOWN],
    "entry": [S.PRESENT, S.INCOMPLETE, S.UNKNOWN],
    "bind": [BindState.MATCHED, BindState.UNKNOWN],
    "cfg": [CfgState.DECLARED, CfgState.EXTENDS_BEYOND, CfgState.UNDECLARED],
}


@pytest.mark.parametrize("dimension", sorted(CHAINS))
def test_degrading_one_dimension_along_its_chain_never_raises_the_verdict(dimension):
    chain = CHAINS[dimension]
    for prov, reach in itertools.product((P.P3, P.P2, P.P0), ((S.ABSENT, ReachBasis.K1), (S.INCOMPLETE, ReachBasis.K1))):
        verdicts = [_verdict(**{dimension: s}, prov_reach=prov, reach=reach[0], reach_basis=reach[1]) for s in chain]
        assert verdicts == sorted(verdicts, reverse=True), (dimension, prov, reach)


def test_degrading_reach_never_raises_the_verdict():
    chain = [(S.ABSENT, ReachBasis.K1, P.P3), (S.INCOMPLETE, ReachBasis.K1, P.P3), (S.INCOMPLETE, ReachBasis.NON_EXHAUSTIVE, P.P3),
             (S.UNKNOWN, None, None)]
    verdicts = [_verdict(reach=r, reach_basis=b, prov_reach=p) for r, b, p in chain]
    assert verdicts == [2, 1, 1, 0]
    assert _verdict(reach=S.PRESENT, reach_basis=None) == 0 and _verdict(reach=S.CONTRADICTORY, reach_basis=None) == 0


def test_m4_injecting_a_positive_observation_yields_insufficient_for_any_other_state():
    for locus, entry, prov in itertools.product(S, S, P):
        assert _verdict(reach=S.PRESENT, reach_basis=None, locus=locus, entry=entry, prov_reach=prov) == 0


# ---- determinism, immutability and input validation -----------------------------------------------------------------------------------------------------

def test_m3_the_same_inputs_give_the_same_result_and_hazard_order_does_not_matter():
    forward = baseline_hazards()
    backward = dict(reversed(list(baseline_hazards().items())))
    forward[HazardClass.REFLECTION] = backward[HazardClass.REFLECTION] = UNKNOWN_HAZARD
    first, second = evaluate_reach(inputs(hazards=forward)), evaluate_reach(inputs(hazards=backward))
    assert first.result == second.result and first.triggered == second.triggered
    assert evaluate_reach(inputs()) == evaluate_reach(inputs())


def test_the_inputs_are_not_mutated_and_the_hazard_mapping_is_read_only():
    original = baseline_hazards()
    snapshot = dict(original)
    reach_inputs = inputs(hazards=original)
    evaluate_reach(reach_inputs)
    assert original == snapshot
    with pytest.raises(TypeError):
        reach_inputs.hazards[HazardClass.REFLECTION] = UNKNOWN_HAZARD  # type: ignore[index]
    original[HazardClass.REFLECTION] = UNKNOWN_HAZARD  # later caller-side changes do not leak in
    assert reach_inputs.hazards[HazardClass.REFLECTION] == snapshot[HazardClass.REFLECTION]


@pytest.mark.parametrize("changes", [
    dict(reach=S.ABSENT, reach_basis=None),                                 # Absent only from K1
    dict(reach=S.ABSENT, reach_basis=ReachBasis.NON_EXHAUSTIVE),
    dict(reach=S.AMBIGUOUS, reach_basis=ReachBasis.NON_EXHAUSTIVE),
    dict(reach=S.INCOMPLETE, reach_basis=None),                             # needs a basis
    dict(reach=S.PRESENT, reach_basis=ReachBasis.NON_EXHAUSTIVE),           # non_exhaustive only gives Incomplete
    dict(reach=S.UNKNOWN, reach_basis=None, prov_reach=P.P3),               # PROV_REACH undefined for Unknown
    dict(prov_reach=None),                                                  # but required when REACH is defined
])
def test_inputs_that_section_5_1_cannot_produce_are_rejected_not_repaired(changes):
    with pytest.raises(ValueError):
        inputs(**changes)


@pytest.mark.parametrize("changes", [
    dict(reach="Absent"), dict(locus="Present"), dict(bind="matched"), dict(cfg="declared"), dict(prov_reach=3),
    dict(reach_basis="k1"), dict(only_k4_evidence=1), dict(hazards={"REFLECTION": modeled()}), dict(hazards=[modeled()]),
])
def test_wrong_types_are_rejected(changes):
    with pytest.raises(TypeError):
        inputs(**changes)


def test_evaluate_reach_refuses_a_non_inputs_object():
    with pytest.raises(TypeError):
        evaluate_reach(object())  # type: ignore[arg-type]
