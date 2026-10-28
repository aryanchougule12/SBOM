"""Tests for evidence.cnp_rules (Phase 1: the pure Req(component_not_present) engine).

NT1-NT21 are encoded from ``docs/formal_specification_v0.2.md`` section 4.7 at the
dimension level, exactly as the specification states them. The engine is a function of
already computed dimension states, so nothing here touches parsing, extraction, matching,
binding or provenance computation.
"""

import itertools
import re

import pytest

from evidence.cnp_rules import (
    CNP_RULES,
    BindState,
    CnpInputs,
    GenState,
    SeparateContentBasis,
    UnresolvedArtifactKindError,
    evaluate_cnp,
)
from model import ArtifactKind, EvidenceState as S, ProvenanceLevel as P
from reports.verdict import RationaleClass, Verdict

SOURCE, CONTAINER, BINARY, OTHER = (
    ArtifactKind.SOURCE, ArtifactKind.CONTAINER, ArtifactKind.BINARY, ArtifactKind.OTHER)
SUPPORTED, WEAK, INSUFFICIENT = Verdict.SUPPORTED, Verdict.WEAK, Verdict.INSUFFICIENT


def inputs(**overrides):
    """NT1 baseline: source artifact, everything established at P3."""
    base = dict(
        artifact_kind=SOURCE, inv=S.PRESENT, match=S.ABSENT, decl=S.PRESENT,
        bind=BindState.MATCHED, prov_sbom=P.P3, prov_decl=P.P3,
    )
    base.update(overrides)
    return CnpInputs(**base)


def basis(ep, meets=True):
    return SeparateContentBasis(ep=ep, meets_basis_criteria=meets)


# ---- the rule table, restated from section 4.2 -------------------------------------------------

SPEC_TABLE = {
    "N1": (INSUFFICIENT, "CONTRADICTORY_EVIDENCE", "CLAIM_CONTRADICTED_BY_INVENTORY"),
    "N2": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "NO_INVENTORY"),
    "N3": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "SCOPE_UNBOUND"),
    "N4": (INSUFFICIENT, "CONTRADICTORY_EVIDENCE", "INVENTORY_CONTRADICTION"),
    "N5": (INSUFFICIENT, "CANNOT_BE_ESTABLISHED", "NO_EVIDENTIAL_VALUE"),
    "N6": (WEAK, "BELOW_BAR", "DECLARED_INCOMPLETE"),
    "N7": (WEAK, "BELOW_BAR", "COMPLETENESS_UNDECLARED"),
    "N8": (WEAK, "BELOW_BAR", "AMBIGUOUS_IDENTITY"),
    "N9": (WEAK, "BELOW_BAR", "VARIANT_COVERAGE_INCOMPLETE"),
    "N10": (WEAK, "BELOW_BAR", "UNATTRIBUTED_DECLARATION"),
    "N11": (WEAK, "BELOW_BAR", "DECLARATION_BELOW_P3"),
    "N12": (WEAK, "BELOW_BAR", "INVENTORY_PROVENANCE_BELOW_P3"),
    "N13": (WEAK, "CONTRADICTORY_EVIDENCE", "PROVENANCE_INCONSISTENT"),
    "N14": (WEAK, "BELOW_BAR", "MANIFEST_ONLY_UNCORROBORATED"),
    "N15": (WEAK, "CANNOT_BE_ESTABLISHED", "GENERATION_METHOD_UNKNOWN"),
    "N16": (WEAK, "BELOW_BAR", "CORROBORATION_PROVENANCE_BELOW_P3"),
    "N17": (INSUFFICIENT, "CONTRADICTORY_EVIDENCE", "MATCH_CONTRADICTION"),
}


def test_the_rule_table_matches_section_4_2_exactly():
    assert [r.rule_id for r in CNP_RULES] == [f"N{n}" for n in range(1, 18)]
    for rule in CNP_RULES:
        assert (rule.ceiling, rule.rationale_class.value, rule.code) == SPEC_TABLE[rule.rule_id], rule.rule_id


# ---- NT1-NT21 (section 4.7) -----------------------------------------------------------------------------

NT_CASES = [
    ("NT1", dict(), SUPPORTED, []),
    ("NT2", dict(prov_sbom=P.P1, prov_decl=P.P1), WEAK, ["N11", "N12"]),
    ("NT3", dict(prov_sbom=P.P3, prov_decl=P.P1), WEAK, ["N11"]),
    ("NT4", dict(decl=S.INCOMPLETE), WEAK, ["N6"]),
    ("NT5", dict(match=S.AMBIGUOUS), WEAK, ["N8"]),
    ("NT6", dict(inv=S.CONTRADICTORY), INSUFFICIENT, ["N4"]),
    ("NT7", dict(decl=S.UNKNOWN, prov_sbom=P.P0, prov_decl=P.P0), INSUFFICIENT, ["N5", "N12"]),
    ("NT8-P1", dict(decl=S.UNKNOWN, prov_sbom=P.P1, prov_decl=P.P1), WEAK, ["N7", "N12"]),
    ("NT8-P2", dict(decl=S.UNKNOWN, prov_sbom=P.P2, prov_decl=P.P2), WEAK, ["N7", "N12"]),
    ("NT8-P3", dict(decl=S.UNKNOWN, prov_sbom=P.P3, prov_decl=P.P3), WEAK, ["N7"]),
    ("NT9", dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY), WEAK, ["N14"]),
    ("NT10", dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P3)), SUPPORTED, []),
    ("NT11", dict(artifact_kind=CONTAINER, gen=GenState.UNKNOWN), WEAK, ["N15"]),
    # NT12: the separate scan covers OS packages only, C is another ecosystem -> not a basis for C.
    ("NT12", dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P3, meets=False)), WEAK, ["N14"]),
    ("NT13-source", dict(match=S.PRESENT), INSUFFICIENT, ["N1"]),
    ("NT13-container-content-based", dict(artifact_kind=CONTAINER, gen=GenState.CONTENT_BASED, match=S.PRESENT), INSUFFICIENT, ["N1"]),
    ("NT14", dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P1)), WEAK, ["N16"]),
    ("NT15", dict(artifact_kind=CONTAINER, gen=GenState.CONTENT_BASED), SUPPORTED, []),
    ("NT16", dict(artifact_kind=CONTAINER, gen=GenState.UNKNOWN), WEAK, ["N15"]),
    # NT17: content-based method whose declared ecosystem excludes C.ecosystem -> GEN relative to C is unknown.
    ("NT17", dict(artifact_kind=CONTAINER, gen=GenState.UNKNOWN), WEAK, ["N15"]),
    ("NT18", dict(match=S.CONTRADICTORY), INSUFFICIENT, ["N17"]),
    ("NT19", dict(match=S.PRESENT), INSUFFICIENT, ["N1"]),
    ("NT20", dict(inv=S.CONTRADICTORY, match=S.ABSENT), INSUFFICIENT, ["N4"]),
    ("NT21", dict(inv=S.CONTRADICTORY, match=S.CONTRADICTORY), INSUFFICIENT, ["N4", "N17"]),
]


@pytest.mark.parametrize("case_id, overrides, verdict, rule_ids", NT_CASES, ids=[c[0] for c in NT_CASES])
def test_section_4_7_cases(case_id, overrides, verdict, rule_ids):
    evaluation = evaluate_cnp(inputs(**overrides))
    assert evaluation.result.verdict is verdict
    assert list(evaluation.rule_ids) == rule_ids  # the triggered rules, in output order
    assert evaluation.result.codes == tuple(SPEC_TABLE[r][2] for r in rule_ids)
    assert evaluation.supported_conditions_hold is (verdict is SUPPORTED)
    if verdict is SUPPORTED:
        assert evaluation.result.rationale == "" and evaluation.unmet_supported_conditions == ()


def test_all_applicable_codes_are_preserved_not_only_the_first():
    # NT13 says "any" GEN: a manifest-only container with a found component keeps both codes.
    evaluation = evaluate_cnp(inputs(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, match=S.PRESENT))
    assert list(evaluation.rule_ids) == ["N1", "N14"]
    assert evaluation.result.verdict is INSUFFICIENT  # the minimum ceiling


# ---- every rule on its own, with the other inputs at the NT1 baseline ------------------------------------------

SINGLE_RULE_CASES = [
    ("N1", dict(match=S.PRESENT), ["N1"]),
    ("N2-unknown", dict(inv=S.UNKNOWN), ["N2"]),
    ("N2-missing", dict(inv=None), ["N2"]),
    ("N3-unknown", dict(bind=BindState.UNKNOWN), ["N3"]),
    ("N3-mismatched", dict(bind=BindState.MISMATCHED), ["N3"]),
    ("N4", dict(inv=S.CONTRADICTORY), ["N4"]),
    ("N5", dict(decl=S.UNKNOWN, prov_sbom=P.P0), ["N5", "N12"]),  # P0 is also below P3
    ("N6", dict(decl=S.INCOMPLETE), ["N6"]),
    ("N7", dict(decl=S.UNKNOWN, prov_sbom=P.P1), ["N7", "N12"]),
    ("N8", dict(match=S.AMBIGUOUS), ["N8"]),
    ("N9", dict(match=S.INCOMPLETE), ["N9"]),
    ("N10", dict(prov_decl=P.P0), ["N10"]),
    ("N11-P1", dict(prov_decl=P.P1), ["N11"]),
    ("N11-P2", dict(prov_decl=P.P2), ["N11"]),
    ("N12-P2", dict(prov_sbom=P.P2), ["N12"]),
    ("N13", dict(provenance_metadata_contradiction=True), ["N13"]),
    ("N14", dict(artifact_kind=BINARY, gen=GenState.MANIFEST_ONLY), ["N14"]),
    ("N15", dict(artifact_kind=BINARY, gen=GenState.UNKNOWN), ["N15"]),
    ("N16", dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P2)), ["N16"]),
    ("N17", dict(match=S.CONTRADICTORY), ["N17"]),
]


@pytest.mark.parametrize("case_id, overrides, rule_ids", SINGLE_RULE_CASES, ids=[c[0] for c in SINGLE_RULE_CASES])
def test_each_rule_triggers_with_its_table_ceiling_class_and_code(case_id, overrides, rule_ids):
    evaluation = evaluate_cnp(inputs(**overrides))
    assert list(evaluation.rule_ids) == rule_ids
    for rule in evaluation.triggered:
        ceiling, rationale_class, code = SPEC_TABLE[rule.rule_id]
        assert (rule.ceiling, rule.rationale_class.value, rule.code) == (ceiling, rationale_class, code)
    expected_verdict = min((SPEC_TABLE[r][0] for r in rule_ids), key=[INSUFFICIENT, WEAK, SUPPORTED].index)
    assert evaluation.result.verdict is expected_verdict


def test_all_seventeen_rules_are_exercised_by_the_cases_above():
    exercised = {rid for _, _, ids in SINGLE_RULE_CASES for rid in ids}
    assert exercised == set(SPEC_TABLE)


# ---- section 3 ordering and grammar ---------------------------------------------------------------------------

def test_codes_are_ordered_by_class_then_numeric_suffix_not_lexicographically():
    # N4, N13 and N17 are all CONTRADICTORY; N13 sorts before N4 lexicographically.
    evaluation = evaluate_cnp(inputs(inv=S.CONTRADICTORY, match=S.CONTRADICTORY, provenance_metadata_contradiction=True))
    assert list(evaluation.rule_ids) == ["N4", "N13", "N17"]


def test_class_rank_is_contradictory_then_cannot_then_below():
    evaluation = evaluate_cnp(
        inputs(inv=S.UNKNOWN, match=S.PRESENT, prov_sbom=P.P2, bind=BindState.UNKNOWN, provenance_metadata_contradiction=True)
    )
    # N1, N13 (CONTRADICTORY); N2, N3 (CANNOT); N12 (BELOW)
    assert list(evaluation.rule_ids) == ["N1", "N13", "N2", "N3", "N12"]


def test_rationale_follows_the_grammar_one_segment_per_class_in_rank_order():
    evaluation = evaluate_cnp(inputs(decl=S.UNKNOWN, prov_sbom=P.P0, prov_decl=P.P0))  # NT7
    segments = evaluation.result.rationale.split(" | ")
    assert len(segments) == 2
    for segment in segments:
        assert re.fullmatch(r"(CONTRADICTORY_EVIDENCE|CANNOT_BE_ESTABLISHED|BELOW_BAR)\[[A-Z0-9_,]+\]: .+", segment)
    assert segments[0].startswith("CANNOT_BE_ESTABLISHED[NO_EVIDENTIAL_VALUE]: ")
    assert segments[1].startswith("BELOW_BAR[INVENTORY_PROVENANCE_BELOW_P3]: ")
    assert evaluation.result.codes == ("NO_EVIDENTIAL_VALUE", "INVENTORY_PROVENANCE_BELOW_P3")


# ---- the no-rule default ---------------------------------------------------------------------------------------

def test_no_rule_default_is_insufficient_with_an_empty_code_list():
    evaluation = evaluate_cnp(inputs(match=S.UNKNOWN))  # no rule addresses MATCH Unknown
    assert evaluation.triggered == () and evaluation.result.codes == ()
    assert evaluation.result.verdict is INSUFFICIENT
    assert evaluation.result.rationale.startswith(f"{RationaleClass.NO_RULE_APPLIES.value}[]: ")
    assert evaluation.unmet_supported_conditions == ("MATCH Absent over all variants",)
    assert evaluation.uncovered_states == ("MATCH=Unknown",)


def test_no_rule_applies_never_co_occurs_with_a_triggered_rule_code():
    for overrides in (dict(match=S.PRESENT), dict(decl=S.INCOMPLETE), dict(prov_sbom=P.P2)):
        evaluation = evaluate_cnp(inputs(**overrides))
        assert "NO_RULE_APPLIES" not in evaluation.result.rationale


def test_states_no_rule_addresses_fall_to_the_default_and_are_reported():
    cases = [
        (dict(inv=S.ABSENT), "INV=Absent"),
        (dict(inv=S.INCOMPLETE), "INV=Incomplete"),
        (dict(inv=S.AMBIGUOUS), "INV=Ambiguous"),
        (dict(decl=S.ABSENT), "DECL=Absent"),
        (dict(decl=S.AMBIGUOUS), "DECL=Ambiguous"),
        (dict(decl=S.CONTRADICTORY), "DECL=Contradictory"),
    ]
    for overrides, label in cases:
        evaluation = evaluate_cnp(inputs(**overrides))
        assert evaluation.triggered == (), label
        assert evaluation.result.verdict is INSUFFICIENT and evaluation.result.codes == (), label
        assert evaluation.uncovered_states == (label,), label


def test_inv_absent_is_not_read_as_missing():
    assert evaluate_cnp(inputs(inv=S.ABSENT)).rule_ids == ()  # N2 reads only Unknown or missing
    assert evaluate_cnp(inputs(inv=None)).rule_ids == ("N2",)


def test_literal_step_4_lets_another_weak_rule_govern_an_uncovered_state():
    # MATCH Unknown is addressed by no rule. With PROV_SBOM at P2, N12 (Weak) triggers, and the
    # literal Step 4 ("minimum ceiling over all triggered rules") yields Weak, although the
    # section 3 definition of Insufficient ("a required dimension is ... Unknown") points the
    # other way. The engine follows the procedure and reports the uncovered state; the
    # tension itself is not resolved here.
    evaluation = evaluate_cnp(inputs(match=S.UNKNOWN, prov_sbom=P.P2))
    assert list(evaluation.rule_ids) == ["N12"]
    assert evaluation.result.verdict is WEAK
    assert evaluation.uncovered_states == ("MATCH=Unknown",)


# ---- BIND keeps its three distinct states ---------------------------------------------------------------------------

def test_bind_mismatched_and_unknown_have_the_same_outcome_but_stay_distinct():
    mismatched = evaluate_cnp(inputs(bind=BindState.MISMATCHED))
    unknown = evaluate_cnp(inputs(bind=BindState.UNKNOWN))
    matched = evaluate_cnp(inputs(bind=BindState.MATCHED))
    assert mismatched.result.codes == unknown.result.codes == ("SCOPE_UNBOUND",)
    assert mismatched.result.verdict is unknown.result.verdict is INSUFFICIENT
    assert mismatched.inputs.bind is BindState.MISMATCHED and unknown.inputs.bind is BindState.UNKNOWN
    assert "mismatched" in mismatched.result.rationale and "unknown" in unknown.result.rationale
    assert "mismatched" not in unknown.result.rationale
    assert matched.result.verdict is SUPPORTED
    assert {b.value for b in BindState} == {"matched", "mismatched", "unknown"}


# ---- manifest-only boundaries (N14/N15/N16, section 4.3) -----------------------------------------------------------------

def test_n14_n15_apply_only_to_binary_and_container_artifacts():
    for kind in (SOURCE, OTHER):
        for gen in (GenState.MANIFEST_ONLY, GenState.UNKNOWN):
            assert evaluate_cnp(inputs(artifact_kind=kind, gen=gen)).result.verdict is SUPPORTED
    for kind in (BINARY, CONTAINER):
        assert evaluate_cnp(inputs(artifact_kind=kind, gen=GenState.MANIFEST_ONLY)).rule_ids == ("N14",)
        assert evaluate_cnp(inputs(artifact_kind=kind, gen=GenState.UNKNOWN)).rule_ids == ("N15",)


def test_a_separate_basis_removes_n14_and_n15_and_n16_depends_on_its_ep():
    for gen, removed in ((GenState.MANIFEST_ONLY, "N14"), (GenState.UNKNOWN, "N15")):
        base = dict(artifact_kind=CONTAINER, gen=gen)
        assert evaluate_cnp(inputs(**base)).rule_ids == (removed,)
        assert evaluate_cnp(inputs(**base, separate_basis=basis(P.P3))).result.verdict is SUPPORTED
        for ep in (P.P1, P.P2):
            assert evaluate_cnp(inputs(**base, separate_basis=basis(ep))).rule_ids == ("N16",)


def test_a_separate_document_below_p1_or_failing_the_criteria_is_not_a_basis():
    base = dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY)
    assert evaluate_cnp(inputs(**base, separate_basis=basis(P.P0))).rule_ids == ("N14",)  # EP(d) >= P1 is required
    assert evaluate_cnp(inputs(**base, separate_basis=basis(P.P3, meets=False))).rule_ids == ("N14",)
    assert not basis(P.P0).qualifies and not basis(P.P3, meets=False).qualifies
    assert basis(P.P1).qualifies


def test_n16_does_not_apply_when_the_primary_sbom_is_itself_the_basis():
    evaluation = evaluate_cnp(inputs(artifact_kind=CONTAINER, gen=GenState.CONTENT_BASED, separate_basis=basis(P.P1)))
    assert evaluation.result.verdict is SUPPORTED and evaluation.rule_ids == ()


def test_n16_needs_the_separate_basis_to_be_relied_upon():
    # Source artifact: N14/N15 cannot fire, so nothing is relied upon and N16 cannot fire.
    assert evaluate_cnp(inputs(artifact_kind=SOURCE, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P1))).rule_ids == ()


# ---- section 4.4: every Supported condition is necessary ------------------------------------------------------------------

@pytest.mark.parametrize(
    "overrides, unmet",
    [
        (dict(inv=S.UNKNOWN), "INV Present as a full list"),
        (dict(match=S.UNKNOWN), "MATCH Absent over all variants"),
        (dict(decl=S.INCOMPLETE), "DECL Present (complete)"),
        (dict(bind=BindState.UNKNOWN), "BIND Present"),
        (dict(prov_sbom=P.P2), "PROV_SBOM = P3"),
        (dict(prov_decl=P.P2), "PROV_DECL = P3"),
        (dict(artifact_kind=CONTAINER, gen=GenState.UNKNOWN), "content-based basis exists (binary or container artifact)"),
        (dict(artifact_kind=CONTAINER, gen=GenState.MANIFEST_ONLY, separate_basis=basis(P.P2)), "separate corroborating basis has EP = P3"),
    ],
)
def test_each_supported_condition_failing_prevents_supported(overrides, unmet):
    evaluation = evaluate_cnp(inputs(**overrides))
    assert unmet in evaluation.unmet_supported_conditions
    assert evaluation.result.verdict is not SUPPORTED and not evaluation.supported_conditions_hold


def test_a_triggered_rule_prevents_supported_even_when_the_conditions_hold():
    evaluation = evaluate_cnp(inputs(provenance_metadata_contradiction=True))  # N13
    assert evaluation.supported_conditions_hold is True
    assert evaluation.rule_ids == ("N13",) and evaluation.result.verdict is WEAK


# ---- unresolved G10 branch and input validation ----------------------------------------------------------------------------

def test_artifact_kind_unknown_is_refused_not_guessed():
    with pytest.raises(UnresolvedArtifactKindError):
        evaluate_cnp(inputs(artifact_kind=ArtifactKind.UNKNOWN))
    assert issubclass(UnresolvedArtifactKindError, ValueError)


def test_prov_decl_is_required_exactly_when_decl_is_present():
    with pytest.raises(ValueError):
        inputs(prov_decl=None)  # decl is Present
    assert evaluate_cnp(inputs(decl=S.UNKNOWN, prov_decl=None)).rule_ids == ("N7",)  # not needed


@pytest.mark.parametrize(
    "overrides",
    [dict(match="Absent"), dict(inv="Present"), dict(bind="matched"), dict(prov_sbom=3), dict(gen="unknown"),
     dict(artifact_kind="source"), dict(separate_basis=P.P3), dict(provenance_metadata_contradiction=1)],
)
def test_wrongly_typed_inputs_are_rejected(overrides):
    with pytest.raises(TypeError):
        inputs(**overrides)


# ---- properties over the whole input grid ---------------------------------------------------------------------------------------

def _grid():
    inv_values = [None] + list(S)
    for inv, match, decl, bind, prov in itertools.product(inv_values, list(S), list(S), list(BindState), list(P)):
        decl_prov = list(P) if decl is S.PRESENT else [None]
        for prov_decl in decl_prov:
            yield inputs(inv=inv, match=match, decl=decl, bind=bind, prov_sbom=prov, prov_decl=prov_decl)


def test_invariants_hold_over_the_whole_source_artifact_grid():
    ceilings = {Verdict.INSUFFICIENT: 0, Verdict.WEAK: 1, Verdict.SUPPORTED: 2}
    count = 0
    for case in _grid():
        evaluation = evaluate_cnp(case)
        result = evaluation.result
        count += 1
        if evaluation.triggered:
            # verdict = minimum ceiling; every triggered code is output; no NO_RULE_APPLIES
            assert result.verdict is min((r.ceiling for r in evaluation.triggered), key=ceilings.get)
            assert result.codes == tuple(r.code for r in evaluation.triggered)
            assert "NO_RULE_APPLIES" not in result.rationale
        elif evaluation.supported_conditions_hold:
            assert result.verdict is SUPPORTED and result.rationale == "" and result.codes == ()
        else:
            assert result.verdict is INSUFFICIENT and result.codes == ()
            assert result.rationale.startswith("NO_RULE_APPLIES[]: ")
        if result.verdict is SUPPORTED:  # Supported only when nothing triggered and every condition holds
            assert not evaluation.triggered and not evaluation.unmet_supported_conditions
        # output order: class rank, then numeric suffix
        ranks = {"CONTRADICTORY_EVIDENCE": 0, "CANNOT_BE_ESTABLISHED": 1, "BELOW_BAR": 2}
        keys = [(ranks[r.rationale_class.value], int(r.rule_id[1:])) for r in evaluation.triggered]
        assert keys == sorted(keys)
        assert evaluation == evaluate_cnp(case)  # deterministic
    # 7 INV values (six states or missing) x 6 MATCH x 3 BIND x 4 PROV_SBOM x (5 non-Present DECL
    # states + Present with 4 PROV_DECL values).
    assert count == 7 * 6 * 3 * 4 * (5 + 4)


def test_only_nt1_style_inputs_reach_supported_on_a_source_artifact():
    supported = [c for c in _grid() if evaluate_cnp(c).result.verdict is SUPPORTED]
    assert supported
    for case in supported:
        assert (case.inv, case.match, case.decl, case.bind, case.prov_sbom, case.prov_decl) == (
            S.PRESENT, S.ABSENT, S.PRESENT, BindState.MATCHED, P.P3, P.P3)
