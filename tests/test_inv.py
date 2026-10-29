"""Tests for evidence.inv (isolated INV state derivation).

INV is derived only from the validated profile, a BIND result and an explicit inventory
assessment. Nothing here parses a document, runs a structural classifier or evaluates a
predicate.
"""

import copy
import dataclasses
import itertools

import pytest

from evidence import inv as I
from evidence.bind import BindBasis, BindCode, BindEvaluation
from evidence.cnp_rules import BindState
from evidence.inv import (
    AssertionStatus,
    CheckOutcome,
    Emptiness,
    Interpretability,
    InvCode as C,
    InvDerivation,
    InventoryAssessment,
    Relevance,
    StructuralCheck,
    derive_inv,
)
from evidence.profile import parse_profile
from model import EvidenceState as S

SCOPE = {"product_id": "pkg:generic/app@1.0", "version": "1.0", "artifact_kind": "container"}
DOC = "sbom"  # the profile's single primary document id
MATCHED = BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH, document_id=DOC)
MATCHED_PV = BindEvaluation(BindState.MATCHED, BindBasis.PRODUCT_VERSION, BindCode.PRODUCT_VERSION_MATCH, document_id=DOC)
MISMATCHED = BindEvaluation(BindState.MISMATCHED, BindBasis.DIGEST, BindCode.DIGEST_MISMATCH, document_id=DOC)
UNKNOWN = BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=DOC)


def assertion(**changes):
    entry = {"document": "sbom", "scope": dict(SCOPE), "statement": "full_component_list", "entered_by": "alice"}
    entry.update(changes)
    return entry


def profile(*assertions):
    return parse_profile({
        "schema_version": "1", "profile_id": "p", "scope": dict(SCOPE),
        "documents": [{"doc_id": "sbom", "role": "primary_sbom"}],
        "inv_assertions": list(assertions),
    })


USABLE = profile(assertion())
NO_ASSERTION = profile()


def passed(check_id="refs", required=True):
    return StructuralCheck(check_id, required, CheckOutcome.PASSED)


def defect(check_id="refs", *, relevant=False, required=True, detail=""):
    return StructuralCheck(check_id, required, CheckOutcome.CONTRADICTION_FOUND,
                           Relevance.RELEVANT_TO_S if relevant else Relevance.UNDETERMINED, detail)


def not_performed(check_id="refs", required=True):
    return StructuralCheck(check_id, required, CheckOutcome.NOT_PERFORMED)


def assessment(*checks, interp=Interpretability.INTERPRETABLE, empty=Emptiness.NON_EMPTY, notes=(), document_id=DOC):
    return InventoryAssessment(interp, empty, tuple(checks), tuple(notes), document_id)


GOOD = assessment(passed())


# ---- Present requires every approved prerequisite ------------------------------------------------------------

def test_present_when_every_prerequisite_holds():
    result = derive_inv(USABLE, MATCHED, GOOD)
    assert (result.state, result.reason, result.reasons) == (S.PRESENT, C.PRESENT, (C.PRESENT,))
    assert result.assertion is AssertionStatus.USABLE and result.contradictions == ()
    assert derive_inv(USABLE, MATCHED_PV, GOOD).state is S.PRESENT  # the BIND basis does not matter here


@pytest.mark.parametrize(
    "label,args,reason",
    [
        ("bind unknown", (USABLE, UNKNOWN, GOOD), C.BIND_UNKNOWN),
        ("bind mismatched", (USABLE, MISMATCHED, GOOD), C.BIND_MISMATCHED),
        ("no assertion", (NO_ASSERTION, MATCHED, GOOD), C.ASSERTION_MISSING),
        ("no assessment", (USABLE, MATCHED, None), C.ASSESSMENT_MISSING),
        ("no checks at all", (USABLE, MATCHED, assessment()), C.NO_REQUIRED_CHECKS),
        ("only optional checks", (USABLE, MATCHED, assessment(passed(required=False))), C.NO_REQUIRED_CHECKS),
        ("required check not performed", (USABLE, MATCHED, assessment(not_performed())), C.REQUIRED_CHECK_NOT_PERFORMED),
        ("uninterpretable", (USABLE, MATCHED, assessment(passed(), interp=Interpretability.UNINTERPRETABLE)),
         C.INVENTORY_UNINTERPRETABLE),
        ("interpretability not assessed", (USABLE, MATCHED, assessment(passed(), interp=Interpretability.NOT_ASSESSED)),
         C.INTERPRETABILITY_NOT_ASSESSED),
        ("empty inventory", (USABLE, MATCHED, assessment(passed(), empty=Emptiness.EMPTY)), C.INVENTORY_EMPTY),
        ("emptiness not assessed", (USABLE, MATCHED, assessment(passed(), empty=Emptiness.NOT_ASSESSED)),
         C.EMPTINESS_NOT_ASSESSED),
        ("found defect, relevance undetermined", (USABLE, MATCHED, assessment(passed("a"), defect("b"))),
         C.DEFECT_RELEVANCE_UNDETERMINED),
    ],
)
def test_each_missing_prerequisite_prevents_present(label, args, reason):
    result = derive_inv(*args)
    assert result.state is S.UNKNOWN, label
    assert result.reason is reason and reason in result.reasons, label


def test_default_assessment_never_means_present():
    assert derive_inv(USABLE, MATCHED, InventoryAssessment(document_id=DOC)).state is S.UNKNOWN
    result = derive_inv(USABLE, MATCHED, InventoryAssessment(document_id=DOC))
    assert {C.NO_REQUIRED_CHECKS, C.INTERPRETABILITY_NOT_ASSESSED, C.EMPTINESS_NOT_ASSESSED} <= set(result.reasons)


def test_every_unmet_prerequisite_is_listed_in_code_order():
    result = derive_inv(NO_ASSERTION, UNKNOWN, assessment(not_performed(), interp=Interpretability.UNINTERPRETABLE,
                                                         empty=Emptiness.EMPTY))
    assert result.reasons == (C.BIND_UNKNOWN, C.ASSERTION_MISSING, C.REQUIRED_CHECK_NOT_PERFORMED,
                              C.INVENTORY_UNINTERPRETABLE, C.INVENTORY_EMPTY)
    assert result.reason is C.BIND_UNKNOWN


# ---- BIND ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bind", [UNKNOWN, MISMATCHED])
def test_usable_assertion_with_unbound_document_never_produces_present(bind):
    result = derive_inv(USABLE, bind, GOOD)
    assert result.state is S.UNKNOWN and result.assertion is AssertionStatus.USABLE
    assert result.bind_state is bind.state


@pytest.mark.parametrize("bind", [UNKNOWN, MISMATCHED])
def test_a_defect_in_an_unbound_document_is_a_diagnostic_not_a_contradiction(bind):
    result = derive_inv(USABLE, bind, assessment(passed("a"), defect("b", relevant=True, detail="dangling x")))
    assert result.state is S.UNKNOWN and result.contradictions == ()
    [diagnostic] = [d for d in result.diagnostics if d.code is C.UNBOUND_DOCUMENT_DEFECT]
    assert "b:" in diagnostic.detail and "dangling x" in diagnostic.detail and bind.state.value in diagnostic.detail
    assert C.STRUCTURAL_CONTRADICTION not in result.reasons


def test_bind_matched_is_required_for_contradictory_too():
    for bind in (UNKNOWN, MISMATCHED):
        assert derive_inv(NO_ASSERTION, bind, assessment(defect(relevant=True))).state is S.UNKNOWN


# ---- contradiction ---------------------------------------------------------------------------------------------------

def test_established_relevant_contradiction_takes_precedence_over_the_assertion():
    result = derive_inv(USABLE, MATCHED, assessment(passed("a"), defect("b", relevant=True)))
    assert (result.state, result.reason) == (S.CONTRADICTORY, C.STRUCTURAL_CONTRADICTION)
    assert result.contradictions == ("b",) and result.assertion is AssertionStatus.USABLE


def test_contradiction_does_not_need_an_assertion_or_a_complete_assessment():
    result = derive_inv(NO_ASSERTION, MATCHED, assessment(defect(relevant=True), interp=Interpretability.NOT_ASSESSED,
                                                         empty=Emptiness.EMPTY))
    assert result.state is S.CONTRADICTORY
    assert derive_inv(USABLE, MATCHED, assessment(defect(relevant=True, required=False))).state is S.CONTRADICTORY


def test_all_relevant_contradictions_are_reported_sorted():
    result = derive_inv(USABLE, MATCHED, assessment(defect("z", relevant=True), defect("a", relevant=True), passed("m")))
    assert result.contradictions == ("a", "z")


def test_unestablished_relevance_is_neither_contradictory_nor_ignored():
    result = derive_inv(USABLE, MATCHED, assessment(passed("a"), defect("b")))
    assert result.state is S.UNKNOWN and result.contradictions == ()
    assert result.reason is C.DEFECT_RELEVANCE_UNDETERMINED


def test_only_a_found_contradiction_can_be_relevant():
    for outcome in (CheckOutcome.PASSED, CheckOutcome.NOT_PERFORMED):
        with pytest.raises(ValueError):
            StructuralCheck("c", True, outcome, Relevance.RELEVANT_TO_S)


# ---- unperformed checks ------------------------------------------------------------------------------------------------

def test_an_unperformed_required_check_is_never_a_pass():
    result = derive_inv(USABLE, MATCHED, assessment(passed("a"), not_performed("b")))
    assert result.state is S.UNKNOWN and result.reason is C.REQUIRED_CHECK_NOT_PERFORMED
    assert [d.detail for d in result.diagnostics if d.code is C.REQUIRED_CHECK_NOT_PERFORMED] == [
        "b: required check was not performed"]


def test_an_unperformed_optional_check_does_not_block_but_is_not_a_pass_either():
    assert derive_inv(USABLE, MATCHED, assessment(passed("a"), not_performed("b", required=False))).state is S.PRESENT
    # ... and it cannot supply the required check that is otherwise missing
    assert derive_inv(USABLE, MATCHED, assessment(not_performed("b", required=False))).reason is C.NO_REQUIRED_CHECKS


def test_a_passed_optional_check_does_not_stand_in_for_a_required_one():
    assert derive_inv(USABLE, MATCHED, assessment(passed("a", required=False), not_performed("b"))).state is S.UNKNOWN


def test_a_contradiction_found_by_an_optional_check_still_blocks_present():
    assert derive_inv(USABLE, MATCHED, assessment(passed("a"), defect("b", required=False))).state is S.UNKNOWN


# ---- assertions ------------------------------------------------------------------------------------------------------------

def test_unsupported_statement_never_produces_present():
    result = derive_inv(profile(assertion(statement="complete_transitively")), MATCHED, GOOD)
    assert result.state is S.UNKNOWN and result.assertion is AssertionStatus.UNUSABLE
    assert result.reason is C.ASSERTION_UNUSABLE
    assert [d.code.value for d in result.assertion_diagnostics] == ["INV_ASSERTION_STATEMENT_UNSUPPORTED"]


def test_conflicting_assertions_never_produce_present():
    result = derive_inv(profile(assertion(), assertion(statement="partial_component_list")), MATCHED, GOOD)
    assert result.state is S.UNKNOWN and result.assertion is AssertionStatus.UNUSABLE
    assert {d.code.value for d in result.assertion_diagnostics} == {
        "INV_ASSERTION_CONFLICTING", "INV_ASSERTION_STATEMENT_UNSUPPORTED"}


def test_scope_mismatching_or_unsupplied_document_assertions_never_produce_present():
    other_scope = dict(SCOPE, version="9.9")
    for entry in (assertion(scope=other_scope), assertion(document="elsewhere")):
        result = derive_inv(profile(entry), MATCHED, GOOD)
        assert result.state is S.UNKNOWN and result.assertion is AssertionStatus.UNUSABLE
        assert result.assertion_diagnostics  # retained


def test_identical_duplicate_assertions_are_one_usable_assertion():
    result = derive_inv(profile(assertion(), assertion(entered_by="bob")), MATCHED, GOOD)
    assert result.state is S.PRESENT
    assert [d.code.value for d in result.assertion_diagnostics] == ["INV_ASSERTION_DUPLICATE_IDENTICAL"]


def test_a_missing_assertion_is_distinguished_from_an_unusable_one():
    assert derive_inv(NO_ASSERTION, MATCHED, GOOD).assertion is AssertionStatus.MISSING
    assert derive_inv(profile(assertion(statement="x")), MATCHED, GOOD).assertion is AssertionStatus.UNUSABLE


def test_the_assertion_alone_sets_nothing():
    # a usable assertion with every other input absent or negative derives no state beyond Unknown
    assert derive_inv(USABLE, UNKNOWN, None).state is S.UNKNOWN
    assert derive_inv(USABLE, MATCHED, None).state is S.UNKNOWN


# ---- inventory ---------------------------------------------------------------------------------------------------------------------

def test_empty_or_uninterpretable_inventory_never_becomes_present_even_with_a_pass():
    for kwargs in ({"empty": Emptiness.EMPTY}, {"interp": Interpretability.UNINTERPRETABLE},
                   {"empty": Emptiness.EMPTY, "interp": Interpretability.UNINTERPRETABLE}):
        assert derive_inv(USABLE, MATCHED, assessment(passed(), **kwargs)).state is S.UNKNOWN


def test_empty_inventory_is_not_given_a_state_of_its_own():
    # G11 Q2 and G18 are open: an empty list is Unknown here, never Absent or Incomplete.
    result = derive_inv(USABLE, MATCHED, assessment(passed(), empty=Emptiness.EMPTY))
    assert result.state is S.UNKNOWN and result.reasons == (C.INVENTORY_EMPTY,)


def test_notes_such_as_duplicate_identifiers_never_change_the_state():
    notes = ("duplicate identifier 'lib-a' (C3)", "something else")
    present = derive_inv(USABLE, MATCHED, assessment(passed(), notes=notes))
    assert present.state is S.PRESENT
    assert [d.detail for d in present.diagnostics if d.code is C.INVENTORY_NOTE] == sorted(notes)
    assert derive_inv(USABLE, UNKNOWN, assessment(passed(), notes=notes)).state is S.UNKNOWN


# ---- document identity ---------------------------------------------------------------------------------------------------------------------

def test_matching_primary_document_ids_allow_normal_derivation():
    result = derive_inv(USABLE, MATCHED, GOOD)
    assert result.state is S.PRESENT and result.identity_verified and result.document_id == DOC
    contradictory = derive_inv(USABLE, MATCHED, assessment(defect(relevant=True)))
    assert contradictory.state is S.CONTRADICTORY and contradictory.identity_verified


def test_bind_result_from_a_different_document_cannot_produce_present():
    foreign = dataclasses.replace(MATCHED, document_id="other")
    result = derive_inv(USABLE, foreign, GOOD)
    assert result.state is S.UNKNOWN and not result.identity_verified
    assert result.reasons == (C.BIND_DOCUMENT_MISMATCH,)
    assert "'other'" in next(d.detail for d in result.diagnostics if d.code is C.BIND_DOCUMENT_MISMATCH)


def test_assessment_from_a_different_document_cannot_produce_present_and_is_ignored():
    result = derive_inv(USABLE, MATCHED, assessment(passed(), notes=("a note",), document_id="other"))
    assert result.state is S.UNKNOWN and not result.identity_verified
    assert result.reasons == (C.ASSESSMENT_DOCUMENT_MISMATCH,)  # nothing else is read from it
    assert not [d for d in result.diagnostics if d.code is C.INVENTORY_NOTE]


def test_missing_document_identity_cannot_produce_present():
    unidentified = dataclasses.replace(MATCHED, document_id=None)
    result = derive_inv(USABLE, unidentified, GOOD)
    assert (result.state, result.reasons) == (S.UNKNOWN, (C.BIND_DOCUMENT_MISSING,))
    result = derive_inv(USABLE, MATCHED, assessment(passed(), document_id=None))
    assert (result.state, result.reasons) == (S.UNKNOWN, (C.ASSESSMENT_DOCUMENT_MISSING,))
    result = derive_inv(USABLE, unidentified, assessment(passed(), document_id=None))
    assert result.reasons == (C.BIND_DOCUMENT_MISSING, C.ASSESSMENT_DOCUMENT_MISSING)


@pytest.mark.parametrize("wrong", ["SBOM", " sbom", "sbom ", "sbom2", "#/metadata/component", "app-1"])
def test_identity_is_exact_and_not_a_subject_reference_or_locator(wrong):
    bind = BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH, subject_ref=DOC,
                          subject_locator="#/metadata/component", document_id=wrong)
    assert derive_inv(USABLE, bind, GOOD).state is S.UNKNOWN
    assert derive_inv(USABLE, MATCHED, assessment(passed(), document_id=wrong)).state is S.UNKNOWN
    # a subject ref equal to the document id is not an identity either
    nameless = BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH, subject_ref=DOC)
    assert derive_inv(USABLE, nameless, GOOD).reasons == (C.BIND_DOCUMENT_MISSING,)


def test_a_relevant_contradiction_is_not_attributed_to_the_wrong_document():
    foreign_assessment = assessment(defect("b", relevant=True, detail="dangling x"), document_id="other")
    result = derive_inv(USABLE, MATCHED, foreign_assessment)
    assert result.state is S.UNKNOWN and result.contradictions == ()
    [diagnostic] = [d for d in result.diagnostics if d.code is C.FOREIGN_DOCUMENT_DEFECT]
    assert "b:" in diagnostic.detail and "'other'" in diagnostic.detail
    # the same defect from the right document, with a BIND result for another one, is only an unbound defect
    foreign_bind = dataclasses.replace(MATCHED, document_id="other")
    result = derive_inv(USABLE, foreign_bind, assessment(defect("b", relevant=True)))
    assert result.state is S.UNKNOWN and result.contradictions == ()
    assert [d.code for d in result.diagnostics if d.code is C.UNBOUND_DOCUMENT_DEFECT] == [C.UNBOUND_DOCUMENT_DEFECT]
    assert "does not identify the primary document" in next(
        d.detail for d in result.diagnostics if d.code is C.UNBOUND_DOCUMENT_DEFECT)
    # an unidentified assessment is treated the same way
    result = derive_inv(USABLE, MATCHED, assessment(defect("b", relevant=True), document_id=None))
    assert result.state is S.UNKNOWN and result.contradictions == ()


def test_a_foreign_assessment_cannot_hide_behind_or_replace_the_right_one():
    # Only one assessment is accepted; the wrong one never combines with the right BIND result into Present.
    for assess in (assessment(passed(), document_id="other"), assessment(passed(), document_id=None), None):
        assert derive_inv(USABLE, MATCHED, assess).state is S.UNKNOWN


def test_identity_check_works_end_to_end_with_a_real_bind_result():
    from pathlib import Path

    from evidence.bind import evaluate_bind_for_profile
    from evidence.stage1_records import load_cyclonedx

    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "cyclonedx" / "complete_composition.json"
    record = load_cyclonedx(fixture)
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    scope = dict(SCOPE, product_id="pkg:generic/app@2.0.0", version="2.0.0", artifact_digests=[f"sha256:{sha}"])
    data = {
        "schema_version": "1", "profile_id": "p", "scope": scope,
        "documents": [{"doc_id": record.doc_id, "role": "primary_sbom"}],
        "inv_assertions": [{"document": record.doc_id, "scope": dict(scope), "statement": "full_component_list",
                            "entered_by": "alice"}],
    }
    prof = parse_profile(data)
    bind = evaluate_bind_for_profile(prof, [record])
    assert bind.state is BindState.MATCHED and bind.document_id == record.doc_id
    good = InventoryAssessment(Interpretability.INTERPRETABLE, Emptiness.NON_EMPTY, (passed(),), (), record.doc_id)
    assert derive_inv(prof, bind, good).state is S.PRESENT
    assert derive_inv(prof, bind, dataclasses.replace(good, document_id="cyclonedx:sha256:other")).state is S.UNKNOWN
    other_profile = parse_profile({**data, "documents": [{"doc_id": "elsewhere", "role": "primary_sbom"}],
                                   "inv_assertions": []})
    assert derive_inv(other_profile, bind, good).state is S.UNKNOWN  # the BIND result is for another document


def test_document_ids_are_validated_and_inputs_not_mutated():
    for bad in ("", "  ", 5):
        with pytest.raises(ValueError):
            InventoryAssessment(document_id=bad)
        with pytest.raises(ValueError):
            BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH, document_id=bad)
    prof, bind, assess = copy.deepcopy(USABLE), copy.deepcopy(MATCHED), copy.deepcopy(
        assessment(defect("b", relevant=True), document_id="other"))
    snapshot = (copy.deepcopy(prof), copy.deepcopy(bind), copy.deepcopy(assess))
    derive_inv(prof, bind, assess)
    assert (prof, bind, assess) == snapshot


# ---- states available, determinism, validation ---------------------------------------------------------------------------------------------

ASSESSMENTS = [
    None, InventoryAssessment(document_id=DOC), GOOD, assessment(passed("a"), passed("b", required=False)),
    assessment(not_performed()), assessment(passed(), not_performed("b")), assessment(passed(), defect("b")),
    assessment(passed(), defect("b", relevant=True)), assessment(defect("b", relevant=True, required=False)),
    assessment(passed(), interp=Interpretability.UNINTERPRETABLE), assessment(passed(), empty=Emptiness.EMPTY),
    assessment(passed(), interp=Interpretability.NOT_ASSESSED), assessment(passed(), empty=Emptiness.NOT_ASSESSED),
    assessment(passed(), document_id="other"), assessment(passed(), document_id=None),
    assessment(defect("b", relevant=True), document_id="other"), assessment(defect("b", relevant=True), document_id=None),
]
PROFILES = [USABLE, NO_ASSERTION, profile(assertion(statement="x")), profile(assertion(), assertion(statement="y"))]
FOREIGN_BIND = dataclasses.replace(MATCHED, document_id="other")
UNIDENTIFIED_BIND = dataclasses.replace(MATCHED, document_id=None)
BINDS = [MATCHED, MATCHED_PV, MISMATCHED, UNKNOWN, FOREIGN_BIND, UNIDENTIFIED_BIND]


def oracle(prof, bind, assess):
    """An independent restatement of the approved rules, for the whole input grid."""
    matched = bind.state is BindState.MATCHED and bind.document_id == prof.primary_document
    usable = bool(prof.usable_inv_assertions)
    if assess is not None and assess.document_id != prof.primary_document:
        assess = None  # an assessment about another (or no) document says nothing about this one
    checks = assess.checks if assess else ()
    if matched and any(c.outcome is CheckOutcome.CONTRADICTION_FOUND and c.relevance is Relevance.RELEVANT_TO_S for c in checks):
        return S.CONTRADICTORY
    if (matched and usable and assess is not None
            and any(c.required for c in checks)
            and all(c.outcome is CheckOutcome.PASSED for c in checks if c.required)
            and not any(c.outcome is CheckOutcome.CONTRADICTION_FOUND for c in checks)
            and assess.interpretability is Interpretability.INTERPRETABLE
            and assess.emptiness is Emptiness.NON_EMPTY):
        return S.PRESENT
    return S.UNKNOWN


def test_whole_input_grid_matches_the_independent_oracle_and_never_leaves_the_three_states():
    seen = set()
    for prof, bind, assess in itertools.product(PROFILES, BINDS, ASSESSMENTS):
        result = derive_inv(prof, bind, assess)
        assert result.state is oracle(prof, bind, assess)
        assert result.state in (S.PRESENT, S.UNKNOWN, S.CONTRADICTORY)
        seen.add(result.state)
    assert seen == {S.PRESENT, S.UNKNOWN, S.CONTRADICTORY}


def test_absent_incomplete_and_ambiguous_are_refused_by_the_result_type():
    for state in (S.ABSENT, S.INCOMPLETE, S.AMBIGUOUS):
        with pytest.raises(ValueError):
            InvDerivation(state, C.INVENTORY_EMPTY, BindState.MATCHED, AssertionStatus.USABLE, (C.INVENTORY_EMPTY,))


def test_result_invariants_are_enforced():
    kwargs = dict(bind_state=BindState.MATCHED, assertion=AssertionStatus.USABLE, identity_verified=True)
    InvDerivation(S.PRESENT, C.PRESENT, reasons=(C.PRESENT,), **kwargs)
    InvDerivation(S.UNKNOWN, C.INVENTORY_EMPTY, reasons=(C.INVENTORY_EMPTY,), **kwargs)
    InvDerivation(S.CONTRADICTORY, C.STRUCTURAL_CONTRADICTION, reasons=(C.STRUCTURAL_CONTRADICTION,),
                  contradictions=("x",), **kwargs)
    bad = [
        dict(state=S.PRESENT, reason=C.PRESENT, reasons=(C.PRESENT,), bind_state=BindState.UNKNOWN,
             assertion=AssertionStatus.USABLE, identity_verified=True),
        dict(state=S.PRESENT, reason=C.PRESENT, reasons=(C.PRESENT,), bind_state=BindState.MATCHED,
             assertion=AssertionStatus.USABLE),  # identity not verified
        dict(state=S.CONTRADICTORY, reason=C.STRUCTURAL_CONTRADICTION, reasons=(C.STRUCTURAL_CONTRADICTION,),
             contradictions=("x",), bind_state=BindState.MATCHED, assertion=AssertionStatus.USABLE),  # identity not verified
        dict(state=S.PRESENT, reason=C.PRESENT, reasons=(C.PRESENT,), bind_state=BindState.MATCHED,
             assertion=AssertionStatus.MISSING, identity_verified=True),
        dict(state=S.PRESENT, reason=C.INVENTORY_EMPTY, reasons=(C.INVENTORY_EMPTY,), **kwargs),
        dict(state=S.UNKNOWN, reason=C.PRESENT, reasons=(C.PRESENT,), **kwargs),
        dict(state=S.UNKNOWN, reason=C.INVENTORY_EMPTY, reasons=(), **kwargs),
        dict(state=S.CONTRADICTORY, reason=C.STRUCTURAL_CONTRADICTION, reasons=(C.STRUCTURAL_CONTRADICTION,), **kwargs),
        dict(state=S.CONTRADICTORY, reason=C.STRUCTURAL_CONTRADICTION, reasons=(C.STRUCTURAL_CONTRADICTION,), contradictions=("x",),
             bind_state=BindState.UNKNOWN, assertion=AssertionStatus.USABLE, identity_verified=True),
    ]
    for entry in bad:
        with pytest.raises(ValueError):
            InvDerivation(**entry)


def test_results_do_not_depend_on_input_order():
    checks = [passed("a"), passed("b", required=False), not_performed("c", required=False),
              defect("d", relevant=True), defect("e", required=False)]
    notes = ["n1", "n2", "n3"]
    results = set()
    for check_order in itertools.permutations(checks):
        assess = InventoryAssessment(Interpretability.INTERPRETABLE, Emptiness.NON_EMPTY, check_order, tuple(notes[::-1]), DOC)
        results.add(derive_inv(USABLE, MATCHED, assess))
    assert len(results) == 1 and next(iter(results)).contradictions == ("d",)
    present_checks = [passed("a"), passed("b"), passed("c", required=False)]
    outcomes = {derive_inv(USABLE, MATCHED, assessment(*order)) for order in itertools.permutations(present_checks)}
    assert len(outcomes) == 1 and next(iter(outcomes)).state is S.PRESENT
    entries = [assertion(), assertion(statement="partial_component_list"), assertion(document="elsewhere")]
    outcomes = {derive_inv(profile(*order), MATCHED, GOOD) for order in itertools.permutations(entries)}
    assert {o.state for o in outcomes} == {S.UNKNOWN}
    assert len({(o.reason, o.reasons, o.assertion) for o in outcomes}) == 1


def test_inputs_are_not_mutated():
    prof, assess = copy.deepcopy(USABLE), copy.deepcopy(GOOD)
    derive_inv(prof, MATCHED, assess)
    assert prof == USABLE and assess == GOOD


def test_assessment_validation():
    with pytest.raises(ValueError):
        InventoryAssessment(checks=(passed("a"), not_performed("a")))  # duplicate ids
    with pytest.raises(ValueError):
        InventoryAssessment(checks=("not a check",))
    with pytest.raises(ValueError):
        StructuralCheck(" ", True, CheckOutcome.PASSED)
    with pytest.raises(ValueError):
        StructuralCheck("a", "yes", CheckOutcome.PASSED)
    with pytest.raises(ValueError):
        StructuralCheck("a", True, "passed")
    with pytest.raises(ValueError):
        InventoryAssessment(interpretability="interpretable")


def test_codes_are_stable_unique_strings():
    values = [c.value for c in C]
    assert len(values) == len(set(values)) and all(v.startswith("INV_DERIVATION_") for v in values)
    assert {m.value for m in CheckOutcome} == {"passed", "contradiction_found", "not_performed"}


# ---- boundary ---------------------------------------------------------------------------------------------------------------------------------

def test_module_is_not_wired_and_runs_no_classifier_provenance_or_verdict():
    import ast
    import importlib

    for name in ("evidence.cnp_rules", "evidence.extraction", "evidence.bind", "evidence.profile", "evidence.stage1_records"):
        source = open(importlib.import_module(name).__file__, encoding="utf-8").read()
        assert "evidence.inv" not in source and "derive_inv" not in source, name
    tree = ast.parse(open(I.__file__, encoding="utf-8").read())
    imported, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    assert imported <= {"__future__", "dataclasses", "enum", "typing", "evidence.bind", "evidence.cnp_rules",
                        "evidence.profile", "model"}
    assert not names & {"evaluate_cnp", "CnpInputs", "ProvenanceLevel", "Verdict", "VerdictResult", "extract",
                        "SbomRecord", "evaluate_bind", "EvidenceItem", "artifact_digest_binding"}


def test_result_carries_no_provenance_or_verdict_fields():
    fields = {f.name for f in dataclasses.fields(InvDerivation)}
    assert fields.isdisjoint({"provenance", "level", "verdict", "p2", "p3", "digest"})
