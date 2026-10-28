"""Tests for evidence.decl_candidates (Stage 2, slice 2a; isolated enumerator).

The enumerator reports candidates, exclusions and root-level candidates for one target
locator. It selects nothing, grants no root-level coverage and is not part of
``extract()``. Documents are built inline from small dictionaries with the Stage 1
loaders, so no new fixtures are needed beyond the committed ones.
"""

import copy
import inspect
import json
from pathlib import Path

import pytest

from evidence import extraction
from evidence import stage1_records as s1
from evidence.decl_candidates import (
    CandidateRelation,
    CoversS,
    EnumerationStatus,
    ExclusionReason,
    RootLevelReason,
    StatusReason,
    TargetPosition,
    enumerate_decl_candidates,
    worst_case_state,
)
from model import EvidenceState

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BOM_LINK = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#lib-a"


def comp(name, ref=None, children=None):
    obj = {"type": "library", "name": name}
    if ref is not None:
        obj["bom-ref"] = ref
    if children:
        obj["components"] = children
    return obj


def rec(aggregate="complete", assemblies=None, dependencies=None, vulnerabilities=None):
    obj = {"aggregate": aggregate}
    if assemblies is not None:
        obj["assemblies"] = assemblies
    if dependencies is not None:
        obj["dependencies"] = dependencies
    if vulnerabilities is not None:
        obj["vulnerabilities"] = vulnerabilities
    return obj


def doc(components=None, compositions=None, root=None, extra=None):
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components or []}
    if root is not None:
        data["metadata"] = {"component": root}
    if compositions is not None:
        data["compositions"] = compositions
    data.update(extra or {})
    return s1.load_cyclonedx(json.dumps(data).encode("utf-8"))


def root_comp(ref="app", children=None):
    obj = {"type": "application", "name": "app"}
    if ref is not None:
        obj["bom-ref"] = ref
    if children:
        obj["components"] = children
    return obj


P_CHILD = "#/components/0/components/0"


def parent_child_doc(compositions, child_ref="c"):
    return doc([comp("parent", "p", [comp("child", child_ref)])], compositions)


def reasons(result):
    return [e.reason for e in result.exclusions]


# ---- 1-2: direct child ----------------------------------------------------------------------

def test_direct_child_under_a_named_parent_is_a_candidate():
    result = enumerate_decl_candidates(parent_child_doc([rec(assemblies=["p"])]), P_CHILD)
    assert result.status is EnumerationStatus.CANDIDATES_FOUND
    assert result.status_reasons == ()
    assert (result.parent_locator, result.parent_ref) == ("#/components/0", "p")
    (candidate,) = result.candidates
    assert candidate.record_locator == "#/compositions/0"
    assert candidate.reference == "p"
    assert candidate.relation is CandidateRelation.NAMED_PARENT
    assert candidate.state is EvidenceState.PRESENT
    assert candidate.aggregate_raw == "complete" and candidate.aggregate_recognized
    assert candidate.parent_is_document_subject is False
    (group,) = result.groups
    assert group.state is EvidenceState.PRESENT and not group.tie and not group.disagreement
    assert result.root_level_candidates == () and result.exclusions == ()


def test_a_direct_child_without_its_own_bom_ref_is_still_a_candidate():
    result = enumerate_decl_candidates(parent_child_doc([rec(assemblies=["p"])], child_ref=None), P_CHILD)
    assert result.status is EnumerationStatus.CANDIDATES_FOUND
    assert [c.reference for c in result.candidates] == ["p"]


# ---- 3: no recursive inheritance ---------------------------------------------------------------

def deep_doc(compositions, middle_ref="m"):
    return doc([comp("p", "p", [comp("middle", middle_ref, [comp("leaf", "leaf")])])], compositions)


LEAF = "#/components/0/components/0/components/0"


def test_a_deeper_descendant_does_not_inherit_the_ancestors_claim():
    result = enumerate_decl_candidates(deep_doc([rec(assemblies=["p"])]), LEAF)
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.NO_RECORD_NAMES_PARENT,)
    assert result.candidates == () and result.groups == ()
    assert [(e.record_locator, e.reference, e.reason) for e in result.exclusions] == [
        ("#/compositions/0", "p", ExclusionReason.NOT_DIRECT_CHILD)
    ]


def test_a_deeper_descendant_below_an_unnameable_parent_has_no_coverage_path():
    result = enumerate_decl_candidates(deep_doc([rec(assemblies=["p"])], middle_ref=None), LEAF)
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.PARENT_HAS_NO_BOM_REF,)
    assert result.parent_ref is None
    assert reasons(result) == [ExclusionReason.NOT_DIRECT_CHILD]


def test_the_intermediate_component_with_its_own_record_is_the_only_candidate():
    compositions = [rec(assemblies=["p"]), rec(aggregate="incomplete", assemblies=["m"])]
    result = enumerate_decl_candidates(deep_doc(compositions), LEAF)
    assert [(c.record_locator, c.reference, c.state) for c in result.candidates] == [
        ("#/compositions/1", "m", EvidenceState.INCOMPLETE)
    ]
    assert [(e.record_locator, e.reason) for e in result.exclusions] == [
        ("#/compositions/0", ExclusionReason.NOT_DIRECT_CHILD)
    ]


# ---- 4: own record plus parent record (G6-D11) -------------------------------------------------

def test_a_targets_own_record_is_not_a_candidate_only_the_parent_record_is():
    document = doc(
        [comp("p", "p", [comp("t", "t", [comp("grandchild", "g")])])],
        [rec(assemblies=["p"]), rec(aggregate="incomplete", assemblies=["t"])],
    )
    target = "#/components/0/components/0"
    result = enumerate_decl_candidates(document, target)
    assert [(c.record_locator, c.reference) for c in result.candidates] == [("#/compositions/0", "p")]
    assert [(e.record_locator, e.reference, e.reason) for e in result.exclusions] == [
        ("#/compositions/1", "t", ExclusionReason.NAMES_TARGET_ITSELF)
    ]
    (group,) = result.groups
    assert group.state is EvidenceState.PRESENT and not group.tie  # the own record is not ranked in

    # The same own record is the candidate for the target's child instead.
    child = enumerate_decl_candidates(document, "#/components/0/components/0/components/0")
    assert [(c.record_locator, c.reference, c.state) for c in child.candidates] == [
        ("#/compositions/1", "t", EvidenceState.INCOMPLETE)
    ]
    assert [(e.record_locator, e.reason) for e in child.exclusions] == [
        ("#/compositions/0", ExclusionReason.NOT_DIRECT_CHILD)
    ]


# ---- 5: tie groups and G6-D8 -----------------------------------------------------------------------

@pytest.mark.parametrize(
    "aggregates, expected, disagreement",
    [
        (("complete", "incomplete"), EvidenceState.INCOMPLETE, True),
        (("complete", "unknown"), EvidenceState.UNKNOWN, True),
        (("complete", "complete"), EvidenceState.PRESENT, False),
        (("incomplete", "unknown"), EvidenceState.UNKNOWN, True),
        (("complete", "not_specified"), EvidenceState.UNKNOWN, True),
        (("complete", "something_new"), EvidenceState.UNKNOWN, True),
    ],
)
def test_records_naming_the_same_parent_form_one_tie_group_with_the_worst_case(aggregates, expected, disagreement):
    compositions = [rec(aggregate=a, assemblies=["p"]) for a in aggregates]
    result = enumerate_decl_candidates(parent_child_doc(compositions), P_CHILD)
    assert [c.record_locator for c in result.candidates] == ["#/compositions/0", "#/compositions/1"]
    (group,) = result.groups
    assert group.tie and group.disagreement is disagreement
    assert group.state is expected
    assert group.members == result.candidates
    assert (group.parent_locator, group.parent_ref) == ("#/components/0", "p")


def test_an_unrecognized_aggregate_is_an_unknown_candidate_flagged_as_unrecognized():
    result = enumerate_decl_candidates(parent_child_doc([rec(aggregate="something_new", assemblies=["p"])]), P_CHILD)
    (candidate,) = result.candidates
    assert candidate.state is EvidenceState.UNKNOWN and not candidate.aggregate_recognized


def test_worst_case_state_follows_g6_d8_and_refuses_to_guess():
    S = EvidenceState
    assert worst_case_state([S.PRESENT]) is S.PRESENT
    assert worst_case_state([S.PRESENT, S.INCOMPLETE]) is S.INCOMPLETE
    assert worst_case_state([S.INCOMPLETE, S.PRESENT, S.UNKNOWN]) is S.UNKNOWN
    with pytest.raises(ValueError):
        worst_case_state([])
    for unsupported in (S.ABSENT, S.AMBIGUOUS, S.CONTRADICTORY):
        with pytest.raises(ValueError):
            worst_case_state([S.PRESENT, unsupported])


def test_records_for_different_parents_are_never_combined():
    document = doc(
        [comp("a", "a", [comp("ax", "ax")]), comp("b", "b", [comp("bx", "bx")])],
        [rec(aggregate="incomplete", assemblies=["a"]), rec(assemblies=["b"])],
    )
    a_child = enumerate_decl_candidates(document, "#/components/0/components/0")
    b_child = enumerate_decl_candidates(document, "#/components/1/components/0")
    assert [(c.record_locator, c.state) for c in a_child.candidates] == [("#/compositions/0", EvidenceState.INCOMPLETE)]
    assert [(c.record_locator, c.state) for c in b_child.candidates] == [("#/compositions/1", EvidenceState.PRESENT)]
    assert a_child.groups[0].state is EvidenceState.INCOMPLETE and b_child.groups[0].state is EvidenceState.PRESENT


# ---- 6: sibling references (G6-D4) ----------------------------------------------------------------------

def test_sibling_references_are_judged_independently():
    document = doc(
        [comp("a", "a", [comp("ax", "ax")]), comp("b", "b", [comp("bx", "bx")]), comp("c", "c", [comp("cx", "cx")])],
        [rec(assemblies=["a", "b", "ghost"])],
    )
    a_child = enumerate_decl_candidates(document, "#/components/0/components/0")
    b_child = enumerate_decl_candidates(document, "#/components/1/components/0")
    c_child = enumerate_decl_candidates(document, "#/components/2/components/0")
    assert [c.reference for c in a_child.candidates] == ["a"]
    assert [c.reference for c in b_child.candidates] == ["b"]
    assert c_child.status is EnumerationStatus.NO_CANDIDATE and c_child.candidates == ()
    # The unresolved sibling is excluded and does not affect the resolved ones.
    for result in (a_child, b_child, c_child):
        assert [(e.reference, e.reason) for e in result.exclusions] == [
            ("ghost", ExclusionReason.REFERENCE_NOT_IN_REGISTRY)
        ]


# ---- 7-8: the root (G6-D3) ----------------------------------------------------------------------------------

def root_doc(aggregate="complete", extra_components=None):
    components = [comp("lib", "lib", [comp("deep", "deep")])] + (extra_components or [])
    return doc(components, [rec(aggregate=aggregate, assemblies=["app"])], root=root_comp())


def test_root_named_complete_is_reported_as_root_level_with_coverage_undetermined():
    result = enumerate_decl_candidates(root_doc(), "#/components/0")
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY,)
    assert result.candidates == () and result.groups == ()
    (root,) = result.root_level_candidates
    assert root.record_locator == "#/compositions/0" and root.root_ref == "app"
    assert root.state is EvidenceState.PRESENT
    assert root.necessary_condition_met is True
    assert root.covers_s is CoversS.UNDETERMINED
    assert root.target_position is TargetPosition.TOP_LEVEL
    assert root.reasons == (RootLevelReason.COVERS_S_UNDETERMINED,)


@pytest.mark.parametrize("aggregate", ["incomplete", "incomplete_first_party_only", "unknown", "not_specified", "other"])
def test_root_named_with_a_non_complete_aggregate_is_reported_but_the_necessary_condition_fails(aggregate):
    result = enumerate_decl_candidates(root_doc(aggregate), "#/components/0")
    (root,) = result.root_level_candidates
    assert root.necessary_condition_met is False
    assert root.covers_s is CoversS.UNDETERMINED
    assert RootLevelReason.AGGREGATE_NOT_COMPLETE in root.reasons
    assert result.candidates == () and result.groups == ()


def test_a_deeper_top_tree_descendant_gets_a_separate_root_fallback_not_a_component_candidate():
    result = enumerate_decl_candidates(root_doc(), "#/components/0/components/0")
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.NO_RECORD_NAMES_PARENT,)
    assert result.candidates == () and result.groups == () and result.exclusions == ()
    (root,) = result.root_level_candidates
    assert root.target_position is TargetPosition.BELOW_TOP_LEVEL
    assert root.reasons == (RootLevelReason.COVERS_S_UNDETERMINED,)
    assert root.covers_s is CoversS.UNDETERMINED and root.necessary_condition_met is True


def test_a_root_without_a_bom_ref_cannot_be_named():
    document = doc([comp("lib", "lib")], [rec(assemblies=["app"])], root=root_comp(ref=None))
    result = enumerate_decl_candidates(document, "#/components/0")
    assert result.root_level_candidates == ()
    assert [(e.reference, e.reason) for e in result.exclusions] == [
        ("app", ExclusionReason.REFERENCE_NOT_IN_REGISTRY)
    ]


def test_a_child_nested_beneath_the_root_is_a_direct_child_of_the_named_root():
    document = doc(
        [comp("lib", "lib")],
        [rec(assemblies=["app"])],
        root=root_comp(children=[comp("inner", "inner", [comp("innermost", "innermost")])]),
    )
    inner = enumerate_decl_candidates(document, "#/metadata/component/components/0")
    assert inner.status is EnumerationStatus.CANDIDATES_FOUND
    assert (inner.parent_locator, inner.parent_ref) == ("#/metadata/component", "app")
    (candidate,) = inner.candidates
    assert candidate.reference == "app" and candidate.parent_is_document_subject is True
    assert inner.root_level_candidates == ()
    # No recursion beneath the root: the grandchild gets no component-specific candidate
    # from the root's reference, only the separate document-level fallback (G6-D13).
    innermost = enumerate_decl_candidates(document, "#/metadata/component/components/0/components/0")
    assert innermost.candidates == () and innermost.groups == () and innermost.exclusions == ()
    (fallback,) = innermost.root_level_candidates
    assert fallback.root_ref == "app" and fallback.target_position is TargetPosition.BELOW_ROOT_CHILD
    assert fallback.covers_s is CoversS.UNDETERMINED


def test_the_document_subject_itself_has_no_parent_assembly():
    result = enumerate_decl_candidates(root_doc(), "#/metadata/component")
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.TARGET_IS_DOCUMENT_SUBJECT,)
    assert result.candidates == () and result.root_level_candidates == ()


# ---- 7b: root-nested children and the document-level fallback (G6-D12, G6-D13) -----------------------------------------------------

def nested_root_doc(aggregate="complete", extra_compositions=None, root_children=None):
    children = root_children or [comp("inner", "inner", [comp("innermost", "innermost", [comp("deepest", "deepest")])])]
    compositions = [rec(aggregate=aggregate, assemblies=["app"])] + (extra_compositions or [])
    return doc([comp("lib", "lib", [comp("libchild", "libchild")])], compositions, root=root_comp(children=children))


ROOT_CHILD = "#/metadata/component/components/0"
ROOT_GRANDCHILD = "#/metadata/component/components/0/components/0"
ROOT_GREAT_GRANDCHILD = "#/metadata/component/components/0/components/0/components/0"


@pytest.mark.parametrize("aggregate, state", [("complete", EvidenceState.PRESENT), ("incomplete", EvidenceState.INCOMPLETE)])
def test_a_direct_root_child_gets_only_a_component_specific_candidate(aggregate, state):
    result = enumerate_decl_candidates(nested_root_doc(aggregate), ROOT_CHILD)
    assert result.status is EnumerationStatus.CANDIDATES_FOUND
    (candidate,) = result.candidates
    assert (candidate.reference, candidate.state, candidate.parent_is_document_subject) == ("app", state, True)
    # No second output path for the same record and reference, and no fallback is implied.
    assert result.root_level_candidates == () and result.exclusions == ()
    assert result.groups[0].state is state


def test_a_deeper_descendant_under_the_root_child_gets_a_separate_fallback_only():
    result = enumerate_decl_candidates(nested_root_doc(), ROOT_GRANDCHILD)
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.NO_RECORD_NAMES_PARENT,)
    assert (result.parent_locator, result.parent_ref) == (ROOT_CHILD, "inner")
    assert result.candidates == () and result.groups == () and result.exclusions == ()
    (fallback,) = result.root_level_candidates
    assert fallback.record_locator == "#/compositions/0" and fallback.root_ref == "app"
    assert fallback.target_position is TargetPosition.BELOW_ROOT_CHILD
    assert fallback.necessary_condition_met is True
    assert fallback.covers_s is CoversS.UNDETERMINED
    assert fallback.reasons == (RootLevelReason.COVERS_S_UNDETERMINED,)
    # The same holds one level further down: the root reference is not inherited.
    deeper = enumerate_decl_candidates(nested_root_doc(), ROOT_GREAT_GRANDCHILD)
    assert deeper.candidates == () and deeper.exclusions == ()
    assert [r.target_position for r in deeper.root_level_candidates] == [TargetPosition.BELOW_ROOT_CHILD]


def test_the_root_fallback_and_an_intermediate_components_own_record_are_separate_paths():
    extra = [rec(aggregate="incomplete", assemblies=["inner"])]
    result = enumerate_decl_candidates(nested_root_doc(extra_compositions=extra), ROOT_GRANDCHILD)
    assert result.status is EnumerationStatus.CANDIDATES_FOUND
    assert [(c.record_locator, c.reference, c.state) for c in result.candidates] == [
        ("#/compositions/1", "inner", EvidenceState.INCOMPLETE)
    ]
    assert result.groups[0].state is EvidenceState.INCOMPLETE  # the fallback is not part of the group
    assert [(r.record_locator, r.root_ref) for r in result.root_level_candidates] == [("#/compositions/0", "app")]
    assert result.exclusions == ()


@pytest.mark.parametrize("target", ["#/components/0/components/0", ROOT_GRANDCHILD])
@pytest.mark.parametrize("aggregate", ["incomplete", "unknown", "not_specified", "something_new"])
def test_a_non_complete_root_record_never_qualifies_as_a_document_level_fallback(aggregate, target):
    document = nested_root_doc(aggregate)
    result = enumerate_decl_candidates(document, target)
    (fallback,) = result.root_level_candidates
    assert fallback.necessary_condition_met is False
    assert RootLevelReason.AGGREGATE_NOT_COMPLETE in fallback.reasons
    assert fallback.covers_s is CoversS.UNDETERMINED
    assert result.candidates == ()


def test_a_deeper_top_tree_descendant_keeps_the_fallback_separate_from_its_parents_record():
    document = doc(
        [comp("lib", "lib", [comp("mid", "mid", [comp("leaf", "leaf")])])],
        [rec(assemblies=["app"]), rec(aggregate="incomplete", assemblies=["mid"])],
        root=root_comp(),
    )
    result = enumerate_decl_candidates(document, "#/components/0/components/0/components/0")
    assert [(c.record_locator, c.reference) for c in result.candidates] == [("#/compositions/1", "mid")]
    (fallback,) = result.root_level_candidates
    assert (fallback.record_locator, fallback.target_position) == ("#/compositions/0", TargetPosition.BELOW_TOP_LEVEL)
    assert result.groups[0].members == result.candidates


def test_a_component_nested_in_another_object_is_not_treated_as_in_scope_for_the_fallback():
    pedigree = {"ancestors": [comp("anc", "anc", [comp("anc-child", "anc-child")])]}
    lib = comp("lib", "lib")
    lib["pedigree"] = pedigree
    document = doc([lib], [rec(assemblies=["app", "anc"])], root=root_comp())
    target = "#/components/0/pedigree/ancestors/0/components/0"
    result = enumerate_decl_candidates(document, target)
    assert [c.reference for c in result.candidates] == ["anc"]  # an ordinary named parent still works
    assert result.root_level_candidates == ()  # scope S membership of such components is not decided


def test_no_record_and_reference_pair_takes_more_than_one_output_path():
    document = doc(
        [comp("lib", "lib", [comp("libchild", "libchild", [comp("libdeep", "libdeep")])]), comp("noref")],
        [
            rec(assemblies=["app", "lib", "inner", "ghost", BOM_LINK]),
            rec(aggregate="incomplete", assemblies=["app", "libchild", "innermost"]),
            rec(assemblies=["app"]),
            rec(dependencies=["app"]),
        ],
        root=root_comp(children=[comp("inner", "inner", [comp("innermost", "innermost", [comp("deepest", "deepest")])])]),
    )
    targets = [
        None,
        "#/components/0", "#/components/0/components/0", "#/components/0/components/0/components/0", "#/components/1",
        ROOT_CHILD, ROOT_GRANDCHILD, ROOT_GREAT_GRANDCHILD,
    ]
    for target in targets:
        result = enumerate_decl_candidates(document, target)
        paths = (
            [(c.record_locator, c.reference) for c in result.candidates]
            + [(r.record_locator, r.root_ref) for r in result.root_level_candidates]
            + [(e.record_locator, e.reference) for e in result.exclusions if e.reference is not None]
        )
        assert len(paths) == len(set(paths)), (target, paths)
        assert all(r.covers_s is CoversS.UNDETERMINED for r in result.root_level_candidates)
        assert not (set((c.record_locator, c.reference) for c in result.candidates)
                    & set((r.record_locator, r.root_ref) for r in result.root_level_candidates))


# ---- 9: no location ------------------------------------------------------------------------------------------------

def test_without_a_target_location_no_parent_is_guessed():
    result = enumerate_decl_candidates(parent_child_doc([rec(assemblies=["p"])]), None)
    assert result.status is EnumerationStatus.TARGET_LOCATION_UNAVAILABLE
    assert result.status_reasons == (StatusReason.NO_TARGET_LOCATION,)
    assert result.parent_locator is None and result.parent_ref is None
    assert result.candidates == () and result.groups == () and result.root_level_candidates == ()


def test_without_a_target_location_a_named_root_is_still_reported_as_undetermined():
    result = enumerate_decl_candidates(root_doc(), None)
    assert result.status is EnumerationStatus.TARGET_LOCATION_UNAVAILABLE
    assert result.candidates == ()
    (root,) = result.root_level_candidates
    assert root.target_position is TargetPosition.LOCATION_UNAVAILABLE
    assert root.covers_s is CoversS.UNDETERMINED and root.necessary_condition_met is True


def test_target_locators_that_are_not_components_of_the_document_are_reported():
    document = doc(
        [comp("p", "p")],
        [rec(assemblies=["p"])],
        extra={"services": [{"name": "svc", "bom-ref": "svc-1"}]},
    )
    missing = enumerate_decl_candidates(document, "#/components/9")
    assert missing.status is EnumerationStatus.TARGET_NOT_IN_DOCUMENT
    assert missing.status_reasons == (StatusReason.LOCATOR_NOT_IN_DOCUMENT,)
    service = enumerate_decl_candidates(document, "#/services/0")
    assert service.status is EnumerationStatus.TARGET_NOT_IN_DOCUMENT
    assert service.status_reasons == (StatusReason.LOCATOR_NOT_A_COMPONENT,)
    malformed = enumerate_decl_candidates(document, "not-a-pointer")
    assert malformed.status is EnumerationStatus.TARGET_NOT_IN_DOCUMENT
    for result in (missing, service, malformed):
        assert result.candidates == () and result.root_level_candidates == ()


# ---- 10: BOM-Link and unresolved references ------------------------------------------------------------------------------

def test_bom_link_unresolved_and_ambiguous_references_are_exclusions_not_guesses():
    document = doc(
        [comp("dup1", "dup", [comp("child-of-dup", "x")]), comp("dup2", "dup"), comp("other", "o", [comp("oc", "oc")])],
        [rec(assemblies=[BOM_LINK, "ghost", "dup", "o"])],
    )
    # The target below the repeated (ambiguous) reference gets no candidate.
    ambiguous_parent = enumerate_decl_candidates(document, "#/components/0/components/0")
    assert ambiguous_parent.status is EnumerationStatus.NO_CANDIDATE
    assert ambiguous_parent.status_reasons == (StatusReason.PARENT_REFERENCE_AMBIGUOUS,)
    assert [(e.reference, e.reason) for e in ambiguous_parent.exclusions] == [
        (BOM_LINK, ExclusionReason.BOM_LINK_UNMATCHED),
        ("ghost", ExclusionReason.REFERENCE_NOT_IN_REGISTRY),
        ("dup", ExclusionReason.AMBIGUOUS_REFERENCE),
    ]
    # An unrelated, unambiguous parent in the same record is still matched.
    unambiguous = enumerate_decl_candidates(document, "#/components/2/components/0")
    assert [c.reference for c in unambiguous.candidates] == ["o"]


def test_a_bom_link_is_never_matched_even_if_a_local_reference_has_the_same_text():
    document = doc([comp("p", BOM_LINK, [comp("c", "c")])], [rec(assemblies=[BOM_LINK])])
    result = enumerate_decl_candidates(document, P_CHILD)
    assert result.candidates == ()
    assert [(e.reference, e.reason) for e in result.exclusions] == [(BOM_LINK, ExclusionReason.BOM_LINK_UNMATCHED)]


def test_only_a_full_schema_pattern_match_is_treated_as_a_bom_link():
    lookalike = "urn:cdx:not-a-uuid/1#x"
    document = doc([comp("p", lookalike, [comp("c", "c")])], [rec(assemblies=[lookalike])])
    result = enumerate_decl_candidates(document, P_CHILD)
    assert [c.reference for c in result.candidates] == [lookalike]
    assert result.exclusions == ()


# ---- 11: scope rules (G6-D2, G6-D9) -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "record, expected",
    [
        (rec(), ExclusionReason.NO_APPLICABLE_SCOPE),
        (rec(assemblies=[]), ExclusionReason.NO_APPLICABLE_SCOPE),
        (rec(assemblies=[], dependencies=[], vulnerabilities=[]), ExclusionReason.NO_APPLICABLE_SCOPE),
        (rec(dependencies=["p"]), ExclusionReason.DEPENDENCIES_ONLY),
        (rec(assemblies=[], dependencies=["p"]), ExclusionReason.DEPENDENCIES_ONLY),
        (rec(vulnerabilities=["p"]), ExclusionReason.VULNERABILITIES_ONLY),
        (rec(dependencies=["p"], vulnerabilities=["v"]), ExclusionReason.DEPENDENCIES_AND_VULNERABILITIES_ONLY),
    ],
)
def test_records_without_an_assemblies_list_cannot_establish_coverage(record, expected):
    result = enumerate_decl_candidates(parent_child_doc([record]), P_CHILD)
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.candidates == () and result.groups == () and result.root_level_candidates == ()
    assert [(e.record_locator, e.reason, e.reference) for e in result.exclusions] == [
        ("#/compositions/0", expected, None)
    ]


def test_a_mixed_scope_record_contributes_only_its_assemblies_portion():
    record = rec(aggregate="incomplete", assemblies=["p"], dependencies=["c"], vulnerabilities=["v"])
    result = enumerate_decl_candidates(parent_child_doc([record]), P_CHILD)
    (candidate,) = result.candidates
    assert candidate.state is EvidenceState.INCOMPLETE
    assert candidate.ignored_scope_lists == ("dependencies", "vulnerabilities")
    assert result.exclusions == ()


def test_a_dependencies_entry_naming_the_parent_does_not_make_a_candidate():
    record = rec(assemblies=["other"], dependencies=["p"])
    result = enumerate_decl_candidates(parent_child_doc([record]), P_CHILD)
    assert result.candidates == ()
    assert [e.reason for e in result.exclusions] == [ExclusionReason.REFERENCE_NOT_IN_REGISTRY]


# ---- 12-14: committed fixtures ---------------------------------------------------------------------------------------------------------

def test_complete_composition_fixture_covers_lib_nested_through_lib_purl_only():
    record = s1.load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    nested = enumerate_decl_candidates(record, "#/components/0/components/0")
    assert nested.status is EnumerationStatus.CANDIDATES_FOUND
    assert (nested.parent_locator, nested.parent_ref) == ("#/components/0", "lib-purl")
    (candidate,) = nested.candidates
    assert (candidate.record_locator, candidate.reference, candidate.state) == (
        "#/compositions/0", "lib-purl", EvidenceState.PRESENT)
    assert candidate.ignored_scope_lists == ("dependencies",)  # ``dependencies: [app-1]`` is ignored
    assert nested.root_level_candidates == ()

    # The top-level components get no component-specific and no root-level candidate: the
    # record does not name the root app-1 (it appears only under ``dependencies``).
    # Each is named by the record, but that is its own assembly (G6-D11), not a candidate.
    for locator, ref in (("#/components/0", "lib-purl"), ("#/components/1", "lib-cpe"), ("#/components/2", "lib-name")):
        top = enumerate_decl_candidates(record, locator)
        assert top.status is EnumerationStatus.NO_CANDIDATE
        assert top.status_reasons == (StatusReason.TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY,)
        assert top.candidates == () and top.root_level_candidates == ()
        assert [(e.record_locator, e.reference, e.reason) for e in top.exclusions] == [
            ("#/compositions/0", ref, ExclusionReason.NAMES_TARGET_ITSELF)
        ]

    subject = enumerate_decl_candidates(record, "#/metadata/component")
    assert subject.status_reasons == (StatusReason.TARGET_IS_DOCUMENT_SUBJECT,)
    assert subject.candidates == () and subject.root_level_candidates == ()


def test_incomplete_composition_fixture_records_stay_separate():
    record = s1.load_cyclonedx(FIXTURES / "cyclonedx" / "incomplete_composition.json")
    for locator, ref, record_locator in (
        ("#/components/0", "comp-a", "#/compositions/0"),
        ("#/components/1", "comp-b", "#/compositions/1"),
    ):
        result = enumerate_decl_candidates(record, locator)
        assert result.status is EnumerationStatus.NO_CANDIDATE
        assert result.candidates == () and result.groups == ()
        # Each record concerns its own named component's assembly, so neither is a candidate.
        assert [(e.record_locator, e.reference, e.reason) for e in result.exclusions] == [
            (record_locator, ref, ExclusionReason.NAMES_TARGET_ITSELF)
        ]
    # The same two records over a nested layout are not merged.
    document = doc(
        [comp("a", "comp-a", [comp("ax", "ax")]), comp("b", "comp-b", [comp("bx", "bx")])],
        [rec(aggregate="incomplete_first_party_only", assemblies=["comp-a"]), rec(assemblies=["comp-b"])],
    )
    a = enumerate_decl_candidates(document, "#/components/0/components/0")
    b = enumerate_decl_candidates(document, "#/components/1/components/0")
    assert [(c.record_locator, c.state) for c in a.candidates] == [("#/compositions/0", EvidenceState.INCOMPLETE)]
    assert [(c.record_locator, c.state) for c in b.candidates] == [("#/compositions/1", EvidenceState.PRESENT)]


@pytest.mark.parametrize(
    "loader, path, locator",
    [
        (s1.load_cyclonedx, ("cyclonedx", "no_compositions.json"), "#/components/0"),
        (s1.load_spdx, ("spdx", "no_completeness.json"), "#/packages/0"),
    ],
)
def test_documents_without_composition_records_have_no_candidates(loader, path, locator):
    record = loader(FIXTURES.joinpath(*path))
    assert record.composition_records == ()
    result = enumerate_decl_candidates(record, locator)
    assert result.status is EnumerationStatus.NO_CANDIDATE
    assert result.status_reasons == (StatusReason.NO_COMPOSITION_RECORDS,)
    assert result.candidates == () and result.groups == () and result.exclusions == ()


def test_unknown_composition_fixture_has_no_applicable_scope_for_its_scope_less_record():
    record = s1.load_cyclonedx(FIXTURES / "cyclonedx" / "unknown_composition.json")
    result = enumerate_decl_candidates(record, "#/components/0")
    assert [(e.record_locator, e.reason) for e in result.exclusions] == [
        ("#/compositions/0", ExclusionReason.NO_APPLICABLE_SCOPE),
        ("#/compositions/1", ExclusionReason.NAMES_TARGET_ITSELF),  # ``not_specified`` over [c1], the target itself
    ]
    assert result.candidates == ()


# ---- 15: determinism, immutability, isolation ------------------------------------------------------------------------------------------------

def test_results_are_deterministic_and_inputs_are_not_mutated():
    document = doc(
        [comp("p", "p", [comp("c", "c")])],
        [rec(aggregate="incomplete", assemblies=["p", "ghost"]), rec(assemblies=["p"]), rec(), rec(dependencies=["p"])],
        root=root_comp(),
    )
    snapshot = copy.deepcopy(document)
    first = enumerate_decl_candidates(document, P_CHILD)
    second = enumerate_decl_candidates(document, P_CHILD)
    assert first == second
    assert document == snapshot
    assert [c.record_locator for c in first.candidates] == ["#/compositions/0", "#/compositions/1"]
    assert [(e.record_locator, e.reason) for e in first.exclusions] == [
        ("#/compositions/0", ExclusionReason.REFERENCE_NOT_IN_REGISTRY),
        ("#/compositions/2", ExclusionReason.NO_APPLICABLE_SCOPE),
        ("#/compositions/3", ExclusionReason.DEPENDENCIES_ONLY),
    ]
    with pytest.raises(Exception):
        first.candidates[0].state = EvidenceState.ABSENT  # results are frozen


def test_the_enumerator_is_not_wired_into_extraction_and_extraction_is_unchanged():
    # Extraction's own DECL tests (tests/test_extraction.py) still pin the Unknown behaviour.
    assert "decl_candidates" not in inspect.getsource(extraction)
    assert not hasattr(extraction, "decl_candidates")
    assert not hasattr(extraction, "enumerate_decl_candidates")
