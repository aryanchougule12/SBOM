"""Tests for evidence.decl_candidates.enumerate_decl_candidates_for_placement: the enumerator entry
for a would-be target that is not in the document, from the profile's explicit placement.

Selection rules G6-D1..D13 are those of the existing enumerator and are pinned by
tests/test_decl_candidates.py; these tests cover the placement entry point only.
"""

import copy
import json

from evidence import stage1_records as s1
from evidence.decl_candidates import (
    CoversS,
    EnumerationStatus as ES,
    ExclusionReason,
    StatusReason as SR,
    TargetPosition,
    enumerate_decl_candidates,
    enumerate_decl_candidates_for_placement as enumerate_for,
)
from model import EvidenceState

BOM_LINK = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#lib-a"


def comp(name, ref=None, children=None):
    obj = {"type": "library", "name": name}
    if ref is not None:
        obj["bom-ref"] = ref
    if children:
        obj["components"] = children
    return obj


def rec(aggregate="complete", assemblies=None, dependencies=None):
    obj = {"aggregate": aggregate}
    if assemblies is not None:
        obj["assemblies"] = assemblies
    if dependencies is not None:
        obj["dependencies"] = dependencies
    return obj


def doc(components=None, compositions=None, root=None, extra=None):
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components or []}
    if root is not None:
        data["metadata"] = {"component": root}
    if compositions is not None:
        data["compositions"] = compositions
    data.update(extra or {})
    return s1.load_cyclonedx(json.dumps(data).encode("utf-8"))


def root(ref="app", children=None):
    obj = {"type": "application", "name": "app"}
    if ref is not None:
        obj["bom-ref"] = ref
    if children:
        obj["components"] = children
    return obj


# ---- top level --------------------------------------------------------------------------------------------

def test_top_level_placement_has_no_parent_and_reports_root_records_only_as_root_level():
    record = doc([comp("a", "a")], [rec(assemblies=["app"])], root=root())
    result = enumerate_for(record, "top_level", None)
    assert result.status is ES.NO_CANDIDATE and result.status_reasons == (SR.TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY,)
    assert (result.parent_locator, result.placement, result.target_locator) == ("#", "top_level", None)
    (candidate,) = result.root_level_candidates
    assert candidate.target_position is TargetPosition.TOP_LEVEL and candidate.covers_s is CoversS.UNDETERMINED
    assert candidate.necessary_condition_met and candidate.record_locator == "#/compositions/0"
    assert result.candidates == () and result.groups == ()


def test_top_level_placement_with_a_non_complete_root_record_does_not_meet_the_necessary_condition():
    record = doc([comp("a", "a")], [rec("incomplete", assemblies=["app"])], root=root())
    (candidate,) = enumerate_for(record, "top_level", None).root_level_candidates
    assert not candidate.necessary_condition_met


def test_top_level_placement_is_never_derived_from_a_root_bom_ref():
    # naming the root as a nested parent is a different request: the root's direct children (G6-D12)
    record = doc([comp("a", "a")], [rec(assemblies=["app"])], root=root())
    nested = enumerate_for(record, "nested_under_component", "app")
    top = enumerate_for(record, "top_level", None)
    assert nested.status is ES.CANDIDATES_FOUND and nested.root_level_candidates == ()
    assert top.status is ES.NO_CANDIDATE and top.candidates == ()


# ---- nested ---------------------------------------------------------------------------------------------------

def test_nested_placement_selects_records_naming_the_direct_parent():
    record = doc([comp("parent", "p", [comp("child", "c")])], [rec(assemblies=["p"])])
    result = enumerate_for(record, "nested_under_component", "p")
    assert result.status is ES.CANDIDATES_FOUND
    assert (result.parent_locator, result.parent_ref) == ("#/components/0", "p")
    (group,) = result.groups
    assert group.state is EvidenceState.PRESENT and [m.record_locator for m in group.members] == ["#/compositions/0"]


def test_a_nested_target_directly_under_the_root_takes_the_component_specific_path():
    record = doc([comp("a", "a")], [rec(assemblies=["app"])], root=root(children=[comp("n", "n")]))
    result = enumerate_for(record, "nested_under_component", "app")
    assert result.status is ES.CANDIDATES_FOUND and result.candidates[0].parent_is_document_subject is True
    assert result.root_level_candidates == ()


def test_a_target_deeper_beneath_the_root_gets_a_root_level_candidate_only():
    record = doc([comp("a", "a")], [rec(assemblies=["app"])], root=root(children=[comp("n", "n")]))
    result = enumerate_for(record, "nested_under_component", "n")
    assert result.status is ES.NO_CANDIDATE and result.status_reasons == (SR.NO_RECORD_NAMES_PARENT,)
    (candidate,) = result.root_level_candidates
    assert candidate.target_position is TargetPosition.BELOW_ROOT_CHILD and candidate.covers_s is CoversS.UNDETERMINED


def test_a_target_below_a_top_level_component_gets_a_root_level_candidate_only():
    record = doc([comp("parent", "p")], [rec(assemblies=["app"])], root=root())
    result = enumerate_for(record, "nested_under_component", "p")
    (candidate,) = result.root_level_candidates
    assert candidate.target_position is TargetPosition.BELOW_TOP_LEVEL
    assert result.candidates == ()


def test_no_inheritance_from_a_grandparent_record():
    record = doc([comp("gp", "gp", [comp("parent", "p")])], [rec(assemblies=["gp"])])
    result = enumerate_for(record, "nested_under_component", "p")
    assert result.status is ES.NO_CANDIDATE
    assert [e.reason for e in result.exclusions] == [ExclusionReason.NOT_DIRECT_CHILD]


def test_equal_specificity_records_use_the_worst_case():
    record = doc([comp("parent", "p")], [rec("complete", assemblies=["p"]), rec("incomplete", assemblies=["p"])])
    (group,) = enumerate_for(record, "nested_under_component", "p").groups
    assert group.state is EvidenceState.INCOMPLETE and group.tie and group.disagreement
    record = doc([comp("parent", "p")], [rec("complete", assemblies=["p"]), rec("unknown", assemblies=["p"])])
    assert enumerate_for(record, "nested_under_component", "p").groups[0].state is EvidenceState.UNKNOWN


def test_scope_filtering_bom_links_and_unregistered_references_are_excluded():
    record = doc([comp("parent", "p")], [
        rec(dependencies=["p"]), rec(assemblies=[BOM_LINK]), rec(assemblies=["ghost"]), rec(assemblies=[]),
    ])
    result = enumerate_for(record, "nested_under_component", "p")
    assert result.status is ES.NO_CANDIDATE
    assert {e.reason for e in result.exclusions} == {
        ExclusionReason.DEPENDENCIES_ONLY, ExclusionReason.BOM_LINK_UNMATCHED,
        ExclusionReason.REFERENCE_NOT_IN_REGISTRY, ExclusionReason.NO_APPLICABLE_SCOPE}


def test_a_real_sibling_at_the_virtual_position_is_not_mistaken_for_the_target():
    record = doc([comp("parent", "p", [comp("sibling", "s")])], [rec(assemblies=["s"])])
    result = enumerate_for(record, "nested_under_component", "p")
    assert ExclusionReason.NAMES_TARGET_ITSELF not in [e.reason for e in result.exclusions]
    assert result.status is ES.NO_CANDIDATE


# ---- unresolved placement -------------------------------------------------------------------------------------

def test_unspecified_or_invalid_placement_selects_nothing():
    record = doc([comp("parent", "p")], [rec(assemblies=["app"]), rec(assemblies=["p"])], root=root())
    unspecified = enumerate_for(record, None, "p")
    assert unspecified.status is ES.TARGET_LOCATION_UNAVAILABLE and unspecified.status_reasons == (SR.PLACEMENT_UNSPECIFIED,)
    assert unspecified.candidates == () and unspecified.groups == ()
    assert all(c.target_position is TargetPosition.LOCATION_UNAVAILABLE for c in unspecified.root_level_candidates)
    for placement, parent in (("sideways", "p"), ("nested_under_component", None), ("nested_under_component", "")):
        invalid = enumerate_for(record, placement, parent)
        assert invalid.status is ES.TARGET_LOCATION_UNAVAILABLE and invalid.status_reasons == (SR.PLACEMENT_INVALID,)


def test_a_parent_that_is_unknown_or_not_a_component_is_not_guessed():
    record = doc([comp("parent", "p")], [rec(assemblies=["p"])], extra={"services": [{"bom-ref": "svc", "name": "s"}]})
    missing = enumerate_for(record, "nested_under_component", "nope")
    assert missing.status is ES.TARGET_NOT_IN_DOCUMENT and missing.status_reasons == (SR.PARENT_REF_NOT_IN_DOCUMENT,)
    service = enumerate_for(record, "nested_under_component", "svc")
    assert service.status is ES.TARGET_NOT_IN_DOCUMENT and service.status_reasons == (SR.PARENT_NOT_A_COMPONENT,)
    assert missing.candidates == service.candidates == ()


def test_an_ambiguous_parent_reference_selects_nothing():
    record = doc([comp("one", "dup"), comp("two", "dup")], [rec(assemblies=["dup"])])
    result = enumerate_for(record, "nested_under_component", "dup")
    assert result.status is ES.NO_CANDIDATE and result.status_reasons == (SR.PARENT_REFERENCE_AMBIGUOUS,)
    assert result.candidates == ()


def test_documents_without_compositions_give_no_candidate():
    record = doc([comp("parent", "p")])
    result = enumerate_for(record, "nested_under_component", "p")
    assert result.status is ES.NO_CANDIDATE and result.candidates == () and result.root_level_candidates == ()


# ---- agreement with the target-locator entry point, purity, determinism ----------------------------------------------

def test_a_would_be_child_gets_the_same_candidates_as_a_real_child():
    compositions = [rec(assemblies=["p"]), rec("incomplete", assemblies=["app"])]
    real = doc([comp("parent", "p", [comp("child", "c")])], compositions, root=root())
    absent = doc([comp("parent", "p")], compositions, root=root())
    by_locator = enumerate_decl_candidates(real, "#/components/0/components/0")
    by_placement = enumerate_for(absent, "nested_under_component", "p")
    assert by_placement.status is by_locator.status is ES.CANDIDATES_FOUND
    assert [(c.record_locator, c.state) for c in by_placement.candidates] == [(c.record_locator, c.state) for c in by_locator.candidates]
    assert [(r.record_locator, r.target_position) for r in by_placement.root_level_candidates] == [
        (r.record_locator, r.target_position) for r in by_locator.root_level_candidates]


def test_pure_and_deterministic():
    record = doc([comp("parent", "p")], [rec(assemblies=["p"]), rec(assemblies=["app"])], root=root())
    snapshot = copy.deepcopy(record)
    first = enumerate_for(record, "nested_under_component", "p")
    assert record == snapshot and enumerate_for(record, "nested_under_component", "p") == first
