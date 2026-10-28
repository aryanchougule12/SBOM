"""Tests for evidence.decl_derivation: DECL selection, component-specific precedence and the
"covers S" conditions of the document-level fallback (register G6, D4, D5)."""

import copy
import json

import pytest

from evidence import stage1_records as s1
from evidence.bind import BindBasis, BindCode, BindEvaluation
from evidence.cnp_rules import BindState
from evidence.decl_derivation import CoversSResult, DeclDerivation, DeclPath, DeclReason as DR, derive_decl
from evidence.inv import AssertionStatus, InvCode, InvDerivation
from evidence.profile import WouldBeLocation
from model import EvidenceState as S

DOC_NESTED = "nested_under_component"


def comp(name, ref=None, children=None):
    obj = {"type": "library", "name": name}
    if ref is not None:
        obj["bom-ref"] = ref
    if children:
        obj["components"] = children
    return obj


def rec(aggregate="complete", assemblies=None):
    return {"aggregate": aggregate, "assemblies": assemblies if assemblies is not None else []}


def record(compositions, components=None, root=True, root_children=None):
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": components if components is not None else [comp("parent", "p", [comp("child", "c")])],
            "compositions": compositions}
    if root:
        subject = {"type": "application", "name": "app", "bom-ref": "app"}
        if root_children:
            subject["components"] = root_children
        data["metadata"] = {"component": subject}
    return s1.load_cyclonedx(json.dumps(data).encode())


def bound(doc, state=BindState.MATCHED):
    if state is BindState.MATCHED:
        return BindEvaluation(state, BindBasis.DIGEST, BindCode.DIGEST_MATCH, agreeing_digests=("sha256:aa",), document_id=doc)
    return BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=doc)


def inv(doc, state=S.PRESENT, assertion=AssertionStatus.USABLE):
    if state is S.PRESENT:
        return InvDerivation(S.PRESENT, InvCode.PRESENT, BindState.MATCHED, AssertionStatus.USABLE, (InvCode.PRESENT,),
                             document_id=doc, identity_verified=True)
    return InvDerivation(S.UNKNOWN, InvCode.ASSESSMENT_MISSING, BindState.MATCHED, assertion,
                         (InvCode.ASSESSMENT_MISSING,), document_id=doc)


def loc(doc, placement=DOC_NESTED, parent="p"):
    return WouldBeLocation(doc.doc_id, parent if placement == DOC_NESTED else None, placement)


def derive(r, location=None, **kw):
    location = location if location is not None else loc(r)
    return derive_decl(r, location, kw.get("bind", bound(r.doc_id)), kw.get("inv", inv(r.doc_id)))


# ---- component-specific path -----------------------------------------------------------------------

def test_a_record_naming_the_direct_parent_gives_the_decl_state():
    result = derive(record([rec(assemblies=["p"])]))
    assert (result.state, result.reason, result.path) == (S.PRESENT, DR.COMPONENT_SPECIFIC_RECORD, DeclPath.COMPONENT_SPECIFIC)
    assert result.record_locators == ("#/compositions/0",) and result.covers_s is CoversSResult.NOT_EVALUATED


def test_incomplete_and_unknown_component_specific_records_are_not_present():
    incomplete = derive(record([rec("incomplete", assemblies=["p"])]))
    assert (incomplete.state, incomplete.reason) == (S.INCOMPLETE, DR.COMPONENT_SPECIFIC_NOT_COMPLETE)
    unknown = derive(record([rec("unknown", assemblies=["p"])]))
    assert (unknown.state, unknown.reason) == (S.UNKNOWN, DR.COMPONENT_SPECIFIC_UNKNOWN) and unknown.record_locators


def test_equal_specificity_records_use_the_conservative_worst_case():
    r = record([rec("complete", assemblies=["p"]), rec("incomplete", assemblies=["p"]), rec("complete", assemblies=["p"])])
    result = derive(r)
    assert result.state is S.INCOMPLETE and result.record_locators == ("#/compositions/0", "#/compositions/1", "#/compositions/2")
    assert derive(record([rec("complete", assemblies=["p"]), rec("unknown", assemblies=["p"])])).state is S.UNKNOWN


def test_a_more_specific_record_wins_over_a_complete_root_record():
    r = record([rec("complete", assemblies=["app"]), rec("incomplete", assemblies=["p"])])
    result = derive(r)
    assert result.state is S.INCOMPLETE and result.path is DeclPath.COMPONENT_SPECIFIC
    assert result.record_locators == ("#/compositions/1",)


def test_a_target_directly_under_the_root_uses_the_root_record_as_component_specific():
    r = record([rec("complete", assemblies=["app"])])
    result = derive(r, WouldBeLocation(r.doc_id, "app", DOC_NESTED))
    assert result.state is S.PRESENT and result.path is DeclPath.COMPONENT_SPECIFIC


def test_no_inheritance_from_a_grandparent():
    r = record([rec("complete", assemblies=["gp"])], components=[comp("gp", "gp", [comp("parent", "p")])], root=False)
    result = derive(r)
    assert result.state is S.UNKNOWN and result.reason is DR.NO_APPLICABLE_RECORD


# ---- document-level fallback and "covers S" ---------------------------------------------------------------------

def test_the_root_record_covers_a_top_level_target_only_when_every_condition_holds():
    r = record([rec("complete", assemblies=["app"])])
    result = derive(r, loc(r, "top_level"))
    assert (result.state, result.path, result.covers_s) == (S.PRESENT, DeclPath.DOCUMENT_LEVEL_FALLBACK, CoversSResult.ESTABLISHED)
    assert result.reason is DR.ROOT_RECORD_COVERS_S and result.record_locators == ("#/compositions/0",)


@pytest.mark.parametrize(
    "label,mutate",
    [
        ("record not complete", lambda r: dict(r=record([rec("incomplete", assemblies=["app"])]))),
        ("record unknown", lambda r: dict(r=record([rec("unknown", assemblies=["app"])]))),
        ("no usable assertion", lambda r: dict(inv_=inv(r.doc_id, S.UNKNOWN, AssertionStatus.UNUSABLE))),
        ("INV not present", lambda r: dict(inv_=inv(r.doc_id, S.UNKNOWN, AssertionStatus.USABLE))),
    ],
)
def test_the_root_record_alone_never_covers_s(label, mutate):
    base = record([rec("complete", assemblies=["app"])])
    changes = mutate(base)
    r = changes.get("r", base)
    location = loc(r, "top_level")
    result = derive_decl(r, location, bound(r.doc_id), changes.get("inv_", inv(r.doc_id)))
    assert result.state is S.UNKNOWN and result.path is DeclPath.NONE, label
    assert result.covers_s is CoversSResult.NOT_ESTABLISHED and result.unmet_covers_s, label
    assert result.reason is DR.COVERS_S_NOT_ESTABLISHED


def test_root_records_that_disagree_do_not_cover_s():
    r = record([rec("complete", assemblies=["app"]), rec("incomplete", assemblies=["app"])])
    result = derive(r, loc(r, "top_level"))
    assert result.state is S.UNKNOWN and result.covers_s is CoversSResult.NOT_ESTABLISHED


def test_a_target_deeper_than_a_root_child_is_in_scope_for_the_fallback():
    r = record([rec("complete", assemblies=["app"])], root_children=[comp("n", "n")])
    result = derive(r, WouldBeLocation(r.doc_id, "n", DOC_NESTED))
    assert result.state is S.PRESENT and result.path is DeclPath.DOCUMENT_LEVEL_FALLBACK


def test_a_bom_link_assembly_is_unresolved_and_never_covers():
    link = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#app"
    r = record([rec("complete", assemblies=[link])])
    assert derive(r, loc(r, "top_level")).reason is DR.NO_APPLICABLE_RECORD


# ---- unresolved inputs -----------------------------------------------------------------------------------------------

def test_missing_location_or_unspecified_placement_is_unknown_and_selects_nothing():
    r = record([rec("complete", assemblies=["app"]), rec("complete", assemblies=["p"])])
    assert derive_decl(r, None, bound(r.doc_id), inv(r.doc_id)).reason is DR.NO_TARGET_LOCATION
    unspecified = WouldBeLocation(r.doc_id, "p", None)  # schema 1: no placement
    assert derive_decl(r, unspecified, bound(r.doc_id), inv(r.doc_id)).reason is DR.PLACEMENT_UNSPECIFIED
    other = WouldBeLocation("another-document", "p", DOC_NESTED)
    assert derive_decl(r, other, bound(r.doc_id), inv(r.doc_id)).reason is DR.LOCATION_FOR_ANOTHER_DOCUMENT


def test_unresolved_parent_is_unknown():
    r = record([rec("complete", assemblies=["p"])])
    result = derive(r, WouldBeLocation(r.doc_id, "nope", DOC_NESTED))
    assert (result.state, result.reason) == (S.UNKNOWN, DR.TARGET_LOCATION_UNRESOLVED)


def test_no_candidate_is_unknown():
    r = record([rec("complete", assemblies=["other"])], components=[comp("parent", "p"), comp("other", "other")], root=False)
    assert derive(r).reason is DR.NO_APPLICABLE_RECORD
    assert derive(record([], root=False)).state is S.UNKNOWN


def test_unbound_document_has_no_declaration_about_s():
    r = record([rec("complete", assemblies=["p"])])
    result = derive_decl(r, loc(r), bound(r.doc_id, BindState.UNKNOWN), inv(r.doc_id))
    assert (result.state, result.reason) == (S.UNKNOWN, DR.BIND_NOT_MATCHED)


def test_spdx_has_no_completeness_declaration():
    spdx = s1.load_spdx("fixtures/spdx/subjects.json")
    location = WouldBeLocation(spdx.doc_id, "SPDXRef-appA", DOC_NESTED)
    result = derive_decl(spdx, location, bound(spdx.doc_id), inv(spdx.doc_id))
    assert (result.state, result.reason) == (S.UNKNOWN, DR.NO_COMPLETENESS_DECLARATION_FORMAT)


def test_document_identities_must_agree():
    r = record([rec("complete", assemblies=["p"])])
    assert derive_decl(r, loc(r), bound("other"), inv(r.doc_id)).reason is DR.DOCUMENT_IDENTITY_MISMATCH
    assert derive_decl(r, loc(r), bound(r.doc_id), inv("other")).reason is DR.DOCUMENT_IDENTITY_MISMATCH


# ---- invariants, purity ----------------------------------------------------------------------------------------------------

def test_only_present_incomplete_and_unknown_are_ever_produced():
    for state in (S.ABSENT, S.AMBIGUOUS, S.CONTRADICTORY):
        with pytest.raises(ValueError):
            DeclDerivation(state, DR.NO_APPLICABLE_RECORD, "d")
    with pytest.raises(ValueError):
        DeclDerivation(S.PRESENT, DR.COMPONENT_SPECIFIC_RECORD, "d")  # Present needs its records
    with pytest.raises(ValueError):
        DeclDerivation(S.PRESENT, DR.ROOT_RECORD_COVERS_S, "d", DeclPath.DOCUMENT_LEVEL_FALLBACK,
                       CoversSResult.NOT_ESTABLISHED, ("#/compositions/0",))


def test_pure_and_deterministic():
    r = record([rec("complete", assemblies=["app"]), rec("complete", assemblies=["p"])])
    snapshot = copy.deepcopy(r)
    first = derive(r)
    assert r == snapshot and derive(r) == first
