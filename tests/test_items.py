"""Tests for evidence.items: item construction and the traceability validator, plus the GEN
derivation and the CNP adapter (evidence.generation, evidence.cnp_adapter)."""

import copy
import dataclasses
import json

import pytest

from evidence import cnp_adapter as CA
from evidence import items as IT
from evidence.bind import BindBasis, BindCode, BindEvaluation
from evidence.cnp_rules import BindState, GenState
from evidence.evaluator import evaluate
from evidence.generation import GEN_LIMITATION, GenDerivation, derive_gen
from evidence.inventory_members import inventory_members
from evidence.items import ItemIntegrityError as IIE
from evidence.stage1_records import Stage1Index, load_cyclonedx
from model import ArtifactKind, DocumentRole, EvidenceItem, EvidenceState as S, ProvenanceLevel as P
from tests.pipeline_support import ABSENT, cdx, equivalent, make_profile, vex_findings, verification_for

ROOT_NESTED = {"placement": "nested_under_component", "parent_ref": "app-1"}


def outcome_for(record=None, **kw):
    record = record or equivalent("cdx")
    profile = make_profile(record.doc_id, target=kw.pop("target", ABSENT), location=kw.pop("location", ROOT_NESTED), **kw)
    out = evaluate(profile, vex_findings(), Stage1Index([record]), verification_for(record.doc_id, ("#/components", "#/compositions/0", "#/packages")))
    assert not hasattr(out, "code"), out
    return record, out


def check(out, record, items):
    IT.validate_items(out.finding, record, inventory_members(record), items)


# ---- construction -----------------------------------------------------------------------------------------------

def test_items_are_built_in_a_fixed_dimension_order_with_deterministic_ids():
    record, out = outcome_for()
    assert [i.dimension for i in out.items] == ["INV", "DECL", "MATCH", "GEN"]
    assert [i.item_id for i in out.items] == [
        f"INV:{record.doc_id}:#/components",
        f"DECL:{record.doc_id}:#/compositions/0",
        f"MATCH:{record.doc_id}:#/components:none",
        f"GEN:{record.doc_id}:-",
    ]
    again = outcome_for(record)[1]
    assert [i.item_id for i in again.items] == [i.item_id for i in out.items]


def test_match_absent_is_derived_from_the_inventory_items():
    record, out = outcome_for()
    match = IT.items_of(out.items, "MATCH")[0]
    assert match.state is S.ABSENT and match.derived_from == [i.item_id for i in IT.items_of(out.items, "INV")]


def test_each_list_level_locator_gets_its_own_inv_item():
    record, out = outcome_for(cdx("subject_nested.json"), location={"placement": "top_level"})
    locators = sorted(i.locator for i in IT.items_of(out.items, "INV"))
    assert locators == ["#/components", "#/metadata/component/components"]


def test_a_present_match_item_is_attached_to_the_matching_member():
    record, out = outcome_for(target={"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"})
    [match] = IT.items_of(out.items, "MATCH")
    assert match.state is S.PRESENT and match.locator == "#/components/1/components/0" and match.derived_from == []
    assert match.value_or_ref.member_locator == match.locator


def test_payloads_keep_the_derivation_reason_and_limitations():
    record, out = outcome_for()
    inv, decl, match, gen = (IT.items_of(out.items, d)[0] for d in ("INV", "DECL", "MATCH", "GEN"))
    assert inv.value_or_ref.derivation is out.inv and inv.value_or_ref.reason == out.inv.reason.value
    assert decl.value_or_ref.derivation is out.decl and decl.value_or_ref.record_locators == out.decl.record_locators
    assert match.value_or_ref.derivation is out.match
    assert gen.state is S.UNKNOWN and gen.value_or_ref.limitations == (GEN_LIMITATION,)
    with pytest.raises(dataclasses.FrozenInstanceError):
        inv.value_or_ref.reason = "x"


def test_no_item_has_a_bind_dimension_or_a_seventh_state():
    record, out = outcome_for()
    assert "BIND" not in {i.dimension for i in out.items}
    assert {i.state for i in out.items} <= set(S)


def test_derivations_for_another_document_are_refused():
    record, out = outcome_for()
    members = inventory_members(record)
    with pytest.raises(IIE) as e:
        IT.build_items("another-doc", members, out.inv, out.decl, out.match, out.gen)
    assert e.value.code == "ITEM_DOCUMENT_MISMATCH"


# ---- validator: every tamper is caught -----------------------------------------------------------------------------

def tamper(out, record, index, **changes):
    items = list(out.items)
    items[index] = dataclasses.replace(items[index], **changes)
    return items


@pytest.mark.parametrize(
    "changes,code",
    [
        (dict(source_doc="not-registered"), "ITEM_SOURCE_NOT_REGISTERED"),
        (dict(source_doc=None), "ITEM_SOURCE_NOT_REGISTERED"),
        (dict(locator="#/components/99"), "ITEM_LOCATOR_NOT_IN_DOCUMENT"),
        (dict(locator="#/compositions/7"), "ITEM_LOCATOR_NOT_IN_DOCUMENT"),
        (dict(item_id=""), "ITEM_ID_MISSING"),
        (dict(derived_from=["nope"]), "ITEM_PARENT_MISSING"),
    ],
)
def test_the_validator_catches_tampered_items(changes, code):
    record, out = outcome_for()
    check(out, record, out.items)
    with pytest.raises(IIE) as e:
        check(out, record, tamper(out, record, 1, **changes))
    assert e.value.code == code


def test_duplicate_ids_self_parent_and_cycles_are_caught():
    record, out = outcome_for()
    items = list(out.items)
    with pytest.raises(IIE) as e:
        check(out, record, items + [items[0]])
    assert e.value.code == "ITEM_ID_DUPLICATE"
    selfie = tamper(out, record, 1, derived_from=[out.items[1].item_id])
    with pytest.raises(IIE) as e:
        check(out, record, selfie)
    assert e.value.code == "ITEM_PARENT_SELF"
    a, b = out.items[1], out.items[3]
    cyc = list(out.items)
    cyc[1] = dataclasses.replace(a, derived_from=[b.item_id])
    cyc[3] = dataclasses.replace(b, derived_from=[a.item_id])
    with pytest.raises(IIE) as e:
        check(out, record, cyc)
    assert e.value.code == "ITEM_DERIVATION_CYCLE"


def test_a_parent_from_another_document_is_caught():
    record, out = outcome_for()
    foreign = EvidenceItem("INV", S.UNKNOWN, None, "other-doc", None, [], "FOREIGN")
    items = list(out.items) + [foreign]
    items[1] = dataclasses.replace(items[1], derived_from=["FOREIGN"])
    with pytest.raises(IIE) as e:
        check(out, record, items)
    assert e.value.code in {"ITEM_SOURCE_NOT_REGISTERED", "ITEM_PARENT_DOCUMENT_MISMATCH"}


def test_a_document_without_the_primary_sbom_role_is_caught():
    record, out = outcome_for()
    finding = dataclasses.replace(out.finding, document_roles={record.doc_id: DocumentRole.CORROBORATING})
    with pytest.raises(IIE) as e:
        IT.validate_items(finding, record, inventory_members(record), out.items)
    assert e.value.code == "ITEM_ROLE_MISSING"
    finding = dataclasses.replace(out.finding, document_roles={})
    with pytest.raises(IIE) as e:
        IT.validate_items(finding, record, inventory_members(record), out.items)
    assert e.value.code == "ITEM_ROLE_MISSING"


def test_a_registered_document_that_is_not_the_primary_record_is_caught():
    record, out = outcome_for()
    other = cdx("dangling_local.json")
    finding = dataclasses.replace(out.finding, source_documents={**out.finding.source_documents, other.doc_id: other.document},
                                  document_roles={**out.finding.document_roles, other.doc_id: DocumentRole.PRIMARY_SBOM})
    items = tamper(out, record, 0, source_doc=other.doc_id)
    with pytest.raises(IIE) as e:
        IT.validate_items(finding, record, inventory_members(record), items)
    assert e.value.code == "ITEM_DOCUMENT_MISMATCH"


def test_known_locators_are_exactly_the_documents_own():
    record = cdx("subject_nested.json")
    known = IT.known_locators(record, inventory_members(record))
    assert {"#", "#/components", "#/metadata/component/components", "#/components/1/components/0",
            "#/metadata/component/components/0/components/0", "#/compositions/0"} <= known
    assert "#/components/9" not in known and "#/services" not in known


def test_the_integrity_error_carries_a_stable_code_and_the_item():
    error = IIE("ITEM_X", "id-1", "msg")
    assert (error.code, error.item_id, error.message) == ("ITEM_X", "id-1", "msg") and "ITEM_X" in str(error)


# ---- GEN ------------------------------------------------------------------------------------------------------------------

def test_gen_is_always_unknown_with_a_precise_limitation():
    for record in (equivalent("cdx"), equivalent("spdx"), cdx("subject_nested.json")):
        gen = derive_gen(record)
        assert gen.state is GenState.UNKNOWN and gen.doc_id == record.doc_id
        assert gen.limitations[0] == GEN_LIMITATION and "G14" in GEN_LIMITATION and "D10" in GEN_LIMITATION


def test_gen_is_not_inferred_from_the_tool_name_context_or_kind():
    record = equivalent("cdx")
    assert derive_gen(record).state is GenState.UNKNOWN
    with_method = dataclasses.replace(record, document=dataclasses.replace(record.document, method="syft-content-scan", generation_context="build"))
    gen = derive_gen(with_method)
    assert gen.state is GenState.UNKNOWN and any("not classified" in l for l in gen.limitations)


def test_a_gen_derivation_cannot_be_anything_but_unknown():
    for state in (GenState.CONTENT_BASED, GenState.MANIFEST_ONLY):
        with pytest.raises(ValueError):
            GenDerivation(state, "x", "d", ())


# ---- adapter ------------------------------------------------------------------------------------------------------------

def test_the_adapter_aggregates_items_and_builds_inputs_without_adding_anything():
    record, out = outcome_for()
    aggregates = CA.aggregate_dimensions(out.items)
    assert (aggregates.inv.state, aggregates.match.state, aggregates.decl.state) == (S.PRESENT, S.ABSENT, S.PRESENT)
    inputs = CA.build_cnp_inputs(ArtifactKind.SOURCE, aggregates, out.bind, P.P3, P.P3)
    assert inputs == out.cnp_inputs
    assert inputs.separate_basis is None and inputs.provenance_metadata_contradiction is False and inputs.gen is GenState.UNKNOWN


def test_prov_decl_is_dropped_unless_decl_is_present():
    record, out = outcome_for(location={"placement": "top_level", **{}}, assertion=False)
    aggregates = CA.aggregate_dimensions(out.items)
    assert aggregates.decl.state is not S.PRESENT
    inputs = CA.build_cnp_inputs(ArtifactKind.SOURCE, aggregates, out.bind, P.P3, P.P3)
    assert inputs.prov_decl is None


def test_a_dimension_without_items_aggregates_to_unknown():
    aggregates = CA.aggregate_dimensions([])
    assert {aggregates.inv.state, aggregates.match.state, aggregates.decl.state} == {S.UNKNOWN}


def test_bind_state_is_the_typed_input_not_an_item_state():
    record, out = outcome_for()
    unmatched = BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=record.doc_id)
    inputs = CA.build_cnp_inputs(ArtifactKind.SOURCE, CA.aggregate_dimensions(out.items), unmatched, P.P3, P.P3)
    assert inputs.bind is BindState.UNKNOWN


# ---- validator: an item never claims more than its derivation supports -------------------------------------------

def _item(out, dimension):
    return IT.items_of(out.items, dimension)[0]


def _replace_item(out, old, **changes):
    return [dataclasses.replace(i, **changes) if i is old else i for i in out.items]


@pytest.mark.parametrize(
    "dimension,changes,code",
    [
        ("INV", dict(dimension="BIND"), "ITEM_DIMENSION_INVALID"),
        ("INV", dict(dimension="inv"), "ITEM_DIMENSION_INVALID"),
        ("INV", dict(state=S.ABSENT), "ITEM_STATE_NOT_ALLOWED"),
        ("INV", dict(state=S.AMBIGUOUS), "ITEM_STATE_NOT_ALLOWED"),
        ("DECL", dict(state=S.CONTRADICTORY), "ITEM_STATE_NOT_ALLOWED"),
        ("MATCH", dict(state=S.CONTRADICTORY), "ITEM_STATE_NOT_ALLOWED"),
        ("GEN", dict(state=S.PRESENT), "ITEM_STATE_NOT_ALLOWED"),
        ("INV", dict(state="Present"), "ITEM_STATE_INVALID"),
        ("INV", dict(value_or_ref=None), "ITEM_PAYLOAD_INVALID"),
        ("INV", dict(value_or_ref="Present"), "ITEM_PAYLOAD_INVALID"),
        ("DECL", dict(value_or_ref=IT.GenPayload(IT.DIM_GEN, "x")), "ITEM_PAYLOAD_INVALID"),
        ("INV", dict(locator="#/compositions/0"), "ITEM_LOCATOR_NOT_IN_DERIVATION"),
    ],
)
def test_invalid_dimensions_states_and_payloads_are_rejected(dimension, changes, code):
    record, out = outcome_for()
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, _item(out, dimension), **changes))
    assert e.value.code == code


def test_a_state_stronger_than_the_derivation_is_rejected():
    # no INV assertion: INV derives Unknown; an item that says Present claims more than that
    record, out = outcome_for(assertion=False)
    inv = _item(out, "INV")
    assert inv.state is S.UNKNOWN
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, inv, state=S.PRESENT))
    assert e.value.code == "ITEM_STATE_UNSUPPORTED_BY_DERIVATION"
    # the same for MATCH (Absent claimed over an Unknown derivation) and DECL
    record, out = outcome_for(assertion=False)
    match = _item(out, "MATCH")
    assert match.state is S.UNKNOWN
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, match, state=S.ABSENT))
    assert e.value.code == "ITEM_STATE_UNSUPPORTED_BY_DERIVATION"
    record, out = outcome_for(assertion=False, location={"placement": "top_level"})  # root fallback does not cover S
    decl = _item(out, "DECL")
    assert decl.state is S.UNKNOWN
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, decl, state=S.PRESENT))
    assert e.value.code == "ITEM_STATE_UNSUPPORTED_BY_DERIVATION"


def test_a_derivation_of_another_document_is_rejected():
    record, out = outcome_for()
    match = _item(out, "MATCH")
    foreign = dataclasses.replace(match.value_or_ref, derivation=dataclasses.replace(match.value_or_ref.derivation, doc_id="another-doc"))
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, match, value_or_ref=foreign))
    assert e.value.code == "ITEM_DOCUMENT_MISMATCH"


def test_match_absent_must_derive_from_present_inventory_items_only():
    record, out = outcome_for()
    match = _item(out, "MATCH")
    assert match.state is S.ABSENT
    for derived_from in ([], [_item(out, "DECL").item_id], [_item(out, "GEN").item_id]):
        with pytest.raises(IIE) as e:
            check(out, record, _replace_item(out, match, derived_from=derived_from))
        assert e.value.code == "ITEM_CLAIM_UNSUPPORTED", derived_from


def test_match_absent_needs_a_fully_extracted_member_domain():
    record, out = outcome_for(cdx("subject_nested.json"), location={"placement": "top_level"})
    assert _item(out, "MATCH").state is S.ABSENT
    unextracted = dataclasses.replace(inventory_members(record), domain_extracted=False)
    with pytest.raises(IIE) as e:
        IT.validate_items(out.finding, record, unextracted, out.items)
    assert e.value.code == "ITEM_CLAIM_UNSUPPORTED"


def test_a_present_match_must_name_the_member_that_matched():
    record, out = outcome_for(target={"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"})
    match = _item(out, "MATCH")
    assert match.state is S.PRESENT
    for locator in (None, "#/components/0"):  # missing, or a real member that did not match
        with pytest.raises(IIE) as e:
            check(out, record, _replace_item(out, match, locator=locator))
        assert e.value.code == "ITEM_CLAIM_UNSUPPORTED", locator


def test_a_present_declaration_must_name_a_composition_record_that_exists():
    record, out = outcome_for()
    decl = _item(out, "DECL")
    assert decl.state is S.PRESENT
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, decl, locator=None))
    assert e.value.code == "ITEM_CLAIM_UNSUPPORTED"
    forged = dataclasses.replace(decl.value_or_ref, record_locators=("#/compositions/9",))
    with pytest.raises(IIE) as e:
        check(out, record, _replace_item(out, decl, value_or_ref=forged))
    assert e.value.code == "ITEM_LOCATOR_NOT_IN_DOCUMENT"


def test_inv_present_needs_an_identity_verified_bind_matched_derivation():
    record, out = outcome_for()
    inv = _item(out, "INV")
    assert inv.state is S.PRESENT
    for attribute, value in (("identity_verified", False), ("bind_state", BindState.UNKNOWN)):
        weakened = copy.copy(out.inv)  # the derivation type guards itself; bypass it to test the validator
        object.__setattr__(weakened, attribute, value)
        payload = dataclasses.replace(inv.value_or_ref, derivation=weakened)
        with pytest.raises(IIE) as e:
            check(out, record, _replace_item(out, inv, value_or_ref=payload))
        assert e.value.code == "ITEM_CLAIM_UNSUPPORTED", attribute


def test_the_untampered_items_of_every_scenario_pass_the_stronger_validator():
    for kwargs in (dict(), dict(location={"placement": "top_level"}), dict(assertion=False),
                   dict(target={"name": "lib-a", "version": "1.0"}), dict(target={"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"})):
        for record in (equivalent("cdx"), equivalent("spdx"), cdx("subject_nested.json"), cdx("dangling_local.json")):
            rec, out = outcome_for(record, **kwargs)
            check(out, rec, out.items)


def test_a_weak_match_beside_a_strong_one_is_not_a_present_item():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app-1", "version": "2.0.0",
                                       "hashes": [{"alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}},
            "components": [{"type": "library", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0", "bom-ref": "a1"},
                           {"type": "library", "name": "lib-a", "version": "1.0", "bom-ref": "a2"}],
            "compositions": [{"aggregate": "complete", "assemblies": ["app-1"]}]}
    record = load_cyclonedx(json.dumps(data).encode())
    rec, out = outcome_for(record, target={"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"})
    assert {m.strength for m in out.match.matches} == {"strong", "weak"}
    match_items = IT.items_of(out.items, "MATCH")
    assert [(i.state, i.locator) for i in match_items] == [(S.PRESENT, "#/components/0")]
    # and an Ambiguous derivation is carried by the weak members only
    rec, out = outcome_for(record, target={"name": "lib-a", "version": "1.0"})
    assert out.match.state is S.AMBIGUOUS and len(out.match.matches) == 2
    assert [i.locator for i in IT.items_of(out.items, "MATCH")] == ["#/components/0", "#/components/1"]


def test_a_present_item_at_a_weak_match_locator_is_rejected():
    record, out = outcome_for(target={"name": "lib-c", "version": "3.0"})  # name+version only: Ambiguous
    match = _item(out, "MATCH")
    assert match.state is S.AMBIGUOUS
    with pytest.raises(IIE) as e:  # claiming Present at a weak match: derivation says Ambiguous
        check(out, record, _replace_item(out, match, state=S.PRESENT))
    assert e.value.code == "ITEM_STATE_UNSUPPORTED_BY_DERIVATION"
