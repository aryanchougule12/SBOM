"""Tests for evidence.reach_items: typed REACH / LOCUS / ENTRY items and their integrity validation.

Items are taken from a real end-to-end run (SYNTHETIC reachability evidence) and then tampered with;
the validator must reject every item that claims more than its facts support or that cannot be traced.
"""

import dataclasses

import pytest

from evidence.items import ItemIntegrityError
from evidence.reach_items import EntryPayload, LocusPayload, ReachPayload, validate_reach_items
from model import DocumentRole, EvidenceItem, EvidenceState as S
from tests.reach_support import add_doc, baseline_data, run, verified


@pytest.fixture(scope="module")
def outcome():
    data = add_doc(baseline_data(), doc_id="k3-trace", kind="K3", finding="negative", analyzed_configurations=["prod"])
    data["entry_points"] = {"complete": True, "entered_by": "t"}
    return run("cdx", data, verification=verified("k1-analysis"))


def pick(outcome, dimension, source=None, kind=None):
    return next(i for i in outcome.items if i.dimension == dimension and i.source_doc == source
                and (kind is None or i.value_or_ref.kind == kind))


def check(outcome, items):
    validate_reach_items(outcome.finding, outcome.doc_id, items)


def replaced(outcome, original, **changes):
    return [dataclasses.replace(original, **changes) if i is original else i for i in outcome.items]


def test_the_untouched_items_validate(outcome):
    check(outcome, outcome.items)
    assert {i.dimension for i in outcome.items} == {"REACH", "LOCUS", "ENTRY"}


def test_the_expected_items_exist_with_the_expected_states(outcome):
    assert pick(outcome, "REACH", "k1-analysis").state is S.ABSENT
    assert pick(outcome, "REACH", "k3-trace").state is S.INCOMPLETE
    assert pick(outcome, "REACH", outcome.doc_id, "K4").state is S.UNKNOWN
    assert pick(outcome, "LOCUS").state is S.PRESENT


TAMPERING = [
    ("k1_absent_without_claim", "REACH", "k1-analysis",
     lambda i: dict(value_or_ref=dataclasses.replace(i.value_or_ref, full_coverage_claim=False)), "ITEM_CLAIM_UNSUPPORTED"),
    ("k3_claimed_absent", "REACH", "k3-trace", lambda i: dict(state=S.ABSENT), "ITEM_CLAIM_UNSUPPORTED"),
    ("k3_claimed_present", "REACH", "k3-trace", lambda i: dict(state=S.PRESENT), "ITEM_CLAIM_UNSUPPORTED"),
    ("k4_claimed_present", "REACH", "K4", lambda i: dict(state=S.PRESENT), "ITEM_CLAIM_UNSUPPORTED"),
    ("k4_claimed_incomplete", "REACH", "K4", lambda i: dict(state=S.INCOMPLETE), "ITEM_CLAIM_UNSUPPORTED"),
    ("reach_state_not_allowed", "REACH", "k1-analysis", lambda i: dict(state=S.CONTRADICTORY), "ITEM_STATE_NOT_ALLOWED"),
    ("entry_state_not_allowed", "ENTRY", "k1-analysis", lambda i: dict(state=S.UNKNOWN), "ITEM_STATE_NOT_ALLOWED"),
    ("locus_overclaimed", "LOCUS", None, lambda i: dict(state=S.INCOMPLETE), "ITEM_CLAIM_UNSUPPORTED"),
    ("entry_overclaimed", "ENTRY", "k1-analysis", lambda i: dict(state=S.INCOMPLETE), "ITEM_CLAIM_UNSUPPORTED"),
    ("source_not_registered", "REACH", "k1-analysis", lambda i: dict(source_doc="ghost"), "ITEM_SOURCE_NOT_REGISTERED"),
    ("document_item_without_source", "REACH", "k1-analysis", lambda i: dict(source_doc=None), "ITEM_SOURCE_MISSING"),
    ("locus_with_a_source", "LOCUS", None, lambda i: dict(source_doc="k1-analysis", locator="#/finding"), "ITEM_SOURCE_NOT_ALLOWED"),
    ("wrong_locator", "REACH", "k1-analysis", lambda i: dict(locator="#/entry_points"), "ITEM_LOCATOR_NOT_IN_DOCUMENT"),
    ("derived_from", "REACH", "k1-analysis", lambda i: dict(derived_from=["x"]), "ITEM_PARENT_MISSING"),
    ("unknown_dimension", "REACH", "k1-analysis", lambda i: dict(dimension="HAZ[REFLECTION]"), "ITEM_DIMENSION_INVALID"),
    ("payload_of_another_dimension", "REACH", "k1-analysis",
     lambda i: dict(value_or_ref=EntryPayload("ENTRY", "x")), "ITEM_PAYLOAD_INVALID"),
    ("no_id", "REACH", "k1-analysis", lambda i: dict(item_id=None), "ITEM_ID_MISSING"),
    ("bad_state_type", "REACH", "k1-analysis", lambda i: dict(state="Absent"), "ITEM_STATE_INVALID"),
]


@pytest.mark.parametrize("label, dimension, source, change, code", TAMPERING, ids=[t[0] for t in TAMPERING])
def test_a_tampered_item_is_rejected_with_a_stable_code(outcome, label, dimension, source, change, code):
    if source == "K4":
        original = pick(outcome, dimension, outcome.doc_id, "K4")
    else:
        original = pick(outcome, dimension, source)
    with pytest.raises(ItemIntegrityError) as error:
        check(outcome, replaced(outcome, original, **change(original)))
    assert error.value.code == code


def test_duplicate_ids_are_rejected(outcome):
    with pytest.raises(ItemIntegrityError) as error:
        check(outcome, list(outcome.items) + [outcome.items[0]])
    assert error.value.code == "ITEM_ID_DUPLICATE"


def test_a_report_without_the_reachability_role_is_rejected(outcome):
    finding = dataclasses.replace(outcome.finding, document_roles={**outcome.finding.document_roles, "k1-analysis": DocumentRole.OTHER})
    with pytest.raises(ItemIntegrityError) as error:
        validate_reach_items(finding, outcome.doc_id, outcome.items)
    assert error.value.code == "ITEM_ROLE_MISSING"


def test_the_k4_item_must_belong_to_the_primary_sbom_at_its_root(outcome):
    k4 = pick(outcome, "REACH", outcome.doc_id, "K4")
    with pytest.raises(ItemIntegrityError):
        check(outcome, replaced(outcome, k4, locator="#/dependencies"))
    with pytest.raises(ItemIntegrityError):
        check(outcome, replaced(outcome, k4, source_doc="k1-analysis", locator="#/finding"))


def test_payload_types_are_frozen():
    payload = ReachPayload("REACH", "r", kind="K1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        payload.kind = "K2"  # type: ignore[misc]
    assert isinstance(EvidenceItem("REACH", S.UNKNOWN), EvidenceItem) and LocusPayload("LOCUS", "r").locus is None
