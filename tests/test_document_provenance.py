"""Tests for evidence.document_provenance: P2 from the BIND subject digest, P3 from a trusted
external verification result, locator-aware levels and the signed-coverage cap."""

import copy
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evidence.bind import BindBasis, BindCode, BindEvaluation, evaluate_bind
from evidence.cnp_rules import BindState
from evidence.document_provenance import (
    P2Status,
    VerificationUse,
    document_provenance,
    item_levels,
    minimum_level,
    record_consumed_integrity,
)
from evidence.profile import ScopeIdentity
from evidence.provenance import DiagnosticCode
from evidence.stage1_records import load_cyclonedx
from evidence.verification import VerificationConfig, VerificationResult
from model import ArtifactKind, EvidenceItem, EvidenceState, Integrity, ProvenanceLevel, SourceDocument

P0, P1, P2, P3 = ProvenanceLevel.P0, ProvenanceLevel.P1, ProvenanceLevel.P2, ProvenanceLevel.P3
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
WHEN = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
DOC = "d1"
X = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def document(doc_id=DOC, **changes):
    values = dict(doc_id=doc_id, producer="Team", tool_name="tool", tool_version="1.0", created=WHEN)
    values.update(changes)
    return SourceDocument(**values)


def bind(doc_id=DOC, *, state=BindState.MATCHED, basis=BindBasis.DIGEST, digests=("sha256:" + X,)):
    if state is BindState.MATCHED and basis is BindBasis.DIGEST:
        return BindEvaluation(state, basis, BindCode.DIGEST_MATCH, agreeing_digests=tuple(digests), document_id=doc_id)
    if state is BindState.MATCHED:
        return BindEvaluation(state, basis, BindCode.PRODUCT_VERSION_MATCH, document_id=doc_id)
    if state is BindState.MISMATCHED:
        return BindEvaluation(state, BindBasis.DIGEST, BindCode.DIGEST_MISMATCH, document_id=doc_id)
    return BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=doc_id)


def result(coverage=("#/components",), *, verified=True, anchor="anchor", doc_id=DOC):
    return VerificationResult(doc_id, verified, anchor, "verifier", "1", coverage)


def config(*results, anchors=("anchor",)):
    return VerificationConfig(frozenset(anchors), tuple(results))


# ---- P2 -----------------------------------------------------------------------------------------

def test_p2_needs_p1_and_a_matched_digest_bind_for_this_document():
    granted = document_provenance(document(), bind(), None)
    assert (granted.level, granted.p2, granted.p2_digests) == (P2, P2Status.GRANTED, ("sha256:" + X,))
    assert granted.attribution.level is P1


@pytest.mark.parametrize(
    "doc,b,status",
    [
        (document(tool_version=None), bind(), P2Status.NOT_P1),                                   # P2 is cumulative on P1
        (document(), None, P2Status.BIND_NOT_MATCHED),
        (document(), bind(state=BindState.UNKNOWN), P2Status.BIND_NOT_MATCHED),
        (document(), bind(state=BindState.MISMATCHED), P2Status.BIND_NOT_MATCHED),
        (document(), bind(basis=BindBasis.PRODUCT_VERSION), P2Status.BIND_BASIS_NOT_DIGEST),      # fallback never grants P2
        (document(), bind(doc_id="other"), P2Status.BIND_FOR_ANOTHER_DOCUMENT),
        (document(), dataclasses.replace(bind(), document_id=None), P2Status.BIND_FOR_ANOTHER_DOCUMENT),
        (document(), bind(digests=()), P2Status.NO_AGREEING_DIGEST),
    ],
)
def test_p2_is_not_granted_otherwise(doc, b, status):
    provenance = document_provenance(doc, b, None)
    assert provenance.p2 is status and provenance.p2_digests == ()
    assert provenance.level is doc_level(doc)


def doc_level(doc):
    return P1 if doc.tool_version else P0


def test_a_hash_on_a_listed_component_never_grants_p2_but_the_subject_digest_does():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    scope = ScopeIdentity("pkg:generic/app@2.0.0", "2.0.0", ("sha256:" + X,), ArtifactKind.CONTAINER)
    matched = evaluate_bind(scope, record)  # the subject's SHA-256 equals X
    assert matched.basis is BindBasis.DIGEST
    assert document_provenance(record.document, matched, None).level is P2
    # a scope whose digest equals only a listed component's hash is not bound by it
    other = ScopeIdentity("pkg:generic/app@2.0.0", "2.0.0", ("sha256:" + "11" * 32,), ArtifactKind.CONTAINER)
    assert document_provenance(record.document, evaluate_bind(other, record), None).level is P1


def test_a_declared_signature_or_digest_binding_in_the_document_grants_nothing():
    forged = document(integrity=Integrity(artifact_digest_binding="sha256:" + X, signature="sig",
                                          signature_verified=True, trust_anchor_id="anchor",
                                          established_coverage=["#"], signed_coverage=["#"]))
    provenance = document_provenance(forged, None, None)
    assert provenance.level is P1 and provenance.verification is VerificationUse.NOT_SUPPLIED
    assert provenance.level_at("#/components") is P1


# ---- P3 and the signed-coverage cap ----------------------------------------------------------------------

def p2_document(coverage_result):
    return document_provenance(document(), bind(), config(coverage_result) if coverage_result else None)


def test_p3_only_inside_verified_coverage_and_the_cap_outside_it():
    provenance = p2_document(result(("#/components",)))
    assert provenance.verification is VerificationUse.APPLIED and provenance.level is P2
    assert provenance.level_at("#/components") is P3
    assert provenance.level_at("#/components/0") is P3            # descendants of a covered pointer
    assert provenance.level_at("#/components/0/components/1") is P3
    assert provenance.level_at("#/compositions/0") is P1          # outside established coverage: min(level, P1)
    assert provenance.level_at(None) is P1                        # a missing locator is outside coverage (G3d)
    assert provenance.level_at("#") is P1                         # the parent of the covered pointer is not covered


def test_coverage_of_a_child_does_not_cover_the_list_and_a_root_covers_everything():
    child = p2_document(result(("#/components/0",)))
    assert child.level_at("#/components/0") is P3 and child.level_at("#/components") is P1
    assert child.level_at("#/components/1") is P1 and child.level_at("#/components/10") is P1
    root = p2_document(result(("#",)))
    assert all(root.level_at(loc) is P3 for loc in ("#", "#/components", "#/compositions/0", "#/metadata/component/components"))
    empty = p2_document(result(()))
    assert empty.verification is VerificationUse.APPLIED and empty.level_at("#/components") is P1  # verified-empty coverage


def test_p3_is_cumulative_and_never_raises_a_p1_document():
    p1_only = document_provenance(document(), bind(basis=BindBasis.PRODUCT_VERSION), config(result(("#",))))
    assert p1_only.level is P1 and p1_only.level_at("#/components") is P1
    p0 = document_provenance(document(tool_name=None), bind(), config(result(("#",))))
    assert p0.level is P0 and p0.level_at("#/components") is P0


@pytest.mark.parametrize(
    "cfg,use",
    [
        (None, VerificationUse.NOT_SUPPLIED),
        (config(), VerificationUse.NO_RESULT_FOR_DOCUMENT),
        (config(result(doc_id="d2")), VerificationUse.NO_RESULT_FOR_DOCUMENT),                       # bound to the exact doc_id
        (config(result(doc_id="D1")), VerificationUse.NO_RESULT_FOR_DOCUMENT),
        (config(result(anchor="stranger")), VerificationUse.UNTRUSTED_ANCHOR),                       # anchor not configured
        (config(result(verified=False)), VerificationUse.NOT_VERIFIED),
        (config(result(coverage=None)), VerificationUse.COVERAGE_NOT_ESTABLISHED),
    ],
)
def test_a_missing_mismatched_untrusted_or_negative_result_cannot_grant_p3_and_applies_no_cap(cfg, use):
    provenance = document_provenance(document(), bind(), cfg)
    assert provenance.verification is use and provenance.level is P2
    for locator in ("#/components", "#/compositions/0", None):
        assert provenance.level_at(locator) is P2  # neither P3 nor the cap: coverage is not established
    assert any(lim.startswith("P3_NOT_AVAILABLE") for lim in provenance.limitations)


def test_parsed_integrity_fields_are_never_read_as_verification():
    signed = load_cyclonedx(FIXTURES / "cyclonedx" / "signed_root.json").document
    assert signed.integrity.signature is not None and signed.integrity.signature_verified is None
    provenance = document_provenance(signed, None, None)
    assert provenance.verification is VerificationUse.NOT_SUPPLIED and provenance.level is P0
    assert provenance.attribution.integrity.signature_declared is True


def test_purity_and_determinism():
    doc, b, cfg = document(), bind(), config(result(("#/components",)))
    snapshot = copy.deepcopy((doc, b, cfg))
    first = document_provenance(doc, b, cfg)
    assert (doc, b, cfg) == snapshot and document_provenance(doc, b, cfg) == first
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.level = P3


# ---- recording what was consumed ---------------------------------------------------------------------------------

def test_consumed_integrity_is_recorded_only_on_the_given_copy():
    original = document()
    provenance = document_provenance(original, bind(), config(result(("#/components",))))
    own_copy = copy.deepcopy(original)
    record_consumed_integrity(own_copy, provenance)
    integrity = own_copy.integrity
    assert integrity.signature_verified is True and integrity.trust_anchor_id == "anchor"
    assert integrity.established_coverage == ["#/components"]
    assert integrity.artifact_digest_binding == "sha256:" + X
    assert original.integrity == Integrity()  # the original (parsed) record is untouched


def test_nothing_is_recorded_without_an_approved_source():
    for cfg, b in ((None, None), (config(result(anchor="stranger")), None), (config(result(doc_id="other")), None)):
        copy_doc = document()
        record_consumed_integrity(copy_doc, document_provenance(copy_doc, b, cfg))
        assert copy_doc.integrity == Integrity()
    negative = document()
    record_consumed_integrity(negative, document_provenance(negative, None, config(result(verified=False))))
    assert negative.integrity.signature_verified is False and negative.integrity.established_coverage is None
    assert negative.integrity.artifact_digest_binding is None


# ---- item levels -----------------------------------------------------------------------------------------------------

def item(item_id, locator, *, doc=DOC, derived_from=()):
    return EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=doc, locator=locator, item_id=item_id,
                        derived_from=list(derived_from))


def test_item_levels_use_the_locator_and_the_derived_from_minimum():
    provenance = {DOC: document_provenance(document(), bind(), config(result(("#/components",))))}
    items = [
        item("a", "#/components"),
        item("b", "#/compositions/0"),
        item("c", "#/components", derived_from=["b"]),
        item("d", None),
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=None, item_id="e"),
        item("f", "#/components", doc="not-supplied"),
    ]
    results = item_levels(items, provenance)
    assert [r.level for r in results] == [P3, P1, P1, P1, P0, P0]
    assert DiagnosticCode.SOURCE_DOC_LEVEL_UNAVAILABLE in [d.code for d in results[5].diagnostics]
    assert items[0].source_doc == DOC  # the input items are not rewritten


def test_minimum_level_over_list_locators():
    provenance = document_provenance(document(), bind(), config(result(("#/components",))))
    assert minimum_level(provenance, ["#/components"]) is P3
    assert minimum_level(provenance, ["#/components", "#/metadata/component/components"]) is P1
    assert minimum_level(provenance, []) is P2  # no list locator exists: no locator-specific claim
    assert minimum_level(provenance, [None]) is P1


def test_a_locator_that_is_not_in_the_document_is_never_claimed_covered():
    provenance = document_provenance(document(), bind(), config(result(("#/packages",))))
    assert provenance.level_at("#/components") is P1  # coverage of an unrelated pointer


def _detached_limitation(provenance):
    return [lim for lim in provenance.limitations if lim.startswith("P3_FROM_DETACHED_VERIFICATION_RESULT")]


def test_a_detached_verification_result_is_accepted_for_a_document_without_a_signature_and_labelled_as_such():
    unsigned = document_provenance(document(), bind(), config(result(("#",))))
    assert unsigned.verification is VerificationUse.APPLIED and unsigned.level_at("#/components") is P3
    [note] = _detached_limitation(unsigned)
    assert "declares no embedded signature" in note and "not on a signature the document carries" in note
    signed_document = document(integrity=Integrity(signature='[{"covers": "#", "signature": {}}]'))
    signed = document_provenance(signed_document, bind(), config(result(("#",))))
    assert signed.verification is VerificationUse.APPLIED and signed.level_at("#/components") is P3
    assert _detached_limitation(signed) == []


def test_a_declared_signature_and_declared_coverage_alone_never_grant_p3_or_the_cap():
    declared = document(integrity=Integrity(signature='[{"covers": "#/components", "signature": {}}]',
                                            signed_coverage=["#/components"]))
    provenance = document_provenance(declared, bind(), None)
    assert provenance.level is P2 and provenance.verification is VerificationUse.NOT_SUPPLIED
    assert provenance.level_at("#/components") is P2 and provenance.level_at("#/compositions/0") is P2
