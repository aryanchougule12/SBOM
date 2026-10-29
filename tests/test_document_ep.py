"""Tests for evidence.provenance.document_level_ep (specification section 1.2 step 2, P0/P1 only).

The approved boundary (register G3b, decision 1): P1 needs a tool or process identity, a tool
version and a timestamp. P2 and P3 are never granted here, and a declared signature or declared
signed coverage is a claim, never verification.
"""

import copy
import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evidence.provenance import (
    AttributionGap as G,
    DeclaredIntegrity,
    EpLimitation as L,
    document_level_ep,
    document_levels,
    effective_provenance_all,
    DiagnosticCode,
)
from evidence.stage1_records import load_cyclonedx, load_openvex, load_spdx
from model import EvidenceItem, EvidenceState, Integrity, ProvenanceLevel, SourceDocument

P0, P1 = ProvenanceLevel.P0, ProvenanceLevel.P1
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
WHEN = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)


def document(**changes):
    values = dict(doc_id="d", producer="Example Team", tool_name="tool", tool_version="1.0", created=WHEN)
    values.update(changes)
    return SourceDocument(**values)


# ---- the approved P0/P1 conditions --------------------------------------------------------------------

def test_p1_needs_tool_identity_version_and_timestamp():
    result = document_level_ep(document())
    assert result.level is P1 and result.attribution_gaps == () and result.producer_declared


@pytest.mark.parametrize(
    "changes,gaps",
    [
        ({"tool_name": None}, (G.TOOL_NAME_MISSING,)),
        ({"tool_version": None}, (G.TOOL_VERSION_MISSING,)),
        ({"created": None}, (G.CREATED_MISSING,)),
        ({"tool_name": None, "tool_version": None}, (G.TOOL_NAME_MISSING, G.TOOL_VERSION_MISSING)),
        ({"tool_name": None, "tool_version": None, "created": None},
         (G.TOOL_NAME_MISSING, G.TOOL_VERSION_MISSING, G.CREATED_MISSING)),
        ({"tool_name": ""}, (G.TOOL_NAME_MISSING,)),
        ({"tool_name": "   "}, (G.TOOL_NAME_MISSING,)),
        ({"tool_version": "\t"}, (G.TOOL_VERSION_MISSING,)),
    ],
)
def test_each_missing_condition_is_p0_with_its_gap(changes, gaps):
    result = document_level_ep(document(**changes))
    assert result.level is P0 and result.attribution_gaps == gaps


def test_a_producer_alone_is_not_enough_under_the_strict_reading():
    result = document_level_ep(document(tool_name=None, tool_version=None, created=None))
    assert result.level is P0 and result.producer_declared
    no_producer = document_level_ep(document(producer=None, tool_name=None, tool_version=None, created=None))
    assert no_producer.level is P0 and not no_producer.producer_declared


def test_boundary_values():
    assert document_level_ep(document(tool_version="0")).level is P1                  # stated, however odd
    assert document_level_ep(document(created=datetime(2026, 1, 1))).level is P1      # naive timestamps are still timestamps
    assert document_level_ep(document(tool_name=" t ")).level is P1                    # not rewritten, only tested for presence
    assert document_level_ep(document(producer=None)).level is P1                      # a tool, not an author, is required


def test_no_substitute_field_can_raise_a_level():
    values = document(tool_name=None, tool_version=None, created=None, generation_context="build", method="content",
                      declared_metadata={"tools": "[...]", "creators": "[...]", "authors": "[...]"})
    assert document_level_ep(values).level is P0


# ---- declared versus verified -------------------------------------------------------------------------------

def test_declared_signature_never_raises_the_level():
    integrity = Integrity(signature="sig", signed_coverage=["#/components/0", "#/"])
    bare = document_level_ep(document(tool_name=None, tool_version=None, created=None, integrity=integrity))
    assert bare.level is P0
    assert bare.integrity.signature_declared and bare.integrity.signed_coverage_declared == ("#/", "#/components/0")
    assert bare.integrity.signature_verified is None and bare.integrity.verified_coverage_established is False
    assert L.SIGNATURE_DECLARED_NOT_VERIFIED in bare.limitations
    attributed = document_level_ep(document(integrity=integrity))
    assert attributed.level is P1  # still not P2 or P3


def test_even_reported_verification_and_digest_declarations_do_not_grant_p2_or_p3_here():
    integrity = Integrity(artifact_digest_binding="sha256:aa", signature="sig", signature_verified=True,
                          trust_anchor_id="anchor", signed_coverage=["#/"], established_coverage=["#/"])
    result = document_level_ep(document(integrity=integrity))
    assert result.level is P1 and L.P2_P3_NOT_EVALUATED in result.limitations
    assert L.SIGNATURE_DECLARED_NOT_VERIFIED not in result.limitations  # a verification result was supplied
    assert result.integrity == DeclaredIntegrity(True, ("#/",), True, True, "sha256:aa")  # copied, not acted on
    unattributed = document_level_ep(document(tool_version=None, integrity=integrity))
    assert unattributed.level is P0  # P2/P3 are cumulative: a signature cannot rescue missing attribution


def test_the_classifier_sets_no_integrity_field():
    original = document(integrity=Integrity(signature="sig", signed_coverage=["#/"]))
    snapshot = copy.deepcopy(original)
    document_level_ep(original)
    assert original == snapshot
    integrity = original.integrity
    assert (integrity.signature_verified, integrity.trust_anchor_id, integrity.established_coverage,
            integrity.artifact_digest_binding) == (None, None, None, None)


def test_every_result_states_the_p2_p3_limitation():
    for value in (document(), document(tool_name=None), document(integrity=Integrity(signature="s"))):
        assert L.P2_P3_NOT_EVALUATED in document_level_ep(value).limitations


# ---- real parser output ------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path,loader,level",
    [
        ("cyclonedx/complete_composition.json", load_cyclonedx, P1),   # one tool with version, and a timestamp
        ("cyclonedx/spec_1_5.json", load_cyclonedx, P1),
        ("cyclonedx/signed_root.json", load_cyclonedx, P0),            # signed but no tool: P0
        ("cyclonedx/signed_component_only.json", load_cyclonedx, P0),
        ("cyclonedx/no_compositions.json", load_cyclonedx, P0),        # no metadata at all
        ("spdx/subjects.json", load_spdx, P1),
        ("openvex/component_not_present.json", load_openvex, P0),      # tooling is kept verbatim, with no version field
    ],
)
def test_fixture_levels(path, loader, level):
    record = loader(FIXTURES / path)
    result = document_level_ep(record.document)
    assert result.level is level and result.doc_id == record.doc_id


def test_signed_fixtures_distinguish_declared_from_verified():
    for name in ("signed_root", "signed_component_only"):
        result = document_level_ep(load_cyclonedx(FIXTURES / "cyclonedx" / f"{name}.json").document)
        assert result.level is P0
        assert result.integrity.signature_declared is True
        assert result.integrity.signature_verified is None and result.integrity.verified_coverage_established is False
        assert L.SIGNATURE_DECLARED_NOT_VERIFIED in result.limitations


def test_openvex_statement_documents_are_classified_on_their_own_fields():
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    statement_document = statements.findings[0].source_documents[f"{statements.document.doc_id}#/statements/0"]
    assert document_level_ep(statement_document).level is P0
    assert document_level_ep(statements.document).attribution_gaps == (G.TOOL_VERSION_MISSING,)


def test_spdx_tool_without_a_parsable_version_is_p0_and_p1_carries_the_heuristic_note():
    data = json.loads((FIXTURES / "spdx" / "subjects.json").read_text())
    data["creationInfo"]["creators"] = ["Tool: example-spdx-tool"]
    result = document_level_ep(load_spdx(json.dumps(data).encode()).document)
    assert result.level is P0 and result.attribution_gaps == (G.TOOL_VERSION_MISSING,)
    assert L.TOOL_FIELDS_FROM_PARSER_HEURISTIC not in result.limitations
    good = document_level_ep(load_spdx(FIXTURES / "spdx" / "subjects.json").document)
    assert good.level is P1 and L.TOOL_FIELDS_FROM_PARSER_HEURISTIC in good.limitations


# ---- determinism, purity, invariants -------------------------------------------------------------------------------

def test_repeated_evaluation_is_identical_and_the_result_is_frozen():
    value = document(integrity=Integrity(signature="s", signed_coverage=["b", "a"]))
    assert document_level_ep(value) == document_level_ep(copy.deepcopy(value))
    result = document_level_ep(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.level = ProvenanceLevel.P3
    assert result.integrity.signed_coverage_declared == ("a", "b")  # order of the declared list does not matter


def test_the_result_type_refuses_p2_p3_and_inconsistent_gaps():
    good = document_level_ep(document())
    for changes in (
        {"level": ProvenanceLevel.P2}, {"level": ProvenanceLevel.P3},
        {"level": P0},                                               # P0 without a gap
        {"attribution_gaps": (G.CREATED_MISSING,)},                  # P1 with a gap
        {"limitations": ()},                                         # the limitation must be stated
    ):
        with pytest.raises(ValueError):
            dataclasses.replace(good, **changes)


# ---- levels as an input of the existing effective-provenance steps ----------------------------------------------------------

def test_document_levels_feed_the_existing_partial_ep():
    sbom, statements = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json"), load_openvex(
        FIXTURES / "openvex" / "component_not_present.json")
    levels = document_levels([sbom.document, statements.document])
    assert levels == {sbom.doc_id: P1, statements.doc_id: P0}
    items = [
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=sbom.doc_id, item_id="a"),
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=statements.doc_id, item_id="b"),
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=None, item_id="c"),
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc="not-supplied", item_id="d"),
        EvidenceItem("INV", EvidenceState.UNKNOWN, source_doc=sbom.doc_id, item_id="e", derived_from=["b"]),
    ]
    results = effective_provenance_all(items, levels)
    assert [r.level for r in results] == [P1, P0, P0, P0, P0]  # derived_from takes the minimum
    assert DiagnosticCode.SOURCE_DOC_LEVEL_UNAVAILABLE in [d.code for d in results[3].diagnostics]
    assert all(r.level <= P1 for r in results)  # nothing here can reach P2 or P3


def test_document_levels_refuses_to_choose_between_conflicting_classifications():
    first, second = document(), document(tool_version=None)
    assert document_levels([first, copy.deepcopy(first)]) == {"d": P1}
    with pytest.raises(ValueError):
        document_levels([first, second])
    assert document_levels([]) == {}
