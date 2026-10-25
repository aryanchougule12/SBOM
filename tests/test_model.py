"""Stage 0 smoke and structure tests for model.py.

These check that the data model imports and can be constructed and that its
enumerations match the committed specification. They assert no predicate semantics.
"""

import dataclasses
import typing
from pathlib import Path

import pytest

import model


def test_evidence_states_are_exactly_the_six_in_the_spec():
    assert [s.value for s in model.EvidenceState] == [
        "Present", "Absent", "Unknown", "Incomplete", "Ambiguous", "Contradictory",
    ]


def test_dispositions_match_the_spec():
    assert {d.value for d in model.Disposition} == {
        "not_affected", "affected", "fixed", "under_investigation",
    }


def test_provenance_ladder_has_p0_to_p3_in_order():
    assert [p.name for p in model.ProvenanceLevel] == ["P0", "P1", "P2", "P3"]
    assert model.ProvenanceLevel.P0 < model.ProvenanceLevel.P3


def test_provenance_roles_are_named():
    assert {r.name for r in model.ProvenanceRole} == {
        "PROV_SBOM", "PROV_DECL", "PROV_CORR", "PROV_REACH", "PROV_HAZ",
    }


def test_artifact_kinds_are_the_four_spec_values_plus_unknown_for_missing_input():
    assert {k.value for k in model.ArtifactKind} == {
        "source", "binary", "container", "other", "unknown",
    }


def test_the_four_original_artifact_kind_values_are_unchanged():
    assert model.ArtifactKind.SOURCE.value == "source"
    assert model.ArtifactKind.BINARY.value == "binary"
    assert model.ArtifactKind.CONTAINER.value == "container"
    assert model.ArtifactKind.OTHER.value == "other"
    assert model.ArtifactKind.UNKNOWN is not model.ArtifactKind.OTHER


def test_scope_defaults_a_missing_artifact_kind_to_unknown_never_other():
    assert model.Scope(product_id="p").artifact_kind is model.ArtifactKind.UNKNOWN
    default = {f.name: f.default for f in dataclasses.fields(model.Scope)}["artifact_kind"]
    assert default is model.ArtifactKind.UNKNOWN
    assert default is not model.ArtifactKind.OTHER


def test_no_parser_module_falls_back_to_artifact_kind_other():
    """Static guard: OTHER is only for an explicitly established kind, so no parser
    source may reference it at all (parsers cannot yet establish any kind)."""
    parser_dir = Path(__file__).resolve().parent.parent / "sbom_parser"
    offenders = [
        path.name
        for path in sorted(parser_dir.glob("*.py"))
        if "ArtifactKind.OTHER" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_can_construct_a_finding():
    component = model.Component(
        name="example-lib",
        version="1.0.0",
        purl="pkg:generic/example-lib@1.0.0",
        ecosystem="generic",
        hashes=[model.Hash(algorithm="SHA-256", value="00")],
        identifier_variants=[model.IdentifierVariant(kind="purl", value="pkg:generic/example-lib@1.0.0")],
    )
    vulnerability = model.Vulnerability(
        id="CVE-0000-0000",
        locus=model.VulnerableCodeLocus(symbols=["example.fn"], granularity="symbol"),
    )
    document = model.SourceDocument(doc_id="doc-1", integrity=model.Integrity(signature_verified=None))
    item = model.EvidenceItem(
        dimension="INV",
        state=model.EvidenceState.UNKNOWN,
        source_doc="doc-1",
        locator="/components",
    )
    finding = model.Finding(
        component=component,
        vulnerability=vulnerability,
        disposition=model.Disposition.NOT_AFFECTED,
        justification=model.Justification(model.JustificationType.COMPONENT_NOT_PRESENT.value),
        evidence=[item],
        scope=model.Scope(product_id="product-1", artifact_kind=model.ArtifactKind.CONTAINER),
        source_documents={"doc-1": document},
    )
    assert finding.evidence[0].source_doc in finding.source_documents


def test_finding_separates_the_target_component_from_the_product():
    hints = typing.get_type_hints(model.Finding)
    assert hints["component"] == typing.Optional[model.Component]  # C; None = unresolved
    assert hints["product"] == typing.Optional[model.Component]
    finding = model.Finding(
        component=None,
        vulnerability=model.Vulnerability(id="CVE-0000-0001"),
        disposition=model.Disposition.NOT_AFFECTED,
        justification=model.Justification("component_not_present"),
        evidence=[],
        scope=model.Scope(product_id="p"),
        product=model.Component(name="", bom_ref="p"),
    )
    assert finding.component is None  # unresolved is representable and distinct from the product
    assert finding.product is not None
    default = model.Finding(
        component=model.Component(name="c"),
        vulnerability=model.Vulnerability(id="CVE-0000-0001"),
        disposition=model.Disposition.NOT_AFFECTED,
        justification=model.Justification("component_not_present"),
        evidence=[],
        scope=model.Scope(product_id="p"),
    )
    assert default.product is None  # product is optional for findings not built from a product entry


def test_provenance_lives_on_source_documents_not_on_items_or_findings():
    """Structure check: there is no global PROV field, and evidence items refer to
    their source document by id rather than carrying provenance themselves."""
    for cls in (model.Finding, model.EvidenceItem, model.SourceDocument):
        assert not [f.name for f in dataclasses.fields(cls) if f.name.lower().startswith("prov")]
    doc_fields = {f.name for f in dataclasses.fields(model.SourceDocument)}
    assert {"producer", "tool_name", "tool_version", "created", "generation_context",
            "method", "integrity"} <= doc_fields
    integrity_fields = {f.name for f in dataclasses.fields(model.Integrity)}
    assert integrity_fields == {
        "artifact_digest_binding", "signature", "signature_verified",
        "trust_anchor_id", "signed_coverage",
    }
    item_fields = {f.name for f in dataclasses.fields(model.EvidenceItem)}
    assert {"dimension", "state", "value_or_ref", "source_doc", "locator", "derived_from"} <= item_fields


def test_justification_field_is_annotated_as_a_raw_string():
    # get_type_hints resolves the postponed (``from __future__ import annotations``)
    # annotations in model.py, so this checks the real annotation, not a string literal.
    assert typing.get_type_hints(model.Justification)["justification"] is str


# Supported subset, valid VEX justifications outside it, and an arbitrary string
# (with a case variant and non-ASCII text) to show nothing is normalized or restricted.
RAW_JUSTIFICATIONS = [
    "component_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
    "COMPONENT_NOT_PRESENT",
    "x-unrecognized/Future Value ☃",
]


@pytest.mark.parametrize("raw", RAW_JUSTIFICATIONS)
def test_justification_preserves_raw_values_exactly(raw):
    stored = model.Justification(justification=raw).justification
    assert stored == raw
    assert type(stored) is str


def test_justification_type_is_only_the_predicate_supported_subset():
    supported = {t.value for t in model.JustificationType}
    assert supported == {"component_not_present", "vulnerable_code_not_in_execute_path"}
    # Unsupported values are not enum members, yet the model still represents them.
    for raw in RAW_JUSTIFICATIONS:
        if raw not in supported:
            with pytest.raises(ValueError):
                model.JustificationType(raw)
            assert model.Justification(justification=raw).justification == raw
