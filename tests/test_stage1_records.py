"""Tests for evidence.stage1_records (typed adapter over Stage 1 parser output)."""

import copy
import json
from pathlib import Path

import pytest

from evidence import stage1_records as s1
from evidence.stage1_records import (
    RecordDecodeError,
    ReferenceStatus,
    Stage1Index,
)
from model import EvidenceState
from sbom_parser.cyclonedx import parse_cyclonedx
from sbom_parser.openvex import parse_openvex
from sbom_parser.spdx import parse_spdx

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CDX = FIXTURES / "cyclonedx"
SPDX = FIXTURES / "spdx"
VEX = FIXTURES / "openvex"


# ---- real fixtures, every supported format --------------------------------------------

def test_cyclonedx_complete_composition_is_decoded():
    record = s1.load_cyclonedx(CDX / "complete_composition.json")
    assert record.format == "CycloneDX"
    assert [c.bom_ref for c in record.components] == ["lib-purl", "lib-nested", "lib-cpe", "lib-name"]
    assert len(record.component_index) == len(record.components)
    assert [(e.source, e.target, e.raw_relationship) for e in record.edges] == [
        ("app-1", "lib-purl", "dependsOn"),
        ("app-1", "lib-cpe", "dependsOn"),
        ("lib-purl", "lib-nested", "dependsOn"),
    ]
    assert all(e.edge_type == "declared_dependency" for e in record.edges)
    assert [(n.ref, n.depends_on_declared) for n in record.nodes] == [
        ("app-1", True), ("lib-purl", True), ("lib-name", True),
    ]
    (composition,) = record.composition_records
    assert composition.state is EvidenceState.PRESENT
    assert composition.aggregate_raw == "complete" and composition.aggregate_recognized
    assert composition.assemblies == ("lib-purl", "lib-cpe", "lib-name")
    assert composition.dependencies == ("app-1",)
    assert composition.locator == "#/compositions/0" and composition.scope_declared
    assert record.subject_declarations == () and record.signature_records == ()
    # unknown fields stay visible
    assert "licenses" in record.component_index[0]["unextracted_keys"]


def test_cyclonedx_two_composition_records_are_kept_separate():
    record = s1.load_cyclonedx(CDX / "incomplete_composition.json")
    assert [(r.aggregate_raw, r.state, r.assemblies) for r in record.composition_records] == [
        ("incomplete_first_party_only", EvidenceState.INCOMPLETE, ("comp-a",)),
        ("complete", EvidenceState.PRESENT, ("comp-b",)),
    ]
    assert record.composition_records[1].bom_ref == "comp-record-2"


def test_cyclonedx_without_compositions_has_no_records():
    assert s1.load_cyclonedx(CDX / "no_compositions.json").composition_records == ()


def test_cyclonedx_signature_records_are_claims_and_preserved():
    record = s1.load_cyclonedx(CDX / "signed_component_only.json")
    (sig,) = record.signature_records
    assert sig.covers == "#/components/0" and sig.coverage_claimed
    assert sig.signature["algorithm"] == "ES256"
    assert record.document.integrity.established_coverage is None  # adapter establishes nothing
    root = s1.load_cyclonedx(CDX / "signed_root.json")
    assert root.signature_records[0].covers == "#"


def test_spdx_subjects_fixture_is_decoded():
    record = s1.load_spdx(SPDX / "subjects.json")
    assert record.format == "SPDX"
    assert len(record.components) == 3 and len(record.component_index) == 3
    assert record.nodes == ()
    assert ("SPDXRef-appA", "DEPENDS_ON", "SPDXRef-lib") in {
        (e.source, e.raw_relationship, e.target) for e in record.edges
    }
    assert all(e.edge_type == "declared_relationship" for e in record.edges)
    resolved_as = {(d.ref, d.declared_via): d.resolved_as for d in record.subject_declarations}
    assert resolved_as[("SPDXRef-fileA", "documentDescribes")] == "file"
    assert resolved_as[("SPDXRef-ghost", "documentDescribes")] == "unresolved"
    assert {"ref": "SPDXRef-lib", "declared_only_via": "relationships"} in record.subject_declaration_mismatch
    assert record.composition_records == ()  # SPDX 2.3 has no completeness declaration


def test_openvex_fixture_is_decoded():
    record = s1.load_openvex(VEX / "subcomponents.json")
    assert len(record.findings) == 4
    assert len(record.statement_documents) == 1
    (targets,) = record.finding_targets.values()
    assert [t["target_locator"] for t in targets] == [
        "#/statements/0/products/0/subcomponents/0",
        "#/statements/0/products/0/subcomponents/1",
        "#/statements/0/products/0/subcomponents/2",
        None,
    ]
    assert record.findings[3].component is None  # unresolved target stays unresolved


def test_every_fixture_that_parses_can_be_adapted():
    for path in sorted(CDX.glob("*.json")):
        if path.name == "malformed.json":
            continue
        document, components = parse_cyclonedx(path)
        s1.from_parsed_sbom(document, components)
    for path in sorted(SPDX.glob("*.json")):
        if path.name == "malformed.json":
            continue
        document, components = parse_spdx(path)
        s1.from_parsed_sbom(document, components)
    for path in sorted(VEX.glob("*.json")):
        if path.name == "malformed.json":
            continue
        document, findings = parse_openvex(path)
        s1.from_parsed_vex(document, findings)


# ---- reference resolution --------------------------------------------------------------

@pytest.fixture(scope="module")
def defined_refs():
    return s1.load_cyclonedx(CDX / "defined_refs.json")


@pytest.mark.parametrize(
    "ref, kinds",
    [
        ("lib-1", ("listed_component",)),
        ("lib-1-child", ("listed_component",)),  # nested inside a listed component
        ("app-1", ("subject",)),  # CycloneDX subject, not in the component list
        ("svc-1", ("service",)),
        ("svc-1-nested", ("nested_service",)),
        ("subject-nested", ("nested_component",)),
        ("tool-1", ("tool_component",)),
        ("form-comp", ("formulation_component",)),
        ("decl-svc", ("declaration_target_service",)),
    ],
)
def test_cyclonedx_references_resolve_by_registry(defined_refs, ref, kinds):
    resolution = defined_refs.resolve(ref)
    assert resolution.status is ReferenceStatus.RESOLVED
    assert resolution.kinds == kinds


def test_resolved_references_are_not_inventory_components(defined_refs):
    inventory = {c.bom_ref for c in defined_refs.components}
    for ref in ("app-1", "svc-1", "svc-1-nested", "subject-nested", "tool-1", "form-comp", "decl-svc"):
        assert defined_refs.resolve(ref).status is ReferenceStatus.RESOLVED
        assert ref not in inventory  # resolving a reference never adds an inventory component
    assert [c.bom_ref for c in defined_refs.components] == ["lib-1", "lib-1-child"]


def test_unregistered_reference_is_not_in_registry_not_a_finding(defined_refs):
    resolution = defined_refs.resolve("truly-missing")
    assert resolution.status is ReferenceStatus.NOT_IN_REGISTRY
    assert resolution.kinds == () and resolution.locators == ()
    assert ReferenceStatus.NOT_IN_REGISTRY.value == "not_in_registry"
    assert not hasattr(ReferenceStatus, "MISSING") and not hasattr(ReferenceStatus, "DANGLING")


def test_edge_resolution_reports_each_endpoint(defined_refs):
    by_target = {r.edge.target: r for r in defined_refs.resolve_edges()}
    assert by_target["truly-missing"].target.status is ReferenceStatus.NOT_IN_REGISTRY
    assert by_target["truly-missing"].source.status is ReferenceStatus.RESOLVED
    assert by_target["svc-1-nested"].target.status is ReferenceStatus.RESOLVED
    assert [r.edge for r in defined_refs.resolve_edges()] == list(defined_refs.edges)


def test_spdx_document_node_package_file_and_unregistered():
    record = s1.load_spdx(SPDX / "subjects.json")
    document = record.resolve("SPDXRef-DOCUMENT")
    assert document.status is ReferenceStatus.RESOLVED and document.kinds == ("document",)
    assert "SPDXRef-DOCUMENT" not in {c.bom_ref for c in record.components}
    package = record.resolve("SPDXRef-appA")
    assert package.kinds == ("listed_component", "subject")  # both registries, fixed order
    assert record.resolve("SPDXRef-fileA").kinds == ("file",)
    assert record.resolve("SPDXRef-snip1").kinds == ("snippet",)
    assert record.resolve("SPDXRef-missing").status is ReferenceStatus.NOT_IN_REGISTRY
    # NOASSERTION is a valid SPDX value yet unregistered: a neutral lookup, not a finding.
    assert record.resolve("NOASSERTION").status is ReferenceStatus.NOT_IN_REGISTRY


# ---- malformed stored metadata ----------------------------------------------------------

def _parsed_cdx():
    return parse_cyclonedx(CDX / "complete_composition.json")


def _parsed_spdx():
    return parse_spdx(SPDX / "subjects.json")


def test_missing_required_key_raises():
    document, components = _parsed_cdx()
    del document.declared_metadata["declared_dependency_edges"]
    with pytest.raises(RecordDecodeError, match="declared_dependency_edges"):
        s1.from_parsed_sbom(document, components)


def test_invalid_json_text_raises():
    document, components = _parsed_cdx()
    document.declared_metadata["composition_records"] = "{not json"
    with pytest.raises(RecordDecodeError, match="not valid JSON"):
        s1.from_parsed_sbom(document, components)


def test_wrong_json_type_raises():
    document, components = _parsed_cdx()
    document.declared_metadata["component_index"] = "{}"
    with pytest.raises(RecordDecodeError, match="expected a JSON list"):
        s1.from_parsed_sbom(document, components)


def test_entry_missing_a_field_raises():
    document, components = _parsed_spdx()
    edges = json.loads(document.declared_metadata["declared_relationships"])
    del edges[0]["target"]
    document.declared_metadata["declared_relationships"] = json.dumps(edges)
    with pytest.raises(RecordDecodeError, match="target"):
        s1.from_parsed_sbom(document, components)


def test_unknown_composition_state_raises():
    document, components = _parsed_cdx()
    records = json.loads(document.declared_metadata["composition_records"])
    records[0]["state"] = "Maybe"
    document.declared_metadata["composition_records"] = json.dumps(records)
    with pytest.raises(RecordDecodeError, match="unknown state"):
        s1.from_parsed_sbom(document, components)


def test_component_index_length_mismatch_raises():
    document, components = _parsed_cdx()
    with pytest.raises(RecordDecodeError, match="component_index"):
        s1.from_parsed_sbom(document, components[:-1])


def test_non_sbom_and_non_vex_inputs_are_rejected():
    document, _ = parse_openvex(VEX / "subcomponents.json")
    with pytest.raises(RecordDecodeError, match="not an SBOM parse result"):
        s1.from_parsed_sbom(document, [])
    cdx_document, _ = _parsed_cdx()
    with pytest.raises(RecordDecodeError, match="not an OpenVEX parse result"):
        s1.from_parsed_vex(cdx_document, [])


def test_malformed_vex_finding_targets_raise():
    document, findings = parse_openvex(VEX / "subcomponents.json")
    statement = next(d for d in findings[0].source_documents.values() if d is not document)
    statement.declared_metadata["finding_targets"] = '[{"product_locator": 1}]'
    with pytest.raises(RecordDecodeError, match="product_locator"):
        s1.from_parsed_vex(document, findings)


# ---- determinism and non-mutation --------------------------------------------------------

def test_repeated_decoding_is_deterministic_and_does_not_mutate_inputs():
    document, components = _parsed_cdx()
    document_before = copy.deepcopy(document)
    components_before = copy.deepcopy(components)
    first = s1.from_parsed_sbom(document, components)
    second = s1.from_parsed_sbom(document, components)
    assert first == second
    assert first.resolve_edges() == second.resolve_edges()
    assert document == document_before
    assert components == components_before
    assert isinstance(first.components, tuple) and first.components is not components


def test_vex_decoding_does_not_mutate_inputs():
    document, findings = parse_openvex(VEX / "subcomponents.json")
    before = copy.deepcopy((document, findings))
    assert s1.from_parsed_vex(document, findings) == s1.from_parsed_vex(document, findings)
    assert (document, findings) == before


# ---- index -------------------------------------------------------------------------------

def test_index_maps_document_ids_to_records():
    cdx = s1.load_cyclonedx(CDX / "complete_composition.json")
    spdx = s1.load_spdx(SPDX / "subjects.json")
    index = Stage1Index([cdx, spdx])
    assert len(index) == 2
    assert index.get(cdx.doc_id) is cdx and cdx.doc_id in index
    assert index.get("nope") is None and "nope" not in index
    assert index.doc_ids() == tuple(sorted([cdx.doc_id, spdx.doc_id]))
    index.add(s1.load_cyclonedx(CDX / "complete_composition.json"))  # identical content: idempotent
    assert len(index) == 2


def test_index_rejects_a_different_record_under_an_existing_id():
    record = s1.load_cyclonedx(CDX / "complete_composition.json")
    other = s1.load_cyclonedx(CDX / "complete_composition.json")
    object.__setattr__(other, "format", "SPDX")  # same id, different content
    index = Stage1Index([record])
    with pytest.raises(ValueError):
        index.add(other)
