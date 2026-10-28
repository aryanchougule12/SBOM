"""End-to-end tests for the Stage 2 foundation batch: input assembly, neutral inventory
observations and document-level P0/P1 provenance, on real parser fixtures.

Nothing here evaluates a rule, derives INV, DECL, MATCH or BIND, runs the structural classifier
or calculates a verdict; the tests make that checkable by patching those entry points to fail
if they are ever called.
"""

import copy
from pathlib import Path

import pytest

from evidence import bind as bind_module
from evidence import cnp_rules, decl_candidates, inv as inv_module
from evidence.extraction import extract
from evidence.inventory_observations import InventoryObservations, observe_inventory
from evidence.pipeline_inputs import AssemblyError, AssemblyErrorCode, assemble
from evidence.profile import parse_profile
from evidence.provenance import (
    AttributionGap,
    document_level_ep,
    document_levels,
    effective_provenance_all,
)
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex, load_spdx
from model import DocumentRole, EvidenceState, ProvenanceLevel

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
P0, P1 = ProvenanceLevel.P0, ProvenanceLevel.P1
PRODUCT = "pkg:oci/example-app@sha256%3Aabc"


@pytest.fixture(autouse=True)
def no_evaluation(monkeypatch):
    """Fail loudly if any evaluation entry point of the later stages is reached."""

    def forbidden(name):
        def raiser(*args, **kwargs):
            raise AssertionError(f"{name} must not be called by the foundation batch")
        return raiser

    monkeypatch.setattr(cnp_rules, "evaluate_cnp", forbidden("evaluate_cnp"))
    monkeypatch.setattr(inv_module, "derive_inv", forbidden("derive_inv"))
    monkeypatch.setattr(bind_module, "evaluate_bind", forbidden("evaluate_bind"))
    monkeypatch.setattr(bind_module, "evaluate_bind_for_profile", forbidden("evaluate_bind_for_profile"))
    monkeypatch.setattr(decl_candidates, "enumerate_decl_candidates", forbidden("enumerate_decl_candidates"))


def profile_for(doc_id):
    return parse_profile({
        "schema_version": "1", "profile_id": "foundation",
        "finding_selector": {"vulnerability": "CVE-2026-0001", "product_id": PRODUCT},
        "scope": {"product_id": PRODUCT, "version": "2.0.0", "artifact_kind": "container"},
        "target": {"component": {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}},
        "documents": [{"doc_id": doc_id, "role": "primary_sbom"}],
    })


def foundation(profile, findings, index):
    """The three foundation steps, in order, and nothing else."""
    assembly = assemble(profile, findings, index)
    observations = observe_inventory(assembly.primary_record)
    document_ep = document_level_ep(assembly.finding.source_documents[assembly.primary_doc_id])
    return assembly, observations, document_ep


@pytest.mark.parametrize(
    "loader,path,format_name,listed",
    [(load_cyclonedx, "cyclonedx/complete_composition.json", "CycloneDX", 4), (load_spdx, "spdx/subjects.json", "SPDX", 3)],
)
def test_real_fixtures_flow_through_all_three_parts_with_one_document_identity(loader, path, format_name, listed):
    record = loader(FIXTURES / path)
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    findings, index = list(statements.findings), Stage1Index([record])
    profile = profile_for(record.doc_id)
    snapshot = (copy.deepcopy(findings), copy.deepcopy(record), copy.deepcopy(profile))

    assembly, observations, document_ep = foundation(profile, findings, index)

    # assembly: role mapping, scope, target, registry
    finding = assembly.finding
    assert finding.document_roles == {record.doc_id: DocumentRole.PRIMARY_SBOM}
    assert (finding.scope.product_id, finding.scope.version) == (PRODUCT, "2.0.0")
    assert finding.component is not None and finding.component.name == "left-pad"
    assert finding.source_documents[record.doc_id] == record.document
    assert all(key == doc.doc_id for key, doc in finding.source_documents.items())

    # observations and provenance keep the same document identity
    assert observations.doc_id == document_ep.doc_id == assembly.primary_doc_id == record.doc_id
    assert observations.format == format_name and observations.listed_component_count == listed
    assert observations == observe_inventory(record)
    assert document_ep.level is P1 and not document_ep.attribution_gaps

    # nothing was mutated
    assert (findings, record, profile) == snapshot


def test_the_existing_extraction_api_agrees_with_the_assembled_registry():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    index = Stage1Index([record])
    assembly, _, _ = foundation(profile_for(record.doc_id), list(statements.findings), index)
    outcome = extract(assembly.finding, index)
    assert outcome.items
    for item in outcome.items:
        assert item.state is EvidenceState.UNKNOWN  # extraction's slice-1 behaviour, unchanged
        if item.source_doc is not None:
            assert item.source_doc in assembly.finding.source_documents
            assert assembly.finding.document_roles[item.source_doc] is DocumentRole.PRIMARY_SBOM
    # the registry's documents get levels that the existing partial EP can consume
    levels = document_levels(assembly.finding.source_documents.values())
    results = effective_provenance_all(outcome.items, levels)
    for item, result in zip(outcome.items, results):
        expected = levels[item.source_doc] if item.source_doc is not None else P0
        assert result.level is expected and result.diagnostics == ()
    assert levels[record.doc_id] is P1
    assert {levels[d] for d in levels if d != record.doc_id} == {P0}  # the OpenVEX documents have no tool version


def test_observations_and_provenance_preserve_locators_without_manufacturing_a_state():
    record = load_spdx(FIXTURES / "spdx" / "subjects.json")
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    _, observations, document_ep = foundation(profile_for(record.doc_id), list(statements.findings), Stage1Index([record]))
    unresolved = [e for e in observations.edges if e.target.ref == "SPDXRef-missing"]
    assert [(e.locator, e.target.status.value) for e in unresolved] == [("#/relationships/5", "not_in_registry")]
    assert isinstance(observations, InventoryObservations) and not hasattr(observations, "state")
    assert document_ep.limitations and document_ep.integrity.signature_verified is None
    for value in (observations, document_ep):
        assert not any(isinstance(getattr(value, f), EvidenceState) for f in value.__dataclass_fields__)


def test_a_missing_primary_record_manufactures_no_downstream_observation(monkeypatch):
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    other = load_spdx(FIXTURES / "spdx" / "subjects.json")
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    calls = []
    import evidence.inventory_observations as observations_module
    import evidence.provenance as provenance_module
    monkeypatch.setattr(observations_module, "observe_inventory", lambda r: calls.append("observe"))
    monkeypatch.setattr(provenance_module, "document_level_ep", lambda d: calls.append("ep"))

    def run(profile, index):
        assembly = assemble(profile, list(statements.findings), index)
        observations_module.observe_inventory(assembly.primary_record)
        provenance_module.document_level_ep(assembly.finding.source_documents[assembly.primary_doc_id])

    with pytest.raises(AssemblyError) as excinfo:
        run(profile_for(record.doc_id), Stage1Index([other]))  # a record exists, but not the primary one
    assert excinfo.value.code is AssemblyErrorCode.RECORD_NOT_SUPPLIED
    with pytest.raises(AssemblyError):
        run(profile_for(record.doc_id.upper()), Stage1Index([record]))  # a near miss is a miss
    assert calls == []  # neither observations nor provenance were produced
    run(profile_for(record.doc_id), Stage1Index([record]))
    assert calls == ["observe", "ep"]


def test_results_are_deterministic_and_independent_of_input_order():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    extra = load_spdx(FIXTURES / "spdx" / "subjects.json")
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    profile = profile_for(record.doc_id)
    first = foundation(profile, list(statements.findings), Stage1Index([record, extra]))
    second = foundation(profile, list(statements.findings)[::-1], Stage1Index([extra, record]))
    assert repr(first) == repr(second)
    assert foundation(profile, list(statements.findings), Stage1Index([record, extra])) == first


def test_the_p0_p1_result_is_a_lower_bound_and_names_what_it_did_not_evaluate():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "signed_root.json")  # signed, but no tool identity
    statements = load_openvex(FIXTURES / "openvex" / "component_not_present.json")
    _, _, document_ep = foundation(profile_for(record.doc_id), list(statements.findings), Stage1Index([record]))
    assert document_ep.level is P0
    assert document_ep.attribution_gaps == (AttributionGap.TOOL_NAME_MISSING, AttributionGap.TOOL_VERSION_MISSING)
    assert document_ep.integrity.signature_declared and document_ep.integrity.signature_verified is None
    assert document_ep.integrity.verified_coverage_established is False
