"""Tests for evidence.inventory_observations (neutral facts from parsed SBOM records).

The observations are parsed facts. These tests also check that no evidence state, completeness,
absence, contradiction or dangling-reference conclusion is manufactured from them.
"""

import ast
import copy
import dataclasses
import json
from pathlib import Path

import pytest

from evidence import inventory_observations as IO
from evidence.inventory_observations import (
    InventoryObservations,
    LISTED_COMPONENT_COUNTING_DOMAIN,
    observe_inventory,
)
from evidence.stage1_records import ReferenceStatus, load_cyclonedx, load_spdx
from model import EvidenceState

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def cdx(name="complete_composition.json"):
    return load_cyclonedx(FIXTURES / "cyclonedx" / name)


def spdx(name="subjects.json"):
    return load_spdx(FIXTURES / "spdx" / name)


def cdx_from(data):
    return load_cyclonedx(json.dumps(data).encode())


def minimal_cdx(**extra):
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
    data.update(extra)
    return cdx_from(data)


# ---- CycloneDX ------------------------------------------------------------------------------------

def test_cyclonedx_listed_components_follow_the_documented_counting_domain():
    record = cdx()
    observed = observe_inventory(record)
    assert observed.doc_id == record.doc_id and observed.format == "CycloneDX"
    assert [c.locator for c in observed.listed_components] == [
        "#/components/0", "#/components/0/components/0", "#/components/1", "#/components/2"]  # pre-order, nested counted
    assert observed.listed_component_count == len(record.components) == 4
    assert all(c.doc_id == record.doc_id for c in observed.listed_components)
    # the subject (metadata.component) is not a listed component, and is reported on its own
    assert "app-1" not in [c.bom_ref for c in observed.listed_components]
    [subject] = observed.subjects
    assert (subject.ref, subject.locator, subject.declared_via, subject.listed_as_component) == (
        "app-1", "#/metadata/component", "metadata.component", False)
    first = observed.listed_components[0]
    assert (first.name, first.version, first.bom_ref, first.declared_type) == ("Left-Pad", "1.3.0", "lib-purl", "library")
    assert "excluding metadata.component" in LISTED_COMPONENT_COUNTING_DOMAIN


def test_cyclonedx_edges_keep_direction_locators_and_neutral_lookups():
    observed = observe_inventory(cdx())
    assert [e.locator for e in observed.edges] == [
        "#/dependencies/0/dependsOn/0", "#/dependencies/0/dependsOn/1", "#/dependencies/1/dependsOn/0"]
    first = observed.edges[0]
    assert (first.edge_type, first.raw_relationship) == ("declared_dependency", "dependsOn")
    assert (first.source.ref, first.target.ref) == ("app-1", "lib-purl")
    assert first.source.status is ReferenceStatus.RESOLVED and first.source.kinds == ("subject",)
    assert first.target.kinds == ("listed_component",) and first.target.locators == ("#/components/0",)
    assert [n.locator for n in observed.dependency_nodes] == ["#/dependencies/0", "#/dependencies/1", "#/dependencies/2"]
    assert observed.dependency_nodes[2].ref == "lib-name" and observed.dependency_nodes[2].depends_on_declared is True
    assert observed.endpoints_not_in_registry == 0


def test_a_reference_that_is_not_in_the_registry_is_reported_but_not_interpreted():
    data = json.loads((FIXTURES / "cyclonedx" / "complete_composition.json").read_text())
    data["dependencies"][0]["dependsOn"].append("ghost-ref")
    observed = observe_inventory(cdx_from(data))
    [edge] = [e for e in observed.edges if e.target.ref == "ghost-ref"]
    assert edge.target.status is ReferenceStatus.NOT_IN_REGISTRY and edge.target.kinds == () and edge.target.locators == ()
    assert edge.locator == "#/dependencies/0/dependsOn/2"
    assert observed.endpoints_not_in_registry == 1
    # nothing says dangling, missing, inconsistent or contradictory
    public = {name for name in dir(observed) + [f.name for f in dataclasses.fields(edge)]}
    assert not any(word in name.lower() for name in public for word in ("dangling", "missing", "contradict", "complete", "defect"))


def test_declared_reference_conflicts_are_preserved_verbatim():
    data = json.loads((FIXTURES / "cyclonedx" / "complete_composition.json").read_text())
    data["components"].append(copy.deepcopy(data["metadata"]["component"]))  # the same bom-ref twice
    observed = observe_inventory(cdx_from(data))
    [conflict] = observed.reference_conflicts
    assert conflict.ref == "app-1" and conflict.doc_id == observed.doc_id
    entries = dict(conflict.items)
    # the parser reports the later declaration (the subject) against the earlier listed component
    assert entries["locator"] == "#/metadata/component" and entries["conflicts_with_locator"] == "#/components/3"
    assert conflict.locator == entries["locator"]
    assert observed.subjects[0].listed_as_component is True
    assert observed.listed_component_count == 5  # both records counted; no duplicate is merged or judged


def test_unextracted_top_level_fields_are_reported_sorted():
    assert observe_inventory(cdx("defined_refs.json")).unextracted_top_level_fields == (
        "annotations", "declarations", "formulation", "services")


def test_empty_cyclonedx_document_gives_empty_observations_and_no_conclusion():
    observed = observe_inventory(minimal_cdx())
    assert observed.listed_components == () and observed.edges == () and observed.dependency_nodes == ()
    assert observed.subjects == () and observed.subject_declarations == ()
    assert observed.reference_conflicts == () and observed.listed_component_count == 0
    assert observed.endpoints_not_in_registry == 0  # zero listed components is a fact, not "Absent" or "Empty"


# ---- SPDX -------------------------------------------------------------------------------------------

def test_spdx_observations_keep_declarations_and_unresolved_endpoints():
    record = spdx()
    observed = observe_inventory(record)
    assert observed.format == "SPDX" and observed.listed_component_count == 3  # packages only
    assert [c.bom_ref for c in observed.listed_components] == ["SPDXRef-appA", "SPDXRef-appB", "SPDXRef-lib"]
    assert all(c.declared_type is None for c in observed.listed_components)
    assert observed.unextracted_top_level_fields == ("files", "snippets")
    assert [(d.locator, d.ref, d.declared_via, d.resolved_as) for d in observed.subject_declarations] == [
        ("#/documentDescribes/0", "SPDXRef-appA", "documentDescribes", "package"),
        ("#/documentDescribes/1", "SPDXRef-appB", "documentDescribes", "package"),
        ("#/documentDescribes/2", "SPDXRef-fileA", "documentDescribes", "file"),
        ("#/documentDescribes/3", "SPDXRef-ghost", "documentDescribes", "unresolved"),
        ("#/relationships/0", "SPDXRef-appA", "DESCRIBES", "package"),
        ("#/relationships/1", "SPDXRef-lib", "DESCRIBED_BY", "package")]
    resolved = {d.ref: d.resolved_as for d in observed.subject_declarations}
    assert resolved["SPDXRef-fileA"] == "file" and resolved["SPDXRef-ghost"] == "unresolved"
    assert {(m.ref, dict(m.items)["declared_only_via"]) for m in observed.subject_declaration_mismatches} == {
        ("SPDXRef-appB", "documentDescribes"), ("SPDXRef-fileA", "documentDescribes"),
        ("SPDXRef-ghost", "documentDescribes"), ("SPDXRef-lib", "relationships")}
    [missing] = [e for e in observed.edges if e.target.ref == "SPDXRef-missing"]
    assert missing.target.status is ReferenceStatus.NOT_IN_REGISTRY and missing.raw_relationship == "DEPENDS_ON"
    assert observed.endpoints_not_in_registry == 1
    document_edge = [e for e in observed.edges if e.source.ref == "SPDXRef-DOCUMENT"][0]
    assert document_edge.source.kinds == ("document",)  # the document node is not a component
    assert [s.ref for s in observed.subjects].count("SPDXRef-appA") == 2  # one per declaration, not merged


def test_spdx_duplicate_definitions_are_reported_as_conflicts_only():
    data = json.loads((FIXTURES / "spdx" / "subjects.json").read_text())
    data["files"].append({"SPDXID": "SPDXRef-appA", "fileName": "./dup"})
    observed = observe_inventory(load_spdx(json.dumps(data).encode()))
    assert [c.ref for c in observed.reference_conflicts] == ["SPDXRef-appA"]
    assert observed.listed_component_count == 3


def test_every_observation_carries_the_document_id_and_a_locator():
    for record in (cdx(), spdx()):
        observed = observe_inventory(record)
        for group in (observed.listed_components, observed.edges, observed.dependency_nodes, observed.subjects,
                      observed.subject_declarations, observed.subject_declaration_mismatches,
                      observed.reference_conflicts):
            for observation in group:
                assert observation.doc_id == record.doc_id
        for observation in (*observed.listed_components, *observed.edges, *observed.dependency_nodes,
                            *observed.subjects, *observed.subject_declarations):
            assert observation.locator.startswith("#/")


# ---- determinism and purity ------------------------------------------------------------------------------

def test_observations_do_not_depend_on_the_order_of_the_record_collections():
    for record in (cdx(), spdx(), cdx("defined_refs.json")):
        shuffled = dataclasses.replace(
            record,
            components=tuple(reversed(record.components)),
            component_index=tuple(reversed(record.component_index)),
            edges=tuple(reversed(record.edges)),
            nodes=tuple(reversed(record.nodes)),
            subject_declarations=tuple(reversed(record.subject_declarations)),
            subject_declaration_mismatch=tuple(reversed(record.subject_declaration_mismatch)),
            defined_ref_conflicts=tuple(reversed(record.defined_ref_conflicts)),
            unextracted_top_level_fields=tuple(reversed(record.unextracted_top_level_fields)),
        )
        assert observe_inventory(shuffled) == observe_inventory(record)


def test_locators_sort_numerically_not_lexically():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": f"c{n}", "version": "1"} for n in range(12)]}
    observed = observe_inventory(cdx_from(data))
    assert [c.locator for c in observed.listed_components] == [f"#/components/{n}" for n in range(12)]


def test_observing_is_deterministic_and_does_not_mutate_the_record():
    record = spdx()
    snapshot = copy.deepcopy(record)
    first, second = observe_inventory(record), observe_inventory(record)
    assert first == second and record == snapshot
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.doc_id = "x"
    assert isinstance(first.listed_components, tuple)


# ---- no manufactured conclusions -----------------------------------------------------------------------------

def test_no_evidence_state_or_completeness_conclusion_is_manufactured():
    tree = ast.parse(open(IO.__file__, encoding="utf-8").read())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"__future__", "dataclasses", "typing", "evidence.stage1_records"}
    assert not names & {"EvidenceState", "EvidenceItem", "ProvenanceLevel", "BindState", "derive_inv", "evaluate_bind",
                        "enumerate_decl_candidates", "evaluate_cnp", "StructuralCheck", "Emptiness", "Interpretability"}
    for record in (cdx(), spdx(), minimal_cdx()):
        observed = observe_inventory(record)
        for field in dataclasses.fields(InventoryObservations):
            assert not isinstance(getattr(observed, field.name), EvidenceState)
        assert not hasattr(observed, "state") and not hasattr(observed, "inv") and not hasattr(observed, "complete")


def test_a_registry_lookup_is_never_presented_as_completeness_or_a_defect():
    observed = observe_inventory(spdx())
    statuses = {e.target.status for e in observed.edges} | {e.source.status for e in observed.edges}
    assert statuses <= {ReferenceStatus.RESOLVED, ReferenceStatus.NOT_IN_REGISTRY}
    # a fully resolved document and a document with an unregistered endpoint differ only in these facts
    clean = observe_inventory(cdx())
    assert clean.endpoints_not_in_registry == 0 and clean.listed_component_count == 4
    assert observed.endpoints_not_in_registry == 1
