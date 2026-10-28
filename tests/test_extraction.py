"""Tests for evidence.extraction (minimal bounded slice)."""

from pathlib import Path

import pytest

from evidence import extraction
from evidence import stage1_records as s1
from evidence.aggregation import aggregate_state
from evidence.extraction import Diagnostic, extract, extract_evidence
from model import (
    Component,
    Disposition,
    DocumentRole,
    EvidenceState,
    Finding,
    Justification,
    Scope,
    Vulnerability,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CNP = "component_not_present"
REACH = "vulnerable_code_not_in_execute_path"


def finding(justification=CNP, component=Component(name="c"), roles=None, disposition=Disposition.NOT_AFFECTED,
            product=None):
    return Finding(
        component=component,
        vulnerability=Vulnerability(id="CVE-0000-0001"),
        disposition=disposition,
        justification=Justification(justification),
        evidence=[],
        scope=Scope(product_id="p"),
        product=product,
        document_roles=dict(roles or {}),
    )


@pytest.fixture(scope="module")
def complete():
    return s1.load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")


@pytest.fixture(scope="module")
def incomplete():
    return s1.load_cyclonedx(FIXTURES / "cyclonedx" / "incomplete_composition.json")


@pytest.fixture(scope="module")
def no_comp():
    return s1.load_cyclonedx(FIXTURES / "cyclonedx" / "no_compositions.json")


@pytest.fixture(scope="module")
def spdx():
    return s1.load_spdx(FIXTURES / "spdx" / "no_completeness.json")


def by_dim(items, dimension):
    return [i for i in items if i.dimension == dimension]


def primary(record):
    return {record.doc_id: DocumentRole.PRIMARY_SBOM}


# ---- interface ---------------------------------------------------------------------------

def test_extract_evidence_is_the_items_of_extract(complete):
    f = finding(roles=primary(complete))
    index = s1.Stage1Index([complete])
    assert extract_evidence(f, index) == extract(f, index).items


def test_extraction_works_without_an_index():
    result = extract(finding())
    assert {i.state for i in result.items} == {EvidenceState.UNKNOWN}


# ---- MATCH ---------------------------------------------------------------------------------

def test_unresolved_target_component_gives_unknown_match_with_a_diagnostic():
    product = Component(name="", purl="pkg:oci/app@sha256%3Adef", bom_ref="pkg:oci/app@sha256%3Adef")
    (match,) = by_dim(extract_evidence(finding(component=None, product=product)), "MATCH")
    assert match.state is EvidenceState.UNKNOWN
    assert isinstance(match.value_or_ref, Diagnostic)
    assert match.value_or_ref.code == "NO_TARGET_COMPONENT"
    assert "no target component" in match.value_or_ref.message
    assert "pkg:oci" not in match.value_or_ref.message  # product identifiers are never reused as C's


def test_openvex_finding_without_subcomponent_yields_unknown_match():
    record = s1.load_openvex(FIXTURES / "openvex" / "subcomponents.json")
    unresolved = [f for f in record.findings if f.component is None]
    assert unresolved
    for f in unresolved:
        (match,) = by_dim(extract_evidence(f), "MATCH")
        assert match.state is EvidenceState.UNKNOWN and match.value_or_ref.code == "NO_TARGET_COMPONENT"


def test_resolved_component_match_is_not_evaluated_and_no_item_is_fabricated(complete):
    result = extract(finding(component=Component(name="Left-Pad", purl="pkg:npm/left-pad@1.3.0"),
                             roles=primary(complete)), s1.Stage1Index([complete]))
    assert by_dim(result.items, "MATCH") == []
    assert any(d.code == "NOT_EVALUATED" and d.message.startswith("MATCH") for d in result.diagnostics)


# ---- DECL ----------------------------------------------------------------------------------

def test_decl_without_composition_record_is_unknown(no_comp, spdx):
    for record in (no_comp, spdx):
        (decl,) = by_dim(extract_evidence(finding(roles=primary(record)), s1.Stage1Index([record])), "DECL")
        assert decl.state is EvidenceState.UNKNOWN
        assert decl.value_or_ref.code == "NO_COMPOSITION_RECORD"
        assert decl.source_doc == record.doc_id


def test_decl_with_composition_records_stays_unknown_because_selection_is_open(complete, incomplete):
    # Even a single, document-covering 'complete' record is not used: G6 is open.
    (single,) = by_dim(extract_evidence(finding(roles=primary(complete)), s1.Stage1Index([complete])), "DECL")
    assert single.state is EvidenceState.UNKNOWN
    assert single.value_or_ref.code == "COMPOSITION_SELECTION_UNDETERMINED"
    assert single.value_or_ref.locators == ("#/compositions/0",)
    (multi,) = by_dim(extract_evidence(finding(roles=primary(incomplete)), s1.Stage1Index([incomplete])), "DECL")
    assert multi.state is EvidenceState.UNKNOWN
    assert multi.value_or_ref.locators == ("#/compositions/0", "#/compositions/1")


def test_decl_never_reads_present_or_incomplete_from_the_records(complete, incomplete):
    for record in (complete, incomplete):
        items = extract_evidence(finding(roles=primary(record)), s1.Stage1Index([record]))
        assert aggregate_state(by_dim(items, "DECL")) is EvidenceState.UNKNOWN


# ---- GEN -----------------------------------------------------------------------------------

def test_gen_with_absent_method_is_unknown_and_ignores_generation_context(complete):
    assert complete.document.generation_context == "build" and complete.document.method is None
    (gen,) = by_dim(extract_evidence(finding(roles=primary(complete)), s1.Stage1Index([complete])), "GEN")
    assert gen.state is EvidenceState.UNKNOWN
    assert gen.value_or_ref.code == "GEN_METHOD_ABSENT"


def test_gen_with_a_stated_method_is_not_classified(complete):
    stated = s1.from_parsed_sbom(
        _with_method(complete.document, "scans container layers"), list(complete.components)
    )
    result = extract(finding(roles=primary(stated)), s1.Stage1Index([stated]))
    assert by_dim(result.items, "GEN") == []
    assert any(d.code == "NOT_EVALUATED" and "G14" in d.message for d in result.diagnostics)


def _with_method(document, method):
    import copy
    clone = copy.deepcopy(document)
    clone.method = method
    return clone


# ---- INV -----------------------------------------------------------------------------------

def test_inv_is_accessible_but_never_present_or_absent(complete):
    (inv,) = by_dim(extract_evidence(finding(roles=primary(complete)), s1.Stage1Index([complete])), "INV")
    assert inv.state is EvidenceState.UNKNOWN
    assert inv.value_or_ref.code == "INV_FULL_LIST_NOT_ESTABLISHED"
    assert "4 listed component" in inv.value_or_ref.message
    assert inv.source_doc == complete.doc_id


def test_nothing_is_derived_from_reference_resolution_alone():
    record = s1.load_cyclonedx(FIXTURES / "cyclonedx" / "defined_refs.json")
    assert record.resolve("svc-1").kinds == ("service",)
    items = extract_evidence(finding(roles=primary(record)), s1.Stage1Index([record]))
    assert EvidenceState.PRESENT not in {i.state for i in items}
    assert EvidenceState.ABSENT not in {i.state for i in items}


# ---- roles ---------------------------------------------------------------------------------

def test_no_primary_sbom_role_means_unknown_for_inv_decl_gen(complete):
    # The record is indexed and even listed as a corroborating document, but is not primary.
    f = finding(roles={complete.doc_id: DocumentRole.CORROBORATING})
    items = extract_evidence(f, s1.Stage1Index([complete]))
    for dimension in ("INV", "DECL", "GEN"):
        (item,) = by_dim(items, dimension)
        assert item.state is EvidenceState.UNKNOWN and item.source_doc is None
        assert item.value_or_ref.code == "NO_PRIMARY_SBOM"


def test_a_role_without_a_supplied_record_is_reported(complete):
    f = finding(roles={"ghost-doc": DocumentRole.PRIMARY_SBOM})
    items = extract_evidence(f, s1.Stage1Index())
    assert {i.value_or_ref.code for i in items if i.dimension != "MATCH"} == {"RECORD_NOT_SUPPLIED"}


def test_an_indexed_document_with_no_role_is_ignored(complete):
    items = extract_evidence(finding(), s1.Stage1Index([complete]))
    assert all(i.source_doc is None for i in items)


# ---- REACH (K4) ----------------------------------------------------------------------------

def test_dependency_edges_are_k4_only_and_stay_unknown(complete):
    f = finding(REACH, roles=primary(complete))
    items = extract_evidence(f, s1.Stage1Index([complete]))
    (reach,) = by_dim(items, "REACH")
    assert reach.state is EvidenceState.UNKNOWN
    assert reach.value_or_ref.code == "K4_DEPENDENCY_GRAPH_ONLY"
    assert reach.value_or_ref.locators == tuple(e.locator for e in complete.edges)
    assert aggregate_state([reach]) is EvidenceState.UNKNOWN
    assert {i.state for i in items} == {EvidenceState.UNKNOWN}


def test_spdx_relationships_are_also_k4_only(spdx):
    (reach,) = by_dim(extract_evidence(finding(REACH, roles=primary(spdx)), s1.Stage1Index([spdx])), "REACH")
    assert reach.state is EvidenceState.UNKNOWN and reach.value_or_ref.code == "K4_DEPENDENCY_GRAPH_ONLY"


def test_reach_without_any_edges_or_documents_is_no_analysis(no_comp):
    (reach,) = by_dim(extract_evidence(finding(REACH)), "REACH")
    assert reach.value_or_ref.code == "NO_ANALYSIS" and reach.state is EvidenceState.UNKNOWN
    (alone,) = by_dim(extract_evidence(finding(REACH, roles=primary(no_comp)), s1.Stage1Index([no_comp])), "REACH")
    assert alone.value_or_ref.code == "NO_ANALYSIS"


def test_reachability_findings_emit_no_cnp_dimensions_and_report_unevaluated_inputs(complete):
    result = extract(finding(REACH, roles=primary(complete)), s1.Stage1Index([complete]))
    assert {i.dimension for i in result.items} == {"REACH"}
    unevaluated = " ".join(d.message for d in result.diagnostics)
    for dimension in ("LOCUS", "ENTRY", "HAZ[class]", "CFG"):
        assert dimension in unevaluated


# ---- boundaries ------------------------------------------------------------------------------

def test_unsupported_justification_is_reported_not_coerced():
    for raw in ("vulnerable_code_not_present", "COMPONENT_NOT_PRESENT", ""):
        result = extract(finding(raw))
        assert result.items == []
        assert [d.code for d in result.diagnostics] == ["UNSUPPORTED_JUSTIFICATION"]
        assert repr(raw) in result.diagnostics[0].message


def test_other_dispositions_are_an_input_error_not_a_verdict():
    result = extract(finding(disposition=Disposition.AFFECTED))
    assert result.items == []
    assert [d.code for d in result.diagnostics] == ["DISPOSITION_NOT_EVALUATED"]


def test_extraction_does_not_mutate_its_inputs(complete):
    f = finding(roles=primary(complete))
    index = s1.Stage1Index([complete])
    before_roles = dict(f.document_roles)
    before_doc = complete.document.method, complete.document.declared_metadata.copy()
    extract(f, index)
    extract(f, index)
    assert f.document_roles == before_roles and f.evidence == []
    assert (complete.document.method, complete.document.declared_metadata) == before_doc


def test_no_extracted_item_is_ever_present_or_absent():
    record = s1.load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    for justification in (CNP, REACH):
        for component in (None, Component(name="x")):
            items = extract_evidence(
                finding(justification, component=component, roles=primary(record)), s1.Stage1Index([record])
            )
            assert {i.state for i in items} <= {EvidenceState.UNKNOWN}


@pytest.mark.skip(
    reason="pending for the legacy extract() API only: MATCH with a resolved C, full-list INV, DECL selection, BIND and "
    "GEN beyond 'method absent' are computed by the integrated CNP pipeline (evidence.evaluator), and LOCUS/ENTRY/HAZ/CFG "
    "and K1-K3 by the reachability pipeline (evidence.reach_evaluator), not by extract() "
    "(see docs/open_issues_register.md)"
)
def test_remaining_evidence_dimensions():
    raise AssertionError("placeholder")
