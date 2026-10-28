"""Tests for evidence.pipeline_inputs (profile-driven input assembly).

Assembly only: nothing here derives an evidence state, runs BIND, INV, DECL or MATCH,
computes provenance or evaluates a rule.
"""

import ast
import copy
import dataclasses
from pathlib import Path

import pytest

from evidence import pipeline_inputs as PI
from evidence.extraction import extract
from evidence.pipeline_inputs import (
    AssemblyDiagnosticCode,
    AssemblyError,
    AssemblyErrorCode as A,
    PipelineAssembly,
    assemble,
)
from evidence.profile import ProfileError, ProfileErrorCode as E, parse_profile
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex, load_spdx
from model import ArtifactKind, DocumentRole, Finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PRODUCT = "pkg:oci/example-app@sha256%3Aabc"   # the product of openvex/component_not_present.json
VULN = "CVE-2026-0001"


def sbom():
    return load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")


def vex():
    return load_openvex(FIXTURES / "openvex" / "component_not_present.json")


def profile_for(doc_id, *, selector=True, target=None, product=PRODUCT, vulnerability=VULN):
    data = {
        "schema_version": "1", "profile_id": "prof-1",
        "scope": {"product_id": product, "version": "2.0.0", "artifact_kind": "container"},
        "documents": [{"doc_id": doc_id, "role": "primary_sbom"}],
    }
    if selector:
        data["finding_selector"] = {"vulnerability": vulnerability, "product_id": product}
    if target:
        data["target"] = target
    return parse_profile(data)


# ---- successful assembly on real fixtures -------------------------------------------------------------

def test_real_openvex_and_cyclonedx_fixtures_assemble():
    record, statements = sbom(), vex()
    target = {"component": {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}}
    result = assemble(profile_for(record.doc_id, target=target), list(statements.findings), Stage1Index([record]))
    assert isinstance(result, PipelineAssembly) and result.diagnostics == ()
    assert result.primary_doc_id == record.doc_id == result.primary_record.doc_id
    finding = result.finding
    assert finding.vulnerability.id == VULN and finding.scope.product_id == PRODUCT
    assert (finding.scope.version, finding.scope.artifact_kind) == ("2.0.0", ArtifactKind.CONTAINER)
    assert finding.component is not None and finding.component.purl == "pkg:npm/left-pad@1.3.0"
    assert finding.document_roles == {record.doc_id: DocumentRole.PRIMARY_SBOM}


def test_without_a_target_the_component_stays_unresolved():
    record = sbom()
    result = assemble(profile_for(record.doc_id), list(vex().findings), Stage1Index([record]))
    assert result.finding.component is None  # never filled from the product


def test_every_registered_document_id_is_a_key_and_the_sbom_is_registered_as_supplied():
    record, statements = sbom(), vex()
    result = assemble(profile_for(record.doc_id), list(statements.findings), Stage1Index([record]))
    registry = result.finding.source_documents
    assert record.doc_id in registry and registry[record.doc_id] == record.document
    assert all(key == document.doc_id for key, document in registry.items())
    assert set(registry) == {statements.document.doc_id, f"{statements.document.doc_id}#/statements/0", record.doc_id}
    assert registry[record.doc_id] is result.primary_record.document


def test_the_assembly_is_frozen():
    result = assemble(profile_for(sbom().doc_id), list(vex().findings), Stage1Index([sbom()]))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.profile_id = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.finding = None


def test_existing_extraction_items_refer_to_registered_primary_documents():
    record = sbom()
    result = assemble(profile_for(record.doc_id), list(vex().findings), Stage1Index([record]))
    outcome = extract(result.finding, Stage1Index([record]))
    assert outcome.items
    sources = {item.source_doc for item in outcome.items}
    assert record.doc_id in sources
    for item in outcome.items:
        if item.source_doc is not None:
            assert item.source_doc in result.finding.source_documents
            assert result.finding.document_roles[item.source_doc] is DocumentRole.PRIMARY_SBOM


# ---- finding selection --------------------------------------------------------------------------------------

def test_zero_one_and_several_matching_findings_follow_the_selector_semantics():
    record = sbom()
    index = Stage1Index([record])
    statements = load_openvex(FIXTURES / "openvex" / "subcomponents.json")
    findings = list(statements.findings)
    other = profile_for(record.doc_id, product="pkg:oci/other-app@sha256%3Aghi", vulnerability="CVE-2026-0100")
    assert assemble(other, findings, index).finding.scope.product_id == "pkg:oci/other-app@sha256%3Aghi"  # exactly one
    ambiguous = profile_for(record.doc_id, product="pkg:oci/example-app@sha256%3Adef", vulnerability="CVE-2026-0100")
    with pytest.raises(ProfileError) as excinfo:
        assemble(ambiguous, findings, index)  # three subcomponent findings match
    assert excinfo.value.code is E.FINDING_AMBIGUOUS
    with pytest.raises(ProfileError) as excinfo:
        assemble(profile_for(record.doc_id, vulnerability="CVE-0000-0000"), findings, index)
    assert excinfo.value.code is E.FINDING_NOT_FOUND


def test_without_a_selector_exactly_one_finding_is_required():
    record = sbom()
    index = Stage1Index([record])
    prof = profile_for(record.doc_id, selector=False)
    assert assemble(prof, list(vex().findings), index).finding.vulnerability.id == VULN
    with pytest.raises(ProfileError) as excinfo:
        assemble(prof, list(load_openvex(FIXTURES / "openvex" / "subcomponents.json").findings), index)
    assert excinfo.value.code is E.FINDING_SELECTOR_REQUIRED
    with pytest.raises(ProfileError) as excinfo:
        assemble(prof, [], index)
    assert excinfo.value.code is E.FINDING_NOT_FOUND


def test_profile_layer_errors_propagate_unchanged():
    record = sbom()
    index = Stage1Index([record])
    with_component = list(load_openvex(FIXTURES / "openvex" / "subcomponents.json").findings)[0]  # C already known
    kwargs = dict(product="pkg:oci/example-app@sha256%3Adef", vulnerability="CVE-2026-0100", selector=False)
    prof = profile_for(record.doc_id, target={"component": {"name": "x"}}, **kwargs)
    with pytest.raises(ProfileError) as excinfo:
        assemble(prof, [with_component], index)
    assert excinfo.value.code is E.TARGET_CONFLICT
    with pytest.raises(ProfileError) as excinfo:
        assemble(profile_for(record.doc_id, product="somewhere-else", selector=False), [vex().findings[0]], index)
    assert excinfo.value.code is E.SCOPE_CONFLICT


# ---- document identity -----------------------------------------------------------------------------------------

def test_a_missing_record_fails_conservatively():
    record = sbom()
    findings = list(vex().findings)
    for index in (Stage1Index(), Stage1Index([load_spdx(FIXTURES / "spdx" / "subjects.json")])):
        with pytest.raises(AssemblyError) as excinfo:
            assemble(profile_for(record.doc_id), findings, index)
        assert excinfo.value.code is A.RECORD_NOT_SUPPLIED and excinfo.value.doc_id == record.doc_id


@pytest.mark.parametrize(
    "transform",
    [str.upper, lambda s: s + " ", lambda s: " " + s, lambda s: s[:-1], lambda s: s.replace("cyclonedx:", ""),
     lambda s: s.replace("sha256", "SHA256"), lambda s: s + "#/metadata/component"],
)
def test_near_matching_ids_are_not_matched(transform):
    record = sbom()
    near = transform(record.doc_id)
    assert near != record.doc_id
    with pytest.raises(AssemblyError) as excinfo:
        assemble(profile_for(near), list(vex().findings), Stage1Index([record]))
    assert excinfo.value.code is A.RECORD_NOT_SUPPLIED


def test_subject_references_and_locators_never_substitute_for_a_document_id():
    record = sbom()
    for not_an_id in ("app-1", "#/metadata/component", record.document.subjects[0].locator, "SPDXRef-DOCUMENT"):
        with pytest.raises(AssemblyError) as excinfo:
            assemble(profile_for(not_an_id), list(vex().findings), Stage1Index([record]))
        assert excinfo.value.code is A.RECORD_NOT_SUPPLIED


def test_a_record_filed_under_an_id_it_does_not_carry_is_a_conflict():
    record, other = sbom(), load_spdx(FIXTURES / "spdx" / "subjects.json")

    class Misfiled(Stage1Index):
        def get(self, doc_id):
            return other  # claims to answer for any id

    with pytest.raises(AssemblyError) as excinfo:
        assemble(profile_for(record.doc_id), list(vex().findings), Misfiled())
    assert excinfo.value.code is A.RECORD_IDENTITY_CONFLICT


def test_a_different_document_already_registered_under_the_id_is_a_conflict():
    record = sbom()
    finding = copy.deepcopy(vex().findings[0])
    impostor = copy.deepcopy(record.document)
    impostor.producer = "someone else"
    finding.source_documents[record.doc_id] = impostor
    with pytest.raises(AssemblyError) as excinfo:
        assemble(profile_for(record.doc_id), [finding], Stage1Index([record]))
    assert excinfo.value.code is A.SOURCE_DOCUMENT_CONFLICT
    same = copy.deepcopy(vex().findings[0])
    same.source_documents[record.doc_id] = copy.deepcopy(record.document)  # an identical registration is fine
    assert assemble(profile_for(record.doc_id), [same], Stage1Index([record])).finding.source_documents[record.doc_id]


def test_unreferenced_records_are_ignored_with_a_diagnostic():
    record, spdx = sbom(), load_spdx(FIXTURES / "spdx" / "subjects.json")
    result = assemble(profile_for(record.doc_id), list(vex().findings), Stage1Index([spdx, record]))
    [diagnostic] = result.diagnostics
    assert diagnostic.code is AssemblyDiagnosticCode.UNREFERENCED_RECORDS_IGNORED and spdx.doc_id in diagnostic.detail
    assert spdx.doc_id not in result.finding.source_documents and set(result.finding.document_roles) == {record.doc_id}


# ---- no mutation ----------------------------------------------------------------------------------------------------

def test_success_mutates_nothing_and_the_assembly_is_independent_of_the_inputs():
    record, statements = sbom(), vex()
    findings, index = list(statements.findings), Stage1Index([record])
    profile = profile_for(record.doc_id, target={"component": {"name": "x", "version": "1"}})
    snapshot = (copy.deepcopy(findings), copy.deepcopy(record), copy.deepcopy(profile), copy.deepcopy(index.doc_ids()))
    result = assemble(profile, findings, index)
    assert (findings, record, profile, index.doc_ids()) == snapshot
    # changing the assembly afterwards does not reach the caller's objects
    result.finding.source_documents.clear()
    result.finding.scope.version = "changed"
    result.primary_record.document.producer = "changed"
    result.primary_record.document.subjects.clear()
    assert (findings, record, profile) == snapshot[:3] and index.get(record.doc_id) == snapshot[1]
    assert findings[0].document_roles == {} and findings[0].component is None


@pytest.mark.parametrize("failure", ["missing", "identity", "selector", "scope"])
def test_failures_leave_no_partial_mutation(failure):
    record, statements = sbom(), vex()
    findings, index = list(statements.findings), Stage1Index([record])
    prof = profile_for(record.doc_id)
    if failure == "missing":
        prof = profile_for("cyclonedx:sha256:missing")
    elif failure == "selector":
        prof = profile_for(record.doc_id, vulnerability="CVE-0")
    elif failure == "scope":
        prof = profile_for(record.doc_id, product="elsewhere", selector=False)
    elif failure == "identity":
        class Misfiled(Stage1Index):
            def get(self, doc_id):
                return load_spdx(FIXTURES / "spdx" / "subjects.json")
        index = Misfiled([record])
    snapshot = (copy.deepcopy(findings), copy.deepcopy(record), copy.deepcopy(prof))
    with pytest.raises((AssemblyError, ProfileError)):
        assemble(prof, findings, index)
    assert (findings, record, prof) == snapshot
    assert findings[0].document_roles == {} and record.doc_id not in findings[0].source_documents


# ---- ordering ---------------------------------------------------------------------------------------------------------

def test_input_ordering_does_not_change_the_result():
    record, spdx = sbom(), load_spdx(FIXTURES / "spdx" / "subjects.json")
    findings = list(load_openvex(FIXTURES / "openvex" / "subcomponents.json").findings)
    prof = profile_for(record.doc_id, product="pkg:oci/other-app@sha256%3Aghi", vulnerability="CVE-2026-0100")
    orders = (findings, findings[::-1], findings[2:] + findings[:2])
    # findings order and index insertion order never change the result ...
    with_extra = {repr(assemble(prof, list(o), i)) for o in orders
                  for i in (Stage1Index([record, spdx]), Stage1Index([spdx, record]))}
    only_primary = {repr(assemble(prof, list(o), Stage1Index([record]))) for o in orders}
    assert len(with_extra) == 1 and len(only_primary) == 1
    # ... and the extra record only adds the diagnostic
    assert with_extra != only_primary


# ---- boundary --------------------------------------------------------------------------------------------------------------

def test_assembly_derives_nothing_and_imports_no_evaluation_module():
    tree = ast.parse(open(PI.__file__, encoding="utf-8").read())
    imported = set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            names.add(node.id)
    assert imported <= {"__future__", "copy", "dataclasses", "enum", "typing", "evidence.profile",
                        "evidence.stage1_records", "model"}
    assert not names & {"EvidenceState", "EvidenceItem", "evaluate_cnp", "evaluate_bind", "derive_inv",
                        "enumerate_decl_candidates", "extract", "ProvenanceLevel", "Verdict"}
    assert Finding  # the only model types used are Finding (and the record types)
