"""Tests for evidence.inventory_checks: the required structural check R1 and the assessment.

R1 classifies a dependency or relationship endpoint only by reference rules that were verified
against the official CycloneDX 1.5/1.6 schemas. Nothing is classified from SPDX endpoint forms, and a
BOM-Link is never called dangling.
"""

import copy
import json

import pytest

from evidence import inventory_checks as IC
from evidence import stage1_records as s1
from evidence.bind import BindBasis, BindCode, BindEvaluation
from evidence.cnp_rules import BindState
from evidence.inv import CheckOutcome, Emptiness, Interpretability, Relevance
from evidence.inventory_checks import EndpointClass as EC, EndpointReason as ER
from evidence.stage1_records import ReferenceStatus
from sbom_parser import cyclonedx as cdx_parser
from tests.pipeline_support import FIXTURES, cdx, spdx


def matched(doc_id):
    return BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH,
                          agreeing_digests=("sha256:aa",), document_id=doc_id)


def unbound(doc_id):
    return BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=doc_id)


def cdx_doc(spec="1.6", **extra):
    data = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1}
    data.update(extra)
    return s1.load_cyclonedx(json.dumps(data).encode())


# ---- classification ------------------------------------------------------------------------------------

def test_a_document_whose_endpoints_all_resolve_passes():
    result = IC.check_endpoint_resolution(cdx("../equivalent/app.cdx.json"))
    assert result.outcome is CheckOutcome.PASSED and result.findings
    assert {f.classification for f in result.findings} == {EC.RESOLVED}
    assert {f.reason for f in result.findings} == {ER.IN_REGISTRY}


def test_a_document_without_edges_passes_because_the_check_ran_and_found_nothing():
    result = IC.check_endpoint_resolution(cdx_doc(components=[{"type": "library", "name": "a"}]))
    assert result.outcome is CheckOutcome.PASSED and result.findings == ()


def test_a_local_bom_ref_missing_from_the_registry_is_a_verified_dangling_candidate():
    result = IC.check_endpoint_resolution(cdx("dangling_local.json"))
    assert result.outcome is CheckOutcome.CONTRADICTION_FOUND
    [dangling] = result.local_unregistered
    assert (dangling.ref, dangling.role, dangling.reason) == ("ghost-ref", "target", ER.LOCAL_BOM_REF_NOT_IN_REGISTRY)


def test_a_bom_link_is_an_unverified_form_never_dangling():
    result = IC.check_endpoint_resolution(cdx("bom_link_endpoint.json"))
    assert result.outcome is CheckOutcome.NOT_PERFORMED and not result.local_unregistered
    [link] = result.unverified
    assert link.reason is ER.BOM_LINK_IN_LOCAL_REFERENCE_POSITION and link.ref.startswith("urn:cdx:")


def test_bom_link_detection_is_case_insensitive():
    record = cdx_doc(components=[{"type": "library", "name": "a", "bom-ref": "a"}],
                     dependencies=[{"ref": "a", "dependsOn": ["URN:CDX:3e671687-395b-41f5-a30f-a58921a69b79/1#x"]}])
    assert IC.check_endpoint_resolution(record).outcome is CheckOutcome.NOT_PERFORMED


def test_a_service_reference_resolves():
    result = IC.check_endpoint_resolution(cdx("service_endpoint.json"))
    assert result.outcome is CheckOutcome.PASSED and not result.local_unregistered


def test_subject_nested_references_resolve_in_the_registry():
    result = IC.check_endpoint_resolution(cdx("subject_nested.json"))
    assert result.outcome is CheckOutcome.PASSED


def test_a_dangling_reference_beats_an_unverified_form():
    record = cdx_doc(components=[{"type": "library", "name": "a", "bom-ref": "a"}],
                     dependencies=[{"ref": "a", "dependsOn": ["urn:cdx:x/1#y", "ghost"]}])
    assert IC.check_endpoint_resolution(record).outcome is CheckOutcome.CONTRADICTION_FOUND


def test_spdx_unregistered_endpoints_are_never_classified_dangling():
    for name in ("external_forms.json", "unregistered_local.json"):
        result = IC.check_endpoint_resolution(spdx(name))
        assert not result.local_unregistered, name
        assert result.outcome is CheckOutcome.NOT_PERFORMED, name
        assert {f.reason for f in result.unverified} == {ER.SPDX_ENDPOINT_FORMS_UNVERIFIED}, name


def test_spdx_with_only_registered_endpoints_passes():
    assert IC.check_endpoint_resolution(spdx("../equivalent/app.spdx.json")).outcome is CheckOutcome.PASSED


def _with_version(record, version):
    clone = copy.deepcopy(record)
    clone.document.declared_metadata["spec_version"] = version
    return clone


def test_an_unverified_format_version_never_classifies_a_dangling_reference():
    # the parser accepts only 1.5 and 1.6; a record from another source/version is simulated here
    record = _with_version(cdx("dangling_local.json"), "1.4")
    result = IC.check_endpoint_resolution(record)
    assert result.outcome is CheckOutcome.NOT_PERFORMED and not result.local_unregistered
    assert {f.reason for f in result.unverified} >= {ER.FORMAT_VERSION_NOT_VERIFIED}
    assert IC.format_version_verified(record) is False
    assert IC.format_version_verified(cdx_doc("1.5")) and IC.format_version_verified(cdx_doc("1.6"))


def test_findings_are_deterministically_ordered_and_input_is_not_mutated():
    record = cdx("dangling_local.json")
    snapshot = copy.deepcopy(record)
    first = IC.check_endpoint_resolution(record)
    assert record == snapshot and IC.check_endpoint_resolution(record) == first
    keys = [(f.edge_locator, f.role, f.ref) for f in first.findings]
    assert keys == sorted(keys)


def test_observations_of_another_document_are_refused():
    from evidence.inventory_observations import observe_inventory
    with pytest.raises(ValueError):
        IC.check_endpoint_resolution(cdx("dangling_local.json"), observe_inventory(cdx("service_endpoint.json")))


# ---- the registry covers every verified schema location (regression against the schema walk) -----------

def _empty_for(kind):
    return {"name": "n"} if kind == "service" else {"type": "library", "name": "n"}


def _insert(root, path, obj):
    node = root
    for index, step in enumerate(path):
        last = index == len(path) - 1
        if step == "*":
            raise AssertionError("handled by the caller")
        if last:
            node[step] = obj
        else:
            node = node.setdefault(step, {})


def _document_with_ref_at(path, kind, ref, spec):
    root = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1}
    obj = dict(_empty_for(kind), **{"bom-ref": ref})
    node = root
    for index, step in enumerate(path):
        last = index == len(path) - 1
        nxt = path[index + 1] if not last else None
        if step == "*":
            continue
        if last:
            node[step] = obj
        elif nxt == "*":
            holder = [{}] if index + 2 < len(path) else [obj]
            node[step] = holder
            if index + 2 < len(path):
                node = holder[0]
            else:
                break
        else:
            node = node.setdefault(step, {})
    return root


@pytest.mark.parametrize("spec", ["1.5", "1.6"])
def test_every_verified_component_and_service_location_registers_its_bom_ref(spec):
    locations = list(cdx_parser._DEFINED_REF_LOCATIONS)
    if spec == "1.6":
        locations += list(cdx_parser._DEFINED_REF_LOCATIONS_1_6)
    assert len(locations) >= 9
    for index, (path, kind, _label) in enumerate(locations):
        ref = f"ref-{index}"
        data = _document_with_ref_at(path, kind, ref, spec)
        data["components"] = [{"type": "library", "name": "holder", "bom-ref": "holder"}]
        data["dependencies"] = [{"ref": "holder", "dependsOn": [ref]}]
        record = s1.load_cyclonedx(json.dumps(data).encode())
        result = IC.check_endpoint_resolution(record)
        assert result.outcome is CheckOutcome.PASSED, (spec, path)
        assert {f.classification for f in result.findings} == {EC.RESOLVED}, (spec, path)


def test_declarations_targets_are_registered_for_1_6_only():
    path, kind, _ = cdx_parser._DEFINED_REF_LOCATIONS_1_6[0]
    data = _document_with_ref_at(path, kind, "decl-ref", "1.5")
    data["components"] = [{"type": "library", "name": "holder", "bom-ref": "holder"}]
    data["dependencies"] = [{"ref": "holder", "dependsOn": ["decl-ref"]}]
    try:
        record = s1.load_cyclonedx(json.dumps(data).encode())
    except Exception:  # the parser may reject or ignore the 1.6-only block in a 1.5 document
        return
    assert IC.check_endpoint_resolution(record).outcome is not CheckOutcome.PASSED


def test_pedigree_and_nested_services_are_registered():
    data = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "library", "name": "a", "bom-ref": "a",
                        "pedigree": {"ancestors": [{"type": "library", "name": "anc", "bom-ref": "anc"}]}}],
        "services": [{"name": "outer", "bom-ref": "outer", "services": [{"name": "inner", "bom-ref": "inner"}]}],
        "dependencies": [{"ref": "a", "dependsOn": ["anc", "outer", "inner"]}],
    }
    record = s1.load_cyclonedx(json.dumps(data).encode())
    assert IC.check_endpoint_resolution(record).outcome is CheckOutcome.PASSED


# ---- the assessment ------------------------------------------------------------------------------------------------

def test_a_clean_bound_document_gives_an_interpretable_non_empty_assessment():
    record = cdx("../equivalent/app.cdx.json")
    assessment, r1 = IC.build_assessment(record, matched(record.doc_id))
    assert assessment.document_id == record.doc_id
    assert assessment.interpretability is Interpretability.INTERPRETABLE
    assert assessment.emptiness is Emptiness.NON_EMPTY
    [check] = assessment.checks
    assert (check.check_id, check.required, check.outcome) == (IC.CHECK_R1, True, CheckOutcome.PASSED)
    assert r1.outcome is CheckOutcome.PASSED


def test_a_defect_is_relevant_to_s_only_when_bind_matched_for_this_document():
    record = cdx("dangling_local.json")
    bound_assessment, _ = IC.build_assessment(record, matched(record.doc_id))
    assert bound_assessment.checks[0].relevance is Relevance.RELEVANT_TO_S
    unbound_assessment, _ = IC.build_assessment(record, unbound(record.doc_id))
    assert unbound_assessment.checks[0].relevance is Relevance.UNDETERMINED
    other = BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, BindCode.DIGEST_MATCH,
                           agreeing_digests=("sha256:aa",), document_id="another")
    assert IC.build_assessment(record, other)[0].checks[0].relevance is Relevance.UNDETERMINED


def test_unverified_forms_make_the_check_not_performed():
    record = cdx("bom_link_endpoint.json")
    assessment, _ = IC.build_assessment(record, matched(record.doc_id))
    assert assessment.checks[0].outcome is CheckOutcome.NOT_PERFORMED
    assert assessment.checks[0].relevance is Relevance.UNDETERMINED


def test_an_empty_member_domain_is_empty_not_a_state():
    record = cdx_doc()
    assessment, _ = IC.build_assessment(record, matched(record.doc_id))
    assert assessment.emptiness is Emptiness.EMPTY


def test_a_domain_that_was_not_extracted_is_not_interpretable_and_not_assessed():
    record = cdx("subject_nested.json")
    stripped = copy.deepcopy(record)
    del stripped.document.declared_metadata["subject_component_index"]
    stripped = _decode_without_subject_index(stripped)
    assessment, _ = IC.build_assessment(stripped, matched(stripped.doc_id))
    assert assessment.interpretability is Interpretability.NOT_ASSESSED
    assert assessment.emptiness is Emptiness.NOT_ASSESSED
    assert any("not fully extracted" in note for note in assessment.notes)


def _decode_without_subject_index(record):
    import dataclasses
    return dataclasses.replace(record, subject_components=(), subject_components_extracted=False)


def test_an_unverified_version_is_not_interpretable():
    record = _with_version(cdx("../equivalent/app.cdx.json"), "1.4")
    assessment, _ = IC.build_assessment(record, matched(record.doc_id))
    assert assessment.interpretability is Interpretability.NOT_ASSESSED
    assert any("no verified reference rules" in note for note in assessment.notes)


def test_reference_conflicts_are_diagnostics_only_never_a_contradiction():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": "a", "bom-ref": "dup"}, {"type": "library", "name": "b", "bom-ref": "dup"}]}
    record = s1.load_cyclonedx(json.dumps(data).encode())
    assessment, r1 = IC.build_assessment(record, matched(record.doc_id))
    assert r1.outcome is CheckOutcome.PASSED and assessment.checks[0].outcome is CheckOutcome.PASSED
    assert any(note.startswith("C3 (deferred)") for note in assessment.notes)


def test_the_assessment_never_infers_completeness_from_edges_or_counts():
    # a rich, fully resolved graph still produces no state, completeness or INV conclusion
    record = cdx("../equivalent/app.cdx.json")
    assessment, _ = IC.build_assessment(record, matched(record.doc_id))
    assert not hasattr(assessment, "state") and not hasattr(assessment, "complete")


# ---- dependency node refs and the vacuous pass ----------------------------------------------------------------------

def _doc_with_dependencies(dependencies):
    return cdx_doc(components=[{"type": "library", "name": "a", "bom-ref": "a"}], dependencies=dependencies)


@pytest.mark.parametrize("dependencies", [
    [{"ref": "ghost"}],                                  # no dependsOn at all
    [{"ref": "ghost", "dependsOn": []}],                 # explicitly empty
    [{"ref": "a", "dependsOn": []}, {"ref": "ghost"}],
])
def test_a_dangling_dependencies_ref_is_found_even_without_any_depends_on(dependencies):
    result = IC.check_endpoint_resolution(_doc_with_dependencies(dependencies))
    assert result.outcome is CheckOutcome.CONTRADICTION_FOUND
    [finding] = result.local_unregistered
    assert (finding.role, finding.ref, finding.reason) == ("node", "ghost", ER.LOCAL_BOM_REF_NOT_IN_REGISTRY)
    assert finding.edge_locator.startswith("#/dependencies/")


def test_a_resolved_or_bom_link_dependencies_ref_is_classified_like_any_endpoint():
    assert IC.check_endpoint_resolution(_doc_with_dependencies([{"ref": "a"}])).outcome is CheckOutcome.PASSED
    link = _doc_with_dependencies([{"ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#x"}])
    result = IC.check_endpoint_resolution(link)
    assert result.outcome is CheckOutcome.NOT_PERFORMED and not result.local_unregistered


def test_a_dangling_node_ref_makes_inv_contradictory_end_to_end():
    from evidence.evaluator import evaluate
    from evidence.stage1_records import Stage1Index
    from tests.pipeline_support import ABSENT, X, make_profile, vex_findings
    data = json.loads((FIXTURES / "equivalent" / "app.cdx.json").read_text())
    data["dependencies"] = [{"ref": "ghost", "dependsOn": []}]
    record = s1.load_cyclonedx(json.dumps(data).encode())
    profile = make_profile(record.doc_id, target=ABSENT, location={"placement": "nested_under_component", "parent_ref": "app-1"})
    outcome = evaluate(profile, vex_findings(), Stage1Index([record]))
    assert outcome.dimension_states["INV"] == "Contradictory" and "INVENTORY_CONTRADICTION" in outcome.result.codes
    assert outcome.result.verdict.value == "Insufficient"


def test_a_pass_with_nothing_to_check_is_reported_as_vacuous():
    record = cdx_doc(components=[{"type": "library", "name": "a", "bom-ref": "a"}])
    assessment, r1 = IC.build_assessment(record, matched(record.doc_id))
    assert r1.outcome is CheckOutcome.PASSED and r1.findings == ()
    assert any("vacuous pass" in note for note in assessment.notes)
    full, _ = IC.build_assessment(cdx("../equivalent/app.cdx.json"), matched(cdx("../equivalent/app.cdx.json").doc_id))
    assert not any("vacuous" in note for note in full.notes)
