"""End-to-end tests of the integrated CNP evidence pipeline (evidence.evaluator).

Real parser fixtures -> validated profile -> assembly -> observations -> BIND -> INV / DECL / MATCH
-> provenance -> typed items -> aggregation -> CnpInputs -> engine -> structured outcome. The
verification inputs used to reach P3 are synthetic and test-only.
"""

import copy
import itertools
import json
from dataclasses import replace

import pytest

from evidence import evaluator as ev
from evidence.cnp_rules import BindState, GenState
from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, RefusalCode as R, evaluate
from evidence.items import ItemIntegrityError, validate_items
from evidence.inventory_members import inventory_members
from evidence.profile import parse_profile
from evidence.stage1_records import Stage1Index, load_cyclonedx
from model import ArtifactKind, DocumentRole, EvidenceState as S, ProvenanceLevel as P
from pipeline_support import (
    ABSENT, FIXTURES, PRODUCT, TOP_LEVEL, X, cdx, equivalent, load_openvex, make_profile, profile_data, spdx,
    verification_for, vex_findings,
)
from reports.verdict import Verdict

SUPPORTED, WEAK, INSUFFICIENT = Verdict.SUPPORTED, Verdict.WEAK, Verdict.INSUFFICIENT
RANK = {INSUFFICIENT: 0, WEAK: 1, SUPPORTED: 2}
ROOT_NESTED = {"placement": "nested_under_component", "parent_ref": "app-1"}  # the root's direct child (G6-D12)
FULL = ("#/components", "#/compositions/0", "#/packages")


def run(record=None, *, verification="p3", findings=None, extra_records=(), **profile_kwargs):
    record = record or equivalent("cdx")
    profile_kwargs.setdefault("target", ABSENT)
    profile_kwargs.setdefault("location", ROOT_NESTED)
    profile = make_profile(record.doc_id, **profile_kwargs)
    if verification == "p3":
        verification = verification_for(record.doc_id, FULL)
    index = Stage1Index([record, *extra_records])
    return evaluate(profile, findings if findings is not None else vex_findings(), index, verification)


def codes(outcome):
    return list(outcome.result.codes)


# ---- the supported path and the engine's rules, end to end ---------------------------------------------

def test_supported_requires_every_condition_including_p3():
    outcome = run()
    assert isinstance(outcome, EvaluationOutcome)
    assert outcome.result.verdict is SUPPORTED and outcome.result.codes == () and outcome.result.limitations == ()
    assert outcome.dimension_states == {"BIND": "matched", "DECL": "Present", "GEN": "unknown",
                                        "INV": "Present", "MATCH": "Absent"}
    assert outcome.bind.basis.value == "digest"
    assert (outcome.provenance.prov_sbom, outcome.provenance.prov_decl) == (P.P3, P.P3)
    assert outcome.cnp_inputs.separate_basis is None and outcome.cnp_inputs.gen is GenState.UNKNOWN
    assert outcome.evaluation.supported_conditions_hold


def test_nt2_like_p2_document_without_verification_is_weak():
    outcome = run(verification=None)
    assert outcome.result.verdict is WEAK
    assert codes(outcome) == ["DECLARATION_BELOW_P3", "INVENTORY_PROVENANCE_BELOW_P3"]  # N11, N12
    assert (outcome.provenance.prov_sbom, outcome.provenance.prov_decl) == (P.P2, P.P2)
    assert "P3_NOT_AVAILABLE:not_supplied" in outcome.limitations


def test_verification_that_does_not_cover_a_list_or_record_caps_it():
    outcome = run(verification=verification_for(equivalent("cdx").doc_id, ("#/components",)))
    assert outcome.provenance.prov_sbom is P.P3 and outcome.provenance.prov_decl is P.P1
    assert outcome.result.verdict is WEAK and "DECLARATION_BELOW_P3" in codes(outcome)
    outcome = run(verification=verification_for(equivalent("cdx").doc_id, ("#/compositions/0",)))
    assert outcome.provenance.prov_sbom is P.P1  # the cap: the list lies outside the verified coverage


@pytest.mark.parametrize("bad", [
    lambda d: verification_for(d, FULL, verified=False),
    lambda d: verification_for(d, FULL, anchor="stranger"),
    lambda d: verification_for(d, None),
    lambda d: verification_for("cyclonedx:sha256:" + "00" * 32, FULL),
])
def test_an_unusable_verification_result_cannot_grant_p3(bad):
    record = equivalent("cdx")
    outcome = run(record, verification=bad(record.doc_id))
    assert outcome.result.verdict is WEAK
    assert (outcome.provenance.prov_sbom, outcome.provenance.prov_decl) == (P.P2, P.P2)


def test_nt13_like_a_found_component_is_insufficient_n1():
    outcome = run(target={"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"})
    assert outcome.match.state is S.PRESENT and outcome.result.verdict is INSUFFICIENT
    assert "CLAIM_CONTRADICTED_BY_INVENTORY" in codes(outcome)


def test_a_component_nested_under_a_cyclonedx_component_is_found():
    outcome = run(target={"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"})
    assert outcome.match.state is S.PRESENT and outcome.match.matches[0].locator == "#/components/1/components/0"


def test_nt5_like_name_and_version_only_is_ambiguous_n8():
    outcome = run(target={"name": "lib-a", "version": "1.0"})
    assert outcome.match.state is S.AMBIGUOUS and outcome.result.verdict is WEAK
    assert codes(outcome) == ["AMBIGUOUS_IDENTITY"]


def test_name_only_target_that_matches_nothing_is_incomplete_n9():
    outcome = run(target={"name": "absent-lib"})
    assert outcome.match.state is S.INCOMPLETE and outcome.result.verdict is WEAK
    assert codes(outcome) == ["VARIANT_COVERAGE_INCOMPLETE"]


def test_unresolved_target_is_match_unknown_and_g18_makes_it_insufficient():
    # OpenVEX gives no subcomponent and the profile gives no target (spec section 1): MATCH Unknown.
    outcome = run(verification=None, target=None, location=None)
    assert outcome.match.state is S.UNKNOWN and outcome.match.reason.value == "MATCH_NO_TARGET_COMPONENT"
    # N11 and N12 (Weak) trigger because the document is only P2, yet the clarified Step 4 gives Insufficient.
    assert codes(outcome) == ["COMPLETENESS_UNDECLARED", "INVENTORY_PROVENANCE_BELOW_P3"]  # N7, N12: Weak ceilings
    assert outcome.result.verdict is INSUFFICIENT
    assert outcome.result.limitations == ("MATCH=Unknown",) and "MATCH=Unknown" in outcome.limitations
    assert not hasattr(outcome, "literal_result")  # one final result only


def test_nt6_like_a_genuinely_dangling_local_reference_is_inv_contradictory_n4():
    outcome = run(cdx("dangling_local.json"), verification=None)
    assert outcome.inv.state is S.CONTRADICTORY and outcome.inv.contradictions == ("R1_ENDPOINT_RESOLUTION",)
    assert outcome.result.verdict is INSUFFICIENT and "INVENTORY_CONTRADICTION" in codes(outcome)
    assert outcome.match.state is S.UNKNOWN  # no Absent without an attested, uncontradicted list


def test_bom_link_endpoints_and_spdx_external_forms_are_not_called_dangling():
    for record in (cdx("bom_link_endpoint.json"), spdx("external_forms.json"), spdx("unregistered_local.json")):
        outcome = run(record, verification=None)
        assert outcome.inv.state is S.UNKNOWN and outcome.inv.contradictions == ()
        assert outcome.reference_check.outcome.value == "not_performed"
        assert outcome.result.verdict is INSUFFICIENT and "NO_INVENTORY" in codes(outcome)


def test_service_endpoints_resolve():
    outcome = run(cdx("service_endpoint.json"), verification=None)
    assert outcome.reference_check.outcome.value == "passed" and outcome.inv.state is S.PRESENT


def test_nt3_like_missing_assertion_means_no_inventory_n2():
    outcome = run(assertion=False)
    assert outcome.inv.state is S.UNKNOWN and "NO_INVENTORY" in codes(outcome)
    assert outcome.result.verdict is INSUFFICIENT and outcome.match.state is S.UNKNOWN


def test_an_unsupported_assertion_statement_is_not_a_full_list():
    outcome = run(assertion_statement="complete_transitively")
    assert outcome.inv.state is S.UNKNOWN and outcome.inv.assertion.value == "unusable"
    assert outcome.result.verdict is INSUFFICIENT


def test_unbound_artifact_is_scope_unbound_n3():
    record = equivalent("cdx")
    data = profile_data(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    data["scope"]["artifact_digests"] = ["sha256:" + "11" * 32]
    data["inv_assertions"][0]["scope"]["artifact_digests"] = ["sha256:" + "11" * 32]
    outcome = evaluate(parse_profile(data), vex_findings(), Stage1Index([record]))
    assert outcome.bind.state is BindState.MISMATCHED and outcome.result.verdict is INSUFFICIENT
    assert "SCOPE_UNBOUND" in codes(outcome) and outcome.inv.state is S.UNKNOWN
    assert outcome.match.state is S.UNKNOWN and outcome.decl.state is S.UNKNOWN
    assert outcome.provenance.document.level is P.P1  # no digest binding, so no P2


def test_product_version_binding_is_p1_never_p2_and_cannot_reach_p3():
    # the subject's purl equals the VEX product id and the versions are equal; no digest is stated
    data = json.loads((FIXTURES / "equivalent" / "app.cdx.json").read_text())
    data["metadata"]["component"]["purl"] = PRODUCT
    del data["metadata"]["component"]["hashes"]
    record = load_cyclonedx(json.dumps(data).encode())
    outcome = run(record, digest=False, verification=verification_for(record.doc_id, FULL))
    assert outcome.bind.state is BindState.MATCHED and outcome.bind.basis.value == "product_version"
    assert outcome.provenance.document.level is P.P1 and outcome.provenance.document.p2.value == "bind_basis_not_digest"
    assert (outcome.provenance.prov_sbom, outcome.provenance.prov_decl) == (P.P1, P.P1)  # P3 is cumulative on P2
    assert outcome.result.verdict is WEAK and {"DECLARATION_BELOW_P3", "INVENTORY_PROVENANCE_BELOW_P3"} <= set(codes(outcome))
    assert outcome.limitations and any(text.startswith("P2_NOT_GRANTED") for text in outcome.limitations)


def test_a_non_matching_product_version_fallback_leaves_bind_unknown_and_everything_downstream_unknown():
    record = equivalent("cdx")  # the subject purl is not the VEX product id
    outcome = run(record, digest=False, verification=verification_for(record.doc_id, FULL))
    assert outcome.bind.state is BindState.UNKNOWN and outcome.result.verdict is INSUFFICIENT
    assert outcome.inv.state is S.UNKNOWN and outcome.match.state is S.UNKNOWN and outcome.decl.state is S.UNKNOWN


def test_container_artifact_without_gen_input_is_n15_weak():
    outcome = run(kind="container")
    assert outcome.cnp_inputs.artifact_kind is ArtifactKind.CONTAINER and outcome.gen.state is GenState.UNKNOWN
    assert outcome.result.verdict is WEAK and codes(outcome) == ["GENERATION_METHOD_UNKNOWN"]
    assert any("GEN_INPUT_UNAVAILABLE" in text for text in outcome.limitations)
    binary = run(kind="binary")
    assert codes(binary) == ["GENERATION_METHOD_UNKNOWN"]
    assert run(kind="other").result.verdict is SUPPORTED  # GEN matters only for binary and container


# ---- DECL end to end -----------------------------------------------------------------------------------------

def test_root_record_does_not_cover_a_top_level_target_unless_every_condition_holds():
    ok = run(location=TOP_LEVEL)
    assert ok.decl.path.value == "document_level_fallback" and ok.decl.covers_s.value == "established"
    assert ok.result.verdict is SUPPORTED
    for kwargs in (dict(assertion=False), dict(assertion_statement="other")):
        outcome = run(location=TOP_LEVEL, **kwargs)
        assert outcome.decl.state is S.UNKNOWN


def test_decl_without_location_or_with_unspecified_placement_is_unknown_n7():
    for kwargs in (dict(location=None), ):
        outcome = run(verification=None, **kwargs)
        assert outcome.decl.state is S.UNKNOWN and "COMPLETENESS_UNDECLARED" in codes(outcome)
    legacy = profile_data(equivalent("cdx").doc_id, target=ABSENT, schema="1")
    legacy["target"]["would_be_location"] = {"document": equivalent("cdx").doc_id, "parent_ref": "app-1"}
    outcome = evaluate(parse_profile(legacy), vex_findings(), Stage1Index([equivalent("cdx")]))
    assert outcome.decl.reason.value == "DECL_PLACEMENT_UNSPECIFIED" and outcome.decl.state is S.UNKNOWN


def test_root_record_covers_a_target_beneath_the_root_only_through_the_fallback_conditions():
    record = cdx("subject_nested.json")  # the root record is complete; sub-a is a root child with its own children
    location = {"placement": "nested_under_component", "parent_ref": "sub-a"}
    covered = run(record, location=location, verification=None)
    assert covered.decl.path.value == "document_level_fallback" and covered.decl.state is S.PRESENT
    assert covered.decl.covers_s.value == "established"
    unattested = run(record, location=location, verification=None, assertion=False)
    assert unattested.decl.state is S.UNKNOWN and unattested.decl.covers_s.value == "not_established"
    assert any("full_component_list" in text for text in unattested.decl.unmet_covers_s)


def test_a_more_specific_record_takes_precedence_over_a_complete_root_record():
    data = json.loads((FIXTURES / "cyclonedx" / "subject_nested.json").read_text())
    data["compositions"].append({"aggregate": "incomplete", "assemblies": ["sub-a"]})
    from evidence.stage1_records import load_cyclonedx
    record = load_cyclonedx(json.dumps(data).encode())
    outcome = run(record, location={"placement": "nested_under_component", "parent_ref": "sub-a"}, verification=None)
    assert outcome.decl.path.value == "component_specific" and outcome.decl.state is S.INCOMPLETE
    assert outcome.decl.record_locators == ("#/compositions/1",)
    assert "DECLARED_INCOMPLETE" in codes(outcome) and outcome.result.verdict is WEAK


def test_spdx_has_no_completeness_declaration_so_decl_is_unknown():
    outcome = run(equivalent("spdx"), verification=None)
    assert outcome.decl.reason.value == "DECL_NO_COMPLETENESS_DECLARATION_FORMAT" and outcome.decl.state is S.UNKNOWN
    assert "COMPLETENESS_UNDECLARED" in codes(outcome) and outcome.result.verdict is WEAK


# ---- subject-nested components ----------------------------------------------------------------------------------

def test_components_nested_beneath_the_cyclonedx_subject_are_searched():
    record = cdx("subject_nested.json")
    present = run(record, target={"name": "bundled-a1", "version": "0.1", "purl": "pkg:npm/bundled-a1@0.1"},
                  verification=None)
    assert present.match.state is S.PRESENT
    assert present.match.matches[0].locator == "#/metadata/component/components/0/components/0"
    assert present.match.matches[0].origin == "subject_nested"
    assert "CLAIM_CONTRADICTED_BY_INVENTORY" in codes(present) and present.result.verdict is INSUFFICIENT
    absent = run(record, target=ABSENT, verification=None)
    assert absent.match.state is S.ABSENT and absent.match.searched_members == 6


def test_a_record_whose_subject_components_were_not_extracted_never_yields_absent():
    record = cdx("subject_nested.json")
    stripped = copy.deepcopy(record.document)
    del stripped.declared_metadata["subject_component_index"]
    from evidence.stage1_records import from_parsed_sbom
    partial = from_parsed_sbom(stripped, list(record.components))
    assert partial.subject_components_extracted is False
    outcome = run(partial, verification=None)
    assert outcome.match.state is S.UNKNOWN and outcome.match.reason.value == "MATCH_DOMAIN_NOT_EXTRACTED"
    assert outcome.inv.state is S.UNKNOWN  # not interpretable either


# ---- refusals ----------------------------------------------------------------------------------------------------------

def test_refusals_have_stable_codes_and_no_verdict():
    record = equivalent("cdx")
    good_profile = make_profile(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    index = Stage1Index([record])

    no_match = evaluate(good_profile, [], index)
    assert isinstance(no_match, EvaluationRefusal) and no_match.code is R.PROFILE_INVALID
    assert no_match.cause == "PROFILE_FINDING_NOT_FOUND" and not hasattr(no_match, "result")

    missing = evaluate(good_profile, vex_findings(), Stage1Index())
    assert missing.code is R.ASSEMBLY_FAILED and missing.cause == "ASSEMBLY_RECORD_NOT_SUPPLIED"

    near = evaluate(make_profile(record.doc_id.upper(), target=ABSENT), vex_findings(), index)
    assert near.code is R.ASSEMBLY_FAILED

    under_investigation = parse_profile({
        **profile_data(record.doc_id, product="example-product-3c", selector=False),
        "finding_selector": {"vulnerability": "https://example.com/vuln/only-an-id", "product_id": "example-product-3c"}})
    refusal = evaluate(under_investigation, load_openvex(FIXTURES / "openvex" / "mixed_statements.json").findings, index)
    assert refusal.code is R.DISPOSITION_NOT_EVALUATED

    reach = evaluate(make_profile(record.doc_id, product="example-product-1", selector=False),
                     load_openvex(FIXTURES / "openvex" / "not_in_execute_path.json").findings, index)
    assert reach.code is R.JUSTIFICATION_NOT_SUPPORTED

    bad_kind = replace(good_profile, scope=replace(good_profile.scope, artifact_kind=ArtifactKind.UNKNOWN))
    assert evaluate(bad_kind, vex_findings(), index).code is R.ARTIFACT_KIND_UNRESOLVED

    assert evaluate(good_profile, vex_findings(), index, verification={"anchors": []}).code is R.VERIFICATION_INVALID
    assert evaluate("not a profile", vex_findings(), index).code is R.PROFILE_INVALID

    ambiguous = parse_profile(profile_data(record.doc_id, selector=False))
    two = vex_findings("component_not_present.json") * 2
    assert evaluate(ambiguous, two, index).cause == "PROFILE_FINDING_SELECTOR_REQUIRED"


def test_profile_errors_for_target_conflicts_and_scope_conflicts_are_refusals():
    record = equivalent("cdx")
    findings = list(load_openvex(FIXTURES / "openvex" / "subcomponents.json").findings)
    profile = parse_profile(profile_data(record.doc_id, product="pkg:oci/example-app@sha256%3Adef", target=ABSENT)
                            | {"finding_selector": {"vulnerability": "CVE-2026-0100",
                                                    "product_id": "pkg:oci/example-app@sha256%3Adef"}})
    refusal = evaluate(profile, findings, Stage1Index([record]))
    assert refusal.code is R.PROFILE_INVALID and refusal.cause == "PROFILE_FINDING_AMBIGUOUS"


def test_a_failing_item_integrity_check_is_a_refusal(monkeypatch):
    def broken(*args, **kwargs):
        raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DOCUMENT", "x", "forced")
    monkeypatch.setattr(ev, "validate_items", broken)
    refusal = run()
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is R.ITEM_INTEGRITY_FAILED
    assert refusal.cause == "ITEM_LOCATOR_NOT_IN_DOCUMENT"


# ---- traceability --------------------------------------------------------------------------------------------------------

SCENARIOS = [
    dict(), dict(verification=None), dict(location=TOP_LEVEL),
    dict(target={"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"}),
    dict(target={"name": "lib-a", "version": "1.0"}), dict(target=None, location=None),
    dict(record="spdx"), dict(record="dangling"), dict(record="nested"), dict(kind="container"),
]


def scenario(options):
    options = dict(options)
    selected = options.pop("record", "cdx")
    record = {"cdx": equivalent("cdx"), "spdx": equivalent("spdx"), "dangling": cdx("dangling_local.json"),
              "nested": cdx("subject_nested.json")}[selected]
    return record, run(record, **options)


@pytest.mark.parametrize("options", SCENARIOS)
def test_every_item_is_traceable_to_a_registered_document_role_locator_and_parent(options):
    record, outcome = scenario(options)
    members = inventory_members(record)
    validate_items(outcome.finding, record, members, outcome.items)  # raises on any violation
    registry = outcome.finding.source_documents
    ids = {item.item_id for item in outcome.items}
    assert len(ids) == len(outcome.items)
    for item in outcome.items:
        assert item.source_doc == outcome.doc_id and item.source_doc in registry
        assert outcome.finding.document_roles[item.source_doc] is DocumentRole.PRIMARY_SBOM
        assert set(item.derived_from) <= ids
        assert item.item_id in outcome.provenance.item_levels
    dimensions = {item.dimension for item in outcome.items}
    assert {"INV", "DECL", "MATCH", "GEN"} <= dimensions
    # PROV_SBOM is the minimum provenance of the inventory items' list-level locators
    inv_levels = [outcome.provenance.item_levels[i.item_id] for i in outcome.items if i.dimension == "INV" and i.locator]
    if inv_levels:
        assert outcome.provenance.prov_sbom == min(inv_levels)
    assert outcome.bind.document_id == outcome.inv.document_id == outcome.match.doc_id == outcome.decl.doc_id == outcome.doc_id


# ---- determinism, purity, report ----------------------------------------------------------------------------------------------

def test_outcome_is_deterministic_and_independent_of_input_order():
    record, other = equivalent("cdx"), equivalent("spdx")
    findings = vex_findings()
    profile = make_profile(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    verification = verification_for(record.doc_id, FULL)
    first = evaluate(profile, findings, Stage1Index([record, other]), verification)
    second = evaluate(profile, findings[::-1], Stage1Index([other, record]), verification)
    assert repr(first) == repr(second)
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(second.to_dict(), sort_keys=True)
    assert evaluate(profile, findings, Stage1Index([record, other]), verification) == first


def test_evaluation_mutates_none_of_its_inputs():
    record = equivalent("cdx")
    findings = vex_findings()
    profile = make_profile(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    verification = verification_for(record.doc_id, FULL)
    index = Stage1Index([record])
    snapshot = copy.deepcopy((findings, record, profile, verification, index.doc_ids()))
    outcome = evaluate(profile, findings, index, verification)
    assert (findings, record, profile, verification, index.doc_ids()) == snapshot
    assert record.document.integrity.signature_verified is None and record.document.integrity.artifact_digest_binding is None
    # what was consumed is recorded on the evaluation's own copy only
    consumed = outcome.finding.source_documents[outcome.doc_id].integrity
    assert consumed.signature_verified is True and consumed.trust_anchor_id == "anchor-1"
    assert consumed.artifact_digest_binding == "sha256:" + X
    assert consumed is not record.document.integrity


def test_structured_report_is_complete_json():
    outcome = run(verification=None)
    report = outcome.to_dict()
    text = json.dumps(report, sort_keys=True)
    assert json.loads(text) == json.loads(json.dumps(report, sort_keys=True))
    assert {"bind", "inv", "decl", "match", "gen", "items", "provenance", "cnp_inputs", "evaluation", "limitations",
            "diagnostics", "observations", "reference_check"} <= set(report)
    assert report["evaluation"]["result"]["verdict"] == "Weak"
    assert report["evaluation"]["triggered"][0]["rule_id"] == "N11"
    assert EvaluationRefusal(R.ASSEMBLY_FAILED, "x", "y").to_dict() == {
        "refused": True, "code": "EVAL_ASSEMBLY_FAILED", "cause": "y", "detail": "x"}


# ---- metamorphic properties --------------------------------------------------------------------------------------------------------

def test_degrading_evidence_never_raises_the_verdict():
    record = equivalent("cdx")
    steps = [
        dict(),                                                  # supported
        dict(verification=None),                                 # P3 -> P2
        dict(verification=None, kind="container"),               # + GEN consequence
        dict(verification=None, kind="container", assertion=False),   # + no attested list
        dict(verification=None, kind="container", assertion=False, target={"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}),
    ]
    ranks = [RANK[run(record, **step).result.verdict] for step in steps]
    assert ranks == sorted(ranks, reverse=True) and ranks[0] == 2 and ranks[-1] == 0
    for single in (dict(verification=None), dict(assertion=False), dict(kind="container"), dict(location=None),
                   dict(target={"name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"}),
                   dict(verification=verification_for(record.doc_id, FULL, verified=False))):
        assert RANK[run(record, **single).result.verdict] <= RANK[run(record).result.verdict], single


def test_irrelevant_additions_do_not_change_the_conclusions():
    record = equivalent("cdx")
    base = run(record, verification=None)
    data = json.loads((FIXTURES / "equivalent" / "app.cdx.json").read_text())
    data["components"].append({"type": "library", "bom-ref": "lib-z", "name": "lib-z", "version": "9", "purl": "pkg:npm/lib-z@9"})
    from evidence.stage1_records import load_cyclonedx
    extended = load_cyclonedx(json.dumps(data).encode())
    grown = run(extended, verification=None)
    assert grown.dimension_states == base.dimension_states
    assert grown.result.verdict is base.result.verdict and grown.result.codes == base.result.codes
    assert grown.match.searched_members == base.match.searched_members + 1
    # an unrelated indexed record and unrelated verification results change nothing either
    other = equivalent("spdx")
    with_extra = run(record, verification=None, extra_records=(other,))
    assert with_extra.result == base.result and with_extra.dimension_states == base.dimension_states


def test_changing_only_free_text_never_changes_the_verdict():
    record = equivalent("cdx")
    findings = vex_findings()
    base = run(record, findings=findings, verification=None)
    changed = copy.deepcopy(findings)
    changed[0].justification.statement = "something entirely different"
    changed[0].justification.asserted_by = "someone else"
    assert run(record, findings=changed, verification=None).result == base.result


def test_equivalent_cyclonedx_and_spdx_inventories_agree_where_both_formats_support_the_evidence():
    cyclone, spdx_record = equivalent("cdx"), equivalent("spdx")
    targets = [
        ABSENT,
        {"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"},
        {"name": "lib-c", "version": "3.0", "purl": "pkg:npm/lib-c@3.0"},        # nested in CycloneDX, flat in SPDX
        {"name": "lib-b", "version": "2.0"},
        {"name": "absent-lib"},
    ]
    for target in targets:
        a, b = run(cyclone, verification=None, target=target), run(spdx_record, verification=None, target=target)
        assert (a.bind.state, a.bind.basis) == (b.bind.state, b.bind.basis), target
        assert a.inv.state is b.inv.state is S.PRESENT, target
        assert a.match.state is b.match.state, target
        assert (a.provenance.document.level, a.provenance.prov_sbom) == (b.provenance.document.level, b.provenance.prov_sbom)
        assert a.decl.state is not b.decl.state or a.decl.state is S.UNKNOWN  # DECL differs: SPDX has no declaration
    # the described subject is a package in SPDX (a member) but not a member in CycloneDX
    subject = {"name": "example-app", "version": "2.0.0", "purl": "pkg:generic/example-app@2.0.0"}
    assert run(cyclone, verification=None, target=subject).match.state is S.ABSENT
    assert run(spdx_record, verification=None, target=subject).match.state is S.PRESENT


def test_items_that_do_not_aggregate_to_their_derivations_state_are_refused(monkeypatch):
    from evidence import cnp_adapter
    real = ev.aggregate_dimensions

    def tampered(items):
        aggregates = real(items)
        return cnp_adapter.DimensionAggregates(inv=aggregates.inv, match=replace(aggregates.match, state=S.PRESENT), decl=aggregates.decl)

    monkeypatch.setattr(ev, "aggregate_dimensions", tampered)
    refusal = run()
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is R.ITEM_INTEGRITY_FAILED
    assert refusal.cause == "ITEM_AGGREGATE_MISMATCH" and not hasattr(refusal, "result")


def test_reported_limitations_correspond_to_the_evaluated_dimensions():
    outcome = run(assertion=False)  # no INV assertion
    assert "INV_DERIVATION_ASSERTION_MISSING" in outcome.limitations
    assert not any(l.startswith("INV_INV_") for l in outcome.limitations)
    assert "MATCH=Unknown" in outcome.limitations and outcome.result.limitations == ("MATCH=Unknown",)
    clean = run()
    assert not any(l.startswith(("INV_", "STRUCTURAL_CHECK_")) for l in clean.limitations)
    assert clean.result.limitations == ()


def test_duplicate_reference_notes_surface_as_diagnostics_not_as_a_state():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "example-app", "bom-ref": "app-1", "version": "2.0.0",
                                       "hashes": [{"alg": "SHA-256", "content": X}]}},
            "components": [{"type": "library", "name": "a", "bom-ref": "dup"}, {"type": "library", "name": "b", "bom-ref": "dup"}],
            "compositions": [{"aggregate": "complete", "assemblies": ["app-1"]}]}
    record = load_cyclonedx(json.dumps(data).encode())
    outcome = run(record)
    assert any(d.startswith("INVENTORY_NOTE: C3 (deferred)") for d in outcome.diagnostics)
    assert outcome.dimension_states["INV"] == "Present"  # duplicates are never turned into Contradictory here


# ---- P-3 end to end: no single step toward weaker evidence raises the verdict -----------------------------------------------------

def _p3_axes(record):
    doc = record.doc_id
    return {
        # each axis lists its options from best to worst
        "verification": [verification_for(doc, FULL), verification_for(doc, ("#/components", "#/packages")), None,
                         verification_for(doc, FULL, verified=False), verification_for(doc, FULL, anchor="rogue", anchors=("anchor-1",))],
        "digest": [True, False],
        "assertion": [True, False],
        "location": [ROOT_NESTED, TOP_LEVEL, None],
        "kind": ["source", "container"],
        "target": [ABSENT, {"name": "absent-lib"}, {"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}],
    }


@pytest.mark.parametrize("kind", ["cdx", "spdx"])
def test_p3_no_single_degradation_of_any_evidence_axis_raises_the_verdict(kind):
    record = equivalent(kind)
    axes = _p3_axes(record)
    names = list(axes)

    def verdict(choice):
        options = dict(choice)
        verification = options.pop("verification")
        outcome = run(record, verification=verification, **options)
        assert isinstance(outcome, EvaluationOutcome)
        return RANK[outcome.result.verdict]

    checked = 0
    for indexes in itertools.product(*(range(len(axes[n])) for n in names)):
        choice = {n: axes[n][i] for n, i in zip(names, indexes)}
        best = verdict(choice)
        for n, i in zip(names, indexes):
            if i + 1 < len(axes[n]):
                worse = dict(choice, **{n: axes[n][i + 1]})
                assert verdict(worse) <= best, (kind, n, i, indexes)
                checked += 1
    assert checked > 1000


def test_the_evaluators_attestation_is_visible_in_the_outcome_when_it_was_relied_on():
    relied = run()
    assert any(d.startswith("INV_ASSERTION_RELIED_ON: full_component_list") and "'tester'" in d for d in relied.diagnostics)
    assert not any(d.startswith("INV_ASSERTION_RELIED_ON") for d in run(assertion=False).diagnostics)


@pytest.mark.parametrize("index,findings,cause", [
    (None, None, "EVAL_INDEX_INVALID"),
    ({"a": 1}, None, "EVAL_INDEX_INVALID"),
    ("ok", "not findings", "EVAL_INDEX_INVALID"),
])
def test_malformed_index_or_findings_are_refused_without_a_verdict_or_a_crash(index, findings, cause):
    record = equivalent("cdx")
    profile = make_profile(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    refusal = evaluate(profile, vex_findings() if findings is None else findings,
                       Stage1Index([record]) if index == "ok" else index)
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is R.ASSEMBLY_FAILED
    if index == "ok":
        assert refusal.cause == "EVAL_FINDINGS_INVALID"
    else:
        assert refusal.cause == cause
    assert not hasattr(refusal, "result") and not hasattr(refusal, "items")


def test_findings_that_are_not_findings_are_refused():
    record = equivalent("cdx")
    profile = make_profile(record.doc_id, target=ABSENT, location=ROOT_NESTED)
    assert evaluate(profile, [object()], Stage1Index([record])).cause == "EVAL_FINDINGS_INVALID"


# ---- P-2 end to end: missing evidence is never Absent ----------------------------------------------------------------------------

def _empty_cdx():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "example-app", "bom-ref": "app-1", "version": "2.0.0",
                                       "hashes": [{"alg": "SHA-256", "content": X}]}},
            "compositions": [{"aggregate": "complete", "assemblies": ["app-1"]}]}
    return load_cyclonedx(json.dumps(data).encode())


P2_CASES = {
    "no evaluator attestation": lambda: run(assertion=False),
    "unusable attestation statement": lambda: run(assertion_statement="direct_dependencies_only"),
    "artifact not bound": lambda: run(digest=False, version="9.9"),
    "BOM-Link endpoint in the graph": lambda: run(cdx("bom_link_endpoint.json")),
    "unverified SPDX endpoint forms": lambda: run(spdx("external_forms.json")),
    "dangling reference (contradiction, not absence)": lambda: run(cdx("dangling_local.json")),
    "no inventory members at all": lambda: run(_empty_cdx()),
    "no target component": lambda: run(target=None, location=None),
    "target without a strong identifier": lambda: run(target={"name": "absent-lib"}),
    "subject-nested members not extracted": lambda: run(_without_subject_index()),
}


def _without_subject_index():
    from dataclasses import replace as _replace
    return _replace(cdx("subject_nested.json"), subject_components=(), subject_components_extracted=False)


@pytest.mark.parametrize("case", sorted(P2_CASES))
def test_p2_missing_or_unusable_evidence_never_becomes_absent_and_never_supports_the_claim(case):
    outcome = P2_CASES[case]()
    assert isinstance(outcome, EvaluationOutcome), case
    assert outcome.cnp_inputs.match is not S.ABSENT, case
    assert outcome.result.verdict is not SUPPORTED, case
    assert all(item.state is not S.ABSENT for item in outcome.items), case


def test_p2_the_only_route_to_absent_needs_every_prerequisite():
    full = run()
    assert full.cnp_inputs.match is S.ABSENT
    # removing any single prerequisite removes Absent
    for label, removed in {
        "attestation": lambda: run(assertion=False),
        "binding": lambda: run(digest=False, version="9.9"),
        "strong target identifier": lambda: run(target={"name": "absent-lib"}),
    }.items():
        assert removed().cnp_inputs.match is not S.ABSENT, label


def _mutated_cdx(mutate):
    data = json.loads((FIXTURES / "equivalent" / "app.cdx.json").read_text())
    mutate(data)
    return load_cyclonedx(json.dumps(data).encode())


DEFECTS = {
    "dangling dependency target": lambda d: d["dependencies"][0]["dependsOn"].append("ghost"),
    "dangling dependency node": lambda d: d["dependencies"].append({"ref": "ghost"}),
    "BOM-Link endpoint": lambda d: d["dependencies"][0]["dependsOn"].append("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#x"),
    "name-only twin of the target": lambda d: d["components"].append({"type": "library", "name": "absent-lib", "version": "9.9"}),
    "exact twin of the target": lambda d: d["components"].append({"type": "library", "name": "twin", "version": "9.9", "purl": "pkg:npm/absent-lib@9.9"}),
    "declaration becomes incomplete": lambda d: d["compositions"][0].update(aggregate="incomplete"),
    "declaration becomes unknown": lambda d: d["compositions"][0].update(aggregate="unknown"),
    "declaration removed": lambda d: d.pop("compositions"),
    "subject digest changed": lambda d: d["metadata"]["component"]["hashes"][0].update(content="ab" * 32),
    "subject digest removed": lambda d: d["metadata"]["component"].pop("hashes"),
    "tool version removed": lambda d: d["metadata"]["tools"]["components"][0].pop("version"),
    "inventory emptied": lambda d: d.update(components=[], dependencies=[]),
}


@pytest.mark.parametrize("defect", sorted(DEFECTS))
@pytest.mark.parametrize("verification", ["p3", None])
def test_p3_a_newly_discovered_defect_never_raises_the_verdict(defect, verification):
    base = run(equivalent("cdx"), verification=verification)
    broken = run(_mutated_cdx(DEFECTS[defect]), verification=verification)
    assert isinstance(base, EvaluationOutcome) and isinstance(broken, EvaluationOutcome)
    assert RANK[broken.result.verdict] <= RANK[base.result.verdict], defect
    if verification == "p3":
        assert base.result.verdict is SUPPORTED and broken.result.verdict is not SUPPORTED, defect


# ---- reference registry versus inventory membership ---------------------------------------------------------------------------------

def test_a_defined_bom_ref_is_not_membership_presence_or_completeness():
    """Formulation components, services and pedigree ancestors are registered (so an edge to
    them resolves) but are not members: a target that matches one of them is not found, which
    never makes MATCH Present, and the registry never establishes completeness."""
    def add(d):
        d["formulation"] = [{"components": [{"type": "library", "name": "tool-lib", "version": "9.9", "bom-ref": "tool-1",
                                             "purl": "pkg:npm/absent-lib@9.9"}]}]
        d["services"] = [{"name": "absent-lib", "bom-ref": "svc-1"}]
        d["components"][0]["pedigree"] = {"ancestors": [{"type": "library", "name": "absent-lib", "version": "9.9",
                                                         "bom-ref": "anc-1", "purl": "pkg:npm/absent-lib@9.9"}]}
        d["dependencies"][0]["dependsOn"] += ["tool-1", "svc-1", "anc-1"]
    record = _mutated_cdx(add)
    outcome = run(record)
    assert outcome.reference_check.outcome.value == "passed"  # all three resolve in the registry
    assert {m.component.name for m in inventory_members(record).members} == {"lib-a", "lib-b", "lib-c"}
    assert outcome.cnp_inputs.match is S.ABSENT and outcome.result.verdict is SUPPORTED  # unchanged by the registry
    # and a registered reference is never read as presence of an arbitrary target
    assert all(item.state is not S.PRESENT for item in outcome.items if item.dimension == "MATCH")


# ---- U-2: detached verification results ---------------------------------------------------------------------------------------

def _detached_limitations(outcome):
    return [l for l in outcome.limitations if l.startswith("P3_FROM_DETACHED_VERIFICATION_RESULT")]


@pytest.mark.parametrize("kind", ["cdx", "spdx"])
def test_u2_a_trusted_exactly_bound_detached_result_establishes_p3_for_the_covered_list(kind):
    record = equivalent(kind)
    list_locator = "#/components" if kind == "cdx" else "#/packages"
    outcome = run(record, verification=verification_for(record.doc_id, (list_locator,)))
    assert outcome.provenance.prov_sbom is P.P3
    assert len(_detached_limitations(outcome)) == 1  # never presented as a signature the SBOM carries
    consumed = outcome.finding.source_documents[outcome.doc_id].integrity
    assert consumed.signature is None  # no signature metadata is invented
    assert consumed.signature_verified is True and consumed.established_coverage == [list_locator]
    assert record.document.integrity.signature_verified is None  # the caller's record is untouched


@pytest.mark.parametrize("kind", ["cdx", "spdx"])
@pytest.mark.parametrize("label,make", [
    ("another document", lambda d, loc: verification_for("cyclonedx:sha256:" + "11" * 32, (loc,))),
    ("case-changed document id", lambda d, loc: verification_for(d.upper(), (loc,))),
    ("untrusted anchor", lambda d, loc: verification_for(d, (loc,), anchor="rogue", anchors=("anchor-1",))),
    ("not verified", lambda d, loc: verification_for(d, (loc,), verified=False)),
    ("coverage not established", lambda d, loc: verification_for(d, None)),
])
def test_u2_an_unbound_untrusted_invalid_or_insufficient_detached_result_never_grants_p3(kind, label, make):
    record = equivalent(kind)
    list_locator = "#/components" if kind == "cdx" else "#/packages"
    outcome = run(record, verification=make(record.doc_id, list_locator))
    assert outcome.provenance.prov_sbom < P.P3, label
    assert outcome.result.verdict is not SUPPORTED, label
    assert _detached_limitations(outcome) == [], label


@pytest.mark.parametrize("kind", ["cdx", "spdx"])
@pytest.mark.parametrize("coverage", [(), ("#/dependencies",), ("#/relationships",)])
def test_u2_a_valid_result_with_insufficient_coverage_grants_no_p3_and_caps_the_uncovered_list(kind, coverage):
    record = equivalent(kind)
    outcome = run(record, verification=verification_for(record.doc_id, coverage))
    assert outcome.provenance.prov_sbom is P.P1  # established coverage that excludes the list: the step 3 cap
    assert outcome.result.verdict is WEAK and "INVENTORY_PROVENANCE_BELOW_P3" in outcome.result.codes
    assert len(_detached_limitations(outcome)) == 1  # the result was used (to cap), and says so


def test_u2_malformed_verification_data_is_rejected_before_any_use():
    from evidence.verification import VerificationError, parse_verification
    good = {"schema_version": "1", "trust_anchors": ["a"],
            "results": [{"doc_id": "d", "verified": True, "trust_anchor_id": "a",
                         "verifier": {"name": "v", "version": "1"}, "established_coverage": ["#/packages"]}]}
    assert parse_verification(good).result_for("d").established_coverage == ("#/packages",)
    for mutate in (lambda d: d["results"][0].update(verified="yes"), lambda d: d["results"][0].update(established_coverage=["packages"]),
                   lambda d: d["results"][0].pop("verifier"), lambda d: d["results"].append(dict(d["results"][0])),
                   lambda d: d.update(schema_version="2")):
        bad = copy.deepcopy(good)
        mutate(bad)
        with pytest.raises(VerificationError):
            parse_verification(bad)
