"""End-to-end tests of the reachability path: real parser fixtures -> evidence.sufficiency -> outcome or refusal.

RT1-RT11 are replayed through the whole pipeline (CycloneDX and SPDX), then the evidence semantics of
section 5.1, the hazard and configuration derivations, binding, provenance, refusals, immutability,
determinism and the interaction with the completed CNP path are checked. All reachability evidence is
SYNTHETIC (fixtures/reachability/README.md).
"""

import copy
import dataclasses
import json

import pytest

from evidence import requirements, sufficiency
from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, RefusalCode
from evidence.reach_derivation import dependency_graph_facts
from evidence.reach_evaluator import ReachOutcome, evaluate_reachability
from evidence.reach_rules import evaluate_reach
from evidence.stage1_records import DeclaredEdge, Stage1Index
from model import Disposition, EvidenceState as S, ProvenanceLevel as P, VulnerableCodeLocus
from reports.verdict import Verdict
from tests.pipeline_support import PRODUCT, equivalent, make_profile, vex_findings
from tests.reach_support import (
    CLASS_NAMES,
    RT_PIPELINE_CASES,
    add_doc,
    baseline_data,
    doc,
    evidence,
    fixture_data,
    replace_k1,
    run,
    verified,
    with_k1,
)

KINDS = ["cdx", "spdx"]
SUPPORTED, WEAK, INSUFFICIENT = Verdict.SUPPORTED, Verdict.WEAK, Verdict.INSUFFICIENT
V_K1 = verified("k1-analysis")
ALL_HAZARDS = tuple(f"HAZARD_{n}" for n in CLASS_NAMES)


def codes_and_rules(outcome):
    return outcome.result.verdict, outcome.result.codes, outcome.evaluation.rule_ids


def strip(data, doc_id, *keys):
    data = copy.deepcopy(data)
    for key in keys:
        doc(data, doc_id).pop(key, None)
    return data


# ---- RT1-RT11 through the whole pipeline (the case table lives in tests/reach_support.py) --------------------------

@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("case", RT_PIPELINE_CASES, ids=[c.case_id for c in RT_PIPELINE_CASES])
def test_rt_cases_end_to_end(kind, case):
    outcome = run(kind, case.data(), verification=case.verification())
    assert isinstance(outcome, ReachOutcome), outcome
    assert outcome.result.verdict is case.verdict
    assert outcome.evaluation.rule_ids == case.rules
    assert outcome.result.codes[:len(case.first_codes)] == case.first_codes
    # the single final verdict is the pure engine's verdict over the derived inputs, and the public predicate agrees
    assert outcome.evaluation == evaluate_reach(outcome.reach_inputs)
    assert requirements.req_vulnerable_code_not_in_execute_path(outcome.reach_inputs) == outcome.result


@pytest.mark.parametrize("kind", KINDS)
def test_rt1_dimension_states(kind):
    outcome = run(kind, verification=V_K1)
    assert outcome.dimension_states == {"BIND": "matched", "CFG": "declared", "ENTRY": "Present", "LOCUS": "Present", "REACH": "Absent"}
    assert outcome.prov_reach is P.P3 and outcome.reach.basis.value == "k1" and outcome.reach.step == 2
    assert all(h.effective.value in ("excluded_by_evidence", "modeled_conservatively") for h in outcome.evaluation.hazards)


# ---- section 5.1 REACH derivation ------------------------------------------------------------------------------------------

def with_extra(data, kind, finding, doc_id, attributed=True):
    data = add_doc(data, doc_id=doc_id, kind=kind, finding=finding, analyzed_configurations=["prod"])
    if not attributed:
        for key in ("tool_name", "tool_version", "created", "producer", "producer_class"):
            doc(data, doc_id).pop(key, None)
    return data


def solo(kind, finding, attributed=True):
    """No K1: a single K2/K3 document (replacing the baseline K1 report)."""
    data = replace_k1(baseline_data(), kind, finding, doc_id="doc-1")
    if not attributed:
        for key in ("tool_name", "tool_version", "created", "producer", "producer_class"):
            doc(data, "doc-1").pop(key, None)
    return data


DERIVATION = [
    # label, data, REACH state, basis, step
    ("k1-negative-with-claim", baseline_data(), S.ABSENT, "k1", 2),
    ("k1-negative-without-claim", with_k1(baseline_data(), full_coverage_claim=False), S.INCOMPLETE, "k1", 2),
    ("k1-incomplete", with_k1(baseline_data(), finding="incomplete"), S.INCOMPLETE, "k1", 2),
    ("k1-ambiguous", with_k1(baseline_data(), finding="ambiguous"), S.AMBIGUOUS, "k1", 2),
    ("k1-unknown", with_k1(baseline_data(), finding="unknown"), S.UNKNOWN, None, 2),
    ("k1-positive", with_k1(baseline_data(), finding="positive"), S.PRESENT, None, 1),
    ("k2-positive-at-p0", solo("K2", "positive", attributed=False), S.PRESENT, None, 1),
    ("k3-positive-at-p0", solo("K3", "positive", attributed=False), S.PRESENT, None, 1),
    ("k1-absent-and-k2-positive-p0", with_extra(baseline_data(), "K2", "positive", "k2-hit", attributed=False), S.CONTRADICTORY, None, 1),
    ("k1-absent-and-k3-hit", with_extra(baseline_data(), "K3", "positive", "k3-hit"), S.CONTRADICTORY, None, 1),
    ("k1-incomplete-and-k2-positive", with_extra(with_k1(baseline_data(), finding="incomplete"), "K2", "positive", "k2-hit"),
     S.PRESENT, None, 1),
    ("k1-absent-and-k3-no-hit-k1-governs", with_extra(baseline_data(), "K3", "negative", "k3-trace"), S.ABSENT, "k1", 2),
    ("k1-absent-and-k2-negative-k1-governs", with_extra(baseline_data(), "K2", "negative", "k2-a"), S.ABSENT, "k1", 2),
    ("two-k1-absent-and-incomplete", with_extra(baseline_data(), "K1", "incomplete", "k1-second"), S.INCOMPLETE, "k1", 2),
    ("two-k1-absent-and-absent", with_extra(add_doc(baseline_data(), doc_id="x", kind="hazard_basis"), "K1", "negative", "k1-second"),
     S.INCOMPLETE, "k1", 2),  # the second K1 declares no full-coverage claim -> Incomplete, never a union of absences
    ("k1-unknown-and-k3-no-hit", with_extra(with_k1(baseline_data(), finding="unknown"), "K3", "negative", "k3-trace"), S.UNKNOWN, None, 2),
    ("k2-negative-at-p1", solo("K2", "negative"), S.INCOMPLETE, "non_exhaustive", 3),
    ("k2-negative-at-p0", solo("K2", "negative", attributed=False), S.UNKNOWN, None, 4),
    ("k3-no-hit-at-p0", solo("K3", "negative", attributed=False), S.INCOMPLETE, "non_exhaustive", 3),
    ("k3-no-hit-at-p3", solo("K3", "negative"), S.INCOMPLETE, "non_exhaustive", 3),
    ("k2-and-k3-negative", with_extra(solo("K3", "negative"), "K2", "negative", "k2-a"), S.INCOMPLETE, "non_exhaustive", 3),
    ("k2-p0-and-k3-no-hit", with_extra(solo("K3", "negative"), "K2", "negative", "k2-a", attributed=False), S.INCOMPLETE, "non_exhaustive", 3),
    ("no-documents", {"schema_version": "1"}, S.UNKNOWN, None, 4),
]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("label, data, state, basis, step", DERIVATION, ids=[d[0] for d in DERIVATION])
def test_reach_derivation_follows_section_5_1_in_order(kind, label, data, state, basis, step):
    outcome = run(kind, data)
    assert isinstance(outcome, ReachOutcome), outcome
    assert outcome.reach.state is state
    assert (outcome.reach.basis.value if outcome.reach.basis else None) == basis
    assert outcome.reach.step == step
    assert (outcome.prov_reach is None) == (state is S.UNKNOWN)


def test_a_k1_absence_without_a_full_coverage_claim_is_never_absent_and_k2_k3_are_never_absent():
    for data in (with_k1(baseline_data(), full_coverage_claim=False), solo("K2", "negative"), solo("K3", "negative")):
        outcome = run("cdx", data, verification=V_K1)
        assert S.ABSENT not in {i.state for i in outcome.items if i.dimension == "REACH"}
        assert outcome.reach.state is not S.ABSENT and outcome.result.verdict is not SUPPORTED


def test_positive_observation_beats_every_ep_and_every_other_item():
    for ep_stripped in (True, False):
        data = with_extra(baseline_data(), "K2", "positive", "k2-hit", attributed=not ep_stripped)
        outcome = run("cdx", data, verification=V_K1)
        assert outcome.reach.state is S.CONTRADICTORY and outcome.result.verdict is INSUFFICIENT
        assert {"R3"} <= set(outcome.evaluation.rule_ids)


def test_prov_reach_is_the_minimum_over_the_documents_the_conclusion_depends_on():
    data = with_extra(solo("K3", "negative"), "K2", "negative", "k2-a")
    both_p3 = run("cdx", data, verification=verified("doc-1", "k2-a"))
    one_p3 = run("cdx", data, verification=verified("doc-1"))
    assert both_p3.prov_reach is P.P3 and one_p3.prov_reach is P.P2
    assert "ANALYSIS_PROVENANCE_BELOW_P3" in one_p3.result.codes and "ANALYSIS_PROVENANCE_BELOW_P3" not in both_p3.result.codes


def test_prov_reach_ignores_documents_the_conclusion_does_not_depend_on():
    # K3 no-hit is ignored once K1 exists (it contributes only through step 1): its low EP must not lower PROV_REACH
    data = with_extra(baseline_data(), "K3", "negative", "k3-trace", attributed=False)
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.reach.state is S.ABSENT and outcome.prov_reach is P.P3 and outcome.result.verdict is SUPPORTED


# ---- K4: the dependency graph never becomes reachability -----------------------------------------------------------------------

@pytest.mark.parametrize("kind", KINDS)
def test_the_sbom_dependency_graph_is_k4_and_gives_unknown_reachability(kind):
    outcome = run(kind, {"schema_version": "1"})
    assert outcome.graph.present and outcome.graph.edge_count >= 3
    assert outcome.reach.state is S.UNKNOWN and outcome.reach.only_k4 and outcome.prov_reach is None
    assert outcome.result.codes[0] == "MISSING_EDGE_IS_UNKNOWN" and outcome.result.verdict is INSUFFICIENT
    k4 = [i for i in outcome.items if i.dimension == "REACH"]
    assert [i.state for i in k4] == [S.UNKNOWN] and k4[0].value_or_ref.kind == "K4"
    assert k4[0].source_doc == outcome.doc_id and k4[0].locator == "#"
    assert any("not a call edge" in lim or "A5" in lim for lim in k4[0].value_or_ref.limitations)


def test_without_any_edge_the_code_is_no_analysis_not_missing_edge():
    for kind in KINDS:
        record = dataclasses.replace(equivalent(kind), edges=(), nodes=())
        outcome = run(kind, {"schema_version": "1"}, record=record)
        assert not outcome.graph.present and outcome.result.codes[0] == "NO_ANALYSIS"


def edges(*triples, relationship="dependsOn", fmt="cdx"):
    edge_type = "declared_dependency" if fmt == "cdx" else "declared_relationship"
    return tuple(DeclaredEdge(edge_type, relationship, s, t, f"#/e/{n}") for n, (s, t) in enumerate(triples))


TOPOLOGIES = {
    "cycle": [("a", "b"), ("b", "a")],
    "self_loop": [("a", "a")],
    "repeated_edge": [("a", "b"), ("a", "b"), ("a", "b")],
    "multiple_paths": [("app", "x"), ("app", "y"), ("x", "lib-b"), ("y", "lib-b")],
    "unresolved_endpoints": [("nowhere", "ghost")],
    "disconnected": [("p", "q"), ("r", "s")],
    "reversed_direction": [("lib-b", "app-1")],
    "direct_path_to_target": [("app-1", "lib-b")],
}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", sorted(TOPOLOGIES))
def test_graph_topology_cannot_change_any_reach_state_or_verdict(kind, name):
    """A5: the shape of the dependency graph (direction, cycles, repeated edges, multiple paths, unresolved or
    disconnected endpoints, a direct path to the target) is irrelevant to REACH. It only decides whether K4 exists."""
    relationship = "dependsOn" if kind == "cdx" else "DEPENDS_ON"
    record = dataclasses.replace(equivalent(kind), edges=edges(*TOPOLOGIES[name], relationship=relationship, fmt=kind))
    no_analysis = run(kind, {"schema_version": "1"}, record=record)
    assert no_analysis.reach.state is S.UNKNOWN and no_analysis.result.codes[0] == "MISSING_EDGE_IS_UNKNOWN"
    with_analysis = run(kind, baseline_data(), record=record, verification=V_K1)
    plain = run(kind, baseline_data(), record=dataclasses.replace(record, edges=()), verification=V_K1)
    assert with_analysis.result == plain.result and with_analysis.reach.state is S.ABSENT


def test_a_direct_dependency_edge_to_the_target_is_not_a_positive_observation():
    """Register G15: counting an edge as positive would give R1 (Present); the specification keeps it Unknown (R2)."""
    record = dataclasses.replace(equivalent("cdx"), edges=edges(("app-1", "lib-b")))
    outcome = run("cdx", {"schema_version": "1"}, record=record)
    assert outcome.reach.state is S.UNKNOWN and "R1" not in outcome.evaluation.rule_ids and "R2" in outcome.evaluation.rule_ids


@pytest.mark.parametrize("fmt, relationship, expected", [
    ("cdx", "dependsOn", True), ("cdx", "provides", False),
    ("spdx", "DEPENDS_ON", True), ("spdx", "DEPENDENCY_OF", True), ("spdx", "TEST_DEPENDENCY_OF", True),
    ("spdx", "DESCRIBES", False), ("spdx", "CONTAINS", False), ("spdx", "GENERATES", False), ("spdx", "dependsOn", False),
])
def test_only_dependency_relationships_count_as_k4_and_the_two_formats_are_not_conflated(fmt, relationship, expected):
    record = dataclasses.replace(equivalent(fmt), edges=edges(("a", "b"), relationship=relationship, fmt=fmt), nodes=())
    assert dependency_graph_facts(record).present is expected


def test_the_cdx_provides_relation_is_not_a_dependency_even_next_to_depends_on_nodes():
    record = dataclasses.replace(equivalent("cdx"), edges=edges(("svc", "x"), relationship="provides"))
    assert dependency_graph_facts(record) == dependency_graph_facts(dataclasses.replace(record, edges=()))


# ---- LOCUS and ENTRY ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("approximation, state, rule", [
    ("over_approximation", S.PRESENT, None), ("possibly_under_approximate", S.INCOMPLETE, "R9"), (None, S.UNKNOWN, "R4"),
])
def test_locus_state_follows_the_declared_approximation(approximation, state, rule):
    data = baseline_data()
    if approximation is None:
        data["locus"].pop("approximation")
    else:
        data["locus"]["approximation"] = approximation
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.locus.state is state
    assert (rule in outcome.evaluation.rule_ids) == (rule is not None)


def test_no_locus_input_is_unknown_and_a_vex_locus_alone_does_not_establish_an_over_approximation():
    data = baseline_data()
    data.pop("locus")
    findings = vex_findings("reachability_equivalent.json")
    findings[0].vulnerability.locus = VulnerableCodeLocus(symbols=["org.example.LibB.parse"], granularity="function")
    outcome = run("cdx", data, verification=V_K1, findings=findings)
    assert outcome.locus.state is S.UNKNOWN and "R4" in outcome.evaluation.rule_ids


def test_locus_is_evaluator_entered_so_it_has_no_document_and_is_p0():
    outcome = run("cdx", verification=V_K1)
    locus_items = [i for i in outcome.items if i.dimension == "LOCUS"]
    assert [(i.source_doc, i.locator) for i in locus_items] == [(None, None)]
    assert any("unauthenticated" in lim for lim in locus_items[0].value_or_ref.limitations)


@pytest.mark.parametrize("entry, rules", [
    ({"complete": True}, set()), ({"complete": False}, {"R10"}), (None, {"R5"}),
])
def test_entry_state_follows_the_declared_entry_point_set(entry, rules):
    data = baseline_data()
    if entry is None:
        doc(data, "k1-analysis").pop("entry_points")
    else:
        doc(data, "k1-analysis")["entry_points"] = entry
    outcome = run("cdx", data, verification=V_K1)
    assert set(outcome.evaluation.rule_ids) == rules


def test_entry_aggregates_under_section_2_a_complete_set_survives_an_incomplete_one():
    data = baseline_data()
    data["entry_points"] = {"complete": False, "entered_by": "synthetic-evaluator"}  # AG1: Present + Incomplete = Present
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.entry.state is S.PRESENT
    data = with_k1(baseline_data(), entry_points={"complete": False})
    data["entry_points"] = {"complete": False, "entered_by": "synthetic-evaluator"}
    assert run("cdx", data, verification=V_K1).entry.state is S.INCOMPLETE  # AG5: never complete by union


# ---- hazards -------------------------------------------------------------------------------------------------------------------------------

def test_every_class_defaults_to_unknown_and_the_modeled_list_of_a_k1_report_is_honoured():
    data = baseline_data()
    data["hazards"] = []
    doc(data, "k1-analysis")["modeled_hazards"] = []
    outcome = run("cdx", data, verification=V_K1)
    assert set(ALL_HAZARDS) == set(outcome.result.codes) - {"ANALYSIS_PROVENANCE_BELOW_P3"} | set()
    assert {h.origin for h in outcome.hazards} == {"default"}
    full = run("cdx", verification=V_K1)
    assert {h.hazard_class.value: h.origin for h in full.hazards}["REFLECTION"] == "evaluator_claim"
    assert {h.origin for h in full.hazards if h.hazard_class.value != "REFLECTION"} == {"k1_report"}


@pytest.mark.parametrize("label, change, downgraded", [
    ("basis_document_unknown", lambda d: d["hazards"][0].update(basis_ref="nowhere"), True),
    ("basis_without_ref_cannot_stand", lambda d: d["hazards"][0].pop("basis_ref"), True),
    ("basis_unattributed", lambda d: doc(d, "reflection-basis").pop("tool_name"), True),
    ("basis_artifact_digest_differs", lambda d: doc(d, "reflection-basis")["artifact"].update(hashes=["sha256:" + "ab" * 32]), True),
    ("basis_without_artifact", lambda d: doc(d, "reflection-basis").pop("artifact"), True),
    ("basis_other_component", lambda d: doc(d, "reflection-basis").update(target={"purl": "pkg:npm/other@1"}), True),
    ("basis_without_target", lambda d: doc(d, "reflection-basis").pop("target"), True),
    ("basis_ok_at_p1_via_product_version", lambda d: doc(d, "reflection-basis")["artifact"].pop("hashes"), False),
    ("basis_ok_at_p2", lambda d: None, False),
])
def test_exclusion_basis_must_exist_be_bound_and_reach_p1(label, change, downgraded):
    data = baseline_data()
    change(data)
    outcome = run("cdx", data, verification=V_K1)
    reflection = next(h for h in outcome.evaluation.hazards if h.hazard_class.value == "REFLECTION")
    assert reflection.provenance_downgrade is downgraded
    assert ("HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION" in outcome.result.codes) is downgraded
    assert (outcome.result.verdict is SUPPORTED) is (not downgraded)


def test_an_explicit_evaluator_claim_governs_its_class_even_when_the_k1_report_models_it():
    data = baseline_data()
    data["hazards"].append({"class": "NATIVE_FFI", "disposition": "unmodeled"})
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.result.codes == ("HAZARD_NATIVE_FFI",) and outcome.result.verdict is WEAK


def test_a_modeled_claim_with_no_k1_declaration_is_unknown():
    data = baseline_data()
    data["hazards"].append({"class": "NATIVE_FFI", "disposition": "modeled_conservatively"})
    doc(data, "k1-analysis")["modeled_hazards"] = [c for c in doc(data, "k1-analysis")["modeled_hazards"] if c != "NATIVE_FFI"]
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.result.codes == ("HAZARD_NATIVE_FFI",)


def test_modeled_hazards_can_only_be_declared_inside_a_k1_report():
    data = baseline_data()
    data["documents"].append(dict(doc_id="k3-trace", kind="K3", finding="negative", modeled_hazards=["NATIVE_FFI"]))
    with pytest.raises(Exception):
        evidence(data)


def test_a_hazard_exclusion_is_reported_as_an_unauthenticated_evaluator_statement():
    outcome = run("cdx", verification=V_K1)
    assert any(d.startswith("HAZARD_CLAIM_EVALUATOR_ENTERED: REFLECTION") for d in outcome.diagnostics)


# ---- CFG ----------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("label, change, cfg, rules", [
    ("covered", lambda d: None, "declared", set()),
    ("s_declares_no_configuration", lambda d: d.pop("configuration"), "undeclared", {"R12"}),
    ("analysis_declares_no_configuration", lambda d: doc(d, "k1-analysis").pop("analyzed_configurations"), "undeclared", {"R12"}),
    ("claim_extends_beyond", lambda d: d.update(configuration={"deployment_config_id": "staging"}), "extends_beyond", {"R12"}),
    ("several_analysed_configs_one_matches", lambda d: doc(d, "k1-analysis").update(analyzed_configurations=["dev", "prod"]), "declared", set()),
])
def test_cfg_is_declared_in_s_and_covered_by_the_analysis(label, change, cfg, rules):
    data = baseline_data()
    change(data)
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.cfg.state.value == cfg and set(outcome.evaluation.rule_ids) == rules


def test_cfg_needs_every_analysis_the_conclusion_depends_on_to_cover_s():
    data = with_extra(with_k1(baseline_data(), finding="incomplete"), "K1", "incomplete", "k1-second")
    doc(data, "k1-second")["analyzed_configurations"] = ["staging"]
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.cfg.state.value == "extends_beyond" and "R12" in outcome.evaluation.rule_ids


def test_cfg_is_not_compared_when_there_is_no_analysis_and_that_caps_the_verdict():
    data = {"schema_version": "1", "configuration": {"deployment_config_id": "prod"}}
    outcome = run("cdx", data)
    assert outcome.cfg.state.value == "not_compared" and "CFG=not_compared" in outcome.result.limitations


def test_a_deployment_configuration_that_conflicts_with_s_is_a_refusal():
    findings = vex_findings("reachability_equivalent.json")
    findings[0].scope.deployment_config_id = "staging"
    refusal = run("cdx", verification=V_K1, findings=findings)
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.REACH_INPUT_INVALID
    assert refusal.cause == "REACH_CONFIGURATION_CONFLICT"
    findings[0].scope.deployment_config_id = "prod"  # the same value is not a conflict
    assert isinstance(run("cdx", verification=V_K1, findings=findings), ReachOutcome)


# ---- BIND (artifact + component version; register G1r) -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("label, change, state, reason", [
    ("matched_by_digest", lambda d: None, "matched", None),
    ("digest_mismatch", lambda d: doc(d, "k1-analysis")["artifact"].update(hashes=["sha256:" + "ab" * 32]), "mismatched", "BIND_DIGEST_MISMATCH"),
    ("no_artifact_declared", lambda d: doc(d, "k1-analysis").pop("artifact"), "unknown", "BIND_NO_SUBJECT"),
    ("target_not_declared", lambda d: doc(d, "k1-analysis").pop("target"), "unknown", "REACH_BIND_TARGET_NOT_DECLARED"),
    ("other_component", lambda d: doc(d, "k1-analysis").update(target={"purl": "pkg:npm/lib-a@1.0"}), "unknown", "REACH_BIND_TARGET_NOT_MATCHED"),
    ("other_version_by_name", lambda d: doc(d, "k1-analysis").update(target={"name": "lib-b", "version": "9"}), "unknown", "REACH_BIND_TARGET_NOT_COMPARABLE"),
])
def test_bind_combines_the_analysis_artifact_and_the_component(label, change, state, reason):
    data = baseline_data()
    change(data)
    outcome = run("cdx", data, verification=V_K1)
    assert outcome.bind.state.value == state
    if reason:
        assert any(reason in r for r in outcome.bind.reasons)
        assert "R6" in outcome.evaluation.rule_ids and outcome.result.verdict is INSUFFICIENT
    else:
        assert "R6" not in outcome.evaluation.rule_ids


def test_a_digest_mismatch_on_one_relied_on_document_makes_bind_mismatched_and_it_cannot_be_p2_or_p3():
    data = with_extra(baseline_data(), "K1", "incomplete", "k1-second")
    doc(data, "k1-second")["artifact"] = {"purl": PRODUCT, "hashes": ["sha256:" + "cd" * 32]}
    outcome = run("cdx", data, verification=verified("k1-analysis", "k1-second"))
    assert outcome.bind.state.value == "mismatched" and "R6" in outcome.evaluation.rule_ids
    # the mismatched document cannot be P2, so the verification result cannot lift it to P3: it stays at P1
    assert outcome.prov_reach is P.P1


def test_product_version_binding_binds_but_grants_no_p2():
    data = baseline_data()
    doc(data, "k1-analysis")["artifact"] = {"purl": PRODUCT, "version": "2.0.0"}
    outcome = run("cdx", data, digest=False)
    assert outcome.bind.state.value == "matched"
    assert outcome.prov_reach is P.P1 and "R13" in outcome.evaluation.rule_ids


def test_an_unresolved_target_component_makes_bind_unknown_g1r():
    findings = vex_findings("reachability_equivalent.json")
    findings[0].component = None
    outcome = run("cdx", verification=V_K1, findings=findings)
    assert outcome.finding.component is None and outcome.bind.state.value == "unknown"
    assert "R6" in outcome.evaluation.rule_ids and outcome.result.verdict is INSUFFICIENT
    assert any(d.startswith("TARGET_COMPONENT_UNRESOLVED") for d in outcome.diagnostics)
    assert "REACH_BIND_NO_TARGET_COMPONENT" in " ".join(outcome.bind.reasons)


def test_an_evaluator_supplied_target_resolves_the_component_and_binding_proceeds():
    findings = vex_findings("reachability_equivalent.json")
    findings[0].component = None
    profile = make_profile(equivalent("cdx").doc_id, target={"name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"})
    outcome = run("cdx", verification=V_K1, findings=findings, profile=profile)
    assert outcome.bind.state.value == "matched" and outcome.result.verdict is SUPPORTED


def test_a_vex_product_identifier_is_never_used_as_the_component():
    findings = vex_findings("reachability_equivalent.json")
    findings[0].component = None
    findings[0].product.purl = "pkg:npm/lib-b@2.0"  # even if the product looked like the target
    assert run("cdx", verification=V_K1, findings=findings).bind.state.value == "unknown"


def test_the_sbom_bind_only_matters_for_k4():
    mismatched = make_profile(equivalent("cdx").doc_id, digest=False, version="9.9")
    # product/version fallback fails: the SBOM is not bound; the K1 report still binds by digest to a scope with no digest? -> unknown
    outcome = run("cdx", verification=V_K1, profile=mismatched)
    assert outcome.sbom_bind.state.value != "matched" and any(d.startswith("SBOM_BIND_") for d in outcome.diagnostics)


# ---- provenance ----------------------------------------------------------------------------------------------------------------------------------------

def test_p3_needs_a_trusted_verified_result_with_coverage_of_the_finding_locator():
    cases = {
        "none": (None, P.P2),
        "trusted_covering": (verified("k1-analysis", coverage=("#/finding",)), P.P3),
        "whole_document": (verified("k1-analysis", coverage=("#",)), P.P3),
        "coverage_excludes_finding": (verified("k1-analysis", coverage=("#/entry_points",)), P.P1),  # step 3 cap
        "empty_coverage": (verified("k1-analysis", coverage=()), P.P1),
        "not_verified": (verified("k1-analysis", verified_flag=False), P.P2),
        "other_document": (verified("k1-analysis-copy"), P.P2),
    }
    for label, (verification, level) in cases.items():
        outcome = run("cdx", verification=verification)
        assert outcome.prov_reach is level, label
        assert (outcome.result.verdict is SUPPORTED) is (level is P.P3), label
        assert ("ANALYSIS_PROVENANCE_BELOW_P3" in outcome.result.codes) is (level is not P.P3), label


def test_an_untrusted_anchor_grants_nothing():
    from evidence.verification import VerificationConfig, VerificationResult
    config = VerificationConfig(frozenset({"anchor-1"}), (VerificationResult("k1-analysis", True, "rogue", "v", "1", ("#",)),))
    assert run("cdx", verification=config).prov_reach is P.P2


def test_detached_verification_is_stated_in_the_limitations_and_nothing_is_signed():
    outcome = run("cdx", verification=V_K1)
    assert any("P3_FROM_DETACHED_VERIFICATION_RESULT" in lim for lim in outcome.limitations)
    assert outcome.finding.source_documents["k1-analysis"].integrity.signature is None
    assert outcome.finding.source_documents["k1-analysis"].integrity.signature_verified is True
    assert any("EVIDENCE_NOT_VERIFIED" in lim for lim in outcome.limitations)  # A6 / CE-R6


def test_a_verification_result_for_an_unknown_document_is_reported_not_applied():
    outcome = run("cdx", verification=verified("k1-analysis", "ghost"))
    assert any(d.startswith("VERIFICATION_RESULT_UNREFERENCED: ghost") for d in outcome.diagnostics)


def test_weaker_provenance_never_improves_the_verdict_end_to_end():
    rank = {INSUFFICIENT: 0, WEAK: 1, SUPPORTED: 2}
    chain = []
    chain.append(run("cdx", verification=V_K1))                                           # P3
    chain.append(run("cdx"))                                                              # P2
    no_digest = baseline_data()
    doc(no_digest, "k1-analysis")["artifact"] = {"purl": PRODUCT, "version": "2.0.0"}
    chain.append(run("cdx", no_digest))                                                   # P1 (product/version, no digest)
    chain.append(run("cdx", strip(baseline_data(), "k1-analysis", "tool_version")))       # P0
    levels = [o.prov_reach for o in chain]
    assert levels == [P.P3, P.P2, P.P1, P.P0]
    verdicts = [rank[o.result.verdict] for o in chain]
    assert verdicts == sorted(verdicts, reverse=True) and verdicts[0] == 2
    # each additional weakness: hazard basis, configuration, locus, entry
    for weaken in (lambda d: doc(d, "reflection-basis").pop("tool_version"), lambda d: d.pop("configuration"),
                   lambda d: d["locus"].pop("approximation"), lambda d: doc(d, "k1-analysis").pop("entry_points")):
        data = baseline_data()
        weaken(data)
        assert rank[run("cdx", data, verification=V_K1).result.verdict] <= 1


def test_a_k2_assertion_below_p1_is_unknown_and_above_it_incomplete_but_never_better_than_weak():
    for attributed, state, verdict in [(False, S.UNKNOWN, INSUFFICIENT), (True, S.INCOMPLETE, WEAK)]:
        data = solo("K2", "negative", attributed=attributed)
        data["entry_points"] = {"complete": True, "entered_by": "t"}
        data["hazards"] = fixture_data("synthetic_k3_no_hit")["hazards"]
        outcome = run("cdx", data, verification=verified("doc-1") if attributed else None)
        assert outcome.reach.state is state and outcome.result.verdict is verdict


# ---- refusals, routing and the shape of failures -----------------------------------------------------------------------------------------------------------

def test_a_non_not_affected_disposition_is_an_input_error_not_a_verdict():
    findings = vex_findings("reachability_equivalent.json")
    findings[0].disposition = Disposition.AFFECTED
    refusal = run("cdx", findings=findings)
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.DISPOSITION_NOT_EVALUATED
    assert not hasattr(refusal, "result")


def test_the_reachability_evaluator_refuses_other_justifications_instead_of_coercing_them():
    record = equivalent("cdx")
    outcome = evaluate_reachability(make_profile(record.doc_id), vex_findings("component_not_present.json"), Stage1Index([record]))
    assert isinstance(outcome, EvaluationRefusal) and outcome.code is RefusalCode.JUSTIFICATION_NOT_SUPPORTED


@pytest.mark.parametrize("bad", [None, "x", 3])
def test_bad_arguments_are_refusals_with_stable_codes(bad):
    record = equivalent("cdx")
    profile, findings = make_profile(record.doc_id), vex_findings("reachability_equivalent.json")
    index = Stage1Index([record])
    assert evaluate_reachability(bad, findings, index).code is RefusalCode.PROFILE_INVALID
    assert evaluate_reachability(profile, findings, bad).code is RefusalCode.ASSEMBLY_FAILED
    assert evaluate_reachability(profile, bad, index).code is RefusalCode.ASSEMBLY_FAILED
    if bad is not None:
        assert evaluate_reachability(profile, findings, index, reachability=bad).code is RefusalCode.REACH_INPUT_INVALID
        assert evaluate_reachability(profile, findings, index, verification=bad).code is RefusalCode.VERIFICATION_INVALID


def test_a_reachability_document_id_that_collides_with_a_profile_document_is_refused():
    record = equivalent("cdx")
    data = baseline_data()
    doc(data, "k1-analysis")["doc_id"] = record.doc_id
    refusal = run("cdx", data, record=record)
    assert isinstance(refusal, EvaluationRefusal) and refusal.cause == "REACH_DOCUMENT_ID_COLLISION"


def test_a_missing_record_or_finding_is_a_refusal_not_a_verdict():
    record = equivalent("cdx")
    assert run("cdx", record=record, profile=make_profile("not-indexed")).code is RefusalCode.ASSEMBLY_FAILED
    assert run("cdx", findings=[]).code is RefusalCode.PROFILE_INVALID


def test_no_refusal_exposes_a_partial_verdict():
    refusal = run("cdx", findings=[])
    assert isinstance(refusal, EvaluationRefusal)
    assert set(refusal.to_dict()) == {"refused", "code", "cause", "detail"} and refusal.to_dict()["refused"] is True


def test_missing_reachability_input_is_unknown_evidence_not_a_refusal():
    outcome = run("cdx", reachability=None)
    assert isinstance(outcome, ReachOutcome) and outcome.result.verdict is INSUFFICIENT
    assert outcome.reach.state is S.UNKNOWN and "R2" in outcome.evaluation.rule_ids


def test_routing_through_evaluate_finding_selects_exactly_one_predicate():
    record = equivalent("cdx")
    index = Stage1Index([record])
    profile = make_profile(record.doc_id)
    cnp = sufficiency.evaluate_finding(profile, vex_findings("component_not_present.json"), index)
    reach = sufficiency.evaluate_finding(profile, vex_findings("reachability_equivalent.json"), index, None, evidence(baseline_data()))
    assert isinstance(cnp, EvaluationOutcome) and isinstance(reach, ReachOutcome)
    assert "cnp_inputs" in cnp.to_dict() and "reach_inputs" in reach.to_dict()


def test_reachability_evidence_for_a_cnp_finding_is_refused_never_ignored():
    record = equivalent("cdx")
    refusal = sufficiency.evaluate_finding(make_profile(record.doc_id), vex_findings("component_not_present.json"),
                                           Stage1Index([record]), None, evidence(baseline_data()))
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.REACH_INPUT_NOT_APPLICABLE


def test_the_cnp_evaluator_still_refuses_a_reachability_finding():
    from evidence.evaluator import evaluate
    record = equivalent("cdx")
    refusal = evaluate(make_profile(record.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record]))
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.JUSTIFICATION_NOT_SUPPORTED


def test_the_two_predicates_do_not_interfere_when_evaluated_back_to_back():
    record = equivalent("cdx")
    index = Stage1Index([record])
    profile = make_profile(record.doc_id)
    cnp_findings, reach_findings = vex_findings("component_not_present.json"), vex_findings("reachability_equivalent.json")
    first = sufficiency.evaluate_finding(profile, cnp_findings, index).to_dict()
    sufficiency.evaluate_finding(profile, reach_findings, index, V_K1, evidence(baseline_data()))
    again = sufficiency.evaluate_finding(profile, cnp_findings, index).to_dict()
    assert first == again


# ---- immutability, determinism, traceability -------------------------------------------------------------------------------------------------------------------

def test_no_caller_owned_input_is_mutated():
    record = equivalent("cdx")
    findings = vex_findings("reachability_equivalent.json")
    profile = make_profile(record.doc_id)
    index = Stage1Index([record])
    data = baseline_data()
    reach_input = evidence(data)
    verification = V_K1
    before = (copy.deepcopy(findings), copy.deepcopy(record), copy.deepcopy(reach_input), copy.deepcopy(verification), copy.deepcopy(profile))
    outcome = evaluate_reachability(profile, findings, index, reach_input, verification)
    assert isinstance(outcome, ReachOutcome)
    assert (findings, record, reach_input, verification, profile) == before
    assert findings[0].scope.deployment_config_id is None and "k1-analysis" not in findings[0].source_documents
    assert "k1-analysis" in outcome.finding.source_documents  # only the evaluation's own copy carries it
    assert record.document.integrity.signature_verified is None


@pytest.mark.parametrize("kind", KINDS)
def test_the_output_is_deterministic_and_json_serialisable(kind):
    first, second = run(kind, verification=V_K1), run(kind, verification=V_K1)
    assert first.to_dict() == second.to_dict()
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(second.to_dict(), sort_keys=True)
    assert first.to_dict()["evaluation"]["result"]["verdict"] == "Supported"


def test_document_order_in_the_input_does_not_change_the_result():
    data = add_doc(with_extra(baseline_data(), "K3", "negative", "k3-trace"), doc_id="extra-basis", kind="hazard_basis")
    reordered = copy.deepcopy(data)
    reordered["documents"].reverse()
    first, second = run("cdx", data, verification=V_K1), run("cdx", reordered, verification=V_K1)
    assert first.result == second.result and first.dimension_states == second.dimension_states


def test_items_carry_valid_sources_roles_locators_and_stable_ids():
    outcome = run("cdx", with_extra(baseline_data(), "K3", "negative", "k3-trace"), verification=V_K1)
    ids = [i.item_id for i in outcome.items]
    assert len(ids) == len(set(ids)) and all(ids)
    for item in outcome.items:
        assert item.state in S
        if item.source_doc is None:
            assert item.dimension in ("LOCUS", "ENTRY") and item.locator is None
        else:
            assert item.source_doc in outcome.finding.source_documents
            assert item.locator in ("#/finding", "#/entry_points", "#")
    roles = {d: r.value for d, r in outcome.finding.document_roles.items()}
    assert roles[outcome.doc_id] == "primary_sbom" and roles["k1-analysis"] == "reachability_report"
    assert roles["reflection-basis"] == "other"
    assert [i.item_id for i in outcome.items if i.dimension == "REACH"][0].startswith("REACH:")


def test_limitations_name_the_actual_deficiencies_of_the_evidence_used():
    outcome = run("cdx", {"schema_version": "1"})
    assert "REACH=Unknown: only a K4 dependency graph exists" in outcome.limitations
    assert any(lim.startswith("LOCUS=Unknown") for lim in outcome.limitations)
    weak = run("cdx", verification=V_K1)
    assert not any(lim.startswith(("REACH=", "LOCUS=")) for lim in weak.limitations)
