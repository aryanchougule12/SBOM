"""End-to-end tests: raw analyzer artifact -> adapter -> binding/provenance -> reachability evaluator -> outcome or refusal.

Fixtures are upstream files (category A), SYNTHETIC (category B) or live CodeQL output (category L); see fixtures/analysis/README.md."""

import copy
import json

import pytest

from evidence import sufficiency
from evidence.analysis_ingest import AnalysisArtifactInput, evaluate_with_analysis, ingest_artifacts, parse_analysis_artifact
from evidence.analysis_model import AnalysisFormat
from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, RefusalCode
from evidence.reach_evaluator import ReachOutcome, evaluate_reachability
from evidence.reach_inputs import parse_reachability
from evidence.stage1_records import Stage1Index
from model import EvidenceState as S
from reports.verdict import Verdict
from tests import analysis_eval
from tests.analysis_support import GRAPHML_DIR, SARIF_DIR, UPSTREAM_DIR, base_evidence, evaluate, resolve_pointer, subject
from tests.pipeline_support import equivalent, make_profile, vex_findings
from tests.reach_support import baseline_data, evidence, run as run_strict, verified

RANK = {Verdict.INSUFFICIENT: 0, Verdict.WEAK: 1, Verdict.SUPPORTED: 2}
MANIFEST = analysis_eval.load_manifest()
BOUND_SARIF = SARIF_DIR / "synthetic_path_bound.sarif"
BOUND_GRAPH = GRAPHML_DIR / "synthetic_path_bound.graphml"
GS = dict(target_source_root="node_modules/lib-b")


def gsubject(**changes):
    return subject(**{**GS, **changes})


# ---- the whole corpus, against the hand-reviewed expectations ------------------------------------------------------------

@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda c: c["id"])
def test_every_corpus_case_matches_its_reviewed_expectation(case):
    actual = analysis_eval.run_case(case, MANIFEST["defaults"])
    assert analysis_eval.compare(case["expected"], actual) == [], case["why"]
    assert analysis_eval.check_fixture(case) == []


# ---- refusal vs Insufficient -------------------------------------------------------------------------------------------------

def test_an_invalid_artifact_is_a_refusal_with_no_verdict_but_an_empty_one_is_an_insufficient_verdict():
    refused = evaluate(SARIF_DIR / "synthetic_invalid_results_type.sarif")
    assert isinstance(refused, EvaluationRefusal) and refused.code is RefusalCode.ANALYSIS_ARTIFACT_INVALID
    assert refused.cause == "ANALYSIS_STRUCTURE_INVALID" and "#/runs/0/results" in refused.detail and not hasattr(refused, "result")
    empty = evaluate(SARIF_DIR / "synthetic_no_results.sarif")
    assert isinstance(empty, ReachOutcome) and empty.result.verdict is Verdict.INSUFFICIENT and empty.reach.state is S.UNKNOWN


def test_bad_arguments_are_refusals_not_exceptions():
    record = equivalent("cdx")
    profile, findings, index = make_profile(record.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record])
    assert evaluate_with_analysis(profile, findings, index, [BOUND_SARIF], object()).code is RefusalCode.ANALYSIS_SUBJECT_INVALID   # type: ignore[arg-type]
    assert evaluate_with_analysis(profile, findings, index, "path", subject()).code is RefusalCode.ANALYSIS_ARTIFACT_INVALID           # type: ignore[arg-type]
    assert evaluate_with_analysis(profile, findings, index, [BOUND_SARIF], subject(), reachability="x").code is RefusalCode.REACH_INPUT_INVALID  # type: ignore[arg-type]
    assert evaluate_with_analysis(profile, findings, index, [b"not an artifact"], subject()).cause == "ANALYSIS_FORMAT_UNRECOGNIZED"
    assert evaluate_with_analysis(profile, findings, index, ["/no/such/file"], subject()).cause == "ANALYSIS_ARTIFACT_UNREADABLE"
    assert evaluate_with_analysis("profile", findings, index, [BOUND_SARIF], subject()).code is RefusalCode.PROFILE_INVALID               # type: ignore[arg-type]


def test_a_format_that_disagrees_with_the_content_is_a_refusal():
    explicit = AnalysisArtifactInput(BOUND_SARIF, AnalysisFormat.JOERN_GRAPHML, "wrong format")
    record = equivalent("cdx")
    result = evaluate_with_analysis(make_profile(record.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record]), [explicit], subject())
    assert isinstance(result, EvaluationRefusal) and "wrong format" in result.detail


def test_an_artifact_supplied_twice_is_refused_not_counted_twice():
    record = equivalent("cdx")
    result = evaluate_with_analysis(make_profile(record.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record]),
                                    [BOUND_SARIF, BOUND_SARIF.read_bytes()], subject(), base_evidence())
    assert isinstance(result, EvaluationRefusal) and result.cause == "ANALYSIS_ARTIFACT_CONTRADICTORY"


def test_path_and_bytes_give_identical_results():
    by_path = evaluate(BOUND_SARIF).to_dict()
    by_bytes = evaluate(BOUND_SARIF.read_bytes()).to_dict()
    assert by_path == by_bytes


# ---- evidence semantics --------------------------------------------------------------------------------------------------------

def test_a_bound_flow_becomes_a_present_reach_state_with_a_traceable_item():
    outcome = evaluate(BOUND_SARIF)
    assert outcome.reach.state is S.PRESENT and outcome.reach.step == 1
    (item,) = [i for i in outcome.items if i.dimension == "REACH" and i.value_or_ref.trace is not None]
    assert item.state is S.PRESENT and item.source_doc == outcome.analysis[0].artifact.doc_id and item.derived_from == []
    assert item.locator == "#/runs/0/results/0/codeFlows/0/threadFlows/0" and item.item_id.startswith("REACH:sarif:sha256:")
    assert item.value_or_ref.trace.step_locators and outcome.finding.document_roles[item.source_doc].value == "reachability_report"
    assert outcome.finding.source_documents[item.source_doc].declared_metadata["format"] == "sarif"
    assert outcome.finding.source_documents[item.source_doc].declared_metadata["derived_by"] == "evidence.analysis_binding"


@pytest.mark.parametrize("name", sorted(p.name for p in SARIF_DIR.glob("synthetic_*.sarif") if "invalid" not in p.name))
def test_every_evidence_locator_resolves_inside_the_raw_artifact(name):
    path = SARIF_DIR / name
    outcome = evaluate(path)
    document = json.loads(path.read_text())
    for item in outcome.items:
        if item.dimension == "REACH" and item.value_or_ref.trace is not None:
            assert resolve_pointer(document, item.locator) is not None
            for locator in item.value_or_ref.trace.step_locators:
                assert "physicalLocation" in resolve_pointer(document, locator)
    for source in outcome.analysis:
        for trace in source.traces:
            assert trace.locator in source.observation_locators


def test_graph_evidence_locators_name_real_elements_of_the_export():
    outcome = evaluate(BOUND_GRAPH, subj=gsubject(), base=base_evidence())
    (item,) = [i for i in outcome.items if i.dimension == "REACH" and i.value_or_ref.trace is not None]
    text = BOUND_GRAPH.read_text()
    assert item.locator == "#/graphml"
    for locator in item.value_or_ref.trace.step_locators:
        kind, ident = locator.split("/")[-2:]
        assert (f'<node id="{ident}">' in text) if kind == "node" else locator.startswith("#/graphml/edge/")


def test_the_explanation_carries_source_identity_diagnostics_and_limitations():
    outcome = evaluate(SARIF_DIR / "synthetic_alert_without_codeflow.sarif")
    (source,) = outcome.analysis
    assert source.artifact.doc_id.startswith("sarif:sha256:") and source.artifact.format_version == "2.1.0" and source.subject_label == "corpus-reviewer"
    assert any(d.startswith(f"ANALYSIS_DIAGNOSTIC {source.artifact.doc_id}: RESULTS_WITHOUT_CODE_FLOW") for d in outcome.diagnostics)
    assert any(lim.startswith(f"{source.artifact.doc_id}: NO_ABSENCE_EVIDENCE") for lim in outcome.limitations)
    exported = outcome.to_dict()
    assert exported["analysis"][0]["artifact"]["doc_id"] == source.artifact.doc_id


def test_no_artifact_can_make_reach_absent_or_supported():
    for path in sorted(SARIF_DIR.glob("synthetic_*.sarif")) + sorted(GRAPHML_DIR.glob("synthetic_*.graphml")) + sorted(UPSTREAM_DIR.glob("*.sarif")):
        if "invalid" in path.name or path.name == "codeql-action__tool-names.sarif":
            continue
        outcome = evaluate(path, subj=gsubject() if path.suffix == ".graphml" else subject())
        assert isinstance(outcome, ReachOutcome), path.name
        assert outcome.reach.state in (S.UNKNOWN, S.PRESENT), path.name
        assert outcome.result.verdict is Verdict.INSUFFICIENT, path.name
        assert all(i.state in (S.UNKNOWN, S.PRESENT) for i in outcome.items if i.dimension == "REACH")


def test_dependency_edges_alone_never_become_a_path():
    for kind in ("cdx", "spdx"):
        outcome = evaluate(None, kind=kind)
        assert outcome.reach.only_k4 and outcome.reach.state is S.UNKNOWN and outcome.result.codes[0] == "MISSING_EDGE_IS_UNKNOWN"
    with_artifact = evaluate(SARIF_DIR / "synthetic_no_results.sarif")
    assert with_artifact.result.codes[0] == "NO_ANALYSIS"  # an ingested artifact is analysis evidence even when nothing can be derived


def test_both_sbom_formats_give_the_same_result_for_the_same_artifact():
    cdx, spdx = evaluate(BOUND_SARIF, kind="cdx"), evaluate(BOUND_SARIF, kind="spdx")
    assert (cdx.result.verdict, cdx.evaluation.rule_ids, cdx.dimension_states) == (spdx.result.verdict, spdx.evaluation.rule_ids, spdx.dimension_states)


def test_equivalence_across_the_two_formats_is_claimed_only_for_a_bound_positive_path():
    sarif, graph = evaluate(BOUND_SARIF), evaluate(BOUND_GRAPH, subj=gsubject())
    assert sarif.dimension_states == graph.dimension_states and sarif.evaluation.rule_ids == graph.evaluation.rule_ids
    kinds = {sarif.analysis[0].traces[0].kind, graph.analysis[0].traces[0].kind}
    assert kinds == {"static_dataflow_trace", "call_graph_path"}          # different evidence kinds, deliberately not unified
    assert sarif.prov_reach.name == "P1" and graph.prov_reach.name == "P0"  # attribution differs: SARIF names its tool, the export does not


# ---- combination with the directly supplied (strict) evidence ----------------------------------------------------------------------

V_K1 = verified("k1-analysis")


def supported_base():
    data = baseline_data()
    data["locus"].update(files=["src/parse.js"], symbols=["lib.b.Parser.parse:java.lang.Object(java.lang.String)"])
    return parse_reachability(data)


def test_the_strict_input_alone_still_gives_supported_and_the_wrapper_with_no_artifacts_is_identical():
    direct = run_strict("cdx", verification=V_K1)
    wrapped = evaluate(None, base=supported_base(), verification=V_K1)
    assert direct.result.verdict is Verdict.SUPPORTED and wrapped.result.verdict is Verdict.SUPPORTED
    assert wrapped.reach_inputs == evaluate_reachability(make_profile(equivalent("cdx").doc_id), vex_findings("reachability_equivalent.json"),
                                                         Stage1Index([equivalent("cdx")]), supported_base(), V_K1).reach_inputs


def test_a_derived_path_can_only_lower_a_supported_verdict_and_a_non_path_artifact_changes_nothing():
    without = evaluate(None, base=supported_base(), verification=V_K1)
    assert without.result.verdict is Verdict.SUPPORTED
    for path in sorted(SARIF_DIR.glob("synthetic_*.sarif")) + sorted(UPSTREAM_DIR.glob("*.sarif")):
        if "invalid" in path.name or path.name == "codeql-action__tool-names.sarif":
            continue
        with_artifact = evaluate(path, base=supported_base(), verification=V_K1)
        if isinstance(with_artifact, EvaluationRefusal):  # an unresolved relevant record that could change the verdict: no verdict at all
            assert with_artifact.code is RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE, path.name
            continue
        assert RANK[with_artifact.result.verdict] <= RANK[without.result.verdict], path.name
        positive = any(s.traces for s in with_artifact.analysis)
        assert (with_artifact.result.verdict is Verdict.INSUFFICIENT) is positive, path.name
        if not positive:
            assert with_artifact.result == without.result, path.name


def test_a_derived_path_next_to_a_k1_absence_is_a_conflict_not_a_choice():
    outcome = evaluate(BOUND_SARIF, base=supported_base(), verification=V_K1)
    assert outcome.reach.state is S.CONTRADICTORY and outcome.evaluation.rule_ids[0] == "R3"
    documents = {i.source_doc for i in outcome.items if i.dimension == "REACH" and i.value_or_ref.kind != "K4"}
    assert documents == {"k1-analysis", outcome.analysis[0].artifact.doc_id}


def test_two_artifacts_of_different_formats_are_evaluated_together():
    outcome = evaluate_with_analysis(make_profile(equivalent("cdx").doc_id), vex_findings("reachability_equivalent.json"),
                                     Stage1Index([equivalent("cdx")]), [BOUND_SARIF, BOUND_GRAPH], gsubject(), base_evidence())
    assert len(outcome.analysis) == 2 and sum(len(s.traces) for s in outcome.analysis) == 2
    assert {s.artifact.format for s in outcome.analysis} == {AnalysisFormat.SARIF, AnalysisFormat.JOERN_GRAPHML}
    assert outcome.reach.state is S.PRESENT and outcome.prov_reach.name == "P0"  # the minimum over the documents it depends on


# ---- provenance and the monotonicity requirements ----------------------------------------------------------------------------------

def test_verification_cannot_lift_a_derived_document_above_p1_because_it_declares_no_digest():
    doc_id = parse_analysis_artifact(BOUND_SARIF).source.doc_id
    levels = {}
    for label, coverage, ok, anchors in [("none", None, True, None), ("covering", ["#"], True, ["anchor-1"]), ("narrow", ["#/runs/0"], True, ["anchor-1"]),
                                         ("excluding", ["#/runs/9"], True, ["anchor-1"]), ("empty", [], True, ["anchor-1"]),
                                         ("failed", ["#"], False, ["anchor-1"])]:
        verification = None if coverage is None else verified(doc_id, coverage=coverage, verified_flag=ok)
        levels[label] = evaluate(BOUND_SARIF, verification=verification).prov_reach.name
    assert set(levels.values()) == {"P1"}, levels


def test_a_result_for_another_artifact_is_not_applied_to_this_one():
    outcome = evaluate(BOUND_SARIF, verification=verified("sarif:sha256:" + "0" * 64))
    assert outcome.prov_reach.name == "P1" and any(d.startswith("VERIFICATION_RESULT_UNREFERENCED") for d in outcome.diagnostics)


def test_weaker_attribution_or_binding_never_improves_the_result():
    def variant(change):
        data = json.loads(BOUND_SARIF.read_text())
        change(data)
        return evaluate(json.dumps(data).encode())

    full = variant(lambda d: None)
    weaker = [
        variant(lambda d: d["runs"][0]["tool"]["driver"].pop("semanticVersion")),
        variant(lambda d: d["runs"][0].pop("invocations")),
        variant(lambda d: d["runs"][0].pop("versionControlProvenance")),
        variant(lambda d: d["runs"][0]["versionControlProvenance"][0].update(revisionId="f" * 40)),
        variant(lambda d: d["runs"][0]["versionControlProvenance"][0].update(repositoryUri="https://example.org/other")),
        variant(lambda d: d["runs"][0]["invocations"][0].update(executionSuccessful=False)),
        variant(lambda d: d["runs"][0]["results"].clear()),
    ]
    for outcome in weaker:
        assert RANK[outcome.result.verdict] <= RANK[full.result.verdict]
        assert outcome.prov_reach is None or outcome.prov_reach <= full.prov_reach
        assert set(outcome.evaluation.rule_ids) >= {"R5", "R11"}


def test_target_identity_mismatch_in_every_form_blocks_binding():
    for changes in (dict(target=dict(purl="pkg:npm/lib-a@1.0")), dict(artifact=dict(purl="pkg:oci/other@1", version="2.0.0")),
                    dict(source_revision="f" * 40), dict(source_repository="https://example.org/git/other.git")):
        outcome = evaluate(BOUND_SARIF, subj=subject(**changes))
        assert outcome.dimension_states["BIND"] != "matched" and "R6" in outcome.evaluation.rule_ids, changes


def test_the_scope_digest_never_binds_a_derived_document_by_itself():
    # the profile has a digest; the derived document declares none, so BIND rests on product/version and the document is not P2
    outcome = evaluate(BOUND_SARIF)
    assessment = outcome.documents[0]
    assert assessment.artifact_bind.basis.value == "product_version" and assessment.provenance.p2.value == "bind_basis_not_digest"


# ---- determinism, immutability, compatibility -------------------------------------------------------------------------------------------

def test_evaluation_is_deterministic_json_and_input_immutable():
    record = equivalent("cdx")
    findings, profile, index = vex_findings("reachability_equivalent.json"), make_profile(record.doc_id), Stage1Index([record])
    subj, base = subject(), base_evidence()
    raw = BOUND_SARIF.read_bytes()
    before = (copy.deepcopy(findings), copy.deepcopy(record), copy.deepcopy(subj), copy.deepcopy(base), raw)
    first = evaluate_with_analysis(profile, findings, index, [raw], subj, base)
    second = evaluate_with_analysis(profile, findings, index, [raw], subj, base)
    assert (findings, record, subj, base, raw) == before
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(second.to_dict(), sort_keys=True)
    assert base.documents == () and base.analysis_sources == ()          # ingestion returns a new evidence object


def test_ingest_returns_new_evidence_and_leaves_the_base_untouched():
    base = base_evidence()
    merged = ingest_artifacts([BOUND_SARIF], subject(), base)
    assert merged is not base and len(merged.documents) == 1 and len(merged.analysis_sources) == 1 and base.documents == ()


def test_the_cnp_path_and_the_direct_reachability_entry_point_are_unaffected():
    record = equivalent("cdx")
    index, profile = Stage1Index([record]), make_profile(record.doc_id)
    evaluate(BOUND_SARIF)
    cnp = sufficiency.evaluate_finding(profile, vex_findings("component_not_present.json"), index)
    assert isinstance(cnp, EvaluationOutcome)
    direct = sufficiency.evaluate_finding(profile, vex_findings("reachability_equivalent.json"), index, V_K1, evidence(baseline_data()))
    assert isinstance(direct, ReachOutcome) and direct.result.verdict is Verdict.SUPPORTED and direct.analysis == ()


def test_a_cnp_finding_is_refused_by_the_analysis_path():
    record = equivalent("cdx")
    refusal = evaluate_with_analysis(make_profile(record.doc_id), vex_findings("component_not_present.json"), Stage1Index([record]), [BOUND_SARIF], subject())
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.JUSTIFICATION_NOT_SUPPORTED


def test_item_validation_rejects_a_derived_item_that_is_detached_from_its_artifact():
    import dataclasses
    from evidence.items import ItemIntegrityError
    from evidence.reach_items import validate_reach_items
    outcome = evaluate(BOUND_SARIF)
    item = next(i for i in outcome.items if i.dimension == "REACH" and i.value_or_ref.trace is not None)
    allowed = {item.source_doc: frozenset({item.locator})}
    validate_reach_items(outcome.finding, outcome.doc_id, outcome.items, allowed)
    for change, expected in [(dict(locator="#/runs/0"), "ITEM_LOCATOR_NOT_IN_DOCUMENT"),
                             (dict(value_or_ref=dataclasses.replace(item.value_or_ref, trace=None)), "ITEM_LOCATOR_NOT_IN_DOCUMENT"),
                             (dict(source_doc="k1-analysis"), "ITEM_SOURCE_NOT_REGISTERED")]:
        tampered = [dataclasses.replace(item, **change) if i is item else i for i in outcome.items]
        with pytest.raises(ItemIntegrityError) as error:
            validate_reach_items(outcome.finding, outcome.doc_id, tampered, allowed)
        assert error.value.code == expected, change
    # a trace on a document that was not derived from an artifact is a forged derivation claim
    with pytest.raises(ItemIntegrityError):
        validate_reach_items(outcome.finding, outcome.doc_id, outcome.items, {})
