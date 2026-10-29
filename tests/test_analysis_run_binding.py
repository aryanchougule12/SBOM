"""Source binding, URI/root mapping, coverage facts and the K1 interplay of analysis-run records, end to end through the real adapters.

Every expectation follows from the specification text quoted in the test or in docs/spec_addendum_v0.2.5.md; the corpus
(fixtures/analysis/manifest.json) holds the per-case rationale."""

import copy
import json

import pytest

from evidence.analysis_ingest import AnalysisArtifactInput
from evidence.analysis_model import BindingStatus
from evidence.analysis_run import parse_analysis_run, parse_analysis_run_data
from evidence.analysis_run_binding import RootMapper, ends_with_file
from evidence.evaluator import EvaluationRefusal, RefusalCode
from evidence.reach_evaluator import ReachOutcome
from model import EvidenceState as S
from reports.verdict import Verdict
from tests.analysis_eval import ANALYSIS_DIR, _base_evidence, load_manifest
from tests.analysis_support import SARIF_DIR, evaluate, subject
from evidence.reach_inputs import parse_reachability
from tests.reach_support import verified

RUNS = ANALYSIS_DIR / "runs"
TREE = "git-tree:" + "ab" * 20
V_K1 = verified("k1-analysis")
RANK = {Verdict.INSUFFICIENT: 0, Verdict.WEAK: 1, Verdict.SUPPORTED: 2}


def load(name):
    return json.loads((RUNS / name).read_text())


def record(name="synthetic_good_no_path.run.json", **edit):
    data = load(name)
    for path, value in edit.items():
        node = data
        keys = path.split("__")
        for key in keys[:-1]:
            node = node[key]
        if value is Ellipsis:
            node.pop(keys[-1], None)
        else:
            node[keys[-1]] = value
    return parse_analysis_run_data(data)


def base(name="baseline_no_k1"):
    locus = load_manifest()["defaults"]["locus"]
    return parse_reachability(_base_evidence(name, locus))


def run(artifact, rec, *, base_name="baseline_no_k1", subj=None, verification=None, base_evidence="default"):
    path = ANALYSIS_DIR / artifact
    chosen = base(base_name) if base_evidence == "default" else base_evidence
    return evaluate(AnalysisArtifactInput(path, run=rec), subj=subj or subject(source_content_hash=TREE), base=chosen, verification=verification)


NO_PATH, PATH = "sarif/synthetic_cq_no_path.sarif", "sarif/synthetic_cq_path.sarif"


# ---- the negative derivation: exactly when, and nothing more -----------------------------------------------------------------------

def test_a_complete_record_derives_a_negative_k1_report_and_the_rules_decide_the_verdict():
    outcome = run(NO_PATH, record())
    assessment = outcome.analysis[0].assessment
    assert assessment.negative_derived and assessment.preventing == () and assessment.binding is BindingStatus.ESTABLISHED
    assert outcome.reach.state is S.ABSENT and outcome.result.verdict is Verdict.WEAK   # §5.1 step 2, R13 (P1), R11, R12
    assert set(outcome.evaluation.rule_ids) == {"R11", "R12", "R13"} and outcome.prov_reach.name == "P1"
    item = next(i for i in outcome.items if i.dimension == "REACH" and i.value_or_ref.kind == "K1")
    assert item.value_or_ref.full_coverage_claim and item.value_or_ref.finding == "negative" and item.value_or_ref.trace is None
    assert item.locator == "#/finding" and outcome.analysis[0].traces == ()


MUTATIONS = {
    "binding: other revision": dict(source__revision="fedcba9876543210fedcba9876543210fedcba98"),
    "binding: abbreviated revision": dict(source__revision="0123456"),
    "binding: other repository": dict(source__repository="https://example.org/git/other.git"),
    "binding: tree digest": dict(source__tree_digest="git-tree:" + "cd" * 20),
    "binding: dirty": dict(source__worktree_clean=False),
    "binding: untracked": dict(source__untracked_files=2),
    "binding: changed during run": dict(source__changed_during_run=True),
    "binding: stability unobserved": dict(source__changed_during_run=None),
    "binding: cleanliness unobserved": dict(source__worktree_clean=None),
    "binding: submodules unrecorded": dict(source__submodules=None),
    "binding: output hash": dict(outputs=[{"path": "x", "sha256": "0" * 64, "size": 1}]),
    "binding: no output listed": dict(outputs=[]),
    "binding: tool": dict(tool__name="Joern"),
    "binding: target": dict(target__purl="pkg:npm/other@1"),
    "execution: analysis failed": dict(stages=[{"name": "e", "role": "extraction", "status": "completed", "exit_code": 0},
                                               {"name": "a", "role": "analysis", "status": "failed", "exit_code": 1}]),
    "execution: analysis timed out": dict(stages=[{"name": "e", "role": "extraction", "status": "completed", "exit_code": 0},
                                                  {"name": "a", "role": "analysis", "status": "timed_out"}]),
    "execution: analysis not run": dict(stages=[{"name": "e", "role": "extraction", "status": "completed", "exit_code": 0},
                                                {"name": "a", "role": "analysis", "status": "not_run"}]),
    "execution: no stages": dict(stages=[]),
    "execution: extraction not recorded": dict(stages=[{"name": "a", "role": "analysis", "status": "completed", "exit_code": 0}]),
    "execution: extraction status unknown": dict(stages=[{"name": "e", "role": "extraction", "status": "unknown"},
                                                         {"name": "a", "role": "analysis", "status": "completed", "exit_code": 0}]),
    "execution: partial indicator": dict(scope__partial_indicators=["SKIPPED_FILES"]),
    "execution: error diagnostic": dict(diagnostics=[{"level": "error", "code": "X", "message": "m"}]),
    "tool: no version": dict(tool__version=Ellipsis),
    "scope: no language": dict(configuration__languages=[]),
    "scope: locus excluded": dict(scope__files__excluded=["node_modules"]),
    "scope: file inventory declared incomplete": dict(scope__files__complete=False),
    "scope: file inventory not stated": dict(scope__files__complete=None),
    "query: no semantics": dict(configuration__query__claim_semantics=Ellipsis),
    "query: taint semantics": dict(configuration__query__claim_semantics="taint_path_query"),
    "query: wrong semantics for the format": dict(configuration__query__claim_semantics="call_graph_export"),
    "query: other pack": dict(configuration__query__pack="codeql/java-queries"),
    "query: other pack version": dict(configuration__query__pack_version="2.4.9"),
    "query: unlisted query id": dict(configuration__query__query_ids=["js/other"]),
    "query: no query ids": dict(configuration__query__query_ids=[]),
    "entry points: incomplete": dict(scope__entry_points__complete=False),
    "entry points: unknown": dict(scope__entry_points__complete=None),
    "entry points: no source": dict(scope__entry_points__source=None),
    "entry points: no methods": dict(scope__entry_points__methods=[]),
    "entry points: differ from the evaluator's": dict(scope__entry_points__methods=["app.Other.main:void()"],
                                                      coverage_claim__entry_methods=["app.Other.main:void()"]),
    "claim: absent": dict(coverage_claim=None),
    "claim: other locus file": dict(coverage_claim__locus_files=["src/other.js"]),
    "claim: no locus symbol": dict(coverage_claim__locus_symbols=[]),
    "claim: other entry methods": dict(coverage_claim__entry_methods=["app.Other.main:void()"]),
}


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_every_missing_or_failed_condition_prevents_the_negative_derivation(label):
    outcome = run(NO_PATH, record(**MUTATIONS[label]))
    assert isinstance(outcome, ReachOutcome)
    assert not outcome.analysis[0].assessment.negative_derived, label
    assert outcome.reach.state is S.UNKNOWN and outcome.result.verdict is Verdict.INSUFFICIENT and "R2" in outcome.evaluation.rule_ids
    assert outcome.analysis[0].assessment.preventing    # the conditions that stop a stronger decision are listed


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_no_weakened_record_ever_yields_more_than_the_complete_record(label):
    complete = run(NO_PATH, record())
    weakened = run(NO_PATH, record(**MUTATIONS[label]))
    assert RANK[weakened.result.verdict] <= RANK[complete.result.verdict]


def test_the_artifact_alone_never_derives_an_absence():
    for name in ("synthetic_cq_no_path.sarif", "synthetic_no_results.sarif", "synthetic_alert_without_codeflow.sarif", "synthetic_unresolved_irrelevant.sarif"):
        outcome = evaluate(SARIF_DIR / name, base=base())
        assert outcome.reach.state is S.UNKNOWN and not outcome.analysis[0].assessment.negative_derived


def test_a_run_record_cannot_be_applied_to_a_different_artifact():
    """The record's hash is the only link to the bytes: moving it to another file contradicts it, and nothing of it is used."""
    outcome = run("sarif/synthetic_cq_locus_not_extracted.sarif", record())
    assert outcome.analysis[0].assessment.binding is BindingStatus.CONTRADICTED and not outcome.analysis[0].assessment.negative_derived
    assert "RUN_OUTPUT_HASH_MISMATCH" in outcome.analysis[0].assessment.binding_reasons


def test_a_successful_process_is_not_a_coverage_claim():
    outcome = run(NO_PATH, record(coverage_claim=None))
    assert outcome.analysis[0].assessment.execution == "completed" and outcome.reach.state is S.UNKNOWN
    assert dict(outcome.analysis[0].assessment.coverage)["process_completed"] == "established"
    assert dict(outcome.analysis[0].assessment.coverage)["coverage_claim_declared"] == "not_recorded"


# ---- paths are never hidden, absences never override --------------------------------------------------------------------------------

def test_a_bound_path_is_not_hidden_by_an_incomplete_run_or_a_complete_claim():
    for rec in (record("synthetic_good_path.run.json"), record("synthetic_analysis_stage_failed_with_path.run.json")):
        outcome = run(PATH, rec)
        assert outcome.reach.state is S.PRESENT and outcome.result.verdict is Verdict.INSUFFICIENT and len(outcome.analysis[0].traces) == 1
        assert not outcome.analysis[0].assessment.negative_derived


def test_a_derived_path_beside_a_supplied_k1_absence_is_a_conflict_not_a_choice():
    outcome = run(PATH, record("synthetic_good_path.run.json"), base_name="supported_k1", verification=V_K1)
    assert outcome.reach.state is S.CONTRADICTORY and outcome.evaluation.rule_ids[0] == "R3"


@pytest.mark.parametrize("name", ["synthetic_abs_no_roots.run.json", "synthetic_abs_other_root_path.run.json", "synthetic_abs_escape.run.json",
                                  "synthetic_abs_remote_host.run.json", "synthetic_abs_outside_every_root.run.json", "synthetic_abs_vendored_root.run.json"])
def test_an_unmapped_relevant_location_beside_a_k1_absence_is_refused_even_with_a_complete_record(name):
    artifact = {"synthetic_abs_escape.run.json": "synthetic_cq_abs_escape", "synthetic_abs_remote_host.run.json": "synthetic_cq_abs_remote_host",
                "synthetic_abs_outside_every_root.run.json": "synthetic_cq_abs_outside_every_root",
                "synthetic_abs_vendored_root.run.json": "synthetic_cq_abs_vendored"}.get(name, "synthetic_cq_abs_path")
    outcome = run(f"sarif/{artifact}.sarif", parse_analysis_run(RUNS / name), base_name="supported_k1", verification=V_K1)
    assert isinstance(outcome, EvaluationRefusal) and outcome.code is RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE


def test_mapping_requires_an_established_binding():
    ok = run("sarif/synthetic_cq_abs_path.sarif", parse_analysis_run(RUNS / "synthetic_abs_root_declared.run.json"), base_name="locus_only")
    assert ok.reach.state is S.PRESENT and dict(ok.analysis[0].assessment.uri_mapping)["mapped"] == 2
    for edit in (dict(source__revision="fedcba9876543210fedcba9876543210fedcba98"), dict(source__worktree_clean=False), dict(tool__name="Joern"),
                 dict(outputs=[{"path": "x", "sha256": "0" * 64}])):
        bad = run("sarif/synthetic_cq_abs_path.sarif", record("synthetic_abs_root_declared.run.json", **edit), base_name="locus_only")
        assert bad.reach.state is S.UNKNOWN and dict(bad.analysis[0].assessment.uri_mapping)["mapped"] == 0 and bad.analysis[0].undecidable


def test_mapping_does_not_depend_on_the_file_name_alone():
    """The same artifact with every directory but the file name replaced is mapped (through the root) to another file: not the locus."""
    text = (SARIF_DIR / "synthetic_cq_abs_path.sarif").read_text().replace("file:///ci/work/app/node_modules/lib-b/src/parse.js", "file:///ci/work/app/other-dir/parse.js")
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as directory:
        target = pathlib.Path(directory) / "x.sarif"
        target.write_text(text)
        data = load("synthetic_abs_root_declared.run.json")
        import hashlib
        data["outputs"][0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        outcome = evaluate(AnalysisArtifactInput(target, run=parse_analysis_run_data(data)), subj=subject(source_content_hash=TREE), base=base("locus_only"))
    assert not outcome.analysis[0].traces and not outcome.analysis[0].undecidable
    assert "FLOWS_NOT_TOUCHING_LOCUS" in {d.code for d in outcome.analysis[0].diagnostics}


# ---- RootMapper units ----------------------------------------------------------------------------------------------------------------

def roots(*items):
    return parse_analysis_run_data({"schema": "analysis-run/1", "run_id": "r", "origin": "caller", "tool": {"name": "t"},
                                    "source": {"roots": [{"id": i, "path": p, "role": r} for i, p, r in items]}}).source.roots


MAPPER = RootMapper(roots(("main", "/ci/work/app", "primary"), ("ext", "/ci/work/lib-b-ext", "vendored")))


@pytest.mark.parametrize("uri,root,relative", [
    ("file:///ci/work/app/src/a.js", "main", "src/a.js"),
    ("FILE:///ci/work/app/src/a.js", "main", "src/a.js"),
    ("file://localhost/ci/work/app/src/a.js", "main", "src/a.js"),
    ("file:/ci/work/app/src/a.js", "main", "src/a.js"),
    ("file:///ci/work/app/src/%61.js", "main", "src/a.js"),
    ("file:///ci/work/lib-b-ext/src/parse.js", "ext", "src/parse.js"),
])
def test_uris_that_are_mapped(uri, root, relative):
    located, why = MAPPER.map_uri(uri)
    assert located is not None and (located.root_id, located.relative) == (root, relative) and why == "mapped"


@pytest.mark.parametrize("uri", [
    "file:///ci/work/app", "file:///ci/work/app/", "file:///ci/work/ap/src/a.js", "file:///ci/work/application/src/a.js",
    "file:///ci/work/app/../app/src/a.js", "file:///ci/work/app/./src/a.js", "file:///ci/work/app//src/a.js", "file:///ci/work/app/src/%2e%2e/a.js",
    "file:///ci/work/app/src%2Fa.js", "file:///ci/work/app/src/a%00.js", "file:///ci/work/app/src%5Ca.js", "file:///ci/work/app/src/%FF.js",
    "file://build-host/ci/work/app/src/a.js", "file:///CI/WORK/APP/src/a.js", "https://example.org/ci/work/app/src/a.js", "ftp:///ci/work/app/src/a.js",
    "/ci/work/app/src/a.js", "ci/work/app/src/a.js", "file:///ci/work/app/src/a.js?x=1", "file:///ci/work/app/src/a.js#L3", "file:///elsewhere/src/a.js",
    "file:///C:/ci/work/app/src/a.js", "", "file:",
])
def test_uris_that_are_not_mapped(uri):
    assert MAPPER.map_uri(uri)[0] is None


def test_a_basename_alone_never_maps():
    assert MAPPER.map_uri("file:///somewhere/else/parse.js")[0] is None
    assert MAPPER.map_path("/somewhere/else/parse.js")[0] is None


def test_ends_with_file_is_whole_segments_and_case_insensitive():
    assert ends_with_file("lib/SRC/parse.js", ["src/parse.js"]) and not ends_with_file("lib/mysrc/parse.js", ["src/parse.js"])
    assert not ends_with_file("src/parse.jsx", ["src/parse.js"]) and not ends_with_file("", ["src/parse.js"])


# ---- binding statuses -----------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("edit,status,reason", [
    ({}, BindingStatus.ESTABLISHED, None),
    (dict(source__revision="fedcba9876543210fedcba9876543210fedcba98"), BindingStatus.CONTRADICTED, "REVISION_MISMATCH"),
    (dict(source__revision="0123456"), BindingStatus.AMBIGUOUS, "REVISION_ABBREVIATED"),
    (dict(source__revision="0123456" + "9" * 8), BindingStatus.CONTRADICTED, "REVISION_MISMATCH"),
    (dict(source__repository="https://example.org/git/other.git"), BindingStatus.CONTRADICTED, "REPOSITORY_MISMATCH"),
    (dict(source__repository="HTTPS://EXAMPLE.ORG/git/app/"), BindingStatus.ESTABLISHED, None),
    (dict(source__worktree_clean=False), BindingStatus.IMPOSSIBLE, "WORKTREE_NOT_CLEAN"),
    (dict(source__changed_during_run=True), BindingStatus.IMPOSSIBLE, "SOURCE_CHANGED_DURING_RUN"),
    (dict(source__submodules=[{"path": "v", "revision": "1" * 40}]), BindingStatus.AMBIGUOUS, "SUBMODULE_CONTENT_NOT_IDENTIFIED"),
    (dict(source__submodules=None), BindingStatus.MISSING, "SUBMODULES_NOT_RECORDED"),
    (dict(source__tree_digest=None), BindingStatus.MISSING, "RECORD_TREE_DIGEST_NOT_RECORDED"),
    (dict(source__revision=Ellipsis), BindingStatus.MISSING, "RECORD_REVISION_NOT_RECORDED"),
])
def test_binding_statuses(edit, status, reason):
    assessment = run(NO_PATH, record(**edit)).analysis[0].assessment
    assert assessment.binding is status and (reason is None or reason in assessment.binding_reasons)
    if status is not BindingStatus.ESTABLISHED:
        assert assessment.source_identity == "not_established"


def test_the_subject_must_declare_what_it_is_compared_with():
    for changes, reason in ((dict(source_revision=None), "SUBJECT_REVISION_NOT_DECLARED"), (dict(source_repository=None, source_revision=None), "SUBJECT_REVISION_NOT_DECLARED")):
        assessment = run(NO_PATH, record(), subj=subject(source_content_hash=TREE, **changes)).analysis[0].assessment
        assert assessment.binding is BindingStatus.MISSING and reason in assessment.binding_reasons
    undeclared = run(NO_PATH, record(), subj=subject(source_content_hash=None)).analysis[0].assessment
    assert undeclared.binding is BindingStatus.ESTABLISHED and undeclared.source_identity == "commit_only"     # clean tree, commit only


def test_the_artifact_may_not_contradict_the_record():
    data = json.loads((SARIF_DIR / "synthetic_cq_path.sarif").read_text())
    data["runs"][0]["versionControlProvenance"] = [{"repositoryUri": "https://example.org/git/app.git", "revisionId": "fedcba9876543210fedcba9876543210fedcba98"}]
    import hashlib, pathlib, tempfile
    with tempfile.TemporaryDirectory() as directory:
        target = pathlib.Path(directory) / "x.sarif"
        target.write_text(json.dumps(data))
        rec = load("synthetic_good_path.run.json")
        rec["outputs"][0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        outcome = evaluate(AnalysisArtifactInput(target, run=parse_analysis_run_data(rec)), subj=subject(source_content_hash=TREE), base=base("locus_only"))
    assert outcome.analysis[0].assessment.binding is BindingStatus.CONTRADICTED
    assert any("ARTIFACT_REVISION_MISMATCH_VS_RECORD" in r for r in outcome.analysis[0].assessment.binding_reasons)
    assert outcome.bind.state.value == "unknown"


# ---- invariants over every record fixture --------------------------------------------------------------------------------------------

def _every_record_on(artifact):
    for path in sorted(RUNS.glob("*.json")):
        if "invalid" in path.name:
            continue
        yield path.name, run(artifact, parse_analysis_run(path), base_name="locus_only")


def test_no_record_ever_confers_p2_p3_or_more_than_p1():
    for artifact in (PATH, NO_PATH):
        for name, outcome in _every_record_on(artifact):
            if isinstance(outcome, ReachOutcome) and outcome.prov_reach is not None:
                assert outcome.prov_reach.name in ("P0", "P1"), name


def test_an_unestablished_binding_never_improves_on_the_established_one():
    best = run(PATH, parse_analysis_run(RUNS / "synthetic_good_path.run.json"), base_name="locus_only")
    for name, outcome in _every_record_on(PATH):
        assert RANK[outcome.result.verdict] <= RANK[best.result.verdict] or isinstance(outcome, EvaluationRefusal), name
        if outcome.analysis[0].assessment.binding is not BindingStatus.ESTABLISHED:
            assert outcome.bind.state.value == "unknown" or not outcome.analysis[0].traces, name


def test_record_evaluation_is_deterministic_and_does_not_mutate_the_record():
    rec = parse_analysis_run(RUNS / "synthetic_good_no_path.run.json")
    before = copy.deepcopy(rec)
    first, second = run(NO_PATH, rec), run(NO_PATH, rec)
    assert rec == before and first.result == second.result and first.analysis == second.analysis and first.items == second.items


def test_unusable_records_are_refusals_not_silence():
    for name in ("synthetic_invalid_forbidden_field.run.json", "synthetic_invalid_truncated.run.json", "synthetic_invalid_hash_form.run.json"):
        outcome = evaluate(AnalysisArtifactInput(ANALYSIS_DIR / PATH, run=RUNS / name), subj=subject(source_content_hash=TREE), base=base("locus_only"))
        assert isinstance(outcome, EvaluationRefusal) and outcome.code is RefusalCode.ANALYSIS_ARTIFACT_INVALID and outcome.cause == "ANALYSIS_RUN_RECORD_INVALID"


def test_without_a_record_the_behaviour_of_the_previous_milestone_is_unchanged():
    for name in ("synthetic_path_bound.sarif", "synthetic_no_results.sarif", "synthetic_unresolvable_locations.sarif"):
        outcome = evaluate(SARIF_DIR / name, base=base("locus_only"))
        assert outcome.analysis[0].assessment.record_id is None and not outcome.analysis[0].assessment.negative_derived


def test_two_artifacts_one_unresolved_next_to_a_derived_absence_is_refused():
    """Artifact A yields a declared absence; artifact B has an unresolved relevant flow. Counting B as a path would contradict A."""
    from evidence.analysis_ingest import evaluate_with_analysis
    from tests.pipeline_support import equivalent, make_profile, vex_findings
    from evidence.stage1_records import Stage1Index
    record_doc = equivalent("cdx")
    outcome = evaluate_with_analysis(
        make_profile(record_doc.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record_doc]),
        [AnalysisArtifactInput(ANALYSIS_DIR / NO_PATH, run=RUNS / "synthetic_good_no_path.run.json"), SARIF_DIR / "synthetic_unresolvable_locations.sarif"],
        subject(source_content_hash=TREE), base())
    assert isinstance(outcome, EvaluationRefusal) and outcome.code is RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE


# ---- GraphML --------------------------------------------------------------------------------------------------------------------------

def test_graph_absence_needs_the_inventoried_entry_methods_to_exist_in_the_export():
    ok = run("joern-graphml/synthetic_rec_no_path.graphml", parse_analysis_run(RUNS / "synthetic_graph_no_path.run.json"),
             subj=subject(source_content_hash=TREE, target_source_root="node_modules/lib-b"))
    assert ok.reach.state is S.ABSENT and ok.analysis[0].assessment.negative_derived and ok.prov_reach.name == "P0"
    vacuous = run("joern-graphml/synthetic_rec_entry_not_in_export.graphml", parse_analysis_run(RUNS / "synthetic_graph_entry_not_in_export.run.json"),
                  subj=subject(source_content_hash=TREE, target_source_root="node_modules/lib-b"))
    assert vacuous.reach.state is S.UNKNOWN and not vacuous.analysis[0].assessment.negative_derived


def test_graph_root_in_the_export_must_agree_with_the_record():
    outcome = run("joern-graphml/synthetic_rec_no_path.graphml", parse_analysis_run(RUNS / "synthetic_graph_analysis_root_mismatch.run.json"),
                  subj=subject(source_content_hash=TREE, target_source_root="node_modules/lib-b"))
    assert outcome.analysis[0].assessment.binding is BindingStatus.CONTRADICTED and "ANALYSIS_ROOT_MISMATCH" in outcome.analysis[0].assessment.binding_reasons
