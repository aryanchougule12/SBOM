"""The authentic CodeQL 2.27.3 runs recorded by `python -m analysis_runner` (fixtures/analysis/authentic/codeql/recorded).

Each SARIF is unedited CodeQL output and each record is the runner's own output for that run (see REPRODUCE.md there). These
tests check the pairs through the real parser, binding and evaluator; the validation of the *wrapper* is test_analysis_runner.py
(a fake executable) - the two are different things."""

import hashlib
import subprocess

import pytest

from analysis_runner import verify_record
from evidence.analysis_ingest import AnalysisArtifactInput, parse_analysis_artifact
from evidence.analysis_model import BindingStatus
from evidence.analysis_run import Origin, StageRole, StageStatus, parse_analysis_run
from model import EvidenceState as S
from reports.verdict import Verdict
from tests.analysis_eval import ANALYSIS_DIR, ANALYSIS_DIR as ROOT
from tests.analysis_support import evaluate, subject

RECORDED = ANALYSIS_DIR / "authentic" / "codeql" / "recorded"
NAMES = ("flow-via-vendor-lib", "no-results", "flow-app-only")
REVISION = "941e384b4a75820cb0f11fe879f2d9ce1384a626"
REPO = "https://github.com/aryanchougule12/SBOM.git"
TREES = {"flow-via-vendor-lib": "0114c001fcd79f7e7dbb0bc791766d5c5a971a53", "no-results": "0114c001fcd79f7e7dbb0bc791766d5c5a971a53",
         "flow-app-only": "428b3b9cc1821dd900c5cf52f049c5b7677d200b"}
SUBPATH = {"flow-via-vendor-lib": "project", "no-results": "project", "flow-app-only": "project-app-only"}


def pair(name):
    return RECORDED / f"codeql-2.27.3__recorded__{name}.sarif", RECORDED / f"codeql-2.27.3__recorded__{name}.run.json"


def subj(name, **changes):
    values = dict(source_repository=REPO, source_revision=REVISION, source_content_hash="git-tree:" + TREES[name], target_source_root="vendor/lib-b")
    values.update(changes)
    return subject(**values)


@pytest.mark.parametrize("name", NAMES)
def test_the_record_is_the_runners_and_describes_exactly_this_file(name):
    sarif, run = pair(name)
    record = parse_analysis_run(run)
    assert record.origin is Origin.RUNNER and verify_record(record, [sarif]) == []
    assert record.tool.name == "CodeQL" and record.tool.version == "2.27.3" and record.source.revision == REVISION and len(record.source.revision) == 40
    assert record.source.worktree_clean is True and record.source.untracked_files == 0 and record.source.changed_during_run is False and record.source.submodules == ()
    assert record.source.tree_digest == "git-tree:" + TREES[name] and record.source.repository == REPO
    assert [(s.role, s.status, s.exit_code) for s in record.stages] == [(StageRole.EXTRACTION, StageStatus.COMPLETED, 0), (StageRole.ANALYSIS, StageStatus.COMPLETED, 0)]
    assert record.outputs[0].sha256 == hashlib.sha256(sarif.read_bytes()).hexdigest()
    assert record.query.claim_semantics == "taint_path_query"   # a stock taint query, and the plan says so
    assert record.coverage_claim is None and record.entry_inventory.complete is None    # nothing about coverage is claimed
    assert dict(record.field_sources)["configuration"].value == "caller_supplied" and record.source_of("stages").value == "observed_by_runner"


@pytest.mark.parametrize("name", NAMES)
def test_the_commit_and_tree_digest_can_be_reproduced_from_git(name):
    record = parse_analysis_run(pair(name)[1])
    try:
        tree = subprocess.run(["git", "-C", str(ROOT), "rev-parse", f"{record.source.revision}:fixtures/analysis/authentic/codeql/{SUBPATH[name]}"],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git is not available")
    if tree.returncode != 0:
        pytest.skip("the analysed commit is not available in this clone (shallow history); the digest was recorded by the runner")
    assert "git-tree:" + tree.stdout.strip() == record.source.tree_digest


def test_the_artifact_states_its_own_scope_and_query_identity():
    run = parse_analysis_artifact(pair("flow-via-vendor-lib")[0]).runs[0]
    assert run.extracted_files == ("src/app.js", "vendor/lib-b/src/parse.js") and run.extracted_files_unresolved == 0
    assert ("codeql/javascript-queries", "2.4.8+a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c") in run.query_packs
    assert run.rule_ids == ("js/command-line-injection",) and run.suppressed_results == 0 and run.execution_successful is True


def test_live_run_with_exact_revision_binds_where_the_log_alone_cannot():
    sarif, run = pair("flow-via-vendor-lib")
    alone = evaluate(sarif, subj=subj("flow-via-vendor-lib"))
    bound = evaluate(AnalysisArtifactInput(sarif, run=run), subj=subj("flow-via-vendor-lib"))
    assert alone.bind.state.value == "unknown" and alone.prov_reach.name == "P0" and "R6" in alone.evaluation.rule_ids      # M4: a CodeQL log carries no revision
    assert bound.reach.state is S.PRESENT and bound.result.verdict is Verdict.INSUFFICIENT and bound.bind.state.value == "matched"
    assert "R6" not in bound.evaluation.rule_ids and bound.prov_reach.name == "P1"       # never P2/P3 from a record
    assessment = bound.analysis[0].assessment
    assert assessment.binding is BindingStatus.ESTABLISHED and assessment.source_identity == "exact" and not assessment.negative_derived
    facts = dict(assessment.coverage)
    assert facts["locus_included"] == "established" and facts["query_suite_completed"] == "established" and facts["claim_semantics"] == "not_established"
    assert {"entry_points_enumerated", "coverage_claim_declared"} <= set(assessment.preventing)


def test_a_successful_live_run_with_no_results_is_not_an_absence():
    sarif, run = pair("no-results")
    outcome = evaluate(AnalysisArtifactInput(sarif, run=run), subj=subj("no-results"))
    assert outcome.reach.state is S.UNKNOWN and outcome.analysis[0].assessment.execution == "completed" and not outcome.analysis[0].assessment.negative_derived


def test_the_record_of_another_run_is_not_reusable():
    outcome = evaluate(AnalysisArtifactInput(pair("no-results")[0], run=pair("flow-via-vendor-lib")[1]), subj=subj("no-results"))
    assert outcome.analysis[0].assessment.binding is BindingStatus.CONTRADICTED
    assert "RUN_OUTPUT_HASH_MISMATCH" in outcome.analysis[0].assessment.binding_reasons


def test_another_assessed_revision_leaves_the_live_path_unbound():
    sarif, run = pair("flow-via-vendor-lib")
    outcome = evaluate(AnalysisArtifactInput(sarif, run=run), subj=subj("flow-via-vendor-lib", source_revision="0123456789abcdef0123456789abcdef01234567"))
    assert outcome.reach.state is S.PRESENT and outcome.bind.state.value == "unknown" and "R6" in outcome.evaluation.rule_ids
