"""Smoke and integration tests of the supported end-to-end workflow, through the real entry points (separate processes).

Uses only committed fixtures/examples and a throw-away git repository with a fake analyzer; no CodeQL/Joern is needed."""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
QUICK = ROOT / "examples" / "quickstart"
SBOM, VEX = "fixtures/equivalent/app.cdx.json", "fixtures/openvex/reachability_equivalent.json"
SARIF_PATH = "fixtures/analysis/sarif/synthetic_cq_path.sarif"
RUN_PATH = "fixtures/analysis/runs/synthetic_good_path.run.json"
GOOD = ["evaluate", "--sbom", SBOM, "--vex", VEX, "--profile", "examples/quickstart/profile.json", "--reachability", "examples/quickstart/reachability.json",
        "--subject", "examples/quickstart/subject.json"]


def cli(*args, module="evidence"):
    done = subprocess.run([sys.executable, "-m", module, *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
    return done


def test_help_lists_the_commands():
    assert cli("--help").returncode == 0 and "evaluate" in cli("--help").stdout
    assert cli("evaluate", "--help").returncode == 0 and "--artifact" in cli("evaluate", "--help").stdout
    runner = cli("--help", module="analysis_runner")
    assert runner.returncode == 0 and "run PLAN.json" in runner.stdout and "check RUN.json" in runner.stdout


def test_valid_end_to_end_run_with_artifact_and_record_is_stable_json(tmp_path):
    first = cli(*GOOD, "--artifact", f"{SARIF_PATH}::{RUN_PATH}")
    second = cli(*GOOD, "--artifact", f"{SARIF_PATH}::{RUN_PATH}")
    assert first.returncode == 0 and first.stdout == second.stdout and first.stderr == ""
    data = json.loads(first.stdout)
    summary = data["summary"]
    assert summary["outcome"] == "evaluated" and summary["verdict"] == "Insufficient" and "CLAIM_CONTRADICTED_BY_PATH" in summary["codes"]
    assert summary["dimension_states"]["REACH"] == "Present" and summary["dimension_states"]["BIND"] == "matched"
    assert data["evaluation"]["analysis"] and not summary["limitations"] == []
    out = tmp_path / "result.json"
    written = cli(*GOOD, "--artifact", f"{SARIF_PATH}::{RUN_PATH}", "--out", str(out))
    assert written.returncode == 0 and "wrote" in written.stdout and out.read_text() == first.stdout


def test_cnp_workflow_without_artifacts_uses_the_same_entry_point():
    done = cli("evaluate", "--sbom", SBOM, "--vex", "fixtures/openvex/component_not_present.json", "--profile", "examples/quickstart/profile.json")
    assert done.returncode in (0, 1)       # a verdict or a structured refusal, never a crash
    assert json.loads(done.stdout)["summary"]["outcome"] in ("evaluated", "refused") and "Traceback" not in done.stderr


def test_a_structurally_invalid_artifact_is_a_refusal_with_exit_1_and_no_verdict():
    done = cli(*GOOD, "--artifact", "fixtures/analysis/sarif/synthetic_invalid_truncated.sarif")
    assert done.returncode == 1
    summary = json.loads(done.stdout)["summary"]
    assert summary["outcome"] == "refused" and "verdict" not in summary and summary["code"] == "EVAL_ANALYSIS_ARTIFACT_INVALID"


def test_an_unusable_run_record_is_a_refusal_not_silence():
    done = cli(*GOOD, "--artifact", f"{SARIF_PATH}::fixtures/analysis/runs/synthetic_invalid_forbidden_field.run.json")
    assert done.returncode == 1 and json.loads(done.stdout)["summary"]["cause"] == "ANALYSIS_RUN_RECORD_INVALID"


@pytest.mark.parametrize("argument,value", [("--sbom", "does-not-exist.json"), ("--vex", "fixtures/openvex/malformed.json"),
                                            ("--profile", "fixtures/openvex/malformed.json"), ("--reachability", "fixtures/openvex/malformed.json")])
def test_unreadable_or_invalid_inputs_exit_2_with_a_message_and_no_traceback(argument, value):
    args = list(GOOD)
    args[args.index(argument) + 1] = value
    done = cli(*args)
    assert done.returncode == 2 and done.stderr.startswith("error:") and "Traceback" not in done.stderr and done.stdout == ""


def test_argument_errors_exit_2():
    assert cli("evaluate").returncode == 2 and cli().returncode == 2 and cli("bogus").returncode == 2
    assert cli(*GOOD[:-2], "--artifact", SARIF_PATH).returncode == 2        # artifact without subject


# ---- the recorder feeding the evaluator ------------------------------------------------------------------------------------------------

FAKE = textwrap.dedent('''
    import pathlib, shutil, sys
    mode, source, out = sys.argv[1:4]
    if mode == "fail":
        sys.exit(3)
    shutil.copy(source, out)
''')


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.js").write_text("1\n")
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.org", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.org", "HOME": str(tmp_path)}
    for command in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "i"]):
        subprocess.run(["git", "-C", str(repo), *command], check=True, capture_output=True, env=env)
    (tmp_path / "tool.py").write_text(FAKE)
    return repo


def _plan(tmp_path, repo, mode, artifact):
    out = tmp_path / "out.sarif"
    plan = {"run_id": "e2e", "repository": "https://example.org/git/app.git", "repo_dir": str(repo),
            "tool": {"name": "CodeQL", "version_command": [sys.executable, "-c", "print('2.15.5')"]},
            "languages": ["javascript"], "stages": [{"name": "analyze", "role": "analysis", "argv": [sys.executable, str(tmp_path / "tool.py"), mode, str(ROOT / artifact), str(out)]}],
            "outputs": [str(out)], "target": {"purl": "pkg:npm/lib-b@2.0", "source_root": "node_modules/lib-b"}}
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    return out


def test_recorder_then_evaluator_end_to_end_and_a_failed_stage_is_never_a_successful_analysis(tmp_path):
    repo = _repo(tmp_path)
    # a successful recorded run of a no-path artifact
    out = _plan(tmp_path, repo, "ok", "fixtures/analysis/sarif/synthetic_cq_no_path.sarif")
    record = tmp_path / "ok.run.json"
    done = cli("run", str(tmp_path / "plan.json"), "--out", str(record), module="analysis_runner")
    assert done.returncode == 0 and cli("check", str(record), str(out), module="analysis_runner").returncode == 0
    # the record's revision is the temp repo's, so the binding to the example subject is contradicted: nothing is trusted, nothing is promoted
    result = json.loads(cli(*GOOD, "--artifact", f"{out}::{record}").stdout)["summary"]
    assert result["verdict"] == "Insufficient" and result["dimension_states"]["REACH"] == "Unknown"
    # a failed stage: exit status 1 from the recorder, the record says failed, and the evaluation reports no successful analysis
    _plan(tmp_path, repo, "fail", "fixtures/analysis/sarif/synthetic_cq_no_path.sarif")
    failed = tmp_path / "failed.run.json"
    done = cli("run", str(tmp_path / "plan.json"), "--out", str(failed), module="analysis_runner")
    assert done.returncode == 1 and "INCOMPLETE" in done.stdout
    recorded = json.loads(failed.read_text())
    assert recorded["stages"][0]["status"] == "failed"
    # the output of the earlier successful run is still on disk: the failed run must not be able to pass it off as its own
    assert any(p.startswith("OUTPUT_NOT_REWRITTEN") for p in recorded["scope"]["partial_indicators"]) and "STAGE_NOT_COMPLETED" in recorded["scope"]["partial_indicators"]
    assert cli("check", str(failed), str(out), module="analysis_runner").returncode == 1
    result = json.loads(cli(*GOOD, "--artifact", f"{ROOT / 'fixtures/analysis/sarif/synthetic_cq_no_path.sarif'}::{failed}").stdout)
    assert result["summary"]["verdict"] == "Insufficient"
    assessment = result["evaluation"]["analysis"][0]["assessment"]
    assert assessment["execution"] == "failed" and assessment["negative_derived"] is False
