"""Tests of the reproducible analysis-run recorder (analysis_runner) with a fake executable and a throw-away git repository.

The fake tool is a few lines of Python written by the test; nothing here runs CodeQL or Joern (see tests/test_analysis_live.py for
the authentic CodeQL record)."""

import json
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from analysis_runner import PlanError, load_plan, redact_argv, run_plan, verify_record
from analysis_runner.cli import main
from analysis_runner.runner import tree_fingerprint
from evidence.analysis_run import dump_analysis_run, parse_analysis_run, parse_analysis_run_data, record_to_dict

FAKE = textwrap.dedent('''
    import sys, time, pathlib
    mode, out = sys.argv[1], sys.argv[2]
    if mode == "ok":
        pathlib.Path(out).write_text('{"version": "2.1.0", "runs": []}')
    elif mode == "fail":
        sys.exit(3)
    elif mode == "sleep":
        time.sleep(30)
    elif mode == "nooutput":
        pass
    elif mode == "touch-source":
        pathlib.Path(sys.argv[3]).write_text("changed during the run\\n")
        pathlib.Path(out).write_text("{}")
''')


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"PATH": "/usr/bin:/bin:/usr/local/bin", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org", "HOME": str(repo)})


@pytest.fixture()
def project(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.js").write_text("console.log(1)\n")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    tool = tmp_path / "fake_tool.py"
    tool.write_text(FAKE)
    return repo, tool, tmp_path


def make_plan(project, mode="ok", *, stages=None, out_name="out.sarif", timeout=20, extra=None):
    repo, tool, tmp = project
    out = tmp / out_name
    data = {
        "run_id": "run-1", "repository": "https://example.org/git/app.git", "repo_dir": str(repo),
        "tool": {"name": "FakeTool", "version_command": [sys.executable, "-c", "print('1.2.3')"], "output_format_version": "sarif-latest"},
        "languages": ["javascript"], "query": {"pack": "fake/queries", "pack_version": "1.0.0", "query_ids": ["fake/q1"]},
        "stages": stages or [{"name": "extract", "role": "extraction", "argv": [sys.executable, str(tool), "ok", str(tmp / "db.marker")], "timeout_s": timeout},
                             {"name": "analyze", "role": "analysis", "argv": [sys.executable, str(tool), mode, str(out)], "timeout_s": timeout}],
        "outputs": [str(out)],
        "target": {"purl": "pkg:npm/lib-b@2.0", "source_root": "src"},
        **(extra or {}),
    }
    plan_file = tmp / "plan.json"
    plan_file.write_text(json.dumps(data))
    return load_plan(plan_file), out


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def test_a_successful_run_records_identity_status_and_the_output_hash(project):
    plan, out = make_plan(project)
    record = run_plan(plan, clock=Clock())
    head = subprocess.run(["git", "-C", str(project[0]), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(project[0]), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True).stdout.strip()
    assert record.origin.value == "runner" and record.tool.version == "1.2.3"
    assert record.source.revision == head and record.source.tree_digest == f"git-tree:{tree}"
    assert record.source.worktree_clean is True and record.source.untracked_files == 0 and record.source.changed_during_run is False
    assert record.source.submodules == ()
    assert [s.status.value for s in record.stages] == ["completed", "completed"] and all(s.exit_code == 0 for s in record.stages)
    assert record.outputs[0].sha256 is not None and verify_record(record, [out]) == []
    assert record.partial_indicators == () and not [d for d in record.diagnostics if d.level == "error"]
    # what the plan merely supplied is labelled as such
    assert dict(record.field_sources)["configuration"].value == "caller_supplied" and dict(record.field_sources)["target"].value == "caller_supplied"


def test_the_record_is_deterministic_for_equal_inputs_and_round_trips(project):
    plan, _ = make_plan(project)
    first, second = dump_analysis_run(run_plan(plan, clock=Clock())), dump_analysis_run(run_plan(plan, clock=Clock()))
    assert first == second
    assert dump_analysis_run(parse_analysis_run_data(json.loads(first))) == first
    assert parse_analysis_run_data(record_to_dict(parse_analysis_run_data(json.loads(first)))) == parse_analysis_run_data(json.loads(first))


def test_a_failing_stage_is_recorded_and_the_later_stage_is_not_run(project):
    plan = load_plan_with_stage_order(project, ["fail", "ok"])
    record = run_plan(plan, clock=Clock())
    assert [(s.name, s.status.value, s.exit_code) for s in record.stages] == [("first", "failed", 3), ("second", "not_run", None)]
    assert "STAGE_NOT_COMPLETED" in record.partial_indicators and any(d.code == "STAGE_FAILED" for d in record.diagnostics)


def load_plan_with_stage_order(project, modes):
    repo, tool, tmp = project
    stages = [{"name": name, "role": "other", "argv": [sys.executable, str(tool), mode, str(tmp / f"{name}.out")], "timeout_s": 20}
              for name, mode in zip(["first", "second"], modes)]
    plan, _ = make_plan(project, stages=stages)
    return plan


def test_a_timeout_is_recorded_as_such(project):
    repo, tool, tmp = project
    plan, _ = make_plan(project, stages=[{"name": "slow", "role": "analysis", "argv": [sys.executable, str(tool), "sleep", str(tmp / "x")], "timeout_s": 0.5}])
    record = run_plan(plan, clock=Clock())
    assert record.stages[0].status.value == "timed_out" and record.stages[0].exit_code is None
    assert any(d.code == "STAGE_TIMED_OUT" for d in record.diagnostics)


def test_a_missing_output_is_not_a_hash_and_marks_the_run_partial(project):
    plan, out = make_plan(project, "nooutput")
    record = run_plan(plan, clock=Clock())
    assert record.outputs[0].sha256 is None and any(p.startswith("OUTPUT_MISSING") for p in record.partial_indicators)
    assert record.stages[-1].status.value == "completed"   # process success is not proof that anything was produced


def test_a_missing_executable_is_a_failed_stage(project):
    plan, _ = make_plan(project, stages=[{"name": "x", "role": "analysis", "argv": ["/nonexistent/analyzer", "run"], "timeout_s": 5}])
    assert run_plan(plan, clock=Clock()).stages[0].status.value == "failed"


def test_a_source_change_during_the_run_is_detected(project):
    repo, tool, tmp = project
    plan, _ = make_plan(project, stages=[{"name": "analyze", "role": "analysis",
                                          "argv": [sys.executable, str(tool), "touch-source", str(tmp / "o.sarif"), str(repo / "src" / "a.js")], "timeout_s": 20}],
                        extra={"outputs": [str(tmp / "o.sarif")]})
    record = run_plan(plan, clock=Clock())
    assert record.source.changed_during_run is True and any(d.code == "SOURCE_CHANGED_DURING_RUN" for d in record.diagnostics)
    assert record.source.worktree_clean is True   # it was clean when the run started: the change happened during it


def test_a_dirty_or_untracked_tree_is_recorded_and_identified_by_content(project):
    repo, _, _ = project
    (repo / "src" / "a.js").write_text("console.log(2)\n")
    (repo / "src" / "new.js").write_text("x\n")
    plan, _ = make_plan(project)
    record = run_plan(plan, clock=Clock())
    assert record.source.worktree_clean is False and record.source.untracked_files == 1
    assert record.source.tree_digest.startswith("sha256-worktree:") and record.source.changed_during_run is False


def test_ignored_files_count_as_files_absent_from_the_commit(project):
    repo, _, _ = project
    (repo / ".gitignore").write_text("vendor/\n")
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "ignore")
    (repo / "vendor").mkdir()
    (repo / "vendor" / "lib.js").write_text("y\n")
    plan, _ = make_plan(project)
    assert run_plan(plan, clock=Clock()).source.untracked_files == 1


def test_the_analysed_project_is_not_modified_by_the_recorder(project):
    repo, _, _ = project
    before = tree_fingerprint(repo)
    plan, _ = make_plan(project)
    run_plan(plan, clock=Clock())
    assert tree_fingerprint(repo) == before


def test_credentials_are_redacted_and_no_environment_is_recorded(project, monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_ENV", "hunter2-env-value")
    repo, tool, tmp = project
    argv = [sys.executable, str(tool), "ok", str(tmp / "o"), "--token", "tok-123", "API_KEY=abc", "https://user:pw@example.org/x"]
    plan, _ = make_plan(project, stages=[{"name": "a", "role": "analysis", "argv": argv, "timeout_s": 20}], extra={"outputs": [str(tmp / "o")]})
    text = dump_analysis_run(run_plan(plan, clock=Clock()))
    for secret in ("tok-123", "abc\"", "pw@", "hunter2-env-value", "user:pw"):
        assert secret not in text
    assert "<redacted>" in text


@pytest.mark.parametrize("argv,expected", [
    (["tool", "--api-key", "k"], ["tool", "--api-key", "<redacted>"]),
    (["tool", "--password=abc"], ["tool", "--password=<redacted>"]),
    (["tool", "plain", "--language=javascript"], ["tool", "plain", "--language=javascript"]),
    (["git", "clone", "https://x:y@host/r.git"], ["git", "clone", "https://<redacted>@host/r.git"]),
])
def test_redact_argv(argv, expected):
    assert redact_argv(argv) == expected


def test_the_loader_refuses_a_record_with_an_unredacted_credential():
    base = {"schema": "analysis-run/1", "run_id": "r", "origin": "caller", "tool": {"name": "t"}, "configuration": {"command": ["tool", "--token=abc123"]}}
    from evidence.analysis_run import AnalysisRunError
    with pytest.raises(AnalysisRunError) as error:
        parse_analysis_run_data(base)
    assert error.value.code.value == "ANALYSIS_RUN_SECRET_IN_COMMAND"


def test_cli_exit_codes_and_check(project, tmp_path, capsys):
    plan, out = make_plan(project)
    plan_file = project[2] / "plan.json"
    record_file = tmp_path / "run.json"
    assert main(["run", str(plan_file), "--out", str(record_file)]) == 0
    record = parse_analysis_run(record_file)
    assert main(["check", str(record_file), str(out)]) == 0
    out.write_text("tampered")
    assert main(["check", str(record_file), str(out)]) == 1 and "matches no output" in capsys.readouterr().out
    bad_plan = tmp_path / "bad.json"
    bad_plan.write_text("{}")
    assert main(["run", str(bad_plan), "--out", str(record_file)]) == 2
    assert main([]) == 2 and main(["bogus"]) == 2
    failing, _ = make_plan(project, "fail")
    assert main(["run", str(project[2] / "plan.json"), "--out", str(tmp_path / "f.json")]) == 1
    assert record.run_id == "run-1"


def test_an_unknown_plan_field_is_an_error(tmp_path):
    plan = tmp_path / "p.json"
    plan.write_text(json.dumps({"verdict": "Supported"}))
    with pytest.raises(PlanError):
        load_plan(plan)
