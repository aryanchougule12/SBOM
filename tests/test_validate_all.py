"""The unified validator is wired correctly (checked with stand-in commands; it never runs itself or the test suite recursively)."""

import io
import sys

from tests import validate_all


def test_the_mandatory_stages_are_exactly_the_documented_ones():
    commands = [" ".join(c[1:]) for _, c in validate_all.stages()]
    assert commands[0] == "-m pytest -q -rs"
    assert commands[1:5] == ["-m tests.conformance", "-m tests.analysis_eval --check", "-m tests.research_report --check", "-m tests.metamorphic --check"]
    assert commands[5].startswith("-m compileall -q evidence tests analysis_runner") and commands[6].startswith("-m pyflakes ")
    assert all(c[0] == sys.executable for _, c in validate_all.stages())      # the current interpreter


def test_every_failure_is_propagated_and_no_stage_is_skipped():
    plan = [("passes", [sys.executable, "-c", "pass"]), ("fails", [sys.executable, "-c", "raise SystemExit(3)"]), ("passes again", [sys.executable, "-c", "pass"])]
    out = io.StringIO()
    assert validate_all.run_stages(plan, out=out) == 1
    text = out.getvalue()
    assert "FAIL  exit 3" in text and "passes again" in text and "FAILED: fails" in text


def test_all_passing_is_exit_zero():
    out = io.StringIO()
    assert validate_all.run_stages([("ok", [sys.executable, "-c", "pass"])], out=out) == 0 and "ALL CHECKS PASSED" in out.getvalue()


def test_list_and_bad_arguments_do_not_run_anything(capsys):
    assert validate_all.main(["--list"]) == 0 and "tests.conformance" in capsys.readouterr().out
    assert validate_all.main(["--bogus"]) == 2


def test_a_missing_command_is_a_failure_not_a_silent_pass():
    try:
        code = validate_all.run_stages([("missing", ["/nonexistent/tool"])], out=io.StringIO())
    except FileNotFoundError:
        code = 1       # raising is also non-silent; the point is that it cannot be reported as a pass
    assert code == 1
