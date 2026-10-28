"""Tests for the rule-conformance harness (tests/conformance.py): it runs under pytest, so there is one
way of evaluating verdicts, and the harness itself is checked for the gaps it is supposed to find."""

import dataclasses
import json

import pytest

from tests import conformance
from tests.conformance import Case, PREDICATES, build_report, main, render, run_case


@pytest.fixture(scope="module")
def report():
    return build_report()


def test_every_normative_rule_and_rule_test_of_both_predicates_is_exercised(report):
    assert report["ok"], render(report)
    for key, predicate in report["predicates"].items():
        assert predicate["failed_cases"] == [] and predicate["missing_rules"] == [] and predicate["missing_tests"] == [], key
    reach = report["predicates"]["reach"]
    assert sorted(reach["rules"], key=lambda r: int(r[1:])) == [f"R{n}" for n in range(1, 14)]
    assert sorted(reach["tests"], key=lambda r: int(r[2:])) == [f"RT{n}" for n in range(1, 14)]
    cnp = report["predicates"]["cnp"]
    assert len(cnp["rules"]) == 17 and len(cnp["tests"]) == 25


def test_the_report_is_deterministic_and_json_serialisable(report):
    assert json.dumps(report, sort_keys=True) == json.dumps(build_report(), sort_keys=True)
    assert render(report) == render(build_report())


def test_the_report_labels_everything_synthetic_and_makes_no_accuracy_claim(report):
    assert report["synthetic_only"] is True and "no claim about real-world accuracy" in report["disclaimer"]
    assert all(case.synthetic for spec in PREDICATES.values() for case in spec["cases"])
    assert "SYNTHETIC" in render(report) and all(r["synthetic"] for p in report["predicates"].values() for r in p["results"])


def test_both_sbom_formats_are_covered_for_every_reachability_rule_test(report):
    reach = report["predicates"]["reach"]["tests"]
    for test, status in reach.items():
        layers = {c.split("/")[1] for c in status["cases"]}
        # RT12-RT13 (addendum v0.2.3) state dimension combinations the pipeline cannot derive from documents
        expected = {"engine"} if test in ("RT12", "RT13") else {"engine", "pipeline-cdx", "pipeline-spdx"}
        assert layers >= expected, test


def test_a_rule_counts_only_if_it_was_observed_to_trigger(monkeypatch):
    """A case that declares RT3 but triggers nothing neither covers RT3 nor exercises R11."""
    lying = Case("RT3/lie", "reach", "engine", ("RT3",), conformance.SUPPORTED, (), PREDICATES["reach"]["cases"][0].run)
    spec = dict(PREDICATES["reach"], cases=tuple(c for c in PREDICATES["reach"]["cases"]
                                                if c.case_id not in ("RT3/engine", "RT3/pipeline-cdx", "RT3/pipeline-spdx")
                                                and "R11" not in c.expected_rules) + (lying,))
    monkeypatch.setitem(PREDICATES, "reach", spec)
    report = build_report()
    assert "R11" in report["predicates"]["reach"]["missing_rules"]
    assert report["ok"] is False


def test_missing_mappings_and_wrong_expectations_are_reported(monkeypatch):
    cases = list(PREDICATES["reach"]["cases"])
    wrong = dataclasses.replace(next(c for c in cases if c.case_id == "RT8/engine"), expected_verdict=conformance.SUPPORTED)
    kept = [wrong if c.case_id == "RT8/engine" else c for c in cases if not c.case_id.startswith("RT5/")]
    monkeypatch.setitem(PREDICATES, "reach", dict(PREDICATES["reach"], cases=tuple(kept)))
    report = build_report()["predicates"]["reach"]
    assert "RT8/engine" in report["failed_cases"]
    assert "RT5" in report["missing_tests"]
    assert not report["tests"]["RT8"]["covered"]  # one of its cases failed


def test_a_crashing_case_is_a_failed_case_not_a_crashed_harness():
    def boom():
        raise RuntimeError("synthetic failure")
    result = run_case(Case("x", "reach", "engine", (), conformance.SUPPORTED, (), boom))
    assert result["ok"] is False and "synthetic failure" in result["error"]


def test_the_command_line_entry_point_exit_status(capsys, monkeypatch):
    assert main([]) == 0 and "result: OK" in capsys.readouterr().out
    assert json.loads((main(["--json"]), capsys.readouterr().out)[1])["ok"] is True
    spec = dict(PREDICATES["reach"], cases=tuple(c for c in PREDICATES["reach"]["cases"] if "R4" not in c.expected_rules))
    monkeypatch.setitem(PREDICATES, "reach", spec)
    assert main([]) == 1 and "missing: R4" in capsys.readouterr().out
