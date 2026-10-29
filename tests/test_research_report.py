"""The research report is current, deterministic and its aggregates have sound denominators."""

import pytest

from tests.research_report import OUT, build, render_json, render_markdown


@pytest.fixture(scope="module")
def report():
    return build()


def test_the_committed_report_is_current_and_deterministic(report):
    assert render_json(report) == (OUT / "research_report.json").read_text(encoding="utf-8")
    assert render_markdown(report) == (OUT / "research_report.md").read_text(encoding="utf-8")
    assert render_json(build()) == render_json(report)


def test_denominators_and_single_counting(report):
    assert sum(c["cases"] for c in report["categories"].values()) == report["corpus"]["cases"]
    for category in report["categories"].values():
        assert category["evaluated"] + category["refused"] == category["cases"]
        assert sum(category["inconclusive"]["one_primary_reason_per_case"].values()) == category["inconclusive"]["count"]
        assert sum(category["by_format"].values()) == category["cases_with_an_artifact"]
        assert category["expected_vs_actual"]["agree"] + category["expected_vs_actual"]["disagree"] == category["cases"]
        runs = category["analysis_run_records"]
        for counts in runs["coverage_facts_per_fact"].values():
            assert sum(counts.values()) == runs["denominator_for_facts"]
        assert runs["negative_k1_derived"]["count"] == len(runs["negative_k1_derived"]["case_ids"])
        assert category["supported_verdicts"]["count"] == category["supported_verdicts"]["resting_on_a_caller_supplied_verified_k1_report"]


def test_weakening_never_beats_both_the_original_and_the_no_record_verdict(report):
    w = report["weakening_analysis"]
    assert w["raised_pairs"] == [] and w["pairs"] == w["cases"] * len(w["weakenings"]) == sum(w["results"].values())


def test_no_accuracy_metric_is_reported(report):
    text = (render_json(report) + render_markdown(report)).lower().replace("no accuracy, precision, recall or false-positive/false-negative rate", "")
    for word in ("precision", "recall", "false_positive", "false positive"):
        assert word not in text
