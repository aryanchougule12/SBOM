"""Checkpoint 4: the campaign report is deterministic, current, correctly counted, and fails loudly on a violation."""

import pytest

from tests.metamorphic import report as R
from tests.metamorphic.scenarios import all_scenarios


@pytest.fixture(scope="module")
def built():
    return R.build()


def test_the_committed_report_is_current_and_deterministic(built):
    out = R.DEFAULT_OUT
    assert R.render_json(built) == (out / R.JSON_NAME).read_text(encoding="utf-8")
    assert R.render_markdown(built) == (out / R.MD_NAME).read_text(encoding="utf-8")
    assert R.render_json(R.build()) == R.render_json(built)


def test_denominators(built):
    pairs, relations = built["pairs"], built["relations"]
    assert sum(pairs["by_kind"].values()) == pairs["count"]
    assert built["scenarios"]["count"] == len(all_scenarios()) == sum(built["scenarios"]["by_predicate"].values()) == sum(built["scenarios"]["by_format"].values())
    assert sum(row["pairs"] for row in built["operator_table"].values()) == pairs["count"]
    bases = built["scenarios"]["count"]
    assert relations["M-3"]["checked"] == relations["M-5"]["checked"] == pairs["count"] + bases
    assert relations["M-1"]["checked"] == pairs["by_kind"]["degrade"] + pairs["by_kind"]["delete"]
    assert relations["M-2"]["checked"] == pairs["by_kind"]["delete"] and relations["M-4"]["checked"] == pairs["by_kind"]["inject_positive"]
    assert relations["M-6"]["checked"] == pairs["by_kind"]["neutral"]
    for stats in relations.values():
        assert stats["held"] + stats.get("violated", 0) == stats["checked"]
    assert sum(sum(row["transitions"].values()) for row in built["operator_table"].values()) == pairs["count"]


def test_the_campaign_found_no_violation_and_the_neutral_relation_is_never_exercised_by_a_change(built):
    assert built["violations"] == []
    assert built["relations"]["M-6"]["exercised"] == 0 and built["relations"]["M-4"]["exercised"] == built["relations"]["M-4"]["checked"]


def test_the_report_makes_no_accuracy_claim(built):
    text = (R.render_json(built) + R.render_markdown(built)).lower()
    for word in ("precision", "recall", "false positive", "false_positive", "f1"):
        assert word not in text
    assert "not an accuracy measurement" in text


def test_a_violated_relation_is_reported_and_fails_the_check(monkeypatch, tmp_path):
    """The harness must be able to fail: rig the engine so that deleting the dependency graph of the Weak scenario yields Supported."""
    from tests.metamorphic import campaign, core
    real = core.observe

    def rigged(scenario):
        observation = real(scenario)
        if scenario.scenario_id == "cnp-cdx-unverified" and "dependencies" not in scenario.sbom:
            return core.Observation("evaluated", "Supported", (), "", dimension_states=observation.dimension_states, item_states=observation.item_states)
        return observation

    monkeypatch.setattr(campaign, "observe", rigged)
    built = R.build()
    assert built["violations"] == [{"scenario": "cnp-cdx-unverified", "operator": "D-DEP-ALL", "relations": ["M-1"]}]
    (tmp_path / R.JSON_NAME).write_text(R.render_json(built))
    (tmp_path / R.MD_NAME).write_text(R.render_markdown(built))
    assert R.main(["--check", "--out", str(tmp_path)]) == 1      # the files are current, but a relation is violated: non-zero


def test_check_detects_a_stale_file(tmp_path, built):
    (tmp_path / R.JSON_NAME).write_text(R.render_json(built))
    (tmp_path / R.MD_NAME).write_text("stale\n")
    assert R.main(["--check", "--out", str(tmp_path)]) == 1
    assert R.main(["--check", "--out", str(tmp_path / "missing")]) == 1


def test_the_mr5_candidate_has_reproducible_counterexamples_and_is_not_counted_as_a_violation(built):
    candidate = next(iter(built["candidate_properties"].values()))
    assert candidate["status"] == "not universally valid" and candidate["pairs"] == 6 and candidate["held"] == 2 and candidate["counterexamples"] == 4
    assert all("Supported -> Weak" in c and "ANALYSIS_PROVENANCE_BELOW_P3" in c for c in candidate["counterexample_cases"])
    assert built["violations"] == []
