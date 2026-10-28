"""Tests for the analyzer-artifact evaluation harness (tests/analysis_eval.py) and the corpus it evaluates."""

import copy
import csv
import io

import pytest

from tests import analysis_eval, conformance
from tests.analysis_eval import ANALYSIS_DIR, DEFAULT_OUT, build_report, check_fixture, compare, main, render_csv, render_json, run_case


@pytest.fixture(scope="module")
def report():
    return build_report()


@pytest.fixture(scope="module")
def manifest():
    return analysis_eval.load_manifest()


def test_every_case_agrees_with_its_reviewed_expectation_and_every_attribution_checks(report):
    assert report["totals"]["disagree"] == 0 and report["totals"]["fixture_problems"] == 0, analysis_eval.render_summary(report)
    assert report["totals"]["cases"] == len(analysis_eval.load_manifest()["cases"]) >= 100


def test_the_report_keeps_upstream_and_synthetic_results_apart_and_reports_no_accuracy_metric(report):
    assert set(report["categories"]) == {"A", "B", "L"}
    assert report["categories"]["A"]["label"].startswith("upstream") and report["categories"]["B"]["label"].startswith("synthetic")
    assert report["categories"]["L"]["label"].startswith("authentic CodeQL")
    assert "0 artifacts" in report["not_obtained"]["authentic_joern"]
    assert report["kind"] == "controlled-conformance-results" and "No accuracy" in report["disclaimer"]
    assert {r["category"] for r in report["cases"] if r["id"].startswith("A")} == {"A"}
    forbidden = {"accuracy", "precision", "recall", "f1", "false_positive_rate", "score"}
    def keys(node):
        if isinstance(node, dict):
            for k, v in node.items():
                yield k.lower()
                yield from keys(v)
        elif isinstance(node, list):
            for v in node:
                yield from keys(v)
    assert not forbidden & set(keys(report))


def test_formats_artifacts_refusals_and_distributions_are_reported_per_category(report):
    a, b = report["categories"]["A"], report["categories"]["B"]
    assert a["by_format"]["sarif"]["artifacts"] == 9 and set(a["by_format"]) == {"sarif"}
    assert {"sarif", "joern-graphml", "none"} == set(b["by_format"]) and b["by_format"]["joern-graphml"]["refused"] == 11
    assert sum(b["refusals_by_cause"].values()) == b["by_format"]["sarif"]["refused"] + b["by_format"]["joern-graphml"]["refused"]
    assert set(a["verdict_distribution"]) == {"Insufficient"} and "Supported" in b["verdict_distribution"]
    assert b["cases_open_semantics"] and b["cases_unbound"] and b["cases_with_positive_path"]
    ell = report["categories"]["L"]
    assert set(ell["by_format"]) == {"sarif"} and ell["by_format"]["sarif"]["artifacts"] == 5 and ell["cases"] == 5
    assert any("B11" in c or "B13" in c for c in b["cases_with_incomplete_or_unverified_run_info"])


def test_rule_coverage_is_observed_not_declared(report):
    cov = report["rule_coverage"]
    assert set(cov["triggered"]) == {f"R{n}" for n in range(1, 14)}
    assert {"R1", "R2", "R4", "R5", "R6", "R11", "R12", "R13"} <= {r for r, n in cov["triggered"].items() if n}
    assert set(cov["never_triggered"]) == {"R7", "R8", "R9", "R10"}
    for rule in cov["never_triggered"]:
        assert cov["triggered"][rule] == 0
    assert "conformance" in cov["note"]


def test_the_output_is_byte_stable_and_the_committed_results_are_current(report, tmp_path):
    assert render_json(report) == render_json(build_report()) and render_csv(report) == render_csv(build_report())
    assert main(["--check", "--out", str(DEFAULT_OUT)]) == 0
    assert main(["--out", str(tmp_path)]) == 0
    assert (tmp_path / "analysis_corpus.json").read_text() == (DEFAULT_OUT / "analysis_corpus.json").read_text()
    assert (tmp_path / "analysis_corpus_cases.csv").read_text() == (DEFAULT_OUT / "analysis_corpus_cases.csv").read_text()


def test_the_check_mode_detects_stale_results(tmp_path, capsys):
    analysis_eval.write_outputs(build_report(), tmp_path)
    assert main(["--check", "--out", str(tmp_path)]) == 0
    (tmp_path / "analysis_corpus_cases.csv").write_text("stale\n")
    assert main(["--check", "--out", str(tmp_path)]) == 1 and "STALE" in capsys.readouterr().out
    assert main(["--check", "--out", str(tmp_path / "missing")]) == 1


def test_the_csv_has_one_row_per_case(report):
    rows = list(csv.DictReader(io.StringIO(render_csv(report))))
    assert len(rows) == report["totals"]["cases"] and {r["agree"] for r in rows} == {"yes"}
    assert rows[0]["id"] == "A01-codeql-results-no-codeflow"


# ---- the harness itself must be able to fail ---------------------------------------------------------------------------------------

def _case(manifest, case_id):
    return copy.deepcopy(next(c for c in manifest["cases"] if c["id"] == case_id))


def test_a_wrong_expectation_is_reported_as_a_disagreement(manifest):
    case = _case(manifest, "B01-sarif-path-bound")
    actual = run_case(case, manifest["defaults"])
    assert compare(case["expected"], actual) == []
    for key, wrong in [("verdict", "Supported"), ("reach", "Absent"), ("rules", ["R1"]), ("bind", "unknown"), ("observations", 2), ("prov_reach", "P3")]:
        bad = copy.deepcopy(case["expected"])
        bad[key] = wrong
        assert any(p.startswith(key) for p in compare(bad, actual)), key
    bad = copy.deepcopy(case["expected"])
    bad["limitations_include"] = ["NO_SUCH_LIMITATION"]
    bad["diagnostics_include"] = ["NO_SUCH_DIAGNOSTIC"]
    assert len(compare(bad, actual)) == 2
    assert compare({"outcome": "refused", "refusal_code": "X", "cause": "Y"}, actual) == ["outcome: expected refused, got evaluated"]


def test_refusal_expectations_are_checked_too(manifest):
    case = _case(manifest, "B-refuse-sarif-truncated")
    actual = run_case(case, manifest["defaults"])
    assert actual["outcome"] == "refused" and compare(case["expected"], actual) == []
    bad = dict(case["expected"], cause="ANALYSIS_STRUCTURE_INVALID")
    assert compare(bad, actual)


def test_attribution_checks_catch_a_changed_file_and_a_mislabelled_category(manifest):
    case = _case(manifest, "A04-documented-codeflow-unbound")
    assert check_fixture(case) == []
    changed = copy.deepcopy(case)
    changed["source"]["sha256"] = "0" * 64
    assert check_fixture(changed) == ["recorded sha256 does not match the file"]
    mislabelled = copy.deepcopy(case)
    mislabelled["source"]["synthetic"] = True
    assert any("category A must not be synthetic" in p for p in check_fixture(mislabelled))
    no_origin = copy.deepcopy(case)
    no_origin["source"].pop("commit")
    assert any("origin, commit and license" in p for p in check_fixture(no_origin))
    synthetic = _case(manifest, "B01-sarif-path-bound")
    synthetic["source"]["synthetic"] = False
    assert any("category B must be flagged synthetic" in p for p in check_fixture(synthetic))
    live = _case(manifest, "B01-sarif-path-bound")
    live["source"]["live_run"] = True
    assert any("only category L may be a live analyzer run" in p for p in check_fixture(live))
    # category L: complete provenance, a matching tool version and a real driver are required
    authentic = _case(manifest, "L01-live-codeql-flow-through-vendored-lib")
    assert check_fixture(authentic) == []
    for key in ("tool_version", "bundle_sha256", "query", "project", "license"):
        stripped = copy.deepcopy(authentic)
        stripped["source"].pop(key)
        assert any(key in p for p in check_fixture(stripped)), key
    wrong_version = copy.deepcopy(authentic)
    wrong_version["source"]["tool_version"] = "2.0.0"
    assert any("semanticVersion" in p for p in check_fixture(wrong_version))
    relabelled = _case(manifest, "B01-sarif-path-bound")
    relabelled["category"] = "L"
    assert any("category L" in p for p in check_fixture(relabelled))
    handwritten = copy.deepcopy(authentic)
    handwritten["source"]["handwritten_here"] = True
    assert any("must be a live run" in p for p in check_fixture(handwritten))


# ---- corpus design requirements ----------------------------------------------------------------------------------------------------

REQUIRED = {
    "positively observed bound path": ["B01-sarif-path-bound", "C01-graphml-path-bound"],
    "different source revision / repository": ["B02-sarif-path-other-revision", "B03-sarif-path-other-repository", "C02-graphml-hash-mismatch"],
    "different target": ["B07-sarif-other-component-same-filename", "F02-target-component-differs-from-finding", "C07-graphml-locus-method-other-component"],
    "empty / no-result artifact": ["A02-lgtm-empty-results", "B09-sarif-no-results"],
    "incomplete analysis": ["B11-sarif-incomplete-no-path", "B12-sarif-incomplete-with-path"],
    "missing coverage information": ["B13-sarif-no-invocation-record", "C04-graphml-no-meta-data"],
    "malformed structure": ["B-refuse-sarif-truncated", "C-refuse-graphml-truncated", "A06-lgtm-results-wrong-type"],
    "unknown tool / format version": ["B14-sarif-unknown-tool-no-version", "B-refuse-sarif-version-2-0-0", "C-refuse-graphml-cpg-spec-version"],
    "unresolved references": ["B-refuse-sarif-unresolved-index", "C-refuse-graphml-unresolved-endpoint"],
    "multiple candidate targets": ["B08-sarif-two-components-one-matches", "C09-graphml-duplicate-locus-name"],
    "ambiguous identity": ["B05-sarif-abbreviated-revision", "B06-sarif-conflicting-revisions", "B19-sarif-absolute-uris"],
    "unresolved relevant location next to a K1 absence": ["G01-unresolved-relevant-flow-beside-k1-absence", "G02-unknown-uri-base-beside-k1-absence",
                                                           "G03-path-escaping-root-beside-k1-absence", "G19-graph-uncontained-call-beside-k1-absence"],
    "unresolved irrelevant location next to a K1 absence": ["G06-unresolved-irrelevant-flow-beside-k1-absence", "G20-graph-uncontained-call-irrelevant-beside-k1-absence"],
    "mixed thread flows, one unresolved": ["G07-mixed-threadflows-one-unresolved-beside-k1-absence"],
    "multiple source roots": ["G08-two-source-roots-default-root", "G09-two-source-roots-other-root"],
    "empty or missing code flows are not absence": ["G11-empty-codeflows-array", "G12-empty-codeflows-beside-k1-absence", "G13-run-without-results-array"],
    "schema-valid but unsupported meaning": ["G10-locus-step-marked-unreachable", "G14-property-bag-claims-complete-coverage"],
    "invalid invocation metadata": ["G16-invalid-invocation-time", "G17-invalid-notification-level"],
    "authentic CodeQL output": ["L01-live-codeql-flow-through-vendored-lib", "L02-live-codeql-empty-results", "L03-live-codeql-flow-not-touching-the-locus",
                                "L04-live-codeql-flow-beside-k1-absence"],
    "contradictory / conflicting evidence": ["D02-path-contradicts-supplied-k1-absence", "B-refuse-sarif-index-uri-conflict", "C-refuse-graphml-call-site-in-two-methods"],
    "valid and invalid provenance": ["B01-sarif-path-bound", "B14-sarif-unknown-tool-no-version", "E01-verified-covering-cannot-reach-p3", "E03-verification-untrusted-anchor"],
    "graph with several relation types": ["C01-graphml-path-bound", "C06-graphml-cfg-edges-only"],
    "dependency-only SBOM observation": ["D01-sbom-dependency-edges-only"],
    "partial output must not support absence": ["B11-sarif-incomplete-no-path", "D04-failed-run-leaves-supported-k1-unchanged", "C05-graphml-no-path"],
    "format-specific edge cases": ["B22-sarif-percent-encoded", "B23-sarif-artifact-index", "B21-sarif-path-escapes-root", "C-refuse-graphml-doctype"],
    "real upstream artifacts": ["A01-codeql-results-no-codeflow", "A04-documented-codeflow-unbound", "A07-tool-names-null-name"],
}


@pytest.mark.parametrize("requirement", sorted(REQUIRED))
def test_the_corpus_covers_each_required_case_category(requirement, manifest):
    ids = {c["id"] for c in manifest["cases"]}
    assert set(REQUIRED[requirement]) <= ids


def test_every_case_states_why_its_expectation_follows_from_the_rules(manifest):
    for case in manifest["cases"]:
        assert len(case["why"]) > 40 and case["id"] and case["expected"]["outcome"] in ("evaluated", "refused")
        assert "source" in case and case["category"] in ("A", "B", "L")


def test_every_corpus_file_is_listed_in_the_manifest_and_vice_versa(manifest):
    listed = {c["file"] for c in manifest["cases"] if c.get("file")}
    on_disk = {str(p.relative_to(ANALYSIS_DIR)) for sub in ("upstream", "sarif", "joern-graphml") for p in (ANALYSIS_DIR / sub).iterdir() if p.is_file()}
    on_disk |= {str(p.relative_to(ANALYSIS_DIR)) for p in (ANALYSIS_DIR / "authentic" / "codeql").glob("*.sarif")}
    assert listed == on_disk


def test_only_category_l_is_a_live_run_and_no_joern_file_claims_to_be_upstream_or_live(manifest):
    for case in manifest["cases"]:
        assert bool(case["source"].get("live_run")) is (case["category"] == "L"), case["id"]
        if case["format"] == "joern-graphml":
            assert case["category"] == "B" and case["source"]["synthetic"]


def test_upstream_provenance_is_recorded_for_every_category_a_file(manifest):
    for case in manifest["cases"]:
        if case["category"] == "A":
            s = case["source"]
            assert len(s["commit"]) == 40 and s["origin"].startswith("github.com/") and s["license"] and s["upstream_path"] and s["nature"]


def test_the_conformance_harness_includes_the_corpus(report):
    summary = conformance.build_report()
    assert summary["analysis_corpus"]["cases"] == report["totals"]["cases"] and summary["analysis_corpus"]["disagree"] == 0 and summary["ok"]
    assert "analyzer-artifact corpus" in conformance.render(summary)
