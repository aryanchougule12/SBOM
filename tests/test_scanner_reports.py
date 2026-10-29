"""Scanner-report adapters: real Trivy/OSV-Scanner fixtures (trimmed), a documented-shape Grype fixture, strict error handling."""

import json
from pathlib import Path

import pytest

from scanner_reports import ScannerReportError, detect_format, parse_report
from scanner_reports.detect import PARSERS

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "scanner_reports"
BENCH = Path(__file__).resolve().parent.parent / "experiments" / "benchmark5" / "tool_out"


def test_each_format_is_detected_from_its_content():
    assert {p.name: detect_format(json.loads(p.read_text())) for p in FIX.glob("*.json")} == {
        "grype_documented_schema.json": "grype", "osv_scanner_real_trimmed.json": "osv-scanner", "trivy_real_trimmed.json": "trivy"}


def test_grype_findings_carry_related_ids_as_aliases_and_ignored_matches_are_counted_not_reported():
    report = parse_report(FIX / "grype_documented_schema.json")
    assert (report.tool, report.tool_version, report.ignored) == ("grype", "0.121.0", 1)
    first, second = report.findings
    assert first.ids == {"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"} and first.ecosystem == "Maven" and first.version == "2.14.1"
    assert second.ids == {"CVE-2020-8203"} and second.purl == "pkg:npm/lodash@4.17.15"


def test_osv_scanner_and_trivy_fixtures_parse_to_the_package_versions_scanned():
    for name, tool in (("osv_scanner_real_trimmed.json", "osv-scanner"), ("trivy_real_trimmed.json", "trivy")):
        report = parse_report(FIX / name)
        assert report.tool == tool and report.findings
        assert all(f.name and f.version and f.vuln_id and f.locator.startswith("#/") for f in report.findings)
    assert any(f.aliases for f in parse_report(FIX / "osv_scanner_real_trimmed.json").findings)


@pytest.mark.skipif(not BENCH.exists(), reason="benchmark outputs not present")
def test_full_benchmark_reports_parse_with_exactly_the_number_of_vulnerabilities_they_contain():
    for path in sorted(BENCH.glob("trivy_*.json")):
        raw = json.loads(path.read_text())
        assert len(parse_report(path).findings) == sum(len(r.get("Vulnerabilities") or []) for r in raw["Results"])
    for path in sorted(BENCH.glob("osv-scanner_*.json")):
        raw = json.loads(path.read_text())
        assert len(parse_report(path).findings) == sum(len(p.get("vulnerabilities") or []) for r in raw["results"] for p in r["packages"])


@pytest.mark.parametrize("data", [[], "x", 3, {}, {"unrelated": 1}])
def test_unrecognised_documents_are_refused_by_detection(data):
    with pytest.raises(ScannerReportError):
        detect_format(data)


@pytest.mark.parametrize("fmt, data, locator_part", [
    ("grype", {"matches": [{"vulnerability": {}, "artifact": {"name": "a", "version": "1"}}]}, "/matches/0/vulnerability/id"),
    ("grype", {"matches": [{"vulnerability": {"id": "X"}, "artifact": {"name": "a"}}]}, "/matches/0/artifact/version"),
    ("grype", {"matches": {}}, "/matches"),
    ("trivy", {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "X", "PkgName": "a"}]}]}, "InstalledVersion"),
    ("trivy", {"Results": "no"}, "/Results"),
    ("osv-scanner", {"results": [{"packages": [{"package": {"name": "a", "version": ""}, "vulnerabilities": []}]}]}, "version"),
    ("osv-scanner", {"results": [{"packages": [{"vulnerabilities": []}]}]}, "package"),
])
def test_structurally_invalid_reports_are_refused_with_a_locator(fmt, data, locator_part):
    with pytest.raises(ScannerReportError) as caught:
        PARSERS[fmt](data)
    assert locator_part in caught.value.locator


def test_unreadable_and_unknown_format_requests_are_refused(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ScannerReportError):
        parse_report(bad)
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"results": []}))
    with pytest.raises(ScannerReportError):
        parse_report(ok, "nessus")
    assert parse_report(ok).findings == ()
