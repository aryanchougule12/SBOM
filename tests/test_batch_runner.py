"""Batch runner on the committed benchmark SBOMs/scanner outputs (real Syft SBOMs, real Trivy / OSV-Scanner reports)."""

import json
from pathlib import Path

import pytest

from batch_runner.cli import main
from batch_runner.runner import BatchError, InventoryAssertion, reconcile
from scanner_reports import parse_report

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "experiments" / "benchmark5"
pytestmark = pytest.mark.skipif(not BENCH.exists(), reason="benchmark data not present")
PROJECT = "legacy-mixed"
SBOM = BENCH / "sbom_clean" / f"{PROJECT}.json"
TRIVY = BENCH / "tool_out" / f"trivy_{PROJECT}.json"
OSV = BENCH / "tool_out" / f"osv-scanner_{PROJECT}.json"


def make_vex(tmp_path, statements):
    sbom = json.loads(SBOM.read_text())
    digest = sbom["metadata"]["component"]["hashes"][0]["content"]
    product = f"pkg:generic/{PROJECT}@1.0.0"
    items = []
    for vuln, status, justification in statements:
        s = {"vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{vuln}", "name": vuln}, "products": [
            {"@id": product, "identifiers": {"purl": product}, "hashes": {"sha-256": digest.upper()}}], "status": status, "timestamp": "2026-10-29T10:05:00Z"}
        if justification:
            s["justification"] = justification
            s["impact_statement"] = "claim"
        items.append(s)
    path = tmp_path / "vex.json"
    path.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://t/vex", "author": "t", "role": "Document Creator",
                                "timestamp": "2026-10-29T10:00:00Z", "version": 1, "tooling": "t", "statements": items}))
    return path


def test_scanner_findings_are_merged_across_tools_by_alias(tmp_path):
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "component_not_present")])
    result = reconcile(SBOM, vex, [parse_report(TRIVY), parse_report(OSV)], artifact_kind="source")
    lodash = [r for r in result["rows"] if r["component"] == "pkg:npm/lodash@4.17.15" and r["status"] != "no_vex_claim"]
    assert len(lodash) == 1 and lodash[0]["reported_by"] == ["osv-scanner", "trivy"]
    assert {"CVE-2020-8203", "GHSA-P6MC-M468-83GW"} <= set(lodash[0]["vulnerability_ids"])


def test_a_component_not_present_claim_about_a_listed_component_is_insufficient_not_accepted(tmp_path):
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "component_not_present")])
    result = reconcile(SBOM, vex, [parse_report(TRIVY)], artifact_kind="source", assertion=InventoryAssertion("full_component_list", "tester"))
    row = next(r for r in result["rows"] if r["status"] == "evaluated")
    assert row["verdict"] == "Insufficient" and "CLAIM_CONTRADICTED_BY_INVENTORY" in row["codes"] and row["component_in_sbom"] is True
    assert "warning" not in row


def test_findings_without_a_vex_statement_and_other_justifications_are_reported_not_evaluated(tmp_path):
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "vulnerable_code_not_in_execute_path"), ("CVE-2019-10744", "affected", None)])
    result = reconcile(SBOM, vex, [parse_report(TRIVY)], artifact_kind="source")
    statuses = {}
    for r in result["rows"]:
        statuses.setdefault(r["status"], []).append(r)
    assert "evaluated" not in statuses
    assert all("reason" in r for r in statuses["not_evaluated"]) and len(statuses["no_vex_claim"]) > 10
    assert sum(result["counts"].values()) == len(result["rows"])


def test_a_scanner_finding_for_a_component_missing_from_the_sbom_carries_a_warning(tmp_path):
    doc = json.loads(SBOM.read_text())
    doc["components"] = [c for c in doc["components"] if "lodash" not in c["purl"]]
    doc["dependencies"] = [d for d in doc["dependencies"] if "lodash" not in d["ref"]]
    short = tmp_path / "short.json"
    short.write_text(json.dumps(doc))
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "component_not_present")])
    result = reconcile(short, vex, [parse_report(TRIVY)], artifact_kind="source", assertion=InventoryAssertion("full_component_list", "tester"))
    row = next(r for r in result["rows"] if r["status"] == "evaluated")
    assert row["component_in_sbom"] is False and row["warning"].startswith("SCANNER_REPORTS_COMPONENT_NOT_IN_SBOM")
    assert row["verdict"] == "Weak" and "CLAIM_CONTRADICTED_BY_INVENTORY" not in row["codes"]


def test_a_missing_subject_digest_is_not_invented(tmp_path):
    doc = json.loads(SBOM.read_text())
    del doc["metadata"]["component"]["hashes"]
    nodigest = tmp_path / "nodigest.json"
    nodigest.write_text(json.dumps(doc))
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "component_not_present")])
    result = reconcile(nodigest, vex, [parse_report(TRIVY)], artifact_kind="source", assertion=InventoryAssertion("full_component_list", "tester"))
    assert result["sbom"]["scope_digest"] is None
    row = next(r for r in result["rows"] if r["status"] == "evaluated")
    assert row["verdict"] == "Insufficient"


def test_unusable_inputs_are_refused(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    with pytest.raises(BatchError):
        reconcile(bad, make_vex(tmp_path, []), [parse_report(TRIVY)], artifact_kind="source")
    assert main(["--sbom", str(bad), "--vex", str(bad), "--scanner", str(TRIVY), "--artifact-kind", "source"]) == 2
    assert main(["--sbom", str(SBOM), "--vex", str(bad), "--scanner", str(bad), "--artifact-kind", "source"]) == 2


def test_the_cli_writes_a_result_file(tmp_path, capsys):
    vex = make_vex(tmp_path, [("CVE-2020-8203", "not_affected", "component_not_present")])
    out = tmp_path / "result.json"
    status = main(["--sbom", str(SBOM), "--vex", str(vex), "--scanner", str(TRIVY), "--scanner", str(OSV), "--artifact-kind", "source", "--out", str(out)])
    assert status == 0 and "wrote" in capsys.readouterr().out
    data = json.loads(out.read_text())
    assert {s["tool"] for s in data["scanners"]} == {"trivy", "osv-scanner"} and data["counts"]["Insufficient"] == 1


def test_a_grype_report_flows_through_the_same_path(tmp_path):
    grype = ROOT / "fixtures" / "scanner_reports" / "grype_documented_schema.json"
    vex = make_vex(tmp_path, [("CVE-2021-44228", "not_affected", "component_not_present"), ("CVE-2020-8203", "not_affected", "component_not_present")])
    result = reconcile(SBOM, vex, [parse_report(grype)], artifact_kind="source")
    evaluated = {r["component"]: r for r in result["rows"] if r["status"] == "evaluated"}
    assert set(evaluated) == {"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:npm/lodash@4.17.15"}
    assert evaluated["pkg:npm/lodash@4.17.15"]["component_in_sbom"] is True     # lodash is in legacy-mixed
    assert result["scanners"] == [{"tool": "grype", "findings": 2, "ignored": 1}]
