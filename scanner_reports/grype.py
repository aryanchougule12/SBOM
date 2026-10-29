"""Grype JSON (``grype -o json``): ``matches[]`` with ``vulnerability.id``, ``relatedVulnerabilities[].id`` and ``artifact`` (name, version, purl).

Written from Grype's documented output schema; no real Grype run was available when this adapter was written (its database host was unreachable), so
the adapter is validated against a documented-shape fixture only. ``ignoredMatches`` are counted, not reported."""

from __future__ import annotations

from typing import Any

from scanner_reports._util import arr, obj, text
from scanner_reports.model import ScannerFinding, ScannerReport, ScannerReportError
from scanner_reports.trivy import ecosystem_of


def parse_grype(data: Any) -> ScannerReport:
    root = obj(data, "#")
    if "matches" not in root:
        raise ScannerReportError("not a Grype report (no 'matches')", "#")
    findings = []
    for i, match in enumerate(arr(root, "matches", "#", required=True)):
        loc = f"#/matches/{i}"
        match = obj(match, loc)
        vuln = obj(match.get("vulnerability"), f"{loc}/vulnerability")
        art = obj(match.get("artifact"), f"{loc}/artifact")
        vid = text(vuln, "id", f"{loc}/vulnerability")
        aliases = tuple(sorted({text(obj(r, f"{loc}/relatedVulnerabilities/{k}"), "id", f"{loc}/relatedVulnerabilities/{k}")
                                for k, r in enumerate(arr(match, "relatedVulnerabilities", loc))} - {vid}))
        purl = art.get("purl") if isinstance(art.get("purl"), str) else None
        findings.append(ScannerFinding("grype", vid, aliases, text(art, "name", f"{loc}/artifact"), text(art, "version", f"{loc}/artifact"), purl, ecosystem_of(purl), loc))
    descriptor = root.get("descriptor") if isinstance(root.get("descriptor"), dict) else {}
    return ScannerReport("grype", descriptor.get("version") if isinstance(descriptor.get("version"), str) else None, tuple(findings),
                         ignored=len(arr(root, "ignoredMatches", "#")))
