"""Trivy JSON (``trivy ... --format json``): ``Results[].Vulnerabilities[]`` with ``VulnerabilityID``, ``PkgName``, ``InstalledVersion``, ``PkgIdentifier.PURL``."""

from __future__ import annotations

import re
from typing import Any

from scanner_reports._util import arr, obj, text
from scanner_reports.model import ScannerFinding, ScannerReport, ScannerReportError

_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist"}


def ecosystem_of(purl: str | None) -> str | None:
    m = re.match(r"pkg:([a-z]+)/", purl or "")
    return _ECO.get(m.group(1)) if m else None


def parse_trivy(data: Any) -> ScannerReport:
    root = obj(data, "#")
    if "Results" not in root and "SchemaVersion" not in root:
        raise ScannerReportError("not a Trivy report (no 'Results' or 'SchemaVersion')", "#")
    findings = []
    for i, result in enumerate(arr(root, "Results", "#")):
        base = f"#/Results/{i}"
        for j, v in enumerate(arr(obj(result, base), "Vulnerabilities", base)):
            loc = f"{base}/Vulnerabilities/{j}"
            v = obj(v, loc)
            purl = (v.get("PkgIdentifier") or {}).get("PURL") if isinstance(v.get("PkgIdentifier"), dict) else None
            findings.append(ScannerFinding("trivy", text(v, "VulnerabilityID", loc), (), text(v, "PkgName", loc), text(v, "InstalledVersion", loc),
                                           purl, ecosystem_of(purl), loc))
    return ScannerReport("trivy", None, tuple(findings))
