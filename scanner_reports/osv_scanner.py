"""OSV-Scanner v2 JSON: ``results[].packages[].package`` (name, version, ecosystem, purl) with ``vulnerabilities[]`` (id, aliases)."""

from __future__ import annotations

from typing import Any

from scanner_reports._util import arr, obj, text
from scanner_reports.model import ScannerFinding, ScannerReport, ScannerReportError


def parse_osv_scanner(data: Any) -> ScannerReport:
    root = obj(data, "#")
    if "results" not in root:
        raise ScannerReportError("not an OSV-Scanner report (no 'results')", "#")
    findings = []
    for i, result in enumerate(arr(root, "results", "#")):
        for j, pkg in enumerate(arr(obj(result, f"#/results/{i}"), "packages", f"#/results/{i}")):
            base = f"#/results/{i}/packages/{j}"
            pkg = obj(pkg, base)
            info = obj(pkg.get("package"), f"{base}/package")
            name, version = text(info, "name", f"{base}/package"), text(info, "version", f"{base}/package")
            for k, v in enumerate(arr(pkg, "vulnerabilities", base)):
                loc = f"{base}/vulnerabilities/{k}"
                v = obj(v, loc)
                aliases = tuple(a for a in arr(v, "aliases", loc) if isinstance(a, str))
                findings.append(ScannerFinding("osv-scanner", text(v, "id", loc), aliases, name, version, info.get("purl") if isinstance(info.get("purl"), str) else None,
                                               info.get("ecosystem") if isinstance(info.get("ecosystem"), str) else None, loc))
    return ScannerReport("osv-scanner", None, tuple(findings))
