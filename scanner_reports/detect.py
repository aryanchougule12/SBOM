from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner_reports.grype import parse_grype
from scanner_reports.model import ScannerReport, ScannerReportError
from scanner_reports.osv_scanner import parse_osv_scanner
from scanner_reports.trivy import parse_trivy

PARSERS = {"grype": parse_grype, "trivy": parse_trivy, "osv-scanner": parse_osv_scanner}


def detect_format(data: Any) -> str:
    """Name the scanner format of an already-loaded report from its top-level keys, or raise ``ScannerReportError``."""
    if isinstance(data, dict):
        if "matches" in data:
            return "grype"
        if "Results" in data or "SchemaVersion" in data:
            return "trivy"
        if "results" in data:
            return "osv-scanner"
    raise ScannerReportError("cannot tell which scanner produced this report (expected Grype 'matches', Trivy 'Results' or OSV-Scanner 'results')", "#")


def parse_report(path: Path, fmt: str | None = None) -> ScannerReport:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ScannerReportError(f"cannot read {path} as JSON ({error})", "#") from None
    name = fmt or detect_format(data)
    if name not in PARSERS:
        raise ScannerReportError(f"unknown scanner format {name!r}; known: {', '.join(sorted(PARSERS))}", "#")
    return PARSERS[name](data)
