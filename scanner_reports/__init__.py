"""Adapters from vulnerability-scanner JSON reports (Grype, Trivy, OSV-Scanner) to one neutral finding record.

Purpose: let the evidence tool consume what real scanners report (which component, which vulnerability ids) without re-implementing detection. An adapter
reads, validates and normalises; it never decides anything about evidence. Reports are *claims by the scanner*: nothing here upgrades them to
evidence of presence or absence.
"""

from scanner_reports.detect import detect_format, parse_report
from scanner_reports.model import ScannerFinding, ScannerReport, ScannerReportError

__all__ = ["ScannerFinding", "ScannerReport", "ScannerReportError", "detect_format", "parse_report"]
