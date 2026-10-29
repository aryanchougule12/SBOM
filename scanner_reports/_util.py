from __future__ import annotations

from typing import Any

from scanner_reports.model import ScannerReportError


def obj(value: Any, locator: str) -> dict:
    if not isinstance(value, dict):
        raise ScannerReportError("expected an object", locator)
    return value


def arr(parent: dict, key: str, locator: str, *, required: bool = False) -> list:
    if key not in parent or parent[key] is None:
        if required:
            raise ScannerReportError(f"missing array {key!r}", locator)
        return []
    if not isinstance(parent[key], list):
        raise ScannerReportError(f"{key!r} must be an array", f"{locator}/{key}")
    return parent[key]


def text(parent: dict, key: str, locator: str, *, required: bool = True):
    value = parent.get(key)
    if isinstance(value, str) and value.strip():
        return value
    if required:
        raise ScannerReportError(f"{key!r} must be a non-empty string", f"{locator}/{key}")
    return None
