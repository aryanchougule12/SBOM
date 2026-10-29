from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class ScannerReportError(ValueError):
    """The report is not valid JSON of the expected scanner format; ``locator`` is a JSON-pointer-like path."""

    def __init__(self, message: str, locator: str = "#") -> None:
        super().__init__(f"{message} (at {locator})")
        self.message = message
        self.locator = locator


@dataclass(frozen=True)
class ScannerFinding:
    """One scanner match: vulnerability ``vuln_id`` (plus ``aliases``) reported on one package version."""

    tool: str
    vuln_id: str
    aliases: tuple[str, ...]
    name: str
    version: str
    purl: Optional[str]
    ecosystem: Optional[str]
    locator: str

    @property
    def ids(self) -> frozenset[str]:
        return frozenset({self.vuln_id, *self.aliases})


@dataclass(frozen=True)
class ScannerReport:
    tool: str
    tool_version: Optional[str]
    findings: tuple[ScannerFinding, ...]
    ignored: int = 0      # matches the scanner itself marked ignored/suppressed; they are not findings
