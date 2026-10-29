"""Reconcile scanner findings with VEX ``component_not_present`` claims through the evidence evaluator.

For every (component, vulnerability) pair that at least one scanner reported on the SBOM's product, find the VEX statements about the same vulnerability
(ids matched through the aliases both sides carry) and, for each ``not_affected`` / ``component_not_present`` statement, build the evaluator profile *from
facts, not guesses* and call ``evaluate_finding``:

* scope product / version / artifact digest come from the SBOM's own subject (``metadata.component``); a missing digest stays missing (the evaluator then
  reports the scope as unbound) - nothing is invented;
* the target component C is the component the scanner reported (identified by its purl when it has one);
* the would-be location mirrors the SBOM layout: libraries listed under ``metadata.component.components`` -> ``nested_under_component`` (that subject),
  otherwise ``top_level``;
* an inventory-completeness assertion is added only when the caller passes one (``InventoryAssertion``): it is a human fact, never derived;
* the artifact kind is a required argument: it cannot be read from a CycloneDX/SPDX document reliably.

Everything else (a different justification, a different status, no statement) is reported with an explicit reason and never evaluated. Scanner findings are
claims about presence, not evidence; the evaluator treats the SBOM as the inventory and a contradiction between the two as such (CLAIM_CONTRADICTED_BY_INVENTORY).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote

from evidence.evaluator import EvaluationRefusal
from evidence.profile import parse_profile
from evidence.stage1_records import SbomRecord, Stage1Index, load_cyclonedx, load_openvex, load_spdx
from evidence.sufficiency import evaluate_finding
from evidence.verification import VerificationConfig, load_verification
from model import Disposition, Finding
from scanner_reports import ScannerFinding, ScannerReport

CNP = "component_not_present"


@dataclass(frozen=True)
class InventoryAssertion:
    statement: str            # e.g. "full_component_list"
    entered_by: str


class BatchError(ValueError):
    """The inputs cannot be reconciled at all (exit status 2 in the CLI)."""


def load_sbom(path: Path) -> SbomRecord:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise BatchError(f"SBOM {path}: cannot read as JSON ({error})") from None
    if isinstance(data, dict) and "bomFormat" in data:
        return load_cyclonedx(path)
    if isinstance(data, dict) and "spdxVersion" in data:
        return load_spdx(path)
    raise BatchError(f"SBOM {path}: neither CycloneDX ('bomFormat') nor SPDX ('spdxVersion')")


def _norm_id(value: str) -> str:
    return value.strip().upper()


def _name_from(finding: ScannerFinding) -> str:
    if finding.purl:
        m = re.match(r"pkg:[^/]+/(?:[^/@?]+/)*([^/@?]+)@", finding.purl)
        if m:
            return unquote(m.group(1))
    return finding.name.split(":")[-1]


def merge_findings(reports: list[ScannerReport]) -> list[dict[str, Any]]:
    """One entry per (package version, vulnerability group); ids of findings that share any id on the same package version are merged."""
    groups: list[dict[str, Any]] = []
    for report in reports:
        for f in report.findings:
            key = (f.purl or f"{f.ecosystem}:{f.name}", f.version)
            ids = {_norm_id(i) for i in f.ids}
            for g in groups:
                if g["key"] == key and g["ids"] & ids:
                    g["ids"] |= ids
                    g["tools"].add(f.tool)
                    g["findings"].append(f)
                    break
            else:
                groups.append({"key": key, "ids": ids, "tools": {f.tool}, "findings": [f]})
    # a later finding can bridge two groups created earlier: merge until stable
    merged = True
    while merged:
        merged = False
        for i, a in enumerate(groups):
            for b in groups[i + 1:]:
                if a["key"] == b["key"] and a["ids"] & b["ids"]:
                    a["ids"] |= b["ids"]; a["tools"] |= b["tools"]; a["findings"] += b["findings"]
                    groups.remove(b)
                    merged = True
                    break
            if merged:
                break
    return groups


def _layout(record: SbomRecord) -> tuple[str, Optional[str]]:
    locators = [str(e.get("locator", "")) for e in record.component_index]
    nested = [l for l in locators if l.startswith("#/metadata/component/components")]
    top = [l for l in locators if l.startswith("#/components")]
    subject = record.document.subjects[0] if record.document.subjects else None
    if nested and not top and subject is not None and subject.ref:
        return "nested_under_component", subject.ref
    return "top_level", None


def _scope_facts(record: SbomRecord):
    subject = record.document.subjects[0].component if record.document.subjects else None
    digest = None
    version = subject.version if subject else None
    if subject:
        for h in subject.hashes:
            if h.algorithm.lower().replace("-", "") == "sha256":
                digest = "sha256:" + h.value.lower()
    return version, digest


def reconcile(sbom: Path, vex: Path, reports: list[ScannerReport], *, artifact_kind: str, assertion: Optional[InventoryAssertion] = None,
              verification: Optional[Path] = None) -> dict[str, Any]:
    record = load_sbom(sbom)
    try:
        vex_findings: list[Finding] = list(load_openvex(vex).findings)
    except Exception as error:      # ParserError subclasses; any unreadable VEX makes the whole run unusable
        raise BatchError(f"VEX {vex}: {error}") from None
    verification_config: Optional[VerificationConfig] = None
    if verification is not None:
        try:
            verification_config = load_verification(verification)
        except (ValueError, OSError) as error:
            raise BatchError(f"verification {verification}: {error}") from None
    version, digest = _scope_facts(record)
    placement, parent_ref = _layout(record)
    index = Stage1Index([record])
    sbom_purls = {c.purl.lower() for c in record.components if c.purl}
    rows = []
    for g in sorted(merge_findings(reports), key=lambda x: (str(x["key"]), sorted(x["ids"]))):
        first: ScannerFinding = g["findings"][0]
        row: dict[str, Any] = {"component": first.purl or f"{first.name}@{first.version}", "vulnerability_ids": sorted(g["ids"]), "reported_by": sorted(g["tools"]),
               "component_in_sbom": bool(first.purl) and first.purl.lower() in sbom_purls if first.purl else None}
        statements = [f for f in vex_findings if g["ids"] & {_norm_id(i) for i in [f.vulnerability.id, *f.vulnerability.aliases]}]
        if not statements:
            rows.append({**row, "status": "no_vex_claim"})
            continue
        for statement in statements:
            out = {**row, "vex_vulnerability": statement.vulnerability.id, "vex_status": statement.disposition.value, "vex_justification": statement.justification.justification}
            if statement.disposition is not Disposition.NOT_AFFECTED:
                rows.append({**out, "status": "not_evaluated", "reason": f"VEX status is {statement.disposition.value}; only not_affected claims are evaluated"})
                continue
            if statement.justification.justification != CNP:
                rows.append({**out, "status": "not_evaluated", "reason": f"justification {statement.justification.justification!r} is not evaluated by this runner "
                             f"(only {CNP}; vulnerable_code_not_in_execute_path needs analyzer artifacts, see `python -m evidence evaluate --subject --artifact`)"})
                continue
            product_id = statement.scope.product_id
            scope = {"product_id": product_id, "artifact_kind": artifact_kind}
            if version:
                scope["version"] = version
            if digest:
                scope["artifact_digests"] = [digest]
            location = {"placement": placement, "document": record.doc_id}
            if parent_ref:
                location["parent_ref"] = parent_ref
            target = {"name": _name_from(first), "version": first.version}
            if first.purl:
                target["purl"] = first.purl
            profile = {"schema_version": "1.1", "profile_id": "batch", "scope": scope, "documents": [{"doc_id": record.doc_id, "role": "primary_sbom"}],
                       "finding_selector": {"vulnerability": statement.vulnerability.id, "product_id": product_id},
                       "target": {"component": target, "would_be_location": location}}
            if assertion is not None:
                profile["inv_assertions"] = [{"document": record.doc_id, "scope": dict(scope), "statement": assertion.statement, "entered_by": assertion.entered_by}]
            try:
                outcome = evaluate_finding(parse_profile(profile), vex_findings, index, verification_config, None)
            except ValueError as error:
                rows.append({**out, "status": "unusable_profile", "reason": str(error)})
                continue
            if isinstance(outcome, EvaluationRefusal):
                rows.append({**out, "status": "refused", "reason": json.loads(json.dumps(outcome.to_dict(), default=str))})
                continue
            result = outcome.result
            evaluated = {**out, "status": "evaluated", "verdict": result.verdict.value, "codes": list(result.codes), "limitations": list(outcome.limitations)}
            if out["component_in_sbom"] is False:     # an independent scanner found C where the SBOM does not list it: the SBOM may be incomplete
                evaluated["warning"] = ("SCANNER_REPORTS_COMPONENT_NOT_IN_SBOM: a scanner reports this component on the product but the SBOM does not list it; "
                                        "the verdict rests on that SBOM being the full inventory, which the scanner finding calls into question")
            rows.append(evaluated)
    counts: dict[str, int] = {}
    for r in rows:
        key = r.get("verdict") or r["status"]
        counts[key] = counts.get(key, 0) + 1
    return {"sbom": {"path": str(sbom), "doc_id": record.doc_id, "layout": placement, "scope_version": version, "scope_digest": digest},
            "inventory_assertion": None if assertion is None else {"statement": assertion.statement, "entered_by": assertion.entered_by},
            "scanners": [{"tool": r.tool, "findings": len(r.findings), "ignored": r.ignored} for r in reports], "counts": counts, "rows": rows}
