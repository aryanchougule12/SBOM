"""Evidence extraction -- minimal bounded slice (Stage 2, slice 1).

Derives ``EvidenceItem`` records for a ``Finding`` from SBOM documents supplied through
the typed Stage 1 records adapter (``evidence.stage1_records``). Parsed component lists
are not stored on ``Finding`` or ``SourceDocument``; the caller passes a ``Stage1Index``
mapping source-document ids to ``SbomRecord``s. A document is used only if the finding's
``document_roles`` assigns it a role (nothing is inferred from a document merely being
present in ``source_documents`` or in the index).

This module will not fabricate evidence (P-2): where nothing establishes a dimension it
emits ``Unknown`` or nothing. Only these cases are implemented:

* **MATCH**: ``Finding.component is None`` -> ``Unknown`` ("no target component
  established"). The product's identifiers are never used as C's.
* **DECL**: no composition record -> ``Unknown``. If records exist, which one governs C's
  location is undecided (open issue G6), so the result stays ``Unknown``.
* **GEN**: ``method is None`` -> ``Unknown``. ``generation_context`` and the mere
  existence of a document are never used to classify the method.
* **REACH**: declared dependency edges are K4 evidence only -> ``Unknown``; never a
  positive or negative call/reachability result.
* **INV**: inventory is reachable through the adapter, but full-list evidence cannot be
  established (open issue G11) -> ``Unknown``.

Everything else (MATCH with a resolved C, BIND, GEN beyond "method absent", LOCUS, ENTRY,
HAZ, CFG, K1-K3) is NOT evaluated: no item is emitted and a ``NOT_EVALUATED`` diagnostic
names the dimension. Open-issue labels (G6, G11, ...) are local labels from
``docs/open_issues_register.md``, not rule identifiers of the formal specification.

No predicate rule (N1-N17, R1-R13) and no verdict is computed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from evidence.stage1_records import SbomRecord, Stage1Index
from model import (
    Disposition,
    DocumentRole,
    EvidenceItem,
    EvidenceState,
    Finding,
    JustificationType,
)

DIM_INV = "INV"
DIM_MATCH = "MATCH"
DIM_DECL = "DECL"
DIM_GEN = "GEN"
DIM_REACH = "REACH"

_SBOM_ROLES = (DocumentRole.PRIMARY_SBOM, DocumentRole.CORROBORATING)


@dataclass(frozen=True)
class Diagnostic:
    """Machine-readable explanation carried in ``EvidenceItem.value_or_ref`` or reported
    in ``ExtractionResult.diagnostics``."""

    code: str
    message: str
    locators: tuple[str, ...] = ()


@dataclass
class ExtractionResult:
    items: list[EvidenceItem] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)


def _primary_records(finding: Finding, index: Stage1Index) -> tuple[list[tuple[str, Optional[SbomRecord]]], bool]:
    """Documents with the PRIMARY_SBOM role (sorted by id) and their records, if indexed."""
    ids = sorted(d for d, role in finding.document_roles.items() if role is DocumentRole.PRIMARY_SBOM)
    return [(d, index.get(d)) for d in ids], bool(ids)


def _unknown(dimension: str, source_doc: Optional[str], code: str, message: str,
             locators: tuple[str, ...] = ()) -> EvidenceItem:
    return EvidenceItem(
        dimension=dimension,
        state=EvidenceState.UNKNOWN,
        value_or_ref=Diagnostic(code, message, locators),
        source_doc=source_doc,
        locator=None,
    )


def _not_evaluated(dimension: str, reason: str) -> Diagnostic:
    return Diagnostic("NOT_EVALUATED", f"{dimension}: {reason}")


def extract(finding: Finding, records: Optional[Stage1Index] = None) -> ExtractionResult:
    """Extract the authorized minimal evidence for ``finding``.

    ``records`` supplies the parsed SBOM component lists and decoded Stage 1 records.
    """
    index = records if records is not None else Stage1Index()
    result = ExtractionResult()

    if finding.disposition is not Disposition.NOT_AFFECTED:
        result.diagnostics.append(
            Diagnostic(
                "DISPOSITION_NOT_EVALUATED",
                f"the predicates apply only to not_affected; got {finding.disposition.value!r} "
                "(an input error, not a verdict)",
            )
        )
        return result

    raw = finding.justification.justification  # compared exactly; never normalised
    if raw == JustificationType.COMPONENT_NOT_PRESENT.value:
        _extract_component_not_present(finding, index, result)
    elif raw == JustificationType.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value:
        _extract_reachability(finding, index, result)
    else:
        result.diagnostics.append(
            Diagnostic(
                "UNSUPPORTED_JUSTIFICATION",
                f"justification {raw!r} is not evaluated by either predicate; preserved as received",
            )
        )
    return result


def extract_evidence(finding: Finding, records: Optional[Stage1Index] = None) -> list[EvidenceItem]:
    """The evidence items of ``extract(finding, records)`` (diagnostics discarded)."""
    return extract(finding, records).items


def _extract_component_not_present(finding: Finding, index: Stage1Index, result: ExtractionResult) -> None:
    primaries, any_primary = _primary_records(finding, index)

    # MATCH
    if finding.component is None:
        result.items.append(
            _unknown(
                DIM_MATCH, None, "NO_TARGET_COMPONENT",
                "no target component was established for this finding; the product's "
                "identifiers are not used as the component's identifier variants",
            )
        )
    else:
        result.diagnostics.append(
            _not_evaluated(DIM_MATCH, "identifier equality and search criteria are an open issue (G13)")
        )

    # INV, DECL and GEN: one item per primary SBOM, or a single item if there is none.
    if not any_primary:
        for dimension in (DIM_INV, DIM_DECL, DIM_GEN):
            result.items.append(
                _unknown(dimension, None, "NO_PRIMARY_SBOM",
                         "no document has the PRIMARY_SBOM role for this finding")
            )
    for doc_id, record in primaries:
        if record is None:
            for dimension in (DIM_INV, DIM_DECL, DIM_GEN):
                result.items.append(
                    _unknown(dimension, doc_id, "RECORD_NOT_SUPPLIED",
                             "no Stage 1 record was supplied for this document")
                )
            continue
        result.items.append(
            _unknown(
                DIM_INV, doc_id, "INV_FULL_LIST_NOT_ESTABLISHED",
                f"{len(record.components)} listed component(s) are accessible, but nothing "
                "establishes that the list is the full inventory for S (open issue G11)",
            )
        )
        if not record.composition_records:
            result.items.append(
                _unknown(DIM_DECL, doc_id, "NO_COMPOSITION_RECORD",
                         "the document declares no composition record")
            )
        else:
            result.items.append(
                _unknown(
                    DIM_DECL, doc_id, "COMPOSITION_SELECTION_UNDETERMINED",
                    "composition record(s) exist, but which one governs the component's "
                    "location is not settled (open issue G6), so none is used",
                    tuple(r.locator for r in record.composition_records),
                )
            )
        if record.document.method is None:
            result.items.append(
                _unknown(DIM_GEN, doc_id, "GEN_METHOD_ABSENT",
                         "the document states no generation method; generation_context is "
                         "not used to infer one")
            )
        else:
            result.diagnostics.append(
                _not_evaluated(DIM_GEN, f"method classification for {doc_id!r} is an open issue (G14)")
            )
    result.diagnostics.append(
        _not_evaluated("BIND", "binding and mismatch semantics are an open issue (G3c, G17)")
    )


def _extract_reachability(finding: Finding, index: Stage1Index, result: ExtractionResult) -> None:
    sbom_docs = sorted(d for d, role in finding.document_roles.items() if role in _SBOM_ROLES)
    emitted = False
    for doc_id in sbom_docs:
        record = index.get(doc_id)
        if record is None or not record.edges:
            continue
        emitted = True
        result.items.append(
            _unknown(
                DIM_REACH, doc_id, "K4_DEPENDENCY_GRAPH_ONLY",
                f"{len(record.edges)} declared dependency edge(s) are package-level "
                "declarations (K4), not call edges; they establish neither reachability "
                "nor non-reachability",
                tuple(edge.locator for edge in record.edges),
            )
        )
    if not emitted:
        result.items.append(
            _unknown(DIM_REACH, None, "NO_ANALYSIS",
                     "no reachability analysis or dependency declaration was supplied")
        )
    for dimension in ("LOCUS", "ENTRY", "HAZ[class]", "CFG", "BIND"):
        result.diagnostics.append(
            _not_evaluated(dimension, "required input records are unavailable (G15) or unsettled")
        )
