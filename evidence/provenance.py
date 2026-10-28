"""Partial effective provenance, EP (specification §1.2; Stage 2, slice 1).

Implemented here, and nothing else:

* **Step 1** -- an item with no ``source_doc`` is P0.
* **Step 4** -- for a *resolved, acyclic* ``derived_from`` chain, a derived item is no
  stronger than the minimum EP of its inputs (and of its own source document).
* **Step 5** -- ``min_provenance``: a pure minimum over an explicitly supplied
  collection of levels. This module does not decide which documents qualify.
* **G4 failure behaviour (approved)** -- an unresolved, ambiguous or cyclic
  ``derived_from`` reference yields P0 plus a diagnostic. It is never ignored and never
  strengthens the result.

* **Step 2, P0/P1 only** -- ``document_level_ep``: the approved strict attribution boundary
  (register G3b, decision 1). A document is P1 only if it states a tool or process
  identity (``tool_name``), a ``tool_version`` and a ``created`` timestamp; otherwise it
  is P0. Nothing here grants P2 or P3.

NOT implemented (deliberately; see ``docs/open_issues_register.md``): P2 (digest binding)
and P3 (verified signature) for a document; the signed-coverage cap (step 3), which can
never lower a P0/P1 result because the cap is ``min(level, P1)``; the "inside the signed
analysis" exception to step 4; any P2/P3 grant from subject hashes, signature presence, or
parser metadata; trust anchors and signature verification (a declared signature and a
declared signed coverage are claims, not verification).

``effective_provenance_all`` still takes the level of each source document as an **input**
(``document_levels``): the caller asserts it, and that function does not derive or check it.
``document_levels`` (below) builds such a mapping from P0/P1 classifications. A
``source_doc`` that is absent from ``document_levels`` cannot be given a level, so the item
is P0 with a ``SOURCE_DOC_LEVEL_UNAVAILABLE`` diagnostic (an implementation convention that
can only lower a result; flagged in the register).

``locator_within`` is an isolated helper for the later step 3. Its existence does not
mean step 3 is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional, Sequence

from model import EvidenceItem, ProvenanceLevel, SourceDocument


class DiagnosticCode(str, Enum):
    SOURCE_DOC_LEVEL_UNAVAILABLE = "SOURCE_DOC_LEVEL_UNAVAILABLE"
    UNRESOLVED_DERIVED_FROM = "UNRESOLVED_DERIVED_FROM"
    AMBIGUOUS_DERIVED_FROM = "AMBIGUOUS_DERIVED_FROM"
    CYCLIC_DERIVATION = "CYCLIC_DERIVATION"


@dataclass(frozen=True)
class ProvenanceDiagnostic:
    code: DiagnosticCode
    detail: str


@dataclass(frozen=True)
class PartialEP:
    """Partial EP of one item. ``diagnostics`` is non-empty whenever a defect forced P0."""

    level: ProvenanceLevel
    diagnostics: tuple[ProvenanceDiagnostic, ...] = ()


def min_provenance(levels: Iterable[ProvenanceLevel]) -> ProvenanceLevel:
    """EP step 5 as a pure minimum over an explicitly supplied collection.

    An empty collection has no minimum; ``ValueError`` is raised rather than choosing a
    level.
    """
    collected = list(levels)
    if not collected:
        raise ValueError("min_provenance requires at least one level")
    for level in collected:
        if not isinstance(level, ProvenanceLevel):
            raise TypeError(f"expected ProvenanceLevel, got {type(level).__name__}")
    return min(collected)


def _name(index: int, item: EvidenceItem) -> str:
    return item.item_id if item.item_id else f"#{index}"


def effective_provenance_all(
    items: Sequence[EvidenceItem],
    document_levels: Mapping[str, ProvenanceLevel],
) -> list[PartialEP]:
    """Partial EP for every item, aligned with ``items`` (steps 1, 4 and G4 only).

    ``derived_from`` entries are resolved against the ``item_id`` values of ``items``. The
    result is deterministic: diagnostics are sorted by ``(code, detail)``.
    """
    by_id: dict[str, list[int]] = {}
    for index, item in enumerate(items):
        if item.item_id is not None:
            by_id.setdefault(item.item_id, []).append(index)

    base_level: list[ProvenanceLevel] = []
    base_diag: list[list[ProvenanceDiagnostic]] = []
    for index, item in enumerate(items):
        diags: list[ProvenanceDiagnostic] = []
        if item.source_doc is None:  # step 1
            level = ProvenanceLevel.P0
        elif item.source_doc in document_levels:
            level = document_levels[item.source_doc]
            if not isinstance(level, ProvenanceLevel):
                raise TypeError(f"document level for {item.source_doc!r} is not a ProvenanceLevel")
        else:
            level = ProvenanceLevel.P0
            diags.append(
                ProvenanceDiagnostic(
                    DiagnosticCode.SOURCE_DOC_LEVEL_UNAVAILABLE,
                    f"item {_name(index, item)}: no level supplied for source document "
                    f"{item.source_doc!r}",
                )
            )
        base_level.append(level)
        base_diag.append(diags)

    results: list[PartialEP] = []
    for root in range(len(items)):
        level = ProvenanceLevel.P3
        diagnostics: list[ProvenanceDiagnostic] = []
        defect = False
        seen: set[int] = set()
        state: dict[int, int] = {}  # 1 = on the DFS stack, 2 = finished
        path: list[int] = []

        def visit(node: int) -> None:
            nonlocal level, defect
            state[node] = 1
            path.append(node)
            seen.add(node)
            level = min(level, base_level[node])
            diagnostics.extend(base_diag[node])
            for parent in items[node].derived_from:
                targets = by_id.get(parent, []) if isinstance(parent, str) and parent else []
                if not targets:
                    defect = True
                    diagnostics.append(
                        ProvenanceDiagnostic(
                            DiagnosticCode.UNRESOLVED_DERIVED_FROM,
                            f"item {_name(node, items[node])}: derived_from {parent!r} "
                            f"does not name any item",
                        )
                    )
                    continue
                if len(targets) > 1:
                    defect = True
                    diagnostics.append(
                        ProvenanceDiagnostic(
                            DiagnosticCode.AMBIGUOUS_DERIVED_FROM,
                            f"item {_name(node, items[node])}: derived_from {parent!r} "
                            f"names {len(targets)} items",
                        )
                    )
                    continue
                target = targets[0]
                if state.get(target) == 1:
                    defect = True
                    cycle = path[path.index(target):] + [target]
                    diagnostics.append(
                        ProvenanceDiagnostic(
                            DiagnosticCode.CYCLIC_DERIVATION,
                            "derivation cycle: "
                            + " -> ".join(_name(i, items[i]) for i in cycle),
                        )
                    )
                elif target not in state:
                    visit(target)
            path.pop()
            state[node] = 2

        visit(root)
        if defect:
            level = ProvenanceLevel.P0
        unique = sorted(set(diagnostics), key=lambda d: (d.code.value, d.detail))
        results.append(PartialEP(level, tuple(unique)))
    return results


def effective_provenance(
    item: EvidenceItem,
    items: Sequence[EvidenceItem],
    document_levels: Mapping[str, ProvenanceLevel],
) -> PartialEP:
    """Partial EP of ``item``, which must be one of ``items`` (compared by identity)."""
    for index, candidate in enumerate(items):
        if candidate is item:
            return effective_provenance_all(items, document_levels)[index]
    raise ValueError("item is not a member of the supplied items")


# ---- document-level EP, step 2, P0/P1 only ------------------------------------------------

class AttributionGap(str, Enum):
    """A condition of P1 (specification section 1.2: "tool or process, version, and
    timestamp known"; strict reading, register G3b) that the document does not state."""

    TOOL_NAME_MISSING = "TOOL_NAME_MISSING"
    TOOL_VERSION_MISSING = "TOOL_VERSION_MISSING"
    CREATED_MISSING = "CREATED_MISSING"


class EpLimitation(str, Enum):
    """Why a document-level result is a lower bound and not a full step 2 result."""

    P2_P3_NOT_EVALUATED = "P2_P3_NOT_EVALUATED"
    SIGNATURE_DECLARED_NOT_VERIFIED = "SIGNATURE_DECLARED_NOT_VERIFIED"
    TOOL_FIELDS_FROM_PARSER_HEURISTIC = "TOOL_FIELDS_FROM_PARSER_HEURISTIC"


@dataclass(frozen=True)
class DeclaredIntegrity:
    """Integrity information as the document or a verification step recorded it, copied
    without interpretation. Declared claims and verified results are kept apart:
    ``signature_declared`` and ``signed_coverage_declared`` are claims read from the input;
    ``signature_verified`` and ``verified_coverage_established`` come from a verification
    step, which no parser performs, so for parsed documents they are ``None`` and
    ``False``. Nothing here changes the level."""

    signature_declared: bool
    signed_coverage_declared: tuple[str, ...]
    signature_verified: Optional[bool]
    verified_coverage_established: bool
    artifact_digest_binding: Optional[str]


@dataclass(frozen=True)
class DocumentEP:
    """The P0/P1 classification of one source document.

    ``level`` is P1 exactly when ``attribution_gaps`` is empty, otherwise P0. It is a lower
    bound: P2 and P3 are not evaluated (``limitations`` always says so), so a P1 result
    never means the document is not P2 or P3, only that this function grants neither.
    ``producer_declared`` records whether any producer was stated; under the strict reading
    a producer without tool identity, version and timestamp is still P0.
    """

    doc_id: str
    level: ProvenanceLevel
    attribution_gaps: tuple[AttributionGap, ...]
    producer_declared: bool
    integrity: DeclaredIntegrity
    limitations: tuple[EpLimitation, ...]

    def __post_init__(self) -> None:
        if self.level not in (ProvenanceLevel.P0, ProvenanceLevel.P1):
            raise ValueError("a document-level result here is P0 or P1 only")
        if (self.level is ProvenanceLevel.P1) != (not self.attribution_gaps):
            raise ValueError("P1 requires, and only requires, that no attribution gap exists")
        if EpLimitation.P2_P3_NOT_EVALUATED not in self.limitations:
            raise ValueError("the P2/P3 limitation must always be stated")


def _stated(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def document_level_ep(document: SourceDocument) -> DocumentEP:
    """Classify ``document`` as P0 or P1 under the approved strict attribution boundary.

    P1 needs all of ``tool_name``, ``tool_version`` (non-blank) and ``created``. The
    evaluator-supplied process attestation that decision 1 allows has no representation yet,
    so it cannot raise a level. Pure: reads the document, mutates nothing, and never sets
    ``signature_verified``, ``trust_anchor_id``, ``established_coverage`` or
    ``artifact_digest_binding``.
    """
    gaps: list[AttributionGap] = []
    if not _stated(document.tool_name):
        gaps.append(AttributionGap.TOOL_NAME_MISSING)
    if not _stated(document.tool_version):
        gaps.append(AttributionGap.TOOL_VERSION_MISSING)
    if document.created is None:
        gaps.append(AttributionGap.CREATED_MISSING)
    level = ProvenanceLevel.P0 if gaps else ProvenanceLevel.P1

    integrity = document.integrity
    declared = DeclaredIntegrity(
        signature_declared=integrity.signature is not None,
        signed_coverage_declared=tuple(sorted(integrity.signed_coverage)),
        signature_verified=integrity.signature_verified,
        verified_coverage_established=integrity.established_coverage is not None,
        artifact_digest_binding=integrity.artifact_digest_binding,
    )
    limitations = [EpLimitation.P2_P3_NOT_EVALUATED]
    if declared.signature_declared and declared.signature_verified is not True:
        limitations.append(EpLimitation.SIGNATURE_DECLARED_NOT_VERIFIED)
    if level is ProvenanceLevel.P1 and document.declared_metadata.get("format") == "SPDX":
        limitations.append(EpLimitation.TOOL_FIELDS_FROM_PARSER_HEURISTIC)  # the Tool: creator split
    return DocumentEP(
        doc_id=document.doc_id,
        level=level,
        attribution_gaps=tuple(gaps),
        producer_declared=_stated(document.producer),
        integrity=declared,
        limitations=tuple(limitations),
    )


def document_levels(documents: Iterable[SourceDocument]) -> dict[str, ProvenanceLevel]:
    """``doc_id -> level`` for ``effective_provenance_all``, from ``document_level_ep``.

    Repeating a document with the same classification is harmless; two documents that share
    a ``doc_id`` but classify differently raise ``ValueError`` rather than choosing one.
    """
    levels: dict[str, ProvenanceLevel] = {}
    for document in documents:
        level = document_level_ep(document).level
        if levels.setdefault(document.doc_id, level) is not level:
            raise ValueError(f"conflicting classifications for document {document.doc_id!r}")
    return levels


# ---- locator containment (isolated helper for the later step 3) -----------------------

def _segments(locator: str) -> tuple[str, ...]:
    if not locator.startswith("#"):
        raise ValueError(f"not a URI-fragment JSON Pointer locator: {locator!r}")
    rest = locator[1:]
    if rest == "":
        return ()
    if not rest.startswith("/"):
        raise ValueError(f"not a URI-fragment JSON Pointer locator: {locator!r}")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in rest[1:].split("/"))


def locator_within(locator: Optional[str], coverage_entry: str) -> bool:
    """True iff ``locator`` equals or lies below ``coverage_entry``, compared over whole
    JSON Pointer path segments (``#/components/1`` is NOT within ``#/components/10``;
    ``#`` covers everything). A missing locator (``None``) is outside any coverage
    (approved G3d convention). Malformed locators raise ``ValueError``.

    This is containment only. It does not compute the signed-coverage cap, and
    ``coverage_entry`` is not checked against any verification result.
    """
    entry = _segments(coverage_entry)
    if locator is None:
        return False
    target = _segments(locator)
    return target[: len(entry)] == entry


def locator_within_any(locator: Optional[str], coverage: Iterable[str]) -> bool:
    """``locator_within`` against any entry of ``coverage`` (empty coverage: False)."""
    return any(locator_within(locator, entry) for entry in coverage)
