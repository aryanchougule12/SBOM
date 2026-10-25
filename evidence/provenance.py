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

NOT implemented (deliberately; see ``docs/open_issues_register.md``): document-level EP
(step 2) including the P0/P1 attribution classifier and P2 digest binding; the
signed-coverage cap (step 3); the "inside the signed analysis" exception to step 4; any
P2/P3 grant from subject hashes, signature presence, or parser metadata; trust anchors.

Because step 2 is not implemented, the level of each source document is an **input**
(``document_levels``): the caller asserts it, and this module does not derive or check
it. A ``source_doc`` that is absent from ``document_levels`` cannot be given a level, so
the item is P0 with a ``SOURCE_DOC_LEVEL_UNAVAILABLE`` diagnostic (an implementation
convention that can only lower a result; flagged in the register).

``locator_within`` is an isolated helper for the later step 3. Its existence does not
mean step 3 is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional, Sequence

from model import EvidenceItem, ProvenanceLevel


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
