"""Six-state aggregation within one dimension (specification §2; Stage 2, slice 1).

Pure function over the ``EvidenceItem`` states supplied for **one finding and one
dimension**. The caller is responsible for supplying only that finding's items; the
dimension is checked here (items of different dimensions are never aggregated together).

Procedure (``docs/formal_specification_v0.2.md`` §2), as implemented:

1. Discard ``Unknown`` items when any other informative item exists. If there are no
   items, or all items are ``Unknown``, the aggregate is ``Unknown`` (the two inputs are
   reported with distinct reasons, ``NO_ITEMS`` and ``ALL_UNKNOWN``).
2. ``Present`` against ``Absent`` over overlapping scope gives ``Contradictory``.
3. An unambiguous positive observation with no overlapping-scope absence gives
   ``Present``, even if other items are ``Incomplete``.
4. Otherwise the most degraded remaining state: ``Ambiguous`` > ``Incomplete`` >
   ``Absent``. ``Absent`` is returned only when an ``Absent`` item was supplied; it is
   never produced by the lack of items.
5. Coverage is never inferred from a union of ``Incomplete`` items; two ``Incomplete``
   items aggregate to ``Incomplete``.

Approved provisional conventions (NOT amendments to the formal specification; see
``docs/open_issues_register.md``, G8, U-9):

* Overlap: items supplied for the same finding and dimension are treated as overlapping.
  Document-relative locators are never compared across documents.
* A supplied ``Contradictory`` item dominates the aggregate.

Specification-determined (not a convention): ``Present`` + ``Ambiguous`` gives
``Present``. This follows from the literal §2 step 3 procedure (positive observation's
conditions do not reference other items' states), corroborated by M-4/N1 consistency,
not exemplified by any AG case. Step 4 ("Otherwise") is not reached.

The function trusts ``EvidenceItem.state``: it cannot verify that an ``Absent`` item
really comes from a source with declared sufficient coverage. That is the producer's
responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from model import EvidenceItem, EvidenceState


class AggregationReason(str, Enum):
    """Which part of the procedure decided the aggregate (for audit and tests)."""

    NO_ITEMS = "no_items"
    ALL_UNKNOWN = "all_unknown"
    CONTRADICTORY_ITEM = "contradictory_item"
    PRESENT_VS_ABSENT = "present_vs_absent"
    POSITIVE_OBSERVATION = "positive_observation"
    AMBIGUOUS = "ambiguous"
    INCOMPLETE = "incomplete"
    ABSENT = "absent"


@dataclass(frozen=True)
class AggregationResult:
    state: EvidenceState
    reason: AggregationReason
    dimension: str | None  # None only when no items were supplied


def aggregate(items: Iterable[EvidenceItem]) -> AggregationResult:
    """Aggregate the states of ``items`` (one finding, one dimension).

    Raises ``TypeError`` for a non-``EvidenceItem`` or a ``state`` that is not an
    ``EvidenceState``, and ``ValueError`` if the items span more than one dimension.
    """
    collected = list(items)
    dimensions: set[str] = set()
    for item in collected:
        if not isinstance(item, EvidenceItem):
            raise TypeError(f"expected EvidenceItem, got {type(item).__name__}")
        if not isinstance(item.state, EvidenceState):
            raise TypeError(f"item state must be an EvidenceState, got {item.state!r}")
        dimensions.add(item.dimension)
    if len(dimensions) > 1:
        raise ValueError(
            "items span multiple dimensions and cannot be aggregated together: "
            + ", ".join(sorted(dimensions))
        )
    dimension = next(iter(dimensions), None)

    if not collected:
        return AggregationResult(EvidenceState.UNKNOWN, AggregationReason.NO_ITEMS, None)

    states = {item.state for item in collected} - {EvidenceState.UNKNOWN}  # step 1
    if not states:
        return AggregationResult(EvidenceState.UNKNOWN, AggregationReason.ALL_UNKNOWN, dimension)

    if EvidenceState.CONTRADICTORY in states:  # approved G8 convention
        return AggregationResult(
            EvidenceState.CONTRADICTORY, AggregationReason.CONTRADICTORY_ITEM, dimension
        )
    if EvidenceState.PRESENT in states:
        if EvidenceState.ABSENT in states:  # step 2 under the approved overlap convention
            return AggregationResult(
                EvidenceState.CONTRADICTORY, AggregationReason.PRESENT_VS_ABSENT, dimension
            )
        return AggregationResult(  # step 3
            EvidenceState.PRESENT, AggregationReason.POSITIVE_OBSERVATION, dimension
        )
    if EvidenceState.AMBIGUOUS in states:  # step 4
        return AggregationResult(EvidenceState.AMBIGUOUS, AggregationReason.AMBIGUOUS, dimension)
    if EvidenceState.INCOMPLETE in states:  # also covers step 5 (no union inference)
        return AggregationResult(EvidenceState.INCOMPLETE, AggregationReason.INCOMPLETE, dimension)
    return AggregationResult(EvidenceState.ABSENT, AggregationReason.ABSENT, dimension)


def aggregate_state(items: Iterable[EvidenceItem]) -> EvidenceState:
    """Convenience wrapper returning only the aggregate ``EvidenceState``."""
    return aggregate(items).state
