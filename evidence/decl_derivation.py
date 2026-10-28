"""DECL derivation and the "covers S" rule (specification section 4.1; register G6, G1r).

DECL is "the completeness declaration for the scope containing C's would-be location. Use the
most specific composition record, and fall back to document level only if it covers S."
This module applies the approved choices (G6-D1 to D13 and this milestone's D4/D5) to the
candidates that ``evidence.decl_candidates`` enumerates; it does not re-decide them.

Inputs: the primary SBOM record, the profile's ``would_be_location`` (document, explicit
placement and, for a nested placement, the direct parent's ``bom-ref``), the BIND result and
the INV derivation. Order of evaluation, and the state each outcome gives:

1. Document identities of the record, BIND and INV must agree; otherwise `Unknown`.
2. SPDX (or any non-CycloneDX record) has no standardized completeness declaration: `Unknown`.
3. No location, a location in another document, or an unspecified placement: `Unknown`; nothing is
   selected from a guessed parent or position (G6-D6).
4. BIND not ``MATCHED``: `Unknown`. A declaration of a document that is not bound to S is not a
   declaration about S.
5. **Component-specific path.** If a record names the would-be target's direct parent assembly
   (G6-D1, D11, D12), the DECL state is the G6-D8 worst case of the equally applicable records
   (`Present`, `Incomplete` or `Unknown`). A more specific candidate always takes precedence over
   the document-level fallback; the fallback is then not consulted.
6. **Document-level fallback** (G6-D3, D13), only when there is no component-specific candidate.
   A root-named record *covers S* only when **all** hold: BIND ``MATCHED``; every root-named
   record that applies to this position has aggregate ``complete``; the evaluator's
   ``full_component_list`` assertion is usable; INV is `Present` (so every required structural
   check was performed and found no applicable contradiction); the target position is
   demonstrably in the root-level scope (a top-level placement, or beneath a top-level component,
   or beneath a root child) ; and no component-specific candidate exists. Then the DECL state is
   `Present` with the root records as its basis. If any condition fails, or if root-named records
   disagree (G6-D8), DECL is `Unknown`. A root record's existence or `complete` aggregate alone
   never covers S.

BOM-Link references stay unresolved (G6-D5); unresolved or missing parents and targets give
`Unknown`. DECL `Contradictory`, `Absent` and `Ambiguous` are never produced. This module
computes no provenance; ``record_locators`` lets the caller assign PROV_DECL from the locators of
the records that were actually used.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from evidence.bind import BindEvaluation
from evidence.cnp_rules import BindState
from evidence.decl_candidates import (
    DeclEnumeration,
    EnumerationStatus,
    TargetPosition,
    enumerate_decl_candidates_for_placement,
)
from evidence.inv import AssertionStatus, InvDerivation
from evidence.profile import WouldBeLocation
from evidence.stage1_records import FORMAT_CYCLONEDX, SbomRecord
from model import EvidenceState


class DeclPath(str, Enum):
    COMPONENT_SPECIFIC = "component_specific"
    DOCUMENT_LEVEL_FALLBACK = "document_level_fallback"
    NONE = "none"


class CoversSResult(str, Enum):
    ESTABLISHED = "established"
    NOT_ESTABLISHED = "not_established"
    NOT_EVALUATED = "not_evaluated"  # the fallback was not consulted


class DeclReason(str, Enum):
    COMPONENT_SPECIFIC_RECORD = "DECL_COMPONENT_SPECIFIC_RECORD"
    ROOT_RECORD_COVERS_S = "DECL_ROOT_RECORD_COVERS_S"
    DOCUMENT_IDENTITY_MISMATCH = "DECL_DOCUMENT_IDENTITY_MISMATCH"
    NO_COMPLETENESS_DECLARATION_FORMAT = "DECL_NO_COMPLETENESS_DECLARATION_FORMAT"
    NO_TARGET_LOCATION = "DECL_NO_TARGET_LOCATION"
    LOCATION_FOR_ANOTHER_DOCUMENT = "DECL_LOCATION_FOR_ANOTHER_DOCUMENT"
    PLACEMENT_UNSPECIFIED = "DECL_PLACEMENT_UNSPECIFIED"
    BIND_NOT_MATCHED = "DECL_BIND_NOT_MATCHED"
    TARGET_LOCATION_UNRESOLVED = "DECL_TARGET_LOCATION_UNRESOLVED"
    NO_APPLICABLE_RECORD = "DECL_NO_APPLICABLE_RECORD"
    COMPONENT_SPECIFIC_NOT_COMPLETE = "DECL_COMPONENT_SPECIFIC_NOT_COMPLETE"
    COMPONENT_SPECIFIC_UNKNOWN = "DECL_COMPONENT_SPECIFIC_UNKNOWN"
    COVERS_S_NOT_ESTABLISHED = "DECL_COVERS_S_NOT_ESTABLISHED"


@dataclass(frozen=True)
class DeclDerivation:
    """The derived DECL state. ``record_locators`` are the composition records actually used
    (empty for `Unknown` without a record). ``unmet_covers_s`` lists, for the fallback, every
    condition of "covers S" that does not hold."""

    state: EvidenceState
    reason: DeclReason
    doc_id: str
    path: DeclPath = DeclPath.NONE
    covers_s: CoversSResult = CoversSResult.NOT_EVALUATED
    record_locators: tuple[str, ...] = ()
    unmet_covers_s: tuple[str, ...] = ()
    enumeration: Optional[DeclEnumeration] = None

    def __post_init__(self) -> None:
        if self.state not in (EvidenceState.PRESENT, EvidenceState.INCOMPLETE, EvidenceState.UNKNOWN):
            raise ValueError("DECL derivation produces Present, Incomplete or Unknown only")
        if self.state is EvidenceState.PRESENT and not self.record_locators:
            raise ValueError("DECL Present needs the record(s) it rests on")
        if self.path is DeclPath.DOCUMENT_LEVEL_FALLBACK and self.state is EvidenceState.PRESENT \
                and self.covers_s is not CoversSResult.ESTABLISHED:
            raise ValueError("a document-level fallback is Present only when it covers S")


_IN_SCOPE_POSITIONS = (TargetPosition.TOP_LEVEL, TargetPosition.BELOW_TOP_LEVEL, TargetPosition.BELOW_ROOT_CHILD)


def _unknown(reason: DeclReason, doc_id: str, enumeration: Optional[DeclEnumeration] = None,
             covers_s: CoversSResult = CoversSResult.NOT_EVALUATED, unmet: tuple[str, ...] = ()) -> DeclDerivation:
    return DeclDerivation(EvidenceState.UNKNOWN, reason, doc_id, DeclPath.NONE, covers_s, (), unmet, enumeration)


def derive_decl(
    record: SbomRecord,
    location: Optional[WouldBeLocation],
    bind: BindEvaluation,
    inv: InvDerivation,
) -> DeclDerivation:
    """Derive DECL for the would-be target at ``location`` in ``record``. Pure."""
    doc_id = record.doc_id
    if not (bind.document_id == doc_id == inv.document_id):
        return _unknown(DeclReason.DOCUMENT_IDENTITY_MISMATCH, doc_id)
    if record.format != FORMAT_CYCLONEDX:
        return _unknown(DeclReason.NO_COMPLETENESS_DECLARATION_FORMAT, doc_id)
    if location is None:
        return _unknown(DeclReason.NO_TARGET_LOCATION, doc_id)
    if location.document != doc_id:
        return _unknown(DeclReason.LOCATION_FOR_ANOTHER_DOCUMENT, doc_id)
    if location.placement is None:
        return _unknown(DeclReason.PLACEMENT_UNSPECIFIED, doc_id)
    if bind.state is not BindState.MATCHED:
        return _unknown(DeclReason.BIND_NOT_MATCHED, doc_id)

    enumeration = enumerate_decl_candidates_for_placement(record, location.placement, location.parent_ref)

    if enumeration.status is EnumerationStatus.CANDIDATES_FOUND:  # more specific than any fallback
        group = enumeration.groups[0]
        locators = tuple(sorted(m.record_locator for m in group.members))
        if group.state is EvidenceState.PRESENT:
            return DeclDerivation(EvidenceState.PRESENT, DeclReason.COMPONENT_SPECIFIC_RECORD, doc_id,
                                  DeclPath.COMPONENT_SPECIFIC, CoversSResult.NOT_EVALUATED, locators, (), enumeration)
        reason = (DeclReason.COMPONENT_SPECIFIC_NOT_COMPLETE if group.state is EvidenceState.INCOMPLETE
                  else DeclReason.COMPONENT_SPECIFIC_UNKNOWN)
        return DeclDerivation(group.state, reason, doc_id, DeclPath.COMPONENT_SPECIFIC, CoversSResult.NOT_EVALUATED,
                              locators, (), enumeration)

    if enumeration.status is EnumerationStatus.TARGET_NOT_IN_DOCUMENT:
        return _unknown(DeclReason.TARGET_LOCATION_UNRESOLVED, doc_id, enumeration)
    if enumeration.status is EnumerationStatus.TARGET_LOCATION_UNAVAILABLE:
        return _unknown(DeclReason.PLACEMENT_UNSPECIFIED, doc_id, enumeration)
    # No component-specific candidate: the document-level fallback is the only route.
    roots = [r for r in enumeration.root_level_candidates if r.target_position in _IN_SCOPE_POSITIONS]
    if not roots:
        return _unknown(DeclReason.NO_APPLICABLE_RECORD, doc_id, enumeration)

    unmet: list[str] = []
    if not all(r.necessary_condition_met for r in roots):
        unmet.append("every root-named record applying to this position must have aggregate 'complete'")
    if inv.assertion is not AssertionStatus.USABLE:
        unmet.append("a usable full_component_list assertion")
    if inv.state is not EvidenceState.PRESENT:
        unmet.append("INV is Present (all required structural checks performed, no applicable contradiction)")
    # BIND MATCHED, a component-specific-free position and an in-scope target position hold here.
    if unmet:
        return _unknown(DeclReason.COVERS_S_NOT_ESTABLISHED, doc_id, enumeration,
                        CoversSResult.NOT_ESTABLISHED, tuple(unmet))
    locators = tuple(sorted(r.record_locator for r in roots))
    return DeclDerivation(EvidenceState.PRESENT, DeclReason.ROOT_RECORD_COVERS_S, doc_id,
                          DeclPath.DOCUMENT_LEVEL_FALLBACK, CoversSResult.ESTABLISHED, locators, (), enumeration)
