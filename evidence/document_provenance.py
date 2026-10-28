"""Document-level provenance P0-P3 and locator-aware item provenance (specification section 1.2).

Builds on ``evidence.provenance`` (P0/P1 from attribution, ``locator_within``, the derived-from
minimum) and adds the two remaining levels, each from a precisely approved input:

* **P2** (register: BIND subject digest rule). A document is P2 iff it is P1 **and** its BIND
  result is ``MATCHED`` with basis ``DIGEST``, was derived from this very document, and carries a
  non-empty list of agreeing digests. Only the BIND *subject* digest is read; a product/version
  binding and hashes on arbitrary components never grant P2. The binding stays self-asserted
  (section 1.2): this is a document's own claim, not verification.
* **P3**. Only from a valid, trusted, externally supplied ``VerificationResult``
  (``evidence.verification``; no cryptography happens here) for exactly this ``doc_id``: the
  result's anchor must be in the configured set, ``verified`` must be true and the result must
  state its established coverage. P3 is cumulative (the document must already be P2) and is
  granted per locator: only an item/list locator that lies within the verified coverage
  (``locator_within``) is P3 ("for the content in question"). Section 1.2 step 3: when coverage is
  established and a locator lies outside it, the level is capped at ``min(level, P1)``. A missing
  locator is outside coverage (G3d). If no result, an untrusted anchor, ``verified = false`` or no
  established coverage, then P3 is not granted and the cap does not apply.

Containment is over whole JSON Pointer segments: coverage of a parent pointer covers its
descendants (``#/components`` covers ``#/components/0``), and coverage of only a child does not
cover the list (``#/components/0`` does not cover ``#/components``). ``#`` covers everything.

Detached verification (U-2 project policy). The result need not correspond to a signature embedded
in the SBOM: an externally supplied detached verification may establish the verification evidence
for a document that has no signature field (SPDX 2.3 JSON has none), under exactly the same
conditions as for a signed document: the result must be bound to the exact ``doc_id``, name a
trust anchor in the caller's configured set, report ``verified``, and state its established
coverage. P3 and the section 1.2 step 3 cap then follow from that coverage alone. This never means
that the SBOM contains a signature; the output says so (``DETACHED_VERIFICATION_LIMITATION``) and
the evaluator performs no cryptographic verification.

What it does not do: it never reads ``signature_verified``, ``established_coverage`` or any
declared signature from a parsed document, never verifies a signature, and never reads a
profile field. P2/P3 say nothing about the accuracy or completeness of the inventory.

``item_levels`` computes the partial effective provenance of evidence items with the existing
``effective_provenance_all`` (steps 1, 4, 5 and the approved G4 behaviour); the locator-specific
document level is supplied through synthetic per-locator keys, so the derived-from minimum is the
tested one.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional, Sequence

from evidence.bind import BindBasis, BindEvaluation
from evidence.cnp_rules import BindState
from evidence.provenance import (
    DocumentEP,
    PartialEP,
    document_level_ep,
    effective_provenance_all,
    locator_within_any,
    min_provenance,
)
from evidence.verification import VerificationConfig, VerificationResult
from model import EvidenceItem, ProvenanceLevel, SourceDocument


DETACHED_VERIFICATION_LIMITATION = (
    "P3_FROM_DETACHED_VERIFICATION_RESULT: the document declares no embedded signature; any P3 grant or "
    "coverage cap rests on an externally supplied verification result (specification A5, register U-2), not on a "
    "signature the document carries"
)


class P2Status(str, Enum):
    GRANTED = "granted"
    NOT_P1 = "not_p1"
    BIND_NOT_MATCHED = "bind_not_matched"
    BIND_BASIS_NOT_DIGEST = "bind_basis_not_digest"
    BIND_FOR_ANOTHER_DOCUMENT = "bind_for_another_document"
    NO_AGREEING_DIGEST = "no_agreeing_digest"


class VerificationUse(str, Enum):
    NOT_SUPPLIED = "not_supplied"
    NO_RESULT_FOR_DOCUMENT = "no_result_for_document"
    UNTRUSTED_ANCHOR = "untrusted_anchor"
    NOT_VERIFIED = "not_verified"
    COVERAGE_NOT_ESTABLISHED = "coverage_not_established"
    APPLIED = "applied"


@dataclass(frozen=True)
class DocumentProvenance:
    """The provenance facts of one document. ``level`` is the document level before any
    locator-specific step (P0, P1 or P2); use ``level_at`` for a locator."""

    doc_id: str
    attribution: DocumentEP
    level: ProvenanceLevel
    p2: P2Status
    p2_digests: tuple[str, ...]
    verification: VerificationUse
    result: Optional[VerificationResult]
    signature_declared: bool = False

    def level_at(self, locator: Optional[str]) -> ProvenanceLevel:
        """Effective document level for content at ``locator``."""
        if self.verification is not VerificationUse.APPLIED:
            return self.level  # no cap and no P3 without established verified coverage
        assert self.result is not None and self.result.established_coverage is not None
        if locator_within_any(locator, self.result.established_coverage):
            return ProvenanceLevel.P3 if self.level >= ProvenanceLevel.P2 else self.level
        return min(self.level, ProvenanceLevel.P1)  # step 3: outside established coverage

    @property
    def limitations(self) -> tuple[str, ...]:
        found = [lim.value for lim in self.attribution.limitations if lim.value != "P2_P3_NOT_EVALUATED"]
        if self.p2 is not P2Status.GRANTED:
            found.append(f"P2_NOT_GRANTED:{self.p2.value}")
        if self.verification is not VerificationUse.APPLIED:
            found.append(f"P3_NOT_AVAILABLE:{self.verification.value}")
        elif not self.signature_declared:
            # U-2 project policy: a trusted, exactly bound, valid external result may establish the
            # verification evidence for a document that embeds no signature field (a detached
            # verification). This is stated in the output so that it is never read as a signature
            # carried by the document.
            found.append(DETACHED_VERIFICATION_LIMITATION)
        return tuple(found)


def _p2(attribution: DocumentEP, doc_id: str, bind: Optional[BindEvaluation]) -> tuple[P2Status, tuple[str, ...]]:
    if attribution.level < ProvenanceLevel.P1:
        return P2Status.NOT_P1, ()
    if bind is None or bind.state is not BindState.MATCHED:
        return P2Status.BIND_NOT_MATCHED, ()
    if bind.document_id != doc_id:
        return P2Status.BIND_FOR_ANOTHER_DOCUMENT, ()
    if bind.basis is not BindBasis.DIGEST:
        return P2Status.BIND_BASIS_NOT_DIGEST, ()
    if not bind.agreeing_digests:
        return P2Status.NO_AGREEING_DIGEST, ()
    return P2Status.GRANTED, tuple(bind.agreeing_digests)


def _verification(doc_id: str, config: Optional[VerificationConfig]) -> tuple[VerificationUse, Optional[VerificationResult]]:
    if config is None:
        return VerificationUse.NOT_SUPPLIED, None
    result = config.result_for(doc_id)
    if result is None:
        return VerificationUse.NO_RESULT_FOR_DOCUMENT, None
    if result.trust_anchor_id not in config.trust_anchors:
        return VerificationUse.UNTRUSTED_ANCHOR, result
    if not result.verified:
        return VerificationUse.NOT_VERIFIED, result
    if result.established_coverage is None:
        return VerificationUse.COVERAGE_NOT_ESTABLISHED, result
    return VerificationUse.APPLIED, result


def document_provenance(
    document: SourceDocument, bind: Optional[BindEvaluation], config: Optional[VerificationConfig]
) -> DocumentProvenance:
    """P0-P3 inputs for ``document``. Pure; ``document`` is not mutated."""
    attribution = document_level_ep(document)
    p2, digests = _p2(attribution, document.doc_id, bind)
    use, result = _verification(document.doc_id, config)
    level = ProvenanceLevel.P2 if p2 is P2Status.GRANTED else attribution.level
    return DocumentProvenance(document.doc_id, attribution, level, p2, digests, use, result,
                              signature_declared=bool(document.integrity.signature))


def record_consumed_integrity(document: SourceDocument, provenance: DocumentProvenance) -> None:
    """Record, on ``document`` (the evaluation's own copy, never a parsed original), the
    verification result that was actually consumed and the digest binding that granted P2.

    Parsers leave these fields unset; this is the only place that sets them, and only from an
    approved source: a ``VerificationResult`` that passed the trust check, or a BIND result.
    ``signature_verified`` records what the external result reported; it does not mean the
    document embeds a signature (for a detached result ``integrity.signature`` stays unset).
    """
    integrity = document.integrity
    if provenance.verification in (VerificationUse.APPLIED, VerificationUse.NOT_VERIFIED,
                                   VerificationUse.COVERAGE_NOT_ESTABLISHED) and provenance.result is not None:
        integrity.signature_verified = provenance.result.verified
        integrity.trust_anchor_id = provenance.result.trust_anchor_id
        if provenance.verification is VerificationUse.APPLIED:
            integrity.established_coverage = list(provenance.result.established_coverage or ())
    if provenance.p2 is P2Status.GRANTED:
        integrity.artifact_digest_binding = ",".join(provenance.p2_digests)


def item_levels(
    items: Sequence[EvidenceItem], provenance: Mapping[str, DocumentProvenance]
) -> list[PartialEP]:
    """Partial effective provenance of every item, aligned with ``items``.

    An item's own level is its document's ``level_at(item.locator)``; an item without a
    ``source_doc`` is P0 and a ``source_doc`` with no provenance entry is P0 with the existing
    ``SOURCE_DOC_LEVEL_UNAVAILABLE`` diagnostic; ``derived_from`` takes the minimum of the chain.
    """
    levels: dict[str, ProvenanceLevel] = {}
    rewritten: list[EvidenceItem] = []
    for item in items:
        if item.source_doc is not None and item.source_doc in provenance:
            key = f"{item.source_doc}\x00{item.locator}"
            levels[key] = provenance[item.source_doc].level_at(item.locator)
            rewritten.append(dataclasses.replace(item, source_doc=key))
        else:
            rewritten.append(item)
    return effective_provenance_all(rewritten, levels)


def minimum_level(provenance: DocumentProvenance, locators: Iterable[Optional[str]]) -> ProvenanceLevel:
    """Minimum ``level_at`` over ``locators`` (EP step 5). With no locator, the document level
    (no locator-specific claim is made for a locator that does not exist)."""
    collected = list(locators)
    if not collected:
        return provenance.level
    return min_provenance(provenance.level_at(locator) for locator in collected)
