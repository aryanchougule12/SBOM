"""Typed evidence items for the reachability pipeline (specification section 1, "E").

Items for REACH, LOCUS and ENTRY, in the same ``model.EvidenceItem`` form as the CNP items
(``evidence.items``): ``(dimension, state, value_or_ref, source_doc, locator, derived_from[])``
plus the stable ``item_id``, with a frozen typed payload that keeps the reason and the facts the
state rests on. No state beyond the six of section 2 is used.

Not items, following the BIND precedent of ``evidence.items``: BIND (its ``matched`` /
``mismatched`` / ``unknown`` outcome has no evidence state, register G17), the hazard
dispositions of §5.2 (four values that are not evidence states) and CFG. They stay typed
inputs of the rule engine and are reported with their own traceability records
(``evidence.reach_derivation.HazardAssessment`` and friends).

Identity and traceability, all checked by ``validate_reach_items``:

* a document item's ``source_doc`` is the exact id of a document registered in the finding's
  ``source_documents`` with the ``reachability_report`` role; the K4 item belongs to the
  ``primary_sbom`` document; an item with no ``source_doc`` is an evaluator-entered statement
  (LOCUS or ENTRY) and is P0 (§1.2 rule 1). Nothing else may lack a document;
* an item's ``locator`` is one of the fixed locators of its document (a K1/K2/K3 report:
  ``#/finding`` for REACH, ``#/entry_points`` for ENTRY; the SBOM's K4 item: ``#``). The validator
  never accepts a locator because it looks plausible;
* ``item_id`` is non-empty, unique and deterministic (``<DIM>:<doc_id>:<locator>``);
* the state is allowed for the dimension and **is the state the payload supports**: it is
  recomputed from the payload's facts (``observation_state`` and friends), so an item cannot claim
  an ``Absent`` that the evidence does not support, a K2/K3 ``Absent``, or a K4 state other than
  ``Unknown``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from evidence.analysis_model import ObservationTrace
from evidence.items import ItemIntegrityError, ItemPayload, item_id
from evidence.reach_derivation import (
    DIM_ENTRY,
    DIM_LOCUS,
    DIM_REACH,
    K4,
    REPORT_ENTRY_LOCATOR,
    REPORT_FINDING_LOCATOR,
    SBOM_GRAPH_LOCATOR,
    DependencyGraphFacts,
    DocumentAssessment,
    entry_item_state,
    locus_item_state,
    observation_state,
)
from evidence.reach_inputs import EntryInput, LocusInput, ReachDocument, ReachFinding, ReachKind, ReachabilityEvidence
from evidence.reach_rules import ReachBasis
from model import DocumentRole, EvidenceItem, EvidenceState, Finding, ProvenanceLevel

NO_DOCUMENT = "-"


@dataclass(frozen=True)
class ReachPayload(ItemPayload):
    kind: str = ""                       # K1 | K2 | K3 | K4
    finding: Optional[str] = None        # what the document reports (None for K4)
    ep: Optional[ProvenanceLevel] = None  # the document's EP at the item locator (None for K4)
    full_coverage_claim: bool = False
    basis: Optional[ReachBasis] = None
    graph: Optional[DependencyGraphFacts] = None
    trace: Optional[ObservationTrace] = None   # set for an observation derived from an analyzer artifact


@dataclass(frozen=True)
class LocusPayload(ItemPayload):
    locus: Optional[LocusInput] = None


@dataclass(frozen=True)
class EntryPayload(ItemPayload):
    complete: bool = False
    origin: str = ""  # document | evaluator
    entered_by: Optional[str] = None


_ALLOWED_STATES = {
    DIM_REACH: frozenset({EvidenceState.PRESENT, EvidenceState.ABSENT, EvidenceState.INCOMPLETE,
                          EvidenceState.AMBIGUOUS, EvidenceState.UNKNOWN}),
    DIM_LOCUS: frozenset({EvidenceState.PRESENT, EvidenceState.INCOMPLETE, EvidenceState.UNKNOWN}),
    DIM_ENTRY: frozenset({EvidenceState.PRESENT, EvidenceState.INCOMPLETE}),
}
_PAYLOAD_TYPES = {DIM_REACH: ReachPayload, DIM_LOCUS: LocusPayload, DIM_ENTRY: EntryPayload}


def _id(dimension: str, doc_id: Optional[str], locator: Optional[str]) -> str:
    return item_id(dimension, doc_id or NO_DOCUMENT, locator)


def build_reach_items(
    evidence: ReachabilityEvidence,
    assessments: Mapping[str, DocumentAssessment],
    sbom_doc_id: str,
    graph: DependencyGraphFacts,
) -> tuple[EvidenceItem, ...]:
    """The items of one evaluation in a fixed order: REACH (K4 first, then documents in input
    order), LOCUS, ENTRY (documents in input order, then the evaluator's statement)."""
    items: list[EvidenceItem] = []
    if graph.present:
        items.append(EvidenceItem(
            dimension=DIM_REACH, state=EvidenceState.UNKNOWN,
            value_or_ref=ReachPayload(DIM_REACH, "K4_DEPENDENCY_GRAPH_ONLY",
                                      ("a dependency edge is not a call edge (A5)",), kind=K4, graph=graph),
            source_doc=sbom_doc_id, locator=SBOM_GRAPH_LOCATOR, item_id=_id(DIM_REACH, sbom_doc_id, SBOM_GRAPH_LOCATOR),
        ))
    for document in evidence.documents:
        if document.kind is ReachKind.HAZARD_BASIS:
            continue
        assessment = assessments[document.doc_id]
        if document.source is not None and document.finding is ReachFinding.POSITIVE:  # one item per recorded path, at its raw-artifact locator
            for trace in document.source.traces:
                ep = assessment.level_at(trace.locator)
                state, basis, reason = observation_state(document, ep)
                items.append(EvidenceItem(
                    dimension=DIM_REACH, state=state,
                    value_or_ref=ReachPayload(DIM_REACH, reason, document.source.limitations, document.kind.value,
                                              document.finding.value if document.finding else None, ep, False, basis, None, trace),
                    source_doc=document.doc_id, locator=trace.locator,
                    item_id=item_id(DIM_REACH, document.doc_id, trace.locator, f"@{trace.observation_id}"),
                ))
            continue
        ep = assessment.level_at(REPORT_FINDING_LOCATOR)
        state, basis, reason = observation_state(document, ep)
        items.append(EvidenceItem(
            dimension=DIM_REACH, state=state,
            value_or_ref=ReachPayload(DIM_REACH, reason, (), document.kind.value, document.finding.value if document.finding else None,
                                      ep, document.full_coverage_claim, basis),
            source_doc=document.doc_id, locator=REPORT_FINDING_LOCATOR,
            item_id=_id(DIM_REACH, document.doc_id, REPORT_FINDING_LOCATOR),
        ))
    if evidence.locus is not None:
        state, reason = locus_item_state(evidence.locus)
        items.append(EvidenceItem(
            dimension=DIM_LOCUS, state=state,
            value_or_ref=LocusPayload(DIM_LOCUS, reason, ("evaluator-entered, unauthenticated; no source document (P0)",), evidence.locus),
            source_doc=None, locator=None, item_id=_id(DIM_LOCUS, None, None),
        ))
    for document in evidence.documents:
        if document.entry_points_complete is not None:
            state, reason = entry_item_state(document.entry_points_complete)
            items.append(EvidenceItem(
                dimension=DIM_ENTRY, state=state,
                value_or_ref=EntryPayload(DIM_ENTRY, reason, (), document.entry_points_complete, "document"),
                source_doc=document.doc_id, locator=REPORT_ENTRY_LOCATOR,
                item_id=_id(DIM_ENTRY, document.doc_id, REPORT_ENTRY_LOCATOR),
            ))
    if evidence.entry_points is not None:
        entry: EntryInput = evidence.entry_points
        state, reason = entry_item_state(entry.complete)
        items.append(EvidenceItem(
            dimension=DIM_ENTRY, state=state,
            value_or_ref=EntryPayload(DIM_ENTRY, reason, ("evaluator-entered, unauthenticated; no source document (P0)",),
                                      entry.complete, "evaluator", entry.entered_by),
            source_doc=None, locator=None, item_id=_id(DIM_ENTRY, None, None),
        ))
    return tuple(items)


def validate_reach_items(finding: Finding, sbom_doc_id: str, items: Iterable[EvidenceItem],
                         observation_locators: Optional[Mapping[str, frozenset]] = None) -> None:
    """Raise ``ItemIntegrityError`` unless every item is traceable (see the module docstring)."""
    collected = list(items)
    seen: set[str] = set()
    for item in collected:
        if not item.item_id:
            raise ItemIntegrityError("ITEM_ID_MISSING", item.item_id, "an item needs a stable id")
        if item.item_id in seen:
            raise ItemIntegrityError("ITEM_ID_DUPLICATE", item.item_id, "item ids must be unique")
        seen.add(item.item_id)
    for item in collected:
        if item.derived_from:
            raise ItemIntegrityError("ITEM_PARENT_MISSING", item.item_id, "reachability observation items are not derived from other items")
        if item.dimension not in _ALLOWED_STATES:
            raise ItemIntegrityError("ITEM_DIMENSION_INVALID", item.item_id, f"dimension {item.dimension!r} is not REACH, LOCUS or ENTRY")
        if not isinstance(item.state, EvidenceState):
            raise ItemIntegrityError("ITEM_STATE_INVALID", item.item_id, "the state is not one of the six evidence states")
        if item.state not in _ALLOWED_STATES[item.dimension]:
            raise ItemIntegrityError("ITEM_STATE_NOT_ALLOWED", item.item_id, f"{item.dimension} cannot be {item.state.value} here")
        payload = item.value_or_ref
        if not isinstance(payload, _PAYLOAD_TYPES[item.dimension]) or payload.dimension != item.dimension:
            raise ItemIntegrityError("ITEM_PAYLOAD_INVALID", item.item_id,
                                     f"{item.dimension} items carry a {_PAYLOAD_TYPES[item.dimension].__name__}")
        _validate_source(item, finding, sbom_doc_id, observation_locators or {})
        _validate_claim(item, finding)


def _validate_source(item: EvidenceItem, finding: Finding, sbom_doc_id: str, observation_locators: Mapping[str, frozenset]) -> None:
    payload = item.value_or_ref
    evaluator_entered = item.dimension == DIM_LOCUS or (item.dimension == DIM_ENTRY and payload.origin == "evaluator")
    if item.source_doc is None:
        if not evaluator_entered or item.locator is not None:
            raise ItemIntegrityError("ITEM_SOURCE_MISSING", item.item_id, "only an evaluator-entered LOCUS or ENTRY statement has no document")
        return
    if evaluator_entered:
        raise ItemIntegrityError("ITEM_SOURCE_NOT_ALLOWED", item.item_id, "an evaluator-entered statement has no source document")
    if item.source_doc not in finding.source_documents:
        raise ItemIntegrityError("ITEM_SOURCE_NOT_REGISTERED", item.item_id,
                                 f"source_doc {item.source_doc!r} is not in the finding's source_documents")
    role = finding.document_roles.get(item.source_doc)
    is_k4 = item.dimension == DIM_REACH and payload.kind == K4
    if is_k4:
        if item.source_doc != sbom_doc_id or role is not DocumentRole.PRIMARY_SBOM or item.locator != SBOM_GRAPH_LOCATOR:
            raise ItemIntegrityError("ITEM_ROLE_MISSING", item.item_id, "the K4 item belongs to the primary SBOM at its document root")
        return
    if role is not DocumentRole.REACHABILITY_REPORT:
        raise ItemIntegrityError("ITEM_ROLE_MISSING", item.item_id, f"document {item.source_doc!r} has no reachability_report role for this finding")
    if item.dimension == DIM_REACH and item.source_doc in observation_locators:
        trace = payload.trace
        if trace is None or item.locator != trace.locator or item.locator not in observation_locators[item.source_doc]:
            raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DOCUMENT", item.item_id,
                                     "an item derived from an analyzer artifact sits at a recorded observation locator of that artifact")
        return
    if item.dimension == DIM_REACH and payload.trace is not None:
        raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "only a derived document can carry an observation trace")
    expected = REPORT_FINDING_LOCATOR if item.dimension == DIM_REACH else REPORT_ENTRY_LOCATOR
    if item.locator != expected:
        raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DOCUMENT", item.item_id, f"a {item.dimension} item of a report is at {expected!r}")


def _validate_claim(item: EvidenceItem, finding: Finding) -> None:
    """The state must be the one the payload's facts support."""
    payload = item.value_or_ref
    if item.dimension == DIM_REACH:
        if payload.kind == K4:
            if item.state is not EvidenceState.UNKNOWN or payload.graph is None or not payload.graph.present:
                raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "K4 evidence is Unknown reachability, never more (A5)")
            return
        if payload.kind not in ("K1", "K2", "K3") or payload.ep is None:
            raise ItemIntegrityError("ITEM_PAYLOAD_INVALID", item.item_id, "a REACH item names its kind and its EP")
        facts = ReachDocument(  # only the facts the state depends on
            doc_id=item.source_doc or "", kind=ReachKind(payload.kind),
            finding=ReachFinding(payload.finding) if payload.finding else None,
            full_coverage_claim=payload.full_coverage_claim)
        state, basis, _ = observation_state(facts, payload.ep)
        if state is not item.state or basis is not payload.basis:
            raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id,
                                     f"the facts support {state.value}/{basis.value if basis else None}, not {item.state.value}")
    elif item.dimension == DIM_LOCUS:
        if payload.locus is None or locus_item_state(payload.locus)[0] is not item.state:
            raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "the LOCUS state is not the one its approximation supports")
    else:
        if entry_item_state(payload.complete)[0] is not item.state:
            raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "the ENTRY state is not the one its completeness supports")
