"""Typed evidence items for the integrated CNP pipeline (specification section 1, "E").

Builds ``model.EvidenceItem`` records for INV, DECL, MATCH and GEN from the derivations of
``evidence.inv``, ``evidence.decl_derivation``, ``evidence.match`` and ``evidence.generation``.
An item is ``(dimension, state, value_or_ref, source_doc, locator, derived_from[])`` plus the
``item_id`` handle; ``value_or_ref`` holds a frozen typed payload (below) that keeps the
derivation, its reason and its limitations. No state beyond the six of section 2 and no new
verdict category exist here. BIND is **not** an item: its ``matched`` / ``mismatched`` /
``unknown`` outcome has no evidence state (register G17), so it stays a typed evaluator input
(``evidence.bind.BindEvaluation``) that the payloads only echo.

Identity and traceability, all checked by ``validate_items``:

* every item's ``source_doc`` is the exact id of a document registered in the finding's
  ``source_documents`` and the finding's ``document_roles`` gives it ``primary_sbom``;
* an item's ``locator`` is ``None`` or a locator that exists in that document (a list-level
  locator, a member, or a composition record) -- the validator never accepts a locator because it
  looks plausible;
* ``derived_from`` names existing items of the same document, never the item itself, without a
  cycle;
* ``item_id`` is non-empty and unique; ids are deterministic (``<DIM>:<doc_id>:<locator>``);
* the dimension is one of INV, DECL, MATCH, GEN, the state is an ``EvidenceState`` that the
  dimension can produce (INV: Present, Unknown, Contradictory; DECL: Present, Incomplete, Unknown;
  MATCH: any but Contradictory; GEN: Unknown), and the payload is the typed payload of that
  dimension;
* an item never claims more than its derivation supports: its state equals the derivation's
  state, the derivation belongs to the item's document, a `Present` MATCH or DECL names the
  member / records that exist, an INV `Present` rests on an identity-verified derivation, and a
  MATCH `Absent` derives only from INV `Present` items.

Locators: INV is attached to the existing list-level locators of the document (CycloneDX
``#/components`` and ``#/metadata/component/components``, SPDX ``#/packages``) so that provenance
can be taken per list (register D8); DECL to the composition record(s) it rests on; a MATCH
`Present` / `Ambiguous` item to the matching member. A MATCH `Absent` item is derived from the INV
items (the attested list), which bounds its provenance by theirs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from evidence.cnp_rules import BindState
from evidence.decl_derivation import DeclDerivation
from evidence.generation import GenDerivation
from evidence.inv import InvDerivation
from evidence.inventory_members import InventoryMembers
from evidence.match import MatchDerivation
from evidence.stage1_records import SbomRecord
from model import DocumentRole, EvidenceItem, EvidenceState, Finding

DIM_INV = "INV"
DIM_MATCH = "MATCH"
DIM_DECL = "DECL"
DIM_GEN = "GEN"


@dataclass(frozen=True)
class ItemPayload:
    """Base of the typed ``value_or_ref`` payloads."""

    dimension: str
    reason: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvPayload(ItemPayload):
    derivation: Optional[InvDerivation] = None
    list_locators: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeclPayload(ItemPayload):
    derivation: Optional[DeclDerivation] = None
    record_locators: tuple[str, ...] = ()


@dataclass(frozen=True)
class MatchPayload(ItemPayload):
    derivation: Optional[MatchDerivation] = None
    member_locator: Optional[str] = None


@dataclass(frozen=True)
class GenPayload(ItemPayload):
    derivation: Optional[GenDerivation] = None


class ItemIntegrityError(ValueError):
    """An item violates the traceability rules above; ``code`` is stable."""

    def __init__(self, code: str, item_id: Optional[str], message: str) -> None:
        super().__init__(f"{code} for item {item_id!r}: {message}")
        self.code = code
        self.item_id = item_id
        self.message = message


def item_id(dimension: str, doc_id: str, locator: Optional[str], suffix: str = "") -> str:
    return f"{dimension}:{doc_id}:{locator if locator is not None else '-'}{suffix}"


def _inv_items(doc_id: str, inv: InvDerivation, members: InventoryMembers) -> list[EvidenceItem]:
    locators = members.locator_prefixes()
    limitations = (() if locators else ("NO_LIST_LOCATOR: the document has no list-level locator for its members",))
    targets: Sequence[Optional[str]] = locators or (None,)
    return [
        EvidenceItem(
            dimension=DIM_INV,
            state=inv.state,
            value_or_ref=InvPayload(DIM_INV, inv.reason.value, limitations, inv, locators),
            source_doc=doc_id,
            locator=locator,
            item_id=item_id(DIM_INV, doc_id, locator),
        )
        for locator in targets
    ]


def _decl_item(doc_id: str, decl: DeclDerivation) -> EvidenceItem:
    locator = decl.record_locators[0] if decl.record_locators else None
    limitations = list(decl.unmet_covers_s)
    return EvidenceItem(
        dimension=DIM_DECL,
        state=decl.state,
        value_or_ref=DeclPayload(DIM_DECL, decl.reason.value, tuple(limitations), decl, decl.record_locators),
        source_doc=doc_id,
        locator=locator,
        item_id=item_id(DIM_DECL, doc_id, locator),
    )


def _match_items(doc_id: str, match: MatchDerivation, inv_items: Sequence[EvidenceItem]) -> list[EvidenceItem]:
    limitations = tuple(match.diagnostics)
    if match.state in (EvidenceState.PRESENT, EvidenceState.AMBIGUOUS):
        # Present rests on the strong matches only; a weak match found beside them is not a
        # positive observation. Ambiguous rests on the weak matches.
        wanted = "strong" if match.state is EvidenceState.PRESENT else "weak"
        return [
            EvidenceItem(
                dimension=DIM_MATCH,
                state=match.state,
                value_or_ref=MatchPayload(DIM_MATCH, match.reason.value, limitations, match, found.locator),
                source_doc=doc_id,
                locator=found.locator,
                item_id=item_id(DIM_MATCH, doc_id, found.locator),
            )
            for found in match.matches
            if found.strength == wanted
        ]
    derived = [i.item_id for i in inv_items] if match.state is EvidenceState.ABSENT else []
    locator = inv_items[0].locator if match.state is EvidenceState.ABSENT and inv_items else None
    return [
        EvidenceItem(
            dimension=DIM_MATCH,
            state=match.state,
            value_or_ref=MatchPayload(DIM_MATCH, match.reason.value, limitations, match, None),
            source_doc=doc_id,
            locator=locator,
            derived_from=derived,
            item_id=item_id(DIM_MATCH, doc_id, locator, ":none"),
        )
    ]


def _gen_item(doc_id: str, gen: GenDerivation) -> EvidenceItem:
    return EvidenceItem(
        dimension=DIM_GEN,
        state=EvidenceState.UNKNOWN,
        value_or_ref=GenPayload(DIM_GEN, gen.reason, gen.limitations, gen),
        source_doc=doc_id,
        locator=None,
        item_id=item_id(DIM_GEN, doc_id, None),
    )


def build_items(
    doc_id: str,
    members: InventoryMembers,
    inv: InvDerivation,
    decl: DeclDerivation,
    match: MatchDerivation,
    gen: GenDerivation,
) -> tuple[EvidenceItem, ...]:
    """The evidence items of one primary SBOM, in a fixed order (INV, DECL, MATCH, GEN)."""
    for name, value in (("members", members), ("decl", decl), ("match", match), ("gen", gen)):
        if value.doc_id != doc_id:
            raise ItemIntegrityError("ITEM_DOCUMENT_MISMATCH", None, f"{name} belongs to document {value.doc_id!r}")
    if inv.document_id != doc_id:
        raise ItemIntegrityError("ITEM_DOCUMENT_MISMATCH", None, f"inv belongs to document {inv.document_id!r}")
    inv_items = _inv_items(doc_id, inv, members)
    return tuple(inv_items + [_decl_item(doc_id, decl)] + _match_items(doc_id, match, inv_items) + [_gen_item(doc_id, gen)])


def known_locators(record: SbomRecord, members: InventoryMembers) -> frozenset[str]:
    """Locators that exist in ``record``: the document root, the list-level locators, the members
    and the composition records."""
    found = {"#", *members.locator_prefixes()}
    found.update(m.locator for m in members.members)
    found.update(r.locator for r in record.composition_records)
    return frozenset(found)


def validate_items(
    finding: Finding,
    record: SbomRecord,
    members: InventoryMembers,
    items: Iterable[EvidenceItem],
) -> None:
    """Raise ``ItemIntegrityError`` unless every item is traceable (see the module docstring)."""
    collected = list(items)
    locators = known_locators(record, members)
    by_id: dict[str, EvidenceItem] = {}
    for item in collected:
        if not item.item_id:
            raise ItemIntegrityError("ITEM_ID_MISSING", item.item_id, "an item needs a stable id")
        if item.item_id in by_id:
            raise ItemIntegrityError("ITEM_ID_DUPLICATE", item.item_id, "item ids must be unique")
        by_id[item.item_id] = item
    for item in collected:
        if item.source_doc is None or item.source_doc not in finding.source_documents:
            raise ItemIntegrityError("ITEM_SOURCE_NOT_REGISTERED", item.item_id,
                                     f"source_doc {item.source_doc!r} is not in the finding's source_documents")
        if finding.document_roles.get(item.source_doc) is not DocumentRole.PRIMARY_SBOM:
            raise ItemIntegrityError("ITEM_ROLE_MISSING", item.item_id,
                                     f"document {item.source_doc!r} has no primary_sbom role for this finding")
        if item.source_doc != record.doc_id:
            raise ItemIntegrityError("ITEM_DOCUMENT_MISMATCH", item.item_id,
                                     f"source_doc {item.source_doc!r} is not the primary record {record.doc_id!r}")
        if item.locator is not None and item.locator not in locators:
            raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DOCUMENT", item.item_id,
                                     f"locator {item.locator!r} does not exist in the document")
        _validate_claim(item, record, members, locators, by_id)
        for parent_id in item.derived_from:
            parent = by_id.get(parent_id)
            if parent is None:
                raise ItemIntegrityError("ITEM_PARENT_MISSING", item.item_id, f"derived_from {parent_id!r} is not an item")
            if parent_id == item.item_id:
                raise ItemIntegrityError("ITEM_PARENT_SELF", item.item_id, "an item cannot derive from itself")
            if parent.source_doc != item.source_doc:
                raise ItemIntegrityError("ITEM_PARENT_DOCUMENT_MISMATCH", item.item_id,
                                         "a derived item and its parent must come from the same document")
    for start in collected:  # no derivation cycle
        seen: set[str] = set()
        stack = list(start.derived_from)
        while stack:
            current = stack.pop()
            if current == start.item_id:
                raise ItemIntegrityError("ITEM_DERIVATION_CYCLE", start.item_id, "derived_from forms a cycle")
            if current in seen:
                continue
            seen.add(current)
            stack.extend(by_id[current].derived_from)


_ALLOWED_STATES = {
    DIM_INV: frozenset({EvidenceState.PRESENT, EvidenceState.UNKNOWN, EvidenceState.CONTRADICTORY}),
    DIM_DECL: frozenset({EvidenceState.PRESENT, EvidenceState.INCOMPLETE, EvidenceState.UNKNOWN}),
    DIM_MATCH: frozenset(EvidenceState) - {EvidenceState.CONTRADICTORY},
    DIM_GEN: frozenset({EvidenceState.UNKNOWN}),
}
_PAYLOAD_TYPES = {DIM_INV: InvPayload, DIM_DECL: DeclPayload, DIM_MATCH: MatchPayload, DIM_GEN: GenPayload}


def _derivation_doc(payload: ItemPayload) -> Optional[str]:
    derivation = payload.derivation  # type: ignore[attr-defined]
    return getattr(derivation, "document_id", None) or getattr(derivation, "doc_id", None)


def _derivation_state(payload: ItemPayload) -> str:
    state = payload.derivation.state  # type: ignore[attr-defined]
    return state.value


def _validate_claim(item: EvidenceItem, record: SbomRecord, members: InventoryMembers, locators: frozenset[str],
                    by_id: Mapping[str, EvidenceItem]) -> None:
    """The item's state, payload and derivation must agree, and it must not claim more than the
    derivation supports (see the module docstring)."""
    dimension = item.dimension
    if dimension not in _ALLOWED_STATES:
        raise ItemIntegrityError("ITEM_DIMENSION_INVALID", item.item_id, f"dimension {dimension!r} is not INV, DECL, MATCH or GEN")
    if not isinstance(item.state, EvidenceState):
        raise ItemIntegrityError("ITEM_STATE_INVALID", item.item_id, "the state is not one of the six evidence states")
    if item.state not in _ALLOWED_STATES[dimension]:
        raise ItemIntegrityError("ITEM_STATE_NOT_ALLOWED", item.item_id,
                                 f"{dimension} cannot be {item.state.value} in this pipeline")
    payload = item.value_or_ref
    if not isinstance(payload, _PAYLOAD_TYPES[dimension]) or payload.dimension != dimension \
            or getattr(payload, "derivation", None) is None:
        raise ItemIntegrityError("ITEM_PAYLOAD_INVALID", item.item_id,
                                 f"{dimension} items carry a {_PAYLOAD_TYPES[dimension].__name__} with its derivation")
    if _derivation_doc(payload) != item.source_doc:
        raise ItemIntegrityError("ITEM_DOCUMENT_MISMATCH", item.item_id, "the derivation belongs to another document")
    if _derivation_state(payload).lower() != item.state.value.lower():
        raise ItemIntegrityError("ITEM_STATE_UNSUPPORTED_BY_DERIVATION", item.item_id,
                                 f"state {item.state.value} but the derivation says {_derivation_state(payload)}")
    member_locators = {m.locator for m in members.members}
    if dimension == DIM_INV:
        if item.locator is not None and item.locator not in payload.list_locators:
            raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DERIVATION", item.item_id, "an INV item is attached to a list-level locator of its derivation")
        if item.state is EvidenceState.PRESENT and not (payload.derivation.identity_verified and payload.derivation.bind_state is BindState.MATCHED):
            raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "INV Present needs an identity-verified, BIND-matched derivation")
    elif dimension == DIM_DECL:
        used = payload.record_locators
        if not set(used) <= {r.locator for r in record.composition_records}:
            raise ItemIntegrityError("ITEM_LOCATOR_NOT_IN_DOCUMENT", item.item_id, "a DECL record locator does not exist in the document")
        if item.state is EvidenceState.PRESENT and (not used or item.locator != used[0]):
            raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "DECL Present needs the composition record it rests on")
    elif dimension == DIM_MATCH:
        if item.state in (EvidenceState.PRESENT, EvidenceState.AMBIGUOUS):
            strength = "strong" if item.state is EvidenceState.PRESENT else "weak"
            if item.locator is None or item.locator not in member_locators or payload.member_locator != item.locator \
                    or item.locator not in {m.locator for m in payload.derivation.matches if m.strength == strength}:
                raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id,
                                         f"a {item.state.value} MATCH names a member that matched {strength}ly")
        if item.state is EvidenceState.ABSENT:
            parents = [by_id.get(p) for p in item.derived_from]
            if not parents or any(p is None or p.dimension != DIM_INV or p.state is not EvidenceState.PRESENT for p in parents):
                raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "MATCH Absent derives only from INV Present items")
            if not members.domain_extracted:
                raise ItemIntegrityError("ITEM_CLAIM_UNSUPPORTED", item.item_id, "MATCH Absent needs a fully extracted member domain")


def items_of(items: Iterable[EvidenceItem], dimension: str) -> list[EvidenceItem]:
    return [i for i in items if i.dimension == dimension]
