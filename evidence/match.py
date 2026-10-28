"""MATCH derivation: is the target component C in the approved inventory-member domain?

Specification section 4.1: MATCH is "C under any identifier variant (purl, CPE, name+version,
hash). `Absent` only if all derivable variants were searched." Section 2 (`Absent`): the
non-observation must come from "an in-scope source whose declared coverage is sufficient"; P-2:
"Missing evidence is `Unknown`, never `Absent`". This module derives MATCH under the approved
milestone rules (register D6), without any closed-world assumption.

Search domain: ``evidence.inventory_members.InventoryMembers`` (CycloneDX top-level and
subject-nested components, SPDX packages), never services, files, pedigree objects or the subject.

Identifier comparison: the committed ``variant-norm-v1`` variants, compared by exact equality of
``(kind, value)`` within the *same* kind, and only after the existing normalization. No cross-kind
conversion is added (a purl is never compared with a CPE; CPE 2.2 and 2.3 are not converted).

* A **strong** match is exact equality of any ``purl``, ``cpe`` or ``hash:<algorithm>`` variant.
* A **weak** match is equal normalized names with compatible versions (equal, or one side without
  a version). A weak match is never `Present`. It is suppressed when both sides carry a purl and no
  purl is equal (the purls state they are different components).

State derivation:

* `Unknown`: no target component, a target without any identifier variant, document identities
  that disagree, BIND not ``MATCHED``, the member domain not fully extracted, or no attested full
  list (INV not `Present` / assertion not usable) when nothing was found. A match observed in a
  document that is not bound to S is reported only as a diagnostic.
* `Present`: BIND ``MATCHED`` and at least one strong match (any number of weak matches too).
* `Ambiguous`: BIND ``MATCHED``, no strong match, at least one weak match.
* `Incomplete`: nothing matched, but C carries no strong variant (only name or name+version), so
  the variants could not be fully enumerated (N9).
* `Absent`: BIND ``MATCHED``, the member domain fully extracted, INV `Present` (which itself needs
  the evaluator's usable ``full_component_list`` assertion and every required structural check),
  C has at least one strong variant, and no member matched strongly or weakly.
* `Contradictory` is never produced here: it needs a second source with declared sufficient
  coverage (N17), which this milestone does not evaluate.

The result states what was searched; it does not claim that the search domain is the whole
inventory beyond the evaluator's attestation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from evidence.bind import BindEvaluation
from evidence.cnp_rules import BindState
from evidence.inv import InvDerivation
from evidence.inventory_members import InventoryMember, InventoryMembers
from model import Component, EvidenceState
from sbom_parser.identifiers import normalize_name

STRONG_KINDS = ("purl", "cpe")


def _is_strong(kind: str) -> bool:
    return kind in STRONG_KINDS or kind.startswith("hash:")


class MatchReason(str, Enum):
    STRONG_IDENTIFIER_EQUAL = "MATCH_STRONG_IDENTIFIER_EQUAL"
    NAME_VERSION_ONLY = "MATCH_NAME_VERSION_ONLY"
    NOT_FOUND_IN_ATTESTED_DOMAIN = "MATCH_NOT_FOUND_IN_ATTESTED_DOMAIN"
    ONLY_WEAK_VARIANTS = "MATCH_ONLY_WEAK_VARIANTS"
    NO_TARGET_COMPONENT = "MATCH_NO_TARGET_COMPONENT"
    NO_IDENTIFIER_VARIANTS = "MATCH_NO_IDENTIFIER_VARIANTS"
    DOCUMENT_IDENTITY_MISMATCH = "MATCH_DOCUMENT_IDENTITY_MISMATCH"
    BIND_NOT_MATCHED = "MATCH_BIND_NOT_MATCHED"
    DOMAIN_NOT_EXTRACTED = "MATCH_DOMAIN_NOT_EXTRACTED"
    INVENTORY_NOT_ATTESTED = "MATCH_INVENTORY_NOT_ATTESTED"


@dataclass(frozen=True)
class MemberMatch:
    """A member of the domain that matched the target."""

    doc_id: str
    locator: str
    origin: str
    strength: str  # "strong" or "weak"
    kinds: tuple[str, ...]  # the equal variant kinds (strong) or ("name",) / ("name+version",) (weak)


@dataclass(frozen=True)
class MatchDerivation:
    """The derived MATCH state with its basis. ``matches`` lists the matching members
    (also for an unbound document, where they are not evidence: see ``diagnostics``)."""

    state: EvidenceState
    reason: MatchReason
    doc_id: str
    matches: tuple[MemberMatch, ...] = ()
    searched_members: int = 0
    target_strong_kinds: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        allowed = (EvidenceState.PRESENT, EvidenceState.ABSENT, EvidenceState.UNKNOWN,
                   EvidenceState.INCOMPLETE, EvidenceState.AMBIGUOUS)
        if self.state not in allowed:
            raise ValueError("MATCH Contradictory is not produced (N17 needs a corroborating document)")


def _variant_pairs(component: Component) -> set[tuple[str, str]]:
    return {(v.kind, v.value) for v in component.identifier_variants}


def _purls(component: Component) -> set[str]:
    return {v.value for v in component.identifier_variants if v.kind == "purl"}


def _weak_match(target: Component, member: Component) -> Optional[str]:
    name = normalize_name(target.name)
    if not name or name != normalize_name(member.name):
        return None
    target_version = target.version.strip() if target.version else ""
    member_version = member.version.strip() if member.version else ""
    if target_version and member_version:
        return "name+version" if target_version == member_version else None
    return "name"


def _match_member(target: Component, target_pairs: set[tuple[str, str]], member: InventoryMember) -> Optional[MemberMatch]:
    common = sorted(kind for kind, value in target_pairs & _variant_pairs(member.component) if _is_strong(kind))
    if common:
        return MemberMatch(member.doc_id, member.locator, member.origin, "strong", tuple(common))
    weak = _weak_match(target, member.component)
    if weak is None:
        return None
    target_purls, member_purls = _purls(target), _purls(member.component)
    if target_purls and member_purls and not (target_purls & member_purls):
        return None  # the purls say these are different components
    return MemberMatch(member.doc_id, member.locator, member.origin, "weak", (weak,))


def derive_match(
    target: Optional[Component],
    members: InventoryMembers,
    bind: BindEvaluation,
    inv: InvDerivation,
) -> MatchDerivation:
    """Derive MATCH for ``target`` over ``members``. Pure and deterministic."""
    doc_id = members.doc_id

    def unknown(reason: MatchReason, matches=(), diagnostics=()) -> MatchDerivation:
        return MatchDerivation(EvidenceState.UNKNOWN, reason, doc_id, tuple(matches), len(members.members),
                               diagnostics=tuple(diagnostics))

    if target is None:
        return unknown(MatchReason.NO_TARGET_COMPONENT)
    target_pairs = _variant_pairs(target)
    if not target_pairs:
        return unknown(MatchReason.NO_IDENTIFIER_VARIANTS)
    strong_kinds = tuple(sorted({kind for kind, _ in target_pairs if _is_strong(kind)}))

    if not (bind.document_id == doc_id == inv.document_id):
        return unknown(MatchReason.DOCUMENT_IDENTITY_MISMATCH)

    found = tuple(
        match
        for match in (_match_member(target, target_pairs, member) for member in members.members)
        if match is not None
    )
    if bind.state is not BindState.MATCHED:
        notes = [f"{len(found)} member(s) matched in a document that is not bound to S; not used as evidence"] if found else []
        return unknown(MatchReason.BIND_NOT_MATCHED, found, notes)

    searched = len(members.members)
    strong = tuple(m for m in found if m.strength == "strong")
    if strong:
        return MatchDerivation(EvidenceState.PRESENT, MatchReason.STRONG_IDENTIFIER_EQUAL, doc_id, found,
                               searched, strong_kinds)
    if found:
        return MatchDerivation(EvidenceState.AMBIGUOUS, MatchReason.NAME_VERSION_ONLY, doc_id, found,
                               searched, strong_kinds)

    if not members.domain_extracted:
        return unknown(MatchReason.DOMAIN_NOT_EXTRACTED)
    if inv.state is not EvidenceState.PRESENT:
        return unknown(MatchReason.INVENTORY_NOT_ATTESTED)
    if not strong_kinds:
        return MatchDerivation(EvidenceState.INCOMPLETE, MatchReason.ONLY_WEAK_VARIANTS, doc_id, (), searched, ())
    return MatchDerivation(EvidenceState.ABSENT, MatchReason.NOT_FOUND_IN_ATTESTED_DOMAIN, doc_id, (),
                           searched, strong_kinds)
