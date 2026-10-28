"""DECL candidate-applicability enumerator (Stage 2, slice 2a; isolated).

Given an ``SbomRecord`` and the locator of one target component, report which CycloneDX
composition records are *candidates* for that target's DECL dimension, which records or
references were excluded and why, and how the candidates group. It selects nothing:

* No winner is chosen and no DECL ``EvidenceItem`` or verdict is produced.
* It is **not wired into** ``evidence.extraction.extract``; extraction still emits
  ``Unknown`` for every document that has composition records (open issue G1r supplies
  the missing location input, G13 the way to locate C, and G3c/G17/G11 "covers S").
* It decides no G1r, G7, G11, G13 or G17 question.

Decisions applied (``docs/open_issues_register.md``, G6; these are approved project
decisions, not specification text):

* **G6-D11 (container interpretation of G6-D1).** A record naming assembly X is a
  candidate for target C when C is a represented *direct* child of X. A record naming C
  itself concerns C's own assembly and is not a candidate for C (it is reported as the
  exclusion ``NAMES_TARGET_ITSELF``). There is no recursive inheritance: a record naming
  an ancestor above C's parent is the exclusion ``NOT_DIRECT_CHILD``.
* **G6-D2 / G6-D9.** Only a non-empty ``assemblies`` list can establish DECL coverage.
  A record without one (scope-less, empty ``assemblies``, ``dependencies``-only,
  ``vulnerabilities``-only) is excluded. A mixed-scope record contributes its
  ``assemblies`` portion only; the ignored lists are named on the candidate.
* **G6-D3 / G6-D12 / G6-D13.** A component directly nested under
  ``metadata.component.components`` is a represented direct child of the named root and
  receives a component-specific candidate (G6-D12); that does not recurse to
  grandchildren. For every other in-scope target (a top-level BOM component, or a
  component deeper in either component tree) a record naming the root is reported as a
  separate *root-level fallback candidate* with ``covers_s`` fixed at ``UNDETERMINED``
  (G6-D13). It is never counted as coverage and never produces ``Present``; a
  non-``complete`` root record only sets ``necessary_condition_met`` to ``False``. The
  root's reference is never used as a component-specific candidate for a deeper
  descendant, and a record never appears both as a candidate and as a root-level
  candidate for the same reference and target.
* **G6-D4.** Each reference of a record is judged on its own; a sibling list is never a
  collective inventory.
* **G6-D5.** A direct child without a ``bom-ref`` can be covered. BOM-Link references
  are excluded as ``BOM_LINK_UNMATCHED``. A reference that matches no registered object
  is ``REFERENCE_NOT_IN_REGISTRY``. A reference declared more than once is
  ``AMBIGUOUS_REFERENCE``: the first registry match is never used.
* **G6-D6.** With no ``target_locator`` the status is ``TARGET_LOCATION_UNAVAILABLE``
  and no parent is guessed; records naming the root are still reported as root-level
  candidates.
* **G6-D7 / G6-D8.** Candidates for one target all name that target's parent, so they
  form one group. The worst-case rule (``Unknown`` is the most conservative result,
  otherwise ``Incomplete`` precedes ``Present``) is applied only inside that group.
  This is project policy and is not the specification's §2 aggregation procedure.

BOM-Link recognition. Both the CycloneDX 1.5 and 1.6 JSON schemas define a BOM-Link
element (``bomLinkElementType``) by the pattern in ``BOM_LINK_PATTERN`` and say a local
``bom-ref`` SHOULD NOT start with ``urn:cdx:``. A reference is classified as a BOM-Link
only if it matches that full pattern; any other string is looked up as an ordinary
local reference.

Limitations (see the register's G6 open points):

* "Covers S" is not established anywhere here (G3c, G17, G11), so no root-level fallback
  candidate is ever coverage. Under G6-D13 it would apply throughout S regardless of
  depth once covers S is established.
* "In scope" for the root-level fallback means the two component trees the BOM places
  under the described product: ``#/components/<n>(/components/<n>)*`` and
  ``#/metadata/component(/components/<n>)+``. A registered component nested in another
  object (for example a ``pedigree`` component) is an accepted target locator but gets
  no root-level fallback candidate; whether such components are part of S is not
  decided.
* Stage 1 records register a nested component only if it carries a ``bom-ref``. A
  component nested under ``metadata.component`` (or another non-listed object) without
  a ``bom-ref`` is therefore not discoverable as a target here; ordinary listed
  components (including nested ones) are always discoverable.
* Whether a reference that resolves to a non-component object (for example a service)
  matters is not decided; such references simply never equal a component's parent
  reference.
* Locators are the JSON Pointers written by ``sbom_parser.cyclonedx``; a parent is
  derived structurally (``.../components/<n>`` -> the enclosing object).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from evidence.stage1_records import CompositionRecord, ReferenceStatus, SbomRecord
from model import EvidenceState

# CycloneDX 1.5 and 1.6 schemas, definition ``bomLinkElementType`` (identical in both).
BOM_LINK_PATTERN = re.compile(
    r"urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+"
)

_SUBJECT_VIA = "metadata.component"
_TOP = "#"  # the document level: the parent of a top-level BOM component


class EnumerationStatus(str, Enum):
    CANDIDATES_FOUND = "CANDIDATES_FOUND"  # at least one component-specific candidate
    NO_CANDIDATE = "NO_CANDIDATE"  # target known; no component-specific candidate
    TARGET_LOCATION_UNAVAILABLE = "TARGET_LOCATION_UNAVAILABLE"
    TARGET_NOT_IN_DOCUMENT = "TARGET_NOT_IN_DOCUMENT"


class StatusReason(str, Enum):
    NO_TARGET_LOCATION = "NO_TARGET_LOCATION"
    LOCATOR_NOT_IN_DOCUMENT = "LOCATOR_NOT_IN_DOCUMENT"
    LOCATOR_NOT_A_COMPONENT = "LOCATOR_NOT_A_COMPONENT"
    TARGET_IS_DOCUMENT_SUBJECT = "TARGET_IS_DOCUMENT_SUBJECT"
    NO_COMPOSITION_RECORDS = "NO_COMPOSITION_RECORDS"
    PARENT_NOT_DERIVABLE = "PARENT_NOT_DERIVABLE"
    TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY = "TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY"
    PARENT_HAS_NO_BOM_REF = "PARENT_HAS_NO_BOM_REF"
    PARENT_REFERENCE_AMBIGUOUS = "PARENT_REFERENCE_AMBIGUOUS"
    NO_RECORD_NAMES_PARENT = "NO_RECORD_NAMES_PARENT"
    # entry by explicit placement (enumerate_decl_candidates_for_placement)
    PLACEMENT_UNSPECIFIED = "PLACEMENT_UNSPECIFIED"
    PLACEMENT_INVALID = "PLACEMENT_INVALID"
    PARENT_REF_NOT_IN_DOCUMENT = "PARENT_REF_NOT_IN_DOCUMENT"
    PARENT_NOT_A_COMPONENT = "PARENT_NOT_A_COMPONENT"


class CandidateRelation(str, Enum):
    NAMED_PARENT = "NAMED_PARENT"  # the record names the target's direct parent assembly


class CoversS(str, Enum):
    """Whether a root-level record covers the formal scope S. Never resolved here."""

    UNDETERMINED = "undetermined"


class TargetPosition(str, Enum):
    TOP_LEVEL = "TOP_LEVEL"  # a top-level BOM component (``#/components/<n>``)
    BELOW_TOP_LEVEL = "BELOW_TOP_LEVEL"  # deeper in the top-level component tree
    # Deeper than a direct child of the root: beneath ``metadata.component.components``.
    BELOW_ROOT_CHILD = "BELOW_ROOT_CHILD"
    LOCATION_UNAVAILABLE = "LOCATION_UNAVAILABLE"


class RootLevelReason(str, Enum):
    COVERS_S_UNDETERMINED = "COVERS_S_UNDETERMINED"
    AGGREGATE_NOT_COMPLETE = "AGGREGATE_NOT_COMPLETE"


class ExclusionReason(str, Enum):
    NO_APPLICABLE_SCOPE = "NO_APPLICABLE_SCOPE"  # no (or empty) assemblies, nothing else
    DEPENDENCIES_ONLY = "DEPENDENCIES_ONLY"
    VULNERABILITIES_ONLY = "VULNERABILITIES_ONLY"
    DEPENDENCIES_AND_VULNERABILITIES_ONLY = "DEPENDENCIES_AND_VULNERABILITIES_ONLY"
    BOM_LINK_UNMATCHED = "BOM_LINK_UNMATCHED"
    REFERENCE_NOT_IN_REGISTRY = "REFERENCE_NOT_IN_REGISTRY"
    AMBIGUOUS_REFERENCE = "AMBIGUOUS_REFERENCE"
    NOT_DIRECT_CHILD = "NOT_DIRECT_CHILD"  # names an ancestor above the target's parent
    NAMES_TARGET_ITSELF = "NAMES_TARGET_ITSELF"  # the record concerns the target's own assembly


@dataclass(frozen=True)
class DeclCandidate:
    """A record that names the target's direct parent assembly. The state is the
    record's own mapped state, not a DECL result."""

    record_locator: str
    reference: str
    relation: CandidateRelation
    state: EvidenceState
    aggregate_raw: str
    aggregate_recognized: bool
    ignored_scope_lists: tuple[str, ...] = ()
    parent_is_document_subject: bool = False


@dataclass(frozen=True)
class DeclGroup:
    """Candidates that name the same parent reference (one target, one scope).

    ``state`` is the G6-D8 worst case over the members and is not the specification's
    §2 aggregation."""

    parent_locator: str
    parent_ref: str
    members: tuple[DeclCandidate, ...]
    state: EvidenceState
    tie: bool  # more than one record names the parent
    disagreement: bool  # the members do not all carry the same state


@dataclass(frozen=True)
class RootLevelCandidate:
    """A document-level fallback candidate: a record that names the
    ``metadata.component`` root, reported apart from the component-specific candidates
    (G6-D13). ``covers_s`` is always ``UNDETERMINED``, so it is never coverage."""

    record_locator: str
    root_ref: str
    state: EvidenceState
    aggregate_raw: str
    aggregate_recognized: bool
    necessary_condition_met: bool  # root named and the aggregate is ``complete`` (G6-D3)
    covers_s: CoversS
    target_position: TargetPosition
    reasons: tuple[RootLevelReason, ...]
    ignored_scope_lists: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeclExclusion:
    record_locator: str
    reason: ExclusionReason
    reference: Optional[str] = None


@dataclass(frozen=True)
class DeclEnumeration:
    doc_id: str
    target_locator: Optional[str]
    status: EnumerationStatus
    status_reasons: tuple[StatusReason, ...]
    parent_locator: Optional[str]
    parent_ref: Optional[str]
    candidates: tuple[DeclCandidate, ...]
    groups: tuple[DeclGroup, ...]
    root_level_candidates: tuple[RootLevelCandidate, ...]
    exclusions: tuple[DeclExclusion, ...]
    placement: Optional[str] = None  # set only by the placement entry point


# ---- G6-D8 worst case -------------------------------------------------------------------

_CONSERVATISM = {
    EvidenceState.UNKNOWN: 2,
    EvidenceState.INCOMPLETE: 1,
    EvidenceState.PRESENT: 0,
}


def worst_case_state(states: Iterable[EvidenceState]) -> EvidenceState:
    """G6-D8 tie-break over equally applicable records: ``Unknown`` is the most
    conservative result, otherwise ``Incomplete`` takes precedence over ``Present``, so
    ``Present`` requires every state to be ``Present``.

    Only the three states a composition aggregate maps to are accepted; an empty
    collection or any other state raises ``ValueError`` rather than choosing a result.
    """
    collected = list(states)
    if not collected:
        raise ValueError("worst_case_state of an empty collection is undefined")
    for state in collected:
        if state not in _CONSERVATISM:
            raise ValueError(f"unsupported state for the G6-D8 tie-break: {state!r}")
    return max(collected, key=_CONSERVATISM.__getitem__)


# ---- locators ---------------------------------------------------------------------------

def _segments(locator: str) -> tuple[str, ...]:
    if not locator.startswith("#"):
        raise ValueError(f"not a URI-fragment JSON Pointer locator: {locator!r}")
    rest = locator[1:]
    if rest == "":
        return ()
    if not rest.startswith("/"):
        raise ValueError(f"not a URI-fragment JSON Pointer locator: {locator!r}")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in rest[1:].split("/"))


def _join(segments: tuple[str, ...]) -> str:
    return "#" + "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in segments)


def _parent(locator: str) -> Optional[str]:
    """The locator of the object whose ``components`` array holds ``locator``;
    ``'#'`` for a top-level BOM component; ``None`` when the locator does not end in
    ``.../components/<n>`` (no parent is guessed)."""
    segments = _segments(locator)
    if len(segments) >= 2 and segments[-2] == "components" and segments[-1].isdigit():
        return _join(segments[:-2])
    return None


def _only_nesting(rest: tuple[str, ...]) -> bool:
    """True iff ``rest`` is ``('components', '<n>')`` repeated (possibly zero times)."""
    return len(rest) % 2 == 0 and all(
        rest[i] == "components" and rest[i + 1].isdigit() for i in range(0, len(rest), 2)
    )


def _component_tree(locator: str, subject_locator: Optional[str]) -> Optional[str]:
    """``'top'`` for ``#/components/<n>(/components/<n>)*``, ``'root'`` for a component
    nested beneath the subject (``<subject>(/components/<n>)+``), else ``None``."""
    segments = _segments(locator)
    if len(segments) >= 2 and segments[0] == "components" and segments[1].isdigit():
        return "top" if _only_nesting(segments[2:]) else None
    if subject_locator is not None:
        subject = _segments(subject_locator)
        if len(segments) > len(subject) and segments[: len(subject)] == subject:
            return "root" if _only_nesting(segments[len(subject):]) else None
    return None


def _ancestors_above_parent(locator: str) -> list[str]:
    """Locators strictly above the parent (the grandparent upward), nearest first."""
    found: list[str] = []
    current = _parent(locator)
    while current is not None and current != _TOP:
        above = _parent(current)
        if above is None or above == _TOP:
            break
        found.append(above)
        current = above
    return found


# ---- registry view ----------------------------------------------------------------------

@dataclass(frozen=True)
class _Registry:
    subject_locator: Optional[str]
    subject_ref: Optional[str]
    listed: dict[str, Optional[str]]  # locator -> bom-ref (ordinary component list)
    nested: dict[str, Optional[str]]  # locator -> ref (``nested_component``)
    other: dict[str, str]  # locator -> ref (any other registered kind)
    conflict_ref_at: dict[str, str]  # locator of a repeated declaration -> its ref
    conflicted_refs: frozenset[str]

    @classmethod
    def build(cls, record: SbomRecord) -> "_Registry":
        subject = next(
            (s for s in record.document.subjects if s.declared_via == _SUBJECT_VIA), None
        )
        listed = {entry["locator"]: entry.get("bom_ref") for entry in record.component_index}
        nested: dict[str, Optional[str]] = {}
        other: dict[str, str] = {}
        for ref, locator in record.defined_ref_locators.items():
            if record.document.other_defined_refs.get(ref) == "nested_component":
                nested[locator] = ref
            else:
                other[locator] = ref
        conflict_ref_at: dict[str, str] = {}
        conflicted: set[str] = set()
        for conflict in record.defined_ref_conflicts:
            conflicted.add(conflict["ref"])
            conflict_ref_at[conflict["locator"]] = conflict["ref"]
            if conflict.get("kind") == "nested_component":
                nested.setdefault(conflict["locator"], conflict["ref"])
        return cls(
            subject_locator=subject.locator if subject is not None else None,
            subject_ref=subject.ref if subject is not None else None,
            listed=listed,
            nested=nested,
            other=other,
            conflict_ref_at=conflict_ref_at,
            conflicted_refs=frozenset(conflicted),
        )

    def ref_at(self, locator: str) -> Optional[str]:
        if locator == self.subject_locator:
            return self.subject_ref
        for table in (self.listed, self.nested, self.other, self.conflict_ref_at):
            ref = table.get(locator)
            if ref is not None:
                return ref
        return None


# ---- enumeration ------------------------------------------------------------------------

def _scope_exclusion(record: CompositionRecord) -> Optional[ExclusionReason]:
    if record.assemblies:
        return None
    if record.dependencies and record.vulnerabilities:
        return ExclusionReason.DEPENDENCIES_AND_VULNERABILITIES_ONLY
    if record.dependencies:
        return ExclusionReason.DEPENDENCIES_ONLY
    if record.vulnerabilities:
        return ExclusionReason.VULNERABILITIES_ONLY
    return ExclusionReason.NO_APPLICABLE_SCOPE


def _ignored_lists(record: CompositionRecord) -> tuple[str, ...]:
    return tuple(
        name
        for name, values in (("dependencies", record.dependencies), ("vulnerabilities", record.vulnerabilities))
        if values
    )


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def enumerate_decl_candidates(record: SbomRecord, target_locator: Optional[str]) -> DeclEnumeration:
    """Enumerate the DECL candidates for the component at ``target_locator``.

    ``target_locator`` is a locator in ``record``'s document (for example
    ``#/components/0/components/1``) supplied by the caller; this function does not find
    components and does not read the evaluator's finding. The result is deterministic:
    candidates, exclusions and root-level candidates follow the order of the record's
    composition records and, within a record, of its ``assemblies`` list. Nothing is
    mutated.
    """
    registry = _Registry.build(record)
    doc_id = record.doc_id

    def result(status, reasons, parent_locator=None, parent_ref=None, candidates=(), groups=(),
               roots=(), exclusions=()):
        return DeclEnumeration(
            doc_id=doc_id,
            target_locator=target_locator,
            status=status,
            status_reasons=tuple(reasons),
            parent_locator=parent_locator,
            parent_ref=parent_ref,
            candidates=tuple(candidates),
            groups=tuple(groups),
            root_level_candidates=tuple(roots),
            exclusions=tuple(exclusions),
        )

    if target_locator is None:
        candidates, roots, exclusions = _scan(record, registry, None)
        return result(
            EnumerationStatus.TARGET_LOCATION_UNAVAILABLE,
            (StatusReason.NO_TARGET_LOCATION,),
            roots=roots,
            exclusions=exclusions,
        )

    try:
        is_listed = target_locator in registry.listed
        _segments(target_locator)
    except ValueError:
        return result(EnumerationStatus.TARGET_NOT_IN_DOCUMENT, (StatusReason.LOCATOR_NOT_IN_DOCUMENT,))
    if not (is_listed or target_locator in registry.nested or target_locator == registry.subject_locator):
        reason = (
            StatusReason.LOCATOR_NOT_A_COMPONENT
            if target_locator in registry.other
            else StatusReason.LOCATOR_NOT_IN_DOCUMENT
        )
        return result(EnumerationStatus.TARGET_NOT_IN_DOCUMENT, (reason,))

    _, _, exclusions_only = _scan(record, registry, None)
    if target_locator == registry.subject_locator:
        return result(
            EnumerationStatus.NO_CANDIDATE,
            (StatusReason.TARGET_IS_DOCUMENT_SUBJECT,),
            exclusions=exclusions_only,
        )
    if not record.composition_records:
        return result(EnumerationStatus.NO_CANDIDATE, (StatusReason.NO_COMPOSITION_RECORDS,))

    parent_locator = _parent(target_locator)
    if parent_locator is None:
        return result(
            EnumerationStatus.NO_CANDIDATE,
            (StatusReason.PARENT_NOT_DERIVABLE,),
            exclusions=exclusions_only,
        )
    parent_ref = None if parent_locator == _TOP else registry.ref_at(parent_locator)

    candidates, roots, exclusions = _scan(record, registry, (target_locator, parent_locator, parent_ref))
    if candidates:
        states = [c.state for c in candidates]
        group = DeclGroup(
            parent_locator=parent_locator,
            parent_ref=parent_ref,  # type: ignore[arg-type]  # a candidate implies a parent reference
            members=tuple(candidates),
            state=worst_case_state(states),
            tie=len(candidates) > 1,
            disagreement=len(set(states)) > 1,
        )
        return result(
            EnumerationStatus.CANDIDATES_FOUND, (), parent_locator, parent_ref, candidates, (group,),
            roots, exclusions,
        )

    if parent_locator == _TOP:
        reason = StatusReason.TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY
    elif parent_ref is None:
        reason = StatusReason.PARENT_HAS_NO_BOM_REF
    elif parent_ref in registry.conflicted_refs:
        reason = StatusReason.PARENT_REFERENCE_AMBIGUOUS
    else:
        reason = StatusReason.NO_RECORD_NAMES_PARENT
    return result(
        EnumerationStatus.NO_CANDIDATE, (reason,), parent_locator, parent_ref, (), (), roots, exclusions
    )


def enumerate_decl_candidates_for_placement(
    record: SbomRecord, placement: Optional[str], parent_ref: Optional[str]
) -> DeclEnumeration:
    """Enumerate the DECL candidates for a would-be target that is NOT in the document, from the
    evaluator's explicit placement (register G6-D6, G1r; profile schema 1.1).

    * ``placement=None``: unspecified; the status is ``TARGET_LOCATION_UNAVAILABLE`` (nothing is
      selected from a guessed position).
    * ``"top_level"``: the target would be a top-level BOM component. It has no parent assembly,
      so the status is ``NO_CANDIDATE`` (``TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY``) and the records
      naming the root are reported as root-level candidates for a ``TOP_LEVEL`` position.
    * ``"nested_under_component"`` with ``parent_ref``: the target would be a direct child of the
      component whose ``bom-ref`` is ``parent_ref``. The parent must be a component of this
      document (the subject, a listed component or a nested component) and its reference must be
      unambiguous; records naming it are component-specific candidates (G6-D1, D11, D12), and
      records naming the root are root-level candidates unless the parent is the root itself.

    Everything else (scope filtering, BOM-Link, ambiguous or unregistered references, the G6-D8
    worst case, root-level candidates that never cover S here) is exactly as in
    ``enumerate_decl_candidates``. Pure; nothing is mutated.
    """
    registry = _Registry.build(record)

    def result(status, reasons, parent_locator=None, parent=None, candidates=(), groups=(),
               roots=(), exclusions=()):
        return DeclEnumeration(
            doc_id=record.doc_id, target_locator=None, status=status, status_reasons=tuple(reasons),
            parent_locator=parent_locator, parent_ref=parent, candidates=tuple(candidates),
            groups=tuple(groups), root_level_candidates=tuple(roots), exclusions=tuple(exclusions),
            placement=placement,
        )

    if placement is None:
        _, roots, exclusions = _scan(record, registry, None)
        return result(EnumerationStatus.TARGET_LOCATION_UNAVAILABLE, (StatusReason.PLACEMENT_UNSPECIFIED,),
                      roots=roots, exclusions=exclusions)

    if placement == "top_level":
        _, roots, exclusions = _scan(record, registry, ("#/components/0", _TOP, None), virtual_target=True)
        return result(EnumerationStatus.NO_CANDIDATE, (StatusReason.TOP_LEVEL_TARGET_NO_PARENT_ASSEMBLY,),
                      _TOP, None, roots=roots, exclusions=exclusions)

    if placement != "nested_under_component" or not parent_ref:
        return result(EnumerationStatus.TARGET_LOCATION_UNAVAILABLE, (StatusReason.PLACEMENT_INVALID,))

    if parent_ref in registry.conflicted_refs:
        _, roots, exclusions = _scan(record, registry, None)
        return result(EnumerationStatus.NO_CANDIDATE, (StatusReason.PARENT_REFERENCE_AMBIGUOUS,),
                      None, parent_ref, exclusions=exclusions)
    locations = sorted(
        {loc for loc, ref in registry.listed.items() if ref == parent_ref}
        | {loc for loc, ref in registry.nested.items() if ref == parent_ref}
        | ({registry.subject_locator} if registry.subject_locator and registry.subject_ref == parent_ref else set())
    )
    if len(locations) > 1:  # the same reference at two component locations: ambiguous
        return result(EnumerationStatus.NO_CANDIDATE, (StatusReason.PARENT_REFERENCE_AMBIGUOUS,), None, parent_ref)
    if not locations:
        reason = (StatusReason.PARENT_NOT_A_COMPONENT if parent_ref in registry.other.values()
                  else StatusReason.PARENT_REF_NOT_IN_DOCUMENT)
        return result(EnumerationStatus.TARGET_NOT_IN_DOCUMENT, (reason,), None, parent_ref)
    parent_locator = locations[0]
    virtual = f"{parent_locator}/components/0"
    candidates, roots, exclusions = _scan(record, registry, (virtual, parent_locator, parent_ref), virtual_target=True)
    if candidates:
        states = [c.state for c in candidates]
        group = DeclGroup(
            parent_locator=parent_locator, parent_ref=parent_ref, members=tuple(candidates),
            state=worst_case_state(states), tie=len(candidates) > 1, disagreement=len(set(states)) > 1,
        )
        return result(EnumerationStatus.CANDIDATES_FOUND, (), parent_locator, parent_ref, candidates, (group,),
                      roots, exclusions)
    return result(EnumerationStatus.NO_CANDIDATE, (StatusReason.NO_RECORD_NAMES_PARENT,), parent_locator,
                  parent_ref, roots=roots, exclusions=exclusions)


def _scan(
    record: SbomRecord,
    registry: _Registry,
    target: Optional[tuple[str, str, Optional[str]]],
    *,
    virtual_target: bool = False,
) -> tuple[list[DeclCandidate], list[RootLevelCandidate], list[DeclExclusion]]:
    """One pass over the composition records. ``target`` is ``(locator, parent_locator,
    parent_ref)`` or ``None`` (then only target-independent findings and, if the root is
    named, root-level candidates for an unavailable location are produced)."""
    candidates: list[DeclCandidate] = []
    roots: list[RootLevelCandidate] = []
    exclusions: list[DeclExclusion] = []
    root_ref = registry.subject_ref

    target_ref: Optional[str] = None
    above: list[Optional[str]] = []
    tree: Optional[str] = None
    if target is not None:
        target_locator, _, _ = target
        # A virtual target (a would-be child that is not in the document) has no reference of
        # its own; a real component that happens to sit at the same pointer must not be read
        # as "the target".
        target_ref = None if virtual_target else registry.ref_at(target_locator)
        above = [registry.ref_at(loc) for loc in _ancestors_above_parent(target_locator)]
        tree = _component_tree(target_locator, registry.subject_locator)

    for composition in record.composition_records:
        scope_reason = _scope_exclusion(composition)
        if scope_reason is not None:
            exclusions.append(DeclExclusion(composition.locator, scope_reason))
            continue
        ignored = _ignored_lists(composition)
        for ref in _unique(composition.assemblies):
            if BOM_LINK_PATTERN.fullmatch(ref):
                exclusions.append(DeclExclusion(composition.locator, ExclusionReason.BOM_LINK_UNMATCHED, ref))
                continue
            if ref in registry.conflicted_refs:
                exclusions.append(DeclExclusion(composition.locator, ExclusionReason.AMBIGUOUS_REFERENCE, ref))
                continue
            if record.resolve(ref).status is ReferenceStatus.NOT_IN_REGISTRY:
                exclusions.append(
                    DeclExclusion(composition.locator, ExclusionReason.REFERENCE_NOT_IN_REGISTRY, ref)
                )
                continue

            if target is None:
                if root_ref is not None and ref == root_ref:
                    roots.append(_root_candidate(composition, ref, TargetPosition.LOCATION_UNAVAILABLE, ignored))
                continue

            _, parent_locator, parent_ref = target
            if parent_locator != _TOP and parent_ref is not None and ref == parent_ref:
                candidates.append(
                    DeclCandidate(
                        record_locator=composition.locator,
                        reference=ref,
                        relation=CandidateRelation.NAMED_PARENT,
                        state=composition.state,
                        aggregate_raw=composition.aggregate_raw,
                        aggregate_recognized=composition.aggregate_recognized,
                        ignored_scope_lists=ignored,
                        parent_is_document_subject=parent_locator == registry.subject_locator,
                    )
                )
            elif root_ref is not None and ref == root_ref and tree is not None:
                # G6-D13: the root's reference is a document-level fallback candidate for
                # every in-scope target that is not its direct nested child (which took
                # the component-specific branch above); never a recursive inheritance.
                if tree == "root":
                    position = TargetPosition.BELOW_ROOT_CHILD
                elif parent_locator == _TOP:
                    position = TargetPosition.TOP_LEVEL
                else:
                    position = TargetPosition.BELOW_TOP_LEVEL
                roots.append(_root_candidate(composition, ref, position, ignored))
            elif target_ref is not None and ref == target_ref:
                exclusions.append(DeclExclusion(composition.locator, ExclusionReason.NAMES_TARGET_ITSELF, ref))
            elif ref in above:
                exclusions.append(DeclExclusion(composition.locator, ExclusionReason.NOT_DIRECT_CHILD, ref))
    return candidates, roots, exclusions


def _root_candidate(
    composition: CompositionRecord,
    root_ref: str,
    position: TargetPosition,
    ignored: tuple[str, ...],
) -> RootLevelCandidate:
    met = composition.aggregate_recognized and composition.state is EvidenceState.PRESENT
    reasons = [RootLevelReason.COVERS_S_UNDETERMINED]
    if not met:
        reasons.append(RootLevelReason.AGGREGATE_NOT_COMPLETE)
    return RootLevelCandidate(
        record_locator=composition.locator,
        root_ref=root_ref,
        state=composition.state,
        aggregate_raw=composition.aggregate_raw,
        aggregate_recognized=composition.aggregate_recognized,
        necessary_condition_met=met,
        covers_s=CoversS.UNDETERMINED,
        target_position=position,
        reasons=tuple(reasons),
        ignored_scope_lists=ignored,
    )
