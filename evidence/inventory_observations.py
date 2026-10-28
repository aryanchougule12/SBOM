"""Neutral inventory observations from a parsed SBOM record (Stage 2 foundation).

``observe_inventory(record)`` restates, as typed frozen records, what the parser and the
Stage 1 adapter *established* about a document's component list and references: which
components the parser returned, which dependency or relationship endpoints the document
declares, how each endpoint resolves in the document's own registry, which reference
declarations conflicted, and how an SPDX document's subject declarations resolved. Every
observation carries the document id and the source locator.

These are parsed facts, not evidence states. This module does not:

* decide what is a member of the full inventory, or infer that the listed components are the
  whole inventory (register G11 Q2);
* turn ``NOT_IN_REGISTRY`` into a dangling reference or a contradiction, or decide which
  checks are required, whether anything is relevant to S, or what is interpretable (G11 Q4);
* treat a duplicate or conflicting reference as ``INV = Contradictory`` (C3 is deferred);
* derive INV, DECL, MATCH or BIND, or produce any ``EvidenceState``, completeness,
  absence or verdict.

Counting domain. ``listed_components`` is exactly the components the parser returned for the
document, nothing more:

* CycloneDX: every entry of the top-level ``components`` array and, recursively, of nested
  ``components``, in pre-order. The described subject (``metadata.component``), ``services``
  and objects reachable only through other schema locations are not included.
* SPDX 2.3: every ``packages`` entry. ``files`` and ``snippets`` are not included.

``subject_nested_components`` are the CycloneDX components nested under the subject
(``metadata.component.components``, recursively, pre-order), which the parser records apart from
the top-level list. The approved member domain (register, D1) is the union of the two: top-level
components recursively, components nested under ``metadata.component``, and SPDX packages. The
subject itself, services, SPDX files and snippets, and pedigree objects are not members.
``evidence.inventory_members`` builds that union with the components themselves (for
matching); ``member_domain_extracted`` says whether the document's stored metadata carried the
subject-nested list, so that a domain that was not fully extracted is never mistaken for a
complete one.

A count of these is a count of records the parser returned. It is not the size of the
inventory for S.

Determinism. Every observation tuple is sorted by a natural order of its locator (numeric
JSON Pointer segments compare as numbers) and then by its own fields, so the result does not
depend on the order in which the record's collections were built. The input record is never
mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, TypeVar

from evidence.stage1_records import ReferenceStatus, SbomRecord

MEMBER_DOMAIN = (
    "approved member domain: CycloneDX top-level components (recursively) and components nested "
    "under metadata.component (recursively); SPDX packages; not the subject, services, SPDX files "
    "or snippets, or pedigree objects"
)

LISTED_COMPONENT_COUNTING_DOMAIN = (
    "components the parser returned: CycloneDX top-level and nested 'components' (pre-order, "
    "excluding metadata.component and services); SPDX 'packages' (excluding files and snippets)"
)


@dataclass(frozen=True)
class EndpointObservation:
    """One endpoint reference and its neutral registry lookup. ``NOT_IN_REGISTRY`` means
    only that the string is not in this document's registry; it is not "dangling"."""

    ref: str
    status: ReferenceStatus
    kinds: tuple[str, ...]
    locators: tuple[str, ...]


@dataclass(frozen=True)
class ListedComponentObservation:
    """A component the parser returned. ``declared_type`` is the CycloneDX ``type`` string
    (``None`` for SPDX). ``registry`` is the neutral lookup of its raw ``bom_ref`` (``None``
    when it has none). Nothing here says the component is a member of the inventory for S."""

    doc_id: str
    locator: str
    name: str
    version: Optional[str]
    bom_ref: Optional[str]
    declared_type: Optional[str]
    registry: Optional[EndpointObservation] = None


@dataclass(frozen=True)
class SubjectNestedComponentObservation:
    """A CycloneDX component nested under ``metadata.component``, recorded apart from the
    top-level list. Same fields and caveats as ``ListedComponentObservation``."""

    doc_id: str
    locator: str
    name: str
    version: Optional[str]
    bom_ref: Optional[str]
    declared_type: Optional[str]
    registry: Optional[EndpointObservation] = None


@dataclass(frozen=True)
class EdgeObservation:
    """A declared dependency edge or relationship, verbatim (direction not normalised)."""

    doc_id: str
    locator: str
    edge_type: str
    raw_relationship: str
    source: EndpointObservation
    target: EndpointObservation


@dataclass(frozen=True)
class DependencyNodeObservation:
    """A CycloneDX ``dependencies`` entry (SPDX records have none)."""

    doc_id: str
    locator: str
    ref: str
    depends_on_declared: bool


@dataclass(frozen=True)
class SubjectObservation:
    """A subject the parser read (CycloneDX ``metadata.component``; SPDX described package)."""

    doc_id: str
    locator: str
    ref: Optional[str]
    declared_via: str
    listed_as_component: bool


@dataclass(frozen=True)
class SubjectDeclarationObservation:
    """An SPDX subject declaration and what its reference resolved to in the document
    (``package``, ``file``, ``snippet`` or ``unresolved``)."""

    doc_id: str
    locator: str  # the declaration locator
    ref: str
    declared_via: str
    resolved_as: str


@dataclass(frozen=True)
class RecordedEntry:
    """A parser-recorded conflict or mismatch entry, kept as sorted ``(key, value)`` pairs
    with the values as text. ``ref`` is the entry's ``ref`` when it has one. The entry is
    reported, not interpreted."""

    doc_id: str
    ref: Optional[str]
    items: tuple[tuple[str, str], ...]

    @property
    def locator(self) -> Optional[str]:
        """The entry's own ``locator`` value when the parser recorded one."""
        return dict(self.items).get("locator")


@dataclass(frozen=True)
class InventoryObservations:
    """Parsed facts about one SBOM document. Not an evidence state."""

    doc_id: str
    format: str
    listed_components: tuple[ListedComponentObservation, ...]
    edges: tuple[EdgeObservation, ...]
    dependency_nodes: tuple[DependencyNodeObservation, ...]
    subjects: tuple[SubjectObservation, ...]
    subject_declarations: tuple[SubjectDeclarationObservation, ...]
    subject_declaration_mismatches: tuple[RecordedEntry, ...]
    reference_conflicts: tuple[RecordedEntry, ...]
    unextracted_top_level_fields: tuple[str, ...]
    subject_nested_components: tuple[SubjectNestedComponentObservation, ...] = ()
    member_domain_extracted: bool = False

    @property
    def member_count(self) -> int:
        """Listed plus subject-nested components (``MEMBER_DOMAIN``). A count of parsed records,
        not the size of the inventory for S."""
        return len(self.listed_components) + len(self.subject_nested_components)

    @property
    def listed_component_count(self) -> int:
        """Records returned by the parser (see ``LISTED_COMPONENT_COUNTING_DOMAIN``)."""
        return len(self.listed_components)

    @property
    def endpoints_not_in_registry(self) -> int:
        """Edge endpoints (source and target, each counted per edge) that were not found in
        the document's own registry. A count of lookups, not of defects."""
        return sum(
            endpoint.status is ReferenceStatus.NOT_IN_REGISTRY
            for edge in self.edges
            for endpoint in (edge.source, edge.target)
        )


# ---- ordering ---------------------------------------------------------------------------------

_T = TypeVar("_T")


def locator_sort_key(locator: Optional[str]) -> tuple:
    if locator is None:
        return ((2, 0, ""),)
    return tuple((0, int(seg), "") if seg.isdigit() else (1, 0, seg) for seg in locator.split("/"))


def _ordered(items: Iterable[_T], locator_of) -> tuple[_T, ...]:
    return tuple(sorted(items, key=lambda o: (locator_sort_key(locator_of(o)), repr(o))))


def _endpoint(resolution) -> EndpointObservation:
    return EndpointObservation(
        ref=resolution.ref,
        status=resolution.status,
        kinds=tuple(resolution.kinds),
        locators=tuple(resolution.locators),
    )


def _recorded(doc_id: str, entry: Mapping[str, Any]) -> RecordedEntry:
    items = tuple(sorted((str(key), str(value)) for key, value in entry.items()))
    ref = entry.get("ref")
    return RecordedEntry(doc_id, ref if isinstance(ref, str) else None, items)


def _registry(record: SbomRecord, bom_ref: Optional[str]) -> Optional[EndpointObservation]:
    return _endpoint(record.resolve(bom_ref)) if bom_ref is not None else None


def observe_inventory(record: SbomRecord) -> InventoryObservations:
    """Build the neutral observations for ``record``. Pure and deterministic."""
    doc_id = record.doc_id

    listed = _ordered(
        (
            ListedComponentObservation(
                doc_id=doc_id,
                locator=entry["locator"],
                name=component.name,
                version=component.version,
                bom_ref=component.bom_ref,
                declared_type=entry.get("type") if isinstance(entry.get("type"), str) else None,
                registry=_registry(record, component.bom_ref),
            )
            for component, entry in zip(record.components, record.component_index)
        ),
        lambda o: o.locator,
    )
    nested = _ordered(
        (
            SubjectNestedComponentObservation(
                doc_id=doc_id,
                locator=located.locator,
                name=located.component.name,
                version=located.component.version,
                bom_ref=located.component.bom_ref,
                declared_type=located.declared_type,
                registry=_registry(record, located.component.bom_ref),
            )
            for located in record.subject_components
        ),
        lambda o: o.locator,
    )
    edges = _ordered(
        (
            EdgeObservation(
                doc_id=doc_id,
                locator=resolved.edge.locator,
                edge_type=resolved.edge.edge_type,
                raw_relationship=resolved.edge.raw_relationship,
                source=_endpoint(resolved.source),
                target=_endpoint(resolved.target),
            )
            for resolved in record.resolve_edges()
        ),
        lambda o: o.locator,
    )
    nodes = _ordered(
        (
            DependencyNodeObservation(doc_id, node.locator, node.ref, node.depends_on_declared)
            for node in record.nodes
        ),
        lambda o: o.locator,
    )
    subjects = _ordered(
        (
            SubjectObservation(doc_id, s.locator, s.ref, s.declared_via, s.listed_as_component)
            for s in record.document.subjects
        ),
        lambda o: o.locator,
    )
    declarations = _ordered(
        (
            SubjectDeclarationObservation(doc_id, d.declaration_locator, d.ref, d.declared_via, d.resolved_as)
            for d in record.subject_declarations
        ),
        lambda o: o.locator,
    )
    mismatches = _ordered(
        (_recorded(doc_id, entry) for entry in record.subject_declaration_mismatch), lambda o: o.locator
    )
    conflicts = _ordered(
        (_recorded(doc_id, entry) for entry in record.defined_ref_conflicts), lambda o: o.locator
    )
    return InventoryObservations(
        doc_id=doc_id,
        format=record.format,
        listed_components=listed,
        edges=edges,
        dependency_nodes=nodes,
        subjects=subjects,
        subject_declarations=declarations,
        subject_declaration_mismatches=mismatches,
        reference_conflicts=conflicts,
        unextracted_top_level_fields=tuple(sorted(record.unextracted_top_level_fields)),
        subject_nested_components=nested,
        member_domain_extracted=record.subject_components_extracted,
    )
