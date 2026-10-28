"""Typed adapter for Stage 1 parser output (Stage 2, slice 1).

The Stage 1 parsers return ``(SourceDocument, list[Component])`` (CycloneDX, SPDX) or
``(SourceDocument, list[Finding])`` (OpenVEX). Neither ``SourceDocument`` nor ``Finding``
carries the parsed component list, and the structured parser output is stored in
``SourceDocument.declared_metadata`` as JSON text. This module bundles each parsed
document with its components and decodes that JSON text into typed, frozen records so
that later extraction can reach the inventory without re-parsing and without assuming
fields the model does not have.

What this module is NOT. It interprets nothing:

* No completeness, presence, absence, matching, binding or provenance decision is made.
* ``ReferenceStatus.RESOLVED`` / ``NOT_IN_REGISTRY`` describe only whether a reference
  string appears in the document's own reference registry (ordinary components, subjects,
  the document node, and ``other_defined_refs``). They are neutral lookups. A reference
  that is ``RESOLVED`` is not thereby an inventory component and is never evidence that
  any target component is present. A reference that is ``NOT_IN_REGISTRY`` is not thereby
  "missing" or "dangling": examples that are valid yet unregistered include SPDX
  ``NOASSERTION``/``NONE`` endpoints and ``DocumentRef-...:`` external-document endpoints
  (``externalDocumentRefs`` is not extracted by the parser), and any object the parser's
  schema-location table does not cover. Whether that matters is an open question (see
  ``docs/open_issues_register.md``, G11).
* Parser behaviour is untouched. The adapter reads exactly what the committed parsers
  write; a document whose stored metadata is absent or malformed raises
  ``RecordDecodeError`` instead of yielding empty records.

Decoding builds new objects on every call; the input ``SourceDocument`` and component
list are never mutated (the record holds the same ``SourceDocument`` object by reference
and a tuple copy of the component list).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Sequence

from model import Component, EvidenceState, Finding, Hash, SourceDocument
from sbom_parser._common import InputSource
from sbom_parser.cyclonedx import parse_cyclonedx
from sbom_parser.identifiers import build_identifier_variants
from sbom_parser.openvex import parse_openvex
from sbom_parser.spdx import parse_spdx

FORMAT_CYCLONEDX = "CycloneDX"
FORMAT_SPDX = "SPDX"
FORMAT_OPENVEX = "OpenVEX"


class RecordDecodeError(ValueError):
    """Stored Stage 1 metadata is absent, not valid JSON, or structurally unexpected."""

    def __init__(self, doc_id: str, key: str, message: str) -> None:
        self.doc_id = doc_id
        self.key = key
        self.message = message
        super().__init__(f"{doc_id}: declared_metadata[{key!r}]: {message}")


# ---- decoded records -----------------------------------------------------------------

@dataclass(frozen=True)
class DeclaredEdge:
    """One declared dependency edge (CycloneDX) or relationship (SPDX), verbatim.

    ``edge_type`` is ``declared_dependency`` or ``declared_relationship``. Direction is
    not normalised. These are package-level declarations: never call edges and never
    evidence of reachability.
    """

    edge_type: str
    raw_relationship: str
    source: str
    target: str
    locator: str


@dataclass(frozen=True)
class DependencyNode:
    """A CycloneDX ``dependencies`` entry: its ``ref`` and whether ``dependsOn`` was
    declared (an explicitly empty array and an absent one are different statements)."""

    ref: str
    locator: str
    depends_on_declared: bool


@dataclass(frozen=True)
class CompositionRecord:
    """One CycloneDX ``compositions`` entry as the parser recorded it. No record is
    selected, merged or promoted to document-wide completeness here."""

    locator: str
    bom_ref: Optional[str]
    aggregate_raw: str
    aggregate_recognized: bool
    state: EvidenceState
    assemblies: tuple[str, ...]
    dependencies: tuple[str, ...]
    vulnerabilities: tuple[str, ...]
    scope_declared: bool


@dataclass(frozen=True)
class SignatureRecord:
    """A signature object found in the document: the container it sits in, whether its
    coverage claim is representable, and the raw object. A claim only; unverified."""

    covers: str
    coverage_claimed: bool
    signature: Mapping[str, Any]


@dataclass(frozen=True)
class SubjectDeclaration:
    """An SPDX subject declaration and what its reference resolved to in the document
    (``package``, ``file``, ``snippet`` or ``unresolved``)."""

    ref: str
    declared_via: str
    declaration_locator: str
    resolved_as: str


@dataclass(frozen=True)
class LocatedComponent:
    """A component the parser recorded with its document locator but did not return in the
    ordinary component list: a component nested under the CycloneDX subject
    (``metadata.component``). ``declared_type`` is the CycloneDX ``type`` string."""

    locator: str
    declared_type: Optional[str]
    component: Component


class ReferenceStatus(str, Enum):
    """Neutral result of a registry lookup. Not a finding about the inventory."""

    RESOLVED = "resolved"
    NOT_IN_REGISTRY = "not_in_registry"


@dataclass(frozen=True)
class ReferenceResolution:
    """Lookup of one reference string in the document's own registry.

    ``kinds`` lists every registry the reference appears in, in a fixed order:
    ``listed_component``, ``subject``, ``document``, then the ``other_defined_refs`` kind
    (for example ``service`` or ``nested_component``). ``locators`` are the declaration
    locators known for those entries (empty when none is recorded).
    """

    ref: str
    status: ReferenceStatus
    kinds: tuple[str, ...] = ()
    locators: tuple[str, ...] = ()


@dataclass(frozen=True)
class EdgeResolution:
    edge: DeclaredEdge
    source: ReferenceResolution
    target: ReferenceResolution


@dataclass(frozen=True)
class SbomRecord:
    """A parsed SBOM document bundled with its components and decoded Stage 1 records.

    ``component_index`` entries are kept as decoded dictionaries (including the
    ``unextracted_*`` keys) so nothing the parser recorded is dropped. For CycloneDX,
    ``nodes`` holds ``dependencies`` entries; for SPDX it is empty and ``edges`` holds the
    relationships. ``subject_declarations`` is SPDX-only; ``signature_records`` is
    CycloneDX-only; the other format leaves them empty. ``subject_components`` are the
    components nested under the CycloneDX subject (pre-order); ``subject_components_extracted``
    is True when the document's stored metadata actually carried that list (always for SPDX,
    which has no such nesting) and False when it was absent, in which case the member domain
    of the document is not known to be fully extracted.
    """

    document: SourceDocument
    components: tuple[Component, ...]
    format: str
    component_index: tuple[Mapping[str, Any], ...]
    edges: tuple[DeclaredEdge, ...]
    nodes: tuple[DependencyNode, ...]
    composition_records: tuple[CompositionRecord, ...]
    subject_declarations: tuple[SubjectDeclaration, ...]
    subject_declaration_mismatch: tuple[Mapping[str, Any], ...]
    signature_records: tuple[SignatureRecord, ...]
    defined_ref_locators: Mapping[str, str]
    defined_ref_conflicts: tuple[Mapping[str, Any], ...]
    unextracted_top_level_fields: tuple[str, ...]
    subject_components: tuple[LocatedComponent, ...] = ()
    subject_components_extracted: bool = False

    @property
    def doc_id(self) -> str:
        return self.document.doc_id

    def resolve(self, ref: str) -> ReferenceResolution:
        """Look ``ref`` up in this document's registry (neutral; see module docstring)."""
        kinds: list[str] = []
        locators: list[str] = []
        for component, entry in zip(self.components, self.component_index):
            if component.bom_ref is not None and component.bom_ref == ref:
                kinds.append("listed_component")
                locators.append(entry["locator"])
                break
        for subject in self.document.subjects:
            if subject.ref is not None and subject.ref == ref:
                kinds.append("subject")
                locators.append(subject.locator)
                break
        if self.document.document_ref is not None and self.document.document_ref == ref:
            kinds.append("document")
            locators.append("#")
        if ref in self.document.other_defined_refs:
            kinds.append(self.document.other_defined_refs[ref])
            if ref in self.defined_ref_locators:
                locators.append(self.defined_ref_locators[ref])
        status = ReferenceStatus.RESOLVED if kinds else ReferenceStatus.NOT_IN_REGISTRY
        return ReferenceResolution(ref, status, tuple(kinds), tuple(locators))

    def resolve_edges(self) -> tuple[EdgeResolution, ...]:
        """Resolve both endpoints of every declared edge, in edge order."""
        return tuple(
            EdgeResolution(edge, self.resolve(edge.source), self.resolve(edge.target))
            for edge in self.edges
        )


@dataclass(frozen=True)
class VexRecord:
    """A parsed OpenVEX document with its findings and statement-level documents.

    ``finding_targets`` maps each statement document id to the decoded
    ``finding_targets`` list (``product_locator`` / ``target_locator`` per finding).
    """

    document: SourceDocument
    findings: tuple[Finding, ...]
    statement_documents: Mapping[str, SourceDocument]
    finding_targets: Mapping[str, tuple[Mapping[str, Any], ...]]

    @property
    def doc_id(self) -> str:
        return self.document.doc_id


class Stage1Index:
    """Maps a source-document id to its ``SbomRecord``.

    Adding the same record twice is idempotent (document ids are content-derived); a
    different record under an existing id is an error rather than a silent overwrite.
    """

    def __init__(self, records: Iterable[SbomRecord] = ()) -> None:
        self._records: dict[str, SbomRecord] = {}
        for record in records:
            self.add(record)

    def add(self, record: SbomRecord) -> None:
        existing = self._records.get(record.doc_id)
        if existing is not None and existing != record:
            raise ValueError(f"a different record is already indexed for {record.doc_id!r}")
        self._records[record.doc_id] = record

    def get(self, doc_id: str) -> Optional[SbomRecord]:
        return self._records.get(doc_id)

    def __contains__(self, doc_id: object) -> bool:
        return doc_id in self._records

    def __len__(self) -> int:
        return len(self._records)

    def doc_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._records))


# ---- decoding ------------------------------------------------------------------------

def _load(document: SourceDocument, key: str, expected: type) -> Any:
    declared = document.declared_metadata
    if key not in declared:
        raise RecordDecodeError(document.doc_id, key, "required key is missing")
    text = declared[key]
    if not isinstance(text, str):
        raise RecordDecodeError(document.doc_id, key, "stored value is not JSON text")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecordDecodeError(document.doc_id, key, f"not valid JSON: {exc}") from exc
    if not isinstance(value, expected):
        raise RecordDecodeError(
            document.doc_id, key,
            f"expected a JSON {expected.__name__}, got {type(value).__name__}",
        )
    return value


def _entries(document: SourceDocument, key: str) -> list[dict[str, Any]]:
    value = _load(document, key, list)
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise RecordDecodeError(document.doc_id, key, f"entry {index} is not an object")
    return value


def _field(document: SourceDocument, key: str, entry: Mapping[str, Any], name: str,
           kind: type, *, nullable: bool = False) -> Any:
    if name not in entry:
        raise RecordDecodeError(document.doc_id, key, f"entry lacks required field {name!r}")
    value = entry[name]
    if value is None and nullable:
        return None
    if kind is bool:
        ok = isinstance(value, bool)
    else:
        ok = isinstance(value, kind) and not isinstance(value, bool)
    if not ok:
        raise RecordDecodeError(
            document.doc_id, key, f"field {name!r} must be {kind.__name__}, got {type(value).__name__}"
        )
    return value


def _str_tuple(document: SourceDocument, key: str, entry: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = _field(document, key, entry, name, list)
    if not all(isinstance(v, str) for v in value):
        raise RecordDecodeError(document.doc_id, key, f"field {name!r} must be a list of strings")
    return tuple(value)


def _decode_edges(document: SourceDocument, key: str) -> tuple[DeclaredEdge, ...]:
    return tuple(
        DeclaredEdge(
            edge_type=_field(document, key, e, "edge_type", str),
            raw_relationship=_field(document, key, e, "raw_relationship", str),
            source=_field(document, key, e, "source", str),
            target=_field(document, key, e, "target", str),
            locator=_field(document, key, e, "locator", str),
        )
        for e in _entries(document, key)
    )


def _decode_compositions(document: SourceDocument) -> tuple[CompositionRecord, ...]:
    key = "composition_records"
    records: list[CompositionRecord] = []
    for e in _entries(document, key):
        state_text = _field(document, key, e, "state", str)
        try:
            state = EvidenceState(state_text)
        except ValueError as exc:
            raise RecordDecodeError(document.doc_id, key, f"unknown state {state_text!r}") from exc
        records.append(
            CompositionRecord(
                locator=_field(document, key, e, "locator", str),
                bom_ref=_field(document, key, e, "bom_ref", str, nullable=True),
                aggregate_raw=_field(document, key, e, "aggregate_raw", str),
                aggregate_recognized=_field(document, key, e, "aggregate_recognized", bool),
                state=state,
                assemblies=_str_tuple(document, key, e, "assemblies"),
                dependencies=_str_tuple(document, key, e, "dependencies"),
                vulnerabilities=_str_tuple(document, key, e, "vulnerabilities"),
                scope_declared=_field(document, key, e, "scope_declared", bool),
            )
        )
    return tuple(records)


def _decode_string_map(document: SourceDocument, key: str) -> dict[str, str]:
    value = _load(document, key, dict)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise RecordDecodeError(document.doc_id, key, "expected an object of string values")
    return value


def _decode_subject_components(document: SourceDocument) -> tuple[bool, tuple[LocatedComponent, ...]]:
    key = "subject_component_index"
    if key not in document.declared_metadata:
        return False, ()
    located: list[LocatedComponent] = []
    for e in _entries(document, key):
        raw = _field(document, key, e, "component", dict)
        name = _field(document, key, raw, "name", str)
        version = _field(document, key, raw, "version", str, nullable=True)
        purl = _field(document, key, raw, "purl", str, nullable=True)
        cpes = list(_str_tuple(document, key, raw, "cpe"))
        hashes: list[Hash] = []
        for h in _field(document, key, raw, "hashes", list):
            if not isinstance(h, dict):
                raise RecordDecodeError(document.doc_id, key, "hash entries must be objects")
            hashes.append(Hash(_field(document, key, h, "algorithm", str), _field(document, key, h, "value", str)))
        located.append(
            LocatedComponent(
                locator=_field(document, key, e, "locator", str),
                declared_type=_field(document, key, e, "type", str, nullable=True),
                component=Component(
                    name=name,
                    version=version,
                    purl=purl,
                    cpe=cpes,
                    ecosystem=None,
                    supplier=_field(document, key, raw, "supplier", str, nullable=True),
                    hashes=hashes,
                    bom_ref=_field(document, key, raw, "bom_ref", str, nullable=True),
                    identifier_variants=build_identifier_variants(name, version, purl, cpes, hashes),
                ),
            )
        )
    return True, tuple(located)


def from_parsed_sbom(document: SourceDocument, components: Sequence[Component]) -> SbomRecord:
    """Bundle a parsed CycloneDX or SPDX result into an ``SbomRecord``.

    Raises ``RecordDecodeError`` if the document is not a CycloneDX/SPDX parse result or
    its stored metadata is absent or malformed.
    """
    fmt = document.declared_metadata.get("format")
    if fmt not in (FORMAT_CYCLONEDX, FORMAT_SPDX):
        raise RecordDecodeError(document.doc_id, "format", f"not an SBOM parse result: {fmt!r}")

    component_index = tuple(_entries(document, "component_index"))
    if len(component_index) != len(components):
        raise RecordDecodeError(
            document.doc_id, "component_index",
            f"has {len(component_index)} entries for {len(components)} components",
        )
    for index, entry in enumerate(component_index):
        _field(document, "component_index", entry, "locator", str)

    nodes: tuple[DependencyNode, ...] = ()
    subject_declarations: tuple[SubjectDeclaration, ...] = ()
    mismatch: tuple[Mapping[str, Any], ...] = ()
    signatures: tuple[SignatureRecord, ...] = ()
    if fmt == FORMAT_CYCLONEDX:
        edges = _decode_edges(document, "declared_dependency_edges")
        node_key = "declared_dependency_nodes"
        nodes = tuple(
            DependencyNode(
                ref=_field(document, node_key, e, "ref", str),
                locator=_field(document, node_key, e, "locator", str),
                depends_on_declared=_field(document, node_key, e, "depends_on_declared", bool),
            )
            for e in _entries(document, node_key)
        )
        sig_key = "signature_records"
        signatures = tuple(
            SignatureRecord(
                covers=_field(document, sig_key, e, "covers", str),
                coverage_claimed=_field(document, sig_key, e, "coverage_claimed", bool),
                signature=_field(document, sig_key, e, "signature", dict),
            )
            for e in _entries(document, sig_key)
        )
    else:
        edges = _decode_edges(document, "declared_relationships")
        decl_key = "subject_declarations"
        subject_declarations = tuple(
            SubjectDeclaration(
                ref=_field(document, decl_key, e, "ref", str),
                declared_via=_field(document, decl_key, e, "declared_via", str),
                declaration_locator=_field(document, decl_key, e, "declaration_locator", str),
                resolved_as=_field(document, decl_key, e, "resolved_as", str),
            )
            for e in _entries(document, decl_key)
        )
        mismatch = tuple(_entries(document, "subject_declaration_mismatch"))

    unextracted = _load(document, "unextracted_top_level_fields", list)
    if not all(isinstance(v, str) for v in unextracted):
        raise RecordDecodeError(
            document.doc_id, "unextracted_top_level_fields", "expected a list of strings"
        )
    if fmt == FORMAT_CYCLONEDX:
        subject_extracted, subject_components = _decode_subject_components(document)
    else:
        subject_extracted, subject_components = True, ()  # SPDX has no nesting under a subject
    return SbomRecord(
        document=document,
        components=tuple(components),
        format=fmt,
        component_index=component_index,
        edges=edges,
        nodes=nodes,
        composition_records=_decode_compositions(document),
        subject_declarations=subject_declarations,
        subject_declaration_mismatch=mismatch,
        signature_records=signatures,
        defined_ref_locators=_decode_string_map(document, "defined_ref_locators"),
        defined_ref_conflicts=tuple(_entries(document, "defined_ref_conflicts")),
        unextracted_top_level_fields=tuple(unextracted),
        subject_components=subject_components,
        subject_components_extracted=subject_extracted,
    )


def from_parsed_vex(document: SourceDocument, findings: Sequence[Finding]) -> VexRecord:
    """Bundle a parsed OpenVEX result into a ``VexRecord``."""
    if document.declared_metadata.get("format") != FORMAT_OPENVEX:
        raise RecordDecodeError(
            document.doc_id, "format",
            f"not an OpenVEX parse result: {document.declared_metadata.get('format')!r}",
        )
    statement_documents: dict[str, SourceDocument] = {}
    for finding in findings:
        for doc_id, doc in finding.source_documents.items():
            if doc_id != document.doc_id:
                statement_documents.setdefault(doc_id, doc)
    targets: dict[str, tuple[Mapping[str, Any], ...]] = {}
    for doc_id in sorted(statement_documents):
        statement = statement_documents[doc_id]
        entries = _entries(statement, "finding_targets")
        for e in entries:
            _field(statement, "finding_targets", e, "product_locator", str)
            _field(statement, "finding_targets", e, "target_locator", str, nullable=True)
        targets[doc_id] = tuple(entries)
    return VexRecord(document, tuple(findings), statement_documents, targets)


# ---- convenience loaders -------------------------------------------------------------

def load_cyclonedx(source: InputSource) -> SbomRecord:
    document, components = parse_cyclonedx(source)
    return from_parsed_sbom(document, components)


def load_spdx(source: InputSource) -> SbomRecord:
    document, components = parse_spdx(source)
    return from_parsed_sbom(document, components)


def load_openvex(source: InputSource) -> VexRecord:
    document, findings = parse_openvex(source)
    return from_parsed_vex(document, findings)
