"""SPDX JSON SBOM parser (Stage 1).

Supported format and version
----------------------------
SPDX **JSON** documents whose ``spdxVersion`` is exactly ``"SPDX-2.3"``
(``SUPPORTED_SPDX_VERSIONS``). Other ``SPDX-*`` versions (for example ``SPDX-2.2``) and
SPDX 3.x JSON-LD documents raise ``UnsupportedVersionError``. Tag-value, YAML, RDF/XML
and spreadsheet serializations are not supported.

How support was established: the parser reads only the fields listed below, and support
is claimed solely for what the hand-authored fixtures under ``fixtures/spdx/`` and
``tests/test_spdx_parser.py`` exercise. The official SPDX JSON schema and the
``spdx-tools`` package were not available offline, so documents are **not** validated
against the full schema; checks cover only the fields this parser reads.

Inputs and outputs
------------------
``parse_spdx(source)`` takes raw ``bytes`` or a filesystem path and returns
``(SourceDocument, list[Component])``. Failures raise ``MalformedInputError``,
``UnsupportedVersionError`` or ``InvalidDocumentError`` (``sbom_parser.errors``); invalid
input never yields an empty result.

All content is a **self-asserted claim** of the document and is not verified. No
predicate, aggregation, effective-provenance or verdict logic lives here.

``SourceDocument`` mapping (set only when the document states it)
------------------------------------------------------------------
* ``doc_id``: ``spdx:sha256:<hex of the exact input bytes>``.
* ``created``: ``creationInfo.created`` (original text in ``declared_metadata["created_raw"]``).
* ``producer`` / ``producer_class``: only when ``creationInfo.creators`` contains exactly
  one ``Organization:`` or ``Person:`` entry; ``producer`` is the text after the prefix
  and ``producer_class`` is the prefix (``"Organization"`` or ``"Person"``).
* ``tool_name`` / ``tool_version``: only when exactly one ``Tool:`` creator exists. SPDX
  writes tools as ``Tool: <identifier>-<version>``; the text is split at the last ``-``
  only if what follows starts with a digit. Otherwise the whole text is ``tool_name`` and
  ``tool_version`` stays ``None``. The raw creator strings are kept in
  ``declared_metadata["creators"]`` because this split is a heuristic.
* ``generation_context`` and ``method``: never set (SPDX 2.3 has no such fields).
* ``integrity``: left at its defaults. SPDX 2.3 JSON has no document signature field;
  package checksums describe packages, not the document.

``declared_metadata`` keys (strings; structured values are canonical JSON text)
-------------------------------------------------------------------------------
``format``, ``spec_version``, ``spdx_id``, ``document_name``, ``document_namespace``,
``data_license``, ``creators``, ``created_raw``, ``license_list_version``,
``document_describes``, ``component_index``, ``declared_relationships``,
``composition_records``, ``defined_ref_locators``, ``defined_ref_conflicts``,
``subject_declarations``, ``subject_declaration_mismatch``,
``unextracted_top_level_fields``, ``assertion_status``, ``locator_convention``.

Subject and defined references
------------------------------
Checked against the official SPDX 2.3 JSON schema (``spdx/spdx-spec``, tag ``v2.3`` and
branch ``support/2.3``): ``documentDescribes`` lists the SPDX IDs of packages, files
and/or snippets the document describes; the 2.3.1 revision marks it deprecated as a
duplicate of the ``SPDXRef-DOCUMENT DESCRIBES`` relationship; ``DESCRIBES`` and
``DESCRIBED_BY`` are both relationship types; packages, files and snippets each carry an
``SPDXID``.

* ``SourceDocument.document_ref`` is the document's own ``SPDXID``. It is the document
  node, never a package or a target component.
* ``SourceDocument.subjects`` has one ``DocumentSubject`` for every declaration that
  resolves to a *listed package*: each ``documentDescribes`` entry, each
  ``<document> DESCRIBES <x>`` relationship and each ``<x> DESCRIBED_BY <document>``
  relationship, in that order (document order within each source). Nothing is merged or
  dropped: a package declared by both mechanisms appears once per declaration, and
  distinct subjects are the distinct ``ref`` values. ``locator`` is the package
  locator; ``declared_via`` names the mechanism; ``listed_as_component`` is true.
* ``declared_metadata["subject_declarations"]`` records every declaration with its own
  locator and what it resolved to (``package``, ``file``, ``snippet`` or
  ``unresolved``), so file/snippet or unresolved descriptions are visible rather than
  silently dropped. ``subject_declaration_mismatch`` lists references declared by only one
  of the two mechanisms when both are used; the parser reports the disagreement and does
  not choose between them.
* ``SourceDocument.other_defined_refs`` registers the ``SPDXID`` of every ``files`` entry
  (kind ``file``) and ``snippets`` entry (kind ``snippet``), so a relationship endpoint
  naming them is declared rather than dangling. This does not make them components and
  asserts nothing about the inventory. An ``SPDXID`` declared more than once is
  registered once and the extra declaration goes to ``defined_ref_conflicts``.

Completeness
------------
SPDX 2.3 has no standardized completeness declaration, so none is invented:
``composition_records`` is always the empty list ``[]``, which later stages must read as
a DECL state of ``Unknown``. The absence of a package or relationship in the document is
not evidence of absence of that package or of non-reachability.

Components
----------
Each entry of ``packages`` is returned in document order. ``Component`` is filled from
``name``, ``versionInfo``, ``SPDXID`` (stored in ``bom_ref``, the in-document reference
id), ``supplier`` (the ``Organization:``/``Person:`` prefix removed, ``NOASSERTION``
becomes ``None``), ``checksums`` (``algorithm``/``checksumValue``), ``externalRefs`` with
``referenceType`` ``purl`` (first one in ``Component.purl``) and ``cpe22Type`` /
``cpe23Type`` (``Component.cpe``). Further purls, the raw supplier text and the names of
keys that were not extracted (licenses, ``filesAnalyzed``, verification codes, other
external references, ...) are recorded per package in ``component_index`` so nothing is
dropped silently. ``Component.ecosystem`` is left ``None`` (see the CycloneDX parser for
the reason). Identifiers stay exactly as supplied; derived keys use
``identifiers.variant-norm-v1``.

Relationships
-------------
Every entry of ``relationships`` is preserved in ``declared_relationships`` with the
raw ``relationshipType`` and both element ids, labelled ``edge_type =
"declared_relationship"``. Direction is NOT normalised (``DEPENDS_ON`` and
``DEPENDENCY_OF`` are kept as written) and no subset is selected as "dependencies".
These are package-level declarations, never call edges, execution-path edges or evidence
of reachability.

Not represented
---------------
``files``, ``snippets``, ``hasExtractedLicensingInfos``, ``annotations``,
``externalDocumentRefs`` and other sections are not interpreted; their names are listed
in ``unextracted_top_level_fields``.
"""

from __future__ import annotations

from typing import Any, Optional

from model import Component, DocumentSubject, Hash, SourceDocument
from sbom_parser._common import (
    ASSERTION_STATUS,
    LOCATOR_CONVENTION,
    InputSource,
    canonical_json,
    document_id,
    get_list,
    get_object,
    get_str,
    load_json_object,
    parse_timestamp,
    ptr,
    ptr_join,
    read_source,
    require_object,
    require_str,
    str_list,
    unextracted_keys,
)
from sbom_parser.errors import InvalidDocumentError, UnsupportedVersionError
from sbom_parser.identifiers import build_identifier_variants

SBOMSource = InputSource

FORMAT_NAME = "SPDX"
SUPPORTED_SPDX_VERSIONS = ("SPDX-2.3",)

_HANDLED_TOP_LEVEL = {
    "spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo",
    "documentDescribes", "packages", "relationships",
}
_HANDLED_PACKAGE_KEYS = {
    "SPDXID", "name", "versionInfo", "supplier", "checksums", "externalRefs",
}
_CPE_REFERENCE_TYPES = ("cpe22Type", "cpe23Type")


def parse_spdx(source: SBOMSource) -> tuple[SourceDocument, list[Component]]:
    """Parse an SPDX 2.3 JSON SBOM into ``(SourceDocument, components)``.

    Raises ``MalformedInputError``, ``UnsupportedVersionError`` or
    ``InvalidDocumentError``. See the module docstring for exact semantics.
    """
    raw = read_source(source)
    data = load_json_object(raw, "SPDX JSON")

    if "spdxVersion" not in data:
        if "@context" in data:
            raise UnsupportedVersionError(
                "SPDX 3.x JSON-LD documents are not supported", ptr("@context")
            )
        raise InvalidDocumentError("required field 'spdxVersion' is missing", ptr())
    version = require_str(data, "spdxVersion", ptr())
    if version not in SUPPORTED_SPDX_VERSIONS:
        if version.startswith("SPDX-"):
            raise UnsupportedVersionError(
                f"unsupported SPDX version {version!r}; "
                f"supported: {', '.join(SUPPORTED_SPDX_VERSIONS)}",
                ptr("spdxVersion"),
            )
        raise InvalidDocumentError(f"'spdxVersion' is not an SPDX version: {version!r}", ptr("spdxVersion"))

    declared: dict[str, str] = {
        "format": FORMAT_NAME,
        "spec_version": version,
        "spdx_id": require_str(data, "SPDXID", ptr()),
        "document_name": require_str(data, "name", ptr()),
        "document_namespace": require_str(data, "documentNamespace", ptr()),
        "data_license": require_str(data, "dataLicense", ptr()),
        "assertion_status": ASSERTION_STATUS,
        "locator_convention": LOCATOR_CONVENTION,
    }
    document = SourceDocument(doc_id=document_id("spdx", raw))
    _read_creation_info(data, document, declared)
    declared["document_describes"] = canonical_json(str_list(data, "documentDescribes", ptr()))

    components: list[Component] = []
    component_index: list[dict[str, Any]] = []
    for index, item in enumerate(get_list(data, "packages", ptr())):
        _read_package(item, ptr("packages", index), components, component_index)
    declared["component_index"] = canonical_json(component_index)

    relationships: list[dict[str, Any]] = []
    for index, item in enumerate(get_list(data, "relationships", ptr())):
        locator = ptr("relationships", index)
        obj = require_object(item, locator, "relationship")
        relationships.append(
            {
                "edge_type": "declared_relationship",
                "source": require_str(obj, "spdxElementId", locator),
                "raw_relationship": require_str(obj, "relationshipType", locator),
                "target": require_str(obj, "relatedSpdxElement", locator),
                "locator": locator,
            }
        )
    declared["declared_relationships"] = canonical_json(relationships)
    _read_subjects_and_refs(data, document, components, component_index, relationships, declared)
    declared["composition_records"] = "[]"
    declared["unextracted_top_level_fields"] = canonical_json(
        unextracted_keys(data, _HANDLED_TOP_LEVEL)
    )

    document.declared_metadata = declared
    return document, components


def _read_creation_info(
    data: dict[str, Any], document: SourceDocument, declared: dict[str, str]
) -> None:
    info = get_object(data, "creationInfo", ptr())
    if info is None:
        raise InvalidDocumentError("required field 'creationInfo' is missing", ptr())
    base = ptr("creationInfo")
    created = require_str(info, "created", base)
    document.created = parse_timestamp(created, ptr_join(base, "created"))
    declared["created_raw"] = created
    creators = str_list(info, "creators", base)
    if "creators" not in info:
        raise InvalidDocumentError("required field 'creators' is missing", base)
    declared["creators"] = canonical_json(creators)
    license_list = get_str(info, "licenseListVersion", base)
    if license_list is not None:
        declared["license_list_version"] = license_list

    tools = [c[len("Tool:"):].strip() for c in creators if c.startswith("Tool:")]
    people = [(c.split(":", 1)[0], c.split(":", 1)[1].strip()) for c in creators
              if c.startswith(("Organization:", "Person:"))]
    if len(tools) == 1 and tools[0]:
        name, version = _split_tool(tools[0])
        document.tool_name = name
        document.tool_version = version
    if len(people) == 1 and people[0][1]:
        document.producer_class, document.producer = people[0]


def _read_subjects_and_refs(
    data: dict[str, Any],
    document: SourceDocument,
    components: list[Component],
    component_index: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    declared: dict[str, str],
) -> None:
    """Fill ``document_ref``, ``subjects`` and ``other_defined_refs`` (no inference).

    Distinct declarations are all kept: one ``DocumentSubject`` per declaration that
    resolves to a listed package, in declaration order (``documentDescribes`` first,
    then relationships in document order). Distinct subjects are distinct ``ref`` values.
    Declarations that resolve to a file or snippet, or to nothing, are not turned into
    components; they are recorded in ``declared_metadata["subject_declarations"]``.
    """
    document_ref = declared["spdx_id"]
    document.document_ref = document_ref

    known: dict[str, tuple[str, str]] = {document_ref: ("document", ptr())}
    conflicts: list[dict[str, str]] = []
    packages: dict[str, tuple[Component, str]] = {}

    def note(ref: str, kind: str, locator: str) -> bool:
        if ref in known:
            prev_kind, prev_locator = known[ref]
            conflicts.append(
                {"ref": ref, "kind": kind, "locator": locator,
                 "conflicts_with_kind": prev_kind, "conflicts_with_locator": prev_locator}
            )
            return False
        known[ref] = (kind, locator)
        return True

    for component, entry in zip(components, component_index):
        if note(entry["spdx_id"], "package", entry["locator"]):
            packages[entry["spdx_id"]] = (component, entry["locator"])

    registry: dict[str, str] = {}
    locators: dict[str, str] = {}
    for section, kind in (("files", "file"), ("snippets", "snippet")):
        for index, item in enumerate(get_list(data, section, ptr())):
            locator = ptr(section, index)
            ref = require_str(require_object(item, locator, kind), "SPDXID", locator)
            if note(ref, kind, locator):
                registry[ref] = kind
                locators[ref] = locator

    declarations: list[tuple[str, str, str]] = []  # (ref, declared_via, declaration locator)
    for index, ref in enumerate(str_list(data, "documentDescribes", ptr())):
        declarations.append((ref, "documentDescribes", ptr("documentDescribes", index)))
    for rel in relationships:
        if rel["raw_relationship"] == "DESCRIBES" and rel["source"] == document_ref:
            declarations.append((rel["target"], "DESCRIBES", rel["locator"]))
        elif rel["raw_relationship"] == "DESCRIBED_BY" and rel["target"] == document_ref:
            declarations.append((rel["source"], "DESCRIBED_BY", rel["locator"]))

    records: list[dict[str, Any]] = []
    for ref, via, declaration_locator in declarations:
        if ref in packages:
            component, package_locator = packages[ref]
            document.subjects.append(
                DocumentSubject(
                    ref=ref, component=component, locator=package_locator,
                    declared_via=via, listed_as_component=True,
                )
            )
            resolved = "package"
        elif ref in known and known[ref][0] in ("file", "snippet"):
            resolved = known[ref][0]
        else:
            resolved = "unresolved"
        records.append(
            {"ref": ref, "declared_via": via, "declaration_locator": declaration_locator,
             "resolved_as": resolved}
        )

    by_documentdescribes = {r["ref"] for r in records if r["declared_via"] == "documentDescribes"}
    by_relationship = {r["ref"] for r in records if r["declared_via"] != "documentDescribes"}
    mismatch: list[dict[str, str]] = []
    if by_documentdescribes and by_relationship:  # both mechanisms used: report any disagreement
        mismatch = [{"ref": ref, "declared_only_via": "documentDescribes"}
                    for ref in sorted(by_documentdescribes - by_relationship)]
        mismatch += [{"ref": ref, "declared_only_via": "relationships"}
                     for ref in sorted(by_relationship - by_documentdescribes)]

    document.other_defined_refs = registry
    declared["defined_ref_locators"] = canonical_json(locators)
    declared["defined_ref_conflicts"] = canonical_json(conflicts)
    declared["subject_declarations"] = canonical_json(records)
    declared["subject_declaration_mismatch"] = canonical_json(mismatch)


def _split_tool(text: str) -> tuple[str, Optional[str]]:
    head, separator, tail = text.rpartition("-")
    if separator and head and tail[:1].isdigit():
        return head, tail
    return text, None


def _read_package(
    item: Any, locator: str, out: list[Component], index_out: list[dict[str, Any]]
) -> None:
    obj = require_object(item, locator, "package")
    name = require_str(obj, "name", locator)
    spdx_id = require_str(obj, "SPDXID", locator)
    version = get_str(obj, "versionInfo", locator)
    supplier_raw = get_str(obj, "supplier", locator)

    supplier: Optional[str] = None
    if supplier_raw is not None and supplier_raw != "NOASSERTION":
        supplier = supplier_raw
        for prefix in ("Organization:", "Person:"):
            if supplier_raw.startswith(prefix):
                supplier = supplier_raw[len(prefix):].strip()

    hashes: list[Hash] = []
    for h_index, entry in enumerate(get_list(obj, "checksums", locator)):
        h_locator = ptr_join(locator, "checksums", h_index)
        h_obj = require_object(entry, h_locator, "checksum")
        hashes.append(
            Hash(
                algorithm=require_str(h_obj, "algorithm", h_locator),
                value=require_str(h_obj, "checksumValue", h_locator),
            )
        )

    purls: list[str] = []
    cpes: list[str] = []
    other_refs: list[dict[str, str]] = []
    for r_index, entry in enumerate(get_list(obj, "externalRefs", locator)):
        r_locator = ptr_join(locator, "externalRefs", r_index)
        r_obj = require_object(entry, r_locator, "external reference")
        ref_type = require_str(r_obj, "referenceType", r_locator)
        ref_locator = require_str(r_obj, "referenceLocator", r_locator)
        if ref_type == "purl":
            purls.append(ref_locator)
        elif ref_type in _CPE_REFERENCE_TYPES:
            cpes.append(ref_locator)
        else:
            other_refs.append({"locator": r_locator, "reference_type": ref_type})

    purl = purls[0] if purls else None
    out.append(
        Component(
            name=name,
            version=version,
            purl=purl,
            cpe=cpes,
            ecosystem=None,
            supplier=supplier,
            hashes=hashes,
            bom_ref=spdx_id,
            identifier_variants=build_identifier_variants(name, version, purl, cpes, hashes),
        )
    )
    index_out.append(
        {
            "locator": locator,
            "spdx_id": spdx_id,
            "supplier_raw": supplier_raw,
            "additional_purls": purls[1:],
            "unextracted_external_refs": other_refs,
            "unextracted_keys": unextracted_keys(obj, _HANDLED_PACKAGE_KEYS),
        }
    )
