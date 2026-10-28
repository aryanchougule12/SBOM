"""CycloneDX JSON SBOM parser (Stage 1).

Supported format and versions
-----------------------------
CycloneDX **JSON** documents whose ``specVersion`` is exactly ``"1.5"`` or ``"1.6"``
(``SUPPORTED_SPEC_VERSIONS``). Any other ``specVersion`` raises
``UnsupportedVersionError``. XML, Protobuf and other serializations are not supported.

How support was established: the parser reads only the fields listed below, and
version support is claimed solely for what the hand-authored fixtures under
``fixtures/cyclonedx/`` and ``tests/test_cyclonedx_parser.py`` exercise. The official
CycloneDX JSON schemas and the ``cyclonedx-python-lib`` package were not available
offline, so documents are **not** validated against the full schema. Structural checks
cover only the fields this parser reads. A document the parser accepts may still violate
the full schema.

Inputs and outputs
------------------
``parse_cyclonedx(source)`` takes raw ``bytes`` (the document) or a filesystem path
(``str``/``os.PathLike``) and returns ``(SourceDocument, list[Component])``. Failures
raise ``MalformedInputError``, ``UnsupportedVersionError`` or ``InvalidDocumentError``
(``sbom_parser.errors``); an invalid document never yields an empty result.

Everything extracted is a **self-asserted claim of the document**. Nothing is verified:
signatures are not checked (``Integrity.signature_verified`` stays ``None``) and
completeness declarations are not tested against the component list. No predicate,
evidence-state aggregation, effective-provenance or verdict logic lives here.

``SourceDocument`` mapping (set only when the document states it)
------------------------------------------------------------------
* ``doc_id``: ``cyclonedx:sha256:<hex of the exact input bytes>``.
* ``created``: ``metadata.timestamp``; the original text is kept in
  ``declared_metadata["created_raw"]``.
* ``tool_name`` / ``tool_version``: only when ``metadata.tools`` lists exactly one tool
  (legacy array form, or ``components``/``services`` form) that has a ``name``. With
  several tools no tool is chosen and all are kept in ``declared_metadata["tools"]``.
* ``producer``: only when ``metadata.authors`` has exactly one author with a ``name``.
* ``producer_class``: never set (CycloneDX does not state one).
* ``generation_context``: the raw lifecycle ``phase`` string, only when
  ``metadata.lifecycles`` has exactly one entry with a ``phase``. It is NOT mapped to
  the specification's vocabulary (for example ``source``/``build``), and it is never
  used to infer ``method``.
* ``method``: never set. CycloneDX has no field that states manifest-only versus
  content-based generation, so none is inferred.
* ``integrity.artifact_digest_binding``: never set here. The subject's hashes are
  available typed in ``subjects[0].component.hashes`` and verbatim in
  ``declared_metadata["metadata"]``; deciding which hash binds to which artifact needs
  the finding's scope and is a later stage.
* ``integrity.signature`` / ``signed_coverage``: see "Signatures".
* ``subjects`` / ``other_defined_refs``: see "Subject and defined references".

``declared_metadata`` keys (all values are strings; structured values are canonical
JSON text)
------------------------------------------------------------------------------------
``format``, ``spec_version``, ``serial_number``, ``bom_version``, ``metadata`` (the
whole ``metadata`` object), ``created_raw``, ``tools``, ``authors``, ``lifecycles``,
``component_index``, ``subject_component_index``, ``declared_dependency_nodes``, ``declared_dependency_edges``,
``composition_records``, ``signature_records``, ``signature_verification``,
``signed_coverage_basis``, ``defined_ref_locators``, ``defined_ref_conflicts``,
``unextracted_top_level_fields``, ``assertion_status``, ``locator_convention``. Locators
are JSON Pointers in URI-fragment form.

Components
----------
Every entry of ``components`` and, recursively, of nested ``components`` is returned in
document (pre-order) order. ``metadata.component`` (the described subject) is NOT
returned as a component; it is a typed ``DocumentSubject`` and is also preserved inside
``declared_metadata["metadata"]``. The components nested under the subject
(``metadata.component.components``, recursively, pre-order) are not returned either; they are
recorded with their locators, types and fields in ``declared_metadata["subject_component_index"]``
and exposed as typed records by the Stage 1 adapter (they are inventory members, kept apart from
the top-level list).
``Component`` is filled from ``name``, ``version``, ``purl``, ``cpe`` (one string),
``bom-ref``, ``hashes`` (``alg``/``content``) and ``supplier.name``. Identifiers are
kept exactly as supplied; derived keys use ``identifiers.variant-norm-v1``.
``Component.ecosystem`` is left ``None``: deriving it (for example from the purl type)
is deferred because the equivalence of such a value with the specification's ecosystem
coverage is undefined. ``component_index`` records, per component, its locator, its
``type``, its ``bom-ref`` and the names of keys that were NOT extracted (licenses,
properties, externalReferences, evidence, pedigree, ...), so nothing is dropped
silently. Nesting is recoverable from the locators.

Dependencies
------------
``dependencies`` entries become **declared dependency edges** (``edge_type`` is always
``"declared_dependency"``): one edge per ``dependsOn``/``provides`` item, with the raw
relationship name, the source and target refs and the locator. They are package-level
declarations. They are not call edges, not execution-path edges and not evidence of
reachability. ``declared_dependency_nodes`` records every ``ref`` with whether it
declared a ``dependsOn`` array, because an explicitly empty array and an absent one are
different statements and neither is interpreted here.

Compositions (completeness)
---------------------------
Each ``compositions`` entry yields one record in ``composition_records`` holding its
locator, ``bom-ref``, the raw ``aggregate``, ``aggregate_recognized``, the mapped
six-state value (``state``) and the declared scope lists (``assemblies``,
``dependencies``, ``vulnerabilities``). ``scope_declared`` is true only if a scope list
is non-empty. Mapping (``map_composition_aggregate``, specification §4.1):
``complete`` -> ``Present``; any value starting ``incomplete`` -> ``Incomplete``;
``unknown`` / ``not_specified`` -> ``Unknown``; any other value -> ``Unknown`` with
``aggregate_recognized`` false. No composition is promoted to document-wide
completeness, and separate compositions are never merged. No compositions means an empty
``composition_records`` list (the DECL state is then ``Unknown`` for later stages).

Signatures
----------
Every object that contains a ``signature`` object (a JSF enveloped signature) is
recorded in ``signature_records`` with the container locator and the raw signature.
``Integrity.signature`` is the canonical JSON list of ``{"covers", "signature"}``
records. ``Integrity.signed_coverage`` lists the container locators the signatures
*declare* they cover (``#`` is the whole document). A signature with a non-empty
``excludes`` list has an unrepresentable (narrower) coverage, so its container is NOT
added to ``signed_coverage`` and the record is marked ``coverage_claimed: false``.
Signature metadata is only a claim: ``signature_verified`` is ``None``,
``trust_anchor_id`` is ``None``, ``established_coverage`` is ``None`` (parsing never
establishes verified coverage) and ``declared_metadata["signature_verification"]`` is
``"not_attempted"``. ``signed_coverage`` is the *declared* union of all signature claims
and is not attributable to any single signature. That a JSF signature covers the object
containing it is this parser's documented reading of the JSF enveloped-signature form
(``signed_coverage_basis = "jsf-enveloped-container-object"``).

Subject and defined references
------------------------------
``metadata.component`` (the ``component`` definition in both the 1.5 and 1.6 schemas)
becomes ``SourceDocument.subjects[0]``: its original ``bom-ref``, identifiers and hashes,
the locator ``#/metadata/component`` and ``declared_via = "metadata.component"``.
``listed_as_component`` is true only if a listed component carries the same ``bom-ref``.

Both official schemas describe a dependency's ``ref`` and ``dependsOn`` (and, in 1.6,
``provides``) as bom-refs of *components or services*, so valid endpoints include objects
that are not in the ordinary component list. ``SourceDocument.other_defined_refs`` maps
``bom-ref -> kind`` for such objects, taken only from the locations where the schema
uses the ``component`` or ``service`` definition: top-level ``services`` (kind
``service``, nested ``nested_service``); components nested under the subject or under
other registered components (``nested_component``); ``pedigree`` ancestors, descendants
and variants (``pedigree_component``); ``metadata.tools`` and ``vulnerabilities[].tools``
in object form (``tool_component``, ``tool_service``); ``annotations[].annotator``
(``annotator_component``, ``annotator_service``); ``formulation[]``
(``formulation_component``, ``formulation_service``); and, for 1.6 only,
``declarations.targets`` (``declaration_target_component``,
``declaration_target_service``). Components nested inside ordinary listed components are
already in the returned list and are not registered again. Unknown references are never
added. Registering a reference only means a dependency endpoint naming it is declared;
it does not put the object in the inventory, assert completeness, or show that any
target component is present. Source locators are in
``declared_metadata["defined_ref_locators"]``; a ``bom-ref`` declared more than once is
registered once and the extra declaration is recorded in ``defined_ref_conflicts``.

Not represented
---------------
``vulnerabilities``, ``externalReferences``, ``annotations``, ``formulation``,
``properties`` and other top-level sections are not interpreted beyond the reference
registry above; their names are listed in ``unextracted_top_level_fields``.
"""

from __future__ import annotations

from typing import Any, Optional

from model import Component, DocumentSubject, EvidenceState, Hash, Integrity, SourceDocument
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

FORMAT_NAME = "CycloneDX"
SUPPORTED_SPEC_VERSIONS = ("1.5", "1.6")

_HANDLED_TOP_LEVEL = {
    "bomFormat",
    "specVersion",
    "serialNumber",
    "version",
    "metadata",
    "components",
    "dependencies",
    "compositions",
    "signature",
}
_HANDLED_COMPONENT_KEYS = {
    "type", "name", "version", "purl", "cpe", "bom-ref", "hashes", "supplier",
    "components", "signature",
}


def map_composition_aggregate(aggregate: str) -> tuple[EvidenceState, bool]:
    """Map a composition ``aggregate`` value to ``(state, recognized)`` (spec §4.1).

    ``complete`` -> ``Present``; values starting ``incomplete`` -> ``Incomplete``;
    ``unknown`` / ``not_specified`` -> ``Unknown``. Any other value maps to ``Unknown``
    and is reported as not recognized. This is a syntactic mapping only; it does not
    check the declaration against the component list.
    """
    if aggregate == "complete":
        return EvidenceState.PRESENT, True
    if aggregate.startswith("incomplete"):
        return EvidenceState.INCOMPLETE, True
    if aggregate in ("unknown", "not_specified"):
        return EvidenceState.UNKNOWN, True
    return EvidenceState.UNKNOWN, False


def parse_cyclonedx(source: SBOMSource) -> tuple[SourceDocument, list[Component]]:
    """Parse a CycloneDX JSON SBOM into ``(SourceDocument, components)``.

    Raises ``MalformedInputError``, ``UnsupportedVersionError`` or
    ``InvalidDocumentError``. See the module docstring for exact semantics.
    """
    raw = read_source(source)
    data = load_json_object(raw, "CycloneDX JSON")

    if data.get("bomFormat") != "CycloneDX":
        raise InvalidDocumentError("bomFormat must be 'CycloneDX'", ptr("bomFormat"))
    spec_version = require_str(data, "specVersion", ptr())
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise UnsupportedVersionError(
            f"unsupported CycloneDX specVersion {spec_version!r}; "
            f"supported: {', '.join(SUPPORTED_SPEC_VERSIONS)}",
            ptr("specVersion"),
        )

    declared: dict[str, str] = {
        "format": FORMAT_NAME,
        "spec_version": spec_version,
        "assertion_status": ASSERTION_STATUS,
        "locator_convention": LOCATOR_CONVENTION,
    }
    serial = get_str(data, "serialNumber", ptr())
    if serial is not None:
        declared["serial_number"] = serial
    if "version" in data:
        bom_version = data["version"]
        if isinstance(bom_version, bool) or not isinstance(bom_version, int):
            raise InvalidDocumentError("'version' must be an integer", ptr("version"))
        declared["bom_version"] = str(bom_version)

    document = SourceDocument(doc_id=document_id("cyclonedx", raw))
    _read_metadata(data, document, declared)

    components: list[Component] = []
    component_index: list[dict[str, Any]] = []
    for index, item in enumerate(get_list(data, "components", ptr())):
        _read_component(item, ptr("components", index), components, component_index)
    declared["component_index"] = canonical_json(component_index)
    _read_subject_and_refs(data, spec_version, component_index, document, declared)
    _read_subject_components(data, declared)

    _read_dependencies(data, declared)
    declared["composition_records"] = canonical_json(_read_compositions(data))
    _read_signatures(data, document, declared)
    declared["unextracted_top_level_fields"] = canonical_json(
        unextracted_keys(data, _HANDLED_TOP_LEVEL)
    )

    document.declared_metadata = declared
    return document, components


def _read_metadata(
    data: dict[str, Any], document: SourceDocument, declared: dict[str, str]
) -> None:
    metadata = get_object(data, "metadata", ptr())
    if metadata is None:
        return
    base = ptr("metadata")
    declared["metadata"] = canonical_json(metadata)

    timestamp = get_str(metadata, "timestamp", base)
    if timestamp is not None:
        document.created = parse_timestamp(timestamp, ptr_join(base, "timestamp"))
        declared["created_raw"] = timestamp

    tools = _collect_tools(metadata, base)
    declared["tools"] = canonical_json(tools)
    if len(tools) == 1 and isinstance(tools[0].get("name"), str):
        document.tool_name = tools[0]["name"]
        version = tools[0].get("version")
        document.tool_version = version if isinstance(version, str) else None

    authors = get_list(metadata, "authors", base)
    for index, author in enumerate(authors):
        require_object(author, ptr_join(base, "authors", index), "author")
    declared["authors"] = canonical_json(authors)
    if len(authors) == 1 and isinstance(authors[0].get("name"), str):
        document.producer = authors[0]["name"]

    lifecycles = get_list(metadata, "lifecycles", base)
    for index, lifecycle in enumerate(lifecycles):
        require_object(lifecycle, ptr_join(base, "lifecycles", index), "lifecycle")
    declared["lifecycles"] = canonical_json(lifecycles)
    if len(lifecycles) == 1 and isinstance(lifecycles[0].get("phase"), str):
        document.generation_context = lifecycles[0]["phase"]


def _collect_tools(metadata: dict[str, Any], base: str) -> list[dict[str, Any]]:
    """Return every declared tool as a raw object (legacy array or object form)."""
    if "tools" not in metadata:
        return []
    tools = metadata["tools"]
    location = ptr_join(base, "tools")
    found: list[dict[str, Any]] = []
    if isinstance(tools, list):
        for index, tool in enumerate(tools):
            found.append(require_object(tool, ptr_join(location, index), "tool"))
    elif isinstance(tools, dict):
        for group in ("components", "services"):
            for index, tool in enumerate(get_list(tools, group, location)):
                found.append(
                    require_object(tool, ptr_join(location, group, index), "tool")
                )
    else:
        raise InvalidDocumentError("'tools' must be an array or an object", location)
    return found


def _read_component(
    item: Any,
    locator: str,
    out: list[Component],
    index_out: list[dict[str, Any]],
) -> None:
    obj = require_object(item, locator, "component")
    out.append(_component_from_obj(obj, locator))
    index_out.append(
        {
            "locator": locator,
            "bom_ref": get_str(obj, "bom-ref", locator),
            "type": get_str(obj, "type", locator),
            "unextracted_keys": unextracted_keys(obj, _HANDLED_COMPONENT_KEYS),
        }
    )
    for n_index, nested in enumerate(get_list(obj, "components", locator)):
        _read_component(nested, ptr_join(locator, "components", n_index), out, index_out)


def _component_from_obj(obj: dict[str, Any], locator: str) -> Component:
    """Read one CycloneDX ``component`` object into a ``Component`` (no recursion)."""
    name = require_str(obj, "name", locator)
    version = get_str(obj, "version", locator)
    purl = get_str(obj, "purl", locator)
    cpe = get_str(obj, "cpe", locator)
    bom_ref = get_str(obj, "bom-ref", locator)

    supplier_name: Optional[str] = None
    supplier = get_object(obj, "supplier", locator)
    if supplier is not None:
        supplier_name = get_str(supplier, "name", ptr_join(locator, "supplier"))

    hashes: list[Hash] = []
    for h_index, entry in enumerate(get_list(obj, "hashes", locator)):
        h_locator = ptr_join(locator, "hashes", h_index)
        h_obj = require_object(entry, h_locator, "hash")
        hashes.append(
            Hash(
                algorithm=require_str(h_obj, "alg", h_locator),
                value=require_str(h_obj, "content", h_locator),
            )
        )

    cpes = [cpe] if cpe is not None else []
    return Component(
        name=name,
        version=version,
        purl=purl,
        cpe=cpes,
        ecosystem=None,
        supplier=supplier_name,
        hashes=hashes,
        bom_ref=bom_ref,
        identifier_variants=build_identifier_variants(name, version, purl, cpes, hashes),
    )


def _component_record(component: Component) -> dict[str, Any]:
    """The fields of a ``Component`` that Stage 1 needs to rebuild it (identifier variants are
    rebuilt from them with the same function the parser uses)."""
    return {
        "name": component.name,
        "version": component.version,
        "purl": component.purl,
        "cpe": list(component.cpe),
        "supplier": component.supplier,
        "bom_ref": component.bom_ref,
        "hashes": [{"algorithm": h.algorithm, "value": h.value} for h in component.hashes],
    }


def _read_subject_components(data: dict[str, Any], declared: dict[str, str]) -> None:
    """Components nested under ``metadata.component`` (recursively, pre-order).

    They are constituents of the described subject (schema: ``component.components``, "a list of
    software and hardware components included in the parent component"), so they are inventory
    members that the ordinary ``components`` list does not contain. They are NOT returned in the
    component list: the subject and what it contains stay separate from the top-level list, and
    ``declared_metadata["subject_component_index"]`` records each one with its locator, its
    ``type`` and its fields. The subject itself, services, pedigree objects and tool components
    are not recorded here.
    """
    metadata = get_object(data, "metadata", ptr())
    subject = get_object(metadata, "component", ptr("metadata")) if metadata is not None else None
    nested: list[Component] = []
    index: list[dict[str, Any]] = []
    if subject is not None:
        base = ptr("metadata", "component")
        for n_index, item in enumerate(get_list(subject, "components", base)):
            _read_component(item, ptr_join(base, "components", n_index), nested, index)
    declared["subject_component_index"] = canonical_json(
        [{**entry, "component": _component_record(component)} for component, entry in zip(nested, index)]
    )


def _read_dependencies(data: dict[str, Any], declared: dict[str, str]) -> None:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for index, item in enumerate(get_list(data, "dependencies", ptr())):
        locator = ptr("dependencies", index)
        obj = require_object(item, locator, "dependency entry")
        ref = require_str(obj, "ref", locator)
        nodes.append({"ref": ref, "locator": locator, "depends_on_declared": "dependsOn" in obj})
        for relationship in ("dependsOn", "provides"):
            for t_index, target in enumerate(str_list(obj, relationship, locator)):
                edges.append(
                    {
                        "edge_type": "declared_dependency",
                        "raw_relationship": relationship,
                        "source": ref,
                        "target": target,
                        "locator": ptr_join(locator, relationship, t_index),
                    }
                )
    declared["declared_dependency_nodes"] = canonical_json(nodes)
    declared["declared_dependency_edges"] = canonical_json(edges)


def _read_compositions(data: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, item in enumerate(get_list(data, "compositions", ptr())):
        locator = ptr("compositions", index)
        obj = require_object(item, locator, "composition")
        aggregate = require_str(obj, "aggregate", locator)
        state, recognized = map_composition_aggregate(aggregate)
        scope = {key: str_list(obj, key, locator) for key in ("assemblies", "dependencies", "vulnerabilities")}
        records.append(
            {
                "locator": locator,
                "bom_ref": get_str(obj, "bom-ref", locator),
                "aggregate_raw": aggregate,
                "aggregate_recognized": recognized,
                "state": state.value,
                "assemblies": scope["assemblies"],
                "dependencies": scope["dependencies"],
                "vulnerabilities": scope["vulnerabilities"],
                "scope_declared": any(scope.values()),
            }
        )
    return records


def _find_signatures(node: Any, locator: str, found: list[tuple[str, dict[str, Any]]]) -> None:
    if isinstance(node, dict):
        signature = node.get("signature")
        if isinstance(signature, dict):
            found.append((locator, signature))
        for key, value in node.items():
            if key != "signature":
                _find_signatures(value, ptr_join(locator, key), found)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _find_signatures(value, ptr_join(locator, index), found)


def _read_signatures(
    data: dict[str, Any], document: SourceDocument, declared: dict[str, str]
) -> None:
    found: list[tuple[str, dict[str, Any]]] = []
    _find_signatures(data, ptr(), found)
    if "signature" in data and not isinstance(data["signature"], dict):
        raise InvalidDocumentError("'signature' must be an object", ptr("signature"))
    records: list[dict[str, Any]] = []
    coverage: list[str] = []
    for container, signature in found:
        excludes = signature.get("excludes")
        claimed = not (isinstance(excludes, list) and excludes)
        records.append({"covers": container, "coverage_claimed": claimed, "signature": signature})
        if claimed:
            coverage.append(container)
    declared["signature_records"] = canonical_json(records)
    if records:
        declared["signature_verification"] = "not_attempted"
        declared["signed_coverage_basis"] = "jsf-enveloped-container-object"
        document.integrity = Integrity(
            signature=canonical_json(
                [{"covers": r["covers"], "signature": r["signature"]} for r in records]
            ),
            signature_verified=None,
            trust_anchor_id=None,
            signed_coverage=coverage,
        )


# ---- subject and defined-reference registry --------------------------------------------
#
# Locations (inside the document) where the official CycloneDX 1.5 and 1.6 JSON schemas
# use the ``component`` or ``service`` definition, and therefore where an object with a
# ``bom-ref`` may legally be declared. "*" iterates an array. Verified against
# https://github.com/CycloneDX/specification (schema/bom-1.5.schema.json and
# schema/bom-1.6.schema.json). Top-level ``components`` (and components nested in them)
# and ``metadata.component`` are handled separately, because they are the ordinary
# component list and the subject. Each entry: (path, "component" | "service", kind).
_DEFINED_REF_LOCATIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("services", "*"), "service", "service"),
    (("metadata", "tools", "components", "*"), "component", "tool_component"),
    (("metadata", "tools", "services", "*"), "service", "tool_service"),
    (("vulnerabilities", "*", "tools", "components", "*"), "component", "tool_component"),
    (("vulnerabilities", "*", "tools", "services", "*"), "service", "tool_service"),
    (("annotations", "*", "annotator", "component"), "component", "annotator_component"),
    (("annotations", "*", "annotator", "service"), "service", "annotator_service"),
    (("formulation", "*", "components", "*"), "component", "formulation_component"),
    (("formulation", "*", "services", "*"), "service", "formulation_service"),
)
# Present in the 1.6 schema only (declarations.targets uses the component/service definitions).
_DEFINED_REF_LOCATIONS_1_6: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("declarations", "targets", "components", "*"), "component", "declaration_target_component"),
    (("declarations", "targets", "services", "*"), "service", "declaration_target_service"),
)


class _RefContext:
    """Collects declared references; a reference is registered at most once."""

    def __init__(self) -> None:
        self.known: dict[str, tuple[str, str]] = {}  # every ref seen -> (kind, locator)
        self.registry: dict[str, str] = {}  # only the refs for SourceDocument.other_defined_refs
        self.locators: dict[str, str] = {}
        self.conflicts: list[dict[str, str]] = []

    def note(self, ref: Optional[str], kind: str, locator: str, *, register: bool) -> None:
        if ref is None:
            return
        if ref in self.known:
            prev_kind, prev_locator = self.known[ref]
            self.conflicts.append(
                {
                    "ref": ref,
                    "kind": kind,
                    "locator": locator,
                    "conflicts_with_kind": prev_kind,
                    "conflicts_with_locator": prev_locator,
                }
            )
            return
        self.known[ref] = (kind, locator)
        if register:
            self.registry[ref] = kind
            self.locators[ref] = locator


def _iter_path(node: Any, path: tuple[str, ...], locator: str) -> Any:
    """Yield ``(object, locator)`` for each element reached by ``path`` (``*`` = array)."""
    if not path:
        yield node, locator
        return
    head, rest = path[0], path[1:]
    if head == "*":
        if not isinstance(node, list):
            raise InvalidDocumentError("expected an array", locator)
        for index, item in enumerate(node):
            yield from _iter_path(item, rest, ptr_join(locator, index))
        return
    if isinstance(node, list) and locator.endswith("/tools"):
        return  # legacy ``tools`` array: tool objects, not component/service definitions
    if not isinstance(node, dict):
        raise InvalidDocumentError("expected an object", locator)
    if head in node:
        yield from _iter_path(node[head], rest, ptr_join(locator, head))


def _visit_pedigree(obj: dict[str, Any], locator: str, ctx: _RefContext) -> None:
    pedigree = get_object(obj, "pedigree", locator)
    if pedigree is None:
        return
    for key in ("ancestors", "descendants", "variants"):
        for index, item in enumerate(get_list(pedigree, key, ptr_join(locator, "pedigree"))):
            item_locator = ptr_join(locator, "pedigree", key, index)
            _visit_component(
                require_object(item, item_locator, "component"),
                item_locator, "pedigree_component", ctx,
            )


def _visit_component(
    obj: dict[str, Any], locator: str, kind: str, ctx: _RefContext, *, register_self: bool = True
) -> None:
    """Register a component object's reference and those of components it contains."""
    if register_self:
        ctx.note(get_str(obj, "bom-ref", locator), kind, locator, register=True)
    _visit_pedigree(obj, locator, ctx)
    for index, child in enumerate(get_list(obj, "components", locator)):
        child_locator = ptr_join(locator, "components", index)
        _visit_component(
            require_object(child, child_locator, "component"),
            child_locator, "nested_component", ctx,
        )


def _visit_listed_component(obj: dict[str, Any], locator: str, ctx: _RefContext) -> None:
    """Components in the ordinary list (nested ones are flattened into it) are not
    re-registered; only their ``pedigree`` components are additional declared objects."""
    _visit_pedigree(obj, locator, ctx)
    for index, child in enumerate(get_list(obj, "components", locator)):
        child_locator = ptr_join(locator, "components", index)
        _visit_listed_component(require_object(child, child_locator, "component"), child_locator, ctx)


def _visit_service(obj: dict[str, Any], locator: str, kind: str, ctx: _RefContext) -> None:
    ctx.note(get_str(obj, "bom-ref", locator), kind, locator, register=True)
    for index, child in enumerate(get_list(obj, "services", locator)):
        child_locator = ptr_join(locator, "services", index)
        _visit_service(
            require_object(child, child_locator, "service"), child_locator, "nested_service", ctx
        )


def _read_subject_and_refs(
    data: dict[str, Any],
    spec_version: str,
    component_index: list[dict[str, Any]],
    document: SourceDocument,
    declared: dict[str, str],
) -> None:
    ctx = _RefContext()
    for entry in component_index:  # refs of the ordinary component list
        ctx.note(entry["bom_ref"], "listed_component", entry["locator"], register=False)
    listed_refs = {e["bom_ref"] for e in component_index if e["bom_ref"] is not None}

    metadata = get_object(data, "metadata", ptr())
    subject_obj = get_object(metadata, "component", ptr("metadata")) if metadata is not None else None
    if subject_obj is not None:
        subject_locator = ptr("metadata", "component")
        subject = _component_from_obj(subject_obj, subject_locator)
        document.subjects.append(
            DocumentSubject(
                ref=subject.bom_ref,
                component=subject,
                locator=subject_locator,
                declared_via="metadata.component",
                listed_as_component=subject.bom_ref is not None and subject.bom_ref in listed_refs,
            )
        )
        ctx.note(subject.bom_ref, "subject", subject_locator, register=False)
        _visit_component(subject_obj, subject_locator, "subject", ctx, register_self=False)

    for index, item in enumerate(get_list(data, "components", ptr())):
        _visit_listed_component(item, ptr("components", index), ctx)

    locations = _DEFINED_REF_LOCATIONS + (_DEFINED_REF_LOCATIONS_1_6 if spec_version == "1.6" else ())
    for path, what, kind in locations:
        for obj, locator in _iter_path(data, path, ptr()):
            checked = require_object(obj, locator, what)
            if what == "component":
                _visit_component(checked, locator, kind, ctx)
            else:
                _visit_service(checked, locator, kind, ctx)

    document.other_defined_refs = ctx.registry
    declared["defined_ref_locators"] = canonical_json(ctx.locators)
    declared["defined_ref_conflicts"] = canonical_json(ctx.conflicts)
