"""OpenVEX JSON document parser (Stage 1).

Supported format and version
----------------------------
OpenVEX **JSON** documents whose ``@context`` is exactly
``"https://openvex.dev/ns/v0.2.0"`` (``SUPPORTED_CONTEXTS``), i.e. OpenVEX v0.2.0. Any
other ``https://openvex.dev/ns...`` context raises ``UnsupportedVersionError``; a missing
or unrelated ``@context`` raises ``InvalidDocumentError``.

How support was established: the parser reads only the fields listed below, and support
is claimed solely for what the hand-authored fixtures under ``fixtures/openvex/`` and
``tests/test_openvex_parser.py`` exercise. The official OpenVEX schema was not available
offline, so documents are **not** validated against the full schema.

Inputs and outputs
------------------
``parse_openvex(source)`` takes raw ``bytes`` or a filesystem path and returns
``(SourceDocument, list[Finding])``. Failures raise ``MalformedInputError``,
``UnsupportedVersionError`` or ``InvalidDocumentError`` (``sbom_parser.errors``); invalid
input never yields an empty result.

What a parsed ``Finding`` is
----------------------------
One ``Finding`` per (statement, product) pair, in document order, for **every** status.
(The Stage 0 stub described only ``not_affected`` statements; dropping the others would
silently lose claims.) A ``Finding`` is the document's **claim**, not a verified fact:

* ``disposition`` is the asserted ``status`` (one of ``not_affected``, ``affected``,
  ``fixed``, ``under_investigation``; any other status is ``InvalidDocumentError``).
  It is neither validated nor recomputed.
* ``justification.justification`` is the raw ``justification`` string exactly as
  received. It is never coerced to ``JustificationType``, never normalised (case is
  preserved) and never rejected for being outside the two predicate-supported values;
  later stages report unsupported values explicitly. When the statement has no
  ``justification``, the value is ``""``. An explicitly empty string in the input is
  rejected as invalid, so ``""`` always means "absent".
* ``justification.asserted_by`` is the document ``author``. ``justification.statement``
  is the statement's ``impact_statement``.
* ``product`` holds the product's identity: ``purl`` from ``identifiers.purl``, ``cpe``
  from ``identifiers.cpe22``/``cpe23``, ``hashes`` from ``hashes`` (key = algorithm as
  written), and ``bom_ref`` from the product ``@id``. ``name`` is ``""`` because OpenVEX
  products carry no name. A product ``@id`` is NOT parsed as a purl. A product must have
  an ``@id`` or at least one ``identifiers`` entry.
* ``component`` is the **target component C** (specification §1), which is NOT the
  product. In OpenVEX v0.2.0 a product entry may carry ``subcomponents``, a list of
  component structs (``@id``, ``identifiers``, ``hashes``) nested *inside that product
  entry*; they identify the components "subject of the VEX statement". Each
  (statement, product, subcomponent) tuple yields one ``Finding`` whose ``component`` is
  that subcomponent, read with the same rules as a product and carrying only its own
  identifiers and variants, and whose ``product`` is the enclosing product. A product with
  N subcomponents therefore yields N findings (none is dropped); a product with no
  subcomponents yields one finding with ``component = None``: the target is unresolved
  and the product is never used in its place. Product and subcomponent identifiers are
  never merged, compared or assumed equivalent. ``declared_metadata["finding_targets"]``
  of the statement-level document lists, in finding order, each finding's
  ``product_locator`` and ``target_locator`` (``null`` when unresolved).
* ``vulnerability.id`` is the vulnerability ``name`` (or ``@id`` if there is no name);
  ``aliases`` are copied; ``source``, ``affected_ranges`` and ``locus`` stay empty.
* ``scope.product_id`` is the product ``@id`` (``""`` if only ``identifiers`` are given).
  ``scope.artifact_kind`` is always ``ArtifactKind.UNKNOWN``: OpenVEX v0.2.0 has no
  artifact-kind field, and the kind is never inferred from the product identifier (an
  OCI-looking purl, say), the status or the justification. Every other ``Scope`` field
  keeps the model default. The scope of an evaluation must be established separately
  by a later stage.
* ``evidence`` is always empty: a VEX claim is not evidence for itself.

Provenance: document level vs statement level
---------------------------------------------
The returned document-level ``SourceDocument`` has ``doc_id`` ``openvex:sha256:<hex of
the input bytes>``, ``producer`` = ``author``, ``producer_class`` = ``role``,
``tool_name`` = ``tooling`` (verbatim, not split), ``created`` = ``timestamp``.
``generation_context``, ``method`` and ``integrity`` stay unset: OpenVEX v0.2.0 carries
no signature field, so no integrity claim is made. Each ``Finding.source_documents``
holds both the document-level document and a **statement-level** ``SourceDocument``
(``doc_id`` = ``<document doc_id>#/statements/<i>``) with ``producer`` = the statement's
``supplier`` and ``created`` = the statement's ``timestamp``. Nothing is inherited from
the document into the statement document, or the reverse.

``declared_metadata`` (strings; structured values are canonical JSON text)
-------------------------------------------------------------------------
Document level: ``format``, ``spec_version``, ``document_id``, ``author``, ``role``,
``timestamp_raw``, ``last_updated``, ``document_version``, ``tooling``,
``statement_count``, ``unextracted_top_level_fields``, ``assertion_status``,
``locator_convention``. Statement level: ``statement_locator``, ``parent_document``,
``status_raw``, ``justification_raw``, ``impact_statement``, ``status_notes``,
``action_statement``, ``action_statement_timestamp``, ``last_updated``,
``statement_version``, ``vulnerability``, ``products``, ``finding_targets``,
``unextracted_statement_fields``, ``assertion_status``, ``locator_convention``. Keys
appear only when the input has them (``finding_targets`` is always present).

Not represented
---------------
Other top-level sections and statement fields are not interpreted; their names are
listed in ``unextracted_top_level_fields`` / ``unextracted_statement_fields``.
"""

from __future__ import annotations

from typing import Any, Optional

from model import (
    ArtifactKind,
    Component,
    Disposition,
    Finding,
    Hash,
    Justification,
    Scope,
    SourceDocument,
    Vulnerability,
)
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

VEXSource = InputSource

FORMAT_NAME = "OpenVEX"
SUPPORTED_CONTEXTS = ("https://openvex.dev/ns/v0.2.0",)

_HANDLED_TOP_LEVEL = {
    "@context", "@id", "author", "role", "timestamp", "last_updated", "version",
    "tooling", "statements",
}
_HANDLED_STATEMENT_KEYS = {
    "vulnerability", "products", "status", "justification", "impact_statement",
    "status_notes", "action_statement", "action_statement_timestamp", "timestamp",
    "last_updated", "supplier", "version",
}


def parse_openvex(source: VEXSource) -> tuple[SourceDocument, list[Finding]]:
    """Parse an OpenVEX v0.2.0 JSON document into ``(SourceDocument, findings)``.

    Raises ``MalformedInputError``, ``UnsupportedVersionError`` or
    ``InvalidDocumentError``. See the module docstring for exact semantics.
    """
    raw = read_source(source)
    data = load_json_object(raw, "OpenVEX JSON")

    context = data.get("@context")
    if context is None:
        raise InvalidDocumentError("required field '@context' is missing", ptr())
    if not isinstance(context, str):
        raise InvalidDocumentError("'@context' must be a string", ptr("@context"))
    if context not in SUPPORTED_CONTEXTS:
        if context.startswith("https://openvex.dev/ns"):
            raise UnsupportedVersionError(
                f"unsupported OpenVEX context {context!r}; supported: {', '.join(SUPPORTED_CONTEXTS)}",
                ptr("@context"),
            )
        raise InvalidDocumentError(f"'@context' is not an OpenVEX context: {context!r}", ptr("@context"))

    declared: dict[str, str] = {
        "format": FORMAT_NAME,
        "spec_version": context,
        "assertion_status": ASSERTION_STATUS,
        "locator_convention": LOCATOR_CONVENTION,
    }
    document = SourceDocument(doc_id=document_id("openvex", raw))
    author = _read_document_fields(data, document, declared)

    statements = get_list(data, "statements", ptr())
    declared["statement_count"] = str(len(statements))
    declared["unextracted_top_level_fields"] = canonical_json(
        unextracted_keys(data, _HANDLED_TOP_LEVEL)
    )
    document.declared_metadata = declared

    findings: list[Finding] = []
    for index, item in enumerate(statements):
        findings.extend(_read_statement(item, index, document, author))
    return document, findings


def _read_document_fields(
    data: dict[str, Any], document: SourceDocument, declared: dict[str, str]
) -> Optional[str]:
    base = ptr()
    document_ref = require_str(data, "@id", base)
    declared["document_id"] = document_ref
    author = require_str(data, "author", base)
    declared["author"] = author
    document.producer = author
    role = get_str(data, "role", base)
    if role is not None:
        document.producer_class = role
        declared["role"] = role
    timestamp = require_str(data, "timestamp", base)
    document.created = parse_timestamp(timestamp, ptr("timestamp"))
    declared["timestamp_raw"] = timestamp
    last_updated = get_str(data, "last_updated", base)
    if last_updated is not None:
        parse_timestamp(last_updated, ptr("last_updated"))
        declared["last_updated"] = last_updated
    if "version" in data:
        version = data["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDocumentError("'version' must be an integer", ptr("version"))
        declared["document_version"] = str(version)
    tooling = get_str(data, "tooling", base)
    if tooling is not None:
        document.tool_name = tooling
        declared["tooling"] = tooling
    return author


def _read_statement(
    item: Any, index: int, document: SourceDocument, author: Optional[str]
) -> list[Finding]:
    locator = ptr("statements", index)
    stmt = require_object(item, locator, "statement")

    status = require_str(stmt, "status", locator)
    try:
        disposition = Disposition(status)
    except ValueError as exc:
        raise InvalidDocumentError(
            f"unsupported status {status!r}; expected one of "
            f"{', '.join(d.value for d in Disposition)}",
            ptr_join(locator, "status"),
        ) from exc

    justification_raw = get_str(stmt, "justification", locator)
    if justification_raw == "":
        raise InvalidDocumentError(
            "'justification' must not be an empty string", ptr_join(locator, "justification")
        )

    vulnerability = _read_vulnerability(stmt, locator)
    products = get_list(stmt, "products", locator)
    if not products:
        raise InvalidDocumentError("a statement needs at least one product", ptr_join(locator, "products"))

    impact = get_str(stmt, "impact_statement", locator)
    statement_doc = _statement_document(stmt, locator, document, status, justification_raw, impact)

    # One finding per (product, subcomponent); a product with no subcomponents yields one
    # finding whose target component is unresolved (None). Nothing is dropped or merged.
    findings: list[Finding] = []
    targets: list[dict[str, Any]] = []
    for p_index, product_item in enumerate(products):
        p_locator = ptr_join(locator, "products", p_index)
        product, product_id = _read_product(product_item, p_locator)
        subcomponents = _read_subcomponents(product_item, p_locator)
        resolved: list[tuple[Optional[Component], Optional[str]]] = (
            [(sub, sub_locator) for sub, sub_locator in subcomponents]
            if subcomponents
            else [(None, None)]
        )
        for target, target_locator in resolved:
            targets.append({"product_locator": p_locator, "target_locator": target_locator})
            findings.append(
                Finding(
                    component=target,
                    product=product,
                    vulnerability=Vulnerability(
                        id=vulnerability.id, aliases=list(vulnerability.aliases)
                    ),
                    disposition=disposition,
                    justification=Justification(
                        justification=justification_raw if justification_raw is not None else "",
                        asserted_by=author,
                        statement=impact,
                    ),
                    evidence=[],
                    scope=Scope(product_id=product_id, artifact_kind=ArtifactKind.UNKNOWN),
                    source_documents={
                        document.doc_id: document,
                        statement_doc.doc_id: statement_doc,
                    },
                )
            )
    statement_doc.declared_metadata["finding_targets"] = canonical_json(targets)
    return findings


def _read_vulnerability(stmt: dict[str, Any], locator: str) -> Vulnerability:
    v_locator = ptr_join(locator, "vulnerability")
    vuln = get_object(stmt, "vulnerability", locator)
    if vuln is None:
        raise InvalidDocumentError("required field 'vulnerability' is missing", locator)
    name = get_str(vuln, "name", v_locator)
    vuln_ref = get_str(vuln, "@id", v_locator)
    identifier = name if name else vuln_ref
    if not identifier:
        raise InvalidDocumentError("vulnerability needs a 'name' or '@id'", v_locator)
    return Vulnerability(id=identifier, aliases=str_list(vuln, "aliases", v_locator))


def _read_product(item: Any, locator: str) -> tuple[Component, str]:
    obj = require_object(item, locator, "product")
    component = _component_from_struct(obj, locator, "product")
    return component, component.bom_ref if component.bom_ref is not None else ""


def _read_subcomponents(
    product_item: Any, product_locator: str
) -> list[tuple[Component, str]]:
    """Read ``subcomponents`` of one product entry (OpenVEX v0.2.0: nested in the product).

    Every entry is returned, in order, with its locator; none is dropped. Each is read
    with its own identifiers only and is never combined with the product's.
    """
    obj = require_object(product_item, product_locator, "product")
    result: list[tuple[Component, str]] = []
    for index, entry in enumerate(get_list(obj, "subcomponents", product_locator)):
        sub_locator = ptr_join(product_locator, "subcomponents", index)
        sub_obj = require_object(entry, sub_locator, "subcomponent")
        result.append((_component_from_struct(sub_obj, sub_locator, "subcomponent"), sub_locator))
    return result


def _component_from_struct(obj: dict[str, Any], locator: str, what: str) -> Component:
    """Read an OpenVEX ``component`` struct (shared by products and subcomponents)."""
    product_ref = get_str(obj, "@id", locator)
    identifiers = get_object(obj, "identifiers", locator) or {}
    if product_ref is None and not identifiers:
        raise InvalidDocumentError(f"a {what} needs an '@id' or 'identifiers'", locator)
    id_locator = ptr_join(locator, "identifiers")
    purl = get_str(identifiers, "purl", id_locator)
    cpes = [
        value
        for key in ("cpe22", "cpe23")
        if (value := get_str(identifiers, key, id_locator)) is not None
    ]
    hashes: list[Hash] = []
    hash_obj = get_object(obj, "hashes", locator) or {}
    for algorithm, value in hash_obj.items():
        if not isinstance(value, str):
            raise InvalidDocumentError(
                "hash values must be strings", ptr_join(locator, "hashes", algorithm)
            )
        hashes.append(Hash(algorithm=algorithm, value=value))
    component = Component(
        name="",
        version=None,
        purl=purl,
        cpe=cpes,
        ecosystem=None,
        supplier=None,
        hashes=hashes,
        bom_ref=product_ref,
        identifier_variants=build_identifier_variants("", None, purl, cpes, hashes),
    )
    return component


def _statement_document(
    stmt: dict[str, Any],
    locator: str,
    document: SourceDocument,
    status: str,
    justification_raw: Optional[str],
    impact: Optional[str],
) -> SourceDocument:
    declared: dict[str, str] = {
        "format": FORMAT_NAME,
        "statement_locator": locator,
        "parent_document": document.doc_id,
        "status_raw": status,
        "assertion_status": ASSERTION_STATUS,
        "locator_convention": LOCATOR_CONVENTION,
    }
    if justification_raw is not None:
        declared["justification_raw"] = justification_raw
    if impact is not None:
        declared["impact_statement"] = impact
    for key in ("status_notes", "action_statement", "action_statement_timestamp", "last_updated"):
        value = get_str(stmt, key, locator)
        if value is not None:
            declared[key] = value
    if "version" in stmt:
        version = stmt["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDocumentError("'version' must be an integer", ptr_join(locator, "version"))
        declared["statement_version"] = str(version)
    declared["vulnerability"] = canonical_json(stmt["vulnerability"])
    declared["products"] = canonical_json(stmt["products"])
    declared["unextracted_statement_fields"] = canonical_json(
        unextracted_keys(stmt, _HANDLED_STATEMENT_KEYS)
    )

    statement_doc = SourceDocument(
        doc_id=f"{document.doc_id}#{locator[1:]}",
        producer=get_str(stmt, "supplier", locator),
        declared_metadata=declared,
    )
    timestamp = get_str(stmt, "timestamp", locator)
    if timestamp is not None:
        statement_doc.created = parse_timestamp(timestamp, ptr_join(locator, "timestamp"))
        declared["timestamp_raw"] = timestamp
    return statement_doc
