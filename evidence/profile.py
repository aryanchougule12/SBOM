"""Evaluator profile, schema versions 1 and 1.1: loading and validation only (Phase 2).

An evaluator profile is the immutable, strictly validated input that carries what the
SBOM and VEX formats cannot: the scope S the claim is about, the target component C, the
supplied documents and their role, and evaluator-entered INV assertions. This module
parses and validates a profile and offers two pure helpers that apply it to a ``Finding``.

What this module is NOT:

* It derives no ``EvidenceState`` -- in particular no INV state -- and no BIND result,
  provenance level, rule outcome or verdict. A profile can never supply any of these:
  the names of such fields are rejected (``PROFILE_FORBIDDEN_FIELD``).
* It is not wired into ``evidence.extraction`` or ``evidence.cnp_rules``, and it does not
  compare a document with the scope (BIND stays open, register G3c).
* It does not implement the structural contradiction classifier (register G11 Q4) and
  makes no decision about duplicate identifiers (deferred "C3").
* It does not compute a profile digest (the contract is deferred).

Project policy, not specification text (each item is a proposal recorded in the register):

* The scope must be identifiable: ``product_id`` plus a ``version`` or at least one
  digest (``PROFILE_SCOPE_NOT_IDENTIFIABLE``). The specification (A6, section 4.1 BIND)
  names these identification forms but does not mandate this check.
* Digests use the approved canonical ``alg:hex`` form (register decision 2, G3c): the
  algorithm lower-cased with ``-``/``_`` removed, the value trimmed and lower-cased, via
  ``sbom_parser.identifiers``. The normalized value must be non-empty hexadecimal
  (``0-9a-f``); a malformed digest is ``PROFILE_DIGEST_MALFORMED``. No algorithm-specific
  length is required, because none has been approved. This is a validation rule only: the
  normalization itself is unchanged.
* ``scope.artifact_kind`` is required and must be one of ``source``, ``binary``,
  ``container``, ``other``. A missing or ``unknown`` kind is a hard error
  (``PROFILE_ARTIFACT_KIND_REQUIRED``). This is a scoped pre-evaluation gate. It does not
  resolve register G10: ``ArtifactKind.UNKNOWN`` semantics for N14/N15/N16 stay open.
* Schema ``"1.1"`` is additive. It makes the placement of a would-be target explicit:
  ``target.would_be_location.placement`` is ``nested_under_component`` (with the direct parent's
  ``parent_ref``) or ``top_level`` (with no ``parent_ref``; a top-level placement is never
  expressed by naming a root ``bom-ref``). Schema ``"1"`` is accepted exactly as before and does
  not accept ``placement`` (its location has an unspecified placement, from which nothing may be
  selected). Version ``"2"`` and any other value remain unsupported.
* Exactly one document, with role ``primary_sbom``. ``corroborating`` is recognised and
  refused (``PROFILE_ROLE_UNSUPPORTED``) in this slice.
* ``Finding.document_roles`` is the only engine-facing role map; ``apply_profile``
  populates it and refuses a conflicting pre-existing map.
* An ``inv_assertions[]`` entry is **evaluator-entered**. It is not an authenticated
  attestation; ``entered_by`` is an unverified label and is never used in a decision.
  The scope block inside it is compared with the profile scope as an input-consistency
  check only; equality neither identifies the artifact nor establishes BIND.

Two distinct layers for assertions:

* Structure (hard ``ProfileError``): types, required and unknown fields, non-empty
  strings, parseable ``entered_at``, a well-formed scope block.
* Semantics (non-fatal ``AssertionDiagnostic``): only the statement
  ``"full_component_list"`` is recognised; anything else is unusable
  (``INV_ASSERTION_STATEMENT_UNSUPPORTED``). A scope block that differs from the profile
  scope (``INV_ASSERTION_SCOPE_MISMATCH``), a document that is not supplied
  (``INV_ASSERTION_DOCUMENT_NOT_SUPPLIED``), and differing statements for one document
  (``INV_ASSERTION_CONFLICTING``) also make an assertion unusable. Identical duplicates
  collapse deterministically to the first (``INV_ASSERTION_DUPLICATE_IDENTICAL``,
  informational). A usable assertion is only an input to a later evaluator step: it
  never sets INV by itself, and INV ``Present`` additionally needs BIND ``MATCHED`` and
  the other conditions of the Phase 2 design.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from model import ArtifactKind, Component, DocumentRole, Finding, Hash
from sbom_parser._common import InputSource, load_json_object, parse_timestamp, read_source
from sbom_parser.errors import ParserError
from sbom_parser.identifiers import (
    build_identifier_variants,
    normalize_hash_algorithm,
    normalize_hash_value,
)

SCHEMA_VERSION = "1"
SCHEMA_VERSION_PLACEMENT = "1.1"  # additive: explicit target placement (register G1r / G6)
SUPPORTED_SCHEMA_VERSIONS = (SCHEMA_VERSION, SCHEMA_VERSION_PLACEMENT)
PLACEMENT_TOP_LEVEL = "top_level"
PLACEMENT_NESTED = "nested_under_component"
SUPPORTED_ASSERTION_STATEMENT = "full_component_list"


class ProfileErrorCode(str, Enum):
    MALFORMED_JSON = "PROFILE_MALFORMED_JSON"
    SCHEMA_VERSION_UNSUPPORTED = "PROFILE_SCHEMA_VERSION_UNSUPPORTED"
    UNKNOWN_FIELD = "PROFILE_UNKNOWN_FIELD"
    FORBIDDEN_FIELD = "PROFILE_FORBIDDEN_FIELD"
    MISSING_FIELD = "PROFILE_MISSING_FIELD"
    INVALID_TYPE = "PROFILE_INVALID_TYPE"
    INVALID_VALUE = "PROFILE_INVALID_VALUE"
    DIGEST_MALFORMED = "PROFILE_DIGEST_MALFORMED"
    SCOPE_NOT_IDENTIFIABLE = "PROFILE_SCOPE_NOT_IDENTIFIABLE"
    ARTIFACT_KIND_REQUIRED = "PROFILE_ARTIFACT_KIND_REQUIRED"
    DUPLICATE_DOCUMENT = "PROFILE_DUPLICATE_DOCUMENT"
    MULTIPLE_PRIMARY = "PROFILE_MULTIPLE_PRIMARY"
    ROLE_UNSUPPORTED = "PROFILE_ROLE_UNSUPPORTED"
    LOCATION_DOCUMENT_UNKNOWN = "PROFILE_LOCATION_DOCUMENT_UNKNOWN"
    FINDING_SELECTOR_REQUIRED = "PROFILE_FINDING_SELECTOR_REQUIRED"
    FINDING_NOT_FOUND = "PROFILE_FINDING_NOT_FOUND"
    FINDING_AMBIGUOUS = "PROFILE_FINDING_AMBIGUOUS"
    ROLE_CONFLICT = "PROFILE_ROLE_CONFLICT"
    SCOPE_CONFLICT = "PROFILE_SCOPE_CONFLICT"
    TARGET_CONFLICT = "PROFILE_TARGET_CONFLICT"
    PLACEMENT_REQUIRED = "PROFILE_PLACEMENT_REQUIRED"
    PLACEMENT_INVALID = "PROFILE_PLACEMENT_INVALID"
    PARENT_REF_REQUIRED = "PROFILE_PARENT_REF_REQUIRED"
    PARENT_REF_FORBIDDEN = "PROFILE_PARENT_REF_FORBIDDEN"


class ProfileError(ValueError):
    """A hard profile error: no further processing is possible. ``path`` locates the
    offending field (for example ``scope.artifact_digests[1]``)."""

    def __init__(self, code: ProfileErrorCode, path: str, message: str) -> None:
        super().__init__(f"{code.value} at {path or '<profile>'}: {message}")
        self.code = code
        self.path = path
        self.message = message


class AssertionDiagnosticCode(str, Enum):
    STATEMENT_UNSUPPORTED = "INV_ASSERTION_STATEMENT_UNSUPPORTED"
    SCOPE_MISMATCH = "INV_ASSERTION_SCOPE_MISMATCH"
    DOCUMENT_NOT_SUPPLIED = "INV_ASSERTION_DOCUMENT_NOT_SUPPLIED"
    CONFLICTING = "INV_ASSERTION_CONFLICTING"
    DUPLICATE_IDENTICAL = "INV_ASSERTION_DUPLICATE_IDENTICAL"


_DISQUALIFYING = frozenset(
    {
        AssertionDiagnosticCode.STATEMENT_UNSUPPORTED,
        AssertionDiagnosticCode.SCOPE_MISMATCH,
        AssertionDiagnosticCode.DOCUMENT_NOT_SUPPLIED,
        AssertionDiagnosticCode.CONFLICTING,
    }
)
_DIAGNOSTIC_ORDER = {code: n for n, code in enumerate(AssertionDiagnosticCode)}

# Names that would let a profile supply evidence states, provenance levels, rule outcomes
# or verdicts. Rejected with a distinct code wherever they appear.
FORBIDDEN_FIELDS = frozenset(
    {
        "verdict", "verdicts", "rationale", "codes", "rule", "rules", "rule_outcomes", "ceiling",
        "state", "states", "inv", "inv_state", "match", "match_state", "decl", "decl_state",
        "bind", "bind_state", "gen", "gen_state",
        "prov", "prov_sbom", "prov_decl", "prov_corr", "provenance", "provenance_level", "ep",
    }
)


# ---- validated representation (immutable) -----------------------------------------------------

@dataclass(frozen=True)
class ScopeIdentity:
    """The identifying fields of S carried by a profile. ``artifact_digests`` is sorted,
    de-duplicated and in canonical ``alg:hex`` form."""

    product_id: str
    version: Optional[str]
    artifact_digests: tuple[str, ...]
    artifact_kind: ArtifactKind

    @property
    def identity_tuple(self) -> tuple[str, Optional[str], tuple[str, ...], str]:
        """``(product_id, version, digests, kind)``: compared for equality between the
        profile and an assertion. An input-consistency check, not artifact identity."""
        return (self.product_id, self.version, self.artifact_digests, self.artifact_kind.value)


@dataclass(frozen=True)
class FindingSelector:
    vulnerability: str
    product_id: str


@dataclass(frozen=True)
class TargetComponentSpec:
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()  # canonical ``alg:hex``

    def to_component(self) -> Component:
        """A ``Component`` for C, with identifier variants built by the existing
        normalizer (no new normalization rule)."""
        hashes = [Hash(*digest.split(":", 1)) for digest in self.hashes]
        return Component(
            name=self.name,
            version=self.version,
            purl=self.purl,
            cpe=list(self.cpe),
            hashes=hashes,
            identifier_variants=build_identifier_variants(self.name, self.version, self.purl, self.cpe, hashes),
        )


@dataclass(frozen=True)
class WouldBeLocation:
    """Where the target component would appear in ``document`` if it were present.

    Schema ``"1"`` carries only ``document`` and ``parent_ref`` (``placement`` is ``None``: the
    placement is unspecified, so nothing may be selected from it). Schema ``"1.1"`` states
    ``placement`` explicitly: ``nested_under_component`` names the direct parent assembly by
    ``parent_ref`` (the ``bom-ref`` of the component whose ``components`` array would contain the
    target); ``top_level`` has no parent and carries no ``parent_ref``. A top-level placement is
    never expressed by naming a root ``bom-ref``.
    """

    document: str
    parent_ref: Optional[str]
    placement: Optional[str] = None


@dataclass(frozen=True)
class TargetSpec:
    component: TargetComponentSpec
    would_be_location: Optional[WouldBeLocation] = None


@dataclass(frozen=True)
class ProfileDocument:
    doc_id: str
    role: DocumentRole


@dataclass(frozen=True)
class InvAssertion:
    """An evaluator-entered assertion that the document's component list is the full
    component list. ``scope`` must equal the profile scope to be usable. ``entered_by``,
    ``entered_at`` and ``basis`` are unverified metadata."""

    index: int  # position in the input list
    document: str
    scope: ScopeIdentity
    statement: str
    entered_by: str
    entered_at: Optional[str] = None
    basis: Optional[str] = None


@dataclass(frozen=True)
class AssertionDiagnostic:
    code: AssertionDiagnosticCode
    index: int  # input position of the assertion concerned
    document: str
    detail: str

    @property
    def disqualifying(self) -> bool:
        return self.code in _DISQUALIFYING


@dataclass(frozen=True)
class ValidatedProfile:
    schema_version: str
    profile_id: str
    scope: ScopeIdentity
    documents: tuple[ProfileDocument, ...]
    finding_selector: Optional[FindingSelector] = None
    target: Optional[TargetSpec] = None
    inv_assertions: tuple[InvAssertion, ...] = ()  # after collapsing identical duplicates
    assertion_diagnostics: tuple[AssertionDiagnostic, ...] = ()

    @property
    def primary_document(self) -> str:
        return next(d.doc_id for d in self.documents if d.role is DocumentRole.PRIMARY_SBOM)

    @property
    def document_roles(self) -> Mapping[str, DocumentRole]:
        return {d.doc_id: d.role for d in self.documents}

    @property
    def usable_inv_assertions(self) -> tuple[InvAssertion, ...]:
        """Assertions without a disqualifying diagnostic. Usable is not Present: no INV
        state is derived here."""
        blocked = {d.index for d in self.assertion_diagnostics if d.disqualifying}
        return tuple(a for a in self.inv_assertions if a.index not in blocked)


# ---- structural validation helpers -------------------------------------------------------------

def _fail(code: ProfileErrorCode, path: str, message: str) -> ProfileError:
    return ProfileError(code, path, message)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _fail(ProfileErrorCode.INVALID_TYPE, path, "expected an object")
    return value


def _check_keys(obj: Mapping[str, Any], path: str, allowed: Sequence[str]) -> None:
    for key in sorted(obj):
        if key in FORBIDDEN_FIELDS:
            raise _fail(
                ProfileErrorCode.FORBIDDEN_FIELD, _join(path, key),
                "a profile cannot supply evidence states, provenance levels, rule outcomes or verdicts",
            )
    for key in sorted(obj):
        if key not in allowed:
            raise _fail(ProfileErrorCode.UNKNOWN_FIELD, _join(path, key), "unknown field")


def _require(obj: Mapping[str, Any], path: str, key: str) -> Any:
    if key not in obj:
        raise _fail(ProfileErrorCode.MISSING_FIELD, _join(path, key), "required field is missing")
    return obj[key]


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise _fail(ProfileErrorCode.INVALID_TYPE, path, "expected a string")
    if not value.strip():
        raise _fail(ProfileErrorCode.INVALID_VALUE, path, "must be a non-empty string")
    return value


def _optional_string(obj: Mapping[str, Any], path: str, key: str) -> Optional[str]:
    return _string(obj[key], _join(path, key)) if key in obj else None


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(ProfileErrorCode.INVALID_TYPE, path, "expected an array")
    return value


_HEX_DIGITS = frozenset("0123456789abcdef")


def _digest(value: Any, path: str) -> str:
    """``alg:hex`` -> the approved canonical form.

    The algorithm and the value must both be non-empty after the approved normalization,
    and the normalized value must consist only of the characters ``0-9a-f``. No length is
    checked: none has been approved for any algorithm.
    """
    if not isinstance(value, str):
        raise _fail(ProfileErrorCode.INVALID_TYPE, path, "expected a string")
    algorithm, separator, digest = value.partition(":")
    algorithm, digest = normalize_hash_algorithm(algorithm), normalize_hash_value(digest)
    if not separator or not algorithm or not digest:
        raise _fail(ProfileErrorCode.DIGEST_MALFORMED, path, "expected '<algorithm>:<hex>'")
    if not _HEX_DIGITS.issuperset(digest):
        raise _fail(ProfileErrorCode.DIGEST_MALFORMED, path, "the digest value must be hexadecimal")
    return f"{algorithm}:{digest}"


def _digests(obj: Mapping[str, Any], path: str, key: str) -> tuple[str, ...]:
    if key not in obj:
        return ()
    items = _list(obj[key], _join(path, key))
    return tuple(sorted({_digest(item, f"{_join(path, key)}[{n}]") for n, item in enumerate(items)}))


def _artifact_kind(obj: Mapping[str, Any], path: str, *, gate: bool) -> ArtifactKind:
    key_path = _join(path, "artifact_kind")
    if "artifact_kind" not in obj:
        code = ProfileErrorCode.ARTIFACT_KIND_REQUIRED if gate else ProfileErrorCode.MISSING_FIELD
        raise _fail(code, key_path, "an explicit artifact kind is required")
    value = obj["artifact_kind"]
    if not isinstance(value, str):
        raise _fail(ProfileErrorCode.INVALID_TYPE, key_path, "expected a string")
    if value == ArtifactKind.UNKNOWN.value and gate:
        raise _fail(
            ProfileErrorCode.ARTIFACT_KIND_REQUIRED, key_path,
            "'unknown' is not an artifact kind a profile may state",
        )
    allowed = (ArtifactKind.SOURCE, ArtifactKind.BINARY, ArtifactKind.CONTAINER, ArtifactKind.OTHER)
    for kind in allowed:
        if kind.value == value:
            return kind
    raise _fail(ProfileErrorCode.INVALID_VALUE, key_path, "must be one of source, binary, container, other")


def _scope(value: Any, path: str, *, profile_scope: bool) -> ScopeIdentity:
    obj = _object(value, path)
    _check_keys(obj, path, ("product_id", "version", "artifact_digests", "artifact_kind"))
    product_id = _string(_require(obj, path, "product_id"), _join(path, "product_id"))
    version = _optional_string(obj, path, "version")
    digests = _digests(obj, path, "artifact_digests")
    kind = _artifact_kind(obj, path, gate=profile_scope)
    if profile_scope and version is None and not digests:
        raise _fail(
            ProfileErrorCode.SCOPE_NOT_IDENTIFIABLE, path,
            "the scope needs a version or at least one digest in addition to product_id",
        )
    return ScopeIdentity(product_id, version, digests, kind)


def _selector(value: Any, path: str) -> FindingSelector:
    obj = _object(value, path)
    _check_keys(obj, path, ("vulnerability", "product_id"))
    return FindingSelector(
        _string(_require(obj, path, "vulnerability"), _join(path, "vulnerability")),
        _string(_require(obj, path, "product_id"), _join(path, "product_id")),
    )


def _location(loc: Mapping[str, Any], location_path: str, schema_version: str) -> WouldBeLocation:
    if schema_version == SCHEMA_VERSION:  # schema 1: exactly as before
        _check_keys(loc, location_path, ("document", "parent_ref"))
        return WouldBeLocation(
            _string(_require(loc, location_path, "document"), _join(location_path, "document")),
            _string(_require(loc, location_path, "parent_ref"), _join(location_path, "parent_ref")),
        )
    _check_keys(loc, location_path, ("document", "placement", "parent_ref"))
    document = _string(_require(loc, location_path, "document"), _join(location_path, "document"))
    placement_path = _join(location_path, "placement")
    if "placement" not in loc:
        raise _fail(ProfileErrorCode.PLACEMENT_REQUIRED, placement_path, "an explicit placement is required")
    placement = loc["placement"]
    if not isinstance(placement, str):
        raise _fail(ProfileErrorCode.INVALID_TYPE, placement_path, "expected a string")
    if placement not in (PLACEMENT_TOP_LEVEL, PLACEMENT_NESTED):
        raise _fail(ProfileErrorCode.PLACEMENT_INVALID, placement_path,
                    f"must be '{PLACEMENT_TOP_LEVEL}' or '{PLACEMENT_NESTED}'")
    parent_path = _join(location_path, "parent_ref")
    if placement == PLACEMENT_TOP_LEVEL:
        if "parent_ref" in loc:
            raise _fail(ProfileErrorCode.PARENT_REF_FORBIDDEN, parent_path,
                        "a top-level placement has no parent; it is never expressed by naming a root bom-ref")
        return WouldBeLocation(document, None, placement)
    if "parent_ref" not in loc:
        raise _fail(ProfileErrorCode.PARENT_REF_REQUIRED, parent_path,
                    "a nested placement must name its direct parent assembly")
    return WouldBeLocation(document, _string(loc["parent_ref"], parent_path), placement)


def _target(value: Any, path: str, schema_version: str = SCHEMA_VERSION) -> TargetSpec:
    obj = _object(value, path)
    _check_keys(obj, path, ("component", "would_be_location"))
    component_path = _join(path, "component")
    comp = _object(_require(obj, path, "component"), component_path)
    _check_keys(comp, component_path, ("name", "version", "purl", "cpe", "hashes"))
    cpe_items = _list(comp["cpe"], _join(component_path, "cpe")) if "cpe" in comp else []
    component = TargetComponentSpec(
        name=_string(_require(comp, component_path, "name"), _join(component_path, "name")),
        version=_optional_string(comp, component_path, "version"),
        purl=_optional_string(comp, component_path, "purl"),
        cpe=tuple(_string(item, f"{_join(component_path, 'cpe')}[{n}]") for n, item in enumerate(cpe_items)),
        hashes=_digests(comp, component_path, "hashes"),
    )
    location: Optional[WouldBeLocation] = None
    if "would_be_location" in obj:
        location_path = _join(path, "would_be_location")
        loc = _object(obj["would_be_location"], location_path)
        location = _location(loc, location_path, schema_version)
    return TargetSpec(component, location)


def _documents(value: Any, path: str) -> tuple[ProfileDocument, ...]:
    items = _list(value, path)
    if not items:
        raise _fail(ProfileErrorCode.INVALID_VALUE, path, "at least one document is required")
    documents: list[ProfileDocument] = []
    seen: set[str] = set()
    for n, item in enumerate(items):
        item_path = f"{path}[{n}]"
        obj = _object(item, item_path)
        _check_keys(obj, item_path, ("doc_id", "role"))
        doc_id = _string(_require(obj, item_path, "doc_id"), _join(item_path, "doc_id"))
        role = _string(_require(obj, item_path, "role"), _join(item_path, "role"))
        if doc_id in seen:
            raise _fail(ProfileErrorCode.DUPLICATE_DOCUMENT, _join(item_path, "doc_id"), f"document {doc_id!r} is listed twice")
        seen.add(doc_id)
        if role == DocumentRole.CORROBORATING.value:
            raise _fail(
                ProfileErrorCode.ROLE_UNSUPPORTED, _join(item_path, "role"),
                "corroborating documents are not accepted in this slice",
            )
        if role != DocumentRole.PRIMARY_SBOM.value:
            raise _fail(ProfileErrorCode.INVALID_VALUE, _join(item_path, "role"), "must be 'primary_sbom'")
        if any(d.role is DocumentRole.PRIMARY_SBOM for d in documents):
            raise _fail(ProfileErrorCode.MULTIPLE_PRIMARY, _join(item_path, "role"), "exactly one primary_sbom is allowed")
        documents.append(ProfileDocument(doc_id, DocumentRole.PRIMARY_SBOM))
    return tuple(documents)


def _assertion(value: Any, path: str, index: int) -> InvAssertion:
    obj = _object(value, path)
    _check_keys(obj, path, ("document", "scope", "statement", "entered_by", "entered_at", "basis"))
    document = _string(_require(obj, path, "document"), _join(path, "document"))
    scope = _scope(_require(obj, path, "scope"), _join(path, "scope"), profile_scope=False)
    statement = _string(_require(obj, path, "statement"), _join(path, "statement"))
    entered_by = _string(_require(obj, path, "entered_by"), _join(path, "entered_by"))
    entered_at = _optional_string(obj, path, "entered_at")
    if entered_at is not None:
        try:
            parse_timestamp(entered_at, _join(path, "entered_at"))
        except ParserError as exc:
            raise _fail(ProfileErrorCode.INVALID_VALUE, _join(path, "entered_at"), "not an ISO 8601 date-time") from exc
    return InvAssertion(index, document, scope, statement, entered_by, entered_at, _optional_string(obj, path, "basis"))


def _assess_assertions(
    assertions: Sequence[InvAssertion], profile_scope: ScopeIdentity, documents: Sequence[ProfileDocument]
) -> tuple[tuple[InvAssertion, ...], tuple[AssertionDiagnostic, ...]]:
    """Semantic checks. Never raises and never derives an INV state."""
    diagnostics: list[AssertionDiagnostic] = []
    kept: list[InvAssertion] = []
    first_by_key: dict[tuple[str, str, tuple[Any, ...]], InvAssertion] = {}
    for assertion in assertions:
        key = (assertion.document, assertion.statement, assertion.scope.identity_tuple)
        if key in first_by_key:
            diagnostics.append(
                AssertionDiagnostic(
                    AssertionDiagnosticCode.DUPLICATE_IDENTICAL, assertion.index, assertion.document,
                    f"identical to the assertion at position {first_by_key[key].index}; collapsed to the first",
                )
            )
            continue
        first_by_key[key] = assertion
        kept.append(assertion)

    statements_by_document: dict[str, set[str]] = {}
    for assertion in kept:
        statements_by_document.setdefault(assertion.document, set()).add(assertion.statement)
    supplied = {d.doc_id for d in documents}
    for assertion in kept:
        if assertion.document not in supplied:
            diagnostics.append(AssertionDiagnostic(
                AssertionDiagnosticCode.DOCUMENT_NOT_SUPPLIED, assertion.index, assertion.document,
                "the document is not listed in documents[]"))
        if assertion.statement != SUPPORTED_ASSERTION_STATEMENT:
            diagnostics.append(AssertionDiagnostic(
                AssertionDiagnosticCode.STATEMENT_UNSUPPORTED, assertion.index, assertion.document,
                f"only {SUPPORTED_ASSERTION_STATEMENT!r} is recognised"))
        if assertion.scope.identity_tuple != profile_scope.identity_tuple:
            diagnostics.append(AssertionDiagnostic(
                AssertionDiagnosticCode.SCOPE_MISMATCH, assertion.index, assertion.document,
                "the assertion's scope block differs from the profile scope (an input-consistency check only)"))
        if len(statements_by_document[assertion.document]) > 1:
            diagnostics.append(AssertionDiagnostic(
                AssertionDiagnosticCode.CONFLICTING, assertion.index, assertion.document,
                "different statements are entered for the same document"))
    diagnostics.sort(key=lambda d: (d.index, _DIAGNOSTIC_ORDER[d.code]))
    return tuple(kept), tuple(diagnostics)


# ---- public API -------------------------------------------------------------------------------------------

def parse_profile(data: Mapping[str, Any]) -> ValidatedProfile:
    """Validate a decoded profile (a JSON object) and return its immutable form.

    Raises ``ProfileError`` (with a stable ``code`` and a ``path``) on the first
    structural problem, in a fixed order, so the result is deterministic.
    """
    obj = _object(data, "")
    if "schema_version" not in obj:
        raise _fail(ProfileErrorCode.MISSING_FIELD, "schema_version", "required field is missing")
    version = obj["schema_version"]
    if not isinstance(version, str):
        raise _fail(ProfileErrorCode.INVALID_TYPE, "schema_version", "expected a string")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise _fail(
            ProfileErrorCode.SCHEMA_VERSION_UNSUPPORTED, "schema_version",
            f"only versions {', '.join(repr(v) for v in SUPPORTED_SCHEMA_VERSIONS)} are supported",
        )
    _check_keys(obj, "", ("schema_version", "profile_id", "finding_selector", "scope", "target", "documents", "inv_assertions"))

    profile_id = _string(_require(obj, "", "profile_id"), "profile_id")
    selector = _selector(obj["finding_selector"], "finding_selector") if "finding_selector" in obj else None
    scope = _scope(_require(obj, "", "scope"), "scope", profile_scope=True)
    target = _target(obj["target"], "target", version) if "target" in obj else None
    documents = _documents(_require(obj, "", "documents"), "documents")
    if target is not None and target.would_be_location is not None:
        if target.would_be_location.document not in {d.doc_id for d in documents}:
            raise _fail(
                ProfileErrorCode.LOCATION_DOCUMENT_UNKNOWN, "target.would_be_location.document",
                "the document is not listed in documents[]",
            )
    raw_assertions = _list(obj["inv_assertions"], "inv_assertions") if "inv_assertions" in obj else []
    assertions = [_assertion(item, f"inv_assertions[{n}]", n) for n, item in enumerate(raw_assertions)]
    kept, diagnostics = _assess_assertions(assertions, scope, documents)
    return ValidatedProfile(
        schema_version=version,
        profile_id=profile_id,
        scope=scope,
        documents=documents,
        finding_selector=selector,
        target=target,
        inv_assertions=kept,
        assertion_diagnostics=diagnostics,
    )


def load_profile(source: InputSource) -> ValidatedProfile:
    """Read ``source`` (bytes, or a path) as strict JSON and validate it."""
    try:
        data = load_json_object(read_source(source), "profile")
    except ParserError as exc:
        raise _fail(ProfileErrorCode.MALFORMED_JSON, "", str(exc)) from exc
    return parse_profile(data)


def select_finding(profile: ValidatedProfile, findings: Sequence[Finding]) -> Finding:
    """Pick the single finding the profile concerns.

    Without a ``finding_selector`` the document must yield exactly one finding; with one,
    exactly one finding must match its vulnerability id and product id.
    """
    if profile.finding_selector is None:
        if len(findings) == 1:
            return findings[0]
        if not findings:
            raise _fail(ProfileErrorCode.FINDING_NOT_FOUND, "", "no finding was supplied")
        raise _fail(
            ProfileErrorCode.FINDING_SELECTOR_REQUIRED, "finding_selector",
            f"{len(findings)} findings were supplied; a finding_selector is required",
        )
    selector = profile.finding_selector
    matches = [f for f in findings if f.vulnerability.id == selector.vulnerability and f.scope.product_id == selector.product_id]
    if not matches:
        raise _fail(ProfileErrorCode.FINDING_NOT_FOUND, "finding_selector", "no finding matches the selector")
    if len(matches) > 1:
        raise _fail(ProfileErrorCode.FINDING_AMBIGUOUS, "finding_selector", f"{len(matches)} findings match the selector")
    return matches[0]


def apply_profile(profile: ValidatedProfile, finding: Finding) -> Finding:
    """Return a copy of ``finding`` carrying the profile's scope, target and roles.

    Nothing is overridden silently: a value the finding already states must agree with the
    profile (``PROFILE_SCOPE_CONFLICT``, ``PROFILE_TARGET_CONFLICT``, ``PROFILE_ROLE_CONFLICT``).
    ``Finding.document_roles`` stays the only role map; extra roles already present are
    preserved. The input finding is not mutated.
    """
    existing_scope = finding.scope
    scope = profile.scope
    if existing_scope.product_id and existing_scope.product_id != scope.product_id:
        raise _fail(ProfileErrorCode.SCOPE_CONFLICT, "scope.product_id", "differs from the finding's product id")
    if existing_scope.artifact_kind is not ArtifactKind.UNKNOWN and existing_scope.artifact_kind is not scope.artifact_kind:
        raise _fail(ProfileErrorCode.SCOPE_CONFLICT, "scope.artifact_kind", "differs from the finding's artifact kind")
    if existing_scope.version is not None and existing_scope.version != scope.version:
        raise _fail(ProfileErrorCode.SCOPE_CONFLICT, "scope.version", "differs from the finding's version")
    if existing_scope.artifact_digest:
        try:
            existing_digests = tuple(sorted({_digest(d, "") for d in existing_scope.artifact_digest}))
        except ProfileError:
            existing_digests = tuple(sorted(existing_scope.artifact_digest))
        if existing_digests != scope.artifact_digests:
            raise _fail(ProfileErrorCode.SCOPE_CONFLICT, "scope.artifact_digests", "differs from the finding's digests")

    if profile.target is not None and finding.component is not None:
        raise _fail(ProfileErrorCode.TARGET_CONFLICT, "target.component", "the finding already establishes a target component")

    primary = profile.primary_document
    for doc_id, role in finding.document_roles.items():
        if (role is DocumentRole.PRIMARY_SBOM and doc_id != primary) or (doc_id == primary and role is not DocumentRole.PRIMARY_SBOM):
            raise _fail(ProfileErrorCode.ROLE_CONFLICT, "documents", f"the finding already assigns {role.value!r} to {doc_id!r}")
    roles = {**finding.document_roles, primary: DocumentRole.PRIMARY_SBOM}

    # Every check above has passed; nothing has been built from the input yet. Copy deeply so
    # the result shares no mutable state (evidence, source documents, ...) with the input.
    finding = copy.deepcopy(finding)
    existing_scope = finding.scope
    component = profile.target.component.to_component() if profile.target is not None else finding.component
    new_scope = dataclasses.replace(
        existing_scope,
        product_id=scope.product_id,
        version=scope.version,
        artifact_digest=list(scope.artifact_digests),
        artifact_kind=scope.artifact_kind,
    )
    return dataclasses.replace(finding, scope=new_scope, component=component, document_roles=roles)
