"""Externally supplied signature-verification results (specification A5, U-2).

The specification does not verify signatures: it "consumes the verification result
`signature_verified` (a boolean) and, when available, the verified locator coverage
`established_coverage` that the result establishes" (A5). This module defines that input as a
strict, typed, immutable record and nothing more. It performs **no cryptographic
verification** and never infers a verification from a signature a document declares.

Trust boundary. A ``VerificationConfig`` is a *trusted, out-of-band* input of the evaluator: the
caller's own environment supplies it, after an external verifier has checked a signature against
a trust anchor that the caller configured. It must never be read from the evaluator profile
(whose assertions are unauthenticated evaluator statements), from the SBOM or VEX document
itself, or from any parser output. ``trust_anchors`` is the externally configured set of anchor
labels the caller accepts (A5, U-2: key governance is outside this project); a result whose
``trust_anchor_id`` is not in that set cannot be used.

Detached verification (U-2 project policy). A result may refer to a document that embeds no
signature field (a detached signature or attestation verified outside this project; SPDX 2.3 JSON
has no signature field at all). It is used exactly as for an embedded signature, provided it is
trusted (its anchor is in ``trust_anchors``), bound to the exact ``doc_id``, ``verified`` and valid
for the coverage it states. Using it does not mean the SBOM contains a signature, and this module
and the evaluator never verify one.

What a result establishes, when it is consumed (``evidence.document_provenance``): that the named
external verifier reported ``verified`` for the exact document ``doc_id`` (a content hash, so it
refers to those bytes) under the named anchor, covering the listed JSON Pointer locators. It does
**not** establish that the content is accurate, that the component inventory is complete, that
the document describes S, or that the verifier was run correctly.

A result with ``established_coverage = None`` states that coverage is not established or is
unavailable; it is not an empty verified coverage (``()`` means verification established that
no locator is covered).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional

from evidence.provenance import locator_within
from sbom_parser._common import InputSource, load_json_object, read_source
from sbom_parser.errors import ParserError

SCHEMA_VERSION = "1"


class VerificationErrorCode(str, Enum):
    MALFORMED_JSON = "VERIFICATION_MALFORMED_JSON"
    SCHEMA_VERSION_UNSUPPORTED = "VERIFICATION_SCHEMA_VERSION_UNSUPPORTED"
    UNKNOWN_FIELD = "VERIFICATION_UNKNOWN_FIELD"
    MISSING_FIELD = "VERIFICATION_MISSING_FIELD"
    INVALID_TYPE = "VERIFICATION_INVALID_TYPE"
    INVALID_VALUE = "VERIFICATION_INVALID_VALUE"
    COVERAGE_MALFORMED = "VERIFICATION_COVERAGE_MALFORMED"
    DUPLICATE_RESULT = "VERIFICATION_DUPLICATE_RESULT"


class VerificationError(ValueError):
    """A hard error: the verification data is malformed or ambiguous and is not used."""

    def __init__(self, code: VerificationErrorCode, path: str, message: str) -> None:
        super().__init__(f"{code.value} at {path or '<verification>'}: {message}")
        self.code = code
        self.path = path
        self.message = message


@dataclass(frozen=True)
class VerificationResult:
    """One external verification result for one document (see the module docstring)."""

    doc_id: str
    verified: bool
    trust_anchor_id: str
    verifier_name: str
    verifier_version: str
    established_coverage: Optional[tuple[str, ...]] = None

    def __post_init__(self) -> None:
        for name in ("doc_id", "trust_anchor_id", "verifier_name", "verifier_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise VerificationError(VerificationErrorCode.INVALID_VALUE, name, "must be a non-empty string")
        if not isinstance(self.verified, bool):
            raise VerificationError(VerificationErrorCode.INVALID_TYPE, "verified", "must be a boolean")
        if self.established_coverage is not None:
            if not isinstance(self.established_coverage, tuple):
                raise VerificationError(VerificationErrorCode.INVALID_TYPE, "established_coverage", "must be a tuple or None")
            for entry in self.established_coverage:
                _check_pointer(entry, "established_coverage")


@dataclass(frozen=True)
class VerificationConfig:
    """The trusted verification input: the accepted anchor labels and at most one result per
    document."""

    trust_anchors: frozenset[str]
    results: tuple[VerificationResult, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.trust_anchors, frozenset) or not all(
            isinstance(a, str) and a.strip() for a in self.trust_anchors
        ):
            raise VerificationError(VerificationErrorCode.INVALID_VALUE, "trust_anchors",
                                    "must be a frozenset of non-empty strings")
        if not isinstance(self.results, tuple) or not all(isinstance(r, VerificationResult) for r in self.results):
            raise VerificationError(VerificationErrorCode.INVALID_TYPE, "results",
                                    "must be a tuple of VerificationResult")
        ids = [r.doc_id for r in self.results]
        if len(ids) != len(set(ids)):
            raise VerificationError(VerificationErrorCode.DUPLICATE_RESULT, "results",
                                    "at most one verification result per document is allowed")

    def result_for(self, doc_id: str) -> Optional[VerificationResult]:
        """The result for exactly ``doc_id`` (no case-folding or trimming), or ``None``."""
        for result in self.results:
            if result.doc_id == doc_id:
                return result
        return None


def _check_pointer(entry: Any, path: str) -> None:
    if not isinstance(entry, str):
        raise VerificationError(VerificationErrorCode.COVERAGE_MALFORMED, path, "coverage entries must be strings")
    try:
        locator_within(entry, entry)
    except ValueError as exc:
        raise VerificationError(VerificationErrorCode.COVERAGE_MALFORMED, path,
                                f"{entry!r} is not a URI-fragment JSON Pointer") from exc


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(VerificationErrorCode.INVALID_TYPE, path, "expected an object")
    return value


def _strict(obj: Mapping[str, Any], path: str, allowed: tuple[str, ...]) -> None:
    for key in sorted(obj):
        if key not in allowed:
            raise VerificationError(VerificationErrorCode.UNKNOWN_FIELD, f"{path}.{key}" if path else key, "unknown field")


def _require(obj: Mapping[str, Any], path: str, key: str) -> Any:
    if key not in obj:
        raise VerificationError(VerificationErrorCode.MISSING_FIELD, f"{path}.{key}" if path else key, "required field is missing")
    return obj[key]


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise VerificationError(VerificationErrorCode.INVALID_TYPE, path, "expected a string")
    if not value.strip():
        raise VerificationError(VerificationErrorCode.INVALID_VALUE, path, "must be a non-empty string")
    return value


def parse_verification(data: Mapping[str, Any]) -> VerificationConfig:
    """Validate decoded verification data (schema ``"1"``) strictly.

    ``{"schema_version": "1", "trust_anchors": [...], "results": [{"doc_id", "verified",
    "trust_anchor_id", "verifier": {"name", "version"}, "established_coverage": [...] | null}]}``.
    """
    obj = _object(data, "")
    version = _require(obj, "", "schema_version")
    if not isinstance(version, str):
        raise VerificationError(VerificationErrorCode.INVALID_TYPE, "schema_version", "expected a string")
    if version != SCHEMA_VERSION:
        raise VerificationError(VerificationErrorCode.SCHEMA_VERSION_UNSUPPORTED, "schema_version",
                                f"only version {SCHEMA_VERSION!r} is supported")
    _strict(obj, "", ("schema_version", "trust_anchors", "results"))
    anchors_raw = _require(obj, "", "trust_anchors")
    if not isinstance(anchors_raw, list):
        raise VerificationError(VerificationErrorCode.INVALID_TYPE, "trust_anchors", "expected an array")
    anchors = frozenset(_string(a, f"trust_anchors[{n}]") for n, a in enumerate(anchors_raw))
    results_raw = obj.get("results", [])
    if not isinstance(results_raw, list):
        raise VerificationError(VerificationErrorCode.INVALID_TYPE, "results", "expected an array")
    results: list[VerificationResult] = []
    for n, item in enumerate(results_raw):
        path = f"results[{n}]"
        entry = _object(item, path)
        _strict(entry, path, ("doc_id", "verified", "trust_anchor_id", "verifier", "established_coverage"))
        verifier = _object(_require(entry, path, "verifier"), f"{path}.verifier")
        _strict(verifier, f"{path}.verifier", ("name", "version"))
        verified = _require(entry, path, "verified")
        if not isinstance(verified, bool):
            raise VerificationError(VerificationErrorCode.INVALID_TYPE, f"{path}.verified", "expected a boolean")
        coverage_raw = _require(entry, path, "established_coverage")
        coverage: Optional[tuple[str, ...]]
        if coverage_raw is None:
            coverage = None
        elif isinstance(coverage_raw, list):
            for m, pointer in enumerate(coverage_raw):
                _check_pointer(pointer, f"{path}.established_coverage[{m}]")
            coverage = tuple(sorted(set(coverage_raw)))
        else:
            raise VerificationError(VerificationErrorCode.INVALID_TYPE, f"{path}.established_coverage",
                                    "expected an array or null")
        results.append(
            VerificationResult(
                doc_id=_string(_require(entry, path, "doc_id"), f"{path}.doc_id"),
                verified=verified,
                trust_anchor_id=_string(_require(entry, path, "trust_anchor_id"), f"{path}.trust_anchor_id"),
                verifier_name=_string(_require(verifier, f"{path}.verifier", "name"), f"{path}.verifier.name"),
                verifier_version=_string(_require(verifier, f"{path}.verifier", "version"), f"{path}.verifier.version"),
                established_coverage=coverage,
            )
        )
    return VerificationConfig(anchors, tuple(sorted(results, key=lambda r: r.doc_id)))


def load_verification(source: InputSource) -> VerificationConfig:
    """Read ``source`` (bytes, or a path) as strict JSON and validate it."""
    try:
        data = load_json_object(read_source(source), "verification")
    except ParserError as exc:
        raise VerificationError(VerificationErrorCode.MALFORMED_JSON, "", str(exc)) from exc
    return parse_verification(data)
