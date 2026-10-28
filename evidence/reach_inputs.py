"""Reachability evidence input (schema ``1``): typed records and a strict JSON loader.

Neither the SBOM formats nor OpenVEX carry call-graph analyses, entry-point sets, hazard
dispositions, a vulnerable-code locus approximation or a deployment configuration (register
G15). This module defines the one place those facts enter the pipeline, in the same spirit as
the evaluator profile: an immutable, strictly validated input. It parses and validates; it
derives no ``EvidenceState``, no BIND result, no provenance level, no rule outcome and no
verdict, and it refuses the names of such fields (``REACH_INPUT_FORBIDDEN_FIELD``): a caller can
never supply a state, a level or a verdict.

What the input contains
-----------------------
``documents[]``: evidence documents, each a source document in the sense of §1.1 with its own
attribution (``producer``, ``tool_name``, ``tool_version``, ``created``), an optional
``artifact`` it declares it analysed (BIND), an optional ``target`` component it concerns
(component-version binding) and a ``kind``:

* ``K1``: call-graph or equivalent authoritative analysis. May carry ``full_coverage_claim``,
  ``entry_points`` (``complete``) and ``modeled_hazards`` (a hazard class declared *inside* the
  report, §5.2).
* ``K2``: an assertion of (non-)reachability that discloses no analysis artifacts.
* ``K3``: runtime coverage or trace data.
* ``hazard_basis``: a document that is only the ``basis_ref`` of a hazard-exclusion claim; it has
  no reachability finding.

``finding`` is what the document reports about a path to the locus: ``negative`` (no path, or
no hit), ``positive`` (a path or execution is observed or asserted), ``incomplete`` and
``ambiguous`` (K1 only: modules unanalysed, unresolved may-reach edges), or ``unknown``.
A K1 ``negative`` finding is only an absence if the report declares a ``full_coverage_claim``
over LOCUS and ENTRY (§5.1 step 2); that is derived later, never read from the input.

Evaluator-entered, unauthenticated statements (like the profile's INV assertions): ``locus`` (with
the over-/under-approximation the evaluator or its authoritative source attests, A2),
``entry_points`` (A3), ``hazards[]`` (dispositions with an optional ``basis_ref``) and
``configuration`` (``deployment_config_id``, A7). ``entered_by`` is a label and is never used in
a decision. These items have no source document and are therefore P0 (§1.2 rule 1); they can never
carry the P3 floor that REACH needs.

Evidence kinds are never inferred: nothing here turns a dependency edge into a call edge (A5),
and a K4 dependency graph is read from the SBOM by the evaluator, not supplied here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Optional

from evidence.analysis_model import SourceRef
from evidence.reach_rules import HazardClass, HazardDisposition
from model import Component, Hash
from sbom_parser._common import InputSource, load_json_object, parse_timestamp, read_source
from sbom_parser.errors import ParserError
from sbom_parser.identifiers import build_identifier_variants, normalize_hash_algorithm, normalize_hash_value

SCHEMA_VERSION = "1"
_HEX = frozenset("0123456789abcdef")


class ReachInputErrorCode(str, Enum):
    MALFORMED_JSON = "REACH_INPUT_MALFORMED_JSON"
    SCHEMA_VERSION_UNSUPPORTED = "REACH_INPUT_SCHEMA_VERSION_UNSUPPORTED"
    UNKNOWN_FIELD = "REACH_INPUT_UNKNOWN_FIELD"
    FORBIDDEN_FIELD = "REACH_INPUT_FORBIDDEN_FIELD"
    MISSING_FIELD = "REACH_INPUT_MISSING_FIELD"
    INVALID_TYPE = "REACH_INPUT_INVALID_TYPE"
    INVALID_VALUE = "REACH_INPUT_INVALID_VALUE"
    DUPLICATE_DOCUMENT = "REACH_INPUT_DUPLICATE_DOCUMENT"
    DUPLICATE_HAZARD = "REACH_INPUT_DUPLICATE_HAZARD"
    FIELD_NOT_ALLOWED_FOR_KIND = "REACH_INPUT_FIELD_NOT_ALLOWED_FOR_KIND"
    INCONSISTENT = "REACH_INPUT_INCONSISTENT"


class ReachInputError(ValueError):
    """A hard input error: nothing is evaluated. ``path`` locates the offending field."""

    def __init__(self, code: ReachInputErrorCode, path: str, message: str) -> None:
        super().__init__(f"{code.value} at {path or '<reachability input>'}: {message}")
        self.code = code
        self.path = path
        self.message = message


class ReachKind(str, Enum):
    K1 = "K1"
    K2 = "K2"
    K3 = "K3"
    HAZARD_BASIS = "hazard_basis"


class ReachFinding(str, Enum):
    NEGATIVE = "negative"
    POSITIVE = "positive"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


_ALLOWED_FINDINGS = {
    ReachKind.K1: frozenset(ReachFinding),
    ReachKind.K2: frozenset({ReachFinding.NEGATIVE, ReachFinding.POSITIVE, ReachFinding.UNKNOWN}),
    ReachKind.K3: frozenset({ReachFinding.NEGATIVE, ReachFinding.POSITIVE, ReachFinding.UNKNOWN}),
    ReachKind.HAZARD_BASIS: frozenset(),
}


class LocusApproximation(str, Enum):
    OVER_APPROXIMATION = "over_approximation"
    POSSIBLY_UNDER_APPROXIMATE = "possibly_under_approximate"


@dataclass(frozen=True)
class TargetRef:
    """The component a document says it concerns. Compared with C by the evaluator."""

    purl: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None


@dataclass(frozen=True)
class ReachDocument:
    doc_id: str
    kind: ReachKind
    finding: Optional[ReachFinding]
    producer: Optional[str] = None
    producer_class: Optional[str] = None
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    created: Optional[datetime] = None
    artifact: Optional[Component] = None
    target: Optional[TargetRef] = None
    full_coverage_claim: bool = False
    entry_points_complete: Optional[bool] = None  # None: the document declares no entry-point set
    analyzed_configurations: tuple[str, ...] = ()
    modeled_hazards: tuple[HazardClass, ...] = ()
    # Derivation metadata of a document produced from a real analyzer artifact (evidence.analysis_binding).
    # Python-level only: the JSON loader never sets it, so input text cannot fabricate it.
    source: Optional[SourceRef] = None


@dataclass(frozen=True)
class LocusInput:
    symbols: tuple[str, ...]
    files: tuple[str, ...]
    granularity: Optional[str]
    locus_source: Optional[str]
    approximation: Optional[LocusApproximation]
    entered_by: str


@dataclass(frozen=True)
class EntryInput:
    complete: bool
    entered_by: str


@dataclass(frozen=True)
class HazardClaim:
    hazard_class: HazardClass
    disposition: HazardDisposition
    basis_ref: Optional[str] = None
    basis_locator: Optional[str] = None


@dataclass(frozen=True)
class ReachabilityEvidence:
    """The validated reachability input. ``documents`` keeps the input order."""

    schema_version: str
    documents: tuple[ReachDocument, ...] = ()
    locus: Optional[LocusInput] = None
    entry_points: Optional[EntryInput] = None
    hazards: tuple[HazardClaim, ...] = ()
    deployment_config_id: Optional[str] = None
    # Every analyzer artifact that was ingested for this evaluation, including those that produced no
    # document (their diagnostics and limitations are part of the explanation). Python-level only.
    analysis_sources: tuple[SourceRef, ...] = ()

    def document(self, doc_id: str) -> Optional[ReachDocument]:
        return next((d for d in self.documents if d.doc_id == doc_id), None)


# ---- validation helpers -----------------------------------------------------------------------------------

_FORBIDDEN = frozenset({
    "verdict", "state", "states", "reach", "reach_state", "evidence_state", "provenance", "provenance_level",
    "provenance_levels", "ep", "prov_reach", "prov_haz", "bind", "bind_state", "rules", "codes", "ceiling",
})
_TOP = ("schema_version", "documents", "locus", "entry_points", "hazards", "configuration")
_DOC = ("doc_id", "kind", "finding", "producer", "producer_class", "tool_name", "tool_version", "created", "artifact",
        "target", "full_coverage_claim", "entry_points", "analyzed_configurations", "modeled_hazards")
_K1_ONLY = ("full_coverage_claim", "entry_points", "modeled_hazards")


def _fail(code: ReachInputErrorCode, path: str, message: str) -> ReachInputError:
    return ReachInputError(code, path, message)


def _join(path: str, key: Any) -> str:
    return f"{path}.{key}" if isinstance(key, str) and path else (key if isinstance(key, str) else f"{path}[{key}]")


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _fail(ReachInputErrorCode.INVALID_TYPE, path, "expected an object")
    return value


def _check_keys(obj: Mapping[str, Any], path: str, allowed: tuple[str, ...]) -> None:
    for key in obj:
        if key in _FORBIDDEN:
            raise _fail(ReachInputErrorCode.FORBIDDEN_FIELD, _join(path, key),
                        "states, provenance levels, BIND results and verdicts are derived and can never be supplied")
        if key not in allowed:
            raise _fail(ReachInputErrorCode.UNKNOWN_FIELD, _join(path, key), f"allowed fields: {', '.join(allowed)}")


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _fail(ReachInputErrorCode.INVALID_TYPE, path, "expected a non-empty string")
    return value


def _optional_string(obj: Mapping[str, Any], path: str, key: str) -> Optional[str]:
    return _string(obj[key], _join(path, key)) if key in obj else None


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(ReachInputErrorCode.INVALID_TYPE, path, "expected a boolean")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(ReachInputErrorCode.INVALID_TYPE, path, "expected an array")
    return value


def _enum(enum_type: type, value: Any, path: str):
    if not isinstance(value, str):
        raise _fail(ReachInputErrorCode.INVALID_TYPE, path, "expected a string")
    try:
        return enum_type(value)
    except ValueError:
        allowed = ", ".join(e.value for e in enum_type)
        raise _fail(ReachInputErrorCode.INVALID_VALUE, path, f"{value!r} is not one of: {allowed}") from None


def _digest(value: Any, path: str) -> Hash:
    text = _string(value, path)
    algorithm, separator, digest = text.partition(":")
    normalized_algorithm, normalized_value = normalize_hash_algorithm(algorithm), normalize_hash_value(digest)
    if not separator or not normalized_algorithm or not normalized_value or not _HEX.issuperset(normalized_value):
        raise _fail(ReachInputErrorCode.INVALID_VALUE, path, "expected a digest in 'alg:hex' form")
    return Hash(normalized_algorithm, normalized_value)


def _artifact(value: Any, path: str) -> Component:
    obj = _object(value, path)
    _check_keys(obj, path, ("name", "version", "purl", "cpe", "hashes"))
    name, version, purl = (_optional_string(obj, path, k) for k in ("name", "version", "purl"))
    cpe = [_string(c, f"{path}.cpe[{n}]") for n, c in enumerate(_list(obj.get("cpe", []), f"{path}.cpe"))]
    hashes = [_digest(h, f"{path}.hashes[{n}]") for n, h in enumerate(_list(obj.get("hashes", []), f"{path}.hashes"))]
    if not (name or purl or cpe or hashes):
        raise _fail(ReachInputErrorCode.MISSING_FIELD, path, "an artifact needs a name, purl, cpe or hash")
    return Component(name=name or purl or "", version=version, purl=purl, cpe=cpe, hashes=hashes,
                     identifier_variants=build_identifier_variants(name or purl or "", version, purl, cpe, hashes))


def _target(value: Any, path: str) -> TargetRef:
    obj = _object(value, path)
    _check_keys(obj, path, ("purl", "name", "version"))
    target = TargetRef(*(_optional_string(obj, path, k) for k in ("purl", "name", "version")))
    if not (target.purl or (target.name and target.version)):
        raise _fail(ReachInputErrorCode.MISSING_FIELD, path, "a target needs a purl, or a name and a version")
    return target


def _document(value: Any, path: str) -> ReachDocument:
    obj = _object(value, path)
    _check_keys(obj, path, _DOC)
    for key in ("doc_id", "kind"):
        if key not in obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, _join(path, key), "required")
    doc_id = _string(obj["doc_id"], f"{path}.doc_id")
    kind = _enum(ReachKind, obj["kind"], f"{path}.kind")
    if kind is not ReachKind.K1:
        for key in _K1_ONLY:
            if key in obj:
                raise _fail(ReachInputErrorCode.FIELD_NOT_ALLOWED_FOR_KIND, f"{path}.{key}", f"only a K1 document can carry {key}")
    finding: Optional[ReachFinding] = None
    if kind is ReachKind.HAZARD_BASIS:
        if "finding" in obj:
            raise _fail(ReachInputErrorCode.FIELD_NOT_ALLOWED_FOR_KIND, f"{path}.finding", "a hazard_basis document reports no finding")
    else:
        if "finding" not in obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, f"{path}.finding", f"a {kind.value} document reports a finding")
        finding = _enum(ReachFinding, obj["finding"], f"{path}.finding")
        if finding not in _ALLOWED_FINDINGS[kind]:
            allowed = ", ".join(sorted(f.value for f in _ALLOWED_FINDINGS[kind]))
            raise _fail(ReachInputErrorCode.INVALID_VALUE, f"{path}.finding", f"a {kind.value} document can report: {allowed}")
    created: Optional[datetime] = None
    if "created" in obj:
        try:
            created = parse_timestamp(_string(obj["created"], f"{path}.created"), f"{path}.created")
        except ParserError as error:
            raise _fail(ReachInputErrorCode.INVALID_VALUE, f"{path}.created", str(error)) from None
    entry = None
    if "entry_points" in obj:
        entry_obj = _object(obj["entry_points"], f"{path}.entry_points")
        _check_keys(entry_obj, f"{path}.entry_points", ("complete",))
        if "complete" not in entry_obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, f"{path}.entry_points.complete", "required")
        entry = _bool(entry_obj["complete"], f"{path}.entry_points.complete")
    configurations = tuple(sorted({_string(c, f"{path}.analyzed_configurations[{n}]")
                                   for n, c in enumerate(_list(obj.get("analyzed_configurations", []), f"{path}.analyzed_configurations"))}))
    modeled = tuple(sorted({_enum(HazardClass, c, f"{path}.modeled_hazards[{n}]")
                            for n, c in enumerate(_list(obj.get("modeled_hazards", []), f"{path}.modeled_hazards"))},
                           key=lambda c: c.value))
    return ReachDocument(
        doc_id=doc_id, kind=kind, finding=finding,
        producer=_optional_string(obj, path, "producer"), producer_class=_optional_string(obj, path, "producer_class"),
        tool_name=_optional_string(obj, path, "tool_name"), tool_version=_optional_string(obj, path, "tool_version"),
        created=created,
        artifact=_artifact(obj["artifact"], f"{path}.artifact") if "artifact" in obj else None,
        target=_target(obj["target"], f"{path}.target") if "target" in obj else None,
        full_coverage_claim=_bool(obj["full_coverage_claim"], f"{path}.full_coverage_claim") if "full_coverage_claim" in obj else False,
        entry_points_complete=entry, analyzed_configurations=configurations, modeled_hazards=modeled,
    )


def _locus(value: Any, path: str) -> LocusInput:
    obj = _object(value, path)
    _check_keys(obj, path, ("symbols", "files", "granularity", "locus_source", "approximation", "entered_by"))
    symbols = tuple(_string(s, f"{path}.symbols[{n}]") for n, s in enumerate(_list(obj.get("symbols", []), f"{path}.symbols")))
    files = tuple(_string(s, f"{path}.files[{n}]") for n, s in enumerate(_list(obj.get("files", []), f"{path}.files")))
    granularity = _optional_string(obj, path, "granularity")
    if not (symbols or files or granularity):
        raise _fail(ReachInputErrorCode.MISSING_FIELD, path, "a locus needs symbols, files or a granularity (for example 'package')")
    approximation = _enum(LocusApproximation, obj["approximation"], f"{path}.approximation") if "approximation" in obj else None
    if "entered_by" not in obj:
        raise _fail(ReachInputErrorCode.MISSING_FIELD, f"{path}.entered_by", "required (an unverified label)")
    return LocusInput(symbols, files, granularity, _optional_string(obj, path, "locus_source"), approximation,
                      _string(obj["entered_by"], f"{path}.entered_by"))


def _entry(value: Any, path: str) -> EntryInput:
    obj = _object(value, path)
    _check_keys(obj, path, ("complete", "entered_by"))
    for key in ("complete", "entered_by"):
        if key not in obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, _join(path, key), "required")
    return EntryInput(_bool(obj["complete"], f"{path}.complete"), _string(obj["entered_by"], f"{path}.entered_by"))


def _hazard(value: Any, path: str) -> HazardClaim:
    obj = _object(value, path)
    _check_keys(obj, path, ("class", "disposition", "basis_ref", "basis_locator"))
    for key in ("class", "disposition"):
        if key not in obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, _join(path, key), "required")
    hazard_class = _enum(HazardClass, obj["class"], f"{path}.class")
    disposition = _enum(HazardDisposition, obj["disposition"], f"{path}.disposition")
    basis_ref, basis_locator = _optional_string(obj, path, "basis_ref"), _optional_string(obj, path, "basis_locator")
    if disposition is not HazardDisposition.EXCLUDED_BY_EVIDENCE and (basis_ref or basis_locator):
        raise _fail(ReachInputErrorCode.INCONSISTENT, path, "only an excluded_by_evidence claim has a basis_ref")
    if basis_locator is not None and basis_ref is None:
        raise _fail(ReachInputErrorCode.INCONSISTENT, f"{path}.basis_locator", "a basis_locator needs a basis_ref")
    if basis_locator is not None and not basis_locator.startswith("#"):
        raise _fail(ReachInputErrorCode.INVALID_VALUE, f"{path}.basis_locator", "expected a JSON Pointer in URI-fragment form ('#', '#/...')")
    return HazardClaim(hazard_class, disposition, basis_ref, basis_locator)


def parse_reachability(data: Mapping[str, Any]) -> ReachabilityEvidence:
    """Validate ``data`` and return the immutable input. Raises ``ReachInputError``."""
    obj = _object(data, "")
    _check_keys(obj, "", _TOP)
    if "schema_version" not in obj:
        raise _fail(ReachInputErrorCode.MISSING_FIELD, "schema_version", "required")
    if obj["schema_version"] != SCHEMA_VERSION:
        raise _fail(ReachInputErrorCode.SCHEMA_VERSION_UNSUPPORTED, "schema_version", f"only {SCHEMA_VERSION!r} is supported")
    documents = tuple(_document(d, f"documents[{n}]") for n, d in enumerate(_list(obj.get("documents", []), "documents")))
    seen: set[str] = set()
    for n, document in enumerate(documents):
        if document.doc_id in seen:
            raise _fail(ReachInputErrorCode.DUPLICATE_DOCUMENT, f"documents[{n}].doc_id", f"{document.doc_id!r} is declared twice")
        seen.add(document.doc_id)
    hazards = tuple(_hazard(h, f"hazards[{n}]") for n, h in enumerate(_list(obj.get("hazards", []), "hazards")))
    classes: set[HazardClass] = set()
    for n, claim in enumerate(hazards):
        if claim.hazard_class in classes:
            raise _fail(ReachInputErrorCode.DUPLICATE_HAZARD, f"hazards[{n}].class", f"{claim.hazard_class.value} is claimed twice")
        classes.add(claim.hazard_class)
    configuration = None
    if "configuration" in obj:
        config_obj = _object(obj["configuration"], "configuration")
        _check_keys(config_obj, "configuration", ("deployment_config_id",))
        if "deployment_config_id" not in config_obj:
            raise _fail(ReachInputErrorCode.MISSING_FIELD, "configuration.deployment_config_id", "required")
        configuration = _string(config_obj["deployment_config_id"], "configuration.deployment_config_id")
    return ReachabilityEvidence(
        schema_version=SCHEMA_VERSION, documents=documents,
        locus=_locus(obj["locus"], "locus") if "locus" in obj else None,
        entry_points=_entry(obj["entry_points"], "entry_points") if "entry_points" in obj else None,
        hazards=hazards, deployment_config_id=configuration,
    )


def load_reachability(source: InputSource) -> ReachabilityEvidence:
    """Read a JSON file (or text/bytes) and validate it. Raises ``ReachInputError``."""
    try:
        data = load_json_object(read_source(source), "reachability input")
    except ParserError as error:
        raise _fail(ReachInputErrorCode.MALFORMED_JSON, "", str(error)) from None
    return parse_reachability(data)
