"""Analysis-run record (schema ``analysis-run/1``): what is recorded about the run that produced an analyzer artifact.

A record is an **assertion**. It is strictly parsed and canonically serialized here; it is never
interpreted here. ``evidence.analysis_run_binding`` relates it to the artifact (whose bytes the
evaluator holds), to the evaluator's ``AnalysisSubject`` and to the locus, and only then do any of its
statements influence an evaluation, and only in the ways listed there.

What a record can and cannot be
-------------------------------
* A record written by the reproducible runner (``python -m analysis_runner``) reliably reports the
  commands it executed, the exit statuses it observed, the source identity it read from git and the
  digest of each output it hashed. Read back from a file it is still only JSON: nothing in it proves
  that those observations were made, so ``origin`` (``runner`` or ``caller``) and every ``field_sources``
  entry are statements, not proof.
* A hash that matches the artifact's bytes shows that the record *describes this file*. It does not show
  that the analyzer ran, that its result is trustworthy, or that it covered anything.
* A record never carries an evidence state, a BIND result, a provenance level, a trust statement or a
  verdict: those names are refused wherever they appear (``ANALYSIS_RUN_FORBIDDEN_FIELD``), and a record
  can never claim ``established_by_verification`` as the source of a field: only a consumed detached
  verification result (``evidence.verification``) can establish anything, and this record is not one.
* Missing is not negative. Every optional fact is ``null``/absent when it was not observed; ``false`` and
  ``0`` are positive statements ("the tree was not clean", "no untracked files") and are different from
  "unknown".

Layout (all keys strict; unknown keys are errors)::

    schema, run_id, origin, field_sources
    tool          name, version, output_format_version, executable_sha256
    source        repository, revision, analysis_subpath, tree_digest, worktree_clean, untracked_files,
                  submodules[{path, revision}], changed_during_run, roots[{id, path, role, repository, revision}]
    target        purl, source_root
    configuration languages[], query{pack, pack_version, pack_digest, suite, query_ids[], claim_semantics}, command[]
    stages[]      name, role, status, exit_code, started, finished
    outputs[]     path, sha256, size
    scope         files{complete, included[], excluded[]}, entry_points{complete, source, methods[]},
                  partial_indicators[], analyzed_configurations[]
    coverage_claim kind, locus_files[], locus_symbols[], entry_methods[], declared_by
    diagnostics[] level, code, message
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Optional

from sbom_parser._common import InputSource, load_json_object, parse_timestamp, read_source
from sbom_parser.errors import ParserError

SCHEMA = "analysis-run/1"
_HEX = re.compile(r"^[0-9a-f]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_ARGUMENT = re.compile(r"(?i)(token|secret|passw(or)?d|api[-_]?key|authorization|bearer|credential)")
REDACTED = "<redacted>"
CLAIM_KIND = "locus_unreachable_from_declared_entry_points"


class AnalysisRunErrorCode(str, Enum):
    UNREADABLE = "ANALYSIS_RUN_UNREADABLE"
    MALFORMED = "ANALYSIS_RUN_MALFORMED"
    SCHEMA_UNSUPPORTED = "ANALYSIS_RUN_SCHEMA_UNSUPPORTED"
    UNKNOWN_FIELD = "ANALYSIS_RUN_UNKNOWN_FIELD"
    FORBIDDEN_FIELD = "ANALYSIS_RUN_FORBIDDEN_FIELD"
    MISSING_FIELD = "ANALYSIS_RUN_MISSING_FIELD"
    INVALID_TYPE = "ANALYSIS_RUN_INVALID_TYPE"
    INVALID_VALUE = "ANALYSIS_RUN_INVALID_VALUE"
    INCONSISTENT = "ANALYSIS_RUN_INCONSISTENT"
    SECRET_IN_COMMAND = "ANALYSIS_RUN_SECRET_IN_COMMAND"


class AnalysisRunError(ValueError):
    def __init__(self, code: AnalysisRunErrorCode, path: str, message: str) -> None:
        super().__init__(f"{code.value} at {path or '<analysis run>'}: {message}")
        self.code = code
        self.path = path
        self.message = message


class FieldSource(str, Enum):
    OBSERVED_BY_RUNNER = "observed_by_runner"
    EXTRACTED_FROM_ARTIFACT = "extracted_from_artifact"
    CALLER_SUPPLIED = "caller_supplied"
    ESTABLISHED_BY_VERIFICATION = "established_by_verification"   # never accepted from input


class StageStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    NOT_RUN = "not_run"
    UNKNOWN = "unknown"


class StageRole(str, Enum):
    EXTRACTION = "extraction"   # source extraction / database or graph construction
    ANALYSIS = "analysis"       # the query / export stage that produces the artifact
    OTHER = "other"


class RootRole(str, Enum):
    PRIMARY = "primary"     # the checkout that is the assessed source
    VENDORED = "vendored"   # separate source tree vendored into / next to the analysis
    EXTERNAL = "external"   # any other tree the analysis read


class Origin(str, Enum):
    RUNNER = "runner"
    CALLER = "caller"


class EntrySource(str, Enum):
    TOOL_ENUMERATED = "tool_enumerated"
    CALLER_DECLARED = "caller_declared"


@dataclass(frozen=True)
class ToolRecord:
    name: str
    version: Optional[str] = None
    output_format_version: Optional[str] = None
    executable_sha256: Optional[str] = None


@dataclass(frozen=True)
class SourceRoot:
    root_id: str
    path: str                       # absolute POSIX path of the analysed checkout, normalized
    role: RootRole
    repository: Optional[str] = None
    revision: Optional[str] = None


@dataclass(frozen=True)
class SubmoduleRecord:
    path: str
    revision: Optional[str]


@dataclass(frozen=True)
class SourceRecord:
    repository: Optional[str] = None
    revision: Optional[str] = None
    analysis_subpath: str = "."
    tree_digest: Optional[str] = None            # '<algorithm>:<hex>' (git-tree | sha256-worktree)
    worktree_clean: Optional[bool] = None
    untracked_files: Optional[int] = None
    submodules: Optional[tuple[SubmoduleRecord, ...]] = None
    changed_during_run: Optional[bool] = None
    roots: tuple[SourceRoot, ...] = ()


@dataclass(frozen=True)
class TargetRecord:
    purl: Optional[str] = None
    source_root: Optional[str] = None


@dataclass(frozen=True)
class QueryRecord:
    pack: Optional[str] = None
    pack_version: Optional[str] = None
    pack_digest: Optional[str] = None
    suite: Optional[str] = None
    query_ids: tuple[str, ...] = ()
    claim_semantics: Optional[str] = None


@dataclass(frozen=True)
class StageRecord:
    name: str
    role: StageRole
    status: StageStatus
    exit_code: Optional[int] = None
    started: Optional[datetime] = None
    finished: Optional[datetime] = None


@dataclass(frozen=True)
class OutputRecord:
    path: str
    sha256: Optional[str]            # None: the output was not present when the runner looked
    size: Optional[int] = None


@dataclass(frozen=True)
class FileScope:
    complete: Optional[bool] = None
    included: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()


@dataclass(frozen=True)
class EntryInventory:
    complete: Optional[bool] = None
    source: Optional[EntrySource] = None
    methods: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageClaim:
    """An author's declaration that the analysis covers a stated claim. It is an assertion (A6); it is
    consumed only by the gates of ``evidence.analysis_run_binding`` and never sets an evidence state."""

    kind: str
    locus_files: tuple[str, ...] = ()
    locus_symbols: tuple[str, ...] = ()
    entry_methods: tuple[str, ...] = ()
    declared_by: Optional[str] = None


@dataclass(frozen=True)
class RunDiagnostic:
    level: str
    code: str
    message: str


@dataclass(frozen=True)
class AnalysisRunRecord:
    run_id: str
    origin: Origin
    tool: ToolRecord
    source: SourceRecord = field(default_factory=SourceRecord)
    target: TargetRecord = field(default_factory=TargetRecord)
    languages: tuple[str, ...] = ()
    query: QueryRecord = field(default_factory=QueryRecord)
    command: tuple[str, ...] = ()
    stages: tuple[StageRecord, ...] = ()
    outputs: tuple[OutputRecord, ...] = ()
    file_scope: FileScope = field(default_factory=FileScope)
    entry_inventory: EntryInventory = field(default_factory=EntryInventory)
    partial_indicators: tuple[str, ...] = ()
    analyzed_configurations: tuple[str, ...] = ()   # deployment configurations the author says the analysis holds under (A7)
    coverage_claim: Optional[CoverageClaim] = None
    diagnostics: tuple[RunDiagnostic, ...] = ()
    field_sources: tuple[tuple[str, FieldSource], ...] = ()

    def source_of(self, group: str) -> FieldSource:
        """The stated source of a field group; the record's ``origin`` decides when none is stated."""
        for key, value in self.field_sources:
            if key == group:
                return value
        return FieldSource.OBSERVED_BY_RUNNER if self.origin is Origin.RUNNER else FieldSource.CALLER_SUPPLIED


# ---- strict loader ----------------------------------------------------------------------------------------------------------

_FORBIDDEN = frozenset({
    "verdict", "state", "states", "evidence_state", "reach", "reach_state", "bind", "bind_state", "provenance", "provenance_level",
    "ep", "prov_reach", "p2", "p3", "trust", "trusted", "verified", "signature_verified", "rules", "codes", "ceiling", "full_coverage_claim",
})
_TOP = ("schema", "run_id", "origin", "field_sources", "tool", "source", "target", "configuration", "stages", "outputs", "scope",
        "coverage_claim", "diagnostics")
FIELD_GROUPS = ("tool", "source", "target", "configuration", "stages", "outputs", "scope", "coverage_claim")


def _fail(code: AnalysisRunErrorCode, path: str, message: str) -> AnalysisRunError:
    return AnalysisRunError(code, path, message)


def _object(value: Any, path: str, allowed: tuple[str, ...]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _fail(AnalysisRunErrorCode.INVALID_TYPE, path, "expected an object")
    for key in value:
        if key in _FORBIDDEN:
            raise _fail(AnalysisRunErrorCode.FORBIDDEN_FIELD, f"{path}.{key}" if path else key,
                        "states, provenance levels, BIND results, trust statements, coverage verdicts and verdicts are derived and can never be supplied")
        if key not in allowed:
            raise _fail(AnalysisRunErrorCode.UNKNOWN_FIELD, f"{path}.{key}" if path else key, f"allowed fields: {', '.join(allowed)}")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise _fail(AnalysisRunErrorCode.INVALID_TYPE, path, "expected a non-empty string without surrounding whitespace")
    return value


def _opt_text(obj: Mapping[str, Any], key: str, path: str) -> Optional[str]:
    return _text(obj[key], f"{path}.{key}") if obj.get(key) is not None else None


def _opt_bool(obj: Mapping[str, Any], key: str, path: str) -> Optional[bool]:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise _fail(AnalysisRunErrorCode.INVALID_TYPE, f"{path}.{key}", "expected a boolean or null")
    return value


def _opt_int(obj: Mapping[str, Any], key: str, path: str, *, minimum: int = 0) -> Optional[int]:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _fail(AnalysisRunErrorCode.INVALID_TYPE, f"{path}.{key}", f"expected an integer >= {minimum} or null")
    return value


def _list(obj: Mapping[str, Any], key: str, path: str) -> list:
    value = obj.get(key, [])
    if not isinstance(value, list):
        raise _fail(AnalysisRunErrorCode.INVALID_TYPE, f"{path}.{key}", "expected an array")
    return value


def _texts(obj: Mapping[str, Any], key: str, path: str, *, unique: bool = True) -> tuple[str, ...]:
    items = tuple(_text(v, f"{path}.{key}[{i}]") for i, v in enumerate(_list(obj, key, path)))
    if unique and len(set(items)) != len(items):
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{path}.{key}", "entries must be unique")
    return items


def _hex(value: str, path: str, *, low: int, high: int) -> str:
    if not (low <= len(value) <= high) or not _HEX.match(value):
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, path, f"expected lowercase hexadecimal of {low}-{high} characters")
    return value


def _digest(value: str, path: str) -> str:
    algorithm, separator, hexdigits = value.partition(":")
    if not separator or algorithm not in ("git-tree", "sha256-worktree", "sha256"):
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, path, "expected '<git-tree|sha256-worktree|sha256>:<hex>'")
    _hex(hexdigits, path, low=40 if algorithm == "git-tree" else 64, high=64)
    return value


def _timestamp(obj: Mapping[str, Any], key: str, path: str) -> Optional[datetime]:
    if obj.get(key) is None:
        return None
    text = _text(obj[key], f"{path}.{key}")
    try:
        stamp = parse_timestamp(text, f"{path}.{key}")
    except ParserError:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{path}.{key}", f"{text!r} is not an ISO 8601 date-time") from None
    if stamp.tzinfo is None:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{path}.{key}", "a date-time needs a UTC offset")
    return stamp


def _relative(value: str, path: str) -> str:
    normalized = posixpath.normpath(value)
    if value.startswith("/") or "\\" in value or normalized in (".", "..") or normalized.startswith("../") or normalized != value:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, path, "expected a normalized relative path inside the analysed tree")
    return value


def _absolute(value: str, path: str) -> str:
    segments = value.split("/")[1:]
    ok = value.startswith("/") and "\\" not in value and "\x00" not in value and value != "/" \
        and all(segment not in ("", ".", "..") for segment in segments)
    if not ok:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, path, "expected a normalized absolute POSIX path (no '.', '..', empty segment, trailing slash or backslash)")
    return value


def parse_analysis_run(source: InputSource) -> AnalysisRunRecord:
    """Strict loader. Raises ``AnalysisRunError`` (and nothing else) for any unusable record. Pure."""
    try:
        raw = read_source(source)
    except (OSError, TypeError) as error:
        raise _fail(AnalysisRunErrorCode.UNREADABLE, "", f"cannot read the record: {error}") from None
    try:
        data = load_json_object(raw, "analysis run record")
    except ParserError as error:
        raise _fail(AnalysisRunErrorCode.MALFORMED, "", error.message) from None
    except RecursionError:
        raise _fail(AnalysisRunErrorCode.MALFORMED, "", "nested too deeply") from None
    return parse_analysis_run_data(data)


def parse_analysis_run_data(data: Any) -> AnalysisRunRecord:
    top = _object(data, "", _TOP)
    if top.get("schema") != SCHEMA:
        raise _fail(AnalysisRunErrorCode.SCHEMA_UNSUPPORTED, "schema", f"{top.get('schema')!r} is not supported (only {SCHEMA!r})")
    for key in ("run_id", "tool"):
        if key not in top:
            raise _fail(AnalysisRunErrorCode.MISSING_FIELD, key, "required")
    run_id = _text(top["run_id"], "run_id")
    try:
        origin = Origin(top.get("origin"))
    except ValueError:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, "origin", "expected 'runner' or 'caller'") from None

    sources: list[tuple[str, FieldSource]] = []
    declared = _object(top.get("field_sources", {}), "field_sources", FIELD_GROUPS)
    for group, value in declared.items():
        try:
            chosen = FieldSource(value)
        except ValueError:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"field_sources.{group}", f"{value!r} is not a field source") from None
        if chosen is FieldSource.ESTABLISHED_BY_VERIFICATION:
            raise _fail(AnalysisRunErrorCode.FORBIDDEN_FIELD, f"field_sources.{group}",
                        "only a consumed detached verification result can establish a field; a record cannot say so about itself")
        if chosen is FieldSource.OBSERVED_BY_RUNNER and origin is Origin.CALLER:
            raise _fail(AnalysisRunErrorCode.INCONSISTENT, f"field_sources.{group}", "a caller-authored record cannot claim runner observation")
        sources.append((group, chosen))

    tool_obj = _object(top["tool"], "tool", ("name", "version", "output_format_version", "executable_sha256"))
    digest = _opt_text(tool_obj, "executable_sha256", "tool")
    if digest is not None and not _SHA256.match(digest):
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, "tool.executable_sha256", "expected 64 lowercase hex characters")
    tool = ToolRecord(_text(tool_obj.get("name"), "tool.name"), _opt_text(tool_obj, "version", "tool"),
                      _opt_text(tool_obj, "output_format_version", "tool"), digest)

    src_obj = _object(top.get("source", {}), "source", ("repository", "revision", "analysis_subpath", "tree_digest", "worktree_clean",
                                                       "untracked_files", "submodules", "changed_during_run", "roots"))
    revision = _opt_text(src_obj, "revision", "source")
    if revision is not None:
        _hex(revision, "source.revision", low=7, high=64)
    tree = _opt_text(src_obj, "tree_digest", "source")
    if tree is not None:
        _digest(tree, "source.tree_digest")
    subpath = _opt_text(src_obj, "analysis_subpath", "source") or "."
    if subpath != ".":
        _relative(subpath, "source.analysis_subpath")
    submodules = None
    if src_obj.get("submodules") is not None:
        submodules = []
        for i, item in enumerate(_list(src_obj, "submodules", "source")):
            sub = _object(item, f"source.submodules[{i}]", ("path", "revision"))
            sub_rev = _opt_text(sub, "revision", f"source.submodules[{i}]")
            if sub_rev is not None:
                _hex(sub_rev, f"source.submodules[{i}].revision", low=7, high=64)
            submodules.append(SubmoduleRecord(_relative(_text(sub.get("path"), f"source.submodules[{i}].path"), f"source.submodules[{i}].path"), sub_rev))
        submodules = tuple(submodules)
    roots = []
    for i, item in enumerate(_list(src_obj, "roots", "source")):
        base = f"source.roots[{i}]"
        root = _object(item, base, ("id", "path", "role", "repository", "revision"))
        try:
            role = RootRole(root.get("role"))
        except ValueError:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{base}.role", "expected primary, vendored or external") from None
        root_rev = _opt_text(root, "revision", base)
        if root_rev is not None:
            _hex(root_rev, f"{base}.revision", low=7, high=64)
        roots.append(SourceRoot(_text(root.get("id"), f"{base}.id"), _absolute(_text(root.get("path"), f"{base}.path"), f"{base}.path"),
                                role, _opt_text(root, "repository", base), root_rev))
    _check_roots(roots)
    source_record = SourceRecord(_opt_text(src_obj, "repository", "source"), revision, subpath, tree,
                                 _opt_bool(src_obj, "worktree_clean", "source"), _opt_int(src_obj, "untracked_files", "source"),
                                 submodules, _opt_bool(src_obj, "changed_during_run", "source"), tuple(roots))

    tgt_obj = _object(top.get("target", {}), "target", ("purl", "source_root"))
    source_root = _opt_text(tgt_obj, "source_root", "target")
    if source_root is not None and source_root != ".":
        _relative(source_root, "target.source_root")
    target = TargetRecord(_opt_text(tgt_obj, "purl", "target"), source_root)

    cfg = _object(top.get("configuration", {}), "configuration", ("languages", "query", "command"))
    q_obj = _object(cfg.get("query", {}), "configuration.query", ("pack", "pack_version", "pack_digest", "suite", "query_ids", "claim_semantics"))
    pack_digest = _opt_text(q_obj, "pack_digest", "configuration.query")
    if pack_digest is not None:
        _digest(pack_digest, "configuration.query.pack_digest")
    query = QueryRecord(_opt_text(q_obj, "pack", "configuration.query"), _opt_text(q_obj, "pack_version", "configuration.query"), pack_digest,
                        _opt_text(q_obj, "suite", "configuration.query"), _texts(q_obj, "query_ids", "configuration.query"),
                        _opt_text(q_obj, "claim_semantics", "configuration.query"))
    command = _texts(cfg, "command", "configuration", unique=False)
    for i, argument in enumerate(command):
        if _SECRET_ARGUMENT.search(argument) and REDACTED not in argument and "=" in argument:
            raise _fail(AnalysisRunErrorCode.SECRET_IN_COMMAND, f"configuration.command[{i}]", "a command argument that looks like a credential must be redacted")
    stages = []
    seen_names: set[str] = set()
    for i, item in enumerate(_list(top, "stages", "")):
        base = f"stages[{i}]"
        stage = _object(item, base, ("name", "role", "status", "exit_code", "started", "finished"))
        name = _text(stage.get("name"), f"{base}.name")
        if name in seen_names:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{base}.name", "stage names must be unique")
        seen_names.add(name)
        try:
            role, status = StageRole(stage.get("role")), StageStatus(stage.get("status"))
        except ValueError:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, base, "role must be extraction|analysis|other and status completed|failed|timed_out|not_run|unknown") from None
        code = stage.get("exit_code")
        if code is not None and (not isinstance(code, int) or isinstance(code, bool)):
            raise _fail(AnalysisRunErrorCode.INVALID_TYPE, f"{base}.exit_code", "expected an integer or null")
        started, finished = _timestamp(stage, "started", base), _timestamp(stage, "finished", base)
        if started and finished and finished < started:
            raise _fail(AnalysisRunErrorCode.INCONSISTENT, base, "finished is before started")
        if status is StageStatus.COMPLETED and code not in (None, 0):
            raise _fail(AnalysisRunErrorCode.INCONSISTENT, base, "a completed stage cannot have a non-zero exit code")
        if status in (StageStatus.FAILED,) and code == 0:
            raise _fail(AnalysisRunErrorCode.INCONSISTENT, base, "a failed stage cannot have exit code 0")
        stages.append(StageRecord(name, role, status, code, started, finished))

    outputs = []
    seen_paths: set[str] = set()
    for i, item in enumerate(_list(top, "outputs", "")):
        base = f"outputs[{i}]"
        out = _object(item, base, ("path", "sha256", "size"))
        path = _text(out.get("path"), f"{base}.path")
        if path in seen_paths:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{base}.path", "output paths must be unique")
        seen_paths.add(path)
        sha = _opt_text(out, "sha256", base)
        if sha is not None and not _SHA256.match(sha):
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"{base}.sha256", "expected 64 lowercase hex characters, or null for an output that was not present")
        outputs.append(OutputRecord(path, sha, _opt_int(out, "size", base)))

    scope = _object(top.get("scope", {}), "scope", ("files", "entry_points", "partial_indicators", "analyzed_configurations"))
    files_obj = _object(scope.get("files", {}), "scope.files", ("complete", "included", "excluded"))
    entry_obj = _object(scope.get("entry_points", {}), "scope.entry_points", ("complete", "source", "methods"))
    try:
        entry_source = EntrySource(entry_obj["source"]) if entry_obj.get("source") is not None else None
    except ValueError:
        raise _fail(AnalysisRunErrorCode.INVALID_VALUE, "scope.entry_points.source", "expected tool_enumerated or caller_declared") from None
    included = _texts(files_obj, "included", "scope.files")
    excluded = _texts(files_obj, "excluded", "scope.files")
    for n, item in enumerate(included):
        _relative(item, f"scope.files.included[{n}]")
    for n, item in enumerate(excluded):
        _relative(item, f"scope.files.excluded[{n}]")
    file_scope = FileScope(_opt_bool(files_obj, "complete", "scope.files"), included, excluded)
    inventory = EntryInventory(_opt_bool(entry_obj, "complete", "scope.entry_points"), entry_source, _texts(entry_obj, "methods", "scope.entry_points"))

    claim = None
    if top.get("coverage_claim") is not None:
        c = _object(top["coverage_claim"], "coverage_claim", ("kind", "locus_files", "locus_symbols", "entry_methods", "declared_by"))
        kind = _text(c.get("kind"), "coverage_claim.kind")
        if kind != CLAIM_KIND:
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, "coverage_claim.kind", f"only {CLAIM_KIND!r} is defined")
        claim = CoverageClaim(kind, _texts(c, "locus_files", "coverage_claim"), _texts(c, "locus_symbols", "coverage_claim"),
                              _texts(c, "entry_methods", "coverage_claim"), _opt_text(c, "declared_by", "coverage_claim"))

    diagnostics = []
    for i, item in enumerate(_list(top, "diagnostics", "")):
        d = _object(item, f"diagnostics[{i}]", ("level", "code", "message"))
        level = _text(d.get("level"), f"diagnostics[{i}].level")
        if level not in ("note", "warning", "error"):
            raise _fail(AnalysisRunErrorCode.INVALID_VALUE, f"diagnostics[{i}].level", "expected note, warning or error")
        diagnostics.append(RunDiagnostic(level, _text(d.get("code"), f"diagnostics[{i}].code"), _text(d.get("message"), f"diagnostics[{i}].message")))

    return AnalysisRunRecord(
        run_id=run_id, origin=origin, tool=tool, source=source_record, target=target,
        languages=_texts(cfg, "languages", "configuration"), query=query, command=command, stages=tuple(stages), outputs=tuple(outputs),
        file_scope=file_scope, entry_inventory=inventory, partial_indicators=_texts(scope, "partial_indicators", "scope"),
        analyzed_configurations=_texts(scope, "analyzed_configurations", "scope"),
        coverage_claim=claim, diagnostics=tuple(diagnostics), field_sources=tuple(sorted(sources)),
    )


def _check_roots(roots: list[SourceRoot]) -> None:
    ids = [r.root_id for r in roots]
    if len(set(ids)) != len(ids):
        raise _fail(AnalysisRunErrorCode.INCONSISTENT, "source.roots", "root ids must be unique")
    if sum(r.role is RootRole.PRIMARY for r in roots) > 1:
        raise _fail(AnalysisRunErrorCode.INCONSISTENT, "source.roots", "at most one root can be the primary (assessed) source")
    for i, a in enumerate(roots):
        for b in roots[i + 1:]:
            pa, pb = a.path.rstrip("/") + "/", b.path.rstrip("/") + "/"
            if pa.startswith(pb) or pb.startswith(pa):
                raise _fail(AnalysisRunErrorCode.INCONSISTENT, "source.roots",
                            f"roots {a.root_id!r} and {b.root_id!r} overlap: one file would have two identities")


# ---- canonical serialization -----------------------------------------------------------------------------------------------------

def _stamp(value: Optional[datetime]) -> Optional[str]:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def record_to_dict(record: AnalysisRunRecord) -> dict:
    """The record as a plain dict; ``parse_analysis_run_data(record_to_dict(r)) == r`` (a tested fixpoint)."""
    s = record.source
    data: dict[str, Any] = {
        "schema": SCHEMA, "run_id": record.run_id, "origin": record.origin.value,
        "field_sources": {k: v.value for k, v in record.field_sources},
        "tool": {"name": record.tool.name, "version": record.tool.version, "output_format_version": record.tool.output_format_version,
                 "executable_sha256": record.tool.executable_sha256},
        "source": {"repository": s.repository, "revision": s.revision, "analysis_subpath": s.analysis_subpath, "tree_digest": s.tree_digest,
                   "worktree_clean": s.worktree_clean, "untracked_files": s.untracked_files,
                   "submodules": None if s.submodules is None else [{"path": m.path, "revision": m.revision} for m in s.submodules],
                   "changed_during_run": s.changed_during_run,
                   "roots": [{"id": r.root_id, "path": r.path, "role": r.role.value, "repository": r.repository, "revision": r.revision} for r in s.roots]},
        "target": {"purl": record.target.purl, "source_root": record.target.source_root},
        "configuration": {"languages": list(record.languages), "command": list(record.command),
                          "query": {"pack": record.query.pack, "pack_version": record.query.pack_version, "pack_digest": record.query.pack_digest,
                                    "suite": record.query.suite, "query_ids": list(record.query.query_ids),
                                    "claim_semantics": record.query.claim_semantics}},
        "stages": [{"name": t.name, "role": t.role.value, "status": t.status.value, "exit_code": t.exit_code,
                    "started": _stamp(t.started), "finished": _stamp(t.finished)} for t in record.stages],
        "outputs": [{"path": o.path, "sha256": o.sha256, "size": o.size} for o in record.outputs],
        "scope": {"files": {"complete": record.file_scope.complete, "included": list(record.file_scope.included),
                            "excluded": list(record.file_scope.excluded)},
                  "entry_points": {"complete": record.entry_inventory.complete,
                                   "source": record.entry_inventory.source.value if record.entry_inventory.source else None,
                                   "methods": list(record.entry_inventory.methods)},
                  "partial_indicators": list(record.partial_indicators), "analyzed_configurations": list(record.analyzed_configurations)},
        "coverage_claim": None if record.coverage_claim is None else {
            "kind": record.coverage_claim.kind, "locus_files": list(record.coverage_claim.locus_files),
            "locus_symbols": list(record.coverage_claim.locus_symbols), "entry_methods": list(record.coverage_claim.entry_methods),
            "declared_by": record.coverage_claim.declared_by},
        "diagnostics": [{"level": d.level, "code": d.code, "message": d.message} for d in record.diagnostics],
    }
    return data


def dump_analysis_run(record: AnalysisRunRecord) -> str:
    """Deterministic JSON text: sorted keys, fixed separators, UTF-8 characters kept, trailing newline."""
    return json.dumps(record_to_dict(record), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
