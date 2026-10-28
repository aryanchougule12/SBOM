"""SARIF 2.1.0 adapter (raw format parsing and structural validation only).

Consumes the Static Analysis Results Interchange Format, version 2.1.0 (OASIS Standard; the
official JSON schema ``sarif-schema-2.1.0.json`` is vendored under ``third_party/`` and the test
suite validates every SARIF fixture against it). CodeQL writes this format; this module relies on
no CodeQL-specific field.

What is consumed, and why (every field was checked against the official schema):

* ``version`` must be exactly ``"2.1.0"``; ``runs[]`` is required.
* ``runs[].tool.driver``: ``name`` (required by the schema), ``semanticVersion`` else ``version``
  (tool identity for P1 attribution), ``organization``.
* ``runs[].invocations[]``: ``executionSuccessful`` (required by the schema), ``startTimeUtc``
  (the document's ``created``), ``toolExecutionNotifications[].level``. Recorded as *claims about
  the run*, never as proof of coverage.
* ``runs[].versionControlProvenance[]``: ``repositoryUri`` (required), ``revisionId``, ``branch``,
  ``revisionTag``: the only SARIF fields that can identify the analysed source revision.
* ``runs[].artifacts[].location`` and ``artifactLocation.index``: resolving ``index`` references.
* ``runs[].results[]``: ``kind`` (default ``fail``), ``baselineState``, ``suppressions``,
  ``ruleId`` and, for path evidence, ``codeFlows[].threadFlows[].locations[].location
  .physicalLocation.artifactLocation`` and ``region.startLine``.

What is deliberately **not** consumed as path evidence: a result's own ``locations`` (where a
problem was reported, not a path), ``level``, ``message`` text, ``relatedLocations``, ``stacks``,
``graphs`` and the empty/non-empty state of ``results``. A SARIF log with no results, or results
without code flows, records that the tool reported nothing for its queries; it is not a statement
about the vulnerable code. Nothing here yields a "no path" fact.

Structural errors (wrong ``version``, wrong types in consumed fields, an ``index`` outside
``run.artifacts``, an ``index`` contradicting an explicit ``uri``) raise
``AnalysisArtifactError`` with a stable code and a locator; the artifact is then unusable and the
pipeline refuses instead of guessing.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, Mapping, Optional

from evidence.analysis_model import (
    AnalysisArtifactError,
    AnalysisArtifactErrorCode as E,
    AnalysisDiagnostic,
    AnalysisFormat,
    FlowCandidate,
    NormalizedAnalysis,
    PathStep,
    RunFacts,
    SourceArtifactIdentity,
    ToolIdentity,
    VcsProvenance,
)
from sbom_parser._common import document_id, load_json_object, parse_timestamp, ptr
from sbom_parser.errors import MalformedInputError, ParserError

SUPPORTED_VERSION = "2.1.0"
#: ``uriBaseId`` values read as "relative to the analysis root" (CodeQL writes ``%SRCROOT%``).
ROOT_BASE_IDS = frozenset({None, "%SRCROOT%", "SRCROOT"})
#: ``result.kind`` values that report a finding; ``pass``, ``notApplicable`` and ``informational`` do not.
FINDING_KINDS = frozenset({"fail", "review", "open"})
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


def _invalid(message: str, locator: str) -> AnalysisArtifactError:
    return AnalysisArtifactError(E.STRUCTURE_INVALID, message, locator)


def _obj(value: Any, locator: str, what: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _invalid(f"{what} must be an object", locator)
    return value


def _list(parent: Mapping[str, Any], key: str, locator: str) -> list:
    if key not in parent:
        return []
    value = parent[key]
    if not isinstance(value, list):
        raise _invalid(f"{key} must be an array", f"{locator}/{key}")
    return value


def _opt_str(parent: Mapping[str, Any], key: str, locator: str) -> Optional[str]:
    if key not in parent:
        return None
    if not isinstance(parent[key], str):
        raise _invalid(f"{key} must be a string", f"{locator}/{key}")
    return parent[key]


def percent_decode(text: str) -> Optional[str]:
    """Decode ``%XX`` escapes as UTF-8; ``None`` if the result is not valid UTF-8."""
    pieces: list[bytes] = []
    position = 0
    for match in _PERCENT.finditer(text):
        pieces.append(text[position:match.start()].encode("utf-8"))
        pieces.append(bytes.fromhex(match.group(1)))
        position = match.end()
    pieces.append(text[position:].encode("utf-8"))
    try:
        return b"".join(pieces).decode("utf-8")
    except UnicodeDecodeError:
        return None


def normalize_relative_path(uri: str, base_id: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """``(path, None)`` for an analysis-root-relative path, else ``(None, reason)``.

    A location is only comparable when it is a relative URI reference against the analysis root:
    an absolute URI, a rooted path, a backslash, an unknown ``uriBaseId`` or a path that escapes the
    root is **unresolved**, never guessed (and never matched on its file name alone)."""
    if base_id not in ROOT_BASE_IDS:
        return None, f"uriBaseId {base_id!r} is not the analysis root"
    if not uri:
        return None, "empty uri"
    if _SCHEME.match(uri):
        return None, "absolute uri"
    decoded = percent_decode(uri)
    if decoded is None:
        return None, "uri is not valid UTF-8 after percent-decoding"
    if decoded.startswith("/") or "\\" in decoded:
        return None, "rooted or backslash path"
    normalized = posixpath.normpath(decoded)
    if normalized in (".", "") or normalized == ".." or normalized.startswith("../"):
        return None, "path is empty or escapes the analysis root"
    return normalized, None


def _location_key(location: Mapping[str, Any], locator: str) -> tuple[Optional[str], Optional[str], Optional[int]]:
    uri = _opt_str(location, "uri", locator)
    base = _opt_str(location, "uriBaseId", locator)
    index = location.get("index")
    if index is not None and (not isinstance(index, int) or isinstance(index, bool)):
        raise _invalid("index must be an integer", f"{locator}/index")
    return uri, base, index


_AUTHORITY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/]*")
_DRIVE = re.compile(r"^[A-Za-z]:(?=/)")
_OTHER_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def loose_path(uri: Optional[str]) -> Optional[str]:
    """The path a URI reference spells, with any scheme, authority and drive letter removed and the
    separators normalized, but **not** anchored to the analysis root (leading ``..`` segments are
    kept). It is used only to decide whether an unresolved location could possibly be a given file;
    it is never evidence that it is. ``None`` for a missing or empty URI."""
    if uri is None or not uri.strip():
        return None
    text = (percent_decode(uri) or uri).replace("\\", "/")
    text = _AUTHORITY.sub("", text)
    text = _DRIVE.sub("", text)
    text = _OTHER_SCHEME.sub("", text)
    normalized = posixpath.normpath(text) if text else "."
    return None if normalized in (".", "") else normalized


def resolve_location_detail(
    location: Any, artifacts: list, locator: str
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Like ``resolve_artifact_location`` but also returns the ``loose_path`` of the location (for an
    unresolved one, so that its relevance can still be judged)."""
    loc = _obj(location, locator, "artifactLocation")
    uri, base, index = _location_key(loc, locator)
    if index is not None and index >= 0:
        if index >= len(artifacts):
            raise AnalysisArtifactError(E.REFERENCE_UNRESOLVED,
                                        f"artifactLocation.index {index} is outside run.artifacts ({len(artifacts)})", f"{locator}/index")
        indexed = _obj(artifacts[index], f"{locator}/index", "artifact")
        target = _obj(indexed.get("location", {}), f"{locator}/index", "artifact.location")
        t_uri, t_base, _ = _location_key(target, f"{locator}/index")
        if uri is not None and t_uri is not None and (uri, base) != (t_uri, t_base):
            raise AnalysisArtifactError(E.CONTRADICTORY,
                                        f"artifactLocation ({uri!r}) contradicts run.artifacts[{index}] ({t_uri!r})", locator)
        if uri is None:
            uri, base = t_uri, t_base
    if uri is None:
        return None, "no uri and no resolvable index", None
    path, reason = normalize_relative_path(uri, base)
    return path, reason, loose_path(uri)


def resolve_artifact_location(
    location: Any, artifacts: list, locator: str
) -> tuple[Optional[str], Optional[str]]:
    """Resolve an ``artifactLocation`` (``uri`` and/or ``index`` into ``run.artifacts``) to a
    normalized path, or ``(None, reason)``. An ``index`` outside ``run.artifacts`` is a
    ``REFERENCE_UNRESOLVED`` error; an ``index`` whose artifact disagrees with an explicit ``uri``
    is a ``CONTRADICTORY`` error."""
    path, reason, _ = resolve_location_detail(location, artifacts, locator)
    return path, reason


def _tool(run: Mapping[str, Any], locator: str) -> ToolIdentity:
    tool = _obj(run.get("tool"), f"{locator}/tool", "tool")
    driver = _obj(tool.get("driver"), f"{locator}/tool/driver", "tool.driver")
    name = _opt_str(driver, "name", f"{locator}/tool/driver")
    if name is None:
        raise _invalid("tool.driver.name is required", f"{locator}/tool/driver/name")
    semantic = _opt_str(driver, "semanticVersion", f"{locator}/tool/driver")
    plain = _opt_str(driver, "version", f"{locator}/tool/driver")
    version, field = (semantic, "semanticVersion") if semantic and semantic.strip() else \
                     (plain, "version") if plain and plain.strip() else (None, None)
    return ToolIdentity(name=name or None, version=version, version_field=field,
                        organization=_opt_str(driver, "organization", f"{locator}/tool/driver"))


def _invocations(run: Mapping[str, Any], locator: str, diagnostics: list[AnalysisDiagnostic]):
    invocations = _list(run, "invocations", locator)
    successes, errors, warnings, started = [], 0, 0, []
    for i, raw in enumerate(invocations):
        here = f"{locator}/invocations/{i}"
        invocation = _obj(raw, here, "invocation")
        if not isinstance(invocation.get("executionSuccessful"), bool):
            raise _invalid("executionSuccessful is required and must be a boolean", f"{here}/executionSuccessful")
        successes.append(invocation["executionSuccessful"])
        if "startTimeUtc" in invocation:
            text = _opt_str(invocation, "startTimeUtc", here)
            try:
                started.append(parse_timestamp(text or "", f"{here}/startTimeUtc"))
            except ParserError as error:
                raise AnalysisArtifactError.from_parser_error(error, E.STRUCTURE_INVALID) from None
        for n, note in enumerate(_list(invocation, "toolExecutionNotifications", here)):
            level = _opt_str(_obj(note, f"{here}/toolExecutionNotifications/{n}", "notification"), "level",
                             f"{here}/toolExecutionNotifications/{n}") or "warning"
            if level not in ("none", "note", "warning", "error"):
                raise _invalid(f"notification level {level!r} is not a SARIF level", f"{here}/toolExecutionNotifications/{n}/level")
            if level == "error":
                errors += 1
            elif level == "warning":
                warnings += 1
    if len(invocations) > 1:
        diagnostics.append(AnalysisDiagnostic("MULTIPLE_INVOCATIONS",
                                              f"{len(invocations)} invocations: no single start time is chosen", f"{locator}/invocations"))
    return (all(successes) if successes else None), errors, warnings, (started[0] if len(started) == 1 and len(invocations) == 1 else None)


def _vcs(run: Mapping[str, Any], locator: str) -> tuple[VcsProvenance, ...]:
    found = []
    for i, raw in enumerate(_list(run, "versionControlProvenance", locator)):
        here = f"{locator}/versionControlProvenance/{i}"
        entry = _obj(raw, here, "versionControlDetails")
        uri = _opt_str(entry, "repositoryUri", here)
        if not uri:
            raise _invalid("repositoryUri is required", f"{here}/repositoryUri")
        found.append(VcsProvenance(uri, _opt_str(entry, "revisionId", here), _opt_str(entry, "branch", here),
                                   _opt_str(entry, "revisionTag", here), here))
    return tuple(found)


def _is_suppressed(result: Mapping[str, Any], locator: str) -> bool:
    return bool(_list(result, "suppressions", locator))


def parse_sarif(raw: bytes) -> NormalizedAnalysis:
    """Parse and structurally validate a SARIF 2.1.0 log. Pure; ``raw`` is not modified."""
    try:
        log = load_json_object(raw, "SARIF")
    except MalformedInputError as error:
        raise AnalysisArtifactError.from_parser_error(error, E.MALFORMED) from None
    version = log.get("version")
    if version != SUPPORTED_VERSION:
        raise AnalysisArtifactError(E.FORMAT_VERSION_UNSUPPORTED,
                                    f"SARIF version {version!r} is not supported (only {SUPPORTED_VERSION!r})", "#/version")
    runs_raw = log.get("runs")
    if not isinstance(runs_raw, list):
        raise _invalid("runs is required and must be an array", "#/runs")

    diagnostics: list[AnalysisDiagnostic] = []
    runs: list[RunFacts] = []
    candidates: list[FlowCandidate] = []
    no_flow = ignored = 0
    for ri, run_raw in enumerate(runs_raw):
        here = ptr("runs", ri)
        run = _obj(run_raw, here, "run")
        tool = _tool(run, here)
        artifacts = _list(run, "artifacts", here)
        for ai, artifact in enumerate(artifacts):
            _obj(artifact, f"{here}/artifacts/{ai}", "artifact")
        successful, errors, warnings, started = _invocations(run, here, diagnostics)
        results = _list(run, "results", here)
        if "results" not in run:
            diagnostics.append(AnalysisDiagnostic(
                "RUN_WITHOUT_RESULTS_ARRAY", "no `results` array: SARIF allows this only for a run that exports rule metadata, "
                "not an actual scan; it records nothing about the analysed code", f"{here}/results"))
        runs.append(RunFacts(locator=here, tool=tool, started=started, execution_successful=successful,
                             error_notifications=errors, warning_notifications=warnings, vcs=_vcs(run, here),
                             result_count=len(results), results_present="results" in run))
        for xi, result_raw in enumerate(results):
            rloc = f"{here}/results/{xi}"
            result = _obj(result_raw, rloc, "result")
            kind = _opt_str(result, "kind", rloc) or "fail"
            if kind not in {"notApplicable", "pass", "fail", "review", "open", "informational"}:
                raise _invalid(f"result.kind {kind!r} is not a SARIF kind", f"{rloc}/kind")
            baseline = _opt_str(result, "baselineState", rloc)
            if kind not in FINDING_KINDS or baseline == "absent":
                ignored += 1
                diagnostics.append(AnalysisDiagnostic(
                    "RESULT_NOT_A_CURRENT_FINDING", f"kind={kind!r} baselineState={baseline!r}: not consumed as a path", rloc))
                continue
            flows = _list(result, "codeFlows", rloc)
            if not flows:
                no_flow += 1
                continue
            suppressed = _is_suppressed(result, rloc)
            for ci, flow_raw in enumerate(flows):
                cloc = f"{rloc}/codeFlows/{ci}"
                flow = _obj(flow_raw, cloc, "codeFlow")
                thread_flows = _list(flow, "threadFlows", cloc)
                if not thread_flows:
                    raise _invalid("a codeFlow needs at least one threadFlow", f"{cloc}/threadFlows")
                for ti, thread_raw in enumerate(thread_flows):
                    tloc = f"{cloc}/threadFlows/{ti}"
                    thread = _obj(thread_raw, tloc, "threadFlow")
                    locations = _list(thread, "locations", tloc)
                    if not locations:
                        raise _invalid("a threadFlow needs at least one location", f"{tloc}/locations")
                    steps = []
                    for li, step_raw in enumerate(locations):
                        sloc = f"{tloc}/locations/{li}"
                        step = _obj(step_raw, sloc, "threadFlowLocation")
                        kinds = step.get("kinds", [])
                        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
                            raise _invalid("kinds must be an array of strings", f"{sloc}/kinds")
                        location = _obj(step.get("location", {}), f"{sloc}/location", "location")
                        physical = location.get("physicalLocation")
                        if physical is None:
                            steps.append(PathStep(f"{sloc}/location", None, "no physicalLocation", kinds=tuple(kinds)))
                            continue
                        physical = _obj(physical, f"{sloc}/location/physicalLocation", "physicalLocation")
                        if "artifactLocation" not in physical:
                            steps.append(PathStep(f"{sloc}/location", None, "no artifactLocation", kinds=tuple(kinds)))
                            continue
                        path, reason, loose = resolve_location_detail(
                            physical["artifactLocation"], artifacts, f"{sloc}/location/physicalLocation/artifactLocation")
                        region = physical.get("region")
                        line = region.get("startLine") if isinstance(region, dict) and isinstance(region.get("startLine"), int) else None
                        steps.append(PathStep(f"{sloc}/location", path, reason, line, loose, tuple(kinds)))
                    candidates.append(FlowCandidate(
                        candidate_id=f"r{ri}.x{xi}.c{ci}.t{ti}", locator=tloc,
                        run_index=ri, rule_id=_opt_str(result, "ruleId", rloc), steps=tuple(steps),
                        suppressed=suppressed, result_locator=rloc))
    if not runs:
        diagnostics.append(AnalysisDiagnostic("NO_RUNS", "the log contains no runs", "#/runs"))
    return NormalizedAnalysis(
        source=SourceArtifactIdentity(document_id("sarif", raw), AnalysisFormat.SARIF, SUPPORTED_VERSION, len(raw)),
        runs=tuple(runs), candidates=tuple(candidates), call_graph=None,
        diagnostics=tuple(diagnostics), results_without_flow=no_flow, ignored_results=ignored,
    )
