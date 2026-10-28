"""Subject binding and derivation of reachability evidence from a ``NormalizedAnalysis``.

This is where a parsed artifact is related to the finding under assessment. It converts neutral
facts into at most **one** strict-input ``ReachDocument`` (kind K1, finding ``positive``) per
artifact, and only when the artifact records a path that touches the declared vulnerable-code
locus. It never produces a negative, incomplete, ambiguous or absent fact, and it sets no evidence
state, provenance level or verdict: the existing derivation (``evidence.reach_derivation``) and
rules (``evidence.reach_rules``) do that.

Why only positives. The specification's REACH ``Absent`` needs a K1 report with a *declared
full-coverage claim over LOCUS and ENTRY* (§5.1 step 2). Neither SARIF nor a CPG export states
such a claim; a run's ``executionSuccessful``, an empty ``results`` array or a graph without a path
to the locus are statements about what a tool reported, not about coverage, and the formal rules
define no way to consume them as absence. They are kept as limitations and diagnostics and the
evidence stays ``Unknown``. A positive observation, by contrast, can only lower a verdict (§5.1 step
1, M-4), so deriving it never violates P-3.

The ``AnalysisSubject`` is an evaluator-entered, unauthenticated statement (like the profile's INV
assertions); ``entered_by`` is a label and is never used in a decision. It supplies what the
formats cannot: which source revision / source hash the evaluator links to the assessed artifact S,
which component is the target, where that component's sources live inside the analysed tree and,
for call graphs, the entry methods. Binding is therefore explicit and conservative:

* **SARIF** is bound only when a ``versionControlProvenance`` entry of every contributing run has
  the same repository and the same ``revisionId`` as the subject (exact comparison after trimming
  and lower-casing the revision; abbreviated revisions are different values). No revision in the
  subject, no provenance in the run, a different repository or revision, or conflicting entries are
  *blockers*: the document is still produced (a path observed in unbound analysis can only lower
  the verdict) but its BIND is Unknown (R6).
* **Joern GraphML** is bound only when the subject's ``source_content_hash`` equals the META_DATA
  ``HASH`` claim; the CPG schema does not specify the hash algorithm, so this is equality of two
  declared strings and nothing more.
* The document's ``artifact`` is the subject's artifact (purl and version, **never hashes**), so the
  existing B2-B5 comparison with S can match only by product/version (P1 at most): a derived
  document can never be P2. P3 can only come from a trusted detached verification result for the
  raw artifact's content-derived ``doc_id``, inside its established coverage of the item locators.
* Matching the locus is exact: SARIF flows must touch ``<target_source_root>/<locus file>`` (a file
  name alone, an absolute URI, an unknown ``uriBaseId`` or a path escaping the root never matches);
  call graphs must reach a ``METHOD`` whose ``FULL_NAME`` equals a locus symbol exactly. The target
  component's identity is compared with the finding's component by the existing reachability BIND.

The evaluator-asserted link between the analysed source revision and the assessed artifact is
always listed as a limitation (``SOURCE_TO_ARTIFACT_LINK_EVALUATOR_ASSERTED``).
"""

from __future__ import annotations

import posixpath
from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from evidence.analysis_model import (
    AnalysisDiagnostic,
    AnalysisFormat,
    CallEdge,
    FlowCandidate,
    MethodNode,
    NormalizedAnalysis,
    ObservationTrace,
    RunFacts,
    SourceRef,
    ToolIdentity,
)
from evidence.analysis_sarif import normalize_relative_path
from evidence.reach_inputs import LocusInput, ReachDocument, ReachFinding, ReachKind, TargetRef
from model import Component
from sbom_parser.identifiers import build_identifier_variants

LINK_LIMITATION = ("SOURCE_TO_ARTIFACT_LINK_EVALUATOR_ASSERTED: that the assessed artifact was built from the analysed source "
                   "is an unauthenticated evaluator statement, not something the artifact establishes")
NO_NEGATIVE_LIMITATION = ("NO_ABSENCE_EVIDENCE: this artifact type states no coverage claim over LOCUS and ENTRY (§5.1 step 2), "
                          "so no absence or incomplete-analysis fact is derived from it; REACH stays Unknown unless a path is recorded")
COMPLETION_LIMITATION = ("RUN_STATUS_RECORDED_AS_CLAIMED: the tool's own success status, notifications and result counts are "
                         "recorded, never read as proof of complete coverage")
UNRESOLVED_LIMITATION = ("UNRESOLVED_LOCATIONS_NOT_MATCHED: locations that could not be resolved to the analysis root are never "
                         "matched, so a path through them would not be seen")


class AnalysisSubjectError(ValueError):
    """The evaluator's analysis subject is invalid; ``path`` locates the field."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path or '<subject>'}: {message}")
        self.path = path
        self.message = message


@dataclass(frozen=True)
class ArtifactRef:
    purl: str
    version: Optional[str] = None


@dataclass(frozen=True)
class AnalysisSubject:
    """What the evaluator asserts about the analysed source (unauthenticated; see the module docstring)."""

    artifact: ArtifactRef
    target: TargetRef
    entered_by: str
    source_repository: Optional[str] = None
    source_revision: Optional[str] = None
    source_content_hash: Optional[str] = None
    target_source_root: Optional[str] = None
    entry_methods: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, ArtifactRef) or not self.artifact.purl.strip():
            raise AnalysisSubjectError("artifact", "an artifact purl is required")
        if not isinstance(self.target, TargetRef) or not (self.target.purl or (self.target.name and self.target.version)):
            raise AnalysisSubjectError("target", "a target needs a purl, or a name and a version")
        if not self.entered_by.strip():
            raise AnalysisSubjectError("entered_by", "required (an unverified label)")
        if self.source_revision is not None and not self.source_repository:
            raise AnalysisSubjectError("source_repository", "a source_revision needs its source_repository")
        if self.target_source_root is not None and self.target_source_root != ".":
            normalized, reason = normalize_relative_path(self.target_source_root, None)
            if normalized is None or normalized != self.target_source_root:
                raise AnalysisSubjectError("target_source_root",
                                           f"must be '.' or a normalized relative path ({reason or 'not normalized'})")
        if len(set(self.entry_methods)) != len(self.entry_methods) or any(not m.strip() for m in self.entry_methods):
            raise AnalysisSubjectError("entry_methods", "entries must be unique non-empty strings")


_SUBJECT_KEYS = ("artifact", "target", "entered_by", "source_repository", "source_revision", "source_content_hash",
                 "target_source_root", "entry_methods")


def parse_analysis_subject(data: Mapping[str, Any]) -> AnalysisSubject:
    """Strict loader. Unknown fields are errors; derived values can not be supplied."""
    if not isinstance(data, dict):
        raise AnalysisSubjectError("", "expected an object")
    for key in data:
        if key not in _SUBJECT_KEYS:
            raise AnalysisSubjectError(key, f"unknown field; allowed: {', '.join(_SUBJECT_KEYS)}")

    def text(key: str, container: Mapping[str, Any] = data, prefix: str = "") -> Optional[str]:
        if key not in container:
            return None
        if not isinstance(container[key], str) or not container[key].strip():
            raise AnalysisSubjectError(prefix + key, "expected a non-empty string")
        return container[key]

    artifact = data.get("artifact")
    target = data.get("target")
    if not isinstance(artifact, dict) or set(artifact) - {"purl", "version"} or not text("purl", artifact, "artifact."):
        raise AnalysisSubjectError("artifact", "expected an object with 'purl' and optional 'version'")
    if not isinstance(target, dict) or set(target) - {"purl", "name", "version"}:
        raise AnalysisSubjectError("target", "expected an object with 'purl' or 'name' and 'version'")
    methods = data.get("entry_methods", [])
    if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
        raise AnalysisSubjectError("entry_methods", "expected an array of strings")
    return AnalysisSubject(
        artifact=ArtifactRef(artifact["purl"], text("version", artifact, "artifact.")),
        target=TargetRef(text("purl", target, "target."), text("name", target, "target."), text("version", target, "target.")),
        entered_by=text("entered_by") or "",
        source_repository=text("source_repository"), source_revision=text("source_revision"),
        source_content_hash=text("source_content_hash"), target_source_root=text("target_source_root"),
        entry_methods=tuple(methods),
    )


@dataclass(frozen=True)
class DerivedEvidence:
    """Result of deriving evidence from one artifact. ``document`` is ``None`` when no path
    touching the locus is recorded; ``source`` is always present and records what was found and why."""

    document: Optional[ReachDocument]
    source: SourceRef


def _norm_repo(uri: str) -> str:
    text = uri.strip().lower().rstrip("/")
    return text[:-4] if text.endswith(".git") else text


def _norm_rev(revision: Optional[str]) -> Optional[str]:
    return revision.strip().lower() if revision and revision.strip() else None


def _sarif_blockers(runs: list[RunFacts], subject: AnalysisSubject) -> list[str]:
    blockers: list[str] = []
    if subject.source_revision is None:
        return ["SUBJECT_REVISION_NOT_DECLARED"]
    wanted_repo, wanted_rev = _norm_repo(subject.source_repository or ""), _norm_rev(subject.source_revision)
    for run in runs:
        same_repo = [v for v in run.vcs if _norm_repo(v.repository_uri) == wanted_repo]
        if not run.vcs:
            blockers.append(f"RUN_REVISION_UNKNOWN:{run.locator}")
        elif not same_repo:
            blockers.append(f"REPOSITORY_MISMATCH:{run.locator}")
        else:
            revisions = {_norm_rev(v.revision_id) for v in same_repo}
            if len(revisions) > 1:
                blockers.append(f"REVISION_AMBIGUOUS:{run.locator}")
            elif revisions == {None}:
                blockers.append(f"RUN_REVISION_UNKNOWN:{run.locator}")
            elif revisions != {wanted_rev}:
                blockers.append(f"REVISION_MISMATCH:{run.locator}")
    return blockers


def _join(root: str, path: str) -> str:
    return path if root == "." else posixpath.join(root, path)


def _tool_for(runs: list[RunFacts]) -> tuple[Optional[ToolIdentity], list[str]]:
    tools = list(dict.fromkeys(run.tool for run in runs))
    if len(tools) == 1:
        return tools[0], []
    return None, ([f"TOOL_IDENTITY_AMBIGUOUS: {len(tools)} different tool identities among the contributing runs; the document is unattributed"]
                  if tools else [])


def _run_limitations(runs: list[RunFacts]) -> list[str]:
    notes = [COMPLETION_LIMITATION]
    for run in runs:
        if run.execution_successful is False:
            notes.append(f"RUN_REPORTS_UNSUCCESSFUL_EXECUTION:{run.locator}")
        if run.error_notifications:
            notes.append(f"RUN_HAS_ERROR_NOTIFICATIONS:{run.locator}:{run.error_notifications}")
        if run.execution_successful is None and run.tool.name is not None:
            notes.append(f"RUN_HAS_NO_INVOCATION_RECORD:{run.locator}")
    return notes


def _sarif_observations(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput],
                        diagnostics: list[AnalysisDiagnostic]) -> list[tuple[FlowCandidate, str]]:
    if locus is None or not locus.files:
        diagnostics.append(AnalysisDiagnostic("NO_LOCUS_FILES", "SARIF flows are matched by file; the locus declares no files"))
        return []
    if subject.target_source_root is None:
        diagnostics.append(AnalysisDiagnostic("TARGET_SOURCE_ROOT_NOT_DECLARED",
                                              "without target_source_root no flow location can be attributed to the target component"))
        return []
    expected: dict[str, str] = {}
    for name in locus.files:
        normalized, reason = normalize_relative_path(name, None)
        if normalized is None:
            diagnostics.append(AnalysisDiagnostic("LOCUS_FILE_NOT_NORMALIZABLE", f"{name!r}: {reason}"))
        else:
            expected[_join(subject.target_source_root, normalized)] = normalized
    found: list[tuple[FlowCandidate, str]] = []
    not_touching = unresolved = degenerate = 0
    for candidate in analysis.candidates:
        touched = sorted({step.path for step in candidate.steps if step.path in expected})
        if touched and len(candidate.steps) >= 2:
            found.append((candidate, touched[0]))
        elif touched:
            degenerate += 1
            diagnostics.append(AnalysisDiagnostic("SINGLE_LOCATION_FLOW", "a flow with one location records no path", candidate.locator))
        elif any(step.path is None for step in candidate.steps):
            unresolved += 1
        else:
            not_touching += 1
    if not_touching:
        diagnostics.append(AnalysisDiagnostic("FLOWS_NOT_TOUCHING_LOCUS", f"{not_touching} flow(s) resolve to paths other than the locus files"))
    if unresolved:
        diagnostics.append(AnalysisDiagnostic("FLOWS_WITH_UNRESOLVED_LOCATIONS",
                                              f"{unresolved} flow(s) have locations that cannot be resolved to the analysis root and none touches the locus"))
    return found


def _summary(candidate: FlowCandidate) -> str:
    def show(step) -> str:
        return f"{step.path or '?'}:{step.line}" if step.line else (step.path or "?")
    first, last = candidate.steps[0], candidate.steps[-1]
    return f"{show(first)} -> ... -> {show(last)} ({len(candidate.steps)} locations)"


def _graph_observations(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput],
                        diagnostics: list[AnalysisDiagnostic]) -> list[tuple[str, str, tuple[str, ...], tuple[str, ...], str]]:
    """``(observation_id, matched symbol, step locators, node ids, summary)`` for every (entry, locus) pair that is connected."""
    graph = analysis.call_graph
    assert graph is not None
    if locus is None or not locus.symbols:
        diagnostics.append(AnalysisDiagnostic("NO_LOCUS_SYMBOLS", "call-graph paths are matched by method full name; the locus declares no symbols"))
        return []
    if not subject.entry_methods:
        diagnostics.append(AnalysisDiagnostic("NO_ENTRY_METHODS", "the subject declares no entry methods, so no path from an entry point can be established"))
        return []
    by_name: dict[str, list[MethodNode]] = {}
    for method in graph.methods:
        if method.full_name:
            by_name.setdefault(method.full_name, []).append(method)
    for name, nodes in sorted(by_name.items()):
        if len(nodes) > 1 and (name in locus.symbols or name in subject.entry_methods):
            diagnostics.append(AnalysisDiagnostic("AMBIGUOUS_METHOD_FULL_NAME",
                                                  f"{len(nodes)} METHOD nodes share FULL_NAME {name!r}; every one is a candidate"))
    entries = [m for name in subject.entry_methods for m in by_name.get(name, [])]
    for name in subject.entry_methods:
        if name not in by_name:
            diagnostics.append(AnalysisDiagnostic("ENTRY_METHOD_NOT_IN_GRAPH", f"{name!r} is not a METHOD FULL_NAME in the export"))
    targets: list[MethodNode] = []
    root = subject.target_source_root
    for symbol in locus.symbols:
        for method in by_name.get(symbol, []):
            if root is not None and method.filename:
                path, _ = normalize_relative_path(method.filename, None)
                if path is None or not (root == "." or path == root or path.startswith(root + "/")):
                    diagnostics.append(AnalysisDiagnostic("LOCUS_METHOD_OUTSIDE_TARGET_ROOT",
                                                          f"{symbol!r} is defined in {method.filename!r}, outside {root!r}", method.locator))
                    continue
            elif root is not None:
                diagnostics.append(AnalysisDiagnostic("LOCUS_METHOD_HAS_NO_FILENAME",
                                                      f"{symbol!r} has no FILENAME: kept as a candidate, its component cannot be confirmed", method.locator))
            targets.append(method)
        if symbol not in by_name:
            diagnostics.append(AnalysisDiagnostic("LOCUS_SYMBOL_NOT_IN_GRAPH", f"{symbol!r} is not a METHOD FULL_NAME in the export"))
    adjacency: dict[str, list[CallEdge]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.caller, []).append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda e: (e.callee, e.locator))
    names = {m.node_id: m.full_name or m.node_id for m in graph.methods}
    found = []
    for entry in sorted(entries, key=lambda m: m.node_id):
        parents: dict[str, Optional[CallEdge]] = {entry.node_id: None}
        queue = deque([entry.node_id])
        while queue:
            current = queue.popleft()
            for edge in adjacency.get(current, []):
                if edge.callee not in parents:
                    parents[edge.callee] = edge
                    queue.append(edge.callee)
        for target in sorted(targets, key=lambda m: m.node_id):
            if target.node_id not in parents:
                continue
            chain: list[CallEdge] = []
            node = target.node_id
            while parents[node] is not None:
                chain.append(parents[node])  # type: ignore[arg-type]
                node = parents[node].caller  # type: ignore[union-attr]
            chain.reverse()
            by_id = {m.node_id: m for m in graph.methods}
            locators = tuple([entry.locator] + [loc for e in chain
                                                for loc in (f"#/graphml/node/{e.call_node}", e.locator, by_id[e.callee].locator)])
            route = " -> ".join([names[entry.node_id]] + [names[e.callee] for e in chain])
            found.append((f"{entry.node_id}>{target.node_id}", target.full_name or target.node_id, locators,
                          tuple([entry.node_id] + [e.callee for e in chain]), route))
    return found


def derive_document(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput]) -> DerivedEvidence:
    """Bind ``analysis`` to ``subject`` and derive at most one positive-path ``ReachDocument``. Pure."""
    diagnostics = list(analysis.diagnostics)
    traces: list[ObservationTrace] = []
    contributing: list[RunFacts] = []
    limitations = [NO_NEGATIVE_LIMITATION, LINK_LIMITATION]

    if analysis.source.format is AnalysisFormat.SARIF:
        for candidate, matched in _sarif_observations(analysis, subject, locus, diagnostics):
            traces.append(ObservationTrace(candidate.candidate_id, candidate.locator, "static_dataflow_trace", matched,
                                           tuple(s.locator for s in candidate.steps), _summary(candidate), candidate.suppressed))
        indices = sorted({int(t.observation_id.split(".")[0][1:]) for t in traces})
        contributing = [analysis.runs[i] for i in indices]
        if analysis.results_without_flow:
            diagnostics.append(AnalysisDiagnostic("RESULTS_WITHOUT_CODE_FLOW",
                                                  f"{analysis.results_without_flow} finding(s) carry no code flow: no path is derived from them"))
        if any(t.suppressed for t in traces):
            limitations.append("SUPPRESSED_RESULT_COUNTED: a path in a suppressed result is kept (it can only lower the verdict)")
        blockers = _sarif_blockers(contributing or list(analysis.runs), subject) if traces else []
    else:
        for obs_id, matched, step_locators, _, route in _graph_observations(analysis, subject, locus, diagnostics):
            traces.append(ObservationTrace(obs_id, "#/graphml", "call_graph_path", matched, step_locators, route))
        contributing = list(analysis.runs)
        blockers = []
        if traces:
            run = analysis.runs[0]
            declared = (subject.source_content_hash or "").strip().lower()
            recorded = (run.content_hash or "").strip().lower()
            if not declared:
                blockers.append("SUBJECT_CONTENT_HASH_NOT_DECLARED")
            elif not recorded:
                blockers.append("GRAPH_CONTENT_HASH_ABSENT")
            elif declared != recorded:
                blockers.append("GRAPH_CONTENT_HASH_MISMATCH")
            else:
                limitations.append("CONTENT_HASH_ALGORITHM_UNSPECIFIED: equality of the declared and recorded source hash; the CPG schema defines no algorithm")
        limitations.append("CALL_GRAPH_COMPLETENESS_UNKNOWN: dynamic dispatch, reflection and unresolved calls leave no CALL edge, "
                           "so the absence of a path says nothing")
    limitations.extend(_run_limitations(contributing or list(analysis.runs)))
    if any(d.code in ("FLOWS_WITH_UNRESOLVED_LOCATIONS",) for d in diagnostics):
        limitations.append(UNRESOLVED_LIMITATION)
    tool, notes = _tool_for(contributing or list(analysis.runs))
    limitations.extend(notes)

    document: Optional[ReachDocument] = None
    if traces:
        started = {run.started for run in contributing}
        artifact = None
        if not blockers:
            artifact = Component(name=subject.artifact.purl, version=subject.artifact.version, purl=subject.artifact.purl,
                                 identifier_variants=build_identifier_variants(subject.artifact.purl, subject.artifact.version,
                                                                              subject.artifact.purl, [], []))
        source = SourceRef(analysis.source, tool, tuple(t.locator for t in traces), tuple(traces), tuple(blockers),
                           tuple(dict.fromkeys(limitations)), tuple(diagnostics), subject.entered_by)
        document = ReachDocument(
            doc_id=analysis.source.doc_id, kind=ReachKind.K1, finding=ReachFinding.POSITIVE,
            producer=tool.organization if tool else None, producer_class="static-analysis-tool",
            tool_name=tool.name if tool else None, tool_version=tool.version if tool else None,
            created=next(iter(started)) if len(started) == 1 else None,
            artifact=artifact, target=subject.target, source=source,
        )
        return DerivedEvidence(document, source)
    source = SourceRef(analysis.source, tool, (), (), tuple(blockers), tuple(dict.fromkeys(limitations)), tuple(diagnostics),
                       subject.entered_by)
    return DerivedEvidence(None, source)
