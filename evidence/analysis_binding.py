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
    UndecidableObservation,
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
UNDECIDABLE_LIMITATION = ("UNDECIDABLE_EVIDENCE: {n} recorded flow(s)/call edge(s) may touch the locus but cannot be resolved. They are not "
                          "counted as paths in the reported outcome; the outcome is reported only if counting them as paths would not change "
                          "the verdict, otherwise the evaluation is refused (EVAL_ANALYSIS_EVIDENCE_UNDECIDABLE)")


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
    # Present only when `source.undecidable` is not empty: the document the artifact would give if every
    # undecidable observation were a path (the evaluator compares the two outcomes).
    worst_document: Optional[ReachDocument] = None


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


def _segments(path: str) -> list[str]:
    return [part for part in path.lower().split("/") if part]


def could_be_locus(loose: Optional[str], expected: Mapping[str, str]) -> bool:
    """Can an *unresolved* location possibly be one of the locus files?

    Necessary condition only: the location's path must end, segment by segment and ignoring case, with
    ``<target_source_root>/<locus file>`` (whatever precedes it is the unknown mapping of the analysis
    root). A location that cannot satisfy it cannot be the locus file, so it is irrelevant; a location
    that carries no usable path at all cannot be excluded. This never establishes that it *is* the
    locus: it only decides that it must not be discarded."""
    if loose is None:
        return True
    have = _segments(loose)
    for path in expected:
        want = _segments(path)
        if want and have[-len(want):] == want:
            return True
    return False


@dataclass(frozen=True)
class SarifClassification:
    established: list[tuple[FlowCandidate, str]]
    undecidable: list[tuple[FlowCandidate, str, tuple[str, ...]]]


def _sarif_observations(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput],
                        diagnostics: list[AnalysisDiagnostic]) -> SarifClassification:
    """Classify every recorded flow as **established** (a visited location is the locus file inside the
    target root), **undecidable** (not established, but some visited location is unresolved and nothing
    excludes it from being the locus) or irrelevant (every visited location is resolved and elsewhere,
    or unresolved yet unable to be the locus). An undecidable flow is kept, with its raw locators."""
    expected: dict[str, str] = {}
    blocker: Optional[str] = None
    if locus is None or not locus.files:
        blocker = "the locus declares no files"
        diagnostics.append(AnalysisDiagnostic("NO_LOCUS_FILES", "SARIF flows are matched by file; the locus declares no files"))
    elif subject.target_source_root is None:
        blocker = "the subject declares no target_source_root"
        diagnostics.append(AnalysisDiagnostic("TARGET_SOURCE_ROOT_NOT_DECLARED",
                                              "without target_source_root no flow location can be attributed to the target component"))
    else:
        for name in locus.files:
            normalized, reason = normalize_relative_path(name, None)
            if normalized is None:
                diagnostics.append(AnalysisDiagnostic("LOCUS_FILE_NOT_NORMALIZABLE", f"{name!r}: {reason}"))
            else:
                expected[_join(subject.target_source_root, normalized)] = normalized
        if not expected:
            blocker = "no locus file could be normalized"
    established: list[tuple[FlowCandidate, str]] = []
    undecidable: list[tuple[FlowCandidate, str, tuple[str, ...]]] = []
    not_touching = unreachable = excluded_unresolved = 0
    for candidate in analysis.candidates:
        visited = [step for step in candidate.steps if "unreachable" not in {k.lower() for k in step.kinds}]
        if blocker is not None:   # relevance cannot be judged at all: every flow that visits something is undecidable
            if visited:
                undecidable.append((candidate, blocker, tuple(step.locator for step in visited)))
            continue
        touched = sorted({step.path for step in visited if step.path in expected})
        if touched:
            established.append((candidate, touched[0]))
            continue
        if any(step.path in expected for step in candidate.steps):
            unreachable += 1   # the only locus locations are marked 'unreachable' by the tool: not a visited location
            diagnostics.append(AnalysisDiagnostic("LOCUS_STEP_MARKED_UNREACHABLE",
                                                  "a location in the locus file is marked kind 'unreachable' in the flow: not counted as visited", candidate.locator))
            continue
        unresolved = [step for step in visited if step.path is None and could_be_locus(step.loose_path, expected)]
        if unresolved:
            undecidable.append((candidate, "; ".join(dict.fromkeys(step.unresolved or "unresolved" for step in unresolved)),
                                tuple(step.locator for step in unresolved)))
        elif any(step.path is None for step in visited):
            excluded_unresolved += 1   # unresolved, but its path cannot end with <target root>/<locus file>
        else:
            not_touching += 1
    if excluded_unresolved:
        diagnostics.append(AnalysisDiagnostic(
            "UNRESOLVED_LOCATIONS_EXCLUDED",
            f"{excluded_unresolved} flow(s) have unresolved locations that cannot be a locus file (their path does not end with "
            "<target_source_root>/<locus file>); they are irrelevant, not discarded blindly"))
    if not_touching:
        diagnostics.append(AnalysisDiagnostic("FLOWS_NOT_TOUCHING_LOCUS",
                                              f"{not_touching} flow(s) visit only locations that cannot be the locus files"))
    for candidate, reason, locators in undecidable:
        diagnostics.append(AnalysisDiagnostic("UNDECIDABLE_FLOW",
                                              f"may touch the locus but cannot be resolved ({reason}); kept, not discarded", candidate.locator))
    return SarifClassification(established, undecidable)


def _summary(candidate: FlowCandidate) -> str:
    def show(step) -> str:
        return f"{step.path or '?'}:{step.line}" if step.line else (step.path or "?")
    first, last = candidate.steps[0], candidate.steps[-1]
    return f"{show(first)} -> ... -> {show(last)} ({len(candidate.steps)} locations)"


@dataclass(frozen=True)
class GraphClassification:
    established: list[tuple[str, str, tuple[str, ...], tuple[str, ...], str]]   # (id, matched symbol, step locators, node ids, route)
    undecidable: list[UndecidableObservation]


def _graph_observations(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput],
                        diagnostics: list[AnalysisDiagnostic]) -> GraphClassification:
    """Paths from a declared entry method to a locus method over method-level ``CALL`` edges, plus the
    ``CALL`` edges whose caller is unknown but whose callee can reach a locus method (undecidable).

    A call graph is a model, not an assertion of a path: relative to no declared entry or locus there
    is nothing to decide, so those cases derive nothing (unlike SARIF flows, which are assertions)."""
    graph = analysis.call_graph
    assert graph is not None
    if locus is None or not locus.symbols:
        diagnostics.append(AnalysisDiagnostic("NO_LOCUS_SYMBOLS", "call-graph paths are matched by method full name; the locus declares no symbols"))
        return GraphClassification([], [])
    if not subject.entry_methods:
        diagnostics.append(AnalysisDiagnostic("NO_ENTRY_METHODS", "the subject declares no entry methods, so no path from an entry point can be established"))
        return GraphClassification([], [])
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
    reverse: dict[str, set[str]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.caller, []).append(edge)
        reverse.setdefault(edge.callee, set()).add(edge.caller)
    for edges in adjacency.values():
        edges.sort(key=lambda e: (e.callee, e.locator))
    names = {m.node_id: m.full_name or m.node_id for m in graph.methods}
    by_id = {m.node_id: m for m in graph.methods}
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
            locators = tuple([entry.locator] + [loc for e in chain
                                                for loc in (f"#/graphml/node/{e.call_node}", e.locator, by_id[e.callee].locator)])
            route = " -> ".join([names[entry.node_id]] + [names[e.callee] for e in chain])
            found.append((f"{entry.node_id}>{target.node_id}", target.full_name or target.node_id, locators,
                          tuple([entry.node_id] + [e.callee for e in chain]), route))
    # methods from which a locus method can be reached over the known edges (the locus methods included)
    can_reach = {t.node_id for t in targets}
    queue = deque(can_reach)
    while queue:
        for caller in reverse.get(queue.popleft(), ()):
            if caller not in can_reach:
                can_reach.add(caller)
                queue.append(caller)
    undecidable = []
    for call in graph.uncontained:
        if entries and call.callee in can_reach:
            undecidable.append(UndecidableObservation(
                f"uncontained:{call.call_node}>{call.callee}", call.locator,
                "a CALL edge into a method that can reach the locus has a call site with no containing METHOD, so its caller "
                "(possibly reachable from an entry method) is unknown",
                (f"#/graphml/node/{call.call_node}", call.locator, by_id[call.callee].locator if call.callee in by_id else call.locator)))
    for item in undecidable:
        diagnostics.append(AnalysisDiagnostic("UNDECIDABLE_CALL_EDGE", f"{item.reason}; kept, not discarded", item.locator))
    return GraphClassification(found, undecidable)


def derive_document(analysis: NormalizedAnalysis, subject: AnalysisSubject, locus: Optional[LocusInput]) -> DerivedEvidence:
    """Bind ``analysis`` to ``subject`` and derive at most one positive-path ``ReachDocument`` from the
    *established* observations, plus a worst-case document that also counts every undecidable
    observation as a path. Pure."""
    diagnostics = list(analysis.diagnostics)
    traces: list[ObservationTrace] = []
    undecidable: list[UndecidableObservation] = []
    contributing: list[RunFacts] = []
    limitations = [NO_NEGATIVE_LIMITATION, LINK_LIMITATION]

    if analysis.source.format is AnalysisFormat.SARIF:
        classified = _sarif_observations(analysis, subject, locus, diagnostics)
        for candidate, matched in classified.established:
            traces.append(ObservationTrace(candidate.candidate_id, candidate.locator, "static_dataflow_trace", matched,
                                           tuple(s.locator for s in candidate.steps), _summary(candidate), candidate.suppressed))
        for candidate, reason, locators in classified.undecidable:
            undecidable.append(UndecidableObservation(candidate.candidate_id, candidate.locator, reason, locators))
        indices = sorted({int(t.observation_id.split(".")[0][1:]) for t in traces} | {int(u.observation_id.split(".")[0][1:]) for u in undecidable})
        contributing = [analysis.runs[i] for i in indices]
        if analysis.results_without_flow:
            diagnostics.append(AnalysisDiagnostic("RESULTS_WITHOUT_CODE_FLOW",
                                                  f"{analysis.results_without_flow} finding(s) carry no code flow (absent or empty `codeFlows`): "
                                                  "no path is derived from them and none is excluded by them"))
        if any(t.suppressed for t in traces):
            limitations.append("SUPPRESSED_RESULT_COUNTED: a path in a suppressed result is kept (it can only lower the verdict)")
        blockers = _sarif_blockers(contributing or list(analysis.runs), subject) if (traces or undecidable) else []
    else:
        classified_graph = _graph_observations(analysis, subject, locus, diagnostics)
        for obs_id, matched, step_locators, _, route in classified_graph.established:
            traces.append(ObservationTrace(obs_id, "#/graphml", "call_graph_path", matched, step_locators, route))
        undecidable = list(classified_graph.undecidable)
        contributing = list(analysis.runs)
        blockers = []
        if traces or undecidable:
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
    if undecidable:
        limitations.append(UNDECIDABLE_LIMITATION.format(n=len(undecidable)))
    tool, notes = _tool_for(contributing or list(analysis.runs))
    limitations.extend(notes)
    limitation_tuple = tuple(dict.fromkeys(limitations))

    def build(trace_list: list[ObservationTrace]) -> tuple[Optional[ReachDocument], SourceRef]:
        source = SourceRef(analysis.source, tool, tuple(t.locator for t in trace_list), tuple(trace_list), tuple(blockers),
                           limitation_tuple, tuple(diagnostics), subject.entered_by, tuple(undecidable))
        if not trace_list:
            return None, source
        started = {run.started for run in contributing}
        artifact = None
        if not blockers:
            artifact = Component(name=subject.artifact.purl, version=subject.artifact.version, purl=subject.artifact.purl,
                                 identifier_variants=build_identifier_variants(subject.artifact.purl, subject.artifact.version,
                                                                              subject.artifact.purl, [], []))
        return ReachDocument(
            doc_id=analysis.source.doc_id, kind=ReachKind.K1, finding=ReachFinding.POSITIVE,
            producer=tool.organization if tool else None, producer_class="static-analysis-tool",
            tool_name=tool.name if tool else None, tool_version=tool.version if tool else None,
            created=next(iter(started)) if len(started) == 1 else None,
            artifact=artifact, target=subject.target, source=source,
        ), source

    document, source = build(traces)
    worst_document = None
    if undecidable:
        as_paths = [ObservationTrace(u.observation_id, u.locator, "undecidable_counted_as_path", "<unresolved>", u.step_locators,
                                     f"UNDECIDABLE: {u.reason}") for u in undecidable]
        worst_document, _ = build(traces + as_paths)
    return DerivedEvidence(document, source, worst_document)
