"""Relating an analysis-run record to the artifact, the assessed source and the locus.

This module decides three things and nothing else:

1. **Binding** (``assess_binding``): is the analysed source *exactly* the source the evaluator assesses? The result is one of
   five explicit statuses (``BindingStatus``). Only ``ESTABLISHED`` lets a derived document carry the assessed artifact;
   every other status keeps the observations (an unbound positive can only lower a verdict, P-3) and leaves BIND Unknown (R6).
2. **URI / path mapping** (``RootMapper``): an absolute ``file`` URI is mapped to a path inside the analysis root only through
   an explicit root of the record whose binding is ESTABLISHED, never through a file name or a path suffix.
3. **Coverage** (``assess_coverage``): which *separate* facts about scope and completeness are established, and therefore
   whether a negative K1 document may be derived at all. A negative document is derived only when every fact below is
   established; the record's own coverage claim is then forwarded as the K1 report's *declared* full-coverage claim
   (specification §5.1 step 2, assumption A6: soundness is recorded as claimed, never verified).

What nothing here can do: set an evidence state, a provenance level above what the artifact itself justifies, P2 or P3, or a
verdict. A hash equality between the record and the artifact's bytes shows that the record describes that file; it is not proof
that an analyzer ran. The record's author is not authenticated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from evidence.analysis_model import BindingStatus, NormalizedAnalysis, RunFacts
from evidence.analysis_run import (
    AnalysisRunRecord,
    EntrySource,
    RootRole,
    SourceRoot,
    StageRole,
    StageStatus,
)
from evidence.analysis_sarif import percent_decode

CLAIM_SEMANTICS_SARIF = "locus_reachability_query"
CLAIM_SEMANTICS_GRAPH = "call_graph_export"
REQUIRED_FACTS = (
    "binding_established", "tool_declared", "process_completed", "extraction_completed", "language_scope", "locus_included",
    "query_suite_completed", "claim_semantics", "entry_points_enumerated", "exclusions_accounted", "suppressions_accounted",
    "no_partial_indicators", "no_undecidable_evidence", "coverage_claim_declared",
)
_FILE_URI = re.compile(r"^file:(?://([^/?#]*))?(/[^?#]*)$", re.IGNORECASE)
_FULL_REVISION = (40, 64)


# ---- repository / revision comparison --------------------------------------------------------------------------------------

def _norm_repo(uri: Optional[str]) -> str:
    text = (uri or "").strip().lower().rstrip("/")
    return text[:-4] if text.endswith(".git") else text


def _norm_rev(revision: Optional[str]) -> Optional[str]:
    return revision.strip().lower() if revision and revision.strip() else None


def _compare_revisions(a: str, b: str) -> Optional[tuple[BindingStatus, str]]:
    """``None`` when equal full revisions; otherwise the failing status and code."""
    if a == b and len(a) in _FULL_REVISION:
        return None
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    if len(short) not in _FULL_REVISION or len(long_) not in _FULL_REVISION:
        if long_.startswith(short):
            return BindingStatus.AMBIGUOUS, "REVISION_ABBREVIATED"
        return BindingStatus.CONTRADICTED, "REVISION_MISMATCH"
    return BindingStatus.CONTRADICTED, "REVISION_MISMATCH"


def _digest_parts(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not value:
        return None, None
    text = value.strip().lower()
    algorithm, separator, hexdigits = text.partition(":")
    return (algorithm, hexdigits) if separator else (None, text)


# ---- binding -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class BindingResult:
    status: BindingStatus
    reasons: tuple[str, ...]
    source_identity: str            # exact | commit_only | not_established
    output_linked: bool


_PRIORITY = (BindingStatus.CONTRADICTED, BindingStatus.AMBIGUOUS, BindingStatus.IMPOSSIBLE, BindingStatus.MISSING)


def assess_binding(record: AnalysisRunRecord, analysis: NormalizedAnalysis, subject: Any) -> BindingResult:
    """Relate ``record`` to ``analysis`` (the raw artifact, content-addressed) and to ``subject`` (the evaluator's
    ``AnalysisSubject``, an unauthenticated statement). Pure."""
    found: list[tuple[BindingStatus, str]] = []

    def add(status: BindingStatus, code: str) -> None:
        found.append((status, code))

    # the record must describe *these bytes*
    digest = analysis.source.doc_id.split(":sha256:")[-1]
    linked = False
    if not record.outputs:
        add(BindingStatus.MISSING, "RUN_OUTPUT_NOT_LISTED")
    elif any(o.sha256 == digest for o in record.outputs):
        linked = True
    elif all(o.sha256 is None for o in record.outputs):
        add(BindingStatus.MISSING, "RUN_OUTPUT_NOT_PRESENT_WHEN_RECORDED")
    else:
        add(BindingStatus.CONTRADICTED, "RUN_OUTPUT_HASH_MISMATCH")

    # the artifact must not contradict the record's tool
    for run in analysis.runs:
        if run.tool.name is not None and run.tool.name.strip().lower() != record.tool.name.strip().lower():
            add(BindingStatus.CONTRADICTED, f"RUN_TOOL_MISMATCH:{run.locator}")
        elif run.tool.version is not None and record.tool.version is not None and run.tool.version.split("+")[0] != record.tool.version.split("+")[0]:
            add(BindingStatus.CONTRADICTED, f"RUN_TOOL_VERSION_MISMATCH:{run.locator}")

    # source identity
    wanted_repo = _norm_repo(subject.source_repository)
    wanted_rev = _norm_rev(subject.source_revision)
    have_repo = _norm_repo(record.source.repository)
    have_rev = _norm_rev(record.source.revision)
    if wanted_rev is None or not wanted_repo:
        add(BindingStatus.MISSING, "SUBJECT_REVISION_NOT_DECLARED")
    if have_rev is None or not have_repo:
        add(BindingStatus.MISSING, "RECORD_REVISION_NOT_RECORDED")
    if wanted_rev and wanted_repo and have_rev and have_repo:
        if wanted_repo != have_repo:
            add(BindingStatus.CONTRADICTED, "REPOSITORY_MISMATCH")
        else:
            outcome = _compare_revisions(wanted_rev, have_rev)
            if outcome is not None:
                add(*outcome)
    # artifact-stated provenance (SARIF) must agree with the record
    for run in analysis.runs:
        same = [v for v in run.vcs if have_repo and _norm_repo(v.repository_uri) == have_repo]
        if run.vcs and not same and have_repo:
            add(BindingStatus.CONTRADICTED, f"ARTIFACT_REPOSITORY_CONTRADICTS_RECORD:{run.locator}")
        for vcs in same:
            theirs = _norm_rev(vcs.revision_id)
            if theirs and have_rev:
                outcome = _compare_revisions(theirs, have_rev)
                if outcome is not None:
                    add(outcome[0], f"ARTIFACT_{outcome[1]}_VS_RECORD:{run.locator}")
    # the content digest of the analysed tree
    declared_alg, declared_hex = _digest_parts(subject.source_content_hash)
    record_alg, record_hex = _digest_parts(record.source.tree_digest)
    digest_compared = False
    if declared_hex:
        if record_hex is None:
            add(BindingStatus.MISSING, "RECORD_TREE_DIGEST_NOT_RECORDED")
        elif (declared_alg and record_alg and declared_alg != record_alg) or declared_hex != record_hex:
            add(BindingStatus.CONTRADICTED, "TREE_DIGEST_MISMATCH")
        else:
            digest_compared = True
    # a graph's own claimed hash, compared exactly as before (the CPG schema defines no algorithm)
    for run in analysis.runs:
        if run.content_hash and declared_hex and run.content_hash.strip().lower() != declared_hex:
            add(BindingStatus.CONTRADICTED, "GRAPH_CONTENT_HASH_MISMATCH")
    # is the analysed tree the committed tree? (a content digest of the dirty tree, equal to the declared one, identifies it)
    identified_by_content = digest_compared and record_alg == "sha256-worktree"
    if record.source.changed_during_run is True:
        add(BindingStatus.IMPOSSIBLE, "SOURCE_CHANGED_DURING_RUN")
    elif record.source.changed_during_run is None:
        add(BindingStatus.MISSING, "SOURCE_STABILITY_NOT_OBSERVED")
    if not identified_by_content:
        if record.source.worktree_clean is False:
            add(BindingStatus.IMPOSSIBLE, "WORKTREE_NOT_CLEAN")
        elif record.source.worktree_clean is None:
            add(BindingStatus.MISSING, "WORKTREE_STATE_NOT_RECORDED")
        if record.source.untracked_files:
            add(BindingStatus.IMPOSSIBLE, "UNTRACKED_FILES_PRESENT")
        elif record.source.untracked_files is None:
            add(BindingStatus.MISSING, "UNTRACKED_FILES_NOT_RECORDED")
    if record.source.submodules is None:
        add(BindingStatus.MISSING, "SUBMODULES_NOT_RECORDED")
    elif record.source.submodules:
        add(BindingStatus.AMBIGUOUS, "SUBMODULE_CONTENT_NOT_IDENTIFIED")
    # target and root
    if record.target.purl and subject.target.purl and record.target.purl.strip().lower() != subject.target.purl.strip().lower():
        add(BindingStatus.CONTRADICTED, "TARGET_MISMATCH")
    if record.target.source_root and subject.target_source_root and record.target.source_root != subject.target_source_root:
        add(BindingStatus.CONTRADICTED, "TARGET_SOURCE_ROOT_MISMATCH")
    primary = [r for r in record.source.roots if r.role is RootRole.PRIMARY]
    for run in analysis.runs:
        if run.analysis_root and primary and run.analysis_root.rstrip("/") != primary[0].path:
            add(BindingStatus.CONTRADICTED, "ANALYSIS_ROOT_MISMATCH")

    for status in _PRIORITY:
        if any(s is status for s, _ in found):
            reasons = tuple(dict.fromkeys([c for s, c in found if s is status] + [c for _, c in found]))
            return BindingResult(status, reasons, "not_established", linked)
    identity = "exact" if digest_compared else "commit_only"
    reasons = ("DIRTY_TREE_IDENTIFIED_BY_CONTENT_DIGEST",) if identified_by_content and (record.source.worktree_clean is False or record.source.untracked_files) else ()
    return BindingResult(BindingStatus.ESTABLISHED, reasons, identity, linked)


# ---- URI mapping ---------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MappedLocation:
    root_id: str
    role: RootRole
    relative: str


class RootMapper:
    """Maps an absolute file location to ``(root, relative path)`` through the roots of a record whose binding is established.
    Anything it cannot map is returned with a reason and stays unresolved (and, if it could be the locus, undecidable)."""

    def __init__(self, roots: Sequence[SourceRoot]) -> None:
        self.roots = tuple(roots)

    def map_path(self, path: str) -> tuple[Optional[MappedLocation], str]:
        if not path.startswith("/") or "\\" in path or "\x00" in path:
            return None, "not an absolute POSIX path"
        segments = path.split("/")[1:]
        if any(s in ("", ".", "..") for s in segments):
            return None, "dot or empty path segment (no lexical normalization is trusted without a canonical path)"
        for root in self.roots:
            prefix = root.path + "/"
            if path.startswith(prefix):
                relative = path[len(prefix):]
                return MappedLocation(root.root_id, root.role, relative), "mapped"
        return None, "no declared root contains the path"

    def map_uri(self, uri: str) -> tuple[Optional[MappedLocation], str]:
        match = _FILE_URI.match(uri.strip())
        if match is None:
            return None, "only the file scheme can be mapped to a local source"
        authority = (match.group(1) or "").lower()
        if authority not in ("", "localhost"):
            return None, "file URI with a remote host"
        raw_path = match.group(2)
        if re.search(r"%(2f|5c|00)", raw_path, re.IGNORECASE):
            return None, "encoded separator or NUL in the path"
        decoded = percent_decode(raw_path)
        if decoded is None:
            return None, "path is not valid UTF-8 after percent-decoding"
        return self.map_path(decoded)


def mapper_for(record: Optional[AnalysisRunRecord], binding: Optional[BindingResult]) -> Optional[RootMapper]:
    """A mapper exists only when a record declares roots *and* its binding to the assessed source is established."""
    if record is None or binding is None or binding.status is not BindingStatus.ESTABLISHED or not record.source.roots:
        return None
    return RootMapper(record.source.roots)


def ends_with_file(relative: str, locus_files: Sequence[str]) -> bool:
    """Necessary condition for a file of a root that is not the primary tree to be (a copy of) a locus file: its path inside
    that root ends, by whole segments and ignoring case, with a locus file path."""
    have = [s for s in relative.lower().split("/") if s]
    for file in locus_files:
        want = [s for s in file.lower().split("/") if s]
        if want and have[-len(want):] == want:
            return True
    return False


# ---- coverage ------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class CoverageResult:
    facts: tuple[tuple[str, str], ...]          # fact -> established | not_established | contradicted | not_recorded
    execution: str
    entry_points_known: bool
    negative_derivable: bool
    preventing: tuple[str, ...]
    notes: tuple[str, ...]


def _stage_state(record: AnalysisRunRecord) -> tuple[str, bool, bool]:
    """(execution label, extraction completed, analysis completed) from the recorded stages only."""
    if not record.stages:
        return "not_recorded", False, False
    statuses = [s.status for s in record.stages]
    if any(s in (StageStatus.FAILED, StageStatus.TIMED_OUT) for s in statuses) or any(s.exit_code not in (None, 0) for s in record.stages):
        label = "failed"
    elif all(s is StageStatus.COMPLETED for s in statuses) and not record.partial_indicators:
        label = "completed"
    elif any(s is StageStatus.NOT_RUN for s in statuses) or record.partial_indicators:
        label = "partial"
    else:
        label = "unknown"
    extraction = any(s.role is StageRole.EXTRACTION and s.status is StageStatus.COMPLETED for s in record.stages)
    analysis_done = any(s.role is StageRole.ANALYSIS and s.status is StageStatus.COMPLETED for s in record.stages)
    return label, extraction, analysis_done


def assess_coverage(
    record: Optional[AnalysisRunRecord],
    analysis: NormalizedAnalysis,
    subject: Any,
    locus: Any,
    binding: Optional[BindingResult],
    expected_locus_paths: Mapping[str, str],
    undecidable: int,
    established_paths: int,
    graph_locus_methods: int,
) -> CoverageResult:
    """Evaluate each coverage fact separately. ``expected_locus_paths`` maps ``<target root>/<locus file>`` to the locus file;
    ``graph_locus_methods`` is the number of locus-symbol METHOD nodes found inside the target root (graphs)."""
    sarif = analysis.call_graph is None
    runs: list[RunFacts] = list(analysis.runs)
    facts: dict[str, str] = {}
    notes: list[str] = []
    if record is None:
        for name in REQUIRED_FACTS:
            facts[name] = "not_recorded"
        facts["no_undecidable_evidence"] = "established" if not undecidable else "not_established"
        return CoverageResult(tuple(facts.items()), "not_recorded", False, False, tuple(n for n, s in facts.items() if s != "established"),
                              ("no analysis-run record: coverage is not established",))

    execution, extraction, analysis_done = _stage_state(record)
    if execution == "completed" and any(r.execution_successful is False for r in runs):
        facts["process_completed"] = "contradicted"
        execution = "failed"
        notes.append("the record says the stages completed but the artifact reports an unsuccessful execution")
    elif execution == "completed":
        facts["process_completed"] = "established"
    elif execution == "not_recorded":
        facts["process_completed"] = "not_recorded"
    else:
        facts["process_completed"] = "not_established"
    if any(r.error_notifications for r in runs):
        notes.append("the artifact records error notifications")
    facts["binding_established"] = "established" if binding is not None and binding.status is BindingStatus.ESTABLISHED else "not_established"
    facts["tool_declared"] = "established" if record.tool.name and record.tool.version else "not_recorded"
    facts["extraction_completed"] = "established" if extraction else ("not_recorded" if not record.stages else "not_established")
    facts["language_scope"] = "established" if record.languages else "not_recorded"

    # is the locus part of what was analysed?
    locus_paths = list(expected_locus_paths)
    if sarif:
        extracted = [r.extracted_files for r in runs]
        if all(e is not None for e in extracted) and extracted:
            have = set().union(*(set(e) for e in extracted))  # type: ignore[arg-type]
            facts["locus_included"] = "established" if locus_paths and all(p in have for p in locus_paths) else "not_established"
            notes.append("locus inclusion taken from the artifact's expected-extracted-files notifications (files in scope of extraction)")
        elif record.file_scope.complete is True and locus_paths:
            facts["locus_included"] = "established" if all(p in record.file_scope.included for p in locus_paths) else "not_established"
            notes.append("locus inclusion taken from the record's own file inventory (an assertion)")
        else:
            facts["locus_included"] = "not_recorded"
    else:
        facts["locus_included"] = "established" if graph_locus_methods else "not_established"

    # the query / export stage and its identity
    query = record.query
    if not analysis_done:
        facts["query_suite_completed"] = "not_recorded" if not record.stages else "not_established"
    elif sarif:
        identified = bool((query.pack or query.suite) and query.query_ids)
        packs = {name: version for r in runs for name, version in r.query_packs}
        rules = {rule for r in runs for rule in r.rule_ids}
        if not identified:
            facts["query_suite_completed"] = "not_recorded"
        elif query.pack and packs and (query.pack not in packs or (query.pack_version and packs[query.pack].split("+")[0] != query.pack_version.split("+")[0])):
            facts["query_suite_completed"] = "contradicted"
            notes.append("the artifact lists a different query pack or pack version than the record")
        elif rules and not set(query.query_ids) <= rules:
            facts["query_suite_completed"] = "contradicted"
            notes.append("a query id of the record is not among the rules the artifact lists")
        else:
            facts["query_suite_completed"] = "established"
            if not packs or not rules:
                notes.append("query identity is the record's assertion (the artifact does not list packs or rules)")
    else:
        facts["query_suite_completed"] = "established"

    expected_semantics = CLAIM_SEMANTICS_SARIF if sarif else CLAIM_SEMANTICS_GRAPH
    facts["claim_semantics"] = "established" if query.claim_semantics == expected_semantics else \
        ("not_recorded" if query.claim_semantics is None else "not_established")

    # entry points: a declared inventory, consistent with the evaluator's entry set
    inventory = record.entry_inventory
    entry_known = False
    subject_entries = set(subject.entry_methods)
    if inventory.complete is None or inventory.source is None or not inventory.methods:
        facts["entry_points_enumerated"] = "not_recorded"
    elif inventory.complete is False:
        facts["entry_points_enumerated"] = "not_established"
    elif subject_entries and set(inventory.methods) != subject_entries:
        facts["entry_points_enumerated"] = "contradicted"
        notes.append("the record's entry-point inventory differs from the entry methods the evaluator declared")
    else:
        facts["entry_points_enumerated"] = "established"
        entry_known = True
        if inventory.source is EntrySource.CALLER_DECLARED:
            notes.append("entry-point completeness is a caller declaration; no supported tool enumerates entry points")

    if not sarif and entry_known and analysis.call_graph is not None:
        names = {m.full_name for m in analysis.call_graph.methods if m.full_name}
        if not set(inventory.methods) <= names:
            facts["entry_points_enumerated"] = "not_established"
            entry_known = False
            notes.append("an inventoried entry method is not a METHOD of the export: a path from it cannot be absent, it cannot be looked for")

    excluded_hits = [p for p in locus_paths if any(p == e or p.startswith(e.rstrip("/") + "/") for e in record.file_scope.excluded)]
    if excluded_hits or record.file_scope.complete is False:
        facts["exclusions_accounted"] = "not_established"      # the locus is excluded, or the record itself says its file scope is incomplete
    else:
        facts["exclusions_accounted"] = "established" if record.file_scope.complete is True else "not_recorded"
    suppressed = sum(r.suppressed_results for r in runs)
    facts["suppressions_accounted"] = "established" if suppressed == 0 else "not_established"
    errors = [d for d in record.diagnostics if d.level == "error"]
    facts["no_partial_indicators"] = "established" if not record.partial_indicators and not errors and not any(r.error_notifications for r in runs) else "not_established"
    facts["no_undecidable_evidence"] = "established" if not undecidable else "not_established"

    claim = record.coverage_claim
    if claim is None:
        facts["coverage_claim_declared"] = "not_recorded"
    else:
        loci_ok = (not getattr(locus, "files", ()) or set(locus.files) <= set(claim.locus_files)) and \
                  (not getattr(locus, "symbols", ()) or set(locus.symbols) <= set(claim.locus_symbols))
        entries_ok = bool(claim.entry_methods) and set(claim.entry_methods) == set(inventory.methods)
        facts["coverage_claim_declared"] = "established" if loci_ok and entries_ok and locus is not None else "contradicted"
        if facts["coverage_claim_declared"] == "contradicted":
            notes.append("the coverage claim does not cover the evaluated locus, or its entry methods differ from the recorded inventory")

    preventing = [name for name in REQUIRED_FACTS if facts.get(name) != "established"]
    if established_paths:
        preventing.append("path_recorded")
    derivable = not preventing
    return CoverageResult(tuple((n, facts[n]) for n in REQUIRED_FACTS), execution, entry_known, derivable, tuple(preventing), tuple(notes))
