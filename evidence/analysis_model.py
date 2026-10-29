"""Normalized analysis-evidence contract shared by the analyzer-artifact adapters.

A real analyzer artifact (a SARIF log, a Joern GraphML export) is parsed by a format-specific
module into a ``NormalizedAnalysis``: neutral, typed, deterministic facts with stable locators into
the raw artifact. Nothing in this module (or in the format parsers) interprets those facts against
a target, binds them to S, assigns an evidence state, a provenance level or a verdict: that happens
later and only through the existing reachability engine (``evidence.analysis_binding`` derives a
strict-input ``ReachDocument`` from them, ``evidence.reach_evaluator`` evaluates it).

Flow::

    raw bytes -> format parser (strict, structural validation)      -> NormalizedAnalysis
              -> analysis_binding (subject binding, locus matching) -> ReachDocument (+ SourceRef)
              -> reach_evaluator (existing derivation/rules)        -> ReachOutcome / EvaluationRefusal

Locators. Every fact carries a locator into the raw artifact. For JSON formats it is a JSON Pointer
in URI-fragment form (``#/runs/0/results/3``); for GraphML it is ``#/graphml/node/<id>`` or
``#/graphml/edge/<n>`` (``n`` the zero-based document-order index among ``<edge>`` elements). The
convention is the project's own for GraphML (XML has no pointer standard); it is stable under
re-serialisation of the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from sbom_parser.errors import ParserError


class AnalysisFormat(str, Enum):
    SARIF = "sarif"
    JOERN_GRAPHML = "joern-graphml"


class AnalysisArtifactErrorCode(str, Enum):
    """Stable codes of an unusable artifact (a structured error, never a leaked exception)."""

    UNREADABLE = "ANALYSIS_ARTIFACT_UNREADABLE"
    FORMAT_UNRECOGNIZED = "ANALYSIS_FORMAT_UNRECOGNIZED"
    MALFORMED = "ANALYSIS_ARTIFACT_MALFORMED"
    FORMAT_VERSION_UNSUPPORTED = "ANALYSIS_FORMAT_VERSION_UNSUPPORTED"
    STRUCTURE_INVALID = "ANALYSIS_STRUCTURE_INVALID"
    REFERENCE_UNRESOLVED = "ANALYSIS_REFERENCE_UNRESOLVED"
    CONTRADICTORY = "ANALYSIS_ARTIFACT_CONTRADICTORY"
    UNSAFE_CONSTRUCT = "ANALYSIS_UNSAFE_CONSTRUCT"
    RUN_RECORD_INVALID = "ANALYSIS_RUN_RECORD_INVALID"


class AnalysisArtifactError(ValueError):
    """The artifact cannot be used. ``locator`` points into the raw artifact when known."""

    def __init__(self, code: AnalysisArtifactErrorCode, message: str, locator: Optional[str] = None) -> None:
        super().__init__(f"{code.value}: {message}" + (f" (at {locator})" if locator else ""))
        self.code = code
        self.message = message
        self.locator = locator

    @classmethod
    def from_parser_error(cls, error: ParserError, code: AnalysisArtifactErrorCode) -> "AnalysisArtifactError":
        return cls(code, error.message, error.locator)


@dataclass(frozen=True)
class SourceArtifactIdentity:
    """The raw artifact: content-addressed, so a detached verification result can be bound to the
    exact bytes (``doc_id`` is ``<format>:sha256:<hex>``, like the SBOM document ids)."""

    doc_id: str
    format: AnalysisFormat
    format_version: Optional[str]
    size: int


@dataclass(frozen=True)
class ToolIdentity:
    """What the artifact says about the producing tool. ``None`` fields are not stated; nothing is
    inferred from the format name or the file name."""

    name: Optional[str]
    version: Optional[str]
    version_field: Optional[str]      # the field the version was read from
    organization: Optional[str] = None


@dataclass(frozen=True)
class VcsProvenance:
    """A SARIF ``versionControlDetails`` entry, verbatim."""

    repository_uri: str
    revision_id: Optional[str]
    branch: Optional[str]
    revision_tag: Optional[str]
    locator: str


@dataclass(frozen=True)
class RunFacts:
    """What one analysis run states about itself. Recorded as claimed; none of it is evidence of
    complete coverage (the specification defines no such evidence for these formats)."""

    locator: str
    tool: ToolIdentity
    started: Optional[datetime] = None
    execution_successful: Optional[bool] = None
    error_notifications: int = 0
    warning_notifications: int = 0
    vcs: tuple[VcsProvenance, ...] = ()
    content_hash: Optional[str] = None  # a claimed hash over the analysed sources (GraphML META_DATA HASH)
    language: Optional[str] = None
    result_count: int = 0
    results_present: bool = True   # SARIF: the `results` array exists (it "must be present ... if a log file represents an actual scan")
    # Scope facts the artifact itself states (None / empty: not stated; never read as "nothing was analysed").
    analysis_root: Optional[str] = None                 # GraphML META_DATA ROOT
    extracted_files: Optional[tuple[str, ...]] = None   # SARIF `*/baseline/expected-extracted-files` notifications (resolved paths); None: no such notification
    extracted_files_unresolved: int = 0                 # ... notifications whose location could not be resolved against the analysis root
    query_packs: tuple[tuple[str, str], ...] = ()       # SARIF tool.extensions[].(name, semanticVersion)
    rule_ids: tuple[str, ...] = ()                      # SARIF tool.driver.rules[].id
    suppressed_results: int = 0                         # results carrying a suppression


@dataclass(frozen=True)
class PathStep:
    """One location of a recorded flow. ``path`` is the analysis-root-relative path when the
    location could be resolved, else ``None`` with the reason in ``unresolved``."""

    locator: str
    path: Optional[str]
    unresolved: Optional[str] = None
    line: Optional[int] = None
    # What the artifact says about an *unresolved* location, kept so that its relevance can be judged
    # instead of the location being discarded: ``loose_path`` is the decoded URI path with any scheme
    # and authority removed (not anchored to the analysis root); ``None`` when the location carries no
    # usable URI at all (then its relevance cannot be excluded).
    loose_path: Optional[str] = None
    kinds: tuple[str, ...] = ()   # threadFlowLocation.kinds, verbatim ('unreachable' matters)
    raw_uri: Optional[str] = None  # the location's URI as recorded (after resolving `index`), for the root-mapping policy


@dataclass(frozen=True)
class FlowCandidate:
    """One recorded flow (a SARIF ``threadFlow``): an ordered list of steps. A static data-flow trace
    is not a call graph and not a coverage statement."""

    candidate_id: str
    locator: str                 # the pointer of the codeFlow (the unit a verification can cover)
    run_index: int
    rule_id: Optional[str]
    steps: tuple[PathStep, ...]
    suppressed: bool = False
    result_locator: str = ""


@dataclass(frozen=True)
class MethodNode:
    node_id: str
    locator: str
    full_name: Optional[str]
    name: Optional[str]
    filename: Optional[str]
    is_external: Optional[bool]


@dataclass(frozen=True)
class CallEdge:
    """A method-level call edge derived from a CPG ``CALL`` edge: the method that contains the call
    site (``caller``) and the method the call site invokes (``callee``). ``locator`` is the CALL
    edge, ``call_node`` the call site."""

    caller: str
    callee: str
    call_node: str
    locator: str


@dataclass(frozen=True)
class UncontainedCall:
    """A CALL edge whose call site has no containing METHOD in the artifact: the callee is known, the
    caller is not, so the edge cannot be placed in the method-level call graph. It is kept because
    the unknown caller might be reachable from an entry point."""

    call_node: str
    callee: str
    locator: str


@dataclass(frozen=True)
class CallGraph:
    methods: tuple[MethodNode, ...]
    edges: tuple[CallEdge, ...]
    call_edge_count: int         # CALL edges in the artifact (0 means this is not a call-graph export)
    uncontained: tuple[UncontainedCall, ...] = ()


@dataclass(frozen=True)
class AnalysisDiagnostic:
    code: str
    detail: str
    locator: Optional[str] = None


@dataclass(frozen=True)
class NormalizedAnalysis:
    """The neutral result of parsing one artifact. ``candidates`` (SARIF flows) and ``call_graph``
    (GraphML) are the only path-bearing facts; ``diagnostics`` keeps everything the parser
    noticed that no formal rule can consume."""

    source: SourceArtifactIdentity
    runs: tuple[RunFacts, ...]
    candidates: tuple[FlowCandidate, ...] = ()
    call_graph: Optional[CallGraph] = None
    diagnostics: tuple[AnalysisDiagnostic, ...] = ()
    results_without_flow: int = 0
    ignored_results: int = 0

    @property
    def tools(self) -> tuple[ToolIdentity, ...]:
        return tuple(dict.fromkeys(run.tool for run in self.runs))


@dataclass(frozen=True)
class ObservationTrace:
    """A path observation retained as evidence, with the raw locators it rests on. ``matched`` names
    the locus element (file or method) it touches. ``summary`` is a short human-readable path."""

    observation_id: str
    locator: str                 # the evidence-item locator (verification coverage is checked here)
    kind: str                    # static_dataflow_trace | call_graph_path
    matched: str
    step_locators: tuple[str, ...]
    summary: str
    suppressed: bool = False


@dataclass(frozen=True)
class UndecidableObservation:
    """A recorded flow or call edge that might touch the locus but cannot be classified: some
    location (or the caller of a call edge) cannot be resolved, and nothing excludes it from being the
    locus. It is neither a path observation nor a demonstrated non-path. It is never dropped: the
    evaluator decides whether it can change the verdict (``evidence.reach_evaluator``)."""

    observation_id: str
    locator: str
    reason: str
    step_locators: tuple[str, ...]


class BindingStatus(str, Enum):
    """The five outcomes of relating an analysis run to the assessed source. Only ESTABLISHED lets a
    derived document carry the assessed artifact (BIND); every other status keeps the observation and
    leaves BIND Unknown (R6). None of them is an evidence state or a verdict."""

    ESTABLISHED = "established"
    MISSING = "missing"            # a required identity fact is not stated by one side
    CONTRADICTED = "contradicted"  # two statements about the same fact differ
    AMBIGUOUS = "ambiguous"        # an abbreviated or conflicting statement matches more than one source
    IMPOSSIBLE = "impossible"      # the stated identity cannot identify the analysed bytes (dirty or changed tree, unpinned submodule)


@dataclass(frozen=True)
class RunAssessment:
    """What was established about one artifact's analysis run (derived, immutable, explanatory).
    ``coverage`` lists separate facts, each ``established`` / ``not_established`` / ``contradicted`` /
    ``not_recorded``: they are not interchangeable and none of them is an evidence state."""

    record_id: Optional[str]
    binding: Optional[BindingStatus]
    binding_reasons: tuple[str, ...]
    source_identity: str                           # exact | commit_only | not_established | not_assessed
    uri_mapping: tuple[tuple[str, int], ...]       # mapped | not_mapped_irrelevant | undecidable
    execution: str                                 # completed | failed | partial | unknown | not_recorded
    coverage: tuple[tuple[str, str], ...]
    entry_points_known: bool
    negative_derived: bool
    preventing: tuple[str, ...]                    # the conditions that stop a stronger (negative) conclusion
    field_sources: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SourceRef:
    """Where a derived ``ReachDocument`` came from. Python-level only: the strict JSON input of
    ``evidence.reach_inputs`` can never carry it, so a caller cannot fabricate derivation metadata."""

    artifact: SourceArtifactIdentity
    tool: Optional[ToolIdentity]
    observation_locators: tuple[str, ...]
    traces: tuple[ObservationTrace, ...]
    bind_blockers: tuple[str, ...]
    limitations: tuple[str, ...]
    diagnostics: tuple[AnalysisDiagnostic, ...]
    subject_label: str = ""
    undecidable: tuple[UndecidableObservation, ...] = ()
    assessment: Optional[RunAssessment] = None
