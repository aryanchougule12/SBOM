# Analyzer-artifact ingestion (Milestones 3 and 4)

Flow:

```
raw artifact --parse--> NormalizedAnalysis --bind/derive--> strict ReachDocument(+SourceRef)
   (strict, structural)   (neutral facts,       (subject binding,     --> existing reach_evaluator
                           raw locators)         locus matching)           --> ReachOutcome | EvaluationRefusal
                                                                              (+ outcome.analysis explanation)
```

| Layer | Module | Responsibility |
|---|---|---|
| Neutral model | `evidence/analysis_model.py` | Typed facts, locator conventions, stable error codes. No interpretation. |
| Raw format | `evidence/analysis_sarif.py`, `evidence/analysis_graphml.py` | Parse, structurally validate, identify tool/format version, content digest, resolve references **within the document**. |
| Binding/derivation | `evidence/analysis_binding.py` | Relate the facts to the finding (evaluator-entered `AnalysisSubject` + locus), classify binding blockers, derive at most one `ReachDocument` per artifact: a positive-path report, or - only with an analysis-run record satisfying every coverage fact - a negative K1 report that forwards the record's declared claim. |
| API | `evidence/analysis_ingest.py` | `parse_analysis_artifact`, `ingest_artifacts`, `evaluate_with_analysis`. |
| Evaluation | `evidence/reach_*` (unchanged rules) | REACH §5.1 derivation, BIND, provenance, R1-R13. |

```python
from evidence.analysis_ingest import evaluate_with_analysis
outcome = evaluate_with_analysis(profile, findings, index, ["scan.sarif"], subject, reachability, verification)
# ReachOutcome (outcome.result, outcome.analysis, outcome.items, ...) or EvaluationRefusal
```

The strict `reachability=` input and `evaluate_finding` / `evaluate_reachability` are unchanged;
`ReachDocument.source` and `ReachabilityEvidence.analysis_sources` are Python-level fields that the JSON
loader cannot set.

## Formats and what each can establish

| | SARIF 2.1.0 (CodeQL and others) | Joern GraphML (`joern-export --format graphml`) |
|---|---|---|
| Authority checked | OASIS schema `sarif-schema-2.1.0.json` (vendored, tests validate fixtures); field list below | flatgraph `GraphMLExporter` source; CPG schema (`CallGraph.scala`, `Method.scala`, `MetaData.scala`); semanticcpg traversal code |
| Consumed | `version`; `runs[].tool.driver` (`name`, `semanticVersion`/`version`, `organization`); `invocations[]` (`executionSuccessful`, `startTimeUtc`, notification levels); `versionControlProvenance[]`; `artifacts[].location` and `artifactLocation.index`; `results[]` (`kind`, `baselineState`, `suppressions`, `ruleId`, `codeFlows[].threadFlows[].locations[].location.physicalLocation`) | `META_DATA` (`LANGUAGE`, `VERSION`, `HASH`), `METHOD` (`FULL_NAME`, `NAME`, `FILENAME`, `IS_EXTERNAL`), `CALL` nodes, `CALL` and `CONTAINS` edges |
| **Can establish** | A recorded flow whose locations touch the declared locus file inside the target's source root → a **positive** path observation (static data-flow trace); the analysed revision (from `versionControlProvenance`); tool name/version and start time (P1 attribution) | A CALL path from a declared entry method to a METHOD whose `FULL_NAME` is a locus symbol → a **positive** call-graph path observation; a claimed source hash (`META_DATA.HASH`) |
| **Cannot establish** | Absence of a path; completeness; coverage of locus or entry points; reachability from an entry point (a data-flow trace is not a call graph); that a result's location is "execution" | Absence of a path (dynamic dispatch, reflection and unresolved calls leave no edge); tool or version (the file names none → P0); revision; which passes ran (list properties are dropped by the exporter) |
| Not consumed (deliberately) | a result's own `locations`, `level`, `message`, `relatedLocations`, `stacks`, `graphs`, `results` being empty, the tool's success flag as proof of coverage | AST, CFG, PDG, REACHING_DEF, ARGUMENT edges and every other property: not call-graph evidence |

Neither format states a **full-coverage claim over LOCUS and ENTRY**, which is what §5.1 step 2 requires
for REACH `Absent`. From an artifact alone the adapters therefore derive **only positive observations**; every other fact
(empty results, failed runs, missing path, unresolved locations) is kept as a diagnostic or limitation and
REACH stays `Unknown`. *Milestone 5:* an analysis-run record may add a **declared** claim; it is consumed only when every coverage fact is established
(see "Analysis-run records" below) and then yields at most Weak. A stock CodeQL taint query, a graph without an entry-point inventory and a successful process
are never enough. This is a finding about the evidence, not a limitation of the code.

## Mapping from the formal rules to artifact fields

| Formal need (spec) | Artifact field | Normalized field | Derivation | Binding/provenance | Behaviour | Tests |
|---|---|---|---|---|---|---|
| §5.1 step 1: an item that observes a path or execution of the locus | SARIF `codeFlows[].threadFlows[]` with ≥2 locations touching `<target_source_root>/<locus file>`; CPG `CALL` path entry→locus method | `FlowCandidate` / `CallGraph` → `ObservationTrace` (locator, step locators, summary) | `observation_state` → `Present` at any EP | item locator = the codeFlow/threadFlow pointer (SARIF) or `#/graphml` (graph) | R1 (or R3 beside a K1 absence) | `test_analysis_binding`, `test_analysis_pipeline`, corpus B01/B08/B12/C01/C09-C11/D02 |
| §5.1 step 2/3: absence, K1 coverage | — (no field states it) | — | never derived | — | REACH `Unknown` (R2 `NO_ANALYSIS`) | corpus A01-A03, B09-B11, C05-C06, D03-D04 |
| §5.1 BIND: analysis bound to artifact and component version | SARIF `versionControlProvenance`; CPG `META_DATA.HASH`; subject `target` | `RunFacts.vcs` / `content_hash` + `SourceRef.bind_blockers` | equality of repository and full revision / of the declared hash; component via existing reach BIND | `ReachDocument.artifact` = subject artifact **without hashes** (product/version → B4) | blockers → BIND `Unknown` → R6; the positive is **kept** | corpus B02-B06, B25, C02-C04, F02-F06 |
| §1.2 P1 attribution | `tool.driver.name/semanticVersion|version`, `invocations[0].startTimeUtc` | `ToolIdentity`, `RunFacts.started` | existing strict-P1 classification | — | no version or no time → P0 | B13, B14, B26, all C |
| §1.2 P2 (declared digest = S digest) | none | — | **never granted**: the document declares no digest of S | — | P3 unreachable for derived documents | corpus E01-E04, `test_verification_cannot_lift…` |
| §1.2 step 3 coverage cap | raw-artifact pointers | item locator | existing `locator_within` | detached result keyed by the content-derived `doc_id` | cap at P1 outside coverage | E02 |
| §5.1 LOCUS | none (evaluator-entered) | `LocusInput` | unchanged | — | needed for matching; none → no match | F01, F07 |
| Structural validity | whole artifact | `AnalysisArtifactError` | — | — | **refusal** `EVAL_ANALYSIS_ARTIFACT_INVALID`, not a verdict | corpus A06, A07, B-refuse-*, C-refuse-* |

## Binding and provenance protections

* The assessed artifact is linked to the analysed source only by the evaluator's `AnalysisSubject`
  (an unauthenticated statement, always listed as `SOURCE_TO_ARTIFACT_LINK_EVALUATOR_ASSERTED`). The
  artifact then has to **agree** with it: same repository and full revision (SARIF, every contributing
  run), same declared source hash (GraphML). No name, version string or label is treated as identity.
* A binding failure never discards a positive observation (an unbound positive can only lower the
  verdict, P-3); it makes BIND `Unknown`.
* A raw artifact's existence is not trust: `doc_id` is `<format>:sha256:<digest>` so a detached
  `VerificationResult` can be bound to the exact bytes, but the derived document is never P2 (no
  declared digest of S), hence never P3. The run's own `executionSuccessful`, notifications and counts are
  recorded as claims, never as coverage.
* Unresolved or absolute locations, unknown `uriBaseId`, `..` escapes, other-component paths with the
  same file name, other-component methods with the same `FULL_NAME`, and flows of one location are never
  matched as locus files. A flow with such a location that **might** be the locus (its path ends with
  `<target source root>/<locus file>`, or it has no usable path) is never discarded: it is kept as
  *undecidable* and handled by the procedure below. Only a location that cannot be the locus is excluded
  (`UNRESOLVED_LOCATIONS_EXCLUDED`).

## Evaluation and reproduction

```bash
python -m tests.analysis_eval            # run the corpus, print the summary, write evaluation_results/
python -m tests.analysis_eval --check    # fail if the committed results are stale
python -m tests.conformance              # rules + tests of both predicates, plus the corpus agreement
python -m pytest -q                      # everything
```

`evaluation_results/analysis_corpus.json` and `analysis_corpus_cases.csv` are byte-stable. They are
**controlled conformance results**: agreement of the pipeline with hand-reviewed expectations, reported
separately for category A (upstream examples) and category B (synthetic). No accuracy, precision, recall
or false-positive rate is computed: there is no labelled ground truth, only the category L files are live analyzer runs (CodeQL 2.27.3, `fixtures/analysis/authentic/codeql/REPRODUCE.md`),
and the corpus has no Joern-generated file. Category L (authentic CodeQL output) is reported separately from A (upstream) and B (synthetic); authentic Joern output is reported as 0 (not obtained).

## Unresolved locations: the undecidable-evidence procedure (Milestone 4)

**Defect found.** A flow whose locations cannot be resolved against the analysis root (absolute `file://` URI,
unknown `uriBaseId`, `..` escape, logical-only locations) used to be dropped. Next to a verified K1 absence
(Supported on its own) the dropped flow could have been the very path that contradicts the absence, so the
verdict was Supported although recorded analysis evidence might have shown the code reachable: an
absence assertion overrode unresolved positive evidence (spec M-4, P-1, P-3).

**Repair (no rule change, no new verdict or state).**

1. Every recorded flow (SARIF `threadFlow`) or call edge (GraphML) is classified:
   *established* (a resolved path touches the locus), *irrelevant* (every location resolved elsewhere, or
   each unresolved location demonstrably cannot be the locus: `could_be_locus` is a necessary-condition
   filter on the decoded path suffix `<target source root>/<locus file>`, case-insensitively), or
   *undecidable* (some location, or the caller of a call edge, cannot be resolved and cannot be excluded).
2. Only *established* flows become observations. Undecidable ones are kept (`SourceRef.undecidable`, a
   locator and a reason each, diagnostics `UNDECIDABLE_FLOW` / `UNDECIDABLE_CALL_EDGE`).
3. `evaluate_reachability` evaluates twice: as classified (best case) and with every undecidable flow
   counted as a path (worst case). Equal verdicts: the best-case outcome is returned with the limitation
   `UNDECIDABLE_EVIDENCE_DID_NOT_CHANGE_THE_VERDICT`. Different verdicts: the formal rules define no verdict for
   an input whose relevance is unknown, so the evaluation is a structured refusal
   `EVAL_ANALYSIS_EVIDENCE_UNDECIDABLE` (cause `UNRESOLVED_RELEVANT_EVIDENCE`), not a fourth verdict.
4. A call edge whose call site has no containing METHOD (`CALL_SITE_WITHOUT_CONTAINING_METHOD`) is
   undecidable only if its callee can reach the locus method over known edges.

Example (corpus G01 / G06): K1 absence + an absolute-URI flow ending in `node_modules/lib-b/src/parse.js` →
refusal; the same absence + an absolute-URI flow ending in `lib/more.js` → Supported with
`UNRESOLVED_LOCATIONS_EXCLUDED`. Without a K1 absence the verdict is Insufficient either way, so the
flow is reported and nothing is refused.

## What SARIF code flows establish (field-by-field normative mapping)

Sources: SARIF 2.1.0 (OASIS) §3.36 `codeFlow`, §3.37 `threadFlow`, §3.38 `threadFlowLocation`, §3.27 `result`,
§3.14 `run`, §3.20 `invocation`; GitHub docs "SARIF support for code scanning" (CodeQL `path-problem`: a
code flow is the query-defined data-flow path from source to sink). A SARIF *validity* check (schema) says
the file is well formed; *evidence validity* is the table below.

| Field | Meaning (SARIF) | Observation we derive | Preconditions | Does **not** establish | Facts required | Rule | Tests |
|---|---|---|---|---|---|---|---|
| `result.codeFlows[].threadFlows[].locations[]` | The locations a tool visited, in execution order, while producing the result | Each resolved location in the locus file under the target source root → path/execution observation (R1) | locations resolved to analysis-root-relative paths; run bound (else R6) | a call path (a data-flow trace is not a call graph); that the code runs in the deployment; absence elsewhere | repository+revision (bind), tool+version+start (P1) | §5.1 step 1; R1/R3/R6/R13 | G07, G15, L01, L04 |
| empty or missing `codeFlows` | no flow recorded | none | — | **not** absence of a path (the result may lack flow detail; the producer may not emit flows) | — | R2 (Unknown) | G11, G12, L02 |
| `result.locations` (primary location) | where the result is reported | none (never a path) | — | execution of that location | — | — | `test_the_primary_result_location_is_not_a_path` |
| `threadFlowLocation.kinds` contains `unreachable` | the location is *not* visited | none; recorded as `LOCUS_STEP_MARKED_UNREACHABLE` | — | an absence either (a tool note on one step) | — | R2 | G10 |
| `artifactLocation.uri` / `uriBaseId` / `index` | where the location is | resolution only: relative URI against `%SRCROOT%`/`SRCROOT`/none; `index` through `run.artifacts` and checked against `uri` | analysis-root mapping known | file identity of an absolute or unknown-base URI | root declaration (subject) | undecidable procedure | G01–G04, B19–B21 |
| `versionControlProvenance` | repository/revision analysed | bind blockers on mismatch/abbreviation/absence | full revision equal | the artifact analysed == the assessed artifact (subject link is evaluator-asserted) | | R6 | B02–B06, L01 |
| `invocations[].executionSuccessful`, notifications | run status claimed by the tool | limitations only | schema-valid enums/date-times (else refusal) | complete coverage | | R2/R5/R11, P0/P1 | B11–B13, G16, G17 |
| `result.kind`, `baselineState`, `suppressions` | result disposition | only `fail`/`review`/`open` and not `absent` count; suppressed results are counted and disclosed | | that a suppressed finding is not a path | | | B15–B17 |
| `run.results` absent | rule-metadata export, not a scan | none (`RUN_WITHOUT_RESULTS_ARRAY`) | | absence | | R2 | G13 |
| `run.properties` (property bag) | producer-specific, no defined semantics | none | | a coverage claim | | | G14 |
| a producer other than CodeQL | schema-valid | same mapping; CodeQL semantics are **not** assumed | | CodeQL's data-flow meaning | tool identity | | A-category tutorial files |

## Joern GraphML contract (audit)

Verified from source (flatgraph `GraphMLExporter`, codepropertygraph schema, semanticcpg), without installing
Joern (about 1.7 GB; not needed for a contract audit):

* Nodes: `labelV` key + `node__<LABEL>__<PROP>` data keys. Edges: `labelE`, directed `<graph id="G">`; ids are
  node ids, edge order is document order. Only `META_DATA`, `METHOD`, `CALL` nodes and `CALL`, `CONTAINS` edges
  are consumed; AST, CFG, REACHING_DEF, ARGUMENT, … are never turned into call edges.
* `CALL` edge: call site → callee `METHOD`. The caller is the METHOD containing the call site via `CONTAINS`
  (METHOD → node, the direction `method._containsOut` reads). A reversed `CONTAINS` edge is **not** used
  (`CONTAINS_EDGE_REVERSED`) and the call edges that lose their container become undecidable edges, not silent losses.
* `--repr all` writes one file with all CALL edges; `--repr cpg` splits per method and drops cross-method CALL
  edges: such an export under-reports calls, which is why a missing path is never an absence.
* List properties are dropped by the exporter (no tool name, no pass list): the export is P0 and states no coverage.
* No authentic GraphML was obtained: all Joern fixtures are synthetic (category B).

## Identity and source binding (audit)

| Assertion (input) | Verification (binding) | Failure behaviour |
|---|---|---|
| `AnalysisSubject`: artifact purl/version, target, repository, revision, content hash, target source root, entry methods | SARIF: equal repository and full (not abbreviated) revision for every contributing run; GraphML: equal declared hash | observation kept; BIND `Unknown` (R6); never an improvement |
| source root | the explicit `target_source_root`; two roots with the same relative file are two different locations | wrong root → no match, not another candidate |
| tool, version, start time | read from the artifact | missing → P0; never P2/P3 from declarations |

A mismatching revision, repository, hash or root can never produce a better verdict than the matching subject
(`tests/test_analysis_soundness.py`, G08/G09).

## Analysis-run records, exact source binding and coverage (Milestone 5)

Contract: `evidence/analysis_run.py` (schema `analysis-run/1`, strict, deterministic serialization); binding, URI mapping and coverage
gates: `evidence/analysis_run_binding.py`; recorder: `analysis_runner/` (outside `evidence/`: it runs processes and hashes files, which the
evidence pipeline must never do). Readings: `docs/spec_addendum_v0.2.5.md`.

```python
AnalysisArtifactInput("scan.sarif", run="scan.run.json")      # or run=AnalysisRunRecord; an unusable record is a structured refusal
```

**The record is an assertion.** It never carries a state, a provenance level, a BIND result, a trust statement, a coverage verdict or a
verdict (refused at any depth), cannot say that a field was verified, and cannot make a document P2 or P3. Each field group has a stated
source (`observed_by_runner`, `caller_supplied`; `extracted_from_artifact` is a value the evaluation reports, `established_by_verification`
is refused from input). `null` means not observed and is not the same as `false` or `0`.

| Group | Fields (all optional except `schema`, `run_id`, `origin`, `tool.name`) |
|---|---|
| `tool` | name, version, output format version, executable SHA-256 |
| `source` | repository, **full** revision, analysis subpath, tree digest (`git-tree:` or `sha256-worktree:`), worktree clean, untracked/ignored file count, submodules, changed during run, roots (id, absolute path, role, repository, revision) |
| `target` | purl, source root |
| `configuration` | languages, query (pack, version, digest, suite, ids, **claim semantics**), redacted command |
| `stages[]` | name, role (`extraction`/`analysis`/`other`), status, exit code, start, finish |
| `outputs[]` | path, SHA-256 (`null`: absent when looked for), size |
| `scope` | file inventory (complete, included, excluded), entry-point inventory (complete, source, methods), partial-analysis indicators, analysed configurations |
| `coverage_claim` | kind, locus files and symbols, entry methods, declared by |

### The recorder

```bash
python -m analysis_runner run PLAN.json --out RUN.json      # exit 0 complete, 1 written but a stage failed / output missing, 2 unusable plan
python -m analysis_runner check RUN.json FILE [FILE...]     # re-hash files against the record's outputs (exit 1 on mismatch)
```

It records the redacted argument vector of each stage (credential-looking flags, `NAME=value` and URL userinfo are redacted; no environment value
is ever recorded), start/finish instants, exit status, timeout, the tool's reported version, the git identity of the analysed directory before the run
(commit, tree id of the analysed subpath, tracked changes, untracked **and ignored** files, submodules), a digest of every file under the analysis root
before and after the run (a change is `changed_during_run`), and each output's SHA-256 and size. A failed or timed-out stage ends the run (later stages are
`not_run`). It does not modify the analysed project. Plan fields that are not observations (languages, query identity and semantics, scope, claim) are
recorded as `caller_supplied`. **Process success is execution metadata, not proof of coverage.** Validated with a fake executable
(`tests/test_analysis_runner.py`: success, failure, timeout, missing output, source change during the run, dirty tree, redaction, determinism) and against
live CodeQL 2.27.3 (`fixtures/analysis/authentic/codeql/recorded/`; `tests/test_analysis_live.py`).

### Binding of the run to the assessed source

Five statuses (`established`, `missing`, `contradicted`, `ambiguous`, `impossible`; addendum v0.2.5 §2). Established needs: output hash equal to the artifact's;
tool/version consistent with the artifact; equal repository and equal **full** revision (an abbreviation is ambiguous); equal tree digest when the evaluator
declared one; clean, observed tree without untracked or ignored files and without unpinned submodules, unchanged during the run (unless the evaluator's declared
identity is a digest of the dirty contents); consistent target, source root and (GraphML) `META_DATA ROOT`; and an artifact-stated VCS provenance that does not
contradict the record. Anything else keeps the observations and leaves BIND Unknown (R6). Identity levels reported: `exact` (digest compared), `commit_only`,
`not_established`. The link to the assessed artifact S remains evaluator-asserted.

### Absolute URI and root mapping

See addendum v0.2.5 §3. Table of decisions (all tested in `tests/test_analysis_run_binding.py` and corpus cases U01-U18):

| Location | Result |
|---|---|
| `file:///<primary root>/rel` with binding established | mapped to `rel` in the analysis root, then matched as any relative location |
| same, binding not established / no record / no roots | unmapped: undecidable if its path ends with a locus file (refusal beside a K1 absence), else irrelevant |
| under a vendored/external root | never the assessed tree: undecidable if its path inside that root ends with a locus file, else irrelevant |
| `..`/`.`/empty segment, `%2e%2e`, `%2F`, `%00`, remote host, `https:`, query, fragment, outside every root, root-name prefix only | unmapped |
| a file name alone | never maps |

### Coverage facts and when a negative K1 report is derived

Fourteen separate facts (addendum v0.2.5 §4): `binding_established`, `tool_declared`, `process_completed`, `extraction_completed`, `language_scope`,
`locus_included`, `query_suite_completed`, `claim_semantics`, `entry_points_enumerated`, `exclusions_accounted`, `suppressions_accounted`,
`no_partial_indicators`, `no_undecidable_evidence`, `coverage_claim_declared`; each `established`, `not_established`, `contradicted` or `not_recorded`.
A negative K1 report with the record's **declared** full-coverage claim is derived only if all hold and no path is recorded; the result is then decided by the
unchanged rules and is at most **Weak** (P1; a record cannot reach P2/P3). Otherwise REACH stays Unknown and the conditions that prevented a stronger
decision are listed (`outcome.analysis[i].assessment.preventing`). For the authentic CodeQL runs the stock taint query (`claim_semantics =
taint_path_query`), the absent entry-point inventory and the absent claim keep the absence from being derived, as they should.

## Limitations

* Live CodeQL 2.27.3 output exists (category L: three earlier files plus three runs recorded by the runner, JavaScript queries); no authentic Joern output
  was obtained, and the GraphML fixtures follow the exporter's source, not a real export.
* A code flow is a static data-flow trace; counting it as a path observation is a convention (register
  AI-D3). Suppressed results are counted. A flow of one location counts (SARIF: a visited location).
  Abbreviated revisions never bind. Real CodeQL logs carry no `versionControlProvenance`, so they bind Unknown.
* Locations that cannot be resolved against the analysis root are not matched as locus files; if they might
  be the locus the evaluation is refused when that could change the verdict (see the procedure above). An absolute URI is mapped only through an
  explicit root of an established run record (above); there is no rule that maps by file name or suffix.
* No supported tool enumerates entry points: entry-point completeness is a declaration. No query of a stock CodeQL pack is a locus-reachability analysis.
* Entry points for call graphs are evaluator-declared; entry-point completeness is not derived.
* `CONTAINS` is read in the semanticcpg direction (METHOD → node) only; a reversed edge is reported and not used;
  `IS_EXTERNAL` is recorded, not used.
