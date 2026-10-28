# Analyzer-artifact ingestion (Milestone 3)

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
| Binding/derivation | `evidence/analysis_binding.py` | Relate the facts to the finding (evaluator-entered `AnalysisSubject` + locus), classify binding blockers, derive at most one positive `ReachDocument` per artifact. |
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
for REACH `Absent`. The adapters therefore derive **only positive observations**; every other fact
(empty results, failed runs, missing path, unresolved locations) is kept as a diagnostic or limitation and
REACH stays `Unknown`. Consequence for the research: *no artifact of these two formats can by itself make
a `vulnerable_code_not_in_execute_path` claim Weak or Supported*; the best case is Insufficient. A
supportive K1 report must be supplied through the strict input (or come from a future adapter for a
format that declares coverage). This is a finding about the evidence, not a limitation of the code.

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
  matched. They are reported (`UNRESOLVED_LOCATIONS_NOT_MATCHED` states that a path through them would
  not be seen).

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
or false-positive rate is computed: there is no labelled ground truth, no fixture is a live analyzer run,
and the corpus has no Joern-generated file.

## Limitations

* No live CodeQL or Joern run; the GraphML fixtures follow the exporter's source, not a real export.
* A code flow is a static data-flow trace; counting it as a path observation is a convention (register
  AI-D3). Suppressed results are counted. A flow of one location is not a path. Abbreviated revisions
  never bind.
* Locations that cannot be resolved against the analysis root are not matched, so a path through them is
  not seen; this can only hide a positive observation next to a supplied K1 absence (documented, not
  closed: needs an approved root mapping).
* Entry points for call graphs are evaluator-declared; entry-point completeness is not derived.
* `CONTAINS` direction is not relied on (the CPG schema comment and the semanticcpg code word it
  oppositely); `IS_EXTERNAL` is recorded, not used.
