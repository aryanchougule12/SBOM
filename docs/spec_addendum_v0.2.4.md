# Specification Addendum v0.2.4

This addendum **amends no rule** of `docs/formal_specification_v0.2.md`. It records the readings that the analyzer-artifact adapters (Milestone 4) rely on, so that they are reviewable as readings rather than discovered in code. The earlier addenda (`v0.2.1`–`v0.2.3`) are unchanged; G18/P-3 is not reopened. No fourth verdict and no seventh evidence state exists or is introduced.

## 1. Reading: recorded analysis evidence of unknown relevance is not absence (M-4, P-1, P-3)

§5.1 step 1 makes a positive observation of any kind at any EP decisive over a K1 absence (positive + K1 Absent = Contradictory, R3). The adapters therefore must not discard a recorded flow or call edge that **might** touch the locus merely because they cannot resolve its locations. The evaluation treats such a record as *undecidable* and computes the outcome twice, with the record ignored and with the record counted as a path:

* same verdict in both → that verdict, with the limitation `UNDECIDABLE_EVIDENCE_DID_NOT_CHANGE_THE_VERDICT`;
* different verdicts → no verdict is justified; the evaluation is refused with `EVAL_ANALYSIS_EVIDENCE_UNDECIDABLE` (cause `UNRESOLVED_RELEVANT_EVIDENCE`). A refusal is an input condition ("the input cannot be evaluated"), as for the other `EVAL_*` refusals; it is not a verdict.

This is the only monotone choice: counting the record can only lower the verdict (P-3), and choosing the lower verdict silently would assert a path that no resolved location shows. Which of the two verdicts applies is exactly what the unresolved location decides, so the evaluator says that it cannot decide.

## 2. Reading: what a SARIF code flow is

A `threadFlow` is the sequence of locations a tool *visited* (SARIF 2.1.0 §3.37/§3.38); for CodeQL `path-problem` queries it is the query-defined data-flow path. Therefore:

| Statement | Reading |
|---|---|
| A resolved visited location in the locus file | an observation that "asserts an execution of the locus" (§5.1 step 1) → Present (R1). One location suffices. |
| A data-flow trace | a **path observation of kind `static_dataflow_trace`**, not a call path from an entry point; entry-point reachability is not claimed. Counting it can only lower a verdict. |
| `kinds: ["unreachable"]` on a step | the step is *not* visited: no observation, and not an absence. |
| Empty, missing or absent `codeFlows`; `results: []`; a run without `results` | records nothing; never Absent (P-2). |
| `executionSuccessful`, notification counts, `run.properties` | claims about the run, never the "declared full-coverage claim over LOCUS and ENTRY" of §5.1 step 2. |
| Schema validity | says the file is well formed (a precondition), never that the evidence is valid, bound or covers anything. |

## 3. Conventions that are not amendments

Per-decision status for AI-D1–AI-D10 is in `docs/open_issues_register.md`. None changes a rule; the ones that changed behaviour in this milestone are listed there with their tests (single-location flows count; `CONTAINS` direction is read in one direction only; run-level and invocation-metadata validation).
