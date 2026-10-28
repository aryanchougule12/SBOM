# SBOM evidence-sufficiency prototype

A research prototype for judging whether the *recorded evidence* behind a VEX
`not_affected` claim meets a defined bar. It is not production software.

## Authoritative specification

The committed specification is the sole source of truth:

- `docs/formal_specification_v0.2.md`
- `docs/spec_addendum_v0.2.1.md`, `docs/spec_addendum_v0.2.2.md`, `docs/spec_addendum_v0.2.3.md`

The specification and addendum v0.2.1 were fixed at commit
`e0d5bfadf9bd45e753051d7e7c8654f656ddb8ef`. Later clarifications are changelogged in the
numbered addenda (v0.2.2: the §3 Step 4 unresolved-dimension ceiling; v0.2.3: the same ceiling for
the reachability predicate, RT12-RT13, and the readings of §5 the implementation relies on) and are
present in the specification file. Open questions and decisions live in
`docs/open_issues_register.md`.

## Research scope

Two predicates are specified:

- `Req(component_not_present)` (spec §4, rules N1–N17)
- `Req(vulnerable_code_not_in_execute_path)` (spec §5, rules R1–R13)

A verdict is exactly one of **Supported**, **Weak** or **Insufficient**. A verdict
states whether the recorded evidence meets the specification's bar. It does not say
whether the claim is true (spec P-1); ground-truth validation is out of scope here.
Whether a verdict is acceptable to a downstream consumer is a policy question outside
the formal procedure (D-5). The provenance ladder P0–P3 and the P3 threshold are this
prototype's proposed profile, not a classification defined by CISA (P-4).

## Current status

Both predicates are implemented and integrated end to end; nothing here is validated against
ground truth, and every fixture is synthetic.

* `Req(component_not_present)` (§4, N1-N17, NT1-NT25): the integrated CNP pipeline
  (`evidence/evaluator.py`), documented in `docs/open_issues_register.md`.
* `Req(vulnerable_code_not_in_execute_path)` (§5, R1-R13, RT1-RT13): the reachability pipeline
  (`evidence/reach_evaluator.py`), documented in `docs/reachability_implementation.md` (contracts,
  rule-to-implementation matrix, limitations). Reachability follows the specification: it rests on
  call-graph or equivalent analysis evidence (K1-K3) supplied through the project's own reachability
  input schema; an SBOM dependency graph (K4) is read but is never reachability (A5).
* Real analyzer artifacts (SARIF 2.1.0, Joern GraphML) are ingested by `evidence/analysis_*` and evaluated through the same engine
  (`evidence.analysis_ingest.evaluate_with_analysis`; `docs/analysis_ingestion.md`). They can establish only positive path
  observations. The corpus is `fixtures/analysis/`; `python -m tests.analysis_eval` reports controlled conformance (no accuracy claim).
* One documented entry point, `evidence.sufficiency.evaluate_finding(profile, findings, index,
  verification=None, reachability=None)`, routes by the finding's justification. A run evaluates one
  predicate; no combined-predicate verdict exists.
* Not implemented: cryptographic verification (a trusted external `VerificationResult` is consumed),
  GEN assertions, corroborating documents, C3 duplicate classification, parsing of real analyser
  output formats, rendering (`render_verdict`).

## Module structure

| Path | Role |
|---|---|
| `model.py` | Typed dataclasses and enums for F = (C, V, D, J, E), scope S, source-document provenance and evidence items. |
| `sbom_parser/` | CycloneDX, SPDX and OpenVEX parsers. |
| `evidence/stage1_records.py`, `profile.py`, `verification.py` | Typed parser output, the evaluator profile, the external verification input. |
| `evidence/cnp_rules.py`, `evaluator.py` and the INV/DECL/MATCH/GEN/BIND modules | The `component_not_present` engine and pipeline. |
| `evidence/reach_rules.py`, `reach_inputs.py`, `reach_derivation.py`, `reach_items.py`, `reach_evaluator.py` | The `vulnerable_code_not_in_execute_path` engine and pipeline. |
| `evidence/rule_core.py` | What both predicates share (ordering, rationale rendering, minimum ceiling). |
| `evidence/requirements.py`, `sufficiency.py` | The pure predicates and the documented entry point. |
| `tests/` | The test suite, including `tests/conformance.py`, the rule-conformance harness. |
| `fixtures/` | Parser fixtures; `fixtures/reachability/` holds synthetic reachability evidence. |

## Running the tests

From the repository root:

```
python -m pytest -v -rs
python -m tests.conformance
python -m tests.analysis_eval --check
```

`python -m` is used so the repository root is on the import path. Install the dependencies first
with `pip install -r requirements.txt`. `python -m tests.conformance` prints the rule-conformance
summary for both predicates (synthetic cases only) and exits non-zero on any gap or failure; it also
runs under pytest. Skipped tests are placeholders for functionality that does not exist yet, and `-rs`
prints their reasons.

## Mapping to FR-01–FR-09

**Pending.** No SRS defining FR-01–FR-09 is present in this repository, so no mapping
is given and none has been invented.
