# Reachability predicate: implementation, contracts and traceability

Implements `Req(vulnerable_code_not_in_execute_path)` (`docs/formal_specification_v0.2.md` §5, rules **R1–R13**, tests **RT1–RT11**, plus RT12–RT13 of `docs/spec_addendum_v0.2.3.md`). This is the specification's reachability predicate; the R1–R13 here are the §5.4 rules and are unrelated to the inventory structural check "R1" in `evidence/inventory_checks.py`. All fixtures and cases are **synthetic**; nothing here is evidence of real-world accuracy (P-1).

The semantics are the specification's: reachability is judged from **call-graph or equivalent analysis evidence (K1)**, with weaker kinds K2/K3, and a package/SBOM **dependency graph (K4) is not reachability** (§5.1, A5). The implementation does not treat an SBOM relationship as a call edge anywhere.

## 1. Public interface

| Entry point | Role |
|---|---|
| `evidence.sufficiency.evaluate_finding(profile, findings, index, verification=None, reachability=None)` | Documented entry point. Selects the profile's finding and routes by its justification: `component_not_present` → `evidence.evaluator.evaluate`; `vulnerable_code_not_in_execute_path` → `evidence.reach_evaluator.evaluate_reachability`. One finding has one justification, so one predicate runs; no combined verdict exists. |
| `evidence.reach_evaluator.evaluate_reachability(profile, findings, index, reachability=None, verification=None)` | The integrated pipeline. Returns `ReachOutcome` or `EvaluationRefusal`. |
| `evidence.requirements.req_vulnerable_code_not_in_execute_path(ReachInputs)` | The pure predicate over already computed dimension states (replaces the Stage 0 stub). |
| `evidence.reach_rules.evaluate_reach(ReachInputs)` | The rule engine: §3 Steps 1, 3, 4, 5 and §5.4/§5.5. |
| `evidence.reach_inputs.load_reachability / parse_reachability` | Strict loader of the reachability evidence input (schema `1`). |

`evidence.rule_core` holds what both predicates share (triggered-rule record, §3 output ordering, rationale rendering, minimum ceiling, JSON view); `evidence.cnp_rules` and `evidence.reach_rules` both use it. Backward compatibility: `evaluate`, `evaluate_finding(profile, findings, index[, verification])` and `req_component_not_present` behave as before.

## 2. Input contract (`reachability` evidence, schema `1`)

Reachability facts that no SBOM or VEX format carries (register G15) enter only here. The loader rejects unknown fields and the names of derived values (`state`, `verdict`, `provenance_level`, `ep`, `prov_reach`, `bind_state`, `codes`, …) with `REACH_INPUT_FORBIDDEN_FIELD`.

| Block | Content | Treatment |
|---|---|---|
| `documents[]` | `doc_id`, `kind` ∈ {`K1`,`K2`,`K3`,`hazard_basis`}, `finding` ∈ {`negative`,`positive`,`incomplete`,`ambiguous`,`unknown`} (K1 all; K2/K3 `negative`/`positive`/`unknown`; none for `hazard_basis`), attribution (`producer`, `tool_name`, `tool_version`, `created`), `artifact` (what it analysed), `target` (the component it concerns), K1-only `full_coverage_claim`, `entry_points.complete`, `modeled_hazards`, and `analyzed_configurations` | A source document in the §1.1 sense with its own BIND and EP. Registered on the evaluation's copy of the finding with role `reachability_report` (`hazard_basis` → `other`). |
| `locus` | `symbols`/`files`/`granularity`, `approximation` ∈ {`over_approximation`,`possibly_under_approximate`}, `locus_source`, `entered_by` | Evaluator-entered, unauthenticated, no source document → P0 (§1.2 rule 1). |
| `entry_points` | `complete`, `entered_by` | Same. Aggregated with the K1 reports' sets under §2. |
| `hazards[]` | `class`, `disposition`, `basis_ref`, `basis_locator` | An evaluator claim; Step 1 applies. |
| `configuration` | `deployment_config_id` (A7) | Applied to S on the evaluation's own copy; a conflicting value already in S is a refusal. |

`reachability=None` means no evidence: every evidence-dependent dimension is `Unknown` and the verdict is Insufficient (not a refusal).

## 3. Output contract

`ReachOutcome` (frozen, deterministic, `to_dict()` is JSON-serialisable): `result` (the single `VerdictResult`: verdict, codes in §3 order, rationale `<CLASS>[CODE,…]: …`, `limitations`), `dimension_states`, `items` (typed `EvidenceItem`s for REACH, LOCUS, ENTRY), `reach` (derivation step, basis, depends-on item ids), `documents` (per-document BIND and provenance), `hazards` (per-class traceability), `cfg`, `bind`, `prov_reach`, `graph` (K4 facts), `diagnostics`, `limitations`. The verdict is exactly Supported, Weak or Insufficient.

`EvaluationRefusal` (no verdict, no partial result): `EVAL_PROFILE_INVALID`, `EVAL_ASSEMBLY_FAILED`, `EVAL_VERIFICATION_INVALID`, `EVAL_DISPOSITION_NOT_EVALUATED` (disposition other than `not_affected`, an input error), `EVAL_JUSTIFICATION_NOT_SUPPORTED`, `EVAL_REACH_INPUT_INVALID` (not a `ReachabilityEvidence`; a reachability `doc_id` that collides with a profile document; a configuration that conflicts with S), `EVAL_REACH_INPUT_NOT_APPLICABLE` (reachability evidence supplied for a finding that is not a reachability finding), `EVAL_ITEM_INTEGRITY_FAILED`. Malformed reachability JSON is a `ReachInputError` at load time.

## 4. Dimension derivations

| Dimension | Derivation | Source and locator |
|---|---|---|
| REACH | §5.1 steps 1–4 over the REACH items (see `docs/spec_addendum_v0.2.3.md` §2 for the readings). K4 is an `Unknown` item and never reaches steps 1–3. | Items at `#/finding` of each report; the K4 item at `#` of the primary SBOM. |
| LOCUS | Over-approximation declared → Present; possibly under-approximate → Incomplete; otherwise Unknown. | Evaluator-entered (no document). |
| ENTRY | Complete → Present, incomplete → Incomplete, aggregated under §2 (a complete set survives an incomplete one, AG1; two incomplete never give complete, AG5). | `#/entry_points` of K1 reports; evaluator-entered. |
| HAZ | §5.2 Step 1 in the rule engine; per-class assessment records `origin`, claim, basis, bound, EP. | `basis_ref` document at `basis_locator` (default `#`). |
| CFG | S states a configuration (A7) and every analysis the conclusion depends on declares it among `analyzed_configurations`. | S; `#/analyzed_configurations` is declared, not locator-addressed. |
| BIND | Matched only when every relied-on document's declared artifact matches S (B2–B5) and its target matches C; mismatch only from a digest disagreement; unresolved C → Unknown. | Per document; the SBOM's own B1–B5 result when K4 is the only evidence. |
| PROV_REACH | Minimum EP over the documents the conclusion depends on, at their item locators; undefined for Unknown. | Existing P0–P3 machinery; P3 only from a trusted external `VerificationResult` inside its established coverage. |

## 5. Rule-to-implementation matrix (R1–R13)

Class ranks and ceilings are from §5.4. "Engine test" lives in `tests/test_reach_rules.py` (isolation in `test_each_rule_fires_alone_with_its_table_ceiling_class_and_code`, boundaries in `test_rules_do_not_fire_outside_their_condition`); "Pipeline" is `tests/test_reach_evaluator.py`; "Harness" is `python -m tests.conformance`.

| Rule | Required inputs | Transition (fires when) | Ceiling / class / code | Evidence attribution | Limitations reported | Tests |
|---|---|---|---|---|---|---|
| R1 | REACH | REACH = Present | Insufficient / CONTRADICTORY / `CLAIM_CONTRADICTED_BY_PATH` | positive REACH items (`depends_on`) | none | engine `R1`; pipeline `k1-positive`, `k2-positive-at-p0`, `k3-positive-at-p0`; RT harness |
| R2 | REACH, K4 flag | REACH = Unknown; code `MISSING_EDGE_IS_UNKNOWN` iff no K1–K3 document exists and K4 exists, else `NO_ANALYSIS` | Insufficient / CANNOT / one of the two codes | K4 item (SBOM `#`) or none | `REACH=Unknown: <reason>` | RT2, RT11; pipeline K4 topology tests (cycles, repeated, multiple paths, unresolved, disconnected, reversed, direct-to-target) |
| R3 | REACH | REACH = Contradictory (positive + any K1 Absent) | Insufficient / CONTRADICTORY / `REACH_CONFLICT` | positive items + K1 Absent items | none | RT4; pipeline `k1-absent-and-k3-hit`, `k1-absent-and-k2-positive-p0` |
| R4 | LOCUS | LOCUS = Unknown | Insufficient / CANNOT / `NO_LOCUS` | none (evaluator-entered) | `LOCUS=Unknown` | engine; pipeline locus tests; harness `R4/engine` |
| R5 | ENTRY | ENTRY = Unknown | Insufficient / CANNOT / `ENTRYPOINTS_UNDECLARED` | none | none | RT2, RT11; pipeline entry tests |
| R6 | BIND | BIND ≠ matched | Insufficient / CANNOT / `SCOPE_UNBOUND` | relied-on documents (reasons listed) | `BIND: <doc>: <reason>` | engine (unknown, mismatched); pipeline BIND tests incl. G1r |
| R7 | REACH, basis | REACH = Incomplete with basis `non_exhaustive` | Weak / BELOW / `NON_EXHAUSTIVE_EVIDENCE` | K3 / K2 items | none | RT9, RT10; never double-fires with R8 (`test_r7_and_r8_never_double_fire…`) |
| R8 | REACH, basis | REACH ∈ {Incomplete, Ambiguous} with a K1 basis | Weak / BELOW / `PARTIAL_OR_UNRESOLVED_CALLGRAPH` | informative K1 items | none | RT5, RT6 |
| R9 | LOCUS | LOCUS = Incomplete | Weak / BELOW / `LOCUS_MAY_BE_UNDERAPPROXIMATE` | none | none | engine; pipeline locus tests |
| R10 | ENTRY | ENTRY = Incomplete | Weak / BELOW / `ENTRYPOINTS_INCOMPLETE` | K1 / evaluator entry items | none | engine; pipeline entry tests |
| R11 | HAZ[class] after Step 1 | any class Unmodeled/Unknown; plus `HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>` when an exclusion was downgraded | Weak / BELOW / `HAZARD_<CLASS>` | `basis_ref` document or K1 `modeled_hazards` | `HAZARD_STEP1` diagnostics; evaluator-entered exclusions flagged | RT2, RT3, RT7; pipeline hazard tests |
| R12 | CFG | CFG undeclared, or the claim extends beyond the analysed configurations | Weak / BELOW / `CONFIG_ASSUMPTION_UNDECLARED` | S and K1 `analyzed_configurations` | none | engine; pipeline CFG tests |
| R13 | REACH, PROV_REACH | REACH defined and PROV_REACH < P3 | Weak / BELOW / `ANALYSIS_PROVENANCE_BELOW_P3` | documents in `depends_on` | detached-verification limitation when P3 rests on an external result | RT8; pipeline provenance tests |

Supported (§5.5) needs all of: REACH Absent from K1; LOCUS Present; ENTRY Present; every hazard class excluded (≥ P1, bound) or modeled; CFG declared and covering; BIND matched; PROV_REACH = P3; no rule triggered. `test_each_supported_condition_is_necessary` removes each in turn.

Step 4: the verdict is the minimum ceiling over triggered rules and the unresolved-dimension ceiling (addendum v0.2.3); with no triggered rule and an unmet Supported condition the verdict is Insufficient with class `NO_RULE_APPLIES` and no code.

## 6. Test-case matrix (RT1–RT13)

| Test | Variation | Verdict, rules | Engine test | Pipeline (CycloneDX and SPDX) | Harness cases |
|---|---|---|---|---|---|
| RT1 | baseline | Supported | `test_rt1_baseline…` | `RT1` with a trusted detached verification | `RT1/engine`, `RT1/pipeline-cdx`, `RT1/pipeline-spdx` |
| RT2 | K4 only | Insufficient: R2 `MISSING_EDGE_IS_UNKNOWN`, R5, R11 | `test_rt2…` | `RT2` | yes |
| RT3 | reflection Unknown | Weak: R11 | `test_rt3…` | `RT3` | yes |
| RT4 | K1 Absent + K3 hit | Insufficient: R3 (pipeline adds R13: the unverified hit document is P2) | `test_rt4…` | `RT4` | yes |
| RT5 | K1 Incomplete | Weak: R8 | `test_rt5_rt6…` | `RT5` | yes |
| RT6 | K1 Ambiguous | Weak: R8 | `test_rt5_rt6…` | `RT6` | yes |
| RT7 | exclusion basis EP P0 | Weak: R11 + provenance code | `test_rt7…` | `RT7` | yes |
| RT8 | PROV_REACH P2 | Weak: R13 | `test_rt8…` | `RT8` (no verification) | yes |
| RT9 | K3 no-hit, hazards excluded | Weak: R7 | `test_rt9_rt10…` | `RT9` | yes |
| RT10 | K2 negative at P3 | Weak: R7 | `test_rt9_rt10…` | `RT10` | yes |
| RT11 | K2 negative at P0 | Insufficient: R2 `NO_ANALYSIS` | `test_rt11…` | `RT11` | yes |
| RT12 | LOCUS Ambiguous, P2 | Insufficient: R13 + `LOCUS=Ambiguous` | `test_rt12_rt13…` | engine-level only (no document produces it) | `RT12/engine` |
| RT13 | ENTRY Contradictory, P2 | Insufficient: R13 + `ENTRY=Contradictory` | `test_rt12_rt13…` | engine-level only | `RT13/engine` |

`python -m tests.conformance` (also run by `tests/test_conformance.py`) counts a rule as exercised only when it is **observed to trigger** in a passing case and an RT/NT as covered only when a declaring case runs and matches its expected verdict and rule set. It covers both predicates (R1–R13/RT1–RT13 and N1–N17/NT1–NT25) and reports gaps and failures.

## 7. Format behaviour and limitations

* **K4 per format.** CycloneDX: `dependencies[].dependsOn` edges (a `provides` edge is not a dependency). SPDX: relationships of the dependency family (`DEPENDS_ON`, `DEPENDENCY_OF`, `BUILD_/DEV_/OPTIONAL_/PROVIDED_/RUNTIME_/TEST_DEPENDENCY_OF`; names verified against the official SPDX 2.3 `spdx-schema.json`). `DESCRIBES`, `CONTAINS` and the rest are not K4. Relationship **direction is not interpreted and no traversal is performed**: the graph's shape cannot change any REACH state (A5), so computing paths would add unverified semantics for no effect on a verdict; `test_graph_topology_cannot_change_any_reach_state_or_verdict` pins this. Equivalent behaviour across formats is claimed only for this K4-presence fact.
* **No parser change was needed.** The parsers extract the edges verbatim; nothing was added to them, and they still extract no reachability facts (`test_the_parsers_still_extract_no_reachability_facts`).
* **No real analyser format is parsed.** K1–K3 reports, entry points, hazards and configuration come from the project's own input schema (G15 remains open for that reason).
* **Provenance.** The existing P0–P3 ladder and the settled detached-verification policy are reused unchanged; the evaluator performs no cryptography and claims none. Weaker provenance never improves a verdict (`test_weaker_provenance_never_improves_the_verdict_end_to_end`, whole-grid P-3 engine tests). List-level locators are not used for reachability: report items sit at fixed locators (`#/finding`, `#/entry_points`); G7/G3d stay open for the SBOM list-level question.
* **Soundness is recorded, not verified (A6).** A verified signature authenticates origin, not soundness (CE-R6); the outcome says so in its limitations.
* **Not covered.** GEN assertions, corroborating documents, C3 duplicate classification, BOM-Link self-link handling and outstanding SPDX conventions are untouched.
