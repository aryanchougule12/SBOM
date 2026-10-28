# Specification Addendum v0.2.3

This addendum is a changelog for one clarification of `docs/formal_specification_v0.2.md` that is present in that file (§3 Step 4, test cases RT12 and RT13 in §5.8, and the Resolved list in §7), plus the statement of the readings of §5 that the reachability implementation relies on and that are **not** amendments. The earlier addenda, `docs/spec_addendum_v0.2.1.md` and `docs/spec_addendum_v0.2.2.md`, are unchanged.

## 1. Unresolved-dimension ceiling for `Req(vulnerable_code_not_in_execute_path)` (the only amendment)

**Problem.** Addendum v0.2.2 stated the Step 4 unresolved-dimension ceiling generally but enumerated the governed states only for `Req(component_not_present)`; §7 recorded that the reachability predicate's governed states were not enumerated because §5 was not implemented. The same P-3 failure mode exists in §5.4: a required dimension in a state that fails its Supported condition and that no rule of the table governs gives the no-rule default Insufficient when no rule triggers, but gives Weak when a Weak-ceiling rule (for example R13 at a lower `PROV_REACH`) triggers, so *lowering* provenance would *raise* the verdict.

**Change.** The ceiling is applied to §5 with the governed states enumerated:

| Dimension | Governed by a rule (keeps the table's ceiling) | Ungoverned (imposes the Insufficient ceiling) |
|---|---|---|
| REACH | Present R1, Unknown R2, Contradictory R3, Incomplete R7 (non-exhaustive basis) or R8 (K1 basis), Ambiguous R8 | none (Absent from K1 is the Supported state) |
| LOCUS | Unknown R4, Incomplete R9 | Absent, Ambiguous, Contradictory |
| ENTRY | Unknown R5, Incomplete R10 | Absent, Ambiguous, Contradictory |
| BIND | Unknown or mismatched R6 | none |
| HAZ[class] | `Unmodeled` or `Unknown` after Step 1 R11 | none |
| CFG | undeclared, or the claim extends beyond the analyzed configurations R12 | declared but not comparable with any analysis (`not_compared`) |
| PROV_REACH | below P3 with REACH defined R13 | none |

The ceiling is not a rule: no code or rationale class is added, no rule of R1–R13 changes its trigger, ceiling, class, code or ordering, and no verdict category is added. Unresolved dimensions are reported in the `limitations` field as `<DIMENSION>=<State>` (`CFG=not_compared` for the CFG case). For inputs with no ungoverned state the result equals the literal Step 4.

**Tests.** RT12 (LOCUS `Ambiguous`, `PROV_REACH` = P2) and RT13 (ENTRY `Contradictory`, `PROV_REACH` = P2) in §5.8; `tests/test_reach_rules.py` (`test_an_ungoverned_locus_or_entry_state_caps_a_weak_result_at_insufficient`, `test_every_state_of_every_dimension_is_either_ok_governed_or_capped`, the whole-grid P-3 tests). RT1–RT11 are unchanged.

## 2. Readings of §5 relied on by the implementation (not amendments)

These resolve points where §5 is silent or ambiguous. Each is recorded in the issue register under G15 with its status. None changes a rule of §5.4, a verdict category or a code; each can only be removed by a documented replacement.

1. **K4 is never a positive observation.** §5.1 step 1 counts an item that "observes or asserts a path or execution of the locus". A dependency edge is not a call edge (§5.1, A5). R2's text ("if the only reachability-related evidence is K4") presupposes K4 evidence that leaves REACH Unknown, and RT2 pairs K4 with R2, not R1. A dependency edge, present or absent, therefore never contributes to REACH; its only effect is the code of R2 (`MISSING_EDGE_IS_UNKNOWN` instead of `NO_ANALYSIS`).
2. **Positive evidence with any K1 `Absent` is `Contradictory`.** §5.1 step 1 says "Positive plus a K1 `Absent` gives `Contradictory`"; the implementation applies it whenever any K1 report is `Absent`, so a third K1 report that is `Incomplete` cannot hide a conflict. Positive with K1 `Incomplete`/`Ambiguous` or K2/K3 items gives `Present` (§2 step 3, AG1).
3. **Step 2 applies whenever a K1 document exists.** A K1 report that reports nothing usable (`unknown`) makes step 2 apply and gives `Unknown`; the derivation does not fall through to step 3. This is the literal reading ("if K1 reports exist, aggregate them") and the conservative one (adding an uninformative K1 report can only lower the result).
4. **K3 no-hit counts at any EP; K2 negative needs EP ≥ P1.** Literal §5.1 step 3. K3 evidence at P0 therefore still gives `Incomplete`/R7 (and R13), while K2 at P0 is `Unknown`/R2 (RT11).
5. **`PROV_REACH` dependency set.** The documents "the REACH conclusion depends on" are those whose items produced the final state: the positive items (and the K1 absences they conflict with) for `Present`/`Contradictory`; the informative K1 items for the K1 basis; the K2/K3 items that produced the non-exhaustive basis. A K3 or K2 document that is ignored because K1 exists does not lower `PROV_REACH`.
6. **BIND (§5.1).** A document is bound when the artifact it declares it analysed matches S under the existing B2–B5 policy and the component it declares it concerns matches C (purl equality, else normalized name and version equality). A component difference gives `Unknown`, never `Mismatched` (B5). An unresolved C gives `Unknown` (register G1r).
7. **LOCUS.** Present only when the locus is declared an over-approximation; a possibly-under-approximate locus is `Incomplete`; an undeclared approximation is `Unknown`. No approximation is inferred from a VEX locus or from granularity.
8. **Hazard Step 1.** Excluded-by-evidence stands only with a `basis_ref` that names a supplied document bound to S whose EP at the basis locator is at least P1; otherwise it is downgraded to `Unknown` with `HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>`. Modeled-conservatively stands only when declared inside a K1 report, otherwise `Unknown`. An explicit evaluator claim governs its class.
9. **Hazard class tokens.** The closed enumeration of §5.3 (A4) is versioned `hazard-classes-v1`; the code tokens other than `REFLECTION` are this project's naming of the §5.3 list.

## 3. What is not claimed

The evidence a reachability run consumes (K1–K3 reports, locus approximation, entry-point completeness, hazard dispositions, deployment configuration) enters through the project's own input schema (`evidence/reach_inputs.py`); no real analyser output format is parsed (register G15). Analyser soundness claims are recorded as claimed (A6), a signature authenticates origin and not soundness (CE-R6), and a verdict states only that the recorded evidence meets the bar (P-1).
