# Metamorphic validation (Phase III foundation)

Code: `tests/metamorphic/`. Run: `python -m tests.metamorphic` (writes `evaluation_results/metamorphic_report.{json,md}`), `--check` (stale or violated => exit 1);
it is a stage of `python -m tests.validate_all`. Checkpoint history: `docs/metamorphic_checkpoints.md`. All numbers are in the generated report; none are copied here.

## Method
A **scenario** is a complete evaluation input held as JSON (SBOM in CycloneDX or SPDX, OpenVEX, evaluator profile, optional detached verification, optional strict
reachability evidence). A **mutation operator** edits one kind of evidence in a deep copy. Both scenario and mutant are evaluated through the public entry point
(`evidence.sufficiency.evaluate_finding`); a **relation** compares the two observations (verdict, codes, rationale, dimension and item states). A mutant that the
parsers or the profile reject is an `input_error`, and one the evaluator refuses is `refused`: neither has a verdict, so neither can have raised one.

## Relations (the specification's section 6 invariants)
| Id | Statement | Applied to | Dissertation name |
|---|---|---|---|
| M-1 | degrading any state, provenance or hazard disposition never raises a verdict | delete, degrade operators | to be confirmed by the author |
| M-2 | deleting evidence never turns Unknown into Absent | delete operators | to be confirmed |
| M-3 | the same input gives the same result | every base and every mutant, evaluated twice | to be confirmed |
| M-4 | injecting a positive observation (a match, a path) gives Insufficient | inject-positive operators | to be confirmed |
| M-5 | every triggered rule appears in the rationale | every base and every mutant | to be confirmed |
| M-6 | changing only free text never changes the verdict or codes | neutral operators | to be confirmed |

The Phase-I report names MR1-MR5 without defining them operationally; the mapping above is left to the author. **Candidate MR5** (monotonicity of *supporting* evidence) is
investigated, not assumed (`candidates.py`).

## Operator families
* **Neutral** (free-text SBOM descriptions, VEX impact statements, evaluator labels).
* **component_not_present** (CycloneDX and SPDX): remove dependency edges, components, the completeness declaration, versions, strong identifiers, the subject digest, tool identity,
  timestamp, the verification result, the evaluator's inventory assertion, the VEX justification; declare the composition incomplete/unknown; alter versions or the subject digest;
  narrow verified coverage; add a dangling edge or an unrelated orphan; inject the target component (with an edge, as an orphan, nested).
* **vulnerable_code_not_in_execute_path**: remove the K1 report, entry points, modeled hazards, analysed configurations, the hazard basis or dispositions, the locus, the configuration,
  the declared artifact digest, tool version, timestamp, the verification; withdraw the coverage claim; make the K1 report incomplete/ambiguous/unknown; incomplete entry points;
  under-approximate locus; wrong target, artifact digest or configuration; narrow verification; inject a positive K1, K2, K3 or unattributed observation.

## Results and findings (see the generated report for counts)
* No relation is violated by any pair, and every base evaluation is deterministic with every triggered code in its rationale. A rigged-engine test proves that the harness reports a
  violation and fails the check.
* Each condition of the Supported requirements is *necessary*: removing or degrading any single one of them (CNP: component present, declaration, binding, attribution, verification;
  reachability: K1 absence, entry points, hazards, configuration, binding, provenance) lowers the fully supported scenario.
* Some operators never change a verdict on these scenarios (dependency edges, versions or identifiers of *other* components, an unrelated orphan): the target's absence rests on a complete,
  bound, attributed inventory, not on dependency edges (a dependency edge is not membership). The report lists them; the effectiveness test pins the set.
* **Candidate MR5 is not universally valid**: adding a bound K1 absence of lower provenance to a Supported finding lowers it to Weak (minimum-provenance rule, section 1.2 step 5, R13).
  This is the specification's rule, not a defect, but it must be stated in the dissertation: evidence added can lower a verdict, evidence removed can raise it back.

## Limits (what this does not show)
Six scenarios from committed synthetic fixtures; single-operator mutations (no operator composition); synthetic only. It shows the implementation obeys the written invariants on these
mutations. It is not an accuracy, prevalence or real-world result, and says nothing about the correctness of the specification itself.
