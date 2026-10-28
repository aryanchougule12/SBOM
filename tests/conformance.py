"""Rule-conformance harness for both predicates (deterministic, dependency-free).

Enumerates the normative rules and transition tests of the formal specification, runs a table of
labelled cases through the **public evaluation entry points** (the pure engines and, for the
reachability predicate, the whole pipeline from a real parser fixture), and reports:

* which normative identifiers are *exercised* -- a rule counts only if it was **observed to trigger**
  in a passing case, a rule-test (NT/RT) counts only if a case declaring it ran and matched its
  expected verdict and rules -- never because a table says so;
* which identifiers have no case (missing rule-to-test mapping);
* which cases failed.

It is the project's own consistency check of code against the specification's tables. It is not a
benchmark: **every case is SYNTHETIC** (hand-built dimension states, or hand-built reachability
documents combined with the repository's parser fixtures). A passing harness says the engines
implement the written rules; it makes no claim about real-world accuracy, about the truth of any
claim (P-1) or about the soundness of any analyser.

Run it::

    python -m tests.conformance            # human-readable summary, exit status 1 on any gap or failure
    python -m tests.conformance --json     # the same report as deterministic JSON

``tests/test_conformance.py`` runs it under pytest, so there is one way of evaluating verdicts.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Callable, Optional

from evidence.cnp_rules import BindState, CnpInputs, GenState, SeparateContentBasis, evaluate_cnp
from evidence.reach_evaluator import ReachOutcome
from evidence.reach_rules import (
    REACH_RULES,
    CfgState,
    HazardClass,
    HazardDisposition,
    HazardInput,
    ReachBasis,
    evaluate_reach,
)
from model import ArtifactKind, EvidenceState as S, ProvenanceLevel as P
from reports.verdict import Verdict
from tests import analysis_eval
from tests.reach_support import RT_PIPELINE_CASES, all_hazards, baseline_hazards, excluded, inputs as reach_inputs, run

NT_IDS = tuple(f"NT{n}" for n in range(1, 26))
RT_IDS = tuple(f"RT{n}" for n in range(1, 14))  # RT12-RT13: addendum v0.2.3 (the unresolved-dimension ceiling)
CNP_RULE_IDS = tuple(f"N{n}" for n in range(1, 18))
REACH_RULE_IDS = tuple(r.rule_id for r in REACH_RULES)
SUPPORTED, WEAK, INSUFFICIENT = Verdict.SUPPORTED, Verdict.WEAK, Verdict.INSUFFICIENT


@dataclass(frozen=True)
class Case:
    """A labelled conformance case. ``tests`` are the NT/RT identifiers it realises, ``layer`` says
    what it runs through (``engine`` or ``pipeline``). ``expected_rules`` is the exact set of rule
    ids that must trigger. ``synthetic`` is always True: it is stated, not assumed."""

    case_id: str
    predicate: str
    layer: str
    tests: tuple[str, ...]
    expected_verdict: Verdict
    expected_rules: tuple[str, ...]
    run: Callable[[], tuple[Verdict, tuple[str, ...]]]
    synthetic: bool = True


# ---- CNP (section 4.7) ------------------------------------------------------------------------------------------

def _cnp(**overrides) -> Callable[[], tuple[Verdict, tuple[str, ...]]]:
    base = dict(artifact_kind=ArtifactKind.SOURCE, inv=S.PRESENT, match=S.ABSENT, decl=S.PRESENT,
                bind=BindState.MATCHED, prov_sbom=P.P3, prov_decl=P.P3)
    base.update(overrides)

    def go():
        evaluation = evaluate_cnp(CnpInputs(**base))
        return evaluation.result.verdict, tuple(dict.fromkeys(evaluation.rule_ids))
    return go


_C = ArtifactKind.CONTAINER
_basis = lambda ep, meets=True: SeparateContentBasis(ep=ep, meets_basis_criteria=meets)  # noqa: E731

CNP_CASES = (
    Case("NT1", "cnp", "engine", ("NT1",), SUPPORTED, (), _cnp()),
    Case("NT2", "cnp", "engine", ("NT2",), WEAK, ("N11", "N12"), _cnp(prov_sbom=P.P1, prov_decl=P.P1)),
    Case("NT3", "cnp", "engine", ("NT3",), WEAK, ("N11",), _cnp(prov_decl=P.P1)),
    Case("NT4", "cnp", "engine", ("NT4",), WEAK, ("N6",), _cnp(decl=S.INCOMPLETE)),
    Case("NT5", "cnp", "engine", ("NT5",), WEAK, ("N8",), _cnp(match=S.AMBIGUOUS)),
    Case("NT6", "cnp", "engine", ("NT6",), INSUFFICIENT, ("N4",), _cnp(inv=S.CONTRADICTORY)),
    Case("NT7", "cnp", "engine", ("NT7",), INSUFFICIENT, ("N5", "N12"), _cnp(decl=S.UNKNOWN, prov_sbom=P.P0, prov_decl=P.P0)),
    Case("NT8", "cnp", "engine", ("NT8",), WEAK, ("N7", "N12"), _cnp(decl=S.UNKNOWN, prov_sbom=P.P1, prov_decl=P.P1)),
    Case("NT9", "cnp", "engine", ("NT9",), WEAK, ("N14",), _cnp(artifact_kind=_C, gen=GenState.MANIFEST_ONLY)),
    Case("NT10", "cnp", "engine", ("NT10",), SUPPORTED, (), _cnp(artifact_kind=_C, gen=GenState.MANIFEST_ONLY, separate_basis=_basis(P.P3))),
    Case("NT11", "cnp", "engine", ("NT11",), WEAK, ("N15",), _cnp(artifact_kind=_C, gen=GenState.UNKNOWN)),
    Case("NT12", "cnp", "engine", ("NT12",), WEAK, ("N14",), _cnp(artifact_kind=_C, gen=GenState.MANIFEST_ONLY, separate_basis=_basis(P.P3, False))),
    Case("NT13", "cnp", "engine", ("NT13",), INSUFFICIENT, ("N1",), _cnp(match=S.PRESENT)),
    Case("NT14", "cnp", "engine", ("NT14",), WEAK, ("N16",), _cnp(artifact_kind=_C, gen=GenState.MANIFEST_ONLY, separate_basis=_basis(P.P1))),
    Case("NT15", "cnp", "engine", ("NT15",), SUPPORTED, (), _cnp(artifact_kind=_C, gen=GenState.CONTENT_BASED)),
    Case("NT16", "cnp", "engine", ("NT16",), WEAK, ("N15",), _cnp(artifact_kind=_C, gen=GenState.UNKNOWN)),
    Case("NT17", "cnp", "engine", ("NT17",), WEAK, ("N15",), _cnp(artifact_kind=_C, gen=GenState.UNKNOWN)),
    Case("NT18", "cnp", "engine", ("NT18",), INSUFFICIENT, ("N17",), _cnp(match=S.CONTRADICTORY)),
    Case("NT19", "cnp", "engine", ("NT19",), INSUFFICIENT, ("N1",), _cnp(match=S.PRESENT)),
    Case("NT20", "cnp", "engine", ("NT20",), INSUFFICIENT, ("N4",), _cnp(inv=S.CONTRADICTORY)),
    Case("NT21", "cnp", "engine", ("NT21",), INSUFFICIENT, ("N4", "N17"), _cnp(inv=S.CONTRADICTORY, match=S.CONTRADICTORY)),
    Case("NT22", "cnp", "engine", ("NT22",), INSUFFICIENT, ("N12",), _cnp(match=S.UNKNOWN, prov_sbom=P.P2)),
    Case("NT23", "cnp", "engine", ("NT23",), INSUFFICIENT, ("N12",), _cnp(decl=S.CONTRADICTORY, prov_sbom=P.P2)),
    Case("NT24", "cnp", "engine", ("NT24",), INSUFFICIENT, ("N12",), _cnp(inv=S.INCOMPLETE, prov_sbom=P.P2)),
    Case("NT25", "cnp", "engine", ("NT25",), INSUFFICIENT, ("N12",), _cnp(decl=S.AMBIGUOUS, prov_sbom=P.P2)),
    # rules that no NT isolates by itself
    Case("N2", "cnp", "engine", (), INSUFFICIENT, ("N2",), _cnp(inv=S.UNKNOWN)),
    Case("N3", "cnp", "engine", (), INSUFFICIENT, ("N3",), _cnp(bind=BindState.UNKNOWN)),
    Case("N9", "cnp", "engine", (), WEAK, ("N9",), _cnp(match=S.INCOMPLETE)),
    Case("N10", "cnp", "engine", (), WEAK, ("N10",), _cnp(prov_decl=P.P0)),
    Case("N13", "cnp", "engine", (), WEAK, ("N13",), _cnp(provenance_metadata_contradiction=True)),
)


# ---- reachability (section 5.8) ----------------------------------------------------------------------------------------

def _engine(**changes) -> Callable[[], tuple[Verdict, tuple[str, ...]]]:
    def go():
        evaluation = evaluate_reach(reach_inputs(**changes))
        return evaluation.result.verdict, evaluation.rule_ids
    return go


_UNKNOWN_REACH = dict(reach=S.UNKNOWN, reach_basis=None, prov_reach=None)
_NO_HAZARDS: dict = {}
_open = lambda hc, claim: {**baseline_hazards(), hc: claim}  # noqa: E731

REACH_ENGINE_CASES = (
    Case("RT1/engine", "reach", "engine", ("RT1",), SUPPORTED, (), _engine()),
    Case("RT2/engine", "reach", "engine", ("RT2",), INSUFFICIENT, ("R2", "R5", "R11"),
         _engine(**_UNKNOWN_REACH, only_k4_evidence=True, entry=S.UNKNOWN, hazards=_NO_HAZARDS)),
    Case("RT3/engine", "reach", "engine", ("RT3",), WEAK, ("R11",), _engine(hazards=_open(HazardClass.REFLECTION, HazardInput()))),
    Case("RT4/engine", "reach", "engine", ("RT4",), INSUFFICIENT, ("R3",), _engine(reach=S.CONTRADICTORY, reach_basis=None)),
    Case("RT5/engine", "reach", "engine", ("RT5",), WEAK, ("R8",), _engine(reach=S.INCOMPLETE, reach_basis=ReachBasis.K1)),
    Case("RT6/engine", "reach", "engine", ("RT6",), WEAK, ("R8",), _engine(reach=S.AMBIGUOUS, reach_basis=ReachBasis.K1)),
    Case("RT7/engine", "reach", "engine", ("RT7",), WEAK, ("R11",), _engine(hazards=_open(HazardClass.REFLECTION, excluded(P.P0)))),
    Case("RT8/engine", "reach", "engine", ("RT8",), WEAK, ("R13",), _engine(prov_reach=P.P2)),
    Case("RT9/engine", "reach", "engine", ("RT9",), WEAK, ("R7",),
         _engine(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE, hazards=all_hazards(lambda: excluded(P.P1)))),
    Case("RT10/engine", "reach", "engine", ("RT10",), WEAK, ("R7",),
         _engine(reach=S.INCOMPLETE, reach_basis=ReachBasis.NON_EXHAUSTIVE, hazards=all_hazards(lambda: excluded(P.P1)))),
    Case("RT11/engine", "reach", "engine", ("RT11",), INSUFFICIENT, ("R2", "R5", "R11"),
         _engine(**_UNKNOWN_REACH, only_k4_evidence=False, entry=S.UNKNOWN, hazards=_NO_HAZARDS)),
    # RT12-RT13 (addendum v0.2.3): ungoverned LOCUS/ENTRY states cap a Weak result at Insufficient
    Case("RT12/engine", "reach", "engine", ("RT12",), INSUFFICIENT, ("R13",), _engine(locus=S.AMBIGUOUS, prov_reach=P.P2)),
    Case("RT13/engine", "reach", "engine", ("RT13",), INSUFFICIENT, ("R13",), _engine(entry=S.CONTRADICTORY, prov_reach=P.P2)),
    # one isolating case per rule (R-cases not isolated by an RT)
    Case("R1/engine", "reach", "engine", (), INSUFFICIENT, ("R1",), _engine(reach=S.PRESENT, reach_basis=None)),
    Case("R4/engine", "reach", "engine", (), INSUFFICIENT, ("R4",), _engine(locus=S.UNKNOWN)),
    Case("R6/engine", "reach", "engine", (), INSUFFICIENT, ("R6",), _engine(bind=BindState.MISMATCHED)),
    Case("R9/engine", "reach", "engine", (), WEAK, ("R9",), _engine(locus=S.INCOMPLETE)),
    Case("R10/engine", "reach", "engine", (), WEAK, ("R10",), _engine(entry=S.INCOMPLETE)),
    Case("R12/engine", "reach", "engine", (), WEAK, ("R12",), _engine(cfg=CfgState.EXTENDS_BEYOND)),
    Case("R11/modeled-outside-k1", "reach", "engine", (), WEAK, ("R11",),
         _engine(hazards=_open(HazardClass.NATIVE_FFI, HazardInput(HazardDisposition.MODELED_CONSERVATIVELY)))),
)


def _pipeline(kind: str, pipeline_case) -> Callable[[], tuple[Verdict, tuple[str, ...]]]:
    def go():
        outcome = run(kind, pipeline_case.data(), verification=pipeline_case.verification())
        if not isinstance(outcome, ReachOutcome):
            raise AssertionError(f"expected an outcome, got a refusal: {outcome}")
        return outcome.result.verdict, outcome.evaluation.rule_ids
    return go


REACH_PIPELINE_CASES = tuple(
    Case(f"{c.case_id}/pipeline-{kind}", "reach", "pipeline", (c.case_id,), c.verdict, c.rules, _pipeline(kind, c))
    for kind in ("cdx", "spdx") for c in RT_PIPELINE_CASES
)

PREDICATES = {
    "cnp": dict(title="Req(component_not_present)", rules=CNP_RULE_IDS, tests=NT_IDS, cases=CNP_CASES),
    "reach": dict(title="Req(vulnerable_code_not_in_execute_path)", rules=REACH_RULE_IDS, tests=RT_IDS,
                  cases=REACH_ENGINE_CASES + REACH_PIPELINE_CASES),
}


# ---- running and reporting --------------------------------------------------------------------------------------------------

def run_case(case: Case) -> dict:
    """Run one case. Never raises: an exception is a failed case with its message."""
    try:
        verdict, rules = case.run()
        rules = tuple(rules)
        ok = verdict is case.expected_verdict and rules == tuple(case.expected_rules)
        return {"case": case.case_id, "layer": case.layer, "ok": ok, "synthetic": case.synthetic,
                "verdict": verdict.value, "expected_verdict": case.expected_verdict.value,
                "rules": list(rules), "expected_rules": list(case.expected_rules)}
    except Exception as error:  # noqa: BLE001 - a harness reports, it does not crash
        return {"case": case.case_id, "layer": case.layer, "ok": False, "synthetic": case.synthetic,
                "error": f"{type(error).__name__}: {error}"}


def build_report() -> dict:
    """The deterministic report: per predicate, per normative rule and test, and the gaps."""
    report: dict = {"synthetic_only": True,
                    "disclaimer": "All cases are synthetic. The report shows that the engines implement the written "
                                  "rule tables; it makes no claim about real-world accuracy (P-1).",
                    "predicates": {}}
    for key in sorted(PREDICATES):
        spec = PREDICATES[key]
        results = [run_case(case) for case in spec["cases"]]
        by_case = {case.case_id: result for case, result in zip(spec["cases"], results)}
        observed: dict[str, set] = {rule: set() for rule in spec["rules"]}
        for case, result in zip(spec["cases"], results):
            if result["ok"]:
                for rule in result["rules"]:
                    observed.setdefault(rule, set()).add(case.case_id)
        tests: dict[str, list] = {test: [] for test in spec["tests"]}
        for case in spec["cases"]:
            for test in case.tests:
                tests.setdefault(test, []).append(case.case_id)
        test_status = {}
        for test in spec["tests"]:
            ids = tests[test]
            passed = [c for c in ids if by_case[c]["ok"]]
            test_status[test] = {"cases": sorted(ids), "passed": len(passed), "covered": bool(passed) and len(passed) == len(ids)}
        rule_status = {rule: {"exercised_by": sorted(observed[rule]), "exercised": bool(observed[rule])} for rule in spec["rules"]}
        report["predicates"][key] = {
            "title": spec["title"],
            "cases": len(results),
            "failed_cases": sorted(r["case"] for r in results if not r["ok"]),
            "rules": rule_status,
            "tests": test_status,
            "missing_rules": [r for r in spec["rules"] if not rule_status[r]["exercised"]],
            "missing_tests": [t for t in spec["tests"] if not test_status[t]["covered"]],
            "results": results,
        }
    corpus = analysis_eval.build_report()  # the analyzer-artifact corpus is evaluated by the same public entry points
    report["analysis_corpus"] = {"cases": corpus["totals"]["cases"], "agree": corpus["totals"]["agree"],
                                 "disagree": corpus["totals"]["disagree"], "fixture_problems": corpus["totals"]["fixture_problems"],
                                 "note": "controlled conformance against reviewed expectations; see python -m tests.analysis_eval"}
    report["ok"] = all(not p["failed_cases"] and not p["missing_rules"] and not p["missing_tests"]
                       for p in report["predicates"].values()) and not corpus["totals"]["disagree"] and not corpus["totals"]["fixture_problems"]
    return report


def render(report: dict) -> str:
    lines = ["Rule-conformance harness (SYNTHETIC cases only; no real-world accuracy is claimed)"]
    for key in sorted(report["predicates"]):
        p = report["predicates"][key]
        rules_hit = sum(1 for r in p["rules"].values() if r["exercised"])
        tests_hit = sum(1 for t in p["tests"].values() if t["covered"])
        lines.append(f"\n{p['title']}: {p['cases']} cases, {len(p['failed_cases'])} failed")
        lines.append(f"  rules exercised (observed to trigger): {rules_hit}/{len(p['rules'])}"
                     + (f"; missing: {', '.join(p['missing_rules'])}" if p["missing_rules"] else ""))
        lines.append(f"  rule tests covered:                    {tests_hit}/{len(p['tests'])}"
                     + (f"; missing: {', '.join(p['missing_tests'])}" if p["missing_tests"] else ""))
        for failed in p["failed_cases"]:
            lines.append(f"  FAILED: {failed}")
    corpus = report["analysis_corpus"]
    lines.append(f"\nanalyzer-artifact corpus: {corpus['agree']}/{corpus['cases']} cases agree with the reviewed expectations "
                 f"({corpus['fixture_problems']} fixture-attribution problems)")
    lines.append("\nresult: " + ("OK" if report["ok"] else "GAPS OR FAILURES"))
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True) if "--json" in args else render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
