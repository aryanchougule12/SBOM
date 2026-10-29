"""Reproducible research-evaluation report over the committed corpus (deterministic; no accuracy claim).

    python -m tests.research_report            # print the summary and write evaluation_results/research_report.{json,md}
    python -m tests.research_report --check    # fail if the committed files are stale

Everything here is computed from ``tests.analysis_eval`` (the corpus: A upstream examples, B synthetic, L authentic CodeQL output
with the runner's records) and ``tests.conformance`` (the rule tables). Every aggregate states its denominator and counts each case
once, except where a table is explicitly "per rule" or "per fact" (then it says what the unit is).

What it is: controlled conformance of the pipeline against hand-reviewed expectations, plus a *weakening analysis* (the same case with
its analysis-run record degraded in one way must never obtain a better verdict). What it is not: it reports no accuracy, precision,
recall or false-positive/false-negative rate, because no independently labelled ground truth exists. Category L shows integration
behaviour on those particular artifacts only, not detection accuracy of CodeQL.
"""

from __future__ import annotations

import copy
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from evidence.analysis_run import parse_analysis_run_data
from tests import analysis_eval, conformance

OUT = analysis_eval.DEFAULT_OUT
VERDICT_RANK = {"Insufficient": 0, "Weak": 1, "Supported": 2}
COVERAGE_FACTS = ("binding_established", "tool_declared", "process_completed", "extraction_completed", "language_scope", "locus_included",
                  "query_suite_completed", "claim_semantics", "entry_points_enumerated", "exclusions_accounted", "suppressions_accounted",
                  "no_partial_indicators", "no_undecidable_evidence", "coverage_claim_declared")


def _weakenings() -> dict:
    """One degradation each of an analysis-run record. None may improve a verdict."""
    def edit(path, value):
        def apply(data):
            node = data
            keys = path.split(".")
            for key in keys[:-1]:
                node = node[key]
            node[keys[-1]] = value
            return data
        return apply

    def failed_analysis(data):
        for stage in data["stages"]:
            if stage["role"] == "analysis":
                stage.update(status="failed", exit_code=1)
        return data

    return {
        "record dropped": None,
        "output hash altered": edit("outputs", [{"path": "x", "sha256": "0" * 64, "size": 1}]),
        "tree digest altered": edit("source.tree_digest", "git-tree:" + "cd" * 20),
        "working tree dirty": edit("source.worktree_clean", False),
        "source changed during run": edit("source.changed_during_run", True),
        "analysis stage failed": failed_analysis,
        "entry-point inventory incomplete": edit("scope.entry_points.complete", False),
        "coverage claim removed": edit("coverage_claim", None),
        "tool version removed": edit("tool.version", None),
        "partial-analysis indicator": edit("scope.partial_indicators", ["WEAKENED"]),
    }


def _primary_reason(row: dict) -> str:
    """Exactly one reason per inconclusive case (the first that applies, in this order)."""
    a = row["actual"]
    if a["outcome"] == "refused":
        return f"refused: {a['cause']}"
    if a["verdict"] != "Insufficient":
        return "not inconclusive"
    if a["reach"] == "Present":
        return "a path to the locus is recorded (contradicts the claim)"
    if a["reach"] == "Contradictory":
        return "a recorded path conflicts with a supplied K1 absence"
    if "UNDECIDABLE_FLOW" in a["diagnostic_codes"] or "UNDECIDABLE_CALL_EDGE" in a["diagnostic_codes"]:
        return "unresolved potentially relevant evidence"
    assessed = a.get("assessment")
    if assessed is None or assessed["record_id"] is None:
        return "no analysis-run record: an artifact alone states no coverage"
    if assessed["binding"] != "established":
        return f"run binding {assessed['binding']}"
    prevented = [c for c in assessed["preventing"]]
    return f"coverage not established: {prevented[0]}" if prevented else "other"


def build() -> dict:
    manifest = analysis_eval.load_manifest()
    corpus = analysis_eval.build_report()
    rows = corpus["cases"]
    total = len(rows)
    assert len({r["id"] for r in rows}) == total
    by_id = {c["id"]: c for c in manifest["cases"]}
    report: dict[str, Any] = {
        "kind": "research-evaluation-report",
        "disclaimer": ("Controlled conformance and a weakening analysis over a hand-reviewed corpus. Category B is synthetic; category A is upstream "
                       "format examples; category L is unedited output of live CodeQL 2.27.3 runs (integration behaviour for those artifacts only). "
                       "No accuracy, precision, recall or false-positive/false-negative rate is reported: no independently labelled ground truth exists."),
        "corpus": {"cases": total, "agree": corpus["totals"]["agree"], "disagree": corpus["totals"]["disagree"],
                   "fixture_attribution_problems": corpus["totals"]["fixture_problems"]},
        "categories": {},
    }
    for category in sorted({r["category"] for r in rows}):
        part = [r for r in rows if r["category"] == category]
        evaluated = [r for r in part if r["actual"]["outcome"] == "evaluated"]
        refused = [r for r in part if r["actual"]["outcome"] == "refused"]
        with_artifact = [r for r in part if r["file"]]
        with_record = [r for r in evaluated if (r["actual"].get("assessment") or {}).get("record_id") is not None]
        inconclusive = [r for r in part if r["actual"]["outcome"] == "refused" or r["actual"]["verdict"] == "Insufficient"]
        facts: dict[str, Counter] = {f: Counter() for f in COVERAGE_FACTS}
        for r in with_record:
            for name, status in r["actual"]["assessment"]["coverage"].items():
                facts[name][status] += 1
        derived = sorted(r["id"] for r in with_record if r["actual"]["assessment"]["negative_derived"])
        report["categories"][category] = {
            "label": corpus["categories"][category]["label"],
            "cases": len(part), "cases_with_an_artifact": len(with_artifact),
            "by_format": dict(sorted(Counter(r["format"] for r in with_artifact).items())),
            "evaluated": len(evaluated), "refused": len(refused),
            "refusals_by_cause": dict(sorted(Counter(r["actual"]["cause"] for r in refused).items())),
            "evidence_states_of_evaluated_cases": {"denominator": len(evaluated), "REACH": dict(sorted(Counter(r["actual"]["reach"] for r in evaluated).items())),
                                                  "BIND": dict(sorted(Counter(r["actual"]["bind"] for r in evaluated).items()))},
            "verdicts_of_evaluated_cases": {"denominator": len(evaluated), **dict(sorted(Counter(r["actual"]["verdict"] for r in evaluated).items()))},
            "supported_verdicts": {"count": sum(r["actual"]["verdict"] == "Supported" for r in evaluated),
                                   "resting_on_a_caller_supplied_verified_k1_report": sum(
                                       1 for r in evaluated if r["actual"]["verdict"] == "Supported"
                                       and by_id[r["id"]].get("base", manifest["defaults"]["base"]) == "supported_k1"),
                                   "note": "no Supported verdict rests on an artifact or an analysis-run record"},
            "inconclusive": {"definition": "refused, or evaluated with verdict Insufficient", "count": len(inconclusive), "denominator": len(part),
                             "one_primary_reason_per_case": dict(sorted(Counter(_primary_reason(r) for r in inconclusive).items()))},
            "analysis_run_records": {"evaluated_cases_with_a_record": len(with_record), "denominator_for_facts": len(with_record),
                                     "binding": dict(sorted(Counter(r["actual"]["assessment"]["binding"] for r in with_record).items())),
                                     "coverage_facts_per_fact": {f: dict(sorted(c.items())) for f, c in facts.items() if c},
                                     "negative_k1_derived": {"count": len(derived), "denominator": len(with_record), "case_ids": derived,
                                                             "resulting_verdicts": dict(sorted(Counter(
                                                                 r["actual"]["verdict"] for r in with_record if r["id"] in derived).items()))}},
            "expected_vs_actual": {"agree": sum(r["agree"] for r in part), "disagree": sum(not r["agree"] for r in part), "cases": len(part)},
        }
    assert sum(c["cases"] for c in report["categories"].values()) == total
    assert all(c["supported_verdicts"]["count"] == c["supported_verdicts"]["resting_on_a_caller_supplied_verified_k1_report"] for c in report["categories"].values())
    assert all(c["evaluated"] + c["refused"] == c["cases"] for c in report["categories"].values())
    report["authentic_joern"] = "0 artifacts: no authentic Joern output was obtained; every GraphML case is synthetic (category B)."

    # weakening analysis: every evaluated case with an analysis-run record x every weakening
    weakenings = _weakenings()
    defaults = manifest["defaults"]
    results: Counter = Counter()
    per_weakening: dict[str, Counter] = {name: Counter() for name in weakenings}
    raised: list[str] = []
    verdict_changed: Counter = Counter()
    pairs = 0
    for case, row in zip(manifest["cases"], rows):
        if row["actual"]["outcome"] != "evaluated" or not case.get("run"):
            continue
        if (row["actual"].get("assessment") or {}).get("record_id") is None:
            continue
        base_rank = VERDICT_RANK[row["actual"]["verdict"]]
        dropped = analysis_eval.run_case(case, defaults, run=None)
        dropped_rank = VERDICT_RANK[dropped["verdict"]] if dropped["outcome"] == "evaluated" else -1
        for name, edit in weakenings.items():
            if edit is None:
                weak = analysis_eval.run_case(case, defaults, run=None)
            else:
                data = copy.deepcopy(json.loads((analysis_eval.ANALYSIS_DIR / case["run"]).read_text()))
                weak = analysis_eval.run_case(case, defaults, run=parse_analysis_run_data(edit(data)))
            pairs += 1
            if weak["outcome"] == "refused":
                kind = "refused (no verdict)"
            else:
                after = VERDICT_RANK[weak["verdict"]]
                if after > base_rank:
                    # A record-derived report that is itself weaker than a supplied one lowers the aggregate (minimum provenance, §1.2 step 5);
                    # degrading the record then returns the verdict to what the evaluation gives without the record. That is not an improvement
                    # by weakening: it is the no-record verdict. Anything above both is.
                    kind = "returned to the no-record verdict" if after <= dropped_rank else "raised"
                else:
                    kind = "lowered" if after < base_rank else "unchanged"
                if after != base_rank:
                    verdict_changed[f"{row['actual']['verdict']} -> {weak['verdict']}"] += 1
            if kind == "raised":
                raised.append(f"{case['id']} / {name}")
            results[kind] += 1
            per_weakening[name][kind] += 1
    report["weakening_analysis"] = {
        "unit": "(evaluated case with an analysis-run record) x (one weakening of that record)",
        "cases": sum(1 for r in rows if r["actual"]["outcome"] == "evaluated" and (r["actual"].get("assessment") or {}).get("record_id")),
        "weakenings": list(weakenings), "pairs": pairs, "results": dict(sorted(results.items())),
        "verdict_changes": dict(sorted(verdict_changed.items())), "raised_pairs": sorted(raised),
        "per_weakening": {k: dict(sorted(v.items())) for k, v in per_weakening.items()},
        "invariant": ("a weakened record never yields a verdict better than the larger of (the original verdict, the verdict without the record); "
                      "'raised' must be 0. 'returned to the no-record verdict' counts the pairs where a record-derived K1 absence of lower provenance had "
                      "lowered a supplied K1 absence (minimum provenance, §1.2 step 5) and weakening the record removed that effect."),
    }
    assert sum(results.values()) == pairs

    conf = conformance.build_report()
    report["conformance"] = {
        "synthetic_only": conf["synthetic_only"], "ok": conf["ok"],
        "predicates": {key: {"title": p["title"], "cases": p["cases"], "failed_cases": len(p["failed_cases"]),
                             "rules_exercised": sum(1 for r in p["rules"].values() if r["exercised"]), "rules": len(p["rules"]),
                             "rule_tests_covered": sum(1 for t in p["tests"].values() if t["covered"]), "rule_tests": len(p["tests"])}
                       for key, p in conf["predicates"].items()},
        "analysis_corpus": conf["analysis_corpus"],
    }
    report["limitations"] = LIMITATIONS
    return report


LIMITATIONS = [
    "The corpus is hand-built or small: 9 upstream examples, 12 authentic CodeQL cases from 6 tiny JavaScript runs, the rest synthetic. Results show behaviour, not prevalence.",
    "Expected outcomes were derived by hand from the rules; they validate the implementation against that reading of the specification, not the specification against reality.",
    "The link between the analysed source and the assessed artifact S is an evaluator statement in every case (SOURCE_TO_ARTIFACT_LINK_EVALUATOR_ASSERTED).",
    "An analysis-run record is an unauthenticated assertion; a record-derived absence rests on its declared coverage claim (A6) and is capped at Weak. It is not stronger than a caller-authored strict-input K1 report with the same claim.",
    "No supported tool enumerates entry points; entry-point completeness is always a declaration. No stock CodeQL query is a locus-reachability analysis.",
    "No authentic Joern output was obtained; all GraphML cases are synthetic and follow the exporter source.",
    "Aggregation of several K1 reports takes the minimum provenance (§1.2 step 5), so adding a lower-provenance report can lower a verdict (case U12b); this is the specification's rule, not a defect, and it is why the weakening invariant is stated against the no-record verdict too.",
    "Cryptographic verification is not implemented; verification results are consumed, not produced.",
    "Open specification decisions (G7, G8/U-9, G15 conventions, G17, AI/AR conventions) are unconfirmed implementation choices; see docs/open_issues_register.md.",
]


def render_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def render_markdown(report: dict) -> str:
    c = report["corpus"]
    lines = ["# Research evaluation report (generated by `python -m tests.research_report`)", "", report["disclaimer"], "",
             f"Corpus: **{c['cases']}** cases; expected vs actual: {c['agree']} agree, {c['disagree']} disagree; fixture-attribution problems {c['fixture_attribution_problems']}.", "",
             "## Per category", "",
             "| Category | Cases | With artifact | Formats | Evaluated | Refused | Verdicts of evaluated | Inconclusive | Run records | Negative K1 derived |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for key, p in report["categories"].items():
        verdicts = ", ".join(f"{k} {v}" for k, v in p["verdicts_of_evaluated_cases"].items() if k != "denominator")
        runs = p["analysis_run_records"]
        lines.append(f"| {key}: {p['label']} | {p['cases']} | {p['cases_with_an_artifact']} | {', '.join(f'{k} {v}' for k, v in p['by_format'].items())} | "
                     f"{p['evaluated']} | {p['refused']} | {verdicts} (Supported: all {p['supported_verdicts']['resting_on_a_caller_supplied_verified_k1_report']} rest on a supplied verified K1 report) | {p['inconclusive']['count']}/{p['inconclusive']['denominator']} | "
                     f"{runs['evaluated_cases_with_a_record']} | {runs['negative_k1_derived']['count']}/{runs['negative_k1_derived']['denominator']} |")
    for key, p in report["categories"].items():
        lines += ["", f"### Category {key}", "", f"REACH states of evaluated cases (n={p['evidence_states_of_evaluated_cases']['denominator']}): {p['evidence_states_of_evaluated_cases']['REACH']}", "",
                  f"Refusals (n={p['refused']}): {p['refusals_by_cause'] or 'none'}", "", "Inconclusive cases, one primary reason each:", ""]
        lines += [f"* {reason}: {n}" for reason, n in p["inconclusive"]["one_primary_reason_per_case"].items()]
        runs = p["analysis_run_records"]
        if runs["evaluated_cases_with_a_record"]:
            lines += ["", f"Coverage facts over the {runs['denominator_for_facts']} evaluated cases with a record (one count per case and fact):", "",
                      "| Fact | " + " | ".join(("established", "not_established", "contradicted", "not_recorded")) + " |", "|---|---|---|---|---|"]
            for fact, counts in runs["coverage_facts_per_fact"].items():
                lines.append(f"| {fact} | " + " | ".join(str(counts.get(s, 0)) for s in ("established", "not_established", "contradicted", "not_recorded")) + " |")
            lines += ["", f"Negative K1 derived: {runs['negative_k1_derived']['count']} of {runs['negative_k1_derived']['denominator']} (verdicts {runs['negative_k1_derived']['resulting_verdicts']})."]
    w = report["weakening_analysis"]
    lines += ["", "## Weakening analysis", "", f"Unit: {w['unit']}. {w['cases']} cases x {len(w['weakenings'])} weakenings = {w['pairs']} pairs. Results: {w['results']}. "
              f"Verdict changes: {w['verdict_changes']}. **Raised: {len(w['raised_pairs'])}** (invariant: must be 0).", "",
              "| Weakening | " + " | ".join(("unchanged", "lowered", "refused (no verdict)", "returned to the no-record verdict", "raised")) + " |", "|---|---|---|---|---|---|"]
    for name, counts in w["per_weakening"].items():
        lines.append(f"| {name} | " + " | ".join(str(counts.get(k, 0)) for k in ("unchanged", "lowered", "refused (no verdict)", "returned to the no-record verdict", "raised")) + " |")
    lines += ["", "## Rule conformance (synthetic cases)", ""]
    for key, p in report["conformance"]["predicates"].items():
        lines.append(f"* {p['title']}: {p['cases']} cases, {p['failed_cases']} failed; rules exercised {p['rules_exercised']}/{p['rules']}; rule tests covered {p['rule_tests_covered']}/{p['rule_tests']}.")
    lines += ["", f"Authentic Joern: {report['authentic_joern']}", "", "## Limitations", ""] + [f"* {t}" for t in report["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    out = Path(args[args.index("--out") + 1]) if "--out" in args else OUT
    report = build()
    text_json, text_md = render_json(report), render_markdown(report)
    if "--check" in args:
        stale = [n for n, t in (("research_report.json", text_json), ("research_report.md", text_md))
                 if not (out / n).is_file() or (out / n).read_text(encoding="utf-8") != t]
        if stale:
            print(f"STALE: {', '.join(stale)}")
            return 1
        return 0 if not report["weakening_analysis"]["raised_pairs"] else 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "research_report.json").write_text(text_json, encoding="utf-8")
    (out / "research_report.md").write_text(text_md, encoding="utf-8")
    print(text_md)
    return 0 if not report["weakening_analysis"]["raised_pairs"] and report["corpus"]["disagree"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
