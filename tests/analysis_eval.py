"""Deterministic evaluation harness for the analyzer-artifact corpus (``fixtures/analysis``).

It runs every case of ``fixtures/analysis/manifest.json`` through the **public** pipeline

    raw artifact -> evidence.analysis_ingest.evaluate_with_analysis -> ReachOutcome | EvaluationRefusal

and compares the observable result with the hand-reviewed expectation of the manifest (each
expectation carries a ``why`` that derives it from the formal rules; none was copied from program
output). It reports, per artifact category and format: artifacts, refusals, evidence-state and verdict
distributions, incomplete/unverified/unbound cases, rule coverage that was *observed* to trigger,
cases that depend on a still-open semantic question, and agreement with the expectations.

What the numbers mean
---------------------
They are **controlled conformance results**. Category B fixtures are synthetic. Category A files are
upstream test data / documentation examples of the formats, copied byte-for-byte; category L files are
unedited output of live CodeQL runs made for this repository (fixtures/analysis/authentic/codeql/REPRODUCE.md);
none is a labelled ground-truth set for any security question, and no authentic Joern output was obtained. The report therefore contains **no accuracy, precision, recall or false-positive
rate**; "agreement" is the fraction of cases whose output equals the reviewed expectation, reported
separately for the categories and never merged into one score.

Run::

    python -m tests.analysis_eval                 # print the summary, write evaluation_results/
    python -m tests.analysis_eval --check         # fail if the committed results are stale
    python -m tests.analysis_eval --out DIR       # write elsewhere

The output (``analysis_corpus.json`` and ``analysis_corpus_cases.csv``) is byte-stable: no timestamps,
sorted keys, fixed ordering.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from evidence.analysis_binding import parse_analysis_subject
from evidence.analysis_ingest import evaluate_with_analysis, parse_analysis_artifact
from evidence.evaluator import EvaluationRefusal
from evidence.reach_evaluator import ReachOutcome
from evidence.reach_inputs import parse_reachability
from evidence.reach_rules import REACH_RULES
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig, VerificationResult
from tests.pipeline_support import FIXTURES, equivalent, make_profile, vex_findings

ANALYSIS_DIR = FIXTURES / "analysis"
MANIFEST = ANALYSIS_DIR / "manifest.json"
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "evaluation_results"
RULE_IDS = tuple(r.rule_id for r in REACH_RULES)


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _merged(defaults: dict, override: Optional[dict]) -> dict:
    merged = json.loads(json.dumps(defaults))
    for key, value in (override or {}).items():
        if value is None:   # an explicit null removes the default (for example "no revision declared")
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def _base_evidence(name: str, locus: dict) -> dict:
    """The directly supplied (strict-input) evidence a case starts from."""
    data: dict[str, Any] = {"schema_version": "1"}
    if name == "locus_only":
        data.update(locus=locus, configuration={"deployment_config_id": "prod"})
    elif name == "supported_k1":
        data = json.loads((FIXTURES / "reachability" / "synthetic_baseline.json").read_text(encoding="utf-8"))
        data["locus"] = locus
    elif name != "empty":
        raise ValueError(f"unknown base evidence {name!r}")
    return data


def _verification(spec: Optional[dict], artifact_doc_id: Optional[str]) -> Optional[VerificationConfig]:
    if not spec:
        return None
    results = []
    for entry in spec["results"]:
        doc = artifact_doc_id if entry["doc"] == "artifact" else entry["doc"]
        results.append(VerificationResult(doc, entry["verified"], entry["anchor"], "external-verifier", "1.0", tuple(entry["coverage"])))
    return VerificationConfig(frozenset(spec["trust"]), tuple(results))


def run_case(case: dict, defaults: dict) -> dict:
    """Run one case; returns the observed result (never raises)."""
    subject = parse_analysis_subject(_merged(defaults["subject"], case.get("subject")))
    locus = _merged(defaults["locus"], case.get("locus"))
    base = parse_reachability(_base_evidence(case.get("base", defaults["base"]), locus))
    artifacts = [] if case.get("file") is None else [str(ANALYSIS_DIR / case["file"])]
    doc_id = None
    if artifacts:
        try:
            doc_id = parse_analysis_artifact(artifacts[0]).source.doc_id
        except Exception:  # noqa: BLE001 - an invalid artifact has no id; the refusal is what is under test
            doc_id = None
    record = equivalent("cdx")
    outcome = evaluate_with_analysis(make_profile(record.doc_id), vex_findings("reachability_equivalent.json"), Stage1Index([record]),
                                     artifacts, subject, base, _verification(case.get("verification"), doc_id))
    if isinstance(outcome, EvaluationRefusal):
        return {"outcome": "refused", "refusal_code": outcome.code.value, "cause": outcome.cause}
    assert isinstance(outcome, ReachOutcome)
    sources = outcome.analysis
    return {
        "outcome": "evaluated",
        "reach": outcome.dimension_states["REACH"], "bind": outcome.dimension_states["BIND"],
        "verdict": outcome.result.verdict.value, "rules": list(outcome.evaluation.rule_ids), "codes": list(outcome.result.codes),
        "observations": sum(len(s.traces) for s in sources),
        "prov_reach": outcome.prov_reach.name if outcome.prov_reach is not None else None,
        "blockers": [b for s in sources for b in s.bind_blockers],
        "diagnostic_codes": sorted({d.code for s in sources for d in s.diagnostics}),
        "limitations": list(outcome.limitations),
        "result_limitations": list(outcome.result.limitations),
        "evidence_items": len(outcome.items),
    }


def compare(expected: dict, actual: dict) -> list[str]:
    """Differences between the reviewed expectation and the observed result (empty = agreement)."""
    problems: list[str] = []
    if expected["outcome"] != actual["outcome"]:
        return [f"outcome: expected {expected['outcome']}, got {actual['outcome']}"]
    if expected["outcome"] == "refused":
        for key in ("refusal_code", "cause"):
            if expected[key] != actual[key]:
                problems.append(f"{key}: expected {expected[key]!r}, got {actual[key]!r}")
        return problems
    for key in ("reach", "verdict", "rules", "bind", "observations", "prov_reach", "blockers"):
        if expected[key] != actual[key]:
            problems.append(f"{key}: expected {expected[key]!r}, got {actual[key]!r}")
    if "result_limitations" in expected and expected["result_limitations"] != actual["result_limitations"]:
        problems.append(f"result_limitations: expected {expected['result_limitations']!r}, got {actual['result_limitations']!r}")
    if "first_code" in expected and actual["codes"][:1] != [expected["first_code"]]:
        problems.append(f"first_code: expected {expected['first_code']!r}, got {actual['codes'][:1]!r}")
    for code in expected.get("diagnostics_include", []):
        if code not in actual["diagnostic_codes"]:
            problems.append(f"diagnostic {code!r} not reported")
    for text in expected.get("limitations_include", []):
        if not any(text in lim for lim in actual["limitations"]):
            problems.append(f"limitation containing {text!r} not reported")
    return problems


def check_fixture(case: dict) -> list[str]:
    """Attribution integrity: the recorded digest matches the file, and a category-A file is flagged as not handwritten here."""
    if case.get("file") is None:
        return []
    path = ANALYSIS_DIR / case["file"]
    source = case["source"]
    problems = []
    if not path.is_file():
        return [f"file missing: {case['file']}"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
        problems.append("recorded sha256 does not match the file")
    if case["category"] == "A":
        if source.get("handwritten_here") or source.get("synthetic"):
            problems.append("category A must not be synthetic or handwritten")
        if not (case["file"].startswith("upstream/") and source.get("commit") and source.get("origin") and source.get("license")):
            problems.append("category A needs origin, commit and license")
    elif case["category"] == "L":
        problems.extend(_check_live(case, path))
    elif not source.get("synthetic"):
        problems.append("category B must be flagged synthetic")
    if source.get("live_run") and case["category"] != "L":
        problems.append("only category L may be a live analyzer run")
    return problems


def _check_live(case: dict, path: Path) -> list[str]:
    """Category L (output of a real analyzer run made for this repository) must carry its full provenance and match the file."""
    source = case["source"]
    problems = []
    if source.get("synthetic") or source.get("handwritten_here") or not source.get("live_run"):
        problems.append("category L must be a live run: not synthetic, not handwritten, live_run true")
    for key in ("tool_version", "bundle_sha256", "bundle_url", "query", "query_pack", "project", "retrieved_or_run", "license"):
        if not source.get(key):
            problems.append(f"category L needs {key}")
    if not case["file"].startswith("authentic/"):
        problems.append("category L files live under authentic/")
    try:
        driver = json.loads(path.read_bytes())["runs"][0]["tool"]["driver"]
    except (ValueError, KeyError, IndexError, TypeError):
        return problems + ["category L file is not a SARIF log with a tool driver"]
    if driver.get("semanticVersion") != source.get("tool_version"):
        problems.append(f"driver semanticVersion {driver.get('semanticVersion')!r} does not match the recorded tool_version")
    if "codeql" not in str(driver.get("name", "")).lower():
        problems.append("driver name is not CodeQL")
    return problems


CATEGORY_LABELS = {
    "A": "upstream format examples / test data (byte-for-byte)",
    "B": "synthetic controlled fixtures",
    "L": "authentic CodeQL output (live runs made for this repository)",
}
AUTHENTIC_JOERN = ("authentic Joern output: 0 artifacts. Not obtained: the Joern distribution is about 1.7 GB and was not installed "
                   "for this task; every Joern GraphML here is category B (synthetic), checked against the exporter source and CPG schema only.")


def _distribution(values) -> dict:
    return dict(sorted(Counter(values).items(), key=lambda kv: (-kv[1], str(kv[0]))))


def build_report() -> dict:
    manifest = load_manifest()
    defaults = manifest["defaults"]
    rows, cases = [], manifest["cases"]
    for case in cases:
        actual = run_case(case, defaults)
        problems = compare(case["expected"], actual)
        rows.append({"id": case["id"], "category": case["category"], "format": case["format"], "file": case.get("file"),
                     "agree": not problems, "differences": problems, "fixture_problems": check_fixture(case),
                     "expected": case["expected"], "actual": actual, "why": case["why"],
                     "open_questions": case.get("open_questions", [])})
    report: dict[str, Any] = {
        "kind": "controlled-conformance-results",
        "disclaimer": ("Controlled conformance against hand-reviewed expectations. Category B is synthetic; category A files are upstream "
                       "format examples/test data, not live analyzer runs; category L files are live CodeQL runs made for this repository. No accuracy, precision, recall or false-positive rate is "
                       "reported because no labelled ground truth exists."),
        "manifest_schema": manifest["schema"],
        "totals": {"cases": len(rows), "agree": sum(r["agree"] for r in rows), "disagree": sum(not r["agree"] for r in rows),
                   "fixture_problems": sum(bool(r["fixture_problems"]) for r in rows)},
        "categories": {},
        "not_obtained": {"authentic_joern": AUTHENTIC_JOERN},
    }
    for category in ("A", "B", "L"):
        part = [r for r in rows if r["category"] == category]
        evaluated = [r for r in part if r["actual"]["outcome"] == "evaluated"]
        by_format = {}
        for fmt in sorted({r["format"] for r in part}):
            of_format = [r for r in part if r["format"] == fmt]
            by_format[fmt] = {
                "cases": len(of_format),
                "artifacts": sum(1 for r in of_format if r["file"]),
                "evaluated": sum(r["actual"]["outcome"] == "evaluated" for r in of_format),
                "refused": sum(r["actual"]["outcome"] == "refused" for r in of_format),
                "agree": sum(r["agree"] for r in of_format),
            }
        report["categories"][category] = {
            "label": CATEGORY_LABELS[category],
            "cases": len(part), "agree": sum(r["agree"] for r in part),
            "by_format": by_format,
            "refusals_by_cause": _distribution(r["actual"]["cause"] for r in part if r["actual"]["outcome"] == "refused"),
            "reach_state_distribution": _distribution(r["actual"]["reach"] for r in evaluated),
            "bind_state_distribution": _distribution(r["actual"]["bind"] for r in evaluated),
            "verdict_distribution": _distribution(r["actual"]["verdict"] for r in evaluated),
            "rules_observed": _distribution(rule for r in evaluated for rule in r["actual"]["rules"]),
            "cases_with_positive_path": sorted(r["id"] for r in evaluated if r["actual"]["observations"]),
            "cases_unbound": sorted(r["id"] for r in evaluated if r["actual"]["blockers"]),
            "cases_with_incomplete_or_unverified_run_info": sorted(
                r["id"] for r in evaluated
                if any(("UNSUCCESSFUL_EXECUTION" in l or "NO_INVOCATION_RECORD" in l or "ERROR_NOTIFICATIONS" in l) for l in r["actual"]["limitations"])),
            "cases_open_semantics": sorted(r["id"] for r in part if r["open_questions"]),
        }
    seen = Counter(rule for r in rows if r["actual"]["outcome"] == "evaluated" for rule in r["actual"]["rules"])
    report["rule_coverage"] = {
        "scope": "rules observed to trigger in at least one evaluated case of this corpus (a count of cases, not of artifacts)",
        "triggered": {rule: seen.get(rule, 0) for rule in RULE_IDS},
        "never_triggered": [rule for rule in RULE_IDS if not seen.get(rule)],
        "note": ("The artifact adapters can only produce positive path observations, so rules that need an absence, an incomplete or "
                 "an ambiguous K1 fact (R7, R8) or a non-governed dimension are exercised by the strict-input conformance harness "
                 "(python -m tests.conformance), not by this corpus."),
    }
    report["cases"] = rows
    return report


def render_csv(report: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["id", "category", "format", "file", "expected_outcome", "actual_outcome", "expected_verdict", "actual_verdict",
                     "expected_reach", "actual_reach", "bind", "observations", "prov_reach", "rules", "agree"])
    for r in report["cases"]:
        e, a = r["expected"], r["actual"]
        writer.writerow([r["id"], r["category"], r["format"], r["file"] or "", e["outcome"], a["outcome"], e.get("verdict", ""),
                         a.get("verdict", ""), e.get("reach", ""), a.get("reach", ""), a.get("bind", ""), a.get("observations", ""),
                         a.get("prov_reach") or "", " ".join(a.get("rules", [])), "yes" if r["agree"] else "NO"])
    return out.getvalue()


def render_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def render_summary(report: dict) -> str:
    lines = ["Analyzer-artifact corpus: controlled conformance (no accuracy claim; category B is synthetic)"]
    t = report["totals"]
    lines.append(f"cases {t['cases']}, agree {t['agree']}, disagree {t['disagree']}, fixture-attribution problems {t['fixture_problems']}")
    for category, part in report["categories"].items():
        lines.append(f"\nCategory {category}: {part['label']}: {part['cases']} cases, {part['agree']} agree")
        for fmt, row in part["by_format"].items():
            lines.append(f"  {fmt}: artifacts {row['artifacts']}, evaluated {row['evaluated']}, refused {row['refused']}, agree {row['agree']}/{row['cases']}")
        lines.append(f"  REACH states {part['reach_state_distribution']}; verdicts {part['verdict_distribution']}; refusals {part['refusals_by_cause']}")
        lines.append(f"  unbound {len(part['cases_unbound'])}, positive path {len(part['cases_with_positive_path'])}, open semantics {len(part['cases_open_semantics'])}")
    lines.append("\n" + report["not_obtained"]["authentic_joern"])
    cov = report["rule_coverage"]
    lines.append(f"\nrules triggered in this corpus: {sum(1 for v in cov['triggered'].values() if v)}/{len(RULE_IDS)}; never: {', '.join(cov['never_triggered']) or '-'}")
    for r in report["cases"]:
        if not r["agree"] or r["fixture_problems"]:
            lines.append(f"  MISMATCH {r['id']}: {'; '.join(r['differences'] + r['fixture_problems'])}")
    return "\n".join(lines)


def write_outputs(report: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "analysis_corpus.json").write_text(render_json(report), encoding="utf-8")
    (out_dir / "analysis_corpus_cases.csv").write_text(render_csv(report), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    out_dir = Path(args[args.index("--out") + 1]) if "--out" in args else DEFAULT_OUT
    report = build_report()
    print(render_summary(report))
    ok = report["totals"]["disagree"] == 0 and report["totals"]["fixture_problems"] == 0
    if "--check" in args:
        stale = []
        for name, text in (("analysis_corpus.json", render_json(report)), ("analysis_corpus_cases.csv", render_csv(report))):
            path = out_dir / name
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        if stale:
            print(f"STALE: {', '.join(stale)} differ from a fresh run; re-run without --check")
            return 1
    else:
        write_outputs(report, out_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
