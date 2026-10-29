"""Evaluate this repository's evidence tool on `component_not_present` VEX claims built from the five projects.

Task (different from vulnerability detection): given an SBOM and a VEX statement "vulnerability V is not_affected because component C is not present",
return Supported / Weak / Insufficient. Ground truth of a claim comes from the construction of the projects (inventory_truth.json):
  true claim  = C is not in the project (taken from another project of the benchmark, or same package at a different version);
  false claim = C is in the project (every one of the 47 components, claimed absent).
Positive class = verdict Supported. TP: Supported & true claim; FP: Supported & false claim (unsafe VEX acceptance); FN: not Supported & true claim;
TN: not Supported & false claim. Evidence variants add support to the same SBOM:
  A SBOM only; B + human full_component_list assertion (P2); C + flat composition 'complete'; D nested layout (libraries under metadata.component) + 'complete' + assertion; E = D + an external verification result
  for the SBOM (synthetic: tests.pipeline_support.verification_for - no cryptography is performed here; it models a verifier having succeeded)."""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from evidence.profile import parse_profile                                         # noqa: E402
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex       # noqa: E402
from evidence.sufficiency import evaluate_finding                                   # noqa: E402
from tests.pipeline_support import profile_data, verification_for                   # noqa: E402

INVENTORY = json.loads((HERE / "inventory_truth.json").read_text())
VULN = "CVE-2099-0001"        # placeholder id: the evaluator judges the justification, not the vulnerability


def purl(eco, name, version):
    if eco == "maven":
        group, artifact = name.split(":")
        return f"pkg:maven/{group}/{artifact}@{version}"
    if eco == "pypi":
        return f"pkg:pypi/{name.lower()}@{version}"
    return f"pkg:npm/{name}@{version}"


def components(project):
    return {(eco, n, v) for eco, comps in INVENTORY[project].items() for n, v in comps.items()}


def claims(project):
    own = components(project)
    own_names = {(e, n.lower()) for e, n, _ in own}
    out = [("false", "present_component", c) for c in sorted(own)]
    seen = set()
    for other in sorted(INVENTORY):
        if other == project:
            continue
        for c in sorted(components(other) - own):
            if c in seen:
                continue
            seen.add(c)
            out.append(("true", "same_package_other_version" if (c[0], c[1].lower()) in own_names else "absent_package", c))
    return out


def with_composition(path, tmp, nested):
    doc = json.loads(path.read_text())
    root = doc["metadata"]["component"]["bom-ref"]
    if nested:       # libraries become direct children of the root component (CycloneDX metadata.component.components)
        doc["metadata"]["component"]["components"] = doc["components"]
        doc["components"] = []
        doc["compositions"] = [{"aggregate": "complete", "assemblies": [root]}]
    else:
        doc["compositions"] = [{"aggregate": "complete", "assemblies": [c["bom-ref"] for c in doc["components"]], "dependencies": [root]}]
    out = Path(tmp) / f"{'nested' if nested else 'flat'}_{path.name}"
    out.write_text(json.dumps(doc))
    return out


def evaluate(project, variant, claim, rec_cache, vex_cache):
    truth, stratum, (eco, name, version) = claim
    sbom = HERE / "sbom_clean" / f"{project}.json"
    doc = json.loads(sbom.read_text())
    digest = doc["metadata"]["component"]["hashes"][0]["content"]
    product = f"pkg:generic/{project}@1.0.0"
    key = (project, variant if variant in "CDE" else "-")
    path = rec_cache.get(key)
    if path is None:
        path = rec_cache[key] = with_composition(sbom, tempfile.mkdtemp(), nested=variant in "DE") if variant in "CDE" else sbom
    record = load_cyclonedx(path)
    if project not in vex_cache:
        vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://bench/vex/{project}", "author": "bench", "role": "Document Creator",
               "timestamp": "2026-10-29T10:00:00Z", "version": 1, "tooling": "benchmark5",
               "statements": [{"vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{VULN}", "name": VULN},
                               "products": [{"@id": product, "identifiers": {"purl": product}, "hashes": {"sha-256": digest.upper()}}],
                               "status": "not_affected", "justification": "component_not_present", "impact_statement": "claim under test",
                               "timestamp": "2026-10-29T10:05:00Z"}]}
        target = Path(tempfile.mkdtemp()) / "vex.json"
        target.write_text(json.dumps(vex))
        vex_cache[project] = list(load_openvex(target).findings)
    data = profile_data(record.doc_id, product=product, version="1.0.0", assertion=variant != "A",
                        target={"name": name.split(":")[-1], "version": version, "purl": purl(eco, name, version)}, location={"placement": "nested_under_component", "parent_ref": doc["metadata"]["component"]["bom-ref"]} if variant in "DE" else {"placement": "top_level"})
    data["scope"]["artifact_digests"] = ["sha256:" + digest]
    for assertion in data.get("inv_assertions", []):
        assertion["scope"]["artifact_digests"] = ["sha256:" + digest]
    data["finding_selector"] = {"vulnerability": VULN, "product_id": product}
    verification = verification_for(record.doc_id, coverage=("#/components", "#/metadata", "#/compositions")) if variant == "E" else None
    outcome = evaluate_finding(parse_profile(data), vex_cache[project], Stage1Index([record]), verification, None)
    result = getattr(outcome, "result", None)
    return (result.verdict.value, list(result.codes)) if result else ("Refused", [str(outcome)])


def main():
    rows = []
    rec_cache, vex_cache = {}, {}
    for variant in "ABCDE":
        for project in sorted(INVENTORY):
            for claim in claims(project):
                verdict, codes = evaluate(project, variant, claim, rec_cache, vex_cache)
                rows.append({"variant": variant, "project": project, "truth": claim[0], "stratum": claim[1], "component": purl(*claim[2]), "verdict": verdict, "codes": codes})
    summary = {}
    for variant in "ABCDE":
        sub = [r for r in rows if r["variant"] == variant]
        c = Counter()
        for r in sub:
            positive = r["verdict"] == "Supported"
            c[("TP" if positive else "FN") if r["truth"] == "true" else ("FP" if positive else "TN")] += 1
        summary[variant] = {"TP": c["TP"], "FP": c["FP"], "TN": c["TN"], "FN": c["FN"], "verdicts": dict(Counter((r["truth"], r["verdict"]) .__str__() for r in sub)),
                            "top_codes": Counter(code for r in sub for code in r["codes"]).most_common(6)}
    (HERE / "ours_results.json").write_text(json.dumps({"rows": rows, "summary": summary}, indent=1, sort_keys=True) + "\n")
    for variant, s in summary.items():
        print(variant, {k: s[k] for k in ("TP", "FP", "TN", "FN")}, s["verdicts"])


if __name__ == "__main__":
    main()
