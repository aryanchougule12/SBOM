"""Mutation operators for ``vulnerable_code_not_in_execute_path`` evidence (strict reachability input, verification, provenance, positive paths)."""

from __future__ import annotations

from tests.metamorphic.core import Operator, Scenario

K1 = "k1-analysis"


def _k1(scenario: Scenario) -> dict:
    return next(d for d in scenario.reachability["documents"] if d["doc_id"] == K1)


def _edit_k1(change):
    def apply(s: Scenario) -> Scenario:
        out = s.mutate()
        change(_k1(out))
        return out
    return apply


def _edit_reach(change):
    def apply(s: Scenario) -> Scenario:
        out = s.mutate()
        change(out.reachability)
        return out
    return apply


def _drop(key):
    return _edit_k1(lambda doc: doc.pop(key, None))


def _set(key, value):
    return _edit_k1(lambda doc: doc.__setitem__(key, value))


def _positive_doc(doc_id, kind, **extra):
    document = {"doc_id": doc_id, "kind": kind, "finding": "positive", "producer": "synthetic-lab", "producer_class": "tool",
                "tool_name": "synthetic-analyser", "tool_version": "0.0.1", "created": "2026-01-16T09:00:00Z"}
    document.update(extra)
    return document


def _inject(document):
    def apply(s: Scenario) -> Scenario:
        out = s.mutate()
        out.reachability["documents"].append(dict(document))
        return out
    return apply


def _no_verification(s: Scenario) -> Scenario:
    return s.mutate(verified_docs=())


def _narrow_verification(s: Scenario) -> Scenario:
    return s.mutate(verified_docs=tuple((doc, ("#/nothing",)) for doc, _ in s.verified_docs))


def _other_target(doc):
    doc["target"] = {"purl": "pkg:npm/some-other-lib@1.0"}


def _alter_artifact_hash(doc):
    doc["artifact"]["hashes"] = ["sha256:" + "ab" * 32]


def _remove_artifact_hash(doc):
    doc["artifact"].pop("hashes", None)


def _drop_hazard_basis(reach):
    reach["documents"] = [d for d in reach["documents"] if d["kind"] != "hazard_basis"]


def _drop_hazard_claims(reach):
    reach["hazards"] = []


def _under_approximate_locus(reach):
    reach["locus"]["approximation"] = "possibly_under_approximate"


def _drop_locus(reach):
    reach.pop("locus", None)


def _drop_configuration(reach):
    reach.pop("configuration", None)


def _drop_k1(reach):
    reach["documents"] = [d for d in reach["documents"] if d["doc_id"] != K1]


def _verified(s: Scenario) -> bool:
    return bool(s.verified_docs)


REACH_OPERATORS = (
    Operator("DR-K1", "delete", "remove the K1 analysis report", ("reach",), _edit_reach(_drop_k1)),
    Operator("DR-ENTRY", "delete", "remove the K1 report's entry-point completeness", ("reach",), _drop("entry_points")),
    Operator("DR-MODELED", "delete", "remove the hazards the K1 report declares modeled", ("reach",), _drop("modeled_hazards")),
    Operator("DR-CONFIGS", "delete", "remove the K1 report's analysed configurations", ("reach",), _drop("analyzed_configurations")),
    Operator("DR-HAZ-BASIS", "delete", "remove the hazard-exclusion basis document", ("reach",), _edit_reach(_drop_hazard_basis)),
    Operator("DR-HAZ-CLAIMS", "delete", "remove the evaluator's hazard dispositions", ("reach",), _edit_reach(_drop_hazard_claims)),
    Operator("DR-LOCUS", "delete", "remove the vulnerable-code locus", ("reach",), _edit_reach(_drop_locus)),
    Operator("DR-CFG", "delete", "remove the deployment configuration", ("reach",), _edit_reach(_drop_configuration)),
    Operator("DR-ARTIFACT-HASH", "delete", "remove the digest the K1 report declares for the analysed artifact", ("reach",), _edit_k1(_remove_artifact_hash)),
    Operator("DR-TOOL-VERSION", "delete", "remove the K1 report's tool version (attribution)", ("reach",), _drop("tool_version")),
    Operator("DR-CREATED", "delete", "remove the K1 report's timestamp (attribution)", ("reach",), _drop("created")),
    Operator("DR-VERIFICATION", "delete", "remove the detached verification result", ("reach",), _no_verification, applies=_verified),
    Operator("GR-COVERAGE", "degrade", "withdraw the K1 report's full-coverage claim", ("reach",), _set("full_coverage_claim", False)),
    Operator("GR-K1-INCOMPLETE", "degrade", "the K1 report says the analysis is incomplete", ("reach",), _set("finding", "incomplete")),
    Operator("GR-K1-AMBIGUOUS", "degrade", "the K1 report says unresolved may-reach edges remain", ("reach",), _set("finding", "ambiguous")),
    Operator("GR-K1-UNKNOWN", "degrade", "the K1 report reports nothing usable", ("reach",), _set("finding", "unknown")),
    Operator("GR-ENTRY-INCOMPLETE", "degrade", "the K1 report declares its entry-point set incomplete", ("reach",), _set("entry_points", {"complete": False})),
    Operator("GR-LOCUS", "degrade", "the locus may be an under-approximation", ("reach",), _edit_reach(_under_approximate_locus)),
    Operator("GR-TARGET", "degrade", "the K1 report concerns another component", ("reach",), _edit_k1(_other_target)),
    Operator("GR-ARTIFACT-HASH", "degrade", "the K1 report's declared artifact digest is not the assessed artifact's", ("reach",), _edit_k1(_alter_artifact_hash)),
    Operator("GR-CONFIGS", "degrade", "the K1 report was analysed under another configuration", ("reach",), _set("analyzed_configurations", ["staging"])),
    Operator("GR-VERIFICATION", "degrade", "narrow the verified coverage so it excludes the report", ("reach",), _narrow_verification, applies=_verified),
    Operator("IR-K1-POSITIVE", "inject_positive", "add a second K1 report that observes a path to the locus", ("reach",),
             _inject(_positive_doc("k1-second", "K1"))),
    Operator("IR-K2-POSITIVE", "inject_positive", "add a K2 assertion that the code is reachable", ("reach",), _inject(_positive_doc("k2-assertion", "K2"))),
    Operator("IR-K3-POSITIVE", "inject_positive", "add runtime coverage data that executes the locus", ("reach",), _inject(_positive_doc("k3-trace", "K3"))),
    Operator("IR-UNATTRIBUTED-POSITIVE", "inject_positive", "add an unattributed (P0) assertion that the code is reachable", ("reach",),
             _inject({"doc_id": "k2-anon", "kind": "K2", "finding": "positive"})),
)
