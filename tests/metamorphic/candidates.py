"""Candidate properties: investigated, not assumed (the Phase-I report treats MR5 'monotonicity of supporting evidence' this way).

Candidate MR5: *adding evidence that supports the claim never lowers the verdict*. The specification does not assert it. Under the minimum-provenance
rule (§1.2 step 5), a supporting K1 absence of lower provenance lowers PROV_REACH, hence the verdict, so the candidate is expected to have
counterexamples; this module measures that instead of assuming it. These pairs are reported separately and never counted as violations of M-1..M-6."""

from __future__ import annotations

from dataclasses import dataclass

from tests.metamorphic.core import Observation, Operator, Scenario, observe


def _add_k1_negative(document):
    """The added report is bound to the same artifact and target as the baseline K1 report and covers the same configuration, so the only thing
    that differs is its attribution (provenance): the effect measured is the minimum-provenance rule, not a binding failure."""
    def apply(s: Scenario) -> Scenario:
        out = s.mutate()
        baseline = next(d for d in out.reachability["documents"] if d["doc_id"] == "k1-analysis")
        added = {"artifact": baseline["artifact"], "target": baseline["target"], "analyzed_configurations": baseline["analyzed_configurations"],
                 "modeled_hazards": baseline["modeled_hazards"]}
        added.update(document)
        out.reachability["documents"].append(added)
        return out
    return apply


SUPPORT_OPERATORS = (
    Operator("S-K1-UNATTRIBUTED", "support", "add a second K1 absence with a full-coverage claim but no attribution (P0)", ("reach",),
             _add_k1_negative({"doc_id": "k1-anon", "kind": "K1", "finding": "negative", "full_coverage_claim": True, "entry_points": {"complete": True}})),
    Operator("S-K1-ATTRIBUTED", "support", "add a second K1 absence, attributed (P1), not verified, with a full-coverage claim", ("reach",),
             _add_k1_negative({"doc_id": "k1-attributed", "kind": "K1", "finding": "negative", "full_coverage_claim": True, "entry_points": {"complete": True},
                               "producer": "lab", "producer_class": "tool", "tool_name": "analyser", "tool_version": "1.0", "created": "2026-01-16T09:00:00Z"})),
)


@dataclass(frozen=True)
class CandidateResult:
    scenario_id: str
    op_id: str
    base: Observation
    mutant: Observation

    @property
    def holds(self) -> bool:
        """Candidate MR5: the verdict is not lower after adding supporting evidence (a refusal counts as lower)."""
        return self.mutant.rank is not None and self.base.rank is not None and self.mutant.rank >= self.base.rank


def run_candidates(scenarios) -> list[CandidateResult]:
    results = []
    for scenario in scenarios:
        base = observe(scenario)
        for operator in SUPPORT_OPERATORS:
            if scenario.predicate in operator.predicates and scenario.sbom_format in operator.formats and operator.applies(scenario):
                results.append(CandidateResult(scenario.scenario_id, operator.op_id, base, observe(operator.apply(scenario))))
    return results
