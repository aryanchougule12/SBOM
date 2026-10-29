"""Running every applicable (scenario, operator) pair and checking the relations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from tests.metamorphic.core import (
    RELATIONS_BY_KIND,
    Observation,
    Operator,
    RelationResult,
    Scenario,
    m3_deterministic,
    m5_rationale_lists_every_code,
    observe,
)


@dataclass(frozen=True)
class PairResult:
    scenario_id: str
    op_id: str
    kind: str
    base: Observation
    mutant: Observation
    relations: tuple[RelationResult, ...]
    changed: bool                      # whether the mutation changed the verdict or the codes (a relation can hold vacuously otherwise)

    @property
    def violations(self) -> tuple[RelationResult, ...]:
        return tuple(r for r in self.relations if not r.holds)


@dataclass(frozen=True)
class BaseResult:
    scenario_id: str
    observation: Observation
    relations: tuple[RelationResult, ...]


def run_campaign(scenarios: Sequence[Scenario], operators: Sequence[Operator]) -> tuple[list[BaseResult], list[PairResult]]:
    bases: list[BaseResult] = []
    pairs: list[PairResult] = []
    for scenario in scenarios:
        base = observe(scenario)
        bases.append(BaseResult(scenario.scenario_id, base, (m3_deterministic(base, observe(scenario)), m5_rationale_lists_every_code(base))))
        for operator in operators:
            if scenario.predicate not in operator.predicates or scenario.sbom_format not in operator.formats or not operator.applies(scenario):
                continue
            mutated = operator.apply(scenario)
            mutant = observe(mutated)
            relations = [check(base, mutant) for check in RELATIONS_BY_KIND[operator.kind]]
            relations.append(m3_deterministic(mutant, observe(mutated)))
            relations.append(m5_rationale_lists_every_code(mutant))
            changed = (base.kind, base.verdict, base.codes) != (mutant.kind, mutant.verdict, mutant.codes)
            pairs.append(PairResult(scenario.scenario_id, operator.op_id, operator.kind, base, mutant, tuple(relations), changed))
    return bases, pairs
