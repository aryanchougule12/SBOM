"""Scenarios, observations, operators and relations (the framework's vocabulary)."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Optional

from evidence.evaluator import EvaluationRefusal
from evidence.profile import parse_profile
from evidence.reach_inputs import parse_reachability
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex, load_spdx
from evidence.sufficiency import evaluate_finding
from evidence.verification import VerificationConfig, VerificationResult
from sbom_parser.errors import ParserError

PLACEHOLDER = "@PRIMARY@"
VERDICT_RANK = {"Insufficient": 0, "Weak": 1, "Supported": 2}


@dataclass(frozen=True)
class Scenario:
    """One complete evaluation input as JSON. ``verified_coverage`` (``None``: no verification) is the locator coverage of a trusted detached
    verification result for the primary SBOM; ``reachability`` is the strict reachability evidence (JSON) for the reachability predicate."""

    scenario_id: str
    predicate: str                                   # "cnp" | "reach"
    sbom_format: str                                 # "cdx" | "spdx"
    sbom: Mapping[str, Any]
    vex: Mapping[str, Any]
    profile: Mapping[str, Any]
    verified_coverage: Optional[tuple[str, ...]] = None
    reachability: Optional[Mapping[str, Any]] = None
    # trusted detached verification results for *reachability documents*: ((doc_id, coverage), ...)
    verified_docs: tuple[tuple[str, tuple[str, ...]], ...] = ()
    note: str = ""

    def mutate(self, **changes) -> "Scenario":
        """A deep copy with the given fields replaced (callers mutate the copies they receive)."""
        data = {f: copy.deepcopy(getattr(self, f)) for f in ("sbom", "vex", "profile", "reachability")}
        data.update(changes)
        return replace(self, **data)


@dataclass(frozen=True)
class Observation:
    """What one evaluation produced, reduced to what the relations compare. ``kind``: evaluated | refused | input_error (a parser/profile
    rejected the (mutated) input: no verdict, the mutation made the input unusable)."""

    kind: str
    verdict: Optional[str] = None
    codes: tuple[str, ...] = ()
    rationale: str = ""
    limitations: tuple[str, ...] = ()
    dimension_states: tuple[tuple[str, str], ...] = ()
    item_states: tuple[tuple[str, str], ...] = ()
    rules: tuple[str, ...] = ()
    detail: str = ""

    @property
    def rank(self) -> Optional[int]:
        return VERDICT_RANK[self.verdict] if self.verdict else None

    def states(self) -> dict[str, str]:
        return dict(self.dimension_states)


def observe(scenario: Scenario) -> Observation:
    """Evaluate ``scenario`` through the public entry point. Pure and deterministic; never raises for unusable inputs."""
    try:
        text = json.dumps(scenario.sbom).encode("utf-8")
        record = load_cyclonedx(text) if scenario.sbom_format == "cdx" else load_spdx(text)
        findings = list(load_openvex(json.dumps(scenario.vex).encode("utf-8")).findings)
        profile = parse_profile(json.loads(json.dumps(scenario.profile).replace(PLACEHOLDER, record.doc_id)))
        verification = None
        results = []
        if scenario.verified_coverage is not None:
            results.append(VerificationResult(record.doc_id, True, "anchor-1", "external-verifier", "1.0", tuple(scenario.verified_coverage)))
        results += [VerificationResult(doc, True, "anchor-1", "external-verifier", "1.0", tuple(cov)) for doc, cov in scenario.verified_docs]
        if results:
            verification = VerificationConfig(frozenset({"anchor-1"}), tuple(results))
        reachability = parse_reachability(copy.deepcopy(dict(scenario.reachability))) if scenario.reachability is not None else None
        outcome = evaluate_finding(profile, findings, Stage1Index([record]), verification, reachability)
    except (ParserError, ValueError, KeyError, TypeError) as error:       # includes ProfileError / ReachInputError (ValueErrors)
        return Observation("input_error", detail=f"{type(error).__name__}: {error}"[:200])
    if isinstance(outcome, EvaluationRefusal):
        return Observation("refused", detail=f"{outcome.code.value}: {outcome.cause or ''}")
    result = outcome.result
    states = dict(getattr(outcome, "dimension_states", {}) or {})
    return Observation(
        "evaluated", result.verdict.value, tuple(result.codes), result.rationale, tuple(outcome.limitations),
        tuple(sorted((str(k), str(v)) for k, v in states.items())),
        tuple(sorted((i.dimension, i.state.value) for i in outcome.items)),
        tuple(outcome.evaluation.rule_ids),
    )


@dataclass(frozen=True)
class Operator:
    """A mutation operator. ``kind`` says what relation family applies: ``degrade`` (M-1), ``delete`` (M-1 and M-2), ``inject_positive``
    (M-4), ``neutral`` (M-6). ``applies`` decides whether the base scenario has what the operator removes or changes."""

    op_id: str
    kind: str
    description: str
    predicates: tuple[str, ...]
    apply: Callable[[Scenario], Scenario]
    applies: Callable[[Scenario], bool] = lambda scenario: True
    formats: tuple[str, ...] = ("cdx", "spdx")


@dataclass(frozen=True)
class RelationResult:
    relation: str
    holds: bool
    detail: str = ""


def m1_never_raises(base: Observation, mutant: Observation) -> RelationResult:
    """M-1: degrading evidence never raises a verdict. A mutant that yields no verdict (refusal / unusable input) did not raise it."""
    if mutant.rank is None:
        return RelationResult("M-1", True, "no verdict")
    if base.rank is None:
        return RelationResult("M-1", True, "base has no verdict")
    ok = mutant.rank <= base.rank
    return RelationResult("M-1", ok, f"{base.verdict} -> {mutant.verdict}")


def m2_no_absent_from_deletion(base: Observation, mutant: Observation) -> RelationResult:
    """M-2: deleting evidence never turns Unknown into Absent: no dimension or item is Absent in the mutant unless it already was in the base."""
    if mutant.kind != "evaluated" or base.kind != "evaluated":
        return RelationResult("M-2", True, "not comparable")
    base_absent = {d for d, s in base.dimension_states if s in ("Absent", "absent")}
    new_absent = sorted(d for d, s in mutant.dimension_states if s in ("Absent", "absent") and d not in base_absent)
    base_items = {d for d, s in base.item_states if s == "Absent"}
    new_items = sorted(d for d, s in mutant.item_states if s == "Absent" and d not in base_items)
    return RelationResult("M-2", not (new_absent or new_items), f"new Absent: {new_absent + new_items}" if new_absent or new_items else "")


def m3_deterministic(first: Observation, second: Observation) -> RelationResult:
    """M-3: the same input gives the same (verdict, codes) - here compared on the whole observation."""
    return RelationResult("M-3", first == second)


def m4_positive_gives_insufficient(base: Observation, mutant: Observation) -> RelationResult:
    """M-4: injecting a positive observation yields Insufficient. A mutant with no verdict is reported as such (not a violation)."""
    if mutant.rank is None:
        return RelationResult("M-4", True, "no verdict")
    return RelationResult("M-4", mutant.verdict == "Insufficient", f"{base.verdict} -> {mutant.verdict}")


def m5_rationale_lists_every_code(observation: Observation) -> RelationResult:
    """M-5: every triggered rule appears in the rationale."""
    if observation.kind != "evaluated":
        return RelationResult("M-5", True, "no verdict")
    missing = [c for c in observation.codes if c not in observation.rationale]
    return RelationResult("M-5", not missing, f"missing {missing}" if missing else "")


def m6_neutral(base: Observation, mutant: Observation) -> RelationResult:
    """M-6: changing only free-text fields never changes the verdict (nor the codes)."""
    return RelationResult("M-6", (base.kind, base.verdict, base.codes) == (mutant.kind, mutant.verdict, mutant.codes),
                          f"{base.verdict}{list(base.codes)} -> {mutant.verdict}{list(mutant.codes)}")


RELATIONS_BY_KIND = {
    "degrade": (m1_never_raises,),
    "delete": (m1_never_raises, m2_no_absent_from_deletion),
    "inject_positive": (m4_positive_gives_insufficient,),
    "neutral": (m6_neutral,),
}
