"""Predicate-independent parts of the section 3 decision procedure.

Shared by ``evidence.cnp_rules`` (``Req(component_not_present)``) and ``evidence.reach_rules``
(``Req(vulnerable_code_not_in_execute_path)``). Only what the two predicates genuinely have in
common lives here:

* ``TriggeredRule``: one triggered rule (id, code, ceiling, rationale class, detail);
* the section 3 output order: rationale-class rank (CONTRADICTORY, CANNOT, BELOW), then the
  alphabetic rule-family prefix, then the numeric suffix as an integer. The sort is stable, so a
  predicate that emits several codes for one rule controls their relative order;
* the ``<CLASS>[CODE,...]: text`` rationale rendering (one segment per class, joined by `` | ``);
* the minimum-ceiling step of section 3 Step 4;
* ``jsonable``, the deterministic JSON view used by the outcome reports.

Everything predicate-specific (rule tables, Supported conditions, which dimension states a rule
governs) stays in the predicate's own module.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from reports.verdict import RationaleClass, Verdict

CLASS_RANK = {
    RationaleClass.CONTRADICTORY_EVIDENCE: 0,
    RationaleClass.CANNOT_BE_ESTABLISHED: 1,
    RationaleClass.BELOW_BAR: 2,
    RationaleClass.NO_RULE_APPLIES: 3,
}
VERDICT_RANK = {Verdict.INSUFFICIENT: 0, Verdict.WEAK: 1, Verdict.SUPPORTED: 2}
_RULE_ID = re.compile(r"([A-Za-z]+)([0-9]+)")


@dataclass(frozen=True)
class TriggeredRule:
    rule_id: str
    code: str
    ceiling: Verdict
    rationale_class: RationaleClass
    detail: str


def output_key(rule: TriggeredRule) -> tuple[int, str, int]:
    """Section 3 ordering: class rank, then rule-family prefix, then the numeric suffix as an
    integer (never the lexicographic order of the whole identifier)."""
    match = _RULE_ID.fullmatch(rule.rule_id)
    if match is None:  # unreachable for the committed tables
        raise ValueError(f"malformed rule id {rule.rule_id!r}")
    return (CLASS_RANK[rule.rationale_class], match.group(1), int(match.group(2)))


def order_triggered(rules: Iterable[TriggeredRule]) -> tuple[TriggeredRule, ...]:
    """Triggered rules in output order (stable for equal keys)."""
    return tuple(sorted(rules, key=output_key))


def render_rationale(rules: Sequence[TriggeredRule]) -> str:
    """One ``<CLASS>[CODE,...]: <rule>: detail; ...`` segment per class, in class-rank order."""
    segments: list[str] = []
    for rationale_class in (RationaleClass.CONTRADICTORY_EVIDENCE, RationaleClass.CANNOT_BE_ESTABLISHED,
                            RationaleClass.BELOW_BAR):
        group = [r for r in rules if r.rationale_class is rationale_class]
        if group:
            codes = ",".join(r.code for r in group)
            text = "; ".join(dict.fromkeys(f"{r.rule_id}: {r.detail}" for r in group))  # one text per rule
            segments.append(f"{rationale_class.value}[{codes}]: {text}")
    return " | ".join(segments)


def minimum_ceiling(ceilings: Iterable[Verdict]) -> Verdict:
    """Section 3 Step 4: the minimum of the ceilings (Supported > Weak > Insufficient)."""
    return min(ceilings, key=VERDICT_RANK.__getitem__)


def jsonable(value: Any) -> Any:
    """A deterministic JSON-compatible view of nested frozen records, enums and tuples."""
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(jsonable(v) for v in value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value
