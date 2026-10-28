"""Pure rule evaluation for ``Req(vulnerable_code_not_in_execute_path)`` (specification section 5).

Implements, from ``docs/formal_specification_v0.2.md`` section 5 and addendum v0.2.3 only:

* **§3 Steps 1, 3, 4, 5** for this predicate: the hazard downgrade of §5.2 (Step 1), every rule of
  the §5.4 table evaluated with no short-circuiting (Step 3), the minimum ceiling over the
  triggered rules together with the unresolved-dimension ceiling (Step 4), and every triggered
  code in the §3 output order (Step 5);
* **§5.4 rules R1-R13** and the **§5.5 Supported conditions**.

What this module is NOT. Like ``evidence.cnp_rules`` it is a function of *already computed*
dimension states. It extracts nothing and computes no effective provenance: REACH (§5.1
derivation), LOCUS, ENTRY, BIND, CFG, ``PROV_REACH`` and the hazard facts are the caller's
responsibility (``evidence.reach_derivation`` computes them from evidence; this module only
decides). The R1-R13 here are the rules of §5.4. They are unrelated to the inventory structural
check "R1" of ``evidence.inventory_checks``.

Interpretations the specification leaves open (each visible in the code and tested):

* **Hazard Step 1.** An ``EXCLUDED_BY_EVIDENCE`` claim stands only if its basis is bound to S and
  its basis provenance is at least P1; otherwise it is downgraded to ``UNKNOWN`` and
  ``HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>`` is recorded with R11 (§5.2). A
  ``MODELED_CONSERVATIVELY`` claim stands only if it is declared inside a K1 report; otherwise it
  is ``UNKNOWN`` with no extra code (the spec names the code for exclusion bases only). A class
  with no entry is ``UNKNOWN`` (the §5.2 default).
* **Code order inside R11.** Per hazard class, alphabetically by class token; for one class the
  ``HAZARD_<CLASS>`` code precedes ``HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>`` (the order RT7
  lists them in).
* **R2 code.** ``MISSING_EDGE_IS_UNKNOWN`` only when the caller states that the only
  reachability-related evidence is K4; otherwise ``NO_ANALYSIS`` (RT2, RT11).
* **Unresolved-dimension ceiling (register G18, addendum v0.2.3).** A required dimension in a
  state that fails its Supported condition and that no rule of §5.4 governs caps the verdict at
  Insufficient even when only Weak-ceiling rules triggered. For this predicate those states are
  exactly LOCUS and ENTRY ``Absent``, ``Ambiguous`` and ``Contradictory``, and CFG
  ``not_compared`` (declared, but there is no analysis whose configuration could be compared).
  Every state of REACH, BIND and HAZ, LOCUS ``Unknown``/``Incomplete`` and ENTRY
  ``Unknown``/``Incomplete`` is governed by a rule. The ceiling adds no code and no rationale
  class and is reported in ``VerdictResult.limitations``.
* **Consistency of the REACH inputs.** ``reach`` ``Absent`` and ``Ambiguous`` are only producible
  from a K1 basis, ``Incomplete`` needs a basis (K1, or ``NON_EXHAUSTIVE``), and ``prov_reach`` is
  required exactly when REACH is not ``Unknown`` (it is undefined otherwise, §5.1). Inputs that
  violate this are a ``ValueError``: they cannot arise from §5.1 and are never silently repaired.

Unlike the CNP engine there is no artifact-kind branch: §5 does not use ``S.artifact_kind``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Callable, Mapping, Optional

from evidence.cnp_rules import BindState
from evidence.rule_core import TriggeredRule, minimum_ceiling, order_triggered, render_rationale
from model import EvidenceState, ProvenanceLevel
from reports.verdict import RationaleClass, Verdict, VerdictResult

PREDICATE = "vulnerable_code_not_in_execute_path"
HAZARD_CLASS_LIST_VERSION = "hazard-classes-v1"  # A4: the enumeration is closed and versioned


class HazardClass(str, Enum):
    """The closed hazard enumeration of §5.3 (A4). The value is the token used in rule codes
    (``HAZARD_<token>``); the tokens other than ``REFLECTION`` are this project's naming of the
    §5.3 list and are an implementation convention."""

    REFLECTION = "REFLECTION"
    DYNAMIC_LOADING = "DYNAMIC_LOADING"                        # dynamic or class loading and plugins
    CONFIGURATION_DEPENDENT_PATHS = "CONFIGURATION_DEPENDENT_PATHS"  # flags, profiles, DI wiring
    NATIVE_FFI = "NATIVE_FFI"                                  # native and FFI boundaries
    SERIALIZATION_GADGETS = "SERIALIZATION_GADGETS"            # serialization gadget paths
    GENERATED_CODE = "GENERATED_CODE"                          # generated or annotation-driven code
    INTER_PROCESS_CALLS = "INTER_PROCESS_CALLS"                # inter-process and inter-service calls
    BUILD_TIME_PRUNING = "BUILD_TIME_PRUNING"                  # build-time pruning differences


class HazardDisposition(str, Enum):
    """§5.2 dispositions. ``UNKNOWN`` is the default."""

    EXCLUDED_BY_EVIDENCE = "excluded_by_evidence"
    MODELED_CONSERVATIVELY = "modeled_conservatively"
    UNMODELED = "unmodeled"
    UNKNOWN = "unknown"


class ReachBasis(str, Enum):
    """The basis of a REACH conclusion (§5.1): K1 analysis, or the ``non_exhaustive`` basis of
    derivation step 3 (K3 no-hit or K2 negative assertion)."""

    K1 = "k1"
    NON_EXHAUSTIVE = "non_exhaustive"


class CfgState(str, Enum):
    """CFG relative to the claim (§5.1, R12, §5.5).

    ``DECLARED`` is "declared and covers the claim". ``UNDECLARED`` and ``EXTENDS_BEYOND`` are
    the two conditions of R12. ``NOT_COMPARED`` means S states a configuration but there is no
    analysis whose analysed configurations could be compared with it; no rule governs it, so it
    imposes the unresolved-dimension ceiling.
    """

    DECLARED = "declared"
    UNDECLARED = "undeclared"
    EXTENDS_BEYOND = "extends_beyond"
    NOT_COMPARED = "not_compared"


@dataclass(frozen=True)
class HazardInput:
    """One hazard class before Step 1. ``basis_bound`` and ``basis_ep`` describe the
    ``basis_ref`` of an exclusion claim (``None`` EP: the basis is missing). ``declared_in_k1``
    says a modeled-conservatively claim is declared inside a K1 report."""

    disposition: HazardDisposition = HazardDisposition.UNKNOWN
    basis_bound: bool = False
    basis_ep: Optional[ProvenanceLevel] = None
    declared_in_k1: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, HazardDisposition):
            raise TypeError("disposition must be a HazardDisposition")
        if not isinstance(self.basis_bound, bool) or not isinstance(self.declared_in_k1, bool):
            raise TypeError("basis_bound and declared_in_k1 must be bool")
        if self.basis_ep is not None and not isinstance(self.basis_ep, ProvenanceLevel):
            raise TypeError("basis_ep must be a ProvenanceLevel or None")


@dataclass(frozen=True)
class EffectiveHazard:
    """A hazard class after Step 1."""

    hazard_class: HazardClass
    claimed: HazardDisposition
    effective: HazardDisposition
    provenance_downgrade: bool
    note: str


@dataclass(frozen=True)
class ReachInputs:
    """The already computed inputs of ``Req(vulnerable_code_not_in_execute_path)``.

    ``reach_basis`` is required when ``reach`` is Incomplete or Ambiguous (and must be K1 for
    Absent and Ambiguous). ``only_k4_evidence`` is the caller's statement that the only
    reachability-related evidence is K4 (R2's code). ``prov_reach`` is ``PROV_REACH``: required
    exactly when REACH is not Unknown. ``hazards`` maps a class to its claim; a missing class is
    Unknown.
    """

    reach: EvidenceState
    locus: EvidenceState
    entry: EvidenceState
    bind: BindState
    cfg: CfgState
    prov_reach: Optional[ProvenanceLevel] = None
    reach_basis: Optional[ReachBasis] = None
    only_k4_evidence: bool = False
    hazards: Mapping[HazardClass, HazardInput] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, value, expected in (("reach", self.reach, EvidenceState), ("locus", self.locus, EvidenceState),
                                      ("entry", self.entry, EvidenceState), ("bind", self.bind, BindState),
                                      ("cfg", self.cfg, CfgState)):
            if not isinstance(value, expected):
                raise TypeError(f"{name} must be a {expected.__name__}")
        if self.prov_reach is not None and not isinstance(self.prov_reach, ProvenanceLevel):
            raise TypeError("prov_reach must be a ProvenanceLevel or None")
        if self.reach_basis is not None and not isinstance(self.reach_basis, ReachBasis):
            raise TypeError("reach_basis must be a ReachBasis or None")
        if not isinstance(self.only_k4_evidence, bool):
            raise TypeError("only_k4_evidence must be a bool")
        if not isinstance(self.hazards, Mapping):
            raise TypeError("hazards must be a mapping of HazardClass to HazardInput")
        for key, value in self.hazards.items():
            if not isinstance(key, HazardClass) or not isinstance(value, HazardInput):
                raise TypeError("hazards must map HazardClass to HazardInput")
        object.__setattr__(self, "hazards", MappingProxyType(dict(self.hazards)))
        if self.reach is EvidenceState.UNKNOWN and self.prov_reach is not None:
            raise ValueError("prov_reach is undefined when REACH is Unknown")
        if self.reach is not EvidenceState.UNKNOWN and self.prov_reach is None:
            raise ValueError("prov_reach (PROV_REACH) is required when REACH is defined")
        if self.reach in (EvidenceState.ABSENT, EvidenceState.AMBIGUOUS) and self.reach_basis is not ReachBasis.K1:
            raise ValueError(f"REACH {self.reach.value} can only come from a K1 basis (§5.1)")
        if self.reach is EvidenceState.INCOMPLETE and self.reach_basis is None:
            raise ValueError("REACH Incomplete needs a basis (k1 or non_exhaustive)")
        if self.reach_basis is ReachBasis.NON_EXHAUSTIVE and self.reach is not EvidenceState.INCOMPLETE:
            raise ValueError("the non_exhaustive basis only gives REACH Incomplete (§5.1 step 3)")


@dataclass(frozen=True)
class ReachEvaluation:
    """The outcome of ``evaluate_reach``.

    ``result`` is the single final ``(verdict, codes, rationale)``; ``triggered`` every
    triggered rule in output order (R11 contributes one entry per code). ``hazards`` is the
    Step 1 view of every class. ``unmet_supported_conditions`` names each §5.5 condition that
    does not hold; ``unresolved_dimensions`` the states that impose the unresolved-dimension
    ceiling (also in ``result.limitations``).
    """

    inputs: ReachInputs
    result: VerdictResult
    triggered: tuple[TriggeredRule, ...]
    hazards: tuple[EffectiveHazard, ...]
    supported_conditions_hold: bool
    unmet_supported_conditions: tuple[str, ...]
    unresolved_dimensions: tuple[str, ...] = ()

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(rule.rule_id for rule in self.triggered))


# ---- Step 1: hazard normalization (§5.2) -----------------------------------------------------------

_OK_HAZARD = frozenset({HazardDisposition.EXCLUDED_BY_EVIDENCE, HazardDisposition.MODELED_CONSERVATIVELY})


def normalize_hazards(hazards: Mapping[HazardClass, HazardInput]) -> tuple[EffectiveHazard, ...]:
    """Step 1 for every class of the closed enumeration, in alphabetical order of the class token."""
    result: list[EffectiveHazard] = []
    for hazard_class in sorted(HazardClass, key=lambda c: c.value):
        claim = hazards.get(hazard_class, HazardInput())
        effective, downgrade, note = claim.disposition, False, ""
        if claim.disposition is HazardDisposition.EXCLUDED_BY_EVIDENCE:
            if not claim.basis_bound:
                effective, downgrade, note = HazardDisposition.UNKNOWN, True, "the exclusion basis is missing or not bound to S"
            elif claim.basis_ep is None or claim.basis_ep < ProvenanceLevel.P1:
                shown = "missing" if claim.basis_ep is None else claim.basis_ep.name
                effective, downgrade, note = HazardDisposition.UNKNOWN, True, f"the exclusion basis provenance is {shown}, below P1"
        elif claim.disposition is HazardDisposition.MODELED_CONSERVATIVELY and not claim.declared_in_k1:
            effective, note = HazardDisposition.UNKNOWN, "the modeled-conservatively claim is not declared inside a K1 report"
        result.append(EffectiveHazard(hazard_class, claim.disposition, effective, downgrade, note))
    return tuple(result)


# ---- rule table (§5.4) -------------------------------------------------------------------------------

_C = RationaleClass.CONTRADICTORY_EVIDENCE
_K = RationaleClass.CANNOT_BE_ESTABLISHED
_B = RationaleClass.BELOW_BAR
_S = EvidenceState


@dataclass(frozen=True)
class _Context:
    inputs: ReachInputs
    hazards: tuple[EffectiveHazard, ...]


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    ceiling: Verdict
    rationale_class: RationaleClass
    code: str  # a fixed code; R2 and R11 compute theirs and use ``codes``
    applies: Callable[[_Context], Optional[str]]
    codes: Optional[Callable[[_Context], tuple[str, ...]]] = None


def _r1(c: _Context) -> Optional[str]:
    return "REACH is Present: a path or execution of the locus is observed or asserted" if c.inputs.reach is _S.PRESENT else None


def _r2(c: _Context) -> Optional[str]:
    if c.inputs.reach is not _S.UNKNOWN:
        return None
    if c.inputs.only_k4_evidence:
        return "REACH is Unknown and the only reachability-related evidence is K4 (a dependency graph, not call edges)"
    return "REACH is Unknown: no analysis establishes reachability"


def _r2_codes(c: _Context) -> tuple[str, ...]:
    return ("MISSING_EDGE_IS_UNKNOWN",) if c.inputs.only_k4_evidence else ("NO_ANALYSIS",)


def _r3(c: _Context) -> Optional[str]:
    return "REACH is Contradictory (positive evidence conflicts with a K1 absence)" if c.inputs.reach is _S.CONTRADICTORY else None


def _r4(c: _Context) -> Optional[str]:
    return "LOCUS is Unknown" if c.inputs.locus is _S.UNKNOWN else None


def _r5(c: _Context) -> Optional[str]:
    return "ENTRY is Unknown" if c.inputs.entry is _S.UNKNOWN else None


def _r6(c: _Context) -> Optional[str]:
    if c.inputs.bind is BindState.MISMATCHED:
        return "BIND is mismatched: the analysis is bound to something other than S"
    if c.inputs.bind is BindState.UNKNOWN:
        return "BIND is unknown: the analysis is not shown to be bound to S and the component version"
    return None


def _r7(c: _Context) -> Optional[str]:
    i = c.inputs
    if i.reach is _S.INCOMPLETE and i.reach_basis is ReachBasis.NON_EXHAUSTIVE:
        return "REACH is Incomplete on the non_exhaustive basis (K3 no-hit or K2 assertion); it never declares sufficient coverage"
    return None


def _r8(c: _Context) -> Optional[str]:
    i = c.inputs
    if i.reach in (_S.INCOMPLETE, _S.AMBIGUOUS) and i.reach_basis is ReachBasis.K1:
        return f"REACH is {i.reach.value} on a K1 basis (partial or unresolved call graph)"
    return None


def _r9(c: _Context) -> Optional[str]:
    return "LOCUS is Incomplete (possibly under-approximate)" if c.inputs.locus is _S.INCOMPLETE else None


def _r10(c: _Context) -> Optional[str]:
    return "ENTRY is Incomplete" if c.inputs.entry is _S.INCOMPLETE else None


def _unmodeled(c: _Context) -> list[EffectiveHazard]:
    return [h for h in c.hazards if h.effective not in _OK_HAZARD]


def _r11(c: _Context) -> Optional[str]:
    open_classes = _unmodeled(c)
    if not open_classes:
        return None
    return "hazard classes unmodeled or unknown after Step 1: " + ", ".join(h.hazard_class.value for h in open_classes)


def _r11_codes(c: _Context) -> tuple[str, ...]:
    codes: list[str] = []
    for hazard in _unmodeled(c):  # already in alphabetical class order
        codes.append(f"HAZARD_{hazard.hazard_class.value}")
        if hazard.provenance_downgrade:
            codes.append(f"HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:{hazard.hazard_class.value}")
    return tuple(codes)


def _r12(c: _Context) -> Optional[str]:
    if c.inputs.cfg is CfgState.UNDECLARED:
        return "CFG is undeclared"
    if c.inputs.cfg is CfgState.EXTENDS_BEYOND:
        return "the claim extends beyond the analysed configurations"
    return None


def _r13(c: _Context) -> Optional[str]:
    i = c.inputs
    if i.reach is not _S.UNKNOWN and i.prov_reach is not None and i.prov_reach < ProvenanceLevel.P3:
        return f"REACH is defined and PROV_REACH is {i.prov_reach.name}, below P3"
    return None


REACH_RULES: tuple[_Rule, ...] = (
    _Rule("R1", Verdict.INSUFFICIENT, _C, "CLAIM_CONTRADICTED_BY_PATH", _r1),
    _Rule("R2", Verdict.INSUFFICIENT, _K, "", _r2, _r2_codes),
    _Rule("R3", Verdict.INSUFFICIENT, _C, "REACH_CONFLICT", _r3),
    _Rule("R4", Verdict.INSUFFICIENT, _K, "NO_LOCUS", _r4),
    _Rule("R5", Verdict.INSUFFICIENT, _K, "ENTRYPOINTS_UNDECLARED", _r5),
    _Rule("R6", Verdict.INSUFFICIENT, _K, "SCOPE_UNBOUND", _r6),
    _Rule("R7", Verdict.WEAK, _B, "NON_EXHAUSTIVE_EVIDENCE", _r7),
    _Rule("R8", Verdict.WEAK, _B, "PARTIAL_OR_UNRESOLVED_CALLGRAPH", _r8),
    _Rule("R9", Verdict.WEAK, _B, "LOCUS_MAY_BE_UNDERAPPROXIMATE", _r9),
    _Rule("R10", Verdict.WEAK, _B, "ENTRYPOINTS_INCOMPLETE", _r10),
    _Rule("R11", Verdict.WEAK, _B, "", _r11, _r11_codes),
    _Rule("R12", Verdict.WEAK, _B, "CONFIG_ASSUMPTION_UNDECLARED", _r12),
    _Rule("R13", Verdict.WEAK, _B, "ANALYSIS_PROVENANCE_BELOW_P3", _r13),
)


# ---- Supported conditions (§5.5) --------------------------------------------------------------------------

def _unmet_supported_conditions(i: ReachInputs, hazards: tuple[EffectiveHazard, ...]) -> tuple[str, ...]:
    unmet: list[str] = []
    if not (i.reach is _S.ABSENT and i.reach_basis is ReachBasis.K1):
        unmet.append("REACH Absent from K1")
    if i.locus is not _S.PRESENT:
        unmet.append("LOCUS Present as an over-approximation")
    if i.entry is not _S.PRESENT:
        unmet.append("ENTRY Present and complete")
    open_classes = [h.hazard_class.value for h in hazards if h.effective not in _OK_HAZARD]
    if open_classes:
        unmet.append("every hazard class excluded by evidence or modeled conservatively (open: " + ", ".join(open_classes) + ")")
    if i.cfg is not CfgState.DECLARED:
        unmet.append("CFG declared and covering the claim")
    if i.bind is not BindState.MATCHED:
        unmet.append("BIND Present")
    if i.prov_reach is not ProvenanceLevel.P3:
        unmet.append("PROV_REACH = P3")
    return tuple(unmet)


def unresolved_dimensions(i: ReachInputs) -> tuple[str, ...]:
    """Dimension states that fail a Supported condition and that no rule of §5.4 governs (see the
    module docstring); they impose the Insufficient ceiling of §3 Step 4."""
    found: list[str] = []
    ungoverned = (_S.ABSENT, _S.AMBIGUOUS, _S.CONTRADICTORY)
    if i.locus in ungoverned:
        found.append(f"LOCUS={i.locus.value}")
    if i.entry in ungoverned:
        found.append(f"ENTRY={i.entry.value}")
    if i.cfg is CfgState.NOT_COMPARED:
        found.append("CFG=not_compared")
    return tuple(found)


# ---- evaluation ----------------------------------------------------------------------------------------------

def evaluate_reach(inputs: ReachInputs) -> ReachEvaluation:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)`` over already computed inputs."""
    if not isinstance(inputs, ReachInputs):
        raise TypeError("evaluate_reach takes ReachInputs")
    context = _Context(inputs, normalize_hazards(inputs.hazards))  # Step 1

    triggered_list: list[TriggeredRule] = []  # Step 3: every rule is evaluated; nothing short-circuits
    for rule in REACH_RULES:
        detail = rule.applies(context)
        if detail is None:
            continue
        for code in (rule.codes(context) if rule.codes is not None else (rule.code,)):
            triggered_list.append(TriggeredRule(rule.rule_id, code, rule.ceiling, rule.rationale_class, detail))
    triggered = order_triggered(triggered_list)
    unmet = _unmet_supported_conditions(inputs, context.hazards)

    unresolved = unresolved_dimensions(inputs)  # Step 4
    if triggered:
        ceilings = [r.ceiling for r in triggered] + ([Verdict.INSUFFICIENT] if unresolved else [])
        result = VerdictResult(minimum_ceiling(ceilings), render_rationale(triggered),
                               tuple(r.code for r in triggered), unresolved)
    elif not unmet:
        result = VerdictResult(Verdict.SUPPORTED, "", ())
    else:
        rationale = (f"{RationaleClass.NO_RULE_APPLIES.value}[]: no rule triggered, but Supported conditions not met: "
                     + "; ".join(unmet))
        result = VerdictResult(Verdict.INSUFFICIENT, rationale, (), unresolved)

    return ReachEvaluation(
        inputs=inputs,
        result=result,
        triggered=triggered,
        hazards=context.hazards,
        supported_conditions_hold=not unmet,
        unmet_supported_conditions=unmet,
        unresolved_dimensions=unresolved,
    )
