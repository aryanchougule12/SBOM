"""Pure rule evaluation for ``Req(component_not_present)`` (Phase 1 of the prototype).

Implements, from ``docs/formal_specification_v0.2.md`` and nothing else:

* **§3 Steps 3-5** -- every rule of the predicate's table is evaluated (no
  short-circuiting); the verdict is the minimum ceiling over the triggered rules; if no
  rule triggers and every Supported condition holds the verdict is Supported; if no rule
  triggers but a Supported condition fails, the verdict is Insufficient with the rationale
  class ``NO_RULE_APPLIES`` and no code; every triggered code is output, ordered by
  rationale-class rank (CONTRADICTORY, CANNOT, BELOW), then by rule-family prefix, then
  by the numeric suffix as an integer.
* **§4.2 rules N1-N17** and the §4.3 manifest-only trigger (N14/N15/N16).
* **§4.4 Supported conditions.**

What this module is NOT. It is a function of *already computed* dimension states. It
extracts nothing, matches nothing, binds nothing and computes no effective provenance:
Steps 0-2 of §3 (EP, role values, dimension states) are the caller's responsibility, and
how a later phase produces them is outside this module. No reachability predicate, input
profile, CLI or rendering lives here.

Interpretations the specification leaves open (each is visible in the code and tested):

* ``INV`` accepts ``None`` for "missing". N2 reads "INV Unknown or missing": ``Unknown``
  and ``None`` trigger it. ``INV = Absent`` is *not* read as "missing" (the specification
  does not say so), so no rule covers it.
* ``BIND`` has three distinct input states (``MATCHED``, ``MISMATCHED``, ``UNKNOWN``).
  N3 treats the last two identically, but the factual state is preserved in the
  evaluation and named in the rationale text.
* Step 4 applies the unresolved-dimension ceiling of the clarified specification (section 3,
  addendum v0.2.2, register G18). A required dimension in a state that fails its Supported
  condition and that no rule of the table governs caps the verdict at Insufficient even when only
  Weak-ceiling rules triggered. For this predicate those states are exactly: MATCH ``Unknown``;
  INV ``Absent``, ``Incomplete``, ``Ambiguous``; DECL ``Absent``, ``Ambiguous``, ``Contradictory``.
  The states that a rule governs keep that rule's ceiling (INV Unknown/missing N2, INV
  Contradictory N4, BIND N3, DECL Unknown N5/N7, DECL Incomplete N6, MATCH Present N1, Ambiguous
  N8, Incomplete N9, Contradictory N17, GEN N14/N15). Without the extension to the INV and DECL
  states, a lower provenance level could raise the verdict (a Weak N12 would replace the
  no-rule default Insufficient), which P-3 forbids. The ceiling adds no code or rationale class;
  it is reported in ``VerdictResult.limitations`` and ``CnpEvaluation.unresolved_dimensions``.
* Several rationale classes in one result are rendered as one ``<CLASS>[CODE,...]: text``
  segment per class, in class-rank order, joined by `` | `` (the specification gives the
  grammar of a single segment). A Supported result has no class and an empty rationale.

Unresolved branch (register G10). ``ArtifactKind.UNKNOWN`` is not one of the four values
of §1 and the specification does not say how N14/N15/N16 and the §4.4 content-basis
condition treat it. ``evaluate_cnp`` raises ``UnresolvedArtifactKindError`` instead of
choosing: it is never read as ``SOURCE`` or ``OTHER``, and never as binary/container.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from evidence.rule_core import TriggeredRule, minimum_ceiling, order_triggered, render_rationale
from model import ArtifactKind, EvidenceState, ProvenanceLevel
from reports.verdict import RationaleClass, Verdict, VerdictResult

PREDICATE = "component_not_present"


class BindState(str, Enum):
    """The factual state of BIND (§4.1): the inventory and declaration are bound to S
    (``MATCHED``, "BIND Present" in the specification), demonstrably bound to something
    else (``MISMATCHED``), or the binding cannot be established (``UNKNOWN``)."""

    MATCHED = "matched"
    MISMATCHED = "mismatched"
    UNKNOWN = "unknown"


class GenState(str, Enum):
    """GEN of the primary SBOM relative to C (§4.1): exactly one of three values."""

    MANIFEST_ONLY = "manifest_only"
    CONTENT_BASED = "content_based"
    UNKNOWN = "unknown"


class UnresolvedArtifactKindError(ValueError):
    """``ArtifactKind.UNKNOWN`` was supplied; the specification does not define its
    effect on N14/N15/N16 or on the §4.4 content-basis condition (register G10)."""


@dataclass(frozen=True)
class SeparateContentBasis:
    """A content-based corroborating document that is separate from the primary SBOM
    (§4.3, ``PROV_CORR``).

    ``meets_basis_criteria`` is the caller's determination that the document satisfies
    every requirement of a content-based basis *other than* provenance: BIND(d) Present,
    a declared method that analyses the shipped artifact's contents, whole (not Incomplete)
    declared coverage, and ecosystem coverage that includes ``C.ecosystem``. ``ep`` is its
    effective provenance. The document qualifies as a basis only if the criteria are met
    and ``ep >= P1`` (§4.3).
    """

    ep: ProvenanceLevel
    meets_basis_criteria: bool

    def __post_init__(self) -> None:
        if not isinstance(self.ep, ProvenanceLevel):
            raise TypeError("ep must be a ProvenanceLevel")
        if not isinstance(self.meets_basis_criteria, bool):
            raise TypeError("meets_basis_criteria must be a bool")

    @property
    def qualifies(self) -> bool:
        return self.meets_basis_criteria and self.ep >= ProvenanceLevel.P1


@dataclass(frozen=True)
class CnpInputs:
    """The already computed inputs of ``Req(component_not_present)``.

    ``inv`` may be ``None`` for "missing" (N2). ``prov_decl`` is required exactly when
    ``decl`` is Present (it is the EP of the applicable completeness declaration, §1.2)
    and is ignored otherwise. ``gen`` and ``separate_basis`` matter only for binary and
    container artifacts (§4.3) and are ignored for ``SOURCE`` and ``OTHER``.
    ``provenance_metadata_contradiction`` is the caller's determination of N13's
    condition ("contradiction confined to provenance metadata").
    """

    artifact_kind: ArtifactKind
    inv: Optional[EvidenceState]
    match: EvidenceState
    decl: EvidenceState
    bind: BindState
    prov_sbom: ProvenanceLevel
    prov_decl: Optional[ProvenanceLevel] = None
    gen: GenState = GenState.UNKNOWN
    separate_basis: Optional[SeparateContentBasis] = None
    provenance_metadata_contradiction: bool = False

    def __post_init__(self) -> None:
        checks = (
            ("artifact_kind", self.artifact_kind, ArtifactKind),
            ("match", self.match, EvidenceState),
            ("decl", self.decl, EvidenceState),
            ("bind", self.bind, BindState),
            ("prov_sbom", self.prov_sbom, ProvenanceLevel),
            ("gen", self.gen, GenState),
        )
        for name, value, expected in checks:
            if not isinstance(value, expected):
                raise TypeError(f"{name} must be a {expected.__name__}")
        if self.inv is not None and not isinstance(self.inv, EvidenceState):
            raise TypeError("inv must be an EvidenceState or None (missing)")
        if self.prov_decl is not None and not isinstance(self.prov_decl, ProvenanceLevel):
            raise TypeError("prov_decl must be a ProvenanceLevel or None")
        if self.separate_basis is not None and not isinstance(self.separate_basis, SeparateContentBasis):
            raise TypeError("separate_basis must be a SeparateContentBasis or None")
        if not isinstance(self.provenance_metadata_contradiction, bool):
            raise TypeError("provenance_metadata_contradiction must be a bool")
        if self.decl is EvidenceState.PRESENT and self.prov_decl is None:
            raise ValueError("prov_decl (PROV_DECL) is required when decl is Present")


@dataclass(frozen=True)
class CnpEvaluation:
    """The outcome of ``evaluate_cnp``.

    ``result`` is the single final ``(verdict, codes, rationale)`` of §3 as clarified by
    addendum v0.2.2. ``triggered`` lists every triggered rule in output order.
    ``unmet_supported_conditions`` names each §4.4 condition that does not hold.
    ``unresolved_dimensions`` names the dimension states that impose the unresolved-dimension
    ceiling (they are also in ``result.limitations``). ``uncovered_states`` names every
    dimension state that no rule of the table addresses; it equals ``unresolved_dimensions``
    (kept as a separate field for callers written before the ceiling covered every such state).
    """

    inputs: CnpInputs
    result: VerdictResult
    triggered: tuple[TriggeredRule, ...]
    supported_conditions_hold: bool
    unmet_supported_conditions: tuple[str, ...]
    uncovered_states: tuple[str, ...]
    unresolved_dimensions: tuple[str, ...] = ()

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(rule.rule_id for rule in self.triggered)


# ---- derived facts (§4.3) -------------------------------------------------------------------

@dataclass(frozen=True)
class _Context:
    inputs: CnpInputs
    binary_or_container: bool
    primary_is_basis: bool
    separate_qualifies: bool

    @property
    def basis_exists(self) -> bool:
        return self.primary_is_basis or self.separate_qualifies

    @property
    def n14_n15_preconditions(self) -> bool:
        """``artifact_kind`` is binary/container and no content-based basis exists."""
        return self.binary_or_container and not self.basis_exists

    @property
    def separate_relied_upon(self) -> bool:
        """A separate basis removes N14/N15 only if the primary SBOM is not itself the
        basis (N16: "If the primary SBOM itself is the content-based basis, N16 does not
        apply")."""
        return self.binary_or_container and not self.primary_is_basis and self.separate_qualifies


def _context(inputs: CnpInputs) -> _Context:
    kind = inputs.artifact_kind
    if kind is ArtifactKind.UNKNOWN:
        raise UnresolvedArtifactKindError(
            "ArtifactKind.UNKNOWN: the specification does not define its effect on N14/N15/N16 "
            "or on the section 4.4 content-basis condition (register G10); it is never read as "
            "source, other, binary or container"
        )
    binary_or_container = kind in (ArtifactKind.BINARY, ArtifactKind.CONTAINER)
    return _Context(
        inputs=inputs,
        binary_or_container=binary_or_container,
        primary_is_basis=binary_or_container and inputs.gen is GenState.CONTENT_BASED,
        separate_qualifies=inputs.separate_basis is not None and inputs.separate_basis.qualifies,
    )


# ---- rule table (§4.2) ------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    rule_id: str
    ceiling: Verdict
    rationale_class: RationaleClass
    code: str
    applies: Callable[[_Context], Optional[str]]  # a detail text when triggered, else None


_C = RationaleClass.CONTRADICTORY_EVIDENCE
_K = RationaleClass.CANNOT_BE_ESTABLISHED
_B = RationaleClass.BELOW_BAR
_S = EvidenceState


def _n1(c: _Context) -> Optional[str]:
    return "aggregated MATCH is Present: the component was found in the inventory" if c.inputs.match is _S.PRESENT else None


def _n2(c: _Context) -> Optional[str]:
    if c.inputs.inv is None:
        return "INV is missing"
    return "INV is Unknown" if c.inputs.inv is _S.UNKNOWN else None


def _n3(c: _Context) -> Optional[str]:
    if c.inputs.bind is BindState.MISMATCHED:
        return "BIND is mismatched: the inventory is bound to something other than S"
    if c.inputs.bind is BindState.UNKNOWN:
        return "BIND is unknown: the inventory is not shown to be bound to S"
    return None


def _n4(c: _Context) -> Optional[str]:
    return "INV is Contradictory (inventory-level structural contradiction)" if c.inputs.inv is _S.CONTRADICTORY else None


def _n5(c: _Context) -> Optional[str]:
    i = c.inputs
    return "DECL is Unknown and PROV_SBOM is P0" if i.decl is _S.UNKNOWN and i.prov_sbom is ProvenanceLevel.P0 else None


def _n6(c: _Context) -> Optional[str]:
    return "DECL is Incomplete" if c.inputs.decl is _S.INCOMPLETE else None


def _n7(c: _Context) -> Optional[str]:
    i = c.inputs
    return "DECL is Unknown and PROV_SBOM is at least P1" if i.decl is _S.UNKNOWN and i.prov_sbom >= ProvenanceLevel.P1 else None


def _n8(c: _Context) -> Optional[str]:
    return "MATCH is Ambiguous" if c.inputs.match is _S.AMBIGUOUS else None


def _n9(c: _Context) -> Optional[str]:
    return "MATCH is Incomplete (identifier variants under-enumerated)" if c.inputs.match is _S.INCOMPLETE else None


def _n10(c: _Context) -> Optional[str]:
    i = c.inputs
    return "DECL is Present and PROV_DECL is P0" if i.decl is _S.PRESENT and i.prov_decl is ProvenanceLevel.P0 else None


def _n11(c: _Context) -> Optional[str]:
    i = c.inputs
    if i.decl is _S.PRESENT and i.prov_decl in (ProvenanceLevel.P1, ProvenanceLevel.P2):
        return f"DECL is Present and PROV_DECL is {i.prov_decl.name}"
    return None


def _n12(c: _Context) -> Optional[str]:
    p = c.inputs.prov_sbom
    return f"PROV_SBOM is {p.name}, below P3" if p < ProvenanceLevel.P3 else None


def _n13(c: _Context) -> Optional[str]:
    return "a contradiction confined to provenance metadata was reported" if c.inputs.provenance_metadata_contradiction else None


def _n14(c: _Context) -> Optional[str]:
    if c.n14_n15_preconditions and c.inputs.gen is GenState.MANIFEST_ONLY:
        return "binary/container artifact, manifest-only generation, no content-based basis"
    return None


def _n15(c: _Context) -> Optional[str]:
    if c.n14_n15_preconditions and c.inputs.gen is GenState.UNKNOWN:
        return "binary/container artifact, generation method unknown relative to C, no content-based basis"
    return None


def _n16(c: _Context) -> Optional[str]:
    if c.separate_relied_upon and c.inputs.separate_basis.ep < ProvenanceLevel.P3:  # type: ignore[union-attr]
        return f"a separate content-based document is relied upon but its EP is {c.inputs.separate_basis.ep.name}, below P3"  # type: ignore[union-attr]
    return None


def _n17(c: _Context) -> Optional[str]:
    return "MATCH is Contradictory (one source finds C, another with declared sufficient coverage asserts absence)" if c.inputs.match is _S.CONTRADICTORY else None


CNP_RULES: tuple[_Rule, ...] = (
    _Rule("N1", Verdict.INSUFFICIENT, _C, "CLAIM_CONTRADICTED_BY_INVENTORY", _n1),
    _Rule("N2", Verdict.INSUFFICIENT, _K, "NO_INVENTORY", _n2),
    _Rule("N3", Verdict.INSUFFICIENT, _K, "SCOPE_UNBOUND", _n3),
    _Rule("N4", Verdict.INSUFFICIENT, _C, "INVENTORY_CONTRADICTION", _n4),
    _Rule("N5", Verdict.INSUFFICIENT, _K, "NO_EVIDENTIAL_VALUE", _n5),
    _Rule("N6", Verdict.WEAK, _B, "DECLARED_INCOMPLETE", _n6),
    _Rule("N7", Verdict.WEAK, _B, "COMPLETENESS_UNDECLARED", _n7),
    _Rule("N8", Verdict.WEAK, _B, "AMBIGUOUS_IDENTITY", _n8),
    _Rule("N9", Verdict.WEAK, _B, "VARIANT_COVERAGE_INCOMPLETE", _n9),
    _Rule("N10", Verdict.WEAK, _B, "UNATTRIBUTED_DECLARATION", _n10),
    _Rule("N11", Verdict.WEAK, _B, "DECLARATION_BELOW_P3", _n11),
    _Rule("N12", Verdict.WEAK, _B, "INVENTORY_PROVENANCE_BELOW_P3", _n12),
    _Rule("N13", Verdict.WEAK, _C, "PROVENANCE_INCONSISTENT", _n13),
    _Rule("N14", Verdict.WEAK, _B, "MANIFEST_ONLY_UNCORROBORATED", _n14),
    _Rule("N15", Verdict.WEAK, _K, "GENERATION_METHOD_UNKNOWN", _n15),
    _Rule("N16", Verdict.WEAK, _B, "CORROBORATION_PROVENANCE_BELOW_P3", _n16),
    _Rule("N17", Verdict.INSUFFICIENT, _C, "MATCH_CONTRADICTION", _n17),
)

# ---- Supported conditions (§4.4) ------------------------------------------------------------------

def _unmet_supported_conditions(c: _Context) -> tuple[str, ...]:
    i = c.inputs
    unmet: list[str] = []
    if i.inv is not _S.PRESENT:
        unmet.append("INV Present as a full list")
    if i.match is not _S.ABSENT:
        unmet.append("MATCH Absent over all variants")
    if i.decl is not _S.PRESENT:
        unmet.append("DECL Present (complete)")
    if i.bind is not BindState.MATCHED:
        unmet.append("BIND Present")
    if i.prov_sbom is not ProvenanceLevel.P3:
        unmet.append("PROV_SBOM = P3")
    if i.decl is _S.PRESENT and i.prov_decl is not ProvenanceLevel.P3:
        unmet.append("PROV_DECL = P3")  # PROV_DECL is undefined unless DECL is Present
    if c.binary_or_container:
        if not c.basis_exists:
            unmet.append("content-based basis exists (binary or container artifact)")
        elif c.separate_relied_upon and c.inputs.separate_basis.ep is not ProvenanceLevel.P3:  # type: ignore[union-attr]
            unmet.append("separate corroborating basis has EP = P3")
    return tuple(unmet)


def _uncovered_states(i: CnpInputs) -> tuple[str, ...]:
    """Dimension states that fail a Supported condition and that no rule of the table addresses
    (section 3 Step 4 as clarified in addendum v0.2.2): MATCH Unknown; INV Absent, Incomplete,
    Ambiguous; DECL Absent, Ambiguous, Contradictory."""
    found: list[str] = []
    if i.match is _S.UNKNOWN:
        found.append("MATCH=Unknown")
    if i.inv in (_S.ABSENT, _S.INCOMPLETE, _S.AMBIGUOUS):
        found.append(f"INV={i.inv.value}")
    if i.decl in (_S.ABSENT, _S.AMBIGUOUS, _S.CONTRADICTORY):
        found.append(f"DECL={i.decl.value}")
    return tuple(found)


def _unresolved_dimensions(i: CnpInputs) -> tuple[str, ...]:
    """The unresolved-dimension ceiling applies to exactly the uncovered states."""
    return _uncovered_states(i)


# ---- evaluation ------------------------------------------------------------------------------------------

def evaluate_cnp(inputs: CnpInputs) -> CnpEvaluation:
    """Evaluate ``Req(component_not_present)`` over already computed dimension inputs.

    Raises ``UnresolvedArtifactKindError`` for ``ArtifactKind.UNKNOWN`` (register G10).
    """
    context = _context(inputs)

    # Step 3: every rule is evaluated; nothing short-circuits.
    triggered = order_triggered(
        TriggeredRule(rule.rule_id, rule.code, rule.ceiling, rule.rationale_class, detail)
        for rule in CNP_RULES
        for detail in (rule.applies(context),)
        if detail is not None
    )
    unmet = _unmet_supported_conditions(context)

    # Step 4, with the unresolved-dimension ceiling.
    unresolved = _unresolved_dimensions(inputs)
    if triggered:
        ceilings = [r.ceiling for r in triggered] + ([Verdict.INSUFFICIENT] if unresolved else [])
        verdict = minimum_ceiling(ceilings)
        result = VerdictResult(verdict, render_rationale(triggered), tuple(r.code for r in triggered), unresolved)
    elif not unmet:
        result = VerdictResult(Verdict.SUPPORTED, "", ())
    else:
        # No-rule default: no code, and it never co-occurs with a triggered rule's code.
        rationale = f"{RationaleClass.NO_RULE_APPLIES.value}[]: no rule triggered, but Supported conditions not met: " + "; ".join(unmet)
        result = VerdictResult(Verdict.INSUFFICIENT, rationale, (), unresolved)

    return CnpEvaluation(
        inputs=inputs,
        result=result,
        triggered=triggered,
        supported_conditions_hold=not unmet,
        unmet_supported_conditions=unmet,
        uncovered_states=_uncovered_states(inputs),
        unresolved_dimensions=unresolved,
    )
