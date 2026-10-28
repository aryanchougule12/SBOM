"""Pure INV state derivation for the primary SBOM (Stage 2; register G11, G3c).

INV (formal specification section 4.1) is the observation status of "the full component list
for S (not direct dependencies only)". ``derive_inv`` combines four things the caller already
has, and nothing else:

* the validated profile (``evidence.profile``): the evaluator-entered INV assertion and its
  diagnostics;
* the BIND result for the primary SBOM (``evidence.bind``);
* an explicit ``InventoryAssessment``: what a structural check *that actually ran* reported,
  and whether the inventory is interpretable and non-empty.

Document identity. The BIND result and the assessment must each name the document they
were derived from (``BindEvaluation.document_id``, ``InventoryAssessment.document_id``) and
both must equal the profile's single ``primary_sbom`` document id (exact string equality). A
subject reference or locator is document-relative and is not an identity. A missing or
different identity is not an error: it is a stable reason (``INV_DERIVATION_BIND_DOCUMENT_*``,
``INV_DERIVATION_ASSESSMENT_DOCUMENT_*``) and the state is ``Unknown``, consistent with how
every other unmet prerequisite is reported. A BIND result with a wrong identity is treated as
no BIND for the primary document; an assessment with a wrong identity is ignored entirely
(its defects become ``FOREIGN_DOCUMENT_DEFECT`` diagnostics and are never attributed to the
primary document, so they cannot make INV ``Contradictory``).

The profile assertion never sets a state by itself. The derivation decides, in this order
(the approved INV/BIND principle):

1. BIND must be ``MATCHED`` (for the primary document) for ``Present`` or ``Contradictory``. With BIND ``UNKNOWN`` or
   ``MISMATCHED`` the state is ``Unknown``; a defect reported for such a document is only a
   document-level diagnostic (``UNBOUND_DOCUMENT_DEFECT``), never an INV contradiction.
2. With BIND ``MATCHED``, a structural contradiction that the caller has established as
   relevant to S gives ``Contradictory``. It takes precedence over the assertion, and it does
   not need one.
3. ``Present`` needs all of: BIND ``MATCHED``; a usable assertion; an assessment; at least
   one declared required check and every required check ``PASSED`` (performed, with no
   applicable contradiction found); no found defect whose relevance is undetermined; an
   ``INTERPRETABLE`` inventory; a ``NON_EMPTY`` inventory.
4. Anything else is ``Unknown``, with every unmet condition listed (first one is the reason).

An unperformed or unassessed check is never treated as a pass, and a missing assessment never
defaults to ``Present``.

What this module is NOT. It decides nothing that the repository has not approved:

* It computes no scope binding (BIND is an input), runs no structural classifier (G11 Q4:
  which checks are required, and what a dangling reference is, stay open), and defines no
  component or member, no full-depth interpretation and no empty-list state (G11 Q2).
  "Interpretable" and "non-empty" are statements by the caller. An empty inventory is
  ``Unknown`` here only because it cannot be ``Present``; that is not a ruling on G11 Q2.
* It never produces ``Absent``, ``Incomplete`` or ``Ambiguous`` (G18 is open); the result type
  refuses them.
* Duplicate identifiers (C3) are not a contradiction: they may be passed as notes, which never
  change the state.
* It grants no provenance level, computes no verdict or profile digest, and is not wired into
  extraction, BIND evaluation or the CNP engine.

The caller is responsible for the truth of the assessment and of the document identities it
states; the module can compare identities but cannot verify them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from evidence.bind import BindEvaluation
from evidence.cnp_rules import BindState
from evidence.profile import AssertionDiagnostic, ValidatedProfile
from model import EvidenceState


class CheckOutcome(str, Enum):
    """What one structural check reported. ``PASSED`` means the check ran and found no
    contradiction; ``NOT_PERFORMED`` is never a pass."""

    PASSED = "passed"
    CONTRADICTION_FOUND = "contradiction_found"
    NOT_PERFORMED = "not_performed"


class Relevance(str, Enum):
    """Whether a found defect has been demonstrated to concern S. ``UNDETERMINED`` is the
    default; relevance is a statement by the producer of the check, never inferred here."""

    RELEVANT_TO_S = "relevant_to_s"
    UNDETERMINED = "undetermined"


class Interpretability(str, Enum):
    INTERPRETABLE = "interpretable"
    UNINTERPRETABLE = "uninterpretable"
    NOT_ASSESSED = "not_assessed"


class Emptiness(str, Enum):
    NON_EMPTY = "non_empty"
    EMPTY = "empty"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class StructuralCheck:
    """One structural check, as reported by whoever ran (or did not run) it."""

    check_id: str
    required: bool
    outcome: CheckOutcome
    relevance: Relevance = Relevance.UNDETERMINED
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.check_id, str) or not self.check_id.strip():
            raise ValueError("a structural check needs a non-empty check_id")
        if not isinstance(self.required, bool):
            raise ValueError("'required' must be a bool")
        if not isinstance(self.outcome, CheckOutcome) or not isinstance(self.relevance, Relevance):
            raise ValueError("outcome and relevance must be CheckOutcome and Relevance values")
        if self.relevance is Relevance.RELEVANT_TO_S and self.outcome is not CheckOutcome.CONTRADICTION_FOUND:
            raise ValueError("only a found contradiction can be relevant to S")


@dataclass(frozen=True)
class InventoryAssessment:
    """Explicit inventory and structural-check input about ONE document, named by
    ``document_id`` (``None`` means it does not say, which can never yield ``Present``).
    ``checks`` is stored sorted by
    ``check_id``; ids must be unique. ``notes`` are document-level observations (for example
    duplicate identifiers, C3) and never change the derived state."""

    interpretability: Interpretability = Interpretability.NOT_ASSESSED
    emptiness: Emptiness = Emptiness.NOT_ASSESSED
    checks: tuple[StructuralCheck, ...] = ()
    notes: tuple[str, ...] = ()
    document_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.document_id is not None and (not isinstance(self.document_id, str) or not self.document_id.strip()):
            raise ValueError("document_id must be None or a non-empty string")
        if not isinstance(self.interpretability, Interpretability) or not isinstance(self.emptiness, Emptiness):
            raise ValueError("interpretability and emptiness must be enum values")
        checks = tuple(self.checks)
        if not all(isinstance(c, StructuralCheck) for c in checks):
            raise ValueError("checks must be StructuralCheck values")
        ids = [c.check_id for c in checks]
        if len(ids) != len(set(ids)):
            raise ValueError("structural check ids must be unique")
        object.__setattr__(self, "checks", tuple(sorted(checks, key=lambda c: c.check_id)))
        object.__setattr__(self, "notes", tuple(sorted(str(n) for n in self.notes)))


class AssertionStatus(str, Enum):
    USABLE = "usable"
    UNUSABLE = "unusable"
    MISSING = "missing"


class InvCode(str, Enum):
    """Stable reason and diagnostic codes, in the order several applicable ones are reported."""

    PRESENT = "INV_DERIVATION_PRESENT"
    STRUCTURAL_CONTRADICTION = "INV_DERIVATION_STRUCTURAL_CONTRADICTION"
    BIND_MISMATCHED = "INV_DERIVATION_BIND_MISMATCHED"
    BIND_UNKNOWN = "INV_DERIVATION_BIND_UNKNOWN"
    BIND_DOCUMENT_MISSING = "INV_DERIVATION_BIND_DOCUMENT_MISSING"
    BIND_DOCUMENT_MISMATCH = "INV_DERIVATION_BIND_DOCUMENT_MISMATCH"
    ASSERTION_MISSING = "INV_DERIVATION_ASSERTION_MISSING"
    ASSERTION_UNUSABLE = "INV_DERIVATION_ASSERTION_UNUSABLE"
    ASSESSMENT_MISSING = "INV_DERIVATION_ASSESSMENT_MISSING"
    ASSESSMENT_DOCUMENT_MISSING = "INV_DERIVATION_ASSESSMENT_DOCUMENT_MISSING"
    ASSESSMENT_DOCUMENT_MISMATCH = "INV_DERIVATION_ASSESSMENT_DOCUMENT_MISMATCH"
    NO_REQUIRED_CHECKS = "INV_DERIVATION_NO_REQUIRED_CHECKS"
    REQUIRED_CHECK_NOT_PERFORMED = "INV_DERIVATION_REQUIRED_CHECK_NOT_PERFORMED"
    DEFECT_RELEVANCE_UNDETERMINED = "INV_DERIVATION_DEFECT_RELEVANCE_UNDETERMINED"
    INVENTORY_UNINTERPRETABLE = "INV_DERIVATION_INVENTORY_UNINTERPRETABLE"
    INTERPRETABILITY_NOT_ASSESSED = "INV_DERIVATION_INTERPRETABILITY_NOT_ASSESSED"
    INVENTORY_EMPTY = "INV_DERIVATION_INVENTORY_EMPTY"
    EMPTINESS_NOT_ASSESSED = "INV_DERIVATION_EMPTINESS_NOT_ASSESSED"
    # diagnostics only (never a reason)
    UNBOUND_DOCUMENT_DEFECT = "INV_DERIVATION_UNBOUND_DOCUMENT_DEFECT"
    FOREIGN_DOCUMENT_DEFECT = "INV_DERIVATION_FOREIGN_DOCUMENT_DEFECT"
    INVENTORY_NOTE = "INV_DERIVATION_INVENTORY_NOTE"


_ORDER = {code: n for n, code in enumerate(InvCode)}
_DIAGNOSTIC_ONLY = frozenset({InvCode.UNBOUND_DOCUMENT_DEFECT, InvCode.FOREIGN_DOCUMENT_DEFECT, InvCode.INVENTORY_NOTE})
_ALLOWED_STATES = frozenset({EvidenceState.PRESENT, EvidenceState.UNKNOWN, EvidenceState.CONTRADICTORY})


@dataclass(frozen=True)
class InvDiagnostic:
    code: InvCode
    detail: str


@dataclass(frozen=True)
class InvDerivation:
    """The derived INV state with its reasons.

    ``state`` is ``Present``, ``Unknown`` or ``Contradictory`` only. ``reasons`` lists every
    unmet prerequisite of ``Present`` for ``Unknown`` (``reason`` is the first); ``PRESENT`` and
    ``STRUCTURAL_CONTRADICTION`` are the sole reason of their states. ``contradictions`` are the
    ids of the checks that established a contradiction relevant to S. ``assertion_diagnostics``
    are the profile's assertion diagnostics, unchanged. ``document_id`` is the profile's
    primary document; ``identity_verified`` is True only when both the BIND result and the
    assessment named exactly that document, and ``Present`` and ``Contradictory`` require it.
    It means exact document-id consistency and nothing more: it is not proof of artifact
    identity (that is BIND's separate, self-asserted comparison), not proof that the assessment
    is true, and not proof of the document's authenticity or integrity.
    """

    state: EvidenceState
    reason: InvCode
    bind_state: BindState
    assertion: AssertionStatus
    reasons: tuple[InvCode, ...] = ()
    contradictions: tuple[str, ...] = ()
    assertion_diagnostics: tuple[AssertionDiagnostic, ...] = ()
    diagnostics: tuple[InvDiagnostic, ...] = ()
    document_id: Optional[str] = None
    identity_verified: bool = False

    def __post_init__(self) -> None:
        if self.state not in _ALLOWED_STATES:
            raise ValueError(f"INV derivation cannot produce {self.state.value} (G18 is open)")
        if self.state is EvidenceState.UNKNOWN:
            consistent = bool(self.reasons) and self.reason is self.reasons[0] and not self.contradictions
            consistent = consistent and not ({InvCode.PRESENT, InvCode.STRUCTURAL_CONTRADICTION} & set(self.reasons))
        else:
            expected = InvCode.PRESENT if self.state is EvidenceState.PRESENT else InvCode.STRUCTURAL_CONTRADICTION
            consistent = (
                self.reason is expected and self.reasons == (expected,)
                and self.bind_state is BindState.MATCHED and self.identity_verified
                and bool(self.contradictions) == (self.state is EvidenceState.CONTRADICTORY)
            )
            if self.state is EvidenceState.PRESENT:
                consistent = consistent and self.assertion is AssertionStatus.USABLE
        if not consistent:
            raise ValueError(f"inconsistent InvDerivation: {self.state.value}, {self.reason}")


def _assertion_input(profile: ValidatedProfile) -> tuple[AssertionStatus, tuple[AssertionDiagnostic, ...]]:
    """Whether a usable assertion exists for the profile's primary document. An entered
    assertion that is not usable (including one naming another document) is ``UNUSABLE`` and
    its diagnostics are retained; ``MISSING`` means none was entered at all."""
    primary = profile.primary_document
    diagnostics = tuple(profile.assertion_diagnostics)
    if any(a.document == primary for a in profile.usable_inv_assertions):
        return AssertionStatus.USABLE, diagnostics
    if profile.inv_assertions:
        return AssertionStatus.UNUSABLE, diagnostics
    return AssertionStatus.MISSING, diagnostics


def _sorted(diagnostics: Iterable[InvDiagnostic]) -> tuple[InvDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda d: (_ORDER[d.code], d.detail)))


def _identity_codes(
    primary: str, bind: BindEvaluation, assessment: Optional[InventoryAssessment]
) -> tuple[list[InvDiagnostic], bool, bool]:
    """Compare the document ids with the primary document. Returns the unmet-identity
    diagnostics and whether the BIND result and the assessment each belong to the primary
    document (an absent assessment is not "ok")."""
    unmet: list[InvDiagnostic] = []
    bind_ok = bind.document_id == primary
    if bind.document_id is None:
        unmet.append(InvDiagnostic(InvCode.BIND_DOCUMENT_MISSING, "the BIND result names no source document"))
    elif not bind_ok:
        unmet.append(InvDiagnostic(
            InvCode.BIND_DOCUMENT_MISMATCH,
            f"the BIND result is for document {bind.document_id!r}, not the primary document {primary!r}"))
    assessment_ok = assessment is not None and assessment.document_id == primary
    if assessment is not None:
        if assessment.document_id is None:
            unmet.append(InvDiagnostic(InvCode.ASSESSMENT_DOCUMENT_MISSING, "the assessment names no document"))
        elif not assessment_ok:
            unmet.append(InvDiagnostic(
                InvCode.ASSESSMENT_DOCUMENT_MISMATCH,
                f"the assessment is for document {assessment.document_id!r}, not the primary document {primary!r}"))
    return unmet, bind_ok, assessment_ok


def derive_inv(
    profile: ValidatedProfile, bind: BindEvaluation, assessment: Optional[InventoryAssessment]
) -> InvDerivation:
    """Derive INV for the primary SBOM. Pure and deterministic: nothing is mutated and the
    result does not depend on the order of assertions, checks or notes."""
    primary = profile.primary_document
    assertion_status, assertion_diagnostics = _assertion_input(profile)
    identity_unmet, bind_ok, assessment_ok = _identity_codes(primary, bind, assessment)
    bound = bind.state is BindState.MATCHED and bind_ok
    verified = bound and assessment_ok
    used = assessment if assessment_ok else None  # a foreign or unidentified assessment is not used
    checks = used.checks if used is not None else ()
    diagnostics: list[InvDiagnostic] = [
        InvDiagnostic(InvCode.INVENTORY_NOTE, note) for note in (used.notes if used else ())
    ]

    if assessment is not None and not assessment_ok:  # never attributed to the primary document
        for check in assessment.checks:
            if check.outcome is CheckOutcome.CONTRADICTION_FOUND:
                diagnostics.append(InvDiagnostic(
                    InvCode.FOREIGN_DOCUMENT_DEFECT,
                    f"{check.check_id}: defect reported by an assessment that does not identify the primary "
                    f"document (it names {assessment.document_id!r})",
                ))

    found = [c for c in checks if c.outcome is CheckOutcome.CONTRADICTION_FOUND]
    relevant = [c for c in found if c.relevance is Relevance.RELEVANT_TO_S]
    if not bound:  # a defect in an unbound document is a document-level diagnostic only
        reason = f"BIND is {bind.state.value}" if bind.state is not BindState.MATCHED else (
            "the BIND result does not identify the primary document")
        for check in found:
            diagnostics.append(InvDiagnostic(
                InvCode.UNBOUND_DOCUMENT_DEFECT,
                f"{check.check_id}: reported defect is not an INV contradiction because {reason}"
                + (f" ({check.detail})" if check.detail else ""),
            ))

    if bound and relevant:
        return InvDerivation(
            state=EvidenceState.CONTRADICTORY, reason=InvCode.STRUCTURAL_CONTRADICTION, bind_state=bind.state,
            assertion=assertion_status, reasons=(InvCode.STRUCTURAL_CONTRADICTION,),
            contradictions=tuple(c.check_id for c in relevant),
            assertion_diagnostics=assertion_diagnostics, diagnostics=_sorted(diagnostics),
            document_id=primary, identity_verified=verified,
        )

    unmet: list[InvDiagnostic] = list(identity_unmet)
    if bind.state is BindState.MISMATCHED:
        unmet.append(InvDiagnostic(InvCode.BIND_MISMATCHED, "BIND is mismatched"))
    elif bind.state is BindState.UNKNOWN:
        unmet.append(InvDiagnostic(InvCode.BIND_UNKNOWN, "BIND is unknown"))
    if assertion_status is AssertionStatus.MISSING:
        unmet.append(InvDiagnostic(InvCode.ASSERTION_MISSING, "no INV assertion was entered for the primary document"))
    elif assertion_status is AssertionStatus.UNUSABLE:
        unmet.append(InvDiagnostic(InvCode.ASSERTION_UNUSABLE, "the entered INV assertion(s) are not usable"))

    if assessment is None:
        unmet.append(InvDiagnostic(InvCode.ASSESSMENT_MISSING, "no inventory assessment was supplied"))
    elif used is not None:
        required = [c for c in checks if c.required]
        if not required:
            unmet.append(InvDiagnostic(InvCode.NO_REQUIRED_CHECKS, "no required structural check is declared"))
        for check in required:
            if check.outcome is CheckOutcome.NOT_PERFORMED:
                unmet.append(InvDiagnostic(InvCode.REQUIRED_CHECK_NOT_PERFORMED,
                                           f"{check.check_id}: required check was not performed"))
        for check in found:  # reaching here: not bound, or bound with relevance undetermined
            if bound:
                unmet.append(InvDiagnostic(InvCode.DEFECT_RELEVANCE_UNDETERMINED,
                                           f"{check.check_id}: a defect was found and its relevance to S is undetermined"))
        if used.interpretability is Interpretability.UNINTERPRETABLE:
            unmet.append(InvDiagnostic(InvCode.INVENTORY_UNINTERPRETABLE, "the inventory is uninterpretable"))
        elif used.interpretability is Interpretability.NOT_ASSESSED:
            unmet.append(InvDiagnostic(InvCode.INTERPRETABILITY_NOT_ASSESSED, "interpretability was not assessed"))
        if used.emptiness is Emptiness.EMPTY:
            unmet.append(InvDiagnostic(InvCode.INVENTORY_EMPTY, "the inventory is empty"))
        elif used.emptiness is Emptiness.NOT_ASSESSED:
            unmet.append(InvDiagnostic(InvCode.EMPTINESS_NOT_ASSESSED, "emptiness was not assessed"))

    if not unmet:
        return InvDerivation(
            state=EvidenceState.PRESENT, reason=InvCode.PRESENT, bind_state=bind.state,
            assertion=assertion_status, reasons=(InvCode.PRESENT,),
            assertion_diagnostics=assertion_diagnostics, diagnostics=_sorted(diagnostics),
            document_id=primary, identity_verified=verified,
        )
    ordered = _sorted(unmet)
    return InvDerivation(
        state=EvidenceState.UNKNOWN, reason=ordered[0].code, bind_state=bind.state,
        assertion=assertion_status, reasons=tuple(dict.fromkeys(d.code for d in ordered)),
        assertion_diagnostics=assertion_diagnostics, diagnostics=_sorted([*diagnostics, *ordered]),
        document_id=primary, identity_verified=verified,
    )
