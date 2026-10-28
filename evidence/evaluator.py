"""The integrated ``Req(component_not_present)`` evaluator.

``evaluate(profile, findings, index, verification=None)`` runs the whole evidence pipeline for one
finding and one primary SBOM, and returns either an ``EvaluationOutcome`` (one final verdict with
all of its evidence) or an ``EvaluationRefusal`` (no verdict, a stable code).

Flow, each stage consuming only what the previous stages actually established:

1. ``pipeline_inputs.assemble``: select the one finding, apply the profile, resolve every profile
   document id exactly against the Stage 1 index, register the SBOM document.
2. ``inventory_observations`` and ``inventory_members``: neutral facts and the approved member
   domain, with source locators.
3. ``bind.evaluate_bind_for_profile``: BIND (B1-B5), a typed input.
4. ``document_provenance``: P0/P1 attribution, P2 from a DIGEST-basis BIND, P3 only from a trusted
   external ``VerificationResult`` and only inside its verified coverage.
5. ``inventory_checks``: the required check R1 -> ``InventoryAssessment``; ``inv.derive_inv``.
6. ``decl_derivation.derive_decl`` (profile placement, G6, "covers S"), ``match.derive_match``,
   ``generation.derive_gen`` (always `unknown`).
7. ``items``: typed evidence items, validated for source ids, roles, locators and derivation links.
8. ``cnp_adapter``: per-dimension aggregation and ``CnpInputs``; ``cnp_rules.evaluate_cnp``.

A failure in a stage never invents evidence for the next one: a stage that cannot establish its
dimension returns `Unknown` with a reason. Inputs that make a run meaningless (an invalid or
ambiguous profile, a missing primary record, a disposition or justification outside this
predicate, an unresolved artifact kind, malformed verification data, an item that fails its
integrity check) are **refusals**, in the same way the specification treats a non-`not_affected`
disposition as "an input error, not a verdict".

Scope of this milestone: only ``component_not_present``; one primary SBOM; no corroborating
documents; GEN `unknown` (D10 deferred); no reachability or hazard logic.

Trust boundary: ``verification`` is a trusted, out-of-band input (see ``evidence.verification``).
The profile, the documents and the parsers can never supply it.

The single final verdict is ``outcome.result``, produced by the engine under the clarified
specification (section 3 Step 4, addendum v0.2.2); there is no second, conflicting verdict.
``outcome.to_dict()`` is a complete, deterministic, JSON-serializable report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Union

from evidence.bind import BindEvaluation, evaluate_bind_for_profile
from evidence.cnp_adapter import DimensionAggregates, aggregate_dimensions, build_cnp_inputs
from evidence.cnp_rules import CnpEvaluation, CnpInputs, UnresolvedArtifactKindError, evaluate_cnp
from evidence.decl_derivation import DeclDerivation, derive_decl
from evidence.document_provenance import (
    DocumentProvenance,
    document_provenance,
    item_levels,
    minimum_level,
    record_consumed_integrity,
)
from evidence.generation import GenDerivation, derive_gen
from evidence.inv import InvCode, InvDerivation, derive_inv
from evidence.inventory_checks import ReferenceCheckResult, build_assessment
from evidence.inventory_members import inventory_members
from evidence.inventory_observations import InventoryObservations, observe_inventory
from evidence.items import (
    DIM_DECL,
    DIM_INV,
    ItemIntegrityError,
    build_items,
    items_of,
    validate_items,
)
from evidence.match import MatchDerivation, derive_match
from evidence.pipeline_inputs import AssemblyDiagnostic, AssemblyError, assemble
from evidence.profile import ProfileError, ValidatedProfile
from evidence.rule_core import jsonable as _jsonable
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig
from model import ArtifactKind, Disposition, EvidenceItem, EvidenceState, Finding, JustificationType, ProvenanceLevel
from reports.verdict import VerdictResult


class RefusalCode(str, Enum):
    PROFILE_INVALID = "EVAL_PROFILE_INVALID"
    ASSEMBLY_FAILED = "EVAL_ASSEMBLY_FAILED"
    VERIFICATION_INVALID = "EVAL_VERIFICATION_INVALID"
    DISPOSITION_NOT_EVALUATED = "EVAL_DISPOSITION_NOT_EVALUATED"
    JUSTIFICATION_NOT_SUPPORTED = "EVAL_JUSTIFICATION_NOT_SUPPORTED"
    ARTIFACT_KIND_UNRESOLVED = "EVAL_ARTIFACT_KIND_UNRESOLVED"
    ITEM_INTEGRITY_FAILED = "EVAL_ITEM_INTEGRITY_FAILED"
    # used by the evidence.reach_evaluator path and by evidence.sufficiency routing (additive)
    REACH_INPUT_INVALID = "EVAL_REACH_INPUT_INVALID"
    REACH_INPUT_NOT_APPLICABLE = "EVAL_REACH_INPUT_NOT_APPLICABLE"
    # used by evidence.analysis_ingest (analyzer artifacts)
    ANALYSIS_ARTIFACT_INVALID = "EVAL_ANALYSIS_ARTIFACT_INVALID"
    ANALYSIS_SUBJECT_INVALID = "EVAL_ANALYSIS_SUBJECT_INVALID"


@dataclass(frozen=True)
class EvaluationRefusal:
    """No verdict. ``cause`` is the stable code of the underlying error, when there is one."""

    code: RefusalCode
    detail: str
    cause: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"refused": True, "code": self.code.value, "cause": self.cause, "detail": self.detail}


@dataclass(frozen=True)
class ProvenanceSummary:
    document: DocumentProvenance
    prov_sbom: ProvenanceLevel
    prov_decl: Optional[ProvenanceLevel]
    item_levels: Mapping[str, ProvenanceLevel]


@dataclass(frozen=True)
class EvaluationOutcome:
    """The complete, reproducible result of one evaluation."""

    profile_id: str
    doc_id: str
    finding: Finding
    bind: BindEvaluation
    observations: InventoryObservations
    reference_check: ReferenceCheckResult
    inv: InvDerivation
    decl: DeclDerivation
    match: MatchDerivation
    gen: GenDerivation
    items: tuple[EvidenceItem, ...]
    aggregates: DimensionAggregates
    provenance: ProvenanceSummary
    cnp_inputs: CnpInputs
    evaluation: CnpEvaluation
    diagnostics: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def result(self) -> VerdictResult:
        """The single final verdict, codes and rationale (section 3, as clarified in v0.2.2)."""
        return self.evaluation.result

    @property
    def dimension_states(self) -> Mapping[str, str]:
        return {
            "BIND": self.bind.state.value,
            "DECL": self.cnp_inputs.decl.value,
            "GEN": self.cnp_inputs.gen.value,
            "INV": self.cnp_inputs.inv.value if self.cnp_inputs.inv is not None else "missing",
            "MATCH": self.cnp_inputs.match.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


def _refuse(code: RefusalCode, detail: str, cause: Optional[str] = None) -> EvaluationRefusal:
    return EvaluationRefusal(code, detail, cause)


def evaluate(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    verification: Optional[VerificationConfig] = None,
) -> Union[EvaluationOutcome, EvaluationRefusal]:
    """Evaluate ``Req(component_not_present)`` for the finding ``profile`` selects.

    Nothing the caller passes in is mutated. See the module docstring for the stages, the
    refusals and the trust boundary.
    """
    if not isinstance(profile, ValidatedProfile):
        return _refuse(RefusalCode.PROFILE_INVALID, "the profile must be a ValidatedProfile")
    if verification is not None and not isinstance(verification, VerificationConfig):
        return _refuse(RefusalCode.VERIFICATION_INVALID, "verification must be a VerificationConfig")

    if not isinstance(index, Stage1Index):
        return _refuse(RefusalCode.ASSEMBLY_FAILED, "the index must be a Stage1Index", "EVAL_INDEX_INVALID")
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence) \
            or not all(isinstance(f, Finding) for f in findings):
        return _refuse(RefusalCode.ASSEMBLY_FAILED, "findings must be a sequence of Finding", "EVAL_FINDINGS_INVALID")

    try:
        assembly = assemble(profile, findings, index)
    except ProfileError as error:
        return _refuse(RefusalCode.PROFILE_INVALID, str(error), error.code.value)
    except AssemblyError as error:
        return _refuse(RefusalCode.ASSEMBLY_FAILED, str(error), error.code.value)

    finding, record, doc_id = assembly.finding, assembly.primary_record, assembly.primary_doc_id
    if finding.disposition is not Disposition.NOT_AFFECTED:
        return _refuse(RefusalCode.DISPOSITION_NOT_EVALUATED,
                       f"the predicates apply only to not_affected; got {finding.disposition.value!r} "
                       "(an input error, not a verdict)")
    if finding.justification.justification != JustificationType.COMPONENT_NOT_PRESENT.value:
        return _refuse(RefusalCode.JUSTIFICATION_NOT_SUPPORTED,
                       f"justification {finding.justification.justification!r} is not evaluated by this "
                       "milestone (only component_not_present)")
    if finding.scope.artifact_kind is ArtifactKind.UNKNOWN:
        return _refuse(RefusalCode.ARTIFACT_KIND_UNRESOLVED,
                       "the artifact kind is unknown: its effect on N14/N15 is undefined (register G10)")

    diagnostics: list[str] = [f"{d.code.value}: {d.detail}" for d in assembly.diagnostics]
    if verification is not None:
        unreferenced = sorted({r.doc_id for r in verification.results} - {doc_id})
        if unreferenced:
            diagnostics.append(f"VERIFICATION_RESULT_UNREFERENCED: {', '.join(unreferenced)}")

    observations = observe_inventory(record)
    members = inventory_members(record)
    bind = evaluate_bind_for_profile(profile, [record])
    document = finding.source_documents[doc_id]
    provenance = document_provenance(document, bind, verification)
    record_consumed_integrity(document, provenance)  # on the assembly's own copy only

    assessment, reference_check = build_assessment(record, bind, observations)
    inv = derive_inv(profile, bind, assessment)
    location = profile.target.would_be_location if profile.target is not None else None
    decl = derive_decl(record, location, bind, inv)
    match = derive_match(finding.component, members, bind, inv)
    gen = derive_gen(record)

    try:
        items = build_items(doc_id, members, inv, decl, match, gen)
        validate_items(finding, record, members, items)
    except ItemIntegrityError as error:
        return _refuse(RefusalCode.ITEM_INTEGRITY_FAILED, str(error), error.code)

    aggregates = aggregate_dimensions(items)
    for name, aggregated, derived in (("INV", aggregates.inv.state, inv.state), ("DECL", aggregates.decl.state, decl.state),
                                      ("MATCH", aggregates.match.state, match.state)):
        if aggregated is not derived:  # the items must carry exactly the state their derivation produced
            return _refuse(RefusalCode.ITEM_INTEGRITY_FAILED,
                           f"{name}: the items aggregate to {aggregated.value} but the derivation produced {derived.value}",
                           "ITEM_AGGREGATE_MISMATCH")
    levels = item_levels(items, {doc_id: provenance})
    prov_sbom = minimum_level(provenance, members.locator_prefixes())
    prov_decl = minimum_level(provenance, decl.record_locators) if aggregates.decl.state is EvidenceState.PRESENT else None
    cnp_inputs = build_cnp_inputs(finding.scope.artifact_kind, aggregates, bind, prov_sbom, prov_decl, gen.state)
    try:
        evaluation = evaluate_cnp(cnp_inputs)
    except UnresolvedArtifactKindError as error:  # defensive: the gate above already refuses
        return _refuse(RefusalCode.ARTIFACT_KIND_UNRESOLVED, str(error))

    limitations: list[str] = list(gen.limitations) + list(provenance.limitations) + list(evaluation.result.limitations)
    for check in assessment.checks:
        if check.outcome.value != "passed":
            limitations.append(f"STRUCTURAL_CHECK_{check.check_id}: {check.outcome.value}")
    limitations.extend(code.value for code in inv.reasons if code is not InvCode.PRESENT)
    diagnostics.extend(f"INVENTORY_NOTE: {note}" for note in assessment.notes)
    diagnostics.extend(
        f"INV_ASSERTION_RELIED_ON: {a.statement} for {a.document} entered_by={a.entered_by!r} "
        "(an unauthenticated evaluator statement; completeness is a self-assertion, A4)"
        for a in profile.usable_inv_assertions if a.document == doc_id and inv.state is EvidenceState.PRESENT
    )

    return EvaluationOutcome(
        profile_id=profile.profile_id,
        doc_id=doc_id,
        finding=finding,
        bind=bind,
        observations=observations,
        reference_check=reference_check,
        inv=inv,
        decl=decl,
        match=match,
        gen=gen,
        items=items,
        aggregates=aggregates,
        provenance=ProvenanceSummary(
            provenance, prov_sbom, prov_decl,
            {item.item_id: result.level for item, result in zip(items, levels) if item.item_id is not None},
        ),
        cnp_inputs=cnp_inputs,
        evaluation=evaluation,
        diagnostics=tuple(diagnostics),
        limitations=tuple(dict.fromkeys(limitations)),
    )
