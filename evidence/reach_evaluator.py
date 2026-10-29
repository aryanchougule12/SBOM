"""The integrated ``Req(vulnerable_code_not_in_execute_path)`` evaluator (specification section 5).

``evaluate_reachability(profile, findings, index, reachability=None, verification=None)`` runs the
reachability pipeline for one finding and one primary SBOM and returns a ``ReachOutcome`` (one
final verdict with all of its evidence) or an ``EvaluationRefusal`` (no verdict, a stable code),
using the same refusal model, evidence-item model and provenance model as the CNP evaluator
(``evidence.evaluator``).

Flow, each stage consuming only what the previous stages actually established:

1. ``pipeline_inputs.assemble``: select the one finding, apply the profile, resolve the primary
   SBOM exactly against the Stage 1 index.
2. The reachability evidence documents are registered on the evaluation's own copy of the
   finding (role ``reachability_report``); the evaluator's deployment configuration is applied to
   S (A7) unless S already states a different one (a refusal).
3. BIND of the primary SBOM (existing B1-B5) and K4: the SBOM's declared dependency edges.
4. ``reach_derivation.assess_document``: BIND (artifact + component, G1r) and document provenance
   for every evidence document with the existing P0-P3 machinery, P3 only from a trusted external
   ``VerificationResult`` and only inside its verified coverage.
5. ``reach_items``: typed REACH / LOCUS / ENTRY items, validated for source, role, locator and the
   state their facts support; per-dimension §2 aggregation; ``derive_reach`` (§5.1).
6. HAZ (§5.2), CFG, BIND and ``PROV_REACH`` are derived, ``ReachInputs`` is assembled and
   ``reach_rules.evaluate_reach`` applies Steps 1, 3, 4 and 5.

The result is **one predicate per finding**: a finding carries one justification, so a run is
either ``component_not_present`` (``evidence.evaluator``) or this one. No combined-predicate
verdict policy is defined by the specification and none is invented here; the two evaluators share
modules, never state.

Refusals (no verdict): invalid profile, verification, index, findings or reachability input; a
disposition other than ``not_affected`` (an input error, §1); a justification other than
``vulnerable_code_not_in_execute_path``; an evidence document id that collides with a profile
document; a deployment configuration that conflicts with S; an item that fails its integrity check.
Missing evidence is not a refusal: it is ``Unknown`` and yields an Insufficient verdict.

Trust boundary: ``verification`` is a trusted, out-of-band input. The reachability input can never
supply a state, a provenance level or a verification result.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Union

from evidence.aggregation import AggregationResult, aggregate
from evidence.analysis_model import SourceRef
from evidence.bind import BindEvaluation, evaluate_bind_for_profile
from evidence.cnp_rules import BindState
from evidence.document_provenance import record_consumed_integrity
from evidence.evaluator import EvaluationRefusal, RefusalCode
from evidence.items import ItemIntegrityError
from evidence.pipeline_inputs import AssemblyError, assemble
from evidence.profile import ProfileError, ValidatedProfile
from evidence.reach_derivation import (
    DIM_ENTRY,
    DIM_LOCUS,
    CfgDerivation,
    DependencyGraphFacts,
    DocumentAssessment,
    HazardAssessment,
    ReachBind,
    ReachDerivation,
    assess_document,
    assess_hazards,
    dependency_graph_facts,
    derive_bind,
    derive_cfg,
    derive_reach,
    prov_reach,
)
from evidence.reach_inputs import ReachFinding, ReachabilityEvidence, ReachKind
from evidence.reach_items import build_reach_items, validate_reach_items
from evidence.reach_rules import ReachEvaluation, ReachInputs, evaluate_reach
from evidence.rule_core import jsonable
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig
from model import Disposition, DocumentRole, EvidenceItem, EvidenceState, Finding, JustificationType, ProvenanceLevel
from reports.verdict import VerdictResult

EMPTY_EVIDENCE = ReachabilityEvidence(schema_version="1")


@dataclass(frozen=True)
class ReachOutcome:
    """The complete, reproducible result of one reachability evaluation."""

    profile_id: str
    doc_id: str
    finding: Finding
    sbom_bind: BindEvaluation
    graph: DependencyGraphFacts
    documents: tuple[DocumentAssessment, ...]
    items: tuple[EvidenceItem, ...]
    reach: ReachDerivation
    locus: AggregationResult
    entry: AggregationResult
    hazards: tuple[HazardAssessment, ...]
    cfg: CfgDerivation
    bind: ReachBind
    prov_reach: Optional[ProvenanceLevel]
    reach_inputs: ReachInputs
    evaluation: ReachEvaluation
    diagnostics: tuple[str, ...]
    limitations: tuple[str, ...]
    analysis: tuple[SourceRef, ...] = ()   # every ingested analyzer artifact and what was derived from it

    @property
    def result(self) -> VerdictResult:
        """The single final verdict, codes and rationale (section 3, §5.4)."""
        return self.evaluation.result

    @property
    def dimension_states(self) -> Mapping[str, str]:
        inputs = self.reach_inputs
        return {
            "BIND": inputs.bind.value,
            "CFG": inputs.cfg.value,
            "ENTRY": inputs.entry.value,
            "LOCUS": inputs.locus.value,
            "REACH": inputs.reach.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


def _refuse(code: RefusalCode, detail: str, cause: Optional[str] = None) -> EvaluationRefusal:
    return EvaluationRefusal(code, detail, cause)


def evaluate_reachability(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    reachability: Optional[ReachabilityEvidence] = None,
    verification: Optional[VerificationConfig] = None,
) -> Union[ReachOutcome, EvaluationRefusal]:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)`` for the finding ``profile`` selects.

    ``reachability`` ``None`` means no reachability evidence was supplied: every evidence-dependent
    dimension is then ``Unknown``. Nothing the caller passes in is mutated.

    **Undecidable analyzer evidence.** If an ingested analyzer artifact records flows or call edges that
    might touch the locus but cannot be resolved (``evidence.worst_case_documents``), the evaluation is
    run twice: as given, and in the worst case in which each of them is a path. If the two verdicts
    are the same, the first outcome is returned with the situation stated in its limitations and
    diagnostics. If they differ, the unresolved records could change the verdict, no verdict is
    justified, and an ``EVAL_ANALYSIS_EVIDENCE_UNDECIDABLE`` refusal is returned: an unresolved record is
    never allowed to be overridden by a supplied absence. No new state or verdict is involved.
    """
    outcome = _evaluate_once(profile, findings, index, reachability, verification)
    if not isinstance(reachability, ReachabilityEvidence) or not reachability.worst_case_documents \
            or isinstance(outcome, EvaluationRefusal):
        return outcome
    replaced = {d.doc_id for d in reachability.worst_case_documents}
    worst_evidence = dataclasses.replace(
        reachability,
        documents=tuple(d for d in reachability.documents if d.doc_id not in replaced) + reachability.worst_case_documents,
        worst_case_documents=())
    worst = _evaluate_once(profile, findings, index, worst_evidence, verification)
    if isinstance(worst, EvaluationRefusal):
        return worst
    undecidable = [(s.artifact.doc_id, u) for s in reachability.analysis_sources for u in s.undecidable]
    names = "; ".join(f"{doc} {u.locator} ({u.reason})" for doc, u in undecidable)
    if outcome.result.verdict is not worst.result.verdict:
        return _refuse(RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE,
                       f"{len(undecidable)} recorded flow(s)/call edge(s) may touch the locus but cannot be resolved, and counting them as "
                       f"paths would change the verdict from {outcome.result.verdict.value} to {worst.result.verdict.value}: {names}",
                       "UNRESOLVED_RELEVANT_EVIDENCE")
    note = (f"UNDECIDABLE_EVIDENCE_DID_NOT_CHANGE_THE_VERDICT: counting the {len(undecidable)} undecidable observation(s) as paths "
            f"gives the same verdict ({outcome.result.verdict.value})")
    return dataclasses.replace(outcome, limitations=tuple(dict.fromkeys(outcome.limitations + (note,))),
                               diagnostics=outcome.diagnostics + (f"{note}: {names}",))


def _evaluate_once(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    reachability: Optional[ReachabilityEvidence] = None,
    verification: Optional[VerificationConfig] = None,
) -> Union[ReachOutcome, EvaluationRefusal]:
    if not isinstance(profile, ValidatedProfile):
        return _refuse(RefusalCode.PROFILE_INVALID, "the profile must be a ValidatedProfile")
    if verification is not None and not isinstance(verification, VerificationConfig):
        return _refuse(RefusalCode.VERIFICATION_INVALID, "verification must be a VerificationConfig")
    if reachability is not None and not isinstance(reachability, ReachabilityEvidence):
        return _refuse(RefusalCode.REACH_INPUT_INVALID, "reachability must be a ReachabilityEvidence")
    if not isinstance(index, Stage1Index):
        return _refuse(RefusalCode.ASSEMBLY_FAILED, "the index must be a Stage1Index", "EVAL_INDEX_INVALID")
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence) \
            or not all(isinstance(f, Finding) for f in findings):
        return _refuse(RefusalCode.ASSEMBLY_FAILED, "findings must be a sequence of Finding", "EVAL_FINDINGS_INVALID")
    evidence = reachability if reachability is not None else EMPTY_EVIDENCE

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
    if finding.justification.justification != JustificationType.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value:
        return _refuse(RefusalCode.JUSTIFICATION_NOT_SUPPORTED,
                       f"justification {finding.justification.justification!r} is not evaluated by the reachability "
                       "evaluator (only vulnerable_code_not_in_execute_path)")
    collisions = sorted({d.doc_id for d in evidence.documents} & {d.doc_id for d in profile.documents})
    if collisions:
        return _refuse(RefusalCode.REACH_INPUT_INVALID,
                       f"reachability document id(s) collide with profile document id(s): {', '.join(collisions)}",
                       "REACH_DOCUMENT_ID_COLLISION")
    existing_config = finding.scope.deployment_config_id
    if evidence.deployment_config_id is not None and existing_config not in (None, evidence.deployment_config_id):
        return _refuse(RefusalCode.REACH_INPUT_INVALID,
                       f"configuration {evidence.deployment_config_id!r} conflicts with the scope's {existing_config!r}",
                       "REACH_CONFIGURATION_CONFLICT")

    diagnostics: list[str] = [f"{d.code.value}: {d.detail}" for d in assembly.diagnostics]
    known_ids = {doc_id} | {d.doc_id for d in evidence.documents} | {a.artifact.doc_id for a in evidence.analysis_sources}
    if verification is not None:
        unreferenced = sorted({r.doc_id for r in verification.results} - known_ids)
        if unreferenced:
            diagnostics.append(f"VERIFICATION_RESULT_UNREFERENCED: {', '.join(unreferenced)}")

    # S and the finding's own registry: only the evaluation's own copy is touched.
    if evidence.deployment_config_id is not None:
        finding.scope.deployment_config_id = evidence.deployment_config_id
    component = finding.component
    if component is None:
        diagnostics.append("TARGET_COMPONENT_UNRESOLVED: no component-level target was identified (register G1r); "
                           "BIND cannot establish the component version")
    sbom_bind = evaluate_bind_for_profile(profile, [record])
    if sbom_bind.state is not BindState.MATCHED:
        diagnostics.append(f"SBOM_BIND_{sbom_bind.state.value.upper()}: the primary SBOM is not shown to be bound to S "
                           "(it supplies only K4; it is never reachability evidence)")
    graph = dependency_graph_facts(record)

    assessments: dict[str, DocumentAssessment] = {}
    for document in evidence.documents:
        assessment = assess_document(copy.deepcopy(document), profile.scope, component, verification)
        record_consumed_integrity(assessment.source, assessment.provenance)  # on the evaluation's own copy only
        assessments[document.doc_id] = assessment
        finding.source_documents[document.doc_id] = assessment.source
        finding.document_roles[document.doc_id] = (DocumentRole.OTHER if document.kind is ReachKind.HAZARD_BASIS
                                                   else DocumentRole.REACHABILITY_REPORT)

    items = build_reach_items(evidence, assessments, doc_id, graph)
    try:
        validate_reach_items(finding, doc_id, items, {d.doc_id: frozenset(d.source.observation_locators)
                                                      for d in evidence.documents
                                                      if d.source is not None and d.finding is ReachFinding.POSITIVE})
    except ItemIntegrityError as error:
        return _refuse(RefusalCode.ITEM_INTEGRITY_FAILED, str(error), error.code)

    reach = derive_reach(items)
    locus = aggregate(i for i in items if i.dimension == DIM_LOCUS)
    entry = aggregate(i for i in items if i.dimension == DIM_ENTRY)
    hazards = assess_hazards(evidence, assessments)
    cfg = derive_cfg(finding.scope.deployment_config_id, reach, items, assessments)
    bind = derive_bind(component, reach, items, assessments, sbom_bind, doc_id)
    level = prov_reach(reach, items, assessments)

    inputs = ReachInputs(
        reach=reach.state, locus=locus.state, entry=entry.state, bind=bind.state, cfg=cfg.state,
        prov_reach=level, reach_basis=reach.basis,
        # an ingested analyzer artifact is reachability-related evidence even when nothing could be derived from it (R2 text)
        only_k4_evidence=reach.only_k4 and not evidence.analysis_sources,
        hazards={h.hazard_class: h.to_input() for h in hazards},
    )
    evaluation = evaluate_reach(inputs)

    limitations: list[str] = list(evaluation.result.limitations)
    for assessment in assessments.values():
        limitations.extend(f"{assessment.document.doc_id}: {lim}" for lim in assessment.provenance.limitations)
    if reach.state is EvidenceState.UNKNOWN:
        limitations.append(f"REACH=Unknown: {reach.reason}")
    if locus.state is EvidenceState.UNKNOWN:
        limitations.append("LOCUS=Unknown: no locus was supplied or it declares no approximation")
    if bind.reasons:
        limitations.extend(f"BIND: {r}" for r in bind.reasons)
    limitations.append("EVIDENCE_NOT_VERIFIED: analyser soundness claims are recorded as claimed (A6); "
                       "a signature authenticates origin, not soundness (CE-R6)")
    for hazard in hazards:
        if hazard.origin == "evaluator_claim" and hazard.claimed.value == "excluded_by_evidence":
            diagnostics.append(f"HAZARD_CLAIM_EVALUATOR_ENTERED: {hazard.hazard_class.value} exclusion is an unauthenticated "
                               "evaluator statement resting on its basis_ref")
    for effective in evaluation.hazards:
        if effective.note:
            diagnostics.append(f"HAZARD_STEP1: {effective.hazard_class.value}: {effective.note}")

    for source in evidence.analysis_sources:
        limitations.extend(f"{source.artifact.doc_id}: {lim}" for lim in source.limitations)
        diagnostics.extend(f"ANALYSIS_DIAGNOSTIC {source.artifact.doc_id}: {d.code}: {d.detail}"
                           + (f" [{d.locator}]" if d.locator else "") for d in source.diagnostics)

    return ReachOutcome(
        profile_id=profile.profile_id,
        doc_id=doc_id,
        finding=finding,
        sbom_bind=sbom_bind,
        graph=graph,
        documents=tuple(assessments[d.doc_id] for d in evidence.documents),
        items=items,
        reach=reach,
        locus=locus,
        entry=entry,
        hazards=hazards,
        cfg=cfg,
        bind=bind,
        prov_reach=level,
        reach_inputs=inputs,
        evaluation=evaluation,
        diagnostics=tuple(diagnostics),
        limitations=tuple(dict.fromkeys(limitations)),
        analysis=evidence.analysis_sources,
    )
