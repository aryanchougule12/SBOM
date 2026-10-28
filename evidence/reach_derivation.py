"""Derivations for ``Req(vulnerable_code_not_in_execute_path)`` (specification §5.1, §5.2, §1.2).

Pure functions from validated inputs to the dimension values that ``evidence.reach_rules``
consumes. Nothing here evaluates a rule or produces a verdict, and nothing invents evidence: a
derivation that cannot establish its dimension returns ``Unknown`` with a stated reason.

REACH (§5.1), evaluated in order over the REACH evidence items:

1. *Positive observation.* Any item of any kind at any EP that observes or asserts a path or
   execution of the locus is positive. Positive plus a K1 ``Absent`` gives ``Contradictory``;
   positive otherwise gives ``Present`` (a positive observation survives an ``Incomplete`` or
   ``Ambiguous`` item, §2 step 3 / AG1).
2. *K1 basis.* Otherwise, if any K1 document exists, its items are aggregated under §2
   (``evidence.aggregation``). ``Absent`` needs a declared full-coverage claim; that is applied when
   the item is built (``observation_state``).
3. *Non-exhaustive basis.* Otherwise a K3 no-hit, or a K2 negative assertion with EP >= P1, gives
   ``Incomplete`` with basis ``non_exhaustive``.
4. *Otherwise* ``Unknown``: K2 at P0, K4 only, no evidence.

A dependency graph (K4) never reaches steps 1-3: it is read from the SBOM as an ``Unknown`` item
(A5, §5.1 "dependency edge vs. call edge"). Its only effect is the code of R2.

The evidence the conclusion depends on (``PROV_REACH``, §5.1) is the set of items that produced
the final state: the positive items (and the K1 absences they conflict with) for ``Present`` and
``Contradictory``; the informative K1 items for the K1 basis; the non-exhaustive items for step 3.
``PROV_REACH`` is the minimum EP over them, undefined for ``Unknown``. (Which documents "jointly
support" a conclusion is only settled by this explicit rule, register G7.)

BIND for reachability (§5.1: "binding of the analysis to the artifact and component version") is a
project convention, unconfirmed: a document is bound when the artifact it declares it analysed
matches S under the existing B2-B5 policy (``evidence.bind.evaluate_subject_bind``) **and** the
component it declares it concerns matches C (purl equality, else name and version equality). A
difference of component only gives ``Unknown``, never ``Mismatched`` (the B5 principle: only a
digest disagreement is a demonstrated mismatch). An unresolved C (register G1r) makes BIND
``Unknown``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from evidence.aggregation import AggregationResult, aggregate
from evidence.bind import BindCode, BindEvaluation, evaluate_subject_bind
from evidence.cnp_rules import BindState
from evidence.document_provenance import DocumentProvenance, document_provenance
from evidence.profile import ScopeIdentity
from evidence.reach_inputs import (
    HazardClaim,
    LocusApproximation,
    LocusInput,
    ReachDocument,
    ReachFinding,
    ReachKind,
    ReachabilityEvidence,
    TargetRef,
)
from evidence.reach_rules import CfgState, HazardClass, HazardDisposition, HazardInput, ReachBasis
from evidence.stage1_records import FORMAT_CYCLONEDX, FORMAT_SPDX, SbomRecord
from evidence.verification import VerificationConfig
from model import Component, DocumentSubject, EvidenceItem, EvidenceState, ProvenanceLevel, SourceDocument
from sbom_parser.identifiers import normalize_name, normalize_purl

DIM_REACH = "REACH"
DIM_LOCUS = "LOCUS"
DIM_ENTRY = "ENTRY"
K4 = "K4"

REPORT_FINDING_LOCATOR = "#/finding"
REPORT_ENTRY_LOCATOR = "#/entry_points"
REPORT_CONFIG_LOCATOR = "#/analyzed_configurations"
REPORT_ROOT_LOCATOR = "#"
SBOM_GRAPH_LOCATOR = "#"

# SPDX 2.3 relationship types of the dependency family (names verified against the official
# spdx-schema.json of the 2.3 release; direction is not interpreted anywhere in this module).
SPDX_DEPENDENCY_RELATIONSHIPS = frozenset({
    "DEPENDS_ON", "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
})
CYCLONEDX_DEPENDENCY_RELATIONSHIP = "dependsOn"


# ---- K4: the declared dependency graph of the SBOM -----------------------------------------------------

@dataclass(frozen=True)
class DependencyGraphFacts:
    """Whether the primary SBOM declares dependency edges, and how many. This is the whole of what
    K4 contributes: the graph's topology (direction, cycles, paths, reachability from the subject)
    cannot change any REACH state (A5), so it is deliberately not computed."""

    present: bool
    edge_count: int
    edge_locators: tuple[str, ...]  # at most the first 5, in document order, for audit


def dependency_graph_facts(record: SbomRecord) -> DependencyGraphFacts:
    if record.format == FORMAT_CYCLONEDX:
        wanted = lambda raw: raw == CYCLONEDX_DEPENDENCY_RELATIONSHIP  # noqa: E731  ("provides" is not a dependency)
    elif record.format == FORMAT_SPDX:
        wanted = lambda raw: raw in SPDX_DEPENDENCY_RELATIONSHIPS  # noqa: E731
    else:
        return DependencyGraphFacts(False, 0, ())
    edges = [e for e in record.edges if wanted(e.raw_relationship)]
    return DependencyGraphFacts(bool(edges), len(edges), tuple(e.locator for e in edges[:5]))


# ---- binding and provenance of an evidence document ----------------------------------------------------------

@dataclass(frozen=True)
class ComponentBind:
    state: BindState  # MATCHED or UNKNOWN; never MISMATCHED (B5 principle)
    reason: str


@dataclass(frozen=True)
class DocumentAssessment:
    """Source document, BIND and provenance of one reachability document."""

    document: ReachDocument
    source: SourceDocument
    artifact_bind: BindEvaluation
    component_bind: ComponentBind
    provenance: DocumentProvenance

    @property
    def source_blockers(self) -> tuple[str, ...]:
        """Binding failures recorded when the document was derived from an analyzer artifact
        (``evidence.analysis_binding``); empty for a directly supplied document."""
        return self.document.source.bind_blockers if self.document.source is not None else ()

    @property
    def bind_state(self) -> BindState:
        if self.artifact_bind.state is BindState.MISMATCHED:
            return BindState.MISMATCHED
        if self.source_blockers:
            return BindState.UNKNOWN
        if self.artifact_bind.state is BindState.MATCHED and self.component_bind.state is BindState.MATCHED:
            return BindState.MATCHED
        return BindState.UNKNOWN

    @property
    def bind_reasons(self) -> tuple[str, ...]:
        reasons = list(self.source_blockers)
        if self.artifact_bind.state is not BindState.MATCHED and not self.source_blockers:
            reasons.append(self.artifact_bind.reason.value)
        if self.component_bind.state is not BindState.MATCHED:
            reasons.append(self.component_bind.reason)
        return tuple(reasons)

    def level_at(self, locator: Optional[str]) -> ProvenanceLevel:
        return self.provenance.level_at(locator)


def _component_bind(component: Optional[Component], target: Optional[TargetRef]) -> ComponentBind:
    if component is None:
        return ComponentBind(BindState.UNKNOWN, "REACH_BIND_NO_TARGET_COMPONENT")  # register G1r
    if target is None:
        return ComponentBind(BindState.UNKNOWN, "REACH_BIND_TARGET_NOT_DECLARED")
    if target.purl and component.purl:
        same = normalize_purl(target.purl) == normalize_purl(component.purl)
        return ComponentBind(BindState.MATCHED if same else BindState.UNKNOWN,
                             "REACH_BIND_TARGET_PURL_MATCH" if same else "REACH_BIND_TARGET_NOT_MATCHED")
    if target.name and target.version and component.version and component.name:
        same = (normalize_name(target.name) == normalize_name(component.name)
                and target.version.strip() == component.version.strip())
        return ComponentBind(BindState.MATCHED if same else BindState.UNKNOWN,
                             "REACH_BIND_TARGET_NAME_VERSION_MATCH" if same else "REACH_BIND_TARGET_NOT_MATCHED")
    return ComponentBind(BindState.UNKNOWN, "REACH_BIND_TARGET_NOT_COMPARABLE")


def assess_document(
    document: ReachDocument,
    scope: ScopeIdentity,
    component: Optional[Component],
    verification: Optional[VerificationConfig],
) -> DocumentAssessment:
    """Build the evaluation's own ``SourceDocument`` for ``document`` and compute its BIND and
    provenance. Pure; the input is not mutated."""
    source = SourceDocument(
        doc_id=document.doc_id, producer=document.producer, producer_class=document.producer_class,
        tool_name=document.tool_name, tool_version=document.tool_version, created=document.created,
        declared_metadata={"format": "reachability-evidence", "kind": document.kind.value},
    )
    if document.source is not None:  # a derived document: keep what the raw artifact is
        source.declared_metadata.update({"format": document.source.artifact.format.value,
                                         "format_version": document.source.artifact.format_version or "unknown",
                                         "derived_by": "evidence.analysis_binding"})
    if document.artifact is None:
        artifact_bind = BindEvaluation(state=BindState.UNKNOWN, basis=None, reason=BindCode.NO_SUBJECT,
                                       document_id=document.doc_id)
    else:
        subject = DocumentSubject(ref=None, component=document.artifact, locator="#/artifact",
                                  declared_via="reachability_document", listed_as_component=False)
        artifact_bind = evaluate_subject_bind(scope, subject, document.doc_id)
    provenance = document_provenance(source, artifact_bind, verification)
    return DocumentAssessment(document, source, artifact_bind, _component_bind(component, document.target), provenance)


# ---- item states ---------------------------------------------------------------------------------------------------

def observation_state(document: ReachDocument, ep: ProvenanceLevel) -> tuple[EvidenceState, Optional[ReachBasis], str]:
    """The REACH state a single K1/K2/K3 document contributes, its basis and a reason (§5.1).

    ``ep`` is the document's EP at the finding locator. K1 ``Absent`` requires the declared
    full-coverage claim; K2 and K3 evidence is never ``Absent`` (it declares no sufficient
    coverage) and a K2 negative below P1 is ``Unknown``.
    """
    finding, kind = document.finding, document.kind
    if finding is ReachFinding.POSITIVE:
        return EvidenceState.PRESENT, None, "a path or execution of the locus is observed or asserted"
    if finding is ReachFinding.UNKNOWN or finding is None:
        return EvidenceState.UNKNOWN, None, "the document reports no usable finding"
    if kind is ReachKind.K1:
        if finding is ReachFinding.INCOMPLETE:
            return EvidenceState.INCOMPLETE, ReachBasis.K1, "the K1 analysis is partial (modules unanalysed or timeout)"
        if finding is ReachFinding.AMBIGUOUS:
            return EvidenceState.AMBIGUOUS, ReachBasis.K1, "the K1 analysis has unresolved may-reach edges"
        if document.full_coverage_claim:
            return EvidenceState.ABSENT, ReachBasis.K1, "K1 reports no path under a declared full-coverage claim"
        return EvidenceState.INCOMPLETE, ReachBasis.K1, "K1 reports no path but declares no full-coverage claim over LOCUS and ENTRY"
    if kind is ReachKind.K3:
        return EvidenceState.INCOMPLETE, ReachBasis.NON_EXHAUSTIVE, "K3 no-hit observation (non-exhaustive)"
    # K2 negative assertion
    if ep >= ProvenanceLevel.P1:
        return EvidenceState.INCOMPLETE, ReachBasis.NON_EXHAUSTIVE, "K2 negative assertion with EP >= P1 (non-exhaustive)"
    return EvidenceState.UNKNOWN, None, "K2 negative assertion with EP = P0 carries no evidential value"


# ---- REACH derivation (§5.1) -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class ReachDerivation:
    state: EvidenceState
    basis: Optional[ReachBasis]
    only_k4: bool
    step: int  # the §5.1 derivation step that decided the state (4 for Unknown)
    reason: str
    depends_on: tuple[str, ...]  # item ids the conclusion depends on (empty for Unknown)
    aggregation: Optional[AggregationResult] = None


def _kind(item: EvidenceItem) -> str:
    return getattr(item.value_or_ref, "kind", "")


def derive_reach(items: Sequence[EvidenceItem]) -> ReachDerivation:
    """§5.1 over REACH items (each carries a payload with ``kind`` K1/K2/K3/K4)."""
    reach = [i for i in items if i.dimension == DIM_REACH]
    documents = [i for i in reach if _kind(i) in ("K1", "K2", "K3")]
    only_k4 = not documents and any(_kind(i) == K4 for i in reach)

    positives = [i for i in documents if i.state is EvidenceState.PRESENT]
    k1_absent = [i for i in documents if _kind(i) == "K1" and i.state is EvidenceState.ABSENT]
    if positives:  # step 1
        if k1_absent:
            return ReachDerivation(EvidenceState.CONTRADICTORY, None, False, 1,
                                   "positive evidence conflicts with a K1 absence", _ids(positives + k1_absent))
        return ReachDerivation(EvidenceState.PRESENT, None, False, 1, "a path or execution of the locus is observed or asserted",
                               _ids(positives))

    k1 = [i for i in documents if _kind(i) == "K1"]
    if k1:  # step 2
        result = aggregate(k1)
        informative = [i for i in k1 if i.state is not EvidenceState.UNKNOWN]
        return ReachDerivation(result.state, ReachBasis.K1 if result.state is not EvidenceState.UNKNOWN else None, False, 2,
                               f"K1 aggregate ({result.reason.value})", _ids(informative), result)

    non_exhaustive = [i for i in documents if i.state is EvidenceState.INCOMPLETE]
    if non_exhaustive:  # step 3
        return ReachDerivation(EvidenceState.INCOMPLETE, ReachBasis.NON_EXHAUSTIVE, False, 3,
                               "K3 no-hit or K2 negative assertion (non-exhaustive basis)", _ids(non_exhaustive))

    reason = "only a K4 dependency graph exists" if only_k4 else ("no reachability evidence" if not documents else
                                                                  "the reachability evidence carries no evidential value")
    return ReachDerivation(EvidenceState.UNKNOWN, None, only_k4, 4, reason, ())  # step 4


def _ids(items: Sequence[EvidenceItem]) -> tuple[str, ...]:
    return tuple(i.item_id for i in items if i.item_id is not None)


def prov_reach(derivation: ReachDerivation, items: Sequence[EvidenceItem],
               assessments: Mapping[str, DocumentAssessment]) -> Optional[ProvenanceLevel]:
    """``PROV_REACH``: the minimum EP over the documents the conclusion depends on; ``None`` when
    REACH is Unknown (undefined)."""
    if derivation.state is EvidenceState.UNKNOWN:
        return None
    by_id = {i.item_id: i for i in items}
    levels = []
    for item_id in derivation.depends_on:
        item = by_id[item_id]
        assessment = assessments.get(item.source_doc or "")
        levels.append(assessment.level_at(item.locator) if assessment is not None else ProvenanceLevel.P0)
    return min(levels) if levels else ProvenanceLevel.P0


# ---- LOCUS and ENTRY -------------------------------------------------------------------------------------------------

def locus_item_state(locus: LocusInput) -> tuple[EvidenceState, str]:
    """§5.1 LOCUS: it must be an over-approximation (a coarser locus is acceptable); a possibly
    under-approximate subset is Incomplete; an approximation that is not declared cannot be
    assumed, so it is Unknown."""
    if locus.approximation is LocusApproximation.OVER_APPROXIMATION:
        return EvidenceState.PRESENT, "the locus is declared an over-approximation"
    if locus.approximation is LocusApproximation.POSSIBLY_UNDER_APPROXIMATE:
        return EvidenceState.INCOMPLETE, "the locus is declared possibly under-approximate"
    return EvidenceState.UNKNOWN, "the locus does not declare whether it over-approximates the vulnerable code"


def entry_item_state(complete: bool) -> tuple[EvidenceState, str]:
    if complete:
        return EvidenceState.PRESENT, "the entry-point set is declared complete"
    return EvidenceState.INCOMPLETE, "the entry-point set is declared incomplete"


# ---- hazards (§5.2) -------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class HazardAssessment:
    """Traceability of one hazard class before the rule engine's Step 1."""

    hazard_class: HazardClass
    origin: str  # evaluator_claim | k1_report | default
    claimed: HazardDisposition
    basis_ref: Optional[str]
    basis_locator: Optional[str]
    basis_known: bool
    basis_bound: bool
    basis_ep: Optional[ProvenanceLevel]
    declared_in_k1: tuple[str, ...]

    def to_input(self) -> HazardInput:
        return HazardInput(self.claimed, self.basis_bound, self.basis_ep, bool(self.declared_in_k1))


def assess_hazards(evidence: ReachabilityEvidence, assessments: Mapping[str, DocumentAssessment]) -> tuple[HazardAssessment, ...]:
    """One assessment per class of the closed enumeration, in alphabetical order.

    An explicit evaluator claim governs its class (even when unfavourable). A class without a
    claim that a K1 document lists in ``modeled_hazards`` is modeled conservatively (declared
    inside the report, §5.2). Every other class is ``Unknown`` (the default).
    """
    claims: dict[HazardClass, HazardClaim] = {c.hazard_class: c for c in evidence.hazards}
    declared = {hc: tuple(sorted(d.doc_id for d in evidence.documents if d.kind is ReachKind.K1 and hc in d.modeled_hazards))
                for hc in HazardClass}
    result: list[HazardAssessment] = []
    for hazard_class in sorted(HazardClass, key=lambda c: c.value):
        claim = claims.get(hazard_class)
        if claim is None:
            if declared[hazard_class]:
                result.append(HazardAssessment(hazard_class, "k1_report", HazardDisposition.MODELED_CONSERVATIVELY,
                                               None, None, False, False, None, declared[hazard_class]))
            else:
                result.append(HazardAssessment(hazard_class, "default", HazardDisposition.UNKNOWN,
                                               None, None, False, False, None, ()))
            continue
        basis_known = bound = False
        ep: Optional[ProvenanceLevel] = None
        locator = claim.basis_locator or REPORT_ROOT_LOCATOR if claim.basis_ref else None
        if claim.disposition is HazardDisposition.EXCLUDED_BY_EVIDENCE and claim.basis_ref is not None:
            basis = assessments.get(claim.basis_ref)
            if basis is not None:
                basis_known = True
                bound = basis.bind_state is BindState.MATCHED
                ep = basis.level_at(locator)
        result.append(HazardAssessment(hazard_class, "evaluator_claim", claim.disposition, claim.basis_ref, locator,
                                       basis_known, bound, ep, declared[hazard_class]))
    return tuple(result)


# ---- CFG (§5.1, R12) -----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class CfgDerivation:
    state: CfgState
    reason: str


def derive_cfg(
    deployment_config_id: Optional[str],
    reach: ReachDerivation,
    items: Sequence[EvidenceItem],
    assessments: Mapping[str, DocumentAssessment],
) -> CfgDerivation:
    """CFG: S must record the deployment configuration (A7), and the analysis the REACH conclusion
    depends on must declare the configurations it holds under, including S's. With no REACH
    conclusion there is no analysed configuration to compare (``NOT_COMPARED``)."""
    if not deployment_config_id:
        return CfgDerivation(CfgState.UNDECLARED, "S records no deployment configuration (A7)")
    if reach.state is EvidenceState.UNKNOWN:
        return CfgDerivation(CfgState.NOT_COMPARED, "S records a configuration but no analysis exists to compare it with")
    by_id = {i.item_id: i for i in items}
    for item_id in reach.depends_on:
        assessment = assessments.get(by_id[item_id].source_doc or "")
        configurations = assessment.document.analyzed_configurations if assessment is not None else ()
        if not configurations:
            return CfgDerivation(CfgState.UNDECLARED, f"{item_id} declares no analysed configuration")
        if deployment_config_id not in configurations:
            return CfgDerivation(CfgState.EXTENDS_BEYOND,
                                 f"{item_id} analysed {', '.join(configurations)}; S records {deployment_config_id}")
    return CfgDerivation(CfgState.DECLARED, "every analysis the conclusion depends on covers S's configuration")


# ---- BIND (§5.1) -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ReachBind:
    state: BindState
    reasons: tuple[str, ...]
    relied_on: tuple[str, ...]  # document ids whose binding decided the state


def derive_bind(
    component: Optional[Component],
    reach: ReachDerivation,
    items: Sequence[EvidenceItem],
    assessments: Mapping[str, DocumentAssessment],
    sbom_bind: Optional[BindEvaluation],
    sbom_doc_id: str,
) -> ReachBind:
    """The BIND dimension: the combined binding of the evidence the REACH conclusion depends on
    (when REACH is Unknown, of every supplied analysis document and, if K4 evidence exists, of the
    primary SBOM). A mismatch of any relied-on document gives Mismatched, all relied-on documents
    Matched gives Matched, anything else Unknown; no relied-on document gives Unknown."""
    if component is None:
        return ReachBind(BindState.UNKNOWN, ("REACH_BIND_NO_TARGET_COMPONENT",), ())
    by_id = {i.item_id: i for i in items}
    if reach.state is not EvidenceState.UNKNOWN:
        relied = sorted({by_id[i].source_doc for i in reach.depends_on if by_id[i].source_doc})
    else:
        relied = sorted(d for d in assessments if assessments[d].document.kind is not ReachKind.HAZARD_BASIS)
        if reach.only_k4:
            relied = [sbom_doc_id]
    if not relied:
        return ReachBind(BindState.UNKNOWN, ("REACH_BIND_NO_ANALYSIS",), ())
    states: list[BindState] = []
    reasons: list[str] = []
    for doc_id in relied:
        if doc_id == sbom_doc_id:
            state = sbom_bind.state if sbom_bind is not None else BindState.UNKNOWN
            if state is not BindState.MATCHED:
                reasons.append(f"{doc_id}: {sbom_bind.reason.value if sbom_bind is not None else 'BIND_NO_PRIMARY_SBOM'}")
        else:
            state = assessments[doc_id].bind_state
            reasons.extend(f"{doc_id}: {r}" for r in assessments[doc_id].bind_reasons)
        states.append(state)
    if BindState.MISMATCHED in states:
        return ReachBind(BindState.MISMATCHED, tuple(reasons), tuple(relied))
    if all(s is BindState.MATCHED for s in states):
        return ReachBind(BindState.MATCHED, (), tuple(relied))
    return ReachBind(BindState.UNKNOWN, tuple(reasons), tuple(relied))
