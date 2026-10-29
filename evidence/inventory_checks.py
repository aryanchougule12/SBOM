"""The required structural check R1 and the inventory assessment for INV derivation.

R1 is the only required structural check of this milestone (register D2): **dependency and
relationship endpoint resolution**. It classifies each endpoint that the neutral observations
report, using only reference rules that were verified against authoritative format sources:

* **CycloneDX 1.5, 1.6 and 1.7** (official JSON schemas, `CycloneDX/specification`; 1.7 was checked by diffing the
  `component`/`service` definition references and the `dependency` properties against 1.6: identical, so the same rules hold). `dependencies[].ref`, `dependsOn[]` and (1.6) `provides[]` are
  typed `refLinkType`: "an element identified by the attribute `bom-ref` in the same BOM
  document, in contrast to `bomLinkElementType`". A value that does not start with `urn:cdx:` and
  is not in the document's reference registry is therefore a **local unregistered reference** (a
  verified dangling candidate). The registry itself (components, subject, and every schema
  location that uses the `component` or `service` definition, including nested components,
  pedigree objects and nested services) was checked against both schemas by a walk of their
  definitions; the check is recorded as a regression test (`tests/test_inventory_checks.py`).
  A value starting with `urn:cdx:` is a BOM-Link, which the schema does not type for these
  positions and which cannot be resolved here: an **unverified form**.
* **SPDX 2.3**. The official JSON schema types `relatedSpdxElement` and `spdxElementId` as plain
  strings, with no pattern. The forms of an endpoint that is not an element of this document
  (for example `NONE`, `NOASSERTION`, `DocumentRef-...:SPDXRef-...`) could not be verified from
  an authoritative source reachable for this milestone, so an unregistered SPDX endpoint is
  classified as an **unverified form**, never as dangling.
* Any other format or version: every unregistered endpoint is an unverified form.

The endpoints checked are both ends of every declared edge and the ``ref`` of every CycloneDX
``dependencies`` entry (a dangling ``ref`` whose ``dependsOn`` is absent or empty is still a
dangling reference). Composition ``assemblies`` are not R1 inputs (DECL treats a record that names
an unresolved reference as not applicable). The registry holds components and services; a
dependency endpoint that names another kind of ``bom-ref`` holder (for example a vulnerability or a
license) is not in it and is classified as a local unregistered reference, which is the
conservative reading of N4 ("absent from the component list").

R1 outcome (``evidence.inv.CheckOutcome``): a verified local unregistered reference gives
``CONTRADICTION_FOUND``; otherwise an unverified form gives ``NOT_PERFORMED`` (the check could not
be carried out, which INV derivation never treats as a pass); otherwise ``PASSED`` (including a
document with no edges: the check ran and found nothing). The defect is ``RELEVANT_TO_S`` only
when BIND is ``MATCHED`` for this very document (register D2); otherwise it stays undetermined,
and INV derivation reports it as a document-level diagnostic.

This module classifies nothing else: it does not infer fullness from counts or edges, does not
treat duplicate or conflicting references as a contradiction (C3 stays deferred; they appear only
in the assessment notes), and an empty member domain is ``EMPTY``, not a state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from evidence.bind import BindEvaluation
from evidence.cnp_rules import BindState
from evidence.inv import (
    CheckOutcome,
    Emptiness,
    Interpretability,
    InventoryAssessment,
    Relevance,
    StructuralCheck,
)
from evidence.inventory_observations import InventoryObservations, observe_inventory
from evidence.stage1_records import FORMAT_CYCLONEDX, FORMAT_SPDX, ReferenceStatus, SbomRecord

CHECK_R1 = "R1_ENDPOINT_RESOLUTION"
CYCLONEDX_VERIFIED_VERSIONS = ("1.5", "1.6", "1.7")
SPDX_VERIFIED_VERSIONS = ("SPDX-2.3",)
BOM_LINK_PREFIX = "urn:cdx:"


class EndpointClass(str, Enum):
    RESOLVED = "resolved"
    LOCAL_UNREGISTERED = "local_unregistered"  # a verified dangling candidate
    UNVERIFIED_FORM = "unverified_form"


class EndpointReason(str, Enum):
    IN_REGISTRY = "in_registry"
    LOCAL_BOM_REF_NOT_IN_REGISTRY = "local_bom_ref_not_in_registry"
    BOM_LINK_IN_LOCAL_REFERENCE_POSITION = "bom_link_in_local_reference_position"
    SPDX_ENDPOINT_FORMS_UNVERIFIED = "spdx_endpoint_forms_unverified"
    FORMAT_VERSION_NOT_VERIFIED = "format_version_not_verified"


@dataclass(frozen=True)
class EndpointFinding:
    doc_id: str
    edge_locator: str
    role: str  # "source" or "target" of an edge, or "node" (the ``ref`` of a ``dependencies`` entry)
    ref: str
    classification: EndpointClass
    reason: EndpointReason


@dataclass(frozen=True)
class ReferenceCheckResult:
    """The outcome of R1 for one document, with every endpoint classification."""

    doc_id: str
    format: str
    spec_version: Optional[str]
    outcome: CheckOutcome
    findings: tuple[EndpointFinding, ...]

    @property
    def local_unregistered(self) -> tuple[EndpointFinding, ...]:
        return tuple(f for f in self.findings if f.classification is EndpointClass.LOCAL_UNREGISTERED)

    @property
    def unverified(self) -> tuple[EndpointFinding, ...]:
        return tuple(f for f in self.findings if f.classification is EndpointClass.UNVERIFIED_FORM)


def _spec_version(record: SbomRecord) -> Optional[str]:
    return record.document.declared_metadata.get("spec_version")


def format_version_verified(record: SbomRecord) -> bool:
    version = _spec_version(record)
    if record.format == FORMAT_CYCLONEDX:
        return version in CYCLONEDX_VERIFIED_VERSIONS
    if record.format == FORMAT_SPDX:
        return version in SPDX_VERIFIED_VERSIONS
    return False


def _classify(record: SbomRecord, ref: str, status: ReferenceStatus) -> tuple[EndpointClass, EndpointReason]:
    if status is ReferenceStatus.RESOLVED:
        return EndpointClass.RESOLVED, EndpointReason.IN_REGISTRY
    if not format_version_verified(record):
        return EndpointClass.UNVERIFIED_FORM, EndpointReason.FORMAT_VERSION_NOT_VERIFIED
    if record.format == FORMAT_CYCLONEDX:
        if ref.lower().startswith(BOM_LINK_PREFIX):
            return EndpointClass.UNVERIFIED_FORM, EndpointReason.BOM_LINK_IN_LOCAL_REFERENCE_POSITION
        return EndpointClass.LOCAL_UNREGISTERED, EndpointReason.LOCAL_BOM_REF_NOT_IN_REGISTRY
    return EndpointClass.UNVERIFIED_FORM, EndpointReason.SPDX_ENDPOINT_FORMS_UNVERIFIED


def check_endpoint_resolution(record: SbomRecord, observations: Optional[InventoryObservations] = None) -> ReferenceCheckResult:
    """Run R1 on ``record`` (see the module docstring). Pure and deterministic."""
    observed = observations if observations is not None else observe_inventory(record)
    if observed.doc_id != record.doc_id:
        raise ValueError("observations belong to another document")
    findings: list[EndpointFinding] = []
    for edge in observed.edges:
        for role, endpoint in (("source", edge.source), ("target", edge.target)):
            classification, reason = _classify(record, endpoint.ref, endpoint.status)
            findings.append(EndpointFinding(record.doc_id, edge.locator, role, endpoint.ref, classification, reason))
    for node in observed.dependency_nodes:  # a `dependencies[].ref` is an endpoint even without any `dependsOn`
        classification, reason = _classify(record, node.ref, record.resolve(node.ref).status)
        findings.append(EndpointFinding(record.doc_id, node.locator, "node", node.ref, classification, reason))
    findings.sort(key=lambda f: (f.edge_locator, f.role, f.ref))
    if any(f.classification is EndpointClass.LOCAL_UNREGISTERED for f in findings):
        outcome = CheckOutcome.CONTRADICTION_FOUND
    elif any(f.classification is EndpointClass.UNVERIFIED_FORM for f in findings):
        outcome = CheckOutcome.NOT_PERFORMED
    else:
        outcome = CheckOutcome.PASSED
    return ReferenceCheckResult(record.doc_id, record.format, _spec_version(record), outcome, tuple(findings))


def build_assessment(
    record: SbomRecord,
    bind: BindEvaluation,
    observations: Optional[InventoryObservations] = None,
) -> tuple[InventoryAssessment, ReferenceCheckResult]:
    """The ``InventoryAssessment`` of ``record`` for ``derive_inv`` and the R1 result behind it.

    The assessment names ``record.doc_id``. Interpretability and emptiness are statements about
    parsed records only: ``INTERPRETABLE`` needs the member domain extracted and a verified
    format version; ``NON_EMPTY`` / ``EMPTY`` count the member domain (not the inventory for S).
    """
    observed = observations if observations is not None else observe_inventory(record)
    r1 = check_endpoint_resolution(record, observed)

    bound = bind.state is BindState.MATCHED and bind.document_id == record.doc_id
    if r1.outcome is CheckOutcome.CONTRADICTION_FOUND:
        first = r1.local_unregistered[0]
        detail = (f"{len(r1.local_unregistered)} local bom-ref endpoint(s) are not in the document's registry; "
                  f"first: {first.ref!r} at {first.edge_locator}")
        check = StructuralCheck(CHECK_R1, True, r1.outcome,
                                Relevance.RELEVANT_TO_S if bound else Relevance.UNDETERMINED, detail)
    elif r1.outcome is CheckOutcome.NOT_PERFORMED:
        first = r1.unverified[0]
        detail = (f"{len(r1.unverified)} endpoint(s) are in a form whose rules are not verified; "
                  f"first: {first.ref!r} at {first.edge_locator} ({first.reason.value})")
        check = StructuralCheck(CHECK_R1, True, r1.outcome, Relevance.UNDETERMINED, detail)
    else:
        check = StructuralCheck(CHECK_R1, True, r1.outcome, Relevance.UNDETERMINED,
                                f"{len(r1.findings)} endpoint classification(s), all resolved")

    interpretable = observed.member_domain_extracted and format_version_verified(record)
    members = observed.member_count
    if not observed.member_domain_extracted:
        emptiness = Emptiness.NOT_ASSESSED
    else:
        emptiness = Emptiness.NON_EMPTY if members > 0 else Emptiness.EMPTY

    notes: list[str] = []
    if not r1.findings:
        notes.append("R1 had no dependency or relationship endpoint to check (a vacuous pass: it says nothing "
                     "about the completeness of the inventory)")
    if observed.reference_conflicts:
        notes.append(f"C3 (deferred): {len(observed.reference_conflicts)} duplicate or conflicting reference "
                     "declaration(s) recorded; diagnostic only")
    if observed.endpoints_not_in_registry:
        notes.append(f"{observed.endpoints_not_in_registry} endpoint lookup(s) were not in the document's registry")
    if not observed.member_domain_extracted:
        notes.append("the member domain was not fully extracted (subject-nested components unavailable)")
    if not format_version_verified(record):
        notes.append(f"format/version {record.format} {_spec_version(record)!r} has no verified reference rules")

    assessment = InventoryAssessment(
        interpretability=Interpretability.INTERPRETABLE if interpretable else Interpretability.NOT_ASSESSED,
        emptiness=emptiness,
        checks=(check,),
        notes=tuple(notes),
        document_id=record.doc_id,
    )
    return assessment, r1
