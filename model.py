"""Typed data model for the SBOM evidence-sufficiency prototype (Stage 0).

Authoritative source: ``docs/formal_specification_v0.2.md`` and
``docs/spec_addendum_v0.2.1.md`` at commit e0d5bfadf9bd45e753051d7e7c8654f656ddb8ef.
Section references below (e.g. "§1.1") refer to that specification.

This module contains data structures only. It deliberately does NOT implement
effective-provenance calculation, evidence aggregation, identifier resolution,
completeness inference, manifest-only classification, decision rules or verdict
calculation. Constructors perform no validation: whether a structure satisfies a
rule or bar is decided by later stages, never by the data model.

Provenance is attached to *source documents* (§1.1) and referenced by evidence
items through ``EvidenceItem.source_doc``. There is intentionally no global
``PROV`` field anywhere in this model (§1.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Optional


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------

class EvidenceState(str, Enum):
    """The six evidence states of §2, and no others."""

    PRESENT = "Present"
    ABSENT = "Absent"
    UNKNOWN = "Unknown"
    INCOMPLETE = "Incomplete"
    AMBIGUOUS = "Ambiguous"
    CONTRADICTORY = "Contradictory"


class Disposition(str, Enum):
    """VEX disposition D (§1). The predicates apply only to ``NOT_AFFECTED``;
    other values are an input error, not a verdict. That rule is NOT enforced here.
    """

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class JustificationType(str, Enum):
    """The predicate-supported subset of justification values: the two values the
    specification defines predicates for.

    This is NOT the complete VEX justification vocabulary. §1 describes
    ``justification`` as a "VEX/CSAF value", but only these two are covered by
    the committed specification. Other valid VEX justifications exist and must
    remain representable (see ``Justification.justification``, which is a raw
    string); this enum only names the ones the prototype can evaluate.
    """

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"


class ArtifactKind(str, Enum):
    """``S.artifact_kind`` (§1), plus ``UNKNOWN`` for missing input.

    ``SOURCE``, ``BINARY``, ``CONTAINER`` and ``OTHER`` are the four values listed in
    §1. ``OTHER`` may be used only when the input explicitly establishes a kind outside
    source/binary/container; it is never a fallback for missing information.

    ``UNKNOWN`` is not one of the four values listed in §1. It means the artifact kind
    cannot be determined from the available input. It is a representation of absent
    information in the data model; how it interacts with the rules that depend on the
    artifact kind (for example N14/N15, §4.3) is defined by a later stage, not here.

    OPEN ISSUE (deferred): the specification does not yet define ``UNKNOWN`` or say how
    N14/N15 treat it. This is to be resolved during Stage 3's mandatory design-gap
    review, before N14/N15 are implemented. Until then no rule may treat ``UNKNOWN`` as
    ``SOURCE`` or ``OTHER``, or as a reason to skip those rules.
    """

    SOURCE = "source"
    BINARY = "binary"
    CONTAINER = "container"
    OTHER = "other"
    UNKNOWN = "unknown"


class DocumentRole(str, Enum):
    """The role a source document plays for one particular ``Finding`` (§1.2 roles).

    Roles are relative to a finding (``Finding.document_roles``). ``CORROBORATING``
    means only that the document was *explicitly designated as offered for
    corroboration*; it does not by itself establish artifact binding, sufficient
    provenance, ecosystem coverage, or that any generation-method criterion of §4.3
    is met. No role is implied by a document merely being present.
    """

    PRIMARY_SBOM = "primary_sbom"
    CORROBORATING = "corroborating"
    VEX_STATEMENT = "vex_statement"
    REACHABILITY_REPORT = "reachability_report"
    OTHER = "other"


class ProvenanceLevel(IntEnum):
    """The provenance ladder P0-P3 (§1.2).

    This is the research prototype's *proposed profile*, not a classification
    defined by CISA (P-4). Integer values allow later stages to compare levels;
    no effective-provenance calculation is implemented here.

    P0: unattributed. P1: attributed. P2: P1 plus a self-asserted artifact-digest
    binding. P3: P2 plus signature verified against a configured trust anchor for
    the content in question.
    """

    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3


class ProvenanceRole(str, Enum):
    """Named provenance roles of §1.2. Names only; no value is computed here.

    ``PROV_HAZ`` is parameterised per hazard class (``PROV_HAZ[class]``); the class
    is carried by whatever later structure uses the role, not by this enum.
    """

    PROV_SBOM = "PROV_SBOM"
    PROV_DECL = "PROV_DECL"
    PROV_CORR = "PROV_CORR"
    PROV_REACH = "PROV_REACH"
    PROV_HAZ = "PROV_HAZ"


# --------------------------------------------------------------------------
# C: component identity (§1)
# --------------------------------------------------------------------------

@dataclass
class Hash:
    """A component hash value and its algorithm (``C.hashes[]``)."""

    algorithm: str
    value: str


@dataclass
class IdentifierVariant:
    """One auditable member of ``C.identifier_variants`` (§1).

    The spec says variants are derived under versioned normalization rules and
    recorded for audit. ``kind`` is free text (e.g. purl, cpe, name+version, hash);
    the specification does not enumerate it. Deriving variants is a later stage.
    """

    kind: str
    value: str
    normalization_rule_version: Optional[str] = None


@dataclass
class Component:
    """C: component identity. At least one identifier is expected (§1); this is
    not validated by the model."""

    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: list[str] = field(default_factory=list)
    ecosystem: Optional[str] = None
    supplier: Optional[str] = None
    hashes: list[Hash] = field(default_factory=list)
    bom_ref: Optional[str] = None
    identifier_variants: list[IdentifierVariant] = field(default_factory=list)


# --------------------------------------------------------------------------
# V: vulnerability identity (§1)
# --------------------------------------------------------------------------

@dataclass
class VulnerableCodeLocus:
    """``V.locus`` (§1, §5.1). ``granularity`` is free text because the committed
    specification does not enumerate its values (it mentions "package-level")."""

    symbols: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    granularity: Optional[str] = None
    locus_source: Optional[str] = None


@dataclass
class Vulnerability:
    """V: vulnerability identity."""

    id: str
    aliases: list[str] = field(default_factory=list)
    source: Optional[str] = None
    affected_ranges: list[str] = field(default_factory=list)
    locus: Optional[VulnerableCodeLocus] = None


# --------------------------------------------------------------------------
# J: justification (§1)
# --------------------------------------------------------------------------

@dataclass
class Justification:
    """J: ``justification`` (VEX/CSAF value), ``asserted_by``, ``statement``.

    ``justification`` preserves the raw input value as a string. Values outside
    the predicate-supported subset (``JustificationType``), including valid VEX
    justifications such as ``vulnerable_code_not_present`` and arbitrary
    unrecognized strings, remain representable so that a later pipeline stage can
    reject them explicitly. The model neither validates nor classifies the value.
    """

    justification: str
    asserted_by: Optional[str] = None
    statement: Optional[str] = None


# --------------------------------------------------------------------------
# S: product/artifact scope (§1)
# --------------------------------------------------------------------------

@dataclass
class ValidInterval:
    """``S.valid_interval``. Either bound may be unspecified."""

    start: Optional[datetime] = None
    end: Optional[datetime] = None


@dataclass
class Scope:
    """S: the claim holds only for S.

    ``artifact_kind`` defaults to ``ArtifactKind.UNKNOWN`` (kind not determinable from
    the input), never to ``OTHER``.
    """

    product_id: str
    artifact_digest: list[str] = field(default_factory=list)
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    version: Optional[str] = None
    build_id: Optional[str] = None
    deployment_config_id: Optional[str] = None
    environment_assumptions: list[str] = field(default_factory=list)
    valid_interval: Optional[ValidInterval] = None


# --------------------------------------------------------------------------
# Source-document provenance (§1.1)
# --------------------------------------------------------------------------

@dataclass
class Integrity:
    """``integrity {...}`` of a source document (§1.1).

    ``signature_verified`` is the verification result: ``None`` when verification was
    not attempted or its outcome is unknown, ``False`` when it was attempted and did
    not verify, ``True`` when it verified. The model does not interpret it.

    ``signed_coverage`` records the coverage *declared by the input*. It is an
    assertion: it is neither proof that a signature verifies nor proof that the
    asserted coverage was actually signed. With several signatures it is the union of
    the declared claims and is not attributable to any one of them.

    ``established_coverage`` is the verified locator coverage that a verification result
    establishes (§1.2 step 3, A5):

    * ``None``: verified coverage is not established or is unavailable (the default,
      and the only value parsing ever produces).
    * ``[]``: verification explicitly established an empty set of covered locators.
    * a non-empty list: only locators that the verification result establishes as
      covered, for the signature(s) it verified.

    Parsing alone never sets ``signature_verified`` to ``True`` and never populates
    ``established_coverage``; both are set only by a verification step, which no parser
    performs. ``signed_coverage`` must never be copied into ``established_coverage``
    without such a result.
    """

    artifact_digest_binding: Optional[str] = None
    signature: Optional[str] = None
    signature_verified: Optional[bool] = None
    trust_anchor_id: Optional[str] = None
    signed_coverage: list[str] = field(default_factory=list)
    established_coverage: Optional[list[str]] = None


@dataclass
class DocumentSubject:
    """The artifact an SBOM document describes (its *subject*), distinct from the list
    of components the document inventories.

    ``ref`` is the identifier the document itself uses to point at the subject
    (CycloneDX ``bom-ref``, SPDX ``SPDXID``); ``None`` when the input gives none.
    ``component`` carries the subject's name, version, identifiers and hashes as
    declared. ``locator`` is a JSON Pointer in URI-fragment form (for example
    ``#/metadata/component`` or ``#/packages/0``). ``declared_via`` names the input
    construct that declared the subject (``metadata.component``, ``documentDescribes``,
    ``DESCRIBES`` or ``DESCRIBED_BY``). ``listed_as_component`` is True when the same
    entity is also an entry of the document's component list (an SPDX described
    package), False when it is not (CycloneDX ``metadata.component``).

    A subject is not evidence that any other component is, or is not, present.
    """

    ref: Optional[str]
    component: Component
    locator: str
    declared_via: str
    listed_as_component: bool


@dataclass
class SourceDocument:
    """A source document (SBOM file, reachability report, attestation).

    Provenance is recorded once per document (§1.1). ``producer_class``,
    ``generation_context`` and ``method`` are free text because the specification
    does not enumerate their values.

    ``declared_metadata`` holds any other declared attributes read from the
    document (e.g. declared ecosystem or artifact coverage referenced by §4.3 and
    assumption A7). Their structure is unspecified until a later stage defines how
    they are extracted; nothing here interprets them.

    Reference registry (for resolving dependency endpoints; it asserts nothing about
    inventory):

    * ``subjects``: the artifact(s) the document describes (see ``DocumentSubject``).
    * ``document_ref``: the document's own node reference (SPDX ``SPDXID`` of the
      document, e.g. ``SPDXRef-DOCUMENT``); ``None`` for formats without one. It is not
      a package or a target component.
    * ``other_defined_refs``: ``reference -> kind`` for objects the document declares in
      schema-supported locations that are neither listed in the ordinary component
      collection nor the subject (for example CycloneDX services and components nested
      under the subject, SPDX files and snippets). Registering a reference only means a
      dependency endpoint naming it is declared rather than dangling. It does not add the
      object to the inventory, does not assert inventory completeness, and is not
      evidence that any target component is present. Source locators for these
      references are kept in ``declared_metadata["defined_ref_locators"]``.
    """

    doc_id: str
    producer: Optional[str] = None
    producer_class: Optional[str] = None
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    created: Optional[datetime] = None
    generation_context: Optional[str] = None
    method: Optional[str] = None
    integrity: Integrity = field(default_factory=Integrity)
    declared_metadata: dict[str, str] = field(default_factory=dict)
    subjects: list[DocumentSubject] = field(default_factory=list)
    document_ref: Optional[str] = None
    other_defined_refs: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# E: evidence (§1)
# --------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    """An evidence item ``(dimension, state, value_or_ref, source_doc, locator,
    derived_from[])`` (§1).

    ``dimension`` is free text (e.g. INV, MATCH, DECL, BIND, REACH, ENTRY, LOCUS,
    CFG, ``HAZ[class]``). ``source_doc`` is a ``SourceDocument.doc_id``; the item
    carries no provenance of its own. ``item_id`` is a reference handle so that
    ``derived_from`` can name other items; it is an addition required to make
    ``derived_from[]`` expressible.
    """

    dimension: str
    state: EvidenceState
    value_or_ref: Optional[Any] = None
    source_doc: Optional[str] = None
    locator: Optional[str] = None
    derived_from: list[str] = field(default_factory=list)
    item_id: Optional[str] = None


# --------------------------------------------------------------------------
# F = (C, V, D, J, E) with finding-level scope S (§1)
# --------------------------------------------------------------------------

@dataclass
class Finding:
    """F = (C, V, D, J, E) with finding-level scope S.

    ``component`` is **C**, the specific component the finding's evidence concerns
    (§1). It is ``None`` when the target component is *unresolved*, i.e. cannot be
    established from the input; ``None`` is never to be read as "no component" or
    filled in from the product. ``product`` is the product under assessment (what a VEX
    statement asserts a status for). The two are distinct entities: the product's
    identifiers are never identifier variants of C, and neither is derived from the
    other. ``product`` is ``None`` for findings that were not built from a product
    entry.

    ``source_documents`` is the registry that ``EvidenceItem.source_doc`` refers
    to (§1: "plus source documents and evidence items that carry provenance").

    ``document_roles`` maps a source-document id to the role that document plays *for
    this finding*. It lives here, not on ``SourceDocument``, because one shared
    ``SourceDocument`` can play different roles for different findings. An absent entry
    means no role is established: a document's presence in ``source_documents`` never
    implies that it is the primary SBOM or that it corroborates anything.
    """

    component: Optional[Component]
    vulnerability: Vulnerability
    disposition: Disposition
    justification: Justification
    evidence: list[EvidenceItem]
    scope: Scope
    source_documents: dict[str, SourceDocument] = field(default_factory=dict)
    product: Optional[Component] = None
    document_roles: dict[str, DocumentRole] = field(default_factory=dict)
