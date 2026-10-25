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

    ``signature_verified`` is ``None`` when verification was not attempted or its
    outcome is unknown; the model does not interpret it.
    ``signed_coverage`` is the set of locators the signature actually covers.
    """

    artifact_digest_binding: Optional[str] = None
    signature: Optional[str] = None
    signature_verified: Optional[bool] = None
    trust_anchor_id: Optional[str] = None
    signed_coverage: list[str] = field(default_factory=list)


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

    ``source_documents`` is the registry that ``EvidenceItem.source_doc`` refers
    to (§1: "plus source documents and evidence items that carry provenance").
    """

    component: Component
    vulnerability: Vulnerability
    disposition: Disposition
    justification: Justification
    evidence: list[EvidenceItem]
    scope: Scope
    source_documents: dict[str, SourceDocument] = field(default_factory=dict)
