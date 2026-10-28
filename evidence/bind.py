"""Pure BIND evaluator for the primary SBOM (Stage 2, BIND slice; register G3c / G17).

BIND (formal specification section 4.1) is the "binding of the inventory and declaration to S
(digest, else product and version)". ``evaluate_bind`` takes the profile's scope identity and
one parsed primary SBOM and returns a typed ``BindEvaluation``: ``MATCHED``, ``MISMATCHED`` or
``UNKNOWN`` (the engine's ``BindState``), the identity basis, a stable reason code and
diagnostics.

What this module is NOT. It derives no INV state, no provenance level (P2/P3 are never
granted and ``integrity.artifact_digest_binding`` is never set), no contradiction, no
predicate result, no verdict and no profile digest. It is not wired into
``evidence.extraction`` or ``evidence.cnp_rules`` (the engine does not import it; this module
only reuses the engine's ``BindState`` type) and it never reads the profile's INV assertions,
a VEX document, or ``Scope.artifact_kind`` (G10 stays open). The profile cannot set a BIND
state.

The policy below is the approved decision set B1-B5 recorded in
``docs/open_issues_register.md``. It is a project policy, not specification text: the
specification gives only the parenthesis quoted above.

B1, subject selection. Only the subject the document itself declares is a candidate:
``SourceDocument.subjects`` and, for SPDX, every ``SubjectDeclaration``. Exactly one distinct
subject (one distinct ``ref``) is required, and every SPDX declaration must have resolved to a
package. No subject, several distinct subjects, a declaration that resolved to a file, a
snippet or nothing, or declarations of one reference that disagree on identity fields all give
``UNKNOWN``. A listed or nested component, a similar name and a VEX product are never
substituted.

B2, precedence. The digest path decides whenever the scope and the subject have a comparable
usable digest (same normalized algorithm). Product and version is used only when no such
digest exists, and a product/version match never overrides a digest disagreement.

B3, digests. The approved canonical ``alg:hex`` normalization (``sbom_parser.identifiers``) is
applied to both sides, and the value must be non-empty hexadecimal. Algorithms are compared by
their normalized string only: there is no alias table, allow-list or length rule. For the
algorithms both sides state, an algorithm *agrees* when some value is equal and *disagrees*
otherwise. Agreement with no disagreement is ``MATCHED``; disagreement with no agreement is
``MISMATCHED``; both together, or two different values for one algorithm on either side, are
``UNKNOWN``. A malformed source-side digest is ignored and reported as a diagnostic; it is
never a mismatch.

B4, product and version fallback. The scope's ``product_id`` must be a purl (``pkg:``) or a CPE
(``cpe:``) and is compared exactly with the subject's purl, or one of its CPEs, after
``variant-norm-v1`` normalization. The scope version and the subject version must be equal
after trimming. A name, a ``bom-ref`` or an SPDXID is never compared. Anything missing,
incompatible or different gives ``UNKNOWN``.

B5. Only a digest disagreement can produce ``MISMATCHED``; a product or version difference
alone is ``UNKNOWN``.

Limitation. A declared hash is a self-asserted claim of the document. It is neither
independent proof that the document describes S nor proof that the hash covers the same bytes
as S's digest; a hash on a subject can describe a different object than the artifact in S. A
``MATCHED`` result therefore means only that the document's declared subject agrees with S
under this policy. It does not establish completeness, grant P2/P3 or show that a signature
covers the subject. Whether P2's "document declares a digest" must be read on the subject is
left to the provenance stage.

Outputs are deterministic: they do not depend on the order of subjects, hashes or CPEs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from evidence.cnp_rules import BindState
from evidence.profile import ScopeIdentity, ValidatedProfile
from evidence.stage1_records import FORMAT_SPDX, SbomRecord
from model import Component, DocumentSubject
from sbom_parser.identifiers import (
    normalize_cpe,
    normalize_hash_algorithm,
    normalize_hash_value,
    normalize_name,
    normalize_purl,
)

_HEX_DIGITS = frozenset("0123456789abcdef")


class BindBasis(str, Enum):
    """Which identity evidence decided a ``MATCHED`` or ``MISMATCHED`` result."""

    DIGEST = "digest"
    PRODUCT_VERSION = "product_version"


class BindCode(str, Enum):
    """Stable reason and diagnostic codes. The declaration order is the order in which
    several applicable codes are reported (the first applicable one is the reason)."""

    # decisive results
    DIGEST_MATCH = "BIND_DIGEST_MATCH"
    PRODUCT_VERSION_MATCH = "BIND_PRODUCT_VERSION_MATCH"
    DIGEST_MISMATCH = "BIND_DIGEST_MISMATCH"
    # UNKNOWN: primary document
    NO_PRIMARY_SBOM = "BIND_NO_PRIMARY_SBOM"
    PRIMARY_SBOM_AMBIGUOUS = "BIND_PRIMARY_SBOM_AMBIGUOUS"
    # UNKNOWN: subject selection (B1)
    SUBJECT_DECLARATION_UNRESOLVED = "BIND_SUBJECT_DECLARATION_UNRESOLVED"
    MULTIPLE_SUBJECTS = "BIND_MULTIPLE_SUBJECTS"
    SUBJECT_RECORDS_INCONSISTENT = "BIND_SUBJECT_RECORDS_INCONSISTENT"
    REPEATED_SUBJECT_CONFLICT = "BIND_REPEATED_SUBJECT_CONFLICT"
    NO_SUBJECT = "BIND_NO_SUBJECT"
    # UNKNOWN: digest path (B3)
    SCOPE_DIGEST_SELF_CONFLICT = "BIND_SCOPE_DIGEST_SELF_CONFLICT"
    SUBJECT_DIGEST_SELF_CONFLICT = "BIND_SUBJECT_DIGEST_SELF_CONFLICT"
    DIGEST_CONFLICT = "BIND_DIGEST_CONFLICT"
    # UNKNOWN: product and version fallback (B4)
    SCOPE_VERSION_UNAVAILABLE = "BIND_SCOPE_VERSION_UNAVAILABLE"
    PRODUCT_ID_NOT_COMPARABLE = "BIND_PRODUCT_ID_NOT_COMPARABLE"
    SUBJECT_PRODUCT_ID_MISSING = "BIND_SUBJECT_PRODUCT_ID_MISSING"
    PRODUCT_NOT_MATCHED = "BIND_PRODUCT_NOT_MATCHED"
    SUBJECT_VERSION_MISSING = "BIND_SUBJECT_VERSION_MISSING"
    VERSION_NOT_MATCHED = "BIND_VERSION_NOT_MATCHED"
    # diagnostics only (never a reason)
    SOURCE_DIGEST_MALFORMED = "BIND_SOURCE_DIGEST_MALFORMED"
    SCOPE_DIGEST_MALFORMED = "BIND_SCOPE_DIGEST_MALFORMED"


_ORDER = {code: n for n, code in enumerate(BindCode)}
_DIAGNOSTIC_ONLY = frozenset({BindCode.SOURCE_DIGEST_MALFORMED, BindCode.SCOPE_DIGEST_MALFORMED})


@dataclass(frozen=True)
class BindDiagnostic:
    code: BindCode
    detail: str


@dataclass(frozen=True)
class BindEvaluation:
    """The result of one BIND evaluation.

    ``basis`` is set exactly for ``MATCHED`` and ``MISMATCHED`` and is ``None`` for
    ``UNKNOWN``. ``reason`` is the stable code for the state (the first applicable code when
    several apply); the other applicable conditions are in ``diagnostics``.
    ``agreeing_digests`` (canonical ``alg:hex``) and ``disagreeing_algorithms`` describe the
    digest comparison when it took place. ``document_id`` is the ``doc_id`` of the SBOM record
    the result was derived from (``None`` when no record was evaluated); a later stage uses it
    to check that a BIND result belongs to the document it is combined with. A subject
    reference or locator is document-relative and does not identify a document. This record
    never carries a provenance level.
    """

    state: BindState
    basis: Optional[BindBasis]
    reason: BindCode
    subject_ref: Optional[str] = None
    subject_locator: Optional[str] = None
    agreeing_digests: tuple[str, ...] = ()
    disagreeing_algorithms: tuple[str, ...] = ()
    diagnostics: tuple[BindDiagnostic, ...] = ()
    document_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.document_id is not None and (not isinstance(self.document_id, str) or not self.document_id.strip()):
            raise ValueError("document_id must be None or a non-empty string")
        decisive = {
            BindCode.DIGEST_MATCH: (BindState.MATCHED, BindBasis.DIGEST),
            BindCode.PRODUCT_VERSION_MATCH: (BindState.MATCHED, BindBasis.PRODUCT_VERSION),
            BindCode.DIGEST_MISMATCH: (BindState.MISMATCHED, BindBasis.DIGEST),
        }
        if self.reason in decisive:
            consistent = decisive[self.reason] == (self.state, self.basis)
        else:
            consistent = (
                self.state is BindState.UNKNOWN and self.basis is None and self.reason not in _DIAGNOSTIC_ONLY
            )
        if not consistent:
            raise ValueError(f"inconsistent BindEvaluation: {self.state.value}, {self.basis}, {self.reason}")


# ---- digests ------------------------------------------------------------------------------------

def _canonical(algorithm: str, value: str) -> Optional[tuple[str, str]]:
    """Approved canonical form, or ``None`` when the algorithm or value is empty or the value
    is not hexadecimal. No algorithm-specific length is checked."""
    normalized_algorithm = normalize_hash_algorithm(algorithm)
    normalized_value = normalize_hash_value(value)
    if not normalized_algorithm or not normalized_value or not _HEX_DIGITS.issuperset(normalized_value):
        return None
    return normalized_algorithm, normalized_value


def _by_algorithm(pairs: Iterable[tuple[str, str]]) -> dict[str, frozenset[str]]:
    grouped: dict[str, set[str]] = {}
    for algorithm, value in pairs:
        grouped.setdefault(algorithm, set()).add(value)
    return {algorithm: frozenset(values) for algorithm, values in grouped.items()}


def _self_conflicts(digests: dict[str, frozenset[str]]) -> list[str]:
    return sorted(algorithm for algorithm, values in digests.items() if len(values) > 1)


# ---- subjects -------------------------------------------------------------------------------------

def _identity_signature(component: Component) -> tuple:
    """Normalized identity fields, used only to detect repeated declarations of one reference
    that disagree. Malformed hashes take part, so a disagreement is never hidden."""
    version = component.version.strip() if component.version is not None else None
    return (
        normalize_name(component.name),
        version or None,
        normalize_purl(component.purl) if component.purl and component.purl.strip() else None,
        tuple(sorted({normalize_cpe(c) for c in component.cpe if c.strip()})),
        tuple(sorted({(normalize_hash_algorithm(h.algorithm), normalize_hash_value(h.value))
                      for h in component.hashes})),
    )


def _select_subject(record: SbomRecord) -> tuple[Optional[DocumentSubject], list[BindDiagnostic]]:
    """Apply B1. Returns the single subject, or ``None`` with the blocking diagnostics
    (reported in ``BindCode`` order; the first is the reason)."""
    blockers: list[BindDiagnostic] = []
    subjects = record.document.subjects

    if record.format == FORMAT_SPDX:
        for declaration in sorted(record.subject_declarations, key=lambda d: (d.ref, d.declared_via, d.declaration_locator)):
            if declaration.resolved_as != "package":
                blockers.append(BindDiagnostic(
                    BindCode.SUBJECT_DECLARATION_UNRESOLVED,
                    f"{declaration.declared_via} declaration of {declaration.ref!r} at "
                    f"{declaration.declaration_locator} resolved as {declaration.resolved_as!r}, not as a package",
                ))
        declared_packages = {d.ref for d in record.subject_declarations if d.resolved_as == "package"}
        if declared_packages != {s.ref for s in subjects if s.ref is not None} or any(s.ref is None for s in subjects):
            blockers.append(BindDiagnostic(
                BindCode.SUBJECT_RECORDS_INCONSISTENT,
                "the document's subject records and its subject declarations do not name the same packages",
            ))

    groups: dict[tuple, list[DocumentSubject]] = {}
    for position, subject in enumerate(subjects):
        key = ("ref", subject.ref) if subject.ref is not None else ("anonymous", position)
        groups.setdefault(key, []).append(subject)

    if len(groups) > 1:
        refs = sorted(str(subject.ref) for subject in subjects)
        blockers.append(BindDiagnostic(
            BindCode.MULTIPLE_SUBJECTS,
            f"the document declares {len(groups)} distinct subjects: {', '.join(sorted(set(refs)))}",
        ))
    for key in sorted(groups, key=repr):
        members = groups[key]
        if len({_identity_signature(s.component) for s in members}) > 1:
            blockers.append(BindDiagnostic(
                BindCode.REPEATED_SUBJECT_CONFLICT,
                f"declarations of subject {key[1]!r} disagree on identity fields",
            ))
    if not groups:
        blockers.append(BindDiagnostic(BindCode.NO_SUBJECT, "the document declares no subject"))

    if blockers:
        return None, blockers
    [members] = groups.values()
    return min(members, key=lambda s: (s.locator, s.declared_via)), []


# ---- fallback ------------------------------------------------------------------------------------------

def _fallback_failures(scope: ScopeIdentity, component: Component) -> list[BindDiagnostic]:
    """B4. Every unmet condition, in ``BindCode`` order; empty means product and version match."""
    failures: list[BindDiagnostic] = []
    scope_version = scope.version.strip() if scope.version is not None else ""
    if not scope_version:
        failures.append(BindDiagnostic(BindCode.SCOPE_VERSION_UNAVAILABLE,
                                       "the scope states no version, so the product/version fallback is unavailable"))

    product_id = scope.product_id.strip()
    lowered = product_id.lower()
    if lowered.startswith("pkg:"):
        if not (component.purl and component.purl.strip()):
            failures.append(BindDiagnostic(BindCode.SUBJECT_PRODUCT_ID_MISSING, "the subject has no purl"))
        elif normalize_purl(product_id) != normalize_purl(component.purl):
            failures.append(BindDiagnostic(BindCode.PRODUCT_NOT_MATCHED, "the scope purl differs from the subject purl"))
    elif lowered.startswith("cpe:"):
        subject_cpes = {normalize_cpe(c) for c in component.cpe if c.strip()}
        if not subject_cpes:
            failures.append(BindDiagnostic(BindCode.SUBJECT_PRODUCT_ID_MISSING, "the subject has no CPE"))
        elif normalize_cpe(product_id) not in subject_cpes:
            failures.append(BindDiagnostic(BindCode.PRODUCT_NOT_MATCHED, "the scope CPE matches no subject CPE"))
    else:
        failures.append(BindDiagnostic(BindCode.PRODUCT_ID_NOT_COMPARABLE,
                                       "the scope product_id is neither a purl nor a CPE, so it is not compared"))

    if scope_version:
        subject_version = component.version.strip() if component.version is not None else ""
        if not subject_version:
            failures.append(BindDiagnostic(BindCode.SUBJECT_VERSION_MISSING, "the subject states no version"))
        elif subject_version != scope_version:
            failures.append(BindDiagnostic(BindCode.VERSION_NOT_MATCHED, "the scope version differs from the subject version"))
    return failures


# ---- evaluation ---------------------------------------------------------------------------------------------

def _sorted(diagnostics: Iterable[BindDiagnostic]) -> tuple[BindDiagnostic, ...]:
    return tuple(sorted(diagnostics, key=lambda d: (_ORDER[d.code], d.detail)))


def _unknown(blockers: list[BindDiagnostic], extra: Iterable[BindDiagnostic] = (),
             subject: Optional[DocumentSubject] = None, document_id: Optional[str] = None) -> BindEvaluation:
    ordered = _sorted([*blockers, *extra])
    reason = next(d.code for d in ordered if d.code not in _DIAGNOSTIC_ONLY)
    return BindEvaluation(
        state=BindState.UNKNOWN, basis=None, reason=reason,
        subject_ref=subject.ref if subject else None,
        subject_locator=subject.locator if subject else None,
        diagnostics=ordered, document_id=document_id,
    )


def evaluate_bind(scope: ScopeIdentity, record: Optional[SbomRecord]) -> BindEvaluation:
    """Evaluate BIND of the primary SBOM ``record`` to the profile ``scope``.

    ``record`` is the one primary SBOM of the run; ``None`` (no primary document) gives
    ``UNKNOWN``. Pure: nothing is mutated and the result depends only on the arguments.
    """
    if record is None:
        return _unknown([BindDiagnostic(BindCode.NO_PRIMARY_SBOM, "no primary SBOM record was supplied")])

    subject, blockers = _select_subject(record)
    if subject is None:
        return _unknown(blockers, document_id=record.doc_id)

    diagnostics: list[BindDiagnostic] = []
    scope_pairs: list[tuple[str, str]] = []
    for text in scope.artifact_digests:
        algorithm, separator, value = text.partition(":")
        canonical = _canonical(algorithm, value) if separator else None
        if canonical is None:
            diagnostics.append(BindDiagnostic(BindCode.SCOPE_DIGEST_MALFORMED,
                                              f"scope digest {text!r} is not a usable 'alg:hex' value and is ignored"))
        else:
            scope_pairs.append(canonical)
    subject_pairs: list[tuple[str, str]] = []
    for hash_entry in subject.component.hashes:
        canonical = _canonical(hash_entry.algorithm, hash_entry.value)
        if canonical is None:
            diagnostics.append(BindDiagnostic(
                BindCode.SOURCE_DIGEST_MALFORMED,
                f"subject digest {hash_entry.algorithm!r}:{hash_entry.value!r} is not usable and is ignored",
            ))
        else:
            subject_pairs.append(canonical)
    scope_digests = _by_algorithm(scope_pairs)
    subject_digests = _by_algorithm(subject_pairs)

    conflicts: list[BindDiagnostic] = []
    if scope_conflicts := _self_conflicts(scope_digests):
        conflicts.append(BindDiagnostic(BindCode.SCOPE_DIGEST_SELF_CONFLICT,
                                        f"the scope states different values for: {', '.join(scope_conflicts)}"))
    if subject_conflicts := _self_conflicts(subject_digests):
        conflicts.append(BindDiagnostic(BindCode.SUBJECT_DIGEST_SELF_CONFLICT,
                                        f"the subject states different values for: {', '.join(subject_conflicts)}"))
    if conflicts:
        return _unknown(conflicts, diagnostics, subject, record.doc_id)

    common = sorted(set(scope_digests) & set(subject_digests))
    if common:  # B2: the digest path decides; product and version is not consulted
        agreeing = tuple(f"{a}:{v}" for a in common if scope_digests[a] == subject_digests[a]
                         for v in sorted(scope_digests[a]))
        disagreeing = tuple(a for a in common if scope_digests[a] != subject_digests[a])
        if agreeing and disagreeing:
            return _unknown(
                [BindDiagnostic(BindCode.DIGEST_CONFLICT,
                                f"digests agree for {', '.join(a.split(':')[0] for a in agreeing)} "
                                f"but disagree for {', '.join(disagreeing)}")],
                diagnostics, subject, record.doc_id,
            )
        if agreeing:
            state, reason = BindState.MATCHED, BindCode.DIGEST_MATCH
        else:
            state, reason = BindState.MISMATCHED, BindCode.DIGEST_MISMATCH
        return BindEvaluation(
            state=state, basis=BindBasis.DIGEST, reason=reason,
            subject_ref=subject.ref, subject_locator=subject.locator,
            agreeing_digests=agreeing, disagreeing_algorithms=disagreeing,
            diagnostics=_sorted(diagnostics), document_id=record.doc_id,
        )

    failures = _fallback_failures(scope, subject.component)
    if failures:
        return _unknown(failures, diagnostics, subject, record.doc_id)
    return BindEvaluation(
        state=BindState.MATCHED, basis=BindBasis.PRODUCT_VERSION, reason=BindCode.PRODUCT_VERSION_MATCH,
        subject_ref=subject.ref, subject_locator=subject.locator, diagnostics=_sorted(diagnostics),
        document_id=record.doc_id,
    )


def evaluate_bind_for_profile(profile: ValidatedProfile, records: Iterable[SbomRecord]) -> BindEvaluation:
    """Evaluate BIND for the profile's single primary document, found by ``doc_id`` among
    ``records``. Absent gives ``UNKNOWN`` (``BIND_NO_PRIMARY_SBOM``); several records with that
    ``doc_id`` give ``UNKNOWN`` (``BIND_PRIMARY_SBOM_AMBIGUOUS``). Other records are ignored."""
    matches = [r for r in records if r.doc_id == profile.primary_document]
    if len(matches) > 1:
        return _unknown([BindDiagnostic(
            BindCode.PRIMARY_SBOM_AMBIGUOUS, f"{len(matches)} records have doc_id {profile.primary_document!r}")])
    return evaluate_bind(profile.scope, matches[0] if matches else None)
