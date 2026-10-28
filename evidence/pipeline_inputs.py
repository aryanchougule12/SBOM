"""Profile-driven pipeline input assembly (Stage 2 foundation).

``assemble(profile, findings, index)`` joins three things that were built separately and
checks that they refer to the same documents:

* the validated evaluator profile (``evidence.profile``);
* the parsed findings (for example from OpenVEX);
* the typed Stage 1 records (``evidence.stage1_records.Stage1Index``).

It selects the one finding the profile concerns (``select_finding``), applies the profile to a
copy of it (``apply_profile``: scope, target component, ``Finding.document_roles``), resolves
every profile document id against the index, and registers the supplied SBOM
``SourceDocument`` in the returned finding's ``source_documents`` so that
``EvidenceItem.source_doc`` values for that document refer to a registered document.

This module is assembly only. It derives no evidence item or state, evaluates no BIND, INV,
DECL or MATCH, computes no provenance and no verdict, and does not change
``evidence.extraction``.

Document identity. A profile ``doc_id`` is resolved by exact string equality against the
index (``Stage1Index.get``). There is no case-folding, trimming, alias, subject reference or
locator substitution, and a near miss is a missing record. Failures raise ``AssemblyError``
(a stable ``code`` and the offending id) before anything is returned, in the same hard-error
style as ``ProfileError``; errors of the profile layer (``ProfileError``) propagate
unchanged. On any failure nothing has been mutated.

Non-mutation. The profile, the supplied findings, the index and its records are never
modified. The returned ``PipelineAssembly`` is frozen, and it holds deep copies: the
finding is a copy and the primary record (with the ``SourceDocument`` registered on the
finding) is a copy, so later changes to the caller's objects cannot change the assembly.

Limitation, as in the profile: exactly one primary SBOM; corroborating documents are not
handled. Records the index holds for documents the profile does not name are ignored.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from evidence.profile import ValidatedProfile, apply_profile, select_finding
from evidence.stage1_records import SbomRecord, Stage1Index
from model import Finding


class AssemblyErrorCode(str, Enum):
    RECORD_NOT_SUPPLIED = "ASSEMBLY_RECORD_NOT_SUPPLIED"
    RECORD_IDENTITY_CONFLICT = "ASSEMBLY_RECORD_IDENTITY_CONFLICT"
    SOURCE_DOCUMENT_CONFLICT = "ASSEMBLY_SOURCE_DOCUMENT_CONFLICT"


class AssemblyError(ValueError):
    """A hard assembly error. ``doc_id`` is the profile document id concerned."""

    def __init__(self, code: AssemblyErrorCode, doc_id: str, message: str) -> None:
        super().__init__(f"{code.value} for document {doc_id!r}: {message}")
        self.code = code
        self.doc_id = doc_id
        self.message = message


class AssemblyDiagnosticCode(str, Enum):
    UNREFERENCED_RECORDS_IGNORED = "ASSEMBLY_UNREFERENCED_RECORDS_IGNORED"


@dataclass(frozen=True)
class AssemblyDiagnostic:
    code: AssemblyDiagnosticCode
    detail: str


@dataclass(frozen=True)
class PipelineAssembly:
    """The assembled inputs for one profile run.

    ``finding`` carries the profile's scope, target component and role map, and registers the
    primary SBOM's ``SourceDocument`` (the same object as ``primary_record.document``).
    ``primary_record`` is the Stage 1 record of the profile's single ``primary_sbom``.
    """

    profile_id: str
    primary_doc_id: str
    finding: Finding
    primary_record: SbomRecord
    diagnostics: tuple[AssemblyDiagnostic, ...] = ()


def assemble(profile: ValidatedProfile, findings: Sequence[Finding], index: Stage1Index) -> PipelineAssembly:
    """Assemble the pipeline inputs for ``profile``.

    Raises ``ProfileError`` (selection or application problems, unchanged),
    ``AssemblyError`` ``RECORD_NOT_SUPPLIED`` (a profile document id has no record),
    ``RECORD_IDENTITY_CONFLICT`` (a record is filed under an id it does not carry), or
    ``SOURCE_DOCUMENT_CONFLICT`` (the finding already registers a different document under
    the same id).
    """
    selected = select_finding(profile, findings)

    records: dict[str, SbomRecord] = {}
    for document in profile.documents:  # one primary document today; resolved by exact id
        record = index.get(document.doc_id)
        if record is None:
            raise AssemblyError(
                AssemblyErrorCode.RECORD_NOT_SUPPLIED, document.doc_id,
                f"no Stage 1 record is indexed under exactly this id ({len(index)} record(s) supplied)",
            )
        if record.doc_id != document.doc_id or record.document.doc_id != document.doc_id:
            raise AssemblyError(
                AssemblyErrorCode.RECORD_IDENTITY_CONFLICT, document.doc_id,
                f"the record found carries the id {record.document.doc_id!r}",
            )
        records[document.doc_id] = record

    existing = selected.source_documents.get(profile.primary_document)
    primary = records[profile.primary_document]
    if existing is not None and existing != primary.document:
        raise AssemblyError(
            AssemblyErrorCode.SOURCE_DOCUMENT_CONFLICT, profile.primary_document,
            "the finding already registers a different document under this id",
        )

    applied = apply_profile(profile, selected)  # a deep copy; the selected finding is untouched
    primary_copy = copy.deepcopy(primary)
    applied.source_documents[profile.primary_document] = primary_copy.document

    ignored = sorted(set(index.doc_ids()) - set(records))
    diagnostics = ()
    if ignored:
        diagnostics = (AssemblyDiagnostic(
            AssemblyDiagnosticCode.UNREFERENCED_RECORDS_IGNORED,
            f"{len(ignored)} indexed record(s) are not named by the profile and were ignored: {', '.join(ignored)}",
        ),)
    return PipelineAssembly(
        profile_id=profile.profile_id,
        primary_doc_id=profile.primary_document,
        finding=applied,
        primary_record=primary_copy,
        diagnostics=diagnostics,
    )
