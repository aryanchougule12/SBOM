"""Public API for analyzer artifacts: parse, bind, derive, evaluate, explain.

    raw artifact -> parse_analysis_artifact -> NormalizedAnalysis
                 -> analysis_binding.derive_document (subject binding, locus matching)
                 -> strict ReachabilityEvidence (merged with any directly supplied evidence)
                 -> evidence.reach_evaluator.evaluate_reachability (unchanged rules)
                 -> ReachOutcome (with ``outcome.analysis`` explaining every artifact) or EvaluationRefusal

``evaluate_with_analysis`` is the one call that does all of it. An unusable artifact (unreadable,
malformed, unsupported version, structurally invalid, with unresolved or contradictory references) is
a structured **refusal** (``EVAL_ANALYSIS_ARTIFACT_INVALID``, no verdict): it is not "no evidence".
A well-formed artifact that records no path touching the locus is not an error: it contributes no
document, REACH stays ``Unknown`` (verdict Insufficient, R2 ``NO_ANALYSIS``) and its diagnostics and
limitations are reported.

The existing strict ``reachability=`` input is untouched and can be combined with artifacts: derived
documents are *added* to it (a directly supplied K1 absence next to a derived positive path is a
REACH ``Contradictory``, R3). Direct callers of ``evaluate_reachability`` / ``evaluate_finding`` with
a ``ReachabilityEvidence`` are not affected.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Optional, Sequence, Union

from evidence.analysis_binding import AnalysisSubject, DerivedEvidence, derive_document
from evidence.analysis_graphml import parse_joern_graphml
from evidence.analysis_model import (
    AnalysisArtifactError,
    AnalysisArtifactErrorCode as E,
    AnalysisFormat,
    NormalizedAnalysis,
)
from evidence.analysis_sarif import parse_sarif
from evidence.evaluator import EvaluationRefusal, RefusalCode
from evidence.profile import ValidatedProfile
from evidence.reach_evaluator import EMPTY_EVIDENCE, ReachOutcome, evaluate_reachability
from evidence.reach_inputs import ReachabilityEvidence
from evidence.stage1_records import Stage1Index
from evidence.verification import VerificationConfig
from model import Finding
from sbom_parser._common import InputSource, read_source

_PARSERS = {AnalysisFormat.SARIF: parse_sarif, AnalysisFormat.JOERN_GRAPHML: parse_joern_graphml}


@dataclass(frozen=True)
class AnalysisArtifactInput:
    """One raw artifact: bytes or a path, an optional explicit format, an optional label for messages."""

    source: InputSource
    format: Optional[AnalysisFormat] = None
    label: Optional[str] = None


def detect_format(raw: bytes) -> AnalysisFormat:
    """Recognise a supported format from the content (never from the file name)."""
    head = raw.lstrip(b"\xef\xbb\xbf \t\r\n")[:1]
    if head == b"{":
        try:
            text = raw.decode("utf-8")
            data = json.loads(text)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise AnalysisArtifactError(E.MALFORMED, "looks like JSON but is not valid UTF-8 JSON") from None
        if isinstance(data, dict) and "runs" in data and "version" in data:
            return AnalysisFormat.SARIF
    elif head == b"<":
        return AnalysisFormat.JOERN_GRAPHML
    raise AnalysisArtifactError(E.FORMAT_UNRECOGNIZED, "neither a SARIF log nor a GraphML document")


def parse_analysis_artifact(source: InputSource, format: Optional[AnalysisFormat] = None) -> NormalizedAnalysis:
    """Parse one artifact into the neutral ``NormalizedAnalysis``. Raises ``AnalysisArtifactError``
    (and nothing else) for any unusable input. Pure: the input is not modified."""
    try:
        raw = read_source(source)
    except (OSError, TypeError) as error:
        raise AnalysisArtifactError(E.UNREADABLE, f"cannot read the artifact: {error}") from None
    chosen = format if format is not None else detect_format(raw)
    try:
        return _PARSERS[chosen](raw)
    except AnalysisArtifactError:
        raise
    except RecursionError:
        raise AnalysisArtifactError(E.MALFORMED, "the artifact is nested too deeply") from None


def ingest_artifacts(
    artifacts: Sequence[Union[AnalysisArtifactInput, InputSource]],
    subject: AnalysisSubject,
    base: Optional[ReachabilityEvidence] = None,
) -> ReachabilityEvidence:
    """Parse and bind every artifact and return ``base`` plus the derived documents and sources.

    Raises ``AnalysisArtifactError`` if any artifact is unusable, or if the same artifact (the same
    bytes) is supplied twice or collides with a directly supplied document id."""
    evidence = base if base is not None else EMPTY_EVIDENCE
    documents = list(evidence.documents)
    sources = list(evidence.analysis_sources)
    seen = {d.doc_id for d in documents} | {s.artifact.doc_id for s in sources}
    for position, item in enumerate(artifacts):
        entry = item if isinstance(item, AnalysisArtifactInput) else AnalysisArtifactInput(item)
        try:
            analysis = parse_analysis_artifact(entry.source, entry.format)
        except AnalysisArtifactError as error:
            raise AnalysisArtifactError(error.code, f"artifact #{position}{' ' + repr(entry.label) if entry.label else ''}: {error.message}",
                                        error.locator) from None
        if analysis.source.doc_id in seen:
            raise AnalysisArtifactError(E.CONTRADICTORY, f"artifact #{position} ({analysis.source.doc_id}) is already present in the evidence")
        seen.add(analysis.source.doc_id)
        derived: DerivedEvidence = derive_document(analysis, subject, evidence.locus)
        sources.append(derived.source)
        if derived.document is not None:
            documents.append(derived.document)
    return dataclasses.replace(evidence, documents=tuple(documents), analysis_sources=tuple(sources))


def evaluate_with_analysis(
    profile: ValidatedProfile,
    findings: Sequence[Finding],
    index: Stage1Index,
    artifacts: Sequence[Union[AnalysisArtifactInput, InputSource]],
    subject: AnalysisSubject,
    reachability: Optional[ReachabilityEvidence] = None,
    verification: Optional[VerificationConfig] = None,
) -> Union[ReachOutcome, EvaluationRefusal]:
    """Evaluate ``Req(vulnerable_code_not_in_execute_path)`` from real analyzer artifacts.

    ``reachability`` carries the evaluator-entered facts the artifacts cannot supply (locus,
    entry-point completeness, hazards, configuration) and any directly supplied documents. Nothing
    the caller passes in is mutated."""
    if not isinstance(subject, AnalysisSubject):
        return EvaluationRefusal(RefusalCode.ANALYSIS_SUBJECT_INVALID, "subject must be an AnalysisSubject")
    if reachability is not None and not isinstance(reachability, ReachabilityEvidence):
        return EvaluationRefusal(RefusalCode.REACH_INPUT_INVALID, "reachability must be a ReachabilityEvidence")
    if isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, Sequence):
        return EvaluationRefusal(RefusalCode.ANALYSIS_ARTIFACT_INVALID, "artifacts must be a sequence", E.UNREADABLE.value)
    try:
        evidence = ingest_artifacts(artifacts, subject, reachability)
    except AnalysisArtifactError as error:
        return EvaluationRefusal(RefusalCode.ANALYSIS_ARTIFACT_INVALID,
                                 error.message + (f" (at {error.locator})" if error.locator else ""), error.code.value)
    return evaluate_reachability(profile, findings, index, evidence, verification)
