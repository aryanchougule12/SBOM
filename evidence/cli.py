"""Command line for the supported end-to-end workflow: evidence files in, one evaluation result (JSON) out.

    python -m evidence evaluate --sbom SBOM.json --vex VEX.json --profile PROFILE.json
                                [--reachability REACH.json] [--verification VERIFY.json]
                                [--subject SUBJECT.json --artifact ARTIFACT[::RUN_RECORD] ...] [--out RESULT.json]

* ``--sbom`` is a CycloneDX or SPDX JSON document (detected from its content); it is the profile's primary SBOM.
* ``--profile`` is the evaluator profile (``evidence/profile.py``). The text ``@PRIMARY@`` in it stands for the primary SBOM's
  content-derived document id (the same convention as ``fixtures/profiles``), so the profile need not know the id in advance.
* ``--subject`` (an ``AnalysisSubject`` JSON, ``evidence/analysis_binding.py``) with one or more ``--artifact`` options evaluates
  ``Req(vulnerable_code_not_in_execute_path)`` from real analyzer artifacts (SARIF, Joern GraphML), each optionally with its
  unauthenticated analysis-run record after ``::``.

The result is ``{"summary": ..., "evaluation": Outcome.to_dict()}`` serialized with sorted keys: a *presentation* of the evaluation, never an input to it. The verdict, codes,
rationale, limitations and evidence states are exactly the evaluator's. Exit status: 0 evaluated (any verdict: Insufficient is a result,
not an error); 1 a structured refusal (no verdict; the JSON says why); 2 unusable arguments or unreadable/invalid input files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from evidence.analysis_binding import AnalysisSubjectError, parse_analysis_subject
from evidence.analysis_ingest import AnalysisArtifactInput, evaluate_with_analysis
from evidence.evaluator import EvaluationRefusal
from evidence.profile import parse_profile
from evidence.reach_inputs import ReachInputError, load_reachability
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex, load_spdx
from evidence.sufficiency import evaluate_finding
from evidence.verification import load_verification
from sbom_parser.errors import ParserError

PLACEHOLDER = "@PRIMARY@"


class UsageError(Exception):
    """Unusable arguments or input files (exit status 2)."""


def _read_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise UsageError(f"{what} {path}: cannot read as JSON ({error})") from None


def _load_sbom(path: Path):
    data = _read_json(path, "SBOM")
    try:
        if isinstance(data, dict) and "bomFormat" in data:
            return load_cyclonedx(path)
        if isinstance(data, dict) and "spdxVersion" in data:
            return load_spdx(path)
    except ParserError as error:
        raise UsageError(f"SBOM {path}: {error}") from None
    raise UsageError(f"SBOM {path}: neither a CycloneDX ('bomFormat') nor an SPDX ('spdxVersion') JSON document")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m evidence", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("evaluate", help="evaluate the finding selected by a profile")
    run.add_argument("--sbom", type=Path, required=True)
    run.add_argument("--vex", type=Path, required=True)
    run.add_argument("--profile", type=Path, required=True)
    run.add_argument("--reachability", type=Path)
    run.add_argument("--verification", type=Path)
    run.add_argument("--subject", type=Path)
    run.add_argument("--artifact", action="append", default=[], metavar="ARTIFACT[::RUN_RECORD]")
    run.add_argument("--out", type=Path)
    return parser


def evaluate_command(args: argparse.Namespace) -> tuple[Any, int]:
    record = _load_sbom(args.sbom)
    try:
        vex = load_openvex(args.vex)
    except ParserError as error:
        raise UsageError(f"VEX {args.vex}: {error}") from None
    try:
        profile_text = args.profile.read_text(encoding="utf-8").replace(PLACEHOLDER, record.doc_id)
    except OSError as error:
        raise UsageError(f"profile {args.profile}: {error}") from None
    try:
        profile = parse_profile(json.loads(profile_text))
    except ValueError as error:      # ProfileError and JSON errors are both ValueErrors
        raise UsageError(f"profile {args.profile}: {error}") from None
    reachability = None
    if args.reachability:
        try:
            reachability = load_reachability(args.reachability)
        except (ReachInputError, ParserError, OSError) as error:
            raise UsageError(f"reachability {args.reachability}: {error}") from None
    verification = None
    if args.verification:
        try:
            verification = load_verification(args.verification)
        except (ValueError, ParserError, OSError) as error:
            raise UsageError(f"verification {args.verification}: {error}") from None
    index = Stage1Index([record])
    if args.artifact or args.subject:
        if not (args.artifact and args.subject):
            raise UsageError("--subject and --artifact must be given together")
        try:
            subject = parse_analysis_subject(_read_json(args.subject, "subject"))
        except AnalysisSubjectError as error:
            raise UsageError(f"subject {args.subject}: {error}") from None
        artifacts = []
        for item in args.artifact:
            artifact, _, run_record = item.partition("::")
            artifacts.append(AnalysisArtifactInput(Path(artifact), run=Path(run_record) if run_record else None))
        outcome = evaluate_with_analysis(profile, list(vex.findings), index, artifacts, subject, reachability, verification)
    else:
        outcome = evaluate_finding(profile, list(vex.findings), index, verification, reachability)
    return outcome, (1 if isinstance(outcome, EvaluationRefusal) else 0)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exit_:
        return 0 if exit_.code in (0, None) else 2
    try:
        outcome, status = evaluate_command(args)
    except UsageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    full = outcome.to_dict()
    summary = {"outcome": "refused" if status else "evaluated"}
    if status:
        summary.update(full)
    else:
        result = outcome.result
        summary.update(verdict=result.verdict.value, codes=list(result.codes), rationale=result.rationale, limitations=list(outcome.limitations),
                       dimension_states=dict(getattr(outcome, "dimension_states", {}) or {}))
    text = json.dumps({"summary": summary, "evaluation": full}, indent=1, sort_keys=True, ensure_ascii=False, default=str) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({summary['outcome']}{', verdict ' + summary['verdict'] if not status else ''})")
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))     # bytes, not the console's code page: the output is identical on every platform
        sys.stdout.buffer.flush()
    return status
