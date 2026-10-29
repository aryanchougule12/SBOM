"""``python -m batch_runner --sbom SBOM --vex VEX --scanner REPORT [--scanner REPORT ...] --artifact-kind KIND [--assert-full-inventory NAME]
[--verification FILE] [--out RESULT.json]``. Exit status: 0 reconciled (any mix of verdicts), 2 unusable arguments or inputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from batch_runner.runner import BatchError, InventoryAssertion, reconcile
from scanner_reports import ScannerReportError, parse_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m batch_runner", description=__doc__.split("\n\n")[0])
    p.add_argument("--sbom", type=Path, required=True)
    p.add_argument("--vex", type=Path, required=True)
    p.add_argument("--scanner", type=Path, action="append", required=True, help="Grype, Trivy or OSV-Scanner JSON report (format detected)")
    p.add_argument("--artifact-kind", required=True, choices=["source", "binary", "container", "other"], help="not derivable from the SBOM; stated by the caller")
    p.add_argument("--assert-full-inventory", metavar="NAME", help="record that NAME (a person) asserts the SBOM lists every component of the product")
    p.add_argument("--verification", type=Path)
    p.add_argument("--out", type=Path)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exit_:
        return 0 if exit_.code in (0, None) else 2
    try:
        reports = [parse_report(path) for path in args.scanner]
        assertion = InventoryAssertion("full_component_list", args.assert_full_inventory) if args.assert_full_inventory else None
        result = reconcile(args.sbom, args.vex, reports, artifact_kind=args.artifact_kind, assertion=assertion, verification=args.verification)
    except (BatchError, ScannerReportError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False, default=str) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({sum(result['counts'].values())} row(s): {result['counts']})")
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
    return 0
