"""Command line: ``python -m analysis_runner run PLAN.json --out RUN.json`` and ``python -m analysis_runner check RUN.json FILE...``."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from analysis_runner.runner import PlanError, load_plan, run_plan, verify_record
from evidence.analysis_run import AnalysisRunError, dump_analysis_run, parse_analysis_run

USAGE = """usage:
  python -m analysis_runner run PLAN.json --out RUN.json
      Execute the plan's stages, then write the analysis-run record. Exit status: 0 the record was written and every stage
      completed; 1 the record was written but a stage failed/timed out or an output is missing (the record says so); 2 the plan
      or arguments are unusable (nothing is written).
  python -m analysis_runner check RUN.json FILE [FILE...]
      Re-hash FILE(s) and compare with the record's outputs, and report any stage that did not complete, partial-analysis
      indicator or missing output. Exit status: 0 consistent and complete; 1 a mismatch or an incomplete run; 2 unusable input.

The record is execution metadata. A completed run is not proof of complete analysis coverage, and a matching hash is not proof
that the analyzer ran."""


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0 if args else 2
    command = args[0]
    try:
        if command == "run" and len(args) == 4 and args[2] == "--out":
            plan = load_plan(Path(args[1]))
            record = run_plan(plan, record_path=Path(args[3]))
            Path(args[3]).write_text(dump_analysis_run(record), encoding="utf-8")
            failed = any(s.status.value != "completed" for s in record.stages) or any(o.sha256 is None for o in record.outputs)
            print(f"wrote {args[3]} ({len(record.stages)} stage(s), {len(record.outputs)} output(s)){' - INCOMPLETE' if failed else ''}")
            return 1 if failed else 0
        if command == "check" and len(args) >= 3:
            record = parse_analysis_run(Path(args[1]))
            problems = verify_record(record, [Path(a) for a in args[2:]])
            problems += [f"stage {t.name!r}: {t.status.value}" for t in record.stages if t.status.value != "completed"]
            problems += [f"partial-analysis indicator: {p}" for p in record.partial_indicators]
            problems += [f"output {o.path!r} was not present when the run ended" for o in record.outputs if o.sha256 is None]
            for problem in problems:
                print(problem)
            return 1 if problems else 0
    except (PlanError, AnalysisRunError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(USAGE, file=sys.stderr)
    return 2
