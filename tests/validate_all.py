"""One command for every mandatory check, with the current Python interpreter:

    python -m tests.validate_all            # run all stages; exit status 0 only if every stage passed
    python -m tests.validate_all --list     # print the stages and exit

Stages (each is an ordinary command whose own output is shown and whose own exit status is judged; nothing is suppressed or retried):

1. ``pytest -q -rs``                        the whole test suite (skip reasons are printed)
2. ``tests.conformance``                    rule conformance of both predicates and the corpus agreement
3. ``tests.analysis_eval --check``          the analyzer corpus report is current and every case agrees
4. ``tests.research_report --check``        the research report is current, deterministic, and the weakening invariant holds
5. ``tests.metamorphic --check``            the metamorphic campaign report is current and no relation is violated
6. ``compileall``                           every module compiles
7. ``pyflakes``                             static check (declared in requirements.txt)

All stages run even if an earlier one fails, so one invocation shows every problem; the exit status is 1 if any failed. The test suite never
calls this module's ``main`` (it would recurse); ``tests/test_validate_all.py`` checks it with stand-in commands only.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ("evidence", "tests", "analysis_runner", "reports", "sbom_parser")


def stages(python: str = sys.executable) -> list[tuple[str, list[str]]]:
    return [
        ("tests (pytest)", [python, "-m", "pytest", "-q", "-rs"]),
        ("rule conformance", [python, "-m", "tests.conformance"]),
        ("analyzer corpus report is current", [python, "-m", "tests.analysis_eval", "--check"]),
        ("research report is current", [python, "-m", "tests.research_report", "--check"]),
        ("metamorphic report is current", [python, "-m", "tests.metamorphic", "--check"]),
        ("compile", [python, "-m", "compileall", "-q", *PACKAGES]),
        ("static check (pyflakes)", [python, "-m", "pyflakes", *PACKAGES, "model.py"]),
    ]


def run_stages(plan: Sequence[tuple[str, list[str]]], run: Callable[..., "subprocess.CompletedProcess"] = subprocess.run,
               cwd: Path = ROOT, out=sys.stdout) -> int:
    results = []
    for name, command in plan:
        print(f"\n=== {name}: {' '.join(command[1:])}", file=out, flush=True)
        started = time.monotonic()
        done = run(command, cwd=str(cwd))
        results.append((name, done.returncode, time.monotonic() - started))
    print("\n=== summary", file=out)
    for name, code, seconds in results:
        print(f"{'PASS' if code == 0 else 'FAIL'}  exit {code:<3} {seconds:6.1f}s  {name}", file=out)
    failed = [name for name, code, _ in results if code != 0]
    print(f"\n{'ALL CHECKS PASSED' if not failed else 'FAILED: ' + ', '.join(failed)}", file=out)
    return 0 if not failed else 1


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    plan = stages()
    if args == ["--list"]:
        for name, command in plan:
            print(f"{name}: {' '.join(command[1:])}")
        return 0
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    return run_stages(plan)


if __name__ == "__main__":
    sys.exit(main())
