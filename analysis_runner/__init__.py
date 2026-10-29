"""Reproducible analysis-run recorder: runs the commands of a plan and writes an ``analysis-run/1`` record.

This package is deliberately outside ``evidence/``: it executes processes and hashes files, which the evidence pipeline
must never do (``tests/test_pipeline_boundaries.py``). The evaluation consumes only the JSON record it writes, and treats it
as an unauthenticated assertion.
"""

from analysis_runner.runner import PlanError, load_plan, redact_argv, run_plan, verify_record

__all__ = ["PlanError", "load_plan", "redact_argv", "run_plan", "verify_record"]
