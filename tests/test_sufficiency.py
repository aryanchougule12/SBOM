"""Tests for evidence.sufficiency: the integrated entry point (replaces the Stage 0 stub tests).

The stub ``evaluate_finding(finding)`` that raised ``NotImplementedError`` is intentionally
replaced by ``evaluate_finding(profile, findings, index, verification=None)``, which runs the
integrated pipeline of ``evidence.evaluator``. The decision procedure's rules are covered by
tests/test_cnp_rules.py (NT1-NT23) and the end-to-end behaviour by tests/test_evaluator.py.
"""

from pathlib import Path

from evidence import sufficiency
from evidence.evaluator import EvaluationOutcome, EvaluationRefusal, RefusalCode
from evidence.profile import parse_profile
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_module_exposes_the_entry_point():
    assert callable(sufficiency.evaluate_finding)


def test_entry_point_returns_an_outcome_with_one_final_verdict():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    findings = list(load_openvex(FIXTURES / "openvex" / "component_not_present.json").findings)
    product = "pkg:oci/example-app@sha256%3Aabc"
    profile = parse_profile({
        "schema_version": "1.1", "profile_id": "p",
        "scope": {"product_id": product, "version": "2.0.0", "artifact_kind": "source"},
        "documents": [{"doc_id": record.doc_id, "role": "primary_sbom"}],
    })
    outcome = sufficiency.evaluate_finding(profile, findings, Stage1Index([record]))
    assert isinstance(outcome, EvaluationOutcome)
    assert outcome.result.verdict.value in ("Supported", "Weak", "Insufficient")


def test_entry_point_refuses_instead_of_raising_for_bad_input():
    record = load_cyclonedx(FIXTURES / "cyclonedx" / "complete_composition.json")
    profile = parse_profile({
        "schema_version": "1.1", "profile_id": "p",
        "scope": {"product_id": "p", "version": "1", "artifact_kind": "source"},
        "documents": [{"doc_id": record.doc_id, "role": "primary_sbom"}],
    })
    refusal = sufficiency.evaluate_finding(profile, [], Stage1Index([record]))
    assert isinstance(refusal, EvaluationRefusal) and refusal.code is RefusalCode.PROFILE_INVALID
