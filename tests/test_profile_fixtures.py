"""The shipped profile fixtures (schema 1.1 placement) through the real profile parser and the
integrated evaluator. The ``@PRIMARY@`` placeholder is replaced by the primary document's id."""

import pytest

from evidence.evaluator import EvaluationOutcome, evaluate
from evidence.profile import ProfileError, ProfileErrorCode as PE, parse_profile
from evidence.stage1_records import Stage1Index
from tests.pipeline_support import equivalent, load_profile_fixture, vex_findings, verification_for


def profile_for(name, record):
    return parse_profile(load_profile_fixture(name, record.doc_id))


def test_the_nested_fixture_parses_with_its_explicit_parent():
    record = equivalent("cdx")
    location = profile_for("placement_nested.json", record).target.would_be_location
    assert (location.document, location.placement, location.parent_ref) == (record.doc_id, "nested_under_component", "lib-b")


def test_the_top_level_fixture_has_no_parent():
    record = equivalent("cdx")
    location = profile_for("placement_top_level.json", record).target.would_be_location
    assert (location.placement, location.parent_ref) == ("top_level", None)


@pytest.mark.parametrize(
    "name,code",
    [
        ("ambiguous_missing_placement.json", PE.PLACEMENT_REQUIRED),
        ("ambiguous_nested_without_parent.json", PE.PARENT_REF_REQUIRED),
        ("ambiguous_top_level_with_parent.json", PE.PARENT_REF_FORBIDDEN),
    ],
)
def test_ambiguous_placements_are_rejected_by_the_profile_gate(name, code):
    record = equivalent("cdx")
    with pytest.raises(ProfileError) as e:
        profile_for(name, record)
    assert e.value.code is code


@pytest.mark.parametrize("name", ["placement_nested.json", "placement_top_level.json"])
@pytest.mark.parametrize("kind", ["cdx", "spdx"])
def test_valid_placement_fixtures_evaluate_to_a_structured_outcome_on_both_formats(name, kind):
    record = equivalent(kind)
    outcome = evaluate(profile_for(name, record), vex_findings(), Stage1Index([record]),
                       verification_for(record.doc_id, ("#/components", "#/compositions/0", "#/packages")))
    assert isinstance(outcome, EvaluationOutcome)
    assert outcome.doc_id == record.doc_id and outcome.result.verdict is not None
