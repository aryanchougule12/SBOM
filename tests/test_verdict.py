"""Stage 0 smoke and structure tests for reports.verdict."""

import pytest

from reports import verdict


def test_verdict_categories_are_exactly_three():
    assert [v.value for v in verdict.Verdict] == ["Supported", "Weak", "Insufficient"]


def test_rationale_classes_are_exactly_the_four_spec_tokens():
    # Spec section 3: the three rule classes plus NO_RULE_APPLIES (the Step 4 no-rule default).
    assert {c.value for c in verdict.RationaleClass} == {
        "CONTRADICTORY_EVIDENCE", "CANNOT_BE_ESTABLISHED", "BELOW_BAR", "NO_RULE_APPLIES",
    }
    # Rationale classes are sub-reasons, not verdicts.
    assert {c.value for c in verdict.RationaleClass}.isdisjoint({v.value for v in verdict.Verdict})


def test_can_construct_a_result_object():
    result = verdict.VerdictResult(verdict=verdict.Verdict.WEAK, rationale="BELOW_BAR[]: structure test only")
    assert result.verdict is verdict.Verdict.WEAK


def test_render_stub_is_honestly_unimplemented():
    result = verdict.VerdictResult(verdict=verdict.Verdict.WEAK, rationale="")
    with pytest.raises(NotImplementedError):
        verdict.render_verdict(result)


@pytest.mark.skip(reason="pending: rationale generation and code ordering are not implemented")
def test_rationale_ordering():
    raise AssertionError("placeholder")
