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


def _rule(rule_id, cls, code=None):
    from evidence.rule_core import TriggeredRule
    return TriggeredRule(rule_id, code or f"CODE_{rule_id}", verdict.Verdict.WEAK, cls, f"detail {rule_id}")


def test_rationale_ordering_follows_section_3():
    """§3: order by class rank (CONTRADICTORY, CANNOT, BELOW), then the alphabetic family prefix, then the numeric
    suffix as an integer (R10 after R9), never the lexicographic order of the whole identifier."""
    from evidence.rule_core import order_triggered, render_rationale
    C, K, B = verdict.RationaleClass.CONTRADICTORY_EVIDENCE, verdict.RationaleClass.CANNOT_BE_ESTABLISHED, verdict.RationaleClass.BELOW_BAR
    rules = [_rule("R10", B), _rule("N2", K), _rule("R9", B), _rule("R3", C), _rule("N10", B), _rule("N1", C), _rule("R2", K)]
    ordered = [r.rule_id for r in order_triggered(rules)]
    assert ordered == ["N1", "R3", "N2", "R2", "N10", "R9", "R10"]
    assert [r.rule_id for r in order_triggered(reversed(rules))] == ordered     # independent of input order
    text = render_rationale(order_triggered(rules))
    assert text.startswith("CONTRADICTORY_EVIDENCE[CODE_N1,CODE_R3]:") and " | CANNOT_BE_ESTABLISHED[CODE_N2,CODE_R2]: " in text
    assert text.endswith("BELOW_BAR[CODE_N10,CODE_R9,CODE_R10]: N10: detail N10; R9: detail R9; R10: detail R10")
