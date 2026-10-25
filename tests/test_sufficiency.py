"""Stage 0 structure tests for evidence.sufficiency (stub only)."""

import pytest

from evidence import sufficiency


def test_module_exposes_the_stub_interface():
    assert callable(sufficiency.evaluate_finding)


def test_stub_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        sufficiency.evaluate_finding(None)  # type: ignore[arg-type]


@pytest.mark.skip(reason="pending: the Step 0-5 decision procedure and aggregation cases AG1-AG5 are not implemented")
def test_decision_procedure_and_aggregation():
    raise AssertionError("placeholder")
