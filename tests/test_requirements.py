"""Stage 0 structure tests for evidence.requirements (stubs only).

No predicate semantics are asserted. The specification's test cases (NT1-NT21,
RT1-RT11) are pending and are listed here as skipped so a test run reports them
honestly as not implemented.
"""

import pytest

from evidence import requirements


def test_module_exposes_both_predicate_entry_points():
    assert callable(requirements.req_component_not_present)
    assert callable(requirements.req_vulnerable_code_not_in_execute_path)


def test_stubs_are_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        requirements.req_component_not_present(None)  # type: ignore[arg-type]
    with pytest.raises(NotImplementedError):
        requirements.req_vulnerable_code_not_in_execute_path(None)  # type: ignore[arg-type]


@pytest.mark.skip(reason="pending: Req(component_not_present) rules N1-N17 and tests NT1-NT21 are not implemented")
def test_component_not_present_nt1_to_nt21():
    raise AssertionError("placeholder")


@pytest.mark.skip(reason="pending: Req(vulnerable_code_not_in_execute_path) rules R1-R13 and tests RT1-RT11 are not implemented")
def test_vulnerable_code_not_in_execute_path_rt1_to_rt11():
    raise AssertionError("placeholder")
