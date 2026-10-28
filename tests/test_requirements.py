"""Tests for evidence.requirements.

``req_component_not_present`` is implemented (replacing the Stage 0 stub) as a pure function of the
engine's ``CnpInputs``; NT1-NT25 are encoded in tests/test_cnp_rules.py. The reachability predicate
is still not implemented and its stub is unchanged.
"""

import pytest

from evidence import requirements
from evidence.cnp_rules import BindState, CnpInputs, evaluate_cnp
from model import ArtifactKind, EvidenceState as S, ProvenanceLevel as P
from reports.verdict import Verdict, VerdictResult


def supported_inputs(**changes):
    values = dict(artifact_kind=ArtifactKind.SOURCE, inv=S.PRESENT, match=S.ABSENT, decl=S.PRESENT,
                  bind=BindState.MATCHED, prov_sbom=P.P3, prov_decl=P.P3)
    values.update(changes)
    return CnpInputs(**values)


def test_module_exposes_both_predicate_entry_points():
    assert callable(requirements.req_component_not_present)
    assert callable(requirements.req_vulnerable_code_not_in_execute_path)


def test_component_not_present_returns_the_engines_single_final_result():
    inputs = supported_inputs()
    result = requirements.req_component_not_present(inputs)
    assert isinstance(result, VerdictResult) and result == evaluate_cnp(inputs).result
    assert result.verdict is Verdict.SUPPORTED
    weak = requirements.req_component_not_present(supported_inputs(prov_sbom=P.P2))
    assert weak.verdict is Verdict.WEAK and weak.codes == ("INVENTORY_PROVENANCE_BELOW_P3",)
    # the clarified Step 4 (NT22): a required dimension that is Unknown with no governing rule
    nt22 = requirements.req_component_not_present(supported_inputs(match=S.UNKNOWN, prov_sbom=P.P2))
    assert nt22.verdict is Verdict.INSUFFICIENT and nt22.limitations == ("MATCH=Unknown",)


def test_component_not_present_refuses_the_removed_finding_form():
    with pytest.raises(TypeError, match="CnpInputs"):
        requirements.req_component_not_present(object())  # type: ignore[arg-type]


def test_reachability_predicate_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        requirements.req_vulnerable_code_not_in_execute_path(None)  # type: ignore[arg-type]


@pytest.mark.skip(reason="pending: Req(vulnerable_code_not_in_execute_path) rules R1-R13 and tests RT1-RT11 are not implemented")
def test_vulnerable_code_not_in_execute_path_rt1_to_rt11():
    raise AssertionError("placeholder")
