"""Tests for evidence.requirements.

Both predicates are implemented (replacing the Stage 0 stubs) as pure functions of their engine's
input records: ``CnpInputs`` (NT1-NT25 are encoded in tests/test_cnp_rules.py) and ``ReachInputs``
(RT1-RT11 are encoded in tests/test_reach_rules.py and replayed through the whole pipeline in
tests/test_reach_evaluator.py).
"""

import pytest

from evidence import requirements
from evidence.cnp_rules import BindState, CnpInputs, evaluate_cnp
from model import ArtifactKind, EvidenceState as S, ProvenanceLevel as P
from evidence.reach_rules import ReachBasis, ReachInputs, evaluate_reach
from reports.verdict import Verdict, VerdictResult
from tests.reach_support import inputs as reach_inputs


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


def test_reachability_returns_the_engines_single_final_result():
    result = requirements.req_vulnerable_code_not_in_execute_path(reach_inputs())  # RT1 baseline
    assert isinstance(result, VerdictResult) and result == evaluate_reach(reach_inputs()).result
    assert result.verdict is Verdict.SUPPORTED
    weak = requirements.req_vulnerable_code_not_in_execute_path(reach_inputs(prov_reach=P.P2))  # RT8
    assert weak.verdict is Verdict.WEAK and weak.codes == ("ANALYSIS_PROVENANCE_BELOW_P3",)
    conflict = requirements.req_vulnerable_code_not_in_execute_path(reach_inputs(reach=S.CONTRADICTORY, reach_basis=None))  # RT4
    assert conflict.verdict is Verdict.INSUFFICIENT and conflict.codes == ("REACH_CONFLICT",)
    ceiling = requirements.req_vulnerable_code_not_in_execute_path(reach_inputs(locus=S.AMBIGUOUS, prov_reach=P.P2))  # G18
    assert ceiling.verdict is Verdict.INSUFFICIENT and ceiling.limitations == ("LOCUS=Ambiguous",)


def test_reachability_refuses_the_removed_finding_form():
    with pytest.raises(TypeError, match="ReachInputs"):
        requirements.req_vulnerable_code_not_in_execute_path(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ReachInputs"):
        requirements.req_vulnerable_code_not_in_execute_path(supported_inputs())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="CnpInputs"):
        requirements.req_component_not_present(reach_inputs())  # type: ignore[arg-type]


def test_reachability_rejects_inputs_the_specification_cannot_produce():
    with pytest.raises(ValueError):
        ReachInputs(reach=S.ABSENT, locus=S.PRESENT, entry=S.PRESENT, bind=BindState.MATCHED,
                    cfg=reach_inputs().cfg, prov_reach=P.P3, reach_basis=None)
    assert ReachBasis.K1 in ReachBasis
