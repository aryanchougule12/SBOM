"""Soundness tests for analyzer-artifact evidence: unresolved locations, SARIF code-flow semantics, authentic CodeQL output,
Joern GraphML contract, identity binding and metamorphic invariants.

Fixtures are synthetic unless they live under fixtures/analysis/authentic (live CodeQL runs, see its REPRODUCE.md)."""

import copy
import json
import pathlib
import tempfile

import pytest

from evidence.analysis_binding import could_be_locus
from evidence.analysis_graphml import parse_joern_graphml
from evidence.analysis_sarif import loose_path, parse_sarif
from evidence.evaluator import EvaluationRefusal, RefusalCode
from evidence.reach_evaluator import ReachOutcome
from evidence.reach_inputs import parse_reachability
from model import EvidenceState as S
from reports.verdict import Verdict
from tests.analysis_support import ANALYSIS_DIR, GRAPHML_DIR, SARIF_DIR, evaluate, subject
from tests.reach_support import baseline_data, verified

AUTHENTIC = ANALYSIS_DIR / "authentic" / "codeql"
LIVE_FLOW = AUTHENTIC / "codeql-2.27.3__js-command-injection__flow-via-vendor-lib.sarif"
LIVE_EMPTY = AUTHENTIC / "codeql-2.27.3__js-tainted-path__no-results.sarif"
LIVE_APP_ONLY = AUTHENTIC / "codeql-2.27.3__js-command-injection__flow-app-only.sarif"
V_K1 = verified("k1-analysis")
LIB_ROOT = dict(target_source_root="vendor/lib-b")
GRAPH_ROOT = dict(target_source_root="node_modules/lib-b")


def supported_base():
    data = baseline_data()
    data["locus"].update(files=["src/parse.js"], symbols=["lib.b.Parser.parse:java.lang.Object(java.lang.String)"])
    return parse_reachability(data)


def k1(path, **subject_changes):
    return evaluate(SARIF_DIR / path if isinstance(path, str) else path, base=supported_base(), verification=V_K1,
                    subj=subject(**subject_changes) if subject_changes else None)


def alone(path, **subject_changes):
    return evaluate(SARIF_DIR / path if isinstance(path, str) else path, subj=subject(**subject_changes) if subject_changes else None)


# ---- the repaired hazard: an unresolved relevant record beside a K1 absence ---------------------------------------------------------

def test_the_k1_absence_alone_is_supported():
    assert evaluate(None, base=supported_base(), verification=V_K1).result.verdict is Verdict.SUPPORTED


@pytest.mark.parametrize("name", ["synthetic_unresolvable_locations.sarif", "synthetic_unknown_uri_base.sarif",
                                  "synthetic_path_traversal_location.sarif", "synthetic_flow_without_locations.sarif"])
def test_an_unresolved_relevant_flow_cannot_be_overridden_by_a_k1_absence(name):
    outcome = k1(name)
    assert isinstance(outcome, EvaluationRefusal)
    assert outcome.code is RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE and outcome.cause == "UNRESOLVED_RELEVANT_EVIDENCE"
    assert not hasattr(outcome, "result")  # no verdict, in particular not Supported


def test_without_the_absence_the_same_artifact_is_evaluated_and_the_flow_stays_visible():
    outcome = alone("synthetic_unresolvable_locations.sarif")
    assert isinstance(outcome, ReachOutcome) and outcome.result.verdict is Verdict.INSUFFICIENT and outcome.reach.state is S.UNKNOWN
    source = outcome.analysis[0]
    assert source.undecidable and source.undecidable[0].locator.startswith("#/runs/0/results/0/codeFlows/0")
    assert {"UNDECIDABLE_FLOW"} <= {d.code for d in source.diagnostics}
    assert any("UNDECIDABLE_EVIDENCE" in lim for lim in outcome.limitations)


@pytest.mark.parametrize("name", ["synthetic_unresolved_irrelevant.sarif", "synthetic_empty_codeflows_array.sarif"])
def test_an_irrelevant_or_empty_record_leaves_the_supplied_absence_in_force(name):
    outcome = k1(name)
    assert isinstance(outcome, ReachOutcome) and outcome.result.verdict is Verdict.SUPPORTED and outcome.reach.state is S.ABSENT
    assert not outcome.analysis[0].undecidable


def test_the_irrelevant_unresolved_location_is_reported_not_dropped():
    outcome = k1("synthetic_unresolved_irrelevant.sarif")
    assert "UNRESOLVED_LOCATIONS_EXCLUDED" in {d.code for d in outcome.analysis[0].diagnostics}


def test_an_established_path_decides_the_verdict_so_a_remaining_unresolved_flow_needs_no_refusal():
    outcome = k1("synthetic_mixed_threadflows_one_unresolved.sarif")
    assert isinstance(outcome, ReachOutcome) and outcome.reach.state is S.CONTRADICTORY and outcome.result.verdict is Verdict.INSUFFICIENT
    assert outcome.analysis[0].traces and outcome.analysis[0].undecidable
    assert any("UNDECIDABLE_EVIDENCE_DID_NOT_CHANGE_THE_VERDICT" in lim for lim in outcome.limitations)


def test_no_new_verdict_or_evidence_state_exists():
    assert {v.value for v in Verdict} == {"Supported", "Weak", "Insufficient"}
    assert {s.name for s in S} == {"PRESENT", "ABSENT", "UNKNOWN", "INCOMPLETE", "AMBIGUOUS", "CONTRADICTORY"}


def test_the_refusal_is_deterministic_and_the_inputs_are_not_mutated():
    base = supported_base()
    before = copy.deepcopy(base)
    first = evaluate(SARIF_DIR / "synthetic_unresolvable_locations.sarif", base=base, verification=V_K1)
    second = evaluate(SARIF_DIR / "synthetic_unresolvable_locations.sarif", base=base, verification=V_K1)
    assert first == second and base == before


# ---- graph: a call edge whose caller is unknown -------------------------------------------------------------------------------------

def test_an_unknown_caller_edge_into_the_locus_method_is_refused_beside_a_k1_absence_and_kept_without_one():
    path = GRAPHML_DIR / "synthetic_uncontained_call_into_locus.graphml"
    refused = evaluate(path, base=supported_base(), verification=V_K1, subj=subject(**GRAPH_ROOT))
    assert isinstance(refused, EvaluationRefusal) and refused.code is RefusalCode.ANALYSIS_EVIDENCE_UNDECIDABLE
    kept = evaluate(path, subj=subject(**GRAPH_ROOT))
    assert kept.reach.state is S.UNKNOWN and kept.analysis[0].undecidable
    assert {"UNDECIDABLE_CALL_EDGE", "CALL_SITE_WITHOUT_CONTAINING_METHOD"} <= {d.code for d in kept.analysis[0].diagnostics}


def test_an_unknown_caller_edge_that_cannot_reach_the_locus_is_irrelevant():
    outcome = evaluate(GRAPHML_DIR / "synthetic_uncontained_call_irrelevant.graphml", base=supported_base(), verification=V_K1,
                       subj=subject(**GRAPH_ROOT))
    assert isinstance(outcome, ReachOutcome) and outcome.result.verdict is Verdict.SUPPORTED and not outcome.analysis[0].undecidable


def test_reversed_contains_edges_are_not_trusted_and_not_silently_lost():
    path = GRAPHML_DIR / "synthetic_contains_edges_reversed.graphml"
    assert isinstance(evaluate(path, base=supported_base(), verification=V_K1, subj=subject(**GRAPH_ROOT)), EvaluationRefusal)
    alone_ = evaluate(path, subj=subject(**GRAPH_ROOT))
    assert alone_.reach.state is S.UNKNOWN and "CONTAINS_EDGE_REVERSED" in {d.code for d in alone_.analysis[0].diagnostics}


# ---- relevance filter units ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("loose,expected", [
    ("ci/work/app/node_modules/lib-b/src/parse.js", True),
    ("NODE_MODULES/LIB-B/SRC/PARSE.JS", True),            # case-insensitive: only ever widens the undecidable set
    ("../node_modules/lib-b/src/parse.js", True),
    ("ci/work/app/lib/more.js", False),
    ("ci/work/app/node_modules/lib-b/src/other.js", False),
    ("parse.js", False),                                    # shorter than the expected path: cannot end with it
    (None, True),                                           # no usable path: relevance cannot be excluded
])
def test_could_be_locus_is_a_necessary_condition_filter(loose, expected):
    assert could_be_locus(loose, {"node_modules/lib-b/src/parse.js": "x"}) is expected


def test_loose_path_strips_scheme_and_authority_and_keeps_leading_parent_segments():
    assert loose_path("file:///ci/work/app/a.js") == "/ci/work/app/a.js"
    assert loose_path("../a/b.js") == "../a/b.js"


# ---- SARIF code-flow semantics ------------------------------------------------------------------------------------------------------

def test_a_step_marked_unreachable_is_neither_a_path_nor_an_absence():
    outcome = alone("synthetic_locus_step_marked_unreachable.sarif")
    assert outcome.reach.state is S.UNKNOWN and not outcome.analysis[0].traces
    assert "LOCUS_STEP_MARKED_UNREACHABLE" in {d.code for d in outcome.analysis[0].diagnostics}
    assert k1("synthetic_locus_step_marked_unreachable.sarif").result.verdict is Verdict.SUPPORTED  # leaves the supplied absence alone


@pytest.mark.parametrize("name", ["synthetic_empty_codeflows_array.sarif", "synthetic_run_without_results_array.sarif",
                                  "synthetic_property_bag_claims_complete_coverage.sarif", "synthetic_no_results.sarif"])
def test_empty_missing_or_claimed_coverage_never_becomes_absence(name):
    outcome = alone(name)
    assert outcome.reach.state is S.UNKNOWN and outcome.result.verdict is Verdict.INSUFFICIENT


def test_the_primary_result_location_is_not_a_path():
    document = json.loads((SARIF_DIR / "synthetic_path_bound.sarif").read_text())
    for run in document["runs"]:
        for result in run["results"]:
            result.pop("codeFlows", None)
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "node_modules/lib-b/src/parse.js"}, "region": {"startLine": 3}}}]
    parsed = parse_sarif(json.dumps(document).encode())
    assert parsed.candidates == () and parsed.results_without_flow >= 1


@pytest.mark.parametrize("name", ["synthetic_invalid_invocation_time.sarif", "synthetic_invalid_notification_level.sarif"])
def test_invalid_invocation_metadata_is_refused(name):
    outcome = alone(name)
    assert isinstance(outcome, EvaluationRefusal) and outcome.cause == "ANALYSIS_STRUCTURE_INVALID"


def test_duplicate_locations_are_one_observation():
    outcome = alone("synthetic_duplicate_locations.sarif")
    assert len(outcome.analysis[0].traces) == 1


# ---- authentic CodeQL output (through the real adapter and binding) --------------------------------------------------------------

def test_authentic_codeql_flow_is_a_present_but_unbound_p0_observation():
    outcome = evaluate(LIVE_FLOW, subj=subject(**LIB_ROOT))
    assert outcome.reach.state is S.PRESENT and outcome.result.verdict is Verdict.INSUFFICIENT
    assert outcome.bind.state.value == "unknown" and "RUN_REVISION_UNKNOWN:#/runs/0" in outcome.analysis[0].bind_blockers
    assert outcome.prov_reach.name == "P0" and len(outcome.analysis[0].traces) == 1
    assert {"R1", "R6"} <= set(outcome.evaluation.rule_ids)


def test_authentic_codeql_flow_has_real_structure():
    parsed = parse_sarif(LIVE_FLOW.read_bytes())
    assert parsed.runs[0].tool.name == "CodeQL" and parsed.runs[0].tool.version == "2.27.3"
    candidate = parsed.candidates[0]
    assert len(candidate.steps) >= 2 and candidate.steps[0].locator.startswith("#/runs/0/results/0/codeFlows/0/threadFlows/0")
    assert [step.path for step in candidate.steps][-3:] == ["vendor/lib-b/src/parse.js"] * 3


def test_authentic_codeql_flow_next_to_a_k1_absence_is_a_conflict():
    outcome = evaluate(LIVE_FLOW, base=supported_base(), verification=V_K1, subj=subject(**LIB_ROOT))
    assert outcome.reach.state is S.CONTRADICTORY and outcome.result.verdict is Verdict.INSUFFICIENT and outcome.evaluation.rule_ids[0] == "R3"


def test_authentic_empty_results_are_not_a_coverage_claim():
    outcome = evaluate(LIVE_EMPTY, subj=subject(**LIB_ROOT))
    assert outcome.reach.state is S.UNKNOWN and not outcome.analysis[0].traces


def test_authentic_flow_that_does_not_touch_the_locus_is_neither_path_nor_absence():
    outcome = evaluate(LIVE_APP_ONLY, subj=subject(**LIB_ROOT))
    assert outcome.reach.state is S.UNKNOWN and "FLOWS_NOT_TOUCHING_LOCUS" in {d.code for d in outcome.analysis[0].diagnostics}
    assert evaluate(LIVE_APP_ONLY, base=supported_base(), verification=V_K1, subj=subject(**LIB_ROOT)).result.verdict is Verdict.SUPPORTED


def test_authentic_flow_under_the_wrong_root_cannot_improve_or_create_a_path():
    outcome = evaluate(LIVE_FLOW, subj=subject(target_source_root="node_modules/lib-b"))
    assert not outcome.analysis[0].traces and outcome.reach.state is S.UNKNOWN


def test_the_authentic_provenance_record_exists():
    text = (AUTHENTIC / "REPRODUCE.md").read_text()
    assert "64518dc413c8e7b5733fee2489e830a899bb1e3f28c8873b5869d5cc90164c5c" in text and "2.27.3" in text


# ---- Joern GraphML contract ---------------------------------------------------------------------------------------------------------

def test_cfg_only_exports_have_no_call_edges_and_are_reported_not_promoted():
    parsed = parse_joern_graphml((GRAPHML_DIR / "synthetic_no_call_edges_cfg_only.graphml").read_bytes())
    assert parsed.call_graph.edges == () and parsed.call_graph.call_edge_count == 0
    assert "NO_CALL_EDGES" in {d.code for d in parsed.diagnostics}
    assert alone_graph("synthetic_no_call_edges_cfg_only.graphml").reach.state is S.UNKNOWN


def alone_graph(name):
    return evaluate(GRAPHML_DIR / name, subj=subject(**GRAPH_ROOT))


# ---- binding / identity can never improve a verdict ---------------------------------------------------------------------------------

RANK = {Verdict.INSUFFICIENT: 0, Verdict.WEAK: 1, Verdict.SUPPORTED: 2}
MISBOUND = [dict(source_revision="ffffffffffffffffffffffffffffffffffffffff"), dict(source_repository="https://example.org/other.git"),
            dict(source_content_hash="0000000000000000"), dict(target_source_root="other/root"), dict(source_revision="0123456")]


@pytest.mark.parametrize("change", MISBOUND, ids=lambda c: next(iter(c)))
def test_a_mismatched_subject_never_yields_a_better_verdict_than_the_matching_one(change):
    for name in ("synthetic_path_bound.sarif", "synthetic_unresolvable_locations.sarif"):
        matching = alone(name)
        changed = alone(name, **change)
        if isinstance(changed, EvaluationRefusal) or isinstance(matching, EvaluationRefusal):
            continue
        assert RANK[changed.result.verdict] <= RANK[matching.result.verdict]
        assert changed.prov_reach is None or matching.prov_reach is None or changed.prov_reach <= matching.prov_reach


def test_no_derived_document_is_ever_p2_or_p3_from_declarations_alone():
    for path in sorted(SARIF_DIR.glob("synthetic_*.sarif")):
        outcome = alone(path.name)
        if isinstance(outcome, ReachOutcome) and outcome.prov_reach is not None:
            assert outcome.prov_reach.name in ("P0", "P1"), path.name


# ---- metamorphic: widening location uncertainty can only move toward refusal or a lower verdict ----------------------------------

def test_making_a_resolved_location_unresolvable_never_raises_the_verdict_next_to_a_k1_absence():
    document = json.loads((SARIF_DIR / "synthetic_path_bound.sarif").read_text())
    resolved = k1_text(document)
    for run in document["runs"]:
        for result in run["results"]:
            for flow in result.get("codeFlows", []):
                for tf in flow["threadFlows"]:
                    for loc in tf["locations"]:
                        art = loc["location"]["physicalLocation"]["artifactLocation"]
                        art["uri"] = "file:///ci/work/app/" + art["uri"]
    unresolved = k1_text(document)
    assert isinstance(unresolved, EvaluationRefusal) or RANK[unresolved.result.verdict] <= RANK[resolved.result.verdict]


def k1_text(document):
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "x.sarif"
        path.write_text(json.dumps(document))
        return evaluate(path, base=supported_base(), verification=V_K1)
