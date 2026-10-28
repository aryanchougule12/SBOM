"""Tests for evidence.analysis_binding: subject loading, binding blockers, locus matching and document derivation."""

import dataclasses

import pytest

from evidence.analysis_binding import (
    AnalysisSubjectError,
    ArtifactRef,
    derive_document,
    parse_analysis_subject,
)
from evidence.analysis_ingest import parse_analysis_artifact
from evidence.reach_inputs import ReachFinding, ReachKind, ReachInputError, TargetRef, parse_reachability
from tests.analysis_support import GRAPHML_DIR, HASH, MAIN, PARSE, REV, SARIF_DIR, locus, subject
from tests.reach_support import baseline_data


def derive(path, subj=None, loc="default"):
    return derive_document(parse_analysis_artifact(path), subj or subject(), locus() if loc == "default" else loc)


# ---- the evaluator's subject --------------------------------------------------------------------------------

def test_the_default_subject_loads_and_is_immutable():
    s = subject()
    assert s.artifact == ArtifactRef("pkg:oci/example-app@sha256%3Aabc", "2.0.0") and s.entry_methods == (MAIN,)
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.entered_by = "x"  # type: ignore[misc]


SUBJECT_ERRORS = [
    ({"artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}}, "entered_by"),
    ({"entered_by": "t", "target": {"purl": "pkg:x/z@1"}}, "artifact"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"name": "z"}}, "target"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "source_revision": REV}, "source_repository"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "target_source_root": "/abs"}, "target_source_root"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "target_source_root": "a/../b"}, "target_source_root"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "entry_methods": ["a", "a"]}, "entry_methods"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "entry_methods": "main"}, "entry_methods"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1", "hashes": ["sha256:00"]}, "target": {"purl": "pkg:x/z@1"}}, "artifact"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "verdict": "Supported"}, "verdict"),
    ({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1"}, "target": {"purl": "pkg:x/z@1"}, "prov_reach": "P3"}, "prov_reach"),
]


@pytest.mark.parametrize("data, path", SUBJECT_ERRORS)
def test_an_invalid_subject_is_a_structured_error(data, path):
    with pytest.raises(AnalysisSubjectError) as error:
        parse_analysis_subject(data)
    assert error.value.path == path


def test_a_subject_can_never_carry_artifact_hashes_so_a_derived_document_is_never_p2():
    with pytest.raises(AnalysisSubjectError):
        parse_analysis_subject({"entered_by": "t", "artifact": {"purl": "pkg:x/y@1", "hashes": ["sha256:" + "0" * 64]}, "target": {"purl": "pkg:x/z@1"}})
    document = derive(SARIF_DIR / "synthetic_path_bound.sarif").document
    assert document.artifact.hashes == []


# ---- SARIF binding -----------------------------------------------------------------------------------------------------------

def test_a_bound_flow_derives_one_k1_positive_document_with_attribution_and_no_hashes():
    derived = derive(SARIF_DIR / "synthetic_path_bound.sarif")
    d = derived.document
    assert (d.kind, d.finding, d.full_coverage_claim, d.entry_points_complete, d.analyzed_configurations) == (ReachKind.K1, ReachFinding.POSITIVE, False, None, ())
    assert (d.tool_name, d.tool_version, d.producer, d.created.isoformat()) == ("CodeQL", "2.15.5", "GitHub", "2026-01-16T09:00:00+00:00")
    assert d.doc_id == derived.source.artifact.doc_id and d.source is derived.source and d.target == TargetRef(purl="pkg:npm/lib-b@2.0")
    assert derived.source.bind_blockers == ()
    assert derived.source.observation_locators == ("#/runs/0/results/0/codeFlows/0/threadFlows/0",)


@pytest.mark.parametrize("name, blocker", [
    ("synthetic_path_other_revision.sarif", "REVISION_MISMATCH:#/runs/0"),
    ("synthetic_path_other_repository.sarif", "REPOSITORY_MISMATCH:#/runs/0"),
    ("synthetic_path_no_vcs.sarif", "RUN_REVISION_UNKNOWN:#/runs/0"),
    ("synthetic_path_abbreviated_revision.sarif", "REVISION_MISMATCH:#/runs/0"),
    ("synthetic_conflicting_revisions_in_run.sarif", "REVISION_AMBIGUOUS:#/runs/0"),
])
def test_binding_failures_keep_the_observation_but_withhold_the_artifact_identity(name, blocker):
    derived = derive(SARIF_DIR / name)
    assert derived.source.bind_blockers == (blocker,)
    assert derived.document is not None and derived.document.artifact is None and len(derived.source.traces) == 1


def test_repository_comparison_ignores_case_trailing_slash_and_dot_git_but_not_the_host_or_path():
    path = SARIF_DIR / "synthetic_path_bound.sarif"   # the run states https://example.org/git/app.git
    for uri, bound in [("HTTPS://EXAMPLE.ORG/git/app", True), ("https://example.org/git/app.git/", True), ("https://example.org/git/app", True),
                       ("https://example.org/git/app2.git", False), ("https://example.com/git/app.git", False), ("https://example.org/git/other", False)]:
        blockers = derive(path, subject(source_repository=uri)).source.bind_blockers
        assert (blockers == ()) is bound, uri


def test_the_revision_comparison_is_case_insensitive_but_exact():
    assert derive(SARIF_DIR / "synthetic_path_bound.sarif", subject(source_revision=REV.upper())).source.bind_blockers == ()
    assert derive(SARIF_DIR / "synthetic_path_bound.sarif", subject(source_revision=REV[:7])).source.bind_blockers != ()


def test_every_contributing_run_must_bind():
    bad = derive(SARIF_DIR / "synthetic_two_runs_second_other_revision.sarif")
    assert bad.source.bind_blockers == ("REVISION_MISMATCH:#/runs/1",) and len(bad.source.traces) == 2


def test_no_flow_touching_the_locus_derives_no_document_but_keeps_the_explanation():
    derived = derive(SARIF_DIR / "synthetic_path_other_component.sarif")
    assert derived.document is None and derived.source.traces == () and derived.source.observation_locators == ()
    assert any(d.code == "FLOWS_NOT_TOUCHING_LOCUS" for d in derived.source.diagnostics)
    assert any("NO_ABSENCE_EVIDENCE" in lim for lim in derived.source.limitations)


def test_matching_needs_a_declared_locus_with_files_and_a_target_root():
    path = SARIF_DIR / "synthetic_path_bound.sarif"
    assert derive(path, loc=None).document is None
    assert derive(path, loc=locus(files=[])).document is None
    assert derive(path, subject(target_source_root=None)).document is None
    assert derive(path, subject(target_source_root=".")).document is None          # the flow is under node_modules/lib-b
    assert derive(path, subject(target_source_root="node_modules")).document is None  # a parent directory is not the target root
    assert derive(path, loc=locus(files=["src/parse.js", "other.js"])).document is not None


def test_a_file_name_alone_never_matches():
    assert derive(SARIF_DIR / "synthetic_path_bound.sarif", subject(target_source_root="node_modules/lib-bb")).document is None


def test_the_derived_document_carries_traces_with_locators_and_a_readable_summary():
    (trace,) = derive(SARIF_DIR / "synthetic_path_bound.sarif").source.traces
    assert trace.kind == "static_dataflow_trace" and trace.matched == "node_modules/lib-b/src/parse.js"
    assert trace.locator == "#/runs/0/results/0/codeFlows/0/threadFlows/0"
    assert trace.summary == "src/app.js:3 -> ... -> node_modules/lib-b/src/parse.js:42 (3 locations)"
    assert len(trace.step_locators) == 3


def test_limitations_always_name_the_evaluator_asserted_link_and_the_absence_boundary():
    derived = derive(SARIF_DIR / "synthetic_path_bound.sarif")
    joined = " ".join(derived.source.limitations)
    for text in ("SOURCE_TO_ARTIFACT_LINK_EVALUATOR_ASSERTED", "NO_ABSENCE_EVIDENCE", "RUN_STATUS_RECORDED_AS_CLAIMED"):
        assert text in joined


# ---- GraphML binding ------------------------------------------------------------------------------------------------------------

def test_a_call_path_from_a_declared_entry_to_the_locus_method_is_a_positive_observation():
    derived = derive(GRAPHML_DIR / "synthetic_path_bound.graphml")
    (trace,) = derived.source.traces
    assert trace.kind == "call_graph_path" and trace.locator == "#/graphml" and trace.matched == PARSE
    assert trace.summary == f"{MAIN} -> app.Svc.run:void() -> {PARSE}"
    assert derived.source.bind_blockers == () and derived.document.tool_name is None and derived.document.created is None


@pytest.mark.parametrize("name, blocker", [
    ("synthetic_path_hash_mismatch.graphml", "GRAPH_CONTENT_HASH_MISMATCH"),
    ("synthetic_path_no_hash.graphml", "GRAPH_CONTENT_HASH_ABSENT"),
    ("synthetic_no_meta_data.graphml", "GRAPH_CONTENT_HASH_ABSENT"),
])
def test_graph_binding_failures(name, blocker):
    derived = derive(GRAPHML_DIR / name)
    assert derived.source.bind_blockers == (blocker,) and derived.document.artifact is None


def test_the_graph_hash_comparison_is_case_insensitive_equality_of_declared_strings():
    assert derive(GRAPHML_DIR / "synthetic_path_bound.graphml", subject(source_content_hash=HASH.upper())).source.bind_blockers == ()
    assert derive(GRAPHML_DIR / "synthetic_path_bound.graphml", subject(source_content_hash=None)).source.bind_blockers == ("SUBJECT_CONTENT_HASH_NOT_DECLARED",)


def test_only_call_edges_are_followed_and_the_search_terminates_on_cycles():
    assert derive(GRAPHML_DIR / "synthetic_no_call_edges_cfg_only.graphml").document is None
    assert derive(GRAPHML_DIR / "synthetic_cycle_with_path.graphml").document is not None
    assert derive(GRAPHML_DIR / "synthetic_no_path_to_locus.graphml").document is None


def test_graph_matching_is_by_exact_full_name_and_declared_entries_only():
    path = GRAPHML_DIR / "synthetic_path_bound.graphml"
    assert derive(path, loc=locus(symbols=["lib.b.Parser.parse"])).document is None         # a prefix/short name does not match
    assert derive(path, subject(entry_methods=["app.Svc.run:void()"])).document is not None  # any declared entry may start the path
    assert derive(path, subject(entry_methods=["lib.c.Util.helper:void()"])).document is None
    assert derive(path, subject(entry_methods=[])).document is None


def test_graphml_documents_are_never_attributed_to_a_tool():
    d = derive(GRAPHML_DIR / "synthetic_path_bound.graphml").document
    assert (d.tool_name, d.tool_version, d.producer) == (None, None, None)


# ---- strict input boundary ---------------------------------------------------------------------------------------------------------

def test_derivation_metadata_cannot_be_supplied_through_the_json_input():
    data = baseline_data()
    data["documents"][0]["source"] = {"artifact": "x"}
    with pytest.raises(ReachInputError):
        parse_reachability(data)
    data = baseline_data()
    data["analysis_sources"] = []
    with pytest.raises(ReachInputError):
        parse_reachability(data)


def test_deriving_does_not_modify_the_inputs():
    analysis = parse_analysis_artifact(SARIF_DIR / "synthetic_path_bound.sarif")
    s, l = subject(), locus()
    before = (analysis, s, l)
    first = derive_document(analysis, s, l)
    assert (analysis, s, l) == before and derive_document(analysis, s, l) == first
