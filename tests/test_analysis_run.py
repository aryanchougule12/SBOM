"""The analysis-run record contract (schema analysis-run/1): strict parsing, deterministic serialization, forbidden fields, trust boundary."""

import copy
import json
from pathlib import Path

import pytest

from evidence.analysis_run import (
    AnalysisRunError,
    AnalysisRunErrorCode as E,
    FieldSource,
    Origin,
    StageStatus,
    dump_analysis_run,
    parse_analysis_run,
    parse_analysis_run_data,
    record_to_dict,
)
from tests.analysis_eval import ANALYSIS_DIR

RUNS = ANALYSIS_DIR / "runs"
RECORDED = ANALYSIS_DIR / "authentic" / "codeql" / "recorded"
INVALID = {
    "synthetic_invalid_forbidden_field.run.json": E.FORBIDDEN_FIELD,
    "synthetic_invalid_forbidden_nested_field.run.json": E.FORBIDDEN_FIELD,
    "synthetic_invalid_schema_version.run.json": E.SCHEMA_UNSUPPORTED,
    "synthetic_invalid_unknown_field.run.json": E.UNKNOWN_FIELD,
    "synthetic_invalid_completed_with_nonzero_exit.run.json": E.INCONSISTENT,
    "synthetic_invalid_overlapping_roots.run.json": E.INCONSISTENT,
    "synthetic_invalid_secret_in_command.run.json": E.SECRET_IN_COMMAND,
    "synthetic_invalid_self_verified_source.run.json": E.FORBIDDEN_FIELD,
    "synthetic_invalid_caller_claims_runner_observation.run.json": E.INCONSISTENT,
    "synthetic_invalid_hash_form.run.json": E.INVALID_VALUE,
    "synthetic_invalid_truncated.run.json": E.MALFORMED,
}
VALID = sorted(p for p in list(RUNS.glob("*.json")) + list(RECORDED.glob("*.run.json")) if p.name not in INVALID)


def minimal(**changes):
    data = {"schema": "analysis-run/1", "run_id": "r1", "origin": "caller", "tool": {"name": "CodeQL", "version": "2.15.5"}}
    data.update(changes)
    return data


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.name)
def test_every_valid_record_loads_and_serializes_to_a_fixpoint(path):
    record = parse_analysis_run(path)
    text = dump_analysis_run(record)
    assert parse_analysis_run_data(json.loads(text)) == record
    assert dump_analysis_run(parse_analysis_run_data(json.loads(text))) == text
    assert text.endswith("\n") and text == dump_analysis_run(record)


@pytest.mark.parametrize("name,code", sorted(INVALID.items()))
def test_every_invalid_record_is_refused_with_its_code(name, code):
    with pytest.raises(AnalysisRunError) as error:
        parse_analysis_run(RUNS / name)
    assert error.value.code is code


def test_the_runner_written_records_are_stored_unedited_in_canonical_form():
    for path in RECORDED.glob("*.run.json"):
        assert path.read_text(encoding="utf-8") == dump_analysis_run(parse_analysis_run(path)), path.name


@pytest.mark.parametrize("name", ["verdict", "state", "evidence_state", "reach_state", "bind", "bind_state", "provenance", "provenance_level",
                                  "ep", "prov_reach", "p2", "p3", "trust", "verified", "signature_verified", "rules", "codes", "ceiling",
                                  "full_coverage_claim"])
def test_a_record_can_never_carry_a_derived_value_at_any_depth(name):
    for host in (lambda d: d.update({name: 1}), lambda d: d["tool"].update({name: 1}),
                 lambda d: d.setdefault("source", {}).update({name: 1}), lambda d: d.setdefault("scope", {}).setdefault("files", {}).update({name: 1})):
        data = minimal()
        host(data)
        with pytest.raises(AnalysisRunError) as error:
            parse_analysis_run_data(data)
        assert error.value.code is E.FORBIDDEN_FIELD


def test_missing_is_not_negative_null_false_and_zero_stay_distinct():
    unknown = parse_analysis_run_data(minimal(source={"worktree_clean": None, "untracked_files": None, "submodules": None, "changed_during_run": None}))
    stated = parse_analysis_run_data(minimal(source={"worktree_clean": False, "untracked_files": 0, "submodules": [], "changed_during_run": False}))
    assert (unknown.source.worktree_clean, unknown.source.untracked_files, unknown.source.submodules, unknown.source.changed_during_run) == (None, None, None, None)
    assert (stated.source.worktree_clean, stated.source.untracked_files, stated.source.submodules, stated.source.changed_during_run) == (False, 0, (), False)
    for record in (unknown, stated):
        assert parse_analysis_run_data(record_to_dict(record)) == record
    assert record_to_dict(unknown)["source"]["submodules"] is None and record_to_dict(stated)["source"]["submodules"] == []


def test_required_fields_and_types():
    for broken in ({}, {"schema": "analysis-run/1"}, minimal(run_id=""), minimal(origin="robot"), minimal(tool={}), minimal(tool={"name": ""}),
                   minimal(stages=[{"name": "a", "role": "analysis", "status": "weird"}]), minimal(outputs=[{"path": "x", "sha256": "abc"}]),
                   minimal(source={"revision": "XYZ"}), minimal(source={"revision": "abc"}), minimal(source={"tree_digest": "md5:abcd"}),
                   minimal(source={"untracked_files": -1}), minimal(source={"worktree_clean": "yes"})):
        with pytest.raises(AnalysisRunError):
            parse_analysis_run_data(broken)


@pytest.mark.parametrize("path", ["relative/root", "/a/./b", "/a/../b", "/a//b", "/a/b/", "/", "/a\\b", ""])
def test_root_paths_must_be_normalized_absolute_posix_paths(path):
    with pytest.raises(AnalysisRunError):
        parse_analysis_run_data(minimal(source={"roots": [{"id": "r", "path": path, "role": "primary"}]}))


def test_roots_may_not_overlap_repeat_or_have_two_primaries():
    def roots(*items):
        return minimal(source={"roots": [{"id": i, "path": p, "role": r} for i, p, r in items]})
    parse_analysis_run_data(roots(("a", "/ci/app", "primary"), ("b", "/ci/app-ext", "vendored")))     # a string prefix is not an overlap
    for bad in (roots(("a", "/ci/app", "primary"), ("b", "/ci/app/sub", "vendored")), roots(("a", "/ci/app", "primary"), ("a", "/ci/x", "vendored")),
                roots(("a", "/ci/app", "primary"), ("b", "/ci/x", "primary")), roots(("a", "/ci/app", "primary"), ("b", "/ci/app", "vendored"))):
        with pytest.raises(AnalysisRunError) as error:
            parse_analysis_run_data(bad)
        assert error.value.code is E.INCONSISTENT


def test_timestamps_need_an_offset_and_may_not_run_backwards():
    stage = {"name": "a", "role": "analysis", "status": "completed", "exit_code": 0}
    for started, finished in (("2026-01-01T00:00:00", None), ("not a time", None), ("2026-01-01T00:00:10Z", "2026-01-01T00:00:00Z")):
        with pytest.raises(AnalysisRunError):
            parse_analysis_run_data(minimal(stages=[dict(stage, started=started, finished=finished)]))
    ok = parse_analysis_run_data(minimal(stages=[dict(stage, started="2026-01-01T00:00:00+00:00", finished="2026-01-01T00:00:01Z")]))
    assert ok.stages[0].status is StageStatus.COMPLETED and ok.stages[0].started.tzinfo is not None


def test_stage_names_and_output_paths_are_unique_and_a_failed_stage_cannot_have_exit_zero():
    stage = {"name": "a", "role": "analysis", "status": "completed", "exit_code": 0}
    with pytest.raises(AnalysisRunError):
        parse_analysis_run_data(minimal(stages=[stage, stage]))
    with pytest.raises(AnalysisRunError):
        parse_analysis_run_data(minimal(stages=[dict(stage, status="failed", exit_code=0)]))
    with pytest.raises(AnalysisRunError):
        parse_analysis_run_data(minimal(outputs=[{"path": "x", "sha256": None}, {"path": "x", "sha256": None}]))
    assert parse_analysis_run_data(minimal(outputs=[{"path": "x", "sha256": None}])).outputs[0].sha256 is None   # an absent output is a fact


def test_field_sources_cannot_self_verify_or_fake_observation():
    with pytest.raises(AnalysisRunError) as error:
        parse_analysis_run_data(minimal(field_sources={"source": "established_by_verification"}))
    assert error.value.code is E.FORBIDDEN_FIELD
    with pytest.raises(AnalysisRunError) as error:
        parse_analysis_run_data(minimal(field_sources={"stages": "observed_by_runner"}))
    assert error.value.code is E.INCONSISTENT
    runner = parse_analysis_run_data(minimal(origin="runner", field_sources={"target": "caller_supplied"}))
    assert runner.source_of("target") is FieldSource.CALLER_SUPPLIED and runner.source_of("stages") is FieldSource.OBSERVED_BY_RUNNER
    assert parse_analysis_run_data(minimal()).source_of("stages") is FieldSource.CALLER_SUPPLIED and parse_analysis_run_data(minimal()).origin is Origin.CALLER


@pytest.mark.parametrize("argument,ok", [("--token=abc", False), ("GITHUB_TOKEN=abc", False), ("--password=x", False), ("--token=<redacted>", True),
                                         ("--language=javascript", True), ("--output=out/token-report.sarif", False), ("--format=sarif-latest", True)])
def test_credential_looking_arguments_are_refused_unless_redacted(argument, ok):
    data = minimal(configuration={"command": ["tool", argument]})
    if ok:
        parse_analysis_run_data(data)
    else:
        with pytest.raises(AnalysisRunError) as error:
            parse_analysis_run_data(data)
        assert error.value.code is E.SECRET_IN_COMMAND


def test_parsing_does_not_mutate_its_input():
    data = minimal(source={"roots": [{"id": "r", "path": "/ci/app", "role": "primary"}]})
    before = copy.deepcopy(data)
    parse_analysis_run_data(data)
    assert data == before


def test_a_record_cannot_be_unreadable_in_a_way_that_leaks_an_exception():
    for bad in (b"\xff\xfe", b"[]", b"{", b"null", b'{"a":' * 5000):
        with pytest.raises(AnalysisRunError):
            parse_analysis_run(bad)
    with pytest.raises(AnalysisRunError) as error:
        parse_analysis_run(Path("/nonexistent/record.json"))
    assert error.value.code is E.UNREADABLE
