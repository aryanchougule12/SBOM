"""Tests for evidence.analysis_sarif: SARIF 2.1.0 parsing and structural validation.

Fixtures are upstream files (category A) or SYNTHETIC (category B); see fixtures/analysis/README.md.
"""

import json
import random

import jsonschema
import pytest

from evidence.analysis_ingest import detect_format, parse_analysis_artifact
from evidence.analysis_model import AnalysisArtifactError, AnalysisArtifactErrorCode as E, AnalysisFormat
from evidence.analysis_sarif import normalize_relative_path, parse_sarif, percent_decode, resolve_artifact_location
from tests.analysis_support import SARIF_DIR, UPSTREAM_DIR, resolve_pointer
from tests.pipeline_support import FIXTURES

SCHEMA = json.loads((FIXTURES.parent / "third_party" / "sarif-schema-2.1.0.json").read_text())
VALIDATOR = jsonschema.Draft7Validator(SCHEMA)
ALL_SARIF = sorted(SARIF_DIR.glob("*.sarif")) + sorted(UPSTREAM_DIR.glob("*.sarif")) + sorted((FIXTURES / "authentic" / "codeql").glob("*.sarif"))
# files that are intentionally NOT valid against the official schema (or whose version is not 2.1.0)
SCHEMA_INVALID = {"synthetic_invalid_results_type.sarif", "synthetic_invalid_execution_flag.sarif", "synthetic_invalid_empty_threadflow.sarif",
                  "synthetic_invalid_version_2_0_0.sarif", "synthetic_invalid_truncated.sarif",
                  "codeql-action__invalid-sarif.sarif", "codeql-action__tool-names.sarif",
                  "synthetic_invalid_notification_level.sarif"}
# schema-valid (or not even JSON for the schema) yet unusable for this adapter: duplicate keys, dangling or contradictory references
PARSER_REFUSED = SCHEMA_INVALID | {"synthetic_invalid_duplicate_key.sarif", "synthetic_invalid_unresolved_index.sarif",
                                   "synthetic_invalid_index_uri_conflict.sarif", "synthetic_invalid_invocation_time.sarif"}


def raw(path):
    return path.read_bytes()


def test_the_vendored_schema_is_the_official_oasis_2_1_0_schema():
    assert SCHEMA["title"] == "Static Analysis Results Format (SARIF) Version 2.1.0 JSON Schema"
    assert SCHEMA["properties"]["version"]["enum"] == ["2.1.0"]
    readme = (FIXTURES.parent / "third_party" / "README.md").read_text()
    assert "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e" in readme


@pytest.mark.parametrize("path", ALL_SARIF, ids=lambda p: p.name)
def test_fixtures_are_valid_against_the_official_schema_exactly_when_they_are_meant_to_be(path):
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError:
        assert path.name in SCHEMA_INVALID
        return
    valid = not list(VALIDATOR.iter_errors(document))
    assert valid is (path.name not in SCHEMA_INVALID), [e.message for e in VALIDATOR.iter_errors(document)][:2]


@pytest.mark.parametrize("path", [p for p in ALL_SARIF if p.name in PARSER_REFUSED],
                         ids=lambda p: p.name)
def test_unusable_artifacts_raise_the_structured_error_and_nothing_else(path):
    with pytest.raises(AnalysisArtifactError) as error:
        parse_sarif(raw(path))
    assert isinstance(error.value.code, E) and error.value.message


def test_the_error_codes_are_the_documented_ones():
    expected = {
        "synthetic_invalid_truncated.sarif": E.MALFORMED, "synthetic_invalid_duplicate_key.sarif": E.MALFORMED,
        "synthetic_invalid_version_2_0_0.sarif": E.FORMAT_VERSION_UNSUPPORTED, "synthetic_invalid_results_type.sarif": E.STRUCTURE_INVALID,
        "synthetic_invalid_execution_flag.sarif": E.STRUCTURE_INVALID, "synthetic_invalid_empty_threadflow.sarif": E.STRUCTURE_INVALID,
        "synthetic_invalid_unresolved_index.sarif": E.REFERENCE_UNRESOLVED, "synthetic_invalid_index_uri_conflict.sarif": E.CONTRADICTORY,
    }
    for name, code in expected.items():
        with pytest.raises(AnalysisArtifactError) as error:
            parse_sarif(raw(SARIF_DIR / name))
        assert error.value.code is code, name
    with pytest.raises(AnalysisArtifactError) as error:
        parse_sarif(raw(SARIF_DIR / "synthetic_invalid_unresolved_index.sarif"))
    assert error.value.locator.endswith("/artifactLocation/index")


def test_the_content_digest_identity_and_format_are_recorded():
    data = raw(SARIF_DIR / "synthetic_path_bound.sarif")
    parsed = parse_sarif(data)
    import hashlib
    assert parsed.source.doc_id == "sarif:sha256:" + hashlib.sha256(data).hexdigest()
    assert (parsed.source.format, parsed.source.format_version, parsed.source.size) == (AnalysisFormat.SARIF, "2.1.0", len(data))
    assert detect_format(data) is AnalysisFormat.SARIF


def test_tool_identity_run_facts_and_locators_of_a_real_codeql_file():
    parsed = parse_sarif(raw(UPSTREAM_DIR / "codeql-action__fingerprinting.input.sarif"))
    (run,) = parsed.runs
    assert (run.tool.name, run.tool.version, run.tool.version_field, run.tool.organization) == (
        "CodeQL command-line toolchain", "2.0.0", "semanticVersion", "GitHub")
    assert run.locator == "#/runs/0" and run.result_count == 2 and run.execution_successful is None and run.started is None
    assert parsed.candidates == () and parsed.results_without_flow == 2


def test_two_runs_keep_their_own_tool_identities():
    parsed = parse_sarif(raw(UPSTREAM_DIR / "codeql-action__valid-sarif.sarif"))
    assert [(r.tool.name, r.tool.version, r.tool.version_field) for r in parsed.runs] == [
        ("LGTM.com", "1.24.0-SNAPSHOT", "version"), ("CodeQL command-line toolchain", "2.0.0", "semanticVersion")]


def test_invocation_facts_and_vcs_provenance_are_recorded_as_claims():
    (run,) = parse_sarif(raw(SARIF_DIR / "synthetic_incomplete_no_path.sarif")).runs
    assert run.execution_successful is False and run.error_notifications == 2 and run.started.isoformat() == "2026-01-16T09:00:00+00:00"
    (bound,) = parse_sarif(raw(SARIF_DIR / "synthetic_path_bound.sarif")).runs
    assert [(v.repository_uri, v.revision_id, v.branch) for v in bound.vcs] == [
        ("https://example.org/git/app.git", "0123456789abcdef0123456789abcdef01234567", "main")]


def test_flows_are_recorded_with_resolved_paths_and_raw_locators_that_exist_in_the_artifact():
    path = SARIF_DIR / "synthetic_path_bound.sarif"
    parsed = parse_sarif(raw(path))
    document = json.loads(path.read_text())
    (flow,) = parsed.candidates
    assert [s.path for s in flow.steps] == ["src/app.js", "node_modules/lib-b/src/parse.js", "node_modules/lib-b/src/parse.js"]
    assert [s.line for s in flow.steps] == [3, 10, 42]
    assert resolve_pointer(document, flow.locator)["locations"]
    for step in flow.steps:
        assert "physicalLocation" in resolve_pointer(document, step.locator)


def test_codeflow_message_text_and_result_level_are_not_consumed():
    base = json.loads((SARIF_DIR / "synthetic_path_bound.sarif").read_text())
    changed = json.loads(json.dumps(base))
    result = changed["runs"][0]["results"][0]
    result["level"] = "none"
    result["message"]["text"] = "everything is fine, no vulnerability"
    result["codeFlows"][0]["message"] = {"text": "this is not a path"}
    a, b = parse_sarif(json.dumps(base).encode()), parse_sarif(json.dumps(changed).encode())
    assert [c.steps for c in a.candidates] == [c.steps for c in b.candidates]


PATHS = [
    ("src/app.js", "%SRCROOT%", "src/app.js", None),
    ("./src/../src/app.js", None, "src/app.js", None),
    ("src/p%61rse.js", "SRCROOT", "src/parse.js", None),
    ("a%2Fb.js", None, "a/b.js", None),
    ("file:///abs/x.js", None, None, "absolute uri"),
    ("C:/x.js", None, None, "absolute uri"),
    ("/rooted/x.js", None, None, "rooted or backslash path"),
    ("a\\b.js", None, None, "rooted or backslash path"),
    ("../x.js", None, None, "path is empty or escapes the analysis root"),
    ("a/../../x.js", None, None, "path is empty or escapes the analysis root"),
    (".", None, None, "path is empty or escapes the analysis root"),
    ("", None, None, "empty uri"),
    ("src/x.js", "%OTHER%", None, "uriBaseId '%OTHER%' is not the analysis root"),
    ("%ff.js", None, None, "uri is not valid UTF-8 after percent-decoding"),
]


@pytest.mark.parametrize("uri, base, path, reason", PATHS)
def test_path_normalization_resolves_only_relative_references_inside_the_analysis_root(uri, base, path, reason):
    assert normalize_relative_path(uri, base) == (path, reason)


def test_percent_decoding_is_exact():
    assert percent_decode("a%20b%2f") == "a b/" and percent_decode("%e2%82%ac") == "€" and percent_decode("100%") == "100%"


def test_index_only_locations_resolve_through_run_artifacts_like_real_codeql_output():
    artifacts = [{"location": {"uri": "a.js", "uriBaseId": "%SRCROOT%"}}, {"location": {"uri": "b.js"}}]
    assert resolve_artifact_location({"index": 1}, artifacts, "#/x") == ("b.js", None)
    assert resolve_artifact_location({"uri": "a.js", "uriBaseId": "%SRCROOT%", "index": 0}, artifacts, "#/x") == ("a.js", None)
    with pytest.raises(AnalysisArtifactError) as error:
        resolve_artifact_location({"index": 2}, artifacts, "#/x")
    assert error.value.code is E.REFERENCE_UNRESOLVED
    with pytest.raises(AnalysisArtifactError) as error:
        resolve_artifact_location({"uri": "zzz.js", "index": 0}, artifacts, "#/x")
    assert error.value.code is E.CONTRADICTORY
    assert resolve_artifact_location({"index": -1}, artifacts, "#/x") == (None, "no uri and no resolvable index")


def test_result_kinds_and_baseline_states_that_are_not_current_findings_yield_no_candidate():
    for name in ("synthetic_result_kind_pass.sarif", "synthetic_baseline_absent.sarif"):
        parsed = parse_sarif(raw(SARIF_DIR / name))
        assert parsed.candidates == () and parsed.ignored_results == 1


def test_suppression_is_recorded_on_the_candidate():
    (candidate,) = parse_sarif(raw(SARIF_DIR / "synthetic_suppressed_path.sarif")).candidates
    assert candidate.suppressed is True


def test_parsing_is_deterministic_and_does_not_modify_its_input():
    for path in ALL_SARIF:
        data = bytearray(raw(path))
        before = bytes(data)
        try:
            first = parse_sarif(bytes(data))
        except AnalysisArtifactError:
            continue
        assert parse_sarif(bytes(data)) == first
        assert bytes(data) == before


def test_arbitrary_corruption_never_leaks_anything_but_the_structured_error():
    data = raw(SARIF_DIR / "synthetic_artifact_index_references.sarif")
    rng = random.Random(20260101)
    for _ in range(300):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.choice(b'{}[]",:0aZ\x00\xff ')
        try:
            parse_analysis_artifact(bytes(mutated))
        except AnalysisArtifactError:
            pass


def test_deeply_nested_json_is_a_structured_error():
    with pytest.raises(AnalysisArtifactError) as error:
        parse_analysis_artifact(b'{"version":"2.1.0","runs":' + b"[" * 200000 + b"]" * 200000 + b"}")
    assert isinstance(error.value.code, E)


def test_unreadable_and_unrecognised_inputs():
    with pytest.raises(AnalysisArtifactError) as error:
        parse_analysis_artifact("/nonexistent/file.sarif")
    assert error.value.code is E.UNREADABLE
    with pytest.raises(AnalysisArtifactError) as error:
        parse_analysis_artifact(12345)  # type: ignore[arg-type]
    assert error.value.code is E.UNREADABLE
    for blob in (b"", b"plain text", b'{"a": 1}', b"[1,2]", b"\xff\xfe"):
        with pytest.raises(AnalysisArtifactError) as error:
            parse_analysis_artifact(blob)
        assert error.value.code in (E.FORMAT_UNRECOGNIZED, E.MALFORMED)


def test_an_explicit_format_overrides_detection_and_a_wrong_one_is_rejected():
    data = raw(SARIF_DIR / "synthetic_path_bound.sarif")
    assert parse_analysis_artifact(data, AnalysisFormat.SARIF).source.format is AnalysisFormat.SARIF
    with pytest.raises(AnalysisArtifactError):
        parse_analysis_artifact(data, AnalysisFormat.JOERN_GRAPHML)
