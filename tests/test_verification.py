"""Tests for evidence.verification: the strict, trusted, externally supplied verification input.

Nothing here verifies a signature; the module only validates and holds an externally produced
result. See also tests/test_document_provenance.py for how a result is consumed.
"""

import copy
import dataclasses
import json

import pytest

from evidence.verification import (
    VerificationConfig,
    VerificationError,
    VerificationErrorCode as E,
    VerificationResult,
    load_verification,
    parse_verification,
)

DOC = "cyclonedx:sha256:" + "ab" * 32


def good():
    return {
        "schema_version": "1",
        "trust_anchors": ["anchor-1", "anchor-2"],
        "results": [
            {
                "doc_id": DOC,
                "verified": True,
                "trust_anchor_id": "anchor-1",
                "verifier": {"name": "external-verifier", "version": "2.1"},
                "established_coverage": ["#/components", "#/metadata"],
            }
        ],
    }


def code_of(data):
    with pytest.raises(VerificationError) as excinfo:
        parse_verification(data)
    return excinfo.value.code


def test_valid_input_parses_into_immutable_typed_records():
    config = parse_verification(good())
    assert config.trust_anchors == frozenset({"anchor-1", "anchor-2"})
    [result] = config.results
    assert (result.doc_id, result.verified, result.trust_anchor_id) == (DOC, True, "anchor-1")
    assert (result.verifier_name, result.verifier_version) == ("external-verifier", "2.1")
    assert result.established_coverage == ("#/components", "#/metadata")  # sorted and de-duplicated
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.verified = False
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.results = ()


def test_lookup_is_by_exact_document_id():
    config = parse_verification(good())
    assert config.result_for(DOC) is not None
    for near in (DOC.upper(), DOC + " ", " " + DOC, DOC[:-1], DOC.replace("cyclonedx:", "")):
        assert config.result_for(near) is None


def test_null_coverage_is_not_an_empty_verified_coverage():
    data = good()
    data["results"][0]["established_coverage"] = None
    assert parse_verification(data).results[0].established_coverage is None
    data["results"][0]["established_coverage"] = []
    assert parse_verification(data).results[0].established_coverage == ()


def test_results_are_optional_and_anchors_are_required():
    data = good()
    del data["results"]
    assert parse_verification(data).results == ()
    data = good()
    del data["trust_anchors"]
    assert code_of(data) is E.MISSING_FIELD


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda d: d.pop("schema_version"), E.MISSING_FIELD),
        (lambda d: d.update(schema_version="2"), E.SCHEMA_VERSION_UNSUPPORTED),
        (lambda d: d.update(schema_version=1), E.INVALID_TYPE),
        (lambda d: d.update(extra=1), E.UNKNOWN_FIELD),
        (lambda d: d["results"][0].update(extra=1), E.UNKNOWN_FIELD),
        (lambda d: d["results"][0]["verifier"].update(extra=1), E.UNKNOWN_FIELD),
        (lambda d: d["results"][0].pop("verified"), E.MISSING_FIELD),
        (lambda d: d["results"][0].update(verified="yes"), E.INVALID_TYPE),
        (lambda d: d["results"][0].update(verified=1), E.INVALID_TYPE),
        (lambda d: d["results"][0].pop("established_coverage"), E.MISSING_FIELD),
        (lambda d: d["results"][0].update(established_coverage="#/components"), E.INVALID_TYPE),
        (lambda d: d["results"][0].update(established_coverage=["components"]), E.COVERAGE_MALFORMED),
        (lambda d: d["results"][0].update(established_coverage=[5]), E.COVERAGE_MALFORMED),
        (lambda d: d["results"][0].update(established_coverage=["#components"]), E.COVERAGE_MALFORMED),
        (lambda d: d["results"][0].update(doc_id=""), E.INVALID_VALUE),
        (lambda d: d["results"][0].update(trust_anchor_id="  "), E.INVALID_VALUE),
        (lambda d: d["results"][0]["verifier"].update(name=""), E.INVALID_VALUE),
        (lambda d: d["results"][0].pop("verifier"), E.MISSING_FIELD),
        (lambda d: d["results"][0]["verifier"].pop("version"), E.MISSING_FIELD),
        (lambda d: d.update(trust_anchors="anchor"), E.INVALID_TYPE),
        (lambda d: d.update(trust_anchors=[""]), E.INVALID_VALUE),
        (lambda d: d.update(results={}), E.INVALID_TYPE),
        (lambda d: d["results"].append(copy.deepcopy(d["results"][0])), E.DUPLICATE_RESULT),
    ],
)
def test_malformed_data_is_rejected_with_a_stable_code(mutate, code):
    data = good()
    mutate(data)
    assert code_of(data) is code


def test_top_level_must_be_an_object():
    assert code_of([]) is E.INVALID_TYPE


def test_typed_records_validate_themselves():
    with pytest.raises(VerificationError):
        VerificationResult(DOC, "true", "a", "v", "1")  # type: ignore[arg-type]
    with pytest.raises(VerificationError):
        VerificationResult("", True, "a", "v", "1")
    with pytest.raises(VerificationError):
        VerificationResult(DOC, True, "a", "v", "1", established_coverage=["#/x"])  # type: ignore[arg-type]
    with pytest.raises(VerificationError):
        VerificationConfig({"a"})  # type: ignore[arg-type]
    result = VerificationResult(DOC, True, "a", "v", "1", ("#/x",))
    with pytest.raises(VerificationError) as excinfo:
        VerificationConfig(frozenset({"a"}), (result, result))
    assert excinfo.value.code is E.DUPLICATE_RESULT


def test_load_from_bytes_and_path_and_malformed_json(tmp_path):
    raw = json.dumps(good()).encode()
    assert load_verification(raw) == parse_verification(good())
    path = tmp_path / "verification.json"
    path.write_bytes(raw)
    assert load_verification(path) == load_verification(str(path)) == parse_verification(good())
    for bad in (b"not json", b"[]", b'{"a": 1, "a": 2}', b'{"schema_version": NaN}', b"\xff"):
        with pytest.raises(VerificationError) as excinfo:
            load_verification(bad)
        assert excinfo.value.code is E.MALFORMED_JSON


def test_parsing_is_pure_deterministic_and_order_independent():
    data = good()
    second = copy.deepcopy(data["results"][0])
    second["doc_id"] = "spdx:sha256:" + "cd" * 32
    data["results"].append(second)
    snapshot = copy.deepcopy(data)
    first = parse_verification(data)
    assert data == snapshot
    reordered = copy.deepcopy(data)
    reordered["results"].reverse()
    reordered["trust_anchors"].reverse()
    assert parse_verification(reordered) == first


def test_the_module_performs_no_cryptography_and_reads_no_document_or_profile():
    import ast
    import evidence.verification as module

    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"__future__", "dataclasses", "enum", "typing", "evidence.provenance",
                        "sbom_parser._common", "sbom_parser.errors"}
    assert not {n.module for n in ast.walk(tree) if isinstance(n, ast.Import)} & {"hashlib", "hmac", "ssl", "cryptography"}


def test_a_config_rejects_results_that_are_not_verification_results():
    from evidence.verification import VerificationConfig, VerificationError, VerificationErrorCode
    for bad in ([object()], ({"doc_id": "d"},), "x", ["d"]):
        with pytest.raises(VerificationError) as error:
            VerificationConfig(frozenset({"a"}), bad)  # type: ignore[arg-type]
        assert error.value.code is VerificationErrorCode.INVALID_TYPE
