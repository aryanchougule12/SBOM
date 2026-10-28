"""Tests for the additive profile schema "1.1" (explicit target placement).

Schema "1" behaviour is pinned by tests/test_profile.py and must not change.
"""

import copy

import pytest

from evidence.profile import ProfileError, ProfileErrorCode as E, WouldBeLocation, parse_profile

DIGEST = "sha256:" + "ab" * 32


def good(version="1.1", location=None):
    data = {
        "schema_version": version,
        "profile_id": "p",
        "scope": {"product_id": "pkg:generic/app", "version": "1.0", "artifact_kind": "container"},
        "target": {"component": {"name": "libfoo", "purl": "pkg:generic/libfoo@1"}},
        "documents": [{"doc_id": "sbom-a", "role": "primary_sbom"}],
    }
    if location is not None:
        data["target"]["would_be_location"] = location
    return data


def code_of(data):
    with pytest.raises(ProfileError) as excinfo:
        parse_profile(data)
    return excinfo.value.code


def test_nested_placement_names_its_direct_parent():
    profile = parse_profile(good(location={"document": "sbom-a", "placement": "nested_under_component", "parent_ref": "lib-a"}))
    assert profile.schema_version == "1.1"
    assert profile.target.would_be_location == WouldBeLocation("sbom-a", "lib-a", "nested_under_component")


def test_top_level_placement_has_no_parent():
    profile = parse_profile(good(location={"document": "sbom-a", "placement": "top_level"}))
    assert profile.target.would_be_location == WouldBeLocation("sbom-a", None, "top_level")


def test_a_top_level_placement_cannot_be_expressed_by_naming_a_root():
    location = {"document": "sbom-a", "placement": "top_level", "parent_ref": "app-1"}
    assert code_of(good(location=location)) is E.PARENT_REF_FORBIDDEN


def test_a_nested_placement_must_name_a_parent():
    assert code_of(good(location={"document": "sbom-a", "placement": "nested_under_component"})) is E.PARENT_REF_REQUIRED
    for blank in ("", "  "):
        location = {"document": "sbom-a", "placement": "nested_under_component", "parent_ref": blank}
        assert code_of(good(location=location)) is E.INVALID_VALUE
    location = {"document": "sbom-a", "placement": "nested_under_component", "parent_ref": 5}
    assert code_of(good(location=location)) is E.INVALID_TYPE


def test_placement_is_required_and_validated_in_schema_1_1():
    assert code_of(good(location={"document": "sbom-a", "parent_ref": "lib-a"})) is E.PLACEMENT_REQUIRED
    for bad in ("TOP_LEVEL", "top-level", "root", "nested", ""):
        assert code_of(good(location={"document": "sbom-a", "placement": bad})) is E.PLACEMENT_INVALID
    assert code_of(good(location={"document": "sbom-a", "placement": None})) is E.INVALID_TYPE
    assert code_of(good(location={"document": "sbom-a", "placement": 1})) is E.INVALID_TYPE


def test_location_document_must_still_be_a_listed_document_and_fields_are_strict():
    location = {"document": "elsewhere", "placement": "top_level"}
    assert code_of(good(location=location)) is E.LOCATION_DOCUMENT_UNKNOWN
    location = {"document": "sbom-a", "placement": "top_level", "surprise": 1}
    assert code_of(good(location=location)) is E.UNKNOWN_FIELD
    assert code_of(good(location={"placement": "top_level"})) is E.MISSING_FIELD


def test_schema_1_is_unchanged_and_does_not_accept_placement():
    old = parse_profile(good("1", {"document": "sbom-a", "parent_ref": "lib-a"}))
    assert old.schema_version == "1"
    assert old.target.would_be_location == WouldBeLocation("sbom-a", "lib-a", None)  # unspecified placement
    assert code_of(good("1", {"document": "sbom-a", "parent_ref": "lib-a", "placement": "top_level"})) is E.UNKNOWN_FIELD
    assert code_of(good("1", {"document": "sbom-a"})) is E.MISSING_FIELD  # parent_ref is required in schema 1


@pytest.mark.parametrize("version", ["2", "1.0", "1.2", "01", 1.1, None])
def test_other_schema_versions_remain_unsupported(version):
    data = good()
    data["schema_version"] = version
    assert code_of(data) in (E.SCHEMA_VERSION_UNSUPPORTED, E.INVALID_TYPE)
    if isinstance(version, str):
        assert code_of(data) is E.SCHEMA_VERSION_UNSUPPORTED


def test_the_location_block_is_optional_in_schema_1_1_and_inputs_are_not_mutated():
    data = good()
    assert parse_profile(data).target.would_be_location is None
    data = good(location={"document": "sbom-a", "placement": "top_level"})
    snapshot = copy.deepcopy(data)
    parse_profile(data)
    assert data == snapshot


def test_profile_still_cannot_supply_states_levels_or_verdicts_in_schema_1_1():
    data = good(location={"document": "sbom-a", "placement": "top_level"})
    data["target"]["would_be_location"]["state"] = "Present"
    assert code_of(data) is E.FORBIDDEN_FIELD
    data = good()
    data["verdict"] = "Supported"
    assert code_of(data) is E.FORBIDDEN_FIELD
    data = good()
    data["generation_assertions"] = []  # deferred (D10): not part of this schema
    assert code_of(data) is E.UNKNOWN_FIELD
