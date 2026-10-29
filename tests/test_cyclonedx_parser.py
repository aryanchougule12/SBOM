"""Stage 1 tests for sbom_parser.cyclonedx.

Parsing only: these tests check extraction and preservation of what a document states.
They assert no predicate result, evidence sufficiency, aggregation, reachability or
verdict. Everything is offline and deterministic (hand-authored fixtures).
"""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import model
from sbom_parser import cyclonedx
from sbom_parser.cyclonedx import map_composition_aggregate, parse_cyclonedx
from sbom_parser.errors import (
    InvalidDocumentError,
    MalformedInputError,
    ParserError,
    UnsupportedVersionError,
)
from sbom_parser.identifiers import VARIANT_NORMALIZATION_VERSION

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "cyclonedx"
COMPLETE = FIXTURES / "complete_composition.json"
HASH_UPPER = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def encode(obj):
    return json.dumps(obj).encode("utf-8")


def meta(document, key):
    return json.loads(document.declared_metadata[key])


def covers(coverage, locator):
    """Does a declared signed-coverage list contain ``locator`` (or an ancestor)?"""
    return any(c == "#" or locator == c or locator.startswith(c + "/") for c in coverage)


# ---- supported versions -------------------------------------------------------------

def test_supported_versions_are_exactly_1_5_1_6_and_1_7():
    assert cyclonedx.SUPPORTED_SPEC_VERSIONS == ("1.5", "1.6", "1.7")


@pytest.mark.parametrize("version", ["1.0", "1.3", "1.4", "1.8", "2.0", "1.6.1", "1.7.0", ""])
def test_unsupported_spec_versions_are_rejected_explicitly(version):
    data = load("complete_composition.json")
    data["specVersion"] = version
    with pytest.raises(UnsupportedVersionError) as caught:
        parse_cyclonedx(encode(data))
    assert caught.value.locator == "#/specVersion"


def test_version_1_5_fixture_is_accepted_and_reads_the_legacy_tools_array():
    document, components = parse_cyclonedx(FIXTURES / "spec_1_5.json")
    assert document.declared_metadata["spec_version"] == "1.5"
    assert (document.tool_name, document.tool_version) == ("legacy-tool", "0.9")
    assert [c.name for c in components] == ["v15-lib"]


def test_version_1_6_fixture_is_accepted():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.declared_metadata["spec_version"] == "1.6"
    assert document.declared_metadata["format"] == "CycloneDX"


# ---- input forms --------------------------------------------------------------------

def test_bytes_str_path_and_pathlib_inputs_give_identical_results():
    raw = COMPLETE.read_bytes()
    from_bytes = parse_cyclonedx(raw)
    assert parse_cyclonedx(str(COMPLETE)) == from_bytes
    assert parse_cyclonedx(COMPLETE) == from_bytes


def test_parsing_is_deterministic():
    assert parse_cyclonedx(COMPLETE) == parse_cyclonedx(COMPLETE)


def test_missing_file_is_not_swallowed():
    with pytest.raises(FileNotFoundError):
        parse_cyclonedx(FIXTURES / "does_not_exist.json")


def test_unsupported_source_type_is_a_type_error():
    with pytest.raises(TypeError):
        parse_cyclonedx(12345)  # type: ignore[arg-type]


def test_document_id_is_derived_from_the_exact_input_bytes():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.doc_id.startswith("cyclonedx:sha256:")
    changed = COMPLETE.read_bytes() + b"\n"
    assert parse_cyclonedx(changed)[0].doc_id != document.doc_id


# ---- SourceDocument metadata --------------------------------------------------------

def test_source_document_metadata_is_extracted_from_the_document():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.created == datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
    assert document.declared_metadata["created_raw"] == "2026-01-15T10:00:00Z"
    assert (document.tool_name, document.tool_version) == ("example-sbom-tool", "1.2.3")
    assert document.producer == "Example Build Team"
    assert document.generation_context == "build"
    assert document.declared_metadata["serial_number"].startswith("urn:uuid:")
    assert document.declared_metadata["bom_version"] == "1"


def test_fields_the_format_does_not_state_are_not_inferred():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.method is None  # never inferred from tool or lifecycle
    assert document.producer_class is None
    assert document.integrity.artifact_digest_binding is None  # subject hashes only preserved
    metadata = meta(document, "metadata")
    assert metadata["component"]["hashes"][0]["content"] == HASH_UPPER  # preserved verbatim


def test_metadata_is_left_unset_when_the_document_has_none():
    document, _ = parse_cyclonedx(FIXTURES / "no_compositions.json")
    assert document.created is None
    assert (document.tool_name, document.tool_version, document.producer) == (None, None, None)
    assert document.generation_context is None


def test_ambiguous_metadata_is_not_guessed_but_is_preserved():
    data = load("complete_composition.json")
    data["metadata"]["tools"] = {
        "components": [
            {"type": "application", "name": "tool-a", "version": "1"},
            {"type": "application", "name": "tool-b", "version": "2"},
        ]
    }
    data["metadata"]["authors"] = [{"name": "A"}, {"name": "B"}]
    data["metadata"]["lifecycles"] = [{"phase": "build"}, {"phase": "operations"}]
    document, _ = parse_cyclonedx(encode(data))
    assert (document.tool_name, document.tool_version) == (None, None)
    assert document.producer is None
    assert document.generation_context is None
    assert [t["name"] for t in meta(document, "tools")] == ["tool-a", "tool-b"]
    assert [a["name"] for a in meta(document, "authors")] == ["A", "B"]
    assert [l["phase"] for l in meta(document, "lifecycles")] == ["build", "operations"]


def test_lifecycle_phase_is_kept_raw_and_not_mapped_to_the_spec_vocabulary():
    data = load("complete_composition.json")
    data["metadata"]["lifecycles"] = [{"phase": "post-build"}]
    document, _ = parse_cyclonedx(encode(data))
    assert document.generation_context == "post-build"


def test_everything_parsed_is_marked_as_an_unverified_self_assertion():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.declared_metadata["assertion_status"] == "self_asserted_unverified"
    assert document.integrity.signature_verified is None


# ---- components and identifier preservation -----------------------------------------

def test_components_are_returned_in_document_order_including_nested_ones():
    _, components = parse_cyclonedx(COMPLETE)
    assert [c.name for c in components] == ["Left-Pad", "nested-lib", "Example Product", "Plain-Lib"]
    assert [c.bom_ref for c in components] == ["lib-purl", "lib-nested", "lib-cpe", "lib-name"]


def test_component_index_records_locators_nesting_and_unextracted_keys():
    document, _ = parse_cyclonedx(COMPLETE)
    index = meta(document, "component_index")
    assert [e["locator"] for e in index] == [
        "#/components/0", "#/components/0/components/0", "#/components/1", "#/components/2",
    ]
    assert index[0]["unextracted_keys"] == ["licenses"]  # reported, not silently dropped
    assert index[0]["type"] == "library"


def test_original_identifiers_are_preserved_exactly():
    _, components = parse_cyclonedx(COMPLETE)
    left_pad, _, example, _ = components
    assert left_pad.purl == "pkg:NPM/Left-Pad@1.3.0"  # mixed case kept
    assert left_pad.name == "Left-Pad" and left_pad.version == "1.3.0"
    assert left_pad.hashes == [model.Hash("SHA-256", HASH_UPPER)]  # upper-case hex kept
    assert left_pad.supplier == "Example Supplier"
    assert example.cpe == ["cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"]
    assert example.purl is None


def test_variants_are_versioned_deterministic_and_do_not_overwrite_originals():
    _, components = parse_cyclonedx(COMPLETE)
    left_pad, _, example, plain = components
    assert [(v.kind, v.value) for v in left_pad.identifier_variants] == [
        ("purl", "pkg:npm/Left-Pad@1.3.0"),  # scheme/type lower-cased only
        ("name+version", "left-pad@1.3.0"),
        ("hash:sha256", HASH_UPPER.lower()),
    ]
    assert [(v.kind, v.value) for v in example.identifier_variants] == [
        ("cpe", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
        ("name+version", "example product@1.0"),
    ]
    assert [(v.kind, v.value) for v in plain.identifier_variants] == [("name+version", "plain-lib@2.1.0")]
    for component in components:
        assert {v.normalization_rule_version for v in component.identifier_variants} == {
            VARIANT_NORMALIZATION_VERSION
        }
    assert VARIANT_NORMALIZATION_VERSION == "variant-norm-v1"


def test_resembling_identifiers_are_never_merged_or_declared_equivalent():
    data = load("no_compositions.json")
    data["components"] = [
        {"type": "library", "name": "Left-Pad", "version": "1.3.0", "purl": "pkg:npm/Left-Pad@1.3.0"},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:NPM/Left-Pad@1.3.0"},
    ]
    _, components = parse_cyclonedx(encode(data))
    assert len(components) == 2  # not deduplicated, not merged
    assert components[0].purl != components[1].purl  # originals untouched
    assert components[0].identifier_variants[1] == components[1].identifier_variants[1]  # same derived key
    assert components[0] != components[1]


def test_ecosystem_is_not_inferred():
    _, components = parse_cyclonedx(FIXTURES / "spec_1_5.json")
    assert components[0].purl == "pkg:pypi/v15-lib@1.5.0"
    assert components[0].ecosystem is None


# ---- dependency edges are declarations, not call edges ------------------------------

def test_declared_dependency_edges_are_preserved_with_their_type():
    document, _ = parse_cyclonedx(COMPLETE)
    edges = meta(document, "declared_dependency_edges")
    assert [(e["source"], e["target"]) for e in edges] == [
        ("app-1", "lib-purl"), ("app-1", "lib-cpe"), ("lib-purl", "lib-nested"),
    ]
    assert {e["edge_type"] for e in edges} == {"declared_dependency"}
    assert {e["raw_relationship"] for e in edges} == {"dependsOn"}
    assert edges[0]["locator"] == "#/dependencies/0/dependsOn/0"


def test_dependency_edges_are_never_labelled_as_call_or_reachability_information():
    document, _ = parse_cyclonedx(COMPLETE)
    assert not [k for k in document.declared_metadata if "call" in k or "reach" in k or "execut" in k]
    for edge in meta(document, "declared_dependency_edges"):
        assert not any(word in json.dumps(edge).lower() for word in ("call", "reach", "execut"))


def test_an_explicitly_empty_dependson_is_distinguished_from_an_absent_one():
    data = load("complete_composition.json")
    data["dependencies"].append({"ref": "lib-cpe"})
    document, _ = parse_cyclonedx(encode(data))
    nodes = {n["locator"]: n for n in meta(document, "declared_dependency_nodes")}
    assert nodes["#/dependencies/2"]["depends_on_declared"] is True  # []
    assert nodes["#/dependencies/3"]["depends_on_declared"] is False  # key absent
    assert not [e for e in meta(document, "declared_dependency_edges") if e["source"] == "lib-name"]


# ---- composition / completeness -----------------------------------------------------

@pytest.mark.parametrize(
    "aggregate, state, recognized",
    [
        ("complete", model.EvidenceState.PRESENT, True),
        ("incomplete", model.EvidenceState.INCOMPLETE, True),
        ("incomplete_first_party_only", model.EvidenceState.INCOMPLETE, True),
        ("incomplete_third_party_only", model.EvidenceState.INCOMPLETE, True),
        ("incomplete_first_party_opensource_only", model.EvidenceState.INCOMPLETE, True),
        ("unknown", model.EvidenceState.UNKNOWN, True),
        ("not_specified", model.EvidenceState.UNKNOWN, True),
        ("Complete", model.EvidenceState.UNKNOWN, False),  # case-sensitive
        ("", model.EvidenceState.UNKNOWN, False),
        ("mostly_complete", model.EvidenceState.UNKNOWN, False),
    ],
)
def test_aggregate_mapping_follows_spec_4_1(aggregate, state, recognized):
    assert map_composition_aggregate(aggregate) == (state, recognized)


def test_complete_composition_is_preserved_with_its_locator_and_scope():
    document, _ = parse_cyclonedx(COMPLETE)
    [record] = meta(document, "composition_records")
    assert record["state"] == "Present"
    assert record["aggregate_raw"] == "complete"
    assert record["aggregate_recognized"] is True
    assert record["locator"] == "#/compositions/0"
    assert record["assemblies"] == ["lib-purl", "lib-cpe", "lib-name"]
    assert record["dependencies"] == ["app-1"]
    assert record["scope_declared"] is True


def test_incomplete_and_complete_compositions_are_kept_separate_not_merged():
    document, _ = parse_cyclonedx(FIXTURES / "incomplete_composition.json")
    first, second = meta(document, "composition_records")
    assert (first["aggregate_raw"], first["state"], first["assemblies"]) == (
        "incomplete_first_party_only", "Incomplete", ["comp-a"])
    assert (second["aggregate_raw"], second["state"], second["assemblies"]) == (
        "complete", "Present", ["comp-b"])
    assert second["bom_ref"] == "comp-record-2"
    assert first["locator"] != second["locator"]


def test_unknown_and_not_specified_map_to_unknown_without_promotion():
    document, _ = parse_cyclonedx(FIXTURES / "unknown_composition.json")
    first, second = meta(document, "composition_records")
    assert (first["aggregate_raw"], first["state"], first["scope_declared"]) == ("unknown", "Unknown", False)
    assert (second["aggregate_raw"], second["state"], second["scope_declared"]) == ("not_specified", "Unknown", True)


def test_absent_compositions_yield_no_records():
    document, _ = parse_cyclonedx(FIXTURES / "no_compositions.json")
    assert meta(document, "composition_records") == []


def test_unrecognized_aggregate_is_unknown_and_flagged_not_rejected():
    data = load("complete_composition.json")
    data["compositions"][0]["aggregate"] = "totally_new_value"
    document, _ = parse_cyclonedx(encode(data))
    [record] = meta(document, "composition_records")
    assert (record["state"], record["aggregate_recognized"], record["aggregate_raw"]) == (
        "Unknown", False, "totally_new_value")


def test_a_composition_without_scope_is_not_promoted_to_document_wide_completeness():
    document, _ = parse_cyclonedx(FIXTURES / "unknown_composition.json")
    records = meta(document, "composition_records")
    assert records[0]["scope_declared"] is False
    assert not any("document" in key or "global" in key for key in document.declared_metadata)


def test_composition_states_are_six_state_values_not_booleans():
    valid = {s.value for s in model.EvidenceState}
    for name in ("complete_composition", "incomplete_composition", "unknown_composition"):
        document, _ = parse_cyclonedx(FIXTURES / f"{name}.json")
        for record in meta(document, "composition_records"):
            assert isinstance(record["state"], str) and record["state"] in valid


# ---- signatures: claims only --------------------------------------------------------

def test_unsigned_document_has_default_integrity_and_no_signature_records():
    document, _ = parse_cyclonedx(COMPLETE)
    assert document.integrity == model.Integrity()
    assert meta(document, "signature_records") == []
    assert "signature_verification" not in document.declared_metadata


def test_root_signature_is_recorded_as_an_unverified_claim_covering_the_document():
    document, _ = parse_cyclonedx(FIXTURES / "signed_root.json")
    integrity = document.integrity
    assert integrity.signature_verified is None  # never verified
    assert integrity.trust_anchor_id is None
    assert integrity.signed_coverage == ["#"]
    [entry] = json.loads(integrity.signature)
    assert entry["covers"] == "#"
    assert entry["signature"]["algorithm"] == "RS256"
    assert document.declared_metadata["signature_verification"] == "not_attempted"
    assert document.declared_metadata["signed_coverage_basis"] == "jsf-enveloped-container-object"


def test_component_level_signature_coverage_excludes_other_locators_in_the_document():
    document, _ = parse_cyclonedx(FIXTURES / "signed_component_only.json")
    coverage = document.integrity.signed_coverage
    assert coverage == ["#/components/0"]
    assert document.integrity.signature_verified is None
    assert covers(coverage, "#/components/0/name")
    # Referenced elsewhere in the same document, but outside the declared coverage:
    assert not covers(coverage, "#/compositions/0")
    assert not covers(coverage, "#/components/1")
    assert not covers(coverage, "#/metadata")


def test_signature_with_excludes_does_not_claim_coverage():
    data = load("signed_root.json")
    data["signature"]["excludes"] = ["compositions"]
    document, _ = parse_cyclonedx(encode(data))
    assert document.integrity.signed_coverage == []  # narrower coverage not representable
    [record] = meta(document, "signature_records")
    assert record["coverage_claimed"] is False
    assert record["signature"]["excludes"] == ["compositions"]


def test_every_signature_in_the_document_is_recorded():
    data = load("signed_component_only.json")
    data["signature"] = {"algorithm": "RS256", "value": "cm9vdA"}
    document, _ = parse_cyclonedx(encode(data))
    assert [r["covers"] for r in meta(document, "signature_records")] == ["#", "#/components/0"]
    assert document.integrity.signed_coverage == ["#", "#/components/0"]


# ---- unextracted features are reported ----------------------------------------------

def test_unextracted_top_level_sections_are_listed_not_dropped_silently():
    data = load("complete_composition.json")
    data["services"] = []
    data["vulnerabilities"] = []
    document, _ = parse_cyclonedx(encode(data))
    assert meta(document, "unextracted_top_level_fields") == ["services", "vulnerabilities"]


# ---- malformed input ----------------------------------------------------------------

def test_malformed_json_fixture_is_rejected():
    with pytest.raises(MalformedInputError):
        parse_cyclonedx(FIXTURES / "malformed.json")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"   ",
        b"[]",
        b'"a string"',
        b"\xff\xfe\x00",
        b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}',
        b'{"bomFormat": NaN}',
    ],
)
def test_malformed_inputs_raise_instead_of_returning_empty_results(raw):
    with pytest.raises(MalformedInputError):
        parse_cyclonedx(raw)


def test_all_parser_errors_share_one_base_class():
    for error in (MalformedInputError, UnsupportedVersionError, InvalidDocumentError):
        assert issubclass(error, ParserError)


# ---- structurally invalid documents -------------------------------------------------

def _mutated(mutator):
    data = copy.deepcopy(load("complete_composition.json"))
    mutator(data)
    return encode(data)


@pytest.mark.parametrize(
    "mutator, locator",
    [
        (lambda d: d.pop("bomFormat"), "#/bomFormat"),
        (lambda d: d.update(bomFormat="SPDX"), "#/bomFormat"),
        (lambda d: d.pop("specVersion"), "#"),
        (lambda d: d.update(specVersion=1.6), "#/specVersion"),
        (lambda d: d.update(version="1"), "#/version"),
        (lambda d: d.update(components={}), "#/components"),
        (lambda d: d["components"].append("not-an-object"), "#/components/3"),
        (lambda d: d["components"][0].pop("name"), "#/components/0"),
        (lambda d: d["components"][0].update(version=1), "#/components/0/version"),
        (lambda d: d["components"][0]["hashes"][0].pop("alg"), "#/components/0/hashes/0"),
        (lambda d: d["components"][0]["components"][0].pop("name"), "#/components/0/components/0"),
        (lambda d: d["dependencies"][0].pop("ref"), "#/dependencies/0"),
        (lambda d: d["dependencies"][0].update(dependsOn=["ok", 5]), "#/dependencies/0/dependsOn/1"),
        (lambda d: d["compositions"][0].pop("aggregate"), "#/compositions/0"),
        (lambda d: d["compositions"][0].update(assemblies="lib-purl"), "#/compositions/0/assemblies"),
        (lambda d: d["metadata"].update(timestamp="not-a-date"), "#/metadata/timestamp"),
        (lambda d: d["metadata"].update(tools="x"), "#/metadata/tools"),
        (lambda d: d.update(signature="not-an-object"), "#/signature"),
    ],
)
def test_structurally_invalid_documents_raise_with_a_locator(mutator, locator):
    with pytest.raises(InvalidDocumentError) as caught:
        parse_cyclonedx(_mutated(mutator))
    assert caught.value.locator == locator
    assert locator in str(caught.value) or locator == "#"


# ---- G3a: parsers declare coverage but never establish it --------------------------------

@pytest.mark.parametrize("name", ["signed_root.json", "signed_component_only.json", "complete_composition.json"])
def test_parser_never_verifies_or_establishes_coverage(name):
    integrity = parse_cyclonedx(FIXTURES / name)[0].integrity
    assert integrity.signature_verified is None
    assert integrity.established_coverage is None


def test_multi_signature_document_keeps_declared_union_and_establishes_nothing():
    data = load("signed_component_only.json")
    data["signature"] = {"algorithm": "RS256", "value": "cm9vdA"}
    document = parse_cyclonedx(encode(data))[0]
    assert document.integrity.signed_coverage == ["#", "#/components/0"]
    assert document.integrity.established_coverage is None
    assert document.integrity.signature_verified is None


# ---- G12: subject and defined-reference registry ----------------------------------------

DEFINED = FIXTURES / "defined_refs.json"


def test_subject_comes_from_metadata_component_and_is_not_a_listed_component():
    document, components = parse_cyclonedx(COMPLETE)
    [subject] = document.subjects
    assert subject.ref == "app-1"
    assert subject.locator == "#/metadata/component"
    assert subject.declared_via == "metadata.component"
    assert subject.component.name == "example-app"
    assert subject.listed_as_component is False
    assert "app-1" not in [c.bom_ref for c in components]
    assert document.document_ref is None  # CycloneDX has no document node


def test_no_metadata_component_means_no_subject():
    data = load("complete_composition.json")
    del data["metadata"]["component"]
    document = parse_cyclonedx(encode(data))[0]
    assert document.subjects == []


def test_subject_listed_in_components_is_flagged():
    data = load("complete_composition.json")
    data["components"].append(copy.deepcopy(data["metadata"]["component"]))
    document, components = parse_cyclonedx(encode(data))
    [subject] = document.subjects
    assert subject.listed_as_component is True
    assert "app-1" in [c.bom_ref for c in components]
    # bom-ref must be unique in a CycloneDX document, so the repeat is reported, not resolved
    [conflict] = meta(document, "defined_ref_conflicts")
    assert conflict["ref"] == "app-1"
    assert {conflict["kind"], conflict["conflicts_with_kind"]} == {"subject", "listed_component"}


def test_defined_refs_cover_every_schema_declared_component_or_service_location():
    document, components = parse_cyclonedx(DEFINED)
    assert document.other_defined_refs == {
        "app-ancestor": "pedigree_component",
        "subject-nested": "nested_component",
        "lib-1-variant": "pedigree_component",
        "svc-1": "service",
        "svc-1-nested": "nested_service",
        "tool-1": "tool_component",
        "tool-1-nested": "nested_component",
        "tool-svc": "tool_service",
        "ann-svc": "annotator_service",
        "form-comp": "formulation_component",
        "form-svc": "formulation_service",
        "decl-comp": "declaration_target_component",
        "decl-svc": "declaration_target_service",
    }
    locators = meta(document, "defined_ref_locators")
    assert set(locators) == set(document.other_defined_refs)
    assert locators["svc-1-nested"] == "#/services/0/services/0"
    assert locators["decl-svc"] == "#/declarations/targets/services/0"
    assert locators["subject-nested"] == "#/metadata/component/components/0"


def test_registering_a_ref_does_not_add_inventory():
    document, components = parse_cyclonedx(DEFINED)
    assert [c.bom_ref for c in components] == ["lib-1", "lib-1-child"]
    for ref in document.other_defined_refs:
        assert ref not in [c.bom_ref for c in components]
    assert "app-1" not in document.other_defined_refs  # the subject is not double-registered
    assert "lib-1" not in document.other_defined_refs  # listed components are not re-registered


def test_declarations_are_only_registered_for_spec_1_6():
    data = load("defined_refs.json")
    data["specVersion"] = "1.5"
    document = parse_cyclonedx(encode(data))[0]
    assert "decl-comp" not in document.other_defined_refs
    assert "decl-svc" not in document.other_defined_refs
    assert "svc-1" in document.other_defined_refs


def test_duplicate_bom_ref_is_reported_not_resolved():
    data = load("defined_refs.json")
    data["services"].append({"bom-ref": "lib-1", "name": "clash"})
    document = parse_cyclonedx(encode(data))[0]
    conflicts = meta(document, "defined_ref_conflicts")
    assert [c["ref"] for c in conflicts] == ["lib-1"]
    assert "lib-1" not in document.other_defined_refs  # first definition (the component) wins


def _resolve_endpoint(document, components, ref):
    """Test-local helper (not part of the product): where does a dependency endpoint
    name resolve? Models the intended use of the registry without implementing N4."""
    if any(s.ref == ref for s in document.subjects):
        return "subject"
    if ref in [c.bom_ref for c in components]:
        return "component"
    if ref in document.other_defined_refs:
        return document.other_defined_refs[ref]
    return None


def test_dependency_endpoints_resolve_distinctly_and_missing_stays_unresolved():
    document, components = parse_cyclonedx(DEFINED)
    nodes = meta(document, "declared_dependency_edges")
    targets = {edge["to"] if "to" in edge else edge.get("target") for edge in nodes}
    resolved = {ref: _resolve_endpoint(document, components, ref)
                for ref in ["app-1", "lib-1", "svc-1", "svc-1-nested", "subject-nested", "truly-missing"]}
    assert resolved == {
        "app-1": "subject", "lib-1": "component", "svc-1": "service",
        "svc-1-nested": "nested_service", "subject-nested": "nested_component",
        "truly-missing": None,
    }
    assert "truly-missing" in targets


def test_version_1_7_parses_identically_to_1_6_apart_from_the_version_and_unextracted_citations():
    d16, c16 = parse_cyclonedx(FIXTURES / "complete_composition.json")
    d17, c17 = parse_cyclonedx(FIXTURES / "spec_1_7.json")
    assert [(c.name, c.version, c.purl, c.bom_ref) for c in c17] == [(c.name, c.version, c.purl, c.bom_ref) for c in c16]
    assert d17.declared_metadata["spec_version"] == "1.7"
    assert d17.declared_metadata["composition_records"] == d16.declared_metadata["composition_records"]
    assert json.loads(d17.declared_metadata["unextracted_top_level_fields"]) == ["citations"]


def test_version_1_7_registers_the_declarations_targets_like_1_6():
    data = load("complete_composition.json")
    data["specVersion"] = "1.7"
    data["declarations"] = {"targets": {"components": [{"type": "library", "name": "t", "bom-ref": "decl-target"}]}}
    document, _ = parse_cyclonedx(encode(data))
    assert "decl-target" in document.other_defined_refs


@pytest.mark.parametrize("where", ["components", "nested", "subject"])
def test_a_1_7_component_version_range_is_refused_rather_than_ignored(where):
    data = load("complete_composition.json")
    data["specVersion"] = "1.7"
    ranged = {"type": "library", "name": "ranged-lib", "versionRange": "vers:npm/>=1.0.0|<2.0.0"}
    if where == "components":
        data["components"].append(ranged)
    elif where == "nested":
        data["components"][0].setdefault("components", []).append(ranged)
    else:
        data["metadata"]["component"].update(ranged)
    with pytest.raises(InvalidDocumentError) as caught:
        parse_cyclonedx(encode(data))
    assert caught.value.locator.endswith("/versionRange")


def test_a_version_range_is_refused_in_any_spec_version_since_it_is_never_an_exact_version():
    data = load("complete_composition.json")
    data["components"].append({"type": "library", "name": "x", "version": "1", "versionRange": "irrelevant"})
    with pytest.raises(InvalidDocumentError):
        parse_cyclonedx(encode(data))
