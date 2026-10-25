"""Stage 1 tests for sbom_parser.spdx.

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
from sbom_parser import spdx
from sbom_parser.errors import InvalidDocumentError, MalformedInputError, UnsupportedVersionError
from sbom_parser.identifiers import VARIANT_NORMALIZATION_VERSION
from sbom_parser.spdx import parse_spdx

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "spdx"
FIXTURE = FIXTURES / "no_completeness.json"
HASH_UPPER = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def encode(obj):
    return json.dumps(obj).encode("utf-8")


def meta(document, key):
    return json.loads(document.declared_metadata[key])


# ---- supported versions -------------------------------------------------------------

def test_supported_version_is_exactly_spdx_2_3():
    assert spdx.SUPPORTED_SPDX_VERSIONS == ("SPDX-2.3",)


@pytest.mark.parametrize("version", ["SPDX-2.2", "SPDX-2.1", "SPDX-3.0", "SPDX-2.3.1", "SPDX-"])
def test_unsupported_spdx_versions_are_rejected_explicitly(version):
    data = load()
    data["spdxVersion"] = version
    with pytest.raises(UnsupportedVersionError) as caught:
        parse_spdx(encode(data))
    assert caught.value.locator == "#/spdxVersion"


def test_spdx_3_json_ld_is_reported_as_unsupported_not_invalid():
    raw = encode({"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld", "@graph": []})
    with pytest.raises(UnsupportedVersionError):
        parse_spdx(raw)


def test_a_non_spdx_version_string_is_an_invalid_document():
    data = load()
    data["spdxVersion"] = "2.3"
    with pytest.raises(InvalidDocumentError):
        parse_spdx(encode(data))


def test_fixture_is_accepted_and_version_recorded():
    document, _ = parse_spdx(FIXTURE)
    assert document.declared_metadata["spec_version"] == "SPDX-2.3"
    assert document.declared_metadata["format"] == "SPDX"


# ---- input forms and determinism ----------------------------------------------------

def test_bytes_str_path_and_pathlib_inputs_give_identical_results():
    from_bytes = parse_spdx(FIXTURE.read_bytes())
    assert parse_spdx(str(FIXTURE)) == from_bytes
    assert parse_spdx(FIXTURE) == from_bytes


def test_parsing_is_deterministic():
    assert parse_spdx(FIXTURE) == parse_spdx(FIXTURE)


def test_missing_file_is_not_swallowed():
    with pytest.raises(FileNotFoundError):
        parse_spdx(FIXTURES / "does_not_exist.json")


# ---- SourceDocument metadata --------------------------------------------------------

def test_source_document_metadata_is_extracted():
    document, _ = parse_spdx(FIXTURE)
    assert document.doc_id.startswith("spdx:sha256:")
    assert document.created == datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
    assert document.declared_metadata["created_raw"] == "2026-01-15T10:00:00Z"
    assert (document.tool_name, document.tool_version) == ("example-spdx-tool", "1.4.0")
    assert (document.producer_class, document.producer) == ("Organization", "Example Org")
    assert meta(document, "creators") == ["Tool: example-spdx-tool-1.4.0", "Organization: Example Org"]
    assert document.declared_metadata["document_namespace"] == "https://example.com/spdx/example-sbom-1"
    assert document.declared_metadata["license_list_version"] == "3.21"
    assert meta(document, "document_describes") == ["SPDXRef-app"]


def test_fields_spdx_does_not_state_are_not_inferred():
    document, _ = parse_spdx(FIXTURE)
    assert document.generation_context is None
    assert document.method is None
    assert document.integrity == model.Integrity()  # no document signature in SPDX 2.3 JSON
    assert document.integrity.signature_verified is None
    assert document.declared_metadata["assertion_status"] == "self_asserted_unverified"


def test_tool_text_is_split_only_at_a_version_looking_suffix():
    data = load()
    data["creationInfo"]["creators"] = ["Tool: my-tool"]
    document, _ = parse_spdx(encode(data))
    assert (document.tool_name, document.tool_version) == ("my-tool", None)  # no digit after last '-'


def test_ambiguous_creators_are_not_guessed_but_are_preserved():
    data = load()
    data["creationInfo"]["creators"] = ["Tool: a-1.0", "Tool: b-2.0", "Organization: O1", "Person: P1"]
    document, _ = parse_spdx(encode(data))
    assert (document.tool_name, document.tool_version) == (None, None)
    assert (document.producer, document.producer_class) == (None, None)
    assert len(meta(document, "creators")) == 4


# ---- packages and identifier preservation -------------------------------------------

def test_packages_become_components_in_document_order():
    _, components = parse_spdx(FIXTURE)
    assert [c.name for c in components] == ["example-app", "Left-Pad", "Plain-Lib"]
    assert [c.bom_ref for c in components] == ["SPDXRef-app", "SPDXRef-lib1", "SPDXRef-lib2"]


def test_original_identifiers_are_preserved_exactly():
    _, (_, left_pad, plain) = parse_spdx(FIXTURE)
    assert left_pad.purl == "pkg:NPM/Left-Pad@1.3.0"  # first purl, case untouched
    assert left_pad.cpe == ["cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"]
    assert left_pad.hashes == [model.Hash("SHA256", HASH_UPPER)]
    assert (left_pad.name, left_pad.version) == ("Left-Pad", "1.3.0")
    assert plain.purl is None and plain.cpe == [] and plain.hashes == []


def test_supplier_is_unwrapped_and_noassertion_is_not_a_supplier():
    _, (app, left_pad, plain) = parse_spdx(FIXTURE)
    assert app.supplier == "Example Org"
    assert left_pad.supplier is None and plain.supplier is None
    document, _ = parse_spdx(FIXTURE)
    index = meta(document, "component_index")
    assert index[0]["supplier_raw"] == "Organization: Example Org"
    assert index[1]["supplier_raw"] == "NOASSERTION"  # raw value kept for audit


def test_variants_are_versioned_deterministic_and_do_not_overwrite_originals():
    _, (_, left_pad, plain) = parse_spdx(FIXTURE)
    assert [(v.kind, v.value) for v in left_pad.identifier_variants] == [
        ("purl", "pkg:npm/Left-Pad@1.3.0"),
        ("cpe", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
        ("name+version", "left-pad@1.3.0"),
        ("hash:sha256", HASH_UPPER.lower()),
    ]
    assert [(v.kind, v.value) for v in plain.identifier_variants] == [("name+version", "plain-lib@2.1.0")]
    assert {v.normalization_rule_version for v in left_pad.identifier_variants} == {
        VARIANT_NORMALIZATION_VERSION
    }


def test_extra_purls_and_unextracted_package_content_are_reported_not_dropped():
    document, _ = parse_spdx(FIXTURE)
    index = meta(document, "component_index")
    assert index[1]["additional_purls"] == ["pkg:npm/left-pad@1.3.0"]  # not merged with the first
    assert index[1]["unextracted_external_refs"] == [
        {"locator": "#/packages/1/externalRefs/3", "reference_type": "advisory"}
    ]
    assert index[0]["unextracted_keys"] == ["downloadLocation", "filesAnalyzed"]
    assert index[0]["locator"] == "#/packages/0"


def test_unextracted_top_level_sections_are_listed():
    document, _ = parse_spdx(FIXTURE)
    assert meta(document, "unextracted_top_level_fields") == ["files"]


# ---- relationships are declarations, not call edges ---------------------------------

def test_relationships_are_preserved_raw_with_direction_unnormalised():
    document, _ = parse_spdx(FIXTURE)
    relationships = meta(document, "declared_relationships")
    assert [(r["source"], r["raw_relationship"], r["target"]) for r in relationships] == [
        ("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-app"),
        ("SPDXRef-app", "DEPENDS_ON", "SPDXRef-lib1"),
        ("SPDXRef-lib2", "DEPENDENCY_OF", "SPDXRef-app"),  # kept as written, not reversed
    ]
    assert {r["edge_type"] for r in relationships} == {"declared_relationship"}
    assert relationships[1]["locator"] == "#/relationships/1"


def test_relationships_are_never_labelled_as_call_or_reachability_information():
    document, _ = parse_spdx(FIXTURE)
    assert not [k for k in document.declared_metadata if "call" in k or "reach" in k or "execut" in k]
    for relationship in meta(document, "declared_relationships"):
        assert not any(w in relationship["edge_type"] for w in ("call", "reach", "execut"))


# ---- completeness: none is invented -------------------------------------------------

def test_no_completeness_declaration_is_invented_for_spdx():
    document, _ = parse_spdx(FIXTURE)
    assert meta(document, "composition_records") == []  # later stages read this as Unknown


def test_missing_package_or_relationship_is_not_turned_into_any_claim():
    data = load()
    data["packages"] = data["packages"][:1]
    data["relationships"] = []
    document, components = parse_spdx(encode(data))
    assert [c.name for c in components] == ["example-app"]
    assert meta(document, "declared_relationships") == []
    assert meta(document, "composition_records") == []
    assert not [k for k in document.declared_metadata if "absent" in k or "complete" in k]


# ---- malformed input ----------------------------------------------------------------

def test_malformed_json_fixture_is_rejected():
    with pytest.raises(MalformedInputError):
        parse_spdx(FIXTURES / "malformed.json")


@pytest.mark.parametrize(
    "raw",
    [b"", b"[]", b"42", b"\xff\xfe", b'{"SPDXID": 1, "SPDXID": 2}', b'{"x": Infinity}'],
)
def test_malformed_inputs_raise_instead_of_returning_empty_results(raw):
    with pytest.raises(MalformedInputError):
        parse_spdx(raw)


# ---- structurally invalid documents -------------------------------------------------

def _mutated(mutator):
    data = copy.deepcopy(load())
    mutator(data)
    return encode(data)


@pytest.mark.parametrize(
    "mutator, locator",
    [
        (lambda d: d.pop("spdxVersion"), "#"),
        (lambda d: d.pop("SPDXID"), "#"),
        (lambda d: d.pop("name"), "#"),
        (lambda d: d.pop("documentNamespace"), "#"),
        (lambda d: d.pop("dataLicense"), "#"),
        (lambda d: d.pop("creationInfo"), "#"),
        (lambda d: d["creationInfo"].pop("created"), "#/creationInfo"),
        (lambda d: d["creationInfo"].pop("creators"), "#/creationInfo"),
        (lambda d: d["creationInfo"].update(creators="Tool: x"), "#/creationInfo/creators"),
        (lambda d: d["creationInfo"].update(created="yesterday"), "#/creationInfo/created"),
        (lambda d: d.update(packages={}), "#/packages"),
        (lambda d: d["packages"].append(7), "#/packages/3"),
        (lambda d: d["packages"][0].pop("name"), "#/packages/0"),
        (lambda d: d["packages"][0].pop("SPDXID"), "#/packages/0"),
        (lambda d: d["packages"][1]["checksums"][0].pop("algorithm"), "#/packages/1/checksums/0"),
        (lambda d: d["packages"][1]["externalRefs"][0].pop("referenceLocator"), "#/packages/1/externalRefs/0"),
        (lambda d: d["relationships"][0].pop("relationshipType"), "#/relationships/0"),
        (lambda d: d["relationships"][1].update(relatedSpdxElement=3), "#/relationships/1/relatedSpdxElement"),
    ],
)
def test_structurally_invalid_documents_raise_with_a_locator(mutator, locator):
    with pytest.raises(InvalidDocumentError) as caught:
        parse_spdx(_mutated(mutator))
    assert caught.value.locator == locator
