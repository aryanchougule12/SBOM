"""Stage 1 tests for sbom_parser.openvex.

Parsing only: a parsed Finding is the document's claim. These tests assert no predicate
result, evidence sufficiency, aggregation, reachability or verdict. Everything is
offline and deterministic (hand-authored fixtures).
"""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import model
from sbom_parser import openvex
from sbom_parser.errors import InvalidDocumentError, MalformedInputError, UnsupportedVersionError
from sbom_parser.identifiers import VARIANT_NORMALIZATION_VERSION
from sbom_parser.openvex import parse_openvex

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "openvex"
NOT_PRESENT = FIXTURES / "component_not_present.json"
NOT_IN_PATH = FIXTURES / "not_in_execute_path.json"
UNSUPPORTED = FIXTURES / "unsupported_justification.json"
MIXED = FIXTURES / "mixed_statements.json"
HASH_UPPER = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
SUPPORTED_JUSTIFICATIONS = {t.value for t in model.JustificationType}


def load(path=NOT_PRESENT):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def encode(obj):
    return json.dumps(obj).encode("utf-8")


def meta(document, key):
    return json.loads(document.declared_metadata[key])


def statement_doc(finding):
    [doc] = [d for key, d in finding.source_documents.items() if "#/statements/" in key]
    return doc


# ---- supported versions -------------------------------------------------------------

def test_supported_context_is_exactly_openvex_v0_2_0():
    assert openvex.SUPPORTED_CONTEXTS == ("https://openvex.dev/ns/v0.2.0",)


@pytest.mark.parametrize(
    "context",
    ["https://openvex.dev/ns/v0.1.0", "https://openvex.dev/ns/v0.3.0", "https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0/"],
)
def test_other_openvex_contexts_are_reported_as_unsupported(context):
    data = load()
    data["@context"] = context
    with pytest.raises(UnsupportedVersionError) as caught:
        parse_openvex(encode(data))
    assert caught.value.locator == "#/@context"


def test_missing_or_unrelated_context_is_an_invalid_document():
    data = load()
    del data["@context"]
    with pytest.raises(InvalidDocumentError):
        parse_openvex(encode(data))
    data["@context"] = "https://example.com/not-openvex"
    with pytest.raises(InvalidDocumentError):
        parse_openvex(encode(data))
    data["@context"] = 2
    with pytest.raises(InvalidDocumentError):
        parse_openvex(encode(data))


# ---- input forms and determinism ----------------------------------------------------

def test_bytes_str_path_and_pathlib_inputs_give_identical_results():
    from_bytes = parse_openvex(NOT_PRESENT.read_bytes())
    assert parse_openvex(str(NOT_PRESENT)) == from_bytes
    assert parse_openvex(NOT_PRESENT) == from_bytes


def test_parsing_is_deterministic():
    assert parse_openvex(MIXED) == parse_openvex(MIXED)


def test_missing_file_is_not_swallowed():
    with pytest.raises(FileNotFoundError):
        parse_openvex(FIXTURES / "does_not_exist.json")


# ---- document-level provenance ------------------------------------------------------

def test_document_level_metadata_is_extracted():
    document, _ = parse_openvex(NOT_PRESENT)
    assert document.doc_id.startswith("openvex:sha256:")
    assert (document.producer, document.producer_class) == ("Example Security Team", "Document Creator")
    assert document.created == datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
    assert document.tool_name == "example-vex-tool 0.3.0"  # verbatim, not split
    assert document.tool_version is None
    declared = document.declared_metadata
    assert declared["document_id"] == "https://example.com/vex/component-not-present"
    assert declared["document_version"] == "1"
    assert declared["statement_count"] == "1"
    assert declared["spec_version"] == "https://openvex.dev/ns/v0.2.0"


def test_fields_openvex_does_not_state_are_not_inferred():
    document, _ = parse_openvex(NOT_IN_PATH)
    assert document.producer_class is None  # no role in this fixture
    assert document.tool_name is None
    assert document.generation_context is None and document.method is None
    assert document.integrity == model.Integrity()  # v0.2.0 documents carry no signature
    assert document.declared_metadata["assertion_status"] == "self_asserted_unverified"


# ---- findings: the claim as stated --------------------------------------------------

def test_component_not_present_statement_is_extracted():
    document, [finding] = parse_openvex(NOT_PRESENT)
    assert finding.disposition is model.Disposition.NOT_AFFECTED
    assert finding.justification.justification == "component_not_present"
    assert finding.justification.asserted_by == "Example Security Team"
    assert finding.justification.statement == "The affected library is not part of this image."
    assert finding.vulnerability.id == "CVE-2026-0001"
    assert finding.vulnerability.aliases == ["GHSA-xxxx-yyyy-zzzz"]
    assert finding.scope.product_id == "pkg:oci/example-app@sha256%3Aabc"
    assert finding.evidence == []  # a VEX claim is not evidence for itself


def test_vulnerable_code_not_in_execute_path_statement_is_extracted():
    _, [finding] = parse_openvex(NOT_IN_PATH)
    assert finding.disposition is model.Disposition.NOT_AFFECTED
    assert finding.justification.justification == "vulnerable_code_not_in_execute_path"
    assert finding.vulnerability.id == "CVE-2026-0002"
    assert finding.justification.statement is None


def test_supported_justifications_are_kept_as_plain_strings_not_enum_members():
    for path in (NOT_PRESENT, NOT_IN_PATH):
        _, [finding] = parse_openvex(path)
        raw = finding.justification.justification
        assert type(raw) is str
        assert raw in SUPPORTED_JUSTIFICATIONS


def test_unsupported_justification_strings_are_preserved_exactly():
    _, findings = parse_openvex(UNSUPPORTED)
    raws = [f.justification.justification for f in findings]
    assert raws == ["vulnerable_code_not_present", "Inline_Mitigations_Already_Exist"]
    for raw in raws:
        assert type(raw) is str
        assert raw not in SUPPORTED_JUSTIFICATIONS  # not coerced, not mapped, not rejected
    assert all(f.disposition is model.Disposition.NOT_AFFECTED for f in findings)  # claim kept as-is


@pytest.mark.parametrize(
    "raw",
    [
        "vulnerable_code_not_present",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
        "COMPONENT_NOT_PRESENT",
        " component_not_present",
        "x-unrecognized/Future Value ☃",
    ],
)
def test_arbitrary_justification_strings_survive_unchanged(raw):
    data = load()
    data["statements"][0]["justification"] = raw
    _, [finding] = parse_openvex(encode(data))
    assert finding.justification.justification == raw


def test_an_absent_justification_is_the_empty_string_and_an_empty_input_is_rejected():
    _, findings = parse_openvex(MIXED)
    assert all(f.justification.justification == "" for f in findings)  # none stated
    data = load()
    data["statements"][0]["justification"] = ""
    with pytest.raises(InvalidDocumentError) as caught:
        parse_openvex(encode(data))
    assert caught.value.locator == "#/statements/0/justification"


def test_disposition_is_the_asserted_status_and_not_recomputed():
    _, findings = parse_openvex(MIXED)
    assert [f.disposition for f in findings] == [
        model.Disposition.AFFECTED, model.Disposition.AFFECTED, model.Disposition.UNDER_INVESTIGATION,
    ]


def test_unknown_status_is_an_invalid_document():
    data = load()
    data["statements"][0]["status"] = "exploitable"
    with pytest.raises(InvalidDocumentError) as caught:
        parse_openvex(encode(data))
    assert caught.value.locator == "#/statements/0/status"


def test_one_finding_per_statement_and_product_for_every_status():
    document, findings = parse_openvex(MIXED)
    assert document.declared_metadata["statement_count"] == "2"
    assert [(f.scope.product_id, f.vulnerability.id) for f in findings] == [
        ("example-product-3a", "CVE-2026-0005"),
        ("example-product-3b", "CVE-2026-0005"),
        ("example-product-3c", "https://example.com/vuln/only-an-id"),
    ]


# ---- statement-level provenance -----------------------------------------------------

def test_document_and_statement_provenance_are_kept_distinct():
    document, [finding] = parse_openvex(NOT_PRESENT)
    assert document.doc_id in finding.source_documents
    stmt = statement_doc(finding)
    assert stmt is not document
    assert stmt.doc_id == f"{document.doc_id}#/statements/0"
    assert stmt.producer == "Example Supplier"  # statement supplier, not the document author
    assert document.producer == "Example Security Team"
    assert stmt.created == datetime(2026, 1, 15, 10, 5, tzinfo=timezone.utc)
    assert stmt.declared_metadata["parent_document"] == document.doc_id
    assert stmt.declared_metadata["statement_locator"] == "#/statements/0"
    assert stmt.declared_metadata["status_notes"] == "Checked at build time."
    assert stmt.declared_metadata["justification_raw"] == "component_not_present"


def test_nothing_is_inherited_between_document_and_statement_provenance():
    document, [finding] = parse_openvex(NOT_IN_PATH)
    stmt = statement_doc(finding)
    assert stmt.producer is None and stmt.created is None  # statement states neither
    assert document.created is not None and document.producer is not None


def test_statement_level_fields_are_preserved_when_present():
    _, findings = parse_openvex(MIXED)
    stmt = statement_doc(findings[0])
    assert stmt.declared_metadata["action_statement"] == "Upgrade to 1.1."
    assert stmt.declared_metadata["action_statement_timestamp"] == "2026-01-16T00:00:00Z"
    assert stmt.producer == "Statement Supplier"
    assert json.loads(stmt.declared_metadata["vulnerability"])["description"] == "Example description."
    # statements sharing one source statement share one statement-level document:
    assert statement_doc(findings[1]).doc_id == stmt.doc_id
    assert statement_doc(findings[2]).doc_id != stmt.doc_id


def test_subcomponents_and_unknown_statement_fields_are_reported_not_dropped():
    document, findings = parse_openvex(MIXED)
    products = json.loads(statement_doc(findings[0]).declared_metadata["products"])
    assert products[1]["subcomponents"] == [{"@id": "example-sub-1"}]
    assert json.loads(statement_doc(findings[2]).declared_metadata["unextracted_statement_fields"]) == ["custom_field"]
    assert json.loads(statement_doc(findings[0]).declared_metadata["unextracted_statement_fields"]) == []


def test_unextracted_top_level_fields_are_listed():
    data = load()
    data["x-extension"] = {"a": 1}
    document, _ = parse_openvex(encode(data))
    assert json.loads(document.declared_metadata["unextracted_top_level_fields"]) == ["x-extension"]


# ---- component identity: preservation -----------------------------------------------

def test_product_identifiers_are_preserved_exactly():
    _, [finding] = parse_openvex(NOT_PRESENT)
    component = finding.product
    assert component.purl == "pkg:oci/example-app@sha256%3Aabc"
    assert component.bom_ref == "pkg:oci/example-app@sha256%3Aabc"
    assert component.hashes == [model.Hash("sha-256", HASH_UPPER)]  # key and case kept
    assert component.name == "" and component.version is None  # OpenVEX products carry no name


def test_cpe_identifiers_keep_their_original_form():
    _, [finding] = parse_openvex(NOT_IN_PATH)
    assert finding.product.cpe == ["cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"]
    _, findings = parse_openvex(MIXED)
    assert findings[0].product.cpe == ["cpe:/a:vendor:product:1.0"]  # 2.2 form, not converted


def test_variants_are_versioned_and_do_not_overwrite_originals():
    _, [finding] = parse_openvex(NOT_PRESENT)
    assert [(v.kind, v.value) for v in finding.product.identifier_variants] == [
        ("purl", "pkg:oci/example-app@sha256%3Aabc"),
        ("hash:sha256", HASH_UPPER.lower()),
    ]
    assert {v.normalization_rule_version for v in finding.product.identifier_variants} == {
        VARIANT_NORMALIZATION_VERSION
    }
    _, [other] = parse_openvex(NOT_IN_PATH)
    assert [(v.kind, v.value) for v in other.product.identifier_variants] == [
        ("cpe", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
    ]


def test_a_product_id_is_not_parsed_as_a_purl_or_used_to_invent_variants():
    _, findings = parse_openvex(UNSUPPORTED)
    component = findings[0].product
    assert component.bom_ref == "example-product-2"
    assert component.purl is None and component.cpe == []
    assert component.identifier_variants == []


def test_scope_carries_only_what_the_document_states():
    _, [finding] = parse_openvex(NOT_PRESENT)
    scope = finding.scope
    assert scope.product_id == "pkg:oci/example-app@sha256%3Aabc"
    assert scope.artifact_digest == [] and scope.build_id is None and scope.valid_interval is None
    # OpenVEX does not state an artifact kind, so it is UNKNOWN (never the OTHER fallback):
    assert scope.artifact_kind is model.ArtifactKind.UNKNOWN


@pytest.mark.parametrize("path", [NOT_PRESENT, NOT_IN_PATH, UNSUPPORTED, MIXED])
def test_unspecified_artifact_kind_is_unknown_not_other_for_every_finding(path):
    _, findings = parse_openvex(path)
    assert findings
    for finding in findings:
        assert finding.scope.artifact_kind is model.ArtifactKind.UNKNOWN
        assert finding.scope.artifact_kind is not model.ArtifactKind.OTHER


def test_artifact_kind_is_not_inferred_from_the_product_status_or_justification():
    # An OCI-looking purl (component_not_present fixture), the three statuses in the
    # mixed fixture and both supported justifications all still yield UNKNOWN.
    _, [oci] = parse_openvex(NOT_PRESENT)
    assert oci.product.purl.startswith("pkg:oci/")
    assert oci.scope.artifact_kind is model.ArtifactKind.UNKNOWN
    _, mixed = parse_openvex(MIXED)
    assert {f.disposition for f in mixed} == {
        model.Disposition.AFFECTED, model.Disposition.UNDER_INVESTIGATION,
    }
    assert {f.scope.artifact_kind for f in mixed} == {model.ArtifactKind.UNKNOWN}
    for justification in ("component_not_present", "vulnerable_code_not_in_execute_path"):
        data = load()
        data["statements"][0]["justification"] = justification
        _, [finding] = parse_openvex(encode(data))
        assert finding.scope.artifact_kind is model.ArtifactKind.UNKNOWN


def test_a_nonstandard_artifact_kind_field_is_reported_not_adopted():
    data = load()
    data["statements"][0]["artifact_kind"] = "container"
    _, [finding] = parse_openvex(encode(data))
    assert finding.scope.artifact_kind is model.ArtifactKind.UNKNOWN  # no format support for it
    reported = json.loads(statement_doc(finding).declared_metadata["unextracted_statement_fields"])
    assert reported == ["artifact_kind"]  # visible, not silently dropped


# ---- target component C versus product (spec §1, G1) --------------------------------
# In OpenVEX v0.2.0 `subcomponents` is nested inside each product entry (not a
# statement-level field). The product is what the statement asserts a status for; the
# subcomponents identify the component the evidence concerns (the target C).

SUBS = FIXTURES / "subcomponents.json"
PRODUCT_A_ID = "pkg:oci/example-app@sha256%3Adef"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.4"


def variant_pairs(component):
    return {(v.kind, v.value) for v in component.identifier_variants}


def test_a_product_with_a_subcomponent_keeps_the_product_and_extracts_a_distinct_target():
    _, findings = parse_openvex(SUBS)
    finding = findings[0]
    product, target = finding.product, finding.component
    # The product is fully retained ...
    assert product.bom_ref == PRODUCT_A_ID
    assert product.purl == PRODUCT_A_ID
    assert product.cpe == ["cpe:2.3:a:Example:App:2.0:*:*:*:*:*:*:*"]
    assert product.hashes == [model.Hash("sha-256", "A" * 64)]
    assert finding.scope.product_id == PRODUCT_A_ID  # the claim is about the product
    # ... and the target is a separate entity carrying only the subcomponent's own data.
    assert target is not None and target is not product
    assert target.bom_ref == LOG4J
    assert target.purl == LOG4J
    assert target.cpe == ["cpe:/a:apache:log4j:2.4", "cpe:2.3:a:Apache:Log4j:2.4:*:*:*:*:*:*:*"]
    assert target.hashes == [model.Hash("sha-1", "B" * 40)]
    assert (target.purl, target.cpe) != (product.purl, product.cpe)


def test_a_product_without_subcomponents_keeps_the_product_but_has_no_established_target():
    _, findings = parse_openvex(SUBS)
    unresolved = findings[3]  # second product entry, no subcomponents
    assert unresolved.component is None  # unresolved: never replaced by the product
    assert unresolved.product.bom_ref == "pkg:oci/other-app@sha256%3Aghi"
    assert unresolved.product.purl == "pkg:oci/other-app@sha256%3Aghi"
    assert unresolved.scope.product_id == "pkg:oci/other-app@sha256%3Aghi"
    # The same holds for every product-only fixture:
    for path in (NOT_PRESENT, NOT_IN_PATH, UNSUPPORTED):
        _, found = parse_openvex(path)
        assert found and all(f.component is None and f.product is not None for f in found)


def test_multiple_subcomponents_are_all_represented_in_order_and_none_is_dropped():
    document, findings = parse_openvex(SUBS)
    assert len(findings) == 4  # 3 subcomponents of product A + 1 unresolved product B
    targets = [f.component for f in findings[:3]]
    assert [t.bom_ref for t in targets] == [LOG4J, "example-sub-only-an-id", None]
    assert targets[2].purl == "pkg:npm/Left-Pad@1.3.0"  # identifiers-only subcomponent kept
    assert {f.product.bom_ref for f in findings[:3]} == {PRODUCT_A_ID}  # same product each time
    stmt = statement_doc(findings[0])
    assert json.loads(stmt.declared_metadata["finding_targets"]) == [
        {"product_locator": "#/statements/0/products/0",
         "target_locator": "#/statements/0/products/0/subcomponents/0"},
        {"product_locator": "#/statements/0/products/0",
         "target_locator": "#/statements/0/products/0/subcomponents/1"},
        {"product_locator": "#/statements/0/products/0",
         "target_locator": "#/statements/0/products/0/subcomponents/2"},
        {"product_locator": "#/statements/0/products/1", "target_locator": None},
    ]
    raw_products = json.loads(stmt.declared_metadata["products"])
    assert len(raw_products[0]["subcomponents"]) == 3  # raw statement data preserved too


def test_product_identifiers_are_never_copied_into_the_targets_identifier_variants():
    _, findings = parse_openvex(SUBS)
    product_variants = variant_pairs(findings[0].product)
    assert product_variants  # the product does have variants of its own
    for finding in findings[:3]:
        assert not (variant_pairs(finding.component) & product_variants)
    # A subcomponent that gives only an @id has no identifiers or variants of its own;
    # it does not inherit the product's purl, CPE or hashes.
    bare = findings[1].component
    assert (bare.purl, bare.cpe, bare.hashes, bare.identifier_variants) == (None, [], [], [])
    # Without any subcomponent there is no target at all, hence no variants to fill in:
    assert findings[3].component is None
    assert variant_pairs(findings[3].product) == {("purl", "pkg:oci/other-app@sha256%3Aghi")}


def test_variants_of_a_target_are_derived_from_the_targets_own_identifiers_only():
    _, findings = parse_openvex(SUBS)
    assert [(v.kind, v.value) for v in findings[0].component.identifier_variants] == [
        ("purl", LOG4J),
        ("cpe", "cpe:/a:apache:log4j:2.4"),
        ("cpe", "cpe:2.3:a:apache:log4j:2.4:*:*:*:*:*:*:*"),
        ("hash:sha1", "b" * 40),
    ]
    assert {v.normalization_rule_version for v in findings[0].component.identifier_variants} == {
        VARIANT_NORMALIZATION_VERSION
    }


def test_equal_looking_product_and_subcomponent_identifiers_are_not_merged_or_equated():
    data = json.loads(SUBS.read_text(encoding="utf-8"))
    product = data["statements"][0]["products"][0]
    product["subcomponents"] = [{"@id": PRODUCT_A_ID, "identifiers": {"purl": PRODUCT_A_ID}}]
    _, findings = parse_openvex(encode(data))
    first = findings[0]
    assert first.component is not None and first.product is not None
    assert first.component is not first.product  # still two entities
    assert first.component.purl == first.product.purl  # preserved as given, no equivalence claimed
    assert len(findings) == 2  # the identical-looking subcomponent was not collapsed away


def test_subcomponents_are_read_from_the_product_entry_not_from_the_statement():
    data = load()  # component_not_present fixture: one product, no subcomponents
    data["statements"][0]["subcomponents"] = [{"@id": "statement-level-is-not-the-schema"}]
    document, [finding] = parse_openvex(encode(data))
    assert finding.component is None  # a statement-level key is not a subcomponent list
    reported = json.loads(statement_doc(finding).declared_metadata["unextracted_statement_fields"])
    assert reported == ["subcomponents"]  # visible, not silently dropped


@pytest.mark.parametrize(
    "mutator, locator",
    [
        (lambda p: p.update(subcomponents={}), "#/statements/0/products/0/subcomponents"),
        (lambda p: p["subcomponents"].append(7), "#/statements/0/products/0/subcomponents/3"),
        (lambda p: p["subcomponents"].append({}), "#/statements/0/products/0/subcomponents/3"),
        (lambda p: p["subcomponents"][0].update(identifiers={"purl": 5}), "#/statements/0/products/0/subcomponents/0/identifiers/purl"),
        (lambda p: p["subcomponents"][0].update(hashes={"sha-1": 5}), "#/statements/0/products/0/subcomponents/0/hashes/sha-1"),
    ],
)
def test_invalid_subcomponent_structures_are_rejected_with_a_locator(mutator, locator):
    data = json.loads(SUBS.read_text(encoding="utf-8"))
    mutator(data["statements"][0]["products"][0])
    with pytest.raises(InvalidDocumentError) as caught:
        parse_openvex(encode(data))
    assert caught.value.locator == locator


# ---- malformed input ----------------------------------------------------------------

def test_malformed_json_fixture_is_rejected():
    with pytest.raises(MalformedInputError):
        parse_openvex(FIXTURES / "malformed.json")


@pytest.mark.parametrize(
    "raw",
    [b"", b"null", b"[]", b"\xff\xfe", b'{"@id": 1, "@id": 2}', b'{"x": -Infinity}'],
)
def test_malformed_inputs_raise_instead_of_returning_empty_results(raw):
    with pytest.raises(MalformedInputError):
        parse_openvex(raw)


# ---- structurally invalid documents -------------------------------------------------

def _mutated(mutator):
    data = copy.deepcopy(load())
    mutator(data)
    return encode(data)


@pytest.mark.parametrize(
    "mutator, locator",
    [
        (lambda d: d.pop("@id"), "#"),
        (lambda d: d.pop("author"), "#"),
        (lambda d: d.pop("timestamp"), "#"),
        (lambda d: d.update(timestamp="soon"), "#/timestamp"),
        (lambda d: d.update(version="1"), "#/version"),
        (lambda d: d.update(statements={}), "#/statements"),
        (lambda d: d["statements"].append(3), "#/statements/1"),
        (lambda d: d["statements"][0].pop("status"), "#/statements/0"),
        (lambda d: d["statements"][0].update(justification=5), "#/statements/0/justification"),
        (lambda d: d["statements"][0].pop("vulnerability"), "#/statements/0"),
        (lambda d: d["statements"][0].update(vulnerability="CVE-2026-0001"), "#/statements/0/vulnerability"),
        (lambda d: d["statements"][0]["vulnerability"].clear(), "#/statements/0/vulnerability"),
        (lambda d: d["statements"][0].update(products=[]), "#/statements/0/products"),
        (lambda d: d["statements"][0].pop("products"), "#/statements/0/products"),
        (lambda d: d["statements"][0]["products"].append({}), "#/statements/0/products/1"),
        (lambda d: d["statements"][0]["products"][0].update(hashes={"sha-256": 1}), "#/statements/0/products/0/hashes/sha-256"),
        (lambda d: d["statements"][0]["vulnerability"].update(aliases="x"), "#/statements/0/vulnerability/aliases"),
    ],
)
def test_structurally_invalid_documents_raise_with_a_locator(mutator, locator):
    with pytest.raises(InvalidDocumentError) as caught:
        parse_openvex(_mutated(mutator))
    assert caught.value.locator == locator
