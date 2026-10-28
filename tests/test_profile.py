"""Tests for evidence.profile (Phase 2 profile-schema and validation slice).

Nothing here derives an INV or BIND state: the module under test only parses, validates
and applies a profile.
"""

import copy
import dataclasses
import importlib
import json

import pytest

from evidence import profile as P
from evidence.profile import (
    AssertionDiagnosticCode as A,
    ProfileError,
    ProfileErrorCode as E,
    apply_profile,
    load_profile,
    parse_profile,
    select_finding,
)
from model import (
    ArtifactKind,
    Component,
    Disposition,
    DocumentRole,
    Finding,
    Hash,
    Justification,
    Scope,
    Vulnerability,
)

DIGEST = "sha256:" + "ab" * 32


def good(**overrides):
    data = {
        "schema_version": "1",
        "profile_id": "prof-1",
        "finding_selector": {"vulnerability": "CVE-2024-0001", "product_id": "pkg:generic/app"},
        "scope": {
            "product_id": "pkg:generic/app",
            "version": "1.0.0",
            "artifact_digests": [DIGEST],
            "artifact_kind": "container",
        },
        "target": {
            "component": {"name": "libfoo", "version": "2.1", "purl": "pkg:generic/libfoo@2.1"},
            "would_be_location": {"document": "sbom-a", "parent_ref": "app"},
        },
        "documents": [{"doc_id": "sbom-a", "role": "primary_sbom"}],
        "inv_assertions": [
            {
                "document": "sbom-a",
                "scope": {
                    "product_id": "pkg:generic/app",
                    "version": "1.0.0",
                    "artifact_digests": [DIGEST],
                    "artifact_kind": "container",
                },
                "statement": "full_component_list",
                "entered_by": "alice",
                "entered_at": "2026-01-02T03:04:05Z",
            }
        ],
    }
    data.update(overrides)
    return data


def code_of(data):
    with pytest.raises(ProfileError) as excinfo:
        parse_profile(data)
    return excinfo.value.code


def mutated(path, value=None, *, delete=False):
    data = copy.deepcopy(good())
    node = data
    for part in path[:-1]:
        node = node[part]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return data


# ---- happy path and immutability ----------------------------------------------------------------

def test_valid_profile_parses_and_is_immutable():
    profile = parse_profile(good())
    assert profile.schema_version == "1"
    assert profile.primary_document == "sbom-a"
    assert profile.document_roles == {"sbom-a": DocumentRole.PRIMARY_SBOM}
    assert profile.scope.artifact_kind is ArtifactKind.CONTAINER
    assert len(profile.usable_inv_assertions) == 1
    assert profile.assertion_diagnostics == ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.profile_id = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.scope.product_id = "x"
    assert isinstance(profile.documents, tuple) and isinstance(profile.inv_assertions, tuple)


def test_parse_does_not_mutate_input():
    data = good()
    before = copy.deepcopy(data)
    parse_profile(data)
    assert data == before


def test_minimal_profile_without_optional_blocks():
    data = good()
    for key in ("finding_selector", "target", "inv_assertions"):
        del data[key]
    profile = parse_profile(data)
    assert profile.finding_selector is None and profile.target is None
    assert profile.inv_assertions == () and profile.usable_inv_assertions == ()


def test_parsing_is_deterministic():
    assert parse_profile(good()) == parse_profile(good())


# ---- schema version and unknown / forbidden fields ----------------------------------------------

def test_schema_version_required_and_exact():
    assert code_of(mutated(["schema_version"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["schema_version"], "2")) is E.SCHEMA_VERSION_UNSUPPORTED
    assert code_of(mutated(["schema_version"], 1)) is E.INVALID_TYPE


def test_top_level_must_be_object():
    assert code_of([]) is E.INVALID_TYPE


@pytest.mark.parametrize("path", [[], ["scope"], ["target"], ["target", "component"], ["documents", 0],
                                  ["inv_assertions", 0], ["inv_assertions", 0, "scope"], ["finding_selector"]])
def test_unknown_fields_rejected_everywhere(path):
    data = good()
    node = data
    for part in path:
        node = node[part]
    node["surprise"] = 1
    assert code_of(data) is E.UNKNOWN_FIELD


@pytest.mark.parametrize("name", sorted(P.FORBIDDEN_FIELDS))
def test_profile_cannot_supply_states_levels_or_verdicts(name):
    for path in ([], ["scope"], ["inv_assertions", 0]):
        data = good()
        node = data
        for part in path:
            node = node[part]
        node[name] = "Present"
        assert code_of(data) is E.FORBIDDEN_FIELD


def test_forbidden_field_error_carries_path():
    data = good()
    data["inv_assertions"][0]["inv_state"] = "Present"
    with pytest.raises(ProfileError) as excinfo:
        parse_profile(data)
    assert excinfo.value.path == "inv_assertions[0].inv_state"


# ---- scope ---------------------------------------------------------------------------------------

def test_scope_required_fields():
    assert code_of(mutated(["scope"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["scope", "product_id"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["scope", "product_id"], "  ")) is E.INVALID_VALUE
    assert code_of(mutated(["scope", "product_id"], 3)) is E.INVALID_TYPE


def test_scope_identifiability_version_or_digest():
    data = good()
    del data["scope"]["version"]
    assert parse_profile(data).scope.version is None  # digest only
    data = good()
    data["scope"]["artifact_digests"] = []
    assert parse_profile(data).scope.artifact_digests == ()  # version only
    data = good()
    del data["scope"]["version"]
    data["scope"]["artifact_digests"] = []
    assert code_of(data) is E.SCOPE_NOT_IDENTIFIABLE
    data = good()
    del data["scope"]["version"]
    del data["scope"]["artifact_digests"]
    assert code_of(data) is E.SCOPE_NOT_IDENTIFIABLE


def test_product_id_alone_never_identifies():
    data = good(scope={"product_id": "p", "artifact_kind": "binary"})
    assert code_of(data) is E.SCOPE_NOT_IDENTIFIABLE


def test_digests_normalised_sorted_deduplicated():
    data = good()
    data["scope"]["artifact_digests"] = ["SHA-256: " + "AB" * 32, "sha256:" + "ab" * 32, "SHA_512:" + "0f" * 64]
    digests = parse_profile(data).scope.artifact_digests
    assert digests == ("sha256:" + "ab" * 32, "sha512:" + "0f" * 64)


@pytest.mark.parametrize(
    "bad",
    [
        "abc",              # no separator
        "sha256",           # no separator
        ":abcd",            # empty algorithm
        " :abcd",           # whitespace-only algorithm
        "-:abcd",           # algorithm empty after normalization
        "_-_:abcd",
        "sha256:",          # empty value
        "sha256: ",         # whitespace-only value
        "",                 # empty string
        "   ",
        "sha256:xyz",       # non-hex
        "sha256:abcg",
        "sha256:ab cd",     # internal whitespace
        "sha256:ab:cd",     # second separator ends up in the value
        "sha256:0x1f",
        "sha256:\uff11\uff12",  # full-width digits are not hexadecimal
        "sha256:\u0661\u0662",  # Arabic-Indic digits are not hexadecimal
    ],
)
def test_malformed_digest_rejected(bad):
    for path in (["scope", "artifact_digests"], ["target", "component", "hashes"]):
        assert code_of(mutated(path, [bad])) is E.DIGEST_MALFORMED
    assert code_of(mutated(assertion_path("scope", "artifact_digests"), [bad])) is E.DIGEST_MALFORMED


@pytest.mark.parametrize(
    "text,canonical",
    [
        ("sha256:ABCDEF", "sha256:abcdef"),                    # value lower-cased
        ("SHA256:abcdef", "sha256:abcdef"),                    # algorithm lower-cased
        ("SHA-256:abcdef", "sha256:abcdef"),                   # '-' removed from the algorithm
        ("sha_256:abcdef", "sha256:abcdef"),                   # '_' removed from the algorithm
        ("  Sha-256 :  AbCdEf  ", "sha256:abcdef"),            # surrounding whitespace trimmed
        ("sha256:0123456789abcdef", "sha256:0123456789abcdef"),
        ("sha256:abc", "sha256:abc"),                          # no length is required
        ("md5:a", "md5:a"),
        ("sha512:" + "F" * 128, "sha512:" + "f" * 128),
    ],
)
def test_digest_normalisation(text, canonical):
    assert parse_profile(mutated(["scope", "artifact_digests"], [text])).scope.artifact_digests == (canonical,)
    spec = parse_profile(mutated(["target", "component", "hashes"], [text])).target.component
    assert spec.hashes == (canonical,)
    assert P._digest(text, "x") == P._digest(canonical, "x") == canonical  # idempotent


def test_digest_normalisation_is_the_approved_one():
    from sbom_parser.identifiers import normalize_hash_algorithm, normalize_hash_value

    for algorithm, value in [("SHA-256", " AB12 "), ("Sha_1", "ff"), ("blake2b", "0A")]:
        expected = f"{normalize_hash_algorithm(algorithm)}:{normalize_hash_value(value)}"
        assert P._digest(f"{algorithm}:{value}", "x") == expected


def test_digest_error_code_is_stable_and_located():
    with pytest.raises(ProfileError) as excinfo:
        parse_profile(mutated(["scope", "artifact_digests"], [DIGEST, "sha256:nothex"]))
    assert excinfo.value.code is E.DIGEST_MALFORMED and excinfo.value.code.value == "PROFILE_DIGEST_MALFORMED"
    assert excinfo.value.path == "scope.artifact_digests[1]"


def test_digest_type_and_list_checks():
    assert code_of(mutated(["scope", "artifact_digests"], "sha256:aa")) is E.INVALID_TYPE
    assert code_of(mutated(["scope", "artifact_digests"], [5])) is E.INVALID_TYPE
    assert code_of(mutated(["scope", "artifact_digests"], [None])) is E.INVALID_TYPE


# ---- artifact kind (G10 stays open) -----------------------------------------------------------------

@pytest.mark.parametrize("kind", ["source", "binary", "container", "other"])
def test_explicit_kinds_accepted(kind):
    assert parse_profile(mutated(["scope", "artifact_kind"], kind)).scope.artifact_kind.value == kind


def test_missing_or_unknown_kind_is_a_hard_error():
    assert code_of(mutated(["scope", "artifact_kind"], delete=True)) is E.ARTIFACT_KIND_REQUIRED
    assert code_of(mutated(["scope", "artifact_kind"], "unknown")) is E.ARTIFACT_KIND_REQUIRED


def test_invalid_kind_values():
    assert code_of(mutated(["scope", "artifact_kind"], "Container")) is E.INVALID_VALUE
    assert code_of(mutated(["scope", "artifact_kind"], 1)) is E.INVALID_TYPE
    assert code_of(mutated(["scope", "artifact_kind"], None)) is E.INVALID_TYPE


# ---- documents and roles -----------------------------------------------------------------------------

def test_documents_required_and_nonempty():
    assert code_of(mutated(["documents"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["documents"], [])) is E.INVALID_VALUE
    assert code_of(mutated(["documents"], {})) is E.INVALID_TYPE


def test_corroborating_is_recognised_and_refused():
    data = good()
    data["documents"].append({"doc_id": "sbom-b", "role": "corroborating"})
    assert code_of(data) is E.ROLE_UNSUPPORTED


def test_exactly_one_primary():
    data = good()
    data["documents"].append({"doc_id": "sbom-b", "role": "primary_sbom"})
    assert code_of(data) is E.MULTIPLE_PRIMARY
    data = good()
    data["documents"] = [{"doc_id": "sbom-b", "role": "corroborating"}]
    assert code_of(data) is E.ROLE_UNSUPPORTED  # and in any case no primary can exist


def test_duplicate_document_id_and_unknown_role():
    data = good()
    data["documents"].append({"doc_id": "sbom-a", "role": "primary_sbom"})
    assert code_of(data) is E.DUPLICATE_DOCUMENT
    assert code_of(mutated(["documents", 0, "role"], "reference")) is E.INVALID_VALUE
    assert code_of(mutated(["documents", 0, "role"], delete=True)) is E.MISSING_FIELD


# ---- target ---------------------------------------------------------------------------------------------

def test_target_component_requires_name():
    assert code_of(mutated(["target", "component", "name"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["target", "component", "name"], "")) is E.INVALID_VALUE


def test_would_be_location_is_optional_and_validated():
    data = good()
    del data["target"]["would_be_location"]
    assert parse_profile(data).target.would_be_location is None
    assert code_of(mutated(["target", "would_be_location", "parent_ref"], delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(["target", "would_be_location", "document"], "nowhere")) is E.LOCATION_DOCUMENT_UNKNOWN


def test_target_component_hashes_and_cpe():
    data = good()
    data["target"]["component"]["hashes"] = ["SHA-1:" + "AA" * 20]
    data["target"]["component"]["cpe"] = ["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]
    spec = parse_profile(data).target.component
    assert spec.hashes == ("sha1:" + "aa" * 20,)
    component = spec.to_component()
    assert component.hashes == [Hash("sha1", "aa" * 20)]
    assert component.cpe == ["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]
    kinds = [v.kind for v in component.identifier_variants]
    assert kinds, "identifier variants come from the existing normalizer"


def test_name_only_target_has_name_variant():
    data = good()
    data["target"]["component"] = {"name": "libbar"}
    component = parse_profile(data).target.component.to_component()
    assert component.purl is None and component.version is None
    assert component.identifier_variants


# ---- finding selector -------------------------------------------------------------------------------------

def make_finding(vuln="CVE-2024-0001", product="pkg:generic/app", **kwargs):
    return Finding(
        component=kwargs.pop("component", None),
        vulnerability=Vulnerability(id=vuln),
        disposition=Disposition.NOT_AFFECTED,
        justification=Justification("component_not_present"),
        evidence=[],
        scope=kwargs.pop("scope", Scope(product_id=product)),
        **kwargs,
    )


def test_selector_picks_exactly_one():
    profile = parse_profile(good())
    findings = [make_finding("CVE-2024-0002"), make_finding(), make_finding(product="other")]
    assert select_finding(profile, findings) is findings[1]


def test_selector_no_match_and_ambiguous():
    profile = parse_profile(good())
    with pytest.raises(ProfileError) as excinfo:
        select_finding(profile, [make_finding("CVE-9")])
    assert excinfo.value.code is E.FINDING_NOT_FOUND
    with pytest.raises(ProfileError) as excinfo:
        select_finding(profile, [make_finding(), make_finding()])
    assert excinfo.value.code is E.FINDING_AMBIGUOUS


def test_no_selector_requires_a_single_finding():
    data = good()
    del data["finding_selector"]
    profile = parse_profile(data)
    only = make_finding()
    assert select_finding(profile, [only]) is only
    with pytest.raises(ProfileError) as excinfo:
        select_finding(profile, [only, make_finding("CVE-2")])
    assert excinfo.value.code is E.FINDING_SELECTOR_REQUIRED
    with pytest.raises(ProfileError) as excinfo:
        select_finding(profile, [])
    assert excinfo.value.code is E.FINDING_NOT_FOUND


# ---- apply_profile / document_roles ------------------------------------------------------------------------

def test_apply_profile_populates_roles_scope_and_target():
    profile = parse_profile(good())
    original = make_finding()
    result = apply_profile(profile, original)
    assert result.document_roles == {"sbom-a": DocumentRole.PRIMARY_SBOM}
    assert result.scope.artifact_kind is ArtifactKind.CONTAINER
    assert result.scope.artifact_digest == [DIGEST]
    assert result.scope.version == "1.0.0"
    assert result.component is not None and result.component.name == "libfoo"
    # the input is not mutated
    assert original.document_roles == {} and original.component is None
    assert original.scope.artifact_kind is ArtifactKind.UNKNOWN


def test_apply_profile_preserves_unrelated_roles():
    profile = parse_profile(good())
    result = apply_profile(profile, make_finding(document_roles={"other": DocumentRole.CORROBORATING}))
    assert result.document_roles == {"other": DocumentRole.CORROBORATING, "sbom-a": DocumentRole.PRIMARY_SBOM}


@pytest.mark.parametrize(
    "roles",
    [
        {"sbom-a": DocumentRole.CORROBORATING},
        {"sbom-z": DocumentRole.PRIMARY_SBOM},
    ],
)
def test_apply_profile_rejects_conflicting_role_map(roles):
    with pytest.raises(ProfileError) as excinfo:
        apply_profile(parse_profile(good()), make_finding(document_roles=roles))
    assert excinfo.value.code is E.ROLE_CONFLICT


def test_apply_profile_accepts_agreeing_role_map():
    roles = {"sbom-a": DocumentRole.PRIMARY_SBOM}
    assert apply_profile(parse_profile(good()), make_finding(document_roles=roles)).document_roles == roles


def test_apply_profile_rejects_scope_conflicts():
    profile = parse_profile(good())
    cases = [
        Scope(product_id="different"),
        Scope(product_id="pkg:generic/app", artifact_kind=ArtifactKind.BINARY),
        Scope(product_id="pkg:generic/app", version="9"),
        Scope(product_id="pkg:generic/app", artifact_digest=["sha256:" + "00" * 32]),
    ]
    for scope in cases:
        with pytest.raises(ProfileError) as excinfo:
            apply_profile(profile, make_finding(scope=scope))
        assert excinfo.value.code is E.SCOPE_CONFLICT


def test_apply_profile_accepts_agreeing_scope_with_unnormalised_digest():
    scope = Scope(product_id="pkg:generic/app", artifact_digest=["SHA-256:" + "AB" * 32], version="1.0.0")
    result = apply_profile(parse_profile(good()), make_finding(scope=scope))
    assert result.scope.artifact_digest == [DIGEST]


def test_apply_profile_never_overrides_an_existing_component():
    with pytest.raises(ProfileError) as excinfo:
        apply_profile(parse_profile(good()), make_finding(component=Component(name="x")))
    assert excinfo.value.code is E.TARGET_CONFLICT


def test_apply_profile_without_target_leaves_component_unresolved():
    data = good()
    del data["target"]
    assert apply_profile(parse_profile(data), make_finding()).component is None


def test_forbidden_field_wins_over_unknown_field_regardless_of_key_order():
    data = good()
    data["aaa_unknown"] = 1  # sorts before the forbidden key
    data["verdict"] = "Supported"
    assert code_of(data) is E.FORBIDDEN_FIELD


def test_apply_profile_does_not_mutate_the_input_even_when_it_succeeds():
    finding = make_finding(
        scope=Scope(product_id="pkg:generic/app", environment_assumptions=["env-1"]),
        document_roles={"other": DocumentRole.CORROBORATING},
    )
    snapshot = copy.deepcopy(finding)
    result = apply_profile(parse_profile(good()), finding)
    assert finding == snapshot
    # the copy shares no mutable state with the input
    result.scope.environment_assumptions.append("env-2")
    result.document_roles["x"] = DocumentRole.CORROBORATING
    result.scope.artifact_digest.append("sha256:00")
    assert finding == snapshot


def test_apply_profile_copy_does_not_alias_an_existing_component():
    # Without a target the existing component stays, as a copy.
    data = good()
    del data["target"]
    component = Component(name="existing")
    finding = make_finding(component=component)
    result = apply_profile(parse_profile(data), finding)
    assert result.component == component and result.component is not component


@pytest.mark.parametrize(
    "finding_kwargs",
    [
        {"scope": Scope(product_id="different")},
        {"scope": Scope(product_id="pkg:generic/app", artifact_kind=ArtifactKind.BINARY)},
        {"scope": Scope(product_id="pkg:generic/app", version="9")},
        {"scope": Scope(product_id="pkg:generic/app", artifact_digest=["sha256:" + "00" * 32])},
        {"component": Component(name="x")},
        {"document_roles": {"sbom-a": DocumentRole.CORROBORATING}},
        {"document_roles": {"sbom-z": DocumentRole.PRIMARY_SBOM}},
    ],
)
def test_failed_apply_profile_leaves_the_input_untouched(finding_kwargs):
    finding = make_finding(**copy.deepcopy(finding_kwargs))
    snapshot = copy.deepcopy(finding)
    with pytest.raises(ProfileError):
        apply_profile(parse_profile(good()), finding)
    assert finding == snapshot


# ---- INV assertions: structure (hard) ---------------------------------------------------------------------------

def assertion_path(*rest):
    return ["inv_assertions", 0, *rest]


@pytest.mark.parametrize("key", ["document", "scope", "statement", "entered_by"])
def test_assertion_required_fields(key):
    assert code_of(mutated(assertion_path(key), delete=True)) is E.MISSING_FIELD


def test_assertion_field_types():
    assert code_of(mutated(assertion_path("statement"), 5)) is E.INVALID_TYPE
    assert code_of(mutated(assertion_path("statement"), "")) is E.INVALID_VALUE
    assert code_of(mutated(assertion_path("entered_by"), " ")) is E.INVALID_VALUE
    assert code_of(mutated(["inv_assertions"], {})) is E.INVALID_TYPE
    assert code_of(mutated(["inv_assertions"], ["x"])) is E.INVALID_TYPE


def test_assertion_entered_at_must_parse_when_present():
    assert code_of(mutated(assertion_path("entered_at"), "yesterday")) is E.INVALID_VALUE
    data = good()
    del data["inv_assertions"][0]["entered_at"]
    assert parse_profile(data).inv_assertions[0].entered_at is None


def test_assertion_scope_kind_cannot_be_unknown_or_invalid():
    assert code_of(mutated(assertion_path("scope", "artifact_kind"), "unknown")) is E.INVALID_VALUE
    assert code_of(mutated(assertion_path("scope", "artifact_kind"), "image")) is E.INVALID_VALUE
    assert code_of(mutated(assertion_path("scope", "artifact_kind"), 3)) is E.INVALID_TYPE


def test_assertion_scope_block_is_structurally_validated_but_not_gated():
    # A malformed scope block is a hard error.
    assert code_of(mutated(assertion_path("scope", "product_id"), delete=True)) is E.MISSING_FIELD
    assert code_of(mutated(assertion_path("scope", "artifact_digests"), ["nope"])) is E.DIGEST_MALFORMED
    assert code_of(mutated(assertion_path("scope", "artifact_kind"), delete=True)) is E.MISSING_FIELD
    # An assertion scope block need not satisfy the profile-scope policy gates; it is
    # merely compared, and a mismatch is a diagnostic, not an error.
    data = good()
    data["inv_assertions"][0]["scope"] = {"product_id": "pkg:generic/app", "artifact_kind": "container"}
    profile = parse_profile(data)
    assert [d.code for d in profile.assertion_diagnostics] == [A.SCOPE_MISMATCH]
    assert profile.usable_inv_assertions == ()


# ---- INV assertions: semantics (non-fatal) ---------------------------------------------------------------------------

def test_unsupported_statement_is_unusable_not_fatal():
    profile = parse_profile(mutated(assertion_path("statement"), "complete_transitively"))
    assert [d.code for d in profile.assertion_diagnostics] == [A.STATEMENT_UNSUPPORTED]
    assert profile.usable_inv_assertions == ()
    assert len(profile.inv_assertions) == 1  # retained, but not usable


def test_unsupported_statement_is_never_usable_even_when_everything_else_matches():
    for statement in ("complete_transitively", "FULL_COMPONENT_LIST", " full_component_list", "partial_component_list"):
        profile = parse_profile(mutated(assertion_path("statement"), statement))
        assert profile.usable_inv_assertions == ()
        assert A.STATEMENT_UNSUPPORTED in {d.code for d in profile.assertion_diagnostics}


def test_scope_tuple_equality_ignores_digest_order_and_spelling():
    data = good()
    data["scope"]["artifact_digests"] = [DIGEST, "sha512:" + "0f" * 64]
    data["inv_assertions"][0]["scope"]["artifact_digests"] = ["SHA512:" + "0F" * 64, DIGEST.upper().replace("SHA256", "sha256")]
    profile = parse_profile(data)
    assert profile.assertion_diagnostics == ()
    assert len(profile.usable_inv_assertions) == 1


@pytest.mark.parametrize(
    "field,value",
    [("product_id", "other"), ("version", "2.0"), ("artifact_kind", "binary"),
     ("artifact_digests", ["sha256:" + "11" * 32])],
)
def test_scope_mismatch_makes_assertion_unusable(field, value):
    profile = parse_profile(mutated(assertion_path("scope", field), value))
    assert [d.code for d in profile.assertion_diagnostics] == [A.SCOPE_MISMATCH]
    assert profile.usable_inv_assertions == ()


def test_assertion_for_unsupplied_document_is_a_diagnostic():
    profile = parse_profile(mutated(assertion_path("document"), "sbom-zzz"))
    assert [d.code for d in profile.assertion_diagnostics] == [A.DOCUMENT_NOT_SUPPLIED]
    assert profile.usable_inv_assertions == ()


def test_identical_duplicates_collapse_deterministically():
    data = good()
    duplicate = copy.deepcopy(data["inv_assertions"][0])
    duplicate["entered_by"] = "bob"  # unverified metadata does not distinguish assertions
    data["inv_assertions"].append(duplicate)
    profile = parse_profile(data)
    assert [a.entered_by for a in profile.inv_assertions] == ["alice"]
    assert [(d.code, d.index) for d in profile.assertion_diagnostics] == [(A.DUPLICATE_IDENTICAL, 1)]
    assert not profile.assertion_diagnostics[0].disqualifying
    assert len(profile.usable_inv_assertions) == 1
    reversed_profile = parse_profile({**data, "inv_assertions": list(reversed(data["inv_assertions"]))})
    assert [a.entered_by for a in reversed_profile.inv_assertions] == ["bob"]  # first wins: order is explicit


def test_conflicting_statements_for_one_document_are_distinguished():
    data = good()
    other = copy.deepcopy(data["inv_assertions"][0])
    other["statement"] = "partial_component_list"
    data["inv_assertions"].append(other)
    profile = parse_profile(data)
    by_index = {}
    for d in profile.assertion_diagnostics:
        by_index.setdefault(d.index, []).append(d.code)
    assert by_index[0] == [A.CONFLICTING]
    assert by_index[1] == [A.STATEMENT_UNSUPPORTED, A.CONFLICTING]
    assert profile.usable_inv_assertions == ()  # neither wins


def test_diagnostics_are_ordered_deterministically():
    data = good()
    data["inv_assertions"][0]["document"] = "ghost"
    data["inv_assertions"][0]["statement"] = "other"
    data["inv_assertions"][0]["scope"]["version"] = "9"
    codes = [d.code for d in parse_profile(data).assertion_diagnostics]
    assert codes == [A.STATEMENT_UNSUPPORTED, A.SCOPE_MISMATCH, A.DOCUMENT_NOT_SUPPLIED]  # enum order


def test_assertion_never_produces_an_evidence_state():
    profile = parse_profile(good())
    for obj in (profile, profile.inv_assertions[0], profile.scope):
        names = {f.name for f in dataclasses.fields(obj)}
        assert names.isdisjoint({"state", "inv", "inv_state", "bind", "bind_state", "verdict", "level"})
    assert not any(hasattr(profile, name) for name in ("inv_state", "bind", "bind_state", "verdict"))


# ---- loading --------------------------------------------------------------------------------------------------------------

def test_load_profile_from_bytes_and_path(tmp_path):
    raw = json.dumps(good()).encode()
    assert load_profile(raw) == parse_profile(good())
    path = tmp_path / "profile.json"
    path.write_bytes(raw)
    assert load_profile(path) == parse_profile(good())
    assert load_profile(str(path)) == parse_profile(good())


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'{"a": 1, "a": 2}', b'{"schema_version": NaN}', b"\xff\xfe"],
)
def test_load_profile_rejects_malformed_json(raw):
    with pytest.raises(ProfileError) as excinfo:
        load_profile(raw)
    assert excinfo.value.code is E.MALFORMED_JSON


def test_duplicate_keys_inside_nested_objects_rejected():
    raw = b'{"schema_version": "1", "scope": {"product_id": "a", "product_id": "b"}}'
    with pytest.raises(ProfileError) as excinfo:
        load_profile(raw)
    assert excinfo.value.code is E.MALFORMED_JSON


# ---- error code catalogue and unwired confirmation -----------------------------------------------------------------------

def test_error_codes_are_distinct_stable_strings():
    values = [c.value for c in E]
    assert len(values) == len(set(values))
    assert all(v.startswith("PROFILE_") for v in values)
    assert all(c.value.startswith("INV_ASSERTION_") for c in A)


def test_profile_error_message_includes_code_and_path():
    with pytest.raises(ProfileError) as excinfo:
        parse_profile(mutated(["scope", "artifact_kind"], "unknown"))
    assert "PROFILE_ARTIFACT_KIND_REQUIRED" in str(excinfo.value) and "scope.artifact_kind" in str(excinfo.value)


def test_engine_and_extraction_do_not_import_profile():
    for name in ("evidence.cnp_rules", "evidence.extraction"):
        module = importlib.import_module(name)
        assert not hasattr(module, "profile") and "evidence.profile" not in getattr(module, "__dict__", {})
        source = open(module.__file__, encoding="utf-8").read()
        assert "evidence.profile" not in source and "from evidence import profile" not in source


def test_profile_module_does_not_import_engine_or_extraction():
    source = open(P.__file__, encoding="utf-8").read()
    for forbidden in ("cnp_rules", "extraction", "reports.verdict", "decl_candidates"):
        assert f"import {forbidden}" not in source and f"{forbidden} import" not in source
