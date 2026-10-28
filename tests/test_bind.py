"""Tests for evidence.bind (the pure BIND evaluator, register G3c / G17, decisions B1-B5).

BIND is evaluated on parsed CycloneDX/SPDX records and a profile scope only. Nothing here
derives an INV state, a provenance level, a contradiction or a verdict.
"""

import copy
import itertools
import json
from pathlib import Path

import pytest

from evidence import bind as B
from evidence.bind import BindBasis, BindCode as C, BindEvaluation, evaluate_bind, evaluate_bind_for_profile
from evidence.cnp_rules import BindState
from evidence.profile import ScopeIdentity, parse_profile
from evidence.stage1_records import load_cyclonedx, load_spdx
from model import ArtifactKind, DocumentSubject, Hash

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
X = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # the fixture subject's SHA-256
Y = "aa" * 32
PURL = "pkg:generic/app@2.0.0"
CPE = "cpe:2.3:a:vendor:app:2.0.0:*:*:*:*:*:*:*"


def scope(product_id=PURL, version="2.0.0", digests=(), kind=ArtifactKind.CONTAINER):
    return ScopeIdentity(product_id, version, tuple(sorted(digests)), kind)


# ---- record builders ------------------------------------------------------------------------------

def cdx(subject=None, *, drop_subject=False, components=None):
    data = json.loads((FIXTURES / "cyclonedx" / "complete_composition.json").read_text())
    if drop_subject:
        del data["metadata"]["component"]
    elif subject is not None:
        data["metadata"]["component"].update(subject)
    if components is not None:
        data["components"] = components
    return load_cyclonedx(json.dumps(data).encode())


def spdx(packages, describes, *, relationships=(), files=()):
    data = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "bind-test",
        "documentNamespace": "https://example.com/spdx/bind-test",
        "creationInfo": {"created": "2026-01-15T10:00:00Z", "creators": ["Tool: example-tool-1.0"]},
        "documentDescribes": list(describes),
        "packages": packages,
        "files": list(files),
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": ref}
            for ref in relationships
        ],
    }
    return load_spdx(json.dumps(data).encode())


def package(ref, name, version=None, *, checksums=(), purl=None):
    entry = {"SPDXID": ref, "name": name, "downloadLocation": "NOASSERTION"}
    if version is not None:
        entry["versionInfo"] = version
    if checksums:
        entry["checksums"] = [{"algorithm": a, "checksumValue": v} for a, v in checksums]
    if purl:
        entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                  "referenceLocator": purl}]
    return entry


def with_hashes(record, hashes):
    """A deep copy of ``record`` whose single subject carries exactly ``hashes``."""
    record = copy.deepcopy(record)
    record.document.subjects[0].component.hashes = [Hash(a, v) for a, v in hashes]
    return record


def unshared(record):
    """A deep copy whose repeated subject declarations own separate components (a plain deep
    copy keeps the parser's shared object, so editing one declaration would edit both)."""
    record = copy.deepcopy(record)
    for subject in record.document.subjects:
        subject.component = copy.deepcopy(subject.component)
    return record


def reasons(result):
    return [d.code for d in result.diagnostics]


# ---- B3: digest comparison ----------------------------------------------------------------------------

def test_digest_match_uses_the_approved_normalisation():
    # The fixture subject declares SHA-256 with an upper-case value.
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), cdx())
    assert (result.state, result.basis, result.reason) == (BindState.MATCHED, BindBasis.DIGEST, C.DIGEST_MATCH)
    assert result.agreeing_digests == (f"sha256:{X}",) and result.disagreeing_algorithms == ()
    assert result.subject_ref == "app-1" and result.subject_locator == "#/metadata/component"


@pytest.mark.parametrize("algorithm", ["SHA-256", "sha_256", " Sha256 ", "SHA256"])
def test_algorithm_spelling_is_normalised(algorithm):
    record = with_hashes(cdx(), [(algorithm, X.upper())])
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).state is BindState.MATCHED


def test_digest_mismatch_for_a_single_unambiguous_subject():
    result = evaluate_bind(scope(digests=[f"sha256:{Y}"]), cdx())
    assert (result.state, result.basis, result.reason) == (BindState.MISMATCHED, BindBasis.DIGEST, C.DIGEST_MISMATCH)
    assert result.agreeing_digests == () and result.disagreeing_algorithms == ("sha256",)


def test_product_and_version_never_override_a_digest_disagreement():
    # purl and version match perfectly; the comparable digest decides and disagrees.
    record = cdx({"purl": PURL})
    assert evaluate_bind(scope(digests=[f"sha256:{Y}"]), record).state is BindState.MISMATCHED
    assert evaluate_bind(scope(), record).state is BindState.MATCHED  # with no digest it would bind


def test_a_digest_match_does_not_need_product_or_version_to_match():
    result = evaluate_bind(scope(product_id="something-else", version="9", digests=[f"sha256:{X}"]), cdx())
    assert (result.state, result.basis) == (BindState.MATCHED, BindBasis.DIGEST)


def test_agreement_on_one_algorithm_with_no_disagreement_matches():
    # Only sha256 is comparable; the scope's sha512 has no counterpart and is not a disagreement.
    result = evaluate_bind(scope(digests=[f"sha256:{X}", f"sha512:{'0f' * 64}"]), cdx())
    assert result.state is BindState.MATCHED and result.agreeing_digests == (f"sha256:{X}",)


def test_agreement_and_disagreement_across_algorithms_is_unknown():
    record = with_hashes(cdx(), [("SHA-256", X), ("SHA-512", "0f" * 64)])
    result = evaluate_bind(scope(digests=[f"sha256:{X}", f"sha512:{'11' * 64}"]), record)
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.DIGEST_CONFLICT)


def test_disagreement_on_every_comparable_algorithm_is_a_mismatch():
    record = with_hashes(cdx(), [("SHA-256", X), ("SHA-512", "0f" * 64)])
    result = evaluate_bind(scope(digests=[f"sha256:{Y}", f"sha512:{'11' * 64}"]), record)
    assert result.state is BindState.MISMATCHED and result.disagreeing_algorithms == ("sha256", "sha512")


def test_subject_with_two_different_values_for_one_algorithm_is_unknown():
    record = with_hashes(cdx(), [("SHA-256", X), ("sha256", Y)])
    for digests in ([f"sha256:{X}"], [f"sha256:{Y}"], [f"sha256:{'bb' * 32}"]):
        result = evaluate_bind(scope(digests=digests), record)
        assert (result.state, result.reason) == (BindState.UNKNOWN, C.SUBJECT_DIGEST_SELF_CONFLICT)


def test_scope_with_two_different_values_for_one_algorithm_is_unknown():
    result = evaluate_bind(scope(digests=[f"sha256:{X}", f"sha256:{Y}"]), cdx())
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.SCOPE_DIGEST_SELF_CONFLICT)


def test_a_self_conflict_on_an_uncomparable_algorithm_still_blocks():
    record = with_hashes(cdx(), [("SHA-256", X), ("MD5", "aa"), ("md5", "bb")])
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).reason is C.SUBJECT_DIGEST_SELF_CONFLICT


def test_identical_repeated_values_are_not_a_self_conflict():
    record = with_hashes(cdx(), [("SHA-256", X), ("sha256", X.upper())])
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).state is BindState.MATCHED


@pytest.mark.parametrize(
    "bad",
    [("SHA-256", "nothex"), ("", X), ("SHA-256", ""), ("SHA-256", "  "), ("-", X), ("SHA-256", "ab cd"), ("SHA-256", "0x1f")],
)
def test_malformed_source_digests_are_ignored_not_mismatches(bad):
    record = with_hashes(cdx({"purl": PURL}), [bad])
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    # Ignored: nothing comparable is left, so the fallback decides (here it matches).
    assert (result.state, result.basis) == (BindState.MATCHED, BindBasis.PRODUCT_VERSION)
    assert C.SOURCE_DIGEST_MALFORMED in reasons(result)
    unbound = evaluate_bind(scope(product_id="unrelated", digests=[f"sha256:{X}"]), record)
    assert unbound.state is BindState.UNKNOWN and C.SOURCE_DIGEST_MALFORMED in reasons(unbound)


def test_a_malformed_digest_does_not_hide_a_usable_one():
    record = with_hashes(cdx(), [("SHA-256", "nothex"), ("SHA-512", "0f" * 64)])
    result = evaluate_bind(scope(digests=[f"sha512:{'0f' * 64}"]), record)
    assert result.state is BindState.MATCHED and C.SOURCE_DIGEST_MALFORMED in reasons(result)


def test_malformed_scope_digest_is_ignored_with_a_diagnostic():
    result = evaluate_bind(scope(digests=["sha256:zz", f"sha256:{X}"]), cdx())
    assert result.state is BindState.MATCHED and C.SCOPE_DIGEST_MALFORMED in reasons(result)
    only_bad = evaluate_bind(scope(digests=["nonsense"]), cdx({"purl": PURL}))
    assert (only_bad.state, only_bad.basis) == (BindState.MATCHED, BindBasis.PRODUCT_VERSION)


@pytest.mark.parametrize("algorithm,value", [("MD5", "ab"), ("SHA-1", "abc"), ("CRC", "0"), ("blake3", "f" * 7)])
def test_no_algorithm_allow_list_alias_table_or_length_rule(algorithm, value):
    record = with_hashes(cdx(), [(algorithm, value)])
    normalized = algorithm.lower().replace("-", "").replace("_", "")
    assert evaluate_bind(scope(digests=[f"{normalized}:{value}"]), record).state is BindState.MATCHED
    # no aliasing: a different spelling of "the same" algorithm is a different algorithm
    other = with_hashes(cdx({"purl": PURL}), [("SHA-256", X)])
    assert evaluate_bind(scope(digests=[f"sha2-256:{X}"]), other).basis is BindBasis.PRODUCT_VERSION


def test_no_comparable_algorithm_falls_back_to_product_and_version():
    record = with_hashes(cdx({"purl": PURL}), [("SHA-512", "0f" * 64)])
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.basis, result.reason) == (
        BindState.MATCHED, BindBasis.PRODUCT_VERSION, C.PRODUCT_VERSION_MATCH)


def test_fallback_without_a_scope_version_is_unavailable():
    record = with_hashes(cdx({"purl": PURL}), [("SHA-512", "0f" * 64)])
    result = evaluate_bind(scope(version=None, digests=[f"sha256:{X}"]), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.SCOPE_VERSION_UNAVAILABLE)


# ---- B4 / B5: product and version fallback ---------------------------------------------------------------

def test_purl_is_compared_after_the_approved_normalisation():
    record = cdx({"purl": "pkg:GENERIC/app@2.0.0 "})
    result = evaluate_bind(scope(product_id=" pkg:generic/app@2.0.0"), with_hashes(record, []))
    assert (result.state, result.basis) == (BindState.MATCHED, BindBasis.PRODUCT_VERSION)


def test_purl_namespace_and_name_case_are_not_folded():
    record = with_hashes(cdx({"purl": "pkg:generic/App@2.0.0"}), [])
    result = evaluate_bind(scope(product_id="pkg:generic/app@2.0.0"), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.PRODUCT_NOT_MATCHED)


def test_cpe_is_compared_case_insensitively_against_any_subject_cpe():
    record = with_hashes(cdx({"cpe": CPE.upper()}), [])
    assert evaluate_bind(scope(product_id=CPE), record).basis is BindBasis.PRODUCT_VERSION
    assert evaluate_bind(scope(product_id="cpe:2.3:a:vendor:other:2.0.0:*:*:*:*:*:*:*"), record).reason is C.PRODUCT_NOT_MATCHED


def test_product_not_matched_is_unknown_never_mismatched():
    record = with_hashes(cdx({"purl": "pkg:generic/other@2.0.0"}), [])
    result = evaluate_bind(scope(), record)
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.PRODUCT_NOT_MATCHED)


@pytest.mark.parametrize("scope_version,subject_version", [("1.0", "1.0.0"), ("2.0.0", "2.0.1"), ("v2.0.0", "2.0.0")])
def test_version_difference_is_unknown_never_mismatched(scope_version, subject_version):
    record = with_hashes(cdx({"purl": PURL, "version": subject_version}), [])
    result = evaluate_bind(scope(version=scope_version), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.VERSION_NOT_MATCHED)


def test_versions_are_trimmed_before_comparison():
    record = with_hashes(cdx({"purl": PURL, "version": " 2.0.0 "}), [])
    assert evaluate_bind(scope(version="2.0.0\t"), record).state is BindState.MATCHED


def test_name_alone_never_binds():
    record = with_hashes(cdx(), [])
    result = evaluate_bind(scope(product_id="example-app"), record)  # equals the subject's name
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.PRODUCT_ID_NOT_COMPARABLE)


def test_bom_ref_and_spdxid_are_never_compared():
    result = evaluate_bind(scope(product_id="app-1"), with_hashes(cdx(), []))  # the CycloneDX bom-ref
    assert result.reason is C.PRODUCT_ID_NOT_COMPARABLE
    record = spdx([package("SPDXRef-app", "app", "2.0.0")], ["SPDXRef-app"])
    assert evaluate_bind(scope(product_id="SPDXRef-app"), record).reason is C.PRODUCT_ID_NOT_COMPARABLE


def test_non_purl_non_cpe_identifiers_are_not_comparable():
    record = with_hashes(cdx({"purl": PURL}), [])
    for product_id in ("https://example.com/vex/app", "urn:uuid:1234", "app"):
        assert evaluate_bind(scope(product_id=product_id), record).reason is C.PRODUCT_ID_NOT_COMPARABLE


def test_identifier_kind_must_be_compatible():
    only_cpe = with_hashes(cdx({"cpe": CPE}), [])
    assert evaluate_bind(scope(product_id=PURL), only_cpe).reason is C.SUBJECT_PRODUCT_ID_MISSING
    only_purl = with_hashes(cdx({"purl": PURL}), [])
    assert evaluate_bind(scope(product_id=CPE), only_purl).reason is C.SUBJECT_PRODUCT_ID_MISSING


def test_missing_subject_version_is_unknown():
    record = with_hashes(cdx({"purl": PURL}), [])
    record.document.subjects[0].component.version = None
    assert evaluate_bind(scope(), record).reason is C.SUBJECT_VERSION_MISSING


def test_every_failed_fallback_condition_is_reported_in_code_order():
    record = with_hashes(cdx({"purl": "pkg:generic/other@1"}), [])
    record.document.subjects[0].component.version = "3"
    result = evaluate_bind(scope(), record)
    assert result.reason is C.PRODUCT_NOT_MATCHED
    assert reasons(result) == [C.PRODUCT_NOT_MATCHED, C.VERSION_NOT_MATCHED]


# ---- B1: subject selection --------------------------------------------------------------------------------

def test_no_subject_is_unknown_and_no_listed_component_is_substituted():
    listed = [{"type": "library", "bom-ref": "lib", "name": "app", "version": "2.0.0", "purl": PURL,
               "hashes": [{"alg": "SHA-256", "content": X}]}]
    record = cdx(drop_subject=True, components=listed)
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.NO_SUBJECT)
    assert evaluate_bind(scope(), record).reason is C.NO_SUBJECT


def test_a_matching_listed_component_does_not_bind_when_the_subject_differs_or_is_silent():
    listed = [{"type": "library", "bom-ref": "lib", "name": "app", "version": "2.0.0", "purl": PURL,
               "hashes": [{"alg": "SHA-256", "content": Y}]}]
    record = with_hashes(cdx(components=listed), [])  # the subject itself states no hash
    result = evaluate_bind(scope(digests=[f"sha256:{Y}"]), record)
    # nothing comparable on the subject: the listed component's purl and hash are not used
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.SUBJECT_PRODUCT_ID_MISSING)


def test_spdx_two_distinct_package_subjects_are_unknown_even_if_one_matches():
    record = spdx(
        [package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)], purl=PURL),
         package("SPDXRef-b", "b", "3.0.0")],
        ["SPDXRef-a", "SPDXRef-b"],
    )
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.MULTIPLE_SUBJECTS)
    assert evaluate_bind(scope(), record).reason is C.MULTIPLE_SUBJECTS


def test_spdx_subjects_fixture_is_unknown_with_every_blocker_reported():
    record = load_spdx(FIXTURES / "spdx" / "subjects.json")
    result = evaluate_bind(scope(version="1.0.0", digests=[f"sha256:{X}"]), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.SUBJECT_DECLARATION_UNRESOLVED)
    assert C.MULTIPLE_SUBJECTS in reasons(result)
    unresolved = [d.detail for d in result.diagnostics if d.code is C.SUBJECT_DECLARATION_UNRESOLVED]
    assert any("SPDXRef-fileA" in d and "'file'" in d for d in unresolved)
    assert any("SPDXRef-ghost" in d and "'unresolved'" in d for d in unresolved)


def test_spdx_declared_by_both_mechanisms_is_one_subject():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a"], relationships=["SPDXRef-a"])
    assert len(record.document.subjects) == 2  # one per declaration, same reference
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.basis, result.subject_ref) == (BindState.MATCHED, BindBasis.DIGEST, "SPDXRef-a")


def test_spdx_non_package_description_blocks_even_with_one_package_subject():
    files = [{"SPDXID": "SPDXRef-f", "fileName": "./f"}]
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a", "SPDXRef-f"], files=files)
    assert len(record.document.subjects) == 1  # the parser exposes only the package
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.SUBJECT_DECLARATION_UNRESOLVED)


def test_spdx_without_any_subject_declaration_is_unknown():
    record = spdx([package("SPDXRef-a", "a", "2.0.0")], [])
    assert evaluate_bind(scope(), record).reason is C.NO_SUBJECT


def test_spdx_package_subject_with_purl_binds_by_product_and_version():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", purl=PURL)], ["SPDXRef-a"])
    result = evaluate_bind(scope(), record)
    assert (result.state, result.basis) == (BindState.MATCHED, BindBasis.PRODUCT_VERSION)


def test_repeated_declarations_that_disagree_on_identity_are_unknown():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a"], relationships=["SPDXRef-a"])
    record = unshared(record)
    record.document.subjects[1].component.version = "9.9.9"
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.REPEATED_SUBJECT_CONFLICT)
    for field, value in (("purl", "pkg:generic/zzz@1"), ("cpe", ["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]),
                         ("hashes", [Hash("SHA256", Y)]), ("name", "other")):
        changed = unshared(record)
        changed.document.subjects[1].component.version = "2.0.0"
        setattr(changed.document.subjects[1].component, field, value)
        assert evaluate_bind(scope(digests=[f"sha256:{X}"]), changed).reason is C.REPEATED_SUBJECT_CONFLICT, field


def test_repeated_declarations_that_agree_after_normalisation_are_not_a_conflict():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a"], relationships=["SPDXRef-a"])
    record = unshared(record)
    twin = record.document.subjects[1].component
    twin.name, twin.version, twin.hashes = "A", " 2.0.0 ", [Hash("sha-256", X.upper())]
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).state is BindState.MATCHED


def test_inconsistent_subject_records_are_unknown():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a"])
    record = copy.deepcopy(record)
    record.document.subjects.clear()
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), record)
    assert (result.state, result.reason) == (BindState.UNKNOWN, C.SUBJECT_RECORDS_INCONSISTENT)
    assert C.NO_SUBJECT in reasons(result)


def test_two_cyclonedx_style_subjects_are_multiple():
    record = copy.deepcopy(cdx())
    extra = copy.deepcopy(record.document.subjects[0])
    extra.ref = "app-2"
    record.document.subjects.append(extra)
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).reason is C.MULTIPLE_SUBJECTS


def test_subjects_without_a_reference_are_never_merged():
    record = copy.deepcopy(cdx())
    for subject in list(record.document.subjects):
        subject.ref = None
    record.document.subjects.append(copy.deepcopy(record.document.subjects[0]))
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record).reason is C.MULTIPLE_SUBJECTS


# ---- primary document -----------------------------------------------------------------------------------------

def test_no_record_is_unknown():
    result = evaluate_bind(scope(), None)
    assert (result.state, result.basis, result.reason) == (BindState.UNKNOWN, None, C.NO_PRIMARY_SBOM)


def profile_for(doc_id, **scope_changes):
    scope_data = {"product_id": PURL, "version": "2.0.0", "artifact_digests": [f"sha256:{X}"], "artifact_kind": "container"}
    scope_data.update(scope_changes)
    return parse_profile({
        "schema_version": "1", "profile_id": "p", "scope": scope_data,
        "documents": [{"doc_id": doc_id, "role": "primary_sbom"}],
    })


def test_profile_run_selects_the_primary_document_by_doc_id():
    primary, other = cdx(), spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", Y)])], ["SPDXRef-a"])
    profile = profile_for(primary.doc_id)
    assert evaluate_bind_for_profile(profile, [other, primary]).state is BindState.MATCHED
    # a different document that would mismatch is ignored, as is a non-primary one that matches
    assert evaluate_bind_for_profile(profile_for(other.doc_id), [other, primary]).state is BindState.MISMATCHED


def test_profile_run_without_or_with_duplicate_primary():
    primary = cdx()
    profile = profile_for(primary.doc_id)
    assert evaluate_bind_for_profile(profile, []).reason is C.NO_PRIMARY_SBOM
    assert evaluate_bind_for_profile(profile, [spdx([package("SPDXRef-a", "a", "1")], ["SPDXRef-a"])]).reason is C.NO_PRIMARY_SBOM
    assert evaluate_bind_for_profile(profile, [primary, copy.deepcopy(primary)]).reason is C.PRIMARY_SBOM_AMBIGUOUS


def test_profile_assertions_and_scope_equality_do_not_bind():
    primary = cdx()
    data = {
        "schema_version": "1", "profile_id": "p",
        "scope": {"product_id": "unrelated", "version": "1", "artifact_kind": "container"},
        "documents": [{"doc_id": primary.doc_id, "role": "primary_sbom"}],
        "inv_assertions": [{
            "document": primary.doc_id, "statement": "full_component_list", "entered_by": "alice",
            "scope": {"product_id": "unrelated", "version": "1", "artifact_kind": "container"},
        }],
    }
    profile = parse_profile(data)
    assert len(profile.usable_inv_assertions) == 1  # the scope tuples are equal and the assertion is usable
    assert evaluate_bind_for_profile(profile, [primary]).state is BindState.UNKNOWN


# ---- document identity ------------------------------------------------------------------------------------------

def test_every_evaluated_result_names_the_document_it_came_from():
    cyclonedx = cdx()
    pv_record = with_hashes(cdx({"purl": PURL}), [])
    fallback_fail = with_hashes(cdx(), [])
    no_subject = cdx(drop_subject=True)
    multi = load_spdx(FIXTURES / "spdx" / "subjects.json")
    cases = [
        (evaluate_bind(scope(digests=[f"sha256:{X}"]), cyclonedx), cyclonedx),          # digest match
        (evaluate_bind(scope(digests=[f"sha256:{Y}"]), cyclonedx), cyclonedx),          # digest mismatch
        (evaluate_bind(scope(), pv_record), pv_record),                                  # product/version match
        (evaluate_bind(scope(product_id="unrelated"), fallback_fail), fallback_fail),    # unknown: fallback failure
        (evaluate_bind(scope(), no_subject), no_subject),                                # unknown: no subject
        (evaluate_bind(scope(), multi), multi),                                          # unknown: subject blockers
        (evaluate_bind(scope(digests=[f"sha256:{X}", f"sha256:{Y}"]), cyclonedx), cyclonedx),  # unknown: self-conflict
    ]
    for result, record in cases:
        assert result.document_id == record.doc_id and record.doc_id.startswith(("cyclonedx:", "spdx:"))
    assert {r.state for r, _ in cases} == {BindState.MATCHED, BindState.MISMATCHED, BindState.UNKNOWN}


def test_no_record_has_no_document_identity_and_the_profile_helper_uses_the_record_id():
    assert evaluate_bind(scope(), None).document_id is None
    primary = cdx()
    profile = profile_for(primary.doc_id)
    assert evaluate_bind_for_profile(profile, [primary]).document_id == primary.doc_id
    assert evaluate_bind_for_profile(profile, []).document_id is None
    assert evaluate_bind_for_profile(profile, [primary, copy.deepcopy(primary)]).document_id is None


def test_document_id_is_validated_and_does_not_change_the_state_or_basis():
    for bad in ("", "  ", 5):
        with pytest.raises(ValueError):
            BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, C.DIGEST_MATCH, document_id=bad)
    result = evaluate_bind(scope(digests=[f"sha256:{X}"]), cdx())
    assert (result.state, result.basis, result.reason) == (BindState.MATCHED, BindBasis.DIGEST, C.DIGEST_MATCH)


# ---- ordering invariance and purity ---------------------------------------------------------------------------------

def test_result_does_not_depend_on_hash_or_cpe_order():
    hashes = [("SHA-256", X), ("SHA-512", "0f" * 64), ("MD5", "aa"), ("SHA-1", "zz")]
    results = set()
    for ordering in itertools.permutations(hashes):
        record = with_hashes(cdx({"purl": PURL}), list(ordering))
        results.add(evaluate_bind(scope(digests=[f"sha256:{X}", f"sha512:{'0f' * 64}"]), record))
    assert len(results) == 1
    cpes = [f"cpe:2.3:a:v:p{n}:1:*:*:*:*:*:*:*" for n in range(3)]
    results = set()
    for ordering in itertools.permutations(cpes + [CPE]):
        record = with_hashes(cdx(), [])
        record.document.subjects[0].component.cpe = list(ordering)
        results.add(evaluate_bind(scope(product_id=CPE), record))
    assert len(results) == 1


def test_result_does_not_depend_on_scope_digest_order_or_subject_order():
    record = spdx([package("SPDXRef-a", "a", "2.0.0", checksums=[("SHA256", X)])], ["SPDXRef-a"], relationships=["SPDXRef-a"])
    reversed_record = copy.deepcopy(record)
    reversed_record.document.subjects.reverse()
    assert evaluate_bind(scope(digests=[f"sha256:{X}"]), record) == evaluate_bind(scope(digests=[f"sha256:{X}"]), reversed_record)
    multi = load_spdx(FIXTURES / "spdx" / "subjects.json")
    shuffled = copy.deepcopy(multi)
    shuffled.document.subjects.reverse()
    shuffled = copy.deepcopy(shuffled)
    object.__setattr__(shuffled, "subject_declarations", tuple(reversed(multi.subject_declarations)))
    assert evaluate_bind(scope(), multi) == evaluate_bind(scope(), shuffled)
    digests = [f"sha256:{X}", f"sha512:{'0f' * 64}", f"md5:{'ab' * 16}"]
    outcomes = {evaluate_bind(ScopeIdentity(PURL, "2.0.0", tuple(order), ArtifactKind.CONTAINER), cdx())
                for order in itertools.permutations(digests)}
    assert len(outcomes) == 1


def test_evaluation_is_pure():
    record = cdx({"purl": PURL})
    snapshot = copy.deepcopy(record)
    candidate = scope(digests=[f"sha256:{X}"])
    first = evaluate_bind(candidate, record)
    assert record == snapshot and evaluate_bind(candidate, record) == first
    assert record.document.integrity.artifact_digest_binding is None  # never set here


def test_artifact_kind_is_not_consulted():
    outcomes = {evaluate_bind(scope(kind=kind, digests=[f"sha256:{X}"]), cdx()) for kind in
                (ArtifactKind.SOURCE, ArtifactKind.BINARY, ArtifactKind.CONTAINER, ArtifactKind.OTHER, ArtifactKind.UNKNOWN)}
    assert len(outcomes) == 1


# ---- result invariants and boundary --------------------------------------------------------------------------------------

def test_result_invariants_are_enforced():
    BindEvaluation(BindState.MATCHED, BindBasis.DIGEST, C.DIGEST_MATCH)
    BindEvaluation(BindState.MATCHED, BindBasis.PRODUCT_VERSION, C.PRODUCT_VERSION_MATCH)
    BindEvaluation(BindState.MISMATCHED, BindBasis.DIGEST, C.DIGEST_MISMATCH)
    BindEvaluation(BindState.UNKNOWN, None, C.NO_SUBJECT)
    for state, basis, reason in [
        (BindState.MATCHED, None, C.DIGEST_MATCH),                              # a decisive result needs its basis
        (BindState.MATCHED, BindBasis.PRODUCT_VERSION, C.DIGEST_MATCH),         # basis must fit the reason
        (BindState.MATCHED, BindBasis.DIGEST, C.DIGEST_MISMATCH),               # reason must fit the state
        (BindState.MISMATCHED, BindBasis.PRODUCT_VERSION, C.DIGEST_MISMATCH),   # only a digest can mismatch
        (BindState.MISMATCHED, BindBasis.DIGEST, C.PRODUCT_NOT_MATCHED),        # a product difference is never a mismatch
        (BindState.UNKNOWN, BindBasis.DIGEST, C.NO_SUBJECT),                    # unknown has no basis
        (BindState.UNKNOWN, None, C.DIGEST_MATCH),
        (BindState.UNKNOWN, None, C.SOURCE_DIGEST_MALFORMED),                   # diagnostic-only code
    ]:
        with pytest.raises(ValueError):
            BindEvaluation(state, basis, reason)


def test_codes_are_stable_unique_strings():
    values = [c.value for c in C]
    assert len(values) == len(set(values)) and all(v.startswith("BIND_") for v in values)
    assert [b.value for b in BindBasis] == ["digest", "product_version"]


def test_every_result_state_is_the_engine_bind_state():
    assert isinstance(evaluate_bind(scope(), None).state, BindState)
    assert isinstance(evaluate_bind(scope(digests=[f"sha256:{X}"]), cdx()).state, BindState)


def test_evaluator_is_not_wired_into_extraction_or_the_engine():
    import importlib

    for name in ("evidence.cnp_rules", "evidence.extraction", "evidence.stage1_records", "evidence.profile"):
        source = open(importlib.import_module(name).__file__, encoding="utf-8").read()
        assert "evidence.bind" not in source and "evaluate_bind" not in source and "import bind" not in source, name


def test_evaluator_derives_no_inv_provenance_or_verdict():
    import ast

    tree = ast.parse(open(B.__file__, encoding="utf-8").read())
    imported = set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    assert imported <= {"__future__", "dataclasses", "enum", "typing", "evidence.cnp_rules", "evidence.profile",
                        "evidence.stage1_records", "model", "sbom_parser.identifiers"}
    assert {"BindState"} == names & {"BindState", "evaluate_cnp", "CnpInputs", "ProvenanceLevel", "EvidenceState",
                                     "Verdict", "VerdictResult", "extract", "artifact_digest_binding"}
    fields = set(BindEvaluation.__dataclass_fields__)
    assert fields.isdisjoint({"inv", "inv_state", "provenance", "level", "verdict", "p2", "p3"})


def test_subject_type_is_the_documented_model_type():
    assert isinstance(cdx().document.subjects[0], DocumentSubject)
