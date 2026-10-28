"""Tests for evidence.match: MATCH derivation over the approved inventory-member domain.

No closed-world assumption: Absent needs a bound document, an attested and uncontradicted list
(INV Present), the fully extracted member domain and a strong target identifier.
"""

import copy

import pytest

from evidence.bind import BindBasis, BindCode, BindEvaluation
from evidence.cnp_rules import BindState
from evidence.inv import AssertionStatus, InvCode, InvDerivation
from evidence.inventory_members import InventoryMember, InventoryMembers
from evidence.match import MatchDerivation, MatchReason as MR, derive_match
from model import Component, EvidenceState as S, Hash
from sbom_parser.identifiers import build_identifier_variants

DOC = "doc-1"


def comp(name, version=None, purl=None, cpe=(), hashes=()):
    hashes = [Hash(a, v) for a, v in hashes]
    return Component(name=name, version=version, purl=purl, cpe=list(cpe), hashes=hashes,
                     identifier_variants=build_identifier_variants(name, version, purl, list(cpe), hashes))


def members(*components, extracted=True, doc=DOC):
    items = tuple(InventoryMember(doc, f"#/components/{n}", "listed", c, "library") for n, c in enumerate(components))
    return InventoryMembers(doc, items, extracted)


def bound(doc=DOC, state=BindState.MATCHED):
    if state is BindState.MATCHED:
        return BindEvaluation(state, BindBasis.DIGEST, BindCode.DIGEST_MATCH, agreeing_digests=("sha256:aa",), document_id=doc)
    return BindEvaluation(BindState.UNKNOWN, None, BindCode.NO_SUBJECT, document_id=doc)


def inv(state=S.PRESENT, doc=DOC):
    if state is S.PRESENT:
        return InvDerivation(S.PRESENT, InvCode.PRESENT, BindState.MATCHED, AssertionStatus.USABLE, (InvCode.PRESENT,),
                             document_id=doc, identity_verified=True)
    return InvDerivation(S.UNKNOWN, InvCode.ASSERTION_MISSING, BindState.MATCHED, AssertionStatus.MISSING,
                         (InvCode.ASSERTION_MISSING,), document_id=doc)


TARGET = comp("absent", "1.0", "pkg:npm/absent@1.0")
LIB = comp("lib-a", "1.0", "pkg:npm/lib-a@1.0", ["cpe:2.3:a:v:lib-a:1.0:*:*:*:*:*:*:*"], [("SHA-256", "ab" * 32)])


def derive(target, *comps, extracted=True, bind=None, inv_=None, doc=DOC):
    return derive_match(target, members(*comps, extracted=extracted, doc=doc), bind or bound(doc), inv_ or inv(doc=doc))


# ---- positive ------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "target,kinds",
    [
        (comp("x", None, "pkg:npm/lib-a@1.0"), ("purl",)),
        (comp("x", None, None, ["CPE:2.3:a:V:lib-a:1.0:*:*:*:*:*:*:*"]), ("cpe",)),             # CPE normalised to lower case
        (comp("x", None, None, (), [("sha_256", "AB" * 32)]), ("hash:sha256",)),                # algorithm and value normalised
        (comp("x", None, "pkg:NPM/lib-a@1.0"), ("purl",)),                                      # purl type is normalised
    ],
)
def test_any_strong_identifier_equality_is_present(target, kinds):
    result = derive(target, comp("other"), LIB)
    assert result.state is S.PRESENT and result.reason is MR.STRONG_IDENTIFIER_EQUAL
    assert [(m.locator, m.strength, m.kinds) for m in result.matches] == [("#/components/1", "strong", kinds)]


def test_present_survives_additional_weak_matches_and_reports_all():
    target = comp("lib-a", "1.0", "pkg:npm/lib-a@1.0")
    result = derive(target, LIB, comp("Lib-A", "1.0"))
    assert result.state is S.PRESENT and [m.strength for m in result.matches] == ["strong", "weak"]


def test_a_match_beneath_the_subject_is_found_with_its_origin():
    nested = InventoryMember(DOC, "#/metadata/component/components/0", "subject_nested", LIB, "library")
    result = derive_match(comp("x", None, "pkg:npm/lib-a@1.0"), InventoryMembers(DOC, (nested,), True), bound(), inv())
    assert result.state is S.PRESENT and result.matches[0].origin == "subject_nested"


# ---- weak / ambiguous / incomplete -----------------------------------------------------------------

def test_name_and_version_only_is_ambiguous_never_present():
    result = derive(comp("LIB-A", "1.0"), LIB)
    assert result.state is S.AMBIGUOUS and result.reason is MR.NAME_VERSION_ONLY
    assert result.matches[0].strength == "weak" and result.matches[0].kinds == ("name+version",)


def test_name_only_match_is_ambiguous_and_a_missing_version_on_either_side_is_compatible():
    assert derive(comp("lib-a"), LIB).state is S.AMBIGUOUS
    assert derive(comp("lib-a", "1.0"), comp("lib-a")).state is S.AMBIGUOUS


def test_different_versions_are_not_a_match():
    assert derive(comp("lib-a", "2.0", "pkg:npm/lib-a@2.0"), LIB).state is S.ABSENT
    assert derive(comp("lib-a", "2.0"), LIB).state is S.INCOMPLETE  # weak-only target: not Absent


def test_different_purls_suppress_a_name_match():
    target = comp("lib-a", "1.0", "pkg:pypi/lib-a@1.0")  # same name, a different ecosystem
    assert derive(target, LIB).state is S.ABSENT


def test_a_target_with_only_weak_variants_that_matches_nothing_is_incomplete_not_absent():
    result = derive(comp("absent", "1.0"), LIB)
    assert result.state is S.INCOMPLETE and result.reason is MR.ONLY_WEAK_VARIANTS and result.target_strong_kinds == ()


# ---- absent -----------------------------------------------------------------------------------------

def test_absent_needs_every_condition():
    result = derive(TARGET, LIB)
    assert result.state is S.ABSENT and result.reason is MR.NOT_FOUND_IN_ATTESTED_DOMAIN
    assert result.searched_members == 1 and result.target_strong_kinds == ("purl",)
    assert derive(TARGET).state is S.ABSENT  # an attested empty domain is still a search (INV decides emptiness elsewhere)


def test_no_absent_without_a_bound_document():
    result = derive(TARGET, LIB, bind=bound(state=BindState.UNKNOWN))
    assert result.state is S.UNKNOWN and result.reason is MR.BIND_NOT_MATCHED


def test_no_absent_when_the_member_domain_was_not_fully_extracted():
    result = derive(TARGET, LIB, extracted=False)
    assert result.state is S.UNKNOWN and result.reason is MR.DOMAIN_NOT_EXTRACTED


def test_no_absent_without_an_attested_and_uncontradicted_list():
    result = derive(TARGET, LIB, inv_=inv(S.UNKNOWN))
    assert result.state is S.UNKNOWN and result.reason is MR.INVENTORY_NOT_ATTESTED
    contradictory = InvDerivation(S.CONTRADICTORY, InvCode.STRUCTURAL_CONTRADICTION, BindState.MATCHED,
                                  AssertionStatus.USABLE, (InvCode.STRUCTURAL_CONTRADICTION,), ("R1",),
                                  document_id=DOC, identity_verified=True)
    assert derive(TARGET, LIB, inv_=contradictory).state is S.UNKNOWN


def test_missing_or_unusable_targets_are_unknown():
    assert derive(None, LIB).reason is MR.NO_TARGET_COMPONENT
    assert derive(comp(""), LIB).reason is MR.NO_IDENTIFIER_VARIANTS  # an OpenVEX subcomponent with only an @id
    only_name = derive(comp("x", None, None), LIB)  # a name that matches nothing, with no strong variant
    assert only_name.state is S.INCOMPLETE


# ---- unbound documents and document identity ----------------------------------------------------------------

def test_a_match_in_an_unbound_document_is_a_diagnostic_not_evidence():
    result = derive(comp("x", None, "pkg:npm/lib-a@1.0"), LIB, bind=bound(state=BindState.UNKNOWN))
    assert result.state is S.UNKNOWN and result.reason is MR.BIND_NOT_MATCHED
    assert len(result.matches) == 1 and "not used as evidence" in result.diagnostics[0]


def test_document_identities_must_agree():
    assert derive(TARGET, LIB, bind=bound("other")).reason is MR.DOCUMENT_IDENTITY_MISMATCH
    assert derive(TARGET, LIB, inv_=inv(doc="other")).reason is MR.DOCUMENT_IDENTITY_MISMATCH
    assert derive_match(TARGET, members(LIB, doc="other"), bound(), inv()).reason is MR.DOCUMENT_IDENTITY_MISMATCH


# ---- no cross-kind conversion, no contradictory, purity ---------------------------------------------------------

def test_no_cross_kind_comparison():
    # the same text under different kinds never matches, and CPE 2.2 is not converted to 2.3
    assert derive(comp("x", None, None, ["cpe:/a:v:lib-a:1.0"]), LIB).state is S.ABSENT
    assert derive(comp("x", None, "pkg:npm/lib-a@1.0"), comp("y", None, None, [], [])).state is S.ABSENT


def test_match_contradictory_is_never_produced():
    with pytest.raises(ValueError):
        MatchDerivation(S.CONTRADICTORY, MR.STRONG_IDENTIFIER_EQUAL, DOC)
    states = {derive(t, *c).state for t in (TARGET, comp("lib-a"), comp("x", None, "pkg:npm/lib-a@1.0"), None)
              for c in ((), (LIB,))}
    assert S.CONTRADICTORY not in states


def test_pure_and_deterministic_regardless_of_member_order():
    snapshot = copy.deepcopy((TARGET, LIB))
    first = derive(TARGET, LIB, comp("zzz"), comp("lib-a", "1.0"))
    assert (TARGET, LIB) == snapshot
    reordered = InventoryMembers(DOC, tuple(reversed(members(LIB, comp("zzz"), comp("lib-a", "1.0")).members)), True)
    assert derive_match(TARGET, reordered, bound(), inv()).state is first.state
    again = derive(comp("lib-a", "1.0"), LIB, comp("zzz"))
    assert again == derive(comp("lib-a", "1.0"), LIB, comp("zzz"))
