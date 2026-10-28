"""Tests for components nested under ``metadata.component``: parser output, Stage 1 decoding,
neutral observations and the member domain (register D1).

The subject itself, services, pedigree objects, tool components and SPDX files/snippets are never
members; duplicate or conflicting references stay diagnostics (C3 deferred).
"""

import copy
import dataclasses
import json

import pytest

from evidence import stage1_records as s1
from evidence.inventory_members import ORIGIN_LISTED, ORIGIN_SUBJECT_NESTED, inventory_members
from evidence.inventory_observations import MEMBER_DOMAIN, observe_inventory
from sbom_parser.cyclonedx import parse_cyclonedx
from tests.pipeline_support import FIXTURES, cdx, spdx


def doc(subject_components=None, components=None, **extra):
    subject = {"type": "application", "name": "app", "bom-ref": "app"}
    if subject_components is not None:
        subject["components"] = subject_components
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"component": subject}}
    if components is not None:
        data["components"] = components
    data.update(extra)
    return s1.load_cyclonedx(json.dumps(data).encode())


def lib(name, ref=None, **kw):
    obj = {"type": "library", "name": name, "version": "1"}
    if ref:
        obj["bom-ref"] = ref
    obj.update(kw)
    return obj


# ---- parser ------------------------------------------------------------------------------------------------------

def test_the_parser_keeps_subject_nested_components_out_of_the_component_list():
    document, components = parse_cyclonedx(FIXTURES / "cyclonedx" / "subject_nested.json")
    assert [c.name for c in components] == ["lib-a", "lib-b", "lib-c"]
    index = json.loads(document.declared_metadata["subject_component_index"])  # canonical JSON text
    assert [e["locator"] for e in index] == [
        "#/metadata/component/components/0",
        "#/metadata/component/components/0/components/0",
        "#/metadata/component/components/1",
    ]
    assert [e["component"]["bom_ref"] for e in index] == ["sub-a", "sub-a1", "sub-b"]


def test_a_subject_without_nested_components_records_an_empty_index():
    document, _ = parse_cyclonedx(FIXTURES / "cyclonedx" / "dangling_local.json")
    assert json.loads(document.declared_metadata["subject_component_index"]) == []


def test_a_document_without_a_subject_records_an_empty_index():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [lib("a")]}
    document, _ = parse_cyclonedx(json.dumps(data).encode())
    assert json.loads(document.declared_metadata["subject_component_index"]) == []


# ---- Stage 1 -----------------------------------------------------------------------------------------------------

def test_stage1_decodes_subject_components_with_locators_and_types():
    record = cdx("subject_nested.json")
    assert record.subject_components_extracted is True
    assert [(c.locator, c.declared_type, c.component.name) for c in record.subject_components] == [
        ("#/metadata/component/components/0", "library", "bundled-a"),
        ("#/metadata/component/components/0/components/0", "library", "bundled-a1"),
        ("#/metadata/component/components/1", "library", "bundled-b"),
    ]
    assert {v.kind for v in record.subject_components[0].component.identifier_variants} >= {"purl"}
    assert any(v.kind.startswith("hash:") for v in record.subject_components[2].component.identifier_variants)


def test_spdx_has_no_subject_components_and_the_domain_counts_as_extracted():
    record = spdx("../equivalent/app.spdx.json")
    assert record.subject_components == () and record.subject_components_extracted is True


def test_a_record_loaded_without_the_index_is_not_extracted():
    record = cdx("subject_nested.json")
    stripped = copy.deepcopy(record.document)
    del stripped.declared_metadata["subject_component_index"]
    assert s1._decode_subject_components(stripped) == (False, ())


# ---- observations ------------------------------------------------------------------------------------------------

def test_observations_separate_subject_nested_components_from_listed_ones():
    record = cdx("subject_nested.json")
    observed = observe_inventory(record)
    assert [c.locator for c in observed.listed_components] == [
        "#/components/0", "#/components/1", "#/components/1/components/0"]
    assert [c.locator for c in observed.subject_nested_components] == [
        "#/metadata/component/components/0",
        "#/metadata/component/components/0/components/0",
        "#/metadata/component/components/1",
    ]
    assert observed.member_count == 6 and observed.listed_component_count == 3
    assert observed.member_domain_extracted is True and MEMBER_DOMAIN
    assert [c.registry.status.value if c.registry else None for c in observed.subject_nested_components][:2] == ["resolved", "resolved"]


def test_subject_nested_components_resolve_as_dependency_endpoints():
    observed = observe_inventory(cdx("subject_nested.json"))
    targets = {e.target.ref: e.target.status for e in observed.edges}
    assert targets["sub-a"] is s1.ReferenceStatus.RESOLVED and targets["sub-a1"] is s1.ReferenceStatus.RESOLVED


def test_the_observations_do_not_claim_the_subject_is_a_member():
    observed = observe_inventory(cdx("subject_nested.json"))
    refs = [c.bom_ref for c in observed.listed_components + observed.subject_nested_components]
    assert "app-1" not in refs


# ---- the member domain ---------------------------------------------------------------------------------------

def test_the_member_domain_is_listed_plus_subject_nested_in_natural_order():
    members = inventory_members(cdx("subject_nested.json"))
    assert members.domain_extracted is True
    assert [(m.locator, m.origin) for m in members.members] == [
        ("#/components/0", ORIGIN_LISTED),
        ("#/components/1", ORIGIN_LISTED),
        ("#/components/1/components/0", ORIGIN_LISTED),
        ("#/metadata/component/components/0", ORIGIN_SUBJECT_NESTED),
        ("#/metadata/component/components/0/components/0", ORIGIN_SUBJECT_NESTED),
        ("#/metadata/component/components/1", ORIGIN_SUBJECT_NESTED),
    ]
    assert members.locator_prefixes() == ("#/components", "#/metadata/component/components")


def test_services_pedigree_tool_components_and_the_subject_are_not_members():
    record = doc(
        subject_components=[lib("nested", "n")],
        components=[lib("a", "a", pedigree={"ancestors": [lib("ancestor", "anc")]})],
        services=[{"name": "svc", "bom-ref": "svc"}],
    )
    names = [m.component.name for m in inventory_members(record).members]
    assert sorted(names) == ["a", "nested"]
    assert "app" not in names and "svc" not in names and "ancestor" not in names


def test_spdx_members_are_packages_only():
    members = inventory_members(spdx("subjects.json"))
    assert members.locator_prefixes() == ("#/packages",)
    assert all(m.locator.startswith("#/packages/") for m in members.members)


def test_members_are_unextracted_when_the_record_says_so():
    record = dataclasses.replace(cdx("subject_nested.json"), subject_components=(), subject_components_extracted=False)
    members = inventory_members(record)
    assert members.domain_extracted is False
    assert all(m.origin == ORIGIN_LISTED for m in members.members)


def test_duplicate_references_stay_diagnostics_and_do_not_change_membership():
    record = doc(subject_components=[lib("dup-in-subject", "same")], components=[lib("dup-listed", "same")])
    observed = observe_inventory(record)
    assert observed.reference_conflicts  # preserved, not interpreted (C3 deferred)
    assert {m.component.name for m in inventory_members(record).members} == {"dup-in-subject", "dup-listed"}


def test_an_empty_domain_has_no_list_locators():
    members = inventory_members(doc())
    assert members.members == () and members.locator_prefixes() == () and members.domain_extracted is True


def test_pure_and_deterministic():
    record = cdx("subject_nested.json")
    snapshot = copy.deepcopy(record)
    assert inventory_members(record) == inventory_members(record) and record == snapshot


# ---- locators point at the very records that were used --------------------------------------------------------------

def _resolve(raw, locator):
    assert locator.startswith("#")
    node = raw
    for segment in [s for s in locator[1:].split("/") if s]:
        segment = segment.replace("~1", "/").replace("~0", "~")
        node = node[int(segment)] if isinstance(node, list) else node[segment]
    return node


@pytest.mark.parametrize("path", [
    "cyclonedx/subject_nested.json", "equivalent/app.cdx.json", "cyclonedx/complete_composition.json",
    "spdx/subjects.json", "equivalent/app.spdx.json",
])
def test_every_member_and_composition_locator_resolves_to_the_source_record_it_was_read_from(path):
    raw = json.loads((FIXTURES / path).read_text())
    record = (s1.load_cyclonedx if path.startswith(("cyclonedx", "equivalent/app.cdx")) else s1.load_spdx)(FIXTURES / path)
    members = inventory_members(record)
    assert members.members
    for member in members.members:
        node = _resolve(raw, member.locator)
        assert node["name"] == member.component.name, member.locator
        if member.origin == ORIGIN_SUBJECT_NESTED:
            assert member.locator.startswith("#/metadata/component/components/")
    for composition in record.composition_records:
        assert "aggregate" in _resolve(raw, composition.locator)
    assert members.locator_prefixes()
    for prefix in members.locator_prefixes():
        assert isinstance(_resolve(raw, prefix), list)


def test_locators_contain_list_positions_and_fixed_keys_never_names():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app",
                                       "components": [lib("n")]}},
            "components": [lib("a/b~c", "r")],
            "dependencies": [{"ref": "r", "dependsOn": []}]}
    record = s1.load_cyclonedx(json.dumps(data).encode())
    assert [m.locator for m in inventory_members(record).members] == ["#/components/0", "#/metadata/component/components/0"]
    # a locator is built from list positions and fixed keys only, so a name containing "/" or "~" never reaches it
    assert all("a/b" not in m.locator and "~" not in m.locator for m in inventory_members(record).members)
