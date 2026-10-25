"""Tests for evidence.provenance (partial EP: steps 1, 4 and 5; approved G4 behaviour).

Document levels are supplied inputs; nothing here computes P0/P1/P2/P3 for a document.
"""

import pytest

from evidence.provenance import (
    DiagnosticCode,
    effective_provenance,
    effective_provenance_all,
    locator_within,
    locator_within_any,
    min_provenance,
)
from model import EvidenceItem, EvidenceState, ProvenanceLevel

P0, P1, P2, P3 = ProvenanceLevel.P0, ProvenanceLevel.P1, ProvenanceLevel.P2, ProvenanceLevel.P3
LEVELS = {"d3": P3, "d2": P2, "d1": P1, "d0": P0}


def ev(item_id=None, doc="d3", derived_from=(), state=EvidenceState.PRESENT):
    return EvidenceItem(
        dimension="MATCH", state=state, source_doc=doc, item_id=item_id,
        derived_from=list(derived_from),
    )


def codes(result):
    return [d.code for d in result.diagnostics]


# ---- step 1 -----------------------------------------------------------------------------

def test_no_source_document_is_p0():
    (result,) = effective_provenance_all([ev(doc=None)], LEVELS)
    assert result.level is P0 and result.diagnostics == ()


def test_a_supplied_document_level_is_used_unchanged():
    for doc, level in LEVELS.items():
        (result,) = effective_provenance_all([ev(doc=doc)], LEVELS)
        assert result.level is level and result.diagnostics == ()


def test_source_document_without_a_supplied_level_is_p0_with_a_diagnostic():
    (result,) = effective_provenance_all([ev(item_id="a", doc="unknown-doc")], LEVELS)
    assert result.level is P0
    assert codes(result) == [DiagnosticCode.SOURCE_DOC_LEVEL_UNAVAILABLE]


# ---- step 4: resolved, acyclic chains ---------------------------------------------------

def test_derived_item_is_no_stronger_than_its_weakest_input():
    items = [
        ev("a", doc="d3"),
        ev("b", doc="d1"),
        ev("c", doc="d3", derived_from=["a", "b"]),
    ]
    a, b, c = effective_provenance_all(items, LEVELS)
    assert (a.level, b.level, c.level) == (P3, P1, P1)
    assert c.diagnostics == ()


def test_derived_item_is_also_capped_by_its_own_source_document():
    items = [ev("a", doc="d3"), ev("b", doc="d2", derived_from=["a"])]
    assert effective_provenance_all(items, LEVELS)[1].level is P2


def test_indirect_chain_propagates_the_minimum():
    items = [
        ev("a", doc="d1"),
        ev("b", doc="d3", derived_from=["a"]),
        ev("c", doc="d3", derived_from=["b"]),
    ]
    assert [r.level for r in effective_provenance_all(items, LEVELS)] == [P1, P1, P1]


def test_diamond_derivation_is_not_a_cycle():
    items = [
        ev("a", doc="d3"),
        ev("b", doc="d3", derived_from=["a"]),
        ev("c", doc="d2", derived_from=["a"]),
        ev("d", doc="d3", derived_from=["b", "c"]),
    ]
    results = effective_provenance_all(items, LEVELS)
    assert results[3].level is P2 and results[3].diagnostics == ()


def test_derived_level_never_exceeds_the_minimum_input_level_for_all_level_pairs():
    for first, second in [(a, b) for a in LEVELS for b in LEVELS]:
        items = [ev("x", doc=first), ev("y", doc=second), ev("z", doc="d3", derived_from=["x", "y"])]
        results = effective_provenance_all(items, LEVELS)
        assert results[2].level <= min(results[0].level, results[1].level)
        assert results[2].level is min(LEVELS[first], LEVELS[second])


def test_derived_item_without_a_source_document_is_p0_even_with_strong_inputs():
    items = [ev("a", doc="d3"), ev("b", doc=None, derived_from=["a"])]
    assert effective_provenance_all(items, LEVELS)[1].level is P0


# ---- G4: unresolved, ambiguous and cyclic references -------------------------------------

@pytest.mark.parametrize("parent", ["nope", "", None])
def test_missing_or_empty_parent_reference_is_p0_with_a_diagnostic(parent):
    items = [ev("a", doc="d3"), ev("b", doc="d3", derived_from=["a", parent])]
    a, b = effective_provenance_all(items, LEVELS)
    assert a.level is P3
    assert b.level is P0  # never silently ignored, never stronger
    assert codes(b) == [DiagnosticCode.UNRESOLVED_DERIVED_FROM]


def test_item_without_an_id_cannot_be_a_parent():
    items = [ev(None, doc="d3"), ev("b", doc="d3", derived_from=["#0"])]
    assert effective_provenance_all(items, LEVELS)[1].level is P0


def test_duplicate_item_id_makes_the_reference_ambiguous_and_p0():
    items = [ev("a", doc="d3"), ev("a", doc="d3"), ev("b", doc="d3", derived_from=["a"])]
    result = effective_provenance_all(items, LEVELS)[2]
    assert result.level is P0 and codes(result) == [DiagnosticCode.AMBIGUOUS_DERIVED_FROM]


def test_direct_self_cycle_is_p0():
    (result,) = effective_provenance_all([ev("a", doc="d3", derived_from=["a"])], LEVELS)
    assert result.level is P0
    assert codes(result) == [DiagnosticCode.CYCLIC_DERIVATION]
    assert "a -> a" in result.diagnostics[0].detail


def test_two_item_cycle_and_indirect_cycle_are_p0_for_every_member():
    two = [ev("a", derived_from=["b"]), ev("b", derived_from=["a"])]
    assert [r.level for r in effective_provenance_all(two, LEVELS)] == [P0, P0]
    three = [ev("a", derived_from=["b"]), ev("b", derived_from=["c"]), ev("c", derived_from=["a"])]
    results = effective_provenance_all(three, LEVELS)
    assert [r.level for r in results] == [P0, P0, P0]
    assert all(DiagnosticCode.CYCLIC_DERIVATION in codes(r) for r in results)


def test_an_item_derived_from_a_cycle_is_p0_and_reports_why():
    items = [ev("a", derived_from=["b"]), ev("b", derived_from=["a"]), ev("c", doc="d3", derived_from=["a"])]
    result = effective_provenance_all(items, LEVELS)[2]
    assert result.level is P0 and DiagnosticCode.CYCLIC_DERIVATION in codes(result)


def test_a_defect_never_strengthens_the_result_whatever_the_other_inputs():
    items = [ev("a", doc="d3"), ev("b", doc="d3", derived_from=["a", "missing"])]
    assert effective_provenance_all(items, LEVELS)[1].level is P0


def test_diagnostics_are_deterministic_and_sorted():
    items = [
        ev("a", doc="d3"),
        ev("b", doc="d3", derived_from=["zzz", "yyy", "a"]),
    ]
    first = effective_provenance_all(items, LEVELS)[1]
    second = effective_provenance_all(items, LEVELS)[1]
    assert first == second
    assert list(first.diagnostics) == sorted(first.diagnostics, key=lambda d: (d.code.value, d.detail))
    assert len(first.diagnostics) == 2


def test_effective_provenance_for_a_single_member_item():
    items = [ev("a", doc="d1"), ev("b", doc="d3", derived_from=["a"])]
    assert effective_provenance(items[1], items, LEVELS).level is P1
    with pytest.raises(ValueError):
        effective_provenance(ev("a", doc="d3"), items, LEVELS)  # not a member (identity)


def test_inputs_are_not_mutated():
    items = [ev("a", doc="d1"), ev("b", doc="d3", derived_from=["a", "x"])]
    levels = dict(LEVELS)
    before = [(i.item_id, i.source_doc, tuple(i.derived_from)) for i in items]
    effective_provenance_all(items, levels)
    assert [(i.item_id, i.source_doc, tuple(i.derived_from)) for i in items] == before
    assert levels == LEVELS


# ---- step 5: pure minimum ----------------------------------------------------------------

def test_min_provenance_is_a_pure_minimum_over_the_supplied_levels():
    assert min_provenance([P3, P3]) is P3
    assert min_provenance([P3, P1, P2]) is P1
    assert min_provenance(iter([P2])) is P2
    assert min_provenance([P0, P3]) is P0


def test_min_provenance_requires_levels():
    with pytest.raises(ValueError):
        min_provenance([])
    with pytest.raises(TypeError):
        min_provenance([3])  # type: ignore[list-item]


# ---- locator containment helper (not EP step 3) ------------------------------------------

@pytest.mark.parametrize(
    "locator, entry, expected",
    [
        ("#/components/1", "#/components/1", True),
        ("#/components/1/name", "#/components/1", True),
        ("#/components/10", "#/components/1", False),  # whole segments, not a string prefix
        ("#/components/1", "#/components/10", False),
        ("#/components", "#/components/0", False),  # a list-level locator is not inside an element
        ("#/components/0", "#/components", True),
        ("#/anything/at/all", "#", True),
        ("#", "#", True),
        ("#", "#/components", False),
        ("#/a~1b", "#/a~1b", True),
        ("#/a~1b", "#/a/b", False),
    ],
)
def test_locator_containment_uses_whole_pointer_segments(locator, entry, expected):
    assert locator_within(locator, entry) is expected


def test_missing_locator_is_outside_any_coverage():
    assert locator_within(None, "#") is False
    assert locator_within_any(None, ["#", "#/components/0"]) is False


def test_empty_coverage_covers_nothing():
    assert locator_within_any("#/components/0", []) is False
    assert locator_within_any("#/components/0", ["#/services", "#/components/0"]) is True


@pytest.mark.parametrize("bad", ["", "components/0", "#components", "/components"])
def test_malformed_locators_raise(bad):
    with pytest.raises(ValueError):
        locator_within(bad, "#")
    with pytest.raises(ValueError):
        locator_within("#/a", bad)


def test_the_module_grants_no_p2_or_p3_without_a_supplied_level():
    items = [ev("a", doc="d-with-signature-and-hashes")]
    (result,) = effective_provenance_all(items, {})
    assert result.level is P0
