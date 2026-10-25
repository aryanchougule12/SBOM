"""Tests for evidence.aggregation (specification §2).

AG1-AG5 are the specification's acceptance cases. M-1 and M-2 are defined in §6 of the
specification at the *verdict* level ("degrading any state, EP, or hazard disposition never
raises a verdict"; "deleting evidence never turns Unknown into Absent"). Aggregation
produces no verdict, so the property tests below are LOCAL aggregation-level invariants
that are compatible with, and motivated by, those statements. They are not the formal
M-1/M-2 and make no claim about verdicts. See also U-10 (spec §7) for M-1's scope.
"""

import itertools

import pytest

from evidence.aggregation import AggregationReason, aggregate, aggregate_state
from model import EvidenceItem, EvidenceState

S = EvidenceState
ALL_STATES = list(EvidenceState)


def item(state, dimension="MATCH", doc="d1", locator=None):
    return EvidenceItem(dimension=dimension, state=state, source_doc=doc, locator=locator)


# ---- AG1-AG5 (spec §2) ------------------------------------------------------------------

def test_ag1_present_plus_incomplete_is_present():
    result = aggregate([item(S.PRESENT, doc="d1", locator="#/components/2"), item(S.INCOMPLETE, doc="d2")])
    assert result.state is S.PRESENT
    assert result.reason is AggregationReason.POSITIVE_OBSERVATION


def test_ag2_present_plus_absent_is_contradictory_under_the_approved_overlap_convention():
    result = aggregate([item(S.PRESENT, doc="d1", locator="#/components/2"), item(S.ABSENT, doc="d2")])
    assert result.state is S.CONTRADICTORY
    assert result.reason is AggregationReason.PRESENT_VS_ABSENT


def test_ag2_does_not_compare_document_relative_locators():
    # Same locator in different documents, different locators in one document: both overlap.
    assert aggregate_state([item(S.PRESENT, doc="d1", locator="#/a"), item(S.ABSENT, doc="d2", locator="#/a")]) is S.CONTRADICTORY
    assert aggregate_state([item(S.PRESENT, doc="d1", locator="#/a"), item(S.ABSENT, doc="d1", locator="#/b")]) is S.CONTRADICTORY


def test_ag3_present_plus_unknown_is_present():
    assert aggregate_state([item(S.PRESENT), item(S.UNKNOWN, doc="d2")]) is S.PRESENT


def test_ag4_unknown_only_is_unknown():
    for count in (1, 3):
        result = aggregate([item(S.UNKNOWN, doc=f"d{i}") for i in range(count)])
        assert result.state is S.UNKNOWN
        assert result.reason is AggregationReason.ALL_UNKNOWN


def test_ag5_incomplete_plus_incomplete_is_incomplete_never_absent_or_complete():
    result = aggregate([item(S.INCOMPLETE, doc="d1"), item(S.INCOMPLETE, doc="d2")])
    assert result.state is S.INCOMPLETE
    assert result.reason is AggregationReason.INCOMPLETE


# ---- boundaries -------------------------------------------------------------------------

def test_empty_input_and_all_unknown_input_are_both_unknown_but_distinguishable():
    empty = aggregate([])
    unknown = aggregate([item(S.UNKNOWN)])
    assert empty.state is S.UNKNOWN and unknown.state is S.UNKNOWN
    assert empty.reason is AggregationReason.NO_ITEMS
    assert unknown.reason is AggregationReason.ALL_UNKNOWN
    assert empty.reason is not unknown.reason
    assert empty.dimension is None and unknown.dimension == "MATCH"


def test_empty_input_is_never_absent():
    assert aggregate_state([]) is not S.ABSENT


def test_explicit_contradictory_item_dominates():
    for others in ([], [S.PRESENT], [S.ABSENT], [S.INCOMPLETE], [S.AMBIGUOUS], [S.UNKNOWN], [S.PRESENT, S.ABSENT]):
        items = [item(S.CONTRADICTORY)] + [item(s, doc=f"x{i}") for i, s in enumerate(others)]
        result = aggregate(items)
        assert result.state is S.CONTRADICTORY, others
    assert aggregate([item(S.CONTRADICTORY)]).reason is AggregationReason.CONTRADICTORY_ITEM
    assert aggregate([item(S.CONTRADICTORY), item(S.PRESENT), item(S.ABSENT)]).reason is AggregationReason.CONTRADICTORY_ITEM


def test_mixed_dimensions_are_rejected_deterministically():
    with pytest.raises(ValueError, match="DECL, MATCH"):
        aggregate([item(S.PRESENT, dimension="MATCH"), item(S.ABSENT, dimension="DECL")])
    with pytest.raises(ValueError):  # even when one of them is Unknown
        aggregate([item(S.UNKNOWN, dimension="INV"), item(S.UNKNOWN, dimension="MATCH")])


def test_invalid_items_are_rejected():
    with pytest.raises(TypeError):
        aggregate(["Present"])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        aggregate([EvidenceItem(dimension="MATCH", state="Present")])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "states, expected",
    [
        ([S.ABSENT], S.ABSENT),
        ([S.ABSENT, S.ABSENT], S.ABSENT),
        ([S.ABSENT, S.INCOMPLETE], S.INCOMPLETE),
        ([S.ABSENT, S.AMBIGUOUS], S.AMBIGUOUS),
        ([S.INCOMPLETE, S.AMBIGUOUS], S.AMBIGUOUS),
        ([S.ABSENT, S.INCOMPLETE, S.AMBIGUOUS], S.AMBIGUOUS),
        ([S.PRESENT, S.AMBIGUOUS], S.PRESENT),  # specification-determined: literal §2 step 3 (see register)
        ([S.PRESENT, S.INCOMPLETE, S.UNKNOWN], S.PRESENT),
        ([S.PRESENT, S.ABSENT, S.INCOMPLETE], S.CONTRADICTORY),
    ],
)
def test_mixed_and_conflicting_states(states, expected):
    assert aggregate_state([item(s, doc=f"d{i}") for i, s in enumerate(states)]) is expected


def test_absent_requires_an_absent_item():
    for states in itertools.chain.from_iterable(
        itertools.combinations_with_replacement(ALL_STATES, n) for n in range(0, 4)
    ):
        if aggregate_state([item(s) for s in states]) is S.ABSENT:
            assert S.ABSENT in states


# ---- local aggregation-level invariants (not the formal M-1/M-2) -------------------------

MULTISETS = [
    combo
    for n in range(0, 5)
    for combo in itertools.combinations_with_replacement(ALL_STATES, n)
]


def test_local_invariant_order_independence():
    """aggregate(items) is a function of the multiset of states, not of their order."""
    for combo in MULTISETS:
        expected = aggregate_state([item(s) for s in combo])
        for perm in set(itertools.permutations(combo)):
            assert aggregate_state([item(s) for s in perm]) is expected, combo


def test_local_invariant_adding_unknown_items_changes_nothing_once_informative_evidence_exists():
    for combo in MULTISETS:
        if all(s is S.UNKNOWN for s in combo):
            continue
        base = aggregate_state([item(s) for s in combo])
        extended = [item(s) for s in combo] + [item(S.UNKNOWN, doc="u1"), item(S.UNKNOWN, doc="u2")]
        assert aggregate_state(extended) is base, combo


def test_local_invariant_unknown_only_input_stays_unknown_when_unknowns_are_added():
    assert aggregate_state([]) is S.UNKNOWN
    assert aggregate_state([item(S.UNKNOWN)] * 3) is S.UNKNOWN


def test_local_m2_deleting_evidence_never_turns_unknown_into_absent():
    """For every item list whose aggregate is Unknown, every sub-list is also Unknown, so
    deleting items never produces Absent (local analogue of spec M-2)."""
    for combo in MULTISETS:
        items = [item(s, doc=f"d{i}") for i, s in enumerate(combo)]
        if aggregate_state(items) is not S.UNKNOWN:
            continue
        for size in range(len(items) + 1):
            for subset in itertools.combinations(items, size):
                assert aggregate_state(list(subset)) is S.UNKNOWN


def test_local_m1_replacing_an_absent_item_with_a_less_favourable_state_never_creates_absent():
    """Local analogue of spec M-1 for the claim 'not present': degrading an Absent item
    (to any other state) never makes a non-Absent aggregate become Absent."""
    for combo in MULTISETS:
        for position, state in enumerate(combo):
            if state is not S.ABSENT:
                continue
            for degraded in ALL_STATES:
                if degraded is S.ABSENT:
                    continue
                before = aggregate_state([item(s, doc=f"d{i}") for i, s in enumerate(combo)])
                changed = list(combo)
                changed[position] = degraded
                after = aggregate_state([item(s, doc=f"d{i}") for i, s in enumerate(changed)])
                if before is not S.ABSENT:
                    assert after is not S.ABSENT, (combo, position, degraded)


def test_aggregation_does_not_mutate_its_input():
    items = [item(S.PRESENT), item(S.ABSENT, doc="d2")]
    snapshot = [(i.dimension, i.state, i.source_doc, i.locator) for i in items]
    aggregate(items)
    assert [(i.dimension, i.state, i.source_doc, i.locator) for i in items] == snapshot
