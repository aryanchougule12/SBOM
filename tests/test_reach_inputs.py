"""Tests for evidence.reach_inputs: the strict reachability evidence input (all fixtures are SYNTHETIC)."""

import copy
import json

import pytest

from evidence.reach_inputs import (
    LocusApproximation,
    ReachFinding,
    ReachInputError,
    ReachInputErrorCode as E,
    ReachKind,
    load_reachability,
    parse_reachability,
)
from evidence.reach_rules import HazardClass, HazardDisposition
from tests.reach_support import REACH_FIXTURES, add_doc, baseline_data, doc

FIXTURE_NAMES = ["synthetic_baseline", "synthetic_k3_no_hit", "synthetic_k2_p0", "synthetic_k4_only"]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_committed_fixture_loads(name):
    assert load_reachability(REACH_FIXTURES / f"{name}.json").schema_version == "1"


def test_the_baseline_fixture_is_read_as_written():
    evidence = parse_reachability(baseline_data())
    k1 = evidence.document("k1-analysis")
    assert (k1.kind, k1.finding, k1.full_coverage_claim, k1.entry_points_complete) == (ReachKind.K1, ReachFinding.NEGATIVE, True, True)
    assert k1.analyzed_configurations == ("prod",) and HazardClass.REFLECTION not in k1.modeled_hazards
    assert evidence.document("reflection-basis").finding is None
    assert evidence.locus.approximation is LocusApproximation.OVER_APPROXIMATION
    assert evidence.hazards[0].disposition is HazardDisposition.EXCLUDED_BY_EVIDENCE and evidence.hazards[0].basis_ref == "reflection-basis"
    assert evidence.deployment_config_id == "prod" and evidence.document("absent") is None


def test_digests_are_canonicalised_and_the_input_is_immutable():
    data = baseline_data()
    doc(data, "k1-analysis")["artifact"]["hashes"] = ["SHA-256:" + "E3B0" * 16]
    evidence = parse_reachability(data)
    assert [(h.algorithm, h.value) for h in evidence.document("k1-analysis").artifact.hashes] == [("sha256", "e3b0" * 16)]
    with pytest.raises(Exception):
        evidence.documents = ()  # type: ignore[misc]


def test_loading_from_bytes_and_text_and_malformed_json():
    assert load_reachability(json.dumps(baseline_data()).encode()).documents
    with pytest.raises(ReachInputError) as error:
        load_reachability(b"{not json")
    assert error.value.code is E.MALFORMED_JSON


def mutated(change):
    data = baseline_data()
    change(data)
    return data


REJECTED = [
    ("not_an_object", lambda d: None, E.INVALID_TYPE),
    ("missing_schema", lambda d: d.pop("schema_version"), E.MISSING_FIELD),
    ("schema_2", lambda d: d.update(schema_version="2"), E.SCHEMA_VERSION_UNSUPPORTED),
    ("unknown_top_field", lambda d: d.update(extra=1), E.UNKNOWN_FIELD),
    ("unknown_doc_field", lambda d: doc(d, "k1-analysis").update(extra=1), E.UNKNOWN_FIELD),
    ("bad_kind", lambda d: doc(d, "k1-analysis").update(kind="K4"), E.INVALID_VALUE),
    ("k4_cannot_be_supplied", lambda d: doc(d, "k1-analysis").update(kind="dependency_graph"), E.INVALID_VALUE),
    ("bad_finding", lambda d: doc(d, "k1-analysis").update(finding="reachable"), E.INVALID_VALUE),
    ("missing_finding", lambda d: doc(d, "k1-analysis").pop("finding"), E.MISSING_FIELD),
    ("basis_with_finding", lambda d: doc(d, "reflection-basis").update(finding="negative"), E.FIELD_NOT_ALLOWED_FOR_KIND),
    ("coverage_claim_on_k3", lambda d: doc(d, "k1-analysis").update(kind="K3", finding="negative"), E.FIELD_NOT_ALLOWED_FOR_KIND),
    ("duplicate_doc", lambda d: d["documents"].append(copy.deepcopy(doc(d, "k1-analysis"))), E.DUPLICATE_DOCUMENT),
    ("bad_timestamp", lambda d: doc(d, "k1-analysis").update(created="yesterday"), E.INVALID_VALUE),
    ("bad_digest", lambda d: doc(d, "k1-analysis")["artifact"].update(hashes=["sha256:xyz"]), E.INVALID_VALUE),
    ("empty_artifact", lambda d: doc(d, "k1-analysis").update(artifact={}), E.MISSING_FIELD),
    ("target_name_only", lambda d: doc(d, "k1-analysis").update(target={"name": "lib-b"}), E.MISSING_FIELD),
    ("empty_locus", lambda d: d.update(locus={"entered_by": "x"}), E.MISSING_FIELD),
    ("bad_approximation", lambda d: d["locus"].update(approximation="exact"), E.INVALID_VALUE),
    ("locus_without_label", lambda d: d["locus"].pop("entered_by"), E.MISSING_FIELD),
    ("unknown_hazard_class", lambda d: d["hazards"][0].update({"class": "TIMING"}), E.INVALID_VALUE),
    ("unknown_disposition", lambda d: d["hazards"][0].update(disposition="excluded"), E.INVALID_VALUE),
    ("duplicate_hazard", lambda d: d["hazards"].append(dict(d["hazards"][0])), E.DUPLICATE_HAZARD),
    ("basis_on_modeled", lambda d: d["hazards"].append({"class": "NATIVE_FFI", "disposition": "modeled_conservatively",
                                                        "basis_ref": "reflection-basis"}), E.INCONSISTENT),
    ("locator_without_ref", lambda d: d["hazards"].append({"class": "NATIVE_FFI", "disposition": "excluded_by_evidence",
                                                           "basis_locator": "#"}), E.INCONSISTENT),
    ("locator_not_a_pointer", lambda d: d["hazards"][0].update(basis_locator="finding"), E.INVALID_VALUE),
    ("entry_without_flag", lambda d: d.update(entry_points={"entered_by": "x"}), E.MISSING_FIELD),
    ("config_missing_id", lambda d: d.update(configuration={}), E.MISSING_FIELD),
    ("modeled_class_unknown", lambda d: doc(d, "k1-analysis").update(modeled_hazards=["TIMING"]), E.INVALID_VALUE),
]


@pytest.mark.parametrize("label, change, code", REJECTED, ids=[r[0] for r in REJECTED])
def test_invalid_input_is_a_hard_error_with_a_stable_code(label, change, code):
    if label == "not_an_object":
        with pytest.raises(ReachInputError) as error:
            parse_reachability([])  # type: ignore[arg-type]
    else:
        with pytest.raises(ReachInputError) as error:
            parse_reachability(mutated(change))
    assert error.value.code is code
    assert error.value.path or label == "not_an_object"


@pytest.mark.parametrize("key", ["verdict", "state", "reach", "provenance_level", "ep", "prov_reach", "bind_state", "codes", "ceiling"])
def test_states_levels_bind_results_and_verdicts_can_never_be_supplied(key):
    for target in (lambda d: d, lambda d: doc(d, "k1-analysis"), lambda d: d["locus"], lambda d: d["hazards"][0]):
        data = baseline_data()
        target(data)[key] = "Absent"
        with pytest.raises(ReachInputError) as error:
            parse_reachability(data)
        assert error.value.code is E.FORBIDDEN_FIELD


def test_k2_and_k3_documents_only_accept_their_findings():
    for kind, finding, ok in [("K2", "negative", True), ("K2", "positive", True), ("K2", "unknown", True), ("K2", "ambiguous", False),
                              ("K3", "negative", True), ("K3", "incomplete", False), ("K1", "ambiguous", True), ("K1", "incomplete", True)]:
        data = baseline_data()
        d = doc(data, "k1-analysis")
        for k in ("full_coverage_claim", "entry_points", "modeled_hazards"):
            if kind != "K1":
                d.pop(k, None)
        d.update(kind=kind, finding=finding)
        if ok:
            assert parse_reachability(data).document("k1-analysis").finding.value == finding
        else:
            with pytest.raises(ReachInputError):
                parse_reachability(data)


def test_the_parser_does_not_mutate_its_argument():
    data = baseline_data()
    snapshot = copy.deepcopy(data)
    parse_reachability(data)
    assert data == snapshot
    assert add_doc(data, doc_id="extra", kind="hazard_basis")["documents"][-1]["doc_id"] == "extra"
