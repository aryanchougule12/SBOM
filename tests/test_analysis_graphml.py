"""Tests for evidence.analysis_graphml (Joern / flatgraph GraphML). All GraphML fixtures are SYNTHETIC, written to
the structure of the flatgraph GraphMLExporter source; no Joern-generated file was available (see fixtures/analysis/README.md)."""

import random

import pytest

from evidence.analysis_graphml import parse_joern_graphml
from evidence.analysis_ingest import detect_format, parse_analysis_artifact
from evidence.analysis_model import AnalysisArtifactError, AnalysisArtifactErrorCode as E, AnalysisFormat
from tests.analysis_support import GRAPHML_DIR

ALL = sorted(GRAPHML_DIR.glob("*.graphml"))
VALID = [p for p in ALL if "invalid" not in p.name]


def raw(name):
    return (GRAPHML_DIR / name).read_bytes()


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.name)
def test_valid_exports_parse_and_are_identified_by_content(path):
    parsed = parse_joern_graphml(path.read_bytes())
    assert parsed.source.format is AnalysisFormat.JOERN_GRAPHML and parsed.source.doc_id.startswith("joern-graphml:sha256:")
    assert parsed.call_graph is not None and parsed.candidates == ()
    assert detect_format(path.read_bytes()) is AnalysisFormat.JOERN_GRAPHML


def test_the_call_graph_is_method_level_and_uses_only_call_edges():
    parsed = parse_joern_graphml(raw("synthetic_path_bound.graphml"))
    graph = parsed.call_graph
    assert {m.node_id: m.full_name for m in graph.methods}["12"] == "lib.b.Parser.parse:java.lang.Object(java.lang.String)"
    # three CALL edges; the AST, CFG, ARGUMENT and REACHING_DEF edges of the export are not call edges
    assert graph.call_edge_count == 3
    assert [(e.caller, e.callee) for e in graph.edges] == [("10", "11"), ("11", "12"), ("11", "13")]
    assert [e.locator for e in graph.edges] == ["#/graphml/edge/3", "#/graphml/edge/4", "#/graphml/edge/5"]


def test_meta_data_and_format_version_come_from_the_file_only():
    parsed = parse_joern_graphml(raw("synthetic_path_bound.graphml"))
    (run,) = parsed.runs
    assert (run.content_hash, run.language) == ("9f2b6c1d4e7a8b30", "JAVASRC")
    assert parsed.source.format_version == "cpg-spec:1.1"
    assert (run.tool.name, run.tool.version, run.started) == (None, None, None)  # the export names no tool
    assert any(d.code == "LIST_PROPERTIES_NOT_EXPORTED" for d in parsed.diagnostics)


def test_a_file_without_meta_data_is_accepted_with_unknown_version_and_a_diagnostic():
    parsed = parse_joern_graphml(raw("synthetic_no_meta_data.graphml"))
    assert parsed.source.format_version is None and parsed.runs[0].content_hash is None
    assert any(d.code == "NO_META_DATA" for d in parsed.diagnostics)


def test_a_graph_without_call_edges_is_reported_as_not_a_call_graph_export():
    parsed = parse_joern_graphml(raw("synthetic_no_call_edges_cfg_only.graphml"))
    assert parsed.call_graph.call_edge_count == 0 and parsed.call_graph.edges == ()
    assert any(d.code == "NO_CALL_EDGES" for d in parsed.diagnostics)


def test_contains_is_read_in_the_exporter_direction_only_and_a_reversed_edge_is_never_silently_lost():
    """semanticcpg reads ``method._containsOut`` (METHOD -> node); an edge written the other way is not used, but it is
    reported and the call edges it would have placed become undecidable instead of vanishing."""
    forward = raw("synthetic_path_bound.graphml")
    reversed_ = forward.replace(b'<edge source="10" target="20">', b'<edge source="20" target="10">')
    assert reversed_ != forward
    parsed = parse_joern_graphml(reversed_)
    assert any(d.code == "CONTAINS_EDGE_REVERSED" for d in parsed.diagnostics)
    assert parsed.call_graph.edges != parse_joern_graphml(forward).call_graph.edges
    assert {u.call_node for u in parsed.call_graph.uncontained} == {"20"}


def test_a_call_edge_whose_call_site_has_no_container_is_not_usable_and_is_reported():
    text = raw("synthetic_path_bound.graphml").decode().replace('<edge source="11" target="21">', '<edge source="99" target="21">')
    with pytest.raises(AnalysisArtifactError) as error:  # node 99 does not exist: unresolved, not silently dropped
        parse_joern_graphml(text.encode())
    assert error.value.code is E.REFERENCE_UNRESOLVED
    dropped = raw("synthetic_path_bound.graphml").decode()
    dropped = dropped.replace('<edge source="11" target="22">', '<edge source="22" target="22">')  # not a CONTAINS of a method any more
    parsed = parse_joern_graphml(dropped.encode())
    assert any(d.code == "CALL_SITE_WITHOUT_CONTAINING_METHOD" for d in parsed.diagnostics)


REFUSED = {
    "synthetic_invalid_unresolved_endpoint.graphml": (E.REFERENCE_UNRESOLVED, "#/graphml/edge/6"),
    "synthetic_invalid_duplicate_node_id.graphml": (E.CONTRADICTORY, "#/graphml/node/20"),
    "synthetic_invalid_call_site_in_two_methods.graphml": (E.CONTRADICTORY, "#/graphml/edge/3"),
    "synthetic_invalid_call_edge_wrong_kinds.graphml": (E.STRUCTURE_INVALID, "#/graphml/edge/6"),
    "synthetic_invalid_cpg_spec_version.graphml": (E.FORMAT_VERSION_UNSUPPORTED, "#/graphml/node/1"),
    "synthetic_invalid_doctype.graphml": (E.UNSAFE_CONSTRUCT, None),
    "synthetic_invalid_undirected.graphml": (E.STRUCTURE_INVALID, None),
    "synthetic_invalid_truncated.graphml": (E.MALFORMED, None),
    "synthetic_invalid_not_flatgraph.graphml": (E.FORMAT_UNRECOGNIZED, None),
}


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_invalid_exports_are_refused_with_a_stable_code_and_locator(name):
    code, locator = REFUSED[name]
    with pytest.raises(AnalysisArtifactError) as error:
        parse_joern_graphml(raw(name))
    assert (error.value.code, error.value.locator) == (code, locator)


def test_every_invalid_fixture_is_covered():
    assert {p.name for p in ALL if "invalid" in p.name} == set(REFUSED)


@pytest.mark.parametrize("payload", [
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><graphml xmlns="http://graphml.graphdrawing.org/xmlns"/>',
    b'<!doctype graphml SYSTEM "file:///etc/passwd"><graphml/>',
])
def test_entity_and_doctype_declarations_are_rejected_before_parsing(payload):
    with pytest.raises(AnalysisArtifactError) as error:
        parse_joern_graphml(payload)
    assert error.value.code is E.UNSAFE_CONSTRUCT


def test_parsing_is_deterministic_and_does_not_modify_its_input():
    for path in VALID:
        data = bytearray(path.read_bytes())
        before = bytes(data)
        assert parse_joern_graphml(bytes(data)) == parse_joern_graphml(before)
        assert bytes(data) == before


def test_arbitrary_corruption_never_leaks_anything_but_the_structured_error():
    data = raw("synthetic_path_bound.graphml")
    rng = random.Random(20260102)
    for _ in range(300):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.choice(b'<>"=/ &;0aZ\x00\xff')
        try:
            parse_analysis_artifact(bytes(mutated))
        except AnalysisArtifactError:
            pass
