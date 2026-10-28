"""Joern / flatgraph GraphML adapter (raw format parsing and structural validation only).

Consumes the GraphML written by ``joern-export --format graphml`` (the flatgraph
``GraphMLExporter``). The exporter's output structure was read from its source
(``joernio/flatgraph``, ``GraphMLExporter.scala``): a ``<graphml>`` element in the GraphML
namespace, ``<key>`` declarations (``labelV`` / ``labelE`` carry the node and edge labels; node
properties are keys ``node__<LABEL>__<PROPERTY>`` whose ``attr.name`` is the property name), one
``<graph id="G" edgedefault="directed">`` with ``<node id=...>`` and ``<edge source=... target=...>``
elements. **List-valued properties are dropped by the exporter** (for example the META_DATA
``OVERLAYS``), so the artifact cannot say which overlays/passes ran.

The semantics used come from the code property graph schema (``ShiftLeftSecurity/codepropertygraph``,
``CallGraph.scala``): a ``CALL`` edge connects a call site (a ``CALL`` node) to the ``METHOD`` node it
invokes; a ``CONTAINS`` edge relates a ``METHOD`` to the nodes in its body (the semanticcpg library
traverses it from the method, ``_containsOut``, while the schema comment words it the other way
round; this adapter therefore does not depend on the edge direction and identifies the container as
the ``METHOD`` end). The method-level call edge is *container(call site) -> invoked METHOD*.

Consumed: ``META_DATA`` (``LANGUAGE``, ``ROOT``, ``VERSION``, ``HASH``), ``METHOD`` (``FULL_NAME``,
``NAME``, ``FILENAME``, ``IS_EXTERNAL``), ``CALL`` nodes and ``CALL`` / ``CONTAINS`` edges.
Everything else (AST, CFG, REACHING_DEF, ARGUMENT, ... and every other property) is ignored on
purpose: a CFG, a PDG and a data-flow edge are not call-graph evidence.

The file does not record the tool or its version, nor a source revision: tool identity is therefore
``None`` (so the document is unattributed, P0) and the only source identity is the optional
META_DATA ``HASH`` claim (its algorithm is not specified by the CPG schema).

Unsafe XML (a DOCTYPE or entity declaration) is rejected before parsing. Duplicate node ids, edges
with unknown endpoints, a ``CALL`` edge between the wrong node kinds, a call site contained in two
methods, an unsupported META_DATA ``VERSION`` and a non-directed graph are structural errors.
"""

from __future__ import annotations

import re
from typing import Optional
from xml.etree import ElementTree

from evidence.analysis_model import (
    AnalysisArtifactError,
    AnalysisArtifactErrorCode as E,
    AnalysisDiagnostic,
    AnalysisFormat,
    CallEdge,
    CallGraph,
    MethodNode,
    NormalizedAnalysis,
    RunFacts,
    SourceArtifactIdentity,
    ToolIdentity,
)
from sbom_parser._common import document_id

NS = "http://graphml.graphdrawing.org/xmlns"
KEY_NODE_LABEL = "labelV"   # flatgraph.formats.graphml.KeyForNodeLabel
KEY_EDGE_LABEL = "labelE"   # flatgraph.formats.graphml.KeyForEdgeLabel
SUPPORTED_CPG_SPEC_VERSIONS = frozenset({"1.1"})
_UNSAFE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def _q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def _node_locator(node_id: str) -> str:
    return f"#/graphml/node/{node_id}"


def _edge_locator(index: int) -> str:
    return f"#/graphml/edge/{index}"


def parse_joern_graphml(raw: bytes) -> NormalizedAnalysis:
    """Parse and structurally validate a Joern GraphML export. Pure; ``raw`` is not modified."""
    if _UNSAFE.search(raw):
        raise AnalysisArtifactError(E.UNSAFE_CONSTRUCT, "a DOCTYPE or ENTITY declaration is not accepted")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as error:
        raise AnalysisArtifactError(E.MALFORMED, f"not well-formed XML: {error}") from None
    if root.tag != _q("graphml"):
        raise AnalysisArtifactError(E.FORMAT_UNRECOGNIZED, f"root element {root.tag!r} is not a GraphML <graphml>")

    keys: dict[str, tuple[str, str]] = {}  # key id -> (for, attr.name)
    for key in root.findall(_q("key")):
        key_id, domain, name = key.get("id"), key.get("for"), key.get("attr.name")
        if not key_id or not domain or not name:
            raise AnalysisArtifactError(E.STRUCTURE_INVALID, "a <key> needs id, for and attr.name")
        if key_id in keys:
            raise AnalysisArtifactError(E.STRUCTURE_INVALID, f"duplicate <key> id {key_id!r}")
        keys[key_id] = (domain, name)
    if keys.get(KEY_NODE_LABEL, ("",))[0] != "node" or keys.get(KEY_EDGE_LABEL, ("",))[0] != "edge":
        raise AnalysisArtifactError(E.FORMAT_UNRECOGNIZED,
                                    f"no {KEY_NODE_LABEL!r}/{KEY_EDGE_LABEL!r} label keys: not a flatgraph GraphML export")

    graphs = root.findall(_q("graph"))
    if len(graphs) != 1:
        raise AnalysisArtifactError(E.STRUCTURE_INVALID, f"exactly one <graph> is required, found {len(graphs)}")
    graph = graphs[0]
    if graph.get("edgedefault") != "directed":
        raise AnalysisArtifactError(E.STRUCTURE_INVALID, "the graph must be edgedefault=\"directed\"")

    def data(element: ElementTree.Element, domain: str, locator: str) -> dict[str, str]:
        found: dict[str, str] = {}
        for item in element.findall(_q("data")):
            key_id = item.get("key")
            if key_id not in keys or keys[key_id][0] != domain:
                raise AnalysisArtifactError(E.REFERENCE_UNRESOLVED, f"<data key={key_id!r}> has no matching <key for={domain!r}>", locator)
            name = keys[key_id][1]
            if name in found:
                raise AnalysisArtifactError(E.CONTRADICTORY, f"property {name!r} is given twice", locator)
            found[name] = item.text or ""
        return found

    nodes: dict[str, tuple[str, dict[str, str]]] = {}
    edges: list[tuple[int, str, str, str, dict[str, str]]] = []
    diagnostics: list[AnalysisDiagnostic] = []
    for child in graph:
        if child.tag == _q("node"):
            node_id = child.get("id")
            if not node_id:
                raise AnalysisArtifactError(E.STRUCTURE_INVALID, "a <node> needs an id")
            loc = _node_locator(node_id)
            if node_id in nodes:
                raise AnalysisArtifactError(E.CONTRADICTORY, f"duplicate node id {node_id!r}", loc)
            if child.find(_q("graph")) is not None:
                raise AnalysisArtifactError(E.STRUCTURE_INVALID, "nested graphs are not part of the flatgraph export", loc)
            props = data(child, "node", loc)
            label = props.pop(KEY_NODE_LABEL, None)
            if not label:
                raise AnalysisArtifactError(E.STRUCTURE_INVALID, "a node without a label", loc)
            nodes[node_id] = (label, props)
        elif child.tag == _q("edge"):
            index = len(edges)
            loc = _edge_locator(index)
            source, target = child.get("source"), child.get("target")
            if not source or not target:
                raise AnalysisArtifactError(E.STRUCTURE_INVALID, "an <edge> needs source and target", loc)
            props = data(child, "edge", loc)
            label = props.pop(KEY_EDGE_LABEL, None)
            if not label:
                raise AnalysisArtifactError(E.STRUCTURE_INVALID, "an edge without a label", loc)
            edges.append((index, source, target, label, props))
        elif child.tag in (_q("data"),):
            continue
        else:
            raise AnalysisArtifactError(E.STRUCTURE_INVALID, f"unexpected element {child.tag!r} in <graph>")

    for index, source, target, label, _ in edges:
        for end in (source, target):
            if end not in nodes:
                raise AnalysisArtifactError(E.REFERENCE_UNRESOLVED, f"edge endpoint {end!r} is not a node", _edge_locator(index))

    meta = [(i, p) for i, (label, p) in nodes.items() if label == "META_DATA"]
    if len(meta) > 1:
        raise AnalysisArtifactError(E.CONTRADICTORY, "more than one META_DATA node", _node_locator(meta[1][0]))
    spec_version: Optional[str] = None
    content_hash = language = None
    if meta:
        props = meta[0][1]
        spec_version = props.get("VERSION") or None
        content_hash = props.get("HASH") or None
        language = props.get("LANGUAGE") or None
        if spec_version is not None and spec_version not in SUPPORTED_CPG_SPEC_VERSIONS:
            raise AnalysisArtifactError(E.FORMAT_VERSION_UNSUPPORTED,
                                        f"CPG specification version {spec_version!r} is not supported", _node_locator(meta[0][0]))
        if spec_version is None:
            diagnostics.append(AnalysisDiagnostic("CPG_SPEC_VERSION_ABSENT", "META_DATA has no VERSION", _node_locator(meta[0][0])))
    else:
        diagnostics.append(AnalysisDiagnostic("NO_META_DATA", "no META_DATA node: language, root and source hash are unknown"))

    methods = []
    for node_id, (label, props) in nodes.items():
        if label != "METHOD":
            continue
        external = props.get("IS_EXTERNAL")
        flag: Optional[bool] = {"true": True, "false": False}.get((external or "").strip().lower())
        if external is not None and flag is None:
            diagnostics.append(AnalysisDiagnostic("IS_EXTERNAL_UNPARSEABLE", f"IS_EXTERNAL={external!r}", _node_locator(node_id)))
        methods.append(MethodNode(node_id, _node_locator(node_id), props.get("FULL_NAME") or None, props.get("NAME") or None,
                                  props.get("FILENAME") or None, flag))

    container: dict[str, str] = {}   # CALL node id -> containing METHOD node id
    for index, source, target, label, _ in edges:
        if label != "CONTAINS":
            continue
        kinds = {source: nodes[source][0], target: nodes[target][0]}
        method_ends = [n for n, k in kinds.items() if k == "METHOD"]
        call_ends = [n for n, k in kinds.items() if k == "CALL"]
        if len(method_ends) == 1 and len(call_ends) == 1:  # direction-agnostic (see the module docstring)
            call, method = call_ends[0], method_ends[0]
            if container.setdefault(call, method) != method:
                raise AnalysisArtifactError(E.CONTRADICTORY, f"call site {call!r} is contained in two methods", _edge_locator(index))

    call_edges: list[CallEdge] = []
    call_edge_count = 0
    uncontained = 0
    for index, source, target, label, _ in edges:
        if label != "CALL":
            continue
        call_edge_count += 1
        if nodes[source][0] != "CALL" or nodes[target][0] != "METHOD":
            raise AnalysisArtifactError(E.STRUCTURE_INVALID,
                                        f"a CALL edge must run from a CALL node to a METHOD node, not {nodes[source][0]} -> {nodes[target][0]}",
                                        _edge_locator(index))
        caller = container.get(source)
        if caller is None:
            uncontained += 1
            continue
        call_edges.append(CallEdge(caller, target, source, _edge_locator(index)))
    if uncontained:
        diagnostics.append(AnalysisDiagnostic("CALL_SITE_WITHOUT_CONTAINING_METHOD",
                                              f"{uncontained} CALL edge(s) have a call site with no containing METHOD and cannot be used"))
    if call_edge_count == 0:
        diagnostics.append(AnalysisDiagnostic("NO_CALL_EDGES", "the export contains no CALL edges: it is not a call-graph export"))
    diagnostics.append(AnalysisDiagnostic("LIST_PROPERTIES_NOT_EXPORTED",
                                          "the GraphML exporter drops list properties (for example OVERLAYS): which passes ran is unknown"))
    run = RunFacts(locator="#/graphml", tool=ToolIdentity(None, None, None), content_hash=content_hash, language=language,
                   result_count=len(call_edges))
    return NormalizedAnalysis(
        source=SourceArtifactIdentity(document_id("joern-graphml", raw), AnalysisFormat.JOERN_GRAPHML,
                                      f"cpg-spec:{spec_version}" if spec_version else None, len(raw)),
        runs=(run,), candidates=(), call_graph=CallGraph(tuple(methods), tuple(call_edges), call_edge_count),
        diagnostics=tuple(diagnostics),
    )
