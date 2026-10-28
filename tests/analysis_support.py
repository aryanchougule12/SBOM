"""Helpers for the analyzer-artifact tests. Fixtures under fixtures/analysis are either upstream files or
SYNTHETIC (see fixtures/analysis/README.md); nothing here is a live analyzer run."""

import json

from evidence.analysis_binding import AnalysisSubject, parse_analysis_subject
from evidence.analysis_ingest import evaluate_with_analysis
from evidence.reach_inputs import LocusInput, parse_reachability
from evidence.stage1_records import Stage1Index
from tests.analysis_eval import ANALYSIS_DIR, load_manifest
from tests.pipeline_support import equivalent, make_profile, vex_findings

SARIF_DIR = ANALYSIS_DIR / "sarif"
GRAPHML_DIR = ANALYSIS_DIR / "joern-graphml"
UPSTREAM_DIR = ANALYSIS_DIR / "upstream"
REPO = "https://example.org/git/app.git"
REV = "0123456789abcdef0123456789abcdef01234567"
HASH = "9f2b6c1d4e7a8b30"
PARSE = "lib.b.Parser.parse:java.lang.Object(java.lang.String)"
MAIN = "app.Main.main:void(java.lang.String[])"


def subject(**changes) -> AnalysisSubject:
    data = json.loads(json.dumps(load_manifest()["defaults"]["subject"]))
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return parse_analysis_subject(data)


def locus(**changes) -> LocusInput:
    data = dict(load_manifest()["defaults"]["locus"])
    data.update(changes)
    return parse_reachability({"schema_version": "1", "locus": data}).locus


def base_evidence(**locus_changes):
    data = dict(load_manifest()["defaults"]["locus"])
    data.update(locus_changes)
    return parse_reachability({"schema_version": "1", "locus": data, "configuration": {"deployment_config_id": "prod"}})


def evaluate(path, *, subj=None, base="default", verification=None, kind="cdx", findings=None):
    record = equivalent(kind)
    base = base_evidence() if base == "default" else base
    artifacts = [] if path is None else [path]
    return evaluate_with_analysis(make_profile(record.doc_id), vex_findings("reachability_equivalent.json") if findings is None else findings,
                                  Stage1Index([record]), artifacts, subj or subject(), base, verification)


def resolve_pointer(document, pointer: str):
    """Resolve a JSON Pointer in URI-fragment form against a decoded JSON document."""
    assert pointer.startswith("#")
    node = document
    for part in [p for p in pointer[1:].split("/") if p]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node
