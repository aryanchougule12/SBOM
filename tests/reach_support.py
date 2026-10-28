"""Shared helpers for the reachability tests (fixtures, evidence builders, runners).

Test support only: nothing here is part of the evaluator. Every reachability document built here is a
SYNTHETIC fixture (see ``fixtures/reachability/README.md``); none is real analyser output. Verification
inputs are synthetic and exist solely so that tests can exercise the P3 path; no cryptography happens.
"""

import copy
import json
from dataclasses import dataclass
from typing import Callable, Optional

from evidence.cnp_rules import BindState
from evidence.reach_inputs import ReachabilityEvidence, parse_reachability
from evidence.reach_rules import (
    CfgState,
    HazardClass,
    HazardDisposition,
    HazardInput,
    ReachBasis,
    ReachInputs,
)
from evidence.stage1_records import Stage1Index
from evidence.sufficiency import evaluate_finding
from evidence.verification import VerificationConfig, VerificationResult
from model import EvidenceState as S, ProvenanceLevel as P
from reports.verdict import Verdict
from tests.pipeline_support import FIXTURES, equivalent, make_profile, vex_findings

REACH_FIXTURES = FIXTURES / "reachability"
ALL_CLASSES = tuple(sorted(HazardClass, key=lambda c: c.value))
CLASS_NAMES = tuple(c.value for c in ALL_CLASSES)
VEX = "reachability_equivalent.json"


# ---- pure-engine inputs (RT1 baseline) -----------------------------------------------------------------

def modeled():
    return HazardInput(HazardDisposition.MODELED_CONSERVATIVELY, declared_in_k1=True)


def excluded(ep=P.P1, bound=True):
    return HazardInput(HazardDisposition.EXCLUDED_BY_EVIDENCE, bound, ep)


def baseline_hazards():
    """RT1: reflection Excluded with basis EP = P1, every other class Modeled."""
    hazards = {c: modeled() for c in HazardClass}
    hazards[HazardClass.REFLECTION] = excluded(P.P1)
    return hazards


def inputs(**changes):
    """The RT1 baseline: K1 Absent, LOCUS/ENTRY Present, BIND matched, CFG declared, PROV_REACH = P3."""
    values = dict(reach=S.ABSENT, reach_basis=ReachBasis.K1, locus=S.PRESENT, entry=S.PRESENT, bind=BindState.MATCHED,
                  cfg=CfgState.DECLARED, prov_reach=P.P3, hazards=baseline_hazards())
    values.update(changes)
    return ReachInputs(**values)


def all_hazards(factory):
    return {c: factory() for c in HazardClass}


# ---- evidence documents (synthetic) --------------------------------------------------------------------------

def baseline_data():
    """A fresh, mutable copy of ``fixtures/reachability/synthetic_baseline.json``."""
    return json.loads((REACH_FIXTURES / "synthetic_baseline.json").read_text())


def fixture_data(name):
    return json.loads((REACH_FIXTURES / f"{name}.json").read_text())


def doc(data, doc_id):
    return next(d for d in data["documents"] if d["doc_id"] == doc_id)


def with_k1(data, **changes):
    data = copy.deepcopy(data)
    doc(data, "k1-analysis").update(changes)
    return data


def replace_k1(data, kind, finding, doc_id=None, **extra):
    """Replace the baseline K1 report by a document of another kind (keeping attribution and binding)."""
    data = copy.deepcopy(data)
    base = doc(data, "k1-analysis")
    keep = {k: base[k] for k in ("producer", "producer_class", "tool_name", "tool_version", "created", "artifact", "target",
                                 "analyzed_configurations") if k in base}
    index = data["documents"].index(base)
    data["documents"][index] = dict(doc_id=doc_id or "k1-analysis", kind=kind, finding=finding, **keep, **extra)
    return data


def add_doc(data, **document):
    data = copy.deepcopy(data)
    base = doc(data, "reflection-basis")
    entry = {k: base[k] for k in ("producer", "producer_class", "tool_name", "tool_version", "created", "artifact", "target")}
    entry.update(document)
    data["documents"].append(entry)
    return data


def evidence(data) -> ReachabilityEvidence:
    return parse_reachability(data)


def verified(*doc_ids, coverage=("#",), anchor="anchor-1", verified_flag=True):
    results = tuple(VerificationResult(d, verified_flag, anchor, "external-verifier", "1.0", tuple(coverage)) for d in doc_ids)
    return VerificationConfig(frozenset({anchor}), results)


# ---- end-to-end runners ----------------------------------------------------------------------------------------

def run(kind="cdx", data=None, *, verification=None, vex=VEX, record=None, profile=None, reachability="default", findings=None,
        **profile_kwargs):
    """Run the whole path from a real parser fixture to the evaluator outcome or refusal."""
    record = record if record is not None else equivalent(kind)
    findings = vex_findings(vex) if findings is None else findings
    profile = profile if profile is not None else make_profile(record.doc_id, **profile_kwargs)
    if reachability == "default":
        reachability = evidence(baseline_data() if data is None else data)
    return evaluate_finding(profile, findings, Stage1Index([record]), verification, reachability)


# ---- RT1-RT11 as end-to-end cases (shared by the evaluator tests and the conformance harness) -----------------------

@dataclass(frozen=True)
class PipelineCase:
    """One of RT1-RT11 realised with synthetic reachability documents against a real SBOM fixture.
    ``rules`` is the exact set of triggered rule ids; ``first_codes`` the leading codes of the result."""

    case_id: str
    data: Callable[[], dict]
    verification: Callable[[], Optional[VerificationConfig]]
    verdict: Verdict
    rules: tuple
    first_codes: tuple


def _rt2_data():
    return {"schema_version": "1", "locus": baseline_data()["locus"], "configuration": {"deployment_config_id": "prod"}}


def _rt4_data():
    return add_doc(baseline_data(), doc_id="k3-hit", kind="K3", finding="positive", analyzed_configurations=["prod"])


def _rt7_data():
    data = baseline_data()
    doc(data, "reflection-basis").pop("tool_version")  # unattributed basis: EP = P0
    return data


def _rt10_data():
    data = replace_k1(baseline_data(), "K2", "negative", doc_id="k2-assertion")
    data["entry_points"] = {"complete": True, "entered_by": "synthetic-evaluator"}
    data["hazards"] = fixture_data("synthetic_k3_no_hit")["hazards"]
    return data


_V = lambda *ids: (lambda: verified(*ids))  # noqa: E731
_NONE = lambda: None  # noqa: E731

RT_PIPELINE_CASES = (
    PipelineCase("RT1", baseline_data, _V("k1-analysis"), Verdict.SUPPORTED, (), ()),
    PipelineCase("RT2", _rt2_data, _NONE, Verdict.INSUFFICIENT, ("R2", "R5", "R11"), ("MISSING_EDGE_IS_UNKNOWN", "ENTRYPOINTS_UNDECLARED")),
    PipelineCase("RT3", lambda: {**baseline_data(), "hazards": []}, _V("k1-analysis"), Verdict.WEAK, ("R11",), ("HAZARD_REFLECTION",)),
    PipelineCase("RT4", _rt4_data, _V("k1-analysis"), Verdict.INSUFFICIENT, ("R3", "R13"), ("REACH_CONFLICT",)),
    PipelineCase("RT5", lambda: with_k1(baseline_data(), finding="incomplete"), _V("k1-analysis"), Verdict.WEAK, ("R8",),
                 ("PARTIAL_OR_UNRESOLVED_CALLGRAPH",)),
    PipelineCase("RT6", lambda: with_k1(baseline_data(), finding="ambiguous"), _V("k1-analysis"), Verdict.WEAK, ("R8",),
                 ("PARTIAL_OR_UNRESOLVED_CALLGRAPH",)),
    PipelineCase("RT7", _rt7_data, _V("k1-analysis"), Verdict.WEAK, ("R11",),
                 ("HAZARD_REFLECTION", "HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION")),
    PipelineCase("RT8", baseline_data, _NONE, Verdict.WEAK, ("R13",), ("ANALYSIS_PROVENANCE_BELOW_P3",)),
    PipelineCase("RT9", lambda: fixture_data("synthetic_k3_no_hit"), _V("k3-trace"), Verdict.WEAK, ("R7",), ("NON_EXHAUSTIVE_EVIDENCE",)),
    PipelineCase("RT10", _rt10_data, _V("k2-assertion"), Verdict.WEAK, ("R7",), ("NON_EXHAUSTIVE_EVIDENCE",)),
    PipelineCase("RT11", lambda: fixture_data("synthetic_k2_p0"), _NONE, Verdict.INSUFFICIENT, ("R2",), ("NO_ANALYSIS",)),
)
