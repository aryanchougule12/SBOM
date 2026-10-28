"""Adapter from the derived evidence items to the inputs of the CNP engine.

The engine (``evidence.cnp_rules``) is a pure function of already computed dimension states.
This module computes those states from the evidence items -- one aggregation per dimension with
the existing section 2 procedure (``evidence.aggregation``, including its provisional G8 overlap
convention) -- and assembles ``CnpInputs`` without adding anything:

* INV, MATCH and DECL are the aggregates of their items; a dimension with no item aggregates to
  `Unknown` (`NO_ITEMS`), never to a state it was not given.
* BIND is the typed ``BindEvaluation`` state (it is not an item).
* ``PROV_SBOM`` and ``PROV_DECL`` are supplied by the caller, already computed from document
  provenance and list/record locators; ``PROV_DECL`` is required (and only used) when DECL is
  `Present`.
* GEN is the (always `unknown`) derivation; ``separate_basis`` is ``None`` (corroborating documents
  are not evaluated) and the N13 flag is ``False`` (no second source to contradict provenance
  metadata).

It evaluates no rule and produces no verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from evidence.aggregation import AggregationResult, aggregate
from evidence.bind import BindEvaluation
from evidence.cnp_rules import CnpInputs, GenState
from evidence.items import DIM_DECL, DIM_INV, DIM_MATCH, items_of
from model import ArtifactKind, EvidenceItem, EvidenceState, ProvenanceLevel


@dataclass(frozen=True)
class DimensionAggregates:
    inv: AggregationResult
    match: AggregationResult
    decl: AggregationResult


def aggregate_dimensions(items: Iterable[EvidenceItem]) -> DimensionAggregates:
    collected = list(items)
    return DimensionAggregates(
        inv=aggregate(items_of(collected, DIM_INV)),
        match=aggregate(items_of(collected, DIM_MATCH)),
        decl=aggregate(items_of(collected, DIM_DECL)),
    )


def build_cnp_inputs(
    artifact_kind: ArtifactKind,
    aggregates: DimensionAggregates,
    bind: BindEvaluation,
    prov_sbom: ProvenanceLevel,
    prov_decl: Optional[ProvenanceLevel],
    gen: GenState = GenState.UNKNOWN,
) -> CnpInputs:
    """``CnpInputs`` from the aggregates, the BIND result and the computed provenance roles."""
    decl_state = aggregates.decl.state
    return CnpInputs(
        artifact_kind=artifact_kind,
        inv=aggregates.inv.state,
        match=aggregates.match.state,
        decl=decl_state,
        bind=bind.state,
        prov_sbom=prov_sbom,
        prov_decl=prov_decl if decl_state is EvidenceState.PRESENT else None,
        gen=gen,
        separate_basis=None,
        provenance_metadata_contradiction=False,
    )
