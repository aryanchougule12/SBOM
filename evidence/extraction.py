"""Evidence extraction interface (Stage 0 stub; NOT implemented).

Future role: derive ``EvidenceItem`` records for a ``Finding`` from its parsed source
documents (Step 2 inputs of ``docs/formal_specification_v0.2.md`` §3). This module
will not fabricate evidence: where nothing bears on a dimension the state is
``Unknown`` (P-2), and that rule is applied by a later stage.
"""

from __future__ import annotations

from model import EvidenceItem, Finding


def extract_evidence(finding: Finding) -> list[EvidenceItem]:
    """Extract evidence items for ``finding``. Not implemented at Stage 0."""
    raise NotImplementedError("Stage 0 stub: evidence extraction is not implemented.")
