"""GEN derivation (specification section 4.1, section 4.3; register G14, D10 deferred).

GEN is "the declared generation method of the primary SBOM, evaluated relative to C specifically":
`manifest_only`, `content_based` (which needs a documented content-based method, whole artifact
coverage, ecosystem coverage that includes ``C.ecosystem``, BIND and EP >= P1) or `unknown`.

No source-backed input establishes any of that today: no parser sets ``method`` (CycloneDX and SPDX
state no generation method), ``Component.ecosystem`` is never set, there is no declared artifact or
ecosystem coverage, and there is no controlled vocabulary (U-3, U-7, G14). The evaluator-entered
``generation_assertions`` block was deliberately **not** added (decision D10 is deferred). So this
function always returns `unknown` and says why. It never classifies from ``generation_context``,
the tool name, the SBOM format or the artifact kind ([S] section 4.3: ``generation_context`` alone
never establishes a method), and it does not fabricate a content-based basis.

For binary and container artifacts the engine therefore applies N15 (Weak, "generation method
unknown"), as the specification says for an unestablished method.
"""

from __future__ import annotations

from dataclasses import dataclass

from evidence.cnp_rules import GenState
from evidence.stage1_records import SbomRecord

GEN_LIMITATION = (
    "GEN_INPUT_UNAVAILABLE: no source-backed input establishes the generation method, artifact "
    "coverage or ecosystem coverage (register G14; evaluator-entered generation assertions are deferred, D10)"
)


@dataclass(frozen=True)
class GenDerivation:
    state: GenState
    reason: str
    doc_id: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.state is not GenState.UNKNOWN:
            raise ValueError("no approved input can establish GEN beyond 'unknown' in this milestone")


def derive_gen(record: SbomRecord) -> GenDerivation:
    """GEN of the primary SBOM relative to C: always `unknown` (see the module docstring)."""
    limitations = [GEN_LIMITATION]
    if record.document.method is not None:
        limitations.append("a method string is stated but is not classified (no controlled vocabulary)")
    return GenDerivation(GenState.UNKNOWN, "GEN_INPUT_UNAVAILABLE", record.doc_id, tuple(limitations))
