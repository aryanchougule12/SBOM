"""CycloneDX SBOM parser interface (Stage 0 stub; NOT implemented).

Future role: read a CycloneDX document and return its provenance as a
``SourceDocument`` plus the components it lists as ``Component`` records. Intended
inputs are a filesystem path or raw bytes; intended outputs are model objects only.
It will not compute effective provenance, aggregate evidence, or judge completeness.

No CycloneDX schema version is claimed to be supported. Version support will be
declared only once a later stage implements and tests it.
"""

from __future__ import annotations

import os
from typing import Union

from model import Component, SourceDocument

SBOMSource = Union[str, bytes, "os.PathLike[str]"]


def parse_cyclonedx(source: SBOMSource) -> tuple[SourceDocument, list[Component]]:
    """Parse a CycloneDX SBOM into ``(SourceDocument, components)``.

    Not implemented at Stage 0.
    """
    raise NotImplementedError("Stage 0 stub: CycloneDX parsing is not implemented.")
