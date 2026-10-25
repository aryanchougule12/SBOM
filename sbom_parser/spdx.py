"""SPDX SBOM parser interface (Stage 0 stub; NOT implemented).

Future role: read an SPDX document and return its provenance as a
``SourceDocument`` plus the packages it lists as ``Component`` records. Intended
inputs are a filesystem path or raw bytes; intended outputs are model objects only.
It will not compute effective provenance, aggregate evidence, or judge completeness.

No SPDX version or serialization is claimed to be supported. Support will be
declared only once a later stage implements and tests it.
"""

from __future__ import annotations

import os
from typing import Union

from model import Component, SourceDocument

SBOMSource = Union[str, bytes, "os.PathLike[str]"]


def parse_spdx(source: SBOMSource) -> tuple[SourceDocument, list[Component]]:
    """Parse an SPDX SBOM into ``(SourceDocument, components)``.

    Not implemented at Stage 0.
    """
    raise NotImplementedError("Stage 0 stub: SPDX parsing is not implemented.")
