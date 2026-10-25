"""OpenVEX document parser interface (Stage 0 stub; NOT implemented).

Future role: read an OpenVEX document and return its provenance as a
``SourceDocument`` plus one ``Finding`` skeleton per ``not_affected`` statement
(component, vulnerability, disposition, justification and scope as far as the
document states them). The skeletons carry no evidence: evidence comes from SBOM
and analysis documents, never from the VEX claim itself.

No OpenVEX version is claimed to be supported. Support will be declared only once a
later stage implements and tests it.
"""

from __future__ import annotations

import os
from typing import Union

from model import Finding, SourceDocument

VEXSource = Union[str, bytes, "os.PathLike[str]"]


def parse_openvex(source: VEXSource) -> tuple[SourceDocument, list[Finding]]:
    """Parse an OpenVEX document into ``(SourceDocument, finding skeletons)``.

    Not implemented at Stage 0.
    """
    raise NotImplementedError("Stage 0 stub: OpenVEX parsing is not implemented.")
