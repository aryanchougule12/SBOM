"""Stage 0 structure tests for sbom_parser.spdx (stub only)."""

import pytest

from sbom_parser import spdx


def test_module_exposes_the_stub_interface():
    assert callable(spdx.parse_spdx)


def test_stub_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        spdx.parse_spdx(b"")


@pytest.mark.skip(reason="pending: SPDX parsing is not implemented and no fixtures exist yet")
def test_parses_an_spdx_document():
    raise AssertionError("placeholder")
