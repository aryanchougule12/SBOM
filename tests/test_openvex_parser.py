"""Stage 0 structure tests for sbom_parser.openvex (stub only)."""

import pytest

from sbom_parser import openvex


def test_module_exposes_the_stub_interface():
    assert callable(openvex.parse_openvex)


def test_stub_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        openvex.parse_openvex(b"")


@pytest.mark.skip(reason="pending: OpenVEX parsing is not implemented and no fixtures exist yet")
def test_parses_an_openvex_document():
    raise AssertionError("placeholder")
