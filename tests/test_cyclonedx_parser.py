"""Stage 0 structure tests for sbom_parser.cyclonedx (stub only)."""

import pytest

from sbom_parser import cyclonedx


def test_module_exposes_the_stub_interface():
    assert callable(cyclonedx.parse_cyclonedx)


def test_stub_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        cyclonedx.parse_cyclonedx(b"")


@pytest.mark.skip(reason="pending: CycloneDX parsing is not implemented and no fixtures exist yet")
def test_parses_a_cyclonedx_document():
    raise AssertionError("placeholder")
