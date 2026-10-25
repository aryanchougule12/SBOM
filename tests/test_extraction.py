"""Stage 0 structure tests for evidence.extraction (stub only)."""

import pytest

from evidence import extraction


def test_module_exposes_the_stub_interface():
    assert callable(extraction.extract_evidence)


def test_stub_is_honestly_unimplemented():
    with pytest.raises(NotImplementedError):
        extraction.extract_evidence(None)  # type: ignore[arg-type]


@pytest.mark.skip(reason="pending: evidence extraction is not implemented")
def test_extracts_evidence_items_from_source_documents():
    raise AssertionError("placeholder")
