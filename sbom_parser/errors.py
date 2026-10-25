"""Parser exceptions for the SBOM and OpenVEX parsers (Stage 1).

All parser failures derive from ``ParserError`` so callers can catch them together.
A parser never returns an empty or partial result for invalid input; it raises one of
these instead.

* ``MalformedInputError``   -- the bytes are not a usable JSON object (not UTF-8,
  not JSON, duplicate object keys, non-standard JSON constants, or the top-level
  value is not an object).
* ``UnsupportedVersionError`` -- the document is recognisably the right format but
  declares a version this parser does not support.
* ``InvalidDocumentError``  -- well-formed JSON that is structurally invalid for the
  format: a required field is missing, a field has the wrong type, or the document is
  not the expected format at all.

Every exception may carry a ``locator`` (a JSON Pointer in URI-fragment form, for
example ``#/components/0/name``) naming the offending part of the document.
"""

from __future__ import annotations

from typing import Optional


class ParserError(Exception):
    """Base class for all parser failures."""

    def __init__(self, message: str, locator: Optional[str] = None) -> None:
        self.locator = locator
        self.message = message
        super().__init__(f"{message} (at {locator})" if locator else message)


class MalformedInputError(ParserError):
    """The input is not a usable JSON object."""


class UnsupportedVersionError(ParserError):
    """The document declares a format version this parser does not support."""


class InvalidDocumentError(ParserError):
    """The document is well-formed JSON but structurally invalid for the format."""
