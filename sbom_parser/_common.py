"""Shared low-level helpers for the Stage 1 parsers (private to ``sbom_parser``).

Nothing here interprets document content. The helpers read bytes, decode strict JSON,
build locators and type-check fields. No network access and no non-determinism.

Locator convention: JSON Pointers (RFC 6901) in URI-fragment form. ``#`` is the whole
document and ``#/components/0`` the first array element of ``components``.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any, Iterable, Optional, Union

from sbom_parser.errors import InvalidDocumentError, MalformedInputError

InputSource = Union[str, bytes, "os.PathLike[str]"]

ASSERTION_STATUS = "self_asserted_unverified"
LOCATOR_CONVENTION = "json-pointer-uri-fragment"


def read_source(source: InputSource) -> bytes:
    """Return the raw document bytes.

    ``bytes`` are the document itself; ``str`` and path-like values are filesystem
    paths. A missing or unreadable file raises the usual ``OSError`` subclass.
    """
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as handle:
            return handle.read()
    raise TypeError(f"source must be bytes, str or os.PathLike, not {type(source).__name__}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MalformedInputError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise MalformedInputError(f"non-standard JSON constant {name!r} is not allowed")


def load_json_object(raw: bytes, format_name: str) -> dict[str, Any]:
    """Strictly decode ``raw`` as a UTF-8 JSON object, or raise ``MalformedInputError``."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedInputError(f"{format_name} input is not valid UTF-8: {exc}") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        raise MalformedInputError(f"{format_name} input is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MalformedInputError(f"{format_name} top-level JSON value must be an object")
    return data


def ptr(*parts: Union[str, int]) -> str:
    """Build a JSON Pointer in URI-fragment form; ``ptr()`` is ``'#'``."""
    return "#" + "".join(
        "/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts
    )


def canonical_json(value: Any) -> str:
    """Deterministic JSON text (sorted keys, no insignificant whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def document_id(prefix: str, raw: bytes) -> str:
    """Content-derived, deterministic document id: ``<prefix>:sha256:<hex>``."""
    return f"{prefix}:sha256:{hashlib.sha256(raw).hexdigest()}"


def parse_timestamp(value: str, locator: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 date-time; a trailing ``Z`` means UTC."""
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvalidDocumentError(f"invalid date-time {value!r}", locator) from exc


# ---- typed field access -------------------------------------------------------------

def get_object(parent: dict[str, Any], key: str, locator: str) -> Optional[dict[str, Any]]:
    if key not in parent:
        return None
    value = parent[key]
    if not isinstance(value, dict):
        raise InvalidDocumentError(f"{key!r} must be an object", ptr_join(locator, key))
    return value


def get_list(parent: dict[str, Any], key: str, locator: str) -> list[Any]:
    if key not in parent:
        return []
    value = parent[key]
    if not isinstance(value, list):
        raise InvalidDocumentError(f"{key!r} must be an array", ptr_join(locator, key))
    return value


def get_str(
    parent: dict[str, Any], key: str, locator: str, *, required: bool = False
) -> Optional[str]:
    if key not in parent:
        if required:
            raise InvalidDocumentError(f"required field {key!r} is missing", locator)
        return None
    value = parent[key]
    if not isinstance(value, str):
        raise InvalidDocumentError(f"{key!r} must be a string", ptr_join(locator, key))
    return value


def require_str(parent: dict[str, Any], key: str, locator: str) -> str:
    """Like ``get_str(..., required=True)`` but typed as always returning a string."""
    value = get_str(parent, key, locator, required=True)
    if value is None:  # unreachable: required=True raises when the key is absent
        raise InvalidDocumentError(f"required field {key!r} is missing", locator)
    return value


def require_object(value: Any, locator: str, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidDocumentError(f"{what} must be an object", locator)
    return value


def str_list(parent: dict[str, Any], key: str, locator: str) -> list[str]:
    items = get_list(parent, key, locator)
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise InvalidDocumentError(
                f"{key!r} entries must be strings", ptr_join(locator, key, index)
            )
    return list(items)


def ptr_join(locator: str, *parts: Union[str, int]) -> str:
    """Extend an existing fragment locator with more pointer segments."""
    return locator + ptr(*parts)[1:]


def unextracted_keys(obj: dict[str, Any], handled: Iterable[str]) -> list[str]:
    """Sorted names of keys in ``obj`` that the parser does not interpret."""
    handled_set = set(handled)
    return sorted(key for key in obj if key not in handled_set)
