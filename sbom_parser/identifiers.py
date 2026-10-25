"""Deterministic identifier-variant derivation, rule version ``variant-norm-v1``.

Purpose. ``Component.identifier_variants`` records auditable, reproducible search keys
derived from the identifiers a document supplied. The originals are NEVER replaced:
they stay verbatim in ``Component.purl``, ``Component.cpe``, ``Component.name``,
``Component.version`` and ``Component.hashes``. Each derived variant carries
``normalization_rule_version = VARIANT_NORMALIZATION_VERSION``.

``variant-norm-v1`` is purely syntactic:

* purl  -- surrounding whitespace removed; the scheme and the package type (the text
  up to the first ``/`` after ``pkg:``) lower-cased. Namespace, name, version,
  qualifiers and subpath are left exactly as supplied, because their case sensitivity
  depends on the package type.
* CPE   -- surrounding whitespace removed and the whole string lower-cased (CPE
  attribute comparison is case-insensitive). CPE 2.2 and 2.3 strings are NOT converted
  into one another.
* name+version -- ``<name>@<version>`` with the name whitespace-trimmed and
  case-folded and the version whitespace-trimmed only (no ``v`` prefix handling, no
  range handling). With no version the kind is ``name``. An empty name yields no
  variant.
* hash  -- kind ``hash:<alg>`` where ``<alg>`` is the algorithm lower-cased with ``-``
  and ``_`` removed (``SHA-256`` and ``SHA256`` both give ``sha256``) and the value is
  trimmed and lower-cased.

Limits of equivalence. A variant is a search key, not a claim. Two components with
equal variants have not been shown to be the same real-world component, and two
components with different variants have not been shown to differ. Forks, renames,
repackaging, vendored copies and ecosystem-specific name normalization (for example
PyPI ``-``/``_``/``.`` folding) are deliberately NOT handled. Variants are never
deduplicated, so each original identifier keeps its own audit entry. Matching a
component against a vulnerability is a later stage.
"""

from __future__ import annotations

from typing import Optional, Sequence

from model import Hash, IdentifierVariant

VARIANT_NORMALIZATION_VERSION = "variant-norm-v1"


def normalize_purl(value: str) -> str:
    text = value.strip()
    scheme, separator, rest = text.partition(":")
    if not separator:
        return text
    scheme = scheme.lower()
    if scheme != "pkg":
        return f"{scheme}:{rest}"
    package_type, slash, tail = rest.partition("/")
    return f"pkg:{package_type.lower()}{slash}{tail}"


def normalize_cpe(value: str) -> str:
    return value.strip().lower()


def normalize_name(value: str) -> str:
    return value.strip().casefold()


def normalize_hash_algorithm(value: str) -> str:
    return value.strip().lower().replace("-", "").replace("_", "")


def normalize_hash_value(value: str) -> str:
    return value.strip().lower()


def build_identifier_variants(
    name: str,
    version: Optional[str],
    purl: Optional[str],
    cpes: Sequence[str],
    hashes: Sequence[Hash],
) -> list[IdentifierVariant]:
    """Derive variants in a fixed order: purl, each CPE, name(+version), each hash."""
    rule = VARIANT_NORMALIZATION_VERSION
    variants: list[IdentifierVariant] = []
    if purl:
        variants.append(IdentifierVariant("purl", normalize_purl(purl), rule))
    for cpe in cpes:
        variants.append(IdentifierVariant("cpe", normalize_cpe(cpe), rule))
    normalized_name = normalize_name(name)
    if normalized_name:
        if version is not None and version.strip():
            variants.append(
                IdentifierVariant("name+version", f"{normalized_name}@{version.strip()}", rule)
            )
        else:
            variants.append(IdentifierVariant("name", normalized_name, rule))
    for digest in hashes:
        variants.append(
            IdentifierVariant(
                f"hash:{normalize_hash_algorithm(digest.algorithm)}",
                normalize_hash_value(digest.value),
                rule,
            )
        )
    return variants
