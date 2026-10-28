"""The approved inventory-member domain of a parsed SBOM, with the components themselves.

Register D1 (this milestone): the member domain of a document is

* CycloneDX: every top-level ``components`` entry (recursively, pre-order) **and** every
  component nested under ``metadata.component`` (recursively, pre-order);
* SPDX 2.3: every ``packages`` entry.

It does not include the subject itself (``metadata.component``, the described artifact), CycloneDX
``services``, SPDX ``files`` and ``snippets``, pedigree objects or tool components. Membership is
a statement about which parsed records are searched; it is not a claim that the records are the
full inventory for S (that is the evaluator's attested ``full_component_list`` statement, and
INV derivation).

``domain_extracted`` is False when the document's stored metadata did not carry the list of
components nested under the subject (see ``SbomRecord.subject_components_extracted``): the domain
is then not known to be complete, and a search over it can never support ``Absent``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from evidence.inventory_observations import locator_sort_key
from evidence.stage1_records import SbomRecord
from model import Component

ORIGIN_LISTED = "listed"
ORIGIN_SUBJECT_NESTED = "subject_nested"


@dataclass(frozen=True)
class InventoryMember:
    """A component of the member domain. ``origin`` is ``listed`` or ``subject_nested``."""

    doc_id: str
    locator: str
    origin: str
    component: Component
    declared_type: Optional[str]


@dataclass(frozen=True)
class InventoryMembers:
    """The member domain of one document, sorted by locator (numeric-aware)."""

    doc_id: str
    members: tuple[InventoryMember, ...]
    domain_extracted: bool

    def locator_prefixes(self) -> tuple[str, ...]:
        """The list-level locators that actually exist in the document for these members
        (``#/components``, ``#/metadata/component/components``, ``#/packages``), sorted."""
        found: set[str] = set()
        for member in self.members:
            if member.locator.startswith("#/components/"):
                found.add("#/components")
            elif member.locator.startswith("#/metadata/component/components/"):
                found.add("#/metadata/component/components")
            elif member.locator.startswith("#/packages/"):
                found.add("#/packages")
        return tuple(sorted(found))


def inventory_members(record: SbomRecord) -> InventoryMembers:
    """The approved member domain of ``record``. Pure and deterministic."""
    members = [
        InventoryMember(record.doc_id, entry["locator"], ORIGIN_LISTED, component,
                        entry.get("type") if isinstance(entry.get("type"), str) else None)
        for component, entry in zip(record.components, record.component_index)
    ]
    members += [
        InventoryMember(record.doc_id, located.locator, ORIGIN_SUBJECT_NESTED, located.component, located.declared_type)
        for located in record.subject_components
    ]
    ordered = tuple(sorted(members, key=lambda m: (locator_sort_key(m.locator), m.origin)))
    return InventoryMembers(record.doc_id, ordered, record.subject_components_extracted)
