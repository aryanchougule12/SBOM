# Specification Addendum v0.2.1

This addendum is a changelog for the N16 correction. The changes below are present in `docs/formal_specification_v0.2.md` (rule N16 in §4.2 and §4.3, the Supported conditions in §4.4, test cases NT10 and NT14 in §4.7).

## N16 correction

- Added **N16**: when a separate content-based corroborating document is relied upon to remove N14/N15, effective provenance below P3 gives **Weak** with code `CORROBORATION_PROVENANCE_BELOW_P3`.
- Clarified: a P1/P2 content-based corroborating scan may remove the N14/N15 ceiling, but it triggers N16 and yields at most Weak. It cannot, by itself, support a Supported verdict.
- **P3 rule for separate corroborating documents:** per §1.2 rule 5 (minimum-across-documents), a separate document relied upon to reach Supported must independently meet the P3 floor. It cannot borrow the primary SBOM's provenance.
- **NT10 updated:** to remain Supported, the separate content-based layer scan must have effective provenance P3.
- **NT14 added:** the otherwise equivalent separate layer scan at P1 produces Weak with N16.
- §4.4 (Supported conditions) now requires, for binary or container artifacts, a content-based basis whose EP is P3 when it is a separate corroborating document, and that none of N1–N16 is triggered.

## `PROV_CORR` clarification

`PROV_CORR` remains a defined role in §1.2 for cases where the content-based basis is a document separate from the primary SBOM. It is simply not instantiated as a distinct value when the primary SBOM itself serves as its own content-based basis—in that case `PROV_SBOM` is reused directly, per §4.3.

## Related clarifications in the same revision of the specification file

These are not part of the N16 correction but are present in the final specification:

- §2: aggregation rules restated so that a positive observation (`Present`) is not erased by other `Incomplete` evidence, plus acceptance cases AG1–AG5 (AG1: `Present` + `Incomplete` without a conflicting `Absent` aggregates to `Present`).
- §1.3, §4.3: `generation_context` alone never establishes a manifest-only method or triggers N14. An unknown or unstated method for a binary or container finding without a qualifying content-based basis triggers N15 (Weak). NT16 added.
- §7: D-6 states that CISA element names and the release date were cross-checked against secondary sources only. U-1 records that the primary CISA document has not been independently read. The `PROV_HAZ` P1 floor is recorded as an intentional profile choice, and U-5 is a non-blocking future-profile consideration.
