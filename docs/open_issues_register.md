# Open Issues Register (Stage 2 design-gap audit)

> **WARNING: these gap identifiers are local working labels, not specification identifiers.**
> The IDs below (G1r, G3b-G3e, G4, G6-G11, G13-G17, G9r, G10) were assigned during the Stage 2
> design-gap audit of HEAD `cf062df32a1d257d62b087f8d6c6c11be34df586` and are **not** defined by
> `docs/formal_specification_v0.2.md` or `docs/spec_addendum_v0.2.1.md`. They are not
> rule IDs in the sense of N1-N17 / R1-R13 / NT / RT / AG / M / U / D / CE. Do not cite them
> as normative, and do not renumber them. The specification's own unresolved items (U-1, U-2,
> U-3, U-6, U-7, U-9, U-10, U-11) keep their own names and are cross-referenced here only
> where they overlap. Numbering has gaps by design: **there is no G5 row**, and G2, G3a and
> G12 are resolved prerequisites listed only in the cross-reference section at the end (they
> were not rows of the audit's gap register).

This file does not amend either protected specification document.

## How to read the status column

| Status | Meaning |
|---|---|
| **Specification-determined result** | A result fixed by the committed specification's own procedure, confirmed on review. Not a policy choice and not an implementation convention. |
| **Approved convention** | A decision explicitly approved for the current implementation. Not an amendment to the formal specification. |
| **Implementation convention (unconfirmed)** | A small choice made while implementing slice 1 that was not among the approved decisions. It can only lower a result or add a diagnostic. It needs explicit confirmation. |
| **Open** | A research-semantic or design decision that has not been made. Code must not guess it. |
| **Deferred** | Belongs to a later stage. |
| **Input limitation** | The model or parsers do not supply the required input. |

## Decision log: approved for the current implementation

| # | Gap | Decision | Where it takes effect |
|---|---|---|---|
| 1 | G3b | **Strict P1 attribution.** P1 requires a tool/process identity, a tool version and a timestamp, unless an explicitly represented evaluator-supplied process attestation provides the required information. (No representation of such an attestation exists yet.) | Recorded for later EP work. **Not implemented**: document-level EP (step 2) is out of slice 1. |
| 2 | G3c | **Canonical digest form.** Where digest normalization is needed, use normalized `alg:hex` (algorithm lower-cased with `-`/`_` removed, value trimmed and lower-cased, consistent with `sbom_parser/identifiers.py`). | Recorded for later EP/BIND work. **No BIND evaluation** is implemented. |
| 3 | G3d | **Locator containment** over complete JSON Pointer path segments, never a naive string prefix. A missing evidence locator (`None`) is outside coverage. | Isolated helper `evidence.provenance.locator_within` / `locator_within_any`. **EP step 3 (the signed-coverage cap) is not implemented.** |
| 4 | G4 | An unresolved or cyclic `derived_from` chain yields **P0 plus a diagnostic**; never ignored, never stronger. The "inside the signed analysis" exception is **not** implemented (no representation or policy). | `evidence.provenance` (steps 1, 4, 5 only). |
| 5 | G8 | **Provisional**: items supplied to the aggregator for the same finding and the same dimension are treated as overlapping; an item whose state is `Contradictory` dominates the aggregate. | `evidence.aggregation`. Not an amendment to the specification (U-9 remains open in the specification). |

## Gap register

Each row: affected sections/tests, issue, proposed fix, whether it changes research semantics, what it blocks, and current status.

### G1r: Evaluator-supplied target component C
- **Affects:** spec §1 (VEX target-component rule), §4.1 MATCH, §4.5 A3.
- **Issue:** where an OpenVEX product entry has no `subcomponents`, the parsed `Finding.component` is `None` and the statement alone cannot establish C. A subcomponent that carries only an `@id` has `identifier_variants == []`, so there is nothing to search with, and the state for that case is undefined.
- **Proposed fix:** an evaluator-supplied C input; MATCH is Unknown with an explicit reason when C is unresolved; decide the state for an empty-variant C.
- **Changes research semantics:** partly. **Blocks:** MATCH for those findings only.
- **Status:** **Open.** Slice 1 only emits `Unknown` (`NO_TARGET_COMPONENT`) when `Finding.component is None`; the product's identifiers are never used as C's.

### G3b: P0/P1 attribution boundary
- **Affects:** spec §1.2 level table (P0, P1), EP step 2.
- **Issue:** the spec says P1 needs "tool or process, version, and timestamp known" and P0 means "no identifiable producer". Parser output makes the boundary matter: the signed CycloneDX fixtures have no producer or tool (so P0 even though signed); OpenVEX documents have author and timestamp but a tool without a version; statement-level OpenVEX documents have at most a supplier and timestamp. P3 is cumulative, so an unattributed signed document can never be P3.
- **Proposed fix (audit):** conservative rule: P1 needs `tool_name`, `tool_version` and `created` (or an evaluator-supplied process attestation).
- **Changes research semantics:** yes. **Blocks:** document-level EP (step 2).
- **Status:** **Approved convention (strict P1).** Recorded; **not implemented** in slice 1. A representation for the evaluator-supplied process attestation does not yet exist.

### G3c: Digest binding format and comparison
- **Affects:** spec §1.2 P2, §4.1 BIND.
- **Issue:** `Scope.artifact_digest` is `list[str]` with no defined format; `Integrity.artifact_digest_binding` is `Optional[str]` and no parser sets it; subject hashes are typed `Hash(algorithm, value)`; which subject binds when a document has several (SPDX subjects fixture: `appA`, `appB`) is undefined; SPDX file-subject checksums are not extracted at all; OpenVEX product hashes describe the product, not an SBOM.
- **Proposed fix (audit):** canonical `<normalized-alg>:<normalized-hex>` for `Scope.artifact_digest`, compared with the `identifiers.normalize_hash_*` functions against subject hashes; decide which subject binds.
- **Changes research semantics:** yes. **Blocks:** P2, P3, BIND.
- **Status:** **Approved convention (canonical `alg:hex`).** Recorded; **not implemented**. The choice of which subject binds is still open. No P2/P3 is ever granted from declared hashes.

### G3d: Locator containment and absent-locator semantics
- **Affects:** spec §1.2 step 3.
- **Issue:** segment-wise JSON Pointer containment is the natural reading, but the cases of an item with `locator=None`, list-level evidence (no `#/components` convention exists) and externally supplied `established_coverage` entries (assumed to use the same pointer convention) needed a decision.
- **Proposed fix (audit):** segment-prefix containment; `None` or uncontained locator means not inside coverage; document a list-level convention.
- **Changes research semantics:** yes. **Blocks:** step 3 and P3.
- **Status:** **Approved convention (segment containment; `None` is outside coverage).** Implemented only as the isolated, tested helper `locator_within`. **Step 3 itself is not implemented.** The list-level locator convention remains open (see G7, G11).

### G3e: P3 wording tension
- **Affects:** spec §1.2 step 3 and "Establishing signed coverage".
- **Issue:** the step 3 text says P3 is "governed solely by its definition in the level table (`signature_verified` for the content in question)", while the sub-bullet says P3 "is not granted for content whose required coverage is not established". The audit found no concrete contradiction and read them conservatively: P3 needs `signature_verified` True **and** the item's locator inside `established_coverage`.
- **Proposed fix (audit):** adopt the conservative reading as written; do not reopen settled G3 semantics.
- **Changes research semantics:** no, if confirmed. **Blocks:** P3.
- **Status:** **Recorded as in the audit; not expanded or weakened.** Not implemented in slice 1. No verification result, trust anchor or established coverage is inferred anywhere in the code.

### G4: `derived_from` semantics
- **Affects:** spec §1.2 step 4.
- **Issue:** `item_id` is Optional; references can be missing, ambiguous (duplicate ids) or cyclic; the spec is silent on those cases; the exception "unless the derivation occurred inside the signed analysis" has no representation.
- **Proposed fix (audit):** unresolved or cyclic means P0 with a diagnostic; never apply the exception until a representation is approved.
- **Changes research semantics:** yes (conservative). **Blocks:** step 4 only for the exception.
- **Status:** **Approved convention; implemented** for resolved/unresolved/cyclic cases (`evidence.provenance`). Duplicate ids are treated as ambiguous references and also give P0 plus a diagnostic (**implementation convention, unconfirmed**). The signed-analysis exception is **not implemented**.

### G6: DECL record selection
- **Affects:** spec §4.1 DECL, N5-N7, NT4/NT7/NT8.
- **Issue (four sub-gaps):**
  - **(a)** For an absent target there is no "location", so "the scope containing C's would-be location" is undefined.
  - **(b)** The parser deliberately does not promote any composition record to document-wide, and the spec does not define a document-level record or when it "covers S".
  - **(c)** When several records disagree for different scopes (e.g. `incomplete_first_party_only` over `[comp-a]` and `complete` over `[comp-b]`), the spec does not say what governs.
  - **(d)** A `complete` record scoped to `dependencies` or `vulnerabilities` concerns the dependency graph or vulnerability list, not completeness of the component list.
- **Proposed fix (audit):** approve a selection rule for an absent C, a definition of document-level, and multi-record handling.
- **Changes research semantics:** yes. **Blocks:** DECL.
- **Status:** **Open.** Slice 1 emits `Unknown` for DECL when no record exists (`NO_COMPOSITION_RECORD`) and also `Unknown` when records exist (`COMPOSITION_SELECTION_UNDETERMINED`, record locators listed); no record is ever used.

### G7: Provenance role mapping and "jointly supporting" documents
- **Affects:** spec §1.2 roles table and step 5; N5, N10-N12, N16; R13.
- **Issue:** the mapping from dimensions to `PROV_SBOM`, `PROV_DECL`, `PROV_CORR`, `PROV_REACH`, `PROV_HAZ[class]` and the notion of which documents "jointly support" a conclusion or are "relied upon" are undefined. `PROV_SBOM` is "EP of the component list", a list-level locator question; `PROV_DECL` can differ from `PROV_SBOM` inside one document (NT3); `PROV_CORR` needs reliance, but `DocumentRole.CORROBORATING` only means "offered"; `PROV_HAZ` has no hazard record.
- **Proposed fix (audit):** `PROV_SBOM` = EP at a documented list-level locator in the `PRIMARY_SBOM` document; reliance deferred to Stage 3.
- **Changes research semantics:** yes. **Blocks:** role values; Stage 3.
- **Status:** **Open** beyond a pure minimum over an explicitly supplied set (`min_provenance`). The module does not decide which documents qualify.

### G8: Aggregation overlap and `Contradictory` handling
- **Affects:** spec §2 steps 2-4, AG2, U-9, U-10, U-11, NT18-NT21.
- **Issue:**
  1. **Overlap (U-9):** `EvidenceItem` has no scope/coverage field; locators are document-relative and not comparable across documents. Options: (a) all same-finding same-dimension items overlap; (b) overlap only within one document when locators nest; (c) add an explicit scope field.
  2. **Item-level `Contradictory`:** the procedure never mentions it; step 4's order lists only Ambiguous, Incomplete, Absent.
  3. **Ambiguous alongside Present:** resolved on review as a specification-determined result; see "Specification-determined results" below.
  4. **Zero items vs an explicit Unknown item:** both map to Unknown; U-11 lists the zero-item case as unstated in the procedure.
  5. **Who guarantees an `Absent` item is legitimate:** the aggregator can only trust `item.state`.
- **Proposed fix (audit):** (1) option (a) provisionally, otherwise (c); (2) a Contradictory item dominates.
- **Changes research semantics:** yes. **Blocks:** AG2 and Present x Absent resolution (now provisionally unblocked).
- **Status:** (1) and (2): **Approved convention (provisional), implemented** in `evidence.aggregation`; this is not an amendment to the specification. (3): **specification-determined result** (Present + Ambiguous gives Present), not a convention: see "Specification-determined results" below. (4): empty input and all-Unknown input both give `Unknown` and are reported with distinct reasons (`NO_ITEMS`, `ALL_UNKNOWN`); **unconfirmed** U-11 mapping. (5) **Open**: remains the producer's responsibility.

### G9r: `RationaleClass` / `NO_RULE_APPLIES`
- **Affects:** spec §3 rationale grammar; `reports/verdict.py`.
- **Issue:** the spec defines the no-rule default (Insufficient) and the class `NO_RULE_APPLIES`; `RationaleClass` has three members and its NOTE defers the fourth; there is no rationale generation.
- **Proposed fix:** add the class together with rationale generation in Stage 3/4.
- **Changes research semantics:** no. **Blocks:** Stage 3/4 only.
- **Status:** **Deferred.** Nothing changed.

### G10: `ArtifactKind.UNKNOWN` and N14/N15
- **Affects:** spec §4.3 N14/N15 preconditions, NT9-NT17, CE-N7; `model.ArtifactKind`.
- **Issue:** the spec lists four kinds; the model adds `UNKNOWN` and every OpenVEX finding has it. Whether `UNKNOWN` satisfies the `{binary, container}` precondition is undefined. The `model.py` docstring is a deferral note, not an approved decision.
- **Proposed fix:** Stage 3 must decide explicitly (e.g. treat `UNKNOWN` as possibly binary/container, giving N15 Weak, or make it an input error). It must never be coerced to `SOURCE` or `OTHER`.
- **Changes research semantics:** yes. **Blocks:** Stage 3 only.
- **Status:** **Deferred (Stage 3 decision).** Extraction does not consult `artifact_kind`.

### G11: Inventory completeness and reference resolution
- **Affects:** spec §4.1 INV, N2, N4, NT6, NT20, NT21.
- **Issue:** nothing distinguishes a full component list from a direct-dependencies-only list; the state for an empty list is undefined; "dangling" is detectable only relative to the parser's registry. Valid endpoints can be unregistered: SPDX `NOASSERTION`/`NONE`, `DocumentRef-...:` external-document endpoints (`externalDocumentRefs` is not extracted), and anything the CycloneDX schema-location table in `sbom_parser/cyclonedx.py` does not cover. The CycloneDX docstring says the official schemas were not available offline while the in-code comment says the table was verified against the upstream schema; that claim was not re-verified in the audit. Resolving a reference (subject, document node, service, nested component) never adds an inventory component and never shows a target component present.
- **Proposed fix:** decide a "full list" criterion and the empty-list state; decide how unregistered endpoints may feed an INV `Contradictory` state.
- **Changes research semantics:** yes. **Blocks:** INV Present/Contradictory.
- **Status:** **Open.** Slice 1 exposes the inventory through the adapter and emits INV `Unknown` (`INV_FULL_LIST_NOT_ESTABLISHED`). Reference lookups return the neutral `resolved` / `not_in_registry`; neither is called "missing" or "dangling".

### G13: MATCH criteria
- **Affects:** spec §4.1 MATCH, N1, N8, N9, N17, NT5, NT13, NT18, NT19.
- **Issue:** variant equality semantics (kind plus normalized value), the thresholds for Present vs Ambiguous, name-only matches, CPE 2.2 vs 2.3 (not converted by `identifiers.py`), whether subjects, nested components and `other_defined_refs` objects belong to the search domain, and "Absent only if all derivable variants were searched" when variants cannot be enumerated.
- **Proposed fix:** approve an equality and threshold policy and the search domain.
- **Changes research semantics:** yes. **Blocks:** MATCH.
- **Status:** **Open.** A resolved C produces no MATCH item and a `NOT_EVALUATED` diagnostic.

### G14: GEN inputs
- **Affects:** spec §4.1 GEN, §4.3, NT9-NT17, U-3, U-7.
- **Issue:** no parser sets `method`; `Component.ecosystem` is always `None`; there are no declared ecosystem or artifact coverage fields; no controlled vocabulary exists for method or ecosystem.
- **Proposed fix:** a controlled vocabulary and explicit inputs for declared ecosystem/artifact coverage.
- **Changes research semantics:** yes. **Blocks:** GEN beyond "unknown".
- **Status:** **Input limitation / Open.** GEN stays `Unknown` where required method, coverage, ecosystem or binding information is unavailable. Implemented: `method is None` gives `Unknown` (`GEN_METHOD_ABSENT`), and `generation_context` is never used to infer a method. A stated method is not classified.

### G15: Reachability inputs
- **Affects:** spec §5.1 (K1-K4, LOCUS, ENTRY, HAZ, CFG), §5.2, R1-R13, RT1-RT11.
- **Issue:** no record types for K1-K3, ENTRY, HAZ (class, disposition, `basis_ref`), CFG or LOCUS; `EvidenceItem.value_or_ref` is untyped; no reachability-report parser exists; whether a present dependency edge counts as a "positive observation" under §5.1 step 1 is unaddressed (counting it gives R1, not counting it gives R2; both are Insufficient with different codes).
- **Proposed fix:** typed input records for the missing kinds; an explicit ruling on K4 edges.
- **Changes research semantics:** yes. **Blocks:** the reachability family beyond Unknown.
- **Status:** **Input limitation / Open.** Slice 1 treats declared dependency edges as K4 only, giving `Unknown` (`K4_DEPENDENCY_GRAPH_ONLY`), or `Unknown` (`NO_ANALYSIS`) otherwise. A dependency edge is never converted to a call edge, and nothing is reported as reached or not reached. Hazard normalization (§5.2) is not implemented.

### G16: Extraction API and inventory access
- **Affects:** `evidence/extraction.py` interface; all CNP extraction.
- **Issue:** parsers return components next to the `SourceDocument`; `Finding` has no inventory field; structured parser output is JSON text in `declared_metadata`; OpenVEX findings carry only VEX documents, so an SBOM document must be supplied externally.
- **Proposed fix:** a typed Stage 1 records adapter and an extraction signature that takes it.
- **Changes research semantics:** no (plumbing). **Blocks:** all CNP extraction.
- **Status:** **Addressed in slice 1** by `evidence/stage1_records.py` and `extract(finding, records)`. This resolves the plumbing only; it does **not** resolve inventory, matching, completeness or binding semantics (G11, G13, G6, G17 stay open).

### G17: BIND mismatch and product/version mapping
- **Affects:** spec §4.1 BIND, N3, §5.1 BIND, R6.
- **Issue:** "mismatched" (N3) has no corresponding evidence state; mapping `Scope.product_id` (an OpenVEX `@id`, possibly a purl with an embedded digest that the parser deliberately does not parse) and `Scope.version` to an SBOM subject is undefined; OpenVEX scopes have no `artifact_digest`.
- **Proposed fix:** define a mismatch representation and a product/version comparison; depends on G3c.
- **Changes research semantics:** yes. **Blocks:** BIND.
- **Status:** **Open.** BIND is not extracted (a `NOT_EVALUATED` diagnostic is reported).

## Specification-determined results

These are fixed by the committed specification's own procedure and confirmed on review. They are not implementation conventions and are not in the same class as the approved conventions G3b, G3c, G3d and G8 above.

| Case | Result | Basis |
|---|---|---|
| G8 sub-case 3: item A `Present` + item B `Ambiguous`, same finding and dimension, no `Absent` item | `Present` | follows from the literal §2 step 3 procedure (positive observation's conditions do not reference other items' states), corroborated by M-4/N1 consistency, not exemplified by any AG case. Step 1 and step 2 do not apply, step 3's conditions are met, and step 4 ("Otherwise") is not reached. |

Reviewed against `docs/formal_specification_v0.2.md` at `cf062df32a1d257d62b087f8d6c6c11be34df586` (§2 steps 1-4, the AG1-AG5 table, M-4, N1 and N8). If the project later wants an `Ambiguous` item to prevent a positive observation from surviving, that would be an amendment to the specification, not a reading of it.

## Implementation conventions made in slice 1 (not among the five approved decisions)

These can only lower a result or add a diagnostic, and need explicit confirmation:

1. `evidence.provenance`: a `source_doc` absent from the supplied `document_levels` is P0 with `SOURCE_DOC_LEVEL_UNAVAILABLE`.
2. `evidence.provenance`: a duplicate `item_id` makes a `derived_from` reference ambiguous, giving P0 with `AMBIGUOUS_DERIVED_FROM`.
3. `evidence.provenance.min_provenance` of an empty collection raises `ValueError` rather than choosing a level.
4. `evidence.aggregation`: empty input is `Unknown` (the U-11 mapping).
5. `evidence.extraction`: a dimension that is not evaluated emits **no item** and a `NOT_EVALUATED` diagnostic (rather than an `Unknown` item); a non-`not_affected` disposition or an unsupported justification emits no items and a diagnostic; only documents with an explicit `DocumentRole` are used (`PRIMARY_SBOM` for INV/DECL/GEN; `PRIMARY_SBOM` or `CORROBORATING` for K4 edges).

## Cross-reference: resolved prerequisite changes

These were resolved before the audit and are **not** unresolved gaps. They were not rows of the audit's gap register.

| Label | Resolved change | Introduced in |
|---|---|---|
| G1 | Target component C represented distinctly from the VEX product (`Finding.component` Optional, `Finding.product`); OpenVEX subcomponents read from the product entry | `7652501` (`fix: resolve Stage 2 design-gap findings G1/G3/G9 ...`) |
| G3 | EP signed-coverage cap semantics clarified in spec §1.2 step 3 and A5 | `7652501` |
| G9 | No-rule default (Insufficient) and `NO_RULE_APPLIES` defined in spec §3 | `7652501` |
| G3a | Declared (`signed_coverage`) vs established (`established_coverage`) signature coverage | `35fcc6e` (`feat: resolve Stage 2 prerequisites G3a/G2/G12 ...`) |
| G2 | Finding-specific document roles (`DocumentRole`, `Finding.document_roles`) | `35fcc6e` |
| G12 | Typed SBOM subjects and reference registries (`DocumentSubject`, `SourceDocument.subjects`, `document_ref`, `other_defined_refs`) | `35fcc6e` |

The `model.py` docstring spec-pin correction landed in `cf062df` and is documentation only.

## Related unresolved items named in the specification itself

U-1, U-2, U-3, U-6, U-7, U-9, U-10 and U-11 (spec §7) are unchanged. G8 touches U-9/U-10/U-11, G14 touches U-3/U-7, and G7/G11 touch U-6. The approved G8 convention does not close U-9.
