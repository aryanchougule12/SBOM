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
- **Status:** **Open (format interpretation supported; project mapping open).** The format interpretation of named `assemblies` references is supported, and project decisions G6-D1 to G6-D13 are approved and recorded below. Slice 2a implements their applicability rules only as an isolated candidate enumerator (`evidence/decl_candidates.py`, tests in `tests/test_decl_candidates.py`). The enumerator lists candidate records, exclusions and root-level candidates; it selects no record, produces no DECL evidence item or verdict, and is **not wired into `extract()`**. G6 is not closed: the open points listed at the end of this section remain. DECL extraction is unchanged: slice 1 emits `Unknown` for DECL when no record exists (`NO_COMPOSITION_RECORD`) and also `Unknown` when records exist (`COMPOSITION_SELECTION_UNDETERMINED`, record locators listed); no record is ever used.

**Labels.** G6-D1 to G6-D13 are local labels for the decisions below (G6-D1 to G6-D10 were referred to as D1-D10 in review; G6-D11 and G6-D12 are later clarifications of G6-D1, and G6-D13 is a later conditional decision about the document-level fallback). They are not specification identifiers and are unrelated to the specification's own D-1 to D-6. Basis labels used below: **[S]** formal specification wording; **[F]** CycloneDX JSON schema wording (1.5 and 1.6 release tags); **[X]** official usage-example evidence (not normative); **[I]** logical inference; **[P]** project policy (approved, per the decision list).

**Format evidence (recorded; not decisions).**
- **[F]** (identical in 1.5 and 1.6) `assemblies`: "The bom-ref identifiers of the components or services being described. Assemblies refer to nested relationships whereby a constituent part may include other constituent parts. References do not cascade to child parts. References are explicit for the specified constituent part only." `dependencies`: "…Dependencies refer to a relationship whereby an independent constituent part requires another independent constituent part. References do not cascade to transitive dependencies. References are explicit for the specified dependency only." `vulnerabilities`: "The bom-ref identifiers of the vulnerabilities being described." `aggregate: complete`: "The relationship is complete. No further relationships including constituent components, services, or dependencies are known to exist."
- **[F]** (1.5 and 1.6) `metadata.component` references the common `component` definition ("The component that the BOM describes"). That definition has a `components` array ("A list of software and hardware components included in the parent component. This is not a dependency tree. It provides a way to specify a hierarchical representation of component assemblies…"). The BOM-level `components` array is a separate property ("A list of software and hardware components."). The schema text does not state that the BOM-level `components` are the constituents of `metadata.component`, and does not equate them with `metadata.component.components`.
- **[F]** The schema is silent on a composition record with none of the three lists, and on how one `aggregate` applies when a record lists several references.
- **[X]** Official component-composition example (`cyclonedx.org/use-cases/compositions-components/`), as **reported** by a coordinating session: three consistent retrievals showed `specVersion: "1.6"` and `bom-1.6.schema.json`; one separate retrieval reported `"1.7"` and `bom-1.7.schema.json`. The discrepancy is recorded and unresolved. The example is reported to name only the root application in `assemblies` while describing a complete application inventory with three libraries. This is usage-example support for the root-only pattern, not normative schema text. It was **not independently retrieved** by the author of this entry (the authoring environment's network policy denied `cyclonedx.org` and `ecma-international.org`); ECMA-424 was not read. Where the example places its libraries (nested under the root or in top-level `components`) is not recorded here. The component-assembly example (`cyclonedx.org/use-cases/compositions-component-assembly/`) is reported as `specVersion: "1.7"` and is supporting evidence only, not a 1.5/1.6 requirement.
- **[I]** A named `assemblies` reference identifies the assembly being described. The no-cascade rule means a reference does not independently establish completeness for a child's own assembly. It does not follow that a represented child is excluded from its parent's assembly claim, and no source requires every inventory component to appear in `assemblies`.

**Approved project decisions (all [P]; recorded; implemented only as the isolated enumerator described in the Status line, not in extraction).**
- **G6-D1: assembly claim to scope.** For an ordinary named assembly reference, a `complete` claim applies to that referenced assembly and its represented direct constituent children. It does not independently assert that a child's own assembly is complete and does not recursively establish completeness for descendant assemblies. The root-document case is separate and is specified by G6-D3. Basis: [F] no-cascade wording, [I].
- **G6-D2: scope-less records.** A composition record with no applicable scope list is non-covering for DECL, and DECL is `Unknown` when no other qualifying record applies. This explicitly includes a record whose `assemblies` array is present but empty and which has no other applicable scope: it is non-covering and cannot establish `Present`. Document-wide scope is never inferred from the absence of an `assemblies`, `dependencies` or `vulnerabilities` list. Basis: [F] silence, [S] P-2.
- **G6-D3: top-level components and `metadata.component`.** Top-level BOM components may contribute to document-wide DECL coverage only when an applicable composition explicitly names the `metadata.component` root in `assemblies` and declares `aggregate: complete`. This is a project rule supported by the reported official component-composition example [X]. It is not a statement that the schema binds the two arrays together ([F] does not). The mere existence of a top-level `components` array does not establish completeness. "Only when" states a necessary condition, not a sufficient one (see the open points on "covers S").
- **G6-D4: sibling references.** Distributive, per-reference reading: the record's aggregate applies independently to each listed assembly reference. A sibling list is not a collective inventory union, and no broader coverage is inferred because several references occur in one record. Basis: [F] "explicit for the specified constituent part only" (per reference), [I]; the schema does not state it directly.
- **G6-D5: missing `bom-ref` and BOM-Link references.** A component without a `bom-ref` cannot be directly targeted by an assembly reference, but may be covered as a represented **direct** constituent child of an otherwise qualifying named parent or root assembly under G6-D1 or G6-D3. This indirect coverage does not extend recursively to deeper descendants (G6-D1 is non-recursive). A missing `bom-ref` does not always exclude a component from all coverage. BOM-Link references are treated as unresolved and unmatched for DECL until their handling is explicitly defined. No local target is guessed and no unresolved reference is promoted to coverage.
- **G6-D6: most-specific selection and absent C.** For a known target location, select the most-specific applicable record. If C is absent from the inventory and no evaluator-supplied location is available, no component-specific record is selected on the basis of a guessed parent or position. DECL is then `Unknown` when no qualifying document-level fallback exists. The specification's document-level fallback ([S] §4.1: "fall back to document level only if it covers S") is preserved: it may be used only when an explicit root-level record qualifies under G6-D3 and covers S. DECL is not stated to be unconditionally `Unknown` for every absent target. Dependencies: G6-D1 and G6-D3 (what a record covers), and G1r (an evaluator-supplied target and location input).
- **G6-D7: selection versus combination.** Select the most-specific applicable record. Do not aggregate all composition records together, and do not combine records merely because they occur in the same BOM. This selection is separate from the specification's §2 evidence aggregation.
- **G6-D8: ties and overlapping scopes.** When equally applicable records refer to the same target and scope but disagree, use an explicit conservative worst-case tie-break instead of taking whichever record appears first. Ordering: `Unknown` is the most conservative result; otherwise `Incomplete` takes precedence over `Present`. A `Present` DECL result requires all equally applicable records to support completeness. This is project policy. It is **not** the specification's §2 aggregation procedure and does not close U-9 or amend the specification. It does not merge unrelated records or records scoped to different targets.
- **G6-D9: dependency and vulnerability scope.** A vulnerabilities-only record cannot establish component-inventory DECL. A dependencies-only record cannot establish it by itself. For a mixed-scope record only its `assemblies` portion may contribute to DECL; its `dependencies` and `vulnerabilities` portions are ignored for this dimension. Basis: [F] three distinct fields; [S] §4.1 INV, "The full component list for S (not direct dependencies only)".
- **G6-D10: status wording.** The existing status vocabulary is used. `Open (format interpretation supported; project mapping open)` is used where part of an issue is settled and questions remain. No new top-level status class is introduced.
- **G6-D11: target applicability (container interpretation; clarification of G6-D1).** A composition record naming assembly X is a candidate for target C when C is a represented direct child of X. A record naming C itself is about C's own assembly. It is not a candidate for determining completeness of the scope containing C's location merely because C is named (it is a candidate for C's direct children instead). There is no recursive inheritance: a record naming X does not establish coverage for grandchildren through an intermediate component. For a top-level target without a resolvable parent assembly, any record naming the `metadata.component` root is reported separately as a root-level candidate, and "covers S" is left undetermined (G6-D3). The target's own record is not ranked against its parent's record, because under this interpretation it is not a candidate for the target's own DECL applicability. Basis: [P]. This is the project's reading of "the scope containing C's would-be location" ([S] §4.1) and of G6-D1's phrase "that referenced assembly" (the assembly of the named component, i.e. its children); it is not specification text, and the specification is unchanged.
- **G6-D12: components directly nested under `metadata.component` (clarification of G6-D1 and G6-D11; resolves former open point 10).** A component directly nested under `metadata.component.components` is a represented direct child of the named root component and can receive a component-specific candidate under G6-D1 and G6-D11. This does not establish document-wide coverage and does not recursively cover grandchildren. Basis: [P]; the placement of such a component inside the root is [F] (`component.components`).
- **G6-D13: document-level fallback across S (conditional; resolves the root-reach question, former open point 9).** A qualifying document-level fallback applies across formal scope S regardless of component-tree depth, but only after "covers S" is actually established. This is distinct from recursive inheritance under G6-D1. A root record is a component-specific candidate for the root's direct nested children (G6-D12). For other in-scope targets, a qualifying root-level record is retained as a separate document-level fallback candidate. That fallback cannot establish coverage or produce DECL `Present` while "covers S" remains undetermined, and a root record whose aggregate is not `complete` does not qualify. If "covers S" is established, the fallback applies throughout S, including deeper descendants. The root's named assembly reference is not used to infer the own-assembly completeness of intermediate descendants. The definition and validation of "covers S" stay open and depend on G3c, G17 and G11 (open point 2). Basis: [P]; builds on G6-D3 and G6-D6, and the specification's own document-level fallback wording ([S] §4.1).

**Sub-gap status (what is settled and what is not).**
- **(a) Absent target:** **Approved convention (G6-D6); enumerator reports `TARGET_LOCATION_UNAVAILABLE` and guesses no parent (Slice 2a); not wired into extraction.** Still depends on G1r. No field for an evaluator-supplied location exists on `model.Finding` (it has an Optional `component` and a `product`, not a location).
- **(b) Document-level / "covers S":** **Open (format interpretation supported; project mapping open).** Approved: G6-D1 (as clarified by G6-D11 and G6-D12), G6-D2, G6-D3, G6-D4, G6-D5, G6-D13 (conditional on "covers S"); the enumerator implements them in isolation. Not settled: see the open points.
- **(c) Several records:** **Approved convention (G6-D7, G6-D8, G6-D11); the enumerator groups records that name the same parent reference and applies the G6-D8 worst case only inside that group (Slice 2a); not wired into extraction.** A target's own record versus its parent's record needs no ranking under G6-D11, because the own record is not a candidate for the target.
- **(d) dependencies / vulnerabilities:** **Approved convention (G6-D9); the enumerator excludes dependencies-only and vulnerabilities-only records and ignores those lists in mixed records (Slice 2a); not wired into extraction.**

**`fixtures/cyclonedx/complete_composition.json`** (CycloneDX 1.6; one record `#/compositions/0`: `complete`, `assemblies` = `lib-purl`, `lib-cpe`, `lib-name`, `dependencies` = `app-1`; `metadata.component` is `app-1` with no nested `components`; `lib-nested` is nested under `lib-purl`):
- Omitting `lib-nested` from `assemblies` does not by itself exclude it from `lib-purl`'s assembly. Under G6-D1 it is a represented direct constituent child of the named `lib-purl`, so the record is the applicable record for a target located directly under `lib-purl`. The Slice 2a enumerator reports that record as a candidate for a target located directly under `lib-purl`, carrying the record's own mapped state (`Present`); no DECL result is produced.
- The record does not establish completeness of `lib-nested`'s own assembly (not a named reference, and no recursion under G6-D1).
- `app-1` is not named in `assemblies`; it appears only under `dependencies`, which is ignored for DECL under G6-D9. G6-D3 is therefore not satisfied. The record establishes no document-wide DECL coverage and does not make the top-level `components` list a complete-inventory claim.
- `lib-cpe` and `lib-name` are each covered individually under G6-D4. Nothing is inferred as a union.
- `incomplete_composition.json`: its records name disjoint references (`comp-a`, `comp-b`) and no root. Under G6-D4 and G6-D7 they are not combined and neither is document-level.

**Open points remaining in G6 (not resolved by G6-D1 to G6-D13; points 9 and 10 are kept for numbering and are resolved).**
1. **BOM-Link references:** unresolved and unmatched for DECL; their handling is still to be defined (G6-D5).
2. **"Covers S":** the mapping of a root-level record to formal S (product/version, artifact binding, build) is not defined. It depends on G3c and G17 (BIND) and on G11 (what a full component list is). G6-D3 gives a necessary condition only. DECL `Present` does not by itself establish INV.
3. **Location input:** no representation of an evaluator-supplied location exists (see sub-gap (a)); the model change belongs with G1r.
4. **Reference-resolution cases.** A parent without a `bom-ref` cannot be directly named in `assemblies`, so it cannot be the named parent of a G6-D1 claim **[I]**. Cases are distinguished as follows:
   - An unreferenced component (no `bom-ref`) that is a represented **direct** child of a qualifying named assembly may be covered by that parent's claim under G6-D1.
   - A deeper descendant, separated from the named assembly by an intermediate component, is not covered merely through recursive inheritance of the ancestor's claim (G6-D1 is non-recursive).
   - A descendant with its own resolvable `bom-ref` may potentially be targeted independently, subject to the applicable-scope rules.
   - Unresolved assembly-reference matching stays open: a reference in `assemblies` that matches no registered component or service is unresolved, and no target is guessed. BOM-Link handling also stays open (open point 1).
   - A deeper descendant without a resolvable `bom-ref`, below a parent that cannot itself be named, is not an open question about recursive inheritance. Under G6-D1 and G6-D5 it has no component-specific coverage path through that parent, so DECL remains `Unknown` by this route. This does not rule out other coverage mechanisms: an independent qualifying document-level fallback under G6-D3 and G6-D6 is unaffected.
5. **Specificity:** G6-D11 removes the own-record versus parent-record question: a target's own record is not a candidate for it. Candidates for one target therefore all name its single parent assembly and form one group (G6-D8), and the specification makes a component-specific record take precedence over the document-level fallback ([S] §4.1). What remains open is how a root-level fallback interacts with component-specific candidates once "covers S" is defined (open point 2); G6-D13 keeps them as separate paths until then.
6. **Cross-issue dependencies:** G1r (target C and location), G7 (which declaration is "applicable" for `PROV_DECL`, and role mapping), G11 (full-list criterion; INV is a separate dimension). U-9 is unchanged.
7. **Example provenance:** the 1.6/1.7 observations on the component-composition example remain unreconciled and the example was not independently retrieved. G6-D3 is a project rule and does not rest on the example alone.
8. **Test comment:** `tests/test_extraction.py` (the comment in `test_decl_with_composition_records_stays_unknown_because_selection_is_open`) calls the fixture's single record "document-covering". Under G6-D3 it is not, because it does not name `app-1`. The comment is a documentation inconsistency and was not edited.
9. **Root reach: resolved conditionally by G6-D13.** A qualifying root-level record is a separate document-level fallback candidate for any in-scope target other than the root's direct nested children, at any depth, and it applies throughout S only once "covers S" is established. Until then it is reported with `covers_s=UNDETERMINED` and never grants coverage or `Present`. The remaining dependency is open point 2.
10. **Children nested under `metadata.component`: resolved by G6-D12.** A direct child receives a component-specific candidate from the named root; a deeper descendant receives only the separate fallback candidate (target position `BELOW_ROOT_CHILD`), not a root-derived component-specific candidate.
11. **Discoverability limits (Stage 1 records):** a component nested beneath `metadata.component` (or another non-listed object) is registered only if it carries a `bom-ref`, so one without a `bom-ref` cannot be passed as a target. Ordinary listed components, including nested ones, are always discoverable. A reference resolving to a non-component object (for example a service) never equals a component's parent reference and is not reported. A reference declared more than once is reported as ambiguous and is never resolved to the first match. For the root fallback, "in scope" is implemented as the two component trees `#/components/<n>(/components/<n>)*` and `#/metadata/component(/components/<n>)+`; a registered component nested in another object (for example a `pedigree` component) is an accepted target locator that gets no root-level fallback candidate. Whether such components belong to S is not decided.

**No-closed-world safeguard.** A missing record, an unselected record, or a target absent from a record's references never produces `Absent` ([S] §2, "It is never produced by the lack of items"; P-2). [S] §4.1 maps DECL only to Present, Incomplete and Unknown. A scoped, explicit `complete` claim and the absence of evidence are different things. The former may yield `Present` for the scope it covers. The latter yields `Unknown`.

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
- **Status:** **Addressed in Phase 1 for `Req(component_not_present)`.** `RationaleClass.NO_RULE_APPLIES` exists, and `evidence/cnp_rules.py` generates the rationale (grammar and code ordering) for that predicate. Rationale generation for the reachability predicate is not implemented.

### G10: `ArtifactKind.UNKNOWN` and N14/N15
- **Affects:** spec §4.3 N14/N15 preconditions, NT9-NT17, CE-N7; `model.ArtifactKind`.
- **Issue:** the spec lists four kinds; the model adds `UNKNOWN` and every OpenVEX finding has it. Whether `UNKNOWN` satisfies the `{binary, container}` precondition is undefined. The `model.py` docstring is a deferral note, not an approved decision.
- **Proposed fix:** Stage 3 must decide explicitly (e.g. treat `UNKNOWN` as possibly binary/container, giving N15 Weak, or make it an input error). It must never be coerced to `SOURCE` or `OTHER`.
- **Changes research semantics:** yes. **Blocks:** Stage 3 only.
- **Status:** **Deferred (Stage 3 decision); still unresolved.** Extraction does not consult `artifact_kind`. The Phase 1 rule engine (`evidence/cnp_rules.py`) refuses `ArtifactKind.UNKNOWN` with `UnresolvedArtifactKindError` and decides nothing: it is never read as `SOURCE`, `OTHER`, binary or container.

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

### G18: Step 4 versus the definition of Insufficient (found in Phase 1)
- **Affects:** spec §3 (Verdict definitions, Step 4, no-rule default), §4.2 rule table.
- **Issue:** the §3 definition of Insufficient includes "a required dimension is missing or `Unknown`", but §4.2 has no rule for MATCH `Unknown`, DECL `Absent`/`Ambiguous`/`Contradictory`, or INV `Absent`/`Incomplete`/`Ambiguous`. When no other rule triggers, the no-rule default gives Insufficient. When another rule triggers (for example N12, Weak), the literal Step 4 ("minimum ceiling over all triggered rules") gives Weak although such an uncovered state is present.
- **Proposed fix:** a project decision whether an uncovered state caps the verdict at Insufficient. That would be a reading or amendment of the specification and has not been made.
- **Changes research semantics:** yes. **Blocks:** nothing in Phase 1.
- **Status:** **Open.** `evidence/cnp_rules.py` follows the literal Step 4 and reports such states in `CnpEvaluation.uncovered_states` without changing the verdict.

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

## Implementation conventions made in slice 2a (unconfirmed; not approved semantic decisions)

These are API choices made while implementing the isolated DECL candidate enumerator (`evidence/decl_candidates.py`). They are not requirements of the formal specification and are not among the approved G6 decisions. They need explicit confirmation:

1. `evidence.decl_candidates.worst_case_state` raises `ValueError` for an empty collection and for any state other than `Present`, `Incomplete` and `Unknown`, rather than choosing a result. (The ordering it applies, `Unknown` > `Incomplete` > `Present`, is the approved G6-D8 policy; the refusal behaviour is the unconfirmed convention.)

## Implementation conventions made in Phase 1 (unconfirmed; not approved semantic decisions)

These are choices made in the pure `Req(component_not_present)` engine (`evidence/cnp_rules.py`) where the specification is silent. They need explicit confirmation:

1. `INV` accepts `None` for "missing" (N2 reads "Unknown or missing"). `INV = Absent` is not read as missing, so N2 does not fire for it.
2. `BIND` has three input states (`matched`, `mismatched`, `unknown`). N3 treats the last two identically; the factual state is preserved in the evaluation and named in the rationale text.
3. Several rationale classes in one result are rendered as one `<CLASS>[CODE,...]: text` segment per class, in class-rank order, joined by ` | `. A Supported result has an empty rationale.
4. `ArtifactKind.UNKNOWN` raises `UnresolvedArtifactKindError` (see G10).
5. A separate corroborating document is a content-based basis only if the caller states that it meets the non-provenance criteria and its EP is at least P1; it is "relied upon" (N16) only for binary/container artifacts whose primary SBOM is not itself content-based.
6. `prov_decl` is a required input when `decl` is Present and is ignored otherwise.

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
