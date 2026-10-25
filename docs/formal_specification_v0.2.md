# Corrected Specification v0.2

## 0. Principles

- **P-1. Sufficiency is not truth.** A verdict says whether the recorded evidence meets a defined bar. It does not say whether the claim is true. Ground truth is out of scope.
- **P-2. No closed-world assumption.** Missing evidence is `Unknown`, never `Absent`.
- **P-3. Monotone downgrade.** Defects, limitations, and unattributed sources can only lower a verdict. No rule may raise one.
- **P-4. Profile disclaimer.** P0–P3 and the rule "Supported requires P3" are this research prototype's proposed profile. CISA defines neither a provenance ladder nor a decision threshold. CISA elements are only inputs that populate profile attributes (§1.3).

## 1. Finding Model

F = (C, V, D, J, E), with finding-level scope S, plus source documents and evidence items that carry provenance.

| Element | Fields |
|---|---|
| **C** | `purl?`, `cpe[]`, `name`, `version`, `ecosystem`, `supplier`, `hashes[]`, `bom_ref`, and `identifier_variants` (derived under versioned normalization rules, recorded for audit). |
| **V** | `id`, `aliases[]`, `source`, `affected_ranges`, `locus {symbols[], files[], granularity, locus_source}`. |
| **D** | `{not_affected, affected, fixed, under_investigation}`. Predicates apply only to `not_affected`. Any other value is an input error, not a verdict. |
| **J** | `justification` (VEX/CSAF value), `asserted_by`, `statement`. |
| **S** | `product_id`, `artifact_digest[]`, `artifact_kind ∈ {source, binary, container, other}`, `version`, `build_id`, `deployment_config_id`, `environment_assumptions`, `valid_interval`. The claim holds only for S. |
| **E** | Evidence items `(dimension, state, value_or_ref, source_doc, locator, derived_from[])`. |

For a finding derived from a VEX statement, C is the specific component that the finding's evidence concerns, not merely the product under assessment. When a product entry in the statement identifies one or more relevant subcomponents, those subcomponents identify the target component C for the corresponding findings. When no subcomponent identifies C, the target component cannot be established from the VEX statement alone. In that case, MATCH (§4.1) must be extracted as Unknown, with an explicit reason that no component-level target was identified. The product's identifiers must not be treated as identifier variants of C.

Req(J) denotes whichever of Req(component_not_present) (§4) or Req(vulnerable_code_not_in_execute_path) (§5) applies to a given justification J; the notation is used generically in places that apply to both.

A justification value outside the two predicates this specification defines (§4, §5) is not evaluated by either Req(J); it must be preserved as received and explicitly reported as unsupported by the pipeline stage that encounters it, never silently coerced into one of the two supported predicates.

### 1.1 Source-document provenance (SDP)

Provenance is recorded **once per source document** (an SBOM file, a reachability report, an attestation). Each evidence item points to its document through `source_doc` and `locator`.

A source document records:
- `producer`, `producer_class`, `tool_name`, `tool_version`, `created`
- `generation_context` and `method`
- `integrity {artifact_digest_binding, signature, signature_verified, trust_anchor_id, signed_coverage, established_coverage}`

Here `signed_coverage` is the coverage declared by the input: an assertion, not proof that the signature verifies or that the asserted locators were actually signed. `established_coverage` is the locator coverage that a verification result establishes: `None` means not established or unavailable, `[]` means verification established an empty set of covered locators, and otherwise it contains only the locators the verification result establishes as covered.

### 1.2 Ladder and effective provenance

| Level | Meaning |
|---|---|
| P0 | Unattributed: no identifiable producer. |
| P1 | Attributed: tool or process, version, and timestamp known. No integrity mechanism. |
| P2 | P1, plus the document declares a digest equal to `S.artifact_digest`. The binding is self-asserted. |
| P3 | P2, plus `signature_verified` against a configured trust anchor, **for the content in question**. |

**Effective provenance EP(item):**
1. An item with no `source_doc` is P0.
2. Otherwise EP is the level of its source document.
3. **Signed-coverage cap.** This step applies only to a source document that carries a signature. If the document has no signature, the cap does not apply; the absence of a signature neither lowers EP through this step nor satisfies any requirement of the level table (P2 still requires the document to declare a digest equal to `S.artifact_digest`). For a signed document, the cap applies only when the signed coverage relevant to the calculation is *established* under the verification assumptions (A5) and the item's locator lies outside that established coverage; EP is then capped at `min(level, P1)`. A coverage declaration read from the document itself (for example by a parser reading a signature object) is an unverified claim: it is not cryptographic verification and not proof of what the signature actually covers. A coverage that is unavailable or only claimed is not treated as an empty, verified coverage set, so it does not trigger the cap; it likewise does not establish that any locator lies inside verified coverage, and P3 remains governed solely by its definition in the level table (`signature_verified` for the content in question).

   *Establishing signed coverage (clarifies step 3).* Coverage is **established** only when the document carries a signature, that signature is reported verified under the verification assumptions (A5; `signature_verified` is True), and the verification result states which locators it establishes as covered (`established_coverage`). A coverage declaration read from the document (`signed_coverage`) is a claim and never becomes established coverage by being parsed.
   - *No signature:* the cap does not apply.
   - *Signature present, `signature_verified` is None or False:* coverage is not established. The cap does not apply on the basis of declared coverage, and P3 is not granted merely because a signature object exists.
   - *Signature present, `signature_verified` is True:* coverage is established only for the locators the verification result actually establishes as covered (`established_coverage`; an empty set means no locator is covered). The cap applies to an item whose locator lies outside them, and a locator inside them is the "content in question" for P3.
   - *Coverage unavailable, ambiguous, or not attributable to a verified signature* (`established_coverage` is None, or the result does not identify which signatures it verified): it is not treated as verified-empty coverage, as complete coverage, or as proof that any locator is covered. The cap does not apply, and P3 is not granted for content whose required coverage is not established.
4. For a derived item, EP ≤ the minimum EP of its inputs, unless the derivation occurred inside the signed analysis.
5. Where several documents jointly support one conclusion, the relevant provenance is the **minimum** EP across them.

**Provenance roles.** There is no global `PROV`. Each predicate names its own roles:

| Predicate | Roles |
|---|---|
| CNP | `PROV_SBOM` (EP of the component list), `PROV_DECL` (EP of the applicable completeness declaration), `PROV_CORR` (EP of a content-based corroborating document that is separate from the primary SBOM, §4.3). `PROV_CORR` is instantiated only in that case. When the primary SBOM itself is the content-based basis, `PROV_SBOM` applies and no separate `PROV_CORR` value is instantiated. |
| Reachability | `PROV_REACH` (EP of the reachability evidence supporting the REACH conclusion), `PROV_HAZ[class]` (EP of the basis for each hazard-exclusion claim). |

### 1.3 Mapping to the 2026 CISA Minimum Elements

The table gives how this profile uses each element, and what it does not establish.

| CISA element | Profile attribute | Does **not** establish |
|---|---|---|
| SBOM Author Signature | SBOM authenticity and integrity, used for P3 (`signature_verified`, `signed_coverage`) | Accuracy or completeness of the inventory, or ground-truth absence |
| Component Hash Value / Algorithm | Component identity and integrity, used as an additional identifier variant in MATCH, and to reduce Ambiguous identity | That the list is complete, or that an unlisted component is absent |
| SBOM Generation Context | Lifecycle phase and available data, recorded as `generation_context`. It may inform, but never alone establishes, the generation method evaluated by the manifest-only rules (§4.3, N14, N15) | That the generator saw everything in the shipped artifact, or that the method was manifest-only |
| SBOM Tool Name / Version | Generation provenance, used for P1 attribution | That the tool is correct |
| Coverage | Scope of the component inventory, i.e. what part of S it purports to enumerate. Feeds DECL and BIND | That the declared scope is actually complete (still a self-assertion) |

A signature or hash never proves inventory completeness or ground-truth absence. It can only raise the provenance level required by the profile.

## 2. Evidence States

Each dimension names a *subject*. The state describes the observation status of that subject.

| State | Definition |
|---|---|
| **Present** | An in-scope evidence item affirmatively records the subject as observed, in a form interpretable as one unambiguous positive observation. |
| **Absent** | An in-scope source whose declared coverage is sufficient for the dimension affirmatively records that the subject was sought and not found. |
| **Unknown** | No in-scope item bears on the dimension, or one exists but nothing establishes whether it covers the subject, so neither observation nor non-observation can be asserted. |
| **Incomplete** | An in-scope item exists but, declaredly or demonstrably, covers only a proper subset of what the dimension requires, so its silence on the remainder is uninformative. |
| **Ambiguous** | In-scope evidence admits two or more materially different interpretations that the available data cannot resolve. |
| **Contradictory** | Two or more in-scope items assert mutually exclusive observations about the same subject, or one item is internally inconsistent, and no rule here resolves it. |

**Asymmetry.** Positive observations survive incompleteness. Negative observations need declared coverage.

**Aggregation within one dimension:**
1. Discard `Unknown` items when any other informative item exists. If all items are `Unknown`, the aggregate is `Unknown`.
2. `Present` against `Absent` over overlapping scope gives `Contradictory`.
3. If an in-scope, unambiguous positive observation of the subject exists and no overlapping-scope absence contradicts it, the aggregate state is `Present`, even if other items about the same subject are `Incomplete`. Another evidence item's `Incomplete` status never erases a positive observation.
4. Otherwise, use the most degraded applicable remaining state: `Ambiguous` > `Incomplete` > `Absent`. `Absent` is assigned only when an item satisfies the `Absent` definition, i.e. a source with declared sufficient coverage records non-observation. It is never produced by the lack of items.
5. Coverage is never inferred from the union of `Incomplete` items: combining incomplete sources does not yield complete coverage, and does not yield `Absent`.

**Aggregation acceptance cases** (specification level; they restate the rules above and do not weaken P-2):

| # | Items for one subject | Aggregate |
|---|---|---|
| AG1 | `Present` + `Incomplete`, no conflicting `Absent` observation | **Present** |
| AG2 | `Present` + `Absent` over overlapping scope | **Contradictory** |
| AG3 | `Present` + `Unknown` | **Present** |
| AG4 | `Unknown` only (one or more items) | **Unknown** |
| AG5 | `Incomplete` + `Incomplete` | **Incomplete** (never `Absent`, never complete) |

## 3. Verdicts and Deterministic Decision Procedure

| Verdict | Definition |
|---|---|
| **Supported** | Every required dimension meets the predicate's bar and no triggered rule has a ceiling below Supported. |
| **Weak** | The evidence is relevant and does not contradict the claim, but at least one bar condition is unmet, and further evidence of a kind named in the rationale could repair it. |
| **Insufficient** | The evidence cannot establish the claim. A required dimension is missing or `Unknown`, or the evidence contradicts the claim or itself. |

**Procedure (fixed order):**
- **Step 0.** Compute EP for every item and the named provenance roles.
- **Step 1.** Apply classification normalizations (hazard downgrade in §5.2).
- **Step 2.** Compute dimension states, applying the derivation rules.
- **Step 3.** Evaluate **all** rules in the predicate's table, with no short-circuiting.
- **Step 4.** Verdict = the minimum ceiling over all triggered rules (Supported > Weak > Insufficient). If none triggered and all Supported conditions hold, the verdict is Supported.
  - **No-rule default.** If no rule in the predicate's rule table triggers, but not every Supported condition (§4.4 or §5.5) holds, the verdict is Insufficient. This default applies only when no rule's ceiling already governs the outcome. Its rationale class is `NO_RULE_APPLIES`, which has no rule code because no specific rule triggered; it is emitted only when this default applies and never co-occurs with codes belonging to a triggered rule.
- **Step 5.** Output every triggered code.

**Rationale grammar:** `<CLASS>[CODE,…]: text`, where CLASS is `CONTRADICTORY_EVIDENCE`, `CANNOT_BE_ESTABLISHED`, `BELOW_BAR`, or `NO_RULE_APPLIES` (the class of the Step 4 no-rule default, which has no rule code, so its code list is empty). These are sub-reasons, not verdicts. Codes are ordered by class rank (CONTRADICTORY, then CANNOT, then BELOW). After ordering by rationale class rank, order rule identifiers by their alphabetic rule-family prefix and then by their numeric suffix interpreted as an integer, never by lexicographic ordering of the entire identifier. For codes within the same rule, order per-hazard codes alphabetically. Free text is not evaluated.

**D-5 (explicitly outside the procedure).** Whether Weak (or Supported) is acceptable to a downstream consumer is a policy question. The procedure defines no acceptance threshold and no function from verdict to action.

## 4. Req(component_not_present)

**Claim.** Component C does not exist within S.

### 4.1 Dimensions

| Dim | Subject |
|---|---|
| INV | The full component list for S (not direct dependencies only). |
| MATCH | C under any identifier variant (purl, CPE, name+version, hash). `Absent` only if all derivable variants were searched. |
| DECL | The completeness declaration for the scope containing C's would-be location. Use the most specific composition record, and fall back to document level only if it covers S. Mapping, e.g. CycloneDX aggregates: `complete` → Present; `incomplete*` → Incomplete; `unknown` / `not_specified` → Unknown. Formats with no completeness field give `Unknown`. |
| BIND | Binding of the inventory and declaration to S (digest, else product and version). |
| GEN | Declared generation method of the primary SBOM, evaluated relative to C specifically (including `C.ecosystem`). Exactly one of: `manifest_only` (the documented method explicitly lists only manifest-class sources, §4.3); `content_based` (the documented method performs content-based analysis and, relative to C, the primary SBOM satisfies every requirement of a content-based basis in §4.3); `unknown` (any other case, including an absent or ambiguous method, content-based analysis whose declared ecosystem coverage excludes `C.ecosystem`, or content-based analysis that fails another basis requirement). |

### 4.2 Rules

| ID | Condition | Ceiling | Class | Code |
|---|---|---|---|---|
| N1 | Aggregated MATCH = Present, from any document including a corroborating one. Does not apply when the aggregated MATCH state is Contradictory (see N17) | Insufficient | CONTRADICTORY | `CLAIM_CONTRADICTED_BY_INVENTORY` |
| N2 | INV Unknown or missing | Insufficient | CANNOT | `NO_INVENTORY` |
| N3 | BIND Unknown or mismatched | Insufficient | CANNOT | `SCOPE_UNBOUND` |
| N4 | INV Contradictory through an inventory-level structural contradiction or inconsistency not already classified as a MATCH-only contradiction under N17 (e.g., a dependency edge references a `bom_ref` absent from the component list, or documents disagree about the component list other than through the MATCH-only conflict of N17) | Insufficient | CONTRADICTORY | `INVENTORY_CONTRADICTION` |
| N5 | DECL Unknown **and** `PROV_SBOM` = P0 | Insufficient | CANNOT | `NO_EVIDENTIAL_VALUE` |
| N6 | DECL Incomplete | Weak | BELOW | `DECLARED_INCOMPLETE` |
| N7 | DECL Unknown **and** `PROV_SBOM` ≥ P1 | Weak | BELOW | `COMPLETENESS_UNDECLARED` |
| N8 | MATCH Ambiguous | Weak | BELOW | `AMBIGUOUS_IDENTITY` |
| N9 | MATCH Incomplete (variants under-enumerated) | Weak | BELOW | `VARIANT_COVERAGE_INCOMPLETE` |
| N10 | DECL Present **and** `PROV_DECL` = P0 | Weak | BELOW | `UNATTRIBUTED_DECLARATION` |
| N11 | DECL Present **and** `PROV_DECL` ∈ {P1, P2} | Weak | BELOW | `DECLARATION_BELOW_P3` |
| N12 | `PROV_SBOM` < P3 | Weak | BELOW | `INVENTORY_PROVENANCE_BELOW_P3` |
| N13 | Contradiction confined to provenance metadata | Weak | CONTRADICTORY | `PROVENANCE_INCONSISTENT` |
| N14 | **Manifest-only trigger** (see below) | Weak | BELOW | `MANIFEST_ONLY_UNCORROBORATED` |
| N15 | Same as N14, but the primary SBOM's GEN relative to C = `unknown` | Weak | CANNOT | `GENERATION_METHOD_UNKNOWN` |
| N16 | A separate content-based corroborating document is relied upon to remove N14/N15, but its effective provenance is below P3 | Weak | BELOW | `CORROBORATION_PROVENANCE_BELOW_P3` |
| N17 | MATCH Contradictory: one in-scope document finds C under a valid identifier while another source with declared sufficient coverage asserts absence for the corresponding scope | Insufficient | CONTRADICTORY | `MATCH_CONTRADICTION` |

**Interaction of N1, N4, and N17 (deterministic output).** All rules are still evaluated and every genuinely applicable code is preserved (§3). N1 applies when the aggregated MATCH state is Present; it does not also fire when the aggregated MATCH state is Contradictory and N17 applies. N17 exclusively handles the defined MATCH-Contradictory case. N4 applies to inventory-level structural contradictions or inconsistencies not already classified as a MATCH-only contradiction under N17; it does not fire solely because of the conflicting MATCH observations covered by N17. If an independent inventory-level contradiction is also present, N4 and N17 both fire.

### 4.3 Manifest-only trigger (N14 and N15), defined precisely

**Preconditions for either rule:**
- `S.artifact_kind ∈ {binary, container}`, and
- no *content-based basis for C* exists.

A **content-based basis for C** is a source document d such that all of these hold:
- BIND(d) is Present.
- EP(d) ≥ P1.
- d's declared method includes analysis of the shipped artifact's contents: filesystem or layer scan, binary composition analysis, or inspection of embedded archives.
- d's declared coverage of the artifact is whole, not Incomplete.
- d's declared ecosystem coverage includes `C.ecosystem`.

The primary SBOM can itself be such a document. Its result for C must not be Present (that is N1, or N17 if another source with declared sufficient coverage asserts absence) and must not otherwise conflict with the primary SBOM at inventory level (that is N4).

A qualifying content-based basis for C must satisfy every requirement above, including artifact binding, sufficient (whole) coverage, applicable ecosystem coverage (`C.ecosystem`), and provenance (EP ≥ P1). A method being content-based for unrelated ecosystems is not sufficient evidence for C.

**N14 additionally requires** that the primary SBOM's documented `method` explicitly indicates manifest-only generation: it lists only package manifests, lockfiles, build descriptors, or source-declared dependency metadata, with no analysis of the shipped artifact's contents. An explicit method of that kind establishes GEN = `manifest_only`. `generation_context ∈ {source, build}` may support that interpretation but is not, by itself, sufficient to classify the method as manifest-only, and never alone triggers N14.

GEN is evaluated relative to C specifically. If the primary SBOM's documented method performs content-based analysis but its declared ecosystem coverage does not include C.ecosystem, GEN relative to C is `unknown`, and N15 applies if no other qualifying content-based basis for C exists.

Under the preconditions above, GEN relative to C is therefore exactly one of `manifest_only` (N14) or `unknown` (N15). `content_based` means the primary SBOM is itself a qualifying basis, so the preconditions do not hold and neither rule fires. A primary SBOM cannot bypass both N14 and N15.

**N15 instead applies** when GEN relative to C is `unknown`, so manifest-only generation cannot be ruled out. GEN is `unknown` whenever it is neither `manifest_only` nor `content_based` relative to C as defined in §4.1: for example, when the method is absent or ambiguous, does not clearly list only manifest-class sources and does not qualify as content-based for C, or performs content-based analysis that fails a basis requirement. In particular, do not infer `manifest_only` from `generation_context` alone when the method is not established. For a binary or container finding with no qualifying content-based basis, N15 caps the verdict at Weak.

**N16 applies** when the content-based basis is a document separate from the primary SBOM (a corroborating scan), and that document's EP is below P3. Per the minimum-across-documents rule (§1.2, rule 5), a separate document relied upon to support the Supported verdict must independently meet the P3 floor; it cannot borrow the primary SBOM's provenance. If the primary SBOM itself is the content-based basis, N16 does not apply: `PROV_SBOM` is used directly and no separate `PROV_CORR` value is instantiated.

**Effect.** A content-based basis removes N14 and N15. N16 may still apply if that basis is a separate document below P3. These rules never raise the verdict above any other triggered ceiling.

### 4.4 Supported requires ALL

- INV Present as a full list.
- MATCH Absent over all variants.
- DECL Present (complete).
- BIND Present.
- `PROV_SBOM` = P3 and `PROV_DECL` = P3.
- For binary or container artifacts, a content-based basis exists, and if that basis is a separate corroborating document (not the primary SBOM), its EP = P3.
- None of N1–N17 triggered.

**Sufficiency vs. truth.** Supported means: *an SBOM with attributed, integrity-protected origin declares its list complete for S, C appears nowhere in it, and for binary or container artifacts the inventory is backed by content-appropriate evidence meeting the same provenance bar.* It does not mean C is absent. Signatures and hashes establish authenticity and identity, not completeness.

### 4.5 Assumptions

- **A1.** The SBOM parses correctly.
- **A2.** Normalization is deterministic and versioned.
- **A3.** V supplies enough identifiers to enumerate variants. This assumption holds only when C is established per §1's VEX-target-component rule; when no subcomponent identifies C, this assumption does not apply and MATCH is extracted as Unknown per that rule.
- **A4.** Completeness is a self-assertion by the generator.
- **A5.** Trust anchors are configured externally. The spec consumes the verification result `signature_verified` (a boolean) and, when available, the verified locator coverage `established_coverage` that the result establishes.
- **A6.** S identifies the artifact unambiguously.
- **A7.** Declared generation method and ecosystem coverage are read from document metadata. They are self-asserted.

### 4.6 Counterexamples

- **CE-N1. Vendored or shaded code.** Content analysis misses relocated, renamed, or statically linked code. A signed, complete, corroborated SBOM yields Supported while C is present.
- **CE-N2. Wrong self-assertion.** A buggy or compromised generator signs a false "complete." The signature proves origin, not accuracy.
- **CE-N3. Variant gap.** C ships as a fork or repackage under coordinates no enumerated variant covers.
- **CE-N4. Scope drift.** BIND by product name only, with a layer added after generation.
- **CE-N5. Over-conservatism (false Weak).** A correct, complete internal unsigned SBOM caps at Weak. This is intended under P-1.
- **CE-N6. Coarse corroboration.** A layer scan declares coverage of `deb` and a language ecosystem, but only reads package databases. The corroboration criteria pass and the predicate yields Supported while a vendored library is present. Declared ecosystem coverage is self-asserted.
- **CE-N7. Misdeclared artifact kind.** S says `source` while a container is what ships, which bypasses N14.

### 4.7 Test cases

All cases assume BIND Present and `PROV_DECL` = `PROV_SBOM` unless stated.

| # | kind | INV | MATCH | DECL | PROV_SBOM / PROV_DECL | GEN / content-based basis | Expected | Codes |
|---|---|---|---|---|---|---|---|---|
| NT1 | source | Present | Absent | Present | P3 / P3 | n/a | **Supported** | none |
| NT2 | source | Present | Absent | Present | P1 / P1 | n/a | **Weak** | N11, N12 |
| NT3 | source | Present | Absent | Present | P3 / P1 (declaration outside signed coverage) | n/a | **Weak** | N11 |
| NT4 | source | Present | Absent | Incomplete | P3 / P3 | n/a | **Weak** | N6 |
| NT5 | source | Present | Ambiguous | Present | P3 / P3 | n/a | **Weak** | N8 |
| NT6 | source | Contradictory (dangling `bom_ref`) | Absent | Present | P3 / P3 | n/a | **Insufficient** | N4 |
| NT7 | source | Present | Absent | Unknown | P0 | n/a | **Insufficient** | N5, N12 |
| NT8 | source | Present | Absent | Unknown | P1 (same result at P2, P3, minus N12) | n/a | **Weak** | N7, N12 |
| NT9 | container | Present | Absent | Present | P3 / P3 | manifest_only; no basis | **Weak** | N14 |
| NT10 | container | Present | Absent | Present | P3 / P3 | manifest_only; basis = separate layer scan, EP P3, bound, whole-artifact, ecosystem ⊇ C's, no match | **Supported** | none |
| NT11 | container | Present | Absent | Present | P3 / P3 | unknown; no basis | **Weak** | N15 |
| NT12 | container | Present | Absent | Present | P3 / P3 | manifest_only; basis covers OS packages only, C is another ecosystem | **Weak** | N14 |
| NT13 | any | Present | Present | Present | P3 / P3 | any | **Insufficient** | N1 |
| NT14 | container | Present | Absent | Present | P3 / P3 | manifest_only; basis = separate layer scan, EP P1, bound, whole-artifact, ecosystem ⊇ C's, no match | **Weak** | N16 |
| NT15 | container | Present | Absent | Present | P3 / P3 | content_based; primary SBOM itself analyzes shipped contents, bound, whole-artifact, ecosystem ⊇ C's, no match | **Supported** | none |
| NT16 | container | Present | Absent | Present | P3 / P3 | unknown (`generation_context` = build; method not stated, so `manifest_only` is not inferred); no basis | **Weak** | N15 |
| NT17 | container | Present | Absent | Present | P3 / P3 | primary SBOM method explicitly performs content-based analysis, but its declared ecosystem coverage excludes `C.ecosystem`; no separate qualifying basis; GEN relative to C = unknown | **Weak** | N15 |
| NT18 | source | Present (structurally consistent) | Contradictory (one P3 source finds C under a valid identifier; another P3 source with declared sufficient coverage asserts absence for the corresponding scope; MATCH-only conflict) | Present | P3 / P3 | n/a | **Insufficient** | N17 (not N1, not N4) |
| NT19 | source | Present | Present (aggregate of `Present` + `Incomplete`, no `Absent`; cf. AG1) | Present | P3 / P3 | n/a | **Insufficient** | N1 |
| NT20 | source | Contradictory (two P3 documents disagree about the component list for a component other than C; no source records C) | Absent | Present | P3 / P3 | n/a | **Insufficient** | N4 |
| NT21 | source | Contradictory (independent structural inconsistency, e.g. dangling `bom_ref`) | Contradictory (as NT18) | Present | P3 / P3 | n/a | **Insufficient** | N4, N17 |

Regression coverage for the N1/N4/N17 split: NT13 and NT19 exercise N1, NT6 and NT20 exercise N4, NT18 exercises N17 alone, and NT21 shows N4 and N17 co-firing when both conditions are independently present.

## 5. Req(vulnerable_code_not_in_execute_path)

**Claim.** The vulnerable code in C, as identified for V, cannot execute in S under the declared configuration.

### 5.1 Dimensions and evidence kinds

| Dim | Subject |
|---|---|
| LOCUS | Vulnerable code location. It must be an over-approximation. A coarser locus (package-level) is acceptable. A possibly under-approximate subset is `Incomplete`. |
| REACH | A call path from an entry point to the locus. |
| ENTRY | The entry-point set used. For a library, the full public API. |
| HAZ[class] | Per-hazard disposition (§5.3). |
| CFG | The configuration the analysis holds under, recorded in S. |
| BIND | Binding of the analysis to the artifact and component version. |

**Evidence kinds for REACH:**
- **K1:** call-graph or equivalent authoritative analysis with declared tool, algorithm, entry points, and coverage.
- **K2:** an assertion of (non-)reachability that discloses no analysis artifacts.
- **K3:** runtime coverage or trace data.
- **K4:** package or SBOM **dependency** graph only.

**Dependency edge vs. call edge.** A *dependency edge* (SBOM or package graph) is not a *call edge* (inside a K1 analysis). A missing dependency edge alone is `Unknown` reachability and must never support a non-reachability conclusion. It is never an input to `Absent`.

**REACH state derivation (deterministic, evaluated in order):**
1. **Positive observation.** Any item of any kind, at any EP, that observes or asserts a path or execution of the locus counts as positive. Positive plus a K1 `Absent` gives `Contradictory`. Positive alone gives `Present`.
2. **K1 basis.** Otherwise, if K1 reports exist, aggregate them under §2. `Absent` requires a declared full-coverage claim over LOCUS and ENTRY.
3. **Non-exhaustive basis.** Otherwise, if there is a K3 no-hit observation, or a K2 negative assertion with EP ≥ P1, the state is `Incomplete` with basis `non_exhaustive`. Runtime and assertion evidence cannot be `Absent`, because it never declares sufficient coverage.
4. **Otherwise** the state is `Unknown`. This includes K2 with EP = P0, K4 only, and no evidence.

`PROV_REACH` = the minimum EP over the documents that the REACH conclusion depends on. It is undefined when REACH is Unknown.

### 5.2 Hazard-exclusion provenance

Each hazard class has a disposition: `Excluded-by-evidence`, `Modeled-conservatively`, `Unmodeled`, or `Unknown`. The default is `Unknown`.

- **Excluded-by-evidence** is a claim with its own `basis_ref`. It stands only if the basis is bound to S **and** `PROV_HAZ[class]` = EP(basis) ≥ P1.
- **Normalization (Step 1).** If the basis is missing, unbound, or EP < P1, the disposition is **downgraded to `Unknown`**. The code `HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>` is recorded with R11.
- **Modeled-conservatively** must be declared inside a K1 report. It inherits `PROV_REACH`. Otherwise it is `Unknown`.

### 5.3 Hazard classes (lowering-only)

- reflection
- dynamic or class loading and plugins
- configuration-dependent paths (flags, profiles, dependency-injection wiring)
- native and FFI boundaries
- serialization gadget paths
- generated or annotation-driven code
- inter-process and inter-service calls
- build-time pruning differences

A tool's failure to detect one of these is not evidence that it is absent.

### 5.4 Rules

| ID | Condition | Ceiling | Class | Code |
|---|---|---|---|---|
| R1 | REACH Present | Insufficient | CONTRADICTORY | `CLAIM_CONTRADICTED_BY_PATH` |
| R2 | REACH Unknown | Insufficient | CANNOT | `MISSING_EDGE_IS_UNKNOWN` if the only reachability-related evidence is K4; otherwise `NO_ANALYSIS` |
| R3 | REACH Contradictory | Insufficient | CONTRADICTORY | `REACH_CONFLICT` (e.g., static vs. runtime) |
| R4 | LOCUS Unknown | Insufficient | CANNOT | `NO_LOCUS` |
| R5 | ENTRY Unknown | Insufficient | CANNOT | `ENTRYPOINTS_UNDECLARED` |
| R6 | BIND Unknown or mismatched | Insufficient | CANNOT | `SCOPE_UNBOUND` |
| R7 | REACH basis `non_exhaustive` (derivation step 3) | Weak | BELOW | `NON_EXHAUSTIVE_EVIDENCE` |
| R8 | REACH Incomplete or Ambiguous with a K1 basis | Weak | BELOW | `PARTIAL_OR_UNRESOLVED_CALLGRAPH` |
| R9 | LOCUS Incomplete | Weak | BELOW | `LOCUS_MAY_BE_UNDERAPPROXIMATE` |
| R10 | ENTRY Incomplete | Weak | BELOW | `ENTRYPOINTS_INCOMPLETE` |
| R11 | Any HAZ class `Unmodeled` or `Unknown` after Step 1 | Weak | BELOW | `HAZARD_<CLASS>` (+ `HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:<CLASS>` if downgraded) |
| R12 | CFG undeclared, or the claim extends beyond analyzed configurations | Weak | BELOW | `CONFIG_ASSUMPTION_UNDECLARED` |
| R13 | REACH defined and `PROV_REACH` < P3 | Weak | BELOW | `ANALYSIS_PROVENANCE_BELOW_P3` |

**K2/K3 interaction and precedence.** K2 and K3 evidence is mapped to `Incomplete` (non-exhaustive) in derivation step 3. That is how it receives its Weak ceiling, and it is why R2 (Insufficient) cannot fire for K2 or K3 evidence of adequate attribution. R7 is the **only** rule that fires for a non-exhaustive basis, and R8 is limited to K1. The two never double-fire. If K1 exists, K2 and K3 contribute only through step 1: positive observations lead to `Present` or `Contradictory`. Because the verdict is the minimum over all triggered rules and all codes are kept, there is no order dependence.

### 5.5 Supported requires ALL

- REACH `Absent` from K1.
- LOCUS Present as an over-approximation.
- ENTRY Present and complete.
- Every hazard class is `Excluded-by-evidence` (PROV_HAZ ≥ P1) or `Modeled-conservatively`.
- CFG is declared and covers the claim.
- BIND Present.
- `PROV_REACH` = P3.
- None of R1–R13 triggered.

The P3 floor applies to the evidence behind the central conclusion (REACH). Hazard-exclusion bases have their own P1 floor (see U-5).

### 5.6 Assumptions

- **A1.** Analyzer output carries its declared metadata.
- **A2.** The locus comes from authoritative sources.
- **A3.** Entry points are supplied by the analysis or evaluator.
- **A4.** The hazard enumeration is closed and versioned.
- **A5.** Dependency edges are not call edges.
- **A6.** Soundness claims are recorded as claimed, not verified.
- **A7.** Deployment configuration is recorded in S.

### 5.7 Counterexamples

- **CE-R1. Flawed hazard exclusion.** A P1-attributed exclusion basis missed a configuration-resolved class load. The verdict is Supported while the code is reachable.
- **CE-R2. Entry-point omission.** A scheduled job or annotation-registered endpoint is missing from the entry set.
- **CE-R3. Library consumers.** The entry set models the library's own tests, not downstream callers.
- **CE-R4. Configuration flip.** Production enables a flag that the recorded CFG does not cover.
- **CE-R5. Mis-identified locus.** The patch diff names a symbol that is not the root cause.
- **CE-R6. Signed but unsound.** A P3 report is signed but its algorithm is unsound for the program's idioms. The signature authenticates origin, not soundness.

### 5.8 Test cases

Baseline **RT1**: LOCUS Present; REACH Absent (K1, full coverage); ENTRY Present and complete; HAZ: reflection `Excluded` with basis EP = P1, all other classes `Modeled`; CFG declared; BIND Present; `PROV_REACH` = P3.

| # | Variation from baseline | Expected | Codes |
|---|---|---|---|
| RT1 | none | **Supported** | none |
| RT2 | Only K4 evidence (missing dependency edge). LOCUS Present, ENTRY Unknown, all HAZ Unknown. | **Insufficient** | R2 `MISSING_EDGE_IS_UNKNOWN`, R5, R11 (all classes) |
| RT3 | Reflection `Unknown` | **Weak** | R11 `HAZARD_REFLECTION` |
| RT4 | K1 `Absent` plus K3 trace hit | **Insufficient** | R3 |
| RT5 | K1 `Incomplete` (modules unanalyzed or timeout) | **Weak** | R8 |
| RT6 | K1 `Ambiguous` (unresolved may-reach edges) | **Weak** | R8 |
| RT7 | Reflection exclusion basis EP = P0 | **Weak** | R11 `HAZARD_REFLECTION`, `HAZARD_EXCLUSION_PROVENANCE_BELOW_P1:REFLECTION` |
| RT8 | `PROV_REACH` = P2 | **Weak** | R13 |
| RT9 | No K1. K3 no-hit trace (EP P3). All hazards `Excluded` with bases ≥ P1. | **Weak** | R7 |
| RT10 | No K1. K2 negative assertion, EP = P3. Hazards as RT9. | **Weak** | R7 |
| RT11 | No K1. K2 negative assertion, EP = P0. | **Insufficient** | R2 `NO_ANALYSIS` (+R5, R11 per fixture) |

## 6. Invariants for Later Metamorphic Validation

- **M-1.** Degrading any state, EP, or hazard disposition never raises a verdict.
- **M-2.** Deleting evidence never turns `Unknown` into `Absent`.
- **M-3.** The same F gives the same `(verdict, codes)`.
- **M-4.** Injecting a positive observation (match, path) into any finding yields Insufficient.
- **M-5.** Every triggered rule appears in the rationale.
- **M-6.** Changing only free-text fields never changes the verdict.

## 7. Remaining Assumptions and Unresolved Decisions

**Resolved:**
- D-1 and D-2: P3 for both predicates.
- D-3: manifest-only ceiling (N14, N15).
- D-6: CISA element names (SBOM Author Signature, Component Hash Value/Algorithm, SBOM Generation Context, SBOM Tool Name/Version, Coverage) and the July 29, 2026 release date were cross-checked against multiple secondary industry sources describing the published guidance. The primary CISA document's exact text and section numbers have not been independently read and must be confirmed before dissertation citation.
- Provenance consistency for corroborating documents (N16), per the minimum-across-documents rule.
- The `PROV_HAZ` P1 floor, compared with P3 for `PROV_SBOM`, `PROV_DECL`, `PROV_REACH` and separate CNP corroborating evidence, is an intentional profile choice. The residual risk represented by CE-R1 remains documented for the dissertation's discussion and limitations section.

**Out of scope by design:**
- D-5: downstream acceptability of Weak (§3).

**Non-blocking future-profile consideration:**
- **U-5.** A future profile may evaluate whether to raise the hazard-exclusion provenance floor to P3. This is not an unresolved defect, and the current P1 rule is unchanged.

**Unresolved:**
- **U-1.** The primary CISA 2026 Minimum Elements document's exact text, section numbers, and any formal field definitions have not been independently read. Confirm directly against the published PDF before the dissertation cites specific clauses.
- **U-2.** Trust-anchor configuration and key governance.
- **U-3.** Ecosystem coverage and content-based method are self-asserted by the corroborating tool (CE-N6). Consider a controlled vocabulary.
- **U-6.** LOCUS provenance is recorded but not gated.
- **U-7.** How `generation_context` and method class are extracted from specific SBOM formats (CycloneDX lifecycles and tools, SPDX creation info) is unspecified.
- **U-9.** "Overlapping scope" (§2, rule 2/AG2) has no formal definition; an implementation choice is needed.
- **U-10.** M-1's "degrading a state never raises a verdict" should be clarified to state it governs claim-unfavorable degradation; AG1 (Present + Incomplete = Present) is not a counterexample since adding corroborating-but-weaker evidence to an existing positive observation is not a degradation of that observation.
- **U-11.** Zero evidence items for a subject should explicitly map to Unknown (already implied by the Unknown definition, but not stated in the aggregation procedure itself).
