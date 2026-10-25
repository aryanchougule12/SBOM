# SBOM evidence-sufficiency prototype

A research prototype for judging whether the *recorded evidence* behind a VEX
`not_affected` claim meets a defined bar. It is not production software.

## Authoritative specification

The committed specification is the sole source of truth:

- `docs/formal_specification_v0.2.md`
- `docs/spec_addendum_v0.2.1.md`

Both are fixed at commit `e0d5bfadf9bd45e753051d7e7c8654f656ddb8ef` and are not
modified by this project's code stages.

## Research scope

Two predicates are specified:

- `Req(component_not_present)` (spec §4, rules N1–N17)
- `Req(vulnerable_code_not_in_execute_path)` (spec §5, rules R1–R13)

A verdict is exactly one of **Supported**, **Weak** or **Insufficient**. A verdict
states whether the recorded evidence meets the specification's bar. It does not say
whether the claim is true (spec P-1); ground-truth validation is out of scope here.
Whether a verdict is acceptable to a downstream consumer is a policy question outside
the formal procedure (D-5). The provenance ladder P0–P3 and the P3 threshold are this
prototype's proposed profile, not a classification defined by CISA (P-4).

## Current status: Stage 0 scaffold only

This repository currently contains the module layout and typed data model. **No
parsing, evidence extraction, predicate logic, verdict calculation or report rendering
is implemented.** Unimplemented functions raise `NotImplementedError`. Nothing here
is validated.

## Module structure

| Path | Role |
|---|---|
| `model.py` | Typed dataclasses and enums for F = (C, V, D, J, E), scope S, source-document provenance and evidence items. Data only. |
| `sbom_parser/cyclonedx.py`, `spdx.py`, `openvex.py` | Parser interfaces (stubs). No schema version is claimed as supported. |
| `evidence/extraction.py` | Evidence extraction interface (stub). |
| `evidence/requirements.py` | Entry points for the two predicates (stubs). |
| `evidence/sufficiency.py` | Entry point for the spec §3 decision procedure (stub). |
| `reports/verdict.py` | Verdict and rationale-class types; rendering stub. |
| `tests/` | Smoke and structure tests; future behaviour is listed as skipped. |
| `fixtures/` | Empty (`.gitkeep`); fixtures belong to a later approved stage. |

## Running the tests

From the repository root:

```
python -m pytest -v -rs
```

`python -m` is used so the repository root is on the import path. Install the
dependencies first with `pip install -r requirements.txt`. At Stage 0 the parsing
libraries listed there are not yet imported by any module; only `pytest` is needed to
run the tests. Skipped tests are placeholders for functionality that does not exist
yet, and `-rs` prints their reasons.

## Mapping to FR-01–FR-09

**Pending.** No SRS defining FR-01–FR-09 is present in this repository, so no mapping
is given and none has been invented.
