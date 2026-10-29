# Metamorphic validation framework: checkpoints

Goal (dissertation Phase III): security-semantic mutation operators over SBOM/VEX/profile/reachability evidence, and executable metamorphic relations
(the specification's invariants M-1..M-6, section 6), run as a deterministic, denominated campaign. Code: `tests/metamorphic/`. The mapping of M-1..M-6
to the dissertation's MR1-MR5 names is **to be confirmed by the author** (the Phase-I report does not define MR1-MR5 operationally); until then the
specification's identifiers are used.

| Checkpoint | Scope | Status |
|---|---|---|
| CP1 | Framework vocabulary (scenario, observation, operator, relation), CNP base scenarios, neutral operators (M-6), determinism (M-3) and rationale (M-5) relations, tests proving each relation can fail | done |
| CP2 | CNP evidence operators: delete dependency edge/component/declaration, alter/remove version/identifier/digest, ambiguous identifier, orphan component, provenance degradation, remove verification, remove VEX justification; relations M-1, M-2, M-4 | done |
| CP3 | Reachability operators (drop K1/coverage claim/entry points/hazard basis, weaken provenance, inject a positive path, unresolved evidence) over reachability scenarios | done |
| CP4 | Campaign report (JSON/markdown, denominators, violations, "mutation changed the verdict" counts), `python -m tests.metamorphic [--check]`, wired into `tests.validate_all` | planned |
| CP5 | Documentation: relation/operator catalogue, MR mapping, findings (including candidate non-monotone behaviour), threats to validity; update the readiness document and register | planned |

Each checkpoint is committed and pushed only after `python -m tests.validate_all` passes.
