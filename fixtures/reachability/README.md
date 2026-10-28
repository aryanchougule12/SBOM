# Reachability evidence fixtures (SYNTHETIC)

Every file here is a **synthetic** test fixture for the reachability evidence input (schema `1`,
`evidence/reach_inputs.py`). None is the output of a real call-graph analyser, runtime tracer or
assertion. They exist to exercise the parser, the evaluator and the conformance harness, and they
support no claim about real-world accuracy.

| File | Purpose |
|---|---|
| `synthetic_baseline.json` | RT1-shaped evidence: one K1 report with a full-coverage claim, a complete entry-point set, a hazard basis document, an over-approximate locus and a declared configuration. With a trusted detached verification covering `#/finding` it evaluates to Supported; without it, Weak (R13). |
| `synthetic_k3_no_hit.json` | RT9-shaped: no K1; a K3 no-hit trace. |
| `synthetic_k2_p0.json` | RT11-shaped: a K2 negative assertion that is unattributed (P0). |
| `synthetic_k4_only.json` | RT2-shaped: no reachability document at all (the SBOM's dependency graph is the only evidence). |
