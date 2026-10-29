# Batch runner and scanner-report adapters

```
python -m batch_runner --sbom SBOM.json --vex VEX.json --scanner trivy.json [--scanner grype.json --scanner osv.json]
                       --artifact-kind source|binary|container|other [--assert-full-inventory NAME] [--verification V.json] [--out RESULT.json]
```
Reads what real tools produce (a CycloneDX/SPDX SBOM, an OpenVEX document, Grype / Trivy / OSV-Scanner JSON reports) and reports, per
(component, vulnerability) that a scanner found, what the evidence evaluator says about the VEX claim for it. Exit 0 = reconciled, 2 = unusable input.

What it does and does not do
* Scanner findings are merged across tools by shared vulnerability ids on the same package version; they are *claims by the scanner*, never evidence.
* Only `not_affected` + `component_not_present` statements are evaluated. Other statuses/justifications get `status: not_evaluated` with the reason;
  findings with no statement get `no_vex_claim`.
* Profile facts come from the SBOM subject (version, SHA-256) and the scanner (target component by purl). Nothing is invented: no digest in the SBOM
  means an unbound scope (Insufficient). The inventory-completeness assertion exists only when `--assert-full-inventory` is given, because it is a human fact.
  `--artifact-kind` is required because it cannot be read reliably from an SBOM.
* Placement mirrors the SBOM: libraries under `metadata.component.components` -> nested under the subject, else top level.
* If a scanner reports a component the SBOM does not list, the row carries `SCANNER_REPORTS_COMPONENT_NOT_IN_SBOM`: the SBOM may be incomplete and the
  verdict (which assumes it is the inventory) should not be trusted.

Limits: the Grype adapter was written from Grype's documented schema and is tested on a documented-shape fixture only; the Trivy and OSV-Scanner
adapters are tested on trimmed real outputs and on every full report of `experiments/benchmark5`. As measured there, flat Syft SBOMs cannot reach `Supported`
(decision G6-D13) and real verification input is still needed for P3; the runner reports that honestly instead of working around it.
