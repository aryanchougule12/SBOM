# benchmark5 — five constructed projects, scanners vs. an independent oracle, and this repository's tool

Reproduce: see "Pipeline" below. Results: `RESULTS.md` (generated). Raw tool outputs: `tool_out/`.

## Design
* **Five projects** (`projects/`, 47 pinned components, three ecosystems) built to resemble real manifests: `shop-frontend-api` (npm, old pins), `data-service`
  (PyPI, old pins), `billing-backend` (Maven: log4j-core 2.14.1, jackson-databind 2.9.8, …), `hardened-service` (npm + PyPI, recent pins), `legacy-mixed`
  (npm + PyPI + Maven). Every pinned version was checked to exist in its registry; this caught two fixture mistakes of mine (Django `3.2.0` → canonical
  `3.2`, Guava `24.1.1` → `24.1.1-jre`). Known inventory = `inventory_truth.json`.
* **SBOMs** are real Syft 1.55.0 output (CycloneDX 1.6, `sbom_raw/`, unmodified). Syft's inventory equals the known inventory exactly. `prepare_sboms.py`
  derives `sbom_clean/` by dropping `file` components and the project's own self-component and adding an `application` subject with the SHA-256 of a
  reproducible project tarball. CycloneDX 1.7 (Syft's default) was refused by this repository's parser when the benchmark was run (so 1.6 was generated); 1.7 support was added afterwards.
* **Oracle** (`oracle.py` → `oracle_raw.json`): all non-withdrawn OSV advisories naming each package, from OSV bulk dumps downloaded 2026-10-28/29
  (npm 28 Oct 21:18Z, PyPI 29 Oct 11:33Z, Maven 29 Oct 10:33Z). Affected-version decision uses my own comparators (npm semver, PEP 440 via `packaging`, Maven
  ComparableVersion rules; unit-checked) over OSV `ranges` (events sorted, because real records are not in ascending order) and, independently, the explicit `versions`
  list. One record where they disagree (Pillow 8.1.0 / PYSEC-2022-42980) is *disputed* and excluded from scoring.
* **Scoring** (`score_scanners.py`): unit = (component, advisory group), groups = alias closure (CVE/GHSA/PYSEC/…). TP reported & affected; FN affected & not
  reported; FP reported & not affected; TN not reported & not affected, over every advisory that names the package. Findings matching no oracle advisory are
  counted FP and listed (`unmapped`); there were none after one documented adjudication (NSWG-ECO-516 = CVE-2020-8203).
* **This repository's tool** (`evaluate_ours.py`): a *different task* — accept/reject VEX `component_not_present` claims. Truth by construction. See RESULTS.md §2.

## Pipeline
```
python oracle.py <dir with npm.zip PyPI.zip Maven.zip>   # oracle_raw.json
python prepare_sboms.py                                    # sbom_clean/
trivy sbom --skip-db-update ...; osv-scanner scan source --offline-vulnerabilities --sbom X.cdx.json ...; pip-audit -r ...; npm audit --package-lock-only
python score_scanners.py; python evaluate_ours.py; python report.py
```
Tool versions: Trivy 0.76.1 (DB updated 2026-10-29 07:17Z), OSV-Scanner 2.7.0 (offline, same OSV zips as the oracle), pip-audit 2.10.1 (PyPI JSON API, live),
npm 10.9.4 (`npm audit`, live registry), Syft 1.55.0. **Grype 0.121.0 could not be evaluated**: `grype.anchore.io` (its database host) returns 403 here.

## Limitations — read before quoting any number
1. **Oracle bias.** The oracle uses the OSV data that OSV-Scanner (offline) queries; OSV-Scanner's 100% is therefore largely an agreement check of my range
   evaluator against its matcher, not independent accuracy. pip-audit (PyPI advisory DB) and npm audit (GitHub advisories) draw on overlapping sources too.
   Trivy's misses can be genuine gaps *or* oracle over-inclusion (e.g. PYSEC-only records); each is listed, none was individually adjudicated.
2. **TN/FP are structurally easy**: the universe is advisories naming the same package, so name-confusion false positives (CPE matching) cannot appear. 0 FP
   here does not imply 0 FP on other inputs.
3. **Small, curated sample** (47 components, 5 projects, flat dependency lists with no transitive resolution); counts per advisory are very unequal
   (Pillow 120, jackson-databind 60), so micro-averaged accuracy is dominated by a few packages. Confidence intervals are Wilson on pooled pairs and treat them as
   independent, which they are not.
4. **Snapshot timing**: tools ran on different data dates (Trivy DB 07:17Z vs OSV dumps later the same day; live APIs for pip-audit/npm audit). Some Trivy
   misses are 2026-dated advisories published after its DB build.
5. **The repository tool's variant E uses a synthetic verification result** (`tests.pipeline_support.verification_for`): no cryptographic verification is performed.
   Its "Supported" therefore shows what the rules allow *given* a verified, nested, complete SBOM, not that such evidence is obtainable from Syft output. With
   flat Syft SBOMs (the normal case) no claim can reach Supported (project decision G6-D13). The tool's precision there is a safety property (FP = 0), and its low
   recall on real SBOMs is the cost of that conservatism.
