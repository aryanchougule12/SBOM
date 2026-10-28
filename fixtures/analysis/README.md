# Analyzer-artifact corpus

Inputs and reviewed expectations for the analyzer-artifact adapters (`evidence/analysis_*.py`).
`manifest.json` lists every case; each case records its source, its expected outcome and **why** the
expectation follows from the formal rules. Run the corpus with `python -m tests.analysis_eval`.

Categories are kept strictly apart. **Category L** (`authentic/codeql/`) is unedited output of live
CodeQL 2.27.3 runs made for this repository (provenance and exact commands in
`authentic/codeql/REPRODUCE.md`). Category A is upstream example/test data; category B is synthetic.
**No authentic Joern output was obtained** (the distribution is about 1.7 GB; not installed), so every
Joern GraphML here is synthetic. The corpus must not be described as an evaluation of CodeQL or Joern: it
checks the adapters against hand-reviewed expectations.

## Categories

| Category | Directory | What it is |
|---|---|---|
| **A** | `upstream/` | Files copied **byte-for-byte** from public repositories (provenance below). They are format examples / upstream test data, not verified-unmodified outputs of a live run. |
| **L** | `authentic/codeql/` | **Live CodeQL 2.27.3 output** (3 SARIF files from two tiny JavaScript projects written for this repository; the SARIF is tool output, the sources are MIT-licensed here; CodeQL bundle and queries are GitHub's, MIT). Not a labelled ground truth. |
| **B** | `sarif/`, `joern-graphml/` | **Synthetic** controlled fixtures written for this repository to the documented formats, each testing one edge case. |

## Category A provenance

| File | Origin (repository, path) | Commit | License | What it is |
|---|---|---|---|---|
| `codeql-action__fingerprinting.input.sarif` | `github/codeql-action` `src/testdata/fingerprinting.input.sarif` | `354d3a23c0a0a30518fc36e7ed533bc072f874f6` | MIT | CodeQL-format (CLI 2.0.0) SARIF: two findings, `%SRCROOT%` URIs and an `index`-only location; no code flows |
| `codeql-action__valid-sarif.sarif` | same, `valid-sarif.sarif` | same | MIT | Two runs (LGTM.com 1.24.0-SNAPSHOT, CodeQL 2.0.0), three findings, no code flows |
| `codeql-action__empty-sarif.sarif` | same, `empty-sarif.sarif` | same | MIT | LGTM.com run with an empty `results` array |
| `codeql-action__invalid-sarif.sarif` | same, `invalid-sarif.sarif` | same | MIT | Deliberately invalid: `results` is the number 42 |
| `codeql-action__tool-names.sarif` | same, `tool-names.sarif` | same | MIT | Five runs with different tool names, one `null` and one empty (invalid) |
| `codeql-action__with-invalid-uri.sarif` | same, `with-invalid-uri.sarif` | same | MIT | A finding whose `uri` is not a valid URI reference; no code flow |
| `sarif-tutorials__bad-eval-with-code-flow.sarif` | `microsoft/sarif-tutorials` `samples/3-Beyond-basics/bad-eval-with-code-flow.sarif` | `819b0f62f47ecde9a8f24dfc387c41926f5edabe` | CC-BY-4.0 (docs) / MIT (code) | Microsoft's documented SARIF example with a `codeFlow` (a documentation example, tool `PythonScanner`) |
| `sarif-tutorials__CodeFlows.sarif` | same, `samples/CodeFlows.sarif` | same | same | Documented example with two code flows through `collections/list.h` |
| `sarif-tutorials__bad-eval.sarif` | same, `samples/3-Beyond-basics/bad-eval.sarif` | same | same | The finding of the first example without its code flow |

The SHA-256 of every file is in `manifest.json` and is re-checked by the harness. No upstream file was
edited.

## Category B

SARIF fixtures follow the official OASIS schema (`third_party/sarif-schema-2.1.0.json`; the tests
validate every one against it, except the deliberately invalid ones) and CodeQL's path-problem shape
(`codeFlows[].threadFlows[].locations[]`, `versionControlProvenance`, `invocations`).

The **Joern GraphML fixtures are modelled on the exporter's source**, not on a real export: no
Joern-generated GraphML file was obtainable. They follow `flatgraph`'s `GraphMLExporter`
(`joernio/flatgraph` @ `45d3b703d410dc70a5fe615573ae53a2a50647b3`: `labelV`/`labelE` keys,
`node__<LABEL>__<PROPERTY>` data keys, one directed `<graph id="G">`) and the code property graph schema
(`ShiftLeftSecurity/codepropertygraph` @ `d02d76ea5c9e3b398317d334228d7e8e78ab45aa`: `META_DATA`,
`METHOD`, `CALL` nodes; `CALL` and `CONTAINS` edges). Whether a real `joern-export` file always has
exactly this shape has not been verified here.

## Default scenario of every case

SBOM: `fixtures/equivalent/app.cdx.json`. VEX: `fixtures/openvex/reachability_equivalent.json` (target
`pkg:npm/lib-b@2.0`, justification `vulnerable_code_not_in_execute_path`). The evaluator-entered
`AnalysisSubject` (artifact, target, source repository/revision/hash, target source root, entry methods)
and the locus are in `manifest.json` `defaults`; a case overrides only what it tests.
