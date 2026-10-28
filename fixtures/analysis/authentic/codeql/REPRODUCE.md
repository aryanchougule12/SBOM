# Authentic CodeQL output (live runs)

These three SARIF files were produced **by a live run of the CodeQL CLI** in the session that created
this milestone (2026-10-28), on the two tiny JavaScript projects in `project/` and `project-app-only/`
(written for this repository, MIT; not a public repository). Nothing in them was edited after CodeQL
wrote them (`--no-sarif-minify` was used only so that they are reviewable; the content is CodeQL's).

| Item | Value |
|---|---|
| Tool | CodeQL command-line toolchain release **2.27.3** (the file's `tool.driver.semanticVersion`) |
| Distribution | `https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.3/codeql-bundle-linux64.tar.gz` (GitHub release asset of `github/codeql-action`), 695,275,440 bytes |
| Bundle SHA-256 (computed after download) | `64518dc413c8e7b5733fee2489e830a899bb1e3f28c8873b5869d5cc90164c5c` |
| Query pack | `codeql/javascript-queries` 2.4.8 (inside the bundle) |
| Queries | `Security/CWE-078/CommandInjection.ql` (`@kind path-problem`, rule `js/command-line-injection`); `Security/CWE-022/TaintedPath.ql` (rule `js/path-injection`, no result on these projects) |
| Language / extractor | `javascript`, no build step |

```bash
# unpack the bundle, then (paths relative to the bundle directory):
codeql database create db  --language=javascript --source-root=project
codeql database analyze db codeql/qlpacks/codeql/javascript-queries/2.4.8/Security/CWE-078/CommandInjection.ql \
       --format=sarif-latest --no-sarif-minify --output=flow-via-vendor-lib.sarif
codeql database analyze db codeql/qlpacks/codeql/javascript-queries/2.4.8/Security/CWE-022/TaintedPath.ql \
       --format=sarif-latest --no-sarif-minify --output=no-results.sarif
codeql database create db2 --language=javascript --source-root=project-app-only
codeql database analyze db2 .../CWE-078/CommandInjection.ql --format=sarif-latest --no-sarif-minify --output=flow-app-only.sarif
```

Re-running reproduces the results and code flows; the notification timestamps (`timeUtc`) and the
platform string differ per run, so the bytes do not.

## What each file is

| File | Results | Code flow |
|---|---|---|
| `codeql-2.27.3__js-command-injection__flow-via-vendor-lib.sarif` | 1 (`js/command-line-injection`) at `vendor/lib-b/src/parse.js:5` | one threadFlow of 8 locations, `src/app.js:7` (`req.url`) → ... → `vendor/lib-b/src/parse.js:5`; a `path-problem` data-flow path that crosses from the application into the vendored library |
| `codeql-2.27.3__js-tainted-path__no-results.sarif` | 0 | none: a successful run with an empty `results` array |
| `codeql-2.27.3__js-command-injection__flow-app-only.sarif` | 1 at `src/app.js:8` | one threadFlow entirely inside `src/app.js`; the vendored file is never visited |

## What these files do and do not show

* They are authentic output of CodeQL 2.27.3 for **these queries and projects**; they do not validate
  every CodeQL scenario (other languages, other queries, multi-run logs, suppressions, baselines).
* Real CodeQL output has **no `versionControlProvenance`** (the CodeQL CLI SARIF reference does not list
  it among the properties it generates) and **no `invocations[].startTimeUtc`** (notifications carry
  `timeUtc`). A real CodeQL log therefore cannot, by itself, be bound to a source revision, and under
  the strict P1 rule it is unattributed (P0) - see `docs/analysis_ingestion.md`.
* `invocations[0].executionSuccessful` is true and the `cli/file-coverage-baseline` /
  `js/baseline/expected-extracted-files` notifications exist, but they report extraction telemetry,
  not a coverage claim over the locus and entry points (§5.1 step 2).
