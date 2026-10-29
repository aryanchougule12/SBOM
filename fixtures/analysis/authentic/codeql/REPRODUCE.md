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


## Recorded runs (`recorded/`)

Three further runs of the same CodeQL 2.27.3 bundle, executed through the recorder (`python -m analysis_runner run PLAN.json --out RUN.json`) on a clean
`git worktree` of commit `941e384b4a75820cb0f11fe879f2d9ce1384a626` of this repository, with the database and the output outside the analysed
directory. For each run the directory contains the SARIF (unedited CodeQL output) and `*.run.json` (the runner's record, unedited, canonical form).

| Run | Analysed directory (git tree id) | Query |
|---|---|---|
| `flow-via-vendor-lib` | `fixtures/analysis/authentic/codeql/project` (`0114c001fcd79f7e7dbb0bc791766d5c5a971a53`) | `Security/CWE-078/CommandInjection.ql` |
| `no-results` | the same | `Security/CWE-022/TaintedPath.ql` |
| `flow-app-only` | `fixtures/analysis/authentic/codeql/project-app-only` (`428b3b9cc1821dd900c5cf52f049c5b7677d200b`) | `Security/CWE-078/CommandInjection.ql` |

A plan has this shape (paths are those of the machine that ran it; the records keep them in `source.roots` and `configuration.command`):

```json
{"run_id": "codeql-2.27.3-flow-via-vendor-lib", "repository": "https://github.com/aryanchougule12/SBOM.git", "repo_dir": "<clean checkout>",
 "analysis_subpath": "fixtures/analysis/authentic/codeql/project",
 "tool": {"name": "CodeQL", "version_command": ["<bundle>/codeql/codeql", "version", "--format=terse"], "output_format_version": "sarif-latest"},
 "languages": ["javascript"],
 "query": {"pack": "codeql/javascript-queries", "pack_version": "2.4.8", "query_ids": ["js/command-line-injection"], "claim_semantics": "taint_path_query"},
 "stages": [{"name": "database-create", "role": "extraction", "argv": ["<bundle>/codeql/codeql", "database", "create", "db", "--language=javascript", "--source-root=<analysed directory>", "--overwrite"]},
            {"name": "database-analyze", "role": "analysis", "argv": ["<bundle>/codeql/codeql", "database", "analyze", "db", "<query.ql>", "--format=sarif-latest", "--no-sarif-minify", "--output=out/flow-via-vendor-lib.sarif", "--rerun"]}],
 "outputs": ["out/flow-via-vendor-lib.sarif"], "target": {"purl": "pkg:npm/lib-b@2.0", "source_root": "vendor/lib-b"},
 "roots": [{"id": "analysis-root", "path": "<absolute analysed directory>", "role": "primary", "repository": "...", "revision": "..."}]}
```

What the records do and do not say: `claim_semantics` is `taint_path_query` (these are stock taint queries, not locus-reachability analyses), there is no entry-point
inventory and no coverage claim, so no absence can be derived from them (corpus LR01-LR07). Timestamps and the database differ per run; the git identity and the
query results reproduce. The tree id of an analysed directory can be recomputed with `git rev-parse <revision>:<directory>` (checked by `tests/test_analysis_live.py`).
