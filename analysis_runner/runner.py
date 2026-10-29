"""Executes an analysis plan and records what was observed, as an ``analysis-run/1`` record.

What the recorder observes (and therefore may state as ``observed_by_runner``): the executable that answered the version
command, the redacted argument vector of each stage, each stage's start and end instants, its exit status and whether it timed
out, the git identity of the analysed checkout before the run (commit, tree id, cleanliness, untracked and ignored files,
submodules), a digest of every file under the analysis root before and after the run (so that a modification during the run is
noticed), and the SHA-256 and size of each declared output.

What it does **not** establish, and never states: that the analyzer is sound or complete, that the query covers the code of
interest, that a successful exit status means the analysis reached every file, or anything about entry points. Fields it copies
from the plan (languages, query identity, claims about scope, the coverage claim) are recorded as ``caller_supplied``.

It never modifies the analysed project itself (it only reads it); the *plan's commands* may write wherever they are told to,
which is exactly what the before/after digest of the analysis root detects. No environment value is recorded and any argument
that looks like a credential is redacted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from evidence.analysis_run import REDACTED, AnalysisRunRecord, parse_analysis_run_data

_SECRET_NAME = re.compile(r"(?i)(token|secret|passw(or)?d|api[-_]?key|authorization|bearer|credential)")
_URL_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]+@")
_PLAN_KEYS = {"run_id", "repository", "repo_dir", "analysis_subpath", "target", "tool", "languages", "query", "stages", "outputs", "scope",
              "coverage_claim", "roots", "hash_executable"}
Clock = Callable[[], datetime]


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class Stage:
    name: str
    role: str
    argv: tuple[str, ...]
    timeout_s: float


@dataclass(frozen=True)
class Plan:
    run_id: str
    repository: str
    repo_dir: Path
    analysis_subpath: str
    tool_name: str
    version_command: tuple[str, ...]
    output_format_version: Optional[str]
    stages: tuple[Stage, ...]
    outputs: tuple[Path, ...]
    hash_executable: bool
    target: Mapping[str, Any]
    languages: Sequence[str]
    query: Mapping[str, Any]
    scope: Mapping[str, Any]
    coverage_claim: Optional[Mapping[str, Any]]
    roots: Sequence[Mapping[str, Any]]


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Replace values that look like credentials: the value after a ``--token``-like flag, ``NAME=value`` with a credential-like
    name, and the userinfo of a URL. The remaining arguments are kept verbatim."""
    out: list[str] = []
    redact_next = False
    for argument in argv:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        if argument.startswith("-") and "=" not in argument and _SECRET_NAME.search(argument):
            out.append(argument)
            redact_next = True
            continue
        if "=" in argument:
            name, _, value = argument.partition("=")
            if _SECRET_NAME.search(name):
                out.append(f"{name}={REDACTED}")
                continue
        out.append(_URL_USERINFO.sub(r"\1" + REDACTED + "@", argument))
    return out


def load_plan(path: Path) -> Plan:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PlanError(f"cannot read the plan: {error}") from None
    if not isinstance(data, dict):
        raise PlanError("the plan must be a JSON object")
    unknown = set(data) - _PLAN_KEYS
    if unknown:
        raise PlanError(f"unknown plan field(s): {', '.join(sorted(unknown))}")
    for key in ("run_id", "repository", "repo_dir", "tool", "stages"):
        if key not in data:
            raise PlanError(f"the plan needs {key!r}")
    tool = data["tool"]
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or set(tool) - {"name", "version_command", "output_format_version"}:
        raise PlanError("tool needs 'name' and may have 'version_command' and 'output_format_version'")
    stages = []
    for item in data["stages"]:
        if not isinstance(item, dict) or set(item) - {"name", "role", "argv", "timeout_s"} or not isinstance(item.get("argv"), list) \
                or not item["argv"] or not all(isinstance(a, str) for a in item["argv"]) or not isinstance(item.get("name"), str):
            raise PlanError("each stage needs 'name', 'argv' (non-empty list of strings), and optionally 'role' and 'timeout_s'")
        timeout = item.get("timeout_s", 600)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise PlanError("timeout_s must be a positive number")
        stages.append(Stage(item["name"], item.get("role", "other"), tuple(item["argv"]), float(timeout)))
    base = Path(data["repo_dir"])
    outputs = tuple((Path(o) if os.path.isabs(o) else base / o) for o in data.get("outputs", []))
    return Plan(
        run_id=data["run_id"], repository=data["repository"], repo_dir=base, analysis_subpath=data.get("analysis_subpath", "."),
        tool_name=tool["name"], version_command=tuple(tool.get("version_command", [])), output_format_version=tool.get("output_format_version"),
        stages=tuple(stages), outputs=outputs, hash_executable=bool(data.get("hash_executable", False)), target=data.get("target", {}),
        languages=data.get("languages", []), query=data.get("query", {}), scope=data.get("scope", {}),
        coverage_claim=data.get("coverage_claim"), roots=data.get("roots", []),
    )


# ---- git and file identity -------------------------------------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return done.returncode, done.stdout


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_fingerprint(root: Path, exclude: Sequence[Path] = ()) -> str:
    """Digest of every file under ``root`` (a symbolic link by its target string), skipping ``.git`` and ``exclude``.
    Deterministic; it identifies the bytes that were present, tracked or not."""
    skip = {Path(os.path.realpath(e)) for e in exclude}
    entries = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d != ".git")
        for name in sorted(files):
            full = Path(current) / name
            if Path(os.path.realpath(full)) in skip and not full.is_symlink():
                continue
            relative = full.relative_to(root).as_posix()
            if full.is_symlink():
                entries.append(f"{relative}\0symlink:{os.readlink(full)}")
            else:
                entries.append(f"{relative}\0{_sha256_file(full)}")
        for name in sorted(d for d in directories if (Path(current) / d).is_symlink()):
            entries.append(f"{(Path(current) / name).relative_to(root).as_posix()}\0symlink:{os.readlink(Path(current) / name)}")
    return hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()


def git_identity(repo: Path, subpath: str, exclude: Sequence[Path]) -> dict[str, Any]:
    """What git says about the analysed directory; every value is ``None`` when it cannot be read (never guessed)."""
    info: dict[str, Any] = {"revision": None, "tree_digest": None, "worktree_clean": None, "untracked_files": None, "submodules": None}
    code, head = _git(repo, "rev-parse", "HEAD")
    if code != 0:
        return info
    info["revision"] = head.strip()
    spec = "HEAD^{tree}" if subpath == "." else f"HEAD:{subpath}"
    code, tree = _git(repo, "rev-parse", spec)
    tree_id = tree.strip() if code == 0 else None
    pathspec = [] if subpath == "." else ["--", subpath]
    code, status = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", *pathspec)
    if code == 0:
        excluded = {os.path.relpath(os.path.realpath(e), os.path.realpath(repo)) for e in exclude}
        tracked_changes = untracked = 0
        for entry in (e for e in status.split("\0") if e):
            flag, path = entry[:2], entry[3:]
            if path in excluded:
                continue
            if flag in ("??", "!!"):
                untracked += 1
            else:
                tracked_changes += 1
        info["worktree_clean"] = tracked_changes == 0
        info["untracked_files"] = untracked
        info["tree_digest"] = (f"git-tree:{tree_id}" if tree_id and tracked_changes == 0 and untracked == 0 else None)
    code, subs = _git(repo, "submodule", "status", "--recursive")
    if code == 0:
        found = []
        for line in subs.splitlines():
            if not line.strip():
                continue
            marker, parts = line[0], line[1:].split()
            if len(parts) < 2:
                continue
            if marker in ("+", "U"):          # checked out at another commit than recorded, or in conflict
                info["worktree_clean"] = False
            found.append({"path": parts[1], "revision": parts[0] if marker == " " else None})
        info["submodules"] = found
    return info


# ---- execution ---------------------------------------------------------------------------------------------------------------------

def _run_stage(stage: Stage, cwd: Path, clock: Clock) -> dict[str, Any]:
    started = clock()
    try:
        done = subprocess.run(list(stage.argv), cwd=str(cwd), capture_output=True, timeout=stage.timeout_s)
        status, code = ("completed" if done.returncode == 0 else "failed"), done.returncode
    except subprocess.TimeoutExpired:
        status, code = "timed_out", None
    except OSError:
        status, code = "failed", None
    return {"name": stage.name, "role": stage.role, "status": status, "exit_code": code,
            "started": _iso(started), "finished": _iso(clock())}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _tool_version(plan: Plan) -> tuple[Optional[str], Optional[str], list[dict]]:
    notes: list[dict] = []
    version = None
    if plan.version_command:
        try:
            done = subprocess.run(list(plan.version_command), capture_output=True, text=True, timeout=60)
            lines = [line.strip() for line in done.stdout.splitlines() if line.strip()]
            version = lines[0] if done.returncode == 0 and lines else None
        except (OSError, subprocess.TimeoutExpired):
            version = None
        if version is None:
            notes.append({"level": "warning", "code": "TOOL_VERSION_NOT_OBSERVED", "message": "the version command did not report a version"})
    executable = None
    if plan.hash_executable and plan.stages:
        resolved = shutil.which(plan.stages[0].argv[0], path=None)
        if resolved:
            executable = _sha256_file(Path(resolved))
    return version, executable, notes


def run_plan(plan: Plan, record_path: Optional[Path] = None, clock: Clock = lambda: datetime.now(timezone.utc)) -> AnalysisRunRecord:
    """Execute ``plan`` and return the validated record (the caller writes it). A failed or timed-out stage ends the run: the
    remaining stages are ``not_run``. Pure with respect to the analysed project: it is only read."""
    analysed = plan.repo_dir if plan.analysis_subpath == "." else plan.repo_dir / plan.analysis_subpath
    if not analysed.is_dir():
        raise PlanError(f"analysis directory {analysed} does not exist")
    exclude = list(plan.outputs) + ([record_path] if record_path else [])
    before = git_identity(plan.repo_dir, plan.analysis_subpath, exclude)
    digest_before = tree_fingerprint(analysed, exclude)
    outputs_before = {path: ((_sha256_file(path), path.stat().st_mtime_ns) if path.is_file() else None) for path in plan.outputs}   # a stale output must not pass as this run's
    version, executable_sha, diagnostics = _tool_version(plan)

    stage_records: list[dict[str, Any]] = []
    stopped = False
    for stage in plan.stages:
        if stopped:
            stage_records.append({"name": stage.name, "role": stage.role, "status": "not_run", "exit_code": None, "started": None, "finished": None})
            continue
        result = _run_stage(stage, plan.repo_dir, clock)
        stage_records.append(result)
        if result["status"] != "completed":
            stopped = True
            diagnostics.append({"level": "error", "code": f"STAGE_{result['status'].upper()}", "message": f"stage {stage.name!r} did not complete"})

    digest_after = tree_fingerprint(analysed, exclude)
    after = git_identity(plan.repo_dir, plan.analysis_subpath, exclude)
    changed = digest_before != digest_after or before["revision"] != after["revision"]
    clean = before["worktree_clean"]
    untracked = before["untracked_files"]
    tree = before["tree_digest"]
    if tree is None:
        tree = f"sha256-worktree:{digest_before}"   # a tree that is not the committed tree is identified by its own content

    outputs, partial = [], []
    for path in plan.outputs:
        if path.is_file():
            if outputs_before.get(path) is not None and outputs_before[path] == (_sha256_file(path), path.stat().st_mtime_ns):
                label = os.path.relpath(path, plan.repo_dir) if str(path).startswith(str(plan.repo_dir)) else str(path)
                partial.append(f"OUTPUT_NOT_REWRITTEN:{label}")
                diagnostics.append({"level": "warning", "code": "OUTPUT_NOT_REWRITTEN",
                                    "message": f"output {label!r} existed before the run and is untouched by it (same bytes, same modification time): it may be stale"})
            outputs.append({"path": os.path.relpath(path, plan.repo_dir) if str(path).startswith(str(plan.repo_dir)) else str(path),
                            "sha256": _sha256_file(path), "size": path.stat().st_size})
        else:
            label = os.path.relpath(path, plan.repo_dir) if str(path).startswith(str(plan.repo_dir)) else str(path)
            outputs.append({"path": label, "sha256": None, "size": None})
            diagnostics.append({"level": "error", "code": "OUTPUT_MISSING", "message": f"declared output {label!r} is not present"})
            partial.append(f"OUTPUT_MISSING:{label}")
    if any(r["status"] != "completed" for r in stage_records):
        partial.append("STAGE_NOT_COMPLETED")
    if changed:
        diagnostics.append({"level": "warning", "code": "SOURCE_CHANGED_DURING_RUN",
                            "message": "the analysed directory (or the commit) differs between the start and the end of the run"})

    scope = dict(plan.scope)
    scope["partial_indicators"] = sorted(set(list(scope.get("partial_indicators", [])) + partial))
    data: dict[str, Any] = {
        "schema": "analysis-run/1", "run_id": plan.run_id, "origin": "runner",
        "field_sources": {"target": "caller_supplied", "configuration": "caller_supplied", "scope": "caller_supplied",
                          **({"coverage_claim": "caller_supplied"} if plan.coverage_claim else {})},
        "tool": {"name": plan.tool_name, "version": version, "output_format_version": plan.output_format_version,
                 "executable_sha256": executable_sha},
        "source": {"repository": plan.repository, "revision": before["revision"], "analysis_subpath": plan.analysis_subpath,
                   "tree_digest": tree, "worktree_clean": clean, "untracked_files": untracked, "submodules": before["submodules"],
                   "changed_during_run": changed, "roots": list(plan.roots)},
        "target": dict(plan.target),
        "configuration": {"languages": list(plan.languages), "query": dict(plan.query),
                          "command": [" ".join(redact_argv(s.argv)) for s in plan.stages]},
        "stages": stage_records, "outputs": outputs, "scope": scope,
        "diagnostics": diagnostics,
    }
    if plan.coverage_claim:
        data["coverage_claim"] = dict(plan.coverage_claim)
    return parse_analysis_run_data(data)


def verify_record(record: AnalysisRunRecord, files: Sequence[Path]) -> list[str]:
    """Problems found when re-hashing ``files`` against the record's outputs (empty: every file matches an output)."""
    wanted = {o.sha256 for o in record.outputs if o.sha256}
    problems = []
    for path in files:
        if not Path(path).is_file():
            problems.append(f"{path}: missing")
        elif _sha256_file(Path(path)) not in wanted:
            problems.append(f"{path}: SHA-256 {_sha256_file(Path(path))} matches no output of record {record.run_id!r}")
    return problems
