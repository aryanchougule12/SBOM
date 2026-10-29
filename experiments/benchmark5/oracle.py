"""Ground-truth oracle: which OSV advisories affect which component version of the five projects.

Independent of every scanner under test (own version-range evaluator for npm semver, PyPI PEP 440 via `packaging`, and Maven ComparableVersion
rules), computed from a downloaded snapshot of the OSV database (osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip). A component version is
*affected* by an advisory iff an `affected[]` entry for that package lists the version in `versions`, or the version satisfies one of its `ranges`
(introduced/fixed/last_affected events, OSV spec). Both methods are computed and any disagreement is recorded, never hidden. Withdrawn advisories are
excluded. The oracle shares its data source with osv-scanner (and partly with Trivy and Grype, which ingest GitHub advisories): it is a reference
for these projects, not an absolute truth; see the report's limitations."""

from __future__ import annotations

import functools
import json
import re
import sys
import zipfile
from pathlib import Path

from packaging.version import InvalidVersion, Version

HERE = Path(__file__).resolve().parent
ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}


# ---- version comparison ----------------------------------------------------------------------------------------------------------------

def _semver_key(text: str):
    text = text.strip().lstrip("v").partition("+")[0]
    core, _, pre = text.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in (core.split(".") + ["0", "0", "0"])[:3])
    if not pre:
        return (nums, ((2,),))      # a release sorts above every prerelease of the same core
    return (nums, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))


def cmp_npm(a: str, b: str) -> int:
    ka, kb = _semver_key(a), _semver_key(b)
    return (ka > kb) - (ka < kb)


def cmp_pypi(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return (a > b) - (a < b)
    return (va > vb) - (va < vb)


_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_ALIASES = {"a": "alpha", "b": "beta", "m": "milestone", "cr": "rc", "ga": "", "final": "", "release": ""}


def _maven_items(text: str):
    items = []
    for token in re.findall(r"\d+|[A-Za-z]+", text.lower()):
        if token.isdigit():
            items.append((1, int(token)))
        else:
            token = _ALIASES.get(token, token)
            items.append((0, _QUALIFIERS.index(token) if token in _QUALIFIERS else len(_QUALIFIERS) + 1))
    while items and items[-1] in ((1, 0), (0, _QUALIFIERS.index(""))):    # trailing zeros / release qualifiers are insignificant
        items.pop()
    return items


def _vs_null(item) -> int:
    """Compare one Maven item against the absent item (0 for numbers, the release qualifier for strings)."""
    kind, value = item
    return (value > 0) - (value < 0) if kind == 1 else (value > _QUALIFIERS.index("")) - (value < _QUALIFIERS.index(""))


def cmp_maven(a: str, b: str) -> int:
    ia, ib = _maven_items(a), _maven_items(b)
    for i in range(max(len(ia), len(ib))):
        x = ia[i] if i < len(ia) else None
        y = ib[i] if i < len(ib) else None
        if x == y:
            continue
        if x is None:
            r = -_vs_null(y)
        elif y is None:
            r = _vs_null(x)
        elif x[0] != y[0]:
            r = 1 if x[0] == 1 else -1       # a number beats a qualifier at the same position
        else:
            r = (x > y) - (x < y)
        if r:
            return r
    return 0


COMPARE = {"npm": cmp_npm, "pypi": cmp_pypi, "maven": cmp_maven}


def in_range(version: str, events: list, compare) -> bool:
    """OSV range semantics: events are applied in file order (the spec requires ascending order); a version is affected if the last event
    not after it is an introduction rather than a fix / last_affected."""
    affected = False
    # Real records do not keep events in ascending order (e.g. PYSEC-2025-1 lists 5.1, 5.1.5, 5.0, 5.0.11, ...): sort them; at equal versions closers go first.
    for event in sorted(events, key=lambda e: (list(e.values())[0] != "0", functools.cmp_to_key(compare)(list(e.values())[0]), list(e)[0] == "introduced")):
        (kind, value), = event.items()
        if kind == "introduced":
            if value == "0" or compare(version, value) >= 0:
                affected = True
        elif kind == "fixed":
            if compare(version, value) >= 0:
                affected = False
        elif kind == "last_affected":
            if compare(version, value) > 0:
                affected = False
    return affected


# ---- normalisation ---------------------------------------------------------------------------------------------------------------------

def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def advisory_matches(record: dict, ecosystem: str, name: str, version: str):
    """``(affected, by_versions, by_range, disputed)`` for one OSV record and one package version."""
    compare = COMPARE[ecosystem]
    by_versions = by_range = disputed = False
    for entry in record.get("affected", []):
        package = entry.get("package", {})
        if package.get("ecosystem") != ECOSYSTEM[ecosystem] or norm_name(ecosystem, package.get("name", "")) != norm_name(ecosystem, name):
            continue
        has_list = bool(entry.get("versions"))
        has_range = any(r.get("type") in ("SEMVER", "ECOSYSTEM") for r in entry.get("ranges", []))
        in_list = version in entry.get("versions", [])
        in_rng = any(r.get("type") in ("SEMVER", "ECOSYSTEM") and in_range(version, r.get("events", []), compare) for r in entry.get("ranges", []))
        by_versions |= in_list
        by_range |= in_rng
        if has_list and has_range and in_list != in_rng:
            disputed = True
    return (by_versions or by_range), by_versions, by_range, disputed


def build(osv_dir: Path, inventory: dict) -> dict:
    wanted: dict[str, dict[str, set]] = {}
    for project, ecos in inventory.items():
        for eco, comps in ecos.items():
            for name, version in comps.items():
                wanted.setdefault(eco, {}).setdefault(norm_name(eco, name), set()).add((name, version))
    result: dict = {}
    universe: dict = {}
    snapshot = {}
    for eco, names in wanted.items():
        path = osv_dir / f"{ECOSYSTEM[eco]}.zip"
        snapshot[eco] = {"file": path.name, "bytes": path.stat().st_size, "records": 0}
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                snapshot[eco]["records"] += 1
                if not member.endswith(".json"):
                    continue
                record = json.loads(archive.read(member))
                if record.get("withdrawn"):
                    continue
                touched = {norm_name(eco, e.get("package", {}).get("name", "")) for e in record.get("affected", []) if e.get("package", {}).get("ecosystem") == ECOSYSTEM[eco]}
                for key in touched & set(names):
                    for name in {n for n, _ in names[key]}:
                        universe.setdefault(f"{eco}:{name}", []).append({"id": record["id"], "aliases": sorted(record.get("aliases", []))})
                    for name, version in names[key]:
                        affected, by_v, by_r, disputed = advisory_matches(record, eco, name, version)
                        if affected or disputed:
                            result.setdefault(f"{eco}:{name}@{version}", []).append({
                                "id": record["id"], "aliases": sorted(record.get("aliases", [])), "affected": affected,
                                "by_versions_list": by_v, "by_range": by_r, "disputed": disputed, "summary": (record.get("summary") or "")[:120]})
    for items in result.values():
        items.sort(key=lambda r: r["id"])
    for items in universe.values():
        items.sort(key=lambda r: r["id"])
    return {"snapshot": snapshot, "universe": dict(sorted(universe.items())), "components": dict(sorted(result.items()))}


if __name__ == "__main__":
    osv_dir = Path(sys.argv[1])
    inventory = json.loads((HERE / "inventory_truth.json").read_text())
    out = build(osv_dir, inventory)
    (HERE / "oracle_raw.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    total = sum(1 for items in out["components"].values() for r in items if r["affected"])
    disagree = sum(1 for items in out["components"].values() for r in items if r["disputed"])
    print(f"components with advisories: {len(out['components'])}; affected (component, advisory) pairs: {total}; method disagreements: {disagree}")
