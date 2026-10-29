"""Score vulnerability scanners against the OSV-derived oracle (oracle_raw.json).

Unit of decision = (component, advisory group), where an advisory group is the set of OSV ids that alias each other (CVE/GHSA/PYSEC/...).
Universe of decisions per component = every non-withdrawn OSV advisory that names the component's package (any version).
  oracle positive  : some record of the group affects the pinned version (own range evaluation, cross-checked with explicit version lists);
  oracle negative  : the group names the package but not this version;
  excluded         : the group is *disputed* (version list and range disagree) - counted separately, not scored.
Per tool: TP = reported & positive, FN = positive & not reported, FP = reported & negative, TN = negative & not reported.
A finding whose ids match no advisory of that package in the oracle is *unmapped*; it is added to FP in the strict columns and listed in full
in `unmapped` for manual adjudication (the oracle is a reference snapshot, not infallible)."""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
INVENTORY = json.loads((HERE / "inventory_truth.json").read_text())
ORACLE = json.loads((HERE / "oracle_raw.json").read_text())


# Manual adjudication of tool ids the oracle does not alias. NSWG-ECO-516 (Node Security WG, npm advisory 1523, HackerOne 712065) is the same
# lodash zipObjectDeep prototype-pollution issue as CVE-2020-8203 / GHSA-p6mc-m468-83gw, affecting lodash < 4.17.19 (Trivy lists both with fix 4.17.19).
ADJUDICATED_ALIASES = {"NSWG-ECO-516": "GHSA-p6mc-m468-83gw"}


def norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name


def purl_parts(purl: str):
    m = re.match(r"pkg:(\w+)/(?:([^/@]+)/)?([^@?]+)@([^?]+)", purl)
    eco, group, name, version = m.groups()
    eco = {"pypi": "pypi", "npm": "npm", "maven": "maven"}[eco]
    full = f"{group}:{name}" if eco == "maven" else (f"{group}/{name}" if group else name)
    return eco, full.replace("%40", "@"), version


# ---- extractors: each returns {project: set((eco, name, version, id, frozenset(aliases)))} -----------------------------------------------

def trivy(project):
    out = set()
    for result in json.loads((HERE / "tool_out" / f"trivy_{project}.json").read_text()).get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            eco, name, version = purl_parts(v["PkgIdentifier"]["PURL"])
            out.add((eco, name, version, v["VulnerabilityID"], frozenset()))
    return out


def osv_scanner(project):
    out = set()
    for res in json.loads((HERE / "tool_out" / f"osv-scanner_{project}.json").read_text()).get("results", []):
        for pkg in res.get("packages", []):
            p = pkg["package"]
            eco = {"npm": "npm", "PyPI": "pypi", "Maven": "maven"}[p["ecosystem"]]
            for v in pkg.get("vulnerabilities", []):
                out.add((eco, p["name"], p["version"], v["id"], frozenset(v.get("aliases", []))))
    return out


def pip_audit(project):
    path = HERE / "tool_out" / f"pip-audit_{project}.json"
    if not path.exists():
        return None
    out = set()
    for dep in json.loads(path.read_text())["dependencies"]:
        for v in dep.get("vulns", []):
            out.add(("pypi", dep["name"], dep["version"], v["id"], frozenset(v.get("aliases", []))))
    return out


def npm_audit(project):
    path = HERE / "tool_out" / f"npm-audit_{project}.json"
    if not path.exists():
        return None
    lock = json.loads((HERE / "projects" / project / "package-lock.json").read_text())["packages"]
    out = set()
    for name, entry in json.loads(path.read_text())["vulnerabilities"].items():
        for via in entry["via"]:
            if isinstance(via, dict):
                ghsa = via["url"].rsplit("/", 1)[-1]
                out.add(("npm", via["name"], lock[f"node_modules/{via['name']}"]["version"], ghsa, frozenset()))
    return out


TOOLS = {"Trivy": trivy, "OSV-Scanner": osv_scanner, "pip-audit": pip_audit, "npm audit": npm_audit}
ECOSYSTEMS = {"Trivy": {"npm", "pypi", "maven"}, "OSV-Scanner": {"npm", "pypi", "maven"}, "pip-audit": {"pypi"}, "npm audit": {"npm"}}


# ---- oracle indexing --------------------------------------------------------------------------------------------------------------------

def groups_for(eco, name):
    """Advisory groups (union of aliasing OSV ids) of one package: list of {ids:set}."""
    records = ORACLE["universe"].get(f"{eco}:{name}", [])
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in records:
        for other in r["aliases"]:
            parent[find(r["id"])] = find(other)
    members = defaultdict(set)
    for r in records:
        for i in [r["id"], *r["aliases"]]:
            members[find(i)].add(i)
    return list(members.values())


def component_truth(eco, name, version):
    """{group_index: 'pos'|'neg'|'disputed'} and the group list for one component."""
    groups = groups_for(eco, name)
    hits = {r["id"]: r for r in ORACLE["components"].get(f"{eco}:{name}@{version}", [])}
    status = {}
    for idx, group in enumerate(groups):
        recs = [hits[i] for i in group if i in hits]
        if any(r["disputed"] for r in recs):
            status[idx] = "disputed"
        elif any(r["affected"] for r in recs):
            status[idx] = "pos"
        else:
            status[idx] = "neg"
    return groups, status


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def score():
    rows = []
    unmapped_all = []
    missed_all = []
    for tool, extract in TOOLS.items():
        per = {}
        for project, ecos in INVENTORY.items():
            found = extract(project)
            if found is None:
                continue
            tp = fp = tn = fn = unm = disp = 0
            for eco, comps in ecos.items():
                if eco not in ECOSYSTEMS[tool]:
                    continue
                for name, version in comps.items():
                    groups, status = component_truth(eco, name, version)
                    reported = set()
                    for (e, n, v, fid, aliases) in found:
                        if e != eco or norm(eco, n) != norm(eco, name) or v != version:
                            continue
                        ids = {fid, *aliases, *([ADJUDICATED_ALIASES[fid]] if fid in ADJUDICATED_ALIASES else [])}
                        idx = next((i for i, g in enumerate(groups) if g & ids), None)
                        if idx is None:
                            unm += 1
                            unmapped_all.append({"tool": tool, "project": project, "component": f"{eco}:{name}@{version}", "id": fid, "aliases": sorted(aliases)})
                        else:
                            reported.add(idx)
                    for idx, st in status.items():
                        if st == "disputed":
                            disp += 1
                        elif st == "pos":
                            tp += idx in reported
                            fn += idx not in reported
                            if idx not in reported:
                                missed_all.append({"tool": tool, "project": project, "component": f"{eco}:{name}@{version}", "advisory": sorted(groups[idx])})
                        else:
                            fp += idx in reported
                            tn += idx not in reported
            per[project] = dict(TP=tp, FP=fp, TN=tn, FN=fn, unmapped=unm, disputed=disp)
        total = {k: sum(p[k] for p in per.values()) for k in ("TP", "FP", "TN", "FN", "unmapped", "disputed")}
        rows.append({"tool": tool, "per_project": per, "total": total})
    return rows, unmapped_all, missed_all


def metrics(c):
    tp, fp, tn, fn, unm = c["TP"], c["FP"], c["TN"], c["FN"], c["unmapped"]
    fps = fp + unm
    precision = tp / (tp + fps) if tp + fps else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    n = tp + fps + tn + fn
    accuracy = (tp + tn) / n if n else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else float("nan")
    return dict(precision=precision, recall=recall, accuracy=accuracy, f1=f1, precision_ci=wilson(tp, tp + fps), recall_ci=wilson(tp, tp + fn),
                accuracy_ci=wilson(tp + tn, n), n=n)


if __name__ == "__main__":
    rows, unmapped, missed = score()
    for r in rows:
        r["metrics"] = metrics(r["total"])
        r["per_project_metrics"] = {p: metrics(c) for p, c in r["per_project"].items()}
    (HERE / "scanner_results.json").write_text(json.dumps({"rows": rows, "unmapped": unmapped, "missed": missed}, indent=1, sort_keys=True) + "\n")
    print(f"{'tool':12} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} {'unm':>4} {'disp':>4}  prec   rec    acc    f1")
    for r in rows:
        t, m = r["total"], r["metrics"]
        print(f"{r['tool']:12} {t['TP']:5} {t['FP']:5} {t['TN']:5} {t['FN']:5} {t['unmapped']:4} {t['disputed']:4}  {m['precision']:.3f}  {m['recall']:.3f}  {m['accuracy']:.3f}  {m['f1']:.3f}")
    print("unmapped findings:", len(unmapped))
