"""Security-semantic mutation operators for ``component_not_present`` evidence (CycloneDX and SPDX).

Kinds: ``delete`` (evidence is removed: M-1 and M-2), ``degrade`` (evidence is kept but made less reliable: M-1) and ``inject_positive``
(a component that matches the target is added: M-4). Each operator edits one kind of evidence only."""

from __future__ import annotations

from tests.metamorphic.core import Operator, Scenario

TARGET_PURL = "pkg:npm/absent-lib@9.9"
TWIN = {"name": "absent-lib", "version": "9.9", "purl": TARGET_PURL}


def _walk(components):
    for component in components or []:
        yield component
        yield from _walk(component.get("components"))


def _spdx_purl(package):
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref
    return None


# ---- deletions -----------------------------------------------------------------------------------------------------------------------

def _remove_one_dependency_edge(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        for entry in out.sbom.get("dependencies", []):
            if entry.get("dependsOn"):
                entry["dependsOn"].pop()
                break
    else:
        depends = [i for i, r in enumerate(out.sbom["relationships"]) if r["relationshipType"] == "DEPENDS_ON"]
        if depends:
            out.sbom["relationships"].pop(depends[-1])
    return out


def _remove_all_dependencies(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom.pop("dependencies", None)
    else:
        out.sbom["relationships"] = [r for r in out.sbom["relationships"] if r["relationshipType"] != "DEPENDS_ON"]
    return out


def _remove_a_component(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["components"] = out.sbom["components"][1:]
    else:
        packages = out.sbom["packages"]
        out.sbom["packages"] = [packages[0]] + packages[2:]
    return out


def _remove_the_completeness_declaration(s: Scenario) -> Scenario:
    out = s.mutate()
    out.sbom.pop("compositions", None)
    return out


def _remove_versions(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        for component in _walk(out.sbom.get("components")):
            component.pop("version", None)
    else:
        for package in out.sbom["packages"][1:]:
            package.pop("versionInfo", None)
    return out


def _remove_strong_identifiers(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        for component in _walk(out.sbom.get("components")):
            component.pop("purl", None)
    else:
        for package in out.sbom["packages"][1:]:
            package.pop("externalRefs", None)
    return out


def _remove_the_subject_digest(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["metadata"]["component"].pop("hashes", None)
    else:
        out.sbom["packages"][0].pop("checksums", None)
    return out


def _remove_the_tool_identity(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["metadata"].pop("tools", None)
    else:
        out.sbom["creationInfo"]["creators"] = []
    return out


def _remove_the_timestamp(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["metadata"].pop("timestamp", None)
    else:
        out.sbom["creationInfo"].pop("created", None)
    return out


def _remove_the_verification(s: Scenario) -> Scenario:
    return s.mutate(verified_coverage=None)


def _remove_the_assertion(s: Scenario) -> Scenario:
    out = s.mutate()
    out.profile.pop("inv_assertions", None)
    return out


def _remove_the_vex_justification(s: Scenario) -> Scenario:
    out = s.mutate()
    for statement in out.vex["statements"]:
        statement.pop("justification", None)
    return out


# ---- degradations --------------------------------------------------------------------------------------------------------------------

def _declaration_incomplete(s: Scenario) -> Scenario:
    out = s.mutate()
    out.sbom["compositions"][0]["aggregate"] = "incomplete"
    return out


def _declaration_unknown(s: Scenario) -> Scenario:
    out = s.mutate()
    out.sbom["compositions"][0]["aggregate"] = "unknown"
    return out


def _alter_versions(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        for component in _walk(out.sbom.get("components")):
            component["version"] = "0.0.0-altered"
    else:
        for package in out.sbom["packages"][1:]:
            package["versionInfo"] = "0.0.0-altered"
    return out


def _alter_the_subject_digest(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["metadata"]["component"]["hashes"][0]["content"] = "ab" * 32
    else:
        out.sbom["packages"][0]["checksums"][0]["checksumValue"] = "ab" * 32
    return out


def _narrow_the_verification(s: Scenario) -> Scenario:
    return s.mutate(verified_coverage=("#/components",) if s.sbom_format == "cdx" else ("#/nothing",))


def _declaration_dangling_edge(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["dependencies"][0]["dependsOn"].append("ghost-component")
    else:
        out.sbom["relationships"].append({"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-ghost"})
    return out


def _add_an_unrelated_orphan(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["components"].append({"type": "library", "bom-ref": "orphan-1", "name": "orphan-lib", "version": "1.0", "purl": "pkg:npm/orphan-lib@1.0"})
    else:
        out.sbom["packages"].append({"SPDXID": "SPDXRef-orphan", "name": "orphan-lib", "versionInfo": "1.0", "downloadLocation": "NOASSERTION",
                                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/orphan-lib@1.0"}]})
    return out


# ---- positive injections (the target component is found) --------------------------------------------------------------------------------

def _inject_exact_twin(s: Scenario) -> Scenario:
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["components"].append({"type": "library", "bom-ref": "twin-1", "name": TWIN["name"], "version": TWIN["version"], "purl": TARGET_PURL})
        out.sbom["dependencies"].append({"ref": "twin-1", "dependsOn": []})
        out.sbom["dependencies"][0]["dependsOn"].append("twin-1")
    else:
        out.sbom["packages"].append({"SPDXID": "SPDXRef-twin", "name": TWIN["name"], "versionInfo": TWIN["version"], "downloadLocation": "NOASSERTION",
                                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": TARGET_PURL}]})
        out.sbom["relationships"].append({"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-twin"})
    return out


def _inject_orphan_twin(s: Scenario) -> Scenario:
    """The target is present but no dependency edge reaches it: an orphan is still a member of the inventory."""
    out = s.mutate()
    if s.sbom_format == "cdx":
        out.sbom["components"].append({"type": "library", "bom-ref": "twin-2", "name": TWIN["name"], "version": TWIN["version"], "purl": TARGET_PURL})
    else:
        out.sbom["packages"].append({"SPDXID": "SPDXRef-twin2", "name": TWIN["name"], "versionInfo": TWIN["version"], "downloadLocation": "NOASSERTION",
                                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": TARGET_PURL}]})
    return out


def _inject_nested_twin(s: Scenario) -> Scenario:
    out = s.mutate()
    for component in out.sbom["components"]:
        if component.get("components"):
            component["components"].append({"type": "library", "bom-ref": "twin-3", "name": TWIN["name"], "version": TWIN["version"], "purl": TARGET_PURL})
            break
    return out


def _has_cdx_nested(s: Scenario) -> bool:
    return any(c.get("components") for c in s.sbom.get("components", []))


CNP_OPERATORS = (
    Operator("D-DEP-EDGE", "delete", "remove one dependency edge", ("cnp",), _remove_one_dependency_edge),
    Operator("D-DEP-ALL", "delete", "remove every dependency edge", ("cnp",), _remove_all_dependencies),
    Operator("D-COMPONENT", "delete", "remove one component from the inventory", ("cnp",), _remove_a_component),
    Operator("D-DECLARATION", "delete", "remove the completeness declaration", ("cnp",), _remove_the_completeness_declaration, formats=("cdx",)),
    Operator("D-VERSION", "delete", "remove component version information", ("cnp",), _remove_versions),
    Operator("D-IDENTIFIER", "delete", "remove the strong identifier (purl) of every component", ("cnp",), _remove_strong_identifiers),
    Operator("D-SUBJECT-DIGEST", "delete", "remove the subject's digest", ("cnp",), _remove_the_subject_digest),
    Operator("D-TOOL", "delete", "remove the generating tool identity", ("cnp",), _remove_the_tool_identity),
    Operator("D-TIMESTAMP", "delete", "remove the document timestamp", ("cnp",), _remove_the_timestamp),
    Operator("D-VERIFICATION", "delete", "remove the detached verification result", ("cnp",), _remove_the_verification,
             applies=lambda s: s.verified_coverage is not None),
    Operator("D-ASSERTION", "delete", "remove the evaluator's inventory assertion", ("cnp",), _remove_the_assertion,
             applies=lambda s: bool(s.profile.get("inv_assertions"))),
    Operator("D-VEX-JUSTIFICATION", "delete", "remove the VEX justification", ("cnp",), _remove_the_vex_justification),
    Operator("G-DECL-INCOMPLETE", "degrade", "declare the composition incomplete", ("cnp",), _declaration_incomplete, applies=lambda s: bool(s.sbom.get("compositions")), formats=("cdx",)),
    Operator("G-DECL-UNKNOWN", "degrade", "declare the composition unknown", ("cnp",), _declaration_unknown, applies=lambda s: bool(s.sbom.get("compositions")), formats=("cdx",)),
    Operator("G-VERSION", "degrade", "replace component versions with a wrong value", ("cnp",), _alter_versions),
    Operator("G-SUBJECT-DIGEST", "degrade", "alter the subject's digest", ("cnp",), _alter_the_subject_digest),
    Operator("G-VERIFICATION", "degrade", "narrow the verified coverage", ("cnp",), _narrow_the_verification, applies=lambda s: s.verified_coverage is not None),
    Operator("G-DANGLING-EDGE", "degrade", "add a dependency edge to a component that is not defined", ("cnp",), _declaration_dangling_edge),
    Operator("G-ORPHAN", "degrade", "add an unrelated orphan component", ("cnp",), _add_an_unrelated_orphan),
    Operator("I-TWIN", "inject_positive", "add the target component with a dependency edge", ("cnp",), _inject_exact_twin),
    Operator("I-ORPHAN-TWIN", "inject_positive", "add the target component as an orphan (no edge)", ("cnp",), _inject_orphan_twin),
    Operator("I-NESTED-TWIN", "inject_positive", "add the target component nested under another component", ("cnp",), _inject_nested_twin,
             applies=_has_cdx_nested, formats=("cdx",)),
)
