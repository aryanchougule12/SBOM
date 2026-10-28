"""Boundary guards of the integrated pipeline that must hold as the code evolves.

* no cryptography or network access exists in the evidence pipeline (verification results are
  consumed, never produced);
* the four verification-derived integrity fields are only ever set from a consumed verification
  result or BIND result, in one place, on the evaluation's own document copy;
* the profile cannot carry generation assertions, verdicts, states or levels (decision D10 is
  deferred; the profile never supplies states);
* no module of the pipeline implements corroboration, reachability or C3 classification.
"""

import ast
import json
from pathlib import Path

import pytest

from evidence.profile import ProfileError, ProfileErrorCode as PE, parse_profile
from tests.pipeline_support import profile_data

ROOT = Path(__file__).resolve().parent.parent
PIPELINE = [
    "cnp_adapter", "decl_derivation", "document_provenance", "evaluator", "generation", "inventory_checks",
    "inventory_members", "items", "match", "verification",
]
FORBIDDEN_IMPORTS = {"hashlib", "hmac", "ssl", "socket", "urllib", "http", "requests", "cryptography", "nacl",
                     "OpenSSL", "Crypto", "subprocess", "secrets"}
INTEGRITY_FIELDS = {"signature_verified", "trust_anchor_id", "established_coverage", "artifact_digest_binding"}


def _tree(path):
    return ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=str(path))


def _imports(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("module", PIPELINE)
def test_the_pipeline_modules_import_no_cryptography_or_network_library(module):
    assert not (_imports(_tree(f"evidence/{module}.py")) & FORBIDDEN_IMPORTS)


def test_the_integrity_fields_are_assigned_only_by_record_consumed_integrity():
    offenders = []
    allowed = ROOT / "evidence" / "document_provenance.py"
    for path in sorted((ROOT / "evidence").glob("*.py")) + sorted((ROOT / "sbom_parser").glob("*.py")) + [ROOT / "model.py"]:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in INTEGRITY_FIELDS and path != allowed:
                    offenders.append(f"{path.name}:{node.lineno}:{target.attr}")
    assert offenders == []
    tree = _tree("evidence/document_provenance.py")
    functions = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                 for sub in ast.walk(n) for t in (sub.targets if isinstance(sub, ast.Assign) else [])
                 if isinstance(t, ast.Attribute) and t.attr in INTEGRITY_FIELDS}
    assert functions == {"record_consumed_integrity"}


def test_parsers_never_construct_a_verified_or_bound_integrity():
    for name in ("cyclonedx", "spdx", "openvex"):
        for node in ast.walk(_tree(f"sbom_parser/{name}.py")):
            if isinstance(node, ast.keyword) and node.arg in {"signature_verified", "trust_anchor_id", "established_coverage",
                                                              "artifact_digest_binding"}:
                assert isinstance(node.value, ast.Constant) and node.value.value is None, (name, node.arg)


def test_the_profile_cannot_carry_generation_assertions_states_levels_or_verdicts():
    for key in ("generation_assertions", "verdict", "states", "provenance_levels", "bind_state", "inv_state"):
        data = profile_data("d", target={"name": "x"}, location=None)
        data[key] = {"anything": 1}
        with pytest.raises(ProfileError) as error:
            parse_profile(data)
        assert error.value.code in (PE.UNKNOWN_FIELD, PE.FORBIDDEN_FIELD), key


def test_no_pipeline_module_implements_out_of_scope_logic():
    for module in PIPELINE:
        names = {n.id for n in ast.walk(_tree(f"evidence/{module}.py")) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(_tree(f"evidence/{module}.py")) if isinstance(n, ast.Attribute)}
        names |= {n.name for n in ast.walk(_tree(f"evidence/{module}.py")) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        lowered = {n.lower() for n in names}
        assert not any(word in n for n in lowered for word in ("reachab", "callgraph", "corroborat", "hazard")), module


def test_corroborating_documents_are_refused_by_the_profile_not_ignored():
    data = profile_data("d", target={"name": "x"}, location=None)
    data["documents"].append({"doc_id": "other", "role": "corroborating"})
    with pytest.raises(ProfileError) as error:
        parse_profile(data)
    assert error.value.code is PE.ROLE_UNSUPPORTED
