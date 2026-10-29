"""Boundary guards of the integrated pipeline that must hold as the code evolves.

* no cryptography or network access exists in the evidence pipeline (verification results are
  consumed, never produced);
* the four verification-derived integrity fields are only ever set from a consumed verification
  result or BIND result, in one place, on the evaluation's own document copy;
* the profile cannot carry generation assertions, verdicts, states or levels (decision D10 is
  deferred; the profile never supplies states);
* no module of the CNP pipeline implements corroboration, reachability or C3 classification, and none
  imports the reachability modules: the two predicates share modules, never state (the reachability
  pipeline has its own guards below);
* the reachability pipeline imports no cryptography or network library either, and its input can never
  carry a state, a provenance level, a BIND result or a verdict.
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
REACH_PIPELINE = ["reach_derivation", "reach_evaluator", "reach_inputs", "reach_items", "reach_rules", "rule_core"]
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


@pytest.mark.parametrize("module", REACH_PIPELINE)
def test_the_reachability_modules_import_no_cryptography_or_network_library(module):
    assert not (_imports(_tree(f"evidence/{module}.py")) & FORBIDDEN_IMPORTS)


def _evidence_imports(module):
    found = set()
    for node in ast.walk(_tree(f"evidence/{module}.py")):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("evidence."):
            found.add(node.module.split(".", 1)[1])
    return found


@pytest.mark.parametrize("module", PIPELINE + ["cnp_rules", "bind", "aggregation", "inv", "inventory_observations"])
def test_no_cnp_module_imports_the_reachability_modules(module):
    assert not {m for m in _evidence_imports(module) if m.startswith("reach")}, module


def test_the_shared_core_imports_no_predicate_specific_module():
    assert _evidence_imports("rule_core") == set()


def test_the_reachability_input_cannot_carry_states_levels_bind_results_or_verdicts():
    from evidence.reach_inputs import ReachInputError, ReachInputErrorCode, parse_reachability
    for key in ("verdict", "state", "provenance_level", "bind_state", "prov_reach", "ep"):
        with pytest.raises(ReachInputError) as error:
            parse_reachability({"schema_version": "1", key: "x"})
        assert error.value.code is ReachInputErrorCode.FORBIDDEN_FIELD


def test_the_parsers_still_extract_no_reachability_facts():
    """K1-K3, entry points, hazards and configurations enter only through the reachability input."""
    for name in ("cyclonedx", "spdx", "openvex"):
        names = {n.id for n in ast.walk(_tree(f"sbom_parser/{name}.py")) if isinstance(n, ast.Name)}
        assert not any(word in n.lower() for n in names for word in ("callgraph", "hazard", "entry_point"))


# ---- analyzer-artifact adapter layering ----------------------------------------------------------------------------------------

ANALYSIS_MODULES = ["analysis_model", "analysis_sarif", "analysis_graphml", "analysis_binding", "analysis_ingest", "analysis_run",
                    "analysis_run_binding"]


@pytest.mark.parametrize("module", ANALYSIS_MODULES)
def test_the_analysis_modules_import_no_cryptography_network_or_process_library(module):
    assert not (_imports(_tree(f"evidence/{module}.py")) & FORBIDDEN_IMPORTS)


def test_the_raw_format_parsers_depend_only_on_the_neutral_model():
    """Layering: parsing and structural validation know nothing of subjects, reachability rules or the evaluator."""
    assert _evidence_imports("analysis_model") == set()
    assert _evidence_imports("analysis_sarif") == {"analysis_model"}
    assert _evidence_imports("analysis_graphml") == {"analysis_model"}


def test_binding_depends_on_the_model_the_parsers_helper_and_the_strict_input_only():
    assert _evidence_imports("analysis_binding") == {"analysis_model", "analysis_sarif", "reach_inputs", "analysis_run", "analysis_run_binding"}


def test_the_run_record_is_a_leaf_and_its_binding_depends_only_on_the_model_the_record_and_the_sarif_helpers():
    """The record is parsed with no knowledge of subjects, rules or the evaluator; nothing in the evaluation path imports the runner."""
    assert _evidence_imports("analysis_run") == set()
    assert _evidence_imports("analysis_run_binding") == {"analysis_model", "analysis_run", "analysis_sarif"}
    for path in sorted((ROOT / "evidence").glob("*.py")):
        assert "analysis_runner" not in _imports(_tree(f"evidence/{path.name}")), path.name


def test_the_reachability_rule_engine_and_the_cnp_modules_do_not_import_the_adapters():
    for module in PIPELINE + ["cnp_rules", "bind", "aggregation", "reach_rules", "reach_derivation", "reach_items", "rule_core"]:
        assert not {m for m in _evidence_imports(module) if m.startswith("analysis")} - {"analysis_model"}, module


def test_only_the_neutral_model_is_imported_by_the_evaluation_path():
    assert {m for m in _evidence_imports("reach_evaluator") if m.startswith("analysis")} == {"analysis_model"}
    assert {m for m in _evidence_imports("reach_inputs") if m.startswith("analysis")} == {"analysis_model"}


def test_the_hash_function_is_used_only_for_content_addressed_ids_through_the_existing_parser_helper():
    for module in ANALYSIS_MODULES:
        assert "hashlib" not in _imports(_tree(f"evidence/{module}.py")), module
