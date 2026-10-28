"""Shared helpers for the integrated-pipeline tests (fixtures, profiles, verification inputs).

Test support only: nothing here is part of the evaluator. Verification inputs built here are
synthetic and exist solely so that tests can exercise the P3 path; no cryptography happens.
"""

import copy
import json
from pathlib import Path

from evidence.profile import parse_profile
from evidence.stage1_records import Stage1Index, load_cyclonedx, load_openvex, load_spdx
from evidence.verification import VerificationConfig, VerificationResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
X = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
PRODUCT = "pkg:oci/example-app@sha256%3Aabc"
VULN = "CVE-2026-0001"
SUBJECT_PURL = "pkg:generic/example-app@2.0.0"


def vex_findings(name="component_not_present.json"):
    return list(load_openvex(FIXTURES / "openvex" / name).findings)


def cdx(name):
    return load_cyclonedx(FIXTURES / "cyclonedx" / name)


def spdx(name):
    return load_spdx(FIXTURES / "spdx" / name)


def equivalent(kind):
    return cdx("../equivalent/app.cdx.json") if kind == "cdx" else spdx("../equivalent/app.spdx.json")


def profile_data(
    doc_id,
    *,
    kind="source",
    digest=True,
    version="2.0.0",
    target=None,
    location=None,
    assertion=True,
    assertion_statement="full_component_list",
    product=PRODUCT,
    selector=True,
    schema="1.1",
):
    scope = {"product_id": product, "artifact_kind": kind}
    if version is not None:
        scope["version"] = version
    if digest:
        scope["artifact_digests"] = ["sha256:" + X]
    data = {
        "schema_version": schema,
        "profile_id": "pipeline-test",
        "scope": scope,
        "documents": [{"doc_id": doc_id, "role": "primary_sbom"}],
    }
    if selector:
        data["finding_selector"] = {"vulnerability": VULN, "product_id": product}
    if target is not None or location is not None:
        data["target"] = {"component": target or {"name": "absent-lib", "version": "9.9", "purl": "pkg:npm/absent-lib@9.9"}}
        if location is not None:
            data["target"]["would_be_location"] = dict(location, document=doc_id)
    if assertion:
        data["inv_assertions"] = [{
            "document": doc_id, "scope": copy.deepcopy(scope), "statement": assertion_statement, "entered_by": "tester",
        }]
    return data


def make_profile(doc_id, **kwargs):
    return parse_profile(profile_data(doc_id, **kwargs))


def verification_for(doc_id, coverage=("#/components", "#/packages"), *, verified=True, anchor="anchor-1",
                     anchors=("anchor-1",)):
    result = VerificationResult(doc_id, verified, anchor, "external-verifier", "1.0",
                                None if coverage is None else tuple(coverage))
    return VerificationConfig(frozenset(anchors), (result,))


def load_profile_fixture(name, doc_id):
    text = (FIXTURES / "profiles" / name).read_text().replace("@PRIMARY@", doc_id)
    return json.loads(text)


NESTED = {"placement": "nested_under_component", "parent_ref": "lib-b"}
TOP_LEVEL = {"placement": "top_level"}
ABSENT = {"name": "absent-lib", "version": "9.9", "purl": "pkg:npm/absent-lib@9.9"}
