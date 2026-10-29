"""Base scenarios: complete, controlled evaluation inputs built from the repository's committed fixtures."""

from __future__ import annotations

import json

from tests.metamorphic.core import PLACEHOLDER, Scenario
from tests.pipeline_support import ABSENT, FIXTURES, profile_data

ROOT_NESTED = {"placement": "nested_under_component", "parent_ref": "app-1"}
CDX_FULL = ("#/components", "#/compositions/0", "#/packages")


def _load(path) -> dict:
    return json.loads((FIXTURES / path).read_text(encoding="utf-8"))


def cnp_scenarios() -> list[Scenario]:
    """``component_not_present`` baselines. The first is the fully supported case; the others are the same evidence with a weaker basis, so the
    relations are also exercised from Weak and Insufficient starting points."""
    cdx, spdx, vex = _load("equivalent/app.cdx.json"), _load("equivalent/app.spdx.json"), _load("openvex/component_not_present.json")
    profile = profile_data(PLACEHOLDER, target=ABSENT, location=ROOT_NESTED)
    return [
        Scenario("cnp-cdx-verified", "cnp", "cdx", cdx, vex, profile, CDX_FULL,
                 note="complete CycloneDX inventory, completeness declaration, digest binding, trusted verification covering it: Supported"),
        Scenario("cnp-cdx-unverified", "cnp", "cdx", cdx, vex, profile, None, note="the same evidence without a verification result: provenance below P3"),
        Scenario("cnp-spdx", "cnp", "spdx", spdx, vex, profile_data(PLACEHOLDER, target=ABSENT), ("#/packages",),
                 note="SPDX has no completeness declaration: the starting verdict is below Supported"),
    ]


def reach_scenarios() -> list[Scenario]:
    """``vulnerable_code_not_in_execute_path`` baselines: the synthetic K1 negative report with a declared full-coverage claim, complete entry
    points, modeled and excluded hazards, a declared configuration, bound to the SBOM's artifact by digest; verified, unverified, and over SPDX."""
    cdx, spdx, vex = _load("equivalent/app.cdx.json"), _load("equivalent/app.spdx.json"), _load("openvex/reachability_equivalent.json")
    profile = profile_data(PLACEHOLDER)
    reach = _load("reachability/synthetic_baseline.json")
    verified = (("k1-analysis", ("#",)),)
    return [
        Scenario("reach-cdx-verified", "reach", "cdx", cdx, vex, profile, None, reach, verified,
                 note="K1 absence with a declared full-coverage claim, verified (P3), every other dimension satisfied: Supported"),
        Scenario("reach-cdx-unverified", "reach", "cdx", cdx, vex, profile, None, reach, (), note="the same evidence without verification: R13, Weak"),
        Scenario("reach-spdx-verified", "reach", "spdx", spdx, vex, profile, None, reach, verified, note="the same evidence over an SPDX SBOM"),
    ]


def all_scenarios() -> list[Scenario]:
    return cnp_scenarios() + reach_scenarios()
