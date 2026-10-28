# Vendored third-party files

| File | Source | SHA-256 | Use |
|---|---|---|---|
| `sarif-schema-2.1.0.json` | OASIS SARIF TC, `oasis-tcs/sarif-spec`, path `sarif-2.1/schema/sarif-schema-2.1.0.json` (branch `main`, retrieved 2026-10-28 from raw.githubusercontent.com) | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` | Test-time validation of the SARIF fixtures (`tests/test_analysis_sarif.py`). The runtime parser does not import it. |

The SARIF schema is published by OASIS under the OASIS IPR policy; it is reproduced unmodified for
test purposes. It is the authority used for the field names, types, required fields and enumerations
that `evidence/analysis_sarif.py` consumes.
