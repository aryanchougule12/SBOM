"""Security-semantic mutation and metamorphic validation framework (dissertation Phase III).

A *scenario* is a complete evaluation input (SBOM, VEX, evaluator profile, optional verification and reachability evidence) held as
plain JSON so that a *mutation operator* can degrade, delete, inject or neutrally rewrite one kind of evidence. A *relation*
(the specification's invariants M-1..M-6, section 6) states what must hold between the evaluation of the base scenario and of the mutant.
A *campaign* runs every applicable (scenario, operator) pair and reports, with denominators, which relations held and any violation.

It exercises only the public evaluation entry point (``evidence.sufficiency.evaluate_finding``) and never changes a rule: a violation is a
finding about the implementation (or the specification), reported, not repaired here. Everything is synthetic: it shows the engine obeys the
written invariants on these controlled mutations, not detection accuracy or anything about real SBOMs.
"""
