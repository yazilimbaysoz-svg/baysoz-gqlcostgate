"""Baysöz Labs <baysozlabs@proton.me> — stable rule catalogue for CI evidence."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    remediation: str


RULES: tuple[Rule, ...] = (
    Rule(
        "GQL-DEPTH-001",
        "Query nesting exceeds the declared depth budget",
        "high",
        "CWE-400",
        "OWASP API4:2023",
        "Enforce a server-side maximum query depth and reject deeper documents.",
    ),
    Rule(
        "GQL-COST-001",
        "Estimated query cost exceeds the declared complexity budget",
        "high",
        "CWE-770",
        "OWASP API4:2023",
        "Enforce a complexity budget that includes list multipliers and aliases.",
    ),
    Rule(
        "GQL-ALIAS-001",
        "Alias fan-out amplifies one field into many units of work",
        "high",
        "CWE-770",
        "OWASP API4:2023",
        "Cap aliases per document and duplicate aliases per resolved field.",
    ),
    Rule(
        "GQL-BATCH-001",
        "Array batch request exceeds the declared batch budget",
        "high",
        "CWE-770",
        "OWASP API4:2023",
        "Disable batching or cap batch size and apply per-operation budgets.",
    ),
    Rule(
        "GQL-OPS-001",
        "Document defines more operations than the declared budget",
        "medium",
        "CWE-400",
        "OWASP API4:2023",
        "Require one named operation per document in production traffic.",
    ),
    Rule(
        "GQL-DIRECTIVE-001",
        "Directive applications exceed the declared budget",
        "medium",
        "CWE-400",
        "OWASP API4:2023",
        "Cap directive applications and @defer/@stream use per document.",
    ),
    Rule(
        "GQL-INTRO-001",
        "Introspection is reachable while policy forbids it",
        "high",
        "CWE-200",
        "OWASP API8:2023",
        "Disable schema introspection in production or authenticate it.",
    ),
    Rule(
        "GQL-INTRO-002",
        "Recursive introspection traversal exceeds the declared depth budget",
        "medium",
        "CWE-674",
        "OWASP API4:2023",
        "Exclude introspection from complexity accounting or bound its depth.",
    ),
    Rule(
        "GQL-FRAG-001",
        "Circular fragment spread is present in the document",
        "high",
        "CWE-674",
        "OWASP API4:2023",
        "Reject cyclic fragment spreads during validation before execution.",
    ),
    Rule(
        "GQL-FRAG-002",
        "Fragment expansion count exceeds the declared fan-out budget",
        "medium",
        "CWE-400",
        "OWASP API4:2023",
        "Cap fragment spreads per document and reuse field selection sets.",
    ),
    Rule(
        "GQL-AUTHZ-001",
        "Sensitive field is not guarded by an authorization directive",
        "critical",
        "CWE-862",
        "OWASP API1:2023",
        "Apply @auth or an equivalent field-level authorization directive.",
    ),
    Rule(
        "GQL-AUTHZ-002",
        "Sensitive field is wrapped in a conditional skip/include directive",
        "high",
        "CWE-862",
        "OWASP API1:2023",
        "Do not let clients conditionally remove authorization-critical fields.",
    ),
    Rule(
        "GQL-PAGINATE-001",
        "Pagination argument exceeds the declared page-size budget",
        "medium",
        "CWE-770",
        "OWASP API4:2023",
        "Clamp first/last/limit/pageSize server-side to a safe maximum.",
    ),
    Rule(
        "GQL-VALIDATE-001",
        "Document fails GraphQL schema validation",
        "low",
        "CWE-20",
        "OWASP API8:2023",
        "Reject invalid documents during validation with stable error codes.",
    ),
)

RULE_INDEX: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}
