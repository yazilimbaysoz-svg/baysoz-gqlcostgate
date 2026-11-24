"""Baysöz Labs <baysozlabs@proton.me> — immutable analysis result types."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single deterministic rule hit with remediation evidence."""

    rule_id: str
    severity: str
    message: str
    location: str
    evidence: str
    remediation: str
    cwe: str
    owasp: str

    def key(self) -> str:
        return f"{self.rule_id}|{self.location}|{self.evidence}"

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
        }


@dataclass(frozen=True, slots=True)
class Analysis:
    """Aggregated metrics and ordered findings for one analyzed payload."""

    source: str
    batch_size: int
    operation_count: int
    depth: int
    cost: int
    alias_count: int
    directive_count: int
    introspection_depth: int
    fragment_expansions: int
    findings: tuple[Finding, ...]

    def to_dict(self, attribution: str) -> dict[str, object]:
        return {
            "attribution": attribution,
            "source": self.source,
            "metrics": {
                "batch_size": self.batch_size,
                "operation_count": self.operation_count,
                "depth": self.depth,
                "cost": self.cost,
                "alias_count": self.alias_count,
                "directive_count": self.directive_count,
                "introspection_depth": self.introspection_depth,
                "fragment_expansions": self.fragment_expansions,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def severity_at_least(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        return any(
            SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold] for finding in self.findings
        )
