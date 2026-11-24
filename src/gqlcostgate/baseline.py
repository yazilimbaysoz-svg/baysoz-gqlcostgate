"""Baysöz Labs <baysozlabs@proton.me> — deterministic baseline drift gate."""

from __future__ import annotations

import json
from typing import Any

from gqlcostgate import ATTRIBUTION
from gqlcostgate.model import Analysis
from gqlcostgate.policy import read_text_bounded
from pathlib import Path


def build_baseline(
    analyses: tuple[Analysis, ...] | list[Analysis], policy_name: str
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    for analysis in analyses:
        for finding in analysis.findings:
            findings.append(
                {
                    "key": finding.key(),
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "location": finding.location,
                    "evidence": finding.evidence,
                    "message": finding.message,
                }
            )
    findings.sort(key=lambda item: item["key"])
    return {
        "attribution": ATTRIBUTION,
        "tool": "baysoz-gqlcostgate",
        "policy": policy_name,
        "finding_count": len(findings),
        "findings": findings,
    }


def load_baseline(path: Path) -> dict[str, Any]:
    data = json.loads(read_text_bounded(path))
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"invalid baseline format: {path}")
    keys: set[str] = set()
    for item in data["findings"]:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise ValueError(f"invalid baseline finding in {path}")
        keys.add(item["key"])
    return data


def compare_baseline(
    baseline: dict[str, Any], analyses: tuple[Analysis, ...] | list[Analysis]
) -> dict[str, Any]:
    before = {item["key"] for item in baseline["findings"]}
    current = {finding.key(): finding for analysis in analyses for finding in analysis.findings}
    new = sorted(set(current) - before)
    resolved = sorted(before - set(current))
    return {
        "attribution": ATTRIBUTION,
        "verdict": "FAIL" if new else "PASS",
        "baseline_policy": baseline.get("policy", "unknown"),
        "new_count": len(new),
        "resolved_count": len(resolved),
        "new_findings": [current[key].to_dict() for key in new],
        "resolved_findings": resolved,
    }
