"""Baysöz Labs <baysozlabs@proton.me> — deterministic SARIF 2.1.0 emitter."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from gqlcostgate import ATTRIBUTION
from gqlcostgate.model import Analysis
from gqlcostgate.rules import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _split_location(location: str) -> tuple[str, int, int]:
    try:
        head, column_text = location.rsplit(":", 1)
        uri, line_text = head.rsplit(":", 1)
        return uri or "inline", int(line_text), int(column_text)
    except ValueError:
        return location, 1, 1


def _level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def build_sarif(analyses: tuple[Analysis, ...] | list[Analysis]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for analysis in analyses:
        for finding in analysis.findings:
            uri, line, column = _split_location(finding.location)
            digest = hashlib.sha256(finding.key().encode("utf-8")).hexdigest()
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _level(finding.severity),
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": line, "startColumn": column},
                            }
                        }
                    ],
                    "partialFingerprints": {"gqlcostgate/v1": digest},
                    "properties": {
                        "severity": finding.severity,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "cwe": finding.cwe,
                        "owasp": finding.owasp,
                    },
                }
            )
    results.sort(key=lambda item: (item["ruleId"], str(item["locations"]), str(item["message"])))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "properties": {"attribution": ATTRIBUTION},
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-gqlcostgate",
                        "version": "1.0.0",
                        "fullName": f"baysoz-gqlcostgate by {ATTRIBUTION}",
                        "rules": [
                            {
                                "id": rule.rule_id,
                                "name": rule.title,
                                "shortDescription": {"text": rule.title},
                                "defaultConfiguration": {"level": _level(rule.severity)},
                                "properties": {"cwe": rule.cwe, "owasp": rule.owasp},
                            }
                            for rule in RULES
                        ],
                    }
                },
                "properties": {"attribution": ATTRIBUTION},
                "results": results,
            }
        ],
    }


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
