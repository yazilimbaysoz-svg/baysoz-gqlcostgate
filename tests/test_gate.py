"""Baysöz Labs <baysozlabs@proton.me> — baseline drift-gate tests."""

from gqlcostgate.analyzer import analyze_payload
from gqlcostgate.baseline import build_baseline, compare_baseline
from gqlcostgate.policy import default_policy


def test_stable_baseline_passes():
    policy = default_policy()
    analyses = (analyze_payload("query { __typename }", policy, source="stable"),)
    baseline = build_baseline(analyses, "default")
    result = compare_baseline(baseline, analyses)
    assert result["verdict"] == "PASS"
    assert result["new_count"] == 0


def test_new_finding_fails_gate():
    policy = default_policy()
    clean = (analyze_payload("query { __typename }", policy, source="clean"),)
    hostile = (analyze_payload("query { users(first: 900) { id } }", policy, source="hostile"),)
    baseline = build_baseline(clean, "default")
    result = compare_baseline(baseline, hostile)
    assert result["verdict"] == "FAIL"
    assert result["new_count"] > 0
    assert all("rule_id" in item for item in result["new_findings"])


def test_resolved_finding_is_reported():
    policy = default_policy()
    hostile = (analyze_payload("query { users(first: 900) { id } }", policy),)
    baseline = build_baseline(hostile, "default")
    result = compare_baseline(baseline, ())
    assert result["verdict"] == "PASS"
    assert result["resolved_count"] == len(baseline["findings"])
