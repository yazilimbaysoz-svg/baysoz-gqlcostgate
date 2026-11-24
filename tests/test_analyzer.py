"""Baysöz Labs <baysozlabs@proton.me> — analyzer unit and adversarial tests."""

from pathlib import Path

import pytest

from gqlcostgate.analyzer import analyze_file, analyze_payload
from gqlcostgate.policy import load_policy, policy_from_dict, read_text_bounded


def test_benign_query_has_no_findings(policy, schema, fixtures: Path):
    analysis = analyze_file(fixtures / "safe.graphql", policy, schema)
    assert analysis.findings == ()
    assert analysis.cost == 3
    assert analysis.depth == 2


def test_hostile_query_fires_distinct_rules(policy, schema, fixtures: Path):
    analysis = analyze_file(fixtures / "hostile.graphql", policy, schema)
    rules = {finding.rule_id for finding in analysis.findings}
    expected = {
        "GQL-ALIAS-001",
        "GQL-INTRO-001",
        "GQL-PAGINATE-001",
        "GQL-COST-001",
        "GQL-AUTHZ-001",
        "GQL-DEPTH-001",
    }
    assert expected.issubset(rules)
    assert analysis.alias_count == 4
    assert analysis.introspection_depth >= 6


def test_batch_json_detected(policy, fixtures: Path):
    analysis = analyze_file(fixtures / "batch.json", policy)
    assert analysis.batch_size == 6
    assert any(finding.rule_id == "GQL-BATCH-001" for finding in analysis.findings)


def test_variable_cost_is_deterministic(policy):
    payload = '{"query": "query Q($n: Int!) { items(first: $n) { id } }", "variables": {"n": 9}}'
    analysis = analyze_payload(payload, policy, source="variables")
    assert analysis.cost == 10
    assert analysis.to_dict("Baysöz Labs <baysozlabs@proton.me>")["metrics"]["cost"] == 10


def test_strict_policy_field_costs(strict_policy, schema, fixtures: Path):
    analysis = analyze_file(fixtures / "safe.graphql", strict_policy, schema)
    assert analysis.findings == ()
    hostile = analyze_file(fixtures / "hostile.graphql", strict_policy, schema)
    assert hostile.cost > 300
    assert any(finding.rule_id == "GQL-COST-001" for finding in hostile.findings)


def test_fragment_cycle_is_bounded(policy):
    query = "query { ...loop } fragment loop on Query { ...loop }"
    analysis = analyze_payload(query, policy, source="cycle")
    assert analysis.fragment_expansions <= policy.value("limits", "max_fragment_expansions")
    assert any(finding.rule_id == "GQL-FRAG-001" for finding in analysis.findings)


def test_introspection_policy_can_allow_schema(policy):
    allowed = policy_from_dict({"introspection": {"allowed": True}})
    analysis = analyze_payload("query { __schema { types { name } } }", allowed)
    assert not any(finding.rule_id == "GQL-INTRO-001" for finding in analysis.findings)


def test_authz_guarded_field_is_not_flagged(policy, schema):
    analysis = analyze_payload("query { adminPanel { secret } }", policy, schema)
    assert not any(finding.rule_id == "GQL-AUTHZ-001" for finding in analysis.findings)


def test_conditional_sensitive_field_flagged(policy, schema):
    analysis = analyze_payload("query { viewer { email @skip(if: false) } }", policy, schema)
    rules = {finding.rule_id for finding in analysis.findings}
    assert "GQL-AUTHZ-002" in rules


def test_multi_operation_document_flagged(policy):
    analysis = analyze_payload("query A { __typename } query B { __typename }", policy)
    assert analysis.operation_count == 2
    assert any(finding.rule_id == "GQL-OPS-001" for finding in analysis.findings)


def test_analysis_is_byte_deterministic(policy, schema, fixtures: Path):
    first = analyze_file(fixtures / "hostile.graphql", policy, schema)
    second = analyze_file(fixtures / "hostile.graphql", policy, schema)
    assert first.to_dict("Baysöz Labs <baysozlabs@proton.me>") == second.to_dict(
        "Baysöz Labs <baysozlabs@proton.me>"
    )


def test_unknown_payload_shape_rejected(policy):
    with pytest.raises(ValueError, match="payload must be"):
        analyze_payload('{"unexpected": true}', policy)


def test_input_size_cap(tmp_path: Path):
    huge = tmp_path / "huge.graphql"
    huge.write_text("query { __typename }" + " " * 2_000_100, encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds"):
        read_text_bounded(huge)


def test_policy_rejects_unknown_keys():
    with pytest.raises(ValueError, match="unknown policy keys"):
        policy_from_dict({"limits": {"maximum_depth": 4}})


def test_policy_rejects_zero_limit():
    with pytest.raises(ValueError, match="positive integer"):
        policy_from_dict({"limits": {"max_depth": 0}})


def test_load_policy_from_file(strict_policy, fixtures: Path):
    loaded = load_policy(fixtures / "policy.json")
    assert loaded.data == strict_policy.data
