"""Baysöz Labs <baysozlabs@proton.me> — bounded probe forge tests."""

import json

from gqlcostgate.analyzer import analyze_payload
from gqlcostgate.forge import build_probes, forge_report, self_check_probes


def test_probes_are_derived_from_schema(policy, schema):
    probes = build_probes(policy, schema)
    ids = {probe.probe_id for probe in probes}
    assert {
        "depth-nesting",
        "alias-fanout",
        "batch-array",
        "directive-overload",
        "introspection-schema",
        "fragment-cycle",
        "cost-amplification",
        "authz-sensitive-field",
    }.issubset(ids)
    assert all(probe.to_dict()["bounded"] for probe in probes)


def test_every_probe_triggers_declared_rule(policy, schema):
    probes = build_probes(policy, schema)
    evidence = self_check_probes(probes, policy, schema)
    assert len(evidence) == len(probes)
    for probe in probes:
        assert probe.expected_rule in evidence[probe.probe_id]


def test_report_is_deterministic(policy, schema):
    first = forge_report(policy, schema, schema_name="schema.graphql")
    second = forge_report(policy, schema, schema_name="schema.graphql")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["self_check"] == "PASS"


def test_forge_works_without_a_schema(policy):
    probes = build_probes(policy)
    self_check_probes(probes, policy, None)
    assert len(probes) >= 9
    for probe in probes:
        payload = json.dumps(probe.request, sort_keys=True)
        analysis = analyze_payload(payload, policy, source=probe.probe_id)
        assert probe.expected_rule in {finding.rule_id for finding in analysis.findings}
