"""Baysöz Labs <baysozlabs@proton.me> — bounded, schema-derived probe forge."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from graphql import GraphQLSchema
from graphql.type.definition import get_named_type, is_interface_type, is_object_type

from gqlcostgate import ATTRIBUTION
from gqlcostgate.analyzer import analyze_payload
from gqlcostgate.policy import Policy
from gqlcostgate.rules import RULE_INDEX
from gqlcostgate.schema import (
    fields_with_argument,
    index_fields,
    recursive_field_chain,
    root_field_names,
)


@dataclass(frozen=True, slots=True)
class Probe:
    """A single bounded request with a deterministic expected rule."""

    probe_id: str
    vector: str
    expected_rule: str
    request: dict[str, Any] | list[dict[str, Any]]
    expected_defense: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.probe_id,
            "vector": self.vector,
            "expected_rule": self.expected_rule,
            "severity": RULE_INDEX[self.expected_rule].severity,
            "bounded": True,
            "request": self.request,
            "expected_defense": self.expected_defense,
        }


class ForgeSelfCheckError(RuntimeError):
    """Raised when a generated probe does not trigger its declared rule."""


def _object_root(schema: GraphQLSchema | None) -> str:
    if schema is None or schema.query_type is None:
        return "__typename"
    for name in sorted(schema.query_type.fields):
        named = get_named_type(schema.query_type.fields[name].type)
        if name.startswith("__"):
            continue
        if is_object_type(named) or is_interface_type(named):
            return name
    return "__typename"


def _depth_query(schema: GraphQLSchema | None, policy: Policy) -> str:
    needed = policy.value("limits", "max_depth") + 2
    chain = recursive_field_chain(schema)
    if chain:
        selection = "__typename"
        for _ in range(needed):
            for field in reversed(chain):
                selection = f"{field} {{ {selection} }}"
        return f"query DepthProbe {{ {selection} }}"
    selection = "name"
    levels = max(4, needed // 2 + 1)
    for index in range(levels):
        selection = f"p{index}: type {{ fields {{ {selection} }} }}"
    return f"query DepthProbe {{ __schema {{ types {{ fields {{ {selection} }} }} }} }}"


def _authz_probe(schema: GraphQLSchema | None, policy: Policy) -> Probe | None:
    if schema is None or schema.query_type is None:
        return None
    fields = index_fields(schema, policy)
    candidates = [
        field
        for field in fields.values()
        if field.sensitive and not field.guarded and field.type_name in schema.type_map
    ]
    for target in candidates:
        for root in sorted(schema.query_type.fields):
            if root.startswith("__"):
                continue
            root_field = fields.get(f"Query.{root}")
            if root_field is not None and root_field.named_type == target.type_name:
                query = f"query AuthzProbe {{ {root} {{ {target.field_name} }} }}"
                return Probe(
                    "authz-sensitive-field",
                    "authorization gap on sensitive output field",
                    "GQL-AUTHZ-001",
                    {"query": query, "variables": {}},
                    "Field-level authorization directive must guard this field.",
                )
    return None


def build_probes(policy: Policy, schema: GraphQLSchema | None = None) -> tuple[Probe, ...]:
    """Derive all probes from the policy and optional local SDL schema."""
    limits = policy["limits"]
    cost_cfg = policy["cost"]
    root = _object_root(schema)
    roots = root_field_names(schema)
    alias_root = "users" if "users" in roots else root
    pagination_fields = fields_with_argument(schema, tuple(cost_cfg["pagination_arguments"]))
    pagination_field = pagination_fields[0] if pagination_fields else alias_root
    page_value = cost_cfg["max_pagination_value"] + 1
    multiplier = min(page_value, cost_cfg["max_multiplier"])
    duplicate_count = max(2, limits["max_cost"] // multiplier + 1)

    def aliased(field: str, count: int, arguments: str = "") -> str:
        selection = "{ __typename }" if field != "__typename" else ""
        return " ".join(
            f"p{index}: {field}{arguments} {selection}".strip() for index in range(count)
        )

    probes: list[Probe] = [
        Probe(
            "depth-nesting",
            "deep selection-set nesting",
            "GQL-DEPTH-001",
            {"query": _depth_query(schema, policy), "variables": {}},
            "Reject documents whose depth exceeds the configured limit.",
        ),
        Probe(
            "alias-fanout",
            "aliased duplicate field fan-out",
            "GQL-ALIAS-001",
            {
                "query": f"query AliasProbe {{ {aliased(alias_root, limits['max_aliases'] + 1)} }}",
                "variables": {},
            },
            "Cap aliases per document and duplicates per resolved field.",
        ),
        Probe(
            "batch-array",
            "JSON array request batching",
            "GQL-BATCH-001",
            [{"query": "query BatchProbe { __typename }", "variables": {}}]
            * (limits["max_batch_size"] + 1),
            "Cap batch size or disable array batching entirely.",
        ),
        Probe(
            "directive-overload",
            "repeated directive applications on one field",
            "GQL-DIRECTIVE-001",
            {
                "query": "query DirectiveProbe { __typename "
                + " ".join(["@skip(if: false)"] * (limits["max_directives"] + 1))
                + " }",
                "variables": {},
            },
            "Cap directive applications and token length per document.",
        ),
        Probe(
            "introspection-schema",
            "recursive schema introspection",
            "GQL-INTRO-001",
            {
                "query": "query IntroProbe { __schema { types { fields { type { "
                "fields { name } } } } } }",
                "variables": {},
            },
            "Disable introspection in production or gate it behind authentication.",
        ),
        Probe(
            "fragment-cycle",
            "self-referential fragment spread",
            "GQL-FRAG-001",
            {
                "query": "query CycleProbe { ...loop } fragment loop on Query { ...loop }",
                "variables": {},
            },
            "Reject cyclic fragment spreads during validation.",
        ),
        Probe(
            "pagination-bypass",
            "oversized pagination argument",
            "GQL-PAGINATE-001",
            {
                "query": f"query PageProbe {{ {pagination_field}(first: {page_value}) "
                "{ __typename } }",
                "variables": {},
            },
            "Clamp page-size arguments server-side.",
        ),
        Probe(
            "cost-amplification",
            "aliased paginated fan-out above cost budget",
            "GQL-COST-001",
            {
                "query": f"query CostProbe {{ "
                f"{aliased(pagination_field, duplicate_count, f'(first: {page_value})')} }}",
                "variables": {},
            },
            "Enforce a complexity budget including list multipliers and aliases.",
        ),
        Probe(
            "multi-operation-document",
            "multiple operations in one document",
            "GQL-OPS-001",
            {
                "query": "query OperationProbeA { __typename } "
                "query OperationProbeB { __typename }",
                "variables": {},
            },
            "Require exactly one named operation per production document.",
        ),
    ]
    authz = _authz_probe(schema, policy)
    if authz is not None:
        probes.append(authz)
    return tuple(probes)


def self_check_probes(
    probes: tuple[Probe, ...], policy: Policy, schema: GraphQLSchema | None
) -> dict[str, list[str]]:
    """Execute every probe against the analyzer; every expected rule must fire."""
    evidence: dict[str, list[str]] = {}
    failures: list[str] = []
    for probe in probes:
        payload = json.dumps(probe.request, sort_keys=True)
        analysis = analyze_payload(payload, policy, schema, source=f"forge:{probe.probe_id}")
        rule_ids = [finding.rule_id for finding in analysis.findings]
        evidence[probe.probe_id] = rule_ids
        if probe.expected_rule not in rule_ids:
            failures.append(f"{probe.probe_id}: expected {probe.expected_rule}, got {rule_ids}")
    if failures:
        raise ForgeSelfCheckError("; ".join(failures))
    return evidence


def forge_report(
    policy: Policy,
    schema: GraphQLSchema | None = None,
    *,
    schema_name: str = "inline",
    self_check: bool = True,
) -> dict[str, Any]:
    probes = build_probes(policy, schema)
    evidence = self_check_probes(probes, policy, schema) if self_check else {}
    return {
        "attribution": ATTRIBUTION,
        "tool": "baysoz-gqlcostgate",
        "schema": schema_name,
        "policy": policy.data["name"],
        "probe_count": len(probes),
        "self_check": "PASS" if self_check else "SKIPPED",
        "self_check_evidence": evidence,
        "probes": [probe.to_dict() for probe in probes],
    }
