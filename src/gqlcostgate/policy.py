"""Baysöz Labs <baysozlabs@proton.me> — validated, bounded policy loading."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gqlcostgate import ATTRIBUTION

MAX_INPUT_BYTES = 2_000_000

DEFAULT_POLICY: dict[str, Any] = {
    "name": "default",
    "attribution": ATTRIBUTION,
    "limits": {
        "max_depth": 8,
        "max_cost": 500,
        "max_aliases": 10,
        "max_aliases_per_field": 3,
        "max_directives": 12,
        "max_batch_size": 5,
        "max_operations_per_document": 1,
        "max_introspection_depth": 3,
        "max_fragment_expansions": 64,
    },
    "introspection": {"allowed": False},
    "cost": {
        "default_field_cost": 1,
        "default_list_multiplier": 10,
        "max_multiplier": 10_000,
        "pagination_arguments": ["first", "last", "limit", "pageSize"],
        "max_pagination_value": 100,
        "field_costs": {},
    },
    "authz": {
        "sensitive_field_patterns": [
            "*password*",
            "*secret*",
            "*token*",
            "*ssn*",
            "*email*",
        ],
        "auth_directives": ["auth", "requires", "authorized"],
        "forbid_conditional_sensitive_fields": True,
    },
}


def read_text_bounded(path: Path, limit: int = MAX_INPUT_BYTES) -> str:
    """Read UTF-8 text with an explicit size cap; never resolve remote inputs."""
    if not path.is_file():
        raise ValueError(f"not a readable file: {path}")
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds {limit} bytes: {path}")
    return path.read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class Policy:
    """Normalized policy with defaults filled in and all values validated."""

    data: dict[str, Any]

    def __getitem__(self, section: str) -> dict[str, Any]:
        value = self.data[section]
        if isinstance(value, dict):
            return value
        raise ValueError(f"policy section is not an object: {section}")

    def value(self, section: str, key: str) -> Any:
        return self[section][key]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)


def default_policy() -> Policy:
    return Policy(copy.deepcopy(DEFAULT_POLICY))


def _merge(defaults: dict[str, Any], supplied: dict[str, Any], path: str) -> dict[str, Any]:
    unknown = sorted(set(supplied) - set(defaults))
    if unknown:
        raise ValueError(f"unknown policy keys at {path}: {', '.join(unknown)}")
    merged = copy.deepcopy(defaults)
    for key, value in supplied.items():
        expected = defaults[key]
        if isinstance(expected, dict) and not expected:
            if not isinstance(value, dict):
                raise ValueError(f"policy.{path}.{key} must be an object")
            merged[key] = copy.deepcopy(value)
        elif isinstance(expected, dict):
            if not isinstance(value, dict):
                raise ValueError(f"policy.{path}.{key} must be an object")
            merged[key] = _merge(expected, value, f"{path}.{key}" if path else key)
        else:
            merged[key] = value
    return merged


def _positive_int(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"policy.{label} must be a positive integer")


def _string_list(value: Any, label: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"policy.{label} must be a list of non-empty strings")


def _validate(policy: Policy) -> Policy:
    data = policy.data
    if not isinstance(data.get("name"), str) or not data["name"]:
        raise ValueError("policy.name must be a non-empty string")
    if not isinstance(data.get("attribution"), str) or "Baysöz Labs" not in data["attribution"]:
        raise ValueError("policy.attribution must attribute Baysöz Labs")

    for key in (
        "max_depth",
        "max_cost",
        "max_aliases",
        "max_aliases_per_field",
        "max_directives",
        "max_batch_size",
        "max_operations_per_document",
        "max_introspection_depth",
        "max_fragment_expansions",
    ):
        _positive_int(policy.value("limits", key), f"limits.{key}")
    if not isinstance(policy.value("introspection", "allowed"), bool):
        raise ValueError("policy.introspection.allowed must be a boolean")

    for key in (
        "default_field_cost",
        "default_list_multiplier",
        "max_multiplier",
        "max_pagination_value",
    ):
        _positive_int(policy.value("cost", key), f"cost.{key}")
    _string_list(policy.value("cost", "pagination_arguments"), "cost.pagination_arguments")
    field_costs = policy.value("cost", "field_costs")
    if not isinstance(field_costs, dict) or len(field_costs) > 256:
        raise ValueError("policy.cost.field_costs must be an object with at most 256 entries")
    for key, value in field_costs.items():
        if not isinstance(key, str) or not key:
            raise ValueError("policy.cost.field_costs keys must be non-empty strings")
        _positive_int(value, f"cost.field_costs.{key}")

    _string_list(
        policy.value("authz", "sensitive_field_patterns"), "authz.sensitive_field_patterns"
    )
    _string_list(policy.value("authz", "auth_directives"), "authz.auth_directives")
    conditional = policy.value("authz", "forbid_conditional_sensitive_fields")
    if not isinstance(conditional, bool):
        raise ValueError("policy.authz.forbid_conditional_sensitive_fields must be a boolean")
    return policy


def policy_from_dict(data: dict[str, Any], name: str = "inline") -> Policy:
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    merged = _merge(DEFAULT_POLICY, data, "")
    merged["name"] = data.get("name", name)
    return _validate(Policy(merged))


def load_policy(path: Path | None) -> Policy:
    """Load a JSON policy; an absent path selects the hardened default policy."""
    if path is None:
        return default_policy()
    try:
        raw = json.loads(read_text_bounded(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid policy JSON in {path}: {exc}") from exc
    return policy_from_dict(raw, name=path.name)
