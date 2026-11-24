"""Baysöz Labs <baysozlabs@proton.me> — offline SDL schema indexing."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from graphql import GraphQLSchema, build_schema
from graphql.type.definition import (
    get_named_type,
    is_interface_type,
    is_list_type,
    is_non_null_type,
    is_object_type,
)

from gqlcostgate.policy import Policy, read_text_bounded
from gqlcostgate.rules import RULE_INDEX

MAX_SCHEMA_TYPES = 512


@dataclass(frozen=True, slots=True)
class SchemaField:
    """One indexed output field with its directive and shape metadata."""

    path: str
    type_name: str
    field_name: str
    named_type: str
    is_list: bool
    arguments: tuple[str, ...]
    directives: tuple[str, ...]
    sensitive: bool
    guarded: bool


def load_schema(path: Path | None) -> GraphQLSchema | None:
    """Parse local SDL only; no introspection endpoint or network access."""
    if path is None:
        return None
    return build_schema(read_text_bounded(path))


def _contains_list(type_: object) -> bool:
    current = type_
    for _ in range(8):
        if is_list_type(current):
            return True
        if is_non_null_type(current):
            current = current.of_type
            continue
        return False
    return False


def _directive_names(field: object) -> tuple[str, ...]:
    ast_node = getattr(field, "ast_node", None)
    if ast_node is None:
        return ()
    return tuple(sorted(item.name.value for item in (ast_node.directives or ())))


def index_fields(schema: GraphQLSchema | None, policy: Policy) -> dict[str, SchemaField]:
    """Build a deterministic path -> field map, including authz classification."""
    if schema is None:
        return {}
    patterns = policy.value("authz", "sensitive_field_patterns")
    auth_directives = set(policy.value("authz", "auth_directives"))
    fields: dict[str, SchemaField] = {}
    type_map = schema.type_map
    if len(type_map) > MAX_SCHEMA_TYPES:
        raise ValueError(f"schema exceeds {MAX_SCHEMA_TYPES} types")
    for type_name in sorted(type_map):
        type_ = type_map[type_name]
        if not (is_object_type(type_) or is_interface_type(type_)) or type_name.startswith("__"):
            continue
        for field_name in sorted(type_.fields):
            if field_name.startswith("__"):
                continue
            field = type_.fields[field_name]
            directives = _directive_names(field)
            sensitive = any(fnmatchcase(field_name, pattern) for pattern in patterns)
            sensitive = sensitive or "sensitive" in directives
            fields[f"{type_name}.{field_name}"] = SchemaField(
                path=f"{type_name}.{field_name}",
                type_name=type_name,
                field_name=field_name,
                named_type=get_named_type(field.type).name,
                is_list=_contains_list(field.type),
                arguments=tuple(sorted(field.args)),
                directives=directives,
                sensitive=sensitive,
                guarded=bool(auth_directives.intersection(directives)),
            )
    return fields


def root_field_names(schema: GraphQLSchema | None) -> tuple[str, ...]:
    """Return sorted public query root field names, or a safe offline fallback."""
    if schema is None or schema.query_type is None:
        return ("__typename",)
    return tuple(
        sorted(name for name in schema.query_type.fields if not name.startswith("__"))
    ) or ("__typename",)


def recursive_field_chain(schema: GraphQLSchema | None) -> tuple[str, ...]:
    """Find a short recursive field chain for depth probes (empty when absent)."""
    if schema is None:
        return ()
    indexed = schema.type_map
    for type_name in sorted(indexed):
        type_ = indexed[type_name]
        if not (is_object_type(type_) or is_interface_type(type_)) or type_name.startswith("__"):
            continue
        for field_name in sorted(type_.fields):
            field = type_.fields[field_name]
            if _contains_list(field.type) and get_named_type(field.type).name == type_name:
                return (field_name,)
    for type_name in sorted(indexed):
        type_ = indexed[type_name]
        if not (is_object_type(type_) or is_interface_type(type_)) or type_name.startswith("__"):
            continue
        for field_name in sorted(type_.fields):
            field = type_.fields[field_name]
            next_type = get_named_type(field.type)
            if next_type.name == type_name or not (
                is_object_type(next_type) or is_interface_type(next_type)
            ):
                continue
            for next_field_name in sorted(next_type.fields):
                back = next_type.fields[next_field_name]
                if get_named_type(back.type).name == type_name:
                    return (field_name, next_field_name)
    return ()


def fields_with_argument(
    schema: GraphQLSchema | None, arguments: tuple[str, ...]
) -> tuple[str, ...]:
    """Return root fields accepting one of the policy pagination arguments."""
    if schema is None or schema.query_type is None:
        return ()
    wanted = set(arguments)
    return tuple(
        sorted(
            name
            for name, field in schema.query_type.fields.items()
            if not name.startswith("__") and any(arg in wanted for arg in field.args)
        )
    )


def authz_requirement(field: SchemaField) -> str:
    return RULE_INDEX["GQL-AUTHZ-001"].remediation if field.sensitive and not field.guarded else ""
