"""Baysöz Labs <baysozlabs@proton.me> — deterministic GraphQL AST cost oracle."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graphql import Source, parse, validate
from graphql.language.ast import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    OperationDefinitionNode,
    SelectionSetNode,
    VariableNode,
)

from gqlcostgate.model import Analysis, Finding
from gqlcostgate.policy import Policy, read_text_bounded
from gqlcostgate.rules import RULE_INDEX
from gqlcostgate.schema import SchemaField, index_fields

MAX_DOCUMENTS = 512
MAX_EVIDENCE_CHARS = 240
CONDITIONAL_DIRECTIVES = frozenset({"skip", "include"})
INTROSPECTION_PREFIX = "__"
INTROSPECTION_FIELDS = frozenset(
    {
        "schema",
        "types",
        "type",
        "fields",
        "name",
        "inputFields",
        "enumValues",
        "interfaces",
        "directives",
        "args",
        "queryType",
        "mutationType",
        "subscriptionType",
        "ofType",
        "description",
    }
)


@dataclass(slots=True)
class _State:
    findings: dict[str, Finding] = field(default_factory=dict)
    depth: int = 0
    cost: int = 0
    aliases: int = 0
    alias_fields: Counter[str] = field(default_factory=Counter)
    directives: int = 0
    introspection_depth: int = 0
    fragment_expansions: int = 0
    flags: set[str] = field(default_factory=set)

    def add(self, finding: Finding) -> None:
        self.findings.setdefault(finding.key(), finding)


def _location(node: object, source_name: str) -> str:
    loc = getattr(node, "loc", None)
    if loc is None or getattr(loc, "source", None) is None:
        return f"{source_name}:1:1"
    position = loc.source.get_location(loc.start)
    return f"{source_name}:{position.line}:{position.column}"


def _directives(node: object) -> tuple[object, ...]:
    return tuple(getattr(node, "directives", None) or ())


def _arguments(node: object) -> tuple[object, ...]:
    return tuple(getattr(node, "arguments", None) or ())


def _clipped(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS] + "..."


def _emit(
    state: _State,
    rule_id: str,
    node: object,
    source_name: str,
    evidence: str,
    message: str = "",
) -> None:
    rule = RULE_INDEX[rule_id]
    state.add(
        Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            message=message or rule.title,
            location=_location(node, source_name),
            evidence=_clipped(evidence),
            remediation=rule.remediation,
            cwe=rule.cwe,
            owasp=rule.owasp,
        )
    )


def _literal_int(node: object, variables: dict[str, Any]) -> int | None:
    if isinstance(node, IntValueNode):
        try:
            return int(node.value)
        except ValueError:
            return None
    if isinstance(node, VariableNode):
        value = variables.get(node.name.value)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value
    return None


def _root_type_name(operation: OperationDefinitionNode) -> str:
    if operation.operation == "mutation":
        return "Mutation"
    if operation.operation == "subscription":
        return "Subscription"
    return "Query"


def _walk(
    selection_set: SelectionSetNode,
    parent_type: str,
    depth: int,
    fragment_stack: tuple[str, ...],
    state: _State,
    *,
    source_name: str,
    policy: Policy,
    fields: dict[str, SchemaField],
    fragments: dict[str, FragmentDefinitionNode],
    variables: dict[str, Any],
    introspection_active: bool = False,
) -> None:
    limits = policy["limits"]
    cost_cfg = policy["cost"]
    authz_cfg = policy["authz"]
    hard_depth = limits["max_depth"] + 64

    for selection in selection_set.selections:
        current_depth = depth + 1
        if isinstance(selection, FieldNode):
            name = selection.name.value
            field_path = f"{parent_type}.{name}" if parent_type else name
            meta = fields.get(field_path)
            directives = tuple(item.name.value for item in _directives(selection))
            state.directives += len(directives)

            if selection.alias is not None:
                state.aliases += 1
                state.alias_fields[name] += 1
                duplicate_count = state.alias_fields[name]
                if duplicate_count > limits["max_aliases_per_field"]:
                    _emit(
                        state,
                        "GQL-ALIAS-001",
                        selection,
                        source_name,
                        f"field={name} aliases={duplicate_count} "
                        f"limit={limits['max_aliases_per_field']}",
                    )
            if state.aliases > limits["max_aliases"]:
                _emit(
                    state,
                    "GQL-ALIAS-001",
                    selection,
                    source_name,
                    f"document aliases={state.aliases} limit={limits['max_aliases']}",
                )

            paginated_value: int | None = None
            for argument in _arguments(selection):
                if argument.name.value not in cost_cfg["pagination_arguments"]:
                    continue
                value = _literal_int(argument.value, variables)
                if value is None:
                    continue
                paginated_value = value
                if value > cost_cfg["max_pagination_value"]:
                    flag = f"pagination:{field_path}:{value}"
                    if flag not in state.flags:
                        state.flags.add(flag)
                        _emit(
                            state,
                            "GQL-PAGINATE-001",
                            selection,
                            source_name,
                            f"field={field_path} value={value} "
                            f"limit={cost_cfg['max_pagination_value']}",
                        )

            base = cost_cfg["field_costs"].get(
                field_path, cost_cfg["field_costs"].get(name, cost_cfg["default_field_cost"])
            )
            if paginated_value is not None:
                multiplier = min(paginated_value, cost_cfg["max_multiplier"])
            elif meta is not None and meta.is_list:
                multiplier = cost_cfg["default_list_multiplier"]
            else:
                multiplier = 1
            state.cost += base * max(1, multiplier)

            is_introspection = name.startswith(INTROSPECTION_PREFIX) or (
                introspection_active and name in INTROSPECTION_FIELDS
            )
            if is_introspection:
                state.introspection_depth = max(state.introspection_depth, current_depth)
                if not policy.value("introspection", "allowed"):
                    _emit(
                        state,
                        "GQL-INTRO-001",
                        selection,
                        source_name,
                        f"field={name} introspection.allowed=false",
                    )
                if current_depth > limits["max_introspection_depth"]:
                    _emit(
                        state,
                        "GQL-INTRO-002",
                        selection,
                        source_name,
                        f"field={name} depth={current_depth} "
                        f"limit={limits['max_introspection_depth']}",
                    )

            if meta is not None and meta.sensitive:
                if not meta.guarded and f"authz:{field_path}" not in state.flags:
                    state.flags.add(f"authz:{field_path}")
                    _emit(
                        state,
                        "GQL-AUTHZ-001",
                        selection,
                        source_name,
                        f"field={field_path} directives={','.join(directives) or 'none'}",
                    )
                if authz_cfg[
                    "forbid_conditional_sensitive_fields"
                ] and CONDITIONAL_DIRECTIVES.intersection(directives):
                    _emit(
                        state,
                        "GQL-AUTHZ-002",
                        selection,
                        source_name,
                        f"field={field_path} conditional={','.join(sorted(directives))}",
                    )

            state.depth = max(state.depth, current_depth)
            if current_depth > limits["max_depth"]:
                _emit(
                    state,
                    "GQL-DEPTH-001",
                    selection,
                    source_name,
                    f"depth={current_depth} limit={limits['max_depth']}",
                )
            if state.cost > limits["max_cost"] and "cost-overflow" not in state.flags:
                state.flags.add("cost-overflow")
                _emit(
                    state,
                    "GQL-COST-001",
                    selection,
                    source_name,
                    f"cost={state.cost} limit={limits['max_cost']}",
                )

            if selection.selection_set is not None and current_depth < hard_depth:
                child_type = meta.named_type if meta is not None else ""
                _walk(
                    selection.selection_set,
                    child_type,
                    current_depth,
                    fragment_stack,
                    state,
                    source_name=source_name,
                    policy=policy,
                    fields=fields,
                    fragments=fragments,
                    variables=variables,
                    introspection_active=is_introspection,
                )

        elif isinstance(selection, InlineFragmentNode):
            state.directives += len(_directives(selection))
            child_type = parent_type
            if selection.type_condition is not None:
                child_type = selection.type_condition.name.value
            _walk(
                selection.selection_set,
                child_type,
                depth,
                fragment_stack,
                state,
                source_name=source_name,
                policy=policy,
                fields=fields,
                fragments=fragments,
                variables=variables,
                introspection_active=introspection_active,
            )

        elif isinstance(selection, FragmentSpreadNode):
            name = selection.name.value
            state.directives += len(_directives(selection))
            if name in fragment_stack:
                _emit(
                    state,
                    "GQL-FRAG-001",
                    selection,
                    source_name,
                    f"fragment={name} cycle={'->'.join((*fragment_stack, name))}",
                )
                continue
            fragment = fragments.get(name)
            if fragment is None:
                continue
            state.fragment_expansions += 1
            if state.fragment_expansions > limits["max_fragment_expansions"]:
                _emit(
                    state,
                    "GQL-FRAG-002",
                    selection,
                    source_name,
                    f"expansions={state.fragment_expansions} "
                    f"limit={limits['max_fragment_expansions']}",
                )
                continue
            child_type = parent_type
            if fragment.type_condition is not None:
                child_type = fragment.type_condition.name.value
            _walk(
                fragment.selection_set,
                child_type,
                depth,
                fragment_stack + (name,),
                state,
                source_name=source_name,
                policy=policy,
                fields=fields,
                fragments=fragments,
                variables=variables,
                introspection_active=introspection_active,
            )


def analyze_payload(
    text: str,
    policy: Policy,
    schema: Any = None,
    *,
    source: str = "inline",
) -> Analysis:
    """Analyze a raw SDL document, a GraphQL request JSON, or a JSON batch."""
    documents: list[tuple[str, dict[str, Any], str]] = []
    batch_size = 1
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        documents.append((text, {}, source))
    else:
        if isinstance(payload, list):
            batch_size = len(payload)
            if batch_size > MAX_DOCUMENTS:
                raise ValueError(f"batch exceeds {MAX_DOCUMENTS} documents")
            for index, item in enumerate(payload):
                if not isinstance(item, dict) or not isinstance(item.get("query"), str):
                    raise ValueError(f"batch item {index} has no string query")
                variables = item.get("variables", {})
                if not isinstance(variables, dict):
                    raise ValueError(f"batch item {index} variables must be an object")
                documents.append((item["query"], variables, f"{source}#{index}"))
        elif isinstance(payload, dict) and isinstance(payload.get("query"), str):
            variables = payload.get("variables", {})
            if not isinstance(variables, dict):
                raise ValueError("variables must be an object")
            documents.append((payload["query"], variables, source))
        else:
            raise ValueError("payload must be a GraphQL document, request object, or batch array")

    if not documents:
        raise ValueError("payload contains no operations")
    if len(documents) > MAX_DOCUMENTS:
        raise ValueError(f"payload exceeds {MAX_DOCUMENTS} documents")

    state = _State()
    fields = index_fields(schema, policy)
    operation_count = 0
    for query, variables, name in documents:
        source_obj = Source(query, name=name)
        try:
            document = parse(source_obj)
        except RecursionError as exc:
            _emit(state, "GQL-VALIDATE-001", None, name, f"parser recursion limit: {exc}")
            continue
        except Exception as exc:
            _emit(state, "GQL-VALIDATE-001", None, name, f"parse error: {exc}")
            continue

        fragments = {
            definition.name.value: definition
            for definition in document.definitions
            if isinstance(definition, FragmentDefinitionNode)
        }
        operations = [
            definition
            for definition in document.definitions
            if isinstance(definition, OperationDefinitionNode)
        ]
        operation_count += len(operations)
        if (
            len(operations) > policy.value("limits", "max_operations_per_document")
            and len(operations) > 1
        ):
            _emit(
                state,
                "GQL-OPS-001",
                operations[1],
                name,
                f"operations={len(operations)} "
                f"limit={policy.value('limits', 'max_operations_per_document')}",
            )
        for operation in operations:
            state.directives += len(_directives(operation))
            root_type = _root_type_name(operation)
            if operation.selection_set is not None:
                _walk(
                    operation.selection_set,
                    root_type,
                    0,
                    (),
                    state,
                    source_name=name,
                    policy=policy,
                    fields=fields,
                    fragments=fragments,
                    variables=variables,
                )

        if schema is not None:
            try:
                errors = validate(schema, document)
            except RecursionError:
                errors = ()
            for error in errors[:3]:
                line = error.locations[0].line if error.locations else 1
                column = error.locations[0].column if error.locations else 1
                state.add(
                    Finding(
                        rule_id="GQL-VALIDATE-001",
                        severity=RULE_INDEX["GQL-VALIDATE-001"].severity,
                        message=RULE_INDEX["GQL-VALIDATE-001"].title,
                        location=f"{name}:{line}:{column}",
                        evidence=_clipped(error.message),
                        remediation=RULE_INDEX["GQL-VALIDATE-001"].remediation,
                        cwe=RULE_INDEX["GQL-VALIDATE-001"].cwe,
                        owasp=RULE_INDEX["GQL-VALIDATE-001"].owasp,
                    )
                )

    if state.directives > policy.value("limits", "max_directives"):
        _emit(
            state,
            "GQL-DIRECTIVE-001",
            None,
            source,
            f"directives={state.directives} limit={policy.value('limits', 'max_directives')}",
        )
    if batch_size > policy.value("limits", "max_batch_size"):
        _emit(
            state,
            "GQL-BATCH-001",
            None,
            source,
            f"batch_size={batch_size} limit={policy.value('limits', 'max_batch_size')}",
        )

    findings = tuple(sorted(state.findings.values(), key=lambda item: item.key()))
    return Analysis(
        source=source,
        batch_size=batch_size,
        operation_count=operation_count,
        depth=state.depth,
        cost=state.cost,
        alias_count=state.aliases,
        directive_count=state.directives,
        introspection_depth=state.introspection_depth,
        fragment_expansions=state.fragment_expansions,
        findings=findings,
    )


def analyze_file(path: Path, policy: Policy, schema: Any = None) -> Analysis:
    return analyze_payload(read_text_bounded(path), policy, schema, source=path.name)
