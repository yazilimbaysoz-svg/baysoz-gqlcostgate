"""Baysöz Labs <baysozlabs@proton.me> — Supreme Grand Jury verification suite."""

from __future__ import annotations

import copy
import io
import json
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from graphql import build_schema, parse

from gqlcostgate import ATTRIBUTION, __version__
from gqlcostgate.analyzer import analyze_payload
from gqlcostgate.baseline import build_baseline, compare_baseline
from gqlcostgate.forge import build_probes, self_check_probes
from gqlcostgate.model import Analysis
from gqlcostgate.policy import Policy
from gqlcostgate.sarif import build_sarif, dump_json

PROHIBITED_SOURCE_MARKERS = (
    "TO" + "DO",
    "FIX" + "ME",
    "NotImplemented" + "Error",
    "import " + "requests",
    "import " + "httpx",
    "import " + "socket",
    "import " + "subprocess",
)
SKIP_DIRECTORIES = frozenset(
    {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
)
TEXT_SUFFIXES = frozenset(
    {".py", ".md", ".toml", ".yml", ".yaml", ".json", ".graphql", ".txt", ".lock"}
)
SPECIAL_FILES = frozenset({"LICENSE", ".gitignore"})


@dataclass(frozen=True, slots=True)
class JurorVerdict:
    name: str
    passed: bool
    detail: str


def _verdict(name: str, passed: bool, detail: str) -> JurorVerdict:
    return JurorVerdict(name=name, passed=passed, detail=detail)


def _selection_count(query: str) -> int:
    document = parse(query)
    total = 0
    stack: list[Any] = []
    for definition in document.definitions:
        selection_set = getattr(definition, "selection_set", None)
        if selection_set is not None:
            stack.append(selection_set)
    while stack:
        selections = getattr(stack.pop(), "selections", None) or ()
        total += len(selections)
        for selection in selections:
            selection_set = getattr(selection, "selection_set", None)
            if selection_set is not None:
                stack.append(selection_set)
    return total


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _public_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in SPECIAL_FILES:
            result.append(path)
    return result


def _attribution_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    from gqlcostgate.cli import main

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        try:
            main(["--version"])
        except SystemExit:
            pass
    version_text = stdout.getvalue()

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        try:
            main(["--help"])
        except SystemExit:
            pass
    help_text = stdout.getvalue()

    root = _project_root()
    files = _public_files(root)
    missing: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        if "Baysöz Labs" not in text or "baysozlabs@proton.me" not in text:
            missing.append(str(path.relative_to(root)))
    ok = (
        "Baysöz Labs" in version_text
        and "baysozlabs@proton.me" in version_text
        and "Baysöz Labs" in help_text
        and "baysozlabs@proton.me" in help_text
        and not missing
    )
    detail = f"version/help attributed; {len(files)} files checked"
    if missing:
        detail += f"; missing: {', '.join(missing[:5])}"
    return _verdict("ATTRIBUTION", ok, detail)


def _no_stubs_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    source_files = sorted((_project_root() / "src" / "gqlcostgate").glob("*.py"))
    flagged: list[str] = []
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        for marker in PROHIBITED_SOURCE_MARKERS:
            if marker in text:
                flagged.append(f"{path.name}:{marker}")
    ok = len(source_files) >= 8 and not flagged
    detail = f"{len(source_files)} modules inspected for stubs and network calls"
    if flagged:
        detail += f"; flagged: {', '.join(flagged)}"
    return _verdict("NO_STUBS", ok, detail)


def _parser_juror(
    policy: Policy,
    schema_path: Path | None,
    probes: tuple[Any, ...],
) -> JurorVerdict:
    selections = 0
    for probe in probes:
        requests = probe.request if isinstance(probe.request, list) else [probe.request]
        for request in requests:
            selections += _selection_count(request["query"])
    ok = len(probes) >= 9 and selections >= 40
    return _verdict("PARSER", ok, f"{len(probes)} probes parsed into {selections} selections")


def _cost_math_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    local = Policy(copy.deepcopy(policy.data))
    local.data["cost"]["field_costs"] = {"Query.items": 3}
    analysis = analyze_payload(
        "query CostMath { items(first: 7) { id } }", local, source="juror:cost"
    )
    ok = analysis.cost == 22
    return _verdict("COST_MATH", ok, f"expected cost=22 (21 + id), computed cost={analysis.cost}")


def _depth_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    nesting = "__typename"
    levels = max(12, policy.value("limits", "max_depth") + 2)
    for _ in range(levels):
        nesting = f"child {{ {nesting} }}"
    analysis = analyze_payload(f"query DepthJuror {{ {nesting} }}", policy, source="juror:depth")
    rules = {finding.rule_id for finding in analysis.findings}
    expected_depth = levels + 1
    ok = analysis.depth == expected_depth and "GQL-DEPTH-001" in rules
    return _verdict(
        "DEPTH",
        ok,
        f"expected depth={expected_depth}, computed depth={analysis.depth}, "
        f"rule_hit={'GQL-DEPTH-001' in rules}",
    )


def _alias_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    query = (
        "query AliasJuror { "
        + " ".join(f"a{index}: items {{ __typename }}" for index in range(5))
        + " }"
    )
    analysis = analyze_payload(query, policy, source="juror:alias")
    rules = {finding.rule_id for finding in analysis.findings}
    ok = analysis.alias_count == 5 and "GQL-ALIAS-001" in rules
    return _verdict(
        "ALIAS", ok, f"aliases={analysis.alias_count}, rule_hit={'GQL-ALIAS-001' in rules}"
    )


def _batch_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    count = policy.value("limits", "max_batch_size") + 1
    payload = json.dumps([{"query": "query { __typename }"}] * count)
    analysis = analyze_payload(payload, policy, source="juror:batch")
    rules = {finding.rule_id for finding in analysis.findings}
    ok = analysis.batch_size == count and "GQL-BATCH-001" in rules
    return _verdict(
        "BATCH", ok, f"batch_size={analysis.batch_size}, rule_hit={'GQL-BATCH-001' in rules}"
    )


def _fragment_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    query = "query FragmentJuror { ...loop } fragment loop on Query { ...loop }"
    analysis = analyze_payload(query, policy, source="juror:fragment")
    rules = {finding.rule_id for finding in analysis.findings}
    bounded = analysis.fragment_expansions <= policy.value("limits", "max_fragment_expansions")
    ok = "GQL-FRAG-001" in rules and bounded
    return _verdict(
        "FRAGMENT",
        ok,
        f"cycle_detected={'GQL-FRAG-001' in rules}, expansions={analysis.fragment_expansions}",
    )


def _introspection_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    query = "query IntroJuror { __schema { types { fields { type { fields { name } } } } } }"
    analysis = analyze_payload(query, policy, source="juror:introspection")
    rules = {finding.rule_id for finding in analysis.findings}
    ok = {"GQL-INTRO-001", "GQL-INTRO-002"}.issubset(rules)
    return _verdict(
        "INTROSPECTION",
        ok,
        f"introspection_depth={analysis.introspection_depth}, rules={sorted(rules)}",
    )


def _authz_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    schema = build_schema(
        """
        directive @auth on FIELD_DEFINITION
        directive @sensitive on FIELD_DEFINITION
        type Query { viewer: User }
        type User { id: ID!, email: String @sensitive, token: String @auth }
        """
    )
    analysis = analyze_payload(
        "query AuthzJuror { viewer { email token } }", policy, schema, source="juror:authz"
    )
    paths = {
        finding.evidence for finding in analysis.findings if finding.rule_id == "GQL-AUTHZ-001"
    }
    ok = len(paths) == 1 and "User.email" in next(iter(paths))
    return _verdict("AUTHZ", ok, f"unguarded_fields={sorted(paths)}")


def _forge_juror(
    policy: Policy,
    schema_path: Path | None,
    schema: Any,
    probes: tuple[Any, ...],
) -> JurorVerdict:
    evidence = self_check_probes(probes, policy, schema)
    ok = len(evidence) == len(probes)
    return _verdict(
        "FORGE", ok, f"{len(evidence)}/{len(probes)} probes triggered their expected rule"
    )


def _sarif_juror(
    policy: Policy, schema_path: Path | None, analyses: tuple[Analysis, ...]
) -> JurorVerdict:
    report = build_sarif(analyses)
    results = report["runs"][0]["results"]
    found = sum(len(analysis.findings) for analysis in analyses)
    deterministic = dump_json(report) == dump_json(build_sarif(analyses))
    ok = (
        report["version"] == "2.1.0"
        and len(results) == found
        and len(report["runs"][0]["tool"]["driver"]["rules"]) >= 10
        and deterministic
    )
    return _verdict(
        "SARIF",
        ok,
        f"version={report['version']}, results={len(results)}, deterministic={deterministic}",
    )


def _gate_juror(
    policy: Policy, schema_path: Path | None, analyses: tuple[Analysis, ...]
) -> JurorVerdict:
    baseline = build_baseline(analyses, policy.data["name"])
    stable = compare_baseline(baseline, analyses)
    empty = build_baseline([], policy.data["name"])
    regressions = compare_baseline(empty, analyses)
    resolved = compare_baseline(baseline, [])
    ok = (
        stable["verdict"] == "PASS"
        and stable["new_count"] == 0
        and regressions["verdict"] == "FAIL"
        and regressions["new_count"] > 0
        and resolved["resolved_count"] > 0
    )
    return _verdict(
        "GATE",
        ok,
        f"stable={stable['verdict']}, regression={regressions['verdict']}, "
        f"resolved={resolved['resolved_count']}",
    )


def _cli_juror(policy: Policy, schema_path: Path | None) -> JurorVerdict:
    from gqlcostgate.cli import main

    with tempfile.TemporaryDirectory() as tmp:
        payload = Path(tmp) / "adversarial.json"
        payload.write_text(
            json.dumps(
                {
                    "query": "query { "
                    + " ".join(f"a{i}: items {{ __typename }}" for i in range(20))
                    + " }"
                }
            ),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["analyze", str(payload), "--json"])
        output = stdout.getvalue()
    ok = code == 1 and "GQL-ALIAS-001" in output and ATTRIBUTION in output
    return _verdict(
        "CLI", ok, f"live analyze exit={code}, alias rule emitted={'GQL-ALIAS-001' in output}"
    )


def run_tribunal(policy: Policy, schema_path: Path | None) -> tuple[JurorVerdict, ...]:
    """Convene all jurors; each checks live runtime evidence, not declarations."""
    from gqlcostgate.schema import load_schema

    schema = load_schema(schema_path)
    probes = build_probes(policy, schema)
    analyses = tuple(
        analyze_payload(
            json.dumps(probe.request, sort_keys=True),
            policy,
            schema,
            source=f"tribunal:{probe.probe_id}",
        )
        for probe in probes
    )
    checks: list[Callable[..., JurorVerdict]] = [
        lambda: _attribution_juror(policy, schema_path),
        lambda: _no_stubs_juror(policy, schema_path),
        lambda: _parser_juror(policy, schema_path, probes),
        lambda: _cost_math_juror(policy, schema_path),
        lambda: _depth_juror(policy, schema_path),
        lambda: _alias_juror(policy, schema_path),
        lambda: _batch_juror(policy, schema_path),
        lambda: _fragment_juror(policy, schema_path),
        lambda: _introspection_juror(policy, schema_path),
        lambda: _authz_juror(policy, schema_path),
        lambda: _forge_juror(policy, schema_path, schema, probes),
        lambda: _sarif_juror(policy, schema_path, analyses),
        lambda: _gate_juror(policy, schema_path, analyses),
        lambda: _cli_juror(policy, schema_path),
    ]
    verdicts: list[JurorVerdict] = []
    for check in checks:
        try:
            verdicts.append(check())
        except Exception as exc:
            verdicts.append(
                _verdict(
                    "EXCEPTION",
                    False,
                    f"{check.__name__ if hasattr(check, '__name__') else 'juror'}: {exc}",
                )
            )
    return tuple(verdicts)


__all__ = ["JurorVerdict", "run_tribunal", "__version__"]
