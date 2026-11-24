"""Baysöz Labs <baysozlabs@proton.me> — production command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from gqlcostgate import ATTRIBUTION, __version__
from gqlcostgate.analyzer import analyze_file
from gqlcostgate.baseline import build_baseline, compare_baseline, load_baseline
from gqlcostgate.forge import ForgeSelfCheckError, forge_report
from gqlcostgate.model import Analysis
from gqlcostgate.policy import Policy, load_policy
from gqlcostgate.rules import RULES
from gqlcostgate.sarif import build_sarif, dump_json

SEVERITY_CHOICES = ("none", "low", "medium", "high", "critical")


def _add_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "inputs", nargs="+", type=Path, help="GraphQL documents, request JSON, or batch JSON files"
    )
    parser.add_argument("--policy", type=Path, help="local JSON policy file")
    parser.add_argument("--schema", type=Path, help="local GraphQL SDL schema file")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gqlcostgate",
        description="Offline GraphQL adversarial cost, depth, batching and authorization oracle.",
        epilog=f"Baysöz Labs <baysozlabs@proton.me> — v{__version__}. Authorized testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"baysoz-gqlcostgate {__version__} — {ATTRIBUTION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="analyze documents or requests and emit deterministic findings",
        epilog=f"By {ATTRIBUTION}. No network calls are performed.",
    )
    _add_inputs(analyze)
    analyze.add_argument("--fail-on", choices=SEVERITY_CHOICES, default="medium")
    analyze.add_argument("--json", action="store_true", help="emit stable JSON instead of text")
    analyze.add_argument("--sarif", type=Path, help="also write SARIF 2.1.0 to this path")

    forge = subparsers.add_parser(
        "forge",
        help="generate bounded, schema-derived adversarial probe requests",
        epilog=f"By {ATTRIBUTION}. Every probe is verified against the analyzer by default.",
    )
    forge.add_argument("--policy", type=Path)
    forge.add_argument("--schema", type=Path)
    forge.add_argument("--out", type=Path, help="write probe report to this path")
    forge.add_argument("--no-self-check", action="store_true")

    baseline = subparsers.add_parser(
        "baseline",
        help="write a deterministic finding baseline for CI drift gating",
        epilog=f"By {ATTRIBUTION}.",
    )
    _add_inputs(baseline)
    baseline.add_argument("--out", type=Path, required=True)

    gate = subparsers.add_parser(
        "gate",
        help="compare current findings against a baseline and fail on new hits",
        epilog=f"By {ATTRIBUTION}.",
    )
    _add_inputs(gate)
    gate.add_argument("--baseline", type=Path, required=True)

    sarif = subparsers.add_parser(
        "sarif",
        help="write a SARIF 2.1.0 report for CI ingestion",
        epilog=f"By {ATTRIBUTION}.",
    )
    _add_inputs(sarif)
    sarif.add_argument("--out", type=Path, required=True)

    subparsers.add_parser(
        "rules",
        help="list the stable rule catalogue with CWE and OWASP mappings",
        epilog=f"By {ATTRIBUTION}.",
    )

    tribunal = subparsers.add_parser(
        "tribunal",
        help="run the Supreme Grand Jury live adversarial verification suite",
        epilog=f"By {ATTRIBUTION}. Release requires a unanimous PASS.",
    )
    tribunal.add_argument("--policy", type=Path)
    tribunal.add_argument("--schema", type=Path)
    return parser


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _load_inputs(args: argparse.Namespace, policy: Policy) -> tuple[Analysis, ...]:
    from gqlcostgate.schema import load_schema

    schema = load_schema(getattr(args, "schema", None))
    return tuple(analyze_file(path, policy, schema) for path in args.inputs)


def _render_analyses(analyses: tuple[Analysis, ...], fail_on: str) -> str:
    lines = [f"baysoz-gqlcostgate {__version__} — {ATTRIBUTION}"]
    failed = False
    for analysis in analyses:
        lines.append(f"\n[{analysis.source}]")
        lines.append(
            f"  depth={analysis.depth} cost={analysis.cost} aliases={analysis.alias_count} "
            f"directives={analysis.directive_count} batch={analysis.batch_size} "
            f"operations={analysis.operation_count}"
        )
        if not analysis.findings:
            lines.append("  no findings")
            continue
        failed = failed or analysis.severity_at_least(fail_on)
        for finding in analysis.findings:
            lines.append(
                f"  [{finding.severity.upper()}] {finding.rule_id} {finding.location} "
                f"— {finding.message}"
            )
            lines.append(f"      evidence: {finding.evidence}")
            lines.append(f"      fix: {finding.remediation}")
            lines.append(f"      mapping: {finding.cwe} / {finding.owasp}")
    verdict = "FAIL" if failed else "PASS"
    lines.append(f"\nverdict: {verdict} (fail-on={fail_on})")
    return "\n".join(lines)


def _cmd_analyze(args: argparse.Namespace, policy: Policy) -> int:
    analyses = _load_inputs(args, policy)
    if args.json:
        payload = {
            "attribution": ATTRIBUTION,
            "tool": "baysoz-gqlcostgate",
            "version": __version__,
            "analyses": [analysis.to_dict(ATTRIBUTION) for analysis in analyses],
        }
        print(dump_json(payload), end="")
    else:
        print(_render_analyses(analyses, args.fail_on))
    if args.sarif is not None:
        _write(args.sarif, dump_json(build_sarif(analyses)))
        print(f"sarif written: {args.sarif} ({ATTRIBUTION})")
    return 1 if any(analysis.severity_at_least(args.fail_on) for analysis in analyses) else 0


def _cmd_forge(args: argparse.Namespace, policy: Policy) -> int:
    from gqlcostgate.schema import load_schema

    schema = load_schema(args.schema)
    report = forge_report(
        policy,
        schema,
        schema_name=args.schema.name if args.schema else "inline",
        self_check=not args.no_self_check,
    )
    text = dump_json(report)
    if args.out is not None:
        _write(args.out, text)
        print(f"probe report written: {args.out} ({ATTRIBUTION})")
    else:
        print(text, end="")
    return 0


def _cmd_baseline(args: argparse.Namespace, policy: Policy) -> int:
    analyses = _load_inputs(args, policy)
    baseline = build_baseline(analyses, policy.data["name"])
    _write(args.out, dump_json(baseline))
    print(f"baseline written: {args.out} ({baseline['finding_count']} findings) — {ATTRIBUTION}")
    return 0


def _cmd_gate(args: argparse.Namespace, policy: Policy) -> int:
    baseline = load_baseline(args.baseline)
    analyses = _load_inputs(args, policy)
    result = compare_baseline(baseline, analyses)
    print(dump_json(result), end="")
    return 1 if result["verdict"] == "FAIL" else 0


def _cmd_sarif(args: argparse.Namespace, policy: Policy) -> int:
    analyses = _load_inputs(args, policy)
    report = build_sarif(analyses)
    _write(args.out, dump_json(report))
    print(
        f"sarif written: {args.out} ({len(report['runs'][0]['results'])} results) — {ATTRIBUTION}"
    )
    return 0


def _cmd_rules(_args: argparse.Namespace, _policy: Policy) -> int:
    print(f"baysoz-gqlcostgate rule catalogue — {ATTRIBUTION}")
    for rule in RULES:
        print(f"{rule.rule_id:<18} {rule.severity:<8} {rule.cwe:<8} {rule.title}")
    return 0


def _cmd_tribunal(args: argparse.Namespace, policy: Policy) -> int:
    from gqlcostgate.tribunal import run_tribunal

    schema_path = args.schema
    jurors = run_tribunal(policy, schema_path)
    for juror in jurors:
        marker = "PASS" if juror.passed else "FAIL"
        print(f"[{marker}] {juror.name}: {juror.detail}")
    unanimous = all(juror.passed for juror in jurors)
    print(f"Supreme Grand Jury Tribunal: {'UNANIMOUS PASS' if unanimous else 'NOT UNANIMOUS'}")
    print(f"Convened by {ATTRIBUTION}")
    return 0 if unanimous else 1


_COMMANDS = {
    "analyze": _cmd_analyze,
    "forge": _cmd_forge,
    "baseline": _cmd_baseline,
    "gate": _cmd_gate,
    "sarif": _cmd_sarif,
    "rules": _cmd_rules,
    "tribunal": _cmd_tribunal,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        policy = load_policy(getattr(args, "policy", None))
        return _COMMANDS[args.command](args, policy)
    except ForgeSelfCheckError as exc:
        print(f"forge self-check failed: {exc} ({ATTRIBUTION})", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc} ({ATTRIBUTION})", file=sys.stderr)
        return 2
