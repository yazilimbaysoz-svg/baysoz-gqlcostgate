"""Baysöz Labs <baysozlabs@proton.me> — end-to-end CLI contract tests."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from gqlcostgate import ATTRIBUTION
from gqlcostgate.cli import main


def run_cli(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def test_version_and_help_attribute_baysöz_labs():
    version = io.StringIO()
    with redirect_stdout(version), pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "Baysöz Labs" in version.getvalue()
    assert "baysozlabs@proton.me" in version.getvalue()

    help_output = io.StringIO()
    with redirect_stdout(help_output), pytest.raises(SystemExit):
        main(["--help"])
    assert "Baysöz Labs" in help_output.getvalue()
    assert "baysozlabs@proton.me" in help_output.getvalue()


def test_analyze_text_output(fixtures: Path):
    code, output, _ = run_cli(
        "analyze", str(fixtures / "hostile.graphql"), "--schema", str(fixtures / "schema.graphql")
    )
    assert code == 1
    assert "GQL-ALIAS-001" in output
    assert "GQL-AUTHZ-001" in output
    assert ATTRIBUTION in output
    assert "verdict: FAIL" in output


def test_analyze_json_output(fixtures: Path):
    code, output, _ = run_cli("analyze", str(fixtures / "safe.graphql"), "--json")
    assert code == 0
    data = json.loads(output)
    assert data["analyses"][0]["findings"] == []
    assert data["attribution"] == ATTRIBUTION


def test_analyze_benign_with_schema_passes(fixtures: Path):
    code, output, _ = run_cli(
        "analyze",
        str(fixtures / "safe.graphql"),
        "--schema",
        str(fixtures / "schema.graphql"),
    )
    assert code == 0
    assert "verdict: PASS" in output


def test_sarif_command(tmp_path: Path, fixtures: Path):
    out = tmp_path / "report.sarif.json"
    code, output, _ = run_cli("sarif", str(fixtures / "hostile.graphql"), "--out", str(out))
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"]
    assert report["properties"]["attribution"] == ATTRIBUTION
    assert "sarif written" in output


def test_baseline_gate_drift(tmp_path: Path, fixtures: Path):
    baseline = tmp_path / "baseline.json"
    code, _, _ = run_cli("baseline", str(fixtures / "safe.graphql"), "--out", str(baseline))
    assert code == 0
    code, output, _ = run_cli(
        "gate",
        str(fixtures / "safe.graphql"),
        "--baseline",
        str(baseline),
    )
    assert code == 0
    assert '"verdict": "PASS"' in output
    code, output, _ = run_cli(
        "gate",
        str(fixtures / "hostile.graphql"),
        "--baseline",
        str(baseline),
        "--schema",
        str(fixtures / "schema.graphql"),
    )
    assert code == 1
    assert '"verdict": "FAIL"' in output
    assert ATTRIBUTION in output


def test_forge_self_check(fixtures: Path):
    code, output, _ = run_cli("forge", "--schema", str(fixtures / "schema.graphql"))
    assert code == 0
    report = json.loads(output)
    assert report["self_check"] == "PASS"
    assert report["probe_count"] >= 10
    assert all(probe["bounded"] for probe in report["probes"])
    assert report["attribution"] == ATTRIBUTION


def test_rules_command():
    code, output, _ = run_cli("rules")
    assert code == 0
    assert "GQL-AUTHZ-001" in output
    assert ATTRIBUTION in output


def test_tribunal_unanimous(fixtures: Path):
    code, output, _ = run_cli("tribunal", "--schema", str(fixtures / "schema.graphql"))
    assert code == 0
    assert "UNANIMOUS PASS" in output
    assert "NOT UNANIMOUS" not in output
    assert ATTRIBUTION in output


def test_invalid_policy_exits_two(tmp_path: Path, fixtures: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"unknown": true}', encoding="utf-8")
    code, _, stderr = run_cli("analyze", str(fixtures / "safe.graphql"), "--policy", str(bad))
    assert code == 2
    assert "unknown policy keys" in stderr
    assert ATTRIBUTION in stderr
