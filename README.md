# baysoz-gqlcostgate

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-gqlcostgate/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-gqlcostgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-green.svg)](pyproject.toml)
[![Offline / no network](https://img.shields.io/badge/network-none-darkgreen.svg)](SECURITY.md)

**Offline GraphQL cost, depth, batching and authorization conformance oracle with deterministic SARIF CI gates and a bounded adversarial probe forge.**

Built by **Baysöz Labs <baysozlabs@proton.me>**. Authorized testing only.

## Why

Live GraphQL DAST tools tell you what a deployed endpoint tolerated; they cannot gate a pull request. Generic API-security checklists still miss batching and alias amplification. `baysoz-gqlcostgate` closes that shift-left gap: it reads local SDL, policies, documents, request JSON and batch arrays, computes reproducible evidence, and emits stable rule IDs with CWE/OWASP mappings. See [market research](docs/MARKET_RESEARCH.md).

## Install

```bash
git clone https://github.com/yazilimbaysoz-svg/baysoz-gqlcostgate.git
cd baysoz-gqlcostgate
uv venv
uv pip install -e .
uv run gqlcostgate --version
```

Python 3.13+ and `uv` are the only requirements. `graphql-core` is the single runtime dependency. No services, databases, browsers, local LLMs, or network calls.

## Architecture

```
 SDL schema ─┐                         ┌─ Finding[] (stable key/order)
 policy JSON ┼─> Policy ─> Analyzer ───┼─ metrics (depth, cost, aliases, ...)
 request(s) ─┘       │                 └─ SARIF 2.1.0 / JSON / text
                     └─> Forge ─> bounded probes ─> Analyzer self-check
                                  │
                                  └─> Baseline ─> gate verdict (new/resolved)
```

Modules: `policy.py` (strict bounded JSON), `schema.py` (SDL field/directive index), `analyzer.py` (fragment-aware AST cost and authz oracle), `forge.py` (schema-derived probes), `sarif.py` (deterministic SARIF), `baseline.py` (drift gate), `tribunal.py` (14 live jurors), `cli.py`. Full details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Commands

```bash
gqlcostgate analyze tests/fixtures/hostile.graphql --schema tests/fixtures/schema.graphql
gqlcostgate analyze request.json --policy policy.json --json
gqlcostgate sarif request.json --out report.sarif.json
gqlcostgate baseline tests/fixtures/safe.graphql --out baseline.json
gqlcostgate gate request.json --baseline baseline.json
gqlcostgate forge --schema tests/fixtures/schema.graphql --out probes.json
gqlcostgate rules
gqlcostgate tribunal --schema tests/fixtures/schema.graphql
```

Exit codes: `0` clean, `1` findings at/above `--fail-on` (default `medium`) or gate regression, `2` invalid input/policy.

## Real CLI output

```
$ uv run gqlcostgate --version
baysoz-gqlcostgate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
```

```
$ uv run gqlcostgate analyze tests/fixtures/hostile.graphql --schema tests/fixtures/schema.graphql

[hostile.graphql]
  depth=10 cost=4022 aliases=4 directives=0 batch=1 operations=1
  [HIGH] GQL-ALIAS-001 hostile.graphql:6:3 — Alias fan-out amplifies one field into many units of work
      evidence: field=users aliases=4 limit=3
      fix: Cap aliases per document and duplicate aliases per resolved field.
      mapping: CWE-770 / OWASP API4:2023
  [CRITICAL] GQL-AUTHZ-001 hostile.graphql:8:12 — Sensitive field is not guarded by an authorization directive
      evidence: field=User.email directives=none
      fix: Apply @auth or an equivalent field-level authorization directive.
      mapping: CWE-862 / OWASP API1:2023
  [HIGH] GQL-COST-001 hostile.graphql:3:3 — Estimated query cost exceeds the declared complexity budget
      evidence: cost=1000 limit=500
      fix: Enforce a complexity budget that includes list multipliers and aliases.
      mapping: CWE-770 / OWASP API4:2023
  [HIGH] GQL-DEPTH-001 hostile.graphql:7:93 — Query nesting exceeds the declared depth budget
      evidence: depth=10 limit=8
      fix: Enforce a server-side maximum query depth and reject deeper documents.
      mapping: CWE-400 / OWASP API4:2023
  [HIGH] GQL-INTRO-001 hostile.graphql:9:3 — Introspection is reachable while policy forbids it
      evidence: field=__schema introspection.allowed=false
      fix: Disable schema introspection in production or authenticate it.
      mapping: CWE-200 / OWASP API8:2023
  [MEDIUM] GQL-INTRO-002 hostile.graphql:9:31 — Recursive introspection traversal exceeds the declared depth budget
      evidence: field=type depth=4 limit=3
      fix: Exclude introspection from complexity accounting or bound its depth.
      mapping: CWE-674 / OWASP API4:2023
  ... deterministic findings omitted for brevity ...
verdict: FAIL (fail-on=medium)
```

```
$ uv run gqlcostgate tribunal --schema tests/fixtures/schema.graphql
[PASS] ATTRIBUTION: version/help attributed; 33 files checked
[PASS] NO_STUBS: 12 modules inspected for stubs and network calls
[PASS] PARSER: 10 probes parsed into 64 selections
[PASS] COST_MATH: expected cost=22 (21 + id), computed cost=22
[PASS] DEPTH: expected depth=13, computed depth=13, rule_hit=True
[PASS] ALIAS: aliases=5, rule_hit=True
[PASS] BATCH: batch_size=6, rule_hit=True
[PASS] FRAGMENT: cycle_detected=True, expansions=1
[PASS] INTROSPECTION: introspection_depth=6, rules=['GQL-INTRO-001', 'GQL-INTRO-002']
[PASS] AUTHZ: unguarded_fields=['field=User.email directives=none']
[PASS] FORGE: 10/10 probes triggered their expected rule
[PASS] SARIF: version=2.1.0, results=64, deterministic=True
[PASS] GATE: stable=PASS, regression=FAIL, resolved=64
[PASS] CLI: live analyze exit=1, alias rule emitted=True
Supreme Grand Jury Tribunal: UNANIMOUS PASS
Convened by Baysöz Labs <baysozlabs@proton.me>
```

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

Final state: 33 tests passing, Ruff 0 findings, Semgrep 0 findings, Tribunal unanimous PASS.

## Documentation

- [Market research](docs/MARKET_RESEARCH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Plan](PLAN.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

MIT licensed by Baysöz Labs <baysozlabs@proton.me>.
