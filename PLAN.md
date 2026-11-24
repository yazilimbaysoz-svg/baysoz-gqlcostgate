# PLAN — Baysöz Labs <baysozlabs@proton.me>

## Phase 1 — Ecosystem validation (complete)

- Inspected all 27 entries in `existing-repos.json`; confirmed no GraphQL security tool exists in the portfolio.
- Mined live GitHub trend and issue data via `gh search repos` / `gh search issues`; confirmed GraphQL batching detection gap and SARIF CI demand.
- Selected an offline GraphQL cost/authz/adversarial-probe oracle with `uv`, Python 3.13+, `graphql-core`, zero heavy services, zero local LLMs.

## Phase 2 — Product construction (complete)

- Strict layered package under `src/gqlcostgate/` (policy, schema, analyzer, forge, SARIF, baseline, CLI, tribunal).
- 14 stable rules with CWE/OWASP mappings, remediation text, deterministic ordering.
- Commands: `analyze`, `forge`, `baseline`, `gate`, `sarif`, `rules`, `tribunal`.
- Documentation: `README.md`, `docs/MARKET_RESEARCH.md`, `docs/ARCHITECTURE.md`, `PLAN.md`, `SECURITY.md`, `CHANGELOG.md`.
- Packaging: `pyproject.toml`, MIT `LICENSE`, `.github/workflows/ci.yml`, `.gitignore`.

## Phase 3 — Zero-defect gates (complete)

Commands executed from the repository root:

```
uv venv
uv pip install -e .
uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

Defects found and fixed during iteration: `graphql-core` 3.3 nullable AST collections, field-argument naming (`GraphQLArgument` keys), recursive policy merge for free-form `field_costs`, rpartition location parsing, introspection descendant tracking, test CLI stderr capture, fixture depth calibration, and unused imports. Final state: 33 tests passing, Ruff 0 findings, Semgrep 0 findings.

## Phase 4 — Supreme Grand Jury Tribunal (complete)

Run `gqlcostgate tribunal --schema tests/fixtures/schema.graphql`. Fourteen jurors execute live evidence checks: attribution, stub/network-marker scan, parser selection counting, cost math (22), depth math (13), alias count, batch size, bounded fragment cycle, recursive introspection, positive/negative authz classification, forge self-check, SARIF determinism, baseline drift semantics, and a real CLI invocation with exit code verification. Release requires `UNANIMOUS PASS`.

## Phase 5 — Publication (in progress)

- Create the public repository under the `yazilimbaysoz-svg` account with a crisp description and security topics.
- Emit the showcase result JSON at the path supplied by the orchestration workspace without touching other showcase files.

## Future work (deliberately out of scope for 1.0.0)

- Additional SDL directive vocabularies contributed by adopters.
- Persisted-query allowlist compilation as a separate rule family.
- Machine-readable policy templates for specific gateway implementations.

Baysöz Labs <baysozlabs@proton.me>
