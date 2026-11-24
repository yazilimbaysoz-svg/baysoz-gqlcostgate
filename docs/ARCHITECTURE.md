# Architecture — Baysöz Labs <baysozlabs@proton.me>

## 1. System shape

`baysoz-gqlcostgate` is a single-process, offline Python 3.13 CLI and importable library. There is no daemon, database, message broker, browser, LLM, or network client. The only runtime dependency is `graphql-core`, used for SDL construction, document parsing, and schema validation.

```
 SDL schema ─┐                         ┌─ Finding[] (stable key/order)
 policy JSON ┼─> Policy ─> Analyzer ───┼─ metrics (depth, cost, aliases, ...)
 request(s) ─┘       │                 └─ SARIF 2.1.0 / JSON / text
                     └─> Forge ─> bounded probes ─> Analyzer self-check
                                  │
                                  └─> Baseline ─> gate verdict (new/resolved)
```

## 2. Module responsibilities

| Module | Responsibility |
| --- | --- |
| `src/gqlcostgate/cli.py` | argparse commands: `analyze`, `forge`, `baseline`, `gate`, `sarif`, `rules`, `tribunal`; exit codes 0/1/2 |
| `src/gqlcostgate/policy.py` | strict JSON policy merge, validation, 2 MB input cap |
| `src/gqlcostgate/schema.py` | SDL loading via `build_schema`; deterministic field index with list/pagination/directive metadata |
| `src/gqlcostgate/analyzer.py` | AST traversal, metrics, rule emission, GraphQL schema validation |
| `src/gqlcostgate/forge.py` | schema-derived bounded probe generation and per-probe self-check |
| `src/gqlcostgate/sarif.py` | deterministic SARIF 2.1.0 with SHA-256 partial fingerprints |
| `src/gqlcostgate/baseline.py` | finding-key baseline and new/resolved drift comparison |
| `src/gqlcostgate/tribunal.py` | 14 live jurors; unanimous-pass release gate |
| `src/gqlcostgate/model.py`, `rules.py` | immutable result types and 14-rule catalogue |

## 3. Analysis algorithms

**Input normalization.** Text that is not JSON is parsed as one GraphQL document. A JSON object with a `query` string is a single request; a JSON array is an array batch. Each batch item may carry `variables`. Inputs are capped at 2 MB and 512 documents.

**Depth.** The root selection set is depth 0; each field adds one. Inline fragments and fragment spreads preserve the current depth. Recursive traversal stops at `max_depth + 64` so hostile nesting cannot exhaust the Python stack.

**Cost.** `cost = Σ base(field) × multiplier(field)`. Base is `policy.cost.field_costs["Parent.field"]`, then `field_costs["field"]`, then `default_field_cost`. A literal or variable-backed pagination argument (`first`, `last`, `limit`, `pageSize`) supplies the multiplier; otherwise a list-typed field uses `default_list_multiplier`. Multipliers are capped by `max_multiplier`, so attacker-controlled integers cannot overflow the accounting.

**Aliases.** Every alias increments the document alias count; the per-resolved-field counter detects duplicate alias fan-out independently of the total budget.

**Fragments.** Fragment spreads are expanded with a path-local stack. A repeated name emits `GQL-FRAG-001` and stops expansion on that branch. A global expansion counter enforces `max_fragment_expansions` and emits `GQL-FRAG-002`.

**Introspection.** Meta-fields and their known descendant fields are tracked through an introspection-active flag, so recursive `__schema { types { fields { type { ... } } } }` chains are measured even when no schema is supplied. Policy can allow introspection while still bounding recursion depth.

**Authorization.** SDL directives are indexed per output field. A sensitive field (policy glob or `@sensitive`) with none of the configured auth directives emits `GQL-AUTHZ-001`; `@skip`/`@include` on such a field emits `GQL-AUTHZ-002`. Guarded fields are deliberately not reported.

**Validation.** With SDL available, `graphql-core` validation errors become low-severity `GQL-VALIDATE-001` findings (first three), so invalid adversarial payloads remain analyzable instead of aborting the gate.

**Determinism.** Findings are deduplicated by `(rule, location, evidence)` and sorted by that key. JSON uses sorted keys and UTF-8. SARIF fingerprints are SHA-256 of the finding key. The same inputs always produce byte-identical reports.

## 4. Forge design

Probes are generated from policy thresholds and the optional SDL: recursive field chains for depth, paginated root fields for cost, sensitive unguarded fields for authz, plus alias, batch, directive, introspection, cycle and multi-operation vectors. Every probe is a single bounded request (arrays are capped at `max_batch_size + 1`). Before any report is emitted, the forge replays each probe through the analyzer and raises `ForgeSelfCheckError` if its declared rule does not fire. There are no flood loops and no network calls.

## 5. Security boundary

- File reads are explicit local paths, UTF-8, size-capped.
- No subprocess, socket, HTTP client, dynamic evaluation, or template execution.
- Policies are strict: unknown keys are rejected; numeric limits must be positive integers.
- Sensitive field patterns use `fnmatchcase`, not user-supplied regular expressions, avoiding regex blow-ups.
- Output files are written only to paths explicitly passed by the operator.
- See `SECURITY.md` for the threat model and authorized-use policy.

## 6. Quality gates and release

`uv venv`, `uv pip install -e .`, `uv pip install pytest`, `uv run pytest -q`, `ruff check --select E,F,W,S,B .`, `semgrep --config p/default --error .`, then `gqlcostgate tribunal`. A release is permitted only when all tests and static/security scans are clean and every juror returns PASS.

Baysöz Labs <baysozlabs@proton.me>
