# Market Research — Baysöz Labs <baysozlabs@proton.me>

## 1. Method and evidence base

This research was performed before implementation. We inspected the 27 existing Baysöz Labs repositories in `/home/runner/work/_temp/existing-repos.json` to eliminate overlap, then mined live GitHub trend and issue signals with `gh search repos` / `gh search issues` (rate limits were reached after the initial result sets), and cross-checked the ecosystem with public repository documentation.

Existing portfolio clusters: Alertmanager, CSP3, MCP contracts, Python SBOM reachability, Kubernetes PDB/NetworkPolicy/Gateway API, PromQL, HTTP/1.1 desync, OpenAPI BOLA, SLO burn-rate, JOSE/JWT, Terraform blast radius, OpenTelemetry, ATR/Sigma parity, GitHub Actions lockfiles, log masking. **No GraphQL security tool exists in the portfolio.** Reusing any of those names or rule sets would be redundant; adding a GraphQL-specific capability is a distinct, non-trivial gap.

## 2. Live trend signals

- The `red-team` topic returned high-star, actively updated repositories as of 2026-11-24: `mukul975/Anthropic-Cybersecurity-Skills` (~36.6k stars), `elementalsouls/Claude-BugHunter` (~20k), `BaaRai/ARTEX` (~17.9k), `BishopFox/sliver` (~12.4k), `microsoft/PyRIT` (~5k). Security engineering demand is clearly concentrated in offensive/validation tooling rather than another generic scanner.
- `gh search issues "jwt confusion"` surfaced `UnitOneAI/SecuritySkills#1026`: "[REVIEW] api-security: Missing GraphQL batching attack detection and JWT confusion vulnerabilities". The JWT half is already covered in this portfolio by `baysoz-josegate`; the **GraphQL batching half is still uncovered**.
- `gh search issues "SAST false positive" OR "sarif"` surfaced `trufflesecurity/trufflehog#578` (SARIF 2.1.0 output for CI), `golangci/golangci-lint#2866`, and `semgrep/semgrep#3019`. SARIF is the integration currency; a new tool that emits human text only would be a CI dead end.

## 3. GraphQL-specific ecosystem pain

Public repositories found via live search and documentation review:

| Project | Stars / vintage | What it does | Gap we address |
| --- | --- | --- | --- |
| `dolevf/graphql-cop` | ~700, 2022 | Live endpoint checks for alias overloading, batching, introspection, debug leakage | Requires a target; no offline schema/query conformance, no baseline gate, no CI-stable rule IDs |
| `kabiri-labs/gdos` | ~2, 2025 | 12 bounded single-shot DoS probes against a live endpoint | DAST-only; no local SDL + query corpus analysis, no drift baseline, no field-level authz evidence |
| `m3m0rydmp/Introspectre` | evolving 2026 | Passive schema graph + active offensive probes, JWT analysis | Active probing and visualization; not a deterministic pre-merge policy compiler with SARIF exit codes |
| `zentinelproxy/zentinel-agent-graphql-security` | 2026, Rust | Runtime proxy agent for depth, cost, aliases, batches, authz | Runtime enforcement; cannot gate a pull request before deployment or compare a policy baseline |
| `Vampsecure-Labs/vamp-graphql-audit` | 2026 | Six-phase DAST auditor with HTML reports | Needs a live endpoint; no deterministic offline oracle or CI drift semantics |
| `mstuart/graphql-sentinel` | 2026 | Runtime shield / scanner | Same deployment-time bias; no auditable offline evidence chain |

Pain points are consistent across these projects and issues:

1. **Batching and alias amplification are still missed** by generic API security review skills and by scanners that only inspect a single operation.
2. **Cost formulas are opaque.** Pagination arguments, list multipliers, fragments and aliases interact; most tools report a single heuristic number without reproducible evidence.
3. **Field-level authorization regressions are invisible** until runtime. Sensitive fields (`email`, `passwordHash`, `secret`) often lack `@auth` guards in SDL, and conditional `@skip`/`@include` can be used to drop guarded fields from a client query.
4. **CI needs stable evidence.** Findings must have stable IDs, fingerprints, CWE/OWASP mappings, deterministic ordering, and a baseline diff; DAST output is timing-dependent and cannot serve as a merge gate.
5. **Offensive probe generation is unbounded or network-bound** in many tools. A red team needs bounded, schema-derived request packets that can be replayed by an authorized tester, with each probe provably detected by the local oracle.

## 4. Product decision

**Selected:** `baysoz-gqlcostgate`, a Python 3.13+ CLI/library built with `uv` and `graphql-core`. It is an offline GraphQL cost/depth/batching/authorization conformance oracle plus a bounded adversarial probe forge. It does not spawn services, does not call LLMs, does not open sockets, and does not execute JavaScript.

Why this is genuinely needed and not a toy:

- It consumes *both* SDL and real request payloads (single document, request JSON, JSON batch arrays) and reasons about their interaction.
- It implements fragment-aware traversal with cycle detection and bounded expansion, variable-aware pagination cost with capped multipliers, alias duplication accounting, introspection recursion detection, and SDL-driven sensitive-field authorization classification.
- It emits 14 stable rules with CWE/OWASP mapping, deterministic SARIF 2.1.0, and a baseline drift gate that distinguishes new findings from resolved ones.
- Its forge derives probes from the supplied schema (recursive field chains, paginated root fields, sensitive unguarded fields) and self-verifies that each probe triggers its declared rule before release.
- Its Supreme Grand Jury suite executes live adversarial inputs through the built CLI/analyzer, checks cost/depth math against known answers, verifies SARIF determinism and baseline gate semantics, and refuses a non-unanimous verdict.

## 5. Non-goals

No live target scanning, no credentialed auth testing, no traffic interception, no fuzzing floods, no LLM-generated findings, no heavy services. Those belong to the DAST tools listed above and to authorized engagement workflows.

Baysöz Labs <baysozlabs@proton.me>
