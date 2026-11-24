# Security Policy — Baysöz Labs <baysozlabs@proton.me>

## Intended use

`baysoz-gqlcostgate` is an **offline** analysis and probe-generation tool for authorized application security work: engineering teams hardening their own GraphQL APIs, red teams preparing bounded test plans, and CI systems guarding regressions. Generated probes are deliberately adversarial but bounded; replay them only against endpoints you own or are explicitly authorized to test.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Hostile GraphQL document exhausts analyzer resources | 2 MB per-file cap, 512-document cap, hard recursion stop at `max_depth + 64`, bounded fragment expansions, capped cost multipliers |
| Cyclic fragments hang traversal | Path-local fragment stack emits `GQL-FRAG-001` and stops that branch |
| Malicious policy inflates limits or injects code | Strict JSON validation, no code evaluation, positive-integer limits, free-form maps limited to 256 entries |
| Regex denial of service via sensitive-field patterns | `fnmatchcase` globs only; no user-supplied regex compilation |
| Accidental network activity | No socket, HTTP, subprocess, JS, LLM, or service dependency in `src/`; enforced by the NO_STUBS juror and Semgrep |
| Secret leakage in reports | No secrets are read; findings contain field names, locations, numeric evidence and remediation text only |
| Non-deterministic CI evidence | Stable rule IDs, sorted keys and findings, SHA-256 partial fingerprints, baseline keyed by rule/location/evidence |

## Data handling

Inputs are local files passed explicitly on the command line. Outputs (JSON, SARIF, baselines, probe packets) are written only to explicitly requested paths. The tool does not phone home, does not cache payloads, and does not embed telemetry.

## Vulnerability reporting

Report security issues privately to **baysozlabs@proton.me** with a minimal reproduction, affected version, and impact assessment. Please do not open public issues for exploitable vulnerabilities.

## Supported versions

Security fixes are applied to the latest 1.x release. Python 3.13+ is required.

Baysöz Labs <baysozlabs@proton.me>
