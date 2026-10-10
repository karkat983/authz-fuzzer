# authz-fuzzer

The **AuthZ Fuzzer** component of [Lattivant](https://github.com/karkat983?tab=repositories):
an *authorized* API authorization tester that discovers operations from an OpenAPI document,
replays them as different test identities, and verifies broken object-level and cross-tenant
authorization against a deterministic oracle — **never inferring a vulnerability from a 2xx
status alone**.

> Authorized use only. Every request is bounded by a declared scope: a host allowlist, permitted
> methods, request and time budgets, and an explicit mutation policy. The engine refuses anything
> outside the scope and fails closed.

## Problem

Multi-tenant APIs often check *what* a user may do (their role) but forget to check *whose* data
they are touching (their tenant), letting one customer read or change another's records. Broken
object-level authorization (BOLA) is the most common serious API flaw, and example-based tests
rarely cover enough identity/resource/verb combinations to catch it. See OWASP API Security Top
10 (2023), API1.

## What's here

Two parts:

1. **`scanner/`** — a Rust workspace implementing the scanner. It is the focus of the project.
2. **Repository root (Java / Spring Boot)** — a small multi-tenant RBAC service that serves as
   the **reference target** the scanner is validated against: a hardened variant must produce
   zero verified findings, and seeded authorization-check mutants must be detected.

### The scanner (`scanner/`)

A Cargo workspace of focused crates:

| Crate | Responsibility |
|-------|----------------|
| `authz-core` | Domain model: HTTP primitives, operations, the identity matrix, scope, findings, the common event envelope. Pure logic. |
| `authz-openapi` | OpenAPI 3.x discovery into an operation registry; classifies object-reference parameters and ownership fields. |
| `authz-http` | HTTP transport (reqwest) behind a trait, evidence capture, and secret redaction. |
| `authz-oracle` | The decision core: reads compared against an owner-visible reference; writes judged by whether owner state changed; reproduction combining. |
| `authz-exec` | The scoped execution engine: guard, rate limiter, budget, kill switch, worker pool, credentials, request building, cleanup journal. |
| `authz-scan` | Fixtures, probe planning and the async runner that produces findings. |
| `authz-findings` | Deduplication, suppression, the CI gate, and SARIF/JSON export. |
| `authz-cli` | The `authz` binary and the scan manifest. |

Why Rust: an authorization oracle's job is to decide "was this access allowed?", and one wrong
comparison turns a real vulnerability into a silent pass. The types make illegal states hard to
represent — a `Finding` cannot be `Verified` without an oracle, an identity relation, and an
observed effect.

## Run it

### The scanner

```bash
cd scanner
cargo test                                   # the full workspace test suite
cargo run -p authz-cli -- discover --spec path/to/openapi.json
cargo run -p authz-cli -- plan     --manifest scan.json
cargo run -p authz-cli -- scan     --manifest scan.json --sarif out.sarif --json report.json
```

`scan` exits 0 when the CI gate passes and 2 when it fails, so it can gate a pipeline. A manifest
declares the target, its OpenAPI spec, the authorized scope, the test identities and the known
resources; see `scanner/crates/authz-cli/src/manifest.rs`.

### The reference target (Java)

Requires JDK 17+ (`JAVA_HOME` set).

```bash
./mvnw test                                  # all tests (H2 in memory, no setup)
./mvnw spring-boot:run                       # service on http://localhost:8080
```

It seeds three tenants (`alpha`, `bravo`, `charlie`), each with a viewer, an editor and an admin,
and three resources; the authorization policy is one table in
[docs/authz-model.md](docs/authz-model.md).

## Notes

No external data; all identities and resources are synthetic. Authorized testing only. Built from
the Lattivant engineering specification.
