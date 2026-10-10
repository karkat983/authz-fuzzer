# authz-scanner

A Rust implementation of the **AuthZ Fuzzer** component of Lattivant: an *authorized*
API authorization tester that discovers operations from an OpenAPI document, replays them
as different test identities, and verifies broken object-level and cross-tenant
authorization against a deterministic oracle — never inferring a vulnerability from a 2xx
status alone.

> Authorized use only. Every request is bounded by a signed [`Scope`](crates/authz-core/src/scope.rs):
> a host allowlist, permitted methods, request and time budgets, and an explicit mutation
> policy. The executor refuses anything outside the scope and fails closed.

## Workspace layout

| Crate | Responsibility |
|-------|----------------|
| `authz-core` | Domain model: HTTP primitives, operations, the identity matrix, scope, findings, the common event envelope. Pure logic, no I/O. |
| _(more crates added as the scanner grows: openapi discovery, http transport, the oracle engine, the scoped executor, findings export, the CLI)_ | |

## Why Rust

An authorization oracle's job is to decide "was this access allowed?" A single wrong
comparison turns a real vulnerability into a silent pass. Rust's type system lets the model
make illegal states unrepresentable — for example, a `Finding` cannot be constructed as
`Verified` without an oracle, an identity relation, and an expected-versus-observed outcome.

## Build and test

```bash
cd scanner
cargo test
```

## Relationship to the reference target

The repository root contains a Spring Boot multi-tenant RBAC service. That service is the
**reference target** the scanner is validated against: a hardened variant must produce zero
verified findings, and seeded authorization-check mutants must be detected. See the
top-level `README.md`.
