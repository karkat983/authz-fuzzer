# authz-fuzzer

> Status: **in progress.** Sections marked *planned* are not built yet.

## Problem
Multi-tenant APIs often check *what* a user may do (their role) but forget to check *whose* data they are touching (their tenant), letting one customer read or change another's records. This matters because broken object-level authorization is the most common serious API flaw and example-based tests rarely cover enough user/resource combinations to catch it. See OWASP API Security Top 10 (2023), API1: Broken Object Level Authorization.

## Design
*Planned.* A small Spring Boot REST service with tenants, users and role-based access control, plus a property-based test suite (jqwik) that generates thousands of (user, resource, verb) triples and asserts that no cross-tenant request ever succeeds. Deliberately planted authorization bugs measure how well the suite finds them.

## Results
*Planned.* No numbers yet.

| Metric | Value |
|--------|-------|
| Generated test cases | — |
| Planted flaws caught | — |
| Mean time to first failing case | — |
| C++ fuzzer: crashes found in parser | — |

## Run it
Requires JDK 17+ (`JAVA_HOME` set). The Maven wrapper downloads the pinned Maven version on first use.
See [docs/build.md](docs/build.md) for the exact versions verified.

```bash
./mvnw test                                   # all tests (H2 in memory, no setup)
./mvnw spring-boot:run                        # service on http://localhost:8080
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev   # also enables the H2 console at /h2-console
```

On start-up the service seeds three tenants (`alpha`, `bravo`, `charlie`), each with a viewer,
an editor and an admin (`alpha-viewer`, `alpha-editor`, ...) and three resources
(see [docs/seed.md](docs/seed.md), planned).

REST endpoints, RBAC and the jqwik properties are *planned*.

## What I learned
*Planned.*

## Notes
No external data; all users and resources are synthetic seed data. Not affiliated with any employer. Built October 2026.

## Changelog
- Day 1: project scaffold and changelog.
