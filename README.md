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
*Planned.*

## What I learned
*Planned.*

## Notes
No external data; all users and resources are synthetic seed data. Not affiliated with any employer. Built October 2026.

## Changelog
- Day 1: project scaffold and changelog.
