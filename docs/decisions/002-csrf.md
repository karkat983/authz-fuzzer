# ADR 002: CSRF protection off for the stateless API

**Status:** accepted (2026-10-09)

## Context

Spring Security enables CSRF protection by default. CSRF attacks work by getting a victim's
browser to send a forged request that the browser *automatically* authenticates, using a
session cookie it already holds for the target site.

## Decision

Disable CSRF protection for `/api/**`, because the attack has nothing to ride on:

- Every request authenticates with an explicit `Authorization: Basic ...` header. Browsers do not
  attach that header to cross-site requests on their own (apart from cached Basic credentials,
  which this API never asks a browser to store because there is no browser UI).
- Sessions are `STATELESS`: the server never issues a session cookie (tested in
  `SecurityConfigTest.noSessionCookieIsIssued`), so there is no ambient credential to steal.
- Keeping CSRF on would make every state-changing API request need a token the API has no way to
  hand out, with no security gain.

## Consequences

- If a browser front-end or cookie-based login is ever added, this decision must be revisited:
  cookies bring back the ambient credential and CSRF protection must be re-enabled for them.
- The tests check both halves: no `Set-Cookie` is ever issued, and a POST with Basic credentials
  and no CSRF token succeeds.
