# Releases

## v0.2-rbac (2026-10-09)

Authentication and authorization, ready to be attacked by the property suite.

- HTTP Basic login with BCrypt; the principal carries tenant and role from the database.
- Role -> permission matrix (VIEWER / EDITOR / ADMIN; READ, CREATE, UPDATE, DELETE, MANAGE_USERS,
  SHARE), checked first in every service method.
- Tenant isolation in two layers: tenant-scoped queries and an object-level check.
- Cross-tenant access returns the same 404 as a missing object (ADR 001).
- REST endpoints for resources, admin user listing, read-only sharing (grant / revoke).
- Policy documented as one table (docs/authz-model.md); 102 tests passing, including
  hand-written examples for each rule.

## v0.1-skeleton (2026-10-09)

The service skeleton, before any authentication or authorization.

- Spring Boot 3.3 / Java 17 / H2, Maven wrapper, CI (`./mvnw verify`), Spotless formatting.
- Entities: `Tenant`, `AppUser` (role), `Resource` (owned by one tenant, unique name per tenant,
  `createdAt`), all with Bean Validation.
- Seed data: 3 tenants x 3 roles x 3 resources (docs/seed.md).
- `ResourceService` CRUD returning DTOs; problem-JSON errors with non-leaking 404s.
- 32 tests passing.

Not yet present: authentication, roles' permissions, tenant checks, REST endpoints. Those are
the next phase, and the property-based tests come after that.
