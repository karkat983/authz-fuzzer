# Releases

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
