# Seed data

`SeedData` (a `CommandLineRunner`) fills the in-memory H2 database on every start, unless
tenants already exist. Everything is synthetic.

## Tenants

| ID | Name |
|----|------|
| 1 | alpha |
| 2 | bravo |
| 3 | charlie |

## Users

One user per role in each tenant, named `{tenant}-{role}`:

| Tenant | Viewer | Editor | Admin |
|--------|--------|--------|-------|
| alpha | alpha-viewer | alpha-editor | alpha-admin |
| bravo | bravo-viewer | bravo-editor | bravo-admin |
| charlie | charlie-viewer | charlie-editor | charlie-admin |

What each role may do is defined in the RBAC phase (`docs/authz-model.md`, planned).

## Resources

Three per tenant, named `{tenant}-doc-{n}`, content `Confidential note {n} belonging to tenant {tenant}`.

| IDs | Tenant |
|-----|--------|
| 1-3 | alpha |
| 4-6 | bravo |
| 7-9 | charlie |

IDs are database identities assigned in insertion order, so they are predictable. That is
deliberate: sequential IDs are exactly what makes broken object-level authorization easy to
exploit (guess `id + 1`), so the property tests must hold even when the attacker knows every ID.

The content string names its tenant, which lets a test detect a cross-tenant leak just by
looking for another tenant's name in a response body.
