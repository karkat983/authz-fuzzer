# Authorization model

Every request is authenticated with HTTP Basic. The caller's **tenant** and **role** are fixed
at login from the database (`AppUserPrincipal`); nothing in the request (headers, body, IDs) can
change them. Two independent checks then decide each request:

1. **Role check** (`RolePermissions`): does the caller's role grant the action? If not, **403**.
2. **Object check**: is the object the caller's tenant's own (or, for reads, shared with it)? If
   not, **404**, identical to a missing object (ADR 001).

The role check runs first and depends only on the caller and the verb, never on the object, so a
403 reveals nothing about which objects exist.

## The policy in one table

| Request | Permission | VIEWER | EDITOR | ADMIN | Object rule (else 404) |
|---------|-----------|:------:|:------:|:-----:|------------------------|
| `GET /api/resources` | READ | yes | yes | yes | lists only the caller's tenant |
| `GET /api/resources/{id}` | READ | yes | yes | yes | owned by caller's tenant **or** shared with it |
| `POST /api/resources` | CREATE | 403 | yes | yes | always created in the caller's tenant |
| `PUT /api/resources/{id}` | UPDATE | 403 | yes | yes | owned by caller's tenant (shares never allow writes) |
| `DELETE /api/resources/{id}` | DELETE | 403 | 403 | yes | owned by caller's tenant; its grants are deleted too |
| `POST /api/resources/{id}/shares` | SHARE | 403 | 403 | yes | owned by caller's tenant; grantee must be another existing tenant |
| `DELETE /api/resources/{id}/shares/{tenant}` | SHARE | 403 | 403 | yes | owned by caller's tenant; grant must exist |
| `GET /api/users` | MANAGE_USERS | 403 | 403 | yes | lists only the caller's tenant |
| any `/api/**` without valid credentials | | 401 | 401 | 401 | |

## Where each rule is enforced

| Rule | Code |
|------|------|
| role -> permission matrix | `security/RolePermissions` |
| role check | `AuthorizationService.check` (called first in every service method) |
| tenant ownership | tenant-scoped queries (`findByIdAndTenantId`) **and** `AuthorizationService.checkTenant` on the loaded object |
| shared reads | `ResourceService.get` + `AuthorizationService.checkReadable` |
| create in own tenant | `ResourceService.create` uses the principal's tenant; `ResourceRequest` has no tenant field |
| uniform 404 | `ApiExceptionHandler` maps `NotFoundException` and `CrossTenantException` to the same body |

## Properties the test suite will check

The property-based phase turns this table into executable rules: for every generated
(user, resource, verb) triple, the response must match what the table says, and in particular
**a request on another tenant's unshared resource is never 2xx and never reveals its content**.
