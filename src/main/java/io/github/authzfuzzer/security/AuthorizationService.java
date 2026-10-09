package io.github.authzfuzzer.security;

import org.springframework.stereotype.Service;

import io.github.authzfuzzer.domain.Resource;

/** Every authorization decision goes through here, so there is one place to audit and test. */
@Service
public class AuthorizationService {

    /** Throws ForbiddenException unless the caller's role grants the permission. */
    public void check(AppUserPrincipal caller, Permission permission) {
        if (!RolePermissions.allows(caller.role(), permission)) {
            throw new ForbiddenException(caller.username(), permission);
        }
    }

    /**
     * Throws CrossTenantException unless the resource belongs to the caller's tenant. The tenant
     * comes from the authenticated principal, never from anything in the request.
     */
    public void checkTenant(AppUserPrincipal caller, Resource resource) {
        if (!caller.tenantId().equals(resource.getTenant().getId())) {
            throw new CrossTenantException(caller.username(), resource.getId());
        }
    }

    /** Read access: own tenant, or a share grant from the owner to the caller's tenant. */
    public void checkReadable(AppUserPrincipal caller, Resource resource, boolean sharedWithCaller) {
        if (!sharedWithCaller) {
            checkTenant(caller, resource);
        }
    }
}
