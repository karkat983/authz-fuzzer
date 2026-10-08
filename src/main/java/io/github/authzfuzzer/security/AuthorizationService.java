package io.github.authzfuzzer.security;

import org.springframework.stereotype.Service;

/** Every authorization decision goes through here, so there is one place to audit and test. */
@Service
public class AuthorizationService {

    /** Throws ForbiddenException unless the caller's role grants the permission. */
    public void check(AppUserPrincipal caller, Permission permission) {
        if (!RolePermissions.allows(caller.role(), permission)) {
            throw new ForbiddenException(caller.username(), permission);
        }
    }
}
