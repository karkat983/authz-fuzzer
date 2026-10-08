package io.github.authzfuzzer.security;

/** The caller tried to touch an object owned by another tenant. */
public class CrossTenantException extends RuntimeException {

    public CrossTenantException(String username, Long resourceId) {
        super(username + " denied cross-tenant access to resource " + resourceId);
    }
}
