package io.github.authzfuzzer.security;

/** Actions a role may take. Each REST verb on resources maps to exactly one permission. */
public enum Permission {
    READ,
    CREATE,
    UPDATE,
    DELETE,
    /** See and manage the users of one's own tenant. */
    MANAGE_USERS,
    /** Grant or revoke another tenant's read access to one's own resources. */
    SHARE
}
