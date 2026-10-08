package io.github.authzfuzzer.security;

/** Actions on resources. Each REST verb maps to exactly one permission. */
public enum Permission {
    READ,
    CREATE,
    UPDATE,
    DELETE
}
