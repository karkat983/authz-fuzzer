package io.github.authzfuzzer.domain;

/** Roles within a tenant. What each role may do is defined by the permission matrix. */
public enum Role {
    VIEWER,
    EDITOR,
    ADMIN
}
