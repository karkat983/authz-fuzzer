package io.github.authzfuzzer.security;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import io.github.authzfuzzer.domain.Role;

/**
 * The role -> permission matrix. This table is the single source of truth: the service enforces
 * it and the property tests use it as their oracle.
 *
 * <pre>
 *            READ  CREATE  UPDATE  DELETE  MANAGE_USERS  SHARE
 *   VIEWER    x
 *   EDITOR    x      x       x
 *   ADMIN     x      x       x       x          x          x
 * </pre>
 */
public final class RolePermissions {

    private static final Map<Role, Set<Permission>> MATRIX = new EnumMap<>(Role.class);

    static {
        MATRIX.put(Role.VIEWER, EnumSet.of(Permission.READ));
        MATRIX.put(Role.EDITOR, EnumSet.of(Permission.READ, Permission.CREATE, Permission.UPDATE));
        MATRIX.put(Role.ADMIN, EnumSet.allOf(Permission.class));
    }

    private RolePermissions() {}

    public static boolean allows(Role role, Permission permission) {
        return MATRIX.getOrDefault(role, Set.of()).contains(permission);
    }

    public static Set<Permission> of(Role role) {
        return EnumSet.copyOf(MATRIX.get(role));
    }
}
