package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import io.github.authzfuzzer.domain.Role;

class RolePermissionsTest {

    @ParameterizedTest(name = "{0} {1} -> {2}")
    @CsvSource({
        "VIEWER, READ,   true",
        "VIEWER, CREATE, false",
        "VIEWER, UPDATE, false",
        "VIEWER, DELETE, false",
        "EDITOR, READ,   true",
        "EDITOR, CREATE, true",
        "EDITOR, UPDATE, true",
        "EDITOR, DELETE, false",
        "ADMIN,  READ,   true",
        "ADMIN,  CREATE, true",
        "ADMIN,  UPDATE, true",
        "ADMIN,  DELETE, true",
        "VIEWER, MANAGE_USERS, false",
        "EDITOR, MANAGE_USERS, false",
        "ADMIN,  MANAGE_USERS, true",
    })
    void matrix(Role role, Permission permission, boolean allowed) {
        assertThat(RolePermissions.allows(role, permission)).isEqualTo(allowed);
    }

    @ParameterizedTest
    @EnumSource(Role.class)
    void everyRoleCanRead(Role role) {
        assertThat(RolePermissions.of(role)).contains(Permission.READ);
    }

    @ParameterizedTest
    @EnumSource(Role.class)
    void returnedSetIsACopy(Role role) {
        RolePermissions.of(role).clear();
        assertThat(RolePermissions.of(role)).isNotEmpty();
    }
}
