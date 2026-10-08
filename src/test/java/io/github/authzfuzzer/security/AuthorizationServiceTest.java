package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import io.github.authzfuzzer.domain.Role;

class AuthorizationServiceTest {

    AuthorizationService authz = new AuthorizationService();

    static AppUserPrincipal caller(Role role) {
        return new AppUserPrincipal(1L, "alpha-" + role.name().toLowerCase(), "!", 1L, "alpha", role);
    }

    @Test
    void allowedPermissionPasses() {
        assertThatCode(() -> authz.check(caller(Role.EDITOR), Permission.UPDATE))
                .doesNotThrowAnyException();
    }

    @Test
    void missingPermissionThrowsForbidden() {
        assertThatThrownBy(() -> authz.check(caller(Role.VIEWER), Permission.CREATE))
                .isInstanceOf(ForbiddenException.class)
                .hasMessageContaining("alpha-viewer");
    }

    @Test
    void editorCannotDelete() {
        assertThatThrownBy(() -> authz.check(caller(Role.EDITOR), Permission.DELETE))
                .isInstanceOf(ForbiddenException.class);
    }
}
