package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.domain.ResourceRepository;

@SpringBootTest
@Transactional
class CheckTenantTest {

    @Autowired
    AuthorizationService authz;

    @Autowired
    AppUserDetailsService users;

    @Autowired
    ResourceRepository resources;

    @Test
    void ownTenantPasses() {
        var alpha = users.loadUserByUsername("alpha-viewer");
        assertThatCode(() -> authz.checkTenant(alpha, resources.findById(1L).orElseThrow()))
                .doesNotThrowAnyException();
    }

    @Test
    void otherTenantIsRejectedEvenForAdmins() {
        var bravoAdmin = users.loadUserByUsername("bravo-admin");
        assertThatThrownBy(() ->
                        authz.checkTenant(bravoAdmin, resources.findById(1L).orElseThrow()))
                .isInstanceOf(CrossTenantException.class);
    }
}
