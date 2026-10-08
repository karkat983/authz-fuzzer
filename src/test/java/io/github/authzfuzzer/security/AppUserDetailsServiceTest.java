package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@SpringBootTest
class AppUserDetailsServiceTest {

    @Autowired
    AppUserDetailsService service;

    @Test
    void loadsSeededUserWithRoleAuthority() {
        var details = service.loadUserByUsername("bravo-editor");
        assertThat(details.getUsername()).isEqualTo("bravo-editor");
        assertThat(details.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_EDITOR");
    }

    @Test
    void unknownUserIsRejected() {
        assertThatThrownBy(() -> service.loadUserByUsername("nobody")).isInstanceOf(UsernameNotFoundException.class);
    }
}
