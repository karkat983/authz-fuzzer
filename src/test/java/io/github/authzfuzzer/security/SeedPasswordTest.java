package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.github.authzfuzzer.SeedData;
import io.github.authzfuzzer.domain.AppUserRepository;

@SpringBootTest
class SeedPasswordTest {

    @Autowired
    AppUserRepository users;

    @Autowired
    PasswordEncoder encoder;

    @Test
    void seededPasswordsAreBcryptHashesOfTheDocumentedPassword() {
        users.findAll().forEach(u -> {
            assertThat(u.getPasswordHash()).startsWith("$2a$");
            assertThat(encoder.matches(SeedData.PASSWORD, u.getPasswordHash())).isTrue();
            assertThat(encoder.matches("wrong", u.getPasswordHash())).isFalse();
        });
    }
}
