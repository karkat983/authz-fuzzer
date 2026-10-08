package io.github.authzfuzzer.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    /**
     * BCrypt work factor. 10 is a sensible production default; the test profile lowers it so the
     * property suite can authenticate thousands of requests quickly.
     */
    @Bean
    PasswordEncoder passwordEncoder(@Value("${authz.bcrypt-strength:10}") int strength) {
        return new BCryptPasswordEncoder(strength);
    }
}
