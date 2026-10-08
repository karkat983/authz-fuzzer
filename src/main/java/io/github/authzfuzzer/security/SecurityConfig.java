package io.github.authzfuzzer.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * Every /api/** request must authenticate with HTTP Basic; no sessions are created, so each
     * request is judged on its own credentials. CSRF protection is off because the API is
     * stateless and accepts no cookies (see the CSRF ADR in the RBAC phase).
     */
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable());
        return http.build();
    }
}
