package io.github.authzfuzzer.security;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.SeedData;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    MockMvc mvc;

    @Test
    void noCredentialsIs401WithBasicChallenge() throws Exception {
        mvc.perform(get("/api/anything"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void wrongPasswordIs401() throws Exception {
        mvc.perform(get("/api/anything").with(httpBasic("alpha-admin", "nope"))).andExpect(status().isUnauthorized());
    }

    @Test
    void validCredentialsPassAuthentication() throws Exception {
        // No endpoint exists yet, so an authenticated request reaches the router and gets 404.
        mvc.perform(get("/api/anything").with(httpBasic("alpha-admin", SeedData.PASSWORD)))
                .andExpect(status().isNotFound());
    }

    @Test
    void noSessionCookieIsIssued() throws Exception {
        mvc.perform(get("/api/anything").with(httpBasic("alpha-admin", SeedData.PASSWORD)))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    @Transactional
    void stateChangingRequestNeedsNoCsrfTokenWithBasicAuth() throws Exception {
        // ADR 002: stateless API, explicit credentials, no cookies, so no CSRF token is required.
        mvc.perform(post("/api/resources")
                        .with(httpBasic("alpha-editor", SeedData.PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"csrf-check\",\"content\":\"x\"}"))
                .andExpect(status().isCreated())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }
}
