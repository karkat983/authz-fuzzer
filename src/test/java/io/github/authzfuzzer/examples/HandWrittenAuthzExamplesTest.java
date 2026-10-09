package io.github.authzfuzzer.examples;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.SeedData;

/**
 * The authorization tests a developer would typically write by hand: one example per rule.
 * Kept separate from the property suite so the two can be compared on the planted bugs.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class HandWrittenAuthzExamplesTest {

    @Autowired
    MockMvc mvc;

    static RequestPostProcessor as(String username) {
        return httpBasic(username, SeedData.PASSWORD);
    }

    @Test
    void viewerReadsOwnTenantResource() throws Exception {
        mvc.perform(get("/api/resources/1").with(as("alpha-viewer")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("alpha-doc-1"))
                .andExpect(jsonPath("$.tenant").value("alpha"));
    }

    static final String BODY = "{\"name\":\"example\",\"content\":\"text\"}";

    @Test
    void viewerCannotCreate() throws Exception {
        mvc.perform(post("/api/resources")
                        .with(as("alpha-viewer"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isForbidden());
    }

    @Test
    void editorUpdatesOwnTenantResource() throws Exception {
        mvc.perform(put("/api/resources/2")
                        .with(as("alpha-editor"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("example"))
                .andExpect(jsonPath("$.tenant").value("alpha"));
    }

    @Test
    void adminDeletesOwnTenantResource() throws Exception {
        mvc.perform(delete("/api/resources/3").with(as("alpha-admin"))).andExpect(status().isNoContent());
    }

    @Test
    void tenantBGets404OnTenantAResource() throws Exception {
        mvc.perform(get("/api/resources/1").with(as("bravo-viewer"))).andExpect(status().isNotFound());
    }
}
