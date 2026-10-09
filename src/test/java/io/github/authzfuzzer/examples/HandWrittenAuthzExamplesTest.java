package io.github.authzfuzzer.examples;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.support.Api;

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

    Api api;

    @BeforeEach
    void setUp() {
        api = new Api(mvc);
    }

    @Test
    void viewerReadsOwnTenantResource() throws Exception {
        api.get("alpha-viewer", 1)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("alpha-doc-1"))
                .andExpect(jsonPath("$.tenant").value("alpha"));
    }

    @Test
    void viewerCannotCreate() throws Exception {
        api.create("alpha-viewer", "example", "text").andExpect(status().isForbidden());
    }

    @Test
    void editorUpdatesOwnTenantResource() throws Exception {
        api.update("alpha-editor", 2, "example", "text")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("example"))
                .andExpect(jsonPath("$.tenant").value("alpha"));
    }

    @Test
    void adminDeletesOwnTenantResource() throws Exception {
        api.delete("alpha-admin", 3).andExpect(status().isNoContent());
    }

    @Test
    void tenantBGets404OnTenantAResource() throws Exception {
        api.get("bravo-viewer", 1).andExpect(status().isNotFound());
    }

    @Test
    void unauthenticatedGets401() throws Exception {
        api.get(null, 1).andExpect(status().isUnauthorized());
    }
}
