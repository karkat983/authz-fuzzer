package io.github.authzfuzzer.api;

import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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

/** Endpoint behaviour for a caller acting on their own tenant. Each test rolls back. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ResourceControllerTest {

    @Autowired
    MockMvc mvc;

    static RequestPostProcessor as(String username) {
        return httpBasic(username, SeedData.PASSWORD);
    }

    @Test
    void listReturnsOnlyCallersTenant() throws Exception {
        mvc.perform(get("/api/resources").with(as("bravo-viewer")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[*].tenant", everyItem(is("bravo"))));
    }

    @Test
    void getOwnResource() throws Exception {
        mvc.perform(get("/api/resources/4").with(as("bravo-viewer")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("bravo-doc-1"))
                .andExpect(jsonPath("$.tenant").value("bravo"));
    }

    @Test
    void getUnknownIdIs404() throws Exception {
        mvc.perform(get("/api/resources/99999").with(as("bravo-viewer"))).andExpect(status().isNotFound());
    }

    static String body(String name, String content) {
        return "{\"name\":\"" + name + "\",\"content\":\"" + content + "\"}";
    }

    @Test
    void createInCallersTenantReturns201WithLocation() throws Exception {
        mvc.perform(post("/api/resources")
                        .with(as("charlie-editor"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("plan", "q4")))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.tenant").value("charlie"));
    }

    @Test
    void createWithBlankNameIs400() throws Exception {
        mvc.perform(post("/api/resources")
                        .with(as("charlie-editor"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("", "x")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void updateOwnResource() throws Exception {
        mvc.perform(put("/api/resources/7")
                        .with(as("charlie-editor"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("charlie-doc-1-v2", "revised")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("charlie-doc-1-v2"))
                .andExpect(jsonPath("$.tenant").value("charlie"));
    }

    @Test
    void deleteOwnResourceThenItIsGone() throws Exception {
        mvc.perform(delete("/api/resources/1").with(as("alpha-admin"))).andExpect(status().isNoContent());
        mvc.perform(get("/api/resources/1").with(as("alpha-admin"))).andExpect(status().isNotFound());
    }

    @Test
    void crossTenantRequestsAre404OnEveryIdEndpoint() throws Exception {
        // resource 1 belongs to alpha; bravo-admin has every permission but the wrong tenant
        mvc.perform(get("/api/resources/1").with(as("bravo-admin"))).andExpect(status().isNotFound());
        mvc.perform(put("/api/resources/1")
                        .with(as("bravo-admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("stolen", "x")))
                .andExpect(status().isNotFound());
        mvc.perform(delete("/api/resources/1").with(as("bravo-admin"))).andExpect(status().isNotFound());
        mvc.perform(get("/api/resources/1").with(as("alpha-viewer")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("alpha-doc-1"));
    }

    @Test
    void viewerCannotWriteInOwnTenant() throws Exception {
        mvc.perform(post("/api/resources")
                        .with(as("alpha-viewer"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("x", "y")))
                .andExpect(status().isForbidden());
        mvc.perform(put("/api/resources/1")
                        .with(as("alpha-viewer"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("x", "y")))
                .andExpect(status().isForbidden());
        mvc.perform(delete("/api/resources/1").with(as("alpha-viewer"))).andExpect(status().isForbidden());
    }

    @Test
    void editorCannotDelete() throws Exception {
        mvc.perform(delete("/api/resources/1").with(as("alpha-editor"))).andExpect(status().isForbidden());
    }
}
