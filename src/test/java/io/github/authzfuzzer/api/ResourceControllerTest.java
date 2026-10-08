package io.github.authzfuzzer.api;

import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
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
}
