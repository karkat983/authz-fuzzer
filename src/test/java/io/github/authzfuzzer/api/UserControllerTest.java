package io.github.authzfuzzer.api;

import static io.github.authzfuzzer.support.Api.as;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void adminListsOwnTenantUsersWithoutPasswordHashes() throws Exception {
        mvc.perform(get("/api/users").with(as("charlie-admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].username", contains("charlie-admin", "charlie-editor", "charlie-viewer")))
                .andExpect(content().string(not(containsString("$2a$"))));
    }

    @Test
    void nonAdminsAreForbidden() throws Exception {
        mvc.perform(get("/api/users").with(as("charlie-editor"))).andExpect(status().isForbidden());
    }
}
