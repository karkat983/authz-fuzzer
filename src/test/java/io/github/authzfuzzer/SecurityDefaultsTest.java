package io.github.authzfuzzer;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityDefaultsTest {

    @Autowired
    MockMvc mvc;

    @Test
    void anonymousRequestsAreRejectedByDefault() throws Exception {
        mvc.perform(get("/api/resources")).andExpect(status().isUnauthorized());
    }
}
