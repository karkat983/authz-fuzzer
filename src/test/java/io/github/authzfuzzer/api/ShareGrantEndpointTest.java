package io.github.authzfuzzer.api;

import static io.github.authzfuzzer.support.Api.as;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ShareGrantEndpointTest {

    @Autowired
    MockMvc mvc;

    ResultActions share(String user, long id, String tenant) throws Exception {
        return mvc.perform(post("/api/resources/{id}/shares", id)
                .with(as(user))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"tenant\":\"" + tenant + "\"}"));
    }

    @Test
    void ownerAdminSharesWithAnotherTenant() throws Exception {
        share("alpha-admin", 1, "bravo")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.resourceId").value(1))
                .andExpect(jsonPath("$.tenant").value("bravo"));
        share("alpha-admin", 1, "bravo").andExpect(status().isCreated()); // idempotent
    }

    @Test
    void onlyAdminsMayShare() throws Exception {
        share("alpha-editor", 1, "bravo").andExpect(status().isForbidden());
    }

    @Test
    void cannotShareSomeoneElsesResource() throws Exception {
        share("bravo-admin", 1, "charlie").andExpect(status().isNotFound());
    }

    @Test
    void cannotShareWithOwnTenantOrUnknownTenant() throws Exception {
        share("alpha-admin", 1, "alpha").andExpect(status().isBadRequest());
        share("alpha-admin", 1, "zulu").andExpect(status().isNotFound());
    }

    @Test
    void ownerAdminRevokesAGrant() throws Exception {
        share("alpha-admin", 1, "bravo").andExpect(status().isCreated());
        mvc.perform(delete("/api/resources/1/shares/bravo").with(as("alpha-admin")))
                .andExpect(status().isNoContent());
        mvc.perform(delete("/api/resources/1/shares/bravo").with(as("alpha-admin")))
                .andExpect(status().isNotFound());
    }

    @Test
    void granteeCannotRevokeItself() throws Exception {
        share("alpha-admin", 1, "bravo").andExpect(status().isCreated());
        mvc.perform(delete("/api/resources/1/shares/bravo").with(as("bravo-admin")))
                .andExpect(status().isNotFound());
    }
}
