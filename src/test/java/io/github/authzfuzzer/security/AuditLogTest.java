package io.github.authzfuzzer.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.support.Api;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditLogTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    AuditLog audit;

    Api api;

    @BeforeEach
    void setUp() {
        api = new Api(mvc);
        audit.clear();
    }

    @Test
    void crossTenantProbeIsAuditedButLooksLikeAMissingObject() throws Exception {
        api.get("bravo-admin", 1).andExpect(status().isNotFound());
        assertThat(audit.recent()).singleElement().satisfies(e -> {
            assertThat(e.username()).isEqualTo("bravo-admin");
            assertThat(e.tenant()).isEqualTo("bravo");
            assertThat(e.resourceId()).isEqualTo(1L);
            assertThat(e.reason()).isEqualTo(AuditLog.Reason.CROSS_TENANT_ACCESS);
        });
    }

    @Test
    void roleDenialIsAudited() throws Exception {
        api.delete("alpha-viewer", 1).andExpect(status().isForbidden());
        assertThat(audit.recent())
                .extracting(AuditLog.Entry::reason)
                .containsExactly(AuditLog.Reason.ROLE_LACKS_PERMISSION);
    }

    @Test
    void genuinelyMissingObjectIsNotAnAttack() throws Exception {
        api.get("alpha-admin", 99_999).andExpect(status().isNotFound());
        assertThat(audit.recent()).isEmpty();
    }

    @Test
    void ownTenantAccessLeavesNoEntry() throws Exception {
        api.get("alpha-viewer", 1).andExpect(status().isOk());
        assertThat(audit.recent()).isEmpty();
    }
}
