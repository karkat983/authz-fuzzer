package io.github.authzfuzzer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import io.github.authzfuzzer.domain.AppUserRepository;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.TenantRepository;

/**
 * Seeds an empty database and compares the result with a fixed snapshot. The property tests rely
 * on knowing every user and resource in advance, so the seed must never drift silently.
 */
@DataJpaTest(showSql = false)
@Import(SeedData.class)
class SeedDeterminismTest {

    @Autowired
    SeedData seed;

    @Autowired
    TenantRepository tenants;

    @Autowired
    AppUserRepository users;

    @Autowired
    ResourceRepository resources;

    static List<String> expectedSnapshot() {
        List<String> rows = new ArrayList<>();
        for (String t : SeedData.TENANTS) {
            for (String role : List.of("viewer", "editor", "admin")) {
                rows.add("user " + t + "-" + role + " @" + t + " " + role.toUpperCase());
            }
            for (int i = 1; i <= SeedData.RESOURCES_PER_TENANT; i++) {
                rows.add("resource " + t + "-doc-" + i + " @" + t + " Confidential note " + i + " belonging to tenant "
                        + t);
            }
        }
        return rows.stream().sorted().toList();
    }

    List<String> snapshot() {
        List<String> rows = new ArrayList<>();
        users.findAll()
                .forEach(u -> rows.add(
                        "user " + u.getUsername() + " @" + u.getTenant().getName() + " " + u.getRole()));
        resources
                .findAll()
                .forEach(r -> rows.add(
                        "resource " + r.getName() + " @" + r.getTenant().getName() + " " + r.getContent()));
        return rows.stream().sorted().toList();
    }

    @Test
    void seedMatchesTheDocumentedSnapshot() {
        seed.run();
        assertThat(tenants.count()).isEqualTo(3);
        assertThat(snapshot()).isEqualTo(expectedSnapshot());
    }
}
