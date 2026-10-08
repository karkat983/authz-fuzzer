package io.github.authzfuzzer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.domain.AppUser;
import io.github.authzfuzzer.domain.AppUserRepository;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.Role;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;

@SpringBootTest
@Transactional
class SeedDataTest {

    @Autowired
    TenantRepository tenants;

    @Autowired
    AppUserRepository users;

    @Autowired
    ResourceRepository resources;

    @Autowired
    SeedData seedData;

    @Test
    void contextLoads() {
        assertThat(seedData).isNotNull();
    }

    @Test
    void seedsThreeTenants() {
        assertThat(tenants.findAll())
                .extracting(Tenant::getName)
                .containsExactlyInAnyOrderElementsOf(SeedData.TENANTS);
    }

    @Test
    void everyTenantHasOneUserPerRole() {
        for (Tenant tenant : tenants.findAll()) {
            var roles = users.findAllByTenant(tenant).stream()
                    .map(AppUser::getRole)
                    .collect(Collectors.toCollection(() -> EnumSet.noneOf(Role.class)));
            assertThat(roles).isEqualTo(EnumSet.allOf(Role.class));
        }
        assertThat(users.count()).isEqualTo((long) SeedData.TENANTS.size() * Role.values().length);
    }

    @Test
    void everyTenantOwnsItsResources() {
        for (Tenant tenant : tenants.findAll()) {
            var owned = resources.findAllByTenant(tenant);
            assertThat(owned).hasSize(SeedData.RESOURCES_PER_TENANT);
            assertThat(owned).allSatisfy(r -> assertThat(r.getName()).startsWith(tenant.getName() + "-"));
        }
    }

    @Test
    void seedingTwiceDoesNotDuplicate() {
        long before = resources.count();
        seedData.run();
        assertThat(resources.count()).isEqualTo(before);
        assertThat(tenants.count()).isEqualTo(SeedData.TENANTS.size());
    }
}
