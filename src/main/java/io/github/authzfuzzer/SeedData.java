package io.github.authzfuzzer;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.domain.AppUser;
import io.github.authzfuzzer.domain.AppUserRepository;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.Role;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;

/**
 * Seeds three tenants, each with one user per role and three resources.
 * Usernames follow "{tenant}-{role}", e.g. "alpha-viewer".
 */
@Component
public class SeedData implements CommandLineRunner {

    public static final List<String> TENANTS = List.of("alpha", "bravo", "charlie");
    public static final int RESOURCES_PER_TENANT = 3;

    private final TenantRepository tenants;
    private final AppUserRepository users;
    private final ResourceRepository resources;

    public SeedData(TenantRepository tenants, AppUserRepository users, ResourceRepository resources) {
        this.tenants = tenants;
        this.users = users;
        this.resources = resources;
    }

    @Override
    @Transactional
    public void run(String... args) {
        if (tenants.count() > 0) {
            return;
        }
        for (String name : TENANTS) {
            Tenant tenant = tenants.save(new Tenant(name));
            for (Role role : Role.values()) {
                users.save(new AppUser(name + "-" + role.name().toLowerCase(), tenant, role));
            }
            for (int i = 1; i <= RESOURCES_PER_TENANT; i++) {
                resources.save(new Resource(
                        name + "-doc-" + i, "Confidential note " + i + " belonging to tenant " + name, tenant));
            }
        }
    }
}
