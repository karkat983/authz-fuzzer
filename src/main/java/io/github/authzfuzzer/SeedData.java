package io.github.authzfuzzer;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 * Usernames follow "{tenant}-{role}", e.g. "alpha-viewer". Every seeded account uses the
 * password {@link #PASSWORD}: these are synthetic test users on an in-memory database.
 */
@Component
public class SeedData implements CommandLineRunner {

    public static final List<String> TENANTS = List.of("alpha", "bravo", "charlie");
    public static final int RESOURCES_PER_TENANT = 3;
    public static final String PASSWORD = "seed-password";

    private final TenantRepository tenants;
    private final AppUserRepository users;
    private final ResourceRepository resources;
    private final PasswordEncoder encoder;

    public SeedData(
            TenantRepository tenants, AppUserRepository users, ResourceRepository resources, PasswordEncoder encoder) {
        this.tenants = tenants;
        this.users = users;
        this.resources = resources;
        this.encoder = encoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        if (tenants.count() > 0) {
            return;
        }
        for (String name : TENANTS) {
            Tenant tenant = tenants.save(new Tenant(name));
            String hash = encoder.encode(PASSWORD);
            for (Role role : Role.values()) {
                AppUser user = new AppUser(name + "-" + role.name().toLowerCase(), tenant, role);
                user.setPasswordHash(hash);
                users.save(user);
            }
            for (int i = 1; i <= RESOURCES_PER_TENANT; i++) {
                resources.save(new Resource(
                        name + "-doc-" + i, "Confidential note " + i + " belonging to tenant " + name, tenant));
            }
        }
    }
}
