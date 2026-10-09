package io.github.authzfuzzer.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);

    List<AppUser> findAllByTenant(Tenant tenant);

    List<AppUser> findAllByTenantIdOrderByUsernameAsc(Long tenantId);
}
