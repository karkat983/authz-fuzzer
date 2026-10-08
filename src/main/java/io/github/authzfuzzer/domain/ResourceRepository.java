package io.github.authzfuzzer.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ResourceRepository extends JpaRepository<Resource, Long> {

    List<Resource> findAllByTenant(Tenant tenant);

    List<Resource> findAllByTenantIdOrderByIdAsc(Long tenantId);

    /** Scoped lookup: a resource of another tenant is simply not found by this query. */
    Optional<Resource> findByIdAndTenantId(Long id, Long tenantId);
}
