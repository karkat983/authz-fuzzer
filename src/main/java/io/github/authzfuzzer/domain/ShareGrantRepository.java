package io.github.authzfuzzer.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ShareGrantRepository extends JpaRepository<ShareGrant, Long> {

    boolean existsByResourceIdAndGranteeId(Long resourceId, Long granteeTenantId);

    Optional<ShareGrant> findByResourceIdAndGranteeId(Long resourceId, Long granteeTenantId);

    List<ShareGrant> findAllByResourceId(Long resourceId);
}
