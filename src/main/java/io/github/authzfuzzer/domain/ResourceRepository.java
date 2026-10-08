package io.github.authzfuzzer.domain;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ResourceRepository extends JpaRepository<Resource, Long> {

    List<Resource> findAllByTenant(Tenant tenant);
}
