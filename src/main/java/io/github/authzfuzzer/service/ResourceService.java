package io.github.authzfuzzer.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.TenantRepository;

/**
 * CRUD on resources. Callers pass the tenant they act for; authorization checks are
 * layered on top in the RBAC phase.
 */
@Service
@Transactional(readOnly = true)
public class ResourceService {

    private final ResourceRepository resources;
    private final TenantRepository tenants;

    public ResourceService(ResourceRepository resources, TenantRepository tenants) {
        this.resources = resources;
        this.tenants = tenants;
    }
}
