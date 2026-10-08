package io.github.authzfuzzer.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.api.ResourceDto;
import io.github.authzfuzzer.api.ResourceMapper;
import io.github.authzfuzzer.api.ResourceRequest;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.Tenant;
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

    /** All resources owned by the tenant, oldest first. */
    public List<ResourceDto> list(Long tenantId) {
        return resources.findAllByTenantIdOrderByIdAsc(tenantId).stream()
                .map(ResourceMapper::toDto)
                .toList();
    }

    /** One resource by ID. Tenant checks are added by the authorization layer. */
    public ResourceDto get(Long id) {
        return resources
                .findById(id)
                .map(ResourceMapper::toDto)
                .orElseThrow(() -> new NotFoundException("resource", id));
    }

    /** Create a resource owned by the given tenant (the caller's tenant, never one from the body). */
    @Transactional
    public ResourceDto create(Long tenantId, ResourceRequest request) {
        Tenant owner = tenants.findById(tenantId).orElseThrow(() -> new NotFoundException("tenant", tenantId));
        Resource saved = resources.save(ResourceMapper.toEntity(request, owner));
        return ResourceMapper.toDto(saved);
    }

    /** Replace name and content. The owning tenant can never change through an update. */
    @Transactional
    public ResourceDto update(Long id, ResourceRequest request) {
        Resource r = resources.findById(id).orElseThrow(() -> new NotFoundException("resource", id));
        r.rename(request.name());
        r.updateContent(request.content());
        return ResourceMapper.toDto(resources.saveAndFlush(r));
    }

    @Transactional
    public void delete(Long id) {
        Resource r = resources.findById(id).orElseThrow(() -> new NotFoundException("resource", id));
        resources.delete(r);
    }
}
