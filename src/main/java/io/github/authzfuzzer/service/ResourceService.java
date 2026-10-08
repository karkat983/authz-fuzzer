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
import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.security.AuthorizationService;

/**
 * CRUD on resources for an authenticated caller. Every method that takes an ID loads the object
 * and checks it belongs to the caller's tenant before doing anything else.
 */
@Service
@Transactional(readOnly = true)
public class ResourceService {

    private final ResourceRepository resources;
    private final TenantRepository tenants;
    private final AuthorizationService authz;

    public ResourceService(ResourceRepository resources, TenantRepository tenants, AuthorizationService authz) {
        this.resources = resources;
        this.tenants = tenants;
        this.authz = authz;
    }

    /** All resources owned by the caller's tenant, oldest first. */
    public List<ResourceDto> list(AppUserPrincipal caller) {
        return resources.findAllByTenantIdOrderByIdAsc(caller.tenantId()).stream()
                .map(ResourceMapper::toDto)
                .toList();
    }

    public ResourceDto get(AppUserPrincipal caller, Long id) {
        return ResourceMapper.toDto(owned(caller, id));
    }

    /** Create a resource owned by the caller's tenant (never a tenant named in the body). */
    @Transactional
    public ResourceDto create(AppUserPrincipal caller, ResourceRequest request) {
        Tenant owner = tenants.findById(caller.tenantId())
                .orElseThrow(() -> new NotFoundException("tenant", caller.tenantId()));
        return ResourceMapper.toDto(resources.save(ResourceMapper.toEntity(request, owner)));
    }

    /** Replace name and content. The owning tenant can never change through an update. */
    @Transactional
    public ResourceDto update(AppUserPrincipal caller, Long id, ResourceRequest request) {
        Resource r = owned(caller, id);
        r.rename(request.name());
        r.updateContent(request.content());
        return ResourceMapper.toDto(resources.saveAndFlush(r));
    }

    @Transactional
    public void delete(AppUserPrincipal caller, Long id) {
        resources.delete(owned(caller, id));
    }

    /** Load a resource and enforce tenant ownership; missing and foreign both end in a 404. */
    private Resource owned(AppUserPrincipal caller, Long id) {
        Resource r = resources.findById(id).orElseThrow(() -> new NotFoundException("resource", id));
        authz.checkTenant(caller, r);
        return r;
    }
}
