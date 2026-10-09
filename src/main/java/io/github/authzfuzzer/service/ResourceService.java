package io.github.authzfuzzer.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.api.ResourceDto;
import io.github.authzfuzzer.api.ResourceMapper;
import io.github.authzfuzzer.api.ResourceRequest;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.ShareGrantRepository;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;
import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.security.AuthorizationService;
import io.github.authzfuzzer.security.Permission;

/**
 * CRUD on resources for an authenticated caller. Every method first checks the caller's role
 * grants the permission (else 403), then, for ID-based methods, that the object belongs to the
 * caller's tenant (else the same 404 as a missing object).
 */
@Service
@Transactional(readOnly = true)
public class ResourceService {

    private final ResourceRepository resources;
    private final TenantRepository tenants;
    private final AuthorizationService authz;
    private final ShareGrantRepository shares;

    public ResourceService(
            ResourceRepository resources,
            TenantRepository tenants,
            AuthorizationService authz,
            ShareGrantRepository shares) {
        this.resources = resources;
        this.tenants = tenants;
        this.authz = authz;
        this.shares = shares;
    }

    /** All resources owned by the caller's tenant, oldest first. */
    public List<ResourceDto> list(AppUserPrincipal caller) {
        authz.check(caller, Permission.READ);
        return resources.findAllByTenantIdOrderByIdAsc(caller.tenantId()).stream()
                .map(ResourceMapper::toDto)
                .toList();
    }

    public ResourceDto get(AppUserPrincipal caller, Long id) {
        authz.check(caller, Permission.READ);
        return ResourceMapper.toDto(owned(caller, id));
    }

    /** Create a resource owned by the caller's tenant (never a tenant named in the body). */
    @Transactional
    public ResourceDto create(AppUserPrincipal caller, ResourceRequest request) {
        authz.check(caller, Permission.CREATE);
        Tenant owner = tenants.findById(caller.tenantId())
                .orElseThrow(() -> new NotFoundException("tenant", caller.tenantId()));
        return ResourceMapper.toDto(resources.save(ResourceMapper.toEntity(request, owner)));
    }

    /** Replace name and content. The owning tenant can never change through an update. */
    @Transactional
    public ResourceDto update(AppUserPrincipal caller, Long id, ResourceRequest request) {
        authz.check(caller, Permission.UPDATE);
        Resource r = owned(caller, id);
        r.rename(request.name());
        r.updateContent(request.content());
        return ResourceMapper.toDto(resources.saveAndFlush(r));
    }

    @Transactional
    public void delete(AppUserPrincipal caller, Long id) {
        authz.check(caller, Permission.DELETE);
        Resource r = owned(caller, id);
        shares.deleteAll(shares.findAllByResourceId(r.getId())); // a deleted resource keeps no grants
        resources.delete(r);
    }

    /**
     * Load a resource of the caller's tenant. Two layers: the query itself is tenant-scoped, and
     * the loaded object is checked again, so one forgotten filter cannot leak data on its own.
     * Missing and foreign objects both end in the same 404.
     */
    private Resource owned(AppUserPrincipal caller, Long id) {
        Resource r = resources
                .findByIdAndTenantId(id, caller.tenantId())
                .orElseThrow(() -> new NotFoundException("resource", id));
        authz.checkTenant(caller, r);
        return r;
    }
}
