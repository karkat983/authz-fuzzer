package io.github.authzfuzzer.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.api.ShareDto;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.ShareGrant;
import io.github.authzfuzzer.domain.ShareGrantRepository;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;
import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.security.AuthorizationService;
import io.github.authzfuzzer.security.Permission;

/** Owners' admins grant other tenants read access to individual resources. */
@Service
@Transactional
public class ShareService {

    private final ResourceRepository resources;
    private final TenantRepository tenants;
    private final ShareGrantRepository shares;
    private final AuthorizationService authz;

    public ShareService(
            ResourceRepository resources,
            TenantRepository tenants,
            ShareGrantRepository shares,
            AuthorizationService authz) {
        this.resources = resources;
        this.tenants = tenants;
        this.shares = shares;
        this.authz = authz;
    }

    /** Grant `tenantName` read access to the caller's resource. Granting twice is a no-op. */
    public ShareDto grant(AppUserPrincipal caller, Long resourceId, String tenantName) {
        authz.check(caller, Permission.SHARE);
        Resource r = resources
                .findByIdAndTenantId(resourceId, caller.tenantId())
                .orElseThrow(() -> new NotFoundException("resource", resourceId));
        Tenant grantee = tenants.findByName(tenantName).orElseThrow(() -> new NotFoundException("tenant", tenantName));
        if (grantee.getId().equals(caller.tenantId())) {
            throw new IllegalArgumentException("a resource cannot be shared with its own tenant");
        }
        if (!shares.existsByResourceIdAndGranteeId(r.getId(), grantee.getId())) {
            shares.save(new ShareGrant(r, grantee));
        }
        return new ShareDto(r.getId(), grantee.getName());
    }
}
