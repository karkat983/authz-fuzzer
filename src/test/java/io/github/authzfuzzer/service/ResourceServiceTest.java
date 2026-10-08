package io.github.authzfuzzer.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import io.github.authzfuzzer.api.ResourceDto;
import io.github.authzfuzzer.api.ResourceRequest;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.Role;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;
import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.security.AuthorizationService;

/**
 * Service behaviour against a real (in-memory H2) JPA layer. @DataJpaTest rolls back after each
 * test and does not run SeedData, so every test builds exactly the rows it needs.
 */
@DataJpaTest(showSql = false)
@Import({ResourceService.class, AuthorizationService.class})
class ResourceServiceTest {

    @Autowired
    ResourceService service;

    @Autowired
    TenantRepository tenants;

    @Autowired
    ResourceRepository resources;

    Tenant tenant(String name) {
        return tenants.save(new Tenant(name));
    }

    Resource resource(String name, Tenant owner) {
        return resources.save(new Resource(name, "content of " + name, owner));
    }

    static AppUserPrincipal admin(Tenant t) {
        return new AppUserPrincipal(null, t.getName() + "-admin", "!", t.getId(), t.getName(), Role.ADMIN);
    }

    static ResourceRequest request(String name, String content) {
        return new ResourceRequest(name, content);
    }

    @Test
    void listReturnsOnlyTheCallersResourcesInIdOrder() {
        Tenant a = tenant("alpha");
        Tenant b = tenant("bravo");
        resource("a1", a);
        resource("b1", b);
        resource("a2", a);
        assertThat(service.list(admin(a))).extracting(ResourceDto::name).containsExactly("a1", "a2");
    }

    @Test
    void getReturnsOwnResource() {
        Tenant a = tenant("alpha");
        ResourceDto dto = service.get(admin(a), resource("a1", a).getId());
        assertThat(dto.name()).isEqualTo("a1");
        assertThat(dto.tenant()).isEqualTo("alpha");
    }

    @Test
    void getUnknownIdThrowsNotFound() {
        assertThatThrownBy(() -> service.get(admin(tenant("alpha")), 12345L)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void createStoresResourceUnderTheCallersTenant() {
        Tenant a = tenant("alpha");
        ResourceDto dto = service.create(admin(a), request("plan", "q3"));
        assertThat(dto.id()).isNotNull();
        assertThat(dto.tenant()).isEqualTo("alpha");
        assertThat(service.list(admin(a))).extracting(ResourceDto::name).containsExactly("plan");
    }

    @Test
    void updateChangesNameAndContentButNotOwner() {
        Tenant a = tenant("alpha");
        Resource r = resource("a1", a);
        ResourceDto dto = service.update(admin(a), r.getId(), request("a1-v2", "new"));
        assertThat(dto.name()).isEqualTo("a1-v2");
        assertThat(dto.content()).isEqualTo("new");
        assertThat(dto.tenant()).isEqualTo("alpha");
        assertThat(dto.createdAt()).isEqualTo(service.get(admin(a), r.getId()).createdAt());
    }

    @Test
    void deleteRemovesTheResource() {
        Tenant a = tenant("alpha");
        Resource r = resource("a1", a);
        service.delete(admin(a), r.getId());
        assertThat(resources.findById(r.getId())).isEmpty();
    }

    @Test
    void createdIdsAreUnique() {
        Tenant a = tenant("alpha");
        long first = service.create(admin(a), request("one", "1")).id();
        long second = service.create(admin(a), request("two", "2")).id();
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void everyIdBasedMethodRejectsAnotherTenantsResource() {
        Resource theirs = resource("secret", tenant("bravo"));
        AppUserPrincipal me = admin(tenant("alpha"));
        Long id = theirs.getId();
        // the scoped query finds nothing, so the caller sees "not found", exactly as for a missing ID
        assertThatThrownBy(() -> service.get(me, id)).isInstanceOf(NotFoundException.class);
        assertThatThrownBy(() -> service.update(me, id, request("x", "y"))).isInstanceOf(NotFoundException.class);
        assertThatThrownBy(() -> service.delete(me, id)).isInstanceOf(NotFoundException.class);
        assertThat(resources.findById(id))
                .hasValueSatisfying(r -> assertThat(r.getName()).isEqualTo("secret"));
    }

    @Test
    void scopedQueryFindsOnlyOwnTenant() {
        Tenant a = tenant("alpha");
        Tenant b = tenant("bravo");
        Resource r = resource("a1", a);
        assertThat(resources.findByIdAndTenantId(r.getId(), a.getId())).isPresent();
        assertThat(resources.findByIdAndTenantId(r.getId(), b.getId())).isEmpty();
    }
}
