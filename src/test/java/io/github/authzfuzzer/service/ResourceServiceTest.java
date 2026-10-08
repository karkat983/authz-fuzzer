package io.github.authzfuzzer.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import io.github.authzfuzzer.api.ResourceDto;
import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.ResourceRepository;
import io.github.authzfuzzer.domain.Tenant;
import io.github.authzfuzzer.domain.TenantRepository;

@DataJpaTest
@Import(ResourceService.class)
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

    @Test
    void listReturnsOnlyTheTenantsResourcesInIdOrder() {
        Tenant a = tenant("alpha");
        Tenant b = tenant("bravo");
        resource("a1", a);
        resource("b1", b);
        resource("a2", a);
        assertThat(service.list(a.getId())).extracting(ResourceDto::name).containsExactly("a1", "a2");
    }

    @Test
    void listOfUnknownTenantIsEmpty() {
        assertThat(service.list(999L)).isEmpty();
    }

    @Test
    void getReturnsTheResource() {
        Resource r = resource("a1", tenant("alpha"));
        ResourceDto dto = service.get(r.getId());
        assertThat(dto.name()).isEqualTo("a1");
        assertThat(dto.tenant()).isEqualTo("alpha");
    }

    @Test
    void getUnknownIdThrowsNotFound() {
        assertThatThrownBy(() -> service.get(12345L)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void createStoresResourceUnderTheGivenTenant() {
        Tenant a = tenant("alpha");
        ResourceDto dto = service.create(a.getId(), new io.github.authzfuzzer.api.ResourceRequest("plan", "q3"));
        assertThat(dto.id()).isNotNull();
        assertThat(dto.tenant()).isEqualTo("alpha");
        assertThat(service.list(a.getId())).extracting(ResourceDto::name).containsExactly("plan");
    }

    @Test
    void createForUnknownTenantThrowsNotFound() {
        assertThatThrownBy(() -> service.create(999L, new io.github.authzfuzzer.api.ResourceRequest("x", "y")))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void updateChangesNameAndContentButNotOwner() {
        Resource r = resource("a1", tenant("alpha"));
        ResourceDto dto = service.update(r.getId(), new io.github.authzfuzzer.api.ResourceRequest("a1-v2", "new"));
        assertThat(dto.name()).isEqualTo("a1-v2");
        assertThat(dto.content()).isEqualTo("new");
        assertThat(dto.tenant()).isEqualTo("alpha");
        assertThat(dto.createdAt()).isEqualTo(service.get(r.getId()).createdAt());
    }

    @Test
    void updateUnknownIdThrowsNotFound() {
        assertThatThrownBy(() -> service.update(4242L, new io.github.authzfuzzer.api.ResourceRequest("x", "y")))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void deleteRemovesTheResource() {
        Resource r = resource("a1", tenant("alpha"));
        service.delete(r.getId());
        assertThat(resources.findById(r.getId())).isEmpty();
    }

    @Test
    void deleteUnknownIdThrowsNotFound() {
        assertThatThrownBy(() -> service.delete(777L)).isInstanceOf(NotFoundException.class);
    }
}
