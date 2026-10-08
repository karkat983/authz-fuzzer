package io.github.authzfuzzer.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.Tenant;

class ResourceMapperTest {

    @Test
    void copiesFieldsAndFlattensTenantToItsName() {
        Resource r = new Resource("doc-1", "secret text", new Tenant("alpha"));
        ResourceDto dto = ResourceMapper.toDto(r);
        assertThat(dto.name()).isEqualTo("doc-1");
        assertThat(dto.content()).isEqualTo("secret text");
        assertThat(dto.tenant()).isEqualTo("alpha");
        assertThat(dto.id()).isNull();          // not persisted yet
    }

    @Test
    void dtoHasNoEntityTypedFields() {
        for (var component : ResourceDto.class.getRecordComponents()) {
            assertThat(component.getType().getPackageName()).doesNotEndWith(".domain");
        }
    }

    @Test
    void requestBecomesEntityOwnedByGivenTenant() {
        Tenant owner = new Tenant("bravo");
        Resource r = ResourceMapper.toEntity(new ResourceRequest("plan", "q3 budget"), owner);
        assertThat(r.getTenant()).isSameAs(owner);
        assertThat(r.getName()).isEqualTo("plan");
        assertThat(r.getContent()).isEqualTo("q3 budget");
    }
}
