package io.github.authzfuzzer.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

@DataJpaTest
class ResourceConstraintsTest {

    @Autowired
    TenantRepository tenants;

    @Autowired
    ResourceRepository resources;

    @Test
    void sameNameInSameTenantIsRejected() {
        Tenant t = tenants.save(new Tenant("delta"));
        resources.saveAndFlush(new Resource("report", "a", t));
        assertThatThrownBy(() -> resources.saveAndFlush(new Resource("report", "b", t)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void sameNameInDifferentTenantsIsAllowed() {
        Tenant d = tenants.save(new Tenant("delta"));
        Tenant e = tenants.save(new Tenant("echo"));
        resources.saveAndFlush(new Resource("report", "a", d));
        resources.saveAndFlush(new Resource("report", "b", e));
        assertThat(resources.findAllByTenant(e)).hasSize(1);
    }
}
