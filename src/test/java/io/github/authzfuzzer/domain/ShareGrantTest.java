package io.github.authzfuzzer.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

@DataJpaTest(showSql = false)
class ShareGrantTest {

    @Autowired
    TenantRepository tenants;

    @Autowired
    ResourceRepository resources;

    @Autowired
    ShareGrantRepository shares;

    @Test
    void grantIsFoundByResourceAndGrantee() {
        Tenant owner = tenants.save(new Tenant("delta"));
        Tenant grantee = tenants.save(new Tenant("echo"));
        Resource r = resources.save(new Resource("plan", "x", owner));
        shares.saveAndFlush(new ShareGrant(r, grantee));
        assertThat(shares.existsByResourceIdAndGranteeId(r.getId(), grantee.getId()))
                .isTrue();
        assertThat(shares.existsByResourceIdAndGranteeId(r.getId(), owner.getId()))
                .isFalse();
        assertThat(shares.findAllByResourceId(r.getId())).singleElement().satisfies(g -> assertThat(g.getCreatedAt())
                .isNotNull());
    }

    @Test
    void sameGrantTwiceIsRejected() {
        Tenant owner = tenants.save(new Tenant("delta"));
        Tenant grantee = tenants.save(new Tenant("echo"));
        Resource r = resources.save(new Resource("plan", "x", owner));
        shares.saveAndFlush(new ShareGrant(r, grantee));
        assertThatThrownBy(() -> shares.saveAndFlush(new ShareGrant(r, grantee)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
