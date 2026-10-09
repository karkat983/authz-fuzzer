package io.github.authzfuzzer.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * Read access to one resource granted by its owning tenant to another tenant. Grants are
 * read-only by design: a grantee can never update or delete the resource.
 */
@Entity
@Table(
        name = "share_grant",
        uniqueConstraints =
                @UniqueConstraint(
                        name = "uk_share_resource_grantee",
                        columnNames = {"resource_id", "grantee_tenant_id"}))
public class ShareGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "resource_id", nullable = false)
    private Resource resource;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "grantee_tenant_id", nullable = false)
    private Tenant grantee;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    protected ShareGrant() {
        // for JPA
    }

    public ShareGrant(Resource resource, Tenant grantee) {
        this.resource = resource;
        this.grantee = grantee;
    }

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public Resource getResource() {
        return resource;
    }

    public Tenant getGrantee() {
        return grantee;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
