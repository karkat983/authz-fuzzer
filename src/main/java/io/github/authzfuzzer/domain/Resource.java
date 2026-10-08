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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** A record owned by one tenant. This is the object the authorization tests try to reach across tenants. */
@Entity
@Table(
        name = "resource_item",
        uniqueConstraints =
                @UniqueConstraint(
                        name = "uk_resource_tenant_name",
                        columnNames = {"tenant_id", "name"}))
public class Resource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public static final int MAX_NAME = 200;
    public static final int MAX_CONTENT = 4000;

    @Column(nullable = false, length = MAX_NAME)
    @NotBlank
    @Size(max = MAX_NAME)
    private String name;

    @Column(nullable = false, length = MAX_CONTENT)
    @NotBlank
    @Size(max = MAX_CONTENT)
    private String content;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    protected Resource() {
        // for JPA
    }

    public Resource(String name, String content, Tenant tenant) {
        this.name = name;
        this.content = content;
        this.tenant = tenant;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getContent() {
        return content;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }

    public void rename(String name) {
        this.name = name;
    }

    public void updateContent(String content) {
        this.content = content;
    }
}
