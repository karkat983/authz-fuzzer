package io.github.authzfuzzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/** A record owned by one tenant. This is the object the authorization tests try to reach across tenants. */
@Entity
@Table(
        name = "resource_item",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_resource_tenant_name", columnNames = {"tenant_id", "name"}))
public class Resource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, length = 4000)
    private String content;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

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

    public void rename(String name) {
        this.name = name;
    }

    public void updateContent(String content) {
        this.content = content;
    }
}
