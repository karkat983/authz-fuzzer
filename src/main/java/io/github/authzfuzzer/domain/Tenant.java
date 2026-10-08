package io.github.authzfuzzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Pattern;

/** A customer organisation. Every user and resource belongs to exactly one tenant. */
@Entity
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Lower-case slug, e.g. "alpha". Used in usernames, so kept short and URL-safe. */
    @Column(nullable = false, unique = true)
    @Pattern(regexp = "[a-z0-9][a-z0-9-]{1,39}")
    private String name;

    protected Tenant() {
        // for JPA
    }

    public Tenant(String name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
